"""Lifecycle for response-quality analysis."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import os
from pathlib import Path
from threading import Lock

from .quality import (
    QualityModelUnavailableError,
    QualityResult,
    ResponseQualityGuardrail,
    ResponseType,
)


class QualityService:
    def __init__(self) -> None:
        default_model = Path.cwd() / "models" / "quality" / "all-MiniLM-L6-v2"
        self.model_path = Path(os.getenv("PROMPT_LEAKS_QUALITY_MODEL_DIR", str(default_model)))
        self.semantic_enabled = os.getenv("PROMPT_LEAKS_QUALITY_SEMANTIC", "true").casefold() not in {
            "0", "false", "no", "off"
        }
        self._guardrail: ResponseQualityGuardrail | None = None
        self._lock = Lock()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="quality-check")

    def _load(self) -> ResponseQualityGuardrail:
        if self._guardrail is None:
            with self._lock:
                if self._guardrail is None:
                    model = None
                    if self.semantic_enabled:
                        if not self.model_path.is_dir():
                            raise QualityModelUnavailableError("Quality model is missing.")
                        try:
                            from sentence_transformers import SentenceTransformer

                            model = SentenceTransformer(str(self.model_path), local_files_only=True)
                        except Exception as error:
                            raise QualityModelUnavailableError(
                                "Quality model could not be initialized."
                            ) from error
                    self._guardrail = ResponseQualityGuardrail(semantic_model=model)
        return self._guardrail

    def check_sync(self, prompt: str, response: str, response_type: ResponseType) -> QualityResult:
        return self._load().validate(prompt, response, response_type)

    async def check(self, prompt: str, response: str, response_type: ResponseType) -> QualityResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._pool,
            lambda: self.check_sync(prompt, response, response_type),
        )


@lru_cache(maxsize=1)
def get_quality_service() -> QualityService:
    return QualityService()


def check_response_quality(
    prompt: str,
    response: str,
    response_type: ResponseType = "text",
) -> QualityResult:
    return get_quality_service().check_sync(prompt, response, response_type)


async def check_response_quality_async(
    prompt: str,
    response: str,
    response_type: ResponseType = "text",
) -> QualityResult:
    return await get_quality_service().check(prompt, response, response_type)
