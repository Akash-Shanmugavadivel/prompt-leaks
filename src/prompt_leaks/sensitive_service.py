"""Application-facing lifecycle for optional sensitive-data models."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import os
from pathlib import Path
from threading import Lock

from .sensitive import Mode, Scope, SensitivePolicyEngine, SensitiveScanResult
from .sensitive import HybridSensitiveDetector
from .sensitive_defaults import load_sensitive_settings


class SensitiveDataService:
    """Load models once and serialize inference through one worker."""

    def __init__(self) -> None:
        policy_path = os.getenv("PROMPT_LEAKS_SENSITIVE_POLICY")
        self.settings = load_sensitive_settings(policy_path)
        default_models = Path.cwd() / "models" / "sensitive"
        self.models_dir = Path(
            os.getenv("PROMPT_LEAKS_SENSITIVE_MODELS_DIR", str(default_models))
        )
        self.device = os.getenv("PROMPT_LEAKS_SENSITIVE_DEVICE", "auto")
        self._engine: SensitivePolicyEngine | None = None
        self._load_lock = Lock()
        self._scan_lock = Lock()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sensitive-scan")

    def _load(self) -> SensitivePolicyEngine:
        if self._engine is None:
            with self._load_lock:
                if self._engine is None:
                    detector = HybridSensitiveDetector.from_local_models(
                        self.settings,
                        self.models_dir,
                        self.device,
                    )
                    self._engine = SensitivePolicyEngine(detector, self.settings)
        return self._engine

    def scan_sync(
        self,
        text: str,
        *,
        scope: Scope = "INPUT",
        mode: Mode = "DRY_RUN",
    ) -> SensitiveScanResult:
        with self._scan_lock:
            return self._load().scan(text, scope=scope, mode=mode)

    async def scan(
        self,
        text: str,
        *,
        scope: Scope = "INPUT",
        mode: Mode = "DRY_RUN",
    ) -> SensitiveScanResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._pool,
            lambda: self.scan_sync(text, scope=scope, mode=mode),
        )


@lru_cache(maxsize=1)
def get_sensitive_service() -> SensitiveDataService:
    return SensitiveDataService()


def scan_sensitive_data(
    text: str,
    *,
    scope: Scope = "INPUT",
    mode: Mode = "DRY_RUN",
) -> SensitiveScanResult:
    return get_sensitive_service().scan_sync(text, scope=scope, mode=mode)


async def scan_sensitive_data_async(
    text: str,
    *,
    scope: Scope = "INPUT",
    mode: Mode = "DRY_RUN",
) -> SensitiveScanResult:
    return await get_sensitive_service().scan(text, scope=scope, mode=mode)
