"""FastAPI application for prompt secret detection."""

from __future__ import annotations

import os
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator

from .presidio import (
    PresidioAnalysisError,
    PresidioScanConfig,
    PresidioUnavailableError,
)

from .service import (
    MAX_PROMPT_CHARS,
    scan_messages,
    scan_messages_with_liveness,
    scan_prompt,
    scan_prompt_with_liveness,
)


class PromptMessage(BaseModel):
    role: Literal["system", "developer", "user", "assistant", "tool"]
    content: str = Field(max_length=MAX_PROMPT_CHARS)


class PresidioOptions(BaseModel):
    language: str = Field(default="en", min_length=1, max_length=16)
    entities: list[str] | None = Field(default=None, min_length=1, max_length=100)
    score_threshold: float = Field(default=0.5, ge=0, le=1)
    operator: Literal["replace", "mask"] = "replace"
    masking_char: str = Field(default="*", min_length=1, max_length=1)
    chars_to_mask: int = Field(default=10, ge=0, le=100_000)
    from_end: bool = False

    def to_config(self) -> PresidioScanConfig:
        return PresidioScanConfig(
            language=self.language,
            entities=tuple(self.entities) if self.entities is not None else None,
            score_threshold=self.score_threshold,
            operator=self.operator,
            masking_char=self.masking_char,
            chars_to_mask=self.chars_to_mask,
            from_end=self.from_end,
        )


class ScanRequest(BaseModel):
    prompt: str | None = Field(default=None, max_length=MAX_PROMPT_CHARS)
    messages: list[PromptMessage] | None = Field(
        default=None, min_length=1, max_length=100
    )
    mode: Literal["block", "redact"] = "block"
    verify_liveness: bool = False
    presidio: PresidioOptions | None = None

    @model_validator(mode="after")
    def validate_input(self) -> ScanRequest:
        if (self.prompt is None) == (self.messages is None):
            raise ValueError("provide exactly one of prompt or messages")
        if (
            self.messages is not None
            and sum(len(message.content) for message in self.messages) > MAX_PROMPT_CHARS
        ):
            raise ValueError(f"messages exceed {MAX_PROMPT_CHARS} total characters")
        return self


class LivenessResponse(BaseModel):
    status: Literal[
        "active",
        "invalid",
        "valid_but_restricted",
        "indeterminate",
        "unsupported",
    ]
    provider: str | None = None
    reason: str | None = None
    checked_at: str | None = None


class FindingResponse(BaseModel):
    rule_id: str
    description: str
    start_offset: int
    end_offset: int
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    entropy: float
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float
    tags: list[str]
    encodings: list[str]
    liveness: LivenessResponse | None = None
    start_message_index: int | None = None
    end_message_index: int | None = None


class ScanResponse(BaseModel):
    detected: bool
    action: Literal["allow", "block", "redact"]
    finding_count: int
    findings: list[FindingResponse]
    sanitized_prompt: str | None = None
    sanitized_messages: list[str] | None = None


app = FastAPI(
    title="prompt-leaks",
    version="0.1.0",
    description="Detect secrets before prompt text is sent to an AI model.",
)


@app.exception_handler(RequestValidationError)
async def safe_validation_error(
    _request: Request,
    error: RequestValidationError,
) -> JSONResponse:
    """Return validation details without echoing the submitted prompt."""
    details = [
        {
            key: value
            for key, value in item.items()
            if key not in {"input", "ctx", "url"}
        }
        for item in error.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": details})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/v1/scan",
    response_model=ScanResponse,
    response_model_exclude_none=True,
)
async def scan(request: ScanRequest) -> dict[str, object]:
    presidio_config = request.presidio.to_config() if request.presidio else None
    if presidio_config is not None:
        enabled = os.getenv("PROMPT_LEAKS_ENABLE_PRESIDIO", "true").casefold()
        if enabled in {"0", "false", "no", "off"}:
            raise HTTPException(
                status_code=403,
                detail="Presidio PII analysis is disabled by the server.",
            )
    try:
        if request.verify_liveness:
            enabled = os.getenv("PROMPT_LEAKS_ENABLE_LIVENESS", "true").casefold()
            if enabled in {"0", "false", "no", "off"}:
                raise HTTPException(
                    status_code=403,
                    detail="Credential liveness verification is disabled by the server.",
                )
            if request.messages is not None:
                result = await scan_messages_with_liveness(
                    [message.content for message in request.messages],
                    mode=request.mode,
                    presidio=presidio_config,
                )
            else:
                assert request.prompt is not None
                result = await scan_prompt_with_liveness(
                    request.prompt,
                    mode=request.mode,
                    presidio=presidio_config,
                )
        else:
            if request.messages is not None:
                result = scan_messages(
                    [message.content for message in request.messages],
                    mode=request.mode,
                    presidio=presidio_config,
                )
            else:
                assert request.prompt is not None
                result = scan_prompt(
                    request.prompt,
                    mode=request.mode,
                    presidio=presidio_config,
                )
    except PresidioUnavailableError as error:
        raise HTTPException(
            status_code=503,
            detail=(
                "Presidio is unavailable. Install the optional dependency and "
                "configured NLP model."
            ),
        ) from error
    except PresidioAnalysisError as error:
        raise HTTPException(
            status_code=422,
            detail="Presidio could not analyze the requested language or entities.",
        ) from error
    return result.to_dict(include_sanitized_prompt=request.mode == "redact")


def run() -> None:
    """Launch the local development server."""
    import uvicorn

    host = os.getenv("PROMPT_LEAKS_HOST", "127.0.0.1")
    port = int(os.getenv("PROMPT_LEAKS_PORT", "8000"))
    uvicorn.run("prompt_leaks.api:app", host=host, port=port)

