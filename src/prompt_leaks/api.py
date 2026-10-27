"""FastAPI application for prompt secret detection."""

from __future__ import annotations

import os
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .service import MAX_PROMPT_CHARS, scan_prompt, scan_prompt_with_liveness


class ScanRequest(BaseModel):
    prompt: str = Field(max_length=MAX_PROMPT_CHARS)
    mode: Literal["block", "redact"] = "block"
    verify_liveness: bool = False


class LivenessResponse(BaseModel):
    status: Literal[
        "active",
        "invalid",
        "restricted",
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
    tags: list[str]
    encodings: list[str]
    liveness: LivenessResponse | None = None


class ScanResponse(BaseModel):
    detected: bool
    action: Literal["allow", "block", "redact"]
    finding_count: int
    findings: list[FindingResponse]
    sanitized_prompt: str | None = None


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
    if request.verify_liveness:
        enabled = os.getenv("PROMPT_LEAKS_ENABLE_LIVENESS", "true").casefold()
        if enabled in {"0", "false", "no", "off"}:
            raise HTTPException(
                status_code=403,
                detail="Credential liveness verification is disabled by the server.",
            )
        result = await scan_prompt_with_liveness(request.prompt, mode=request.mode)
    else:
        result = scan_prompt(request.prompt, mode=request.mode)
    return result.to_dict(include_sanitized_prompt=request.mode == "redact")


def run() -> None:
    """Launch the local development server."""
    import uvicorn

    host = os.getenv("PROMPT_LEAKS_HOST", "127.0.0.1")
    port = int(os.getenv("PROMPT_LEAKS_PORT", "8000"))
    uvicorn.run("prompt_leaks.api:app", host=host, port=port)

