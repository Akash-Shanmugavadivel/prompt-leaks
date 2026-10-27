"""Application-facing prompt scanning function."""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import Literal

from .config import load_config_text
from .detector import PromptLeakDetector
from .liveness import ProviderLivenessVerifier
from .models import ScanResult


MAX_PROMPT_CHARS = 100_000


@lru_cache(maxsize=1)
def get_detector() -> PromptLeakDetector:
    """Load and compile the packaged rule catalog once per process."""
    catalog = (
        files("prompt_leaks")
        .joinpath("catalog")
        .joinpath("gitleaks.toml")
        .read_text(encoding="utf-8")
    )
    config = load_config_text(catalog)
    return PromptLeakDetector(
        config.rules,
        global_allowlists=config.global_allowlists,
        max_decode_depth=1,
        max_prompt_chars=MAX_PROMPT_CHARS,
    )


def scan_prompt(
    prompt: str,
    *,
    mode: Literal["block", "redact"] = "block",
) -> ScanResult:
    """Scan prompt text and return findings without exposing matched secrets.

    ``block`` returns safe finding metadata and no prompt copy when a secret is
    found. ``redact`` additionally returns a sanitized prompt suitable for the
    downstream model.
    """
    return get_detector().scan(prompt, mode=mode)


async def scan_prompt_with_liveness(
    prompt: str,
    *,
    mode: Literal["block", "redact"] = "block",
) -> ScanResult:
    """Scan a prompt and verify supported credentials with their issuer."""
    async with ProviderLivenessVerifier() as verifier:
        return await get_detector().scan_with_liveness(
            prompt,
            verifier,
            mode=mode,
        )

