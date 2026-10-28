"""Application-facing prompt scanning function."""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
import os
from pathlib import Path
from typing import Literal, Sequence

from .config import DetectorConfig, load_config, load_config_text
from .detector import PromptLeakDetector
from .liveness import ProviderLivenessVerifier
from .models import ScanResult
from .presidio import (
    MicrosoftPresidioAnalyzer,
    PiiAnalyzer,
    PresidioScanConfig,
)


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
    config = _with_organization_config(load_config_text(catalog))
    return PromptLeakDetector(
        config.rules,
        global_allowlists=config.global_allowlists,
        max_decode_depth=1,
        max_prompt_chars=MAX_PROMPT_CHARS,
    )


def _with_organization_config(base: DetectorConfig) -> DetectorConfig:
    config_path = os.getenv("PROMPT_LEAKS_ORG_CONFIG")
    if not config_path:
        return base
    organization = load_config(Path(config_path), require_rules=False)
    rules = {rule.rule_id: rule for rule in base.rules}
    rules.update({rule.rule_id: rule for rule in organization.rules})
    return DetectorConfig(
        rules=tuple(rules.values()),
        global_allowlists=base.global_allowlists + organization.global_allowlists,
    )


@lru_cache(maxsize=1)
def get_presidio_analyzer() -> PiiAnalyzer:
    """Initialize the optional local Presidio analyzer once per process."""
    return MicrosoftPresidioAnalyzer()


def _presidio_components(
    config: PresidioScanConfig | None,
) -> tuple[PiiAnalyzer | None, PresidioScanConfig | None]:
    if config is None:
        return None, None
    return get_presidio_analyzer(), config


def scan_prompt(
    prompt: str,
    *,
    mode: Literal["block", "redact"] = "block",
    presidio: PresidioScanConfig | None = None,
) -> ScanResult:
    """Scan prompt text and return findings without exposing matched secrets.

    ``block`` returns safe finding metadata and no prompt copy when a secret is
    found. ``redact`` additionally returns a sanitized prompt suitable for the
    downstream model.
    """
    pii_analyzer, pii_config = _presidio_components(presidio)
    return get_detector().scan(
        prompt,
        mode=mode,
        pii_analyzer=pii_analyzer,
        pii_config=pii_config,
    )


async def scan_prompt_with_liveness(
    prompt: str,
    *,
    mode: Literal["block", "redact"] = "block",
    presidio: PresidioScanConfig | None = None,
) -> ScanResult:
    """Scan a prompt and verify supported credentials with their issuer."""
    pii_analyzer, pii_config = _presidio_components(presidio)
    async with ProviderLivenessVerifier() as verifier:
        return await get_detector().scan_with_liveness(
            prompt,
            verifier,
            mode=mode,
            pii_analyzer=pii_analyzer,
            pii_config=pii_config,
        )


def scan_messages(
    messages: Sequence[str],
    *,
    mode: Literal["block", "redact"] = "block",
    presidio: PresidioScanConfig | None = None,
) -> ScanResult:
    """Scan conversation messages, including secrets split at boundaries."""
    pii_analyzer, pii_config = _presidio_components(presidio)
    return get_detector().scan_messages(
        messages,
        mode=mode,
        pii_analyzer=pii_analyzer,
        pii_config=pii_config,
    )


async def scan_messages_with_liveness(
    messages: Sequence[str],
    *,
    mode: Literal["block", "redact"] = "block",
    presidio: PresidioScanConfig | None = None,
) -> ScanResult:
    """Scan conversation messages and verify supported credentials."""
    pii_analyzer, pii_config = _presidio_components(presidio)
    async with ProviderLivenessVerifier() as verifier:
        return await get_detector().scan_messages_with_liveness(
            messages,
            verifier,
            mode=mode,
            pii_analyzer=pii_analyzer,
            pii_config=pii_config,
        )

