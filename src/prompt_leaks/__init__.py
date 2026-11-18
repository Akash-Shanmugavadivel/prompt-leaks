"""Public API for prompt-leaks."""

from .config import DetectorConfig, load_config, load_config_text
from .defaults import default_config
from .detector import PromptLeakDetector
from .models import Finding, LivenessResult, ScanResult
from .presidio import (
    PresidioAnalysisError,
    PresidioScanConfig,
    PresidioUnavailableError,
)
from .quality import QualityModelUnavailableError, QualityPolicy, QualityResult, ResponseQualityGuardrail
from .quality_service import check_response_quality, check_response_quality_async
from .service import (
    scan_messages,
    scan_messages_with_liveness,
    scan_prompt,
    scan_prompt_with_liveness,
)
from .sensitive import (
    SensitiveCategory,
    SensitiveFinding,
    SensitiveModelUnavailableError,
    SensitiveScanResult,
    SensitiveSettings,
)
from .sensitive_service import scan_sensitive_data, scan_sensitive_data_async


def default_detector(
    *,
    max_decode_depth: int = 1,
    max_prompt_chars: int = 100_000,
) -> PromptLeakDetector:
    """Create a detector with the built-in rules."""
    config = default_config()
    return PromptLeakDetector(
        config.rules,
        global_allowlists=config.global_allowlists,
        max_decode_depth=max_decode_depth,
        max_prompt_chars=max_prompt_chars,
    )


__all__ = [
    "DetectorConfig",
    "Finding",
    "LivenessResult",
    "PromptLeakDetector",
    "QualityModelUnavailableError",
    "QualityPolicy",
    "QualityResult",
    "ResponseQualityGuardrail",
    "PresidioAnalysisError",
    "PresidioScanConfig",
    "PresidioUnavailableError",
    "ScanResult",
    "SensitiveCategory",
    "SensitiveFinding",
    "SensitiveModelUnavailableError",
    "SensitiveScanResult",
    "SensitiveSettings",
    "default_config",
    "default_detector",
    "load_config",
    "load_config_text",
    "scan_prompt",
    "scan_prompt_with_liveness",
    "scan_messages",
    "scan_messages_with_liveness",
    "scan_sensitive_data",
    "scan_sensitive_data_async",
    "check_response_quality",
    "check_response_quality_async",
]

