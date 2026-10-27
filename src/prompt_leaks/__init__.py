"""Public API for prompt-leaks."""

from .config import DetectorConfig, load_config, load_config_text
from .defaults import default_config
from .detector import PromptLeakDetector
from .models import Finding, LivenessResult, ScanResult
from .service import scan_prompt, scan_prompt_with_liveness


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
    "ScanResult",
    "default_config",
    "default_detector",
    "load_config",
    "load_config_text",
    "scan_prompt",
    "scan_prompt_with_liveness",
]

