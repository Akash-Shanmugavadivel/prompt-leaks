"""Configuration and safe result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from re import Pattern
from typing import Any, Literal

from .validators import ValidatorName


AllowlistTarget = Literal["secret", "match", "line"]
LivenessStatus = Literal[
    "active",
    "invalid",
    "valid_but_restricted",
    "indeterminate",
    "unsupported",
]
Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class Allowlist:
    """Suppresses known-safe values after a rule finds a candidate."""

    target: AllowlistTarget = "secret"
    regexes: tuple[Pattern[str], ...] = ()
    stop_words: tuple[str, ...] = ()

    def matches(self, *, secret: str, match: str, line: str) -> bool:
        regex_value = {"secret": secret, "match": match, "line": line}[self.target]
        if any(pattern.search(regex_value) for pattern in self.regexes):
            return True
        # Gitleaks applies regexTarget only to allowlist regexes. Stop words
        # always inspect the captured secret, never the surrounding match/line.
        normalized_secret = secret.casefold()
        return any(word.casefold() in normalized_secret for word in self.stop_words)


@dataclass(frozen=True, slots=True)
class Rule:
    """A compiled secret-detection rule."""

    rule_id: str
    description: str
    regex: Pattern[str]
    keywords: tuple[str, ...] = ()
    secret_group: int | str | None = None
    min_entropy: float = 0.0
    tags: tuple[str, ...] = ()
    allowlists: tuple[Allowlist, ...] = ()
    generic: bool = False
    priority: int = 50
    validator: ValidatorName | None = None
    severity: Severity = "high"
    confidence: float = 0.9


@dataclass(frozen=True, slots=True)
class LivenessResult:
    """Safe provider verification result containing no credential material."""

    status: LivenessStatus
    provider: str | None = None
    reason: str | None = None
    checked_at: str | None = None

    def to_dict(self) -> dict[str, str]:
        return {
            key: value
            for key, value in {
                "status": self.status,
                "provider": self.provider,
                "reason": self.reason,
                "checked_at": self.checked_at,
            }.items()
            if value is not None
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A public finding that deliberately contains no matched secret."""

    rule_id: str
    description: str
    start_offset: int
    end_offset: int
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    entropy: float
    severity: Severity = "high"
    confidence: float = 0.9
    tags: tuple[str, ...] = ()
    encodings: tuple[str, ...] = ()
    liveness: LivenessResult | None = None
    start_message_index: int | None = None
    end_message_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "rule_id": self.rule_id,
            "description": self.description,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "end_column": self.end_column,
            "entropy": round(self.entropy, 4),
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "tags": list(self.tags),
            "encodings": list(self.encodings),
        }
        if self.liveness is not None:
            data["liveness"] = self.liveness.to_dict()
        if self.start_message_index is not None:
            data["start_message_index"] = self.start_message_index
        if self.end_message_index is not None:
            data["end_message_index"] = self.end_message_index
        return data


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Safe scan result. Raw matches are never retained here."""

    detected: bool
    action: Literal["allow", "block", "redact"]
    findings: tuple[Finding, ...] = ()
    sanitized_prompt: str | None = field(default=None, repr=False)
    sanitized_messages: tuple[str, ...] | None = field(default=None, repr=False)

    def to_dict(self, *, include_sanitized_prompt: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "detected": self.detected,
            "action": self.action,
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
        }
        if include_sanitized_prompt and self.sanitized_prompt is not None:
            data["sanitized_prompt"] = self.sanitized_prompt
        if include_sanitized_prompt and self.sanitized_messages is not None:
            data["sanitized_messages"] = list(self.sanitized_messages)
        return data

