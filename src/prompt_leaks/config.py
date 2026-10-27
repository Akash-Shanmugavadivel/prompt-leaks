"""TOML configuration loading."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Allowlist, Rule
from .validators import SUPPORTED_VALIDATORS


@dataclass(frozen=True, slots=True)
class DetectorConfig:
    rules: tuple[Rule, ...]
    global_allowlists: tuple[Allowlist, ...] = ()


def load_config(
    path: str | Path,
    *,
    require_rules: bool = True,
) -> DetectorConfig:
    """Load a complete detector configuration from TOML."""
    config_path = Path(path)
    with config_path.open("rb") as handle:
        data = tomllib.load(handle)

    return _parse_config(data, require_rules=require_rules)


def load_config_text(content: str, *, require_rules: bool = True) -> DetectorConfig:
    """Load a complete detector configuration from a TOML string."""
    return _parse_config(tomllib.loads(content), require_rules=require_rules)


def _parse_config(
    data: dict[str, Any],
    *,
    require_rules: bool,
) -> DetectorConfig:
    """Translate parsed TOML into compiled rules."""

    rules = tuple(_parse_rule(item) for item in data.get("rules", []))
    if require_rules and not rules:
        raise ValueError("configuration must contain at least one [[rules]] entry")

    allowlists = tuple(
        _parse_allowlist(item) for item in data.get("allowlists", [])
    )
    return DetectorConfig(rules=rules, global_allowlists=allowlists)


def _parse_rule(data: dict[str, Any]) -> Rule:
    rule_id = _required_string(data, "id")
    description = _required_string(data, "description")
    regex_text = _required_string(data, "regex")
    flags = _parse_flags(data.get("flags", []))
    secret_group = data.get("secret_group")
    if secret_group is not None and not isinstance(secret_group, (int, str)):
        raise ValueError(f"rule {rule_id!r}: secret_group must be an integer or string")
    validator = data.get("validator")
    if validator is not None and validator not in SUPPORTED_VALIDATORS:
        raise ValueError(f"rule {rule_id!r}: unsupported validator {validator!r}")
    severity = str(data.get("severity", "medium" if data.get("generic") else "high"))
    if severity not in {"low", "medium", "high", "critical"}:
        raise ValueError(f"rule {rule_id!r}: invalid severity {severity!r}")
    confidence = float(data.get("confidence", 0.7 if data.get("generic") else 0.9))
    if not 0 <= confidence <= 1:
        raise ValueError(f"rule {rule_id!r}: confidence must be between 0 and 1")

    return Rule(
        rule_id=rule_id,
        description=description,
        regex=re.compile(regex_text, flags),
        keywords=tuple(str(value) for value in data.get("keywords", [])),
        secret_group=secret_group,
        min_entropy=float(data.get("entropy", 0.0)),
        tags=tuple(str(value) for value in data.get("tags", [])),
        allowlists=tuple(
            _parse_allowlist(item) for item in data.get("allowlists", [])
        ),
        generic=bool(data.get("generic", False)),
        priority=int(data.get("priority", 50)),
        validator=validator,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,
    )


def _parse_allowlist(data: dict[str, Any]) -> Allowlist:
    target = str(data.get("target", "secret"))
    if target not in {"secret", "match", "line"}:
        raise ValueError(f"invalid allowlist target: {target!r}")
    flags = _parse_flags(data.get("flags", []))
    return Allowlist(
        target=target,  # type: ignore[arg-type]
        regexes=tuple(re.compile(str(value), flags) for value in data.get("regexes", [])),
        stop_words=tuple(str(value) for value in data.get("stop_words", [])),
    )


def _parse_flags(values: list[str]) -> int:
    supported = {
        "ASCII": re.ASCII,
        "DOTALL": re.DOTALL,
        "IGNORECASE": re.IGNORECASE,
        "MULTILINE": re.MULTILINE,
        "VERBOSE": re.VERBOSE,
    }
    flags = 0
    for value in values:
        name = str(value).upper()
        if name not in supported:
            raise ValueError(f"unsupported regex flag: {value!r}")
        flags |= supported[name]
    return flags


def _required_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key!r} must be a non-empty string")
    return value

