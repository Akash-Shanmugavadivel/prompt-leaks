"""Hybrid GLiNER and NLI detection for confidential business information."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import logging
from pathlib import Path
import re
from typing import Any, Literal, Sequence


Action = Literal["ALLOW", "MASK", "REDACT", "BLOCK"]
Mode = Literal["ENFORCE", "DRY_RUN"]
Scope = Literal["INPUT", "OUTPUT"]
SpanType = Literal["ENTITY", "CONTEXT"]
DetectionMethod = Literal["GLINER", "SEMANTIC", "HYBRID"]

ACTION_PRIORITY: dict[Action, int] = {
    "ALLOW": 0,
    "MASK": 1,
    "REDACT": 2,
    "BLOCK": 3,
}

logger = logging.getLogger("prompt_leaks.sensitive")


class SensitiveModelUnavailableError(RuntimeError):
    """Raised when optional models or runtime dependencies are unavailable."""


@dataclass(frozen=True, slots=True)
class SensitiveCategory:
    category_id: str
    description: str
    entity_labels: tuple[str, ...]
    gliner_threshold: float = 0.6
    semantic_threshold: float = 0.75
    require_both: bool = True
    input_action: Action = "BLOCK"
    output_action: Action = "BLOCK"

    def __post_init__(self) -> None:
        if not self.category_id or not self.description:
            raise ValueError("sensitive category id and description are required")
        if not self.entity_labels:
            raise ValueError(f"category {self.category_id!r} requires entity labels")
        if not 0 <= self.gliner_threshold <= 1:
            raise ValueError("gliner_threshold must be between 0 and 1")
        if not 0 <= self.semantic_threshold <= 1:
            raise ValueError("semantic_threshold must be between 0 and 1")
        if self.input_action not in ACTION_PRIORITY:
            raise ValueError(f"unsupported input action: {self.input_action}")
        if self.output_action not in ACTION_PRIORITY:
            raise ValueError(f"unsupported output action: {self.output_action}")


@dataclass(frozen=True, slots=True)
class SensitiveSettings:
    categories: tuple[SensitiveCategory, ...]
    fail_closed: bool = True
    max_chars: int = 20_000
    chunk_chars: int = 700

    def __post_init__(self) -> None:
        if not self.categories:
            raise ValueError("at least one sensitive category is required")
        identifiers = [item.category_id for item in self.categories]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("sensitive category ids must be unique")
        if self.max_chars <= 0 or self.chunk_chars <= 0:
            raise ValueError("sensitive text limits must be positive")
        if self.chunk_chars > self.max_chars:
            raise ValueError("chunk_chars cannot exceed max_chars")


@dataclass(frozen=True, slots=True)
class SensitiveFinding:
    category: str
    start: int
    end: int
    confidence: float
    method: DetectionMethod
    signals: dict[str, float | None]
    span_type: SpanType
    action: Action = "ALLOW"

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "start": self.start,
            "end": self.end,
            "confidence": round(self.confidence, 4),
            "method": self.method,
            "signals": self.signals,
            "span_type": self.span_type,
            "action": self.action,
        }


@dataclass(frozen=True, slots=True)
class SensitiveScanResult:
    status: Literal["SUCCESS", "ERROR"]
    scope: Scope
    mode: Mode
    detected: bool
    blocked: bool
    would_block: bool
    decision: Action
    findings: tuple[SensitiveFinding, ...] = ()
    sanitized_text: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "status": self.status,
            "scope": self.scope,
            "mode": self.mode,
            "detected": self.detected,
            "blocked": self.blocked,
            "would_block": self.would_block,
            "decision": self.decision,
            "finding_count": len(self.findings),
            "findings": [item.to_dict() for item in self.findings],
        }
        if self.sanitized_text is not None:
            data["sanitized_text"] = self.sanitized_text
        if self.error is not None:
            data["error"] = self.error
        return data


def text_chunks(text: str, limit: int) -> tuple[tuple[int, int], ...]:
    """Split text at nearby sentence or whitespace boundaries."""
    if limit <= 0:
        raise ValueError("chunk limit must be positive")
    output: list[tuple[int, int]] = []
    cursor = 0
    while cursor < len(text):
        end = min(cursor + limit, len(text))
        if end < len(text):
            segment = text[cursor:end]
            boundaries = list(re.finditer(r"[.!?](?:\s|$)|\s+", segment))
            candidates = [match.end() for match in boundaries if match.end() >= limit // 2]
            if candidates:
                end = cursor + candidates[-1]
        if end <= cursor:
            end = min(cursor + limit, len(text))
        output.append((cursor, end))
        cursor = end
    return tuple(output)


class HybridSensitiveDetector:
    """Use GLiNER spans and BART NLI context as complementary signals."""

    def __init__(self, entity_model: Any, semantic_model: Any, settings: SensitiveSettings):
        self.entity_model = entity_model
        self.semantic_model = semantic_model
        self.settings = settings

    @classmethod
    def from_local_models(
        cls,
        settings: SensitiveSettings,
        models_dir: str | Path,
        device: str = "auto",
    ) -> HybridSensitiveDetector:
        try:
            import torch
            from gliner import GLiNER
            from transformers import pipeline
        except ImportError as error:
            raise SensitiveModelUnavailableError(
                "Install prompt-leaks with the 'sensitive' extra."
            ) from error

        root = Path(models_dir).resolve()
        gliner_path = root / "gliner"
        bart_path = root / "bart-large-mnli"
        if not gliner_path.is_dir() or not bart_path.is_dir():
            raise SensitiveModelUnavailableError(
                "Sensitive models are missing; run scripts/download_sensitive_models.py."
            )

        # The published GLiNER config names its encoder by Hub ID. The encoder
        # weights are already inside the GLiNER checkpoint, but construction
        # still resolves the encoder config. Point it at the colocated offline
        # DeBERTa config/tokenizer downloaded by our setup script.
        gliner_config_path = gliner_path / "gliner_config.json"
        try:
            gliner_config = json.loads(gliner_config_path.read_text(encoding="utf-8"))
            local_encoder_path = str(gliner_path)
            if gliner_config.get("model_name") != local_encoder_path:
                gliner_config["model_name"] = local_encoder_path
                gliner_config_path.write_text(
                    json.dumps(gliner_config, indent=2) + "\n",
                    encoding="utf-8",
                )
        except (OSError, ValueError, TypeError) as error:
            raise SensitiveModelUnavailableError(
                "The local GLiNER configuration is invalid or read only."
            ) from error

        requested = device.casefold()
        if requested not in {"auto", "cpu", "cuda"}:
            raise ValueError("sensitive model device must be auto, cpu, or cuda")
        if requested == "cuda" and not torch.cuda.is_available():
            raise SensitiveModelUnavailableError("CUDA was requested but is unavailable.")
        resolved_device = (
            "cuda"
            if requested == "cuda" or (requested == "auto" and torch.cuda.is_available())
            else "cpu"
        )

        try:
            entity_model = GLiNER.from_pretrained(
                str(gliner_path),
                local_files_only=True,
            )
            entity_model.to(resolved_device)
            semantic_model = pipeline(
                task="zero-shot-classification",
                model=str(bart_path),
                tokenizer=str(bart_path),
                device=0 if resolved_device == "cuda" else -1,
                local_files_only=True,
            )
        except Exception as error:
            raise SensitiveModelUnavailableError(
                "Sensitive models could not be initialized."
            ) from error
        logger.info("Loaded sensitive-data models on %s", resolved_device)
        return cls(entity_model, semantic_model, settings)

    def detect(self, text: str) -> tuple[SensitiveFinding, ...]:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if len(text) > self.settings.max_chars:
            raise ValueError(f"text exceeds maximum length {self.settings.max_chars}")
        if not text.strip():
            return ()

        findings: list[SensitiveFinding] = []
        for start, end in text_chunks(text, self.settings.chunk_chars):
            findings.extend(self._detect_chunk(text[start:end], start))
        return self._deduplicate(findings)

    def _detect_chunk(self, chunk: str, base: int) -> list[SensitiveFinding]:
        label_categories: dict[str, list[SensitiveCategory]] = {}
        display_labels: dict[str, str] = {}
        for category in self.settings.categories:
            for label in category.entity_labels:
                key = label.casefold()
                display_labels.setdefault(key, label)
                label_categories.setdefault(key, []).append(category)

        labels = [display_labels[key] for key in sorted(display_labels)]
        raw_entities = self.entity_model.predict_entities(chunk, labels, threshold=0.01)
        hits: dict[str, list[tuple[int, int, float]]] = {
            item.category_id: [] for item in self.settings.categories
        }
        for entity in raw_entities:
            label = str(entity.get("label", entity.get("entity_type", ""))).casefold()
            local_start = int(entity.get("start", -1))
            local_end = int(entity.get("end", -1))
            score = float(entity.get("score", 0.0))
            if not 0 <= local_start < local_end <= len(chunk):
                continue
            for category in label_categories.get(label, ()):
                if score >= category.gliner_threshold:
                    hits[category.category_id].append((local_start, local_end, score))

        semantic_categories = [
            category
            for category in self.settings.categories
            if hits[category.category_id] or not category.require_both
        ]
        semantic_scores: dict[str, float] = {}
        if semantic_categories:
            descriptions = [item.description for item in semantic_categories]
            result = self.semantic_model(
                chunk,
                candidate_labels=descriptions,
                multi_label=True,
                hypothesis_template="This text contains {}.",
                truncation=True,
            )
            by_description = {
                str(label): float(score)
                for label, score in zip(result["labels"], result["scores"], strict=True)
            }
            semantic_scores = {
                item.category_id: by_description.get(item.description, 0.0)
                for item in semantic_categories
            }

        output: list[SensitiveFinding] = []
        for category in self.settings.categories:
            category_hits = hits[category.category_id]
            semantic_score = semantic_scores.get(category.category_id, 0.0)
            semantic_hit = semantic_score >= category.semantic_threshold
            if category.require_both and not (category_hits and semantic_hit):
                continue
            for local_start, local_end, gliner_score in category_hits:
                output.append(
                    SensitiveFinding(
                        category=category.category_id,
                        start=base + local_start,
                        end=base + local_end,
                        confidence=max(gliner_score, semantic_score),
                        method="HYBRID" if semantic_hit else "GLINER",
                        signals={
                            "gliner_score": round(gliner_score, 4),
                            "semantic_score": round(semantic_score, 4),
                        },
                        span_type="ENTITY",
                    )
                )
            if semantic_hit and not category_hits:
                output.append(
                    SensitiveFinding(
                        category=category.category_id,
                        start=base,
                        end=base + len(chunk),
                        confidence=semantic_score,
                        method="SEMANTIC",
                        signals={
                            "gliner_score": None,
                            "semantic_score": round(semantic_score, 4),
                        },
                        span_type="CONTEXT",
                    )
                )
        return output

    @staticmethod
    def _deduplicate(findings: Sequence[SensitiveFinding]) -> tuple[SensitiveFinding, ...]:
        best: dict[tuple[str, int, int], SensitiveFinding] = {}
        method_priority = {"SEMANTIC": 0, "GLINER": 1, "HYBRID": 2}
        for finding in findings:
            key = (finding.category, finding.start, finding.end)
            current = best.get(key)
            if current is None or (
                finding.confidence,
                method_priority[finding.method],
            ) > (
                current.confidence,
                method_priority[current.method],
            ):
                best[key] = finding
        return tuple(sorted(best.values(), key=lambda item: (item.start, item.end, item.category)))


class SensitivePolicyEngine:
    def __init__(self, detector: HybridSensitiveDetector, settings: SensitiveSettings):
        self.detector = detector
        self.settings = settings
        self.categories = {item.category_id: item for item in settings.categories}

    def scan(
        self,
        text: str,
        *,
        scope: Scope = "INPUT",
        mode: Mode = "DRY_RUN",
    ) -> SensitiveScanResult:
        if scope not in {"INPUT", "OUTPUT"}:
            raise ValueError("scope must be INPUT or OUTPUT")
        if mode not in {"ENFORCE", "DRY_RUN"}:
            raise ValueError("mode must be ENFORCE or DRY_RUN")
        try:
            return self._decide(text, scope, mode, self.detector.detect(text))
        except (TypeError, ValueError):
            raise
        except Exception:
            logger.exception("Sensitive-data inference failed")
            decision: Action = "BLOCK" if self.settings.fail_closed else "ALLOW"
            return SensitiveScanResult(
                status="ERROR",
                scope=scope,
                mode=mode,
                detected=False,
                blocked=decision == "BLOCK" and mode == "ENFORCE",
                would_block=decision == "BLOCK",
                decision=decision,
                error="DETECTOR_UNAVAILABLE",
            )

    def _decide(
        self,
        text: str,
        scope: Scope,
        mode: Mode,
        findings: Sequence[SensitiveFinding],
    ) -> SensitiveScanResult:
        resolved: list[SensitiveFinding] = []
        for finding in findings:
            category = self.categories[finding.category]
            action = category.input_action if scope == "INPUT" else category.output_action
            if finding.span_type == "CONTEXT" and action in {"MASK", "REDACT"}:
                action = "BLOCK"
            resolved.append(replace(finding, action=action))

        decision = max(
            (item.action for item in resolved),
            key=lambda action: ACTION_PRIORITY[action],
            default="ALLOW",
        )
        blocked = decision == "BLOCK" and mode == "ENFORCE"
        sanitized = None
        if mode == "ENFORCE" and not blocked:
            transformed = self._apply_patches(text, resolved)
            if transformed != text:
                sanitized = transformed
        return SensitiveScanResult(
            status="SUCCESS",
            scope=scope,
            mode=mode,
            detected=bool(resolved),
            blocked=blocked,
            would_block=decision == "BLOCK",
            decision=decision,
            findings=tuple(resolved),
            sanitized_text=sanitized,
        )

    @staticmethod
    def _apply_patches(text: str, findings: Sequence[SensitiveFinding]) -> str:
        patches = [
            (item.start, item.end, item.action)
            for item in findings
            if item.action in {"MASK", "REDACT"} and item.span_type == "ENTITY"
        ]
        if not patches:
            return text
        boundaries = sorted({offset for start, end, _ in patches for offset in (start, end)})
        intervals: list[tuple[int, int, Action]] = []
        for start, end in zip(boundaries, boundaries[1:], strict=False):
            active = [action for left, right, action in patches if left < end and right > start]
            if active:
                intervals.append(
                    (start, end, max(active, key=lambda action: ACTION_PRIORITY[action]))
                )
        output = text
        for start, end, action in reversed(intervals):
            replacement = "[REDACTED]" if action == "REDACT" else "*" * (end - start)
            output = output[:start] + replacement + output[end:]
        return output
