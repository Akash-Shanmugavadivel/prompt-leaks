"""Optional Microsoft Presidio integration for local PII analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Sequence


class PresidioUnavailableError(RuntimeError):
    """Raised when Presidio or its configured NLP model is unavailable."""


class PresidioAnalysisError(ValueError):
    """Raised when Presidio rejects per-request analysis options."""


@dataclass(frozen=True, slots=True)
class PresidioScanConfig:
    """Per-scan controls passed to Presidio Analyzer."""

    language: str = "en"
    entities: tuple[str, ...] | None = None
    score_threshold: float = 0.5

    def __post_init__(self) -> None:
        if not self.language or len(self.language) > 16:
            raise ValueError("Presidio language must contain 1 to 16 characters")
        if not 0 <= self.score_threshold <= 1:
            raise ValueError("Presidio score_threshold must be between 0 and 1")
        if self.entities is not None and not self.entities:
            raise ValueError("Presidio entities must be omitted or contain values")


@dataclass(frozen=True, slots=True)
class PresidioEntity:
    """Safe positional metadata returned by a PII analyzer."""

    entity_type: str
    start: int
    end: int
    score: float


class PiiAnalyzer(Protocol):
    """Interface used by the detector and lightweight test doubles."""

    def analyze(
        self,
        text: str,
        *,
        config: PresidioScanConfig,
    ) -> Sequence[PresidioEntity]: ...


class MicrosoftPresidioAnalyzer:
    """Lazy adapter around ``presidio_analyzer.AnalyzerEngine``."""

    def __init__(self, analyzer: Any | None = None) -> None:
        if analyzer is not None:
            self._analyzer = analyzer
            return

        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError as error:
            raise PresidioUnavailableError(
                "Install prompt-leaks with the 'presidio' extra."
            ) from error

        try:
            self._analyzer = AnalyzerEngine()
        except Exception as error:
            raise PresidioUnavailableError(
                "Presidio could not initialize its configured NLP model."
            ) from error

    def analyze(
        self,
        text: str,
        *,
        config: PresidioScanConfig,
    ) -> tuple[PresidioEntity, ...]:
        arguments: dict[str, object] = {
            "text": text,
            "language": config.language,
            "score_threshold": config.score_threshold,
        }
        if config.entities is not None:
            arguments["entities"] = list(config.entities)

        try:
            results = self._analyzer.analyze(**arguments)
        except (KeyError, ValueError) as error:
            raise PresidioAnalysisError(
                "Presidio could not analyze the requested language or entities."
            ) from error
        entities: list[PresidioEntity] = []
        for result in results:
            entity_type = str(result.entity_type).strip().upper()
            start = int(result.start)
            end = int(result.end)
            score = float(result.score)
            if entity_type and 0 <= start < end <= len(text) and 0 <= score <= 1:
                entities.append(
                    PresidioEntity(
                        entity_type=entity_type,
                        start=start,
                        end=end,
                        score=score,
                    )
                )
        return tuple(sorted(entities, key=lambda item: (item.start, item.end)))
