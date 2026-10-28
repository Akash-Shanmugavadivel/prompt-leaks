"""Optional Microsoft Presidio integration for local PII analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol, Sequence


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
    operator: Literal["replace", "mask"] = "replace"
    masking_char: str = "*"
    chars_to_mask: int = 10
    from_end: bool = False

    def __post_init__(self) -> None:
        if not self.language or len(self.language) > 16:
            raise ValueError("Presidio language must contain 1 to 16 characters")
        if not 0 <= self.score_threshold <= 1:
            raise ValueError("Presidio score_threshold must be between 0 and 1")
        if self.entities is not None and not self.entities:
            raise ValueError("Presidio entities must be omitted or contain values")
        if self.operator not in {"replace", "mask"}:
            raise ValueError("Presidio operator must be 'replace' or 'mask'")
        if len(self.masking_char) != 1:
            raise ValueError("Presidio masking_char must contain exactly one character")
        if not 0 <= self.chars_to_mask <= 100_000:
            raise ValueError("Presidio chars_to_mask must be between 0 and 100000")


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

    def anonymize(
        self,
        value: str,
        *,
        entity_type: str,
        replacement: str,
        config: PresidioScanConfig,
    ) -> str: ...


class MicrosoftPresidioAnalyzer:
    """Lazy adapter around ``presidio_analyzer.AnalyzerEngine``."""

    def __init__(
        self,
        analyzer: Any | None = None,
        anonymizer: Any | None = None,
    ) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine
            from presidio_anonymizer.entities import OperatorConfig, RecognizerResult
        except ImportError as error:
            raise PresidioUnavailableError(
                "Install prompt-leaks with the 'presidio' extra."
            ) from error

        try:
            self._analyzer = analyzer or AnalyzerEngine()
            self._anonymizer = anonymizer or AnonymizerEngine()
            self._operator_config = OperatorConfig
            self._recognizer_result = RecognizerResult
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

    def anonymize(
        self,
        value: str,
        *,
        entity_type: str,
        replacement: str,
        config: PresidioScanConfig,
    ) -> str:
        if config.operator == "mask":
            operator = self._operator_config(
                "mask",
                {
                    "masking_char": config.masking_char,
                    "chars_to_mask": min(config.chars_to_mask, len(value)),
                    "from_end": config.from_end,
                },
            )
        else:
            operator = self._operator_config(
                "replace",
                {"new_value": replacement},
            )
        try:
            result = self._anonymizer.anonymize(
                text=value,
                analyzer_results=[
                    self._recognizer_result(
                        entity_type=entity_type,
                        start=0,
                        end=len(value),
                        score=1.0,
                    )
                ],
                operators={"DEFAULT": operator},
            )
        except (KeyError, ValueError) as error:
            raise PresidioAnalysisError(
                "Presidio could not apply the requested anonymization operator."
            ) from error
        return str(result.text)
