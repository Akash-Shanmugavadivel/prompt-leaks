"""Advisory response-quality checks, separate from security enforcement."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Literal


ResponseType = Literal["text", "code", "json"]
QualityStatus = Literal["PASS", "REVIEW", "FAIL", "SKIP"]


class QualityModelUnavailableError(RuntimeError):
    """Raised when optional semantic-repetition detection is unavailable."""


@dataclass(frozen=True, slots=True)
class QualityPolicy:
    short_limit: int = 60
    default_limit: int = 150
    detailed_limit: int = 500
    max_sentence_words: int = 35
    semantic_threshold: float = 0.88


@dataclass(frozen=True, slots=True)
class QualityResult:
    status: QualityStatus
    score: int | None
    reasons: tuple[str, ...]
    word_count: int | None = None
    word_budget: int | None = None
    semantic_pairs: tuple[tuple[int, int], ...] | None = None
    policy_version: str = "1.0"

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "status": self.status,
            "score": self.score,
            "reasons": list(self.reasons),
            "policy_version": self.policy_version,
        }
        if self.word_count is not None:
            data["word_count"] = self.word_count
        if self.word_budget is not None:
            data["word_budget"] = self.word_budget
        if self.semantic_pairs is not None:
            data["semantic_pairs"] = [list(pair) for pair in self.semantic_pairs]
        return data


class ResponseQualityGuardrail:
    FILLERS = (
        "it is important to note that",
        "it should be noted that",
        "needless to say",
        "as a matter of fact",
    )

    def __init__(
        self,
        policy: QualityPolicy | None = None,
        semantic_model: Any | None = None,
    ) -> None:
        self.policy = policy or QualityPolicy()
        self.semantic_model = semantic_model

    def _budget(self, prompt: str) -> int:
        lowered = prompt.casefold()
        if re.search(r"\b(detailed|deep dive|comprehensive|step[- ]by[- ]step)\b", lowered):
            return self.policy.detailed_limit
        if re.search(
            r"\b(short|shortly|brief(?:ly)?|concise(?:ly)?|one sentence|tl;dr|minimal tokens)\b",
            lowered,
        ):
            return self.policy.short_limit
        return self.policy.default_limit

    def _semantic_duplicates(
        self,
        sentences: list[str],
    ) -> tuple[tuple[int, int], ...] | None:
        if self.semantic_model is None:
            return None
        if len(sentences) < 2:
            return ()
        embeddings = self.semantic_model.encode(
            sentences,
            normalize_embeddings=True,
            convert_to_numpy=True,
        )
        similarity = embeddings @ embeddings.T
        return tuple(
            (left, right)
            for left in range(len(sentences))
            for right in range(left + 1, len(sentences))
            if float(similarity[left, right]) >= self.policy.semantic_threshold
        )

    def validate(
        self,
        prompt: str,
        response: str,
        response_type: ResponseType = "text",
    ) -> QualityResult:
        if not response.strip():
            return QualityResult("FAIL", 0, ("EMPTY_RESPONSE",))

        if response_type == "code":
            return QualityResult("SKIP", None, ("CODE_OUTPUT",))
        if response_type == "json":
            try:
                json.loads(response)
            except json.JSONDecodeError:
                return QualityResult("FAIL", 0, ("INVALID_JSON",))
            return QualityResult("SKIP", None, ("VALID_JSON_OUTPUT",))

        prose = re.sub(r"```[\s\S]*?```", "", response)
        words = re.findall(r"\b[\w'-]+\b", prose)
        sentences = [
            sentence.strip()
            for sentence in re.split(r"(?<=[.!?])\s+", prose)
            if sentence.strip()
        ]
        budget = self._budget(prompt)
        score = 100
        reasons: list[str] = []

        if len(words) > budget:
            score -= min(35, round(((len(words) - budget) / budget) * 25))
            reasons.append("EXCESSIVE_LENGTH")
        if any(len(sentence.split()) > self.policy.max_sentence_words for sentence in sentences):
            score -= 15
            reasons.append("LONG_SENTENCE")
        if any(re.search(rf"\b{re.escape(filler)}\b", prose, re.I) for filler in self.FILLERS):
            score -= 15
            reasons.append("FILLER_LANGUAGE")

        normalized = [re.sub(r"\W+", " ", sentence.casefold()).strip() for sentence in sentences]
        if len(set(normalized)) < len(normalized):
            score -= 25
            reasons.append("EXACT_REPETITION")

        semantic_pairs = self._semantic_duplicates(sentences)
        if semantic_pairs:
            score -= 25
            reasons.append("SEMANTIC_REPETITION")

        score = max(0, score)
        if semantic_pairs is None:
            status: QualityStatus = "FAIL" if score < 60 else "REVIEW"
        elif score >= 85:
            status = "PASS"
        elif score >= 60:
            status = "REVIEW"
        else:
            status = "FAIL"
        return QualityResult(
            status,
            score,
            tuple(reasons),
            len(words),
            budget,
            semantic_pairs,
        )
