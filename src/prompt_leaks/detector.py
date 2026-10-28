"""Prompt secret detector."""

from __future__ import annotations

from dataclasses import dataclass
from bisect import bisect_right
import re
from typing import Literal, Protocol, Sequence

from .decoder import DecodedView, decoded_views
from .entropy import shannon_entropy
from .keywords import KeywordIndex
from .models import Allowlist, Finding, LivenessResult, Rule, ScanResult
from .presidio import PiiAnalyzer, PresidioScanConfig
from .validators import validate_candidate


class SecretVerifier(Protocol):
    """Internal verifier interface. Implementations must never retain secrets."""

    async def verify_many(
        self,
        targets: Sequence[tuple[str, str, int, int]],
        *,
        context: str,
    ) -> tuple[LivenessResult, ...]: ...


@dataclass(slots=True, repr=False)
class _Candidate:
    rule: Rule
    secret: str
    match: str
    source_start: int
    source_end: int
    entropy: float
    encodings: tuple[str, ...]
    confidence: float | None = None


class PromptLeakDetector:
    """Detect secrets in a prompt without retaining raw findings."""

    def __init__(
        self,
        rules: tuple[Rule, ...],
        *,
        global_allowlists: tuple[Allowlist, ...] = (),
        max_decode_depth: int = 1,
        max_prompt_chars: int = 100_000,
    ) -> None:
        if not rules:
            raise ValueError("at least one rule is required")
        if max_decode_depth < 0:
            raise ValueError("max_decode_depth must be non-negative")
        if max_prompt_chars <= 0:
            raise ValueError("max_prompt_chars must be positive")

        by_id = {rule.rule_id: rule for rule in rules}
        if len(by_id) != len(rules):
            raise ValueError("rule IDs must be unique")

        self._rules = by_id
        self._global_allowlists = global_allowlists
        self._max_decode_depth = max_decode_depth
        self._max_prompt_chars = max_prompt_chars
        self._always_rules = {rule.rule_id for rule in rules if not rule.keywords}
        self._keywords = KeywordIndex()
        for rule in rules:
            for keyword in rule.keywords:
                self._keywords.add(keyword, rule.rule_id)
        self._keywords.build()

    def scan(
        self,
        prompt: str,
        *,
        mode: Literal["block", "redact"] = "block",
        pii_analyzer: PiiAnalyzer | None = None,
        pii_config: PresidioScanConfig | None = None,
    ) -> ScanResult:
        """Scan one prompt and return only safe metadata and optional redacted text."""
        candidates = self._find_candidates(
            prompt,
            mode=mode,
            pii_analyzer=pii_analyzer,
            pii_config=pii_config,
        )
        findings = tuple(self._to_safe_finding(prompt, item) for item in candidates)
        return self._build_result(prompt, candidates, findings, mode=mode)

    async def scan_with_liveness(
        self,
        prompt: str,
        verifier: SecretVerifier,
        *,
        mode: Literal["block", "redact"] = "block",
        pii_analyzer: PiiAnalyzer | None = None,
        pii_config: PresidioScanConfig | None = None,
    ) -> ScanResult:
        """Scan and verify supported credentials without exposing their values."""
        candidates = self._find_candidates(
            prompt,
            mode=mode,
            pii_analyzer=pii_analyzer,
            pii_config=pii_config,
        )
        checks = await verifier.verify_many(
            tuple(
                (
                    item.rule.rule_id,
                    item.secret,
                    item.source_start,
                    item.source_end,
                )
                for item in candidates
            ),
            context=prompt,
        )
        findings = tuple(
            self._to_safe_finding(prompt, item, liveness=check)
            for item, check in zip(candidates, checks, strict=True)
        )
        return self._build_result(prompt, candidates, findings, mode=mode)

    def scan_messages(
        self,
        messages: Sequence[str],
        *,
        mode: Literal["block", "redact"] = "block",
        pii_analyzer: PiiAnalyzer | None = None,
        pii_config: PresidioScanConfig | None = None,
    ) -> ScanResult:
        """Scan one conversation, including credentials split across messages."""
        combined, starts, candidates = self._find_message_candidates(
            messages,
            mode=mode,
            pii_analyzer=pii_analyzer,
            pii_config=pii_config,
        )
        findings = tuple(
            self._to_safe_finding(combined, item, message_starts=starts)
            for item in candidates
        )
        return self._build_message_result(
            tuple(messages), starts, candidates, findings, mode=mode
        )

    async def scan_messages_with_liveness(
        self,
        messages: Sequence[str],
        verifier: SecretVerifier,
        *,
        mode: Literal["block", "redact"] = "block",
        pii_analyzer: PiiAnalyzer | None = None,
        pii_config: PresidioScanConfig | None = None,
    ) -> ScanResult:
        """Scan a conversation and verify supported credentials."""
        combined, starts, candidates = self._find_message_candidates(
            messages,
            mode=mode,
            pii_analyzer=pii_analyzer,
            pii_config=pii_config,
        )
        checks = await verifier.verify_many(
            tuple(
                (
                    item.rule.rule_id,
                    item.secret,
                    item.source_start,
                    item.source_end,
                )
                for item in candidates
            ),
            context=combined,
        )
        findings = tuple(
            self._to_safe_finding(
                combined,
                item,
                liveness=check,
                message_starts=starts,
            )
            for item, check in zip(candidates, checks, strict=True)
        )
        return self._build_message_result(
            tuple(messages), starts, candidates, findings, mode=mode
        )

    def _find_message_candidates(
        self,
        messages: Sequence[str],
        *,
        mode: Literal["block", "redact"],
        pii_analyzer: PiiAnalyzer | None,
        pii_config: PresidioScanConfig | None,
    ) -> tuple[str, tuple[int, ...], list[_Candidate]]:
        if isinstance(messages, (str, bytes)) or not messages:
            raise ValueError("messages must contain at least one prompt string")
        if any(not isinstance(message, str) for message in messages):
            raise TypeError("every message must be a string")
        starts: list[int] = []
        total = 0
        for message in messages:
            starts.append(total)
            total += len(message)
        if total > self._max_prompt_chars:
            raise ValueError(
                f"messages exceed max_prompt_chars={self._max_prompt_chars}"
            )
        combined = "".join(messages)
        return combined, tuple(starts), self._find_candidates(
            combined,
            mode=mode,
            pii_analyzer=pii_analyzer,
            pii_config=pii_config,
        )

    def _find_candidates(
        self,
        prompt: str,
        *,
        mode: Literal["block", "redact"],
        pii_analyzer: PiiAnalyzer | None = None,
        pii_config: PresidioScanConfig | None = None,
    ) -> list[_Candidate]:
        if not isinstance(prompt, str):
            raise TypeError("prompt must be a string")
        if len(prompt) > self._max_prompt_chars:
            raise ValueError(
                f"prompt exceeds max_prompt_chars={self._max_prompt_chars}"
            )
        if mode not in {"block", "redact"}:
            raise ValueError("mode must be 'block' or 'redact'")

        candidates = self._scan_view(
            prompt,
            DecodedView(prompt, 0, len(prompt), ()),
        )
        for view in decoded_views(prompt, self._max_decode_depth):
            candidates.extend(self._scan_view(prompt, view))
        if pii_analyzer is not None:
            candidates.extend(
                self._scan_pii(
                    prompt,
                    pii_analyzer,
                    pii_config or PresidioScanConfig(),
                )
            )
        return self._deduplicate(candidates)

    def _scan_pii(
        self,
        prompt: str,
        analyzer: PiiAnalyzer,
        config: PresidioScanConfig,
    ) -> list[_Candidate]:
        candidates: list[_Candidate] = []
        for entity in analyzer.analyze(prompt, config=config):
            if not 0 <= entity.start < entity.end <= len(prompt):
                continue
            secret = prompt[entity.start : entity.end]
            line = self._line_at(prompt, entity.start)
            if self._is_allowed(
                secret=secret,
                match=secret,
                line=line,
                allowlists=self._global_allowlists,
            ):
                continue
            normalized_type = re.sub(
                r"[^a-z0-9]+", "-", entity.entity_type.casefold()
            ).strip("-")
            if not normalized_type:
                continue
            candidates.append(
                _Candidate(
                    rule=Rule(
                        rule_id=f"presidio-{normalized_type}",
                        description=(
                            f"Microsoft Presidio detected {entity.entity_type} PII."
                        ),
                        regex=re.compile(r"(?!)"),
                        tags=("pii", "presidio", entity.entity_type.casefold()),
                        generic=True,
                        priority=30,
                        severity=self._presidio_severity(entity.entity_type),
                        confidence=entity.score,
                    ),
                    secret=secret,
                    match=secret,
                    source_start=entity.start,
                    source_end=entity.end,
                    entropy=shannon_entropy(secret),
                    encodings=(),
                    confidence=entity.score,
                )
            )
        return candidates

    @staticmethod
    def _presidio_severity(entity_type: str) -> Literal[
        "low", "medium", "high", "critical"
    ]:
        high_risk_markers = (
            "BANK",
            "CREDIT_CARD",
            "CRYPTO",
            "DRIVER_LICENSE",
            "HEALTH",
            "IBAN",
            "IDENTITY",
            "ITIN",
            "LICENSE",
            "MEDICAL",
            "NATIONAL_ID",
            "PASSPORT",
            "SSN",
            "TAX",
        )
        if any(marker in entity_type for marker in high_risk_markers):
            return "high"
        return "medium"

    @staticmethod
    def _build_result(
        prompt: str,
        candidates: list[_Candidate],
        findings: tuple[Finding, ...],
        *,
        mode: Literal["block", "redact"],
    ) -> ScanResult:

        if not findings:
            return ScanResult(
                detected=False,
                action="allow",
                sanitized_prompt=prompt if mode == "redact" else None,
            )

        if mode == "redact":
            sanitized = PromptLeakDetector._redact(prompt, candidates)
            return ScanResult(
                detected=True,
                action="redact",
                findings=findings,
                sanitized_prompt=sanitized,
            )

        return ScanResult(detected=True, action="block", findings=findings)

    @staticmethod
    def _build_message_result(
        messages: tuple[str, ...],
        starts: tuple[int, ...],
        candidates: list[_Candidate],
        findings: tuple[Finding, ...],
        *,
        mode: Literal["block", "redact"],
    ) -> ScanResult:
        if not findings:
            return ScanResult(
                detected=False,
                action="allow",
                sanitized_messages=messages if mode == "redact" else None,
            )
        if mode == "redact":
            return ScanResult(
                detected=True,
                action="redact",
                findings=findings,
                sanitized_messages=PromptLeakDetector._redact_messages(
                    messages, starts, candidates
                ),
            )
        return ScanResult(detected=True, action="block", findings=findings)

    def _scan_view(self, original_prompt: str, view: DecodedView) -> list[_Candidate]:
        selected = self._always_rules | self._keywords.matching_rules(view.text)
        candidates: list[_Candidate] = []

        for rule_id in selected:
            rule = self._rules[rule_id]
            for regex_match in rule.regex.finditer(view.text):
                group = self._select_group(rule, regex_match)
                if group is None:
                    continue
                secret, local_start, local_end = group
                entropy = shannon_entropy(secret)
                if rule.min_entropy and entropy <= rule.min_entropy:
                    continue
                if not validate_candidate(rule.validator, secret):
                    continue

                line = self._line_at(view.text, local_start)
                full_match = regex_match.group(0)
                if self._is_allowed(
                    secret=secret,
                    match=full_match,
                    line=line,
                    allowlists=self._global_allowlists + rule.allowlists,
                ):
                    continue

                if view.encodings:
                    source_start, source_end = view.origin_start, view.origin_end
                else:
                    source_start, source_end = local_start, local_end

                if source_start < 0 or source_end > len(original_prompt):
                    continue

                candidates.append(
                    _Candidate(
                        rule=rule,
                        secret=secret,
                        match=full_match,
                        source_start=source_start,
                        source_end=source_end,
                        entropy=entropy,
                        encodings=view.encodings,
                    )
                )

        return candidates

    @staticmethod
    def _select_group(rule: Rule, regex_match) -> tuple[str, int, int] | None:
        if rule.secret_group is not None:
            try:
                value = regex_match.group(rule.secret_group)
                start, end = regex_match.span(rule.secret_group)
            except (IndexError, KeyError):
                return None
            return (value, start, end) if value else None

        for index, value in enumerate(regex_match.groups(), start=1):
            if value:
                start, end = regex_match.span(index)
                return value, start, end

        return regex_match.group(0), regex_match.start(), regex_match.end()

    @staticmethod
    def _is_allowed(
        *,
        secret: str,
        match: str,
        line: str,
        allowlists: tuple[Allowlist, ...],
    ) -> bool:
        return any(
            allowlist.matches(secret=secret, match=match, line=line)
            for allowlist in allowlists
        )

    @staticmethod
    def _line_at(text: str, offset: int) -> str:
        start = text.rfind("\n", 0, offset) + 1
        end = text.find("\n", offset)
        if end < 0:
            end = len(text)
        return text[start:end]

    @staticmethod
    def _deduplicate(candidates: list[_Candidate]) -> list[_Candidate]:
        ordered = sorted(
            candidates,
            key=lambda item: (
                item.source_start,
                item.source_end,
                item.rule.generic,
                -item.rule.priority,
                item.rule.rule_id,
            ),
        )
        exact: dict[tuple[int, int], _Candidate] = {}
        for item in ordered:
            key = (item.source_start, item.source_end)
            current = exact.get(key)
            if current is None or (
                current.rule.generic and not item.rule.generic
            ) or item.rule.priority > current.rule.priority:
                exact[key] = item

        values = sorted(exact.values(), key=lambda item: item.source_start)
        output: list[_Candidate] = []
        for item in values:
            if item.rule.generic and any(
                not other.rule.generic
                and item.source_start < other.source_end
                and other.source_start < item.source_end
                for other in values
            ):
                continue
            output.append(item)
        return output

    @staticmethod
    def _to_safe_finding(
        prompt: str,
        candidate: _Candidate,
        *,
        liveness: LivenessResult | None = None,
        message_starts: tuple[int, ...] | None = None,
    ) -> Finding:
        start_line = prompt.count("\n", 0, candidate.source_start) + 1
        end_line = prompt.count("\n", 0, candidate.source_end) + 1
        line_start = prompt.rfind("\n", 0, candidate.source_start) + 1
        end_line_start = prompt.rfind("\n", 0, candidate.source_end) + 1
        start_message_index = None
        end_message_index = None
        confidence = (
            candidate.confidence
            if candidate.confidence is not None
            else candidate.rule.confidence
        )
        if message_starts is not None:
            start_message_index = max(
                0, bisect_right(message_starts, candidate.source_start) - 1
            )
            end_probe = max(candidate.source_start, candidate.source_end - 1)
            end_message_index = max(0, bisect_right(message_starts, end_probe) - 1)
            if start_message_index != end_message_index:
                confidence = max(0.0, confidence - 0.05)

        return Finding(
            rule_id=candidate.rule.rule_id,
            description=candidate.rule.description,
            start_offset=candidate.source_start,
            end_offset=candidate.source_end,
            start_line=start_line,
            end_line=end_line,
            start_column=candidate.source_start - line_start + 1,
            end_column=candidate.source_end - end_line_start + 1,
            entropy=candidate.entropy,
            severity=candidate.rule.severity,
            confidence=confidence,
            tags=candidate.rule.tags,
            encodings=candidate.encodings,
            liveness=liveness,
            start_message_index=start_message_index,
            end_message_index=end_message_index,
        )

    @staticmethod
    def _redact(prompt: str, candidates: list[_Candidate]) -> str:
        spans: list[tuple[int, int, set[str]]] = []
        for item in sorted(candidates, key=lambda value: (value.source_start, value.source_end)):
            if spans and item.source_start <= spans[-1][1]:
                start, end, rule_ids = spans[-1]
                spans[-1] = (
                    start,
                    max(end, item.source_end),
                    rule_ids | {item.rule.rule_id},
                )
            else:
                spans.append(
                    (item.source_start, item.source_end, {item.rule.rule_id})
                )

        output = prompt
        for start, end, rule_ids in reversed(spans):
            label = ",".join(sorted(rule_ids))
            output = output[:start] + f"[REDACTED:{label}]" + output[end:]
        return output

    @staticmethod
    def _redact_messages(
        messages: tuple[str, ...],
        starts: tuple[int, ...],
        candidates: list[_Candidate],
    ) -> tuple[str, ...]:
        spans_by_message: list[list[tuple[int, int, str]]] = [
            [] for _ in messages
        ]
        for item in candidates:
            label = f"[REDACTED:{item.rule.rule_id}]"
            for index, message in enumerate(messages):
                message_start = starts[index]
                message_end = message_start + len(message)
                overlap_start = max(item.source_start, message_start)
                overlap_end = min(item.source_end, message_end)
                if overlap_start < overlap_end:
                    spans_by_message[index].append(
                        (
                            overlap_start - message_start,
                            overlap_end - message_start,
                            label,
                        )
                    )

        sanitized: list[str] = []
        for message, spans in zip(messages, spans_by_message, strict=True):
            output = message
            for start, end, label in sorted(spans, reverse=True):
                output = output[:start] + label + output[end:]
            sanitized.append(output)
        return tuple(sanitized)

