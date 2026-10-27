"""Bounded decoding of text-like encoded prompt segments."""

from __future__ import annotations

import base64
import binascii
import re
from collections import deque
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes


_PERCENT = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_HEX = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")
_BASE64 = re.compile(
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_-])"
)


@dataclass(frozen=True, slots=True)
class DecodedView:
    text: str
    origin_start: int
    origin_end: int
    encodings: tuple[str, ...]


def decoded_views(prompt: str, max_depth: int) -> tuple[DecodedView, ...]:
    """Return decoded views mapped back to the encoded span in the prompt."""
    if max_depth <= 0:
        return ()

    results: list[DecodedView] = []
    queue: deque[tuple[str, int, int, tuple[str, ...], int]] = deque(
        [(prompt, 0, len(prompt), (), 0)]
    )
    seen: set[tuple[int, int, str]] = set()

    while queue:
        text, parent_start, parent_end, chain, depth = queue.popleft()
        if depth >= max_depth:
            continue

        for start, end, decoded, encoding in _decode_candidates(text):
            if chain:
                origin_start, origin_end = parent_start, parent_end
            else:
                origin_start, origin_end = start, end

            marker = (origin_start, origin_end, decoded)
            if marker in seen:
                continue
            seen.add(marker)

            next_chain = chain + (encoding,)
            view = DecodedView(decoded, origin_start, origin_end, next_chain)
            results.append(view)
            queue.append((decoded, origin_start, origin_end, next_chain, depth + 1))

    return tuple(results)


def _decode_candidates(text: str):
    spans: set[tuple[int, int, str]] = set()

    for match in _PERCENT.finditer(text):
        decoded = _decode_text(unquote_to_bytes(match.group(0)))
        if decoded is not None:
            marker = (match.start(), match.end(), decoded)
            if marker not in spans:
                spans.add(marker)
                yield match.start(), match.end(), decoded, "percent"

    for match in _HEX.finditer(text):
        value = match.group(0)
        if len(value) % 2:
            continue
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            continue
        decoded = _decode_text(raw)
        if decoded is not None:
            marker = (match.start(), match.end(), decoded)
            if marker not in spans:
                spans.add(marker)
                yield match.start(), match.end(), decoded, "hex"

    for match in _BASE64.finditer(text):
        value = match.group(0)
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        try:
            raw = base64.b64decode(padded, altchars=b"-_", validate=False)
        except (binascii.Error, ValueError):
            continue
        decoded = _decode_text(raw)
        if decoded is not None:
            marker = (match.start(), match.end(), decoded)
            if marker not in spans:
                spans.add(marker)
                yield match.start(), match.end(), decoded, "base64"


def _decode_text(raw: bytes) -> str | None:
    if len(raw) < 6 or b"\x00" in raw:
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(char.isprintable() or char in "\r\n\t" for char in decoded)
    if printable / max(len(decoded), 1) < 0.9:
        return None
    return decoded

