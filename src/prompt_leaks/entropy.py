"""Entropy helpers."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy in bits per character."""
    if not value:
        return 0.0
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(value).values()
    )

