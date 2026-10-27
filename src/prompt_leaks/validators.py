"""Deterministic validators used after a rule finds a candidate."""

from __future__ import annotations

import re
from typing import Literal


ValidatorName = Literal["iban", "luhn"]
SUPPORTED_VALIDATORS: frozenset[str] = frozenset({"iban", "luhn"})


def validate_candidate(validator: ValidatorName | None, value: str) -> bool:
    """Return whether a regex candidate passes its configured checksum."""
    if validator is None:
        return True
    if validator == "luhn":
        return _valid_luhn(value)
    if validator == "iban":
        return _valid_iban(value)
    return False


def _valid_luhn(value: str) -> bool:
    digits = re.sub(r"[ -]", "", value)
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False

    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        number = int(character)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _valid_iban(value: str) -> bool:
    compact = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}", compact):
        return False

    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for character in rearranged:
        expanded = character if character.isdigit() else str(ord(character) - 55)
        for digit in expanded:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1
