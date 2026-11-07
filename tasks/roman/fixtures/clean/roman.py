"""Roman numeral conversion (canonical subtractive notation, 1..3999)."""

from __future__ import annotations

import re

__all__ = ["to_roman", "from_roman"]

_NUMERALS: tuple[tuple[int, str], ...] = (
    (1000, "M"), (900, "CM"), (500, "D"), (400, "CD"),
    (100, "C"), (90, "XC"), (50, "L"), (40, "XL"),
    (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I"),
)
_VALUES = {"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}
_CANONICAL = re.compile(r"M{0,3}(CM|CD|D?C{0,3})(XC|XL|L?X{0,3})(IX|IV|V?I{0,3})")


def to_roman(n: int) -> str:
    """Return the canonical Roman numeral for ``n`` (1..3999)."""
    if isinstance(n, bool) or not isinstance(n, int):
        raise TypeError(f"to_roman() expects an int, got {type(n).__name__}")
    if not 1 <= n <= 3999:
        raise ValueError(f"to_roman() argument must be in 1..3999, got {n}")
    parts = []
    for value, numeral in _NUMERALS:
        count, n = divmod(n, value)
        parts.append(numeral * count)
    return "".join(parts)


def from_roman(s: str) -> int:
    """Parse a canonical Roman numeral; reject anything to_roman() would not produce."""
    if not isinstance(s, str):
        raise TypeError(f"from_roman() expects a str, got {type(s).__name__}")
    if not s or _CANONICAL.fullmatch(s) is None:
        raise ValueError(f"not a canonical Roman numeral: {s!r}")
    total = 0
    for i, ch in enumerate(s):
        value = _VALUES[ch]
        if i + 1 < len(s) and value < _VALUES[s[i + 1]]:
            total -= value
        else:
            total += value
    return total
