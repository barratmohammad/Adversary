# Roman numerals

Implement in `roman.py`:

```python
def to_roman(n: int) -> str: ...
def from_roman(s: str) -> int: ...
```

## `to_roman(n)`
- Returns the canonical uppercase Roman numeral for `n`, using I=1, V=5, X=10, L=50, C=100, D=500, M=1000 and only the subtractive pairs IV, IX, XL, XC, CD, CM (e.g. 4 is `"IV"`, never `"IIII"`).
- Valid range is **1..3999 inclusive**. Any other int (0, negatives, 4000+) raises `ValueError`.
- `n` must be an `int`; any other type (including `bool`, `float`, `str`) raises `TypeError`.

## `from_roman(s)`
- Strict inverse of `to_roman`: returns `n` if and only if `s == to_roman(n)` for some `n` in 1..3999.
- Every other string raises `ValueError`. This includes the empty string, lowercase (`"iv"`), any whitespace (`" X"`, `"X\n"`), non-canonical forms (`"IIII"`, `"VV"`, `"IC"`, `"XM"`, `"IXI"`), values above 3999 (`"MMMM"`) and unknown characters.
- `s` must be a `str`; any other type raises `TypeError`.

## Invariants
- `from_roman(to_roman(n)) == n` for every `n` in 1..3999.
- `to_roman(from_roman(s)) == s` for every string `s` that `from_roman` accepts.
- Every result of `from_roman` is an int in 1..3999.

## Examples
- `to_roman(4) == "IV"`
- `to_roman(1994) == "MCMXCIV"`
- `to_roman(3999) == "MMMCMXCIX"`
- `from_roman("LVIII") == 58`
- `from_roman("IIII")` raises `ValueError`
- `to_roman(0)` raises `ValueError`
