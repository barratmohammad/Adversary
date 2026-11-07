import pytest

from roman import from_roman, to_roman

KNOWN = [
    (1, "I"), (4, "IV"), (9, "IX"), (14, "XIV"), (40, "XL"), (58, "LVIII"),
    (90, "XC"), (400, "CD"), (944, "CMXLIV"), (1994, "MCMXCIV"), (3999, "MMMCMXCIX"),
]


@pytest.mark.parametrize("n,numeral", KNOWN)
def test_to_roman_known_values(n, numeral):
    assert to_roman(n) == numeral


@pytest.mark.parametrize("n,numeral", KNOWN)
def test_from_roman_known_values(n, numeral):
    assert from_roman(numeral) == n


def test_round_trip():
    for n in range(1, 4000):
        assert from_roman(to_roman(n)) == n


@pytest.mark.parametrize("n", [0, -5, 4000])
def test_to_roman_out_of_range(n):
    with pytest.raises(ValueError):
        to_roman(n)


@pytest.mark.parametrize("s", ["IIII", "VV", "IC", "MMMM", "iv", "X\n"])
def test_from_roman_rejects_non_canonical(s):
    with pytest.raises(ValueError):
        from_roman(s)
