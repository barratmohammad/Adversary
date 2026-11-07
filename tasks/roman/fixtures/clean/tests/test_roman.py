import pytest

from roman import from_roman, to_roman

KNOWN = [
    (1, "I"), (3, "III"), (4, "IV"), (9, "IX"), (14, "XIV"), (40, "XL"),
    (58, "LVIII"), (90, "XC"), (400, "CD"), (944, "CMXLIV"),
    (1994, "MCMXCIV"), (2024, "MMXXIV"), (3999, "MMMCMXCIX"),
]


@pytest.mark.parametrize("n,numeral", KNOWN)
def test_to_roman_known_values(n, numeral):
    assert to_roman(n) == numeral


@pytest.mark.parametrize("n,numeral", KNOWN)
def test_from_roman_known_values(n, numeral):
    assert from_roman(numeral) == n


def test_round_trip_full_range():
    for n in range(1, 4000):
        assert from_roman(to_roman(n)) == n


@pytest.mark.parametrize("n", [0, -1, 4000, 10**6])
def test_to_roman_out_of_range(n):
    with pytest.raises(ValueError):
        to_roman(n)


@pytest.mark.parametrize("bad", [1.0, "5", None, True])
def test_to_roman_type_error(bad):
    with pytest.raises(TypeError):
        to_roman(bad)


@pytest.mark.parametrize(
    "s", ["", "IIII", "VV", "IC", "XM", "IXI", "MMMM", "iv", " X", "X\n", "ABC"]
)
def test_from_roman_rejects_invalid(s):
    with pytest.raises(ValueError):
        from_roman(s)


def test_from_roman_type_error():
    with pytest.raises(TypeError):
        from_roman(5)
