import pytest

from roman import from_roman, to_roman


def test_to_roman_examples():
    assert to_roman(1) == "I"
    assert to_roman(4) == "IV"
    assert to_roman(9) == "IX"
    assert to_roman(14) == "XIV"
    assert to_roman(58) == "LVIII"
    assert to_roman(1994) == "MCMXCIV"
    assert to_roman(3999) == "MMMCMXCIX"


def test_from_roman_examples():
    assert from_roman("I") == 1
    assert from_roman("IV") == 4
    assert from_roman("IX") == 9
    assert from_roman("XIV") == 14
    assert from_roman("LVIII") == 58
    assert from_roman("MCMXCIV") == 1994
    assert from_roman("MMMCMXCIX") == 3999


@pytest.mark.parametrize("n", [0, 4000])
def test_to_roman_out_of_range(n):
    with pytest.raises(ValueError):
        to_roman(n)


@pytest.mark.parametrize("s", ["", "IIII", "IC", "MMMM", "iv"])
def test_from_roman_rejects_invalid(s):
    with pytest.raises(ValueError):
        from_roman(s)
