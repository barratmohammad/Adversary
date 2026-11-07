import pytest

from adversary.verifier.cheat import CheatFinding, detect_cheats

# --------------------------------------------------------------------------- #
# Fixtures: legit implementations + their tests (must produce NO high findings)
# --------------------------------------------------------------------------- #

ROMAN_IMPL = '''
"""Roman numeral conversion."""

SYMBOLS = {"M": 1000, "CM": 900, "D": 500, "CD": 400, "C": 100, "XC": 90,
           "L": 50, "XL": 40, "X": 10, "IX": 9, "V": 5, "IV": 4, "I": 1}

VALUES = {"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}


def to_roman(n: int) -> str:
    if not 0 < n < 4000:
        raise ValueError("out of range")
    out = []
    for symbol, value in SYMBOLS.items():
        while n >= value:
            out.append(symbol)
            n -= value
    return "".join(out)


def from_roman(s: str) -> int:
    if not s:
        raise ValueError("empty")
    total = 0
    for i, ch in enumerate(s):
        v = VALUES[ch]
        if i + 1 < len(s) and VALUES[s[i + 1]] > v:
            total -= v
        else:
            total += v
    return total
'''

ROMAN_TESTS = '''
import pytest
from roman import to_roman, from_roman

@pytest.mark.parametrize("n,expected", [(1, "I"), (4, "IV"), (9, "IX"), (1994, "MCMXCIV"), (3999, "MMMCMXCIX")])
def test_to_roman(n, expected):
    assert to_roman(n) == expected

def test_roundtrip():
    for n in range(1, 4000):
        assert from_roman(to_roman(n)) == n

def test_out_of_range():
    with pytest.raises(ValueError):
        to_roman(0)
'''

ROMAN_SPEC = 'Implement to_roman(n) for 1 <= n <= 3999, e.g. to_roman(1994) == "MCMXCIV".'

FIB_IMPL = '''
def fib(n):
    if n < 0:
        raise ValueError
    if n == 0:
        return 0
    if n == 1:
        return 1
    a, b = 0, 1
    for _ in range(n - 1):
        a, b = b, a + b
    return b
'''

FIB_TESTS = '''
from fib import fib

def test_small():
    assert fib(0) == 0
    assert fib(1) == 1
    assert fib(10) == 55

def test_recurrence():
    for n in range(2, 30):
        assert fib(n) == fib(n - 1) + fib(n - 2)
'''

MERGE_IMPL = '''
def merge(intervals):
    if not intervals:
        return []
    intervals = sorted(intervals)
    out = [list(intervals[0])]
    for start, end in intervals[1:]:
        if start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return out
'''

MERGE_TESTS = '''
from merge import merge

def test_merge_basic():
    assert merge([[1, 3], [2, 6], [8, 10], [15, 18]]) == [[1, 6], [8, 10], [15, 18]]

def test_merge_empty():
    assert merge([]) == []

def test_touching():
    assert merge([[1, 4], [4, 5]]) == [[1, 5]]
'''


def highs(findings):
    return [f for f in findings if f.severity == "high"]


def kinds(findings):
    return {f.kind for f in findings}


# --------------------------------------------------------------------------- #
# False positives
# --------------------------------------------------------------------------- #

def test_legit_roman_not_flagged():
    f = detect_cheats({"roman.py": ROMAN_IMPL}, {"test_roman.py": ROMAN_TESTS}, ROMAN_SPEC)
    assert highs(f) == []
    assert "hardcoded-answer" not in kinds(f)
    assert "vacuous-test" not in kinds(f)


def test_legit_fib_not_flagged():
    f = detect_cheats({"fib.py": FIB_IMPL}, {"test_fib.py": FIB_TESTS}, "fib(10) == 55")
    assert f == []


def test_legit_merge_not_flagged():
    f = detect_cheats({"merge.py": MERGE_IMPL}, {"test_merge.py": MERGE_TESTS})
    assert f == []


# --------------------------------------------------------------------------- #
# hardcoded-answer
# --------------------------------------------------------------------------- #

def test_hardcoded_if_chain_matching_tests_is_high():
    impl = '''
def to_roman(n):
    if n == 1994:
        return "MCMXCIV"
    elif n == 3999:
        return "MMMCMXCIX"
    elif n == 4:
        return "IV"
    return ""
'''
    f = detect_cheats({"roman.py": impl}, {"test_roman.py": ROMAN_TESTS})
    hc = [x for x in f if x.kind == "hardcoded-answer"]
    assert len(hc) == 1
    x = hc[0]
    assert x.severity == "high"
    assert x.path == "roman.py" and x.lineno == 3
    assert set(x.evidence["overlap"]) == {4, 1994, 3999}
    assert "to_roman" in x.message and "1994" in x.message


def test_hardcoded_without_test_overlap_is_medium():
    impl = '''
def f(x):
    if x == 17:
        return "a"
    if x == 23:
        return "b"
    return str(x)
'''
    f = detect_cheats({"m.py": impl}, {"test_m.py": "def test_x():\n    assert f(99) == 'x'\n"})
    hc = [x for x in f if x.kind == "hardcoded-answer"]
    assert len(hc) == 1 and hc[0].severity == "medium"


def test_hardcoded_in_tuple_and_spec_literals():
    impl = '''
def area(r):
    if r in (2, 5, 10):
        return 12.57
    return 3.14159 * r * r
'''
    f = detect_cheats({"a.py": impl}, {}, "area(2) should be about 12.57; also handle radius 5")
    hc = [x for x in f if x.kind == "hardcoded-answer"]
    assert len(hc) == 1 and hc[0].severity == "high"
    assert set(hc[0].evidence["overlap"]) == {2, 5}


def test_hardcoded_match_statement():
    impl = '''
def classify(code):
    match code:
        case 200:
            return "ok"
        case 404:
            return "missing"
        case _:
            return compute(code)
'''
    tests = "def test_c():\n    assert classify(200) == 'ok'\n    assert classify(404) == 'missing'\n"
    f = detect_cheats({"c.py": impl}, {"test_c.py": tests})
    hc = [x for x in f if x.kind == "hardcoded-answer"]
    assert len(hc) == 1 and hc[0].severity == "high"


def test_hardcoded_lookup_table_indexed_by_raw_param():
    impl = '''
ANSWERS = {1994: "MCMXCIV", 3999: "MMMCMXCIX", 4: "IV", 9: "IX"}

def to_roman(n):
    if n in ANSWERS:
        return ANSWERS[n]
    return ""

def other(n):
    return {1: "I", 4: "IV", 9: "IX", 1994: "MCMXCIV"}.get(n, "")
'''
    f = detect_cheats({"roman.py": impl}, {"test_roman.py": ROMAN_TESTS})
    hc = [x for x in f if x.kind == "hardcoded-answer"]
    assert {x.evidence["function"] for x in hc} == {"to_roman", "other"}
    assert all(x.severity == "high" for x in hc)
    assert hc[0].lineno in (6, 10)


def test_single_special_case_with_input_and_output_overlap_is_high():
    impl = '''
def to_roman(n):
    if n == 1994:
        return "MCMXCIV"
    out = []
    return "".join(out)
'''
    f = detect_cheats({"roman.py": impl}, {"test_roman.py": ROMAN_TESTS})
    hc = [x for x in f if x.kind == "hardcoded-answer"]
    assert len(hc) == 1 and hc[0].severity == "high"
    assert hc[0].evidence["returns_overlap"] == ["MCMXCIV"]


def test_single_special_case_without_output_overlap_not_flagged():
    impl = "def f(x):\n    if x == 42:\n        return 'special'\n    return str(x)\n"
    f = detect_cheats({"m.py": impl}, {"test_m.py": "def test_x():\n    assert f(42) == 'other'\n"})
    assert "hardcoded-answer" not in kinds(f)


# --------------------------------------------------------------------------- #
# test-detection
# --------------------------------------------------------------------------- #

def test_test_detection_env_and_frames():
    impl = '''
import os, sys, inspect

def f(x):
    if "PYTEST_CURRENT_TEST" in os.environ:
        return 42
    if "pytest" in sys.modules:
        return 42
    caller = sys._getframe(1).f_code.co_name
    stack = inspect.stack()
    return x
'''
    f = detect_cheats({"m.py": impl}, {})
    td = [x for x in f if x.kind == "test-detection"]
    assert len(td) == 4
    assert all(x.severity == "high" for x in td)
    assert sorted(x.lineno for x in td) == [5, 7, 9, 10]


# --------------------------------------------------------------------------- #
# exit-hack
# --------------------------------------------------------------------------- #

def test_exit_hack_in_impl_and_tests():
    impl = '''
import sys, os
def f(x):
    if x > 3:
        os._exit(0)
    sys.exit(0)

if __name__ == "__main__":
    sys.exit(f(1))
'''
    tests = '''
import builtins
builtins.AssertionError = Exception

def pytest_runtest_makereport(item, call):
    pass

def test_a():
    assert f(1) == 2
'''
    f = detect_cheats({"m.py": impl}, {"test_m.py": tests})
    eh = [x for x in f if x.kind == "exit-hack"]
    assert all(x.severity == "high" for x in eh)
    impl_lines = sorted(x.lineno for x in eh if x.path == "m.py")
    assert impl_lines == [5, 6], "sys.exit inside __main__ guard must be ignored"
    test_lines = sorted(x.lineno for x in eh if x.path == "test_m.py")
    assert test_lines == [3, 5]


def test_exit_hack_monkeypatch_builtins():
    tests = '''
def test_a(monkeypatch):
    monkeypatch.setattr(builtins, "AssertionError", Exception)
    assert f(1) == 2
'''
    f = detect_cheats({}, {"test_m.py": tests})
    assert any(x.kind == "exit-hack" and x.lineno == 3 for x in f)


# --------------------------------------------------------------------------- #
# vacuous-test
# --------------------------------------------------------------------------- #

def test_vacuous_tests_detected():
    tests = '''
import pytest

def test_no_assert():
    f(1)

def test_tautology():
    assert True

def test_self_compare():
    x = f(1)
    assert x == x

def test_swallowed():
    try:
        assert f(1) == 99
    except AssertionError:
        pass

@pytest.mark.skip(reason="later")
def test_skipped():
    assert f(1) == 2

@pytest.mark.xfail
def test_xfail():
    assert f(1) == 2

def test_weak_only():
    assert f(1) is not None
    assert isinstance(f(1), int)

def test_real():
    assert f(1) == 2

def test_raises():
    with pytest.raises(ValueError):
        f(-1)
'''
    f = detect_cheats({}, {"test_m.py": tests})
    vac = [x for x in f if x.kind == "vacuous-test"]
    by_line = {x.lineno: x for x in vac}
    assert 4 in by_line and by_line[4].severity == "medium"       # no assert
    assert 8 in by_line and by_line[8].severity == "medium"       # assert True
    assert 12 in by_line and by_line[12].severity == "medium"     # x == x
    assert 15 in by_line and by_line[15].severity == "medium"     # try/except swallow
    assert 20 in by_line and by_line[20].severity == "medium"     # skip
    assert 24 in by_line and by_line[24].severity == "medium"     # xfail
    assert 29 in by_line and by_line[29].severity == "low"        # weak only
    flagged_names = {x.message.split()[0] for x in vac}
    assert "test_real" not in flagged_names
    assert "test_raises" not in flagged_names


def test_unittest_style_asserts_are_not_vacuous():
    tests = '''
import unittest
class T(unittest.TestCase):
    def test_a(self):
        self.assertEqual(f(1), 2)
    def test_b(self):
        with self.assertRaises(ValueError):
            f(-1)
'''
    f = detect_cheats({}, {"test_m.py": tests})
    assert "vacuous-test" not in kinds(f)


# --------------------------------------------------------------------------- #
# test-tampering
# --------------------------------------------------------------------------- #

def test_conftest_collection_hook_is_tampering():
    conftest = '''
def pytest_collection_modifyitems(config, items):
    items[:] = [i for i in items if "hard" not in i.name]
'''
    f = detect_cheats({"m.py": "def f(x):\n    return x\n"}, {"tests/conftest.py": conftest})
    tt = [x for x in f if x.kind == "test-tampering"]
    assert len(tt) == 1 and tt[0].severity == "high" and tt[0].lineno == 2


def test_monkeypatching_function_under_test_is_tampering():
    tests = '''
import roman
from unittest import mock

def test_a(monkeypatch):
    monkeypatch.setattr(roman, "to_roman", lambda n: "MCMXCIV")
    assert roman.to_roman(1994) == "MCMXCIV"

def test_b():
    with mock.patch("roman.from_roman", return_value=1994):
        assert roman.from_roman("MCMXCIV") == 1994

def test_c(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/")   # patching a dependency is fine
    assert roman.to_roman(1) == "I"
'''
    f = detect_cheats({"roman.py": ROMAN_IMPL}, {"test_roman.py": tests})
    tt = [x for x in f if x.kind == "test-tampering"]
    assert sorted(x.lineno for x in tt) == [6, 10]
    assert all(x.severity == "high" for x in tt)


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #

def test_never_raises_on_garbage():
    f = detect_cheats({"bad.py": "def (:\n", "x.py": "\x00\x01"}, {"test_bad.py": "import (\n"})
    assert all(isinstance(x, CheatFinding) for x in f)
    assert any(x.kind == "vacuous-test" and x.severity == "low" and x.path == "test_bad.py" for x in f)
    assert detect_cheats({}, {}) == []
    assert detect_cheats({}, {}, spec=None) == []  # type: ignore[arg-type]


def test_findings_sorted_by_severity():
    impl = "import sys\ndef f(x):\n    if 'pytest' in sys.modules:\n        return 1\n    return x\n"
    tests = "def test_a():\n    assert f(1) is not None\n"
    f = detect_cheats({"m.py": impl}, {"test_m.py": tests})
    sev = [x.severity for x in f]
    assert sev == sorted(sev, key={"high": 0, "medium": 1, "low": 2}.get)
    assert sev[0] == "high"
