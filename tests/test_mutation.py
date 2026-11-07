import ast

import pytest

from adversary.verifier.mutation import Mutant, generate_mutants

SAMPLE = '''
"""Module docstring with 42 and 'text' that must not be mutated."""
from typing import List

SYMBOLS = {"M": 1000, "D": 500}


@some_decorator(3)
def f(xs: List[int], k: int = 2) -> int:
    """Function docstring: 7 < 8."""
    total = 0
    for i, x in enumerate(xs):
        if x < 0 and i != k:
            continue
        if x > 10:
            break
        total += x * 2 - xs[0] + xs[-1] // 3
    if not xs:
        return -1
    if total == 5 or total in (1, 2):
        return xs[1:3][0]
    if xs is None or xs is not SYMBOLS:
        return 0
    flag = True
    name = "hello"
    return total


if __name__ == "__main__":
    print(f([1, 2, 3]) + 99)
'''


@pytest.fixture(scope="module")
def mutants():
    return generate_mutants("sample.py", SAMPLE)


def test_returns_mutant_dataclasses(mutants):
    assert mutants
    assert all(isinstance(m, Mutant) for m in mutants)
    for m in mutants:
        assert m.path == "sample.py"
        assert m.id.startswith(f"sample.py:{m.lineno}:{m.col}:{m.op}:")
        assert m.description.endswith(f"at line {m.lineno}")


def test_every_mutant_compiles_and_differs(mutants):
    original = ast.unparse(ast.parse(SAMPLE))
    for m in mutants:
        compile(m.source, m.path, "exec")  # must not raise
        assert m.source != original, m.id


def test_ids_unique_and_sources_unique(mutants):
    ids = [m.id for m in mutants]
    assert len(ids) == len(set(ids))
    sources = [m.source for m in mutants]
    assert len(sources) == len(set(sources))


def test_sorted_by_position(mutants):
    keys = [(m.lineno, m.col, m.id) for m in mutants]
    assert keys == sorted(keys)


def test_deterministic_full():
    a = generate_mutants("sample.py", SAMPLE)
    b = generate_mutants("sample.py", SAMPLE)
    assert a == b


def test_operator_coverage(mutants):
    ops = {m.op for m in mutants}
    assert {"AOR", "ROR", "LCR", "UOI", "CRP", "RVR", "AAR", "SBR", "IDX"} <= ops

    details = {m.id.split(":", 4)[4] for m in mutants}
    # arithmetic
    assert {"+->-", "-->+", "*->/", "//->/"} <= details
    # relational
    assert {"<-><=", "<->>", ">->>=", ">-><", "==->!=", "!=->==", "in->not in",
            "is->is not", "is not->is"} <= details
    # boolean / not
    assert {"and->or", "or->and", "del-not"} <= details
    # constants
    assert {"True->False", "str->empty", "10->11", "10->9"} <= details
    # augmented assign / break / continue
    assert {"+=->-=", "break->continue", "continue->break"} <= details
    # subscript off-by-one incl. slices and negative indices
    assert {"index:0->1", "index:0->-1", "index:-1->0", "index:-1->-2",
            "lower:1->2", "lower:1->0", "upper:3->4", "upper:3->2"} <= details
    # return value replacement, but never for bare `return`
    assert "ret-None" in details


def test_skips_docstrings_main_guard_annotations_decorators(mutants):
    lines = {m.lineno for m in mutants}
    assert 2 not in lines, "module docstring mutated"
    assert 10 not in lines, "function docstring mutated"
    assert 8 not in lines, "decorator mutated"
    assert not any(ln >= 29 for ln in lines), "__main__ block mutated"
    # the annotation `List[int]` lives on the def line; nothing on it except default arg `2`
    for m in mutants:
        if m.lineno == 9:
            assert m.op == "CRP" and m.description.startswith("replaced 2 with")
    # the mutated sources never touch the docstring text
    for m in mutants:
        assert "Module docstring with 42" in m.source


def test_bare_return_and_return_none_not_mutated():
    src = "def g(x):\n    if x:\n        return\n    return None\n"
    assert all(m.op != "RVR" for m in generate_mutants("g.py", src))


def test_max_mutants_sampling_is_deterministic_and_sorted():
    full = generate_mutants("sample.py", SAMPLE)
    assert len(full) > 12
    a = generate_mutants("sample.py", SAMPLE, max_mutants=12, seed=7)
    b = generate_mutants("sample.py", SAMPLE, max_mutants=12, seed=7)
    assert a == b
    assert len(a) == 12
    assert [(m.lineno, m.col, m.id) for m in a] == sorted((m.lineno, m.col, m.id) for m in a)
    assert set(a) <= set(full)
    c = generate_mutants("sample.py", SAMPLE, max_mutants=12, seed=8)
    assert len(c) == 12
    assert c != a, "different seeds should (almost surely) give different samples"


def test_sampling_spreads_across_functions():
    src = "\n".join(
        f"def f{i}(x):\n    return x + {i} * 2 - 1\n" for i in range(6)
    )
    picked = generate_mutants("many.py", src, max_mutants=6, seed=1)
    assert len(picked) == 6
    funcs_hit = {m.lineno // 2 for m in picked}  # each function spans 2 lines
    assert len(funcs_hit) == 6, "sample should touch every function"


def test_max_mutants_larger_than_candidates_returns_all():
    full = generate_mutants("sample.py", SAMPLE)
    assert generate_mutants("sample.py", SAMPLE, max_mutants=10_000) == full
    assert generate_mutants("sample.py", SAMPLE, max_mutants=0) == []


def test_invalid_source_returns_empty():
    assert generate_mutants("bad.py", "def (:\n") == []
    assert generate_mutants("empty.py", "") == []


def test_mutant_actually_changes_behaviour():
    src = "def add(a, b):\n    return a + b\n"
    ms = generate_mutants("add.py", src)
    aor = [m for m in ms if m.op == "AOR"]
    assert len(aor) == 1
    ns: dict = {}
    exec(aor[0].source, ns)
    assert ns["add"](2, 3) == -1
