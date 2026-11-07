import pytest

from overclock import harness
from overclock.tasks import ALL, load

FAST_MEMBERSHIP = """
def membership(pool, queries):
    s = set(pool)
    return sum(1 for q in queries if q in s)
"""

WRONG_MEMBERSHIP = """
def membership(pool, queries):
    s = set(pool)
    return sum(1 for q in set(queries) if q in s)   # drops repeats: wrong
"""

CRASHING = """
def membership(pool, queries):
    raise ValueError("boom")
"""


def test_slow_vs_slow_is_correct_and_about_1x():
    task = load("t02_membership")
    src = task.public_source
    res = harness.benchmark(task, src, repeats=3)
    assert res.correct and res.error is None
    assert 0.5 < res.speedup < 2.0


def test_correct_rewrite_gets_speedup():
    task = load("t02_membership")
    res = harness.benchmark(task, FAST_MEMBERSHIP, repeats=3)
    assert res.correct
    assert res.speedup > 5


def test_wrong_rewrite_is_caught_and_never_timed():
    task = load("t02_membership")
    res = harness.benchmark(task, WRONG_MEMBERSHIP)
    assert not res.correct
    assert res.mismatches
    assert res.speedup is None


def test_crash_is_reported():
    task = load("t02_membership")
    res = harness.benchmark(task, CRASHING)
    assert not res.correct
    assert "runtime error" in res.error


@pytest.mark.parametrize("name", ALL)
def test_every_task_runs_and_is_deterministic(name):
    task = load(name)
    a = task.gen_inputs(7, 3)
    b = task.gen_inputs(7, 3)
    assert a == b
    ok, mism, err = harness.check_correctness(task, task.public_source, n=2)
    assert ok and not mism and err is None
