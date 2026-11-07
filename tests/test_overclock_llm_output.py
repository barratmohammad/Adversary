"""Realistic LLM reply shapes through the optimizer's extractor and the reflect cleaner (no model calls)."""
from overclock import harness, loop, optimizer, reflect
from overclock.tasks import load

FAST = "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n"
SLOW = "def fib(n):\n    def f(k):\n        return k if k < 2 else f(k - 1) + f(k - 2)\n    return f(n)\n"


def test_before_after_echo_picks_the_rewrite():
    text = f"Before:\n```python\n{SLOW}```\nAfter:\n```python\n{FAST}```\n"
    assert optimizer.extract_code(text, "fib") == FAST


def test_helper_block_above_is_kept():
    text = "Helper:\n```python\nfrom functools import lru_cache\n```\nMain:\n```python\n@lru_cache(None)\n" + FAST + "```"
    src = optimizer.extract_code(text, "fib")
    assert src.startswith("from functools import lru_cache") and "@lru_cache(None)\ndef fib" in src


def test_odd_fence_tags_and_truncated_reply():
    assert optimizer.extract_code(f"```Python\n{FAST}```", "fib") == FAST
    assert optimizer.extract_code(f"```python3\n{FAST}```", "fib") == FAST
    assert optimizer.extract_code(f"Here you go:\n```python\n{FAST}", "fib") == FAST      # unclosed fence


def test_prose_mentioning_the_signature_is_not_code():
    assert optimizer.extract_code("I would rewrite def fib(n) iteratively but cannot.", "fib") is None
    assert optimizer.extract_code(f"```python\ndef fibonacci(n):\n    return 1\n```", "fib") is None


def test_bare_code_without_fences_is_accepted():
    assert optimizer.extract_code(FAST, "fib") == FAST


def test_clean_rule_strips_prefixes_and_takes_last_paragraph():
    assert reflect.clean_rule("Here is the rule:\n\n**Rule:** When a list is only used for membership, build a set first.") \
        == "When a list is only used for membership, build a set first."
    assert reflect.clean_rule("1. Hoist loop-invariant work.") == "Hoist loop-invariant work."
    assert reflect.clean_rule('- "Use join for string building."') == "Use join for string building."


def test_legit_exponential_to_linear_rewrite_is_not_a_timing_cheat():
    t = load("t01_fib")
    flagged = 0
    for _ in range(3):
        r = harness.benchmark(t, FAST, repeats=3)
        assert r.correct and r.speedup > 50
        flagged += 0 if r.timing_consistent else 1
    assert flagged == 0


def test_gmean_caps_one_runaway_task():
    assert loop._gmean([27000.0, 1.0, 1.0]) == loop._gmean([100.0, 1.0, 1.0])
    assert abs(loop._gmean([4.0, 1.0]) - 2.0) < 1e-9
