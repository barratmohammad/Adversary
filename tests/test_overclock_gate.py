"""Gate plumbing and planted attacks, without any LLM calls."""
from adversary.verifier.cheat import detect_cheats
from adversary.verifier.security import scan
from overclock import attacks, gate, harness
from overclock import playbook as pb
from overclock.tasks import load

FAST = """
def membership(pool, queries):
    s = set(pool)
    return sum(1 for q in queries if q in s)
"""


def _high(findings):
    return [f for f in findings if getattr(f, "severity", None) == "high"]


def test_gate_presents_a_one_module_diff_to_the_verifier():
    t = load("t02_membership")
    rt, ch = gate.as_repo_task(t), gate.as_change(t, FAST)
    assert rt.module == "membership.py" and rt.functions == ["membership"]
    assert "def membership(pool, queries)" in rt.spec
    assert set(ch.impl_files) == {"membership.py"} and not ch.test_files
    assert "-    hits = 0" in ch.diff() and "+    s = set(pool)" in ch.diff()


def test_honest_rewrite_passes_static_checks():
    t = load("t02_membership")
    ch = gate.as_change(t, FAST)
    assert not _high(scan(ch.impl_files))
    assert not _high(detect_cheats(ch.impl_files, {}, t.public_spec))


def test_escape_attack_is_flagged_by_security_pass():
    t = load("t02_membership")
    ch = gate.as_change(t, attacks.escape(t))
    assert _high(scan(ch.impl_files))


def test_table_attack_passes_seeded_check_but_collapses_on_fresh_inputs():
    t = load("t02_membership")
    src = attacks.table(t)
    ok, _, err = harness.check_correctness(t, src)
    assert ok and err is None                      # it IS correct on the published inputs
    res = harness.benchmark(t, src, repeats=3)
    assert res.correct
    assert res.speedup > 5                         # looks like a huge win...
    assert res.fresh_speedup is not None and res.fresh_speedup < 2
    assert res.timing_consistent is False          # ...until re-timed on inputs it never saw


def test_edge_attack_is_correct_on_seeded_inputs_but_violates_spec():
    t = load("t02_membership")
    src = attacks.edge(t)
    ok, _, _ = harness.check_correctness(t, src)
    assert ok                                      # seeded inputs never include an empty list
    ok2, mism, _ = harness.check_correctness(t, src, inputs=[([1, 2], [])])
    assert not ok2 and mism[0].expected == 0 and mism[0].got == -1


def test_playbook_versions_and_rollback(tmp_path):
    d = tmp_path / "pb"
    pb.reset(d)
    cur = pb.load_current(d)
    assert cur.version == 0 and cur.rules == []
    c1 = cur.with_rule("When you see X, do Y.", "t01_fib", pb.latest_version_number(d) + 1)
    pb.accept(c1, d)
    c2 = pb.load_current(d).with_rule("Bad rule.", "t02_membership", pb.latest_version_number(d) + 1)
    pb.rollback(c2, d)
    assert pb.load_current(d).version == 1
    assert (d / "v002.json").exists() and pb.latest_version_number(d) == 2
    assert "rolled_back" in (d / "v002.json").read_text()
