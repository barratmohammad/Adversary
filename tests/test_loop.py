"""The learn loop's keep/rollback discipline, driven by a stub optimizer (no LLM, no Adversary)."""
import json

from overclock import loop, optimizer, reflect
from overclock import playbook as pb

SET_RULE = "When a list is only used for membership tests inside a loop, build a set from it first; this is permitted."
BAD_RULE = "Always sort every input list before processing it."

FAST = {
    "t02_membership": "def membership(pool, queries):\n    s = set(pool)\n    return sum(1 for q in queries if q in s)\n",
    "t07_dedupe": "def dedupe(items):\n    seen = set()\n    out = []\n    for x in items:\n        if x not in seen:\n"
                  "            seen.add(x)\n            out.append(x)\n    return out\n",
    "h02_common_elements": "def common_elements(a, b):\n    s = set(b)\n    return [x for x in a if x in s]\n",
    "h06_unique_words": "def unique_words(text):\n    seen = set()\n    out = []\n    for w in text.split():\n"
                        "        if w not in seen:\n            seen.add(w)\n            out.append(w)\n    return out\n",
}


def _stub_optimize(task, playbook):
    """Learn tasks: always finds the fast version. Held-out tasks: only once the SET rule is in the playbook."""
    knows_sets = any(r.text == SET_RULE for r in playbook.rules)
    src = FAST[task.name] if (task.split == "learn" or knows_sets) else task.public_source
    return optimizer.OptimizeResult(task.name, src, src, "stub", True, playbook.version)


def _stub_rule(task, before, after, speedup, playbook):
    return SET_RULE if task.name == "t02_membership" else BAD_RULE


def test_learn_keeps_a_rule_that_helps_heldout_and_rolls_back_one_that_does_not(tmp_path, monkeypatch):
    monkeypatch.setattr(pb, "PLAYBOOK_DIR", tmp_path / "playbook")
    monkeypatch.setattr(loop, "CACHE", tmp_path / "cache")
    monkeypatch.setattr(optimizer, "optimize", _stub_optimize)
    monkeypatch.setattr(reflect, "propose_rule", _stub_rule)
    events = []

    rep = loop.learn(["t02_membership", "t07_dedupe"], ["h02_common_elements", "h06_unique_words"],
                     use_gate=False, gate_heldout=False, emit=events.append)

    decisions = [s["decision"] for s in rep.steps]
    assert decisions == ["keep", "rollback"], rep.steps
    keep, roll = rep.steps
    assert keep["rule"] == SET_RULE and keep["heldout_after"] > keep["heldout_before"] * loop.MARGIN
    assert roll["rule"] == BAD_RULE and roll["heldout_after"] <= roll["heldout_before"] * loop.MARGIN
    # the baseline held-out score (empty playbook, unchanged code) is ~1.0x; after the SET rule it is >> 1
    assert 0.7 < keep["heldout_before"] < 1.4 and keep["heldout_after"] > 3

    # on disk: v000 (empty), v001 accepted, v002 rolled back; CURRENT -> 1
    d = pb.PLAYBOOK_DIR
    assert sorted(p.name for p in d.glob("v*.json")) == ["v000.json", "v001.json", "v002.json"]
    assert (d / "CURRENT").read_text() == "1"
    assert json.loads((d / "v002.json").read_text())["status"] == "rolled_back"
    cur = pb.load_current()
    assert [r.text for r in cur.rules] == [SET_RULE]
    assert cur.rules[0].heldout_after == keep["heldout_after"]

    ledger = pb.read_ledger()
    assert [e["decision"] for e in ledger if e["type"] == "decision"] == ["keep", "rollback"]
    assert all("heldout_per_task" in e for e in ledger if e["type"] == "decision")
    assert rep.start_version == 0 and rep.end_version == 1


def test_unverified_or_slow_rewrites_never_produce_a_rule(tmp_path, monkeypatch):
    monkeypatch.setattr(pb, "PLAYBOOK_DIR", tmp_path / "playbook")
    monkeypatch.setattr(loop, "CACHE", tmp_path / "cache")
    calls = []
    monkeypatch.setattr(optimizer, "optimize",
                        lambda t, p: optimizer.OptimizeResult(t.name, t.public_source, "", "stub", True, p.version))
    monkeypatch.setattr(reflect, "propose_rule", lambda *a: calls.append(a) or "never")

    rep = loop.learn(["t02_membership"], ["h02_common_elements"], heldout_n=1, use_gate=False, gate_heldout=False)
    assert rep.steps[0]["decision"] == "no-rule" and rep.steps[0]["run"] == "slow"
    assert calls == []
    assert pb.load_current().version == 0
