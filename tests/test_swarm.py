"""Swarm Verify: aggregation, veto, reputation/staking, determinism, and the uAgents Bureau path.

Fast and offline: the Bureau test blocks every non-loopback socket connection.
"""
from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from adversary.hashing import sha256_text
from adversary.swarm.cli import sample_paths
from adversary.swarm.consensus import aggregate
from adversary.swarm.engine import Job, build_request, direct_review, load_verdict, specialist_vote, validate_vote
from adversary.swarm.policies import SPECIALISTS, evidence_slice, judge
from adversary.swarm.reputation import GAIN, MIN_REP, STAKE_RATE, Ledger, required_stake


def vote(agent, decision, confidence, veto=False, stake=None):
    return {"job_id": "j", "agent": agent, "decision": decision, "confidence": confidence, "rationale": "",
            "evidence_sha256": "e", "stake": required_stake(1.0, confidence) if stake is None else stake, "veto": veto}


def samples() -> dict[str, tuple[dict, str]]:
    return {p.stem: load_verdict(p) for p in sample_paths()}


# ---- aggregation ---------------------------------------------------------------------------------

def test_weighted_tally_blocks_and_allows():
    votes = [vote("spec-agent", "block", 0.8), vote("cheat-agent", "allow", 0.4), vote("lenient-agent", "allow", 0.9)]
    equal = aggregate(votes, {"spec-agent": 1, "cheat-agent": 1, "lenient-agent": 1})
    assert equal.decision == "MERGE" and equal.block_mass == pytest.approx(0.8) and equal.allow_mass == pytest.approx(1.3)
    earned = aggregate(votes, {"spec-agent": 2.5, "cheat-agent": 1, "lenient-agent": 0.2})
    assert earned.decision == "BLOCK" and earned.p_block == pytest.approx(2.0 / (2.0 + 0.4 + 0.18), abs=1e-6)


def test_tie_and_no_quorum_fail_closed():
    tie = aggregate([vote("a", "block", 0.5), vote("b", "allow", 0.5)], {"a": 1, "b": 1})
    assert tie.decision == "BLOCK"
    none = aggregate([vote("a", "abstain", 0.0)], {"a": 1}, expected=["a", "b"])
    assert none.decision == "BLOCK" and "quorum" in none.reason and none.missing == ["b"]


def test_security_veto_overrides_tally_and_only_security_can_veto():
    votes = [vote("security-agent", "block", 0.9, veto=True), vote("spec-agent", "allow", 0.8), vote("lenient-agent", "allow", 0.9),
             vote("cheat-agent", "allow", 0.35)]
    w = {"security-agent": 0.1, "spec-agent": 3, "lenient-agent": 3, "cheat-agent": 3}
    d = aggregate(votes, w)
    assert d.p_block < 0.05 and d.decision == "BLOCK" and d.vetoed_by == "security-agent"
    forged = aggregate([vote("lenient-agent", "block", 0.9, veto=True), vote("spec-agent", "allow", 0.8)], {"lenient-agent": 0.1, "spec-agent": 3})
    assert forged.decision == "MERGE" and forged.vetoed_by == ""


def test_aggregation_is_order_independent():
    votes = [vote(a, d, c) for a, d, c in [("security-agent", "allow", 0.3), ("spec-agent", "block", 0.75), ("cheat-agent", "allow", 0.35),
                                            ("mutation-agent", "block", 0.67), ("lenient-agent", "allow", 0.9)]]
    w = {"security-agent": 1.1, "spec-agent": 1.3, "cheat-agent": 0.9, "mutation-agent": 0.7, "lenient-agent": 0.4}
    a = aggregate(votes, w)
    b = aggregate(list(reversed(votes)), w)
    assert a.decision_sha256 == b.decision_sha256 and a.p_block == b.p_block


# ---- policies ------------------------------------------------------------------------------------

def test_specialists_see_only_their_slice_and_have_blind_spots():
    s = samples()
    backdoor, _ = s["backdoor_safe_path"]
    assert set(evidence_slice(backdoor, "spec-agent")["checks"]) == {"property_tests"}
    assert judge("security-agent", evidence_slice(backdoor, "security-agent")).veto is True
    assert judge("spec-agent", evidence_slice(backdoor, "spec-agent")).decision == "allow"  # dormant backdoor passes every property
    subtle, _ = s["subtle_intervals"]
    assert judge("spec-agent", evidence_slice(subtle, "spec-agent")).decision == "block"
    assert judge("cheat-agent", evidence_slice(subtle, "cheat-agent")).decision == "allow"
    assert judge("lenient-agent", evidence_slice(subtle, "lenient-agent")).decision == "allow"


def test_tampered_evidence_is_refused_and_votes_are_pinned():
    v, _ = samples()["cheat_roman"]
    req = build_request(v, "cheat-agent", 1.0, "j")
    good = specialist_vote("cheat-agent", req)
    assert good["decision"] == "block" and good["evidence_sha256"] == sha256_text(req["evidence_json"])
    bad = dict(req, evidence_json=req["evidence_json"].replace("hardcoded-answer", "fine"))
    assert specialist_vote("cheat-agent", bad)["decision"] == "abstain"
    # coordinator rejects a vote pinned to other evidence, and never lets an agent understake
    assert validate_vote(dict(good, evidence_sha256="0" * 64), "cheat-agent", req)["decision"] == "abstain"
    assert validate_vote(dict(good, stake=0.0), "cheat-agent", req)["stake"] == required_stake(1.0, good["confidence"])
    assert validate_vote(dict(good, agent="security-agent"), "cheat-agent", req)["agent"] == "cheat-agent"


# ---- reputation ----------------------------------------------------------------------------------

def test_stake_settlement_rewards_right_and_punishes_confident_wrong_more():
    led = Ledger.load(None, ("a", "b", "c"))
    entry = led.record({"job_id": "j", "decision": "BLOCK", "votes": [vote("a", "block", 0.8), vote("b", "allow", 0.8), vote("c", "abstain", 0.0, stake=0.0)]})
    st = {s.agent: s for s in led.settle(entry, "block")}
    stake = STAKE_RATE * 0.8
    assert st["a"].after == pytest.approx(1 + GAIN * stake) and st["b"].after == pytest.approx(1 - stake)
    assert abs(st["b"].delta) > abs(st["a"].delta)  # wrong confident vote costs more than a right one earns
    assert st["c"].delta == 0 and led.agents["c"].abstained == 1
    assert led.swarm == {"settled": 1, "correct": 1}
    with pytest.raises(ValueError):
        led.settle(entry, "allow")  # no double settlement


def test_low_confidence_wrong_costs_little_and_reputation_is_floored():
    led = Ledger.load(None, ("a",))
    for _ in range(40):
        e = led.record({"job_id": "j", "decision": "MERGE", "votes": [vote("a", "allow", 0.95, stake=required_stake(led.weight("a"), 0.95))]})
        led.settle(e, "block")
    assert led.weight("a") == MIN_REP
    led2 = Ledger.load(None, ("a",))
    e = led2.record({"job_id": "j", "decision": "MERGE", "votes": [vote("a", "allow", 0.2)]})
    led2.settle(e, "block")
    assert led2.weight("a") == pytest.approx(1 - STAKE_RATE * 0.2)


def test_ledger_roundtrip_and_resolve(tmp_path: Path):
    path = tmp_path / "rep.json"
    led = Ledger.load(path, SPECIALISTS)
    v, label = samples()["cheat_roman"]
    d, st = direct_review(Job(v, None, "cheat"), led)
    assert st is None
    led.save()
    led2 = Ledger.load(path, SPECIALISTS)
    entry = led2.find(v["run_id"])
    assert entry is not None and entry["settled"] is False
    led2.settle(entry, label)
    led2.save()
    data = json.loads(path.read_text())
    assert data["decisions"][-1]["settled"] and data["agents"]["cheat-agent"]["correct"] == 1


def test_calibration_converges_and_lenient_agent_loses_weight():
    led = Ledger.load(None, SPECIALISTS)
    jobs = [Job(v, lab, n) for n, (v, lab) in samples().items()]
    acc = []
    for _ in range(6):
        acc.append(sum((direct_review(j, led)[0].decision == "BLOCK") == (j.label == "block") for j in jobs))
    assert acc[-1] == len(jobs)
    assert acc[0] < len(jobs)  # equal weights get fooled by the subtle boundary bug
    w = led.weights()
    assert min(w, key=w.get) == "lenient-agent" and w["lenient-agent"] < 0.2
    assert max(w, key=w.get) == "spec-agent"


# ---- determinism + the uAgents Bureau ------------------------------------------------------------

def test_direct_review_is_deterministic():
    def run():
        led = Ledger.load(None, SPECIALISTS)
        return [direct_review(Job(v, lab, n), led)[0].decision_sha256 for _ in range(2) for n, (v, lab) in samples().items()]
    assert run() == run()


@pytest.fixture
def no_network(monkeypatch):
    real = socket.socket.connect

    def guarded(self, addr):
        host = addr[0] if isinstance(addr, tuple) else addr
        if isinstance(host, str) and host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0") and not host.startswith("/"):
            raise OSError(f"network disabled in tests: {addr}")
        return real(self, addr)
    monkeypatch.setattr(socket.socket, "connect", guarded)


def test_bureau_matches_direct_path_offline(no_network):
    pytest.importorskip("uagents")
    from adversary.swarm.runtime import SwarmRuntime
    jobs = [Job(v, lab, n) for n, (v, lab) in samples().items()] * 2
    events = []
    led = Ledger.load(None, SPECIALISTS)
    res = SwarmRuntime(led, on_event=lambda k, p: events.append(k), vote_timeout=5).run(jobs)
    ref = Ledger.load(None, SPECIALISTS)
    expected = [direct_review(j, ref)[0] for j in jobs]
    assert [d.decision_sha256 for d, _ in res] == [d.decision_sha256 for d in expected]
    assert led.weights() == ref.weights()
    assert events.count("vote") == len(jobs) * len(SPECIALISTS) and events.count("decision") == len(jobs)


def test_chat_protocol_review_offline(no_network):
    pytest.importorskip("uagents")
    from adversary.swarm.runtime import SwarmRuntime
    led = Ledger.load(None, SPECIALISTS)
    transcript = SwarmRuntime(led, vote_timeout=5).serve(chat_script=["review cheat_roman block", "reputation"])
    assert len(transcript) == 2
    assert "SWARM BLOCKS" in transcript[0][1] and "swarm was right" in transcript[0][1]
    assert "cheat-agent" in transcript[1][1]
    assert led.agents["cheat-agent"].correct == 1 and led.swarm["settled"] == 1
