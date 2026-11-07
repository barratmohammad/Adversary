"""Transport-independent swarm logic shared by the uAgents runtime and the tests.

``specialist_vote`` is exactly what a specialist uAgent runs when a ReviewRequest arrives;
``direct_review`` runs the same code without any messaging (used to prove the Bureau run is
deterministic and equivalent).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..hashing import sha256_text, short
from .consensus import DEFAULT_THRESHOLD, SwarmDecision, aggregate
from .policies import SPECIALISTS, encode_evidence, evidence_slice, judge
from .reputation import Ledger, Settlement, required_stake


@dataclass
class Job:
    verdict: dict
    label: str | None = None  # ground truth: block | allow
    name: str = ""

    @property
    def job_id(self) -> str:
        return f"{self.verdict.get('run_id', '?')}:{short(self.verdict.get('verdict_sha256') or '0' * 12)}"


def load_verdict(path: Path | str) -> tuple[dict, str | None]:
    """Load a verdict.json (or a run dir containing one). Returns (verdict, ground-truth label or None)."""
    p = Path(path)
    if p.is_dir():
        p = p / "verdict.json"
    data = json.loads(p.read_text())
    gt = data.get("ground_truth") or {}
    label = gt.get("label") if isinstance(gt, dict) else None
    return data, label


def build_request(verdict: dict, agent: str, reputation: float, job_id: str) -> dict:
    ev = evidence_slice(verdict, agent)
    js, h = encode_evidence(ev)
    return {"job_id": job_id, "run_id": verdict.get("run_id", ""), "task": verdict.get("task", ""),
            "verdict_sha256": verdict.get("verdict_sha256", ""), "evidence_json": js, "evidence_sha256": h,
            "reputation": float(reputation)}


def specialist_vote(agent: str, req: dict) -> dict:
    """What a specialist does with a ReviewRequest. Pure and deterministic."""
    if sha256_text(req["evidence_json"]) != req["evidence_sha256"]:
        return {"job_id": req["job_id"], "agent": agent, "decision": "abstain", "confidence": 0.0,
                "rationale": "evidence hash mismatch; refusing to judge tampered evidence",
                "evidence_sha256": req["evidence_sha256"], "stake": 0.0, "veto": False}
    j = judge(agent, json.loads(req["evidence_json"]))
    stake = required_stake(req["reputation"], j.confidence) if j.decision != "abstain" else 0.0
    return {"job_id": req["job_id"], "agent": agent, "decision": j.decision, "confidence": j.confidence,
            "rationale": j.rationale, "evidence_sha256": req["evidence_sha256"], "stake": stake, "veto": j.veto}


def validate_vote(vote: dict, agent: str, req: dict) -> dict:
    """Coordinator-side checks: identity, evidence pin, decision domain, and minimum stake."""
    v = dict(vote)
    v["agent"] = agent  # identity comes from the sender address, never from the message body
    if v.get("decision") not in ("block", "allow", "abstain"):
        v.update(decision="abstain", confidence=0.0, stake=0.0, rationale=f"invalid decision {vote.get('decision')!r}")
    if v.get("evidence_sha256") != req["evidence_sha256"]:
        v.update(decision="abstain", confidence=0.0, stake=0.0, veto=False, rationale="vote not pinned to the evidence it was sent")
    v["confidence"] = max(0.0, min(1.0, float(v.get("confidence", 0.0))))
    if v["decision"] != "abstain":
        v["stake"] = max(float(v.get("stake", 0.0)), required_stake(req["reputation"], v["confidence"]))
    else:
        v["stake"] = 0.0
    return v


def decide(job: Job, votes: list[dict], ledger: Ledger, agents: tuple[str, ...] = SPECIALISTS,
           threshold: float = DEFAULT_THRESHOLD) -> tuple[SwarmDecision, list[Settlement] | None]:
    v = job.verdict
    d = aggregate(votes, {a: ledger.weight(a) for a in agents}, job_id=job.job_id, run_id=v.get("run_id", ""), task=v.get("task", ""),
                  verdict_sha256=v.get("verdict_sha256", ""), expected=list(agents), threshold=threshold,
                  pipeline_decision=v.get("decision"))
    entry = ledger.record(d.to_dict())
    settlements = ledger.settle(entry, job.label) if job.label else None
    return d, settlements


def direct_review(job: Job, ledger: Ledger, agents: tuple[str, ...] = SPECIALISTS,
                  threshold: float = DEFAULT_THRESHOLD) -> tuple[SwarmDecision, list[Settlement] | None]:
    votes = []
    for a in agents:
        req = build_request(job.verdict, a, ledger.weight(a), job.job_id)
        votes.append(validate_vote(specialist_vote(a, req), a, req))
    return decide(job, votes, ledger, agents, threshold)
