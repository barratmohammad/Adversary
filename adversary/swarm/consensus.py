"""Reputation-weighted consensus over specialist votes.

Rules, in order (all fail-closed):
  1. Veto: a ``block`` vote with ``veto=True`` from a veto-holding specialist (security-agent,
     i.e. a high-severity security finding) blocks the merge regardless of the tally.
  2. No quorum: if no specialist cast a non-abstaining vote, block.
  3. Tally: block_mass = sum(weight * confidence) over block votes, allow_mass likewise.
     p_block = block_mass / (block_mass + allow_mass). BLOCK if p_block >= threshold (ties block).

Votes are sorted by agent name before summing so the float arithmetic (and therefore the
decision hash) does not depend on message arrival order.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..hashing import sha256_json

VETO_AGENTS = frozenset({"security-agent"})
DEFAULT_THRESHOLD = 0.5


@dataclass
class SwarmDecision:
    job_id: str
    run_id: str
    task: str
    verdict_sha256: str
    decision: str  # MERGE | BLOCK
    reason: str
    p_block: float
    block_mass: float
    allow_mass: float
    threshold: float
    vetoed_by: str
    votes: list[dict]
    weights: dict[str, float]
    missing: list[str] = field(default_factory=list)
    pipeline_decision: str | None = None
    decision_sha256: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _r(x: float) -> float:
    return round(float(x), 6)


def aggregate(
    votes: list[dict],
    weights: dict[str, float],
    *,
    job_id: str = "",
    run_id: str = "",
    task: str = "",
    verdict_sha256: str = "",
    expected: list[str] | None = None,
    threshold: float = DEFAULT_THRESHOLD,
    pipeline_decision: str | None = None,
) -> SwarmDecision:
    votes = sorted((dict(v) for v in votes), key=lambda v: v["agent"])
    block_mass = allow_mass = 0.0
    rows = []
    veto_by = ""
    for v in votes:
        w = float(weights.get(v["agent"], 1.0))
        c = max(0.0, min(1.0, float(v.get("confidence", 0.0))))
        contrib = 0.0
        if v["decision"] == "block":
            contrib = w * c
            block_mass += contrib
            if v.get("veto") and v["agent"] in VETO_AGENTS and not veto_by:
                veto_by = v["agent"]
        elif v["decision"] == "allow":
            contrib = w * c
            allow_mass += contrib
        rows.append({**v, "confidence": _r(c), "stake": _r(v.get("stake", 0.0)), "weight": _r(w), "contribution": _r(contrib)})

    total = block_mass + allow_mass
    p_block = block_mass / total if total > 0 else 1.0
    missing = sorted(set(expected or []) - {v["agent"] for v in votes})
    if veto_by:
        decision, reason = "BLOCK", f"veto by {veto_by} (high-severity security finding)"
    elif total <= 0:
        decision, reason = "BLOCK", "no quorum: every specialist abstained or timed out (fail closed)"
    elif p_block >= threshold:
        decision, reason = "BLOCK", f"weighted tally {p_block:.0%} block >= {threshold:.0%}"
    else:
        decision, reason = "MERGE", f"weighted tally {1 - p_block:.0%} allow"

    d = SwarmDecision(
        job_id=job_id, run_id=run_id, task=task, verdict_sha256=verdict_sha256, decision=decision, reason=reason,
        p_block=_r(p_block), block_mass=_r(block_mass), allow_mass=_r(allow_mass), threshold=threshold, vetoed_by=veto_by,
        votes=rows, weights={k: _r(v) for k, v in sorted(weights.items())}, missing=missing, pipeline_decision=pipeline_decision,
    )
    d.decision_sha256 = decision_hash(d)
    return d


def decision_hash(d: SwarmDecision) -> str:
    return sha256_json({
        "verdict_sha256": d.verdict_sha256,
        "decision": d.decision,
        "p_block": d.p_block,
        "vetoed_by": d.vetoed_by,
        "threshold": d.threshold,
        "weights": d.weights,
        "missing": d.missing,
        "votes": [{k: v[k] for k in ("agent", "decision", "confidence", "evidence_sha256", "stake", "veto")} for v in d.votes],
    })
