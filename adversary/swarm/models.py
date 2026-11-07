"""uAgents wire models for the verifier swarm.

These are the messages specialists and the coordinator exchange over uAgents messaging.
Evidence travels as canonical JSON plus its sha256, so a specialist can refuse evidence that
was tampered with in transit and every vote is pinned to the exact bytes it judged.
"""
from __future__ import annotations

from uagents import Model

DECISIONS = ("block", "allow", "abstain")


class ReviewRequest(Model):
    """Coordinator -> specialist: judge this slice of the verdict evidence."""

    job_id: str
    run_id: str
    task: str
    verdict_sha256: str
    evidence_json: str  # canonical JSON of the agent's evidence slice
    evidence_sha256: str
    reputation: float  # the agent's current reputation; it stakes a fraction of this


class Vote(Model):
    """Specialist -> coordinator: a staked vote on the merge."""

    job_id: str
    agent: str
    decision: str  # block | allow | abstain
    confidence: float  # 0..1
    rationale: str
    evidence_sha256: str
    stake: float
    veto: bool = False  # only the security specialist may set this (high-severity finding)

