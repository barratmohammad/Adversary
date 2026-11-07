"""Reputation ledger with staking.

Every non-abstaining vote stakes ``STAKE_RATE * confidence * reputation``. When ground truth
arrives (a sample label, a later ``reproduce``, or a human override) the stake is settled:

  correct vote: reputation += GAIN * stake      (multiplicative: r * (1 + STAKE_RATE*GAIN*c))
  wrong vote:   reputation -= stake             (multiplicative: r * (1 - STAKE_RATE*c))

GAIN < 1, so being confidently wrong costs more than being confidently right earns; abstaining
stakes nothing and moves nothing. Reputation is the agent's voting weight, clamped to
[MIN_REP, MAX_REP] so nobody is ever fully silenced or becomes a dictator. We also keep Beta
counts (correct/wrong) for a calibrated accuracy estimate.

Storage: ``runs/swarm_reputation.json`` (source of truth). If ``MONGODB_URI`` is set the agent
states and decisions are mirrored to MongoDB; a Mongo failure never breaks the swarm.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..workspace import RUNS_DIR

STAKE_RATE = 0.25
GAIN = 0.6
MIN_REP = 0.05
MAX_REP = 3.0
INITIAL_REP = 1.0
DEFAULT_PATH = RUNS_DIR / "swarm_reputation.json"


def required_stake(reputation: float, confidence: float) -> float:
    return round(STAKE_RATE * max(0.0, min(1.0, confidence)) * reputation, 6)


@dataclass
class AgentRep:
    reputation: float = INITIAL_REP
    correct: int = 0
    wrong: int = 0
    abstained: int = 0
    staked: float = 0.0
    won: float = 0.0
    lost: float = 0.0

    @property
    def accuracy(self) -> float:
        """Posterior mean of a Beta(1,1)-prior Bernoulli accuracy."""
        return (self.correct + 1) / (self.correct + self.wrong + 2)


@dataclass
class Settlement:
    agent: str
    decision: str
    confidence: float
    stake: float
    correct: bool | None  # None for abstain
    before: float
    after: float

    @property
    def delta(self) -> float:
        return self.after - self.before


@dataclass
class Ledger:
    path: Path | None = None
    agents: dict[str, AgentRep] = field(default_factory=dict)
    decisions: list[dict] = field(default_factory=list)
    swarm: dict = field(default_factory=lambda: {"settled": 0, "correct": 0})

    # ---- persistence -------------------------------------------------------------------------
    @classmethod
    def load(cls, path: Path | str | None = DEFAULT_PATH, agents: tuple[str, ...] = ()) -> "Ledger":
        led = cls(path=Path(path) if path else None)
        if led.path and led.path.exists():
            data = json.loads(led.path.read_text())
            led.agents = {k: AgentRep(**v) for k, v in data.get("agents", {}).items()}
            led.decisions = data.get("decisions", [])
            led.swarm = data.get("swarm", led.swarm)
        for a in agents:
            led.agents.setdefault(a, AgentRep())
        return led

    def to_dict(self) -> dict:
        return {"version": 1, "params": {"stake_rate": STAKE_RATE, "gain": GAIN, "min": MIN_REP, "max": MAX_REP},
                "agents": {k: asdict(v) for k, v in sorted(self.agents.items())}, "swarm": self.swarm, "decisions": self.decisions}

    def save(self) -> str:
        if self.path is None:
            return "memory"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2))
        tmp.replace(self.path)
        return str(self.path) + _mongo_mirror(self)

    def reset(self) -> None:
        for a in list(self.agents):
            self.agents[a] = AgentRep()
        self.decisions.clear()
        self.swarm = {"settled": 0, "correct": 0}

    # ---- voting weights ----------------------------------------------------------------------
    def weight(self, agent: str) -> float:
        return self.agents.setdefault(agent, AgentRep()).reputation

    def weights(self) -> dict[str, float]:
        return {a: r.reputation for a, r in sorted(self.agents.items())}

    # ---- decisions ---------------------------------------------------------------------------
    def record(self, decision: dict, label: str | None = None) -> dict:
        entry = {**decision, "label": label, "settled": False,
                 "recorded_at": _dt.datetime.now(_dt.timezone.utc).isoformat()}
        self.decisions.append(entry)
        return entry

    def find(self, key: str) -> dict | None:
        for d in reversed(self.decisions):
            if key in (d.get("job_id"), d.get("run_id"), d.get("verdict_sha256"), d.get("decision_sha256")) or d.get("decision_sha256", "").startswith(key):
                return d
        return None

    def settle(self, entry: dict, label: str) -> list[Settlement]:
        """Settle every stake in a recorded decision against ground truth ('block' | 'allow')."""
        if label not in ("block", "allow"):
            raise ValueError(f"label must be block|allow, got {label!r}")
        if entry.get("settled"):
            raise ValueError(f"decision {entry.get('job_id')} already settled as {entry.get('label')!r}")
        out = []
        for v in sorted(entry["votes"], key=lambda v: v["agent"]):
            rep = self.agents.setdefault(v["agent"], AgentRep())
            before = rep.reputation
            if v["decision"] == "abstain":
                rep.abstained += 1
                out.append(Settlement(v["agent"], "abstain", v["confidence"], 0.0, None, before, before))
                continue
            stake = float(v.get("stake", 0.0))
            ok = v["decision"] == label
            rep.staked = round(rep.staked + stake, 6)
            if ok:
                rep.correct += 1
                rep.won = round(rep.won + GAIN * stake, 6)
                rep.reputation = before + GAIN * stake
            else:
                rep.wrong += 1
                rep.lost = round(rep.lost + stake, 6)
                rep.reputation = before - stake
            rep.reputation = round(min(MAX_REP, max(MIN_REP, rep.reputation)), 6)
            out.append(Settlement(v["agent"], v["decision"], v["confidence"], stake, ok, before, rep.reputation))
        entry["label"] = label
        entry["settled"] = True
        entry["swarm_correct"] = (entry["decision"] == "BLOCK") == (label == "block")
        self.swarm["settled"] = self.swarm.get("settled", 0) + 1
        self.swarm["correct"] = self.swarm.get("correct", 0) + int(entry["swarm_correct"])
        entry["settlements"] = [{**asdict(s), "delta": round(s.delta, 6)} for s in out]
        return out


def _mongo_mirror(led: Ledger) -> str:
    uri = os.environ.get("MONGODB_URI")
    if not uri:
        return ""
    try:
        from pymongo import MongoClient
        db = MongoClient(uri, serverSelectionTimeoutMS=4000)[os.environ.get("ADVERSARY_MONGO_DB", "adversary")]
        for name, rep in led.agents.items():
            db["swarm_reputation"].update_one({"agent": name}, {"$set": {"agent": name, **asdict(rep)}}, upsert=True)
        for d in led.decisions[-50:]:
            db["swarm_decisions"].update_one({"job_id": d["job_id"], "decision_sha256": d["decision_sha256"]}, {"$set": d}, upsert=True)
        return " + mongodb"
    except Exception as e:  # the ledger mirror must never break a decision
        return f" (mongodb unavailable: {type(e).__name__})"
