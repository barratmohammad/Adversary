"""Verdict model: a reproducible, hash-pinned merge decision."""
from __future__ import annotations

import json
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .hashing import sha256_json, sha256_text

VERSION = "0.1.0"


@dataclass
class Check:
    id: str
    title: str
    status: str = "pending"  # pass | fail | warn | skip | error
    blocking: bool = False
    summary: str = ""
    details: dict = field(default_factory=dict)

    def outcome(self) -> dict:
        """The parts of a check that must be identical on reproduction (no timings, no prose from LLMs)."""
        return {"id": self.id, "status": self.status, "blocking": self.blocking, "fingerprint": self.details.get("fingerprint")}


@dataclass
class Verdict:
    run_id: str
    task: str
    decision: str  # MERGE | BLOCK
    reasons: list[str]
    checks: list[Check]
    seed: int
    inputs: dict
    pinned: dict
    environment: dict
    models: dict
    independence: dict
    created_at: str
    reproduce: str
    outcome_sha256: str = ""
    verdict_sha256: str = ""
    version: str = VERSION

    def finalize(self) -> "Verdict":
        self.outcome_sha256 = sha256_json({
            "decision": self.decision,
            "checks": [c.outcome() for c in self.checks],
            "inputs": self.inputs,
            "pinned": self.pinned,
            "seed": self.seed,
        })
        body = self.to_dict()
        for k in ("verdict_sha256", "created_at", "run_id", "reproduce"):
            body.pop(k, None)
        for c in body["checks"]:
            c.get("details", {}).pop("timing", None)
        self.verdict_sha256 = sha256_json(body)
        return self

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, d: Path) -> Path:
        p = d / "verdict.json"
        p.write_text(json.dumps(self.to_dict(), indent=2, default=str))
        return p


def environment_fingerprint(sandbox_desc: dict) -> dict:
    try:
        freeze = subprocess.run([sys.executable, "-m", "pip", "freeze", "--all"], capture_output=True, text=True, timeout=30).stdout
    except Exception:
        freeze = ""
    if not freeze.strip():
        try:
            freeze = subprocess.run(["uv", "pip", "freeze", "--python", sys.executable], capture_output=True, text=True, timeout=30).stdout
        except Exception:
            freeze = ""
    pkgs = {}
    for line in freeze.splitlines():
        if "==" in line:
            n, v = line.split("==", 1)
            pkgs[n.lower()] = v
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": f"{platform.system()}-{platform.machine()}",
        "hypothesis": pkgs.get("hypothesis"),
        "pytest": pkgs.get("pytest"),
        "lock_sha256": sha256_text("\n".join(f"{k}=={v}" for k, v in sorted(pkgs.items()))),
        "sandbox": sandbox_desc,
    }
