"""The Adversary gate: every optimized function is verified as a real spec+diff PR.

We hand the independent verifier (adversary.verifier.pipeline) a one-module repo:
    base:  <func>.py containing the slow reference
    after: <func>.py containing the optimizer's rewrite
plus the SPEC. The verifier never sees the playbook, the optimizer's prompt, or the harness seed.
It runs the security pass, the cheat detector, blind property tests (written by a different model
family from the spec alone) and mutation testing, and returns a hash-pinned verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from adversary.verifier.pipeline import verify as adversary_verify
from adversary.workspace import RUNS_DIR, Change
from adversary.workspace import Task as RepoTask
from overclock.tasks import Task

GATE_RUNS = RUNS_DIR / "overclock"


@dataclass
class GateResult:
    task: str
    decision: str                       # MERGE | BLOCK
    run_id: str
    outcome_sha256: str
    reasons: list[str]
    checks: dict[str, tuple[str, str]] = field(default_factory=dict)   # id -> (status, summary)
    verifier_model: str = ""
    run_dir: str = ""

    @property
    def passed(self) -> bool:
        return self.decision == "MERGE"

    def to_dict(self) -> dict:
        return {"task": self.task, "decision": self.decision, "run_id": self.run_id,
                "outcome_sha256": self.outcome_sha256, "reasons": self.reasons,
                "checks": {k: {"status": s, "summary": m} for k, (s, m) in self.checks.items()},
                "verifier_model": self.verifier_model, "run_dir": self.run_dir}


def as_repo_task(task: Task) -> RepoTask:
    return RepoTask(
        name=f"overclock-{task.name}",
        title=f"OVERCLOCK: {task.func}",
        module=task.module_file,
        functions=[task.func],
        spec=f"# {task.func}\n\nImplement in `{task.module_file}`:\n\n```python\ndef {task.signature}: ...\n```\n\n"
             f"{task.public_spec}\n",
        base={task.module_file: task.public_source},
    )


def as_change(task: Task, candidate_source: str, model_desc: dict | None = None) -> Change:
    return Change(base={task.module_file: task.public_source}, after={task.module_file: candidate_source},
                  meta={"model_desc": model_desc or {}})


def verify(task: Task, candidate_source: str, *, seed: int = 1337, max_mutants: int = 8,
           max_examples: int = 60, emit=None, label: str = "", model_desc: dict | None = None) -> GateResult:
    repo_task, change = as_repo_task(task), as_change(task, candidate_source, model_desc)
    run_dir = GATE_RUNS / (f"{task.name}-{label}" if label else task.name)
    verdict, rdir = adversary_verify(repo_task, change, seed=seed, emit=emit, run_dir=_unique(run_dir),
                                     max_mutants=max_mutants, max_examples=max_examples)
    return GateResult(
        task=task.name, decision=verdict.decision, run_id=verdict.run_id,
        outcome_sha256=verdict.outcome_sha256, reasons=list(verdict.reasons),
        checks={c.id: (c.status, c.summary) for c in verdict.checks},
        verifier_model=str(verdict.models.get("verifier", {}).get("model", "")), run_dir=str(rdir),
    )


def _unique(path: Path) -> Path:
    if not path.exists():
        return path
    i = 2
    while (p := path.with_name(f"{path.name}-{i}")).exists():
        i += 1
    return p
