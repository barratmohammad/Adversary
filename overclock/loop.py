"""The learn loop: optimize -> verify (Adversary) -> time -> reflect -> held-out eval -> keep | rollback.

    for task in LEARN:
        src     = optimize(task, playbook)            # implementer LLM, sees playbook
        correct = differential check vs reference     # harness, seeded inputs
        verdict = Adversary.verify(spec, diff)        # independent model; never sees playbook/prompt
        bench   = stopwatch (+ fresh-seed re-time)    # correctness before speed, always
        if win:  rule = reflect(...)                  # ONE general rule
                 after = heldout_score(playbook + rule)
                 keep if after > before * margin else roll back
        ledger.append(decision with all the numbers)
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from adversary import llm
from overclock import gate as gatemod
from overclock import harness, optimizer, reflect
from overclock import playbook as pb
from overclock.tasks import HELD_OUT, LEARN, Task, load

Emit = Callable[[dict], None]
CACHE = Path(".cache/overclock/heldout")
MIN_SPEEDUP = 1.5
MARGIN = 1.10


def _noop(_e: dict) -> None:
    pass


@dataclass
class TaskRun:
    task: str
    playbook_version: int
    status: str = "pending"      # win | slow | incorrect | blocked | timing-cheat | error
    source: str = ""
    model: str = ""
    cached: bool = False
    correct: bool = False
    mismatch: str | None = None
    gate: dict | None = None
    speedup: float | None = None
    fresh_speedup: float | None = None
    slow_ms: float | None = None
    fast_ms: float | None = None
    error: str | None = None

    @property
    def effective_speedup(self) -> float:
        """What the system actually banks: an unverified or wrong rewrite is never shipped (1.0x)."""
        return self.speedup if self.status in ("win", "slow") and self.speedup else 1.0

    def to_dict(self) -> dict:
        return asdict(self)


GATE_BUDGET = {"max_mutants": 8, "max_examples": 60}          # learn tasks and single runs
HELDOUT_GATE_BUDGET = {"max_mutants": 4, "max_examples": 40}  # held-out scoring: correctness is what matters


def run_task(task: Task, playbook: pb.Playbook, *, use_gate: bool = True, seed: int = harness.DEFAULT_SEED,
             emit: Emit = _noop, label: str = "", explore: bool = False,
             gate_budget: dict | None = None) -> TaskRun:
    """`explore` (training only) lets the optimizer restructure freely on LEARN tasks. Held-out and
    unseen tasks must always be run with explore=False: same policy, only the playbook differs."""
    run = TaskRun(task=task.name, playbook_version=playbook.version)
    emit({"event": "optimize", "task": task.name, "version": playbook.version, "explore": explore})
    try:
        opt = optimizer.optimize(task, playbook, explore=explore)
    except llm.LLMError as e:
        run.status, run.error = "error", str(e)
        emit({"event": "error", "task": task.name, "error": str(e)})
        return run
    run.source, run.model, run.cached = opt.source, opt.model, opt.cached

    emit({"event": "correctness", "task": task.name})
    ok, mism, err = harness.check_correctness(task, run.source, seed=seed)
    run.correct = ok
    if not ok:
        run.status = "incorrect"
        run.mismatch = err or (f"{len(mism)} mismatch(es); e.g. args={mism[0].args_preview} "
                               f"expected={str(mism[0].expected)[:40]} got={str(mism[0].got)[:40]}")
        emit({"event": "incorrect", "task": task.name, "detail": run.mismatch})
        return run

    if use_gate:
        emit({"event": "gate", "task": task.name, "status": "running"})
        g = gatemod.verify(task, run.source, label=label or f"v{playbook.version}",
                           emit=lambda cid, st, msg: emit({"event": "gate-check", "task": task.name,
                                                           "check": cid, "status": st, "msg": msg}),
                           model_desc={"model": run.model}, **(gate_budget or GATE_BUDGET))
        run.gate = g.to_dict()
        emit({"event": "gate", "task": task.name, "status": g.decision, "reasons": g.reasons,
              "sha": g.outcome_sha256, "run_dir": g.run_dir})
        if not g.passed:
            run.status = "blocked"
            return run

    emit({"event": "bench", "task": task.name})
    b = harness.benchmark(task, run.source, seed=seed)
    if not b.correct:
        run.status, run.correct, run.mismatch = "incorrect", False, b.error or "wrong on fresh inputs"
        emit({"event": "incorrect", "task": task.name, "detail": run.mismatch})
        return run
    run.speedup, run.fresh_speedup = b.speedup, b.fresh_speedup
    run.slow_ms = (b.slow_median_s or 0) * 1000
    run.fast_ms = (b.fast_median_s or 0) * 1000
    if not b.timing_consistent:
        run.status = "timing-cheat"
        emit({"event": "timing-cheat", "task": task.name, "speedup": b.speedup, "fresh": b.fresh_speedup})
        return run
    run.status = "win" if b.speedup >= MIN_SPEEDUP else "slow"
    emit({"event": "bench-done", "task": task.name, "status": run.status, "speedup": b.speedup,
          "fresh": b.fresh_speedup, "slow_ms": run.slow_ms, "fast_ms": run.fast_ms})
    return run


# ---- held-out evaluation ------------------------------------------------------------------------
def _gmean(xs: list[float]) -> float:
    xs = [max(x, 1e-6) for x in xs] or [1.0]
    return math.exp(sum(math.log(x) for x in xs) / len(xs))


def heldout_key(playbook: pb.Playbook, tasks: list[Task], seed: int, use_gate: bool) -> str:
    blob = json.dumps([[r.text for r in playbook.rules], [t.name for t in tasks], seed, use_gate])
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def heldout_eval(playbook: pb.Playbook, tasks: list[Task], *, use_gate: bool = True,
                 seed: int = harness.DEFAULT_SEED, emit: Emit = _noop, use_cache: bool = True) -> dict:
    key = heldout_key(playbook, tasks, seed, use_gate)
    path = CACHE / f"{key}.json"
    if use_cache and path.exists():
        data = json.loads(path.read_text())
        emit({"event": "heldout-cached", "version": playbook.version, "gmean": data["gmean"]})
        return data
    runs = []
    for t in tasks:
        emit({"event": "heldout-task", "task": t.name, "version": playbook.version})
        runs.append(run_task(t, playbook, use_gate=use_gate, seed=seed, emit=emit, explore=False,
                             label=f"heldout-v{playbook.version}-{key[:6]}", gate_budget=HELDOUT_GATE_BUDGET))
    data = {"key": key, "playbook_version": playbook.version, "rules": [r.text for r in playbook.rules],
            "gmean": _gmean([r.effective_speedup for r in runs]),
            "per_task": {r.task: {"status": r.status, "speedup": r.speedup, "effective": r.effective_speedup}
                         for r in runs},
            "runs": [r.to_dict() for r in runs]}
    CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1))
    emit({"event": "heldout-done", "version": playbook.version, "gmean": data["gmean"], "per_task": data["per_task"]})
    return data


# ---- the loop -----------------------------------------------------------------------------------
@dataclass
class LearnReport:
    start_version: int
    end_version: int
    steps: list[dict] = field(default_factory=list)


def learn(learn_names: list[str] | None = None, heldout_names: list[str] | None = None, *, heldout_n: int = 3,
          use_gate: bool = True, gate_heldout: bool = True, seed: int = harness.DEFAULT_SEED,
          min_speedup: float = MIN_SPEEDUP, margin: float = MARGIN, emit: Emit = _noop) -> LearnReport:
    learn_tasks = [load(n) for n in (learn_names or LEARN)]
    held_tasks = [load(n) for n in (heldout_names or HELD_OUT)][:heldout_n]
    current = pb.load_current()
    if not (pb.PLAYBOOK_DIR / "v000.json").exists():
        pb.Playbook().save()
    report = LearnReport(start_version=current.version, end_version=current.version)

    emit({"event": "heldout-begin", "version": current.version, "tasks": [t.name for t in held_tasks]})
    before = heldout_eval(current, held_tasks, use_gate=gate_heldout, seed=seed, emit=emit)

    for task in learn_tasks:
        emit({"event": "learn-task", "task": task.name, "version": current.version})
        run = run_task(task, current, use_gate=use_gate, seed=seed, emit=emit, explore=True)
        step = {"task": task.name, "from_version": current.version, "run": run.status, "speedup": run.speedup}
        if run.status != "win" or (run.speedup or 0) < min_speedup:
            step["decision"] = "no-rule"
            step["why"] = {"incorrect": "rewrite was wrong", "blocked": "Adversary blocked the rewrite",
                           "timing-cheat": "fast only on published inputs", "slow": "speed-up below threshold",
                           "error": run.error or "error"}.get(run.status, run.status)
            pb.log({"type": "step", **step, "gate": run.gate})
            report.steps.append(step)
            emit({"event": "step", **step})
            continue

        emit({"event": "reflect", "task": task.name})
        try:
            rule_text = reflect.propose_rule(task, task.public_source, run.source, run.speedup, current)
        except llm.LLMError as e:
            step.update(decision="no-rule", why=f"reflection failed: {e}")
            pb.log({"type": "step", **step})
            report.steps.append(step)
            emit({"event": "step", **step})
            continue
        candidate = current.with_rule(rule_text, task.name, pb.latest_version_number() + 1)
        candidate.save()  # candidate file on disk before evaluation; status flips below
        emit({"event": "candidate", "task": task.name, "version": candidate.version, "rule": rule_text})

        after = heldout_eval(candidate, held_tasks, use_gate=gate_heldout, seed=seed, emit=emit)
        base_gmean = before["gmean"]
        keep = after["gmean"] > base_gmean * margin
        candidate.rules[-1].heldout_before = base_gmean
        candidate.rules[-1].heldout_after = after["gmean"]
        if keep:
            pb.accept(candidate)
            current, before = candidate, after
        else:
            pb.rollback(candidate)
        step.update(decision="keep" if keep else "rollback", candidate_version=candidate.version, rule=rule_text,
                    heldout_before=base_gmean, heldout_after=after["gmean"],
                    heldout_per_task={k: v["effective"] for k, v in after["per_task"].items()})
        pb.log({"type": "decision", **step})
        report.steps.append(step)
        report.end_version = current.version
        emit({"event": "step", **step})
    report.end_version = current.version
    return report
