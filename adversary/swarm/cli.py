"""Swarm Verify CLI.

  python -m adversary.swarm <verdict.json|run_dir|sample> [--label block|allow]
        specialists review one verdict over uAgents messaging; --label settles the stakes now
  python -m adversary.swarm --calibrate [--rounds 6]
        replay every labelled sample for N rounds from fresh reputations; watch weights converge
  python -m adversary.swarm --resolve <run_id|job_id|sha> --label block|allow
        settle a pending decision later (human override, or after `adversary reproduce`)
  python -m adversary.swarm --show          print the reputation ledger
  python -m adversary.swarm --samples       list bundled sample verdicts
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import Job, load_verdict
from .policies import SPECIALISTS
from .reputation import DEFAULT_PATH, Ledger
from . import view

SAMPLES_DIR = Path(__file__).parent / "samples"
SAMPLE_ORDER = ["subtle_intervals", "cheat_roman", "clean_roman", "backdoor_safe_path", "noisy_clean_intervals"]


def sample_paths() -> list[Path]:
    found = {p.stem: p for p in SAMPLES_DIR.glob("*.json")}
    return [found[n] for n in SAMPLE_ORDER if n in found] + sorted(p for n, p in found.items() if n not in SAMPLE_ORDER)


def resolve_verdict_path(arg: str) -> Path:
    p = Path(arg)
    if p.exists():
        return p
    s = SAMPLES_DIR / (arg if arg.endswith(".json") else arg + ".json")
    if s.exists():
        return s
    raise SystemExit(f"no such verdict: {arg} (not a file, run dir, or sample name; see --samples)")


def _runtime(ledger: Ledger, args, on_event, pace: float, job_delay: float = 0.0):
    from .runtime import SwarmRuntime
    return SwarmRuntime(ledger, on_event=on_event, pace=pace, job_delay=job_delay, vote_timeout=args.timeout,
                        threshold=args.threshold, agentverse=args.agentverse)


def cmd_review(args) -> int:
    path = resolve_verdict_path(args.verdict)
    verdict, gt = load_verdict(path)
    ledger = Ledger.load(args.ledger, SPECIALISTS)
    job = Job(verdict, args.label, path.stem)
    view.banner(f"local Bureau: {len(SPECIALISTS)} specialist uAgents + coordinator, in-process, offline · ledger {ledger.path}"
                if not args.agentverse else "Agentverse mode: agents use mailboxes")
    pace = 0.0 if args.fast else args.pace
    with view.ReviewView(SPECIALISTS, ledger) as rv:
        results = _runtime(ledger, args, rv.on_event, pace).run([job])
    if not results:
        view.console.print("[bold red]swarm produced no decision[/]")
        return 3
    d, settlements = results[0]
    where = ledger.save()
    if not args.label:
        hint = f" (fixture ground truth is {gt!r}: add --label {gt} to settle)" if gt else ""
        view.console.print(f"[dim]decision recorded as pending{hint}; settle later with --resolve {d.run_id} --label block|allow[/]")
    view.console.print(f"[dim]ledger: {where}[/]")
    if args.json:
        print(json.dumps(d.to_dict(), indent=2))
    return 1 if d.decision == "BLOCK" else 0


def cmd_calibrate(args) -> int:
    paths = sample_paths() if not args.verdict else [resolve_verdict_path(x) for x in [args.verdict]]
    loaded = [(p.stem, *load_verdict(p)) for p in paths]
    loaded = [(n, v, lab) for n, v, lab in loaded if lab]
    if not loaded:
        raise SystemExit("no labelled samples to calibrate on")
    ledger = Ledger.load(args.ledger, SPECIALISTS)
    ledger.reset()
    jobs = [Job(v, lab, n) for _ in range(args.rounds) for n, v, lab in loaded]
    names = [n for n, _, _ in loaded]
    view.banner(f"calibration: {len(names)} labelled samples × {args.rounds} rounds, reputations reset to 1.00 · "
                f"{len(SPECIALISTS)} specialist uAgents + coordinator in a local Bureau")
    pace, delay = (0.0, 0.0) if args.fast else (args.pace if args.pace_set else 0.04, 0.2)
    with view.CalibrationView(SPECIALISTS, names, {n: lab for n, _, lab in loaded}, args.rounds, ledger) as cv:
        results = _runtime(ledger, args, cv.on_event, pace, delay).run(jobs)
    where = ledger.save()
    k = len(names)
    first = sum((d.decision == "BLOCK") == (j.label == "block") for (d, _), j in zip(results[:k], jobs[:k]))
    last = sum((d.decision == "BLOCK") == (j.label == "block") for (d, _), j in zip(results[-k:], jobs[-k:]))
    worst = min(SPECIALISTS, key=ledger.weight)
    view.console.print(f"\n[bold]round 1[/] (equal weights) {first}/{k} correct → [bold]round {args.rounds}[/] {last}/{k} correct. "
                       f"Least trusted: [bold red]{worst}[/] at weight {ledger.weight(worst):.2f}.")
    view.console.print(f"[dim]ledger: {where}[/]")
    return 0 if last == k else 1


def cmd_resolve(args) -> int:
    if not args.label:
        raise SystemExit("--resolve needs --label block|allow")
    ledger = Ledger.load(args.ledger, SPECIALISTS)
    entry = ledger.find(args.resolve)
    if entry is None:
        raise SystemExit(f"no recorded decision matches {args.resolve!r}")
    st = ledger.settle(entry, args.label)
    view.console.print(view._decision_text(_as_decision(entry), args.label))
    view.console.print(view._settlement_table(st, ledger))
    view.console.print(f"[dim]ledger: {ledger.save()}[/]")
    return 0


def _as_decision(entry: dict):
    from .consensus import SwarmDecision
    fields = SwarmDecision.__dataclass_fields__
    return SwarmDecision(**{k: v for k, v in entry.items() if k in fields})


def cmd_show(args) -> int:
    ledger = Ledger.load(args.ledger, SPECIALISTS)
    view.console.print(view.reputation_table(ledger, f"reputation ledger · {ledger.path}"))
    return 0


def cmd_samples(args) -> int:
    for p in sample_paths():
        v, lab = load_verdict(p)
        gt = v.get("ground_truth", {})
        view.console.print(f"[bold]{p.stem:24}[/] pipeline {v['decision']:5}  truth {str(lab).upper():5}  [dim]{gt.get('why', '')}[/]")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m adversary.swarm", description="Swarm Verify: specialist uAgents vote on a verdict and stake reputation")
    p.add_argument("verdict", nargs="?", help="verdict.json, a run dir, or a bundled sample name")
    p.add_argument("--label", choices=["block", "allow"], help="ground truth; settles stakes immediately")
    p.add_argument("--calibrate", action="store_true", help="replay all labelled samples for --rounds rounds from fresh reputations")
    p.add_argument("--rounds", type=int, default=6)
    p.add_argument("--resolve", metavar="KEY", help="settle a pending decision (run_id, job_id or decision sha)")
    p.add_argument("--show", action="store_true", help="print the reputation ledger")
    p.add_argument("--samples", action="store_true", help="list bundled sample verdicts")
    p.add_argument("--ledger", default=str(DEFAULT_PATH), help="reputation ledger JSON path")
    p.add_argument("--threshold", type=float, default=0.5, help="block if weighted block share >= threshold")
    p.add_argument("--pace", type=float, default=None, help="seconds between vote arrivals (demo pacing)")
    p.add_argument("--fast", action="store_true", help="no demo pacing")
    p.add_argument("--timeout", type=float, default=10.0, help="seconds to wait for votes before failing closed")
    p.add_argument("--agentverse", action="store_true", help="give agents Agentverse mailboxes (needs network); default is offline")
    p.add_argument("--json", action="store_true", help="also print the decision as JSON")
    args = p.parse_args(argv)
    args.pace_set = args.pace is not None
    if args.pace is None:
        args.pace = 0.45
    if args.samples:
        return cmd_samples(args)
    if args.show:
        return cmd_show(args)
    if args.resolve:
        return cmd_resolve(args)
    if args.calibrate:
        return cmd_calibrate(args)
    if not args.verdict:
        p.print_help()
        return 2
    return cmd_review(args)


if __name__ == "__main__":
    sys.exit(main())
