"""adversary CLI.

  adversary tasks                                  list demo tasks + fixtures
  adversary run <task> [--plant cheat|subtle|...]  implementer agent writes the PR, verifier judges it
  adversary run <task> --fixture subtle            same, with a pre-recorded implementer change
  adversary verify <task> --change <dir>           verify a change directory (files after the PR)
  adversary reproduce <run_dir>                    re-run a verdict from pinned inputs; hashes must match
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import implementer, llm, store, ui
from .sandbox import detect_sandbox
from .verdict import Verdict, Check
from .verifier.pipeline import load_pinned, verify
from .workspace import Change, list_tasks, load_task, read_tree


def _verify_and_show(task, change, private, args, pinned=None, run_dir=None):
    sandbox = detect_sandbox(args.sandbox)
    vcfg = llm.config_for("verifier")
    icfg = llm.config_for("implementer")
    impl_desc = icfg.describe() if change.meta.get("source") == "llm" else {"role": "implementer", "provider": "fixture", "model": "pre-recorded change"}
    ui.banner(task.title, f"{impl_desc['provider']}/{impl_desc['model']}", f"{vcfg.provider}/{vcfg.model}", sandbox.kind)
    if not args.quiet:
        ui.show_diff(change.diff(), max_lines=args.diff_lines)
    with ui.LiveChecks() as live:
        verdict, rdir = verify(task, change, seed=args.seed, sandbox=sandbox, pinned=pinned, emit=live.emit, run_dir=run_dir,
                               max_mutants=args.mutants, max_examples=args.examples, implementer_model=impl_desc)
    if private is not None:
        implementer.save_private(rdir / "private", private)
    change.save(rdir / "change")
    ui.show_verdict(verdict, rdir)
    where = store.record(verdict.to_dict())
    ui.console.print(f"[dim]ledger: {where}[/]")
    return verdict, rdir


def cmd_tasks(args) -> int:
    for t in list_tasks():
        ui.console.print(f"[bold]{t.name}[/]  {t.title}  [dim]fixtures: {', '.join(t.fixtures()) or '-'}[/]")
    return 0


def cmd_run(args) -> int:
    task = load_task(args.task)
    if args.fixture:
        change, private = implementer.from_fixture(task, args.fixture)
    else:
        ui.console.print(f"[dim]implementer ({llm.config_for('implementer').model}) is writing the change...[/]")
        change, private = implementer.implement(task, plant=args.plant)
    verdict, _ = _verify_and_show(task, change, private, args)
    return 1 if verdict.decision == "BLOCK" else 0


def cmd_verify(args) -> int:
    task = load_task(args.task)
    change = Change.load(task, Path(args.change))
    verdict, _ = _verify_and_show(task, change, None, args)
    return 1 if verdict.decision == "BLOCK" else 0


def cmd_reproduce(args) -> int:
    src = Path(args.run_dir)
    old = json.loads((src / "verdict.json").read_text())
    task = load_task(old["task"])
    if task.spec != (src / "inputs" / "spec.md").read_text():
        ui.console.print("[yellow]warning: task spec changed since the original run; using the pinned spec[/]")
        task.spec = (src / "inputs" / "spec.md").read_text()
    change = Change(base=task.base, after=read_tree(src / "inputs" / "after"))
    pinned = load_pinned(src)
    args.seed = old["seed"]
    sandbox = detect_sandbox(args.sandbox)
    ui.console.print(f"[bold]reproducing[/] {src.name}: seed {old['seed']}, pinned tests sha256:{(old['pinned']['verifier_tests_sha256'] or '-')[:12]}, no LLM calls")
    with ui.LiveChecks() as live:
        v, rdir = verify(task, change, seed=old["seed"], sandbox=sandbox, pinned=pinned, emit=live.emit,
                         run_dir=src.parent / (src.name + "-repro"), max_mutants=old["pinned"].get("max_mutants", args.mutants),
                         max_examples=old["pinned"].get("max_examples", args.examples),
                         implementer_model=old["models"]["implementer"])
    same_outcome = v.outcome_sha256 == old["outcome_sha256"]
    same_inputs = v.inputs == old["inputs"] and v.pinned == old["pinned"]
    t = ui.Table(title="reproduction", show_header=True)
    t.add_column("")
    t.add_column("original")
    t.add_column("reproduced")
    t.add_column("")
    t.add_row("decision", old["decision"], v.decision, "✔" if old["decision"] == v.decision else "✘")
    t.add_row("inputs", old["inputs"]["diff_sha256"][:16], v.inputs["diff_sha256"][:16], "✔" if same_inputs else "✘")
    t.add_row("outcome", old["outcome_sha256"][:16], v.outcome_sha256[:16], "✔" if same_outcome else "✘")
    ui.console.print(t)
    if same_outcome:
        ui.console.print("[bold green]reproduced: identical outcome hash[/]")
        return 0
    ui.console.print("[bold red]NOT reproduced: outcome differs[/]")
    for c_old, c_new in zip(old["checks"], v.checks):
        if c_old["status"] != c_new.status or c_old["details"].get("fingerprint") != c_new.details.get("fingerprint"):
            ui.console.print(f"  {c_new.id}: {c_old['status']} -> {c_new.status}")
    return 2


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="adversary", description="Independent verifier for AI-generated changes")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--seed", type=int, default=1337)
        sp.add_argument("--sandbox", choices=["docker", "seatbelt", "local"], default=None)
        sp.add_argument("--mutants", type=int, default=30)
        sp.add_argument("--examples", type=int, default=200, help="hypothesis max_examples per property")
        sp.add_argument("--quiet", action="store_true", help="don't print the diff")
        sp.add_argument("--diff-lines", type=int, default=50)

    sub.add_parser("tasks").set_defaults(fn=cmd_tasks)
    r = sub.add_parser("run")
    r.add_argument("task")
    r.add_argument("--plant", default="none", choices=sorted(implementer.PLANTS))
    r.add_argument("--fixture", default=None)
    common(r)
    r.set_defaults(fn=cmd_run)
    v = sub.add_parser("verify")
    v.add_argument("task")
    v.add_argument("--change", required=True)
    common(v)
    v.set_defaults(fn=cmd_verify)
    rp = sub.add_parser("reproduce")
    rp.add_argument("run_dir")
    common(rp)
    rp.set_defaults(fn=cmd_reproduce)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except llm.LLMError as e:
        ui.console.print(f"[bold red]LLM error:[/] {e}")
        return 3


if __name__ == "__main__":
    sys.exit(main())
