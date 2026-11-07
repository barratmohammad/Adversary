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
    if getattr(args, "open_pr", False):
        from . import gate
        if not gate.ensure_playground(task):
            ui.console.print(f"[red]{gate.PLAYGROUND}/{task.name}/ is not on origin/main yet - run `adversary playground {task.name}` first[/]")
            return 2
        pr = gate.open_pr(task, change, title=f"[{task.name}] implement {', '.join(task.functions) or task.module}",
                          body=f"Implements `{task.module}` per `tasks/{task.name}/spec.md`.\n\nOpened by the Adversary implementer agent.")
        implementer.save_private(gate.RUNS_DIR / "private" / pr["branch"].replace("/", "-"), private)
        ui.console.print(f"[bold]implementer opened PR #{pr['number']}[/] {pr['url']}")
        args.pr = pr["number"]
        return cmd_gate(args)
    verdict, _ = _verify_and_show(task, change, private, args)
    return 1 if verdict.decision == "BLOCK" else 0


def cmd_gate(args) -> int:
    from . import gate
    task, change, info = gate.fetch_pr(args.pr)
    sha = info["headRefOid"]
    ui.console.print(f"[bold]gate[/] PR #{info['number']} {info['title']}  [dim]{info['url']}  head {sha[:10]}[/]")
    if not args.no_post:
        gate.post_status(sha, "pending", "Adversary is writing blind tests for this change...", info["url"])
    try:
        verdict, rdir = _verify_and_show(task, change, None, args)
    except Exception as e:
        if not args.no_post:
            gate.post_status(sha, "error", f"verifier error: {e}"[:139], info["url"])
        raise
    if not args.no_post:
        first = verdict.reasons[0] if verdict.reasons else ""
        desc = ("BLOCK: " + first if verdict.decision == "BLOCK" else "MERGE: all checks passed") + f" [{verdict.verdict_sha256[:8]}]"
        gate.post_status(sha, "failure" if verdict.decision == "BLOCK" else "success", desc, info["url"])
        gate.comment(info["number"], gate.comment_markdown(verdict, rdir))
        ui.console.print(f"[dim]posted status {gate.CONTEXT} = {'failure' if verdict.decision == 'BLOCK' else 'success'} and a PR comment[/]")
    return 1 if verdict.decision == "BLOCK" else 0


def cmd_playground(args) -> int:
    """Write the files to commit at pr_demo/<task>/ on main (the base every AI PR starts from)."""
    from . import gate
    from .workspace import write_tree
    task = load_task(args.task)
    dest = Path(gate.ROOT) / gate.PLAYGROUND / task.name
    write_tree(dest, task.base)
    ui.console.print(f"wrote {len(task.base)} base file(s) to {dest} - commit and push them to main")
    return 0


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
                         implementer_model=old["models"]["implementer"], playbook=pinned.get("playbook", ""))
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


def cmd_matrix(args) -> int:
    """Run every task x fixture variant; clean must MERGE, every planted variant must BLOCK."""
    from concurrent.futures import ThreadPoolExecutor
    from rich.table import Table
    tasks = [load_task(t) for t in (args.tasks.split(",") if args.tasks else [t.name for t in list_tasks()])]
    jobs = [(t, v) for t in tasks for v in t.fixtures()]
    sandbox = detect_sandbox(args.sandbox)
    ui.console.print(f"[bold]matrix[/]: {len(jobs)} changes · verifier {llm.config_for('verifier').model} · adjudicator subq-snap · sandbox {sandbox.kind}")

    def one(job):
        t, variant = job
        change, private = implementer.from_fixture(t, variant)
        try:
            v, rdir = verify(t, change, seed=args.seed, sandbox=sandbox, max_mutants=args.mutants, max_examples=args.examples,
                             implementer_model={"provider": "fixture", "model": variant})
            ui.console.print(f"  [dim]{t.name}/{variant}: {v.decision}[/]")
            return t.name, variant, v, rdir
        except Exception as e:
            ui.console.print(f"  [red]{t.name}/{variant}: error {e}[/]")
            return t.name, variant, None, None

    with ThreadPoolExecutor(max_workers=args.parallel) as ex:
        results = list(ex.map(one, jobs))
    table = Table(title="Adversary verdict matrix")
    for col in ("task", "change", "expected", "verdict", "caught by", "counterexample / finding", "run"):
        table.add_column(col, overflow="fold")
    correct = 0
    for name, variant, v, rdir in results:
        expected = "MERGE" if variant == "clean" else "BLOCK"
        if v is None:
            table.add_row(name, variant, expected, "[magenta]ERROR[/]", "", "", "")
            continue
        ok = v.decision == expected
        correct += ok
        blockers = [c for c in v.checks if c.blocking]
        caught = ", ".join(c.id for c in blockers) or "-"
        detail = ""
        pt = next(c for c in v.checks if c.id == "property_tests")
        if pt.details.get("counterexamples"):
            detail = pt.details["counterexamples"][0]["falsifying"] or pt.details["counterexamples"][0]["message"][:80]
        elif blockers:
            detail = blockers[0].summary[:90]
        style = "green" if ok else "bold red"
        table.add_row(name, variant, expected, f"[{style}]{v.decision}[/]", caught, detail, rdir.name if rdir else "")
    ui.console.print(table)
    ui.console.print(f"[bold]{correct}/{len(results)} correct[/]")
    return 0 if correct == len(results) else 1


def cmd_learn(args) -> int:
    from . import learn
    learn.learn([t.strip() for t in args.train.split(",") if t.strip()], [t.strip() for t in args.heldout.split(",") if t.strip()],
                rounds=args.rounds, seed=args.seed, console=ui.console)
    return 0


def cmd_playbook(args) -> int:
    from . import learn
    learn.show(ui.console)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "swarm":
        # Fetch.ai uAgents verifier swarm: specialists vote on a verdict, reputation-weighted
        from .swarm.cli import main as swarm_main
        return swarm_main(argv[1:])
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
    sub.add_parser("swarm", help="Fetch.ai uAgents verifier swarm (see `adversary swarm -h`)")
    r = sub.add_parser("run")
    r.add_argument("task")
    r.add_argument("--plant", default="none", choices=sorted(implementer.PLANTS))
    r.add_argument("--fixture", default=None)
    r.add_argument("--open-pr", action="store_true", help="push the change as a real GitHub PR and gate it")
    r.add_argument("--no-post", action="store_true")
    common(r)
    r.set_defaults(fn=cmd_run)
    v = sub.add_parser("verify")
    v.add_argument("task")
    v.add_argument("--change", required=True)
    common(v)
    v.set_defaults(fn=cmd_verify)
    g = sub.add_parser("gate", help="verify a GitHub PR and post a commit status + comment")
    g.add_argument("pr", type=int)
    g.add_argument("--no-post", action="store_true", help="don't post status/comment")
    common(g)
    g.set_defaults(fn=cmd_gate)
    pg = sub.add_parser("playground", help="write tasks/<task>/base to pr_demo/<task>/ for PR-based demos")
    pg.add_argument("task")
    pg.set_defaults(fn=cmd_playground)
    mx = sub.add_parser("matrix", help="run every task x fixture; clean must MERGE, planted variants must BLOCK")
    mx.add_argument("--tasks", default=None)
    mx.add_argument("--parallel", type=int, default=3)
    common(mx)
    mx.set_defaults(fn=cmd_matrix)
    ln = sub.add_parser("learn", help="improve the verifier's playbook; adopt only held-out-validated tactics")
    ln.add_argument("--train", required=True, help="comma-separated task names to learn from")
    ln.add_argument("--heldout", required=True, help="comma-separated held-out task names")
    ln.add_argument("--rounds", type=int, default=1)
    ln.add_argument("--seed", type=int, default=1337)
    ln.set_defaults(fn=cmd_learn)
    sub.add_parser("playbook", help="show playbook versions and the adopt/rollback log").set_defaults(fn=cmd_playbook)
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
