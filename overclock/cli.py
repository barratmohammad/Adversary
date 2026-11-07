"""OVERCLOCK terminal view (not a dashboard: a live log of what the loop decides and why)."""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from overclock import attacks, harness, loop
from overclock import playbook as pb
from overclock.tasks import ALL, HELD_OUT, LEARN, load

app = typer.Typer(add_completion=False, no_args_is_help=True, help="OVERCLOCK x ADVERSARY")
con = Console()

STATUS_STYLE = {"win": "bold green", "slow": "yellow", "incorrect": "bold red", "blocked": "bold red",
                "timing-cheat": "bold red", "error": "red", "MERGE": "bold green", "BLOCK": "bold red",
                "keep": "bold green", "rollback": "bold red", "no-rule": "dim"}


def _st(s: str) -> str:
    return f"[{STATUS_STYLE.get(s, 'white')}]{s.upper()}[/]"


def _x(v: float | None) -> str:
    return f"{v:.1f}x" if v else "-"


def emit(e: dict) -> None:
    ev = e["event"]
    t = e.get("task", "")
    if ev == "optimize":
        mode = "exploring" if e.get("explore") else "deploy policy"
        con.print(f"  [cyan]{t}[/] optimizer (playbook v{e['version']}, {mode}) rewriting…")
    elif ev == "correctness":
        con.print(f"  [cyan]{t}[/] differential check vs reference…")
    elif ev == "incorrect":
        con.print(f"  [cyan]{t}[/] {_st('incorrect')} {e['detail']}")
    elif ev == "gate" and e["status"] == "running":
        con.print(f"  [cyan]{t}[/] [magenta]ADVERSARY[/] verifying spec + diff (blind)…")
    elif ev == "gate-check":
        icon = {"pass": "[green]✔[/]", "fail": "[red]✘[/]", "warn": "[yellow]![/]", "skip": "[dim]-[/]",
                "error": "[red]✘[/]", "running": "[dim]…[/]"}.get(e["status"], "?")
        if e["status"] != "running":
            con.print(f"      {icon} {e['check']:<18} {e['msg'][:95]}")
    elif ev == "gate":
        con.print(f"  [cyan]{t}[/] [magenta]ADVERSARY[/] verdict: {_st(e['status'])}  outcome sha256:{e['sha'][:12]}")
    elif ev == "bench":
        con.print(f"  [cyan]{t}[/] stopwatch (median of 7, then fresh-seed re-time)…")
    elif ev == "timing-cheat":
        con.print(f"  [cyan]{t}[/] {_st('timing-cheat')} {e['speedup']:.1f}x on published inputs but "
                  f"{e['fresh']:.1f}x on fresh inputs")
    elif ev == "bench-done":
        con.print(f"  [cyan]{t}[/] {_st(e['status'])} {e['slow_ms']:.1f} ms -> {e['fast_ms']:.2f} ms = "
                  f"[bold]{e['speedup']:.1f}x[/] (fresh seed {_x(e['fresh'])})")
    elif ev == "heldout-begin":
        con.print(f"\n[bold]held-out baseline[/] playbook v{e['version']} on {', '.join(e['tasks'])}")
    elif ev == "heldout-task":
        con.print(f"  [dim]held-out[/] {e['task']} (v{e['version']})")
    elif ev == "heldout-cached":
        con.print(f"  [dim]held-out score for v{e['version']} from cache:[/] gmean {e['gmean']:.2f}x")
    elif ev == "heldout-done":
        per = "  ".join(f"{k}={_x(v['effective'])}" for k, v in e["per_task"].items())
        con.print(f"  held-out v{e['version']}: [bold]gmean {e['gmean']:.2f}x[/]  ({per})")
    elif ev == "learn-task":
        con.rule(f"[bold]learn from {t}[/]  (playbook v{e['version']})")
    elif ev == "reflect":
        con.print(f"  [cyan]{t}[/] reflecting: writing one general rule…")
    elif ev == "candidate":
        con.print(Panel(e["rule"], title=f"candidate rule -> playbook v{e['version']}", border_style="blue"))
    elif ev == "step":
        d = e["decision"]
        if d == "no-rule":
            con.print(f"  -> {_st('no-rule')} {e['why']}")
        else:
            con.print(f"  -> {_st(d)} held-out {e['heldout_before']:.2f}x -> {e['heldout_after']:.2f}x "
                      f"({'kept as v%d' % e['candidate_version'] if d == 'keep' else 'v%d rolled back' % e['candidate_version']})")
    elif ev == "error":
        con.print(f"  [red]error:[/] {e['error']}")


@app.command()
def tasks() -> None:
    """List the task bank."""
    tb = Table("task", "function", "split", "tags")
    for n in ALL:
        t = load(n)
        tb.add_row(n, t.signature, t.split, ", ".join(t.tags))
    con.print(tb)


@app.command()
def bench(task: str, file: Path | None = typer.Option(None, help="candidate .py defining the function")) -> None:
    """Correctness + stopwatch for a candidate (defaults to slow-vs-slow)."""
    t = load(task)
    src = file.read_text() if file else t.public_source
    r = harness.benchmark(t, src)
    con.print_json(json.dumps(r.to_dict(), default=str))


@app.command()
def optimize(task: str, no_gate: bool = typer.Option(False, "--no-gate"), show_code: bool = True,
             version: int | None = typer.Option(None, help="playbook version to use (default: current)")) -> None:
    """One optimize -> verify -> time pass for a single task."""
    t = load(task)
    book = pb.load_current() if version is None else pb.Playbook.from_dict(
        json.loads((pb.PLAYBOOK_DIR / f"v{version:03d}.json").read_text()))
    con.print(f"[bold]{t.name}[/] with playbook v{book.version} ({len(book.rules)} rules)")
    run = loop.run_task(t, book, use_gate=not no_gate, emit=emit)
    if show_code and run.source:
        con.print(Syntax(run.source, "python", theme="ansi_dark", line_numbers=False))
    con.print(f"result: {_st(run.status)}  speed-up {_x(run.speedup)}")


@app.command()
def learn(heldout_n: int = typer.Option(3, help="how many held-out tasks score each candidate rule"),
          tasks: str = typer.Option("", help="comma-separated learn tasks (default: all LEARN)"),
          heldout: str = typer.Option("", help="comma-separated held-out tasks (default: HELD_OUT)"),
          no_gate: bool = typer.Option(False, "--no-gate", help="skip Adversary on learn tasks"),
          no_gate_heldout: bool = typer.Option(False, "--no-gate-heldout", help="skip Adversary on held-out"),
          reset: bool = typer.Option(False, help="wipe the playbook and ledger first")) -> None:
    """Run the self-improvement loop."""
    if reset:
        import shutil
        pb.reset()
        shutil.rmtree(loop.CACHE, ignore_errors=True)
        con.print("[yellow]playbook reset to v000; held-out score cache cleared[/]")
    learn_names = [s for s in tasks.split(",") if s] or None
    held_names = [s for s in heldout.split(",") if s] or None
    rep = loop.learn(learn_names, held_names, heldout_n=heldout_n, use_gate=not no_gate,
                     gate_heldout=not no_gate_heldout, emit=emit)
    con.rule("[bold]summary[/]")
    tb = Table("learned from", "run", "speed-up", "rule", "held-out before", "after", "decision")
    for s in rep.steps:
        tb.add_row(s["task"], s["run"], _x(s.get("speedup")), (s.get("rule") or s.get("why") or "")[:70],
                   f"{s['heldout_before']:.2f}x" if "heldout_before" in s else "-",
                   f"{s['heldout_after']:.2f}x" if "heldout_after" in s else "-", _st(s["decision"]))
    con.print(tb)
    con.print(f"playbook v{rep.start_version} -> v{rep.end_version}")


@app.command()
def playbook() -> None:
    """Show playbook versions and the keep/rollback ledger."""
    cur = pb.load_current()
    con.print(f"[bold]current playbook v{cur.version}[/] ({len(cur.rules)} rules)")
    for r in cur.rules:
        con.print(f"  [{r.id}] (v{r.version_added}, from {r.learned_from}, held-out "
                  f"{_x(r.heldout_before)} -> {_x(r.heldout_after)}) {r.text}")
    tb = Table("version", "status", "from", "rule / why", "held-out before", "after", "decision")
    for p in sorted(pb.PLAYBOOK_DIR.glob("v*.json")):
        d = json.loads(p.read_text())
        tb.add_row(f"v{d['version']:03d}", d.get("status", "accepted"),
                   d["rules"][-1]["learned_from"] if d["rules"] else "-",
                   (d["rules"][-1]["text"][:60] if d["rules"] else "(empty)"),
                   _x(d["rules"][-1].get("heldout_before")) if d["rules"] else "-",
                   _x(d["rules"][-1].get("heldout_after")) if d["rules"] else "-",
                   _st({"accepted": "keep", "rolled_back": "rollback"}.get(d.get("status"), d.get("status", ""))))
    con.print(tb)


def _attack(task: str, kind: str, use_gate: bool) -> loop.TaskRun:
    t = load(task)
    src = attacks.build(kind, t)
    con.print(Panel(Syntax(src if len(src) < 2500 else src[:1200] + "\n# … (answer table elided) …\n" + src[-500:],
                           "python", theme="ansi_dark"), title=f"planted '{kind}' rewrite of {t.func}", border_style="red"))
    book = pb.load_current()
    # Reuse the loop's own gauntlet so the attack faces exactly what a real rewrite faces.
    from overclock import optimizer as _opt
    real = _opt.optimize
    try:
        _opt.optimize = lambda tk, book_, **kw: _opt.OptimizeResult(tk.name, src, src, "planted", True, book_.version)
        run = loop.run_task(t, book, use_gate=use_gate, emit=emit, label=f"attack-{kind}")
    finally:
        _opt.optimize = real
    con.print(f"outcome: {_st(run.status)}" + (f"  speed-up {_x(run.speedup)}" if run.speedup else ""))
    return run


@app.command()
def attack(task: str = typer.Argument("t02_membership"), kind: str = typer.Option("edge", help="table | edge | escape"),
           no_gate: bool = typer.Option(False, "--no-gate")) -> None:
    """Plant a cheating rewrite and watch it get caught."""
    _attack(task, kind, not no_gate)


@app.command()
def demo(unseen: str = "h02_common_elements", heldout_n: int = 3) -> None:
    """The 3-minute story: unseen task before learning, learn, show a rollback, same task after, then an attack."""
    con.rule("[bold]1. unseen function, EMPTY playbook (deployment policy)[/]")
    t = load(unseen)
    empty = pb.Playbook()
    before = loop.run_task(t, empty, emit=emit)
    con.rule("[bold]1b. same function, EMPTY playbook, UNCONSTRAINED exploration (the baseline a skeptic asks for)[/]")
    free = loop.run_task(t, empty, emit=emit, explore=True, label="baseline-explore")
    con.rule("[bold]2. learn[/]")
    rep = loop.learn(None, None, heldout_n=heldout_n, emit=emit)
    con.rule("[bold]3. one rule that failed held-out and was rolled back[/]")
    rb = [s for s in rep.steps if s.get("decision") == "rollback"]
    if rb:
        s = rb[0]
        con.print(Panel(f"{s['rule']}\n\nheld-out {s['heldout_before']:.2f}x -> {s['heldout_after']:.2f}x  => "
                        f"[bold red]ROLLBACK[/] (v{s['candidate_version']} kept on disk as evidence)", border_style="red"))
    else:
        con.print("[dim]no rollback this run; see `overclock playbook` for history[/]")
    con.rule(f"[bold]4. same unseen function, LEARNED playbook v{pb.load_current().version}[/]")
    after = loop.run_task(t, pb.load_current(), emit=emit)
    learned = after.speedup or 0
    beats_free = learned > (free.speedup or 0)
    con.print(Panel(
        f"{t.func}\n"
        f"  empty playbook, deployment policy : {_x(before.speedup)}\n"
        f"  empty playbook, unconstrained     : {_x(free.speedup)}   <- the skeptic's baseline\n"
        f"  learned playbook, deployment policy: [bold]{_x(after.speedup)}[/]\n\n"
        + ("[green]The learned playbook beats even the unconstrained optimizer: the gain comes from learned rules, "
           "not from relaxing the policy.[/]" if beats_free else
           "[yellow]The learned playbook does NOT beat the unconstrained optimizer on this function: the honest read is "
           "that the rules transfer the policy's permissions, not new knowledge.[/]"),
        title="the learning effect", border_style="green" if beats_free else "yellow"))
    con.rule("[bold]5. a planted cheat[/]")
    _attack(unseen if unseen in attacks._EDGE else "t02_membership", "edge", True)


if __name__ == "__main__":
    app()
