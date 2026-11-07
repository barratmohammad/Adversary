"""Terminal view (rich). Live check progress, then the verdict."""
from __future__ import annotations

import time

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.spinner import Spinner
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from .hashing import short
from .verdict import Verdict

console = Console()

ORDER = ["security", "cheat", "import", "implementer_tests", "property_tests", "mutation"]
TITLES = {
    "security": "Security pass",
    "cheat": "Cheat detector",
    "import": "Sandbox import",
    "implementer_tests": "Implementer's own tests",
    "property_tests": "Blind property tests",
    "mutation": "Mutation testing",
}
ICON = {"pass": ("✔", "green"), "fail": ("✘", "bold red"), "warn": ("!", "yellow"), "skip": ("-", "dim"),
        "error": ("✘", "bold magenta"), "pending": ("·", "dim"), "running": (None, "cyan")}


class LiveChecks:
    def __init__(self) -> None:
        self.state = {k: ("pending", "") for k in ORDER}
        self.t0 = {}
        self.t1 = {}
        self.live = Live(self._render(), console=console, refresh_per_second=12, transient=False)

    def __enter__(self):
        self.live.__enter__()
        return self

    def __exit__(self, *a):
        self.live.update(self._render())
        self.live.__exit__(*a)
        console.print()

    def emit(self, cid: str, status: str, msg: str) -> None:
        if cid not in self.state:
            return
        if status == "running" and cid not in self.t0:
            self.t0[cid] = time.monotonic()
        if status != "running":
            self.t1[cid] = time.monotonic()
        self.state[cid] = (status, msg)
        self.live.update(self._render())

    def _render(self):
        t = Table.grid(padding=(0, 1))
        t.add_column(width=2)
        t.add_column(width=26)
        t.add_column(ratio=1)
        t.add_column(width=7, justify="right")
        for k in ORDER:
            status, msg = self.state[k]
            icon, style = ICON.get(status, ("?", "white"))
            glyph = Spinner("dots", style="cyan") if status == "running" else Text(icon, style=style)
            el = ""
            if k in self.t0:
                el = f"{(self.t1.get(k, time.monotonic()) - self.t0[k]):.1f}s"
            t.add_row(glyph, Text(TITLES[k], style="bold" if status == "running" else ""), Text(msg, style=style if status in ("fail", "error") else ""), Text(el, style="dim"))
        return Panel(t, title="[bold]ADVERSARY[/] · independent verifier", border_style="cyan", padding=(0, 1))


def banner(task_title: str, implementer: str, verifier: str, sandbox: str) -> None:
    console.print(Rule("[bold cyan]ADVERSARY[/]  trust, but verify"))
    if str(sandbox).startswith("local"):
        sandbox = f"{sandbox} [bold yellow]⚠ no isolation: network allowed (install Docker or run on macOS)[/]"
    console.print(f"[dim]task[/] {task_title}   [dim]implementer[/] {implementer}   [dim]verifier[/] {verifier}   [dim]sandbox[/] {sandbox}")
    console.print("[dim]information barrier: verifier sees spec + comment-stripped diff only; implementer reasoning and tests withheld[/]\n")


def show_diff(diff: str, max_lines: int = 60) -> None:
    lines = diff.splitlines()
    shown = "\n".join(lines[:max_lines]) + (f"\n... ({len(lines) - max_lines} more lines)" if len(lines) > max_lines else "")
    console.print(Panel(Syntax(shown or "(empty diff)", "diff", theme="ansi_dark", word_wrap=True), title="proposed change", border_style="dim"))


def show_verdict(v: Verdict, run_dir) -> None:
    block = v.decision == "BLOCK"
    color = "red" if block else "green"
    head = Text("⛔  MERGE BLOCKED" if block else "✅  SAFE TO MERGE", style=f"bold {color}")
    body = [head, Text("")]
    for r in v.reasons:
        body.append(Text(f"• {r}", style=color if block else "green"))
    checks = {c.id: c for c in v.checks}
    ce = checks.get("property_tests")
    if ce and ce.details.get("counterexamples"):
        body.append(Text(""))
        body.append(Text("counterexamples (reproducible with the pinned seed):", style="bold"))
        for c in ce.details["counterexamples"][:3]:
            first = (c["falsifying"] or c["message"]).strip().splitlines()[0][:150] if (c["falsifying"] or c["message"]).strip() else ""
            body.append(Text(f"  {c['test']}: {first}", style="yellow"))
            if c.get("adjudication"):
                body.append(Text(f"    adjudicator: {c['adjudication']}", style="dim"))
    if ce and ce.details.get("discarded"):
        body.append(Text(f"  discarded as not spec-backed by the adjudicator: {', '.join(ce.details['discarded'])}", style="dim"))
    for cid in ("security", "cheat"):
        c = checks.get(cid)
        if c and c.status in ("fail", "warn"):
            for f in c.details.get("findings", [])[:3]:
                body.append(Text(f"  [{f.get('severity')}] {f.get('rule', f.get('kind'))} {f.get('path')}:{f.get('lineno')} {f.get('message', '')[:140]}", style="yellow"))
    mu = checks.get("mutation")
    if mu and mu.details.get("only_adversary_caught"):
        body.append(Text(""))
        body.append(Text("mutants only the adversary caught:", style="bold"))
        for m in mu.details["only_adversary_caught"][:3]:
            body.append(Text(f"  {m['description']}", style="dim"))
    so = (v.independence or {}).get("second_opinion")
    if so and "risk" in so:
        body.append(Text(""))
        body.append(Text(f"second opinion (SubQ Snap, advisory): merge risk {so['risk']:.2f}/3 \"{so['risk_label']}\" · P(gamed) {so['p_gamed']:.2f}", style="bold"))
    ind = v.independence or {}
    if "model_differs" in ind:
        if ind["model_differs"] is None:
            parts = [f"implementer: pre-recorded change (no model) · verifier {ind.get('verifier_model')}"]
        else:
            parts = [
                f"implementer {ind.get('implementer_model')} vs verifier {ind.get('verifier_model')}: "
                + ("different models" if ind["model_differs"] else "SAME MODEL"),
                "different vendors" if ind.get("vendor_differs") else "same vendor",
            ]
        parts.append("adjudicator from a different vendor" if ind.get("adjudicator_vendor_differs") else "adjudicator shares the verifier's vendor")
        body.append(Text("independence: " + " · ".join(parts), style="dim" if ind["model_differs"] is not False else "bold yellow"))
    body.append(Text(""))
    env = v.environment
    body.append(Text(f"seed {v.seed} · sandbox {env['sandbox']['kind']} (network {env['sandbox']['network']}) · python {env['python']} · lock {short(env['lock_sha256'])}", style="dim"))
    body.append(Text(f"spec {short(v.inputs['spec_sha256'])} · diff {short(v.inputs['diff_sha256'])} · tests {short(v.pinned['verifier_tests_sha256'] or '-')} · outcome {short(v.outcome_sha256)}", style="dim"))
    body.append(Text(f"verdict sha256:{v.verdict_sha256}", style="bold dim"))
    body.append(Text(f"reproduce: adversary reproduce {run_dir}", style="dim"))
    console.print(Panel(Group(*body), border_style=color, title="verdict", padding=(1, 2)))
