"""Terminal view (rich): agents arguing in real time.

``ReviewView`` renders one job live: each specialist's vote as it arrives over uAgents
messaging, the running weighted tally, then the decision and the stake settlement.
``CalibrationView`` renders many rounds: reputations converging and swarm accuracy per round.
"""
from __future__ import annotations

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from ..hashing import short
from .consensus import SwarmDecision
from .policies import ROLES
from .reputation import MAX_REP, Ledger, Settlement

console = Console()

VOTE_STYLE = {"block": ("BLOCK", "bold red"), "allow": ("ALLOW", "bold green"), "abstain": ("ABSTAIN", "dim")}
SPARK = "▁▂▃▄▅▆▇█"


def _addr(a: str) -> str:
    return f"{a[:10]}…{a[-4:]}" if a and len(a) > 16 else (a or "")


def _bar(frac: float, width: int = 24, on: str = "red", off: str = "green") -> Text:
    frac = max(0.0, min(1.0, frac))
    n = round(frac * width)
    t = Text()
    t.append("█" * n, style=on)
    t.append("█" * (width - n), style=off)
    return t


def _rep_bar(r: float, width: int = 18) -> Text:
    n = max(0, min(width, round(r / MAX_REP * width)))
    style = "green" if r >= 1.0 else ("yellow" if r >= 0.5 else "red")
    t = Text("■" * n, style=style)
    t.append("·" * (width - n), style="dim")
    return t


def banner(mode: str) -> None:
    console.print(Rule("[bold magenta]ADVERSARY · SWARM VERIFY[/]  specialist uAgents vote, stake, and earn trust"))
    console.print(f"[dim]{mode}[/]\n")


class ReviewView:
    """Live table for one job; fed by SwarmRuntime events."""

    def __init__(self, agents: tuple[str, ...], ledger: Ledger, live: bool = True) -> None:
        self.agents = agents
        self.ledger = ledger
        self.votes: dict[str, dict] = {}
        self.job = None
        self.addresses: dict[str, str] = {}
        self.weights: dict[str, float] = {}
        self.decision: SwarmDecision | None = None
        self.settlements: list[Settlement] | None = None
        self.order: list[str] = []
        self._live = Live(self._render(), console=console, refresh_per_second=15, transient=False) if live else None

    def __enter__(self):
        if self._live:
            self._live.__enter__()
        return self

    def __exit__(self, *a):
        if self._live:
            self._live.update(self._render())
            self._live.__exit__(*a)
            console.print()
            console.print()

    def on_event(self, kind: str, p: dict) -> None:
        if kind == "job_start":
            self.job, self.addresses, self.weights = p["job"], p["addresses"], p["weights"]
            self.votes, self.order, self.decision, self.settlements = {}, [], None, None
        elif kind == "vote":
            self.votes[p["vote"]["agent"]] = p["vote"]
            self.order.append(p["vote"]["agent"])
        elif kind == "decision":
            self.decision, self.settlements = p["decision"], p["settlements"]
        if self._live:
            self._live.update(self._render())

    # ------------------------------------------------------------------------------------------
    def _tally(self) -> tuple[float, float]:
        b = sum(self.weights.get(a, 1) * v["confidence"] for a, v in self.votes.items() if v["decision"] == "block")
        al = sum(self.weights.get(a, 1) * v["confidence"] for a, v in self.votes.items() if v["decision"] == "allow")
        return b, al

    def _render(self):
        parts = []
        if self.job is not None:
            v = self.job.verdict
            head = Text.assemble(("run ", "dim"), (v.get("run_id", "?"), "bold"), ("  task ", "dim"), (v.get("task", "?"), "bold"),
                                 ("  verdict ", "dim"), (short(v.get("verdict_sha256", "")), "bold"), ("  pipeline said ", "dim"),
                                 (v.get("decision", "?"), "bold red" if v.get("decision") == "BLOCK" else "bold green"))
            parts.append(head)
        t = Table(show_header=True, header_style="bold", expand=True, box=None, padding=(0, 1))
        t.add_column("#", width=2, justify="right", style="dim")
        t.add_column("specialist", width=15)
        t.add_column("uAgent address", width=16, style="dim")
        t.add_column("weight", width=6, justify="right")
        t.add_column("vote", width=8)
        t.add_column("conf", width=5, justify="right")
        t.add_column("stake", width=6, justify="right")
        t.add_column("rationale", ratio=1, overflow="ellipsis", no_wrap=True)
        for a in self.agents:
            w = self.weights.get(a, self.ledger.weight(a))
            vote = self.votes.get(a)
            if vote is None:
                waiting = Spinner("dots", text=Text(" reviewing…", style="cyan"), style="cyan") if self.job else Text("")
                t.add_row("", Text(a, style="bold"), _addr(self.addresses.get(a, "")), f"{w:.2f}", waiting, "", "", Text(ROLES.get(a, ""), style="dim"))
                continue
            label, style = VOTE_STYLE[vote["decision"]]
            if vote.get("veto"):
                label, style = "VETO", "bold white on red"
            t.add_row(str(self.order.index(a) + 1), Text(a, style="bold"), _addr(self.addresses.get(a, "")), f"{w:.2f}", Text(label, style=style),
                      f"{vote['confidence']:.2f}", f"{vote['stake']:.3f}", vote["rationale"])
        parts.append(t)
        b, al = self._tally()
        tot = b + al
        frac = b / tot if tot else 0.0
        tl = Text.assemble(("tally  ", "bold"), ("block ", "red"), (f"{b:.2f} ", "bold red"))
        tl.append_text(_bar(frac))
        tl.append_text(Text.assemble((f" {al:.2f}", "bold green"), (" allow", "green"), (f"   p_block {frac:.0%}", "dim"),
                                     (f"   {len(self.votes)}/{len(self.agents)} votes in", "dim")))
        parts.append(Text(""))
        parts.append(tl)
        if self.decision is not None:
            parts.append(Text(""))
            parts.append(_decision_text(self.decision, getattr(self.job, "label", None)))
        if self.settlements:
            parts.append(Text(""))
            parts.append(_settlement_table(self.settlements, self.ledger))
        return Panel(Group(*parts), title="[bold]SWARM[/] · Fetch.ai uAgents Bureau", border_style="magenta", padding=(0, 1))


def _decision_text(d: SwarmDecision, label: str | None) -> Text:
    block = d.decision == "BLOCK"
    t = Text("⛔  SWARM BLOCKS THE MERGE" if block else "✅  SWARM APPROVES THE MERGE", style="bold red" if block else "bold green")
    t.append(f"   {d.reason}", style="red" if block else "green")
    if d.missing:
        t.append(f"   (no vote from: {', '.join(d.missing)})", style="yellow")
    t.append(f"\n   decision sha256:{short(d.decision_sha256, 16)}", style="dim")
    if label:
        ok = (label == "block") == block
        t.append(f"   ground truth: {label.upper()} ", style="bold")
        t.append("✔ correct" if ok else "✘ WRONG", style="bold green" if ok else "bold red")
    return t


def _settlement_table(st: list[Settlement], ledger: Ledger) -> Table:
    t = Table(title="stakes settled against ground truth", title_style="bold", show_header=True, header_style="bold", box=None, padding=(0, 1))
    t.add_column("specialist", width=15)
    t.add_column("voted", width=8)
    t.add_column("staked", width=7, justify="right")
    t.add_column("result", width=9)
    t.add_column("reputation", width=17)
    t.add_column("Δ", width=8, justify="right")
    t.add_column("", width=18)
    t.add_column("accuracy", width=8, justify="right")
    for s in st:
        if s.correct is None:
            res = Text("abstained", style="dim")
        else:
            res = Text("✔ right", style="green") if s.correct else Text("✘ wrong", style="red")
        dl = s.delta
        dstyle = "green" if dl > 0 else ("red" if dl < 0 else "dim")
        acc = ledger.agents[s.agent].accuracy
        t.add_row(s.agent, VOTE_STYLE[s.decision][0], f"{s.stake:.3f}", res, f"{s.before:.3f} → {s.after:.3f}", Text(f"{dl:+.3f}", style=dstyle),
                  _rep_bar(s.after), f"{acc:.0%}")
    return t


def reputation_table(ledger: Ledger, title: str = "reputation ledger") -> Table:
    t = Table(title=title, title_style="bold", show_header=True, header_style="bold")
    t.add_column("specialist")
    t.add_column("weight", justify="right")
    t.add_column("")
    t.add_column("right", justify="right")
    t.add_column("wrong", justify="right")
    t.add_column("abstain", justify="right")
    t.add_column("won", justify="right")
    t.add_column("lost", justify="right")
    t.add_column("accuracy", justify="right")
    for a, r in sorted(ledger.agents.items(), key=lambda kv: -kv[1].reputation):
        t.add_row(a, f"{r.reputation:.3f}", _rep_bar(r.reputation), str(r.correct), str(r.wrong), str(r.abstained),
                  f"{r.won:.3f}", f"{r.lost:.3f}", f"{r.accuracy:.0%}")
    s = ledger.swarm
    if s.get("settled"):
        t.caption = f"swarm accuracy on settled decisions: {s['correct']}/{s['settled']} · {sum(1 for d in ledger.decisions if not d.get('settled'))} pending"
    return t


class CalibrationView:
    """Live view of reputations converging over calibration rounds."""

    def __init__(self, agents: tuple[str, ...], samples: list[str], labels: dict[str, str], rounds: int, ledger: Ledger) -> None:
        self.agents, self.samples, self.labels, self.rounds, self.ledger = agents, samples, labels, rounds, ledger
        self.history: dict[str, list[float]] = {a: [ledger.weight(a)] for a in agents}
        self.grid: dict[tuple[int, str], tuple[str, bool]] = {}
        self.round = 0
        self.current = ""
        self.live_votes: dict[str, dict] = {}
        self._live = Live(self._render(), console=console, refresh_per_second=15)

    def __enter__(self):
        self._live.__enter__()
        return self

    def __exit__(self, *a):
        self.current = ""
        self._live.update(self._render())
        self._live.__exit__(*a)
        console.print()
        console.print()

    def on_event(self, kind: str, p: dict) -> None:
        if kind == "job_start":
            self.round = p["index"] // len(self.samples)
            self.current = p["job"].name
            self.live_votes = {}
        elif kind == "vote":
            self.live_votes[p["vote"]["agent"]] = p["vote"]
        elif kind == "decision":
            d, job = p["decision"], p["job"]
            ok = (d.decision == "BLOCK") == (job.label == "block")
            self.grid[(self.round, job.name)] = (d.decision, ok)
            if job.name == self.samples[-1]:
                for a in self.agents:
                    self.history[a].append(self.ledger.weight(a))
        self._live.update(self._render())

    def _render(self):
        g = Table(title="swarm decision per round (✔ matches ground truth)", title_style="bold", header_style="bold", box=None, padding=(0, 1))
        g.add_column("sample", width=24)
        g.add_column("truth", width=6)
        for r in range(self.rounds):
            g.add_column(f"r{r + 1}", width=7, justify="center")
        for s in self.samples:
            row = [Text(s, style="bold" if s == self.current else ""), Text(self.labels.get(s, "?").upper(), style="dim")]
            for r in range(self.rounds):
                cell = self.grid.get((r, s))
                if cell is None:
                    row.append(Text("·", style="dim") if not (r == self.round and s == self.current) else Text("…", style="cyan"))
                else:
                    dec, ok = cell
                    row.append(Text(f"{dec[:5]} {'✔' if ok else '✘'}", style="green" if ok else "bold red"))
            g.add_row(*row)
        acc = [Text("accuracy", style="bold"), Text("")]
        for r in range(self.rounds):
            cells = [self.grid.get((r, s)) for s in self.samples]
            if all(cells):
                k = sum(1 for c in cells if c[1])
                acc.append(Text(f"{k}/{len(cells)}", style="bold green" if k == len(cells) else "bold yellow"))
            else:
                acc.append(Text(""))
        g.add_row(*acc)

        rt = Table(title="voting weight (reputation) per specialist", title_style="bold", header_style="bold", box=None, padding=(0, 1))
        rt.add_column("specialist", width=15)
        rt.add_column("trend", width=self.rounds + 2)
        rt.add_column("weight", width=14)
        rt.add_column("", width=18)
        rt.add_column("acc", width=5, justify="right")
        for a in sorted(self.agents, key=lambda a: -self.ledger.weight(a)):
            h = self.history[a]
            spark = "".join(SPARK[min(len(SPARK) - 1, int(x / MAX_REP * (len(SPARK) - 1) + 0.5))] for x in h)
            cur = self.ledger.weight(a)
            trend_style = "green" if cur >= h[0] else "red"
            rt.add_row(Text(a, style="bold"), Text(spark, style=trend_style), f"{h[0]:.2f} → {cur:.2f}", _rep_bar(cur), f"{self.ledger.agents[a].accuracy:.0%}")
        live = Text("")
        if self.current:
            live = Text.assemble((f"round {self.round + 1}/{self.rounds} · reviewing {self.current}: ", "cyan"))
            for a in self.agents:
                v = self.live_votes.get(a)
                if v:
                    lab, sty = VOTE_STYLE[v["decision"]]
                    live.append(f"{a.split('-')[0]}={lab.lower()} ", style=sty)
        return Panel(Group(g, Text(""), rt, Text(""), live), title="[bold]SWARM CALIBRATION[/] · Fetch.ai uAgents Bureau", border_style="magenta")
