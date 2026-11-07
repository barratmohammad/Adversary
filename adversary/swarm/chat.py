"""Text interface for the coordinator's chat protocol (what an ASI:One user types).

  review <sample|run_dir|verdict.json> [block|allow]   run the swarm; optional ground truth settles stakes
  <a pasted verdict JSON>                              same, for a verdict the user pastes
  reputation                                           current voting weights
  samples                                              bundled sample verdicts
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Awaitable, Callable

from ..hashing import short
from .engine import Job, load_verdict
from .reputation import Ledger

HELP = ("I'm the **Adversary Swarm Verify** coordinator. Five specialist verifier agents (security, cheat, spec, mutation, "
        "and a deliberately lenient one) vote on whether an AI-written code change is safe to merge, weighted by reputation "
        "they earn when they're right.\n\n"
        "Try: `review cheat_roman`, `review subtle_intervals block`, `reputation`, `samples`, or paste a verdict.json.")


def _samples() -> list[Path]:
    from .cli import sample_paths
    return sample_paths()


def _resolve(token: str) -> Path | None:
    from .cli import SAMPLES_DIR
    for cand in (Path(token), SAMPLES_DIR / token, SAMPLES_DIR / f"{token}.json"):
        if cand.exists() and (cand.is_dir() and (cand / "verdict.json").exists() or cand.suffix == ".json"):
            return cand
    return None


def format_decision(d, label: str | None) -> str:
    head = "⛔ **SWARM BLOCKS THE MERGE**" if d.decision == "BLOCK" else "✅ **SWARM APPROVES THE MERGE**"
    lines = [f"{head} - {d.reason}", "", f"run `{d.run_id}` · task `{d.task}` · verdict `{short(d.verdict_sha256)}` · pipeline said {d.pipeline_decision}", "",
             "| specialist | weight | vote | conf | rationale |", "|---|---|---|---|---|"]
    for v in d.votes:
        vote = "VETO" if v.get("veto") else v["decision"].upper()
        lines.append(f"| {v['agent']} | {v['weight']:.2f} | {vote} | {v['confidence']:.2f} | {v['rationale'][:90]} |")
    lines.append("")
    lines.append(f"tally: block {d.block_mass:.2f} vs allow {d.allow_mass:.2f} (p_block {d.p_block:.0%}) · decision sha256 `{short(d.decision_sha256, 16)}`")
    if label:
        ok = (label == "block") == (d.decision == "BLOCK")
        lines.append(f"ground truth **{label.upper()}**: swarm was {'right' if ok else 'WRONG'}; stakes settled.")
    else:
        lines.append("no ground truth given: decision recorded as pending.")
    return "\n".join(lines)


def format_reputation(ledger: Ledger) -> str:
    lines = ["| specialist | weight | right | wrong | accuracy |", "|---|---|---|---|---|"]
    for a, r in sorted(ledger.agents.items(), key=lambda kv: -kv[1].reputation):
        lines.append(f"| {a} | {r.reputation:.2f} | {r.correct} | {r.wrong} | {r.accuracy:.0%} |")
    return "\n".join(lines)


async def handle_text(text: str, ledger: Ledger, review: Callable[[Job], Awaitable]) -> str:
    t = text.strip()
    low = t.lower()
    if "{" in t and '"checks"' in t:
        try:
            verdict = json.loads(t[t.index("{"): t.rindex("}") + 1])
        except ValueError as e:
            return f"couldn't parse that verdict JSON: {e}"
        gt = verdict.get("ground_truth") or {}
        d, _ = await review(Job(verdict, None, verdict.get("run_id", "pasted")))
        ledger.save()
        return format_decision(d, None) + (f"\n(the verdict carries ground truth {gt.get('label')!r}; say `review <path> {gt.get('label')}` to settle)" if gt.get("label") else "")
    if low in ("", "help", "hi", "hello", "?") or low.startswith("help"):
        return HELP
    if low.startswith(("reputation", "leaderboard", "weights")):
        return format_reputation(ledger)
    if low.startswith("samples"):
        return "\n".join(f"- `{p.stem}`: {load_verdict(p)[0].get('ground_truth', {}).get('why', '')}" for p in _samples())
    words = re.findall(r"[\w./:-]+", t)
    if words and words[0].lower() in ("review", "verify", "check"):
        words = words[1:]
    label = next((w.lower() for w in words if w.lower() in ("block", "allow")), None)
    target = next((p for p in (_resolve(w) for w in words if w.lower() not in ("block", "allow")) if p), None)
    if target is None:
        return "I couldn't find that verdict. " + HELP
    verdict, _ = load_verdict(target)
    d, _ = await review(Job(verdict, label, target.stem))
    ledger.save()
    return format_decision(d, label)
