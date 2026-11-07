"""The verifier that gets better: a versioned playbook of test-writing tactics.

Each time Adversary's blind tests miss a defect on a training task (a known-bad change slips past
the property tests, or mutants survive them), it reflects on the miss and proposes ONE general,
task-agnostic tactic. The candidate playbook v(n+1) is adopted only if it improves the score on
HELD-OUT tasks the reflection never saw; otherwise it is rolled back. Every decision is logged with
the numbers.

  adversary learn --train roman,intervals --heldout safe_path --rounds 2
  adversary playbook                     # show versions + decision log
"""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import llm
from .hashing import sha256_json, sha256_text, short
from .workspace import ROOT, RUNS_DIR, Change, Task, load_task

PLAYBOOK_DIR = ROOT / ".adversary" / "playbook"
EXPECTED = {"clean": "MERGE"}  # every other fixture variant is a known-bad change -> BLOCK


@dataclass
class Playbook:
    version: int = 0
    tactics: list[dict] = field(default_factory=list)  # {id, text, rationale, learned_from, added_in}
    parent: int | None = None
    created_at: str = ""

    @property
    def sha256(self) -> str:
        return sha256_json(self.tactics)

    def text(self) -> str:
        return "\n".join(f"- {t['text']}" for t in self.tactics)


def _path(v: int) -> Path:
    return PLAYBOOK_DIR / f"v{v}.json"


def save(pb: Playbook) -> None:
    PLAYBOOK_DIR.mkdir(parents=True, exist_ok=True)
    _path(pb.version).write_text(json.dumps(asdict(pb), indent=2))
    (PLAYBOOK_DIR / "CURRENT").write_text(str(pb.version))


def load(v: int | None = None) -> Playbook:
    if v is None:
        cur = PLAYBOOK_DIR / "CURRENT"
        if not cur.exists():
            return Playbook(created_at=_now())
        v = int(cur.read_text().strip())
    return Playbook(**json.loads(_path(v).read_text()))


def current_playbook_text() -> str:
    try:
        return load().text()
    except Exception:
        return ""


def log_decision(entry: dict) -> None:
    PLAYBOOK_DIR.mkdir(parents=True, exist_ok=True)
    with open(PLAYBOOK_DIR / "log.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")
    try:
        import os
        if os.environ.get("MONGODB_URI"):
            from pymongo import MongoClient
            MongoClient(os.environ["MONGODB_URI"], serverSelectionTimeoutMS=4000)["adversary"]["playbook_log"].insert_one(dict(entry))
    except Exception:
        pass


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# ---------------------------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------------------------

@dataclass
class VariantResult:
    task: str
    variant: str
    expected: str
    decision: str
    prop_caught: bool        # did the blind property tests (the part the playbook improves) flag it?
    adversary_kill: float | None
    survivors: list[str]
    counterexamples: list[str]


def evaluate(tasks: list[Task], playbook: Playbook, seed: int = 1337, emit=None, max_mutants: int = 15, max_examples: int = 100) -> dict:
    from .implementer import from_fixture
    from .verifier.pipeline import verify

    results: list[VariantResult] = []
    for task in tasks:
        for variant in task.fixtures():
            change, _ = from_fixture(task, variant)
            if emit:
                emit(f"{task.name}/{variant}")
            v, _ = verify(task, change, seed=seed, playbook=playbook.text(), max_mutants=max_mutants, max_examples=max_examples,
                          run_dir=RUNS_DIR / "learn" / f"pb{playbook.version}-{short(playbook.sha256, 6)}-{task.name}-{variant}")
            checks = {c.id: c for c in v.checks}
            pt, mu = checks["property_tests"], checks["mutation"]
            results.append(VariantResult(
                task=task.name, variant=variant, expected=EXPECTED.get(variant, "BLOCK"), decision=v.decision,
                prop_caught=pt.status == "fail",
                adversary_kill=mu.details.get("score_adversary"),
                survivors=[s["description"] for s in mu.details.get("survivors", [])][:8],
                counterexamples=[c["falsifying"] for c in pt.details.get("counterexamples", [])][:3],
            ))
    return score(results)


def score(results: list[VariantResult]) -> dict:
    bad = [r for r in results if r.expected == "BLOCK"]
    clean = [r for r in results if r.expected == "MERGE"]
    catch = sum(r.prop_caught for r in bad) / len(bad) if bad else 0.0
    false_block = sum(r.prop_caught for r in clean) / len(clean) if clean else 0.0
    kills = [r.adversary_kill for r in clean if r.adversary_kill is not None]
    kill = sum(kills) / len(kills) if kills else 0.0
    return {
        # blind-test catch rate on known-bad changes + mutation kill rate on honest ones, false blocks penalised
        "score": round(catch + kill - 2 * false_block, 4),
        "catch_rate": round(catch, 4),
        "kill_rate": round(kill, 4),
        "false_block_rate": round(false_block, 4),
        "results": [asdict(r) for r in results],
    }


# ---------------------------------------------------------------------------------------------
# reflection
# ---------------------------------------------------------------------------------------------

REFLECT_SYSTEM = """You are ADVERSARY reviewing your own blind spots. Your property tests, written only from a spec,
missed real defects. Propose ONE new tactic for writing property-based tests that would catch this CLASS of defect
in other, unrelated code. It must be general: no function names, no task-specific values, no references to this spec.
One or two sentences, imperative voice. Do not repeat a tactic already in the playbook.
Respond with JSON only: {"tactic": "...", "rationale": "..."}"""


def reflect(task: Task, misses: list[VariantResult], playbook: Playbook) -> dict:
    lines = []
    for m in misses:
        fixture = task.fixture(m.variant)
        clean = task.fixture("clean") if "clean" in task.fixtures() else {}
        mod = task.module
        if m.expected == "BLOCK" and not m.prop_caught:
            import difflib
            d = "".join(difflib.unified_diff(clean.get(mod, "").splitlines(True), fixture.get(mod, "").splitlines(True), "correct", "defective"))
            lines.append(f"## Defective change your tests let through ({m.variant})\n```diff\n{d[-2500:]}\n```")
        if m.survivors:
            lines.append(f"## Mutants that survived your tests on the correct implementation\n" + "\n".join(f"- {s}" for s in m.survivors))
    messages = [
        {"role": "system", "content": REFLECT_SYSTEM},
        {"role": "user", "content": f"# SPEC (context only)\n{task.spec}\n\n" + "\n\n".join(lines) +
                                    f"\n\n# CURRENT PLAYBOOK v{playbook.version}\n{playbook.text() or '(empty)'}"},
    ]
    comp = llm.chat("verifier", messages, temperature=0.0, max_tokens=500, tag=f"reflect:{task.name}")
    data = llm.extract_json(comp.text)
    return {"text": str(data["tactic"]).strip(), "rationale": str(data.get("rationale", "")).strip(), "request_hash": comp.request_hash}


# ---------------------------------------------------------------------------------------------
# the loop
# ---------------------------------------------------------------------------------------------

def learn(train: list[str], heldout: list[str], rounds: int = 1, seed: int = 1337, console=None) -> Playbook:
    from rich.table import Table

    say = console.print if console else print
    train_tasks = [load_task(t) for t in train]
    held_tasks = [load_task(t) for t in heldout]
    pb = load()
    if pb.version == 0 and not _path(0).exists():
        save(pb)
    say(f"[bold]playbook v{pb.version}[/] ({len(pb.tactics)} tactics)  train={train}  held-out={heldout}")
    say("[dim]evaluating current playbook on held-out tasks...[/]")
    held = evaluate(held_tasks, pb, seed, emit=lambda s: say(f"  [dim]held-out {s}[/]"))
    say(f"held-out score {held['score']:.3f}  (catch {held['catch_rate']:.0%}, kill {held['kill_rate']:.0%}, false-block {held['false_block_rate']:.0%})")

    table = Table(title="learning log", show_lines=False)
    for col in ("round", "learned from", "candidate tactic", "held-out before", "after", "decision"):
        table.add_column(col)

    for rnd in range(1, rounds + 1):
        for task in train_tasks:
            say(f"\n[bold]round {rnd}[/] · training on [cyan]{task.name}[/]")
            tr = evaluate([task], pb, seed, emit=lambda s: say(f"  [dim]train {s}[/]"))
            misses = [VariantResult(**r) for r in tr["results"]
                      if (r["expected"] == "BLOCK" and not r["prop_caught"]) or (r["expected"] == "MERGE" and r["survivors"])]
            if not misses:
                say("  no misses on this task - nothing to learn")
                continue
            say(f"  {len(misses)} miss(es): " + ", ".join(f"{m.variant}{' (escaped)' if m.expected == 'BLOCK' and not m.prop_caught else ' (surviving mutants)'}" for m in misses))
            try:
                tactic = reflect(task, misses, pb)
            except (llm.LLMError, KeyError, json.JSONDecodeError) as e:
                say(f"  [red]reflection failed: {e}[/]")
                continue
            say(f"  candidate tactic: [italic]{tactic['text']}[/]")
            cand = Playbook(version=pb.version + 1, parent=pb.version, created_at=_now(),
                            tactics=pb.tactics + [{"id": short(sha256_text(tactic["text"]), 8), "text": tactic["text"],
                                                   "rationale": tactic["rationale"], "learned_from": task.name, "added_in": pb.version + 1}])
            after = evaluate(held_tasks, cand, seed, emit=lambda s: say(f"  [dim]held-out {s}[/]"))
            accepted = after["score"] > held["score"]
            entry = {
                "at": _now(), "round": rnd, "learned_from": task.name, "tactic": tactic["text"], "rationale": tactic["rationale"],
                "from_version": pb.version, "candidate_version": cand.version,
                "heldout_before": {k: held[k] for k in ("score", "catch_rate", "kill_rate", "false_block_rate")},
                "heldout_after": {k: after[k] for k in ("score", "catch_rate", "kill_rate", "false_block_rate")},
                "decision": "ADOPT" if accepted else "ROLLBACK",
            }
            log_decision(entry)
            table.add_row(str(rnd), task.name, tactic["text"][:70] + ("…" if len(tactic["text"]) > 70 else ""),
                          f"{held['score']:.3f}", f"{after['score']:.3f}",
                          "[green]ADOPT[/]" if accepted else "[red]ROLLBACK[/]")
            if accepted:
                save(cand)
                pb, held = cand, after
                say(f"  [green]adopted -> playbook v{pb.version}[/] (held-out {entry['heldout_before']['score']:.3f} -> {after['score']:.3f})")
            else:
                say(f"  [red]rolled back[/] (held-out {held['score']:.3f} -> {after['score']:.3f}); staying on v{pb.version}")
    say(table)
    return pb


def show(console) -> None:
    from rich.table import Table
    pb = load()
    console.print(f"[bold]playbook v{pb.version}[/]  sha256:{short(pb.sha256)}")
    for t in pb.tactics:
        console.print(f"  v{t['added_in']} [{t['learned_from']}] {t['text']}")
    logf = PLAYBOOK_DIR / "log.jsonl"
    if logf.exists():
        table = Table(title="decision log")
        for col in ("from", "tactic", "before", "after", "decision"):
            table.add_column(col)
        for line in logf.read_text().splitlines():
            e = json.loads(line)
            table.add_row(e["learned_from"], e["tactic"][:60], f"{e['heldout_before']['score']:.3f}", f"{e['heldout_after']['score']:.3f}",
                          "[green]ADOPT[/]" if e["decision"] == "ADOPT" else "[red]ROLLBACK[/]")
        console.print(table)
