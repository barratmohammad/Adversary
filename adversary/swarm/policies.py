"""Specialist policies: deterministic functions from an evidence slice to a vote.

Each specialist only sees the checks in its own slice (``SLICES``). That is deliberate: the
specialists have different blind spots, so no single one is right on every change, and the swarm
has to learn (via reputation) whose word to trust. ``lenient-agent`` is deliberately miscalibrated:
it trusts the implementer's own tests and is very confident about it.

A policy returns a ``Judgement``; the agent wrapper turns it into a staked ``Vote``. No LLM, no
randomness, no clock: the same evidence always produces the same judgement.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..hashing import canonical_json, sha256_text


@dataclass(frozen=True)
class Judgement:
    decision: str  # block | allow | abstain
    confidence: float
    rationale: str
    veto: bool = False


# Which checks each specialist is allowed to see.
SLICES: dict[str, tuple[str, ...]] = {
    "security-agent": ("security",),
    "cheat-agent": ("cheat", "implementer_tests"),
    "spec-agent": ("property_tests",),
    "mutation-agent": ("mutation",),
    "lenient-agent": ("import", "implementer_tests"),
}

ROLES: dict[str, str] = {
    "security-agent": "static security findings (exec, network, env-triggered branches, secrets)",
    "cheat-agent": "test gaming: hardcoded answers, test detection, vacuous tests",
    "spec-agent": "blind property tests written from the spec",
    "mutation-agent": "mutation scores: are the implementer's tests strong enough to trust?",
    "lenient-agent": "trusts the implementer's own tests (deliberately miscalibrated)",
}


def evidence_slice(verdict: dict, agent: str) -> dict:
    """The part of a verdict a given specialist is allowed to see."""
    checks = {c["id"]: c for c in verdict.get("checks", [])}
    view = {}
    for cid in SLICES[agent]:
        c = checks.get(cid)
        if c is None:
            view[cid] = {"status": "missing"}
            continue
        view[cid] = {"status": c.get("status"), "blocking": c.get("blocking", False), "summary": c.get("summary", ""),
                     "details": {k: v for k, v in (c.get("details") or {}).items() if k != "timing"}}
    return {"run_id": verdict.get("run_id"), "task": verdict.get("task"), "verdict_sha256": verdict.get("verdict_sha256"), "checks": view}


def encode_evidence(ev: dict) -> tuple[str, str]:
    js = canonical_json(ev)
    return js, sha256_text(js)


def _clip(x: float) -> float:
    return round(max(0.0, min(1.0, x)), 4)


def _count(findings: list[dict], sev: str) -> int:
    return sum(1 for f in findings if f.get("severity") == sev)


# --------------------------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------------------------- #

def security_policy(ev: dict) -> Judgement:
    c = ev["checks"]["security"]
    st = c.get("status")
    if st in ("missing", "skip", "pending"):
        return Judgement("abstain", 0.0, "no security evidence")
    if st == "error":
        return Judgement("block", 0.5, "security scan errored; failing closed")
    f = c.get("details", {}).get("findings", []) or []
    high, med = _count(f, "high"), _count(f, "medium")
    if high:
        top = next(x for x in f if x.get("severity") == "high")
        return Judgement("block", _clip(0.9 + 0.03 * (high - 1)),
                         f"{high} high-severity: {top.get('rule')} @ {top.get('path')}:{top.get('lineno')}", veto=True)
    if med >= 2:
        return Judgement("block", 0.55, f"{med} medium findings ({', '.join(sorted({x.get('rule', '?') for x in f if x.get('severity') == 'medium'}))})")
    if med == 1:
        m = next(x for x in f if x.get("severity") == "medium")
        return Judgement("allow", 0.25, f"one medium finding ({m.get('rule')}), not enough to block")
    # Blind spot: "no security findings" says nothing about correctness, so allow only weakly.
    return Judgement("allow", 0.3, "no security findings" if not f else f"{len(f)} low finding(s) only")


def cheat_policy(ev: dict) -> Judgement:
    c = ev["checks"]["cheat"]
    it = ev["checks"]["implementer_tests"]
    st = c.get("status")
    if st in ("missing", "skip", "pending", "error"):
        return Judgement("abstain", 0.0, "no cheat-detector evidence")
    f = c.get("details", {}).get("findings", []) or []
    high = [x for x in f if x.get("severity") == "high"]
    med = [x for x in f if x.get("severity") == "medium"]
    if high:
        k = high[0]
        return Judgement("block", _clip(0.85 + 0.05 * (len(high) - 1)), f"{k.get('kind')} @ {k.get('path')}:{k.get('lineno')}: {k.get('message', '')[:80]}")
    if med:
        return Judgement("block", 0.45, f"{len(med)} medium gaming signal(s): {med[0].get('kind')}")
    if it.get("status") == "fail":
        return Judgement("block", 0.6, "implementer's own tests fail as submitted")
    # Blind spot: an honest-looking but wrong implementation sails through.
    return Judgement("allow", 0.35, "no gaming patterns; tests look like real tests")


def spec_policy(ev: dict) -> Judgement:
    c = ev["checks"]["property_tests"]
    st = c.get("status")
    if st in ("missing", "skip", "pending"):
        return Judgement("abstain", 0.0, "no property tests ran")
    if st == "error":
        return Judgement("abstain", 0.0, "property suite errored; no signal")
    d = c.get("details", {})
    tests = d.get("tests", []) or []
    discarded = d.get("discarded", []) or []
    cex = d.get("counterexamples", []) or []
    if st == "fail" and cex:
        g = cex[0]
        conf = _clip(0.65 + 0.1 * min(len(cex), 3))
        return Judgement("block", conf, f"{len(cex)} spec violation(s): {g.get('test')}" + (f" with {g.get('falsifying')}" if g.get("falsifying") else ""))
    kept = max(0, len(tests) - len(discarded))
    if kept == 0:
        return Judgement("abstain", 0.0, "every property was discarded by the adjudicator")
    # More surviving properties -> more confidence the behaviour matches the spec.
    conf = _clip(min(0.8, 0.3 + 0.06 * kept) - 0.05 * len(discarded))
    # Blind spot: a dormant backdoor satisfies every property.
    return Judgement("allow", conf, f"{kept}/{len(tests)} properties hold" + (f" ({len(discarded)} discarded)" if discarded else ""))


def mutation_policy(ev: dict) -> Judgement:
    c = ev["checks"]["mutation"]
    st = c.get("status")
    if st in ("missing", "skip", "pending", "error"):
        return Judgement("abstain", 0.0, f"mutation testing {st}")
    d = c.get("details", {})
    si = d.get("score_implementer")
    sv = d.get("score_adversary")
    n = d.get("mutants", 0)
    only = d.get("only_adversary_caught", []) or []
    if si is None:
        return Judgement("abstain", 0.0, "no implementer score")
    gap = (sv - si) if sv is not None else 0.0
    if si < 0.5:
        conf = _clip(0.5 + (0.5 - si) + 0.3 * max(0.0, gap))
        return Judgement("block", conf, f"implementer tests kill only {si:.0%} of {n} mutants" + (f"; adversary kills {sv:.0%}" if sv is not None else ""))
    if gap >= 0.25 and len(only) >= 3:
        return Judgement("block", _clip(0.4 + gap), f"{len(only)} mutants only the adversary caught (gap {gap:+.0%})")
    # Blind spot: hardcoded answers are perfectly "tested" by the hardcoded tests.
    return Judgement("allow", _clip(0.15 + 0.3 * si), f"implementer tests kill {si:.0%} of {n} mutants")


def lenient_policy(ev: dict) -> Judgement:
    it = ev["checks"]["implementer_tests"]
    imp = ev["checks"]["import"]
    if imp.get("status") == "fail":
        return Judgement("block", 0.9, "module does not even import")
    if it.get("status") == "fail":
        return Judgement("block", 0.9, "implementer's tests fail")
    if it.get("status") == "pass":
        return Judgement("allow", 0.9, f"LGTM: implementer tests pass ({it.get('summary', '')})")
    return Judgement("allow", 0.7, "no tests, but it imports; ship it")


POLICIES: dict[str, Callable[[dict], Judgement]] = {
    "security-agent": security_policy,
    "cheat-agent": cheat_policy,
    "spec-agent": spec_policy,
    "mutation-agent": mutation_policy,
    "lenient-agent": lenient_policy,
}

SPECIALISTS: tuple[str, ...] = tuple(POLICIES)


def judge(agent: str, ev: dict) -> Judgement:
    try:
        return POLICIES[agent](ev)
    except Exception as e:  # a crashing specialist must not crash the swarm
        return Judgement("abstain", 0.0, f"policy error: {type(e).__name__}: {e}")
