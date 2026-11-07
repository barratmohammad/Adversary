"""HumanEval+ benchmark: does Adversary catch bugs that the official tests miss?

Dataset construction (all from public data - none of the bugs are hand-written):
  * spec      = the HumanEval prompt (signature + docstring)
  * correct   = the canonical solution                                  -> label MERGE
  * buggy     = single-fault mutants of the canonical solution that
                  - PASS every official HumanEval input (the "implementer's tests" pass), and
                  - FAIL at least one EvalPlus input (ground truth: really wrong)   -> label BLOCK
  * the official HumanEval inputs ship with each change as the implementer's own tests

  adversary bench --n 20 --bugs 2
"""
from __future__ import annotations

import json
import random
import subprocess
import sys
import tempfile
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .workspace import ROOT, Change, Task

BENCH_DIR = ROOT / "bench"

_CHECK = r'''
import json, math, sys, signal, copy, importlib.util
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
class TO(Exception): pass
def _alarm(*a): raise TO()
signal.signal(signal.SIGALRM, _alarm)
ref, cand = load(sys.argv[1], "ref"), load(sys.argv[2], "cand")
entry, atol = sys.argv[3], float(sys.argv[4])
inputs = json.load(open(sys.argv[5]))
def call(m, args):
    signal.setitimer(signal.ITIMER_REAL, 1.0)
    try:
        return ("ok", getattr(m, entry)(*copy.deepcopy(args)))
    except TO:
        return ("timeout", None)
    except BaseException as e:
        return ("exc", type(e).__name__)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
def same(a, b):
    if a[0] != b[0]: return False
    if a[0] != "ok": return a[1] == b[1]
    x, y = a[1], b[1]
    if isinstance(x, float) or isinstance(y, float):
        try: return math.isclose(x, y, rel_tol=1e-6, abs_tol=max(atol, 1e-6))
        except TypeError: return False
    return x == y
out = {}
for key in ("base", "plus"):
    bad = 0
    for args in inputs[key]:
        if not same(call(ref, args), call(cand, args)): bad += 1
    out[key] = bad
print(json.dumps(out))
'''


@dataclass
class Case:
    task: Task
    variant: str            # "correct" | "bug"
    label: str              # MERGE | BLOCK
    code: str
    description: str = ""
    official_fail: int = 0
    plus_fail: int = 0
    meta: dict = field(default_factory=dict)


def _differential(ref_src: str, cand_src: str, entry: str, atol: float, base: list, plus: list) -> dict | None:
    with tempfile.TemporaryDirectory() as d:
        dp = Path(d)
        (dp / "ref.py").write_text(ref_src)
        (dp / "cand.py").write_text(cand_src)
        (dp / "inputs.json").write_text(json.dumps({"base": base, "plus": plus}, default=list))
        (dp / "check.py").write_text(_CHECK)
        try:
            from .sandbox import detect_sandbox
            rr = detect_sandbox().run(["-I", "check.py", "ref.py", "cand.py", entry, str(atol or 0), "inputs.json"], cwd=dp, timeout=120)
            return json.loads(rr.stdout.strip().splitlines()[-1]) if rr.returncode == 0 and rr.stdout.strip() else None
        except Exception:
            return None


def _official_tests(entry: str, module: str, ref_src: str, base: list, atol: float) -> str:
    """The official HumanEval inputs, with expected outputs from the canonical solution, as pytest tests."""
    ns: dict = {}
    exec(compile(ref_src, "ref", "exec"), ns)
    rows = []
    for args in base:
        try:
            exp = ns[entry](*json.loads(json.dumps(args)))
            json.dumps(exp)
            rows.append((args, exp))
        except Exception:
            continue
    lines = [f"import math\nfrom {module[:-3]} import {entry}\n\nCASES = {json.dumps(rows)}\n\n",
             "def _eq(a, b):\n    if isinstance(a, float) or isinstance(b, float):\n"
             f"        return math.isclose(a, b, rel_tol=1e-6, abs_tol={max(atol or 0, 1e-6)})\n"
             "    if isinstance(a, tuple) or isinstance(b, tuple):\n        return list(a) == list(b)\n    return a == b\n\n",
             f"def test_official_humaneval_inputs():\n    for args, expected in CASES:\n        assert _eq({entry}(*args), expected), (args, expected)\n"]
    return "".join(lines)


def build_cases(n: int = 20, bugs_per: int = 2, seed: int = 0, plus_cap: int = 400, log=print) -> list[Case]:
    from evalplus.data import get_human_eval_plus
    from .verifier.mutation import generate_mutants

    data = get_human_eval_plus()
    ids = sorted(data)
    random.Random(seed).shuffle(ids)
    cases: list[Case] = []
    used = 0
    for tid in ids:
        if used >= n:
            break
        p = data[tid]
        entry, prompt = p["entry_point"], p["prompt"]
        ref_src = prompt + p["canonical_solution"]
        base, plus = p["base_input"], p["plus_input"][:plus_cap]
        atol = p.get("atol") or 0
        try:
            json.dumps(base); json.dumps(plus)
        except TypeError:
            continue
        sneaky = []
        for m in generate_mutants("solution.py", ref_src, max_mutants=60, seed=seed):
            r = _differential(ref_src, m.source, entry, atol, base, plus)
            if r and r["base"] == 0 and r["plus"] > 0:
                sneaky.append((m, r))
        if not sneaky:
            continue
        rng = random.Random(f"{seed}:{tid}")
        picks = rng.sample(sneaky, min(bugs_per, len(sneaky)))
        name = "he_" + tid.split("/")[-1]
        spec = (f"# {tid}: `{entry}`\n\nImplement the function below in `solution.py`. The docstring is the specification.\n\n"
                f"```python\n{prompt.rstrip()}\n```\n")
        base_files = {"solution.py": prompt.rstrip() + "\n    raise NotImplementedError\n", "tests/__init__.py": ""}
        task = Task(name=name, title=f"HumanEval+ {tid} {entry}", module="solution.py", functions=[entry], spec=spec, base=base_files)
        tests = _official_tests(entry, "solution.py", ref_src, base, atol)
        cases.append(Case(task, "correct", "MERGE", ref_src, "canonical solution", meta={"tid": tid, "tests": tests}))
        for m, r in picks:
            cases.append(Case(task, "bug", "BLOCK", m.source, m.description, official_fail=r["base"], plus_fail=r["plus"],
                              meta={"tid": tid, "tests": tests, "mutant": m.id}))
        used += 1
        log(f"  {tid} {entry}: {len(sneaky)} sneaky mutants (pass all official tests, fail EvalPlus) -> using {len(picks)}")
    return cases


EVALPLUS_MODELS = {  # EvalPlus v0.1.0 release: greedy (temperature 0) HumanEval samples
    "gpt-4": "gpt-4_temp_0.0.zip",
    "chatgpt": "chatgpt_temp_0.0.zip",
    "code-llama-34b": "code-llama-34b_temp_0.0.zip",
    "mistral-7b": "mistral-7b_temp_0.0.zip",
}
SAMPLES_DIR = ROOT / ".adversary" / "evalplus_samples"


def fetch_samples(log=print) -> dict[str, dict[str, str]]:
    """Download (once) and index EvalPlus's published LLM samples: {model: {task_id: source}}."""
    import zipfile
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    out: dict[str, dict[str, str]] = {}
    for model, asset in EVALPLUS_MODELS.items():
        z = SAMPLES_DIR / asset
        if not z.exists():
            log(f"  downloading {asset} from github.com/evalplus/evalplus releases/v0.1.0")
            subprocess.run(["gh", "release", "download", "v0.1.0", "-R", "evalplus/evalplus", "-p", asset, "-D", str(SAMPLES_DIR)],
                           check=True, capture_output=True)
        sols = {}
        with zipfile.ZipFile(z) as zf:
            for name in zf.namelist():
                parts = name.split("/")
                if len(parts) >= 2 and parts[-1] == "0.py" and parts[-2].startswith("HumanEval_"):
                    sols["HumanEval/" + parts[-2].split("_", 1)[1]] = zf.read(name).decode("utf-8", "replace")
        out[model] = sols
    return out


def build_llm_cases(max_bugs: int = 40, max_correct: int = 20, seed: int = 0, parallel: int = 8, log=print) -> list[Case]:
    """Real LLM-written solutions. Buggy = passes every official HumanEval input but fails EvalPlus (the false passes
    that motivated EvalPlus). Correct = passes both - used to measure false blocks on realistic, non-canonical code."""
    from evalplus.data import get_human_eval_plus

    data = get_human_eval_plus()
    samples = fetch_samples(log)
    jobs = []
    for model, sols in samples.items():
        for tid, src in sols.items():
            if tid in data:
                jobs.append((model, tid, src))
    log(f"  {len(jobs)} LLM solutions from {len(samples)} models; differential-testing against EvalPlus in the sandbox...")

    def judge(job):
        model, tid, src = job
        p = data[tid]
        ref_src = p["prompt"] + p["canonical_solution"]
        try:
            json.dumps(p["base_input"]); json.dumps(p["plus_input"][:400])
        except TypeError:
            return job, None
        return job, _differential(ref_src, src, p["entry_point"], p.get("atol") or 0, p["base_input"], p["plus_input"][:400])

    cache = SAMPLES_DIR / "judged.json"
    cached = json.loads(cache.read_text()) if cache.exists() else {}
    todo = [j for j in jobs if f"{j[0]}|{j[1]}" not in cached]
    with ThreadPoolExecutor(max_workers=parallel) as ex:
        for (model, tid, _src), r in ex.map(judge, todo):
            cached[f"{model}|{tid}"] = r
    cache.write_text(json.dumps(cached))
    judged = [(j, cached.get(f"{j[0]}|{j[1]}")) for j in jobs]
    bugs, good = [], []
    seen = set()
    for (model, tid, src), r in judged:
        if not r or src.strip() in seen:
            continue
        seen.add(src.strip())
        if r["base"] == 0 and r["plus"] > 0:
            bugs.append((model, tid, src, r))
        elif r["base"] == 0 and r["plus"] == 0:
            good.append((model, tid, src, r))
    log(f"  found {len(bugs)} real LLM false passes (pass official tests, fail EvalPlus) and {len(good)} fully-correct LLM solutions")
    rng = random.Random(seed)
    rng.shuffle(bugs)
    bugs = sorted(bugs[:max_bugs], key=lambda x: (x[1], x[0]))
    bug_tids = {b[1] for b in bugs}
    good = [g for g in good if g[1] in bug_tids] + [g for g in good if g[1] not in bug_tids]  # prefer same problems
    good = good[:max_correct]
    cases = []
    for model, tid, src, r in bugs + good:
        p = data[tid]
        entry, prompt = p["entry_point"], p["prompt"]
        ref_src = prompt + p["canonical_solution"]
        name = "he_" + tid.split("/")[-1]
        spec = (f"# {tid}: `{entry}`\n\nImplement the function below in `solution.py`. The docstring is the specification.\n\n"
                f"```python\n{prompt.rstrip()}\n```\n")
        base_files = {"solution.py": prompt.rstrip() + "\n    raise NotImplementedError\n", "tests/__init__.py": ""}
        task = Task(name=name, title=f"HumanEval+ {tid} {entry}", module="solution.py", functions=[entry], spec=spec, base=base_files)
        tests = _official_tests(entry, "solution.py", ref_src, p["base_input"], p.get("atol") or 0)
        is_bug = r["plus"] > 0
        cases.append(Case(task, "llm-bug" if is_bug else "llm-correct", "BLOCK" if is_bug else "MERGE", src,
                          f"{model} solution" + (f", fails {r['plus']}/{min(400, len(p['plus_input']))} EvalPlus inputs" if is_bug else ""),
                          plus_fail=r["plus"], meta={"tid": tid, "tests": tests, "model": model}))
    return cases


def run(n: int = 20, bugs_per: int = 2, seed: int = 0, parallel: int = 6, console=None, source: str = "mutants",
        max_llm_bugs: int = 40, max_llm_correct: int = 20) -> dict:
    from rich.table import Table
    from .verifier.pipeline import verify

    say = console.print if console else print
    t0 = time.monotonic()
    say(f"[bold]building HumanEval+ cases[/] (source={source}, seed={seed})")
    log = lambda s: say(f"[dim]{s}[/]")
    cases: list[Case] = []
    if source in ("mutants", "both"):
        cases += build_cases(n, bugs_per, seed, log=log)
    if source in ("llm", "both"):
        cases += build_llm_cases(max_llm_bugs, max_llm_correct, seed, log=log)
    say(f"[bold]{len(cases)} changes[/] ({sum(c.label == 'MERGE' for c in cases)} correct, {sum(c.label == 'BLOCK' for c in cases)} sneaky bugs). verifying...")

    def one(c: Case):
        after = dict(c.task.base)
        after["solution.py"] = c.code
        after["tests/test_official.py"] = c.meta["tests"]
        change = Change(base=c.task.base, after=after, meta={"source": "bench"})
        try:
            v, rdir = verify(c.task, change, max_mutants=0, max_examples=150,
                             implementer_model={"provider": "humaneval", "model": c.variant})
        except Exception as e:  # noqa: BLE001
            return c, None, None, str(e)
        say(f"  [dim]{c.meta['tid']} {c.variant}: expected {c.label}, got {v.decision}[/]")
        return c, v, rdir, None

    with ThreadPoolExecutor(max_workers=parallel) as ex:
        results = list(ex.map(one, cases))

    rows, caught, missed, fa, ok_correct, errors = [], 0, 0, 0, 0, 0
    by_check: dict[str, int] = {}
    for c, v, rdir, err in results:
        if v is None:
            errors += 1
            rows.append({"tid": c.meta["tid"], "variant": c.variant, "label": c.label, "decision": "ERROR", "error": err})
            continue
        checks = {k.id: k for k in v.checks}
        blockers = [k.id for k in v.checks if k.blocking]
        ce = checks["property_tests"].details.get("counterexamples", [])
        row = {"tid": c.meta["tid"], "variant": c.variant, "model": c.meta.get("model", ""), "label": c.label, "decision": v.decision, "blocked_by": blockers,
               "bug": c.description, "evalplus_failures": c.plus_fail, "counterexample": (ce[0]["falsifying"] or ce[0]["message"][:120]) if ce else "",
               "run": rdir.name}
        rows.append(row)
        if c.label == "BLOCK":
            if v.decision == "BLOCK":
                caught += 1
                for b in blockers:
                    by_check[b] = by_check.get(b, 0) + 1
            else:
                missed += 1
        else:
            if v.decision == "BLOCK":
                fa += 1
            else:
                ok_correct += 1
    n_bug = caught + missed
    n_ok = fa + ok_correct
    split = {}
    for r in rows:
        if r["decision"] == "ERROR":
            continue
        k = "llm" if r["variant"].startswith("llm") else "mutant"
        d = split.setdefault(k, {"bugs": 0, "caught": 0, "correct": 0, "false_blocks": 0})
        if r["label"] == "BLOCK":
            d["bugs"] += 1
            d["caught"] += r["decision"] == "BLOCK"
        else:
            d["correct"] += 1
            d["false_blocks"] += r["decision"] == "BLOCK"
    summary = {
        "dataset": "HumanEval+ (EvalPlus) - canonical solutions + single-fault mutants that pass all official tests but fail EvalPlus",
        "problems": len({c.meta["tid"] for c in cases}),
        "buggy_changes": n_bug, "correct_changes": n_ok, "errors": errors,
        "catch_rate": round(caught / n_bug, 3) if n_bug else None,
        "false_block_rate": round(fa / n_ok, 3) if n_ok else None,
        "official_tests_catch_rate": 0.0,
        "caught_by": by_check,
        "by_source": split,
        "seed": seed, "minutes": round((time.monotonic() - t0) / 60, 1),
        "rows": rows,
    }
    BENCH_DIR.mkdir(exist_ok=True)
    out = BENCH_DIR / f"humaneval_plus_{source}_n{summary['problems']}_seed{seed}.json"
    out.write_text(json.dumps(summary, indent=2))

    table = Table(title="HumanEval+ benchmark: bugs the official tests miss")
    for col in ("problem", "change", "expected", "verdict", "caught by", "counterexample"):
        table.add_column(col, overflow="fold")
    for r in rows:
        okr = r["decision"] == r["label"]
        table.add_row(r["tid"], r["variant"] + (f" ({r.get('bug', '')[:40]})" if r["variant"] == "bug" else ""), r["label"],
                      f"[{'green' if okr else 'bold red'}]{r['decision']}[/]", ", ".join(r.get("blocked_by", [])) or "-",
                      textwrap.shorten(str(r.get("counterexample", "")), 60))
    say(table)
    say(f"[bold]catch rate[/] {caught}/{n_bug} = {summary['catch_rate']:.0%} of sneaky bugs blocked "
        f"(official HumanEval tests: 0% by construction)" if n_bug else "no buggy cases")
    say(f"[bold]false blocks[/] {fa}/{n_ok} = {summary['false_block_rate']:.0%} of correct solutions wrongly blocked" if n_ok else "")
    for k, d in split.items():
        label = "real LLM-written code (EvalPlus samples)" if k == "llm" else "single-fault mutants"
        if d["bugs"]:
            say(f"  {label}: caught {d['caught']}/{d['bugs']} bugs" + (f", false blocks {d['false_blocks']}/{d['correct']}" if d["correct"] else ""))
    say(f"[dim]saved {out} · {summary['minutes']} min · errors {errors}[/]")
    return summary
