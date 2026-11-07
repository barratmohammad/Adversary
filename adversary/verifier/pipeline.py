"""The verifier pipeline: spec + change in, reproducible verdict out.

Information barrier: this module receives the Task (spec + base repo) and the Change (files after
the PR). It never receives the implementer's reasoning. The LLM test author only sees the spec
and a sanitized view of the changed implementation files.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from .. import llm
from ..hashing import sha256_files, sha256_json, sha256_text, short
from ..sandbox import Sandbox, detect_sandbox
from ..verdict import Check, Verdict, environment_fingerprint
from ..workspace import RUNS_DIR, Change, Task, materialize, sanitized_view, write_tree
from . import propgen
from .runner import HYPOTHESIS_HEADER, VERIFIER_DIR, install_verifier_suite, run_suite

Emit = Callable[[str, str, str], None]  # (check_id, status, message)

STARTUP_HOOK_NAMES = {"sitecustomize.py", "usercustomize.py"}
VERIFIER_TEST_FILE = "test_adversary.py"


def _noop(*_a) -> None:
    pass


def _tree_without_tests(tree: dict[str, str]) -> dict[str, str]:
    return tree


def verify(
    task: Task,
    change: Change,
    seed: int = 1337,
    sandbox: Sandbox | None = None,
    pinned: dict | None = None,
    emit: Emit | None = None,
    run_dir: Path | None = None,
    max_mutants: int = 40,
    max_examples: int = 200,
    implementer_model: dict | None = None,
) -> tuple[Verdict, Path]:
    emit = emit or _noop
    sandbox = sandbox or detect_sandbox()
    run_id = _dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    run_dir = run_dir or (RUNS_DIR / run_id)
    run_dir.mkdir(parents=True, exist_ok=True)

    # ---- pin inputs -------------------------------------------------------------------------
    inputs_dir = run_dir / "inputs"
    inputs_dir.mkdir(exist_ok=True)
    (inputs_dir / "spec.md").write_text(task.spec)
    (inputs_dir / "change.diff").write_text(change.diff())
    (inputs_dir / "task.json").write_text(json.dumps({"name": task.name, "module": task.module, "functions": task.functions,
                                                      "allow_network": task.allow_network, "allow_fs_write": task.allow_fs_write}))
    write_tree(inputs_dir / "after", change.after)
    sanitized = sanitized_view(change)
    write_tree(inputs_dir / "verifier_view", sanitized)
    inputs = {
        "spec_sha256": task.spec_hash,
        "diff_sha256": change.diff_hash,
        "tree_sha256": change.after_hash,
        "sanitized_view_sha256": sha256_files(sanitized),
    }

    checks: dict[str, Check] = {
        "security": Check("security", "Security pass"),
        "cheat": Check("cheat", "Cheat detector"),
        "import": Check("import", "Module imports cleanly"),
        "implementer_tests": Check("implementer_tests", "Implementer's own tests"),
        "property_tests": Check("property_tests", "Adversary property tests (blind)"),
        "mutation": Check("mutation", "Mutation testing"),
    }

    def done(c: Check, status: str, summary: str, blocking: bool = False, **details) -> None:
        c.status, c.summary, c.blocking = status, summary, blocking
        c.details.update(details)
        emit(c.id, status, summary)

    # ---- 1. security pass --------------------------------------------------------------------
    emit("security", "running", "static analysis of changed implementation files")
    from .security import scan
    findings = scan(change.impl_files, allow_network=task.allow_network, allow_fs_write=task.allow_fs_write)
    for rel in change.changed:
        if Path(rel).name in STARTUP_HOOK_NAMES or rel.endswith(".pth"):
            findings.insert(0, _finding("startup-hook", rel, 1, "high", f"{rel} would execute at interpreter startup", rel))
    fd = [_as_dict(f) for f in findings]
    high = [f for f in fd if f["severity"] == "high"]
    med = [f for f in fd if f["severity"] == "medium"]
    fp = sha256_json(sorted((f["rule"], f["path"], f["lineno"], f["severity"]) for f in fd))
    if high:
        done(checks["security"], "fail", f"{len(high)} high-severity finding(s): " + "; ".join(f"{f['rule']} @ {f['path']}:{f['lineno']}" for f in high[:3]), True, findings=fd, fingerprint=fp)
    elif med:
        done(checks["security"], "warn", f"{len(med)} medium finding(s)", False, findings=fd, fingerprint=fp)
    else:
        done(checks["security"], "pass", "no findings" if not fd else f"{len(fd)} low finding(s)", False, findings=fd, fingerprint=fp)

    # ---- 2. cheat detector -------------------------------------------------------------------
    emit("cheat", "running", "looking for hardcoded answers, test detection, vacuous tests")
    from .cheat import detect_cheats
    cheats = [_as_dict(c) for c in detect_cheats(change.impl_files, change.test_files, task.spec)]
    chigh = [c for c in cheats if c["severity"] == "high"]
    fp = sha256_json(sorted((c["kind"], c["path"], c["lineno"], c["severity"]) for c in cheats))
    if chigh:
        done(checks["cheat"], "fail", chigh[0]["message"] + (f" (+{len(chigh)-1} more)" if len(chigh) > 1 else ""), True, findings=cheats, fingerprint=fp)
    elif cheats:
        done(checks["cheat"], "warn", cheats[0]["message"], False, findings=cheats, fingerprint=fp)
    else:
        done(checks["cheat"], "pass", "no gaming patterns detected", False, findings=cheats, fingerprint=fp)

    # ---- 3. materialize + import check -------------------------------------------------------
    work = materialize(run_dir / "work", change.full_tree())
    mod = task.module[:-3].replace("/", ".")
    emit("import", "running", f"import {mod}")
    rr = sandbox.run(["-I", "-c", f"import sys; sys.path.insert(0, '.'); import {mod}"], cwd=work, timeout=30)
    if rr.returncode != 0:
        done(checks["import"], "fail", f"import {mod} failed: {rr.stderr.strip().splitlines()[-1] if rr.stderr.strip() else rr.returncode}", True,
             stderr=rr.stderr[-2000:], fingerprint=sha256_text("import-fail"))
    else:
        done(checks["import"], "pass", f"import {mod} ok ({sandbox.kind} sandbox, network denied)" if sandbox.isolated else f"import {mod} ok", False, fingerprint=sha256_text("import-ok"))

    # ---- 4. implementer's own tests ----------------------------------------------------------
    impl_tests_present = bool(change.test_files) or any(k.startswith("tests/test_") for k in change.full_tree())
    impl_res = None
    if impl_tests_present:
        emit("implementer_tests", "running", "running the implementer's tests as submitted")
        impl_res = run_suite(sandbox, work, "tests", seed=seed, hardened=False, max_examples=max_examples, junit_name="impl.xml")
        fp = sha256_json(sorted((o.nodeid, o.status) for o in impl_res.outcomes))
        if impl_res.ok:
            done(checks["implementer_tests"], "pass", f"{len(impl_res.passed)}/{len(impl_res.outcomes)} passed", False, result=impl_res.summary(), fingerprint=fp)
        else:
            why = impl_res.collection_error.splitlines()[-1] if impl_res.collection_error else f"{len(impl_res.failed)} failing"
            done(checks["implementer_tests"], "fail", f"implementer's own tests fail: {why}", True, result=impl_res.summary(),
                 failures=[{"test": o.name, "message": o.message[:300]} for o in impl_res.failed[:5]], fingerprint=fp)
    else:
        done(checks["implementer_tests"], "warn", "change ships no tests", False, fingerprint=sha256_text("no-tests"))

    # ---- 5. blind property tests -------------------------------------------------------------
    pinned_dir = run_dir / "pinned"
    pinned_dir.mkdir(exist_ok=True)
    gen_meta: dict = {}
    if pinned and pinned.get("verifier_tests"):
        test_src = pinned["verifier_tests"]
        gen_meta = {"pinned": True}
        emit("property_tests", "running", f"replaying pinned verifier tests sha256:{short(sha256_text(test_src))}")
    else:
        emit("property_tests", "running", f"verifier ({llm.config_for('verifier').model}) writing tests from spec + sanitized diff")
        test_src, gen_meta, gen_err = _generate_with_retry(task, sanitized, work, sandbox, seed, max_examples, emit)
        if test_src is None:
            done(checks["property_tests"], "error", f"could not produce a valid test suite: {gen_err}", True, fingerprint=sha256_text("gen-error"), generation=gen_meta)
    prop_res = None
    triage: dict = dict((pinned or {}).get("triage", {}))
    discarded: list[str] = []
    genuine: list[dict] = []
    if test_src is not None:
        (pinned_dir / VERIFIER_TEST_FILE).write_text(test_src)
        install_verifier_suite(work, {VERIFIER_TEST_FILE: HYPOTHESIS_HEADER + test_src})
        emit("property_tests", "running", "running blind property tests (seeded, hardened runner)")
        prop_res = run_suite(sandbox, work, VERIFIER_DIR, seed=seed, hardened=True, max_examples=max_examples, junit_name="props.xml")
        if prop_res.collection_error and not prop_res.outcomes:
            done(checks["property_tests"], "error", f"verifier suite failed to run: {prop_res.collection_error.splitlines()[-1][:200]}", True,
                 output=prop_res.collection_error[-1500:], fingerprint=sha256_text("collect-error"))
            prop_res = None
        else:
            # Adjudicate failures: is it a real spec violation or a bad test?
            for o in prop_res.failed:
                if o.name not in triage:
                    if pinned:
                        triage[o.name] = {"genuine": True, "reason": "no pinned adjudication; failing closed"}
                    else:
                        emit("property_tests", "running", f"adjudicating failure: {o.name}")
                        try:
                            triage[o.name] = propgen.triage_failure(task.spec, test_src, o.name, o.message + "\n" + o.detail, o.falsifying)
                        except llm.LLMError as e:
                            triage[o.name] = {"genuine": True, "reason": f"adjudicator unavailable ({e}); failing closed"}
                t = triage[o.name]
                if t.get("genuine", True):
                    genuine.append({"test": o.name, "falsifying": o.falsifying, "message": (o.message or o.detail)[:600], "adjudication": t.get("reason", "")})
                else:
                    discarded.append(o.name)
            (pinned_dir / "triage.json").write_text(json.dumps(triage, indent=2))
            total = len(prop_res.outcomes)
            fp = sha256_json(sorted((o.name, o.status, o.name in discarded) for o in prop_res.outcomes))
            details = {"result": prop_res.summary(), "tests": [{"name": o.name, "status": o.status, "falsifying": o.falsifying} for o in prop_res.outcomes],
                       "discarded": discarded, "generation": gen_meta, "fingerprint": fp, "timing": round(prop_res.duration, 2)}
            if genuine:
                g = genuine[0]
                done(checks["property_tests"], "fail", f"{len(genuine)}/{total} properties violated - {g['test']}" + (f" with {g['falsifying']}" if g["falsifying"] else ""),
                     True, counterexamples=genuine, **details)
            else:
                note = f" ({len(discarded)} test(s) discarded by adjudicator as not spec-backed)" if discarded else ""
                done(checks["property_tests"], "pass", f"{total - len(discarded)}/{total} properties hold{note}", False, **details)

    # ---- 6. mutation testing -----------------------------------------------------------------
    from .mutation import generate_mutants
    emit("mutation", "running", "generating mutants of the changed implementation")
    mutants = []
    for rel, src in sorted(change.impl_files.items()):
        try:
            mutants.extend(generate_mutants(rel, src, max_mutants=max_mutants, seed=seed))
        except Exception as e:  # never let the mutator crash the verdict
            emit("mutation", "running", f"mutator skipped {rel}: {e}")
    mutants = sorted(mutants, key=lambda m: m.id)[: max_mutants]
    (pinned_dir / "mutants.json").write_text(json.dumps([{"id": m.id, "description": m.description} for m in mutants], indent=2))
    excluded = {o.name for o in (prop_res.failed if prop_res else [])}
    can_impl = impl_res is not None and impl_res.ok
    can_ver = prop_res is not None and len(prop_res.outcomes) > len(excluded)
    if not mutants:
        done(checks["mutation"], "skip", "no mutable code in change", False, fingerprint=sha256_text("no-mutants"))
    elif not (can_impl or can_ver):
        done(checks["mutation"], "skip", "no passing suite to evaluate against mutants", False, fingerprint=sha256_text("no-suite"))
    else:
        emit("mutation", "running", f"running {len(mutants)} mutants against both suites")
        results = _run_mutants(task, change, mutants, run_dir, sandbox, seed, test_src if can_ver else None, excluded, can_impl, emit)
        killed_impl = sorted(m for m, r in results.items() if r["impl"])
        killed_ver = sorted(m for m, r in results.items() if r["ver"])
        n = len(mutants)
        si = len(killed_impl) / n if can_impl else None
        sv = len(killed_ver) / n if can_ver else None
        only_ver = sorted(set(killed_ver) - set(killed_impl)) if can_impl and can_ver else []
        survivors = sorted(m.id for m in mutants if not results[m.id]["impl"] and not results[m.id]["ver"])
        desc = {m.id: m.description for m in mutants}
        fp = sha256_json({"impl": killed_impl, "ver": killed_ver})
        parts = []
        if si is not None:
            parts.append(f"implementer tests kill {len(killed_impl)}/{n} ({si:.0%})")
        if sv is not None:
            parts.append(f"adversary tests kill {len(killed_ver)}/{n} ({sv:.0%})")
        summary = ", ".join(parts)
        details = {"mutants": n, "killed_by_implementer": killed_impl, "killed_by_adversary": killed_ver,
                   "survivors": [{"id": s, "description": desc[s]} for s in survivors][:20],
                   "only_adversary_caught": [{"id": s, "description": desc[s]} for s in only_ver][:20],
                   "score_implementer": si, "score_adversary": sv, "fingerprint": fp}
        if si is not None and si < 0.4 and (sv is None or sv - si >= 0.25):
            done(checks["mutation"], "fail", f"implementer's tests are too weak to trust - {summary}", True, **details)
        elif si is not None and si < 0.6:
            done(checks["mutation"], "warn", summary, False, **details)
        else:
            done(checks["mutation"], "pass", summary, False, **details)

    # ---- decision ----------------------------------------------------------------------------
    blocking = [c for c in checks.values() if c.blocking]
    decision = "BLOCK" if blocking else "MERGE"
    reasons = [f"{c.title}: {c.summary}" for c in blocking] or ["all checks passed"]
    vcfg = llm.config_for("verifier").describe()
    impl_cfg = implementer_model or change.meta.get("model_desc") or llm.config_for("implementer").describe()
    pinned_hashes = {
        "verifier_tests_sha256": sha256_text(test_src) if test_src else None,
        "triage_sha256": sha256_json(triage),
        "mutants_sha256": sha256_json([m.id for m in mutants]),
    }
    verdict = Verdict(
        run_id=run_dir.name,
        task=task.name,
        decision=decision,
        reasons=reasons,
        checks=list(checks.values()),
        seed=seed,
        inputs=inputs,
        pinned=pinned_hashes,
        environment=environment_fingerprint(sandbox.describe()),
        models={"implementer": impl_cfg, "verifier": vcfg},
        independence={
            "verifier_saw": ["spec.md", "changed implementation files (comments + docstrings stripped)"],
            "withheld_from_verifier": ["implementer reasoning", "implementer tests", "code comments/docstrings", "plant instructions"],
            "model_family_differs": impl_cfg.get("provider") != vcfg.get("provider"),
            "verifier_view_sha256": inputs["sanitized_view_sha256"],
        },
        created_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
        reproduce=f"adversary reproduce {run_dir}",
    ).finalize()
    verdict.save(run_dir)
    shutil.rmtree(run_dir / "mutants", ignore_errors=True)
    return verdict, run_dir


def _generate_with_retry(task, sanitized, work, sandbox, seed, max_examples, emit):
    feedback = None
    meta: dict = {}
    for attempt in range(3):
        try:
            src, meta = propgen.generate_tests(task.spec, sanitized, task.module, task.functions, feedback=feedback)
        except llm.LLMError as e:
            return None, {"error": str(e)}, str(e)
        err = propgen.validate_tests(src)
        if err is None:
            # Smoke-collect: make sure the suite imports and collects before we trust it.
            install_verifier_suite(work, {VERIFIER_TEST_FILE: HYPOTHESIS_HEADER + src})
            rr = sandbox.run(["-I", "-m", "pytest", "-c", f"{VERIFIER_DIR}/pytest.ini", "--rootdir", VERIFIER_DIR, "--noconftest",
                              "-q", "--collect-only", "-p", "no:cacheprovider", VERIFIER_DIR], cwd=work, timeout=60)
            if rr.returncode == 0:
                meta["attempts"] = attempt + 1
                return src, meta, None
            err = "collection failed:\n" + (rr.stdout + rr.stderr)[-1500:]
        emit("property_tests", "running", f"test suite rejected ({err.splitlines()[0][:80]}); regenerating")
        feedback = err
    return None, meta, feedback


def _run_mutants(task, change, mutants, run_dir, sandbox, seed, test_src, excluded, run_impl, emit):
    tree = change.full_tree()
    base_dir = run_dir / "mutants"
    base_dir.mkdir(exist_ok=True)
    kexpr = " and ".join(f"not {n.split('[')[0]}" for n in sorted(excluded)) if excluded else None

    def one(m):
        d = base_dir / short(sha256_text(m.id), 10)
        t = dict(tree)
        t[m.path] = m.source
        materialize(d, t)
        res = {"impl": False, "ver": False}
        if run_impl:
            r = run_suite(sandbox, d, "tests", seed=seed, hardened=False, max_examples=40, timeout=60, junit_name="impl.xml")
            res["impl"] = r.timed_out or bool(r.failed) or bool(r.collection_error)
        if test_src is not None:
            install_verifier_suite(d, {VERIFIER_TEST_FILE: HYPOTHESIS_HEADER + test_src})
            target = VERIFIER_DIR
            r = _run_ver(sandbox, d, target, seed, kexpr)
            res["ver"] = r.timed_out or bool([o for o in r.failed if o.name not in excluded]) or (bool(r.collection_error) and not r.outcomes)
        shutil.rmtree(d, ignore_errors=True)
        return m.id, res

    out = {}
    workers = max(2, min(8, (os.cpu_count() or 4)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for i, (mid, res) in enumerate(ex.map(one, mutants), 1):
            out[mid] = res
            if i % 5 == 0 or i == len(mutants):
                emit("mutation", "running", f"{i}/{len(mutants)} mutants evaluated")
    return out


def _run_ver(sandbox, d, target, seed, kexpr):
    from .runner import _parse_junit, SuiteResult
    from pathlib import Path as _P
    (d / ".tmp").mkdir(exist_ok=True)
    args = ["-I", "-m", "pytest", "-c", f"{VERIFIER_DIR}/pytest.ini", "--rootdir", VERIFIER_DIR, "--noconftest",
            "-q", "-x", "-p", "no:cacheprovider", f"--hypothesis-seed={seed}", "--junitxml=.tmp/ver.xml", "-o", "junit_family=xunit1"]
    if kexpr:
        args += ["-k", kexpr]
    args.append(target)
    rr = sandbox.run(args, cwd=d, timeout=90, env={"ADVERSARY_MAX_EXAMPLES": "40"})
    res = SuiteResult(returncode=rr.returncode, timed_out=rr.timed_out, duration=rr.duration)
    res.outcomes = _parse_junit(d / ".tmp" / "ver.xml")
    if not res.outcomes and rr.returncode not in (0, 5) and not rr.timed_out:
        res.collection_error = (rr.stdout + rr.stderr)[-500:]
    return res


def _finding(rule, path, lineno, severity, message, snippet):
    return {"rule": rule, "path": path, "lineno": lineno, "severity": severity, "message": message, "snippet": snippet}


def _as_dict(x) -> dict:
    if isinstance(x, dict):
        return x
    from dataclasses import asdict, is_dataclass
    return asdict(x) if is_dataclass(x) else dict(vars(x))


def load_pinned(run_dir: Path) -> dict:
    p = run_dir / "pinned"
    out = {}
    if (p / VERIFIER_TEST_FILE).exists():
        out["verifier_tests"] = (p / VERIFIER_TEST_FILE).read_text()
    if (p / "triage.json").exists():
        out["triage"] = json.loads((p / "triage.json").read_text())
    return out
