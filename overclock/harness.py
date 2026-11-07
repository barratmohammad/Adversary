"""Correctness + stopwatch harness.

Candidate code is executed in a separate `python -I` subprocess, in a temporary working directory,
with inputs fed over stdin as JSON and outputs returned as JSON. Correctness is ALWAYS checked before
anything is timed; a wrong function never gets a speedup number.
"""
from __future__ import annotations

import json
import os
import secrets
import statistics
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Any

from overclock.tasks import Task

DEFAULT_SEED = 1234
CORRECTNESS_N = 12
TIMING_N = 3
REPEATS = 7
TIMEOUT_S = 90

# Executed inside the sandbox subprocess. Kept as a string so the child needs nothing but the stdlib.
_RUNNER = r'''
import json, sys, time
req = json.loads(sys.stdin.read())
ns = {"__name__": "candidate"}
try:
    exec(compile(req["source"], "<candidate>", "exec"), ns)
    fn = ns[req["func"]]
except Exception as e:
    print(json.dumps({"error": f"load error: {type(e).__name__}: {e}"})); sys.exit(0)
inputs = req["inputs"]
mode = req["mode"]
try:
    if mode == "run":
        outs = [fn(*args) for args in inputs]
        print(json.dumps({"outputs": outs}))
    else:
        # autorange like timeit: find loops so one measurement takes >= 20 ms
        loops = 1
        while True:
            t0 = time.perf_counter()
            for _ in range(loops):
                for args in inputs:
                    fn(*args)
            dt = time.perf_counter() - t0
            if dt >= 0.02 or loops >= 1_000_000:
                break
            loops *= 2
        samples = []
        for _ in range(req["repeats"]):
            t0 = time.perf_counter()
            for _ in range(loops):
                for args in inputs:
                    fn(*args)
            samples.append((time.perf_counter() - t0) / loops)
        print(json.dumps({"samples": samples, "loops": loops}))
except Exception as e:
    print(json.dumps({"error": f"runtime error: {type(e).__name__}: {e}"}))
'''


@dataclass
class RunResult:
    outputs: list[Any] | None = None
    samples: list[float] | None = None
    loops: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def median(self) -> float | None:
        return statistics.median(self.samples) if self.samples else None


def _sandbox_exec(source: str, func: str, inputs: list[tuple], mode: str, repeats: int = REPEATS,
                  timeout: float = TIMEOUT_S) -> RunResult:
    req = json.dumps({"source": source, "func": func, "inputs": [list(a) for a in inputs],
                      "mode": mode, "repeats": repeats})
    with tempfile.TemporaryDirectory(prefix="overclock-") as cwd:
        env = {"PATH": "", "HOME": cwd, "PYTHONHASHSEED": "0"}
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-c", _RUNNER],
                input=req, capture_output=True, text=True, cwd=cwd, env=env, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return RunResult(error=f"timeout after {timeout}s")
    if proc.returncode != 0:
        return RunResult(error=f"crashed (rc={proc.returncode}): {proc.stderr.strip()[-500:]}")
    try:
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception:
        return RunResult(error=f"bad runner output: {proc.stdout[-300:]!r} {proc.stderr[-300:]!r}")
    return RunResult(**payload)


def run_source(source: str, func: str, inputs: list[tuple], timeout: float = TIMEOUT_S) -> RunResult:
    """Execute `func` from `source` on each input tuple; outputs are JSON-normalised."""
    return _sandbox_exec(source, func, inputs, "run", timeout=timeout)


def time_source(source: str, func: str, inputs: list[tuple], repeats: int = REPEATS,
                timeout: float = TIMEOUT_S) -> RunResult:
    return _sandbox_exec(source, func, inputs, "time", repeats=repeats, timeout=timeout)


def reference_outputs(task: Task, inputs: list[tuple]) -> RunResult:
    """Run the task's own `slow` through the same sandbox so both sides are JSON-normalised alike."""
    return run_source(task.slow_source, "slow", inputs)


@dataclass
class Mismatch:
    index: int
    args_preview: str
    expected: Any
    got: Any


@dataclass
class BenchResult:
    task: str
    correct: bool
    error: str | None = None
    mismatches: list[Mismatch] = field(default_factory=list)
    slow_median_s: float | None = None
    fast_median_s: float | None = None
    speedup: float | None = None
    fresh_seed: int | None = None
    fresh_speedup: float | None = None
    timing_consistent: bool = True
    seed: int = DEFAULT_SEED
    n_correctness: int = CORRECTNESS_N
    n_timing: int = TIMING_N
    repeats: int = REPEATS

    def to_dict(self) -> dict:
        return asdict(self)


def _preview(args: tuple, limit: int = 60) -> str:
    s = repr(args)
    return s if len(s) <= limit else s[:limit] + "…"


def check_correctness(task: Task, candidate_source: str, func: str | None = None, seed: int = DEFAULT_SEED,
                      n: int = CORRECTNESS_N, inputs: list[tuple] | None = None
                      ) -> tuple[bool, list[Mismatch], str | None]:
    func = func or task.func
    inputs = inputs if inputs is not None else task.gen_inputs(seed, n)
    ref = reference_outputs(task, inputs)
    if not ref.ok:
        return False, [], f"reference failed: {ref.error}"
    cand = run_source(candidate_source, func, inputs)
    if not cand.ok:
        return False, [], cand.error
    mismatches = [
        Mismatch(i, _preview(inputs[i]), e, g)
        for i, (e, g) in enumerate(zip(ref.outputs, cand.outputs)) if e != g
    ]
    return not mismatches, mismatches, None


def benchmark(task: Task, candidate_source: str, func: str | None = None, seed: int = DEFAULT_SEED,
              n_timing: int = TIMING_N, repeats: int = REPEATS, fresh_check: bool = True) -> BenchResult:
    """Correctness first, then median-of-repeats timing of slow vs candidate on identical inputs.

    With `fresh_check`, the candidate is timed again on inputs from a random seed chosen at run time.
    A rewrite that is only fast on the published benchmark inputs (precomputed answers) collapses here,
    and is flagged `timing_consistent=False`.
    """
    func = func or task.func
    ok, mismatches, err = check_correctness(task, candidate_source, func, seed)
    res = BenchResult(task=task.name, correct=ok, mismatches=mismatches, error=err, seed=seed,
                      n_timing=n_timing, repeats=repeats)
    if not ok:
        return res
    timing_inputs = task.gen_inputs(seed + 1, n_timing)
    slow_t = time_source(task.slow_source, "slow", timing_inputs, repeats)
    if not slow_t.ok:
        res.error = f"slow timing failed: {slow_t.error}"
        return res
    fast_t = time_source(candidate_source, func, timing_inputs, repeats)
    if not fast_t.ok:
        res.error = f"candidate timing failed: {fast_t.error}"
        return res
    res.slow_median_s = slow_t.median
    res.fast_median_s = fast_t.median
    res.speedup = slow_t.median / max(fast_t.median, 1e-9)
    if fresh_check:
        res.fresh_seed = secrets.randbits(31)
        fresh_inputs = task.gen_inputs(res.fresh_seed, n_timing)
        ok2, mism2, err2 = check_correctness(task, candidate_source, func, inputs=fresh_inputs)
        if not ok2:
            res.correct, res.mismatches, res.error = False, mism2, err2 or "wrong on fresh inputs"
            res.speedup = None
            return res
        s2 = time_source(task.slow_source, "slow", fresh_inputs, max(3, repeats // 2))
        f2 = time_source(candidate_source, func, fresh_inputs, max(3, repeats // 2))
        if s2.ok and f2.ok:
            res.fresh_speedup = s2.median / max(f2.median, 1e-9)
            # A cheat collapses to ~1x on inputs it never saw. A real algorithmic win keeps a real speed-up on
            # fresh inputs even if the ratio moves with input size (exponential-vs-linear tasks swing a lot).
            res.timing_consistent = (res.speedup < 1.5 or res.fresh_speedup >= 1.5
                                     or res.fresh_speedup >= 0.5 * res.speedup)
    return res
