"""Task bank registry.

Each task module exports:
    SPEC: str                      plain-English contract (seen by optimizer AND verifier)
    TAGS: list[str]                for the README only
    slow(*args)                    deliberately naive reference implementation
    gen_inputs(seed, n) -> list    deterministic list of argument tuples

The public function name is derived from the module name (t01_fib -> `fib`). Both the slow reference
and every optimized rewrite define that same name, so the Adversary verifier sees an ordinary
"before/after" diff of one module.

Tasks are split into LEARN (the system may learn rules from these) and HELD_OUT
(never learned from; used only to decide whether a candidate rule is kept).
"""
from __future__ import annotations

import importlib
import inspect
from dataclasses import dataclass
from types import ModuleType

LEARN = [
    "t01_fib",
    "t02_membership",
    "t03_str_concat",
    "t04_resort",
    "t05_pair_sums",
    "t06_index_lookup",
    "t07_dedupe",
    "t08_count_each",
    "t09_is_prime",
    "t10_queue_pop0",
    "t11_running_max",
    "t12_flatten",
    "t13_anagram_groups",
]

HELD_OUT = [
    "h01_tribonacci",
    "h02_common_elements",
    "h03_join_words",
    "h04_prefix_ranges",
    "h05_first_index",
    "h06_unique_words",
    "h07_prime_count",
]

ALL = LEARN + HELD_OUT


@dataclass(frozen=True)
class Task:
    name: str
    spec: str
    tags: tuple[str, ...]
    module: ModuleType

    # ---- the public API, as the optimizer and the verifier see it -------------
    @property
    def func(self) -> str:
        """Public function name: t01_fib -> fib."""
        return self.name.split("_", 1)[1]

    @property
    def public_spec(self) -> str:
        return self.spec.replace("slow(", f"{self.func}(")

    @property
    def public_source(self) -> str:
        """The slow reference, renamed to the public function name."""
        return self.slow_source.replace("def slow(", f"def {self.func}(", 1)

    @property
    def signature(self) -> str:
        return f"{self.func}{inspect.signature(self.module.slow)}"

    @property
    def module_file(self) -> str:
        return f"{self.func}.py"

    # ---- harness-side ----------------------------------------------------------
    @property
    def slow(self):
        return self.module.slow

    @property
    def slow_source(self) -> str:
        return inspect.getsource(self.module.slow)

    def gen_inputs(self, seed: int, n: int) -> list[tuple]:
        return self.module.gen_inputs(seed, n)

    @property
    def split(self) -> str:
        return "held_out" if self.name in HELD_OUT else "learn"


def load(name: str) -> Task:
    if name not in ALL:
        raise KeyError(f"unknown task {name!r}; known: {ALL}")
    mod = importlib.import_module(f"overclock.tasks.{name}")
    return Task(name=name, spec=mod.SPEC.strip(), tags=tuple(mod.TAGS), module=mod)


def load_all(names: list[str] | None = None) -> list[Task]:
    return [load(n) for n in (names or ALL)]
