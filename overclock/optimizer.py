"""The optimizer: the implementer LLM rewrites a slow function, guided only by the playbook.

Design choice (stated in the README): with an EMPTY playbook the optimizer follows a conservative
policy: local, obviously-safe edits only; no new imports, no algorithm swaps, no caching. Playbook
rules are what grant permission and supply patterns. The scaffold is identical in every run, so
the only thing that changes between "before learning" and "after learning" is the rule list.

Uses the same `implementer` role (Meta Muse by default) and record/replay cassette as the rest of
the repo, so the optimizer and the Adversary verifier are guaranteed to be different model families.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from adversary import llm
from overclock.playbook import Playbook
from overclock.tasks import Task

SYSTEM = """You are a careful Python performance engineer working inside an automated loop.
You will be given a SPEC, a slow reference implementation, and a PLAYBOOK of rules that previous
iterations of this system have learned and verified.

Hard requirements:
- Output exactly one ```python code block defining a function with the SAME NAME and SAME signature
  as the reference. No other top-level code except imports/helpers that the function needs.
- The function must return results identical to the reference for every valid input in the SPEC.
- Never hard-code answers, never read files, never use eval/exec, never touch os/sys/subprocess.

{policy}
"""

DEPLOY_POLICY = """Default policy when the PLAYBOOK does not say otherwise:
- Make only local, obviously-safe micro-optimisations (bind attributes/globals to locals, hoist
  loop-invariant expressions, avoid redundant work inside loops).
- Do NOT change the underlying algorithm or data structures, do NOT add imports, and do NOT add
  caching/memoisation unless a PLAYBOOK rule explicitly permits that kind of change.
The PLAYBOOK rules override the default policy: when a rule applies, follow it."""

EXPLORE_POLICY = """Exploration mode (training): find the FASTEST correct implementation you can.
- You may restructure the algorithm, change data structures, use the Python standard library
  (collections, itertools, functools, math, bisect, heapq) and add memoisation or precomputation,
  as long as the outputs stay identical to the reference for every valid input in the SPEC.
- Still no hard-coded answers, no I/O, no eval/exec, no os/sys/subprocess.
Apply any PLAYBOOK rules that fit, and go beyond them when you see a bigger safe win."""

USER_TMPL = """SPEC:
{spec}

SLOW REFERENCE:
```python
{source}
```

PLAYBOOK (verified rules; follow any that apply):
{rules}

Rewrite `{signature}` to be faster. Respond with only the code block."""


@dataclass
class OptimizeResult:
    task: str
    source: str
    raw: str
    model: str
    cached: bool
    playbook_version: int


_BLOCK = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.S)


def extract_code(text: str, func: str) -> str | None:
    for b in _BLOCK.findall(text):
        if f"def {func}(" in b:
            return b.strip() + "\n"
    if f"def {func}(" in text:
        return text.strip() + "\n"
    return None


def build_messages(task: Task, playbook: Playbook, explore: bool = False) -> list[dict]:
    """`explore=True` is used only on LEARN tasks (training). Held-out and unseen tasks always get the
    fixed deployment policy, so the only thing that differs between runs on them is the rule list."""
    system = SYSTEM.format(policy=EXPLORE_POLICY if explore else DEPLOY_POLICY)
    user = USER_TMPL.format(spec=task.public_spec, source=task.public_source, rules=playbook.render(),
                            signature=task.signature)
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def optimize(task: Task, playbook: Playbook, explore: bool = False) -> OptimizeResult:
    messages = build_messages(task, playbook, explore)
    tag = f"overclock{'-explore' if explore else ''}:{task.name}"
    comp = llm.chat("implementer", messages, temperature=0.0, max_tokens=2048, tag=tag)
    src = extract_code(comp.text, task.func)
    if src is None:  # one retry with a nudge
        messages.append({"role": "assistant", "content": comp.text})
        messages.append({"role": "user", "content": f"Your reply had no ```python block defining `{task.func}`. "
                                                    "Reply with only the code block."})
        comp = llm.chat("implementer", messages, temperature=0.0, max_tokens=2048, tag=f"overclock-retry:{task.name}")
        src = extract_code(comp.text, task.func) or (
            f"def {task.signature}:\n    raise RuntimeError('optimizer produced no code')\n")
    return OptimizeResult(task.name, src, comp.text, comp.model, comp.cached, playbook.version)
