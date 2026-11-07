"""Reflect: turn one verified speed-up into ONE general, reusable playbook rule."""
from __future__ import annotations

import re

from adversary import llm
from overclock.playbook import Playbook
from overclock.tasks import Task

SYSTEM = """You distil performance wins into short, general, reusable rules for a Python optimizer.
A rule has two parts: a trigger ("When you see ...") and an action ("... do ... ; this is permitted").
Rules must be general (never mention the specific function or variable names), must preserve exact
outputs, and must be at most two sentences. Reply with the rule text only, no numbering, no quotes."""

USER_TMPL = """A slow function was rewritten, independently verified correct, and measured {speedup:.1f}x faster.

SPEC:
{spec}

BEFORE:
```python
{before}
```

AFTER:
```python
{after}
```

EXISTING PLAYBOOK RULES (do not duplicate these; if the trick is already covered, generalise further
or capture a different aspect of the win):
{rules}

Write the one new rule."""


def propose_rule(task: Task, before: str, after: str, speedup: float, playbook: Playbook) -> str:
    user = USER_TMPL.format(speedup=speedup, spec=task.public_spec, before=before, after=after,
                            rules=playbook.render())
    comp = llm.chat("implementer", [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
                    temperature=0.0, max_tokens=4000, tag=f"overclock-reflect:{task.name}")
    return clean_rule(comp.text)


_PREFIX = re.compile(r"^(\*\*)?\s*(new\s+)?rule\s*[:\-]?\s*(\*\*)?\s*|^\d+[.)]\s*|^[-*•]\s*", re.I)


def clean_rule(text: str) -> str:
    """Last non-empty paragraph, markdown and 'Rule:'/numbering prefixes stripped, one line."""
    paras = [p.strip() for p in re.split(r"\n\s*\n", text.strip()) if p.strip()]
    para = paras[-1] if paras else text.strip()
    line = " ".join(l.strip() for l in para.splitlines() if l.strip())
    line = _PREFIX.sub("", line).replace("**", "").strip().strip('"').strip("'").strip()
    return line
