# OVERCLOCK — an AI that teaches itself to make code faster

*The System That Gets Better* track. Built on top of (and gated by) [Adversary](README.md), the independent verifier.

OVERCLOCK speeds up slow Python functions **and gets better as it goes**. Each verified win is distilled into one
reusable *rule* in a versioned playbook. A rule is kept only if it makes the optimizer faster on **held-out**
functions it has never learned from; otherwise it is rolled back. The rolled-back version stays on disk as evidence.

```
                 playbook v(n)                       ┌──────────────────────────────────┐
  slow function ──────────────▶ OPTIMIZER (implementer LLM) ──▶ candidate rewrite        │
                                                      │                                 │
   1. differential check: same answers as the reference on seeded inputs   (harness)   │  any failure:
   2. ADVERSARY verdict: spec + diff only, a different model, blind         (gate)     │  nothing is timed,
      property tests, cheat detector, security pass, mutation testing                   │  nothing is learned
   3. stopwatch: median of 7, then RE-TIMED on a fresh random seed          (harness)   │
                                                      │ win (>= 1.5x)                   │
                                        REFLECT: write ONE general rule  ──▶ candidate playbook v(n+1)
                                                      │
                        score v(n+1) on HELD-OUT tasks (full gauntlet above, geometric-mean speed-up)
                                                      │
                               better than v(n) by > 10%?  ── yes ──▶ KEEP  (CURRENT -> v(n+1))
                                                      └──── no ───▶ ROLLBACK (v(n+1) saved as rolled_back)
                                              every decision -> playbook/ledger.jsonl with the numbers
```

## The one rule that matters: it learns, it doesn't just optimize

There are two optimizer policies, and which one applies is decided by the task split, never by the model:

- **Exploration (learn tasks only):** the optimizer may restructure freely (algorithms, data structures, stdlib,
  memoisation) to *find* a win. This is training. Nothing from here is shipped directly.
- **Deployment (held-out and unseen tasks, always):** a fixed, conservative policy: local, obviously-safe edits only;
  no new imports, no algorithm swaps, no caching, *unless a playbook rule explicitly permits it*. Rules grant
  permission and supply the pattern ("when a list is only used for membership tests, build a set first").

So on an unseen function the prompt scaffold and policy are identical before and after learning; the *only* thing
that differs is the rule list. That is what the before/after measurement isolates.

Because a conservative baseline could be accused of manufacturing the effect, `overclock demo` reports a **second
baseline**: the same unseen function optimized in unconstrained exploration mode with an empty playbook. The learned
playbook has to beat *that* too for the learning claim to stand; if it doesn't, the demo says so.

**Status at submission:** the loop has not yet been run against a live model (no key on the machine that built it),
so there are no playbook versions or speed-up numbers in this repository yet. Everything above is implemented and
covered by offline tests (`tests/test_loop.py`, `tests/test_overclock_gate*.py`); the numbers appear here after the
first `overclock learn`. Exploration wins that the
reflection step fails to turn into a rule that helps held-out tasks are rolled back like any other.

## Honesty rules (never cut)

| Rule | Where |
|---|---|
| Correctness is checked **before** anything is timed; a wrong rewrite never gets a speed-up number | `overclock/harness.py` |
| Speed is the median of 7 repeats, slow vs fast on identical inputs, in a `python -I` subprocess | `harness.benchmark` |
| The rewrite is re-timed on inputs from a **fresh random seed**; a precomputed answer table collapses here | `harness.benchmark(fresh_check=True)` |
| Every rewrite is a PR to an **independent verifier** that never sees the playbook, the prompt, or the seed | `overclock/gate.py` -> `adversary.verifier.pipeline` |
| Held-out tasks are never learned from; a rule is kept only if their geometric-mean speed-up rises > 10% | `overclock/loop.py` |
| Rolled-back playbook versions are kept on disk (`status: rolled_back`), `CURRENT` points at the last accepted | `playbook/` |
| Every decision is appended to `playbook/ledger.jsonl` with before/after numbers per task | `overclock/playbook.py` |

## Quickstart

```bash
uv sync                                   # or: uv pip install -e .
cp .env.example .env                      # keys: see README "Configuration"
uv run overclock tasks                    # 13 learn + 7 held-out slow functions
uv run overclock optimize h02_common_elements          # one pass: optimize -> verify -> time
uv run overclock learn --heldout-n 4                   # the loop; watch rules get kept or rolled back
uv run overclock playbook                              # versions + ledger
uv run overclock attack t02_membership --kind table    # planted cheat: 56x on published inputs, 1x on fresh ones
uv run overclock attack t02_membership --kind edge     # fast but wrong on an empty list + a note to "AI reviewers"
uv run overclock attack t02_membership --kind escape   # reads answers from disk -> security pass
uv run overclock demo                                  # the 3-minute story
```

Flags: `--no-gate` skips Adversary on learn tasks and `--no-gate-heldout` on held-out scoring (fast dev loop; the
honest run uses both). All LLM calls go through the repo's record/replay cassette, so a demo replays offline.

## Layout

```
overclock/
  tasks/        t01..t13 (learn) and h01..h07 (held-out): SPEC, slow(), gen_inputs(seed, n)
  harness.py    subprocess sandbox, correctness-before-timing, fresh-seed re-time
  optimizer.py  implementer LLM + playbook -> rewrite (same public name, same signature)
  gate.py       wraps adversary.verifier.pipeline.verify around a one-module spec+diff PR
  reflect.py    one verified win -> one general rule
  playbook.py   immutable versions v000.json, v001.json, ...; CURRENT pointer; ledger.jsonl
  loop.py       learn(): optimize -> verify -> time -> reflect -> held-out eval -> keep | rollback
  attacks.py    planted cheats (table / edge / escape) and what should catch each
  cli.py        terminal view (a log of decisions, not a dashboard)
playbook/       the artifact that improves; committed so the history is inspectable
```

Note: `adversary learn` / `adversary playbook` are the *verifier's* self-improving playbook of test tactics
(`.adversary/playbook/`). `overclock learn` / `overclock playbook` are the *optimizer's* playbook of speed rules
(`playbook/`). Both follow the same adopt-only-if-held-out-improves discipline.
