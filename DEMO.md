# Demo

## 1-minute submission video
Make the terminal big (font ~16pt, ~120 columns), start screen recording (macOS: Cmd+Shift+5), then:
```bash
cd ~/Desktop/CVHACKS && ./demo.sh          # offline replay, ~45s; LIVE=1 ./demo.sh for real model calls
```
End the video on https://github.com/barratmohammad/Adversary/pull/2 (red `adversary/verify` check + verdict comment).

## 3-minute live pitch

Pre-flight: `source .venv/bin/activate`. If Wi-Fi is bad: `export ADVERSARY_LLM_MODE=replay` (every model call
replays from `.adversary/cassettes/`; verdicts are identical).

**0:00 - Problem (20s).** "AI writes code faster than anyone can review it. And when the same AI writes the code
*and* the tests, the tests share its blind spots - or it just hardcodes the answers. Adversary is an independent
verifier: it gets the spec and the diff, never the implementer's reasoning or tests, writes its own tests, and
blocks the merge with a verdict anyone can reproduce."

**0:20 - Honest change merges (25s).**
```bash
adversary run roman --fixture clean --quiet
```
Point at: verifier = Meta Muse Spark writing tests from the spec; 108 blind properties hold; mutation testing scores
both suites; SubQ Snap second opinion "safe"; verdict hash.

**0:45 - The secret sabotage (50s). The demo moment.**
```bash
adversary run intervals --plant subtle
```
"I'm secretly telling the implementer to plant a bug. The verifier isn't told." Point at: implementer's own 14 tests
pass ✔ - but 8 blind properties fail with a concrete counterexample `[(1,3),(4,4)] -> [(1,4)]`; two judges (SubQ Snap
+ a reasoning judge) agree it's a real spec violation; MERGE BLOCKED.

**1:35 - It blocks real PRs (30s).** Open https://github.com/barratmohammad/Adversary/pull/2: the implementer's PR
has a hidden env-var backdoor. Red `adversary/verify` check + verdict comment. Caught twice: the security pass, and a
blind test Meta wrote from the spec line "must not depend on the environment".

**2:05 - Hard to game, reproducible (30s).**
```bash
adversary reproduce runs/<id>     # no model calls, identical outcome hash
adversary matrix                  # 13/13: every honest change merges, every cheat/bug/backdoor blocks
```
Say: comments are stripped before the verifier sees code (prompt-injection proof); its tests run with `python -I`,
`--noconftest`, its own ini, network denied - a planted `conftest.py`/`sitecustomize.py` can't rewrite results.

**2:35 - Bonus (25s).** `adversary swarm --calibrate` - Fetch.ai uAgents specialists vote and stake reputation; the
miscalibrated agent loses its weight (1.00 -> 0.06). And OVERCLOCK: a self-improving optimizer whose every speed-up
must pass Adversary first.

## Q&A crib
- **Can the verifier's own tests be wrong?** Yes - we hit it: Meta once asserted something the spec forbids. So a
  failing test only blocks if SubQ Snap *and* a step-by-step reasoning judge both call it a genuine violation.
  Discards are recorded in the verdict.
- **Why can't the implementer game it?** It never sees the verifier's tests; they're generated after the diff is
  frozen, from the spec, by a different model; the code is comment-stripped; the runner ignores conftest/ini/startup
  hooks; mutation testing exposes vacuous tests; the cheat detector flags hardcoded test inputs.
- **Reproducible how?** Seed, sandbox profile, lockfile hash, spec/diff/test/mutant hashes are pinned; model calls are
  recorded; `reproduce` must produce the same outcome hash.
- **Sponsors:** Meta Model API (blind test author + implementer), Subquadratic SubQ Snap Decisions API (adjudicator +
  merge-risk), Fetch.ai uAgents (verifier swarm), MongoDB (verdict ledger when `MONGODB_URI` is set).
- **Built today?** Yes - every commit is from Nov 7.
