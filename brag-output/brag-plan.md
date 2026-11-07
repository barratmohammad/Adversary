# Adversary: brag plan

**What it is:** an independent AI verifier for AI-written pull requests. It writes blind tests from the spec, which the
coder never sees, fuzzes the change in a sandbox, has two judges confirm every failure, and blocks the merge with a
reproducible verdict.
**For:** teams merging AI-generated code faster than humans can review it.
**What sets it apart:** independence. The verifier never sees the implementer's reasoning, tests, or comments; it
proves bugs with concrete counterexamples.
**Most impressive claim:** of 44 real GPT-4 / ChatGPT / Code Llama / Mistral bugs that passed *every* official
HumanEval test, Adversary blocked 27. The adaptive red team got 1 of 11 attacks through.
**Visual hook:** a green "14/14 tests passed" that turns into a red "MERGE BLOCKED".
**Real UI shown:** the actual terminal verdict panel from `adversary run intervals --plant subtle` (run
20261107-134955), and the GitHub status check on PR #2.
**Tone:** `polished`, leaning cinematic. It's a security tool, so the drama comes from the catch.
**Identity:** the CLI's own palette (rich): near-black `#0b0f14`, cyan `#22d3ee` borders, green `#22c55e` ✔, red
`#ef4444` ✘, yellow `#eab308` counterexamples. SF Mono for terminal text, SF Pro for display type.
**Share caption:** "AI wrote the PR. Its tests passed. Adversary wrote its own and blocked it."

## Music
120 BPM (beat 0.5s, bar 2s), A minor, Am-F-C-G per bar. Sparse pad + ticks for the hook; the kick enters on the reveal
at 4.0s; outro resolves on Am and fades. Whooshes rise into each cut; row-reveal blips sit on 8th notes, tuned to A.

## Storyboard (40s = 20 bars, every cut on a bar line)
| # | time | scene | on screen |
|---|---|---|---|
| 1 | 0-4 | Hook | "An AI wrote this pull request." types in; "Its own tests pass. ✔ 14/14" (green); on beat 3.0 red "It's still wrong." |
| 2 | 4-8 | Reveal | ADVERSARY wordmark; "Writes the tests the AI never sees. Blocks the merge." |
| 3 | 8-16 | How | pipeline nodes light up one per beat-pair: spec + diff → comments stripped → Meta Muse Spark writes blind tests → fuzzed in a sandbox → 2 judges (SubQ Snap + reasoning) → MERGE / BLOCK |
| 4 | 16-24 | The catch (real UI) | live-checks panel rows tick in; "Implementer's own tests ✔ 14/14 passed"; "Blind property tests ✘ 8/28 violated"; verdict "⛔ MERGE BLOCKED", counterexample `assert [(1, 4)] == [(1, 3), (4, 4)]`, SubQ P(violation)=0.99 |
| 5 | 24-28 | On GitHub | PR #2 check: ✘ adversary/verify, BLOCK: env-triggered backdoor |
| 6 | 28-36 | Proof | stat cards: 27/44 real LLM bugs blocked (official tests 0/44) · 10/11 red-team attacks caught · identical verdict hash on re-run |
| 7 | 36-40 | Outro | "ADVERSARY: trust, but verify." · github.com/barratmohammad/Adversary · Meta Muse Spark · SubQ Snap · Fetch.ai uAgents |

No secrets, keys, or personal data appear on screen; all numbers come from `README.md` / `bench/*.json`.
