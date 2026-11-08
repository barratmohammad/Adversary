#!/usr/bin/env bash
# One-minute demo for the submission video. Replays recorded model calls by default, so it is fast
# and works without Wi-Fi. LIVE=1 ./demo.sh makes real Meta + SubQ calls instead.
set -uo pipefail   # adversary exits 1 on BLOCK by design; keep going
cd "$(dirname "$0")"
# iCloud-synced folders can mark the venv's .pth files hidden; Python 3.12 then skips them (No module named adversary).
chflags nohidden .venv/lib/python*/site-packages/*.pth 2>/dev/null || true
export COLUMNS=${COLUMNS:-120}
[ "${LIVE:-0}" = "1" ] || export ADVERSARY_LLM_MODE=replay
A=".venv/bin/adversary"
say() { printf "\n\033[1;36m▶ %s\033[0m\n" "$1"; sleep "${PAUSE:-1.5}"; }

clear
printf "\033[1mADVERSARY\033[0m - AI writes the code. An independent AI decides if it merges.\n"
printf "Meta Muse Spark writes blind tests from the spec · SubQ Snap judges every failure · sandboxed, seeded, hash-pinned\n"

say "1. An honest change: blind tests written from the spec all hold -> safe to merge"
$A run roman --fixture clean --quiet --mutants 20

say "2. Now the implementer AI is SECRETLY told to plant a subtle bug. The verifier is not told."
$A run intervals --plant subtle --mutants 20 --diff-lines 0 --quiet
# newest run directory (don't parse it out of the panel: long paths wrap)
RUN=$(ls -td runs/[0-9]*/ 2>/dev/null | grep -v -- '-repro' | head -1)
RUN=${RUN%/}

say "3. Anyone can re-run the verdict from pinned inputs - no model calls, same outcome hash"
$A reproduce "$RUN" | tail -9

say "4. Every planted bug, cheat and backdoor - and every honest change"
$A matrix --mutants 20 --parallel 4 | sed -n '/Adversary verdict matrix/,$p'
