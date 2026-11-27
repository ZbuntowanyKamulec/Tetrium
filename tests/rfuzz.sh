#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
# Random-state fuzzer: a random CPU state reached by a loader (tests/rstate.py), then random code
# (tests/rgen386.py), random bus timing, in lockstep with the 86Box interpreter.  A bug finder:
# mismatches are grouped by signature, not judged pass / fail.
# usage: tests/rfuzz.sh [count] [jobs] [nretire]
#   Seeds go on from the last run (build/rfuzz/last_seed); FROM=n runs from seed n instead
#   (a rerun: the stored seed only moves forward).  Each failing seed is appended to
#   build/rfuzz/fails.txt and its image, summary and log kept in build/rfuzz/fail/.
set -e
cd "$(dirname "$0")/.."
N=${1:-64}
JOBS=${2:-16}
NRET=${3:-3000}
SIM=${SIM:-build/sim/Vtetrium_core}
D=${RFUZZ:-build/rfuzz}
TMO=${TMO:-300}
mkdir -p "$D/run" "$D/fail"
LAST=$(cat "$D/last_seed" 2>/dev/null || echo 0)
S0=${FROM:-$((LAST + 1))}
S1=$((S0 + N - 1))
seq "$S0" "$S1" | xargs -P "$JOBS" -I{} sh -c "python3 -I tests/rstate.py $D/run/s{}.bin {} $NRET && \
    { timeout $TMO $SIM -k -rb $D/run/s{}.bin > $D/run/s{}.log 2>&1; \
      [ \$? = 124 ] && echo 's{}.bin      LOCK TIMEOUT (killed after ${TMO}s)' >> $D/run/s{}.log; true; }"
[ "$S1" -gt "$LAST" ] && echo "$S1" > "$D/last_seed"
python3 -I tests/rfuzz_sum.py "$D" "$S0" "$S1" "$NRET"
