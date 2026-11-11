#!/usr/bin/env bash
# Soak one nos-e2e group N times (#884): GROUP=<group> N=<n> tools/ci/e2e-soak.sh
# Holds the shared lab lock for the whole loop. Per-run logs and results.txt go
# to $TMPDIR/e2e-soak/<group>-<ts>/; only the last 3 failed run logs are kept.
set -u

GROUP=${GROUP:-}
N=${N:-}
if [ -z "$GROUP" ] || [ -z "$N" ] || ! [ "$N" -ge 1 ] 2>/dev/null; then
    echo "usage: make e2e-soak GROUP=<base|drivers|rpl|ospf-suite|pki-suite> N=<runs>" >&2
    exit 2
fi
if [ "$GROUP" = multi ]; then
    echo "e2e-soak: 'multi' is refused until the evpn-l3-chunked hang is fixed (#839)" >&2
    exit 2
fi

LOCK=/tmp/nos-e2e.lock
mkdir "$LOCK" 2>/dev/null || { echo "e2e-soak: lab lock $LOCK exists, another e2e run is active" >&2; exit 1; }
trap 'rmdir "$LOCK"' EXIT

OUT="${TMPDIR:-/tmp}/e2e-soak/$GROUP-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
RESULTS="$OUT/results.txt"
: >"$RESULTS"
echo "e2e-soak: $GROUP x$N, logs in $OUT"

pass=0
for i in $(seq 1 "$N"); do
    log="$OUT/run-$i.log"
    start=$(date +%s)
    if cargo run -q -p nos-e2e -- "$GROUP" >"$log" 2>&1; then
        echo "$i PASS $(($(date +%s) - start))s" >>"$RESULTS"
        pass=$((pass + 1))
        rm -f "$log"
    else
        secs=$(($(date +%s) - start))
        # The phase is the last "=== name ===" banner; the error is the
        # harness's own "FAILED: ..." line (first line only, anyhow chains
        # and multi-line quiet failures continue below it).
        phase=$(sed -n 's/.*=== \(.*\) ===.*/\1/p' "$log" | tail -1)
        err=$(sed -n 's/.*\] [^ ]*: FAILED: //p' "$log" | head -1 | cut -c1-200)
        echo "$i FAIL ${secs}s $phase | $err" >>"$RESULTS"
        # keep only the 3 newest failed logs
        ls -t "$OUT"/run-*.log 2>/dev/null | tail -n +4 | xargs -r rm -f
    fi
    docker image prune -f >/dev/null 2>&1 || true
done

echo
cat "$RESULTS"
echo
echo "Per-check failures ($GROUP):"
grep ' FAIL ' "$RESULTS" | cut -d' ' -f4- | sort | uniq -c | sort -rn
echo
echo "$GROUP: $pass/$N passed"
