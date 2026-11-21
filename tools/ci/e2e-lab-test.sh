#!/usr/bin/env bash
# Tests for e2e-lab.sh against a temp lock prefix.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
export NOS_E2E_LOCK_PREFIX=$d/lock NOS_E2E_LABS=3
lab="$here/e2e-lab.sh"
export E2E_LAB_PID=$$
st() { "$lab" status >"$d/st"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[ "$($lab acquire)" = 0 ] || fail "first acquire is slot 0"
[ "$($lab acquire)" = 1 ] || fail "second acquire is slot 1"
[ "$($lab acquire)" = 2 ] || fail "third acquire is slot 2"
if out=$($lab acquire 2>/dev/null); then fail "fourth acquire must fail, got $out"; fi
st; grep -q '^lab 0: held by' "$d/st" || fail "status shows lab 0 held"
$lab release 0
st; grep -q '^lab 0: free' "$d/st" || fail "release frees lab 0"
[ "$($lab acquire)" = 0 ] || fail "released slot is reused"
if $lab release 3 2>/dev/null; then fail "release of an out-of-range slot must fail"; fi
if $lab release x 2>/dev/null; then fail "release of a non-number must fail"; fi

# A slot whose owner pid is gone is flagged STALE, a live one is not.
$lab release 1
$lab release 2
sleep 0 & dead=$!; wait "$dead"
[ "$(E2E_LAB_PID=$dead $lab acquire)" = 1 ] || fail "acquire with a pid"
st; grep -q '^lab 1: .*STALE' "$d/st" || fail "dead pid is flagged stale"
st; grep "^lab 0:" "$d/st" | grep -q STALE && fail "live slot flagged stale"
echo "e2e-lab-test: OK"
