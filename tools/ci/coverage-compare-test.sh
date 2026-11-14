#!/usr/bin/env bash
# Tests for coverage-compare.sh: equal, drop, rise, within tolerance, missing baseline.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
cd "$d"
unset GITHUB_STEP_SUMMARY
mk() { printf 'SF:a\nLF:%s\nLH:%s\nend_of_record\nSF:b\nLF:%s\nLH:%s\nend_of_record\n' "$1" "$2" "$3" "$4" > "$5"; }
mk 100 90 100 90 equal.info
mk 100 80 100 80 drop.info   # 80.00
mk 100 95 100 95 rise.info   # 95.00
mk 10000 9000 10000 8999 tiny.info # 89.995: 0.005 pt below, within tolerance
run() { COVERAGE_TOTAL_OUT=out.txt "$here/coverage-compare.sh" "$@" >log.txt 2>&1; }
fail() { echo "FAIL: $*"; cat log.txt; exit 1; }
echo 90.00 > baseline.txt

run equal.info baseline.txt || fail equal
run rise.info baseline.txt || fail rise
run tiny.info baseline.txt || fail tiny
run drop.info baseline.txt && fail "drop must fail"
grep -q '90.00%.*80.00%' log.txt || fail "drop must print both numbers"
[ "$(cat out.txt)" = 80.00 ] || fail "total file"
run drop.info missing.txt || fail "missing baseline must pass"
grep -q 'comparison skipped' log.txt || fail "missing baseline notice"
run drop.info || fail "no baseline arg must pass"
echo ok
