#!/usr/bin/env bash
# One soak result line (#884, #1050): e2e-result-line.sh <run> <exit-code> <secs> <log>
# prints `N PASS <secs>s` or `N FAIL <secs>s <phase> | <error>`. Shared by
# tools/ci/e2e-soak.sh and the verify-e2e.yml matrix.
set -u
i=$1 rc=$2 secs=$3 log=$4
if [ "$rc" = 0 ]; then
    echo "$i PASS ${secs}s"
    exit 0
fi
# The phase is the last "=== name ===" banner; the error is the harness's own
# "FAILED: ..." line (first line only, anyhow chains continue below it).
phase=$(grep -v 'docker logs' "$log" | sed -n 's/.*=== \(.*\) ===.*/\1/p' | tail -1)
err=$(sed -n 's/.*\] [^ ]*: FAILED: //p' "$log" | head -1 | cut -c1-200)
echo "$i FAIL ${secs}s $phase | $err"
