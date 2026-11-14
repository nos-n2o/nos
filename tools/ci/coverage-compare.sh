#!/usr/bin/env bash
# Line-coverage total from an lcov file, optionally compared to a stored baseline (#1043).
#   coverage-compare.sh <lcov.info> [<baseline-file>]
# Writes the total (percent, 2 decimals) to $COVERAGE_TOTAL_OUT (default coverage-total.txt)
# and to $GITHUB_STEP_SUMMARY. With a baseline file holding one number, exits 1 when the
# total dropped by more than $COVERAGE_TOLERANCE points (default 0.05), printing both.
# A missing/empty baseline file is a notice, not a failure (first run, expired artifact).
set -euo pipefail
lcov=${1:?usage: coverage-compare.sh <lcov.info> [<baseline-file>]}
base=${2:-}
tol=${COVERAGE_TOLERANCE:-0.05}
out=${COVERAGE_TOTAL_OUT:-coverage-total.txt}

total=$(awk -F: '/^LH:/{h+=$2} /^LF:/{f+=$2} END{if(f==0){exit 1} printf "%.2f", 100*h/f}' "$lcov") \
  || { echo "::error::no LF/LH lines in $lcov"; exit 1; }
echo "$total" > "$out"

say() { echo "$*"; [ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "$*" >> "$GITHUB_STEP_SUMMARY"; }
say "Line coverage total: ${total}%"

if [ -z "$base" ] || [ ! -s "$base" ]; then
  echo "::notice::no master coverage baseline available; comparison skipped"
  exit 0
fi
old=$(tr -d '[:space:]' < "$base")
say "Master baseline: ${old}% (PR: ${total}%, tolerance ${tol} pt)"
if awk -v n="$total" -v o="$old" -v t="$tol" 'BEGIN{exit !(o-n>t)}'; then
  echo "::error::coverage dropped from ${old}% to ${total}% (more than ${tol} pt)"
  exit 1
fi
