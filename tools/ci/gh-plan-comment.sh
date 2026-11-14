#!/usr/bin/env bash
# Post or update the `## Implementation plan (Claude review)` (or `## Already fixed on master (Claude review)`) comment of an issue (#1046).
# Usage: tools/ci/gh-plan-comment.sh <issue> <file>
# Finds the comment by its heading and PATCHes it by id, else posts a new one (never `--edit-last`:
# the owner shares the account). Verifies the posted body; retries gh on 403/5xx.
set -euo pipefail
issue=${1:?usage: gh-plan-comment.sh <issue> <file>}
file=${2:?usage: gh-plan-comment.sh <issue> <file>}
repo=${NOS_REPO:-nos-n2o/nos}
heading='## Implementation plan (Claude review)'
# #1047: a stale-issue report uses its own heading (same find-by-heading PATCH/POST logic).
stale='## Already fixed on master (Claude review)'
[[ -s "$file" ]] || { echo "$file: missing or empty" >&2; exit 1; }
first=$(head -n1 "$file")
if [[ "$first" == "$stale"* ]]; then heading=$stale; fi
[[ "$first" == "$heading"* ]] || { echo "$file: first line must be '$heading' or '$stale'" >&2; exit 1; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gh-plan-comment-$issue.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# gh with 3 tries; 20/40/80 s backoff (scaled by RETRY_SCALE, tests set 0) on 403 or 5xx only.
gh_retry() {
  local n=0 delay=20 out
  while :; do
    if out=$(gh "$@" 2>"$tmp/err"); then printf '%s' "$out"; return 0; fi
    if ((++n >= 3)) || ! grep -qE '403|HTTP 5[0-9][0-9]' "$tmp/err"; then cat "$tmp/err" >&2; return 1; fi
    echo "gh $1: retry $n after ${delay}s: $(head -c 200 "$tmp/err")" >&2
    sleep "$(awk -v d="$delay" -v s="${RETRY_SCALE:-1}" 'BEGIN{print d*s}')"
    delay=$((delay * 2))
  done
}

jq -Rs '{body: .}' "$file" >"$tmp/body.json"
id=$(gh_retry api --paginate "repos/$repo/issues/$issue/comments" |
  jq -s --arg h "$heading" 'add // [] | map(select(.body | startswith($h))) | last | .id // empty')
if [[ -n "$id" ]]; then
  gh_retry api -X PATCH "repos/$repo/issues/comments/$id" --input "$tmp/body.json" >/dev/null
else
  id=$(gh_retry api -X POST "repos/$repo/issues/$issue/comments" --input "$tmp/body.json" | jq -r .id)
fi
got=$(gh_retry api "repos/$repo/issues/comments/$id" --jq .body)
[[ "$got" == "$(cat "$file")" ]] || { echo "comment $id: posted body differs from $file" >&2; exit 1; }
echo "https://github.com/$repo/issues/$issue#issuecomment-$id"
