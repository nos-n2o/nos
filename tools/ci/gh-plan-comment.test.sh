#!/usr/bin/env bash
# Tests gh-plan-comment.sh against a stubbed `gh` (#1046). Run: tools/ci/gh-plan-comment.test.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir "$t/bin"
# Stub: $T/list = comment list JSON, $T/fail = n -> next n writes fail with 403,
# STUB_CORRUPT=1 -> GET returns another body. Calls are logged to $T/log, last written body to $T/body.
cat >"$t/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$T/log"
case "$*" in
  *"-X PATCH"*|*"-X POST"*)
    if [[ $(cat "$T/fail") -gt 0 ]]; then
      echo $(($(cat "$T/fail") - 1)) >"$T/fail"; echo "gh: HTTP 403" >&2; exit 1
    fi
    jq -r .body "${@: -1}" >"$T/body"
    echo '{"id":99}' ;;
  *"--paginate"*) cat "$T/list" ;;
  *"--jq .body"*) if [[ -n "${STUB_CORRUPT:-}" ]]; then echo other; else cat "$T/body"; fi ;;
esac
STUB
chmod +x "$t/bin/gh"
printf '## Implementation plan (Claude review)\n\nbody "quoted"\n' >"$t/plan.md"
run() { T=$t PATH="$t/bin:$PATH" RETRY_SCALE=0 "$here/gh-plan-comment.sh" 7 "$t/plan.md" 2>"$t/err"; }
reset() { : >"$t/log"; echo "${1:-0}" >"$t/fail"; echo "${2:-[]}" >"$t/list"; }
has() { grep -q -- "$1" "$t/log"; }
fail() { echo "FAIL: $1"; cat "$t/err" "$t/log"; exit 1; }

reset 0 '[{"id":5,"body":"hi"},{"id":42,"body":"## Implementation plan (Claude review)\nold"}]'
run >/dev/null || fail "heading found"
has '-X PATCH .*comments/42' || fail "expected PATCH of 42"
has '-X POST' && fail "unexpected POST"

reset 0 '[{"id":5,"body":"hi"}]'
run >/dev/null || fail "not found"
has '-X POST .*issues/7/comments' || fail "expected POST"

reset 2
run >/dev/null || fail "403 then success"
[[ $(grep -c -- '-X POST' "$t/log") -eq 3 ]] || fail "expected 3 POST tries"

reset 3
run >/dev/null && fail "3x 403 should fail"

reset 0
STUB_CORRUPT=1 run >/dev/null && fail "verify mismatch should fail"
grep -q differs "$t/err" || fail "mismatch message"
printf '## Already fixed on master (Claude review)\n\nabc123\n' >"$t/plan.md"
reset 0 '[{"id":42,"body":"## Implementation plan (Claude review)\nold"},{"id":43,"body":"## Already fixed on master (Claude review)\nold"}]'
run >/dev/null || fail "stale heading"
has '-X PATCH .*comments/43' || fail "expected PATCH of 43 (stale heading)"
printf 'nope\n' >"$t/plan.md"
run >/dev/null && fail "bad heading should fail"
echo ok
