#!/usr/bin/env bash
# The nos-e2e lab slot pool (#1049): tools/ci/e2e-lab.sh acquire | release <k> | status
#   acquire    take the first free slot k in 0..NOS_E2E_LABS-1 (default 3), print k, exit 0;
#              exit 1 (nothing printed) when all are held
#   release k  free slot k
#   status     list every slot: free, or its owner (worktree, pid, age); a slot whose
#              pid is gone is flagged STALE
# Then run every nos-e2e command with NOS_E2E_LAB=<k> (and NOS_E2E_IMAGE=...) and release
# when done. A slot is the directory /tmp/nos-e2e.lock.<k> (mkdir is atomic); the lab lock
# spans several `cargo run -p nos-e2e` invocations, so it stays a convention, not harness code.
# The recorded pid is $E2E_LAB_PID, else the caller's pid ($PPID): a long-lived caller
# (e2e-soak.sh) is flagged STALE correctly; an agent whose shell exits between tool calls is
# flagged too, so STALE is advisory: check `docker ps` for l<k>- containers, then release.
set -eu

PREFIX=${NOS_E2E_LOCK_PREFIX:-/tmp/nos-e2e.lock}
LABS=${NOS_E2E_LABS:-3}

usage() {
    echo "usage: e2e-lab.sh acquire | release <k> | status" >&2
    exit 2
}

valid() {
    case $1 in '' | *[!0-9]*) return 1 ;; esac
    [ "$1" -lt "$LABS" ]
}

owner() { # field of slot $1's owner file
    sed -n "s/^$2=//p" "$PREFIX.$1/owner" 2>/dev/null | head -1
}

cmd=${1:-}
case $cmd in
acquire)
    pid=${E2E_LAB_PID:-$PPID}
    wt=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
    k=0
    while [ "$k" -lt "$LABS" ]; do
        if mkdir "$PREFIX.$k" 2>/dev/null; then
            printf 'pid=%s\nworktree=%s\nstarted=%s\n' "$pid" "$wt" "$(date +%s)" >"$PREFIX.$k/owner"
            echo "$k"
            exit 0
        fi
        k=$((k + 1))
    done
    echo "e2e-lab: all $LABS slots are held (see: tools/ci/e2e-lab.sh status)" >&2
    exit 1
    ;;
release)
    valid "${2:-}" || usage
    rm -rf "${PREFIX:?}.$2"
    ;;
status)
    k=0
    while [ "$k" -lt "$LABS" ]; do
        if [ -d "$PREFIX.$k" ]; then
            pid=$(owner "$k" pid)
            started=$(owner "$k" started)
            stale=
            if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then stale=" STALE (pid gone)"; fi
            age=
            if [ -n "$started" ]; then age=" $(($(date +%s) - started))s"; fi
            echo "lab $k: held by $(owner "$k" worktree) pid ${pid:-?}${age}${stale}"
        else
            echo "lab $k: free"
        fi
        k=$((k + 1))
    done
    ;;
*) usage ;;
esac
