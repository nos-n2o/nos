#!/usr/bin/env bash
# Prune worktrees of merged work, their ~/.cache/nos-target-<issue>* dirs, and docker cache (#1051).
# Dry run unless APPLY=1. Only touches <main>/.claude/worktrees/* and $XDG_CACHE_HOME/nos-target-*.
set -euo pipefail
apply=${APPLY:-0}
cache=${XDG_CACHE_HOME:-$HOME/.cache}
main=$(cd "$(git rev-parse --git-common-dir)/.." && pwd)
root="$main/.claude/worktrees"
self=$(git rev-parse --show-toplevel)
run() { if [ "$apply" = 1 ]; then echo "+ $*"; "$@"; else echo "would: $*"; fi; }
echo "== df before"; df -h /
master=$(git -C "$main" rev-parse origin/master)
in_master() { git -C "$main" merge-base --is-ancestor "$1" "$master"; }

path= branch= head=
handle() {
  [ -n "$path" ] && [ -n "$branch" ] || return 0
  case "$path" in "$root"/*) ;; *) return 0 ;; esac   # never the main checkout or foreign paths
  [ "$path" != "$self" ] || { echo "keep $path: current worktree"; return 0; }
  local why=
  # a fresh branch sitting at the master tip has no work of its own: not "merged"
  if in_master "$head" && [ "$head" != "$master" ]; then why="in origin/master"; fi
  if [ -z "$why" ] && [ -n "$(gh pr list --head "$branch" --state merged --json number -q '.[].number')" ]; then why="PR merged"; fi
  [ -n "$why" ] || { echo "keep $path: not merged ($branch)"; return 0; }
  [ -z "$(gh pr list --head "$branch" --state open --json number -q '.[].number')" ] || { echo "keep $path: open PR"; return 0; }
  [ -z "$(git -C "$path" status --porcelain)" ] || { echo "keep $path: uncommitted changes"; return 0; }
  if ! in_master "$head" && [ "$(git -C "$main" rev-parse -q --verify "origin/$branch" || true)" != "$head" ]; then
    echo "keep $path: unpushed commits ($branch)"; return 0
  fi
  echo "prune $path ($branch: $why)"
  run git -C "$main" worktree remove -f -f "$path"
  local n d; n=$(printf '%s\n%s\n' "$branch" "${path##*/}" | grep -oE '[0-9]+' | head -1 || true)
  if [ -n "$n" ]; then
    for d in "$cache"/nos-target-"$n" "$cache"/nos-target-"$n"-*; do [ -d "$d" ] && run rm -rf "$d"; done
  fi
  return 0
}
while IFS= read -r line; do
  case "$line" in
    "worktree "*) handle; path=${line#worktree }; branch=; head= ;;
    "HEAD "*) head=${line#HEAD } ;;
    "branch refs/heads/"*) branch=${line#branch refs/heads/} ;;
  esac
done < <(git -C "$main" worktree list --porcelain; echo)
handle
run docker image prune -f
run docker buildx prune --keep-storage 100GB -f
echo "== df after"; df -h /
[ "$apply" = 1 ] || echo "(dry run: APPLY=1 to apply)"
