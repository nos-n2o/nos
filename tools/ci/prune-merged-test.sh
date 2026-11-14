#!/usr/bin/env bash
# Tests for prune-merged.sh with a temp repo, fake worktrees and stubbed gh/docker.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir "$d/bin"
# gh stub: PR state comes from $d/pr-<branch>.{merged,open}
cat > "$d/bin/gh" <<'S'
#!/usr/bin/env bash
b= st=
while [ $# -gt 0 ]; do case $1 in --head) b=$2; shift;; --state) st=$2; shift;; esac; shift; done
if [ -e "$STUB/pr-$b.$st" ]; then echo 1; fi
S
printf '#!/usr/bin/env bash\necho "docker $*" >> "$STUB/docker.log"\n' > "$d/bin/docker"
chmod +x "$d/bin/gh" "$d/bin/docker"
export STUB=$d PATH="$d/bin:$PATH" XDG_CACHE_HOME=$d/cache
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
git init -q --bare "$d/origin.git"
git init -q -b master "$d/repo"; cd "$d/repo"
git remote add origin "$d/origin.git"
git commit -q --allow-empty -m base
mkdir -p .claude/worktrees
wt() { git worktree add -q -b "$1" ".claude/worktrees/$1" master; git -C ".claude/worktrees/$1" commit -q --allow-empty -m "$1"; }
wt issue-1-merged; wt issue-2-dirty; wt issue-3-open; wt issue-4-unpushed; wt issue-5-ghmerged
git merge -q --no-ff issue-1-merged -m m1
git merge -q --no-ff issue-2-dirty -m m2
git push -q origin master; git fetch -q origin
echo x > .claude/worktrees/issue-2-dirty/f   # merged but uncommitted work
touch "$d/pr-issue-3-open.open" "$d/pr-issue-3-open.merged" "$d/pr-issue-5-ghmerged.merged"
git push -q origin issue-5-ghmerged
for n in 1 1-x 10 5; do mkdir -p "$XDG_CACHE_HOME/nos-target-$n"; done
fail() { echo "FAIL: $*"; exit 1; }

"$here/prune-merged.sh" > "$d/dry.txt" 2>&1 || { cat "$d/dry.txt"; fail "dry run"; }
[ -d .claude/worktrees/issue-1-merged ] || fail "dry run removed"
[ ! -e "$d/docker.log" ] || fail "dry run called docker"
grep -q "would: git .* worktree remove -f -f .*issue-1-merged" "$d/dry.txt" || fail "dry output"

APPLY=1 "$here/prune-merged.sh" > "$d/out.txt" 2>&1 || { cat "$d/out.txt"; fail apply; }
[ ! -d .claude/worktrees/issue-1-merged ] || fail "merged kept"
[ ! -d .claude/worktrees/issue-5-ghmerged ] || fail "gh-merged kept"
[ -d .claude/worktrees/issue-2-dirty ] || fail "dirty removed"
[ -d .claude/worktrees/issue-3-open ] || fail "open-PR removed"
[ -d .claude/worktrees/issue-4-unpushed ] || fail "unmerged removed"
[ -d .git ] || fail "main gone"
[ ! -d "$XDG_CACHE_HOME/nos-target-1" ] && [ ! -d "$XDG_CACHE_HOME/nos-target-1-x" ] || fail "cache 1 kept"
[ ! -d "$XDG_CACHE_HOME/nos-target-5" ] || fail "cache 5 kept"
[ -d "$XDG_CACHE_HOME/nos-target-10" ] || fail "cache 10 (other issue) removed"
grep -q "image prune -f" "$d/docker.log" && grep -q "buildx prune --keep-storage 100GB -f" "$d/docker.log" || fail docker
echo ok
