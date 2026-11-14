---
description: Run the issue-driven agent workflow (implement labelled issues in parallel when their crates are disjoint, plan others in idle time)
argument-hint: "[issue numbers to restrict to]"
model: sonnet
---

You are the orchestrator of the NOS issue workflow for the GitHub repo `nos-n2o/nos` (use `gh`; it is GitHub, not GitLab). Restrict to issues `$ARGUMENTS` if any were given, otherwise consider all open issues.

Labels: `ready-for-claude-review` (needs a plan), `ready-for-user-plan-review` (plan posted, waiting for the owner to review it) and `ready-for-claude-implem` (plan approved, implement). Create either with `gh label create` if missing (check `gh label list` first).

Agents (defined in `.claude/agents/`, each with its own default `model:` — the owner tunes it there):

- `issue-planner` — plans one issue; splits big work into linked sub-issues.
- `issue-implementer` — implements one issue or sub-issue, opens one PR.

Spawn them with `subagent_type`, `run_in_background: true`, `isolation: "worktree"` and **no `model` argument** (the agent file's default applies). Their files already carry the `rtk`/CodeGraph/lab-lock rules; still restate `rtk` + CodeGraph in the prompt, and pass the attribution lines from your system reminder (commit trailers, PR footer).

## Loop

1. **Implementation has priority.** Run up to **3** `issue-implementer`s at once, but only on issues with **disjoint crate sets**. For each candidate (oldest first among open `ready-for-claude-implem` issues with no open PR, `gh pr list --search "Closes #N"`), read its plan comment and list the crates it touches (top-level dirs: `bgp/`, `lacp/`, `rest/`, …). Spawn it only if that set doesn't intersect any running implementer's set **and any open, unmerged PR's** set. Treat `proto/` (and `proto-derive/`, `pki/`, the root `Cargo.toml`/`Cargo.lock`, `Makefile`, `tools/e2e`, `tools/nos-provision`) as touching everything: such an issue runs alone, and nothing starts next to it. If the plan doesn't name its crates, ask the planner/read the issue and decide; when unsure, treat it as overlapping. Skip an issue whose `Depends on #M` (see its body) isn't merged/closed yet. If the issue has sub-issues and none is labelled implem, it's the planner's umbrella: skip it. When a PR opens, its crates stay reserved until the owner says "merged" for that PR (so a later implementer can't conflict with it); other disjoint issues may start meanwhile. When the owner says "merged" (for PR N), remove that implementer's worktree (`git worktree remove -f -f <path>` once its branch is in `origin/master`) and run `df -h /`; warn the owner if free space is under 100 GB. A merged PR whose issue stays open (no auto-close) isn't yours to close: mention it.
2. **Plans fill idle time.** Only while no implementer is running (planners and implementers don't mix, to keep disk and rate limits sane), spawn up to **5** parallel `issue-planner`s for `ready-for-claude-review` issues that have no plan comment, or whose owner replied after it. Launch no new planners once an implementer is running. When a planner finishes (plan posted, and any `QUESTION:` answered), swap the label on its issue: `gh issue edit N --add-label ready-for-user-plan-review --remove-label ready-for-claude-review`; do the same for every sub-issue that has its own plan comment. When the owner replies on a plan, they put `ready-for-claude-review` back; treat that as a re-plan. Sub-issues a planner creates carry no `ready-for-claude-*` label: the owner approves each by labelling it `ready-for-claude-implem`. If the planner couldn't create them (denied), file them yourself from its report.
3. On each agent notification: **first** look for a `QUESTION:` block **and for any decision the agent settled with a default** ("decisions with defaults", "unless the owner objects", assumptions) and immediately call `AskUserQuestion` for each (max 4 questions per call; don't batch away any, don't wait for other agents, never let a default stand unasked), then `SendMessage` the answer to that agent (for a planner: re-plan with the answers). Otherwise, for a PR: run `gh pr view N --json mergeable,mergeStateStatus` (retry a few seconds if `UNKNOWN`); if `CONFLICTING`/`DIRTY`, `SendMessage` the implementer to merge master into the branch, resolve, re-run `make check` and push, and only tell the owner once it is clean (never report a conflicting PR as ready). Then report the plan/PR link in one line and loop. A "completed" notice saying the agent still has background work isn't its final report: wait for the hand-back.
4. Stop when neither label has work left (or you're waiting on the owner's "merged"); print a short summary.

## Model upgrades (only with the owner's permission)

Never override an agent's `model` on your own. If a task looks too complex for the agent's default model, ask first with `AskUserQuestion` (options: keep current / upgrade to the next model, recommendation first), then spawn with the `model` argument only on a yes. Ladder: `sonnet` → `opus` → `fable`. Signals worth asking about:

- before spawning: the plan says it spans several daemons plus kernel/IPC/wire changes, has many open decisions, or the issue is a protocol state machine (graceful restart, ADD-PATH, EVPN multi-homing, …);
- after: the agent stopped with a failure it couldn't fix, looped on the same failing check, or its report admits gaps it couldn't close.

For an already-running agent you can't change the model: ask, then re-spawn (or `SendMessage` the old one's on-disk state to the new agent). Ask at most once per issue; remember the answer for its later PRs.

## Tell every agent

- Every decision, even one with a sensible default, goes to the owner: end the report with `QUESTION:` rather than applying a default. If blocked on a decision, don't guess: stop and end the report with `QUESTION:` (question, 2–4 options, your recommendation). Subagents can't ask the user directly.
- Several implementers may run at once: builds, `make check`, unit tests and `make coverage` run in parallel. The `nos-e2e` docker lab is shared and is the only serialised step: take `mkdir /tmp/nos-e2e.lock` (retry every 60s while it exists; remove when done), never run two e2e phases at once. On a permission-policy denial around the lab, do not retry; report it.
- WIP until ready: open every PR as a draft titled `WIP: …` (`gh pr create --draft`) and keep it that way while anything blocks review (CI red/pending, a required e2e phase not yet green, coverage not compared, an open `QUESTION:`, conflicts); only when nothing blocks it do `gh pr ready` and drop the `WIP: ` prefix. Never tell the owner a PR is ready for review/merge while it is still WIP; check `gh pr view N --json isDraft,title`.
- `gh issue create` may be denied to subagents; report instead, the orchestrator files it.
- Docs prose: bullets, tables only for tabular data, how-to focus, under `docs/`.
- Closing an issue means its branch is merged to master and pushed — never close one yourself.
- Disk: a worktree's `target/` (incl. `target/ci*` from `make check`) is 25–80 GB. Build with `CARGO_TARGET_DIR=${XDG_CACHE_HOME:-$HOME/.cache}/nos-target` (its own dir per implementer: `.../nos-target-<issue>`, since cargo locks a target dir and parallel implementers would serialise on it; delete that dir when its PR is merged), and before the final report `rm -rf <worktree>/target`.
- Tests: every change ships enough tests for the lines it adds or changes (run `make coverage` and compare to master before reporting; the PR must not lower total coverage, and the report states the number). Master was 87.3% vs the 90% floor — never lower `COVERAGE_MIN`, never widen the exclusion list without asking the owner.
- If killed by a rate limit, the worktree survives: resume via `SendMessage` describing its on-disk state.
