# nos-sandbox

`nos-sandbox-exec --profile <role> -- <program> [args...]`: the exec trampoline the watchdog puts between the uid switch and every daemon but `nos-sshd` (#1211, part of #1186). Depends on `libc` and `seccompiler`.

## Step order (`src/main.rs`)

1. `check_target`: canonical path, regular file, directly in `/usr/local/bin` (`TARGET_DIR`).
2. `read_file_caps`: `security.capability` xattr (`ENODATA`/`ENOTSUP` = empty), parsed by `parse_vfs_cap` (v1/v2/v3, v3 only with `rootid` 0).
3. `set_caps(target.permitted)`: permitted and effective cut to the target's set, inheritable emptied.
4. `clear_ambient`, `no_new_privs`.
5. `seccomp::deny_list` then `seccomp::install` (#1217): `seccompiler` deny-list (allow by default, `KILL_PROCESS` on listed syscalls, x32 guard on x86_64), after `no_new_privs`. List and rationale: `docs/architecture/ipc-security.md`.
6. `execv`: no fork, the pid stays the daemon's.

Any error: `nos-sandbox-exec: <reason>` on stderr, exit 126. Never exec unsandboxed.

## Invariant

- Under `NO_NEW_PRIVS` the exec'd file's permitted set is clipped to the caller's. The trampoline's own file capabilities (`Dockerfile`: the union of every daemon's) are the ceiling; step 3 trims to the target, so the daemon gets exactly what a direct exec gives it and never more.
- Keep the trampoline's `setcap` line equal to the union of the daemon lines.
- A root-run daemon would lose root's implicit capabilities under the clip rule: exempt it (as `nos-sshd` is, in `ProcessSpec::with_sandbox`) or give it xattr capabilities.
- No `--allow-dir` test flag: it would be a bypass. The success path is proven by the e2e phase `sandbox-nnp`.

## Layout

- `src/lib.rs`: pure, unit-tested (xattr parser, target check, argument parser).
- `src/sys.rs`: the only `unsafe` (getxattr, capget/capset, prctl, execv). Counted by coverage: its tests lower this test process's own capabilities and set its `NO_NEW_PRIVS`, hence one test for the irrevocable steps.
- `src/seccomp.rs`: the deny-list table `DENIED` (add a syscall there), pure builder + `install`.
- `tests/seccomp.rs`: forks a child, applies the filter, expects `SIGSYS` on `ptrace`.
- `tests/trampoline.rs`: runs the built binary (a target outside the directory exits 126).
