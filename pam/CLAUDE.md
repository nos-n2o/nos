# nos-pam

`pam_nos.so`: a PAM module (cdylib, `libpam_nos.so`; #998 installs it as `pam_nos.so`) built on `nonstick`. Part of #987; #996 is this crate, #992 hands the ticket to `nos` (docs/ssh-access.md), #998 wires `/etc/pam.d/nos-sshd`, the image and the `pamtester` e2e phase.

## Layout

- `src/lib.rs`: `mod export` holds the only `#[allow(unsafe_code)]` (`pam_export!`); everything else is safe.
- `src/module.rs`: `NosPam` (`PamModule`), a thin adapter over the PAM-free `authenticate_user` / `check_account`, every hook wrapped by `guard` (a panic becomes `ServiceError`, never unwinds into sshd).
- `src/login.rs`: one `LoginTicket` round trip to the watchdog broker.
- `src/options.rs`, `src/session.rs`: module arguments; `NosTicket`.
- `edition = "2021"` in `Cargo.toml` on purpose: `pam_export!` emits a bare `#[no_mangle]`, an error in 2024.
- Building needs `libpam.so` (`libpam0g-dev` / `pam-devel`) for `-lpam`, not the headers. CI installs it for test/coverage/mutants and `tools/ci/Dockerfile` has it; the release `Dockerfile` builds `--bin`s only, so #998 adds it there when it builds this crate.

## Options

| Option | Meaning |
|--------|---------|
| `socket=` | broker socket, default `nos_proto::DEFAULT_WATCHDOG_SOCKET` |
| `ca=` | CA certificate PEM, default `nos_proto::DEFAULT_PKI_CA` (`/run/nos/pki/ca.crt`) |
| `use_first_pass` | take `PAM_AUTHTOK`, never prompt; missing = `AuthenticationError` |
| `try_first_pass` | accepted; `PAM_AUTHTOK` when set, else prompt (what `authtok` does) |

Unknown options are ignored with a syslog line naming the option (never its value).

## Return codes

| Case | Code |
|------|------|
| broker `Denied(INVALID_CREDENTIALS)` | `AuthenticationError` |
| empty or non-UTF-8 user or password (broker never contacted) | `AuthenticationError` |
| `LOGIN_BUSY`, "login unavailable", any other `Denied`, connect/TLS/EOF/timeout, unreadable `ca.crt`, unexpected event | `AuthInfoUnavailable` |
| name resolves (NSS) to a shell other than `/usr/bin/nos` or a uid outside 20000-59999 (broker never contacted, #1375) | `AuthenticationError` |
| NSS lookup error | `AuthInfoUnavailable` |
| `account_management` without a matching `NosTicket` | `AuthenticationError` (not `Ignore`: `account required` must not pass a flow that skipped `authenticate`) |
| `set_credentials` | `Ok` for every action |
| panic in any hook | `ServiceError` |

Fail closed: no cache, no retry, one 10 s deadline over dial + TLS handshake + request + reply.

## Rules

- **Never `nos_pki::install`/`nos_pki::connect`.** Their identity is a process-global `OnceLock`; sshd's monitor calls this module once per attempt for its whole life, and a watchdog restart re-keys the CA. Build `Identity::anonymous_from_pem(ca)` per call.
- **The ticket hand-off (#992)**: `authenticate` stores `NosTicket { user, encoded: Zeroizing<String> }` with `set_module_data(NosTicket::KEY, ..)` (for `account_management`) and inserts `NOS_LOGIN_TICKET` in the PAM environment right there. No `open_session`: sshd runs authenticate/acct_mgmt in a forked child and copies only that child's environment (see `docs/architecture/pam.md`); keep the ticket out of logs and `Debug`.
- Never log the password, broker text or error sources: syslog (nonstick `Logger`, authpriv) gets `user`, `service` and `outcome=success|denied|unavailable` only. No `tracing` subscriber is installed.
- No timing shortcut for unknown users: the watchdog's `verify_or_dummy` equalizes.
- A system account never reaches the broker: `account_guard` runs first in `authenticate_user` and `check_account`; shell and uid range come from `nos_proto` (`NOS_LOGIN_SHELL`, `NOS_UID_RANGE`), shared with `nos-configd`. `nix` (`user` feature) does the lookup, no `unsafe`.
- No shell-out (#228).
- Residual risks of a password crossing sshd's monitor: see #987.

## Tests

- `cargo test -p nos-pam` runs the logic against `nos_test_support::FakeLogin` (real mutual TLS, certificate-optional listener) with no real PAM stack. The `PamModule` adapters are covered end to end by #998's `pamtester` phase.
- Locally without the dev package: symlink `libpam.so.0` as `libpam.so` in a directory and export `LIBRARY_PATH` to it.
