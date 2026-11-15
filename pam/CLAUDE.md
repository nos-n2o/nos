# nos-pam

`pam_nos.so`: a PAM module (cdylib, `libpam_nos.so`; #998 installs it as `pam_nos.so`) built on `nonstick`. Part of #987; #996 is this crate, #989 consumes `NosSession`, #998 wires `/etc/pam.d/nos-sshd`, the image and the `pamtester` e2e phase.

## Layout

- `src/lib.rs`: `mod export` holds the only `#[allow(unsafe_code)]` (`pam_export!`); everything else is safe.
- `src/module.rs`: `NosPam` (`PamModule`), a thin adapter over the PAM-free `authenticate_user` / `check_account`, every hook wrapped by `guard` (a panic becomes `ServiceError`, never unwinds into sshd).
- `src/login.rs`: one `Login` round trip to the watchdog broker.
- `src/options.rs`, `src/session.rs`: module arguments; `NosSession`.
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
| `account_management` without a matching `NosSession` | `AuthenticationError` (not `Ignore`: `account required` must not pass a flow that skipped `authenticate`) |
| `set_credentials` | `Ok` for every action (ticket hand-off is #989) |
| panic in any hook | `ServiceError` |

Fail closed: no cache, no retry, one 10 s deadline over dial + TLS handshake + request + reply.

## Rules

- **Never `nos_pki::install`/`nos_pki::connect`.** Their identity is a process-global `OnceLock`; sshd's monitor calls this module once per attempt for its whole life, and a watchdog restart re-keys the CA. Build `Identity::anonymous_from_pem(ca)` per call.
- **`NosSession` is the #989 contract**: stored with `set_module_data(NosSession::KEY = "nos_pam_session", ..)`, `pub` fields `user`, `cert_der`, `key` (`Zeroizing`), `lifetime`. Dropped with the PAM handle, overwritten (and zeroized) by a second `authenticate`. Its `Debug` prints only the user.
- Never log the password, broker text or error sources: syslog (nonstick `Logger`, authpriv) gets `user`, `service` and `outcome=success|denied|unavailable` only. No `tracing` subscriber is installed.
- No timing shortcut for unknown users: the watchdog's `verify_or_dummy` equalizes.
- No shell-out (#228).
- Residual risks of a password crossing sshd's monitor: see #987.

## Tests

- `cargo test -p nos-pam` runs the logic against `nos_test_support::FakeLogin` (real mutual TLS, certificate-optional listener) with no real PAM stack. The `PamModule` adapters are covered end to end by #998's `pamtester` phase.
- Locally without the dev package: symlink `libpam.so.0` as `libpam.so` in a directory and export `LIBRARY_PATH` to it.
