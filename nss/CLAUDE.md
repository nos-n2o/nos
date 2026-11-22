# nos-nss

`libnss_nos.so.2`: glibc NSS `passwd` module (cdylib `libnss_nos.so`, rlib for tests) on the `libnss` crate. Part of #987, built by #999. Design and file format: [docs/architecture/pam.md](../docs/architecture/pam.md#account-mapping-nss).

## Layout

- `src/parse.rs`: pure parser for `name:uid:gid:dir:shell`; malformed lines skipped, first duplicate wins, never panics.
- `src/lib.rs`: `NosPasswd` (`PasswdHooks`) over the fixed `PASSWD_FILE`; `mod export` holds the only `#[allow(unsafe_code)]` (`libnss_passwd_hooks!`). Every lookup is `catch_unwind`-guarded (`Unavail`).
- `edition = "2021"` on purpose: the macro emits a bare `#[no_mangle]`, an error in 2024.

## Rules

- Read-only, no network, no secrets, no config: the path is a const (this runs inside sshd and every `ls`).
- A panic must never cross `extern "C"`; a too-small buffer is `ERANGE` (libnss turns it into TryAgain + errno).
- `nos-configd` (`config/src/nss_users.rs`) writes the file; this crate only reads it (local users plus the external AAA users, #1374; same format, this crate is unchanged).
- Install as `libnss_nos.so.2` (the Dockerfile does); `nm -D` must show `_nss_nos_getpwnam_r` etc.
