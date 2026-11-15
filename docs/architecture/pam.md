# PAM and account mapping

- `pam_nos.so` (crate `nos-pam`, see `pam/CLAUDE.md`) checks a password against `nos-watchdogd`'s login broker; `/etc/pam.d/nos-sshd` wires it as `auth` and `account`.
- sshd with `UsePAM` also needs the user to exist for `getpwnam`: that is the NSS module below. Login itself is still decided only by the watchdog against the config.

## Account mapping (NSS)

- `nos-configd` writes `/run/nos-users/passwd`, one `name:uid:gid:/nonexistent:/usr/bin/nos` line per user, sorted by uid, gid = uid. Names only, never a password or hash.
- `libnss_nos.so.2` (crate `nos-nss`, `nss/CLAUDE.md`) serves it as glibc's `passwd` database; the image sets `passwd: files nos` in `/etc/nsswitch.conf`. There is no `group` database: no group lookups are needed for a PAM login.
- Uids are 20000-59999 (the roles use 10001-10014, `nos-wd` 990). They come from a persisted map `--user-ids-file` (default `/var/lib/nos/configd/user-ids`, 0600, `name:uid`): a name always keeps its uid, also after deletion and re-creation, and a uid is never given to another name.
- A missing map is a fresh start. A corrupt or out-of-range map is not regenerated (it would reuse uids): `nos-configd` logs an error and leaves the passwd file untouched. At 59999 the next user gets no entry (logged).
- Only names matching `^[a-z_][a-z0-9_-]{0,31}$` get an entry; wider names (PRECIS allows Unicode and upper case) are skipped with a warning and cannot use ssh.
- The file is rewritten, atomically (temp file + rename, 0644), at startup and on every commit that changes the set of user names (a password change does not), under the `running` lock so writes never reorder. The uid map is persisted first. A write failure is logged and never fails the commit.
- `/run/nos-users` must be writable although the image is read-only: a tmpfs in `docker-compose.yml` and `nos-e2e`. `nos-watchdogd --users-dir` creates it 0755 owned by the configd role at startup (privileged mode). Without it (non-docker run) configd logs a warning and carries on.
- `/run/nos-sshd` (`nos-sshd`'s `sshd_config`, #995) is likewise a tmpfs in `docker-compose.yml` and `nos-e2e`; `nos-sshd` runs as root and creates it itself.
- `libnss_nos` is read-only, no network; a missing or unreadable file is `UNAVAIL`, an unknown name `NOTFOUND`, a panic is caught (`UNAVAIL`), and a buffer too small is reported as `ERANGE`. It allocates inside the `libnss` crate, not only in the caller's buffer.
- License: `libnss` is LGPL-3.0, linked as a library into a cdylib; `deny.toml` allows it.
- Verified by the `pam` e2e phase: a created user resolves with `getent`, authenticates, a deleted one disappears, a re-created one keeps its uid.
