# PAM and account mapping

- `pam_nos.so` (crate `nos-pam`, see `pam/CLAUDE.md`) checks a password against `nos-watchdogd`'s login broker; `/etc/pam.d/nos-sshd` wires it as `auth` and `account`.
- Operator view of the whole flow: [ssh-access.md](../ssh-access.md).

## Ticket hand-off (#992)

- `authenticate` sends `WatchdogRequest::LoginTicket` (the one password check) and keeps the encoded ticket as module data for `account` (`NosTicket`, zeroized, `Debug` shows only the user). It never makes a key or CSR.
- It also puts `NOS_LOGIN_TICKET=<nos_proto::ticket_to_env>` in the PAM environment. Why there and not in `open_session`: with `KbdInteractiveAuthentication` sshd runs `authenticate` and `acct_mgmt` in a forked child and copies that child's `pam_getenvlist()` to the session; the monitor's handle that later runs `open_session` never saw the module data. So the stack has no `session` line.
- The login shell is `nos` (NSS shell `/usr/bin/nos`, symlink to `/usr/local/bin/nos`, listed in `/etc/shells`); it redeems the ticket (60 s, single use) for a certificate on its own key.
- `nos` is setgid `nos`: a NOS user's uid is outside the group that alone reaches `/run/nos` (CA, sockets). Side effect: the process is non-dumpable, so even its owner cannot read `/proc/<pid>/environ`, where the ticket sits until the process ends.
- sshd with `UsePAM` also needs the user to exist for `getpwnam`: that is the NSS module below. Login itself is still decided only by the watchdog against the config.

## Account mapping (NSS)

- `nos-configd` writes `/run/nos-users/passwd`, one `name:uid:gid:/nonexistent:/usr/bin/nos` line per user, sorted by uid, gid = uid. Names only, never a password or hash.
- `libnss_nos.so.2` (crate `nos-nss`, `nss/CLAUDE.md`) serves it as glibc's `passwd` database; the image sets `passwd: files nos` in `/etc/nsswitch.conf`. There is no `group` database: no group lookups are needed for a PAM login.
- Uids are 20000-59999 (the roles use 10001-10014, `nos-wd` 990). They come from a persisted map `--user-ids-file` (default `/var/lib/nos/configd/user-ids`, 0600, `name:uid`): a name always keeps its uid, also after deletion and re-creation, and a uid is never given to another name.
- A missing map is a fresh start. A corrupt or out-of-range map is not regenerated (it would reuse uids): `nos-configd` logs an error and leaves the passwd file untouched. At 59999 the next user gets no entry (logged).
- Only names matching `^[a-z_][a-z0-9_-]{0,31}$` get an entry; wider names (PRECIS allows Unicode and upper case) are skipped with a warning and cannot use ssh.
- The file is rewritten, atomically (temp file + rename, 0644), at startup and on every commit that changes the set of user names (a password change does not), under the `running` lock so writes never reorder. The uid map is persisted first. A write failure is logged and never fails the commit.
- External users (#1374, part of #1359): names authenticated by a RADIUS (later TACACS+) server have no config entry. `Request::AllocateExternalUser { name }` (`Role::Watchdog` only; replies `Event::ExternalUser { uid }`) adds the name to a persisted set `aaa-users` next to the uid map (names only, 0600, atomic) and rewrites the passwd file with local users plus that set. Nothing calls it yet (the broker does in #1376); the admin commands `allocate aaa user <name>`, `clear aaa user <name>` and `show aaa users` (`AdminAllocateExternalUser`/`ClearExternalUser`/`ListExternalUsers`, admin role) are the manual path.
  - Same uid map and range as local users: one allocator, monotone, a uid never given to another name. `clear` drops the entry; the uid stays reserved, and re-allocating the name returns it.
  - Refused (error reply, warn log): unsafe name, `nos-` prefix, a local user name, a name already in `/etc/passwd`, a uid or gid already in `/etc/passwd` or `/etc/group` (those files are parsed directly, never through NSS; a clashing uid is skipped, never handed out), more than 10000 external names, range exhausted. Idempotent for an existing name.
  - Every rewrite re-checks `/etc/passwd`/`/etc/group` and skips (error log) a name or uid that has appeared there since. `/etc` unreadable: nothing is written. A local user created later with an external name keeps the uid and one line is written (the config role governs).
  - A corrupt `aaa-users` (unsafe or duplicate name, or a name without a uid in the map) is not regenerated: configd leaves the passwd file untouched, like a corrupt map.
  - Why ssh cannot allocate by itself: see the spike in [ssh.md](ssh.md): for an unknown name `pam_nos` gets the real name but an empty password.
- `/run/nos-users` must be writable although the image is read-only: a tmpfs in `docker-compose.yml` and `nos-e2e`. `nos-watchdogd --users-dir` creates it 0755 owned by the configd role at startup (privileged mode). Without it (non-docker run) configd logs a warning and carries on.
- `/run/nos-sshd` (`nos-sshd`'s `sshd_config`, #995) is likewise a tmpfs in `docker-compose.yml` and `nos-e2e`; `nos-sshd` runs as root and creates it itself.
- `libnss_nos` is read-only, no network; a missing or unreadable file is `UNAVAIL`, an unknown name `NOTFOUND`, a panic is caught (`UNAVAIL`), and a buffer too small is reported as `ERANGE`. It allocates inside the `libnss` crate, not only in the caller's buffer.
- License: `libnss` is LGPL-3.0, linked as a library into a cdylib; `deny.toml` allows it.
- Verified by the `pam` e2e phase: a created user resolves with `getent`, authenticates, a deleted one disappears, a re-created one keeps its uid.
