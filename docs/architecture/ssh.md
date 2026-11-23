# nos-sshd

`nos-sshd` is the SSH server of a routing table (`set routing-table <t> ssh-server address <ip> port <n>`). Details for contributors are in [`ssh/CLAUDE.md`](../../ssh/CLAUDE.md).

- Stock OpenSSH cannot bind inside a VRF, so `nos-sshd` owns the listener (`SO_BINDTODEVICE`) and runs `sshd -i -e` once per connection.
- Login is PAM only: the rendered config sets `PAMServiceName nos-sshd`, so `/etc/pam.d/nos-sshd` calls `pam_nos.so`, which asks `nos-watchdogd` ([pam.md](pam.md)). No public keys, no root login, no forwarding.
- OpenSSH comes from the distro: the runtime image is `debian:trixie-slim` (OpenSSH 10.0p2, `openssh-server` package). Bookworm's 9.2 has no `PAMServiceName` (`sshd -T` rejects it), hence the base bump; the builder is `rust:<channel>-slim-trixie`, so build and runtime glibc match.
- Runs as root with a reduced capability set (SETUID, SETGID, SYS_CHROOT, CHOWN, NET_RAW, NET_BIND_SERVICE, AUDIT_WRITE, KILL). Root is inherent (#1187): OpenSSH 10.0p2 switches to the logging-in user only when `getuid()==0` (a spike on #1187 with CAP_SETUID/SETGID ambient on a non-root uid: pubkey auth under the user's uid is a no-op and the session dies with `Failed to set uids`), so a role uid with file capabilities cannot run `sshd -i`. Possible later design: an unprivileged listener passing accepted fds to a minimal root spawner.
- Limits: 64 connections, 8 per source address (`MaxStartups` does not apply with `-i`); `LoginGraceTime 30`, `MaxAuthTries 3` per connection.
- sshd's own log (auth accepted/failed) is forwarded to `nos-logd` line by line.
- Files: `/run/nos-sshd/<table>/sshd_config` (rendered at start), `/run/nos-sshd/<table>/ssh_host_ed25519_key` (tmpfs, 0600, rendered from the keystore).
- Host key (#1104): the admin-keystore secret `ssh-host-key` (base64 ed25519 seed) in `nos-configd`, saved with the config. The first `nos-sshd` to start generates it (`SetSshHostKey`, set-if-absent); the others adopt it. The log line `host key fingerprint=SHA256:...` is the only trace of it. To regenerate: `delete admin key ssh-host-key`, commit; each daemon rewrites its file and new connections use the new key. Nothing is stored under `/var/lib`.
- Spawning by the watchdog is #995; the host-key e2e phase is `ssh-hostkey`, the login phase #1002.

## Spike: what PAM sees for a name sshd calls invalid (#1374)

- Setup: `debian:trixie-slim` (OpenSSH 10.0p2, the runtime image's sshd), `UsePAM yes`, a PAM service whose only `auth` module was `pam_exec expose_authtok` logging `PAM_USER` and the token. Real `ssh` attempts with a known local user, then two unknown names; both `PasswordAuthentication yes` and the shipped `KbdInteractiveAuthentication yes`.
- Known user: `PAM_USER` is the name, the token is the typed password.
- Unknown name (sshd logs `Invalid user`): `PAM_USER` is the REAL typed name (not `NOUSER`), but the token is EMPTY, with both methods. The stack still runs, and the attempt is always a failure.
- Consequence: `pam_nos` can read the name but never a password for an unallocated user, so RADIUS cannot be asked and an ssh attempt cannot allocate an external user. Allocation must come from a RADIUS accept on another path (`nos` or REST login) or from the admin command `allocate aaa user <name>` (#1359 Q6), which #1374 therefore provides. `pam_nos` refuses an empty password before contacting the broker (pinned by a unit test), and an account guard (#1375) refuses a name that resolves (getpwnam through NSS) to a shell other than `nos_proto::NOS_LOGIN_SHELL` or a uid outside `NOS_UID_RANGE`, also before the broker. A name that does not resolve passes the guard: the broker decides.
