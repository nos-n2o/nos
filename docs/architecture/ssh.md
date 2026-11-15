# nos-sshd

`nos-sshd` is the SSH server of a routing table (`set routing-table <t> ssh-server address <ip> port <n>`). Details for contributors are in [`ssh/CLAUDE.md`](../../ssh/CLAUDE.md).

- Stock OpenSSH cannot bind inside a VRF, so `nos-sshd` owns the listener (`SO_BINDTODEVICE`) and runs `sshd -i -e` once per connection.
- Login is PAM only: the rendered config sets `PAMServiceName nos-sshd`, so `/etc/pam.d/nos-sshd` calls `pam_nos.so`, which asks `nos-watchdogd` ([pam.md](pam.md)). No public keys, no root login, no forwarding.
- OpenSSH comes from the distro: the runtime image is `debian:trixie-slim` (OpenSSH 10.0p2, `openssh-server` package). Bookworm's 9.2 has no `PAMServiceName` (`sshd -T` rejects it), hence the base bump; the builder is `rust:<channel>-slim-trixie`, so build and runtime glibc match.
- Runs as root with a reduced capability set (SETUID, SETGID, SYS_CHROOT, CHOWN, NET_RAW, NET_BIND_SERVICE, AUDIT_WRITE, KILL).
- Limits: 64 connections, 8 per source address (`MaxStartups` does not apply with `-i`); `LoginGraceTime 30`, `MaxAuthTries 3` per connection.
- sshd's own log (auth accepted/failed) is forwarded to `nos-logd` line by line.
- Files: `/run/nos-sshd/<table>/sshd_config` (rendered at start), `/run/nos-sshd/<table>/ssh_host_ed25519_key` (tmpfs, 0600, rendered from the keystore).
- Host key (#1104): the admin-keystore secret `ssh-host-key` (base64 ed25519 seed) in `nos-configd`, saved with the config. The first `nos-sshd` to start generates it (`SetSshHostKey`, set-if-absent); the others adopt it. The log line `host key fingerprint=SHA256:...` is the only trace of it. To regenerate: `delete admin key ssh-host-key`, commit; each daemon rewrites its file and new connections use the new key. Nothing is stored under `/var/lib`.
- Spawning by the watchdog is #995; the host-key e2e phase is `ssh-hostkey`, the login phase #1002.
