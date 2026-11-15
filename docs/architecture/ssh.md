# nos-sshd

`nos-sshd` is the SSH server of a routing table (`set routing-table <t> ssh-server address <ip> port <n>`). Details for contributors are in [`ssh/CLAUDE.md`](../../ssh/CLAUDE.md).

- Stock OpenSSH cannot bind inside a VRF, so `nos-sshd` owns the listener (`SO_BINDTODEVICE`) and runs `sshd -i -e` once per connection.
- Login is PAM only: sshd runs through a symlink named `nos-sshd` (OpenSSH takes its PAM service name from `argv[0]`; bookworm has no `PAMServiceName`), so `/etc/pam.d/nos-sshd` calls `pam_nos.so`, which asks `nos-watchdogd` ([pam.md](pam.md)). No public keys, no root login, no forwarding.
- Runs as root with a reduced capability set (SETUID, SETGID, SYS_CHROOT, CHOWN, NET_RAW, NET_BIND_SERVICE, AUDIT_WRITE, KILL).
- Limits: 64 connections, 8 per source address (`MaxStartups` does not apply with `-i`); `LoginGraceTime 30`, `MaxAuthTries 3` per connection.
- sshd's own log (auth accepted/failed) is forwarded to `nos-logd` line by line.
- Files: `/run/nos-sshd/<table>/sshd_config` (rendered at start), `/var/lib/nos/sshd/ssh_host_ed25519_key` (persistent, shared by every table).
- Spawning by the watchdog and the e2e phase are separate issues (#995, #1002).
