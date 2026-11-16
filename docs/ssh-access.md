# SSH access

- `ssh <user>@<router> -p <port>` lands in the `nos` shell for any user in the NOS config. The listener is `nos-sshd` (`ssh-server`, pinned on a routing table).
- Flow: sshd asks for the password (keyboard-interactive) -> `pam_nos.so` verifies it with the watchdog and gets a single-use ticket -> sshd starts `nos` as the user's login shell with `NOS_LOGIN_TICKET` set -> `nos` redeems it and opens with no `login:` prompt.
- Password only: public-key and plain `password` authentication are off, and root cannot log in.
- `ssh <host> <command>` is refused (`running a command is not supported`, non-zero exit); use the REST API for scripting.
- Config edits made in the session are audited with the user as actor (`config commit audit ... actor="<user>"`).
- A ticket lives 60 s and works once. A refused or unknown ticket makes `nos` fall back to its `login:` prompt.
- The ticket sits in the shell's environment. `nos` is setgid, so the process is non-dumpable: `/proc/<pid>/environ` is unreadable for its owner too. Root in a container without `CAP_SYS_PTRACE` cannot read it either.
- The user's `role` applies to the SSH shell as to any other (`read-only` and `operator` cannot edit or save), see `docs/architecture/auth.md`.
- Deleting a user or changing its password revokes its certificates; a new login is refused at once. An already open shell dials each daemon per command, so its next command should fail the TLS handshake (not asserted by the e2e phase).
- Not yet: restricting which users may log in over SSH and VRF-only reachability checks (#1001, #1002).
- Verified by the `ssh-login-shell` e2e phase (`docs/e2e-phases.md`).
