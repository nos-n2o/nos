# nos-ssh — SSH server daemon (`nos-sshd`)

A VRF-bound TCP listener that hands each accepted connection to a stock OpenSSH `sshd -i` (#994, part of #988/#987). `RoutingTable.ssh_server: Option<SshServer { address, port }>` (#993) pins it to a table; the watchdog spawn is #995, the PAM stack is `pam/` (#996/#998). Why a wrapper: stock `sshd` can neither bind inside a VRF nor inherit a listener, but `-i` serves one connection on stdin/stdout.

## Privilege model

- Runs as **uid 0** (`role_uid(Sshd) = Some(0)`; the supervisor's setuid to 0 is #995). `sshd` needs root to authenticate and `setuid` to the user: OpenSSH 10.0p2 switches to the logging-in user only when `getuid()==0` (a spike on #1187 with CAP_SETUID/SETGID ambient on a non-root uid: pubkey auth under the user's uid is a no-op and the session dies with `Failed to set uids`), so a role uid with file capabilities cannot run `sshd -i`. Root is inherent, the capability bounding below is the mitigation (#1187; an unprivileged listener plus a root spawner is an open design option).
- `caps::restrict()` runs **first** in `main`, before stdin or any socket: `PR_CAPBSET_DROP` for everything outside `KEEP` (SETUID, SETGID, SYS_CHROOT, CHOWN, NET_RAW, NET_BIND_SERVICE, AUDIT_WRITE, KILL), then `capset` on its own sets. The bounding drop alone only limits what an `execve` gains; the running process would keep the full root set. Failure is fatal. Not held (unprivileged dev run) is tolerated. The file is excluded from coverage (raw `prctl`/`capset`).
- No `CAP_DAC_OVERRIDE`/`CAP_FOWNER`, so root obeys DAC. `/run/nos` and `/var/lib/nos` belong to `nos-wd` and are not writable by it: the rendered config goes to `/run/nos-sshd/<table>/sshd_config` (root tmpfs), and the host key next to it (rendered from the keystore). No `setcap` on the binary.
- `Role::Sshd` sees exactly one secret, the admin key `ssh-host-key` (`redact::visible`), may send `Request::SetSshHostKey` (`config/src/authz.rs`, set-if-absent) and may only `GetVrfName` on `nos-ribd` (not `GetTableId`).

## Layout

- `listen.rs`: `Listener<Source, Binder>` like `nos-restd`: converges every 1s and on a `RoutingTables` diff; rebinds on address, port, VRF name or ifindex change; a config read error keeps the listener; `EADDRNOTAVAIL`/no VRF are retried and logged once per change. `bind_listener` is a third per-crate copy (extracting it would pull `socket2` into every daemon).
- `conn.rs`: accept loop. Caps checked **before** spawning: 64 total, 8 per source address (`MaxStartups` means nothing under `-i`, these are the brake). Child: `sshd -i -e -f <cfg>`, `env_clear()` + `PATH` only, stdin/stdout = the socket (made blocking again), **stderr = a pipe** forwarded line by line to `info!` (sshd's auth log reaches `nos-logd`). Stop: SIGTERM, SIGKILL after 5s. The single `tokio::process::Command` use carries the `disallowed_types` allow with its reason.
- `sshd_config.rs`: pure `render`; password via PAM only (`UsePAM yes`, `KbdInteractiveAuthentication yes`, no pubkey, no root, forwarding fully off: `DisableForwarding yes` plus the older per-kind directives, `PermitUserRC no`, no `Subsystem`/sftp, no `ForceCommand`: it runs as `<shell> -c`, breaking the interactive login; the NSS shell + exec refusal are the boundary, #1184). `extra_directives()` is appended last for #989/#987.
- **PAM service name:** `PAMServiceName nos-sshd` in the rendered config selects `/etc/pam.d/nos-sshd` (#998). It needs the OpenSSH of the runtime image: `debian:trixie-slim` (10.0p2; bookworm's 9.2 rejects the option), distro `openssh-server`, `--sshd-bin /usr/sbin/sshd`.
- `hostkey.rs`: `Keeper` converges `<run>/<table>/ssh_host_ed25519_key` to the keystore's `ssh-host-key` on `Admin` diffs (absent: generate and `SetSshHostKey`, then re-read, so a lost race adopts the winner; unreadable config or a bad seed keeps the file). The seed's ed25519 OpenSSH key is hand-encoded from `aws-lc-rs` (the `ssh-key` crate pulls `rsa` and its RUSTSEC advisory; `ssh-keygen -y` accepts the output); atomic 0600 write; only the `SHA256:` fingerprint is logged.
- `main.rs` creates `/run/sshd` (privsep chroot, absent in the image).

## Rules

- Never start the distro's own `sshd` service.
- Do not widen `KEEP` without the owner; do not add a `Request` for this daemon without classifying it in every `allowed`.

## Manual smoke test

Run the image as root with a seeded router that has `ssh-server` set, start `nos-sshd --table rt1` by hand: `ss -l` shows the listener inside the VRF only; `/proc/<pid>/status` `CapEff`/`CapBnd` equal the `KEEP` mask `00000000200424e1`; SIGINT ends children. The host-key e2e phase is `ssh-hostkey`.
