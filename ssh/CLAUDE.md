# nos-ssh — SSH server daemon (`nos-sshd`)

A VRF-bound TCP listener that hands each accepted connection to a stock OpenSSH `sshd -i` (#994, part of #988/#987). `RoutingTable.ssh_server: Option<SshServer { address, port }>` (#993) pins it to a table; the watchdog spawn is #995, the PAM stack is `pam/` (#996/#998). Why a wrapper: stock `sshd` can neither bind inside a VRF nor inherit a listener, but `-i` serves one connection on stdin/stdout.

## Privilege model

- Runs as **uid 0** (`role_uid(Sshd) = Some(0)`; the supervisor's setuid to 0 is #995). `sshd` needs root to authenticate and `setuid` to the user.
- `caps::restrict()` runs **first** in `main`, before stdin or any socket: `PR_CAPBSET_DROP` for everything outside `KEEP` (SETUID, SETGID, SYS_CHROOT, CHOWN, NET_RAW, NET_BIND_SERVICE, AUDIT_WRITE, KILL), then `capset` on its own sets. The bounding drop alone only limits what an `execve` gains; the running process would keep the full root set. Failure is fatal. Not held (unprivileged dev run) is tolerated. The file is excluded from coverage (raw `prctl`/`capset`).
- No `CAP_DAC_OVERRIDE`/`CAP_FOWNER`, so root obeys DAC. `/run/nos` and `/var/lib/nos` belong to `nos-wd` and are not writable by it: the rendered config goes to `/run/nos-sshd/<table>/sshd_config` (root tmpfs), the host key to `/var/lib/nos/sshd/` (the watchdog's `ensure_state_dirs` creates it for uid 0). No `setcap` on the binary.
- `Role::Sshd` sees no secrets (`redact::visible` none arm) and may only `GetVrfName` on `nos-ribd` (not `GetTableId`). It adds no `Request` and no `nos-configd` allow-list entry (`Get`/`SubscribeDiff` are open to every role).

## Layout

- `listen.rs`: `Listener<Source, Binder>` like `nos-restd`: converges every 1s and on a `RoutingTables` diff; rebinds on address, port, VRF name or ifindex change; a config read error keeps the listener; `EADDRNOTAVAIL`/no VRF are retried and logged once per change. `bind_listener` is a third per-crate copy (extracting it would pull `socket2` into every daemon).
- `conn.rs`: accept loop. Caps checked **before** spawning: 64 total, 8 per source address (`MaxStartups` means nothing under `-i`, these are the brake). Child: `sshd -i -e -f <cfg>`, `env_clear()` + `PATH` only, stdin/stdout = the socket (made blocking again), **stderr = a pipe** forwarded line by line to `info!` (sshd's auth log reaches `nos-logd`). Stop: SIGTERM, SIGKILL after 5s. The single `tokio::process::Command` use carries the `disallowed_types` allow with its reason.
- `sshd_config.rs`: pure `render`; password via PAM only (`UsePAM yes`, `KbdInteractiveAuthentication yes`, no pubkey, no root, no forwarding). `extra_directives()` is appended last for #989/#987.
- **PAM service name:** bookworm's OpenSSH has no `PAMServiceName`; sshd names the service after its `argv[0]` basename, so the image symlinks `/usr/libexec/nos-sshd/nos-sshd` -> `/usr/sbin/sshd` (`--sshd-bin`) and `/etc/pam.d/nos-sshd` (#998) applies. Verified in a bookworm container.
- `hostkey.rs`: ed25519 OpenSSH key, 0600 in a 0700 dir; temp file + `hard_link` so concurrent tables' daemons never replace each other's key.
- `main.rs` creates `/run/sshd` (privsep chroot, absent in the image).

## Rules

- Never start the distro's own `sshd` service.
- Do not widen `KEEP` without the owner; do not add a `Request` for this daemon without classifying it in every `allowed`.

## Manual smoke test

Run the image as root with a seeded router that has `ssh-server` set, start `nos-sshd --table rt1` by hand: `ss -l` shows the listener inside the VRF only; `/proc/<pid>/status` `CapEff`/`CapBnd` equal the `KEEP` mask `00000000200424e1`; SIGINT ends children. The e2e phase is #1002.
