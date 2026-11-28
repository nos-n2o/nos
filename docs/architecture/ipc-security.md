# IPC security

Contributor-facing; moved from the root `CLAUDE.md` (#260). Operator view: [docs/README.md](../README.md).


Every daemon-to-daemon and client-to-daemon connection is mutually authenticated TLS (`nos-pki`), with `nos-watchdogd` as the CA:

- **Identity.** Each certificate carries one URI SAN `nos://<role>/<name>` (`nos_proto::Role`: `watchdog`, `configd`, `logd`, `bgpd`, `ribd`, `ospfd`, `ospfv3d`, `interfaced`, `lacpd`, `lldpd`, `radvd`, `fdbd`, `restd`, `sshd`, `user`). A client dialing `ServiceRef::RibTable("rt1")` requires the server to prove it is `ribd/rt1` (`ServiceRef::role()`/`instance()`); a client that only has a socket path checks the role (`connect_role`).
- **Post-quantum only.** No classical fallback anywhere: the only key-exchange group is hybrid `X25519MLKEM768`, the only cipher `TLS13_AES_256_GCM_SHA384`, and IPC certificates are ML-DSA-65 (a verifier that accepts nothing else, so an ECDSA leaf fails even when it chains to a trusted CA). One policy, in `pki/src/policy.rs`, on the aws-lc-rs provider. The REST listener has the same key exchange but **ECDSA P-256** certificates from a second CA, so browsers and stock clients can still present one; a REST certificate never opens an IPC socket, nor an IPC one the REST API. `Policy::Syslog` (`nos-logd` dialing a syslog collector, RFC 5425, #71) is the same key exchange and TLS 1.3 with the classical signatures webpki supports, since no deployed collector holds an ML-DSA certificate. The one classical path is the per-collector `allow-tls12` opt-in: TLS 1.2 with ECDHE-AES-GCM suites, confined to `pki/src/syslog.rs` (every classical group wrapped to be TLS 1.2-only, so TLS 1.3 stays post-quantum) and unreachable from IPC and REST.
- **Handoff.** The watchdog creates two ephemeral in-memory CAs at start (writing only the public `ca.crt` and `rest-ca.crt` to `--pki-dir`, default `/run/nos/pki`) and, for **every spawn** in `supervisor::supervise_one`, mints a fresh keypair + leaf and writes it to the child's piped **stdin** — never argv, environment or disk. Daemons have no plaintext fallback. The watchdog's own identity rotates in-process.
- **Rotation.** Leaves are valid `--pki-leaf-lifetime` (24h) and re-pushed down the same stdin every `--pki-rotate-every` (8h); daemons swap them in hot (`Identity::update`) — new connections use the new certificate, established ones are untouched, so a long-lived stream (e.g. `nos-bgpd`→`nos-ribd`'s route push) outlives its handshake certificate and only a *reconnect* needs the rotated one.
- **Revocation.** The IPC CA keeps an RFC 5280 CRL, pushed down every child's stdin with its identity (at spawn and when it changes, not with every rotation: rotation frames carry an empty CRL, meaning "keep"; #858) and enforced on every new handshake (never on an open connection): a child's certificates are revoked when its process exits, a user's IPC certificates when the user is deleted or its password changes. Each bundle (CRL included) is one stdin frame capped at 16 MiB, ~430k revoked serials; a child whose identity pipe breaks exits so it is respawned (#677). No CA roll: a child can't outlive the watchdog. See `pki/CLAUDE.md`.
- **Login.** The broker socket is TLS with the client certificate **optional**. An unauthenticated peer may send only `WatchdogRequest::Login { user, password, csr_der }`: the watchdog reads the users from `nos-configd` (its own identity), verifies with `nos_password::verify_or_dummy` (1s delay per failure, dropped after `login-policy max-failures`, default 5), and returns a `user/<name>` certificate for the **public key in the CSR** (the subject/SANs the CSR asks for are discarded). `RenewCert` trades a still-valid user certificate for a fresh one without a password, refused once the user is deleted; `nos` renews at half-life (`--pki-user-lifetime`, 8h). Renewals are capped at `--pki-ipc-session-max` (24h) from the password login: the watchdog records each IPC certificate's login time, takes the presented certificate's serial from the verified TLS peer (`Stream::peer_serial`, never from the client), and the renewed certificate inherits that time; past the cap it answers `session expired` and `nos` prints a notice and stops renewing (#637). `ResolveEndpoint` requires a certificate.
- **Login ticket (#990).** `LoginTicket { user, password }` (anonymous) verifies the password like `Login` but returns `Ticket { ticket, ttl_secs }`: 32 random bytes, single use, 60 s, at most 256 outstanding (the oldest is evicted), held only as a SHA-256 in `Pki` so `revoke_user` (user delete, password change) drops them. `RedeemTicket { ticket, csr_der }` (anonymous) burns the ticket, re-checks the user still exists and issues the `user/<name>` certificate; every failure is the one opaque `Denied(INVALID_TICKET)`. Failed `LoginTicket`/`RedeemTicket` count toward the per-connection throttle like `Login` (per connection only; argon2 stays bounded globally). The transport (`NOS_LOGIN_TICKET`, `ticket_to_env`/`ticket_from_env`) belongs to PAM and `nos` (#991/#992).
- **Anonymous peers.** The broker answers an unauthenticated peer's first non-`Login` request with `Denied("authentication required")` and closes the connection (one log line, no flooding); authenticated wrong-role peers get `Denied` and stay connected. Anonymous connections are capped at 64 concurrent (the 65th is dropped right after the handshake, one rate-limited warn per second) and closed after 30 s waiting for the next request (#950); authenticated peers are neither counted nor timed.
- **REST.** `nos-restd` uses the same broker for its REST clients (`RestLogin`/`RestRenew`, REST-CA certificates, no per-connection throttle — `nos-restd` allows one guess per second per username itself) and for its listener certificate (`IssueRestServerCert`).
- **Socket mode.** Every IPC socket is `0660`, group `nos` (chmod right after bind, in `nos-pki`'s `listen_with`; the process umask is not relied on). The watchdog (`nos-wd`), each daemon role (`nos-<role>`) and the clients (`nos`) are different uids with the same primary group `nos`, and `connect()` on a Unix socket needs write permission, so a `0600` socket would be unreachable across them. mTLS, not the file mode, is the gate. See "uid model".
- **Accept errors never end a loop.** Every IPC accept loop calls `Listener::accept_resilient`, which retries `accept` errors (EMFILE, ECONNABORTED, ...) with exponential backoff from 50 ms to 1 s and logs at most one warning per second (with a `suppressed` count); the delay resets after each accepted connection (#949).
- **Authorization.** Each server has a pure, unit-tested `allowed(role, &request)` with **no wildcard arm** (a new request variant won't compile until classified); a refused request is logged with role+name and the connection is closed. Config *reads* are open to every authenticated daemon; edits/saves are `user`/`restd` only (`config/src/authz.rs`); the broker's `allowed` (`watchdog/src/broker.rs`) likewise: `Login`/`LoginTicket`/`RedeemTicket` anyone, `ResolveEndpoint` any certificate, `RenewCert` `user`, the three `Rest*` requests `restd`; route pushes are each daemon family's alone (`ribd`: `bgpd` → `PushBgpRoutes` and the `BgpRouteCount` query (graceful restart), `ospfd`/`ospfv3d` → `PushOspfRoutes`; the redistribution feeds `RedistributeRoutes` into `nos-ospfd`/`nos-ospfv3d` are `ribd`'s); `PushLacpMembers` and `PushLacpConversations` are `lacpd`'s, `PushBfdMembers` `bfdd`'s, `SubscribeLinks` `ospfd`/`ospfv3d`'s; `PushEvpnRoutes` (to `nos-fdbd` and to `nos-ribd` alike) is `bgpd`'s, `RedistributeMacs` is `fdbd`'s and `RedistributeEvpnPrefixes` is `ribd`'s; `nos-ribd` answers `GetEvpnIrb` (symmetric IRB) to `fdbd` only; queries are `user`/`restd`, except that `nos-interfaced`'s status queries are also open to the daemons that resolve addresses through it (`bgpd`, `ribd` — for its connected routes — `ospfd`, `ospfv3d`, `fdbd`); `nos-logd` accepts pushes from any daemon and reads from `user`/`restd`; `ribd`'s `GetVrfName` is also open to `logd` (a syslog collector's VRF). Role-level only — see `pki/CLAUDE.md`'s ceilings.
- **`nos-configd --listen` is Unix-only**: the TCP variant was removed, since a network listener would bypass all of this.

- **Key hygiene.** Every NOS-owned buffer holding a private key is `nos_pki::Zeroizing<Vec<u8>>` (wiped on drop): `Bundle.key`, the `Bundle::encode()` frame and the `read_from` body, and the key `generate_csr`/`generate_csr_for` return (the `nos` session key, `nos-restd`'s listener key). Use the `nos_pki::Zeroizing` re-export; no crate adds `zeroize` itself.
  - Ceilings: rustls/aws-lc-rs keep their own copy of the loaded key; rcgen's `KeyPair` and the REST test client's owned `PrivatePkcs8KeyDer` are not wiped; tokio stdin buffers, the kernel pipe buffer, swap and core dumps are out of reach.

## Who sees which secrets (#384)

- `allowed` lets every daemon read the config, so `nos-configd` also projects it: `Get`, `Subscribe`, `SubscribeDiff` (initial and per-commit) all go through `Config::for_role(role)` (`proto/src/schema/redact.rs`), a second layer after `allowed`. It clears `users` (password hashes) and the `admin.keys` entries the role has no use for; auth structures keep their key labels, so the config still parses.
- Visibility:

| Role | Users | Admin keys kept |
|------|-------|-----------------|
| `user`, `restd` | yes | all |
| `watchdog` | yes | none |
| `bgpd` | no | labels used by BGP auth (peer-groups, RPKI caches) and BFD profiles |
| `ospfd` | no | OSPFv2 auth (profiles, virtual links) and BFD profiles |
| `ospfv3d` | no | OSPFv3 auth and BFD profiles |
| `ribd`, `bfdd` | no | BFD profile auth |
| `sshd` | no | `ssh-host-key` only (#1104) |
| every other role | no | none |

- Adding a secret-bearing field: extend `for_role` and the sentinel fixture in `redact.rs` (the test cannot notice a field missing from the fixture). Adding a role: classify it in `visible()` (exhaustive `match`).
- The negative side (a foreign role sees no keys) is covered by `config/tests/ipc.rs`; the e2e harness only has user-role REST access, so the existing auth phases (`auth`, `ao`, `ospf-auth`, `ospfv3-auth`, `bfd-auth`) prove the allowed side.

## W^X for daemons (#1210)

- `nos-watchdogd` sets `PR_SET_MDWE` (`PR_MDWE_REFUSE_EXEC_GAIN`) on itself at start and fails to start without it; every supervised process inherits it, `nos-sshd` included. The watchdog is under it too (no JIT in it).
- The kernel then refuses a writable+executable mapping and `mprotect` of a writable mapping to executable; inherited across fork and exec, never liftable by the daemon.
- `nos-sshd`'s children (`sshd -i`, login shells) inherit it too: JIT-based tools (node, JVM, PyPy) fail in an ssh session. Accepted (owner decision, #1210).

## Sandbox (#1211, part of #1186)

- Every daemon but `nos-sshd` runs `NO_NEW_PRIVS`: the watchdog execs `nos-sandbox-exec` (crate `sandbox/`), which sets it and execs the daemon. Container-level `no-new-privileges` stays off: it would also strip the watchdog's own file capabilities.
- The clip rule: under `NO_NEW_PRIVS` the exec'd file's permitted set is intersected with the caller's permitted set. So the trampoline holds, as file capabilities, the union of what daemons need (`cap_net_admin,cap_net_raw,cap_net_bind_service`; keep equal to the other `setcap` lines in the `Dockerfile`), reads the target's `security.capability` xattr and trims itself to exactly that before `NO_NEW_PRIVS` and `execv`. The daemon then gets its own file capabilities, identical to a direct exec (the `sandbox-nnp` phase asserts `CapEff` per daemon).
- Exposure: any process can exec the trampoline, but under `NO_NEW_PRIVS` it gets only the target's xattr capabilities, never more than a direct exec of that target. Targets are confined to regular files directly in `/usr/local/bin` (canonicalised, so a symlink out is refused). It never execs unsandboxed: any error exits 126.
- `nos-sshd` is exempt: it runs as root and `NO_NEW_PRIVS` would break its login `setuid`. A root-run daemon would also lose root's implicit capabilities under the clip rule: exempt it or give it xattr caps.

### Seccomp deny-list (#1217)

- Installed by the trampoline right after `NO_NEW_PRIVS`, before `execv` (inherited across the exec). Same list for every sandboxed daemon (`--profile` is not used yet); `nos-sshd` is exempt, with its children. Allow by default, `SECCOMP_RET_KILL_PROCESS` on a listed syscall. A per-daemon allowlist is a later step.
- Built by `seccompiler` (`sandbox/src/seccomp.rs`), the only seccomp generator in the tree; no env or config switch.
- Denied, since no daemon needs them:

| Syscalls | Why |
|---|---|
| `ptrace`, `process_vm_readv/writev` | read or inject into another daemon's memory (mTLS keys live there) |
| `personality` | `ADDR_NO_RANDOMIZE`, `READ_IMPLIES_EXEC` weaken ASLR/W^X |
| `kexec_load`, `kexec_file_load`, `reboot` | replace or stop the kernel/host |
| `init_module`, `finit_module`, `delete_module` | kernel code loading |
| `mount`, `umount2`, `pivot_root`, `fsopen`, `fsmount`, `move_mount`, `open_tree`, `fsconfig`, `fspick`, `mount_setattr` | filesystem and mount namespace tampering |
| `swapon`, `swapoff` | host-level |
| `bpf`, `perf_event_open` | kernel attack surface, side channels (`nos-tc` uses netlink only) |
| `keyctl`, `add_key`, `request_key` | kernel keyring, unused |
| `userfaultfd` | kernel race exploitation primitive |
| `open_by_handle_at` | container-escape primitive |

- Kept allowed: `unshare`/`setns` (VRF/netns), `clone3` (tokio/glibc), `execve`.
- Architectures: x86_64 and aarch64 only (anything else fails to compile). The program kills a foreign `AUDIT_ARCH` (i386 compat). On x86_64 the x32 ABI shares the x86_64 arch value and ORs `0x40000000` into the syscall number, which a name-based list would miss, so three BPF instructions kill any number with that bit first.
- Diagnosing: a daemon using a denied syscall dies of `SIGSYS`; the watchdog logs `exited ... signal: 31` with `hint="seccomp deny-list violation (nos-sandbox)..."` and restarts it with backoff. If a daemon really needs one, exempt that daemon only and record why here; never widen the shared list silently.
- Proof: the `sandbox-nnp` phase asserts `Seccomp_filters` = `nos-watchdogd`'s count + 1 per sandboxed daemon (+ 0 for `nos-sshd`; the baseline is Docker's own filter) and no SIGSYS in the log; `sandbox/tests/seccomp.rs` forks a child and checks `ptrace` is killed.

## uid model (#512, #513)

- **Who runs as whom.** `nos-watchdogd` runs as `nos-wd` (uid 990); it starts each daemon as its role's own user `nos-<role>` (uids 10001+ in `Role` declaration order, table in `watchdog/src/uids.rs`: `role_uid`, an exhaustive `match`, so a new `Role` won't compile until it has a uid). The image's `ENTRYPOINT` passes `--child-gid` (group `nos`), which also turns per-role uids on; unset (tests, non-container runs) every child keeps the watchdog's uid. `nos` (uid 991) is the shared client user: the `nos` shell, `nos-provision`, `nos-e2e` execs. Everyone has primary group `nos`.
- **Adding a role.** Append the `Role`, give it the next uid in `role_uid`, add the `useradd ... nos-<role>` line to the `Dockerfile`; a unit test fails when the two drift.
- **Privilege.** `nos-watchdogd` carries file capabilities `cap_setuid,cap_setgid,cap_chown,cap_kill=ep` (all in Docker's default bounding set) and no more; `cap_kill` lets it SIGINT and kill the per-role-uid children it supervises (#639). `Command::uid/gid` switch before exec, so the children's own file capabilities (`setcap` in the `Dockerfile`) are computed as before. A file-capability binary is non-dumpable, which also hardens the CA process against `ptrace`.
- **`/run/nos`** is `nos-wd:nos`, mode `1770`: group-writable so children create their `0660` sockets, sticky so no daemon can unlink or re-bind another's (or the watchdog's) socket. `/run/nos/pki` is `0755` (public certs and CRL only).
- **`/var/lib/nos`** is `nos-wd:nos` `0755`; the watchdog creates `/var/lib/nos/<role>` (`0700`, `nos-<role>:nos`) for every role at startup (`uids::ensure_state_dirs`, idempotent, also fixes the owner on a volume an older image left behind). A daemon's state default lives in its own directory:
  - `configd/config.yaml`, `logd/entries.jsonl`, `ribd/table-ids.yaml`, `interfaced/bridge-ids.yaml` and `interfaced/port-aggregate-ids.yaml` (the two daemons no longer share `linux-driver/`), `ospfd/` (`--state-dir`), `bgpd/` (only the dev `--profile-memory-out=/var/lib/nos/bgpd/dhat-heap.json`).
  - Seeding a file for a first boot (as `nos-e2e` does) means writing it into the role's directory, e.g. `configd/config.yaml`.
- **What it stops.** A compromised daemon cannot `kill` or `ptrace` the watchdog or a sibling role, unlink or re-bind another socket, read `/proc/<pid>/mem` of the CA process, or read another role's state directory; the CA keys live only in the watchdog.
- **What it does not stop.**
  - Same-role instances (`nos-bgpd` for `r1` and `r2`, every `nos-ribd`) share a uid and a state directory. A role uid is not a substitute for the certificate check.
  - A compromised daemon keeps its own capabilities and its certificate until revoked.
  - rustls/aws-lc-rs heap copies of keys (see "Key hygiene"), and host root.
- **Host settings, not ours.** Set `kernel.yama.ptrace_scope=2` on the host; it cannot be set from the container. Do not set `no-new-privileges`: the kernel then ignores file capabilities, so the watchdog could not change uid and no daemon would get its capabilities.
- **Existing volumes (upgrade by hand, there is no migration).**
  - An existing `nos-run` volume keeps its old owner: remove it (`docker volume rm`).
  - In an existing `nos-data` volume, move `config.yaml` to `configd/config.yaml`, `log/` to `logd/`, and `linux-driver/table-ids.yaml` to `ribd/`, `linux-driver/{bridge,port-aggregate}-ids.yaml` to `interfaced/`, `ospf/` to `ospfd/`. A missing `config.yaml` silently falls back to the default config, so a router that forgot the move boots unconfigured; the other files are only caches (a missing registry re-allocates ids, a missing log starts empty).
- The `cli` compose service runs as `nos` (`user: nos`); `nos-e2e` execs into routers as `nos`, and as root (`Dock::exec_root`) where it must signal a daemon or read its state.

- **`nos-sshd` uid.** Root (uid 0) by design (PAM, setuid); it reduces its own bounding set to SETUID, SETGID, SYS_CHROOT, CHOWN, NET_RAW, NET_BIND_SERVICE, AUDIT_WRITE, KILL, all in Docker's default set, so `docker-compose.yml` needs no `cap_add`.
