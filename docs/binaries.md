# Inputs of every NOS binary (#1214)

Audit of every flag and environment variable of every binary the `Dockerfile` ships (`nos-cli`'s `nos` is in [cli.md](cli.md#input-inventory-of-nos-1214)). Sources: each `*/src/main.rs` `clap` struct, `watchdog/src/{main,supervisor,instances}.rs`, `tools/e2e`, `tools/nos-provision`, `docker-compose.yml`, `Dockerfile`, `watchdog/tests/system.rs`.

Classes:
- **operator**: documented, an operator may pass it.
- **supervisor**: `nos-watchdogd` passes it to a child; never typed by hand.
- **e2e/dev**: only a test, the e2e harness or a developer uses it.

Status: `kept`, or `proposed gate` (not implemented; the owner decides, see the PR for #1214). Only `nos`'s `--watchdog-socket`/`--pki-ca` are gated today.

## How the harness starts things

- `tools/e2e` starts one `nos-watchdogd` container per router (image entrypoint `nos-watchdogd --child-gid 991`) and appends `--logd-arg=--capacity=200000`, `--acld-arg=--flowspec-file=...` and per-phase `--<daemon>-arg=...` flags. It never starts a daemon directly, except `nos-rtr-stub` (own entrypoint).
- Children are started by the watchdog with `--watchdog-socket`, `--log-socket`, and per object `--table`/`--instance`/`--domain`, `--listen-socket`, `--driver`, `--plain` as needed; the watchdog clears the child environment except `RUST_LOG`, `PATH`, `TZ`, `NOS_LACP_CHURN_SECS`.
- `watchdog/tests/system.rs` (unprivileged system test) runs the real binaries with relocated sockets/dirs and `--driver=noop`.
- `docker-compose.yml` runs the watchdog image default and a `cli` service (`nos`, no flags).

## Flags common to the daemons

| Flag | Binaries | Class | Used by | Status |
|---|---|---|---|---|
| `--watchdog-socket <path>` | every daemon except `nos-watchdogd` | supervisor | watchdog passes it; system test relocates it | kept |
| `--log-socket <path>` | all but `nos-logd`, `nos-watchdogd` (as its own flag) | supervisor | watchdog passes it | kept |
| `--listen-socket <path>` | acl, bfd, interface, lacp, lldp, log, stp, bgp, ospf, ospfv3, rib, fdb | supervisor | watchdog passes it; system test | kept |
| `--table`, `--instance`, `--domain <name>` | rib/rest/ssh, bgp/ospf/ospfv3, fdb | supervisor | watchdog passes the one it spawns for | kept |
| `--profile-memory-out` | bgp, config, log, rest | dev | only exists in a `dhat-heap` build (already feature-gated); `bench-bgp.sh` | kept (gated) |

## Per binary

| Binary | Flag / env | Class | Used by | Status |
|---|---|---|---|---|
| `nos-watchdogd` | `--<daemon>-bin`, `--<daemon>-arg` (configd, bgpd, ribd, fdbd, ospfd, ospfv3d, restd, sshd, interfaced, logd, lacpd, lldpd, bfdd, stpd, acld) | operator | e2e (every `--*-arg` below), system test, `bench-bgp.sh` | kept: root-only opaque passthrough, the carrier of every child dev flag |
| | `--<daemon>-listen-socket`, `--config-socket`, `--listen-socket`, `--log-socket`, `--run-dir`, `--state-dir`, `--users-dir`, `--pki-dir` | operator | system test relocates them; `--pki-dir` documented in `protocols/system.md` | kept |
| | `--child-gid` | operator | `Dockerfile` ENTRYPOINT (991), compose | kept |
| | `--pki-leaf-lifetime`, `--pki-rotate-every`, `--pki-ipc-session-max`, `--pki-user-lifetime`, `--pki-rest-session-max` | operator (tunables) | e2e `pki-rotation` (leaf, rotate, ipc-session-max) | kept (proposed gate: the three shortening flags) |
| | `--no-heartbeat-kill` | dev | documented for debugging under a debugger (`architecture/supervision.md`); no test | proposed gate |
| | env `RUST_LOG` | operator | `bench-bgp.sh` | kept |
| `nos-configd` | `--listen`, `--config-file`, `--user-ids-file`, `--passwd-file` | operator/supervisor | watchdog; e2e seeds `--config-file`; system test | kept |
| `nos-ribd` | `--driver linux\|noop`, `--table-registry-path` | operator/dev | `noop`: system test; registry path: system test | kept |
| | `--redistribute-chunk`, `--startup-hold` (hidden) | e2e/dev | `ospf-push-chunked` (`--ribd-arg=--redistribute-chunk`); `--startup-hold` none found | proposed gate |
| `nos-interfaced` | `--driver`, `--bridge-registry-path`, `--port-aggregate-registry-path` | operator/dev | `noop` + registries: system test | kept |
| `nos-fdbd` | `--driver`, `--df-wait` | operator/dev | `evpn-esi` (`--fdbd-arg=--df-wait=12`) | kept (`--df-wait` is an RFC 7432 timer) |
| `nos-acld` | `--driver` | dev | system test | kept |
| | `--flowspec-file` (hidden) | e2e/dev | every router in e2e (`router.rs`), `acl` phase writes it | proposed gate |
| `nos-logd` | `--log-store-path`, `--capacity` | operator | e2e `--logd-arg=--capacity=200000` on every router | kept |
| `nos-ospfd` | `--lsa-age-multiplier`, `--dbd-max-headers`, `--state-dir` | operator/dev | e2e `ospf-aging` (multiplier), `ospf-dbd-pagination` (headers) | kept (multiplier proposed gate) |
| | `--dbd-fault`, `--push-chunk` (hidden) | e2e/dev | `ospf-dbd-pagination`, `ospf-push-chunked` | proposed gate |
| `nos-ospfv3d` | `--lsa-age-multiplier`, `--dbd-max-headers`, `--state-dir` | operator/dev | as ospfd | kept (multiplier proposed gate) |
| | `--dbd-fault`, `--push-chunk`, `--originate-lsinfinity`, `--router-lsa-max-links` (hidden) | e2e/dev | `ospfv3-mtu-pagination`, `ospfv3-lsinfinity*`, `ospfv3-router-lsa-split` | proposed gate |
| `nos-lacpd` | env `NOS_LACP_CHURN_SECS` | e2e/dev | `docker.rs` sets 8 on every router; watchdog forwards it | proposed gate |
| `nos-sshd` | `--sshd-bin`, `--run-dir`, `--max-connections` | operator | defaults only in e2e (`ssh-login-shell`) | kept |
| `nos-bgpd`, `nos-restd`, `nos-lldpd`, `nos-bfdd`, `nos-stpd` | only the common flags | | | kept |
| `nos-provision` | `--login-user`, `--login-password`, env `NOS_LOGIN_PASSWORD`, `--watchdog-socket`, `--pki-ca`, `--config-socket`, ~300 config-building flags | dev/operator | `bench-bgp.sh`, `watchdog/tests/system.rs`, e2e `pki` (`run_provision`); e2e config seeding reuses `build_ops` | proposed: not a daemon; ship or not is the owner's call |
| | `--pki-cert-out`, `--pki-cert-in`, `--renew-probe` | e2e/dev | `pki`, `pki-rotation` | proposed gate |
| `nos-rtr-stub` | positional `<listen> <prefix> <max-len> <asn> ...` | e2e/dev | `rpki` phase only | proposed: not in the production image |
| `libpam_nos.so`, `libnss_nos.so.2` | none (PAM module args, NSS) | operator | `pam`, `ssh-login-shell` | kept |

e2e uses no flag of `nos-bgpd`, `nos-restd`, `nos-lldpd`, `nos-bfdd`, `nos-stpd`, `nos-sshd` beyond the supervisor ones.
