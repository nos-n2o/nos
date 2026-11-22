# Inputs of every NOS binary (#1214)

Audit of every flag and environment variable of every binary the `Dockerfile` ships (`nos`'s own table: [cli.md](cli.md#input-inventory-of-nos-1214)). Sources: each `*/src/main.rs` `clap` struct, `watchdog/src/{main,supervisor,instances}.rs`, `tools/e2e`, `tools/nos-provision`, `docker-compose.yml`, `Dockerfile`, `watchdog/tests/system.rs`.

- **Gated** = exists only in a `dev-args` build (per-crate cargo feature, list in `tools/ci/dev-features.txt`). A release binary rejects the flag (clap `unexpected argument`, exit 2) or ignores the env var. How to build with it: [development.md](architecture/development.md).
- **Kept** = available in every build.
- Classes: **operator** (documented, typed by an operator), **supervisor** (`nos-watchdogd` passes it to a child), **e2e/dev** (only tests, the e2e harness or a developer).

## How the harness starts things

- `tools/e2e` starts one `nos-watchdogd` container per router from the lab image (entrypoint `nos-watchdogd --child-gid 991`) and appends `--logd-arg=--capacity=200000`, `--acld-arg=--flowspec-file=...` and per-phase `--<daemon>-arg=...` flags. It starts no daemon directly, except `nos-rtr-stub` (own entrypoint).
- The watchdog starts children with `--watchdog-socket`, `--log-socket`, per object `--table`/`--instance`/`--domain`, `--listen-socket`, `--plain` as needed, and clears their environment except `RUST_LOG`, `PATH`, `TZ` (and `NOS_LACP_CHURN_SECS` in a `dev-args` build).
- `watchdog/tests/system.rs` runs the real binaries with relocated sockets/dirs and `--driver=noop`; it is built only with the dev features.
- Images: `make docker-build` = lab target, dev features, `nos-rtr-stub`, `pamtester` (e2e, `bench-bgp.sh`); `make docker-build-release` and `docker-compose.yml` = `runtime` target, no dev flags, no `nos-rtr-stub`.

## Flags common to the daemons (kept)

| Flag | Binaries | Class | Used by |
|---|---|---|---|
| `--watchdog-socket <path>` | every daemon except `nos-watchdogd` | supervisor | watchdog passes it; system test relocates it |
| `--log-socket <path>` | every daemon except `nos-logd` | supervisor | watchdog passes it |
| `--listen-socket <path>` | acl, bfd, interface, lacp, lldp, log, stp, bgp, ospf, ospfv3, rib, fdb | supervisor | watchdog passes it; system test |
| `--table`, `--instance`, `--domain <name>` | rib/rest/ssh, bgp/ospf/ospfv3, fdb | supervisor | watchdog passes the one it spawns for |
| `--profile-memory-out` | bgp, config, log, rest | dev | exists only in a `dhat-heap` build (its own feature); `bench-bgp.sh` |

## Gated (`dev-args`)

| Binary | Flag / env | Used by |
|---|---|---|
| `nos` | `--watchdog-socket`, `--pki-ca` | `cli/tests/login_shell.rs`; a relocated `--pki-dir` |
| `nos-ribd`, `nos-interfaced`, `nos-fdbd`, `nos-acld` | `--driver linux\|noop` (default `linux`; `noop` is log-only) | `watchdog/tests/system.rs` |
| `nos-ribd` | `--redistribute-chunk` (hidden) | e2e `ospf-push-chunked` |
| `nos-ribd` | `--test-ilm` (hidden, repeatable) | e2e `mpls-ilm` |
| `nos-acld` | `--flowspec-file` (hidden) | e2e: every router starts with it; the `acl` phase writes the file |
| `nos-ospfd`, `nos-ospfv3d` | `--lsa-age-multiplier` | e2e `ospf-aging` |
| `nos-ospfd`, `nos-ospfv3d` | `--dbd-fault`, `--push-chunk` (hidden) | e2e `ospf-dbd-pagination`, `ospf-push-chunked`, `ospfv3-mtu-pagination` |
| `nos-ospfv3d` | `--originate-lsinfinity`, `--router-lsa-max-links` (hidden) | e2e `ospfv3-lsinfinity*`, `ospfv3-router-lsa-split` |
| `nos-lacpd`, `nos-watchdogd` | env `NOS_LACP_CHURN_SECS` (read by lacpd, forwarded by the watchdog) | e2e: set to 8 on every router |
| `nos-watchdogd` | `--no-heartbeat-kill` | debugging under a debugger; no test |
| `nos-provision` | `--pki-cert-out`, `--pki-cert-in`, `--renew-probe` | e2e `pki`, `pki-rotation` |

Deleted: `nos-ribd --startup-hold` (no user).

## Kept

| Binary | Flag / env | Class | Used by |
|---|---|---|---|
| `nos-watchdogd` | `--<daemon>-bin`, `--<daemon>-arg` (configd, bgpd, ribd, fdbd, ospfd, ospfv3d, restd, sshd, interfaced, logd, lacpd, lldpd, bfdd, stpd, acld) | operator | e2e (every `--*-arg` above), `bench-bgp.sh`; root-only opaque passthrough, the carrier of every child dev flag |
| | `--<daemon>-listen-socket`, `--config-socket`, `--listen-socket`, `--log-socket`, `--run-dir`, `--state-dir`, `--users-dir`, `--pki-dir` | operator | system test relocates them; `--pki-dir` in `protocols/system.md` |
| | `--child-gid` | operator | `Dockerfile` ENTRYPOINT (991) |
| | `--pki-leaf-lifetime`, `--pki-rotate-every`, `--pki-ipc-session-max`, `--pki-user-lifetime`, `--pki-rest-session-max` | operator (tunables) | e2e `pki-rotation` (leaf, rotate, ipc-session-max) |
| | env `RUST_LOG`, `PATH`, `TZ` | operator | `bench-bgp.sh` (`RUST_LOG`) |
| `nos-configd` | `--listen`, `--config-file`, `--user-ids-file`, `--passwd-file` | operator/supervisor | watchdog; e2e seeds `--config-file`; system test |
| `nos-ribd` | `--table-registry-path` | operator | system test |
| `nos-interfaced` | `--bridge-registry-path`, `--port-aggregate-registry-path` | operator | system test |
| `nos-fdbd` | `--df-wait` | operator | e2e `evpn-esi` (`--fdbd-arg=--df-wait=12`) |
| `nos-logd` | `--log-store-path`, `--capacity` | operator | e2e `--logd-arg=--capacity=200000` on every router |
| `nos-ospfd`, `nos-ospfv3d` | `--dbd-max-headers`, `--state-dir` | operator | e2e `ospf-dbd-pagination` (headers) |
| `nos-sshd` | `--sshd-bin`, `--run-dir`, `--max-connections` | operator | defaults only in e2e (`ssh-login-shell`) |
| `nos-bgpd`, `nos-restd`, `nos-lldpd`, `nos-bfdd`, `nos-stpd` | only the common flags | | |
| `nos-provision` (in both images) | `--login-user`, `--login-password`, env `NOS_LOGIN_PASSWORD`, `--watchdog-socket`, `--pki-ca`, `--login-burst`, `--config-socket`, ~300 config-building flags | operator/dev | `bench-bgp.sh`, system test, e2e `pki`/`pki-crl` (`run_provision`); e2e config seeding reuses `build_ops` |
| `nos-rtr-stub` (lab image only) | positional `<listen> <prefix> <max-len> <asn> ...` | e2e/dev | `rpki` phase |
| `libpam_nos.so`, `libnss_nos.so.2` | none | operator | `pam`, `ssh-login-shell` |

e2e uses no flag of `nos-bgpd`, `nos-restd`, `nos-lldpd`, `nos-bfdd`, `nos-stpd`, `nos-sshd` beyond the supervisor ones.
