# NOS — Network Operating System

A network operating system built from scratch in Rust.

## Agent tooling requirements

Every agent working in this repo — the main session and any subagent spawned via the Agent tool (Explore, general-purpose, fork, etc.) — MUST always use:

- **`rtk`** for shell command output, per the "Command output" conventions at the bottom of this file. Subagents don't inherit the user's global CLAUDE.md, so this rule is restated here.
- **CodeGraph** (`codegraph_explore` MCP tool, or `codegraph explore "<query>"` from the shell) before grep/find or reading files, to locate or understand code — this repo has a `.codegraph/` index at its root.

The project's Claude tooling is tracked in `.claude/`, so every worktree (incl. `isolation: "worktree"` agents) gets it:

- `.claude/settings.json` wires the `PreToolUse` hook via `"$CLAUDE_PROJECT_DIR"`, never a relative path (a relative one exits 127 inside a worktree, #128).
- `.claude/hooks/codegraph-first.sh` denies `Grep` and `grep`/`rg` over the tree; append `# cg-ok` to a Bash command for a raw text scan (logs, non-code files).
- `.claude/commands/issue.md` is the `/issue` workflow.
- Machine-local files stay untracked: `.claude/settings.local.json`, `.claude/worktrees/`.

## Components

| Directory | Crate | Purpose |
|-----------|-------|---------|
| `proto/` | `nos-proto` | Shared wire types, IPC codec — single source of truth for all inter-process contracts |
| `proto-derive/` | `nos-proto-derive` | `#[derive(Cli)]` for `nos-proto`'s schema: every field's mandatory `#[cli(...)]` (help `Topic`, CLI words, aliases, sugar) becomes the CLI's config tree (`nos_proto::cli`) (#109) |
| `tcp-auth/` | `nos-tcp-auth` | Raw Linux `setsockopt` bindings for TCP session authentication (`TCP_MD5SIG`, TCP-AO) — no NOS dependencies, like `nos-proto` |
| `rpl/` | `nos-rpl` | Routing Policy Language — compiler and VM for BGP import/export policy scripts, no NOS dependencies, like `nos-proto` |
| `l2-socket/` | `nos-l2-socket` | Raw `AF_PACKET` L2 socket for `nos-lacp`/`nos-lldp`, plus `L2Unicast` for `nos-bfd` Echo — `unsafe` `sockaddr_ll`/BPF FFI, no NOS dependencies |
| `bfd-socket/` | `nos-bfd-socket` | `nos-bfd`'s raw-libc UDP FFI (cmsg, `setsockopt`); no NOS dependencies |
| `tc/` | `nos-tc` | Hand-encoded tc netlink (clsact, flower/fw, gact/skbedit, chains, per-action stats) shared by `nos-fdbd`, `nos-interfaced`, `nos-acld`; no NOS dependencies — see `tc/CLAUDE.md` |
| `password/` | `nos-password` | argon2id password hashing/verification for local users — no NOS dependencies; used by `nos-config` (hashing) and `nos-watchdog` (login verification) |
| `pki/` | `nos-pki` | Post-quantum mutual TLS (hybrid ML-KEM key exchange only, ML-DSA-65 certificates) over Unix sockets for every IPC connection, with `nos-watchdogd` as the certificate authority — identities are `nos://<role>/<name>` URI SANs, delivered to each daemon over its stdin and hot-rotated; also the TLS for `nos-restd`'s TCP listener and its clients (`nos_pki::rest`, a second CA); no NOS dependencies, like `nos-password` — see `pki/CLAUDE.md` |
| `pam/` | `nos-pam` | PAM module (`pam_nos.so`): checks a password against `nos-watchdogd`'s login broker, exports a login ticket (`LoginTicket`, #996, #992) — `pam/CLAUDE.md` |
| `nss/` | `nos-nss` | NSS `passwd` module (`libnss_nos.so.2`): sshd resolves NOS users (#999) — `nss/CLAUDE.md` |
| `log-client/` | `nos-log-client` | The `tracing` → `nos-logd` forwarding layer every daemon installs — depends only on `nos-proto`, like `nos-tcp-auth`/`nos-rpl` |
| `daemon/` | `nos-daemon` | Boilerplate every daemon shares: watchdog endpoint resolution, `nos-configd` fetch/subscribe, generic one-shot IPC query, `main()` identity + tracing bootstrap — see `daemon/CLAUDE.md` |
| `config/` | `nos-config` | Configuration store and IPC server |
| `bgp/` | `nos-bgp` | BGP-4 implementation |
| `rib/` | `nos-rib` | Routing information base daemon — best-path selection per routing table, applied to the kernel via a Linux driver (VRF device + routes) |
| `interface/` | `nos-interface` | Interface reconciliation daemon — one process manages every configured interface, applying addresses and VRF enslavement to the kernel via a Linux driver |
| `log/` | `nos-log` | Log collection daemon (`nos-logd`) — a single process collects structured log entries pushed by every other daemon into a bounded, disk-backed buffer, queryable by `nos-cli` |
| `ospf/` | `nos-ospf` | OSPF daemon — one process per `OspfInstance`; real RFC 2328 Hello-protocol neighbor discovery plus DBD/LSR/LSU/LSAck adjacency formation, reaching `Full` with a real per-area LSDB, over point-to-point and broadcast links, plus real RFC 2328 §16 SPF route computation pushed to `nos-ribd` — see `ospf/CLAUDE.md` |
| `ospf-common/` | `nos-ospf-common` | Address-family-agnostic logic for `nos-ospf`/`nos-ospfv3` — §9.4 DR/BDR election, §10.5 neighbor FSM, the generic LSA store (§13/§14), DBD exchange (§10.6-10.8), AllDRouters join/leave; no NOS dependencies — see `ospf-common/CLAUDE.md` |
| `ospfv3/` | `nos-ospfv3` | OSPFv3 (RFC 5340, IPv6 OSPF) daemon — one process per `Ospfv3Instance`, mirroring `nos-ospfd` (adjacencies to `Full`, SPF pushed to `nos-ribd`) over IPv6 raw protocol-89 sockets; RFC 7166 auth trailers, ABR and ASBR; no stub/NSSA or RFC 5838 multi-instance yet — see `ospfv3/CLAUDE.md` |
| `lacp/` | `nos-lacp` | LACP daemon (`nos-lacpd`) — one fixed process: IEEE 802.1AX LACPDUs over raw `AF_PACKET` for every `Lacp`-mode `PortAggregate` member, pushing the active set to `nos-interfaced` (owns the bond) — see `lacp/CLAUDE.md` |
| `stp/` | `nos-stp` | Spanning tree: pure IEEE 802.1Q RSTP core plus `nos-stpd`, one fixed process with a raw `AF_PACKET` BPDU socket per port, pushing states to `nos-interfaced` — see `stp/CLAUDE.md` |
| `lldp/` | `nos-lldp` | LLDP daemon (`nos-lldpd`), one fixed process: IEEE 802.1AB over raw `AF_PACKET` sockets on every `Interface` with `lldp transmit`/`receive`; `show lldp neighbors`; no rtnetlink — see `lldp/CLAUDE.md` |
| `acl/` | `nos-acl` | Access lists (`nos-acld`), one fixed process: every attached ACL compiled to tc flower filters (clsact, A/B chains, `nos-tc`) — see `acl/CLAUDE.md` |
| `bfd/` | `nos-bfd` | BFD (RFC 5880) core: packet codec, FSM, timers, authz; library only, no daemon yet — see `bfd/CLAUDE.md` |
| `fdb/` | `nos-fdb` | Forwarding-database daemon (`nos-fdbd`) — the MAC counterpart of `nos-ribd`: one per `BroadcastDomain` with a `vni`, owning its VXLAN device and bridge FDB; installs remote MACs from `nos-bgpd`'s EVPN routes, originates local Type-2/3; `show fdb <domain>` — see `fdb/CLAUDE.md` |
| `rest/` | `nos-rest` | REST API daemon (`nos-restd`) — one per `RoutingTable` with `rest-api` pinned: mutual TLS + HTTP/2 inside the VRF, every `show` query and the config tree as HTTP+JSON, OpenAPI + Swagger UI — see `rest/CLAUDE.md` |
| `ssh/` | `nos-ssh` | SSH daemon (`nos-sshd`) — VRF-bound listener handing each connection to `sshd -i`, PAM login — see `ssh/CLAUDE.md` |
| `cli/` | `nos-cli` | Interactive shell (binary `nos`) — main user-facing entry point |
| `watchdog/` | `nos-watchdog` | Process supervisor — starts and restarts the other component processes |

## Architecture

### Process model

Each component (BGP, RIB, OSPF, …) runs as a dedicated OS process. No component shares memory with another.

```
┌──────────────────────────────────────────────────────┐
│  nos-config process                                  │
│  ConfigStore (named transactions/running) + IPC      │
│  Listens on: /run/nos/config.sock                    │
└───────────────────────┬──────────────────────────────┘
                        │ Unix socket (nos-proto wire protocol)
          ┌─────────────┼─────────────┬─────────────┐
          ▼             ▼             ▼             ▼
    nos-bgp         nos-rib       nos-ospf       nos-cli
    process         process       process        (shell)
```

### IPC transport

**Transport:** Unix domain sockets carrying **mutually authenticated, post-quantum TLS 1.3** (`nos-pki`, `tokio-rustls` over `UnixStream`) — see "IPC security" below.  
**Serialization:** `postcard` (binary, compact, serde-based, no-alloc capable).  
**Framing:** 4-byte little-endian length prefix + postcard payload (see `nos-proto::codec::IpcCodec`).

This gives maximum performance for intra-host IPC with full Rust type safety — no HTTP overhead, no IDL outside the type system.

### Protocol spec sync

All wire types live in `nos-proto`. Since every component imports its message types from there, changing a type causes a **compile error in every consumer immediately** — stronger than protobuf's silent field-drop. This is the mechanism that keeps all processes in sync.

### Dependency graph

```
nos-proto   (no NOS dependencies)
    ↑               ↑
nos-config      nos-bgp, nos-rib, nos-ospf, nos-cli, …
(server)        (clients)
```

Component crates depend on `nos-proto` for types and `IpcCodec` for framing, plus `nos-daemon` for the shared client boilerplate. They do **not** depend on `nos-config` internals or on each other.


### Architecture details

Mechanisms live in [`docs/architecture/`](docs/architecture/README.md) (also benchmark, CI toolchain, e2e harness); the rules an agent must not break are here.

**Config protocol and transactions** ([page](docs/architecture/config-protocol.md))
- Edits happen in a named transaction held in `nos-configd`, not tied to a connection; `CommitTransaction` validates, replaces running config and broadcasts to every subscriber.
- `Describe`/`Topic` serve help text authored once in `nos-config`/`nos-proto` (mandatory `#[cli(topic = …)]` on every schema field); never duplicate it per client.
- A subscriber sends its request and never writes again: the server must not close a subscribed connection on request-side EOF.

**Process supervision** ([page](docs/architecture/supervision.md))
- `nos-watchdogd` supervises everything; per-object families (`nos-bgpd`, `nos-ribd`, `nos-ospfd`, `nos-fdbd`, `nos-restd`, `nos-sshd` (opt-in per table, root)) are spawned from `Request::SubscribeDiff`; `nos-interfaced`, `nos-logd`, `nos-lacpd`, `nos-lldpd`, `nos-stpd` are single fixed processes.
- The first diff on a connection is authoritative (stop anything not in it); `Modified` is a no-op at watchdog level because daemons re-resolve their own config.
- Crash backoff is exponential (1s to 30s); SIGINT then 10s then kill; `docker-compose.yml` keeps `stop_grace_period: 15s`.
- Every supervised process gets its identity on stdin (`ProcessSpec::with_identity`).

**Endpoint broker** ([page](docs/architecture/endpoint-broker.md))
- Daemons find each other through the watchdog (`ServiceRef` → socket path).

**Linux drivers** ([page](docs/architecture/linux-drivers.md))
- `nos-ribd` and `nos-interfaced` program the kernel through a swappable `Driver` trait (`--driver linux|noop`); capabilities come from file caps on the binaries.
- `nos-lacpd` never touches rtnetlink, and the kernel bond is always `BalanceXor`, never `Ieee8023Ad` (it would swallow the LACPDUs).

**Authentication** ([auth](docs/architecture/auth.md), [IPC security](docs/architecture/ipc-security.md))
- Password hashing lives in `nos-config`, never `nos-proto`; `nos-cli` logs in through the watchdog; `nos-restd` requires a client certificate except on `POST /v1/login`.
- Every IPC connection is mutual TLS, post-quantum only (hybrid `X25519MLKEM768`, ML-DSA-65 certificates); no plaintext or classical fallback (the REST listener and `Policy::Syslog` are the documented exceptions).
- Each server has a pure `allowed(role, &request)` with no wildcard arm; a new request variant must be classified before it compiles.
- `nos-configd --listen` stays Unix-only.

**Routing policy language** ([page](docs/architecture/rpl.md))
- `nos-rpl` has no NOS dependencies: consumers adapt their route type into `Input` and apply the `Verdict`; names resolve through a `Symbols` table built by the caller.
- Every policy path must reach `accept`/`reject` (checked at compile time); an unset peer-group policy is `deny-all`.

**Log collection** ([page](docs/architecture/logging.md))
- Every daemon installs `nos-log-client`'s `ForwardingLayer` next to its `fmt` layer (bounded channel, drops oldest, never blocks); `nos-logd` holds a disk-backed ring buffer.

## Development

```bash
make check   # build + fmt + clippy + test (matches CI's fast jobs)
make fix     # auto-fix formatting and clippy-fixable lints
make help    # list all available targets
make coverage  # line coverage, fails under COVERAGE_MIN (CI runs this) — excluded: tools/e2e, the Linux drivers, raw-socket FFI (see below)
```

- `make claude-md-size` (part of `make check`) keeps every `CLAUDE.md` under its ceiling in `tools/ci/claude-md-budget.txt`; move detail to `docs/` instead of raising it. Targets: root 20 KB, crates 8 KB, bgp/ospf 12 KB (#252).

**No external commands (#228).** Production code never shells out: use a crate (`rtnetlink`, `bollard`) or FFI. `clippy.toml` bans `std::process::Command`/`tokio::process::Command`, so `make clippy` fails on it. Exceptions carry `#[allow(clippy::disallowed_types, reason = "…")]`: the watchdog supervisor and tests that run built binaries or an independent oracle. `tools/e2e` needs none (it drives docker via `bollard`). A new exception needs its reason justified in the PR.

`COVERAGE_MIN` in the `Makefile` is 90% (#104, #131): raise it when a change lifts the total, never lower it. The metric excludes code that only runs against the real kernel — `*/driver/linux.rs`, `rib/src/driver/route_channel.rs`, `l2-socket/`, `ospf{,v3}/src/socket.rs`, `bfd/src/socket.rs`: a mock would only test the mock; `nos-e2e` is their real test.

Toolchain pins, the bump procedure, the unprivileged system test and the container workflow: [docs/architecture/development.md](docs/architecture/development.md).

### Two-router end-to-end verification

`tools/e2e` (`nos-e2e`, run as `cargo run -p nos-e2e -- <phase|group|all>`) stands up two independent `nos-watchdogd` containers on a shared docker network (through the `bollard` crate — no `docker` CLI, no shell script), configures each as a full BGP router peering the other purely over its REST API, and checks the logs (streamed back over the same REST API) and the real kernel for what each phase proves. Every phase, its requirements, the CI groups and what each asserts: [docs/e2e-phases.md](docs/e2e-phases.md) (kept in sync with `phases::ALL` by a unit test). `base`/`drivers`/`rpl`/`ospf-suite`/`multi`/`pki-suite` are self-contained groups run as parallel CI jobs by `.github/workflows/verify-e2e.yml`; `all` leaves the containers up for `logs`.

**How the harness drives NOS** (seeded config, REST provisioning/logs, `bollard`; details and gotchas in [docs/architecture/e2e-harness.md](docs/architecture/e2e-harness.md)): it uses the REST API for everything. Run `make docker-build` first (the harness never builds the image); `make e2e-preflight` checks the host kernel modules when `up` fails with "REST API never came up".
- BGP sessions can sit Idle for the whole connect-retry timer after a fresh start or a config change (RFC 4271 §6.8 collision resolution), and the default is 120s. `nos-e2e` sets `connect-retry-time` to 3s on every peer-group it provisions (`nos-provision --connect-retry-time`), so "session established" waits are 60s at most; phases that change config still take a baseline first and wait for a *new* session rather than a stale log line.

### New features require an end-to-end Docker verification phase

`cargo test`/`clippy` only prove the pure logic (validators, ops, diffing, bytecode) is correct — they never touch a real kernel, a real `rtnetlink` call, or a real two-process IPC round trip, because every driver test in this codebase runs against `NoopInterfaceDriver`/`NoopRibDriver`, not `LinuxInterfaceDriver`/`LinuxRibDriver`. A feature that programs the kernel (a new `Driver` behavior), adds a new cross-daemon IPC call, or changes what gets advertised/learned over a real BGP session is **not done** until it's also proven against the real thing: add a new phase to `nos-e2e` (or extend an existing one if the feature is a variant of something already covered, e.g. a new RPL construct extends `policy`/`redistribute-policy`/`communities` rather than getting its own phase) and **run it** — don't just write it and assume it passes. A unit-test-only change here is only sufficient for pure logic with no OS/IPC surface (e.g. a new validator, a new bytecode op with no kernel effect).

How to add a phase, using `loopback` (`tools/e2e/src/phases/drivers.rs`) as the template:

1. **Provisioning**: if the feature needs new flags (a new op sequence to apply), add them to `tools/nos-provision/src/lib.rs`'s `Args` and push the ops in `build_ops` — one flag per independent toggle, matching the existing style (`--md5-password`, `--route-reflector-client`, etc.). Keep it a thin, mostly-linear list of `ConfigOp`s; it's a test fixture, not a general tool.
2. **A phase function** in `tools/e2e/src/phases/{bgp,drivers,ospf}.rs`: `async fn <thing>(w: &mut World) -> anyhow::Result<()>`. `w.a()?`/`w.b()?` are the routers; `a.provision(&["--flag", "value"])` applies the base flags plus yours over REST (`provision_flags` takes the complete list, for a phase whose base differs). Then assert on the log line the daemon itself already emits, never by inspecting kernel state directly — the runtime image has no `ip`/`iproute2`:
   - `a.wait(PATTERN)` — first-occurrence wait, for a pattern that can't have appeared earlier in this run.
   - `a.wait_new(PATTERN, BASELINE, SECS)` with `BASELINE = a.count(PATTERN)` taken **before** provisioning — for anything an earlier phase may already have logged (re-establishing after a config change). `a.established()` waits for a BGP session.
   - `a.assert_quiet(PATTERN, BASELINE, SECS)` — a negative check (no new match).
   - Find the exact text by reading the `info!`/`debug!`/`warn!` call in the code you wrote: the message string is the anchor, followed by `field=value` for each field in declaration order, so `info!(interface = %x, "did the thing")` matches `"did the thing interface=<value>"`. A quoted (`reason="shutdown"`) or `Debug` (`source=Some(Ospf)`) field renders that way too. Patterns are POSIX BRE (`.*` wildcards, `\[ \]` literals, `\|` alternation; a bare `(` is literal).
   - If a check needs a deterministic derived value (like a `nos-ribd`-allocated table id), work out *why* it's deterministic in this fixed topology (e.g. `rt1` is always the first and only routing table any scenario configures per container, so it always gets kernel table id 100) and say so in a comment next to the constant in `consts.rs`.
3. **Wire it in**: add the phase name to `phases::run`'s `match`, to `phases::ALL` and the relevant group in `phases::group` (in a sensible position relative to what it depends on), and add a row to `docs/e2e-phases.md` (`cargo test -p nos-e2e` fails until the table matches).
4. **Run it**: `make docker-build && cargo run -p nos-e2e -- up && … -- established && … -- <new-phase>`, then `… -- established` again afterward to confirm the existing session wasn't disturbed, then `… -- down` to clean up. Fix forward until it passes — a phase that's never actually been run against real containers isn't verification, it's an unverified guess at what the logs will say.

<!-- rtk-instructions v2 -->
# Command output

Command output here is condensed to save tokens, keeping every signal and
dropping costly noise. Treat it as the complete result: run commands
normally, and batch related commands into one call to avoid extra turns.
Truncated results state their recovery path in their own output. Re-run a
command as `rtk proxy <cmd>` only when its result is unusable: empty when
output was clearly expected, contradicting its exit code, or garbled.
<!-- /rtk-instructions -->