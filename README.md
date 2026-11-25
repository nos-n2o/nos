<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo/nos-horizontal-dark.svg">
    <img src="docs/assets/logo/nos-horizontal.svg" alt="NOS" width="420">
  </picture>
</p>

# NOS — a network operating system built from scratch in Rust

NOS is a multi-process router operating system: one OS process per routing
protocol/component (BGP, OSPF, OSPFv3, LACP, LLDP, EVPN/VXLAN forwarding,
interface/RIB reconciliation, ...), talking over mutually authenticated
**post-quantum** TLS Unix-socket IPC, applying reconciled state to a real
Linux kernel (`rtnetlink`, VRFs, bridges, bonds, VXLAN). `nos-watchdogd`
supervises every other process and is also the internal certificate
authority.

Architecture and protocol internals: [`docs/architecture/`](docs/architecture/README.md).
Using a router (concepts, shell, REST): [`docs/`](docs/README.md).
Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md). Coding agents: see
[`CLAUDE.md`](CLAUDE.md). This file only orients a human and gets a router
running.

## Features

- **BGP-4** (RFC 4271): RFC 2385 (MD5) / RFC 5925 (TCP-AO) session auth,
  RFC 5082 GTSM, RFC 4456 route reflection, RFC 7947 route-server
  transparency, RFC 6793 four-octet ASNs, RFC 7606 error handling,
  MRAI pacing, route flap damping.
- **EVPN/VXLAN** (RFC 7432): Type-1/2/3/4 routes, multi-homing with DF
  election, MAC mobility, nexthop-group aliasing.
- **OSPFv2** (RFC 2328) and **OSPFv3** (RFC 5340): Hello/DBD/LSR/LSU/LSAck,
  DR/BDR election, SPF + LFA (RFC 5286) backup paths, ABR/ASBR, RFC 5709 /
  RFC 7166 (RFC 7474) authentication.
- **LACP** (IEEE 802.1AX) and **LLDP** (IEEE 802.1AB), each a real
  from-scratch protocol implementation over raw `AF_PACKET` sockets.
- **RPL** — an imperative routing-policy language for BGP import/export
  filtering (community/AS-path/prefix-list matching and rewriting).
- **REST API** (`nos-restd`) with a generated OpenAPI document and Swagger
  UI, config-tree-as-URL transactions, mutual TLS.
- **Post-quantum mutual TLS everywhere** (`nos-pki`): hybrid ML-KEM key
  exchange, ML-DSA-65 IPC certificates, no classical fallback.

See the [repository layout](#repository-layout) for the full component
list, including static routing, VLAN switching/SVIs, port aggregation, and
structured log collection.

## Quick start

Requires Docker.

```sh
make docker-build                 # build the nos image
docker compose up -d watchdog     # start the router (nos-watchdogd + its daemons)
docker compose run --rm cli       # interactive shell, against the running router
```

The shell prompts `login:`/`password:`. On first boot with no configured
users it seeds `admin`/`admin` — change it (see
[`docs/architecture/auth.md`](docs/architecture/auth.md)).

## A minimal config example

```
configure test
edit bgp instance my-instance
set asn 65000
set router-id 1.1.1.1
top
commit
show bgp summary
```

User documentation (concepts, the `nos` shell, the REST API and how they map to each other) is in [`docs/`](docs/README.md).
See [`docs/cli.md`](docs/cli.md) for the full command reference.

## Build natively

- Install Rust through `rustup`: it picks the pinned toolchain (1.100.0) from `rust-toolchain.toml`.
- `cargo build --workspace` builds every daemon and the `nos` shell; `make check` runs build + fmt + clippy + test.
- A host with a different `rustc` and no rustup runs `make check` inside the `nos-ci` image instead (`make ci-image`); details in [`docs/architecture/development.md`](docs/architecture/development.md).
- Running the daemons for real needs Linux >= 6.3 (the watchdog sets MDWE on itself and every daemon inherits it, #1210), capabilities and kernel modules (`make e2e-preflight` checks them); the e2e harness needs Docker and the built image.

## Development

```sh
make check   # build + fmt + clippy + test — run before pushing
make help    # list every Make target (deny, audit, sast, miri, coverage, mutants, ...)
```

Everything here only proves the pure logic is correct. Features that touch
a real kernel or a real multi-daemon IPC round trip are verified against
real Docker containers instead:

```sh
cargo run -p nos-e2e -- up established   # bring up two routers, wait for BGP to establish
cargo run -p nos-e2e -- all              # every verification phase (see tools/e2e)
```

`tools/bench-bgp.sh` benchmarks `nos-bgpd` against GoBGP/BIRD/FRR on the
same load. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/architecture/development.md`](docs/architecture/development.md) for CI
details and the rest of the tooling.

## Repository layout

| Directory | Crate | Purpose |
|-----------|-------|---------|
| [`proto/`](proto/CLAUDE.md) | `nos-proto` | Shared wire types, IPC codec |
| `tcp-auth/` | `nos-tcp-auth` | Raw `TCP_MD5SIG`/TCP-AO bindings |
| `rpl/` | `nos-rpl` | Routing Policy Language compiler/VM |
| `l2-socket/` | `nos-l2-socket` | Raw `AF_PACKET` L2 socket (LACP/LLDP) |
| `password/` | `nos-password` | argon2id password hashing |
| [`pki/`](pki/CLAUDE.md) | `nos-pki` | Post-quantum mutual TLS for every IPC connection |
| `log-client/` | `nos-log-client` | `tracing` → `nos-logd` forwarding layer |
| [`config/`](config/CLAUDE.md) | `nos-config` | Configuration store and IPC server |
| [`bgp/`](bgp/CLAUDE.md) | `nos-bgp` | BGP-4 implementation |
| [`rib/`](rib/CLAUDE.md) | `nos-rib` | Routing information base daemon |
| [`interface/`](interface/CLAUDE.md) | `nos-interface` | Interface reconciliation daemon |
| [`log/`](log/CLAUDE.md) | `nos-log` | Log collection daemon |
| [`ospf/`](ospf/CLAUDE.md) | `nos-ospf` | OSPF daemon |
| `ospf-common/` | `nos-ospf-common` | Logic shared by OSPFv2/OSPFv3 |
| [`ospfv3/`](ospfv3/CLAUDE.md) | `nos-ospfv3` | OSPFv3 (RFC 5340) daemon |
| [`lacp/`](lacp/CLAUDE.md) | `nos-lacp` | LACP daemon |
| [`lldp/`](lldp/CLAUDE.md) | `nos-lldp` | LLDP daemon |
| [`fdb/`](fdb/CLAUDE.md) | `nos-fdb` | EVPN/VXLAN forwarding-database daemon |
| [`rest/`](rest/CLAUDE.md) | `nos-rest` | REST API daemon |
| [`cli/`](cli/CLAUDE.md) | `nos-cli` | Interactive shell (binary `nos`) |
| `watchdog/` | `nos-watchdog` | Process supervisor and certificate authority |
| `tools/nos-provision` | `nos-provision` | Scriptable config client (used by benchmarks/e2e) |
| `tools/e2e` | `nos-e2e` | Two-router Docker end-to-end verification harness |

## Status

Actively developed. Every protocol feature is verified against real Docker
containers and a real Linux kernel by `nos-e2e` (see "Development" above),
not unit tests alone — this is not a claim of production-readiness.

## Licence

GPL-3.0 — see [`LICENSE`](LICENSE).
