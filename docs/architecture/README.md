# Architecture (for contributors)

How NOS is built internally. Operators: see [docs/README.md](../README.md). The rules agents must obey are in the root [`CLAUDE.md`](../../CLAUDE.md).

- [config-protocol.md](config-protocol.md): config subscription requests/events, `Describe`, named transactions, config vs data plane
- [supervision.md](supervision.md): how `nos-watchdogd` spawns, reconciles and restarts every daemon
- [endpoint-broker.md](endpoint-broker.md): `ServiceRef` resolution and each daemon's query listener
- [linux-drivers.md](linux-drivers.md): `Driver` traits, VRFs, bridges, connected routes, the LACP push
- [ipc-security.md](ipc-security.md): mutual post-quantum TLS, identities, rotation, revocation, allow-lists
- [auth.md](auth.md): users, login flows, BGP session authentication
- [pam.md](pam.md): `pam_nos.so`, the PAM module that checks logins against `nos-watchdogd`
- [rpl.md](rpl.md): `nos-rpl` compiler/VM internals
- [logging.md](logging.md): `nos-log-client` and `nos-logd`
- [benchmark.md](benchmark.md): `tools/bench-bgp.sh`
- [development.md](development.md): toolchain pins, bump procedure, system test, containers
- [e2e-harness.md](e2e-harness.md): how `nos-e2e` drives NOS
