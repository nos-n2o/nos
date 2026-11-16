# nos-daemon — shared daemon boilerplate

Library crate (#418) holding what every NOS daemon repeated verbatim. Depends only on `nos-proto`, `nos-pki`, `nos-log-client`; never on a component crate.

## Modules

- `watchdog::{resolve_once, resolve_with_retry}`: resolve a `ServiceRef` against `nos-watchdogd`'s broker; the retry loop is a fixed 1s delay until success or shutdown (`None`).
- `config::{ConfigClientError, fetch_config, subscribe_diff}`: one-shot `Get` and a `SubscribeDiff` stream. A diff is only a resync trigger; callers re-fetch the config.
- `ipc::one_shot<Req, Ev>(socket, Role, req) -> Option<Ev>`: connect as `Role`, send one request, read one reply; the exchange is bounded by a 10 s reply timeout (`IpcError::Timeout`); any failure is a `trace!` and `None`. Per-daemon `get_interface`/`get_vrf_name` stay in their crate as thin wrappers matching the expected reply variant.
- `bootstrap::{identity, init_tracing}`: stdin identity, then registry + `EnvFilter` (default `trace`) + fmt + `ForwardingLayer` + panic hook.
- `liveness::start(watchdog_socket)`: heartbeat to `nos-watchdogd` (#1150): a runtime task bumps a counter, a std thread sends `Heartbeat` every 5 s only if it advanced. Call it right after `init_tracing`; see supervision.md "Liveness".

## Rules

- `init_tracing` takes the log shutdown receiver: the daemon flips it last so shutdown-time log lines (e.g. OSPF's RFC 2328 §14.1 flush) are still forwarded.
- A long-lived subscription stream (`rib_push_client`, `link_client`) is not a one-shot: keep it in the daemon.
- Adding a daemon-specific helper here is wrong; only code identical in 3+ daemons belongs.

## Tests

- Each module runs against `nos_pki::testing::shared()` listeners (reply, refused, malformed, closed). No e2e phase: behaviour-preserving move, exercised by every daemon's phases.
