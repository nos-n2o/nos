# nos-bgp — BGP Component

BGP-4 implementation for NOS (binary `nos-bgpd`, one process per `BgpInstance`, dynamically spawned by `nos-watchdog` — see `docs/architecture/supervision.md`).

Details: behaviour and config in `docs/protocols/{bgp,evpn-vxlan,routing-policy}.md`; how it is built (log lines, `ponytail:` ceilings) in `docs/protocols/bgp-internals.md`; e2e phases in `docs/e2e-phases.md`. Only editing rules are kept here.

## Scope

Resolves peers and VRF from `nos-configd`, runs the FSM over VRF-scoped TCP, exchanges routes with `nos-ribd`/`nos-fdbd`. Open work: `bgp/TODO.md`.

## VRF resolution

`BgpInstance.routing_table` is a reflexive field (`docs/schema-reference.md`); `nos-bgpd` resolves it to a Linux VRF name through `ServiceRef::RibTable` + `RibRequest::GetVrfName` (`VrfRequirement`):
- `Invalid` (no owning table): a config error, never a "default VRF" fallback; nothing is opened, error logged every resync.
- `Pending` (table exists, VRF not yet created): transient, `debug` log, retried by the 10s tick (VRF readiness is no config diff).
- `Resolved(name)`: the only state in which anything opens.

## Raw TCP session model

- Per peer, an active retry loop plus one shared passive listener (`0.0.0.0:179` + `[::]:179`), both scoped into the VRF by `SO_BINDTODEVICE` (`tcp.rs`).
- Skip dialing while `PeerSlot::is_established` (either role).
- Retry sleep is jittered `[0.75, 1] x connect_retry_time` (`session::jittered`) (#158).
- Shutdown/removal: `PeerSlot::stop` + abort listeners before the Cease (#444).
- **Both roles must be stopped on reconcile.** `peer_tasks` owns only the active loop; passive sessions live on the `PeerSlot` (`set_passive_task`/`stop_passive`). Both stops are `abort()`s that skip `fsm::run`'s exit path, so `reconcile_peers` calls `BgpRib::peer_disconnected` itself, or Adj-RIB-In outlives the session.

## Session authentication

- Socket-level only: `fsm.rs` never sees it. MD5 or TCP-AO, mutually exclusive (one per socket); `setsockopt` lives in `nos-tcp-auth`. Keys are admin labels (#508): `ResolvedAuth::resolve(&BgpAuth, &Config)`, subscribed with `DiffScope::Admin`, so a rotation restarts the peer except what `session::ao_delta` expresses.
- The listener is shared: keys are installed per peer address (`applied_auth`, `sync_listener_auth`; `spawn_listeners` primes them).
- `tcp::apply_auth(on_listener)` strips `set_current`/`set_rnext` for a socket in `LISTEN` (`TCP_AO_ADD_KEY` returns `EINVAL` otherwise); the active side keeps them.
- Hitless rollover (#83): the kernel does RFC 5925 §7.5.2 per connection; `ao_delta` returns `None` (restart) for MD5, a changed kept key or a reused RecvID, else an Established session gets `FsmCommand::UpdateAo` (errors such as `EBUSY` reset).

## GTSM / `max-hops`

`tcp::bind_listener` always sets TTL 255 or a GTSM active side drops the SYN-ACK; the minimum TTL is per socket (`apply_max_hops`).

## BGP finite state machine

- `fsm::step` is the pure transition core, unit-tested; `fsm::run` owns the framed socket and timers. `UPDATE`/`ROUTE_REFRESH` bypass `step` (handled in `run`'s read branch, only once `Established`).
- Send to a peer only via `OutboxTx::send` (bounded, coalescing, #395).
- Every well-formed inbound message resets the hold timer (RFC 4271 §4.4), in the read branch.
- Timer defaults and floors live in `nos_proto`; OPEN check order: internals page.
- The `PeerSlot` command channel is polled only while `Established`, so one task contends for it.
- 4-octet AS: `AS_TRANS` without capability 65 is a bad peer AS; a peer without it gets `BgpCodec::two_octet_as` (`AS4_PATH` merge). RFC 9072 OPEN is emitted only above 255 bytes.

## Aggregation (#78)

All in `rib/aggregate.rs`: runs before `fan_out` in `recompute_and_propagate`; the aggregate is a local candidate in `BgpRib.aggregated`, next-hop-self and never pushed to `nos-ribd` (no discard route).

## Malformed UPDATE (RFC 7606)

`parse_update` resets only for framing errors; a bad attribute value or missing mandatory attribute is treat-as-withdraw, rewritten there (NLRI -> `withdrawn_routes`, `mp_reach` -> `mp_unreach`, `attributes = None`), so `BgpRib::handle_update` needs no special case.

## Damping

`damping::Damping` is keyed by (peer, prefix); an identical re-announcement is no change (#160).

## Collision resolution

`collision::PeerSlot` is shared by both roles. An already-`Established` connection beats an ID compare; a tie keeps the first registered. `fsm::run` calls `BgpRib::peer_disconnected` **only if it registered** (its `registered` flag), or a collision loser wipes the winner's `adj_rib_in`/`peer_outbox`; guarded by `handshake.rs`'s `collision_leaves_exactly_one_side_running`.

## Administrative shutdown

`session::cease_reason` picks the Cease subcode for every session `reconcile_peers` stops (2 shutdown with an RFC 9003 message, 3 de-configured, 6 other change); `FsmCommand::Cease` carries already-encoded `data`.

## Maximum prefixes

Counters (`path_counts`) change only in `put_path`/`take_path`, the sole Adj-RIB-In mutators (`prefix_counters_match_a_recount_through_every_mutation`). The hold lives on `PeerSlot`; the Cease is queued once (a queued command outlives the session). No built-in cap; `limit 0` = explicitly uncapped.

## Route refresh

Route Refresh (2) and Enhanced (70) are always advertised. The RFC 7313 stale deadline is one per family, per session. Peer requests pass `RefreshLimiter` (2, then 1/10s). `send_route_refresh` sends nothing without the peer's capability.

## Soft reconfiguration inbound (#859)

`rib/retain.rs` keeps pre-policy copies; `remove_path` drops them. `Reapply` (`diff_peers`) applies policy/flag-only changes in place; `session/reeval.rs` re-evaluates in chunks.

## RPKI

Runs inside `nos-bgpd` (#17). `BgpRib::set_vrps` re-validates in place; peers whose import policy `reads_validation_state()` are route-refreshed (re-evaluated if retained), 5s after a burst. RFC 8097 wire order (0 valid, 1 not-found, 2 invalid) differs from `nos_rpl::ValidationState`'s discriminants.

## BMP (#878)

`Hub` in `SharedRib` (`bgp_rib.bmp()`); the FSM only pushes under a std mutex. Peer Up/Down at `ReportEstablished`/the `registered` exit. Dial only on `Resolved`. Route Monitoring (#864): pre-policy = the received UPDATE; post-policy = a tap at every Adj-RIB-In mutation (`learn_*`, `drop_*`, `remove_path`, `settle`): a new site must tap. Stats: a new drop site bumps `PeerStats`. Out (#867): `fsm::write_update`.

## Graceful restart (#12)

- Pure decisions in `gr.rs`; F bit from `BgpRib::gr_forwarding`; `peer_disconnected(peer, Disconnect)` with `Transport`/`Graceful`/`Hard` (`fsm::disconnect_kind`).
- A Cease with N exchanged goes out as a Hard Reset (subcodes 1-4); 6 stays graceful. SIGINT sends Cease/Administrative Shutdown first (`SessionManager::shutdown`) so peers stop forwarding to a vanished VRF.
- Deferral (`gr::Deferral`) blocks every outbound path (`fan_out`, `propagate_add_path`, `resend_all`, EVPN, `push_snapshot`) and also waits for `nos-ribd`'s first redistribution `Full` (`redistribute_seen`).

## Confederations, local-as, roles

- `session::PeerKind` (`Internal`/`ConfedExternal`/`External`) drives what each peer sees; `ResolvedPeer::open_as` gives the OPEN AS, `PeerOutbox::prepend_external` (shared by `build_advertisement` and `evpn_out::advertise`) the path prepend; OPEN/AS_PATH per kind: internals page.
- Step 6 ranks external > confed-external > internal (`peer_rank`); the RFC 4456 gate stays keyed on `Internal`. RPL sees the flat path (`AsPath::flat`).
- Validation: `bgp_instance::valid_local_as`/`valid_role`/`valid_route_reflection_and_server`. Roles/OTC (#220, #221): `fsm::negotiate_role`, `otc_leak`.

## Route reflection / route server

Route-server candidates (`rs_candidates`) are never filtered by feasibility or aggregates (RFC 7947 transparency).

## ADD-PATH (#13)

- The codec's rx set (reader `add_path_afis`) and tx set (writer) differ; encoding writes an id whenever the update has one, so the RIB must never hand a tx session an id-less NLRI.
- `propagate_add_path` runs first in `recompute_and_propagate`, before the "best unchanged" return (a non-best path can change the top N), and beside `fan_out` in `aggregate.rs`.
- A path keeps its id while selected; an entering path takes the lowest freed id, else `add_path_next_id` (monotonic per (peer, prefix), never recycled). Step 10 compares `(peer, path id)`.

## Communities

The RFC 4360 transitive bit is enforced on eBGP export (#162). RFC 1997: `decision::well_known_blocks` (#873). RFC 8326 (#860): knobs outside `ResolvedPeer`.

## EVPN and MAC mobility

- `AddressFamily::L2vpnEvpn` is appended last in the enum (postcard indexes by position). `evpn_adj_rib_in` is keyed by `EvpnNlri::route_key` (attribute fields zeroed, #188); best path does not apply (RFC 7432 §15 aside). `evpn_import_policy` (#502, `None` = accept all) gates Type-1/2/3/5 in `learn_evpn` before mobility (reject = withdraw, Type-4 exempt).
- MAC mobility has **no withdraw**: a sequence only means something relative to the last one seen, so `MacMobility` forgets a `(VNI, MAC)` only after an hour of silence (`EXPIRE`).
- Same ESI is not a move (#172): `MacMobility::holds`; else PEs on one segment freeze each other as duplicates.
- Flowspec, VPN (keyed by (RD, prefix), every RT kept, no ADD-PATH), VRF import (`vpn::VrfSet`; PE via the underlay's `ResolveNextHop`): internals page.
- `nos-bgpd` is dumb about origination: `nos-fdbd`/`nos-ribd` supply RD, RTs, VTEP, VNI, label (`evpn_local` by `EvpnSource`, `vpn_local` by table).

## L3VPN (#573), RT-Constraint (#875)

- RT-Constraint interest is the per-peer `rtc_adj_rib_in` (stale entries included), cached as `PeerOutbox.rtc_interest`; `None` = family not negotiated = no filtering. Type-4 is never filtered.

- A reflector holds every VPN path whatever its RTs (no VRF needed) and keeps label, RD and next hop; a VRF export is next-hop-self.
- Imported routes are never re-exported; a route with a VRF's own Site of Origin is not imported into it.
- The label is owned and persisted by `nos-ribd`, never `nos-bgpd`.
- `bgp/src/vpn/` is the shared RD/RT core (`VpnKey<T>`, `VrfSet`); VPN Flowspec (#574) must reuse it. Policies see `this.bgp.rd`.

## Backup path, multipath (#70)

`backups`/`multipaths` are updated before the `unchanged` early return so a sibling reaches `nos-ribd` without touching Loc-RIB or advertisements; only `best` is advertised. Multipath = ties on steps 1-7 plus the same neighbouring AS; a backup must not share an installed next hop.

## IGP cost, next-hop feasibility

`igp_client.rs` polls `nos-ribd` every 2s. Infeasible candidates (`next_hop_feasible`) leave the decision entirely, except before the first `set_igp` and for route-server clients; `set_igp` re-decides every Adj-RIB-In prefix (details: internals page).

## BFD (#286)

`bfd` stays out of `ResolvedPeer` (no reset on add/remove). `bfd_client.rs` acts only on Up to Down; `BfdDown { flush }` needs the C bit at both ends (RFC 5882 §4.3).

## Modules

| Module | Role |
|--------|------|
| `main.rs`, `reconcile.rs` | Startup, resync on diffs + 10s tick (`classify_vrf`, `restart_check`) |
| `session.rs`, `tcp.rs`, `collision.rs` | `SessionManager`, `diff_peers`, `ao_delta`; VRF-scoped sockets; `PeerSlot` |
| `fsm.rs`, `status.rs`, `gr.rs`, `mrai.rs`, `damping.rs`, `mac_mobility.rs` | State machine and per-peer state |
| `message.rs`, `evpn.rs`, `flowspec*.rs`, `vpn/`, `as_path.rs` | Wire codecs (`BgpCodec`) |
| `rib.rs`, `rib/` | RIB core; `decision`, `adj_in`, `gr`, `aggregate`, `evpn_out`, `flowspec_out`, `vpn_out`, `vpn_import`, `rtc`, `shared`, `tests/` |
| `page.rs` | Keyset paging (#722/#723), generic: `Snapshot<K>`, `Keyed`, `page` |
| `rib_push_client.rs`, `fdb_push_client.rs`, `vpn_push_client.rs`, `acl_push_client.rs`, `igp_client.rs` | Pushes wake on `SharedRib`'s write generation (#420); rib/fdb/vpn EOF-watch via `push_conn` (#718) |
| `rib_client.rs`, `interface_client.rs` | One-shot queries (`nos_daemon::ipc::one_shot`) |
| `rpki/`, `server.rs` | `vrp.rs`/`rtr.rs`; `--listen-socket`, `allowed(role, &request)` with no wildcard arm |

Tests: `bgp/tests/`, `reconcile_tests.rs`, `fsm_tests.rs` (#344).
