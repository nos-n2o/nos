# nos-ospf — OSPF Component

OSPFv2 daemon for NOS (binary `nos-ospfd`, one process per `OspfInstance`, dynamically spawned by `nos-watchdog` — see `docs/architecture/supervision.md`).

Details: behaviour and config in `docs/protocols/ospf.md`; how it is built (functions, log lines, `ponytail:` ceilings, not-done lists, the module table, per-feature walk-throughs) in `docs/protocols/ospf-internals.md`; e2e phases in `docs/e2e-phases.md`. This file keeps only the rules to respect when editing the crate. OSPFv3 is `ospfv3/CLAUDE.md`.

## Scope

`nos-ospfd` resolves its instance, areas and profiles from `nos-configd` and runs RFC 2328 on every `Subinterface.ospf_profile` (point-to-point) and `BroadcastDomain.ospf_profile` (broadcast, DR/BDR) attach point: raw protocol-89 socket, Hello to `Full`, per-area LSDB, SPF pushed to `nos-ribd` (`RibRequest::PushOspfRoutes`). A loopback (`Interface.ospf_profile`) has no peer and is log-only: it only feeds `LinkManager.stub_networks`. Modules: `main`, `rib_client`, `interface_client`, `link_client`, `packet`, `lsa`, `lsdb`, `exchange`, `neighbor`, `election`, `socket`, `link` (+ `link/{rx,flood,grace,originate}.rs` and `link/tests/`, split from one file in #424), `spf`, `rib_push_client`, `reconcile`, `server`, `boot`.

## Shared with OSPFv3

- `nos-ospf-common` holds the pure RFC 2328 §9.4 DR/BDR election and §10.5 neighbor FSM (`neighbor::step`, `election::elect`) for both daemons; no NOS dependencies. `run_election`'s candidate pool takes every neighbor at `TwoWay` or later, or a router alone on the segment re-elects itself the moment its only neighbor passes `TwoWay`.
- `nos-ospf-common::exchange` holds the DBD exchange, LSR/LSU handling, the delayed-ack queue and `LSAck` handling for both daemons (#430, #431); `exchange.rs` here only supplies v2's closures (`in_area_scope`, `is_opaque`, type-9 to the link store), `Params` (`dbd_options(stub)`, the peer's O-bit) and its two stores (no AS store).
- The `link::LinkSocket`/`LinkManager::with_opener` test seam, the `biased;` select and the RFC 3623/5187 helper rules are mirrored in `ospfv3/`; change one, check the other.

## Link and exchange rules

- `packet.rs`, `lsa.rs`, `exchange.rs`, `neighbor.rs`, `election.rs`, `spf.rs` are pure (no I/O); `exchange` returns `Action`s for `link.rs` to carry out (`bgp::fsm::step`'s shape). `packet.rs` has no `nos-proto` dependency (`packet::CryptoAlgorithm` mirrors the proto enum, converted in `link::LinkAuthConfig`).
- `socket.rs` binds to the link's own interface, never the VRF: a raw socket has no port to demultiplex by, so a VRF bind makes every link in it hear every other link (the DBD sequence-mismatch storm). Hello is multicast 224.0.0.5 on every network type; DBD/LSR/retransmitted LSUs are unicast to the neighbor's last Hello source; on broadcast links the periodic LSU flood and delayed LSAck are multicast (#879, below). Multicast loop is off.
- `on_dbd_in_exstart` accepts a real negotiation attempt or the peer's one reply/poll, on both sides (a peer's first attempt is dropped when we have no adjacency yet, so only the reply ever arrives). It processes that chunk but only fires `NegotiationDone`; termination is decided in `Exchange` only.
- A negotiation-shaped duplicate in `Exchange` is ignored. Treating it as `SeqNumberMismatch` makes both sides re-pick sequence numbers in lockstep forever.
- An Init DBD in `Loading`/`Full` is `SeqNumberMismatch`; the slave answers a duplicate final poll from its kept last DBD (`retransmit_pending` resends only in `ExStart`/`Exchange`).
- DBD pagination budget: `exchange::mtu_based_max_headers`; `--dbd-max-headers` is test-only. `exchange::mtu_acceptable` drops a larger neighbor MTU unless `mtu_ignore`.
- LSR/LSU/LSAck are cut to the link MTU (#806): every send goes through `link::rx::split_{lsr,lsu,lsack}` (`chunk_by_budget`, budget `mtu - 20 - 24 - digest [- 4 for LSU]`, an oversize LSA goes alone), one signed packet per chunk; a new send site must use them. `socket.rs` receives into a 64 KB buffer with `MSG_TRUNC` and drops a truncated datagram with a warn.
- Acks are delayed and batched (RFC 2328 §13.5, `pending_acks`, flushed by the 5s `RXMT_INTERVAL` sweep). Flooding is a periodic full-area resend (`flood_full_neighbors`) plus `FloodNow` on shutdown; event-driven flooding is deliberately not built.
- One `Lsdb` per area (`Arc<Mutex<_>>`), plus one per link for type-9. `Lsdb::install` takes only a strictly newer instance; `install_received` adds `MinLSArrival`. A MaxAge LSA with no held copy and not requested is acked and discarded (§13 step 4), or two routers reinstall each other's echo forever.
- Self-originated LSAs are held with their real wire checksum (`lsa::fill_checksum`), or a neighbor's echo supersedes the held copy and undoes a flush. Premature aging (§14.1) reinstalls at `MAX_AGE` with the sequence number unchanged; every origination pass ends with `withdraw_undesired`.
- Shutdown (`LinkManager::shutdown`) flushes self-originated LSAs and keeps links up `PREMATURE_AGE_FLOOD_WINDOW` (6s); with RFC 6987's on-shutdown hold the sum stays <= 9s (`const` assertion) inside the watchdog's 10s SIGINT budget (`stop_grace_period: 15s` for `docker stop`).
- Own LSA flooded back newer (§13.4, #731): `Lsdb::mark_reflected` + `LinkManager::reoriginate` wake `origination_pass`; `install_self_originated` takes the mark. See `docs/protocols/ospf-internals.md`.
- Origination runs on its own 2s tick and aging on a 1s tick (`--lsa-age-multiplier`, test-only), both independent of the 10s config re-apply tick. LSAs leave with `INF_TRANS_DELAY` added to the wire age only.
- `run()`'s select is `biased;` (Hello first, RFC 4222); `note_alive` runs after `accept_crypto_sequence`; any packet proves liveness only for a neighbor at `ExStart` or later.

- **Multicast flood** (#879): `flood_full_neighbors`/`flush_pending_acks` pick `nos_ospf_common::drouters::flood_dest` (DR/Backup 224.0.0.5, else 224.0.0.6; p2p/p2mp/virtual stay unicast) and send each chunk once via `LinkSocket::send_flood`; a send error falls back to unicast for that pass. `retransmit_pending`, the LSR answer and Grace-LSAs stay unicast.
- **AllDRouters** (#855): `link::rx::sync_all_drouters` joins/leaves 224.0.0.6 (DR/Backup on broadcast only) after every election pass via `OspfSocket::set_all_drouters`; logged on change, `ospf-dr` e2e asserts it.
- BFD (#288): `bfd_client.rs` is shared with `nos-ospfv3d` (`#[path]` include, generic over `Host`, implemented by `LinkManager`); the wanted set is polled every 250 ms from the links' neighbor tables, the `bfd` profile per attach point comes from `LinkManager::set_bfd` (never from `LinkConfig`, so it cannot restart a link). BFD only kills (`LinkCommand::BfdDown`, `neighbor::on_bfd_down`), never gates adjacency; AdminDown and connection loss kill nothing.
- Link state (#277): gating happens only in `reconcile::resync`, never in `link::run`; a down kernel device (`link_client::gate`) is left out of `desired_links` and `apply_links` aborts it. Ungated when never connected or `observed = false`. An unresolved VRF/address/bridge keeps the running link's value (`merge_running`) while the config still gives the attach point an address, so only the stream or a config removal tears a link down. `LinkConfig.ifindex` restarts a link on a recreated device.

- Receive hardening (#394): `source_on_link` drops off-subnet packets (not p2p/virtual); `handle_hello` caps a link at `nos_ospf_common::ratelimit::MAX_NEIGHBORS_PER_LINK` neighbors and logs mismatches through a per-link `WarnLimiter` (`warn_limited!`).

## Authentication

- `packet.rs` stays stateless; the anti-replay sequence is `link.rs`'s (`NeighborInfo.last_crypto_seq`, per packet type, checked once at the single decode site). A non-increasing number is dropped, never fatal; failures log `ospf packet authentication failed` (asserted by `nos-e2e ospf-auth`).
- `checksum` excludes the 8-byte Authentication field; Crypto skips it. A key or auth change restarts the link like any `LinkConfig` change. `OspfCryptoKey.key_id` is `u16` (shared with OSPFv3's SA ID); classic AuType 2 needs <= 255 (`valid_profile_timers`).
- RFC 7474 (AuType 3): the boot count (`boot::BootCounter`) is taken on every link (re)start, not just process start. RFC 5613 LLS is not built.

## SPF and routes

- `spf::compute` derives next hops from the LSDB only (a neighbor's address comes from its own LSA's link back), never the neighbor table. Roots' directly attached destinations are filtered by `(link_id, link_data)`, not reachability. Equal-cost sets are unioned (`merge_equal`); `compute_routes` merges areas keeping the cheaper route, path classes per `spf::PathClass`.
- `run_dijkstra` checks `back_link` on every edge (§16.1 2(b), #959); a new edge kind needs its reciprocal rule there.
- Every route push goes through `rib_push_client::push` (`OspfRouteUpdate::frames_with`, a big `Full` becomes `FullPart`s + `Full`, #727); `--push-chunk` is test-only (`ospf-push-chunked`).
- Every collector skips `advertising_router == root` (our own LSA must not route back through us). External collection runs after every Internal collector (forwarding address resolution).
- ABR = attached to 2+ areas, derived, never configured (`lsdbs.len() >= 2` for summaries; `is_area_border_router` for the B bit, counting a virtual link as backbone). `intra_area_routes` feeds summarization and excludes inter-area/external routes, which prevents two-area loops.
- Link State IDs of Type-3/5/7 follow RFC 2328 Appendix E (`link::originate::assign_link_state_ids`, stateless, per area and type); `spf::net_from` truncates host bits on receive.
- `lsa::in_area_scope(type, stub, nssa)` is the one scope rule (Type-5/11 out of stub/NSSA, Type-7 only in an NSSA); every path (DBD, LSR answer, LSU, flood, SPF) must use it.
- Stub/NSSA, virtual links, LFA/remote LFA, prefix suppression, stub router, host router, opaque LSAs: see the internals page for each knob and its tests.

## Graceful restart

- Only SIGTERM announces (`planned_restart` -> `announce_graceful_restart`, sets `restarting` so `shutdown` skips the flush); SIGINT still flushes. The restarter resyncs cold.
- Helper is always on, capped (`LinkConfig.helper_max_grace_period`, `helper_deadline_secs`: remaining = grace - Grace-LSA age) and strict (RFC 3623 §3.2 (c)): `Lsdb::install` records the origin of every new/changed/flushed type 1-5 LSA, `age_lsdbs` hands them to the links (`LinkCommand::TopologyChanged`), the restarter's own never count; the Grace-LSA is removed from the link store at once so it is never offered back. `<state-dir>/<instance>.gr` is read and deleted once at start and only skips RFC 6987 on-startup while `now < deadline <= now + u16::MAX`.
- Never apply RFC 6987 on-shutdown under a grace period (§3.2 (c)).

## Wiring and tests

- Config/watchdog clients, the one-shot IPC skeleton and the `main()` tracing bootstrap come from `nos-daemon` (`daemon/CLAUDE.md`); `rib_client`/`interface_client` are thin typed wrappers over `nos_daemon::ipc::one_shot`. `link_client.rs` is shared differently: `nos-ospfv3d` `#[path]`-includes it, log prefix from `crate::DAEMON`.
- `nos-watchdogd` gives each instance `--listen-socket` (`/run/nos/ospf-<name>.sock`, `EndpointKind::OspfInstance`); `server.rs` serves `GetNeighbors`/`GetDatabase` and takes `ribd`'s fire-and-forget `RedistributeRoutes` (`docs/architecture/endpoint-broker.md`).
- `tests/server.rs` drives the live IPC role gate over mTLS (#364, deny = closed with no frame; ribd feed = stays open).
- `reconcile_tests.rs` drives `resync`/`run` against `nos-test-support`'s fake configd/watchdog/ribd/interfaced (`Fakes::start`) and a real `LinkManager` over `link::tests::wire` (#342); a service left out of `Fakes::start` is the "unreachable" branch.
- `link::tests` run whole `LinkManager`s over an in-memory wire under `start_paused = true`; `socket.rs` is excluded from coverage (`nos-e2e` is its test). Verify kernel, IPC or wire changes with the matching `nos-e2e` phase.
- Mark a deliberate corner-cut with a `ponytail:` comment naming its ceiling; ones that cut an RFC feature also go on the "not supported" list in `docs/protocols/ospf.md`.
