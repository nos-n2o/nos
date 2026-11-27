# nos-ospf-common — logic shared by OSPFv2 and OSPFv3

Pure, address-family-agnostic code used by `nos-ospf` and `nos-ospfv3`. No NOS dependencies (not even `nos-proto`), no I/O except the `drouters` socket-option helper; external crates are `tokio` (`sync`, for `Lsdb`s `Notify`), `socket2` (for `drouters`) and `tracing`.

## Modules

- `neighbor`, `election`: RFC 2328 §10.5 neighbor FSM and §9.4 DR/BDR election (identical in RFC 5340).
- `throttle`: `SpfThrottle`, the RFC 8405 QUIET/SHORT_WAIT/LONG_WAIT SPF delay machine with an injected `Instant` (#1138; `nos-ospf` only so far).
- `restart`: RFC 3623/5187 restarting router (#1145, reused by #1163): the `.gr` marker (`encode_marker`/`encode_running_marker`/`parse_marker`: deadline + `Full` neighbor ids + the `unplanned` crash flag) and `exit_reason` (complete / topology-change / timeout); the daemons own the file, clock and what restart mode suppresses.
- `boot`: `BootCounter`, the persisted RFC 7474/7166 boot count (atomic file write, `std` only; `next()` returns the count plus an optional warning for the daemon to log) and `write_atomic` (#612). Adds the `tempfile` dependency.
- `ratelimit`: `WarnLimiter` (token bucket for peer-triggerable `warn!`s) and `MAX_NEIGHBORS_PER_LINK`.
- `bfd`: `bfd_wanted`, the neighbor-state rule for which neighbors get a BFD session.
- `drouters`: `AllDRouters` (idempotent AllDRouters join/leave on a `socket2::Socket`; `Iface` implies the family), `wants_all_drouters`, `ALL_D_ROUTERS_V4/V6`, `Dest` and `flood_dest` (where a flooded LSU/delayed LSAck goes, #879).
- `lsa`: the `LsaHeader` and `Lsa` traits, `MAX_AGE`, and the RFC 2328 §13.1 `is_newer` ordering (a provided method of `LsaHeader`).
- `areas`: `apply_ranges` (RFC 2328 §12.4.3 / RFC 5340 §4.4.3.3 range aggregation, generic over `RangePrefix` for `Ipv4Net`/`Ipv6Net`) and `in_area_scope(as_scope, nssa_type, stub, nssa)`; each daemon classifies its own LSA types (#1178). Adds the `ipnet` dependency.
- `lsdb`: the generic `Lsdb<L: Lsa>` store, `InstallOutcome`, `MIN_LS_ARRIVAL`, `MAX_AGE_HOLD_TICKS`; the flood sink (`set_flood_sink`, `FloodEvent`, `Origin`, #1516).
- `flood`: pure §13.3 `flood_on_link`/`merge_floods` and §13.5 `ack_action`/`floods_back` (#1516); see `docs/protocols/ospf-internals.md`.
- `exchange`: the RFC 2328 §10.6-10.8 DBD exchange (`Dbd<H>`, `AdjacencyData<L>`, `Action<L>`, `Params`, `on_dbd_received`), LSR/LSU handling (`on_lsr_received`, `on_lsu_received`, `Stores`, `Scope`), the §13.5 delayed-ack queue (`take_pending_acks`, `take_all_pending_acks` for the broadcast-link multicast set), `on_lsack_received`, `Rxmt`/`due_retransmissions`, `mtu_based_max_headers`/`mtu_acceptable`.

## Rules

- **`drouters` owns only the idempotent join/leave** (EADDRINUSE/EADDRNOTAVAIL on join and EADDRNOTAVAIL on leave mean already-in-state); deciding when (election outcome, link type) stays in the daemons.
- **Traits carry identity only.** `LsaHeader` exposes key, sequence, age, checksum, length and advertising router; `Lsa` exposes its header. Bodies, scope (area/link/AS), type numbering and wire codecs stay in the daemons.
- **No family-wide trait.** Where v2 and v3 differ, the shared function takes a per-call closure or a plain argument; never add a `Family` trait.
- **The key is an associated type** (`LsaHeader::Key`): v2's `lsa_type` is a `u8`, v3's a `u16`. `advertising_router()` is on the header so `age_and_evict` can apply the RFC 3623/5187 grace `hold` set without bounds on `Key`.
- **Daemons alias, not wrap**: each daemon has `pub type Lsdb = nos_ospf_common::lsdb::Lsdb<Lsa>` and re-exports the constants, so call sites stay `Lsdb::new()`. `lsa::is_newer` in each daemon only delegates to the trait method.
- **Two install paths**: `install` (self-originated, paced by `MinLSInterval` elsewhere) and `install_received` (flooding, paced by `MIN_LS_ARRIVAL`; `TooSoon` means not installed, not acked, not counted as answering a request). `remove` and eviction also clear the pacing clock.
- A flushed (`MAX_AGE`) entry is held `MAX_AGE_HOLD_TICKS` ticks (the flood sink sends it at once; the hold covers one retransmission and the stale-echo guard) before it is evicted; a superseding install restarts the hold.
- `Lsdb` fires its `Notify` on every change that can alter SPF input (install, remove, evict), never on a rejected install.
- **Exchange closures**: `on_dbd_received` takes `in_scope` (v2 `lsa::in_area_scope`, v3 always true; an out-of-scope header in a DBD is `SeqNumberMismatch` and is never summarized) and `is_opaque` (v2 RFC 5250, v3 never). Per-link values go in `Params`; `dbd_options` stamps every DBD reply/poll, so v3 sends `link_options` (AT-bit included) in all of them.
- **DBD duplicates (#607, RFC 2328 §10.6)**: in `Exchange` the slave answers the master's duplicate poll (seq == ours) with `last_dbd_sent` (none: ignore), the master discards a duplicate reply (seq == ours - 1); other wrong seqs stay `SeqNumberMismatch`. An ExStart master ignores a reply whose seq is not its own. Daemons' `retransmit_pending` resends `last_dbd_sent` only in ExStart or as Exchange master. `dbd_fault` is the test-only `--dbd-fault drop:N,dup:N` hook (process-global, counts the reply/poll send path) used by `nos-e2e`.
- **RFC 5243 summary optimization (#1140)**: after each DBD from the neighbor (`slave_process_poll`/`master_process_reply`), `trim_summary` drops from `summary_remaining` every header it lists at an equal or newer instance; bits, sequence and termination are untouched; logs `ospf dbd summary trimmed removed=<n>` at debug.
- **LSU closures**: `on_lsu_received` takes `scope` (which of `Stores`' `area`/`link_local`/`as_scope` gets the LSA; v2 never says `As` and passes `as_scope: None`, which is a `debug_assert!` plus discard-unacked), `discard` (dropped unacked, §13 step 3: v2 `!in_area_scope`, v3 S2/S1 reserved) and `exempt_max_age` (skips §13 step 4: v3 Grace-LSA, v2 never). `on_lsr_received` takes the stores as a slice, searched in order.
- **Acks (#1516)**: `on_lsu_received` takes an `AckCtx` and applies Table 19 via `ack_action` (`Direct` is `Action::SendLsAck`, `Delayed` goes on `pending_acks`). `TooSoon` is neither installed, acked nor counted as answering a request. It returns `LsuResult` (actions, installed, per-LSA `RxVerdict`).
- **Hash lookups (#682)**: `compute_request_list` indexes the local headers in a `HashMap` per call and `on_lsu_received` a `HashSet` of the request list per LSU (one `retain` at the end). `request_list` stays an ordered `Vec` because the LSR is built from it in order.
- **What stays in the daemons**: `start_negotiation` (reads `LinkConfig`), Grace-LSA handling after install (removed from the link store under the install's lock), and the packet codecs. Each daemon aliases `DbdPacket`, `AdjacencyData`, `Action` and wraps `on_dbd_received`/`on_lsr_received`/`on_lsu_received` with its closures and stores. Both daemons flood through the sink, `flood_on_link`, `due_retransmissions` and `AckCtx` (#1517, #1518).

## Tests

- `lsa::test_lsa` is a ~20-line `Lsa`/`LsaHeader` (a `u32` key) so store, ordering and exchange tests need no daemon types (`exchange/tests.rs` keeps the pre-#430 positional call through a shim). Daemon-side tests cover their trait impls, aliases and closures (stub/NSSA, opaque/type-9 routing, v3 DBD options, v3 S2/S1 routing and Grace exemption).
- Behaviour that needs a kernel or two processes belongs in a `nos-ospf*` test or a `nos-e2e` phase (`docs/e2e-phases.md`), not here.
- **Step 8**: `on_lsu_received` answers a `DbNewer` LSA with `Action::SendLsu` of the held copy, rate-limited per neighbor and LSA by `AdjacencyData.db_resent` (#1626).
