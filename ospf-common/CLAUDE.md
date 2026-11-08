# nos-ospf-common — logic shared by OSPFv2 and OSPFv3

Pure, address-family-agnostic code used by `nos-ospf` and `nos-ospfv3`. No NOS dependencies (not even `nos-proto`), no I/O except the `drouters` socket-option helper; external crates are `tokio` (`sync`, for `Lsdb`s `Notify`) and `socket2` (for `drouters`).

## Modules

- `neighbor`, `election`: RFC 2328 §10.5 neighbor FSM and §9.4 DR/BDR election (identical in RFC 5340).
- `ratelimit`: `WarnLimiter` (token bucket for peer-triggerable `warn!`s) and `MAX_NEIGHBORS_PER_LINK`.
- `bfd`: `bfd_wanted`, the neighbor-state rule for which neighbors get a BFD session.
- `drouters`: `AllDRouters` (idempotent AllDRouters join/leave on a `socket2::Socket`; `Iface` implies the family), `wants_all_drouters`, `ALL_D_ROUTERS_V4/V6`, `Dest` and `flood_dest` (where a flooded LSU/delayed LSAck goes, #879).
- `lsa`: the `LsaHeader` and `Lsa` traits, `MAX_AGE`, and the RFC 2328 §13.1 `is_newer` ordering (a provided method of `LsaHeader`).
- `lsdb`: the generic `Lsdb<L: Lsa>` store, `InstallOutcome`, `MIN_LS_ARRIVAL`, `MAX_AGE_HOLD_TICKS`.
- `exchange`: the RFC 2328 §10.6-10.8 DBD exchange (`Dbd<H>`, `AdjacencyData<L>`, `Action<L>`, `Params`, `on_dbd_received`), LSR/LSU handling (`on_lsr_received`, `on_lsu_received`, `Stores`, `Scope`), the §13.5 delayed-ack queue (`take_pending_acks`, `take_all_pending_acks` for the broadcast-link multicast set), `on_lsack_received`, `mtu_based_max_headers`/`mtu_acceptable`.

## Rules

- **`drouters` owns only the idempotent join/leave** (EADDRINUSE/EADDRNOTAVAIL on join and EADDRNOTAVAIL on leave mean already-in-state); deciding when (election outcome, link type) stays in the daemons.
- **Traits carry identity only.** `LsaHeader` exposes key, sequence, age, checksum, length and advertising router; `Lsa` exposes its header. Bodies, scope (area/link/AS), type numbering and wire codecs stay in the daemons.
- **No family-wide trait.** Where v2 and v3 differ, the shared function takes a per-call closure or a plain argument; never add a `Family` trait.
- **The key is an associated type** (`LsaHeader::Key`): v2's `lsa_type` is a `u8`, v3's a `u16`. `advertising_router()` is on the header so `age_and_evict` can apply the RFC 3623/5187 grace `hold` set without bounds on `Key`.
- **Daemons alias, not wrap**: each daemon has `pub type Lsdb = nos_ospf_common::lsdb::Lsdb<Lsa>` and re-exports the constants, so call sites stay `Lsdb::new()`. `lsa::is_newer` in each daemon only delegates to the trait method.
- **Two install paths**: `install` (self-originated, paced by `MinLSInterval` elsewhere) and `install_received` (flooding, paced by `MIN_LS_ARRIVAL`; `TooSoon` means not installed, not acked, not counted as answering a request). `remove` and eviction also clear the pacing clock.
- A flushed (`MAX_AGE`) entry is held `MAX_AGE_HOLD_TICKS` ticks so the periodic full-LSDB resend can carry it to every neighbor before it is evicted; a superseding install restarts the hold.
- `Lsdb` fires its `Notify` on every change that can alter SPF input (install, remove, evict), never on a rejected install.
- **Exchange closures**: `on_dbd_received` takes `in_scope` (v2 `lsa::in_area_scope`, v3 always true; an out-of-scope header in a DBD is `SeqNumberMismatch` and is never summarized) and `is_opaque` (v2 RFC 5250, v3 never). Per-link values go in `Params`; `dbd_options` stamps every DBD reply/poll, so v3 sends `link_options` (AT-bit included) in all of them.
- **LSU closures**: `on_lsu_received` takes `scope` (which of `Stores`' `area`/`link_local`/`as_scope` gets the LSA; v2 never says `As` and passes `as_scope: None`, which is a `debug_assert!` plus discard-unacked), `discard` (dropped unacked, §13 step 3: v2 `!in_area_scope`, v3 S2/S1 reserved) and `exempt_max_age` (skips §13 step 4: v3 Grace-LSA, v2 never). `on_lsr_received` takes the stores as a slice, searched in order.
- **Acks are always delayed**: `on_lsu_received` queues on `pending_acks` (a `MaxAge`/stale duplicate too) and never returns `SendLsAck`; `TooSoon` is neither installed, acked nor counted as answering a request. The daemon stamps `pending_acks_since` and flushes on its `RXMT_INTERVAL` sweep.
- **Hash lookups (#682)**: `compute_request_list` indexes the local headers in a `HashMap` per call and `on_lsu_received` a `HashSet` of the request list per LSU (one `retain` at the end). `request_list` stays an ordered `Vec` because the LSR is built from it in order.
- **What stays in the daemons**: `start_negotiation` (reads `LinkConfig`), Grace-LSA handling after install (removed from the link store under the install's lock), and the packet codecs. Each daemon aliases `DbdPacket`, `AdjacencyData`, `Action` and wraps `on_dbd_received`/`on_lsr_received`/`on_lsu_received` with its closures and stores. `Action` has no `InstallAndFlood`: flooding is the periodic resend.

## Tests

- `lsa::test_lsa` is a ~20-line `Lsa`/`LsaHeader` (a `u32` key) so store, ordering and exchange tests need no daemon types (`exchange/tests.rs` keeps the pre-#430 positional call through a shim). Daemon-side tests cover their trait impls, aliases and closures (stub/NSSA, opaque/type-9 routing, v3 DBD options, v3 S2/S1 routing and Grace exemption).
- Behaviour that needs a kernel or two processes belongs in a `nos-ospf*` test or a `nos-e2e` phase (`docs/e2e-phases.md`), not here.
