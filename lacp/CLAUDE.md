# nos-lacp — LACP (IEEE 802.1AX) Daemon

A real, from-scratch Link Aggregation Control Protocol implementation for NOS (binary `nos-lacpd`, a single fixed process — see `docs/architecture/supervision.md` for why, the same reasoning as `nos-interfaced`/`nos-logd`: `PortAggregate` has no per-VRF/per-instance multiplicity to key a dynamic per-object spawn off).

## Scope and the critical design boundary

`nos-lacpd` runs the real protocol — raw `AF_PACKET` LACPDU exchange and the IEEE 802.1AX Actor/Partner state machines — for every `Lacp`-mode `PortAggregate`'s member ports. It **never touches rtnetlink and never creates or modifies the kernel bond device itself**. `nos-interfaced` remains the sole owner of that (`ensure_port_aggregate`/`port_aggregate_registry`, see `interface/CLAUDE.md`); `nos-lacpd` only computes which member ports are currently negotiated into the aggregate and pushes that decision over IPC (`InterfaceRequest::PushLacpMembers`, fire-and-forget, the data-plane-push pattern this NOS already uses for `RibRequest::PushBgpRoutes`).

**The kernel bond is created identically for `Xor` and `Lacp` modes** — `BondMode::BalanceXor` in both cases (`interface::driver::linux::bond_mode_of`). It must never be created as the kernel's own `BondMode::Ieee8023Ad`: that mode installs an `rx_handler` on every slave that intercepts slow-protocol (ethertype `0x8809`) frames in-kernel before userspace ever sees them, which would silently starve `nos-lacpd`'s own raw sockets of every LACPDU it needs — defeating the entire from-scratch design. The `PortAggregateMode` only changes which control plane decides *membership*, never the kernel driver's own bonding algorithm.

## Robustness rules learned the hard way (each has a regression test)

Every one of these was a real hot loop or stall found by running `nos-e2e lacp` against real containers:

- **Never leave an elapsed deadline armed.** `link::run` uses `sleep_until(deadline)` arms; a deadline left in the past re-fires on every loop iteration, flooding the log and the wire. Handling any timer-expiry event must move its deadline forward (`apply_mux_action`/`apply_receive_action`) — but `Action::None` must *not* disarm a still-pending timer.
- **Ignore our own frames.** An `AF_PACKET` socket also receives its own outgoing frames (`socket::payload_of_foreign_frame` drops them by source MAC); otherwise a port negotiates with itself. Members keep their own MACs until Distributing, so the MAC filter is not enough: `Port::on_frame` also drops (after the RX budget, before any machine) a LACPDU whose actor system id equals ours, warning once per run (`lacp loopback detected`, #658).
- **Only signal on a real change.** `watch::Sender::send` wakes the receiver even for an identical value, so `aggregate::set_if_changed` and `link::report`'s dedupe exist to break the report → re-select → notify feedback loop.
- **A down link is not fatal.** `ENETDOWN` on read/send (link administratively down, or just coming up) is retried (`socket::is_link_down`), not a reason for the link task to exit; a task that does end on its own is respawned by `reconcile`.
- **Bound the receive path (#397).** `Port::on_frame` takes an RX budget (10 LACPDUs/s per port, Markers excluded) before touching any machine, warning once per burst; `lacp lacpdu received` is `info!` only when receive state, mux state or partner changed, else `debug!`. `selection_loop` coalesces `PushLacpMembers` to one per second (leading edge immediate, newest set trailing, A->B->A pushes nothing).

## Explicitly deferred (documented, not silently missing)

- **Marker Generator** (§6.5.4.1, optional) — only matters for frame ordering during a live port move between aggregators; irrelevant with config-fixed membership. The **Marker Responder** (§6.5.4.2, mandatory) *is* implemented: `link::run` answers a Marker PDU (subtype 0x02, TLV 0x01) on the same port with a clean Marker Response, echoing requester port/system/transaction id, without touching any LACP machine. Own `TxLimiter` (5/s, excess dropped; LACPDUs keep their 3/s), so the port stays under 802.3 Annex 57A's 10 slow-protocol frames/s. Linux sets the Marker length byte to 0x16 where the standard says 16, so `decode_marker` reads fixed offsets only. No counters in `show lacp` (#59). IEEE 802.1AX/802.3 are paywalled: the layout was checked against Linux `bond_3ad.h`, not the standard text.
- **Full dynamic cross-aggregate Selection Logic** — see the Selection Logic section above; permanent, not temporary.


## Invariants to keep

- Each member port runs three pure `step(state, event) -> (state, Action)` machines (Receive §6.4.12, Periodic Transmission §6.4.13, Mux §6.4.15) driven by the impure `link::run`; **only `Distributing` belongs in the active-member set pushed to `nos-interfaced`**.
- Transmit rate follows the partner's `LACP_Timeout` bit, never our own `lacp-rate`; our `lacp-rate` sets our advertised TIMEOUT bit and our own `Current_While_Timer` (3s fast / 90s slow). Send on change (`link::needs_transmit`), not on every receipt.
- `Expired` keeps the learned partner and the port selected (only Sync/Collecting clear); only `Defaulted` drops it (partner `None` = administrative default, reported as key 1/port 1/0xffff/0xff, zero system). Selectable = `PortObservation::selectable()`, never plain `current()` (#687).
- A partner's Synchronization/Collecting count only when its Partner block matches our Actor (`link::partner_matches_actor`, §6.4.9); a changed partner identity drops the mux out of Distributing.
- Selection is config-scoped, permanently: it only checks the wire agrees with the configured aggregate (`selection.rs`); it never discovers membership.
- Actor System ID is derived (FNV-1a of hostname + machine-id, `aggregate::local_system_id`), never from a member port (bonding rewrites slave MACs), overridable by `lacp-system-id`; no persisted registry. Internal state types are never `nos_proto::lacp`'s wire types.
- Changing rate, system id or system priority restarts every member link; a port priority or `lacp-mode` change restarts only that member; `min-links` restarts nothing.

## Modules

| Module | Role |
|---|---|
| `main.rs` | Single-instance args (`--watchdog-socket`, `--listen-socket`, `--log-socket`); starts `server::start`, `reconcile::run`, `interface_client::run` |
| `packet.rs` | Hand-rolled LACPDU and Marker PDU codec, pure; `Lacpdu.v2` = UNVERIFIED v2 TLVs (#893, nothing sends them) |
| `conversation.rs` | Pure CSCD model: `ConversationMap`, `PortAlgorithm`, MD5 digest, masks, `send_version` (UNVERIFIED wire choices) |
| `socket.rs` | `LacpSocket` over `nos-l2-socket`: one member interface, ethertype `0x8809`, group `01:80:C2:00:00:02` |
| `receive_machine.rs`, `periodic_tx_machine.rs`, `mux_machine.rs`, `churn_machine.rs` | The pure state machines (churn: 60s, `NOS_LACP_CHURN_SECS`) |
| `selection.rs` | Config-scoped `select` |
| `link.rs` | Per-port `run()` (open the socket, build a `Port`) and `drive()` (the event loop); `Port` has one method per event. Test seam (#346): `FrameSink`/`FrameLink` abstract the socket, so `link/port_tests.rs` needs no `CAP_NET_RAW`; deadlines use `tokio::time::Instant` so paused-time tests work |
| `aggregate.rs` | `AggregateManager`: per-aggregate `reconcile` and `selection_loop` |
| `interface_client.rs` | Full-resend push of `PushLacpMembers` to `nos-interfaced` |
| `server.rs` | `LacpRequest::GetSummary` for `show lacp` |
| `reconcile.rs` | Config diff resync plus a 10s tick |
| (no `config_client`/`watchdog_client`) | config, watchdog and `main()` bootstrap come from `nos-daemon` (`daemon/CLAUDE.md`) |

Details: [internals](../docs/internals/lacp.md) (state machines, `lacp-rate`, selection, actor identity and the `nos-e2e lacp` narrative), [user guide](../docs/protocols/port-aggregation-lacp.md), [e2e phases](../docs/e2e-phases.md), [v2/CSCD research](../docs/internals/lacp-v2.md).
