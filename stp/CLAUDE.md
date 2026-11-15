# nos-stp — spanning tree

The pure core (`bpdu`, `vector`, `cost`, `timers`, `machines`, `bridge`, `actions`: no I/O, no tokio) and the `nos-stpd` daemon (`main.rs` plus the modules below) for the STP series (#316). Byte layouts, cost table, the 13.25 rule, the machine table, the host contract and the deviations from the standard: `docs/internals/stp.md`.

## Modules

- `bpdu.rs`: IEEE 802.1Q-2022 cl.14. `decode`/`encode` work on the BPDU body, `decode_frame`/`encode_frame` add the 802.3 header (group MAC, length field, LLC `42 42 03`). `Bpdu::{Config, Rst}` share one `Params` struct.
- `vector.rs`: `BridgeId`, `PortId` (private fields, constructors reject bad priority/extension/number) and `PriorityVector` (derived `Ord` = 13.10 order, lower is better). The `infoIs`/`designatedPriority` comparisons are state-machine business, not here.
- `cost.rs`: Table 13-4 as `20 000 000 / speed_mbps` clamped to `1..=200 000 000`; speed 0 means unknown and gives the maximum.
- `timers.rs`: `Timers` defaults, Table 13-5 ranges and the 13.25 relation. The relation is also in the config commit check (`nos-proto`); this crate cannot depend on it.

- `machines/`: the nine clause 13 machines (`prx ppm bdm pim prs prt pst tcm ptx`), `step(&mut Bridge, port) -> bool` = one diagram edge; shared variables and procedures in `machines/mod.rs`. One `Bridge` is one tree: the CIST, or an MSTI in `mst/` (#321); port protections (#320: BPDU guard/filter, root/loop guard, `restricted-tcn`) are `Protections` set by `Bridge::set_protections`; `force-version`/`mcheck` (#319) are `Bridge::set_rstp_version`/`mcheck`.
- `bridge.rs`: `Bridge` (host inputs: `set_port_enabled`, `set_oper_point_to_point`, `receive`, `tick`; `run()` loops all machines to quiescence, cap 1000 passes). `actions.rs`: what the host drains (`Transmit`, `SetPortState`, `FlushFdb`, `ErrDisable`/`ErrRecover`, `Log`).
- `mst/` (#321, mode `mstp`): `digest.rs` (HMAC-MD5 over the 4096-entry VID table), `vidmap.rs` (domain tag + `stp-instance` to the table), `mod.rs` (`Mst`: one `Bridge` per MSTI whose message age is the hops used and `max_age` is `MaxHops`; `flat`/`msti_params` convert a v3 BPDU; `Edge::Boundary` ports run no MSTI and follow the CIST). `bpdu.rs` has the v3 codec (`decode_any`/`encode_mst`).
- `sstp.rs` + `pvst.rs` (#322, mode `rapid-pvst`): `sstp` is the Cisco SNAP/SSTP framing with the Originating VLAN TLV; `Pvst` runs one `Engine` per domain (`Plan.pvst` = one `TreePlan` each: VLAN as bridge-id extension, member cost/priority, only the member ports), forces a PVID-inconsistent `(port, domain)` to Blocking, and holds the native rule (`tx_wires`/`accepts`). BPDUs ride `<port>.<tag>` for a tagged member, the port itself for the untagged one (`L2Socket::open_pvst`). A plain PVST+ peer needs no code: the tree's port migrates to 802.1D (#319).
- `events.rs` (#323): every core/engine log message as a constant, pinned by a test; log sites use `"{}", events::NAME`, fields follow in the order the site declares (`docs/protocols/stp.md`, "Log lines"). `Engine` also keeps per-port RFC 4318 counters and per-tree topology-change records (`Event::TopologyChange` from TCM; `uptime` is the clock), served in `StpSummary`.
- `sim.rs` (test-only): deterministic multi-bridge simulator plus proptest on random graphs.

## Daemon (`nos-stpd`)

- `ports.rs` (pure): config to `Plan` (STP ports, timers, priority) and the core's state to `SetStpPortStates`/`FlushFdb` assignments per domain. `identity.rs`, `link.rs` (sysfs speed/duplex, cost, point-to-point): pure.
- `engine.rs`: the core(s) plus the action-to-`Out` mapping and the e2e log lines; kernel states are pushed by diff per `(tree, port)` (`diff_states`), an MSTI's domains are those whose `stp-instance` names it. `daemon.rs`: the one actor owning the engine, the BPDU sockets (`L2Socket::open_bpdu`) and the 1 s tick.
- Test seam (#346): the actor reaches a port's socket through `BpduIo` (`send_frame`, `own_hw_addr`) and opens it through an injectable `Opener` (production `open_l2`: raw socket plus reader task), so `daemon/tests.rs` drives `Daemon` with fake sockets and no `CAP_NET_RAW`; `run` is `run_with(open_l2, local_mac(), ..)`.
- `reconcile.rs` (diff resync to a `Plan`), `link_client.rs` (`SubscribeLinks`), `interface_client.rs` (push + resend cache); config/watchdog clients and the `main()` bootstrap come from `nos-daemon` (`daemon/CLAUDE.md`).
- `server.rs` (`--listen-socket`, `GetSummary` from an `Arc<RwLock<StpSummary>>` the actor refreshes after every event via `Engine::summary`) and `authz.rs` (`allowed`: `User`/`Restd`, no wildcard arm): backs `show spanning-tree` and its `instance`/`mst-config` views (#328, #321: one `StpSummary.mst`, no extra request) and `StpRequest::Mcheck` (#319) / `ClearErrDisabled` (#320), forwarded to the actor as `server::Cmd`.
- An err-disabled port (BPDU guard) is pushed as `SetErrDisabled` to `nos-interfaced`, which holds its link down; a plan rebuild keeps it down (`Engine::restore_err_disabled`), and so does a restart: the first plan apply reads the held set back from `nos-interfaced` (`interface_client::read_err_disabled`, `HeldReader` test seam), fail closed after 10 s (#697).
- A changed plan is applied in place when `Engine::apply_plan` can (priority, timers, per-port cost/priority/edge/protections, ports added/removed; port numbers come from the daemon allocator and stay stable; a removed port keeps a hidden slot), else rebuilt (`Rebuild`: mode, force-version, MSTP) (#662). Rapid-PVST+ goes tree by tree (`Pvst::apply_plan`, #1122): added tree appended, removed tree a hidden `gone` slot, a VLAN or member-tag change restarts only that tree (`new_keeping`). Log lines are the e2e contract (`docs/internals/stp.md`): change them with `phases::stp`.

## Invariants


- Time enters only through `Bridge::tick` (1 s); no clock reads. A change to a machine guard needs a sim scenario or proptest run (`PROPTEST_CASES=3000`), the unit tests alone do not catch stalls.
- Timers in a BPDU stay raw `u16` (1/256 s) so any peer value round-trips; use `secs`/`raw_secs` for whole seconds.
- Decode ignores trailing bytes and NIC padding past the length field; a type 0x02 BPDU of version >= 2 (MSTP's 3 too) decodes as RST; so does a version 3 BPDU with an invalid Version 3 Length or a short version 3 body (`decode_any` falls back, never errors).
- Linux's kernel STP only emits Config BPDUs: the Config test vectors are real captures, the RST and TCN vectors follow the clause 14 layout.
