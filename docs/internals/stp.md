# Spanning tree internals

Reference for `nos-stp` (IEEE 802.1Q-2022). User-facing configuration: [Spanning tree](../protocols/stp.md).

## BPDU frame

- 802.3 frame: destination `01:80:c2:00:00:00`, source MAC, a length field (not an ethertype, at most 1500), LLC `42 42 03`, then the BPDU body.
- A receiver trusts the length field, so NIC padding after it is ignored.

## BPDU body

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | Protocol identifier, always 0 |
| 2 | 1 | Version: 0 Config, 2 RST, 3 MSTP |
| 3 | 1 | Type: `0x00` Config, `0x02` RST, `0x80` TCN |
| 4 | 1 | Flags |
| 5 | 8 | Root bridge identifier |
| 13 | 4 | Root path cost |
| 17 | 8 | Designated bridge identifier |
| 25 | 2 | Designated port identifier |
| 27 | 2 each | Message age, max age, hello time, forward delay (1/256 s) |
| 35 | 1 | RST only: Version 1 Length, 0 |

- Lengths: Config 35, RST 36, TCN 4 (header only), MST 102 plus 16 per MSTI message.
- Flags: bit 0 TC, 1 Proposal, 2-3 Port Role (0 unknown, 1 alternate/backup, 2 root, 3 designated), 4 Learning, 5 Forwarding, 6 Agreement, 7 TC Ack. A Config BPDU uses only TC and TC Ack.
- Bridge identifier: first u16 is priority (4 bits, steps of 4096) over system id extension (12 bits), then the MAC. Port identifier: priority (4 bits, steps of 16) over number (12 bits).

## MST BPDU (version 3, 14.6)

| Offset | Size | Field |
|--------|------|-------|
| 0-35 | 36 | As an RST BPDU, with version 3; offset 5 is the CIST root, 13 the CIST external root path cost, 17 the CIST regional root |
| 36 | 2 | Version 3 Length: 64 plus 16 per MSTI message (at most 64 messages) |
| 38 | 1 | Format selector, 0 |
| 39 | 32 | Region name, NUL padded |
| 71 | 2 | Revision |
| 73 | 16 | Configuration digest |
| 89 | 4 | CIST internal root path cost |
| 93 | 8 | CIST bridge identifier |
| 101 | 1 | CIST remaining hops |
| 102 | 16 each | MSTI message |

- MSTI message: flags (as RST, bit 7 is Master), regional root id (priority plus the MSTID as extension, 8), internal root path cost (4), bridge priority (1, high nibble), port priority (1, high nibble), remaining hops (1).
- A bad Version 3 Length (below 64, not 64 plus a multiple of 16, over 64 messages) (or a body shorter than that length) makes the BPDU be processed as its RST part (802.1Q cl.14), never dropped. `bpdu::decode` still reads a version 3 BPDU as its RST part; `decode_any` keeps the MST part.
- The Configuration Digest is HMAC-MD5 with the key `13AC06A62E47FD51F95D2BA243CD0346` over 4096 big-endian 16-bit MSTIDs, entry `i` for VLAN `i`. An empty table gives `AC36177F50283CD4B83821D8AB26DE62`.

## Priority vector

- Order (13.10), lowest wins: root, root path cost, designated bridge, designated port, receiving port.
- Identifiers compare as the big-endian integers of their wire bytes.

## Path cost

- `cost = 20 000 000 / speed in Mb/s`, clamped to 1..=200 000 000 (Table 13-4 is exactly this: 1 Gb/s 20 000, 10 Gb/s 2 000, 100 Mb/s 200 000).
- A bond uses the same formula on the sum of its active members' speeds.
- Speed 0 (unknown) gives 200 000 000.

## Timers

| Timer | Default | Range |
|-------|---------|-------|
| Hello | 2 | 1-10 |
| Max age | 20 | 6-40 |
| Forward delay | 15 | 4-30 |
| Tx hold count | 6 | 1-10 |
| Migrate time | 3 | fixed |

- 13.25: `2 * (forward-delay - 1) >= max-age >= 2 * (hello + 1)`.

## Test vectors

- Config BPDUs in `bpdu.rs` are real: captured from two Linux bridges (`stp_state 1`, veth pair) in a user+net namespace. Reproduce with `unshare -rn`, `ip link add ... type bridge stp_state 1` and an `AF_PACKET` socket.
- The kernel never emits RST or TCN BPDUs (it runs legacy STP), so those vectors come from the layout above.

## Kernel side (`nos-interfaced`, #326)

How the bridge ports are made safe before `nos-stpd` exists. Spike results, on kernel 7.2.9:

- **BR_NO_STP floods the group MAC.** A Linux bridge with `stp_state 0` treats `01:80:c2:00:00:00` as ordinary traffic and forwards it. Every bridge port therefore gets an ingress `flower dst_mac <group> action drop` filter (the BPDU group, plus Cisco SSTP `01:00:0c:cc:cc:cd`) under a `clsact` qdisc (encoded by `nos-tc`, prio 1): the BPDU never reaches the bridge.
- **The tap still sees it.** An `ETH_P_ALL` `AF_PACKET` socket taps before tc ingress and before the bridge `rx_handler`, so it receives the frames the filter drops. A protocol-bound socket (`ETH_P_802_2`) runs after them and gets nothing. `nos-stpd` (#327) must capture with `ETH_P_ALL`.
- **The trap matches untagged LLC frames only** (tc protocol `802.2`, #322). A frame carrying a VLAN tag classifies as `802.1Q`, and tc ingress of a trunk's parent port runs before `vlan_do_receive`; a trap on every protocol dropped the tagged SSTP of the `ethX.<tag>` sub-links as soon as the parent itself was a bridge port (the native VLAN). The sub-link sees the tag already removed and still traps.
- **Tagged BPDUs never reach the parent's socket.** `open_bpdu`/`open_pvst` always drop a frame that carried an 802.1Q tag (kernel BPF, `SKF_AD_VLAN_TAG_PRESENT`, also when the tag was offloaded into metadata), so a VLAN's BPDUs are not taken for the native ones (#690). Two checks, because on a veth pair (kernel 7.2.11) the tag is stripped from the bytes and invisible to BPF but the frame arrives as `PACKET_OTHERHOST`: `SKF_AD_VLAN_TAG_PRESENT` (offloading NICs) and `SKF_AD_PKTTYPE == OTHERHOST`. Real-NIC offload is untested.
- **BLOCKING does not stick.** With STP off the kernel's `br_port_state_selection` turns a blocking port back into forwarding at once (every port is designated). Only DISABLED survives, written through `RTM_SETLINK` in the `AF_BRIDGE` family with `IFLA_PROTINFO` (`bridge link set dev <port> state 0`); the `RTM_NEWLINK` slave-data path ignores it. So `StpPortState::Blocking` is kernel DISABLED, which neither learns nor forwards. `Learning` is 2, `Forwarding` 3, both through the same path.
- **A down device refuses** a state write (`ENETDOWN`) but is already DISABLED. The kernel opens a port when its link goes up, so the driver reconciles again right after every `up`.

Fail-safe rules:

- While `spanning-tree mode` is not `disabled` (the default is `rstp`), a bridge port is blocked and trapped until `nos-stpd` pushes a state. Log: `bridge port enslaved blocking interface=<link>`, `bpdu trap installed interface=<link>`. Until `nos-stpd` pushes a state this blackholes the bridge port by design.
- Window: one netlink round trip between the kernel opening a freshly enslaved running port and the block; and, after a carrier flap, up to the 10s resync. `nos-stpd` shortens the second one by reacting to `SubscribeLinks`.
- Mode `disabled` restores forwarding and removes the trap, but only on ports this process blocked or trapped (`nos-fdbd` also disables ports, for single-active segments). Logs: `bridge port forwarding restored`, `bpdu trap removed`.
- The VXLAN port of a VNI domain is never touched.

How to check by hand, in a throwaway namespace (`unshare -Urn`): `ip link add br0 type bridge stp_state 0`, a veth pair with one end in `br0`, `bridge link show dev <port>` for the state, `tc filter show dev <port> ingress` for the trap. `cargo test -p nos-interface stp_kernel -- --ignored` runs the same against the driver.

## State machines (`nos-stp`, clause 13)

- The core is pure: `Bridge` holds the per-port variable set (13.27) and one state per machine; nothing reads a clock or touches a socket.
- One module per machine under `stp/src/machines/`, each with `step(&mut Bridge, port) -> bool` (one diagram edge per call) and `enter` (a state's entry actions). State names follow the standard (`DESIGNATED_PORT` is `prt::State::DesignatedPort`).

| Machine | Module | Clause | Job |
|---------|--------|--------|-----|
| Port Receive | `prx` | 13.28 | takes the delivered BPDU, sets `rcvdMsg`, `rcvdRSTP`/`rcvdSTP`, drops `operEdge` |
| Port Protocol Migration | `ppm` | 13.31 | `sendRSTP` per port: falls back to STP after a legacy BPDU, `mcheck` restarts the probe |
| Bridge Detection | `bdm` | 13.32 | `operEdge` from admin edge / auto-edge |
| Port Information | `pim` | 13.34 | judges a received vector against the port's (`rcvInfo`), ages info out |
| Port Role Selection | `prs` | 13.36 | per bridge: root port, designated vectors, every port's `selectedRole` |
| Port Role Transition | `prt` | 13.35 | roles, sync/agree/reRoot handshake, `learn`/`forward` |
| Port State Transition | `pst` | 13.38 | `learn`/`forward` become `learning`/`forwarding` |
| Topology Change | `tcm` | 13.37 | `tcWhile`, TC propagation, FDB flush |
| Port Transmit | `ptx` | 13.33 | builds and rate-limits (`txHoldCount`) Config/RST/TCN BPDUs |

## Host contract (what `nos-stpd` feeds and drains)

- Build with `Bridge::new(id, timers, &[PortParams])`; every port starts disabled.
- Inputs, each one call that also runs the machines to quiescence:
  - `set_port_enabled(port, up)` is `portEnabled` (carrier and admin state).
  - `set_oper_point_to_point(port, bool)` is `operPointToPoint` (full duplex or configured).
  - `receive(port, bpdu)` delivers a decoded BPDU.
  - `tick()` once per second; every 13.22 timer decrements here, and so does `txCount` (by 1, floor 0, like mstpd; not reset).
  - `set_path_cost`, `set_bridge_id` re-run role selection.
- Output: `take_actions()` returns, in order:
  - `Transmit { port, bpdu }`: encode with `bpdu::encode_frame` and send.
  - `SetPortState { port, Discarding | Learning | Forwarding }`: program the kernel port.
  - `FlushFdb { port }`: flush that port's learned MACs now (the core does not wait for completion).
  - `Log(Event)`: role and root changes, plain data for the host to log.
- Port protections (#320): `set_protections(port, Protections)`; `restrictedRole`/`restrictedTcn` are `root_guard`/`restricted_tcn`. `Action::ErrDisable`/`ErrRecover` ask the host to take a link down or up; `Event::{RootInconsistent, LoopInconsistent}` are plain facts. `mcheck` and `rstp_version` (#319), CIST only (#321).

## MSTP (`nos-stp::mst`, #321)

- Model: each MSTI is a second [`Bridge`] with bridge id = MSTI priority + MSTID as system id extension, so the clause 13 machines run unchanged per tree. The CIST bridge is instance 0.
- Remaining hops: an MSTI bridge uses `max_age = MaxHops` and a received message's "message age" is `MaxHops - remainingHops`, so PRX's aged-BPDU drop and `rcvdInfoWhile` are the remaining-hops rules. A sender's remaining hops is `MaxHops` minus its `designatedTimes.messageAge`.
- Wire: one MST BPDU per port carries the CIST and every enabled MSTI message. The CIST bridge's transmit is the pace; an MSTI's Transmit action only triggers a send (so a burst can exceed the CIST's `txHoldCount` by the number of MSTIs).
- Region check on receive: `mismatch(name, revision, digest)`. Same region: the MSTI messages are delivered to the instances by the MSTID in the regional root. Else (or a plain BPDU) the port is `Edge::Boundary`, its MSTI bridges are disabled and the kernel state of every tree is the CIST's.
- Kernel states: `Engine::diff_states` pushes every `(tree, port)` whose effective state changed; a tree's assignments cover the domains whose `stp-instance` is that tree (0 for none). `FlushFdb` of an MSTI flushes only its domains.
- Deviations: the CIST is a flat 5-component vector (external and internal root path costs summed, the regional root is the CIST root, internal cost 0 on send); `rcvdInternal`/`infoInternal` and the Master port role are not modelled, a boundary port follows the CIST instead; port protections other than `bpdu-filter`/err-disable act on the CIST only.
- The BPDU socket's receive buffer is 1536 bytes (an MST BPDU with 64 MSTI messages is 1143 bytes plus the frame header); at the old 128 bytes every v3 BPDU with MSTIs was dropped as truncated.
- Every 10 s the daemon re-pushes every `(port, domain)` state (`Engine::all_states`): `nos-interfaced` only writes states that differ, and a resync running at the same time as a plan rebuild was seen to overwrite a pushed Blocking with the previous Forwarding.
- Known limit of `nos-interfaced`, not of MSTP: a tagged trunk over a parent link that is administratively down fails to bring `ethX.<tag>` up (ENETDOWN) and is retried forever; `nos-interfaced` now raises an admin-down parent itself, proven by the `reconcile_tagged_subinterfaces` kernel test in `interface/src/driver/linux.rs` (#338, #355); the `stp-mstp` phase only asserts no ENETDOWN loop and the sub-links' state.
- Tests: `stp/src/mst/` (digest oracle, VLAN map, region mismatch, a two-engine run with two trees blocking different links) and the `stp-mstp` e2e phase.

## Deviations from the standard's text

- `setSyncTree` also clears `synced`. With `sync && synced` already true, a Designated port neither discards nor clears `sync` (both need `!synced`) and stalls forever; found by the random-graph test.
- `PIM` resets `agree` on superior info, so a new root port always runs a fresh sync/agreement cycle.
- DESIGNATED_DISCARD is tested before DESIGNATED_SYNCED: a forwarding port must stop forwarding before it counts as synced.
- A down port never transmits (`PTX` requires `portEnabled`).
- `rcvInfo` treats a Designated BPDU from the same bridge/port as the stored info but with different values (e.g. a larger cost) as superior, so upstream changes are accepted.
- Sender identity (`rcvInfo`) and the own-bridge tests in `updtRolesTree` are bridge MAC plus port number only; priority and system-id extension are excluded, so a neighbor that changes its priority is the same sender with new info, not an inferior BPDU (#661). `BridgeId`/`PortId` ordering stays the full 13.10 order.
- A BPDU whose message age is already at max age is dropped in `PRX` (9.3.4).

## Legacy 802.1D compatibility (#319)

- `Bridge::set_rstp_version(false)` is `forceVersion < 2`: PPM restarts with `sendRSTP` false, so PTX sends Config (Designated) or TCN (Root) and PRT/PST use `fdWhile` instead of the proposal handshake. `Plan::rstp_version` carries the config value, so a change rebuilds the bridge.
- A port starts with `sendRSTP` true; PPM moves it with `rcvdSTP`/`rcvdRSTP`/`mcheck` and each real change emits `Event::ProtocolMigrated`, logged as `port migrated to STP` / `port migrated to RSTP` (field `port`; a forced bridge logs STP once per port at start).
- `Bridge::mcheck(port)` sets the `mcheck` variable; `Engine::mcheck(None | Some(name))` applies it and returns the port count. The actor serves it from `StpRequest::Mcheck` (`StpEvent::Mcheck { ports }`, `User` and `Restd`).
- Port states stay discarding/learning/forwarding: legacy Listening is `Discarding` (the kernel neither learns nor forwards in it).
- Sim scenarios: a forced-STP bridge in a triangle, an all-legacy topology change (TCN, `FlushFdb`) and the `mcheck` round trip, in `stp/src/sim.rs`.

## Port protections (#320)

- `Bridge::receive` is the one place BPDU guard and filter act: a filtered or err-disabled port drops the BPDU; a guarded port that is `operEdge` and enabled is err-disabled (`Action::ErrDisable`, `portEnabled` forced false) before PRX sees the frame. `transmit` returns early on a filtered port.
- Err-disable is held in the core (`err_disabled`, `err_remaining`): `set_port_enabled(true)` is ignored while it is set, `tick` counts the recovery down, `clear_err_disabled` (`clear`, timer) emits `Action::ErrRecover`.
- Root guard: PRS skips a `root_guard` port as a root candidate; if it would have won, `root_inconsistent` is set and the port is selected Alternate (the existing "received info worse than ours" arm). It clears when the superior info ages out.
- Loop guard: PIM entering AGED on a Root/Alternate/Backup `loop_guard` port sets `loop_inconsistent`; PRS selects such an aged port Alternate instead of Designated, and PIM leaves AGED (via UPDATE) when a BPDU arrives. A link down clears it (PIM DISABLED).
- Restricted TCN: TCM NOTIFIED_TC skips `setTcPropTree` on a `restricted_tcn` port (a locally detected change still propagates).
- Daemon: the engine maps `ErrDisable`/`ErrRecover` to `Out::ErrDisabled`, pushed as `InterfaceRequest::SetErrDisabled { port, disabled }`; `nos-interfaced` keeps the set (carried over resyncs) and applies the link administratively down. `interface_client` resends the set on reconnect. A plan change rebuilds the bridge but `restore_err_disabled` keeps a port that still has `bpdu-guard` down (the new recovery value wins); the others are released and log `port err-disabled recovered`. A fresh start asks `nos-interfaced` (`GetInterfaces` + `GetPortAggregates`, `err_disabled` on the status structs; `Role::Stpd` may send only those two of the Get* requests) which ports it still holds: held ports that keep `bpdu-guard` stay down through the same `restore_err_disabled` with the full configured `bpdu-guard-recovery` (manual if unset), the others are released, never-held ports get no push. Unreachable for 10 s, it logs `cannot read the err-disabled ports from nos-interfaced, releasing none` and releases nothing (fail closed). Only the first plan apply asks.
- `clear spanning-tree err-disabled <if>` is `StpRequest::ClearErrDisabled { interface }`, answered `StpEvent::ErrDisabledCleared { cleared }` (`User`/`Restd`).
- Logs: `port err-disabled` (`port`, `reason=bpdu-guard`), `port err-disabled recovered`, `port root-inconsistent`/`root-consistent`, `port loop-inconsistent`/`loop-consistent` (all `port`).
- `bpdu-filter` does not turn the port into an operEdge forwarding port (the standard has no such rule); it only silences BPDUs, so a non-edge filtered port still goes through the normal handshake and ends up forwarding.

## Run and read the simulator

- `cargo test -p nos-stp sim` runs `stp/src/sim.rs`: N bridges joined by in-memory links (two ends point-to-point, more a shared segment), BPDUs delivered instantly, time moves only on `Sim::tick`.
- A failing scenario prints `Sim::dump()`: root port, role and state of every port. `Sim::converged()` means one root everywhere, every port settled, and the forwarding links form a tree (a loop of stale root info otherwise looks settled).
- Property tests: `PROPTEST_CASES=3000 cargo test -p nos-stp random` stresses random 4-8 bridge graphs (also with a cut link).
- Expected timing with default timers: a point-to-point link converges within a few hello times; a shared segment waits `max-age + forward-delay` after start.

## Daemon (`nos-stpd`, #327)

- One fixed process, supervised like `nos-lldpd`; `--listen-socket` serves the status query (below).
- Ports: a physical `Interface` or a `PortAggregate` (the bond, never a member) with a `switching_profile`; loopbacks, VXLAN and L3-only interfaces are not ports. Modes `rstp`, `mstp` and `rapid-pvst` run; `disabled` leaves the daemon idle.
- Task layout, all in `stp/src/daemon.rs`: one actor owns the bridge core and every BPDU socket; a reader task per port, the link table, plan changes and a 1 s tick are events to it. A changed plan rebuilds the bridge (the protocol restarts, sockets of ports that stay are kept).
- The BPDU socket (`L2Socket::open_bpdu`) is `ETH_P_ALL` with a classic BPF for the group MAC plus LLC `42 42 03`. A protocol-bound socket runs after tc ingress and the bridge `rx_handler`, where the trap from #326 drops the frame; the tap runs before. It sees its own outgoing frames, so the source MAC is filtered.
- Inputs to the core per port:
  - `portEnabled`: socket open and the `SubscribeLinks` table shows carrier (no table or an unobserved one counts as up).
  - Cost: the profile `cost`, else `20 000 000 / speed` from `/sys/class/net/<dev>/speed`; unknown speed falls back to 1 Gb/s with a `warn!`.
  - `operPointToPoint`: profile `link-type`, else full duplex (unknown counts as full). Re-read on every carrier change.
  - Edge: `edge-port admin` is admin edge, `auto` (the default) is the core's own BPDU-absence detection, `disabled` neither.
- Bridge identifier: configured priority, extension 0, MAC derived from hostname + machine-id (locally administered); port number is the index in the name-sorted port list plus one.
- Output: the state of a tree on a port becomes one `SetStpPortStates` assignment per domain of that tree in the port's switching profile (`Discarding` is `Blocking`; in `rstp` every domain is the CIST's); `FlushFdb` becomes one `FlushFdb` per domain of the tree. The push is fire-and-forget; the cache is resent on every reconnect.
- Logs (the e2e anchors; `Debug` renders roles and states capitalised):

| Line | Fields |
|------|--------|
| `port role changed` | `port`, `role` (`Root`, `Designated`, `Alternate`, `Backup`, `Disabled`) |
| `port state changed` | `port`, `state` (`Discarding`, `Learning`, `Forwarding`) |
| `root bridge changed` | `root` (`8000.02:aa:bb:cc:dd:ee`) |
| `port carrier up` / `port carrier lost` | `port` |
| `bpdu rx` | `port`, `count` received in the last 10 s, every 10 s per enabled port |
| `mst configuration` | `name`, `revision`, `digest`, `instances`; once per start in `mstp` |
| `mst region match` / `mst boundary port` | `port` (+ `digest`) / `port`, `reason` (`plain-bpdu`, `name`, `revision`, `digest`); on change |
| `msti port role changed` | `port`, `msti`, `role` |
| `msti port state changed` | `port`, `msti`, `state`, `domains` (comma list of the tree's domains on the port); the effective state, a boundary port shows the CIST's |

## Rapid-PVST+ (`nos-stp::pvst`, `sstp`, #322)

- Model: `Plan.pvst` holds one `TreePlan` per domain of the switching profiles, each a complete `Plan` of its own (`ext` = the domain's VLAN as bridge-id system id extension, the domain's `stp-priority` and timers over the global ones, only the ports that are members, with the member's `stp-cost`/`stp-priority` over the port profile's). `pvst::Pvst` runs one `Engine` per tree, so the clause 13 machines, protections, `force-version` and legacy migration work per tree unchanged. Port numbers differ between trees (index in the tree's port list); they are only compared within a tree.
- Frames: `sstp.rs` is the Cisco framing (802.3, LLC/SNAP `AA AA 03 00 00 0C 01 0B`, the IEEE BPDU body, then the Originating VLAN TLV: type 0, length 2, VLAN id). A frame without the TLV is accepted (`pvid: None`). Layout from Wireshark's `packet-stp.c`; the test vectors are assembled from it, not captured.
- Links: a tagged member's BPDUs use the sub-link `<port>.<tag>` (the kernel adds the tag), an untagged member's the port itself. `L2Socket::open_pvst(link, ieee)` is an `ETH_P_ALL` socket with a BPF of either group; the SSTP group is always joined, the IEEE one only for the untagged member (the native rule: `pvst::tx_wires` sends both forms, `pvst::accepts` ignores an IEEE BPDU elsewhere). Carrier is read per link, so a sub-link that is down disables only its tree.
- PVID inconsistency: `Pvst::receive` compares the TLV with the tree's VLAN; a mismatch forces the `(port, domain)` kernel state to Blocking (`Pvst::wrap` rewrites the engine's pushes) and keeps the BPDU out of the machines. It clears on a consistent BPDU or after 3 hellos without any.
- Kernel states: each tree pushes `SetStpPortStates` for its own domain only (the sub-link of a tagged member), and a `FlushFdb` flushes that domain only.
- Logs (the e2e anchors; roles and states capitalised):

| Line | Fields |
|------|--------|
| `pvst port role changed` | `domain`, `port`, `role` |
| `pvst port state changed` | `domain`, `port`, `state` |
| `pvst root bridge changed` | `domain`, `root` (`100a.02:aa:bb:cc:dd:ee`: priority plus VLAN) |
| `pvst port migrated to STP` / `pvst port migrated to RSTP` | `domain`, `port` |
| `pvid inconsistent` | `domain`, `port`, `expected`, `got`; `pvid consistent` with `domain`, `port`, `reason` (`bpdu`, `silence`) |

- Limits: `clear spanning-tree detected-protocols` and `clear spanning-tree err-disabled` act on `rstp`/`mstp` only; a bond's sockets use the config name like the other modes. A changed plan rebuilds every tree.
- Tests: `stp/src/sstp.rs` (layout, round trips, rejects), `stp/src/pvst.rs` (two bridges, two trees blocking different links; PVID block; per-tree fallback; native rule), `ports.rs` (tree plans) and the `stp-pvst` e2e phase.

## Status query (#328)

- Path: `nos show spanning-tree` / `GET /v1/spanning-tree` resolve `ServiceRef::Stp` through the watchdog, then send `StpRequest::GetSummary`; the reply is one `StpEvent::Summary(StpSummary)`.
- `stp/src/server.rs` answers from an `Arc<RwLock<StpSummary>>` snapshot. The daemon actor rewrites it after every event (plan change, BPDU, link change, tick) from `Engine::summary()`; no engine (mode `disabled`) publishes the default, `enabled: false`.
- `stp/src/authz.rs`: `allowed(role, &StpRequest)` lists `User` and `Restd`, no wildcard arm; any other role is disconnected with a `warn!`.
- Roles and states are the `StpRole`/`StpState` enums, so the CLI and REST print the same words. Bridge and port ids are display strings (`8000.02:aa:bb:cc:dd:ee`, `128.1`).
- Root path cost is the root port's received cost plus its own; the timers are the root's (`rootTimes`), what the bridge actually runs.
- `StpSummary` only grows by appended fields; `mst` (#321) holds the region and every instance's root and ports, which `show spanning-tree instance`/`mst-config` and the two `GET /v1/spanning-tree/...` routes render, so MSTP added no request variant. `pvst` (#322) is one `StpInstance` per Rapid-PVST+ tree (`id` is the VLAN; ports carry `inconsistent` and `compat`), served by `show spanning-tree domain` and `GET /v1/spanning-tree/domain/<bd>`; its top-level ports are empty.
- Counters and topology changes (#323) ride the same summary, no new request. `Engine` keeps one `StpPortCounters` per port (bumped in `receive_rx`, in `drain` for BPDUs it emits, on `ProtocolMigrated` and on `SetPortState` to forwarding; `note_invalid` is the daemon's decode-failure hook) and one `Tc` record per tree. TCM emits `Event::TopologyChange` when it enters `Detected` (local), `NotifiedTcn` or `NotifiedTc` (received; a TCN counts once although it chains through both). `Engine::note_tc` counts a received change once per episode: a flag repeated on the same port within `EPISODE_HELLOS` (3) hellos is the same change. Time is `uptime`, one per `tick`, so "seconds ago" needs no clock.
- The MSTIs share the CIST port's counters and keep their own `Tc` record (`topology` of each `StpInstance`); each Rapid-PVST+ tree is an `Engine`, so its counters are per `(port, domain)`.
- Every log message of the core is a constant in `stp/src/events.rs`, pinned by a unit test; a log site writes `info!(port = %p, "{}", events::NAME)`.
- Read the state of a running lab: `cargo run -p nos-e2e -- logs 200` and look at the last `port state changed` per port.
- Limits: no in-place update of priority, timers or cost (a config change restarts the protocol); a link whose speed changes without a carrier change keeps its old cost.
