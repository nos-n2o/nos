# nos-lldp — LLDP (IEEE 802.1AB) Daemon

A real, from-scratch Link Layer Discovery Protocol implementation for NOS (binary `nos-lldpd`, a single fixed process — see `docs/architecture/supervision.md`; same reasoning as `nos-lacpd`/`nos-interfaced`/`nos-logd`: LLDP has no per-VRF/per-instance multiplicity to key a dynamic per-object spawn off).

## Scope

`nos-lldpd` runs one raw `AF_PACKET` socket per LLDP-enabled **physical** interface, transmitting this system's identity and recording the neighbors it hears. It **never touches rtnetlink** and owns no kernel state — `nos-interfaced` already brings every configured physical interface admin-up, which is all LLDP needs. It has `CAP_NET_RAW` only. It exists as its own daemon (rather than a module of `nos-interfaced`) because it parses untrusted frames from the wire: a bug in a decoder should not take down interface reconciliation.

Config is two independent booleans on `Interface` (`lldp_transmit`, `lldp_receive`, both off by default, physical interfaces only — `valid_lldp_physical_only` rejects them on a `loopback-*` interface at commit time). CLI: `set|delete interface <name> lldp transmit|receive`, `show lldp neighbors [detail]` and `show lldp statistics`. A member of a `PortAggregate` is an ordinary `Interface`, so LLDP runs on the physical members, never on the bond device (as the standard requires).

Four more knobs, none of which enable LLDP by themselves:

- **Timers** (system-wide, `Config.lldp`, `nos_proto::LldpSettings`): `set lldp tx-interval <secs>` (`msgTxInterval`, 1–3600, default 30) and `set lldp tx-hold <n>` (`msgTxHold`, 1–100, default 4). The advertised TTL is `hold × interval` (default 120s) and `LldpSettings::check` rejects a product over 65535, since the TTL field is 16 bits and the two ranges alone allow 360000. The daemon reads them through `LldpSettings::effective_*`, the same helpers the validator uses.
- **Management addresses** (system-wide, `LldpSettings.management_addresses`): `set lldp management-address <ip>` adds one, `delete lldp management-address <ip>` removes one. Up to `MAX_MANAGEMENT_ADDRESSES` (4, in `nos-proto` so the sender's and receiver's caps are the same number) unique IPv4/IPv6 unicast addresses, each in its own TLV on every LLDP-enabled link. Taken as configured, never checked against kernel state at commit. A config saved before the list existed (`management_address: <ip>`) still loads, via a serde alias plus a scalar-or-list deserializer.
- **System Description** (system-wide, `LldpSettings.system_description`): `set lldp system-description <text>`, 1-255 bytes, no control characters, default `nos` (never a version). Part of `LinkConfig`, so a change restarts the links.
- **Destination group** (per interface, `Interface.lldp_destination`): `set interface <name> lldp destination nearest-bridge|non-tpmr|customer-bridge` → `01:80:C2:00:00:{0E,03,00}`. Physical interfaces only, like the on/off flags.

A change to any of these restarts the affected links (`LinkConfig` equality): a shutdown LLDPDU, then a fresh advertisement, so neighbors briefly drop and relearn. Not worth an in-place timer hot-swap.

## Decode robustness

`packet::decode` is the one place untrusted bytes are parsed and never panics; the rules (TLV bounds, order, skipped vs rejected, caps, `lossy`) are in [internals](../docs/internals/lldp.md#decode-robustness).

## Explicitly deferred (documented, not silently missing)

- **DCBX and other organizationally-specific TLVs** (received ones are skipped, never stored). LLDP-MED is config-only until #1572: the schema is in [internals](../docs/internals/lldp.md#lldp-med-configuration).
- **Port VLAN ID and 802.3 MAC/PHY transmit** — decoded only, see "What is sent" in [internals](../docs/internals/lldp.md).
- **Several destination groups per interface** — one group each, chosen in config.


## Behavior that bites

- A stopping `transmit` link sends a TTL-0 shutdown LLDPDU (`shutdown_pdu`, not credit-gated): neighbors drop at once, which `nos-e2e lldp` depends on.
- Fast start (802.1AB §9.2.5.19-21) and `txCredit` (`TX_CREDIT_MAX` 5, +1/s) bound transmits; only a `New` neighbor restarts a burst, so two systems settle.
- `handle_rx` logs `neighbor learned`/shutdown `removed` at `info` only while the link's `LogBucket` has a credit (burst 5, +1 per 10s), else `debug`; the table is never affected.
- Neighbor identity is (chassis id, port id); `NeighborTable` is capped at `MAX_NEIGHBORS_PER_LINK` (32), since input is untrusted.
- Own frames are dropped twice (source MAC in `socket::payload_of_foreign_frame`, own chassis id in `link::handle_rx`); a down link is retried (`LINK_DOWN_RETRY` 1s), never fatal; never leave an elapsed deadline armed (as in `nos-lacp`).
- The chassis MAC is derived (FNV-1a of hostname + machine-id, `reconcile::local_system_id`, `ponytail:` collision caveat as in `nos-lacp`).
- Sockets follow `nos-interfaced`'s `LinkRemoved`/`LinkAdded` (`link_client`, #1431, no polling): `absent` closes the socket and clears neighbors, a new epoch reopens it with a fast-start burst; the task survives. `no-carrier` and `admin-down` flush the neighbor table once per transition (`lldp neighbors flushed … reason=`, 802.1AB portEnabled false, #1519) and keep the socket.
- Destination group is one per interface; a different group on each end never sees the other.

## Modules

| Module | Role |
|---|---|
| `main.rs` | Single-instance args (`--watchdog-socket`, `--listen-socket`, `--log-socket`); links send a shutdown LLDPDU on exit |
| `packet.rs` | Hand-rolled TLV codec (`decode_counted`, `TlvCounts`), pure |
| `socket.rs` | `nos-l2-socket` wrapper, ethertype `0x88CC` |
| `neighbor.rs` | Pure `NeighborTable` (`apply`, `expire`, `snapshot`), `now` passed in |
| `link.rs` | Per-interface `run()`, `SharedPorts` read by `server.rs` |
| `link_client.rs` | `SubscribeLinks` table + per-name epochs (copy of `nos-stpd`'s) |
| `reconcile.rs` | Diff-triggered resync (`desired_links`), 10s tick |
| `server.rs` | `GetNeighbors`/`GetStatistics` on `--listen-socket` (`ServiceRef::Lldp`) |
| (no `config_client`/`watchdog_client`) | config, watchdog and `main()` bootstrap come from `nos-daemon` (`daemon/CLAUDE.md`) |

Details: [internals](../docs/internals/lldp.md) (TLVs sent, behaviour notes, per-module notes, `nos-e2e lldp` narrative), [LLDP guide](../docs/protocols/lldp.md), [e2e phases](../docs/e2e-phases.md).
