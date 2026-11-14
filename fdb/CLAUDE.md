# nos-fdb — Forwarding-database (EVPN/VXLAN) component

`nos-fdbd` is the MAC counterpart of `nos-ribd`: one process per `BroadcastDomain` that has a `vni` (spawned by `nos-watchdogd` through `instances::manage`, `claim_label: "vni"`, the opt-in mechanism `nos-restd` uses on `rest-api`). It owns the kernel side of the domain's EVPN: a VXLAN device enslaved into the domain's bridge, and the bridge FDB behind it, in both directions.

| `nos-ribd` (per `RoutingTable`) | `nos-fdbd` (per `BroadcastDomain`) |
|---|---|
| owns the kernel VRF + routes, deletes them on shutdown | owns the kernel VXLAN device + FDB entries, deletes the device on shutdown |
| `nos-bgpd` pushes learned routes in (`PushBgpRoutes`) | `nos-bgpd` pushes received EVPN routes in (`FdbRequest::PushEvpnRoutes`) |
| pushes redistributed routes to `nos-bgpd` (`RedistributeRoutes`) | pushes local MACs to `nos-bgpd` (`BgpRequest::RedistributeMacs`) |
| `show route <table>` | `show fdb <domain>` (`GET /v1/fdb/{domain}`) |

Config is a `BroadcastDomain` (`vni`, `rd`, route targets, `vtep_source`, `redistribute from mac|arp|connected to bgp <instance>`, `neigh_suppress`). The daemon is only *ready* (`fdb::Ready`) when `rd`, `vtep_source`, `mac_redistribute`, the bridge (`nos-interfaced` `GetBroadcastDomain`) and the VTEP address (`GetInterface`) all resolve; until then it idles and the 10s tick retries. A `neigh_suppress` or `irb`-only change is applied in place (`set_ready`), never a rebuild.

## Kernel pitfalls (`driver/`)

`FdbDriver` (`--driver linux|noop`). Each of these cost a debugging session:
- `vx<vni>` needs **`dev <underlay>`** (`eth0`, or `lo<table-id>` via `RibRequest::GetTableId`): inside a VRF the kernel binds the UDP socket only through that device. A device opened before its underlay joined the VRF is reopened (`bound_master`), else every FDB nexthop group is sent via the main table and dropped (`tx_carrier_errors`).
- Every remote FDB entry must name its underlay (`via`/`NDA_IFINDEX`, the `underlay` map).
- Flood list = one all-zero-MAC entry per remote VTEP, which needs `NLM_F_APPEND`; `NeighbourAddRequest` hardcodes its flags, so every FDB write is a raw `Handle::request`.
- Remote MAC: `NTF_SELF|NTF_MASTER|NTF_EXT_LEARNED`, permanent. Bridge-port learning is **off** on `vx<vni>` (`IFLA_BRPORT_LEARNING`, #173).
- `bridge fdb add` defaults to *permanent*: pin a test MAC with `static`.
- Segment pin: `NUD_NOARP` + nested (`NLA_F_NESTED`) `NDA_FDB_EXT_ATTRS { NFEA_ACTIVITY_NOTIFY }`, not `extern_learn`.
- Single-active block: STP state **disabled** via `RTM_SETLINK` + `IFLA_PROTINFO`. *Blocking* and the `RTM_NEWLINK` slave-data path silently do nothing.
- A forward-facing FDB entry must be **deleted before it changes form** (nexthop group vs plain): the kernel keeps the old form on `replace`.
- Nexthops (`nexthop.rs`) are hand-encoded netlink, unit tests pin the bytes; tc goes through `nos-tc` (`tc/CLAUDE.md`: priorities 1 and 2 are ours).
- With the underlay in a VRF, receiving VXLAN needs `net.ipv4.udp_l3mdev_accept=1`; nothing in nos sets it (unprivileged daemons), the e2e helper does.
- Loop guards: `local_macs` skips `extern_learn` entries (fdbd's own writes), the VXLAN port and inactive segment pins.

## IPC

- `--listen-socket` `/run/nos/fdb-<domain>.sock` (`ServiceRef::FdbDomain`); `allowed`: `PushEvpnRoutes` is `bgpd`'s, `GetMacs` is `user`/`restd`. `server::handle_connection` stages `EvpnUpdate::FullPart`s per connection and applies the assembled `Full` once (#720). The other direction, `bgp_client.rs`'s `RedistributeMacs`, cuts a big `Full` the same way (`send`, `EvpnUpdate::split_with`, #725).
- `bgp_client.rs` originates this domain's Type-3, Type-2 (MAC and MAC+IP) into `ServiceRef::BgpInstance(mac_redistribute)`, `Full` on every (re)connect.
- **Route-Target filtering is fdbd's** (`fdb::desired`): `nos-bgpd` pushes every received EVPN route.
- Symmetric IRB (#188): `Ready.irb` from `RibRequest::GetEvpnIrb`.
- Type-5, the L3 VNI and the Router's MAC are `nos-ribd`'s (`docs/internals/rib.md` "EVPN IP-VRF"); MAC mobility is resolved in `nos-bgpd`.

## Ethernet Segments, DF and local bias: invariants

- `df.rs` is pure. `Fdb::sync_df` re-runs the election on every received Type-4/per-EVI A-D change and every resync; an algorithm change re-elects without a new DF wait.
- DF wait blocks the port first; the election is applied only when it ends.
- `desired` pins a remote Type-2 for a local segment only while the port can carry unicast (`pinnable`).
- ES-down comes from `port_up` (`IFF_LOWER_UP`), read by `refresh_local`; a dead port withdraws Type-4 and both Type-1.
- Mass withdrawal: a remote Type-2 with a non-zero ESI is installed only while its PE's per-ES A-D is held.
- Local bias (RFC 8365 §8.3.1, #24) **replaces** "non-DF refuses all BUM". BUM reaching an all-active segment port P: from a local access port, deliver always; from the VXLAN port, from a PE on P's segment, drop always; from any other PE, deliver only when P is the DF. Unknown unicast keeps the DF rule; single-active is excluded.
- **Order is the safety property** (`sync_df`): egress filters, then ingress marking, then the multicast/broadcast flood flags open. A missing piece degrades to duplicates, never loss. If tc setup fails the port keeps DF-only flooding (`local_bias: false`, warning `local bias unavailable, df-only flooding`).
- The mark is `0xE5000000|bitmap(P)` (mask `0xFF00FFFF`); 16 all-active segments per domain, the 17th is DF-only.
- `enc_src_ip` only matches with tunnel metadata on: `set_local_bias` keeps a `nop` `tun_id` fib rule per domain (#460). A flower `enc_*` filter alone does not turn it on.
- Type-4 counts (`ad_index`) for any ESI when it carries that ESI's ES-Import RT: it feeds only the single-active `backup_pe`; `plan_df` reads Type-4s itself, by exact ESI. `max_remote_macs` (`Fdb::sync_keys`) admits the lowest N remote `Mac`/`MacGroup` addresses, moved incrementally at the boundary (O(log N) per changed MAC; no ceiling = O(1) per push, #604; every change to a route's `desired` inputs must pass that key to `sync_keys`; `holders` refcounts `installed`); neighbours, flood and `SegmentMac` don't count.
- Ceilings are `ponytail:` comments: search `ponytail:` in `fdb/src` (HRW only cross-checked nos-to-nos, 255 nexthops + groups per domain, 16 segments, reserved mark bits, `del_segment_mac`).

## Modules

| Module | Role |
|---|---|
| `main.rs` | flags, PKI identity from stdin, tracing + `ForwardingLayer`, spawns reconcile / local-MAC loop / bgp push / server; SIGINT deletes the VXLAN device |
| `fdb.rs` | `Fdb`: the MAC table (`received`, `installed`, `local` with each MAC's port, `ads`, `es_down`), `desired`/`local_routes`/`plan_df`/`plan_local_bias`/`ad_index` (pure), `set_ready`/`apply_push`/`sync_df`/`refresh_local`/`run_local`/`table` |
| `df.rs` | pure DF election (`candidates`/`elect` modulo, `elect_hrw`/`hrw_weight`, `effective`) |
| `reconcile.rs` | config diff + tick → `Ready` → `Fdb::set_ready` |
| `driver/` | `FdbDriver`, `linux.rs`, `noop.rs`, `nexthop.rs`, `is_local_mac` (pure) |
| `bgp_client.rs`, `interface_client.rs`, `server.rs` | push to `nos-bgpd`; bridge/VTEP/bond lookups (over `nos_daemon::ipc::one_shot`); `GetMacs`/`PushEvpnRoutes` |

Config/watchdog clients and the `main()` bootstrap come from `nos-daemon` (`daemon/CLAUDE.md`).

`nos-e2e evpn-fdb`, `evpn-esi`, `evpn-single-active`, `evpn-dataplane` and `evpn-v6` are the end-to-end proof (log anchors, kernel read-backs).

Details: [implementation notes](../docs/protocols/evpn-vxlan.md#implementation-notes-nos-fdbd) (config, kernel side, DF, local bias, ceilings).
