# nos-tc — hand-encoded Linux tc

A leaf crate (only `netlink-sys`, no NOS dependencies, like `nos-l2-socket`): the tc messages `netlink-packet-route` cannot build (`gact`, `skbedit`, `fw`, chains, action cookies, stats dumps), encoded by hand and sent on a plain `NETLINK_ROUTE` socket. Used by `nos-fdbd` (EVPN local bias), `nos-interfaced` (STP BPDU trap) and `nos-acld` (#541).

## API

- `Request`: `Clsact { ifindex }` (exclusive: tolerate `EEXIST`), `AddFilter(Filter)`, `DelFilter { .., prio, protocol, handle }` (`handle == 0` deletes the whole priority), `FlushChain` (`RTM_DELCHAIN`: every filter of the chain goes; `ENOENT` if it has none).
- `Filter { ifindex, hook, chain, prio, protocol, handle, kind, actions, replace }`:
  - `chain == 0` sends **no** `TCA_CHAIN`, so the fdb/interfaced messages stay byte-identical.
  - `replace` adds `NLM_F_REPLACE`: the same handle at the same chain/prio is swapped in place (one RCU swap).
  - `Protocol::Ip`/`Ipv6` also send `TCA_FLOWER_KEY_ETH_TYPE`: flower ignores every L3 key without it.
  - `Protocol::Dot1Q` (0x8100, tagged frames only; untagged traffic never matches) also sends `KEY_ETH_TYPE`; it is the only protocol `FlowerKeys.vlan_id` (`0..=4094`, host-order u16, kernel-proven) accepts, and refuses any L3/L4 key alongside (`KEY_VLAN_ETH_TYPE` is not modelled).
  - `Kind::Flower(FlowerKeys)` (all `None` = match-all; a keyless flower, not `matchall`, because only flower replaces in place) or `Kind::Fw { mask }`.
  - An exact port (`min == max`) uses the `TCP_*`/`UDP_*` key (needs `ip_proto` 6 or 17); a range uses `PORT_*_MIN/MAX` (the kernel wants min below max).
- `Action { kind, cookie }`: `Gact(Verdict)`, `Skbedit { mark, mask, verdict }`, `Sample { rate, trunc, group }` (`act_sample`, always `pipe`; the kernel hands the cookie to psample), `Police { rate, burst, unit: Bytes|Packets }` (exceed drops, conform `pipe`; neither may be 0), `Mirred { ifindex }` (`act_mirred` egress redirect, `TC_ACT_STOLEN`, ifindex non-zero; only redirect is modelled, no mirror modes) or `Pedit(Pedit::Dscp { value <= 63, family })` (the IPv4 form also emits an `act_csum` entry, so it takes two table slots). `Verdict::GotoChain(n)` is `TC_ACT_GOTO_CHAIN | n`, `n < 2^28`; `Verdict::Unspec` is `TC_ACT_UNSPEC`: matched and counted, the next filter runs. A cookie is at most 16 bytes.
- `FlowerKeys.ip_tos: Some(dscp)` matches the DSCP (ECN masked out). No flow-label key exists in flower on 7.2: unsupported, refuse it upstream.
- Fall-through facts (spike, #563): a miss inside a `goto chain` target ends classification (no fall back to later chain-0 filters); an `Unspec` filter falls through to the next filter of its chain. Details in `docs/architecture/linux-drivers.md`.
- `encode` refuses (`InvalidInput`) what the kernel would reject less clearly: long cookie, chain ≥ 2^28, inverted range, exact port without tcp/udp, prefix too long, police rate or burst 0, DSCP over 63, `vlan_id` over 4094 or without `Dot1Q`, `Dot1Q` with an L3/L4 key, mirred ifindex 0.
- `send(&Request, tolerate)` and `dump(ifindex, hook, chain) -> Vec<FilterStats>` **block**: call them from `spawn_blocking`.
- psample (generic netlink, hand-decoded, #544): `psample() -> Psample { family, group, user_cookie }` (`CTRL_CMD_GETFAMILY`; `ENOENT` until the module loads; `user_cookie` = `CTRL_ATTR_MAXATTR` reaches `PSAMPLE_ATTR_USER_COOKIE`), `SampleSocket::open` joins `packets` (`CAP_NET_ADMIN`), `recv() -> Vec<Sample { group, in_ifindex, out_ifindex, cookie, data }>` (blocking; `ENOBUFS` = drops, socket still usable).
- `FilterStats`: one row per **action** (`chain, prio, handle, action, cookie, packets, bytes`); `TCA_STATS_PKT64` wins over the 32-bit `gnet_stats_basic` count. A missing chain dumps as an empty list.

## Priorities in use (chain 0, first match wins)

| Owner | Hook | Prio | What |
|---|---|---|---|
| `nos-fdbd` | VXLAN ingress | 1, 2 | `flower enc_src_ip` + `skbedit mark` (peers, catch-all) |
| `nos-fdbd` | segment port egress | 1, 2 | `fw` + `gact drop` (local bias, DF) |
| `nos-interfaced` | bridge port ingress | 1 | `flower dst_mac` + `gact drop`, protocol 802.2 |
| `nos-interfaced` | bond egress / member ingress (#895) | 3 | `flower vlan_id` + `mirred` redirect / `gact drop` |
| `nos-acld` flowspec (#561, part B) | ingress | 10..99 | one flower prio per rule, directly in chain 0 (a `goto chain` miss would skip the ACL); a stopping rule jumps to chain 999, which jumps to the live ACL chain |
| `nos-acld` (#541) | ingress/egress | 100 | keyless flower `goto chain` 1000/1001 |

- Nobody deletes the `clsact` qdisc: every owner only ensures it.
- Delete only your own priorities (or chains).

## Files

- `consts.rs`: uapi values, grouped by header; private (N2 of #545).
- `encode.rs` (pure): types, `encode`, `dump_request`. Tests in `encode_tests.rs`, including the golden bytes of the former fdb/interfaced encoders.
- `decode.rs` (pure): `ack`, `dump_part`. Tests in `decode_tests.rs`, including a captured kernel dump reply.
- `genl.rs` (pure): family request/reply, psample sample decode. Tests in `genl_tests.rs`, from a captured kernel reply and sample.
- `socket.rs`: the only I/O, a fresh socket per call (plus the long-lived `SampleSocket`).

## Adding a key or an action

1. The constant in `consts.rs`, under its header's group, value from the header (not memory).
2. A field on `FlowerKeys` (or an `ActionKind` variant), encoded in `flower`/`action`; validate in `check` if the kernel can refuse it.
3. A byte test in `encode_tests.rs`, and a case in `tests/kernel.rs` read back with `tc filter show`.

## Kernel test

- `unshare -Urn cargo test -p nos-tc --test kernel -- --ignored` (needs `ip`, `tc`).
- With `NOS_TC_CAPTURE=1 ... --nocapture` it prints `DUMP_REPLY`, `FAMILY_REPLY` and `SAMPLE_MSG` hex, the sources of `decode_tests.rs`'s and `genl_tests.rs`'s fixtures.
