# nos-nexthop

Hand-encoded Linux nexthop netlink over a plain `NETLINK_ROUTE` socket (`netlink-packet-route` has no nexthop messages). No NOS dependencies, like `nos-tc`. First user `nos-fdbd`; `nos-ribd` follows (#1582, #1587).

## API

- `Nexthop::{Gateway(Gateway), Group(Group), Delete { id }}`; `encode(&Nexthop, seq) -> io::Result<Vec<u8>>` (pure).
- `Gateway { id, gateway, oif, onlink, labels, fdb, replace }`: `labels` is an MPLS stack, outermost first, empty = no encap. `Gateway::fdb(id, ip)` is what `nos-fdbd` sends (`NHA_ID`, `NHA_GATEWAY`, `NHA_FDB`, bytes unchanged from before the move).
- `Group { id, members: Vec<(id, weight)>, fdb }`: weight 1..=65535 (stored as weight-1 over `weight`/`weight_high`). Always `CREATE|REPLACE`: re-sending an id swaps the member list atomically and routes keep pointing at the id.
- `send(&Nexthop, tolerate_errno)` and `dump(id_range) -> Vec<NexthopRecord>` **block**: call from `spawn_blocking`. `dump` filters by id so each daemon only sees its own range.
- `encode` refuses with `InvalidInput`: id 0 (auto-assign), empty group, member = own id or 0 or weight 0, `fdb` with `oif`/`onlink`/`labels`, more than `MAX_LABELS` (30, the kernel's `MAX_NEW_LABELS`) labels, a label above 2^20-1.
- Decoding skips unknown attributes (the kernel adds them); MPLS labels are read only when `NHA_ENCAP_TYPE` is `LWTUNNEL_ENCAP_MPLS`.

## uapi values (private `consts.rs`)

| Value | Header |
|---|---|
| `RTM_NEWNEXTHOP` 104, `RTM_DELNEXTHOP` 105, `RTM_GETNEXTHOP` 106 | `rtnetlink.h` |
| `NHA_ID` 1, `NHA_GROUP` 2, `NHA_BLACKHOLE` 4, `NHA_OIF` 5, `NHA_GATEWAY` 6, `NHA_ENCAP_TYPE` 7 (u16), `NHA_ENCAP` 8, `NHA_FDB` 11 | `nexthop.h` |
| `LWTUNNEL_ENCAP_MPLS` 1 | `lwtunnel.h` |
| `MPLS_IPTUNNEL_DST` 1: BE u32 `label<<12`, S bit 0x100 on the last | `mpls_iptunnel.h` |
| `RTNH_F_ONLINK` 4 in `nhmsg.nh_flags` | `rtnetlink.h` |

## Kernel rules

- `nhmsg` scope must be 0 in a request (the kernel picks link scope, else `EINVAL`); a delete leaves the protocol 0 too.
- A group takes no attribute but its members; `NHA_FDB` forbids `OIF`/`ENCAP`/`BLACKHOLE`.
- `NHA_ENCAP` is sent with `NLA_F_NESTED`; decoding masks the flag.
- Ids are netns-global. Convention (not enforced): `nos-fdbd` keeps its low per-VNI range (`NH_SLOTS`), `nos-ribd` takes `table_id << 20 | seq`.

## Kernel-proven (Linux 7.2, `tests/kernel.rs`)

- Gateway + oif, onlink off-subnet gateway, FDB gateway and group (v4 and v6), group replace in place, delete (`ENOENT` tolerated), `dump` vs `ip nexthop show`: pass.
- MPLS label-stack gateway (`mpls_iptunnel` loaded): `ip -d nexthop show` reads `100/200` and `dump` returns `[100, 200]`; the test prints `SKIPPED` when the module is absent.
- An IPv6 route cannot use an IPv4-gateway nexthop, alone or via a group: the kernel answers "IPv6 routes can not use an IPv4 nexthop". #1587's fallback must not rely on it.

## Tests

- Unit: `src/encode_tests.rs` (bytes), `src/decode_tests.rs` (dump replies built in the test). `socket.rs` is excluded from coverage (raw netlink I/O; the kernel test is its test).
- Kernel: `modprobe mpls_iptunnel` on the host, then `unshare -Urn cargo test -p nos-nexthop --test kernel -- --ignored --test-threads=1` (the tests share one netns; `ip` is the oracle).
