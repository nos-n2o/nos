# Router Advertisement internals

How `nos-radv` (binary `nos-radvd`) is built. Rules for editing the crate: [`radv/CLAUDE.md`](../../radv/CLAUDE.md). Operator guide: [radv](../protocols/radv.md).

## Packet layout

`packet::build_ra` writes the 16-byte RA header, then the options in this order, each length in units of 8 octets and never 0:

- Header: type 134, code 0, checksum 0 (the kernel fills it on an `IPPROTO_ICMPV6` raw socket), current hop limit, flags `M<<7 | O<<6 | Prf<<3`, router lifetime (u16), reachable time (ms), retrans timer (ms).
- Source link-layer address (type 1), read from `/sys/class/net/<if>/address` at each send.
- MTU (type 5), only with `advertise-mtu`, read from `/sys/class/net/<if>/mtu`.
- Prefix Information (type 3, 32 bytes): prefix length, flags `L<<7 | A<<6`, valid and preferred lifetimes, the prefix with host bits cleared.
- RDNSS (type 25), one option per address. A missing lifetime is `2 * max-interval`.
- DNSSL (type 31), one option per domain, RFC 1035 labels, zero-padded to 8 octets.

A final RA (`RaParams.final_ra`) is the same packet with router lifetime 0.

## Sockets

`nos-radv-socket::RaSocket::open` creates the raw socket, binds it to the device (`SO_BINDTODEVICE`), allows only types 133 and 134 (`ICMP6_FILTER`), sets unicast and multicast hop limit 255, switches multicast loop off, enables `IPV6_RECVPKTINFO` and `IPV6_RECVHOPLIMIT`, joins `ff02::2` and registers with tokio. `recv` returns the source, the hop limit from the cmsg and the message.

## Timers

`schedule::Schedule` (pure): `deadline()` is the earlier of the unsolicited timer and a pending RS reply, never before the last RA plus 3 s. `on_sent` picks the next interval at random, capped at 16 s for the first three RAs. `reconfigure` (a profile edit) and `restart` (a reopened socket) make the next RA due now.

## Link task and reconcile

- `reconcile::desired_links` turns the config into one `LinkConfig { interface, profile }` per device. `Links::reconcile` compares with the running tasks: an unchanged config does nothing, a changed one goes through a `watch` channel into the task, a missing one stops the task (final RAs, up to 5 s grace, concurrently for all links).
- `link::run` selects over stop, config change, link-table change, the schedule deadline and the socket. The first RA after a start or a change is logged at `info` whatever the log bucket says.

## `nos-e2e radv`

Both routers get an `ra-profile lan` (one /64, one RDNSS) attached to `eth1` with `--ra-interface eth1`, over the direct veth made by `World::link_veths`.

- Each router logs `router advertisement sent interface=eth1` (built and sent on a real veth) and `foreign router advertisement interface=eth1` for the peer's RA (hop limit 255 and source validation passed).
- `--ra-managed` on router-a: a new `sent ... managed=true` on a, a new `foreign ... managed=true` on b, and no `final` line (an edit is not a stop).
- `--clear-ra-profile --ra-interface eth1` on router-a: three `router advertisement final` lines on a, `foreign ... lifetime=0` on b, then no further `sent` for 8 seconds.
