# nos-radv — IPv6 Router Advertisement Daemon

`nos-radvd` (one fixed process, like `nos-lldpd`; see `docs/architecture/supervision.md`) sends RFC 4861 Router Advertisements on every link that attaches an `ra-profile` (`Interface.ra_profile`, `Subinterface.ra_profile`, schema in `nos_proto::schema::ra_profile`, #1583) and answers Router Solicitations. Operator guide: [RA guide](../docs/protocols/radv.md); internals and the `nos-e2e radv` narrative: [internals](../docs/internals/radv.md).

## Scope

- One raw `AF_INET6/SOCK_RAW/IPPROTO_ICMPV6` socket per advertising device (`nos-radv-socket`, the only `unsafe`, excluded from coverage like the other FFI). `CAP_NET_RAW` only; no rtnetlink, no kernel state, no sysctls. It parses untrusted bytes, so it is its own process.
- A subinterface attach point advertises on its kernel device (`eth1` for tag 0, `eth1.<tag>` otherwise, the name `nos-interfaced` gives it). A device attached twice keeps its first attachment.
- Prefixes come only from the profile's explicit list. Deferred and listed as such: RFC 4191 Route Information option, RFC 6275 options, DHCPv6, `prefix auto` (derive from the interface's addresses), RFC 7084, unicast RS replies (replies go to `ff02::1`, `ponytail:`).
- `--listen-socket` is accepted (the watchdog always passes it) and unused until the show/REST surface (#1585); `ServiceRef::Radv` already resolves it.

## Decode robustness

`packet::decode_rs`/`decode_ra` are the only places untrusted bytes are parsed; they never panic (fuzz target `radv_packet`). Validation per RFC 4861 s6.1.1/s6.1.2: hop limit 255 (from the cmsg, `IPV6_RECVHOPLIMIT`), code 0, length, source link-local (RS may be `::` but then carries no source link-layer option), every option length non-zero and inside the message. At most 64 options are looked at.

## Behaviour that bites

- RFC 4191 Prf: high `01`, medium `00`, low `11`; `10` is reserved and never sent (`packet::prf_bits`).
- The builder refuses an RA over `MAX_RA_LEN` (1240 bytes, the IPv6 minimum MTU less the header) and a bad DNSSL label; the link logs and retries at `max-interval`. The kernel fills the ICMPv6 checksum.
- `schedule::Schedule` is pure (`now` and the seed are passed in): the first RA is immediate, the first three follow within 16 s, then random in [min, max]; an RS reply waits 0..0.5 s and a pending reply absorbs further RSs; two RAs are never closer than `MIN_DELAY_BETWEEN_RAS` (3 s). Never leave an elapsed deadline armed: every wake sends (`on_sent`) or moves it (`retry`).
- A send that finds the link down or the link-local address tentative retries after 1 s, never fatal.
- A profile edit reaches the running task through a `watch` channel (`reconcile::Links::reconcile`): it re-advertises at once, no final RAs, no restart. Only a removed attach point (or shutdown) stops a link, which sends 3 RAs with router lifetime 0 one second apart (`FINAL_SPACING`, `ponytail:` the RFC's 3 s would outlast `STOP_GRACE`).
- Foreign RAs are validated, logged (`foreign router advertisement`) and compared with our own (s6.2.7, `packet::inconsistencies`, `inconsistent router advertisement` at `warn`); never acted on. `info` logs go through a `LogBucket` (burst 5, +1 per 10 s) except the first RA after a (re)start or a settings change and the final ones; multicast loop is off, so own RAs are never received.
- Sockets follow `nos-interfaced`'s `SubscribeLinks` (`link_client`, copy of `nos-lldpd`'s): `absent` closes the socket, a new epoch reopens it with a fresh initial burst.

## Modules

| Module | Role |
|---|---|
| `main.rs` | Args (`--watchdog-socket`, `--listen-socket`, `--log-socket`); links send final RAs on exit |
| `packet.rs` | RA builder, RS/RA decoders, s6.2.7 comparison, pure |
| `schedule.rs` | Timers of s6.2.4/s6.2.6, pure |
| `link.rs` | Per-device `run()`, `LinkConfig`, `LogBucket` |
| `link_client.rs` | `SubscribeLinks` table + per-name epochs |
| `reconcile.rs` | Diff-triggered resync (`desired_links`), 10 s tick |

`nos-e2e radv` is the real test of `radv-socket` and `link.rs`.
