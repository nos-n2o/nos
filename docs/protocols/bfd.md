# BFD profiles

A BFD profile (RFC 5880) is a named set of session parameters that BGP, OSPF, OSPFv3 and static routes can reference by name.

- `nos-bfdd` runs the sessions (RFC 5880, single-hop RFC 5881 over UDP 3784, multihop RFC 5883 over UDP 4784, both inside the routing table's VRF).
- **Static routes, BGP peer-groups, OSPF and OSPFv3 profiles use it** (see [BGP](bgp.md#bfd-rfc-5882-rfc-9384) and [OSPF and OSPFv3](#ospf-and-ospfv3)).
- Profiles are checked at commit time; the shell and REST accept any edit in a transaction.

## Define a profile

```
edit bfd-profile fast
set min-tx-interval 100
set min-rx-interval 100
set detect-multiplier 3
```

- `edit bfd-profile <name>` creates the profile with its defaults if it does not exist, then moves into it.
- The REST equivalent is `PUT /v1/transactions/<tx>/bfd-profile/<name>` (see [CLI ↔ API mapping](../cli-api-mapping.md)).

## Reference it

Set `bfd <profile>` on the object that should run BFD:

| Object | Command |
|--------|---------|
| BGP peer-group | `set bgp instance <i> peer-group <g> bfd <profile>` |
| OSPF profile | `set ospf instance <i> area <a> profile <p> bfd <profile>` |
| OSPFv3 profile | `set ospfv3 instance <i> area <a> profile <p> bfd <profile>` |
| Static route | `set static-routing-instance <i> route <cidr> bfd <profile>` |

`delete bfd` (relative) removes the reference.

## Protect a static route

```
edit bfd-profile fast
set min-tx-interval 100
set min-rx-interval 100
edit static-routing-instance s1
set route 198.51.100.0/24 gateway 192.0.2.1
set route 198.51.100.0/24 bfd fast
```

- `nos-ribd` registers one session per route gateway, in the route's routing table; the peer must also run BFD (or be a BFD-capable system such as FRR `bfdd`).
- The route stays out of the RIB until the session is `up`. It fails closed: while `nos-bfdd` is unreachable nothing is up.
- The route is removed when the session goes `down` or `init`, and when the peer signals `admin-down` (a peer that is administratively down gives no data-plane assurance).
- Editing the profile applies through Poll/Final without a flap; `shutdown enable` puts the session in `admin-down`.
- One session is shared by every route with the same gateway in the same table; it is identified by (table, peer address), not by interface.

## OSPF and OSPFv3

RFC 5882 §4.1: OSPF is a BFD client; BFD only ever kills a neighbor, it never gates one coming up.

```
set ospf instance o1 area 0.0.0.0 profile p1 bfd fast
set ospfv3 instance o1 area 0.0.0.0 profile p1 bfd fast
```

- `nos-ospfd` and `nos-ospfv3d` register one single-hop session per neighbor, in the instance's routing table, once the neighbor is at 2-Way or later; on a broadcast link that is one per neighbor, not per link. Below 2-Way, or when the link or the `bfd` reference goes, the session is deregistered.
- OSPFv2 sessions run between the interface addresses; OSPFv3 sessions between link-local addresses, scoped by the link's interface (the peer must run BFD too, or be a BFD-capable system such as FRR `bfdd`).
- A session going `up` then `down` kills the neighbor like an expired dead interval (RFC 2328 §10.2 `KillNbr`): it goes `Down`, the adjacency is cleared and the Router-LSA is re-originated within the 2 s origination tick, so the SPF route is withdrawn at once instead of after the dead interval (40 s by default). The next Hello brings it back through Init.
- A point-to-point link is advertised in the Router-LSA only while its neighbor is `Full` (RFC 2328 §12.4.1.1, RFC 5340 §4.4.3.2), so a neighbor already back in Init when the tick runs still drops out of the LSA (#463).
- `admin-down` (a local `shutdown enable`), `init`, a session that was never `up` and a lost connection to `nos-bfdd` kill nothing (RFC 5882 §3.2): OSPF behaves as without BFD.
- Adding, changing or removing the `bfd` reference never resets an adjacency; only registrations change.
- Log anchors: `bfd session down, killing ospf neighbor link=... neighbor=...` (`ospfv3` for OSPFv3), preceded by `ospf: bfd session down peer=... diag=...`.
- `show bfd sessions` lists the sessions; they are keyed by (table, peer), so two links to one peer address in one table share a session.

## Authenticate sessions

RFC 5880 section 6.7: every packet of a session carries a password or a digest, and packets that fail are dropped.

```
set admin key bfd-fast secret s3cret
edit bfd-profile fast
set auth key-id 1 method meticulous-sha1 key bfd-fast
```

- The `key` is the label of an admin key, never the secret: the secret is stored once under `admin key` and never shown, logged or returned by REST. Commit fails if the label does not exist, if the secret length does not fit the method, or if you delete an admin key a profile still uses.
- Set the same `auth` (same secret) on both ends. `delete auth` turns it off.
- Rotate a secret by setting the admin key again under the same label (`set admin key bfd-fast secret <new>`) on both ends: the session keeps running, the old secret stays accepted for 4 detection times.
- Methods: `simple-password` (clear text on the wire), `keyed-md5`, `keyed-sha1`, and the `meticulous-` variants, which sign every packet with a fresh sequence number (strongest replay protection, a little more work per packet). Prefer `meticulous-sha1`.
- Key length: 1 to 16 bytes (`simple-password`, MD5), 1 to 20 bytes (SHA1); `key-id` is 0 to 255 and must match on both ends.
- A packet is dropped, and does not refresh the detection timer, when:
  - the A bit is set but no auth is configured, or the reverse;
  - the method or key id differs;
  - the password or digest is wrong;
  - the sequence number is outside the window (3 x the packet's detect multiplier ahead; for `meticulous-` it must also be new).
- A wrong key therefore leaves the session `down`. The drop is logged as `bfd auth failed peer=... reason=...`, at most once per 10 s per session, and counted in `auth_failures`.
- Enabling or disabling auth on one side only drops the session after the detection time, as the RFC allows.

### Change the key without a flap

- Edit the profile on both routers. The new key signs from that moment, and the previous key is still accepted for 4 detection times.
- Apply the change on the second router within that time. A change of key id, secret or method keeps the session `up` (a method change resets the sequence tracking, as the spaces differ).
- The router that changes second is the one at risk: until it applies the change it rejects the first router's packets, so keep the gap below the detection time (use longer intervals for a planned rollover).
- Multiple concurrent keys and key lifetimes are not supported.

## Use the Echo function

RFC 5880 section 6.4 and RFC 5881 section 4: each end sends packets addressed to itself through the neighbour, which only forwards them back. A broken forwarding path is found in `echo-interval x detect-multiplier` instead of the control detection time.

```
edit bfd-profile fast
set echo-mode affiliated
set echo-interval 50
```

- `echo-mode` is `disabled` (default), `affiliated` (Echo runs next to the Control session) or `unaffiliated` (next section). `echo-interval` is in milliseconds (10 to 4294967, default 50).
- Every Control packet advertises `echo-interval` as Required Min Echo RX; `disabled` advertises 0, so the peer never loops echoes through you.
- Echo starts when the session is `up`, the profile asks for it and the peer advertises a nonzero Required Min Echo RX. The interval used is the larger of the two. `nos-bfdd` logs `bfd echo active peer=... interval_us=...`, and `bfd echo inactive` when it stops (session not `up`, `echo-mode` removed, peer advertises 0).
- While Echo runs, Control packets slow to one per second or less (a Poll sequence raises Desired Min TX to 1 s, and restores it when Echo stops).
- No echo returning for `echo-interval x detect-multiplier` takes the session `down` with `diag echo-function-failed` (diagnostic 2). Control keeps flowing, so the session comes back `up` and Echo restarts; a persistent fault shows as a flapping session.
- Single-hop sessions only. A session that cannot open its Echo transport (no interface or address towards the peer) logs `bfd echo unavailable` once and stays Control-only.
- The neighbour must forward IP between the two addresses of the link (`net.ipv4.ip_forward=1` / `net.ipv6.conf.all.forwarding=1`). It may send ICMP redirects for the looped packet; it still forwards, but set `send_redirects=0` on that interface to avoid the noise.
- The neighbour's MAC comes from the kernel neighbour table, read only: the Control session's ARP/ND creates the entry. Without one, echoes are not sent and the session goes `down` after the echo detection time.
- Echo packets carry no authentication (RFC 5880 has none for Echo); `auth` covers Control only.

## Monitor a gateway that runs no BFD

RFC 9747 unaffiliated Echo: the session is made only of your own Control packets, looped back through the neighbour's forwarding. Use it to guard a static route whose gateway has no BFD.

```
edit bfd-profile gw
set echo-mode unaffiliated
set echo-interval 50
```

- Reference the profile from the route as usual (`bfd gw` on the static route). The route is installed once the session is `up` and withdrawn when it goes `down`.
- The packet is a BFD Control packet to UDP 3785, addressed from and to one of your own addresses, sent with TTL 255 to the gateway's MAC. It is accepted only when it returns with TTL exactly 254, so the loop must cross exactly one routed hop; a pure L2 reflector is rejected.
- The state machine of RFC 5880 section 6.2 runs on your own looped state: `down` to `init` to `up`. Until `up` at most one packet a second goes out; once `up`, one per `echo-interval`.
- No packet back for `echo-interval x detect-multiplier` while `up` takes the session `down` with `diag echo-function-failed`. It stays `down` and retries at one packet a second until packets return.
- Desired Min TX, Required Min RX (both 1 s) and Required Min Echo RX (0) are populated but never used. `min-rx-interval`, `min-tx-interval`, `passive` and `auth` are ignored (no authentication on unaffiliated sessions yet).
- The gateway must forward IP back out of the same interface (`ip_forward=1`, no strict uRPF `rp_filter=1` on it) and the loop must not be dropped by a firewall. It does not need to run BFD.
- Nothing is sent on UDP 3784. Because no Control exchange resolves the neighbour, `nos-bfdd` sends an empty datagram to the gateway's UDP 3785 until the kernel has an ARP/ND entry, and then reads the MAC from it.
- Single-hop only: a multihop key logs `bfd unaffiliated echo needs a single-hop session` and stays `down`.
- Changing `echo-mode` between `unaffiliated` and another value restarts the session.

## Test the path with padded packets (RFC 9764)

- Set `padded-pdu-size <bytes>` (24 to 9000) on the `bfd-profile`: every Control packet's UDP payload is zero-padded to that size.
  - `edit bfd-profile fast`, then `set padded-pdu-size 1500`.
  - The size is a path MTU you want proven, not the link MTU: an IP packet of `size + 28` bytes (IPv6: `size + 48`) must cross every hop.
  - A size below the bare packet (24 bytes, more with `auth`) sends the bare packet. The padding follows the authenticated part, so `auth` is unaffected.
- Set it on both ends to test both directions. One padded end and one bare end is valid: padding is a local transmit property, never negotiated, and an edit applies from the next packet with no Poll.
- Every BFD transmit socket sets don't-fragment (`IP_PMTUDISC_DO`, `IPV6_DONTFRAG`), so a packet that does not fit fails instead of fragmenting. `nos-bfdd` logs `bfd padded packet exceeds the path mtu peer=<ip> size=<n>` once and the peer goes `down` by detection time. Restoring the MTU brings the session back by itself.
- A peer that drops large packets also takes the session `down` by detection time. The receiver never checks the padding.
- When several clients share one session, the profile of the last `Register` wins (as for every other setting).
- `show bfd sessions` shows the size in `Pdu` while padding is set; REST has `tx_pdu_bytes` (0 when not padded).

## Seamless BFD (RFC 7880, RFC 7881)

S-BFD probes a target that keeps no per-session state: the far end only has to answer for a discriminator. Two parts: a reflector and an initiator profile.

- Reflector, on the system being probed:
  - `set sbfd reflector discriminator 10.0.0.2` (repeat for more). A discriminator is a 32-bit value, written as an IPv4 address (`10.0.0.2` is 167772162); 0.0.0.0 is refused.
  - `nos-bfdd` then listens on UDP 7784 in the VRF of every routing table and answers a probe whose Your Discriminator is one of them. With none configured it listens on nothing.
  - It sends nothing on a timer and remembers nothing per initiator: one probe in, at most one reply out (State Up, D bit 0, Required Min RX 10 ms, replied from the address that was probed, TTL 255).
  - `set sbfd reflector allow-from 10.0.0.0/24` (repeatable) answers only those sources (RFC 7881 section 7). Martian sources (unspecified, multicast, loopback, broadcast, reserved, link-local towards a global address) are never answered; reverse-path validation is the kernel's `rp_filter`.
  - A global limit of 10 000 packets a second (burst 2 000) bounds the work a flood can cause.
- Initiator, on the system that wants to know the target is reachable:
  - `edit bfd-profile sb`, `set mode sbfd`, optionally `set sbfd-remote-discriminator 10.0.0.2`, then reference the profile as for any other: `set static-routing-instance <i> route <cidr> bfd sb`.
  - Without `sbfd-remote-discriminator` the discriminator is the session peer's own IPv4 address, which suits a reflector configured with its own address. An IPv6 peer needs it; a static route to an IPv6 gateway without one is refused at commit.
  - The probe goes to UDP 7784 from a source port of its own (never 7784), so the reflection finds its way back to that session's socket.
  - There is no Init state: the session is `up` on a reflected Up and `down` when `detect-multiplier` x the transmit interval pass without a reflection (`diag control-detection-time-expired`).
  - The transmit interval is `min-tx-interval`, raised to the Required Min RX the reflector answers with. Probing starts at that rate at once; the one-second wait of classical BFD while not Up does not apply.
  - A reflector that answers AdminDown (out of service) takes the session `down` without a failure diagnostic and slows probing to one packet a second until it answers Up again.
  - Single-hop sessions require TTL 255 on the reflection.
- Not available yet: `mode sbfd` is refused together with `echo-mode`, `padded-pdu-size` and `auth` (a follow-up adds S-BFD authentication after RFC 5880 authentication, #289; until then the reflector drops any packet with the A bit set and counts it).
- Interoperability: FRR's `bfdd` implements RFC 5880, 5881, 5882 and 5883 only (its documentation lists no S-BFD, checked against FRR 10.4), so it can be neither initiator nor reflector. The e2e phase `bfd-sbfd` therefore runs `nos` against `nos`, with an FRR classical session alongside to prove the two kinds do not disturb each other.
- Check the reflector with `show bfd reflector` (`GET /v1/bfd/reflector`): the discriminators and counters of packets received, replied and dropped per reason (`malformed`, `source_port`, `martian`, `filtered`, `rate_limited`, `authenticated`, `demand_clear`, `unknown_discriminator`).
- An initiator is listed by `show bfd sessions` with `Kind` `SbfdInitiator`; REST has `kind` (`Classical`, `SbfdInitiator` or `Unsolicited`), and `remote_discriminator` is the S-BFD discriminator probed.
- To take an initiator down on purpose, remove the discriminator from the reflector: the initiator logs `bfd session down … diag=control-detection-time-expired` and the guarded route is withdrawn. Re-adding it brings both back.

## Micro-BFD on a port aggregate (RFC 7130)

- Set `bfd <profile>` and `bfd-peer <ip>` on a `port-aggregate` (xor or lacp), and put an address of the peer's family on its untagged subinterface: `nos-bfdd` runs one session per member link, each over that member only.
  - `set port-aggregate bond0 bfd fast`, `set port-aggregate bond0 bfd-peer 10.0.0.2`, `set port-aggregate bond0 address 10.0.0.1/30`.
  - The profile's timers and `detect-multiplier` apply per member; an edit runs Poll/Final and flaps nothing. `echo-mode` is ignored (Echo is out of scope in RFC 7130 section 2.2); `auth` applies as for any session.
  - The commit rules are those of the aggregate: a missing profile, a missing `bfd-peer` or no source address of the peer's family is refused.
- What goes on the wire: control packets in IP/UDP to the peer's address, UDP destination port 6784, TTL 255, source address the bond's, source MAC the member's own, destination MAC `01-00-5E-90-00-01` (the dedicated multicast MAC; unicast to our own MAC is accepted too). Untagged and 802.1p tag-0 frames are received.
- What Up and Down do: a member is enslaved into the bond only while its session is Up, and released when it goes Down. `nos-bfdd` sends `nos-interfaced` the whole Up set of the aggregate on every change (`PushBfdMembers`); no push means no member is enslaved.
- The sessions run on the member itself, whether or not it is enslaved, so a released member keeps probing and rejoins by itself once its session is Up again.
- Deviation from RFC 7130 section 3: sessions exist for every configured member, not only those LACP has in Distributing or Standby. Cost: an extra probe on a link LACP has not selected yet.
- Check with `show bfd sessions`: a micro session has the aggregate's name in `Aggregate` and the member in `Interface`, for example `10.0.0.2  10.0.0.1  eth1  bond0`. In REST the session `key` has `aggregate` and `interface` (the member).
- Log lines: `bfd session up aggregate=<a> member=<if> peer=<ip>` and `bfd session down aggregate=<a> member=<if> peer=<ip> diag=<...>`.
- Kernel noise: the frames carry the peer's unicast IP in a multicast MAC; the kernel finds no socket on UDP port 6784 and drops them; it does not send ICMP port unreachable for a frame received as link-layer multicast.

## Unsolicited BFD (RFC 9468)

- Use it where the peers start the sessions and you do not want to configure each one: a peer sends BFD Control with Your Discriminator 0 and `nos-bfdd` answers with a passive session.
  - `set interface eth0 subinterface 0 bfd-unsolicited fast` names the `bfd-profile` (`fast`) for those sessions. The subinterface needs a `routing-table` and an address: the VRF picks the socket, and a source must be inside one of the subinterface's subnets.
  - Single-hop only (UDP 3784, TTL exactly 255). A packet on a subinterface without `bfd-unsolicited` is dropped silently, as before.
- What the profile does here: intervals, `detect-multiplier`, `auth` and `minimum-ttl` apply (`echo-mode` is not tested here); `passive` is ignored, the session is always passive. It never sends before the peer's first packet, and stops sending when the peer goes away.
- A session is created only for a packet from state `Down`; one in any other state, with a nonzero discriminator or from `AdminDown` creates nothing.
- Limits, fixed in the code:
  - 256 unsolicited sessions per subinterface; the next packets are dropped with a warning (`bfd unsolicited session limit reached`, at most one per 10 s).
  - A session that has not been Up for 60 s is deleted (`bfd unsolicited session aged out`). Down or never-Up counts; coming back Up resets the clock. The peer's next packet creates a new one.
- Editing the profile applies by Poll/Final. Removing `bfd-unsolicited` (or the profile's subinterface) deletes its sessions (`bfd unsolicited session removed: no longer configured`).
- Registering the same peer from a client (a static route, BGP) adopts the session; the client then owns it and nothing ages it out.
- `show bfd sessions` shows `Kind` `Unsolicited`; REST has `kind` `Unsolicited`.
- Security: the TTL check and the cap are the only defences against a spoofed source filling the table. Use it only on links where every neighbour is trusted, and set `auth` on the profile when the peers support it. IPv6 sources must be inside a configured prefix (a link-local source is not accepted).
- Not built: unsolicited sessions on port-aggregate subinterfaces, a configurable age or cap.

## Check sessions

- `show bfd sessions` lists every session, `show bfd sessions <peer>` those to one address. Sample:

```
Table  Peer       Local  Interface  Aggregate  Multihop  State  Diag          Local-Disc  Remote-Disc  Tx-Interval  Detection  Kind       Auth  Auth-Key  Auth-Failures  Echo  Echo-Interval  Echo-Only  Pdu
-----  ---------  -----  ---------  ---------  --------  -----  ------------  ----------  -----------  -----------  ---------  ---------  ----  --------  -------------  ----  -------------  ---------  ---
rt1    192.0.2.1  -      -          -          no        Up     NoDiagnostic           1            7        100ms      300ms  Classical  -            -              0  no              0us  no         0 B
```

- `Tx-Interval` is the negotiated transmit interval, `Detection` the detection time, `Local-Disc`/`Remote-Disc` the discriminators.
- With `auth` set, `Auth`, `Auth-Key` and `Auth-Failures` show the method, key id and failure count; the key is never shown.
- While Echo runs `Echo` is `yes` and `Echo-Interval` is set; `Echo-Only` is `yes` for an unaffiliated session, where `Tx-Interval` is the echo interval and `Detection` is `echo-interval x detect-multiplier`.
- With `padded-pdu-size` set `Pdu` shows the size.
- An S-BFD initiator has `Kind` `SbfdInitiator`, and its `Remote-Disc` is the one probed.
- A `Down` session shows why in `Diag`: `ControlDetectionTimeExpired`, `NeighborSignaledSessionDown`, and so on (RFC 5880 section 4.1 names).
- The REST equivalent is `GET /v1/bfd/sessions` (optionally `?peer=192.0.2.1`); it returns the same fields as JSON (`state` is `Up`, `Down`, `Init` or `AdminDown`), plus `auth_method`, `auth_key_id`, `auth_failures`, `echo_active`, `echo_interval_us` (0 while Echo is off), `echo_only` (unaffiliated) and `tx_pdu_bytes` (0 when not padded).
- "nos-bfdd is not running" (CLI) or `503` (REST) means the daemon is not up.

## Multi-hop sessions

- A client picks multi-hop for a peer that is not directly connected; you configure nothing extra beyond the profile.
  - BGP: the peer-group has `max-hops` above 1, or the peer address is on no subnet configured on an interface (or subinterface) of the instance's routing table. An iBGP session between loopbacks reached over OSPF is the typical case.
  - Static routes: the gateway is on no such subnet.
- A subnet that is not in the configuration (learned over DHCP) is not seen: the peer is then registered multi-hop, which still works.
- Multi-hop sessions use UDP 4784 and are not tied to an interface; `show bfd sessions` shows `Multihop` `yes` and no `Interface`.
- TX TTL is 255. A received packet is dropped when its TTL is below the profile's `minimum-ttl` (default 254). Single-hop sessions still require exactly 255.
- The local address is the peer-group's `source-address` for BGP; otherwise `nos-bfdd` uses the address the kernel would use towards the peer, fixed when the session opens.
- Changing a peer between single-hop and multi-hop (an address added or `max-hops` edited) replaces the session: the old one is deregistered and a new one starts `down`.

## Commit-time errors

- A `bfd` reference to a profile that does not exist is refused: `bfd profile '<name>' does not exist`.
- Deleting a profile that is still referenced is refused the same way, once per referencing object, each under its own path (for example `bgp_instances[0].peer_groups[0].bfd`). Remove the references first, or delete them in the same transaction.
- Duplicate profile names are refused.

## Configuration reference

| Field | CLI | Type | Default | Validation |
|-------|-----|------|---------|------------|
| `name` | `edit bfd-profile <name>` | string | | 1 to 64 characters, unique |
| `min_tx_interval` | `set min-tx-interval <ms>` | integer, ms | 300 | 10 to 4294967 |
| `min_rx_interval` | `set min-rx-interval <ms>` | integer, ms | 300 | 10 to 4294967 |
| `detect_multiplier` | `set detect-multiplier <n>` | integer | 3 | at least 1 |
| `passive` | `set passive enable` | bool | off | |
| `minimum_ttl` | `set minimum-ttl <n>` | integer | 254 | |
| `shutdown` | `set shutdown enable` | bool | off | |
| `auth` | `set auth key-id <n> method <m> key <label>` | key id, method, admin key label | none | the label must exist; secret length per method, below |
| `mode` | `set mode async\|sbfd` | enum | `async` | `sbfd` excludes `echo-mode`, `padded-pdu-size` and `auth` |
| `sbfd_remote_discriminator` | `set sbfd-remote-discriminator <ipv4>` | IPv4 address | the peer's IPv4 address | not 0.0.0.0 |

- Methods: `simple-password`, `keyed-md5`, `meticulous-md5`, `keyed-sha1`, `meticulous-sha1`.
- Secret length (RFC 5880 sections 4.2 and 4.3): 1 to 16 bytes for `simple-password` and the MD5 methods, 1 to 20 bytes for the SHA1 methods.
- Keys are stored in clear text, like BGP and OSPF keys.
- The interval ceiling keeps the later millisecond-to-microsecond conversion inside the RFC's 32-bit field.
