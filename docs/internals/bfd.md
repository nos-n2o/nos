# BFD internals

How `nos-bfd` is built. The library (#296) plus the daemon `nos-bfdd` (#297). Rules to respect when editing: [`bfd/CLAUDE.md`](../../bfd/CLAUDE.md). The profile that feeds it: [protocols/bfd.md](../protocols/bfd.md).

## Modules

- `packet`: RFC 5880 §4.1 control packet codec.
    - `decode` applies the stateless §6.8.6 checks; with the A bit it also parses the authentication section into `Packet.auth` (`DecodeError::BadAuthSection` when malformed). `encode` writes the mandatory section only.
- `auth`: RFC 5880 §4.2-4.4/§6.7. `sign` appends the section, `AuthState` holds a session's key, old key, `RcvAuthSeq`/`AuthSeqKnown` and `XmitAuthSeq`.
- `fsm`: `step(state, event) -> (state, Option<diag>)`, the §6.8.6 table; `may_transmit` covers `passive` (§6.1) and Remote Min RX 0.
- `timers`: `Timers`, `now` and the jitter draw passed in.
- `authz`: `allowed(role, &BfdRequest)`, no wildcard arm.
- `echo`: the Echo packet, pure. `payload` (our discriminator and a sequence), `build` (IPv4/IPv6 + UDP 3785 from a port in 49152-65535, TTL 255, source = destination = our address, checksums), `parse` (accepts TTL 254..=255, checks both addresses, checksums, payload length).
- `micro`: RFC 7130 frames, pure: `build_frame`/`parse_frame` (IPv4 and IPv6 + UDP 6784, TTL 255, hand-built checksums), `untag_priority` (802.1p tag 0), `GROUP` (`01-00-5E-90-00-01`).
- `micro_sessions`: `wanted(&Config)` derives one `SessionKey` (with `aggregate` set, `interface` = the member, `local` = the bond's address) per member of every aggregate with `bfd`; `Micro::apply` registers them with the `Manager` as an internal client; `UpSets` computes the aggregate's Up set and returns a `PushBfdMembers` payload only when it changed; `run` follows `Interfaces`/`PortAggregates`/`BfdProfiles` diffs. `interface_client` resends the cached sets to `nos-interfaced` on every reconnect.
- `neigh`: the neighbour's MAC from an `rtnetlink` neighbour dump (usable states only), never written.
- Wire types live in `nos_proto::bfd`.

## UDP FFI

- The `unsafe` libc calls of `socket.rs` live in `bfd-socket/` (`nos-bfd-socket`, a leaf crate like `nos-l2-socket`): `ifindex`, `set_int`, `recv_one` (source + TTL/hop limit cmsg), `recv_probe` (source + `IP_PKTINFO` destination), `send_from` (`IP_PKTINFO` source).
- `nos-bfd` itself has no `unsafe`. New raw-libc code goes in `bfd-socket/`, which `.semgrepignore` exempts from the unsafe-usage rule.
- Its tests run unprivileged on loopback and count towards coverage.

## Micro-BFD (RFC 7130)

- `socket::MicroTx` is the session's `Tx`: an `nos_l2_socket::L2Socket` per member (ethertype by the peer's family, kernel-filtered to UDP 6784, own-unicast accepted) plus one on 0x8100 for tag-0 frames; two rx tasks feed `Demux::route_micro`, which takes the arrival member as part of the key (RFC 7130 section 2.2: Your Discriminator nonzero must also match the interface).
- The socket is bound to the member's ifindex, so it keeps receiving once the member is enslaved: the packet tap sees the skb with `orig_dev` = the member after the bond's `rx_handler`. `nos-e2e`'s `micro-bfd` proves it.
- A `tc` ingress drop on UDP 6784 starves the IP packet socket the same way it does Echo.
- No Echo for a session with `aggregate` set (`Manager::register`).

## Authentication

- `Core::authenticate(now, &Packet)` runs before `on_packet` and `Core::sign` wraps every outgoing packet; a failed packet never reaches the FSM or the timers.
- The digest is MD5/SHA1 over the packet with the digest field replaced by the key zero-padded to 16/20 bytes; digests and passwords compare in constant time.
- Replay window: keyed accepts `[RcvAuthSeq, RcvAuthSeq + 3 x DetectMult]`, meticulous `(RcvAuthSeq, ...]`, wrap-aware; unknown (`AuthSeqKnown` false) accepts any, and silence of 2 detection times forgets it.
- `XmitAuthSeq` starts random; meticulous bumps it per packet, keyed once per detection time.
- A profile edit goes through `AuthState::set`: the new key signs at once, the previous one stays acceptable for 4 detection times; a method change resets `AuthSeqKnown`.
- Keys (#510): `BfdAuth.key` is an admin-keystore label. `nos-bfdd` is the only resolver (clients send the profile with the label; no secret on the BFD IPC): `Manager.keys` is filled by `micro_sessions::resync` from `Config.admin` (subscribed to `DiffScope::Admin`), `Manager::resolve` turns a profile into an `AuthKey` (runtime type, `Debug` hides the secret) that `Core::new`/`update_profile` take next to the profile.
- `Manager::set_keys` re-sends the stored profile with its new key to every authenticating session, so a rotation under the same label goes through `AuthState::set` (old key accepted for 4 detection times, no flap).
- A label that does not resolve (config race) fails closed: `bfd auth key not found label=...` is logged, `Core::unkeyed` makes every received packet fail (`AuthError::NoKey`) and nothing is sent until the key arrives; it never falls back to no authentication.
- `session::run` logs `bfd auth failed` (rate limited to one per 10 s per session); `Status` and `BfdSessionView` carry `auth_method`, `auth_key_id`, `auth_failures`.
- Unit tests check digests against an independent re-implementation of the RFC recipe in `auth.rs` tests. `ponytail:` no FRR positive proof: FRR `bfdd` has no §6.7 support, so `nos-e2e`'s `bfd-auth` only proves the negative case against it.
- #294 (S-BFD) will add reflector authentication on top of this module.

## FSM

| State | Rx Down | Rx Init | Rx Up | Rx AdminDown | Detect timeout |
|-------|---------|---------|-------|--------------|----------------|
| AdminDown | stay | stay | stay | stay | stay |
| Down | Init | Up | stay | stay | stay |
| Init | stay | Up | Up | Down (diag 3) | Down (diag 1) |
| Up | Down (diag 3) | stay | stay | Down (diag 3) | Down (diag 1) |

- An echo timeout only moves an Up session: it goes Down with diag 2.

- Local `AdminDown` event: any state goes to AdminDown (diag 7); `AdminUp` brings AdminDown back to Down (diag 0).
- Demand mode is not implemented: D is sent 0 and a received D is ignored.

## Echo

- `Core` owns the sub-state: `sync_echo` starts Echo when `echo_wanted` (transport present, profile `Affiliated`, state Up, remote Required Min Echo RX > 0) and stops it otherwise. Both directions go through `Timers::change`, so Desired Min TX is raised to 1 s (and restored) by an ordinary Poll sequence.
- `echo_due(now)` hands out the next sequence number, `on_echo(now, seq)` records a returned one (`seq` must be new and sent); `echo_expired` after `echo interval x detect multiplier` without one applies `Event::EchoTimeout`, which takes an Up session to Down with diag 2.
- `session::run` sends with `EchoTx` and receives sequences on the `EchoPath` channel; `Core::set_echo_path` tells the core whether a transport exists.
- Transport (`socket.rs`, `nos-l2-socket`'s `L2Unicast`): an `AF_PACKET` socket on the session's interface, a kernel BPF filter for UDP port 3785, frames sent to the neighbour's MAC. The returned packet carries our own address as source, which the IP stack drops as a martian, so receiving at the packet layer is the only way. The socket is bound to the interface, so it works for a VRF-enslaved one.
- Unaffiliated (#291, RFC 9747): `Core::unaffiliated()` replaces the Control machinery. `on_packet` ignores everything, `on_timer` only runs the echo clock (no Control packet is ever returned), `deadline` is the echo deadline. `echo_due` returns the encoded Control packet (state, `my_discriminator`, 1 s Desired Min TX/Required Min RX, echo RX 0) as the payload; `on_echo(Looped::Control(state))` feeds the §6.8.6 table with our own looped state and sets `remote_disc` to our discriminator. The Echo interval is 1 s until Up (`watching()` is false, silence is not counted), then `echo-interval`; entering Up and timing out both re-arm `next_tx`.
- Unaffiliated transport: `Manager::register` starts no Control socket and adds no `Demux` slot (`NoTx`), retries `Net::open_echo(.., unaffiliated = true)` every second, and `echo_rx_loop` accepts only TTL 254 and our own discriminator (`echo::parse_udp`). `neigh_loop` also sends an empty UDP datagram to peer:3785 while the neighbour is unresolved, because no Control traffic makes the kernel ARP. A switch of echo-mode drops and recreates the session.
- Tapping a packet socket sits after the `tc` ingress hook, so a `tc` drop on UDP 3785 starves Echo (this is how `bfd-echo` injects the failure).
- `ponytail:` the echo transport is opened once at session start; a later-appearing address needs a re-`Register` of a new session. Echo timing has no jitter.

## Timer rules

- TX interval: `max(local desired min TX, remote required min RX)`; at least 1 s while not Up (also advertised as Desired Min TX).
- Detection time: `remote detect mult x max(local required min RX, remote desired min TX)`.
- Jitter: the caller draws 75..=100 (clamped; 75..=90 when the local detect mult is 1).
- Changing an interval opens a Poll sequence (P=1 on every packet); the new value takes effect locally on Final. An incoming P is answered with F.
- When a session reaches Up the 1 s floor lifts, which is a Desired Min TX change: `Core::apply` calls `Timers::on_state`, which opens a Poll sequence (P=1 carrying the configured value; transmission uses it at once, Final only closes the sequence). Leaving Up restores the floor and drops the moot sequence. No sequence when the configured value is already >= 1 s.

## Add a packet field

- Add it to `Packet`, `encode` and `decode`, then extend `round_trip_with_every_flag` and `known_wire_bytes`.
- A check that needs no session goes in `decode` with its own `DecodeError` variant and a named `rx_*` test.

## The daemon

- `nos-bfdd` is one fixed process (`/run/nos/bfd.sock`, `ServiceRef::Bfd`). Clients `Register` a session on a persistent connection and get `BfdEvent::State` (current state first, then each change).
- `Manager` keeps one task per `SessionKey`, shared by every client that registered it; the last client leaving drops it.
- Removing a session is graceful (#659): `Manager::retire` drops the demux slot, sends a `shutdown` profile (the peer logs `neighbor-signaled-session-down` instead of waiting out its detection time) and aborts the task after `max(2 x tx interval, 300 ms)`, capped at 2 s. Last-client deregister, client disconnect, mode switch and the unsolicited sweep all go through it; on SIGINT/SIGTERM `shutdown_all` retires every session with one wait. S-BFD initiators and unaffiliated echo have no Control packet and abort at once.
- A re-`Register` with a different profile is the profile edit: intervals go through Poll/Final, `shutdown` through AdminDown.
- Sockets (RFC 5881, RFC 5883): one receive socket per (table, family, multihop) on UDP 3784 or 4784, bound to the table's VRF; one connected transmit socket per session with a random source port in 49152-65535 and TTL 255. `Demux::route` checks the TTL per session with `ttl_ok`: exactly 255 single-hop, at least the profile's `minimum_ttl` multihop.
- Receive errors never end a receive task (#693): a failed `recv` backs off (10 ms doubling to 1 s, one `warn!` per streak, `bfd receive recovered` at its end) and retries; a failed `readable()` rebuilds the socket in the loop (`socket::socket_loop`: UDP 3784/4784 and the 7784 reflector are recreated, S-BFD re-registers a `try_clone` of its socket to keep the source port; echo and micro-BFD recreate their `AF_PACKET` socket on any error or when the interface index changed, checked every second because `recv` on a packet socket of a deleted interface blocks silently). Log anchors: `bfd receive socket recreated table=`, `bfd micro receive socket recreated member=`.
- Multihop: the key keeps `multihop` and `local`, never an interface; the transmit socket binds to the VRF and to `local`, else to `kernel_source` (a connected UDP socket's local address, no packet sent). Zero-discriminator demux is by (table, source, multihop). `ponytail:` no destination address in it (RFC 5883 §4 names the pair), so two multihop sessions to one peer from different local addresses in one table collide; add `IP_PKTINFO` if that matters.
- The VRF device comes from the table's `nos-ribd` (`GetVrfName`); a session whose VRF or local address is not ready retries every second.

## Static routes (`nos-ribd`)

- `rib/src/bfd_client.rs` registers the gateway of every static route with a `bfd` reference (one session per gateway), multihop when `!Config::is_connected(table, gateway)`; `local` is left to `nos-bfdd`.
- A route is left out of the RIB until its gateway's session is `Up`; `Down`, `Init` and `AdminDown` all take it out. While `nos-bfdd` is unreachable nothing is up (fail closed); after a reconnect everything is registered again.
- `reconcile::resync` reads the up set and re-runs when it changes.

## Querying sessions

- `BfdRequest::GetSessions { peer }` is a one-shot request answered with `BfdEvent::Sessions(Vec<BfdSessionView>)`, ordered by (table, peer); `peer: Some(ip)` filters in the daemon.
- `BfdSessionView` carries the `SessionKey` (table, peer, optional local/interface, multihop), `state`, `diag`, both discriminators, the negotiated `tx_interval_us` and `detection_time_us`. There is no uptime or receive interval in it.
- Single-hop sessions are keyed by (table, peer address) only: `nos-ribd` registers with `interface: None`, so `show` prints no interface; a BGP multihop session also shows its `local`.
- Only `Role::User` (`nos-cli`) and `Role::Restd` may ask (`authz::allowed`); `cli/src/bfd_client.rs` and `rest/src/show.rs::bfd_sessions` are the two clients.
- `BfdRequest::GetReflector` is answered with `BfdEvent::Reflector(ReflectorView)` (discriminators, received, replied, `ReflectorDiscards`), for the same two roles; `show bfd reflector` and `GET /v1/bfd/reflector`.

## Seamless BFD (#294)

- `sbfd` (pure): `reflect(packet, source, destination, policy)` returns the reply or a `Discard` reason, in this order: source port 7784, martian source, `allow-from`, A bit, D bit clear, unknown discriminator. `Initiator` is RFC 7880 Figure 4 (Down and Up only) with the same `now`-as-argument style as `session::Core`.
- `reflector`: `Reflector` holds the policy (`policy_of(&Config)`), a global token bucket (10 000 pps, burst 2 000, checked before the packet is parsed) and the counters `GetReflector` returns. It lives in the `Manager` (`manager.reflector()`); `handle` takes the datagram and returns the reply bytes.
- `socket::ReflectorNet`: one UDP 7784 socket per (table VRF, family) while a discriminator is configured, `IP_PKTINFO`/`IPV6_RECVPKTINFO` to learn the probed address and a `sendmsg` with that address as the source of the reply (a wildcard-bound socket would pick the route's source); TTL 255. A recreated VRF device (new ifindex) reopens the socket. `micro_sessions::run` drives it from the same config resync (scopes `SbfdReflector` and `RoutingTables`, plus the 10 s re-apply that also retries a VRF `nos-ribd` has not created yet).
- An initiator is a `Manager` session whose profile has `mode sbfd`: no `Demux` slot (the reflection comes back to the session's own connected socket, `Net::open_sbfd`, which also reads the TTL), and `sbfd::run` instead of `session::run`. A change of `mode` replaces the session, like `echo-mode unaffiliated`. `BfdSessionView.kind` tells them apart.
- The target discriminator is `sbfd-remote-discriminator`, else the peer's IPv4 address (`sbfd::remote_discriminator`); none (IPv6 peer) logs a warning and the session stays `down` and silent.
- `ponytail:` the reflector rate limit is one global bucket and its constants are not configurable; reflector authentication (RFC 7880 section 11) is a follow-up after #289.

## Check it by hand

- `nos show bfd sessions` or `GET /v1/bfd/sessions` lists what the daemon holds.
- `cargo run -p nos-e2e -- bfd-sbfd` proves an S-BFD initiator Up from reflections alone, the reflector's counters over REST, the Down and route withdrawal when the reflector stops answering for the discriminator, and a classical FRR session undisturbed beside it.
- `cargo run -p nos-e2e -- bfd-padded` proves 1400-byte packets between the routers, the `EMSGSIZE` warning and the peer's detection-time Down when router-a's MTU drops to 1300, recovery, and FRR `bfdd` accepting padded packets.
- `cargo run -p nos-e2e -- bfd-auth` proves matching and wrong keys, a live key and method change without a flap, and the unauthenticated FRR staying down.
- `cargo run -p nos-e2e -- bfd-echo-unaffiliated` proves a BFD-less forwarding gateway (router-b with `ip_forward`) brings the session and the guarded route up from looped packets, `echo-function-failed` and route withdrawal when UDP 3785 is dropped, and recovery.
- `cargo run -p nos-e2e -- bfd-echo` proves Echo active on both ends with Control slowed to 1 s, `echo-function-failed` when only UDP 3785 is dropped, recovery, and an FRR `bfdd` (`echo receive-interval 50`) with Echo running.
- `cargo run -p nos-e2e -- bfd` proves both ways Up (also read back over `GET /v1/bfd/sessions`), the route withdrawn and restored around a dropped UDP 3784, and interop with FRR `bfdd`.
- `docker exec router-a ...` has no `ip`/`tcpdump`: use the netns helper images from `tools/e2e` to sniff.
