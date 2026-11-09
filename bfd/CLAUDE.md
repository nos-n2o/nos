# nos-bfd — BFD (RFC 5880/5881) library and `nos-bfdd`

The pure core (#296) plus the single system-wide daemon `nos-bfdd` (#297), a fixed process like `nos-lldpd`. Single-hop and multihop; its clients are `nos-ribd`'s `bfd_client.rs` (static routes), `nos-bgpd`'s (peer-groups, #286) and `nos-ospfd`/`nos-ospfv3d`'s (#288).

| Module | Purpose |
|--------|---------|
| `packet` | control packet codec (parses the auth section), §6.8.6 reception checks |
| `auth` | RFC 5880 §6.7: auth section sign/parse, digests, `AuthState` (key, old key, sequence window) |
| `fsm` | `step(state, event)` state machine, `may_transmit` (passive) |
| `timers` | Interval negotiation, jitter, Poll/Final, detection time |
| `authz` | `allowed(role, &BfdRequest)` |
| `session` | `Core` (pure: packets and clock in, packets out) and `run`, one tokio task per session |
| `manager` | Session table, refcount per client, `Demux` (rx packet to session), `Net` trait |
| `server` | `--listen-socket`: `Register` streams `BfdEvent::State`, `GetSessions` replies once |
| `echo` | Echo packet build/parse (IP + UDP 3785, TTL 255, source = destination) |
| `micro` | RFC 7130 IP/UDP 6784 frame build/parse (pure), 802.1p tag-0 untagging |
| `micro_sessions` | `wanted(&Config)` (one session per aggregate member), `Micro::apply`, `UpSets` (push-on-change), config follow loop |
| `interface_client` | The `PushBfdMembers` connection to `nos-interfaced` (cached, resent on reconnect); config/watchdog clients come from `nos-daemon` |
| `neigh` | The neighbour's MAC from rtnetlink (read-only) |
| `sbfd` | RFC 7880 Seamless BFD, pure: `reflect` (the stateless reflector's decision) and `Initiator` (Figure 4), `run` its task |
| `reflector` | The reflector's policy, token bucket and counters (`Manager::reflector()`) |
| `socket` | `vrf_name` (the table's VRF device via `nos-ribd` `GetVrfName`), UDP 3784/4784/7784 sockets (`UdpNet`, `ReflectorNet`) and the Echo `AF_PACKET` transport; excluded from coverage, `nos-e2e`'s `bfd`, `bfd-echo` and `bfd-sbfd` phases are its test |
| `unsolicited` | RFC 9468, pure: `Rule`s from the config, `decide` (create/ignore/cap), `age_step` |

Wire types are in `nos-proto::bfd`; `ServiceRef::Bfd` / `Role::Bfdd` in `broker`.

## Rules that bite

- `decode` never panics: use `get`/`try_into`, never index untrusted bytes.
- Auth (#289): `Core::authenticate` before `on_packet`, `Core::sign` on every send; a failed packet must not reach the FSM or timers. A profile edit keeps the old key valid for 4 detection times. Keys (#510): `BfdAuth.key` is an admin label resolved only in `nos-bfdd` (`Manager::resolve`/`set_keys`, `AuthKey` hides the secret); unresolved = fail closed (`Core::unkeyed`), never unauthenticated. S-BFD reflector auth is a follow-up.
- `timers` and `Core` take `now` and the jitter percentage as arguments; only `session::run` reads the clock.
- Discriminators come from the manager's counter (random start), never 0.
- `BfdRequest`/`BfdEvent` variants are appended, never reordered (postcard). A new `BfdRequest` must be classified in `authz::allowed`.
- Echo (#290, single-hop, affiliated only): `Core::sync_echo` toggles it and Desired Min TX goes to 1 s through `Timers::change`; never write the neighbour table; echoes are received at the packet layer (the IP stack drops our own source). No demand mode. Multihop (#287): UDP 4784, TTL checked per session in `Demux::route`; no destination address in the zero-discriminator demux (`ponytail:` in `manager.rs`).
- Unaffiliated echo (#291, RFC 9747): `echo-mode unaffiliated` makes Echo the whole session. `Core` ignores Control, sends encoded Control packets as the Echo payload and feeds the FSM its own looped state; no 3784 socket, no `Demux` slot (`NoTx`); only TTL 254 accepted. The neighbour is resolved by an empty UDP datagram (`neigh_loop`). `auth` ignored (`ponytail:`).
- Padding (#293, RFC 9764): `Core::wire` = `sign` + zero padding after the `length` bytes (auth digest untouched); `decode` already ignores trailing bytes. TX sockets always set `IP_PMTUDISC_DO`/`IPV6_DONTFRAG`; `EMSGSIZE` logs `bfd padded packet exceeds the path mtu` once. The RX buffer stays 128 bytes: a longer datagram is truncated, harmless as only `length` bytes are read.
- S-BFD (#294, RFC 7880/7881): `mode sbfd` makes a session an `Initiator` with no `Demux` slot; its own connected socket (source port other than 7784) receives the reflection, TTL checked in `sbfd::run`. The reflector (`Reflector`, UDP 7784 per VRF, only while a discriminator is configured) answers from the probed address via `IP_PKTINFO`, drops D=0, A bit, source port 7784, martians, non-`allow-from` and over-rate packets, and counts each. No S-BFD authentication yet (follow-up after #289); A-bit packets are discarded.
- Unsolicited (#295, RFC 9468): `Subinterface.bfd_unsolicited` becomes a `Rule` (`Manager::set_unsolicited`, fed by the config resync); `Demux::route_on` calls a hook for a single-hop Your Discriminator 0 packet no session claims, `Manager::unsolicited_rx` creates a client-less passive session (`Entry.unsolicited`, key interface = the kernel device, source must be in the subinterface subnet, TTL 255, cap 256). `sweep_loop` deletes one not Up for 60 s; a client registering the peer adopts it. Log anchors `bfd unsolicited session created|aged out peer=`, `removed: no longer configured`.
- Desired Min TX is floored at 1 s while not Up by `Timers` itself; reaching Up opens a Poll sequence for the lifted floor (RFC 5880 §6.8.3) through `Timers::on_state`, called from `Core::apply`.
- The profile travels in `Register`; a re-`Register` with a changed profile runs Poll/Final (no flap), `shutdown` goes AdminDown. `nos-bfdd` follows only `Interfaces`/`PortAggregates`/`BfdProfiles`/`Admin` diffs (micro-BFD, auth keys) and `SbfdReflector`/`RoutingTables` (the reflector).
- Retiring (#659): `Manager::retire` (last client, `drop_client`, mode switch, sweep) removes the demux slot at once, sends a `shutdown` profile so the peer hears `AdminDown`, and aborts the task after `max(2 x tx interval, 300 ms)` capped at 2 s; `shutdown_all` does it on SIGINT/SIGTERM. S-BFD and unaffiliated echo abort at once. Anchor `bfd session admin down sent peer=`.
- A client's connection drop releases its sessions; the last client drops the session. Request-side EOF ends the connection (`ponytail:` in `server.rs`).
- A TX socket must bind an explicit source address (`socket::local_for`): bound to a VRF with a wildcard source the kernel sends from 0.0.0.0.
- RX: UDP 3784 per (table, family) bound to the VRF; TTL must be exactly 255. Demux is by Your Discriminator, else (table, source address): no interface in the key (`ponytail:` in `manager.rs`).
- `BfdEvent::State.control_plane_independent` is the C bit at both ends (`nos-bfdd` always sets its own; the remote's is from the last received packet): BGP flushes routes on Down only when it is set (RFC 5882 §4.3).
- Micro-BFD (#299, RFC 7130): a `SessionKey` with `aggregate` set (`interface` = member, `table` empty) is a member session; `socket::MicroTx` runs on the member itself via `nos-l2-socket` (UDP 6784, dst MAC `01-00-5E-90-00-01`), `Demux::route_micro` requires the arrival member, no Echo. The aggregate's Up set goes to `nos-interfaced` whole and only on change; no push = not Up. `ponytail:` sessions exist for every member, not only LACP Distributing/Standby.
- Receive loops never exit (#693): `recv` errors back off (10 ms to 1 s, `warn!` once per streak) and retry, a dead socket is recreated inside the loop (`socket::socket_loop`/`reopen`); S-BFD keeps its source port via `try_clone`; L2 loops also recreate when the interface index changes (1 s check). TX (#660): `socket::UdpTx` rebuilds on a device/VRF index change.
- Log anchors the e2e relies on: `bfd receive socket recreated table=`, `bfd transmit socket recreated`, `bfd micro receive socket recreated member=`, `bfd session up aggregate= member= peer=` (micro), `bfd session up peer=`, `bfd session down peer= diag=`, `bfd echo active peer=` (S-BFD initiators log the same up/down lines).

Details: [docs/internals/bfd.md](../docs/internals/bfd.md).
