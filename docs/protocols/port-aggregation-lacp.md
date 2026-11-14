# Port aggregation and LACP

A port aggregate bundles several physical links into one logical link (a bond, or LAG). This page covers static aggregates, LACP-negotiated ones, and how to check them. Addresses and VLANs on top of an aggregate work as on any interface: see [Interfaces](interfaces.md) and [L2 switching](l2-switching.md).

- [What a port aggregate is](#what-a-port-aggregate-is)
- [Common operations](#common-operations)
- [How aggregation behaves](#how-aggregation-behaves)
- [Configuration reference](#configuration-reference)

## What a port aggregate is

A `port-aggregate` is a named bond. Physical interfaces join it by pointing at it: `set interface eth1 port-aggregate bond1`. The aggregate itself is then used like a physical interface: it can be trunked into broadcast domains, carry routed subinterfaces, and have an MTU.

An aggregate runs in one of two modes:

- **`xor`** (static). Every member interface is put in the bond as soon as it is configured. There is no protocol with the other end, so both ends must be configured to match by hand. This is the default for a new aggregate.
- **`lacp`**. Members are negotiated with the other end using LACP (IEEE 802.1AX). A member only joins the bond once LACP on both ends agrees it should, and leaves it again when the partner stops answering. This protects against a miscabled or half-configured link, which a static bond would happily use.

In both modes, traffic is spread over the active members by a hash of each frame's source and destination MAC addresses, so traffic between two hosts always uses the same link.

## Common operations

The examples bundle `eth1` and `eth2` of router-a, which are cabled to `eth1` and `eth2` of router-b (see [Verification](#verification-notes) below for how this was set up in the lab).

### Create an LACP aggregate

```
router-a> configure lag
router-a(lag)> edit port-aggregate bond-lacp
router-a(lag/port-aggregate:bond-lacp)> set mode lacp
router-a(lag/port-aggregate:bond-lacp)> set lacp-rate fast
router-a(lag/port-aggregate:bond-lacp)> top
router-a(lag)> edit interface eth1
router-a(lag/interface:eth1)> set port-aggregate bond-lacp
router-a(lag/interface:eth1)> top
router-a(lag)> edit interface eth2
router-a(lag/interface:eth2)> set port-aggregate bond-lacp
router-a(lag/interface:eth2)> commit
transaction 'lag' committed
```

The same on router-b. Once both ends have negotiated:

```
router-a> show lacp
lacp bond-lacp: system 02:47:33:45:65:f2, key 1, rate fast, system priority 32768
  eth1: port 17, receive current, mux distributing, partner 02:e1:8b:33:6b:4c key 1 port 4, selected yes, synchronized yes, churn none, port priority 32768, partner priority 32768/32768, mode active, unsupported-version PDUs 0
  eth2: port 18, receive current, mux distributing, partner 02:e1:8b:33:6b:4c key 1 port 5, selected yes, synchronized yes, churn none, port priority 32768, partner priority 32768/32768, mode active, unsupported-version PDUs 0
router-a> show port-aggregate
port-aggregate bond-lacp: mode Lacp, switching-profile unset, mtu 1500
```

Absolute forms: `edit port-aggregate bond-lacp`, `set port-aggregate bond-lacp mode lacp`, `set port-aggregate bond-lacp lacp-rate fast`, and `set interface eth1 port-aggregate bond-lacp`, which creates `eth1` in the configuration if it isn't there yet, like every `set`. A static aggregate is the same without `mode lacp` and `lacp-rate`.

REST:

```sh
$ $C -X POST $B/v1/transactions/lag
$ $C -X PUT -H 'Content-Type: application/json' \
    -d '{"name":"bond-lacp","mode":"Lacp","lacp_rate":"Fast","subinterfaces":[]}' \
    $B/v1/transactions/lag/port-aggregate/bond-lacp
$ $C -X PUT -H 'Content-Type: application/json' -d '{"name":"eth1","addresses":[],"subinterfaces":[],"port_aggregate":"bond-lacp"}' \
    $B/v1/transactions/lag/interface/eth1
$ $C -X PUT -H 'Content-Type: application/json' -d '{"name":"eth2","addresses":[],"subinterfaces":[],"port_aggregate":"bond-lacp"}' \
    $B/v1/transactions/lag/interface/eth2
$ $C -X POST $B/v1/transactions/lag/commit
{"committed":"lag"}
$ $C $B/v1/lacp/bond-lacp | jq -c '{aggregate, actor_key, rate, ports: [.ports[] | {interface, receive_state, mux_state, partner_port_number, selected, synchronized}]}'
{"aggregate":"bond-lacp","actor_key":1,"rate":"Fast","ports":[{"interface":"eth1","receive_state":"Current","mux_state":"Distributing","partner_port_number":4,"selected":true,"synchronized":true},{"interface":"eth2","receive_state":"Current","mux_state":"Distributing","partner_port_number":5,"selected":true,"synchronized":true}]}
```

For an interface that is already in the configuration, set only the field: `PUT …/interface/eth1/port-aggregate` with body `"bond-lacp"`.

### Use the aggregate

Route the aggregate like an interface: its subinterface 0 is the bond itself. For example, to route `bond-lacp` in `rt1` with a 9000-byte MTU:

```
router-a> configure lag2
router-a(lag2)> edit port-aggregate bond-lacp
router-a(lag2/port-aggregate:bond-lacp)> set mtu 9000
router-a(lag2/port-aggregate:bond-lacp)> edit subinterface 0
router-a(lag2/port-aggregate:bond-lacp/subinterface:0)> set address 192.0.2.33/29
router-a(lag2/port-aggregate:bond-lacp/subinterface:0)> set routing-table rt1
router-a(lag2/port-aggregate:bond-lacp/subinterface:0)> commit
transaction 'lag2' committed
```

The same over REST:

```sh
$ $C -X POST $B/v1/transactions/lag2
$ $C -X PUT -H 'Content-Type: application/json' \
    -d '{"tag":0,"addresses":[{"address":"192.0.2.33/29","label":null}],"routing_table":"rt1"}' \
    $B/v1/transactions/lag2/port-aggregate/bond-lacp/subinterface/0
$ $C -X PUT -H 'Content-Type: application/json' -d '9000' $B/v1/transactions/lag2/port-aggregate/bond-lacp/mtu
$ $C -X POST $B/v1/transactions/lag2/commit
{"committed":"lag2"}
```

Then, in the shell:

```
router-a> show port-aggregate
port-aggregate bond-lacp: mode Lacp, switching-profile unset, mtu 9000
  subinterface 0: address [192.0.2.33/29], routing-table rt1, mtu 9000
```

To trunk the aggregate into broadcast domains instead, `set port-aggregate bond-lacp switching-profile sp1` (REST: `PUT …/port-aggregate/bond-lacp/switching-profile` with body `"sp1"`).

Addresses on an aggregate's subinterfaces are listed as `connected` routes in `show route <table>`, like those of an interface or an SVI.

### Take a member out, or remove the aggregate

`delete interface eth2 port-aggregate` releases `eth2` from the bond. To delete the aggregate, first release every member, since a member still pointing at a missing aggregate fails the commit:

```
router-a> configure nolag
router-a(nolag)> delete interface eth1 port-aggregate
router-a(nolag)> delete interface eth2 port-aggregate
router-a(nolag)> delete port-aggregate bond-lacp
router-a(nolag)> commit
transaction 'nolag' committed
```

REST: `DELETE …/interface/eth1/port-aggregate`, the same for `eth2`, then `DELETE …/port-aggregate/bond-lacp`, and commit.

## How aggregation behaves

**Members.** A member must be a physical interface, and it gives the whole link to the bond: the commit refuses a member that also has subinterfaces (including an untagged `.0`) or a switching profile. Put those on the aggregate instead. LLDP, which is per physical link, still runs on the members (see [LLDP](lldp.md)).

**LACP negotiation.** In `lacp` mode each member runs the LACP state machines. `show lacp` shows, per member, two of them:

- `receive` is whether the partner is heard: `current` when LACPDUs arrive in time, `expired` right after they stop, then `defaulted`. While `expired` the member keeps its partner and stays selected, so a single lost LACPDU does not detach it; `defaulted` shows `partner none (defaulted)`, and the REST fields then carry the administrative default (all-zero system, key 1, port 1, priorities 65535/255).
- `mux` is how far the member is into the bond: `detached`, `waiting` (a two-second settling time), `attached`, `collecting`, and finally `distributing`. Only a `distributing` member carries traffic, and NOS adds a member to the bond only in that state.

`selected` and `synchronized` say whether the member is chosen for the aggregate and in sync with the partner. `churn` reports `actor` or `partner` when one side has stayed out of sync for too long, which usually means a misconfiguration at that end; the member is kept out of the bond until it clears.

**`lacp-rate`** is how often this end asks its partner to send LACPDUs, and so how quickly a dead partner is detected: `slow` (default) asks for one every 30 seconds and gives up after 90; `fast` asks for one every second and gives up after 3. Each end sends at the rate the *other* end asks for, so set `fast` on both ends for fast detection in both directions.

**Marker protocol.** NOS answers LACP Marker PDUs (802.1AX §6.5) on every member, so a partner that flushes a conversation before moving it gets an immediate reply. NOS never sends Markers itself: its members never move between aggregates.

**LACP identity.** An LACP partner is identified by a system ID (a MAC address) and a key. NOS derives both from the router and the aggregate; `show lacp` shows them as `system` and `key`. `lacp-system-id` overrides the system ID. It is meant for EVPN multi-homing, where two routers present one LACP partner to a dual-homed device: set the same value on both.

**Priorities.** Each end advertises an Actor System Priority (per aggregate, `lacp-system-priority`) and an Actor Port Priority (per member interface, `lacp-port-priority`), both 0-65535 with default 32768; a lower value is a higher priority. `show lacp` prints your own values and the partner's (`partner priority <system>/<port>`).

- Membership of an aggregate is fixed by configuration and there is no standby link, so priorities do not choose which members carry traffic.
- They matter in one case: if the partner splits your members into equally sized groups, the group holding the member with the lowest (port priority, port number) is kept.
- Changing the system priority restarts LACP on every member of the aggregate; changing a member's port priority restarts only that member. Each renegotiates and rejoins the bond.
- Set with `set port-aggregate bond-lacp lacp-system-priority 100` and `set interface eth1 lacp-port-priority 100`; `delete` goes back to 32768. They have no effect on an `xor` aggregate.

**Passive mode.** `lacp-mode` on a member sets its LACP Activity: `active` (default) sends LACPDUs as soon as the link is up; `passive` stays silent until it hears a partner that is active, then answers and keeps sending.

- Set with `set interface eth1 lacp mode passive`; `delete` goes back to `active`. Changing it restarts LACP on that member only. It has no effect on an `xor` aggregate.
- Active against passive negotiates normally. Passive against passive never does: neither end speaks, so both stay `defaulted`, no member reaches `distributing` and the bond stays empty. Put at least one end on `active`.
- `show lacp` prints `mode active|passive` per member, and NOS logs `lacp periodic transmission machine transitioned … no_periodic=true` when a passive member goes silent.

**`min-links`.** The minimum number of members that must be `distributing` for the bond to be used, default 1 (0 means the same).

- Below it NOS empties the kernel bond: every member is released from it, and `nos-lacpd` logs `lacp min-links not met, bond emptied`. The members keep negotiating (`show lacp` still shows them `distributing`), so the bond refills the moment enough of them are back.
- `show lacp` prints `min-links <n>: met` or `not met, bond emptied` under the aggregate when `min-links` is above 1.
- It is not checked against the number of members, which are configured on the interfaces: a value above that count keeps the bond empty for good, and `nos-lacpd` logs a warning.
- Set with `set port-aggregate bond-lacp min-links 2`. A change takes effect at once and restarts no member. It has no effect on an `xor` aggregate.

**`bfd` and `bfd-peer` (RFC 7130 micro-BFD gating).** `bfd <profile>` gates each member's enslavement on a per-member BFD session; `bfd-peer <ip>` is the remote end's address.

- A member is enslaved only while it is Up in the last push from `nos-bfdd` (`PushBfdMembers`); enslavement is `lacp_ok && bfd_ok`, so it also needs the LACP rule for a `lacp` aggregate and applies to `xor` ones alike.
- No push yet counts as not Up: a member of an aggregate with `bfd` stays out of the bond until its session is Up (fail closed, like LACP).
- A push is applied at once and survives unrelated config changes.
- The commit is refused when `bfd` names no `bfd-profile`, has no `bfd-peer`, or the untagged subinterface has no address of the peer's family (the session source). `bfd` on an aggregate without members is accepted.
- Set with `set port-aggregate bond-lacp bfd fast` and `set port-aggregate bond-lacp bfd-peer 10.0.0.2`. The sessions are `nos-bfdd`'s micro-BFD member sessions: see [BFD profiles](bfd.md#micro-bfd-on-a-port-aggregate-rfc-7130).

**Individual ports.** A partner that clears the Aggregation bit of its LACPDUs declares the link Individual: it will not bundle it with any other link. NOS never selects such a member, and it does not count towards the partner groups of the others.

- `show lacp` ends that member's line with `individual (partner not aggregatable)`; `GET /v1/lacp` has `"individual": true`.
- NOS itself never declares a link Individual: only configured members run LACP.
- An Individual member stays out of the bond while the partner keeps it so, and joins as soon as the partner sets the bit again. Check the partner's configuration (for example a link it considers half duplex).

**LACPDU versions.** NOS accepts version 1 and version 2 (802.1AX-2014) LACPDUs, so a LACPv2 partner bundles; it still sends version 1.

- Any other Version byte is dropped without a log line and counted: `show lacp` ends each member's line with `unsupported-version PDUs <n>`; `GET /v1/lacp` has `"unsupported_version_pdus"`.
- A count that keeps growing means the partner sends a version other than 1 or 2: check its LACP configuration. The count restarts at 0 when the member's link task restarts (member re-added, `nos-lacpd` restart).
- A `lacp loopback detected interface=<member>` warning means the member hears LACPDUs carrying this router's own system id: the link is cabled back to this host (another member or aggregate). Such PDUs are ignored, so the member never joins the aggregate; fix the cabling.

**EVPN multi-homing.** `esi` attaches the aggregate to an EVPN Ethernet Segment, `redundancy-mode` chooses all-active or single-active forwarding for it, and `df-algorithm` the designated forwarder election. They are documented with EVPN.

**`show port-aggregate`** shows each aggregate's mode, switching profile, MTU and subinterfaces, as applied; `show lacp` the LACP state of every `lacp` aggregate. Neither lists the members of an `xor` aggregate: check them in `show config`.

### Verification notes

The examples on this page were run on the lab of the [README](../README.md#conventions-used-in-these-pages), with two extra links: `eth1` and `eth2` are veth pairs directly between router-a and router-b. A direct link matters: LACP (and LLDP) frames use reserved multicast addresses that a bridge, including a Docker network, never forwards, so the two ends would never hear each other through one.

## Configuration reference

Every REST path starts with `/v1/transactions/{tx}/`. The relative CLI form is what you type after `edit port-aggregate <pa>`.

### `port-aggregate <pa>`

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit port-aggregate <pa>` (creates it in `xor` mode); `delete port-aggregate <pa>` | `port-aggregate/<pa>` | string, 1-64 characters | unique; no `.`; no member may still reference a deleted aggregate | creates or deletes the bond | `show port-aggregate` |
| mode | `set port-aggregate <pa> mode xor\|lacp` / `set mode xor\|lacp` | `port-aggregate/<pa>/mode`, body `"Xor"` or `"Lacp"` | `xor` (default) or `lacp` | | `xor`: members join unconditionally; `lacp`: members join once negotiated | `show port-aggregate`, `show lacp` |
| lacp-rate | `set port-aggregate <pa> lacp-rate fast\|slow` / `set lacp-rate fast\|slow` | `port-aggregate/<pa>/lacp-rate`, body `"Fast"` or `"Slow"` | `slow` (default) or `fast` | | asks the partner for LACPDUs every 1 s (`fast`) or 30 s (`slow`); `lacp` mode only | `show lacp` (`rate`) |
| lacp-system-id | `set port-aggregate <pa> lacp-system-id <mac>` / `set lacp-system-id <mac>`; `delete … lacp-system-id` | `port-aggregate/<pa>/lacp-system-id` | unicast MAC, `02:00:00:00:00:01`; default derived | a unicast MAC | the LACP system ID advertised to the partner | `show lacp` (`system`) |
| lacp-system-priority | `set port-aggregate <pa> lacp-system-priority <n>` / `set lacp-system-priority <n>`; `delete … lacp-system-priority` | `port-aggregate/<pa>/lacp-system-priority` | 0-65535; default 32768 | | the Actor System Priority advertised to the partner; a change restarts every member's LACP; `lacp` mode only | `show lacp` (`system priority`) |
| min-links | `set port-aggregate <pa> min-links <n>` / `set min-links <n>` | `port-aggregate/<pa>/min-links` | 0-65535; default 1 | | the bond carries traffic only with at least this many `distributing` members; applies live; `lacp` mode only | `show lacp` (`min-links`) |
| bfd | `set port-aggregate <pa> bfd <profile>` / `set bfd <profile>`; `delete … bfd` | `port-aggregate/<pa>/bfd` | a `bfd-profile` name; default unset | the profile exists; needs `bfd-peer` and a same-family address on the untagged subinterface | a member is enslaved only while its micro-BFD session is Up | `show config` |
| bfd-peer | `set port-aggregate <pa> bfd-peer <ip>` / `set bfd-peer <ip>`; `delete … bfd-peer` | `port-aggregate/<pa>/bfd-peer` | IPv4 or IPv6 address; default unset | | the address the micro-BFD sessions are sent to; ignored without `bfd` | `show config` |
| esi | `set port-aggregate <pa> esi <esi>` / `set esi <esi>`; `delete … esi` | `port-aggregate/<pa>/esi` | 10 hex bytes; default unset | not all zero; unique among aggregates | EVPN Ethernet Segment, see EVPN | `show bgp evpn` |
| redundancy-mode | `set port-aggregate <pa> redundancy-mode all-active\|single-active` / `set redundancy-mode …` | `port-aggregate/<pa>/redundancy-mode`, body `"AllActive"` or `"SingleActive"` | `all-active` (default) | `single-active` needs an `esi` | EVPN multi-homing mode, see EVPN | `show config` |
| df-algorithm | `set port-aggregate <pa> df-algorithm modulo\|hrw` / `set df-algorithm …` | `port-aggregate/<pa>/df-algorithm`, body `"Modulo"` or `"Hrw"` | `modulo` (default) | `hrw` needs an `esi` | EVPN designated forwarder election algorithm, see EVPN | `show config` |
| switching-profile | `set port-aggregate <pa> switching-profile <sp>` / `set switching-profile <sp>`; `delete … switching-profile` | `port-aggregate/<pa>/switching-profile` | name; default unset | profile exists; tags don't collide with the aggregate's subinterfaces | trunks the bond into the profile's broadcast domains | `show port-aggregate <pa>` |
| subinterface mtu | `edit port-aggregate <pa> subinterface <tag>`, then `set mtu <n>`; `delete mtu` | `port-aggregate/<pa>/subinterface/<tag>/mtu` | 68-65535; follows the bond's MTU | not above the bond's MTU; not on tag 0 | per-VLAN override, applied to the kernel sub-link | `show port-aggregate <pa>` |
| mtu | `set port-aggregate <pa> mtu <n>` / `set mtu <n>`; `delete … mtu` | `port-aggregate/<pa>/mtu` | 68-65535; default 1500, enforced | range | the bond's MTU, which the bond also sets on its members | `show port-aggregate <pa>` |
| subinterface | `edit port-aggregate <pa> subinterface <tag>`, then `set address <cidr>` / `set routing-table <t>`; `delete port-aggregate <pa> subinterface <tag>` | `port-aggregate/<pa>/subinterface/<tag>`, body `{"tag":<n>,"addresses":[…],"routing_table":…}` | tag 0-4094, as on an interface | as on an interface | routed subinterfaces of the bond (tag 0 is the bond itself) | `show port-aggregate <pa>` |

| lacp-version | `set port-aggregate <pa> lacp-version 1\|2` | `port-aggregate/<pa>/lacp-version`, body `"V1"` or `"V2"` | `1` or `2`; default `2` | `lacp-version 1` refuses a port algorithm or conversation map | the LACP version to advertise; `1` is the per-aggregate opt-out | `show lacp` (`version 2` line, v2 only) |
| lacp-port-algorithm | `set port-aggregate <pa> lacp-port-algorithm unspecified\|c-vlan\|s-vlan` | `port-aggregate/<pa>/lacp-port-algorithm` | default `unspecified` (plain hashing) | needs a `lacp` aggregate with `lacp-version 2` | conversation id = the C/S-VLAN id | `show lacp` |
| lacp-conversation-map | `set port-aggregate <pa> lacp-conversation-map <first> last <n> member <if>`; `delete port-aggregate <pa> lacp-conversation-map <first>` | `port-aggregate/<pa>/lacp-conversation-map/<first>` | `first <= last <= 4095`, no overlap, `member` is a member of `<pa>`; empty = automatic distribution (`conversation mod active-links`) | needs an algorithm other than `unspecified` | explicit conversation-to-link map | `show lacp` |

**LACP v2 knobs (#892): accepted and shown, not read yet.** Nothing in `nos-lacpd` reads `lacp-version`, `lacp-port-algorithm`, `lacp-conversation-map` or `lacp-link-number` until #894 (wire format) and #895 (steering). The default `lacp-version 2` becomes a wire-format change (every aggregate starts sending v2 PDUs on upgrade, `lacp-version 1` opts out) when #894 lands, and that release carries the upgrade note.

`delete mode`, `delete lacp-rate`, `delete redundancy-mode` and `delete df-algorithm` put them back to their default (`xor`, `slow`, `all-active`, `modulo`).

### On a member interface

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| port-aggregate | `set interface <if> port-aggregate <pa>` / `set port-aggregate <pa>`; `delete interface <if> port-aggregate` / `delete port-aggregate` | `interface/<if>/port-aggregate` | name; default unset | aggregate exists; the interface has no subinterfaces and no switching profile | makes the interface a member | `show lacp` |
| lacp-mode | `set interface <if> lacp mode active\|passive`; `delete … lacp mode` | `interface/<if>/lacp-mode`, body `"Active"` or `"Passive"` | `active` (default) or `passive` | | the LACP Activity advertised for this member; `passive` sends nothing until the partner is heard active; a change restarts this member's LACP only; meaningful while it is in a `lacp` aggregate | `show lacp` (`mode`) |
| lacp-port-priority | `set interface <if> lacp-port-priority <n>` / `set lacp-port-priority <n>`; `delete … lacp-port-priority` | `interface/<if>/lacp-port-priority` | 0-65535; default 32768 | | the Actor Port Priority advertised for this member; a change restarts this member's LACP only; meaningful while it is in a `lacp` aggregate | `show lacp` (`port priority`) |
| lacp-link-number | `set interface <if> lacp-link-number <n>`; `delete … lacp-link-number` | `interface/<if>/lacp-link-number` | 1-65535, unique among the aggregate's members; unset by default (range is a placeholder until verified, see `docs/internals/lacp-v2.md`) | non-zero and unique within the aggregate | the 802.1AX-2014 Link_Number naming this link in the conversation map; not read yet | |

Implementation notes for developers are in [`docs/internals/lacp.md`](../internals/lacp.md) and [`docs/internals/interface.md`](../internals/interface.md).
