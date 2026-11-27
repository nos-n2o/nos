# LLDP

LLDP (IEEE 802.1AB) lets directly connected devices discover each other: each end periodically announces who it is and which port the frame left from, and records what its neighbours announce. This page covers turning it on per interface, tuning it, and reading the neighbour table.

- [What NOS sends and records](#what-nos-sends-and-records)
- [Common operations](#common-operations)
- [How LLDP behaves](#how-lldp-behaves)
- [Configuration reference](#configuration-reference)

## What NOS sends and records

LLDP is off by default. It is enabled per physical interface, separately for each direction:

- **transmit**: NOS sends an LLDP frame out of the interface every 30 seconds (by default).
- **receive**: NOS listens on the interface and records every neighbour it hears.

Each frame NOS sends carries:

- the chassis ID, a MAC address that identifies this router;
- the port ID and port description, both the interface name (`eth1`);
- the time to live: how long the neighbour should keep this information, 120 seconds by default;
- the system name, which is the router's `hostname`, and the system description, `nos` unless you set one (no version number is sent);
- the capabilities: supported "Router, Bridge"; enabled "Router", plus "Bridge" on an interface that has a switching profile;
- up to four management addresses, if configured, each with the ifIndex of the interface that carries it;
- the maximum frame size (IEEE 802.3): the interface's MTU plus 18 bytes of Ethernet header and FCS, 1518 by default. A port-aggregate member uses its aggregate's MTU;
- on an interface with a switching profile, one VLAN name (IEEE 802.1) per `dot1q` member: the tag and the broadcast domain's name, cut to 32 bytes. An `untagged` member has no VLAN number in NOS, so it is not sent;
- on a port-aggregate member, the link aggregation state (IEEE 802.1): always "capable", and "aggregated" with the bond's ifIndex while the member is enslaved. For an LACP aggregate that is while LACP has the member in the bond. A change shows up in the next frame, so within `tx-interval`.

NOS does not send a port VLAN ID or the 802.3 MAC/PHY field. It decodes and shows both when a neighbour sends them.

Four settings apply to all interfaces at once: the transmit interval, the hold multiplier, the management addresses and the system description. One more is per interface: the destination group.

## Common operations

The examples use router-a and router-b, with `eth1` a direct link between them (see [Verification notes](#verification-notes)).

### Enable LLDP on a link

```
router-a> configure lldp
router-a(lldp)> edit interface eth1
router-a(lldp/interface:eth1)> set lldp transmit
router-a(lldp/interface:eth1)> set lldp receive
router-a(lldp/interface:eth1)> commit
transaction 'lldp' committed
```

With the same on router-b, a few seconds later:

```
router-a> show lldp neighbors
eth1: neighbor router-b, chassis 02:e1:8b:33:6b:4c, port eth1, capabilities router, ttl 112s
```

Each line gives the local interface, the neighbour's system name, chassis ID and port ID, the capabilities it has enabled, its management addresses if it sends any, and how many seconds are left before the entry expires.

The absolute forms are `set interface eth1 lldp transmit` and `set interface eth1 lldp receive`. `delete interface eth1 lldp transmit` (or `receive`) turns one direction off again.

REST: the two directions are booleans on the interface.

```sh
$ $C -X POST $B/v1/transactions/lldp
$ $C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/lldp/interface/eth1/lldp-transmit
$ $C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/lldp/interface/eth1/lldp-receive
$ $C -X POST $B/v1/transactions/lldp/commit
{"committed":"lldp"}
$ $C $B/v1/lldp/neighbors | jq .
[
  {
    "local_interface": "eth1",
    "chassis_id": "02:e1:8b:33:6b:4c",
    "port_id": "eth1",
    "port_description": "eth1",
    "system_name": "router-b",
    "system_description": "nos",
    "capabilities": [
      "router"
    ],
    "management_addresses": [],
    "ttl_remaining_secs": 94
  }
]
```

The REST answer also carries the IEEE 802.1/802.3 fields (`vlan_names`, `port_vlan_id`, `link_aggregation`, `max_frame_size`, `mac_phy`), `null` or empty when the neighbour did not send them.

This assumes `eth1` is already in the configuration. If it is not, create it whole: `PUT …/interface/eth1` with body `{"name":"eth1","addresses":[],"subinterfaces":[],"lldp_transmit":true,"lldp_receive":true}`.

### See everything a neighbour sent

`show lldp neighbors detail` prints one block per neighbour, with a line for each field it sent:

```
router-b> show lldp neighbors detail
eth1: neighbor router-a
  chassis 02:47:33:45:65:f2
  port eth1
  port-description eth1
  system-description nos
  capabilities bridge,router
  vlans 100 (bd1)
  max-frame-size 9018
  ttl 108s
eth2: neighbor router-a
  chassis 02:47:33:45:65:f2
  port eth2
  port-description eth2
  system-description nos
  capabilities router
  aggregation aggregated, port id 9
  max-frame-size 1518
  ttl 112s
```

Here router-a's `eth1` has `mtu 9000` and a switching profile trunking it into `bd1` at `dot1q 100`, and its `eth2` is a member of a port aggregate. A neighbour that sends them also gets `port-vlan-id` and `mac/phy` lines (auto-negotiation, advertised capabilities, MAU type).

REST: the same fields are in `GET /v1/lldp/neighbors`.

### Tune the timers and advertise management addresses

```
router-a> configure lldp2
router-a(lldp2)> set lldp tx-interval 5
router-a(lldp2)> set lldp tx-hold 3
router-a(lldp2)> set lldp management-address 10.50.0.2
router-a(lldp2)> set lldp management-address 192.0.2.1
router-a(lldp2)> commit
transaction 'lldp2' committed
```

Router-b now keeps router-a's entry for 5 × 3 = 15 seconds and shows both management addresses. 10.50.0.2 is on router-a's `eth0`, so it comes with that interface's ifIndex; 192.0.2.1 is on no interface, so it comes without one:

```
router-b> show lldp neighbors
eth1: neighbor router-a, chassis 02:47:33:45:65:f2, port eth1, capabilities router, management 10.50.0.2 (ifindex 2),192.0.2.1, ttl 10s
```

REST: the three settings are the `lldp` section of the configuration.

```sh
$ $C -X PUT -H 'Content-Type: application/json' \
    -d '{"tx_interval_secs":5,"tx_hold":3,"management_addresses":["10.50.0.2","192.0.2.1"]}' \
    $B/v1/transactions/lldp2/lldp
$ $C -X POST $B/v1/transactions/lldp2/commit
```

Each can also be set on its own, for example `PUT …/lldp/tx-interval-secs` with body `5`. `delete lldp tx-interval` (REST: `DELETE …/lldp/tx-interval-secs`) goes back to the default. `delete lldp management-address 192.0.2.1` stops advertising that one address.

### Set the system description

```
router-a> configure lldp4
router-a(lldp4)> set lldp system-description "core router, rack 4"
router-a(lldp4)> commit
transaction 'lldp4' committed
```

- Free text, 1-255 bytes, no control characters. `delete lldp system-description` goes back to `nos`.
- Neighbours see it in `show lldp neighbors detail` (`system-description`) and in `GET /v1/lldp/neighbors`.
- REST: `PUT …/lldp/system-description` with body `"core router, rack 4"`.
- Changing it restarts LLDP on every enabled interface, like the timers.

### Change the destination group

```
router-a> configure lldp3
router-a(lldp3)> set interface eth1 lldp destination customer-bridge
router-a(lldp3)> commit
transaction 'lldp3' committed
```

REST: `PUT …/interface/eth1/lldp-destination` with body `"CustomerBridge"`. Both ends of the link must use the same group; see below.

### Read the counters

```
router-a> show lldp statistics
eth1: tx 14, rx 12, rx errors 0, rx discarded 0, tlvs discarded 0, tlvs unrecognized 0, ageouts 0, too many neighbors 0
```

One line per LLDP-enabled interface, with the IEEE 802.1AB counters:

- `tx`: frames sent, shutdown frames included.
- `rx`: valid frames received. Our own frames looped back are not counted.
- `rx errors`: frames that failed validation (a missing, misordered or malformed mandatory field).
- `rx discarded`: every frame in error, plus every frame from a new neighbour refused because the table was full.
- `tlvs discarded`: optional fields dropped: a malformed or non-IP management address, or one past the fourth in a frame; a malformed or repeated IEEE 802.1/802.3 field, or a VLAN name past the 32nd.
- `tlvs unrecognized`: fields NOS does not decode: reserved types and the organization-specific fields other than the IEEE 802.1/802.3 ones above (LLDP-MED, DCBX, …).
- `ageouts`: neighbours removed because their time to live ran out (not those that sent a shutdown frame).
- `too many neighbors`: new neighbours refused because the interface already had 32.

The counters start at zero when `nos-lldpd` starts or LLDP is enabled on the interface. A settings change that restarts LLDP on the interface keeps them; turning both directions off drops them.

REST: `GET /v1/lldp/statistics`, one object per interface.

```sh
$ $C $B/v1/lldp/statistics | jq .
[
  {
    "interface": "eth1",
    "frames_out": 14,
    "frames_in": 12,
    "frames_in_errors": 0,
    "frames_discarded": 0,
    "tlvs_discarded": 0,
    "tlvs_unrecognized": 0,
    "ageouts": 0,
    "too_many_neighbors": 0
  }
]
```

### Configure LLDP-MED (configuration only for now)

LLDP-MED (ANSI/TIA-1057) lets a switch port tell an IP phone which VLAN to use, how much power to expect and where it is. NOS stores and validates this configuration. `nos-lldpd` does not send it yet, so nothing changes on the wire until the transmit step lands (#1572).

- A profile groups the settings and an interface attaches it with `lldp-med-profile <name>`. One profile can serve many ports.
- `network-policy <application>` sets `vlan`, `tagged`, `priority` and `dscp` for one application type. At most 8 per profile, one per type: `voice`, `voice-signaling`, `guest-voice`, `guest-voice-signaling`, `softphone-voice`, `video-conferencing`, `streaming-video`, `video-signaling`.
- `poe` sets the power source, priority and power in units of 0.1 W (154 is 15.4 W, at most 1023). The values are advertised as configured and never measured: NOS has no PoE hardware.
- `advertise-always` exists for NOS-to-NOS links, where neither side would speak first. What it gates is described with the transmit step.
- The location is per interface, so each jack has its own. It needs an `lldp-med-profile` on the same interface (an empty one is enough). Set any of `elin`, `civic` and `coordinate`.

```
nos(config)# set lldp-med-profile phones network-policy voice vlan 100
nos(config)# set lldp-med-profile phones network-policy voice tagged
nos(config)# set lldp-med-profile phones network-policy voice priority 5
nos(config)# set lldp-med-profile phones network-policy voice dscp 46
nos(config)# set lldp-med-profile phones poe power 154
nos(config)# set interface eth1 lldp-med-profile phones
nos(config)# set interface eth1 lldp-location elin 3125550123
nos(config)# set interface eth1 lldp-location civic country FR
nos(config)# set interface eth1 lldp-location civic element 3 value Paris
nos(config)# set interface eth1 lldp-location coordinate latitude 48.8566
nos(config)# set interface eth1 lldp-location coordinate longitude 2.3522
```

Check with `show config`. The commit is refused when:

- an interface names a profile that does not exist, or a profile is deleted while one still uses it;
- `lldp-location` is set without an `lldp-med-profile` on the same interface;
- LLDP-MED is set on a loopback;
- a policy has `tagged` without a `vlan`, a VLAN above 4094, a priority above 7, a DSCP above 63, or twice the same application type;
- the ELIN is not 10 to 25 digits, the civic country is not two uppercase letters, the civic address is over 250 bytes encoded, or a coordinate is out of range.

## How LLDP behaves

**Physical interfaces only.** LLDP describes a physical link, so it can be enabled on a physical interface, including a port-aggregate member, but not on a loopback (refused at commit) and not on a subinterface or on the aggregate itself.

**Neighbours.** A neighbour is identified by its chassis ID and port ID, so one device heard on two of our ports shows as two neighbours. Each entry is kept for the time to live its sender advertised, counting down in `show lldp neighbors` (`ttl`); every new frame from the neighbour restarts the count. NOS keeps at most 32 neighbours per interface: known neighbours keep refreshing, a new one is refused and counted in `too many neighbors`, and NOS logs `lldp neighbor table full, dropping new neighbor` as a warning once until the table has room again. Frames that NOS itself sent, looped back by a cable or a mirror port, are ignored.

**Shutdown.** When transmit stops on an interface (you delete `lldp transmit`, remove the interface, or the router shuts down), NOS sends a last frame with a time to live of zero, so the neighbour removes this router at once instead of waiting for the entry to expire. Turning receive off forgets the neighbours heard on that interface.

**Link down.** When an interface loses carrier or is set admin-down, NOS forgets every neighbour heard on it at once (IEEE 802.1AB-2016 §9.2.7.1, portEnabled false) and logs `lldp neighbors flushed`, instead of showing them until their time to live runs out. The listening socket is kept, so neighbours are learned again as soon as the link returns. A device that disappears altogether also clears them.

**Fast start.** When LLDP starts on an interface (including any restart after a settings change) and whenever NOS hears a neighbour it did not know, it sends 4 frames one second apart before going back to `tx-interval`. Two routers learn each other within seconds of the link coming up, even if the first frame is lost. At most 5 frames go out back to back, with one more allowed per second, so a flapping neighbour cannot make NOS flood the link. These numbers are the IEEE 802.1AB defaults and cannot be changed.

**Timers.** `tx-interval` is the time between frames (1-3600 seconds, default 30). `tx-hold` is how many intervals a neighbour keeps our information (1-100, default 4); the time to live we advertise is `tx-interval × tx-hold`, which must not exceed 65535 seconds. Changing either, or the management addresses, restarts LLDP on every enabled interface: a shutdown frame, then a fresh one, so neighbours briefly drop and relearn this router.

**Log volume.** NOS logs `lldp neighbor learned` and `lldp neighbor removed` at info level, at most 5 in a row per interface, then one more every 10 seconds. Beyond that they are logged at debug level with the same fields. The neighbour table and the counters are not affected, so a flapping neighbour cannot flood the log.

**Management addresses.** Up to four IPv4 or IPv6 unicast addresses, each sent in its own field on every interface. NOS sends them as configured and does not check them at commit. When it sends a frame, it looks up the interface that carries each address. If it finds one, the field carries that interface's ifIndex. If not, the field says the interface is unknown. So an address added to an interface later gets its ifIndex on the next frame, with no restart. NOS also keeps at most four management addresses from each neighbour frame.

**Destination groups.** LLDP frames go to one of three reserved multicast addresses, which decide how far a frame travels through intermediate bridges:

- `nearest-bridge` (`01:80:C2:00:00:0E`, the default): reaches only the device at the other end of the cable; no bridge forwards it. The usual choice.
- `non-tpmr` (`01:80:C2:00:00:03`, "nearest non-TPMR bridge"): passes through two-port MAC relays (TPMRs), and stops at the first real bridge.
- `customer-bridge` (`01:80:C2:00:00:00`, "nearest customer bridge"): also passes through provider (S-VLAN) bridges, and stops at the first customer bridge.

An interface sends and listens on one group only, so both ends must be configured with the same group or they will never see each other.

### Verification notes

The examples were run on the lab of the [README](../README.md#conventions-used-in-these-pages), with `eth1` added as a veth pair directly between router-a and router-b. LLDP frames are never forwarded by a bridge, including a Docker network, so two containers can only hear each other over a direct link.

## Configuration reference

Every REST path starts with `/v1/transactions/{tx}/`. The relative CLI forms are what you type after `edit interface <if>`.

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| transmit | `set interface <if> lldp transmit` / `set lldp transmit`; `delete interface <if> lldp transmit` / `delete lldp transmit` | `interface/<if>/lldp-transmit` | boolean, default off | physical interface only | sends LLDP frames on the interface | the neighbour's `show lldp neighbors` |
| receive | `set interface <if> lldp receive` / `set lldp receive`; `delete … lldp receive` | `interface/<if>/lldp-receive` | boolean, default off | physical interface only | records neighbours heard on the interface | `show lldp neighbors` |
| destination | `set interface <if> lldp destination nearest-bridge\|non-tpmr\|customer-bridge` / `set lldp destination …`; `delete … lldp destination` | `interface/<if>/lldp-destination`, body `"NearestBridge"`, `"NonTpmr"` or `"CustomerBridge"` | default `nearest-bridge` | physical interface only | the multicast group sent to and listened on | `show config` |
| tx-interval | `set lldp tx-interval <secs>`; `delete lldp tx-interval` | `lldp/tx-interval-secs` | 1-3600 seconds, default 30 | range; `tx-interval × tx-hold` ≤ 65535 | time between frames, on every interface | the neighbour's `show lldp neighbors` (`ttl`) |
| tx-hold | `set lldp tx-hold <n>`; `delete lldp tx-hold` | `lldp/tx-hold` | 1-100, default 4 | range; as above | advertised time to live = `tx-interval × tx-hold` | the neighbour's `show lldp neighbors` (`ttl`) |
| management-address | `set lldp management-address <ip>` adds one; `delete lldp management-address <ip>` removes one | `lldp/management-address`, a list | up to 4 IPv4 or IPv6 addresses, default none | unicast (not unspecified, not multicast), no duplicates, at most 4 | each advertised on every interface, with its interface's ifIndex when one carries it | the neighbour's `show lldp neighbors` (`management`) |

| lldp-med-profile (interface) | `set interface <if> lldp-med-profile <name>`; `delete interface <if> lldp-med-profile` | `interface/<if>/lldp-med-profile` | profile name, default none | the profile exists; physical interface only | none yet (#1572) | `show config` |
| lldp-location | `set interface <if> lldp-location elin <digits>`, `civic …`, `coordinate …`; `delete interface <if> lldp-location elin` | `interface/<if>/lldp-location` | ELIN, civic address and/or coordinates, default none | needs an `lldp-med-profile` on the interface; ELIN 10-25 digits; civic at most 250 bytes; latitude -90 to 90, longitude -180 to 180 | none yet (#1572) | `show config` |
| lldp-med-profile | `edit lldp-med-profile <name>`; `delete lldp-med-profile <name>` | `lldp-med-profile/<name>` | `network-policy` (at most 8), `poe`, `advertise-always` | name 1-64 characters, unique; policy and PoE ranges as above | none yet (#1572) | `show config` |
| system-description | `set lldp system-description <text>`; `delete lldp system-description` | `lldp/system-description` | text, 1-255 bytes, default `nos` | not empty, at most 255 bytes, no control characters | the System Description field of every frame | the neighbour's `show lldp neighbors detail` (`system-description`) |

`tx-interval`, `tx-hold`, `management-address` and `system-description` are system-wide: they are typed the same way from anywhere in configuration mode.

Implementation notes for developers are in [`docs/internals/lldp.md`](../internals/lldp.md).
