# Interfaces, subinterfaces and loopbacks

This page covers layer-3 interfaces: putting addresses on a physical interface or one of its VLANs, placing it in a routing table, setting its MTU, and giving a routing table a loopback. Bridging and VLAN trunking are on [L2 switching](l2-switching.md), bonds on [Port aggregation and LACP](port-aggregation-lacp.md), and LLDP on [LLDP](lldp.md).

- [What an interface is in NOS](#what-an-interface-is-in-nos)
- [Common operations](#common-operations)
- [How interfaces behave](#how-interfaces-behave)
- [Configuration reference](#configuration-reference)

## What an interface is in NOS

An `interface` in the configuration is one of two things:

- A **physical interface**, named exactly as the operating system names it (`eth0`, `eth1`, …). NOS does not create physical interfaces: the link must already exist on the router. Adding it to the configuration tells NOS to manage it: bring it up, apply its addresses and MTU, and attach it to its routing table.
- A **loopback**, named `loopback-<table>`, for example `loopback-rt1`. The name alone makes it a loopback, and says which routing table it belongs to. NOS creates the loopback device itself, and there is at most one per routing table. Loopbacks are the usual home for a router ID, a BGP source address or an EVPN VTEP address.

A physical interface carries its layer-3 configuration on **subinterfaces**, one per VLAN tag:

- Tag `0` is the untagged (native) part of the link. `eth0.0` is the interface itself, with no VLAN header.
- Tags `1` to `4094` are 802.1Q VLANs. `eth0.300` is VLAN 300 on `eth0`, and NOS creates the VLAN device for it.

Each subinterface has its own addresses and its own routing table, independently of the others. A loopback has no subinterfaces: its addresses and routing table sit directly on it.

Putting a subinterface or loopback in a routing table makes it a member of that table's VRF (see [Concepts: Routing tables are VRFs](../concepts.md#routing-tables-are-vrfs)). Its addresses then appear in the table as connected routes. An address without a routing table is applied to the interface, but belongs to no routing table.

## Common operations

The examples use router-a from the lab described in the [README](../README.md#conventions-used-in-these-pages), where `eth0.0` already has `10.50.0.2/24` in routing table `rt1`.

### Address a VLAN subinterface and put it in a routing table

```
router-a> configure vlan300
router-a(vlan300)> edit interface eth0.300
router-a(vlan300/interface:eth0/subinterface:300)> set address 192.0.2.1/24
router-a(vlan300/interface:eth0/subinterface:300)> set routing-table rt1
router-a(vlan300/interface:eth0/subinterface:300)> top
router-a(vlan300)> diff
  interface eth0:
+   subinterface 300:
+     addresses: 192.0.2.1/24
+     routing-table: rt1
+     ospf-profile: unset
router-a(vlan300)> commit
transaction 'vlan300' committed
router-a> show interface eth0
interface eth0: address [none], routing-table unset, switching-profile unset, mtu 1500
  subinterface 0: address [10.50.0.2/24], routing-table rt1, mtu 1500
  subinterface 300: address [192.0.2.1/24], routing-table rt1, mtu 1500
router-a> show route rt1
10.50.0.0/24
  * via 10.50.0.2 [connected]
192.0.2.0/24
  * via 192.0.2.1 [connected]
```

`edit interface eth0.300` creates the subinterface (and the interface, if it is new). The absolute form does the same in one line per field: `set interface eth0.300 address 192.0.2.1/24` and `set interface eth0.300 routing-table rt1`. Without a `.<tag>`, an address or routing-table command applies to the untagged subinterface: `set interface eth1 address 192.0.2.1/24` configures `eth1.0`.

Over REST, a subinterface that does not exist yet is created by `PUT`ting it whole:

```sh
$ $C -X POST $B/v1/transactions/vlan300
$ $C -X PUT -H 'Content-Type: application/json' \
    -d '{"tag":300,"addresses":[{"address":"192.0.2.1/24","label":null}],"routing_table":"rt1"}' \
    $B/v1/transactions/vlan300/interface/eth0/subinterface/300
{"addresses":[{"address":"192.0.2.1/24","label":null}],"ospf_profile":null,"ospfv3_profiles":[],"routing_table":"rt1","tag":300}
$ $C -X POST $B/v1/transactions/vlan300/commit
{"committed":"vlan300"}
$ $C $B/v1/interfaces/eth0 | jq -c '.subinterfaces[]'
{"tag":0,"addresses":[{"address":"10.50.0.2/24","label":null}],"routing_table":"rt1","link_local_address":"fe80::306e:68ff:fed3:69b8"}
{"tag":300,"addresses":[{"address":"192.0.2.1/24","label":null}],"routing_table":"rt1","link_local_address":"fe80::306e:68ff:fed3:69b8"}
```

Once the subinterface exists, one address is added or removed by its own URL: `PUT …/interface/eth0/subinterface/300/address/198.51.100.1%2F24` with body `{"address":"198.51.100.1/24","label":null}`, and `DELETE` on the same URL.

### Remove a subinterface

```
router-a> configure novlan
router-a(novlan)> delete interface eth0.300
router-a(novlan)> commit
transaction 'novlan' committed
```

REST: `DELETE $B/v1/transactions/novlan/interface/eth0/subinterface/300`, then commit. NOS deletes the VLAN device. `delete interface eth0` (no tag) removes the whole interface from the configuration: NOS then removes the addresses, VLAN devices and routing-table membership it had applied, and stops managing the link.

### Add a loopback to a routing table

```
router-a> configure lo
router-a(lo)> edit interface loopback-rt1
router-a(lo/interface:loopback-rt1)> set address 203.0.113.1/32
router-a(lo/interface:loopback-rt1)> set routing-table rt1
router-a(lo/interface:loopback-rt1)> commit
transaction 'lo' committed
router-a> show interface loopback-rt1
interface loopback-rt1: address [203.0.113.1/32], routing-table rt1, switching-profile unset, mtu 1500
router-a> show route rt1 203.0.113.1
203.0.113.1/32
  * via 203.0.113.1 [connected]
```

The name alone puts the loopback in routing table `rt1`, which must exist when you commit, and lists its addresses as connected routes in `show route rt1`; `show interface` reports `routing-table rt1` even when the field is unset. Set `routing-table rt1` as well only to run OSPF or OSPFv3 on it: the commit refuses `ospf`/`ospfv3` without it. You can add several addresses, IPv4 and IPv6. The loopback device NOS creates is named after the routing table's kernel table number (`lo100` for the first routing table), not after `loopback-rt1`; you only need that name when looking at the router with Linux tools.

REST:

```sh
$ $C -X PUT -H 'Content-Type: application/json' \
    -d '{"name":"loopback-rt1","addresses":[{"address":"203.0.113.1/32","label":null}],"routing_table":"rt1","subinterfaces":[]}' \
    $B/v1/transactions/lo/interface/loopback-rt1
$ $C -X POST $B/v1/transactions/lo/commit
```

Deleting it (`delete interface loopback-rt1`, or `DELETE …/interface/loopback-rt1`) deletes the loopback device.

### Set the MTU

```
router-a> configure jumbo
router-a(jumbo)> set interface eth0 mtu 9000
router-a(jumbo)> commit
transaction 'jumbo' committed
router-a> show interface eth0
interface eth0: address [none], routing-table unset, switching-profile unset, mtu 9000
  subinterface 0: address [10.50.0.2/24], routing-table rt1, mtu 9000
```

REST: `PUT $B/v1/transactions/jumbo/interface/eth0/mtu` with body `9000`, then commit.

The MTU belongs to the link, so it is set on `eth0`; a VLAN subinterface follows it by default.

- Override one VLAN sub-link with `set interface eth0.300 mtu 1400` (or `set mtu 1400` in `edit interface eth0.300`; REST: `PUT …/interface/eth0/subinterface/300/mtu`). `delete interface eth0.300 mtu` makes it follow the link again.
- The override must not exceed the link's MTU (1500 when unset), and tag 0 refuses it (that subinterface is the link itself: set `mtu` on `eth0`). The commit is rejected otherwise, including when lowering the link's MTU below an existing override.
- `show interface` and `GET /v1/interfaces/<name>` report each subinterface's effective `mtu` (override, else the link's). `nos-interfaced` applies it to the kernel sub-link on every resync, after changing the link's own MTU, so a sub-link created before the link was raised reaches the new value.

`delete interface eth0 mtu` (REST: `DELETE …/interface/eth0/mtu`) puts the link back to 1500.

An interface with no `mtu` is held at 1500, not left at whatever the link had:

- A link whose platform default is not 1500 (1450 on some VXLAN or overlay underlays, 9001 on some cloud NICs) drops to 1500 as soon as it is added to the configuration. Set `mtu` explicitly on such links.
- A port aggregate member is the exception: the bond sets its members' MTU, so set `mtu` on the port aggregate instead.

## How interfaces behave

**NOS owns what you configure, and only that.** Interfaces that are not in the configuration are left alone. On an interface that is, the configured addresses are the complete list: NOS adds the missing ones and removes any other address it finds, except IPv6 link-local addresses, which it never touches. A configured interface is always brought up. There is no `shutdown` for an interface.

**Names.** An interface name is 1 to 64 characters and cannot contain `.`, which is reserved for the `<interface>.<tag>` form. A name starting with `loopback-` is a loopback, and the rest of the name must be an existing routing table.

**Addresses.** A subinterface or loopback can carry any number of IPv4 and IPv6 addresses, written as `<address>/<prefix length>`. The same address cannot appear twice on one subinterface; this is checked at commit. `set … address <addr> label <label>` attaches a label to the address. The label is kept in the configuration and shown by `show this`, but it is not applied to the router's network stack yet. Setting the same address again with a different label, or without one, replaces the label.

**Routing tables.** Many interfaces, subinterfaces and loopbacks can be in the same routing table. The addresses of a subinterface (of an interface or a port aggregate) with a `routing-table`, and those of a loopback, show up in that table as `connected` routes (see `show route <table>`), a few seconds after the commit; BGP uses them to decide whether a next hop is reachable.

**What can share a link.** Linux lets each link, and each VLAN device, have only one master: a VRF, a bridge or a bond. The commit therefore refuses:

- a subinterface whose tag is also used by the interface's switching profile (an untagged member uses tag 0, a `dot1q <n>` member tag `n`; see [L2 switching](l2-switching.md#untagged-members-and-subinterfaces));
- an interface that is a member of a port aggregate and also has subinterfaces or a switching profile (see [Port aggregation and LACP](port-aggregation-lacp.md));
- `address`, `routing-table` or `ospf` set directly on a physical interface rather than on a subinterface. The CLI never does this (a bare `eth0` means `eth0.0`), but a REST body could.

**`show interface` shows the configuration NOS is applying,** not a live read of the kernel. Right after a commit, or while a routing table's VRF is still being created, the two can differ for a few seconds; NOS retries every 10 seconds until they match. `mtu` is the configured MTU, or `1500` when none is configured: the value NOS holds the link at.

**OSPF and OSPFv3** are enabled per subinterface or loopback with `set interface <name> ospf <profile>` and `set interface <name> ospfv3 <profile>`, which require a routing table on the same subinterface. They are covered with the OSPF configuration they refer to.

## Configuration reference

In the tables, `<if>` is a physical interface name, `<if>.<tag>` a subinterface, and `<lo>` a loopback name (`loopback-<table>`). Every REST path starts with `/v1/transactions/{tx}/`. The relative CLI form is the one you type after `edit interface <if>`, `edit interface <if>.<tag>` or `edit interface <lo>`. The `show` column says how to check the result; `show this` works everywhere in configuration mode.

### `interface <if>` (physical interface)

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit interface <if>`; `delete interface <if>` | `interface/<if>` | string, 1-64 characters | unique; no `.` | NOS starts or stops managing this link | `show interface` |
| mtu | `set interface <if> mtu <n>` / `set mtu <n>`; `delete interface <if> mtu` / `delete mtu` | `interface/<if>/mtu` | integer 68-65535; default 1500, enforced | range | sets the link's MTU, the default for every subinterface; not on a port aggregate member, whose bond sets it | `show interface <if>` |
| subinterface mtu | `set interface <if>.<tag> mtu <n>` / `set mtu <n>`; `delete interface <if>.<tag> mtu` | `interface/<if>/subinterface/<tag>/mtu` | integer 68-65535; default follows the link | range; not above the link's MTU; not on tag 0 | per-VLAN override, applied to the kernel sub-link | `show interface <if>` |
| switching-profile | `set interface <if> switching-profile <sp>` / `set switching-profile <sp>`; `delete … switching-profile` | `interface/<if>/switching-profile` | name; default unset | profile exists; tags disjoint from subinterfaces | see [L2 switching](l2-switching.md) | `show interface <if>` |
| port-aggregate | `set interface <if> port-aggregate <pa>` / `set port-aggregate <pa>`; `delete … port-aggregate` | `interface/<if>/port-aggregate` | name; default unset | aggregate exists; no subinterfaces or switching profile on the same interface | see [Port aggregation](port-aggregation-lacp.md) | `show lacp`, `show config` |
| lldp transmit, lldp receive, lldp destination | `set interface <if> lldp …` | `interface/<if>/lldp-transmit`, `…/lldp-receive`, `…/lldp-destination` | see [LLDP](lldp.md#configuration-reference) | | | `show lldp neighbors` |
| subinterface | `edit interface <if>.<tag>`; `delete interface <if>.<tag>` | `interface/<if>/subinterface/<tag>` | tag 0-4094 | unique tag per interface | tag 0 is the link itself; 1-4094 creates the VLAN device `<if>.<tag>` | `show interface <if>` |

### `interface <if>.<tag>` (subinterface)

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| address | `set interface <if>[.<tag>] address <cidr> [label <text>]` / `set address <cidr> [label <text>]`; `delete … address <cidr>` | `interface/<if>/subinterface/<tag>/address/<cidr, / as %2F>`, body `{"address":"<cidr>","label":null}` | IPv4 or IPv6 `addr/len`; list, default empty | no repeated address | adds the address; the label is stored only | `show interface <if>`, `show route <table>` |
| routing-table | `set interface <if>[.<tag>] routing-table <t>` / `set routing-table <t>`; `delete … routing-table` | `interface/<if>/subinterface/<tag>/routing-table` | name; default unset | table exists | joins the table's VRF; addresses become connected routes | `show interface <if>`, `show route <t>` |
| ospf, ospfv3 | `set interface <if>[.<tag>] ospf <profile>`, `… ospfv3 <profile>`; `delete … ospf`, `… ospfv3 <profile>` (ospfv3 is a list: `set` adds, `delete <profile>` removes) | `interface/<if>/subinterface/<tag>/ospf-profile`, `…/ospfv3-profiles` | name; default unset | profile exists; needs a routing-table on the same subinterface | runs OSPF / OSPFv3 on it | `show ospf neigh`, `show ospfv3 neigh` |

### `interface <lo>` (loopback)

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit interface loopback-<table>`; `delete interface loopback-<table>` | `interface/loopback-<table>` | `loopback-` + a routing table name | the table exists; one loopback per table | creates or deletes the loopback device, in that table | `show interface <lo>` |
| address | `set interface <lo> address <cidr> [label <text>]` / `set address …`; `delete … address <cidr>` | `interface/<lo>/address/<cidr>` | as for a subinterface | no repeated address | as for a subinterface | `show interface <lo>`, `show route <table>` |
| routing-table | `set interface <lo> routing-table <table>` / `set routing-table <table>`; `delete … routing-table` | `interface/<lo>/routing-table` | name; default unset (the table in the name) | table exists | set it to the table in the name; only needed by `ospf`/`ospfv3` (the addresses are connected routes either way) | `show route <table>` |
| ospf, ospfv3 | `set interface <lo> ospf <profile>`, `… ospfv3 <profile>` | `interface/<lo>/ospf-profile`, `…/ospfv3-profiles` | name; default unset | profile exists; needs `routing-table` | advertises the loopback in OSPF / OSPFv3 | `show ospf database` |
| mtu | `set interface <lo> mtu <n>` / `set mtu <n>`; `delete … mtu` | `interface/<lo>/mtu` | as for a physical interface (default 1500, enforced) | | | `show interface <lo>` |

A loopback cannot have subinterfaces, a switching profile, a port aggregate or LLDP.

Implementation notes for developers are in [`docs/internals/interface.md`](../internals/interface.md).
