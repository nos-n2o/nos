# L2 switching: broadcast domains, switching profiles and SVIs

This page covers bridging: grouping ports into layer-2 domains, trunking VLANs into them, and routing in and out of a domain through an SVI. Layer-3 interfaces are on [Interfaces](interfaces.md), and bonds on [Port aggregation and LACP](port-aggregation-lacp.md). Extending a domain across routers over VXLAN (the `vni`, `rd`, `route-target`, `vtep-source` and `redistribute` settings of a broadcast domain) is covered with EVPN, not here.

- [The model](#the-model)
- [Common operations](#common-operations)
- [How switching behaves](#how-switching-behaves)
- [Configuration reference](#configuration-reference)

## The model

Three objects work together:

- A **broadcast domain** is one layer-2 segment: one MAC learning table, one flooding scope. NOS builds each domain as its own bridge on the router. A domain has a name and nothing else is required.
- A **switching profile** is a trunk definition: a list of broadcast domains, each with the VLAN tag it uses on the wire, either `dot1q <1-4094>` or `untagged`. A profile can carry many domains, but each domain at most once.
- An **interface** (or a port aggregate) joins domains by pointing at one switching profile. Several interfaces can share the same profile.

The tag is local to the interface. Two interfaces can carry the same domain with different tags, for example VLAN 100 on `eth1` and VLAN 700 on `eth2`, by using two profiles: both still land in the same domain. That is how NOS translates VLANs between ports.

A broadcast domain can also have its own addresses and routing table. This makes the domain's bridge a routed interface, an **SVI** (switch virtual interface): hosts in the domain use the SVI address as their gateway, and the SVI's subnet appears in the routing table as a connected route. The SVI is independent of the ports in the domain, which do not need, and must not have, layer-3 configuration of their own for the tags they bridge.

## Common operations

The examples use router-a from the lab described in the [README](../README.md#conventions-used-in-these-pages). Its `eth0.0` (untagged) is already routed in `rt1`, so `eth0` can still trunk tagged VLANs.

### Trunk two VLANs into two domains

```
router-a> configure trunk
router-a(trunk)> edit broadcast domain bd1
router-a(trunk/broadcast-domain:bd1)> top
router-a(trunk)> edit broadcast domain bd2
router-a(trunk/broadcast-domain:bd2)> top
router-a(trunk)> edit switching-profile sp1
router-a(trunk/switching-profile:sp1)> set broadcast-domain bd1 tag dot1q 100
router-a(trunk/switching-profile:sp1)> set broadcast-domain bd2 tag dot1q 200
router-a(trunk/switching-profile:sp1)> top
router-a(trunk)> set interface eth0 switching-profile sp1
router-a(trunk)> diff
  interface eth0:
-   switching-profile: unset
+   switching-profile: sp1
+ broadcast-domain bd1:
+   addresses: none
+   routing-table: unset
…
+ broadcast-domain bd2:
…
+ switching-profile sp1:
+   broadcast-domain bd1:
+     tag: dot1q 100
+   broadcast-domain bd2:
+     tag: dot1q 200
router-a(trunk)> commit
transaction 'trunk' committed
router-a> show interface eth0
interface eth0: address [none], routing-table unset, switching-profile sp1, mtu 1500
  subinterface 0: address [10.50.0.2/24], routing-table rt1, mtu 1500
router-a> show config
…
broadcast domain bd1
broadcast domain bd2
switching-profile sp1
  broadcast-domain bd1
    tag dot1q 100
  broadcast-domain bd2
    tag dot1q 200
…
```

`diff` lists the new broadcast domains and switching profile, and the change to `eth0`.

NOS creates one bridge per domain and the VLAN devices `eth0.100` and `eth0.200`, each attached to its domain's bridge. The absolute forms are `edit broadcast domain bd1`, `set switching-profile sp1 broadcast-domain bd1 tag dot1q 100` and `set interface eth0 switching-profile sp1`.

REST, in one transaction:

```sh
$ $C -X POST $B/v1/transactions/trunk
$ $C -X PUT -H 'Content-Type: application/json' -d '{"name":"bd1","addresses":[]}' \
    $B/v1/transactions/trunk/broadcast-domain/bd1
$ $C -X PUT -H 'Content-Type: application/json' -d '{"name":"bd2","addresses":[]}' \
    $B/v1/transactions/trunk/broadcast-domain/bd2
$ $C -X PUT -H 'Content-Type: application/json' \
    -d '{"name":"sp1","members":[{"broadcast_domain":"bd1","tag":{"Dot1q":100}},{"broadcast_domain":"bd2","tag":{"Dot1q":200}}]}' \
    $B/v1/transactions/trunk/switching-profile/sp1
$ $C -X PUT -H 'Content-Type: application/json' -d '"sp1"' \
    $B/v1/transactions/trunk/interface/eth0/switching-profile
$ $C -X POST $B/v1/transactions/trunk/commit
{"committed":"trunk"}
```

One member is changed on its own at `…/switching-profile/sp1/member/bd1` (the domain name is the key), with a body such as `{"broadcast_domain":"bd1","tag":{"Dot1q":150}}`, or `{"broadcast_domain":"bd1","tag":"Untagged"}`.

### Retag or remove a domain

`set switching-profile sp1 broadcast-domain bd1 tag dot1q 150` replaces bd1's tag: a domain is in a profile once, so setting it again retags it. `delete switching-profile sp1 broadcast-domain bd2` removes bd2 from the profile; NOS removes the matching VLAN device from every interface using the profile. `delete interface eth0 switching-profile` takes the interface out of all of its domains at once.

### Give a domain an SVI

```
router-a> configure svi
router-a(svi)> edit broadcast domain users
router-a(svi/broadcast-domain:users)> set address 198.51.100.1/24
router-a(svi/broadcast-domain:users)> set routing-table rt1
router-a(svi/broadcast-domain:users)> commit
transaction 'svi' committed
router-a> show route rt1
10.50.0.0/24
  * via 10.50.0.2 [connected]
198.51.100.0/24
  * via 198.51.100.1 [connected]
```

The SVI's subnet shows up as a connected route a few seconds after the commit.

REST:

```sh
$ $C -X POST $B/v1/transactions/svi
$ $C -X PUT -H 'Content-Type: application/json' \
    -d '{"name":"users","addresses":[{"address":"198.51.100.1/24","label":null}],"routing_table":"rt1"}' \
    $B/v1/transactions/svi/broadcast-domain/users
$ $C -X POST $B/v1/transactions/svi/commit
```

On an existing domain, the address list and the routing table are reachable on their own: `PUT …/broadcast-domain/users/address/198.51.100.1%2F24` with body `{"address":"198.51.100.1/24","label":null}`, and `PUT …/broadcast-domain/users/routing-table` with body `"rt1"`.

`delete broadcast domain users` removes the domain and its bridge. A switching profile that still names the domain makes the commit fail (`switching_profiles[0].members[0].broadcast_domain: referenced broadcast domain does not exist`), so remove it from the profiles first.

### Untagged members and subinterfaces

An `untagged` member bridges the interface itself, without a VLAN header. It uses tag 0, the same tag as the untagged subinterface `eth0.0`, so the two cannot coexist on one interface. On router-a, whose `eth0.0` is routed:

```
router-a> configure untag
router-a(untag)> set switching-profile sp1 broadcast-domain bd1 tag untagged
router-a(untag)> commit
error: nos-configd reported an error: validation failed:
interfaces: subinterface tag 0 conflicts with a switching-profile member using the same tag
 (transaction left open — fix and retry)
router-a(untag)> discard
transaction 'untag' discarded
```

The same rule applies to every tag: an interface cannot have both a subinterface `eth0.100` and a switching-profile member tagged `dot1q 100`. Pick which one the tag is for: routed (a subinterface) or bridged (a profile member).

## How switching behaves

- **One bridge per domain.** Each broadcast domain is its own bridge, created as soon as the domain exists in the configuration, even before any interface uses it, and deleted with it. Traffic in a domain never leaks into another one; routing between domains goes through their SVIs and a routing table.
- **Tagged members** get a VLAN device `<interface>.<tag>` that NOS creates and attaches to the domain's bridge. It is removed when the member, the profile or the interface's `switching-profile` goes away. An **untagged member** attaches the interface itself to the bridge.
- **Tags are checked at commit.** A `dot1q` tag must be 1-4094; a profile cannot list a domain twice; the domain must exist; and the tags a profile uses on an interface must not collide with that interface's subinterfaces (see above). A port aggregate member cannot have a switching profile; give the aggregate the profile instead (see [Port aggregation and LACP](port-aggregation-lacp.md)).
- **An SVI is an interface of its own.** It can carry any number of IPv4 and IPv6 addresses, belongs to one routing table, and its addresses appear as `connected` routes there. OSPF and OSPFv3 can run on it (`set broadcast domain <name> ospf <profile>`), which requires the SVI's routing table.
- **Nothing to show per domain yet.** `show interface <name>` shows which switching profile an interface uses and `show config` shows the domains and profiles; there is no MAC-table view for a plain domain (`show fdb` is for domains extended with EVPN).

## Configuration reference

Every REST path starts with `/v1/transactions/{tx}/`. The relative CLI form is what you type after `edit broadcast domain <bd>` or `edit switching-profile <sp>`.

### `broadcast domain <bd>`

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit broadcast domain <bd>`; `delete broadcast domain <bd>` | `broadcast-domain/<bd>` | string, 1-64 characters | unique; no profile may still reference a deleted domain | creates or deletes the domain's bridge | `show config` |
| address | `set broadcast domain <bd> address <cidr> [label <text>]` / `set address …`; `delete … address <cidr>` | `broadcast-domain/<bd>/address/<cidr, / as %2F>`, body `{"address":"<cidr>","label":null}` | IPv4 or IPv6 `addr/len`; list, default empty | no repeated address | addresses the SVI; the label is stored only | `show route <table>` |
| routing-table | `set broadcast domain <bd> routing-table <t>` / `set routing-table <t>`; `delete … routing-table` | `broadcast-domain/<bd>/routing-table` | name; default unset | table exists | puts the SVI in the table's VRF | `show route <t>` |
| ospf, ospfv3 | `set broadcast domain <bd> ospf <profile>` (relative: `set ospf <profile>`), `… ospfv3 <profile>` | `broadcast-domain/<bd>/ospf-profile`, `…/ospfv3-profile` | name; default unset | profile exists; needs `routing-table` | runs OSPF / OSPFv3 on the SVI | `show ospf neigh` |
| vni, rd, route-target, vtep-source, redistribute | `set broadcast domain <bd> vni …` etc. | `broadcast-domain/<bd>/vni` etc. | | | EVPN/VXLAN, documented with EVPN | `show fdb <bd>` |

### `switching-profile <sp>`

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit switching-profile <sp>`; `delete switching-profile <sp>` | `switching-profile/<sp>` | string, 1-64 characters | unique; no interface or aggregate may still reference a deleted profile | | `show config` |
| member | `set switching-profile <sp> broadcast-domain <bd> tag dot1q <1-4094>\|untagged` / `set broadcast-domain <bd> tag …`; `delete switching-profile <sp> broadcast-domain <bd>` / `delete broadcast-domain <bd>` | `switching-profile/<sp>/member/<bd>`, body `{"broadcast_domain":"<bd>","tag":{"Dot1q":<n>}}` or `…"tag":"Untagged"}` | list, default empty | domain exists; each domain once; tag 1-4094 | bridges the tag of every interface using the profile into the domain | `show interface <if>` |

### On an interface or port aggregate

| Field | CLI | REST path | Type, range, default | Validation at commit | Effect | Check with |
|---|---|---|---|---|---|---|
| switching-profile | `set interface <if> switching-profile <sp>` / `set port-aggregate <pa> switching-profile <sp>` / `set switching-profile <sp>`; `delete … switching-profile` | `interface/<if>/switching-profile`; `port-aggregate/<pa>/switching-profile` (see [Port aggregation](port-aggregation-lacp.md#configuration-reference)) | name; default unset | profile exists; its tags don't collide with the interface's subinterfaces; not on a port aggregate member | joins the profile's domains | `show interface <if>`, `show port-aggregate <pa>` |

Spanning tree settings for these objects (`stp-instance`, `stp-priority`, `stp-cost`, `stp-port-profile`) are in [Spanning tree](stp.md).

Implementation notes for developers are in [`docs/internals/interface.md`](../internals/interface.md).
