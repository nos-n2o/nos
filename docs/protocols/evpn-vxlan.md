# EVPN and VXLAN

EVPN (RFC 7432) extends a layer-2 broadcast domain across a routed network. Each router (a PE, or VTEP) carries the domain's Ethernet frames inside VXLAN tunnels (RFC 7348) to the other routers that have the same domain, and uses BGP to tell them which MAC addresses sit behind it. NOS implements EVPN over VXLAN as described in RFC 8365, including multi-homing: one customer device attached to two routers at once.

- [What it is for](#what-it-is-for)
- [Before you start](#before-you-start)
- [Common operations](#common-operations)
  - [Enable EVPN on a BGP session](#enable-evpn-on-a-bgp-session)
  - [Stretch a broadcast domain over VXLAN](#stretch-a-broadcast-domain-over-vxlan)
  - [Also advertise IP addresses](#also-advertise-ip-addresses)
  - [Check what was learned](#check-what-was-learned)
  - [Multi-home a customer device (Ethernet Segments)](#multi-home-a-customer-device-ethernet-segments)
  - [Route between subnets over EVPN (IP-VRF, Type 5)](#route-between-subnets-over-evpn-ip-vrf-type-5)
  - [Turn EVPN off](#turn-evpn-off)
- [How EVPN behaves](#how-evpn-behaves)
- [Configuration reference](#configuration-reference)

The examples use the `$B`/`$C` variables from [The REST API](../api.md#a-complete-session-with-curl) and the two-router lab from the [README](../README.md#conventions-used-in-these-pages): router-a (`10.50.0.2`, AS 65001, BGP instance `r1` in routing table `rt1`) peers with router-b (`10.50.0.3`, AS 65002) through peer-group `pg1`.

## What it is for

Without EVPN, a broadcast domain in NOS is a bridge local to one router: the interfaces trunked into it can talk to each other and nothing else. With EVPN, the same domain exists on several routers and behaves as one LAN:

- Hosts in the domain on router-a reach hosts in the domain on router-b at layer 2, over an IP network between the routers (the **underlay**). The underlay only needs to route between the routers' tunnel addresses.
- Each router learns MAC addresses on its own ports as a normal switch does, and advertises them in BGP. The other routers install them directly, so unicast frames go straight to the right router instead of being flooded.
- Broadcast, unknown-unicast and multicast frames (BUM) are copied to every router that has the domain (ingress replication). There is no multicast in the underlay.
- A customer device can be connected to two routers with one bond. Both routers know they share it, and they make sure it receives each flooded frame only once.

A **VNI** (VXLAN Network Identifier, 1 to 16777215) names the domain on the wire. Routers that should share a domain use the same VNI. **Route targets** decide which routers accept whose MAC addresses, and a **route distinguisher** keeps each router's routes apart in BGP.

## Before you start

EVPN builds on three things configured elsewhere:

- **A broadcast domain with ports.** Interfaces, VLAN tags and port aggregates join a domain through a switching profile; see the L2 switching guide. The examples below use a domain `bd100`. EVPN works on a domain that has no local ports yet, but it then has nothing to advertise except itself.
- **A BGP session between the routers.** Any BGP instance and peer-group will do, eBGP or iBGP; the examples reuse `r1` and `pg1`. EVPN routes are not passed through routing policies, so the peer-group's `import-policy` and `export-policy` do not affect them.
- **A tunnel address** on each router, reachable from the others through the underlay: an interface address, or the routing table's loopback. The examples use each router's `eth0` address.

When the tunnel address is in a routing table (it always is in NOS: there is no default VRF), Linux only delivers incoming VXLAN packets to the tunnel if the system setting `net.ipv4.udp_l3mdev_accept` is `1`. NOS does not change system settings, so set it yourself on the router's network namespace. With Docker Compose:

```yaml
services:
  watchdog:
    sysctls:
      - net.ipv4.udp_l3mdev_accept=1
```

Without it, the control plane works (routes are exchanged and `show fdb` fills in), but frames arriving from other routers are dropped.

A multi-homed segment (see below) also needs these kernel modules on the router's host: `cls_flower`, `cls_fw`, `act_skbedit`, `act_gact` and `sch_ingress` (`modprobe` them if your distribution does not load them on demand). Without them the router cannot set up local bias and falls back to the DF-only behaviour: `show fdb` shows no `local-bias` on the segment and `nos-fdbd` logs `local bias unavailable, df-only flooding`.

## Common operations

### Enable EVPN on a BGP session

Add the `l2vpn-evpn` address family to the peer-group on both routers. The session restarts to negotiate it:

```
lab-1> configure evpn
lab-1(evpn)> set bgp instance r1 peer-group pg1 address-family l2vpn-evpn
lab-1(evpn)> commit
transaction 'evpn' committed
```

The family is added to the ones already there, so the session keeps carrying unicast routes. Over REST, `PUT` the new element of the peer-group's `address-family` list:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"L2vpnEvpn"' \
   $B/v1/transactions/evpn/bgp-instance/r1/peer-group/pg1/address-family/L2vpnEvpn
```

`show config` then shows `address-family [ipv4, l2vpn-evpn]` on the peer-group.

### Stretch a broadcast domain over VXLAN

Give the domain a VNI, a route distinguisher, import and export route targets, a tunnel source, and name the BGP instance to advertise into. Do it on every router that has the domain, with the same VNI and matching route targets, and a route distinguisher unique to each router. On router-a:

```
lab-1> configure bd
lab-1(bd)> edit broadcast domain bd100
lab-1(bd/broadcast-domain:bd100)> set vni 10100
lab-1(bd/broadcast-domain:bd100)> set rd 65001:100
lab-1(bd/broadcast-domain:bd100)> set route-target import 65000:10100
lab-1(bd/broadcast-domain:bd100)> set route-target export 65000:10100
lab-1(bd/broadcast-domain:bd100)> set vtep-source interface eth0
lab-1(bd/broadcast-domain:bd100)> set redistribute from mac to bgp r1
lab-1(bd/broadcast-domain:bd100)> commit
transaction 'bd' committed
```

On router-b, the same with `rd 65002:100`. Each command also has an absolute form that works from anywhere in the transaction, for example `set broadcast domain bd100 vni 10100`.

Over REST, the EVPN fields are fields of the broadcast domain. Here the whole domain is written in one `PUT`:

```sh
$C -X POST "$B/v1/transactions/bd?base=current"
$C -X PUT -H 'Content-Type: application/json' -d '{
  "name": "bd100", "addresses": [], "routing_table": null,
  "ospf_profile": null, "ospfv3_profiles": [],
  "vni": 10100, "rd": "65001:100",
  "route_targets_import": ["65000:10100"], "route_targets_export": ["65000:10100"],
  "vtep_source": {"Interface": {"interface": "eth0", "label": null}},
  "mac_redistribute": "r1", "arp_redistribute": null, "connected_redistribute": null
}' $B/v1/transactions/bd/broadcast-domain/bd100
$C -X POST $B/v1/transactions/bd/commit
```

Each field also has its own path, for example `PUT …/broadcast-domain/bd100/vni` with body `10100`, or `PUT …/broadcast-domain/bd100/route-targets-import/65000:10100` with body `"65000:10100"` to add one route target.

What each setting does:

- `vni` turns EVPN on for the domain: the router creates the VXLAN tunnel in the domain's bridge. Every other EVPN setting requires it.
- `rd` is written `<asn>:<n>` or `<ipv4>:<n>`. It is attached to every route the domain advertises.
- `route-target import <rt>` (repeatable): a route received for this domain is used only if it carries at least one of these. `route-target export <rt>` (repeatable): attached to every route the domain advertises. Using one route target per domain, identical on all routers, is the simplest scheme.
- `vtep-source interface <name>` sources the tunnels from that interface's address; add `label <label>` to pick one address when the interface has several. `vtep-source loopback` uses the loopback of the routing table that owns the BGP instance (`loopback-rt1` for `r1`). This address is also the BGP next hop of every route the domain advertises, so the other routers must be able to reach it.
- `redistribute from mac to bgp <instance>` advertises the domain into that BGP instance, and installs the EVPN routes that instance receives. It needs `rd` and `vtep-source`.

Once committed, the domain advertises itself to the other routers (an Inclusive Multicast route, Type 3), and each router adds the others to its flood list:

```
lab-1> show fdb bd100
broadcast-domain bd100: vni 10100, bridge br1, vxlan vx10100
  no MAC addresses
  flood list: 10.50.0.3
```

`bridge` and `vxlan` are the Linux devices of the domain; the bridge number is allocated by the router.

From then on, every MAC address the bridge learns on a local port is advertised as a MAC route (Type 2), and withdrawn when the bridge forgets it.

### Filter received EVPN routes (trust model)

By default every EVPN route a peer sends is accepted and stored; `nos-fdbd` then keeps only those carrying one of the domain's import route targets. To drop routes earlier, point the peer-group at a routing policy:

```
edge-1(t1/bgp-instance:r1/peer-group:pg-evpn)> set evpn-import-policy only-tenant-a
```

- The policy is an ordinary [RPL](routing-policy.md) policy. Match route targets with `this.bgp.extended_communities.contains(<rt>)`; a two-octet-AS route target `65000:10000` is the extended community `0:2:279172874250000` (the AS times 2^32 plus the number). Aliases and groups work too.
- Example policy: `if this.bgp.extended_communities.contains(0:2:279172874250000):` then `accept`, else `reject`. The same RT can be written `rt(65000:10000)` ([Values](routing-policy.md#values)).
- Applies to Type-1, 2, 3 and 5. A rejected route is treated like a withdrawal: it is not stored, not given to `nos-fdbd`, and `nos-bgpd` logs `evpn route rejected by import policy`.
- Type-4 (Ethernet Segment) routes are never filtered by this policy: their route target is the ES-Import one, so an RT match would reject all of them. `nos-fdbd` applies the ES-Import check itself (below).
- Only accept/reject counts; attribute rewrites are ignored. `this.prefix` is the Type-5 prefix, `0.0.0.0/0` for the other types.
- With [soft reconfiguration inbound](bgp.md#keeping-received-routes-soft-reconfiguration-inbound) on the peer-group, changing this policy is applied in place (no session reset): the routes it rejects are kept aside, so loosening it brings them back without a refresh. `nos-bgpd` logs `re-evaluated import policy peer=… family=l2vpn-evpn`. Type-4 routes are exempt, and MAC mobility only ever sees accepted routes. The kept-aside routes are dropped when the session ends.
- Unset means accept everything (unlike `import-policy`, which defaults to `deny-all`), so existing EVPN setups keep working.
- Changing the policy restarts the peer's sessions; routes stored from before are re-checked against the new policy.
- MAC mobility (RFC 7432 section 15) is the defense against a peer claiming a MAC you own: `nos-bgpd` arbitrates by sequence number, a rejected Type-2 never takes part, and a MAC that moves too often is frozen on its last holder.

### Limit what a peer can install

- `set max-remote-macs <n>` on the broadcast domain (at least 1, needs a `vni`; `delete` lifts it) caps the remote MAC entries `nos-fdbd` installs from received Type-2 routes.
- Beyond the cap the lowest MAC addresses win, whatever order the routes arrived in: a lower MAC arriving later evicts a higher one. `nos-fdbd` logs `remote mac ceiling reached` once per crossing.
- Only remote MAC entries count: not neighbours (IP bindings), flood entries, or MACs pinned to one of our own segments.
- A remote Type-2 for a MAC learned locally is still installed (bgpd's MAC mobility arbitrates and freezes a MAC that moves too often); the cap bounds the damage a peer can do.
- Type-1/Type-4 ES check: `nos-fdbd` counts a Type-4 for the single-active backup choice (below) only when it carries that segment's ES-Import route target (RFC 7432 section 7.6), for any segment, attached or not. The DF election of a segment this domain is attached to matches Type-4s on the exact ESI and never reads another segment's, and ignores a Type-4 without that ESI's ES-Import route target (warning `evpn type-4 ignored, es-import rt mismatch`, once per change; #1521).

### Also advertise IP addresses

Two optional rules add IP addresses to the MAC routes. Both must name the same BGP instance as `redistribute from mac`:

- `redistribute from arp to bgp <instance>` advertises the IPv4 ARP and IPv6 neighbour entries the router holds for hosts on the domain's local ports, as MAC+IP routes. Receiving routers install them as neighbour entries on their own bridge, so they can reach those hosts without resolving them first.
- `redistribute from connected to bgp <instance>` advertises the domain's own addresses (its SVI), with the bridge's MAC address, marked as a default gateway.

```
lab-1(bd)> set broadcast domain bd100 address 203.0.113.1/24
lab-1(bd)> set broadcast domain bd100 routing-table rt1
lab-1(bd)> set broadcast domain bd100 redistribute from arp to bgp r1
lab-1(bd)> set broadcast domain bd100 redistribute from connected to bgp r1
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"r1"' $B/v1/transactions/bd/broadcast-domain/bd100/arp-redistribute
$C -X PUT -H 'Content-Type: application/json' -d '"r1"' $B/v1/transactions/bd/broadcast-domain/bd100/connected-redistribute
```

Link-local, loopback and multicast addresses are never advertised.

### Check what was learned

`show bgp evpn` lists every EVPN route each BGP instance has received, with the peer it came from, its next hop, the route itself and its extended communities:

```
lab-1> show bgp evpn
bgp instance r1:
  from 10.50.0.3 next-hop 10.50.0.3 [3]:[65002:100]:[0]:[10.50.0.3] [RT:65000:10100 encap:8]
```

The route is shown in the usual bracketed EVPN notation, starting with its type:

- `[2]:[<rd>]:[<esi>]:[<tag>]:[48]:[<mac>]:[<ip>]:[<vni>]`: a MAC address (and, with `arp`/`connected`, its IP) behind the sending router. The ESI is all zeros unless the MAC sits behind a multi-homed bond.
- `[3]:[<rd>]:[<tag>]:[<address>]`: the sending router has the domain; the address is its tunnel address.
- `[4]:…`: the sending router is attached to an Ethernet Segment.
- `[1]:…`: an Ethernet A-D route, per segment or per domain, used for multi-homing (below).

The communities in brackets: `RT:<rt>` is a route target, `encap:8` means VXLAN, `default-gw` marks an SVI address, `esi-label:all-active|single-active` gives a segment's redundancy mode, and `0x06…` is the MAC Mobility community.

`show fdb <domain>` shows what the domain actually uses: its bridge and tunnel device, every MAC address with where it is (`local`, or `remote via <router>`), the IP neighbours, the flood list, and each Ethernet Segment:

```
lab-2> show fdb bd100
broadcast-domain bd100: vni 10100, bridge br1, vxlan vx10100
  ea:f3:14:7e:69:3f remote via 10.50.0.2
  203.0.113.1 is at ea:f3:14:7e:69:3f remote via 10.50.0.2
  203.0.113.2 is at ee:59:ae:e9:f1:74 local
  flood list: 10.50.0.2
lab-2> show bgp evpn
bgp instance r1:
  from 10.50.0.2 next-hop 10.50.0.2 [2]:[65001:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[48]:[ea:f3:14:7e:69:3f]:[203.0.113.1]:[10100] [RT:65000:10100 encap:8 default-gw 0x0600000000000000]
  from 10.50.0.2 next-hop 10.50.0.2 [3]:[65001:100]:[0]:[10.50.0.2] [RT:65000:10100 encap:8]
```

`show bgp evpn` also prints `local-pref <n> communities [<names>]` per route; a PE announcing RFC 8326 GRACEFUL_SHUTDOWN shows `local-pref 0 communities [graceful-shutdown]` and loses to a PE on the same ESI that does not.

Here router-b (with `address 203.0.113.2/24` and both rules on its own `bd100`) has learned router-a's SVI: its MAC, and its address as a neighbour entry.

A remote route is used only if it carries one of the domain's import route targets, names the domain's VNI and does not come from the router itself; the others appear in `show bgp evpn` but not in `show fdb`. Over REST these are `GET /v1/bgp/evpn` and `GET /v1/fdb/{domain}`:

```sh
$ $C $B/v1/fdb/bd100 | jq -c '{vni, flood, macs: [.macs[] | {mac, source, vtep}]}'
{"vni":10100,"flood":["10.50.0.2"],"macs":[{"mac":"ea:f3:14:7e:69:3f","source":"Remote","vtep":"10.50.0.2"}]}
```

### Multi-home a customer device (Ethernet Segments)

A customer device (CE) can be connected to two or more routers with one bond, for redundancy or capacity. On the NOS side, each router has a port aggregate towards the CE, trunked into the EVPN domain. Giving those port aggregates the same **ESI** (Ethernet Segment Identifier) tells the routers they are one Ethernet Segment. On router-a, with the CE on `eth1`:

```
lab-1> configure es
lab-1(es)> edit switching-profile sp-evpn
lab-1(es/switching-profile:sp-evpn)> set broadcast-domain bd100 tag untagged
lab-1(es/switching-profile:sp-evpn)> top
lab-1(es)> edit port-aggregate bond1
lab-1(es/port-aggregate:bond1)> set esi 00:11:22:33:44:55:66:77:88:99
lab-1(es/port-aggregate:bond1)> set switching-profile sp-evpn
lab-1(es/port-aggregate:bond1)> top
lab-1(es)> edit interface eth1
lab-1(es/interface:eth1)> set port-aggregate bond1
lab-1(es/interface:eth1)> top
lab-1(es)> commit
```

Over REST, the switching profile is the port aggregate's `switching-profile` field:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"sp-evpn"' \
   $B/v1/transactions/es/port-aggregate/bond1/switching-profile
```

Router-b gets the same configuration with the same ESI. The ESI is ten colon-separated hexadecimal bytes, not all zero, and unique per router: two port aggregates on one router cannot share it. The port aggregate can be static (`xor`) or LACP; with LACP, give both routers the same `lacp-system-id` so the CE sees one partner and bundles its links across them (see the port aggregation guide).

With the segment configured, `show fdb` lists it on each router, with its bond and its state:

```
lab-1> show fdb bd100
broadcast-domain bd100: vni 10100, bridge br1, vxlan vx10100
  ee:59:ae:e9:f1:74 remote via 10.50.0.3
  203.0.113.1 is at 42:46:27:6c:ba:fb local
  203.0.113.2 is at ee:59:ae:e9:f1:74 remote via 10.50.0.3
  flood list: 10.50.0.3
  ethernet-segment 00:11:22:33:44:55:66:77:88:99 on bond1: down, no carrier (PEs 10.50.0.2)
```

The state is one of:

- `down, no carrier`: the bond has no working link (as above, in a lab where `eth1` is not cabled). The router does not advertise the segment and is never its DF.
- `designated forwarder`: this router sends flooded traffic to the CE.
- `non-designated forwarder, BUM blocked`: another router is the DF; this one still forwards unicast.
- `non-designated forwarder, port blocked`: the same in a single-active segment, where nothing is forwarded.

`PEs` lists the routers attached to the segment, in election order, and `per-ES A-D from` the other routers whose segment route is held.

**All-active and single-active.** By default a segment is **all-active**: every router forwards unicast traffic to and from the CE, and only the designated forwarder (DF) sends it flooded traffic. The CE can then use a load-balancing bond (`balance-xor`, or LACP). Set **single-active** when only one router at a time may carry the CE's traffic:

```
lab-1(es)> set port-aggregate bond1 redundancy-mode single-active
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"SingleActive"' $B/v1/transactions/es/port-aggregate/bond1/redundancy-mode
```

Set the same mode on every router of the segment. The non-DF routers then block their port to the CE entirely, and the segment line in `show fdb` ends with `single-active`:

```
  ethernet-segment 00:11:22:33:44:55:66:77:88:99 on bond1: down, no carrier (PEs 10.50.0.2), single-active
```

`show config` shows the whole EVPN setup of a router:

```
broadcast-domain bd100: address [203.0.113.1/24], routing-table rt1, ospf-profile unset, vni 10100, rd 65001:100, rt-import [65000:10100], rt-export [65000:10100], vtep-source interface eth0, redistribute-mac r1, redistribute-arp r1, redistribute-connected r1
switching-profile sp-evpn: members [bd100: untagged]
port-aggregate bond1: mode Xor, switching-profile sp-evpn, mtu unset, esi 00:11:22:33:44:55:66:77:88:99, redundancy-mode single-active
``` The blocked port keeps its link up, so the CE cannot see which router to use from the link state: it needs a bond that checks the path end to end, such as a Linux `active-backup` bond with an ARP monitor.

### Route between subnets over EVPN (IP-VRF, Type 5)

A routing table can be an **IP-VRF** stretched over EVPN: each router advertises the table's routes as IP prefix routes (Type 5, RFC 9136) and installs the ones the others advertise, routing the traffic over one VXLAN tunnel per table, its **L3 VNI**. This is the "interface-less" symmetric model of RFC 9135 §4.4.1: no broadcast domain is needed, and the subnets behind each router can all differ.

Before you start:

- The routers already peer with `address-family l2vpn-evpn` (above), in the **underlay** routing table (`rt1`, BGP instance `r1`).
- The IP-VRF is another routing table (`tenant` below) with the interfaces of its subnets in it. Its own `bgp-instance`, if any, is not used for EVPN.
- `net.ipv4.udp_l3mdev_accept=1` is set (see [Before you start](#before-you-start)), and so is `net.ipv4.ip_forward=1`, since the router now routes the tenant's traffic.

On router-a, with the tenant subnet `198.18.1.0/24` on `eth1`:

```
lab-1> configure l3
lab-1(l3)> set interface eth1 address 198.18.1.2/24
lab-1(l3)> set interface eth1 routing-table tenant
lab-1(l3)> edit routing-table tenant
lab-1(l3/routing-table:tenant)> set evpn l3-vni 5000
lab-1(l3/routing-table:tenant)> set evpn rd 65001:5000
lab-1(l3/routing-table:tenant)> set evpn route-target import 65000:5000
lab-1(l3/routing-table:tenant)> set evpn route-target export 65000:5000
lab-1(l3/routing-table:tenant)> set evpn vtep-source interface eth0
lab-1(l3/routing-table:tenant)> set evpn bgp-instance r1
lab-1(l3/routing-table:tenant)> commit
```

On router-b, the same with its own subnet and `rd 65002:5000`. Over REST, write the table's `evpn` object in one `PUT`:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{
  "l3_vni": 5000, "rd": "65001:5000",
  "route_targets_import": ["65000:5000"], "route_targets_export": ["65000:5000"],
  "vtep_source": {"Interface": {"interface": "eth0", "label": null}},
  "bgp_instance": "r1"
}' $B/v1/transactions/l3/routing-table/tenant/evpn
```

What happens:

- The table's `nos-ribd` creates a bridge `brv<l3-vni>` in the table's VRF and a VXLAN device `vx<l3-vni>` on it. The bridge's MAC address is the router's **Router's MAC**.
- Every best route of the table (connected subnets included, EVPN-learned ones excluded) is advertised into `bgp-instance` as a Type 5 route carrying the RD, the export route targets, the VXLAN encapsulation and the Router's MAC (`rmac:` in `show bgp evpn`). The next hop is the `vtep-source` address.
- A received Type 5 route is installed when it carries an import route target, names the table's L3 VNI and carries a Router's MAC. It becomes a route `via <remote VTEP> dev brv<l3-vni> onlink`, with a neighbour entry for the VTEP at its Router's MAC and a forwarding entry sending that MAC into the tunnel.

Check it with `show route`:

```
lab-1> show route tenant
198.18.1.0/24
  * via 198.18.1.2 [connected]
198.18.2.0/24
  * via 10.50.0.3 rmac 0a:1b:2c:3d:4e:5f vni 5000 [evpn]
```

EVPN routes rank below static, BGP and OSPF routes for the same prefix. To remove the IP-VRF, delete its `evpn` fields in one transaction (validation happens at commit): `delete routing-table tenant evpn l3-vni`, `… evpn rd`, `… evpn vtep-source`, `… evpn bgp-instance` and `… evpn route-target import|export <rt>`, or `DELETE` the same paths over REST. Its routes are withdrawn and the two devices deleted.

A broadcast domain whose SVI is in a routing table **without** an L3 VNI is routed the **asymmetric** way (RFC 9135 §4.1): give each router an address in the same broadcast domain (an SVI) and `redistribute from arp|connected`, and routing happens on the ingress router into the stretched domain.

### Route to hosts of a stretched subnet (symmetric IRB)

When a stretched broadcast domain's SVI is in an IP-VRF (a routing table with an `evpn l3-vni`), its hosts are also reached through the L3 VNI (symmetric IRB, RFC 9135 §4.2): routed traffic to a host behind another router crosses the IP-VRF's tunnel, never the domain's. There is no switch to turn on; the L3 VNI on the SVI's table is what does it.

Before you start:

- The IP-VRF works as in the section above.
- The domain has a `vni`, `redistribute from mac` and `redistribute from arp`, all into the instance named by the table's `evpn bgp-instance` (a different instance is refused at commit).
- Every router gives the SVI the same address (an anycast gateway).

On each router, with the IP-VRF `tenant` from above:

```
lab-1> configure irb
lab-1(irb)> edit broadcast domain bd300
lab-1(irb/broadcast-domain:bd300)> set address 198.18.3.1/24
lab-1(irb/broadcast-domain:bd300)> set routing-table tenant
lab-1(irb/broadcast-domain:bd300)> set redistribute from arp to bgp r1
lab-1(irb/broadcast-domain:bd300)> commit
```

(the domain's `vni`, `rd`, route targets, `vtep-source` and `redistribute from mac to bgp r1` as in [Stretch a broadcast domain over VXLAN](#stretch-a-broadcast-domain-over-vxlan)).

What happens:

- Each MAC+IP route a router advertises for a host it learned by ARP/ND carries the table's L3 VNI as a second label, the table's export route targets and its Router's MAC. The SVI's own address (`redistribute from connected`) does not: it is local on every router.
- A receiving router installs the host as a `/32` (or `/128`) route in the IP-VRF, `via <remote VTEP> dev brv<l3-vni> onlink`. It wins over the SVI's connected subnet by longest match, so routed traffic leaves over the L3 VNI; bridged traffic inside the subnet still uses the domain's VNI.
- Until the table's `nos-ribd` has built the IP-VRF, the routes go out without the second label (asymmetric), and are updated in place once it is up.

Check it:

- `show bgp evpn` on the receiving router lists the host's route with both labels, `…:[198.18.3.20]:[10300]:[5000]`, and `rmac:`.
- `show route tenant` lists `198.18.3.20/32 via <VTEP> rmac … vni 5000 [evpn]`.

### Constrain EVPN distribution (RT-Constraint)

- Add `address-family rt-constraint` next to `l2vpn-evpn` in the peer-group (commit refuses it alone); both sides must advertise it.
- The router then originates one RFC 4684 membership route per import Route Target of its broadcast domains and IP-VRFs (and of its VRFs, see [BGP](bgp.md)), and holds back its Type-1/2/3/5 routes from a peer until that peer's membership asks for their Route Targets (the default route asks for all).
- Ethernet Segment (Type-4) routes are never held back: their ES-Import Route Target is not a Route Target membership can ask for.
- Only locally originated routes are filtered (received EVPN routes are not re-advertised). Graceful restart keeps a restarting peer's memberships stale, so its routes are not withdrawn during the restart.

### Turn EVPN off

- `delete broadcast domain <domain> vni` stops EVPN for the domain and removes its tunnel. The other EVPN settings must be removed first (or in the same transaction, since validation happens at commit): `delete broadcast domain <domain> redistribute from mac` (also `from arp`, `from connected`), `delete broadcast domain <domain> vtep-source`, `delete broadcast domain <domain> rd` and `delete broadcast domain <domain> route-target import|export <rt>`.
- `delete port-aggregate <name> esi` takes a bond out of its Ethernet Segment; flooding to it resumes at once.
- `delete bgp instance r1 peer-group pg1 address-family l2vpn-evpn` stops exchanging EVPN routes on that session.

Over REST, `DELETE` the same paths: `…/broadcast-domain/bd100/vni`, `…/mac-redistribute`, `…/vtep-source`, `…/rd`, `…/route-targets-import/65000:10100`, `…/port-aggregate/bond1/esi`.

## How EVPN behaves

### Routes a domain advertises

For each domain with `redistribute from mac`, a router advertises:

- one **Inclusive Multicast route (Type 3)** for the domain, from its tunnel address. Receiving routers add that address to the domain's flood list.
- one **MAC route (Type 2)** per MAC address its bridge has learned on a local port, and with `arp`/`connected` one MAC+IP route per neighbour entry or SVI address. MAC addresses the bridge learned from the tunnel are never re-advertised.
- for each Ethernet Segment attached to the domain whose bond has link: an **Ethernet Segment route (Type 4)**, and two **Ethernet A-D routes (Type 1)**, one for the segment and one for the domain.

All carry the domain's export route targets and the VXLAN encapsulation community, with the tunnel address as BGP next hop. They are advertised to every peer whose peer-group has `l2vpn-evpn`.

EVPN routes a router receives are used, never passed on to other peers. So EVPN does not go through a route reflector or route server built with NOS: each router must peer with every other router that has the domain, or with a reflector that is not NOS.

### MAC mobility

When a host moves from one router to another, both may briefly advertise its MAC address. NOS follows RFC 7432 §15: each advertisement carries a sequence number in a MAC Mobility community, the highest number wins (on a tie, the router with the lower tunnel address), and a router that learns the MAC locally again advertises it with a higher number than the one it saw, so a real move always wins over a stale copy. A MAC address that changes router more than 5 times within 3 minutes is treated as a duplicate: NOS keeps its last location and ignores further moves until it has been quiet for 3 minutes.

A MAC address behind a multi-homed Ethernet Segment is not a move: every router on the segment advertises it with the same ESI, and they all keep their advertisement and share one sequence number. Only an advertisement behind a different ESI (or a single-homed one, ESI 0) competes as above.

### The designated forwarder

Among the routers attached to one Ethernet Segment, one per domain is the designated forwarder: it alone delivers flooded traffic *from other routers* to the CE, so the CE never receives a copy through each router. The candidates are the routers that advertise the segment. When every one of them announces the AC-DF capability (RFC 8584; NOS always does), only those that also serve the domain are candidates; otherwise every router on the segment is, as in RFC 7432. By default (`df-algorithm modulo`, RFC 7432 §8.5) the candidates are ordered by tunnel address and the DF for a domain is candidate number `VNI mod <number of candidates>`. Two domains on the same segment can therefore have different DFs, which spreads the load.

`set port-aggregate <p> df-algorithm hrw` asks for RFC 8584's Highest Random Weight election instead: each candidate gets a pseudo-random weight from its tunnel address, the VNI and the ESI, and the highest weight wins, which spreads domains more evenly and moves fewer of them when a router joins or leaves. The choice is announced in the segment's Type 4 route (`df-election:hrw,ac-df` in `show bgp evpn` on the peer), and HRW is only used when every candidate asks for it; if any router asks for something else or announces nothing (most other implementations), every router falls back to modulo. `show fdb` ends the segment line with `df-algorithm hrw` while HRW is in effect. HRW needs IPv4 tunnel addresses. Changing the algorithm on a live segment re-elects at once, without the wait below.

**Local bias.** In an all-active segment, flooded traffic that a router receives from its own hosts or from the CE goes straight to every segment it is on, whatever its DF role. The other routers on that segment drop their copy of it (RFC 8365 §8.3.1: they recognise it by the tunnel address it came from). Two consequences:

- A CE no longer receives its own broadcast back. The CE sends it on one link; the router it reaches floods it to the other routers, and the DF used to send it back out of the segment.
- A host behind a non-DF router still reaches the CE with its broadcasts, through that router.

`show fdb` ends the segment line with `local-bias` while it is in place. It does not apply to single-active segments, where the non-DF drops everything and the DF delivers what the other router received locally. NOS does it with Linux `tc` filters and packet marks on the domain's VXLAN device and the segment's bond; there is nothing to configure.

Upgrade both routers of a segment together. A router without local bias neither delivers locally sourced flooded traffic as a non-DF nor gets it delivered for it, so flooded traffic from the hosts behind it is lost until both run the new version.

A router that has just joined a segment, whether it just started, the ESI was just set or the bond just came up, waits 3 seconds before applying the election, blocked as a non-DF meanwhile. This gives it time to hear the other routers, so the CE never receives flooded traffic twice. The delay is a start-up option of the router (`--fdbd-arg=--df-wait=<seconds>` on `nos-watchdogd`), not configuration; see [System](system.md#start-up-options).

When a segment's bond loses its link, the router withdraws the segment's Type 4 and Type 1 routes, so the others re-elect without it. It rejoins, with the wait above, when the link returns.

### Traffic towards a segment this router is on

A CE's MAC address is often learned by only one of its routers: the CE sends on one link, the other router never sees it. Yet a remote router balances traffic over both (aliasing), so each must be able to deliver it:

- A MAC address another router advertises on one of this router's own segments is pinned to the segment's bond, as a static entry of the domain's bridge. `show fdb` lists it as `remote, on our esi <esi>`.
- It is pinned only while the bond can carry it: the bond has link, and in a single-active segment the router is the DF. Otherwise the MAC goes over the tunnel to the router that advertised it, like a MAC on a remote segment.
- A pinned MAC is not advertised until the CE sends through this router. From then on the router advertises it too, and stops when the CE has been silent for the bridge's ageing time (300 seconds).
- The bridge never learns MAC addresses from the tunnel: remote MACs come from EVPN routes only (RFC 7432 §9.2). A CE's broadcast that another router floods back here therefore cannot move the CE's MAC behind the tunnel.

### Failover and load sharing towards a remote segment

For a segment that is attached to other routers, not this one:

- A MAC address behind the segment is used only while the router that advertised it still advertises the segment's Type 1 route. When that router loses the segment, it withdraws one route and every one of its MAC addresses on the segment is dropped at once (mass withdrawal, RFC 7432 §8.2.1), instead of one by one.
- In an all-active segment served by several routers, traffic to a MAC address behind it is balanced across all of them, even those that did not advertise that MAC (aliasing, RFC 7432 §8.4). `show fdb` lists such a MAC as `remote via <router>, <router> (aliased)`. This applies to IPv4 tunnel addresses only.
- In a single-active segment, when the router that advertised a MAC address loses the segment, the MAC is moved to the next router that serves it (backup path).

### Limits

- Local bias covers flooded multicast and broadcast traffic only. Unknown unicast that a CE sends to one router is still flooded back to it by the DF (RFC 8365 §8.3.3), which matters for a CE that is an L2 switch.
- Local bias is limited to 16 all-active segments per domain; a further one keeps DF-only flooding and `nos-fdbd` logs a warning.
- The packet mark's top byte (`0xE5`) and its low 16 bits are used for local bias; do not use `fwmark` rules that match them on a router with EVPN segments.
- A router only notices a segment failure when its own bond loses link. If a link fails only on the CE's side (a switch in between, say), the router keeps sending the CE's traffic into it. Run LACP between the CE and its routers so a dead link takes the bond down.
- Over VXLAN only, no MPLS. IP prefix routes (Type 5) and symmetric IRB host routes work through a routing table's L3 VNI.
- A symmetric IRB host route is installed only when the host and the tunnel addresses are of the same family, and through one router only (the lowest tunnel address), even for a host behind a multi-homed segment.
- A Type 5 route is installed only in its interface-less form: one with a gateway IP or an ESI as overlay index (RFC 9136 §4.3) is ignored. Its prefix must be of the same family as the tunnel addresses, and when several routers advertise one prefix the one with the lowest tunnel address is used (no ECMP).
- Routing policies do not apply to EVPN routes.
- ARP suppression is not enabled: received MAC+IP routes are installed as neighbour entries, but ARP requests are still flooded.

How NOS programs VXLAN devices, forwarding entries and the DF on Linux is described in [the implementation notes below](#implementation-notes-nos-fdbd).

## Configuration reference

Broadcast domain EVPN fields. CLI forms are shown absolute; the relative form, valid after `edit broadcast domain <d>`, drops the `broadcast domain <d>` prefix (`set vni 10100`, `delete redistribute from mac`). REST paths are relative to `/v1/transactions/{tx}/broadcast-domain/{domain}/`. The domain's other fields (addresses, routing table, OSPF) are in the L2 switching guide.

| Field | CLI | REST path and body | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| vni | `set broadcast domain <d> vni <n>` / `delete broadcast domain <d> vni` | `vni`, `10100` | 1-16777215, unset | none beyond the range; required by every field below | Creates the domain's VXLAN tunnel | `show fdb <d>` |
| rd | `set broadcast domain <d> rd <rd>` / `delete … rd` | `rd`, `"65001:100"` | `<asn>:<n>` or `<ipv4>:<n>`, unset | `<n>` fits 16 bits unless the ASN fits 16 bits; needs `vni` | Route distinguisher of every route the domain advertises | `show bgp evpn` on the peer |
| route-target import | `set broadcast domain <d> route-target import <rt>` / `delete … route-target import <rt>` | `route-targets-import/{rt}`, `"65000:10100"` (the list: `route-targets-import`, `["65000:10100"]`) | list of `<asn>:<n>` or `<ipv4>:<n>`, empty | valid format; needs `vni` | Received routes must carry one of these to be used | `show fdb <d>` |
| route-target export | `set broadcast domain <d> route-target export <rt>` / `delete … route-target export <rt>` | `route-targets-export/{rt}`, `"65000:10100"` | as above | as above | Attached to every route the domain advertises | `show bgp evpn` on the peer |
| vtep-source | `set broadcast domain <d> vtep-source interface <if> [label <l>]` or `… vtep-source loopback [label <l>]` / `delete … vtep-source` | `vtep-source`, `{"Interface":{"interface":"eth0","label":null}}` or `{"Loopback":{"label":null}}` | unset | needs `vni`; the address is resolved at run time, not checked at commit | Tunnel source address and BGP next hop | `show fdb <d>` on the peer (flood list) |
| redistribute from mac | `set broadcast domain <d> redistribute from mac to bgp <i>` / `delete … redistribute from mac` (or `delete … redistribute`) | `mac-redistribute`, `"r1"` | BGP instance, unset | instance exists; needs `vni`, `rd` and `vtep-source` | Advertises the domain and its MAC addresses into the instance, installs what it receives | `show bgp evpn` on the peer |
| redistribute from arp | `set broadcast domain <d> redistribute from arp to bgp <i>` / `delete … redistribute from arp` | `arp-redistribute`, `"r1"` | BGP instance, unset | same instance as `redistribute from mac`; needs `vni` | Adds MAC+IP routes for local neighbour entries | `show fdb <d>` on the peer |
| redistribute from connected | `set broadcast domain <d> redistribute from connected to bgp <i>` / `delete … redistribute from connected` | `connected-redistribute`, `"r1"` | BGP instance, unset | as above | Adds MAC+IP routes for the domain's own addresses | `show fdb <d>` on the peer |

Port aggregate Ethernet Segment fields. The relative forms (after `edit port-aggregate <name>`) drop the `port-aggregate <p>` prefix (`set esi <esi>`, `delete esi`, `set switching-profile <sp>`). REST paths are relative to `/v1/transactions/{tx}/port-aggregate/{name}/`. The other port aggregate fields are in the port aggregation guide.

| Field | CLI | REST path and body | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| esi | `set port-aggregate <p> esi <esi>` / `delete port-aggregate <p> esi` | `esi`, `"00:11:22:33:44:55:66:77:88:99"` | ten hex bytes, colon-separated, unset | not all zero; not used by another port aggregate on the router | Makes the bond an Ethernet Segment: ESI on its MAC routes, Type 4 and Type 1 routes, DF election | `show fdb <d>` |
| redundancy-mode | `set port-aggregate <p> redundancy-mode all-active\|single-active` | `redundancy-mode`, `"AllActive"` or `"SingleActive"` | `all-active` | `single-active` needs an `esi` | Whether non-DF routers block only flooded traffic or the whole port | `show fdb <d>`, `show bgp evpn` on the peer |
| df-algorithm | `set port-aggregate <p> df-algorithm modulo\|hrw` | `df-algorithm`, `"Modulo"` or `"Hrw"` | `modulo` | `hrw` needs an `esi` | The DF election algorithm asked for; HRW only runs when every router on the segment asks for it | `show fdb <d>`, `show bgp evpn` on the peer |
| switching-profile | `set port-aggregate <p> switching-profile <sp>` / `delete port-aggregate <p> switching-profile` | `switching-profile`, `"sp-evpn"` | name, unset | profile exists | Trunks the bond into the profile's domains; a segment must be in the EVPN domain | `show port-aggregate <p>`, `show fdb <d>` |
| lacp-system-id | `set port-aggregate <p> lacp-system-id <mac>` / `delete … lacp-system-id` | `lacp-system-id`, `"02:00:00:00:00:01"` | unicast MAC, derived | unicast MAC | LACP actor system id; set it identically on every router of an LACP segment | `show lacp <p>` |

BGP peer-group address family:

| Field | CLI | REST path and body | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| address-family l2vpn-evpn | `set bgp instance <i> peer-group <g> address-family l2vpn-evpn` / `delete … address-family l2vpn-evpn` (relative: `set address-family l2vpn-evpn`) | `bgp-instance/{i}/peer-group/{g}/address-family/L2vpnEvpn`, `"L2vpnEvpn"` | list, `[ipv4]` | at least one family | Negotiates EVPN (AFI 25, SAFI 70) on the group's sessions | `show bgp evpn` |

Routing table EVPN (IP-VRF) fields. REST paths are relative to `/v1/transactions/{tx}/routing-table/{table}/evpn/`; the CLI forms are `set routing-table <t> evpn <field> …`, or `set evpn <field> …` after `edit routing-table <t>`.

| Field | CLI | REST path and body | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| l3-vni | `set routing-table <t> evpn l3-vni <n>` / `delete … evpn l3-vni` | `l3-vni`, `5000` | 1-16777215, unset | not used by another table or broadcast domain; every field below needs it | Creates the L3 VNI devices and turns the table into an IP-VRF, and symmetric IRB for the EVPN domains whose SVI is in the table | `show route <t>` |
| rd | `set routing-table <t> evpn rd <rd>` | `rd`, `"65001:5000"` | `<asn>:<n>` or `<ipv4>:<n>`, unset | required with `l3-vni` | Route distinguisher of the table's Type 5 routes | `show bgp evpn` on the peer |
| route-target import | `set routing-table <t> evpn route-target import <rt>` | `route-targets-import/{rt}`, `"65000:5000"` | list, empty | valid format | Received Type 5 routes must carry one of these | `show route <t>` |
| route-target export | `set routing-table <t> evpn route-target export <rt>` | `route-targets-export/{rt}`, `"65000:5000"` | list, empty | at least one with `l3-vni` | Attached to every Type 5 route the table advertises | `show bgp evpn` on the peer |
| vtep-source | `set routing-table <t> evpn vtep-source interface <if> [label <l>]` or `… loopback [label <l>]` | `vtep-source`, `{"Interface":{"interface":"eth0","label":null}}` | unset | required with `l3-vni`; resolved at run time | Tunnel source and next hop; `loopback` is the loopback of the table owning `bgp-instance` | `show bgp evpn` on the peer |
| bgp-instance | `set routing-table <t> evpn bgp-instance <i>` | `bgp-instance`, `"r1"` | BGP instance, unset | exists; not the table's own `bgp-instance`; the `redistribute from mac` instance of every EVPN domain whose SVI is in the table | The underlay instance that carries the Type 5 routes | `show bgp evpn` |

The designated-forwarder wait (`--df-wait`, default 3 seconds) is a start-up option, described in [System](system.md#start-up-options).

## Implementation notes (`nos-fdbd`)

Developer-facing detail of the daemon behind this page: what it writes to the kernel, the netlink pitfalls found the hard way, and how the designated-forwarder and local-bias logic is built. Moved here from `fdb/CLAUDE.md` (#263); the operator view is above. Paths are relative to `fdb/src/`; `ponytail:` comments in the source are the authoritative list of ceilings.

### Config (`BroadcastDomain`, see [Schema reference](../schema-reference.md))

`vni`, `rd`, `route_targets_import`/`route_targets_export`, `vtep_source` (a `SourceAddress`: `interface <if> [label <l>]` or `loopback [label <l>]`) and `mac_redistribute` (`redistribute from mac to bgp <instance>` — the BGP instance is named on that command, not on the domain). Two optional siblings add Type-2 routes *with an IP*: `arp_redistribute` (`redistribute from arp to bgp <instance>` — local ARP/IPv6 ND bindings on the bridge) and `connected_redistribute` (`redistribute from connected to bgp <instance>` — the domain's own SVI `addresses`, originated with the bridge's MAC). Both must name the same instance as `mac_redistribute` (validated) — one EVPN target per domain. `neigh_suppress` (`neigh-suppress`, a bool, off by default, requires a `vni`) turns on ARP/ND suppression on the VXLAN port (see "Kernel side"); a toggle is applied in place by `ensure_vxlan`, never a rebuild of the domain (`set_ready` doesn't count it as a `Ready` change). Link-local/loopback/multicast addresses are never advertised (`is_advertisable_ip`). The daemon is only *ready* (`fdb::Ready`) when all of `rd`, `vtep_source`, `mac_redistribute`, the domain's bridge (asked of `nos-interfaced`, `GetBroadcastDomain` → `bridge_name`) and the VTEP address (`GetInterface`) resolve; until then it idles and the 10s tick retries — a bridge or address that isn't there *yet* is the normal case.

### Kernel side (`driver/`)

`FdbDriver` (`--driver linux|noop`, like `RibDriver`). The Linux driver, over `rtnetlink`:
- `vx<vni>` (a VNI is unique per netns, so no registry file) with `local <vtep>`, dstport 4789, `nolearning`, **and `dev <underlay>`** — the device carrying the VTEP address (`eth0` for an interface source, `lo<table-id>` for a loopback, via `RibRequest::GetTableId`). This is not cosmetic: when the address lives inside a VRF the kernel can only bind the tunnel's UDP socket through that device. A device whose VNI/address/underlay drifted is recreated; VNI can't change in place. A device opened before its underlay joined its VRF is reopened (down/up; the underlay's master is recorded when the device is brought up, `bound_master`, and a change or no record triggers it): the kernel binds the VXLAN socket to the VRF only on open, and an unbound socket sends entries with no `via` — every FDB nexthop group — to the main table, where `ENETUNREACH` drops them (`tx_carrier_errors`). A down keeps the permanent VXLAN entries and the bridge's extern-learned ones, so nothing needs reinstalling. Found by `nos-e2e evpn-v6`, where fdbd raced `nos-interfaced`'s VRF enslavement at boot.
- Remote MAC: `RTM_NEWNEIGH` AF_BRIDGE on the VXLAN device, `NTF_SELF|NTF_MASTER|NTF_EXT_LEARNED` (files it in the bridge table too; the bridge neither ages nor relearns it), `dst`=remote VTEP, `vni`, state permanent.
- Flood list: one all-zero-MAC entry per remote VTEP (head-end replication), which needs `NLM_F_APPEND` — `NeighbourAddRequest` hardcodes its flags, so every FDB write is a raw message via `Handle::request`.
- Remote IP: a Type-2 with an IP (`EvpnKey::MacIp`) is also an IP neighbour on the *bridge* (`RTM_NEWNEIGH` AF_INET/INET6, permanent + `NTF_EXT_LEARNED`, so the SVI resolves the host without ARP and the kernel neither ages nor probes it) next to its FDB entry. `desired` returns both; `installed` holds a list per route and an item is only removed when no other route still names it (a MAC-only and a MAC+IP route for one MAC share the FDB entry).
- ARP/ND suppression: with `neigh_suppress`, `ensure_vxlan` sets `IFLA_BRPORT_NEIGH_SUPPRESS` on `vx<vni>` (the same `RTM_NEWLINK` port-data path as the flood flags, `set_bridge_port`), read back from the link dump every tick (`neigh_suppressed`) so unsetting works and a recreated port is healed — logged `vxlan neigh suppression set`. The kernel bridge (`br_do_proxy_suppress_arp`/`br_do_suppress_nd`) then answers an ARP request / NS for a host whose binding it holds (every remote Type-2 with an IP, above) out of the port it came in on, and doesn't flood it to the VXLAN port; an unknown target floods as before, and requests arriving *from* the VXLAN port are left alone. Gratuitous ARP is no longer flooded to the VXLAN port either, so a local IP moving to a new MAC (a VRRP/keepalived VIP) leaves remote caches stale until they expire — the operator opts in. `show fdb`'s `neigh_suppress` is the value last applied, not the configured one. `nos-e2e evpn-dataplane` proves it for ARP: the CE's request for the host is answered by router-a's bridge and never reaches the host, and floods again once cleared. `ponytail:` IPv6 ND suppression comes with the same flag but no e2e covers it, and a proxied NA's Router flag isn't signalled (no RFC 9047 ARP/ND extended community — `nos-bgpd` codec work, a separate issue if wanted).
- Bridge-port learning is **off** on `vx<vni>` (`IFLA_BRPORT_LEARNING`, RFC 7432 §9.2: remote MACs come from the control plane only), set by `ensure_vxlan` on the `set_bridge_port` path and read back every tick (`port_learning`), logged `vxlan port learning disabled`. With it on, a CE's broadcast another segment PE floods here taught the bridge the CE behind the VXLAN port, and aliased traffic for it was dropped (#173). The VXLAN device's own `nolearning` is a different switch.
- Segment pin (`Installed::SegmentMac`, `set_segment_mac`/`del_segment_mac`): a remote Type-2 for a MAC on one of *our own* segments is a bridge FDB entry on the segment port — `NUD_NOARP` (static: never aged, and not on the VXLAN port, so never moved by it) with `NDA_FDB_EXT_ATTRS { NFEA_ACTIVITY_NOTIFY }` (nested, `NLA_F_NESTED` or the kernel refuses it). Not `extern_learn`: the bridge ignores the ext-attrs on that path, and an extern-learned entry hit by local frames on the same port never shows it. The kernel keeps `FDB_NOTIFY_INACTIVE_BIT` set until a frame from the port refreshes the entry (`br_fdb_update`, with a notification `watch_neigh` sees) and sets it again after the ageing time without one (`br_fdb_cleanup`). `local_macs` reports a pin only while it is active, so a PE re-originates a pinned MAC exactly when the CE sends through it (RFC 7432 §8.4: both segment PEs advertise, #172) and never because the other PE told it — two PEs pinning each other's route can't sustain a stale MAC. A pin over a MAC already learned on that port starts active (`install(.., active)`), so its Type-2 isn't withdrawn. `ponytail:` `del_segment_mac` deletes whatever the bridge holds for the MAC on that port, so an active pin's MAC is withdrawn until the CE's next frame relearns it.
- Local MACs: `local_macs` dumps the bridge FDB and keeps entries that are *not* `permanent` (the ports' own addresses), not `extern_learn` (fdbd's own writes — this is the loop guard), not an inactive segment pin (`fdb_activity`), not on the VXLAN port, and not group/all-zero addresses. An `RTNLGRP_NEIGH` subscription (`watch_neigh`, which also wakes on IPv4/IPv6 neighbour events) only signals "look again"; a debounced (200ms) dump is the source of truth, and the 10s tick covers a dropped notification. `show fdb` adds each MAC's port and age (`NDA_CACHEINFO` `used`, read per query through `local_mac_ages`, not stored). Note `bridge fdb add` defaults to *permanent* — pin a test MAC with `static`.

### IPC

- `--listen-socket` (`/run/nos/fdb-<domain>.sock`, `ServiceRef::FdbDomain`). `allowed`: `PushEvpnRoutes` is `bgpd`'s, `GetMacs` is `user`/`restd`.
- `bgp_client.rs` originates this domain's routes into `ServiceRef::BgpInstance(mac_redistribute)`: one Type-3 (inclusive multicast, origin = VTEP), one Type-2 per local MAC and, with `arp`/`connected`, one Type-2 (MAC+IP) per local neighbour (`local_neighbours`: the bridge's ARP/ND dump, not `extern_learn` — the loop guard — *and only for MACs behind a local port*, so a binding the SVI learned over the VXLAN port isn't re-originated) and per SVI address (`bridge_mac` from netlink), carrying the export Route Targets and the VXLAN encapsulation community, next-hop = VTEP. `Full` on every (re)connect; the otherwise write-only connection is also read for EOF so a `nos-bgpd` restart is answered at once (unlike `nos-bgpd`'s `rib_push_client`, which doesn't notice).
- **Symmetric IRB** (RFC 9135, #188): when the domain's SVI `routing_table` has an `evpn.l3_vni` on our `mac_redistribute` instance (a mismatch is a commit error), `reconcile::resolve` asks that table's `nos-ribd` for `RibRequest::GetEvpnIrb` (`interface_client::evpn_irb`, name-checked `Role::Ribd`) and stores it as `Ready.irb` (`None`, also while ribd isn't ready, is asymmetric; the tick retries). `local_routes` then gives every ARP/ND-learned MAC+IP (never the SVI's own `connected` one) `l3_vni` (Label2), the IP-VRF's export RTs and its Router's MAC. `set_ready` copies an `irb`-only change in place and republishes, like `neigh_suppress` — never the full-teardown path. Log anchor: `symmetric irb changed`.
- `nos-bgpd`'s `fdb_push_client` pushes *every* received EVPN route to each domain that redistributes into it; **Route-Target filtering is fdbd's** (`fdb::desired`): a route is installed only if it carries an import RT, names this VNI (a Type-3's VNI comes from its PMSI attribute, absent = matches) and isn't our own VTEP.

### Ethernet Segments (ESI) and the Designated Forwarder

A `PortAggregate` with an `esi` (config: `set port-aggregate <n> esi <10 hex bytes>`) that is a member of this domain's bridge — through its switching profile, untagged (the bond is the bridge port) or `Dot1q(n)` (its `<bond>.<n>` sub-link is) — is an **Ethernet Segment port** (`Ready.es_ports`, resolved in `reconcile::es_ports`, the bond's real `bond<id>` name coming from `nos-interfaced`'s `GetPortAggregate`). What that does:

- **Type-2 ESI.** `FdbDriver::local_macs` now returns each MAC with the bridge port it sits behind; `local_routes` puts that port's ESI on the MAC's Type-2 (and on a MAC+IP for a neighbour behind it). `EvpnRoute.esi` is in the route *value*, not `EvpnKey`; the ESI is part of a Type-2's wire identity though, so `nos-bgpd`'s `apply_evpn_local` withdraws the old NLRI when a MAC moves onto/off a segment.
- **Type-4.** One `EvpnKey::EthernetSegment { rd, esi, origin = VTEP }` per distinct ESI, carrying its ES-Import Route Target (`nos_proto::evpn_id::es_import_rt`) and the RFC 8584 DF Election community (below). Originated by *every domain's* fdbd that attaches the segment, each with its own RD, so the same segment appears once per domain; receivers dedupe by origin.
- **DF election** (`df.rs`, pure): the candidates are our VTEP plus every received Type-4 origin for that ESI (matched on the exact ESI and carrying that ESI's ES-Import RT, RFC 7432 §7.6: a Type-4 without it is ignored and warned about). **RFC 8584 §2.2.3, strictly:** only when *every* other PE's Type-4 carries AC-DF in its DF Election community (we always set it) does `plan_df` restrict them to PEs with a held per-EVI Ethernet A-D for this domain's own VNI; one PE without AC-DF (GoBGP, most older stacks) restores RFC 7432's list, a PE that never joined this EVI included. Then the algorithm: by default RFC 7432 §8.5 carving — ordered by ascending address, the DF is `pes[vni % n]` (RFC 8365 §8.3.1: the VNI is the Ethernet tag), so two domains on one segment spread over the PEs. With `PortAggregate.df_algorithm = Hrw` (`set port-aggregate <n> df-algorithm hrw`, needs an `esi`), RFC 8584 §3.2 HRW (`elect_hrw`: CRC-32 over the 4-octet VNI + 10-octet ESI, the §3.2 LCG over the IPv4 address, highest weight wins, a tie to the lowest address) — but only if every candidate asked for HRW (`df::effective`); a PE with no community, another algorithm (incl. RFC 9785's Preference, alg 2) or an IPv6 address makes everyone fall back to modulo. Our Type-4 carries `[es_import_rt(esi), df_election_ext(alg, ac_df = true)]` (`nos_proto::evpn_id`, type 0x06 subtype 0x06). A PE with several Type-4s (one per domain/RD) that disagree counts as "no algorithm, no AC-DF". `Fdb::sync_df` re-runs it on every received Type-4/per-EVI-A-D change and on each resync; an algorithm change re-elects without a new DF wait (as a peer's Type-4 arriving does). `ponytail:` HRW is only cross-checked nos-against-nos (no e2e peer implements it); a misreading of §3.2 would elect two DFs against another vendor, which is why `modulo` stays the default. **Interop:** GoBGP (4.9.0) can't decode the community (EVPN subtype 6) and, against RFC 4360/7606, treats the UPDATE carrying our Type-4 as a withdraw — so a GoBGP peer never holds our Type-4 (`nos-e2e evpn-esi` asserts its `unknown evpn subtype: 6` log instead); the other route types are unaffected. Not implemented: the §2.2.4 DP bit, per-ES-per-EVI algorithm sets.
- **Applied to the kernel:** `FdbDriver::set_port_flood(port, unicast, bum)` (an `RTM_NEWLINK` with `IFLA_INFO_PORT_DATA` = `IFLA_BRPORT_{UNICAST,MCAST,BCAST}_FLOOD`, the same as `ip link set … type bridge_slave flood …`; via netlink, not sysfs, since fdbd is the unprivileged `nos` user). All-active with local bias (below): unicast flood = DF, multicast/broadcast flood **always on**; without local bias (tc setup failed, the 17th segment) both = DF as before; single-active: both on. A port that left the segment (or shutdown) goes back to all on. Anything but all-on is re-asserted every resync so a recreated port is healed. Log anchors: `df elected … role=df|non-df algorithm=modulo|hrw ac_df=true|false pes=…`, `segment port flooding set … flood=… unicast=… bum=…` (`flood=` is true only when both are).
- **`desired`**, a remote Type-2 (or MAC+IP) whose ESI is one of our local segments: while that segment's port can carry unicast (`pinnable`: up, and not a single-active non-DF or one in its DF wait — an all-active non-DF still forwards unicast), it is **pinned** to the port (segment pin, above), with or without the advertising PE's per-ES A-D — the MAC is behind our own link too, so a peer losing its link is exactly when the pin matters. Not while the bridge learned the MAC behind *another* port. Otherwise it falls back to the remote handling below (a VXLAN entry to the advertising PE, gated on its per-ES A-D, aliased over the segment's other PEs). `sync_df` re-syncs a segment's Type-2s when its pinnability changes, `refresh_local` those whose MAC moved port. `show fdb` lists a pin as `Remote` with no VTEP and the segment's ESI (`remote, on our esi …` in the CLI). Log anchors: `remote mac pinned|unpinned domain= mac= port=`.
- `show fdb` lists each segment (`FdbTable.segments`: ESI, port, DF role, ranked PEs, the algorithm in effect — `df-algorithm hrw` in the CLI) and the ESI of a local MAC. `nos-bgpd` renders the community `df-election:modulo|hrw|alg<N>[,ac-df]` in `show bgp evpn`.

- **DF wait timer** (§8.5 step 3, `--df-wait`, default 3s): a segment port is held blocked (`segments[].waiting`, reported non-DF in `show fdb`) for the wait after it *first appears* in the plan — fdbd start, ESI newly set, port newly attached, fdbd back from not-ready — and only then is the election applied, so a PE that has just come up doesn't double-deliver BUM. A peer's Type-4 arriving later does not restart it (the joining PE waits, the incumbent doesn't). `run_local` sleeps to the earliest deadline (`df_deadline`) since the 10s tick is too coarse. Log anchors: `df wait started … seconds=`, then `df elected …` only once it ends. Tunable through `--fdbd-arg=--df-wait=N` (e2e `evpn-esi` uses 12s so the kernel state can be read while blocked).

- **Type-1 Ethernet A-D routes** (`EvpnKey::EthernetAd { rd, esi, tag, origin }`; `tag == AD_TAG_ES` is per-ES, otherwise per-EVI). For every attached segment whose port has carrier, `local_routes` originates, next to the Type-4, a **per-ES A-D** (MAX-ET, this domain's export RTs, encapsulation and an **ESI Label** community — `nos_proto::evpn_id::esi_label_ext`, no label with VXLAN (RFC 8365 §8.3.1), only the flags octet whose bit 0 is Single-Active) and a **per-EVI A-D** (tag 0, the VNI in the label field, the domain's RTs). `origin` is not on the wire (the NLRI has no originator): it is the BGP next hop on a received route and our VTEP on a local one, and is only there so two PEs' routes stay apart in `evpn_push_snapshot` (which otherwise collapses one key from two peers). `nos-bgpd` renders the community as `esi-label:single-active|all-active`.
- **Mass withdrawal** (RFC 7432 §8.2.1, receiver side): `Ads` (`ad_index`) records, per segment, the PEs whose per-ES A-D we hold (import RT only, never our own). `desired` installs a remote Type-2/MAC+IP with a non-zero ESI only while *its* PE is in that set, so withdrawing one route removes every MAC (and neighbour) of that PE on the segment at once, and they come back with it. `apply_push` re-syncs every Type-2 of the segments whose set changed (`segment per-es a-d changed` in the log). A MAC on a segment we are attached to is pinned instead (above), and gated only once its port can't carry it.
- **ES down** (the trigger that makes mass withdrawal real): `FdbDriver::port_up` (`IFF_LOWER_UP`) is read by `refresh_local` on every link/neighbour event (`watch_neigh` also subscribes to `RTNLGRP_LINK`) and on the tick. A segment whose port has no carrier withdraws its Type-4 and both Type-1, is never the DF, and restarts its DF wait when carrier returns (`segment port carrier changed … up=`). A failed read counts as up. Local MACs behind the dead port are not withdrawn (the bridge ages them).
- **Single-active** (`PortAggregate.redundancy_mode`, `set port-aggregate <n> redundancy-mode single-active`, needs an `esi`): the election is unchanged (RFC 7432 §8.5, `df.rs`), what differs is what it is applied to. A single-active non-DF (or one still in its wait, or down) has its bridge port put in the STP state **disabled** (`FdbDriver::set_port_forwarding`: an `RTM_SETLINK` in the `AF_BRIDGE` family with `IFLA_PROTINFO` — what `bridge link set … state` sends; **not** the `RTM_NEWLINK` + `IFLA_INFO_SLAVE_DATA` path `set_port_flood` uses, which accepts `IFLA_BRPORT_STATE` and silently ignores it), which drops unicast as well as BUM in both directions; its flood flags stay on. It is *disabled*, not *blocking*: with the bridge's STP off (the only mode here) the kernel's `br_port_state_selection` turns a BLOCKING port straight back to forwarding — the write succeeds and does nothing, which the first e2e run found — but skips disabled ones. The DF's port forwards. Forwarding is the kernel default, so it is only asserted after the port was blocked; a block is re-asserted every resync. Switching the mode swaps the mechanism and undoes the old one (`segment port forwarding set …`). The per-ES A-D carries the Single-Active flag; `show fdb` lists `single_active`. **Ceiling:** the blocked port keeps its carrier, so a customer device needs end-to-end failure detection (an ARP-monitored active-backup bond, as `evpn-single-active` uses) to move over — dropping the carrier would mean touching a link `nos-interfaced` owns.
- **Backup path** (§8.4.1.2, receiver side): `SegmentAds` also records the PEs with a per-EVI A-D for *this domain's VNI* and whether any per-ES A-D carried the Single-Active flag. When a MAC's PE has lost its per-ES A-D and the segment is single-active, `desired` re-points the MAC, ahead of the new Type-2, at the PE the segment would elect as DF (`backup_pe`): RFC 7432 §8.5 modulo over the PEs that still advertise both the segment and the EVI *and* whose Type-4 we hold (`SegmentAds.es_pes`, indexed by `ad_index` for any ESI, attached or not, and only for a Type-4 carrying that ESI's ES-Import RT, not the domain's import RT; a Type-4 change re-syncs the segment's MACs like an A-D change). With none of their Type-4s held (§7.6: only PEs on the segment import them, so a reflector may filter them; NOS's own RT-Constraint filter never holds a Type-4 back, see [Constrain EVPN distribution](#constrain-evpn-distribution-rt-constraint)) it falls back to the lowest address. `ponytail:` the DF is not on the wire, so a remote segment running HRW or Preference may disagree; it matches in the default-carving case. `nos-e2e evpn-esi` reads both choices back from the kernel FDB. An all-active segment has no backup: that is the mass withdrawal above.

- **Aliasing** (§8.4.1.1, receiver side, all-active only): a remote MAC on a segment we are *not* attached to is reached through every PE that advertises **both** the segment (per-ES A-D) and this domain's EVI (per-EVI A-D), provided there are at least two, the MAC's own PE is one of them and they all share our VTEP's address family (`alias_group`: the kernel refuses a mixed-family group, or one whose family differs from the VXLAN device's `local` — a mixed-family segment keeps the single-PE entry). Those PEs become an **FDB nexthop group** (`ip nexthop add id N via <vtep> fdb`, `… group A/B fdb`, then the FDB entry with `NDA_NH_ID`) and the kernel balances flows over it; otherwise the plain single-PE entry is used. The group shrinks when a PE's per-ES or per-EVI A-D goes (`remote mac group installed|removed … vteps=`, `show fdb` lists all `vteps` of a MAC, `(aliased)` in the CLI). Two Type-2 routes for one MAC from two PEs want the *same* group item, so they neither reinstall nor flap each other. The FDB entry has to be **deleted before it changes form** (the kernel keeps the old form on a `replace`), which `set_remote_mac_group` and `sync_key`'s uninstall-then-install order both do. No `netlink-packet-route`/`rtnetlink` support exists for nexthops, so `driver/nexthop.rs` hand-encodes `RTM_NEWNEXTHOP`/`RTM_DELNEXTHOP` (a unit test pins the byte layout) and sends them on a plain `netlink-sys` socket from `spawn_blocking`. Ids are `vni << 8 | slot` so the per-domain `nos-fdbd` processes sharing a netns never collide; `ponytail:` 255 nexthops + groups per domain, deleted only with the domain (`remove_vxlan`). Gateways are IPv4 (`AF_INET`, 4 octets) or IPv6 (`AF_INET6`, 16 octets), so aliasing works over an IPv6 underlay too: `nos-e2e evpn-v6` (three PEs, labelled IPv6 VTEPs, real forwarding) proves it, the IPv6 VXLAN device in a VRF and EVPN over IPv6 sessions with it; `net.ipv4.udp_l3mdev_accept` also governs udp6 sockets. **Spike (2026-09-21, kernel 7.2):** an FDB nexthop group forwards through a VXLAN whose underlay device is in a VRF — the `via`/`NDA_IFINDEX` problem does not recur, since the nexthop path takes the VXLAN device's underlay — so no operator prerequisite beyond the existing `udp_l3mdev_accept`.

Ceilings (`ponytail:`): the remote-MAC ceiling is tracked incrementally (a rebuild over all received routes on each `set_ready`, every 10s tick, only while a ceiling is set); local bias ceilings below. `nos-e2e evpn-esi` proves the control plane, the Type-1/mass-withdrawal behaviour and the kernel port flags and tc filters, `evpn-single-active` the single-active state machine and failover with real traffic, `evpn-dataplane` and `evpn-v6` all-active forwarding and local bias with real broadcasts (below).

#### Local bias (RFC 8365 §8.3.1, #24)

RFC 8365 has the egress PE drop multi-destination traffic from a VTEP that shares the segment, and the ingress PE replicate to its local segments *regardless of the DF state*. The bridge sees only the inner frame, so the decision is split between two tc hooks joined by `skb->mark`; it **replaces** the old "non-DF refuses all BUM" rule rather than sitting on top of it (a drop on top of it black-holed a host behind the non-DF).

| BUM frame reaching an all-active segment port P from | DF | non-DF / DF wait / down |
|---|---|---|
| a local access port | deliver | deliver |
| the VXLAN port, from a PE on P's segment | drop (local bias) | drop |
| the VXLAN port, from any other PE | deliver | drop |

Unknown unicast keeps the DF rule (`flood` = DF). Single-active is excluded (its non-DF is STP-disabled, so the DF must deliver what its peer received locally).

- **Ingress** (`driver/linux.rs` through the shared `nos-tc` crate; `tc/src/encode_tests.rs` pins the bytes, `tc/tests/kernel.rs` runs them against the real kernel under `unshare -Urn`): `clsact` on `vx<vni>`, per peer P a `flower dst_mac 01:00:00:00:00:00/01:00:00:00:00:00 enc_src_ip|enc_src_ipv6 <P> action skbedit mark 0xE5000000|bitmap(P) mask 0xFF00FFFF` at prio 1 (handle n = the n-th peer in address order, so a changed peer set overwrites in place), then a prio 2 catch-all with the magic byte alone (`set_local_bias`). `bitmap(P)` has one bit per local all-active segment P shares (`plan_local_bias`: bit = index among the domain's all-active ports sorted by name). A peer is any PE of `Segment.pes` but us, so the same AC-DF/per-EVI candidate set as the election.
- **Egress** (`set_segment_filter`, on the bond, or `<bond>.<tag>` for a Dot1q member; `clsact` is created if needed and left): `fw` + `gact drop` at prio 1, handle `0xE5000000|bit` mask `0xFF000000|bit` (the local-bias drop, always present on an all-active port) and at prio 2 handle `0xE5000000` mask `0xFF000000` (the DF filter, present while non-DF/waiting/down). Two priorities because a `fw` head has one mask.
- **Why the outer source is readable:** a classic per-VNI VXLAN device attaches tunnel metadata only while the kernel's global `ip_tunnel_collect_metadata()` static key is on.
  - A flower filter with `enc_*` keys does **not** turn it on (#460, kernel 7.2.11). The 2026-10 spike that said it did most likely ran while something else on the host held the key.
  - So `set_local_bias` first adds a fib rule per domain, `tun_id 0xE5<vni as 32 bits> pref 32741 nop`, before the marking. The tun_id is above 32 bits, so no VNI or GRE key matches it, and `nop` would change nothing if one did. The rule goes with the marking (empty peer set) and with the device (`remove_vxlan`).
  - Check by hand: `ip rule show` lists `tun_id`; `tc -s filter show dev vx<vni> ingress` counts hits on the `enc_src_ip` filters. Without the rule, every core BUM frame lands on the catch-all and carries only the magic byte, so the DF echoes same-segment BUM back to the CE. That is a duplicate, never a loss, and `evpn-dataplane`'s "no echo" check fails.
- **Order is the safety property** (`sync_df`): the egress filters, then the ingress marking, and only then the multicast/broadcast flood flags open. A missing piece degrades to duplicates. If either tc step fails for a port (missing `cls_flower`/`cls_fw`/`act_skbedit`/`act_gact`/`sch_ingress`) that port keeps today's DF-only flags (`flood = DF` for all three), `show fdb` has `local_bias: false`, and a warning `local bias unavailable, df-only flooding` is logged once; retried every resync. There is no knob to turn local bias off.
- Unchanged kernel state is not rewritten on every pushed route, only once per `TICK/2` (healing a recreated bond or VXLAN device) or when the plan changed. The flood flags of a non-all-on port are re-asserted as before. On a first call in a process the ingress prio 1 is flushed (a crashed `nos-fdbd` may have left handles beyond the new peer count). `remove_vxlan` takes the ingress filters with the device; the egress ones are cleared when the port leaves the plan (`clear_segment_filter`, also on shutdown through `set_ready(None)`).
- Log anchors: `local bias set domain= vtep= peers= segments=<bitmap>`, `segment filter set domain= port= df_filter=`, `segment filter cleared`, `local bias unavailable, df-only flooding`.
- **Ceilings** (`ponytail:`): 16 all-active segments per domain (the mark's bitmap; the 17th is DF-only, with a warning); the mark's top byte `0xE5` and low 16 bits are reserved (an operator `fwmark` rule matching them would see them); unknown unicast from a CE to its non-DF is still flooded back by the DF (RFC 8365 §8.3.3 territory); an old (pre-#24) non-DF neither delivers locally nor gets delivered for, so upgrade both PEs of a segment together.

### Explicit ceilings (`ponytail:` in the code)

Type-5 routes, the L3 VNI and the Router's MAC are not this daemon's (it only borrows them for symmetric IRB, above): an IP-VRF lives in its routing table's `nos-ribd` (see `docs/internals/rib.md`'s "EVPN IP-VRF"), which also creates `vx<l3-vni>` — a VNI is validated unique across domains and tables, since the device name is shared. `nos-bgpd`'s feed never sends this daemon a Type-5.

MAC mobility / duplicate-MAC selection is resolved in `nos-bgpd`, not here — see `bgp-internals.md`'s "MAC mobility": `nos-fdbd`'s own `received` table only ever gets one copy per `(VNI, MAC)` per push — the lowest VTEP among the PEs holding it (the RFC 7432 §15 winner, or every PE on the winner's multi-homed segment, #172; so a remote same-ESI Type-2 for a local segment now arrives, and `desired` pins it — two PEs' routes want the same `SegmentMac` item, so they don't flap each other), so `desired`/`sync_key` need no cross-key MAC awareness. RPL policy on EVPN (bypassed in `nos-bgpd`); re-advertising received EVPN routes; a `Lookup` query. An SVI's own Type-2 (`redistribute from connected`) carries the RFC 7432 §7.8 Default Gateway extended community (`nos_proto::evpn_id::DEFAULT_GATEWAY`, `local_routes` tagging only `r.connected`-sourced neighbours, never a real ARP/ND-learned host); `bgp::evpn::format_ext_community` renders it `default-gw`. There is no separate proxy-ARP path to gate behind it — any Type-2 with an IP already installs an unconditional kernel neighbour (`Installed::Neigh`), which is already this RFC's actual mechanism. `nos-e2e evpn-fdb` proves the control plane and the kernel FDB programming against GoBGP; `nos-e2e evpn-dataplane` proves **forwarding** between two nos PEs and a dual-homed CE (unicast across the VXLAN both ways, a broadcast delivered to the segment once through the DF and never through the non-DF, local bridging on the non-DF) — the run that found every remote FDB entry must name its underlay (`via`/`NDA_IFINDEX`, the driver's `underlay` map), else with the underlay in a VRF the kernel looks the remote VTEP up in the main table and drops every frame (`tx_carrier_errors`). **Operator prerequisite nothing in nos sets:** with the underlay in a VRF, receiving VXLAN needs `net.ipv4.udp_l3mdev_accept=1` (the daemons are unprivileged and `/proc/sys` is read-only in the container); the e2e phase sets it through its privileged helper.

#### End-to-end proof

`nos-e2e evpn-fdb` (GoBGP as the remote VTEP; a helper container pins a MAC and an `ip neigh ... nud permanent` on the bridge from inside router-a's netns) is the end-to-end proof, including Type-2-with-IP in both directions.
