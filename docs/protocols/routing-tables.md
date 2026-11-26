# Routing tables, static routes and redistribution

A routing table is a VRF: a separate IPv4/IPv6 forwarding table with its own interfaces, its own routing protocols and its own routes. This page covers creating routing tables, feeding them with static routes, attaching BGP and OSPF instances to them, redistributing static routes into BGP or OSPF, reading a table back with `show route`, and running the REST API inside one.

- [What a routing table is for](#what-a-routing-table-is-for)
- [Common operations](#common-operations)
  - [Create a routing table and put an interface in it](#create-a-routing-table-and-put-an-interface-in-it)
  - [Add static routes](#add-static-routes)
  - [Attach a BGP or OSPF instance](#attach-a-bgp-or-ospf-instance)
  - [Redistribute static routes into BGP or OSPF](#redistribute-static-routes-into-bgp-ospf-or-ospfv3)
  - [Read a routing table](#read-a-routing-table)
  - [Run the REST API in a routing table](#run-the-rest-api-in-a-routing-table)
  - [Run SSH in a routing table](#run-ssh-in-a-routing-table)
  - [Remove things](#remove-things)
- [How routing tables behave](#how-routing-tables-behave)
- [Configuration reference](#configuration-reference)

The examples use the `$B`/`$C` variables from [The REST API](../api.md#a-complete-session-with-curl) and the two-router lab described in the [README](../README.md#conventions-used-in-these-pages): router-a (`10.50.0.2`, AS 65001) has routing table `rt1`, BGP instance `r1` and interface `eth0` (`10.50.0.2/24`) in `rt1`, and peers with router-b (`10.50.0.3`, AS 65002).

## What a routing table is for

NOS has no default VRF. Every layer-3 object lives in a routing table that you name:

- an interface, a subinterface, a loopback or a broadcast domain's SVI joins a table with `routing-table <table>`, and its addresses then appear in that table as connected routes;
- a BGP instance, an OSPF instance, an OSPFv3 instance and a static routing instance each feed at most one table;
- the REST API listens inside one table, on one of its addresses.

So a router with one routing table behaves like an ordinary router, and a router with several keeps them fully apart: a route learned in `rt1` is never used to forward traffic arriving in `rt2`. Use separate tables for a management network, for customers who must not see each other, or for an underlay that must stay apart from what it carries.

A routing table holds only references. The routes themselves come from four sources:

- **connected**: the addresses of the interfaces in the table;
- **static**: the routes of the static routing instance the table names;
- **bgp**: the best routes of the BGP instance the table names;
- **ospf**: the routes computed by the OSPF or OSPFv3 instance the table names.

When several sources offer the same prefix, the table keeps them all and uses the best one. See [Route selection](#route-selection).

## Common operations

### Create a routing table and put an interface in it

`edit routing-table <name>` creates the table. It is empty until something refers to it:

```
lab-1> configure rt
lab-1(rt)> edit routing-table rt2
lab-1(rt/routing-table:rt2)> top
lab-1(rt)> set interface eth0.200 address 192.0.2.1/24
lab-1(rt)> set interface eth0.200 routing-table rt2
lab-1(rt)> commit
transaction 'rt' committed
lab-1> show route rt2
192.0.2.0/24
  * via 192.0.2.1 [connected]
```

The interface side (VLAN subinterfaces, loopbacks, addresses) is covered by the interfaces guide; `interface eth0.200` above is VLAN 200 on `eth0`.

Over REST, a routing table is created by `PUT`ting it whole. Every field except `name` may be left out:

```sh
$C -X POST "$B/v1/transactions/rt?base=current"
$C -X PUT -H 'Content-Type: application/json' -d '{"name":"rt2"}' \
   $B/v1/transactions/rt/routing-table/rt2
$C -X PUT -H 'Content-Type: application/json' \
   -d '{"tag":200,"addresses":[{"address":"192.0.2.1/24","label":null}],"routing_table":"rt2"}' \
   $B/v1/transactions/rt/interface/eth0/subinterface/200
$C -X POST $B/v1/transactions/rt/commit
```

### Add static routes

Static routes live in a **static routing instance**, a named list of routes. A routing table uses one by naming it. Create the instance with `edit`, add routes with `route <prefix> gateway <address>`, then point the table at it:

```
lab-1> configure st
lab-1(st)> edit static-routing-instance s1
lab-1(st/static-routing-instance:s1)> set route 198.51.100.0/24 gateway 10.50.0.3
lab-1(st/static-routing-instance:s1)> set route 2001:db8:100::/48 gateway 2001:db8::3
lab-1(st/static-routing-instance:s1)> top
lab-1(st)> set routing-table rt1 static-routing-instance s1
lab-1(st)> commit
transaction 'st' committed
lab-1> show route rt1 198.51.100.7
198.51.100.0/24
  * via 10.50.0.3 [static]
```

Setting a route that already exists changes its gateway. Each prefix has exactly one gateway: equal-cost static routes are not supported.

Optional per-route fields, set one per line under `route <subnet>`:

- `distance <1-255>`: administrative distance; unset keeps the default (1).
- `tag <n>`: opaque route tag.
- `interface <name>`: outgoing interface, or `<interface>.<tag>` for a subinterface. It must sit in a routing table bound to this instance, and is required when the gateway is an IPv6 link-local address.
- `blackhole true`: discard the traffic. The gateway must be `0.0.0.0` (or `::` for IPv6), and `bfd` and `interface` must stay unset. Any other route must not use the unspecified gateway.
- A static with a `distance` competes against other sources on that number (eBGP 20, OSPF 110): `distance 250` is a floating static that takes over when the dynamic route is withdrawn. On a tie the static wins.
- A `blackhole` route is installed as a kernel blackhole, shows as `discard` in `show route`, and is not redistributed into BGP or OSPF.
- `tag` is shown by `show route`. If the `interface` does not exist yet, the route is retried every tick until it does.

The same over REST. An instance is `{"name", "routes"}`, and a route is `{"subnet", "gateway"}`, keyed by its prefix with `/` encoded as `%2F`:

```sh
$C -X POST "$B/v1/transactions/st?base=current"
$C -X PUT -H 'Content-Type: application/json' -d '{"name":"s1","routes":[]}' \
   $B/v1/transactions/st/static-routing-instance/s1
$C -X PUT -H 'Content-Type: application/json' -d '{"subnet":"198.51.100.0/24","gateway":"10.50.0.3"}' \
   $B/v1/transactions/st/static-routing-instance/s1/route/198.51.100.0%2F24
$C -X PUT -H 'Content-Type: application/json' -d '"s1"' \
   $B/v1/transactions/st/routing-table/rt1/static-routing-instance
$C -X POST $B/v1/transactions/st/commit
```

To change a gateway only: `PUT …/static-routing-instance/s1/route/198.51.100.0%2F24/gateway` with body `"10.50.0.4"`.

### Attach a BGP or OSPF instance

`set routing-table <table> bgp-instance <instance>` runs a BGP instance inside the table: its sessions use the table's interfaces and addresses, and its best routes are installed in the table. `ospf-instance` and `ospfv3-instance` do the same for OSPF and OSPFv3. The instances themselves are configured as described in the BGP and OSPF guides.

```
lab-1(bgp)> set routing-table rt1 bgp-instance r1
lab-1(bgp)> set routing-table rt1 ospf-instance o1
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"r1"' $B/v1/transactions/bgp/routing-table/rt1/bgp-instance
$C -X PUT -H 'Content-Type: application/json' -d '"o1"' $B/v1/transactions/bgp/routing-table/rt1/ospf-instance
```

An instance can feed only one routing table, and a table has at most one instance of each kind. A BGP instance that no routing table names opens no session at all: it has no VRF to run in. `show bgp summary` still lists it, but its peers stay down.

### Redistribute static routes into BGP, OSPF or OSPFv3

`redistribute bgp` advertises the table's static routes through its BGP instance. `redistribute ospf` makes the router an OSPF ASBR and originates an AS-external LSA for each of them, and `redistribute ospfv3` does the same into OSPFv3. The table must already name both the static routing instance and the target instance:

```
lab-1> configure rd
lab-1(rd)> set routing-table rt1 redistribute bgp
lab-1(rd)> commit
transaction 'rd' committed
```

Router-b then learns `198.51.100.0/24` over BGP:

```
lab-2> show route rt1 198.51.100.7
198.51.100.0/24
  * via 10.50.0.2 [bgp]
```

The rules are a list keyed by target, so the REST path ends in the target (`bgp`, `ospf` or `ospfv3`, any case). The body is the whole rule: `from` is always `"Static"`, `to` is `"Bgp"`, `"Ospf"` or `"Ospfv3"` and matches the path, and `policy` is optional:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"from":"Static","to":"Bgp","policy":null}' \
   $B/v1/transactions/rd/routing-table/rt1/redistribute/bgp
```

**With a policy.** Without a policy, every static route is redistributed. Add `policy <name>` to pass them through a routing policy first; routes the policy rejects are not redistributed, and routes it accepts carry any attribute it set (local preference, communities, and so on). The name is a policy definition, or one of the built-ins `accept-all` and `deny-all`. The routing-policy guide covers the language.

For example, to keep `198.51.100.0/24` out of BGP and redistribute everything else, first define the policy. It is three lines:

```
if this.prefix in 198.51.100.0/24:
    reject
accept
```

In the shell, `edit policy-definition no-lab`, then `edit source` opens the policy in a text editor, or `set source line <n> <text>` adds it one line at a time (the policy is checked at commit). Over REST, `PUT` it whole:

```sh
$C -X PUT -H 'Content-Type: application/json' \
   -d '{"name":"no-lab","source":"if this.prefix in 198.51.100.0/24:\n    reject\naccept\n"}' \
   $B/v1/transactions/rd2/policy-definition/no-lab
```

Then name it on the redistribution rule:

```
lab-1(rd2)> set routing-table rt1 redistribute bgp policy no-lab
lab-1(rd2)> commit
transaction 'rd2' committed
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"from":"Static","to":"Bgp","policy":"no-lab"}' \
   $B/v1/transactions/rd2/routing-table/rt1/redistribute/bgp
```

Router-b then no longer has the prefix:

```
lab-2> show route rt1 198.51.100.7
no route matches 198.51.100.7
```

A table has one rule per target and any number of targets, so it can redistribute into BGP, OSPF and OSPFv3 at once, each with its own `policy` (and `metric`/`metric-type` for `ospf`). Setting a rule for a target that already has one replaces only that rule:

```
lab-1(rd3)> set routing-table rt1 redistribute ospf
lab-1(rd3)> set routing-table rt1 redistribute ospfv3 policy v6-only
```

Redistribution into BGP is only half of advertising a route: the peer-group's `export-policy` must also let it out, and it defaults to `deny-all`. See the BGP guide.

### Read a routing table

`show route <table>` lists every prefix in the table, and under each prefix every candidate route, best first. The one in use is marked `*`, and its source is in brackets. `show route <table> <address>` shows only the longest prefix that covers the address:

```
lab-1> show route rt1
10.50.0.0/24
  * via 10.50.0.2 [connected]
198.51.100.0/24
  * via 10.50.0.3 [static]
lab-1> show route rt1 198.51.100.7
198.51.100.0/24
  * via 10.50.0.3 [static]
lab-1> show route rt1 203.0.113.1
no route matches 203.0.113.1
```

For a connected route, `via` shows the router's own address on that subnet. A route that has a precomputed backup path (an OSPF loop-free alternate) shows it after the gateway: `* via 10.50.0.3 [ospf] backup 10.50.0.4`.

An OSPF route with several equal-cost paths lists every next hop: `* via 10.50.0.3, 10.60.0.3 [ospf]`. It is one multipath route in the kernel, and the kernel spreads flows across its next hops. Over REST, `gateways` is always a list.

Over REST the same data comes back as JSON:

```sh
$ $C $B/v1/routes/rt1/198.51.100.7
{"prefix":"198.51.100.0/24","candidates":[{"gateways":["10.50.0.3"],"source":"Static","backup":null}]}
```

`GET /v1/routes/{table}` returns every prefix, and `GET /v1/routes/{table}/{address}` answers `404` when no prefix covers the address.

What a routing table is configured with, as opposed to what it holds, is in `show config` (or `GET /v1/transactions/{tx}/routing-table/{table}` inside a transaction):

```
routing-table rt1
  bgp-instance r1
  static-routing-instance s1
  redistribute bgp
    policy no-lab
  rest-api 10.50.0.2
static-routing-instance s1
  route 198.51.100.0/24
    gateway 10.50.0.3
```

Only what is set is shown, so `ospf-instance` and `ospfv3-instance` appear once you set them. Over REST the same table is one JSON object:

```sh
$ $C $B/v1/transactions/rd2/routing-table/rt1
{"bgp_instance":"r1","name":"rt1","ospf_instance":null,"ospfv3_instances":[],"redistribute":[{"from":"Static","instance":null,"metric":null,"metric_type":null,"policy":"no-lab","to":"Bgp"}],"rest_api":{"address":"10.50.0.2","port":8080},"static_routing_instance":"s1"}
```

### Run the REST API in a routing table

The REST API is enabled per routing table, and listens on one address of that table:

```
lab-1(api)> set routing-table rt1 rest-api address 10.50.0.2
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"address":"10.50.0.2","port":8080}' \
   $B/v1/transactions/api/routing-table/rt1/rest-api
```

The port defaults to 8080; add `port <port>` to change it. Enabling it on a management routing table, logging in and certificates are covered in [The REST API](../api.md#enabling-the-api) and [System](system.md#the-rest-api).

### Run SSH in a routing table

SSH is enabled per routing table like the REST API, on one address of that table:

```
lab-1(api)> set routing-table rt1 ssh-server address 10.50.0.2
```

- The port defaults to 22; add `port <port>` to change it.
- `delete routing-table rt1 ssh-server` unpins it.
- This only records the setting: nothing listens until `nos-sshd` ships (#994, #995).

### Remove things

- `delete routing-table <table> bgp-instance` (and `ospf-instance`, `ospfv3-instance`, `static-routing-instance`) detaches that source. Its routes leave the table.
- `delete routing-table <table> redistribute <target>` stops redistribution into that target (`bgp`, `ospf` or `ospfv3`), leaving the other rules. BGP withdraws the routes; OSPF flushes their AS-external LSAs at once.
- `delete static-routing-instance <instance> route <prefix>` removes one route; `delete static-routing-instance <instance>` removes the instance and all its routes.
- `delete routing-table <table>` removes the table, and with it every route it held. The instances and interfaces it referred to are not deleted, but an interface that still names the table makes the commit fail until you move it elsewhere.

Over REST, each is a `DELETE` on the same path, for example `DELETE …/routing-table/rt1/redistribute/ospf` or `DELETE …/static-routing-instance/s1/route/198.51.100.0%2F24`.

## How routing tables behave

### Route selection

Each source has a fixed preference, and the lowest wins:

- connected: 0
- static: 1
- bgp: 20
- ospf (OSPF and OSPFv3): 110
- evpn and vpn (routes imported from the overlay): 200

These are not configurable. A static route therefore beats a BGP route to the same prefix, and a BGP route beats an OSPF route. The losing candidates stay in the table and appear in `show route` below the winner; if the winner goes away, the next one takes over without any reconfiguration.

An IPv6 route whose next hop is IPv4 (a BGP route learned over an IPv4 session, RFC 4798) is held in the table and shown by `show route` with its IPv4 gateway, but `nos-ribd` does not install it: the kernel refuses `RTA_VIA` on an IPv6 route, and an IPv4-mapped `RTA_GATEWAY` (`::ffff:a.b.c.d`) is resolved with IPv6 neighbour discovery, which an Ethernet peer never answers (the e2e probe saw the unanswered neighbour solicitations and no TCP SYN left the router). `nos-ribd` logs `ipv6 route over an ipv4 next hop not installed` once per prefix. VPNv6 routes (MPLS-encapsulated) and EVPN routes are not affected.

Connected routes are listed in `show route` and used by BGP to check next hops, but NOS never installs them for forwarding: the operating system already routes the subnet of each address it holds.

- A connected route wins over every other source, so NOS installs nothing for that prefix and leaves it to the operating system.
- A static, BGP or OSPF route for a connected prefix is still listed in `show route`, below the connected route, but it is not installed.
- If the address is removed, the connected route goes away and the next candidate is installed.

`vpn` routes are VPN routes the `vpn bgp-instance` imported into this table by Route Target ([BGP, L3VPN](bgp.md#l3vpn-vpnv4vpnv6)). A `vpn` winner is installed as an MPLS route: it pushes the received label and leaves over the underlay interface toward the PE. See "Prepare a router as an L3VPN PE" below.

### Prepare a router as an L3VPN PE

NOS programs the MPLS routes itself; the host must provide the rest.

- Load the kernel modules `mpls_router` and `mpls_iptunnel` on the host. Without `mpls_router`, `nos-ribd` logs `MPLS is not available` and the table exports nothing (`mpls label not programmed, vpn export withheld`).
- `net.mpls.platform_labels` must be above the largest label in use (allocated labels start at 1000). NOS raises it when it can, but never lowers it.
- `net.mpls.conf.<interface>.input=1` on every interface facing another PE (the interfaces of the `vpn bgp-instance`'s table). NOS sets it when it can and warns once per interface when it cannot. Never set it on a CE-facing interface: a CE could then inject labelled packets into any VRF.
- `net.ipv4.ip_forward=1` (and `net.ipv6.conf.all.forwarding=1` for IPv6 customers). NOS does not set it.
- In Docker, `/proc/sys` is read-only: set these with `--sysctl` (or `sysctls:` in compose), since NOS can only read them there.
- The PEs must be directly connected or reach each other through the underlay IGP. Only the VPN label is pushed (no transport label), so the link to the next PE must be MPLS-enabled end to end.
- If pings die after the label is popped, check `rp_filter` on the CE-facing interface: strict reverse-path filtering (`1`) drops traffic whose source is reached through the core. Use loose (`2`) or off.
- Check it: `ip -f mpls route` lists `<label> dev <vrf device>`, and `ip route show vrf <vrf device>` lists the remote CE subnet as `encap mpls <label> via <PE> dev <core interface> onlink`.

### What a routing table needs

Validation at commit time checks references and uniqueness:

- A table name is 1 to 64 characters and unique.
- Every instance a table names must exist, and no instance may be named by two tables.
- `redistribute` needs `static-routing-instance` set on the same table; `bgp` needs `bgp-instance`, `ospf` needs `ospf-instance` and `ospfv3` needs `ospfv3-instance`. A target can appear only once ("duplicate redistribute target").
- A redistribution `policy` must be a policy definition, `accept-all` or `deny-all`.
- In a static routing instance, a prefix appears at most once, and its gateway must be of the same address family (an IPv4 prefix needs an IPv4 gateway).
- The REST API address must be a specific unicast address, and the port 1 to 65535.

A few things are not checked at commit time and only show up in operation: a static gateway that is not reachable in the table, or a REST API address that no interface of the table carries yet. In the second case the API keeps retrying every second and logs `rest api not listening yet` until the address appears.

### Changes are live, restarts keep the table

Committing a change to a routing table updates it within about a second, with no restart of the protocols attached to it: changing a table's static routes does not reset its BGP sessions. Removing a table removes its routes from forwarding immediately. A router can hold up to 153 routing tables.

## Configuration reference

A routing table's fields. CLI forms are shown absolute; the relative form, valid after `edit routing-table <table>`, drops the `routing-table <table>` prefix (`set bgp-instance r1`, `delete redistribute`). REST paths are relative to `/v1/transactions/{tx}/`.

| Field | CLI | REST path and body | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit routing-table <table>` | `routing-table/{table}`, body `{"name":"rt2"}` | string | 1-64 characters, unique | Creates the VRF | `show config` |
| bgp-instance | `set routing-table <t> bgp-instance <i>` / `delete routing-table <t> bgp-instance` | `routing-table/{t}/bgp-instance`, `"r1"` | name, unset | instance exists; used by one table only | Runs the BGP instance in this VRF and installs its best routes | `show bgp summary`, `show route <t>` |
| ospf-instance | `set routing-table <t> ospf-instance <i>` / `delete … ospf-instance` | `routing-table/{t}/ospf-instance`, `"o1"` | name, unset | as above | Runs the OSPF instance in this VRF | `show ospf neigh`, `show route <t>` |
| ospfv3-instance | `set routing-table <t> ospfv3-instance <i>` / `delete … ospfv3-instance <i>` | `routing-table/{t}/ospfv3-instance`, `["o3"]` | list of names, empty | each exists, listed once, claimed by one table only | Runs the OSPFv3 instance in this VRF | `show ospfv3 neigh`, `show route <t>` |
| static-routing-instance | `set routing-table <t> static-routing-instance <s>` / `delete … static-routing-instance` | `routing-table/{t}/static-routing-instance`, `"s1"` | name, unset | as above | Installs the instance's routes | `show route <t>` |
| redistribute | `set routing-table <t> redistribute bgp\|ospf [policy <p>]` / `delete … redistribute` | `routing-table/{t}/redistribute`, `{"from":"Static","to":"Bgp","policy":null}` | one rule, unset | source and target instances set on the table; policy exists | Advertises the static routes into BGP, or as OSPF AS-external LSAs | `show route <t>` on the peer, `show ospf database` |
| redistribute policy | `… redistribute <x> policy <p>` | `routing-table/{t}/redistribute/policy`, `"no-lab"` | name, unset (everything redistributed) | policy definition, `accept-all` or `deny-all` | Filters and rewrites what is redistributed | as above |
| rest-api | `set routing-table <t> rest-api address <ip> [port <n>]` / `delete … rest-api` | `routing-table/{t}/rest-api`, `{"address":"10.50.0.2","port":8080}` | unset; port 8080 | unicast address; port 1-65535 | Runs the REST API on that address in this VRF | `show log nos-restd[<t>]` |
| ssh-server | `set routing-table <t> ssh-server address <ip> [port <n>]` / `delete … ssh-server` | `routing-table/{t}/ssh-server`, `{"address":"10.50.0.2","port":22}` | unset; port 22 | unicast address; port 1-65535 | Will run `nos-sshd` on that address in this VRF; no effect until the daemon ships (#994, #995) | none yet |
| vpn rd | `set routing-table <t> vpn rd <rd>` / `delete … vpn rd` | `routing-table/{t}/vpn/rd`, `"65000:1"` | `asn:nn` or `a.b.c.d:nn`, unset | required once any `vpn` field is set; unique across tables' `vpn rd` and `evpn rd` | `nos-bgpd` of `vpn bgp-instance` imports into this table and exports its routes under this RD | `show config` |
| vpn route-target | `set routing-table <t> vpn route-target import\|export <rt>` / `delete …` | `routing-table/{t}/vpn/route-targets-import` or `…/route-targets-export`, `["65000:1"]` | list of `asn:nn` or `a.b.c.d:nn` | at least one export; import may be empty | import: VPN routes carrying one are imported, live; export: attached to every exported route | `show config` |
| vpn bgp-instance | `set routing-table <t> vpn bgp-instance <i>` / `delete … vpn bgp-instance` | `routing-table/{t}/vpn/bgp-instance`, `"r1"` | name, unset | required; exists; not the table's own `bgp-instance` | that instance imports into this table, resolving PEs in its own table, and carries its exports | `show config` |
| vpn label | `set routing-table <t> vpn label <n>` / `delete … vpn label` | `routing-table/{t}/vpn/label`, `100` | 16-1048575, unset | unique across tables | The label of every exported route; unset, `nos-ribd` allocates one from 1000 (kept across restarts) | `show config`; `show route <t>` (`VPN label`) |
| vpn site-of-origin | `set routing-table <t> vpn site-of-origin <soo>` / `delete … vpn site-of-origin` | `routing-table/{t}/vpn/site-of-origin`, `"65001:77"` | `asn:nn` or `a.b.c.d:nn`, unset | well-formed; may equal an RT | Attached to every exported VPN route; a received route carrying it is not imported into this table | `show config`; `show bgp vpnv4` (`soo`) |

A static routing instance and its routes. Relative forms, after `edit static-routing-instance <s>`: `set route <prefix> gateway <ip>`, `delete route <prefix>`.

| Field | CLI | REST path and body | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit static-routing-instance <s>` / `delete static-routing-instance <s>` | `static-routing-instance/{s}`, `{"name":"s1","routes":[]}` | string | 1-64 characters, unique | A named set of static routes | `show config` |
| route | `set static-routing-instance <s> route <prefix> gateway <ip>` / `delete static-routing-instance <s> route <prefix>` | `static-routing-instance/{s}/route/{prefix}`, `{"subnet":"198.51.100.0/24","gateway":"10.50.0.3"}` | IPv4 or IPv6 prefix | unique in the instance | Adds the route, or changes its gateway | `show route <t> <address>` |
| route gateway | same as above | `static-routing-instance/{s}/route/{prefix}/gateway`, `"10.50.0.3"` | address | same family as the prefix | Next hop of the route | `show route <t> <address>` |

`routing-table` on interfaces, subinterfaces, loopbacks and broadcast domains is documented with those objects.

How NOS maps routing tables onto Linux VRFs is described in [`docs/internals/rib.md`](../internals/rib.md).
