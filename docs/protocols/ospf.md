# OSPF (OSPFv2)

OSPF is the link-state interior gateway protocol for IPv4 (RFC 2328). NOS runs it per routing table: each OSPF instance discovers neighbours on the interfaces you attach it to, floods link-state advertisements (LSAs), computes shortest paths, and installs the resulting routes in its routing table. For IPv6, see [OSPFv3](ospfv3.md).

- [How OSPF is configured in NOS](#how-ospf-is-configured-in-nos)
- [Common operations](#common-operations)
  - [Run OSPF between two routers](#run-ospf-between-two-routers)
  - [Check neighbours, the LSDB and routes](#check-neighbours-the-lsdb-and-routes)
  - [Advertise a loopback](#advertise-a-loopback)
  - [Run OSPF on a LAN segment](#run-ospf-on-a-lan-segment)
  - [Authenticate a link, and change its key](#authenticate-a-link-and-change-its-key)
  - [Redistribute static routes (ASBR)](#redistribute-static-routes-asbr)
  - [Add a second area (ABR)](#add-a-second-area-abr)
  - [Make an area a stub, and summarize it with ranges](#make-an-area-a-stub-and-summarize-it-with-ranges)
  - [Redistribute from inside a stub-like area (NSSA)](#redistribute-from-inside-a-stub-like-area-nssa)
  - [Restart without dropping routes (RFC 3623)](#restart-without-dropping-routes-rfc-3623)
  - [Stop running OSPF](#stop-running-ospf)
- [Features and behaviour](#features-and-behaviour)
- [Configuration reference](#configuration-reference)

The examples use the two-router lab described in the [README](../README.md#conventions-used-in-these-pages): router-a (10.50.0.2) and router-b (10.50.0.3) share `10.50.0.0/24` on `eth0`, which is in routing table `rt1`. The CLI sessions run on router-a. The REST calls make the same change on router-b, so that together the two blocks configure both ends of a link; for those calls `$B` points at router-b (`B=https://10.50.0.3:8080`) and `$C` uses a client certificate obtained from router-b, as shown in [The REST API](../api.md#getting-a-client-certificate).

Every CLI command and REST path on this page matches what the shell and the API accept, and each configuration follows one that the end-to-end test suite runs against real routers. The sample outputs are not reproduced here yet; see [The CLI](../cli.md#operational-commands) for the general shape of `show` output.

## How OSPF is configured in NOS

The configuration has three levels, plus the places you attach it:

- An **OSPF instance** (`ospf instance <name>`) has a router ID and belongs to one routing table: `set routing-table <table> ospf-instance <name>`. Until a routing table refers to it, the instance does nothing. A routing table has at most one OSPF instance, and an instance belongs to at most one table.
- An **area** (`area <area-id>`, dotted quad, `0.0.0.0` for the backbone) lives inside an instance.
- A **profile** (`profile <name>`) lives inside an area and holds the per-link settings: hello and dead intervals, cost, priority, network type, authentication and an MTU override. Profile names are unique across the whole configuration, not just within their area.
- You run OSPF on a link by **attaching a profile** to it by name. The link then joins the instance and area the profile is declared in. Three kinds of link take a profile:
  - a subinterface, such as `eth0.0` or `eth0.100`: `set interface eth0 ospf <profile>`. It runs as point-to-point by default.
  - a broadcast domain's own address (its SVI): `set ospf <profile>` inside `edit broadcast domain <name>`. It runs as a broadcast network, with a DR and BDR, by default.
  - a loopback, `loopback-<table>`: `set interface loopback-<table> ospf <profile>`. Its addresses are advertised as stub networks; no neighbour is ever formed on it.

  Each of these must also have `routing-table` set, to the table the instance belongs to.

OSPF routes appear in `show route` with the source `ospf`. When the same prefix is also known from another source, the other source wins: connected, then static, then BGP, then OSPF.

How the OSPF implementation works internally is described in [OSPF internals](ospf-internals.md).

## Common operations

### Run OSPF between two routers

This creates instance `o1` with router ID 1.1.1.1, a backbone area with profile `p1`, links the instance to `rt1`, and runs OSPF on `eth0.0`:

```
configure ospf1
edit ospf instance o1
set router-id 1.1.1.1
edit area 0.0.0.0
edit profile p1
set hello-interval 10
set dead-interval 40
top
set routing-table rt1 ospf-instance o1
set interface eth0 ospf p1
diff
commit
```

`edit` creates the instance, area and profile as it moves into them. The hello and dead intervals shown are the defaults and can be left out; they are set here to show where they go. `set interface eth0 ospf p1` means the untagged subinterface, `eth0.0`, which already has an address and `routing-table rt1`.

Over REST, the instance is created whole, then linked and attached. This configures router-b, with router ID 2.2.2.2 and the same profile:

```sh
$C -X POST $B/v1/transactions/ospf1
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"o1","router_id":"2.2.2.2","areas":[{"area_id":"0.0.0.0","profiles":[{"name":"p1","hello_interval":10,"dead_interval":40}]}]}' \
  $B/v1/transactions/ospf1/ospf-instance/o1
$C -X PUT -H 'Content-Type: application/json' -d '"o1"' $B/v1/transactions/ospf1/routing-table/rt1/ospf-instance
$C -X PUT -H 'Content-Type: application/json' -d '"p1"' $B/v1/transactions/ospf1/interface/eth0/subinterface/0/ospf-profile
$C -X POST $B/v1/transactions/ospf1/commit
```

Within a few seconds both routers reach `Full`.

### Check neighbours, the LSDB and routes

```
show ospf neigh
show ospf database
show route rt1
```

- `show ospf neigh` prints one line per link and neighbour: the link, its area, the link's state (`point-to-point`, or `dr`/`backup`/`dr-other`/`waiting` on a LAN), the neighbour's router ID and state (`Init`, `2-Way`, `ExStart`, `Exchange`, `Loading`, `Full`), when its last Hello arrived, the timers and priorities, and the DR and BDR.
- A bad LSA inside a Link State Update is discarded alone (RFC 2328 section 13): a wrong checksum, an unknown type or an unparseable body skips that LSA, the others in the packet are processed and acked, and the sender retransmits only the bad one. The daemon logs `lsu: discarded LSAs that failed to decode` (rate limited) with the count and the last error. A header whose length cannot be framed still drops the whole packet.
- `show ospf database` lists the header of every LSA held, per area: its type (1 router, 2 network, 3 summary, 4 ASBR summary, 5 AS-external, 9/10/11 opaque, see [Opaque LSAs](#features-and-behaviour)), link-state ID, advertising router, sequence number, age and checksum.
- Both cover every OSPF instance on the router.

Over REST, `GET /v1/ospf/neighbors` and `GET /v1/ospf/database` return the same data as JSON, one entry per instance:

```sh
$C $B/v1/ospf/neighbors | jq .
$C $B/v1/ospf/database | jq .
$C $B/v1/routes/rt1
```

### Advertise a loopback

A loopback is named after its routing table, `loopback-<table>`. Give it an address, put it in the table, and attach a profile; its address is then advertised to the whole area.

```
configure lo
edit interface loopback-rt1
set routing-table rt1
set address 192.0.2.1/32
set ospf p1
commit
```

The same on router-b, with 192.0.2.2/32, over REST:

```sh
$C -X POST $B/v1/transactions/lo
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"loopback-rt1","addresses":[{"address":"192.0.2.2/32","label":null}],"routing_table":"rt1","ospf_profile":"p1","subinterfaces":[]}' \
  $B/v1/transactions/lo/interface/loopback-rt1
$C -X POST $B/v1/transactions/lo/commit
```

Each router now reaches the other's loopback through OSPF, with source `ospf`:

```
show route rt1 192.0.2.2            (on router-a)
$C $B/v1/routes/rt1/192.0.2.1       (on router-b)
```

### Run OSPF on a LAN segment

On a multi-access segment, OSPF elects a designated router (DR) and a backup (BDR), and every router forms a full adjacency only with those two. In NOS a LAN segment is a broadcast domain, and OSPF runs on the broadcast domain's own address (its SVI; see [L2 switching](../README.md#per-protocol-guides)). Here `eth0` carries broadcast domain `bd1` tagged with VLAN 400, the domain's SVI gets an address in `rt1`, and profile `p-lan` gives router-a priority 10 so it becomes the DR:

```
configure lan
edit ospf instance o1 area 0.0.0.0 profile p-lan
set priority 10
top
edit broadcast domain bd1
set address 203.0.113.1/24
set routing-table rt1
set ospf p-lan
top
edit switching-profile sp1
top
set switching-profile sp1 broadcast-domain bd1 tag dot1q 400
set interface eth0 switching-profile sp1
commit
```

Router-b does the same with the default priority of 1 and SVI address 203.0.113.2/24:

```sh
$C -X POST $B/v1/transactions/lan
$C -X PUT -H 'Content-Type: application/json' -d '{"name":"p-lan"}' \
  $B/v1/transactions/lan/ospf-instance/o1/area/0.0.0.0/profile/p-lan
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"bd1","addresses":[{"address":"203.0.113.2/24","label":null}],"routing_table":"rt1","ospf_profile":"p-lan"}' \
  $B/v1/transactions/lan/broadcast-domain/bd1
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"sp1","members":[{"broadcast_domain":"bd1","tag":{"Dot1q":400}}]}' \
  $B/v1/transactions/lan/switching-profile/sp1
$C -X PUT -H 'Content-Type: application/json' -d '"sp1"' $B/v1/transactions/lan/interface/eth0/switching-profile
$C -X POST $B/v1/transactions/lan/commit
```

After the wait interval (the dead interval, 40 seconds by default), the election settles. `show ospf neigh` then shows `bd1` with link state `dr` on router-a and `backup` on router-b, and both neighbours `Full`:

```
show ospf neigh
```

A profile's network type follows the link by default: point-to-point on a subinterface, broadcast on a broadcast domain. `set network-type point-to-point|broadcast|point-to-multipoint` in the profile forces one on every link that uses it.

### Run point-to-multipoint (RFC 2328 section 9.5)

- Use it when one interface reaches several routers that don't need a DR, such as a partial mesh over a shared segment.
- Set `network-type point-to-multipoint` in the profile. Both ends of every link must use it.
- Behaviour:
  - Hello is multicast to 224.0.0.5, with no DR/BDR election and no network-mask check.
  - Each neighbor found forms its own adjacency and reaches `Full`.
  - The router originates one point-to-point link per `Full` neighbor and a single /32 stub for its own interface address, not the subnet. A neighbor's address shows up as a /32 OSPF route.
- Hello and dead intervals keep the usual 10 and 40 seconds. Neighbors are discovered over multicast; there is no static neighbor list, so non-broadcast media (NBMA) are not supported.
- Not available for OSPFv3: the commit is refused.
- Check with `show ospf neigh`: one row per neighbor, interface state `PointToPoint`.

### Authenticate a link, and change its key

Authentication is set on the profile, so it applies to every link using that profile, and both ends must match. HMAC-SHA keys (RFC 5709) are the usual choice:

```
configure auth
set admin key ospf-p1-key1 secret s3cret-one
edit ospf instance o1 area 0.0.0.0 profile p1
set crypto-key 1 hmac-sha256 ospf-p1-key1
set crypto-key 1 current
show this
commit
```

Secrets are not typed into the profile: they live in the admin keystore under a label (`set admin key <label> secret <value>`), and the key names the label. A key has a key ID (0 to 255), an algorithm (`md5`, `hmac-sha1`, `hmac-sha256`, `hmac-sha384` or `hmac-sha512`) and the label of an admin key whose secret is 1 to 80 bytes. The secret reads `<hidden>` in `show config`, `GET /v1/config` and the logs; `show config` displays the label. The commit fails if a label does not exist, and deleting an admin key an OSPF profile still references fails it too. Exactly one key must be `current`: it signs what the router sends. Every configured key is accepted on receive. The same on router-b over REST, where `auth` is replaced whole:

```sh
$C -X POST $B/v1/transactions/auth
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"label":"ospf-p1-key1","secret":"s3cret-one"}' $B/v1/transactions/auth/admin/key/ospf-p1-key1
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"Crypto":{"keys":[{"key_id":1,"algorithm":"HmacSha256","key":"ospf-p1-key1","is_current":true}]}}' \
  $B/v1/transactions/auth/ospf-instance/o1/area/0.0.0.0/profile/p1/auth
$C -X POST $B/v1/transactions/auth/commit
```

To replace a secret in place, set the same label to a new value on both routers (`set admin key ospf-p1-key1 secret <new>`): the link restarts and the adjacency comes back with the new secret. Breaking change: a `config.yaml` saved with an inline `password` or `key` no longer loads; move the secret to an admin key and reference its label.

To change the key without dropping the adjacency, do it in three commits, on both routers each time: add the new key; once both have it, make it current; once both use it, delete the old one.

```
configure roll1
set admin key ospf-p1-key2 secret s3cret-two
set ospf instance o1 area 0.0.0.0 profile p1 crypto-key 2 hmac-sha256 ospf-p1-key2
commit
configure roll2
set ospf instance o1 area 0.0.0.0 profile p1 crypto-key 2 current
commit
configure roll3
edit ospf instance o1 area 0.0.0.0 profile p1
delete crypto-key 1
commit
```

Over REST, the same three steps are three `PUT`s of the whole `auth` value (both keys with key 1 current, both keys with key 2 current, then key 2 alone).

**Replay protection across restarts (RFC 7474).** With ordinary crypto authentication, a packet captured before a router restarts could be replayed after it. `set extended-sequence-numbers enable` in the profile switches to RFC 7474 authentication: the sequence number includes a boot counter kept on disk, and the digest also covers the sender's address. It needs crypto keys that are all HMAC-SHA (not MD5), and both ends must enable it: a router using it and one not using it do not accept each other's packets. It also allows key IDs above 255 (up to 65535).

```
configure ext
set ospf instance o1 area 0.0.0.0 profile p1 extended-sequence-numbers enable
commit
```

```sh
$C -X POST $B/v1/transactions/ext
$C -X PUT -H 'Content-Type: application/json' -d 'true' \
  $B/v1/transactions/ext/ospf-instance/o1/area/0.0.0.0/profile/p1/extended-sequence-numbers
$C -X POST $B/v1/transactions/ext/commit
```

The other two authentication modes are a plain-text password of up to 8 bytes (`set simple-password <label>`, the label of an admin key of 1 to 8 bytes), which only protects against misconfiguration, and none (`delete auth`), the default.

### Redistribute static routes (ASBR)

`redistribute ospf` on a routing table advertises the table's static routes into its OSPF instance, which makes this router an AS boundary router (ASBR). The table needs both a static routing instance and an OSPF instance:

```
configure asbr
edit static-routing-instance s1
set route 198.51.100.0/24 gateway 10.50.0.98
top
set routing-table rt1 static-routing-instance s1
set routing-table rt1 redistribute ospf
commit
```

Router-b receives an AS-external LSA (type 5) and installs the route, which you can check on router-b with:

```
show ospf database          (look for type 5, advertising-router 1.1.1.1)
show route rt1 198.51.100.1
```

The REST equivalent of the redistribute rule, in a transaction `asbr` opened and committed as in the earlier examples (the static routing instance is created the same way as in [The REST API](../api.md#changing-configuration-transactions)):

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"from":"Static","to":"Ospf","policy":null}' \
  $B/v1/transactions/asbr/routing-table/rt1/redistribute/ospf
```

Add `policy <name>` to the command (`"policy": "<name>"` in the JSON) to filter what is redistributed through a routing policy; without it, every static route is redistributed. See [Routing policy](../README.md#per-protocol-guides). Deleting the rule (`delete routing-table rt1 redistribute ospf`, or `DELETE …/routing-table/rt1/redistribute/ospf` over REST) withdraws the routes from the other routers within about 15 seconds.

A routing table keeps one `redistribute` rule per target, so it can redistribute the same static routes into BGP, OSPF and [OSPFv3](ospfv3.md#redistribute-static-routes-asbr) at once, each with its own `policy`. Deleting one rule leaves the others.

#### Choose the metric and metric type of redistributed routes

By default every redistributed route is advertised with metric 20 and metric type 1. Set `metric` (1 to 16777215) and `metric-type` (1 or 2) on the rule to change it; both are valid with `to ospf` only:

```
set routing-table rt1 redistribute ospf metric 50
set routing-table rt1 redistribute ospf metric-type 2
```

```sh
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"from":"Static","to":"Ospf","policy":null,"metric":50,"metric_type":2}' \
  $B/v1/transactions/asbr/routing-table/rt1/redistribute/ospf
```

- **Type 1** (default): other routers rank the route by the metric plus their distance to this router. Use it when the same prefix is reachable through several exits of comparable cost and you want the nearest one.
- **Type 2**: other routers compare the metric first; their distance to this router only breaks a tie. Use it when the external cost dominates and the internal distance should not matter.
- **Check it.** On any router, `GET /v1/ospf/database` lists each type-5 LSA with `external_metric` and `external_type2` (the E bit). Changing either value re-advertises the LSA with a higher sequence number (`ospf lsa originated` in the log).
- **Upgrade note.** Redistributed routes used to be advertised with metric 0 on the wire; they now carry 20 unless you set a metric, so external costs on other routers rise by 20.

### Add a second area (ABR)

A router attached to two or more areas is an area border router (ABR): it advertises each area's prefixes into the others as summary LSAs (type 3). There is no switch to turn this on; declaring a second area and attaching a profile from it is enough. Here router-a's loopback moves into area 0.0.0.1, while `eth0.0` stays in the backbone:

```
configure abr
edit ospf instance o1 area 0.0.0.1 profile p-area1
top
set interface loopback-rt1 ospf p-area1
commit
```

Router-b, which is only in the backbone, now learns 192.0.2.1/32 from router-a's summary LSA. On router-b:

```
show ospf database          (look for type 3, link-state-id 192.0.2.1, advertising-router 1.1.1.1)
show route rt1 192.0.2.1
```

Over REST, in a transaction `abr`, the new area is one `PUT` and the loopback's profile another:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"area_id":"0.0.0.1","profiles":[{"name":"p-area1"}]}' \
  $B/v1/transactions/abr/ospf-instance/o1/area/0.0.0.1
$C -X PUT -H 'Content-Type: application/json' -d '"p-area1"' \
  $B/v1/transactions/abr/interface/loopback-rt1/ospf-profile
```

### Carry external routes across areas

An ABR copies the type-5 LSAs it learns in one area into every other area that may hold them. There is nothing to configure:

- **When it happens.** Any router in two or more areas does it on its 2-second tick, for type-5 LSAs from other routers: live ones, and ones at maximum age so that a withdrawal travels too. The ABR's own type-5 LSAs are installed in each of its areas when it originates them.
- **Where it does not.** Stub areas and NSSAs never get a copy; use `area-type nssa` to redistribute from inside one.
- **Check it.** On the ABR the log says `ospf external lsa copied across areas` with `from_area`/`to_area`. On a router in the other area, `GET /v1/ospf/database` lists the type-5 LSA with the original advertising router, and `show route rt1 <prefix>` shows `[ospf]` at the distance to that router plus the LSA metric (20 by default).
- **Remove it.** Clearing `redistribute ospf` on the ASBR ages its LSA out; the ABR carries the flush into the other areas and every router drops the route within seconds.

### Join an area to the backbone through another area (virtual link)

An area must touch the backbone (0.0.0.0). When it can't, a virtual link (RFC 2328 §15) runs a backbone adjacency across a normal transit area between two of its ABRs. Here router-c has only area 0.0.0.1 (shared with router-b, which is also in the backbone) and its loopback in area 0.0.0.2:

```
configure vlink
set ospf instance o1 area 0.0.0.1 virtual-link 2.2.2.2
commit
```

on router-c (`2.2.2.2` is router-b's router ID), and the mirror image on router-b (`virtual-link 3.3.3.3`). Over REST, `PUT {"router_id":"2.2.2.2"}` on `…/ospf-instance/o1/area/0.0.0.1/virtual-link/2.2.2.2`.

- **When it comes up.** Each end checks every 2 seconds whether the other end is reachable inside the transit area. If it is, the link comes up with that path's cost (`ospf virtual link up link=vlink-0.0.0.1-2.2.2.2 neighbor=… local=… cost=…`); if not, it goes down (`ospf virtual link down`). A cost change alone doesn't restart the adjacency; a new address for the far end does.
- **What it runs.** A backbone adjacency, unicast between the two ends' transit-area addresses: Hellos with mask 0, no DR, the link's own timers and authentication (`hello-interval`, `dead-interval`, `simple-password`, `crypto-key` on the `virtual-link`, as on a profile). Both ends must agree, as on any link.
- **Check it.** `show ospf neigh` lists `vlink-<transit-area>-<router-id>` in area 0.0.0.0, `Full`. In `GET /v1/ospf/database`, each end's area-0 router LSA lists the other in `virtual_links`, and its router LSA in the transit area has the V bit (`router_flags` & 4). Router-c counts as an ABR: its area-0.0.0.2 summaries reach the backbone over the link.
- **Remove it.** `delete … virtual-link <router-id>`. The other end drops the neighbour after its dead interval (`ospf neighbor state changed to down link=vlink-…`) unless it is removed there too.
- **Routes across it.** Backbone routers route to the detached area through the link: router-a (backbone only) installs router-c's loopback with router-b as gateway, and router-b with router-c's transit-area address as gateway (`added route prefix=<loopback> gateway=… source=Some(Ospf)` in `nos-ribd`'s log, `GET /v1/routes/<table>`). Router-c, likewise, routes to the backbone through router-b and advertises it into area 0.0.0.2.
- **When it goes down,** those routes go with it, even though the transit area still carries router-c's summaries: a router attached to the backbone only uses the backbone's summaries (RFC 2328 §16.2). The transit area is only used to shorten a route the backbone already has (§16.3).

### Make an area a stub, and summarize it with ranges

A stub area (RFC 2328 §3.6) carries no AS-external LSAs; its ABR sends a default route into it instead. Here `eth0.0` is in area 0.0.0.1 on both routers, router-b is the ABR (its loopback is in the backbone), and router-a is inside the stub area. Every router on the area's links must set the same type, or their Hellos are dropped (`dropping ospf hello with mismatched e-bit`). Changing it restarts the area's adjacencies.

```
configure stub
set ospf instance o1 area 0.0.0.1 area-type stub
commit
```

```sh
$C -X POST $B/v1/transactions/stub
$C -X PUT -H 'Content-Type: application/json' -d '"Stub"' \
  $B/v1/transactions/stub/ospf-instance/o1/area/0.0.0.1/area-type
$C -X POST $B/v1/transactions/stub/commit
```

- router-a then has `0.0.0.0/0 via 10.50.0.3 [ospf]` in `show route rt1`, at the default route's cost (`stub-default-cost`, 1 unless set on the ABR's area) plus its distance to the ABR, and no type-5 LSA in `show ospf database`.
- `area-type totally-stubby` on the ABR's area also stops the other summaries: the default is the only type-3 LSA left in the area. The routers inside may use `stub` or `totally-stubby`, which are the same for them.
- The backbone (0.0.0.0) can't be a stub.

An area range (RFC 2328 §3.5) is set on the area whose prefixes it covers, on its ABR. To advertise router-b's backbone loopbacks into area 0.0.0.1 as one prefix:

```
configure range
set ospf instance o1 area 0.0.0.0 range 203.0.113.120/29
commit
```

```sh
$C -X POST $B/v1/transactions/range
$C -X PUT -H 'Content-Type: application/json' -d '{"cidr":"203.0.113.120/29"}' \
  $B/v1/transactions/range/ospf-instance/o1/area/0.0.0.0/range/203.0.113.120%2F29
$C -X POST $B/v1/transactions/range/commit
```

- The other areas get one type-3 LSA for the range, at the largest cost among the prefixes it covers, instead of one per prefix. A range covering no prefix of the area is not advertised.
- The ABR installs `203.0.113.120/29 discard [ospf]` in its own routing table (a kernel blackhole route), so traffic to an unused address of the range is dropped there instead of looping. More specific routes still win.
- `set … range 203.0.113.120/29 not-advertise` hides every prefix the range covers from the other areas, with no discard route. `delete ospf instance o1 area 0.0.0.0 range 203.0.113.120/29` removes the range.

### Redistribute from inside a stub-like area (NSSA)

A not-so-stubby area (RFC 3101) keeps AS-external LSAs out like a stub area, but a router inside it may still redistribute static routes. Here area 0.0.0.1 is an NSSA, router-c is inside it and redistributes, and router-a and router-b are its ABRs. Every router on the area's links must set `nssa`, or their Hellos are dropped (`dropping ospf hello with mismatched n-bit`).

```
configure nssa
set ospf instance o1 area 0.0.0.1 area-type nssa
commit
```

```sh
$C -X POST $B/v1/transactions/nssa
$C -X PUT -H 'Content-Type: application/json' -d '"Nssa"' \
  $B/v1/transactions/nssa/ospf-instance/o1/area/0.0.0.1/area-type
$C -X POST $B/v1/transactions/nssa/commit
```

- router-c's redistributed routes become type-7 LSAs, flooded only inside the NSSA. Their forwarding address is one of router-c's own addresses in the area.
- One ABR, the translator, turns them into type-5 LSAs of its own for the other areas. It is the ABR with the highest router ID, unless another ABR has `nssa-translate-always enable`. Each ABR logs `ospf nssa translator role changed area=0.0.0.1 translating=true|false`.
- `area-type nssa-no-summary` on the ABRs also replaces their other type-3 LSAs in the area with one default route.
- `set ospf instance o1 area 0.0.0.1 nssa-default-originate enable` on an ABR originates a `0.0.0.0/0` type-7 LSA into the NSSA, at `stub-default-cost`. It is never translated.
- An ABR that redistributes itself originates a type-7 LSA into the NSSA and its own type-5 LSA elsewhere.

### Restart without dropping routes (RFC 3623)

Set a grace period on the instance so that its neighbours keep the adjacency and this router's routes while its OSPF daemon restarts:

```
configure gr
set ospf instance o1 graceful-restart grace-period 120
commit
```

```sh
$C -X POST $B/v1/transactions/gr
$C -X PUT -H 'Content-Type: application/json' -d '120' $B/v1/transactions/gr/ospf-instance/o1/graceful-restart-grace-period
$C -X POST $B/v1/transactions/gr/commit
```

How it behaves:

- **Restarting router.** Only a planned restart announces a grace period: `nos-ospfd` receiving SIGTERM sends a Grace-LSA to every Full neighbour on every link (log `ospf graceful restart: grace-lsa sent`), keeps the LSAs it originated instead of withdrawing them, then exits and is restarted by the watchdog. Stopping the router or removing the instance (SIGINT) announces nothing and withdraws the LSAs as usual. A crash announces nothing either.
- **Helping neighbour.** Every OSPF instance helps; there is nothing to enable. On a Grace-LSA from a Full neighbour it logs `ospf helper: grace period entered`, keeps that neighbour Full through missing Hellos and through Hellos that don't list it yet, keeps the neighbour's LSAs (and, as DR, keeps it in the network LSA), so its routes stay installed. The Grace-LSA is acknowledged but never stored or passed on.
- **End of the grace period.** When the restarted router's adjacency is Full again, the helper logs `ospf helper: neighbor reformed, exiting grace early`. If it never comes back, the helper logs `ospf helper: grace period expired` and the ordinary dead interval applies from then on.
- **Other vendors.** NOS advertises opaque-LSA support (the O bit), so a third-party router's Grace-LSA is helped like a NOS one (tested with FRR's `graceful-restart prepare ip ospf`). As the restarting router, NOS has been tested with NOS helpers only.
- `delete ospf instance o1 graceful-restart grace-period` turns it off.

### Hide transit-only networks (RFC 6860)

Keep the subnets of the links between routers out of everyone's routing table, while still routing through them:

```
configure ps
set ospf instance o1 prefix-suppression
commit
```

```sh
$C -X POST $B/v1/transactions/ps
$C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/ps/ospf-instance/o1/prefix-suppression
$C -X POST $B/v1/transactions/ps/commit
```

How it behaves:

- **Point-to-point links.** The router stops advertising the link's subnet. Set it on both ends: each end advertises the subnet on its own.
- **LAN segments.** When this router is the DR, its network LSA carries a `/32` mask, and other routers install no route for the segment. The segment's other routers don't need the setting.
- **Loopbacks** stay advertised.
- **Every router** ignores a network LSA with a `/32` mask when building routes and doesn't summarize it into other areas, whatever its own setting. A router without RFC 6860 installs a `/32` route to the DR's address instead.
- **Check it** on another router: `show route rt1` no longer lists the link's subnet with source `ospf`.
- `delete ospf instance o1 prefix-suppression` turns it off.

### Drain traffic away from a router (RFC 6987 stub router)

Make other routers avoid this one for transit, while its own prefixes stay reachable. Three independent settings:

```
configure drain
set ospf instance o1 max-metric router-lsa administrative
set ospf instance o1 max-metric router-lsa on-startup 300
set ospf instance o1 max-metric router-lsa on-shutdown 3
commit
```

```sh
$C -X POST $B/v1/transactions/drain
$C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/drain/ospf-instance/o1/max-metric-administrative
$C -X PUT -H 'Content-Type: application/json' -d '300' $B/v1/transactions/drain/ospf-instance/o1/max-metric-on-startup
$C -X PUT -H 'Content-Type: application/json' -d '3' $B/v1/transactions/drain/ospf-instance/o1/max-metric-on-shutdown
$C -X POST $B/v1/transactions/drain/commit
```

How it behaves:

- **What changes.** The router's router LSA gives every link to a neighbour or a LAN segment the cost 65535. Its stub links (point-to-point subnets, loopbacks) keep their cost. Other routers send traffic through it only when there is no other path, and never use it as a loop-free alternate.
- **`administrative`.** On until removed: drain the router before maintenance, `delete ospf instance o1 max-metric router-lsa administrative` to bring it back.
- **`on-startup <seconds>`** (5 to 86400). For this long after `nos-ospfd` starts, so traffic waits until its routes have converged. It takes effect on the next start, not when set. After a graceful restart it is skipped, since the helpers kept the old topology. `delete` ends a period still running.
- **`on-shutdown <seconds>`** (1 to 3). When `nos-ospfd` stops (not a graceful restart), it first advertises the max-metric router LSA and waits this long before withdrawing its LSAs, so traffic moves away before the router disappears. It is skipped when the router LSA changed in the last 5 seconds, or when the router is already a stub router. 3 seconds is the most that fits in the watchdog's 10-second stop budget beside the withdrawal; the `watchdog` service in `docker-compose.yml` has `stop_grace_period: 15s` for the same reason.
- **Check it.** The router logs `ospf stub router max-metric changed active=true reason="administrative"` (or `"on-startup"`, `"on-shutdown"`), then `active=false` with `reason="expired"` or `"cleared"`. On another router, the route through it shows a metric of 65535 or more in `show route`, and its backup next hop through it is gone.
- **Router Information.** Every router advertises *stub router support* in its Router Information LSA, whatever the setting.

### Keep a router out of transit for good (RFC 8770 host router)

For a router that should only ever be a destination (a server, a route reflector or a controller running OSPF), not a path between other routers:

```
configure host
set ospf instance o1 host-router
commit
```

```sh
$C -X POST $B/v1/transactions/host
$C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/host/ospf-instance/o1/host-router
$C -X POST $B/v1/transactions/host/commit
```

How it behaves:

- **What it advertises.** The H-bit in its router LSA, in every area, and every link to a neighbour or LAN segment at cost 65535, as with [`max-metric router-lsa administrative`](#drain-traffic-away-from-a-router-rfc-6987-stub-router). Its stub links keep their cost, so its own prefixes stay reachable.
- **Other NOS routers** never route through a router with the H-bit, even when it is the only path, and never use it as a loop-free alternate. They honour the bit only while every router in the area advertises *host router support* in its Router Information LSA; NOS always does.
- **With a router that doesn't support it** in the area (FRR, for example), the bit is ignored everywhere in that area, and the 65535 costs alone steer traffic away: the router is still used when it is the only path.
- **Not with redistribution.** A host router is not an ASBR: a commit with both `host-router` and `redistribute … to ospf` on its routing table is refused.
- **Check it.** Every router logs `ospf host-bit state changed area=0.0.0.0 honoured=true host_routers=1` when the bit appears in the area (`honoured=false` if some router lacks support). On another router, routes through the host router disappear from `show route` and so do backup next hops through it.
- `delete ospf instance o1 host-router` turns it off.

### Protect links that have no loop-free alternate (RFC 7490 remote LFA)

On a ring of five or more routers, a destination behind a neighbour often has no [loop-free alternate](#features-and-behaviour): every other neighbour's shortest path to it comes back through this router. A remote LFA tunnels the traffic to a router further away (the *PQ node*) that reaches the destination without the failed link. Turn it on on **every** router of the area:

```
configure rlfa
set ospf instance o1 remote-lfa
commit
```

```sh
$C -X POST $B/v1/transactions/rlfa
$C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/rlfa/ospf-instance/o1/remote-lfa
$C -X POST $B/v1/transactions/rlfa/commit
```

How it behaves:

- **The tunnel device.** The routing table gets an IP-in-IP device, `rlfa<table-id>` (e.g. `rlfa100`), in its VRF. It carries this router's tunnel backups out, and decapsulates other routers' tunnelled traffic into the table, so that this router can be a PQ node. Each router needs it, which is why the setting goes on every router.
- **The PQ node** is a router that this router reaches without the protected link (P-space) and that reaches the neighbour without it (Q-space), and that advertises a `/32` stub, its loopback: the tunnel goes to that address. Among several, the cheapest path wins. Give every router a loopback in OSPF.
- **Which routes.** Only routes with one next hop over a point-to-point link and no basic loop-free alternate. Equal-cost routes and routes with a basic alternate are left alone.
- **Failover.** The backup is installed in the kernel at the backup metric, like a basic alternate, so traffic moves to the tunnel as soon as the primary route is withdrawn (its link goes down). Once OSPF reconverges, the route moves to its new path and the tunnel backup goes away.
- **Check it.** `show route rt1` shows `backup tunnel <pq-loopback>` after the primary; over REST, the candidate has `backup_tunnel: true`. `nos-ribd` logs `created remote lfa tunnel device` and `added route … backup=true … tunnel=true`.
- `delete ospf instance o1 remote-lfa` turns it off and deletes the device.

Things to know:

- **Security.** The device accepts IP-in-IP from any source to any address of the routing table. Filter protocol 4 at the edge of the network if that matters.
- **`rp_filter`.** A PQ node must not run strict reverse-path filtering (`net.ipv4.conf.*.rp_filter = 1`) on the device: loose (`2`, most distributions' default) or off works.
- **One routing table per router** can use it: decapsulated traffic lands in the first such device's table.
- **Not done:** node protection, protection of LAN links, the extended P-space (RFC 7490 §4.2), MPLS/LDP or segment-routing tunnels, and OSPFv3. Interoperates with other NOS routers only: another vendor's router can be a PQ node only if it decapsulates plain IP-in-IP sent to its loopback.

### Stop running OSPF

- On one link: `delete interface eth0 ospf` (or `delete ospf` inside the interface, subinterface or broadcast domain). Over REST, `DELETE …/interface/eth0/subinterface/0/ospf-profile`.
- For the whole routing table: `delete routing-table rt1 ospf-instance`. The instance stays configured but stops running.
- Entirely: `delete ospf instance o1`, after removing every reference to it and to its profiles, or the commit is refused.

When OSPF stops cleanly (and no [graceful restart](#restart-without-dropping-routes-rfc-3623) was announced), the router first withdraws the LSAs it originated, so its neighbours remove its routes within seconds instead of waiting for them to age out.

## Features and behaviour

**Neighbours and adjacencies (RFC 2328 §10).** Hellos are sent every hello interval to 224.0.0.5. A Hello whose hello interval or dead interval differs from the local profile's is dropped, so a timer mismatch shows up as a neighbour that never appears, and the log says `dropping ospf hello with mismatched hello-interval` (or `dead-interval`). A neighbour that NOS hears nothing from for the dead interval is removed. Once an adjacency has started (`ExStart` or later), any authenticated packet from the neighbour (a database description, request, update or acknowledgement) counts as hearing from it, not only a Hello (RFC 4222), so a busy neighbour whose Hellos are lost is not dropped. The "last Hello" column of `show ospf neigh` still counts Hellos only. Sending and receiving Hellos also takes priority over the periodic retransmission of LSAs. On a point-to-point link the two routers always form a full adjacency. On a LAN, every router forms a full adjacency with the DR and the BDR only; two routers that are neither stay at `2-Way`, which is normal.
- NOS joins 224.0.0.6 (AllDRouters) only while it is DR or Backup on a broadcast link, leaves when demoted and never joins it on point-to-point or point-to-multipoint links. Look for `ospf all-drouters membership changed ... joined=true|false`; a failed update logs `ospf all-drouters membership change failed` and is retried on the next election pass. On broadcast links NOS floods LSUs and sends delayed LSAcks by multicast (RFC 2328 §13.3/§13.5): to 224.0.0.5 as DR or Backup, to 224.0.0.6 otherwise (`ospf lsu flood destination changed ... dest=...`). DBD, LSR, retransmissions, Grace-LSAs and everything on point-to-point links stay unicast.

**DR/BDR election (RFC 2328 §9.4).** The highest priority wins, then the highest router ID. A router with priority 0 never becomes DR or BDR. An elected DR keeps its role when a router with a higher priority or router ID joins later; the newcomer takes over only if the DR goes away. Priority has no effect on point-to-point links.

**Shortest paths and costs (RFC 2328 §16).** Each link's cost is the `cost` of its profile (1 by default); a route's metric is the sum of the costs along the path. When the LSDB changes, routes are recomputed right away (a 50 ms hold-down batches a burst of LSAs into one computation) and pushed to the routing table; a 2-second poll is only a safety net. A lost local link (interface deleted, set down, or carrier lost) drops its neighbours at once: `nos-ospfd` follows the link state `nos-interfaced` streams and logs `ospf link kernel interface down link=eth0.0 reason=absent|admin-down|no-carrier`, then `ospf link kernel interface up` when it returns (a recreated device gets a fresh socket). A failure beyond the local link (a dead remote end, a switch in between) still takes the dead interval (BFD is #190). A restarting `nos-interfaced` or `nos-ribd` tears no link down: the link keeps its running address, VRF and bridge (`ospf link resolution failed, keeping running link`) while the configuration still demands it. The neighbour that loses a link re-originates its LSA on a 2-second tick (never faster than every 5 seconds per LSA). Routes are installed with source `ospf`, and their metric is what BGP uses as the IGP cost to a next hop.

**Equal-cost multipath (RFC 2328 §16.1).** When a destination is reachable over several paths with the same lowest metric, NOS keeps all of their next hops and installs one multipath kernel route; the kernel spreads flows across them. It is automatic, with no configuration. `show route` lists every next hop: `* via 203.0.113.2, 203.0.113.6 [ospf]`. A next hop whose link goes down stays in the multipath route until OSPF reconverges (the kernel keeps it unless `ignore_routes_with_linkdown` is set).

**Loop-free alternates (RFC 5286).** For each OSPF route, NOS also looks for a backup next hop through another neighbour (not one of the route's own next hops) whose own shortest path to the destination does not come back through this router. A link that costs 65535 in either direction (a [stub router](#drain-traffic-away-from-a-router-rfc-6987-stub-router) at either end) is never used for one. If there is one, it is installed in the kernel alongside the primary, at a worse metric, so traffic moves to it as soon as the primary next hop is withdrawn. It is computed automatically, with no configuration. `show route` shows it after the primary: `* via 203.0.113.2 [ospf] backup 203.0.113.3`. Only link protection is provided (no node protection). Where there is none, a [remote LFA](#protect-links-that-have-no-loop-free-alternate-rfc-7490-remote-lfa) can tunnel around the failure.

**Authentication (RFC 2328 Appendix D, RFC 5709, RFC 7474).** Described [above](#authenticate-a-link-and-change-its-key). A packet that fails authentication is dropped and logged (`ospf packet authentication failed`). A replayed or out-of-order packet (a sequence number that does not increase) is dropped and logged too.

**AS-external routes (ASBR).** Each redistributed static route becomes one type-5 LSA, flooded to every area the router is in. An ABR also copies every other router's type-5 LSA (and its flush) into its other areas, except stub areas and NSSAs, so externals cross area borders (see [below](#carry-external-routes-across-areas)). A copy ages on the clock of the area that holds it. Only static routes can be redistributed, and every one carries the rule's [metric and metric type](#choose-the-metric-and-metric-type-of-redistributed-routes) (default 20, type 1); the forwarding address is always 0.0.0.0.

**Ranking external routes received from other routers (RFC 2328 §16.4).**
- An intra-area or inter-area route always beats an external one, even a cheaper one. Type 1 beats type 2, even a cheaper type 2.
- Type 1: cost is the distance to the ASBR plus the LSA metric.
- Type 2: the smallest LSA metric wins, then the smaller distance to the ASBR. Equal in both: the next hops are merged (ECMP).
- An LSA with metric 16777215 (LSInfinity) is ignored.
- A zero forwarding address routes via the ASBR. A non-zero one routes via that address: it must be covered by an intra-area or inter-area route, or by a subnet the router is attached to (then the next hop is the address itself). Otherwise the LSA is ignored.
- The route's metric given to the routing table is the distance plus the LSA metric, for both types.
- Not done: the RFC 2328 §16.4.1 preference between areas, and RFC 1583 compatibility mode.

**Overlapping prefixes (RFC 2328 Appendix E).** Prefixes that share a network address, such as `192.0.2.128/25` and `192.0.2.128/26`, are advertised as separate type-3, type-5 or type-7 LSAs:

- The shortest one uses the network address as its link state ID, and each longer one uses its address with the host bits set (`192.0.2.191` for the `/26`). `show ospf database` lists both.
- When a shorter prefix is added, the longer one moves to its host-bits ID. For a few seconds both IDs advertise it, and other routers still compute one route.
- If both IDs of a prefix are already taken (`10.0.0.0/16` and `10.0.0.0/24`, then the host route `10.0.0.255/32`), that prefix is not advertised, and the router logs `ospf lsa link state id collision, not originating`.
- LSAs from other routers that use host-bits IDs are read as their prefix, so they compete with and merge into routes for the same prefix.

**Inter-area routes (ABR).** Each prefix of an area is advertised into the router's other areas as its own type-3 LSA, unless an area range covers it, and each ASBR as a type-4 LSA. A configured virtual link counts as a backbone attachment. An ABR attached to the backbone computes inter-area routes from the backbone's summaries only (RFC 2328 §16.2), and an intra-area route always wins over an inter-area one to the same prefix. Any router in two or more areas acts as an ABR, including towards a stub area, whether or not one of its areas is the backbone. This is designed and tested for one or more non-backbone areas each behind its own ABR; in topologies where several ABRs connect the same areas, check the result.

**Transit-only networks (RFC 6860).** Described [above](#hide-transit-only-networks-rfc-6860). With prefix suppression on, an NSSA type-7 LSA's forwarding address is a loopback's address, or `0.0.0.0` if the router has no loopback in the area, never a hidden link's.

**Opaque LSAs (RFC 5250).** NOS sets the O bit in its database description packets and stores and floods opaque LSAs it receives without reading them: type 9 (link-local) only on the link it arrived on, type 10 (area) in its area, type 11 (AS) in the area it arrived in. Opaque LSAs are offered only to neighbours whose database description packets set the O bit. NOS originates two: its own Grace-LSA, and a Router Information LSA (below). `show ospf database` lists a type-9 LSA under its link's area, without naming the link. An ABR does not pass a type-11 LSA on to its other areas. An LSA of a type NOS does not know (6, 7, 8, or above 11) is dropped on its own; the rest of the update is kept.

**Router Information (RFC 7770).** Every router advertises its capabilities in one type-10 opaque LSA per area (opaque type 4, link state ID `4.0.0.0`), with no configuration:

- *Graceful restart helper* is always set.
- *Graceful restart capable* is set while `graceful-restart grace-period` is configured.
- *Stub router support* (RFC 6987) is always set.
- *Host router support* (RFC 8770) is always set; it says this router honours the H-bit.
- `show ospf database` lists it as type 10 from each router; FRR lists it with `show ip ospf database opaque-area`, but FRR 10.7 shows the body only as raw bytes.
- From other routers' Router Information LSAs (type 10 or 11), only *host router support* is read, to decide whether the H-bit is honoured in the area.

**LSA ageing and withdrawal (RFC 2328 §14).** Self-originated LSAs are refreshed every 30 minutes and others expire after an hour without refresh. An LSA that is no longer wanted (a removed link, redistribution rule or area) is withdrawn at once by flooding it at maximum age.

**MTU and database exchange (RFC 2328 §10.6–10.8).** During the database exchange, the list of LSAs is split over as many packets as the link's MTU requires. The MTU used is the link's real MTU, unless the profile sets `mtu`. A database-description packet advertising an MTU larger than the link's own is dropped (logged as `ospf dbd rejected`), which leaves the neighbour stuck in `ExStart`; a smaller or equal MTU, or 0, is accepted. Set `mtu-ignore` on the profile to skip the check (needed against neighbours that do not honour it either).

**Stub areas and ranges (RFC 2328 §3.5, §3.6).** Described [above](#make-an-area-a-stub-and-summarize-it-with-ranges). In a stub area, Hellos and database description packets go without the E bit, a type-5 or type-11 LSA is neither sent nor accepted, and a router redistributing static routes does not set the ASBR bit in its router LSA there. The E bit in the header of the LSAs NOS originates is always clear.

**NSSA (RFC 3101).** Described [above](#redistribute-from-inside-a-stub-like-area-nssa). In an NSSA, Hellos carry the N bit and not the E bit, a type-5 or type-11 LSA is neither sent nor accepted, and a type-7 LSA is never sent or accepted outside one. A type-7 LSA from an ABR has the P bit clear, so no other ABR translates it. The translator doesn't copy the type-7 forwarding address into its type-5 LSA, so traffic to a translated route goes through the translator. Its election has no stability delay: a translator that loses it flushes its type-5 LSAs at once.

**Virtual links (RFC 2328 §15).** Described [above](#join-an-area-to-the-backbone-through-another-area-virtual-link). The far end's address is taken from the first point-to-point or transit link of its router LSA in the transit area. Database description packets carry the transit link's MTU, not 0, and the MTU check is skipped. DoNotAge (RFC 1793) is not used. A transit area's type-4 summaries are not examined for shorter paths to an ASBR (RFC 2328 §16.3 is applied to type-3 only).

**Not supported:** redistribution of anything other than static routes, flooding type-11 opaque LSAs between areas, the restarting router's own RFC 3623 restart mode (it resynchronises from scratch while its neighbours help) and strict LSA checking in the helper, BFD, NBMA, and static neighbor lists (so point-to-multipoint only runs over multicast-capable media).

## Configuration reference

All paths are relative to `/v1/transactions/{tx}/`. `delete` forms marked *relative only* exist only inside the object (after `edit`), not as an absolute command. The REST equivalent of a `delete` is `DELETE` on the same path, and of `set` a `PUT` on it.

### OSPF instance

| Field | CLI | Config-tree path | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit ospf instance <name>`; `delete ospf instance <name>` | `ospf-instance/<name>` | string, 1 to 64 characters | unique among OSPF instances | names the instance | `show config` |
| router ID | `set ospf instance <name> router-id <ip>`; relative `set router-id <ip>` | `ospf-instance/<name>/router-id` | IPv4 address; `0.0.0.0` when created by `edit` | set it: it identifies the router in every LSA | router ID in Hellos and LSAs | `show ospf neigh` on the neighbour |
| graceful restart | `set ospf instance <name> graceful-restart grace-period <seconds>`; `delete ospf instance <name> graceful-restart grace-period` | `ospf-instance/<name>/graceful-restart-grace-period` | seconds, 1 to 1800; unset by default | | on SIGTERM, ask Full neighbours to keep the adjacency and routes this long (RFC 3623) | `ospf helper: grace period entered` in the neighbour's log |
| prefix suppression | `set ospf instance <name> prefix-suppression`; `delete ospf instance <name> prefix-suppression` | `ospf-instance/<name>/prefix-suppression` | boolean; off by default | | hides point-to-point subnets and, as DR, LAN segments (RFC 6860) | `show route <table>` on another router |
| max-metric on startup | `set ospf instance <name> max-metric router-lsa on-startup <seconds>`; `delete ospf instance <name> max-metric router-lsa on-startup` | `ospf-instance/<name>/max-metric-on-startup` | seconds, 5 to 86400; unset by default | | stub router (RFC 6987) this long after the next start; skipped after a graceful restart | `ospf stub router max-metric changed` in the log |
| max-metric on shutdown | `set ospf instance <name> max-metric router-lsa on-shutdown <seconds>`; `delete ospf instance <name> max-metric router-lsa on-shutdown` | `ospf-instance/<name>/max-metric-on-shutdown` | seconds, 1 to 3; unset by default | | stub router this long before withdrawing the LSAs on stop; not on a graceful restart | `reason="on-shutdown"` in the log |
| max-metric administrative | `set ospf instance <name> max-metric router-lsa administrative`; `delete ospf instance <name> max-metric router-lsa administrative` | `ospf-instance/<name>/max-metric-administrative` | boolean; off by default | | stub router until removed | `show route <table>` on another router |
| host router | `set ospf instance <name> host-router`; `delete ospf instance <name> host-router` | `ospf-instance/<name>/host-router` | boolean; off by default | refused with `redistribute … to ospf` on its routing table | H-bit and max-metric transit links: never used for transit (RFC 8770) | `ospf host-bit state changed` in every router's log |
| remote LFA | `set ospf instance <name> remote-lfa`; `delete ospf instance <name> remote-lfa` | `ospf-instance/<name>/remote-lfa` | boolean; off by default | | tunnel backups to a PQ node where there is no loop-free alternate, and an IP-in-IP device that decapsulates (RFC 7490) | `show route <table>`: `backup tunnel <address>` |
| areas | `edit ospf instance <name> area <area-id>`; relative `edit area <area-id>` | `ospf-instance/<name>/area/<area-id>` | list of areas | area IDs unique within the instance | see [Area](#area) | `show config` |
| routing table | set on the table: `set routing-table <table> ospf-instance <name>`; `delete routing-table <table> ospf-instance` | `routing-table/<table>/ospf-instance` | instance name; unset by default | the instance must exist; one table per instance | runs the instance in that table's VRF and installs its routes there | `show ospf neigh`, `show route <table>` |

The instance's JSON also carries `routing_table`, `redistribute_policy`, `redistribute_metric` and `redistribute_metric_type`. They are filled in by the router from the routing table's settings, are read-only, and any value you send is replaced at commit.

### Area

| Field | CLI | Config-tree path | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| area ID | `edit ospf instance <name> area <area-id>`; `delete ospf instance <name> area <area-id>`; relative `edit area <area-id>` / `delete area <area-id>` | `ospf-instance/<name>/area/<area-id>` | dotted quad; `0.0.0.0` is the backbone | unique within the instance | groups the profiles, and so the links, of one area; deleting an area deletes its profiles | `show ospf neigh` (area column) |
| profiles | `edit ospf instance <name> area <area-id> profile <profile>`; relative `edit profile <profile>` | `…/area/<area-id>/profile/<profile>` | list of profiles | see [Profile](#profile) | | |
| area type | `set ospf instance <name> area <area-id> area-type normal\|stub\|totally-stubby\|nssa\|nssa-no-summary`; `delete … area-type` | `…/area/<area-id>/area-type` | `"Normal"`, `"Stub"`, `"TotallyStubby"`, `"Nssa"`, `"NssaNoSummary"`; `Normal` by default | not on `0.0.0.0` | stub: no type-5 LSA, E bit clear, a default route from the ABR; totally stubby: only that default; NSSA: type-7 LSAs instead of type-5, N bit set; NSSA no-summary: also only a default type-3; restarts the area's adjacencies | `show ospf database`, `show route <table>` |
| stub default cost | `set … area <area-id> stub-default-cost <n>`; `delete … stub-default-cost` | `…/area/<area-id>/stub-default-cost` | 1 to 65535; 1 when unset | only on a stub area or an NSSA | cost of the default route this router originates into the area as an ABR | `show route <table> 0.0.0.0` inside the area |
| NSSA translate always | `set … area <area-id> nssa-translate-always enable`; `delete … nssa-translate-always` | `…/area/<area-id>/nssa-translate-always` | `true`/`false`; `false` by default | only on an NSSA | as an ABR, always translate the area's type-7 LSAs, not only when elected | `show ospf database` in another area |
| NSSA default originate | `set … area <area-id> nssa-default-originate enable`; `delete … nssa-default-originate` | `…/area/<area-id>/nssa-default-originate` | `true`/`false`; `false` by default | only on an NSSA | as an ABR, originate a `0.0.0.0/0` type-7 LSA into the area | `show route <table> 0.0.0.0` inside the area |
| ranges | `set … area <area-id> range <cidr> [not-advertise]`; `delete … range <cidr>`; `delete … range <cidr> not-advertise` | `…/area/<area-id>/range/<cidr>` (`/` as `%2F`) | IPv4 prefix, `not_advertise` false by default | prefixes unique within the area | as an ABR, the area's prefixes inside the range are advertised to the other areas as one type-3 LSA (largest cost) with a local discard route, or not at all with `not-advertise` | `show ospf database` in another area, `show route <table>` on the ABR |
| virtual links | `set … area <area-id> virtual-link <router-id> [hello-interval <s>] [dead-interval <s>] [simple-password <label> \| crypto-key …]`; `delete … virtual-link <router-id>` | `…/area/<area-id>/virtual-link/<router-id>` | list keyed by the far endpoint's router ID; timers and auth as in [Profile](#profile) | not on `0.0.0.0`, a stub area or an NSSA; endpoint unique within the area and not this router's own ID; dead interval above hello interval; auth as a profile's (key ID 0-255) | a backbone adjacency to that router across this transit area, up while it is reachable here (RFC 2328 §15, §16.7); routes across it (§16.1-§16.3) | `show ospf neigh` (`vlink-<area-id>-<router-id>`), `virtual_links`/`router_flags` in `GET /v1/ospf/database` |

### Profile

Absolute forms start with `set ospf instance <name> area <area-id> profile <profile>`, written `set … profile <p>` below. Relative forms work inside the profile.

| Field | CLI | Config-tree path (under `ospf-instance/<name>/area/<area-id>/profile/<p>/`) | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit … profile <p>`; `delete ospf instance <name> area <area-id> profile <p>`; relative `delete profile <p>` | (the profile itself) | string, 1 to 64 characters | unique across all OSPF profiles in the config; deleting a profile that a link still uses is refused at commit | the name links attach to | `show config` |
| hello interval | `set … profile <p> hello-interval <s>`; relative `set hello-interval <s>` / `delete hello-interval` *(relative only)* | `hello-interval` | integer seconds, 0 to 65535; default 10 | if both are set, dead interval must be greater | interval between Hellos; must match the neighbour's | `show ospf neigh` |
| dead interval | `set … profile <p> dead-interval <s>`; relative `set dead-interval <s>` / `delete dead-interval` *(relative only)* | `dead-interval` | integer seconds, 0 to 65535; default 40 | greater than the hello interval when both are set | how long a silent neighbour is kept; must match the neighbour's; also the LAN wait time before the first election | `show ospf neigh` |
| cost | `set … profile <p> cost <n>`; relative `set cost <n>` / `delete cost` *(relative only)* | `cost` | integer 1 to 65535; default 1 | 0 is refused | cost of the link in SPF | `show route <table>` on other routers, `GET /v1/routes/{table}` |
| priority | `set … profile <p> priority <n>`; relative `set priority <n>` / `delete priority` *(relative only)* | `priority` | integer 0 to 255; default 1 | | DR/BDR election; 0 never becomes DR or BDR; no effect on point-to-point | `show ospf neigh` |
| MTU ignore | `set … profile <p> mtu-ignore enable`; relative `set mtu-ignore enable` / `delete mtu-ignore` | `mtu-ignore` | `true`/`false`; default `false` | | Skip the RFC 2328 §10.6 check that a neighbour's advertised MTU is not larger than the link's | `GET …/profile/<p>/mtu-ignore` |
| MTU | `set … profile <p> mtu <bytes>`; relative `set mtu <bytes>` / `delete mtu` *(relative only)* | `mtu` | integer 0 to 65535; default: the link's own MTU (1500 if unknown) | | MTU advertised in database-description packets and used to size them; the interface's real MTU is not changed | `GET …/profile/<p>/mtu` |
| network type | `set … profile <p> network-type point-to-point\|broadcast\|point-to-multipoint`; relative `set network-type …` / `delete network-type` *(relative only)* | `network-type`, `"PointToPoint"`, `"Broadcast"` or `"PointToMultipoint"` | default: point-to-point on a subinterface or loopback, broadcast on a broadcast domain | | forces the network type on every link using the profile | `show ospf neigh` (link state) |
| simple password | `set … profile <p> simple-password <label>`; relative `set simple-password <label>` | `auth`, `{"Simple":{"key":"<label>"}}` | label of an admin key whose secret is 1 to 8 bytes; replaces any crypto keys | the label must exist | RFC 2328 plain-text authentication; the secret is never shown | `show this` in the profile |
| crypto key | `set … profile <p> crypto-key <id> <algorithm> <label>`; relative `set crypto-key <id> <algorithm> <label>` / `delete crypto-key <id>` *(relative only)* | `auth`, `{"Crypto":{"keys":[{"key_id":1,"algorithm":"HmacSha256","key":"<label>","is_current":true}]}}` | ID 0 to 255 (up to 65535 with extended sequence numbers); algorithm `md5`, `hmac-sha1`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512` (`Md5`, `HmacSha1`, … in JSON); label of an admin key whose secret is 1 to 80 bytes | labels must exist; key IDs unique; at least one key; exactly one current | adds or replaces one key; a new key list replaces a simple password | `show this` in the profile |
| current key | `set … profile <p> crypto-key <id> current`; relative `set crypto-key <id> current` | `is_current` of each key | exactly one key | the key must exist | the key that signs sent packets; all keys verify | `show this` in the profile |
| no authentication | relative `delete auth` *(relative only)* | `DELETE …/auth` | default | | no authentication | `show this` in the profile |
| extended sequence numbers | `set … profile <p> extended-sequence-numbers enable\|disable`; relative the same | `extended-sequence-numbers` | boolean; default `false` | needs crypto authentication with HMAC-SHA keys only | RFC 7474 authentication, protecting against replay across restarts; both ends must agree | `show this` in the profile |

`show this` and `show config` show every field of a profile that is set (timers, cost, priority, MTU, network type, authentication), and leave out the ones that are not.

### Where a profile is attached

| Attach point | CLI | Config-tree path | Validation | Effect |
|---|---|---|---|---|
| subinterface | `set interface <if>[.<tag>] ospf <profile>`; `delete interface <if>[.<tag>] ospf`; relative `set ospf <profile>` / `delete ospf` inside `edit interface <if>.<tag>` | `interface/<if>/subinterface/<tag>/ospf-profile` | the profile must exist; the subinterface must have `routing-table` set | runs OSPF on the subinterface, point-to-point by default |
| loopback | `set interface loopback-<table> ospf <profile>`; `delete interface loopback-<table> ospf` | `interface/loopback-<table>/ospf-profile` | as above, on the loopback | advertises the loopback's addresses as stub networks |
| broadcast domain | relative only: `set ospf <profile>` / `delete ospf` inside `edit broadcast domain <name>` | `broadcast-domain/<name>/ospf-profile` | as above, on the broadcast domain | runs OSPF on the domain's SVI, broadcast by default, with DR/BDR election |

A physical interface such as `eth0` never takes a profile itself; `set interface eth0 ospf …` means its subinterface `eth0.0`.

### Redistribution into OSPF

| Field | CLI | Config-tree path | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| redistribute | `set routing-table <table> redistribute ospf`, then `policy <policy>`, `metric <1-16777215>` or `metric-type <1\|2>` (one per line); `delete routing-table <table> redistribute ospf`; relative `set redistribute ospf` / `delete redistribute ospf` | `routing-table/<table>/redistribute/ospf`, `{"from":"Static","to":"Ospf","policy":null,"metric":null,"metric_type":null}` | no rule by default; without a policy, everything is redistributed; metric 20, type 1 | the table needs both `static-routing-instance` and `ospf-instance`; the policy must exist; `metric`/`metric-type` only with `to ospf` | advertises the table's static routes as AS-external LSAs | `show ospf database` (type 5) on other routers |
