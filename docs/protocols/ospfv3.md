# OSPFv3

OSPFv3 (RFC 5340) is OSPF for IPv6. It works like [OSPFv2](ospf.md) and is configured the same way: an instance in a routing table, areas, profiles, and profiles attached to links. This page covers what is different and what is not supported yet; read the [OSPF page](ospf.md) first.

- [How OSPFv3 is configured](#how-ospfv3-is-configured)
- [Common operations](#common-operations)
  - [Run OSPFv3 between two routers](#run-ospfv3-between-two-routers)
  - [Check neighbours, the LSDB and routes](#check-neighbours-the-lsdb-and-routes)
  - [Advertise a loopback](#advertise-a-loopback)
  - [Authenticate a link (RFC 7166)](#authenticate-a-link-rfc-7166)
  - [Set the instance ID](#set-the-instance-id)
  - [Use extended LSAs (RFC 8362)](#use-extended-lsas-rfc-8362)
  - [Restart without dropping routes (RFC 5187)](#restart-without-dropping-routes-rfc-5187)
  - [Redistribute static routes (ASBR)](#redistribute-static-routes-asbr)
  - [Add a second area (ABR)](#add-a-second-area-abr)
- [Features and behaviour](#features-and-behaviour)
- [Not supported yet](#not-supported-yet)
- [Configuration reference](#configuration-reference)

As on the OSPF page, the CLI sessions run on router-a and the REST calls make the same change on router-b (`B=https://10.50.0.3:8080`, with a certificate from router-b). As on that page, the commands and paths match what the router accepts and follow configurations the end-to-end tests run, but sample outputs are not reproduced here yet.

## How OSPFv3 is configured

The model is the same as OSPFv2's, with `ospfv3` in place of `ospf` in every command and path:

- an **instance**, `ospfv3 instance <name>`, with a router ID (a dotted quad, as in OSPFv2) and linked to one routing table with `set routing-table <table> ospfv3-instance <name>`;
- **areas**, `area <area-id>`, inside it;
- **profiles**, `profile <name>`, inside an area, holding the per-link settings;
- a profile **attached** to a subinterface (`set interface eth0 ospfv3 <profile>`), a loopback (`set interface loopback-<table> ospfv3 <profile>`) or a broadcast domain (`set ospfv3 <profile>` inside `edit broadcast domain <name>`). The attach point must have `routing-table` set.

OSPFv2 and OSPFv3 are independent. One routing table can have both an `ospf-instance` and an `ospfv3-instance`, and one link can carry both an `ospf` and an `ospfv3` profile. OSPFv3 profile names are unique among OSPFv3 profiles, separately from OSPFv2's.

Prefix options (RFC 5340 A.4.1.1):

- a loopback `/128` is advertised with the LA bit (a host address of this router);
- a prefix a neighbor advertises with the NU bit is not routed to, nor summarized into other areas;
- the P and DN bits are never set.
- a bad LSA inside a Link State Update (wrong checksum or unparseable body) is discarded alone: the other LSAs of the packet are processed and acked, the sender retransmits only the bad one, and the daemon logs `lsu: discarded LSAs that failed to decode` (rate limited); an LSA header whose length cannot be framed still drops the whole packet.

A link needs an IPv6 address to be advertised. Neighbours talk over IPv6 link-local addresses, which the kernel creates for every interface, so the next hops of OSPFv3 routes are link-local addresses.

Routes are recomputed right away on every LSDB change and pushed to the routing table, with the same timing notes as OSPFv2 (see "Shortest paths and costs" in `ospf.md`).

How the OSPFv3 implementation works internally is described in [OSPFv3 internals](ospfv3-internals.md).

## Common operations

### Run OSPFv3 between two routers

This gives `eth0.0` an IPv6 address, creates instance `v3` with profile `p6` in the backbone, links it to `rt1` and attaches it to `eth0.0`:

```
configure v3
set interface eth0 address 2001:db8:1::1/64
edit ospfv3 instance v3
set router-id 1.1.1.1
edit area 0.0.0.0
edit profile p6
top
set routing-table rt1 ospfv3-instance v3
set interface eth0 ospfv3 p6
commit
```

The same on router-b over REST, with router ID 2.2.2.2 and address 2001:db8:1::2/64:

```sh
$C -X POST $B/v1/transactions/v3
$C -X PUT -H 'Content-Type: application/json' -d '{"address":"2001:db8:1::2/64","label":null}' \
  $B/v1/transactions/v3/interface/eth0/subinterface/0/address/2001:db8:1::2%2F64
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"v3","router_id":"2.2.2.2","areas":[{"area_id":"0.0.0.0","profiles":[{"name":"p6"}]}]}' \
  $B/v1/transactions/v3/ospfv3-instance/v3
$C -X PUT -H 'Content-Type: application/json' -d '"v3"' $B/v1/transactions/v3/routing-table/rt1/ospfv3-instance
$C -X PUT -H 'Content-Type: application/json' -d '"p6"' $B/v1/transactions/v3/interface/eth0/subinterface/0/ospfv3-profile
$C -X POST $B/v1/transactions/v3/commit
```

### Check neighbours, the LSDB and routes

`show ospfv3 neigh` and `show ospfv3 database` work like their OSPF counterparts (`GET /v1/ospfv3/neighbors` and `GET /v1/ospfv3/database` over REST):

```
show ospfv3 neigh
show ospfv3 database
```

The `type` column holds OSPFv3's LS type codes (RFC 5340 and RFC 8362): `0x2001` router, `0x2002` network, `0x2003` inter-area prefix, `0x2004` inter-area router, `0x4005` AS-external, `0x0008` link, `0x2009` intra-area prefix, and, in extended mode, `0xa021` E-Router, `0xa022` E-Network, `0xa023` E-Inter-Area-Prefix, `0xa024` E-Inter-Area-Router, `0xc025` E-AS-External, `0x8028` E-Link and `0xa029` E-Intra-Area-Prefix. Link LSAs are only valid on their own link, so the database also shows which link each one belongs to. AS-external LSAs belong to no area; they are listed under area `0.0.0.0`.

### Advertise a loopback

```
configure v3lo
edit interface loopback-rt1
set routing-table rt1
set address 2001:db8:2::1/128
set ospfv3 p6
commit
```

Router-b learns the loopback with router-a's link-local address as the next hop:


```
$C $B/v1/routes/rt1/2001:db8:2::1     (on router-b)
```

The REST equivalent on router-b adds an address to its loopback and attaches the profile:

```sh
$C -X POST $B/v1/transactions/v3lo
$C -X PUT -H 'Content-Type: application/json' -d '{"address":"2001:db8:4::1/128","label":null}' \
  $B/v1/transactions/v3lo/interface/loopback-rt1/address/2001:db8:4::1%2F128
$C -X PUT -H 'Content-Type: application/json' -d '"p6"' $B/v1/transactions/v3lo/interface/loopback-rt1/ospfv3-profile
$C -X POST $B/v1/transactions/v3lo/commit
```

### Authenticate a link (RFC 7166)

OSPFv3 authenticates with an authentication trailer appended to each packet. The commands are the same as OSPFv2's crypto keys, with two differences: only the HMAC-SHA algorithms are accepted (no `md5`, and no simple password), and the key ID is the RFC 7166 security association ID, from 0 to 65535. As in OSPFv2, the key names the label of an admin key (`set admin key <label> secret <value>`) rather than holding the secret, and setting the same label to a new value on both routers restarts the link with the new secret. Rolling to a new key works the same way as in OSPFv2: add it, make it current, delete the old one.

```
configure v3auth
set admin key ospfv3-p6-key300 secret v3-secret
edit ospfv3 instance v3 area 0.0.0.0 profile p6
set crypto-key 300 hmac-sha256 ospfv3-p6-key300
set crypto-key 300 current
commit
```

Over REST, `auth` is the list of keys itself, without the `Crypto` wrapper OSPFv2 uses:

```sh
$C -X POST $B/v1/transactions/v3auth
$C -X PUT -H 'Content-Type: application/json' \
  -d '[{"key_id":300,"algorithm":"HmacSha256","key":"ospfv3-p6-key300","is_current":true}]' \
  $B/v1/transactions/v3auth/ospfv3-instance/v3/area/0.0.0.0/profile/p6/auth
$C -X POST $B/v1/transactions/v3auth/commit
```

There is no equivalent of OSPFv2's `extended-sequence-numbers`.

### Set the instance ID

Every OSPFv3 packet carries an instance ID (RFC 5340 §A.3.1). A router drops packets whose instance ID differs from the one on its link, so both ends of a link must use the same value. The default is 0.

```
configure v3iid
set ospfv3 instance v3 area 0.0.0.0 profile p6 instance-id 1
commit
```

```sh
$C -X POST $B/v1/transactions/v3iid
$C -X PUT -H 'Content-Type: application/json' -d '1' $B/v1/transactions/v3iid/ospfv3-instance/v3/area/0.0.0.0/profile/p6/instance-id
$C -X POST $B/v1/transactions/v3iid/commit
```

- The range is 0 to 31, the IPv6 unicast range of RFC 5838.
- Changing it restarts the link's adjacencies.
- A dropped packet is logged at debug level only (`ospfv3 packet instance id mismatch, dropping`, with `received` and `expected`). If a neighbour never shows up in `show ospfv3 neigh`, compare both ends' instance IDs.
- `delete ospfv3 instance v3 area 0.0.0.0 profile p6 instance-id` goes back to 0.

### Use extended LSAs (RFC 8362)

`set ospfv3 instance <name> extended-lsa` makes the instance originate the TLV-based extended LSAs of RFC 8362 ("full" mode) instead of the RFC 5340 ones. It also understands extended LSAs from its neighbours either way. `delete ospfv3 instance <name> extended-lsa` goes back to the RFC 5340 LSAs.

```
configure v3ext
set ospfv3 instance v3 extended-lsa
commit
```

```sh
$C -X POST $B/v1/transactions/v3ext
$C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/v3ext/ospfv3-instance/v3/extended-lsa
$C -X POST $B/v1/transactions/v3ext/commit
```

What happens when you switch:

- The new LSAs are originated within about 2 seconds.
- The router then flushes the LSAs of the mode it left (they reach age 3600), so neighbours drop them within about 10 seconds instead of keeping them for an hour.
- `show ospfv3 database` can show the old LSAs at age 3600 for those few seconds.

RFC 8362 intends full mode to be enabled on every router of an area at once, and that is how it has been tested in NOS; running an area with some routers in each mode is not tested.

### Restart without dropping routes (RFC 5187)

Set a grace period on the instance so that its neighbours keep the adjacency and this router's routes while its OSPFv3 daemon restarts:

```
configure v3gr
set ospfv3 instance v3 graceful-restart grace-period 120
commit
```

```sh
$C -X POST $B/v1/transactions/v3gr
$C -X PUT -H 'Content-Type: application/json' -d '120' $B/v1/transactions/v3gr/ospfv3-instance/v3/graceful-restart-grace-period
$C -X POST $B/v1/transactions/v3gr/commit
```

How it behaves:

- **Restarting router.** Only a planned restart announces a grace period: `nos-ospfv3d` receiving SIGTERM sends a Grace-LSA to every Full neighbour (log `ospfv3 graceful restart: grace-lsa sent`), then exits and is restarted by the watchdog. Stopping the router or removing the instance (SIGINT) announces nothing, since nothing comes back. A crash announces nothing either.
- **Helping neighbour.** Every OSPFv3 instance helps; there is nothing to enable. On a Grace-LSA from a Full neighbour it logs `ospfv3 helper: grace period entered`, keeps that neighbour Full through missing Hellos and through Hellos that don't list it yet, and keeps the neighbour's LSAs, so its routes stay installed.
- **How long it helps.** What the Grace-LSA has left (RFC 3623 §3.1): its grace period minus its age, at most the instance's `graceful-restart helper max-grace-period` (default 1800, 1 to 3600). The line carries `effective_grace=<seconds>`. A Grace-LSA whose age is already at or past its grace period is not honoured (`ospfv3 helper: no grace left, exiting grace`).
- **Strict LSA checking.** While helping, a change to a topology LSA in the link's area (or AS-wide for AS-External) ends it (RFC 3623 §3.2 item 3): Router, Network, Inter-Area-Prefix, Inter-Area-Router, AS-External and Intra-Area-Prefix LSAs and their RFC 8362 extended forms, never link-local ones (Link-LSAs). A new LSA, one whose contents changed, or one flushed (MaxAge) counts; a refresh with identical contents never does, nor do the restarting router's own LSAs; this router's own originations do. The helper logs `ospfv3 helper: topology change, exiting grace` (checked on the 1 second aging tick), then the ordinary dead interval applies. Always on.
- **End of the grace period.** When the restarted router's adjacency is Full again, the helper logs `ospfv3 helper: neighbor reformed, exiting grace early`. If it never comes back, the helper logs `ospfv3 helper: grace period expired` and the ordinary dead interval applies from then on.
- `delete ospfv3 instance v3 graceful-restart grace-period` turns it off.

### Redistribute static routes (ASBR)

`redistribute ospfv3` advertises the routing table's IPv6 static routes into its OSPFv3 instance, which makes this router an AS boundary router (ASBR). The table needs a static routing instance and an OSPFv3 instance:

```
configure v3asbr
edit static-routing-instance s1
set route 2001:db8:77::/48 gateway 2001:db8:1::2
top
set routing-table rt1 static-routing-instance s1
set routing-table rt1 redistribute ospfv3
commit
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"from":"Static","to":"Ospfv3","policy":null}' \
  $B/v1/transactions/v3asbr/routing-table/rt1/redistribute/ospfv3
```

- Each static IPv6 route becomes one AS-external LSA (`0x4005`, or `0xc025` in extended mode), with metric 20. IPv4 static routes are ignored.
- The other routers install it at their distance to this router plus 20, through an area border router if this router is in another area.
- `policy <name>` filters what is redistributed, as in [OSPF](ospf.md#redistribute-static-routes-asbr).
- Deleting the rule flushes the LSAs within a few seconds (log `ospfv3 lsa prematurely aged`).
- A routing table keeps one `redistribute` rule per target, so the same static routes can go into BGP, OSPF and OSPFv3 at once (IPv4 statics into OSPF, IPv6 statics into OSPFv3). `delete routing-table rt1 redistribute ospfv3` removes this one only.

### Add a second area (ABR)

As in [OSPF](ospf.md#add-a-second-area-abr), a router with links or loopbacks in two or more areas is an area border router; there is no switch. Here router-a's loopback goes into area 0.0.0.1 while `eth0.0` stays in the backbone:

```
configure v3abr
edit ospfv3 instance v3 area 0.0.0.1 profile p6-area1
top
set interface loopback-rt1 ospfv3 p6-area1
commit
```

- Into each of its areas, the ABR advertises every prefix of its other areas as an inter-area prefix LSA (`0x2003`, or `0xa023`), and every AS boundary router of its other areas as an inter-area router LSA (`0x2004`, or `0xa024`).
- Router-b, in the backbone only, then has the loopback in `show route rt1`, through router-a.
- Moving the loopback back, or deleting the area, flushes those LSAs within a few seconds.

## Features and behaviour

Neighbour discovery, DR/BDR election, timers, costs, network types, the MTU override and database exchange, LSA ageing and withdrawal, and loop-free alternates behave as in [OSPF](ospf.md#features-and-behaviour). The differences:

- The Interface MTU check (RFC 5340 A.3.3) and `mtu-ignore` work as in OSPF; the log line is `ospfv3 dbd rejected`.
- **IPv6 only.** Only IPv6 prefixes are advertised, and neighbours are reached through their link-local addresses. On a link with several IPv6 addresses, only the first one is advertised.
- **Loop-free alternates.** The backup next hop is a link-local address too, and may leave through a different interface from the primary; it is installed with its own interface, at a worse metric than the primary.
- **Authentication** is RFC 7166's authentication trailer, with HMAC-SHA-1, -256, -384 or -512 only. A packet that fails is dropped and logged (`ospfv3 packet authentication failed`).
- **Link-local flooding scope.** A link LSA is only ever sent on the link it belongs to (RFC 5340 §4.5.1).
- **Unknown LSA types** (RFC 5340 §2.9) are accepted, not refused. With the U bit set they are stored and flooded by their S2/S1 scope (area, AS or link-local); with it clear they are kept link-local and never sent past the link they arrived on. They are never used for routing. An LSA with the reserved scope `11` is silently dropped (not acknowledged).
- **Areas and AS boundary.** As in OSPFv2, an inter-area or external route is chosen by cost alone, and an external route is always type 1 (the LSA's metric plus the distance to the ASBR). Unlike OSPFv2, an external LSA's own metric counts, and an ABR passes another router's external LSAs on into all its areas. Every area is a normal area, so Hellos and LSAs set the E option bit.
- **Link failure.** A lost local link (interface deleted, set down, or carrier lost) drops its neighbours within about a second: `nos-ospfv3d` follows the link state `nos-interfaced` streams and logs `ospfv3 link kernel interface down link=eth0.0 reason=absent|admin-down|no-carrier`, then `ospfv3 link kernel interface up` when it returns (a recreated device gets a fresh socket). The LSAs of the dropped link are withdrawn on the next origination tick. A failure beyond the local link (a dead remote end, a switch in between) still takes the dead interval (BFD is #190). A restarting `nos-interfaced` or `nos-ribd` tears no link down: the link keeps its running address, VRF and bridge (`ospfv3 link resolution failed, keeping running link`) while the configuration still demands it. With `--driver noop` nothing is gated.
- **Withdrawal.** An LSA the router stops originating is flushed within about 2 seconds (log `ospfv3 lsa prematurely aged`): for example its network LSA after it stops being DR or loses its last Full neighbour on the link, or its LSAs in an area it has left. Unlike OSPFv2, a clean stop of `nos-ospfv3d` flushes nothing; neighbours drop the router when the dead interval runs out.

## Not supported yet

These work in OSPFv2 but not yet in OSPFv3:

- **Area ranges** (summarizing an area into one prefix) and their discard routes.
- **RFC 7474-style replay protection** (`extended-sequence-numbers`).

Also not supported: several OSPFv3 instances on one link (the RFC 5838 address families; one instance ID per link works, see [Set the instance ID](#set-the-instance-id)), RFC 8362's sparse mode, NSSA and stub areas, virtual links, graceful restart after a crash (RFC 5187 only covers restarts announced beforehand), BFD, and the non-broadcast network types (point-to-multipoint is refused at commit).

## Configuration reference

Fields, types, defaults and validation are those of [OSPF](ospf.md#configuration-reference), with `ospfv3` for `ospf` in the commands and `ospfv3-instance` for `ospf-instance` in the paths. Only the differences are listed here. All paths are relative to `/v1/transactions/{tx}/`.

| Field | CLI | Config-tree path | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| instance | `edit ospfv3 instance <name>`; `delete ospfv3 instance <name>` | `ospfv3-instance/<name>` | string, 1 to 64 characters | unique among OSPFv3 instances | names the instance | `show config` |
| router ID | `set ospfv3 instance <name> router-id <ip>`; relative `set router-id <ip>` | `ospfv3-instance/<name>/router-id` | dotted quad | | router ID in Hellos and LSAs | `show ospfv3 neigh` on the neighbour |
| extended LSAs | `set ospfv3 instance <name> extended-lsa`; `delete ospfv3 instance <name> extended-lsa` (absolute only) | `ospfv3-instance/<name>/extended-lsa` | boolean; default `false` | | originate RFC 8362 extended LSAs | `show ospfv3 database` |
| graceful restart | `set ospfv3 instance <name> graceful-restart grace-period <seconds>`; `delete ospfv3 instance <name> graceful-restart grace-period` | `ospfv3-instance/<name>/graceful-restart-grace-period` | seconds, 1 to 1800; unset by default | | on SIGTERM, ask Full neighbours to keep the adjacency and routes this long (RFC 5187) | `ospfv3 helper: grace period entered` in the neighbour's log |
| graceful restart helper cap | `set ospfv3 instance <name> graceful-restart helper max-grace-period <seconds>`; `delete ospfv3 instance <name> graceful-restart helper max-grace-period` | `ospfv3-instance/<name>/graceful-restart-helper-max-grace-period` | seconds, 1 to 3600; 1800 when unset | | the longest grace period this router honours for a restarting neighbour | `effective_grace=` in `ospfv3 helper: grace period entered` |
| routing table | `set routing-table <table> ospfv3-instance <name>`; `delete routing-table <table> ospfv3-instance` | `routing-table/<table>/ospfv3-instance` | instance name | the instance must exist; one table per instance | runs the instance in that table | `show ospfv3 neigh` |
| area | `edit ospfv3 instance <name> area <area-id>`; `delete ospfv3 instance <name> area <area-id>` | `ospfv3-instance/<name>/area/<area-id>` | dotted quad | unique within the instance | links/loopbacks in 2+ areas make an ABR | `show ospfv3 database` |
| redistribute | `set routing-table <table> redistribute ospfv3 [policy <p>]`; `delete routing-table <table> redistribute ospfv3` | `routing-table/<table>/redistribute/ospfv3`, `{"from":"Static","to":"Ospfv3","policy":null}` | one rule per target | needs `static-routing-instance` and `ospfv3-instance` | IPv6 static routes become AS-external LSAs | `show ospfv3 database` on a neighbour |
| profile | `edit ospfv3 instance <name> area <area-id> profile <p>`; `delete ospfv3 instance <name> area <area-id> profile <p>` | `…/area/<area-id>/profile/<p>` | string, 1 to 64 characters | unique among OSPFv3 profiles | | |
| hello interval, dead interval, cost, priority, MTU, network type | `set ospfv3 instance <name> area <area-id> profile <p> <field> <value>`; relative forms as in OSPF | `…/profile/<p>/hello-interval`, `dead-interval`, `cost`, `priority`, `mtu`, `mtu-ignore`, `network-type` | as in OSPF | as in OSPF | as in OSPF | `show ospfv3 neigh` |
| crypto key | `set ospfv3 instance <name> area <area-id> profile <p> crypto-key <id> <algorithm> <label>`; relative `set crypto-key …` / `delete crypto-key <id>` *(relative only)* | `…/profile/<p>/auth`, `[{"key_id":300,"algorithm":"HmacSha256","key":"<label>","is_current":true}]` | ID 0 to 65535; `hmac-sha1`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512`; label of an admin key whose secret is 1 to 80 bytes; unset by default | labels must exist, at least one key, IDs unique, exactly one current, no `md5` | RFC 7166 authentication trailer | `show this` in the profile |
| current key | `set … profile <p> crypto-key <id> current`; relative `set crypto-key <id> current` | `is_current` of each key | | the key must exist | signs sent packets; all keys verify | `show this` in the profile |
| instance ID | `set ospfv3 instance <name> area <area-id> profile <p> instance-id <n>`; relative `set instance-id <n>` / `delete instance-id` | `…/profile/<p>/instance-id` | 0 to 31; unset means 0 | 0 to 31 | sent in every packet; packets with another instance ID are dropped | `show this` in the profile |
| no authentication | relative `delete auth` *(relative only)* | `DELETE …/profile/<p>/auth` | default | | | |
| subinterface / loopback | `set interface <if>[.<tag>] ospfv3 <p>`, `set interface loopback-<table> ospfv3 <p>`; `delete interface <if> ospfv3` | `interface/<if>/subinterface/<tag>/ospfv3-profile`, `interface/loopback-<table>/ospfv3-profile` | | the attach point needs `routing-table` | runs OSPFv3 on the link | `show ospfv3 neigh` |
| broadcast domain | relative only: `set ospfv3 <p>` / `delete ospfv3` inside `edit broadcast domain <name>` | `broadcast-domain/<name>/ospfv3-profile` | | the domain needs `routing-table` | runs OSPFv3 on the domain's SVI | `show ospfv3 neigh` |

OSPFv3 profiles have no `simple-password` and no `extended-sequence-numbers`. The instance's `routing_table` and `redistribute_policy` JSON fields are filled in by the router and are read-only.
