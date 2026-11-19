# OSPFv3

OSPFv3 (RFC 5340) is OSPF for IPv6. It works like [OSPFv2](ospf.md) and is configured the same way: an instance in a routing table, areas, profiles, and profiles attached to links. This page covers what is different and what is not supported yet; read the [OSPF page](ospf.md) first.

- [How OSPFv3 is configured](#how-ospfv3-is-configured)
- [Common operations](#common-operations)
  - [Run OSPFv3 between two routers](#run-ospfv3-between-two-routers)
  - [Check neighbours, the LSDB and routes](#check-neighbours-the-lsdb-and-routes)
  - [Advertise a LAN without speaking OSPFv3](#advertise-a-lan-without-speaking-ospfv3)
  - [Advertise a loopback](#advertise-a-loopback)
  - [Authenticate a link (RFC 7166)](#authenticate-a-link-rfc-7166)
  - [Set the instance ID](#set-the-instance-id)
  - [Use extended LSAs (RFC 8362)](#use-extended-lsas-rfc-8362)
  - [Use sparse mode (RFC 8362 §3)](#use-sparse-mode-rfc-8362-3)
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
$C -X PUT -H 'Content-Type: application/json' -d '["p6"]' $B/v1/transactions/v3/interface/eth0/subinterface/0/ospfv3-profiles
$C -X POST $B/v1/transactions/v3/commit
```

### Check neighbours, the LSDB and routes

`show ospfv3 neigh` and `show ospfv3 database` work like their OSPF counterparts (`GET /v1/ospfv3/neighbors` and `GET /v1/ospfv3/database` over REST):

```
show ospfv3 neigh
show ospfv3 database
```

The `type` column holds OSPFv3's LS type codes (RFC 5340 and RFC 8362): `0x2001` router, `0x2002` network, `0x2003` inter-area prefix, `0x2004` inter-area router, `0x4005` AS-external, `0x0008` link, `0x2009` intra-area prefix, and, in extended mode, `0xa021` E-Router, `0xa022` E-Network, `0xa023` E-Inter-Area-Prefix, `0xa024` E-Inter-Area-Router, `0xc025` E-AS-External, `0x8028` E-Link and `0xa029` E-Intra-Area-Prefix. Link LSAs are only valid on their own link, so the database also shows which link each one belongs to. AS-external LSAs belong to no area; they are listed under area `0.0.0.0`.

### Advertise a LAN without speaking OSPFv3

A passive profile advertises an attach point's IPv6 prefix (Intra-Area-Prefix-LSA) but sends no Hello and forms no adjacency, for a LAN with only hosts on it.

- `set … profile <p> passive enable` on the profile, then attach it to the subinterface or broadcast domain as usual; `delete passive` makes the link live again without restarting the instance.
- It cannot be combined with `crypto-key` or `bfd`: a commit with both is rejected.
- A down kernel device removes the prefix, like a live link. The prefix's area counts toward the ABR rule.
- `nos-ospfv3d` logs `ospfv3 passive interface advertised attach_point=<name>`.

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
$C -X PUT -H 'Content-Type: application/json' -d '["p6"]' $B/v1/transactions/v3lo/interface/loopback-rt1/ospfv3-profiles
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

- The range is 0 to 31 (IPv6 unicast) or 64 to 95 (IPv4 unicast), RFC 5838 §2.1; the instance's address family decides which (next section).
- Changing it restarts the link's adjacencies.
- A dropped packet is logged at debug level only (`ospfv3 packet instance id mismatch, dropping`, with `received` and `expected`). If a neighbour never shows up in `show ospfv3 neigh`, compare both ends' instance IDs.
- `delete ospfv3 instance v3 area 0.0.0.0 profile p6 instance-id` goes back to 0.

### Choose the address family (RFC 5838)

```
configure v3af
set ospfv3 instance v3 address-family ipv4-unicast
set ospfv3 instance v3 area 0.0.0.0 profile p6 instance-id 64
commit
```

- `ipv6-unicast` is the default; `delete ospfv3 instance v3 address-family` goes back to it.
- Every profile's instance ID must lie in the family's range (0-31 or 64-95), so an `ipv4-unicast` instance needs an explicit `instance-id` on each profile; the commit fails otherwise.
- An `ipv4-unicast` instance sets the AF-bit in its Hellos, DBDs and LSAs and discards a Hello without it (`dropping ospfv3 hello without af-bit`). The base IPv6 family sets no AF-bit and accepts either, for compatibility.
- Only the foundation is built: the adjacency forms, but no IPv4 route is computed yet. Several instances on one link are not possible yet: an attach point names one profile and a routing table claims one OSPFv3 instance.

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

RFC 8362 intends full mode to be enabled on every router of an area at once; use sparse mode (next section) when the area mixes routers with and without extended-LSA support.

### Use sparse mode (RFC 8362 §3)

`set ospfv3 instance <name> extended-lsa-sparse` keeps the RFC 5340 LSAs as the topology and prefix carriers, so full-mode and legacy-only routers in the same area still interoperate with this one. It still reads extended LSAs from full-mode neighbours and merges them into SPF; a link or prefix present in both a legacy LSA and its extended form counts once. It is mutually exclusive with `extended-lsa`: the commit is refused when both are on. `delete ospfv3 instance <name> extended-lsa-sparse` turns it off.

- NOS originates no extended LSA in sparse mode: it has no TE, SR or other TLV content a legacy LSA cannot hold, so the origination is the same as with both modes off. Extended LSAs of this router's earlier full mode are flushed on the switch, like any mode change.
- Verified with router-a sparse, router-b full and router-c legacy-only on one bridge (`nos-e2e ospfv3-extended-lsa-sparse`).

### Use a hybrid broadcast and point-to-multipoint link (RFC 6845)

- Use it on a broadcast domain where each router pair needs its own path cost; hello, DR/BDR election and database sync stay as on a normal broadcast link.
- Set `network-type hybrid` on the profile the broadcast domain's `ospfv3` field names: `set ospfv3 instance <name> area <area-id> profile <p> network-type hybrid`.
- Every router on the segment must use it; a mixed segment still forms adjacencies but some router pairs carry no traffic.
- The DR originates no Network-LSA. Routers describe the link as point-to-point links to their neighbors, and advertise their address as a `/128` plus the link's prefix.
- A router that is not the DR lists a neighbor only once it is `Full` with the DR and the DR's Router-LSA links to that neighbor.
- A hybrid profile on a subinterface or interface, a `passive` hybrid profile, and OSPFv2 hybrid are rejected at commit.
- Check it with `show ospfv3 neighbors` (DR/BDR roles as for broadcast) and `show ospfv3 database` (no network LSA).

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

### Drain traffic away from a router (RFC 6987 stub router)

Make other routers avoid this one for transit, while its own prefixes stay reachable. Same three settings as OSPFv2:

```
configure drain
set ospfv3 instance v3 max-metric router-lsa administrative
set ospfv3 instance v3 max-metric router-lsa on-startup 300
set ospfv3 instance v3 max-metric router-lsa on-shutdown 3
commit
```

```sh
$C -X POST $B/v1/transactions/drain
$C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/drain/ospfv3-instance/v3/max-metric-administrative
$C -X PUT -H 'Content-Type: application/json' -d '300' $B/v1/transactions/drain/ospfv3-instance/v3/max-metric-on-startup
$C -X PUT -H 'Content-Type: application/json' -d '3' $B/v1/transactions/drain/ospfv3-instance/v3/max-metric-on-shutdown
$C -X POST $B/v1/transactions/drain/commit
```

- **What changes.** Every point-to-point and transit-network link in the (E-)Router-LSA costs 65535. Prefixes live in Intra-Area-Prefix-LSAs and keep their metric; other routers' inter-area and external metrics are untouched. There is no H-bit in OSPFv3. Other routers use this one for transit only when there is no other path, and never as a loop-free alternate.
- **`administrative`.** On until removed: `delete ospfv3 instance v3 max-metric router-lsa administrative` brings it back.
- **`on-startup <seconds>`** (5 to 86400). For this long after `nos-ospfv3d` starts. It takes effect on the next start, not when set; `delete` ends a period still running.
- **`on-shutdown <seconds>`** (1 to 3). When `nos-ospfv3d` stops, it first advertises max-metric and waits this long before exiting. `nos-ospfv3d` withdraws no LSAs on a clean stop, so this is the whole delay. Skipped when the router is already a stub router.
- **Not with graceful restart (RFC 6987 §3.2 (c)).** A planned restart with a grace period (SIGTERM) leaves a marker `/var/lib/nos/ospfv3d/<instance>.gr`; the respawned process consumes it and skips `on-startup` (log `ospfv3 stub router on-startup skipped after graceful restart`). `on-shutdown` is skipped whenever the grace period is announced.
- **Check it.** The router logs `ospfv3 stub router max-metric changed active=true reason="administrative"` (or `"on-startup"`, `"on-shutdown"`), then `active=false` with `reason="expired"` or `"cleared"`. On another router, its backup next hop through this one is gone.

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

As in [OSPF](ospf.md#add-a-second-area-abr), a router with links or loopbacks in two or more areas, one of them the backbone, is an area border router; there is no switch. Here router-a's loopback goes into area 0.0.0.1 while `eth0.0` stays in the backbone:

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

### Summarize an area with ranges

An ABR folds an area's own prefixes into one inter-area prefix LSA per range (RFC 5340 §4.4.3.3), as in [OSPF](ospf.md#make-an-area-a-stub-and-summarize-it-with-ranges):

```
edit ospfv3 instance v3 area 0.0.0.1
set range 2001:db8:6::/48
commit
```

- The covered prefixes are no longer advertised on their own; the range is, at the largest covered cost, and only while at least one prefix of it exists in the area. The ABR installs a local discard route (blackhole) for it.
- `set range <cidr> not-advertise` hides the covered prefixes from the other areas entirely and removes the discard route; `delete range <cidr>` restores them.
- Intra-area prefixes only; a prefix covered by two ranges counts towards the most specific. On a router that is no ABR a range does nothing.

### Make an area a stub

A stub area carries no AS-external LSA (RFC 5340 §4.4.3, RFC 2328 §3.6); its ABR sends a default route instead, as in [OSPF](ospf.md#make-an-area-a-stub-and-summarize-it-with-ranges). Set the same type on every router of the area:

```
set ospfv3 instance v3 area 0.0.0.1 area-type stub
set ospfv3 instance v3 area 0.0.0.1 stub-default-cost 10
commit
```

- The routers clear the E option bit in the area's Hellos and LSAs. A Hello whose E bit disagrees is dropped (`dropping ospfv3 hello with mismatched e-bit`), so a router with the wrong type never gets past `Down`.
- The ABR originates a `::/0` inter-area prefix LSA into the area at `stub-default-cost` (1 unless set); the routers inside install `::/0` through it. No AS-external LSA (`0x4005`, `0xc025`) is sent, requested, accepted or routed in the area, and one already held ages out when the area turns stub.
- `area-type totally-stubby` on the ABR's area also stops the other inter-area prefix and router LSAs, leaving the default as the only summary. The routers inside may use `stub` or `totally-stubby`: they are the same for them.
- The backbone cannot be a stub area or an NSSA.

### Make an area an NSSA

An NSSA (RFC 3101, RFC 5340 §4.4.3) carries no AS-external LSA, but its own ASBRs originate NSSA-LSAs (`0x2007`, or `0xa027` in extended mode; the AS-external body, area scope) that one ABR translates into AS-external LSAs for the other areas. Set the type on every router of the area, or their Hellos are dropped (`mismatched n-bit`, `mismatched e-bit`):

```
set ospfv3 instance v3 area 0.0.0.1 area-type nssa
set ospfv3 instance v3 area 0.0.0.1 nssa-translate-always enable
set ospfv3 instance v3 area 0.0.0.1 nssa-default-originate enable
```

- **Origination.** A router in the NSSA that redistributes routes originates one NSSA-LSA per prefix, with the P prefix option and its own link address as forwarding address; an ABR clears P (it originates the AS-external LSA itself). The router sets the E bit in its Router-LSA there.
- **Translation.** One ABR per NSSA translates the NSSA-LSAs that have the P option and a forwarding address into its own AS-external LSAs, and sets E in its other areas. It is the ABR with the highest router ID, unless another has the Nt bit (`nssa-translate-always enable` sets it and forces the role). The log line is `ospfv3 nssa translator role changed`. An NSSA-LSA that goes away flushes its translation.
- **`nssa-default-originate enable`** makes an ABR originate a `::/0` NSSA-LSA (no P, so never translated) into the area at `stub-default-cost`.
- `area-type nssa-no-summary` also sends only a `::/0` inter-area prefix LSA into the area. The ABR sends no Inter-Area-Router-LSA into any NSSA.
- The two `nssa-*` settings are refused on a non-NSSA area. In extended-LSA mode NSSA-LSAs are originated as E-NSSA-LSAs (`0xa027`, RFC 8362) instead of `0x2007`, and both forms are accepted.

### Join an area to the backbone through another area (virtual link)

An area must touch the backbone (0.0.0.0). When it can't, a virtual link (RFC 5340 §4.7, RFC 2328 §15) runs a backbone adjacency across a normal transit area between two of its ABRs. Here router-c has only area 0.0.0.1 (shared with router-b, which also has area 0.0.0.0). Configure the link on the transit area of both ends, with the other end's router ID:

```
set ospfv3 instance v3 area 0.0.0.1 virtual-link 9.9.9.10
```

on router-c (`9.9.9.10` is router-b's router ID), and the mirror image on router-b. Over REST, `PUT {"router_id":"9.9.9.10"}` on `…/ospfv3-instance/v3/area/0.0.0.1/virtual-link/9.9.9.10`. Not allowed on the backbone, a stub area or an NSSA.

- **Each end needs a global address in the transit area.** Add a loopback with a `/128` in the transit area (`set interface loopback-rt1 ospfv3 <profile>` with a profile of that area): its LA prefix in the Intra-Area-Prefix-LSA is the link's address (RFC 5340 §4.4.3.9). Our own `/128` there is the source; without one the link stays down.
- **When it comes up.** Every 2 seconds each end checks that the other is reachable inside the transit area and advertises such an address. If so, the link comes up with that path's cost (`ospfv3 virtual link up link=vlink-0.0.0.1-9.9.9.10 neighbor=… local=… cost=…`), and down again when it isn't (`ospfv3 virtual link down`).
- **What it runs.** A backbone adjacency, unicast between the two addresses (hop limit 64, the only sends that leave the link): Hellos, no DR, the link's own timers and authentication (`hello-interval`, `dead-interval`, `crypto-key`, as on a profile), the transit link's MTU and instance ID. A router with a configured virtual link counts as attached to the backbone (B bit, summaries).
- **Check it.** `show ospfv3 neigh` lists `vlink-<transit-area>-<router-id>` in area 0.0.0.0, `Full`. In `GET /v1/ospfv3/database`, each end's area-0 Router-LSA lists the other in `virtual_links`, and its Router-LSA in the transit area has the V bit (`router_flags` & 4).
- **Remove it.** `delete … virtual-link <router-id>`. The other end drops the neighbour after its dead interval (`ospfv3 neighbor state changed to down link=vlink-…`) unless it is removed there too.
- **Routes.** The backbone-less router routes the backbone through the link (RFC 5340 §4.8, RFC 2328 §16.1): the type-4 link is an SPF edge at its cost, with the first hops toward the far end taken from the transit area; the far end summarizes the backbone into its other areas. A backbone-attached ABR ignores summaries in its non-backbone areas, except that a transit area (V bit) may shorten an inter-area backbone route (§16.3). When the link drops, the routes go with it.

## Features and behaviour

Neighbour discovery, DR/BDR election, timers, costs, network types, the MTU override and database exchange, LSA ageing and withdrawal, and loop-free alternates behave as in [OSPF](ospf.md#features-and-behaviour). The differences:

- The Interface MTU check (RFC 5340 A.3.3) and `mtu-ignore` work as in OSPF; the log line is `ospfv3 dbd rejected` (with the `link`). A broadcast-domain attach point uses the bridge's observed MTU.
- **IPv6 only.** Only IPv6 prefixes are advertised, and neighbours are reached through their link-local addresses. On a link with several IPv6 addresses, only the first one is advertised.
- **Loop-free alternates.** The backup next hop is a link-local address too, and may leave through a different interface from the primary; it is installed with its own interface, at a worse metric than the primary.
- **Authentication** is RFC 7166's authentication trailer, with HMAC-SHA-1, -256, -384 or -512 only. A packet that fails is dropped and logged (`ospfv3 packet authentication failed`).
- **Link-local flooding scope.** A link LSA is only ever sent on the link it belongs to (RFC 5340 §4.5.1).
- **Unknown LSA types** (RFC 5340 §2.9) are accepted, not refused. With the U bit set they are stored and flooded by their S2/S1 scope (area, AS or link-local); with it clear they are kept link-local and never sent past the link they arrived on. They are never used for routing. An LSA with the reserved scope `11` is silently dropped (not acknowledged).
- **Areas and AS boundary.** A route is chosen by class first (intra-area, inter-area, type-1 external or NSSA N1, type-2 external or N2), then by cost; two type-2 externals compare the LSA's own metric before the distance to the ASBR. The metric installed is always the LSA's metric plus the distance to the ASBR. Unlike OSPFv2, an external LSA's own metric counts, and an ABR passes another router's external LSAs on into all its areas. Hellos and LSAs set the E option bit, except in a stub area.
- **Link failure.** A lost local link (interface deleted, set down, or carrier lost) drops its neighbours within about a second: `nos-ospfv3d` follows the link state `nos-interfaced` streams and logs `ospfv3 link kernel interface down link=eth0.0 reason=absent|admin-down|no-carrier`, then `ospfv3 link kernel interface up` when it returns (a recreated device gets a fresh socket). The LSAs of the dropped link are withdrawn on the next origination tick. A failure beyond the local link (a dead remote end, a switch in between) still takes the dead interval (BFD is #190). A restarting `nos-interfaced` or `nos-ribd` tears no link down: the link keeps its running address, VRF and bridge (`ospfv3 link resolution failed, keeping running link`) while the configuration still demands it. With `--driver noop` nothing is gated.
- **Withdrawal.** An LSA the router stops originating is flushed within about 2 seconds (log `ospfv3 lsa prematurely aged`): for example its network LSA after it stops being DR or loses its last Full neighbour on the link, or its LSAs in an area it has left. Unlike OSPFv2, a clean stop of `nos-ospfv3d` flushes nothing; neighbours drop the router when the dead interval runs out.

## Not supported yet

These work in OSPFv2 but not yet in OSPFv3:

- **RFC 7474-style replay protection** (`extended-sequence-numbers`).

Also not supported: several OSPFv3 instances on one link, IPv4 route computation and the multicast address families of RFC 5838 (one instance ID per link works, see [Set the instance ID](#set-the-instance-id)), graceful restart after a crash (RFC 5187 only covers restarts announced beforehand), and BFD.

## Configuration reference

Fields, types, defaults and validation are those of [OSPF](ospf.md#configuration-reference), with `ospfv3` for `ospf` in the commands and `ospfv3-instance` for `ospf-instance` in the paths. Only the differences are listed here. All paths are relative to `/v1/transactions/{tx}/`.

| Field | CLI | Config-tree path | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| instance | `edit ospfv3 instance <name>`; `delete ospfv3 instance <name>` | `ospfv3-instance/<name>` | string, 1 to 64 characters | unique among OSPFv3 instances | names the instance | `show config` |
| router ID | `set ospfv3 instance <name> router-id <ip>`; relative `set router-id <ip>` | `ospfv3-instance/<name>/router-id` | dotted quad | | router ID in Hellos and LSAs | `show ospfv3 neigh` on the neighbour |
| extended LSAs | `set ospfv3 instance <name> extended-lsa`; `delete ospfv3 instance <name> extended-lsa` (absolute only) | `ospfv3-instance/<name>/extended-lsa` | boolean; default `false` | | originate RFC 8362 extended LSAs | `show ospfv3 database` |
| extended LSAs, sparse | `set ospfv3 instance <name> extended-lsa-sparse`; `delete ospfv3 instance <name> extended-lsa-sparse` (absolute only) | `ospfv3-instance/<name>/extended-lsa-sparse` | boolean; default `false`; exclusive with `extended-lsa` | | RFC 8362 sparse mode: legacy LSAs, extended ones merged from neighbours | `show ospfv3 database` |
| graceful restart | `set ospfv3 instance <name> graceful-restart grace-period <seconds>`; `delete ospfv3 instance <name> graceful-restart grace-period` | `ospfv3-instance/<name>/graceful-restart-grace-period` | seconds, 1 to 1800; unset by default | | on SIGTERM, ask Full neighbours to keep the adjacency and routes this long (RFC 5187) | `ospfv3 helper: grace period entered` in the neighbour's log |
| graceful restart helper cap | `set ospfv3 instance <name> graceful-restart helper max-grace-period <seconds>`; `delete ospfv3 instance <name> graceful-restart helper max-grace-period` | `ospfv3-instance/<name>/graceful-restart-helper-max-grace-period` | seconds, 1 to 3600; 1800 when unset | | the longest grace period this router honours for a restarting neighbour | `effective_grace=` in `ospfv3 helper: grace period entered` |
| LSDB overload limit | `set ospfv3 instance <name> max-lsa <n>`; `delete ospfv3 instance <name> max-lsa` | `ospfv3-instance/<name>/max-lsa` | 1 to 1000000; 100000 when unset | | LSAs not originated by this router that one store (each area, the AS scope, each link's Link-LSAs) holds; a new LSA past it is discarded unacknowledged, held ones stay updatable, own and MaxAge LSAs never count, no neighbour is reset, links do not restart | `ospfv3 lsdb limit reached` (rate-limited, with `refused` total) |
| area type | `set ospfv3 instance <name> area <area-id> area-type normal\|stub\|totally-stubby\|nssa\|nssa-no-summary`; `delete … area-type` | `…/area/<area-id>/area-type` | `"Normal"`, `"Stub"`, `"TotallyStubby"`; `Normal` by default | not on `0.0.0.0`; no `nssa` | stub: no AS-external LSA, E bit clear, a `::/0` from the ABR; totally stubby: only that default; restarts the area's adjacencies | `show ospfv3 database`, `show route <table>` |
| stub default cost | `set ospfv3 instance <name> area <area-id> stub-default-cost <metric>`; `delete … stub-default-cost` | `…/area/<area-id>/stub-default-cost` | 1 or more; 1 when unset | only on a stub area | metric of the ABR's `::/0` | `show ospfv3 database` |
| max-metric administrative | `set ospfv3 instance <name> max-metric router-lsa administrative`; `delete ospfv3 instance <name> max-metric router-lsa administrative` | `ospfv3-instance/<name>/max-metric-administrative` | bool; off by default | | RFC 6987 stub router until removed | `ospfv3 stub router max-metric changed` |
| max-metric on-startup | `set ospfv3 instance <name> max-metric router-lsa on-startup <seconds>`; `delete ...` | `ospfv3-instance/<name>/max-metric-on-startup` | seconds, 5 to 86400; unset by default | | stub router for this long after the next start | `reason="on-startup"` |
| max-metric on-shutdown | `set ospfv3 instance <name> max-metric router-lsa on-shutdown <seconds>`; `delete ...` | `ospfv3-instance/<name>/max-metric-on-shutdown` | seconds, 1 to 3; unset by default | | stub router for this long before the process exits | `reason="on-shutdown"` |
| routing table | `set routing-table <table> ospfv3-instance <name>`; `delete routing-table <table> ospfv3-instance` | `routing-table/<table>/ospfv3-instance` | instance name | the instance must exist; one table per instance | runs the instance in that table | `show ospfv3 neigh` |
| area | `edit ospfv3 instance <name> area <area-id>`; `delete ospfv3 instance <name> area <area-id>` | `ospfv3-instance/<name>/area/<area-id>` | dotted quad | unique within the instance | links/loopbacks in 2+ areas, one the backbone, make an ABR (`range <cidr> [not-advertise]` summarizes the area, see [ranges](#summarize-an-area-with-ranges)) | `show ospfv3 database` |
| virtual link | `set ospfv3 instance <name> area <area-id> virtual-link <router-id> [hello-interval <s>] [dead-interval <s>] [crypto-key …]`; `delete … virtual-link <router-id>` | `…/area/<area-id>/virtual-link/<router-id>` | the area is the transit area; router ID unique per area, not the instance's own | not on `0.0.0.0`, a stub area or an NSSA; dead interval above hello interval; keys as on a profile | backbone adjacency to that ABR across the area, needs an area-1 `/128` loopback at both ends | `show ospfv3 neigh` |
| redistribute | `set routing-table <table> redistribute ospfv3 [policy <p>]`; `delete routing-table <table> redistribute ospfv3` | `routing-table/<table>/redistribute/ospfv3`, `{"from":"Static","to":"Ospfv3","policy":null}` | one rule per target | needs `static-routing-instance` and `ospfv3-instance` | IPv6 static routes become AS-external LSAs | `show ospfv3 database` on a neighbour |
| profile | `edit ospfv3 instance <name> area <area-id> profile <p>`; `delete ospfv3 instance <name> area <area-id> profile <p>` | `…/area/<area-id>/profile/<p>` | string, 1 to 64 characters | unique among OSPFv3 profiles | | |
| hello interval, dead interval, cost, priority, MTU, network type | `set ospfv3 instance <name> area <area-id> profile <p> <field> <value>`; relative forms as in OSPF | `…/profile/<p>/hello-interval`, `dead-interval`, `cost`, `priority`, `mtu`, `mtu-ignore`, `network-type` | as in OSPF | as in OSPF | as in OSPF | `show ospfv3 neigh` |
| Passive | `set ospfv3 instance <name> area <area-id> profile <p> passive enable`; relative `set passive enable` / `delete passive` | `…/profile/<p>/passive` | `true`/`false`; default `false` | excludes crypto-key and bfd | advertise the attach point's prefix, no Hello, no adjacency | `GET …/profile/<p>/passive` |
| crypto key | `set ospfv3 instance <name> area <area-id> profile <p> crypto-key <id> <algorithm> <label>`; relative `set crypto-key …` / `delete crypto-key <id>` *(relative only)* | `…/profile/<p>/auth`, `[{"key_id":300,"algorithm":"HmacSha256","key":"<label>","is_current":true}]` | ID 0 to 65535; `hmac-sha1`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512`; label of an admin key whose secret is 1 to 80 bytes; unset by default | labels must exist, at least one key, IDs unique, exactly one current, no `md5` | RFC 7166 authentication trailer | `show this` in the profile |
| current key | `set … profile <p> crypto-key <id> current`; relative `set crypto-key <id> current` | `is_current` of each key | | the key must exist | signs sent packets; all keys verify | `show this` in the profile |
| address family | `set ospfv3 instance <name> address-family <ipv6-unicast\|ipv4-unicast>`; `delete … address-family` | `ospfv3-instance/<name>/address-family` | `Ipv6Unicast` (default), `Ipv4Unicast` | every profile's instance ID within the family's range | `ipv4-unicast` sets the AF-bit and requires it from neighbours | `show this` in the instance |
| instance ID | `set ospfv3 instance <name> area <area-id> profile <p> instance-id <n>`; relative `set instance-id <n>` / `delete instance-id` | `…/profile/<p>/instance-id` | 0 to 31 or 64 to 95; unset means 0 | in the instance's address family range | sent in every packet; packets with another instance ID are dropped | `show this` in the profile |
| no authentication | relative `delete auth` *(relative only)* | `DELETE …/profile/<p>/auth` | default | | | |
| subinterface / loopback | `set interface <if>[.<tag>] ospfv3 <p>`, `set interface loopback-<table> ospfv3 <p>`; `delete interface <if> ospfv3 <p>` | `interface/<if>/subinterface/<tag>/ospfv3-profiles`, `interface/loopback-<table>/ospfv3-profiles` (a list) | | the attach point needs `routing-table`; at most one profile per instance, distinct effective Instance IDs | runs OSPFv3 on the link | `show ospfv3 neigh` |
| broadcast domain | relative only: `set ospfv3 <p>` / `delete ospfv3 <p>` inside `edit broadcast domain <name>` | `broadcast-domain/<name>/ospfv3-profiles` (a list) | | the domain needs `routing-table` | runs OSPFv3 on the domain's SVI | `show ospfv3 neigh` |

OSPFv3 profiles have no `simple-password` and no `extended-sequence-numbers`. The instance's `routing_table` and `redistribute_policy` JSON fields are filled in by the router and are read-only.
