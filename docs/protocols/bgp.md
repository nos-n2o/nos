# BGP

NOS speaks BGP-4 (RFC 4271) over IPv4 and IPv6. Use it to peer with upstream providers and customers over eBGP, to carry routes between your own routers over iBGP (with or without route reflectors), to act as a route server at an exchange point, and to carry EVPN routes for VXLAN. Every BGP instance runs inside one routing table (a VRF): it opens its sessions from that VRF and installs its best routes into it.

This page covers sessions and their options. Which routes a session accepts and advertises is decided by routing policies, covered in [Routing policy](routing-policy.md). How NOS implements BGP internally is in [BGP internals](bgp-internals.md); the rules for editing the crate are in [`bgp/CLAUDE.md`](../../bgp/CLAUDE.md).

- [How BGP is configured](#how-bgp-is-configured)
- [Bringing up a session](#bringing-up-a-session)
- [Checking sessions and routes](#checking-sessions-and-routes)
- [Advertising routes](#advertising-routes)
- [Timers](#timers)
- [Shutting a session down](#shutting-a-session-down)
- [Asking a peer to resend its routes](#asking-a-peer-to-resend-its-routes)
- [Removing peers and instances](#removing-peers-and-instances)
- [Features and how they behave](#features-and-how-they-behave)
- [Configuration reference](#configuration-reference)

## How BGP is configured

BGP configuration has three levels:

- A **BGP instance** (`bgp instance <name>`) is one BGP speaker: its AS number, its router ID and, for route reflection, its cluster ID. It does nothing until a routing table claims it with `set routing-table <table> bgp-instance <name>`. Each instance belongs to at most one routing table, and each routing table has at most one instance.
- A **peer-group** (`peer-group <name>`, inside an instance) holds every session setting: remote AS, address families, timers, authentication, next-hop handling, policies. There is no per-peer override other than shutdown, so peers that need different settings go in different peer-groups.
- A **peer** (`peer <address>`, inside an instance) is a neighbour's address and the peer-group it uses.

Three rules catch people out:

- **Both policies default to `deny-all`.** A peer-group with no `import-policy` accepts no routes, and one with no `export-policy` advertises none. The session still comes up, so nothing looks wrong until you check the routes. Set both, to `accept-all` or to one of your own policies (see [Routing policy](routing-policy.md)).
- **Changing a peer-group resets its sessions.** Any change to a peer-group, or to a policy it uses, except `bfd` (see [BFD](#bfd-rfc-5882-rfc-9384)) and, with [soft reconfiguration inbound](#keeping-received-routes-soft-reconfiguration-inbound), an import-policy change, closes its established sessions with a Cease NOTIFICATION (RFC 4486 subcode 6, Other Configuration Change) and opens them again with the new settings. Plan changes to production peer-groups accordingly.
- **Names are global.** Peer-group names and peer addresses must be unique across all BGP instances, not just within one.

## Bringing up a session

This session sets up an eBGP session from router-a (AS 65001, 10.50.0.2) to router-b (AS 65002, 10.50.0.3) in routing table `rt1`, whose interface `eth0` already has the address 10.50.0.2/24:

```
edge-1> configure bgp1
edge-1(bgp1)> edit bgp instance r1
edge-1(bgp1/bgp-instance:r1)> set asn 65001
edge-1(bgp1/bgp-instance:r1)> set router-id 1.1.1.1
edge-1(bgp1/bgp-instance:r1)> edit peer-group pg1
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> set remote-as 65002
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> set address-family ipv4
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> set import-policy accept-all
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> set export-policy accept-all
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> set connect-retry-time 5
edge-1(bgp1/bgp-instance:r1/peer-group:pg1)> up
edge-1(bgp1/bgp-instance:r1)> set peer 10.50.0.3 peer-group pg1
edge-1(bgp1/bgp-instance:r1)> top
edge-1(bgp1)> set routing-table rt1 bgp-instance r1
edge-1(bgp1)> commit
transaction 'bgp1' committed
edge-1> show bgp brief
bgp instance r1:
  10.50.0.3 AS 65002 peer-group pg1 Established uptime 00:00:04 hold-time 90
```

Router-b needs the mirror image (AS 65002, router ID 2.2.2.2, remote AS 65001, peer 10.50.0.3 replaced by 10.50.0.2). NOS both connects to the peer and accepts its connection on TCP port 179, in the routing table's VRF; whichever connection wins RFC 4271 collision resolution becomes the session.

`connect-retry-time 5` is optional. The default is 120 seconds, which is how long a session can stay down after a failed attempt, for instance while the other side is still being configured.

Over REST, create the whole instance in one `PUT`, then link it to the routing table. A peer-group's `route_reflector_client` and `route_server_client` must be present; every other field can be left out and takes its default:

```sh
$ $C -X POST "$B/v1/transactions/bgp1?base=current" -o /dev/null -w '%{http_code}\n'
201
$ $C -X PUT -H 'Content-Type: application/json' -d '{
    "name": "r1", "asn": 65001, "router_id": "1.1.1.1",
    "peer_groups": [{"name": "pg1", "remote_as": 65002, "address_families": ["Ipv4Unicast"],
                     "import_policy": "accept-all", "export_policy": "accept-all",
                     "connect_retry_time": 5,
                     "route_reflector_client": false, "route_server_client": false}],
    "peers": [{"remote_address": "10.50.0.3", "peer_group": "pg1"}]
  }' $B/v1/transactions/bgp1/bgp-instance/r1 -o /dev/null
$ $C -X PUT -H 'Content-Type: application/json' -d '"r1"' \
    $B/v1/transactions/bgp1/routing-table/rt1/bgp-instance
"r1"
$ $C -X POST $B/v1/transactions/bgp1/commit
{"committed":"bgp1","warnings":[]}
```

To add a peer-group or a peer to an existing instance, `PUT` just that element:

```sh
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"remote_address":"10.50.0.3","peer_group":"pg1"}' \
  $B/v1/transactions/bgp1/bgp-instance/r1/peer/10.50.0.3
```

## Checking sessions and routes

`show bgp brief` (REST: `GET /v1/bgp/summary`) lists every peer of every instance: its state, the AS it announced, how long it has been up, and the negotiated hold time. The states are `Idle` (no OPEN exchanged yet: not connected, or retrying), `OpenSent`, `OpenConfirm` and `Established`. A shut-down peer shows as `Idle (shutdown)`, and a peer held down by its [maximum-prefix](#limiting-the-prefixes-a-peer-sends) limit as `Idle (max-prefix)`. An Established line ends with the accepted prefixes per address family, for example `prefixes v4 3`.

```
edge-1> show bgp brief
bgp instance r1:
  10.50.0.3 AS 65002 peer-group pg1 Established uptime 00:02:21 hold-time 90
```

The JSON form has more detail: the peer's BGP identifier, the negotiated keepalive, and, for TCP-AO sessions, the key state (see [TCP-AO](#tcp-ao-rfc-5925)):

```sh
$ $C $B/v1/bgp/summary | jq '.[0].result[0]'
{
  "remote_address": "10.50.0.3",
  "peer_group": "pg1",
  "shutdown": false,
  "remote_as": 65002,
  "remote_bgp_id": "2.2.2.2",
  "state": "Established",
  "uptime_secs": 141,
  "negotiated_hold_time": 90,
  "negotiated_keepalive": 30,
  …
}
```

Routes learned over BGP and chosen as best appear in the routing table as `bgp`. `show route <table>` lists every candidate for each prefix, best first:

```
edge-2> show route rt1 198.51.100.1
198.51.100.0/24
  * via 10.50.0.2 [bgp]
```

There is no command yet that lists BGP routes with their attributes (AS path, communities and so on). The router's log records each route as it is learned and each change of best path; see `show log nos-bgpd[r1]` in the shell or `GET /v1/logs?source=nos-bgpd%5Br1%5D` (see [Concepts: Logs](../concepts.md#logs)).

## Advertising routes

NOS advertises two kinds of routes to BGP peers:

- routes learned from other BGP peers, subject to the usual iBGP rules (see [Route reflection](#route-reflection-rfc-4456));
- static routes of the same routing table, once you redistribute them with `set routing-table <table> redistribute bgp`.

Every advertisement also has to pass the peer-group's export policy. This example advertises 198.51.100.0/24 from router-a:

```
edge-1> configure adv
edge-1(adv)> edit static-routing-instance s1
edge-1(adv/static-routing-instance:s1)> set route 198.51.100.0/24 gateway 10.50.0.1
edge-1(adv/static-routing-instance:s1)> top
edge-1(adv)> set routing-table rt1 static-routing-instance s1
edge-1(adv)> set routing-table rt1 redistribute bgp
edge-1(adv)> commit
transaction 'adv' committed
```

```sh
$C -X POST "$B/v1/transactions/adv?base=current" -o /dev/null
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"name":"s1","routes":[{"subnet":"198.51.100.0/24","gateway":"10.50.0.1"}]}' \
  $B/v1/transactions/adv/static-routing-instance/s1
$C -X PUT -H 'Content-Type: application/json' -d '"s1"' \
  $B/v1/transactions/adv/routing-table/rt1/static-routing-instance
$C -X PUT -H 'Content-Type: application/json' -d '{"from":"Static","to":"Bgp","policy":null}' \
  $B/v1/transactions/adv/routing-table/rt1/redistribute/bgp
$C -X POST $B/v1/transactions/adv/commit
```

Adding `policy <name>` to the redistribute command filters the static routes before they enter BGP; see [Routing policy: Where policies attach](routing-policy.md#where-policies-attach).

A peer that reads slowly never makes `nos-bgpd` queue updates without limit: once its outbox is full, changes are coalesced per prefix and the current state is sent when it catches up (see [Per-peer outbox is bounded](bgp-internals.md#per-peer-outbox-is-bounded-395)).

## Timers

Three timers are set per peer-group:

- `hold-time` (default 90 seconds) is the hold time this router proposes in its OPEN. The session uses the lower of the two sides' values. `0` turns off both the hold timer and keepalives; otherwise the minimum is 3.
- A peer that offers hold time 0 is refused (NOTIFICATION OPEN / Unacceptable Hold Time, RFC 4271 §6.2) unless this peer-group's `hold-time` is `0` too.
- `keepalive-interval` (default: a third of the negotiated hold time) must be lower than `hold-time` when both are set.
- `connect-retry-time` (default 120 seconds) is how long NOS waits between two attempts to connect to a peer.

```
edge-1(t1/bgp-instance:r1/peer-group:pg1)> set hold-time 30
edge-1(t1/bgp-instance:r1/peer-group:pg1)> set keepalive-interval 10
edge-1(t1/bgp-instance:r1/peer-group:pg1)> set connect-retry-time 5
```

The absolute form works from anywhere in the transaction: `set bgp instance r1 peer-group pg1 hold-time 30`. To go back to a default, use `delete hold-time` (or `keepalive-interval`, `connect-retry-time`) inside the peer-group, or the absolute `delete bgp instance r1 peer-group pg1 hold-time`.

```sh
$C -X PUT -H 'Content-Type: application/json' -d '30' $B/v1/transactions/t1/bgp-instance/r1/peer-group/pg1/hold-time
$C -X PUT -H 'Content-Type: application/json' -d '10' $B/v1/transactions/t1/bgp-instance/r1/peer-group/pg1/keepalive-interval
$C -X DELETE $B/v1/transactions/t1/bgp-instance/r1/peer-group/pg1/hold-time      # back to the default
```

`show bgp brief` shows the negotiated hold time once the session is back up. A keepalive interval that no longer fits under the negotiated hold time (because the peer proposed a lower one) is replaced by a third of the negotiated value.

## Shutting a session down

`shutdown` closes a session and keeps it closed without removing its configuration (RFC 4486). You can shut a whole peer-group or one peer, with an optional message of up to 255 bytes that the peer receives in its Cease NOTIFICATION (RFC 9003) and can log:

```
edge-1(t2/bgp-instance:r1/peer-group:pg1)> set shutdown maintenance until 18:00, ticket 4711
edge-1(t2/bgp-instance:r1/peer-group:pg1)> commit
transaction 't2' committed
edge-1> show bgp brief
bgp instance r1:
  10.50.0.3 AS - peer-group pg1 Idle (shutdown) uptime - hold-time -
```

The peer logs the message:

```
edge-2> show log nos-bgpd[r1]
…  INFO nos-bgpd[r1] nos_bgp::fsm: received notification (peer=10.50.0.2 code=6 subcode=9 hard_reset_code=6 hard_reset_subcode=2 shutdown_message="maintenance until 18:00, ticket 4711")
```

Between two routers with graceful restart (the default), the Cease goes out as an RFC 8538 Hard Reset (subcode 9) wrapping the Administrative Shutdown, so the peer drops the routes at once; without it, the peer logs `subcode=2` directly.

To shut one peer only, set it on the peer, inside the instance: `set peer 10.50.0.3 shutdown [<message>]`, or `set bgp instance r1 peer 10.50.0.3 shutdown [<message>]` from the top. A shutdown set on a peer takes precedence over its peer-group's. `delete shutdown` (in the peer-group) or `delete peer 10.50.0.3 shutdown` (in the instance) brings the session back up.

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"message":"maintenance until 18:00, ticket 4711"}' \
  $B/v1/transactions/t2/bgp-instance/r1/peer-group/pg1/shutdown
$C -X PUT -H 'Content-Type: application/json' -d '{"message":null}' \
  $B/v1/transactions/t2/bgp-instance/r1/peer/10.50.0.3/shutdown           # one peer, no message
$C -X DELETE $B/v1/transactions/t2/bgp-instance/r1/peer-group/pg1/shutdown # up again
```

## Asking a peer to resend its routes

`clear bgp <instance> <peer> soft-in` sends the peer a route refresh request (RFC 2918): it resends every route it advertises to you, without resetting the session. Use it after changing something that affects routes you already hold, for example a prefix list that an import policy uses. It works in both modes and changes no configuration. If the peer-group has [soft reconfiguration inbound](#keeping-received-routes-soft-reconfiguration-inbound), nothing is sent: the import policy is re-evaluated over the routes NOS kept, and the command prints the result per family:

```
edge-1> clear bgp r1 10.50.0.3 soft-in
route refresh requested for 10.50.0.3
```

```sh
$ $C -X POST $B/v1/bgp/r1/peer/10.50.0.3/soft-in
{"instance":"r1","peer":"10.50.0.3","route_refresh":"sent"}
```

```
edge-1> clear bgp r1 10.50.0.3 soft-in
re-evaluated import policy for 10.50.0.3:
  ipv4-unicast: 120 retained, 118 accepted
```

```sh
$ $C -X POST $B/v1/bgp/r1/peer/10.50.0.3/soft-in
{"instance":"r1","peer":"10.50.0.3","route_refresh":"none","reevaluated":[{"family":"ipv4-unicast","retained":120,"accepted":118}]}
```

The request fails with `404` over REST if the peer is not configured or its session is not Established. It is `503` if a local re-evaluation was superseded or aborted (by a policy change, a disconnect or a maximum-prefix trip).

## Keeping received routes (soft reconfiguration inbound)

Without it, a route the import policy rejects is dropped, so changing a policy means restarting the session or asking the peer to resend. With `soft-reconfiguration-inbound` NOS keeps every route the peer sends before the import policy, and a policy change is applied in place: no session reset, no route refresh.

- Enable it per peer-group: `set bgp instance r1 peer-group pg1 soft-reconfiguration-inbound true` (REST: `"soft_reconfiguration_inbound": true` on the peer-group). `delete` it to turn it off.
- Scope: every family the peer-group carries. What is kept differs:
  - IPv4/IPv6 unicast and VPNv4/VPNv6: every received path, before the import policy (VPN paths use the peer-group's `import-policy`, run with the route's RD).
  - Flowspec: every received rule, before `flowspec-import-policy`, which rewrites the stored rule.
  - EVPN: only the routes `evpn-import-policy` rejects. The held ones are already unmodified, since that policy only accepts or rejects.
- A change to `import-policy`, `evpn-import-policy` or `flowspec-import-policy` is applied in place. A change to an export policy (`export-policy`, `flowspec-export-policy`) or anything else still restarts the sessions.
- NOS logs `soft reconfiguration: re-evaluated import policy peer=… family=… retained=… accepted=… changed=…` once per family, then `soft reconfiguration: re-evaluation finished` with the chunk count and duration. Routes whose result changed are re-decided and re-advertised; the rest are untouched. No damping penalty is applied.
- The re-evaluation runs in chunks of 5000 prefixes and releases the RIB between them, so UPDATEs keep being processed. On a 1M-prefix table, a chunk held the lock about 5 ms (release build). A newer policy change supersedes a running pass; `soft-in` during a pass waits for it.
- Enabling it on a session that is already up asks the peer for a route refresh (when it supports it) and keeps what comes back. A peer without the Route Refresh capability gets its session restarted instead (Cease, Other Configuration Change), since only a new session retains every route. Enabling while the session is down needs nothing: the next session retains from its first UPDATE.
- Retention is complete once the peer has finished that refresh: with enhanced route refresh NOS logs `soft reconfiguration: retention complete`; otherwise only `retention enabled, route refresh requested`. A `soft-in` before then re-evaluates what is held so far.
- Disabling it frees the memory and resets nothing (`soft reconfiguration: retention disabled`). Disabling it together with a policy change restarts the sessions.
- Retention is dropped whenever the session ends, graceful restart included: after a restart it refills from the peer's announcements only.
- Routes dropped before policy (AS loop, unusable next hop, first-AS and role-leak checks) are not kept.
- Memory: roughly one extra copy of the peer's received routes for unicast, VPN and Flowspec; EVPN costs only the rejected set. Measured with 100k /24s from one eBGP peer: 63 MB for the RIB without the flag, 112 MB with it (about 490 bytes per prefix more).
- Enabling it on a session that is up also asks for EVPN and Flowspec refreshes when those families are negotiated. An EVPN or Flowspec peer that answers no refresh keeps its old routes unretained until it re-announces them.
- While a large re-evaluation runs, other peers and the feeds to `nos-fdbd`/VRFs can see the intermediate state (some routes already re-decided, some not); the end state is the same as a one-step re-evaluation.
- `clear bgp … soft-in` waits for a running pass. If a policy change supersedes it, or the session drops, or a maximum-prefix limit trips during it, the reply is an error: `import policy changed during re-evaluation`, `session down` or `maximum prefix exceeded during re-evaluation`.
- A change of RPKI VRPs re-evaluates a retained peer locally instead of asking it for a route refresh.

Example:

```
edge-1(t9/bgp-instance:r1/peer-group:pg1)> set soft-reconfiguration-inbound true
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d 'true' \
  $B/v1/transactions/t9/bgp-instance/r1/peer-group/pg1/soft-reconfiguration-inbound
```

## Limiting the prefixes a peer sends

`set maximum-prefix <family> limit <n>` caps how many prefixes each peer of the peer-group may send in that address family (RFC 4486). The family is `ipv4`, `ipv6`, `l2vpn-evpn`, `ipv4-flowspec`, `ipv6-flowspec`, `vpnv4` or `vpnv6`, and must be one the peer-group negotiates.

- Prefixes are counted per peer, after the import policy: a route the policy rejects does not count.
- Each family has its own limit and its own count.
- One prefix over the limit closes the session with a Cease NOTIFICATION, subcode 1 (Maximum Number of Prefixes Reached), carrying the family and the limit.
- The peer then stays down: NOS neither connects to it nor accepts its connections.
- There is no built-in cap: with no `maximum-prefix` for a family, a peer may send any number of prefixes. `limit 0` is the explicit form of that: nothing is enforced and the warning below is silenced.
- Committing an eBGP peer-group (its `remote-as` differs from the instance `asn`) with no limit for a negotiated family prints a warning, e.g. `warning: bgp-instance 'r1' peer-group 'ext': eBGP, no maximum-prefix for ipv4 (...)`. The commit still succeeds; set a limit to silence it, or `limit 0` to say the peer-group is deliberately uncapped. Over REST the commit reply lists them in `warnings` (`[]` when none).

```
edge-1(t3/bgp-instance:r1/peer-group:pg1)> set maximum-prefix ipv4 limit 1000
edge-1(t3/bgp-instance:r1/peer-group:pg1)> commit
transaction 't3' committed
edge-1> show bgp brief
bgp instance r1:
  10.50.0.3 AS - peer-group pg1 Idle (max-prefix) uptime - hold-time -
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"limit":1000,"warning_only":false,"restart_interval":0}' \
  $B/v1/transactions/t3/bgp-instance/r1/peer-group/pg1/maximum-prefix/ipv4
```

To bring a held peer back, do one of:

- `clear bgp <instance> <peer>` (REST: `POST /v1/bgp/{instance}/peer/{peer}/clear`). On a peer whose session is up, this resets the session with Cease subcode 4 (Administrative Reset). It changes no configuration.
- Shut the peer or its peer-group down and bring it back up.
- Change the limit. Any change to `maximum-prefix` restarts the peer-group's sessions.

```
edge-1> clear bgp r1 10.50.0.3
cleared 10.50.0.3
```

```sh
$ $C -X POST $B/v1/bgp/r1/peer/10.50.0.3/clear
{"instance":"r1","peer":"10.50.0.3","cleared":true}
```

If the peer keeps sending too many prefixes, the limit trips again as soon as it reconnects.

Two options change what a trip does:

- `warning-only`: log `maximum prefix limit exceeded` and keep the session up. The warning is logged once each time the count goes over the limit.
- `restart-interval <seconds>`: let the peer reconnect by itself after that long. `0`, the default, keeps it down until cleared.

```
edge-1(t4/bgp-instance:r1/peer-group:pg1)> set maximum-prefix ipv4 limit 1000 restart-interval 300
```

`delete maximum-prefix <family>` removes that family's limit. The router logs every trip (`maximum prefix limit exceeded`, with the peer, family, count and limit) and the Cease it sends.

## Removing peers and instances

- `delete peer 10.50.0.3` in the instance (or `delete bgp instance r1 peer 10.50.0.3`) removes a peer. Its session is closed with a Cease / Peer De-configured NOTIFICATION (RFC 4486 subcode 3).
- `delete peer-group pg1` in the instance (or `delete bgp instance r1 peer-group pg1`) removes a peer-group. Remove or move its peers first: a peer that names a missing peer-group is refused at commit.
- `delete bgp instance r1` removes the instance. Remove the routing table's reference to it in the same transaction (`delete routing-table rt1 bgp-instance`), or the commit is refused.

Over REST, `DELETE` the same paths: `…/bgp-instance/r1/peer/10.50.0.3`, `…/bgp-instance/r1/peer-group/pg1`, `…/bgp-instance/r1` and `…/routing-table/rt1/bgp-instance`.

## Features and how they behave

### Sessions and capabilities (RFC 4271)

NOS runs the full RFC 4271 session: OPEN, KEEPALIVE, UPDATE and NOTIFICATION, with the hold and keepalive timers described in [Timers](#timers) and real collision resolution (§6.8) when both sides connect at once. It checks the peer's OPEN: BGP version 4, the AS number against the peer-group's `remote-as`, a valid BGP identifier and a valid hold time. Any mismatch is answered with the matching NOTIFICATION and the session is closed.

Every OPEN advertises these capabilities, with no option to turn them off:

- four-octet AS numbers (RFC 6793), see below;
- route refresh (RFC 2918) and enhanced route refresh (RFC 7313);
- extended messages up to 65535 bytes (RFC 8654), used only when the peer also advertises it;
- extended optional parameters (RFC 9072), used in an OPEN only when its capabilities exceed 255 bytes;
- multiprotocol extensions (RFC 4760) for each configured address family.

A malformed attribute in a received UPDATE does not reset the session: the routes in that UPDATE are treated as withdrawn and logged (RFC 7606). Attributes whose flags conflict with their type are treated the same way; a repeated attribute keeps its first occurrence (a repeated multiprotocol attribute resets the session). Only a message that cannot be parsed at all closes the session.

- A route whose next hop is unusable is treated as withdrawn and logged (`treating bgp update as withdraw: invalid next hop`): unspecified, `0.0.0.0/8`, loopback, multicast, class-E (incl. broadcast), IPv4-mapped IPv6, or the session's own local address. A link-local IPv6 next hop is accepted. Checked for the `NEXT_HOP` attribute and every `MP_REACH_NLRI`, EVPN included; a peer reached over loopback may advertise loopback.

- A route whose next hop is unusable is treated as withdrawn and logged (`treating bgp update as withdraw: invalid next hop`): unspecified, `0.0.0.0/8`, loopback, multicast, class-E (incl. broadcast), IPv4-mapped IPv6, or the session's own local address. A link-local IPv6 next hop is accepted. Checked for the `NEXT_HOP` attribute and every `MP_REACH_NLRI`, EVPN included; a peer reached over loopback may advertise loopback.

### Address families

`set address-family ipv4|ipv6|l2vpn-evpn|ipv4-flowspec|ipv6-flowspec|vpnv4|vpnv6` adds an address family to a peer-group, and `delete address-family <af>` removes one. A peer-group needs at least one. The address families are independent of whether the peer is reached over IPv4 or IPv6: an IPv6 peer can carry IPv4 routes and the reverse.

- `ipv4` and `ipv6` are unicast routes, installed in the routing table.
- `l2vpn-evpn` (RFC 7432) carries EVPN routes for VXLAN broadcast domains. It is described with the rest of EVPN.
- `ipv4-flowspec` and `ipv6-flowspec` (RFC 8955, RFC 8956) carry Flowspec rules. See [Flowspec](#flowspec-rfc-8955-rfc-8956).
- `vpnv4` and `vpnv6` (RFC 4364, RFC 4659) are the L3VPN families. See [L3VPN](#l3vpn-vpnv4vpnv6).

Over REST the list is `address_families`, with the values `Ipv4Unicast`, `Ipv6Unicast`, `L2vpnEvpn`, `Ipv4Flowspec`, `Ipv6Flowspec`, `Vpnv4Unicast` and `Vpnv6Unicast`: `PUT …/peer-group/pg1/address-family/Ipv6Unicast` with body `"Ipv6Unicast"` adds one, and `DELETE` on the same path removes it.

### L3VPN (VPNv4/VPNv6)

NOS is a PE and a VPN route reflector for RFC 4364 / RFC 4659 L3VPN (AFI 1 and 2, SAFI 128): it exports a VRF's routes as labelled VPN routes, imports received ones into VRFs by Route Target, forwards over MPLS, and reflects VPN routes without holding any VRF.

Prerequisites:

- Load the kernel modules `mpls_router` and `mpls_iptunnel` on the host and set the MPLS sysctls: [Prepare a router as an L3VPN PE](routing-tables.md#prepare-a-router-as-an-l3vpn-pe). `make e2e-preflight` checks a lab host.
- A reachable PE: the PEs must reach each other's session address in the underlay table (directly connected or through an IGP). Only the VPN label is pushed, no transport label.

Configure a PE:

1. Name the VRF's VPN identity on its routing table (the table must differ from the underlay's): `set routing-table red vpn rd 65000:100`, `set routing-table red vpn route-target export 65000:1`, `set routing-table red vpn route-target import 65000:1` and `set routing-table red vpn bgp-instance r1` (the underlay instance). Fields and checks: [routing tables](routing-tables.md#configuration-reference).
2. Optionally pin the label (`vpn label 100`) and mark the CE site (`vpn site-of-origin 65001:77`, below). Otherwise `nos-ribd` allocates a label from 1000 up, kept across restarts and when `vpn` is removed and set again; `show route red` prints `VPN label: <n>`.
3. Enable the families on the underlay peer-group toward the other PEs or the route reflector: `set bgp instance r1 peer-group pg1 address-family vpnv4` (and `vpnv6`). Each is negotiated only when the peer advertises it too. Over REST: `PUT …/bgp-instance/r1/peer-group/pg1/address-family/Vpnv4Unicast` with body `"Vpnv4Unicast"`.
4. Put the CE-facing interface in the VRF (`set routing-table` on its address) and run the routes you want exported in it.

What is exported:

- Every best route of the table: connected, static, OSPF and routes from CEs over the table's own BGP instance. Not exported: routes imported from VPN (no loops between PEs) and EVPN routes. New best routes from the table's own BGP or OSPF go out at the next resync of the table, within 10s.
- Each carries the RD, the export Route Targets, the Site of Origin if set, and the VRF's label. The next hop is the session's own address toward iBGP and eBGP peers alike; a VPNv6 route over an IPv4 session carries it IPv4-mapped (RFC 4659 section 3.2.1).
- A lost route is withdrawn; removing `vpn` (or its `bgp-instance`) withdraws all of them.

What is imported:

- A received VPN route goes into every VRF whose import list shares one of its Route Targets; one without a matching RT goes nowhere. Changing the import RTs moves routes at once.
- The RD is dropped on import: the same prefix under two RDs competes in the VRF and the best path wins. A `vpn` route has distance 200: a CE-facing BGP, static, connected or OSPF route for the same prefix wins.
- The PE is resolved in the underlay table (an IPv4-mapped VPNv6 next hop resolves as the IPv4 PE); a route whose PE is not reachable there is not imported until it is.
- A route carrying the VRF's own Site of Origin is not imported into it (below).

Site of Origin (RFC 4364 section 7):

- `set routing-table red vpn site-of-origin 65001:77` marks the table's CE site: the value is attached to every route the table exports, and a received route that already carries it is not imported into this table, so a route never returns to the site it came from. Another table's SoO does not block, which keeps multi-site and hub-and-spoke designs possible.
- One SoO per table, enforced at VRF import only. A VRF-scoped BGP instance advertises only its own paths and redistributed statics today, so the import is the one place a route could loop back to a CE.
- A skipped route is logged: `vpn route skipped by site of origin table=red rd=65001:4 prefix=10.30.0.0/24 soo=65001:77`. `show bgp vpnv4` ends such a line with `soo <value>`; REST has `site_of_origin`.

Look at it:

- `show bgp vpnv4` (or `vpnv6`): one line per received path with `>` on the best one, RD, prefix, label, next hop, peer and Route Targets; `show bgp vpnv4 rd 65001:1` keeps one RD. Over REST: `GET /v1/bgp/vpnv4`, `GET /v1/bgp/vpnv4?rd=65001:1` (an invalid RD is `400`).
- `show route red`: an imported route shows `via <gateway> pe <pe> rd <rd> label <n> [vpn]`. Over REST: `GET /v1/routes/red`, a candidate with `"source":"Vpn"` and, one entry per gateway, `mpls_labels` (each a label stack) and `vpn` (`pe_next_hop`, `rd`).
- On the host: `ip -f mpls route` and `ip route show vrf <vrf device>` (and `ip -6 route show vrf <vrf device>`).

Use it as a route reflector:

- Every path is held whatever its Route Targets (they only decide VRF import), so a reflector needs no VRF and no label.
- Different RDs never compete: `10.0.0.0/24` under `65001:1` and under `65001:2` are two routes, each reflected.
- Reflection follows the unicast rules (iBGP split horizon, route-reflector clients, eBGP prepend). The label, RD and next hop go out unchanged, even toward eBGP or with `next-hop self`: a new next hop would need a label of its own.
- `maximum-prefix vpnv4|vpnv6` limits each family. Graceful restart and route refresh (including enhanced refresh) cover both families.

Steer routes with policy:

- The peer-group's `import-policy` runs when a path is stored, before import by Route Target: a policy that adds an RT (`this.bgp.extended_communities.add(rt(65000:1))`) imports the route into a VRF it did not match, a reject drops it. The stored and reflected route carries the edit.
- The peer-group's `export-policy` runs on every path sent, after the RTs and Site of Origin were attached: it can remove or add an RT or SoO. `this.prefix` is the customer prefix and `this.bgp.rd` the Route Distinguisher. See [Steer VPN imports with route targets](routing-policy.md#steer-vpn-imports-with-route-targets).

Troubleshooting, by log line:

| You see | It means |
|---------|----------|
| `vpn route learned peer=… rd=… prefix=…` | A path was stored |
| `vpn route rejected by import policy` | The import policy dropped it |
| `vpn route imported table=red prefix=… labels=[…] rd=… next_hop=…` | A VRF took it |
| `vpn route skipped by site of origin table=red …` | It carries the VRF's own Site of Origin |
| `vpn route unimported table=red prefix=…` | It left the VRF (withdrawn, RT or PE lost) |
| `vpn route withheld, pe next hop unresolved in the underlay` (debug) | The PE is not reachable in the underlay table |
| `vpn route advertised peer=… rd=… prefix=… labels=[…]` | A VRF route was sent |
| `sent initial vpn snapshot to nos-bgpd table=red …` (`nos-ribd`) | The VRF's export reached `nos-bgpd` |
| `MPLS is not available`, `mpls label not programmed, vpn export withheld` (`nos-ribd`) | `mpls_router` is not loaded |

Constrain VPN distribution with RT-Constraint (RFC 4684):

- Add `address-family rt-constraint` next to `vpnv4`, `vpnv6` or `l2vpn-evpn` in the peer-group (commit refuses it alone). It is negotiated only when both sides advertise AFI 1 / SAFI 132.
- `nos-bgpd` originates one membership route per import Route Target of this instance (VRF `vpn`, the `l2vpn-evpn` import RTs of its broadcast domains and IP-VRFs), from its own AS (the confederation identifier when set). No import RT, nothing originated.
- A peer with the family negotiated receives VPN and EVPN routes only for the Route Targets it announced; the default route (prefix length 0) means everything, and a peer that announced nothing receives no VPN or EVPN route. A peer without the family is unaffected.
- A membership change adds or withdraws the matching routes at once. A route reflector re-advertises memberships with Originator ID and Cluster List, never back to the sender.
- EVPN: only locally originated routes are filtered; Ethernet Segment (Type-4) routes are never held back.
- Partial prefixes (33 to 95 bits) match the first `length - 32` bits of the Route Target and a 32-bit prefix matches every Route Target; RFC 4684 section 4 does not define this, so it is an inference.
- Export and import policy do not apply to membership routes. There is no `show` command for them; the log lines `rtc membership learned|withdrawn|advertised|advertisement withdrawn` show the exchange.
- Graceful restart: when the peer's graceful restart capability lists `rt-constraint` (NOS sends it), its memberships are kept, marked stale, while its session is down. They still count as interest, so the VPN routes it keeps from us are not withdrawn and the memberships keep being propagated. A re-announced membership loses its stale mark; the rest is purged at the peer's RTC End-of-RIB or when the restart/stale timer ends, and the VPN/EVPN routes it no longer asks for are withdrawn. A peer that comes back without the family (or with F = 0) has them purged at once.
- After a restart of this router, route selection waits for each peer's RTC End-of-RIB like for any other negotiated family, so the VPN dump is filtered by memberships that are already in.
- Limits: no policy on membership routes, no `show` command, and EVPN filtering covers locally originated routes only (EVPN routes received from peers are not re-advertised).

Limits:

- One VPN label per route (no label stacks, so no LDP or segment-routing transport).
- No inter-AS options (RFC 4364 section 10), no carrier's carrier, no ADD-PATH on SAFI 128, no per-prefix labels, one Site of Origin per table (not per CE).
- Load-balancing a VPN route over several PEs: see [Multipath](#multipath).

### Flowspec (RFC 8955, RFC 8956)

NOS learns Flowspec rules, validates them (RFC 8955 section 6), filters them through per-peer-group policies, picks a best path per rule and re-advertises it to its other peers. It originates no rule of its own. It enforces the selected rules on the interfaces you mark with `flowspec`: see [Filter DDoS traffic with flowspec](#filter-ddos-traffic-with-flowspec).

- Enable it per peer-group, like any address family: `set bgp instance r1 peer-group pg1 address-family ipv4-flowspec` (and `ipv6-flowspec`). The family is off unless configured, and negotiated only when the peer advertises it too (AFI 1 or 2, SAFI 133).
- A rule is a list of components (destination, source, protocol, ports, ICMP, TCP flags, length, DSCP, fragment, flow label). The actions are the extended communities of the route, shown decoded: `traffic-rate:0:0` is "discard", `redirect:65000:10`, `traffic-marking:10`.
- Flowspec has no next hop (RFC 8955 section 4). An empty or any other next hop is ignored.
- `maximum-prefix ipv4-flowspec|ipv6-flowspec limit <n>` caps the rules held from a peer, like the other families.
- A rule that cannot be parsed resets the session (RFC 7606 section 3(g)): an unparsable NLRI cannot be turned into a withdrawal.
- A traffic-action community that cannot be decoded (a NaN rate) makes the UPDATE treat-as-withdraw (RFC 8955 section 10); the rules in it are dropped.
- A rule for a family the session did not negotiate is ignored and logged (`flowspec routes for a family not negotiated, ignored`).
- Graceful restart keeps a listed family's rules, marked stale, until End-of-RIB (SAFI 133). A route-refresh request for SAFI 133 re-sends what the peer was last sent of that family.

#### Validity

Every received rule is `valid` or `invalid:<reason>`. An invalid rule stays in the Adj-RIB-In and is shown, but is never used by anything that consumes routes. A rule is valid when:

- **(a)** it has a destination prefix (IPv6: with offset 0, RFC 8956 section 5);
- **(b)** the unicast route with the longest prefix covering that destination, in the same address family, has the same originator (ORIGINATOR_ID, else the peer address; a locally originated route never matches), **or** (b.2, RFC 9117) the rule's own AS_PATH is empty or has only confederation segments. Such a rule is also valid when no unicast route covers its destination (a central controller); (c) is then skipped;
- **(c)** no more-specific unicast route comes from a neighbouring AS other than the one of that best match. Every received route counts, not only the best ones;
- **eBGP only:** the leftmost AS of the AS_PATH equals the leftmost AS of the best-match unicast route (RFC 9117 section 4.2), so a rule relayed by a route server validates. iBGP and confederation-member peers are accepted without this check.

Reasons: `no-destination-prefix`, `ipv6-offset-not-zero`, `no-covering-unicast-route`, `originator-mismatch`, `more-specific-from-other-as`, `leftmost-as-mismatch`, and `bad-neighbour-as` (strict mode only).

- Rules are re-validated when the unicast routes they depend on change (announce, withdraw, best-path change, peer down), and only the rules whose destination overlaps the changed prefix. `flowspec validity changed peer=… family=… flow=… validity=…` is logged each time a state changes.
- To get RFC 8955 section 6 as written (no b.2, and the eBGP check compares with the peer's AS, reported as `bad-neighbour-as`): `set bgp instance r1 peer-group pg1 flowspec-validation rfc8955-strict true` (REST: `"flowspec_validation": {"rfc8955_strict": true}`; changing it restarts the sessions).
- Flows relayed by a route server, or sent by a central iBGP controller, need nothing configured.
- To accept rules without a destination prefix on one peer-group: `set bgp instance r1 peer-group pg1 flowspec-validation disable-dest-prefix-rule true` (REST: `"flowspec_validation": {"disable_dest_prefix_rule": true}`; changing it restarts the sessions). Such a rule skips (b) and (c), which need a destination. Nothing else is relaxed (an eBGP rule without a destination is still checked against the peer's AS), and validation cannot be turned off.

#### Actions

The traffic actions are decoded from the route's extended communities and shown one per entry in `actions`:

- `0x8006` traffic-rate (bytes/s) and `0x800c` traffic-rate (packets/s): a negative or -0 rate is 0, shown as `discard`. A NaN is malformed.
- `0x8007` traffic-action: the sample and terminal bits.
- `0x8008`, `0x8108`, `0x8208` redirect to a Route Target (2-octet AS, IPv4 address, 4-octet AS forms).
- `0x8009` traffic-marking: the DSCP value.
- The redirect to an IPv6 address (RFC 8956 section 6.1, sub-type `0x0d`) travels in the IPv6-address-specific extended community attribute (RFC 5701, attribute 25). It is shown as `redirect ipv6 [<addr>]:<n>` after the other actions, and re-advertised unchanged (a non-transitive one is dropped toward eBGP).
- Interference (RFC 8955 section 7.7): when a route carries several traffic-rates, the first in attribute order wins and the others are shown with `(ignored)`.
- What the dataplane does with each action: [Filter DDoS traffic with flowspec](#filter-ddos-traffic-with-flowspec).

To see the rules received, use `show bgp flowspec` (`GET /v1/bgp/flowspec`):

```
edge-1> show bgp flowspec
bgp instance r1:
  from 10.0.0.2 dest 192.0.2.0/24 proto =6 dst-port =25 [traffic-rate:0:0] valid actions: discard
```

The log has one line per change: `flowspec route learned peer=… family=… route=…`, `flowspec validity changed …` and `flowspec route withdrawn …`.

#### Selection and propagation

- For each rule, the valid copies received from every peer compete through the unicast decision process (local-pref, AS-path length, origin, MED, eBGP over iBGP, oldest eBGP, router-id, peer address). There is no next hop, so the IGP-cost step and the next-hop check do not apply; validity replaces the latter. An invalid copy never competes.
- The best copy is advertised to every peer that negotiated the family, with the unicast rules: never back to the peer it came from, no iBGP to iBGP unless one side is a route-reflector client (ORIGINATOR_ID and CLUSTER_LIST are kept, so rule (b) still holds downstream), our AS prepended toward eBGP, confederation rules, MED dropped toward another AS. The traffic actions travel unchanged.
- A rule that turns invalid, is withdrawn, or is rejected by policy is withdrawn from every peer it was sent to. Re-validation after a unicast change re-selects only the rules it touched.
- The log, per peer: `flowspec route advertised peer=… family=… route=…` and `flowspec route advertisement withdrawn peer=… family=… route=…`.
- RFC 9234 roles (OTC) and RFC 8097 validation-state communities are unicast-only and do not apply.

#### Policies

Two peer-group settings filter Flowspec rules, apart from `import-policy`/`export-policy` (which only see unicast routes):

- `set bgp instance r1 peer-group pg1 flowspec-import-policy <policy>` runs on every rule received from the group's peers. A reject drops the rule as if withdrawn and logs `flowspec route rejected by import policy peer=… family=… route=…`.
- `set bgp instance r1 peer-group pg1 flowspec-export-policy <policy>` runs on every rule before it is advertised to the group's peers.
- Unset accepts every rule (Flowspec is an explicitly configured family). `delete flowspec-import-policy` returns to that.
- REST: `"flowspec_import_policy": "<policy>"` / `"flowspec_export_policy": "<policy>"` on the peer-group, `null` to unset. Changing either restarts the group's sessions.
- What a policy sees and can rewrite: [routing policy](routing-policy.md#flowspec-rules).

#### Filter DDoS traffic with flowspec

The selected (valid, best) rules of a BGP instance can filter the packets arriving on the interfaces of its routing table. `nos-acld` turns each rule into tc filters on the interface's ingress (RFC 8955 section 5: inbound only).

1. Receive the rules: `set bgp instance r1 peer-group pg1 address-family ipv4-flowspec` (and `ipv6-flowspec`), with the covering unicast routes from the same peer so the rules are valid ([Validity](#validity)).
2. Mark the ingress interfaces: `set interface eth0 flowspec` (also on a subinterface, `set interface eth0 subinterface 100 flowspec`, or a port aggregate, `set port-aggregate agg0 flowspec`). REST: `"flowspec": true`.
   - The rules applied are those of the BGP instance whose routing table owns the device: the subinterface's `routing-table`, the untagged subinterface's for the interface itself.
   - The commit is refused on a loopback, a port aggregate member (set it on the aggregate), a switching-profile port, on both an interface and its untagged subinterface, without a routing table, or when no BGP instance uses that table.
3. Check each rule with `show bgp flowspec` (`GET /v1/bgp/flowspec`): the selected copy ends with `dataplane:` and one of
   - `installed`: filtering;
   - `unsupported (<why>)`: not installed, for the reason given;
   - `not-attached`: no `flowspec` interface in the instance's table, or the interface is absent;
   - `unknown`: `nos-acld` did not answer.

```
edge-1> show bgp flowspec
bgp instance r1:
  from 10.0.0.2 dest 192.0.2.1/32 proto =6 dst-port =8080 [traffic-rate:0:0] valid actions: discard dataplane: installed
```

4. Counters: `show acl` (end of the output) and `GET /v1/flowspec` give packets and bytes per rule, summed over its interfaces.

What is enforced:

- traffic-rate 0 drops; a rate above 0 polices (bytes or packets per second); traffic-marking rewrites the DSCP; traffic-action `sample` samples; the `terminal` bit set lets the later rules and the ACL see the packet too, clear (the default) lets only the ACL see it.
- Rules apply in RFC 8955 section 5.1 order, before any `acl in` on the same interface.
- Unsupported, never approximated: packet length, flow label, fragment `DF`/`LF`, a non-zero IPv6 offset, redirects. Up to 90 rules per interface; the rest show `unsupported (rule cap)`.
- The log: `flowspec rules received instance=… rules=… installable=…` and `flowspec applied interface=… rules=…` (`nos-acld`), `flowspec rule unsupported instance=… flow=… reason=…` once per rule.
- Restarts: a stopping `nos-bgpd` removes its rules; during a graceful-restart deferral the installed rules stay until selection ends. If `nos-acld` restarts, the filters stay enforced and `nos-bgpd` pushes the rules again when it reconnects.

### Four-octet AS numbers (RFC 6793)

AS numbers can be anywhere from 1 to 4294967294. With a peer that does not support four-octet AS numbers, NOS uses the RFC 6793 transition mechanism: its own AS appears as 23456 (`AS_TRANS`) in the OPEN, and AS paths are exchanged as two-octet paths plus an `AS4_PATH` attribute. You configure the real AS numbers on both sides in all cases. A received `AS4_PATH` that is malformed, or that carries confederation segments, is ignored and the route is kept with its two-octet path (RFC 7606 §7.11).

### First-AS check (RFC 4271 §6.3)

- On an eBGP session the first AS of a received `AS_PATH` must be the peer's AS; otherwise the UPDATE is treated as a withdraw (the peer's earlier route for those prefixes is removed too) and a warning is logged, at most once per 10 seconds per peer (with `suppressed=<n>`). The session stays up.
- It is on by default. Turn it off per peer-group: `set enforce-first-as false` (REST: `"enforce_first_as": false`); `delete enforce-first-as` returns to the default.
- Never checked: iBGP, confederation members, and `route-server-client` peer-groups (an RFC 7947 route server does not prepend its own AS).
- A first segment that is an `AS_SET`, or an empty path, from an eBGP peer is a violation too.
- With `local-as`, the check compares against the AS in the peer's OPEN, i.e. the `remote-as` you configured.

### Source address

By default the session's source address is whatever the kernel picks to reach the peer. `source-address` makes the session use the address of a given interface instead:

- `set source-address interface <name> [label <label>]` uses the address of that interface. `<name>` is written as in interface commands (`eth0` is its untagged subinterface, `eth0.100` a VLAN subinterface). If the interface has several addresses, `label` picks the one with that label; without it the interface must have exactly one address.
- `set source-address loopback [label <label>]` uses the routing table's loopback, the interface named `loopback-<table>`, without spelling out its name.

The address is looked up each time the configuration changes, and again every few seconds while it cannot be found. The router logs `resolved peer-group source-address` with the address it found, or `peer-group source-address not resolvable yet` (at debug level) while the interface does not exist or has no usable address. `delete source-address` goes back to the default.

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"Loopback":{"label":null}}' \
  $B/v1/transactions/t3/bgp-instance/r1/peer-group/pg1/source-address
$C -X PUT -H 'Content-Type: application/json' -d '{"Interface":{"interface":"eth0","label":null}}' \
  $B/v1/transactions/t3/bgp-instance/r1/peer-group/pg1/source-address
```

### Next hop

`next-hop` controls the `NEXT_HOP` of routes advertised to a peer-group:

- `self` replaces it with this router's own address on the session. This is the default for eBGP peer-groups (`remote-as` different from the instance's `asn`).
- `unchanged` keeps the next hop the route already has. This is the default for iBGP peer-groups and for route-server peer-groups (`route-server-client`).

`set next-hop self|unchanged` overrides the default, and `delete next-hop` restores it. An export policy can also set the next hop of individual routes (see [Routing policy](routing-policy.md#statements)). Over REST the values are `"SelfAddress"` and `"Unchanged"`.

A received route is used only if its next hop is reachable through the routing table (RFC 4271 §9.1.2): through a connected subnet, a static route or an OSPF route. A route whose next hop is not reachable stays in the router's Adj-RIB-In but is left out of best-path selection, and the router logs `bgp: candidate excluded, next hop unresolvable`. It becomes a candidate again as soon as a route to its next hop appears.

### Best path

For each prefix NOS runs the RFC 4271 §9.1.2.2 decision process over the candidates that passed the import policy, damping and next-hop checks, in this order: highest `LOCAL_PREF` (a value received from an eBGP peer is ignored and counts as 100, except from confederation peers; use an import policy `set local-pref` instead); a route redistributed on this router over a learned one; shortest AS path (an `AS_SET` counts as one AS, confederation segments as none); lowest origin (IGP, then EGP, then incomplete); lowest `MED`, compared only between routes from the same neighbouring AS (a missing MED counts as 0); eBGP over confederation eBGP over iBGP; lowest IGP cost to the next hop; between two eBGP routes, the older one; lowest BGP identifier; lowest peer address. The best route is installed in the routing table. When a second-best route with a different next hop exists, it is installed as a backup at a higher metric, so traffic can fail over without waiting for BGP to reconverge.

### Multipath

`set maximum-paths <n>` on the instance installs up to `n` next hops (1 to 64) for a prefix as one equal-cost route, so the kernel spreads traffic over them. Unset or `1` installs the best path alone.

```
edge-1(t9/bgp-instance:r1)> set maximum-paths 4
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '4' $B/v1/transactions/t9/bgp-instance/r1/maximum-paths
```

- A path joins the best one only if it ties with it on every step of [Best path](#best-path) up to the IGP cost to the next hop, and comes from the same neighbouring AS (the first AS in its path). Paths with equal-length AS paths from different ASes do not join.
- Ties are picked in best-path order (oldest eBGP route, BGP identifier, peer address), up to `n`. Two paths with the same next hop count once.
- The same knob load-balances VPN routes imported into a VRF (#595): the paths tying on the rules above join the best one whatever their RD, up to `n`, and `nos-ribd` installs one route with a labelled next hop per path (each keeps its own VPN label). The neighbouring AS must match, so two PEs behind one eBGP neighbour AS qualify, a PE in another AS does not. The same PE under two RDs with different labels counts twice; the same PE and label under two RDs once. A PE that stops resolving or becomes infeasible leaves the set and the route stays on the others. Which VPN path is re-advertised is unchanged (the single best).
- Only the best path is advertised to peers. Multipath changes what this router installs, not what it sends.
- The backup route (see [Best path](#best-path)) is the best path whose next hop is none of the installed ones.
- Redistributed routes never join: they win best path on their own and are not installed.
- A path joining or leaving replaces the kernel route: delete, then add. Traffic to the prefix can see a short gap.

`show route` lists every next hop:

```
edge-1> show route rt1 198.51.100.1
198.51.100.0/24
  * via 10.50.0.3, 10.50.0.4 [bgp]
```

### Aggregation (RFC 4271 §9.2.2.2)

`set aggregate-address <prefix>` on the instance makes the router originate `<prefix>` itself while at least one more specific route of it is in its best paths (learned, redistributed, or another aggregate). The aggregate is withdrawn when the last of these routes goes.

```
edge-1(t9/bgp-instance:r1)> set aggregate-address 198.51.0.0/16
edge-1(t9/bgp-instance:r1)> set aggregate-address 198.51.0.0/16 summary-only
```

```sh
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"prefix":"198.51.0.0/16","as_set":false,"summary_only":true}' \
  $B/v1/transactions/t9/bgp-instance/r1/aggregate-address/198.51.0.0%2F16
```

- The aggregate's `ORIGIN` is the worst of its more specific routes' (incomplete, then EGP, then IGP). It carries no `MED` and no communities, and its next hop is this router.
- `AGGREGATOR` is the instance's `asn` and router ID. A peer without four-octet AS support gets `AS_TRANS` and `AS4_AGGREGATOR`.
- Without `as-set`, the `AS_PATH` is empty, and `ATOMIC_AGGREGATE` is set as soon as one of the more specific routes had a non-empty `AS_PATH` (or carried `ATOMIC_AGGREGATE` itself).
- With `as-set`, the `AS_PATH` is the longest leading `AS_SEQUENCE` all the more specific routes share, then one `AS_SET` of every other AS (RFC 4271 Appendix F.6). A peer whose AS is in the set drops the aggregate as a loop.
- `summary-only` withdraws the more specific routes from every peer, and never sends new ones, while the aggregate is active. They are still installed in the routing table.
- Routes with different `MED`s are aggregated too, unlike RFC 4271 §9.2.2.2's rule.
- No discard (blackhole) route is installed for the aggregate: traffic to a part of it that no more specific route covers follows the routing table's other routes.
- The router logs `bgp: aggregate activated`, `bgp: aggregate updated` and `bgp: aggregate withdrawn`, with the prefix and the number of more specific routes.

### Communities

Standard (RFC 1997), extended (RFC 4360) and large (RFC 8092) communities are passed on unchanged to every peer, with one exception: a non-transitive extended community (its type has bit `0x40` set) is never sent to an eBGP peer, route-server clients included. The well-known communities are enforced on export, see below. Policies can match, add and remove communities; see [Routing policy](routing-policy.md).

#### Well-known communities (RFC 1997)

- Applies only to routes received from a peer. Locally originated, redistributed and aggregate routes are never filtered, whatever an export policy adds.
- Checked on the route as stored, after the import policy and before the export policy, for unicast, VPN and Flowspec (not EVPN). Route-server clients count as eBGP.
- What each community stops, by the destination peer:

| Community | Own AS (iBGP) | Other member AS of our confederation | Outside (eBGP) |
|---|---|---|---|
| `NO_EXPORT` (`65535:65281`) | sent | sent | blocked |
| `NO_ADVERTISE` (`65535:65282`) | blocked | blocked | blocked |
| `NO_EXPORT_SUBCONFED` (`65535:65283`) | sent | blocked | blocked |

- Without a confederation, `NO_EXPORT` and `NO_EXPORT_SUBCONFED` behave the same on eBGP.
- To let such a route through, strip the community in an import policy: `this.bgp.communities.remove(65535:65281)`. An export policy can neither add the effect to a received route nor lift it.
- A route re-learned with the community is withdrawn from the peers that may no longer have it.
- A suppressed advertisement logs `advertisement suppressed by well-known community` at debug level.

#### Graceful shutdown (RFC 8326)

- Behaviour change: a route received from an eBGP peer carrying `65535:0` (GRACEFUL_SHUTDOWN) now gets LOCAL_PREF 0, so any other path wins. This is on by default; `graceful-shutdown-receive disable` in the peer-group turns it off. iBGP and confederation-internal sessions are never affected.
- The demotion is applied before the import policy, which can still override it (`set this.bgp.local_pref = ...`). It covers IPv4/IPv6 unicast, VPN and EVPN routes. EVPN import policy is accept/reject only, so it cannot override the demotion.
- EVPN: a tagged route is stored with LOCAL_PREF 0 and shown in `show bgp evpn` (`local-pref 0 communities [graceful-shutdown]`). When the same Type-2 MAC is held by several PEs (one ESI) the highest LOCAL_PREF wins, then the lowest VTEP, so a drained PE stops being the target. A Type-5 prefix below the best LOCAL_PREF for its (prefix, VNI) is withheld from `nos-ribd`; a lone route stays. Types 1, 3 and 4 are never demoted.
- `graceful-shutdown` in an eBGP peer-group makes this router the one being drained: every unicast and VPN route sent to the group carries `65535:0` (before the export policy, which can strip it), every EVPN route too (EVPN has no export policy), and every route received from the group is tagged and gets LOCAL_PREF 0. Flowspec is not tagged. An iBGP peer-group is refused at commit.
- Both knobs apply live, with no session reset. Routes already received are re-learned through a Route Refresh; a peer without Route Refresh keeps its old LOCAL_PREFs until it re-announces.

How to drain a router for maintenance:

1. `set bgp instance r1 peer-group upstream graceful-shutdown` and commit.
2. Wait until the neighbours have converged on other paths (`show bgp routes` on them shows LOCAL_PREF 0 on this router's paths; for EVPN, `show bgp evpn` shows `local-pref 0 communities [graceful-shutdown]`).
3. `set bgp instance r1 peer-group upstream shutdown maintenance` and commit.

#### Blackhole community (RFC 7999)

> **Warning:** a blackholed route still goes through the peer-group's import policy, and the default import policy is `deny-all`. Without a policy that accepts it, nothing is blackholed.

- Opt in per eBGP peer-group: `set bgp instance r1 peer-group customer blackhole prefix-list CUSTOMER`. An iBGP group, or a prefix-list that does not exist, is refused at commit.
- A unicast route from that group is a blackhole when it carries `BLACKHOLE` (`65535:666`) and its prefix matches the prefix-list. The list is the authorisation and uses the normal `range` rules, so to accept host routes inside a customer block write `10.0.0.0/8 upto 32`; a plain entry matches only that exact prefix.
- A blackhole gets `NO_EXPORT` added (so it is not passed on to eBGP peers, see well-known communities above) and competes in the normal decision process, with no LOCAL_PREF change. If it is best, `nos-bgpd` pushes it to `nos-ribd` as a discard route and the kernel gets an `RTN_BLACKHOLE` route.
- A tagged route that is not covered, or from a group without `blackhole`, is an ordinary route (the community means nothing special). RPKI state does not stop a blackhole by itself, but the import policy can test it.
- `show route` marks the installed route `discard (blackhole)`; an OSPF area-range discard shows plain `discard`. A BGP discard never resolves the next hop of another route, and competes with connected/static routes for the same prefix by the usual source preference.
- Changing the group's `blackhole` setting or editing the prefix-list restarts the group's sessions.

An import policy that accepts it:

```
if this.bgp.communities contains 65535:666 and this.prefix in CUSTOMER
    accept
```

### MD5 authentication (RFC 2385)

Authentication keys are not typed into the peer-group: they live in the admin keystore under a label, and the peer-group names the label. To authenticate a peer-group:

1. Store the secret (1 to 80 bytes) under a label: `set admin key bgp-pg1 secret s3cr3t-md5`.
2. Reference it: `set md5-password bgp-pg1` signs every TCP segment of the peer-group's sessions with that secret. Both sides must hold the same secret; with a wrong or missing one, the kernel drops the segments and the session never comes up.

```
edge-1(t4)> set admin key bgp-pg1 secret s3cr3t-md5
edge-1(t4/bgp-instance:r1/peer-group:pg1)> set md5-password bgp-pg1
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"label":"bgp-pg1","secret":"s3cr3t-md5"}' \
  $B/v1/transactions/t4/admin/key/bgp-pg1
$C -X PUT -H 'Content-Type: application/json' -d '{"Md5":{"key_ref":"bgp-pg1"}}' \
  $B/v1/transactions/t4/bgp-instance/r1/peer-group/pg1/auth
```

- The secret is write-only: it reads `<hidden>` in `show config`, `diff`, `GET /v1/config` and the logs. `show config` displays the label.
- The commit fails if the label does not exist, or if its secret is not 1 to 80 bytes. Deleting an admin key that a peer-group (or RPKI cache) still references fails the commit too, naming the label.
- To rotate the secret, set the same label to a new value on both routers: `set admin key bgp-pg1 secret <new>`. The session is restarted and comes back with the new secret.
- `delete auth` removes authentication, whether MD5 or TCP-AO.
- Breaking change: a `config.yaml` saved with an inline `password` or `key` no longer loads. Move the secret to an admin key and reference its label (`key_ref`).

### TCP-AO (RFC 5925)

TCP-AO is the successor of MD5 authentication. A peer-group can have several keys, which lets you change keys without dropping the session. MD5 and TCP-AO are mutually exclusive: setting one replaces the other.

Each key has:

- a send ID and a receive ID (0 to 255): the key IDs this router puts in outgoing segments and expects in incoming ones. The peer configures the same key with the two IDs swapped (or the same values, if you use the same ID in both directions);
- an algorithm: `hmac-sha1` (HMAC-SHA-1-96) or `aes-cmac` (AES-128-CMAC-96);
- the label of an admin key (`set admin key <label> secret <value>`) holding the secret, 1 to 80 bytes.

Exactly one key must be marked `current`: the key a new connection starts signing with. At most one may be marked `rnext`: the key this router asks the peer to switch to. Send IDs must be unique, and so must receive IDs (the kernel refuses overlapping IDs).

On an established session the peer decides which key signs: the kernel follows the peer's RNextKeyID (RFC 5925 §7.5.2), so `current` never forces a switch on a live session.

```
edge-1(t5)> set admin key ao-pg1-1 secret first-key
edge-1(t5/bgp-instance:r1/peer-group:pg1)> set ao-key 1 1 hmac-sha1 ao-pg1-1
edge-1(t5/bgp-instance:r1/peer-group:pg1)> set ao-key 1 current
edge-1(t5/bgp-instance:r1/peer-group:pg1)> commit
```

`set ao-key <send-id> <recv-id> <algorithm> <label>` adds a key, or replaces the key with that send ID. `set ao-key <send-id> current` and `set ao-key <send-id> rnext` move the flags, and `delete ao-key <send-id>` removes one key.

Once the session is up, `show bgp brief` adds the key state read from the kernel: the key ID this router is sending with, the key ID this router asks the peer to send with, and the counts of good segments, bad segments and segments for an unknown key:

```
  10.50.0.2 AS 65001 peer-group pg1 Established uptime 00:00:15 hold-time 90 ao-current 1 ao-rnext 1 ao-good 7 ao-bad 0 ao-no-key 0
```

(That line is from router-b, whose peer is router-a.) During the rollover below, `ao-current` moves to key 2 as soon as both sides have key 2 as `rnext`.

To roll over to a new key without dropping the session (RFC 5925 §7.5), on both routers:

1. Add the new key and mark it `rnext`: `set admin key ao-pg1-2 secret second-key`, `set ao-key 2 2 hmac-sha1 ao-pg1-2`, `set ao-key 2 rnext`. Commit. Once both sides have done this, the live session switches to key 2 on its own.
2. Make it current: `set ao-key 2 current`. Commit. This only changes what new connections start with.
3. Remove the old key: `delete ao-key 1`. Commit.

Each of these commits is applied to the running session and to the listener in place: the session stays up. These still reset it:

- changing the secret (the admin key's value), algorithm, receive ID or `exclude-options` of a key that stays;
- switching between MD5 and TCP-AO, or adding or removing authentication altogether;
- removing the key the peer still signs with (the kernel refuses; the session resets with Cease/Other Configuration Change and comes back with the new key list). Remove the old key only after the peer has moved to the new one.

A change to any other peer-group field in the same commit also resets the session (see [How BGP is configured](#how-bgp-is-configured)).

Over REST, `auth` holds the whole key list:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"Ao":{"keys":[
    {"send_id":1,"recv_id":1,"algorithm":"HmacSha1_96","key_ref":"ao-pg1-1","is_current":true,"is_rnext":false,"exclude_options":false}]}}' \
  $B/v1/transactions/t5/bgp-instance/r1/peer-group/pg1/auth
```

The algorithm values are `HmacSha1_96` and `AesCmac96`. `exclude_options: true` leaves TCP options out of the MAC (RFC 5925 §5.2); both sides must agree on it. In the shell, `set ao-key <send-id> exclude-options` sets it on an existing key and `delete ao-key <send-id> exclude-options` clears it.

### GTSM (RFC 5082)

`set max-hops <n>` turns on the Generalized TTL Security Mechanism: the router sends the session's packets with TTL (or IPv6 hop limit) 255, and the kernel drops incoming packets whose TTL is below `256 - n`. Use `1` for a directly connected peer, so that nobody further away can inject packets into the session. The range is 1 to 254; `delete max-hops` turns it off. Set it on both sides. The default TTL of 1 for directly connected eBGP is not implemented.

### BFD (RFC 5882, RFC 9384)

`set bgp instance r1 peer-group pg1 bfd fast` makes `nos-bgpd` register a BFD session (profile `fast`, see [BFD profiles](bfd.md)) with `nos-bfdd` for every peer of the group, so a dead path closes the BGP session in milliseconds instead of waiting for the hold time.

- Adding or removing `bfd` resets nothing; editing the profile applies through Poll/Final.
- Sessions are registered as soon as the instance's VRF is known, so BFD is usually `up` before BGP is `Established`.
- When a session goes `up` then `down`, an `Established` peer is closed with Cease subcode 10 (BFD Down, RFC 9384). The router logs `bgp: bfd session down, closing peer=<ip>`.
- `init` and `admin-down` do nothing: BGP has its own keepalive liveness (RFC 5882 section 3.2). A session that was never `up` does nothing either.
- Graceful restart (RFC 5882 section 4.3): what happens depends on the C bit (BFD independent of the control plane), which must be set at both ends.
  - Both set: BFD is a real forwarding verdict. With N exchanged the Cease/10 is wrapped in a Hard Reset so the peer flushes our routes (`sent cease notification … subcode=10 hard_reset=true`, the peer logs `hard_reset_subcode=10`), and routes already stale from a restart of the peer are purged at once.
  - Either clear: BFD fails along with a restart, so stale routes are kept and the Cease/10 is graceful.
  - `nos-bfdd` always sets C.
- Without `nos-bfdd` BGP works as before; sessions are registered again after it comes back.
- A peer with `max-hops` above 1, or off every connected subnet of the instance's routing table, gets a [multi-hop session](bfd.md#multi-hop-sessions) (RFC 5883, UDP 4784); other peers get a single-hop one. A session `nos-bfdd` cannot bring `up` never closes anything.
- A shut-down peer gets no session.

### Administrative shutdown (RFC 4486, RFC 9003)

See [Shutting a session down](#shutting-a-session-down). While a peer is shut down, NOS neither connects to it nor accepts its connections. When a session is closed for another configuration reason, the peer receives a Cease NOTIFICATION that says why: Peer De-configured (subcode 3) when you delete the peer, Other Configuration Change (subcode 6) when you change its peer-group.

### Route refresh (RFC 2918, RFC 7313)

When a peer asks for a route refresh, NOS resends its routes for that address family. A peer may ask at most twice in a burst and then once every 10 seconds, per session; a request over that is not answered and logged at `debug` (`route refresh rate-limited`). The limit is fixed. If both sides support enhanced route refresh, the resent routes are framed by begin and end markers, and routes the peer no longer sends are removed at the end. `clear bgp … soft-in` asks the peer to do the same (see [Asking a peer to resend its routes](#asking-a-peer-to-resend-its-routes)). A peer that did not advertise the route refresh capability is never sent a request: the router logs `route refresh not sent` instead.

If a peer starts an enhanced route refresh and never sends the end marker, NOS still removes the routes it did not resend once `route-refresh-stale-time` has passed (RFC 7313 §4). The router logs `route refresh stale timer expired` and the session stays up.

- the default is 360 seconds;
- `0` keeps the routes until the end marker arrives or the session ends;
- changing the value restarts the peer-group's sessions.

```
edge-1(t6/bgp-instance:r1/peer-group:pg1)> set route-refresh-stale-time 120
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '120' $B/v1/transactions/t6/bgp-instance/r1/peer-group/pg1/route-refresh-stale-time
```

### MRAI (RFC 4271 §9.2.1.1)

`set mrai <seconds>` sets the MinRouteAdvertisementInterval: the minimum time between two advertisements of the same prefix to the same peer. The first advertisement of a prefix is sent at once, and so is every withdrawal. A change within the interval is held back until the interval ends, and several changes collapse into the last one. Unset or `0` sends every change at once. EVPN routes are not paced.

```
edge-1(t6/bgp-instance:r1/peer-group:pg1)> set mrai 30
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '30' $B/v1/transactions/t6/bgp-instance/r1/peer-group/pg1/mrai
```

### Route flap damping (RFC 2439)

`set damping` suppresses routes that a peer withdraws and re-announces too often. It applies to routes received from the peer-group's peers, and only in eBGP peer-groups. Each prefix from each peer has a penalty:

- a withdrawal adds 1000, and so does a route that the import policy now rejects;
- a re-announcement with different attributes adds 500;
- the penalty halves every `half-life` seconds.

When the penalty reaches `suppress`, the route is set aside: the router keeps it but does not use or advertise it. It is released once the penalty decays below `reuse`. `max-suppress` caps the penalty, and so the time a route can stay suppressed.

`set damping` alone uses the RFC 7196 defaults: half-life 900, reuse 750, suppress 6000, max-suppress 3600. Give any of the four parameters, in any order, to change them; the others keep their defaults:

```
edge-1(t7/bgp-instance:r1/peer-group:pg1)> set damping half-life 20 reuse 750 suppress 2000
```

```sh
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"half_life":20,"reuse":750,"suppress":2000,"max_suppress":3600}' \
  $B/v1/transactions/t7/bgp-instance/r1/peer-group/pg1/damping
```

The commit requires half-life > 0, reuse > 0, suppress > reuse and max-suppress ≥ half-life. `delete damping` turns damping off.

There is no `show` command for damping state yet. The router logs `route suppressed by flap damping` and `route released from flap damping` with the peer and prefix. A session reset clears the peer's penalties.

### Route reflection (RFC 4456)

Normally a route learned from one iBGP peer is not advertised to another iBGP peer, so iBGP needs a full mesh. A route reflector removes that need: routes from its clients are reflected to all its iBGP peers, and routes from non-clients are reflected to its clients.

On the reflector, mark the peer-group of its clients with `set route-reflector-client`. The peer-group must be iBGP (`remote-as` equal to the instance's `asn`). The clients need no special configuration.

```
edge-1(t8/bgp-instance:r1)> edit peer-group clients
edge-1(t8/bgp-instance:r1/peer-group:clients)> set remote-as 65001
edge-1(t8/bgp-instance:r1/peer-group:clients)> set address-family ipv4
edge-1(t8/bgp-instance:r1/peer-group:clients)> set import-policy accept-all
edge-1(t8/bgp-instance:r1/peer-group:clients)> set export-policy accept-all
edge-1(t8/bgp-instance:r1/peer-group:clients)> set route-reflector-client
```

On an eBGP peer-group the commit is refused:

```
error: nos-configd reported an error: validation failed:
bgp_instances: route-reflector-client requires an iBGP peer-group (remote-as must equal this instance's asn)
```

Reflected routes carry an `ORIGINATOR_ID` and a `CLUSTER_LIST`. The cluster ID defaults to the instance's router ID; if several reflectors serve the same clients, give them the same cluster ID with `set cluster-id <a.b.c.d>` on the instance (`delete cluster-id` restores the default). A route that comes back with the reflector's own cluster ID or router ID is dropped, which prevents reflection loops.

Over REST, `route_reflector_client` is a boolean on the peer-group and `cluster_id` a string on the instance:

```sh
$C -X PUT -H 'Content-Type: application/json' -d 'true' \
  $B/v1/transactions/t8/bgp-instance/r1/peer-group/clients/route-reflector-client
$C -X PUT -H 'Content-Type: application/json' -d '"10.255.0.1"' \
  $B/v1/transactions/t8/bgp-instance/r1/cluster-id
```

### Confederations (RFC 5065)

A confederation splits one AS into member ASes that peer over eBGP among themselves while the outside world sees a single AS. On each router, the instance's `asn` is its member AS; add the confederation identifier and the other member ASes it peers with:

```
set bgp instance r1 asn 65101
set bgp instance r1 confederation identifier 65100
set bgp instance r1 confederation peer 65102
```

A peer-group whose `remote-as` is a confederation peer is confederation eBGP. Toward it NOS sends its member AS in the OPEN, prepends it in an `AS_CONFED_SEQUENCE`, and keeps the next hop, `MED` and `LOCAL_PREF` as for iBGP. Toward a peer outside the confederation it sends the identifier in the OPEN, removes the confederation segments from the AS path and prepends the identifier, so that peer configures `remote-as 65100`. A path that already holds the identifier, or that holds the member AS in a confederation segment, is a loop and is dropped. A peer outside the confederation never sends confederation segments: a route that has them is treated as withdrawn, and so is any such route when no confederation is configured. Changing the confederation resets the instance's sessions. `delete confederation peer <asn>` and `delete confederation identifier` undo it.

### Local AS (local-as)

`local-as` makes a peer-group's peers see another AS than the instance's own, for example while moving a router to a new AS without reconfiguring every neighbour at once. It is a vendor feature (IOS, Junos), not an RFC. Call G the AS those peers would see otherwise: the instance's `asn`, or the confederation identifier.

- the OPEN carries the local AS, so the peers configure `remote-as <local-as>`;
- routes sent to the peers carry `local-as G …`; with `replace-as`, `local-as …` and G is never sent;
- routes received from the peers get the local AS prepended, so the import policy and every other peer see it as a real hop; `no-prepend` stores them unchanged;
- a route from these peers that already holds the local AS is a loop and is dropped; the same path from another peer is accepted.

IOS's `local-as <n> no-prepend replace-as` is `local-as asn <n> no-prepend replace-as`. Changing it resets the peer-group's sessions.

```
edge-1(t9/bgp-instance:r1/peer-group:pg1)> set local-as asn 65020 no-prepend replace-as
```

```sh
$C -X PUT -H 'Content-Type: application/json' \
  -d '{"asn":65020,"no_prepend":true,"replace_as":true}' \
  $B/v1/transactions/t9/bgp-instance/r1/peer-group/pg1/local-as
```

The commit refuses `local-as` on an iBGP or confederation peer-group, together with `route-server-client`, and equal to the instance's `asn`, its confederation identifier or the group's `remote-as`. `delete local-as` removes it. Not supported: `dual-as` (accepting the peer with either AS).

### BGP roles (RFC 9234)

A role says what the peer-group's peers are to this router, so a misconfigured pair is caught when the session opens instead of leaking routes later. The role goes in the OPEN as a Role capability.

- `provider`, `customer`, `route-server`, `route-server-client` or `peer`: the role of the peers, not of this router. Peers that sell you transit are `provider`; one of your own customers is `customer`.
- Legal pairs: provider/customer, route-server/route-server-client, peer/peer. Any other pair closes the session with NOTIFICATION OPEN Message Error, subcode 11 (Role Mismatch); the refusing side logs `sent notification peer=<ip> code=2 subcode=11`.
- A peer that sends no role is accepted, with no role negotiated, unless `strict-mode` is set: then it is refused with the same NOTIFICATION. `strict-mode` needs a `role`.
- `bgp role negotiated peer=<ip> local=<role> remote=<role>` is logged when a pair is accepted.
- Changing `role` or `strict-mode` resets the peer-group's sessions.
- The commit refuses `role` on an iBGP or confederation peer-group, and on a `route-server-client` group any role but `route-server` or `route-server-client`.

#### Only-To-Customer (route-leak prevention)

With a `role`, the Only-To-Customer (OTC) attribute marks routes as they cross provider/customer/peer links, and a route that should never have crossed is dropped.

- Applies to IPv4/IPv6 unicast on every eBGP session with a configured `role`, whether or not the peer sent the Role capability (RFC 9234 section 4.2). A session with no `role` forwards OTC unchanged.
- On receipt, from a `provider`, `peer` or `route-server` with no OTC: the route is marked with the neighbor's ASN.
- On receipt, a leak is dropped (the earlier path of that prefix is withdrawn): any OTC from a `customer` or `route-server-client`, or an OTC from a `peer` that is not the peer's ASN. It logs `route leak detected peer=<ip> prefix=... otc=... role=...`.
- On sending, to a `customer`, `peer` or `route-server-client` with no OTC: the route gets our ASN (the `local-as` one when set). To a `provider`, `peer` or `route-server` a route that has an OTC is not sent.
- So a route learned from one provider is not passed to another provider or to a peer, but does reach customers. Export policy cannot override this.
- Check with the `learned route for <prefix> into adj-rib-in` log line, which carries `otc=`; it is not shown in `show bgp`.
- A neighbor that does not speak RFC 9234 gets its routes marked on receipt, so they are not leaked onward either.
- Policies can match on the roles and the OTC: see `this.bgp.local_role`, `this.bgp.remote_role` and `this.bgp.otc` in [routing policy](routing-policy.md#fields).

```
edge-1(t9/bgp-instance:r1/peer-group:pg1)> set role customer
edge-1(t9/bgp-instance:r1/peer-group:pg1)> set strict-mode
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"Customer"' \
  $B/v1/transactions/t9/bgp-instance/r1/peer-group/pg1/role
```

### BMP export (RFC 7854, #878)

`nos-bgpd` can stream monitoring data to a BMP station (collector): Initiation, Peer Up, Route Monitoring of the Adj-RIB-In (every family but RT-Constraint, #864), Peer Down and Termination.

Not yet exported: RT-Constraint routes (post-policy and dump), Adj-RIB-Out (#867) and `show bgp bmp`.

- Configure: `edit bgp instance r1`, then `set bmp-station col1 address 192.0.2.50 port 5000`. The port is mandatory (BMP has no default port): a station without one is refused at commit, as are port 0, an unspecified address and a duplicate name. Several stations are allowed; each gets the same stream.
- The router dials the station (the station listens), inside the instance's VRF, like peers and RPKI caches. Nothing is dialled until the VRF is resolved.
- On connect: Initiation (sysDescr `nos-bgpd <version>`, sysName the instance name, a string TLV `vrf=<table>`), then a Peer Up per Established peer, then live events.
- A collector that goes away is redialled with a 5 s backoff doubling to 120 s; the Established peers are replayed on every reconnect.
- Peer type is 0 (global) with a zero distinguisher, or 1 (RD instance) with the routing table's `vpn` route distinguisher when it has one.
- Peer Down reasons: 1 when nos sent a NOTIFICATION (shutdown, hold timer, collision), 3 when the peer sent one, 4 when the peer or the transport closed with none, 2 (event 0) when a configuration change stopped the session.
- Peer Up carries both OPEN messages re-encoded, so a capability nos does not know is missing from them.
- SIGINT or removing a station sends Termination (reason 0) first. If the station's queue overflows (a collector that stops reading), the router sends Termination (reason 2), reconnects and replays.
- Route Monitoring: `set bmp-station col1 monitor post-policy|pre-policy|both` (default `both`). A change restarts that station and re-sends everything. Which peers: all peers of the instance.
  - Post-policy (L flag set): the Adj-RIB-In as the import policy left it. A re-announcement identical to the stored route sends nothing; a route the policy rejects never appears.
  - Pre-policy (L flag clear): each UPDATE exactly as the peer sent it (re-encoded, every family including RT-Constraint), so rejected and looped routes show up.
  - On connect, per peer and stream: the stored routes, one UPDATE per path, then an End-of-RIB per negotiated family (IPv4/IPv6 unicast, L2VPN EVPN, IPv4/IPv6 Flowspec, VPNv4/VPNv6). The pre-policy dump comes from the retained routes of `soft-reconfiguration inbound` (for EVPN the held routes plus the rejected ones); without that flag on the peer-group it is skipped (the router logs `bmp pre-policy dump skipped`, the pre-policy End-of-RIB is still sent) and the collector only learns pre-policy changes from then on. Enable the flag for a complete pre-policy table.
  - EVPN, Flowspec and VPN routes are rebuilt from the stored route. EVPN keeps neither `ORIGIN` nor `AS_PATH`, so its PDU says IGP with an empty path; the VPN codec writes the first label of a stack only.
  - A peer's own End-of-RIB is forwarded on both streams, so a session that comes up after the collector connected gets its markers.
  - PDUs are re-encoded with 4-byte `AS_PATH` (A flag always 0, no `AS4_PATH`); unknown attributes and the RFC 8097 community are not reproduced. A withdraw carries the L flag of the stream it belongs to.
- Statistics Reports: `set bmp-station col1 statistics-interval 30` (1 to 86400 seconds; unset = none). Every interval the router sends one report per Established peer; a change restarts that station.
  - Counters (reset when the session comes up, gone with it): rejected by inbound policy (type 0, per prefix, also EVPN, Flowspec and VPN), duplicate advertisements (1), withdraws of a path not held (2), updates dropped for a `CLUSTER_LIST` loop (3), an `AS_PATH` loop (4), our own `ORIGINATOR_ID` (5), an `AS_CONFED` loop (6), updates (11) and prefixes (12) treated as withdraw (RFC 7606 parse errors, an unusable next hop, a stray confederation segment).
  - Gauges: Adj-RIB-In routes, all families (7); Loc-RIB routes (8); Adj-RIB-In per negotiated AFI/SAFI (9); Loc-RIB per IPv4/IPv6 unicast (10).
  - Not sent: type 13 (duplicate update messages) and the Adj-RIB-Out gauges (#867).
- Check: `bmp station connected` / `bmp peer up sent` / `bmp rib dump sent` / `bmp end-of-rib sent` in `show log`. `bmp statistics sent` marks each report. There is no `show bgp bmp` yet.

### RPKI origin validation (RFC 6811, RFC 8210)

NOS checks each route's origin AS against the Validated ROA Payloads (VRPs) of an RPKI cache, such as Routinator or StayRTR. Give the instance one or more caches:

```
set bgp instance r1 rpki-cache 192.0.2.50
set bgp instance r1 rpki-cache 192.0.2.51 port 3323
set bgp instance r1 rpki-cache 192.0.2.51 preference 1
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"address":"192.0.2.50","port":323,"preference":0}' \
  $B/v1/transactions/t9/bgp-instance/r1/rpki-cache/192.0.2.50
```

The port defaults to 323 and the preference to 0. The instance's nos-bgpd connects to the caches from inside the instance's VRF, over the RTR protocol, version 1 (RFC 8210), or version 0 (RFC 6810) if the cache only speaks that. It uses one cache at a time: the lowest preference that answers, in configured order on a tie. When that cache goes away it moves to the next one. It does not switch back to a more preferred cache until the session with the current one ends.

Each route is valid, invalid or not-found (RFC 6811):

- not-found: no VRP covers the prefix;
- valid: a VRP covers it, with the route's origin AS and a max length at least the prefix length;
- invalid: VRPs cover it, but none of them matches.

The origin AS is the last AS in the AS path. A route whose path ends in an `AS_SET` has no origin AS, so it is invalid when covered. A route with no AS in its path, such as a redistributed one, has this router's AS as origin.

Validation changes nothing by itself (RFC 6811, RFC 8481):

- By default NOS accepts invalid routes. A peer-group whose policy never reads `this.bgp.validation_state` keeps them.
- Rejecting invalid routes is done only in the routing policy; there is no peer-group setting for it.
- To reject them, put this in the policy and set it as the `import-policy` of the eBGP peer-group (`set import-policy <name>`, see [Routing policy](routing-policy.md)):

```
if this.bgp.validation_state == rpki.invalid:
    reject
accept
```

When the VRPs change, NOS re-validates every route it holds. A route the import policy rejected is not held (unless the peer-group keeps its received routes, see [soft reconfiguration inbound](#keeping-received-routes-soft-reconfiguration-inbound): then NOS re-evaluates them locally), so about 5 seconds after a change NOS asks each other established peer whose import policy reads the state for a route refresh. A peer that did not advertise the route refresh capability is not asked; its routes are checked again on its next session. The session is never reset.

The cache's End of Data sets the refresh, retry and expire intervals (RFC 8210 §6; version 0 uses the defaults 3600, 600 and 7200 seconds). If no cache answers for the expire interval, the VRPs are dropped and every route is not-found, so the policy above accepts them again. Until then the last VRPs stay in use.

`show bgp rpki` (`GET /v1/bgp/rpki`) shows each cache: its state, whether its VRPs are in use, the protocol version, session ID, serial, VRP count and the time since its last update:

```
edge-1> show bgp rpki
bgp instance r1:
  192.0.2.50 port 323 preference 0 Established (in use) version 1 session 780 serial 4 vrps 412345 updated 12s ago auth yes
  192.0.2.51 port 3323 preference 1 Idle version - session - serial - vrps 0 updated - auth no
```

To see the state of each route, use `show bgp routes` (`GET /v1/bgp/routes`):

```
edge-1> show bgp routes
bgp instance r1:
  > 198.51.100.0/24 from 10.0.0.2 next-hop 10.0.0.2 as-path [65002] origin-as 65002 local-pref 100 valid
    203.0.113.0/24 from local next-hop - as-path [] origin-as - local-pref 100 not-found
```

- The list is printed page by page as it arrives, so a large table starts printing at once.
- One line per path (every ADD-PATH path), IPv4 and IPv6 unicast; EVPN stays in `show bgp evpn`. `>` marks the best path; `from local` is a redistributed route.
- The state is `valid`, `invalid` or `not-found`. A route your import policy rejects (for example with `rpki.invalid`) is never held, so it is not listed; a route learned through RFC 8097 keeps the state its peer sent.

#### Authenticating the cache session (RFC 8210 §9)

Without a key the RTR session is plain TCP. RFC 8210 §9 then requires the router and the cache to share a trusted, controlled network, and prefers TCP-AO over TLS or TCP-MD5 (MD5 is obsoleted by TCP-AO). Set the same key on the cache:

```
set admin key rpki-192-0-2-50 secret s3cr3t
set bgp instance r1 rpki-cache 192.0.2.50 md5-password rpki-192-0-2-50
set bgp instance r1 rpki-cache 192.0.2.50 ao-key 1 1 hmac-sha1 rpki-192-0-2-50
delete bgp instance r1 rpki-cache 192.0.2.50 auth
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"Md5":{"key_ref":"rpki-192-0-2-50"}}' \
  $B/v1/transactions/t9/bgp-instance/r1/rpki-cache/192.0.2.50/auth
```

- The rules are those of a peer-group's `auth`: a key is an admin key label whose secret is 1 to 80 bytes, MD5 and TCP-AO are mutually exclusive, and TCP-AO needs exactly one current key. The `ao-key` sub-commands (`current`, `rnext`, `exclude-options`, `delete ao-key`) work the same.
- Changing the admin key's secret, or removing the reference, restarts the session with that cache; the VRPs already held stay in use until the new session's first End of Data.
- A cache that does not hold the same key never answers: the router logs `rpki cache unreachable`, and `show bgp rpki` keeps it `Idle`.
- What it protects: the integrity of the session between the router and the cache. On an untrusted path, an attacker who can forge the session can make a hijack look valid or a legitimate route invalid. It does not hide the VRPs (they are public data), and it does not vouch for where the cache got them.
- The secret is stored in clear text, like a peer-group's, and shows in `show config` and the REST config.
- Expiry fails open: when no cache answers for the expire interval, the VRPs are dropped and every route is not-found, which a typical import policy accepts. A cache that is down, or whose key is wrong, therefore turns validation off rather than blocking routes.

#### Sharing the state with iBGP peers (RFC 8097)

A router with no cache of its own can take the state from one that has one. Turn it on in the iBGP peer-group on both routers:

```
set bgp instance r1 peer-group core announce-rpki-state
```

- Every route sent to these peers carries its state in the RFC 8097 extended community (type `0x43`, subtype `0x00`: 0 valid, 1 not-found, 2 invalid). Exactly one is sent, after the export policy runs.
- A route received from them takes its state from that community, before the import policy runs, but only while the instance has no VRPs: no cache, none synced yet, or expired. Once VRPs arrive, the local result wins.
- The community is removed from every received route, whatever the peer. From an eBGP peer it is ignored.
- It is refused on an eBGP peer-group at commit. Changing it restarts the peer-group's sessions.
- `delete announce-rpki-state` turns it off.

Not supported: RTR over SSH or TLS, BGPsec router keys (received and ignored), ASPA, and validating EVPN routes.

### ADD-PATH (RFC 7911)

ADD-PATH lets one session carry several paths for the same prefix, each under its own path identifier. Turn it on per peer-group:

```
edge-1(t9/bgp-instance:r1/peer-group:pg1)> set add-path receive
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"Receive"' \
  $B/v1/transactions/t9/bgp-instance/r1/peer-group/pg1/add-path
```

- The modes are `receive`, `send` and `both`. They apply to the group's `ipv4` and `ipv6` unicast families, never to `l2vpn-evpn`.
- What a session uses is negotiated per family (RFC 7911 §5): NOS receives path identifiers only when it offered `receive` or `both` and the peer offered to send, and sends them only when it offered `send` or `both` and the peer offered to receive.
- With receive negotiated, NOS keeps every path the peer sends for a prefix, instead of only the last one. Each path competes in best-path selection on its own, so two paths from one peer can be installed together as [multipath](#multipath). A withdrawal removes only the path it names, and one that names an unknown path is ignored.
- Each path counts toward the peer's [maximum-prefix](#limiting-the-prefixes-a-peer-sends) limit, and `accepted_prefixes` in `GET /v1/bgp/summary` counts paths.
- With send negotiated, a peer gets the best `add-path-send-count` paths for each prefix (see below). A route-server client gets every other source's path by default (see [Route server](#route-server-rfc-7947)).
- A route-server client defaults to `both`. Any other group defaults to off. An explicit mode replaces the default, so `add-path receive` on a route-server client stops its multi-path view.
- The capability is in the OPEN, so changing `add-path` resets the peer-group's sessions. `delete add-path` goes back to the default.
- `bgp: add-path negotiated peer=… ipv4=… ipv6=…` is logged when a session with a configured mode comes up, each value being `none`, `receive`, `send` or `both`.

To choose how many paths a send peer gets, set `add-path-send-count` on its peer-group:

```
edge-1(t9/bgp-instance:r1/peer-group:pg1)> set add-path send
edge-1(t9/bgp-instance:r1/peer-group:pg1)> set add-path-send-count 3
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '3' \
  $B/v1/transactions/t9/bgp-instance/r1/peer-group/pg1/add-path-send-count
```

- The peer gets the best N paths for each prefix, in decision-process order, so the best path is always first.
- N counts the paths the peer actually gets. A path the group's own filtering refuses (split horizon, route reflection rules, export policy, or a path learned from that peer) doesn't use up a place: the next one moves up.
- The range is 2 to 64. Unset, a group gets 2 (the best path plus one backup), and a route-server client every path.
- It needs `add-path send` or `both` (a route-server client is `both` by default), or the commit is refused.
- It is independent of the instance's [maximum-paths](#multipath), which only sets what NOS installs. For a receiver to build the same multipath set, set `add-path-send-count` to at least `maximum-paths`.
- A path keeps its path identifier as long as it stays among the best N, even when its rank changes. A path entering the set takes over the identifier of one that left, in a single UPDATE, so the receiver never holds fewer paths in between. Identifiers left over are withdrawn.
- Changing it resets the peer-group's sessions.

### Route server (RFC 7947)

At an exchange point, a route server passes routes between its clients without appearing in their paths. Mark the clients' peer-group with `set route-server-client`; it must be eBGP. For such peers NOS:

- never adds its own AS to the AS path;
- if the client supports ADD-PATH (RFC 7911), sends it every other client's path for a prefix, not only the single best one: each path a client sends, so a client that itself sends several paths has each of them passed on. `add-path-send-count` caps this to the best N. A client without ADD-PATH receives the best path only;
- leaves the next hop unchanged by default (RFC 7947 §2.2.1), so clients forward to each other directly. An explicit `set next-hop self` still overrides it;
- passes a received `MED` through unchanged (RFC 7947 §2.2); a `MED` set by the export policy replaces it.

`route-reflector-client` and `route-server-client` cannot both be set on one peer-group.

### Graceful restart (RFC 4724, RFC 8538)

Graceful restart is **on by default**. It lets a peer's routes stay in use while its session is down for a short time, so traffic keeps flowing through a restart:

- Every OPEN carries the graceful restart capability, with the RFC 8538 N bit and one entry per configured address family. A peer that doesn't advertise it is not affected: its session ending withdraws its routes at once, as before.
- When a session with a peer that advertised it ends, its routes of every family it listed are kept and marked stale, for up to its restart time. They stay best paths, stay in the kernel and keep being advertised.
- The router logs `peer down, retaining routes as stale peer=…`, and `show bgp brief` shows the peer as `Idle (gr-stale <n>)` meanwhile.
- When the peer comes back, the routes it re-announces lose their stale mark. Its End-of-RIB removes the rest (`purged stale routes after end-of-rib`), or `stale-time` does if no End-of-RIB comes.
- A peer that comes back without the capability, or without its forwarding state for a family (F bit clear), has that family's stale routes removed at once (`flushing stale routes … reason=no-capability|forwarding-not-preserved`).
- NOS sends End-of-RIB after the initial routes of each family, to peers that advertised graceful restart.

When `nos-bgpd` itself restarts (a crash or a kill) while the routing table's `nos-ribd` keeps running, it restarts gracefully:

- At startup it asks `nos-ribd` how many BGP routes it still holds. More than zero means the kernel kept forwarding, so it logs `graceful restart: forwarding state preserved, deferring route selection bgp_routes=<n>`.
- Its OPEN then sets the R bit and F=1 for every family, so peers keep its routes until its End-of-RIB instead of dropping them.
- It learns routes as usual but sends nothing yet: no UPDATE, no End-of-RIB, and no change to the kernel, which keeps the routes it had.
- It waits for End-of-RIB from every configured peer and for the routes it redistributes. A peer that doesn't advertise graceful restart, or is restarting itself (R bit), isn't waited for, nor is one still down after `restart-time`.
- Then it logs `route selection deferral ended reason=end-of-rib`, sends each peer its routes and End-of-RIB, and replaces the kernel's BGP routes with what it selected. If that takes longer than `selection-deferral-time`, it goes ahead anyway (`reason=timer`).
- If `nos-ribd` restarted too, or holds no BGP route, there is nothing to preserve: no deferral, and F=0.
- EVPN routes this router originates (from a broadcast domain or an IP-VRF) and VRF routes it exports as VPN routes aren't waited for. One that reaches `nos-bgpd` after the deferral is sent on its own, so a peer may drop and re-learn it.

Which session ends keep the routes:

| How the session ended | Routes kept |
|---|---|
| TCP connection lost (peer process crash, link loss) | yes |
| NOTIFICATION sent or received, hold timer expiry included, both sides with N | yes, except a Hard Reset |
| Hard Reset (Cease subcode 9), or any NOTIFICATION without N | no |

With N exchanged, these Cease NOTIFICATIONs go out as a Hard Reset wrapping the original, so the peer drops our routes at once: `clear bgp <i> <peer>`, an administrative shutdown, a peer removed from the config, a maximum-prefix trip, and the router or instance stopping. A peer-group change (Other Configuration Change) stays graceful. A received Hard Reset is logged with the NOTIFICATION it wraps (`code=6 subcode=9 hard_reset_code=6 hard_reset_subcode=2 shutdown_message=…`).

What default-on costs:

- After a crash of the whole router (or of `nos-ribd` too), peers keep forwarding to it for up to `restart-time` (120s by default), even though its routing table is gone. Its OPEN then says F=0, so peers drop its routes as soon as it is back.
- When a peer dies silently (no TCP reset) and both sides have N, its routes are kept until the hold timer expires and then for its restart time: up to 90 + 120 seconds, not 90.

Settings, on the BGP instance:

- `graceful-restart disable` turns it off: no capability, nothing kept.
- `graceful-restart restart-time <s>`: what we advertise, 0 to 4095, default 120.
- `graceful-restart stale-time <s>`: how long a returned peer's stale routes wait for its End-of-RIB, default 180.
- `graceful-restart selection-deferral-time <s>`: the longest a restarted `nos-bgpd` waits for its peers' End-of-RIB before sending its routes, default 360.
- `delete` any of them to go back to the default. Changing the setting restarts the instance's sessions.

```
edge-1(t8/bgp-instance:r1)> set graceful-restart restart-time 60
edge-1> show bgp brief
bgp instance r1:
  10.50.0.3 AS 65002 peer-group pg1 Established uptime 00:01:12 hold-time 90 gr 120s N F:ipv4
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d 'true' $B/v1/transactions/t8/bgp-instance/r1/graceful-restart/disabled
$C -X DELETE $B/v1/transactions/t8/bgp-instance/r1/graceful-restart/disabled
```

`GET /v1/bgp/summary` reports each peer's capability (`graceful_restart`: restart time, N, R and the F bit per family) and `stale_prefixes`.

A peer that rejects capability 64 with an OPEN error never comes up; turn graceful restart off on that instance.

### What is not supported yet

These are known gaps, so plan around them:

- A route's attributes cannot be displayed. `show route` shows the chosen next hop, and the log records each learned route.
- Malformed UPDATEs: a malformed multiprotocol attribute resets the session (no AFI/SAFI-disable, RFC 7606 §3(d)).

## Configuration reference

"Relative" is the form used inside the object (after `edit bgp instance <i>`, or `edit peer-group <g>` inside it). REST paths are relative to `/v1/transactions/{tx}/`. Everything is validated at commit.

### BGP instance

Created with `edit bgp instance <name>`; deleted with `delete bgp instance <name>` (or `delete` inside it). REST: `bgp-instance/<name>`.

| Field | CLI (absolute / relative) | REST path and JSON | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit bgp instance <name>` | `bgp-instance/<name>`, `"name"` | string, 1 to 64 characters | unique | Names the instance, as referenced by a routing table | `show config` |
| asn | `set bgp instance <i> asn <n>` / `set asn <n>` | `…/asn`, number | 1 to 4294967294; required | not 0 or 4294967295 | This router's AS number | `show config` |
| router-id | `set bgp instance <i> router-id <a.b.c.d>` / `set router-id <a.b.c.d>` | `…/router-id`, `"1.1.1.1"` | IPv4 address; required | must be set (`0.0.0.0` is refused by peers) | BGP identifier in the OPEN; best-path tie-breaker | `GET /v1/bgp/summary` on the peer (`remote_bgp_id`) |
| cluster-id | `set bgp instance <i> cluster-id <a.b.c.d>` / `set cluster-id <a.b.c.d>`; `delete bgp instance <i> cluster-id` / `delete cluster-id` | `…/cluster-id`, `"10.255.0.1"` or `null` | IPv4 address; default: the router ID | none | Cluster ID added to `CLUSTER_LIST` when reflecting | `show config` |
| maximum-paths | `set bgp instance <i> maximum-paths <n>` / `set maximum-paths <n>`; `delete bgp instance <i> maximum-paths` / `delete maximum-paths` | `…/maximum-paths`, number or `null` | 1 to 64; default: unset (1) | 1 to 64 | How many equal paths' next hops a prefix installs; see [Multipath](#multipath) | `show route` |
| confederation identifier | `set bgp instance <i> confederation identifier <n>` / `set confederation identifier <n>`; `delete … confederation identifier` | `…/confederation/identifier`, number or `null` | 1 to 4294967294; default: none (not in a confederation) | differs from `asn` | The AS peers outside the confederation see; `asn` becomes the member AS | `show config`; `remote_asn` in the outside peer's `GET /v1/bgp/summary` |
| confederation peer | `set bgp instance <i> confederation peer <n>` / `set confederation peer <n>`; `delete … confederation peer <n>` | `…/confederation/peer`, list of numbers | ASNs; default: none | distinct, not `asn` nor the identifier, needs an identifier; a route-server-client peer-group can't be one | Peer-groups with this `remote-as` are confederation eBGP | `show config` |
| aggregate-address | `set bgp instance <i> aggregate-address <prefix>` / `set aggregate-address <prefix>`; `delete aggregate-address <prefix>` | `…/aggregate-address/<prefix with %2F>`, `{"prefix":"198.51.0.0/16","as_set":false,"summary_only":false}` | list, keyed by prefix; default: none | network address (no host bits), not a /32 or /128, unique | Originates the aggregate; see [Aggregation](#aggregation-rfc-4271-9222) | `show log nos-bgpd[<i>]` |
| aggregate-address as-set | `… aggregate-address <prefix> as-set` / `set aggregate-address <prefix> as-set`; `delete aggregate-address <prefix> as-set` | `as_set` in the aggregate | boolean; default `false` | none | Keeps the more specific routes' ASes in an `AS_SET` | `show log nos-bgpd[<i>]` (`as_path`) |
| aggregate-address summary-only | `… aggregate-address <prefix> summary-only` / `set aggregate-address <prefix> summary-only`; `delete aggregate-address <prefix> summary-only` | `summary_only` in the aggregate | boolean; default `false` | none | Withdraws the more specific routes from peers | `show log nos-bgpd[<i>]` |
| graceful-restart disable | `set bgp instance <i> graceful-restart disable` / `set graceful-restart disable`; `delete … graceful-restart disable` | `…/graceful-restart/disabled`, boolean | default `false` (graceful restart on) | none | Turns graceful restart off; see [Graceful restart](#graceful-restart-rfc-4724-rfc-8538). Restarts the sessions | `GET /v1/bgp/summary` on the peer (`graceful_restart`) |
| graceful-restart restart-time | `set bgp instance <i> graceful-restart restart-time <s>` / `set graceful-restart restart-time <s>`; `delete … graceful-restart restart-time` | `…/graceful-restart/restart-time`, number or `null` | seconds; default 120 | at most 4095 | The restart time we advertise. Restarts the sessions | `show bgp brief` on the peer (`gr <s>s`) |
| graceful-restart stale-time | `set bgp instance <i> graceful-restart stale-time <s>` / `set graceful-restart stale-time <s>`; `delete … graceful-restart stale-time` | `…/graceful-restart/stale-time`, number or `null` | seconds; default 180 | at least 1 | How long a returned peer's stale routes wait for its End-of-RIB | `show log nos-bgpd[<i>]` |
| graceful-restart selection-deferral-time | `set bgp instance <i> graceful-restart selection-deferral-time <s>`; `delete … graceful-restart selection-deferral-time` | `…/graceful-restart/selection-deferral-time`, number or `null` | seconds; default 360 | at least 1 | How long a restarted `nos-bgpd` waits for its peers' End-of-RIB before sending its routes | `show config` |
| routing table | `set routing-table <t> bgp-instance <i>`; `delete routing-table <t> bgp-instance` | `routing-table/<t>/bgp-instance`, `"r1"` | name; default: none | instance must exist; one table per instance | Runs the instance in that table's VRF. Without it, the instance opens no session | `show bgp brief` |

`bgp-instance/<name>/routing-table` and `bgp-instance/<name>/redistribute-policy` also appear in the REST tree. They are read-only copies of the routing table's settings, recomputed at every commit; set the routing table's fields instead.

### Peer-group

Created with `edit bgp instance <i> peer-group <g>` (or `edit peer-group <g>` inside the instance); deleted with `delete bgp instance <i> peer-group <g>` (or `delete peer-group <g>`, or `delete` inside it). REST: `bgp-instance/<i>/peer-group/<g>`. Every `delete` of a single field is relative only: run it inside the peer-group.

| Field | CLI (absolute / relative) | REST path and JSON | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit peer-group <g>` | `…/peer-group/<g>`, `"name"` | string, 1 to 64 characters | unique across all instances | Names the group, as referenced by peers | `show config` |
| remote-as | `set bgp instance <i> peer-group <g> remote-as <n>` / `set remote-as <n>` | `…/remote-as`, number | 1 to 4294967294; required | not 0 or 4294967295 | The AS its peers must announce; equal to `asn` makes it iBGP | `show bgp brief` |
| flowspec-import-policy | `… flowspec-import-policy <policy>` / `set flowspec-import-policy <policy>`; `delete flowspec-import-policy` | `…/flowspec-import-policy`, a policy name or `null` | policy name; default: accept every rule | `accept-all`, `deny-all` or an existing policy-definition | Accepts, rejects or rewrites received Flowspec rules; changing it restarts the sessions | `show bgp flowspec` |
| flowspec-export-policy | `… flowspec-export-policy <policy>` / `set flowspec-export-policy <policy>`; `delete flowspec-export-policy` | `…/flowspec-export-policy`, a policy name or `null` | policy name; default: advertise every rule | `accept-all`, `deny-all` or an existing policy-definition | Accepts, rejects or rewrites Flowspec rules advertised to the peers; changing it restarts the sessions | peer's `show bgp flowspec` |
| flowspec-validation | `… flowspec-validation disable-dest-prefix-rule <bool>` / `set flowspec-validation disable-dest-prefix-rule <bool>` | `…/flowspec-validation`, `{"disable_dest_prefix_rule":false}` | bool; default false | none | Accepts Flowspec rules without a destination prefix (RFC 8955 section 6 rule (a)); changing it restarts the sessions | `show bgp flowspec` |
| flowspec-validation rfc8955-strict | `… flowspec-validation rfc8955-strict <bool>` / `set flowspec-validation rfc8955-strict <bool>` | `…/flowspec-validation`, `{"rfc8955_strict":false}` | bool; default false (RFC 9117) | none | Validates as RFC 8955 section 6 is written; changing it restarts the sessions | `show bgp flowspec` |
| address-family | `… address-family ipv4\|ipv6\|l2vpn-evpn\|ipv4-flowspec\|ipv6-flowspec\|vpnv4\|vpnv6` / `set address-family <af>`; `delete address-family <af>` | `…/address-family/<af>`, `"Ipv4Unicast"`, `"Ipv6Unicast"`, `"L2vpnEvpn"`, `"Ipv4Flowspec"`, `"Ipv6Flowspec"`, `"Vpnv4Unicast"`, `"Vpnv6Unicast"` | list; at least one required | not empty, no duplicates | Address families negotiated with the peer | `show config` |
| source-address | `… source-address interface <if> [label <l>]` or `… source-address loopback [label <l>]` / `set source-address …`; `delete source-address` | `…/source-address`, `{"Interface":{"interface":"eth0","label":null}}` or `{"Loopback":{"label":null}}` | default: chosen by the kernel | none at commit; resolved when connecting | Local address of the session | `show log nos-bgpd[<i>]` |
| hold-time | `… hold-time <s>` / `set hold-time <s>`; `delete hold-time` | `…/hold-time`, number or `null` | 0 to 65535 seconds; default 90 | 0 or ≥ 3 | Proposed hold time; the lower of both sides is used; 0 disables keepalives | `show bgp brief` (`hold-time`) |
| keepalive-interval | `… keepalive-interval <s>` / `set keepalive-interval <s>`; `delete keepalive-interval` | `…/keepalive-interval`, number or `null` | seconds; default: negotiated hold time / 3 | < hold-time when both are set | Interval between KEEPALIVEs | `GET /v1/bgp/summary` (`negotiated_keepalive`) |
| connect-retry-time | `… connect-retry-time <s>` / `set connect-retry-time <s>`; `delete connect-retry-time` | `…/connect-retry-time`, number or `null` | 1 to 65535 seconds; default 120 | ≥ 1 | Wait between two connection attempts | `show config` |
| mrai | `… mrai <s>` / `set mrai <s>`; `delete mrai` | `…/mrai`, number or `null` | 0 to 65535 seconds; default: unset (no pacing) | none | Minimum interval between advertisements of one prefix to one peer | `show config` |
| damping | `… damping [half-life <s>] [reuse <n>] [suppress <n>] [max-suppress <s>]` / `set damping …`; `delete damping` | `…/damping`, `{"half_life":900,"reuse":750,"suppress":6000,"max_suppress":3600}` or `null` | default: off; parameters default to 900 / 750 / 6000 / 3600 | eBGP peer-group only; half-life > 0, reuse > 0, suppress > reuse, max-suppress ≥ half-life | Flap damping of received routes | `show log nos-bgpd[<i>]` |
| local-as | `… local-as asn <n> [no-prepend] [replace-as]` / `set local-as …`; `delete local-as` | `…/local-as`, `{"asn":65020,"no_prepend":false,"replace_as":false}` or `null` | ASN 1 to 4294967294; default: off | eBGP peer-group outside the confederation; not the instance's asn, identifier or remote-as; not with route-server-client | AS presented to the peers; see [Local AS](#local-as-local-as) | `remote_asn` in the peer's `GET /v1/bgp/summary` |
| add-path | `… add-path receive\|send\|both` / `set add-path …`; `delete add-path` | `…/add-path`, `"Receive"`, `"Send"`, `"Both"` or `null` | default: `both` for a route-server client, otherwise off | none | RFC 7911 several paths per prefix on ipv4/ipv6; see [ADD-PATH](#add-path-rfc-7911) | `show log nos-bgpd[<i>]` (`add-path negotiated`) |
| add-path-send-count | `… add-path-send-count <n>` / `set add-path-send-count <n>`; `delete add-path-send-count` | `…/add-path-send-count`, number or `null` | 2 to 64; default: 2, or every path for a route-server client | add-path `send` or `both` | How many paths per prefix an ADD-PATH send peer gets: the best N after the group's own filtering | `show config` |
| role | `… role provider\|route-server\|route-server-client\|customer\|peer` / `set role …`; `delete role` | `…/role`, `"Provider"`, `"RouteServer"`, `"RouteServerClient"`, `"Customer"`, `"Peer"` or `null` | default: none | eBGP peer-group outside the confederation; on a route-server-client group only route-server or route-server-client | Role of the peers, announced in the OPEN; see [BGP roles](#bgp-roles-rfc-9234) | `bgp role negotiated` in the logs |
| strict-mode | `… strict-mode` / `set strict-mode`; `delete strict-mode` | `…/strict-mode`, boolean | default `false` | needs a role | Refuse a peer that sends no role | Role Mismatch NOTIFICATION in the logs |
| max-hops | `… max-hops <n>` / `set max-hops <n>`; `delete max-hops` | `…/max-hops`, number or `null` | 1 to 254; default: off | 1 to 254 | GTSM: TTL 255 out, minimum TTL `256 - n` in | `show config` |
| md5-password | `… md5-password <label>` / `set md5-password <label>`; `delete auth` | `…/auth`, `{"Md5":{"key_ref":"<label>"}}` | admin key label; default: no authentication | the label exists and its secret is 1 to 80 bytes | TCP MD5 signature; replaces any TCP-AO keys | `show bgp brief` (session up) |
| ao-key | `… ao-key <send-id> <recv-id> hmac-sha1\|aes-cmac <label>` / `set ao-key …`; `delete ao-key <send-id>`; `delete auth` | `…/auth`, `{"Ao":{"keys":[{"send_id":1,"recv_id":1,"algorithm":"HmacSha1_96","key_ref":"<label>","is_current":true,"is_rnext":false,"exclude_options":false}]}}` | IDs 0 to 255; label of an admin key with a 1 to 80 byte secret | at least one key; send IDs and receive IDs unique; exactly one current; at most one rnext | TCP-AO; replaces an MD5 password | `show bgp brief` (`ao-current`, `ao-rnext`, counters) |
| ao-key current | `… ao-key <send-id> current` / `set ao-key <send-id> current` | `is_current` in the key | flag | exactly one key | Key a new connection starts signing with; a live session follows the peer's choice | `show bgp brief` (`ao-current`) |
| ao-key rnext | `… ao-key <send-id> rnext` / `set ao-key <send-id> rnext` | `is_rnext` in the key | flag | at most one key | Key this router asks the peer to switch to; applied to the live session in place | `show bgp brief` (`ao-rnext`) |
| exclude-options | `… ao-key <send-id> exclude-options` / `set ao-key <send-id> exclude-options`; `delete ao-key <send-id> exclude-options` | `exclude_options` in the key | boolean; default `false` | the key must exist | Leaves TCP options out of the MAC; both sides must agree | `show bgp brief` (session up) |
| rpki-cache auth | `set bgp instance <i> rpki-cache <addr> md5-password <label>` or `… ao-key …`; `delete … auth` | `…/rpki-cache/<addr>/auth`, as a peer-group's `auth` | default: none (plain TCP) | as a peer-group's `auth` | TCP-MD5 or TCP-AO on the RTR session; see [Authenticating the cache session](#authenticating-the-cache-session-rfc-8210-9) | `show bgp rpki` (`auth yes`) |
| next-hop | `… next-hop self\|unchanged` / `set next-hop self\|unchanged`; `delete next-hop` | `…/next-hop`, `"SelfAddress"`, `"Unchanged"` or `null` | default: `self` for eBGP, `unchanged` for iBGP and route-server peer-groups | none | `NEXT_HOP` of advertised routes | `show config`; `show route` on the peer |
| route-reflector-client | `… route-reflector-client` / `set route-reflector-client`; `delete route-reflector-client` | `…/route-reflector-client`, boolean | default `false`; required in a whole-object `PUT` | iBGP peer-group only; not with route-server-client | Reflects iBGP routes to and from these peers | `show config` |
| route-server-client | `… route-server-client` / `set route-server-client`; `delete route-server-client` | `…/route-server-client`, boolean | default `false`; required in a whole-object `PUT` | eBGP peer-group only; not with route-reflector-client | Transparent AS path; ADD-PATH views | `show config` |
| import-policy | `… import-policy <policy>` / `set import-policy <policy>`; `delete import-policy` | `…/import-policy`, `"accept-all"` or `null` | policy name; default `deny-all` | `accept-all`, `deny-all` or an existing policy-definition | Filters and modifies received routes | `show config`; `show route` |
| export-policy | `… export-policy <policy>` / `set export-policy <policy>`; `delete export-policy` | `…/export-policy`, `"accept-all"` or `null` | policy name; default `deny-all` | as import-policy | Filters and modifies advertised routes | `show config`; `show route` on the peer |
| evpn-import-policy | `… evpn-import-policy <policy>` / `set evpn-import-policy <policy>`; `delete evpn-import-policy` | `…/evpn-import-policy`, a policy name or `null` | policy name; default: accept every EVPN route | `accept-all`, `deny-all` or an existing policy-definition | Accepts or rejects received EVPN routes (types 1, 2, 3, 5), see [EVPN](evpn-vxlan.md#filter-received-evpn-routes-trust-model) | `show config`; `show bgp evpn` |
| shutdown | `… shutdown [<message>]` / `set shutdown [<message>]`; `delete shutdown` | `…/shutdown`, `{"message":"…"}` or `{"message":null}` or `null` | message up to 255 bytes; default: not shut | message ≤ 255 bytes | Closes and keeps closed every session of the group | `show bgp brief` (`Idle (shutdown)`) |
| maximum-prefix | `… maximum-prefix ipv4\|ipv6\|l2vpn-evpn\|ipv4-flowspec\|ipv6-flowspec\|vpnv4\|vpnv6 limit <n> [warning-only] [restart-interval <s>]` / `set maximum-prefix …`; `delete maximum-prefix <family>` | `…/maximum-prefix/<family>`, `{"limit":1000,"warning_only":false,"restart_interval":0}` or `null` | limit 0 (uncapped) to 4294967295; default: no limit; restart-interval 0 (stay down) | the family must be in address-family | Closes the session with Cease subcode 1 when a peer sends more prefixes | `show bgp brief` (`Idle (max-prefix)`, `prefixes`) |

`show config` and `show this` end each peer-group line with its `import-policy` and `export-policy` (`default (deny-all)` when unset). Over REST, `GET …/peer-group/<g>/import-policy`.

### Peer

Created with `set bgp instance <i> peer <address> peer-group <g>` (or `set peer <address> peer-group <g>` inside the instance); the same command moves an existing peer to another group. Deleted with `delete bgp instance <i> peer <address>` (or `delete peer <address>`). REST: `bgp-instance/<i>/peer/<address>`.

| Field | CLI (absolute / relative) | REST path and JSON | Type, range, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| remote-address | `… peer <address> …` | `…/peer/<address>`, `"remote_address":"10.50.0.3"` | IPv4 or IPv6 address | unique across all instances | The neighbour's address | `show bgp brief` |
| peer-group | `set bgp instance <i> peer <a> peer-group <g>` / `set peer <a> peer-group <g>` | `…/peer/<a>/peer-group`, `"pg1"` | name; required | the peer-group must exist | Settings used for this peer | `show bgp brief` |
| shutdown | `set bgp instance <i> peer <a> shutdown [<message>]` / `set peer <a> shutdown [<message>]`; `delete bgp instance <i> peer <a> shutdown` / `delete peer <a> shutdown` | `…/peer/<a>/shutdown`, `{"message":"…"}` or `null` | message up to 255 bytes; default: follow the peer-group | message ≤ 255 bytes | Shuts this peer only; overrides the peer-group | `show bgp brief` |

### Operational commands

| CLI | REST | Effect |
|---|---|---|
| `show bgp brief` | `GET /v1/bgp/summary` | Every peer of every instance, with state, remote AS, uptime, hold time and TCP-AO state |
| `show bgp evpn` | `GET /v1/bgp/evpn` | EVPN routes received, per instance |
| `show bgp flowspec` | `GET /v1/bgp/flowspec` | Flowspec rules received, per instance |
| `show bgp vpnv4\|vpnv6 [rd <rd>]` | `GET /v1/bgp/vpnv4\|vpnv6[?rd=<rd>]` | VPN routes received, per instance |
| `show route <table> [<address>]` | `GET /v1/routes/{table}[/{addr}]` | Installed routes, BGP ones marked `bgp` |
| `clear bgp <instance> <peer> soft-in` | `POST /v1/bgp/{instance}/peer/{peer}/soft-in` | Route refresh request to one peer |
| `clear bgp <instance> <peer>` | `POST /v1/bgp/{instance}/peer/{peer}/clear` | Releases a maximum-prefix hold; resets an Established session |
| `show log nos-bgpd[<instance>]` | `GET /v1/logs?source=nos-bgpd%5B<instance>%5D` | The instance's log: sessions, NOTIFICATIONs, learned routes, damping |

- `show bgp routes|evpn|flowspec|vpnv4|vpnv6` are paged, in the CLI and over REST: the CLI prints each page as it arrives; REST returns `{"items": [...], "pagination": {"limit", "next"}}` per instance, and you continue with `?instance=<name>&after=<pagination.next>` until `next` is `null` (`?limit=` 1 to 1000; `after`/`limit` without `?instance=` are `400`). Details: [REST API guide](../api.md).
