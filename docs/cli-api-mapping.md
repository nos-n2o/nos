# CLI ↔ API mapping

The shell and the REST API are equivalent ways into the same router. This page shows the REST equivalent of each CLI operation, and how to turn a CLI configuration command into a URL. It ends with one change made from both front ends at once.

The REST examples use the `$B`/`$C` variables from [The REST API](api.md#a-complete-session-with-curl).

## Operational commands

| CLI | REST |
|---|---|
| `show config` | `GET /v1/config` |
| `show route <table>` | `GET /v1/routes/{table}` |
| `show route <table> <address>` | `GET /v1/routes/{table}/{addr}` |
| `show interface` / `show interface <name>` | `GET /v1/interfaces` / `GET /v1/interfaces/{name}` |
| `show port-aggregate` / `show port-aggregate <name>` | `GET /v1/port-aggregates` / `GET /v1/port-aggregates/{name}` |
| `show lacp` / `show lacp <name>` | `GET /v1/lacp` / `GET /v1/lacp/{name}` |
| `show acl` / `show acl <name>` | `GET /v1/acl` / `GET /v1/acl/{name}` |
| `show acl` (flowspec rules, at the end) | `GET /v1/flowspec` |
| `show lldp neighbors` / `show lldp neighbors detail` | `GET /v1/lldp/neighbors` |
| `show lldp statistics` | `GET /v1/lldp/statistics` |
| `show version` | `GET /v1/version` |
| `show spanning-tree` / `... detail` | `GET /v1/spanning-tree` (always carries topology and counters) |
| `show spanning-tree instance <id> [detail]` / `domain <bd> [detail]` | `GET /v1/spanning-tree/instance/{id}` / `.../domain/{name}` |
| (counters as a flat table) | `GET /v1/spanning-tree/counters` |
| `clear spanning-tree err-disabled <if>` | `POST /v1/spanning-tree/port/{interface}/err-disabled/clear` |
| `clear spanning-tree detected-protocols` / `... interface <if>` | `POST /v1/spanning-tree/mcheck` / `POST /v1/spanning-tree/port/{interface}/mcheck` |
| `show bfd sessions` / `show bfd sessions <peer>` | `GET /v1/bfd/sessions` / `GET /v1/bfd/sessions?peer=<peer>` |
| `show bfd reflector` | `GET /v1/bfd/reflector` |
| `show bgp brief` | `GET /v1/bgp/summary` |
| `show bgp evpn` | `GET /v1/bgp/evpn` |
| `show bgp flowspec` | `GET /v1/bgp/flowspec` |
| `show bgp vpnv4` / `show bgp vpnv4 rd <rd>` | `GET /v1/bgp/vpnv4` / `GET /v1/bgp/vpnv4?rd=<rd>` |
| `show bgp vpnv6` / `show bgp vpnv6 rd <rd>` | `GET /v1/bgp/vpnv6` / `GET /v1/bgp/vpnv6?rd=<rd>` |
| `show bgp rpki` | `GET /v1/bgp/rpki` |
| `show bgp bmp` | `GET /v1/bgp/bmp` |
| `show bgp routes` | `GET /v1/bgp/routes` |
| `show ospf neigh` / `show ospf database` | `GET /v1/ospf/neighbors` / `GET /v1/ospf/database` |
| `show ospfv3 neigh` / `show ospfv3 database` | `GET /v1/ospfv3/neighbors` / `GET /v1/ospfv3/database` |
| `show fdb <domain>` | `GET /v1/fdb/{domain}` |
| `show log` / `show log <source>` | `GET /v1/logs` / `GET /v1/logs?source=<source>` (also `&limit=<n>`) |
| `show log [<source>] --follow` | `GET /v1/logs/follow[?source=<source>]` (Server-Sent Events) |
| `clear bgp <instance> <peer> soft-in` | `POST /v1/bgp/{instance}/peer/{peer}/soft-in` |
| `clear bgp <instance> <peer>` | `POST /v1/bgp/{instance}/peer/{peer}/clear` |

The shell formats the data as text and REST returns it as JSON, but the data is the same. For example, `show bgp brief`'s line

```
  10.50.0.3 AS 65002 peer-group pg1 Established uptime 00:02:21 hold-time 90
```

comes from the same record that `GET /v1/bgp/summary` returns as `{"remote_address":"10.50.0.3","remote_as":65002,"peer_group":"pg1","state":"Established","uptime_secs":…,"negotiated_hold_time":90,…}`.

## Transaction lifecycle

| CLI | REST |
|---|---|
| `configure <name>` | `POST /v1/transactions/{name}` (or `?base=current`) |
| `configure <name> from blank` | `POST /v1/transactions/{name}?base=blank` |
| `show this` at the top of the transaction | `GET /v1/transactions/{name}` (the `config` member) |
| `show this` inside an object | `GET /v1/transactions/{name}/{path to that object}` |
| `diff` | `GET /v1/transactions/{name}/diff` |
| `commit` | `POST /v1/transactions/{name}/commit` |
| `discard` / `abort` | `DELETE /v1/transactions/{name}` |
| `save` | `POST /v1/config/save` |
| `exit` → `[l]eave open` | nothing to do: a transaction stays open until it is committed or discarded |

## Configuration commands → URLs

Each `set`/`delete` corresponds to a `PUT`/`DELETE` on the URL of what it changes. The URL follows the CLI's own words, with these translations:

1. Start from `/v1/transactions/{tx}/`.
2. Each object keyword becomes its path segment. Two-word CLI keywords become one hyphenated segment: `bgp instance r1` → `bgp-instance/r1`, `ospf instance o1` → `ospf-instance/o1`, `broadcast domain d1` → `broadcast-domain/d1`.
3. An interface's untagged subinterface is explicit in the URL. `interface eth0` in an address or routing-table command is `interface/eth0/subinterface/0`, and `interface eth0.100` is `interface/eth0/subinterface/100`.
4. A list element is identified by its key, with `/` encoded as `%2F`: `route 192.0.2.0/24` → `route/192.0.2.0%2F24`. Addresses live in a list called `address`, keyed by the address itself.
5. The value becomes the JSON body. Numbers and strings go as they are. On/off keywords (`set route-reflector-client`) are `true`/`false`. Keyword values use the names shown in the JSON (`address-family ipv4` is `"Ipv4Unicast"`); `GET` the path, or read the [OpenAPI document](api.md#the-openapi-document), to see the exact form.
6. Where `delete` resets a field to its default, the REST equivalent is `DELETE` on that field.

| CLI (absolute form) | REST |
|---|---|
| `set hostname lab-1` | `PUT …/hostname` body `"lab-1"` |
| `set bgp instance r1 peer-group pg1 hold-time 30` | `PUT …/bgp-instance/r1/peer-group/pg1/hold-time` body `30` |
| `set static-routing-instance s1 route 192.0.2.0/24 gateway 10.50.0.3` | `PUT …/static-routing-instance/s1/route/192.0.2.0%2F24` body `{"subnet":"192.0.2.0/24","gateway":"10.50.0.3"}` |
| `delete static-routing-instance s1 route 192.0.2.0/24` | `DELETE …/static-routing-instance/s1/route/192.0.2.0%2F24` |
| `set interface eth0 address 10.99.0.1/24` | `PUT …/interface/eth0/subinterface/0/address/10.99.0.1%2F24` body `{"address":"10.99.0.1/24","label":null}` |
| `set routing-table rt1 static-routing-instance s1` | `PUT …/routing-table/rt1/static-routing-instance` body `"s1"` |
| `delete routing-table rt1 rest-api` | `DELETE …/routing-table/rt1/rest-api` |
| `delete bgp instance r1` | `DELETE …/bgp-instance/r1` |

**`edit` has no REST counterpart,** because there is no current position to move to: every URL is absolute. `edit` also creates the object if it is missing. Over REST, you create an object by `PUT`ting it whole, with every required field:

```sh
$ $C -X PUT -H 'Content-Type: application/json' \
    -d '{"name":"r2","router_id":"9.9.9.9","asn":65009,"peer_groups":[],"peers":[]}' \
    $B/v1/transactions/m2/bgp-instance/r2
{"asn":65009,"cluster_id":null,"name":"r2","peer_groups":[],"peers":[],"redistribute_policy":null,"router_id":"9.9.9.9","routing_table":null}
```

A body with a required field missing is refused straight away:

```
{"type":"about:blank","title":"Bad Request","status":400,"detail":"invalid JSON body for config path: missing field `router_id`"}
```

In the shell, `edit` creates an object with its defaults (`edit bgp instance r9` gives `asn 0`, `router-id 0.0.0.0`), and the commit's validation catches any required field you forgot to set. `set` creates a missing object the same way, like REST's `PUT`: `set bgp instance r7 asn 65007` creates `r7` with its defaults and sets its ASN.

**Passwords are hashed the same way on both sides.** `set user alice password s3cret` in the shell, and `PUT …/user/alice` with body `{"name":"alice","password":"s3cret"}` over REST, both store only an argon2id hash.

## One transaction, two front ends

A transaction is identified only by its name, so either front end can pick it up. Here it is opened and edited in the shell, left open, then read and committed over REST:

```
lab-1> configure shared
lab-1(shared)> set hostname edge-1
lab-1(shared)> exit
Transaction 'shared' has uncommitted changes. [c]ommit / [d]iscard / [l]eave open (default): l
transaction 'shared' left open on the daemon — resume with 'configure shared'
```

```sh
$ $C -i $B/v1/transactions/shared/hostname
HTTP/2 200
content-type: application/json
etag: "1"

"edge-1"
$ $C -X POST $B/v1/transactions/shared/commit
{"committed":"shared"}
$ $C $B/v1/config | jq .hostname
"edge-1"
```

The `ETag` is `"1"` because the shell's single `set` was the transaction's first edit. Shell edits and REST edits increase the same generation counter.

## Operations with no counterpart

Only in the CLI:

- `help`, `?` and Tab. Over REST, use the [OpenAPI document](api.md#the-openapi-document) or `/swagger-ui/`.
- `edit`, `up` and `top`. They are not needed, because every URL is absolute (see above).

Only in the REST API:

- `If-Match` and `If-None-Match`, for conditional edits by scripts that must not overwrite each other. The shell always lets the last write win.
- `PUT /v1/transactions/{tx}`, which replaces the whole config in one request, for example from a template.
- `POST /v1/renew`, to renew a certificate. The shell renews its own automatically.
- `GET …/diff` returns the diff as structured JSON. The shell shows the same diff as text.
