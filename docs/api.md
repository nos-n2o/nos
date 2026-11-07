# The REST API

The REST API serves the whole router over HTTPS as JSON: every `show` query, the full transaction and configuration-editing workflow, and the live log stream. This page explains how to enable it, how to authenticate, and how to use it. Every example was run with `curl` against a real router.

- [Enabling the API](#enabling-the-api)
- [What a client needs](#what-a-client-needs)
- [Getting a client certificate](#getting-a-client-certificate)
- [A complete session with curl](#a-complete-session-with-curl)
- [Reading state: the show endpoints](#reading-state-the-show-endpoints)
- [Changing configuration: transactions](#changing-configuration-transactions)
- [The config tree as URLs](#the-config-tree-as-urls)
- [Concurrent edits: `ETag` and `If-Match`](#concurrent-edits-etag-and-if-match)
- [Actions](#actions)
- [Following the log (Server-Sent Events)](#following-the-log-server-sent-events)
- [Errors](#errors)
- [The OpenAPI document](#the-openapi-document)

## Enabling the API

The API is off until you enable it for a routing table. It then runs inside that table's VRF and listens on exactly one address, which must be configured on an interface in the same routing table. It never listens on a wildcard address.

```
edge-1> configure rest
edge-1(rest)> set routing-table rt1 rest-api address 10.50.0.2 port 8080
edge-1(rest)> commit
transaction 'rest' committed
```

`set routing-table <table> rest-api address <ip>` listens on port 8080; add `port <port>` to choose another. `delete routing-table <table> rest-api` turns the API off again.

If the address is not configured in the VRF yet, the API keeps retrying every second and logs `rest api not listening yet: …` until it is. When the listener comes up it logs `rest api listening table=rt1 vrf=… address=10.50.0.2 port=8080`. Enable the API on a management routing table and address: every request needs a client certificate, but the address you choose decides who can reach the port in the first place.

## What a client needs

- **HTTPS only**, TLS 1.3, with the hybrid post-quantum key exchange `X25519MLKEM768`. There is no classical fallback. `curl` built against OpenSSL 3.5 or later offers it by default; a client that offers only classical groups fails the handshake:
  ```
  $ $C --curves X25519 $B/v1/config
  curl: (35) TLS connect error: error:0A000410:SSL routines::ssl/tls alert handshake failure
  ```
- **The REST CA certificate**, `/run/nos/pki/rest-ca.crt` on the router, to verify the server. NOS never serves it over the network. Copy it by a channel you already trust, for example:
  ```sh
  docker cp router-a:/run/nos/pki/rest-ca.crt .
  ```
  It changes whenever the router restarts, so copy it again after a restart.
- **A client certificate** for a NOS user, on every request except `POST /v1/login`. Without one, every route, including `/openapi.json` and `/swagger-ui/`, answers 401:
  ```
  $ curl -sS --cacert rest-ca.crt -i $B/v1/config
  HTTP/2 401
  content-type: application/problem+json
  www-authenticate: Mutual realm="nos", login="/v1/login"

  {"type":"about:blank","title":"Unauthorized","status":401,"detail":"a client certificate is required (POST /v1/login to get one)"}
  ```
- HTTP/2 or HTTP/1.1. Both work; HTTP/2 lets many requests share one connection.

## Getting a client certificate

You trade a user name and password once for a certificate. You generate the key pair yourself: the router only ever sees the public key, inside a certificate signing request (CSR), and returns a certificate for it.

**1. Generate an ECDSA P-256 key and a CSR.** The subject is ignored (the router names the certificate after the user who logs in), but `openssl` requires one:

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout key.pem -subj /CN=me -outform DER -out csr.der
```

**2. `POST /v1/login`** with the user, the password and the base64 of the DER CSR:

```sh
curl -sS --cacert rest-ca.crt -H 'Content-Type: application/json' \
  -d "{\"user\":\"e2e\",\"password\":\"e2e-password\",\"csr\":\"$(base64 -w0 csr.der)\"}" \
  https://10.50.0.2:8080/v1/login -o login.json
```

The reply holds the certificate (base64 DER) and its lifetime in seconds:

```json
{"certificate":"MIIBgDCCASagAwIBAgIUXnGz…","lifetime_secs":28800}
```

**3. Convert it to PEM** for `curl`:

```sh
jq -r .certificate login.json | base64 -d | openssl x509 -inform DER -out cert.pem
openssl x509 -in cert.pem -noout -subject -issuer -ext subjectAltName
```
```
subject=CN=user/e2e
issuer=CN=nos ca
X509v3 Subject Alternative Name:
    DNS:nos.internal, URI:nos://user/e2e
```

`key.pem` and `cert.pem` are now your credentials. Keep `key.pem` private.

**Renewing.** The certificate is valid for `lifetime_secs` (8 hours by default). Renew it before then, at about half its lifetime, with `POST /v1/renew`. Present the current certificate and send a CSR for a new key; no password is needed. The reply has the same shape as the login reply:

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout key2.pem -subj /CN=me -outform DER -out csr2.der
$C -H 'Content-Type: application/json' -d "{\"csr\":\"$(base64 -w0 csr2.der)\"}" $B/v1/renew
```

**Failed logins.** A wrong password or unknown user gets 401, `invalid credentials`, after a one-second delay. After 5 failures for the same user within 60 seconds, further attempts get `429 Too Many Requests`, with a `Retry-After` header, even if the password is right. Certificates already issued keep working.

**Deleted users.** Every request checks that the certificate's user still exists in the running config. Deleting a user locks out their certificates on the very next request, even though the certificates have not expired.

## A complete session with curl

The rest of this page, and the other pages, use these two variables:

```sh
B=https://10.50.0.2:8080
C="curl -sS --cacert rest-ca.crt --cert cert.pem --key key.pem"
```

```sh
$ $C $B/v1/bgp/summary | jq .
[
  {
    "instance": "r1",
    "result": [
      {
        "remote_address": "10.50.0.3",
        "peer_group": "pg1",
        "shutdown": false,
        "remote_as": 65002,
        "remote_bgp_id": "2.2.2.2",
        "state": "Established",
        "uptime_secs": 28,
        "negotiated_hold_time": 90,
        "negotiated_keepalive": 30,
        …
      }
    ]
  }
]
```

## Reading state: the show endpoints

All are `GET`, and each returns the same data as the matching shell command, as JSON:

- `/v1/version`: `{version, revision}` of the running build; `revision` is `unknown` unless built by `make docker-build`. No daemon is queried.
- `/v1/config`: the running config. Secrets are masked: a user's `password` and every admin key `secret` read `<hidden>` here and in every transaction response (see [Secrets](#secrets-are-write-only)).
- `/v1/routes/{table}`: one page of prefixes (ascending) with every candidate route, best first: `{"items": [...], "pagination": {"limit": 1000, "next": "10.0.0.0/8"}}`. `?limit=` (1 to 1000, default 1000) sets the page size; pass `pagination.next` back as `?after=` until it is `null`. A malformed `after` is `400`. There is no snapshot: a table that changes mid-walk never repeats a prefix, but a walk may miss or include a concurrent change. Other paged endpoints use the same `items`/`pagination` envelope and `after`/`limit` params. `/v1/routes/{table}/{addr}` is the longest-prefix match for one address, or `404` if nothing covers it.
- `/v1/interfaces` and `/v1/interfaces/{name}`: applied interface state.
- `/v1/interfaces[/{name}]` and `/v1/port-aggregates[/{name}]` carry `err_disabled: true` while `nos-stpd`'s BPDU guard holds the port down.
- `/v1/port-aggregates[/{name}]` and `/v1/lacp[/{name}]`: bonds, their members and LACP state.
- `/v1/acl` and `/v1/acl/{name}`: every ACL (or one) with its attachments and, per rule, packets and bytes summed over its filters and devices; `default_packets`/`default_bytes` count what hit the default action. A rule the optimiser dropped has `dropped` (`shadowed` or `trailing`) and stays at 0. An unknown name is `404`, `nos-acld` not running is `503`.
- `/v1/flowspec`: every flowspec rule `nos-acld` holds, per BGP instance in order: `flow`, `actions`, `unsupported` (why it is not installed, `null` when it is) and packets/bytes summed over its devices.
- `/v1/lldp/neighbors`: LLDP neighbours. `/v1/lldp/statistics`: each LLDP-enabled interface's IEEE 802.1AB counters.
- `/v1/spanning-tree` (bridge, ports, `topology`, per-port `counters`), `/v1/spanning-tree/instance/{id}`, `/domain/{name}`, `/mst-config`, and `/v1/spanning-tree/counters` (one `{tree, port, counters}` row per port and tree, RFC 4318 names): `404` for an instance or domain the mode does not have, `503` when `nos-stpd` is not running. See [Spanning tree](protocols/stp.md#read-the-detail).
- `/v1/bfd/reflector`: the Seamless BFD reflector (`discriminators` as 32-bit numbers, `received`, `replied`, and `discarded` with a counter per reason); `nos-bfdd` not running is `503`.
- `/v1/bfd/sessions[?peer=<ip>]`: every BFD session (`state`, `diag`, discriminators, `tx_interval_us`, `detection_time_us`, and a `key` with `table` and `peer`; a micro-BFD session of a port aggregate has `key.aggregate` and `key.interface` (the member) and an empty `table`); an unparseable `peer` is `400`, `nos-bfdd` not running is `503`.
- `/v1/bgp/summary`, `/v1/bgp/rpki` and `/v1/bgp/bmp`: BGP peers, RPKI cache sessions and BMP stations, per instance.
- `/v1/bgp/routes`: IPv4/IPv6 unicast paths per instance, paged. Each instance's `result` is `{"items": [...], "pagination": {"limit": 1000, "next": "<cursor>"}}`. Without `?instance=<name>` you get every instance's first page; to continue, repeat with `?instance=<name>&after=<pagination.next>` until `next` is `null`. `?limit=` is 1 to 1000 (default 1000). `after` and `limit` without `?instance=` are `400`, as is an `after` that is not a cursor; an unknown instance is `404`. The cursor is opaque URL-safe text: pass it back verbatim. The daemon walks a sorted key snapshot, so a walk never repeats or loops, and routes added mid-walk show up on the next walk.
- `/v1/bgp/evpn`, `/v1/bgp/flowspec`, `/v1/bgp/vpnv4` and `/v1/bgp/vpnv6` (#723): received EVPN routes, Flowspec rules and VPN routes per instance, paged exactly like `/v1/bgp/routes` (same `{"items", "pagination"}` envelope, `?instance=`, `?after=`, `?limit=`, same `400`/`404` rules and opaque cursor). The VPN ones take `?rd=65001:1` for one Route Distinguisher (`400` if it is not one); repeat it on every page of a walk. VPN items carry `rd`, `prefix`, `labels`, `next_hop`, `route_targets`, `best` and the `site_of_origin`, if any.
- `/v1/ospf/neighbors`, `/v1/ospf/database`, and the same under `/v1/ospfv3/`: neighbours and LSDB, per instance.
- `/v1/fdb/{domain}`: a broadcast domain's MAC table and flood list.
- `/v1/logs?source=&limit=`: log entries, optionally from one source and only the last `limit`. `/v1/logs/follow` does the same, then streams new entries (see [below](#following-the-log-server-sent-events)).

The shell command for each is listed in [CLI ↔ API mapping](cli-api-mapping.md#operational-commands).

```sh
$ $C $B/v1/routes/rt1
{"items":[{"prefix":"10.50.0.0/24","candidates":[{"gateways":["10.50.0.2"],"source":"Connected","backup":null}]},
          {"prefix":"192.0.2.0/24","candidates":[{"gateways":["10.50.0.3"],"source":"Static","backup":null}]}],
 "pagination":{"limit":1000,"next":null}}
$ $C $B/v1/routes/rt1/192.0.2.7
{"prefix":"192.0.2.0/24","candidates":[{"gateways":["10.50.0.3"],"source":"Static","backup":null}]}
$ $C "$B/v1/logs?source=nos-bgpd%5Br1%5D&limit=1" | jq '.[0].source'
"nos-bgpd[r1]"
```

The `source` filter must match exactly, and per-instance sources contain brackets, so URL-encode them (`nos-bgpd[r1]` becomes `nos-bgpd%5Br1%5D`).

The endpoints that cover every instance (`bgp`, `ospf`, `ospfv3`) return one entry per configured instance. An instance that cannot answer gets an error entry of its own rather than failing the whole request. If the service behind an endpoint is unavailable, the answer is `503`.

## Changing configuration: transactions

Configuration changes over REST use the same named transactions as the shell (see [Concepts: Named transactions](concepts.md#working-with-transactions)):

| Request | Effect | Success |
|---|---|---|
| `POST /v1/transactions/{tx}?base=current\|blank` | Open `tx`, starting from the running config (default) or empty; or resume it if it already exists | `201` created / `200` resumed |
| `GET /v1/transactions/{tx}` | The transaction: `name`, `generation`, `dirty` (has edits), `resumed`, and the whole `config` | `200` |
| `PUT /v1/transactions/{tx}` | Replace the transaction's whole config with the JSON body | `200` |
| `GET` / `PUT` / `DELETE /v1/transactions/{tx}/{path}` | Read, set or remove one part of the config (see [the next section](#the-config-tree-as-urls)) | `200` / `200` / `204` |
| `GET /v1/transactions/{tx}/diff` | What committing would change | `200` |
| `POST /v1/transactions/{tx}/commit` | Validate and commit; `422` if invalid (the transaction stays open) | `200` `{"committed":"<tx>","warnings":[...]}` (advice, `[]` when none) |
| `DELETE /v1/transactions/{tx}` | Discard | `204` |

A full change, from opening to commit, adding a static route and linking it into `rt1`:

```sh
$ $C -X POST "$B/v1/transactions/doc1?base=current" -o /dev/null -w '%{http_code}\n'
201
$ $C -X PUT -H 'Content-Type: application/json' -d '{"name":"s1","routes":[]}' \
    $B/v1/transactions/doc1/static-routing-instance/s1
{"name":"s1","routes":[]}
$ $C -X PUT -H 'Content-Type: application/json' -d '{"subnet":"192.0.2.0/24","gateway":"10.50.0.3"}' \
    $B/v1/transactions/doc1/static-routing-instance/s1/route/192.0.2.0%2F24
{"gateway":"10.50.0.3","subnet":"192.0.2.0/24"}
$ $C -X PUT -H 'Content-Type: application/json' -d '"s1"' \
    $B/v1/transactions/doc1/routing-table/rt1/static-routing-instance
"s1"
$ $C $B/v1/transactions/doc1/diff | jq -c .static_routing_instances
[{"header":"static-routing-instance s1","name":"s1","status":"Added","fields":[],"subsections":[{"header":"route 192.0.2.0/24","name":"192.0.2.0/24","status":"Added","fields":[{"label":"gateway","old":null,"new":"10.50.0.3"}],"subsections":[]}]}]
$ $C -X POST $B/v1/transactions/doc1/commit
{"committed":"doc1","warnings":[]}
```

The diff lists every section. Each changed object carries a `status` (`Added`, `Removed`, `Modified`), its changed `fields` (each with `label`, `old`, `new`) and its changed `subsections`. This is the same diff the shell's `diff` command renders. Section headers and field labels are the CLI words (`bgp instance r1`, `route-reflector-client`), and every config field is diffed, so a commit that changes one field alone still produces an entry.

Committed changes are live, but not yet saved to disk: a restart loses them. To persist the running config to `/var/lib/nos/configd/config.yaml`, the same as the shell's `save`:

```sh
$ $C -X POST $B/v1/config/save -o /dev/null -w '%{http_code}\n'
204
```

- Saving writes the whole running config, including commits made from the shell or by other clients.
- A failed write (no config file configured, or a disk error) returns `502` with a problem document naming the cause.

## The config tree as URLs

Every part of the configuration has a URL under `/v1/transactions/{tx}/`, built from the same names the shell uses:

- **A section or field is its kebab-case name, in the singular.** `hostname`, `routing-table`, `bgp-instance`, `peer-group`, `static-routing-instance`, `lldp/tx-interval-secs`.
- **A list is followed by the key of one element.** Most lists are keyed by `name`. The exceptions are OSPF areas (`area-id`), BGP peers (`remote-address`), static routes (`subnet`), subinterfaces (`tag`), addresses (`address`), switching-profile members (`broadcast-domain`), prefix-list entries (`cidr`), crypto keys (`key-id`, `send-id`) and admin keys (`label`). Lists of plain values, such as an AS-path list's patterns, are keyed by the value itself.
- **Encode `/` inside a key as `%2F`**, for example a prefix: `route/192.0.2.0%2F24`. The server splits the path before decoding, so the encoded slash stays part of the key.
- **A `PUT` to a list element that does not exist appends it.** The key in the body must match the key in the URL.
- **Choose the place with a query parameter on that `PUT`:** `?first`, `?last`, `?before=<key>` or `?after=<key>`, where the key names a sibling in the same list (percent-encoded like any key). It applies to a new element (insert there) and to an existing one (move it: `PUT` the element's current body). Give at most one parameter; two, an unknown one, or an empty `before=`/`after=` is `400`. An unknown sibling is `404` and nothing changes. A `PUT` to a field, or to a whole list, takes none.
- **The body is the JSON form of that part of the config**, exactly as `GET` returns it: a string for `hostname`, an object for a routing table, and so on. Every schema is in the [OpenAPI document](#the-openapi-document).
- `diff` and `commit` are reserved: they are operations, never config sections.

Some paths on the example router, relative to `/v1/transactions/{tx}/`:

- `hostname` is `"edge-1"`.
- `routing-table/rt1` is the whole `rt1` object, and `routing-table/rt1/rest-api` is `{"address":"10.50.0.2","port":8080}`.
- `bgp-instance/r1/peer-group/pg1/hold-time` is `null`: not set, so the default applies.
- `interface/eth0/subinterface/0/address` is `[{"address":"10.50.0.2/24","label":null}]`.
- `static-routing-instance/s1/route/192.0.2.0%2F24` is `{"gateway":"10.50.0.3","subnet":"192.0.2.0/24"}`.
- `ospf-instance/o1/area/0.0.0.0/profile/p1` is one OSPF interface profile.
- `user/alice` is a user; a clear `password` sent in a `PUT` is hashed on the way in.
- `admin/key/bgp-1` is a keystore entry; its `secret` reads `<hidden>`.

A `DELETE` removes that part of the config, and a `GET` of a path that does not exist is `404`:

```sh
$ $C -i -X DELETE $B/v1/transactions/t2/static-routing-instance/s1/route/198.51.100.0%2F24
HTTP/2 204
etag: "2"
$ $C $B/v1/transactions/bad/no-such-section
{"type":"about:blank","title":"Not Found","status":404,"detail":"no such config path: /no-such-section"}
```

Like the shell's `set`/`delete`, none of this is validated until commit. The one check made immediately is that the edited config is still structurally valid JSON for the schema; a body with the wrong shape is refused with `400`.

## Pushing many items in few requests

Every request costs time proportional to the size of the whole transaction, so one request per static route does not scale (20k sequential per-route `PUT`s took about 692 s). Send a whole subsection or list instead:

- **`PUT` the whole list.** `PUT .../static-routing-instance/s1/route` with a JSON array of routes, or `PUT .../static-routing-instance/s1` with `{"name":"s1","routes":[...]}`. One request, one rebuild of the transaction.
- **A list `PUT` replaces the list.** Chunks do not append, so one `PUT` must carry every element of that list.
- **The body limit is 2 MiB.** A static route is about 65 bytes of JSON (IPv4; about 90 for IPv6), so one list holds about 25-30k routes. Past it the reply is `413` and nothing changes. Split a bigger set across several lists, for example several static routing instances, each its own `PUT`.
- **Order:** create the parent (`PUT .../static-routing-instance/s1` with an empty `routes`) before the list `PUT`, thread the `ETag` of each reply into the next `If-Match`, then commit once.
- `nos-e2e`'s `Router::edit` does this for the harness: a config that fits goes back in one `PUT`, a bigger one as whole-subsection `PUT`s (parent with its big lists emptied, then each list).

Measured on the lab router: 20k static routes in one batched edit plus commit took 0.27 s (`nos-restd` VmHWM 65 MB, `nos-configd` 173 MB).

## Secrets are write-only

- A `#[cli(secret)]` field (a user's `password`, an admin key's `secret`) is never returned: `GET /v1/config`, the transaction GET and the PUT reply all show it as `<hidden>`.
- Set one by sending a real value: `PUT /v1/transactions/{tx}/admin/key/bgp-1` with `{"label":"bgp-1","secret":"s3cret"}`.
- **GET-then-PUT is safe.** A `<hidden>` sent where an existing label or user already has a value keeps the stored value, so editing a GET'd document and PUTting it back does not destroy keys.
- `<hidden>` on a label or user that holds nothing is refused with `400`, and `<hidden>` is never accepted as a real secret.
- The values are stored in clear in `config.yaml` (mode 0600) because the daemons need them; `nos-configd` logs only the op's kind, never its payload.

## Concurrent edits: `ETag` and `If-Match`

Every response that describes a transaction carries its generation as a strong `ETag`, such as `"1"`. This applies to open, `GET`, a successful `PUT`, and a subsection `DELETE`. The generation is per transaction, not per path: any edit to the transaction changes it.

- Send **`If-Match: "<n>"`** on `PUT`, `DELETE`, `POST …/commit` or `GET` to make the request conditional. If the transaction has been edited since you read generation `n`, the request is refused with **412** and nothing changes. A refused commit leaves the transaction open.
- `If-Match` takes `*` or a comma-separated list (`"1", "3"`); it passes if any tag is the current generation. It uses strong comparison, so a weak tag (`W/"3"`) never matches. An opaque tag such as `"abc"` is valid and simply never matches (412). A missing transaction is 412 under any `If-Match`, 404 without one.
- Send **`If-None-Match: "<n>"`** on `GET` to get **304 Not Modified**, with no body, while the transaction is still at generation `n`. It takes `*` or a list and uses weak comparison, so `W/"1"` matches `"1"`.
- On `GET`, `If-Match` is checked first, then `If-None-Match`.
- Both are optional. Without them, the last write wins, which is also how the shell behaves.

```sh
$ $C -i -X PUT -H 'Content-Type: application/json' -H 'If-Match: "0"' -d '"edge-1"' $B/v1/transactions/doc1/hostname
HTTP/2 200
content-type: application/json
etag: "1"

"edge-1"
$ $C -i -X PUT -H 'Content-Type: application/json' -H 'If-Match: "0"' -d '"edge-2"' $B/v1/transactions/doc1/hostname
HTTP/2 412
content-type: application/problem+json

{"type":"about:blank","title":"Precondition Failed","status":412,"detail":"precondition failed: transaction generation is 1, not one of [0]"}
$ $C -i -H 'If-None-Match: "1"' $B/v1/transactions/doc1/hostname
HTTP/2 304
etag: "1"
```

The usual safe pattern for a script is: open the transaction and note its `ETag`; send each `PUT` with the latest `ETag` you received; commit with the final one. If anything else touched the transaction in between, you get a 412 instead of silently overwriting it.

## Actions

Some requests change live state without touching configuration:

`POST /v1/bgp/{instance}/peer/{peer}/soft-in` asks a peer to resend its routes (an RFC 2918 route refresh), like `clear bgp <instance> <peer> soft-in` in the shell. It answers `404` if the peer is not configured or its session is not Established, and `503` if the instance is not running or a local re-evaluation was superseded or aborted. For a peer-group with soft reconfiguration inbound nothing is sent: the reply is `"route_refresh":"none"` with a `reevaluated` list (`family`, `retained`, `accepted`).

```sh
$ $C -X POST $B/v1/bgp/r1/peer/10.50.0.3/soft-in
{"instance":"r1","peer":"10.50.0.3","route_refresh":"sent"}
```

`POST /v1/bgp/{instance}/peer/{peer}/clear` releases a peer held down by its maximum-prefix limit and resets its session if it is up, like `clear bgp <instance> <peer>`. It answers `404` if the peer is not configured.

```sh
$ $C -X POST $B/v1/bgp/r1/peer/10.50.0.3/clear
{"instance":"r1","peer":"10.50.0.3","cleared":true}
```

## Following the log (Server-Sent Events)

`GET /v1/logs/follow` is a [Server-Sent Events](https://html.spec.whatwg.org/multipage/server-sent-events.html) stream. It sends the existing entries first (the last `limit`, if given), then each new entry as it is logged, until you disconnect. Each entry is an `event: log`, whose `data` is one JSON log entry. Use `curl -N` so the output is not buffered:

```sh
$ $C -N "$B/v1/logs/follow?source=nos-configd&limit=1"
event: log
data: {"timestamp_ms":1790621603681,"level":"Debug","source":"nos-configd","target":"nos_pki::identity","message":"ipc tls handshake ok","fields":[["side","server"],["kx","X25519MLKEM768"],["peer_key","ML-DSA-65"]]}

event: log
data: {"timestamp_ms":1790621613661,"level":"Debug","source":"nos-configd",…}
```

The client certificate is checked when the stream opens, not again for each event.

## Errors

Every error response is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem document, `Content-Type: application/problem+json`:

```json
{"type":"about:blank","title":"Unprocessable Entity","status":422,"detail":"validation failed:\nrouting_tables[0].bgp_instance: referenced bgp instance does not exist\n"}
```

`title` is the HTTP reason phrase and `detail` says what went wrong. These are the status codes used:

- `400 Bad Request`: a malformed body, CSR or `If-Match`/`If-None-Match` syntax (unquoted, unterminated), or a body that does not fit the schema at that path.
- `401 Unauthorized`: no client certificate, or its user no longer exists. On `/v1/login`: wrong user or password.
- `404 Not Found`: no such transaction, config path, route, interface, peer, and so on.
- `405 Method Not Allowed`: the path exists, but not with this method. The `Allow` header lists what does.
- `412 Precondition Failed`: `If-Match` did not match the transaction's generation, or named a transaction that does not exist.
- `422 Unprocessable Entity`: validation refused the commit or the edit. The transaction stays open. Besides schema validation, three refusals map here:
  - a commit that would remove every user;
  - a commit with a syslog `tls trust-anchor` that is not a PEM certificate;
  - a `<hidden>` secret with no earlier value to keep, or more than 4 clear-text passwords in one edit (the `PUT`).
- `429 Too Many Requests`: too many failed logins for this user, or 32 transactions already open. See `Retry-After`.
- `502 Bad Gateway`: the router answered with something unexpected.
- `503 Service Unavailable`: a service the request needs is not running, or users cannot be checked right now.

## The OpenAPI document

Every route above, and every config-tree path with its JSON schema, is described by an OpenAPI 3 document:

- **In this repository**: [`openapi.json`](openapi.json). A test keeps this copy identical to what the code serves; `make docs-fix` regenerates it. You can open it in any OpenAPI viewer, such as editor.swagger.io.
- **On a running router**: `GET /openapi.json`, for example `$C $B/openapi.json`. It needs a client certificate like every other route.
- **Browsable**: `https://<address>:<port>/swagger-ui/`, an interactive explorer served by the router itself, with no internet access needed. A browser needs your REST client certificate and key installed, and `rest-ca.crt` trusted, before it can open it.

The document has 206 paths: the fixed routes listed on this page and one path per config-tree location (`/v1/transactions/{tx}/bgp-instance/{bgp_instance}/peer-group/{peer_group}/hold-time`, and so on). Use it as the complete field-level reference for request and response bodies.
