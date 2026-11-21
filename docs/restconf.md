# RESTCONF

RESTCONF (RFC 8040) over the running config, served by `nos-restd` next to `/v1` (#1176, part of #1173). Same listener, client certificate and user/role checks as `/v1`; RBAC applies per method through `nos-configd`.

## Scope

- JSON only (`application/yang-data+json`, `application/json` accepted); XML `Accept` gets 406.
- Running datastore only; no YANG-patch, no operations, no notifications, no `Last-Modified`.
- The data tree is [`yang/nos-config.yang`](yang/nos-config.yang): top-level nodes are the fields of `Config`.

## Paths

- `/restconf/data/nos-config:<node>[=<key>]/<node>[=<key>]...`; the first node carries the module prefix.
- `nos-config:config` is an alias for the whole config; bare `/restconf/data` is the same, wrapped as `ietf-restconf:data`.
- A list entry is `name=key`; exactly one key, percent-decoded after the split (`10.1.0.0%2F16`). Names resolve as in `nos_proto::config_path` (`bgp-instance` and `bgp_instances` both work).
- Example: `GET /restconf/data/nos-config:bgp-instance=main/peer=10.0.0.1`.

## Methods

| Method | Effect |
|--------|--------|
| GET, HEAD | Read; `depth`, `content=config\|nonconfig` (nonconfig: 204), `fields=a;b(c)`; secrets stay `<hidden>` |
| POST | Create the child in the body under the target: 201 + `Location`, 409 if it exists |
| PUT | Replace the target: 201 if created, 204 otherwise |
| PATCH | Merge into an existing target (RFC 7396 merge, `null` deletes a key, arrays replace): 204 |
| DELETE | 204, 404 if absent |
| OPTIONS | `Allow`, `Accept-Patch` |

- GET omits unset (`null`) leaves and the derived `#[cli(hidden)]` fields, so the document is valid instance data of the module (`nos_proto::yang::strip_hidden`; checked by the `restconf-conformance` phase, #1177).
- Bodies are `{"nos-config:<node>": value}`; a list entry is a one-element array.
- Each write is one implicit transaction (open on the current config, edit, commit). Any failure discards it, so none leaks.

## Concurrency

- `ETag` is a strong hash of the running config (quoted decimal); `If-None-Match` gives 304 on GET.
- `If-Match` is checked against the config the write's transaction opened on: 412 on mismatch, nothing changed. Concurrent commits are rebased by `nos-configd`.

## Errors

Body is `{"ietf-restconf:errors":{"error":[{"error-type","error-tag","error-message"}]}}`, rendered from the same `ApiError` as `/v1`:

| Status | error-tag |
|--------|-----------|
| 400, 406, 415 | invalid-value |
| 401, 403 | access-denied |
| 404 | missing-element |
| 409 | data-exists |
| 413 | too-big |
| 429 | resource-denied |
| 412, 422, 5xx | operation-failed |

Authentication failures (401) come from the shared client-certificate layer and stay `application/problem+json`.

## Discovery

- `GET /restconf`, `/restconf/yang-library-version`, `/restconf/data/ietf-yang-library:yang-library` (RFC 8525, module `nos-config` at the embedded revision).
- `GET /restconf/yang/nos-config.yang` serves the module; `GET /.well-known/host-meta` points at `/restconf`.
