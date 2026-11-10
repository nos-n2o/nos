# nos-proto — Shared Protocol Types

Single source of truth for all inter-process wire contracts in NOS.

## Why this crate exists

Component processes (`nos-bgp`, `nos-rib`, …) must not depend on `nos-config` internals — only on the shared types they exchange. By owning all shared types here, we get:
- **Protocol sync at compile time**: change a type → compiler breaks every consumer immediately.
- **Clean dependency graph**: components depend on `nos-proto`, not on each other.

## Contents

| Module | Purpose |
|--------|---------|
| `schema/` | Config tree types (`Config` and every section), `garde::Validate` for commit-time validation. Patterns and cross-validations per type: `docs/schema-reference.md`. |
| `cli` | The CLI's view of the schema (#109): `#[derive(Cli)]` (`nos-proto-derive`) builds a static tree from the real field types. Every struct field **must** carry `#[cli(...)]` (`topic = <Topic>`, `key`, or `hidden`) or the crate doesn't compile. A struct needs `Default` (a new element's starting point) unless `#[cli(no_default)]`; an enum's `#[default]` variant is what `delete` resets to. `secret` prints `<hidden>`; `render = path` gives a sugar-only field its `show config` lines. `cli::render` is the inverse of the grammar. `words`/`alias`/`sugar` catalogue: schema reference. |
| `derive` | `sync_routing_table_refs` recomputes every `BgpInstance.routing_table` from `RoutingTable.bgp_instance`. Pure; `nos-config` only. |
| `validators` | Reusable helpers (`unique_key_in`, `unique_addresses`, `routing_table_reference_valid`, `bfd_reference_valid`); cross-collection or type-specific checks live next to their schema type. |
| `ops/` | Section-scoped edit types (`BgpInstanceOp`, `RoutingTableOp`, …) wrapped by `ConfigOp`, applied to a transaction. Never validated; only `garde` at commit is. Nested ops carry the parent key; `SubinterfaceOp::AddAddress`/`SetRoutingTable` cascade-create the subinterface and its parent `Interface`. |
| `diff/` | Generated from the CLI tree (#116, `diff/generate.rs`): `diff_values` walks two JSON trees through `cli::root()`; `diff_configs` is its typed twin (#778, equal parts skipped with `==`, differential-tested); `diff_configs_for_role` re-diffs only `role_secrets`. `put` maps each `Config` field to a `ConfigDiff` slot. `REST_API_LABEL`/`VNI_LABEL` are the labels `nos-watchdogd` keys on (a test pins them to the CLI words). |
| `ipc`, `broker`, `rib`, `interface`, `bgp`, `log`, `ospf`, `lacp`, `lldp`, `stp`, `fdb` | Wire types per daemon family: `docs/ipc-protocols.md`. |
| `evpn_id` | RD/RT text ⇄ bytes, ESI, EVPN extended communities, `vxlan_name`; RFC detail in the function docs and the schema reference. |
| `config_path` | URL-style addressing of a config subsection, shared by `nos-config` and `nos-restd`. `ELEMENT_KEYS` must be extended for a new list keyed by another field; `field_segment`/`key_field`/`field_matches` are shared with the OpenAPI generator, so spec and behaviour can't drift. The `openapi` feature adds `utoipa::ToSchema` (`IpAddr`/`IpNet` need `schema(value_type = String)`, recursive `SectionDiff.subsections` `schema(no_recursion)`). |
| `version` | `VERSION`/`REVISION` (`build.rs` bakes `NOS_BUILD_REV`), `VersionInfo` for `show version`/`GET /v1/version`. |
| `paths` | The two bootstrap socket defaults that stay fixed (config, watchdog) plus the PKI ones. |
| `page` | Opaque keyset cursors (#714): `encode`/`decode`, `wire_len`. |
| `codec` | `IpcCodec<T>`: 4-byte LE length prefix + postcard payload, generic over any `Serialize + DeserializeOwned`. |

## Schema pitfalls

- `#[serde(default)]` on every field added after release, or an old `config.yaml` no longer loads.
- `#[garde(skip)]` on derived and unconstrained fields. `BgpInstance.routing_table` is derived: never touched by an op, never on a transaction's in-progress config.
- "One Linux master per link": a physical `Interface` has no flat `addresses`/`routing_table`, `Subinterface` tags and `switching_profile` member tags are disjoint, a member of a `port_aggregate` has neither (`valid_addressing_split`, `valid_subinterface_and_switching_profile_tags`, `valid_port_aggregate_membership`).
- Loopback = `Interface.name` starting `loopback-` (`LOOPBACK_PREFIX`); names may not contain `.`, which is reserved for `<interface>.<tag>`.
- `OspfProfile.name` is unique across every instance's every area, since attach points reference it by bare name; each `ospf_profile` attach point also needs a `routing_table`.
- A new keyed list needs its key in `config_path::ELEMENT_KEYS` and `#[cli(key)]`.
- Secrets (#507): `Config.admin` keystore; a secret field is `#[cli(secret)]` plus a `Debug` that hides it, and `Config::redacted()` then masks it for REST. Ops are logged by `ConfigOp::kind()`, never `?op`.
- ACL (#540): `schema/acl.rs`; `AclProtocol`/`PortRange` are text scalars (`Kind::Str`). Compiled by `nos-acld` (#541).
- STP (#316): `Config.spanning_tree` is a singleton (field-level diff, no op), `stp_port_profiles` a keyed section; the commit checks live in `schema/spanning_tree.rs`, the ESI-needs-a-guard-profile rule in `valid_port_aggregates`.
- Wire semantics worth remembering: `Interfaces`/`Log`/`Lacp`/`Lldp` `ServiceRef`s carry no name (one instance each); `PushBgpRoutes`/`PushLacpMembers` are fire-and-forget; `GetVrfName` was the first daemon-to-daemon link; EVPN routes cross the wire structured (proto can't depend on `nos-bgp`); `BgpSessionState::Idle` is reporting-only.

## Wire format

```
┌──────────────┬──────────────────────────┐
│ 4-byte LE u32│ postcard-encoded payload  │
│  (length)    │  (Request or Event enum)  │
└──────────────┴──────────────────────────┘
```

Use `IpcCodec<T>` with `tokio_util::codec::{FramedRead, FramedWrite}` to get typed async send/recv over a `UnixStream`.

## Adding a new config section

1. Add the new struct in `schema/` deriving `Serialize, Deserialize, garde::Validate, Default, Cli`, with a `#[cli(...)]` on every field — a new `Topic` in `docs.rs` (text in `nos-config`'s `docs.rs`) for each field that needs its own help. The shell's `edit`/`set`/`delete` then reach it with no CLI code.
2. Add `#[garde(context(Config as ctx))]` and use the context for any cross-references.
3. Add the field to `Config` in `schema/mod.rs` with `#[garde(dive)]`.
4. Add a sibling `<Section>Op` enum in `ops/<section>.rs` with a synchronous `apply(&self, config: &mut Config) -> Result<(), OpError>` (create/update/delete by name, no `garde` validation — that only runs at commit), then add a `ConfigOp` variant wrapping it in `ops/mod.rs`.
5. Re-export from `lib.rs` if it's part of the public API.

## Adding a scalar top-level field

For a single always-present scalar with exactly one possible edit (e.g. `hostname`), skip the dedicated `<Section>Op` enum and file — that convention exists to give named/keyed collections per-name create/update/delete semantics, which a lone scalar doesn't need:

1. Add the field directly to `Config` in `schema/mod.rs` with its own `#[garde(...)]` rule(s). If the desired default isn't the field type's own `Default::default()` (e.g. `hostname` defaults to `"nos"`, not `""`), add `#[serde(default = "some_fn")]` on the field — required so pre-existing on-disk config missing that key still deserializes — and give `Config` a manual `impl Default` instead of deriving it.
2. Add one `ConfigOp` variant directly in `ops/mod.rs`'s enum (e.g. `SetHostname(String)`), with an `apply` arm that sets the field. No new `OpError` variant needed unless the edit can fail structurally.

## Wire compatibility

`Request`/`Event` variants must always be **appended**, never inserted or reordered — `postcard` encodes enum variants by index, so reordering breaks compatibility with already-built binaries.

Details: [schema reference](../docs/schema-reference.md), [IPC protocols](../docs/ipc-protocols.md).

- `missing_docs` is on for all of `nos-proto`: document every new pub item (variant fields included, #428).
