# YANG module

`nos-config.yang` is the YANG 1.1 (RFC 7950) module of the config tree, generated from the `nos-proto` schema (#1174, part of #1173). It is the contract the RESTCONF facade (#1173) will serve.

## How it is built

- `nos_proto::yang::render(describe)` walks the CLI's schema tree (`nos_proto::cli::root`, from `#[derive(Cli)]`), not a second reflection mechanism.
- Node names are the serde (JSON) keys; top-level nodes are the fields of `Config`; fields marked `#[cli(hidden)]` are skipped.
- Descriptions are the `summary` of each field's `#[cli(topic)]` help text in `nos-config` (single source).
- Type mapping table: module docs of `proto/src/yang/mod.rs`.

## What it does not say

- `garde` rules (length, range, pattern, cross-field and cross-collection checks) are not expressed; the daemon's commit validation stays authoritative.
- References (peer-group, policy, routing-table) are plain `string`: the schema does not name their targets, so there is no `leafref`.
- Enums with payloads are a `container` with a `choice` (serde's externally tagged shape); a unit variant inside such an enum is a `leaf` of type `empty`.
- On RESTCONF that unit variant is `{"X":[null]}` (RFC 7951 `empty`), in reads and writes; on `/v1` and in the store it stays serde's bare string `"X"` (#1300).

## Changing the schema

- Run `make docs-fix` to regenerate `nos-config.yang`.
- Bump `YANG_REVISION` in `proto/src/yang/mod.rs`, then set `RECORDED_HASH` in `config/tests/yang_snapshot.rs` to the hash the test prints.
- `cargo test -p nos-config --test yang_snapshot` fails on a stale file or a missing bump.
- Validation by a real YANG compiler is a separate step (#1173, sub-issue 3).
