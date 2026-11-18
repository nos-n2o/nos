//! YANG 1.1 (RFC 7950) rendering of the config schema (#1174, part of #1173).
//!
//! The generator walks the same static tree as the CLI (`crate::cli::root`,
//! built by `#[derive(Cli)]`): there is no second reflection mechanism. The
//! module's top-level data nodes are the fields of `Config`, named exactly
//! as their serde (JSON) keys.
//!
//! | Schema (`cli::Kind`)          | YANG                                              |
//! |-------------------------------|---------------------------------------------------|
//! | `Str`                         | `string`                                          |
//! | `Bool`                        | `boolean`                                         |
//! | `Uint(max)`                   | `uint8` / `uint16` / `uint32` / `uint64`          |
//! | `Ipv4` / `IpAddr` / `IpNet`   | `inet:ipv4-address` / `inet:ip-address` / `inet:ip-prefix` (imports `ietf-inet-types`) |
//! | `Tuple`                       | `string` (the CLI's `a.b` text form)              |
//! | `Option<T>`                   | the node of `T` (every node is non-mandatory)     |
//! | `List` of keyed struct        | `list` with `key` (`config_path::ELEMENT_KEYS`)     |
//! | `List` of scalar              | `leaf-list`                                       |
//! | struct                        | `container`                                       |
//! | enum of unit variants         | `enumeration` of the serde names                  |
//! | enum with payloads            | `container` holding a `choice`, one `case` per variant (serde's externally tagged JSON) |
//!
//! Descriptions come from the caller's `describe` closure (the help text is
//! authored once, in `nos-config`; this crate only knows the `Topic`).
//!
//! Not expressible, left to the daemon's commit-time validation (which stays
//! authoritative): every `garde` rule (length, range, patterns, cross-field
//! and cross-collection checks). The schema does not name reference targets
//! either, so peer-group / policy / routing-table references are plain
//! `string`, not `leafref`.

use std::fmt::Write;

use crate::cli::{self, Field, Kind, Payload};
use crate::Topic;

/// Revision date of the generated module. Bump it whenever the schema (or a
/// help text) changes: `nos-config`'s `yang_snapshot` test pins a hash of the
/// output and fails until the bump is recorded.
pub const YANG_REVISION: &str = "2026-11-20";

/// Maximum nesting rendered; the schema is a finite tree, so hitting it is a bug.
const MAX_DEPTH: usize = 32;

/// The whole `nos-config` YANG module; `describe` gives a topic's one-line text.
pub fn render(describe: &dyn Fn(Topic) -> String) -> String {
    let mut out = String::new();
    out.push_str("module nos-config {\n  yang-version 1.1;\n");
    out.push_str("  namespace \"urn:nos:params:xml:ns:yang:nos-config\";\n  prefix nos;\n\n");
    out.push_str("  import ietf-inet-types {\n    prefix inet;\n  }\n\n");
    out.push_str(
        "  description\n    \"NOS configuration tree, generated from the nos-proto schema.\";\n\n",
    );
    let _ = writeln!(
        out,
        "  revision {YANG_REVISION} {{\n    description \"Generated.\";\n  }}\n"
    );
    fields(&mut out, cli::root().fields, 1, describe);
    out.push_str("}\n");
    out
}

fn pad(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn quote(s: &str) -> String {
    let s = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ");
    format!("\"{s}\"")
}

fn fields(out: &mut String, fs: &[Field], depth: usize, describe: &dyn Fn(Topic) -> String) {
    for f in fs.iter().filter(|f| !f.hidden) {
        let desc = f.topic.map(describe);
        node(out, f.name, desc.as_deref(), &(f.kind)(), depth, describe);
    }
}

fn leaf_type(k: &Kind) -> &'static str {
    match k {
        Kind::Bool => "boolean",
        Kind::Uint(m) if *m <= u8::MAX.into() => "uint8",
        Kind::Uint(m) if *m <= u16::MAX.into() => "uint16",
        Kind::Uint(m) if *m <= u32::MAX.into() => "uint32",
        Kind::Uint(_) => "uint64",
        Kind::Ipv4 => "inet:ipv4-address",
        Kind::IpAddr => "inet:ip-address",
        Kind::IpNet => "inet:ip-prefix",
        _ => "string",
    }
}

fn desc_stmt(out: &mut String, desc: Option<&str>, depth: usize) {
    if let Some(d) = desc {
        pad(out, depth);
        let _ = writeln!(out, "description {};", quote(d));
    }
}

fn open(out: &mut String, depth: usize, stmt: &str, name: &str) {
    pad(out, depth);
    let _ = writeln!(out, "{stmt} {name} {{");
}

fn close(out: &mut String, depth: usize) {
    pad(out, depth);
    out.push_str("}\n");
}

/// One data node named `name` for a value of kind `kind`.
fn node(
    out: &mut String,
    name: &str,
    desc: Option<&str>,
    kind: &Kind,
    depth: usize,
    describe: &dyn Fn(Topic) -> String,
) {
    assert!(depth < MAX_DEPTH, "recursive schema at {name}");
    let ind = depth + 1;
    match kind {
        Kind::Option(inner) => node(out, name, desc, &inner(), depth, describe),
        Kind::Struct(n) => {
            open(out, depth, "container", name);
            desc_stmt(out, desc, ind);
            fields(out, n.fields, ind, describe);
            close(out, depth);
        }
        Kind::List(inner) => match unwrap_option(inner()) {
            Kind::Struct(n) => {
                open(out, depth, "list", name);
                if let Some(k) = element_key(n.fields) {
                    pad(out, ind);
                    let _ = writeln!(out, "key {};", quote(k));
                }
                desc_stmt(out, desc, ind);
                fields(out, n.fields, ind, describe);
                close(out, depth);
            }
            other => {
                open(out, depth, "leaf-list", name);
                pad(out, ind);
                let _ = writeln!(out, "type {};", leaf_type(&other));
                desc_stmt(out, desc, ind);
                close(out, depth);
            }
        },
        Kind::Enum(vs) if vs.iter().all(|v| matches!(v.payload, Payload::Unit)) => {
            open(out, depth, "leaf", name);
            pad(out, ind);
            out.push_str("type enumeration {\n");
            for v in *vs {
                pad(out, ind + 1);
                let _ = writeln!(out, "enum {};", quote(v.name));
            }
            close(out, ind);
            desc_stmt(out, desc, ind);
            close(out, depth);
        }
        Kind::Enum(vs) => {
            open(out, depth, "container", name);
            desc_stmt(out, desc, ind);
            open(out, ind, "choice", "variant");
            for v in *vs {
                open(out, ind + 1, "case", v.name);
                match &v.payload {
                    Payload::Unit => {
                        open(out, ind + 2, "leaf", v.name);
                        pad(out, ind + 3);
                        out.push_str("type empty;\n");
                        close(out, ind + 2);
                    }
                    Payload::Newtype(k) => node(out, v.name, None, &k(), ind + 2, describe),
                    Payload::Struct(fs) => {
                        open(out, ind + 2, "container", v.name);
                        fields(out, fs, ind + 3, describe);
                        close(out, ind + 2);
                    }
                }
                close(out, ind + 1);
            }
            close(out, ind);
            close(out, depth);
        }
        scalar => {
            open(out, depth, "leaf", name);
            pad(out, ind);
            let _ = writeln!(out, "type {};", leaf_type(scalar));
            desc_stmt(out, desc, ind);
            close(out, depth);
        }
    }
}

/// The REST/`ELEMENT_KEYS` identity of a list element (what `config_path` addresses it by).
fn element_key(fs: &[Field]) -> Option<&'static str> {
    crate::config_path::key_field(fs.iter().map(|f| f.name))
}

fn unwrap_option(k: Kind) -> Kind {
    match k {
        Kind::Option(i) => unwrap_option(i()),
        k => k,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_deterministically_with_expected_shapes() {
        let a = render(&|t| format!("{t:?}"));
        assert_eq!(a, render(&|t| format!("{t:?}")));
        assert!(a.starts_with("module nos-config {\n  yang-version 1.1;"));
        assert!(a.contains("  leaf hostname {\n    type string;\n    description \"Hostname\";"));
        assert!(a.contains("list users {\n    key \"name\";"));
        assert!(a.contains("inet:ip-prefix"));
        assert!(a.contains("type enumeration {"));
        assert!(a.contains("choice variant {"));
        assert_eq!(a.matches('{').count(), a.matches('}').count());
    }

    #[test]
    fn every_struct_list_has_a_key() {
        fn walk(k: &Kind, path: &str) {
            match k {
                Kind::Option(i) => walk(&i(), path),
                Kind::List(i) => {
                    if let Kind::Struct(n) = unwrap_option(i()) {
                        assert!(
                            element_key(n.fields).is_some(),
                            "{path}: list without an ELEMENT_KEYS key"
                        );
                    }
                    walk(&i(), path);
                }
                Kind::Struct(n) => n
                    .fields
                    .iter()
                    .for_each(|f| walk(&(f.kind)(), &format!("{path}/{}", f.name))),
                Kind::Enum(vs) => vs.iter().for_each(|v| match &v.payload {
                    Payload::Newtype(k) => walk(&k(), path),
                    Payload::Struct(fs) => fs.iter().for_each(|f| walk(&(f.kind)(), path)),
                    Payload::Unit => {}
                }),
                _ => {}
            }
        }
        walk(&Kind::Struct(cli::root()), "");
    }
}
