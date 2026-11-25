//! `show config` / `show this`, generated from the same tree that parses
//! `set` (#116): the config's JSON is walked field by field through
//! `cli::root()` and written back in the CLI's own words, so a field the
//! grammar can enter is a field the output can show — no renderer names one.
//!
//! Layout: an indented hierarchy, each line the words relative to its parent
//! (`ospf instance o1` / `  router-id 1.1.1.1`). Only what is configured is
//! written: a field equal to its struct's `Default` is left out, which is also
//! what makes the output replayable (`cli/tests/render.rs` flattens it to
//! absolute `set` lines and feeds the grammar).
//!
//! A field the generic words can't spell (a keyed list inside an `Option`,
//! `ao-key …`) declares its own lines with `#[cli(render = …)]`; a secret
//! (`#[cli(secret)]`) is written as `<hidden>`.

use serde_json::Value;

use super::{field_spellings, root, variant_spellings, Field, Kind, Node, Payload};

/// The text standing in for a secret's value.
pub const HIDDEN: &str = "<hidden>";

/// One output line: its depth and its words.
pub type Line = (usize, String);

/// The whole config.
pub fn render_root(config: &Value) -> Vec<Line> {
    let node = root();
    let mut out = Vec::new();
    object(
        node.fields,
        node.default.map(|d| d()).as_ref(),
        config,
        0,
        &mut out,
    );
    out
}

/// Walks `path` (REST segments) to its node and value, with the last header
/// (`bgp instance r1`) and every header word on the way.
fn resolve<'a>(
    config: &'a Value,
    path: &[String],
) -> Option<(&'static Node, &'a Value, Option<String>, Vec<String>)> {
    let mut node = root();
    let mut value = config;
    let mut header = None;
    let mut prefix = Vec::new();
    let mut segs = path.iter();
    while let Some(seg) = segs.next() {
        let f = node.fields.iter().find(|f| segment(f) == *seg)?;
        value = value.get(f.name)?;
        match (f.kind)() {
            Kind::List(elem) => {
                let Kind::Struct(n) = elem() else { return None };
                let key = n.fields.iter().find(|k| k.key)?;
                let want = segs.next()?;
                value = value
                    .as_array()?
                    .iter()
                    .find(|e| words(&(key.kind)(), &e[key.name]).first() == Some(want))?;
                header = Some(format!("{} {want}", name(f)));
                prefix.extend([name(f), want.clone()]);
                node = n;
            }
            Kind::Struct(n) => {
                header = Some(name(f));
                prefix.push(name(f));
                node = n;
            }
            _ => return None,
        }
    }
    Some((node, value, header, prefix))
}

/// The object at `path` (REST segments), headed by its own words
/// (`bgp instance r1`) — `None` if nothing is there.
pub fn render_at(config: &Value, path: &[String]) -> Option<Vec<Line>> {
    let (node, value, header, _) = resolve(config, path)?;
    let mut out = Vec::new();
    let depth = usize::from(header.is_some());
    if let Some(h) = header {
        out.push((0, h));
    }
    object(
        node.fields,
        node.default.map(|d| d()).as_ref(),
        value,
        depth,
        &mut out,
    );
    Some(out)
}

/// The object at `path` as flat, absolute `set` lines (`| display set`):
/// each pasteable from the root. A secret is a `# ...` comment; a multi-line
/// text (a policy's source) is an `edit` block of `set source line <n>`.
/// Nothing at `path`: no lines.
pub fn render_set(config: &Value, path: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some((node, value, _, prefix)) = resolve(config, path) {
        set_object(
            node.fields,
            node.default.map(|d| d()).as_ref(),
            value,
            &prefix,
            &mut out,
        );
    }
    out
}

fn set_object(
    fields: &[Field],
    default: Option<&Value>,
    obj: &Value,
    prefix: &[String],
    out: &mut Vec<String>,
) {
    for f in fields.iter().filter(|f| !skipped(f)) {
        let v = &obj[f.name];
        if !is_unset(default, f, v) {
            set_field(f, v, prefix, out);
        }
    }
}

/// `set <prefix> <tail>`; a line that would carry a hidden value is a comment.
fn set_line(out: &mut Vec<String>, prefix: &[String], tail: &str) {
    let text = prefix
        .iter()
        .map(String::as_str)
        .chain(Some(tail).filter(|t| !t.is_empty()))
        .collect::<Vec<_>>()
        .join(" ");
    let lead = if text.contains(HIDDEN) { "#" } else { "set" };
    out.push(format!("{lead} {text}"));
}

fn set_field(f: &Field, v: &Value, prefix: &[String], out: &mut Vec<String>) {
    if f.secret {
        return set_line(out, prefix, &format!("{} {HIDDEN}", name(f)));
    }
    if let Some(render) = f.render {
        return render(v).iter().for_each(|l| set_line(out, prefix, l));
    }
    let kind = unwrap_option((f.kind)());
    let longer = |words: Vec<String>| [prefix, &words].concat();
    match &kind {
        Kind::List(elem) => match elem() {
            Kind::Struct(n) if n.fields.iter().any(|k| k.key) => {
                let key = n.fields.iter().find(|k| k.key).expect("checked above");
                for e in v.as_array().into_iter().flatten() {
                    let mut head = vec![name(f)];
                    head.extend(words(&(key.kind)(), &e[key.name]));
                    set_object(
                        n.fields,
                        n.default.map(|d| d()).as_ref(),
                        e,
                        &longer(head),
                        out,
                    );
                }
            }
            elem => {
                for e in v.as_array().into_iter().flatten() {
                    set_line(out, prefix, &join(name(f), words(&elem, e)));
                }
            }
        },
        Kind::Struct(n) if matches!((f.kind)(), Kind::Struct(_)) => set_object(
            n.fields,
            n.default.map(|d| d()).as_ref(),
            v,
            &longer(vec![name(f)]),
            out,
        ),
        Kind::Str if v.as_str().is_some_and(|s| s.contains('\n')) => {
            out.push(format!("edit {}", prefix.join(" ")));
            for (i, l) in v.as_str().into_iter().flat_map(str::lines).enumerate() {
                let text = if l.is_empty() {
                    String::new()
                } else {
                    format!(" {l}")
                };
                out.push(format!("set {} line {}{text}", name(f), i + 1));
            }
            out.push("top".to_string());
        }
        kind => set_line(out, prefix, &join(name(f), words(kind, v))),
    }
}

/// The lines as text, two spaces per depth.
pub fn indent(lines: &[Line]) -> String {
    lines
        .iter()
        .map(|(d, l)| format!("{:1$}{l}", "", d * 2))
        .collect::<Vec<_>>()
        .join("\n")
}

fn segment(f: &Field) -> String {
    let is_list = matches!((f.kind)(), Kind::List(_));
    crate::config_path::field_segment(f.name, is_list)
}

/// The canonical spelling of a field.
pub fn name(f: &Field) -> String {
    field_spellings(f).swap_remove(0)
}

/// A field that is never written: derived state, or the list key (it is in
/// its element's header).
fn skipped(f: &Field) -> bool {
    f.hidden || f.key
}

/// Equal to its struct's default (or, without one, null/false/empty).
fn is_unset(default: Option<&Value>, f: &Field, v: &Value) -> bool {
    match default {
        Some(d) => d.get(f.name) == Some(v),
        None => v.is_null() || *v == Value::Bool(false) || v.as_array().is_some_and(Vec::is_empty),
    }
}

fn object(
    fields: &[Field],
    default: Option<&Value>,
    obj: &Value,
    depth: usize,
    out: &mut Vec<Line>,
) {
    for f in fields.iter().filter(|f| !skipped(f)) {
        let v = &obj[f.name];
        if !is_unset(default, f, v) {
            field(f, v, depth, out);
        }
    }
}

fn push(out: &mut Vec<Line>, depth: usize, text: String) {
    out.push((depth, text));
}

fn field(f: &Field, v: &Value, depth: usize, out: &mut Vec<Line>) {
    if f.secret {
        return out.push((depth, format!("{} {HIDDEN}", name(f))));
    }
    if let Some(render) = f.render {
        return out.extend(render(v).into_iter().map(|l| (depth, l)));
    }
    let kind = unwrap_option((f.kind)());
    match &kind {
        Kind::List(elem) => match elem() {
            Kind::Struct(n) if n.fields.iter().any(|k| k.key) => {
                for e in v.as_array().into_iter().flatten() {
                    let key = n.fields.iter().find(|k| k.key).expect("checked above");
                    push(
                        out,
                        depth,
                        format!(
                            "{} {}",
                            name(f),
                            words(&(key.kind)(), &e[key.name]).join(" ")
                        ),
                    );
                    object(n.fields, n.default.map(|d| d()).as_ref(), e, depth + 1, out);
                }
            }
            elem => {
                for e in v.as_array().into_iter().flatten() {
                    push(out, depth, join(name(f), words(&elem, e)));
                }
            }
        },
        // A plain struct is a section; an optional one is set in one line.
        Kind::Struct(n) if matches!((f.kind)(), Kind::Struct(_)) => {
            let mut inner = Vec::new();
            object(
                n.fields,
                n.default.map(|d| d()).as_ref(),
                v,
                depth + 1,
                &mut inner,
            );
            if !inner.is_empty() {
                push(out, depth, name(f));
                out.extend(inner);
            }
        }
        // Text over several lines (a policy's source) is a block, not a word.
        Kind::Str if v.as_str().is_some_and(|s| s.contains('\n')) => {
            push(out, depth, name(f));
            for l in v.as_str().into_iter().flat_map(str::lines) {
                out.push((depth + 1, l.to_string()));
            }
        }
        kind => push(out, depth, join(name(f), words(kind, v))),
    }
}

fn join(head: String, words: Vec<String>) -> String {
    std::iter::once(head)
        .chain(words)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Strips any number of `Option` layers from `kind`.
pub fn unwrap_option(kind: Kind) -> Kind {
    match kind {
        Kind::Option(inner) => unwrap_option(inner()),
        k => k,
    }
}

/// The words that spell a value of `kind` (what `set <field> …` takes).
pub fn words(kind: &Kind, v: &Value) -> Vec<String> {
    match kind {
        Kind::Option(_) if v.is_null() => Vec::new(),
        Kind::Option(inner) => words(&inner(), v),
        Kind::Str | Kind::Ipv4 | Kind::IpAddr | Kind::IpNet => {
            vec![v.as_str().unwrap_or_default().to_string()]
        }
        Kind::Uint(_) => vec![v.to_string()],
        Kind::Tuple(parts) => parts
            .iter()
            .zip(v.as_array().into_iter().flatten())
            .flat_map(|(p, e)| words(&p(), e))
            .collect(),
        // A bool is its word alone; a list is never one value.
        Kind::Bool | Kind::List(_) => Vec::new(),
        Kind::Struct(n) => struct_words(n.fields, n.default.map(|d| d()).as_ref(), v),
        Kind::Enum(variants) => {
            let (tag, payload) = match v {
                Value::String(s) => (s.as_str(), &Value::Null),
                Value::Object(o) => o
                    .iter()
                    .next()
                    .map_or(("", &Value::Null), |(k, p)| (k.as_str(), p)),
                _ => return Vec::new(),
            };
            let Some(var) = variants.iter().find(|x| x.name == tag) else {
                return Vec::new();
            };
            let word = variant_spellings(var).swap_remove(0);
            let rest = match var.payload {
                Payload::Unit => Vec::new(),
                Payload::Newtype(k) => words(&k(), payload),
                Payload::Struct(fields) => struct_words(fields, None, payload),
            };
            std::iter::once(word).chain(rest).collect()
        }
    }
}

/// `first-required-field-bare key value key value …` — the inverse of the
/// grammar's `fields_value`. Without a `Default` to compare to (an enum
/// payload) every required field is written.
fn struct_words(fields: &[Field], default: Option<&Value>, obj: &Value) -> Vec<String> {
    let optional = |f: &Field| matches!((f.kind)(), Kind::Option(_) | Kind::List(_) | Kind::Bool);
    let bare = fields.iter().find(|f| !optional(f)).map(|f| f.name);
    let (mut first, mut out) = (Vec::new(), Vec::new());
    for f in fields.iter().filter(|f| !f.hidden) {
        let v = &obj[f.name];
        let kind = (f.kind)();
        let shown = Some(f.name) == bare
            || match default {
                Some(d) => d.get(f.name) != Some(v),
                None => !optional(f) || !(v.is_null() || *v == Value::Bool(false)),
            };
        if !shown {
            continue;
        }
        let value = if f.secret {
            vec![HIDDEN.to_string()]
        } else {
            words(&kind, v)
        };
        if Some(f.name) == bare {
            first = value;
        } else if !matches!(kind, Kind::List(_)) {
            out.push(name(f));
            out.extend(value);
        }
    }
    first.extend(out);
    first
}

#[cfg(test)]
#[allow(
    clippy::assert_is_empty,
    reason = "Vec<String> == [] is ambiguous to infer"
)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::cli::{default_json, Node, Variant};
    use crate::Config;

    const fn fld(name: &'static str, kind: fn() -> Kind) -> Field {
        Field {
            name,
            topic: None,
            hidden: false,
            secret: false,
            render: None,
            key: false,
            words: None,
            aliases: &[],
            sugar: &[],
            templates: &[],
            kind,
        }
    }

    fn s() -> Kind {
        Kind::Str
    }
    fn u() -> Kind {
        Kind::Uint(255)
    }
    fn b() -> Kind {
        Kind::Bool
    }
    fn opt_u() -> Kind {
        Kind::Option(u)
    }
    fn list_s() -> Kind {
        Kind::List(s)
    }

    static INNER: Node = Node {
        fields: &[fld("x", opt_u)],
        default: None,
    };
    fn k_inner() -> Kind {
        Kind::Struct(&INNER)
    }
    fn k_opt_inner() -> Kind {
        Kind::Option(k_inner)
    }

    const KEY: Field = Field {
        key: true,
        ..fld("name", s)
    };
    const HID: Field = Field {
        hidden: true,
        ..fld("derived", s)
    };
    const SEC: Field = Field {
        secret: true,
        ..fld("pw", s)
    };

    static ELEM: Node = Node {
        fields: &[KEY, HID, fld("n", u), fld("on", b), fld("opt", opt_u)],
        default: None,
    };
    fn k_elem() -> Kind {
        Kind::Struct(&ELEM)
    }
    fn list_elem() -> Kind {
        Kind::List(k_elem)
    }

    fn lines(fields: &[Field], default: Option<&Value>, v: &Value) -> Vec<Line> {
        let mut out = Vec::new();
        object(fields, default, v, 0, &mut out);
        out
    }

    fn l(d: usize, t: &str) -> Line {
        (d, t.to_string())
    }

    #[test]
    fn indent_is_two_spaces_per_depth() {
        let got = indent(&[l(0, "a"), l(1, "b"), l(2, "c")]);
        assert_eq!(got, "a\n  b\n    c");
    }

    #[test]
    fn object_skips_hidden_key_and_defaults() {
        let fields: &[Field] = &[KEY, HID, fld("n", u), fld("on", b), fld("opt", opt_u)];
        let all = json!({"name":"k","derived":"d","n":0,"on":true,"opt":3});
        assert_eq!(
            lines(fields, None, &all),
            [l(0, "n 0"), l(0, "on"), l(0, "opt 3")]
        );
        // No default: null and false are unset.
        let none = json!({"name":"k","derived":"d","n":7,"on":false,"opt":null});
        assert_eq!(lines(fields, None, &none), [l(0, "n 7")]);
        // With a default: equal is omitted, different shown, both directions.
        let d = json!({"n":5,"on":false,"opt":null});
        let same = json!({"n":5,"on":false,"opt":null});
        assert!(lines(fields, Some(&d), &same).is_empty());
        let diff = json!({"n":6,"on":true,"opt":null});
        assert_eq!(lines(fields, Some(&d), &diff), [l(0, "n 6"), l(0, "on")]);
        let d = json!({"n":5,"on":true,"opt":null});
        let off = json!({"n":5,"on":false,"opt":null});
        assert_eq!(lines(fields, Some(&d), &off), [l(0, "on")]);
    }

    #[test]
    fn object_empty_list_is_unset_without_default() {
        let fields: &[Field] = &[fld("tag_list", list_s)];
        assert!(lines(fields, None, &json!({"tag_list": []})).is_empty());
        assert_eq!(
            lines(fields, None, &json!({"tag_list": ["a","b"]})),
            [l(0, "tag-list a"), l(0, "tag-list b")]
        );
    }

    #[test]
    fn field_secret_render_and_scalar() {
        let mut out = Vec::new();
        field(&SEC, &json!("hunter2"), 2, &mut out);
        assert_eq!(out, [l(2, "pw <hidden>")]);

        let f = Field {
            render: Some(|v| vec![format!("a {v}"), "b".into()]),
            ..fld("r", s)
        };
        let mut out = Vec::new();
        field(&f, &json!(1), 1, &mut out);
        assert_eq!(out, [l(1, "a 1"), l(1, "b")]);

        let mut out = Vec::new();
        field(&fld("n", u), &json!(9), 3, &mut out);
        assert_eq!(out, [l(3, "n 9")]);
    }

    #[test]
    fn field_keyed_list_nests_children_one_deeper() {
        let f = fld("elems", list_elem);
        let v = json!([
            {"name":"a","derived":"x","n":1,"on":false,"opt":null},
            {"name":"b","derived":"x","n":0,"on":true,"opt":2},
        ]);
        let mut out = Vec::new();
        field(&f, &v, 1, &mut out);
        assert_eq!(
            out,
            [
                l(1, "elem a"),
                l(2, "n 1"),
                l(1, "elem b"),
                l(2, "n 0"),
                l(2, "on"),
                l(2, "opt 2"),
            ]
        );
    }

    #[test]
    fn field_unkeyed_struct_list_is_one_line_per_element() {
        fn plain() -> Kind {
            Kind::Struct(&INNER)
        }
        fn list_plain() -> Kind {
            Kind::List(plain)
        }
        let mut out = Vec::new();
        field(
            &fld("items", list_plain),
            &json!([{"x": 1}, {"x": 2}]),
            1,
            &mut out,
        );
        assert_eq!(out, [l(1, "item x 1"), l(1, "item x 2")]);
    }

    #[test]
    fn field_section_optional_struct_and_text_block() {
        let mut out = Vec::new();
        field(&fld("sec", k_inner), &json!({"x": 4}), 1, &mut out);
        assert_eq!(out, [l(1, "sec"), l(2, "x 4")]);

        // An empty section writes nothing at all.
        let mut out = Vec::new();
        field(&fld("sec", k_inner), &json!({"x": null}), 1, &mut out);
        assert!(out.is_empty());

        // An optional struct is one line of words, not a section.
        let mut out = Vec::new();
        field(&fld("sec", k_opt_inner), &json!({"x": 4}), 0, &mut out);
        assert_eq!(out, [l(0, "sec x 4")]);

        let mut out = Vec::new();
        field(&fld("src", s), &json!("one\ntwo"), 1, &mut out);
        assert_eq!(out, [l(1, "src"), l(2, "one"), l(2, "two")]);

        let mut out = Vec::new();
        field(&fld("src", s), &json!("one"), 1, &mut out);
        assert_eq!(out, [l(1, "src one")]);
    }

    #[test]
    fn words_of_scalars_and_options() {
        assert!(words(&Kind::Option(u), &Value::Null).is_empty());
        assert_eq!(words(&opt_u(), &json!(3)), ["3"]);
        assert_eq!(words(&Kind::Ipv4, &json!("1.1.1.1")), ["1.1.1.1"]);
        assert_eq!(words(&Kind::IpNet, &json!("10.0.0.0/8")), ["10.0.0.0/8"]);
        assert_eq!(words(&Kind::Str, &json!("a")), ["a"]);
        assert!(words(&Kind::Bool, &json!(true)).is_empty());
        assert!(words(&list_s(), &json!(["a"])).is_empty());
        assert_eq!(words(&Kind::Tuple(&[u, u]), &json!([1, 2])), ["1", "2"]);
        assert_eq!(words(&Kind::Tuple(&[u, s]), &json!([7, "z"])), ["7", "z"]);
    }

    static REC: &[Field] = &[
        fld("first", s),
        fld("opt", opt_u),
        fld("on", b),
        fld("second", s),
        SEC,
        Field {
            hidden: true,
            ..fld("hid", s)
        },
        fld("many", list_s),
    ];

    #[test]
    fn struct_words_bare_first_then_key_value() {
        let v =
            json!({"first":"x","opt":null,"on":true,"second":"y","pw":"p","hid":"h","many":["m"]});
        assert_eq!(
            struct_words(REC, None, &v),
            ["x", "on", "second", "y", "pw", HIDDEN]
        );
        let v = json!({"first":"x","opt":4,"on":false,"second":"y","pw":"p","hid":"h","many":[]});
        assert_eq!(
            struct_words(REC, None, &v),
            ["x", "opt", "4", "second", "y", "pw", HIDDEN]
        );
        // With a default only what differs is written; the bare field always.
        let d = json!({"first":"","opt":null,"on":false,"second":"y","pw":"p","hid":"h","many":[]});
        let v = json!({"first":"x","opt":null,"on":true,"second":"y","pw":"p","hid":"h","many":[]});
        assert_eq!(struct_words(REC, Some(&d), &v), ["x", "on"]);
        let v =
            json!({"first":"x","opt":null,"on":false,"second":"z","pw":"p","hid":"h","many":[]});
        assert_eq!(struct_words(REC, Some(&d), &v), ["x", "second", "z"]);
    }

    static VARIANTS: &[Variant] = &[
        Variant {
            name: "Plain",
            words: None,
            aliases: &[],
            default: true,
            payload: Payload::Unit,
        },
        Variant {
            name: "WithNum",
            words: Some("num"),
            aliases: &[],
            default: false,
            payload: Payload::Newtype(u),
        },
        Variant {
            name: "Rec",
            words: None,
            aliases: &[],
            default: false,
            payload: Payload::Struct(REC),
        },
    ];

    #[test]
    fn enum_words_by_payload() {
        let k = Kind::Enum(VARIANTS);
        assert_eq!(words(&k, &json!("Plain")), ["plain"]);
        assert_eq!(words(&k, &json!({"WithNum": 5})), ["num", "5"]);
        let rec = json!({"Rec":{"first":"x","opt":null,"on":true,"second":"y","pw":"p","hid":"h","many":[]}});
        assert_eq!(
            words(&k, &rec),
            ["rec", "x", "on", "second", "y", "pw", HIDDEN]
        );
        assert!(words(&k, &json!("Nope")).is_empty());
        assert!(words(&k, &json!(3)).is_empty());
        assert!(words(&k, &json!({})).is_empty());
    }

    fn cfg(f: impl FnOnce(&mut Value)) -> Value {
        let mut v = default_json::<Config>();
        f(&mut v);
        v
    }

    #[test]
    fn render_root_real_config() {
        assert!(render_root(&default_json::<Config>()).is_empty());
        let c = cfg(|v| {
            v["hostname"] = json!("r1");
            v["lldp"]["tx_interval_secs"] = json!(10);
            v["lldp"]["management_addresses"] = json!(["10.0.0.1"]);
            v["community_aliases"] = json!([{"name":"a1","value":"65000:1"}]);
            v["users"] = json!([{"name":"admin","password":"$argon2id$x","role":"Admin"}]);
        });
        assert_eq!(
            indent(&render_root(&c)),
            "community-alias a1\n  value 65000:1\nhostname r1\nlldp\n  tx-interval 10\n  management-address 10.0.0.1\nuser admin\n  password <hidden>"
        );
    }

    #[test]
    fn render_at_paths() {
        let c = cfg(|v| {
            v["lldp"]["tx_interval_secs"] = json!(10);
            v["community_aliases"] = json!([
                {"name":"a1","value":"65000:1"},
                {"name":"a2","value":"65000:2"},
            ]);
        });
        let p = |s: &[&str]| s.iter().map(|x| (*x).to_string()).collect::<Vec<_>>();
        assert_eq!(
            render_at(&c, &p(&["community-alias", "a2"])),
            Some(vec![l(0, "community-alias a2"), l(1, "value 65000:2")])
        );
        assert_eq!(
            render_at(&c, &p(&["lldp"])),
            Some(vec![l(0, "lldp"), l(1, "tx-interval 10")])
        );
        // Nothing there, or a scalar: no object to show.
        assert_eq!(render_at(&c, &p(&["community-alias", "zz"])), None);
        assert_eq!(render_at(&c, &p(&["community-alias"])), None);
        assert_eq!(render_at(&c, &p(&["hostname"])), None);
        assert_eq!(render_at(&c, &p(&["nope"])), None);
        // The empty path is the whole config, with no header.
        assert_eq!(render_at(&c, &[]), Some(render_root(&c)));
    }

    fn set_fields(fields: &[Field], default: Option<&Value>, v: &Value) -> Vec<String> {
        let mut out = Vec::new();
        set_object(fields, default, v, &[], &mut out);
        out
    }

    #[test]
    fn render_set_shapes() {
        let all = json!([{"name":"a","derived":"x","n":1,"on":true,"opt":2}]);
        let mut out = Vec::new();
        set_field(&fld("elems", list_elem), &all, &["top".into()], &mut out);
        assert_eq!(
            out,
            [
                "set top elem a n 1",
                "set top elem a on",
                "set top elem a opt 2"
            ]
        );
        let f: &[Field] = &[
            fld("sec", k_inner),
            fld("o", k_opt_inner),
            fld("l", list_s),
            SEC,
        ];
        let v = json!({"sec":{"x":4},"o":{"x":5},"l":["a","b"],"pw":"p"});
        assert_eq!(
            set_fields(f, None, &v),
            [
                "set sec x 4",
                "set o x 5",
                "set l a",
                "set l b",
                "# pw <hidden>"
            ]
        );
        assert!(set_fields(f, None, &json!({"sec":{"x":null}})).is_empty());
    }

    #[test]
    fn render_set_multiline_source_with_blank_line() {
        let mut out = Vec::new();
        let p = ["policy-definition".to_string(), "p".to_string()];
        set_field(&fld("source", s), &json!("a\n\nb"), &p, &mut out);
        assert_eq!(
            out,
            [
                "edit policy-definition p",
                "set source line 1 a",
                "set source line 2",
                "set source line 3 b",
                "top"
            ]
        );
    }

    #[test]
    fn render_set_real_config() {
        let c = cfg(|v| {
            v["hostname"] = json!("r1");
            v["lldp"]["tx_interval_secs"] = json!(10);
            v["community_aliases"] = json!([
                {"name":"a1","value":"65000:1"},
                {"name":"a2","value":"65000:2"},
            ]);
            v["users"] = json!([{"name":"admin","password":"$argon2id$x","role":"Admin"}]);
        });
        let p = |s: &[&str]| s.iter().map(|x| (*x).to_string()).collect::<Vec<_>>();
        let got = render_set(&c, &[]);
        assert_eq!(got.len(), 5, "{got:?}");
        assert_eq!(got[0], "set community-alias a1 value 65000:1");
        assert!(got.contains(&"set hostname r1".to_string()));
        assert!(got.contains(&"set lldp tx-interval 10".to_string()));
        assert!(got.contains(&"# user admin password <hidden>".to_string()));
        assert!(got.iter().all(|l| !l.contains("argon2")));
        assert_eq!(
            render_set(&c, &p(&["community-alias", "a2"])),
            ["set community-alias a2 value 65000:2"]
        );
        assert!(render_set(&c, &p(&["community-alias", "zz"])).is_empty());
        assert!(render_set(&default_json::<Config>(), &[]).is_empty());
    }

    #[test]
    fn unwrap_option_nests() {
        fn oo() -> Kind {
            Kind::Option(opt_u)
        }
        assert!(matches!(unwrap_option(oo()), Kind::Uint(255)));
    }
}
