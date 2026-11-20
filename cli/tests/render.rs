//! `show config` can't miss a field (#116): the schema's CLI tree builds a
//! config in which **every** field holds a non-default value, the generated
//! rendering of it is flattened to absolute `set …` lines, and replaying
//! those through the grammar onto an empty config must give the same config
//! back. A field that renders wrongly, ambiguously or not at all fails here,
//! and the sample is generated from the tree too, so a new field is covered
//! with no fixture to forget.

use nos_cli::config_grammar;
use nos_proto::cli::render::{render_root, HIDDEN};
use nos_proto::cli::{self, Kind, Node, Payload};
use nos_proto::{config_path, Config};
use serde_json::{json, Map, Value};

struct Gen {
    n: u64,
    round: usize,
}

impl Gen {
    fn next(&mut self) -> u64 {
        self.n += 1;
        self.n
    }

    fn node(&mut self, node: &Node) -> Value {
        let default = node.default.map(|d| d());
        let mut obj = default.clone().unwrap_or_else(|| json!({}));
        for f in node.fields {
            let d = default.as_ref().and_then(|d| d.get(f.name));
            obj[f.name] = if f.hidden {
                d.cloned().unwrap_or(Value::Null)
            } else if f.secret {
                json!(HIDDEN)
            } else {
                self.value(&(f.kind)(), d)
            };
        }
        obj
    }

    fn value(&mut self, kind: &Kind, default: Option<&Value>) -> Value {
        let n = self.next();
        match kind {
            Kind::Str => json!(format!("s{n}")),
            Kind::Bool => json!(default.and_then(Value::as_bool) != Some(true)),
            Kind::Uint(max) => {
                let v = (n % 100 + 2).min(*max);
                json!(if default == Some(&json!(v)) { v - 1 } else { v })
            }
            Kind::Ipv4 | Kind::IpAddr => json!(format!("10.0.{}.{}", n % 200, n % 250 + 1)),
            Kind::IpNet => json!(format!("10.{}.0.0/16", n % 200)),
            Kind::Tuple(parts) => Value::Array(
                parts
                    .iter()
                    .enumerate()
                    .map(|(i, p)| match p() {
                        Kind::Uint(_) => json!(10 + 10 * i as u64 + n % 5),
                        k => self.value(&k, None),
                    })
                    .collect(),
            ),
            Kind::Option(inner) => self.value(&inner(), None),
            Kind::List(elem) => {
                Value::Array(vec![self.value(&elem(), None), self.value(&elem(), None)])
            }
            Kind::Struct(node) => self.node(node),
            Kind::Enum(variants) => {
                let others: Vec<_> = variants
                    .iter()
                    .filter(|v| default != Some(&json!(v.name)))
                    .collect();
                let pool = if others.is_empty() {
                    variants.iter().collect()
                } else {
                    others
                };
                let v = pool[(self.round + usize::try_from(n).unwrap()) % pool.len()];
                match v.payload {
                    Payload::Unit => json!(v.name),
                    Payload::Newtype(k) => json!({ v.name: self.value(&k(), None) }),
                    Payload::Struct(fields) => {
                        let mut o = Map::new();
                        for f in fields {
                            o.insert(f.name.into(), self.value(&(f.kind)(), None));
                        }
                        json!({ v.name: o })
                    }
                }
            }
        }
    }
}

/// What the sample can't know: the sugar's rules (one current, one rnext
/// key per key list) and the interface split (a loopback keeps its L3 config
/// flat, a physical interface only has subinterfaces).
fn fix(v: &mut Value) {
    match v {
        Value::Object(o) => o.values_mut().for_each(fix),
        Value::Array(a) => {
            for (i, k) in a.iter_mut().enumerate() {
                for (flag, pos) in [("is_current", 0), ("is_rnext", 1)] {
                    if k.get(flag).is_some() {
                        k[flag] = json!(i == pos);
                    }
                }
                fix(k);
            }
        }
        _ => {}
    }
}

fn fix_interfaces(config: &mut Value) {
    for (i, iface) in config["interfaces"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        if i == 0 {
            iface["name"] = json!("loopback-rt1");
            iface["subinterfaces"] = json!([]);
        } else {
            iface["addresses"] = json!([]);
            for f in ["routing_table", "ospf_profile"] {
                iface[f] = Value::Null;
            }
            iface["ospfv3_profiles"] = json!([]);
        }
    }
}

/// Indented lines → absolute `set` lines, leaves only (a header with
/// children is created by them; a header alone is an element to create).
fn flatten(lines: &[(usize, String)]) -> Vec<String> {
    let mut stack: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for (i, (d, l)) in lines.iter().enumerate() {
        stack.truncate(*d);
        stack.push(l);
        if lines.get(i + 1).is_none_or(|(next, _)| next <= d) {
            out.push(format!("set {}", stack.join(" ")));
        }
    }
    out
}

fn replay(lines: &[String]) -> Value {
    let mut doc = serde_json::to_value(Config::default()).unwrap();
    for line in lines {
        let edit = config_grammar::parse(line, &[], &doc)
            .unwrap_or_else(|| panic!("the grammar refuses what show config printed: {line}"));
        for (path, value) in edit.writes {
            config_path::set(&mut doc, &path, value).unwrap();
        }
    }
    doc
}

fn first_diff(at: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for (k, v) in x {
                first_diff(
                    &format!("{at}/{k}"),
                    v,
                    y.get(k).unwrap_or(&Value::Null),
                    out,
                );
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (v, w)) in x.iter().zip(y).enumerate() {
                first_diff(&format!("{at}/{i}"), v, w, out);
            }
        }
        _ if a != b => out.push(format!("DIFF {at}: sample {a} vs replay {b}")),
        _ => {}
    }
}

#[test]
fn every_field_survives_show_config_and_back() {
    for round in 0..6 {
        let mut g = Gen { n: 0, round };
        let mut sample = g.node(cli::root());
        fix(&mut sample);
        fix_interfaces(&mut sample);
        let lines = flatten(&render_root(&sample));
        let back = replay(&lines);
        if back != sample {
            let mut diffs = Vec::new();
            first_diff("", &sample, &back, &mut diffs);
            panic!(
                "round {round}: replaying `show config` doesn't rebuild the config\n{}\n{}",
                diffs.join("\n"),
                lines.join("\n")
            );
        }
    }
}

/// Every field's change wakes its daemons (#116): mutate each non-hidden
/// field of the sample (at the root, and inside the first element of every
/// list and struct), and the diff must be non-empty and name the field.
fn mutate(node: &Node, path: &[String], sample: &Value, at: &Value, count: &mut usize) {
    for f in node.fields.iter().filter(|f| !f.hidden && !f.key) {
        let cur = &at[f.name];
        let mut generator = Gen { n: 1000, round: 3 };
        let mut new = generator.value(&(f.kind)(), None);
        if new == *cur {
            new = Value::Null;
        }
        let mut cfg = sample.clone();
        let mut target = path.to_vec();
        target.push(f.name.to_string());
        set_at(&mut cfg, &target, new);
        let diff = nos_proto::diff::diff_values(sample, &cfg);
        let label = cli::render::name(f);
        let text = format!("{diff:?}");
        assert!(
            !diff.is_empty() && text.contains(&label),
            "changing {} ({label}) is not in the diff: {text}",
            target.join("/")
        );
        *count += 1;
        // Only a plain struct and a keyed list show their inner fields; an
        // optional struct (or an unkeyed list) is one field, named as a whole.
        let (inner, list) = match (f.kind)() {
            Kind::Struct(sub) => (Some(sub), false),
            Kind::List(e) => match e() {
                Kind::Struct(sub) if sub.fields.iter().any(|k| k.key) => (Some(sub), true),
                _ => (None, true),
            },
            _ => (None, false),
        };
        let child = if list { cur.get(0) } else { Some(cur) };
        if let (Some(sub), Some(child)) = (inner, child.filter(|c| c.is_object())) {
            let mut inner_path = target.clone();
            if list {
                inner_path.push("0".into());
            }
            mutate(sub, &inner_path, sample, child, count);
        }
    }
}

fn set_at(v: &mut Value, path: &[String], new: Value) {
    let (head, rest) = path.split_first().unwrap();
    let slot = match v {
        Value::Array(a) => &mut a[head.parse::<usize>().unwrap()],
        _ => &mut v[head.as_str()],
    };
    if rest.is_empty() {
        *slot = new;
    } else {
        set_at(slot, rest, new);
    }
}

#[test]
fn every_field_change_is_in_the_diff() {
    let mut g = Gen { n: 0, round: 0 };
    let mut sample = g.node(cli::root());
    fix(&mut sample);
    fix_interfaces(&mut sample);
    let mut n = 0;
    mutate(cli::root(), &[], &sample, &sample.clone(), &mut n);
    assert!(n > 150, "only {n} fields mutated");
}

#[test]
fn an_empty_config_shows_nothing_but_what_differs_from_default() {
    let json = serde_json::to_value(Config::default()).unwrap();
    assert_eq!(render_root(&json), Vec::new());
}
