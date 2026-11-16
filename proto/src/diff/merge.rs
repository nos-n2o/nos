//! Schema-guided 3-way merge of `Config` (#1033): `ours` (a transaction) and
//! `theirs` (the running config) both descend from `base`. Walks the JSON of
//! the three through `cli::root()`, like the diff, so no field is named here
//! and a new one lands in a rule by its type alone.
//!
//! - struct (and `Option<struct>` present on all sides): per field;
//! - keyed list of structs: elements matched by key, a change to one element
//!   never conflicts with a change to another;
//! - anything else (scalar, enum, scalar or unkeyed list, secret, `render`
//!   field, a list with a duplicate key): one atomic leaf;
//! - hidden (derived) fields: always `theirs`.
//!
//! A conflict is only the same path changed on both sides.

#![allow(
    clippy::many_single_char_names,
    reason = "b/o/t are base/ours/theirs throughout"
)]

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde_json::{Map, Value};

use crate::cli::render::unwrap_option;
use crate::cli::{root, Field, Kind, Node};
use crate::config_path::field_segment;
use crate::Config;

use super::walk::key_of;

/// A path both sides changed differently, in `config_path` segment form
/// (`bgp-instance/r1/peer/10.0.0.1/description`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeConflict {
    /// The path's segments.
    pub path: Vec<String>,
}

impl fmt::Display for MergeConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.path.join("/"))
    }
}

/// Merges `ours` and `theirs`, both derived from `base`. Every conflict is
/// reported, not just the first.
pub fn merge_configs(
    base: &Config,
    ours: &Config,
    theirs: &Config,
) -> Result<Config, Vec<MergeConflict>> {
    if ours == base {
        return Ok(theirs.clone());
    }
    if theirs == base || ours == theirs {
        return Ok(ours.clone());
    }
    let obj = |c: &Config| match serde_json::to_value(c).expect("a config serializes") {
        Value::Object(m) => m,
        _ => unreachable!("a config is an object"),
    };
    let mut conflicts = Vec::new();
    let merged = strukt(
        root(),
        &mut Vec::new(),
        &obj(base),
        &obj(ours),
        &obj(theirs),
        &mut conflicts,
    );
    if !conflicts.is_empty() {
        return Err(conflicts);
    }
    serde_json::from_value(Value::Object(merged))
        .map_err(|_| vec![MergeConflict { path: Vec::new() }])
}

fn strukt(
    n: &Node,
    path: &mut Vec<String>,
    b: &Map<String, Value>,
    o: &Map<String, Value>,
    t: &Map<String, Value>,
    out: &mut Vec<MergeConflict>,
) -> Map<String, Value> {
    let mut m = Map::new();
    for f in n.fields {
        let r = if f.hidden {
            t.get(f.name).cloned()
        } else {
            path.push(field_segment(f.name, matches!((f.kind)(), Kind::List(_))));
            let r = field(f, path, b.get(f.name), o.get(f.name), t.get(f.name), out);
            path.pop();
            r
        };
        if let Some(v) = r {
            m.insert(f.name.to_string(), v);
        }
    }
    m
}

/// `Some(value)` to store, `None` for absent. The leaf rule first; only a
/// field changed on both sides looks inside.
fn field(
    f: &Field,
    path: &mut Vec<String>,
    b: Option<&Value>,
    o: Option<&Value>,
    t: Option<&Value>,
    out: &mut Vec<MergeConflict>,
) -> Option<Value> {
    if o == b {
        return t.cloned();
    }
    if t == b || o == t {
        return o.cloned();
    }
    if !f.secret && f.render.is_none() {
        match unwrap_option((f.kind)()) {
            Kind::Struct(n) => {
                if let (Some(Value::Object(b)), Some(Value::Object(o)), Some(Value::Object(t))) =
                    (b, o, t)
                {
                    return Some(Value::Object(strukt(n, path, b, o, t, out)));
                }
            }
            Kind::List(e) => {
                if let Kind::Struct(n) = e()
                    && let Some(key) = key_of(n)
                    && let (Some(Value::Array(b)), Some(Value::Array(o)), Some(Value::Array(t))) =
                        (b, o, t)
                    && let Some(v) = keyed(n, key, path, [b, o, t], out)
                {
                    return Some(v);
                }
            }
            _ => {}
        }
    }
    out.push(MergeConflict { path: path.clone() });
    t.cloned()
}

type Index<'a> = HashMap<String, &'a Value>;

/// Elements by key; `None` on a duplicate key (the list is then a leaf).
fn index<'a>(l: &'a [Value], kn: &str) -> Option<Index<'a>> {
    let mut m = HashMap::with_capacity(l.len());
    for e in l {
        if m.insert(e[kn].to_string(), e).is_some() {
            return None;
        }
    }
    Some(m)
}

fn keys(l: &[Value], kn: &str) -> Vec<String> {
    l.iter().map(|e| e[kn].to_string()).collect()
}

/// `a` restricted to the keys in `set`, in `a`'s order.
fn restrict<'a>(a: &'a [String], set: &Index) -> Vec<&'a String> {
    a.iter().filter(|k| set.contains_key(*k)).collect()
}

fn object(v: &Value) -> &Map<String, Value> {
    v.as_object().expect("a list element is an object")
}

fn keyed(
    n: &Node,
    key: &Field,
    path: &mut Vec<String>,
    [b, o, t]: [&[Value]; 3],
    out: &mut Vec<MergeConflict>,
) -> Option<Value> {
    let kn = key.name;
    let (bi, oi, ti) = (index(b, kn)?, index(o, kn)?, index(t, kn)?);
    let (bk, ok, tk) = (keys(b, kn), keys(o, kn), keys(t, kn));

    // Each element's merged value; absent from `kept` = removed.
    let mut kept: HashMap<&String, Value> = HashMap::new();
    let mut seen = HashSet::new();
    for k in tk.iter().chain(&ok).chain(&bk).filter(|k| seen.insert(*k)) {
        let (be, oe, te) = (bi.get(k), oi.get(k), ti.get(k));
        let one = be.or(oe).or(te).expect("a key from one side");
        path.push(match &one[kn] {
            Value::String(s) => s.clone(),
            v => v.to_string(),
        });
        let clash = |out: &mut Vec<MergeConflict>| {
            out.push(MergeConflict { path: path.clone() });
        };
        let merged = match (be, oe, te) {
            (None, Some(o), Some(t)) => {
                if o != t {
                    clash(out);
                }
                Some((*t).clone())
            }
            (Some(b), Some(o), Some(t)) => Some(if o == b {
                (*t).clone()
            } else if t == b || o == t {
                (*o).clone()
            } else {
                Value::Object(strukt(n, path, object(b), object(o), object(t), out))
            }),
            // Removed by one side: fine only if the other left it alone.
            (Some(b), None, Some(x)) | (Some(b), Some(x), None) => {
                if x == b {
                    None
                } else {
                    clash(out);
                    Some((*x).clone())
                }
            }
            (None, Some(x), None) | (None, None, Some(x)) => Some((*x).clone()),
            (Some(_) | None, None, None) => None,
        };
        path.pop();
        if let Some(v) = merged {
            kept.insert(k, v);
        }
    }

    // Order: theirs' unless only ours reordered the elements it kept.
    let ours_moved = restrict(&ok, &bi) != restrict(&bk, &oi);
    let theirs_moved = restrict(&tk, &bi) != restrict(&bk, &ti);
    if ours_moved && theirs_moved && restrict(&ok, &ti) != restrict(&tk, &oi) {
        out.push(MergeConflict { path: path.clone() });
    }
    let (primary, secondary) = if ours_moved && !theirs_moved {
        (&ok, &tk)
    } else {
        (&tk, &ok)
    };
    let mut order: Vec<&String> = primary.iter().filter(|k| kept.contains_key(k)).collect();
    // ponytail: `position`/`insert` make adding m secondary-only elements
    // O(n*m); fine for thousands of routes, use a linked order for more.
    for (i, k) in secondary.iter().enumerate() {
        if !kept.contains_key(k) || order.contains(&k) {
            continue;
        }
        let at = secondary[..i]
            .iter()
            .rev()
            .find_map(|p| order.iter().position(|x| *x == p))
            .map_or(0, |p| p + 1);
        order.insert(at, k);
    }
    Some(Value::Array(
        order.into_iter().filter_map(|k| kept.remove(k)).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::cli::default_json;
    use crate::config_path::ELEMENT_KEYS;
    use crate::schema::{BgpInstance, BgpPeerGroup, User};

    fn dflt<T: Default + serde::Serialize + serde::de::DeserializeOwned>() -> T {
        serde_json::from_value(default_json::<T>()).unwrap()
    }

    fn pg(name: &str, rr: bool) -> BgpPeerGroup {
        BgpPeerGroup {
            name: name.into(),
            route_reflector_client: rr,
            ..dflt()
        }
    }

    fn inst(name: &str, groups: &[BgpPeerGroup]) -> BgpInstance {
        BgpInstance {
            name: name.into(),
            peer_groups: groups.to_vec(),
            ..dflt()
        }
    }

    fn cfg(host: &str, insts: Vec<BgpInstance>) -> Config {
        Config {
            hostname: host.into(),
            bgp_instances: insts,
            ..Default::default()
        }
    }

    fn user(name: &str, pw: &str) -> User {
        User {
            name: name.into(),
            password: pw.into(),
        }
    }

    fn names(c: &Config) -> Vec<&str> {
        c.bgp_instances[0]
            .peer_groups
            .iter()
            .map(|g| g.name.as_str())
            .collect()
    }

    fn conflicts(r: Result<Config, Vec<MergeConflict>>) -> Vec<String> {
        r.unwrap_err().iter().map(ToString::to_string).collect()
    }

    #[test]
    fn disjoint_adds_and_removes_merge() {
        let base = cfg("h", vec![inst("r1", &[pg("a", false), pg("b", false)])]);
        // ours removes a, adds c; theirs removes b, adds d.
        let ours = cfg("h", vec![inst("r1", &[pg("b", false), pg("c", false)])]);
        let theirs = cfg("h", vec![inst("r1", &[pg("a", false), pg("d", false)])]);
        let m = merge_configs(&base, &ours, &theirs).unwrap();
        let mut n = names(&m);
        n.sort_unstable();
        assert_eq!(n, ["c", "d"]);
    }

    #[test]
    fn different_leaves_merge_same_leaf_conflicts() {
        let base = cfg("h", vec![inst("r1", &[pg("a", false)])]);
        let ours = cfg("h2", vec![inst("r1", &[pg("a", true)])]);
        let theirs = cfg("h", vec![inst("r1", &[pg("a", false), pg("x", false)])]);
        let m = merge_configs(&base, &ours, &theirs).unwrap();
        assert_eq!(m.hostname, "h2");
        assert_eq!(names(&m), ["a", "x"]);
        assert!(m.bgp_instances[0].peer_groups[0].route_reflector_client);

        let (o, t) = (cfg("o", vec![]), cfg("t", vec![]));
        assert_eq!(conflicts(merge_configs(&base, &o, &t)), ["hostname"]);
    }

    #[test]
    fn remove_vs_modify_conflicts_both_ways() {
        let base = cfg("h", vec![inst("r1", &[pg("a", false)])]);
        let removed = cfg("h", vec![inst("r1", &[])]);
        let modified = cfg("h", vec![inst("r1", &[pg("a", true)])]);
        let want = ["bgp-instance/r1/peer-group/a"];
        assert_eq!(conflicts(merge_configs(&base, &removed, &modified)), want);
        assert_eq!(conflicts(merge_configs(&base, &modified, &removed)), want);
        // removed by both is removed.
        let other = cfg("x", vec![inst("r1", &[])]);
        let m = merge_configs(&base, &removed, &other).unwrap();
        assert_eq!(names(&m), Vec::<&str>::new());
    }

    #[test]
    fn both_add_equal_ok_different_conflicts() {
        let base = cfg("h", vec![]);
        let a = cfg("h1", vec![inst("r1", &[pg("a", false)])]);
        let b = cfg("h", vec![inst("r1", &[pg("a", false)])]);
        assert_eq!(merge_configs(&base, &a, &b).unwrap().bgp_instances.len(), 1);
        let c = cfg("h", vec![inst("r1", &[pg("a", true)])]);
        assert_eq!(conflicts(merge_configs(&base, &a, &c)), ["bgp-instance/r1"]);
    }

    #[test]
    fn reorder_rules() {
        let (a, b, c) = (pg("a", false), pg("b", false), pg("c", false));
        let with = |g: &[BgpPeerGroup], h: &str| cfg(h, vec![inst("r1", g)]);
        let base = with(&[a.clone(), b.clone(), c.clone()], "h");
        let rev = with(&[c.clone(), b.clone(), a.clone()], "h");
        // only ours reordered: ours' order, theirs' add after its predecessor.
        let theirs = with(&[a.clone(), b.clone(), c.clone(), pg("d", false)], "h");
        let m = merge_configs(&base, &rev, &theirs).unwrap();
        assert_eq!(names(&m), ["c", "d", "b", "a"]);
        // only theirs reordered: theirs' order.
        let ours = with(&[a.clone(), b.clone(), c.clone()], "o");
        let m = merge_configs(&base, &ours, &rev).unwrap();
        assert_eq!(names(&m), ["c", "b", "a"]);
        // both, differently: a conflict on the list.
        let other = with(&[b.clone(), a.clone(), c.clone()], "h");
        assert_eq!(
            conflicts(merge_configs(&base, &rev, &other)),
            ["bgp-instance/r1/peer-group"]
        );
        // both, identically: fine.
        assert!(merge_configs(&base, &rev, &with(&[c, b, a], "t")).is_ok());
    }

    #[test]
    fn secret_leaf_is_atomic_users_merge() {
        let u = |pw| Config {
            users: vec![user("alice", pw)],
            ..Default::default()
        };
        let base = u("p0");
        assert_eq!(
            conflicts(merge_configs(&base, &u("p1"), &u("p2"))),
            ["user/alice/password"]
        );
        // ours rehashed alice, theirs added bob: both kept.
        let mut theirs = u("p0");
        theirs.users.push(user("bob", "q"));
        let m = merge_configs(&base, &u("p1"), &theirs).unwrap();
        assert_eq!(m.users.len(), 2);
        assert_eq!(m.users[0].password, "p1");
    }

    #[test]
    fn identity_cases() {
        let base = cfg("h", vec![inst("r1", &[pg("a", false)])]);
        let other = cfg("o", vec![inst("r2", &[])]);
        assert_eq!(merge_configs(&base, &base, &other).unwrap(), other);
        assert_eq!(merge_configs(&base, &other, &base).unwrap(), other);
    }

    /// Unkeyed lists of structs that are one atomic leaf on purpose: their
    /// order is their meaning (first match wins), so there is no element
    /// identity to merge by.
    const ORDERED: &[&str] = &[".prefix_lists.entries"];

    /// Every list of structs in the schema is keyed by a field
    /// `ELEMENT_KEYS` knows, or a deliberate leaf (secret / `render`): a new
    /// unkeyed list must be a conscious atomic leaf, not an accident.
    #[test]
    fn every_struct_list_is_keyed_or_a_leaf() {
        type Lists<'a> = Vec<(String, &'a Field, &'a Node)>;
        fn walk<'a>(n: &'a Node, at: &str, seen: &mut HashSet<usize>, out: &mut Lists<'a>) {
            if !seen.insert(std::ptr::from_ref(n) as usize) {
                return;
            }
            for f in n.fields.iter().filter(|f| !f.hidden) {
                let at = format!("{at}.{}", f.name);
                match unwrap_option((f.kind)()) {
                    Kind::Struct(c) => walk(c, &at, seen, out),
                    Kind::List(e) => {
                        if let Kind::Struct(c) = e() {
                            out.push((at.clone(), f, c));
                            walk(c, &at, seen, out);
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut lists = Vec::new();
        walk(root(), "", &mut HashSet::new(), &mut lists);
        let known = |c: &Node| key_of(c).is_some_and(|k| ELEMENT_KEYS.contains(&k.name));
        let bad: Vec<_> = lists
            .iter()
            .filter(|(at, f, c)| {
                !known(c) && !f.secret && f.render.is_none() && !ORDERED.contains(&&**at)
            })
            .map(|(at, ..)| at)
            .collect();
        assert!(bad.is_empty(), "struct lists without a known key: {bad:?}");
    }

    fn arb_cfg() -> impl Strategy<Value = Config> {
        let name = prop::sample::select(vec!["a", "b", "c", "d"]);
        let uniq = |mut v: Vec<(String, Vec<BgpPeerGroup>)>| {
            let mut seen = HashSet::new();
            v.retain(|(n, _)| seen.insert(n.clone()));
            v
        };
        let group = (name.clone(), any::<bool>()).prop_map(|(n, rr)| pg(n, rr));
        let groups = prop::collection::vec(group, 0..4).prop_map(|mut g| {
            let mut seen = HashSet::new();
            g.retain(|x| seen.insert(x.name.clone()));
            g
        });
        let insts = prop::collection::vec((name.clone().prop_map(String::from), groups), 0..3)
            .prop_map(uniq);
        (
            prop::sample::select(vec!["h1", "h2"]),
            insts,
            prop::collection::vec(name.prop_map(|n| user(n, "x")), 0..3),
        )
            .prop_map(|(h, i, mut u)| {
                let mut seen = HashSet::new();
                u.retain(|x| seen.insert(x.name.clone()));
                let mut c = cfg(h, i.iter().map(|(n, g)| inst(n, g)).collect());
                c.users = u;
                c
            })
    }

    proptest! {
        #[test]
        fn identity_laws(b in arb_cfg(), o in arb_cfg(), t in arb_cfg()) {
            prop_assert_eq!(merge_configs(&b, &o, &b).unwrap(), o.clone());
            prop_assert_eq!(merge_configs(&b, &b, &t).unwrap(), t.clone());
            prop_assert_eq!(merge_configs(&b, &o, &o).unwrap(), o);
        }

        /// Without the shortcuts: the field walk itself honours the laws.
        #[test]
        fn walk_identity_laws(b in arb_cfg(), o in arb_cfg()) {
            let mut b2 = b.clone();
            b2.hostname = "zz".into();
            // theirs differs from base only by hostname: ours' other edits survive.
            let m = merge_configs(&b, &o, &b2);
            if o.hostname == b.hostname {
                prop_assert_eq!(m.unwrap().hostname, "zz");
            }
        }
    }
}
