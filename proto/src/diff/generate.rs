//! The config diff, generated from the CLI tree (#116): the two configs' JSON
//! are walked field by field through `cli::root()`, so no field is named here
//! and none can be forgotten — a field the shell can set is a field whose
//! change wakes the daemons. Labels and headers are the CLI's own words
//! (`bgp instance r1`, `route-reflector-client`); values are the same text
//! `show config` writes, `unset` for an absent one.
//!
//! A keyed list of structs is a section (`SectionDiff`, nested ones in
//! `subsections`); everything else is one `FieldDiff` per changed field. A
//! plain struct field (`evpn`, `logging`) and, below the root, every list
//! inside one, is flattened to labels prefixed with its words
//! (`logging syslog s1 address`). Hidden fields (derived state) are skipped.

use std::collections::HashMap;
use std::hash::Hash;

use serde::Serialize;
use serde_json::Value;

use crate::cli::render::{name, unwrap_option, words, HIDDEN};
use crate::cli::{root, Field, Kind, Node};
use crate::schema::StaticRoutingInstance;
use crate::Config;

use super::{ConfigDiff, DiffStatus, FieldDiff, SectionDiff};

/// A secret that is still there but changed.
const CHANGED: &str = "<changed>";

/// The typed diff (#778): the same output as `diff_values` on both configs'
/// JSON, but typed-equal root fields and list elements are skipped with
/// `==` and never serialized, so a commit's transient is the JSON of what
/// changed, not of two whole configs.
pub fn diff_configs(base: &Config, candidate: &Config) -> ConfigDiff {
    let mut out = ConfigDiff::default();
    for f in root().fields.iter().filter(|f| !f.hidden) {
        let (mut fields, mut subs) = (Vec::new(), Vec::new());
        root_field(f, base, candidate, &mut fields, &mut subs);
        assert!(
            put(&mut out, f.name, fields, subs),
            "Config.{} has no ConfigDiff slot",
            f.name
        );
    }
    out
}

/// `diff_configs` on the configs' JSON (the round-trip tests build configs
/// that are only shaped like one). Walks both whole trees: the oracle the
/// typed diff is tested against.
pub fn diff_values(b: &Value, c: &Value) -> ConfigDiff {
    let mut out = ConfigDiff::default();
    for f in root().fields.iter().filter(|f| !f.hidden) {
        let (mut fields, mut subs) = (Vec::new(), Vec::new());
        field(f, "", Some(b), Some(c), false, &mut fields, &mut subs);
        assert!(
            put(&mut out, f.name, fields, subs),
            "Config.{} has no ConfigDiff slot",
            f.name
        );
    }
    out
}

fn to_value<T: Serialize + ?Sized>(c: &T) -> Value {
    serde_json::to_value(c).expect("a config serializes")
}

/// One root field, typed. Every keyed root list is keyed by `name`.
fn root_field(
    f: &Field,
    b: &Config,
    c: &Config,
    fields: &mut Vec<FieldDiff>,
    subs: &mut Vec<SectionDiff>,
) {
    macro_rules! dispatch {
        (lists: $($l:ident),*; values: $($v:ident),*) => {
            $(if f.name == stringify!($l) {
                return keyed(f, &b.$l, &c.$l, |e| &e.name, element, fields, subs);
            })*
            $(if f.name == stringify!($v) {
                return one(f, &b.$v, &c.$v, fields, subs);
            })*
        };
    }
    if f.name == "static_routing_instances" {
        let (b, c) = (&b.static_routing_instances, &c.static_routing_instances);
        return keyed(f, b, c, |e| &e.name, static_instance, fields, subs);
    }
    dispatch!(
        lists: bgp_instances, routing_tables, ospf_instances, ospfv3_instances, interfaces,
            policy_definitions, community_aliases, community_groups, as_path_lists, prefix_lists,
            broadcast_domains, switching_profiles, port_aggregates, users, bfd_profiles,
            stp_port_profiles, acls;
        values: hostname, lldp, logging, sbfd_reflector, spanning_tree, admin
    );
    panic!("Config.{} has no typed diff", f.name);
}

/// A field diffed through its JSON alone. Not skipped when typed-equal: a
/// keyed list inside one (`admin keys`) with a duplicate key pairs every
/// duplicate with the first, which `list` reports even between equal sides
/// (an uncommitted transaction can hold one). The singletons are small.
fn one<T: Serialize + ?Sized>(
    f: &Field,
    b: &T,
    c: &T,
    fields: &mut Vec<FieldDiff>,
    subs: &mut Vec<SectionDiff>,
) {
    let obj = |v: &T| Value::Object([(f.name.to_string(), to_value(v))].into_iter().collect());
    field(f, "", Some(&obj(b)), Some(&obj(c)), false, fields, subs);
}

/// One differing (or added/removed) element, through its JSON.
fn element<T: Serialize>(
    n: &Node,
    b: Option<&T>,
    c: Option<&T>,
    fields: &mut Vec<FieldDiff>,
    subs: &mut Vec<SectionDiff>,
) {
    let (b, c) = (b.map(to_value), c.map(to_value));
    object(n, "", b.as_ref(), c.as_ref(), false, fields, subs);
}

/// A modified static instance holds thousands of routes: diff the instance
/// without them, then its routes typed (only changed routes serialized).
fn static_instance(
    n: &Node,
    b: Option<&StaticRoutingInstance>,
    c: Option<&StaticRoutingInstance>,
    fields: &mut Vec<FieldDiff>,
    subs: &mut Vec<SectionDiff>,
) {
    let (Some(b), Some(c)) = (b, c) else {
        return element(n, b, c, fields, subs);
    };
    // No `..`: a new field must be placed here, and `routes` stays the last
    // field (its diff is appended after the rest's).
    let bare = |e: &StaticRoutingInstance| StaticRoutingInstance {
        name: e.name.clone(),
        routes: Vec::new(),
    };
    element(n, Some(&bare(b)), Some(&bare(c)), fields, subs);
    let routes = n
        .fields
        .iter()
        .find(|f| f.name == "routes")
        .expect("routes field");
    keyed(
        routes,
        &b.routes,
        &c.routes,
        |r| &r.subnet,
        element,
        fields,
        subs,
    );
}

/// Diffs one element pair of a keyed list (`None`: added/removed).
type ElemFn<T> = fn(&Node, Option<&T>, Option<&T>, &mut Vec<FieldDiff>, &mut Vec<SectionDiff>);

/// Each element's index by key; the first wins on a duplicate, as in `list`.
fn index<'l, T, K: Hash + Eq>(l: &'l [T], key: &impl Fn(&T) -> &K) -> HashMap<&'l K, usize> {
    let mut m = HashMap::with_capacity(l.len());
    for (i, e) in l.iter().enumerate() {
        m.entry(key(e)).or_insert(i);
    }
    m
}

/// `list` on typed elements (`field` of a non-flat keyed list): elements
/// paired by their typed key, typed-equal pairs skipped unserialized.
fn keyed<T, K>(
    f: &Field,
    base: &[T],
    cand: &[T],
    key: impl Fn(&T) -> &K,
    elem: ElemFn<T>,
    fields: &mut Vec<FieldDiff>,
    subs: &mut Vec<SectionDiff>,
) where
    T: Serialize + PartialEq,
    K: Serialize + Hash + Eq,
{
    // No `b == c` shortcut, for the duplicate-key reason in `one`; equal
    // sides cost two key indexes, nothing serialized.
    let node = match unwrap_option((f.kind)()) {
        Kind::List(e) if !f.secret && f.render.is_none() => match e() {
            Kind::Struct(n) => key_of(n).map(|k| (n, k)),
            _ => None,
        },
        _ => None,
    };
    let Some((node, kf)) = node else {
        return one(f, base, cand, fields, subs);
    };
    let (bi, ci) = (index(base, &key), index(cand, &key));
    let label = name(f);
    let common = |l: &[T], other: &HashMap<&K, usize>| -> Vec<usize> {
        (0..l.len())
            .filter(|&i| other.contains_key(key(&l[i])))
            .collect()
    };
    let (old_order, new_order) = (common(base, &ci), common(cand, &bi));
    let same_order = old_order.len() == new_order.len()
        && old_order
            .iter()
            .zip(&new_order)
            .all(|(&i, &j)| key(&base[i]) == key(&cand[j]));
    let kw = |k: &K| words(&(kf.kind)(), &to_value(k)).join(" ");
    if !same_order {
        let text = |l: &[T], o: Vec<usize>| -> String {
            o.into_iter()
                .map(|i| kw(key(&l[i])))
                .collect::<Vec<_>>()
                .join(", ")
        };
        fields.push(FieldDiff {
            label: format!("{label} order"),
            old: Some(text(base, old_order)),
            new: Some(text(cand, new_order)),
        });
    }
    let pairs = base
        .iter()
        .map(|e| (Some(e), ci.get(key(e)).map(|&i| &cand[i])))
        .chain(
            cand.iter()
                .filter(|e| !bi.contains_key(key(e)))
                .map(|e| (None, Some(e))),
        );
    for (be, ce) in pairs {
        if be.is_some() && be == ce {
            continue;
        }
        let k = kw(key(be.or(ce).expect("one side")));
        let status = match (be, ce) {
            (None, _) => DiffStatus::Added,
            (_, None) => DiffStatus::Removed,
            _ => DiffStatus::Modified,
        };
        let (mut fs, mut ss) = (Vec::new(), Vec::new());
        elem(node, be, ce, &mut fs, &mut ss);
        if status == DiffStatus::Modified && fs.is_empty() && ss.is_empty() {
            continue;
        }
        subs.push(SectionDiff {
            header: format!("{label} {k}"),
            name: k,
            status,
            fields: fs,
            subsections: ss,
        });
    }
}

/// Stores one root field's diff in its `ConfigDiff` slot; `false` for a
/// field with none (a new `Config` field must get one — pinned by a test).
fn put(d: &mut ConfigDiff, name: &str, mut fields: Vec<FieldDiff>, subs: Vec<SectionDiff>) -> bool {
    match name {
        "hostname" => d.hostname = fields.pop(),
        "bgp_instances" => d.bgp_instances = subs,
        "routing_tables" => d.routing_tables = subs,
        "ospf_instances" => d.ospf_instances = subs,
        "ospfv3_instances" => d.ospfv3_instances = subs,
        "static_routing_instances" => d.static_routing_instances = subs,
        "interfaces" => d.interfaces = subs,
        "policy_definitions" => d.policy_definitions = subs,
        "community_aliases" => d.community_aliases = subs,
        "community_groups" => d.community_groups = subs,
        "as_path_lists" => d.as_path_lists = subs,
        "prefix_lists" => d.prefix_lists = subs,
        "broadcast_domains" => d.broadcast_domains = subs,
        "switching_profiles" => d.switching_profiles = subs,
        "port_aggregates" => d.port_aggregates = subs,
        "lldp" => d.lldp = fields,
        "users" => d.users = subs,
        "logging" => d.logging = fields,
        "bfd_profiles" => d.bfd_profiles = subs,
        "sbfd_reflector" => d.sbfd_reflector = fields,
        "spanning_tree" => d.spanning_tree = fields,
        "stp_port_profiles" => d.stp_port_profiles = subs,
        "acls" => d.acls = subs,
        "admin" => d.admin = fields,
        _ => return false,
    }
    true
}

fn key_of(n: &Node) -> Option<&Field> {
    n.fields.iter().find(|k| k.key)
}

/// A keyed list's element, as `(key words, element)`.
fn key_words(key: &Field, e: &Value) -> String {
    words(&(key.kind)(), &e[key.name]).join(" ")
}

fn join(prefix: &str, rest: &str) -> String {
    if prefix.is_empty() {
        rest.to_string()
    } else {
        format!("{prefix} {rest}")
    }
}

/// One field of `b`/`c` (`None`: that side's object is absent — an added or
/// removed element).
fn field(
    f: &Field,
    prefix: &str,
    b: Option<&Value>,
    c: Option<&Value>,
    flat: bool,
    fields: &mut Vec<FieldDiff>,
    subs: &mut Vec<SectionDiff>,
) {
    let label = join(prefix, &name(f));
    let (bv, cv) = (get(b, f), get(c, f));
    let plain = !f.secret && f.render.is_none();
    match unwrap_option((f.kind)()) {
        Kind::List(elem) if plain => {
            if let Kind::Struct(n) = elem()
                && let Some(key) = key_of(n)
            {
                return list(
                    &Ctx {
                        f,
                        n,
                        key,
                        label: &label,
                        flat,
                    },
                    items(bv),
                    items(cv),
                    fields,
                    subs,
                );
            }
        }
        // A plain struct is a section of the field's words.
        Kind::Struct(n) if plain && matches!((f.kind)(), Kind::Struct(_)) => {
            return object(n, &label, bv, cv, true, fields, subs);
        }
        _ => {}
    }
    if bv == cv {
        return;
    }
    let show = |v: Option<&Value>| v.map(|v| show(f, v));
    let (old, new) = if f.secret {
        (
            bv.map(|_| HIDDEN.to_string()),
            cv.map(|_| if bv.is_some() { CHANGED } else { HIDDEN }.to_string()),
        )
    } else {
        (show(bv), show(cv))
    };
    fields.push(FieldDiff { label, old, new });
}

fn items(v: Option<&Value>) -> &[Value] {
    v.and_then(Value::as_array).map_or(&[][..], Vec::as_slice)
}

fn get<'v>(o: Option<&'v Value>, f: &Field) -> Option<&'v Value> {
    o.map(|o| o.get(f.name).unwrap_or(&Value::Null))
}

struct Ctx<'a> {
    f: &'a Field,
    n: &'a Node,
    key: &'a Field,
    label: &'a str,
    flat: bool,
}

fn list(
    cx: &Ctx,
    base: &[Value],
    cand: &[Value],
    fields: &mut Vec<FieldDiff>,
    subs: &mut Vec<SectionDiff>,
) {
    // Each side indexed by key once (first element wins on a duplicate key,
    // as the linear scan did): O(n) in the list length, no element cloned.
    type Index = std::collections::HashMap<String, usize>;
    fn find<'l>(l: &'l [Value], m: &Index, name: &str, e: &Value) -> Option<&'l Value> {
        m.get(&e[name].to_string()).map(|&i| &l[i])
    }
    let index = |l: &[Value]| -> Index {
        let mut m = Index::with_capacity(l.len());
        for (i, e) in l.iter().enumerate() {
            m.entry(e[cx.key.name].to_string()).or_insert(i);
        }
        m
    };
    let (bi, ci) = (index(base), index(cand));
    let kn = cx.key.name;
    // Pairing by key hides a pure reorder (#539); report the order of the
    // elements both sides have. ponytail: a root-level list (`acls` itself)
    // has no `fields` slot in `put`, so only nested lists report order.
    let common = |l: &[Value], other: &Index| -> Vec<String> {
        l.iter()
            .filter(|e| other.contains_key(&e[cx.key.name].to_string()))
            .map(|e| key_words(cx.key, e))
            .collect()
    };
    let (old_order, new_order) = (common(base, &ci), common(cand, &bi));
    if old_order != new_order {
        fields.push(FieldDiff {
            label: format!("{} order", cx.label),
            old: Some(old_order.join(", ")),
            new: Some(new_order.join(", ")),
        });
    }
    let pairs = base
        .iter()
        .map(|b| (Some(b), find(cand, &ci, kn, b)))
        .chain(
            cand.iter()
                .filter(|c| find(base, &bi, kn, c).is_none())
                .map(|c| (None, Some(c))),
        );
    for (b, c) in pairs {
        if b.is_some() && b == c {
            continue; // unchanged: the dominant case in a big list
        }
        let key = key_words(cx.key, b.or(c).expect("one side"));
        if cx.flat {
            let prefix = format!("{} {key}", cx.label);
            object(cx.n, &prefix, b, c, true, fields, subs);
            continue;
        }
        let status = match (&b, &c) {
            (None, _) => DiffStatus::Added,
            (_, None) => DiffStatus::Removed,
            _ => DiffStatus::Modified,
        };
        let (mut f, mut s) = (Vec::new(), Vec::new());
        object(cx.n, "", b, c, false, &mut f, &mut s);
        if status == DiffStatus::Modified && f.is_empty() && s.is_empty() {
            continue;
        }
        subs.push(SectionDiff {
            header: format!("{} {key}", name(cx.f)),
            name: key,
            status,
            fields: f,
            subsections: s,
        });
    }
}

/// The fields of one struct. An absent side is compared as the struct's
/// default, so a new element lists only what it sets.
fn object(
    n: &Node,
    prefix: &str,
    b: Option<&Value>,
    c: Option<&Value>,
    flat: bool,
    fields: &mut Vec<FieldDiff>,
    subs: &mut Vec<SectionDiff>,
) {
    let default = n
        .default
        .map_or_else(|| Value::Object(serde_json::Map::new()), |d| d());
    for f in n.fields.iter().filter(|f| !f.hidden && !f.key) {
        // Compare against the default, then drop the absent side's text.
        let (mut df, mut ds) = (Vec::new(), Vec::new());
        field(
            f,
            prefix,
            Some(b.unwrap_or(&default)),
            Some(c.unwrap_or(&default)),
            flat,
            &mut df,
            &mut ds,
        );
        for d in &mut df {
            if b.is_none() {
                d.old = None;
            }
            if c.is_none() {
                d.new = None;
            }
        }
        fields.extend(df);
        subs.extend(ds);
    }
}

/// The text `show config` would write for the field's value; `unset` when
/// it has none.
fn show(f: &Field, v: &Value) -> String {
    if let Some(render) = f.render {
        let lines = if v.is_null() { Vec::new() } else { render(v) };
        return if lines.is_empty() {
            "unset".into()
        } else {
            lines.join("; ")
        };
    }
    show_kind(&(f.kind)(), v)
}

fn show_kind(kind: &Kind, v: &Value) -> String {
    match kind {
        Kind::Option(_) if v.is_null() => "unset".into(),
        Kind::Option(inner) => show_kind(&inner(), v),
        Kind::Bool => v.as_bool().unwrap_or_default().to_string(),
        Kind::List(elem) => {
            let items: Vec<String> = v
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| show_kind(&elem(), e))
                .collect();
            if items.is_empty() {
                "none".into()
            } else {
                items.join(", ")
            }
        }
        k => {
            let w = words(k, v).join(" ");
            if w.is_empty() {
                "unset".into()
            } else {
                w
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::default_json;
    use crate::schema::{BgpInstance, BgpPeerGroup, OspfArea, OspfInstance, OspfProfile, User};
    use serde::de::DeserializeOwned;

    fn dflt<T: Default + serde::Serialize + DeserializeOwned>() -> T {
        serde_json::from_value(default_json::<T>()).unwrap()
    }

    fn list_node(root_field: &str) -> &'static Node {
        let f = root().fields.iter().find(|f| f.name == root_field).unwrap();
        let Kind::List(e) = (f.kind)() else { panic!() };
        let Kind::Struct(n) = e() else { panic!() };
        n
    }

    fn label(node: &Node, field: &str) -> String {
        name(node.fields.iter().find(|f| f.name == field).unwrap())
    }

    #[test]
    fn every_config_field_has_a_diff_slot() {
        let missing: Vec<_> = root()
            .fields
            .iter()
            .filter(|f| !put(&mut ConfigDiff::default(), f.name, Vec::new(), Vec::new()))
            .map(|f| f.name)
            .collect();
        assert!(missing.is_empty(), "no ConfigDiff slot for {missing:?}");
    }

    /// `nos-watchdogd` keys its opt-in daemons on these two labels.
    #[test]
    fn watchdog_labels_are_the_cli_words() {
        assert_eq!(
            label(list_node("routing_tables"), "rest_api"),
            super::super::REST_API_LABEL
        );
        assert_eq!(
            label(list_node("broadcast_domains"), "vni"),
            super::super::VNI_LABEL
        );
    }

    #[test]
    fn identical_configs_are_empty() {
        let c = Config::default();
        assert!(diff_configs(&c, &c).is_empty());
    }

    /// The bug this replaced: no event for a commit changing only this.
    #[test]
    fn a_route_reflector_client_change_alone_is_a_diff() {
        let inst = |rr| BgpInstance {
            name: "r1".into(),
            peer_groups: vec![BgpPeerGroup {
                name: "g".into(),
                route_reflector_client: rr,
                ..dflt()
            }],
            ..dflt()
        };
        let cfg = |rr| Config {
            bgp_instances: vec![inst(rr)],
            ..Default::default()
        };
        let d = diff_configs(&cfg(false), &cfg(true));
        let g = &d.bgp_instances[0].subsections[0];
        assert_eq!(g.header, "peer-group g");
        assert_eq!(g.fields[0].label, "route-reflector-client");
        assert_eq!(g.fields[0].new.as_deref(), Some("true"));
    }

    #[test]
    fn an_added_nested_element_lists_only_what_it_sets() {
        let inst = |profiles| OspfInstance {
            name: "o1".into(),
            areas: vec![OspfArea { profiles, ..dflt() }],
            ..dflt()
        };
        let p = OspfProfile {
            name: "p1".into(),
            cost: Some(10),
            ..dflt()
        };
        let cfg = |profiles| Config {
            ospf_instances: vec![inst(profiles)],
            ..Default::default()
        };
        let d = diff_configs(&cfg(vec![]), &cfg(vec![p]));
        let prof = &d.ospf_instances[0].subsections[0].subsections[0];
        assert_eq!(prof.header, "profile p1");
        assert_eq!(prof.status, DiffStatus::Added);
        assert_eq!(prof.fields.len(), 1);
        assert_eq!(prof.fields[0].label, "cost");
        assert_eq!(prof.fields[0].old, None);
        assert_eq!(prof.fields[0].new.as_deref(), Some("10"));
    }

    #[test]
    fn reordering_nested_elements_is_a_diff_but_adding_one_is_not_an_order_change() {
        let cfg = |names: &[&str]| Config {
            bgp_instances: vec![BgpInstance {
                name: "r1".into(),
                peer_groups: names
                    .iter()
                    .map(|n| BgpPeerGroup {
                        name: (*n).into(),
                        ..dflt()
                    })
                    .collect(),
                ..dflt()
            }],
            ..Default::default()
        };
        let order = |d: &ConfigDiff| -> Vec<FieldDiff> {
            d.bgp_instances
                .first()
                .map(|i| i.fields.clone())
                .unwrap_or_default()
        };
        let none = [] as [FieldDiff; 0];
        let ab = cfg(&["a", "b"]);
        assert!(diff_configs(&ab, &ab).is_empty());
        let d = diff_configs(&ab, &cfg(&["b", "a"]));
        assert_eq!(d.bgp_instances[0].status, DiffStatus::Modified);
        let f = order(&d);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].label.ends_with("order"), "{f:?}");
        assert_eq!(f[0].old.as_deref(), Some("a, b"));
        assert_eq!(f[0].new.as_deref(), Some("b, a"));
        // Adding or removing alone is not a reorder.
        assert_eq!(order(&diff_configs(&ab, &cfg(&["a", "b", "c"]))), none);
        assert_eq!(order(&diff_configs(&ab, &cfg(&["b"]))), none);
    }

    fn statics(routes: impl IntoIterator<Item = (u32, u8)>) -> Config {
        use crate::schema::{StaticRoute, StaticRoutingInstance};
        Config {
            static_routing_instances: vec![StaticRoutingInstance {
                name: "s".into(),
                routes: routes
                    .into_iter()
                    .map(|(n, gw)| StaticRoute {
                        subnet: format!("10.{}.{}.0/24", n / 256, n % 256).parse().unwrap(),
                        gateway: format!("192.0.2.{gw}").parse().unwrap(),
                        ..dflt()
                    })
                    .collect(),
            }],
            ..Default::default()
        }
    }

    fn route_sections(d: &ConfigDiff) -> Vec<(String, DiffStatus)> {
        d.static_routing_instances[0]
            .subsections
            .iter()
            .map(|s| (s.name.clone(), s.status))
            .collect()
    }

    /// #751: one changed, one added, one removed in 20 000 routes, found by
    /// key index (the old linear `find` was O(n^2) and cloned every element).
    #[test]
    #[cfg_attr(miri, ignore = "20k-element list, minutes under the interpreter")]
    fn a_large_list_diffs_to_exactly_its_changes() {
        let n = 20_000;
        let base = statics((0..n).map(|i| (i, 1)));
        // Route 5 repointed, 7 removed, `n` added; the rest identical.
        let cand = statics(
            (0..n)
                .filter(|&i| i != 7)
                .map(|i| (i, if i == 5 { 2 } else { 1 }))
                .chain([(n, 1)]),
        );
        let d = diff_configs(&base, &cand);
        assert_eq!(d.static_routing_instances[0].fields, vec![]);
        let mut got = route_sections(&d);
        got.sort_by(|a, b| a.0.cmp(&b.0));
        let mut want = vec![
            ("10.0.5.0/24".to_string(), DiffStatus::Modified),
            ("10.0.7.0/24".to_string(), DiffStatus::Removed),
            (
                format!("10.{}.{}.0/24", n / 256, n % 256),
                DiffStatus::Added,
            ),
        ];
        want.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(got, want);
    }

    /// A key listed twice: every base element pairs with the candidate's
    /// first match, as the linear scan did.
    #[test]
    fn a_duplicate_key_pairs_with_its_first_occurrence() {
        let base = statics([(1, 1), (1, 9)]);
        let d = diff_configs(&base, &statics([(1, 2)]));
        let secs = &d.static_routing_instances[0].subsections;
        let olds: Vec<_> = secs.iter().map(|s| s.fields[0].old.as_deref()).collect();
        assert_eq!(olds, [Some("192.0.2.1"), Some("192.0.2.9")]);
        assert!(secs
            .iter()
            .all(|s| s.fields[0].new.as_deref() == Some("192.0.2.2")));
    }

    #[test]
    fn reorder_add_and_remove_in_one_list() {
        let cfg = |names: &[&str]| Config {
            bgp_instances: vec![BgpInstance {
                name: "r1".into(),
                peer_groups: names
                    .iter()
                    .map(|n| BgpPeerGroup {
                        name: (*n).into(),
                        ..dflt()
                    })
                    .collect(),
                ..dflt()
            }],
            ..Default::default()
        };
        let d = diff_configs(&cfg(&["a", "b", "c"]), &cfg(&["c", "d", "a"]));
        let inst = &d.bgp_instances[0];
        assert_eq!(inst.fields.len(), 1);
        assert_eq!(inst.fields[0].old.as_deref(), Some("a, c"));
        assert_eq!(inst.fields[0].new.as_deref(), Some("c, a"));
        let st: Vec<_> = inst
            .subsections
            .iter()
            .map(|s| (s.name.as_str(), s.status))
            .collect();
        assert_eq!(st, [("b", DiffStatus::Removed), ("d", DiffStatus::Added)]);
    }

    /// The pre-#778 full-JSON walk: the typed diff must match it exactly.
    fn diff_configs_full(b: &Config, c: &Config) -> ConfigDiff {
        diff_values(&to_value(b), &to_value(c))
    }

    /// A deterministic xorshift, so a failure replays.
    struct Rng(u64);
    impl Rng {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            usize::try_from(self.0 % n.max(1) as u64).unwrap()
        }
    }

    /// One random edit: add/remove/modify/reorder routes, instances, peer
    /// groups, users, secrets, singletons; duplicate keys included.
    #[allow(clippy::too_many_lines, clippy::many_single_char_names)] // one flat arm per edit
    fn mutate(c: &mut Config, r: &mut Rng) {
        use crate::schema::{StaticRoute, StaticRoutingInstance};
        let route = |r: &mut Rng| StaticRoute {
            subnet: format!("10.0.{}.0/24", r.below(40)).parse().unwrap(),
            gateway: format!("192.0.2.{}", r.below(4)).parse().unwrap(),
            bfd: (r.below(4) == 0).then(|| "b".to_string()),
        };
        let pick = |r: &mut Rng, len: usize| r.below(len);
        match r.below(16) {
            0 => c.static_routing_instances.push(StaticRoutingInstance {
                name: format!("s{}", r.below(4)),
                routes: (0..r.below(5)).map(|_| route(r)).collect(),
            }),
            1 if !c.static_routing_instances.is_empty() => {
                let i = pick(r, c.static_routing_instances.len());
                c.static_routing_instances.remove(i);
            }
            2..=4 if !c.static_routing_instances.is_empty() => {
                let i = pick(r, c.static_routing_instances.len());
                let rt = route(r);
                c.static_routing_instances[i].routes.push(rt);
            }
            5 | 6 if !c.static_routing_instances.is_empty() => {
                let i = pick(r, c.static_routing_instances.len());
                let routes = &mut c.static_routing_instances[i].routes;
                if !routes.is_empty() {
                    let j = r.below(routes.len());
                    match r.below(3) {
                        0 => drop(routes.remove(j)),
                        1 => {
                            let k = r.below(routes.len());
                            routes.swap(j, k);
                        }
                        _ => routes[j].gateway = format!("192.0.2.{}", r.below(9)).parse().unwrap(),
                    }
                }
            }
            7 if !c.static_routing_instances.is_empty() => {
                let n = c.static_routing_instances.len();
                c.static_routing_instances.swap(r.below(n), r.below(n));
            }
            8 => c.bgp_instances.push(BgpInstance {
                name: format!("b{}", r.below(3)),
                asn: u32::try_from(r.below(3)).unwrap(),
                ..dflt()
            }),
            9 if !c.bgp_instances.is_empty() => {
                let i = pick(r, c.bgp_instances.len());
                let pg = &mut c.bgp_instances[i].peer_groups;
                match r.below(3) {
                    0 => pg.push(BgpPeerGroup {
                        name: format!("g{}", r.below(4)),
                        route_reflector_client: r.below(2) == 0,
                        ..dflt()
                    }),
                    1 if !pg.is_empty() => drop(pg.remove(r.below(pg.len()))),
                    _ => pg.reverse(),
                }
            }
            10 => c.users.push(User {
                name: format!("u{}", r.below(3)),
                password: format!("p{}", r.below(3)),
            }),
            11 if !c.users.is_empty() => {
                let i = pick(r, c.users.len());
                c.users[i].password = format!("p{}", r.below(3));
            }
            12 => {
                let keys = &mut c.admin.keys;
                if keys.is_empty() || r.below(2) == 0 {
                    keys.push(crate::schema::AdminKey {
                        label: format!("k{}", r.below(3)),
                        secret: format!("s{}", r.below(3)),
                    });
                } else {
                    let i = r.below(keys.len());
                    keys[i].secret = format!("s{}", r.below(3));
                }
            }
            13 => c.hostname = format!("h{}", r.below(3)),
            14 => {
                let s = &mut c.logging.syslog;
                if s.is_empty() || r.below(2) == 0 {
                    s.push(crate::schema::SyslogServer {
                        name: format!("l{}", r.below(3)),
                        ..dflt()
                    });
                } else {
                    let i = r.below(s.len());
                    s[i].level = [None, Some(crate::log::LogLevel::Debug)][r.below(2)];
                }
            }
            _ => {
                c.ospf_instances = vec![OspfInstance {
                    name: "o".into(),
                    areas: vec![OspfArea {
                        profiles: vec![OspfProfile {
                            name: format!("p{}", r.below(2)),
                            cost: Some(u16::try_from(r.below(3)).unwrap()),
                            ..dflt()
                        }],
                        ..dflt()
                    }],
                    ..dflt()
                }];
            }
        }
    }

    /// #778: random edit sequences diff the same typed as through JSON.
    #[test]
    fn the_typed_diff_matches_the_full_json_walk() {
        let mut r = Rng(0x9e37_79b9_7f4a_7c15);
        // 300 rounds take tens of minutes under Miri; a few still cover the UB surface.
        for _ in 0..if cfg!(miri) { 3 } else { 300 } {
            let mut base = Config::default();
            for _ in 0..r.below(12) {
                mutate(&mut base, &mut r);
            }
            let mut cand = base.clone();
            for _ in 0..=r.below(4) {
                mutate(&mut cand, &mut r);
            }
            for (b, c) in [(&base, &cand), (&cand, &base), (&base, &base)] {
                assert_eq!(diff_configs(b, c), diff_configs_full(b, c), "{b:?}\n{c:?}");
            }
        }
    }

    /// A 22k-route instance with one route modified, added and removed.
    #[test]
    #[cfg_attr(miri, ignore = "22k-element list, minutes under the interpreter")]
    fn a_large_route_list_matches_the_full_walk() {
        let n = 22_000;
        let base = statics((0..n).map(|i| (i, 1)));
        let cand = statics(
            (0..n)
                .filter(|&i| i != 9)
                .map(|i| (i, if i == 3 { 2 } else { 1 }))
                .chain([(n, 1)]),
        );
        assert_eq!(diff_configs(&base, &cand), diff_configs_full(&base, &cand));
    }

    #[test]
    fn a_password_is_never_shown() {
        let cfg = |pw: &str| Config {
            users: vec![User {
                name: "u".into(),
                password: pw.into(),
            }],
            ..Default::default()
        };
        let d = diff_configs(&cfg("a"), &cfg("b"));
        assert_eq!(d.users[0].status, DiffStatus::Modified);
        let f = &d.users[0].fields[0];
        assert_eq!(
            (f.old.as_deref(), f.new.as_deref()),
            (Some("<hidden>"), Some("<changed>"))
        );
    }

    #[test]
    fn an_admin_secret_is_never_shown() {
        use crate::schema::{Admin, AdminKey};
        let cfg = |sec: &str| Config {
            admin: Admin {
                keys: vec![AdminKey {
                    label: "k".into(),
                    secret: sec.into(),
                }],
            },
            ..Default::default()
        };
        let d = diff_configs(&cfg("hunter2"), &cfg("hunter3"));
        assert!(!format!("{d:?}").contains("hunter"));
        assert_eq!(d.admin.len(), 1);
        assert_eq!(
            (d.admin[0].old.as_deref(), d.admin[0].new.as_deref()),
            (Some("<hidden>"), Some("<changed>"))
        );
    }
}
