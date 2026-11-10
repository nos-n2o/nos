//! `set_transaction_path` at the cost of the edit, not of the config (#775).
//!
//! The path grammar (`nos_proto::config_path`) works on JSON. Instead of the
//! whole config, only the addressed top-level section, or one element of a
//! top-level list, goes through JSON and back into the typed `Config`; a
//! `static-routing-instance/<n>/route/<subnet>` edit touches one route. Every
//! fallible step runs on a read-only `&Config` and yields an infallible
//! [`Planned`] edit, so a failed edit leaves the transaction untouched.
//! [`edit_value`] is the whole-config route: an empty path uses it, and the
//! differential test holds the typed route to its exact results and errors.

use std::fmt::Write as _;

use nos_proto::config_path::{
    self, check_element_key, field_matches, find_field, select_key, ListPosition, PathError,
};
use nos_proto::{Config, User};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Map, Value};

use crate::error::ConfigError;
use crate::secrets::{restore_admin, restore_masked, restore_users};

/// What an edit does to the transaction's config once it is known to succeed.
pub(crate) enum Planned {
    /// Applied in place (`Arc::make_mut`) under the transactions lock.
    Apply(Box<dyn FnOnce(&mut Config) + Send>),
    /// The new user list: its clear passwords are hashed off-lock first.
    Users(Vec<User>),
    /// A whole new config (empty path).
    Whole(Box<Config>),
}

/// The edit at `path` of `cfg`, planned without touching it. `running` is
/// where a `<hidden>` secret is looked up after `cfg`.
pub(crate) fn plan(
    cfg: &Config,
    running: &Config,
    path: &[String],
    value: Option<Value>,
    pos: Option<&ListPosition>,
) -> Result<Planned, ConfigError> {
    if value.is_none() && pos.is_some() {
        return Err(PathError::Invalid("a position needs a value".to_string()).into());
    }
    let Some(seg) = path.first() else {
        return edit_value(cfg, running, path, value, pos).map(|c| Planned::Whole(Box::new(c)));
    };
    let field = find_field(SECTIONS, seg).ok_or_else(|| PathError::NotFound(seg.clone()))?;
    match field {
        "users" => {
            let mut users = cfg.users.clone();
            top_list(
                field,
                &cfg.users,
                |u, buf| buf.push_str(&u.name),
                path,
                value,
                pos,
            )?
            .apply(&mut users);
            restore_users(&mut users, &[cfg, running])?;
            Ok(Planned::Users(users))
        }
        "admin" => {
            let mut admin = plan_field(field, &cfg.admin, path, value, pos)?;
            restore_admin(&mut admin, &[cfg, running])?;
            Ok(Planned::Apply(Box::new(move |c| c.admin = admin)))
        }
        "static_routing_instances" if path.len() >= 4 && field_matches("routes", &path[2]) => {
            let instances = &cfg.static_routing_instances;
            match select_key(instances, &path[1], |s, buf| buf.push_str(&s.name))? {
                Some(i) => {
                    let name = instances[i].name.clone();
                    let edit = plan_list(
                        &instances[i].routes,
                        |r, buf| {
                            let _ = write!(buf, "{}", r.subnet);
                        },
                        path,
                        3,
                        value,
                        pos,
                        |r| {
                            let mut inst = Map::new();
                            inst.insert("name".into(), Value::String(name));
                            inst.insert("routes".into(), Value::Array(vec![r]));
                            wrap(field, Value::Object(inst))
                        },
                        "/static_routing_instances/0/routes/0",
                    )?;
                    Ok(Planned::Apply(Box::new(move |c| {
                        edit.apply(&mut c.static_routing_instances[i].routes);
                    })))
                }
                None => plan_section(cfg, field, path, value, pos).map(Planned::Apply),
            }
        }
        _ => plan_section(cfg, field, path, value, pos).map(Planned::Apply),
    }
}

/// The whole-config route: the config through JSON, edited, and back.
pub(crate) fn edit_value(
    cfg: &Config,
    running: &Config,
    path: &[String],
    value: Option<Value>,
    pos: Option<&ListPosition>,
) -> Result<Config, ConfigError> {
    let mut doc = serde_json::to_value(cfg)?;
    apply_value(&mut doc, path, value, pos)?;
    let mut new: Config = serde_json::from_value(doc)?;
    // A GET-then-PUT round trip carries the REST mask where secrets were.
    restore_masked(&mut new, &[cfg, running])?;
    Ok(new)
}

fn apply_value(
    doc: &mut Value,
    path: &[String],
    value: Option<Value>,
    pos: Option<&ListPosition>,
) -> Result<(), PathError> {
    match value {
        Some(v) => config_path::set_at(doc, path, v, pos),
        None if pos.is_some() => Err(PathError::Invalid("a position needs a value".to_string())),
        None => config_path::remove(doc, path),
    }
}

/// `{field: [element]}`: the root a path resolves against, cut down to the
/// one element it addresses.
fn wrap(field: &str, element: Value) -> Value {
    let mut root = Map::new();
    root.insert(field.to_string(), Value::Array(vec![element]));
    Value::Object(root)
}

/// One list edit, decided before anything changes.
pub(crate) enum ListEdit<E> {
    Replace(usize, E),
    Remove(usize),
    /// Removes `own` (an existing element being moved) then inserts at `at`.
    Insert {
        own: Option<usize>,
        at: usize,
        value: E,
    },
    All(Vec<E>),
}

impl<E> ListEdit<E> {
    fn apply(self, items: &mut Vec<E>) {
        match self {
            Self::Replace(i, v) => items[i] = v,
            Self::Remove(i) => {
                items.remove(i);
            }
            Self::Insert { own, at, value } => {
                if let Some(i) = own {
                    items.remove(i);
                }
                items.insert(at.min(items.len()), value);
            }
            Self::All(v) => *items = v,
        }
    }
}

/// A whole section (any depth inside it) through JSON and back: O(section).
fn plan_field<T: Serialize + DeserializeOwned>(
    field: &str,
    cur: &T,
    path: &[String],
    value: Option<Value>,
    pos: Option<&ListPosition>,
) -> Result<T, ConfigError> {
    if let (1, Some(v), None) = (path.len(), &value, pos) {
        // Replacing the section outright: nothing of the old one is needed.
        return Ok(serde_json::from_value(v.clone())?);
    }
    let mut root = Map::new();
    root.insert(field.to_string(), serde_json::to_value(cur)?);
    let mut doc = Value::Object(root);
    apply_value(&mut doc, path, value, pos)?;
    Ok(serde_json::from_value(doc[field].take())?)
}

/// A top-level list keyed by name: the whole list, or one element.
fn top_list<E: Serialize + DeserializeOwned + Clone>(
    field: &str,
    items: &Vec<E>,
    key_of: impl FnMut(&E, &mut String),
    path: &[String],
    value: Option<Value>,
    pos: Option<&ListPosition>,
) -> Result<ListEdit<E>, ConfigError> {
    if path.len() == 1 {
        return plan_field(field, items, path, value, pos).map(ListEdit::All);
    }
    let ptr = format!("/{field}/0");
    plan_list(items, key_of, path, 1, value, pos, |e| wrap(field, e), &ptr)
}

/// The edit of list element `path[k]` of `items` (`is` says whether an
/// element has a key), with `set_at`'s semantics: replace in place or
/// append, (re)insert at `pos`, remove; a longer path edits inside the
/// element through JSON, `wrap` rebuilding the path's root around it and
/// `ptr` pointing back at it.
#[allow(
    clippy::too_many_arguments,
    reason = "one internal helper, two callers"
)]
fn plan_list<E: Serialize + DeserializeOwned>(
    items: &[E],
    mut key_of: impl FnMut(&E, &mut String),
    path: &[String],
    k: usize,
    value: Option<Value>,
    pos: Option<&ListPosition>,
    wrap: impl FnOnce(Value) -> Value,
    ptr: &str,
) -> Result<ListEdit<E>, ConfigError> {
    let key = &path[k];
    let own = select_key(items, key, &mut key_of)?;
    if path.len() > k + 1 {
        let i = own.ok_or_else(|| PathError::NotFound(path[..=k].join("/")))?;
        let mut doc = wrap(serde_json::to_value(&items[i])?);
        apply_value(&mut doc, path, value, pos)?;
        let v = doc.pointer_mut(ptr).map(Value::take).unwrap_or_default();
        return Ok(ListEdit::Replace(i, serde_json::from_value(v)?));
    }
    let Some(value) = value else {
        let i = own.ok_or_else(|| PathError::NotFound(path.join("/")))?;
        return Ok(ListEdit::Remove(i));
    };
    check_element_key(&value, key)?;
    let at = match pos {
        None => None,
        Some(p) => Some(position(items, &mut key_of, own, p)?),
    };
    let value = serde_json::from_value(value)?;
    Ok(match (own, at) {
        (Some(i), None) => ListEdit::Replace(i, value),
        (own, at) => ListEdit::Insert {
            own,
            at: at.unwrap_or(items.len()),
            value,
        },
    })
}

/// Where a positioned element lands once its own old slot (if any) is gone.
fn position<E>(
    items: &[E],
    key_of: &mut impl FnMut(&E, &mut String),
    own: Option<usize>,
    pos: &ListPosition,
) -> Result<usize, PathError> {
    let anchor = match pos {
        ListPosition::Before(a) | ListPosition::After(a) => {
            let idx = select_key(items, a, &mut *key_of)?
                .ok_or_else(|| PathError::NotFound(a.clone()))?;
            if Some(idx) == own {
                return Err(PathError::Invalid(
                    "cannot position an element relative to itself".to_string(),
                ));
            }
            Some(idx)
        }
        _ => None,
    };
    let at = match (pos, anchor) {
        (ListPosition::First, _) => 0,
        (ListPosition::Before(_), Some(a)) => a,
        (ListPosition::After(_), Some(a)) => a + 1,
        _ => items.len(),
    };
    Ok(match own {
        Some(i) if i < at => at - 1,
        _ => at,
    })
}

/// Every top-level `Config` field, by kind: `lists` are keyed by `name`.
/// `users` and `admin` are planned in [`plan`] (masks, hashing).
macro_rules! sections {
    (lists: $($l:ident),* ; fields: $($f:ident),* ; special: $($s:ident),*) => {
        /// The serde names of every `Config` field (a test checks the list).
        const SECTIONS: &[&str] =
            &[$(stringify!($l),)* $(stringify!($f),)* $(stringify!($s),)*];

        fn plan_section(
            cfg: &Config,
            field: &str,
            path: &[String],
            value: Option<Value>,
            pos: Option<&ListPosition>,
        ) -> Result<Box<dyn FnOnce(&mut Config) + Send>, ConfigError> {
            match field {
                $(stringify!($l) => {
                    let edit = top_list(
                        field, &cfg.$l, |e, buf| buf.push_str(&e.name), path, value, pos,
                    )?;
                    Ok(Box::new(move |c: &mut Config| edit.apply(&mut c.$l)))
                })*
                $(stringify!($f) => {
                    let v = plan_field(field, &cfg.$f, path, value, pos)?;
                    Ok(Box::new(move |c: &mut Config| c.$f = v))
                })*
                _ => unreachable!("{field} is planned by `plan`"),
            }
        }

        /// `{field: ...}` cut down to what `path` addresses: the section, or
        /// the one list element `path[1]` names (an empty list if none).
        fn section_doc(cfg: &Config, field: &str, path: &[String]) -> Result<Value, ConfigError> {
            let elem = |v: Value| -> Result<Value, ConfigError> { Ok(wrap(field, v)) };
            match field {
                $(stringify!($l) => match path.get(1) {
                    None => Ok(json_field(field, serde_json::to_value(&cfg.$l)?)),
                    Some(k) => match select_key(&cfg.$l, k, |e, buf| buf.push_str(&e.name))?
                        .map(|i| &cfg.$l[i])
                    {
                        Some(e) => elem(serde_json::to_value(e)?),
                        None => Ok(json_field(field, Value::Array(Vec::new()))),
                    },
                },)*
                $(stringify!($f) => Ok(json_field(field, serde_json::to_value(&cfg.$f)?)),)*
                _ => unreachable!("every section is listed"),
            }
        }
    };
}

sections! {
    lists: bgp_instances, routing_tables, ospf_instances, ospfv3_instances,
        static_routing_instances, interfaces, policy_definitions, community_aliases,
        community_groups, prefix_lists, as_path_lists, broadcast_domains,
        switching_profiles, port_aggregates, bfd_profiles, stp_port_profiles, acls, users;
    fields: hostname, lldp, logging, sbfd_reflector, spanning_tree, admin;
    special:
}

fn json_field(field: &str, v: Value) -> Value {
    let mut root = Map::new();
    root.insert(field.to_string(), v);
    Value::Object(root)
}

/// The subsection of `cfg` at `path` as `config_path::get` reads it from
/// the whole config, serializing only its section, list element or static
/// route: the reply of an edit costs the edit (#774).
pub(crate) fn get(cfg: &Config, path: &[String]) -> Result<Value, ConfigError> {
    let Some(seg) = path.first() else {
        return Ok(serde_json::to_value(cfg)?);
    };
    let field = find_field(SECTIONS, seg).ok_or_else(|| PathError::NotFound(seg.clone()))?;
    let mut route = None;
    if field == "static_routing_instances" && path.len() >= 4 && field_matches("routes", &path[2]) {
        let insts = &cfg.static_routing_instances;
        if let Some(inst) =
            select_key(insts, &path[1], |s, buf| buf.push_str(&s.name))?.map(|i| &insts[i])
        {
            route = select_key(&inst.routes, &path[3], |r, buf| {
                let _ = write!(buf, "{}", r.subnet);
            })?
            .map(|i| (inst, &inst.routes[i]));
        }
    }
    let doc = match route {
        Some((inst, r)) => {
            let mut i = Map::new();
            i.insert("name".into(), Value::String(inst.name.clone()));
            i.insert(
                "routes".into(),
                Value::Array(vec![serde_json::to_value(r)?]),
            );
            wrap(field, Value::Object(i))
        }
        None => section_doc(cfg, field, path)?,
    };
    Ok(config_path::get(&doc, path)?.clone())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The config as the typed route leaves it.
    fn typed(
        cfg: &Config,
        running: &Config,
        path: &[String],
        value: Option<Value>,
        pos: Option<&ListPosition>,
    ) -> Result<Config, ConfigError> {
        Ok(match plan(cfg, running, path, value, pos)? {
            Planned::Apply(apply) => {
                let mut c = cfg.clone();
                apply(&mut c);
                c
            }
            Planned::Users(users) => Config {
                users,
                ..cfg.clone()
            },
            Planned::Whole(c) => *c,
        })
    }

    fn route(subnet: &str) -> Value {
        let gateway = if subnet.contains(':') {
            "2001:db8::1"
        } else {
            "192.0.2.1"
        };
        json!({"subnet": subnet, "gateway": gateway, "bfd": null})
    }

    fn start() -> Config {
        let mut doc = serde_json::to_value(Config::default()).unwrap();
        let Value::Object(fields) = json!({
            "hostname": "nos",
            "static_routing_instances": [
                {"name": "s0", "routes": [route("10.0.0.0/8"), route("10.1.0.0/16"), route("2001:db8::/32")]},
                {"name": "s1", "routes": [route("10.0.0.0/8")]},
            ],
            "prefix_lists": [{"name": "pl", "entries": [{"cidr": "10.0.0.0/8", "range": null}]}],
            "community_aliases": [{"name": "a1", "value": "65000:1"}],
            "users": [{"name": "u1", "password": "$argon2id$x"}],
            "admin": {"keys": [{"label": "k1", "secret": "s"}]},
        }) else {
            unreachable!()
        };
        for (k, v) in fields {
            doc[k] = v;
        }
        serde_json::from_value(doc).unwrap()
    }

    fn segs(p: &[&str]) -> Vec<String> {
        p.iter().map(|x| (*x).to_string()).collect()
    }

    /// xorshift64: deterministic, no dependency.
    struct Rng(u64);

    impl Rng {
        fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            &xs[usize::try_from(self.0 % xs.len() as u64).unwrap()]
        }
    }

    const INSTANCES: &[&str] = &["s0", "s1", "S1", "s9"];
    const SUBNETS: &[&str] = &[
        "10.0.0.0/8",
        "10.1.0.0/16",
        "10.2.0.0/16",
        "2001:DB8::/32",
        "2001:db8::/32",
    ];

    /// One random edit: a path, a good, bad or missing value, a position.
    fn edit(r: &mut Rng) -> (Vec<String>, Option<Value>, Option<ListPosition>) {
        let inst = *r.pick(INSTANCES);
        let sub = *r.pick(SUBNETS);
        let other = *r.pick(SUBNETS);
        let srt = "static-routing-instance";
        let (path, good, bad) = match r.pick(&[0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13])
        {
            0 => (segs(&[srt, inst, "route", sub]), route(sub), route(other)),
            1 => (
                segs(&[srt, inst, "route", sub, "gateway"]),
                json!("192.0.2.9"),
                json!(5),
            ),
            2 => (
                segs(&[srt, inst, "route", sub, "bfd"]),
                json!("b"),
                json!([1]),
            ),
            3 => (
                segs(&[srt, inst]),
                json!({"name": inst, "routes": [route(sub)]}),
                json!({"name": "zz"}),
            ),
            4 => (segs(&[srt, inst, "route"]), json!([route(sub)]), json!({})),
            5 => (segs(&[srt]), json!([]), json!(7)),
            6 => (segs(&["hostname"]), json!("h"), json!(null)),
            7 => (
                segs(&["prefix-list", "pl", "entry", sub]),
                json!({"cidr": sub, "range": null}),
                json!({"cidr": other}),
            ),
            8 => (
                segs(&["user", "u1"]),
                json!({"name": "u1", "password": "<hidden>"}),
                json!({"name": "u1", "password": 3}),
            ),
            9 => (
                segs(&["admin", "key", "k1"]),
                json!({"label": "k1", "secret": "<hidden>"}),
                json!({"label": "k2", "secret": "<hidden>"}),
            ),
            10 => (
                segs(&["community-alias", "a1"]),
                json!({"name": "a1", "value": "65000:2"}),
                json!({"name": "a1"}),
            ),
            11 => (segs(&["bogus", "x"]), json!(1), json!(2)),
            12 => (
                Vec::new(),
                serde_json::to_value(start()).unwrap(),
                json!({"hostname": 1}),
            ),
            _ => (segs(&["lldp", "tx-hold"]), json!(4), json!("x")),
        };
        let value = r
            .pick(&[Some(good.clone()), Some(good), Some(bad), None])
            .clone();
        let anchor = (*r.pick(SUBNETS)).to_string();
        let pos = r
            .pick(&[
                None,
                None,
                None,
                Some(ListPosition::First),
                Some(ListPosition::Last),
                Some(ListPosition::Before(anchor.clone())),
                Some(ListPosition::After(anchor)),
                Some(ListPosition::After(inst.to_string())),
            ])
            .clone();
        (path, value, pos)
    }

    #[test]
    fn typed_edits_match_the_whole_config_route() {
        let running = start();
        let (mut ok, mut err) = (0, 0);
        for seed in 1..=300_u64 {
            let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut cfg = start();
            for _ in 0..30 {
                let (path, value, pos) = edit(&mut r);
                let want = edit_value(&cfg, &running, &path, value.clone(), pos.as_ref());
                let got = typed(&cfg, &running, &path, value.clone(), pos.as_ref());
                let ctx = format!("seed {seed}: {path:?} {value:?} {pos:?}");
                match (want, got) {
                    (Ok(w), Ok(g)) => {
                        assert_eq!(w, g, "{ctx}");
                        if value.is_some() {
                            // The edit's reply reads what the whole config holds there.
                            let whole = serde_json::to_value(&g).unwrap();
                            let want = config_path::get(&whole, &path).unwrap();
                            assert_eq!(&get(&g, &path).unwrap(), want, "{ctx}");
                        }
                        cfg = g;
                        ok += 1;
                    }
                    (Err(w), Err(g)) => {
                        assert_eq!(w.to_string(), g.to_string(), "{ctx}");
                        err += 1;
                    }
                    (w, g) => panic!("{ctx}: whole-config {w:?}, typed {g:?}"),
                }
            }
        }
        // Both outcomes are well exercised.
        assert!(ok > 1000 && err > 1000, "ok {ok} err {err}");
    }

    #[test]
    fn sections_name_every_config_field() {
        let Value::Object(fields) = serde_json::to_value(Config::default()).unwrap() else {
            panic!("a config serializes as an object");
        };
        let mut want: Vec<&str> = fields.keys().map(String::as_str).collect();
        let mut got = SECTIONS.to_vec();
        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn a_route_edit_touches_one_list_and_a_failed_one_nothing() {
        let cfg = start();
        let path = segs(&["static-routing-instance", "s1", "route", "10.9.0.0/16"]);
        let bad = json!({"subnet": "10.8.0.0/16", "gateway": "192.0.2.1"});
        assert!(plan(&cfg, &cfg, &path, Some(bad), None).is_err());
        let first = Some(&ListPosition::First);
        let Ok(Planned::Apply(apply)) = plan(&cfg, &cfg, &path, Some(route("10.9.0.0/16")), first)
        else {
            panic!("a route edit applies in place");
        };
        let mut c = cfg.clone();
        apply(&mut c);
        let routes = &c.static_routing_instances[1].routes;
        assert_eq!(routes[0].subnet.to_string(), "10.9.0.0/16");
        assert_eq!(routes.len(), 2);
        assert_eq!(
            c.static_routing_instances[0],
            cfg.static_routing_instances[0]
        );
    }

    #[test]
    fn exact_key_wins_and_ambiguous_selector_fails_without_a_change() {
        let mut cfg = start();
        cfg.community_aliases = serde_json::from_value(json!([
            {"name": "pga", "value": "65000:1"}, {"name": "pg-a", "value": "65000:2"}
        ]))
        .unwrap();
        cfg.users = serde_json::from_value(json!([
            {"name": "ua", "password": "$argon2id$x"}, {"name": "u-a", "password": "$argon2id$x"}
        ]))
        .unwrap();
        for (seg, field) in [("community-alias", 0), ("user", 1)] {
            let err = |sel: &str, value: Option<Value>| match plan(
                &cfg,
                &cfg,
                &segs(&[seg, sel]),
                value,
                None,
            ) {
                Err(e) => e.to_string(),
                Ok(_) => panic!("{seg}/{sel} should be ambiguous"),
            };
            let alias = if field == 0 { "PGA" } else { "UA" };
            let name = if field == 0 { "pg-a" } else { "u-a" };
            assert!(err(alias, None).contains("ambiguous key"));
            assert!(err(alias, Some(json!({"name": alias, "value": "65000:3"})))
                .contains("ambiguous key"));
            let c = typed(&cfg, &cfg, &segs(&[seg, name]), None, None).unwrap();
            let left: Vec<String> = if field == 0 {
                c.community_aliases.iter().map(|a| a.name.clone()).collect()
            } else {
                c.users.iter().map(|a| a.name.clone()).collect()
            };
            assert_eq!(left.len(), 1);
            assert_ne!(left[0], name);
        }
        assert!(get(&cfg, &segs(&["community-alias", "PGA"])).is_err());
        assert_eq!(
            get(&cfg, &segs(&["community-alias", "pg-a"])).unwrap()["name"],
            "pg-a"
        );
    }
}
