/// Errors when another name in `names` is a different string that selects the
/// same list element (equal ignoring case, `-` and `_`, see
/// [`crate::config_path::key_matches`]); the error names that sibling.
pub fn no_normalized_collision<'a>(
    name: &str,
    mut names: impl Iterator<Item = &'a str>,
) -> garde::Result {
    match names.find(|o| *o != name && collides(o, name)) {
        Some(other) => Err(garde::Error::new(format!(
            "collides with '{other}': names are compared ignoring case, '-' and '_'"
        ))),
        None => Ok(()),
    }
}

/// `key_matches` with an ASCII byte fast path: validation compares every pair
/// of a list, so the common (ASCII, mismatching early) case must stay cheap.
fn collides(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        let n = |s: &str| {
            s.bytes()
                .filter(|c| *c != b'-' && *c != b'_')
                .map(|c| c.to_ascii_lowercase())
                .collect::<Vec<u8>>()
        };
        // ponytail: allocates per pair; O(n^2) names per commit, fine for real lists.
        return n(a) == n(b);
    }
    crate::config_path::key_matches(a, b)
}

/// `name` must appear once among `names` and collide with none of them
/// (exact repeat: "must be unique"; normalized-only: [`no_normalized_collision`]).
pub fn unique_name_in<'a>(
    name: &str,
    names: impl Iterator<Item = &'a str> + Clone,
) -> garde::Result {
    if names.clone().filter(|o| *o == name).count() > 1 {
        return Err(garde::Error::new("must be unique"));
    }
    no_normalized_collision(name, names)
}

/// List-element names are unique ignoring case, `-` and `_` (the selector's
/// rule, #633): a repeat or a collision with a sibling fails.
pub fn unique_key_in<T>(
    value: &(impl AsRef<str> + ?Sized),
    items: &[T],
    key: impl Fn(&T) -> &String,
) -> garde::Result {
    unique_name_in(value.as_ref(), items.iter().map(|i| key(i).as_str()))
}

/// No two addresses in the same list may repeat, mirroring
/// `static_routing_instance::unique_subnets`. Scoped to the owning list
/// only, since this uniqueness is per-parent (an `Interface`, a
/// `Subinterface`, a `BroadcastDomain`), not global. Compares `.address`
/// only — two entries can't have the same address with different labels
/// either, since `AddAddress` upserts by address.
pub fn unique_addresses(addresses: &[crate::schema::InterfaceAddress]) -> garde::Result {
    let mut seen: Vec<ipnet::IpNet> = Vec::new();
    for addr in addresses {
        if seen.contains(&addr.address) {
            return Err(garde::Error::new("must not repeat an address"));
        }
        seen.push(addr.address);
    }
    Ok(())
}

/// If set, `routing_table` must name an existing `RoutingTable`. There is no
/// single-owner constraint here — many interfaces/subinterfaces/broadcast
/// domains may be assigned to the same routing table/VRF.
pub fn routing_table_reference_valid(
    routing_table: Option<&String>,
    ctx: &crate::schema::Config,
) -> garde::Result {
    let Some(name) = routing_table else {
        return Ok(());
    };
    if !ctx.routing_tables.iter().any(|t| &t.name == name) {
        return Err(garde::Error::new("referenced routing table does not exist"));
    }
    Ok(())
}

/// If set, `bfd` must name an existing `BfdProfile`. Deleting a profile that
/// is still referenced makes every user fail this at commit, each under its
/// own path.
pub fn bfd_reference_valid(bfd: Option<&String>, ctx: &crate::schema::Config) -> garde::Result {
    let Some(name) = bfd else { return Ok(()) };
    if !ctx.bfd_profiles.iter().any(|p| &p.name == name) {
        return Err(garde::Error::new(format!(
            "bfd profile '{name}' does not exist"
        )));
    }
    Ok(())
}

/// If set, `stp_port_profile` must name an existing `StpPortProfile`. Like
/// `bfd_reference_valid`: deleting a referenced profile fails every user at
/// commit, each under its own path.
pub fn stp_port_profile_reference_valid(
    profile: Option<&String>,
    ctx: &crate::schema::Config,
) -> garde::Result {
    let Some(name) = profile else { return Ok(()) };
    if !ctx.stp_port_profiles.iter().any(|p| &p.name == name) {
        return Err(garde::Error::new(format!(
            "stp port profile '{name}' does not exist"
        )));
    }
    Ok(())
}

/// An S-BFD initiator profile (`mode sbfd`) probes the IPv4 address of its
/// peer unless `sbfd-remote-discriminator` names one: an IPv6 `peer` with
/// neither is refused. `peer` is where the attach point sends the session.
pub fn sbfd_peer_valid(
    bfd: Option<&String>,
    peer: std::net::IpAddr,
    ctx: &crate::schema::Config,
) -> garde::Result {
    use crate::schema::BfdMode;
    let Some(p) = bfd.and_then(|n| ctx.bfd_profiles.iter().find(|p| &p.name == n)) else {
        return Ok(());
    };
    if p.mode == BfdMode::Sbfd && peer.is_ipv6() && p.sbfd_remote_discriminator.is_none() {
        return Err(garde::Error::new(format!(
            "bfd profile '{}' is mode sbfd: an IPv6 peer needs sbfd-remote-discriminator",
            p.name
        )));
    }
    Ok(())
}

/// If set, `ospf_profile` must name an existing `OspfProfile`, flattened
/// across every instance's areas — mirrors `routing_table_reference_valid`
/// from the reference side, and `ospf_profile::unique_name` from the
/// declaration side.
pub fn ospf_profile_reference_valid(
    ospf_profile: Option<&String>,
    ctx: &crate::schema::Config,
) -> garde::Result {
    let Some(name) = ospf_profile else {
        return Ok(());
    };
    let exists = ctx
        .ospf_instances
        .iter()
        .flat_map(|i| &i.areas)
        .flat_map(|a| &a.profiles)
        .any(|p| &p.name == name);
    if !exists {
        return Err(garde::Error::new("referenced ospf profile does not exist"));
    }
    Ok(())
}

/// If set, `ospfv3_profile` must name an existing `Ospfv3Profile`, flattened
/// across every instance's areas — mirrors `ospf_profile_reference_valid`
/// exactly, over `ctx.ospfv3_instances` instead.
pub fn ospfv3_profile_reference_valid(
    ospfv3_profile: Option<&String>,
    ctx: &crate::schema::Config,
) -> garde::Result {
    let Some(name) = ospfv3_profile else {
        return Ok(());
    };
    let exists = ctx
        .ospfv3_instances
        .iter()
        .flat_map(|i| &i.areas)
        .flat_map(|a| &a.profiles)
        .any(|p| &p.name == name);
    if !exists {
        return Err(garde::Error::new(
            "referenced ospfv3 profile does not exist",
        ));
    }
    Ok(())
}

/// Returns a `garde` error unless `value` is composed only of ASCII
/// letters, digits, and hyphens, with no leading or trailing hyphen.
///
/// Not RFC-1123-exhaustive (no per-label length limit, no leading-digit
/// restriction) — just enough to keep obviously malformed hostnames out.
pub fn hostname_charset(value: &str) -> garde::Result {
    let valid_chars = value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    let valid_edges = !value.starts_with('-') && !value.ends_with('-');
    if !valid_chars || !valid_edges {
        return Err(garde::Error::new(
            "must contain only ASCII letters, digits, and hyphens, and must not start or end with a hyphen",
        ));
    }
    Ok(())
}

/// Object-name rule (#387): non-empty, only ASCII letters, digits, `_` and
/// `-`, and no leading `-` (a name may end up as an argv word or a path
/// component, so `/`, `..`, whitespace and control characters never pass).
pub fn name_charset(value: &str) -> garde::Result {
    let ok = !value.is_empty()
        && !value.starts_with('-')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !ok {
        return Err(garde::Error::new(
            "must contain only ASCII letters, digits, '_' and '-', and must not start with '-'",
        ));
    }
    Ok(())
}

/// `name_charset` plus the kernel's 15-byte `IFNAMSIZ` limit, for names that
/// become a netdev name.
pub fn device_name(value: &str) -> garde::Result {
    name_charset(value)?;
    if value.len() > 15 {
        return Err(garde::Error::new(
            "kernel interface name must be at most 15 characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_charset_accepts_and_rejects() {
        for ok in ["a", "rt1", "Peer_Group-2", "loopback-rt1"] {
            assert!(name_charset(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-x",
            "../../tmp/x",
            "a b",
            "a\nb",
            "a\u{1b}[31m",
            "a.b",
            "a:b",
            "é",
        ] {
            assert!(name_charset(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn device_name_caps_at_15() {
        assert!(device_name("abcdefghijklmno").is_ok());
        assert!(device_name("abcdefghijklmnop").is_err());
        assert!(device_name("a b").is_err());
    }

    #[test]
    fn hostname_charset_accepts_mixed_case_and_hyphen() {
        assert!(hostname_charset("Router-1").is_ok());
    }

    #[test]
    fn hostname_charset_rejects_leading_hyphen() {
        assert!(hostname_charset("-router").is_err());
    }

    #[test]
    fn hostname_charset_rejects_trailing_hyphen() {
        assert!(hostname_charset("router-").is_err());
    }

    #[test]
    fn hostname_charset_rejects_underscore() {
        assert!(hostname_charset("router_1").is_err());
    }

    #[test]
    fn hostname_charset_rejects_space() {
        assert!(hostname_charset("router 1").is_err());
    }

    fn names(v: &[&str], who: &str) -> garde::Result {
        let items: Vec<String> = v.iter().map(ToString::to_string).collect();
        unique_key_in(who, &items, |s| s)
    }

    #[test]
    fn unique_key_in_rules() {
        assert!(names(&["a", "b"], "a").is_ok());
        assert!(names(&["a"], "a").is_ok());
        assert!(names(&["pga", "x"], "pga").is_ok());
        assert!(format!("{:?}", names(&["a", "a"], "a").unwrap_err()).contains("must be unique"));
        for (a, b) in [("pga", "pg-a"), ("A_b", "ab"), ("Foo", "foo")] {
            for (me, other) in [(a, b), (b, a)] {
                let e = format!("{:?}", names(&[a, b, "zzz"], me).unwrap_err());
                assert!(e.contains(&format!("collides with '{other}'")), "{e}");
            }
        }
    }
}
