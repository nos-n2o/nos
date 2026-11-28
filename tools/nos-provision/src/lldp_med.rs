//! `--lldp-med-*` (#1570): an LLDP-MED profile with its policies, `PoE` and
//! `advertise-always`, plus a per-port location, all on the base `--interface`.
//! One typed fixture feeds the `ConfigOp`, the path edits and the local `Config`
//! edit, so the three can't drift (a test replays them against each other).

use anyhow::{anyhow, bail, Context};
use nos_proto::schema::{
    Config, LldpCivicAddress, LldpCivicElement, LldpCoordinate, LldpLocation, LldpMedNetworkPolicy,
    LldpMedPoe, LldpMedProfile,
};

use crate::Args;

/// The profile created when only a location/policy flag names none.
pub const DEFAULT_PROFILE: &str = "e2e-med";

pub struct Fixture {
    pub profile: LldpMedProfile,
    pub location: Option<LldpLocation>,
}

/// `kebab-case` as the `PascalCase` serde name of an enum variant.
fn pascal(s: &str) -> String {
    s.split('-')
        .map(|w| {
            let mut c = w.chars();
            c.next().map_or_else(String::new, |f| {
                f.to_uppercase().chain(c).collect::<String>()
            })
        })
        .collect()
}

fn word<T: serde::de::DeserializeOwned>(s: &str, what: &str) -> anyhow::Result<T> {
    serde_json::from_value(serde_json::Value::String(pascal(s)))
        .map_err(|_| anyhow!("bad {what} '{s}'"))
}

fn policy(flag: &str) -> anyhow::Result<LldpMedNetworkPolicy> {
    let f: Vec<&str> = flag.split(':').collect();
    if !(4..=5).contains(&f.len()) || f.get(4).is_some_and(|t| *t != "tagged") {
        bail!("--lldp-med-policy wants <app>:<vlan>:<priority>:<dscp>[:tagged], got '{flag}'");
    }
    Ok(LldpMedNetworkPolicy {
        app_type: word(f[0], "application type")?,
        vlan: (!f[1].is_empty()).then(|| f[1].parse()).transpose()?,
        priority: f[2].parse()?,
        dscp: f[3].parse()?,
        tagged: f.len() == 5,
        unknown: false,
    })
}

fn poe(flag: &str) -> anyhow::Result<LldpMedPoe> {
    let f: Vec<&str> = flag.split(':').collect();
    let [source, priority, power] = f[..] else {
        bail!("--lldp-med-poe wants <source>:<priority>:<tenth-watts>, got '{flag}'");
    };
    Ok(LldpMedPoe {
        source: word(source, "poe source")?,
        priority: word(priority, "poe priority")?,
        power: power.parse()?,
    })
}

fn civic(flag: &str) -> anyhow::Result<LldpCivicAddress> {
    let (country, elements) = flag.split_once(':').unwrap_or((flag, ""));
    let elements = elements
        .split(',')
        .filter(|e| !e.is_empty())
        .map(|e| {
            let (t, v) = e
                .split_once('=')
                .with_context(|| format!("--lldp-med-civic element '{e}' is not <ca>=<value>"))?;
            Ok(LldpCivicElement {
                ca_type: t.parse()?,
                value: v.to_string(),
            })
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(LldpCivicAddress {
        what: 2,
        country: country.to_string(),
        elements,
    })
}

fn coordinate(flag: &str) -> anyhow::Result<LldpCoordinate> {
    let f: Vec<&str> = flag.split(':').collect();
    if !(2..=3).contains(&f.len()) {
        bail!("--lldp-med-coordinate wants <lat>:<long>[:<alt>], got '{flag}'");
    }
    Ok(LldpCoordinate {
        latitude: f[0].to_string(),
        longitude: f[1].to_string(),
        altitude: f.get(2).map(ToString::to_string),
        altitude_resolution: if f.len() == 3 { 30 } else { 0 },
        ..Default::default()
    })
}

/// The fixture the flags describe; `None` when none is given. Fails on a
/// malformed flag (called from `build_ops` through [`check`]).
pub fn fixture(args: &Args) -> anyhow::Result<Option<Fixture>> {
    let location = if args.lldp_med_elin.is_some()
        || args.lldp_med_civic.is_some()
        || args.lldp_med_coordinate.is_some()
    {
        Some(LldpLocation {
            elin: args.lldp_med_elin.clone(),
            civic: args
                .lldp_med_civic
                .as_deref()
                .map(civic)
                .transpose()?
                .unwrap_or_default(),
            coordinate: args
                .lldp_med_coordinate
                .as_deref()
                .map(coordinate)
                .transpose()?
                .unwrap_or_default(),
        })
    } else {
        None
    };
    let named = args.lldp_med_profile.clone();
    let any = named.is_some()
        || location.is_some()
        || !args.lldp_med_policy.is_empty()
        || args.lldp_med_poe.is_some()
        || args.lldp_med_advertise_always;
    if !any {
        return Ok(None);
    }
    Ok(Some(Fixture {
        profile: LldpMedProfile {
            name: named.unwrap_or_else(|| DEFAULT_PROFILE.to_string()),
            network_policies: args
                .lldp_med_policy
                .iter()
                .map(|p| policy(p))
                .collect::<anyhow::Result<_>>()?,
            poe: args.lldp_med_poe.as_deref().map(poe).transpose()?,
            advertise_always: args.lldp_med_advertise_always,
        },
        location,
    }))
}

/// Every `--lldp-med-*` flag parses.
pub fn check(args: &Args) -> anyhow::Result<()> {
    fixture(args).map(drop)
}

/// The interface the profile and location attach to: `--link-interface`, else `--interface`.
fn target(args: &Args) -> &str {
    args.link_interface.as_ref().unwrap_or(&args.interface)
}

/// The path edits (applied after the ops, which `Ensure` the profile).
pub fn paths(args: &Args) -> Vec<(Vec<String>, Option<String>)> {
    if args.no_lldp_med_profile {
        let path = |leaf: &str| {
            vec![
                "interface".to_string(),
                target(args).to_string(),
                leaf.to_string(),
            ]
        };
        // The location first: a location without a profile is refused.
        return vec![(path("lldp-location"), None), (path("lldp-med-profile"), None)];
    }
    let Some(f) = fixture(args).ok().flatten() else {
        return Vec::new();
    };
    let mut v = vec![
        (
            vec!["lldp-med-profile".to_string(), f.profile.name.clone()],
            Some(json(&f.profile)),
        ),
        (
            vec![
                "interface".to_string(),
                target(args).to_string(),
                "lldp-med-profile".to_string(),
            ],
            Some(format!("\"{}\"", f.profile.name)),
        ),
    ];
    if let Some(l) = &f.location {
        v.push((
            vec![
                "interface".to_string(),
                target(args).to_string(),
                "lldp-location".to_string(),
            ],
            Some(json(l)),
        ));
    }
    v
}

/// The same edits applied straight to a local `Config`.
pub fn apply(args: &Args, config: &mut Config) {
    if args.no_lldp_med_profile {
        for i in config.interfaces.iter_mut().filter(|i| i.name == target(args)) {
            i.lldp_med_profile = None;
            i.lldp_location = LldpLocation::default();
        }
        return;
    }
    let Some(f) = fixture(args).ok().flatten() else {
        return;
    };
    config
        .lldp_med_profiles
        .retain(|p| p.name != f.profile.name);
    let name = f.profile.name.clone();
    config.lldp_med_profiles.push(f.profile);
    for i in config
        .interfaces
        .iter_mut()
        .filter(|i| i.name == target(args))
    {
        i.lldp_med_profile = Some(name.clone());
        if let Some(l) = &f.location {
            i.lldp_location.clone_from(l);
        }
    }
}

fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("schema types serialize")
}
