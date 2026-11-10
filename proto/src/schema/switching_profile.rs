use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::spanning_tree::valid_port_priority;
use super::Config;
use nos_proto_derive::Cli;

/// A dot1q tag, or the absence of one. `Dot1q`'s value is restricted to
/// `1..=4094` — 802.1Q reserves 0 and 4095.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub enum VlanTag {
    #[default]
    /// Frames carry no VLAN tag.
    Untagged,
    /// Frames carry this 802.1Q tag, 1 to 4094.
    Dot1q(u16),
}

/// One broadcast domain's membership in a `SwitchingProfile`, tagged as
/// either a specific dot1q VLAN or untagged.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct SwitchingProfileMember {
    #[garde(custom(|bd: &String, ctx: &Config| broadcast_domain_reference_valid(bd, ctx)))]
    #[cli(key)]
    /// Name of the member `BroadcastDomain`; the key.
    pub broadcast_domain: String,

    #[garde(custom(|t: &VlanTag, _ctx: &Config| valid_vlan_tag(*t)))]
    #[cli(topic = SwitchingProfileMember)]
    /// How the member's frames are tagged on the port.
    pub tag: VlanTag,

    /// Spanning-tree port cost for the ports using this membership; `None`:
    /// the profile's or automatic. Inert until `nos-stpd`.
    #[serde(default)]
    #[garde(inner(range(min = 1, max = 200_000_000)))]
    #[cli(topic = SwitchingProfileMemberStpCost, words = "stp-cost")]
    pub stp_cost: Option<u32>,

    /// Spanning-tree port priority for this membership; a multiple of 16.
    #[serde(default)]
    #[garde(inner(custom(|p: &u8, _ctx: &Config| valid_port_priority(*p))))]
    #[cli(topic = SwitchingProfileMemberStpPriority, words = "stp-priority")]
    pub stp_priority: Option<u8>,
}

fn broadcast_domain_reference_valid(broadcast_domain: &str, ctx: &Config) -> garde::Result {
    if ctx
        .broadcast_domains
        .iter()
        .any(|d| d.name == broadcast_domain)
    {
        Ok(())
    } else {
        Err(garde::Error::new(
            "referenced broadcast domain does not exist",
        ))
    }
}

fn valid_vlan_tag(tag: VlanTag) -> garde::Result {
    match tag {
        VlanTag::Untagged => Ok(()),
        VlanTag::Dot1q(id) if (1..=4094).contains(&id) => Ok(()),
        VlanTag::Dot1q(_) => Err(garde::Error::new("dot1q tag must be between 1 and 4094")),
    }
}

/// A named, trunk-style container mapping multiple broadcast domains to
/// their dot1q tagging. Will be assigned to a future "switched interface"
/// config object — not modeled yet.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct SwitchingProfile {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.switching_profiles, |p| &p.name))
    )]
    #[cli(key)]
    /// Profile name, 1 to 64 characters (letters, digits, `_`, `-`), unique among switching profiles.
    pub name: String,

    #[garde(dive, custom(|members, _ctx: &Config| unique_broadcast_domains(members)))]
    #[cli(topic = SwitchingProfileMember, words = "broadcast-domain")]
    /// Broadcast domains a port using this profile carries.
    pub members: Vec<SwitchingProfileMember>,
}

/// No two members of the same profile may reference the same broadcast
/// domain — a domain either participates in a profile once or not at all.
/// Scoped to `self.members` only, same as
/// `static_routing_instance::unique_subnets`.
fn unique_broadcast_domains(members: &[SwitchingProfileMember]) -> garde::Result {
    let mut seen: Vec<&str> = Vec::new();
    for m in members {
        if seen.contains(&m.broadcast_domain.as_str()) {
            return Err(garde::Error::new(
                "must not repeat a broadcast domain within the same switching profile",
            ));
        }
        seen.push(&m.broadcast_domain);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::BroadcastDomain;

    fn member(broadcast_domain: &str, tag: VlanTag) -> SwitchingProfileMember {
        SwitchingProfileMember {
            broadcast_domain: broadcast_domain.to_string(),
            tag,
            ..Default::default()
        }
    }

    fn config_with(profiles: Vec<SwitchingProfile>, domains: Vec<BroadcastDomain>) -> Config {
        Config {
            switching_profiles: profiles,
            broadcast_domains: domains,
            ..Default::default()
        }
    }

    fn domain(name: &str) -> BroadcastDomain {
        BroadcastDomain {
            ospfv3_profile: None,
            vni: None,
            rd: None,
            route_targets_import: Vec::new(),
            route_targets_export: Vec::new(),
            vtep_source: None,
            mac_redistribute: None,
            arp_redistribute: None,
            connected_redistribute: None,
            neigh_suppress: false,
            max_remote_macs: None,
            stp_instance: None,
            stp_priority: None,
            stp_hello_time: None,
            stp_max_age: None,
            stp_forward_delay: None,
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
        }
    }

    #[test]
    fn valid_profile_with_no_members_passes() {
        let cfg = config_with(
            vec![SwitchingProfile {
                name: "sp1".to_string(),
                members: Vec::new(),
            }],
            vec![],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn valid_profile_with_multiple_members_passes() {
        let cfg = config_with(
            vec![SwitchingProfile {
                name: "sp1".to_string(),
                members: vec![
                    member("bd1", VlanTag::Dot1q(100)),
                    member("bd2", VlanTag::Untagged),
                ],
            }],
            vec![domain("bd1"), domain("bd2")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_profile_name_fails() {
        let cfg = config_with(
            vec![
                SwitchingProfile {
                    name: "sp1".to_string(),
                    members: Vec::new(),
                },
                SwitchingProfile {
                    name: "sp1".to_string(),
                    members: Vec::new(),
                },
            ],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dangling_broadcast_domain_reference_fails() {
        let cfg = config_with(
            vec![SwitchingProfile {
                name: "sp1".to_string(),
                members: vec![member("does-not-exist", VlanTag::Untagged)],
            }],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_broadcast_domain_within_profile_fails() {
        let cfg = config_with(
            vec![SwitchingProfile {
                name: "sp1".to_string(),
                members: vec![
                    member("bd1", VlanTag::Dot1q(100)),
                    member("bd1", VlanTag::Dot1q(200)),
                ],
            }],
            vec![domain("bd1")],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn same_broadcast_domain_across_different_profiles_passes() {
        let cfg = config_with(
            vec![
                SwitchingProfile {
                    name: "sp1".to_string(),
                    members: vec![member("bd1", VlanTag::Dot1q(100))],
                },
                SwitchingProfile {
                    name: "sp2".to_string(),
                    members: vec![member("bd1", VlanTag::Dot1q(100))],
                },
            ],
            vec![domain("bd1")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dot1q_tag_zero_fails() {
        let cfg = config_with(
            vec![SwitchingProfile {
                name: "sp1".to_string(),
                members: vec![member("bd1", VlanTag::Dot1q(0))],
            }],
            vec![domain("bd1")],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dot1q_tag_4095_fails() {
        let cfg = config_with(
            vec![SwitchingProfile {
                name: "sp1".to_string(),
                members: vec![member("bd1", VlanTag::Dot1q(4095))],
            }],
            vec![domain("bd1")],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dot1q_tag_boundary_values_pass() {
        let cfg = config_with(
            vec![SwitchingProfile {
                name: "sp1".to_string(),
                members: vec![
                    member("bd1", VlanTag::Dot1q(1)),
                    member("bd2", VlanTag::Dot1q(4094)),
                ],
            }],
            vec![domain("bd1"), domain("bd2")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn member_stp_port_settings_are_ranged() {
        let ok = |cost, prio| {
            let cfg = config_with(
                vec![SwitchingProfile {
                    name: "sp1".to_string(),
                    members: vec![SwitchingProfileMember {
                        broadcast_domain: "bd1".to_string(),
                        stp_cost: cost,
                        stp_priority: prio,
                        ..Default::default()
                    }],
                }],
                vec![domain("bd1")],
            );
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(ok(None, None));
        assert!(ok(Some(200_000_000), Some(240)));
        assert!(!ok(Some(0), None));
        assert!(!ok(Some(200_000_001), None));
        assert!(!ok(None, Some(100)));
    }
}
