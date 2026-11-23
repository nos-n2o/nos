//! Spanning tree (IEEE 802.1Q clause 13): `Config.spanning_tree`, the
//! bridge-wide parameters. Per-port tuning is `StpPortProfile`. Declaration
//! only until `nos-stpd` (STP 2/7): attaching anything is inert.

use nos_proto_derive::Cli;

use super::{Config, VlanTag};
use serde::{Deserialize, Serialize};

/// Default bridge priority (802.1Q 13.26.3).
pub const PRIORITY_DEFAULT: u16 = 32768;
/// Default Hello Time, seconds.
pub const HELLO_TIME_DEFAULT: u8 = 2;
/// Default Max Age, seconds.
pub const MAX_AGE_DEFAULT: u8 = 20;
/// Default Forward Delay, seconds.
pub const FORWARD_DELAY_DEFAULT: u8 = 15;
/// Default Transmit Hold Count, BPDUs per second.
pub const TX_HOLD_COUNT_DEFAULT: u8 = 6;
/// Default MSTP hop budget of a BPDU.
pub const MAX_HOPS_DEFAULT: u8 = 20;
/// An MST region carries at most 64 instances besides the CIST (802.1Q 13.8).
pub const MST_INSTANCES_MAX: usize = 64;

/// Which protocol the bridge runs. `Rstp` is the default (one tree);
/// `Mstp` maps VLANs to `mst-instances`; `RapidPvst` runs one RSTP tree per
/// VLAN of a `BroadcastDomain`; `Disabled` turns spanning tree off.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum StpMode {
    #[default]
    /// Rapid spanning tree: one tree for all VLANs.
    Rstp,
    /// Multiple spanning tree (802.1s): VLANs mapped onto MST instances.
    Mstp,
    /// One rapid spanning tree per VLAN of a broadcast domain.
    RapidPvst,
    /// Spanning tree off.
    Disabled,
}

/// Compatibility mode forced on every port (802.1Q 13.7 `ForceProtocolVersion`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum StpForceVersion {
    #[default]
    /// Legacy STP behaviour (802.1D).
    Stp,
    /// RSTP behaviour (802.1w).
    Rstp,
}

/// The MST region identity (802.1Q 13.8): bridges only share an MSTI tree
/// when name and revision match.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct StpRegion {
    #[serde(default)]
    #[cli(topic = SpanningTreeRegion)]
    /// Region name; bridges join one region only when name and revision match.
    pub name: String,
    #[serde(default)]
    #[cli(topic = SpanningTreeRegion)]
    /// Region revision number.
    pub revision: u16,
}

/// One MST instance and this bridge's priority in it.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct MstInstance {
    #[cli(key)]
    /// MST instance id; the key.
    pub id: u16,
    #[serde(default = "priority_default")]
    #[cli(topic = SpanningTreeMstInstancePriority)]
    /// Bridge priority in this instance, a multiple of 4096.
    pub priority: u16,
}

impl Default for MstInstance {
    fn default() -> Self {
        Self {
            id: 0,
            priority: PRIORITY_DEFAULT,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
/// Bridge-wide spanning-tree parameters; there is exactly one per device.
pub struct SpanningTree {
    #[serde(default)]
    #[cli(topic = SpanningTreeMode)]
    /// The protocol the bridge runs.
    pub mode: StpMode,

    /// Bridge priority: a multiple of 4096, 0..=61440.
    #[serde(default = "priority_default")]
    #[cli(topic = SpanningTreePriority)]
    pub priority: u16,

    /// Seconds, 1..=10.
    #[serde(default = "hello_time_default")]
    #[cli(topic = SpanningTreeHelloTime)]
    pub hello_time: u8,

    /// Seconds, 6..=40.
    #[serde(default = "max_age_default")]
    #[cli(topic = SpanningTreeMaxAge)]
    pub max_age: u8,

    /// Seconds, 4..=30.
    #[serde(default = "forward_delay_default")]
    #[cli(topic = SpanningTreeForwardDelay)]
    pub forward_delay: u8,

    /// BPDUs a port may send per second, 1..=10.
    #[serde(default = "tx_hold_count_default")]
    #[cli(topic = SpanningTreeTxHoldCount)]
    pub tx_hold_count: u8,

    /// MSTP hop budget of a BPDU, 6..=40.
    #[serde(default = "max_hops_default")]
    #[cli(topic = SpanningTreeMaxHops)]
    pub max_hops: u8,

    #[serde(default)]
    #[cli(topic = SpanningTreeForceVersion)]
    /// Protocol version forced on every port; `None` negotiates.
    pub force_version: Option<StpForceVersion>,

    #[serde(default)]
    #[cli(topic = SpanningTreeRegion)]
    /// MST region identity.
    pub region: StpRegion,

    #[serde(default)]
    #[cli(topic = SpanningTreeMstInstance, words = "mst-instance")]
    /// MST instances and this bridge's priority in each.
    pub mst_instances: Vec<MstInstance>,
}

fn priority_default() -> u16 {
    PRIORITY_DEFAULT
}
fn hello_time_default() -> u8 {
    HELLO_TIME_DEFAULT
}
fn max_age_default() -> u8 {
    MAX_AGE_DEFAULT
}
fn forward_delay_default() -> u8 {
    FORWARD_DELAY_DEFAULT
}
fn tx_hold_count_default() -> u8 {
    TX_HOLD_COUNT_DEFAULT
}
fn max_hops_default() -> u8 {
    MAX_HOPS_DEFAULT
}

impl Default for SpanningTree {
    fn default() -> Self {
        Self {
            mode: StpMode::default(),
            priority: PRIORITY_DEFAULT,
            hello_time: HELLO_TIME_DEFAULT,
            max_age: MAX_AGE_DEFAULT,
            forward_delay: FORWARD_DELAY_DEFAULT,
            tx_hold_count: TX_HOLD_COUNT_DEFAULT,
            max_hops: MAX_HOPS_DEFAULT,
            force_version: None,
            region: StpRegion::default(),
            mst_instances: Vec::new(),
        }
    }
}

/// A bridge, MSTI or per-VLAN priority: a multiple of 4096 (802.1Q 13.26.2:
/// only the top four bits are the priority, the rest the system ID).
pub(crate) fn valid_bridge_priority(p: u16, what: &str) -> garde::Result {
    if p > 61440 || !p.is_multiple_of(4096) {
        return Err(garde::Error::new(format!(
            "{what} must be a multiple of 4096 between 0 and 61440"
        )));
    }
    Ok(())
}

/// A port priority: a multiple of 16, 0..=240 (802.1Q 13.25.32).
pub(crate) fn valid_port_priority(p: u8) -> garde::Result {
    if p > 240 || !p.is_multiple_of(16) {
        return Err(garde::Error::new(
            "port priority must be a multiple of 16 between 0 and 240",
        ));
    }
    Ok(())
}

/// The 802.1Q 13.25 timer relations on one (hello, max-age, forward-delay)
/// set, with the Table 13-5 ranges.
pub(crate) fn valid_timers(hello: u8, max_age: u8, forward_delay: u8, what: &str) -> garde::Result {
    let range = |v: u8, lo: u8, hi: u8, name: &str| {
        if (lo..=hi).contains(&v) {
            Ok(())
        } else {
            Err(garde::Error::new(format!(
                "{what} {name} must be between {lo} and {hi}"
            )))
        }
    };
    range(hello, 1, 10, "hello-time")?;
    range(max_age, 6, 40, "max-age")?;
    range(forward_delay, 4, 30, "forward-delay")?;
    if u16::from(max_age) > 2 * (u16::from(forward_delay) - 1) {
        return Err(garde::Error::new(format!(
            "{what}: max-age {max_age} must not exceed 2 * (forward-delay - 1)"
        )));
    }
    if u16::from(max_age) < 2 * (u16::from(hello) + 1) {
        return Err(garde::Error::new(format!(
            "{what}: max-age {max_age} must be at least 2 * (hello-time + 1)"
        )));
    }
    Ok(())
}

impl SpanningTree {
    /// Commit-time validation (`Config.spanning_tree`'s `garde` custom check).
    pub(crate) fn check(&self) -> garde::Result {
        valid_bridge_priority(self.priority, "spanning-tree priority")?;
        valid_timers(
            self.hello_time,
            self.max_age,
            self.forward_delay,
            "spanning-tree",
        )?;
        if !(1..=10).contains(&self.tx_hold_count) {
            return Err(garde::Error::new("tx-hold-count must be between 1 and 10"));
        }
        if !(6..=40).contains(&self.max_hops) {
            return Err(garde::Error::new("max-hops must be between 6 and 40"));
        }
        if self.region.name.len() > 32 {
            return Err(garde::Error::new("region name is at most 32 bytes"));
        }
        if self.mst_instances.len() > MST_INSTANCES_MAX {
            return Err(garde::Error::new(format!(
                "at most {MST_INSTANCES_MAX} mst-instances"
            )));
        }
        for (i, m) in self.mst_instances.iter().enumerate() {
            if !(1..=4094).contains(&m.id) {
                return Err(garde::Error::new("mst-instance id must be 1..=4094"));
            }
            if self.mst_instances[..i].iter().any(|o| o.id == m.id) {
                return Err(garde::Error::new(format!(
                    "mst-instance {} is listed twice",
                    m.id
                )));
            }
            valid_bridge_priority(m.priority, "mst-instance priority")?;
        }
        Ok(())
    }
}

/// `Config.spanning_tree`'s check: the singleton's own rules, plus, for the
/// per-VLAN modes, that every `BroadcastDomain` in use maps to exactly one
/// VID and no two domains share one. An untagged-only membership is VID 1
/// (the native VLAN).
pub(crate) fn valid_spanning_tree(s: &SpanningTree, ctx: &Config) -> garde::Result {
    s.check()?;
    if matches!(s.mode, StpMode::Mstp | StpMode::RapidPvst) {
        valid_domain_vids(ctx)?;
    }
    Ok(())
}

fn valid_domain_vids(ctx: &Config) -> garde::Result {
    let profiles = ctx
        .interfaces
        .iter()
        .filter_map(|i| i.switching_profile.as_ref())
        .chain(
            ctx.port_aggregates
                .iter()
                .filter_map(|a| a.switching_profile.as_ref()),
        );
    let mut vids: Vec<(&str, u16)> = Vec::new();
    for p in profiles {
        let Some(p) = ctx.switching_profiles.iter().find(|sp| &sp.name == p) else {
            continue;
        };
        for m in &p.members {
            let vid = match m.tag {
                VlanTag::Untagged => 1,
                VlanTag::Dot1q(n) => n,
            };
            if let Some((_, other)) = vids
                .iter()
                .find(|(d, o)| *d == m.broadcast_domain && *o != vid)
            {
                return Err(garde::Error::new(format!(
                    "broadcast domain {} is VLAN {other} and VLAN {vid} in different switching profiles: per-VLAN spanning tree needs one",
                    m.broadcast_domain
                )));
            }
            if !vids.contains(&(m.broadcast_domain.as_str(), vid)) {
                vids.push((&m.broadcast_domain, vid));
            }
        }
    }
    for (i, (d, vid)) in vids.iter().enumerate() {
        if let Some((o, _)) = vids[..i].iter().find(|(_, v)| v == vid) {
            return Err(garde::Error::new(format!(
                "broadcast domains {o} and {d} are both VLAN {vid}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{BroadcastDomain, Interface, SwitchingProfile, SwitchingProfileMember};
    use garde::Validate;

    fn ok(f: impl FnOnce(&mut SpanningTree)) -> bool {
        let mut c = Config::default();
        f(&mut c.spanning_tree);
        c.validate_with(&c).is_ok()
    }

    #[test]
    fn defaults_commit() {
        assert!(ok(|_| {}));
    }

    #[test]
    fn timers_follow_802_1q_13_25() {
        assert!(ok(
            |s| (s.hello_time, s.max_age, s.forward_delay) = (1, 6, 4)
        ));
        assert!(ok(
            |s| (s.hello_time, s.max_age, s.forward_delay) = (10, 40, 30)
        ));
        // max-age above 2 * (forward-delay - 1)
        assert!(!ok(|s| s.max_age = 29));
        assert!(!ok(|s| (s.max_age, s.forward_delay) = (25, 10)));
        // max-age below 2 * (hello + 1)
        assert!(!ok(|s| (s.hello_time, s.max_age) = (10, 20)));
        // Table 13-5 ranges
        assert!(!ok(|s| s.hello_time = 0));
        assert!(!ok(|s| s.max_age = 5));
        assert!(!ok(|s| (s.forward_delay, s.max_age) = (3, 6)));
    }

    #[test]
    fn counters_are_ranged() {
        assert!(ok(|s| s.tx_hold_count = 10));
        assert!(!ok(|s| s.tx_hold_count = 0));
        assert!(!ok(|s| s.tx_hold_count = 11));
        assert!(ok(|s| s.max_hops = 40));
        assert!(!ok(|s| s.max_hops = 5));
    }

    #[test]
    fn priorities_are_multiples_of_4096() {
        assert!(ok(|s| s.priority = 0));
        assert!(ok(|s| s.priority = 61440));
        assert!(!ok(|s| s.priority = 100));
        assert!(!ok(|s| s.priority = 65535));
        assert!(!ok(
            |s| s.mst_instances = vec![MstInstance { id: 1, priority: 5 }]
        ));
        assert!(ok(|s| s.mst_instances = vec![MstInstance {
            id: 1,
            priority: 4096
        }]));
    }

    #[test]
    fn mst_instances_are_bounded_and_unique() {
        let m = |id| MstInstance {
            id,
            ..Default::default()
        };
        assert!(!ok(|s| s.mst_instances = vec![m(0)]));
        assert!(!ok(|s| s.mst_instances = vec![m(4095)]));
        assert!(!ok(|s| s.mst_instances = vec![m(1), m(1)]));
        assert!(ok(|s| s.mst_instances = (1..=64).map(m).collect()));
        assert!(!ok(|s| s.mst_instances = (1..=65).map(m).collect()));
    }

    #[test]
    fn old_config_without_the_section_loads() {
        let mut v = serde_json::to_value(Config::default()).unwrap();
        v.as_object_mut().unwrap().remove("spanning_tree");
        let c: Config = serde_json::from_value(v).unwrap();
        assert_eq!(c.spanning_tree, SpanningTree::default());
    }

    fn vlan_config(mode: StpMode, profiles: &[(&str, &[(&str, VlanTag)])]) -> Config {
        let mut c = Config::default();
        c.spanning_tree.mode = mode;
        for (n, members) in profiles {
            for (d, _) in *members {
                if !c.broadcast_domains.iter().any(|b| &b.name == d) {
                    c.broadcast_domains.push(BroadcastDomain {
                        name: (*d).to_string(),
                        ..Default::default()
                    });
                }
            }
            c.switching_profiles.push(SwitchingProfile {
                name: (*n).to_string(),
                members: members
                    .iter()
                    .map(|(d, t)| SwitchingProfileMember {
                        broadcast_domain: (*d).to_string(),
                        tag: *t,
                        ..Default::default()
                    })
                    .collect(),
            });
        }
        c.interfaces = profiles
            .iter()
            .enumerate()
            .map(|(i, (n, _))| Interface {
                name: format!("eth{i}"),
                switching_profile: Some((*n).to_string()),
                ..Default::default()
            })
            .collect();
        c
    }

    #[test]
    fn per_vlan_modes_need_one_vid_per_domain() {
        use VlanTag::{Dot1q, Untagged};
        for mode in [StpMode::Mstp, StpMode::RapidPvst] {
            // same tag in two profiles: fine
            let c = vlan_config(
                mode,
                &[("a", &[("bd1", Dot1q(10))]), ("b", &[("bd1", Dot1q(10))])],
            );
            c.validate_with(&c).unwrap();
            // different tags: refused, naming the domain and both tags
            let c = vlan_config(
                mode,
                &[("a", &[("bd1", Dot1q(10))]), ("b", &[("bd1", Dot1q(20))])],
            );
            let err = c.validate_with(&c).unwrap_err().to_string();
            assert!(
                err.contains("bd1") && err.contains("10") && err.contains("20"),
                "{err}"
            );
            // untagged counts as VLAN 1
            let c = vlan_config(
                mode,
                &[("a", &[("bd1", Untagged)]), ("b", &[("bd1", Dot1q(1))])],
            );
            c.validate_with(&c).unwrap();
            let c = vlan_config(
                mode,
                &[("a", &[("bd1", Untagged)]), ("b", &[("bd1", Dot1q(2))])],
            );
            assert!(c.validate_with(&c).is_err());
            // two domains on one VID
            let c = vlan_config(mode, &[("a", &[("bd1", Dot1q(7)), ("bd2", Dot1q(7))])]);
            assert!(c.validate_with(&c).is_err());
        }
    }

    #[test]
    fn single_tree_modes_accept_any_tagging() {
        use VlanTag::Dot1q;
        for mode in [StpMode::Rstp, StpMode::Disabled] {
            let c = vlan_config(
                mode,
                &[("a", &[("bd1", Dot1q(10))]), ("b", &[("bd1", Dot1q(20))])],
            );
            c.validate_with(&c).unwrap();
        }
    }

    #[test]
    fn force_version_is_accepted_with_every_mode() {
        for mode in [StpMode::Rstp, StpMode::Mstp, StpMode::RapidPvst] {
            assert!(ok(|s| {
                s.mode = mode;
                s.force_version = Some(StpForceVersion::Stp);
            }));
        }
    }
}
