//! Named LLDP-MED settings (`lldp-med-profile`, ANSI/TIA-1057), referenced by
//! bare name from an `Interface`. Declaration only until `nos-lldpd` reads it
//! (#1572): attaching one is inert.

use garde::Validate;
use nos_proto_derive::Cli;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::Config;

/// Most network policies one profile holds: one per application type.
pub const MAX_NETWORK_POLICIES: usize = 8;
/// Largest VLAN id a policy names (4095 is reserved).
pub const VLAN_MAX: u16 = 4094;
/// Largest `PoE` power value: the 10-bit wire field, in 0.1 W units.
pub const POE_POWER_MAX: u16 = 1023;

/// Application type of a network policy (TIA-1057 Table 12). Types 0 and 9+
/// are reserved.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum LldpMedAppType {
    /// Voice (1).
    #[default]
    Voice,
    /// Voice signaling (2).
    VoiceSignaling,
    /// Guest voice (3).
    GuestVoice,
    /// Guest voice signaling (4).
    GuestVoiceSignaling,
    /// Softphone voice (5).
    SoftphoneVoice,
    /// Video conferencing (6).
    VideoConferencing,
    /// Streaming video (7).
    StreamingVideo,
    /// Video signaling (8).
    VideoSignaling,
}

impl LldpMedAppType {
    /// The TIA-1057 application type number (1-8), shared with the TLV codec.
    pub const fn wire(self) -> u8 {
        match self {
            Self::Voice => 1,
            Self::VoiceSignaling => 2,
            Self::GuestVoice => 3,
            Self::GuestVoiceSignaling => 4,
            Self::SoftphoneVoice => 5,
            Self::VideoConferencing => 6,
            Self::StreamingVideo => 7,
            Self::VideoSignaling => 8,
        }
    }
}

/// What a port tells its neighbor to do for one application type.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct LldpMedNetworkPolicy {
    #[cli(key)]
    /// Application type; the key, so at most one policy per type.
    pub app_type: LldpMedAppType,
    #[serde(default)]
    #[cli(topic = LldpMedPolicyVlan)]
    /// VLAN id, 0..=4094. `None`: no VLAN (untagged); 0: priority-tagged only.
    pub vlan: Option<u16>,
    #[serde(default)]
    #[cli(topic = LldpMedPolicyTagged)]
    /// The frames carry an 802.1Q tag; needs `vlan`.
    pub tagged: bool,
    #[serde(default)]
    #[cli(topic = LldpMedPolicyPriority)]
    /// 802.1p priority, 0..=7.
    pub priority: u8,
    #[serde(default)]
    #[cli(topic = LldpMedPolicyDscp)]
    /// DSCP value, 0..=63.
    pub dscp: u8,
    #[serde(default)]
    #[cli(topic = LldpMedPolicyUnknown)]
    /// The policy is required but this port does not know it (the `U` flag).
    pub unknown: bool,
}

impl LldpMedNetworkPolicy {
    fn check(&self) -> Result<(), String> {
        if self.vlan.is_some_and(|v| v > VLAN_MAX) {
            return Err(format!("vlan must be 0..={VLAN_MAX}"));
        }
        // TIA-1057 network-policy TLV: T=1 names an 802.1Q VLAN, so it needs
        // a VLAN id; T=0 with VLAN 0 is the priority-tagged case. Taken from
        // the standard's field description, not cross-checked against lldpd.
        if self.tagged && self.vlan.is_none() {
            return Err("tagged needs a vlan".into());
        }
        if self.priority > 7 {
            return Err("priority must be 0..=7".into());
        }
        if self.dscp > 63 {
            return Err("dscp must be 0..=63".into());
        }
        Ok(())
    }
}

/// Which power source the PSE or PD advertises (TIA-1057 extended power-via-MDI).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum PoeSource {
    /// The primary power source.
    #[default]
    Primary,
    /// The backup power source.
    Backup,
}

/// Power priority (TIA-1057 extended power-via-MDI).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum PoePriority {
    /// Critical.
    Critical,
    /// High.
    High,
    /// Low.
    #[default]
    Low,
}

/// The power-via-MDI values this port advertises: **as configured, never
/// measured** (NOS has no `PoE` hardware).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct LldpMedPoe {
    #[serde(default)]
    #[cli(topic = LldpMedPoeSource)]
    /// Power source.
    pub source: PoeSource,
    #[serde(default)]
    #[cli(topic = LldpMedPoePriority)]
    /// Power priority.
    pub priority: PoePriority,
    #[serde(default)]
    #[cli(topic = LldpMedPoePower)]
    /// Power in 0.1 W units, 0..=1023 (the 10-bit wire field: 102.3 W at most).
    pub power: u16,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
/// LLDP-MED settings that an interface attaches with `lldp-med-profile`.
pub struct LldpMedProfile {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.lldp_med_profiles, |p| &p.name))
    )]
    #[cli(key)]
    /// Profile name, 1 to 64 characters (letters, digits, `_`, `-`), unique among LLDP-MED profiles.
    pub name: String,

    #[serde(default)]
    #[garde(custom(|p: &Vec<LldpMedNetworkPolicy>, _ctx: &Config| valid_policies(p)))]
    #[cli(topic = LldpMedProfileNetworkPolicy, words = "network-policy")]
    /// Network policies, at most one per application type.
    pub network_policies: Vec<LldpMedNetworkPolicy>,

    #[serde(default)]
    #[garde(custom(|p: &Option<LldpMedPoe>, _ctx: &Config| valid_poe(p.as_ref())))]
    #[cli(topic = LldpMedProfilePoe)]
    /// Power-via-MDI values to advertise; `None`: no `PoE` TLV.
    pub poe: Option<LldpMedPoe>,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = LldpMedProfileAdvertiseAlways, words = "advertise-always enable", alias = "advertise-always")]
    /// Send the LLDP-MED TLVs without waiting for a neighbor's MED
    /// capabilities (for NOS-to-NOS; off stays silent until a MED device speaks).
    pub advertise_always: bool,
}

fn valid_policies(list: &[LldpMedNetworkPolicy]) -> garde::Result {
    if list.len() > MAX_NETWORK_POLICIES {
        return Err(garde::Error::new(format!(
            "at most {MAX_NETWORK_POLICIES} network-policies"
        )));
    }
    for (i, p) in list.iter().enumerate() {
        if list[..i].iter().any(|o| o.app_type == p.app_type) {
            return Err(garde::Error::new(format!(
                "network-policy {:?} is listed twice",
                p.app_type
            )));
        }
        p.check().map_err(garde::Error::new)?;
    }
    Ok(())
}

fn valid_poe(poe: Option<&LldpMedPoe>) -> garde::Result {
    if poe.is_some_and(|p| p.power > POE_POWER_MAX) {
        return Err(garde::Error::new(format!(
            "poe power must be 0..={POE_POWER_MAX} (units of 0.1 W)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(f: impl FnOnce(&mut LldpMedProfile)) -> bool {
        let mut p = LldpMedProfile {
            name: "p".into(),
            ..Default::default()
        };
        f(&mut p);
        let c = Config {
            lldp_med_profiles: vec![p],
            ..Default::default()
        };
        c.validate_with(&c).is_ok()
    }

    fn policy(app_type: LldpMedAppType) -> LldpMedNetworkPolicy {
        LldpMedNetworkPolicy {
            app_type,
            ..Default::default()
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "full-Config validation, slow under the interpreter; pure logic covered natively"
    )]
    fn defaults_commit_and_names_are_checked() {
        assert!(ok(|_| {}));
        assert!(!ok(|p| p.name = String::new()));
        assert!(!ok(|p| p.name = "a b".into()));
        assert!(!ok(|p| p.name = "x".repeat(65)));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "full-Config validation, slow under the interpreter; pure logic covered natively"
    )]
    fn duplicate_names_are_refused() {
        let p = LldpMedProfile {
            name: "p".into(),
            ..Default::default()
        };
        let c = Config {
            lldp_med_profiles: vec![p.clone(), p],
            ..Default::default()
        };
        assert!(c.validate_with(&c).is_err());
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "full-Config validation, slow under the interpreter; pure logic covered natively"
    )]
    fn policy_bounds() {
        let with = |f: fn(&mut LldpMedNetworkPolicy)| {
            ok(|p| {
                let mut n = policy(LldpMedAppType::Voice);
                f(&mut n);
                p.network_policies = vec![n];
            })
        };
        assert!(with(|n| n.vlan = Some(4094)));
        assert!(with(|n| n.vlan = Some(0)));
        assert!(!with(|n| n.vlan = Some(4095)));
        assert!(with(|n| n.priority = 7));
        assert!(!with(|n| n.priority = 8));
        assert!(with(|n| n.dscp = 63));
        assert!(!with(|n| n.dscp = 64));
        assert!(with(|n| {
            n.vlan = Some(100);
            n.tagged = true;
        }));
        assert!(!with(|n| n.tagged = true));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "full-Config validation, slow under the interpreter; pure logic covered natively"
    )]
    fn policies_are_capped_and_unique() {
        use LldpMedAppType::*;
        let all = [
            Voice,
            VoiceSignaling,
            GuestVoice,
            GuestVoiceSignaling,
            SoftphoneVoice,
            VideoConferencing,
            StreamingVideo,
            VideoSignaling,
        ];
        assert!(ok(|p| p.network_policies = all.map(policy).to_vec()));
        assert!(!ok(|p| {
            let mut v = all.map(policy).to_vec();
            v.push(policy(Voice));
            p.network_policies = v;
        }));
        assert!(!ok(
            |p| p.network_policies = vec![policy(Voice), policy(Voice)]
        ));
        let wire: Vec<u8> = all.iter().map(|a| a.wire()).collect();
        assert_eq!(wire, (1..=8).collect::<Vec<u8>>());
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "full-Config validation, slow under the interpreter; pure logic covered natively"
    )]
    fn poe_power_is_ten_bits() {
        let poe = |power| {
            Some(LldpMedPoe {
                power,
                ..Default::default()
            })
        };
        assert!(ok(|p| p.poe = poe(1023)));
        assert!(!ok(|p| p.poe = poe(1024)));
    }

    #[test]
    fn pre_change_json_loads() {
        let p: LldpMedProfile = serde_json::from_str(r#"{"name":"p"}"#).unwrap();
        assert!(p.network_policies.is_empty() && p.poe.is_none() && !p.advertise_always);
    }
}
