//! LLDP configuration (IEEE 802.1AB) that isn't a per-interface on/off flag:
//! the system-wide timers and management address (`Config.lldp`), and the
//! per-interface destination group (`Interface.lldp_destination`).

use std::net::IpAddr;

use nos_proto_derive::Cli;
use serde::{Deserialize, Serialize};

/// 802.1AB `msgTxInterval` default.
pub const TX_INTERVAL_DEFAULT_SECS: u16 = 30;
/// 802.1AB `msgTxHold` default.
pub const TX_HOLD_DEFAULT: u8 = 4;
/// 802.1AB's `msgTxInterval` range.
pub const TX_INTERVAL_MAX_SECS: u16 = 3600;
/// 802.1AB's `msgTxHold` range is 1..=100.
pub const TX_HOLD_MAX: u8 = 100;
/// Most Management Address TLVs one LLDPDU carries, and the most a receiver
/// keeps — one number on both sides, so one nos never drops another's.
pub const MAX_MANAGEMENT_ADDRESSES: usize = 4;
/// System Description advertised when none is configured. No version: a
/// neighbor (and anyone on the segment) learns nothing about the build.
pub const SYSTEM_DESCRIPTION_DEFAULT: &str = "nos";
/// Longest System Description: the TLV's 255-byte limit.
pub const SYSTEM_DESCRIPTION_MAX_BYTES: usize = 255;

/// System-wide LLDP settings. `None` for a timer means the 802.1AB default.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct LldpSettings {
    /// `msgTxInterval`: seconds between periodic LLDPDUs.
    #[cli(topic = LldpTxInterval, words = "tx-interval")]
    pub tx_interval_secs: Option<u16>,
    /// `msgTxHold`: the advertised TTL is this × the interval.
    #[cli(topic = LldpTxHold)]
    pub tx_hold: Option<u8>,
    /// Each advertised in its own Management Address TLV on every
    /// LLDP-enabled link (at most 4). Taken as configured: an address on a
    /// kernel interface carries that interface's ifIndex, any other is still
    /// sent, with the interface numbering "unknown".
    #[serde(
        default,
        alias = "management_address",
        deserialize_with = "one_or_many"
    )]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    #[cli(topic = LldpManagementAddress, words = "management-address")]
    pub management_addresses: Vec<IpAddr>,
    /// The System Description TLV text; `None` advertises `nos`.
    #[serde(default)]
    #[cli(topic = LldpSystemDescription, words = "system-description")]
    pub system_description: Option<String>,
}

impl LldpSettings {
    /// Transmit interval in seconds: the configured one, else `TX_INTERVAL_DEFAULT_SECS`.
    pub fn effective_interval_secs(&self) -> u16 {
        self.tx_interval_secs.unwrap_or(TX_INTERVAL_DEFAULT_SECS)
    }

    /// Hold multiplier: the configured one, else `TX_HOLD_DEFAULT`.
    pub fn effective_hold(&self) -> u8 {
        self.tx_hold.unwrap_or(TX_HOLD_DEFAULT)
    }

    /// The TTL advertised in every LLDPDU: `msgTxHold × msgTxInterval`.
    /// Saturates rather than overflowing; `check` rejects a config that would.
    pub fn effective_ttl_secs(&self) -> u16 {
        u16::try_from(u32::from(self.effective_interval_secs()) * u32::from(self.effective_hold()))
            .unwrap_or(u16::MAX)
    }

    /// The System Description advertised: the configured one, else `SYSTEM_DESCRIPTION_DEFAULT`.
    pub fn effective_system_description(&self) -> &str {
        self.system_description
            .as_deref()
            .unwrap_or(SYSTEM_DESCRIPTION_DEFAULT)
    }

    /// Commit-time validation (`Config.lldp`'s `garde` custom check).
    pub(crate) fn check(&self) -> garde::Result {
        if !(1..=TX_INTERVAL_MAX_SECS).contains(&self.effective_interval_secs()) {
            return Err(garde::Error::new(format!(
                "lldp tx-interval must be 1-{TX_INTERVAL_MAX_SECS} seconds"
            )));
        }
        if !(1..=TX_HOLD_MAX).contains(&self.effective_hold()) {
            return Err(garde::Error::new(format!(
                "lldp tx-hold must be 1-{TX_HOLD_MAX}"
            )));
        }
        // The TTL field is 16 bits; the two ranges alone allow 360000.
        if u32::from(self.effective_interval_secs()) * u32::from(self.effective_hold())
            > u32::from(u16::MAX)
        {
            return Err(garde::Error::new(
                "lldp tx-interval × tx-hold must be at most 65535 seconds (the 16-bit TTL)",
            ));
        }
        if let Some(d) = &self.system_description
            && (d.is_empty()
                || d.len() > SYSTEM_DESCRIPTION_MAX_BYTES
                || d.chars().any(char::is_control))
        {
            return Err(garde::Error::new(format!(
                    "lldp system-description must be 1-{SYSTEM_DESCRIPTION_MAX_BYTES} bytes without control characters"
                )));
        }
        for (i, addr) in self.management_addresses.iter().enumerate() {
            if addr.is_unspecified() || addr.is_multicast() {
                return Err(garde::Error::new(
                    "lldp management-address must be a unicast address",
                ));
            }
            if self.management_addresses[..i].contains(addr) {
                return Err(garde::Error::new(format!(
                    "lldp management-address {addr} is listed twice"
                )));
            }
        }
        if self.management_addresses.len() > MAX_MANAGEMENT_ADDRESSES {
            return Err(garde::Error::new(format!(
                "at most {MAX_MANAGEMENT_ADDRESSES} lldp management-addresses"
            )));
        }
        Ok(())
    }
}

/// A list, or the single address a config saved before #62 held under
/// `management_address`. Only a self-describing format (YAML/JSON) can tell
/// the two apart; postcard IPC always carries the list.
fn one_or_many<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<IpAddr>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(IpAddr),
        Many(Vec<IpAddr>),
    }
    if !d.is_human_readable() {
        return Vec::deserialize(d);
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(a) => vec![a],
        OneOrMany::Many(v) => v,
    })
}

/// Which 802.1AB destination group an interface's LLDPDUs use. Both ends of a
/// link must agree: a frame to a different group is never seen.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum LldpDestination {
    /// `01:80:C2:00:00:0E` — link-local, never forwarded by any bridge.
    #[default]
    NearestBridge,
    /// `01:80:C2:00:00:03` — nearest non-TPMR bridge: relayed by TPMRs, stopped by
    /// every other bridge (C-VLAN and S-VLAN included).
    NonTpmr,
    /// `01:80:C2:00:00:00` — not forwarded by customer bridges.
    CustomerBridge,
}

impl LldpDestination {
    /// The destination MAC address LLDPDUs are sent to.
    pub const fn mac(self) -> [u8; 6] {
        let last = match self {
            LldpDestination::NearestBridge => 0x0E,
            LldpDestination::NonTpmr => 0x03,
            LldpDestination::CustomerBridge => 0x00,
        };
        [0x01, 0x80, 0xC2, 0x00, 0x00, last]
    }

    /// The CLI/config spelling.
    pub const fn name(self) -> &'static str {
        match self {
            LldpDestination::NearestBridge => "nearest-bridge",
            LldpDestination::NonTpmr => "non-tpmr",
            LldpDestination::CustomerBridge => "customer-bridge",
        }
    }

    /// Inverse of `name`; `None` for an unknown spelling.
    pub fn from_name(name: &str) -> Option<Self> {
        [Self::NearestBridge, Self::NonTpmr, Self::CustomerBridge]
            .into_iter()
            .find(|d| d.name() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(i: Option<u16>, h: Option<u8>, a: Option<&str>) -> LldpSettings {
        LldpSettings {
            tx_interval_secs: i,
            tx_hold: h,
            management_addresses: a.into_iter().map(|a| a.parse().unwrap()).collect(),
            system_description: None,
        }
    }

    #[test]
    fn defaults_are_the_802_1ab_values() {
        let s = LldpSettings::default();
        assert_eq!(s.effective_interval_secs(), 30);
        assert_eq!(s.effective_ttl_secs(), 120);
        assert!(s.check().is_ok());
    }

    #[test]
    fn ttl_is_hold_times_interval() {
        assert_eq!(settings(Some(5), Some(3), None).effective_ttl_secs(), 15);
    }

    #[test]
    fn out_of_range_values_are_rejected() {
        assert!(settings(Some(0), None, None).check().is_err());
        assert!(settings(Some(3601), None, None).check().is_err());
        assert!(settings(None, Some(0), None).check().is_err());
        assert!(settings(None, Some(101), None).check().is_err());
        // Each in range on its own, but the TTL would overflow 16 bits.
        assert!(settings(Some(3600), Some(100), None).check().is_err());
        assert!(settings(Some(3600), Some(18), None).check().is_ok());
    }

    #[test]
    fn range_and_ttl_boundaries_are_inclusive() {
        let ok = |i, h| settings(i, h, None).check().is_ok();
        assert!(ok(Some(1), None));
        assert!(ok(Some(TX_INTERVAL_MAX_SECS), Some(1)));
        assert!(!ok(Some(0), None));
        assert!(!ok(Some(TX_INTERVAL_MAX_SECS + 1), None));
        assert!(ok(None, Some(1)));
        assert!(ok(None, Some(TX_HOLD_MAX)));
        assert!(!ok(None, Some(0)));
        assert!(!ok(None, Some(TX_HOLD_MAX + 1)));
        // 65535 = 51 x 1285 fits the 16-bit TTL exactly; one more does not.
        assert!(ok(Some(1285), Some(51)));
        assert!(!ok(Some(1286), Some(51)));
        assert_eq!(
            settings(Some(1285), Some(51), None).effective_ttl_secs(),
            65535
        );
        assert_eq!(
            settings(Some(1286), Some(51), None).effective_ttl_secs(),
            65535
        );
    }

    #[test]
    fn duplicate_management_address_is_listed_once_only() {
        let a = IpAddr::from([10, 0, 0, 1]);
        let b = IpAddr::from([10, 0, 0, 2]);
        let with = |v: Vec<IpAddr>| LldpSettings {
            management_addresses: v,
            ..LldpSettings::default()
        };
        assert!(with(vec![a, b]).check().is_ok());
        assert!(with(vec![a, b, a]).check().is_err());
        assert!(with(vec![a, a]).check().is_err());
        // Exactly at the cap with distinct addresses passes; one more fails.
        let cap_n: u8 = 4;
        assert_eq!(usize::from(cap_n), MAX_MANAGEMENT_ADDRESSES);
        let cap = |n: u8| with((1..=n).map(|i| IpAddr::from([10, 0, 0, i])).collect());
        assert!(cap(cap_n).check().is_ok());
        assert!(cap(cap_n + 1).check().is_err());
    }

    #[test]
    fn management_address_must_be_unicast() {
        assert!(settings(None, None, Some("10.0.0.1")).check().is_ok());
        assert!(settings(None, None, Some("2001:db8::1")).check().is_ok());
        assert!(settings(None, None, Some("0.0.0.0")).check().is_err());
        assert!(settings(None, None, Some("224.0.0.1")).check().is_err());
        assert!(settings(None, None, Some("ff02::1")).check().is_err());
    }

    #[test]
    fn management_addresses_are_capped_and_unique() {
        let mut s = LldpSettings {
            management_addresses: (1..=4).map(|i| IpAddr::from([10, 0, 0, i])).collect(),
            ..LldpSettings::default()
        };
        assert!(s.check().is_ok());
        s.management_addresses.push(IpAddr::from([10, 0, 0, 5]));
        assert!(s.check().is_err());
        s.management_addresses = vec![IpAddr::from([10, 0, 0, 1]); 2];
        assert!(s.check().is_err());
    }

    #[test]
    fn legacy_single_address_loads_as_a_list() {
        let s: LldpSettings = serde_json::from_str(r#"{"management_address":"10.0.0.1"}"#).unwrap();
        assert_eq!(s.management_addresses, [IpAddr::from([10, 0, 0, 1])]);
        let s = LldpSettings {
            management_addresses: vec![IpAddr::from([10, 0, 0, 1]), "2001:db8::1".parse().unwrap()],
            ..LldpSettings::default()
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<LldpSettings>(&json).unwrap(), s);
        assert_eq!(
            serde_json::from_str::<LldpSettings>("{}").unwrap(),
            LldpSettings::default()
        );
    }

    #[test]
    fn system_description_defaults_and_validates() {
        let with = |d: &str| LldpSettings {
            system_description: Some(d.to_string()),
            ..LldpSettings::default()
        };
        assert_eq!(
            LldpSettings::default().effective_system_description(),
            "nos"
        );
        assert_eq!(
            with("core router").effective_system_description(),
            "core router"
        );
        assert!(with("core router").check().is_ok());
        assert!(with(&"x".repeat(255)).check().is_ok());
        assert!(with(&"x".repeat(256)).check().is_err());
        assert!(with("").check().is_err());
        assert!(with("a\nb").check().is_err());
        assert!(with("a\x1bb").check().is_err());
        // A config saved before the knob existed still loads.
        let s: LldpSettings = serde_json::from_str(r#"{"tx_hold":3}"#).unwrap();
        assert_eq!(s.system_description, None);
    }

    #[test]
    fn destination_macs_and_names_round_trip() {
        assert_eq!(LldpDestination::default().mac()[5], 0x0E);
        assert_eq!(LldpDestination::NonTpmr.mac()[5], 0x03);
        assert_eq!(LldpDestination::CustomerBridge.mac()[5], 0x00);
        for d in [
            LldpDestination::NearestBridge,
            LldpDestination::NonTpmr,
            LldpDestination::CustomerBridge,
        ] {
            assert_eq!(LldpDestination::from_name(d.name()), Some(d));
        }
        assert_eq!(LldpDestination::from_name("bogus"), None);
    }
}
