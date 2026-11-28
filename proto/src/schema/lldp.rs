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

/// Most civic-address elements one location carries.
pub const CIVIC_ELEMENTS_MAX: usize = 16;
/// Largest encoded civic address (TIA-1057 LCI length limit, bytes).
pub const CIVIC_BYTES_MAX: usize = 250;

/// A civic-address element (RFC 4776 `CAtype` and its value).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct LldpCivicElement {
    #[cli(key)]
    /// RFC 4776 `CAtype` (0..=255); the key, so at most one element per type.
    pub ca_type: u8,
    #[serde(default)]
    #[cli(topic = LldpCivicElementValue)]
    /// The element's text (UTF-8), not empty.
    pub value: String,
}

/// A civic address (RFC 4776 layout).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct LldpCivicAddress {
    #[serde(default)]
    #[cli(topic = LldpCivicWhat)]
    /// Which location the address describes: 0 DHCP server, 1 network element, 2 client.
    pub what: u8,
    #[serde(default)]
    #[cli(topic = LldpCivicCountry)]
    /// Two uppercase ASCII letters (ISO 3166).
    pub country: String,
    #[serde(default)]
    #[cli(topic = LldpCivicElementList, words = "element")]
    /// Address elements, at most 16, encoded in at most 250 bytes.
    pub elements: Vec<LldpCivicElement>,
}

/// Geodetic datum (RFC 3825).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum LldpDatum {
    /// WGS 84.
    #[default]
    Wgs84,
    /// NAD83 / NAVD88.
    Nad83Navd88,
    /// NAD83 / MLLW.
    Nad83Mllw,
}

/// Unit of an altitude (RFC 3825).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum LldpAltitudeUnit {
    #[default]
    /// Meters.
    Meters,
    /// Building floors.
    Floors,
}

fn resolution_default() -> u8 {
    34
}

/// A coordinate location (RFC 3825 layout). Degrees are decimal strings so the
/// schema stays `Eq` and round-trips exactly; the 25.9 fixed-point encoding is
/// the daemon's job.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct LldpCoordinate {
    #[serde(default)]
    #[cli(topic = LldpCoordinateLatitude)]
    /// Latitude in decimal degrees, -90 to 90.
    pub latitude: String,
    #[serde(default = "resolution_default")]
    #[cli(topic = LldpCoordinateLatitudeResolution)]
    /// Valid bits of the latitude, 0..=34 (0 means unknown).
    pub latitude_resolution: u8,
    #[serde(default)]
    #[cli(topic = LldpCoordinateLongitude)]
    /// Longitude in decimal degrees, -180 to 180.
    pub longitude: String,
    #[serde(default = "resolution_default")]
    #[cli(topic = LldpCoordinateLongitudeResolution)]
    /// Valid bits of the longitude, 0..=34 (0 means unknown).
    pub longitude_resolution: u8,
    #[serde(default)]
    #[cli(topic = LldpCoordinateAltitude)]
    /// Altitude as a decimal number, in `altitude-unit`; `None`: not advertised.
    pub altitude: Option<String>,
    #[serde(default)]
    #[cli(topic = LldpCoordinateAltitudeUnit)]
    /// Unit of the altitude.
    pub altitude_unit: LldpAltitudeUnit,
    #[serde(default)]
    #[cli(topic = LldpCoordinateAltitudeResolution)]
    /// Valid bits of the altitude, 0..=30 (0 means unknown).
    pub altitude_resolution: u8,
    #[serde(default)]
    #[cli(topic = LldpCoordinateDatum)]
    /// Geodetic datum.
    pub datum: LldpDatum,
}

impl Default for LldpCoordinate {
    fn default() -> Self {
        Self {
            latitude: String::new(),
            latitude_resolution: resolution_default(),
            longitude: String::new(),
            longitude_resolution: resolution_default(),
            altitude: None,
            altitude_unit: LldpAltitudeUnit::default(),
            altitude_resolution: 0,
            datum: LldpDatum::default(),
        }
    }
}

/// A port's location (LLDP-MED location identification): any of the three
/// formats may be set. `civic` and `coordinate` are plain structs, not
/// `Option`s, so the CLI can address their fields one by one; an element equal
/// to its `Default` is "not set" (see `is_empty`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct LldpLocation {
    #[serde(default)]
    #[cli(topic = LldpLocationElin)]
    /// Emergency Location Identification Number: 10 to 25 ASCII digits.
    pub elin: Option<String>,
    #[serde(default)]
    #[cli(topic = LldpLocationCivic)]
    /// Civic address; the default (no country, no elements) means none.
    pub civic: LldpCivicAddress,
    #[serde(default)]
    #[cli(topic = LldpLocationCoordinate)]
    /// Coordinates; the default (no latitude, no longitude) means none.
    pub coordinate: LldpCoordinate,
}

fn decimal_in(s: &str, what: &str, limit: f64) -> Result<(), String> {
    // `f64::from_str` also takes "inf", "nan" and "1e3": allow plain decimals only.
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | '+' | '.'))
        && s.chars().any(|c| c.is_ascii_digit());
    match s.parse::<f64>() {
        Ok(v) if plain && v.is_finite() && v.abs() <= limit => Ok(()),
        _ => Err(format!("{what} must be a decimal number within ±{limit}")),
    }
}

impl LldpLocation {
    /// Commit-time validation (`Interface.lldp_location`'s `garde` custom check).
    pub fn check(&self) -> Result<(), String> {
        if let Some(e) = &self.elin
            && !((10..=25).contains(&e.len()) && e.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err("elin must be 10 to 25 ASCII digits".into());
        }
        if self.civic != LldpCivicAddress::default() {
            self.civic.check()?;
        }
        if self.coordinate != LldpCoordinate::default() {
            self.coordinate.check()?;
        }
        Ok(())
    }

    /// Nothing is set: no ELIN, civic address or coordinates.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl LldpCivicAddress {
    fn check(&self) -> Result<(), String> {
        if self.what > 2 {
            return Err("civic what must be 0..=2".into());
        }
        if self.country.len() != 2 || !self.country.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err("civic country must be two uppercase ASCII letters".into());
        }
        if self.elements.len() > CIVIC_ELEMENTS_MAX {
            return Err(format!("at most {CIVIC_ELEMENTS_MAX} civic elements"));
        }
        let mut size = 3;
        for (i, e) in self.elements.iter().enumerate() {
            if self.elements[..i].iter().any(|o| o.ca_type == e.ca_type) {
                return Err(format!("civic element {} is listed twice", e.ca_type));
            }
            if e.value.is_empty() {
                return Err(format!("civic element {} has an empty value", e.ca_type));
            }
            size += 2 + e.value.len();
        }
        if size > CIVIC_BYTES_MAX {
            return Err(format!(
                "civic address encodes to {size} bytes, at most {CIVIC_BYTES_MAX}"
            ));
        }
        Ok(())
    }
}

impl LldpCoordinate {
    fn check(&self) -> Result<(), String> {
        decimal_in(&self.latitude, "latitude", 90.0)?;
        decimal_in(&self.longitude, "longitude", 180.0)?;
        if self.latitude_resolution > 34 || self.longitude_resolution > 34 {
            return Err("latitude/longitude resolution must be 0..=34".into());
        }
        if let Some(a) = &self.altitude {
            // 22 bits of integer part in RFC 3825.
            decimal_in(a, "altitude", 2_097_151.0)?;
        }
        if self.altitude_resolution > 30 {
            return Err("altitude resolution must be 0..=30".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod location_tests {
    use super::*;

    fn civic(elements: &[(u8, &str)]) -> LldpLocation {
        LldpLocation {
            civic: LldpCivicAddress {
                country: "FR".into(),
                elements: elements
                    .iter()
                    .map(|(t, v)| LldpCivicElement {
                        ca_type: *t,
                        value: (*v).into(),
                    })
                    .collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn coord(lat: &str, long: &str) -> LldpLocation {
        LldpLocation {
            coordinate: LldpCoordinate {
                latitude: lat.into(),
                longitude: long.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn elin_is_10_to_25_digits() {
        let elin = |s: &str| LldpLocation {
            elin: Some(s.into()),
            ..Default::default()
        };
        assert!(elin("1234567890").check().is_ok());
        assert!(elin(&"1".repeat(25)).check().is_ok());
        assert!(elin("123456789").check().is_err());
        assert!(elin(&"1".repeat(26)).check().is_err());
        assert!(elin("12345abcde").check().is_err());
        assert!(LldpLocation::default().check().is_ok());
    }

    #[test]
    fn civic_rules() {
        assert!(civic(&[(3, "Paris"), (6, "Rue X")]).check().is_ok());
        let many: Vec<(u8, &str)> = (0..17).map(|i| (i, "x")).collect();
        assert!(civic(&many).check().is_err());
        assert!(civic(&[(3, "a"), (3, "b")]).check().is_err());
        assert!(civic(&[(3, "")]).check().is_err());
        // 3 + 2 + 245 = 250 fits, one more byte does not.
        let fit = "x".repeat(245);
        assert!(civic(&[(3, &fit)]).check().is_ok());
        assert!(civic(&[(3, &format!("{fit}x"))]).check().is_err());
        let mut bad = civic(&[]);
        bad.civic.country = "fr".into();
        assert!(bad.check().is_err());
        bad.civic.country = "FR".into();
        bad.civic.what = 3;
        assert!(bad.check().is_err());
    }

    #[test]
    fn coordinate_rules() {
        assert!(coord("48.8566", "-2.35").check().is_ok());
        assert!(coord("90", "180").check().is_ok());
        assert!(coord("90.1", "0").check().is_err());
        assert!(coord("0", "-180.5").check().is_err());
        assert!(coord("nan", "0").check().is_err());
        assert!(coord("inf", "0").check().is_err());
        assert!(coord("1e1", "0").check().is_err());
        assert!(coord("", "0").check().is_err());
        let mut l = coord("1", "1");
        let c = &mut l.coordinate;
        c.latitude_resolution = 35;
        assert!(l.check().is_err());
        let c = &mut l.coordinate;
        c.latitude_resolution = 34;
        c.altitude = Some("12.5".into());
        c.altitude_resolution = 31;
        assert!(l.check().is_err());
        l.coordinate.altitude_resolution = 30;
        assert!(l.check().is_ok());
        l.coordinate.altitude = Some("x".into());
        assert!(l.check().is_err());
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
