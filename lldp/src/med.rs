//! LLDP-MED (ANSI/TIA-1057) TLV codec, pure. Layouts follow TIA-1057 §10.2
//! (paywalled), cross-checked against lldpd (`src/daemon/protocols/lldp.c`,
//! `src/lib/atoms/med.c`) and Wireshark (`epan/dissectors/packet-lldp.c`,
//! `dissect_media_tlv`). Coordinate data is RFC 3825 §2.1, civic RFC 4776 §3.1.
//! Typed structs here are independent of the config schema: #1572 maps each
//! interface's location onto them. Input is untrusted: nothing here panics.

use std::fmt::Write as _;

use nos_proto::lldp::{LldpMed, LldpMedInventory, LldpMedLocation, LldpMedPolicy, LldpMedPower};

use crate::packet::{lossy, OrgTlvs};

pub const OUI_TIA: [u8; 3] = [0x00, 0x12, 0xbb];
pub const MED_CAPS: u8 = 1;
pub const MED_POLICY: u8 = 2;
pub const MED_LOCATION: u8 = 3;
pub const MED_POWER: u8 = 4;
/// Inventory subtypes 5 (hardware revision) to 11 (asset id).
pub const MED_INVENTORY_FIRST: u8 = 5;
pub const MED_INVENTORY_LAST: u8 = 11;

/// At most this many Network Policy TLVs are kept per LLDPDU (one per
/// application type, 8 are named).
pub const MAX_MED_POLICIES: usize = 8;
const MAX_INVENTORY: usize = 32;
const COORDINATE_LEN: usize = 16;
const ELIN_LEN: std::ops::RangeInclusive<usize> = 10..=25;

const LOC_COORDINATE: u8 = 1;
const LOC_CIVIC: u8 = 2;
const LOC_ELIN: u8 = 3;

/// MED Capabilities TLV: bitmap and device type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MedCaps {
    pub caps: u16,
    pub device_type: u8,
}

/// Network Policy TLV. `app_type` and `vlan` are kept raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MedPolicy {
    pub app_type: u8,
    pub unknown: bool,
    pub tagged: bool,
    pub vlan: u16,
    pub priority: u8,
    pub dscp: u8,
}

/// RFC 3825 coordinate location: 34-bit lat/lng and 30-bit altitude, two's
/// complement, sign-extended here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coordinate {
    pub lat_res: u8,
    pub lat: i64,
    pub lng_res: u8,
    pub lng: i64,
    pub alt_type: u8,
    pub alt_res: u8,
    pub alt: i32,
    pub datum: u8,
}

/// One Location Identification TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MedLocation {
    Coordinate(Coordinate),
    /// RFC 4776 civic address data (LCI length byte included), validated.
    Civic(Vec<u8>),
    /// Emergency Location Identification Number, 10 to 25 bytes.
    Elin(Vec<u8>),
}

impl MedLocation {
    fn format(&self) -> u8 {
        match self {
            Self::Coordinate(_) => LOC_COORDINATE,
            Self::Civic(_) => LOC_CIVIC,
            Self::Elin(_) => LOC_ELIN,
        }
    }
}

/// Extended Power via MDI TLV (`kind` 0 PSE, 1 PD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MedPower {
    pub kind: u8,
    pub source: u8,
    pub priority: u8,
    pub deci_watts: u16,
}

/// Inventory TLV (decode only, never sent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MedInventory {
    pub field: u8,
    pub value: String,
}

fn small(v: u128) -> u8 {
    u8::try_from(v).expect("masked to 8 bits")
}

fn bits(v: u128, shift: u32, width: u32) -> u128 {
    (v >> shift) & ((1 << width) - 1)
}

/// Sign-extends the low `width` bits of `v`.
fn signed(v: u128, width: u32) -> i64 {
    let shift = 128 - width;
    i64::try_from(((v << shift).cast_signed()) >> shift).expect("<= 34 bits")
}

impl Coordinate {
    fn decode(b: &[u8]) -> Option<Self> {
        let v = u128::from_be_bytes(<[u8; COORDINATE_LEN]>::try_from(b).ok()?);
        Some(Self {
            lat_res: small(bits(v, 122, 6)),
            lat: signed(bits(v, 88, 34), 34),
            lng_res: small(bits(v, 82, 6)),
            lng: signed(bits(v, 48, 34), 34),
            alt_type: small(bits(v, 44, 4)),
            alt_res: small(bits(v, 38, 6)),
            alt: i32::try_from(signed(bits(v, 8, 30), 30)).expect("30 bits"),
            datum: small(bits(v, 0, 8)),
        })
    }

    fn encode(&self) -> [u8; COORDINATE_LEN] {
        let field = |v: i64, width: u32| u128::from(v.cast_unsigned()) & ((1 << width) - 1);
        (u128::from(self.lat_res & 0x3f) << 122
            | field(self.lat, 34) << 88
            | u128::from(self.lng_res & 0x3f) << 82
            | field(self.lng, 34) << 48
            | u128::from(self.alt_type & 0xf) << 44
            | u128::from(self.alt_res & 0x3f) << 38
            | field(i64::from(self.alt), 30) << 8
            | u128::from(self.datum))
        .to_be_bytes()
    }

    #[allow(clippy::cast_precision_loss, reason = "34-bit value, display only")]
    /// `lat=… lng=… alt=… datum=…`; degrees with 25 fractional bits, display only.
    fn display(&self) -> String {
        let deg = |v: i64| v as f64 / f64::from(1u32 << 25);
        let alt = match self.alt_type {
            1 => format!("{:.2}m", f64::from(self.alt) / 256.0),
            2 => format!("{:.2}floor", f64::from(self.alt) / 256.0),
            n => format!("raw({})type({n})", self.alt),
        };
        let datum = match self.datum {
            1 => "wgs84".to_string(),
            2 => "nad83-navd88".to_string(),
            3 => "nad83-mllw".to_string(),
            n => format!("unknown({n})"),
        };
        format!(
            "lat={:.7}/{} lng={:.7}/{} alt={alt} datum={datum}",
            deg(self.lat),
            self.lat_res,
            deg(self.lng),
            self.lng_res
        )
    }
}

/// Walks RFC 4776's `LCI length, what, country(2), (type, len, value)*`
/// and accepts only when every entry sits inside the declared length.
fn civic_is_valid(data: &[u8]) -> bool {
    let Some((&lci_len, rest)) = data.split_first() else {
        return false;
    };
    if usize::from(lci_len) != rest.len() || rest.len() < 3 {
        return false;
    }
    let mut ca = &rest[3..];
    while !ca.is_empty() {
        let Some(&len) = ca.get(1) else { return false };
        let Some(next) = ca.get(2 + usize::from(len)..) else {
            return false;
        };
        ca = next;
    }
    true
}

fn civic_display(data: &[u8]) -> String {
    let rest = &data[1..];
    let mut out = format!("what={} country={}", rest[0], lossy(&rest[1..3]));
    let mut ca = &rest[3..];
    while let [t, len, tail @ ..] = ca {
        let (v, next) = tail.split_at(usize::from(*len));
        let _ = write!(out, " ca{t}={}", lossy(v));
        ca = next;
    }
    out
}

impl MedLocation {
    fn display(&self) -> (&'static str, String) {
        match self {
            Self::Coordinate(c) => ("coordinate", c.display()),
            Self::Civic(d) => ("civic", civic_display(d)),
            Self::Elin(d) => ("elin", lossy(d)),
        }
    }
}

/// Decimal degrees/meters to a fixed-point field: `frac` fractional bits,
/// rounded. The schema validated the string; a bad one yields 0.
#[allow(clippy::cast_possible_truncation, reason = "validated range")]
fn fixed(s: &str, frac: u32) -> i64 {
    (s.parse::<f64>().unwrap_or(0.0) * f64::from(1u32 << frac)).round() as i64
}

/// The Location TLVs a port's configured location describes: coordinate,
/// civic and ELIN, in that order, each only when set.
pub fn locations_from_config(l: &nos_proto::schema::LldpLocation) -> Vec<MedLocation> {
    let mut out = Vec::new();
    let c = &l.coordinate;
    if *c != nos_proto::schema::LldpCoordinate::default() {
        let (alt_type, alt) = match &c.altitude {
            None => (0, 0),
            Some(a) => (
                match c.altitude_unit {
                    nos_proto::schema::LldpAltitudeUnit::Meters => 1,
                    nos_proto::schema::LldpAltitudeUnit::Floors => 2,
                },
                i32::try_from(fixed(a, 8)).unwrap_or(0),
            ),
        };
        out.push(MedLocation::Coordinate(Coordinate {
            lat_res: c.latitude_resolution,
            lat: fixed(&c.latitude, 25),
            lng_res: c.longitude_resolution,
            lng: fixed(&c.longitude, 25),
            alt_type,
            alt_res: c.altitude_resolution,
            alt,
            datum: match c.datum {
                nos_proto::schema::LldpDatum::Wgs84 => 1,
                nos_proto::schema::LldpDatum::Nad83Navd88 => 2,
                nos_proto::schema::LldpDatum::Nad83Mllw => 3,
            },
        }));
    }
    let a = &l.civic;
    if *a != nos_proto::schema::LldpCivicAddress::default() {
        let mut d = vec![0, a.what];
        d.extend_from_slice(a.country.as_bytes());
        for e in &a.elements {
            d.push(e.ca_type);
            d.push(u8::try_from(e.value.len()).unwrap_or(u8::MAX));
            d.extend_from_slice(e.value.as_bytes());
        }
        d[0] = u8::try_from(d.len() - 1).unwrap_or(u8::MAX);
        out.push(MedLocation::Civic(d));
    }
    if let Some(e) = &l.elin {
        out.push(MedLocation::Elin(e.as_bytes().to_vec()));
    }
    out
}

/// Appends one TIA TLV unless the LLDPDU would outgrow `max` (End TLV
/// included); the caller keeps whole TLVs only. Returns whether it fit.
fn push(out: &mut Vec<u8>, max: usize, subtype: u8, info: &[u8]) -> bool {
    // Header (2) + OUI/subtype (4) + info, End TLV (2) still to come.
    if out.len() + 6 + info.len() + 2 > max {
        tracing::debug!(subtype, "lldpdu full, not advertising a med tlv");
        return false;
    }
    crate::packet::push_org(out, OUI_TIA, subtype, info);
    true
}

/// Appends the MED TLVs of `org`: capabilities, policies, locations
/// (coordinate, civic, ELIN), power. Inventory is never sent.
pub fn encode_med(out: &mut Vec<u8>, org: &OrgTlvs, max: usize) {
    if let Some(c) = org.med_caps {
        let mut info = c.caps.to_be_bytes().to_vec();
        info.push(c.device_type);
        push(out, max, MED_CAPS, &info);
    }
    for p in &org.med_policies {
        let v = u32::from(p.unknown) << 23
            | u32::from(p.tagged) << 22
            | u32::from(p.vlan & 0xfff) << 9
            | u32::from(p.priority & 7) << 6
            | u32::from(p.dscp & 0x3f);
        let mut info = vec![p.app_type];
        info.extend_from_slice(&v.to_be_bytes()[1..]);
        push(out, max, MED_POLICY, &info);
    }
    for format in [LOC_COORDINATE, LOC_CIVIC, LOC_ELIN] {
        for l in org.med_locations.iter().filter(|l| l.format() == format) {
            let mut info = vec![format];
            match l {
                MedLocation::Coordinate(c) => info.extend_from_slice(&c.encode()),
                MedLocation::Civic(d) | MedLocation::Elin(d) => info.extend_from_slice(d),
            }
            push(out, max, MED_LOCATION, &info);
        }
    }
    if let Some(p) = org.med_power {
        let b = (p.kind & 3) << 6 | (p.source & 3) << 4 | (p.priority & 0xf);
        let w = p.deci_watts.to_be_bytes();
        push(out, max, MED_POWER, &[b, w[0], w[1]]);
    }
}

/// Decodes one TIA TLV (`subtype`, `info`) into `org`. `Some(true)` kept,
/// `Some(false)` malformed/repeat/past the cap, `None` unknown subtype.
pub fn decode_med(subtype: u8, info: &[u8], org: &mut OrgTlvs) -> Option<bool> {
    Some(match subtype {
        MED_CAPS => match *info {
            [a, b, device_type] if org.med_caps.is_none() => {
                org.med_caps = Some(MedCaps {
                    caps: u16::from_be_bytes([a, b]),
                    device_type,
                });
                true
            }
            _ => false,
        },
        MED_POLICY => match *info {
            [app_type, a, b, c]
                if org.med_policies.len() < MAX_MED_POLICIES
                    && org.med_policies.iter().all(|p| p.app_type != app_type) =>
            {
                let v = u32::from_be_bytes([0, a, b, c]);
                org.med_policies.push(MedPolicy {
                    app_type,
                    unknown: v >> 23 & 1 != 0,
                    tagged: v >> 22 & 1 != 0,
                    // Bit 21 (X) is reserved and ignored; VID 4095 kept.
                    vlan: (v >> 9 & 0xfff) as u16,
                    priority: (v >> 6 & 7) as u8,
                    dscp: (v & 0x3f) as u8,
                });
                true
            }
            _ => false,
        },
        MED_LOCATION => {
            let loc = match info.split_first() {
                Some((&LOC_COORDINATE, d)) => Coordinate::decode(d).map(MedLocation::Coordinate),
                Some((&LOC_CIVIC, d)) => civic_is_valid(d).then(|| MedLocation::Civic(d.to_vec())),
                Some((&LOC_ELIN, d)) => ELIN_LEN
                    .contains(&d.len())
                    .then(|| MedLocation::Elin(d.to_vec())),
                _ => None,
            };
            match loc {
                Some(l) if org.med_locations.iter().all(|o| o.format() != l.format()) => {
                    org.med_locations.push(l);
                    true
                }
                _ => false,
            }
        }
        MED_POWER => match *info {
            [b, w0, w1] if org.med_power.is_none() && b >> 6 < 2 => {
                org.med_power = Some(MedPower {
                    kind: b >> 6,
                    source: b >> 4 & 3,
                    priority: b & 0xf,
                    deci_watts: u16::from_be_bytes([w0, w1]),
                });
                true
            }
            _ => false,
        },
        MED_INVENTORY_FIRST..=MED_INVENTORY_LAST => {
            if info.len() > MAX_INVENTORY || org.med_inventory.iter().any(|i| i.field == subtype) {
                false
            } else {
                org.med_inventory.push(MedInventory {
                    field: subtype,
                    value: lossy(info),
                });
                true
            }
        }
        _ => return None,
    })
}

fn named(n: u8, names: &[&str]) -> String {
    names
        .get(usize::from(n))
        .map_or_else(|| format!("unknown({n})"), ToString::to_string)
}

/// The proto view of the MED TLVs kept in `org`, `None` when there are none.
pub fn to_proto(org: &OrgTlvs) -> Option<LldpMed> {
    if org.med_caps.is_none()
        && org.med_policies.is_empty()
        && org.med_locations.is_empty()
        && org.med_power.is_none()
        && org.med_inventory.is_empty()
    {
        return None;
    }
    let caps = org.med_caps.unwrap_or(MedCaps {
        caps: 0,
        device_type: 0,
    });
    let device_type = match caps.device_type {
        n @ 1..=3 => format!("endpoint-class-{n}"),
        4 => "network-connectivity".to_string(),
        n => format!("unknown({n})"),
    };
    let cap_names = [
        "capabilities",
        "network-policy",
        "location",
        "power-pse",
        "power-pd",
        "inventory",
    ];
    Some(LldpMed {
        device_type,
        capabilities: cap_names
            .iter()
            .enumerate()
            .filter(|(i, _)| caps.caps >> i & 1 != 0)
            .map(|(_, n)| (*n).to_string())
            .collect(),
        policies: org
            .med_policies
            .iter()
            .map(|p| LldpMedPolicy {
                app_type: named(
                    p.app_type,
                    &[
                        "unknown(0)",
                        "voice",
                        "voice-signaling",
                        "guest-voice",
                        "guest-voice-signaling",
                        "softphone-voice",
                        "video-conferencing",
                        "streaming-video",
                        "video-signaling",
                    ],
                ),
                vlan: (p.vlan != 0).then_some(p.vlan),
                tagged: p.tagged,
                unknown: p.unknown,
                priority: p.priority,
                dscp: p.dscp,
            })
            .collect(),
        locations: org
            .med_locations
            .iter()
            .map(|l| {
                let (format, text) = l.display();
                LldpMedLocation {
                    format: format.to_string(),
                    text,
                }
            })
            .collect(),
        power: org.med_power.map(|p| LldpMedPower {
            kind: if p.kind == 0 { "pse" } else { "pd" }.to_string(),
            source: if p.kind == 0 {
                named(p.source, &["unknown", "primary", "backup", "reserved"])
            } else {
                named(p.source, &["unknown", "pse", "local", "pse-and-local"])
            },
            priority: named(p.priority, &["unknown", "critical", "high", "low"]),
            watts_deci: p.deci_watts,
        }),
        inventory: org
            .med_inventory
            .iter()
            .map(|i| LldpMedInventory {
                field: named(
                    i.field - MED_INVENTORY_FIRST,
                    &[
                        "hardware-revision",
                        "firmware-revision",
                        "software-revision",
                        "serial-number",
                        "manufacturer",
                        "model-name",
                        "asset-id",
                    ],
                ),
                value: i.value.clone(),
            })
            .collect(),
    })
}

/// One-line rendering for logs (`-` when there is no MED TLV).
pub fn display(med: Option<&LldpMed>) -> String {
    let Some(m) = med else {
        return "-".to_string();
    };
    let mut parts = vec![m.device_type.clone()];
    if !m.capabilities.is_empty() {
        parts.push(format!("caps:{}", m.capabilities.join("+")));
    }
    for p in &m.policies {
        parts.push(format!(
            "{}:vlan={}{}/p{}/dscp{}",
            p.app_type,
            p.vlan.map_or_else(|| "-".to_string(), |v| v.to_string()),
            if p.tagged { "t" } else { "u" },
            p.priority,
            p.dscp
        ));
    }
    for l in &m.locations {
        parts.push(format!("{}:{}", l.format, l.text));
    }
    if let Some(p) = &m.power {
        parts.push(format!(
            "power:{}/{}/{}/{}.{}W",
            p.kind,
            p.source,
            p.priority,
            p.watts_deci / 10,
            p.watts_deci % 10
        ));
    }
    for i in &m.inventory {
        parts.push(format!("{}={}", i.field, i.value));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{decode, decode_counted, encode, Id, Lldpdu};

    // lat 34.0 (34 << 25), lng -118.0, altitude 2.5 m (type 1, 640 / 256).
    fn coordinate() -> Coordinate {
        Coordinate {
            lat_res: 25,
            lat: 34 << 25,
            lng_res: 25,
            lng: -(118 << 25),
            alt_type: 1,
            alt_res: 16,
            alt: 640,
            datum: 1,
        }
    }

    fn civic() -> Vec<u8> {
        // LCI length 12, what 1, "US", CA 3 (A3) "Paris", CA 6 "Rue".
        let mut d = vec![0, 1, b'U', b'S', 3, 5];
        d.extend_from_slice(b"Paris");
        d.extend_from_slice(&[6, 3]);
        d.extend_from_slice(b"Rue");
        d[0] = u8::try_from(d.len() - 1).unwrap();
        d
    }

    fn full() -> OrgTlvs {
        OrgTlvs {
            med_caps: Some(MedCaps {
                caps: 0b11_1111,
                device_type: 3,
            }),
            med_policies: (1..=8)
                .map(|app_type| MedPolicy {
                    app_type,
                    unknown: app_type == 2,
                    tagged: app_type % 2 == 1,
                    vlan: 100 + u16::from(app_type),
                    priority: 5,
                    dscp: 46,
                })
                .collect(),
            med_locations: vec![
                MedLocation::Coordinate(coordinate()),
                MedLocation::Civic(civic()),
                MedLocation::Elin(b"4155550100".to_vec()),
            ],
            med_power: Some(MedPower {
                kind: 1,
                source: 2,
                priority: 3,
                deci_watts: 154,
            }),
            ..OrgTlvs::default()
        }
    }

    fn pdu(org: OrgTlvs) -> Lldpdu {
        Lldpdu {
            chassis_id: Id {
                subtype: 4,
                value: vec![2, 0, 0, 0, 0, 1],
            },
            port_id: Id {
                subtype: 5,
                value: b"eth1".to_vec(),
            },
            ttl: 120,
            port_description: None,
            system_name: None,
            system_description: None,
            capabilities: None,
            management_addresses: Vec::new(),
            org,
        }
    }

    /// A raw TIA TLV for hand-built frames.
    fn tia(subtype: u8, info: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        crate::packet::push_org(&mut out, OUI_TIA, subtype, info);
        out
    }

    fn with_tlvs(tlvs: &[Vec<u8>]) -> (Lldpdu, crate::packet::TlvCounts) {
        let mut wire = encode(&pdu(OrgTlvs::default()));
        wire.truncate(wire.len() - 2); // End TLV
        for t in tlvs {
            wire.extend_from_slice(t);
        }
        wire.extend_from_slice(&[0, 0]);
        decode_counted(&wire).unwrap()
    }

    #[test]
    fn everything_round_trips() {
        let p = pdu(full());
        assert_eq!(decode(&encode(&p)).unwrap(), p);
    }

    #[test]
    fn exact_wire_bytes() {
        assert_eq!(
            tia(MED_CAPS, &[0, 0x23, 3]),
            [0xfe, 7, 0x00, 0x12, 0xbb, 1, 0x00, 0x23, 3]
        );
        // voice, tagged, vid 100, prio 5, dscp 46:
        // 0 1 0 | 000001100100 | 101 | 101110 = 0x40 0xC9 0x6E
        let org = OrgTlvs {
            med_policies: vec![MedPolicy {
                app_type: 1,
                unknown: false,
                tagged: true,
                vlan: 100,
                priority: 5,
                dscp: 46,
            }],
            ..OrgTlvs::default()
        };
        let mut out = Vec::new();
        encode_med(&mut out, &org, 1500);
        assert_eq!(out, tia(MED_POLICY, &[1, 0x40, 0xc9, 0x6e]));
        // PD, source local, priority high, 15.4 W.
        let org = OrgTlvs {
            med_power: full().med_power,
            ..OrgTlvs::default()
        };
        let mut out = Vec::new();
        encode_med(&mut out, &org, 1500);
        assert_eq!(out, tia(MED_POWER, &[0b0110_0011, 0, 154]));
    }

    #[test]
    fn coordinate_vector_and_negative_values() {
        let c = coordinate();
        let b = c.encode();
        // lat_res 25 | lat 34<<25 | lng_res 25 | lng -118<<25 ...
        assert_eq!(b[0] >> 2, 25);
        assert_eq!(Coordinate::decode(&b), Some(c));
        let p = to_proto(&OrgTlvs {
            med_locations: vec![MedLocation::Coordinate(c)],
            ..OrgTlvs::default()
        })
        .unwrap();
        assert_eq!(
            p.locations[0].text,
            "lat=34.0000000/25 lng=-118.0000000/25 alt=2.50m datum=wgs84"
        );
        let mut neg = c;
        neg.lat = -1;
        neg.alt = -256;
        neg.alt_type = 2;
        neg.datum = 9;
        assert_eq!(Coordinate::decode(&neg.encode()), Some(neg));
        assert!(neg.display().contains("alt=-1.00floor datum=unknown(9)"));
    }

    #[test]
    fn rendering() {
        let m = to_proto(&full()).unwrap();
        assert_eq!(m.device_type, "endpoint-class-3");
        assert_eq!(m.capabilities.len(), 6);
        assert_eq!(m.policies[0].app_type, "voice");
        assert_eq!(m.policies[1].vlan, Some(102));
        assert!(m.locations[1].text.contains("country=US ca3=Paris ca6=Rue"));
        assert_eq!(m.locations[2].text, "4155550100");
        let p = m.power.as_ref().unwrap();
        assert_eq!(
            (p.kind.as_str(), p.source.as_str(), p.priority.as_str()),
            ("pd", "local", "low")
        );
        let line = display(Some(&m));
        assert!(
            line.starts_with("endpoint-class-3 caps:capabilities+network-policy"),
            "{line}"
        );
        assert!(line.contains("power:pd/local/low/15.4W"), "{line}");
        assert_eq!(display(None), "-");
        assert_eq!(to_proto(&OrgTlvs::default()), None);
        let odd = OrgTlvs {
            med_caps: Some(MedCaps {
                caps: 0,
                device_type: 9,
            }),
            med_policies: vec![MedPolicy {
                app_type: 0,
                unknown: true,
                tagged: false,
                vlan: 0,
                priority: 0,
                dscp: 0,
            }],
            ..OrgTlvs::default()
        };
        let m = to_proto(&odd).unwrap();
        assert_eq!(m.device_type, "unknown(9)");
        assert_eq!(
            (m.policies[0].app_type.as_str(), m.policies[0].vlan),
            ("unknown(0)", None)
        );
    }

    #[test]
    fn inventory_is_decoded_never_encoded_and_cleaned() {
        let (p, c) = with_tlvs(&[tia(9, b"Acme\x1b[2J"), tia(8, b"SN1"), tia(8, b"dup")]);
        assert_eq!(c.discarded, 1);
        assert_eq!(p.org.med_inventory.len(), 2);
        assert_eq!(p.org.med_inventory[0].value, "Acme\u{fffd}[2J");
        let m = to_proto(&p.org).unwrap();
        assert_eq!(m.inventory[0].field, "manufacturer");
        assert_eq!(m.inventory[1].field, "serial-number");
        let again = decode(&encode(&p)).unwrap();
        assert_eq!(again.org.med_inventory, []);
        let (_, c) = with_tlvs(&[tia(5, &[b'x'; 33])]);
        assert_eq!(c.discarded, 1);
    }

    #[test]
    fn rejects_count_discarded_and_first_wins() {
        let bad = [
            tia(MED_CAPS, &[0, 1]),
            tia(MED_POLICY, &[1, 0, 0]),
            tia(MED_POWER, &[0, 0]),
            tia(MED_POWER, &[0b1000_0000, 0, 1]), // type 2
            tia(MED_LOCATION, &[]),
            tia(MED_LOCATION, &[LOC_COORDINATE, 1, 2, 3]),
            tia(MED_LOCATION, &[&[LOC_ELIN][..], &[b'1'; 9]].concat()),
            tia(MED_LOCATION, &[&[LOC_ELIN][..], &[b'1'; 26]].concat()),
            tia(
                MED_LOCATION,
                &[&[LOC_CIVIC][..], &[9, 1, b'U', b'S', 3, 9, 0, 0, 0, 0]].concat(),
            ), // CA overruns
            tia(MED_LOCATION, &[9, 1, 2]),
        ];
        let (p, c) = with_tlvs(&bad);
        assert_eq!(c.discarded, bad.len() as u64);
        assert_eq!(c.unrecognized, 0);
        assert_eq!(to_proto(&p.org), None);

        let caps = |t| tia(MED_CAPS, &[0, 1, t]);
        let power = |w| tia(MED_POWER, &[0, 0, w]);
        let elin = |n: u8| tia(MED_LOCATION, &[&[LOC_ELIN][..], &[n; 10]].concat());
        let (p, c) = with_tlvs(&[caps(1), caps(2), power(1), power(2), elin(b'1'), elin(b'2')]);
        assert_eq!(c.discarded, 3);
        assert_eq!(p.org.med_caps.unwrap().device_type, 1);
        assert_eq!(p.org.med_power.unwrap().deci_watts, 1);
        assert_eq!(p.org.med_locations, [MedLocation::Elin(vec![b'1'; 10])]);
    }

    #[test]
    fn policy_cap_and_unique_app_type() {
        let policy = |app| tia(MED_POLICY, &[app, 0x40, 0xc9, 0x6e]);
        let mut tlvs: Vec<_> = (1..=9).map(policy).collect();
        tlvs.push(policy(1)); // repeat of a kept app type
        let (p, c) = with_tlvs(&tlvs);
        assert_eq!(p.org.med_policies.len(), MAX_MED_POLICIES);
        assert_eq!(c.discarded, 2);
        // VID 4095 and the reserved X bit are read, not rejected.
        let (p, c) = with_tlvs(&[tia(MED_POLICY, &[12, 0x3f, 0xfe, 0x00])]);
        assert_eq!(c.discarded, 0);
        assert_eq!(p.org.med_policies[0].vlan, 4095);
        assert!(!p.org.med_policies[0].tagged);
    }

    #[test]
    fn unknown_subtype_is_unrecognized() {
        let (_, c) = with_tlvs(&[tia(0, &[1]), tia(12, &[1])]);
        assert_eq!((c.unrecognized, c.discarded), (2, 0));
    }

    #[test]
    fn civic_text_is_cleaned() {
        let mut d = vec![0, 1, b'U', b'S', 3, 3, 0x1b, b'[', b'x'];
        d[0] = u8::try_from(d.len() - 1).unwrap();
        let m = to_proto(&OrgTlvs {
            med_locations: vec![MedLocation::Civic(d)],
            ..OrgTlvs::default()
        })
        .unwrap();
        assert!(m.locations[0].text.ends_with("ca3=\u{fffd}[x"));
    }

    #[test]
    fn every_truncation_of_a_full_lldpdu_is_safe() {
        let mut p = pdu(full());
        p.org.med_inventory = vec![MedInventory {
            field: 9,
            value: "x".into(),
        }];
        let wire = encode(&p);
        for n in 0..wire.len() {
            let _ = decode_counted(&wire[..n]);
        }
        let mut m = wire.clone();
        m.splice(m.len() - 2..m.len() - 2, tia(9, b"Acme"));
        decode(&m).unwrap();
    }

    #[test]
    fn oversize_guard_keeps_the_lldpdu_within_1500() {
        let mut org = full();
        org.vlan_names = (1..=100).map(|i| (i, "v".repeat(32))).collect();
        org.med_locations[1] = MedLocation::Civic({
            let mut d = vec![0, 1, b'U', b'S', 3, 200];
            d.extend_from_slice(&[b'a'; 200]);
            d[0] = u8::try_from(d.len() - 1).unwrap();
            d
        });
        let mut p = pdu(org);
        p.system_description = Some("d".repeat(255));
        let wire = encode(&p);
        assert!(wire.len() <= 1500, "{}", wire.len());
        let got = decode(&wire).unwrap();
        assert_eq!(got.org.med_policies.len(), 8);
        assert_eq!(got.org.med_locations.len(), 3);

        // A frame with no room left drops whole MED TLVs.
        let mut out = vec![0u8; 1490];
        encode_med(&mut out, &full(), 1500);
        assert!(out.len() <= 1498);
    }

    #[test]
    fn configured_location_encodes_and_round_trips() {
        use nos_proto::schema::{LldpCivicAddress, LldpCivicElement, LldpCoordinate, LldpLocation};
        assert_eq!(locations_from_config(&LldpLocation::default()), []);
        let l = LldpLocation {
            elin: Some("4155550100".into()),
            civic: LldpCivicAddress {
                what: 2,
                country: "US".into(),
                elements: vec![LldpCivicElement {
                    ca_type: 3,
                    value: "Paris".into(),
                }],
            },
            coordinate: LldpCoordinate {
                latitude: "34.0".into(),
                longitude: "-118.0".into(),
                altitude: Some("2.5".into()),
                altitude_resolution: 16,
                ..Default::default()
            },
        };
        let locs = locations_from_config(&l);
        assert_eq!(locs.len(), 3);
        let MedLocation::Coordinate(c) = &locs[0] else {
            panic!()
        };
        assert_eq!(
            (c.lat, c.lng, c.alt, c.alt_type),
            (34 << 25, -(118 << 25), 640, 1)
        );
        let p = pdu(OrgTlvs {
            med_locations: locs,
            ..OrgTlvs::default()
        });
        assert_eq!(decode(&encode(&p)).unwrap(), p);
    }
}
