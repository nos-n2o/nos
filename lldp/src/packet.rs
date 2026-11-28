//! Hand-rolled LLDPDU encode/decode (IEEE 802.1AB §8): a run of TLVs, each a
//! 16-bit header (7-bit type, 9-bit length) plus a value, terminated by an End
//! TLV. Pure, no I/O — mirrors `nos-lacp`'s `packet.rs` style. Input is
//! untrusted wire data, so `decode` bounds-checks every length and never
//! panics.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nos_proto::schema::lldp::MAX_MANAGEMENT_ADDRESSES;
use thiserror::Error;

const TLV_END: u8 = 0;
const TLV_CHASSIS_ID: u8 = 1;
const TLV_PORT_ID: u8 = 2;
const TLV_TTL: u8 = 3;
const TLV_PORT_DESCRIPTION: u8 = 4;
const TLV_SYSTEM_NAME: u8 = 5;
const TLV_SYSTEM_DESCRIPTION: u8 = 6;
const TLV_SYSTEM_CAPABILITIES: u8 = 7;
const TLV_MANAGEMENT_ADDRESS: u8 = 8;
const TLV_ORG_SPECIFIC: u8 = 127;

/// IEEE 802.1 organizationally-specific TLVs (802.1Q Annex D, formerly
/// 802.1AB-2005 Annex F): OUI and the subtypes decoded/sent here.
const OUI_8021: [u8; 3] = [0x00, 0x80, 0xc2];
const DOT1_PORT_VLAN_ID: u8 = 1;
const DOT1_VLAN_NAME: u8 = 3;
const DOT1_LINK_AGGREGATION: u8 = 7;
/// IEEE 802.3 organizationally-specific TLVs (802.3 Clause 79).
const OUI_8023: [u8; 3] = [0x00, 0x12, 0x0f];
const DOT3_MAC_PHY: u8 = 1;
/// Deprecated in favor of the 802.1 one (same layout); decoded only.
const DOT3_LINK_AGGREGATION: u8 = 3;
const DOT3_MAX_FRAME_SIZE: u8 = 4;
/// Link Aggregation status bits (802.1Q D.2.7.1, 802.3 79.3.3.1).
const AGG_CAPABLE: u8 = 0x01;
const AGG_ENABLED: u8 = 0x02;
/// A VLAN Name TLV's name is at most 32 octets.
pub const MAX_VLAN_NAME: usize = 32;
/// At most this many VLAN Name TLVs are kept per received LLDPDU (each one
/// is stored and printed; the input is untrusted).
pub const MAX_VLAN_NAMES: usize = 32;
/// An LLDPDU fits one untagged Ethernet payload.
const MAX_LLDPDU: usize = 1500;

/// Chassis ID subtype 4: a MAC address.
pub const CHASSIS_SUBTYPE_MAC: u8 = 4;
/// Port ID subtype 5: an interface name.
pub const PORT_SUBTYPE_IF_NAME: u8 = 5;

/// System Capabilities bit for "Router" (802.1AB Table 8-4).
pub const CAP_ROUTER: u16 = 0x0010;
/// System Capabilities bit for "Bridge" (802.1AB Table 8-4).
pub const CAP_BRIDGE: u16 = 0x0004;

/// IANA address family numbers used in the Management Address TLV.
const AF_IPV4: u8 = 1;
const AF_IPV6: u8 = 2;
/// Interface numbering subtype 1: "unknown" — no interface known for it.
const IF_NUMBERING_UNKNOWN: u8 = 1;
/// Interface numbering subtype 2: the number is the interface's ifIndex.
const IF_NUMBERING_IFINDEX: u8 = 2;

/// Longest value any single TLV can carry (9-bit length field).
const MAX_TLV_VALUE: usize = 511;
/// Chassis/Port ID values are a 1-byte subtype plus up to 255 bytes.
const MAX_ID_VALUE: usize = 255;

/// A Chassis ID or Port ID: a subtype byte plus an opaque value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id {
    pub subtype: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub supported: u16,
    pub enabled: u16,
}

/// One Management Address TLV's address and interface number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementAddress {
    pub address: IpAddr,
    /// `Some(n)`: interface numbering subtype 2, ifIndex `n`. `None`: subtype
    /// 1 ("unknown", number 0) — also what a received subtype 3 (system port
    /// number) decodes to.
    pub if_index: Option<u32>,
}

impl std::fmt::Display for ManagementAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.if_index {
            Some(i) => write!(f, "{} (ifindex {i})", self.address),
            None => write!(f, "{}", self.address),
        }
    }
}

/// The 802.1/802.3 Link Aggregation TLV's content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkAggregation {
    pub capable: bool,
    /// Currently in an aggregation.
    pub enabled: bool,
    /// The aggregate's ifIndex while `enabled`, else 0.
    pub port_id: u32,
}

/// The 802.3 MAC/PHY Configuration/Status TLV's content (decode only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacPhy {
    pub autoneg_supported: bool,
    pub autoneg_enabled: bool,
    /// PMD auto-negotiation advertised capability bits.
    pub advertised: u16,
    /// Operational MAU type (IANA-MAU-MIB).
    pub mau_type: u16,
}

/// The organizationally-specific TLVs nos understands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrgTlvs {
    /// 802.1 Port VLAN ID (decode only).
    pub port_vlan_id: Option<u16>,
    /// 802.1 VLAN Name: (VLAN id, name), in wire order.
    pub vlan_names: Vec<(u16, String)>,
    pub link_aggregation: Option<LinkAggregation>,
    /// 802.3 Maximum Frame Size.
    pub max_frame_size: Option<u16>,
    /// 802.3 MAC/PHY Configuration/Status (decode only).
    pub mac_phy: Option<MacPhy>,
    /// LLDP-MED Capabilities (TIA-1057, `crate::med`).
    pub med_caps: Option<crate::med::MedCaps>,
    /// LLDP-MED Network Policy, one per application type, at most 8.
    pub med_policies: Vec<crate::med::MedPolicy>,
    /// LLDP-MED Location Identification, one per format.
    pub med_locations: Vec<crate::med::MedLocation>,
    /// LLDP-MED Extended Power via MDI.
    pub med_power: Option<crate::med::MedPower>,
    /// LLDP-MED inventory, decode only, one per field.
    pub med_inventory: Vec<crate::med::MedInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lldpdu {
    pub chassis_id: Id,
    pub port_id: Id,
    /// Seconds the receiver should keep this neighbor. `0` is a shutdown
    /// LLDPDU: the sender is going away, forget it now.
    pub ttl: u16,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub capabilities: Option<Capabilities>,
    /// IPv4/IPv6 addresses from Management Address TLVs, in wire order. At
    /// most `MAX_MANAGEMENT_ADDRESSES` are kept on receive (untrusted input,
    /// every one is stored and printed) — the same cap the config puts on
    /// how many we send.
    pub management_addresses: Vec<ManagementAddress>,
    pub org: OrgTlvs,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("truncated TLV")]
    Truncated,
    #[error("mandatory TLVs missing or out of order")]
    MissingMandatory,
    #[error("malformed {0} TLV")]
    Malformed(&'static str),
    #[error("duplicate mandatory TLV")]
    Duplicate,
}

impl Lldpdu {
    /// Chassis ID rendered for humans and logs: a MAC as `aa:bb:..`, a text
    /// subtype as its text, anything else as hex.
    pub fn chassis_display(&self) -> String {
        match (self.chassis_id.subtype, self.chassis_id.value.len()) {
            (CHASSIS_SUBTYPE_MAC, 6) => mac_str(&self.chassis_id.value),
            // interface alias / port component / interface name / locally assigned
            (1..=3 | 6 | 7, _) => text_or_hex(&self.chassis_id.value),
            _ => hex(&self.chassis_id.value),
        }
    }

    /// Port ID rendered like `chassis_display`.
    pub fn port_display(&self) -> String {
        match (self.port_id.subtype, self.port_id.value.len()) {
            (3, 6) => mac_str(&self.port_id.value),
            // interface alias / port component / interface name / circuit id / locally assigned
            (1 | 2 | 5..=7, _) => text_or_hex(&self.port_id.value),
            _ => hex(&self.port_id.value),
        }
    }

    /// Names of the capabilities the sender has *enabled*.
    pub fn enabled_capability_names(&self) -> Vec<String> {
        const NAMES: [(u16, &str); 11] = [
            (0x0001, "other"),
            (0x0002, "repeater"),
            (0x0004, "bridge"),
            (0x0008, "wlan-ap"),
            (0x0010, "router"),
            (0x0020, "telephone"),
            (0x0040, "docsis"),
            (0x0080, "station"),
            (0x0100, "c-vlan"),
            (0x0200, "s-vlan"),
            (0x0400, "tpmr"),
        ];
        let enabled = self.capabilities.map_or(0, |c| c.enabled);
        NAMES
            .iter()
            .filter(|(bit, _)| enabled & bit != 0)
            .map(|(_, name)| (*name).to_string())
            .collect()
    }
}

fn mac_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .concat()
}

fn text_or_hex(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) if s.chars().all(|c| !c.is_control()) => s.to_string(),
        _ => hex(bytes),
    }
}

fn push_tlv(out: &mut Vec<u8>, tlv_type: u8, value: &[u8]) {
    let value = &value[..value.len().min(MAX_TLV_VALUE)];
    let header = (u16::from(tlv_type) << 9) | u16::try_from(value.len()).expect("<= 511");
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(value);
}

fn push_id(out: &mut Vec<u8>, tlv_type: u8, id: &Id) {
    let mut value = vec![id.subtype];
    value.extend_from_slice(&id.value[..id.value.len().min(MAX_ID_VALUE)]);
    push_tlv(out, tlv_type, &value);
}

/// Encodes `pdu` as an LLDPDU (no Ethernet header), ending with the End TLV.
pub fn encode(pdu: &Lldpdu) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    push_id(&mut out, TLV_CHASSIS_ID, &pdu.chassis_id);
    push_id(&mut out, TLV_PORT_ID, &pdu.port_id);
    push_tlv(&mut out, TLV_TTL, &pdu.ttl.to_be_bytes());
    if let Some(s) = &pdu.port_description {
        push_tlv(&mut out, TLV_PORT_DESCRIPTION, s.as_bytes());
    }
    if let Some(s) = &pdu.system_name {
        push_tlv(&mut out, TLV_SYSTEM_NAME, s.as_bytes());
    }
    if let Some(s) = &pdu.system_description {
        push_tlv(&mut out, TLV_SYSTEM_DESCRIPTION, s.as_bytes());
    }
    if let Some(c) = pdu.capabilities {
        let mut value = c.supported.to_be_bytes().to_vec();
        value.extend_from_slice(&c.enabled.to_be_bytes());
        push_tlv(&mut out, TLV_SYSTEM_CAPABILITIES, &value);
    }
    for addr in &pdu.management_addresses {
        push_tlv(
            &mut out,
            TLV_MANAGEMENT_ADDRESS,
            &encode_management_address(addr),
        );
    }
    encode_org(&mut out, &pdu.org);
    push_tlv(&mut out, TLV_END, &[]);
    out
}

pub(crate) fn push_org(out: &mut Vec<u8>, oui: [u8; 3], subtype: u8, info: &[u8]) {
    let mut value = oui.to_vec();
    value.push(subtype);
    value.extend_from_slice(info);
    push_tlv(out, TLV_ORG_SPECIFIC, &value);
}

/// The org TLVs (MED before VLAN names), VLAN names last: they are the only ones that can be many,
/// so they are what gets cut when the LLDPDU would outgrow `MAX_LLDPDU` (an
/// 802.1Q trunk can carry 4094 VLANs, 41 bytes each).
fn encode_org(out: &mut Vec<u8>, org: &OrgTlvs) {
    if let Some(pvid) = org.port_vlan_id {
        push_org(out, OUI_8021, DOT1_PORT_VLAN_ID, &pvid.to_be_bytes());
    }
    if let Some(agg) = org.link_aggregation {
        let mut info = vec![
            if agg.capable { AGG_CAPABLE } else { 0 } | if agg.enabled { AGG_ENABLED } else { 0 },
        ];
        info.extend_from_slice(&agg.port_id.to_be_bytes());
        push_org(out, OUI_8021, DOT1_LINK_AGGREGATION, &info);
    }
    if let Some(m) = org.mac_phy {
        let mut info = vec![u8::from(m.autoneg_supported) | (u8::from(m.autoneg_enabled) << 1)];
        info.extend_from_slice(&m.advertised.to_be_bytes());
        info.extend_from_slice(&m.mau_type.to_be_bytes());
        push_org(out, OUI_8023, DOT3_MAC_PHY, &info);
    }
    if let Some(size) = org.max_frame_size {
        push_org(out, OUI_8023, DOT3_MAX_FRAME_SIZE, &size.to_be_bytes());
    }
    crate::med::encode_med(out, org, MAX_LLDPDU);
    for (i, (vid, name)) in org.vlan_names.iter().enumerate() {
        let name = truncate_at_char(name, MAX_VLAN_NAME);
        // Header (2) + OUI/subtype (4) + VID (2) + length (1) + name, with
        // the End TLV (2) still to come.
        if out.len() + 9 + name.len() + 2 > MAX_LLDPDU {
            // ponytail: logged per transmit (debug only); once per link if it's ever noisy.
            tracing::debug!(
                sent = i,
                dropped = org.vlan_names.len() - i,
                "lldpdu full, not advertising every vlan name"
            );
            break;
        }
        let mut info = vid.to_be_bytes().to_vec();
        info.push(u8::try_from(name.len()).expect("<= 32"));
        info.extend_from_slice(name.as_bytes());
        push_org(out, OUI_8021, DOT1_VLAN_NAME, &info);
    }
}

/// The longest prefix of `s` of at most `max` bytes ending on a char boundary.
pub fn truncate_at_char(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// What `decode_org` did with one org-specific TLV.
enum OrgOutcome {
    Kept,
    /// Malformed, a repeat of a single-instance TLV, or past the cap.
    Discarded,
    /// An OUI/subtype nos doesn't decode.
    Unrecognized,
}

/// Decodes one org-specific TLV value into `org`. Optional and untrusted: a
/// malformed one is dropped, never fatal; a repeat of a single-instance TLV
/// keeps the first.
fn decode_org(value: &[u8], org: &mut OrgTlvs) -> OrgOutcome {
    fn once<T>(slot: &mut Option<T>, v: Option<T>) -> OrgOutcome {
        match v {
            Some(v) if slot.is_none() => {
                *slot = Some(v);
                OrgOutcome::Kept
            }
            _ => OrgOutcome::Discarded,
        }
    }
    let Some((head, info)) = value.split_at_checked(4) else {
        return OrgOutcome::Discarded;
    };
    // Only called after a length check.
    let u16_at = |i: usize| u16::from_be_bytes([info[i], info[i + 1]]);
    match ([head[0], head[1], head[2]], head[3]) {
        (OUI_8021, DOT1_PORT_VLAN_ID) => {
            once(&mut org.port_vlan_id, (info.len() == 2).then(|| u16_at(0)))
        }
        (OUI_8021, DOT1_VLAN_NAME) => {
            let well_formed = info.len() >= 3
                && usize::from(info[2]) <= MAX_VLAN_NAME
                && info.len() == 3 + usize::from(info[2]);
            if !well_formed || org.vlan_names.len() >= MAX_VLAN_NAMES {
                return OrgOutcome::Discarded;
            }
            org.vlan_names.push((u16_at(0), lossy(&info[3..])));
            OrgOutcome::Kept
        }
        (OUI_8021, DOT1_LINK_AGGREGATION) | (OUI_8023, DOT3_LINK_AGGREGATION) => once(
            &mut org.link_aggregation,
            (info.len() == 5).then(|| LinkAggregation {
                capable: info[0] & AGG_CAPABLE != 0,
                enabled: info[0] & AGG_ENABLED != 0,
                port_id: u32::from_be_bytes([info[1], info[2], info[3], info[4]]),
            }),
        ),
        (OUI_8023, DOT3_MAC_PHY) => once(
            &mut org.mac_phy,
            (info.len() == 5).then(|| MacPhy {
                autoneg_supported: info[0] & 0x01 != 0,
                autoneg_enabled: info[0] & 0x02 != 0,
                advertised: u16_at(1),
                mau_type: u16_at(3),
            }),
        ),
        (OUI_8023, DOT3_MAX_FRAME_SIZE) => once(
            &mut org.max_frame_size,
            (info.len() == 2).then(|| u16_at(0)),
        ),
        (crate::med::OUI_TIA, subtype) => match crate::med::decode_med(subtype, info, org) {
            Some(true) => OrgOutcome::Kept,
            Some(false) => OrgOutcome::Discarded,
            None => OrgOutcome::Unrecognized,
        },
        _ => OrgOutcome::Unrecognized,
    }
}

/// Optional TLVs `decode_counted` dropped, for 802.1AB §9.2.6's
/// `statsTLVsDiscardedTotal`/`statsTLVsUnrecognizedTotal`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TlvCounts {
    /// A malformed/non-IP Management Address, or one past the cap; a known
    /// org-specific TLV that is malformed, repeated, or past the cap.
    pub discarded: u64,
    /// A reserved TLV type (9–126), or an organizationally-specific one (127)
    /// whose OUI/subtype nos doesn't decode (an unknown LLDP-MED subtype too).
    pub unrecognized: u64,
}

/// Decodes an LLDPDU. The first three TLVs must be Chassis ID, Port ID and TTL
/// in that order; unknown optional TLVs are skipped; anything after the End TLV
/// (Ethernet padding) is ignored.
pub fn decode(data: &[u8]) -> Result<Lldpdu, DecodeError> {
    decode_counted(data).map(|(pdu, _)| pdu)
}

/// `decode`, also counting the optional TLVs it skipped.
pub fn decode_counted(mut data: &[u8]) -> Result<(Lldpdu, TlvCounts), DecodeError> {
    let mut counts = TlvCounts::default();
    let mut chassis_id = None;
    let mut port_id = None;
    let mut ttl = None;
    let mut pdu = Lldpdu {
        chassis_id: Id {
            subtype: 0,
            value: Vec::new(),
        },
        port_id: Id {
            subtype: 0,
            value: Vec::new(),
        },
        ttl: 0,
        port_description: None,
        system_name: None,
        system_description: None,
        capabilities: None,
        management_addresses: Vec::new(),
        org: OrgTlvs::default(),
    };

    while !data.is_empty() {
        if data.len() < 2 {
            return Err(DecodeError::Truncated);
        }
        let header = u16::from_be_bytes([data[0], data[1]]);
        let tlv_type = u8::try_from(header >> 9).expect("7 bits");
        let len = usize::from(header & 0x01ff);
        let value = data.get(2..2 + len).ok_or(DecodeError::Truncated)?;
        data = &data[2 + len..];

        // The three mandatory TLVs come first, in order, and only once.
        match (
            tlv_type,
            chassis_id.is_some(),
            port_id.is_some(),
            ttl.is_some(),
        ) {
            (TLV_CHASSIS_ID, false, false, false) => {
                chassis_id = Some(decode_id(value, "chassis id")?);
                continue;
            }
            (TLV_PORT_ID, true, false, false) => {
                port_id = Some(decode_id(value, "port id")?);
                continue;
            }
            (TLV_TTL, true, true, false) => {
                let bytes: [u8; 2] = value
                    .try_into()
                    .map_err(|_| DecodeError::Malformed("ttl"))?;
                ttl = Some(u16::from_be_bytes(bytes));
                continue;
            }
            (TLV_CHASSIS_ID | TLV_PORT_ID | TLV_TTL, ..) if ttl.is_some() => {
                return Err(DecodeError::Duplicate)
            }
            (TLV_END, ..) => break,
            (_, true, true, true) => {}
            _ => return Err(DecodeError::MissingMandatory),
        }

        match tlv_type {
            TLV_PORT_DESCRIPTION => pdu.port_description = Some(lossy(value)),
            TLV_SYSTEM_NAME => pdu.system_name = Some(lossy(value)),
            TLV_SYSTEM_DESCRIPTION => pdu.system_description = Some(lossy(value)),
            TLV_SYSTEM_CAPABILITIES => {
                // Matches lldpd (lldp.c, LLDP_TLV_SYSTEM_CAP): shorter than 4
                // bytes rejects the LLDPDU, extra bytes are ignored, and a
                // repeat silently overwrites (last wins).
                let [a, b, c, d, ..] = *value else {
                    return Err(DecodeError::Malformed("system capabilities"));
                };
                pdu.capabilities = Some(Capabilities {
                    supported: u16::from_be_bytes([a, b]),
                    enabled: u16::from_be_bytes([c, d]),
                });
            }
            // Optional and untrusted: a malformed or non-IP one is skipped
            // rather than rejecting the whole LLDPDU (and its neighbor).
            TLV_MANAGEMENT_ADDRESS => match decode_management_address(value) {
                Some(addr) if pdu.management_addresses.len() < MAX_MANAGEMENT_ADDRESSES => {
                    pdu.management_addresses.push(addr);
                }
                _ => counts.discarded += 1,
            },
            TLV_ORG_SPECIFIC => match decode_org(value, &mut pdu.org) {
                OrgOutcome::Kept => {}
                OrgOutcome::Discarded => counts.discarded += 1,
                OrgOutcome::Unrecognized => counts.unrecognized += 1,
            },
            _ => counts.unrecognized += 1, // reserved: skip
        }
    }

    pdu.chassis_id = chassis_id.ok_or(DecodeError::MissingMandatory)?;
    pdu.port_id = port_id.ok_or(DecodeError::MissingMandatory)?;
    pdu.ttl = ttl.ok_or(DecodeError::MissingMandatory)?;
    Ok((pdu, counts))
}

/// Management Address TLV value (802.1AB §8.5.9): address string length (the
/// family byte plus the address), family, address, interface numbering
/// subtype, 4-byte interface number, OID length, OID. The OID is left empty:
/// it points at a MIB object, and nos runs no SNMP agent.
fn encode_management_address(m: &ManagementAddress) -> Vec<u8> {
    let (family, octets) = match m.address {
        IpAddr::V4(a) => (AF_IPV4, a.octets().to_vec()),
        IpAddr::V6(a) => (AF_IPV6, a.octets().to_vec()),
    };
    let mut value = vec![u8::try_from(1 + octets.len()).expect("<= 17"), family];
    value.extend_from_slice(&octets);
    let (subtype, number) = m
        .if_index
        .map_or((IF_NUMBERING_UNKNOWN, 0), |i| (IF_NUMBERING_IFINDEX, i));
    value.push(subtype);
    value.extend_from_slice(&number.to_be_bytes());
    value.push(0); // no OID
    value
}

/// The IPv4/IPv6 address in a Management Address TLV value, or `None` if it's
/// truncated, internally inconsistent, or another address family.
fn decode_management_address(value: &[u8]) -> Option<ManagementAddress> {
    let addr_len = usize::from(*value.first()?);
    // The trailing interface subtype (1) + number (4) + OID length (1).
    let oid_len = usize::from(*value.get(1 + addr_len + 5)?);
    if addr_len < 2 || value.len() < 1 + addr_len + 6 + oid_len {
        return None;
    }
    let family = value[1];
    let octets = &value[2..=addr_len];
    // In bounds: the length check above covers subtype + number.
    let trailer = &value[1 + addr_len..];
    let if_index = (trailer[0] == IF_NUMBERING_IFINDEX)
        .then(|| u32::from_be_bytes([trailer[1], trailer[2], trailer[3], trailer[4]]));
    let address = match (family, octets.len()) {
        (AF_IPV4, 4) => Some(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(octets).ok()?,
        ))),
        (AF_IPV6, 16) => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(octets).ok()?,
        ))),
        _ => None,
    }?;
    Some(ManagementAddress { address, if_index })
}

fn decode_id(value: &[u8], what: &'static str) -> Result<Id, DecodeError> {
    match value.split_first() {
        Some((&subtype, rest)) if !rest.is_empty() && rest.len() <= MAX_ID_VALUE => Ok(Id {
            subtype,
            value: rest.to_vec(),
        }),
        _ => Err(DecodeError::Malformed(what)),
    }
}

/// Text from the wire, made safe to print. These strings end up in `nos-cli`
/// output and in logs, and a neighbor is untrusted: control characters (an
/// ANSI escape sequence, a carriage return that overwrites a line) are
/// replaced rather than passed through.
pub(crate) fn lossy(value: &[u8]) -> String {
    String::from_utf8_lossy(value)
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Lldpdu {
        Lldpdu {
            chassis_id: Id {
                subtype: CHASSIS_SUBTYPE_MAC,
                value: vec![2, 0, 0, 0, 0, 1],
            },
            port_id: Id {
                subtype: PORT_SUBTYPE_IF_NAME,
                value: b"eth1".to_vec(),
            },
            ttl: 120,
            port_description: Some("eth1".to_string()),
            system_name: Some("router-a".to_string()),
            system_description: Some("nos 0.1.0".to_string()),
            capabilities: Some(Capabilities {
                supported: CAP_ROUTER,
                enabled: CAP_ROUTER,
            }),
            management_addresses: Vec::new(),
            org: OrgTlvs::default(),
        }
    }

    #[test]
    fn round_trips() {
        let pdu = sample();
        assert_eq!(decode(&encode(&pdu)).unwrap(), pdu);
    }

    #[test]
    fn mandatory_only_round_trips_and_shutdown_ttl_is_zero() {
        let mut pdu = sample();
        pdu.ttl = 0;
        pdu.port_description = None;
        pdu.system_name = None;
        pdu.system_description = None;
        pdu.capabilities = None;
        assert_eq!(decode(&encode(&pdu)).unwrap().ttl, 0);
    }

    #[test]
    fn display_and_capabilities() {
        let pdu = sample();
        assert_eq!(pdu.chassis_display(), "02:00:00:00:00:01");
        assert_eq!(pdu.port_display(), "eth1");
        assert_eq!(pdu.enabled_capability_names(), vec!["router".to_string()]);
    }

    fn mgmt(addr: &str) -> ManagementAddress {
        ManagementAddress {
            address: addr.parse().unwrap(),
            if_index: None,
        }
    }

    #[test]
    fn management_addresses_round_trip_in_order() {
        let mut pdu = sample();
        pdu.management_addresses = vec![
            ManagementAddress {
                if_index: Some(7),
                ..mgmt("10.0.0.1")
            },
            mgmt("2001:db8::1"),
        ];
        assert_eq!(decode(&encode(&pdu)).unwrap(), pdu);
        // Subtype 2 + ifIndex 7, then subtype 1 + number 0, each OID length 0.
        let v4 = encode_management_address(&pdu.management_addresses[0]);
        assert_eq!(&v4[6..], &[2, 0, 0, 0, 7, 0]);
        let v6 = encode_management_address(&pdu.management_addresses[1]);
        assert_eq!(&v6[18..], &[1, 0, 0, 0, 0, 0]);
        assert_eq!(
            pdu.management_addresses[0].to_string(),
            "10.0.0.1 (ifindex 7)"
        );
        assert_eq!(pdu.management_addresses[1].to_string(), "2001:db8::1");
    }

    #[test]
    fn system_port_number_subtype_decodes_without_an_ifindex() {
        let value = [5, AF_IPV4, 10, 0, 0, 1, 3, 0, 0, 0, 9, 0];
        assert_eq!(
            decode(&with_mgmt_tlv(&value)).unwrap().management_addresses,
            [mgmt("10.0.0.1")]
        );
    }

    /// `sample()` with one hand-built Management Address TLV before the End TLV.
    fn with_mgmt_tlv(value: &[u8]) -> Vec<u8> {
        let mut bytes = encode(&sample());
        bytes.truncate(bytes.len() - 2);
        push_tlv(&mut bytes, TLV_MANAGEMENT_ADDRESS, value);
        push_tlv(&mut bytes, TLV_END, &[]);
        bytes
    }

    #[test]
    fn malformed_management_addresses_are_skipped_not_fatal() {
        let good = encode_management_address(&mgmt("10.0.0.1"));
        for bad in [
            vec![],                                          // empty
            vec![5, AF_IPV4, 10, 0, 0, 1],                   // no interface/OID trailer
            vec![5, AF_IPV4, 10, 0, 0, 1, 1, 0, 0, 0, 0, 9], // OID length overruns
            vec![4, AF_IPV4, 10, 0, 0, 1, 0, 0, 0, 0, 0], // addr length shorter than family needs
            vec![5, 6, 10, 0, 0, 1, 1, 0, 0, 0, 0, 0],    // family 6 (802): not an IP
            vec![1, AF_IPV4, 1, 0, 0, 0, 0, 0],           // no address bytes
            vec![255, AF_IPV4],                           // length points past the value
        ] {
            let pdu = decode(&with_mgmt_tlv(&bad)).unwrap();
            assert!(pdu.management_addresses.is_empty(), "{bad:?}");
        }
        assert_eq!(
            decode(&with_mgmt_tlv(&good))
                .unwrap()
                .management_addresses
                .len(),
            1
        );
    }

    #[test]
    fn management_address_with_an_oid_is_accepted() {
        let mut value = encode_management_address(&mgmt("10.0.0.1"));
        *value.last_mut().unwrap() = 3;
        value.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            decode(&with_mgmt_tlv(&value)).unwrap().management_addresses,
            vec![mgmt("10.0.0.1")]
        );
    }

    #[test]
    fn stored_management_addresses_are_capped() {
        let mut pdu = sample();
        pdu.management_addresses = (1..=10)
            .map(|i| ManagementAddress {
                address: IpAddr::from([10, 0, 0, i]),
                if_index: None,
            })
            .collect();
        assert_eq!(
            decode(&encode(&pdu)).unwrap().management_addresses.len(),
            MAX_MANAGEMENT_ADDRESSES
        );
    }

    #[test]
    fn trailing_padding_after_end_tlv_is_ignored() {
        let mut bytes = encode(&sample());
        bytes.extend_from_slice(&[0; 20]);
        assert_eq!(decode(&bytes).unwrap(), sample());
    }

    #[test]
    fn unknown_optional_tlv_is_skipped() {
        let mut bytes = encode(&sample());
        // Splice an organizationally-specific TLV (type 127) in before the End TLV.
        bytes.truncate(bytes.len() - 2);
        push_tlv(&mut bytes, 127, &[0x00, 0x80, 0xc2, 0x01, 0xff]);
        push_tlv(&mut bytes, TLV_END, &[]);
        assert_eq!(decode(&bytes).unwrap(), sample());
    }

    #[test]
    fn skipped_tlvs_are_counted() {
        let mut bytes = encode(&sample());
        bytes.truncate(bytes.len() - 2);
        push_tlv(&mut bytes, 42, &[1, 2]); // reserved type
        push_tlv(&mut bytes, 127, &[0x00, 0x80, 0xc2, 0x63]); // unknown 802.1 subtype
        push_tlv(&mut bytes, 127, &[0x00, 0x12, 0x0f, 0x04, 1]); // short max frame size
        push_tlv(&mut bytes, TLV_MANAGEMENT_ADDRESS, &[5, AF_IPV4, 10]); // truncated
        for i in 1..=5 {
            let addr = ManagementAddress {
                address: IpAddr::from([10, 0, 0, i]),
                if_index: None,
            };
            push_tlv(
                &mut bytes,
                TLV_MANAGEMENT_ADDRESS,
                &encode_management_address(&addr),
            );
        }
        push_tlv(&mut bytes, TLV_END, &[]);
        let (pdu, counts) = decode_counted(&bytes).unwrap();
        assert_eq!(pdu.management_addresses.len(), MAX_MANAGEMENT_ADDRESSES);
        // The short org TLV, the truncated address, and the fifth valid one
        // past the cap.
        assert_eq!(
            counts,
            TlvCounts {
                discarded: 3,
                unrecognized: 2
            }
        );
        assert_eq!(
            decode_counted(&encode(&sample())).unwrap().1,
            TlvCounts::default()
        );
    }

    fn full_org() -> OrgTlvs {
        OrgTlvs {
            port_vlan_id: Some(10),
            vlan_names: vec![(100, "bd-x".to_string()), (200, "bd-y".to_string())],
            link_aggregation: Some(LinkAggregation {
                capable: true,
                enabled: true,
                port_id: 9,
            }),
            max_frame_size: Some(1518),
            mac_phy: Some(MacPhy {
                autoneg_supported: true,
                autoneg_enabled: false,
                advertised: 0x6c01,
                mau_type: 30,
            }),
            ..OrgTlvs::default()
        }
    }

    #[test]
    fn org_tlvs_round_trip_and_match_the_wire_layout() {
        let mut pdu = sample();
        pdu.org = full_org();
        let bytes = encode(&pdu);
        let (decoded, counts) = decode_counted(&bytes).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(counts, TlvCounts::default());
        // Link Aggregation: 802.1 OUI, subtype 7, status 0b11, ifIndex 9.
        let mut agg = Vec::new();
        push_org(&mut agg, OUI_8021, DOT1_LINK_AGGREGATION, &[3, 0, 0, 0, 9]);
        assert!(bytes.windows(agg.len()).any(|w| w == agg));
        // Max Frame Size: 802.3 OUI, subtype 4, 1518.
        let mut mfs = Vec::new();
        push_org(
            &mut mfs,
            OUI_8023,
            DOT3_MAX_FRAME_SIZE,
            &1518u16.to_be_bytes(),
        );
        assert_eq!(mfs, [0xfe, 6, 0x00, 0x12, 0x0f, 4, 0x05, 0xee]);
        assert!(bytes.windows(mfs.len()).any(|w| w == mfs));
        // VLAN Name: VID, name length, name.
        let mut vn = Vec::new();
        push_org(&mut vn, OUI_8021, DOT1_VLAN_NAME, b"\x00\x64\x04bd-x");
        assert!(bytes.windows(vn.len()).any(|w| w == vn));
    }

    /// `sample()` with hand-built org TLVs before the End TLV.
    fn with_org(tlvs: &[&[u8]]) -> Vec<u8> {
        let mut bytes = encode(&sample());
        bytes.truncate(bytes.len() - 2);
        for v in tlvs {
            push_tlv(&mut bytes, TLV_ORG_SPECIFIC, v);
        }
        push_tlv(&mut bytes, TLV_END, &[]);
        bytes
    }

    #[test]
    fn bad_org_tlvs_are_skipped_not_fatal() {
        let (pdu, counts) = decode_counted(&with_org(&[
            &[0x00, 0x80, 0xc2],                              // shorter than OUI + subtype
            &[0xaa, 0xbb, 0xcc, 0x01, 0, 1],                  // unknown OUI
            &[0x00, 0x80, 0xc2, 0x03, 0, 100, 5, b'x'],       // name length overruns
            &[0x00, 0x12, 0x0f, 0x04, 0x05, 0xee],            // max frame size 1518
            &[0x00, 0x12, 0x0f, 0x04, 0x23, 0x46],            // a repeat: the first wins
            &[0x00, 0x80, 0xc2, 0x03, 0, 100, 2, 0x1b, b'['], // control character
            &[0x00, 0x12, 0x0f, 0x03, 0x01, 0, 0, 0, 0],      // deprecated 802.3 link aggregation
        ]))
        .unwrap();
        assert_eq!(
            pdu.org,
            OrgTlvs {
                vlan_names: vec![(100, "\u{fffd}[".to_string())],
                link_aggregation: Some(LinkAggregation {
                    capable: true,
                    enabled: false,
                    port_id: 0
                }),
                max_frame_size: Some(1518),
                ..OrgTlvs::default()
            }
        );
        assert_eq!(
            counts,
            TlvCounts {
                discarded: 3,
                unrecognized: 1
            }
        );
    }

    #[test]
    fn received_vlan_names_are_capped() {
        let tlvs: Vec<Vec<u8>> = (0..40u8)
            .map(|i| vec![0x00, 0x80, 0xc2, 0x03, 0, i, 1, b'a'])
            .collect();
        let refs: Vec<&[u8]> = tlvs.iter().map(Vec::as_slice).collect();
        let (pdu, counts) = decode_counted(&with_org(&refs)).unwrap();
        assert_eq!(pdu.org.vlan_names.len(), MAX_VLAN_NAMES);
        assert_eq!(counts.discarded, 8);
    }

    #[test]
    fn a_huge_trunk_still_fits_one_lldpdu() {
        let mut pdu = sample();
        pdu.org.vlan_names = (1..=4094)
            .map(|vid| (vid, format!("broadcast-domain-{vid:0>20}")))
            .collect();
        let bytes = encode(&pdu);
        assert!(bytes.len() <= MAX_LLDPDU, "{}", bytes.len());
        assert_eq!(decode(&bytes).unwrap().org.vlan_names[0].0, 1);
        // Names past 32 bytes are cut on a char boundary.
        assert_eq!(truncate_at_char("ééé", 3), "é");
        assert_eq!(truncate_at_char("abc", 32), "abc");
    }

    #[test]
    fn system_capabilities_follows_lldpd() {
        let mut pdu = sample();
        pdu.capabilities = None;
        let with = |tlvs: &[&[u8]]| {
            let mut bytes = encode(&pdu);
            bytes.truncate(bytes.len() - 2);
            for t in tlvs {
                push_tlv(&mut bytes, TLV_SYSTEM_CAPABILITIES, t);
            }
            push_tlv(&mut bytes, TLV_END, &[]);
            decode_counted(&bytes)
        };
        // Shorter than 4 bytes: the LLDPDU is rejected.
        for bad in [&[][..], &[0; 3]] {
            assert!(matches!(with(&[bad]), Err(DecodeError::Malformed(_))));
        }
        // Longer: the first 4 bytes are used, the rest ignored.
        let (got, counts) = with(&[&[0, 1, 0, 2, 9, 9]]).unwrap();
        assert_eq!(
            got.capabilities,
            Some(Capabilities {
                supported: 1,
                enabled: 2
            })
        );
        assert_eq!(counts.discarded, 0);
        // Repeat: last wins.
        let (got, _) = with(&[&[0, 1, 0, 1], &[0, 3, 0, 4]]).unwrap();
        assert_eq!(
            got.capabilities,
            Some(Capabilities {
                supported: 3,
                enabled: 4
            })
        );
    }

    #[test]
    fn rejects_truncated_tlv() {
        let bytes = encode(&sample());
        assert_eq!(decode(&bytes[..10]), Err(DecodeError::Truncated));
        assert_eq!(decode(&bytes[..1]), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_missing_or_misordered_mandatory_tlvs() {
        // Port ID first.
        let mut bytes = Vec::new();
        push_id(&mut bytes, TLV_PORT_ID, &sample().port_id);
        push_id(&mut bytes, TLV_CHASSIS_ID, &sample().chassis_id);
        push_tlv(&mut bytes, TLV_TTL, &120u16.to_be_bytes());
        assert_eq!(decode(&bytes), Err(DecodeError::MissingMandatory));

        // No TTL.
        let mut bytes = Vec::new();
        push_id(&mut bytes, TLV_CHASSIS_ID, &sample().chassis_id);
        push_id(&mut bytes, TLV_PORT_ID, &sample().port_id);
        push_tlv(&mut bytes, TLV_END, &[]);
        assert_eq!(decode(&bytes), Err(DecodeError::MissingMandatory));

        assert_eq!(decode(&[]), Err(DecodeError::MissingMandatory));
    }

    #[test]
    fn rejects_duplicate_mandatory_tlv_and_bad_lengths() {
        let mut bytes = encode(&sample());
        bytes.truncate(bytes.len() - 2);
        push_id(&mut bytes, TLV_CHASSIS_ID, &sample().chassis_id);
        assert_eq!(decode(&bytes), Err(DecodeError::Duplicate));

        let mut bytes = Vec::new();
        push_id(&mut bytes, TLV_CHASSIS_ID, &sample().chassis_id);
        push_id(&mut bytes, TLV_PORT_ID, &sample().port_id);
        push_tlv(&mut bytes, TLV_TTL, &[1]); // 1 byte, not 2
        assert_eq!(decode(&bytes), Err(DecodeError::Malformed("ttl")));

        let mut bytes = Vec::new();
        push_tlv(&mut bytes, TLV_CHASSIS_ID, &[CHASSIS_SUBTYPE_MAC]); // subtype, no value
        assert_eq!(decode(&bytes), Err(DecodeError::Malformed("chassis id")));
    }

    #[test]
    fn control_characters_in_neighbor_text_are_neutralized() {
        let mut pdu = sample();
        pdu.system_name = Some("evil\x1b[2Jname\r".to_string());
        pdu.port_description = Some("a\nb".to_string());
        let decoded = decode(&encode(&pdu)).unwrap();
        assert_eq!(
            decoded.system_name.as_deref(),
            Some("evil\u{fffd}[2Jname\u{fffd}")
        );
        assert_eq!(decoded.port_description.as_deref(), Some("a\u{fffd}b"));
    }

    #[test]
    fn non_text_ids_fall_back_to_hex() {
        let mut pdu = sample();
        pdu.port_id = Id {
            subtype: PORT_SUBTYPE_IF_NAME,
            value: vec![0xff, 0x00, 0x01],
        };
        pdu.chassis_id = Id {
            subtype: 5,
            value: vec![1, 10, 0, 0, 1],
        };
        assert_eq!(pdu.port_display(), "ff0001");
        assert_eq!(pdu.chassis_display(), "010a000001");
    }
}
