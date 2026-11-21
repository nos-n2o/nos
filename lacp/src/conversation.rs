//! Pure CSCD model for LACPDU v2 (IEEE 802.1AX-2020 clause 6.6, #893/#894):
//! the `Admin_Conv_Link_Map` (a preference list of `Link_Numbers` per
//! conversation), Port Algorithm, MD5 digest, adaptive version choice. Port
//! Conversation Masks are local state only, never on the wire (the four mask
//! TLVs are deprecated, p.57); see `cscd.rs` for the vector computation.
//!
//! Only the digest's entry width is not fixed by the standard text (see
//! [`ConversationMap::digest`]); everything else here is clause-backed.

use md5::{Digest, Md5};

pub const CONVERSATIONS: usize = 4096;

/// IEEE 802 OUI/CID 00-80-C2 prefixes the algorithm id (8.1, Fig 8-1, p.148).
const OUI: [u8; 3] = [0x00, 0x80, 0xc2];

/// Port Algorithm (OUI + id). Others (I-SID, TE-SID, Flow Hash, ...) are kept
/// raw so a partner's value decodes and compares unequal to ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortAlgorithm {
    Unspecified,
    CVid,
    SVid,
    Other([u8; 4]),
}

impl PortAlgorithm {
    /// Ids 0 Unspecified, 1 C-VID, 2 S-VID (Table 8-1, p.149).
    pub fn to_wire(self) -> [u8; 4] {
        match self {
            Self::Unspecified => [OUI[0], OUI[1], OUI[2], 0],
            Self::CVid => [OUI[0], OUI[1], OUI[2], 1],
            Self::SVid => [OUI[0], OUI[1], OUI[2], 2],
            Self::Other(raw) => raw,
        }
    }

    pub fn from_wire(raw: [u8; 4]) -> Self {
        match raw {
            [0x00, 0x80, 0xc2, 0] => Self::Unspecified,
            [0x00, 0x80, 0xc2, 1] => Self::CVid,
            [0x00, 0x80, 0xc2, 2] => Self::SVid,
            other => Self::Other(other),
        }
    }
}

/// The administrative conversation map: for each conversation id (0..4095,
/// the VLAN id space for C-VID/S-VID) the preference-ordered `Link_Number`s;
/// the first one on an active link carries it. An empty list = no link
/// (digested as one 0, 7.3.1.1.34). Built from config only (never from link
/// state), so its digest moves only on an administrative change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationMap(Vec<Vec<u16>>);

impl Default for ConversationMap {
    fn default() -> Self {
        Self(vec![Vec::new(); CONVERSATIONS])
    }
}

impl ConversationMap {
    pub fn set_list(&mut self, conversation: u16, list: Vec<u16>) {
        if let Some(slot) = self.0.get_mut(conversation as usize) {
            *slot = list;
        }
    }

    pub fn list(&self, conversation: u16) -> &[u16] {
        self.0.get(conversation as usize).map_or(&[], Vec::as_slice)
    }

    /// MD5 over the 4096 elements, element i = list i then the conversation id
    /// i (6.6.3.1, p.92).
    /// ponytail: UNVERIFIED for third-party interop: the standard states no
    /// entry width; every field is 16-bit big-endian here (owner decision on
    /// #894). A third-party v2 peer may show `Mismatch reason=digest` until a
    /// capture settles it.
    pub fn digest(&self) -> [u8; 16] {
        // nosemgrep: rust.lang.security.insecure-hashes.insecure-hashes -- MD5 is the LACPDU wire digest (802.1AX), an integrity tag, not a security primitive
        let mut md5 = Md5::new();
        for (id, list) in self.0.iter().enumerate() {
            if list.is_empty() {
                md5.update(0u16.to_be_bytes());
            }
            for link in list {
                md5.update(link.to_be_bytes());
            }
            #[allow(clippy::cast_possible_truncation, reason = "id < 4096")]
            md5.update((id as u16).to_be_bytes());
        }
        md5.finalize().into()
    }
}

/// Adaptive downgrade (#865 3a, mandatory per #890: SR Linux drops v2 PDUs).
/// Preference 2 sends 2 until a v1 PDU is seen from the partner, 1 after, 2
/// again on a v2 PDU; preference 1 always sends 1.
pub fn send_version(actor_pref: u8, last_partner_version: Option<u8>) -> u8 {
    if actor_pref >= 2 && last_partner_version != Some(1) {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_version_truth_table() {
        for partner in [None, Some(1), Some(2)] {
            assert_eq!(send_version(1, partner), 1);
        }
        assert_eq!(send_version(2, None), 2);
        assert_eq!(send_version(2, Some(1)), 1);
        assert_eq!(send_version(2, Some(2)), 2); // re-upgrade
    }

    #[test]
    fn algorithm_round_trips_and_keeps_unknown() {
        for a in [
            PortAlgorithm::Unspecified,
            PortAlgorithm::CVid,
            PortAlgorithm::SVid,
            PortAlgorithm::Other([0x00, 0x80, 0xc2, 3]),
            PortAlgorithm::Other([1, 2, 3, 4]),
        ] {
            assert_eq!(PortAlgorithm::from_wire(a.to_wire()), a);
        }
        assert_ne!(
            PortAlgorithm::CVid,
            PortAlgorithm::from_wire([0, 0x80, 0xc2, 3])
        );
    }

    #[test]
    fn digest_matches_independent_md5() {
        // Expected values from `md5sum` over hand-built bytes (python
        // struct.pack('>H') elements), not from this encoder.
        let empty = ConversationMap::default();
        assert_eq!(hex(&empty.digest()), "9363c25f82227e8e4547d0f4ec632d80");
        let mut m = ConversationMap::default();
        m.set_list(0, vec![1, 2]);
        m.set_list(5, vec![2, 1]);
        assert_eq!(hex(&m.digest()), "cd29f6af2ccac5fba3abd789fed73f3c");
        assert_ne!(m.digest(), empty.digest());
        assert_eq!(m.list(0), &[1, 2]);
        assert_eq!(m.list(4096), &[] as &[u16]);
        m.set_list(5000, vec![1]); // out of range ignored
        assert_eq!(m.list(5000), &[] as &[u16]);
    }

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write as _;
        b.iter().fold(String::new(), |mut s, x| {
            write!(s, "{x:02x}").unwrap();
            s
        })
    }
}
