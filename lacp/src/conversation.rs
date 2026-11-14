//! Pure CSCD model for LACPDU v2 (802.1AX-2014): conversation-id -> link map,
//! Port Algorithm, MD5 digest, mask slicing, adaptive version choice (#893).
//!
//! UNVERIFIED (#890, owner decision on #893): no v2 source (standard text or
//! v2 peer capture) exists. Every wire-facing choice below is tagged
//! `ponytail: UNVERIFIED` and is recollection, not evidence. #894/#895 stay
//! parked until a source confirms or corrects them.

use md5::{Digest, Md5};

pub const CONVERSATIONS: usize = 4096;
/// One of the four Port Conversation Mask TLVs: 1024 bits.
pub const MASK_BYTES: usize = 128;

/// ponytail: UNVERIFIED: IEEE 802 OUI 00-80-C2 prefixes the algorithm id.
const OUI: [u8; 3] = [0x00, 0x80, 0xc2];

/// Port Algorithm (OUI + id). Others (I-SID, TE-SID, ECMP, ...) are kept raw
/// so a partner's value decodes and compares unequal to ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortAlgorithm {
    Unspecified,
    CVid,
    SVid,
    Other([u8; 4]),
}

impl PortAlgorithm {
    /// ponytail: UNVERIFIED: ids 0 unspecified, 1 C-VID, 2 S-VID.
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

/// Conversation id (0..4095, the VLAN id space for C-VID/S-VID) -> link
/// number; 0 = not assigned to any link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationMap(Box<[u16; CONVERSATIONS]>);

impl Default for ConversationMap {
    fn default() -> Self {
        Self(Box::new([0; CONVERSATIONS]))
    }
}

impl ConversationMap {
    pub fn set(&mut self, conversation: u16, link: u16) {
        if let Some(slot) = self.0.get_mut(conversation as usize) {
            *slot = link;
        }
    }

    pub fn link_of(&self, conversation: u16) -> Option<u16> {
        self.0.get(conversation as usize).copied()
    }

    /// MD5 over the 4096 link numbers, conversation 0 first.
    /// ponytail: UNVERIFIED: entry width (2 bytes) and byte order (big
    /// endian) of the digest input are assumed; the likeliest interop bug.
    pub fn digest(&self) -> [u8; 16] {
        let mut md5 = Md5::new();
        for link in &self.0 {
            md5.update(link.to_be_bytes());
        }
        md5.finalize().into()
    }

    /// 4096-bit membership mask of one link, as the four 1024-bit masks.
    /// ponytail: UNVERIFIED: conversation 0 is the MSB of byte 0 of mask 1.
    pub fn masks_for_link(&self, link: u16) -> [[u8; MASK_BYTES]; 4] {
        let mut flat = [0u8; 4 * MASK_BYTES];
        for (c, l) in self.0.iter().enumerate() {
            if *l == link {
                flat[c / 8] |= 0x80 >> (c % 8);
            }
        }
        slice_mask(&flat)
    }

    /// Inverse of [`Self::masks_for_link`]: assign `link` to every set bit.
    pub fn apply_masks(&mut self, link: u16, masks: &[[u8; MASK_BYTES]; 4]) {
        let flat = merge_mask(masks);
        for c in 0..CONVERSATIONS {
            if flat[c / 8] & (0x80 >> (c % 8)) != 0 {
                self.0[c] = link;
            }
        }
    }
}

pub fn slice_mask(flat: &[u8; 4 * MASK_BYTES]) -> [[u8; MASK_BYTES]; 4] {
    let mut out = [[0u8; MASK_BYTES]; 4];
    for (i, chunk) in flat.as_chunks::<MASK_BYTES>().0.iter().enumerate() {
        out[i] = *chunk;
    }
    out
}

pub fn merge_mask(masks: &[[u8; MASK_BYTES]; 4]) -> [u8; 4 * MASK_BYTES] {
    let mut flat = [0u8; 4 * MASK_BYTES];
    for (i, m) in masks.iter().enumerate() {
        flat[i * MASK_BYTES..(i + 1) * MASK_BYTES].copy_from_slice(m);
    }
    flat
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
    fn digest_is_stable_and_sensitive() {
        // MD5 of 8192 zero bytes, from md5sum, not from us.
        let empty = ConversationMap::default();
        assert_eq!(
            empty.digest(),
            [
                0x08, 0x29, 0xf7, 0x17, 0x40, 0xaa, 0xb1, 0xab, 0x98, 0xb3, 0x3e, 0xae, 0x21, 0xde,
                0xe1, 0x22
            ]
        );
        let mut one = ConversationMap::default();
        one.set(100, 1);
        assert_ne!(one.digest(), empty.digest());
        assert_eq!(one.link_of(100), Some(1));
        assert_eq!(one.link_of(4096), None);
        one.set(5000, 1); // out of range ignored
        assert_eq!(one.link_of(5000), None);
    }

    #[test]
    fn masks_slice_merge_round_trip() {
        let mut m = ConversationMap::default();
        for c in [0u16, 1, 1023, 1024, 2047, 3000, 4095] {
            m.set(c, 2);
        }
        let masks = m.masks_for_link(2);
        assert_eq!(masks[0][0], 0xc0);
        assert_eq!(masks[1][0], 0x80); // conversation 1024
        assert_eq!(masks[3][MASK_BYTES - 1], 0x01); // conversation 4095
        let mut back = ConversationMap::default();
        back.apply_masks(2, &masks);
        assert_eq!(back, m);
        assert_eq!(slice_mask(&merge_mask(&masks)), masks);
    }
}
