//! Bridge/port identifiers and priority vectors, IEEE 802.1Q-2022 9.2.5, 13.10.

use crate::bpdu::Params;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("bridge priority {0} is not a multiple of 4096")]
    BridgePriority(u16),
    #[error("system id extension {0} does not fit 12 bits")]
    Extension(u16),
    #[error("port priority {0} is not a multiple of 16 up to 240")]
    PortPriority(u8),
    #[error("port number {0} does not fit 12 bits")]
    PortNumber(u16),
}

/// Bridge identifier: priority (4 bits, steps of 4096) + system id extension
/// (12 bits) + MAC. Field order makes the derived `Ord` the numeric compare of
/// the 8 wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BridgeId {
    priority: u16,
    ext: u16,
    mac: [u8; 6],
}

impl BridgeId {
    pub fn new(priority: u16, ext: u16, mac: [u8; 6]) -> Result<Self, IdError> {
        if !priority.is_multiple_of(4096) {
            return Err(IdError::BridgePriority(priority));
        }
        if ext >= 4096 {
            return Err(IdError::Extension(ext));
        }
        Ok(BridgeId { priority, ext, mac })
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }

    pub fn ext(&self) -> u16 {
        self.ext
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Same bridge address, priority and extension ignored: the identity
    /// 802.1Q 13.29 `rcvInfo` / 13.30 `updtRolesTree` compare, while the
    /// derived `Ord`/`PartialEq` stay the full 13.10 order.
    pub fn same_address(&self, other: &Self) -> bool {
        self.mac == other.mac
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0; 8];
        b[..2].copy_from_slice(&(self.priority | self.ext).to_be_bytes());
        b[2..].copy_from_slice(&self.mac);
        b
    }

    /// Any 8 bytes are a valid identifier.
    pub fn from_bytes(b: [u8; 8]) -> Self {
        let first = u16::from_be_bytes([b[0], b[1]]);
        BridgeId {
            priority: first & 0xf000,
            ext: first & 0x0fff,
            mac: [b[2], b[3], b[4], b[5], b[6], b[7]],
        }
    }
}

/// Port identifier: priority (4 bits, steps of 16) + port number (12 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortId {
    priority: u8,
    number: u16,
}

impl PortId {
    pub fn new(priority: u8, number: u16) -> Result<Self, IdError> {
        if !priority.is_multiple_of(16) {
            return Err(IdError::PortPriority(priority));
        }
        if number >= 4096 {
            return Err(IdError::PortNumber(number));
        }
        Ok(PortId { priority, number })
    }

    pub fn priority(&self) -> u8 {
        self.priority
    }

    pub fn number(&self) -> u16 {
        self.number
    }

    /// Same port number, priority ignored (sender identity, 13.29 `rcvInfo`).
    pub fn same_number(&self, other: &Self) -> bool {
        self.number == other.number
    }

    pub fn to_u16(&self) -> u16 {
        (u16::from(self.priority) << 8) | self.number
    }

    pub fn from_u16(v: u16) -> Self {
        PortId {
            priority: (v >> 8) as u8 & 0xf0,
            number: v & 0x0fff,
        }
    }
}

/// 13.10 priority vector. Derived `Ord` is the lexicographic order of the
/// fields as declared; lower is better. The machine-level comparisons that need
/// `infoIs`/`designatedPriority` belong to the state machines, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PriorityVector {
    pub root: BridgeId,
    pub root_path_cost: u32,
    pub designated_bridge: BridgeId,
    pub designated_port: PortId,
    pub bridge_port: PortId,
}

impl PriorityVector {
    /// The message priority vector of a received BPDU; `receiving_port` is the
    /// port it arrived on (the fifth component).
    pub fn from_bpdu(p: &Params, receiving_port: PortId) -> Self {
        PriorityVector {
            root: p.root,
            root_path_cost: p.root_path_cost,
            designated_bridge: p.bridge,
            designated_port: p.port,
            bridge_port: receiving_port,
        }
    }

    pub fn better_than(&self, other: &Self) -> bool {
        self < other
    }

    pub fn same_as(&self, other: &Self) -> bool {
        self == other
    }

    pub fn worse_than(&self, other: &Self) -> bool {
        self > other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bid(p: u16, ext: u16, m: u8) -> BridgeId {
        BridgeId::new(p, ext, [0, 0, 0, 0, 0, m]).unwrap()
    }

    fn pid(p: u8, n: u16) -> PortId {
        PortId::new(p, n).unwrap()
    }

    fn base() -> PriorityVector {
        PriorityVector {
            root: bid(4096, 0, 5),
            root_path_cost: 10,
            designated_bridge: bid(8192, 0, 5),
            designated_port: pid(128, 3),
            bridge_port: pid(128, 4),
        }
    }

    #[test]
    fn bridge_id_pack_unpack() {
        let b = BridgeId::new(32768, 100, [1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(b.to_bytes(), [0x80, 0x64, 1, 2, 3, 4, 5, 6]);
        assert_eq!(BridgeId::from_bytes(b.to_bytes()), b);
        assert_eq!(
            (b.priority(), b.ext(), b.mac()),
            (32768, 100, [1, 2, 3, 4, 5, 6])
        );
        assert_eq!(
            BridgeId::new(61440, 4095, [0; 6]).unwrap().to_bytes()[..2],
            [0xff, 0xff]
        );
        assert_eq!(
            BridgeId::new(4097, 0, [0; 6]),
            Err(IdError::BridgePriority(4097))
        );
        assert_eq!(
            BridgeId::new(u16::MAX, 0, [0; 6]),
            Err(IdError::BridgePriority(u16::MAX))
        );
        assert_eq!(
            BridgeId::new(0, 4096, [0; 6]),
            Err(IdError::Extension(4096))
        );
    }

    #[test]
    fn port_id_pack_unpack() {
        let p = pid(128, 0x123);
        assert_eq!(p.to_u16(), 0x8123);
        assert_eq!(PortId::from_u16(0x8123), p);
        assert_eq!((p.priority(), p.number()), (128, 0x123));
        assert_eq!(PortId::new(240, 4095).unwrap().to_u16(), 0xffff);
        assert_eq!(PortId::new(8, 1), Err(IdError::PortPriority(8)));
        assert_eq!(PortId::new(0, 4096), Err(IdError::PortNumber(4096)));
    }

    #[test]
    fn bridge_id_order_is_numeric_on_the_wire() {
        // Priority dominates the extension, which dominates the MAC.
        assert!(bid(0, 4095, 255) < bid(4096, 0, 0));
        assert!(bid(4096, 1, 255) > bid(4096, 0, 255));
        assert!(bid(4096, 1, 1) < bid(4096, 1, 2));
    }

    #[test]
    fn one_decisive_field_each() {
        let b = base();
        let cases: [(PriorityVector, PriorityVector); 5] = [
            (
                PriorityVector {
                    root: bid(0, 0, 9),
                    ..b
                },
                b,
            ),
            (
                PriorityVector {
                    root_path_cost: 9,
                    root: b.root,
                    ..b
                },
                b,
            ),
            (
                PriorityVector {
                    designated_bridge: bid(4096, 0, 9),
                    ..b
                },
                b,
            ),
            (
                PriorityVector {
                    designated_port: pid(112, 9),
                    ..b
                },
                b,
            ),
            (
                PriorityVector {
                    bridge_port: pid(128, 3),
                    ..b
                },
                b,
            ),
        ];
        for (better, worse) in cases {
            assert!(better.better_than(&worse) && worse.worse_than(&better));
            assert!(!better.same_as(&worse));
        }
        // A better early field beats a worse later one.
        let early = PriorityVector {
            root: bid(0, 0, 9),
            root_path_cost: 999,
            ..b
        };
        assert!(early.better_than(&b));
        assert!(b.same_as(&b) && !b.better_than(&b) && !b.worse_than(&b));
    }

    fn grid() -> Vec<PriorityVector> {
        // Every combination of two values per component.
        (0u8..32)
            .map(|i| {
                let bit = |n: u8| (i >> n) & 1;
                PriorityVector {
                    root: bid(0, 0, bit(0)),
                    root_path_cost: u32::from(bit(1)),
                    designated_bridge: bid(0, 0, bit(2)),
                    designated_port: pid(0, u16::from(bit(3))),
                    bridge_port: pid(0, u16::from(bit(4))),
                }
            })
            .collect()
    }

    #[test]
    fn antisymmetry_and_transitivity() {
        let g = grid();
        for a in &g {
            for b in &g {
                assert_eq!(a.better_than(b), b.worse_than(a));
                let verdicts = [a.better_than(b), a.same_as(b), a.worse_than(b)];
                assert_eq!(verdicts.iter().filter(|x| **x).count(), 1);
                for c in &g {
                    if a.better_than(b) && b.better_than(c) {
                        assert!(a.better_than(c));
                    }
                }
            }
        }
    }

    #[test]
    fn from_bpdu_maps_fields() {
        let b = base();
        let p = Params {
            flags: crate::bpdu::Flags::default(),
            root: b.root,
            root_path_cost: b.root_path_cost,
            bridge: b.designated_bridge,
            port: b.designated_port,
            message_age: 0,
            max_age: 0,
            hello_time: 0,
            forward_delay: 0,
        };
        assert_eq!(PriorityVector::from_bpdu(&p, b.bridge_port), b);
    }
}
