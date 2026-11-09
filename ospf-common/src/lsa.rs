//! The LSA identity the shared `Lsdb` needs: key, sequence number, checksum,
//! age. Bodies, scope and family decisions stay in the daemons (RFC 2328 and
//! RFC 5340 differ there), so these traits carry identity only.

use std::cmp::Ordering;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::Ipv4Addr;

/// RFC 2328 Appendix B `MaxAge`, in seconds — identical in RFC 5340.
pub const MAX_AGE: u16 = 3600;

/// The 20-byte common LSA header, as far as the database cares.
pub trait LsaHeader: Copy + Debug + PartialEq {
    /// The `(type, link-state id, advertising router)` slot; `lsa_type` is a
    /// `u8` in v2 and a `u16` in v3, hence an associated type.
    type Key: Copy + Eq + Hash + Debug;
    fn key(&self) -> Self::Key;
    fn seq(&self) -> i32;
    fn age(&self) -> u16;
    fn set_age(&mut self, age: u16);
    fn checksum(&self) -> u16;
    fn length(&self) -> u16;
    fn advertising_router(&self) -> Ipv4Addr;

    /// RFC 2328 §13.1's "which LSA instance is newer": higher sequence number
    /// wins, then higher checksum, then an instance at `MAX_AGE` (being
    /// flushed) is newer than one that isn't. `Equal` is §13.1's "same
    /// instance"; the `MaxAgeDiff` tie-break is deliberately not implemented
    /// (instances tying on sequence and checksum are the same content).
    fn is_newer(&self, other: &Self) -> Ordering {
        if self.seq() != other.seq() {
            return self.seq().cmp(&other.seq());
        }
        if self.checksum() != other.checksum() {
            return self.checksum().cmp(&other.checksum());
        }
        match (self.age() == MAX_AGE, other.age() == MAX_AGE) {
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            _ => Ordering::Equal,
        }
    }
}

/// RFC 2328 §13.4: the headers among `installed` that this router itself
/// advertised — its own LSAs a neighbor flooded back newer than the held
/// copy (including a `MaxAge` one).
pub fn reflected_self_lsas<H: LsaHeader>(installed: &[H], router_id: Ipv4Addr) -> Vec<H> {
    installed
        .iter()
        .filter(|h| h.advertising_router() == router_id)
        .copied()
        .collect()
}

/// A whole LSA: a header plus a family-specific body the database never reads.
pub trait Lsa: Clone + Debug + PartialEq {
    type Header: LsaHeader;
    /// Extra per-packet data a DBD carries (RFC 5613 LLS for v2, `()` for v3).
    type Lls: Clone + Debug + PartialEq;
    fn header(&self) -> &Self::Header;
    fn header_mut(&mut self) -> &mut Self::Header;
}

#[cfg(test)]
pub(crate) mod test_lsa {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct H {
        pub id: u32,
        pub seq: i32,
        pub age: u16,
        pub checksum: u16,
    }

    impl LsaHeader for H {
        type Key = u32;
        fn key(&self) -> u32 {
            self.id
        }
        fn seq(&self) -> i32 {
            self.seq
        }
        fn age(&self) -> u16 {
            self.age
        }
        fn set_age(&mut self, age: u16) {
            self.age = age;
        }
        fn checksum(&self) -> u16 {
            self.checksum
        }
        fn length(&self) -> u16 {
            20
        }
        fn advertising_router(&self) -> Ipv4Addr {
            Ipv4Addr::from(self.id)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct L(pub H);

    impl Lsa for L {
        type Header = H;
        type Lls = ();
        fn header(&self) -> &H {
            &self.0
        }
        fn header_mut(&mut self) -> &mut H {
            &mut self.0
        }
    }

    pub fn lsa(seq: i32) -> L {
        L(H {
            id: 9,
            seq,
            age: 0,
            checksum: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_lsa::{lsa, H};
    use super::*;

    fn h(seq: i32, checksum: u16, age: u16) -> H {
        H {
            id: 1,
            seq,
            age,
            checksum,
        }
    }

    #[test]
    fn is_newer_orders_by_seq_then_checksum_then_max_age() {
        use Ordering::{Equal, Greater, Less};
        let table = [
            (h(2, 0, 0), h(1, 9, 0), Greater),
            (h(1, 9, 0), h(2, 0, 0), Less),
            (h(1, 5, 0), h(1, 4, 0), Greater),
            (h(1, 4, 0), h(1, 5, 0), Less),
            (h(1, 4, MAX_AGE), h(1, 4, 10), Greater),
            (h(1, 4, 10), h(1, 4, MAX_AGE), Less),
            (h(1, 4, 10), h(1, 4, 99), Equal),
            (h(1, 4, MAX_AGE), h(1, 4, MAX_AGE), Equal),
        ];
        for (a, b, want) in table {
            assert_eq!(a.is_newer(&b), want, "{a:?} vs {b:?}");
        }
    }

    #[test]
    fn reflected_self_lsas_keeps_only_own_including_max_age() {
        let own = |age| H {
            id: 5,
            seq: 1,
            age,
            checksum: 0,
        };
        let foreign = H {
            id: 6,
            seq: 1,
            age: 0,
            checksum: 0,
        };
        let me = Ipv4Addr::from(5u32);
        assert_eq!(
            reflected_self_lsas(&[own(0), foreign, own(MAX_AGE)], me),
            vec![own(0), own(MAX_AGE)]
        );
    }

    #[test]
    fn test_lsa_accessors_round_trip() {
        let mut l = lsa(3);
        l.header_mut().set_age(7);
        assert_eq!(l.header().age(), 7);
        assert_eq!(l.header().length(), 20);
        assert_eq!(l.header().advertising_router(), Ipv4Addr::from(9u32));
    }
}
