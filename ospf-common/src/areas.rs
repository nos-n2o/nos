//! Area logic shared by `nos-ospf` and `nos-ospfv3`: RFC 2328 §3.5/§12.4.3
//! (RFC 5340 §4.4.3.3) address-range aggregation, and the stub/NSSA LSA scope
//! rule. Each daemon classifies its own LSA types and prefix type.

use std::collections::HashMap;
use std::hash::Hash;

use ipnet::{Ipv4Net, Ipv6Net};

/// What `apply_ranges` needs from a prefix type.
pub trait RangePrefix: Copy + Eq + Hash {
    /// Whether `other` lies inside `self` (equal counts).
    fn contains_prefix(&self, other: &Self) -> bool;
    fn plen(&self) -> u8;
    /// Host bits cleared.
    #[must_use]
    fn truncated(&self) -> Self;
}

macro_rules! range_prefix {
    ($t:ty) => {
        impl RangePrefix for $t {
            fn contains_prefix(&self, other: &Self) -> bool {
                self.contains(other)
            }
            fn plen(&self) -> u8 {
                self.prefix_len()
            }
            fn truncated(&self) -> Self {
                self.trunc()
            }
        }
    };
}
range_prefix!(Ipv4Net);
range_prefix!(Ipv6Net);

/// `(prefix, metric)` pairs.
pub type Summaries<P> = Vec<(P, u32)>;

/// Applies one source area's address ranges to its intra-area `(prefix,
/// metric)` routes. Returns what to summarize into the other areas — every
/// route no range covers, plus one entry per `advertise` range with at least
/// one covered route (metric = the *largest* covered cost, RFC 2328; RFC 1583
/// used the smallest) — and those active advertised ranges on their own, for
/// the ABR's discard routes. A route covered by two ranges counts towards the
/// most specific one.
pub fn apply_ranges<P: RangePrefix>(
    routes: &[(P, u32)],
    ranges: &[(P, bool)],
) -> (Summaries<P>, Summaries<P>) {
    let mut summarize = Vec::new();
    let mut covered: HashMap<P, (bool, u32)> = HashMap::new();
    for &(prefix, metric) in routes {
        let range = ranges
            .iter()
            .filter(|(net, _)| net.contains_prefix(&prefix))
            .max_by_key(|(net, _)| net.plen());
        match range {
            None => summarize.push((prefix, metric)),
            Some((net, advertise)) => {
                let entry = covered.entry(net.truncated()).or_insert((*advertise, 0));
                entry.1 = entry.1.max(metric);
            }
        }
    }
    let active: Vec<(P, u32)> = covered
        .into_iter()
        .filter(|(_, (advertise, _))| *advertise)
        .map(|(net, (_, metric))| (net, metric))
        .collect();
    summarize.extend(active.iter().copied());
    (summarize, active)
}

/// Whether an LSA belongs in an area of this kind: no AS-scope LSA in a stub
/// area or NSSA (`stub` is set for both), and an NSSA-type LSA (Type-7) only
/// in an NSSA (RFC 3101 §2.4).
#[allow(
    clippy::fn_params_excessive_bools,
    reason = "v2/v3 classify their own LSA types into these flags"
)]
pub fn in_area_scope(as_scope: bool, nssa_type: bool, stub: bool, nssa: bool) -> bool {
    !(stub && as_scope) && (nssa || !nssa_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }
    fn v6(s: &str) -> Ipv6Net {
        s.parse().unwrap()
    }

    /// Aggregates at the largest covered cost, not-advertise hides, an empty
    /// range is not active.
    #[test]
    fn aggregates_at_max_cost_and_hides_not_advertised() {
        let routes = [
            (v4("10.1.1.0/24"), 3),
            (v4("10.1.2.0/24"), 7),
            (v4("10.2.1.0/24"), 4),
            (v4("192.168.1.0/24"), 9),
        ];
        let ranges = [
            (v4("10.1.0.0/16"), true),
            (v4("10.2.0.0/16"), false),
            (v4("10.3.0.0/16"), true),
        ];
        let (mut summarize, active) = apply_ranges(&routes, &ranges);
        summarize.sort();
        assert_eq!(
            summarize,
            vec![(v4("10.1.0.0/16"), 7), (v4("192.168.1.0/24"), 9)]
        );
        assert_eq!(active, vec![(v4("10.1.0.0/16"), 7)]);
        assert_eq!(apply_ranges(&routes, &[]).0.len(), 4);
    }

    #[test]
    fn v6_most_specific_range_wins() {
        let routes = [
            (v6("2001:db8:1:1::/64"), 5),
            (v6("2001:db8:2::/64"), 2),
            (v6("2001:db8:1:2::/64"), 9),
        ];
        let ranges = [(v6("2001:db8::/32"), true), (v6("2001:db8:1::/48"), true)];
        let (mut summarize, active) = apply_ranges(&routes, &ranges);
        summarize.sort();
        let mut want = vec![(v6("2001:db8:1::/48"), 9), (v6("2001:db8::/32"), 2)];
        want.sort();
        assert_eq!(summarize, want);
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn v6_not_advertise_zero_range_equal_route_and_host_bits() {
        // /0 range swallows everything; not-advertise hides it.
        let routes = [(v6("2001:db8::/64"), 4)];
        let (s, a) = apply_ranges(&routes, &[(v6("::/0"), false)]);
        assert!(s.is_empty() && a.is_empty());
        let (s, a) = apply_ranges(&routes, &[(v6("::/0"), true)]);
        assert_eq!(s, vec![(v6("::/0"), 4)]);
        assert_eq!(a, s);
        // A route equal to its range is covered by it.
        let (s, _) = apply_ranges(&routes, &[(v6("2001:db8::/64"), true)]);
        assert_eq!(s, vec![(v6("2001:db8::/64"), 4)]);
        // Host bits in the configured range are truncated.
        let (s, _) = apply_ranges(&routes, &[(v6("2001:db8::1/32"), true)]);
        assert_eq!(s, vec![(v6("2001:db8::/32"), 4)]);
    }

    #[test]
    fn scope_rule() {
        // (as_scope, nssa_type, stub, nssa)
        assert!(in_area_scope(true, false, false, false));
        assert!(!in_area_scope(true, false, true, false));
        assert!(!in_area_scope(true, false, true, true));
        assert!(!in_area_scope(false, true, false, false));
        assert!(in_area_scope(false, true, true, true));
        assert!(in_area_scope(false, false, true, false));
    }
}
