//! Per-peer BMP statistics (#864, RFC 7854 section 4.8): the counters the
//! Adj-RIB-In paths bump and the gauge snapshot a Statistics Report carries.

use std::net::IpAddr;

use super::BgpRib;
use crate::bmp::stats::Stat;

/// Per-session counters, reset when the peer registers and dropped with it.
/// Wrapping `u32`, as the wire counters are.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerStats {
    /// Type 0: prefixes rejected by inbound policy.
    pub rejected: u32,
    /// Type 1: duplicate advertisements (an identical re-announcement).
    pub dup_adv: u32,
    /// Type 2: withdraws of a path not held.
    pub dup_withdraw: u32,
    /// Type 3: updates dropped for a `CLUSTER_LIST` loop.
    pub cluster_loop: u32,
    /// Type 4: updates dropped for an `AS_PATH` loop.
    pub as_loop: u32,
    /// Type 5: updates dropped for our own `ORIGINATOR_ID`.
    pub originator: u32,
    /// Type 6: updates dropped for an `AS_CONFED` loop.
    pub confed_loop: u32,
    /// Type 11: updates treated as withdraw.
    pub tw_updates: u32,
    /// Type 12: prefixes treated as withdrawn.
    pub tw_prefixes: u32,
}

/// Adds `n` to a counter, wrapping.
pub(super) fn bump(counter: &mut u32, n: u32) {
    *counter = counter.wrapping_add(n);
}

/// Loc-RIB totals, scanned once per station tick and shared by all peers
/// (unicast only; the other families keep no Loc-RIB total here).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocTotals {
    pub v4: u64,
    pub v6: u64,
}

impl BgpRib {
    /// The counter set of `peer` (all zero when it never registered).
    pub fn peer_stats(&self, peer: IpAddr) -> PeerStats {
        self.peer_stats.get(&peer).copied().unwrap_or_default()
    }

    pub(super) fn stats_mut(&mut self, peer: IpAddr) -> &mut PeerStats {
        self.peer_stats.entry(peer).or_default()
    }

    /// One Loc-RIB scan. ponytail: O(Loc-RIB) per tick under the RIB lock;
    /// keep running counts in the decision process if a full table makes the
    /// interval hurt.
    pub fn loc_totals(&self) -> LocTotals {
        let v4 = self.loc_rib.keys().filter(|p| p.addr().is_ipv4()).count();
        LocTotals {
            v4: v4 as u64,
            v6: (self.loc_rib.len() - v4) as u64,
        }
    }

    /// Everything one peer's Statistics Report carries (never empty).
    pub fn bmp_stats(&self, peer: IpAddr, loc: LocTotals) -> Vec<Stat> {
        let s = self.peer_stats(peer);
        let mut out = vec![
            Stat::Counter(0, s.rejected),
            Stat::Counter(1, s.dup_adv),
            Stat::Counter(2, s.dup_withdraw),
            Stat::Counter(3, s.cluster_loop),
            Stat::Counter(4, s.as_loop),
            Stat::Counter(5, s.originator),
            Stat::Counter(6, s.confed_loop),
            Stat::Counter(11, s.tw_updates),
            Stat::Counter(12, s.tw_prefixes),
        ];
        let per_family: Vec<(u16, u8, u64)> = self
            .bmp_families(peer)
            .into_iter()
            .filter_map(|(afi, safi)| {
                let f = crate::gr::family_of(afi, safi)?;
                Some((afi, safi, u64::from(self.accepted_count(peer, f))))
            })
            .collect();
        out.push(Stat::Gauge(7, per_family.iter().map(|f| f.2).sum()));
        out.push(Stat::Gauge(8, loc.v4 + loc.v6));
        out.extend(
            per_family
                .into_iter()
                .map(|(afi, safi, n)| Stat::AfiSafi(9, afi, safi, n)),
        );
        out.push(Stat::AfiSafi(10, 1, 1, loc.v4));
        out.push(Stat::AfiSafi(10, 2, 1, loc.v6));
        out
    }
}
