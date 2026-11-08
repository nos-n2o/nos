//! The RIB side of BMP Adj-RIB-Out monitoring (#867, RFC 8671): the
//! pre-policy candidate hook, the connect-time snapshots and the counts for
//! Statistics types 14-17. The post-policy stream is the FSM's wire hook
//! (`fsm::write_update`), not here.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use ipnet::IpNet;

use super::decision::{build_advertisement, eligibility};
use super::{family_of, AdvertisedRoute, BgpRib, OutboundUpdate, RibRoute};
use crate::bmp::{monitor, Hub};
use crate::message::UpdateMessage;

/// One pre-policy step for a monitored peer: `cand` is the Loc-RIB route when
/// it is a candidate for `peer`, `None` when it is not (or is gone).
/// `tracked` is what the collector was told, so a withdrawal is only sent for
/// a prefix it saw announced.
pub(super) fn pre_step(
    hub: &Hub,
    tracked: &mut HashSet<IpNet>,
    peer: IpAddr,
    prefix: IpNet,
    cand: Option<&RibRoute>,
) {
    match cand {
        Some(r) => {
            hub.route_out_pre(peer, &monitor::pre_out_update(prefix, r));
            tracked.insert(prefix);
        }
        None => {
            if tracked.remove(&prefix) {
                hub.route_out_pre(peer, &monitor::pre_out_withdraw(prefix));
            }
        }
    }
}

/// What a station's Out dump needs for one peer, read under one RIB hold.
pub(crate) struct OutSnapshot {
    /// What the peer was last sent, as the RIB would send it again.
    pub post: Vec<OutboundUpdate>,
    /// AFIs for which this session sends ADD-PATH identifiers.
    pub tx_afis: HashSet<u16>,
    /// The candidate announcements (pre-policy, unicast).
    pub pre: Vec<UpdateMessage>,
}

/// Out counts for the Statistics Report: pre, post, and each per unicast AFI.
pub(crate) struct OutCounts {
    pub pre: u64,
    pub pre_v4: u64,
    pub post: u64,
    pub post_v4: u64,
    pub post_v6: u64,
}

impl BgpRib {
    /// The unicast pre-policy candidates for `peer`: every Loc-RIB route the
    /// export side would even consider.
    fn pre_candidates(&self, peer: IpAddr) -> Vec<(IpNet, &RibRoute)> {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return Vec::new();
        };
        self.loc_rib
            .iter()
            .filter(|(p, _)| !self.suppressed_by_aggregate(**p))
            .filter(|(p, r)| {
                eligibility(family_of(**p), r, peer, outbox, self.source_is_rr_client(r)).is_some()
            })
            .map(|(p, r)| (*p, r))
            .collect()
    }

    /// Snapshots `peer`'s Adj-RIB-Out for a station dump and, when `pre`,
    /// resets the pre-policy tracking to exactly the announced set.
    // ponytail: one RIB lock hold over the peer's whole Out table; chunk it
    // like the Adj-RIB-In dump if a full-table peer ever stalls the RIB.
    pub(crate) fn bmp_out_snapshot(&mut self, peer: IpAddr, post: bool, pre: bool) -> OutSnapshot {
        let mut snap = OutSnapshot {
            post: Vec::new(),
            tx_afis: HashSet::new(),
            pre: Vec::new(),
        };
        if pre {
            let cands = self.pre_candidates(peer);
            snap.pre = cands
                .iter()
                .map(|(p, r)| monitor::pre_out_update(*p, r))
                .collect();
            let set: HashSet<IpNet> = cands.iter().map(|(p, _)| *p).collect();
            self.bmp_pre_out.insert(peer, set);
        }
        let Some(outbox) = self.peer_outboxes.get(&peer).filter(|_| post) else {
            return snap;
        };
        snap.tx_afis = outbox
            .add_path_tx
            .iter()
            .map(|f| crate::gr::afi_safi(*f).0)
            .collect();
        let rebuild = |prefix: IpNet, route: &RibRoute| {
            build_advertisement(
                prefix,
                route,
                peer,
                outbox,
                self.local_asn,
                self.source_is_rr_client(route),
                self.cluster_id,
                None,
            )
        };
        for prefix in self.adj_rib_out.get(&peer).into_iter().flatten() {
            if let Some(adv) = self.loc_rib.get(prefix).and_then(|r| rebuild(*prefix, r)) {
                snap.post.push(OutboundUpdate::Announce(adv));
            }
        }
        for ((p, prefix), sent) in &self.add_path_sent {
            if *p != peer {
                continue;
            }
            for (id, route) in sent.values() {
                if let Some(adv) = rebuild(*prefix, route) {
                    snap.post.push(OutboundUpdate::Announce(AdvertisedRoute {
                        path_id: Some(*id),
                        ..adv
                    }));
                }
            }
        }
        snap.post.extend(
            self.evpn_adj_rib_out
                .get(&peer)
                .into_iter()
                .flat_map(HashMap::values)
                .map(|a| OutboundUpdate::AnnounceEvpn(a.clone())),
        );
        snap.post.extend(
            self.flowspec_adj_rib_out
                .get(&peer)
                .into_iter()
                .flat_map(HashMap::values)
                .map(|a| OutboundUpdate::AnnounceFlowspec(a.clone())),
        );
        snap.post.extend(
            self.vpn_adj_rib_out
                .get(&peer)
                .into_iter()
                .flat_map(HashMap::values)
                .map(|a| OutboundUpdate::AnnounceVpn(a.clone())),
        );
        snap
    }

    /// A monitored peer just came up with a station already connected: its
    /// initial update bypassed the pre-policy hook (the hub did not know the
    /// peer yet), so announce the candidates now.
    pub fn bmp_pre_out_sync(&mut self, peer: IpAddr) {
        let Some(hub) = self.bmp.clone() else { return };
        for u in self.bmp_out_snapshot(peer, false, true).pre {
            hub.route_out_pre(peer, &u);
        }
    }

    /// Adj-RIB-Out sizes of `peer` for Statistics types 14-17.
    pub(crate) fn bmp_out_counts(&self, peer: IpAddr) -> OutCounts {
        let (mut v4, mut v6) = (0u64, 0u64);
        for p in self.adj_rib_out.get(&peer).into_iter().flatten() {
            if p.addr().is_ipv4() {
                v4 += 1;
            } else {
                v6 += 1;
            }
        }
        for ((pr, p), sent) in &self.add_path_sent {
            if *pr == peer {
                if p.addr().is_ipv4() {
                    v4 += sent.len() as u64;
                } else {
                    v6 += sent.len() as u64;
                }
            }
        }
        let pre = self.bmp_pre_out.get(&peer);
        let pre_v4 = pre.map_or(0, |s| s.iter().filter(|p| p.addr().is_ipv4()).count()) as u64;
        let other = self.evpn_adj_rib_out.get(&peer).map_or(0, HashMap::len)
            + self.flowspec_adj_rib_out.get(&peer).map_or(0, HashMap::len)
            + self.vpn_adj_rib_out.get(&peer).map_or(0, HashMap::len);
        OutCounts {
            pre: pre.map_or(0, HashSet::len) as u64,
            pre_v4,
            post: v4 + v6 + other as u64,
            post_v4: v4,
            post_v6: v6,
        }
    }
}
