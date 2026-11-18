//! RFC 4684 Route Target Constraint (AFI 1 / SAFI 132, #875): the membership
//! exchange and the outbound filter it drives.
//!
//! A peer that negotiated the family tells us which Route Targets it wants as
//! `RtcNlri` prefixes; we hold them per peer (`rtc_adj_rib_in`), derive a
//! `RtcInterest` from them and cache it on that peer's `PeerOutbox`
//! (`None` = not negotiated = no filtering). `advertise_vpn` and
//! `evpn_out::advertise` consult it, so a VPN/EVPN route only goes to a peer
//! with matching interest. Our own membership (the union of every import RT
//! of this instance, `membership`) is originated as `Local` candidates and
//! propagated like any other path (best per key, standard reflection and
//! eBGP-prepend rules, RFC 4684 section 3.2).
//!
//! Stale membership from a gracefully restarting peer is live interest
//! (RFC 4724: stale routes stay valid until End-of-RIB or the timer), so the
//! interest is built from the whole table, stale entries included.
//!
//! ponytail: export/import policy does not apply to membership routes
//! (RPL's `Input` is prefix-shaped), like EVPN.
//! ponytail: a membership change re-evaluates `vpn_loc`/`evpn_local` by a
//! scan filtered on the changed keys, O(table); index by RT if profiling asks.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net};
use nos_proto::evpn_id::parse_rt;
use nos_proto::{AddressFamily, Config};

use super::{
    best_path, build_advertisement, debug, decision, info, message, warn, AdvertisedRoute, BgpRib,
    Candidate, OutboundUpdate, RibRoute, RouteOrigin,
};
use crate::evpn::format_ext_community;
use crate::message::RtcNlri;
use crate::vpn::{is_route_target, VrfSet};

/// One membership key: `(origin AS, route target, prefix length)`.
pub type RtcKey = RtcNlri;

/// One membership route rewritten for one peer.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertisedRtc {
    pub key: RtcKey,
    /// The attributes and next hop (our session address); `prefix` unused.
    pub route: AdvertisedRoute,
}

impl RtcNlri {
    /// Whether this membership entry asks for route target `rt` (RFC 4684
    /// section 4 leaves partial prefixes undefined; the rule here is the
    /// inference recorded in `bgp-internals.md`): the default route wants
    /// every RT, otherwise the first `bits - 32` bits of the RT must equal
    /// the entry's (so a 32-bit prefix wants every RT). The origin AS is
    /// ignored.
    #[must_use]
    pub fn covers(&self, rt: u64) -> bool {
        match self.bits {
            0 => true,
            32..=96 => {
                let n = u32::from(self.bits - 32);
                let mask = if n == 0 { 0 } else { u64::MAX << (64 - n) };
                (rt ^ self.rt) & mask == 0
            }
            _ => false,
        }
    }

    /// Whether any RT of `ext_communities` is covered.
    #[must_use]
    pub fn covers_any(&self, ext_communities: &[u64]) -> bool {
        ext_communities
            .iter()
            .any(|c| is_route_target(*c) && self.covers(*c))
    }
}

/// What a peer asked for, built from its whole membership table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct RtcInterest {
    default: bool,
    /// 96-bit entries: RT equality.
    exact: HashSet<u64>,
    /// 32..=95-bit entries.
    partial: Vec<RtcNlri>,
}

impl RtcInterest {
    pub(super) fn from_keys<'a>(keys: impl Iterator<Item = &'a RtcNlri>) -> Self {
        let mut i = Self::default();
        for k in keys {
            match k.bits {
                0 => i.default = true,
                96 => {
                    i.exact.insert(k.rt);
                }
                _ => i.partial.push(*k),
            }
        }
        i
    }

    /// Whether a VPN/EVPN route carrying `ext_communities` is wanted: the
    /// default route is held, or one of its RTs is covered. No membership
    /// at all permits nothing.
    pub(super) fn permits(&self, ext_communities: &[u64]) -> bool {
        self.default
            || ext_communities.iter().any(|c| {
                is_route_target(*c)
                    && (self.exact.contains(c) || self.partial.iter().any(|p| p.covers(*c)))
            })
    }
}

/// The Route Targets this instance wants to receive: every VRF's import RTs,
/// plus those of the broadcast domains it carries `redistribute from mac to
/// bgp` for and of the IP-VRFs whose `evpn` rides it. Empty means nothing is
/// originated (and a peer then sends nothing, which is correct).
#[must_use]
pub fn membership(cfg: &Config, instance: &str) -> BTreeSet<u64> {
    let parse = |v: &[String]| v.iter().filter_map(|r| parse_rt(r)).collect::<Vec<_>>();
    let mut out: BTreeSet<u64> = VrfSet::from_config(cfg, instance)
        .0
        .into_iter()
        .flat_map(|v| v.import)
        .collect();
    for d in &cfg.broadcast_domains {
        if d.vni.is_some() && d.mac_redistribute.as_deref() == Some(instance) {
            out.extend(parse(&d.route_targets_import));
        }
    }
    for t in &cfg.routing_tables {
        if t.evpn.l3_vni.is_some() && t.evpn.bgp_instance.as_deref() == Some(instance) {
            out.extend(parse(&t.evpn.route_targets_import));
        }
    }
    out
}

impl BgpRib {
    /// The AS our membership routes are originated from.
    fn rtc_origin_as(&self) -> u32 {
        self.confed_id.unwrap_or(self.local_asn)
    }

    /// Replaces our originated membership (`membership`) and re-selects what
    /// changed.
    pub fn set_rtc_membership(&mut self, rts: BTreeSet<u64>) {
        if rts == self.rtc_local {
            return;
        }
        let changed: Vec<u64> = self.rtc_local.symmetric_difference(&rts).copied().collect();
        self.rtc_local = rts;
        let origin_as = self.rtc_origin_as();
        for rt in changed {
            self.select_rtc(&RtcNlri {
                origin_as,
                rt,
                bits: 96,
            });
        }
    }

    /// The Route Targets we originate membership for.
    #[must_use]
    pub fn rtc_local(&self) -> &BTreeSet<u64> {
        &self.rtc_local
    }

    fn local_rtc(&self, k: &RtcKey) -> Option<RibRoute> {
        (k.bits == 96 && k.origin_as == self.rtc_origin_as() && self.rtc_local.contains(&k.rt))
            .then(decision::redistributed_route)
    }

    /// Stores one UPDATE's membership batches in `peer`'s table, selects
    /// each key and re-evaluates the VPN/EVPN routes the changed keys
    /// decide. A batch for a peer that did not negotiate the family is
    /// ignored (a test RIB without an outbox has no session to check).
    pub(super) fn learn_rtc(
        &mut self,
        update: &message::UpdateMessage,
        base: &RibRoute,
        peer: IpAddr,
    ) {
        let mut keys = Vec::new();
        for mp in &update.mp_reach {
            if mp.rtc.is_empty() {
                continue;
            }
            if self
                .peer_outboxes
                .get(&peer)
                .is_some_and(|o| !o.negotiated_afs.contains(&AddressFamily::RtConstraint))
            {
                warn!(peer = %peer, "rtc membership for a family not negotiated, ignored");
                continue;
            }
            let table = self.rtc_adj_rib_in.entry(peer).or_default();
            for n in &mp.rtc {
                let route = RibRoute {
                    next_hop: Some(mp.next_hop),
                    ..base.clone()
                };
                let new = match table.get(n) {
                    // An identical re-announcement keeps its age.
                    Some(old)
                        if (RibRoute {
                            received_at: old.received_at,
                            ..route.clone()
                        }) == *old =>
                    {
                        None
                    }
                    _ => Some(route),
                };
                if let Some(route) = new {
                    table.insert(*n, route);
                    info!(peer = %peer, origin_as = n.origin_as, rt = %rt_text(n), prefix_len = n.bits, "rtc membership learned");
                }
                keys.push(*n);
            }
        }
        self.rtc_changed(peer, &keys);
    }

    /// Removes membership `k` from `peer`'s table (logged) without any
    /// re-evaluation toward `peer`; the caller batches `rtc_changed`.
    pub(super) fn drop_rtc(&mut self, peer: IpAddr, k: &RtcKey) -> bool {
        let removed = self
            .rtc_adj_rib_in
            .get_mut(&peer)
            .and_then(|t| t.remove(k))
            .is_some();
        if removed {
            info!(peer = %peer, origin_as = k.origin_as, rt = %rt_text(k), prefix_len = k.bits, "rtc membership withdrawn");
            self.select_rtc(k);
        }
        removed
    }

    /// A graceful restart (or `BoRR`) of `peer`: every membership route held
    /// from it becomes stale, still counted as interest (Q11).
    pub(super) fn mark_rtc_stale(&mut self, peer: IpAddr) {
        if let Some(table) = self.rtc_adj_rib_in.get(&peer) {
            self.rtc_stale
                .entry(peer)
                .or_default()
                .extend(table.keys().copied());
        }
    }

    /// Purges `peer`'s stale membership (through `drop_rtcs`, which
    /// re-selects, re-advertises and resyncs VPN/EVPN toward the peer);
    /// returns how many.
    pub(super) fn purge_stale_rtc(&mut self, peer: IpAddr) -> usize {
        let keys: Vec<RtcKey> = self.rtc_stale.remove(&peer).into_iter().flatten().collect();
        let before = self.rtc_adj_rib_in.get(&peer).map_or(0, HashMap::len);
        self.drop_rtcs(peer, &keys);
        before - self.rtc_adj_rib_in.get(&peer).map_or(0, HashMap::len)
    }

    /// Withdraws a batch of `peer`'s membership and re-evaluates once.
    pub(super) fn drop_rtcs(&mut self, peer: IpAddr, keys: &[RtcKey]) {
        let removed: Vec<RtcKey> = keys
            .iter()
            .filter(|k| self.drop_rtc(peer, k))
            .copied()
            .collect();
        self.rtc_changed(peer, &removed);
    }

    /// `peer`'s membership changed at `keys`: refresh its cached interest
    /// and re-evaluate the VPN/EVPN routes those keys decide.
    pub(super) fn rtc_changed(&mut self, peer: IpAddr, keys: &[RtcKey]) {
        for k in keys {
            self.select_rtc(k);
        }
        let interest = RtcInterest::from_keys(
            self.rtc_adj_rib_in
                .get(&peer)
                .into_iter()
                .flatten()
                .map(|(k, _)| k),
        );
        let Some(outbox) = self.peer_outboxes.get_mut(&peer) else {
            return;
        };
        if outbox.rtc_interest.is_none() {
            return; // RTC not negotiated: nothing is filtered
        }
        outbox.rtc_interest = Some(interest);
        if keys.is_empty() || self.deferring() {
            return;
        }
        self.resync_vpn(peer, keys);
        self.resync_vpn_flow(peer, keys);
        self.resync_evpn(peer, keys);
    }

    /// The interest to cache on `peer`'s outbox at establishment: `None`
    /// unless RTC was negotiated. Stale entries of a restarting peer count.
    pub(super) fn rtc_interest_for(&self, peer: IpAddr, negotiated: bool) -> Option<RtcInterest> {
        negotiated.then(|| {
            RtcInterest::from_keys(
                self.rtc_adj_rib_in
                    .get(&peer)
                    .into_iter()
                    .flat_map(HashMap::keys),
            )
        })
    }

    /// Re-decides `k`'s best path among every peer's copy and our own and,
    /// when it changed, propagates it.
    pub(super) fn select_rtc(&mut self, k: &RtcKey) {
        let local = self.local_rtc(k);
        let candidates: Vec<Candidate> = self
            .rtc_adj_rib_in
            .values()
            .filter_map(|t| t.get(k))
            .chain(local.as_ref())
            .map(|r| (r.clone(), 0))
            .collect();
        let new = best_path(&candidates, &self.igp).and_then(|b| match b.origin {
            RouteOrigin::Peer(p) => Some((b.origin, self.rtc_adj_rib_in.get(&p)?.get(k)?.clone())),
            RouteOrigin::Local => Some((b.origin, local.clone()?)),
        });
        if self.rtc_loc.get(k) == new.as_ref() {
            return;
        }
        match new {
            Some(n) => self.rtc_loc.insert(*k, n),
            None => self.rtc_loc.remove(k),
        };
        if self.deferring() {
            return; // the deferral's end sends the initial update
        }
        let peers: Vec<IpAddr> = self.peer_outboxes.keys().copied().collect();
        for peer in peers {
            self.sync_rtc_to(peer, k, false);
        }
    }

    /// The selected copy of `k` rewritten for `peer`, or `None`. Policy is
    /// bypassed (accept-all); the next hop is always our session address.
    fn advertise_rtc(&self, peer: IpAddr, k: &RtcKey, r: &RibRoute) -> Option<AdvertisedRtc> {
        let outbox = self.peer_outboxes.get(&peer)?;
        if !outbox.negotiated_afs.contains(&AddressFamily::RtConstraint) {
            return None;
        }
        let mut route = build_advertisement(
            IpNet::V4(Ipv4Net::default()),
            r,
            peer,
            outbox,
            self.local_asn,
            self.source_is_rr_client(r),
            self.cluster_id,
            Some((AddressFamily::RtConstraint, &nos_rpl::ACCEPT_ALL, None)),
        )?;
        route.next_hop = outbox.local_addr?;
        Some(AdvertisedRtc { key: *k, route })
    }

    /// Brings `peer` in line with `k`, diffed against what it was last sent;
    /// `force` re-sends even an unchanged state (a lost update).
    pub(super) fn sync_rtc_to(&mut self, peer: IpAddr, k: &RtcKey, force: bool) {
        let adv = self
            .rtc_loc
            .get(k)
            .and_then(|(_, r)| self.advertise_rtc(peer, k, r));
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        let sent = self.rtc_adj_rib_out.entry(peer).or_default();
        match adv {
            Some(adv) if force || sent.get(k) != Some(&adv) => {
                info!(peer = %peer, origin_as = k.origin_as, rt = %rt_text(k), prefix_len = k.bits, next_hop = %adv.route.next_hop, "rtc membership advertised");
                sent.insert(*k, adv.clone());
                outbox.tx.send(OutboundUpdate::AnnounceRtc(adv));
            }
            Some(_) => {}
            None => {
                let was_sent = sent.remove(k).is_some();
                if was_sent
                    || (force && outbox.negotiated_afs.contains(&AddressFamily::RtConstraint))
                {
                    info!(peer = %peer, origin_as = k.origin_as, rt = %rt_text(k), prefix_len = k.bits, "rtc membership advertisement withdrawn");
                    outbox.tx.send(OutboundUpdate::WithdrawRtc(*k));
                }
            }
        }
    }

    /// Initial advertisement to a just-established peer (`initial_update`):
    /// every selected membership route, then the family's End-of-RIB (RFC
    /// 4684 section 6: sent whenever the family is negotiated, graceful
    /// restart or not), ahead of the VPN/EVPN dump it unlocks.
    pub(super) fn announce_rtc_to(&mut self, peer: IpAddr) {
        self.rtc_adj_rib_out.remove(&peer);
        let keys: Vec<RtcKey> = self.rtc_loc.keys().copied().collect();
        for k in keys {
            self.sync_rtc_to(peer, &k, false);
        }
        if let Some(o) = self
            .peer_outboxes
            .get(&peer)
            .filter(|o| o.negotiated_afs.contains(&AddressFamily::RtConstraint))
        {
            o.tx.send(OutboundUpdate::EndOfRib(AddressFamily::RtConstraint));
        }
    }

    /// Route refresh (RFC 2918) of the family: re-sends what `peer` was last
    /// sent.
    pub(super) fn resend_rtc(&self, peer: IpAddr) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        for adv in self
            .rtc_adj_rib_out
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::values)
        {
            outbox.tx.send(OutboundUpdate::AnnounceRtc(adv.clone()));
        }
    }

    /// Re-syncs `peer` for every selected VPN route one of `keys` covers.
    fn resync_vpn(&mut self, peer: IpAddr, keys: &[RtcKey]) {
        let touched: Vec<_> = self
            .vpn_loc
            .iter()
            .filter(|(_, (_, _, r))| {
                keys.iter()
                    .any(|n| n.covers_any(&r.route.extended_communities))
            })
            .map(|(k, _)| *k)
            .collect();
        for k in touched {
            self.sync_vpn_to(peer, &k, false);
        }
    }

    /// Re-syncs `peer` for every selected SAFI 134 rule one of `keys` covers.
    fn resync_vpn_flow(&mut self, peer: IpAddr, keys: &[RtcKey]) {
        let touched: Vec<_> = self
            .vpn_flow_loc
            .iter()
            .filter(|(_, (_, _, r))| {
                keys.iter()
                    .any(|n| n.covers_any(&r.attributes.extended_communities))
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in touched {
            self.sync_vpn_flow_to(peer, &k, false);
        }
    }

    /// Paths held from `peer`, for the RFC 4486 count.
    pub(super) fn accepted_rtc(&self, peer: IpAddr) -> u32 {
        u32::try_from(self.rtc_adj_rib_in.get(&peer).map_or(0, HashMap::len)).unwrap_or(u32::MAX)
    }

    /// Whether VPN route `r` is held back from `peer` by RT-Constraint.
    pub(super) fn rtc_holds(&self, peer: IpAddr, ext_communities: &[u64]) -> bool {
        self.peer_outboxes
            .get(&peer)
            .and_then(|o| o.rtc_interest.as_ref())
            .is_some_and(|i| !i.permits(ext_communities))
    }
}

fn rt_text(k: &RtcKey) -> String {
    if k.bits == 0 {
        "default".to_string()
    } else {
        format_ext_community(k.rt)
    }
}

#[cfg(test)]
pub(super) fn rt_text_for_tests(k: &RtcKey) -> String {
    rt_text(k)
}

/// Logged by `advertise_vpn` when RT-Constraint holds a route back.
pub(super) fn log_held(peer: IpAddr, rd: &str, prefix: IpNet) {
    debug!(peer = %peer, rd = %rd, prefix = %prefix, "vpn route held by rt-constraint");
}
