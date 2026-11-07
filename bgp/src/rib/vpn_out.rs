//! VPN-IPv4/VPN-IPv6 (RFC 4364/4659, SAFI 128) Adj-RIB-In, best path and
//! reflection (#578). Every received path is kept per (RD, prefix), whatever
//! its Route Targets (a reflector holds them all; RTs only gate VRF import,
//! #579). Different RDs never compete (RFC 4364 section 4.3.5): the best
//! path is picked per full key with the unicast decision process
//! (`select_vpn`) and re-advertised with the unicast `build_advertisement`
//! rules (split horizon, RFC 4456 reflection, eBGP prepend, export policy).
//! Labels and RD pass through unchanged. Everything is per key: a change to
//! one path re-selects that key only.
//!
//! VRF export (#580): `nos-ribd` pushes each VRF's routes (`apply_vpn_prefixes`)
//! as `Local` candidates of the same selection, advertised next-hop-self
//! with the VRF's own label (RFC 4364 section 4.3.2).

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use nos_proto::AddressFamily;
use nos_rpl::CompiledPolicy;

use nos_proto::{VpnPrefix, VpnPrefixUpdate};

use super::{
    apply_policy, best_path, build_advertisement, decision, info, message, warn, AdvertisedRoute,
    BgpRib, Candidate, OutboundUpdate, PolicyPeer, RibRoute, RouteOrigin, VpnRoute,
};
use crate::vpn::{format_rd, VpnKey};

/// One VPN path rewritten for one peer.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertisedVpn {
    pub key: VpnKey<IpNet>,
    pub labels: Vec<u32>,
    /// The attributes and next hop; its `prefix` is `key.1`, `path_id` unused.
    pub route: AdvertisedRoute,
}

/// The family of a VPN prefix (an AFI 2 batch always carries IPv6).
pub(crate) fn vpn_family(prefix: IpNet) -> AddressFamily {
    match prefix {
        IpNet::V4(_) => AddressFamily::Vpnv4Unicast,
        IpNet::V6(_) => AddressFamily::Vpnv6Unicast,
    }
}

/// Stores one `MP_REACH_NLRI` batch's VPN paths in a peer's VPN Adj-RIB-In
/// through the peer-group import policy (the customer prefix is
/// `this.prefix`; a reject drops a held copy), logging only new or changed
/// paths, and returns their keys for selection. An unchanged path keeps its
/// age (decision step 8).
#[allow(clippy::too_many_arguments)]
fn learn_batch(
    table: &mut HashMap<VpnKey<IpNet>, VpnRoute>,
    mut retain: Option<&mut HashMap<VpnKey<IpNet>, VpnRoute>>,
    mp: &message::MpReachNlri,
    base: &RibRoute,
    peer: (IpAddr, u32),
    import_policy: &CompiledPolicy,
    bmp: Option<&crate::bmp::Hub>,
    stats: &mut super::PeerStats,
) -> Vec<VpnKey<IpNet>> {
    let from = peer.0;
    let mut keys = Vec::with_capacity(mp.vpn.len());
    for n in &mp.vpn {
        let k = (n.rd, n.prefix);
        keys.push(k);
        let candidate = RibRoute {
            next_hop: Some(mp.next_hop),
            ..base.clone()
        };
        // The policy rewrites the held copy: keep the raw one.
        if let Some(r) = retain.as_deref_mut() {
            r.insert(
                k,
                VpnRoute {
                    labels: n.labels.clone(),
                    route: candidate.clone(),
                },
            );
        }
        let Some(mut route) = apply_policy(
            n.prefix,
            candidate,
            import_policy,
            Some(PolicyPeer::new(peer.0, peer.1)),
            Some(n.rd),
        ) else {
            super::stats::bump(&mut stats.rejected, 1);
            if table.remove(&k).is_some()
                && let Some(h) = bmp
            {
                h.vpn_post(from, &k, None);
            }
            warn!(peer = %from, family = %vpn_family(n.prefix), rd = %format_rd(&n.rd), prefix = %n.prefix, "vpn route rejected by import policy");
            continue;
        };
        if let Some(old) = table.get(&k)
            && old.labels == n.labels
            && (RibRoute {
                received_at: old.route.received_at,
                ..route.clone()
            }) == old.route
        {
            route.received_at = old.route.received_at;
        }
        let new = VpnRoute {
            labels: n.labels.clone(),
            route,
        };
        if table.insert(k, new.clone()) != Some(new.clone()) {
            if let Some(h) = bmp {
                h.vpn_post(from, &k, Some(&new));
            }
            info!(peer = %from, family = %vpn_family(n.prefix), rd = %format_rd(&n.rd), prefix = %n.prefix, labels = ?n.labels, next_hop = %mp.next_hop, "vpn route learned");
        }
    }
    keys
}

impl BgpRib {
    /// `learn_batch` over every VPN batch of `update` (`base`: its route
    /// before the next hop), then selection of each key. A batch of a
    /// family the session did not negotiate is ignored, as for Flowspec (a
    /// test RIB without an outbox has no session to check against).
    pub(super) fn learn_vpn(
        &mut self,
        update: &message::UpdateMessage,
        base: &RibRoute,
        peer: (IpAddr, u32),
        import_policy: &CompiledPolicy,
    ) {
        let from = peer.0;
        let mut keys = Vec::new();
        for mp in &update.mp_reach {
            let Some(n) = mp.vpn.first() else {
                continue;
            };
            let family = vpn_family(n.prefix);
            if self
                .peer_outboxes
                .get(&from)
                .is_some_and(|o| !o.negotiated_afs.contains(&family))
            {
                warn!(peer = %from, family = %family, "vpn routes for a family not negotiated, ignored");
                continue;
            }
            let table = self.vpn_adj_rib_in.entry(from).or_default();
            let retain = self.retained.vpn_slot(from);
            let bmp = super::bmp_tap::tap(self.bmp.as_ref());
            keys.extend(learn_batch(
                table,
                retain,
                mp,
                base,
                peer,
                import_policy,
                bmp,
                self.peer_stats.entry(from).or_default(),
            ));
        }
        for k in keys {
            self.select_vpn(&k);
        }
    }

    /// Removes path `k` from `peer`'s VPN Adj-RIB-In (logged) and re-selects
    /// it.
    pub(super) fn drop_vpn(&mut self, peer: IpAddr, k: &VpnKey<IpNet>) -> bool {
        // A path the policy rejected is not held, but its raw copy is.
        self.retained.take_vpn(peer, k);
        let removed = self
            .vpn_adj_rib_in
            .get_mut(&peer)
            .and_then(|t| t.remove(k))
            .is_some();
        if removed {
            info!(peer = %peer, family = %vpn_family(k.1), rd = %format_rd(&k.0), prefix = %k.1, "vpn route withdrawn");
            if let Some(h) = super::bmp_tap::tap(self.bmp.as_ref()) {
                h.vpn_post(peer, k, None);
            }
            self.select_vpn(k);
        }
        removed
    }

    /// Re-decides `k`'s best path among every peer's copy and the local VRF
    /// export of it and, when it changed, propagates it.
    // ponytail: no next-hop feasibility, and an IGP cost change does not
    // re-select.
    pub(super) fn select_vpn(&mut self, k: &VpnKey<IpNet>) {
        let local = self.local_vpn(k).cloned();
        let candidates: Vec<Candidate> = self
            .vpn_adj_rib_in
            .values()
            .filter_map(|t| t.get(k))
            .chain(local.as_ref())
            .map(|r| (r.route.clone(), 0))
            .collect();
        let new = best_path(&candidates, &self.igp).and_then(|b| match b.origin {
            RouteOrigin::Peer(p) => Some((b.origin, self.vpn_adj_rib_in.get(&p)?.get(k)?.clone())),
            RouteOrigin::Local => Some((b.origin, local.clone()?)),
        });
        if self.vpn_loc.get(k) == new.as_ref() {
            return;
        }
        match new {
            Some(n) => self.vpn_loc.insert(*k, n),
            None => self.vpn_loc.remove(k),
        };
        if self.deferring() {
            return; // the deferral's end sends the initial update
        }
        let peers: Vec<IpAddr> = self.peer_outboxes.keys().copied().collect();
        for peer in peers {
            self.sync_vpn_to(peer, k, false);
        }
    }

    /// The local export of `k`: the first table (by name) holding it, as two
    /// VRFs sharing an RD is a misconfiguration.
    fn local_vpn(&self, k: &VpnKey<IpNet>) -> Option<&VpnRoute> {
        let mut tables: Vec<&String> = self.vpn_local.keys().collect();
        tables.sort();
        tables.into_iter().find_map(|t| self.vpn_local[t].get(k))
    }

    /// How many VPN export routes `nos-ribd` pushed are held, across tables.
    pub fn vpn_local_len(&self) -> usize {
        self.vpn_local.values().map(HashMap::len).sum()
    }

    /// Applies one `RedistributeVpnPrefixes` push from `table`'s `nos-ribd`
    /// and re-selects every key it touched.
    pub fn apply_vpn_prefixes(&mut self, table: &str, update: VpnPrefixUpdate) {
        // Staged per table by `server.rs`'s `VpnStaging` (#791); a stray part
        // creates nothing.
        if matches!(update, VpnPrefixUpdate::FullPart(_)) {
            return;
        }
        let local = |r: VpnPrefix| {
            let mut route = decision::redistributed_route();
            route.extended_communities = r.ext_communities;
            (
                (r.rd, r.prefix),
                VpnRoute {
                    labels: r.labels,
                    route,
                },
            )
        };
        let slot = self.vpn_local.entry(table.to_string()).or_default();
        let touched: Vec<VpnKey<IpNet>> = match update {
            VpnPrefixUpdate::Full(routes) => {
                let new: HashMap<_, _> = routes.into_iter().map(local).collect();
                let old = std::mem::replace(slot, new);
                old.into_keys().chain(slot.keys().copied()).collect()
            }
            VpnPrefixUpdate::Add(r) => {
                let (k, mut v) = local(r);
                // An unchanged re-push keeps its age (decision step 8).
                if let Some(old) = slot.get(&k)
                    && old.labels == v.labels
                    && old.route.extended_communities == v.route.extended_communities
                {
                    v.route.received_at = old.route.received_at;
                }
                slot.insert(k, v);
                vec![k]
            }
            VpnPrefixUpdate::Remove(rd, prefix) => {
                slot.remove(&(rd, prefix));
                vec![(rd, prefix)]
            }
            VpnPrefixUpdate::FullPart(_) => unreachable!("returned above"),
        };
        for k in touched {
            self.select_vpn(&k);
        }
    }

    /// The selected copy of `k` rewritten for `peer`, or `None` when `peer`
    /// must not have it.
    fn advertise_vpn(
        &self,
        peer: IpAddr,
        k: &VpnKey<IpNet>,
        r: &VpnRoute,
    ) -> Option<AdvertisedVpn> {
        let outbox = self.peer_outboxes.get(&peer)?;
        if self.rtc_holds(peer, &r.route.extended_communities) {
            super::rtc::log_held(peer, &format_rd(&k.0), k.1);
            return None;
        }
        let mut route = build_advertisement(
            k.1,
            &r.route,
            peer,
            outbox,
            self.local_asn,
            self.source_is_rr_client(&r.route),
            self.cluster_id,
            Some((vpn_family(k.1), outbox.export_policy.as_ref(), Some(k.0))),
        )?;
        // A local export is always next-hop-self (its label is ours; the
        // codec sends an IPv4 one IPv4-mapped in a VPNv6 batch). A reflected
        // path keeps its next hop so its label stays valid.
        route.next_hop = match r.route.origin {
            RouteOrigin::Local => outbox.local_addr?,
            RouteOrigin::Peer(_) => r.route.next_hop?,
        };
        Some(AdvertisedVpn {
            key: *k,
            labels: r.labels.clone(),
            route,
        })
    }

    /// Brings `peer` in line with `k`, diffed against what it was last sent;
    /// `force` re-sends even an unchanged state (a lost update).
    pub(super) fn sync_vpn_to(&mut self, peer: IpAddr, k: &VpnKey<IpNet>, force: bool) {
        let adv = self
            .vpn_loc
            .get(k)
            .and_then(|(_, r)| self.advertise_vpn(peer, k, r));
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        let family = vpn_family(k.1);
        let sent = self.vpn_adj_rib_out.entry(peer).or_default();
        match adv {
            Some(adv) if force || sent.get(k) != Some(&adv) => {
                info!(peer = %peer, family = %family, rd = %format_rd(&k.0), prefix = %k.1, labels = ?adv.labels, next_hop = %adv.route.next_hop, "vpn route advertised");
                sent.insert(*k, adv.clone());
                outbox.tx.send(OutboundUpdate::AnnounceVpn(adv));
            }
            Some(_) => {}
            None => {
                let was_sent = sent.remove(k).is_some();
                if was_sent || (force && outbox.negotiated_afs.contains(&family)) {
                    info!(peer = %peer, family = %family, rd = %format_rd(&k.0), prefix = %k.1, "vpn route advertisement withdrawn");
                    outbox.tx.send(OutboundUpdate::WithdrawVpn(*k));
                }
            }
        }
    }

    /// Initial advertisement of every selected VPN path to a just-established
    /// peer (`initial_update`).
    pub(super) fn announce_vpn_to(&mut self, peer: IpAddr) {
        self.vpn_adj_rib_out.remove(&peer);
        let keys: Vec<VpnKey<IpNet>> = self.vpn_loc.keys().copied().collect();
        for k in keys {
            self.sync_vpn_to(peer, &k, false);
        }
    }

    /// Route refresh (RFC 2918) of a VPN family: re-sends what `peer` was
    /// last sent of it.
    pub(super) fn resend_vpn(&self, peer: IpAddr, family: AddressFamily) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        for adv in self
            .vpn_adj_rib_out
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::values)
            .filter(|a| vpn_family(a.key.1) == family)
        {
            outbox.tx.send(OutboundUpdate::AnnounceVpn(adv.clone()));
        }
    }

    /// RFC 7313 `BoRR` (or a graceful restart) for a VPN family: every path
    /// of `family` held from `peer` becomes stale until re-announced.
    pub(super) fn mark_vpn_stale(&mut self, peer: IpAddr, family: AddressFamily) {
        let Some(table) = self.vpn_adj_rib_in.get(&peer) else {
            return;
        };
        self.vpn_stale
            .entry(peer)
            .or_default()
            .extend(table.keys().filter(|k| vpn_family(k.1) == family));
    }

    /// Purges `peer`'s stale VPN paths of `family`; returns how many.
    pub(super) fn purge_stale_vpn(&mut self, peer: IpAddr, family: AddressFamily) -> usize {
        let Some(set) = self.vpn_stale.get_mut(&peer) else {
            return 0;
        };
        let keys: Vec<_> = set
            .iter()
            .filter(|k| vpn_family(k.1) == family)
            .copied()
            .collect();
        set.retain(|k| vpn_family(k.1) != family);
        keys.iter().filter(|k| self.drop_vpn(peer, k)).count()
    }

    /// Every received VPN path of `family`, sorted by peer, RD, prefix, each
    /// with whether it is the selected one.
    pub fn vpn_routes(
        &self,
        family: AddressFamily,
    ) -> Vec<(IpAddr, &VpnKey<IpNet>, &VpnRoute, bool)> {
        let mut out: Vec<_> = self
            .vpn_adj_rib_in
            .iter()
            .flat_map(|(peer, t)| t.iter().map(move |(k, r)| (*peer, k, r)))
            .filter(|(_, k, _)| vpn_family(k.1) == family)
            .map(|(peer, k, r)| {
                let best = self
                    .vpn_loc
                    .get(k)
                    .is_some_and(|(o, _)| *o == RouteOrigin::Peer(peer));
                (peer, k, r, best)
            })
            .collect();
        out.sort_by_key(|(peer, k, ..)| (*peer, k.0, k.1));
        out
    }

    /// The sort key of every received VPN path of `family` (only those of
    /// RD `rd` when set; `Some(None)`, an unparsable RD, matches nothing),
    /// sorted: the snapshot a paged `show bgp vpnv4|vpnv6` walk searches
    /// (#723). Keys only.
    pub fn vpn_keys(
        &self,
        family: AddressFamily,
        rd: Option<Option<[u8; 8]>>,
    ) -> Vec<nos_proto::VpnRouteCursor> {
        let mut keys: Vec<_> = self
            .vpn_adj_rib_in
            .iter()
            .flat_map(|(peer, t)| {
                t.keys().map(move |k| nos_proto::VpnRouteCursor {
                    peer: *peer,
                    rd: k.0,
                    prefix: k.1,
                })
            })
            .filter(|c| vpn_family(c.prefix) == family)
            .filter(|c| rd.is_none_or(|want| want == Some(c.rd)))
            .collect();
        keys.sort_unstable();
        keys
    }

    /// The path for one `vpn_keys` key, with whether it is the selected one;
    /// `None` when it is gone.
    pub fn vpn_at(
        &self,
        c: &nos_proto::VpnRouteCursor,
    ) -> Option<(&VpnKey<IpNet>, &VpnRoute, bool)> {
        let (k, r) = self
            .vpn_adj_rib_in
            .get(&c.peer)?
            .get_key_value(&(c.rd, c.prefix))?;
        let best = self
            .vpn_loc
            .get(k)
            .is_some_and(|(o, _)| *o == RouteOrigin::Peer(c.peer));
        Some((k, r, best))
    }

    /// VPN paths held from `peer`, `[vpnv4, vpnv6]` (RFC 4486 counts).
    pub(super) fn accepted_vpn(&self, peer: IpAddr) -> [u32; 2] {
        let mut n = [0u32; 2];
        for k in self
            .vpn_adj_rib_in
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::keys)
        {
            n[usize::from(k.1.addr().is_ipv6())] += 1;
        }
        n
    }
}
