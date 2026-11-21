//! VPN Flowspec (RFC 8955 section 8, SAFI 134) receive side (#1084).
//!
//! The rules live in `vpn_flow_adj_rib_in` keyed `(family, (RD, rule))`
//! (`VpnKey<FlowSpec>`, the SAFI 128 RD/RT core). A rule is *imported* into
//! every VRF whose import Route Targets match one of its RTs (the Site of
//! Origin blocks as for unicast); one with no match stays here and is in no
//! VRF view. Validation is per VRF: the "unicast" side of RFC 8955 section 6
//! is the SAFI 128 paths imported into that VRF (`vrf_unicast`).
//!
//! Selection, import/export policy and propagation are #1085 (below); the
//! ACL push is #1086.
// ponytail: a VPN unicast change rescans the held rules for overlap
// (`revalidate_vpn_flows_around`) and each revalidation scans the SAFI 128
// Adj-RIB-In once, O(paths) per rule; a per-VRF `FlowIndexes` (as for
// SAFI 133) once it shows in `tools/bench-bgp.sh`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use ipnet::IpNet;
use nos_proto::AddressFamily;

use super::flowspec_out::{flow_rib_route, import_flow, AdvertisedFlowspec};
use super::flowspec_validate::{dest_of, validate, FlowValidity, Unicast};
use super::{
    best_index, debug, info, rank, warn, BgpRib, Candidate, FlowspecRoute, OutboundUpdate,
    RouteOrigin, VpnFlowCopy, VpnFlowKey, VpnRoute,
};
use crate::flowspec::FlowSpec;
use crate::message::{self, PathAttributes, UpdateMessage};
use crate::vpn::format_rd;

/// The SAFI 134 family of an MP batch's AFI.
pub(super) fn vpn_flow_family(afi: u16) -> Option<AddressFamily> {
    match afi {
        message::AFI_IPV4 => Some(AddressFamily::Vpnv4Flowspec),
        message::AFI_IPV6 => Some(AddressFamily::Vpnv6Flowspec),
        _ => None,
    }
}

/// One received UPDATE's per-peer context.
pub(super) struct VpnFlowRx<'a> {
    pub from: IpAddr,
    pub attributes: &'a PathAttributes,
    pub learned_via_ibgp: bool,
    pub router_id: Ipv4Addr,
}

/// The imported SAFI 128 paths of one VRF, by prefix.
type VrfUnicast<'a> = HashMap<IpNet, Vec<&'a VpnRoute>>;

impl BgpRib {
    /// Copies (one per rule and path id) held from `peer` of SAFI 134,
    /// `[vpnv4, vpnv6]`: each counts as one route for maximum-prefix.
    pub(super) fn accepted_vpn_flow(&self, peer: IpAddr) -> [u32; 2] {
        let mut n = [0u32; 2];
        for ((family, _), _) in self
            .vpn_flow_adj_rib_in
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::keys)
        {
            n[usize::from(*family == AddressFamily::Vpnv6Flowspec)] += 1;
        }
        n
    }

    /// Stores every SAFI 134 batch of `update` and validates each rule in
    /// the VRFs that import it. A batch of a family the session did not
    /// negotiate is ignored (a test RIB without an outbox has no session to
    /// check against).
    pub(super) fn learn_flowspec_vpn(&mut self, update: &UpdateMessage, rx: &VpnFlowRx<'_>) {
        let from = rx.from;
        let mut copies: Vec<VpnFlowCopy> = Vec::new();
        for mp in update
            .mp_reach
            .iter()
            .filter(|m| !m.flowspec_vpn.is_empty())
        {
            let Some(family) = vpn_flow_family(mp.afi) else {
                continue;
            };
            if self
                .peer_outboxes
                .get(&from)
                .is_some_and(|o| !o.negotiated_afs.contains(&family))
            {
                warn!(peer = %from, family = %family, "vpn flowspec routes for a family not negotiated, ignored");
                continue;
            }
            let import = self.flowspec_import.get(&from).cloned();
            let peer_as = self.peer_asns.get(&from).copied().unwrap_or(0);
            let confed = self.confed_peers.contains(&from);
            let mut retain = self.retained.vpn_flow_slot(from);
            let table = self.vpn_flow_adj_rib_in.entry(from).or_default();
            for (i, n) in mp.flowspec_vpn.iter().enumerate() {
                let k: VpnFlowKey = (family, (n.rd, n.flow.clone()));
                let mut route = FlowspecRoute {
                    family,
                    nlri: n.flow.clone(),
                    attributes: rx.attributes.clone(),
                    learned_via_ibgp: rx.learned_via_ibgp,
                    router_id: rx.router_id,
                    received_at: Instant::now(),
                    validity: None,
                };
                // A copy is (rule, path id); a re-announcement of one replaces it.
                let id = mp.nlri_path_ids.get(i).copied().unwrap_or(0);
                let c: VpnFlowCopy = (k, id);
                copies.push(c.clone());
                // The policy rewrites the held copy: keep the raw one.
                if let Some(r) = retain.as_deref_mut() {
                    r.insert(c.clone(), route.clone());
                }
                if let Some(p) = &import
                    && !import_flow(p, &mut route, from, peer_as, confed)
                {
                    super::stats::bump(&mut self.peer_stats.entry(from).or_default().rejected, 1);
                    if table.remove(&c).is_some()
                        && let Some(h) = super::bmp_tap::tap(self.bmp.as_ref())
                    {
                        h.vpn_flow_post(from, &c, None);
                    }
                    warn!(peer = %from, family = %family, rd = %format_rd(&n.rd), route = %n.flow, "flowspec route rejected by import policy");
                    continue;
                }
                if let Some(old) = table.get(&c)
                    && old.attributes == route.attributes
                {
                    route.received_at = old.received_at;
                }
                if table.insert(c.clone(), route.clone()) != Some(route.clone()) {
                    if let Some(h) = super::bmp_tap::tap(self.bmp.as_ref()) {
                        h.vpn_flow_post(from, &c, Some(&route));
                    }
                    if id == 0 {
                        info!(peer = %from, family = %family, rd = %format_rd(&n.rd), route = %n.flow, "flowspec route learned");
                    } else {
                        info!(peer = %from, family = %family, rd = %format_rd(&n.rd), route = %n.flow, path_id = id, "flowspec route learned");
                    }
                }
            }
        }
        for c in copies {
            self.revalidate_vpn_flow(from, &c);
        }
    }

    /// Removes copy `c` from `peer`'s SAFI 134 Adj-RIB-In (logged).
    pub(super) fn drop_vpn_flow(&mut self, peer: IpAddr, c: &VpnFlowCopy) -> bool {
        let k = &c.0;
        self.vpn_flow_validity.remove(&(peer, c.clone()));
        self.retained.take_vpn_flow(peer, c);
        let removed = self
            .vpn_flow_adj_rib_in
            .get_mut(&peer)
            .and_then(|t| t.remove(c))
            .is_some();
        if removed {
            if c.1 == 0 {
                info!(peer = %peer, family = %k.0, rd = %format_rd(&(k.1).0), route = %(k.1).1, "flowspec route withdrawn");
            } else {
                info!(peer = %peer, family = %k.0, rd = %format_rd(&(k.1).0), route = %(k.1).1, path_id = c.1, "flowspec route withdrawn");
            }
            if let Some(h) = super::bmp_tap::tap(self.bmp.as_ref()) {
                h.vpn_flow_post(peer, c, None);
            }
        }
        self.select_vpn_flow(k);
        removed
    }

    /// Drops everything `peer` sent in SAFI 134 (session down).
    pub(super) fn drop_peer_vpn_flows(&mut self, peer: IpAddr) {
        let keys: Vec<VpnFlowCopy> = self
            .vpn_flow_adj_rib_in
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::keys)
            .cloned()
            .collect();
        for k in keys {
            self.drop_vpn_flow(peer, &k);
        }
        self.vpn_flow_adj_rib_in.remove(&peer);
    }

    /// The SAFI 128 paths a VRF imports (RT match, no own Site of Origin, a
    /// feasible next hop), by prefix, the RD stripped as for unicast import.
    fn vrf_unicast(&self, table: &str) -> VrfUnicast<'_> {
        let mut out: VrfUnicast<'_> = HashMap::new();
        for (k, r) in self
            .vpn_adj_rib_in
            .values()
            .flatten()
            .flat_map(|(k, ids)| ids.values().map(move |r| (k, r)))
        {
            if r.route.next_hop.is_some()
                && self.next_hop_feasible(r.route.next_hop)
                && self
                    .vpn_vrfs
                    .import_targets(&r.route.extended_communities)
                    .contains(&table)
            {
                out.entry(k.1).or_default().push(r);
            }
        }
        out
    }

    /// The best imported SAFI 128 path for exactly `net`, as `validate` sees it.
    fn vrf_best(&self, cands: &VrfUnicast<'_>, net: IpNet) -> Option<Unicast> {
        let paths = cands.get(&net)?;
        let scored: Vec<Candidate> = paths.iter().map(|r| (r.route.clone(), 0)).collect();
        let b = &scored[best_index(&scored, &self.igp)?].0;
        Some(Unicast {
            originator: match b.origin {
                RouteOrigin::Peer(p) => Some(b.originator_id.map_or(p, IpAddr::V4)),
                RouteOrigin::Local => None,
            },
            neighbour_as: self.neighbour_as_of(b.origin, &b.as_path),
            leftmost_as: b.as_path.neighbor_as(),
        })
    }

    /// Re-validates rule `k` of `peer` in every VRF that imports it (and
    /// forgets the VRFs that no longer do), logging each change.
    pub(super) fn revalidate_vpn_flow(&mut self, peer: IpAddr, c: &VpnFlowCopy) {
        let k = &c.0;
        let Some(r) = self.vpn_flow_adj_rib_in.get(&peer).and_then(|t| t.get(c)) else {
            // Rejected by the import policy: no copy, so nothing to select.
            self.vpn_flow_validity.remove(&(peer, c.clone()));
            self.select_vpn_flow(k);
            return;
        };
        let tables: Vec<String> = self
            .vpn_vrfs
            .import_targets(&r.attributes.extended_communities)
            .into_iter()
            .map(str::to_string)
            .collect();
        let (flow, mode) = self.flow_side(peer, r);
        let mut new: HashMap<String, FlowValidity> = HashMap::new();
        for t in tables {
            let cands = self.vrf_unicast(&t);
            let more_specific = |net: IpNet| {
                cands
                    .iter()
                    .filter(|(p, _)| p.prefix_len() > net.prefix_len() && net.contains(&p.addr()))
                    .flat_map(|(_, rs)| rs.iter())
                    .map(|r| self.neighbour_as_of(r.route.origin, &r.route.as_path))
                    .collect()
            };
            let v = validate(&flow, mode, |net| self.vrf_best(&cands, net), more_specific);
            new.insert(t, v);
        }
        let old = self.vpn_flow_validity.get(&(peer, c.clone()));
        let mut changed: Vec<(&String, &FlowValidity)> = new
            .iter()
            .filter(|(t, v)| old.and_then(|o| o.get(*t)) != Some(*v))
            .collect();
        changed.sort_by_key(|(t, _)| *t);
        for (table, v) in changed {
            if c.1 == 0 {
                info!(peer = %peer, family = %k.0, rd = %format_rd(&(k.1).0), table = %table, flow = %(k.1).1, validity = %v, "flowspec validity changed");
            } else {
                info!(peer = %peer, family = %k.0, rd = %format_rd(&(k.1).0), table = %table, flow = %(k.1).1, validity = %v, path_id = c.1, "flowspec validity changed");
            }
        }
        self.vpn_flow_visits += 1;
        if new.is_empty() {
            self.vpn_flow_validity.remove(&(peer, c.clone()));
        } else {
            self.vpn_flow_validity.insert((peer, c.clone()), new);
        }
        // A validity flip (or the first validation) decides the candidates.
        self.select_vpn_flow(k);
    }

    /// Valid in at least one VRF that imports it: a best-path candidate
    /// (RFC 8955 section 6 validation, per VRF as RFC 4364 distributes it).
    fn vpn_flow_usable(&self, peer: IpAddr, c: &VpnFlowCopy) -> bool {
        self.vpn_flow_validity
            .get(&(peer, c.clone()))
            .is_some_and(|m| m.values().any(|v| *v == FlowValidity::Valid))
    }

    /// The (peer, path id) whose copy of `k` is best among the copies `keep`
    /// accepts (standard decision, no IGP step: there is no next hop; step 10
    /// compares the path id).
    // ponytail: scans every held copy per call (the copies of a rule share no
    // index); O(held copies), an index by rule if `tools/bench-bgp.sh` shows it.
    fn best_vpn_flow_copy(
        &self,
        k: &VpnFlowKey,
        keep: impl Fn(IpAddr, &VpnFlowCopy) -> bool,
    ) -> Option<(IpAddr, u32)> {
        let mut who = Vec::new();
        let mut candidates: Vec<Candidate> = Vec::new();
        for (p, t) in &self.vpn_flow_adj_rib_in {
            for (c, r) in t.iter().filter(|(c, _)| c.0 == *k && keep(*p, c)) {
                who.push((*p, c.1));
                candidates.push((flow_rib_route(*p, r, self.confed_peers.contains(p)), c.1));
            }
        }
        best_index(&candidates, &HashMap::new()).map(|i| who[i])
    }

    /// Re-decides rule `k`'s best path among the valid, imported copies every
    /// peer holds (`vpn_flow_loc`, the Loc-RIB winner BMP shows) and re-syncs
    /// every peer: the advertised set is the per-VRF winners
    /// (`vpn_flow_candidates`), so it can change with `vpn_flow_loc` unchanged.
    // ponytail: every selection re-syncs every peer (a diff, no message when
    // nothing changed); O(peers x copies of k), gate on a changed candidate
    // set if `tools/bench-bgp.sh` shows it.
    pub(super) fn select_vpn_flow(&mut self, k: &VpnFlowKey) {
        let new = self
            .best_vpn_flow_copy(k, |p, c| self.vpn_flow_usable(p, c))
            .and_then(|(p, id)| {
                let r = self.vpn_flow_adj_rib_in.get(&p)?.get(&(k.clone(), id))?;
                Some((p, id, r.clone()))
            });
        match new {
            Some(n) => self.vpn_flow_loc.insert(k.clone(), n),
            None => self.vpn_flow_loc.remove(k),
        };
        if self.deferring() {
            return; // the deferral's end sends the initial update
        }
        let peers: Vec<IpAddr> = self.peer_outboxes.keys().copied().collect();
        for peer in peers {
            self.sync_vpn_flow_to(peer, k, false);
        }
    }

    /// The copies of `k` a peer may be sent, best first (owner D7, #1124): the
    /// winner of `k` in each local VRF table (the copies valid there, #1111),
    /// deduplicated, ranked by the decision process.
    fn vpn_flow_candidates(&self, k: &VpnFlowKey) -> Vec<(IpAddr, u32, &FlowspecRoute)> {
        let mut winners: Vec<(IpAddr, u32, &FlowspecRoute)> = Vec::new();
        for table in self.vpn_vrfs.tables() {
            let mut here: Vec<(IpAddr, u32, &FlowspecRoute)> = Vec::new();
            for (p, t) in &self.vpn_flow_adj_rib_in {
                for (c, r) in t.iter().filter(|(c, _)| c.0 == *k) {
                    let valid = self
                        .vpn_flow_validity
                        .get(&(*p, c.clone()))
                        .and_then(|m| m.get(table))
                        == Some(&FlowValidity::Valid);
                    if valid {
                        here.push((*p, c.1, r));
                    }
                }
            }
            let scored: Vec<Candidate> = here
                .iter()
                .map(|(p, id, r)| (flow_rib_route(*p, r, self.confed_peers.contains(p)), *id))
                .collect();
            if let Some(i) = best_index(&scored, &HashMap::new())
                && !winners.iter().any(|w| (w.0, w.1) == (here[i].0, here[i].1))
            {
                winners.push(here[i]);
            }
        }
        let scored: Vec<Candidate> = winners
            .iter()
            .map(|(p, id, r)| (flow_rib_route(*p, r, self.confed_peers.contains(p)), *id))
            .collect();
        rank(&scored, &HashMap::new())
            .into_iter()
            .filter_map(|(route, id)| {
                let RouteOrigin::Peer(p) = route.origin else {
                    return None;
                };
                winners.iter().find(|w| (w.0, w.1) == (p, id)).copied()
            })
            .collect()
    }

    /// Every rule with a held copy that satisfies `f`.
    pub(super) fn vpn_flow_keys_where(
        &self,
        f: impl Fn(&FlowspecRoute) -> bool,
    ) -> HashSet<VpnFlowKey> {
        self.vpn_flow_adj_rib_in
            .values()
            .flat_map(HashMap::iter)
            .filter(|(_, r)| f(r))
            .map(|(c, _)| c.0.clone())
            .collect()
    }

    /// The copy of `k` rewritten for `peer`, or `None` when `peer` must not
    /// have it (RT-Constraint of the copy, split horizon, reflection, policy).
    fn advertise_vpn_flow(
        &self,
        peer: IpAddr,
        k: &VpnFlowKey,
        src: IpAddr,
        r: &FlowspecRoute,
    ) -> Option<AdvertisedFlowspec> {
        if self.rtc_holds(peer, &r.attributes.extended_communities) {
            debug!(peer = %peer, family = %k.0, rd = %format_rd(&(k.1).0), route = %(k.1).1, "vpn flowspec route held by rt-constraint");
            return None;
        }
        self.advertise_flow(peer, src, r, Some((k.1).0))
    }

    /// Brings `peer` in line with rule `k`, diffed against what it was last
    /// sent; `force` re-sends even an unchanged state (a lost update). Toward
    /// an Add-Path peer that is the first `add_path_send_count` candidates it
    /// may have, each keeping its id while it stays selected; a copy leaving
    /// frees its id, which an entering copy takes (an RFC 7911 section 3
    /// implicit replace), else a fresh one from `vpn_flow_next_id`; ids still
    /// free are withdrawn. Any other peer gets the first candidate it may
    /// have (RFC 4271 implicit replace, a withdrawal only when none passes).
    pub(super) fn sync_vpn_flow_to(&mut self, peer: IpAddr, k: &VpnFlowKey, force: bool) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        let add_path = outbox.add_path_tx.contains(&k.0);
        let limit = if add_path {
            outbox.add_path_send_count.unwrap_or(usize::MAX)
        } else {
            1
        };
        let (tx, negotiated) = (outbox.tx.clone(), outbox.negotiated_afs.contains(&k.0));
        let mut selected: Vec<((IpAddr, u32), AdvertisedFlowspec)> = Vec::new();
        for (p, id, r) in self.vpn_flow_candidates(k) {
            if selected.len() >= limit {
                break;
            }
            if let Some(adv) = self.advertise_vpn_flow(peer, k, p, r) {
                selected.push(((p, id), adv));
            }
        }
        let mut sent = self
            .vpn_flow_adj_rib_out
            .entry(peer)
            .or_default()
            .remove(k)
            .unwrap_or_default();
        let had_sent = !sent.is_empty();
        let mut freed: Vec<u32> = Vec::new();
        sent.retain(|ck, a| {
            let keep = selected.iter().any(|(s, _)| s == ck);
            if !keep {
                freed.extend(a.route.path_id);
            }
            keep
        });
        freed.sort_unstable_by(|a, b| b.cmp(a)); // `pop` takes the lowest
        let (rd, fmt_rd) = ((k.1).0, format_rd(&(k.1).0));
        let announced = !selected.is_empty();
        for (ck, mut adv) in selected {
            let id = match sent.get(&ck) {
                Some(old) => old.route.path_id,
                None if add_path => Some(freed.pop().unwrap_or_else(|| {
                    // ponytail: never recycled once withdrawn, a u32 per
                    // (peer, key) is nowhere near exhausted.
                    let next = self.vpn_flow_next_id.entry((peer, k.clone())).or_insert(1);
                    *next += 1;
                    *next - 1
                })),
                None => None,
            };
            adv.route.path_id = id;
            if !force && sent.get(&ck) == Some(&adv) {
                continue;
            }
            match id {
                Some(id) => {
                    info!(peer = %peer, family = %k.0, rd = %fmt_rd, route = %(k.1).1, path_id = id, "flowspec route advertised");
                }
                None => {
                    info!(peer = %peer, family = %k.0, rd = %fmt_rd, route = %(k.1).1, "flowspec route advertised");
                }
            }
            sent.insert(ck, adv.clone());
            tx.send(OutboundUpdate::AnnounceVpnFlowspec(rd, adv));
        }
        if add_path {
            for id in freed.into_iter().rev() {
                info!(peer = %peer, family = %k.0, rd = %fmt_rd, route = %(k.1).1, path_id = id, "flowspec route advertisement withdrawn");
                tx.send(OutboundUpdate::WithdrawVpnFlowspec(k.clone(), Some(id)));
            }
        } else if !announced && (had_sent || (force && negotiated)) {
            info!(peer = %peer, family = %k.0, rd = %fmt_rd, route = %(k.1).1, "flowspec route advertisement withdrawn");
            tx.send(OutboundUpdate::WithdrawVpnFlowspec(k.clone(), None));
        }
        if !sent.is_empty() {
            self.vpn_flow_adj_rib_out
                .entry(peer)
                .or_default()
                .insert(k.clone(), sent);
        }
    }

    /// Initial advertisement of every held SAFI 134 rule to a just-established
    /// peer (`initial_update`).
    pub(super) fn announce_vpn_flow_to(&mut self, peer: IpAddr) {
        self.vpn_flow_adj_rib_out.remove(&peer);
        for k in self.vpn_flow_keys_where(|_| true) {
            self.sync_vpn_flow_to(peer, &k, false);
        }
    }

    /// Route refresh (RFC 2918) of a SAFI 134 family: re-sends what `peer`
    /// was last sent of it.
    pub(super) fn resend_vpn_flow(&self, peer: IpAddr, family: AddressFamily) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        for (k, adv) in self
            .vpn_flow_adj_rib_out
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::iter)
            .filter(|(k, _)| k.0 == family)
            .flat_map(|(k, m)| m.values().map(move |a| (k, a)))
        {
            outbox
                .tx
                .send(OutboundUpdate::AnnounceVpnFlowspec((k.1).0, adv.clone()));
        }
    }

    /// Purges `peer`'s stale SAFI 134 rules of `family` (a graceful
    /// restart's); returns how many.
    pub(super) fn purge_stale_vpn_flow(&mut self, peer: IpAddr, family: AddressFamily) -> usize {
        let Some(set) = self.vpn_flow_stale.get_mut(&peer) else {
            return 0;
        };
        let keys: Vec<_> = set.iter().filter(|c| (c.0).0 == family).cloned().collect();
        set.retain(|c| (c.0).0 != family);
        keys.iter().filter(|c| self.drop_vpn_flow(peer, c)).count()
    }

    /// A VPN unicast prefix changed: revalidate the held rules whose
    /// destination overlaps it (an ancestor, or a descendant).
    pub(super) fn revalidate_vpn_flows_around(&mut self, prefix: IpNet) {
        if self.vpn_flow_adj_rib_in.is_empty() {
            return;
        }
        let hit: Vec<(IpAddr, VpnFlowCopy)> = self
            .vpn_flow_adj_rib_in
            .iter()
            .flat_map(|(p, t)| t.iter().map(move |(k, r)| (*p, k, r)))
            .filter(|(_, _, r)| {
                dest_of(&r.nlri).is_some_and(|d| d.net.contains(&prefix) || prefix.contains(&d.net))
            })
            .map(|(p, k, _)| (p, k.clone()))
            .collect();
        for (p, k) in hit {
            self.revalidate_vpn_flow(p, &k);
        }
    }

    /// The copy of each VPN flow rule that `table` enforces (#1086, #1111,
    /// owner D7): per (RD, rule), the best path among every copy (any peer,
    /// any path id, #1126) valid in `table`, then the lowest RD per (family,
    /// rule), matching `best_import`'s tie-break. IPv4 first, RFC 8955
    /// section 5.1 order.
    // ponytail: computed on read, O(copies of each held rule) per table per
    // snapshot; a cache per table if `tools/bench-bgp.sh` shows it.
    fn vpn_flows_of(&self, table: &str) -> Vec<(&VpnFlowCopy, IpAddr, &FlowspecRoute)> {
        let mut best: HashMap<(AddressFamily, &FlowSpec), (&VpnFlowCopy, IpAddr, &FlowspecRoute)> =
            HashMap::new();
        let mut groups: HashMap<&VpnFlowKey, Vec<(&VpnFlowCopy, IpAddr, &FlowspecRoute)>> =
            HashMap::new();
        for (p, t) in &self.vpn_flow_adj_rib_in {
            for (c, r) in t {
                let valid_here = self
                    .vpn_flow_validity
                    .get(&(*p, c.clone()))
                    .and_then(|m| m.get(table))
                    == Some(&FlowValidity::Valid);
                if valid_here {
                    groups.entry(&c.0).or_default().push((c, *p, r));
                }
            }
        }
        for (k, copies) in groups {
            let scored: Vec<Candidate> = copies
                .iter()
                .map(|(c, p, r)| (flow_rib_route(*p, r, self.confed_peers.contains(p)), c.1))
                .collect();
            let Some(i) = best_index(&scored, &HashMap::new()) else {
                continue;
            };
            let win = copies[i];
            let slot = best.entry((k.0, &(k.1).1)).or_insert(win);
            if (k.1).0 < (((slot.0).0).1).0 {
                *slot = win;
            }
        }
        let mut out: Vec<_> = best.into_values().collect();
        let v6 = |r: &FlowspecRoute| r.family == AddressFamily::Vpnv6Flowspec;
        out.sort_by(|a, b| {
            v6(a.2)
                .cmp(&v6(b.2))
                .then_with(|| crate::flowspec::cmp_precedence(&a.2.nlri, &b.2.nlri))
        });
        out
    }

    /// The VPN flow rules enforced in each VRF, as `nos-acld` takes them
    /// (#1083, #1086): per table, `vpn_flows_of`. `None` while deferring. A
    /// table with no rule is listed empty, so the push clears it.
    pub fn vpn_flowspec_push_snapshot(&self) -> Option<Vec<(String, Vec<nos_proto::FlowRule>)>> {
        if self.deferring() {
            return None;
        }
        Some(
            self.vpn_vrfs
                .tables()
                .map(|table| {
                    let rules = self
                        .vpn_flows_of(table)
                        .into_iter()
                        .map(|(_, _, r)| crate::acl_push_client::flow_rule(r))
                        .collect();
                    (table.to_string(), rules)
                })
                .collect(),
        )
    }

    /// Copy `id` of `k`, held from `peer`, is the copy `table` enforces.
    pub fn vpn_flow_enforced(&self, table: &str, peer: IpAddr, k: &VpnFlowKey, id: u32) -> bool {
        self.vpn_flows_of(table)
            .iter()
            .any(|(c, p, _)| c.0 == *k && c.1 == id && *p == peer)
    }

    /// The VRF set changed: every rule may import elsewhere.
    pub(super) fn revalidate_all_vpn_flows(&mut self) {
        let all: Vec<(IpAddr, VpnFlowCopy)> = self
            .vpn_flow_adj_rib_in
            .iter()
            .flat_map(|(p, t)| t.keys().map(move |k| (*p, k.clone())))
            .collect();
        for (p, k) in all {
            self.revalidate_vpn_flow(p, &k);
        }
    }
}
