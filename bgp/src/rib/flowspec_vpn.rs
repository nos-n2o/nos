//! VPN Flowspec (RFC 8955 section 8, SAFI 134) receive side (#1084).
//!
//! The rules live in `vpn_flow_adj_rib_in` keyed `(family, (RD, rule))`
//! (`VpnKey<FlowSpec>`, the SAFI 128 RD/RT core). A rule is *imported* into
//! every VRF whose import Route Targets match one of its RTs (the Site of
//! Origin blocks as for unicast); one with no match stays here and is in no
//! VRF view. Validation is per VRF: the "unicast" side of RFC 8955 section 6
//! is the SAFI 128 paths imported into that VRF (`vrf_unicast`).
//!
//! No selection, no propagation, no ACL push: that is #1085/#1086.
// ponytail: a VPN unicast change rescans the held rules for overlap
// (`revalidate_vpn_flows_around`) and each revalidation scans the SAFI 128
// Adj-RIB-In once, O(paths) per rule; a per-VRF `FlowIndexes` (as for
// SAFI 133) once it shows in `tools/bench-bgp.sh`.
// ponytail: not retained across graceful restart (dropped with the session),
// and no import policy: both land with #1085.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use ipnet::IpNet;
use nos_proto::AddressFamily;

use super::flowspec_validate::{dest_of, validate, FlowValidity, Unicast};
use super::{
    best_index, info, warn, BgpRib, Candidate, FlowspecRoute, RouteOrigin, VpnFlowKey, VpnRoute,
};
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
    /// Rules held from `peer` of SAFI 134, `[vpnv4, vpnv6]`.
    pub(super) fn accepted_vpn_flow(&self, peer: IpAddr) -> [u32; 2] {
        let mut n = [0u32; 2];
        for (family, _) in self
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
        let mut keys = Vec::new();
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
            let table = self.vpn_flow_adj_rib_in.entry(from).or_default();
            for n in &mp.flowspec_vpn {
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
                if let Some(old) = table.get(&k)
                    && old.attributes == route.attributes
                {
                    route.received_at = old.received_at;
                }
                if table.insert(k.clone(), route.clone()) != Some(route) {
                    info!(peer = %from, family = %family, rd = %format_rd(&n.rd), route = %n.flow, "flowspec route learned");
                }
                keys.push(k);
            }
        }
        for k in keys {
            self.revalidate_vpn_flow(from, &k);
        }
    }

    /// Removes rule `k` from `peer`'s SAFI 134 Adj-RIB-In (logged).
    pub(super) fn drop_vpn_flow(&mut self, peer: IpAddr, k: &VpnFlowKey) -> bool {
        self.vpn_flow_validity.remove(&(peer, k.clone()));
        let removed = self
            .vpn_flow_adj_rib_in
            .get_mut(&peer)
            .and_then(|t| t.remove(k))
            .is_some();
        if removed {
            info!(peer = %peer, family = %k.0, rd = %format_rd(&(k.1).0), route = %(k.1).1, "flowspec route withdrawn");
        }
        removed
    }

    /// Drops everything `peer` sent in SAFI 134 (session down).
    pub(super) fn drop_peer_vpn_flows(&mut self, peer: IpAddr) {
        let keys: Vec<VpnFlowKey> = self
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
        for (k, r) in self.vpn_adj_rib_in.values().flatten() {
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
    pub(super) fn revalidate_vpn_flow(&mut self, peer: IpAddr, k: &VpnFlowKey) {
        let Some(r) = self.vpn_flow_adj_rib_in.get(&peer).and_then(|t| t.get(k)) else {
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
        let old = self.vpn_flow_validity.get(&(peer, k.clone()));
        let mut changed: Vec<(&String, &FlowValidity)> = new
            .iter()
            .filter(|(t, v)| old.and_then(|o| o.get(*t)) != Some(*v))
            .collect();
        changed.sort_by_key(|(t, _)| *t);
        for (table, v) in changed {
            info!(peer = %peer, family = %k.0, rd = %format_rd(&(k.1).0), table = %table, flow = %(k.1).1, validity = %v, "flowspec validity changed");
        }
        self.vpn_flow_visits += 1;
        if new.is_empty() {
            self.vpn_flow_validity.remove(&(peer, k.clone()));
        } else {
            self.vpn_flow_validity.insert((peer, k.clone()), new);
        }
    }

    /// A VPN unicast prefix changed: revalidate the held rules whose
    /// destination overlaps it (an ancestor, or a descendant).
    pub(super) fn revalidate_vpn_flows_around(&mut self, prefix: IpNet) {
        if self.vpn_flow_adj_rib_in.is_empty() {
            return;
        }
        let hit: Vec<(IpAddr, VpnFlowKey)> = self
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

    /// The VRF set changed: every rule may import elsewhere.
    pub(super) fn revalidate_all_vpn_flows(&mut self) {
        let all: Vec<(IpAddr, VpnFlowKey)> = self
            .vpn_flow_adj_rib_in
            .iter()
            .flat_map(|(p, t)| t.keys().map(move |k| (*p, k.clone())))
            .collect();
        for (p, k) in all {
            self.revalidate_vpn_flow(p, &k);
        }
    }
}
