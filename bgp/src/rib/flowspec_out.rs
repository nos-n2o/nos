//! Flowspec (RFC 8955) selection, import/export policy and propagation
//! (#560). The received rules live in `flowspec_adj_rib_in` and are
//! validated by `flowspec_validate`; this module picks one best path per
//! rule (`select_flow`, the unicast decision process through a `RibRoute`
//! adapter, no IGP step: there is no next hop) and advertises it with the
//! unicast `build_advertisement` rules (split horizon, route reflection,
//! eBGP prepend, confederations, export policy).
//!
//! Everything is per rule: a change to one rule (learn, withdraw, validity
//! flip) re-selects that rule only, never the table. Nothing is originated
//! locally (#16 D7).

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use nos_proto::AddressFamily;
use nos_rpl::CompiledPolicy;

use super::{
    apply_policy, best_path, build_advertisement, info, warn, AdvertisedRoute, Arc, BgpRib,
    FlowspecKey, FlowspecRoute, OutboundUpdate, PolicyPeer, RibRoute, RouteOrigin,
    DEFAULT_LOCAL_PREF,
};
use crate::flowspec::FlowSpec;

/// One Flowspec rule rewritten for one peer.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertisedFlowspec {
    pub family: AddressFamily,
    pub nlri: FlowSpec,
    /// The attributes, as for a unicast route; its `prefix`, `next_hop`,
    /// `use_mp` and `path_id` are not encoded (RFC 8955 section 4: no next
    /// hop).
    pub route: AdvertisedRoute,
    /// RFC 5701 IPv6 address specific extended communities (the RFC 8956
    /// redirect), non-transitive ones stripped toward eBGP.
    pub ipv6_extended_communities: Vec<[u8; 20]>,
}

/// What a policy sees as `this.prefix` for a rule (#16 D5): its destination
/// prefix, else its family's default route.
pub(super) fn flow_prefix(family: AddressFamily, nlri: &FlowSpec) -> IpNet {
    match super::flowspec_validate::dest_of(nlri) {
        Some(p) => p.net.trunc(),
        None if family == AddressFamily::Ipv6Flowspec => IpNet::V6(ipnet::Ipv6Net::default()),
        None => IpNet::V4(ipnet::Ipv4Net::default()),
    }
}

/// `r` (held from `peer`) as a decision-process / policy candidate. No next
/// hop, so decision step 7 and next-hop feasibility never apply.
pub(super) fn flow_rib_route(peer: IpAddr, r: &FlowspecRoute, confed: bool) -> RibRoute {
    let a = &r.attributes;
    RibRoute {
        origin: RouteOrigin::Peer(peer),
        as_path: Arc::new(a.as_path.clone()),
        bgp_origin: a.origin,
        local_pref: a.local_pref.unwrap_or(DEFAULT_LOCAL_PREF),
        med: a.med,
        learned_via_ibgp: r.learned_via_ibgp && !confed,
        learned_via_confed: confed,
        router_id: Some(r.router_id),
        next_hop: None,
        received_at: r.received_at,
        originator_id: a.originator_id,
        cluster_list: a.cluster_list.clone().into(),
        communities: a.communities.clone(),
        extended_communities: a.extended_communities.clone(),
        large_communities: a.large_communities.clone(),
        atomic_aggregate: a.atomic_aggregate,
        aggregator: a.aggregator,
        otc: a.otc,
        validation_state: nos_rpl::ValidationState::NotFound,
        received_ov: None,
    }
}

/// Runs a peer's Flowspec import policy over `r`; `false` is a reject. An
/// accept writes the rewrites back into `r.attributes`, except an `AS_PATH`
/// prepend: RFC 8955 section 6 validation reads the path as received.
pub(super) fn import_flow(
    policy: &CompiledPolicy,
    r: &mut FlowspecRoute,
    peer: IpAddr,
    peer_as: u32,
    confed: bool,
) -> bool {
    let candidate = flow_rib_route(peer, r, confed);
    let prefix = flow_prefix(r.family, &r.nlri);
    let Some(out) = apply_policy(
        prefix,
        candidate,
        policy,
        Some(PolicyPeer::new(peer, peer_as)),
        None,
    ) else {
        return false;
    };
    let a = &mut r.attributes;
    if out.local_pref != a.local_pref.unwrap_or(DEFAULT_LOCAL_PREF) {
        a.local_pref = Some(out.local_pref);
    }
    a.med = out.med;
    a.origin = out.bgp_origin;
    a.communities = out.communities;
    a.extended_communities = out.extended_communities;
    a.large_communities = out.large_communities;
    true
}

impl BgpRib {
    /// `peer`'s Flowspec settings (`set_peer_flowspec_validation`,
    /// `set_peer_flowspec_policies`). Call before `peer_established`, after
    /// `set_peer_confed`.
    pub fn set_peer_flowspec(&mut self, peer: &crate::session::ResolvedPeer) {
        let addr = peer.remote_address;
        self.set_peer_flowspec_validation(addr, peer.flowspec_validation);
        self.set_peer_flowspec_policies(
            addr,
            peer.flowspec_import_policy.clone(),
            peer.flowspec_export_policy.clone(),
        );
    }

    /// Sets `peer`'s Flowspec import and export policies (`None`: accept
    /// all) and re-runs the rules it already holds (kept across a graceful
    /// restart) through the import one. Call before `peer_established`,
    /// after `set_peer_confed`.
    pub fn set_peer_flowspec_policies(
        &mut self,
        peer: IpAddr,
        import: Option<Arc<CompiledPolicy>>,
        export: Option<Arc<CompiledPolicy>>,
    ) {
        match export {
            Some(p) => self.flowspec_export.insert(peer, p),
            None => self.flowspec_export.remove(&peer),
        };
        let Some(policy) = import else {
            self.flowspec_import.remove(&peer);
            return;
        };
        let peer_as = self.peer_asns.get(&peer).copied().unwrap_or(0);
        let confed = self.confed_peers.contains(&peer);
        let mut rerun = Vec::new();
        if let Some(table) = self.flowspec_adj_rib_in.get_mut(&peer) {
            for (k, r) in table.iter_mut() {
                let accepted = import_flow(&policy, r, peer, peer_as, confed);
                if !accepted {
                    warn!(peer = %peer, family = %k.0, route = %k.1, "flowspec route rejected by import policy");
                }
                rerun.push((k.clone(), accepted));
            }
        }
        for (k, accepted) in rerun {
            if accepted {
                self.select_flow(&k); // a rewrite may change the winner
            } else {
                self.drop_flow(peer, &k);
            }
        }
        self.flowspec_import.insert(peer, policy);
    }

    /// Removes rule `k` from `peer`'s Adj-RIB-In (logged) and re-selects it.
    pub(super) fn drop_flow(&mut self, peer: IpAddr, k: &FlowspecKey) -> bool {
        // A rule the policy rejected is not held, but its raw copy is.
        self.retained.take_flow(peer, k);
        let removed = self
            .flowspec_adj_rib_in
            .get_mut(&peer)
            .and_then(|t| t.remove(k))
            .is_some();
        if removed {
            info!(peer = %peer, family = %k.0, route = %k.1, "flowspec route withdrawn");
            if let Some(h) = super::bmp_tap::tap(self.bmp.as_ref()) {
                h.flow_post(peer, k, None);
            }
            self.select_flow(k);
        }
        removed
    }

    /// Re-decides rule `k`'s best path among the valid copies every peer
    /// holds and, when it changed, propagates it.
    pub(super) fn select_flow(&mut self, k: &FlowspecKey) {
        let candidates: Vec<super::Candidate> = self
            .flowspec_adj_rib_in
            .iter()
            .filter_map(|(p, t)| {
                let r = t.get(k).filter(|r| r.is_usable())?;
                Some((flow_rib_route(*p, r, self.confed_peers.contains(p)), 0))
            })
            .collect();
        let new = best_path(&candidates, &HashMap::new()).and_then(|b| match b.origin {
            RouteOrigin::Peer(p) => Some((p, self.flowspec_adj_rib_in.get(&p)?.get(k)?.clone())),
            RouteOrigin::Local => None,
        });
        if self.flowspec_loc.get(k) == new.as_ref() {
            return;
        }
        match new {
            Some(n) => self.flowspec_loc.insert(k.clone(), n),
            None => self.flowspec_loc.remove(k),
        };
        if self.deferring() {
            return; // the deferral's end sends the initial update
        }
        let peers: Vec<IpAddr> = self.peer_outboxes.keys().copied().collect();
        for peer in peers {
            self.sync_flow_to(peer, k, false);
        }
    }

    /// The selected copy of rule `k` (from `src`) rewritten for `peer`, or
    /// `None` when `peer` must not have it.
    fn advertise_flow(
        &self,
        peer: IpAddr,
        src: IpAddr,
        r: &FlowspecRoute,
    ) -> Option<AdvertisedFlowspec> {
        let outbox = self.peer_outboxes.get(&peer)?;
        let route = flow_rib_route(src, r, self.confed_peers.contains(&src));
        let policy = self
            .flowspec_export
            .get(&peer)
            .map_or(&*nos_rpl::ACCEPT_ALL, AsRef::as_ref);
        let adv = build_advertisement(
            flow_prefix(r.family, &r.nlri),
            &route,
            peer,
            outbox,
            self.local_asn,
            self.source_is_rr_client(&route),
            self.cluster_id,
            Some((r.family, policy, None)),
        )?;
        let ebgp = !outbox.is_ibgp && !outbox.is_confed;
        Some(AdvertisedFlowspec {
            family: r.family,
            nlri: r.nlri.clone(),
            route: adv,
            // RFC 5701 section 2: the 0x40 type bit is non-transitive.
            ipv6_extended_communities: r
                .attributes
                .ipv6_extended_communities
                .iter()
                .filter(|c| !ebgp || c[0] & 0x40 == 0)
                .copied()
                .collect(),
        })
    }

    /// Brings `peer` in line with rule `k`, diffed against what it was last
    /// sent; `force` re-sends even an unchanged state (a lost update).
    pub(super) fn sync_flow_to(&mut self, peer: IpAddr, k: &FlowspecKey, force: bool) {
        let adv = self
            .flowspec_loc
            .get(k)
            .and_then(|(src, r)| self.advertise_flow(peer, *src, r));
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        let sent = self.flowspec_adj_rib_out.entry(peer).or_default();
        match adv {
            Some(adv) if force || sent.get(k) != Some(&adv) => {
                info!(peer = %peer, family = %k.0, route = %k.1, "flowspec route advertised");
                sent.insert(k.clone(), adv.clone());
                outbox.tx.send(OutboundUpdate::AnnounceFlowspec(adv));
            }
            Some(_) => {}
            None => {
                let was_sent = sent.remove(k).is_some();
                if was_sent || (force && outbox.negotiated_afs.contains(&k.0)) {
                    info!(peer = %peer, family = %k.0, route = %k.1, "flowspec route advertisement withdrawn");
                    outbox
                        .tx
                        .send(OutboundUpdate::WithdrawFlowspec(k.0, k.1.clone()));
                }
            }
        }
    }

    /// Initial advertisement of every selected rule to a just-established
    /// peer (`initial_update`).
    pub(super) fn announce_flowspec_to(&mut self, peer: IpAddr) {
        self.flowspec_adj_rib_out.remove(&peer);
        let keys: Vec<FlowspecKey> = self.flowspec_loc.keys().cloned().collect();
        for k in keys {
            self.sync_flow_to(peer, &k, false);
        }
    }

    /// Route refresh (RFC 2918) of a Flowspec family: re-sends what `peer`
    /// was last sent of it.
    pub(super) fn resend_flowspec(&self, peer: IpAddr, family: AddressFamily) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        for adv in self
            .flowspec_adj_rib_out
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::values)
            .filter(|a| a.family == family)
        {
            outbox
                .tx
                .send(OutboundUpdate::AnnounceFlowspec(adv.clone()));
        }
    }

    /// The selected rules as `nos-acld` takes them (#562): IPv4 first, each
    /// family in RFC 8955 section 5.1 order. `None` while deferring
    /// (graceful restart): `nos-acld` keeps what it was last sent.
    pub fn flowspec_push_snapshot(&self) -> Option<Vec<nos_proto::FlowRule>> {
        if self.deferring() {
            return None;
        }
        let mut rules: Vec<&FlowspecRoute> = self.flowspec_loc.values().map(|(_, r)| r).collect();
        let v6 = |r: &FlowspecRoute| r.family == AddressFamily::Ipv6Flowspec;
        rules.sort_by(|a, b| {
            v6(a)
                .cmp(&v6(b))
                .then_with(|| crate::flowspec::cmp_precedence(&a.nlri, &b.nlri))
        });
        Some(
            rules
                .into_iter()
                .map(crate::acl_push_client::flow_rule)
                .collect(),
        )
    }

    /// `r`, held from `peer`, is the selected copy of its rule.
    pub fn flowspec_selected(&self, peer: IpAddr, r: &FlowspecRoute) -> bool {
        self.flowspec_loc
            .get(&(r.family, r.nlri.clone()))
            .is_some_and(|(p, _)| *p == peer)
    }

    /// The peer whose copy of rule `k` is selected.
    #[cfg(test)]
    pub(crate) fn flowspec_best(&self, k: &FlowspecKey) -> Option<IpAddr> {
        self.flowspec_loc.get(k).map(|(p, _)| *p)
    }
}
