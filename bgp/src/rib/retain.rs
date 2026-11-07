//! Soft reconfiguration inbound (#859): the pre-policy copy of every route a
//! flagged peer sends, kept so an import-policy change is re-evaluated locally
//! (no session reset, no Route Refresh). Unicast, EVPN (rejected routes only:
//! the held ones are already raw), Flowspec and VPN (#866).
//!
//! Re-evaluation is chunked (`BgpRib::reevaluate_chunk`): the caller takes the
//! RIB lock per chunk, so UPDATEs interleave between chunks. See
//! `docs/protocols/bgp-internals.md`, "Soft reconfiguration inbound".

use super::adj_in::{
    evpn_mac_key, evpn_rejected, get_path, put_path, register_mobility, take_path, PathCounts,
    PeerTable,
};
use super::flowspec_out::import_flow;
use super::vpn_out::vpn_family;
use super::{
    apply_policy, family_index, info, ov_state, warn, Arc, BgpRib, CompiledPolicy, EvpnNlri,
    EvpnRoute, FlowspecKey, FlowspecRoute, HashMap, HashSet, IpAddr, IpNet, PolicyPeer, RibRoute,
    VpnRoute,
};
use crate::vpn::{format_rd, VpnKey};
use nos_proto::{AddressFamily, FamilyReeval, ReevalFamily};

/// Prefixes re-evaluated per RIB lock hold: keeps a hold in the low
/// milliseconds on a full table. Not configurable (#859).
pub const REEVAL_CHUNK: usize = 5000;

/// Per flagged peer: the pre-policy tables and counters. Reuses
/// `put_path`/`take_path`, so ADD-PATH ids come for free.
#[derive(Default)]
pub(super) struct Retained {
    pub(super) tables: HashMap<IpAddr, PeerTable>,
    counts: HashMap<IpAddr, PathCounts>,
    enabled: HashSet<IpAddr>,
    /// Families whose enhanced-refresh `EoRR` is still awaited after an
    /// in-place enable (`BgpRib::enable_soft_reconfig_live`).
    awaiting_eorr: HashSet<(IpAddr, AddressFamily)>,
    /// EVPN routes the import policy rejected: a held route is already the
    /// raw one (the policy only accepts or rejects).
    pub(super) evpn: HashMap<IpAddr, HashMap<EvpnNlri, EvpnRoute>>,
    /// Flowspec rules as received: the policy rewrites the held copy.
    pub(super) flow: HashMap<IpAddr, HashMap<FlowspecKey, FlowspecRoute>>,
    /// VPN paths as received (the policy rewrites the held copy).
    pub(super) vpn: HashMap<IpAddr, HashMap<VpnKey<IpNet>, VpnRoute>>,
}

/// The import policies a re-evaluation applies, as the peer slot holds them.
#[derive(Clone)]
pub struct ImportPolicies {
    /// Unicast and VPN (the peer-group's `import_policy`).
    pub unicast: Arc<CompiledPolicy>,
    /// `None` accepts every EVPN route.
    pub evpn: Option<Arc<CompiledPolicy>>,
    /// `None` accepts every Flowspec rule.
    pub flowspec: Option<Arc<CompiledPolicy>>,
}

impl From<Arc<CompiledPolicy>> for ImportPolicies {
    fn from(unicast: Arc<CompiledPolicy>) -> Self {
        Self {
            unicast,
            evpn: None,
            flowspec: None,
        }
    }
}

/// The mutable halves of one peer's retention, handed to `learn_prefix`.
pub(super) struct RetainSlot<'a> {
    pub table: &'a mut PeerTable,
    pub counts: &'a mut PathCounts,
    pub evpn: &'a mut HashMap<EvpnNlri, EvpnRoute>,
    pub flow: &'a mut HashMap<FlowspecKey, FlowspecRoute>,
}

impl Retained {
    pub(super) fn slot(&mut self, peer: IpAddr) -> Option<RetainSlot<'_>> {
        if !self.enabled.contains(&peer) {
            return None;
        }
        Some(RetainSlot {
            table: self.tables.entry(peer).or_default(),
            counts: self.counts.entry(peer).or_default(),
            evpn: self.evpn.entry(peer).or_default(),
            flow: self.flow.entry(peer).or_default(),
        })
    }

    pub(super) fn vpn_slot(
        &mut self,
        peer: IpAddr,
    ) -> Option<&mut HashMap<VpnKey<IpNet>, VpnRoute>> {
        self.enabled
            .contains(&peer)
            .then(|| self.vpn.entry(peer).or_default())
    }

    pub(super) fn take_evpn(&mut self, peer: IpAddr, k: &EvpnNlri) {
        if let Some(t) = self.evpn.get_mut(&peer) {
            t.remove(k);
        }
    }

    pub(super) fn take_flow(&mut self, peer: IpAddr, k: &FlowspecKey) {
        if let Some(t) = self.flow.get_mut(&peer) {
            t.remove(k);
        }
    }

    pub(super) fn take_vpn(&mut self, peer: IpAddr, k: &VpnKey<IpNet>) {
        if let Some(t) = self.vpn.get_mut(&peer) {
            t.remove(k);
        }
    }

    pub(super) fn take(&mut self, peer: IpAddr, prefix: IpNet, id: u32) {
        if let (Some(t), Some(c)) = (self.tables.get_mut(&peer), self.counts.get_mut(&peer)) {
            take_path(t, c, prefix, id);
        }
    }

    /// Frees everything held for `peer`, including the enabled mark.
    pub(super) fn drop_peer(&mut self, peer: IpAddr) {
        self.tables.remove(&peer);
        self.counts.remove(&peer);
        self.evpn.remove(&peer);
        self.flow.remove(&peer);
        self.vpn.remove(&peer);
        self.enabled.remove(&peer);
        self.awaiting_eorr.retain(|(p, _)| *p != peer);
    }

    pub(super) fn count(&self, peer: IpAddr) -> PathCounts {
        self.counts.get(&peer).copied().unwrap_or_default()
    }
}

/// One entry of a pass's key snapshot.
enum ReevalKey {
    Unicast(IpNet),
    Evpn(EvpnNlri),
    Flow(FlowspecKey),
    Vpn(VpnKey<IpNet>),
}

/// `(visited, accepted, changed)` of one family.
type Tally = (u32, u32, u32);

/// One re-evaluation pass over a peer's retained routes.
pub struct ReevalPass {
    peer: IpAddr,
    policies: ImportPolicies,
    keys: Vec<ReevalKey>,
    next: usize,
    /// Indexed like `ReevalFamily`.
    stats: [Tally; 7],
    /// Families reported even when empty: unicast, plus what was negotiated.
    shown: [bool; 7],
}

/// What `reevaluate_chunk` did.
#[derive(Debug, PartialEq, Eq)]
pub enum ChunkOutcome {
    /// More keys remain.
    More,
    /// Every snapshot key was visited.
    Done,
    /// Retention is gone (disconnect or flag off).
    Gone,
}

const FAMILIES: [ReevalFamily; 7] = [
    ReevalFamily::Ipv4Unicast,
    ReevalFamily::Ipv6Unicast,
    ReevalFamily::L2vpnEvpn,
    ReevalFamily::Ipv4Flowspec,
    ReevalFamily::Ipv6Flowspec,
    ReevalFamily::Vpnv4,
    ReevalFamily::Vpnv6,
];

fn family_slot(f: AddressFamily) -> usize {
    match f {
        AddressFamily::Ipv4Unicast => 0,
        AddressFamily::Ipv6Unicast => 1,
        AddressFamily::L2vpnEvpn => 2,
        AddressFamily::Ipv4Flowspec => 3,
        AddressFamily::Ipv6Flowspec => 4,
        AddressFamily::Vpnv4Unicast => 5,
        AddressFamily::Vpnv6Unicast => 6,
        AddressFamily::RtConstraint => unreachable!("RT-Constraint routes are never re-evaluated"),
    }
}

fn tally(t: &mut Tally, accepted: bool, changed: bool) {
    t.0 += 1;
    t.1 += u32::from(accepted);
    t.2 += u32::from(changed);
}

impl ReevalPass {
    /// Per-family counts so far, in `ReevalFamily` order.
    pub fn families(&self) -> Vec<FamilyReeval> {
        FAMILIES
            .into_iter()
            .zip(self.stats)
            .zip(self.shown)
            .filter(|((_, (retained, ..)), shown)| *shown || *retained > 0)
            .map(|((family, (retained, accepted, _)), _)| FamilyReeval {
                family,
                retained,
                accepted,
            })
            .collect()
    }

    /// Logs one line per family; the caller logs the closing line.
    pub fn log(&self) {
        for ((family, (retained, accepted, changed)), shown) in
            FAMILIES.into_iter().zip(self.stats).zip(self.shown)
        {
            if shown || retained > 0 {
                info!(
                    peer = %self.peer, family = %family, retained, accepted, changed,
                    "soft reconfiguration: re-evaluated import policy"
                );
            }
        }
    }
}

impl BgpRib {
    /// Turns retention on or off for `peer`; off frees the memory. Call
    /// before `peer_established`, like `set_peer_damping`.
    pub fn set_peer_soft_reconfig(&mut self, peer: IpAddr, on: bool) {
        if on {
            self.retained.enabled.insert(peer);
        } else {
            self.retained.drop_peer(peer);
        }
    }

    /// Enables retention on an `Established` peer whose routes are about to be
    /// re-sent by a Route Refresh; remembers which families' `EoRR` marks
    /// retention as complete.
    pub fn enable_soft_reconfig_live(&mut self, peer: IpAddr, enhanced: bool) {
        self.retained.enabled.insert(peer);
        if !enhanced {
            info!(peer = %peer, "soft reconfiguration: retention enabled, route refresh requested");
            return;
        }
        let afs = self
            .peer_outboxes
            .get(&peer)
            .map(|o| o.negotiated_afs.clone());
        for f in afs.into_iter().flatten() {
            self.retained.awaiting_eorr.insert((peer, f));
        }
        info!(peer = %peer, "soft reconfiguration: retention enabled, route refresh requested");
    }

    /// An RFC 7313 `EoRR` for `family` arrived; logs once every awaited family
    /// is in.
    pub fn retention_eorr(&mut self, peer: IpAddr, family: AddressFamily) {
        if self.retained.awaiting_eorr.remove(&(peer, family))
            && !self.retained.awaiting_eorr.iter().any(|(p, _)| *p == peer)
        {
            let n = self.retained_count(peer);
            info!(peer = %peer, retained = n, "soft reconfiguration: retention complete");
        }
    }

    /// Paths retained for `peer`, all families. EVPN counts what the peer
    /// currently sends: the held routes plus the rejected ones.
    pub fn retained_count(&self, peer: IpAddr) -> u32 {
        if !self.retained.enabled.contains(&peer) {
            return 0;
        }
        let n = |len: Option<usize>| u32::try_from(len.unwrap_or(0)).unwrap_or(u32::MAX);
        self.retained.count(peer).iter().sum::<u32>()
            + n(self.evpn_adj_rib_in.get(&peer).map(HashMap::len))
            + n(self.retained.evpn.get(&peer).map(HashMap::len))
            + n(self.retained.flow.get(&peer).map(HashMap::len))
            + n(self.retained.vpn.get(&peer).map(HashMap::len))
    }

    /// Whether retention is on for `peer`.
    pub fn soft_reconfig_enabled(&self, peer: IpAddr) -> bool {
        self.retained.enabled.contains(&peer)
    }

    /// Every retained unicast path of `peer`: `(prefix, path id, route)`.
    pub fn retained_routes(&self, peer: IpAddr) -> Vec<(IpNet, u32, &RibRoute)> {
        self.retained
            .tables
            .get(&peer)
            .into_iter()
            .flatten()
            .flat_map(|(p, paths)| paths.iter().map(move |(id, r)| (*p, *id, r)))
            .collect()
    }

    /// Starts a pass: `policies` is what every later UPDATE of `peer` is
    /// judged by (the caller installs the unicast one in its slot in the same
    /// critical section; the EVPN and Flowspec ones are installed here), the
    /// pass snapshots the retained KEYS only. `None` if retention is off.
    pub fn begin_reevaluation(
        &mut self,
        peer: IpAddr,
        policies: impl Into<ImportPolicies>,
    ) -> Option<ReevalPass> {
        if !self.retained.enabled.contains(&peer) {
            return None;
        }
        let policies = policies.into();
        match &policies.evpn {
            Some(p) => self.evpn_import.insert(peer, p.clone()),
            None => self.evpn_import.remove(&peer),
        };
        match &policies.flowspec {
            Some(p) => self.flowspec_import.insert(peer, p.clone()),
            None => self.flowspec_import.remove(&peer),
        };
        let mut keys: Vec<ReevalKey> = self
            .retained
            .tables
            .get(&peer)
            .map(|t| t.keys().copied().map(ReevalKey::Unicast).collect())
            .unwrap_or_default();
        let held = self.evpn_adj_rib_in.get(&peer).into_iter().flatten();
        let rejected = self.retained.evpn.get(&peer).into_iter().flatten();
        keys.extend(
            held.chain(rejected)
                .map(|(k, _)| k)
                .collect::<HashSet<_>>()
                .into_iter()
                .map(|k| ReevalKey::Evpn(k.clone())),
        );
        keys.extend(
            self.retained
                .flow
                .get(&peer)
                .into_iter()
                .flat_map(HashMap::keys)
                .cloned()
                .map(ReevalKey::Flow),
        );
        keys.extend(
            self.retained
                .vpn
                .get(&peer)
                .into_iter()
                .flat_map(HashMap::keys)
                .copied()
                .map(ReevalKey::Vpn),
        );
        let mut shown = [false; 7];
        shown[0] = true;
        shown[1] = true;
        for f in self
            .peer_outboxes
            .get(&peer)
            .into_iter()
            .flat_map(|o| o.negotiated_afs.iter())
            .filter(|f| **f != AddressFamily::RtConstraint)
        {
            shown[family_slot(*f)] = true;
        }
        Some(ReevalPass {
            peer,
            policies,
            keys,
            next: 0,
            stats: [(0, 0, 0); 7],
            shown,
        })
    }

    /// Re-evaluates the next `n` snapshot keys against the CURRENT retained
    /// tables (a path withdrawn since the snapshot is skipped), refreshing the
    /// RPKI state, and applies admit/replace/remove to the Adj-RIBs-In.
    /// Only keys whose result changed are re-decided and propagated.
    /// Applies no damping.
    pub fn reevaluate_chunk(&mut self, pass: &mut ReevalPass, n: usize) -> ChunkOutcome {
        let peer = pass.peer;
        if !self.retained.enabled.contains(&peer) {
            return ChunkOutcome::Gone;
        }
        let end = (pass.next + n).min(pass.keys.len());
        let mut touched = Vec::new();
        let mut flows = Vec::new();
        let mut vpns = Vec::new();
        let mut macs = Vec::new();
        for key in &pass.keys[pass.next..end] {
            match key {
                ReevalKey::Unicast(prefix) => {
                    if self.reeval_unicast(peer, *prefix, &pass.policies.unicast, &mut pass.stats) {
                        touched.push(*prefix);
                    }
                }
                ReevalKey::Evpn(k) => {
                    let policy = pass.policies.evpn.as_deref();
                    self.reeval_evpn(peer, k, policy, &mut pass.stats[2], &mut macs);
                }
                ReevalKey::Flow(k) => {
                    let policy = pass.policies.flowspec.as_deref();
                    if self.reeval_flow(peer, k, policy, &mut pass.stats) {
                        flows.push(k.clone());
                    }
                }
                ReevalKey::Vpn(k) => {
                    if self.reeval_vpn(peer, k, &pass.policies.unicast, &mut pass.stats) {
                        vpns.push(*k);
                    }
                }
            }
        }
        pass.next = end;
        for prefix in touched {
            self.recompute_and_propagate(prefix);
        }
        if !flows.is_empty() {
            self.enable_flow_indexes();
            for k in flows {
                self.track_flow(peer, &k);
            }
        }
        for k in vpns {
            self.select_vpn(&k);
        }
        for (vni, mac) in macs {
            self.mac_mobility_recheck(vni, mac);
        }
        if end >= pass.keys.len() {
            ChunkOutcome::Done
        } else {
            ChunkOutcome::More
        }
    }

    /// One retained unicast prefix; whether its Adj-RIB-In entry changed.
    fn reeval_unicast(
        &mut self,
        peer: IpAddr,
        prefix: IpNet,
        policy: &CompiledPolicy,
        stats: &mut [Tally; 7],
    ) -> bool {
        let Some(paths) = self.retained.tables.get(&peer).and_then(|t| t.get(&prefix)) else {
            return false;
        };
        let peer_as = self.peer_asns.get(&peer).copied().unwrap_or(0);
        let pp = PolicyPeer::new(peer, peer_as).with_roles(self.policy_roles(peer));
        let local = self.confed_id.unwrap_or(self.local_asn);
        let adj = self.adj_rib_in.entry(peer).or_default();
        let counts = self.path_counts.entry(peer).or_default();
        let bmp = super::bmp_tap::tap(self.bmp.as_ref());
        let fam = family_index(prefix);
        let mut changed = false;
        for (id, held) in paths {
            let mut cand = held.clone();
            cand.validation_state = ov_state(
                &self.vrps,
                prefix,
                crate::rpki::origin_as(&cand.as_path, local),
                cand.received_ov,
            );
            let result = apply_policy(prefix, cand, policy, Some(pp), None);
            stats[fam].0 += 1;
            stats[fam].1 += u32::from(result.is_some());
            changed |= settle(adj, counts, (peer, prefix, *id), result, bmp);
        }
        if changed {
            stats[fam].2 += 1;
        }
        changed
    }

    /// One EVPN route, held or rejected. The policy only accepts or
    /// rejects, so the stored route is the raw one in both places. Newly
    /// admitted Type-2 routes register as MAC mobility candidates now, with
    /// the route as it is at this moment.
    fn reeval_evpn(
        &mut self,
        peer: IpAddr,
        k: &EvpnNlri,
        policy: Option<&CompiledPolicy>,
        stat: &mut Tally,
        macs: &mut Vec<(u32, [u8; 6])>,
    ) {
        let held = self.evpn_adj_rib_in.get(&peer).and_then(|t| t.get(k));
        let was_held = held.is_some();
        let Some(route) = held
            .or_else(|| self.retained.evpn.get(&peer).and_then(|t| t.get(k)))
            .cloned()
        else {
            return;
        };
        let peer_as = self.peer_asns.get(&peer).copied().unwrap_or(0);
        let ibgp = self.peer_outboxes.get(&peer).is_some_and(|o| o.is_ibgp);
        let rejected = policy.is_some_and(|p| evpn_rejected(p, &route, peer, peer_as, ibgp));
        let changed = rejected == was_held;
        tally(stat, !rejected, changed);
        if !changed {
            return;
        }
        let nlri = &route.nlri;
        let bmp = super::bmp_tap::tap(self.bmp.as_ref());
        if rejected {
            self.evpn_adj_rib_in.entry(peer).or_default().remove(k);
            if let Some(h) = bmp {
                h.evpn_post(peer, k, None);
            }
            self.retained
                .evpn
                .entry(peer)
                .or_default()
                .insert(k.clone(), route.clone());
            warn!(peer = %peer, route_type = nlri.route_type(), route = %nlri, "evpn route rejected by import policy");
        } else {
            self.retained.take_evpn(peer, k);
            register_mobility(&mut self.mac_mobility, &route);
            macs.extend(evpn_mac_key(nlri).map(|(vni, mac, _)| (vni, mac)));
            if let Some(h) = bmp {
                h.evpn_post(peer, k, Some(&route));
            }
            info!(peer = %peer, route_type = nlri.route_type(), route = %nlri, next_hop = %route.next_hop, local_pref = route.local_pref, communities = %format_args!("[{}]", nos_proto::bgp::fmt_communities(&route.communities)), "evpn route learned");
            self.evpn_adj_rib_in
                .entry(peer)
                .or_default()
                .insert(k.clone(), route);
        }
    }

    /// One retained Flowspec rule, from its raw copy; whether the held rule
    /// changed (the caller validates and re-selects it).
    fn reeval_flow(
        &mut self,
        peer: IpAddr,
        k: &FlowspecKey,
        policy: Option<&CompiledPolicy>,
        stats: &mut [Tally; 7],
    ) -> bool {
        let Some(mut route) = self
            .retained
            .flow
            .get(&peer)
            .and_then(|t| t.get(k))
            .cloned()
        else {
            return false;
        };
        let peer_as = self.peer_asns.get(&peer).copied().unwrap_or(0);
        let confed = self.confed_peers.contains(&peer);
        let accepted = policy.is_none_or(|p| import_flow(p, &mut route, peer, peer_as, confed));
        let bmp = super::bmp_tap::tap(self.bmp.as_ref());
        let table = self.flowspec_adj_rib_in.entry(peer).or_default();
        let changed = if accepted {
            if let Some(old) = table.get(k) {
                route.validity = old.validity;
                if old.attributes == route.attributes {
                    route.received_at = old.received_at;
                }
            }
            let changed = table.get(k) != Some(&route);
            if changed {
                info!(peer = %peer, family = %k.0, route = %k.1, "flowspec route learned");
                if let Some(h) = bmp {
                    h.flow_post(peer, k, Some(&route));
                }
                table.insert(k.clone(), route);
            }
            changed
        } else {
            let removed = table.remove(k).is_some();
            if removed {
                warn!(peer = %peer, family = %k.0, route = %k.1, "flowspec route rejected by import policy");
                if let Some(h) = bmp {
                    h.flow_post(peer, k, None);
                }
            }
            removed
        };
        let slot = family_slot(k.0);
        tally(&mut stats[slot], accepted, changed);
        changed
    }

    /// One retained VPN path, from its raw copy; whether the held path
    /// changed (the caller re-selects it).
    fn reeval_vpn(
        &mut self,
        peer: IpAddr,
        k: &VpnKey<IpNet>,
        policy: &CompiledPolicy,
        stats: &mut [Tally; 7],
    ) -> bool {
        let Some(raw) = self.retained.vpn.get(&peer).and_then(|t| t.get(k)).cloned() else {
            return false;
        };
        let peer_as = self.peer_asns.get(&peer).copied().unwrap_or(0);
        let result = apply_policy(
            k.1,
            raw.route,
            policy,
            Some(PolicyPeer::new(peer, peer_as)),
            Some(k.0),
        );
        let accepted = result.is_some();
        let bmp = super::bmp_tap::tap(self.bmp.as_ref());
        let table = self.vpn_adj_rib_in.entry(peer).or_default();
        let changed = if let Some(mut route) = result {
            if let Some(old) = table.get(k)
                && old.labels == raw.labels
                && (RibRoute {
                    received_at: old.route.received_at,
                    ..route.clone()
                }) == old.route
            {
                route.received_at = old.route.received_at;
            }
            let new = VpnRoute {
                labels: raw.labels,
                route,
            };
            let changed = table.get(k) != Some(&new);
            if changed {
                info!(peer = %peer, family = %vpn_family(k.1), rd = %format_rd(&k.0), prefix = %k.1, "vpn route learned");
                if let Some(h) = bmp {
                    h.vpn_post(peer, k, Some(&new));
                }
                table.insert(*k, new);
            }
            changed
        } else {
            let removed = table.remove(k).is_some();
            if removed {
                warn!(peer = %peer, family = %vpn_family(k.1), rd = %format_rd(&k.0), prefix = %k.1, "vpn route rejected by import policy");
                if let Some(h) = bmp {
                    h.vpn_post(peer, k, None);
                }
            }
            removed
        };
        let slot = family_slot(vpn_family(k.1));
        tally(&mut stats[slot], accepted, changed);
        changed
    }

    /// Re-evaluates everything in one go (tests and small tables); the daemon
    /// uses the chunked form.
    pub fn reevaluate_peer(
        &mut self,
        peer: IpAddr,
        policies: impl Into<ImportPolicies>,
    ) -> Vec<FamilyReeval> {
        let Some(mut pass) = self.begin_reevaluation(peer, policies) else {
            return Vec::new();
        };
        while self.reevaluate_chunk(&mut pass, usize::MAX) == ChunkOutcome::More {}
        pass.families()
    }
}

/// Applies one re-evaluated path to the Adj-RIB-In; whether it changed.
fn settle(
    adj: &mut PeerTable,
    counts: &mut PathCounts,
    (peer, prefix, id): (IpAddr, IpNet, u32),
    result: Option<RibRoute>,
    bmp: Option<&crate::bmp::Hub>,
) -> bool {
    let Some(mut route) = result else {
        let gone = take_path(adj, counts, prefix, id).is_some();
        if let Some(h) = bmp.filter(|_| gone) {
            h.route_post(peer, prefix, id, None);
        }
        return gone;
    };
    if let Some(old) = get_path(adj, prefix, id) {
        route.received_at = old.received_at;
        if route == *old {
            return false;
        }
    } else {
        info!(
            peer = %peer, path_id = id,
            "bgp: learned route for {prefix} into adj-rib-in"
        );
    }
    if let Some(h) = bmp {
        h.route_post(peer, prefix, id, Some(&route));
    }
    put_path(adj, counts, prefix, id, route);
    true
}
