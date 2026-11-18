//! VRF import of received VPN-IPv4/IPv6 paths (RFC 4364 section 4.3.2,
//! #579): every path of the VPN Adj-RIB-In whose Route Targets match a VRF's
//! import set (`VrfSet::import_by_table`) is a candidate in that VRF, the RD
//! stripped, so paths under different RDs for one prefix compete there
//! (section 4.3.5 keeps them apart only in the VPN table itself). The best
//! set per (VRF, prefix) (the best path plus, up to `maximum-paths`, the
//! ones tying with it as for unicast multipath, RD ignored) is what
//! `vpn_push_client` resolves and pushes. Install-only: `select_vpn` /
//! `vpn_out` (what is re-advertised) still picks one best.
//!
//! Snapshot-based like `evpn_push_snapshot`: one derivation covers announce,
//! withdraw, RT change, peer loss, GR purge and a VRF set change.
// ponytail: O(paths x VRFs) per push tick; import incrementally if it ever
// shows in `tools/bench-bgp.sh`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use ipnet::IpNet;

use super::decision::multipath_ties;
use super::{best_index, BgpRib, Candidate, VpnRoute};
use crate::vpn::{Rd, VpnKey, VrfSet};

/// A held copy: its peer, path id and route.
type Held<'a> = (IpAddr, u32, &'a VpnRoute);

/// One route imported into one VRF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnImport {
    /// Never empty, sorted by (PE, labels).
    pub paths: Vec<VpnImportPath>,
}

/// One next hop of an imported route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnImportPath {
    /// The remote PE (the path's BGP next hop), still to resolve in the
    /// underlay.
    pub pe: IpAddr,
    pub labels: Vec<u32>,
    pub rd: Rd,
}

/// A path a VRF refused by Site of Origin: (table, RD, prefix, Site of Origin).
pub type SooSkip = (String, Rd, IpNet, u64);

/// Per VRF table (every one of the set, even empty), per prefix.
pub type VpnImports = HashMap<String, HashMap<IpNet, VpnImport>>;

impl BgpRib {
    /// The VRFs whose `vpn.bgp_instance` is this instance (`reconcile.rs`).
    pub fn set_vpn_vrfs(&mut self, vrfs: VrfSet) {
        self.vpn_vrfs = vrfs;
        self.revalidate_all_vpn_flows();
    }

    pub fn vpn_vrfs(&self) -> &VrfSet {
        &self.vpn_vrfs
    }

    /// This instance's (underlay) routing table, where PE next hops resolve,
    /// and what each VRF imports; `None` while deferring (graceful restart:
    /// the VRFs keep what they hold). A path whose PE is unfeasible
    /// (`next_hop_feasible`) is no candidate.
    pub fn vpn_import_snapshot(&self) -> (Option<String>, Option<VpnImports>) {
        if self.deferring() {
            return (None, None);
        }
        // Every copy, with its peer and path id (the deterministic tie order).
        let held: Vec<(&VpnKey<IpNet>, Held<'_>)> = self
            .vpn_adj_rib_in
            .iter()
            .flat_map(|(p, t)| {
                t.iter()
                    .flat_map(move |(k, ids)| ids.iter().map(move |(id, r)| (k, (*p, *id, r))))
            })
            .filter(|(_, (_, _, r))| {
                r.route.next_hop.is_some() && self.next_hop_feasible(r.route.next_hop)
            })
            .collect();
        let paths = held
            .iter()
            .map(|(k, h)| (*k, h.2.route.extended_communities.as_slice(), h));
        let mut out: VpnImports = self
            .vpn_vrfs
            .tables()
            .map(|t| (t.to_string(), HashMap::new()))
            .collect();
        for (table, routes) in self.vpn_vrfs.import_by_table(paths) {
            let mut per_prefix: HashMap<IpNet, Vec<(&VpnKey<IpNet>, Held<'_>)>> = HashMap::new();
            for (k, h) in routes {
                per_prefix.entry(k.1).or_default().push((k, *h));
            }
            let dest = out.entry(table.to_string()).or_default();
            for (prefix, cands) in per_prefix {
                if let Some(best) = self.best_import(cands) {
                    dest.insert(prefix, best);
                }
            }
        }
        (self.owning_routing_table.clone(), Some(out))
    }

    /// The (table, RD, prefix, Site of Origin) of every held path a VRF
    /// refused for carrying its own Site of Origin (RFC 4364 section 7).
    pub fn vpn_soo_skipped(&self) -> HashSet<SooSkip> {
        self.vpn_adj_rib_in
            .values()
            .flatten()
            .flat_map(|(k, ids)| ids.values().map(move |r| (k, r)))
            .flat_map(|(k, r)| {
                self.vpn_vrfs
                    .soo_blocked(&r.route.extended_communities)
                    .into_iter()
                    .map(move |(t, soo)| (t.to_string(), k.0, k.1, soo))
            })
            .collect()
    }

    /// The unicast decision process over one VRF prefix's candidates, then
    /// the multipath ties (`multipath_ties`, RD plays no part). They are
    /// ordered by (RD, peer, path id) and the position is the step-10 path id,
    /// so a full tie always picks the lowest RD, then peer, then path id
    /// (the input comes from `HashMap` iteration, #1133). Only an identical
    /// (PE, labels) pair is collapsed: one PE under two RDs with different
    /// labels stays two next hops.
    fn best_import(&self, mut cands: Vec<(&VpnKey<IpNet>, Held<'_>)>) -> Option<VpnImport> {
        cands.sort_by_key(|(k, (peer, id, _))| (k.0, *peer, *id));
        let scored: Vec<Candidate> = cands
            .iter()
            .zip(0u32..)
            .map(|((_, (_, _, r)), id)| (r.route.clone(), id))
            .collect();
        let i = best_index(&scored, &self.igp)?;
        let best = &scored[i].0;
        best.next_hop?;
        let mut paths: Vec<VpnImportPath> = Vec::new();
        for tie in multipath_ties(&scored, best, &self.igp, usize::MAX) {
            if paths.len() >= self.maximum_paths {
                break;
            }
            // `tie` borrows `scored`; its index maps back to the VPN key.
            let j = scored.iter().position(|(r, _)| std::ptr::eq(r, tie))?;
            let (k, (_, _, r)) = cands[j];
            let path = VpnImportPath {
                pe: r.route.next_hop?,
                labels: r.labels.clone(),
                rd: k.0,
            };
            if !paths
                .iter()
                .any(|p| (p.pe, &p.labels) == (path.pe, &path.labels))
            {
                paths.push(path);
            }
        }
        paths.sort_by(|a, b| (a.pe, &a.labels).cmp(&(b.pe, &b.labels)));
        Some(VpnImport { paths })
    }
}
