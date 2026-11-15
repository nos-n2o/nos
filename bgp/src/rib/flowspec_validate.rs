//! RFC 8955 section 6 / RFC 8956 section 5 Flowspec validation.
//!
//! `validate` is pure: it sees the unicast RIB only through two closures, so
//! the rules unit-test without a session. The `BgpRib` half below owns the
//! incremental revalidation: a derived index of flow destinations
//! (`flow_index`) and of the neighbouring ASes of every received unicast
//! prefix (`uni_index`, rule (c)), so a unicast change only revisits the
//! flows whose destination overlaps it, never the whole Flowspec table.
//!
//! The default procedure is RFC 9117 (rule (b.2): a flow with an empty or
//! confederation-only `AS_PATH` skips the originator match; the eBGP check
//! compares the flow's leftmost AS with the best-match route's, not the
//! neighbour's). `flowspec-validation rfc8955-strict` restores RFC 8955 as
//! written.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;

use super::{info, BgpRib, FlowspecKey, RouteOrigin};
use crate::flowspec::{Component, FlowSpec};

/// Why a flow is not valid; the `Display` form is what `show` and the logs print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidReason {
    /// Rule (a): no destination prefix component.
    NoDestinationPrefix,
    /// RFC 8956 section 5: an IPv6 destination prefix with a non-zero offset.
    OffsetNotZero,
    /// Rule (b): the originator differs from the best-match route's.
    OriginatorMismatch,
    /// Rule (b): no unicast route covers the destination.
    NoUnicastRoute,
    /// Rule (c): a more-specific route comes from another neighbouring AS.
    MoreSpecificFromOtherAs,
    /// RFC 8955 eBGP check (strict mode): the leftmost AS of the path is not
    /// the neighbour's.
    BadNeighbourAs,
    /// RFC 9117 eBGP check: the flow's leftmost AS differs from the
    /// best-match unicast route's (or either has none).
    LeftmostAsMismatch,
}

impl fmt::Display for InvalidReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoDestinationPrefix => "no-destination-prefix",
            Self::OffsetNotZero => "ipv6-offset-not-zero",
            Self::OriginatorMismatch => "originator-mismatch",
            Self::NoUnicastRoute => "no-covering-unicast-route",
            Self::MoreSpecificFromOtherAs => "more-specific-from-other-as",
            Self::BadNeighbourAs => "bad-neighbour-as",
            Self::LeftmostAsMismatch => "leftmost-as-mismatch",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowValidity {
    Valid,
    Invalid(InvalidReason),
}

impl fmt::Display for FlowValidity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => f.write_str("valid"),
            Self::Invalid(r) => write!(f, "invalid:{r}"),
        }
    }
}

/// What a flow's validation needs to know about the best-match unicast route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unicast {
    /// `ORIGINATOR_ID`, else the advertising peer; `None` for a local route.
    pub originator: Option<IpAddr>,
    pub neighbour_as: u32,
    /// Leftmost AS of the route's `AS_PATH`; `None` for a local route.
    pub leftmost_as: Option<u32>,
}

/// The flow side of a validation.
#[derive(Debug, Clone, Copy)]
pub struct Flow {
    pub dest: Option<crate::flowspec::Prefix>,
    pub originator: IpAddr,
    /// eBGP only: `(peer AS, leftmost AS of the path)`.
    pub ebgp: Option<(u32, Option<u32>)>,
    /// RFC 9117 (b.2): the flow's `AS_PATH` has no non-confederation segment.
    pub local_domain: bool,
}

/// The first destination prefix component of a rule.
#[must_use]
pub fn dest_of(f: &FlowSpec) -> Option<crate::flowspec::Prefix> {
    f.components.iter().find_map(|c| match c {
        Component::Dest(p) => Some(*p),
        _ => None,
    })
}

/// `mode.disable_dest_prefix_rule`: rule (a) is not enforced (peer-group
/// knob); a flow without a usable destination prefix then skips (b) and (c),
/// which need one, and (for eBGP) falls back to the RFC 8955 neighbour-AS
/// check. `mode.rfc8955_strict` selects RFC 8955 as written instead of
/// RFC 9117. `best` is the longest-prefix-match lookup of one exact prefix in
/// the Loc-RIB; `more_specific` the neighbouring ASes of every received
/// unicast route strictly inside the given prefix.
pub fn validate(
    flow: &Flow,
    mode: nos_proto::BgpFlowspecValidation,
    best: impl Fn(IpNet) -> Option<Unicast>,
    more_specific: impl Fn(IpNet) -> Vec<u32>,
) -> FlowValidity {
    use FlowValidity::{Invalid, Valid};
    use InvalidReason as R;
    let (relax_dest, strict) = (mode.disable_dest_prefix_rule, mode.rfc8955_strict);
    let dest = match flow.dest {
        Some(p) if p.offset == 0 => Some(p.net.trunc()),
        Some(_) if !relax_dest => return Invalid(R::OffsetNotZero),
        None if !relax_dest => return Invalid(R::NoDestinationPrefix),
        _ => None,
    };
    // RFC 8955 §6 checks the neighbour AS up front; RFC 9117 only when there
    // is no destination (hence no best match) to compare with.
    if (strict || dest.is_none())
        && let Some((peer_as, leftmost)) = flow.ebgp
        && leftmost != Some(peer_as)
    {
        return Invalid(R::BadNeighbourAs);
    }
    let Some(dest) = dest else { return Valid };
    let Some(b) = (0..=dest.prefix_len()).rev().find_map(|len| {
        let net = IpNet::new(dest.addr(), len).ok()?.trunc();
        best(net)
    }) else {
        // RFC 9117 central controller: nothing to compare with, skip (c).
        return if !strict && flow.local_domain {
            Valid
        } else {
            Invalid(R::NoUnicastRoute)
        };
    };
    if !strict
        && let Some((_, leftmost)) = flow.ebgp
        && (leftmost.is_none() || leftmost != b.leftmost_as)
    {
        return Invalid(R::LeftmostAsMismatch);
    }
    if b.originator != Some(flow.originator) && (strict || !flow.local_domain) {
        return Invalid(R::OriginatorMismatch);
    }
    if more_specific(dest).iter().any(|a| *a != b.neighbour_as) {
        return Invalid(R::MoreSpecificFromOtherAs);
    }
    Valid
}

/// `(is_v6, address as a number, length)`: orders a prefix's descendants
/// contiguously by address.
type IndexKey = (bool, u128, u8);

fn key(net: IpNet) -> IndexKey {
    match net.trunc() {
        IpNet::V4(n) => (false, u128::from(u32::from(n.addr())), n.prefix_len()),
        IpNet::V6(n) => (true, u128::from(n.addr()), n.prefix_len()),
    }
}

/// The last address of `net` as a number.
fn last(net: IpNet) -> u128 {
    match net.trunc() {
        IpNet::V4(n) => u128::from(u32::from(n.broadcast())),
        IpNet::V6(n) => u128::from(n.broadcast()),
    }
}

#[cfg(test)]
impl FlowIndexes {
    pub fn entries(&self) -> usize {
        self.flow_entries
    }
}

/// The derived indexes behind incremental revalidation. Both are rebuildable
/// from the RIB tables; neither is ever authoritative.
#[derive(Default)]
pub struct FlowIndexes {
    /// Set once the first Flowspec rule is learned: until then no unicast
    /// change pays anything for Flowspec.
    pub on: bool,
    /// Flow destination -> the flows (peer, rule) using it. Entries of
    /// withdrawn flows are dropped lazily (`BgpRib::revalidate_around`) and
    /// by `compact_flows`.
    flows: BTreeMap<IndexKey, HashSet<(IpAddr, FlowspecKey)>>,
    flow_entries: usize,
    /// Rules revalidated so far (what the tests count to prove a unicast
    /// change only revisits the overlapping ones).
    pub visits: u64,
    /// Received unicast prefix -> sorted, deduplicated neighbouring ASes.
    unicast: BTreeMap<IndexKey, Vec<u32>>,
}

impl BgpRib {
    /// `route`'s neighbouring AS: the leftmost AS of its path, else the AS of
    /// the peer it came from, else ours.
    pub(super) fn neighbour_as_of(
        &self,
        origin: RouteOrigin,
        path: &crate::as_path::AsPath,
    ) -> u32 {
        path.neighbor_as()
            .or_else(|| match origin {
                RouteOrigin::Peer(p) => self.peer_asns.get(&p).copied(),
                RouteOrigin::Local => None,
            })
            .unwrap_or(self.local_asn)
    }

    /// Refreshes `prefix`'s entry of the neighbouring-AS index from every
    /// peer's Adj-RIB-In.
    fn index_unicast(&mut self, prefix: IpNet) {
        let this = &*self;
        let mut ases: Vec<u32> =
            this.adj_rib_in
                .iter()
                .flat_map(|(peer, t)| {
                    t.get(&prefix).into_iter().flatten().map(move |(_, r)| {
                        this.neighbour_as_of(RouteOrigin::Peer(*peer), &r.as_path)
                    })
                })
                .collect();
        ases.sort_unstable();
        ases.dedup();
        if ases.is_empty() {
            self.flow_ix.unicast.remove(&key(prefix));
        } else {
            self.flow_ix.unicast.insert(key(prefix), ases);
        }
    }

    /// Turns the indexes on, filling the unicast one from what is already held.
    pub(super) fn enable_flow_indexes(&mut self) {
        if self.flow_ix.on {
            return;
        }
        self.flow_ix.on = true;
        let prefixes: Vec<IpNet> = self
            .adj_rib_in
            .values()
            .flat_map(|t| t.keys().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        for p in prefixes {
            self.index_unicast(p);
        }
    }

    /// Records a (new or re-announced) rule in the destination index and
    /// validates it.
    pub(super) fn track_flow(&mut self, peer: IpAddr, k: &FlowspecKey) {
        if let Some(d) = dest_of(&k.1).filter(|p| p.offset == 0)
            && self
                .flow_ix
                .flows
                .entry(key(d.net))
                .or_default()
                .insert((peer, k.clone()))
        {
            self.flow_ix.flow_entries += 1;
        }
        self.compact_flows();
        self.revalidate_flow(peer, k);
        // An attribute change (or a reject) re-selects even when the
        // validity did not move.
        self.select_flow(k);
    }

    /// Drops index entries of rules no longer held once they outnumber the
    /// live rules two to one.
    fn compact_flows(&mut self) {
        let live: usize = self
            .flowspec_adj_rib_in
            .values()
            .map(std::collections::HashMap::len)
            .sum();
        if self.flow_ix.flow_entries <= 2 * live + 64 {
            return;
        }
        let held = &self.flowspec_adj_rib_in;
        self.flow_ix.flow_entries = 0;
        self.flow_ix.flows.retain(|_, set| {
            set.retain(|(p, k)| held.get(p).is_some_and(|t| t.contains_key(k)));
            self.flow_ix.flow_entries += set.len();
            !set.is_empty()
        });
    }

    /// The flow side of validating `r` (received from `peer`) and the peer's
    /// validation knobs.
    pub(super) fn flow_side(
        &self,
        peer: IpAddr,
        r: &super::FlowspecRoute,
    ) -> (Flow, nos_proto::BgpFlowspecValidation) {
        let ibgp = r.learned_via_ibgp;
        let peer_as = self.peer_asns.get(&peer).copied().filter(|a| *a != 0);
        let mode = self
            .flowspec_validation
            .get(&peer)
            .copied()
            .unwrap_or_default();
        // RFC 9117 section 2: a confederation member counts as iBGP.
        let ibgp = ibgp || (!mode.rfc8955_strict && self.confed_peers.contains(&peer));
        let path = &r.attributes.as_path;
        let flow = Flow {
            dest: dest_of(&r.nlri),
            originator: r.attributes.originator_id.map_or(peer, IpAddr::V4),
            ebgp: peer_as.filter(|_| !ibgp).map(|a| (a, path.neighbor_as())),
            local_domain: path.segments().all(|(k, _)| k.is_confed()),
        };
        (flow, mode)
    }

    /// The validity of one held rule, from the current unicast state.
    fn flow_validity(&self, peer: IpAddr, k: &FlowspecKey) -> Option<FlowValidity> {
        let r = self.flowspec_adj_rib_in.get(&peer)?.get(k)?;
        let (flow, mode) = self.flow_side(peer, r);
        let best = |net: IpNet| {
            let b = self.loc_rib.get(&net)?;
            Some(Unicast {
                originator: match b.origin {
                    RouteOrigin::Peer(p) => Some(b.originator_id.map_or(p, IpAddr::V4)),
                    RouteOrigin::Local => None,
                },
                neighbour_as: self.neighbour_as_of(b.origin, &b.as_path),
                leftmost_as: b.as_path.neighbor_as(),
            })
        };
        let more_specific = |net: IpNet| {
            let (fam, start, _) = key(net);
            let end = last(net);
            self.flow_ix
                .unicast
                .range((fam, start, 0)..=(fam, end, u8::MAX))
                .filter(|((_, _, len), _)| *len > net.prefix_len())
                .flat_map(|(_, v)| v.iter().copied())
                .collect()
        };
        Some(validate(&flow, mode, best, more_specific))
    }

    /// Re-validates one rule and logs when its state changed.
    pub(super) fn revalidate_flow(&mut self, peer: IpAddr, k: &FlowspecKey) {
        let Some(new) = self.flow_validity(peer, k) else {
            return;
        };
        self.flow_ix.visits += 1;
        let Some(r) = self
            .flowspec_adj_rib_in
            .get_mut(&peer)
            .and_then(|t| t.get_mut(k))
        else {
            return;
        };
        if r.validity != Some(new) {
            r.validity = Some(new);
            info!(peer = %peer, family = %r.family, flow = %r.nlri, validity = %new, "flowspec validity changed");
            self.select_flow(k);
        }
    }

    /// Everything a change of unicast `prefix` can affect: refreshes the
    /// neighbouring-AS index and revalidates the flows whose destination
    /// overlaps it (an ancestor, for the best match and rule (c); or a
    /// descendant, whose best match it may become).
    pub(super) fn revalidate_around(&mut self, prefix: IpNet) {
        if !self.flow_ix.on {
            return;
        }
        self.index_unicast(prefix);
        if self.flow_ix.flows.is_empty() {
            return;
        }
        let (fam, start, plen) = key(prefix);
        let mut hit: HashSet<(IpAddr, FlowspecKey)> = HashSet::new();
        for len in 0..=plen {
            let net = IpNet::new(prefix.addr(), len)
                .expect("len <= prefix length")
                .trunc();
            if let Some(s) = self.flow_ix.flows.get(&key(net)) {
                hit.extend(s.iter().cloned());
            }
        }
        for (_, s) in self
            .flow_ix
            .flows
            .range((fam, start, plen)..=(fam, last(prefix), u8::MAX))
        {
            hit.extend(s.iter().cloned());
        }
        for (peer, k) in hit {
            self.revalidate_flow(peer, &k);
        }
    }
}

#[cfg(test)]
#[path = "flowspec_validate_tests.rs"]
mod tests;
