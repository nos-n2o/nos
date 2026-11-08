//! Best-path decision process and outbound advertisement building (RFC 4271
//! §9.1.2.2; RFC 9234 OTC egress) — the stateless free functions `BgpRib`
//! calls. Moved verbatim out of `rib.rs`.

use super::{
    apply_verdict, family_of, message, next_hop_family_ok, policy_segments, to_policy_input,
    warn_next_hop_family, AddressFamily, AdvertisedRoute, Arc, AsPath, HashMap, Instant, IpAddr,
    IpNet, Ipv4Addr, NextHopMode, PeerOutbox, PolicyPeer, RibRoute, RouteOrigin,
    DEFAULT_LOCAL_PREF,
};
use nos_proto::BgpRole::{Customer, Peer, Provider, RouteServer, RouteServerClient};

pub(super) fn redistributed_route() -> RibRoute {
    RibRoute {
        origin: RouteOrigin::Local,
        as_path: Arc::default(),
        bgp_origin: message::Origin::Igp,
        local_pref: DEFAULT_LOCAL_PREF,
        med: None,
        learned_via_ibgp: false,
        learned_via_confed: false,
        router_id: None,
        next_hop: None,
        received_at: Instant::now(),
        originator_id: None,
        atomic_aggregate: false,
        aggregator: None,
        otc: None,
        cluster_list: Vec::new().into(),
        communities: Vec::new(),
        extended_communities: Vec::new(),
        large_communities: Vec::new(),
        validation_state: nos_rpl::ValidationState::NotFound,
        received_ov: None,
    }
}

/// `ORIGIN` rank for the decision process's step 4 — lower wins (`Igp` <
/// `Egp` < `Incomplete`), using the enum's own discriminant values.
pub(super) fn origin_rank(origin: message::Origin) -> u8 {
    origin as u8
}

/// The "neighboring AS" a route was received from, per RFC 4271 §9.1.2.2's
/// MED comparison rule — the nearest-hop entry in `AS_PATH`. `None` for an
/// empty `AS_PATH` (e.g. a route relayed by an iBGP peer that never went
/// through an eBGP hop), which makes it ineligible for MED comparison
/// against anything.
pub(super) fn neighboring_as(route: &RibRoute) -> Option<u32> {
    route.as_path.neighbor_as()
}

/// Step 5: lower `MULTI_EXIT_DISC` wins, but only between routes sharing
/// the same neighboring AS — otherwise this step is skipped entirely
/// (`Equal`). Missing MED is treated as 0, the common convention.
pub(super) fn compare_med(a: &RibRoute, b: &RibRoute) -> std::cmp::Ordering {
    match (neighboring_as(a), neighboring_as(b)) {
        (Some(x), Some(y)) if x == y => b.med.unwrap_or(0).cmp(&a.med.unwrap_or(0)),
        _ => std::cmp::Ordering::Equal,
    }
}

/// Decision step 6 rank, higher wins: external 2, confederation-external 1,
/// internal 0.
pub(super) fn peer_rank(route: &RibRoute) -> u8 {
    if route.learned_via_ibgp {
        0
    } else if route.learned_via_confed {
        1
    } else {
        2
    }
}

/// A route's next hops (its multipath set, sorted, at least one) plus its
/// backup (runner-up path's next hop), as pushed to `nos-ribd`; the `bool` is
/// an RFC 7999 blackhole (no hops, a discard route).
pub type Hops = (Vec<IpAddr>, Option<IpAddr>, bool);

/// The next hop of the best candidate whose real next hop is none of
/// `primary` (the winner's multipath set) — the backup path. `None` when
/// there is no such candidate (a single path, or every other path shares a
/// primary next hop, which a backup route couldn't protect against anyway).
pub(super) fn runner_up_next_hop(
    candidates: &[Candidate],
    primary: &[IpAddr],
    igp: &HashMap<IpNet, u32>,
) -> Option<IpAddr> {
    if candidates.len() < 2 {
        return None;
    }
    let others: Vec<Candidate> = candidates
        .iter()
        .filter(|(r, _)| r.next_hop.is_some_and(|nh| !primary.contains(&nh)))
        .cloned()
        .collect();
    best_path(&others, igp)?.next_hop
}

/// Cost of the longest `igp` prefix covering `addr`, `None` if nothing does.
pub(super) fn igp_lookup(igp: &HashMap<IpNet, u32>, addr: IpAddr) -> Option<u32> {
    if igp.is_empty() {
        return None;
    }
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (0..=max)
        .rev()
        .find_map(|len| igp.get(&IpNet::new(addr, len).ok()?.trunc()))
        .copied()
}

/// Cost of the longest `igp` prefix covering `next_hop`; 0 when there is no
/// next hop (a local route) or nothing covers it (only reachable before the
/// first IGP poll — afterwards such a candidate is unfeasible, see
/// `BgpRib::next_hop_feasible`).
pub(super) fn igp_cost(igp: &HashMap<IpNet, u32>, next_hop: Option<IpAddr>) -> u32 {
    next_hop.and_then(|addr| igp_lookup(igp, addr)).unwrap_or(0)
}

/// One best-path candidate: the route and its path id — `(route.origin, id)`
/// is its `PathKey`. The id breaks the final tie (step 10).
pub(super) type Candidate = (RibRoute, u32);

/// Index of the best candidate, deterministic-MED (RFC 4271 §9.1.2.2(c)):
/// the best path of each neighbouring-AS group (where MED is a plain key, so
/// `decision_cmp` is total), then the best of those winners (distinct
/// neighbouring ASes, MED never consulted). Independent of input order.
pub(super) fn best_index(candidates: &[Candidate], igp: &HashMap<IpNet, u32>) -> Option<usize> {
    let mut winners: HashMap<Option<u32>, usize> = HashMap::new();
    for (i, c) in candidates.iter().enumerate() {
        winners
            .entry(neighboring_as(&c.0))
            .and_modify(|w| {
                if decision_cmp(c, &candidates[*w], igp).is_gt() {
                    *w = i;
                }
            })
            .or_insert(i);
    }
    winners
        .into_values()
        .max_by(|&a, &b| decision_cmp(&candidates[a], &candidates[b], igp))
}

/// The full RFC 4271 §9.1.2.2 decision process — see the module doc
/// comment for the ten-step order.
pub(super) fn best_path(candidates: &[Candidate], igp: &HashMap<IpNet, u32>) -> Option<RibRoute> {
    best_index(candidates, igp).map(|i| candidates[i].0.clone())
}

/// `candidates` best first, same deterministic-MED rule as `best_index`
/// (`rank(..)[0]` is `best_path`). Never hand a mixed-AS set to
/// `sort_by`/`max_by` with `decision_cmp` directly: it is only a total order
/// within one neighbouring AS, and `sort_by` may panic otherwise.
pub(super) fn rank(candidates: &[Candidate], igp: &HashMap<IpNet, u32>) -> Vec<Candidate> {
    let mut groups: HashMap<Option<u32>, Vec<Candidate>> = HashMap::new();
    for c in candidates {
        groups
            .entry(neighboring_as(&c.0))
            .or_default()
            .push(c.clone());
    }
    let mut groups: Vec<std::collections::VecDeque<Candidate>> = groups
        .into_values()
        .map(|mut g| {
            g.sort_by(|a, b| decision_cmp(b, a, igp));
            g.into()
        })
        .collect();
    let mut out = Vec::with_capacity(candidates.len());
    while let Some(g) = (0..groups.len())
        .filter(|&g| !groups[g].is_empty())
        .max_by(|&a, &b| decision_cmp(&groups[a][0], &groups[b][0], igp))
    {
        out.extend(groups[g].pop_front());
    }
    out
}

/// `best_path`'s comparator over two `(route, source_peer)` candidates:
/// `Greater` means `a` is preferred. Total only when both share a
/// neighbouring AS (MED is skipped across ASes): use `rank`/`best_index`
/// for mixed sets.
pub(super) fn decision_cmp(
    (a, a_id): &Candidate,
    (b, b_id): &Candidate,
    igp: &HashMap<IpNet, u32>,
) -> std::cmp::Ordering {
    multipath_cmp(a, b, igp)
        .then_with(|| {
            // Step 8: oldest route wins, only between two
            // eBGP-learned candidates (RFC 4271's anti-flap rule).
            if peer_rank(a) == 2 && peer_rank(b) == 2 {
                b.received_at.cmp(&a.received_at)
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .then_with(|| {
            // Step 9: lowest advertising peer's BGP Identifier.
            match (a.router_id, b.router_id) {
                (Some(a_id), Some(b_id)) => b_id.cmp(&a_id),
                _ => std::cmp::Ordering::Equal,
            }
        })
        .then_with(|| {
            // Step 10: lowest peer address, then lowest RFC 7911 path
            // id (two paths of one peer tie on steps 9 and 10), so the
            // order is total — reverse the comparison since `max_by`
            // favors the greater element. A local route never reaches
            // this arm against a peer one (already decided by step 2).
            match (a.origin, b.origin) {
                (RouteOrigin::Peer(x), RouteOrigin::Peer(y)) => (y, b_id).cmp(&(x, a_id)),
                _ => std::cmp::Ordering::Equal,
            }
        })
}

/// Decision steps 1–7 — the ones two paths must tie on to be installed
/// together as multipath (`multipath_next_hops`); `Greater` means `a` wins.
pub(super) fn multipath_cmp(
    a: &RibRoute,
    b: &RibRoute,
    igp: &HashMap<IpNet, u32>,
) -> std::cmp::Ordering {
    a.local_pref
        .cmp(&b.local_pref)
        .then_with(|| {
            // Step 2 (not an RFC step): a Local route beats any
            // Peer(_) route.
            let a_is_local = matches!(a.origin, RouteOrigin::Local);
            let b_is_local = matches!(b.origin, RouteOrigin::Local);
            a_is_local.cmp(&b_is_local)
        })
        .then_with(|| b.as_path.selection_len().cmp(&a.as_path.selection_len())) // step 3
        .then_with(|| origin_rank(b.bgp_origin).cmp(&origin_rank(a.bgp_origin))) // step 4
        .then_with(|| compare_med(a, b)) // step 5
        // Step 6: eBGP beats confederation-eBGP beats iBGP (RFC 5065 §5.3).
        .then_with(|| peer_rank(a).cmp(&peer_rank(b)))
        // Step 7: lower IGP cost to the next hop wins (evaluated
        // lazily — only reached when steps 1-6 tie).
        .then_with(|| igp_cost(igp, b.next_hop).cmp(&igp_cost(igp, a.next_hop)))
}

/// The next hops installed for `best`'s prefix: `best`'s own, plus those of
/// every other peer-learned candidate tying with it on decision steps 1–7
/// (`multipath_cmp`) and learned from the same neighbouring AS (the usual
/// non-relaxed vendor rule — no RFC defines multipath selection; RFC 2991/
/// 2992 only cover forwarding). Deduplicated, picked in decision order
/// (steps 8–10 between the ties), capped at `max`, then sorted so the push
/// diff is stable. Empty when `best` has no next hop (a `Local` route).
pub(super) fn multipath_next_hops(
    candidates: &[Candidate],
    best: &RibRoute,
    igp: &HashMap<IpNet, u32>,
    max: usize,
) -> Vec<IpAddr> {
    let Some(best_hop) = best.next_hop else {
        return Vec::new();
    };
    let mut hops = vec![best_hop];
    for r in multipath_ties(candidates, best, igp, usize::MAX) {
        if hops.len() >= max {
            break;
        }
        let hop = r.next_hop.expect("filtered");
        if !hops.contains(&hop) {
            hops.push(hop);
        }
    }
    hops.sort_unstable();
    hops
}

/// The candidates eligible to share `best`'s multipath set (decision order,
/// not deduplicated by next hop, so a caller may keep two paths to one next
/// hop that differ otherwise): peer-learned, tying on steps 1-7 and from the
/// same neighbouring AS. `best` itself is among them, first (it wins every
/// decision). Shared by unicast and VPN import.
pub(super) fn multipath_ties<'a>(
    candidates: &'a [Candidate],
    best: &RibRoute,
    igp: &HashMap<IpNet, u32>,
    max: usize,
) -> Vec<&'a RibRoute> {
    let mut ties: Vec<&Candidate> = candidates
        .iter()
        .filter(|(r, _)| {
            r.next_hop.is_some()
                && !matches!(r.origin, RouteOrigin::Local)
                && neighboring_as(r) == neighboring_as(best)
                && multipath_cmp(r, best, igp).is_eq()
        })
        .collect();
    ties.sort_by(|a, b| decision_cmp(b, a, igp));
    ties.into_iter().map(|(r, _)| r).take(max).collect()
}

/// RFC 9234 §5 ingress rules 1 and 2: is a route with `otc` a leak from a
/// neighbor whose role is `remote`?
pub(super) fn otc_leak(remote: nos_proto::BgpRole, otc: Option<u32>, peer_as: u32) -> bool {
    match (remote, otc) {
        (Customer | RouteServerClient, Some(_)) => true,
        (Peer, Some(o)) => o != peer_as,
        _ => false,
    }
}

/// RFC 1997: does a well-known community on a route *received from a peer*
/// forbid sending it to `outbox`? Peer classes: own member AS (`is_ibgp`),
/// another member AS of our confederation (`is_confed`), outside. Locally
/// originated routes are never filtered.
pub(super) fn well_known_blocks(best: &RibRoute, outbox: &PeerOutbox) -> bool {
    use message::{COMMUNITY_NO_ADVERTISE, COMMUNITY_NO_EXPORT, COMMUNITY_NO_EXPORT_SUBCONFED};
    if !matches!(best.origin, RouteOrigin::Peer(_)) {
        return false;
    }
    let has = |c| best.communities.contains(&c);
    let outside = !outbox.is_ibgp && !outbox.is_confed;
    has(COMMUNITY_NO_ADVERTISE)
        || (outside && has(COMMUNITY_NO_EXPORT))
        || (!outbox.is_ibgp && has(COMMUNITY_NO_EXPORT_SUBCONFED))
}

/// The part of `build_advertisement` that decides whether `best` is a
/// candidate for `peer` at all, before any policy: family negotiated, no echo
/// to the source peer, iBGP split horizon / RFC 4456 reflection. `Some(r)`
/// with `r` = whether it is reflected. Shared with BMP's pre-policy
/// Adj-RIB-Out (RFC 8671 section 5.2) so the two candidate sets cannot drift.
pub(super) fn eligibility(
    family: AddressFamily,
    best: &RibRoute,
    peer: IpAddr,
    outbox: &PeerOutbox,
    source_is_rr_client: bool,
) -> Option<bool> {
    if !outbox.negotiated_afs.contains(&family) {
        return None;
    }
    if best.origin == RouteOrigin::Peer(peer) {
        // Never echo a route back to the peer it came from.
        return None;
    }
    // RFC 4456 §6: a route learned via iBGP is reflected to another iBGP
    // peer only when the source or the destination is a configured
    // route-reflector client — otherwise the standard iBGP split-horizon
    // rule (no reflection, full mesh assumed) still applies unchanged.
    let ibgp_to_ibgp =
        matches!(best.origin, RouteOrigin::Peer(_)) && best.learned_via_ibgp && outbox.is_ibgp;
    let reflecting = ibgp_to_ibgp && (source_is_rr_client || outbox.is_rr_client);
    (!ibgp_to_ibgp || reflecting).then_some(reflecting)
}

/// Decides whether `best` should be advertised to `peer` and, if so, rewrites
/// it for that destination. `None` covers every ineligibility case
/// (split-horizon, source-peer echo, family not negotiated by this peer, no
/// local address for next-hop-self). `source_is_rr_client` is whether the
/// peer `best` was learned from (if any) is a route-reflector client;
/// `cluster_id` is this instance's own effective RFC 4456 cluster-id, used
/// only when actually reflecting. `flow` is `None` for a unicast route; for
/// a Flowspec rule (`flowspec_out`) its family and the peer's Flowspec
/// export policy, and the unicast-only RFC 9234 and RFC 8097 steps are
/// skipped.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_advertisement(
    prefix: IpNet,
    best: &RibRoute,
    peer: IpAddr,
    outbox: &PeerOutbox,
    local_asn: u32,
    source_is_rr_client: bool,
    cluster_id: Ipv4Addr,
    flow: Option<(AddressFamily, &nos_rpl::CompiledPolicy, Option<[u8; 8]>)>,
) -> Option<AdvertisedRoute> {
    let family = flow.map_or_else(|| family_of(prefix), |(f, ..)| f);
    let reflecting = eligibility(family, best, peer, outbox, source_is_rr_client)?;
    // RFC 1997, on the stored (post-import-policy) route and before the
    // export policy, so only an import policy can lift it.
    if well_known_blocks(best, outbox) {
        tracing::debug!(%peer, %prefix, "advertisement suppressed by well-known community");
        return None;
    }

    // This destination peer-group's resolved export policy (`deny-all` by
    // default — see root `CLAUDE.md`'s "Default-deny rollout impact").
    // `best` is shadowed with a possibly policy-adjusted owned copy so every
    // rewrite below (`AS_PATH`, `LOCAL_PREF`, `MED`, reflection) sees the
    // policy's `local_pref`/`med`, not the pre-policy values.
    let mut adjusted = best.clone();
    // RFC 4271 §5.1.4: a MED received from a neighbouring AS is never
    // passed on to another AS. It is cleared before the export policy runs,
    // so a MED the policy sets (or a locally originated one) is still sent.
    // RFC 7947 §2.2: a route server passes MED through unchanged to its clients.
    // RFC 5065 §5.3: kept within the confederation too.
    if !outbox.is_ibgp
        && !outbox.is_confed
        && !outbox.is_rs_client
        && matches!(best.origin, RouteOrigin::Peer(_))
    {
        adjusted.med = None;
    }
    // RFC 8326 §4.2: tag unicast and VPN exports toward eBGP before the
    // policy, which may strip or override it. Flowspec stays untagged.
    if outbox.gs_send
        && !outbox.is_ibgp
        && !outbox.is_confed
        && flow.is_none_or(|(f, ..)| crate::fsm::is_vpn(f))
        && !adjusted
            .communities
            .contains(&crate::message::COMMUNITY_GRACEFUL_SHUTDOWN)
    {
        adjusted
            .communities
            .push(crate::message::COMMUNITY_GRACEFUL_SHUTDOWN);
    }
    let segs = policy_segments(&adjusted);
    let verdict = nos_rpl::vm::run(
        flow.map_or(&*outbox.export_policy, |(_, p, _)| p),
        &to_policy_input(
            prefix,
            &adjusted,
            &segs,
            Some(
                PolicyPeer::new(peer, outbox.remote_asn).with_roles(if flow.is_none() {
                    outbox.policy_roles
                } else {
                    (None, None)
                }),
            ),
            flow.and_then(|(.., rd)| rd),
        ),
    );
    let nh_edit = apply_verdict(
        &mut adjusted,
        verdict,
        flow.is_none().then_some((prefix, outbox.local_addr)),
    )?;
    // RFC 9234 §5 egress, after policy so it cannot defeat it (unicast only).
    match (outbox.remote_role, adjusted.otc) {
        _ if flow.is_some() => {}
        (Some(Customer | Peer | RouteServerClient), None) => {
            adjusted.otc = Some(outbox.local_as.map_or(local_asn, |l| l.asn));
        }
        (Some(Provider | Peer | RouteServer), Some(_)) => return None,
        _ => {}
    }
    // RFC 4360 §6: non-transitive extended communities (type bit 0x40)
    // don't leave the AS (kept across a confederation, like MED).
    if !outbox.is_ibgp && !outbox.is_confed {
        adjusted.extended_communities.retain(|c| c >> 62 & 1 == 0);
    }
    // RFC 8097 §2: at most one, regenerated from our own state.
    adjusted
        .extended_communities
        .retain(|&c| !crate::rpki::community::is_ov(c));
    if outbox.is_ibgp && outbox.announce_rpki_state && flow.is_none() {
        adjusted
            .extended_communities
            .push(crate::rpki::community::encode(adjusted.validation_state));
    }
    let best = adjusted;
    let best = &best;

    // RFC 7947 §2.2.1: a route server passes NEXT_HOP through unchanged, so
    // a route-server client defaults to `Unchanged` like an iBGP peer. An
    // explicit `next-hop self` still wins.
    let mode = outbox.next_hop_mode.unwrap_or(
        if outbox.is_ibgp || outbox.is_confed || outbox.is_rs_client {
            NextHopMode::Unchanged
        } else {
            NextHopMode::SelfAddress
        },
    );
    let next_hop = match (nh_edit, mode) {
        (nos_rpl::NextHopSet::Addr(a), _) => a,
        (nos_rpl::NextHopSet::SelfAddress, _) | (_, NextHopMode::SelfAddress) => {
            outbox.local_addr?
        }
        (nos_rpl::NextHopSet::Unchanged, NextHopMode::Unchanged) => {
            best.next_hop.or(outbox.local_addr)?
        }
    };
    // A next hop of the wrong family (policy `self` fallback included) is
    // never advertised: drop the route instead.
    if flow.is_none() && !next_hop_family_ok(prefix, next_hop, outbox.local_addr) {
        warn_next_hop_family(prefix, next_hop, "advertisement dropped");
        return None;
    }

    // `as_path` is only replaced (never mutated in place) by an RPL
    // `prepend`, so when the script didn't touch it it's still shared with whatever's stored in loc_rib/adj_rib_in at this
    // point — `Arc::clone` is a refcount bump, not a deep copy. The one
    // real content copy this function can't avoid is the eBGP prepend
    // case, where the result genuinely differs per destination peer;
    // `Arc::make_mut` does that copy directly into an owned buffer instead
    // of cloning twice (once wastefully inside `adjusted = best.clone()`
    // above, once again here) like the pre-Arc version of this code did.
    let mut as_path = Arc::clone(&best.as_path);
    if outbox.is_confed {
        // RFC 5065 §4.1: our member AS, in an AS_CONFED_SEQUENCE.
        Arc::make_mut(&mut as_path).prepend_confed_seq(local_asn);
    } else if !outbox.is_ibgp {
        // RFC 5065 §4.1: outside the confederation, its segments go and
        // only the identifier is prepended.
        if as_path.has_confed() {
            Arc::make_mut(&mut as_path).strip_confed();
        }
        // RFC 7947 route-server clients get a fully transparent AS_PATH: no
        // local-ASN prepend, even though they're always eBGP (enforced at
        // config-validation time — see `bgp_instance::valid_route_reflection_and_server`).
        if !outbox.is_rs_client {
            outbox.prepend_external(Arc::make_mut(&mut as_path), local_asn);
        }
    }
    let as_path: AsPath = Arc::try_unwrap(as_path).unwrap_or_else(|arc| (*arc).clone());
    let local_pref = (outbox.is_ibgp || outbox.is_confed).then_some(best.local_pref);
    let med = best.med;

    let (originator_id, cluster_list) = if reflecting {
        let mut clusters = (*best.cluster_list).clone();
        clusters.insert(0, cluster_id);
        (best.originator_id.or(best.router_id), clusters)
    } else {
        (None, Vec::new())
    };

    Some(AdvertisedRoute {
        prefix,
        as_path,
        next_hop,
        local_pref,
        med,
        origin: best.bgp_origin,
        use_mp: outbox.mp_bgp_negotiated,
        originator_id,
        cluster_list,
        communities: best.communities.clone(),
        extended_communities: best.extended_communities.clone(),
        large_communities: best.large_communities.clone(),
        atomic_aggregate: best.atomic_aggregate,
        aggregator: best.aggregator,
        otc: best.otc,
        path_id: None,
    })
}
