//! Adj-RIB-In: per-peer path tables, UPDATE handling and withdrawal.
//! Moved verbatim out of `rib.rs`.

use super::stats::bump;
use super::PeerStats;
use super::{
    apply_policy, debug, family_index, info, message, otc_leak, ov_state, warn, AddressFamily, Arc,
    BgpRib, CompiledPolicy, Damping, EvpnNlri, EvpnRoute, FlowspecKey, FlowspecRoute, GsKnobs,
    HashMap, HashSet, Instant, IpAddr, IpNet, Ipv4Addr, MacMobility, PolicyPeer, RibRoute,
    RouteOrigin, SmallVec, UpdateMessage, CHANGE_PENALTY, DEFAULT_LOCAL_PREF, WITHDRAW_PENALTY,
};
use crate::as_path::SegKind;
use nos_proto::BgpRole::{Peer, Provider, RouteServer};

/// A Type-2 route's `(VNI, MAC)` mobility identity, plus its ESI — `None`
/// for every other EVPN route type, which RFC 7432 §15 mobility doesn't
/// apply to.
pub(super) fn evpn_mac_key(nlri: &EvpnNlri) -> Option<(u32, [u8; 6], [u8; 10])> {
    match nlri {
        EvpnNlri::MacIp {
            mac, labels, esi, ..
        } => Some((labels.first().copied().unwrap_or(0), *mac, *esi)),
        _ => None,
    }
}

/// Runs the peer's EVPN import policy over one route (accept/reject only:
/// rewrites are ignored). Type-4 and unknown types bypass it: the ES-Import
/// RT lives on Type-4 only, so an RT match would reject every one.
pub(super) fn evpn_rejected(
    policy: &CompiledPolicy,
    route: &EvpnRoute,
    from: IpAddr,
    peer_as: u32,
    ibgp: bool,
) -> bool {
    let prefix = match &route.nlri {
        EvpnNlri::EthernetSegment { .. } | EvpnNlri::Unknown { .. } => return false,
        EvpnNlri::IpPrefix { prefix, .. } => *prefix,
        // ponytail: Type-1/2/3 have no prefix; scripts see 0.0.0.0/0.
        _ => IpNet::V4(ipnet::Ipv4Net::default()),
    };
    let input = nos_rpl::Input {
        prefix,
        bgp: nos_rpl::BgpInput {
            origin: nos_rpl::Origin::Igp,
            // EVPN routes carry no AS_PATH here: empty segments and path_length 0 are correct (#868); if one ever does, fill it via `policy_segments`.
            as_path: &[],
            as_path_segments: &[],
            local_pref: DEFAULT_LOCAL_PREF,
            med: None,
            next_hop: Some(route.next_hop),
            learned_via_ibgp: ibgp,
            router_id: None,
            originator_id: None,
            cluster_list: &[],
            peer: Some(from),
            peer_as,
            communities: &[],
            extended_communities: &route.extended_communities,
            large_communities: &[],
            validation_state: nos_rpl::ValidationState::NotFound,
            rd: None,
            local_role: None,
            remote_role: None,
            otc: None,
        },
    };
    !matches!(
        nos_rpl::vm::run(policy, &input),
        nos_rpl::Verdict::Accept { .. }
    )
}

/// Registers a Type-2 route's `(VNI, MAC)` as a mobility candidate (nothing
/// for other route types).
pub(super) fn register_mobility(mac_mobility: &mut MacMobility, route: &EvpnRoute) {
    if let Some((vni, mac, esi)) = evpn_mac_key(&route.nlri) {
        let (seq, sticky) = route
            .extended_communities
            .iter()
            .find_map(|c| nos_proto::evpn_id::parse_mac_mobility(*c))
            .unwrap_or((0, false));
        mac_mobility.candidate(vni, mac, route.next_hop, esi, seq, sticky, Instant::now());
    }
}

/// Stores one `MP_REACH_NLRI` batch's EVPN routes in a peer's EVPN Adj-RIB-In,
/// logging only routes that are new or changed, and registers each Type-2's
/// `(VNI, MAC)` as an RFC 7432 §15 mobility candidate. A route the peer's
/// EVPN import policy (`ctx`: policy, peer AS, iBGP flag; `None` accepts
/// all) rejects is treated as a withdrawal and never reaches mobility.
#[allow(clippy::too_many_arguments)]
pub(super) fn learn_evpn(
    table: &mut HashMap<EvpnNlri, EvpnRoute>,
    mut retain: Option<&mut HashMap<EvpnNlri, EvpnRoute>>,
    mac_mobility: &mut MacMobility,
    from: IpAddr,
    mp: &message::MpReachNlri,
    extended_communities: &[u64],
    pmsi: Option<message::Pmsi>,
    ctx: Option<(&CompiledPolicy, u32, bool)>,
    communities: &[u32],
    gs: Option<GsKnobs>,
    bmp: Option<&crate::bmp::Hub>,
    stats: &mut PeerStats,
) {
    // RFC 8326, eBGP only (`gs` is `None` for iBGP/confed), before policy.
    let mut communities = communities.to_vec();
    let local_pref = if gs.is_some_and(|g| g.apply(&mut communities)) {
        0
    } else {
        DEFAULT_LOCAL_PREF
    };
    for nlri in &mp.evpn {
        let route = EvpnRoute {
            nlri: nlri.clone(),
            next_hop: mp.next_hop,
            pmsi_vni: pmsi.map(|p| p.vni),
            extended_communities: extended_communities.to_vec(),
            communities: communities.clone(),
            local_pref,
        };
        if let Some((policy, peer_as, ibgp)) = ctx
            && evpn_rejected(policy, &route, from, peer_as, ibgp)
        {
            bump(&mut stats.rejected, 1);
            if table.remove(&nlri.route_key()).is_some()
                && let Some(h) = bmp
            {
                h.evpn_post(from, nlri, None);
            }
            if let Some(r) = retain.as_deref_mut() {
                r.insert(nlri.route_key(), route);
            }
            warn!(peer = %from, route_type = nlri.route_type(), route = %nlri, "evpn route rejected by import policy");
            continue;
        }
        if let Some(r) = retain.as_deref_mut() {
            r.remove(&nlri.route_key());
        }
        register_mobility(mac_mobility, &route);
        if table.insert(nlri.route_key(), route.clone()) != Some(route.clone()) {
            if let Some(h) = bmp {
                h.evpn_post(from, nlri, Some(&route));
            }
            info!(peer = %from, route_type = nlri.route_type(), route = %nlri, next_hop = %mp.next_hop, local_pref, communities = %format_args!("[{}]", nos_proto::bgp::fmt_communities(&communities)), "evpn route learned");
        }
    }
}

/// One received Flowspec batch's per-peer context, handed to `learn_flowspec`.
pub(super) struct FlowRx<'a> {
    pub from: IpAddr,
    pub family: AddressFamily,
    pub attributes: &'a message::PathAttributes,
    pub learned_via_ibgp: bool,
    pub router_id: Ipv4Addr,
    /// The peer's Flowspec import policy (`None` accepts all), its AS and
    /// whether it is a confederation peer.
    pub import: Option<(&'a CompiledPolicy, u32, bool)>,
    /// The BMP post-policy tap, when some station wants it.
    pub bmp: Option<&'a crate::bmp::Hub>,
}

/// Stores one `MP_REACH_NLRI` batch's Flowspec rules in a peer's Flowspec
/// Adj-RIB-In through its import policy (a reject is a withdraw), logging
/// only rules that are new or changed, and returns their keys for
/// validation and selection (which need the whole RIB, so the caller runs
/// them). A re-announcement keeps the rule's validity until it is
/// re-validated, and its age when nothing changed.
pub(super) fn learn_flowspec(
    table: &mut HashMap<FlowspecKey, FlowspecRoute>,
    mut retain: Option<&mut HashMap<FlowspecKey, FlowspecRoute>>,
    mp: &message::MpReachNlri,
    rx: &FlowRx<'_>,
    stats: &mut PeerStats,
) -> Vec<FlowspecKey> {
    let (from, family) = (rx.from, rx.family);
    let mut keys = Vec::with_capacity(mp.flowspec.len());
    for nlri in &mp.flowspec {
        let k = (family, nlri.clone());
        let mut route = FlowspecRoute {
            family,
            nlri: nlri.clone(),
            attributes: rx.attributes.clone(),
            learned_via_ibgp: rx.learned_via_ibgp,
            router_id: rx.router_id,
            received_at: Instant::now(),
            validity: None,
        };
        keys.push(k.clone());
        // The policy rewrites the held copy: keep the raw one.
        if let Some(r) = retain.as_deref_mut() {
            r.insert(k.clone(), route.clone());
        }
        if let Some((policy, peer_as, confed)) = rx.import
            && !super::flowspec_out::import_flow(policy, &mut route, from, peer_as, confed)
        {
            bump(&mut stats.rejected, 1);
            if table.remove(&k).is_some()
                && let Some(h) = rx.bmp
            {
                h.flow_post(from, &k, None);
            }
            warn!(peer = %from, family = %family, route = %nlri, "flowspec route rejected by import policy");
            continue;
        }
        if let Some(old) = table.get(&k) {
            route.validity = old.validity;
            if old.attributes == route.attributes {
                route.received_at = old.received_at;
            }
        }
        if table.insert(k.clone(), route.clone()) != Some(route.clone()) {
            if let Some(h) = rx.bmp {
                h.flow_post(from, &k, Some(&route));
            }
            info!(peer = %from, family = %family, route = %nlri, "flowspec route learned");
        }
    }
    keys
}

/// The Flowspec family of an MP batch's AFI.
pub(super) fn flowspec_family(afi: u16) -> Option<AddressFamily> {
    match afi {
        message::AFI_IPV4 => Some(AddressFamily::Ipv4Flowspec),
        message::AFI_IPV6 => Some(AddressFamily::Ipv6Flowspec),
        _ => None,
    }
}

/// Every path one peer holds for a prefix, by RFC 7911 path id (0 on a
/// session that doesn't receive ADD-PATH). One inline entry, so a table
/// without ADD-PATH pays no extra allocation per prefix.
pub(super) type Paths = SmallVec<[(u32, RibRoute); 1]>;

/// What `propagate_add_path` last sent one ADD-PATH peer for one prefix:
/// per source path (`PathKey`), the id it was sent under and the route.
pub(super) type AddPathSent = HashMap<PathKey, (u32, RibRoute)>;

/// A path's identity: its origin and its received RFC 7911 path id (0
/// without ADD-PATH). A `Local` origin is 0 for the redistributed route and
/// 1 for the aggregate, which can coexist on one prefix.
pub(super) type PathKey = (RouteOrigin, u32);

/// One peer's Adj-RIB-In.
pub(super) type PeerTable = HashMap<IpNet, Paths>;

/// How many paths a peer holds, `[ipv4, ipv6]` — kept in step at every
/// Adj-RIB-In mutation by `put_path`/`take_path`.
pub(super) type PathCounts = [u32; 2];

pub(super) fn get_path(table: &PeerTable, prefix: IpNet, id: u32) -> Option<&RibRoute> {
    table
        .get(&prefix)?
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, r)| r)
}

/// Stores path `id` of `prefix` (RFC 7911 §5: a new advertisement for the
/// same path id replaces the old one).
pub(super) fn put_path(
    table: &mut PeerTable,
    counts: &mut PathCounts,
    prefix: IpNet,
    id: u32,
    route: RibRoute,
) {
    let paths = table.entry(prefix).or_default();
    if let Some((_, old)) = paths.iter_mut().find(|(i, _)| *i == id) {
        *old = route;
    } else {
        paths.push((id, route));
        counts[family_index(prefix)] += 1;
    }
}

/// Removes path `id` of `prefix`, if held — an unknown id is a no-op (RFC
/// 7911 §5).
pub(super) fn take_path(
    table: &mut PeerTable,
    counts: &mut PathCounts,
    prefix: IpNet,
    id: u32,
) -> Option<RibRoute> {
    let paths = table.get_mut(&prefix)?;
    let pos = paths.iter().position(|(i, _)| *i == id)?;
    let (_, route) = paths.remove(pos);
    if paths.is_empty() {
        table.remove(&prefix);
    }
    counts[family_index(prefix)] -= 1;
    Some(route)
}

/// The path id of entry `i` of an NLRI list whose ids are index-aligned in
/// `ids` — empty without ADD-PATH, which is path id 0.
pub(super) fn path_id_at(ids: &[u32], i: usize) -> u32 {
    ids.get(i).copied().unwrap_or(0)
}

/// Every `(prefix, path id)` an UPDATE withdraws, legacy and MP alike.
pub(super) fn withdrawn_paths(update: &UpdateMessage) -> Vec<(IpNet, u32)> {
    let legacy = update
        .withdrawn_routes
        .iter()
        .enumerate()
        .map(|(i, p)| (IpNet::V4(*p), path_id_at(&update.withdrawn_path_ids, i)));
    let mp = update.mp_unreach.iter().flat_map(|u| {
        u.withdrawn
            .iter()
            .enumerate()
            .map(|(i, p)| (*p, path_id_at(&u.withdrawn_path_ids, i)))
    });
    legacy.chain(mp).collect()
}

/// Every `(prefix, path id)` an UPDATE announces, legacy and MP alike.
pub(super) fn announced_paths(update: &UpdateMessage) -> Vec<(IpNet, u32)> {
    let legacy = update
        .nlri
        .iter()
        .enumerate()
        .map(|(i, p)| (IpNet::V4(*p), path_id_at(&update.nlri_path_ids, i)));
    let mp = update.mp_reach.iter().flat_map(|m| {
        m.nlri
            .iter()
            .enumerate()
            .map(|(i, p)| (*p, path_id_at(&m.nlri_path_ids, i)))
    });
    legacy.chain(mp).collect()
}

/// Applies one learned NLRI to a peer's Adj-RIB-In, shared by an UPDATE's
/// plain IPv4 NLRI and its RFC 4760 `MP_REACH_NLRI`, which differ only in
/// where the next-hop comes from.
///
/// A rejected prefix is *removed* rather than skipped — a policy that now
/// rejects it must not leave an earlier, now-superseded copy behind — and is
/// `touched` either way so best-path selection re-runs for it.
// ponytail: damping stays keyed by (peer, prefix), so a flap of any one
// ADD-PATH path penalises the prefix from that peer; key it by path id too
// if per-path damping is ever needed.
#[allow(clippy::too_many_arguments, clippy::single_match_else)]
pub(super) fn learn_prefix(
    table: &mut PeerTable,
    counts: &mut PathCounts,
    damping: &mut Damping,
    touched: &mut HashSet<IpNet>,
    peer: PolicyPeer,
    (prefix, id): (IpNet, u32),
    candidate: RibRoute,
    import_policy: &CompiledPolicy,
    retain: Option<&mut super::retain::RetainSlot<'_>>,
    blackhole: Option<&[nos_rpl::PrefixListEntry]>,
    bmp: Option<&crate::bmp::Hub>,
    stats: &mut PeerStats,
) {
    let from = peer.addr;
    // Soft reconfiguration inbound: keep the pre-policy candidate.
    if let Some(r) = retain {
        put_path(r.table, r.counts, prefix, id, candidate.clone());
    }
    match apply_policy(prefix, candidate, import_policy, Some(peer), None) {
        Some(mut route) => {
            // RFC 7999 §3.2: the receiver adds NO_EXPORT to an accepted blackhole.
            if blackhole.is_some_and(|l| super::blackhole_applies(l, prefix, &route.communities))
                && !route
                    .communities
                    .contains(&crate::message::COMMUNITY_NO_EXPORT)
            {
                route.communities.push(crate::message::COMMUNITY_NO_EXPORT);
            }
            let mut unchanged = false;
            if let Some(old) = get_path(table, prefix, id) {
                // An RPKI state change alone is no flap (#17).
                let same = RibRoute {
                    received_at: old.received_at,
                    validation_state: old.validation_state,
                    ..route.clone()
                } == *old;
                unchanged = same;
                if same {
                    bump(&mut stats.dup_adv, 1);
                    // Keep the age: `received_at` is part of `PartialEq`, so a
                    // fresh one would make every identical re-announcement
                    // look changed downstream and be re-propagated (#160).
                    route.received_at = old.received_at;
                } else if damping.enabled(from) {
                    damping.flap(from, prefix, CHANGE_PENALTY, Instant::now());
                }
            }
            info!(
                peer = %from,
                path_id = id,
                atomic_aggregate = route.atomic_aggregate,
                aggregator = ?route.aggregator.map(|a| (a.asn, a.router_id)),
                otc = ?route.otc,
                validation_state = ?route.validation_state,
                communities = ?route.communities,
                local_pref = route.local_pref,
                "bgp: learned route for {prefix} into adj-rib-in"
            );
            // BMP state compression: an identical re-announcement says nothing.
            if let Some(h) = bmp.filter(|_| !unchanged) {
                h.route_post(from, prefix, id, Some(&route));
            }
            put_path(table, counts, prefix, id, route);
        }
        None => {
            bump(&mut stats.rejected, 1);
            if take_path(table, counts, prefix, id).is_some() {
                damping.flap(from, prefix, WITHDRAW_PENALTY, Instant::now());
                if let Some(h) = bmp {
                    h.route_post(from, prefix, id, None);
                }
            }
        }
    }
    touched.insert(prefix);
}

impl BgpRib {
    /// Handles one inbound UPDATE from `from`, whose BGP Identifier is
    /// `remote_bgp_id` (used as the RFC 4271 §9.1.2.2 router-id tiebreak).
    /// Withdrawals (legacy `withdrawn_routes` plus any `mp_unreach` batch)
    /// are always processed first, unconditionally; announcements (legacy
    /// `nlri` plus any `mp_reach` batch) are dropped entirely (with a
    /// `warn!`) if the `AS_PATH` already contains our own ASN (loop
    /// prevention), never partially applied. `ORIGIN`/`AS_PATH`/
    /// `LOCAL_PREF`/`MULTI_EXIT_DISC` are shared across the legacy `nlri`
    /// and every `mp_reach` batch in the same UPDATE (RFC 4760: only the
    /// next-hop is per-batch); each `mp_reach` batch's own `next_hop` is
    /// used instead of the legacy attribute's. `import_policy` is `from`'s
    /// peer-group's resolved import policy (`deny-all` by default — see root
    /// `CLAUDE.md`'s "Default-deny rollout impact"): a rejected prefix is
    /// treated like an explicit withdrawal rather than inserted.
    #[allow(clippy::too_many_lines, reason = "one linear pass per UPDATE")]
    pub fn handle_update(
        &mut self,
        from: IpAddr,
        remote_is_ibgp: bool,
        remote_bgp_id: Ipv4Addr,
        update: &UpdateMessage,
        import_policy: &CompiledPolicy,
    ) {
        let peer_as = self.peer_asns.get(&from).copied().unwrap_or(0);
        // Sized from the message's own known counts so this doesn't rehash
        // its way up on every insert — bounded by the total NLRI/withdrawn
        // entries this one UPDATE could possibly touch.
        let touched_capacity = update.nlri.len()
            + update.mp_reach.iter().map(|m| m.nlri.len()).sum::<usize>()
            + update.withdrawn_routes.len()
            + update
                .mp_unreach
                .iter()
                .map(|u| u.withdrawn.len())
                .sum::<usize>();
        let mut touched: HashSet<IpNet> = HashSet::with_capacity(touched_capacity);
        if update.treat_as_withdraw_prefixes != 0 {
            let s = self.stats_mut(from);
            bump(&mut s.tw_updates, 1);
            bump(&mut s.tw_prefixes, update.treat_as_withdraw_prefixes);
        }

        let announced = self.apply_withdrawals(from, update, &mut touched);

        if !update.nlri.is_empty() || !update.mp_reach.is_empty() {
            let Some(attrs) = &update.attributes else {
                // parse_update never actually produces this (attributes is
                // Some whenever nlri or mp_reach is non-empty), but stay
                // defensive.
                for prefix in touched {
                    self.recompute_and_propagate(prefix);
                }
                return;
            };
            let from_confed = self.confed_peers.contains(&from);
            // RFC 9234 §5 applies to unicast only, never EVPN.
            let unicast =
                !update.nlri.is_empty() || update.mp_reach.iter().any(|m| !m.nlri.is_empty());
            // RFC 9234 §5 ingress 3: a route from a Provider, Peer or Route
            // Server with no OTC gets the neighbor's ASN.
            let otc = match self.role_peers.get(&from).map(|r| r.counterpart()) {
                Some(Provider | Peer | RouteServer) if unicast && attrs.otc.is_none() => {
                    Some(peer_as)
                }
                _ => attrs.otc,
            };
            // RFC 5065 §5.3 / RFC 7606 §7.2: confederation segments only ever
            // come from inside our own confederation.
            let stray_confed = attrs.as_path.has_confed()
                && (self.confed_id.is_none() || !(remote_is_ibgp || from_confed));
            // RFC 5065 §5.1: our confederation identifier (or AS) in a plain
            // segment, or our member AS in a confederation segment.
            // Vendor `local-as`: it counts as ours on this peer's routes only.
            let local_as = self.local_as_peers.get(&from).copied();
            let as_loop = attrs
                .as_path
                .contains(self.confed_id.unwrap_or(self.local_asn))
                || local_as.is_some_and(|l| attrs.as_path.contains(l.asn));
            let confed_loop =
                self.confed_id.is_some() && attrs.as_path.contains_confed(self.local_asn);
            let looped = as_loop || confed_loop;
            // RFC 4271 §6.3 / §5.1.3: an unusable NEXT_HOP (legacy attribute
            // or any MP_REACH batch) makes the whole UPDATE a withdraw.
            let own = self.peer_outboxes.get(&from).and_then(|o| o.local_addr);
            // A peer reached over loopback may itself advertise loopback.
            let martian = |nh: IpAddr| {
                message::next_hop_is_martian(nh, own) && !(nh.is_loopback() && from.is_loopback())
            };
            let bad_next_hop = (!update.nlri.is_empty() && martian(attrs.next_hop.into()))
                .then(|| IpAddr::from(attrs.next_hop))
                .or_else(|| {
                    update
                        .mp_reach
                        .iter()
                        .filter(|m| {
                            !m.nlri.is_empty()
                                || !m.evpn.is_empty()
                                || !m.vpn.is_empty()
                                || !m.rtc.is_empty()
                        })
                        .find(|m| martian(m.next_hop))
                        .map(|m| m.next_hop)
                });
            // RFC 4271 §6.3: an eBGP AS_PATH starts with the peer's own AS
            // (an AS_SET first, or an empty path, is a violation too).
            let first_as_forged = peer_as != 0
                && !remote_is_ibgp
                && !from_confed
                && self.first_as_peers.contains(&from)
                && !matches!(attrs.as_path.segments().next(),
                    Some((SegKind::Sequence, s)) if s[0] == peer_as);
            if bad_next_hop.is_some() || stray_confed {
                let s = self.stats_mut(from);
                bump(&mut s.tw_updates, 1);
                bump(
                    &mut s.tw_prefixes,
                    u32::try_from(announced.len()).unwrap_or(u32::MAX),
                );
            }
            if let Some(next_hop) = bad_next_hop {
                warn!(
                    peer = %from, next_hop = %next_hop,
                    "treating bgp update as withdraw: invalid next hop"
                );
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else if stray_confed {
                warn!(
                    peer = %from, as_path = ?attrs.as_path,
                    "treating bgp update as withdraw: as_path has confederation segments from outside the confederation"
                );
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else if first_as_forged {
                if let Some(suppressed) = self.first_as_warn_due(from) {
                    warn!(
                        peer = %from, expected = peer_as, as_path = ?attrs.as_path, suppressed,
                        "treating bgp update as withdraw: first AS of as_path is not the peer's AS"
                    );
                }
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else if looped {
                let s = self.stats_mut(from);
                if as_loop {
                    bump(&mut s.as_loop, 1);
                }
                if confed_loop {
                    bump(&mut s.confed_loop, 1);
                }
                // RFC 4271 §9.1.2: a looped route is unfeasible, so it
                // replaces (implicitly withdraws) an earlier one.
                warn!(
                    peer = %from, as_path = ?attrs.as_path,
                    "dropping bgp update: as_path already contains our own asn (loop prevention)"
                );
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else if let Some(role) = unicast
                .then(|| self.role_peers.get(&from).map(|r| r.counterpart()))
                .flatten()
                .filter(|&r| otc_leak(r, attrs.otc, peer_as))
            {
                warn!(
                    peer = %from, prefix = ?announced.iter().map(|a| a.0).collect::<Vec<_>>(),
                    otc = ?attrs.otc, role = ?role,
                    "route leak detected: dropping bgp update (rfc 9234 only-to-customer)"
                );
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else if attrs.cluster_list.contains(&self.cluster_id) {
                bump(&mut self.stats_mut(from).cluster_loop, 1);
                warn!(
                    peer = %from, cluster_list = ?attrs.cluster_list,
                    "dropping bgp update: cluster_list already contains our own cluster-id (rfc 4456 reflection loop prevention)"
                );
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else if attrs.originator_id == Some(self.local_router_id) {
                bump(&mut self.stats_mut(from).originator, 1);
                warn!(
                    peer = %from, originator_id = ?attrs.originator_id,
                    "dropping bgp update: originator_id is our own router-id (rfc 4456 reflection loop prevention)"
                );
                self.withdraw_announced(from, update, &announced, &mut touched);
            } else {
                let rx = Received {
                    from,
                    peer_as,
                    remote_is_ibgp,
                    remote_bgp_id,
                    from_confed,
                    otc,
                    local_as,
                    attrs,
                    update,
                };
                self.learn_announced(&rx, import_policy, &mut touched);
            }
        }

        for prefix in touched {
            self.recompute_and_propagate(prefix);
        }
    }

    /// The withdrawal half of `handle_update`: clears stale marks for what
    /// the peer mentions again, removes explicit withdrawals (feeding
    /// damping) and returns the paths `update` announces (#425).
    fn apply_withdrawals(
        &mut self,
        from: IpAddr,
        update: &UpdateMessage,
        touched: &mut HashSet<IpNet>,
    ) -> Vec<(IpNet, u32)> {
        // RFC 4724: an EVPN route the peer mentions again is no longer stale.
        if let Some(stale) = self.evpn_stale.get_mut(&from) {
            for n in update.mp_reach.iter().flat_map(|m| &m.evpn) {
                stale.remove(&n.route_key());
            }
            for n in update.mp_unreach.iter().flat_map(|m| &m.evpn) {
                stale.remove(&n.route_key());
            }
        }
        if let Some(stale) = self.flowspec_stale.get_mut(&from) {
            for (m_afi, rule) in update
                .mp_reach
                .iter()
                .flat_map(|m| m.flowspec.iter().map(move |r| (m.afi, r)))
                .chain(
                    update
                        .mp_unreach
                        .iter()
                        .flat_map(|m| m.flowspec.iter().map(move |r| (m.afi, r))),
                )
            {
                if let Some(f) = flowspec_family(m_afi) {
                    stale.remove(&(f, rule.clone()));
                }
            }
        }
        if let Some(stale) = self.rtc_stale.get_mut(&from) {
            for n in update
                .mp_reach
                .iter()
                .flat_map(|m| &m.rtc)
                .chain(update.mp_unreach.iter().flat_map(|m| &m.rtc))
            {
                stale.remove(n);
            }
        }
        if let Some(stale) = self.vpn_stale.get_mut(&from) {
            for n in update.mp_reach.iter().flat_map(|m| &m.vpn) {
                stale.remove(&(n.rd, n.prefix));
            }
            for n in update.mp_unreach.iter().flat_map(|m| &m.vpn) {
                stale.remove(&(n.rd, n.prefix));
            }
        }
        let withdrawn = withdrawn_paths(update);
        let announced = announced_paths(update);
        // RFC 7313 / RFC 4724: any path the peer mentions again is no
        // longer stale.
        if let Some(stale) = self.stale.get_mut(&from) {
            for path in withdrawn.iter().chain(&announced) {
                stale.remove(path);
            }
        }

        for nlri in update.mp_unreach.iter().flat_map(|u| &u.evpn) {
            self.retained.take_evpn(from, &nlri.route_key());
            // mac_mobility's record of this route's (vni, mac) is
            // deliberately left alone here too — see peer_disconnected.
            let removed = self
                .evpn_adj_rib_in
                .get_mut(&from)
                .is_some_and(|t| t.remove(&nlri.route_key()).is_some());
            if removed {
                info!(peer = %from, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
                if let Some(h) = super::bmp_tap::tap(self.bmp.as_ref()) {
                    h.evpn_post(from, nlri, None);
                }
            }
        }
        for u in &update.mp_unreach {
            self.drop_rtcs(from, &u.rtc);
            for n in &u.vpn {
                self.drop_vpn(from, &(n.rd, n.prefix));
            }
            let Some(family) = flowspec_family(u.afi) else {
                continue;
            };
            for rule in &u.flowspec {
                self.drop_flow(from, &(family, rule.clone()));
            }
        }
        for &(prefix, id) in &withdrawn {
            if self.remove_path(from, prefix, id).is_none() {
                bump(&mut self.stats_mut(from).dup_withdraw, 1);
            } else {
                debug!(peer = %from, path_id = id, "bgp: withdrew path for {prefix} from adj-rib-in");
                touched.insert(prefix);
                self.damping
                    .flap(from, prefix, WITHDRAW_PENALTY, Instant::now());
            }
        }
        announced
    }

    /// The accept half of `handle_update`: builds the candidate route from
    /// `rx.attrs` and learns every announced prefix through the import
    /// policy (#425).
    #[allow(clippy::too_many_lines, reason = "one linear pass per received family")]
    fn learn_announced(
        &mut self,
        rx: &Received<'_>,
        import_policy: &CompiledPolicy,
        touched: &mut HashSet<IpNet>,
    ) {
        let Received {
            from,
            peer_as,
            remote_is_ibgp,
            remote_bgp_id,
            from_confed,
            otc,
            local_as,
            attrs,
            update,
        } = *rx;
        let mut evpn_recheck: Vec<(u32, [u8; 6])> = Vec::new();
        let mut flow_keys: Vec<FlowspecKey> = Vec::new();
        let policy_peer = PolicyPeer::new(from, peer_as).with_roles(self.policy_roles(from));
        let table = self.adj_rib_in.entry(from).or_default();
        let counts = self.path_counts.entry(from).or_default();
        let mut retain = self.retained.slot(from);
        let stats = self.peer_stats.entry(from).or_default();
        let bmp = super::bmp_tap::tap(self.bmp.as_ref());
        let blackhole = self.blackhole_peers.get(&from).cloned();
        // This UPDATE adds at most this many entries — reserving
        // once lets the per-peer table grow in fewer, larger steps
        // on the way up to a full table, instead of rehashing on
        // every insert-triggered doubling.
        table.reserve(
            update.nlri.len() + update.mp_reach.iter().map(|m| m.nlri.len()).sum::<usize>(),
        );
        // RFC 8097 §2: always stripped; honoured only from an
        // opted-in iBGP peer (`rpki_state_peers` holds no other).
        let mut extended_communities = attrs.extended_communities.clone();
        let mut received_ov = None;
        extended_communities.retain(|&c| {
            let ov = crate::rpki::community::is_ov(c);
            if ov && received_ov.is_none() {
                received_ov = crate::rpki::community::decode(c);
            }
            !ov
        });
        let received_ov = received_ov.filter(|_| self.rpki_state_peers.contains(&from));
        // Vendor `local-as`: the received path gets it as a real hop,
        // so policy and every other peer see `[local-as, peer…]`.
        let mut as_path = attrs.as_path.clone();
        if let Some(l) = local_as.filter(|l| !l.no_prepend) {
            as_path.prepend_seq(l.asn);
        }
        // RFC 8326, eBGP only, before import policy so policy can override.
        let mut communities = attrs.communities.clone();
        let mut local_pref = received_local_pref(attrs.local_pref, remote_is_ibgp || from_confed);
        if !remote_is_ibgp && !from_confed {
            let gs = self.gs_peers.get(&from).copied().unwrap_or_default();
            if gs.apply(&mut communities) {
                local_pref = 0;
            }
        }
        let base_route = RibRoute {
            origin: RouteOrigin::Peer(from),
            as_path: Arc::new(as_path),
            bgp_origin: attrs.origin,
            local_pref,
            med: attrs.med,
            learned_via_ibgp: remote_is_ibgp,
            learned_via_confed: from_confed,
            router_id: Some(remote_bgp_id),
            next_hop: None,
            received_at: Instant::now(),
            originator_id: attrs.originator_id,
            cluster_list: attrs.cluster_list.clone().into(),
            communities,
            extended_communities,
            large_communities: attrs.large_communities.clone(),
            atomic_aggregate: attrs.atomic_aggregate,
            aggregator: attrs.aggregator,
            otc,
            validation_state: nos_rpl::ValidationState::NotFound,
            received_ov,
        };
        let origin_as = crate::rpki::origin_as(
            &base_route.as_path,
            self.confed_id.unwrap_or(self.local_asn),
        );
        for (i, prefix) in update.nlri.iter().enumerate() {
            let candidate = RibRoute {
                next_hop: Some(IpAddr::V4(attrs.next_hop)),
                validation_state: ov_state(&self.vrps, IpNet::V4(*prefix), origin_as, received_ov),
                ..base_route.clone()
            };
            learn_prefix(
                table,
                counts,
                &mut self.damping,
                touched,
                policy_peer,
                (IpNet::V4(*prefix), path_id_at(&update.nlri_path_ids, i)),
                candidate,
                import_policy,
                retain.as_mut(),
                blackhole.as_deref().map(Vec::as_slice),
                bmp,
                stats,
            );
        }
        for mp in &update.mp_reach {
            for (i, prefix) in mp.nlri.iter().enumerate() {
                let candidate = RibRoute {
                    next_hop: Some(mp.next_hop),
                    validation_state: ov_state(&self.vrps, *prefix, origin_as, received_ov),
                    ..base_route.clone()
                };
                learn_prefix(
                    table,
                    counts,
                    &mut self.damping,
                    touched,
                    policy_peer,
                    (*prefix, path_id_at(&mp.nlri_path_ids, i)),
                    candidate,
                    import_policy,
                    retain.as_mut(),
                    blackhole.as_deref().map(Vec::as_slice),
                    bmp,
                    stats,
                );
            }
            if !mp.evpn.is_empty() {
                learn_evpn(
                    self.evpn_adj_rib_in.entry(from).or_default(),
                    retain.as_mut().map(|r| &mut *r.evpn),
                    &mut self.mac_mobility,
                    from,
                    mp,
                    &attrs.extended_communities,
                    attrs.pmsi,
                    self.evpn_import
                        .get(&from)
                        .map(|p| (p.as_ref(), peer_as, remote_is_ibgp)),
                    &attrs.communities,
                    (!remote_is_ibgp && !from_confed)
                        .then(|| self.gs_peers.get(&from).copied().unwrap_or_default()),
                    bmp,
                    stats,
                );
                evpn_recheck.extend(
                    mp.evpn
                        .iter()
                        .filter_map(evpn_mac_key)
                        .map(|(vni, mac, _)| (vni, mac)),
                );
            }
            if !mp.flowspec.is_empty()
                && let Some(family) = flowspec_family(mp.afi)
            {
                // D-d: NLRI for a family this session did not negotiate is
                // ignored (a test RIB without an outbox has no session to
                // check against).
                if self
                    .peer_outboxes
                    .get(&from)
                    .is_some_and(|o| !o.negotiated_afs.contains(&family))
                {
                    warn!(peer = %from, family = %family, "flowspec routes for a family not negotiated, ignored");
                } else {
                    let import = self.flowspec_import.get(&from).cloned();
                    let rx = FlowRx {
                        from,
                        family,
                        attributes: attrs,
                        learned_via_ibgp: remote_is_ibgp || from_confed,
                        router_id: remote_bgp_id,
                        import: import.as_deref().map(|p| (p, peer_as, from_confed)),
                        bmp,
                    };
                    flow_keys.extend(learn_flowspec(
                        self.flowspec_adj_rib_in.entry(from).or_default(),
                        retain.as_mut().map(|r| &mut *r.flow),
                        mp,
                        &rx,
                        stats,
                    ));
                }
            }
        }
        if !flow_keys.is_empty() {
            self.enable_flow_indexes();
            for k in flow_keys {
                self.track_flow(from, &k);
            }
        }
        for (vni, mac) in evpn_recheck {
            self.mac_mobility_recheck(vni, mac);
        }
        self.learn_rtc(update, &base_route, from);
        self.learn_vpn(update, &base_route, (from, peer_as), import_policy);
    }

    /// RFC 7606 treat-as-withdraw, decided here rather than in the codec
    /// because it depends on the peer: every route `update` announces is
    /// removed from `from`'s Adj-RIB-In.
    pub(super) fn withdraw_announced(
        &mut self,
        from: IpAddr,
        update: &UpdateMessage,
        announced: &[(IpNet, u32)],
        touched: &mut HashSet<IpNet>,
    ) {
        for &(prefix, id) in announced {
            if self.remove_path(from, prefix, id).is_some() {
                debug!(peer = %from, path_id = id, "bgp: withdrew path for {prefix} from adj-rib-in");
                touched.insert(prefix);
            }
        }
        for m in &update.mp_reach {
            self.drop_rtcs(from, &m.rtc);
            for n in &m.vpn {
                self.drop_vpn(from, &(n.rd, n.prefix));
            }
            let Some(family) = flowspec_family(m.afi) else {
                continue;
            };
            for rule in &m.flowspec {
                self.drop_flow(from, &(family, rule.clone()));
            }
        }
        for nlri in update.mp_reach.iter().flat_map(|m| &m.evpn) {
            self.retained.take_evpn(from, &nlri.route_key());
        }
        if let Some(table) = self.evpn_adj_rib_in.get_mut(&from) {
            for nlri in update.mp_reach.iter().flat_map(|m| &m.evpn) {
                if table.remove(&nlri.route_key()).is_some() {
                    info!(peer = %from, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
                    if let Some(h) = super::bmp_tap::tap(self.bmp.as_ref()) {
                        h.evpn_post(from, nlri, None);
                    }
                }
            }
        }
    }

    /// Removes path `id` of `prefix` from `peer`'s Adj-RIB-In, keeping the
    /// path counters in step.
    pub(super) fn remove_path(&mut self, peer: IpAddr, prefix: IpNet, id: u32) -> Option<RibRoute> {
        // The pre-policy copy goes with the path, even one policy rejected.
        self.retained.take(peer, prefix, id);
        let gone = take_path(
            self.adj_rib_in.get_mut(&peer)?,
            self.path_counts.entry(peer).or_default(),
            prefix,
            id,
        );
        if gone.is_some()
            && let Some(h) = super::bmp_tap::tap(self.bmp.as_ref())
        {
            h.route_post(peer, prefix, id, None);
        }
        gone
    }
}

/// One received UPDATE's per-peer context, handed to `learn_announced`.
#[derive(Clone, Copy)]
struct Received<'a> {
    from: IpAddr,
    peer_as: u32,
    remote_is_ibgp: bool,
    remote_bgp_id: Ipv4Addr,
    from_confed: bool,
    otc: Option<u32>,
    local_as: Option<nos_proto::BgpLocalAs>,
    attrs: &'a message::PathAttributes,
    update: &'a UpdateMessage,
}

/// RFC 4271 §5.1.5: `LOCAL_PREF` is only meaningful from iBGP (and
/// confederation) peers; an eBGP peer's value is ignored (#601).
fn received_local_pref(received: Option<u32>, internal: bool) -> u32 {
    if internal {
        received.unwrap_or(DEFAULT_LOCAL_PREF)
    } else {
        DEFAULT_LOCAL_PREF
    }
}
