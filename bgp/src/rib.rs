//! The BGP RIB engine: Adj-RIB-In per peer, a locally-redistributed route
//! set (fed by `nos-ribd` via `nos_proto::RedistributeUpdate`, filtered
//! through the configured redistribute RPL policy — see
//! `apply_redistribute_update`/`set_redistribute_policy`), a cached
//! Loc-RIB best-path per prefix, and per-peer outbound channels used to push
//! `OutboundUpdate`s out to each `fsm::run` task. Prefixes/next-hops are
//! `IpNet`/`IpAddr` throughout — v4 and v6 share the same maps, family
//! discriminated by the value itself, the same pattern `nos-rib`'s own `Rib`
//! already uses.
//!
//! Before any of it runs, RFC 4271 §9.1.2's feasibility check: a peer-learned
//! candidate whose `NEXT_HOP` no route in the IGP table polled from `nos-ribd`
//! covers is unfeasible and is dropped from the candidate set outright
//! (`next_hop_feasible`) — not merely tie-broken — once that table has been
//! fetched at least once (`igp_ready`; before that every candidate is kept,
//! so a fresh start never blackholes what it just learned). Directly connected
//! next hops resolve because `nos-ribd` holds every applied address as a
//! `Connected` route. The runner-up/backup path is picked from the same
//! filtered set, so it needs a resolvable next hop just the same.
//!
//! Best path selection (`best_path`) implements the full RFC 4271 §9.1.2.2
//! decision process, in order: (1) higher `LOCAL_PREF`; (2) a
//! locally-redistributed route beats any peer-learned route (not an RFC
//! step — this implementation's equivalent of "prefer locally originated",
//! placed here per common vendor convention, e.g. Cisco's own ordering);
//! (3) shorter `AS_PATH` (`AsPath::selection_len`: an `AS_SET` counts one,
//! RFC 5065 confederation segments none); (4) lowest `ORIGIN` type (`Igp` <
//! `Egp` < `Incomplete`); (5) lowest `MULTI_EXIT_DISC`, only compared
//! between routes sharing the same neighboring AS (`AsPath::neighbor_as`,
//! confederation segments skipped), missing MED treated as 0; (6) an
//! eBGP-learned route beats an iBGP-learned one; (7) lowest IGP metric to the next-hop, resolved by
//! longest-prefix match against the table `igp_client` polls from
//! `nos-ribd` (`set_igp`) — a directly connected one is a `Connected` route
//! at cost 0, an unresolvable one never gets here (see above); (8) oldest route
//! wins (by `received_at`), only between two eBGP-learned candidates,
//! per RFC 4271's anti-flap tie-break; (9) lowest BGP Identifier
//! (router-id) of the advertising peer; (10) lowest advertising peer
//! address, the final deterministic tiebreak.
//! - Next-hop rewriting is peer-group configurable (`nos_proto::NextHopMode`
//!   — `SelfAddress`/`Unchanged`), defaulting to `SelfAddress` for an eBGP
//!   peer and `Unchanged` for an iBGP one. `Unchanged` re-advertises the
//!   route's own stored next-hop (the address it was received with, for a
//!   peer-learned route); a locally-redistributed route has no such stored
//!   value, so it always gets next-hop-self regardless of mode.
//!   `SelfAddress` always uses the destination peer's own session-local
//!   address (`PeerOutbox::local_addr`), regardless of the prefix's own
//!   family — this is what makes RFC 8950 cross-family next-hop work: no
//!   special-casing needed here, since `local_addr` is already whatever
//!   family this session's transport is.
//! - Standard iBGP split-horizon (no route reflection): a route learned via
//!   one iBGP peer is never re-advertised to another iBGP peer.
//! - `AS_PATH` is prepended with our own ASN only toward eBGP peers;
//!   `LOCAL_PREF` is included only toward iBGP peers.
//! - A received route whose `AS_PATH` already contains our own ASN is dropped
//!   (loop prevention), not just deprioritized.
//! - RFC 5065 confederations (`set_confederation`, `set_peer_confed`): a
//!   confederation-external peer is treated as iBGP for next hop, MED and
//!   `LOCAL_PREF` and gets our member AS in an `AS_CONFED_SEQUENCE`; an
//!   external peer gets the path without confederation segments and the
//!   identifier prepended. Confederation segments from outside the
//!   confederation are treat-as-withdraw; loop detection checks the
//!   identifier in plain segments and the member AS in confed segments.
//! - A peer only ever gets a prefix whose address family is in its own
//!   `negotiated_afs` (config ∩ what was actually negotiated in OPEN — see
//!   `fsm::negotiate_address_families`); `mp_bgp_negotiated` then picks
//!   whether that peer's `OutboundUpdate`s get encoded as legacy plain NLRI
//!   or `MP_REACH_NLRI`/`MP_UNREACH_NLRI` (`fsm::outbound_update_to_message`
//!   is the encode side of that decision).
//!
//! Locking: one whole-instance `Arc<SharedRib>` (`rib/shared.rs`: a mutex plus the push generation), owned by
//! `session::SessionManager`. All methods here are synchronous `&mut self`
//! (channel sends are non-blocking) — callers lock once per call. A single
//! lock is deliberate: best-path recomputation must see a consistent
//! cross-peer view, and this NOS's route volume is not internet-table scale.
//!
//! Outbox ownership lives here (`BgpRib::peer_outboxes`), keyed by `IpAddr`,
//! rather than as a field on `collision::PeerSlot` — `BgpRib` already needs a
//! peer-keyed table for `adj_rib_in`, and `PeerSlot`'s job is strictly RFC
//! 4271 §6.8 arbitration, not routing state.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use nos_proto::{AddressFamily, BgpDamping, NextHopMode, RedistributeUpdate};
use nos_rpl::CompiledPolicy;
use smallvec::SmallVec;
use tracing::{debug, info, warn};

use crate::as_path::AsPath;
use crate::damping::{Damping, CHANGE_PENALTY, WITHDRAW_PENALTY};
use crate::evpn::EvpnNlri;
use crate::flowspec::FlowSpec;
use crate::gr::{Disconnect, PeerGr};
use crate::mac_mobility::MacMobility;
use crate::message::{self, UpdateMessage};
use crate::page::Keyed;
use crate::vpn::VpnKey;
pub use stats::{LocTotals, PeerStats};

mod adj_in;
mod aggregate;
mod bmp_out;
mod bmp_tap;
mod decision;
mod evpn_out;
mod flowspec_out;
mod flowspec_validate;
mod gr;
mod outbox;
mod retain;
pub use gr::GsKnobs;
mod rtc;
mod shared;
mod stats;
mod vpn_import;
mod vpn_out;
pub use evpn_out::{feeds as evpn_feeds, AdvertisedEvpn, EvpnSource};
pub use flowspec_out::AdvertisedFlowspec;
#[cfg(test)]
pub use outbox::test_channel;
pub use outbox::{channel as outbox_channel, OutboxTx, OUTBOX_CAPACITY};
pub use retain::{ChunkOutcome, ImportPolicies, ReevalPass, REEVAL_CHUNK};
pub use rtc::{membership as rtc_membership, AdvertisedRtc, RtcKey};
pub use shared::{RibGuard, SharedRib};
pub use vpn_import::{SooSkip, VpnImport, VpnImportPath, VpnImports};
pub use vpn_out::AdvertisedVpn;

use adj_in::{evpn_mac_key, AddPathSent, PathCounts, PathKey, PeerTable};
pub use decision::Hops;
use decision::{
    best_index, best_path, build_advertisement, eligibility, igp_lookup, multipath_next_hops,
    origin_rank, otc_leak, rank, redistributed_route, runner_up_next_hop, Candidate,
};
pub use flowspec_validate::{FlowValidity, InvalidReason};

/// The route's `AS_PATH` segments in `nos_rpl`'s shape.
// ponytail: one small Vec per policy run; cache on the route if profiles show it.
fn policy_segments(route: &RibRoute) -> Vec<nos_rpl::Segment<'_>> {
    use crate::as_path::SegKind;
    route
        .as_path
        .segments()
        .map(|(kind, asns)| nos_rpl::Segment {
            kind: match kind {
                SegKind::Sequence => nos_rpl::SegKind::Sequence,
                SegKind::Set => nos_rpl::SegKind::Set,
                SegKind::ConfedSequence => nos_rpl::SegKind::ConfedSequence,
                SegKind::ConfedSet => nos_rpl::SegKind::ConfedSet,
            },
            asns,
        })
        .collect()
}

/// The neighbor a policy runs for (`None` at the call: a redistributed route).
/// The roles are RFC 9234 ones and stay unset for every non-unicast run.
#[derive(Clone, Copy)]
struct PolicyPeer {
    addr: IpAddr,
    asn: u32,
    local_role: Option<nos_rpl::Role>,
    remote_role: Option<nos_rpl::Role>,
}

impl PolicyPeer {
    fn new(addr: IpAddr, asn: u32) -> Self {
        Self {
            addr,
            asn,
            local_role: None,
            remote_role: None,
        }
    }

    fn with_roles(self, (local_role, remote_role): PolicyRoles) -> Self {
        Self {
            local_role,
            remote_role,
            ..self
        }
    }
}

/// `(local_role, remote_role)` as the policy sees them.
type PolicyRoles = (Option<nos_rpl::Role>, Option<nos_rpl::Role>);

fn rpl_role(r: nos_proto::BgpRole) -> nos_rpl::Role {
    use nos_proto::BgpRole as B;
    match r {
        B::Provider => nos_rpl::Role::Provider,
        B::RouteServer => nos_rpl::Role::RouteServer,
        B::RouteServerClient => nos_rpl::Role::RouteServerClient,
        B::Customer => nos_rpl::Role::Customer,
        B::Peer => nos_rpl::Role::Peer,
    }
}

/// Adapts a `RibRoute` into `nos_rpl`'s input shape — see root `CLAUDE.md`'s
/// "Execution model". A plain function, not an adapter trait: there is
/// exactly one producer (`RibRoute`) today, so a trait would add indirection
/// with nothing to abstract over yet.
fn to_policy_input<'a>(
    prefix: IpNet,
    route: &'a RibRoute,
    segments: &'a [nos_rpl::Segment<'a>],
    peer: Option<PolicyPeer>,
    rd: Option<[u8; 8]>,
) -> nos_rpl::Input<'a> {
    nos_rpl::Input {
        prefix,
        bgp: nos_rpl::BgpInput {
            origin: match route.bgp_origin {
                message::Origin::Igp => nos_rpl::Origin::Igp,
                message::Origin::Egp => nos_rpl::Origin::Egp,
                message::Origin::Incomplete => nos_rpl::Origin::Incomplete,
            },
            as_path: route.as_path.flat(),
            as_path_segments: segments,
            local_pref: route.local_pref,
            med: route.med,
            next_hop: route.next_hop,
            learned_via_ibgp: route.learned_via_ibgp,
            router_id: route.router_id,
            originator_id: route.originator_id,
            cluster_list: &route.cluster_list,
            peer: peer.map(|p| p.addr),
            peer_as: peer.map_or(0, |p| p.asn),
            communities: &route.communities,
            extended_communities: &route.extended_communities,
            large_communities: &route.large_communities,
            validation_state: route.validation_state,
            rd: rd.map(u64::from_be_bytes),
            local_role: peer.and_then(|p| p.local_role),
            remote_role: peer.and_then(|p| p.remote_role),
            otc: route.otc,
        },
    }
}

/// Runs a compiled RPL policy against a candidate route — a peer's import
/// policy against a freshly-received UPDATE, or the redistribute policy
/// against a locally-redistributed route (see `apply_redistribute_update`).
/// `None` means reject: for peer import, the caller treats the prefix like
/// an explicit withdrawal instead of inserting it, since a rejected route
/// must not linger in `adj_rib_in` from an earlier, now-superseded UPDATE;
/// for redistribution, the caller simply omits the prefix from `redistributed`.
fn apply_policy(
    prefix: IpNet,
    mut candidate: RibRoute,
    policy: &CompiledPolicy,
    peer: Option<PolicyPeer>,
    rd: Option<[u8; 8]>,
) -> Option<RibRoute> {
    let segs = policy_segments(&candidate);
    let verdict = nos_rpl::vm::run(
        policy,
        &to_policy_input(prefix, &candidate, &segs, peer, rd),
    );
    // VPN routes (`rd`) carry a next hop of either family; others are checked.
    // ponytail: the session transport is unknown on import, so a v4 prefix is
    // checked as if ENH were possible (v6 literal kept); `build_advertisement`
    // re-checks against the real `local_addr`.
    let check = rd
        .is_none()
        .then_some((prefix, Some(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))));
    apply_verdict(&mut candidate, verdict, check).map(|_| candidate)
}

/// Whether a unicast `prefix` may carry next hop `nh`: v6 prefix needs a v6
/// next hop; v4 needs v4, or v6 under RFC 8950 (`local_addr`, the session's
/// own address, is v6).
pub(super) fn next_hop_family_ok(prefix: IpNet, nh: IpAddr, local_addr: Option<IpAddr>) -> bool {
    match prefix {
        IpNet::V6(_) => nh.is_ipv6(),
        IpNet::V4(_) => nh.is_ipv4() || local_addr.is_some_and(|l| l.is_ipv6()),
    }
}

/// At most one next-hop family warning per `NH_FAMILY_WARN_EVERY`, process-wide.
pub(super) fn warn_next_hop_family(prefix: IpNet, nh: IpAddr, what: &str) {
    static LAST: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    let mut last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    if last.is_some_and(|t| now.duration_since(t) < NH_FAMILY_WARN_EVERY) {
        return;
    }
    *last = Some(now);
    warn!(prefix = %prefix, next_hop = %nh, "next hop address family does not match the prefix: {what}");
}

/// Writes an accepting verdict's attribute rewrites back onto `route` and
/// returns the policy's next-hop edit; `None` means the verdict was a reject
/// (and `route` is untouched). An explicit next-hop address is stored on the
/// route; `SelfAddress` only means something when advertising, so it is
/// returned for `build_advertisement` and ignored on import.
///
/// `check` is the unicast `(prefix, session local address)` an explicit next
/// hop must fit (`next_hop_family_ok`); a misfit is ignored with a warning.
fn apply_verdict(
    route: &mut RibRoute,
    verdict: nos_rpl::Verdict,
    check: Option<(IpNet, Option<IpAddr>)>,
) -> Option<nos_rpl::NextHopSet> {
    let nos_rpl::Verdict::Accept {
        local_pref,
        med,
        communities,
        extended_communities,
        large_communities,
        edits,
    } = verdict
    else {
        return None;
    };
    route.local_pref = local_pref;
    route.med = med;
    route.communities = communities;
    route.extended_communities = extended_communities;
    route.large_communities = large_communities;
    // RPL only prepends: the new leading ASNs join the leading AS_SEQUENCE.
    if let Some(flat) = edits.as_path {
        let added = flat.len().saturating_sub(route.as_path.flat().len());
        let path = Arc::make_mut(&mut route.as_path);
        for &asn in flat[..added].iter().rev() {
            path.prepend_seq(asn);
        }
    }
    if let Some(origin) = edits.origin {
        route.bgp_origin = match origin {
            nos_rpl::Origin::Igp => message::Origin::Igp,
            nos_rpl::Origin::Egp => message::Origin::Egp,
            nos_rpl::Origin::Incomplete => message::Origin::Incomplete,
        };
    }
    let mut nh_edit = edits.next_hop;
    if let nos_rpl::NextHopSet::Addr(a) = nh_edit {
        match check {
            Some((p, l)) if !next_hop_family_ok(p, a, l) => {
                warn_next_hop_family(p, a, "set ignored");
                nh_edit = nos_rpl::NextHopSet::Unchanged;
            }
            _ => route.next_hop = Some(a),
        }
    }
    Some(nh_edit)
}

fn family_index(prefix: IpNet) -> usize {
    usize::from(prefix.addr().is_ipv6())
}

/// RFC 4271 §5.1.5's default `LOCAL_PREF`, applied whenever a peer's UPDATE
/// omits the attribute (or for every locally-redistributed route, which
/// carries no wire attributes at all).
const DEFAULT_LOCAL_PREF: u32 = 100;
/// Minimum spacing of the per-peer "first AS is not the peer's" warning.
/// Minimum spacing of the next-hop family warning.
const NH_FAMILY_WARN_EVERY: Duration = Duration::from_secs(10);
const FIRST_AS_WARN_EVERY: Duration = Duration::from_secs(10);

fn family_of(net: IpNet) -> AddressFamily {
    match net {
        IpNet::V4(_) => AddressFamily::Ipv4Unicast,
        IpNet::V6(_) => AddressFamily::Ipv6Unicast,
    }
}

/// Where a `RibRoute` came from — `Local` for a route pushed in by
/// `nos-ribd`'s redistribution feed, `Peer(addr)` for one learned from a
/// specific peer's Adj-RIB-In.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteOrigin {
    Local,
    Peer(IpAddr),
}

/// One received Flowspec (RFC 8955) route — `Adj-RIB-In` content, after
/// the peer's Flowspec import policy. The whole attribute set is kept:
/// validation (#559), selection and propagation (#560) read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowspecRoute {
    /// `Ipv4Flowspec` or `Ipv6Flowspec` (the same bytes differ per AFI).
    pub family: AddressFamily,
    pub nlri: FlowSpec,
    pub attributes: message::PathAttributes,
    /// Learned over iBGP or from a confederation member (RFC 8955 section 6
    /// assumes those validated: no first-AS check).
    pub learned_via_ibgp: bool,
    /// The advertising peer's BGP Identifier (decision step 9).
    pub router_id: Ipv4Addr,
    /// When first received with these attributes (decision step 8).
    pub received_at: Instant,
    /// RFC 8955 section 6 state; `None` only between learning and the first
    /// validation, which follows at once.
    pub validity: Option<FlowValidity>,
}

impl FlowspecRoute {
    /// Valid, so a best-path candidate (`select_flow`): an invalid route
    /// stays in the Adj-RIB-In for `show`, nothing more.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.validity == Some(FlowValidity::Valid)
    }
}

/// A snapshot key of a paged `show bgp evpn` walk (#723).
pub type EvpnKey = Keyed<nos_proto::EvpnRouteCursor, EvpnNlri>;
/// A snapshot key of a paged `show bgp flowspec` walk (#723).
pub type FlowKey = Keyed<nos_proto::FlowspecRouteCursor, FlowspecKey>;

/// A Flowspec Adj-RIB-In key: the NLRI itself, per family.
pub(crate) type FlowspecKey = (AddressFamily, FlowSpec);

/// One received EVPN route's attributes — `Adj-RIB-In` content, nothing derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRoute {
    /// The NLRI as last received; the table key is its `route_key`, so the
    /// labels and ESI live here.
    pub nlri: EvpnNlri,
    pub next_hop: IpAddr,
    /// The VNI of a Type-3 route's PMSI Tunnel attribute, when it had one.
    pub pmsi_vni: Option<u32>,
    /// Raw 8-byte extended communities (Route Targets, Encapsulation, MAC
    /// Mobility, ...), exactly as received.
    pub extended_communities: Vec<u64>,
    /// Standard communities, after RFC 8326 tagging.
    pub communities: Vec<u32>,
    /// `DEFAULT_LOCAL_PREF`, or 0 when RFC 8326 demoted it; ranks copies at
    /// push time (`evpn_push_snapshot`).
    pub local_pref: u32,
}

/// One received VPN-IPv4/IPv6 path (RFC 4364) — `Adj-RIB-In` content, after
/// the peer-group import policy (`vpn_out::learn_vpn`).
#[derive(Debug, Clone, PartialEq)]
pub struct VpnRoute {
    /// The label stack as received; passed through unchanged on reflection.
    pub labels: Vec<u32>,
    /// The path as a decision-process candidate; `next_hop` is the PE.
    pub route: RibRoute,
}

/// One candidate route for a prefix, either locally redistributed or learned
/// from a peer.
#[derive(Debug, Clone, PartialEq)]
pub struct RibRoute {
    pub origin: RouteOrigin,
    /// Never mutated in place by RPL (a `prepend` replaces the whole `Arc`)
    /// — shared via `Arc` so cloning a `RibRoute` (candidate collection,
    /// `loc_rib`/`adj_rib_in` storage) never deep-copies this list.
    pub as_path: Arc<AsPath>,
    pub bgp_origin: message::Origin,
    /// Always the effective value — defaulted to `DEFAULT_LOCAL_PREF` when
    /// the peer's UPDATE omitted `LOCAL_PREF`, or for a `Local` route.
    pub local_pref: u32,
    /// `Some` iff the peer's UPDATE carried `MULTI_EXIT_DISC`. Always
    /// `None` for `origin == Local` — a locally-redistributed route never
    /// carries one.
    pub med: Option<u32>,
    /// Learned from an `Internal` peer (the member AS, in an RFC 5065
    /// confederation). Meaningless when `origin == Local`.
    pub learned_via_ibgp: bool,
    /// Learned from a confederation-external peer (RFC 5065) — ranks
    /// between external and internal at decision step 6.
    pub learned_via_confed: bool,
    /// The advertising peer's BGP Identifier, for `origin == Peer(_)` —
    /// used as the RFC 4271 §9.1.2.2 router-id tiebreak. Always `None` for
    /// `origin == Local`.
    pub router_id: Option<Ipv4Addr>,
    /// The `NEXT_HOP` this route was received with, for `origin ==
    /// Peer(_)` — read back out when a destination peer-group's `next_hop`
    /// resolves to `NextHopMode::Unchanged`. Always `None` for `origin ==
    /// Local`: a locally-redistributed route has no "received" next-hop to
    /// preserve, so it always gets next-hop-self regardless of mode.
    pub next_hop: Option<IpAddr>,
    /// When this candidate was first received with these attributes (an
    /// identical re-announcement keeps it, #160) — used only by the RFC 4271
    /// §9.1.2.2 "oldest route wins" tiebreak between two eBGP-learned
    /// candidates. Meaningless when `origin == Local`.
    pub received_at: Instant,
    /// RFC 4456 §5 `ORIGINATOR_ID`, for `origin == Peer(_)` — `Some` iff the
    /// peer's UPDATE carried it (meaning this route was already reflected at
    /// least once upstream). Always `None` for `origin == Local`.
    pub originator_id: Option<Ipv4Addr>,
    /// RFC 4456 §5 `CLUSTER_LIST`, for `origin == Peer(_)` — one cluster-id
    /// per route reflector this route has already passed through, nearest
    /// first. Always empty for `origin == Local`. Never mutated in place by
    /// RPL, like `as_path` — shared via `Arc` for the same reason.
    pub cluster_list: Arc<Vec<Ipv4Addr>>,
    /// RFC 1997 `COMMUNITY` values, possibly rewritten by import policy.
    /// Empty for a fresh `Local` route (no wire attributes to start from).
    pub communities: Vec<u32>,
    /// RFC 4360 `EXTENDED_COMMUNITIES` values, possibly rewritten by import
    /// policy. Empty for a fresh `Local` route.
    pub extended_communities: Vec<u64>,
    /// RFC 8092 `LARGE_COMMUNITY` values, possibly rewritten by import
    /// policy. Empty for a fresh `Local` route.
    pub large_communities: Vec<(u32, u32, u32)>,
    /// RFC 4271 §5.1.6/§5.1.7: preserved in transit, generated for an
    /// aggregate (`aggregate::build_aggregate`).
    pub atomic_aggregate: bool,
    pub aggregator: Option<message::Aggregator>,
    /// RFC 9234 Only to Customer ASN (`message::PathAttributes::otc`).
    pub otc: Option<u32>,
    /// RFC 6811 origin validation against the instance's current VRP set,
    /// computed before import policy runs (`this.bgp.validation_state`).
    pub validation_state: nos_rpl::ValidationState,
    /// The RFC 8097 state an opted-in iBGP peer sent with this route, used
    /// instead of local validation while the VRP table is empty (`ov_state`).
    pub received_ov: Option<nos_rpl::ValidationState>,
}

/// RFC 7999: `communities` carry BLACKHOLE and `prefix` is inside the peer's
/// blackhole prefix-list (normal prefix-list `range` rules).
pub(crate) fn blackhole_applies(
    list: &[nos_rpl::PrefixListEntry],
    prefix: IpNet,
    communities: &[u32],
) -> bool {
    communities.contains(&message::COMMUNITY_BLACKHOLE)
        && list.iter().any(|e| match e.range {
            None => prefix == e.cidr,
            Some((min, max)) => {
                e.cidr.contains(&prefix) && (min..=max).contains(&prefix.prefix_len())
            }
        })
}

/// RFC 8097 §2: a state signalled by the peer applies only "in the absence
/// of validation state set based on local data".
fn ov_state(
    vrps: &crate::rpki::VrpTable,
    prefix: IpNet,
    origin: Option<u32>,
    received: Option<nos_rpl::ValidationState>,
) -> nos_rpl::ValidationState {
    match received {
        Some(s) if vrps.is_empty() => s,
        _ => vrps.validate(prefix, origin),
    }
}

/// One update this instance needs to send out over a specific peer's
/// session. The `bool` picks the destination peer's wire encoding (`true` =
/// `MP_REACH_NLRI`/`MP_UNREACH_NLRI`, `false` = legacy plain NLRI — see
/// `fsm::outbound_update_to_message`), mirroring `AdvertisedRoute::use_mp`.
/// `Withdraw`'s trailing `Option<u32>` is the RFC 7911 ADD-PATH identifier
/// being withdrawn — `Some` exactly toward a peer we send ADD-PATH to for
/// that family (`PeerOutbox::add_path_tx`), `None` otherwise.
#[derive(Debug, Clone, PartialEq)]
pub enum OutboundUpdate {
    Announce(AdvertisedRoute),
    Withdraw(IpNet, bool, Option<u32>),
    /// An EVPN route originated by `nos-fdbd` (see `evpn_out`).
    AnnounceEvpn(AdvertisedEvpn),
    WithdrawEvpn(EvpnNlri),
    /// RFC 7313 Begin/End-of-Route-Refresh marker for one family, queued in
    /// order with the resent routes it brackets.
    RefreshMarker {
        family: AddressFamily,
        subtype: u8,
    },
    /// RFC 4724 §2 End-of-RIB for one family, after a session's initial dump.
    EndOfRib(AddressFamily),
    /// A selected Flowspec rule (see `flowspec_out`).
    AnnounceFlowspec(AdvertisedFlowspec),
    WithdrawFlowspec(AddressFamily, FlowSpec),
    /// A selected VPN path (see `vpn_out`).
    AnnounceVpn(AdvertisedVpn),
    WithdrawVpn(VpnKey<IpNet>),
    /// An RFC 4684 membership route (see `rtc`).
    AnnounceRtc(AdvertisedRtc),
    WithdrawRtc(RtcKey),
}

/// A route rewritten for advertisement toward one specific peer.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertisedRoute {
    pub prefix: IpNet,
    /// Already rewritten for the destination peer (our ASN prepended iff
    /// eBGP and not a `route_server_client`).
    pub as_path: AsPath,
    /// Rewritten per the destination peer-group's effective `NextHopMode` —
    /// either that peer's own session's local address (`SelfAddress`) or the
    /// route's stored next-hop (`Unchanged`).
    pub next_hop: IpAddr,
    /// `Some` only toward iBGP peers.
    pub local_pref: Option<u32>,
    /// The route's `MULTI_EXIT_DISC`, forwarded only toward iBGP peers —
    /// MED is meant for use between adjacent ASes, so it's never
    /// propagated further to another eBGP peer.
    pub med: Option<u32>,
    pub origin: message::Origin,
    /// Whether the destination peer negotiated any Multiprotocol Extensions
    /// capability at all — `true` means encode via `MP_REACH_NLRI` (even for
    /// an `Ipv4Unicast` prefix), `false` means the legacy plain-NLRI fields
    /// (only ever set for an `Ipv4Unicast` prefix/next-hop).
    pub use_mp: bool,
    /// `Some` only when reflecting (RFC 4456 §5) — the route's original
    /// advertising router, set once by the first reflector and never
    /// rewritten by a later one.
    pub originator_id: Option<Ipv4Addr>,
    /// `Some` only when reflecting — the reflected route's `CLUSTER_LIST`
    /// with this instance's own cluster-id prepended. Empty otherwise.
    pub cluster_list: Vec<Ipv4Addr>,
    /// Optional-transitive by RFC 1997/4360/8092 default, so — unlike
    /// `local_pref`/`med` — these three propagate to every eligible peer
    /// unconditionally, regardless of eBGP/iBGP; an export policy's
    /// `.clear()`/`.remove()` is the only way to strip one toward a
    /// specific peer.
    pub communities: Vec<u32>,
    pub extended_communities: Vec<u64>,
    pub large_communities: Vec<(u32, u32, u32)>,
    /// Transitive: forwarded unchanged to every eligible peer.
    pub atomic_aggregate: bool,
    pub aggregator: Option<message::Aggregator>,
    /// RFC 9234 Only to Customer ASN (`message::PathAttributes::otc`).
    pub otc: Option<u32>,
    /// RFC 7911 ADD-PATH identifier — `Some` exactly toward a peer we send
    /// ADD-PATH to for this family (`BgpRib::propagate_add_path`). `None`
    /// without ADD-PATH.
    pub path_id: Option<u32>,
}

#[allow(clippy::struct_excessive_bools)] // each bool is an independent, unrelated per-session flag
#[allow(clippy::similar_names)] // is_rr_client (reflector) vs. is_rs_client (server) are deliberately parallel
struct PeerOutbox {
    /// Send only through `OutboxTx::send` (bounded, coalescing, #395).
    tx: OutboxTx,
    /// `Internal` (the member AS, in a confederation).
    is_ibgp: bool,
    /// RFC 5065 confederation-external: next hop, MED and `LOCAL_PREF`
    /// kept as for iBGP, `AS_CONFED_SEQUENCE` prepended.
    is_confed: bool,
    /// This instance's confederation identifier when the peer was
    /// registered — the AS an external peer sees.
    confed_id: Option<u32>,
    /// The peer-group's vendor `local-as`, external peers only
    /// (`set_peer_local_as`) — see `prepend_external`.
    local_as: Option<nos_proto::BgpLocalAs>,
    /// This session's own transport-local address, of whatever family —
    /// used as next-hop-self for every negotiated address family this peer
    /// carries, cross-family or not (RFC 8950). `None` if it couldn't be
    /// determined, in which case this peer is never eligible for a
    /// `SelfAddress` advertisement.
    local_addr: Option<IpAddr>,
    /// Address families this peer actually negotiated (config ∩ what was
    /// negotiated in OPEN — see `fsm::negotiate_address_families`). A prefix
    /// whose family isn't in this set is never advertised to this peer.
    negotiated_afs: HashSet<AddressFamily>,
    /// Whether this peer negotiated any Multiprotocol Extensions capability
    /// at all — see `AdvertisedRoute::use_mp`.
    mp_bgp_negotiated: bool,
    /// This peer-group's configured next-hop override, if any — `None`
    /// resolves to `SelfAddress` for an eBGP peer, `Unchanged` for an iBGP
    /// one (see `build_advertisement`).
    next_hop_mode: Option<NextHopMode>,
    /// RFC 4456 route-reflector client — see `build_advertisement`'s
    /// reflection eligibility check.
    is_rr_client: bool,
    /// RFC 7947 route-server client — see `build_advertisement`'s `AS_PATH`
    /// exception and `BgpRib::propagate_add_path`.
    is_rs_client: bool,
    /// RFC 8097: attach the route's validation state (`set_peer_rpki_state`).
    announce_rpki_state: bool,
    /// RFC 8326: tag every export on this eBGP session with 65535:0
    /// (`BgpRib::set_graceful_shutdown`).
    gs_send: bool,
    /// See `BgpRib::peer_asns`.
    remote_asn: u32,
    /// RFC 9234: the peer's role (the counterpart of the configured one).
    remote_role: Option<nos_proto::BgpRole>,
    /// What an export policy sees as `local_role`/`remote_role` (`BgpRib::policy_roles`).
    policy_roles: PolicyRoles,
    /// Address families we send RFC 7911 ADD-PATH ids to this peer for
    /// (`fsm::negotiate_add_path`). Every NLRI of such a family must carry
    /// one, so the plain fan-out skips them and `propagate_add_path` sends
    /// them their paths.
    add_path_tx: HashSet<AddressFamily>,
    /// How many paths per prefix `propagate_add_path` sends this peer
    /// (`set_peer_add_path_send_count`); `None` is every path.
    add_path_send_count: Option<usize>,
    /// This peer-group's resolved export policy — always present, `deny-all`
    /// by default (see root `CLAUDE.md`'s "Default-deny rollout impact"),
    /// consulted by `build_advertisement`.
    export_policy: Arc<CompiledPolicy>,
    /// RFC 4684: what the peer asked for, rebuilt from its membership table
    /// on every change. `None` = RT-Constraint not negotiated = VPN/EVPN
    /// routes are not filtered (today's behaviour).
    rtc_interest: Option<rtc::RtcInterest>,
}

impl PeerOutbox {
    /// What an external (non-confederation) peer gets prepended (RFC 5065
    /// §4.1): our AS — the confederation identifier, if any — or, with a
    /// vendor `local-as`, `[local-as, ours]` (`[local-as]` with `replace-as`).
    fn prepend_external(&self, path: &mut AsPath, local_asn: u32) {
        match self.local_as {
            Some(l) if l.replace_as => {}
            _ => path.prepend_seq(self.confed_id.unwrap_or(local_asn)),
        }
        if let Some(l) = self.local_as {
            path.prepend_seq(l.asn);
        }
    }
}

/// The BGP RIB engine for one `nos-bgpd` instance. See the module doc
/// comment for the locking model.
pub struct BgpRib {
    /// Our AS — the member AS in an RFC 5065 confederation.
    local_asn: u32,
    /// RFC 5065 confederation identifier, if this instance is a member.
    confed_id: Option<u32>,
    /// Peers in another member AS of our confederation (`set_peer_confed`).
    confed_peers: HashSet<IpAddr>,
    /// External peers whose peer-group sets `local-as` (`set_peer_local_as`).
    local_as_peers: HashMap<IpAddr, nos_proto::BgpLocalAs>,
    /// Peers with a configured RFC 9234 role (`set_peer_role`), ours toward them.
    role_peers: HashMap<IpAddr, nos_proto::BgpRole>,
    /// Peers whose RFC 9234 role was negotiated this session (`set_peer_role_negotiated`).
    role_negotiated: HashSet<IpAddr>,
    /// Peers whose first AS is checked (`set_peer_enforce_first_as`).
    first_as_peers: HashSet<IpAddr>,
    /// Per peer: when the first-AS warning last fired and how many were
    /// suppressed since (`first_as_warn_due`).
    first_as_warned: HashMap<IpAddr, (Instant, u64)>,
    /// iBGP peers exchanging RFC 8097 states (`set_peer_rpki_state`).
    rpki_state_peers: HashSet<IpAddr>,
    /// RFC 7999 blackhole prefix-lists per peer (`set_peer_blackhole`); a peer
    /// not in it honours nothing.
    blackhole_peers: HashMap<IpAddr, Arc<Vec<nos_rpl::PrefixListEntry>>>,
    /// RFC 8326 knobs per peer (`set_graceful_shutdown`); a peer not in it has both off.
    gs_peers: HashMap<IpAddr, GsKnobs>,
    /// This instance's own router-id — used for RFC 4456 §5 `ORIGINATOR_ID`
    /// loop-prevention on receipt (`handle_update`).
    local_router_id: Ipv4Addr,
    /// This instance's effective RFC 4456 cluster-id (`BgpInstance.cluster_id`
    /// unwrapped to `router_id` when unset) — prepended to `CLUSTER_LIST` on
    /// reflection and checked for loop-prevention on receipt.
    cluster_id: Ipv4Addr,
    /// Every path each peer sent per prefix (several with RFC 7911 ADD-PATH).
    adj_rib_in: HashMap<IpAddr, PeerTable>,
    /// How many paths each peer's `adj_rib_in` holds per family — kept in
    /// step at every mutation (`put_path`/`take_path`) so the RFC 4486
    /// maximum-prefix check is O(1) per UPDATE, not a table scan.
    path_counts: HashMap<IpAddr, PathCounts>,
    /// BMP statistics counters per peer (#864), reset at `peer_established`.
    peer_stats: HashMap<IpAddr, PeerStats>,
    /// Pre-policy copies for peer-groups with soft reconfiguration inbound.
    retained: retain::Retained,
    /// The BMP hub the post-policy stream is tapped into (#864); `None` in
    /// tests that never attach one.
    bmp: Option<Arc<crate::bmp::Hub>>,
    /// Each peer's maximum-prefix limits (`set_peer_max_prefix`), and the
    /// `(peer, family)` pairs already warned about for a `warning_only` limit,
    /// so the warning is logged once per crossing.
    max_prefix: HashMap<IpAddr, nos_proto::BgpMaximumPrefix>,
    max_prefix_warned: HashSet<(IpAddr, AddressFamily)>,
    /// Received EVPN (RFC 7432) routes per peer, keyed by NLRI.
    // ponytail: Adj-RIB-In only, filtered by `evpn_import` (accept/reject) —
    // no best-path or re-advertisement; add a Loc-RIB when a MAC-VRF needs one.
    /// Keyed by `EvpnNlri::route_key` (RFC 7432 §7.2: labels and ESI are
    /// attributes, not identity).
    evpn_adj_rib_in: HashMap<IpAddr, HashMap<EvpnNlri, EvpnRoute>>,
    /// Peers with an EVPN import policy (`set_peer_evpn_import_policy`); a
    /// peer absent here accepts every EVPN route.
    evpn_import: HashMap<IpAddr, Arc<CompiledPolicy>>,
    /// Received Flowspec routes per peer (after import policy, validated).
    flowspec_adj_rib_in: HashMap<IpAddr, HashMap<FlowspecKey, FlowspecRoute>>,
    /// Per rule, the selected copy and the peer it came from (`select_flow`).
    flowspec_loc: HashMap<FlowspecKey, (IpAddr, FlowspecRoute)>,
    /// What each peer was last sent per rule (`sync_flow_to`).
    flowspec_adj_rib_out: HashMap<IpAddr, HashMap<FlowspecKey, AdvertisedFlowspec>>,
    /// Peers with a Flowspec import / export policy
    /// (`set_peer_flowspec_policies`); a peer absent here accepts all.
    flowspec_import: HashMap<IpAddr, Arc<CompiledPolicy>>,
    flowspec_export: HashMap<IpAddr, Arc<CompiledPolicy>>,
    /// The Flowspec twin of `evpn_stale`.
    flowspec_stale: HashMap<IpAddr, HashSet<FlowspecKey>>,
    /// Received VPN-IPv4/IPv6 paths per peer, keyed by (RD, prefix), every
    /// RT kept (see `vpn_out`).
    vpn_adj_rib_in: HashMap<IpAddr, HashMap<VpnKey<IpNet>, VpnRoute>>,
    /// Per key, the selected copy and where it came from (`select_vpn`).
    vpn_loc: HashMap<VpnKey<IpNet>, (RouteOrigin, VpnRoute)>,
    /// VRF routes `nos-ribd` exports (`apply_vpn_prefixes`), per table so
    /// one table's `Full` never clobbers another's; `Local` candidates.
    vpn_local: HashMap<String, HashMap<VpnKey<IpNet>, VpnRoute>>,
    /// What each peer was last sent per key (`sync_vpn_to`).
    vpn_adj_rib_out: HashMap<IpAddr, HashMap<VpnKey<IpNet>, AdvertisedVpn>>,
    /// The VPN twin of `stale` (graceful restart and RFC 7313 refresh).
    vpn_stale: HashMap<IpAddr, HashSet<VpnKey<IpNet>>>,
    /// The VRFs this (underlay) instance imports VPN routes into (`vpn_import`).
    vpn_vrfs: crate::vpn::VrfSet,
    /// RFC 4684 membership per peer (`rtc`), stale entries included.
    rtc_adj_rib_in: HashMap<IpAddr, HashMap<RtcKey, RibRoute>>,
    /// The Route Targets this instance originates membership for.
    rtc_local: std::collections::BTreeSet<u64>,
    /// Per key, the selected copy and where it came from (`select_rtc`).
    rtc_loc: HashMap<RtcKey, (RouteOrigin, RibRoute)>,
    /// Membership kept across a graceful restart (RFC 4724), still live
    /// interest until re-announced, End-of-RIB or the timers.
    rtc_stale: HashMap<IpAddr, HashSet<RtcKey>>,
    /// What each peer was last sent per key (`sync_rtc_to`).
    rtc_adj_rib_out: HashMap<IpAddr, HashMap<RtcKey, AdvertisedRtc>>,
    /// Peers whose peer-group tunes Flowspec validation (`set_peer_flowspec_validation`).
    flowspec_validation: HashMap<IpAddr, nos_proto::BgpFlowspecValidation>,
    /// Derived indexes for incremental Flowspec revalidation.
    flow_ix: flowspec_validate::FlowIndexes,
    /// RFC 7313: paths (prefix, path id) in a peer's Adj-RIB-In marked stale
    /// by a `BoRR` and not yet re-announced; purged by the matching `EoRR`.
    stale: HashMap<IpAddr, HashSet<(IpNet, u32)>>,
    /// The EVPN twin of `stale` (route keys), filled only by a graceful restart.
    evpn_stale: HashMap<IpAddr, HashSet<EvpnNlri>>,
    /// RFC 4724: each peer's last graceful restart capability
    /// (`set_peer_gr`), recorded only while this instance has graceful
    /// restart on. Kept across the peer's sessions, so its presence also
    /// means this process already had a session with it — what our F bit
    /// says (`gr_forwarding`).
    gr: HashMap<IpAddr, PeerGr>,
    /// When a peer's retained (stale) routes are purged if no End-of-RIB
    /// came: its restart time after it went down, `gr_stale_time` after it
    /// came back. Present exactly while a graceful restart is in progress.
    gr_deadline: HashMap<IpAddr, Instant>,
    /// `BgpGracefulRestart.stale_time`.
    gr_stale_time: Duration,
    /// RFC 4724 §4.1: set while this restarting process defers what it
    /// sends (`begin_deferral`); every send site returns early meanwhile.
    deferral: Option<crate::gr::Deferral>,
    /// `nos-ribd` still held BGP routes when this process started, so our
    /// F bit is 1 toward every peer (`gr_forwarding`).
    forwarding_preserved: bool,
    /// `nos-ribd`'s redistribution feed has delivered its first snapshot.
    redistribute_seen: bool,
    /// EVPN routes originated by each `nos-fdbd` (keyed by broadcast domain),
    /// and what was last announced to each peer — see `evpn_out`.
    evpn_local: HashMap<evpn_out::EvpnSource, HashMap<nos_proto::EvpnKey, nos_proto::EvpnRoute>>,
    evpn_adj_rib_out: HashMap<IpAddr, HashMap<EvpnNlri, AdvertisedEvpn>>,
    /// Broadcast domains whose `redistribute from mac to bgp` names this
    /// instance — the ones `fdb_push_client` feeds received EVPN routes to.
    fdb_domains: Vec<String>,
    /// Routing tables whose `evpn.bgp_instance` names this instance — the
    /// ones `fdb_push_client` feeds received Type-5 routes to.
    evpn_tables: Vec<String>,
    /// The unfiltered prefix set as told by `nos-ribd`'s
    /// `RedistributeUpdate` — the raw truth `redistributed` below is
    /// filtered from (see `apply_redistribute_update`/`set_redistribute_policy`).
    redistribute_raw: HashSet<IpNet>,
    /// `redistribute_raw` filtered through `redistribute_policy` — this is
    /// what best-path selection (`recompute_and_propagate`) actually reads.
    redistributed: HashMap<IpNet, RibRoute>,
    /// The compiled RPL policy currently filtering redistribution, resolved
    /// from `BgpInstance.redistribute_policy` by `reconcile.rs`'s `resync`
    /// (`None` there means accept-all, unlike peer import/export's
    /// deny-all default — see `proto`'s `Redistribute.policy` doc comment).
    redistribute_policy: Arc<CompiledPolicy>,
    /// `BgpInstance.aggregates` and each one's contributors — see `aggregate`.
    aggregates: Vec<aggregate::AggregateState>,
    /// Active aggregate routes: a local candidate source like `redistributed`.
    aggregated: HashMap<IpNet, RibRoute>,
    loc_rib: HashMap<IpNet, RibRoute>,
    /// IGP cost per prefix, as last polled from `nos-ribd` — decision step (d).
    igp: HashMap<IpNet, u32>,
    /// Whether `igp` has been fetched at least once — before that, no
    /// candidate is excluded for an unresolvable next hop (see the module
    /// doc comment).
    igp_ready: bool,
    /// Per prefix, the runner-up path's next hop (a different next hop from
    /// the winner's), pushed to `nos-ribd` as the kernel backup route.
    backups: HashMap<IpNet, IpAddr>,
    /// Per prefix, the multipath next-hop set (`multipath_next_hops`) when
    /// it holds two or more — absent means the winner's own next hop alone.
    multipaths: HashMap<IpNet, Vec<IpAddr>>,
    /// `BgpInstance.maximum_paths` (1 when unset): how many next hops a
    /// prefix may install.
    maximum_paths: usize,
    /// What we've last told each peer, for correct withdrawals.
    adj_rib_out: HashMap<IpAddr, HashSet<IpNet>>,
    /// BMP pre-policy Adj-RIB-Out (#867): the prefixes announced to a
    /// collector per monitored peer; only filled while a station wants it.
    bmp_pre_out: HashMap<IpAddr, HashSet<IpNet>>,
    peer_outboxes: HashMap<IpAddr, PeerOutbox>,
    /// Each peer's negotiated remote ASN (see `set_peer_asn`), for RPL's
    /// `this.bgp.peer_as`. Kept across resets like damping params.
    peer_asns: HashMap<IpAddr, u32>,
    /// Per ADD-PATH send peer, per prefix, the path id and last-sent
    /// snapshot of every path currently advertised to it — see
    /// `propagate_add_path`.
    add_path_sent: HashMap<(IpAddr, IpNet), AddPathSent>,
    /// Per ADD-PATH send peer, per prefix, the next fresh path id —
    /// monotonic, never recycled once withdrawn (see `send_add_paths`).
    add_path_next_id: HashMap<(IpAddr, IpNet), u32>,
    /// Each peer's resolved `add_path_send_count` (`None`: every path), set
    /// before `peer_established` like `set_peer_local_as`.
    add_path_counts: HashMap<IpAddr, Option<usize>>,
    /// Reusable scratch buffer for `recompute_and_propagate`'s peer list —
    /// swapped out via `mem::take` and refilled each call instead of
    /// collecting a fresh `Vec` on every touched prefix, so its capacity is
    /// retained across calls once it reaches the peer count.
    peer_scratch: Vec<IpAddr>,
    /// RFC 2439 flap-damping state for received routes; a suppressed
    /// (peer, prefix) stays in `adj_rib_in` but is not a best-path candidate.
    damping: Damping,
    /// RFC 7432 §15 EVPN MAC mobility: which advertisement (local or from a
    /// peer) for a `(VNI, MAC)` is authoritative, and §15.2 duplicate-MAC
    /// freezing — see `evpn_out`.
    mac_mobility: MacMobility,
    /// This instance's owning `RoutingTable` name (`BgpInstance.routing_table`),
    /// set by `session::SessionManager::reconcile`. Read by `push_snapshot`
    /// to resolve which `nos-ribd` instance, if any, this instance's best
    /// routes should be pushed to.
    owning_routing_table: Option<String>,
    /// The RPKI VRP set (RFC 6811) every route is validated against, from
    /// the instance's RTR client (`crate::rpki`).
    vrps: Arc<crate::rpki::VrpTable>,
}

impl Default for BgpRib {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpRib {
    pub fn new() -> Self {
        Self {
            local_asn: 0,
            confed_id: None,
            confed_peers: HashSet::new(),
            local_as_peers: HashMap::new(),
            role_peers: HashMap::new(),
            role_negotiated: HashSet::new(),
            first_as_peers: HashSet::new(),
            first_as_warned: HashMap::new(),
            blackhole_peers: HashMap::new(),
            rpki_state_peers: HashSet::new(),
            gs_peers: HashMap::new(),
            local_router_id: Ipv4Addr::UNSPECIFIED,
            cluster_id: Ipv4Addr::UNSPECIFIED,
            adj_rib_in: HashMap::new(),
            retained: retain::Retained::default(),
            bmp: None,
            path_counts: HashMap::new(),
            peer_stats: HashMap::new(),
            max_prefix: HashMap::new(),
            max_prefix_warned: HashSet::new(),
            evpn_adj_rib_in: HashMap::new(),
            evpn_import: HashMap::new(),
            flowspec_adj_rib_in: HashMap::new(),
            flowspec_loc: HashMap::new(),
            flowspec_adj_rib_out: HashMap::new(),
            flowspec_import: HashMap::new(),
            flowspec_export: HashMap::new(),
            flowspec_stale: HashMap::new(),
            flowspec_validation: HashMap::new(),
            vpn_adj_rib_in: HashMap::new(),
            vpn_loc: HashMap::new(),
            vpn_local: HashMap::new(),
            vpn_adj_rib_out: HashMap::new(),
            vpn_stale: HashMap::new(),
            vpn_vrfs: crate::vpn::VrfSet::default(),
            rtc_adj_rib_in: HashMap::new(),
            rtc_local: std::collections::BTreeSet::new(),
            rtc_loc: HashMap::new(),
            rtc_stale: HashMap::new(),
            rtc_adj_rib_out: HashMap::new(),
            flow_ix: flowspec_validate::FlowIndexes::default(),
            stale: HashMap::new(),
            evpn_stale: HashMap::new(),
            gr: HashMap::new(),
            gr_deadline: HashMap::new(),
            gr_stale_time: Duration::from_secs(u64::from(nos_proto::GR_STALE_TIME_DEFAULT)),
            deferral: None,
            forwarding_preserved: false,
            redistribute_seen: false,
            evpn_local: HashMap::new(),
            evpn_adj_rib_out: HashMap::new(),
            fdb_domains: Vec::new(),
            evpn_tables: Vec::new(),
            redistribute_raw: HashSet::new(),
            redistributed: HashMap::new(),
            redistribute_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            aggregates: Vec::new(),
            aggregated: HashMap::new(),
            loc_rib: HashMap::new(),
            igp: HashMap::new(),
            igp_ready: false,
            backups: HashMap::new(),
            multipaths: HashMap::new(),
            maximum_paths: 1,
            adj_rib_out: HashMap::new(),
            bmp_pre_out: HashMap::new(),
            peer_outboxes: HashMap::new(),
            peer_asns: HashMap::new(),
            add_path_sent: HashMap::new(),
            add_path_next_id: HashMap::new(),
            add_path_counts: HashMap::new(),
            peer_scratch: Vec::new(),
            damping: Damping::default(),
            mac_mobility: MacMobility::default(),
            owning_routing_table: None,
            vrps: Arc::default(),
        }
    }

    /// The origin AS a route with `path` validates as (RFC 6811 §2): our
    /// own AS — the confederation identifier, if any — for a path with no
    /// non-confederation segment.
    fn validate(&self, prefix: IpNet, path: &AsPath) -> nos_rpl::ValidationState {
        self.vrps.validate(
            prefix,
            crate::rpki::origin_as(path, self.confed_id.unwrap_or(self.local_asn)),
        )
    }

    pub fn vrps(&self) -> Arc<crate::rpki::VrpTable> {
        self.vrps.clone()
    }

    /// Installs a new VRP set and re-validates every held route in place,
    /// re-deciding each prefix whose state changed — so best path and export
    /// policies see it at once. An import policy reading the state needs the
    /// routes again (rejected ones aren't held), which is the caller's route
    /// refresh (`SessionManager::apply_vrps`).
    pub fn set_vrps(&mut self, vrps: Arc<crate::rpki::VrpTable>) {
        self.vrps = vrps;
        let local = self.confed_id.unwrap_or(self.local_asn);
        let mut touched = HashSet::new();
        for table in self.adj_rib_in.values_mut() {
            for (prefix, paths) in table.iter_mut() {
                for (_, route) in paths.iter_mut() {
                    let state = ov_state(
                        &self.vrps,
                        *prefix,
                        crate::rpki::origin_as(&route.as_path, local),
                        route.received_ov,
                    );
                    if state != route.validation_state {
                        route.validation_state = state;
                        touched.insert(*prefix);
                    }
                }
            }
        }
        for prefix in self.redistribute_raw.clone() {
            if self.refilter_redistribute(prefix) {
                touched.insert(prefix);
            }
        }
        info!(
            vrps = self.vrps.len(),
            revalidated = touched.len(),
            "rpki vrp set applied"
        );
        for prefix in touched {
            self.recompute_and_propagate(prefix);
        }
    }

    /// Sets this instance's own ASN, router-id, and effective RFC 4456
    /// cluster-id (already resolved from `BgpInstance.cluster_id.unwrap_or(
    /// router_id)` by the caller — see `session::LocalIdentity`).
    pub fn set_local_identity(&mut self, asn: u32, router_id: Ipv4Addr, cluster_id: Ipv4Addr) {
        self.local_asn = asn;
        self.local_router_id = router_id;
        self.cluster_id = cluster_id;
    }

    /// Sets `BgpInstance.maximum_paths` (`None`: 1) and, on a change,
    /// re-decides every received prefix's multipath set.
    pub fn set_maximum_paths(&mut self, maximum_paths: Option<u8>) {
        let max = usize::from(maximum_paths.unwrap_or(1).max(1));
        if max == self.maximum_paths {
            return;
        }
        self.maximum_paths = max;
        let prefixes: HashSet<IpNet> = self
            .adj_rib_in
            .values()
            .flat_map(HashMap::keys)
            .copied()
            .collect();
        for prefix in prefixes {
            self.recompute_and_propagate(prefix);
        }
    }

    /// Sets the RFC 5065 confederation identifier (`None`: not confederated).
    pub fn set_confederation(&mut self, confed_id: Option<u32>) {
        self.confed_id = confed_id;
    }

    /// Records whether `peer` is in another member AS of our confederation.
    /// Call before `peer_established`, like `set_peer_asn`.
    pub fn set_peer_confed(&mut self, peer: IpAddr, confed: bool) {
        if confed {
            self.confed_peers.insert(peer);
        } else {
            self.confed_peers.remove(&peer);
        }
    }

    /// Records `peer`'s vendor `local-as` (`None`: none, or not an external
    /// peer). Call before `peer_established`, like `set_peer_confed`.
    pub fn set_peer_local_as(&mut self, peer: IpAddr, local_as: Option<nos_proto::BgpLocalAs>) {
        match local_as {
            Some(l) => self.local_as_peers.insert(peer, l),
            None => self.local_as_peers.remove(&peer),
        };
    }

    /// Records whether `peer`'s UPDATEs must start with its own AS (RFC 4271
    /// §6.3; eBGP only, applied in `handle_update`). Call before `peer_established`.
    pub fn set_peer_enforce_first_as(&mut self, peer: IpAddr, enforce: bool) {
        if enforce {
            self.first_as_peers.insert(peer);
        } else {
            self.first_as_peers.remove(&peer);
        }
    }

    /// Records `peer`'s peer-group Flowspec validation knobs. Call before
    /// `peer_established`.
    pub fn set_peer_flowspec_validation(
        &mut self,
        peer: IpAddr,
        v: nos_proto::BgpFlowspecValidation,
    ) {
        if v == nos_proto::BgpFlowspecValidation::default() {
            self.flowspec_validation.remove(&peer);
        } else {
            self.flowspec_validation.insert(peer, v);
        }
    }

    /// Records `peer`'s RFC 7999 blackhole prefix-list (`None`: ordinary
    /// community). Call before `peer_established`, like `set_peer_rpki_state`.
    pub fn set_peer_blackhole(
        &mut self,
        peer: IpAddr,
        list: Option<Arc<Vec<nos_rpl::PrefixListEntry>>>,
    ) {
        match list {
            Some(l) => self.blackhole_peers.insert(peer, l),
            None => self.blackhole_peers.remove(&peer),
        };
    }

    /// Whether `route` for `prefix` is an RFC 7999 blackhole: learned from a
    /// peer with a blackhole prefix-list that covers `prefix`, and tagged
    /// BLACKHOLE.
    fn is_blackhole(&self, prefix: IpNet, route: &RibRoute) -> bool {
        let RouteOrigin::Peer(peer) = route.origin else {
            return false;
        };
        self.blackhole_peers
            .get(&peer)
            .is_some_and(|l| blackhole_applies(l, prefix, &route.communities))
    }

    /// At most one first-AS warning per peer per `FIRST_AS_WARN_EVERY`: the
    /// count suppressed since the last one, or `None` to stay quiet.
    fn first_as_warn_due(&mut self, peer: IpAddr) -> Option<u64> {
        let now = Instant::now();
        if let Some((last, n)) = self.first_as_warned.get_mut(&peer)
            && now.duration_since(*last) < FIRST_AS_WARN_EVERY
        {
            *n += 1;
            return None;
        }
        Some(
            self.first_as_warned
                .insert(peer, (now, 0))
                .map_or(0, |e| e.1),
        )
    }

    /// Records our configured RFC 9234 role toward `peer` (`None`: none).
    /// RFC 9234 §4.2: the procedures apply even when the peer sent no Role. Call before `peer_established`, like `set_peer_local_as`.
    pub fn set_peer_role(&mut self, peer: IpAddr, role: Option<nos_proto::BgpRole>) {
        match role {
            Some(r) => self.role_peers.insert(peer, r),
            None => self.role_peers.remove(&peer),
        };
    }

    /// Whether the peer's Role capability matched ours this session; only then
    /// does a policy see `remote_role`. Call with `set_peer_role`.
    pub fn set_peer_role_negotiated(&mut self, peer: IpAddr, negotiated: bool) {
        if negotiated {
            self.role_negotiated.insert(peer);
        } else {
            self.role_negotiated.remove(&peer);
        }
    }

    /// `(local_role, remote_role)` a unicast policy for `peer` sees: ours, and
    /// the counterpart only when negotiated (a mismatch is refused, so it equals
    /// what the peer sent).
    fn policy_roles(&self, peer: IpAddr) -> PolicyRoles {
        let local = self.role_peers.get(&peer).copied();
        let remote = local.filter(|_| self.role_negotiated.contains(&peer));
        (
            local.map(rpl_role),
            remote.map(|r| rpl_role(r.counterpart())),
        )
    }

    /// Sets `peer`'s EVPN import policy (`None`: accept all) and re-runs the
    /// routes it already holds through it, dropping the rejected ones — a
    /// policy change restarts the session, but a graceful restart keeps the
    /// stored routes. Call before `peer_established`.
    pub fn set_peer_evpn_import_policy(
        &mut self,
        peer: IpAddr,
        policy: Option<Arc<CompiledPolicy>>,
        is_ibgp: bool,
    ) {
        let Some(policy) = policy else {
            self.evpn_import.remove(&peer);
            return;
        };
        let peer_as = self.peer_asns.get(&peer).copied().unwrap_or(0);
        let bmp = bmp_tap::tap(self.bmp.as_ref());
        if let Some(table) = self.evpn_adj_rib_in.get_mut(&peer) {
            table.retain(|key, route| {
                let rejected = adj_in::evpn_rejected(&policy, route, peer, peer_as, is_ibgp);
                if rejected {
                    warn!(peer = %peer, route_type = key.route_type(), route = %key, "evpn route rejected by import policy");
                    if let Some(h) = bmp {
                        h.evpn_post(peer, &route.nlri, None);
                    }
                }
                !rejected
            });
        }
        self.evpn_import.insert(peer, policy);
    }

    /// Our configured RFC 9234 role toward `peer`, if any.
    pub fn peer_role(&self, peer: IpAddr) -> Option<nos_proto::BgpRole> {
        self.role_peers.get(&peer).copied()
    }

    /// Records how many paths per prefix `peer` is sent over ADD-PATH
    /// (`ResolvedPeer::add_path_send_count`; `None`: every path). Call before
    /// `peer_established`, like `set_peer_local_as`. Never set: the
    /// unconfigured default.
    pub fn set_peer_add_path_send_count(&mut self, peer: IpAddr, count: Option<usize>) {
        self.add_path_counts.insert(peer, count);
    }

    /// Replaces every peer's RFC 8326 knobs (`BgpPeerGroup.graceful_shutdown*`,
    /// applied live, outside `ResolvedPeer`). Returns the peers whose knobs
    /// changed (with whether the sender side did); an established one needs
    /// a Route Refresh (`SessionManager`). A sender change re-advertises here.
    pub fn set_graceful_shutdown(
        &mut self,
        knobs: HashMap<IpAddr, GsKnobs>,
    ) -> Vec<(IpAddr, bool)> {
        let mut changed = Vec::new();
        for peer in self
            .gs_peers
            .keys()
            .chain(knobs.keys())
            .collect::<HashSet<_>>()
        {
            let old = self.gs_peers.get(peer).copied().unwrap_or_default();
            let new = knobs.get(peer).copied().unwrap_or_default();
            if old != new {
                changed.push((*peer, old.send != new.send));
            }
        }
        let mut resend = Vec::new();
        for (peer, send_changed) in &changed {
            if *send_changed && let Some(o) = self.peer_outboxes.get_mut(peer) {
                o.gs_send = knobs.get(peer).is_some_and(|k| k.send);
                resend.push((*peer, o.negotiated_afs.clone()));
            }
        }
        self.gs_peers = knobs;
        // Re-advertise so the new tag (or its absence) goes out.
        for (peer, families) in resend {
            let mut vpn_done = false;
            for family in families {
                if family == AddressFamily::L2vpnEvpn {
                    self.announce_evpn_to(peer);
                } else if crate::fsm::is_vpn(family) {
                    // Not `resend_all`: that replays what was last sent.
                    // One call covers both VPN families.
                    if !std::mem::replace(&mut vpn_done, true) {
                        self.announce_vpn_to(peer);
                    }
                } else {
                    self.resend_all(peer, family, false);
                }
            }
        }
        changed
    }

    /// Records whether `peer` exchanges RFC 8097 validation states (an
    /// opted-in iBGP peer). Call before `peer_established`, like `set_peer_asn`.
    pub fn set_peer_rpki_state(&mut self, peer: IpAddr, on: bool) {
        if on {
            self.rpki_state_peers.insert(peer);
        } else {
            self.rpki_state_peers.remove(&peer);
        }
    }

    /// Sets the broadcast domains fed by `fdb_push_client`.
    pub fn set_fdb_domains(&mut self, domains: Vec<String>) {
        self.fdb_domains = domains;
    }

    pub fn fdb_domains(&self) -> &[String] {
        &self.fdb_domains
    }

    /// Sets the IP-VRFs (routing tables) fed received Type-5 routes.
    pub fn set_evpn_tables(&mut self, tables: Vec<String>) {
        self.evpn_tables = tables;
    }

    pub fn evpn_tables(&self) -> &[String] {
        &self.evpn_tables
    }

    /// Sets this instance's owning `RoutingTable` name (`BgpInstance.routing_table`).
    pub fn set_routing_table(&mut self, table: Option<String>) {
        self.owning_routing_table = table;
    }

    /// Snapshot for `rib_push_client`: this instance's owning routing table
    /// name, and every loc-rib prefix whose winner has a real next-hop. A
    /// `Local`-origin (redistributed-from-static) loc-rib entry always has
    /// `next_hop: None` (see `redistributed_route`) and is excluded — there's
    /// no real gateway to install, and pushing it would round-trip
    /// static→bgp→rib→kernel pointlessly on the same table it came from.
    pub fn push_snapshot(&self) -> (Option<String>, HashMap<IpNet, Hops>) {
        // Deferring: `nos-ribd` keeps what it holds, rather than getting a
        // `Full` of a Loc-RIB that is still filling.
        if self.deferring() {
            return (None, HashMap::new());
        }
        let routes = self
            .loc_rib
            .iter()
            .filter_map(|(prefix, route)| {
                route.next_hop.map(|next_hop| {
                    if self.is_blackhole(*prefix, route) {
                        return (*prefix, (vec![], None, true));
                    }
                    let hops = self
                        .multipaths
                        .get(prefix)
                        .cloned()
                        .unwrap_or_else(|| vec![next_hop]);
                    (*prefix, (hops, self.backups.get(prefix).copied(), false))
                })
            })
            .collect();
        (self.owning_routing_table.clone(), routes)
    }

    /// The source peer of `route` is a route-reflector client iff it's still
    /// a registered peer with `is_rr_client` set — `false` for a `Local`
    /// route or a source peer that's since disconnected.
    fn source_is_rr_client(&self, route: &RibRoute) -> bool {
        match route.origin {
            RouteOrigin::Peer(addr) => self
                .peer_outboxes
                .get(&addr)
                .is_some_and(|o| o.is_rr_client),
            RouteOrigin::Local => false,
        }
    }

    /// Deregisters a peer's outbox and Adj-RIB-In, then re-decides every
    /// prefix that peer had contributed — the implicit withdraw-everything
    /// path for a session ending, whatever the reason.
    /// Whether `peer` currently has a registered outbound channel — i.e. an
    /// `Established` session that route propagation can actually reach.
    /// `false` while only a losing/collided connection exists for it.
    pub fn has_peer(&self, peer: IpAddr) -> bool {
        self.peer_outboxes.contains_key(&peer)
    }

    /// Every received EVPN route, ordered by peer then route for stable output.
    pub fn evpn_routes(&self) -> Vec<(IpAddr, &EvpnNlri, &EvpnRoute)> {
        let mut out: Vec<_> = self
            .evpn_adj_rib_in
            .iter()
            .flat_map(|(peer, t)| t.values().map(move |r| (*peer, &r.nlri, r)))
            .collect();
        out.sort_by_cached_key(|(peer, n, _)| (*peer, n.to_string()));
        out
    }

    /// The sort key of every received EVPN route, sorted: the snapshot a
    /// paged `show bgp evpn` walk searches (#723). Keys only.
    pub fn evpn_keys(&self) -> Vec<EvpnKey> {
        let mut keys: Vec<_> = self
            .evpn_adj_rib_in
            .iter()
            .flat_map(|(peer, t)| {
                t.iter().map(move |(k, r)| Keyed {
                    cursor: nos_proto::EvpnRouteCursor {
                        peer: *peer,
                        route: r.nlri.to_string(),
                    },
                    row: Some(k.clone()),
                })
            })
            .collect();
        keys.sort_unstable();
        keys
    }

    /// The route for one `evpn_keys` key; `None` when it is gone.
    pub fn evpn_at(&self, key: &EvpnKey) -> Option<(IpAddr, &EvpnRoute)> {
        let peer = key.cursor.peer;
        let route = self.evpn_adj_rib_in.get(&peer)?.get(key.row.as_ref()?)?;
        Some((peer, route))
    }

    /// The sort key of every received Flowspec route, sorted (#723).
    pub fn flowspec_keys(&self) -> Vec<FlowKey> {
        let mut keys: Vec<_> = self
            .flowspec_adj_rib_in
            .iter()
            .flat_map(|(peer, t)| {
                t.iter().map(move |(k, r)| Keyed {
                    cursor: nos_proto::FlowspecRouteCursor {
                        peer: *peer,
                        family: r.family.to_string(),
                        nlri: r.nlri.to_string(),
                    },
                    row: Some(k.clone()),
                })
            })
            .collect();
        keys.sort_unstable();
        keys
    }

    /// The route for one `flowspec_keys` key; `None` when it is gone.
    pub fn flowspec_at(&self, key: &FlowKey) -> Option<(IpAddr, &FlowspecRoute)> {
        let peer = key.cursor.peer;
        let route = self
            .flowspec_adj_rib_in
            .get(&peer)?
            .get(key.row.as_ref()?)?;
        Some((peer, route))
    }

    /// Every received Flowspec route, ordered by peer then rule.
    pub fn flowspec_routes(&self) -> Vec<(IpAddr, &FlowspecRoute)> {
        let mut out: Vec<_> = self
            .flowspec_adj_rib_in
            .iter()
            .flat_map(|(peer, t)| t.values().map(move |r| (*peer, r)))
            .collect();
        out.sort_by_cached_key(|(peer, r)| (*peer, r.family.to_string(), r.nlri.to_string()));
        out
    }

    /// Every IPv4/IPv6 unicast path held (each Adj-RIB-In path, all ADD-PATH
    /// ones, plus the locally redistributed routes) for `show bgp routes`,
    /// ordered by prefix then peer (local first).
    pub fn routes(&self) -> Vec<nos_proto::BgpRouteSummary> {
        self.route_keys()
            .iter()
            .filter_map(|k| self.route_at(k))
            .collect()
    }

    /// The sort key of every path `routes` lists, sorted: the snapshot a
    /// paged walk searches (#722). Keys only, no summaries.
    pub fn route_keys(&self) -> Vec<nos_proto::BgpRouteCursor> {
        let mut keys: Vec<_> = self
            .redistributed
            .keys()
            .map(|p| nos_proto::BgpRouteCursor {
                prefix: *p,
                peer: None,
                path_id: 0,
            })
            .collect();
        for (peer, table) in &self.adj_rib_in {
            for (prefix, paths) in table {
                keys.extend(paths.iter().map(|(id, _)| nos_proto::BgpRouteCursor {
                    prefix: *prefix,
                    peer: Some(*peer),
                    path_id: *id,
                }));
            }
        }
        keys.sort_unstable();
        keys
    }

    /// The summary for one `route_keys` key; `None` when the path is gone.
    pub fn route_at(&self, key: &nos_proto::BgpRouteCursor) -> Option<nos_proto::BgpRouteSummary> {
        use nos_proto::RpkiValidationState as S;
        let r = match key.peer {
            None => self.redistributed.get(&key.prefix)?,
            Some(peer) => adj_in::get_path(self.adj_rib_in.get(&peer)?, key.prefix, key.path_id)?,
        };
        let local = self.confed_id.unwrap_or(self.local_asn);
        Some(nos_proto::BgpRouteSummary {
            prefix: key.prefix.to_string(),
            peer: key.peer,
            next_hop: r.next_hop,
            as_path: r.as_path.to_string(),
            origin_as: crate::rpki::origin_as(&r.as_path, local),
            local_pref: r.local_pref,
            best: self.loc_rib.get(&key.prefix) == Some(r),
            validation_state: match r.validation_state {
                nos_rpl::ValidationState::Valid => S::Valid,
                nos_rpl::ValidationState::Invalid => S::Invalid,
                nos_rpl::ValidationState::NotFound => S::NotFound,
            },
        })
    }

    /// Enables (or with `None` disables) RFC 2439 damping of routes from `peer`.
    /// Records the remote ASN negotiated in a peer's OPEN, so import and
    /// export policies can match `this.bgp.peer_as`. Call before
    /// `peer_established`.
    pub fn set_peer_asn(&mut self, peer: IpAddr, asn: u32) {
        self.peer_asns.insert(peer, asn);
    }

    pub fn set_peer_damping(&mut self, peer: IpAddr, params: Option<BgpDamping>) {
        self.damping.set_params(peer, params);
    }

    /// Sets `peer`'s RFC 4486 maximum-prefix limits (see `check_max_prefix`).
    pub fn set_peer_max_prefix(&mut self, peer: IpAddr, limits: nos_proto::BgpMaximumPrefix) {
        self.max_prefix.insert(peer, limits);
    }

    /// Accepted (post-import-policy) paths held from `peer` — prefixes, or
    /// more with RFC 7911 ADD-PATH: ipv4, ipv6, l2vpn-evpn.
    pub fn accepted_prefixes(&self, peer: IpAddr) -> [u32; 3] {
        let len = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let [v4, v6] = self.path_counts.get(&peer).copied().unwrap_or_default();
        let evpn = len(self.evpn_adj_rib_in.get(&peer).map_or(0, HashMap::len));
        [v4, v6, evpn]
    }

    /// Flowspec routes held from `peer`, `[ipv4, ipv6]`.
    fn accepted_flowspec(&self, peer: IpAddr) -> [u32; 2] {
        let mut n = [0u32; 2];
        for (family, _) in self
            .flowspec_adj_rib_in
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::keys)
        {
            n[usize::from(*family == AddressFamily::Ipv6Flowspec)] += 1;
        }
        n
    }

    /// Paths held from `peer` of `family`.
    fn accepted_count(&self, peer: IpAddr, family: AddressFamily) -> u32 {
        let [v4, v6, evpn] = self.accepted_prefixes(peer);
        match family {
            AddressFamily::Ipv4Unicast => v4,
            AddressFamily::Ipv6Unicast => v6,
            AddressFamily::L2vpnEvpn => evpn,
            AddressFamily::Ipv4Flowspec => self.accepted_flowspec(peer)[0],
            AddressFamily::Ipv6Flowspec => self.accepted_flowspec(peer)[1],
            AddressFamily::Vpnv4Unicast => self.accepted_vpn(peer)[0],
            AddressFamily::Vpnv6Unicast => self.accepted_vpn(peer)[1],
            AddressFamily::RtConstraint => self.accepted_rtc(peer),
        }
    }

    /// RFC 4486 §4: the first address family whose accepted-prefix count from
    /// `peer` is over a hard (not `warning_only`) limit, with that count —
    /// the caller closes the session. Logs `maximum prefix limit exceeded`
    /// once per crossing for every family over its limit, hard or not.
    pub fn check_max_prefix(
        &mut self,
        peer: IpAddr,
    ) -> Option<(AddressFamily, nos_proto::BgpPrefixLimit, u32)> {
        let limits = *self.max_prefix.get(&peer)?;
        let mut tripped = None;
        for family in AddressFamily::ALL {
            let Some(limit) = limits.get(family) else {
                continue;
            };
            // Only for a limited family: Flowspec and VPN are counted by scan.
            let count = self.accepted_count(peer, family);
            // `limit 0` is explicitly uncapped.
            if limit.limit == 0 || count <= limit.limit {
                self.max_prefix_warned.remove(&(peer, family));
                continue;
            }
            if self.max_prefix_warned.insert((peer, family)) {
                warn!(
                    peer = %peer, family = %family, count, limit = limit.limit,
                    warning_only = limit.warning_only,
                    "maximum prefix limit exceeded"
                );
            }
            if !limit.warning_only && tripped.is_none() {
                tripped = Some((family, limit, count));
            }
        }
        tripped
    }

    /// Installs a fresh IGP cost table (see `igp_client`) and, if it changed
    /// (or this is the first table ever fetched, which turns the feasibility
    /// check on), re-decides every prefix — an IGP change is not a BGP event,
    /// so nothing else would trigger it. Every Adj-RIB-In prefix is
    /// re-decided, not only the Loc-RIB: a candidate excluded as unfeasible
    /// isn't in the Loc-RIB, and a new IGP route is exactly what admits it.
    pub fn set_igp(&mut self, igp: HashMap<IpNet, u32>) {
        let first = !self.igp_ready;
        self.igp_ready = true;
        if !first && igp == self.igp {
            return;
        }
        self.igp = igp;
        tracing::info!(costs = ?self.igp, "igp costs updated");
        let prefixes: HashSet<IpNet> = self
            .loc_rib
            .keys()
            .chain(self.adj_rib_in.values().flat_map(HashMap::keys))
            .copied()
            .collect();
        for prefix in prefixes {
            self.recompute_and_propagate(prefix);
        }
    }

    /// RFC 4271 §9.1.2: a candidate is feasible if it has no next hop of its
    /// own (a locally-redistributed route), if no IGP table has been fetched
    /// yet (startup), or if some route in that table covers its next hop —
    /// which includes `nos-ribd`'s `Connected` routes, so a directly
    /// connected next hop resolves. No link-local exception is needed:
    /// `RibRoute.next_hop` can never be a link-local address, because
    /// `message::decode_mp_reach` keeps only the global half of an RFC 2545
    /// next-hop field (see `message.rs`'s
    /// `mp_reach_accepts_global_plus_link_local_next_hop` test) and the
    /// legacy `NEXT_HOP` attribute is IPv4 — revisit this if that parsing
    /// ever changes.
    fn next_hop_feasible(&self, next_hop: Option<IpAddr>) -> bool {
        match next_hop {
            None => true,
            Some(addr) => !self.igp_ready || igp_lookup(&self.igp, addr).is_some(),
        }
    }

    /// Decays penalties and re-decides every prefix whose suppression ended.
    pub fn damping_tick(&mut self) {
        for (_, prefix) in self.damping.tick(Instant::now()) {
            self.recompute_and_propagate(prefix);
        }
    }

    /// Expires old EVPN MAC-mobility move history and lifts any freeze whose
    /// window has passed quietly — see `mac_mobility`.
    pub fn mac_mobility_tick(&mut self) {
        self.mac_mobility.tick(Instant::now());
    }

    /// A session with `peer` ended (`kind` says how). Graceful restart
    /// (RFC 4724 §4.2, RFC 8538 §4): when the peer's capability allows it,
    /// its routes of every family it listed and negotiated stay in use,
    /// marked stale, for its restart time; everything else is withdrawn as
    /// before. Called again for a peer already down and retaining (by
    /// `reconcile_peers` after an abort), only a `Hard` end changes anything.
    pub fn peer_disconnected(&mut self, peer: IpAddr, kind: Disconnect) {
        self.peer_stats.remove(&peer);
        // ponytail: a deferral this ends (its last waiting peer gone hard)
        // is noticed by the next `gr_tick`, up to 5s later.
        if let Some(deferral) = self.deferral.as_mut() {
            deferral.disconnected(peer, kind == Disconnect::Hard);
        }
        // Retention never outlives a session; after a GR restart it refills
        // from the peer's re-announcements only (#859).
        self.retained.drop_peer(peer);
        let outbox = self.peer_outboxes.remove(&peer);
        if outbox.is_none() && kind != Disconnect::Hard && self.gr_deadline.contains_key(&peer) {
            return;
        }
        let gr = self.gr.get(&peer).copied();
        let retained: Vec<AddressFamily> = match (&outbox, gr) {
            (Some(o), Some(g)) if crate::gr::retains(kind, Some(&g)) => g
                .families()
                .into_iter()
                .filter(|f| o.negotiated_afs.contains(f))
                .collect(),
            _ => Vec::new(),
        };
        self.max_prefix_warned.retain(|(p, _)| *p != peer);
        self.first_as_warned.remove(&peer);
        // ponytail: a session reset forgets its flap history (RFC 2439 allows
        // keeping it); keep entries across resets to damp session flaps too.
        self.damping.clear_peer(peer);
        self.adj_rib_out.remove(&peer);
        self.bmp_pre_out.remove(&peer);
        self.evpn_adj_rib_out.remove(&peer);
        self.flowspec_adj_rib_out.remove(&peer);
        self.vpn_adj_rib_out.remove(&peer);
        self.rtc_adj_rib_out.remove(&peer);
        self.add_path_sent.retain(|(p, _), _| *p != peer);
        self.add_path_next_id.retain(|(p, _), _| *p != peer);
        // Membership survives a graceful restart that lists RT-Constraint
        // (`retain_as_stale` marks it stale); otherwise it goes with the
        // session.
        if !retained.contains(&AddressFamily::RtConstraint) {
            let rtcs: Vec<RtcKey> = self
                .rtc_adj_rib_in
                .get(&peer)
                .into_iter()
                .flat_map(HashMap::keys)
                .copied()
                .collect();
            for k in rtcs {
                self.drop_rtc(peer, &k);
            }
            self.rtc_stale.remove(&peer);
        }
        if let (false, Some(gr)) = (retained.is_empty(), gr) {
            self.retain_as_stale(peer, gr, &retained);
            return;
        }
        self.path_counts.remove(&peer);
        self.stale.remove(&peer);
        self.evpn_stale.remove(&peer);
        self.flowspec_stale.remove(&peer);
        self.vpn_stale.remove(&peer);
        self.gr_deadline.remove(&peer);
        let vpns: Vec<VpnKey<IpNet>> = self
            .vpn_adj_rib_in
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::keys)
            .copied()
            .collect();
        for k in vpns {
            self.drop_vpn(peer, &k);
        }
        let flows: Vec<FlowspecKey> = self
            .flowspec_adj_rib_in
            .remove(&peer)
            .into_iter()
            .flat_map(HashMap::into_keys)
            .collect();
        for k in flows {
            info!(peer = %peer, family = %k.0, route = %k.1, "flowspec route withdrawn");
            self.select_flow(&k);
        }
        if let Some(routes) = self.evpn_adj_rib_in.remove(&peer) {
            // mac_mobility's record of this route's (vni, mac) is
            // deliberately left alone (see its own doc comment): a future
            // re-learn, local or remote, still needs to outrank it.
            for EvpnRoute { nlri, .. } in routes.values() {
                info!(peer = %peer, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
            }
        }
        let removed = self.adj_rib_in.remove(&peer);
        if let Some(routes) = removed {
            for prefix in routes.into_keys() {
                self.recompute_and_propagate(prefix);
            }
        }
    }

    /// How many prefixes `nos-ribd` redistributes (before policy).
    pub fn redistribute_raw_len(&self) -> usize {
        self.redistribute_raw.len()
    }

    /// Applies one `nos_proto::RedistributeUpdate` from `nos-ribd`. `gateway`
    /// on the wire type is never read — a locally-redistributed route always
    /// gets next-hop-self, regardless of the destination peer-group's
    /// configured mode (see `RibRoute::next_hop`'s doc comment). Updates the
    /// raw source-of-truth prefix set (`redistribute_raw`) and re-derives
    /// each touched prefix's policy-filtered entry via `refilter_redistribute`.
    pub fn apply_redistribute_update(&mut self, update: RedistributeUpdate) {
        match update {
            RedistributeUpdate::Full(routes) => {
                let new_raw: HashSet<IpNet> = routes.iter().map(|r| r.prefix).collect();
                let touched: Vec<IpNet> = self
                    .redistribute_raw
                    .symmetric_difference(&new_raw)
                    .copied()
                    .collect();
                self.redistribute_raw = new_raw;
                for prefix in touched {
                    self.refilter_redistribute(prefix);
                    self.recompute_and_propagate(prefix);
                }
            }
            RedistributeUpdate::Add(route) => {
                self.redistribute_raw.insert(route.prefix);
                self.refilter_redistribute(route.prefix);
                self.recompute_and_propagate(route.prefix);
            }
            RedistributeUpdate::Remove(prefix) => {
                self.redistribute_raw.remove(&prefix);
                self.refilter_redistribute(prefix);
                self.recompute_and_propagate(prefix);
            }
            // Staged by `server.rs` (`RedistributeUpdate::absorb`); only the
            // closing `Full` gets here. A stray part is not a whole set.
            RedistributeUpdate::FullPart(_) => return,
        }
        // `nos-ribd` sends a `Full` (maybe empty) as soon as it connects.
        self.redistribute_seen = true;
        if let Some(deferral) = self.deferral.as_mut() {
            deferral.local_routes_in();
            self.maybe_end_deferral(Instant::now());
        }
    }

    /// Recomputes `prefix`'s policy-filtered entry in `redistributed` from
    /// `redistribute_raw` + `redistribute_policy`, inserting or removing it
    /// as needed. Returns whether the entry actually changed — callers use
    /// this to decide whether `recompute_and_propagate` is warranted.
    fn refilter_redistribute(&mut self, prefix: IpNet) -> bool {
        let new = if self.redistribute_raw.contains(&prefix) {
            let route = RibRoute {
                validation_state: self.validate(prefix, &AsPath::default()),
                ..redistributed_route()
            };
            apply_policy(prefix, route, &self.redistribute_policy, None, None)
        } else {
            None
        };
        // Keep the existing `received_at`: it is part of `RibRoute`'s
        // `PartialEq`, and a fresh `Instant::now()` would make every
        // periodic `set_redistribute_policy` look like a change and
        // re-announce the prefix to every peer (#134).
        let new = new.map(|n| match self.redistributed.get(&prefix) {
            Some(o) => RibRoute {
                received_at: o.received_at,
                ..n
            },
            None => n,
        });
        let changed = match (&new, self.redistributed.get(&prefix)) {
            (Some(n), Some(o)) => n != o,
            (None, None) => false,
            _ => true,
        };
        match new {
            Some(route) => {
                self.redistributed.insert(prefix, route);
            }
            None => {
                self.redistributed.remove(&prefix);
            }
        }
        changed
    }

    /// Sets the compiled redistribute policy and re-filters every currently
    /// raw-redistributed prefix against it — called unconditionally on every
    /// `reconcile()`, mirroring `set_local_identity`'s existing
    /// unconditional-call pattern. Unlike peer import/export (which take
    /// effect via a full peer restart on any policy-name change), there's no
    /// restart mechanism for redistribution, so a policy edit only takes
    /// effect promptly because this method actively re-derives the filtered
    /// set on every call rather than waiting for the next unrelated
    /// `RedistributeUpdate` from `nos-ribd`.
    pub fn set_redistribute_policy(&mut self, policy: Arc<CompiledPolicy>) {
        self.redistribute_policy = policy;
        let prefixes: Vec<IpNet> = self.redistribute_raw.iter().copied().collect();
        for prefix in prefixes {
            if self.refilter_redistribute(prefix) {
                self.recompute_and_propagate(prefix);
            }
        }
    }

    /// Every best-path candidate for `prefix`: the redistributed route (path
    /// id 0), the aggregate (1) and every peer path not damped, minus the
    /// unfeasible ones (logged when `log`).
    fn candidates(&self, prefix: IpNet, log: bool) -> Vec<Candidate> {
        // Sized for one redistributed candidate plus one path per peer —
        // avoids the reallocate-on-every-push churn this always-tiny,
        // rebuilt-per-touched-prefix scratch Vec used to pay. ADD-PATH
        // peers add every path they sent.
        let mut candidates: Vec<Candidate> = Vec::with_capacity(1 + self.adj_rib_in.len());
        if let Some(route) = self.redistributed.get(&prefix) {
            candidates.push((route.clone(), 0));
        }
        if let Some(route) = self.aggregated.get(&prefix) {
            candidates.push((route.clone(), 1));
        }
        for (peer, table) in &self.adj_rib_in {
            if self.damping.is_suppressed(*peer, &prefix) {
                continue;
            }
            for (id, route) in table.get(&prefix).into_iter().flatten() {
                candidates.push((route.clone(), *id));
            }
        }
        // RFC 4271 §9.1.2: an unresolvable next hop is unfeasible — out of
        // the decision process (and the backup pick) entirely.
        candidates.retain(|(route, _)| {
            let feasible = self.next_hop_feasible(route.next_hop);
            if !feasible && log {
                debug!(origin = ?route.origin, %prefix, next_hop = ?route.next_hop, "bgp: candidate excluded, next hop unresolvable");
            }
            feasible
        });
        candidates
    }

    /// The shared core: re-decides `prefix`'s winner from every current
    /// candidate (redistributed + every peer's Adj-RIB-In), and if the
    /// winner actually changed, pushes `Announce`/`Withdraw` to every
    /// registered peer as appropriate.
    fn recompute_and_propagate(&mut self, prefix: IpNet) {
        self.recompute_prefix(prefix);
        // Every unicast change funnels through here, `unchanged` or not
        // (rule (c) reads non-best paths too).
        self.revalidate_around(prefix);
    }

    fn recompute_prefix(&mut self, prefix: IpNet) {
        // Runs independently of the single-elected-best-path logic below —
        // an ADD-PATH peer's view covers more than the one instance-wide
        // winner, so a change to a non-winning path must still be reflected
        // here even when `best_path`'s pick doesn't change.
        self.propagate_add_path(prefix, None);

        let candidates = self.candidates(prefix, true);
        let best = best_path(&candidates, &self.igp);
        // Install-only: the multipath set never changes what is advertised
        // (still `best` alone), so it's updated before the `unchanged`
        // return below, like the backup — `rib_push_client`'s poll picks
        // up a sibling joining or leaving on its own.
        let multipath = best.as_ref().map_or_else(Vec::new, |b| {
            multipath_next_hops(&candidates, b, &self.igp, self.maximum_paths)
        });
        if multipath.len() > 1 {
            if self.multipaths.get(&prefix) != Some(&multipath) {
                debug!(
                    next_hops = multipath.len(),
                    "bgp: multipath set for {prefix} updated"
                );
                self.multipaths.insert(prefix, multipath.clone());
            }
        } else if self.multipaths.remove(&prefix).is_some() {
            debug!(
                next_hops = multipath.len(),
                "bgp: multipath set for {prefix} updated"
            );
        }
        match best
            .as_ref()
            .and_then(|_| runner_up_next_hop(&candidates, &multipath, &self.igp))
        {
            Some(nh) => {
                self.backups.insert(prefix, nh);
            }
            None => {
                self.backups.remove(&prefix);
            }
        }

        let unchanged = match (&best, self.loc_rib.get(&prefix)) {
            (Some(new), Some(old)) => new == old,
            (None, None) => true,
            _ => false,
        };
        if unchanged {
            return;
        }
        if let Some(route) = &best {
            debug!(origin = ?route.origin, as_path = ?route.as_path, communities = ?route.communities, med = ?route.med, local_pref = route.local_pref, next_hop = ?route.next_hop, "bgp: loc-rib best path for {prefix} updated");
            self.loc_rib.insert(prefix, route.clone());
        } else {
            debug!("bgp: loc-rib route for {prefix} withdrawn");
            self.loc_rib.remove(&prefix);
        }
        // Before the fan-out, so a `summary-only` aggregate this prefix
        // activates already suppresses it.
        if !self.aggregates.is_empty() {
            self.update_aggregates_for(prefix);
        }
        self.fan_out(prefix);
    }

    /// Sends `prefix`'s current Loc-RIB entry (or its withdrawal) to every
    /// peer, diffed against `adj_rib_out`.
    fn fan_out(&mut self, prefix: IpNet) {
        if self.deferring() {
            return;
        }
        let suppressed = self.suppressed_by_aggregate(prefix);
        let source_is_rr_client = self
            .loc_rib
            .get(&prefix)
            .is_some_and(|r| self.source_is_rr_client(r));
        let best = self.loc_rib.get(&prefix);
        let pre_out = self.bmp.as_deref().filter(|h| h.out_enabled(false));
        // Reused across calls (see `peer_scratch`'s doc comment) instead of
        // collecting a fresh Vec on every touched prefix.
        let mut peers = std::mem::take(&mut self.peer_scratch);
        peers.clear();
        peers.extend(self.peer_outboxes.keys().copied());
        for &peer in &peers {
            let outbox = self.peer_outboxes.get(&peer).expect("just listed");
            if let Some(hub) = pre_out.filter(|h| h.is_up(peer)) {
                let cand = best.filter(|_| !suppressed).filter(|r| {
                    eligibility(family_of(prefix), r, peer, outbox, source_is_rr_client).is_some()
                });
                bmp_out::pre_step(
                    hub,
                    self.bmp_pre_out.entry(peer).or_default(),
                    peer,
                    prefix,
                    cand,
                );
            }
            if outbox.add_path_tx.contains(&family_of(prefix)) {
                continue; // `propagate_add_path`'s, every NLRI needs an id
            }
            let advertisement = best.filter(|_| !suppressed).and_then(|route| {
                build_advertisement(
                    prefix,
                    route,
                    peer,
                    outbox,
                    self.local_asn,
                    source_is_rr_client,
                    self.cluster_id,
                    None,
                )
            });

            match advertisement {
                Some(adv) => {
                    let outbox = self.peer_outboxes.get(&peer).expect("just listed");
                    outbox.tx.send(OutboundUpdate::Announce(adv));
                    self.adj_rib_out.entry(peer).or_default().insert(prefix);
                }
                None => {
                    if let Some(sent) = self.adj_rib_out.get_mut(&peer)
                        && sent.remove(&prefix)
                    {
                        let outbox = self.peer_outboxes.get(&peer).expect("just listed");
                        outbox.tx.send(OutboundUpdate::Withdraw(
                            prefix,
                            outbox.mp_bgp_negotiated,
                            None,
                        ));
                    }
                }
            }
        }
        self.peer_scratch = peers;
    }

    /// RFC 7911 ADD-PATH fan-out of `prefix` to every peer we send ADD-PATH
    /// to for its family (only `only`, re-sending even unchanged paths, for a
    /// new session or a route refresh): the best `add_path_send_count` paths
    /// by the decision process (`decision_cmp`), counted after this peer's
    /// own filtering (`build_advertisement`: split horizon, RR rules, export
    /// policy, never echoing a peer's own path) — a refused path doesn't use
    /// up a slot. The best path is rank 1, so it's sent unless refused (§5).
    ///
    /// An ordinary peer ranks the Loc-RIB's candidates (`candidates`); a
    /// summary-only-suppressed prefix sends none. A route-server client
    /// ranks every source's paths, deliberately *not* filtered by
    /// `next_hop_feasible` nor aggregates (RFC 7947 §2.2.2 transparency:
    /// whether *this* instance can resolve a next hop says nothing about
    /// whether the client can). Ids: see `send_add_paths`.
    fn propagate_add_path(&mut self, prefix: IpNet, only: Option<IpAddr>) {
        if self.deferring() {
            return;
        }
        let family = family_of(prefix);
        let peers: Vec<IpAddr> = self
            .peer_outboxes
            .iter()
            .filter(|(addr, o)| o.add_path_tx.contains(&family) && only.is_none_or(|p| p == **addr))
            .map(|(addr, _)| *addr)
            .collect();
        if peers.is_empty() {
            return;
        }
        let suppressed = self.suppressed_by_aggregate(prefix);
        // Ranked once per prefix, best first, shared by every peer.
        let (mut ranked, mut rs_ranked) = (None, None);
        for peer in peers {
            let list: &[Candidate] = if self.peer_outboxes[&peer].is_rs_client {
                rs_ranked.get_or_insert_with(|| self.ranked(&self.rs_candidates(prefix)))
            } else if suppressed {
                &[]
            } else {
                ranked.get_or_insert_with(|| self.ranked(&self.candidates(prefix, false)))
            };
            self.send_add_paths(prefix, peer, list, only.is_some());
        }
    }

    /// A route-server client's candidates: the redistributed route and every
    /// peer path not damped (`propagate_add_path`).
    fn rs_candidates(&self, prefix: IpNet) -> Vec<Candidate> {
        let mut candidates: Vec<Candidate> = Vec::new();
        if let Some(route) = self.redistributed.get(&prefix) {
            candidates.push((route.clone(), 0));
        }
        for (src, table) in &self.adj_rib_in {
            if !self.damping.is_suppressed(*src, &prefix) {
                candidates.extend(
                    table
                        .get(&prefix)
                        .into_iter()
                        .flatten()
                        .map(|(id, r)| (r.clone(), *id)),
                );
            }
        }
        candidates
    }

    /// `candidates` sorted best first.
    fn ranked(&self, candidates: &[Candidate]) -> Vec<Candidate> {
        rank(candidates, &self.igp)
    }

    /// Sends `peer` the first `add_path_send_count` paths of `ranked` it may
    /// have, diffed against what it was last sent (`add_path_sent`). A path
    /// still selected keeps its id, re-announced only if it changed (or
    /// `force`). A path that left the set frees its id; an entering path
    /// takes the lowest freed id — an RFC 7911 §3 implicit replace, so the
    /// receiver never drops to N−1 paths in between — else a fresh one from
    /// `add_path_next_id`. Ids still free at the end are withdrawn.
    fn send_add_paths(&mut self, prefix: IpNet, peer: IpAddr, ranked: &[Candidate], force: bool) {
        let outbox = &self.peer_outboxes[&peer];
        let limit = outbox.add_path_send_count.unwrap_or(usize::MAX);
        let mut selected: Vec<(PathKey, &RibRoute, AdvertisedRoute)> = Vec::new();
        for (route, id) in ranked {
            if selected.len() >= limit {
                break;
            }
            if let Some(adv) = build_advertisement(
                prefix,
                route,
                peer,
                outbox,
                self.local_asn,
                self.source_is_rr_client(route),
                self.cluster_id,
                None,
            ) {
                selected.push(((route.origin, *id), route, adv));
            }
        }
        let (tx, mp) = (outbox.tx.clone(), outbox.mp_bgp_negotiated);

        let mut sent = self
            .add_path_sent
            .remove(&(peer, prefix))
            .unwrap_or_default();
        let mut freed = Vec::new();
        sent.retain(|key, (id, _)| {
            let keep = selected.iter().any(|(k, ..)| k == key);
            if !keep {
                freed.push(*id);
            }
            keep
        });
        freed.sort_unstable_by(|a, b| b.cmp(a)); // `pop` takes the lowest
        for (key, route, adv) in selected {
            let id = match sent.get(&key) {
                Some((_, last)) if !force && last == route => continue,
                Some((id, _)) => *id,
                None => freed.pop().unwrap_or_else(|| {
                    // ponytail: never recycled once withdrawn, a u32 per
                    // (peer, prefix) is nowhere near exhausted.
                    let next = self.add_path_next_id.entry((peer, prefix)).or_insert(1);
                    *next += 1;
                    *next - 1
                }),
            };
            tx.send(OutboundUpdate::Announce(AdvertisedRoute {
                path_id: Some(id),
                ..adv
            }));
            sent.insert(key, (id, route.clone()));
        }
        for id in freed.into_iter().rev() {
            tx.send(OutboundUpdate::Withdraw(prefix, mp, Some(id)));
        }
        if !sent.is_empty() {
            self.add_path_sent.insert((peer, prefix), sent);
        }
    }
}
#[cfg(test)]
mod tests;
