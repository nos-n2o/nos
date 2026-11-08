//! RFC 2328 §16.1/§16.2 SPF: pure Dijkstra over Router-LSA/Network-LSA
//! vertices, next-hop derivation entirely from already-installed LSAs (no
//! live neighbor-table dependency), plus stub-network leaf processing and a
//! directly-connected filter, extended with a real, 2-area-scoped ABR
//! mechanism (Type-3/Type-4 Summary-LSA collector passes — see
//! `docs/protocols/ospf-internals.md`'s "ABR and Summary-LSA origination"). No I/O —
//! `crate::link::LinkManager::compute_routes` is the only caller of
//! `compute`, feeding it one area's `Lsdb::all()` snapshot at a time and
//! merging each area's own result (`RouteEntry`-per-prefix, cheaper wins on
//! a prefix computed by more than one area — see that function's own doc
//! comment). `intra_area_routes` is `crate::link::originate_summary_lsas`'s
//! own per-area input for deciding what to summarize into a router's *other*
//! areas.
//!
//! # Next-hop derivation (the fiddly part of real OSPF SPF)
//! A point-to-point or transit-network Router-LSA link's `link_data` is
//! always the *originating* router's own address on that link (RFC 2328
//! §12.4.1.1) — never the neighbor's. So the only LSDB-only way to learn a
//! neighbor `w`'s address is to read *`w`'s own* Router-LSA for its link
//! back to us, not our own LSA. `derive_next_hops` applies this once per
//! vertex directly adjacent to the root (or adjacent to a network the root
//! itself sits on); every other vertex simply inherits its parent's
//! next-hop set unchanged, since packets to the whole subtree beyond a
//! vertex flow through the same first-hop neighbors.
//!
//! # Equal-cost multipath (RFC 2328 §16.1 step 2(d))
//! A vertex reached at the same distance through more than one parent keeps
//! the union of every parent's next hops, and a destination collected at
//! the same metric from more than one vertex keeps the union too
//! (`merge_equal`). `RouteEntry.next_hops` is that set, sorted and deduped.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use ipnet::Ipv4Net;

use crate::lsa::{
    AsExternalLsaBody, Lsa, LsaBody, NetworkLsaBody, RouterLink, RouterLsaBody, SummaryLsaBody,
    LINK_TYPE_POINT_TO_POINT, LINK_TYPE_STUB_NETWORK, LINK_TYPE_TRANSIT_NETWORK, LINK_TYPE_VIRTUAL,
    LSA_TYPE_ASBR_SUMMARY, LSA_TYPE_AS_EXTERNAL, LSA_TYPE_NETWORK_SUMMARY, LSA_TYPE_NSSA_EXTERNAL,
    MAX_AGE, MAX_LINK_METRIC, OPTION_P, RI_CAP_HOST_ROUTER, ROUTER_FLAG_B, ROUTER_FLAG_H,
    ROUTER_FLAG_NT, ROUTER_FLAG_V,
};

/// RFC 2328 §12.4.4 `LSInfinity`: an AS-external metric that is never routed.
const LS_INFINITY: u32 = 0x00FF_FFFF;
/// The metric nos originates for a redistributed prefix when none is configured
/// (`redistribute ... metric`); received externals carry their own metric and
/// E bit (`AsExternalLsaBody`).
pub const DEFAULT_EXTERNAL_METRIC: u32 = 20;

/// One SPF vertex — a router (keyed by its router-id) or a transit network
/// (keyed by the Network-LSA's `link_state_id`, the DR's own address on
/// that network).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Vertex {
    Router(Ipv4Addr),
    Network(Ipv4Addr),
}

/// A vertex's derived next-hop. `Network` is a sentinel for a root-adjacent
/// transit network — it has no address of its own, so its own children
/// (routers on that network) must derive their next-hop fresh rather than
/// inherit this; every other vertex stores a concrete `Router` address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum NextHop {
    Network,
    Router(Ipv4Addr),
}

/// One computed destination, ready to push to `nos-ribd`.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteEntry {
    pub prefix: Ipv4Net,
    /// Every equal-cost first hop, sorted by address, deduped — empty only
    /// for a `discard` route.
    pub next_hops: Vec<Ipv4Addr>,
    pub metric: u32,
    /// RFC 5286 loop-free alternate next hop (a first hop outside
    /// `next_hops` that provably won't loop the packet back through us), if
    /// one exists. Filled in by `compute` after every collector has run.
    pub backup_next_hop: Option<Ipv4Addr>,
    /// RFC 7490 remote LFA: the PQ node's loopback to tunnel (IP-in-IP) to
    /// when the single primary next hop fails and there is no
    /// `backup_next_hop`. Filled in by `compute_in` when
    /// `Context.remote_lfa` is set.
    pub backup_tunnel: Option<Ipv4Addr>,
    /// The vertex this destination hangs off (the router/network whose
    /// distance the metric was built from) — what the loop-free test is
    /// evaluated against, since the leaf metric cancels out of it.
    egress: Vertex,
    /// RFC 2328 §16.4 path class, what `prefer` ranks first.
    class: PathClass,
}

/// RFC 2328 §11: intra-area beats inter-area beats Type 1 beats Type 2
/// (§16.2 step 3, §16.4 step 6). `External2.ext` is the LSA's own metric;
/// `RouteEntry.metric` stays `X + ext` (what `nos-ribd` gets) and X is
/// `metric - ext`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathClass {
    Intra,
    Inter,
    External1,
    External2 { ext: u32 },
}

impl PathClass {
    fn rank(self) -> u8 {
        match self {
            PathClass::Intra => 0,
            PathClass::Inter => 1,
            PathClass::External1 => 2,
            PathClass::External2 { .. } => 3,
        }
    }

    fn internal(self) -> bool {
        matches!(self, PathClass::Intra | PathClass::Inter)
    }
}

/// RFC 2328 §11/§16.4 step 6: `Less` = `a` is the better route to one prefix.
/// `Equal` routes are merged (`merge_equal`).
/// `ponytail:` no §16.4.1 area preference and no RFC 1583 mode; ceiling: a
/// multi-area ABR with equal-preference externals in two areas.
pub(crate) fn prefer(a: &RouteEntry, b: &RouteEntry) -> Ordering {
    match (a.class, b.class) {
        (PathClass::External2 { ext: x }, PathClass::External2 { ext: y }) => x
            .cmp(&y)
            .then_with(|| a.metric.saturating_sub(x).cmp(&b.metric.saturating_sub(y))),
        (x, y) => x
            .rank()
            .cmp(&y.rank())
            .then_with(|| a.metric.cmp(&b.metric)),
    }
}

impl RouteEntry {
    /// An ABR's discard route for one of its active advertised area ranges
    /// (RFC 2328 §3.5): no next hop, so `nos-ribd` installs a blackhole.
    pub fn discard(prefix: Ipv4Net, metric: u32) -> Self {
        RouteEntry {
            prefix,
            next_hops: Vec::new(),
            metric,
            backup_next_hop: None,
            backup_tunnel: None,
            egress: Vertex::Router(Ipv4Addr::UNSPECIFIED),
            class: PathClass::Inter,
        }
    }
}

/// What one area's SPF needs beyond its LSDB (RFC 2328 §16.1/§16.2).
#[derive(Debug, Default, Clone, Copy)]
pub struct Context<'a> {
    /// The area is the backbone: type-4 (virtual) links are edges (§16.1).
    pub backbone: bool,
    /// A backbone-attached ABR and a non-backbone area: its Type-3/4 are not
    /// examined (§16.2) — only §16.3's transit pass reads its Type-3s.
    pub skip_summaries: bool,
    /// The §16.7 first hops in the transit area toward each virtual link's
    /// endpoint: the next hops of a type-4 edge out of root.
    pub virtual_links: &'a [VirtualNextHops],
    /// RFC 7490: look for a remote LFA for routes without a basic one.
    pub remote_lfa: bool,
}

/// One virtual link's §16.7 next hops, for `Context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualNextHops {
    pub endpoint: Ipv4Addr,
    pub next_hops: Vec<Ipv4Addr>,
}

/// RFC 2328 §16.3 step 5 for one backbone route `existing` and one transit
/// candidate (`transit_summaries`): a strictly cheaper candidate replaces its
/// cost and next hops, an equal one adds its next hops. An external route is
/// never touched. The caller makes sure `existing` is a backbone route.
pub fn apply_transit(existing: &mut RouteEntry, candidate: RouteEntry) {
    if !existing.class.internal() {
        return;
    }
    match candidate.metric.cmp(&existing.metric) {
        Ordering::Less => {
            existing.metric = candidate.metric;
            existing.next_hops = candidate.next_hops;
            existing.egress = candidate.egress;
            // ponytail: the LFA was computed for the backbone path; none for
            // a transit-replaced route.
            existing.backup_next_hop = None;
            existing.backup_tunnel = None;
        }
        Ordering::Equal => merge_equal(existing, candidate),
        Ordering::Greater => {}
    }
}

/// RFC 2328 §16.3: when `lsas`' area is transit-capable (a reachable
/// Router-LSA with the V bit, §16.1 step 2), every Type-3 from another ABR
/// reachable there, as a candidate for `apply_transit` — never a route by
/// itself. `ponytail:` Type-4s are not examined, so an ASBR's backbone
/// distance is not shortened through a transit area.
pub fn transit_summaries(root: Ipv4Addr, lsas: &[Arc<Lsa>]) -> Vec<RouteEntry> {
    let live = live_lsas(lsas);
    let (routers, networks, hosts) = routers_and_networks(&live);
    let (dist, next_hop) = run_dijkstra(root, &routers, &networks, &hosts, &Context::default());
    let transit = routers
        .iter()
        .any(|(id, r)| r.flags & ROUTER_FLAG_V != 0 && dist.contains_key(&Vertex::Router(*id)));
    if !transit {
        return Vec::new();
    }
    let summaries: Vec<(Ipv4Addr, Ipv4Addr, &SummaryLsaBody)> = live
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::Summary(s)
                if l.header.lsa_type == LSA_TYPE_NETWORK_SUMMARY && s.metric < LS_INFINITY =>
            {
                Some((l.header.advertising_router, l.header.link_state_id, s))
            }
            _ => None,
        })
        .collect();
    let mut out = HashMap::new();
    collect_summary_routes(root, &summaries, &dist, &next_hop, &mut out);
    out.into_values().collect()
}

/// `(prefix, metric)` pairs to originate as Type-3s.
pub type Summaries = Vec<(Ipv4Net, u32)>;

/// RFC 2328 §3.5/§12.4.3: applies one source area's address ranges to its
/// intra-area routes. Returns what to summarize into the other areas — every
/// route no range covers, plus one entry per `advertise` range with at least
/// one covered route (metric = the *largest* covered cost, RFC 2328; RFC 1583
/// used the smallest) — and those active advertised ranges on their own, for
/// the ABR's discard routes. A route covered by two ranges counts towards the
/// most specific one.
pub fn apply_ranges(routes: &[RouteEntry], ranges: &[(Ipv4Net, bool)]) -> (Summaries, Summaries) {
    let mut summarize = Vec::new();
    let mut covered: HashMap<Ipv4Net, (bool, u32)> = HashMap::new();
    for route in routes {
        let range = ranges
            .iter()
            .filter(|(net, _)| net.contains(&route.prefix))
            .max_by_key(|(net, _)| net.prefix_len());
        match range {
            None => summarize.push((route.prefix, route.metric)),
            Some((net, advertise)) => {
                let entry = covered.entry(net.trunc()).or_insert((*advertise, 0));
                entry.1 = entry.1.max(route.metric);
            }
        }
    }
    let active: Vec<(Ipv4Net, u32)> = covered
        .into_iter()
        .filter(|(_, (advertise, _))| *advertise)
        .map(|(net, (_, metric))| (net, metric))
        .collect();
    summarize.extend(active.iter().copied());
    (summarize, active)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeapEntry {
    dist: u32,
    vertex: Vertex,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed: `BinaryHeap` is a max-heap, Dijkstra wants the smallest
        // distance popped first. At equal distance a transit network pops
        // before a router (RFC 2328 §16.1 step 3): its edges to routers cost
        // 0, so a router it ties with must not be finalized before the
        // network adds its own next hops to it.
        other
            .dist
            .cmp(&self.dist)
            .then_with(|| is_network(self.vertex).cmp(&is_network(other.vertex)))
    }
}

fn is_network(v: Vertex) -> bool {
    matches!(v, Vertex::Network(_))
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// RFC 2328 §16.1 step 2: an LSA at `MaxAge` (being flushed, see `lsdb.rs`'s
/// hold) takes no part in the routing computation.
fn live_lsas(lsas: &[Arc<Lsa>]) -> Vec<Arc<Lsa>> {
    lsas.iter()
        .filter(|l| l.header.age < MAX_AGE)
        .cloned()
        .collect()
}

/// RFC 8770 §5: the H-bit is honoured in an area only when every router
/// there (every live Router-LSA's originator) advertises host-router support
/// (bit 7) in an RI LSA — area-scoped type 10, or type 11 as FRR originates
/// it. Otherwise the max-metric links alone steer traffic away.
pub fn host_bit_honoured(lsas: &[Arc<Lsa>]) -> bool {
    let live = live_lsas(lsas);
    let supporting: HashSet<Ipv4Addr> = live
        .iter()
        .filter(|l| {
            crate::lsa::router_info_capabilities(l).is_some_and(|c| c & RI_CAP_HOST_ROUTER != 0)
        })
        .map(|l| l.header.advertising_router)
        .collect();
    live.iter()
        .filter(|l| matches!(l.body, LsaBody::Router(_)))
        .all(|l| supporting.contains(&l.header.advertising_router))
}

/// RFC 8770: the routers SPF must not use for transit — every H-bit router
/// in `lsas` while the area honours the bit, else none.
pub fn host_routers(lsas: &[Arc<Lsa>]) -> HashSet<Ipv4Addr> {
    if !host_bit_honoured(lsas) {
        return HashSet::new();
    }
    h_bit_routers(lsas)
}

/// Every live Router-LSA with the H-bit, honoured or not.
pub fn h_bit_routers(lsas: &[Arc<Lsa>]) -> HashSet<Ipv4Addr> {
    lsas.iter()
        .filter(|l| l.header.age < MAX_AGE)
        .filter_map(|l| match &l.body {
            LsaBody::Router(r) if r.flags & ROUTER_FLAG_H != 0 => Some(l.header.advertising_router),
            _ => None,
        })
        .collect()
}

/// Builds the `routers`/`networks` lookup maps `run_dijkstra` and every
/// collector pass need — shared by `compute` and `intra_area_routes` so
/// neither duplicates the filter — plus `host_routers`.
fn routers_and_networks(
    lsas: &[Arc<Lsa>],
) -> (
    HashMap<Ipv4Addr, &RouterLsaBody>,
    HashMap<Ipv4Addr, &NetworkLsaBody>,
    HashSet<Ipv4Addr>,
) {
    let routers = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::Router(r) => Some((l.header.advertising_router, r)),
            LsaBody::Network(_)
            | LsaBody::Summary(_)
            | LsaBody::AsExternal(_)
            | LsaBody::Grace(_)
            | LsaBody::Opaque(_) => None,
        })
        .collect();
    let networks = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::Network(n) => Some((l.header.link_state_id, n)),
            LsaBody::Router(_)
            | LsaBody::Summary(_)
            | LsaBody::AsExternal(_)
            | LsaBody::Grace(_)
            | LsaBody::Opaque(_) => None,
        })
        .collect();
    (routers, networks, host_routers(lsas))
}

/// Runs RFC 2328 §16.1/§16.2 SPF from `root` over `lsas` (one area's
/// worth), returning every non-directly-connected destination reachable —
/// stub-network leaves, transit-network prefixes, RFC 2328 §16.3 inter-area
/// routes (Type-3 Summary-LSA) and §16.4 AS-external routes alike.
pub fn compute(root: Ipv4Addr, lsas: &[Arc<Lsa>]) -> Vec<RouteEntry> {
    compute_in(root, lsas, &Context::default())
}

/// `compute` with the area's `Context`: type-4 edges in the backbone, and
/// no summaries examined in a non-backbone area of a backbone-attached ABR.
pub fn compute_in(root: Ipv4Addr, lsas: &[Arc<Lsa>], ctx: &Context) -> Vec<RouteEntry> {
    let live = live_lsas(lsas);
    let lsas = &live[..];
    let (routers, networks, hosts) = routers_and_networks(lsas);
    // Plain `Vec`s, not `HashMap`s keyed by advertising_router — one ASBR/ABR
    // can originate more than one Type-5/Type-3/Type-4 for different
    // prefixes/ASBRs.
    let externals: Vec<(Ipv4Addr, Ipv4Addr, &AsExternalLsaBody)> = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::AsExternal(e) => {
                Some((l.header.advertising_router, l.header.link_state_id, e))
            }
            LsaBody::Router(_)
            | LsaBody::Network(_)
            | LsaBody::Summary(_)
            | LsaBody::Grace(_)
            | LsaBody::Opaque(_) => None,
        })
        .collect();
    let network_summaries: Vec<(Ipv4Addr, Ipv4Addr, &SummaryLsaBody)> = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::Summary(s) if l.header.lsa_type == LSA_TYPE_NETWORK_SUMMARY => {
                Some((l.header.advertising_router, l.header.link_state_id, s))
            }
            _ => None,
        })
        .collect();
    let asbr_summaries: Vec<(Ipv4Addr, Ipv4Addr, &SummaryLsaBody)> = lsas
        .iter()
        .filter_map(|l| match &l.body {
            LsaBody::Summary(s) if l.header.lsa_type == LSA_TYPE_ASBR_SUMMARY => {
                Some((l.header.advertising_router, l.header.link_state_id, s))
            }
            _ => None,
        })
        .collect();

    let (dist, next_hop) = run_dijkstra(root, &routers, &networks, &hosts, ctx);
    let mut out: HashMap<Ipv4Net, RouteEntry> = HashMap::new();

    collect_network_routes(root, &routers, &networks, &dist, &next_hop, &mut out);
    collect_stub_routes(root, &routers, &dist, &next_hop, &mut out);
    let (network_summaries, asbr_summaries) = if ctx.skip_summaries {
        (Vec::new(), Vec::new())
    } else {
        (network_summaries, asbr_summaries)
    };
    collect_summary_routes(root, &network_summaries, &dist, &next_hop, &mut out);
    let attached = root_attached_prefixes(root, &routers, &networks);
    collect_external_routes(
        root,
        &externals,
        &asbr_summaries,
        &dist,
        &next_hop,
        &attached,
        &mut out,
    );

    let alternates = alternates(root, &routers, &networks, &hosts);
    for route in out.values_mut() {
        route.backup_next_hop = pick_backup(route, &alternates, &dist);
    }
    if ctx.remote_lfa {
        remote_lfas(
            root, &routers, &networks, &hosts, &dist, &next_hop, &mut out,
        );
    }

    out.into_values().collect()
}

/// One candidate first hop for a loop-free alternate: a router adjacent to
/// root (over a p2p link, or sharing a transit network), reached at `addr`,
/// with the shortest-path distances *from that router* to every vertex.
struct Alternate {
    /// The neighbor's own address on the shared link — the next hop.
    addr: Ipv4Addr,
    /// Root's cost of the link to it.
    link_cost: u32,
    /// Its shortest distance back to root.
    to_root: u32,
    dist_from: HashMap<Vertex, u32>,
}

/// RFC 5286 basic loop-free alternates: every root-adjacent router other
/// than root itself, each with its own Dijkstra (over the same LSDB), so
/// `pick_backup` can evaluate the loop-free inequality per destination.
///
/// `ponytail:` one full Dijkstra per neighbor per area on every SPF run —
/// fine for the handful of neighbors this NOS has; an incremental/reverse-SPF
/// would be the upgrade if a router ever had hundreds. Link protection only
/// (RFC 5286 §3.1's inequality), no node-protecting or downstream-path
/// criteria, no remote LFA.
fn alternates(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
    hosts: &HashSet<Ipv4Addr>,
) -> Vec<Alternate> {
    let Some(root_lsa) = routers.get(&root) else {
        return Vec::new();
    };
    // (neighbor router-id, its address toward us, our cost to it). RFC 5286
    // §3.5: never along a link whose cost or reverse cost (the neighbor's own
    // link back to root, or to the network) is `LSInfinity` — an RFC 6987 stub
    // router on either end.
    let mut candidates: Vec<(Ipv4Addr, Ipv4Addr, u32)> = Vec::new();
    for l in root_lsa
        .links
        .iter()
        .filter(|l| l.metric != MAX_LINK_METRIC)
    {
        match l.link_type {
            LINK_TYPE_POINT_TO_POINT => {
                if let Some(back) = own_link(routers, l.link_id, LINK_TYPE_POINT_TO_POINT, root)
                    .filter(|b| b.metric != MAX_LINK_METRIC)
                {
                    candidates.push((l.link_id, back.link_data, u32::from(l.metric)));
                }
            }
            LINK_TYPE_TRANSIT_NETWORK => {
                let Some(net) = networks.get(&l.link_id) else {
                    continue;
                };
                for &r in net.attached_routers.iter().filter(|&&r| r != root) {
                    if let Some(back) = own_link(routers, r, LINK_TYPE_TRANSIT_NETWORK, l.link_id)
                        .filter(|b| b.metric != MAX_LINK_METRIC)
                    {
                        candidates.push((r, back.link_data, u32::from(l.metric)));
                    }
                }
            }
            _ => {}
        }
    }
    candidates
        .into_iter()
        // RFC 8770: a host router carries no transit, so it's no alternate —
        // its own Dijkstra (rooted at it) wouldn't show that.
        .filter(|(id, _, _)| !hosts.contains(id))
        .filter_map(|(id, addr, link_cost)| {
            // No virtual-link hops: a type-4 edge out of the alternate is
            // skipped, so it is no alternate through a virtual link.
            let dist_from = run_dijkstra(id, routers, networks, hosts, &Context::default()).0;
            let to_root = *dist_from.get(&Vertex::Router(root))?;
            Some(Alternate {
                addr,
                link_cost,
                to_root,
                dist_from,
            })
        })
        .collect()
}

/// The best alternate for `route`: among candidates whose address is none of
/// the primary next hops and that satisfy RFC 5286 §3.1's loop-free
/// inequality `dist(N, E) < dist(N, root) + dist(root, E)` for the route's
/// egress vertex `E`, the one with the lowest total cost (ties: lowest
/// address, for determinism).
fn pick_backup(
    route: &RouteEntry,
    alternates: &[Alternate],
    dist: &HashMap<Vertex, u32>,
) -> Option<Ipv4Addr> {
    let root_to_egress = *dist.get(&route.egress)?;
    alternates
        .iter()
        .filter(|a| !route.next_hops.contains(&a.addr))
        .filter_map(|a| {
            let n_to_egress = *a.dist_from.get(&route.egress)?;
            (n_to_egress < a.to_root.saturating_add(root_to_egress))
                .then_some((a.link_cost.saturating_add(n_to_egress), a.addr))
        })
        .min()
        .map(|(_, addr)| addr)
}

/// RFC 7490 remote LFA, link protection over root's point-to-point links:
/// for every route whose single next hop has no basic LFA, a PQ node to
/// tunnel to.
///
/// - **P-space** of root for the link to neighbor E: routers none of whose
///   shortest paths from root use that link (their next-hop set lacks E's
///   address on it). Plain P-space only — an extended P-space node must be
///   reached through a given neighbor, which a tunnel route can't pin.
/// - **Q-space** of E: routers none of whose shortest paths *to* E use the
///   link, i.e. `dist(Q,E) < dist(Q,root) + cost(root,E)` — reverse distances
///   (`reverse_distances`), since link costs can be asymmetric.
/// - A PQ node must advertise a /32 stub (`host_stub`, the tunnel's
///   destination) and carry transit (no RFC 8770 host router). Per route,
///   among PQ nodes whose own shortest path to the egress vertex doesn't come
///   back through root (`dist(PQ,E') < dist(PQ,root) + dist(root,E')`), the
///   cheapest `dist(root,PQ) + dist(PQ,E')` wins, ties by address.
///
/// `ponytail:` one reverse Dijkstra to root, one per protected neighbor and
/// one forward Dijkstra per PQ candidate on every SPF run (RFC 7490 §4.4's
/// incremental computation is the upgrade); no node protection, no transit
/// network protection, IPv4 only.
fn remote_lfas(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
    hosts: &HashSet<Ipv4Addr>,
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
    out: &mut HashMap<Ipv4Net, RouteEntry>,
) {
    let Some(root_lsa) = routers.get(&root) else {
        return;
    };
    // (neighbor E, its address toward us = the next hop, our cost to it)
    let links: Vec<(Ipv4Addr, Ipv4Addr, u32)> = root_lsa
        .links
        .iter()
        .filter(|l| l.link_type == LINK_TYPE_POINT_TO_POINT && l.metric != MAX_LINK_METRIC)
        .filter_map(|l| {
            own_link_data(routers, l.link_id, LINK_TYPE_POINT_TO_POINT, root)
                .map(|addr| (l.link_id, addr, u32::from(l.metric)))
        })
        .collect();
    let unprotected =
        |r: &RouteEntry, addr: Ipv4Addr| r.backup_next_hop.is_none() && r.next_hops == [addr];
    if !out
        .values()
        .any(|r| links.iter().any(|&(_, addr, _)| unprotected(r, addr)))
    {
        return;
    }
    let to_root = reverse_distances(root, routers, networks, hosts);
    let mut from: HashMap<Ipv4Addr, HashMap<Vertex, u32>> = HashMap::new();
    for (e, addr, cost) in links {
        if !out.values().any(|r| unprotected(r, addr)) {
            continue;
        }
        let to_e = reverse_distances(e, routers, networks, hosts);
        let pq: Vec<(Ipv4Addr, Ipv4Addr)> = routers
            .iter()
            .filter(|&(&id, _)| id != root && id != e && !hosts.contains(&id))
            .filter(|&(&id, _)| {
                let hops = router_hops(next_hop, Vertex::Router(id));
                !hops.is_empty() && !hops.contains(&addr)
            })
            .filter(|&(&id, _)| {
                let v = Vertex::Router(id);
                to_e.get(&v).is_some_and(|&q_e| {
                    to_root
                        .get(&v)
                        .is_none_or(|&q_root| q_e < q_root.saturating_add(cost))
                })
            })
            .filter_map(|(&id, body)| host_stub(body).map(|stub| (id, stub)))
            .collect();
        for route in out.values_mut().filter(|r| unprotected(r, addr)) {
            let Some(&root_to_egress) = dist.get(&route.egress) else {
                continue;
            };
            route.backup_tunnel = pq
                .iter()
                .filter_map(|&(id, stub)| {
                    let d = from.entry(id).or_insert_with(|| {
                        run_dijkstra(id, routers, networks, hosts, &Context::default()).0
                    });
                    let pq_to_egress = *d.get(&route.egress)?;
                    let pq_to_root = *d.get(&Vertex::Router(root))?;
                    let root_to_pq = *dist.get(&Vertex::Router(id))?;
                    (pq_to_egress < pq_to_root.saturating_add(root_to_egress))
                        .then_some((root_to_pq.saturating_add(pq_to_egress), stub))
                })
                .min()
                .map(|(_, stub)| stub);
        }
    }
}

/// The lowest /32 stub a router advertises (its loopback) — a remote LFA
/// tunnel's destination, since a router-id isn't necessarily routable.
fn host_stub(body: &RouterLsaBody) -> Option<Ipv4Addr> {
    body.links
        .iter()
        .filter(|l| l.link_type == LINK_TYPE_STUB_NETWORK && l.link_data == Ipv4Addr::BROADCAST)
        .map(|l| l.link_id)
        .min()
}

/// Every vertex's shortest distance *to* `target` (Dijkstra over reversed
/// edges): a router's p2p/transit link costs what that router advertises, a
/// network-to-router edge 0. A host router (RFC 8770) other than `target` is
/// never transited. No virtual links.
fn reverse_distances(
    target: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
    hosts: &HashSet<Ipv4Addr>,
) -> HashMap<Vertex, u32> {
    // Incoming edges per vertex: (from, cost).
    let mut incoming: HashMap<Vertex, Vec<(Vertex, u32)>> = HashMap::new();
    for &id in routers.keys() {
        for (to, cost, _) in neighbors(Vertex::Router(id), routers, networks, false) {
            incoming
                .entry(to)
                .or_default()
                .push((Vertex::Router(id), cost));
        }
    }
    for &id in networks.keys() {
        for (to, cost, _) in neighbors(Vertex::Network(id), routers, networks, false) {
            incoming
                .entry(to)
                .or_default()
                .push((Vertex::Network(id), cost));
        }
    }
    let target = Vertex::Router(target);
    let mut dist: HashMap<Vertex, u32> = HashMap::from([(target, 0)]);
    let mut visited: HashSet<Vertex> = HashSet::new();
    let mut heap = BinaryHeap::from([HeapEntry {
        dist: 0,
        vertex: target,
    }]);
    while let Some(HeapEntry { dist: d, vertex }) = heap.pop() {
        if !visited.insert(vertex) {
            continue;
        }
        if vertex != target && matches!(vertex, Vertex::Router(id) if hosts.contains(&id)) {
            continue;
        }
        for &(from, cost) in incoming.get(&vertex).into_iter().flatten() {
            let candidate = d.saturating_add(cost);
            if candidate < *dist.get(&from).unwrap_or(&u32::MAX) {
                dist.insert(from, candidate);
                heap.push(HeapEntry {
                    dist: candidate,
                    vertex: from,
                });
            }
        }
    }
    dist
}

/// One area's intra-area-only view — the subset of RFC 2328 §16.1 SPF fit
/// for re-summarization into another area (`crate::link::
/// originate_summary_lsas`). Deliberately skips the external/summary
/// collector passes: RFC 2328 forbids re-summarizing an already inter-area
/// or already-external route — the mechanism that prevents trivial two-area
/// routing loops. Only a genuinely intra-area prefix or a genuinely-in-this-
/// area ASBR ever qualifies.
///
/// `ponytail:` root's own directly-attached *transit network* (as opposed to
/// a stub network — see `collect_intra_area_stub_routes`) is not summarized
/// — a router won't advertise reachability to a broadcast segment it's
/// itself sitting on into its other areas. Real RFC 2328 ABRs do; this NOS's
/// concrete ABR scenarios (a loopback stub, a redistributed prefix) never
/// need it. Upgrade path: a root-attached-network variant mirroring
/// `collect_intra_area_stub_routes`'s own root-inclusion, keyed off the
/// root's own transit-network `RouterLink`s rather than `next_hop`, which
/// (unlike a stub) is never populated for a vertex root itself sits on.
pub struct IntraAreaRoutes {
    pub routes: Vec<RouteEntry>,
    /// Every router-id in this area that both originated at least one
    /// Type-5 AS-external-LSA and is actually reachable via this area's own
    /// Dijkstra (a real, in-this-area ASBR) — `(router_id, intra_area_distance)`.
    pub asbrs: Vec<(Ipv4Addr, u32)>,
}

/// `ctx` matters in the backbone only: a virtual link's far side is
/// backbone too, so it is summarized into this router's other areas.
pub fn intra_area_routes(root: Ipv4Addr, lsas: &[Arc<Lsa>], ctx: &Context) -> IntraAreaRoutes {
    let live = live_lsas(lsas);
    let lsas = &live[..];
    let (routers, networks, hosts) = routers_and_networks(lsas);
    let (dist, next_hop) = run_dijkstra(root, &routers, &networks, &hosts, ctx);

    let mut out: HashMap<Ipv4Net, RouteEntry> = HashMap::new();
    collect_network_routes(root, &routers, &networks, &dist, &next_hop, &mut out);
    collect_intra_area_stub_routes(root, &routers, &dist, &next_hop, &mut out);

    let asbr_ids: HashSet<Ipv4Addr> = lsas
        .iter()
        .filter(|l| l.header.lsa_type == LSA_TYPE_AS_EXTERNAL)
        .map(|l| l.header.advertising_router)
        .filter(|&id| id != root)
        .collect();
    let asbrs = asbr_ids
        .into_iter()
        .filter_map(|id| dist.get(&Vertex::Router(id)).map(|&d| (id, d)))
        .collect();

    IntraAreaRoutes {
        routes: out.into_values().collect(),
        asbrs,
    }
}

/// RFC 3101 §3.1 translator election, for `root` as one ABR of an NSSA whose
/// LSDB is `lsas`: `root` translates unless `always` is off and another ABR
/// (B-bit Router-LSA) reachable in the area has the Nt-bit or a higher
/// router-id. `ponytail:` no `TranslatorStabilityInterval` — a translator
/// that loses the election flushes its Type-5s at once.
pub fn nssa_translator(root: Ipv4Addr, lsas: &[Arc<Lsa>], always: bool) -> bool {
    if always {
        return true;
    }
    let live = live_lsas(lsas);
    let (routers, networks, hosts) = routers_and_networks(&live);
    let (dist, next_hop) = run_dijkstra(root, &routers, &networks, &hosts, &Context::default());
    !routers.iter().any(|(&id, r)| {
        id != root
            && r.flags & ROUTER_FLAG_B != 0
            && (r.flags & ROUTER_FLAG_NT != 0 || id > root)
            && asbr_distance(id, &[], &dist, &next_hop).is_some()
    })
}

/// RFC 3101 §3.2: what an elected translator turns into Type-5s from this
/// NSSA's LSDB — every live Type-7 with the P-bit and a non-zero forwarding
/// address, from an ASBR other than `root` reachable in the area, as
/// `(prefix, metric, e_type2)`. `ponytail:` two Type-7s for one prefix aren't
/// compared (§3.2's preference rules) — the last one wins.
pub fn nssa_translations(root: Ipv4Addr, lsas: &[Arc<Lsa>]) -> Vec<(Ipv4Net, u32, bool)> {
    let live = live_lsas(lsas);
    let (routers, networks, hosts) = routers_and_networks(&live);
    let (dist, next_hop) = run_dijkstra(root, &routers, &networks, &hosts, &Context::default());
    live.iter()
        .filter(|l| {
            l.header.lsa_type == LSA_TYPE_NSSA_EXTERNAL
                && l.header.options & OPTION_P != 0
                && l.header.advertising_router != root
                && asbr_distance(l.header.advertising_router, &[], &dist, &next_hop).is_some()
        })
        .filter_map(|l| match &l.body {
            LsaBody::AsExternal(e) if !e.forwarding_address.is_unspecified() => Some((
                net_from(l.header.link_state_id, e.network_mask),
                e.metric,
                e.e_type2,
            )),
            _ => None,
        })
        .collect()
}

/// RFC 2328 §16.7: a virtual link's far end, as seen in its transit area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualEndpoint {
    /// The endpoint's intra-area distance — the virtual link's cost.
    pub cost: u32,
    /// The first-hop router addresses toward it (sorted).
    pub next_hops: Vec<Ipv4Addr>,
    /// The endpoint's own interface address in the transit area: where the
    /// virtual link's packets go.
    pub address: Ipv4Addr,
}

/// RFC 2328 §16.7 for one virtual link: `endpoint`'s intra-area path from
/// `root` over the transit area's `lsas`, or `None` while it has none (the
/// virtual link is down). `ponytail:` the endpoint's address is the
/// `link_data` of its Router-LSA's first type-1/type-2 link, not the
/// interface on the computed path — the same for a single-homed endpoint.
pub fn virtual_link_endpoint(
    root: Ipv4Addr,
    lsas: &[Arc<Lsa>],
    endpoint: Ipv4Addr,
) -> Option<VirtualEndpoint> {
    let live = live_lsas(lsas);
    let (routers, networks, hosts) = routers_and_networks(&live);
    let (dist, next_hop) = run_dijkstra(root, &routers, &networks, &hosts, &Context::default());
    let vertex = Vertex::Router(endpoint);
    let cost = *dist.get(&vertex)?;
    let next_hops = router_hops(&next_hop, vertex);
    let address = routers
        .get(&endpoint)?
        .links
        .iter()
        .find(|l| {
            matches!(
                l.link_type,
                LINK_TYPE_POINT_TO_POINT | LINK_TYPE_TRANSIT_NETWORK
            )
        })?
        .link_data;
    (endpoint != root && !next_hops.is_empty()).then_some(VirtualEndpoint {
        cost,
        next_hops,
        address,
    })
}

/// The Dijkstra core: standard lazy-deletion priority-queue shortest path,
/// tracking each finalized vertex's distance and derived next-hop set. An
/// equal-distance relaxation unions the new parent's hops in (RFC 2328
/// §16.1 step 2(d)); it can only hit a not-yet-popped vertex, since every
/// parent at a lower distance pops first and a zero-cost network parent is
/// ordered ahead of its routers (`HeapEntry::cmp`).
fn run_dijkstra(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
    hosts: &HashSet<Ipv4Addr>,
    ctx: &Context,
) -> (HashMap<Vertex, u32>, HashMap<Vertex, Vec<NextHop>>) {
    let root_vertex = Vertex::Router(root);
    let mut dist: HashMap<Vertex, u32> = HashMap::new();
    let mut next_hop: HashMap<Vertex, Vec<NextHop>> = HashMap::new();
    let mut visited: HashSet<Vertex> = HashSet::new();
    let mut heap = BinaryHeap::new();

    dist.insert(root_vertex, 0);
    heap.push(HeapEntry {
        dist: 0,
        vertex: root_vertex,
    });

    while let Some(HeapEntry { dist: d, vertex }) = heap.pop() {
        if !visited.insert(vertex) {
            continue;
        }
        if d > *dist.get(&vertex).unwrap_or(&u32::MAX) {
            continue;
        }

        // RFC 8770 §4: a host router other than root is a leaf — reached,
        // and its stubs collected, but never transited.
        if matches!(vertex, Vertex::Router(id) if id != root && hosts.contains(&id)) {
            continue;
        }
        for (next_vertex, edge_cost, virtual_link) in
            neighbors(vertex, routers, networks, ctx.backbone)
        {
            if visited.contains(&next_vertex) {
                continue;
            }
            let candidate = d.saturating_add(edge_cost);
            let current = *dist.get(&next_vertex).unwrap_or(&u32::MAX);
            if candidate > current {
                continue;
            }
            // RFC 2328 §16.1: a virtual link out of root goes through the
            // transit area, so its next hops are §16.7's, not the link's.
            let hops = match next_vertex {
                Vertex::Router(endpoint) if virtual_link && vertex == root_vertex => ctx
                    .virtual_links
                    .iter()
                    .filter(|v| v.endpoint == endpoint)
                    .flat_map(|v| v.next_hops.iter().map(|&a| NextHop::Router(a)))
                    .collect(),
                _ => derive_next_hops(vertex, next_vertex, root, routers, &next_hop),
            };
            if hops.is_empty() {
                // No reciprocal link back — stale/asymmetric LSDB
                // mid-convergence. Treat as unreachable via this edge,
                // never panic.
                continue;
            }
            if candidate < current {
                dist.insert(next_vertex, candidate);
                next_hop.insert(next_vertex, hops);
                heap.push(HeapEntry {
                    dist: candidate,
                    vertex: next_vertex,
                });
            } else {
                let set = next_hop.entry(next_vertex).or_default();
                set.extend(hops);
                set.sort_unstable();
                set.dedup();
            }
        }
    }

    (dist, next_hop)
}

/// Every graph edge out of `vertex`, flagged when it is a virtual link.
/// Type-3 (stub) Router-LSA links are never edges — they're leaves, handled
/// by `collect_stub_routes`. A type-4 (virtual) link is an edge in the
/// backbone only, and only when the endpoint's Router-LSA has one back
/// (RFC 2328 §16.1 step 2(b)).
fn neighbors(
    vertex: Vertex,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
    backbone: bool,
) -> Vec<(Vertex, u32, bool)> {
    match vertex {
        Vertex::Router(id) => {
            let Some(body) = routers.get(&id) else {
                return Vec::new();
            };
            body.links
                .iter()
                .filter_map(|l| match l.link_type {
                    LINK_TYPE_POINT_TO_POINT => {
                        Some((Vertex::Router(l.link_id), u32::from(l.metric), false))
                    }
                    LINK_TYPE_TRANSIT_NETWORK => {
                        Some((Vertex::Network(l.link_id), u32::from(l.metric), false))
                    }
                    LINK_TYPE_VIRTUAL
                        if backbone
                            && own_link(routers, l.link_id, LINK_TYPE_VIRTUAL, id).is_some() =>
                    {
                        Some((Vertex::Router(l.link_id), u32::from(l.metric), true))
                    }
                    _ => None,
                })
                .collect()
        }
        Vertex::Network(id) => {
            let Some(net) = networks.get(&id) else {
                return Vec::new();
            };
            net.attached_routers
                .iter()
                .map(|&r| (Vertex::Router(r), 0, false))
                .collect()
        }
    }
}

/// Computes the next-hop set to contribute to `child`, given it's being
/// reached via `parent`: each of the parent's hops is inherited, except the
/// `Network` sentinel, resolved per child. Empty means no next-hop could be
/// derived at all — the caller treats `child` as unreachable via this edge.
fn derive_next_hops(
    parent: Vertex,
    child: Vertex,
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
) -> Vec<NextHop> {
    if parent == Vertex::Router(root) {
        return match child {
            Vertex::Router(w) => own_link_data(routers, w, LINK_TYPE_POINT_TO_POINT, root)
                .map(NextHop::Router)
                .into_iter()
                .collect(),
            Vertex::Network(_) => vec![NextHop::Network],
        };
    }
    let mut hops: Vec<NextHop> = next_hop
        .get(&parent)
        .into_iter()
        .flatten()
        .filter_map(|&nh| match nh {
            NextHop::Router(addr) => Some(NextHop::Router(addr)),
            NextHop::Network => match (parent, child) {
                (Vertex::Network(network_id), Vertex::Router(w)) => {
                    own_link_data(routers, w, LINK_TYPE_TRANSIT_NETWORK, network_id)
                        .map(NextHop::Router)
                }
                // Only a `Network` vertex ever stores this sentinel — a
                // `Router` parent always resolves to `NextHop::Router`. Not
                // a real path.
                _ => None,
            },
        })
        .collect();
    hops.sort_unstable();
    hops.dedup();
    hops
}

/// The concrete router addresses in a vertex's next-hop set (sorted, since
/// the set is) — empty if it has none, e.g. only the `Network` sentinel.
fn router_hops(next_hop: &HashMap<Vertex, Vec<NextHop>>, vertex: Vertex) -> Vec<Ipv4Addr> {
    next_hop
        .get(&vertex)
        .into_iter()
        .flatten()
        .filter_map(|&nh| match nh {
            NextHop::Router(addr) => Some(addr),
            NextHop::Network => None,
        })
        .collect()
}

/// Looks up `router`'s own Router-LSA for a link of `link_type` pointing
/// back to `target` (root's router-id for a p2p link, or a network's
/// vertex id for a transit-network link), returning that link's
/// `link_data` — see the module doc for why this is `router`'s own address
/// as seen from `target`, derived purely from the LSDB.
fn own_link_data(
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    router: Ipv4Addr,
    link_type: u8,
    target: Ipv4Addr,
) -> Option<Ipv4Addr> {
    own_link(routers, router, link_type, target).map(|l| l.link_data)
}

/// `own_link_data`'s whole link — its metric is the reverse cost RFC 5286
/// §3.5 checks.
fn own_link<'a>(
    routers: &HashMap<Ipv4Addr, &'a RouterLsaBody>,
    router: Ipv4Addr,
    link_type: u8,
    target: Ipv4Addr,
) -> Option<&'a RouterLink> {
    routers
        .get(&router)?
        .links
        .iter()
        .find(|l| l.link_type == link_type && l.link_id == target)
}

/// Transit-network destinations (Network-LSA vertices reached by SPF),
/// skipping any network root itself is directly attached to — already a
/// real kernel connected route via the interface's own address, per the
/// module doc's directly-connected filter.
fn collect_network_routes(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
    out: &mut HashMap<Ipv4Net, RouteEntry>,
) {
    for (&network_id, network) in networks {
        let vertex = Vertex::Network(network_id);
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        // RFC 6860 §2.2.2.2: a hidden transit network still carries transit
        // (it stays a Dijkstra vertex) but MUST NOT be installed — nor, via
        // `intra_area_routes`, summarized into another area.
        if network.network_mask == Ipv4Addr::BROADCAST {
            continue;
        }
        if root_attached_to_network(root, routers, network_id) {
            continue;
        }
        let next_hops = router_hops(next_hop, vertex);
        if next_hops.is_empty() {
            continue;
        }
        insert_best(
            out,
            RouteEntry {
                prefix: net_from(network_id, network.network_mask),
                next_hops,
                metric: d,
                backup_next_hop: None,
                backup_tunnel: None,
                egress: vertex,
                class: PathClass::Intra,
            },
        );
    }
}

/// Stub-network leaves (RFC 2328 §16.2): attached to every non-root router
/// with a finite Dijkstra distance. Filters by `(link_id, link_data)` key,
/// not by reachability — the far end of root's own point-to-point link
/// independently advertises the identical subnet (see `crate::link`'s
/// unconditional stub-network origination), which Dijkstra *will* reach;
/// only a key-based filter catches that mirrored duplicate.
fn collect_stub_routes(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
    out: &mut HashMap<Ipv4Net, RouteEntry>,
) {
    for (&router_id, body) in routers {
        if router_id == root {
            continue;
        }
        let vertex = Vertex::Router(router_id);
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        let next_hops = router_hops(next_hop, vertex);
        if next_hops.is_empty() {
            continue;
        }
        for link in &body.links {
            if link.link_type != LINK_TYPE_STUB_NETWORK {
                continue;
            }
            let key = (link.link_id, link.link_data);
            if root_advertises_stub(root, routers, key) {
                continue;
            }
            insert_best(
                out,
                RouteEntry {
                    prefix: net_from(link.link_id, link.link_data),
                    next_hops: next_hops.clone(),
                    metric: d.saturating_add(u32::from(link.metric)),
                    backup_next_hop: None,
                    backup_tunnel: None,
                    egress: vertex,
                    class: PathClass::Intra,
                },
            );
        }
    }
}

/// `intra_area_routes`'s own stub-network collector — unlike
/// `collect_stub_routes` (used by `compute` for this router's own final
/// route set, where a directly-connected destination is deliberately
/// excluded since it's already a real kernel connected route), this
/// **includes** root's own directly-attached stub networks: what's "already
/// directly connected" from this area's own perspective is exactly what a
/// real ABR must summarize into its *other* areas (e.g. this router's own
/// loopback stub in area A becomes a Type-3 into area B). `next_hop` is
/// irrelevant to a caller that only reads `.metric`/`.prefix` (see
/// `LinkManager::originate_summary_lsas`), so root's own stubs use `root`
/// itself as a placeholder next-hop. No mirrored-duplicate key filter is
/// needed (unlike `collect_stub_routes`'s `root_advertises_stub` guard): a
/// p2p subnet's own copy (distance 0 + local cost) and a neighbor's mirrored
/// copy (link cost + neighbor's advertised cost) share the same
/// prefix key, so `insert_best` already keeps the cheaper —
/// always root's own — automatically.
fn collect_intra_area_stub_routes(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
    out: &mut HashMap<Ipv4Net, RouteEntry>,
) {
    for (&router_id, body) in routers {
        let vertex = Vertex::Router(router_id);
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        let next_hops = if router_id == root {
            vec![root]
        } else {
            router_hops(next_hop, vertex)
        };
        if next_hops.is_empty() {
            continue;
        }
        for link in &body.links {
            if link.link_type != LINK_TYPE_STUB_NETWORK {
                continue;
            }
            insert_best(
                out,
                RouteEntry {
                    prefix: net_from(link.link_id, link.link_data),
                    next_hops: next_hops.clone(),
                    metric: d.saturating_add(u32::from(link.metric)),
                    backup_next_hop: None,
                    backup_tunnel: None,
                    egress: vertex,
                    class: PathClass::Intra,
                },
            );
        }
    }
}

/// RFC 2328 §16.3 inter-area routes from Type-3 Summary-LSAs. Mirrors
/// `collect_external_routes` exactly: the summary's advertising router (the
/// ABR that originated it, see `crate::link::originate_summary_lsas`) must
/// already have a computed intra-area distance/next-hop in this area; the
/// summary's own `metric` is simply added. `advertising_router == root` is
/// guarded the same way `collect_external_routes` guards `asbr == root` —
/// this router's own self-installed Type-3 must never produce a spurious
/// route to its own summarized prefix via itself.
fn collect_summary_routes(
    root: Ipv4Addr,
    summaries: &[(Ipv4Addr, Ipv4Addr, &SummaryLsaBody)],
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
    out: &mut HashMap<Ipv4Net, RouteEntry>,
) {
    for &(abr, link_state_id, s) in summaries {
        if abr == root {
            continue;
        }
        let vertex = Vertex::Router(abr);
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        let next_hops = router_hops(next_hop, vertex);
        if next_hops.is_empty() {
            continue;
        }
        insert_best(
            out,
            RouteEntry {
                prefix: net_from(link_state_id, s.network_mask),
                next_hops,
                metric: d.saturating_add(s.metric),
                backup_next_hop: None,
                backup_tunnel: None,
                egress: vertex,
                class: PathClass::Inter,
            },
        );
    }
}

/// Distance+next-hop to `asbr`. Prefers a direct intra-area Router-LSA
/// vertex; if `asbr` has none (it's genuinely outside this area), falls back
/// to an installed Type-4 ASBR-summary LSA for it in this area — cost is
/// that summary's advertising ABR's own intra-area distance plus the
/// summary's metric, next-hop is the ABR's own next-hop (packets to a
/// foreign ASBR go via the ABR proxying reachability to it). Multiple
/// Type-4s for the same `asbr` (from different ABRs) take the cheapest;
/// equal-cost ones union their ABRs' next hops (egress: the first of them).
fn asbr_distance(
    asbr: Ipv4Addr,
    asbr_summaries: &[(Ipv4Addr, Ipv4Addr, &SummaryLsaBody)],
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
) -> Option<(u32, Vec<Ipv4Addr>, Vertex)> {
    let direct = Vertex::Router(asbr);
    if let Some(&d) = dist.get(&direct) {
        let hops = router_hops(next_hop, direct);
        if !hops.is_empty() {
            return Some((d, hops, direct));
        }
    }
    let proxies: Vec<(u32, Vec<Ipv4Addr>, Vertex)> = asbr_summaries
        .iter()
        .filter(|&&(_, target, _)| target == asbr)
        .filter_map(|&(abr, _, s)| {
            let vertex = Vertex::Router(abr);
            let &d = dist.get(&vertex)?;
            let hops = router_hops(next_hop, vertex);
            (!hops.is_empty()).then_some((d.saturating_add(s.metric), hops, vertex))
        })
        .collect();
    let best = proxies.iter().map(|&(d, _, _)| d).min()?;
    let mut ties = proxies.into_iter().filter(|&(d, _, _)| d == best);
    let (_, mut hops, egress) = ties.next()?;
    for (_, more, _) in ties {
        hops.extend(more);
    }
    hops.sort_unstable();
    hops.dedup();
    Some((best, hops, egress))
}

/// RFC 2328 §16.4 AS-external routes. Per LSA: skip `LSInfinity` (step 1); a
/// forwarding address of `0.0.0.0` routes via the ASBR (`asbr_distance`, direct
/// or through a Type-4), any other via the intra-/inter-area route to it
/// (`resolve_forwarding_address`, step 3; none = skip); the path class
/// (Type 1 / Type 2) comes from the E bit and `insert_best` ranks with
/// `prefer`. Must run after every Internal collector, which the FA lookup reads.
///
/// **Explicit `asbr == root` guard**: this router's own Type-5, once
/// installed into its own area's LSDB (see `crate::link::
/// originate_as_external_lsas`), would otherwise compute a spurious route to
/// its own redistributed prefix via itself — `dist` is seeded with `root -> 0`.
fn collect_external_routes(
    root: Ipv4Addr,
    externals: &[(Ipv4Addr, Ipv4Addr, &AsExternalLsaBody)],
    asbr_summaries: &[(Ipv4Addr, Ipv4Addr, &SummaryLsaBody)],
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
    attached: &[(Ipv4Net, u32)],
    out: &mut HashMap<Ipv4Net, RouteEntry>,
) {
    for &(asbr, link_state_id, ext) in externals {
        if asbr == root || ext.metric >= LS_INFINITY {
            continue;
        }
        let resolved = if ext.forwarding_address.is_unspecified() {
            asbr_distance(asbr, asbr_summaries, dist, next_hop)
        } else {
            resolve_forwarding_address(ext.forwarding_address, root, attached, out)
        };
        let Some((d, next_hops, egress)) = resolved else {
            continue;
        };
        // Keyed by the truncated prefix like every collector, so a stub
        // route and an external route to the same prefix collide.
        insert_best(
            out,
            RouteEntry {
                prefix: net_from(link_state_id, ext.network_mask),
                next_hops,
                metric: d.saturating_add(ext.metric),
                backup_next_hop: None,
                backup_tunnel: None,
                egress,
                class: if ext.e_type2 {
                    PathClass::External2 { ext: ext.metric }
                } else {
                    PathClass::External1
                },
            },
        );
    }
}

/// RFC 3101 / RFC 2328 §16.4 step 3: cost and next hops to a non-zero
/// forwarding address — the longest match among the Internal routes in `out`
/// (intra- and inter-area; an external route doesn't count) and root's own
/// attached prefixes (`attached`, which `out` leaves out: the FA is then on-link,
/// next hop the FA itself).
fn resolve_forwarding_address(
    fa: Ipv4Addr,
    root: Ipv4Addr,
    attached: &[(Ipv4Net, u32)],
    out: &HashMap<Ipv4Net, RouteEntry>,
) -> Option<(u32, Vec<Ipv4Addr>, Vertex)> {
    let route = out
        .values()
        .filter(|r| r.class.internal() && r.prefix.contains(&fa))
        .max_by_key(|r| r.prefix.prefix_len());
    let direct = attached
        .iter()
        .filter(|(net, _)| net.contains(&fa))
        .max_by_key(|(net, _)| net.prefix_len());
    match (route, direct) {
        (r, Some(&(net, cost))) if r.is_none_or(|r| net.prefix_len() >= r.prefix.prefix_len()) => {
            Some((cost, vec![fa], Vertex::Router(root)))
        }
        (Some(r), _) if !r.next_hops.is_empty() => Some((r.metric, r.next_hops.clone(), r.egress)),
        _ => None,
    }
}

/// Root's own attached prefixes with their link cost: its stub links and the
/// transit networks it sits on (mask from the Network-LSA).
fn root_attached_prefixes(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
) -> Vec<(Ipv4Net, u32)> {
    let Some(body) = routers.get(&root) else {
        return Vec::new();
    };
    body.links
        .iter()
        .filter_map(|l| match l.link_type {
            LINK_TYPE_STUB_NETWORK => Some((net_from(l.link_id, l.link_data), l.metric)),
            LINK_TYPE_TRANSIT_NETWORK => networks
                .get(&l.link_id)
                .map(|n| (net_from(l.link_id, n.network_mask), l.metric)),
            _ => None,
        })
        .map(|(net, metric)| (net, u32::from(metric)))
        .collect()
}

fn root_attached_to_network(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    network_id: Ipv4Addr,
) -> bool {
    routers.get(&root).is_some_and(|body| {
        body.links
            .iter()
            .any(|l| l.link_type == LINK_TYPE_TRANSIT_NETWORK && l.link_id == network_id)
    })
}

fn root_advertises_stub(
    root: Ipv4Addr,
    routers: &HashMap<Ipv4Addr, &RouterLsaBody>,
    key: (Ipv4Addr, Ipv4Addr),
) -> bool {
    routers.get(&root).is_some_and(|body| {
        body.links
            .iter()
            .any(|l| l.link_type == LINK_TYPE_STUB_NETWORK && (l.link_id, l.link_data) == key)
    })
}

/// Keeps the minimum-metric candidate per destination key — a stub network
/// (or, in principle, a transit network) reachable via more than one
/// router/path keeps only its shortest, and equal-metric candidates merge
/// their next hops (`merge_equal`).
fn insert_best(out: &mut HashMap<Ipv4Net, RouteEntry>, candidate: RouteEntry) {
    match out.get_mut(&candidate.prefix) {
        None => {
            out.insert(candidate.prefix, candidate);
        }
        Some(existing) => match prefer(&candidate, existing) {
            Ordering::Less => *existing = candidate,
            Ordering::Equal => merge_equal(existing, candidate),
            Ordering::Greater => {}
        },
    }
}

/// Folds an equal-metric `other` route to the same prefix into `existing`:
/// unions `next_hops` (sorted, deduped) and keeps `existing`'s `egress` — the
/// LFA test only needs *a* shortest-path egress, and both are at the same
/// distance. A backup that became a primary hop is dropped. Shared by
/// `insert_best` and `LinkManager::compute_routes`' cross-area merge.
pub(crate) fn merge_equal(existing: &mut RouteEntry, other: RouteEntry) {
    existing.next_hops.extend(other.next_hops);
    existing.next_hops.sort_unstable();
    existing.next_hops.dedup();
    if existing
        .backup_next_hop
        .is_some_and(|b| existing.next_hops.contains(&b))
    {
        existing.backup_next_hop = None;
    }
    // A remote LFA protects a single next hop only.
    if existing.next_hops.len() > 1 {
        existing.backup_tunnel = None;
    }
}

/// Builds the truncated `Ipv4Net` for an `(address, subnet mask)` pair off
/// the wire. The address can have host bits set: a Network-LSA's ID is the
/// DR's interface address, and a Type-3/5/7 ID is the prefix with host bits
/// set when the originator needed RFC 2328 Appendix E to tell two
/// overlapping prefixes apart. Truncating makes both name the same prefix as
/// a network-address ID. The mask is assumed contiguous, so `count_ones`
/// recovers the prefix length.
fn net_from(addr: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Net {
    #[allow(clippy::cast_possible_truncation)]
    let prefix_len = u32::from(mask).count_ones() as u8;
    Ipv4Net::new(addr, prefix_len)
        .unwrap_or_else(|_| Ipv4Net::new(addr, 32).unwrap())
        .trunc()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{LsaHeader, RouterLink, LSA_TYPE_NETWORK, LSA_TYPE_ROUTER};

    fn router_id(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(1, 1, 1, n)
    }

    fn addr(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn p2p(neighbor: Ipv4Addr, own_addr: Ipv4Addr, metric: u16) -> RouterLink {
        RouterLink {
            tos: Vec::new(),
            link_id: neighbor,
            link_data: own_addr,
            link_type: LINK_TYPE_POINT_TO_POINT,
            metric,
        }
    }

    fn transit(network_id: Ipv4Addr, own_addr: Ipv4Addr, metric: u16) -> RouterLink {
        RouterLink {
            tos: Vec::new(),
            link_id: network_id,
            link_data: own_addr,
            link_type: LINK_TYPE_TRANSIT_NETWORK,
            metric,
        }
    }

    fn stub(net: Ipv4Addr, mask: Ipv4Addr, metric: u16) -> RouterLink {
        RouterLink {
            tos: Vec::new(),
            link_id: net,
            link_data: mask,
            link_type: LINK_TYPE_STUB_NETWORK,
            metric,
        }
    }

    fn router_lsa(id: Ipv4Addr, links: Vec<RouterLink>) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: id,
                advertising_router: id,
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody { flags: 0, links }),
        })
    }

    fn network_lsa(id: Ipv4Addr, mask: Ipv4Addr, attached: Vec<Ipv4Addr>) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_NETWORK,
                link_state_id: id,
                advertising_router: attached[0],
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Network(NetworkLsaBody {
                network_mask: mask,
                attached_routers: attached,
            }),
        })
    }

    /// RFC 2328 §16.7: reachable over two hops (cost, first hop, the
    /// endpoint's own address), a changed endpoint address follows its
    /// Router-LSA, and no path (or root itself) is no endpoint.
    #[test]
    fn virtual_link_endpoint_follows_the_transit_area_path() {
        let (root, mid, end) = (router_id(1), router_id(2), router_id(3));
        let root_lsa = router_lsa(root, vec![p2p(mid, addr(10, 0, 0, 1), 2)]);
        let mid_lsa = router_lsa(
            mid,
            vec![
                p2p(root, addr(10, 0, 0, 2), 2),
                p2p(end, addr(10, 0, 1, 1), 3),
            ],
        );
        let end_lsa = |own| router_lsa(end, vec![p2p(mid, own, 3)]);
        let lsas = [
            root_lsa.clone(),
            mid_lsa.clone(),
            end_lsa(addr(10, 0, 1, 2)),
        ];
        assert_eq!(
            virtual_link_endpoint(root, &lsas, end),
            Some(VirtualEndpoint {
                cost: 5,
                next_hops: vec![addr(10, 0, 0, 2)],
                address: addr(10, 0, 1, 2),
            })
        );
        let moved = [root_lsa.clone(), mid_lsa, end_lsa(addr(10, 0, 1, 9))];
        assert_eq!(
            virtual_link_endpoint(root, &moved, end).map(|e| e.address),
            Some(addr(10, 0, 1, 9))
        );
        // The middle router gone: no intra-area path, the link is down.
        let cut = [root_lsa, end_lsa(addr(10, 0, 1, 2))];
        assert_eq!(virtual_link_endpoint(root, &cut, end), None);
        assert_eq!(virtual_link_endpoint(root, &lsas, root), None);
    }

    fn vlink(endpoint: Ipv4Addr, own_addr: Ipv4Addr, metric: u16) -> RouterLink {
        RouterLink {
            tos: Vec::new(),
            link_id: endpoint,
            link_data: own_addr,
            link_type: LINK_TYPE_VIRTUAL,
            metric,
        }
    }

    /// The backbone of a virtual link between root (1) and 3, root's p2p
    /// neighbor 2 behind it: 3 holds a stub, a Type-3 and a Type-5.
    fn virtual_backbone(back: bool) -> Vec<Arc<Lsa>> {
        let (root, near, far) = (router_id(1), router_id(2), router_id(3));
        let far_links = if back {
            vec![vlink(root, addr(10, 0, 1, 2), 4)]
        } else {
            Vec::new()
        };
        let mut far_links = far_links;
        far_links.push(stub(addr(192, 0, 2, 0), addr(255, 255, 255, 0), 1));
        vec![
            router_lsa(
                root,
                vec![
                    p2p(near, addr(10, 0, 0, 1), 1),
                    vlink(far, addr(10, 0, 1, 1), 4),
                ],
            ),
            router_lsa(near, vec![p2p(root, addr(10, 0, 0, 2), 1)]),
            router_lsa(far, far_links),
            network_summary_lsa(addr(198, 51, 100, 0), addr(255, 255, 255, 0), far, 10),
            as_external_lsa(addr(203, 0, 113, 0), addr(255, 255, 255, 0), far),
        ]
    }

    /// RFC 2328 §16.1 (#226): in the backbone a reciprocal type-4 link is an
    /// edge at its metric, with §16.7's transit-area next hops out of root;
    /// the endpoint's stub, Type-3 and (§16.4) Type-5 route through it. Not
    /// in another area, not one-way, and not without its §16.7 hops.
    #[test]
    fn virtual_link_is_a_backbone_edge_with_transit_next_hops() {
        let root = router_id(1);
        let hops = [VirtualNextHops {
            endpoint: router_id(3),
            next_hops: vec![addr(10, 0, 1, 9)],
        }];
        let ctx = Context {
            backbone: true,
            skip_summaries: false,
            virtual_links: &hops,
            remote_lfa: false,
        };
        let routes = compute_in(root, &virtual_backbone(true), &ctx);
        for (prefix, metric) in [
            ("192.0.2.0/24", 5),
            ("198.51.100.0/24", 14),
            ("203.0.113.0/24", 4 + DEFAULT_EXTERNAL_METRIC),
        ] {
            let r = route_to(&routes, prefix);
            assert_eq!(
                (r.metric, &r.next_hops[..]),
                (metric, &[addr(10, 0, 1, 9)][..])
            );
        }
        assert_eq!(compute_in(root, &virtual_backbone(false), &ctx), []);
        let not_backbone = Context {
            backbone: false,
            ..ctx
        };
        assert_eq!(compute_in(root, &virtual_backbone(true), &not_backbone), []);
        assert_eq!(compute(root, &virtual_backbone(true)), []);
    }

    /// A router behind the endpoint's peer (here: root seen from 2) reaches
    /// across the virtual link with its own first hop, inherited.
    #[test]
    fn virtual_link_beyond_the_first_hop_inherits_the_next_hop() {
        let ctx = Context {
            backbone: true,
            ..Context::default()
        };
        let routes = compute_in(router_id(2), &virtual_backbone(true), &ctx);
        let r = route_to(&routes, "192.0.2.0/24");
        assert_eq!((r.metric, &r.next_hops[..]), (6, &[addr(10, 0, 0, 1)][..]));
    }

    /// §16.2: a backbone ABR doesn't examine a non-backbone area's Type-3/4.
    #[test]
    fn skip_summaries_ignores_type3_and_type4() {
        let root = router_id(1);
        let abr = router_id(2);
        let foreign_asbr = router_id(9);
        let lsas = [
            router_lsa(root, vec![p2p(abr, addr(10, 0, 0, 1), 1)]),
            router_lsa(abr, vec![p2p(root, addr(10, 0, 0, 2), 1)]),
            network_summary_lsa(addr(198, 51, 100, 0), addr(255, 255, 255, 0), abr, 10),
            asbr_summary_lsa(foreign_asbr, abr, 5),
            as_external_lsa(addr(203, 0, 113, 0), addr(255, 255, 255, 0), foreign_asbr),
        ];
        assert_eq!(compute(root, &lsas).len(), 2);
        let ctx = Context {
            skip_summaries: true,
            ..Context::default()
        };
        assert_eq!(compute_in(root, &lsas, &ctx), []);
    }

    /// §16.3: only a transit-capable area (a reachable V-bit Router-LSA)
    /// yields candidates; `apply_transit` takes a cheaper one, merges an
    /// equal one, ignores a dearer one and never touches an external.
    #[test]
    fn transit_summaries_improve_backbone_routes() {
        let root = router_id(1);
        let abr = router_id(2);
        let abr_lsa = router_lsa(abr, vec![p2p(root, addr(10, 0, 1, 2), 1)]);
        let lsas = |abr_lsa: Arc<Lsa>| {
            vec![
                router_lsa(root, vec![p2p(abr, addr(10, 0, 1, 1), 1)]),
                abr_lsa,
                network_summary_lsa(addr(198, 51, 100, 0), addr(255, 255, 255, 0), abr, 10),
                network_summary_lsa(
                    addr(198, 51, 101, 0),
                    addr(255, 255, 255, 0),
                    abr,
                    LS_INFINITY,
                ),
            ]
        };
        assert_eq!(transit_summaries(root, &lsas(abr_lsa.clone())), []);
        let candidates = transit_summaries(root, &lsas(with_flags(&abr_lsa, ROUTER_FLAG_V)));
        assert_eq!(candidates.len(), 1);
        let candidate = candidates[0].clone();
        assert_eq!(
            (candidate.metric, &candidate.next_hops[..]),
            (11, &[addr(10, 0, 1, 2)][..])
        );

        let backbone = |metric, class| RouteEntry {
            prefix: candidate.prefix,
            next_hops: vec![addr(10, 0, 0, 2)],
            metric,
            backup_next_hop: None,
            backup_tunnel: None,
            egress: Vertex::Router(router_id(3)),
            class,
        };
        let applied = |metric, class| {
            let mut r = backbone(metric, class);
            apply_transit(&mut r, candidate.clone());
            (r.metric, r.next_hops)
        };
        assert_eq!(applied(14, PathClass::Inter), (11, vec![addr(10, 0, 1, 2)]));
        assert_eq!(
            applied(11, PathClass::Intra),
            (11, vec![addr(10, 0, 0, 2), addr(10, 0, 1, 2)])
        );
        assert_eq!(applied(9, PathClass::Inter), (9, vec![addr(10, 0, 0, 2)]));
        assert_eq!(
            applied(30, PathClass::External1),
            (30, vec![addr(10, 0, 0, 2)])
        );
    }

    #[test]
    fn direct_p2p_neighbor_stub_network_distance_and_next_hop() {
        let root = router_id(1);
        let w = router_id(2);
        let root_lsa = router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 5)]);
        let w_lsa = router_lsa(
            w,
            vec![
                p2p(root, addr(10, 0, 0, 2), 5),
                stub(addr(192, 168, 1, 0), addr(255, 255, 255, 0), 10),
            ],
        );

        let routes = compute(root, &[root_lsa, w_lsa]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "192.168.1.0/24".parse().unwrap());
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
        assert_eq!(routes[0].metric, 15);
    }

    #[test]
    fn two_hop_chain_inherits_first_hop_next_hop() {
        let root = router_id(1);
        let w = router_id(2);
        let x = router_id(3);
        let root_lsa = router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1)]);
        let w_lsa = router_lsa(
            w,
            vec![
                p2p(root, addr(10, 0, 0, 2), 1),
                p2p(x, addr(10, 0, 1, 1), 1),
            ],
        );
        let x_lsa = router_lsa(
            x,
            vec![
                p2p(w, addr(10, 0, 1, 2), 1),
                stub(addr(192, 168, 2, 0), addr(255, 255, 255, 0), 1),
            ],
        );

        let routes = compute(root, &[root_lsa, w_lsa, x_lsa]);
        assert_eq!(routes.len(), 1);
        // Next-hop is W's own derived address (10.0.0.2), inherited
        // unchanged from the first hop — never X's link_data toward W
        // (10.0.1.2), which would be wrong.
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
        assert_eq!(routes[0].metric, 3);
    }

    #[test]
    fn network_attached_router_next_hop_derived_from_its_own_type2_link() {
        let root = router_id(1);
        let w = router_id(2);
        let network_id = addr(10, 0, 0, 1); // root is DR, so this is root's own address too
        let root_lsa = router_lsa(root, vec![transit(network_id, addr(10, 0, 0, 1), 1)]);
        let w_lsa = router_lsa(
            w,
            vec![
                transit(network_id, addr(10, 0, 0, 2), 1),
                stub(addr(192, 168, 3, 0), addr(255, 255, 255, 0), 1),
            ],
        );
        let net_lsa = network_lsa(network_id, addr(255, 255, 255, 0), vec![root, w]);

        let routes = compute(root, &[root_lsa, w_lsa, net_lsa]);
        // Only the stub behind W, never a route for the shared network
        // itself (root is directly attached to it).
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "192.168.3.0/24".parse().unwrap());
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
        assert_eq!(routes[0].metric, 2);
    }

    /// RFC 6860 §2.2.2.2: root reaches X only across W's segment. A /32
    /// Network-LSA still carries that transit, but yields no route itself —
    /// neither installed nor (via `intra_area_routes`) summarized.
    #[test]
    fn hidden_transit_network_carries_transit_but_yields_no_route() {
        let root = router_id(1);
        let w = router_id(2);
        let x = router_id(3);
        let segment = addr(10, 1, 0, 1); // W is DR
        let lsdb = |mask: Ipv4Addr| {
            vec![
                router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1)]),
                router_lsa(
                    w,
                    vec![
                        p2p(root, addr(10, 0, 0, 2), 1),
                        transit(segment, segment, 1),
                    ],
                ),
                router_lsa(
                    x,
                    vec![
                        transit(segment, addr(10, 1, 0, 2), 1),
                        stub(addr(192, 168, 9, 0), addr(255, 255, 255, 0), 1),
                    ],
                ),
                network_lsa(segment, mask, vec![w, x]),
            ]
        };
        let by_prefix = |routes: Vec<RouteEntry>| -> HashMap<Ipv4Net, RouteEntry> {
            routes.into_iter().map(|r| (r.prefix, r)).collect()
        };
        let stub_net: Ipv4Net = "192.168.9.0/24".parse().unwrap();
        let segment_net: Ipv4Net = "10.1.0.0/24".parse().unwrap();

        let shown = by_prefix(compute(root, &lsdb(addr(255, 255, 255, 0))));
        assert!(shown.contains_key(&segment_net), "not vacuous");
        let hidden = by_prefix(compute(root, &lsdb(Ipv4Addr::BROADCAST)));
        assert_eq!(hidden.len(), 1);
        assert!(!hidden.keys().any(|p| p.addr() == segment));
        let (a, b) = (&shown[&stub_net], &hidden[&stub_net]);
        assert_eq!((&a.next_hops, a.metric), (&b.next_hops, b.metric));
        assert_eq!(b.next_hops, vec![addr(10, 0, 0, 2)]);

        let summarized =
            intra_area_routes(root, &lsdb(Ipv4Addr::BROADCAST), &Context::default()).routes;
        assert_eq!(
            summarized.iter().map(|r| r.prefix).collect::<Vec<_>>(),
            vec![stub_net]
        );
    }

    #[test]
    fn stub_leaf_duplicate_network_keeps_minimum_distance() {
        let root = router_id(1);
        let w1 = router_id(2);
        let w2 = router_id(3);
        let net = addr(192, 168, 4, 0);
        let mask = addr(255, 255, 255, 0);
        let root_lsa = router_lsa(
            root,
            vec![p2p(w1, addr(10, 0, 0, 1), 1), p2p(w2, addr(10, 0, 1, 1), 1)],
        );
        let w1_lsa = router_lsa(
            w1,
            vec![p2p(root, addr(10, 0, 0, 2), 1), stub(net, mask, 10)],
        );
        let w2_lsa = router_lsa(
            w2,
            vec![p2p(root, addr(10, 0, 1, 2), 1), stub(net, mask, 1)],
        );

        let routes = compute(root, &[root_lsa, w1_lsa, w2_lsa]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metric, 2);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 1, 2)]);
    }

    #[test]
    fn directly_connected_p2p_subnet_is_filtered() {
        let root = router_id(1);
        let root_lsa = router_lsa(
            root,
            vec![stub(addr(10, 0, 0, 0), addr(255, 255, 255, 252), 1)],
        );
        assert_eq!(compute(root, &[root_lsa]), []);
    }

    #[test]
    fn directly_connected_transit_network_is_filtered() {
        let root = router_id(1);
        let network_id = addr(10, 0, 0, 1);
        let root_lsa = router_lsa(root, vec![transit(network_id, addr(10, 0, 0, 1), 1)]);
        let net_lsa = network_lsa(network_id, addr(255, 255, 255, 0), vec![root]);
        assert_eq!(compute(root, &[root_lsa, net_lsa]), []);
    }

    #[test]
    fn mirrored_p2p_subnet_via_neighbor_is_filtered() {
        let root = router_id(1);
        let w = router_id(2);
        let net = addr(10, 0, 0, 0);
        let mask = addr(255, 255, 255, 252);
        let root_lsa = router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1), stub(net, mask, 1)]);
        let w_lsa = router_lsa(w, vec![p2p(root, addr(10, 0, 0, 2), 1), stub(net, mask, 1)]);

        // Without the key-based filter, Dijkstra would happily reach W and
        // produce a spurious second route to root's own subnet via W.
        assert_eq!(compute(root, &[root_lsa, w_lsa]), []);
    }

    #[test]
    fn no_reciprocal_link_back_is_treated_as_unreachable() {
        let root = router_id(1);
        let w = router_id(2);
        let root_lsa = router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1)]);
        // W's own LSA has no link back to root — asymmetric/stale LSDB.
        let w_lsa = router_lsa(
            w,
            vec![stub(addr(192, 168, 5, 0), addr(255, 255, 255, 0), 1)],
        );

        // Must not panic, and W's stub must never appear — no next-hop
        // could be derived for it.
        assert_eq!(compute(root, &[root_lsa, w_lsa]), []);
    }

    #[test]
    fn dangling_link_id_with_no_matching_lsa_is_skipped() {
        let root = router_id(1);
        let w = router_id(2);
        // W's Router-LSA was never flooded/installed at all.
        let root_lsa = router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1)]);
        assert_eq!(compute(root, &[root_lsa]), []);
    }

    fn as_external_lsa(prefix: Ipv4Addr, mask: Ipv4Addr, advertising_router: Ipv4Addr) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: crate::lsa::LSA_TYPE_AS_EXTERNAL,
                link_state_id: prefix,
                advertising_router,
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(AsExternalLsaBody {
                tos: Vec::new(),
                network_mask: mask,
                metric: DEFAULT_EXTERNAL_METRIC,
                // E bit set: translation must carry it, SPF ignores it.
                e_type2: true,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                external_route_tag: 0,
            }),
        })
    }

    #[test]
    fn reachable_asbr_external_route_uses_asbr_distance_plus_constant() {
        let root = router_id(1);
        let asbr = router_id(2);
        let root_lsa = router_lsa(root, vec![p2p(asbr, addr(10, 0, 0, 1), 5)]);
        let asbr_lsa = router_lsa(asbr, vec![p2p(root, addr(10, 0, 0, 2), 5)]);
        let ext_lsa = as_external_lsa(addr(192, 0, 2, 0), addr(255, 255, 255, 0), asbr);

        let routes = compute(root, &[root_lsa, asbr_lsa, ext_lsa]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "192.0.2.0/24".parse().unwrap());
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
        assert_eq!(routes[0].metric, 5 + DEFAULT_EXTERNAL_METRIC);
    }

    fn type7(prefix: Ipv4Addr, asbr: Ipv4Addr, p_bit: bool, fa: Ipv4Addr) -> Arc<Lsa> {
        let mut l = (*as_external_lsa(prefix, addr(255, 255, 255, 0), asbr)).clone();
        l.header.lsa_type = LSA_TYPE_NSSA_EXTERNAL;
        l.header.options = if p_bit { OPTION_P } else { 0 };
        if let LsaBody::AsExternal(e) = &mut l.body {
            e.forwarding_address = fa;
        }
        Arc::new(l)
    }

    fn with_flags(lsa: &Arc<Lsa>, flags: u8) -> Arc<Lsa> {
        let mut l = (**lsa).clone();
        if let LsaBody::Router(r) = &mut l.body {
            r.flags = flags;
        }
        Arc::new(l)
    }

    /// RFC 3101: a Type-7 is an external route inside the NSSA, and only a
    /// P-bit one with a forwarding address from a reachable ASBR is
    /// translated.
    #[test]
    fn type7_routes_and_translations() {
        let (root, asbr, gone) = (router_id(1), router_id(2), router_id(9));
        let lsas = [
            router_lsa(
                root,
                vec![
                    p2p(asbr, addr(10, 0, 0, 1), 5),
                    stub(addr(10, 0, 0, 0), addr(255, 255, 255, 0), 5),
                ],
            ),
            router_lsa(asbr, vec![p2p(root, addr(10, 0, 0, 2), 5)]),
            type7(addr(192, 0, 2, 0), asbr, true, addr(10, 0, 0, 2)),
            type7(addr(198, 51, 100, 0), asbr, false, addr(10, 0, 0, 2)),
            type7(addr(203, 0, 113, 0), asbr, true, Ipv4Addr::UNSPECIFIED),
            type7(addr(192, 0, 3, 0), gone, true, addr(10, 9, 0, 9)),
        ];
        let routes = compute(root, &lsas);
        assert_eq!(routes.len(), 3, "{routes:?}");
        assert!(routes
            .iter()
            .all(|r| r.metric == 5 + DEFAULT_EXTERNAL_METRIC));
        assert_eq!(
            nssa_translations(root, &lsas),
            vec![(
                "192.0.2.0/24".parse().unwrap(),
                DEFAULT_EXTERNAL_METRIC,
                true
            )]
        );
    }

    /// RFC 3101 §3.1: the highest router-id among reachable ABRs translates,
    /// unless another has the Nt-bit; `always` translates regardless; an
    /// unreachable ABR doesn't count.
    #[test]
    fn nssa_translator_election() {
        let (low, high, far) = (router_id(1), router_id(2), router_id(3));
        let lsas = |high_flags, far_flags| {
            vec![
                with_flags(
                    &router_lsa(low, vec![p2p(high, addr(10, 0, 0, 1), 1)]),
                    ROUTER_FLAG_B,
                ),
                with_flags(
                    &router_lsa(high, vec![p2p(low, addr(10, 0, 0, 2), 1)]),
                    high_flags,
                ),
                // No link back to it: unreachable.
                with_flags(&router_lsa(far, vec![]), far_flags),
            ]
        };
        // Alone (the other isn't an ABR): low translates.
        assert!(nssa_translator(low, &lsas(0, ROUTER_FLAG_B), false));
        // Two ABRs: the higher id wins.
        let two = lsas(ROUTER_FLAG_B, ROUTER_FLAG_B | ROUTER_FLAG_NT);
        assert!(!nssa_translator(low, &two, false));
        assert!(nssa_translator(high, &two, false));
        // Always beats a higher id; Nt on the lower one beats the higher id.
        assert!(nssa_translator(low, &two, true));
        let nt_low = vec![
            with_flags(&two[0], ROUTER_FLAG_B | ROUTER_FLAG_NT),
            two[1].clone(),
        ];
        assert!(!nssa_translator(high, &nt_low, false));
    }

    #[test]
    fn unreachable_asbr_external_route_is_skipped() {
        let root = router_id(1);
        let asbr = router_id(2);
        // ASBR's own Router-LSA was never flooded/installed at all.
        let root_lsa = router_lsa(root, vec![]);
        let ext_lsa = as_external_lsa(addr(192, 0, 2, 0), addr(255, 255, 255, 0), asbr);
        assert_eq!(compute(root, &[root_lsa, ext_lsa]), []);
    }

    #[test]
    fn intra_area_route_beats_a_cheaper_external_route() {
        let root = router_id(1);
        let stub_router = router_id(2);
        let asbr = router_id(3);
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);

        // Via the stub-advertising router: cost 1 + 100 = 101.
        let root_lsa = router_lsa(
            root,
            vec![
                p2p(stub_router, addr(10, 0, 0, 1), 1),
                p2p(asbr, addr(10, 0, 1, 1), 1),
            ],
        );
        let stub_router_lsa = router_lsa(
            stub_router,
            vec![p2p(root, addr(10, 0, 0, 2), 1), stub(net, mask, 100)],
        );
        // Via the ASBR: cost 1 + 20 = 21, cheaper but external (§16.4 step 6a).
        let asbr_lsa = router_lsa(asbr, vec![p2p(root, addr(10, 0, 1, 2), 1)]);
        let ext_lsa = as_external_lsa(net, mask, asbr);

        let routes = compute(root, &[root_lsa, stub_router_lsa, asbr_lsa, ext_lsa]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
        assert_eq!(routes[0].metric, 101);
    }

    fn ext_lsa(
        prefix: Ipv4Addr,
        asbr: Ipv4Addr,
        metric: u32,
        e_type2: bool,
        fa: Ipv4Addr,
    ) -> Arc<Lsa> {
        let mut l = (*as_external_lsa(prefix, addr(255, 255, 255, 0), asbr)).clone();
        if let LsaBody::AsExternal(e) = &mut l.body {
            e.metric = metric;
            e.e_type2 = e_type2;
            e.forwarding_address = fa;
        }
        Arc::new(l)
    }

    /// Root with two ASBRs behind p2p links of cost `ca`/`cb` (10.0.1.0/30 and
    /// 10.0.2.0/30 root-side stubs, as `router_lsa_links` emits).
    fn two_asbrs(ca: u16, cb: u16, extra: Vec<Arc<Lsa>>) -> Vec<Arc<Lsa>> {
        let (root, a, b) = (router_id(1), router_id(2), router_id(3));
        let mut lsas = vec![
            router_lsa(
                root,
                vec![
                    p2p(a, addr(10, 0, 1, 1), ca),
                    stub(addr(10, 0, 1, 0), addr(255, 255, 255, 252), ca),
                    p2p(b, addr(10, 0, 2, 1), cb),
                    stub(addr(10, 0, 2, 0), addr(255, 255, 255, 252), cb),
                ],
            ),
            router_lsa(a, vec![p2p(root, addr(10, 0, 1, 2), ca)]),
            router_lsa(b, vec![p2p(root, addr(10, 0, 2, 2), cb)]),
        ];
        lsas.extend(extra);
        lsas
    }

    /// RFC 2328 §16.4 step 6: Type 1 beats Type 2 even when dearer; between
    /// Type 2s the smaller external metric wins, then the smaller distance;
    /// equal in both merges the next hops.
    #[test]
    fn external_type1_beats_type2_and_type2_compares_metric_then_distance() {
        let (a, b) = (router_id(2), router_id(3));
        let p = addr(192, 0, 2, 0);
        let none = Ipv4Addr::UNSPECIFIED;
        // Type 1 at 1+500 vs Type 2 at 1+5.
        let lsas = two_asbrs(
            1,
            1,
            vec![
                ext_lsa(p, a, 500, false, none),
                ext_lsa(p, b, 5, true, none),
            ],
        );
        let routes = compute(router_id(1), &lsas);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 1, 2)]);
        // Two Type 2s: smaller ext (b) wins although further away.
        let lsas = two_asbrs(
            1,
            9,
            vec![ext_lsa(p, a, 50, true, none), ext_lsa(p, b, 40, true, none)],
        );
        assert_eq!(
            compute(router_id(1), &lsas)[0].next_hops,
            vec![addr(10, 0, 2, 2)]
        );
        // Equal ext: the nearer ASBR (a).
        let lsas = two_asbrs(
            1,
            9,
            vec![ext_lsa(p, a, 40, true, none), ext_lsa(p, b, 40, true, none)],
        );
        assert_eq!(
            compute(router_id(1), &lsas)[0].next_hops,
            vec![addr(10, 0, 1, 2)]
        );
        // Equal in both: merged.
        let lsas = two_asbrs(
            1,
            1,
            vec![ext_lsa(p, a, 40, true, none), ext_lsa(p, b, 40, true, none)],
        );
        let r = &compute(router_id(1), &lsas)[0];
        assert_eq!(r.next_hops, vec![addr(10, 0, 1, 2), addr(10, 0, 2, 2)]);
        assert_eq!(r.metric, 41);
    }

    #[test]
    fn external_with_ls_infinity_metric_is_skipped() {
        let lsas = two_asbrs(
            1,
            1,
            vec![ext_lsa(
                addr(192, 0, 2, 0),
                router_id(2),
                LS_INFINITY,
                false,
                Ipv4Addr::UNSPECIFIED,
            )],
        );
        assert_eq!(compute(router_id(1), &lsas), []);
    }

    /// §16.4 step 3: a forwarding address on a root-attached subnet routes
    /// via the FA itself (not the ASBR), at the link cost.
    #[test]
    fn forwarding_address_on_an_attached_subnet_is_the_next_hop() {
        let fa = addr(10, 0, 2, 3);
        let lsas = two_asbrs(
            1,
            4,
            vec![ext_lsa(addr(192, 0, 2, 0), router_id(2), 7, false, fa)],
        );
        let routes = compute(router_id(1), &lsas);
        let r = route_to(&routes, "192.0.2.0/24");
        assert_eq!(r.next_hops, vec![fa]);
        assert_eq!(r.metric, 4 + 7);
    }

    /// An FA reached through an inter-area (Type-3) route uses that route's
    /// cost and next hops; one that only an external route covers, or nothing
    /// covers, drops the LSA.
    #[test]
    fn forwarding_address_resolves_through_inter_area_only() {
        let (a, none) = (router_id(2), Ipv4Addr::UNSPECIFIED);
        let mask = addr(255, 255, 255, 0);
        let lsas = two_asbrs(
            1,
            1,
            vec![
                network_summary_lsa(addr(172, 16, 0, 0), mask, a, 10),
                ext_lsa(addr(192, 0, 2, 0), a, 7, false, addr(172, 16, 0, 5)),
                // FA covered only by the external route above.
                ext_lsa(addr(198, 51, 100, 0), a, 7, false, addr(192, 0, 2, 9)),
                ext_lsa(addr(203, 0, 113, 0), a, 7, false, addr(172, 17, 0, 5)),
                // The metric-less control: still via the ASBR.
                ext_lsa(addr(100, 64, 0, 0), a, 7, false, none),
            ],
        );
        let routes = compute(router_id(1), &lsas);
        let r = route_to(&routes, "192.0.2.0/24");
        assert_eq!(r.next_hops, vec![addr(10, 0, 1, 2)]);
        assert_eq!(r.metric, 1 + 10 + 7);
        assert!(routes
            .iter()
            .all(|r| r.prefix.addr() != addr(198, 51, 100, 0)));
        assert!(routes
            .iter()
            .all(|r| r.prefix.addr() != addr(203, 0, 113, 0)));
        assert_eq!(route_to(&routes, "100.64.0.0/24").metric, 8);
    }

    #[test]
    fn own_as_external_lsa_is_never_treated_as_a_route_to_self() {
        let root = router_id(1);
        let root_lsa = router_lsa(root, vec![]);
        let ext_lsa = as_external_lsa(addr(192, 0, 2, 0), addr(255, 255, 255, 0), root);
        assert_eq!(compute(root, &[root_lsa, ext_lsa]), []);
    }

    fn network_summary_lsa(
        prefix: Ipv4Addr,
        mask: Ipv4Addr,
        advertising_router: Ipv4Addr,
        metric: u32,
    ) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_NETWORK_SUMMARY,
                link_state_id: prefix,
                advertising_router,
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Summary(SummaryLsaBody {
                tos: Vec::new(),
                network_mask: mask,
                metric,
            }),
        })
    }

    fn asbr_summary_lsa(target_asbr: Ipv4Addr, advertising_abr: Ipv4Addr, metric: u32) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_ASBR_SUMMARY,
                link_state_id: target_asbr,
                advertising_router: advertising_abr,
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Summary(SummaryLsaBody {
                tos: Vec::new(),
                network_mask: Ipv4Addr::UNSPECIFIED,
                metric,
            }),
        })
    }

    #[test]
    fn intra_area_routes_excludes_external_and_summary_derived_routes() {
        let root = router_id(1);
        let asbr = router_id(2);
        let border = router_id(3);
        let net = addr(192, 168, 6, 0);
        let mask = addr(255, 255, 255, 0);

        let root_lsa = router_lsa(
            root,
            vec![
                p2p(asbr, addr(10, 0, 0, 1), 1),
                p2p(border, addr(10, 0, 1, 1), 1),
                stub(net, mask, 5),
            ],
        );
        let asbr_lsa = router_lsa(asbr, vec![p2p(root, addr(10, 0, 0, 2), 1)]);
        let border_lsa = router_lsa(border, vec![p2p(root, addr(10, 0, 1, 2), 1)]);
        let ext_lsa = as_external_lsa(addr(198, 51, 100, 0), addr(255, 255, 255, 0), asbr);
        let summary_lsa_ = network_summary_lsa(addr(203, 0, 113, 0), mask, border, 10);

        let view = intra_area_routes(
            root,
            &[root_lsa, asbr_lsa, border_lsa, ext_lsa, summary_lsa_],
            &Context::default(),
        );
        // Only the genuine intra-area stub, never the external/summary route.
        assert_eq!(view.routes.len(), 1);
        assert_eq!(view.routes[0].prefix, "192.168.6.0/24".parse().unwrap());
        // Only the genuine in-area ASBR, never the border router (no Type-5 of its own).
        assert_eq!(view.asbrs, vec![(asbr, 1)]);
    }

    #[test]
    fn intra_area_routes_excludes_asbr_unreachable_in_this_area() {
        let root = router_id(1);
        let asbr = router_id(2);
        let root_lsa = router_lsa(root, vec![]);
        let ext_lsa = as_external_lsa(addr(192, 0, 2, 0), addr(255, 255, 255, 0), asbr);
        let view = intra_area_routes(root, &[root_lsa, ext_lsa], &Context::default());
        assert_eq!(view.routes, []);
        assert_eq!(view.asbrs, []);
    }

    #[test]
    fn type3_summary_route_uses_abr_distance_plus_summary_metric() {
        let root = router_id(1);
        let abr = router_id(2);
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);
        let root_lsa = router_lsa(root, vec![p2p(abr, addr(10, 0, 0, 1), 5)]);
        let abr_lsa = router_lsa(abr, vec![p2p(root, addr(10, 0, 0, 2), 5)]);
        let summary_lsa_ = network_summary_lsa(net, mask, abr, 10);

        let routes = compute(root, &[root_lsa, abr_lsa, summary_lsa_]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "192.0.2.0/24".parse().unwrap());
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
        assert_eq!(routes[0].metric, 15);
    }

    #[test]
    fn own_type3_summary_is_never_treated_as_a_route_to_self() {
        let root = router_id(1);
        let root_lsa = router_lsa(root, vec![]);
        let summary_lsa_ =
            network_summary_lsa(addr(192, 0, 2, 0), addr(255, 255, 255, 0), root, 10);
        assert_eq!(compute(root, &[root_lsa, summary_lsa_]), []);
    }

    #[test]
    fn intra_area_route_beats_a_cheaper_type3_summary() {
        let root = router_id(1);
        let stub_router = router_id(2);
        let abr = router_id(3);
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);

        // Via the stub-advertising router: cost 1 + 100 = 101.
        let root_lsa = router_lsa(
            root,
            vec![
                p2p(stub_router, addr(10, 0, 0, 1), 1),
                p2p(abr, addr(10, 0, 1, 1), 1),
            ],
        );
        let stub_router_lsa = router_lsa(
            stub_router,
            vec![p2p(root, addr(10, 0, 0, 2), 1), stub(net, mask, 100)],
        );
        // Via the ABR's summary: cost 1 + 10 = 11, cheaper but inter-area
        // (RFC 2328 §11, §16.2 step 3: the intra-area path wins).
        let abr_lsa = router_lsa(abr, vec![p2p(root, addr(10, 0, 1, 2), 1)]);
        let summary_lsa_ = network_summary_lsa(net, mask, abr, 10);

        let routes = compute(root, &[root_lsa, stub_router_lsa, abr_lsa, summary_lsa_]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
        assert_eq!(routes[0].metric, 101);
    }

    #[test]
    fn type4_summary_lets_foreign_asbr_be_reached_via_abr_proxy() {
        let root = router_id(1);
        let border = router_id(2);
        let asbr = router_id(3); // genuinely in another area: no Router-LSA here at all
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);

        let root_lsa = router_lsa(root, vec![p2p(border, addr(10, 0, 0, 1), 5)]);
        let border_lsa = router_lsa(border, vec![p2p(root, addr(10, 0, 0, 2), 5)]);
        let asbr_summary = asbr_summary_lsa(asbr, border, 10);
        let ext_lsa = as_external_lsa(net, mask, asbr);

        let routes = compute(root, &[root_lsa, border_lsa, asbr_summary, ext_lsa]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 0, 2)]);
        assert_eq!(routes[0].metric, 5 + 10 + DEFAULT_EXTERNAL_METRIC);
    }

    #[test]
    fn direct_intra_area_asbr_beats_type4_proxy() {
        let root = router_id(1);
        let border = router_id(2);
        let asbr = router_id(3);
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);

        // Direct path to the ASBR: cost 1. Via the border router's (much
        // pricier) Type-4 proxy: cost 5 + 10 = 15. Direct must win.
        let root_lsa = router_lsa(
            root,
            vec![
                p2p(asbr, addr(10, 0, 2, 1), 1),
                p2p(border, addr(10, 0, 0, 1), 5),
            ],
        );
        let asbr_lsa = router_lsa(asbr, vec![p2p(root, addr(10, 0, 2, 2), 1)]);
        let border_lsa = router_lsa(border, vec![p2p(root, addr(10, 0, 0, 2), 5)]);
        let asbr_summary = asbr_summary_lsa(asbr, border, 10);
        let ext_lsa = as_external_lsa(net, mask, asbr);

        let routes = compute(
            root,
            &[root_lsa, asbr_lsa, border_lsa, asbr_summary, ext_lsa],
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 2, 2)]);
        assert_eq!(routes[0].metric, 1 + DEFAULT_EXTERNAL_METRIC);
    }

    #[test]
    fn asbr_distance_prefers_cheapest_of_multiple_type4_proxies() {
        let root = router_id(1);
        let abr1 = router_id(2);
        let abr2 = router_id(3);
        let asbr = router_id(4);
        let net = addr(192, 0, 2, 0);
        let mask = addr(255, 255, 255, 0);

        // Via abr1: 1 + 100 = 101. Via abr2: 1 + 1 = 2, cheaper.
        let root_lsa = router_lsa(
            root,
            vec![
                p2p(abr1, addr(10, 0, 0, 1), 1),
                p2p(abr2, addr(10, 0, 1, 1), 1),
            ],
        );
        let abr1_lsa = router_lsa(abr1, vec![p2p(root, addr(10, 0, 0, 2), 1)]);
        let abr2_lsa = router_lsa(abr2, vec![p2p(root, addr(10, 0, 1, 2), 1)]);
        let summary1 = asbr_summary_lsa(asbr, abr1, 100);
        let summary2 = asbr_summary_lsa(asbr, abr2, 1);
        let ext_lsa = as_external_lsa(net, mask, asbr);

        let routes = compute(
            root,
            &[root_lsa, abr1_lsa, abr2_lsa, summary1, summary2, ext_lsa],
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hops, vec![addr(10, 0, 1, 2)]);
        assert_eq!(routes[0].metric, 2 + DEFAULT_EXTERNAL_METRIC);
    }

    /// root(1) — 2, root — 3, 2 — 3 with the given 2–3 cost; 2 owns a stub.
    fn triangle(cost_23: u16) -> Vec<Arc<Lsa>> {
        let (r1, r2, r3) = (router_id(1), router_id(2), router_id(3));
        vec![
            router_lsa(
                r1,
                vec![
                    p2p(r2, addr(10, 0, 12, 1), 1),
                    p2p(r3, addr(10, 0, 13, 1), 1),
                ],
            ),
            router_lsa(
                r2,
                vec![
                    p2p(r1, addr(10, 0, 12, 2), 1),
                    p2p(r3, addr(10, 0, 23, 2), cost_23),
                    stub(addr(192, 168, 2, 0), addr(255, 255, 255, 0), 1),
                ],
            ),
            router_lsa(
                r3,
                vec![
                    p2p(r1, addr(10, 0, 13, 3), 1),
                    p2p(r2, addr(10, 0, 23, 3), cost_23),
                ],
            ),
        ]
    }

    fn route_to(routes: &[RouteEntry], prefix: &str) -> RouteEntry {
        routes
            .iter()
            .find(|r| r.prefix == prefix.parse().unwrap())
            .cloned()
            .unwrap()
    }

    #[test]
    fn triangle_gets_loop_free_alternate_via_the_other_neighbor() {
        let routes = compute(router_id(1), &triangle(1));
        let r = route_to(&routes, "192.168.2.0/24");
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2)]);
        // 3 reaches 2 directly (1) < 3→root (1) + root→2 (1).
        assert_eq!(r.backup_next_hop, Some(addr(10, 0, 13, 3)));
    }

    /// An `n`-router ring (1-2-…-n-1), `cost(i, j)` the cost router `i`
    /// advertises toward `j`, each router with a loopback `10.255.0.i/32`
    /// unless listed in `no_loopback`.
    fn ring(n: u8, cost: impl Fn(u8, u8) -> u16, no_loopback: &[u8]) -> Vec<Arc<Lsa>> {
        let next = |i: u8| i % n + 1;
        let prev = |i: u8| if i == 1 { n } else { i - 1 };
        // The link between i and j (i < j) is 10.i.j.0/24, each end .i/.j.
        let end = |i: u8, j: u8| addr(10, i.min(j), i.max(j), i);
        (1..=n)
            .map(|i| {
                let mut links = vec![
                    p2p(router_id(next(i)), end(i, next(i)), cost(i, next(i))),
                    p2p(router_id(prev(i)), end(i, prev(i)), cost(i, prev(i))),
                ];
                if !no_loopback.contains(&i) {
                    links.push(stub(addr(10, 255, 0, i), Ipv4Addr::BROADCAST, 1));
                }
                router_lsa(router_id(i), links)
            })
            .collect()
    }

    fn with_remote_lfa(root: Ipv4Addr, lsas: &[Arc<Lsa>]) -> Vec<RouteEntry> {
        let ctx = Context {
            remote_lfa: true,
            ..Context::default()
        };
        compute_in(root, lsas, &ctx)
    }

    #[test]
    fn five_node_ring_gets_a_remote_lfa_to_the_pq_node() {
        let lsas = ring(5, |_, _| 1, &[]);
        let r = route_to(&with_remote_lfa(router_id(1), &lsas), "10.255.0.2/32");
        assert_eq!(r.next_hops, vec![addr(10, 1, 2, 2)]);
        // R5 reaches R2 back through R1: no basic LFA.
        assert_eq!(r.backup_next_hop, None);
        // P-space {R5, R4} ∩ Q-space {R3, R4}: R4, by its loopback.
        assert_eq!(r.backup_tunnel, Some(addr(10, 255, 0, 4)));
        // Off unless asked for.
        let r = route_to(&compute(router_id(1), &lsas), "10.255.0.2/32");
        assert_eq!(r.backup_tunnel, None);
    }

    #[test]
    fn a_basic_lfa_needs_no_tunnel() {
        let r = route_to(
            &with_remote_lfa(router_id(1), &triangle(1)),
            "192.168.2.0/24",
        );
        assert_eq!(r.backup_next_hop, Some(addr(10, 0, 13, 3)));
        assert_eq!(r.backup_tunnel, None);
    }

    /// R4→R3 costs 10 while R3→R4 costs 1: R4's own shortest path to R2 runs
    /// back through R1 (3 < 11), so R4 is not in R2's Q-space — which only a
    /// reverse SPF sees (from R2 forward, R4 is 2 away, R1 1).
    #[test]
    fn q_space_uses_reverse_distances() {
        let lsas = ring(5, |i, j| if (i, j) == (4, 3) { 10 } else { 1 }, &[]);
        let r = route_to(&with_remote_lfa(router_id(1), &lsas), "10.255.0.2/32");
        assert_eq!(r.backup_next_hop, None);
        assert_eq!(r.backup_tunnel, None);
    }

    #[test]
    fn a_pq_node_without_a_loopback_is_skipped() {
        let lsas = ring(5, |_, _| 1, &[4]);
        let r = route_to(&with_remote_lfa(router_id(1), &lsas), "10.255.0.2/32");
        assert_eq!(r.backup_tunnel, None);
    }

    #[test]
    fn an_ecmp_route_gets_no_tunnel() {
        let lsas = ring(4, |_, _| 1, &[]);
        let r = route_to(&with_remote_lfa(router_id(1), &lsas), "10.255.0.3/32");
        assert_eq!(r.next_hops.len(), 2);
        assert_eq!(r.backup_tunnel, None);
    }

    #[test]
    fn neighbor_whose_best_path_loops_through_root_is_not_an_alternate() {
        // 3's shortest way to 2 is back through root (1+1=2 < 10), so
        // 2 < 1 + 1 fails: it would loop.
        let routes = compute(router_id(1), &triangle(10));
        let r = route_to(&routes, "192.168.2.0/24");
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2)]);
        assert_eq!(r.backup_next_hop, None);
    }

    /// `triangle(1)` with `router`'s transit links at `MAX_LINK_METRIC`.
    fn triangle_with_stub_router(router: Ipv4Addr) -> Vec<Arc<Lsa>> {
        triangle(1)
            .into_iter()
            .map(|l| {
                if l.header.advertising_router != router {
                    return l;
                }
                let LsaBody::Router(body) = &l.body else {
                    unreachable!()
                };
                let links = body
                    .links
                    .iter()
                    .map(|rl| RouterLink {
                        metric: if rl.link_type == LINK_TYPE_STUB_NETWORK {
                            rl.metric
                        } else {
                            MAX_LINK_METRIC
                        },
                        ..rl.clone()
                    })
                    .collect();
                router_lsa(router, links)
            })
            .collect()
    }

    /// An RI LSA (`lsa_type` 10 or 11) from `id` with `caps`.
    fn router_info(id: Ipv4Addr, lsa_type: u8, caps: u32) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: LsaHeader {
                lsa_type,
                link_state_id: crate::lsa::ROUTER_INFO_LINK_STATE_ID,
                ..router_lsa(id, vec![]).header
            },
            body: LsaBody::Opaque(crate::lsa::encode_router_info(caps)),
        })
    }

    /// `lsas` with `router`'s Router-LSA flagged H (links unchanged, so only
    /// the bit is under test), plus a bit-7 RI from each router in `ri_from`.
    fn with_host_router(lsas: Vec<Arc<Lsa>>, router: Ipv4Addr, ri_from: &[u8]) -> Vec<Arc<Lsa>> {
        let mut out: Vec<Arc<Lsa>> = lsas
            .into_iter()
            .map(|l| match &l.body {
                LsaBody::Router(b) if l.header.advertising_router == router => {
                    let mut body = b.clone();
                    body.flags |= ROUTER_FLAG_H;
                    router_lsa_with(router, body)
                }
                _ => l,
            })
            .collect();
        for &n in ri_from {
            out.push(router_info(
                router_id(n),
                crate::lsa::LSA_TYPE_OPAQUE_AREA,
                RI_CAP_HOST_ROUTER,
            ));
        }
        out
    }

    fn router_lsa_with(id: Ipv4Addr, body: RouterLsaBody) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: router_lsa(id, vec![]).header,
            body: LsaBody::Router(body),
        })
    }

    /// root(1) — 3 — 2 over p2p; 2 and 3 each own a stub.
    fn chain() -> Vec<Arc<Lsa>> {
        let (r1, r2, r3) = (router_id(1), router_id(2), router_id(3));
        vec![
            router_lsa(r1, vec![p2p(r3, addr(10, 0, 13, 1), 1)]),
            router_lsa(
                r3,
                vec![
                    p2p(r1, addr(10, 0, 13, 3), 1),
                    p2p(r2, addr(10, 0, 23, 3), 1),
                    stub(addr(192, 168, 3, 0), addr(255, 255, 255, 0), 1),
                ],
            ),
            router_lsa(
                r2,
                vec![
                    p2p(r3, addr(10, 0, 23, 2), 1),
                    stub(addr(192, 168, 2, 0), addr(255, 255, 255, 0), 1),
                ],
            ),
        ]
    }

    /// #644: TOS/MT entries on links never change the TOS-0 routes.
    #[test]
    fn tos_entries_do_not_change_routes() {
        let with_tos: Vec<Arc<Lsa>> = chain()
            .into_iter()
            .map(|l| {
                let LsaBody::Router(b) = &l.body else {
                    unreachable!()
                };
                let links = b
                    .links
                    .iter()
                    .cloned()
                    .map(|mut rl| {
                        rl.tos = vec![0x10, 0, 0, 99];
                        rl
                    })
                    .collect();
                router_lsa_with(
                    l.header.advertising_router,
                    RouterLsaBody {
                        flags: b.flags,
                        links,
                    },
                )
            })
            .collect();
        let sorted = |mut v: Vec<RouteEntry>| {
            v.sort_by_key(|r| r.prefix.to_string());
            v
        };
        assert_eq!(
            sorted(compute(router_id(1), &with_tos)),
            sorted(compute(router_id(1), &chain()))
        );
    }

    #[test]
    fn host_router_is_a_leaf_only_when_every_router_supports_the_bit() {
        let has =
            |routes: &[RouteEntry], p: &str| routes.iter().any(|r| r.prefix == p.parse().unwrap());
        // RFC 8770 §4: 3 isn't transit, but its own stub is still reached.
        let lsas = with_host_router(chain(), router_id(3), &[1, 2, 3]);
        assert!(host_bit_honoured(&lsas));
        let routes = compute(router_id(1), &lsas);
        assert!(!has(&routes, "192.168.2.0/24"), "{routes:?}");
        assert_eq!(
            route_to(&routes, "192.168.3.0/24").next_hops,
            vec![addr(10, 0, 13, 3)]
        );
        // §5: 2 doesn't advertise support, so the bit is ignored in the area.
        let lsas = with_host_router(chain(), router_id(3), &[1, 3]);
        assert!(!host_bit_honoured(&lsas));
        assert!(has(&compute(router_id(1), &lsas), "192.168.2.0/24"));
        // §4: "vertex V is not the root" — 3's own SPF transits itself.
        let lsas = with_host_router(chain(), router_id(3), &[1, 2, 3]);
        assert!(has(&compute(router_id(3), &lsas), "192.168.2.0/24"));
    }

    #[test]
    fn host_router_neighbor_is_never_an_alternate() {
        let lsas = with_host_router(triangle(1), router_id(3), &[1, 2, 3]);
        let r = route_to(&compute(router_id(1), &lsas), "192.168.2.0/24");
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2)]);
        assert_eq!(r.backup_next_hop, None);
    }

    #[test]
    fn host_bit_support_counts_a_type_11_router_info() {
        let mut lsas = with_host_router(chain(), router_id(3), &[1, 3]);
        lsas.push(router_info(
            router_id(2),
            crate::lsa::LSA_TYPE_OPAQUE_AS,
            RI_CAP_HOST_ROUTER,
        ));
        assert!(host_bit_honoured(&lsas));
        assert_eq!(host_routers(&lsas), HashSet::from([router_id(3)]));
        // An RI without bit 7 isn't support.
        let mut lsas = with_host_router(chain(), router_id(3), &[1, 3]);
        lsas.push(router_info(
            router_id(2),
            crate::lsa::LSA_TYPE_OPAQUE_AREA,
            crate::lsa::RI_CAP_GR_HELPER,
        ));
        assert!(!host_bit_honoured(&lsas));
        assert!(host_routers(&lsas).is_empty());
    }

    #[test]
    fn stub_router_neighbor_is_never_an_alternate() {
        // RFC 5286 §3.5: 3's reverse cost to root is `LSInfinity`.
        let routes = compute(router_id(1), &triangle_with_stub_router(router_id(3)));
        let r = route_to(&routes, "192.168.2.0/24");
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2)]);
        assert_eq!(r.backup_next_hop, None);
    }

    #[test]
    fn stub_router_root_has_no_alternates() {
        // Root's own links are `LSInfinity`: no alternate at all.
        let routes = compute(router_id(1), &triangle_with_stub_router(router_id(1)));
        let r = route_to(&routes, "192.168.2.0/24");
        assert_eq!(r.backup_next_hop, None);
    }

    #[test]
    fn stub_router_on_a_transit_network_is_never_an_alternate() {
        // root — 2 over p2p; root and 3 on one LAN (3 is DR); 3 — 2 over
        // p2p; 2 owns a stub. 3 is a loop-free alternate until its link to
        // the LAN (its reverse cost) is `LSInfinity`.
        let (root, r2, r3) = (router_id(1), router_id(2), router_id(3));
        let dr = addr(10, 0, 9, 3);
        let lsas = |r3_cost| {
            vec![
                router_lsa(
                    root,
                    vec![
                        p2p(r2, addr(10, 0, 12, 1), 1),
                        transit(dr, addr(10, 0, 9, 1), 1),
                    ],
                ),
                router_lsa(
                    r2,
                    vec![
                        p2p(root, addr(10, 0, 12, 2), 1),
                        p2p(r3, addr(10, 0, 23, 2), 1),
                        stub(addr(192, 168, 2, 0), addr(255, 255, 255, 0), 1),
                    ],
                ),
                router_lsa(
                    r3,
                    vec![transit(dr, dr, r3_cost), p2p(r2, addr(10, 0, 23, 3), 1)],
                ),
                network_lsa(dr, addr(255, 255, 255, 0), vec![root, r3]),
            ]
        };
        let r = route_to(&compute(root, &lsas(1)), "192.168.2.0/24");
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2)]);
        assert_eq!(r.backup_next_hop, Some(dr));
        let r = route_to(&compute(root, &lsas(MAX_LINK_METRIC)), "192.168.2.0/24");
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2)]);
        assert_eq!(r.backup_next_hop, None);
    }

    #[test]
    fn stub_router_still_carries_transit_when_it_is_the_only_path() {
        // RFC 6987 §3: MaxLinkMetric is not unreachable. Root reaches 3's
        // neighbor 2 only through 3, a stub router.
        let (root, r2, r3) = (router_id(1), router_id(2), router_id(3));
        let lsas = [
            router_lsa(root, vec![p2p(r3, addr(10, 0, 13, 1), 1)]),
            router_lsa(
                r3,
                vec![
                    p2p(root, addr(10, 0, 13, 3), MAX_LINK_METRIC),
                    p2p(r2, addr(10, 0, 23, 3), MAX_LINK_METRIC),
                ],
            ),
            router_lsa(
                r2,
                vec![
                    p2p(r3, addr(10, 0, 23, 2), 1),
                    stub(addr(192, 168, 2, 0), addr(255, 255, 255, 0), 1),
                ],
            ),
        ];
        let r = route_to(&compute(root, &lsas), "192.168.2.0/24");
        assert_eq!(r.next_hops, vec![addr(10, 0, 13, 3)]);
        assert_eq!(r.metric, 1 + u32::from(MAX_LINK_METRIC) + 1);
    }

    #[test]
    fn single_neighbor_has_no_alternate() {
        let root = router_id(1);
        let w = router_id(2);
        let lsas = [
            router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1)]),
            router_lsa(
                w,
                vec![
                    p2p(root, addr(10, 0, 0, 2), 1),
                    stub(addr(192, 168, 1, 0), addr(255, 255, 255, 0), 1),
                ],
            ),
        ];
        let routes = compute(root, &lsas);
        assert_eq!(routes[0].backup_next_hop, None);
    }

    /// root(1) — 2 (cost 1) and root — 3 (cost 1), 2 — 4 (cost 1) and 3 — 4
    /// (the given cost), 4 — 5 (cost 1); 4 and 5 each own a stub.
    fn square(cost_34: u16) -> Vec<Arc<Lsa>> {
        let (r1, r2, r3, r4, r5) = (
            router_id(1),
            router_id(2),
            router_id(3),
            router_id(4),
            router_id(5),
        );
        vec![
            router_lsa(
                r1,
                vec![
                    p2p(r2, addr(10, 0, 12, 1), 1),
                    p2p(r3, addr(10, 0, 13, 1), 1),
                ],
            ),
            router_lsa(
                r2,
                vec![
                    p2p(r1, addr(10, 0, 12, 2), 1),
                    p2p(r4, addr(10, 0, 24, 2), 1),
                ],
            ),
            router_lsa(
                r3,
                vec![
                    p2p(r1, addr(10, 0, 13, 3), 1),
                    p2p(r4, addr(10, 0, 34, 3), cost_34),
                ],
            ),
            router_lsa(
                r4,
                vec![
                    p2p(r2, addr(10, 0, 24, 4), 1),
                    p2p(r3, addr(10, 0, 34, 4), cost_34),
                    p2p(r5, addr(10, 0, 45, 4), 1),
                    stub(addr(192, 168, 4, 0), addr(255, 255, 255, 0), 1),
                ],
            ),
            router_lsa(
                r5,
                vec![
                    p2p(r4, addr(10, 0, 45, 5), 1),
                    stub(addr(192, 168, 5, 0), addr(255, 255, 255, 0), 1),
                ],
            ),
        ]
    }

    #[test]
    fn equal_cost_square_keeps_both_next_hops() {
        let routes = compute(router_id(1), &square(1));
        let r = route_to(&routes, "192.168.4.0/24");
        assert_eq!(r.metric, 3);
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2), addr(10, 0, 13, 3)]);
        // Both neighbors are primaries, so neither is an alternate.
        assert_eq!(r.backup_next_hop, None);
    }

    #[test]
    fn destination_behind_ecmp_vertex_inherits_every_next_hop() {
        let routes = compute(router_id(1), &square(1));
        let r = route_to(&routes, "192.168.5.0/24");
        assert_eq!(r.metric, 4);
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2), addr(10, 0, 13, 3)]);
    }

    #[test]
    fn unequal_square_keeps_only_the_cheaper_next_hop() {
        let routes = compute(router_id(1), &square(2));
        let r = route_to(&routes, "192.168.4.0/24");
        assert_eq!(r.metric, 3);
        assert_eq!(r.next_hops, vec![addr(10, 0, 12, 2)]);
        // 3 reaches 4 in 2 < 3→root (1) + root→4 (2): loop-free.
        assert_eq!(r.backup_next_hop, Some(addr(10, 0, 13, 3)));
    }

    #[test]
    fn p2p_and_transit_network_to_same_neighbor_give_both_its_addresses() {
        // The e2e shape: root and w share a p2p link and a broadcast
        // segment, both cost 1 — w's own address on each is a next hop.
        let root = router_id(1);
        let w = router_id(2);
        let dr = addr(10, 0, 9, 2); // w is DR: the network's id is w's own address
        let lsas = [
            router_lsa(
                root,
                vec![
                    p2p(w, addr(10, 0, 0, 1), 1),
                    transit(dr, addr(10, 0, 9, 1), 1),
                ],
            ),
            router_lsa(
                w,
                vec![
                    p2p(root, addr(10, 0, 0, 2), 1),
                    transit(dr, dr, 1),
                    stub(addr(203, 0, 113, 80), addr(255, 255, 255, 255), 1),
                ],
            ),
            network_lsa(dr, addr(255, 255, 255, 0), vec![w, root]),
        ];
        let routes = compute(root, &lsas);
        let r = route_to(&routes, "203.0.113.80/32");
        assert_eq!(r.metric, 2);
        assert_eq!(r.next_hops, vec![addr(10, 0, 0, 2), dr]);
    }

    #[test]
    fn equal_metric_externals_from_two_asbrs_union_next_hops() {
        let root = router_id(1);
        let (a1, a2) = (router_id(2), router_id(3));
        let (net, mask) = (addr(192, 0, 2, 0), addr(255, 255, 255, 0));
        let routes = compute(
            root,
            &[
                router_lsa(
                    root,
                    vec![p2p(a1, addr(10, 0, 0, 1), 1), p2p(a2, addr(10, 0, 1, 1), 1)],
                ),
                router_lsa(a1, vec![p2p(root, addr(10, 0, 0, 2), 1)]),
                router_lsa(a2, vec![p2p(root, addr(10, 0, 1, 2), 1)]),
                as_external_lsa(net, mask, a1),
                as_external_lsa(net, mask, a2),
            ],
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metric, 1 + DEFAULT_EXTERNAL_METRIC);
        assert_eq!(
            routes[0].next_hops,
            vec![addr(10, 0, 0, 2), addr(10, 0, 1, 2)]
        );
    }

    /// RFC 2328 Appendix E: one ASBR/ABR names `192.0.2.128/26` by its
    /// network address, another by the host-bits form `.191`. Both are the
    /// same prefix, one route with both next hops.
    #[test]
    fn host_bit_link_state_ids_truncate_and_merge() {
        let root = router_id(1);
        let (r1, r2) = (router_id(2), router_id(3));
        let mask = addr(255, 255, 255, 192);
        let topology = || {
            vec![
                router_lsa(
                    root,
                    vec![p2p(r1, addr(10, 0, 0, 1), 1), p2p(r2, addr(10, 0, 1, 1), 1)],
                ),
                router_lsa(r1, vec![p2p(root, addr(10, 0, 0, 2), 1)]),
                router_lsa(r2, vec![p2p(root, addr(10, 0, 1, 2), 1)]),
            ]
        };
        let both = vec![addr(10, 0, 0, 2), addr(10, 0, 1, 2)];

        let mut lsas = topology();
        lsas.push(as_external_lsa(addr(192, 0, 2, 128), mask, r1));
        lsas.push(as_external_lsa(addr(192, 0, 2, 191), mask, r2));
        let routes = compute(root, &lsas);
        assert_eq!(routes.len(), 1, "{routes:?}");
        assert_eq!(routes[0].prefix, "192.0.2.128/26".parse().unwrap());
        assert_eq!(routes[0].next_hops, both);

        let mut lsas = topology();
        lsas.push(network_summary_lsa(addr(192, 0, 2, 128), mask, r1, 10));
        lsas.push(network_summary_lsa(addr(192, 0, 2, 191), mask, r2, 10));
        let routes = compute(root, &lsas);
        assert_eq!(routes.len(), 1, "{routes:?}");
        assert_eq!(routes[0].prefix, "192.0.2.128/26".parse().unwrap());
        assert_eq!(routes[0].next_hops, both);
    }

    /// A Network-LSA's ID is the DR's interface address: seen from a router
    /// not on the segment, the route is the segment's prefix.
    #[test]
    fn network_lsa_route_is_truncated_to_the_segment_prefix() {
        let root = router_id(1);
        let (w, x) = (router_id(2), router_id(3));
        let dr = addr(10, 0, 5, 1);
        let lsas = [
            router_lsa(root, vec![p2p(w, addr(10, 0, 0, 1), 1)]),
            router_lsa(w, vec![p2p(root, addr(10, 0, 0, 2), 1), transit(dr, dr, 1)]),
            router_lsa(x, vec![transit(dr, addr(10, 0, 5, 2), 1)]),
            network_lsa(dr, addr(255, 255, 255, 0), vec![w, x]),
        ];
        let routes = compute(root, &lsas);
        let r = route_to(&routes, "10.0.5.0/24");
        assert_eq!(r.next_hops, vec![addr(10, 0, 0, 2)]);
        assert!(!routes.iter().any(|r| r.prefix.addr() == dr), "{routes:?}");
    }

    #[test]
    fn nssa_translations_truncate_a_host_bit_link_state_id() {
        let (root, asbr) = (router_id(1), router_id(2));
        let lsas = [
            router_lsa(root, vec![p2p(asbr, addr(10, 0, 0, 1), 5)]),
            router_lsa(asbr, vec![p2p(root, addr(10, 0, 0, 2), 5)]),
            type7(addr(192, 0, 2, 255), asbr, true, addr(10, 0, 0, 2)),
        ];
        assert_eq!(
            nssa_translations(root, &lsas),
            vec![(
                "192.0.2.0/24".parse().unwrap(),
                DEFAULT_EXTERNAL_METRIC,
                true
            )]
        );
    }

    #[test]
    fn equal_metric_summaries_and_type4_proxies_union_next_hops() {
        let root = router_id(1);
        let (abr1, abr2, asbr) = (router_id(2), router_id(3), router_id(4));
        let mask = addr(255, 255, 255, 0);
        let routes = compute(
            root,
            &[
                router_lsa(
                    root,
                    vec![
                        p2p(abr1, addr(10, 0, 0, 1), 1),
                        p2p(abr2, addr(10, 0, 1, 1), 1),
                    ],
                ),
                router_lsa(abr1, vec![p2p(root, addr(10, 0, 0, 2), 1)]),
                router_lsa(abr2, vec![p2p(root, addr(10, 0, 1, 2), 1)]),
                network_summary_lsa(addr(192, 0, 2, 0), mask, abr1, 10),
                network_summary_lsa(addr(192, 0, 2, 0), mask, abr2, 10),
                asbr_summary_lsa(asbr, abr1, 5),
                asbr_summary_lsa(asbr, abr2, 5),
                as_external_lsa(addr(198, 51, 100, 0), mask, asbr),
            ],
        );
        let both = vec![addr(10, 0, 0, 2), addr(10, 0, 1, 2)];
        let summary = route_to(&routes, "192.0.2.0/24");
        assert_eq!(summary.metric, 11);
        assert_eq!(summary.next_hops, both);
        let external = route_to(&routes, "198.51.100.0/24");
        assert_eq!(external.metric, 1 + 5 + DEFAULT_EXTERNAL_METRIC);
        assert_eq!(external.next_hops, both);
    }

    /// RFC 2328 §3.5: covered prefixes are suppressed, an advertised range
    /// with a component is one summary at the *largest* component cost (not
    /// RFC 1583's smallest), not-advertise hides them, and a range with no
    /// component is not active.
    #[test]
    fn apply_ranges_aggregates_at_max_cost_and_hides_not_advertised() {
        let route = |p: &str, metric| RouteEntry {
            next_hops: vec![addr(10, 0, 0, 1)],
            ..RouteEntry::discard(p.parse().unwrap(), metric)
        };
        let routes = [
            route("10.1.1.0/24", 3),
            route("10.1.2.0/24", 7),
            route("10.2.1.0/24", 4),
            route("192.168.1.0/24", 9),
        ];
        let net = |s: &str| s.parse::<Ipv4Net>().unwrap();
        let ranges = [
            (net("10.1.0.0/16"), true),
            (net("10.2.0.0/16"), false),
            (net("10.3.0.0/16"), true),
        ];
        let (mut summarize, active) = apply_ranges(&routes, &ranges);
        summarize.sort();
        assert_eq!(
            summarize,
            vec![(net("10.1.0.0/16"), 7), (net("192.168.1.0/24"), 9)]
        );
        assert_eq!(active, vec![(net("10.1.0.0/16"), 7)]);
        // No ranges: every route is summarized on its own.
        assert_eq!(apply_ranges(&routes, &[]).0.len(), 4);
    }
}
