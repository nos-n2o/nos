//! RFC 5340 §4.8 SPF: pure Dijkstra over Router-LSA/Network-LSA vertices —
//! same graph algorithm/heap as `ospf::spf` (RFC 2328's §16.1/§16.2
//! counterpart), but next-hop derivation and destination-prefix collection
//! are both structurally different, since v3 restructures where addresses
//! and prefixes live on the wire. No I/O; `crate::link::LinkManager::
//! compute_routes` is the only caller, feeding it one area's `Lsdb::all()`
//! snapshot at a time.
//!
//! # Next-hop derivation (RFC 5340 §4.8.1 — the fiddly part)
//! v3's Router-LSA carries no addresses at all — only topology (Interface
//! ID / Neighbor Interface ID / Neighbor Router ID per link). A neighbor
//! `w`'s IPv6 next-hop address is instead learned from *`w`'s own* Link-LSA
//! for that specific link, keyed by `(w, w's own interface id on that
//! link)`. For a direct point-to-point edge, `w`'s interface id on the link
//! is handed to us directly as the root's own link entry's `Neighbor
//! Interface ID` field — no search needed. For a transit-network edge
//! (`Network(network_id) -> Router(w)`), there's no such shortcut: we must
//! search `w`'s *own* Router-LSA for the transit-network link entry
//! pointing back at this same network (matched by `neighbor_interface_id ==
//! network_id`) and read *that* entry's own `interface_id` field. Every
//! vertex beyond the first hop simply inherits its parent's next-hop
//! unchanged, exactly like v2.
//!
//! # Destination prefixes (structurally new, not a port)
//! v2 folds a stub prefix into the Router-LSA link list directly. v3 has
//! nowhere to put a prefix in a Router-LSA at all — destinations come
//! entirely from Intra-Area-Prefix-LSAs, each referencing either a router
//! (`LSA_TYPE_ROUTER`, that router's own stub/loopback prefixes) or a
//! transit network (`LSA_TYPE_NETWORK`, that network's own prefix). `root`'s
//! own referenced prefixes are always filtered out (directly connected,
//! already a real kernel route via interface addressing) — both when `root`
//! is the referenced router directly, and via a key-based mirrored-prefix
//! filter for a point-to-point link's shared prefix (both ends indepenently
//! advertise the identical prefix via their own router reference, mirroring
//! `ospf::spf`'s own `root_advertises_stub` filter).
//!
//! # Inter-area and external routes (RFC 5340 §4.8.3-§4.8.5)
//! Ported from `ospf::spf`: an Inter-Area-Prefix-LSA is reached through its
//! advertising ABR (its distance plus the LSA metric), an AS-External-LSA
//! through its ASBR — an intra-area Router-LSA vertex with the E-bit, else the
//! cheapest Inter-Area-Router-LSA for it — plus the LSA's own metric.
//! Routes carry a `PathClass` (§16.4 / RFC 3101 §2.5: intra, inter, type-1
//! external (E1/N1), type-2 external (E2/N2)); a better class wins whatever
//! the cost, and two type-2 externals compare the LSA's own metric first
//! (`RouteEntry::rank`, #614). The pushed metric stays distance + LSA metric.
//! `ponytail:` a Type-7 and a Type-5 of the same class tie (RFC 3101 §2.5's
//! N-over-E preference isn't applied), a forwarding address is ignored, and
//! an ABR doesn't restrict itself to the backbone's summaries (§16.2) — the
//! same ceilings `ospf::spf` documents.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::Ipv6Net;

use crate::lsa::{
    self, AsExternalLsaBody, InterAreaPrefixLsaBody, InterAreaRouterLsaBody,
    IntraAreaPrefixLsaBody, Lsa, LsaBody, NetworkLsaBody, RouterLsaBody, LINK_TYPE_POINT_TO_POINT,
    LINK_TYPE_TRANSIT_NETWORK, LINK_TYPE_VIRTUAL, LSA_TYPE_E_NETWORK, LSA_TYPE_E_ROUTER,
    LSA_TYPE_NETWORK, LSA_TYPE_ROUTER,
};

/// The metric this router originates its AS-External-LSAs with (Type-1) —
/// `ospf::spf::EXTERNAL_METRIC_CONSTANT`'s value, but here it's the LSA's own
/// metric, which receivers add (what an FRR ASBR expects too).
pub const EXTERNAL_METRIC: u32 = 20;

/// What one area's SPF needs beyond its LSDB (RFC 5340 §4.7, RFC 2328
/// §16.1/§16.2).
#[derive(Debug, Default, Clone, Copy)]
pub struct Context<'a> {
    /// The area is the backbone: type-4 (virtual) links are edges (§16.1).
    pub backbone: bool,
    /// A backbone-attached ABR's non-backbone area: its Inter-Area-Prefix-
    /// and Inter-Area-Router-LSAs are not examined (§16.2) — only §16.3's
    /// `transit_summaries` reads the former.
    pub skip_summaries: bool,
    /// The first hops in the transit area toward each virtual link's
    /// endpoint (`virtual_next_hops`): the next hops of a type-4 edge out of
    /// root.
    pub virtual_links: &'a [VirtualNextHops],
}

/// One virtual link's transit-area first hops, for `Context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualNextHops {
    pub endpoint: Ipv4Addr,
    /// `(link-local address, root's ifindex)`, as `RouteEntry::next_hops`.
    pub next_hops: Vec<(Ipv6Addr, u32)>,
}

/// One SPF vertex — a router (keyed by its router-id) or a transit network
/// (keyed by its Network-LSA's `link_state_id`, the DR's own interface id
/// on that link — see `link.rs`'s origination convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Vertex {
    Router(Ipv4Addr),
    Network(Ipv4Addr),
}

/// A vertex's derived next-hop. `Network` is a sentinel for a root-adjacent
/// transit network, mirroring `ospf::spf::NextHop`'s shape — but unlike v2,
/// both variants also carry root's own local interface id for that first
/// hop (`u32`, always root's own kernel ifindex — see `LinkConfig.
/// interface_id`'s doc comment in `reconcile.rs`): a link-local IPv6
/// next-hop is only meaningful relative to the specific local link it was
/// learned on, and Linux's netlink route install needs that outgoing
/// interface explicitly (see `RouteEntry::interface_id`'s doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum NextHop {
    Network(u32),
    Router(Ipv6Addr, u32),
}

/// `NextHop`s as sorted, deduplicated `(address, ifindex)` pairs; the
/// `Network` sentinel carries no address and is dropped.
fn hops_of(set: &[NextHop]) -> Vec<(Ipv6Addr, u32)> {
    let mut v: Vec<_> = set
        .iter()
        .filter_map(|h| match *h {
            NextHop::Router(a, i) => Some((a, i)),
            NextHop::Network(_) => None,
        })
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

impl RouteEntry {
    /// `hops` must be non-empty.
    fn new(prefix: Ipv6Net, hops: Vec<(Ipv6Addr, u32)>, metric: u32, egress: Vertex) -> Self {
        RouteEntry {
            class: PathClass::Intra,
            e2_metric: 0,
            prefix: prefix.trunc(),
            next_hop: hops[0].0,
            interface_id: hops[0].1,
            next_hops: hops,
            metric,
            backup_next_hop: None,
            backup_interface_id: None,
            egress,
        }
    }
}

impl RouteEntry {
    /// RFC 2328 §16.4: smaller wins — class first, then for a type-2
    /// external its own metric, then the total cost.
    pub fn rank(&self) -> (PathClass, u32, u32) {
        if self.class == PathClass::External2 {
            (self.class, self.e2_metric, self.metric)
        } else {
            (self.class, self.metric, 0)
        }
    }

    #[must_use]
    fn classed(mut self, class: PathClass, e2_metric: u32) -> Self {
        self.class = class;
        self.e2_metric = e2_metric;
        self
    }

    /// An ABR's discard route for one of its active advertised area ranges
    /// (RFC 5340 §4.4.3.3): no next hop, so `nos-ribd` installs a blackhole.
    pub fn discard(prefix: Ipv6Net, metric: u32) -> Self {
        RouteEntry {
            class: PathClass::Intra,
            e2_metric: 0,
            prefix,
            next_hops: Vec::new(),
            next_hop: Ipv6Addr::UNSPECIFIED,
            interface_id: 0,
            metric,
            backup_next_hop: None,
            backup_interface_id: None,
            egress: Vertex::Router(Ipv4Addr::UNSPECIFIED),
        }
    }
}

/// RFC 2328 §11 / §16.4 path types in order of preference; the NSSA N1/N2
/// classes are the type-1/type-2 external ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathClass {
    Intra,
    Inter,
    External1,
    External2,
}

/// One computed destination, ready to push to `nos-ribd`.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteEntry {
    /// Which §16.4 class the route is of.
    pub class: PathClass,
    /// A type-2 external's own LSA metric (0 otherwise), the first tiebreak
    /// within `External2`.
    pub e2_metric: u32,
    pub prefix: Ipv6Net,
    /// Every equal-cost first hop (RFC 2328 §16.1, #1135): `(link-local
    /// address, root's ifindex)`, sorted and deduplicated; never empty.
    pub next_hops: Vec<(Ipv6Addr, u32)>,
    /// `next_hops[0]`, the lowest — what single-path callers read.
    pub next_hop: Ipv6Addr,
    /// Root's own local kernel interface (ifindex) `next_hop` is reachable
    /// over — required by Linux's netlink `RTM_NEWROUTE` for a link-local
    /// IPv6 gateway (`EINVAL` without it, since the kernel can't otherwise
    /// resolve which link a link-local address belongs to). Mirrors
    /// `nos_proto::OspfRoute::interface_id`, which this is pushed into
    /// verbatim by `rib_push_client`.
    pub interface_id: u32,
    pub metric: u32,
    /// RFC 5286 loop-free alternate (a different first hop than `next_hop`
    /// that provably won't loop the packet back through us), if one exists,
    /// with its own outgoing `interface_id` — it may leave over another link.
    /// Filled in by `compute` after `collect_prefix_routes`.
    pub backup_next_hop: Option<Ipv6Addr>,
    pub backup_interface_id: Option<u32>,
    /// The vertex this prefix hangs off — what the loop-free test is
    /// evaluated against, since the prefix metric cancels out of it.
    egress: Vertex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeapEntry {
    dist: u32,
    vertex: Vertex,
}

impl Ord for HeapEntry {
    /// Nearest first; at equal distance a network pops before a router, so a
    /// router's next-hop set is complete (every 0-cost network edge into it
    /// merged) before it is popped and propagates.
    fn cmp(&self, other: &Self) -> Ordering {
        let is_net = |e: &Self| matches!(e.vertex, Vertex::Network(_));
        other
            .dist
            .cmp(&self.dist)
            .then(is_net(self).cmp(&is_net(other)))
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Every installed Link-LSA's own link-local address, keyed by
/// `(advertising_router, link_state_id)` — `link_state_id` here is that
/// link's own Interface ID, encoded via `lsa::interface_id_key`.
type LinkLocalAddresses = HashMap<(Ipv4Addr, Ipv4Addr), Ipv6Addr>;

/// One merged Router-LSA body per advertising router.
type Routers = HashMap<Ipv4Addr, RouterLsaBody>;

/// Folds the several Router-/E-Router-LSAs one router may originate
/// (fragments differ by Link State ID, RFC 5340 §A.4.3 / RFC 8362) into one
/// body: links concatenated in `(lsa_type, link_state_id)` order with exact
/// duplicates dropped, flags OR-ed, options from the lowest Link State ID
/// (E-Router-LSA wins a tie).
fn merge_router_fragments(mut parts: Vec<(u16, Ipv4Addr, &RouterLsaBody)>) -> RouterLsaBody {
    parts.sort_by_key(|&(t, id, _)| (t, u32::from(id)));
    let options = parts
        .iter()
        .min_by_key(|&&(t, id, _)| (u32::from(id), std::cmp::Reverse(t)))
        .map_or(0, |f| f.2.options);
    let mut links: Vec<lsa::RouterLsaLink> = Vec::new();
    let mut flags = 0;
    for (_, _, b) in parts {
        flags |= b.flags;
        for l in &b.links {
            if !links.contains(l) {
                links.push(*l);
            }
        }
    }
    RouterLsaBody {
        flags,
        options,
        links,
    }
}

/// Builds the lookup maps every pass needs: routers/networks by id (as
/// `ospf::spf`'s own `routers_and_networks` does), plus every installed
/// Link-LSA's own link-local address.
fn routers_networks_links(
    lsas: &[std::sync::Arc<Lsa>],
) -> (
    Routers,
    HashMap<Ipv4Addr, &NetworkLsaBody>,
    LinkLocalAddresses,
) {
    let mut fragments: HashMap<Ipv4Addr, Vec<(u16, Ipv4Addr, &RouterLsaBody)>> = HashMap::new();
    let mut networks = HashMap::new();
    let mut links = HashMap::new();
    for l in lsas {
        match &l.body {
            LsaBody::Router(r) => {
                fragments
                    .entry(l.header.advertising_router)
                    .or_default()
                    .push((l.header.lsa_type, l.header.link_state_id, r));
            }
            LsaBody::Network(n) => {
                networks.insert(l.header.link_state_id, n);
            }
            LsaBody::Link(link) => {
                links.insert(
                    (l.header.advertising_router, l.header.link_state_id),
                    link.link_local_address,
                );
            }
            LsaBody::IntraAreaPrefix(_)
            | LsaBody::Grace(_)
            | LsaBody::InterAreaPrefix(_)
            | LsaBody::InterAreaRouter(_)
            | LsaBody::AsExternal(_)
            | LsaBody::Opaque(_) => {}
        }
    }
    let routers = fragments
        .into_iter()
        .map(|(id, f)| (id, merge_router_fragments(f)))
        .collect();
    (routers, networks, links)
}

/// RFC 2328 §16: a `MaxAge` LSA is being flushed, never a vertex or prefix.
fn live_lsas(lsas: &[std::sync::Arc<Lsa>]) -> Vec<std::sync::Arc<Lsa>> {
    lsas.iter()
        .filter(|l| l.header.age < crate::lsa::MAX_AGE)
        .cloned()
        .collect()
}

/// Every LSA of one body kind, with its advertising router.
fn bodies<'a, T>(
    lsas: &'a [std::sync::Arc<Lsa>],
    pick: impl Fn(&'a LsaBody) -> Option<&'a T>,
) -> Vec<(Ipv4Addr, &'a T)> {
    lsas.iter()
        .filter_map(|l| pick(&l.body).map(|b| (l.header.advertising_router, b)))
        .collect()
}

/// One area's intra-area view, for an ABR to summarize into its other areas
/// (`link::LinkManager::originate_inter_area_lsas`): every prefix of every
/// reachable Intra-Area-Prefix-LSA — root's own included, unlike `compute`,
/// since an ABR summarizes its own loopback too — and every ASBR reachable in
/// the area. Never an inter-area or external route: only the backbone's
/// inter-area routes are passed on (`backbone_view`, RFC 2328 §12.4.3), and a
/// non-backbone area's only to the backbone, which keeps two areas from
/// looping a prefix between them.
pub struct IntraAreaView {
    /// `(prefix, cost from root)`, one per prefix (the cheapest).
    pub prefixes: Vec<(Ipv6Net, u32)>,
    /// `(router id, cost from root, its Router-LSA options)` of every
    /// router other than root whose Router-LSA has the E-bit.
    pub asbrs: Vec<(Ipv4Addr, u32, u32)>,
}

pub fn intra_area_routes(
    root: Ipv4Addr,
    lsas: &[std::sync::Arc<Lsa>],
    ctx: &Context,
) -> IntraAreaView {
    let live = live_lsas(lsas);
    let (routers, networks, _) = routers_networks_links(&live);
    // Distance only: summarizing needs no next hop.
    let (dist, _) = run_dijkstra(root, &routers, &networks, None, ctx);
    let mut prefixes: HashMap<Ipv6Net, u32> = HashMap::new();
    for (_, body) in bodies(&live, |b| match b {
        LsaBody::IntraAreaPrefix(p) => Some(p),
        _ => None,
    }) {
        let vertex = match body.referenced_ls_type {
            LSA_TYPE_ROUTER | LSA_TYPE_E_ROUTER => {
                Vertex::Router(body.referenced_advertising_router)
            }
            LSA_TYPE_NETWORK | LSA_TYPE_E_NETWORK => Vertex::Network(body.referenced_link_state_id),
            _ => continue,
        };
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        for entry in body
            .prefixes
            .iter()
            .filter(|e| e.options & lsa::PREFIX_OPT_NU == 0)
        {
            let cost = d.saturating_add(u32::from(entry.metric));
            prefixes
                .entry(entry.prefix.trunc())
                .and_modify(|c| *c = (*c).min(cost))
                .or_insert(cost);
        }
    }
    let asbrs = routers
        .iter()
        .filter(|&(&id, r)| id != root && r.flags & lsa::ROUTER_FLAG_E != 0)
        .filter_map(|(&id, r)| dist.get(&Vertex::Router(id)).map(|&d| (id, d, r.options)))
        .collect();
    IntraAreaView {
        prefixes: prefixes.into_iter().collect(),
        asbrs,
    }
}

/// RFC 5340 §4.7: a virtual link's far end, as seen in its transit area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualEndpoint {
    /// The endpoint's intra-area distance: the virtual link's cost.
    pub cost: u32,
    /// The endpoint's global address in the transit area: where the virtual
    /// link's packets go.
    pub address: Ipv6Addr,
}

/// Whether `a` can serve as a virtual link endpoint address (RFC 5340
/// §4.4.3.9): a global unicast address, never link-local, loopback or
/// multicast.
pub fn is_virtual_address(a: Ipv6Addr) -> bool {
    !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || a.is_unicast_link_local())
}

/// RFC 5340 §4.7 for one virtual link: `endpoint`'s intra-area distance from
/// `root` over the transit area's `lsas`, and its address, or `None` while it
/// has no path or advertises none (the link is down). The address is the
/// lowest `/128` prefix with the LA-bit in the endpoint's own router-referenced
/// Intra-Area-Prefix-LSAs (§4.4.3.9) that `is_virtual_address`.
pub fn virtual_link_endpoint(
    root: Ipv4Addr,
    lsas: &[std::sync::Arc<Lsa>],
    endpoint: Ipv4Addr,
) -> Option<VirtualEndpoint> {
    if endpoint == root {
        return None;
    }
    let live = live_lsas(lsas);
    let (routers, networks, _) = routers_networks_links(&live);
    let (dist, _) = run_dijkstra(root, &routers, &networks, None, &Context::default());
    let cost = *dist.get(&Vertex::Router(endpoint))?;
    let address = bodies(&live, |b| match b {
        LsaBody::IntraAreaPrefix(p) => Some(p),
        _ => None,
    })
    .into_iter()
    .filter(|&(adv, p)| {
        adv == endpoint
            && p.referenced_advertising_router == endpoint
            && matches!(p.referenced_ls_type, LSA_TYPE_ROUTER | LSA_TYPE_E_ROUTER)
    })
    .flat_map(|(_, p)| p.prefixes.iter())
    .filter(|e| {
        e.prefix.prefix_len() == 128
            && e.options & lsa::PREFIX_OPT_LA != 0
            && e.options & lsa::PREFIX_OPT_NU == 0
            && is_virtual_address(e.prefix.addr())
    })
    .map(|e| e.prefix.addr())
    .min()?;
    Some(VirtualEndpoint { cost, address })
}

/// RFC 2328 §16.1 / RFC 5340 §4.7: the first hops from `root` toward a
/// virtual link's `endpoint` over its transit area's `lsas` (Link-LSAs
/// included), or `None` while there is none.
pub fn virtual_next_hops(
    root: Ipv4Addr,
    lsas: &[std::sync::Arc<Lsa>],
    endpoint: Ipv4Addr,
) -> Option<VirtualNextHops> {
    let live = live_lsas(lsas);
    let (routers, networks, links) = routers_networks_links(&live);
    let (_, next_hop) = run_dijkstra(root, &routers, &networks, Some(&links), &Context::default());
    let next_hops = hops_of(next_hop.get(&Vertex::Router(endpoint))?);
    (!next_hops.is_empty()).then_some(VirtualNextHops {
        endpoint,
        next_hops,
    })
}

/// RFC 2328 §16.3 step 5 for one backbone inter-area route `existing` and one
/// transit candidate (`transit_summaries`): a strictly cheaper candidate
/// replaces its cost and next hops, an equal one adds its next hops. Any
/// other class is never touched.
pub fn apply_transit(existing: &mut RouteEntry, candidate: RouteEntry) {
    if existing.class != PathClass::Inter {
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
            existing.backup_interface_id = None;
        }
        Ordering::Equal => {
            existing.next_hops.extend(candidate.next_hops);
            existing.next_hops.sort_unstable();
            existing.next_hops.dedup();
        }
        Ordering::Greater => return,
    }
    existing.next_hop = existing.next_hops[0].0;
    existing.interface_id = existing.next_hops[0].1;
}

/// RFC 2328 §16.3: when `lsas`' area is transit-capable (a reachable
/// Router-LSA with the V bit, §16.1), every Inter-Area-Prefix-LSA from another
/// ABR reachable there, as a candidate for `apply_transit` — never a route by
/// itself. `ponytail:` Inter-Area-Router-LSAs are not examined, so an ASBR's
/// backbone distance is not shortened through a transit area.
pub fn transit_summaries(root: Ipv4Addr, lsas: &[std::sync::Arc<Lsa>]) -> Vec<RouteEntry> {
    let live = live_lsas(lsas);
    let (routers, networks, links) = routers_networks_links(&live);
    let (dist, next_hop) =
        run_dijkstra(root, &routers, &networks, Some(&links), &Context::default());
    let transit = routers.iter().any(|(id, r)| {
        r.flags & lsa::ROUTER_FLAG_V != 0 && dist.contains_key(&Vertex::Router(*id))
    });
    if !transit {
        return Vec::new();
    }
    let graph = Reach {
        root,
        dist: &dist,
        next_hop: &next_hop,
    };
    let mut out = HashMap::new();
    for (abr, p) in bodies(&live, |b| match b {
        LsaBody::InterAreaPrefix(p) => Some(p),
        _ => None,
    }) {
        collect_inter_area_route(&graph, abr, p, &mut out);
    }
    out.into_values().collect()
}

/// The backbone as RFC 2328 §12.4.3 re-summarizes it into non-backbone areas:
/// what `intra_area_routes` shows plus what only Inter-Area-Prefix/Router-LSAs
/// from other ABRs reveal (#610).
pub struct BackboneView {
    pub intra: IntraAreaView,
    /// Inter-area prefixes with no intra-area route: `(prefix, cost)`.
    pub inter_prefixes: Vec<(Ipv6Net, u32)>,
    /// ASBRs reachable only through an Inter-Area-Router-LSA.
    pub inter_asbrs: Vec<(Ipv4Addr, u32, u32)>,
}

pub fn backbone_view(root: Ipv4Addr, lsas: &[std::sync::Arc<Lsa>], ctx: &Context) -> BackboneView {
    let intra = intra_area_routes(root, lsas, ctx);
    let live = live_lsas(lsas);
    let (routers, networks, _) = routers_networks_links(&live);
    let (dist, _) = run_dijkstra(root, &routers, &networks, None, ctx);
    let via = |abr: Ipv4Addr, metric: u32| {
        (abr != root && metric < LS_INFINITY)
            .then(|| {
                dist.get(&Vertex::Router(abr))
                    .map(|d| d.saturating_add(metric))
            })
            .flatten()
    };
    let own: HashSet<Ipv6Net> = intra.prefixes.iter().map(|(p, _)| *p).collect();
    let mut prefixes: HashMap<Ipv6Net, u32> = HashMap::new();
    for (abr, p) in bodies(&live, |b| match b {
        LsaBody::InterAreaPrefix(p) => Some(p),
        _ => None,
    }) {
        let prefix = p.prefix.trunc();
        if let Some(cost) = via(abr, p.metric).filter(|_| !own.contains(&prefix)) {
            let e = prefixes.entry(prefix).or_insert(cost);
            *e = (*e).min(cost);
        }
    }
    let known: HashSet<Ipv4Addr> = intra.asbrs.iter().map(|&(id, _, _)| id).collect();
    let mut asbrs: HashMap<Ipv4Addr, (u32, u32)> = HashMap::new();
    for (abr, r) in bodies(&live, |b| match b {
        LsaBody::InterAreaRouter(r) => Some(r),
        _ => None,
    }) {
        let id = r.destination_router_id;
        if id == root || known.contains(&id) {
            continue;
        }
        if let Some(cost) = via(abr, r.metric) {
            let e = asbrs.entry(id).or_insert((cost, r.options));
            if cost < e.0 {
                *e = (cost, r.options);
            }
        }
    }
    BackboneView {
        intra,
        inter_prefixes: prefixes.into_iter().collect(),
        inter_asbrs: asbrs.into_iter().map(|(id, (c, o))| (id, c, o)).collect(),
    }
}

/// Runs RFC 5340 §4.8 SPF from `root` over `lsas` (one area's worth),
/// returning every non-directly-connected destination reachable via
/// Intra-Area-Prefix-LSAs.
pub fn compute(root: Ipv4Addr, lsas: &[std::sync::Arc<Lsa>]) -> Vec<RouteEntry> {
    compute_in(root, lsas, &Context::default())
}

/// `compute` with the area's `Context`: type-4 edges in the backbone, and
/// (RFC 2328 §16.2, RFC 5340 §4.8.3) no Inter-Area-Prefix- or Inter-Area-
/// Router-LSA examined in a backbone-attached ABR's non-backbone area.
pub fn compute_in(root: Ipv4Addr, lsas: &[std::sync::Arc<Lsa>], ctx: &Context) -> Vec<RouteEntry> {
    let skip_summaries = ctx.skip_summaries;
    let live = live_lsas(lsas);
    let lsas = live.as_slice();
    let (routers, networks, links) = routers_networks_links(lsas);
    let prefix_lsas: Vec<&IntraAreaPrefixLsaBody> = bodies(lsas, |b| match b {
        LsaBody::IntraAreaPrefix(p) => Some(p),
        _ => None,
    })
    .into_iter()
    .map(|(_, b)| b)
    .collect();

    let (dist, next_hop) = run_dijkstra(root, &routers, &networks, Some(&links), ctx);
    let mut out: HashMap<(Ipv6Addr, u8), RouteEntry> = HashMap::new();
    collect_prefix_routes(root, &routers, &prefix_lsas, &dist, &next_hop, &mut out);
    let graph = Reach {
        root,
        dist: &dist,
        next_hop: &next_hop,
    };
    let inter_area_routers = bodies(lsas, |b| match b {
        LsaBody::InterAreaRouter(r) if !skip_summaries => Some(r),
        _ => None,
    });
    for (abr, p) in bodies(lsas, |b| match b {
        LsaBody::InterAreaPrefix(p) if !skip_summaries => Some(p),
        _ => None,
    }) {
        collect_inter_area_route(&graph, abr, p, &mut out);
    }
    for (asbr, e) in bodies(lsas, |b| match b {
        LsaBody::AsExternal(e) => Some(e),
        _ => None,
    }) {
        collect_external_route(&graph, &routers, &inter_area_routers, asbr, e, &mut out);
    }

    let alternates = alternates(root, &routers, &networks, &links);
    for route in out.values_mut() {
        if let Some(a) = pick_backup(route, &alternates, &dist) {
            route.backup_next_hop = Some(a.addr);
            route.backup_interface_id = Some(a.interface_id);
        }
    }
    out.into_values().collect()
}

/// RFC 3101 §3.1 translator election, for `root` as one ABR of an NSSA whose
/// LSDB is `lsas`: `root` translates unless `always` is off and another ABR
/// (B-bit Router-LSA) reachable in the area has the Nt-bit or a higher
/// router ID. `ponytail:` no `TranslatorStabilityInterval` — a translator
/// that loses the election flushes its AS-External-LSAs at once.
pub fn nssa_translator(root: Ipv4Addr, lsas: &[std::sync::Arc<Lsa>], always: bool) -> bool {
    if always {
        return true;
    }
    let live = live_lsas(lsas);
    let (routers, networks, _) = routers_networks_links(&live);
    let (dist, _) = run_dijkstra(root, &routers, &networks, None, &Context::default());
    !routers.iter().any(|(&id, r)| {
        id != root
            && r.flags & lsa::ROUTER_FLAG_B != 0
            && (r.flags & lsa::ROUTER_FLAG_NT != 0 || id > root)
            && dist.contains_key(&Vertex::Router(id))
    })
}

/// RFC 3101 §3.2: what an elected translator turns into AS-External-LSAs
/// from this NSSA's LSDB — every live NSSA-LSA with the P-bit and a
/// forwarding address, from an ASBR other than `root` reachable in the area
/// (P-bit cleared in the copy). Ascending by advertising router, so a caller
/// inserting into a map keeps the highest router ID's for one prefix (§3.2's
/// tiebreak, short of comparing metrics).
pub fn nssa_translations(
    root: Ipv4Addr,
    lsas: &[std::sync::Arc<Lsa>],
) -> Vec<(Ipv6Net, AsExternalLsaBody)> {
    let live = live_lsas(lsas);
    let (routers, networks, _) = routers_networks_links(&live);
    let (dist, _) = run_dijkstra(root, &routers, &networks, None, &Context::default());
    let mut out: Vec<(Ipv4Addr, Ipv6Net, AsExternalLsaBody)> = live
        .iter()
        .filter(|l| {
            l.header.lsa_type == lsa::LSA_TYPE_NSSA
                && l.header.advertising_router != root
                && dist.contains_key(&Vertex::Router(l.header.advertising_router))
        })
        .filter_map(|l| match &l.body {
            LsaBody::AsExternal(e)
                if e.prefix_options & lsa::PREFIX_OPT_P != 0
                    && e.prefix_options & lsa::PREFIX_OPT_NU == 0
                    && e.forwarding_address.is_some()
                    && e.metric < LS_INFINITY =>
            {
                Some((
                    l.header.advertising_router,
                    e.prefix.trunc(),
                    AsExternalLsaBody {
                        prefix_options: e.prefix_options & !lsa::PREFIX_OPT_P,
                        ..*e
                    },
                ))
            }
            _ => None,
        })
        .collect();
    out.sort_by_key(|(adv, ..)| *adv);
    out.into_iter().map(|(_, p, b)| (p, b)).collect()
}

/// RFC 6987 `MaxLinkMetric` (`link.rs` advertises a stub router with it).
const MAX_LINK_METRIC: u16 = 0xFFFF;

/// One candidate first hop for a loop-free alternate: a router adjacent to
/// root, reached at its link-local `addr` over root's `interface_id`, with
/// the shortest-path distances *from that router* to every vertex.
struct Alternate {
    addr: Ipv6Addr,
    interface_id: u32,
    /// Root's cost of the link to it.
    link_cost: u32,
    /// Its shortest distance back to root.
    to_root: u32,
    dist_from: HashMap<Vertex, u32>,
}

/// RFC 5286 basic loop-free alternates: every root-adjacent router (p2p
/// neighbor, or another router on a transit network root sits on), each with
/// its own distance-only Dijkstra over the same LSDB.
///
/// `ponytail:` one full Dijkstra per neighbor per area on every SPF run, link
/// protection only (RFC 5286 §3.1's inequality) — same ceiling as
/// `ospf::spf::alternates`.
fn alternates(
    root: Ipv4Addr,
    routers: &Routers,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
    links: &LinkLocalAddresses,
) -> Vec<Alternate> {
    let Some(root_lsa) = routers.get(&root) else {
        return Vec::new();
    };
    // (neighbor router-id, its link-local address, root's ifindex, root's cost)
    let mut candidates: Vec<(Ipv4Addr, Ipv6Addr, u32, u32)> = Vec::new();
    // RFC 5286 §3.5: never along a link whose cost or reverse cost (the
    // neighbor's own link back to root, or to the network) is MaxLinkMetric,
    // an RFC 6987 stub router on either end.
    let usable = |b: &crate::lsa::RouterLsaLink| b.metric != MAX_LINK_METRIC;
    for l in root_lsa.links.iter().filter(|l| usable(l)) {
        let cost = u32::from(l.metric);
        match l.link_type {
            LINK_TYPE_POINT_TO_POINT => {
                let w = l.neighbor_router_id;
                let back_ok = routers.get(&w).is_some_and(|b| {
                    b.links.iter().any(|bl| {
                        bl.link_type == LINK_TYPE_POINT_TO_POINT
                            && bl.neighbor_router_id == root
                            && usable(bl)
                    })
                });
                if !back_ok {
                    continue;
                }
                if let Some((addr, ifid)) = p2p_next_hop(routers, links, root, w) {
                    candidates.push((w, addr, ifid, cost));
                }
            }
            LINK_TYPE_TRANSIT_NETWORK => {
                let network_id = lsa::interface_id_key(l.neighbor_interface_id);
                let Some(net) = networks.get(&network_id) else {
                    continue;
                };
                for &r in net.attached_routers.iter().filter(|&&r| r != root) {
                    let back_ok = routers.get(&r).is_some_and(|b| {
                        b.links.iter().any(|bl| {
                            bl.link_type == LINK_TYPE_TRANSIT_NETWORK
                                && lsa::interface_id_key(bl.neighbor_interface_id) == network_id
                                && usable(bl)
                        })
                    });
                    if !back_ok {
                        continue;
                    }
                    if let Some(addr) = network_next_hop(routers, links, network_id, r) {
                        candidates.push((r, addr, l.interface_id, cost));
                    }
                }
            }
            _ => {}
        }
    }
    candidates
        .into_iter()
        .filter_map(|(id, addr, interface_id, link_cost)| {
            let dist_from = run_dijkstra(id, routers, networks, None, &Context::default()).0;
            let to_root = *dist_from.get(&Vertex::Router(root))?;
            Some(Alternate {
                addr,
                interface_id,
                link_cost,
                to_root,
                dist_from,
            })
        })
        .collect()
}

/// The best alternate for `route`: among candidates whose address differs
/// from the primary next hop and that satisfy RFC 5286 §3.1's loop-free
/// inequality `dist(N, E) < dist(N, root) + dist(root, E)` for the route's
/// egress vertex `E`, the one with the lowest total cost (ties: lowest
/// address, for determinism).
fn pick_backup<'a>(
    route: &RouteEntry,
    alternates: &'a [Alternate],
    dist: &HashMap<Vertex, u32>,
) -> Option<&'a Alternate> {
    let root_to_egress = *dist.get(&route.egress)?;
    alternates
        .iter()
        .filter(|a| route.next_hops.iter().all(|&(addr, _)| addr != a.addr))
        .filter_map(|a| {
            let n_to_egress = *a.dist_from.get(&route.egress)?;
            (n_to_egress < a.to_root.saturating_add(root_to_egress)).then_some((
                a.link_cost.saturating_add(n_to_egress),
                a.addr,
                a,
            ))
        })
        .min_by_key(|&(cost, addr, _)| (cost, addr))
        .map(|(_, _, a)| a)
}

fn run_dijkstra(
    root: Ipv4Addr,
    routers: &Routers,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
    links: Option<&LinkLocalAddresses>,
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

        for (next_vertex, edge_cost, virtual_link) in
            neighbors(vertex, routers, networks, ctx.backbone)
        {
            if visited.contains(&next_vertex) {
                continue;
            }
            // RFC 5340 §4.8.1 / RFC 2328 §16.1 step 2(b): the far side must
            // link back; also covers the distance-only (LFA) runs.
            if !back_link(vertex, next_vertex, routers, networks, virtual_link) {
                continue;
            }
            let candidate = d.saturating_add(edge_cost);
            let current = *dist.get(&next_vertex).unwrap_or(&u32::MAX);
            if candidate > current {
                continue;
            }
            // `links: None` is a distance-only run (LFA neighbors), which
            // has no use for next hops and must not drop vertices whose
            // derivation fails from a non-root point of view.
            let derived = match links {
                Some(links) => {
                    // RFC 2328 §16.1: a virtual link out of root goes through
                    // the transit area, so its next hops are that area's.
                    let nh = match next_vertex {
                        Vertex::Router(end) if virtual_link && vertex == root_vertex => {
                            let mut v: Vec<NextHop> = ctx
                                .virtual_links
                                .iter()
                                .filter(|v| v.endpoint == end)
                                .flat_map(|v| v.next_hops.iter())
                                .map(|&(a, i)| NextHop::Router(a, i))
                                .collect();
                            v.sort_unstable();
                            v.dedup();
                            v
                        }
                        _ => derive_next_hops(vertex, next_vertex, root, routers, links, &next_hop),
                    };
                    if nh.is_empty() {
                        continue;
                    }
                    Some(nh)
                }
                None => None,
            };
            if candidate < current {
                if let Some(nh) = derived {
                    next_hop.insert(next_vertex, nh);
                }
                dist.insert(next_vertex, candidate);
                heap.push(HeapEntry {
                    dist: candidate,
                    vertex: next_vertex,
                });
            } else if let Some(nh) = derived {
                // Equal cost (RFC 2328 §16.1): union the first hops.
                let set = next_hop.entry(next_vertex).or_default();
                set.extend(nh);
                set.sort_unstable();
                set.dedup();
            }
        }
    }

    (dist, next_hop)
}

/// Every graph edge out of `vertex`, flagged when it is a virtual link (a
/// type-4 link, an edge in the backbone only). A transit-network
/// `RouterLsaLink`'s own `neighbor_interface_id` is the network's vertex key
/// directly — see the module doc comment.
fn neighbors(
    vertex: Vertex,
    routers: &Routers,
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
                    LINK_TYPE_POINT_TO_POINT => Some((
                        Vertex::Router(l.neighbor_router_id),
                        u32::from(l.metric),
                        false,
                    )),
                    LINK_TYPE_VIRTUAL if backbone => Some((
                        Vertex::Router(l.neighbor_router_id),
                        u32::from(l.metric),
                        true,
                    )),
                    LINK_TYPE_TRANSIT_NETWORK => Some((
                        Vertex::Network(lsa::interface_id_key(l.neighbor_interface_id)),
                        u32::from(l.metric),
                        false,
                    )),
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

/// Does `w` have a link back to `v`? Router to router needs a p2p link
/// back, router to network needs the Network-LSA to list the router,
/// network to router needs a transit link to the network. A virtual edge
/// needs the reciprocal type-4 link (#959), a p2p one a p2p link.
fn back_link(
    v: Vertex,
    w: Vertex,
    routers: &Routers,
    networks: &HashMap<Ipv4Addr, &NetworkLsaBody>,
    virtual_link: bool,
) -> bool {
    let kind = if virtual_link {
        LINK_TYPE_VIRTUAL
    } else {
        LINK_TYPE_POINT_TO_POINT
    };
    match (v, w) {
        (Vertex::Router(v), Vertex::Router(w)) => routers.get(&w).is_some_and(|b| {
            b.links
                .iter()
                .any(|l| l.link_type == kind && l.neighbor_router_id == v)
        }),
        (Vertex::Router(v), Vertex::Network(n)) => networks
            .get(&n)
            .is_some_and(|net| net.attached_routers.contains(&v)),
        (Vertex::Network(n), Vertex::Router(w)) => routers.get(&w).is_some_and(|b| {
            b.links.iter().any(|l| {
                l.link_type == LINK_TYPE_TRANSIT_NETWORK
                    && lsa::interface_id_key(l.neighbor_interface_id) == n
            })
        }),
        (Vertex::Network(_), Vertex::Network(_)) => false,
    }
}

/// The first hops a path to `child` through `parent` leaves root over: one
/// for a root-adjacent child, else `parent`'s own set carried on (a transit
/// network's sentinel resolved to the child router's address). Empty when
/// none can be derived.
fn derive_next_hops(
    parent: Vertex,
    child: Vertex,
    root: Ipv4Addr,
    routers: &Routers,
    links: &LinkLocalAddresses,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
) -> Vec<NextHop> {
    if parent == Vertex::Router(root) {
        return match child {
            Vertex::Router(w) => p2p_next_hop(routers, links, root, w)
                .map(|(addr, interface_id)| NextHop::Router(addr, interface_id)),
            Vertex::Network(network_id) => {
                root_network_interface_id(root, routers, network_id).map(NextHop::Network)
            }
        }
        .into_iter()
        .collect();
    }
    let Some(parent_set) = next_hop.get(&parent) else {
        return Vec::new();
    };
    let mut out: Vec<NextHop> = parent_set
        .iter()
        .filter_map(|&h| match h {
            NextHop::Router(..) => Some(h),
            NextHop::Network(interface_id) => match (parent, child) {
                (Vertex::Network(network_id), Vertex::Router(w)) => {
                    network_next_hop(routers, links, network_id, w)
                        .map(|addr| NextHop::Router(addr, interface_id))
                }
                _ => None,
            },
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Direct point-to-point edge: `parent_router`'s own link entry to
/// `child_router` carries the child's interface id on that link directly
/// (`neighbor_interface_id`) — no search of the child's own LSA needed.
/// Also returns `parent_router`'s own `interface_id` on that same link
/// entry — meaningful only when `parent_router == root` (see
/// `RouteEntry::interface_id`'s doc comment), but harmless to return
/// unconditionally since every non-first-hop call site only reads the
/// address half.
fn p2p_next_hop(
    routers: &Routers,
    links: &LinkLocalAddresses,
    parent_router: Ipv4Addr,
    child_router: Ipv4Addr,
) -> Option<(Ipv6Addr, u32)> {
    // Parallel links to one neighbor: the cheapest, the edge Dijkstra took
    // (#618), not whichever the LSA happens to list first.
    let l = routers
        .get(&parent_router)?
        .links
        .iter()
        .filter(|l| l.link_type == LINK_TYPE_POINT_TO_POINT && l.neighbor_router_id == child_router)
        .min_by_key(|l| l.metric)?;
    let addr = links
        .get(&(child_router, lsa::interface_id_key(l.neighbor_interface_id)))
        .copied()?;
    Some((addr, l.interface_id))
}

/// Root's own local interface id for its transit-network link to
/// `network_id`, if root is attached to it at all — mirrors
/// `root_attached_to_network`'s own lookup, which now delegates here.
fn root_network_interface_id(
    root: Ipv4Addr,
    routers: &Routers,
    network_id: Ipv4Addr,
) -> Option<u32> {
    let network_key = lsa::key_to_interface_id(network_id);
    routers.get(&root)?.links.iter().find_map(|l| {
        (l.link_type == LINK_TYPE_TRANSIT_NETWORK && l.neighbor_interface_id == network_key)
            .then_some(l.interface_id)
    })
}

/// Transit-network edge: unlike the point-to-point case, `network_id` alone
/// doesn't give us `child_router`'s own interface id on the link — we have
/// to search `child_router`'s *own* Router-LSA for its transit-network
/// entry pointing back at this network (matched by `neighbor_interface_id
/// == network_id`) and read that entry's own `interface_id`.
fn network_next_hop(
    routers: &Routers,
    links: &LinkLocalAddresses,
    network_id: Ipv4Addr,
    child_router: Ipv4Addr,
) -> Option<Ipv6Addr> {
    let network_key = lsa::key_to_interface_id(network_id);
    let own_interface_id = routers.get(&child_router)?.links.iter().find_map(|l| {
        (l.link_type == LINK_TYPE_TRANSIT_NETWORK && l.neighbor_interface_id == network_key)
            .then_some(l.interface_id)
    })?;
    links
        .get(&(child_router, lsa::interface_id_key(own_interface_id)))
        .copied()
}

fn root_attached_to_network(root: Ipv4Addr, routers: &Routers, network_id: Ipv4Addr) -> bool {
    root_network_interface_id(root, routers, network_id).is_some()
}

/// RFC 5340 §4.8: every Intra-Area-Prefix-LSA's prefixes, attached either to
/// a router or a transit network. `root`'s own referenced prefixes are
/// filtered twice over: directly (the referenced vertex is `root` itself)
/// and by key (a point-to-point link's shared prefix, independently
/// advertised by both ends via their own router reference — the mirrored
/// case `ospf::spf::root_advertises_stub` also guards).
fn collect_prefix_routes(
    root: Ipv4Addr,
    routers: &Routers,
    prefix_lsas: &[&IntraAreaPrefixLsaBody],
    dist: &HashMap<Vertex, u32>,
    next_hop: &HashMap<Vertex, Vec<NextHop>>,
    out: &mut HashMap<(Ipv6Addr, u8), RouteEntry>,
) {
    let root_prefixes: HashSet<(Ipv6Addr, u8)> = prefix_lsas
        .iter()
        .filter(|p| {
            matches!(p.referenced_ls_type, LSA_TYPE_ROUTER | LSA_TYPE_E_ROUTER)
                && p.referenced_advertising_router == root
        })
        .flat_map(|p| p.prefixes.iter())
        .map(|entry| prefix_key(entry.prefix))
        .collect();

    for body in prefix_lsas {
        let vertex = match body.referenced_ls_type {
            LSA_TYPE_ROUTER | LSA_TYPE_E_ROUTER => {
                Vertex::Router(body.referenced_advertising_router)
            }
            LSA_TYPE_NETWORK | LSA_TYPE_E_NETWORK => Vertex::Network(body.referenced_link_state_id),
            _ => continue,
        };
        if vertex == Vertex::Router(root) {
            continue;
        }
        if let Vertex::Network(network_id) = vertex
            && root_attached_to_network(root, routers, network_id)
        {
            continue;
        }
        let Some(&d) = dist.get(&vertex) else {
            continue;
        };
        let hops = next_hop.get(&vertex).map_or_default(|s| hops_of(s));
        if hops.is_empty() {
            continue;
        }
        // RFC 5340 §4.8.1: an NU-bit prefix is not used for routing.
        for entry in body
            .prefixes
            .iter()
            .filter(|e| e.options & lsa::PREFIX_OPT_NU == 0)
        {
            let key = prefix_key(entry.prefix);
            if root_prefixes.contains(&key) {
                continue;
            }
            insert_best(
                out,
                key,
                RouteEntry::new(
                    entry.prefix,
                    hops.clone(),
                    d.saturating_add(u32::from(entry.metric)),
                    vertex,
                ),
            );
        }
    }
}

/// What the inter-area/external passes read from root's Dijkstra.
struct Reach<'a> {
    root: Ipv4Addr,
    dist: &'a HashMap<Vertex, u32>,
    next_hop: &'a HashMap<Vertex, Vec<NextHop>>,
}

/// A reachable router's distance and every first hop.
type Via = (u32, Vec<(Ipv6Addr, u32)>);

impl Reach<'_> {
    /// `router`'s distance and first hops, if it's a reachable router other
    /// than root.
    fn router(&self, router: Ipv4Addr) -> Option<Via> {
        if router == self.root {
            return None;
        }
        let v = Vertex::Router(router);
        let hops = hops_of(self.next_hop.get(&v)?);
        (!hops.is_empty()).then_some((*self.dist.get(&v)?, hops))
    }
}

fn route_via(prefix: Ipv6Net, (d, hops): Via, metric: u32, egress: Ipv4Addr) -> RouteEntry {
    RouteEntry::new(
        prefix,
        hops,
        d.saturating_add(metric),
        Vertex::Router(egress),
    )
}

/// RFC 5340 §4.8.3 (RFC 2328 §16.2): an Inter-Area-Prefix-LSA's prefix via
/// its advertising ABR. Our own (`abr == root`) is skipped by `Reach::router`.
/// RFC 2328 §12.4.3 `LSInfinity`: a metric of this value means unreachable.
const LS_INFINITY: u32 = 0x00FF_FFFF;

fn collect_inter_area_route(
    graph: &Reach,
    abr: Ipv4Addr,
    p: &InterAreaPrefixLsaBody,
    out: &mut HashMap<(Ipv6Addr, u8), RouteEntry>,
) {
    if p.metric >= LS_INFINITY {
        return;
    }
    if let Some(via) = graph.router(abr) {
        let route = route_via(p.prefix, via, p.metric, abr).classed(PathClass::Inter, 0);
        insert_best(out, prefix_key(p.prefix), route);
    }
}

/// RFC 5340 §4.8.5 (RFC 2328 §16.4): the ASBR's distance — an intra-area
/// Router-LSA vertex with the E-bit, else the cheapest Inter-Area-Router-LSA
/// for it (its ABR's distance plus that LSA's metric, through the ABR) — and
/// the vertex the path leaves through, for LFA.
fn asbr_distance(
    graph: &Reach,
    routers: &Routers,
    inter_area_routers: &[(Ipv4Addr, &InterAreaRouterLsaBody)],
    asbr: Ipv4Addr,
) -> Option<(Via, Ipv4Addr)> {
    if routers
        .get(&asbr)
        .is_some_and(|r| r.flags & lsa::ROUTER_FLAG_E != 0)
        && let Some(via) = graph.router(asbr)
    {
        return Some((via, asbr));
    }
    inter_area_routers
        .iter()
        .filter(|(_, r)| r.destination_router_id == asbr && r.metric < LS_INFINITY)
        .filter_map(|&(abr, r)| {
            let (d, hops) = graph.router(abr)?;
            Some(((d.saturating_add(r.metric), hops), abr))
        })
        // Cheapest wins; equal-cost ABRs pool their first hops (#1135).
        .fold(
            None,
            |best: Option<(Via, Ipv4Addr)>, ((d, hops), abr)| match best {
                Some(((bd, mut bh), babr)) if bd == d => {
                    bh.extend(hops);
                    bh.sort_unstable();
                    bh.dedup();
                    Some(((bd, bh), babr.min(abr)))
                }
                Some(b) if b.0 .0 < d => Some(b),
                _ => Some(((d, hops), abr)),
            },
        )
}

/// An AS-External-LSA's prefix via its ASBR, at the ASBR's distance plus the
/// LSA's own metric. Our own (`asbr == root`) never routes.
fn collect_external_route(
    graph: &Reach,
    routers: &Routers,
    inter_area_routers: &[(Ipv4Addr, &InterAreaRouterLsaBody)],
    asbr: Ipv4Addr,
    e: &AsExternalLsaBody,
    out: &mut HashMap<(Ipv6Addr, u8), RouteEntry>,
) {
    if asbr == graph.root || e.metric >= LS_INFINITY {
        return;
    }
    if let Some((via, egress)) = asbr_distance(graph, routers, inter_area_routers, asbr) {
        let class = if e.type2 {
            PathClass::External2
        } else {
            PathClass::External1
        };
        let route = route_via(e.prefix, via, e.metric, egress).classed(class, e.metric);
        insert_best(out, prefix_key(e.prefix), route);
    }
}

fn prefix_key(prefix: Ipv6Net) -> (Ipv6Addr, u8) {
    let t = prefix.trunc();
    (t.addr(), t.prefix_len())
}

fn insert_best(
    out: &mut HashMap<(Ipv6Addr, u8), RouteEntry>,
    key: (Ipv6Addr, u8),
    candidate: RouteEntry,
) {
    match out.get_mut(&key) {
        None => {
            out.insert(key, candidate);
        }
        Some(existing) if candidate.rank() < existing.rank() => *existing = candidate,
        // Equal rank: one route over the union of the paths (#1135).
        Some(existing) if candidate.rank() == existing.rank() => {
            existing.next_hops.extend(candidate.next_hops);
            existing.next_hops.sort_unstable();
            existing.next_hops.dedup();
            existing.next_hop = existing.next_hops[0].0;
            existing.interface_id = existing.next_hops[0].1;
        }
        Some(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{
        IntraAreaPrefixEntry, LinkLsaBody, Lsa, LsaBody, LsaHeader, RouterLsaLink, LSA_TYPE_LINK,
    };
    use std::sync::Arc;

    fn router_id(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(1, 1, 1, n)
    }

    fn header(lsa_type: u16, link_state_id: Ipv4Addr, advertising_router: Ipv4Addr) -> LsaHeader {
        LsaHeader {
            age: 0,
            lsa_type,
            link_state_id,
            advertising_router,
            sequence_number: 1,
            checksum: 0,
            length: 0,
        }
    }

    fn router_lsa(id: Ipv4Addr, links: Vec<RouterLsaLink>) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(LSA_TYPE_ROUTER, id, id),
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                options: 0,
                links,
            }),
        })
    }

    fn p2p(neighbor: Ipv4Addr, own_if: u32, neighbor_if: u32, metric: u16) -> RouterLsaLink {
        RouterLsaLink {
            link_type: LINK_TYPE_POINT_TO_POINT,
            metric,
            interface_id: own_if,
            neighbor_interface_id: neighbor_if,
            neighbor_router_id: neighbor,
        }
    }

    fn transit(network_if: u32, own_if: u32, dr: Ipv4Addr, metric: u16) -> RouterLsaLink {
        RouterLsaLink {
            link_type: LINK_TYPE_TRANSIT_NETWORK,
            metric,
            interface_id: own_if,
            neighbor_interface_id: network_if,
            neighbor_router_id: dr,
        }
    }

    fn link_lsa(router: Ipv4Addr, if_id: u32, addr: Ipv6Addr) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(LSA_TYPE_LINK, lsa::interface_id_key(if_id), router),
            body: LsaBody::Link(LinkLsaBody {
                priority: 1,
                options: 0,
                link_local_address: addr,
                prefixes: Vec::new(),
            }),
        })
    }

    fn network_lsa(if_id: u32, dr: Ipv4Addr, attached: Vec<Ipv4Addr>) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(LSA_TYPE_NETWORK, lsa::interface_id_key(if_id), dr),
            body: LsaBody::Network(NetworkLsaBody {
                options: 0,
                attached_routers: attached,
            }),
        })
    }

    fn router_prefix_lsa(router: Ipv4Addr, prefixes: Vec<(Ipv6Net, u16)>) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(
                lsa::LSA_TYPE_INTRA_AREA_PREFIX,
                Ipv4Addr::UNSPECIFIED,
                router,
            ),
            body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                referenced_ls_type: LSA_TYPE_ROUTER,
                referenced_link_state_id: router,
                referenced_advertising_router: router,
                prefixes: prefixes
                    .into_iter()
                    .map(|(prefix, metric)| IntraAreaPrefixEntry {
                        options: 0,
                        metric,
                        prefix,
                    })
                    .collect(),
            }),
        })
    }

    fn network_prefix_lsa(
        router: Ipv4Addr,
        network_if: u32,
        dr: Ipv4Addr,
        prefixes: Vec<(Ipv6Net, u16)>,
    ) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(
                lsa::LSA_TYPE_INTRA_AREA_PREFIX,
                lsa::interface_id_key(network_if),
                router,
            ),
            body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                referenced_ls_type: LSA_TYPE_NETWORK,
                referenced_link_state_id: lsa::interface_id_key(network_if),
                referenced_advertising_router: dr,
                prefixes: prefixes
                    .into_iter()
                    .map(|(prefix, metric)| IntraAreaPrefixEntry {
                        options: 0,
                        metric,
                        prefix,
                    })
                    .collect(),
            }),
        })
    }

    /// r1(root) — r2, r1 — r3, r2 — r3 (cost `cost_23`); r2 owns a prefix.
    fn triangle(cost_23: u16) -> Vec<Arc<Lsa>> {
        let (r1, r2, r3) = (router_id(1), router_id(2), router_id(3));
        vec![
            router_lsa(r1, vec![p2p(r2, 1, 1, 1), p2p(r3, 2, 1, 1)]),
            router_lsa(r2, vec![p2p(r1, 1, 1, 1), p2p(r3, 2, 2, cost_23)]),
            router_lsa(r3, vec![p2p(r1, 1, 2, 1), p2p(r2, 2, 2, cost_23)]),
            link_lsa(r2, 1, "fe80::2".parse().unwrap()),
            link_lsa(r3, 1, "fe80::3".parse().unwrap()),
            router_prefix_lsa(r2, vec![("2001:db8:2::/64".parse().unwrap(), 1)]),
        ]
    }

    fn with_flags(l: &Arc<Lsa>, flags: u8) -> Arc<Lsa> {
        let mut l = (**l).clone();
        if let LsaBody::Router(r) = &mut l.body {
            r.flags = flags;
        }
        Arc::new(l)
    }

    fn lsa_of(lsa_type: u16, id: u32, adv: Ipv4Addr, body: LsaBody) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(lsa_type, lsa::interface_id_key(id), adv),
            body,
        })
    }

    fn inter_area_prefix(abr: Ipv4Addr, prefix: &str, metric: u32) -> Arc<Lsa> {
        lsa_of(
            lsa::LSA_TYPE_INTER_AREA_PREFIX,
            1,
            abr,
            LsaBody::InterAreaPrefix(InterAreaPrefixLsaBody {
                metric,
                prefix_options: 0,
                prefix: prefix.parse().unwrap(),
            }),
        )
    }

    fn inter_area_router(via: Ipv4Addr, target: Ipv4Addr, metric: u32) -> Arc<Lsa> {
        lsa_of(
            lsa::LSA_TYPE_INTER_AREA_ROUTER,
            2,
            via,
            LsaBody::InterAreaRouter(InterAreaRouterLsaBody {
                options: 0,
                metric,
                destination_router_id: target,
            }),
        )
    }

    fn external(asbr: Ipv4Addr, prefix: &str) -> Arc<Lsa> {
        lsa_of(
            lsa::LSA_TYPE_AS_EXTERNAL,
            3,
            asbr,
            LsaBody::AsExternal(AsExternalLsaBody {
                type2: false,
                metric: EXTERNAL_METRIC,
                prefix_options: 0,
                prefix: prefix.parse().unwrap(),
                forwarding_address: None,
                route_tag: None,
                referenced_ls_type: 0,
                referenced_link_state_id: None,
            }),
        )
    }

    fn ext_lsa(
        lsa_type: u16,
        asbr: Ipv4Addr,
        prefix: &str,
        type2: bool,
        metric: u32,
        prefix_options: u8,
        forwarding_address: Option<Ipv6Addr>,
    ) -> Arc<Lsa> {
        lsa_of(
            lsa_type,
            3,
            asbr,
            LsaBody::AsExternal(AsExternalLsaBody {
                type2,
                metric,
                prefix_options,
                prefix: prefix.parse().unwrap(),
                forwarding_address,
                route_tag: None,
                referenced_ls_type: 0,
                referenced_link_state_id: None,
            }),
        )
    }

    /// root(1) —1— asbr(2), root —100— asbr(3), both ASBRs.
    fn two_asbrs() -> Vec<Arc<Lsa>> {
        let (r1, r2, r3) = (router_id(1), router_id(2), router_id(3));
        vec![
            router_lsa(r1, vec![p2p(r2, 1, 1, 1), p2p(r3, 2, 1, 100)]),
            with_flags(&router_lsa(r2, vec![p2p(r1, 1, 1, 1)]), lsa::ROUTER_FLAG_E),
            with_flags(
                &router_lsa(r3, vec![p2p(r1, 1, 2, 100)]),
                lsa::ROUTER_FLAG_E,
            ),
            link_lsa(r2, 1, "fe80::2".parse().unwrap()),
            link_lsa(r3, 1, "fe80::3".parse().unwrap()),
        ]
    }

    /// RFC 2328 §16.4 (#614): a type-1 external beats a type-2 whatever the
    /// cost, and two type-2 externals compare the LSA's own metric before
    /// the distance to the ASBR.
    #[test]
    fn path_class_precedence() {
        assert!(PathClass::Intra < PathClass::Inter);
        assert!(PathClass::Inter < PathClass::External1);
        assert!(PathClass::External1 < PathClass::External2);
        let (r2, r3) = (router_id(2), router_id(3));
        let via = |extra: Vec<Arc<Lsa>>| {
            let mut lsas = two_asbrs();
            lsas.extend(extra);
            let routes = compute(router_id(1), &lsas);
            let r = routes
                .iter()
                .find(|r| r.prefix.to_string() == "2001:db8:e::/48")
                .expect("external route")
                .clone();
            r.next_hop
        };
        let t = lsa::LSA_TYPE_AS_EXTERNAL;
        // E2 20 via the near ASBR vs E2 10 via the far one: the smaller E2.
        assert_eq!(
            via(vec![
                ext_lsa(t, r2, "2001:db8:e::/48", true, 20, 0, None),
                ext_lsa(t, r3, "2001:db8:e::/48", true, 10, 0, None),
            ]),
            "fe80::3".parse::<Ipv6Addr>().unwrap()
        );
        // E1 beats E2 even with a far bigger cost.
        assert_eq!(
            via(vec![
                ext_lsa(t, r2, "2001:db8:e::/48", true, 1, 0, None),
                ext_lsa(t, r3, "2001:db8:e::/48", false, 50, 0, None),
            ]),
            "fe80::3".parse::<Ipv6Addr>().unwrap()
        );
    }

    /// RFC 3101: an NSSA-LSA is an external route inside the NSSA (class
    /// N1/N2 = E1/E2), and only a P-bit one with a forwarding address from a
    /// reachable ASBR is translated, with the P-bit cleared.
    #[test]
    fn nssa_lsas_route_and_translate() {
        let (root, asbr, gone) = (router_id(1), router_id(2), router_id(9));
        let t7 = lsa::LSA_TYPE_NSSA;
        let fa: Option<Ipv6Addr> = Some("2001:db8::2".parse().unwrap());
        let mut lsas = two_asbrs();
        lsas.extend([
            ext_lsa(
                t7,
                asbr,
                "2001:db8:a::/48",
                false,
                20,
                lsa::PREFIX_OPT_P,
                fa,
            ),
            ext_lsa(t7, asbr, "2001:db8:b::/48", false, 20, 0, fa),
            ext_lsa(
                t7,
                asbr,
                "2001:db8:c::/48",
                false,
                20,
                lsa::PREFIX_OPT_P,
                None,
            ),
            ext_lsa(
                t7,
                gone,
                "2001:db8:d::/48",
                false,
                20,
                lsa::PREFIX_OPT_P,
                fa,
            ),
            ext_lsa(
                t7,
                root,
                "2001:db8:f::/48",
                false,
                20,
                lsa::PREFIX_OPT_P,
                fa,
            ),
        ]);
        let routes = compute(root, &lsas);
        let routed_prefixes: Vec<String> = routes.iter().map(|r| r.prefix.to_string()).collect();
        for p in ["a", "b", "c"] {
            assert!(
                routed_prefixes.contains(&format!("2001:db8:{p}::/48")),
                "{routed_prefixes:?}"
            );
        }
        assert!(!routed_prefixes
            .iter()
            .any(|p| p.contains(":d:") || p.contains(":f:")));
        let translated = nssa_translations(root, &lsas);
        assert_eq!(translated.len(), 1, "{translated:?}");
        assert_eq!(translated[0].0.to_string(), "2001:db8:a::/48");
        assert_eq!(translated[0].1.prefix_options, 0, "P-bit cleared");
        assert_eq!(translated[0].1.forwarding_address, fa);
    }

    /// RFC 3101 §3.1: the highest router ID among reachable ABRs translates,
    /// unless another has the Nt-bit; `always` translates regardless; an
    /// unreachable ABR doesn't count.
    #[test]
    fn nssa_translator_election() {
        let (low, high, far) = (router_id(1), router_id(2), router_id(3));
        let lsas = |high_flags, far_flags| {
            vec![
                with_flags(
                    &router_lsa(low, vec![p2p(high, 1, 1, 1)]),
                    lsa::ROUTER_FLAG_B,
                ),
                with_flags(&router_lsa(high, vec![p2p(low, 1, 1, 1)]), high_flags),
                // No link back to it: unreachable.
                with_flags(&router_lsa(far, vec![]), far_flags),
            ]
        };
        // The other isn't an ABR: low translates.
        assert!(nssa_translator(low, &lsas(0, lsa::ROUTER_FLAG_B), false));
        // Two ABRs: the higher ID wins.
        let two = lsas(lsa::ROUTER_FLAG_B, lsa::ROUTER_FLAG_B | lsa::ROUTER_FLAG_NT);
        assert!(!nssa_translator(low, &two, false));
        assert!(nssa_translator(high, &two, false));
        // Always beats a higher ID; Nt on the lower one beats the higher ID.
        assert!(nssa_translator(low, &two, true));
        let nt_low = vec![
            with_flags(&two[0], lsa::ROUTER_FLAG_B | lsa::ROUTER_FLAG_NT),
            two[1].clone(),
        ];
        assert!(!nssa_translator(high, &nt_low, false));
    }

    /// root(1) —5— abr(2): the area every inter-area test runs in.
    fn root_and_abr() -> Vec<Arc<Lsa>> {
        let (r1, r2) = (router_id(1), router_id(2));
        vec![
            router_lsa(r1, vec![p2p(r2, 1, 2, 5)]),
            with_flags(&router_lsa(r2, vec![p2p(r1, 2, 1, 5)]), lsa::ROUTER_FLAG_B),
            link_lsa(r2, 2, "fe80::2".parse().unwrap()),
        ]
    }

    fn vlink(endpoint: Ipv4Addr, metric: u16) -> RouterLsaLink {
        RouterLsaLink {
            link_type: LINK_TYPE_VIRTUAL,
            metric,
            interface_id: u32::from(endpoint),
            neighbor_interface_id: 0,
            neighbor_router_id: endpoint,
        }
    }

    /// The backbone of a virtual link between root (1) and 3, root's p2p
    /// neighbor 2 behind it; 3 holds a prefix.
    fn virtual_backbone(back: bool) -> Vec<Arc<Lsa>> {
        let (root, near, far) = (router_id(1), router_id(2), router_id(3));
        vec![
            router_lsa(root, vec![p2p(near, 1, 2, 1), vlink(far, 4)]),
            router_lsa(near, vec![p2p(root, 2, 1, 1)]),
            router_lsa(far, if back { vec![vlink(root, 4)] } else { vec![] }),
            link_lsa(root, 1, a6("fe80::1")),
            link_lsa(near, 2, a6("fe80::2")),
            router_prefix_lsa(far, vec![("2001:db8:3::/64".parse().unwrap(), 1)]),
        ]
    }

    /// RFC 2328 §16.1 (#1159): in the backbone a reciprocal type-4 link is an
    /// edge at its metric with the transit area's next hops out of root; not
    /// in another area, not one-way (#959), not without those hops.
    #[test]
    fn virtual_link_is_a_backbone_edge_with_transit_next_hops() {
        let root = router_id(1);
        let hops = [VirtualNextHops {
            endpoint: router_id(3),
            next_hops: vec![(a6("fe80::9"), 7)],
        }];
        let ctx = Context {
            backbone: true,
            virtual_links: &hops,
            ..Context::default()
        };
        let routes = compute_in(root, &virtual_backbone(true), &ctx);
        assert_eq!(routes.len(), 1, "{routes:?}");
        assert_eq!(
            (routes[0].metric, &routes[0].next_hops[..], routes[0].class),
            (5, &[(a6("fe80::9"), 7)][..], PathClass::Intra)
        );
        assert_eq!(compute_in(root, &virtual_backbone(false), &ctx), []);
        let other_area = Context {
            backbone: false,
            ..ctx
        };
        assert_eq!(compute_in(root, &virtual_backbone(true), &other_area), []);
        assert_eq!(compute(root, &virtual_backbone(true)), []);
        // Beyond the first hop (root seen from 2) the next hop is inherited.
        let from_near = compute_in(router_id(2), &virtual_backbone(true), &ctx);
        assert_eq!(from_near.len(), 1, "{from_near:?}");
        assert_eq!(from_near[0].metric, 6);
        // Distance-only runs see the edge too (the far end's summaries).
        let view = intra_area_routes(root, &virtual_backbone(true), &ctx);
        assert_eq!(view.prefixes.len(), 1);
        let plain = intra_area_routes(root, &virtual_backbone(true), &Context::default());
        assert_eq!(plain.prefixes.len(), 0);
    }

    /// `virtual_next_hops`: the first hops toward the endpoint in its transit
    /// area (Link-LSAs needed), none while it is unreachable.
    #[test]
    fn virtual_next_hops_are_the_transit_first_hops() {
        let (root, near, end) = (router_id(1), router_id(2), router_id(3));
        let lsas = vec![
            router_lsa(root, vec![p2p(near, 1, 2, 1)]),
            router_lsa(near, vec![p2p(root, 2, 1, 1), p2p(end, 3, 4, 1)]),
            router_lsa(end, vec![p2p(near, 4, 3, 1)]),
            link_lsa(near, 2, a6("fe80::2")),
        ];
        assert_eq!(
            virtual_next_hops(root, &lsas, end),
            Some(VirtualNextHops {
                endpoint: end,
                next_hops: vec![(a6("fe80::2"), 1)],
            })
        );
        assert_eq!(virtual_next_hops(root, &lsas, router_id(9)), None);
        assert_eq!(virtual_next_hops(root, &lsas[..1], end), None);
    }

    /// RFC 2328 §16.3 (#1159): a transit-capable area (V bit) offers its ABRs'
    /// Inter-Area-Prefix-LSAs; `apply_transit` takes a strictly cheaper one,
    /// merges an equal one and leaves a dearer one or another class alone.
    #[test]
    fn transit_summaries_shorten_backbone_routes() {
        let (root, abr) = (router_id(1), router_id(2));
        let prefix: Ipv6Net = "2001:db8:9::/64".parse().unwrap();
        let summary = Arc::new(Lsa {
            header: header(lsa::LSA_TYPE_INTER_AREA_PREFIX, router_id(100), abr),
            body: LsaBody::InterAreaPrefix(InterAreaPrefixLsaBody {
                metric: 3,
                prefix_options: 0,
                prefix,
            }),
        });
        let area = |flags| {
            vec![
                router_lsa(root, vec![p2p(abr, 1, 2, 5)]),
                with_flags(&router_lsa(abr, vec![p2p(root, 2, 1, 5)]), flags),
                link_lsa(abr, 2, a6("fe80::2")),
                summary.clone(),
            ]
        };
        assert_eq!(transit_summaries(root, &area(0)), []);
        let cand = transit_summaries(root, &area(lsa::ROUTER_FLAG_V));
        assert_eq!(cand.len(), 1);
        assert_eq!(cand[0].metric, 8);
        let existing = |metric, class| {
            RouteEntry::new(
                prefix,
                vec![(a6("fe80::7"), 3)],
                metric,
                Vertex::Router(router_id(7)),
            )
            .classed(class, 0)
        };
        let mut r = existing(10, PathClass::Inter);
        apply_transit(&mut r, cand[0].clone());
        assert_eq!(
            (r.metric, r.next_hops.clone()),
            (8, vec![(a6("fe80::2"), 1)])
        );
        let mut r = existing(8, PathClass::Inter);
        apply_transit(&mut r, cand[0].clone());
        assert_eq!(
            (r.metric, r.next_hops.len(), r.next_hop),
            (8, 2, a6("fe80::2"))
        );
        let mut r = existing(6, PathClass::Inter);
        apply_transit(&mut r, cand[0].clone());
        assert_eq!((r.metric, r.next_hops.len()), (6, 1));
        let mut r = existing(10, PathClass::Intra);
        apply_transit(&mut r, cand[0].clone());
        assert_eq!((r.metric, r.next_hops.len()), (10, 1));
    }

    /// RFC 5340 §4.7: the endpoint's cost and its lowest global LA `/128`; a
    /// plain, link-local, NU or non-`/128` prefix is no address, no path (or
    /// root itself) is no endpoint.
    #[test]
    fn virtual_link_endpoint_is_cost_and_la_address() {
        let (root, mid, end) = (router_id(1), router_id(2), router_id(3));
        let chain = vec![
            router_lsa(root, vec![p2p(mid, 1, 2, 2)]),
            router_lsa(mid, vec![p2p(root, 2, 1, 2), p2p(end, 3, 4, 3)]),
            router_lsa(end, vec![p2p(mid, 4, 3, 3)]),
        ];
        let prefixes = |list: &[(&str, u8)]| {
            Arc::new(Lsa {
                header: header(lsa::LSA_TYPE_INTRA_AREA_PREFIX, Ipv4Addr::UNSPECIFIED, end),
                body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                    referenced_ls_type: LSA_TYPE_ROUTER,
                    referenced_link_state_id: end,
                    referenced_advertising_router: end,
                    prefixes: list
                        .iter()
                        .map(|(p, options)| IntraAreaPrefixEntry {
                            options: *options,
                            metric: 1,
                            prefix: p.parse().unwrap(),
                        })
                        .collect(),
                }),
            })
        };
        let la = lsa::PREFIX_OPT_LA;
        let mut lsas = chain.clone();
        lsas.push(prefixes(&[
            ("2001:db8:1::/64", 0),
            ("2001:db8:ff::9/128", 0),
            ("fe80::9/128", la),
            ("2001:db8:ff::8/128", la | lsa::PREFIX_OPT_NU),
        ]));
        assert_eq!(virtual_link_endpoint(root, &lsas, end), None);
        lsas.push(prefixes(&[
            ("2001:db8:ff::7/128", la),
            ("2001:db8:ff::5/128", la),
        ]));
        assert_eq!(
            virtual_link_endpoint(root, &lsas, end),
            Some(VirtualEndpoint {
                cost: 5,
                address: "2001:db8:ff::5".parse().unwrap(),
            })
        );
        assert_eq!(virtual_link_endpoint(root, &lsas, root), None);
        // The middle router gone: no intra-area path.
        let cut = vec![chain[0].clone(), chain[2].clone(), lsas[4].clone()];
        assert_eq!(virtual_link_endpoint(root, &cut, end), None);
    }

    fn only(routes: &[RouteEntry]) -> (u32, Ipv6Addr) {
        assert_eq!(routes.len(), 1, "{routes:?}");
        let r = &routes[0];
        assert_eq!(r.interface_id, 1);
        (r.metric, r.next_hop)
    }

    /// RFC 5340 A.4.1.1: NU prefixes are not routed; LA and plain ones are.
    #[test]
    fn nu_prefix_is_not_installed_but_la_and_plain_are() {
        let mut lsas = root_and_abr();
        let r2 = router_id(2);
        let mut lsa = router_prefix_lsa(
            r2,
            vec![
                ("2001:db8:a::/64".parse().unwrap(), 1),
                ("2001:db8:b::/64".parse().unwrap(), 1),
                ("2001:db8:c::/128".parse().unwrap(), 1),
            ],
        );
        let LsaBody::IntraAreaPrefix(body) = &mut Arc::make_mut(&mut lsa).body else {
            unreachable!()
        };
        body.prefixes[0].options = lsa::PREFIX_OPT_NU;
        body.prefixes[2].options = lsa::PREFIX_OPT_LA;
        lsas.push(lsa);
        let routes = compute(router_id(1), &lsas);
        let mut got: Vec<String> = routes.iter().map(|r| r.prefix.to_string()).collect();
        got.sort();
        assert_eq!(got, ["2001:db8:b::/64", "2001:db8:c::/128"]);
        let view = intra_area_routes(router_id(1), &lsas, &Context::default());
        assert_eq!(view.prefixes.len(), 2);
    }

    #[test]
    fn opaque_lsa_does_not_change_routes() {
        let mut lsas = root_and_abr();
        lsas.push(inter_area_prefix(router_id(2), "2001:db8:9::/64", 7));
        let before = compute(router_id(1), &lsas);
        lsas.push(Arc::new(Lsa {
            header: header(0xA0FF, router_id(2), router_id(2)),
            body: LsaBody::Opaque(vec![1, 2, 3, 4]),
        }));
        assert_eq!(compute(router_id(1), &lsas), before);
    }

    #[test]
    fn inter_area_prefix_is_routed_through_its_abr() {
        let mut lsas = root_and_abr();
        lsas.push(inter_area_prefix(router_id(2), "2001:db8:9::/64", 7));
        let routes = compute(router_id(1), &lsas);
        assert_eq!(only(&routes), (12, "fe80::2".parse().unwrap()));
        assert_eq!(
            routes[0].prefix,
            "2001:db8:9::/64".parse::<Ipv6Net>().unwrap()
        );
    }

    #[test]
    fn external_route_through_an_intra_area_asbr_needs_its_e_bit() {
        let (r1, r2) = (router_id(1), router_id(2));
        let mut lsas = root_and_abr();
        lsas.push(external(r2, "2001:db8:e::/48"));
        // B-bit only: not an ASBR.
        assert_eq!(compute(r1, &lsas), []);
        lsas[1] = with_flags(&lsas[1], lsa::ROUTER_FLAG_E);
        let routes = compute(r1, &lsas);
        assert_eq!(
            only(&routes),
            (5 + EXTERNAL_METRIC, "fe80::2".parse().unwrap())
        );
    }

    #[test]
    fn external_route_through_an_inter_area_router_lsa() {
        let (r1, r2, asbr) = (router_id(1), router_id(2), router_id(9));
        let mut lsas = root_and_abr();
        lsas.push(external(asbr, "2001:db8:e::/48"));
        assert_eq!(compute(r1, &lsas), []);
        lsas.push(inter_area_router(r2, asbr, 3));
        let routes = compute(r1, &lsas);
        assert_eq!(
            only(&routes),
            (5 + 3 + EXTERNAL_METRIC, "fe80::2".parse().unwrap())
        );
    }

    #[test]
    fn ls_infinity_is_never_routed_but_one_below_is() {
        let (r1, r2, asbr) = (router_id(1), router_id(2), router_id(9));
        for (metric, routed) in [(LS_INFINITY, false), (LS_INFINITY - 1, true)] {
            let mut lsas = root_and_abr();
            lsas.push(inter_area_prefix(r2, "2001:db8:9::/64", metric));
            assert_eq!(!compute(r1, &lsas).is_empty(), routed, "prefix {metric}");

            let mut lsas = root_and_abr();
            lsas[1] = with_flags(&lsas[1], lsa::ROUTER_FLAG_E);
            let mut ext = external(r2, "2001:db8:e::/48");
            let LsaBody::AsExternal(b) = &mut Arc::make_mut(&mut ext).body else {
                unreachable!()
            };
            b.metric = metric;
            lsas.push(ext);
            assert_eq!(!compute(r1, &lsas).is_empty(), routed, "external {metric}");

            let mut lsas = root_and_abr();
            lsas.push(external(asbr, "2001:db8:e::/48"));
            lsas.push(inter_area_router(r2, asbr, metric));
            assert_eq!(!compute(r1, &lsas).is_empty(), routed, "asbr {metric}");
        }
    }

    #[test]
    fn own_inter_area_and_external_lsas_never_route() {
        let r1 = router_id(1);
        let mut lsas = root_and_abr();
        lsas[0] = with_flags(&lsas[0], lsa::ROUTER_FLAG_E | lsa::ROUTER_FLAG_B);
        lsas.push(inter_area_prefix(r1, "2001:db8:9::/64", 7));
        lsas.push(external(r1, "2001:db8:e::/48"));
        lsas.push(inter_area_router(r1, r1, 0));
        assert_eq!(compute(r1, &lsas), []);
    }

    #[test]
    fn intra_area_view_has_own_and_reachable_prefixes_and_asbrs_only() {
        let (r1, r2) = (router_id(1), router_id(2));
        let mut lsas = root_and_abr();
        lsas[1] = with_flags(&lsas[1], lsa::ROUTER_FLAG_E);
        lsas.push(router_prefix_lsa(
            r1,
            vec![("2001:db8:1::/128".parse().unwrap(), 1)],
        ));
        lsas.push(router_prefix_lsa(
            r2,
            vec![("2001:db8:2::/128".parse().unwrap(), 2)],
        ));
        lsas.push(inter_area_prefix(r2, "2001:db8:9::/64", 7));
        lsas.push(external(r2, "2001:db8:e::/48"));
        let view = intra_area_routes(r1, &lsas, &Context::default());
        let mut prefixes = view.prefixes;
        prefixes.sort();
        assert_eq!(
            prefixes,
            vec![
                ("2001:db8:1::/128".parse().unwrap(), 1),
                ("2001:db8:2::/128".parse().unwrap(), 7),
            ]
        );
        assert_eq!(view.asbrs, vec![(r2, 5, 0)]);
    }

    #[test]
    fn triangle_gets_loop_free_alternate_with_its_own_interface() {
        let routes = compute(router_id(1), &triangle(1));
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hop, "fe80::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(routes[0].interface_id, 1);
        // 3 reaches 2 directly (1) < 3→root (1) + root→2 (1); root's link to
        // 3 is its own interface 2, not the primary's 1.
        assert_eq!(
            routes[0].backup_next_hop,
            Some("fe80::3".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(routes[0].backup_interface_id, Some(2));
    }

    /// RFC 5286 §3.5 / RFC 6987: a stub router (`MaxLinkMetric` on its links,
    /// or on root's link to it) is never an alternate.
    #[test]
    fn stub_router_is_never_an_alternate() {
        let (r1, r2, r3) = (router_id(1), router_id(2), router_id(3));
        let lsas = |root_cost: u16, r3_cost: u16| {
            vec![
                router_lsa(r1, vec![p2p(r2, 1, 1, 1), p2p(r3, 2, 1, root_cost)]),
                router_lsa(r2, vec![p2p(r1, 1, 1, 1), p2p(r3, 2, 2, 1)]),
                router_lsa(r3, vec![p2p(r1, 1, 2, r3_cost), p2p(r2, 2, 2, r3_cost)]),
                link_lsa(r2, 1, "fe80::2".parse().unwrap()),
                link_lsa(r3, 1, "fe80::3".parse().unwrap()),
                router_prefix_lsa(r2, vec![("2001:db8:2::/64".parse().unwrap(), 1)]),
            ]
        };
        let backup = |l: Vec<Arc<Lsa>>| compute(r1, &l)[0].backup_next_hop;
        assert!(backup(lsas(1, 1)).is_some());
        assert_eq!(backup(lsas(1, 0xFFFF)), None, "neighbor is a stub router");
        assert_eq!(backup(lsas(0xFFFF, 1)), None, "root's link is max-metric");
    }

    /// The same on a transit network: a peer whose link to it is
    /// `MaxLinkMetric` is no alternate.
    #[test]
    fn stub_router_on_a_transit_network_is_never_an_alternate() {
        let (r1, r2, r3) = (router_id(1), router_id(2), router_id(3));
        let lsas = |r3_metric: u16| {
            [
                router_lsa(r1, vec![transit(10, 10, r1, 1)]),
                router_lsa(r2, vec![transit(10, 20, r1, 1), p2p(r3, 21, 31, 1)]),
                router_lsa(r3, vec![transit(10, 30, r1, r3_metric), p2p(r2, 31, 21, 1)]),
                network_lsa(10, r1, vec![r1, r2, r3]),
                link_lsa(r2, 20, "fe80::2".parse().unwrap()),
                link_lsa(r3, 30, "fe80::3".parse().unwrap()),
                router_prefix_lsa(r2, vec![("2001:db8:2::/64".parse().unwrap(), 1)]),
            ]
        };
        assert!(compute(r1, &lsas(1))[0].backup_next_hop.is_some());
        assert_eq!(compute(r1, &lsas(0xFFFF))[0].backup_next_hop, None);
    }

    #[test]
    fn neighbor_whose_best_path_loops_through_root_is_not_an_alternate() {
        // 3's shortest way to 2 is back through root (1+1=2 < 10), so
        // 2 < 1 + 1 fails: it would loop.
        let routes = compute(router_id(1), &triangle(10));
        assert_eq!(routes[0].backup_next_hop, None);
        assert_eq!(routes[0].backup_interface_id, None);
    }

    #[test]
    fn single_neighbor_has_no_alternate() {
        let (r1, r2) = (router_id(1), router_id(2));
        let routes = compute(
            r1,
            &[
                router_lsa(r1, vec![p2p(r2, 1, 1, 1)]),
                router_lsa(r2, vec![p2p(r1, 1, 1, 1)]),
                link_lsa(r2, 1, "fe80::2".parse().unwrap()),
                router_prefix_lsa(r2, vec![("2001:db8:2::/64".parse().unwrap(), 1)]),
            ],
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].backup_next_hop, None);
    }

    #[test]
    fn transit_network_peer_is_an_alternate() {
        // root and 2 and 3 share network (DR = root, if 10); 3 also has a
        // direct link to 2 so it doesn't route back through root.
        let (r1, r2, r3) = (router_id(1), router_id(2), router_id(3));
        let lsas = [
            router_lsa(r1, vec![transit(10, 10, r1, 1)]),
            router_lsa(r2, vec![transit(10, 20, r1, 1), p2p(r3, 21, 31, 1)]),
            router_lsa(r3, vec![transit(10, 30, r1, 1), p2p(r2, 31, 21, 1)]),
            network_lsa(10, r1, vec![r1, r2, r3]),
            link_lsa(r2, 20, "fe80::2".parse().unwrap()),
            link_lsa(r3, 30, "fe80::3".parse().unwrap()),
            router_prefix_lsa(r2, vec![("2001:db8:2::/64".parse().unwrap(), 1)]),
        ];
        let routes = compute(r1, &lsas);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hop, "fe80::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            routes[0].backup_next_hop,
            Some("fe80::3".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(routes[0].backup_interface_id, Some(10));
    }

    #[test]
    fn direct_p2p_neighbor_prefix_distance_and_next_hop() {
        let root = router_id(1);
        let w = router_id(2);
        let w_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        let stub: Ipv6Net = "2001:db8:1::/64".parse().unwrap();

        let root_lsa = router_lsa(root, vec![p2p(w, 1, 2, 5)]);
        let w_lsa = router_lsa(w, vec![p2p(root, 2, 1, 5)]);
        let w_link = link_lsa(w, 2, w_link_local);
        let w_prefix = router_prefix_lsa(w, vec![(stub, 10)]);

        let routes = compute(root, &[root_lsa, w_lsa, w_link, w_prefix]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, stub);
        assert_eq!(routes[0].next_hop, w_link_local);
        // Root's own interface id on the p2p link to w — `p2p(w, 1, 2, 5)`'s
        // own_if=1 — required as `RTA_OIF` to install this link-local
        // next-hop (see `RouteEntry::interface_id`'s doc comment).
        assert_eq!(routes[0].interface_id, 1);
        assert_eq!(routes[0].metric, 15);
    }

    #[test]
    fn extended_lsas_give_the_same_routes_as_legacy_ones() {
        let root = router_id(1);
        let w = router_id(2);
        let stub: Ipv6Net = "2001:db8:1::/64".parse().unwrap();
        let as_extended = |l: Arc<Lsa>| {
            let mut l = (*l).clone();
            l.header.lsa_type = match l.header.lsa_type {
                LSA_TYPE_ROUTER => lsa::LSA_TYPE_E_ROUTER,
                LSA_TYPE_LINK => lsa::LSA_TYPE_E_LINK,
                lsa::LSA_TYPE_INTER_AREA_PREFIX => lsa::LSA_TYPE_E_INTER_AREA_PREFIX,
                lsa::LSA_TYPE_INTER_AREA_ROUTER => lsa::LSA_TYPE_E_INTER_AREA_ROUTER,
                lsa::LSA_TYPE_AS_EXTERNAL => lsa::LSA_TYPE_E_AS_EXTERNAL,
                _ => lsa::LSA_TYPE_E_INTRA_AREA_PREFIX,
            };
            if let LsaBody::IntraAreaPrefix(p) = &mut l.body {
                p.referenced_ls_type = lsa::LSA_TYPE_E_ROUTER;
            }
            Arc::new(l)
        };
        let legacy = [
            router_lsa(root, vec![p2p(w, 1, 2, 5)]),
            router_lsa(w, vec![p2p(root, 2, 1, 5)]),
            link_lsa(w, 2, "fe80::2".parse().unwrap()),
            router_prefix_lsa(w, vec![(stub, 10)]),
            inter_area_prefix(w, "2001:db8:9::/64", 7),
            inter_area_router(w, router_id(9), 3),
            external(router_id(9), "2001:db8:e::/48"),
        ];
        let extended: Vec<_> = legacy.iter().cloned().map(as_extended).collect();

        let sorted = |lsas: &[Arc<Lsa>]| {
            let mut routes: Vec<(Ipv6Net, u32, Ipv6Addr)> = compute(root, lsas)
                .into_iter()
                .map(|r| (r.prefix, r.metric, r.next_hop))
                .collect();
            routes.sort();
            routes
        };
        let routes = sorted(&extended);
        assert_eq!(routes.len(), 3);
        assert!(routes.contains(&(stub, 15, "fe80::2".parse().unwrap())));
        assert_eq!(routes, sorted(&legacy));
    }

    /// RFC 8362 §3 Sparse mode: a router may originate both a legacy LSA and
    /// its E-form with the same content; links and prefixes count once.
    #[test]
    fn legacy_and_extended_forms_of_one_router_are_not_double_counted() {
        let root = router_id(1);
        let w = router_id(2);
        let stub: Ipv6Net = "2001:db8:1::/64".parse().unwrap();
        let legacy = [
            router_lsa(root, vec![p2p(w, 1, 2, 5)]),
            router_lsa(w, vec![p2p(root, 2, 1, 5)]),
            link_lsa(w, 2, "fe80::2".parse().unwrap()),
            router_prefix_lsa(w, vec![(stub, 10)]),
        ];
        let mut both: Vec<Arc<Lsa>> = legacy.to_vec();
        let mut e_router = (*legacy[1]).clone();
        e_router.header.lsa_type = lsa::LSA_TYPE_E_ROUTER;
        both.push(Arc::new(e_router));
        let mut e_prefix = (*legacy[3]).clone();
        e_prefix.header.lsa_type = lsa::LSA_TYPE_E_INTRA_AREA_PREFIX;
        if let LsaBody::IntraAreaPrefix(p) = &mut e_prefix.body {
            p.referenced_ls_type = lsa::LSA_TYPE_E_ROUTER;
        }
        both.push(Arc::new(e_prefix));
        let routes = compute(root, &both);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metric, 15);
        assert_eq!(routes[0].prefix, stub);
        let (merged, _, _) = routers_networks_links(&both);
        assert_eq!(merged[&w].links.len(), 1);
    }

    /// A flushed (`MaxAge`) Router-LSA of w's other flavor — here with no link
    /// back to root — is ignored, whichever order it comes in (#149).
    #[test]
    fn max_age_router_lsa_is_ignored() {
        let root = router_id(1);
        let w = router_id(2);
        let stub: Ipv6Net = "2001:db8:1::/64".parse().unwrap();
        let mut stale = (*router_lsa(w, Vec::new())).clone();
        stale.header.lsa_type = lsa::LSA_TYPE_E_ROUTER;
        stale.header.age = lsa::MAX_AGE;
        let stale = Arc::new(stale);
        let live = vec![
            router_lsa(root, vec![p2p(w, 1, 2, 5)]),
            router_lsa(w, vec![p2p(root, 2, 1, 5)]),
            link_lsa(w, 2, "fe80::2".parse().unwrap()),
            router_prefix_lsa(w, vec![(stub, 10)]),
        ];
        let mut before = vec![Arc::clone(&stale)];
        before.extend(live.iter().cloned());
        let mut after = live.clone();
        after.push(stale);
        for lsas in [before, after] {
            let routes = compute(root, &lsas);
            assert_eq!(routes.len(), 1);
            assert_eq!(routes[0].prefix, stub);
            assert_eq!(routes[0].metric, 15);
        }
    }

    #[test]
    fn two_hop_chain_inherits_first_hop_next_hop() {
        let root = router_id(1);
        let w = router_id(2);
        let x = router_id(3);
        let w_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        let stub: Ipv6Net = "2001:db8:2::/64".parse().unwrap();

        let root_lsa = router_lsa(root, vec![p2p(w, 1, 2, 1)]);
        let w_lsa = router_lsa(w, vec![p2p(root, 2, 1, 1), p2p(x, 3, 4, 1)]);
        let x_lsa = router_lsa(x, vec![p2p(w, 4, 3, 1)]);
        let w_link = link_lsa(w, 2, w_link_local);
        let x_link = link_lsa(x, 4, "fe80::4".parse().unwrap());
        let x_prefix = router_prefix_lsa(x, vec![(stub, 1)]);

        let routes = compute(root, &[root_lsa, w_lsa, x_lsa, w_link, x_link, x_prefix]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hop, w_link_local);
        // Inherited unchanged from the first hop (root's own p2p link to w,
        // `p2p(w, 1, 2, 1)`'s own_if=1) — never x's own interface id.
        assert_eq!(routes[0].interface_id, 1);
        assert_eq!(routes[0].metric, 3);
    }

    /// #618: two parallel links to one neighbor: the route leaves over the
    /// cheaper one whatever the LSA's link order.
    #[test]
    fn parallel_links_use_the_cheapest_interface() {
        let (root, w) = (router_id(1), router_id(2));
        let stub: Ipv6Net = "2001:db8:2::/64".parse().unwrap();
        for links in [
            vec![p2p(w, 10, 10, 5), p2p(w, 20, 20, 1)],
            vec![p2p(w, 20, 20, 1), p2p(w, 10, 10, 5)],
        ] {
            let routes = compute(
                root,
                &[
                    router_lsa(root, links),
                    router_lsa(w, vec![p2p(root, 10, 10, 5), p2p(root, 20, 20, 1)]),
                    link_lsa(w, 10, "fe80::2".parse().unwrap()),
                    link_lsa(w, 20, "fe80::2".parse().unwrap()),
                    router_prefix_lsa(w, vec![(stub, 1)]),
                ],
            );
            assert_eq!(routes.len(), 1);
            assert_eq!((routes[0].interface_id, routes[0].metric), (20, 2));
        }
    }

    #[test]
    fn network_attached_router_next_hop_derived_from_its_own_transit_link() {
        let root = router_id(1);
        let w = router_id(2);
        let network_if_on_root = 10u32;
        let w_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        let stub: Ipv6Net = "2001:db8:3::/64".parse().unwrap();

        // root is DR: network vertex key = root's own interface id (10).
        let root_lsa = router_lsa(
            root,
            vec![transit(network_if_on_root, network_if_on_root, root, 1)],
        );
        let w_lsa = router_lsa(w, vec![transit(network_if_on_root, 20, root, 1)]);
        let net_lsa = network_lsa(network_if_on_root, root, vec![root, w]);
        let w_link = link_lsa(w, 20, w_link_local);
        let w_prefix = router_prefix_lsa(w, vec![(stub, 1)]);

        let routes = compute(root, &[root_lsa, w_lsa, net_lsa, w_link, w_prefix]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, stub);
        assert_eq!(routes[0].next_hop, w_link_local);
        // Root's own interface id on its transit-network link — the
        // network sentinel's stored id, inherited unchanged into the
        // resolved router next-hop.
        assert_eq!(routes[0].interface_id, network_if_on_root);
        assert_eq!(routes[0].metric, 2);
    }

    #[test]
    fn directly_connected_transit_network_prefix_is_filtered() {
        let root = router_id(1);
        let w = router_id(2);
        let network_if = 10u32;
        let w_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        let transit_prefix: Ipv6Net = "2001:db8:4::/64".parse().unwrap();

        // root is Backup, w is DR (network vertex key = w's own interface id).
        let root_lsa = router_lsa(root, vec![transit(network_if, 30, w, 1)]);
        let w_lsa = router_lsa(w, vec![transit(network_if, network_if, w, 1)]);
        let net_lsa = network_lsa(network_if, w, vec![root, w]);
        let w_link = link_lsa(w, network_if, w_link_local);
        // A second router "on the network" that isn't root, so the network
        // is reachable but not root-attached... actually root IS attached
        // here (transit link above), so instead prove the transit prefix
        // itself is filtered as directly-connected — see next test. This
        // test proves a *different* router's prefix reachable via the
        // network's own derived next-hop still works when root is not DR.
        let net_prefix = network_prefix_lsa(w, network_if, w, vec![(transit_prefix, 0)]);

        let routes = compute(root, &[root_lsa, w_lsa, net_lsa, w_link, net_prefix]);
        // root is directly attached to this network, so its own transit
        // prefix is filtered (directly connected) — zero routes expected.
        assert_eq!(routes, []);
    }

    #[test]
    fn directly_connected_router_prefix_is_filtered() {
        let root = router_id(1);
        let stub: Ipv6Net = "2001:db8:5::/64".parse().unwrap();
        let root_lsa = router_lsa(root, vec![]);
        let root_prefix = router_prefix_lsa(root, vec![(stub, 1)]);
        assert_eq!(compute(root, &[root_lsa, root_prefix]), []);
    }

    #[test]
    fn mirrored_p2p_prefix_via_neighbor_is_filtered() {
        let root = router_id(1);
        let w = router_id(2);
        let shared: Ipv6Net = "2001:db8:6::/64".parse().unwrap();

        let root_lsa = router_lsa(root, vec![p2p(w, 1, 2, 1)]);
        let w_lsa = router_lsa(w, vec![p2p(root, 2, 1, 1)]);
        let w_link = link_lsa(w, 2, "fe80::2".parse().unwrap());
        let root_prefix = router_prefix_lsa(root, vec![(shared, 1)]);
        let w_prefix = router_prefix_lsa(w, vec![(shared, 1)]);

        let routes = compute(root, &[root_lsa, w_lsa, w_link, root_prefix, w_prefix]);
        assert_eq!(routes, []);
    }

    #[test]
    fn no_link_lsa_for_neighbor_is_treated_as_unreachable() {
        let root = router_id(1);
        let w = router_id(2);
        let stub: Ipv6Net = "2001:db8:7::/64".parse().unwrap();
        let root_lsa = router_lsa(root, vec![p2p(w, 1, 2, 1)]);
        let w_lsa = router_lsa(w, vec![p2p(root, 2, 1, 1)]);
        // No Link-LSA installed for w at all — next-hop can't be derived.
        let w_prefix = router_prefix_lsa(w, vec![(stub, 1)]);
        assert_eq!(compute(root, &[root_lsa, w_lsa, w_prefix]), []);
    }

    #[test]
    fn duplicate_prefix_via_two_routers_keeps_minimum_distance() {
        let root = router_id(1);
        let w1 = router_id(2);
        let w2 = router_id(3);
        let net: Ipv6Net = "2001:db8:8::/64".parse().unwrap();

        let root_lsa = router_lsa(root, vec![p2p(w1, 1, 2, 1), p2p(w2, 3, 4, 1)]);
        let w1_lsa = router_lsa(w1, vec![p2p(root, 2, 1, 1)]);
        let w2_lsa = router_lsa(w2, vec![p2p(root, 4, 3, 1)]);
        let w1_link = link_lsa(w1, 2, "fe80::2".parse().unwrap());
        let w2_link = link_lsa(w2, 4, "fe80::4".parse().unwrap());
        let w1_prefix = router_prefix_lsa(w1, vec![(net, 10)]);
        let w2_prefix = router_prefix_lsa(w2, vec![(net, 1)]);

        let routes = compute(
            root,
            &[
                root_lsa, w1_lsa, w2_lsa, w1_link, w2_link, w1_prefix, w2_prefix,
            ],
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metric, 2);
        assert_eq!(routes[0].next_hop, "fe80::4".parse::<Ipv6Addr>().unwrap());
    }

    fn fragment(
        adv: Ipv4Addr,
        lsid: u32,
        lsa_type: u16,
        flags: u8,
        options: u32,
        links: Vec<RouterLsaLink>,
    ) -> Arc<Lsa> {
        Arc::new(Lsa {
            header: header(lsa_type, Ipv4Addr::from(lsid), adv),
            body: LsaBody::Router(RouterLsaBody {
                flags,
                options,
                links,
            }),
        })
    }

    /// r1(root) split over two fragments, reaching r2 and r3 (each with a prefix).
    fn split_root() -> Vec<Arc<Lsa>> {
        let (r1, r2, r3) = (router_id(1), router_id(2), router_id(3));
        vec![
            fragment(r1, 0, LSA_TYPE_ROUTER, 0, 0, vec![p2p(r2, 1, 1, 1)]),
            fragment(r1, 1, LSA_TYPE_ROUTER, 0, 0, vec![p2p(r3, 2, 1, 1)]),
            router_lsa(r2, vec![p2p(r1, 1, 1, 1)]),
            router_lsa(r3, vec![p2p(r1, 1, 2, 1)]),
            link_lsa(r2, 1, "fe80::2".parse().unwrap()),
            link_lsa(r3, 1, "fe80::3".parse().unwrap()),
            router_prefix_lsa(r2, vec![("2001:db8:2::/64".parse().unwrap(), 1)]),
            router_prefix_lsa(r3, vec![("2001:db8:3::/64".parse().unwrap(), 1)]),
        ]
    }

    fn sorted(mut v: Vec<RouteEntry>) -> Vec<RouteEntry> {
        v.sort_by_key(|r| r.prefix);
        v
    }

    #[test]
    fn split_router_lsa_reaches_both_neighbors_in_any_order() {
        let lsas = split_root();
        let routes = sorted(compute(router_id(1), &lsas));
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].next_hop, "fe80::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(routes[0].interface_id, 1);
        assert_eq!(routes[1].next_hop, "fe80::3".parse::<Ipv6Addr>().unwrap());
        assert_eq!(routes[1].interface_id, 2);
        let mut rev = lsas.clone();
        rev.reverse();
        assert_eq!(sorted(compute(router_id(1), &rev)), routes);
    }

    #[test]
    fn asbr_flag_on_later_fragment_still_counts() {
        let (r1, r2) = (router_id(1), router_id(2));
        let lsas = vec![
            router_lsa(r1, vec![p2p(r2, 1, 1, 1)]),
            fragment(r2, 0, LSA_TYPE_ROUTER, 0, 0x13, vec![p2p(r1, 1, 1, 1)]),
            fragment(r2, 1, LSA_TYPE_ROUTER, lsa::ROUTER_FLAG_E, 0x99, vec![]),
        ];
        let view = intra_area_routes(r1, &lsas, &Context::default());
        assert_eq!(view.asbrs, vec![(r2, 1, 0x13)]);
    }

    #[test]
    fn legacy_and_e_router_overlap_adds_no_duplicate_edge() {
        let (r1, r2) = (router_id(1), router_id(2));
        let lsas = vec![
            fragment(r1, 0, LSA_TYPE_ROUTER, 0, 0, vec![p2p(r2, 1, 1, 1)]),
            fragment(r1, 0, LSA_TYPE_E_ROUTER, 0, 0, vec![p2p(r2, 1, 1, 1)]),
            router_lsa(r2, vec![p2p(r1, 1, 1, 1)]),
            link_lsa(r2, 1, "fe80::2".parse().unwrap()),
            router_prefix_lsa(r2, vec![("2001:db8:2::/64".parse().unwrap(), 1)]),
        ];
        let routes = compute(router_id(1), &lsas);
        assert_eq!(routes.len(), 1);
        let (merged, _, _) = routers_networks_links(&lsas);
        assert_eq!(merged[&r1].links.len(), 1);
    }

    #[test]
    fn transit_link_only_in_second_fragment() {
        let (r1, r2) = (router_id(1), router_id(2));
        let lsas = vec![
            fragment(r1, 0, LSA_TYPE_ROUTER, 0, 0, vec![]),
            fragment(r1, 1, LSA_TYPE_ROUTER, 0, 0, vec![transit(5, 1, r2, 1)]),
            router_lsa(r2, vec![transit(5, 7, r2, 1)]),
            network_lsa(5, r2, vec![r2, r1]),
            link_lsa(r2, 7, "fe80::2".parse().unwrap()),
            router_prefix_lsa(r2, vec![("2001:db8:2::/64".parse().unwrap(), 1)]),
        ];
        let routes = compute(r1, &lsas);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hop, "fe80::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn merge_flags_or_options_lowest_lsid_links_dedup_by_full_identity() {
        let (a, b) = (
            RouterLsaBody {
                flags: 1,
                options: 0xA,
                links: vec![p2p(router_id(2), 1, 1, 1)],
            },
            RouterLsaBody {
                flags: 2,
                options: 0xB,
                links: vec![p2p(router_id(2), 1, 1, 1), p2p(router_id(2), 1, 1, 9)],
            },
        );
        let m = merge_router_fragments(vec![
            (LSA_TYPE_ROUTER, Ipv4Addr::from(1), &b),
            (LSA_TYPE_ROUTER, Ipv4Addr::from(0), &a),
        ]);
        assert_eq!((m.flags, m.options), (3, 0xA));
        assert_eq!(m.links.len(), 2, "same link, other metric, is kept");
    }

    #[test]
    fn tie_at_lowest_lsid_takes_e_router_options_in_any_order() {
        let (l, e) = (
            RouterLsaBody {
                flags: 0,
                options: 1,
                links: vec![],
            },
            RouterLsaBody {
                flags: 0,
                options: 2,
                links: vec![],
            },
        );
        for frags in [
            vec![
                (LSA_TYPE_ROUTER, Ipv4Addr::from(0), &l),
                (LSA_TYPE_E_ROUTER, Ipv4Addr::from(0), &e),
            ],
            vec![
                (LSA_TYPE_E_ROUTER, Ipv4Addr::from(0), &e),
                (LSA_TYPE_ROUTER, Ipv4Addr::from(0), &l),
            ],
        ] {
            assert_eq!(merge_router_fragments(frags).options, 2);
        }
    }

    /// r1(root) - r2 symmetric; r2 claims a link to r9; r9 links back only
    /// when `back`. r9 owns a prefix.
    fn forged_chain(back: bool) -> Vec<Arc<Lsa>> {
        let (r1, r2, r9) = (router_id(1), router_id(2), router_id(9));
        vec![
            router_lsa(r1, vec![p2p(r2, 1, 1, 1)]),
            router_lsa(r2, vec![p2p(r1, 1, 1, 1), p2p(r9, 2, 1, 1)]),
            router_lsa(r9, if back { vec![p2p(r2, 1, 2, 1)] } else { vec![] }),
            link_lsa(r2, 1, "fe80::2".parse().unwrap()),
            router_prefix_lsa(r9, vec![("2001:db8:9::/64".parse().unwrap(), 1)]),
        ]
    }

    /// RFC 5340 §4.8.1: a one-sided p2p edge from a non-root router is not
    /// followed; with the link back it is.
    #[test]
    fn one_sided_p2p_edge_is_rejected() {
        assert_eq!(compute(router_id(1), &forged_chain(false)), []);
        assert_eq!(compute(router_id(1), &forged_chain(true)).len(), 1);
    }

    /// The distance-only (LFA) run applies the same check.
    #[test]
    fn distance_only_run_rejects_one_sided_edge() {
        let r9 = Vertex::Router(router_id(9));
        let run = |back| {
            let routers: Routers = forged_chain(back)
                .iter()
                .filter_map(|l| match &l.body {
                    LsaBody::Router(b) => Some((l.header.advertising_router, b.clone())),
                    _ => None,
                })
                .collect();
            run_dijkstra(
                router_id(2),
                &routers,
                &HashMap::new(),
                None,
                &Context::default(),
            )
            .0
        };
        assert!(!run(false).contains_key(&r9));
        assert!(run(true).contains_key(&r9));
    }

    /// Router to network needs the Network-LSA to list the router; network to
    /// router needs the router's transit link to the network.
    #[test]
    fn one_sided_network_edges_are_rejected() {
        let (r1, r2, r3) = (router_id(1), router_id(2), router_id(3));
        let build = |attached: Vec<Ipv4Addr>, r3_links: Vec<RouterLsaLink>| {
            vec![
                router_lsa(r1, vec![transit(7, 1, r2, 1)]),
                router_lsa(r2, vec![transit(7, 1, r2, 1)]),
                router_lsa(r3, r3_links),
                network_lsa(7, r2, attached),
                link_lsa(r2, 1, "fe80::2".parse().unwrap()),
                link_lsa(r3, 1, "fe80::3".parse().unwrap()),
                router_prefix_lsa(r3, vec![("2001:db8:3::/64".parse().unwrap(), 1)]),
            ]
        };
        let reaches_r3 = |lsas: Vec<Arc<Lsa>>| {
            compute(r1, &lsas)
                .iter()
                .any(|r| r.prefix == "2001:db8:3::/64".parse().unwrap())
        };
        let back = || vec![transit(7, 1, r2, 1)];
        assert!(reaches_r3(build(vec![r1, r2, r3], back())));
        assert!(!reaches_r3(build(vec![r1, r2, r3], vec![])));
        assert!(!reaches_r3(build(vec![r1, r2], back())));
        assert!(!reaches_r3(build(vec![r2, r3], back())));
    }

    /// #610, §12.4.3: the backbone view adds Inter-Area-Prefix/Router-LSAs of
    /// another ABR; `compute_in(.., &Context { skip_summaries: true, ..Context::default() })` ignores them (§16.2).
    #[test]
    fn backbone_view_and_skip_summaries() {
        use crate::lsa::{InterAreaPrefixLsaBody, InterAreaRouterLsaBody};
        let (root, abr, boundary) = (router_id(1), router_id(2), router_id(9));
        let prefix: Ipv6Net = "2001:db8:9::/64".parse().unwrap();
        let lsas = [
            router_lsa(root, vec![p2p(abr, 1, 2, 1)]),
            router_lsa(abr, vec![p2p(root, 2, 1, 1)]),
            Arc::new(Lsa {
                header: header(lsa::LSA_TYPE_INTER_AREA_PREFIX, router_id(100), abr),
                body: LsaBody::InterAreaPrefix(InterAreaPrefixLsaBody {
                    metric: 10,
                    prefix_options: 0,
                    prefix,
                }),
            }),
            Arc::new(Lsa {
                header: header(lsa::LSA_TYPE_INTER_AREA_ROUTER, boundary, abr),
                body: LsaBody::InterAreaRouter(InterAreaRouterLsaBody {
                    options: 0x13,
                    metric: 5,
                    destination_router_id: boundary,
                }),
            }),
        ];
        let view = backbone_view(root, &lsas, &Context::default());
        assert_eq!(view.inter_prefixes, [(prefix, 11)]);
        assert_eq!(view.inter_asbrs, [(boundary, 6, 0x13)]);
        assert_eq!(view.intra.asbrs.len(), 0);
    }

    fn a6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// root(1) with r2 (cost 1) and r3 (cost `c3`), both reaching r4 (cost 1).
    fn diamond(c3: u16) -> Vec<Arc<Lsa>> {
        let (r1, r2, r3, r4) = (router_id(1), router_id(2), router_id(3), router_id(4));
        vec![
            router_lsa(r1, vec![p2p(r2, 1, 1, 1), p2p(r3, 2, 1, c3)]),
            router_lsa(r2, vec![p2p(r1, 1, 1, 1), p2p(r4, 2, 1, 1)]),
            router_lsa(r3, vec![p2p(r1, 1, 2, c3), p2p(r4, 2, 2, 1)]),
            router_lsa(r4, vec![p2p(r2, 1, 2, 1), p2p(r3, 2, 2, 1)]),
            link_lsa(r2, 1, a6("fe80::2")),
            link_lsa(r3, 1, a6("fe80::3")),
            router_prefix_lsa(r4, vec![("2001:db8:4::/64".parse().unwrap(), 1)]),
        ]
    }

    #[test]
    fn diamond_equal_paths_give_two_sorted_hops() {
        let routes = compute(router_id(1), &diamond(1));
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metric, 3);
        assert_eq!(
            routes[0].next_hops,
            [(a6("fe80::2"), 1), (a6("fe80::3"), 2)]
        );
        assert_eq!(routes[0].next_hop, a6("fe80::2"));
    }

    #[test]
    fn diamond_unequal_paths_give_one_hop() {
        let routes = compute(router_id(1), &diamond(2));
        assert_eq!(routes[0].metric, 3);
        assert_eq!(routes[0].next_hops, [(a6("fe80::2"), 1)]);
    }

    /// root, r2, r3 share a transit network; both reach r4 over p2p links.
    #[test]
    fn transit_network_equal_paths_give_two_hops() {
        let (r1, r2, r3, r4) = (router_id(1), router_id(2), router_id(3), router_id(4));
        let lsas = vec![
            router_lsa(r1, vec![transit(5, 1, r2, 1)]),
            router_lsa(r2, vec![transit(5, 1, r2, 1), p2p(r4, 2, 1, 1)]),
            router_lsa(r3, vec![transit(5, 1, r2, 1), p2p(r4, 2, 2, 1)]),
            router_lsa(r4, vec![p2p(r2, 1, 2, 1), p2p(r3, 2, 2, 1)]),
            network_lsa(5, r2, vec![r1, r2, r3]),
            link_lsa(r2, 1, a6("fe80::2")),
            link_lsa(r3, 1, a6("fe80::3")),
            router_prefix_lsa(r4, vec![("2001:db8:4::/64".parse().unwrap(), 1)]),
        ];
        let routes = compute(r1, &lsas);
        let r = routes.iter().find(|r| r.metric == 3).unwrap();
        assert_eq!(r.next_hops, [(a6("fe80::2"), 1), (a6("fe80::3"), 1)]);
    }

    /// Two equal links to ONE neighbor are one hop (#618: the cheapest link).
    #[test]
    fn parallel_links_to_one_neighbor_are_one_hop() {
        let (r1, r2) = (router_id(1), router_id(2));
        let lsas = vec![
            router_lsa(r1, vec![p2p(r2, 1, 1, 1), p2p(r2, 2, 2, 1)]),
            router_lsa(r2, vec![p2p(r1, 1, 1, 1), p2p(r1, 2, 2, 1)]),
            link_lsa(r2, 1, a6("fe80::2")),
            link_lsa(r2, 2, a6("fe80::22")),
            router_prefix_lsa(r2, vec![("2001:db8:2::/64".parse().unwrap(), 1)]),
        ];
        let routes = compute(r1, &lsas);
        assert_eq!(routes[0].next_hops, [(a6("fe80::2"), 1)]);
    }

    #[test]
    fn inter_area_and_external_via_equal_cost_paths_to_the_border_router() {
        let r4 = router_id(4);
        let mut lsas = diamond(1);
        lsas[3] = with_flags(&lsas[3], lsa::ROUTER_FLAG_B | lsa::ROUTER_FLAG_E);
        lsas.push(inter_area_prefix(r4, "2001:db8:99::/64", 10));
        lsas.push(external(r4, "2001:db8:77::/64"));
        let routes = compute(router_id(1), &lsas);
        for pfx in ["2001:db8:99::/64", "2001:db8:77::/64"] {
            let r = routes.iter().find(|r| r.prefix.to_string() == pfx).unwrap();
            assert_eq!(r.next_hops.len(), 2, "{pfx}");
        }
    }

    #[test]
    fn equal_cost_prefix_from_two_routers_unions_hops() {
        let net: Ipv6Net = "2001:db8:8::/64".parse().unwrap();
        let mut lsas = diamond(1);
        lsas.push(router_prefix_lsa(router_id(2), vec![(net, 2)]));
        lsas.push(router_prefix_lsa(router_id(3), vec![(net, 2)]));
        let routes = compute(router_id(1), &lsas);
        let r = routes.iter().find(|r| r.prefix == net).unwrap();
        assert_eq!(r.next_hops.len(), 2);
    }

    /// An LFA must differ from every member of the ECMP set.
    #[test]
    fn backup_differs_from_every_ecmp_member() {
        let mut lsas = diamond(1);
        // r1 also peers r5, which reaches r4.
        let (r1, r4, r5) = (router_id(1), router_id(4), router_id(5));
        lsas[0] = router_lsa(
            r1,
            vec![
                p2p(router_id(2), 1, 1, 1),
                p2p(router_id(3), 2, 1, 1),
                p2p(r5, 3, 1, 1),
            ],
        );
        lsas[3] = router_lsa(
            r4,
            vec![
                p2p(router_id(2), 1, 2, 1),
                p2p(router_id(3), 2, 2, 1),
                p2p(r5, 3, 2, 1),
            ],
        );
        lsas.push(router_lsa(r5, vec![p2p(r1, 1, 3, 1), p2p(r4, 2, 3, 1)]));
        lsas.push(link_lsa(r5, 1, a6("fe80::5")));
        let routes = compute(r1, &lsas);
        let r = &routes[0];
        assert_eq!(r.next_hops.len(), 3);
        assert_eq!(r.backup_next_hop, None);
        assert_ne!(r.backup_next_hop, Some(a6("fe80::2")));
    }
}
