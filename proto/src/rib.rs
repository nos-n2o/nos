use std::net::IpAddr;

use ipnet::IpNet;
use nos_proto_derive::View;
use serde::{Deserialize, Serialize};

/// Wire twin of `nos-rib`'s internal `RouteSource` — kept separate so
/// `nos-rib`'s own domain type doesn't need to derive wire traits it has no
/// other use for.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteSourceKind {
    /// A statically configured route.
    Static,
    /// A route learned via BGP.
    Bgp,
    /// A route learned via OSPF.
    Ospf,
    /// A directly-connected prefix, derived by `nos-ribd` from the
    /// addresses `nos-interfaced` applied in this table.
    Connected,
    /// An EVPN Type-5 (RFC 9136) route received over the table's L3 VNI.
    Evpn,
    /// A VPN-IPv4/IPv6 (RFC 4364) route imported by Route Target from the
    /// underlay `nos-bgpd`'s VPN Adj-RIB-In. Appended (postcard indexes
    /// variants by position).
    Vpn,
}

impl RouteSourceKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Static,
        Self::Bgp,
        Self::Ospf,
        Self::Connected,
        Self::Evpn,
        Self::Vpn,
    ];

    /// The lowercase name the CLI and REST filters use.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Bgp => "bgp",
            Self::Ospf => "ospf",
            Self::Connected => "connected",
            Self::Evpn => "evpn",
            Self::Vpn => "vpn",
        }
    }
}

impl std::fmt::Display for RouteSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for RouteSourceKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .ok_or_else(|| {
                format!("unknown route source `{s}` (static, bgp, ospf, connected, evpn, vpn)")
            })
    }
}

/// Selection for `GetRoutesPage` (#1445). Empty (the default): every prefix.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteFilter {
    /// Only prefixes with a candidate of this source, and only those
    /// candidates.
    pub source: Option<RouteSourceKind>,
    /// Only this prefix (exact), or with `longer` it and everything under it.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub prefix: Option<IpNet>,
    /// With `prefix`: match the prefix and every longer prefix it covers.
    /// Ignored without `prefix`.
    pub longer: bool,
}

/// Candidates of one source in a table, per address family.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, View)]
pub struct SourceCount {
    /// The source.
    #[view(brief, text)]
    pub source: RouteSourceKind,
    /// IPv4 candidates.
    #[view(brief, header = "ipv4", unit = count)]
    pub ipv4: u32,
    /// IPv6 candidates.
    #[view(brief, header = "ipv6", unit = count)]
    pub ipv6: u32,
}

/// One routing table's summary, for `show route summary` and the table list.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, View)]
pub struct RibSummary {
    /// The routing table's name.
    #[view(brief, sort)]
    pub table: String,
    /// The VRF device backing it; `None` until created (or with the noop
    /// driver).
    #[view(brief)]
    pub vrf: Option<String>,
    /// The kernel routing table id; `None` as for `vrf`.
    #[view(brief, header = "kernel-table", unit = count)]
    pub kernel_table: Option<u32>,
    /// Distinct IPv4 prefixes.
    #[view(brief, header = "ipv4", unit = count)]
    pub ipv4_prefixes: u32,
    /// Distinct IPv6 prefixes.
    #[view(brief, header = "ipv6", unit = count)]
    pub ipv6_prefixes: u32,
    /// Candidates per source (only sources with one), declaration order.
    #[view(nested)]
    pub sources: Vec<SourceCount>,
}

/// Where a `Vpn`-sourced candidate came from: the remote PE (the BGP next
/// hop, resolved in the underlay into the candidate's gateway) and the
/// Route Distinguisher it was received under.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnRouteInfo {
    /// The remote PE: the VPN route's BGP next hop.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub pe_next_hop: IpAddr,
    /// `asn:nn` or `a.b.c.d:nn`.
    pub rd: String,
}

/// One next hop of a route: a gateway, the local kernel interface it leaves
/// over when known, and the MPLS label stack pushed toward it (outermost
/// first; empty for a plain IP hop). `nos-ribd`'s `RibEntry` and its Linux
/// driver carry one per hop, so two hops to the same gateway with different
/// labels stay distinct (#594).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NextHop {
    /// The gateway.
    pub gateway: IpAddr,
    /// The ifindex it is reachable over, when the source knows it.
    pub interface_id: Option<u32>,
    /// The label stack pushed toward `gateway`.
    pub labels: Vec<u32>,
}

impl From<(IpAddr, Option<u32>)> for NextHop {
    /// An unlabelled hop.
    fn from((gateway, interface_id): (IpAddr, Option<u32>)) -> Self {
        Self {
            gateway,
            interface_id,
            labels: Vec::new(),
        }
    }
}

/// What an `Evpn`-sourced candidate is reached through: the remote VTEP (its
/// one gateway), the remote PE's Router's MAC and the L3 VNI.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvpnRouteInfo {
    /// Remote VTEP the route is tunnelled to.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub vtep: IpAddr,
    /// `aa:bb:cc:dd:ee:ff`.
    pub router_mac: String,
    /// VXLAN VNI of the tunnel.
    pub vni: u32,
}

/// One candidate route for a prefix.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "wire flags, one per independent fact"
)]
pub struct RouteEntry {
    /// Every next hop of this candidate — two or more is an equal-cost
    /// multipath (ECMP) route, installed as one kernel route.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub gateways: Vec<IpAddr>,
    /// Protocol that produced the route.
    pub source: RouteSourceKind,
    /// Pre-computed backup next hop, installed in the kernel at a higher
    /// metric so it takes over the instant the primary is withdrawn.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub backup: Option<IpAddr>,
    /// A discard (blackhole) route — no gateway; e.g. an OSPF ABR's route
    /// for one of its advertised area ranges (RFC 2328 §3.5).
    #[serde(default)]
    pub discard: bool,
    /// Set on an `Evpn` candidate.
    #[serde(default)]
    pub evpn: Option<EvpnRouteInfo>,
    /// `backup` is an RFC 7490 remote LFA: the PQ node the backup tunnels
    /// (IP-in-IP) to, not a neighbor.
    #[serde(default)]
    pub backup_tunnel: bool,
    /// The MPLS label stack each of `gateways` is forwarded with (RFC 4364
    /// section 4.3.4), outermost first, in `gateways` order; every stack is
    /// empty for a source other than `Vpn`.
    #[serde(default)]
    pub mpls_labels: Vec<Vec<u32>>,
    /// The PE and RD each of `gateways` came from, in `gateways` order, on a
    /// `Vpn` candidate; empty otherwise.
    #[serde(default)]
    pub vpn: Vec<VpnRouteInfo>,
    /// `discard` came from a BGP RFC 7999 blackhole or a static `blackhole`
    /// (an OSPF ABR discard stays `false`).
    #[serde(default)]
    pub blackhole: bool,
    /// The route's metric (an OSPF SPF cost, a BGP best path's MED); `None`
    /// for a source without one.
    #[serde(default)]
    pub metric: Option<u32>,
    /// The source's administrative preference (lower wins).
    #[serde(default)]
    pub preference: u8,
    /// Seconds since the candidate last appeared or its next hops changed
    /// (reset when `nos-ribd` restarts).
    #[serde(default)]
    pub age_secs: u64,
    /// The local interface each of `gateways` leaves over, in `gateways`
    /// order; `None` where unknown (loopback, bond and SVI are not named).
    #[serde(default)]
    pub interfaces: Vec<Option<String>>,
    /// The candidate is the one `nos-ribd` handed to the kernel (logical, not
    /// read back: false for a `Connected` route, a loser, or while a kernel
    /// write is pending retry).
    #[serde(default)]
    pub installed: bool,
    /// The route's tag (a static route's `tag`); `None` where the source has none.
    #[serde(default)]
    pub tag: Option<u32>,
}

/// One prefix's full candidate list, ordered best (winner) to worst by
/// source preference.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrefixRoutes {
    /// The destination prefix.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cfg_attr(feature = "arbitrary", arbitrary(with = crate::arbitrary_support::ip_net))]
    pub prefix: IpNet,
    /// All candidate routes for the prefix.
    pub candidates: Vec<RouteEntry>,
}

impl PrefixRoutes {
    /// Encoded size on the wire, for budgeting a `RoutesPage` reply.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        postcard::to_allocvec(self).map_or(0, |v| v.len())
    }
}

/// One BGP-learned best-path route, pushed by the owning `nos-bgpd`
/// instance for kernel installation. Always peer-learned — a `Local`-origin
/// (redistributed-from-static) loc-rib entry has no real next-hop and is
/// never pushed at all, to avoid a pointless static→bgp→rib→kernel round
/// trip on the same table it came from.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BgpRoute {
    /// The destination prefix.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cfg_attr(feature = "arbitrary", arbitrary(with = crate::arbitrary_support::ip_net))]
    pub prefix: IpNet,
    /// The best path's next hop plus every multipath sibling's
    /// (`BgpInstance.maximum_paths`), sorted, never empty unless `discard`. Two or more
    /// become one `RTA_MULTIPATH` kernel route.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub next_hops: Vec<IpAddr>,
    /// Runner-up path's next hop (none of `next_hops`), if any.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub backup_next_hop: Option<IpAddr>,
    /// An RFC 7999 blackhole: install a discard route; `next_hops` is empty.
    #[serde(default)]
    pub discard: bool,
    /// The best path's `MULTI_EXIT_DISC`, for `show route`.
    #[serde(default)]
    pub metric: Option<u32>,
    /// The best path was learned from an iBGP peer (confed-external counts
    /// as eBGP); `nos-ribd` picks the administrative distance from it.
    #[serde(default)]
    pub ibgp: bool,
}

/// Sent by the owning `nos-bgpd` instance to `nos-ribd` over a persistent,
/// long-lived connection (mirroring `RedistributeUpdate`'s pattern for the
/// opposite direction): a `Full` snapshot on connect, then incremental
/// `Add`/`Remove` for each subsequent change. A push is cut into frames by
/// [`BgpRouteUpdate::frames`] so none exceeds the codec's `MAX_FRAME`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BgpRouteUpdate {
    /// The complete route set, replacing any previous one — together with
    /// every `FullPart` received since the last `Full` on this connection.
    Full(Vec<BgpRoute>),
    /// One route added or changed.
    Add(BgpRoute),
    /// One route withdrawn.
    Remove(IpNet),
    /// The leading part of a `Full` snapshot too large for one frame: the
    /// receiver stages it and publishes nothing until the closing `Full`.
    /// Appended (postcard indexes variants by position).
    FullPart(Vec<BgpRoute>),
}

/// Most routes one `PushBgpRoutes` frame carries. A worst-case route (IPv6
/// prefix, 255 IPv6 multipath next hops, IPv6 backup) encodes to ~4.4 KB,
/// so 2048 of them stay under the 16 MiB `MAX_FRAME` (pinned by a test).
pub const BGP_PUSH_CHUNK: usize = 2048;

impl BgpRouteUpdate {
    /// Routes this update carries, for frame budgeting (at least 1).
    fn weight(&self) -> usize {
        match self {
            Self::Full(r) | Self::FullPart(r) => r.len().max(1),
            Self::Add(_) | Self::Remove(_) => 1,
        }
    }

    /// Cuts one push into `PushBgpRoutes` frames of at most
    /// [`BGP_PUSH_CHUNK`] routes each, in order: a larger `Full` becomes
    /// `FullPart`s closed by a `Full` holding the last chunk, so the
    /// receiver still swaps the whole set at once.
    #[must_use]
    pub fn frames(updates: Vec<Self>) -> Vec<Vec<Self>> {
        let mut split = Vec::with_capacity(updates.len());
        for u in updates {
            match u {
                Self::Full(routes) if routes.len() > BGP_PUSH_CHUNK => {
                    let (parts, last) = crate::chunk::split_full(routes, BGP_PUSH_CHUNK, |_| 1);
                    split.extend(parts.into_iter().map(Self::FullPart));
                    split.push(Self::Full(last));
                }
                u => split.push(u),
            }
        }
        let (mut frames, mut cur, mut weight) = (Vec::new(), Vec::new(), 0);
        for u in split {
            let w = u.weight();
            if weight + w > BGP_PUSH_CHUNK && !cur.is_empty() {
                frames.push(std::mem::take(&mut cur));
                weight = 0;
            }
            cur.push(u);
            weight += w;
        }
        if !cur.is_empty() {
            frames.push(cur);
        }
        frames
    }
}

/// One SPF-computed OSPF route, pushed by the owning `nos-ospfd` instance
/// for kernel installation — the OSPF analogue of `BgpRoute`. Never a
/// directly-connected destination (root's own subnet) — see
/// `ospf::spf::compute`'s directly-connected filter.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OspfRoute {
    /// The destination prefix.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cfg_attr(feature = "arbitrary", arbitrary(with = crate::arbitrary_support::ip_net))]
    pub prefix: IpNet,
    /// Every equal-cost next hop (RFC 2328 §16.1 2(d)), non-empty unless
    /// `discard` is set, each
    /// with the local kernel interface (ifindex) it is reachable over when
    /// the pushing daemon knows it — always `Some` from `nos-ospfv3d`
    /// (RFC 5340 next-hops are link-local IPv6 addresses, which Linux's
    /// netlink `RTM_NEWROUTE` rejects with EINVAL unless an outgoing
    /// interface is given alongside the gateway; `OSPFv3`'s own SPF already
    /// derives it, since a first-hop link-local address is only meaningful
    /// relative to the specific local link it was learned on — see
    /// `ospfv3::spf`'s module doc comment), always `None` from `nos-ospfd`
    /// (RFC 2328 next-hops are ordinary routable IPv4 addresses, which the
    /// kernel resolves via its own routing table without needing one).
    /// Two or more become one `RTA_MULTIPATH` kernel route.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<Object>))]
    pub next_hops: Vec<(IpAddr, Option<u32>)>,
    /// RFC 5286 loop-free alternate next hop, if one exists.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub backup_next_hop: Option<IpAddr>,
    /// The ifindex of `backup_next_hop` (which may leave over a
    /// different link than the primary).
    pub backup_interface_id: Option<u32>,
    /// SPF cost to `prefix` — what BGP's RFC 4271 §9.1.2.2(d) step compares
    /// (via `RibRequest::IgpCosts`) for paths whose `NEXT_HOP` falls in it.
    pub metric: u32,
    /// A discard route: an ABR's blackhole for one of its active advertised
    /// area ranges (RFC 2328 §3.5), so traffic to an unused part of the
    /// range is dropped rather than looping on a covering route.
    /// `next_hops` is empty and `backup_next_hop` `None` when set.
    #[serde(default)]
    pub discard: bool,
    /// RFC 7490 remote LFA: the PQ node (its loopback) to tunnel to when
    /// the primary fails — set only when `backup_next_hop` is `None`.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[serde(default)]
    pub backup_tunnel: Option<IpAddr>,
    /// The MPLS label stack pushed toward each of `next_hops` (outermost
    /// first), in `next_hops` order; empty, or an empty stack, is a plain IP
    /// hop (segment routing, #1165).
    #[serde(default)]
    pub next_hop_labels: Vec<Vec<u32>>,
    /// The SPF path class, for the per-class administrative distance;
    /// `None` is intra-area.
    #[serde(default)]
    pub class: Option<crate::ospf::RoutePathClass>,
}

/// One incoming-label-map (ILM) entry: what a labelled packet arriving with
/// `label` becomes (segment routing, #1165). Each hop is a next hop with
/// the stack it is sent with: a non-empty stack is a swap, an empty one a
/// pop (PHP, or a transit pop). No hop is a pop followed by an IP lookup in
/// this table. Pushed by the OSPF daemons with `RibRequest::PushMplsRoutes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlmRoute {
    /// The incoming label; must be 16..=1048574 (RFC 3032 reserved range).
    pub label: u32,
    /// Where it goes, several are one ECMP route. `interface_id` is the
    /// egress ifindex when the pusher knows it; else `nos-ribd` resolves it.
    pub hops: Vec<NextHop>,
}

/// Sent by the owning `nos-ospfd` instance to `nos-ribd` over a persistent,
/// long-lived connection — the OSPF analogue of `BgpRouteUpdate`, same
/// `Full`-on-connect-then-incremental shape. A push is cut into frames by
/// [`OspfRouteUpdate::frames`] so none exceeds the codec's `MAX_FRAME`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OspfRouteUpdate {
    /// The complete route set, replacing any previous one — together with
    /// every `FullPart` received since the last `Full` on this connection.
    Full(Vec<OspfRoute>),
    /// One route added or changed.
    Add(OspfRoute),
    /// One route withdrawn.
    Remove(IpNet),
    /// The leading part of a `Full` snapshot too large for one frame: the
    /// receiver stages it and publishes nothing until the closing `Full`.
    /// Appended (postcard indexes variants by position).
    FullPart(Vec<OspfRoute>),
}

/// Most weight one `PushOspfRoutes` frame carries, a route weighing its next
/// hop count plus one. The densest worst case (IPv6 everything, no next hop,
/// every optional field set) is ~70 B per unit, so a frame stays near
/// 4.5 MiB, under the 16 MiB `MAX_FRAME` (pinned by a test).
pub const OSPF_PUSH_CHUNK: usize = 65536;

/// The budget [`OspfRouteUpdate::frames`] uses: [`OSPF_PUSH_CHUNK`], or
/// `NOS_OSPF_PUSH_CHUNK` when set (a test hook, so tests and dev runs need
/// few routes). Not usable under the watchdog, which clears its children's
/// environment.
#[must_use]
pub fn ospf_push_chunk() -> usize {
    parse_chunk(std::env::var("NOS_OSPF_PUSH_CHUNK").ok().as_deref())
}

fn parse_chunk(raw: Option<&str>) -> usize {
    raw.and_then(|s| s.trim().parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(OSPF_PUSH_CHUNK)
}

impl OspfRoute {
    /// Frame budget weight: one per next hop and per pushed label, plus one
    /// for the route itself.
    fn weight(&self) -> usize {
        self.next_hops.len() + 1 + self.next_hop_labels.iter().map(Vec::len).sum::<usize>()
    }
}

impl OspfRouteUpdate {
    fn weight(&self) -> usize {
        match self {
            Self::Full(r) | Self::FullPart(r) => {
                r.iter().map(OspfRoute::weight).sum::<usize>().max(1)
            }
            Self::Add(r) => r.weight(),
            Self::Remove(_) => 1,
        }
    }

    /// [`Self::frames_with`] at [`ospf_push_chunk`].
    #[must_use]
    pub fn frames(updates: Vec<Self>) -> Vec<Vec<Self>> {
        Self::frames_with(updates, ospf_push_chunk())
    }

    /// Cuts one push into `PushOspfRoutes` frames of at most `chunk` weight
    /// each, in order: a heavier `Full` becomes `FullPart`s closed by a
    /// `Full` holding the last chunk, so the receiver still swaps the whole
    /// set at once (see [`VpnRouteUpdate::frames`]).
    #[must_use]
    pub fn frames_with(updates: Vec<Self>, chunk: usize) -> Vec<Vec<Self>> {
        let mut split = Vec::with_capacity(updates.len());
        for u in updates {
            match u {
                Self::Full(routes) => {
                    let (parts, last) = crate::chunk::split_full(routes, chunk, OspfRoute::weight);
                    split.extend(parts.into_iter().map(Self::FullPart));
                    split.push(Self::Full(last));
                }
                u => split.push(u),
            }
        }
        let (mut frames, last) = crate::chunk::split_full(split, chunk, Self::weight);
        if !last.is_empty() {
            frames.push(last);
        }
        frames
    }
}

/// One path of a `VpnRoute`: a received VPN route's PE, RD and label stack,
/// with the PE resolved in the underlay table (`ResolveNextHop`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnPath {
    /// The remote PE: the VPN route's BGP next hop.
    pub pe_next_hop: IpAddr,
    /// `asn:nn` or `a.b.c.d:nn`.
    pub rd: String,
    /// The PE's gateway in the underlay table.
    pub gateway: IpAddr,
    /// The ifindex `gateway` leaves over, when known.
    pub interface_id: Option<u32>,
    /// The received label stack, outermost first.
    pub labels: Vec<u32>,
}

/// One VPN route imported into a customer table by the underlay `nos-bgpd`
/// (RFC 4364 section 4.3.2), RD stripped: every selected path among the
/// received VPN routes whose Route Targets match the table's import set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnRoute {
    /// The customer prefix.
    pub prefix: IpNet,
    /// One next hop each, never empty, sorted by PE then labels.
    pub paths: Vec<VpnPath>,
}

/// `PushVpnRoutes`' payload: `Full` on connect, then `Add`/`Remove`, like
/// `BgpRouteUpdate`; cut into frames by [`VpnRouteUpdate::frames`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VpnRouteUpdate {
    /// The complete imported set, replacing any previous one — together with
    /// every `FullPart` received since the last `Full` on this connection.
    Full(Vec<VpnRoute>),
    /// One route added or changed.
    Add(VpnRoute),
    /// One route no longer imported.
    Remove(IpNet),
    /// The leading part of a `Full` snapshot too large for one frame: the
    /// receiver stages it and publishes nothing until the closing `Full`.
    /// Appended (postcard indexes variants by position).
    FullPart(Vec<VpnRoute>),
}

/// Most weight one `PushVpnRoutes` frame carries, a route weighing its path
/// count plus one. A worst-case path (IPv6 PE and gateway, the longest RD
/// text, 28 labels) encodes to ~200 B, so a frame stays near 7 MiB, under
/// the 16 MiB `MAX_FRAME` (pinned by a test).
pub const VPN_PUSH_CHUNK: usize = 32768;

impl VpnRoute {
    /// Frame budget weight: one per path, plus one for the route itself.
    fn weight(&self) -> usize {
        self.paths.len() + 1
    }
}

impl VpnRouteUpdate {
    fn weight(&self) -> usize {
        match self {
            Self::Full(r) | Self::FullPart(r) => {
                r.iter().map(VpnRoute::weight).sum::<usize>().max(1)
            }
            Self::Add(r) => r.weight(),
            Self::Remove(_) => 1,
        }
    }

    /// Cuts one push into `PushVpnRoutes` frames of at most
    /// [`VPN_PUSH_CHUNK`] weight each, in order: a heavier `Full` becomes
    /// `FullPart`s closed by a `Full` holding the last chunk, so the receiver
    /// still swaps the whole set at once (see [`BgpRouteUpdate::frames`]).
    #[must_use]
    pub fn frames(updates: Vec<Self>) -> Vec<Vec<Self>> {
        let mut split = Vec::with_capacity(updates.len());
        for u in updates {
            match u {
                Self::Full(routes) => {
                    let (parts, last) =
                        crate::chunk::split_full(routes, VPN_PUSH_CHUNK, VpnRoute::weight);
                    split.extend(parts.into_iter().map(Self::FullPart));
                    split.push(Self::Full(last));
                }
                u => split.push(u),
            }
        }
        // Greedy packing of whole updates is `split_full` again.
        let (mut frames, last) = crate::chunk::split_full(split, VPN_PUSH_CHUNK, Self::weight);
        if !last.is_empty() {
            frames.push(last);
        }
        frames
    }
}

/// One answer of `RibRequest::ResolveNextHop`: how the table reaches an
/// address through its non-BGP routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedNextHop {
    /// The covering route's gateway, or the address itself when it is on a
    /// directly connected prefix (on-link).
    pub gateway: IpAddr,
    /// The ifindex the gateway is reached over, when the covering route
    /// knows it. Always `None` for a `Connected` route (`nos-ribd` has no
    /// ifindex for connected prefixes): the kernel MPLS install (#581) must
    /// find the device with its own route lookup in the underlay table.
    pub interface_id: Option<u32>,
    /// The covering route's source.
    pub source: RouteSourceKind,
}

/// Messages sent from a client to a `nos-ribd` instance's IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum RibRequest {
    /// Deprecated (#713): answered with `RibEvent::Error`; use
    /// `GetRoutesPage`. The slot stays because postcard indexes by position.
    GetRoutes,
    /// One-shot: longest-prefix-match lookup for one destination address.
    Lookup {
        /// Address to look up.
        addr: IpAddr,
    },
    /// One-shot: this table's Linux VRF interface name, if its driver has
    /// allocated/created one. The only cross-daemon consumer today is
    /// `nos-interfaced`'s Linux driver, resolving which device to enslave
    /// an interface into — see `docs/architecture/endpoint-broker.md`
    /// section for how it finds this instance's socket
    /// (`ServiceRef::RibTable`). No table name is carried on the request:
    /// which table you're asking about is implicit in which per-table
    /// `nos-ribd` socket you connected to, exactly like `GetRoutes`/
    /// `Lookup` above.
    GetVrfName,
    /// One-shot: this table's allocated kernel table id, if any — backs
    /// loopback kernel device naming (`lo<table_id>`) in `nos-interfaced`'s
    /// Linux driver. Symmetric to `GetVrfName`; no table name carried, same
    /// reasoning.
    GetTableId,
    /// Fire-and-forget, no reply — sent continuously by the owning
    /// `nos-bgpd` instance over one long-lived connection, mirroring
    /// `BgpRequest::RedistributeRoutes`'s pattern for the opposite
    /// direction. One or more updates from a single poll tick, batched
    /// into one message rather than one `PushBgpRoutes` per update — the
    /// receiving `nos-ribd` applies the whole batch to its in-memory `Rib`
    /// first, then touches the kernel once for the prefixes whose winning
    /// route actually changed, never once per update.
    PushBgpRoutes(Vec<BgpRouteUpdate>),
    /// Fire-and-forget, no reply — sent continuously by the owning
    /// `nos-ospfd` instance over one long-lived connection, the OSPF
    /// analogue of `PushBgpRoutes` above (its own SPF computation, not BGP
    /// best-path selection, is what changes here). `instance` is the pushing
    /// daemon's instance name: `nos-ribd` keeps one route set per
    /// `(daemon family, instance)`, so a `Full` replaces only that instance's
    /// routes (#1277).
    PushOspfRoutes {
        /// The OSPF instance name (`ospf_instance`/`ospfv3_instance`).
        instance: String,
        /// The batch, applied in order.
        updates: Vec<OspfRouteUpdate>,
    },
    /// One-shot: the IGP cost of every prefix whose best non-BGP candidate
    /// is known (`Static` = 0, `Ospf` = its SPF metric). BGP resolves each
    /// path's `NEXT_HOP` against this for decision step (d); `Bgp`-sourced
    /// routes are excluded so a next hop never resolves recursively.
    IgpCosts,
    /// Fire-and-forget, no reply, `nos-bgpd` only: every EVPN Type-5 route
    /// the underlay instance named by this table's `evpn.bgp_instance`
    /// received (`Full` on connect, then `Add`/`Remove`). Route-Target and
    /// VNI filtering is `nos-ribd`'s.
    PushEvpnRoutes(crate::fdb::EvpnUpdate),
    /// One-shot, `nos-bgpd` only: how many `Bgp`-sourced candidates this
    /// table still holds. A restarted `nos-bgpd` asks it once at startup:
    /// more than zero means its forwarding state survived (RFC 4724 §4.1),
    /// so it restarts gracefully (F bit, selection deferral).
    BgpRouteCount,
    /// One-shot, `nos-fdbd` only: this table's EVPN IP-VRF, for RFC 9135
    /// symmetric IRB (Label2 + Router's MAC on a domain's MAC+IP routes).
    GetEvpnIrb,
    /// Fire-and-forget, no reply, `nos-bgpd` only: the VPN routes the
    /// underlay instance named by this table's `vpn.bgp_instance` imports
    /// into it (`Full` on connect, then `Add`/`Remove`), stored as the `Vpn`
    /// source. Route-Target matching and best path are `nos-bgpd`'s.
    PushVpnRoutes(Vec<VpnRouteUpdate>),
    /// One-shot: resolves each address by longest-prefix match over this
    /// table's non-BGP candidates (`Bgp`/`Evpn`/`Vpn` never count, like
    /// `IgpCosts`), answered by `RibEvent::NextHops` in the same order.
    /// `nos-bgpd` asks its own (underlay) table for its VPN PE next hops.
    ResolveNextHop {
        /// The addresses to resolve.
        addrs: Vec<IpAddr>,
    },
    /// One-shot: this table's VPN label (`show route`'s header), the
    /// explicit `vpn.label` or the one allocated; `None` without `vpn`.
    GetVpnLabel,
    /// One-shot: up to `limit` prefixes strictly after `after` (`None`: from
    /// the start), each with its full candidate list, in ascending CIDR
    /// order; answered by `RibEvent::RoutesPage` (#713). Keyset paging, no
    /// snapshot: a table that changes mid-walk never loops or repeats a
    /// prefix, but may skip or include a concurrent change. `nos-ribd`
    /// clamps `limit` to [`ROUTES_PAGE_MAX`] (0 means the maximum).
    GetRoutesPage {
        /// Cursor: the last prefix of the previous page.
        after: Option<IpNet>,
        /// Most prefixes wanted.
        limit: u32,
        /// Which prefixes (and candidates) to return (#1445); the cursor
        /// walks the filtered set.
        filter: RouteFilter,
    },
    /// Fire-and-forget, `nos-ospfd`/`nos-ospfv3d` only (#1165): the complete
    /// ILM set of one OSPF instance (segment routing), replacing its previous
    /// one. `instance` must equal the pusher's identity name, as for
    /// `PushOspfRoutes`. An instance's labels are removed from the kernel
    /// when it pushes an empty set or leaves the config.
    PushMplsRoutes {
        /// The OSPF instance name.
        instance: String,
        /// The whole ILM set.
        routes: Vec<IlmRoute>,
    },
    /// One-shot: this table's [`RibSummary`], answered by
    /// `RibEvent::Summary` (#1445). Appended (postcard indexes by position).
    GetSummary,
}

/// Most prefixes `nos-ribd` returns in one `RoutesPage`, and the default
/// page size of `show route` and `GET /v1/routes/{table}`.
pub const ROUTES_PAGE_MAX: u32 = 1000;

/// Reply to `GetEvpnIrb`: what a MAC+IP route needs to be symmetric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvpnIrb {
    /// L3 VNI of the IP-VRF (RFC 9135), if any.
    pub l3_vni: u32,
    /// The IP-VRF's Router's MAC (`brv<l3-vni>`'s address).
    pub router_mac: [u8; 6],
    /// The IP-VRF's export Route Targets, as extended communities.
    pub route_targets_export: Vec<u64>,
}

/// Messages sent from a `nos-ribd` instance to a client.
#[derive(Debug, Serialize, Deserialize)]
pub enum RibEvent {
    /// Unused since #713 (`GetRoutes` is gone); the slot stays for the
    /// wire indexes.
    Routes(Vec<PrefixRoutes>),
    /// Reply to `Lookup` when a covering prefix exists.
    Match(PrefixRoutes),
    /// Reply to `Lookup` when no configured prefix covers the address (no
    /// default route).
    NoMatch,
    /// A human-readable error message from the daemon.
    Error(String),
    /// Reply to `GetVrfName`. `None` if no VRF has been allocated/created
    /// yet (or the running driver never backs a table with a real VRF at
    /// all, e.g. a no-op driver) — a normal, expected transient state, not
    /// an error.
    VrfName(Option<String>),
    /// Reply to `GetTableId`. `None` under the same conditions as
    /// `VrfName(None)` — normal/transient, never an error.
    TableId(Option<u32>),
    /// Reply to `IgpCosts`.
    IgpCosts(Vec<(IpNet, u32)>),
    /// Reply to `BgpRouteCount`.
    BgpRouteCount(u32),
    /// Reply to `GetEvpnIrb`. `None` until the IP-VRF is up (an L3 VNI, its
    /// VTEP and the Router's MAC known; never with `--driver noop`).
    EvpnIrb(Option<EvpnIrb>),
    /// Reply to `ResolveNextHop`, one entry per address (`None`:
    /// unresolvable).
    NextHops(Vec<Option<ResolvedNextHop>>),
    /// Reply to `GetVpnLabel`.
    VpnLabel(Option<u32>),
    /// Reply to `GetRoutesPage`: up to `limit` prefixes (fewer when the
    /// reply hit its byte budget) in ascending CIDR order. `next` is the last
    /// prefix returned, to pass back as `after`; `None` on the last page.
    RoutesPage {
        /// The page, ascending CIDR order.
        routes: Vec<PrefixRoutes>,
        /// Cursor for the next page; `None` on the last.
        next: Option<IpNet>,
    },
    /// Reply to `GetSummary`.
    Summary(RibSummary),
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use tokio_util::codec::Encoder;

    use super::*;
    use crate::codec::{IpcCodec, MAX_FRAME};

    fn route(i: u32) -> BgpRoute {
        BgpRoute {
            ibgp: false,
            prefix: IpNet::new(IpAddr::from(i.to_be_bytes()), 32).unwrap(),
            next_hops: vec![IpAddr::from([10, 0, 0, 1])],
            backup_next_hop: None,
            discard: false,
            metric: None,
        }
    }

    fn routes(n: u32) -> Vec<BgpRoute> {
        (0..n).map(route).collect()
    }

    fn shape(frames: &[Vec<BgpRouteUpdate>]) -> Vec<Vec<(char, usize)>> {
        frames
            .iter()
            .map(|f| {
                f.iter()
                    .map(|u| match u {
                        BgpRouteUpdate::Full(r) => ('F', r.len()),
                        BgpRouteUpdate::FullPart(r) => ('P', r.len()),
                        BgpRouteUpdate::Add(_) => ('A', 1),
                        BgpRouteUpdate::Remove(_) => ('R', 1),
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn small_pushes_stay_one_frame() {
        let f = BgpRouteUpdate::frames(vec![BgpRouteUpdate::Full(vec![])]);
        assert_eq!(shape(&f), [vec![('F', 0)]]);
        let f = BgpRouteUpdate::frames(vec![BgpRouteUpdate::Full(routes(2048))]);
        assert_eq!(shape(&f), [vec![('F', 2048)]]);
        assert_eq!(BgpRouteUpdate::frames(vec![]).len(), 0);
    }

    #[test]
    fn a_large_full_becomes_parts_closed_by_a_full_in_order() {
        let all = routes(5000);
        let f = BgpRouteUpdate::frames(vec![BgpRouteUpdate::Full(all.clone())]);
        assert_eq!(
            shape(&f),
            [vec![('P', 2048)], vec![('P', 2048)], vec![('F', 904)]]
        );
        let rejoined: Vec<BgpRoute> = f
            .into_iter()
            .flatten()
            .flat_map(|u| match u {
                BgpRouteUpdate::Full(r) | BgpRouteUpdate::FullPart(r) => r,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(rejoined, all);
        let f = BgpRouteUpdate::frames(vec![BgpRouteUpdate::Full(routes(4096))]);
        assert_eq!(shape(&f), [vec![('P', 2048)], vec![('F', 2048)]]);
    }

    #[test]
    fn incremental_updates_are_cut_by_route_count() {
        let mut u: Vec<_> = routes(4000).into_iter().map(BgpRouteUpdate::Add).collect();
        u.push(BgpRouteUpdate::Remove(route(9).prefix));
        let f = BgpRouteUpdate::frames(u);
        assert_eq!(f.iter().map(Vec::len).collect::<Vec<_>>(), [2048, 1953]);
        // A full chunk does not share its frame with a following update.
        let f = BgpRouteUpdate::frames(vec![
            BgpRouteUpdate::Full(routes(2048)),
            BgpRouteUpdate::Add(route(1)),
        ]);
        assert_eq!(shape(&f), [vec![('F', 2048)], vec![('A', 1)]]);
    }

    /// The worst case `BGP_PUSH_CHUNK` is sized for still fits one frame.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "serialises a full chunk, minutes under the interpreter"
    )]
    fn a_chunk_of_worst_case_routes_fits_max_frame() {
        let v6 = |i: u16| IpAddr::from(Ipv6Addr::new(0x2001, 0xdb8, i, i, i, i, i, i));
        let worst = BgpRoute {
            ibgp: false,
            prefix: IpNet::new(v6(1), 128).unwrap(),
            next_hops: (0..255).map(v6).collect(),
            backup_next_hop: Some(v6(999)),
            discard: false,
            metric: Some(u32::MAX),
        };
        let frame =
            RibRequest::PushBgpRoutes(vec![BgpRouteUpdate::Full(vec![worst; BGP_PUSH_CHUNK])]);
        let len = postcard::to_allocvec(&frame).unwrap().len();
        assert!(len < MAX_FRAME, "{len} bytes");
        let mut buf = bytes::BytesMut::new();
        IpcCodec::<RibRequest>::default()
            .encode(frame, &mut buf)
            .unwrap();
    }

    #[test]
    fn route_entry_attributes_round_trip_and_default_in_json() {
        let e = RouteEntry {
            gateways: vec![IpAddr::from([10, 0, 0, 1])],
            source: RouteSourceKind::Ospf,
            backup: None,
            discard: false,
            evpn: None,
            backup_tunnel: false,
            mpls_labels: vec![vec![]],
            vpn: vec![],
            blackhole: false,
            metric: Some(20),
            preference: 110,
            age_secs: 7,
            interfaces: vec![Some("eth0.5".into())],
            installed: true,
            tag: None,
        };
        let bytes = postcard::to_allocvec(&e).unwrap();
        assert_eq!(postcard::from_bytes::<RouteEntry>(&bytes).unwrap(), e);
        let mut j = serde_json::to_value(&e).unwrap();
        assert_eq!(serde_json::from_value::<RouteEntry>(j.clone()).unwrap(), e);
        for k in [
            "metric",
            "preference",
            "age_secs",
            "interfaces",
            "installed",
            "tag",
        ] {
            j.as_object_mut().unwrap().remove(k);
        }
        let old: RouteEntry = serde_json::from_value(j).unwrap();
        assert_eq!(
            (old.metric, old.preference, old.installed),
            (None, 0, false)
        );
    }

    fn vpn_route(i: u32, paths: usize) -> VpnRoute {
        let path = VpnPath {
            pe_next_hop: IpAddr::from([192, 0, 2, 1]),
            rd: "65001:1".into(),
            gateway: IpAddr::from([10, 0, 0, 1]),
            interface_id: Some(3),
            labels: vec![100],
        };
        VpnRoute {
            prefix: IpNet::new(IpAddr::from(i.to_be_bytes()), 32).unwrap(),
            paths: vec![path; paths],
        }
    }

    fn vpn_shape(frames: &[Vec<VpnRouteUpdate>]) -> Vec<Vec<(char, usize)>> {
        frames
            .iter()
            .map(|f| {
                f.iter()
                    .map(|u| match u {
                        VpnRouteUpdate::Full(r) => ('F', r.len()),
                        VpnRouteUpdate::FullPart(r) => ('P', r.len()),
                        VpnRouteUpdate::Add(_) => ('A', 1),
                        VpnRouteUpdate::Remove(_) => ('R', 1),
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "tens of thousands of routes, minutes under the interpreter"
    )]
    fn vpn_frames_weigh_paths_plus_one_per_route() {
        // Small pushes stay one frame; nothing is no frame.
        assert_eq!(VpnRouteUpdate::frames(vec![]).len(), 0);
        let f = VpnRouteUpdate::frames(vec![VpnRouteUpdate::Full(vec![])]);
        assert_eq!(vpn_shape(&f), [vec![('F', 0)]]);
        // 16384 single-path routes weigh exactly VPN_PUSH_CHUNK.
        let fits: Vec<_> = (0..16384).map(|i| vpn_route(i, 1)).collect();
        let f = VpnRouteUpdate::frames(vec![VpnRouteUpdate::Full(fits)]);
        assert_eq!(vpn_shape(&f), [vec![('F', 16384)]]);

        // A heavier Full: parts closed by a Full, in order, rejoined whole.
        let all: Vec<_> = (0..20000).map(|i| vpn_route(i, 3)).collect();
        let f = VpnRouteUpdate::frames(vec![VpnRouteUpdate::Full(all.clone())]);
        assert_eq!(
            vpn_shape(&f),
            [vec![('P', 8192)], vec![('P', 8192)], vec![('F', 3616)]]
        );
        let rejoined: Vec<VpnRoute> = f
            .into_iter()
            .flatten()
            .flat_map(|u| match u {
                VpnRouteUpdate::Full(r) | VpnRouteUpdate::FullPart(r) => r,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(rejoined, all);

        // Add (paths + 1) and Remove (1) are packed by weight.
        let mut u: Vec<_> = (0..11000)
            .map(|i| VpnRouteUpdate::Add(vpn_route(i, 2)))
            .collect();
        u.push(VpnRouteUpdate::Remove(vpn_route(1, 1).prefix));
        let f = VpnRouteUpdate::frames(u);
        assert_eq!(f.iter().map(Vec::len).collect::<Vec<_>>(), [10922, 79]);
    }

    /// The worst case `VPN_PUSH_CHUNK` is sized for still fits one frame.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "serialises a full chunk, minutes under the interpreter"
    )]
    fn a_chunk_of_worst_case_vpn_routes_fits_max_frame() {
        let v6 = |i: u16| IpAddr::from(Ipv6Addr::new(0x2001, 0xdb8, i, i, i, i, i, i));
        let path = VpnPath {
            pe_next_hop: v6(1),
            rd: "4294967295:65535".into(),
            gateway: v6(2),
            interface_id: Some(u32::MAX),
            labels: vec![0x000F_FFFF; 28],
        };
        // One route of VPN_PUSH_CHUNK - 1 paths weighs exactly the budget.
        let worst = VpnRoute {
            prefix: IpNet::new(v6(3), 128).unwrap(),
            paths: vec![path; VPN_PUSH_CHUNK - 1],
        };
        let f = VpnRouteUpdate::frames(vec![VpnRouteUpdate::Full(vec![worst])]);
        assert_eq!(f.len(), 1);
        let frame = RibRequest::PushVpnRoutes(f.into_iter().next().unwrap());
        let len = postcard::to_allocvec(&frame).unwrap().len();
        assert!(len < MAX_FRAME, "{len} bytes");
        let mut buf = bytes::BytesMut::new();
        IpcCodec::<RibRequest>::default()
            .encode(frame, &mut buf)
            .unwrap();
    }

    fn ospf_route(i: u32, hops: usize) -> OspfRoute {
        OspfRoute {
            class: None,
            prefix: IpNet::new(IpAddr::from(i.to_be_bytes()), 32).unwrap(),
            next_hops: vec![(IpAddr::from([10, 0, 0, 1]), None); hops],
            backup_next_hop: None,
            backup_interface_id: None,
            metric: 10,
            discard: false,
            backup_tunnel: None,
            next_hop_labels: Vec::new(),
        }
    }

    fn ospf_shape(frames: &[Vec<OspfRouteUpdate>]) -> Vec<Vec<(char, usize)>> {
        frames
            .iter()
            .map(|f| {
                f.iter()
                    .map(|u| match u {
                        OspfRouteUpdate::Full(r) => ('F', r.len()),
                        OspfRouteUpdate::FullPart(r) => ('P', r.len()),
                        OspfRouteUpdate::Add(_) => ('A', 1),
                        OspfRouteUpdate::Remove(_) => ('R', 1),
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn ospf_frames_weigh_next_hops_plus_one_per_route() {
        let frames = |u, chunk| OspfRouteUpdate::frames_with(u, chunk);
        // Small pushes stay one frame; nothing is no frame.
        assert_eq!(frames(vec![], 10).len(), 0);
        let f = frames(vec![OspfRouteUpdate::Full(vec![])], 10);
        assert_eq!(ospf_shape(&f), [vec![('F', 0)]]);
        // 5 single-hop routes weigh exactly the chunk.
        let fits: Vec<_> = (0..5).map(|i| ospf_route(i, 1)).collect();
        let f = frames(vec![OspfRouteUpdate::Full(fits)], 10);
        assert_eq!(ospf_shape(&f), [vec![('F', 5)]]);

        // A heavier Full: parts closed by a Full, in order, rejoined whole.
        let all: Vec<_> = (0..12).map(|i| ospf_route(i, 2)).collect();
        let f = frames(vec![OspfRouteUpdate::Full(all.clone())], 10);
        assert_eq!(
            ospf_shape(&f),
            [
                vec![('P', 3)],
                vec![('P', 3)],
                vec![('P', 3)],
                vec![('F', 3)]
            ]
        );
        let rejoined: Vec<OspfRoute> = f
            .into_iter()
            .flatten()
            .flat_map(|u| match u {
                OspfRouteUpdate::Full(r) | OspfRouteUpdate::FullPart(r) => r,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(rejoined, all);

        // Add (hops + 1) and Remove (1) are packed by weight.
        let mut u: Vec<_> = (0..7)
            .map(|i| OspfRouteUpdate::Add(ospf_route(i, 2)))
            .collect();
        u.push(OspfRouteUpdate::Remove(ospf_route(1, 1).prefix));
        let f = frames(u, 10);
        assert_eq!(f.iter().map(Vec::len).collect::<Vec<_>>(), [3, 3, 2]);
    }

    #[test]
    fn ospf_push_chunk_reads_the_env_hook() {
        assert_eq!(parse_chunk(None), OSPF_PUSH_CHUNK);
        assert_eq!(parse_chunk(Some("junk")), OSPF_PUSH_CHUNK);
        assert_eq!(parse_chunk(Some("0")), OSPF_PUSH_CHUNK);
        assert_eq!(parse_chunk(Some(" 64 ")), 64);
    }

    /// The worst cases `OSPF_PUSH_CHUNK` is sized for still fit one frame:
    /// the densest bytes per weight unit (hop-less routes, every optional
    /// field IPv6/maxed) and one route of `OSPF_PUSH_CHUNK - 1` ECMP hops.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "serialises a full chunk, minutes under the interpreter"
    )]
    fn a_chunk_of_worst_case_ospf_routes_fits_max_frame() {
        let v6 = |i: u16| IpAddr::from(Ipv6Addr::new(0x2001, 0xdb8, i, i, i, i, i, i));
        let worst = |hops: usize| OspfRoute {
            class: None,
            prefix: IpNet::new(v6(1), 128).unwrap(),
            next_hops: vec![(v6(2), Some(u32::MAX)); hops],
            backup_next_hop: Some(v6(3)),
            backup_interface_id: Some(u32::MAX),
            metric: u32::MAX,
            discard: true,
            backup_tunnel: Some(v6(4)),
            next_hop_labels: Vec::new(),
        };
        for routes in [
            vec![worst(0); OSPF_PUSH_CHUNK],
            vec![worst(OSPF_PUSH_CHUNK - 1)],
        ] {
            let f =
                OspfRouteUpdate::frames_with(vec![OspfRouteUpdate::Full(routes)], OSPF_PUSH_CHUNK);
            assert_eq!(f.len(), 1);
            let frame = RibRequest::PushOspfRoutes {
                instance: "i".into(),
                updates: f.into_iter().next().unwrap(),
            };
            let len = postcard::to_allocvec(&frame).unwrap().len();
            assert!(len < MAX_FRAME, "{len} bytes");
            let mut buf = bytes::BytesMut::new();
            IpcCodec::<RibRequest>::default()
                .encode(frame, &mut buf)
                .unwrap();
        }
    }

    /// Back-compat (#1165): `PushMplsRoutes` is appended after every older
    /// variant, and an `OspfRoute` round-trips its label stacks.
    #[test]
    fn mpls_push_and_labelled_ospf_route_round_trip() {
        let hop = |labels: Vec<u32>| NextHop {
            gateway: "10.0.0.2".parse().unwrap(),
            interface_id: Some(3),
            labels,
        };
        let req = RibRequest::PushMplsRoutes {
            instance: "o1".into(),
            routes: vec![
                IlmRoute {
                    label: 16001,
                    hops: vec![hop(vec![16002])],
                },
                IlmRoute {
                    label: 16002,
                    hops: vec![],
                },
            ],
        };
        let bytes = postcard::to_allocvec(&req).unwrap();
        // GetRoutesPage was the last variant: the new one is the next index.
        let last = postcard::to_allocvec(&RibRequest::GetRoutesPage {
            after: None,
            limit: 0,
            filter: RouteFilter::default(),
        })
        .unwrap()[0];
        assert_eq!(bytes[0], last + 1);
        let RibRequest::PushMplsRoutes { routes, .. } = postcard::from_bytes(&bytes).unwrap()
        else {
            panic!()
        };
        assert_eq!(routes[0].hops[0].labels, vec![16002]);

        let mut r = ospf_route(1, 2);
        let plain = r.weight();
        r.next_hop_labels = vec![vec![16001, 16002], vec![]];
        assert_eq!(r.weight(), plain + 2);
        let back: OspfRoute = postcard::from_bytes(&postcard::to_allocvec(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        r.class = Some(crate::ospf::RoutePathClass::External2);
        let back: OspfRoute = postcard::from_bytes(&postcard::to_allocvec(&r).unwrap()).unwrap();
        assert_eq!(back.class, Some(crate::ospf::RoutePathClass::External2));
        let mut b = route(1);
        b.ibgp = true;
        let back: BgpRoute = postcard::from_bytes(&postcard::to_allocvec(&b).unwrap()).unwrap();
        assert!(back.ibgp);
    }

    /// `GetSummary`/`Summary` are appended after the previous last variants
    /// (#1445), and `RouteSourceKind` parses what it prints.
    #[test]
    fn summary_variants_are_last_and_sources_parse() {
        let idx = |v: &RibRequest| postcard::to_allocvec(v).unwrap()[0];
        let mpls = RibRequest::PushMplsRoutes {
            instance: String::new(),
            routes: vec![],
        };
        assert_eq!(idx(&RibRequest::GetSummary), idx(&mpls) + 1);
        let sum = RibSummary {
            table: "rt1".into(),
            vrf: None,
            kernel_table: Some(100),
            ipv4_prefixes: 1,
            ipv6_prefixes: 0,
            sources: vec![],
        };
        let page = RibEvent::RoutesPage {
            routes: vec![],
            next: None,
        };
        let i = |e: &RibEvent| postcard::to_allocvec(e).unwrap()[0];
        assert_eq!(i(&RibEvent::Summary(sum)), i(&page) + 1);
        for k in RouteSourceKind::ALL {
            assert_eq!(k.to_string().parse::<RouteSourceKind>(), Ok(k));
        }
        assert!("nope"
            .parse::<RouteSourceKind>()
            .unwrap_err()
            .contains("bgp"));
    }
}
