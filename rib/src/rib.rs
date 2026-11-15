use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use nos_proto::{Config, IpNet, NextHop};
use tracing::warn;

/// Where a route came from. New sources are appended as new variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteSource {
    /// From a `StaticRoutingInstance` in the running config. Populated
    /// wholesale by `build_from_config` on every resync.
    Static,
    /// Pushed by the owning `nos-bgpd` instance over `RibRequest::PushBgpRoutes`
    /// (see `crate::server::apply_bgp_route_update`) — its per-prefix best
    /// path, peer-learned routes only.
    Bgp,
    /// Pushed by the owning `nos-ospfd` instance over `RibRequest::PushOspfRoutes`
    /// (see `crate::server::apply_ospf_route_update`) — its own SPF-computed
    /// routes, never a directly-connected destination (see `ospf::spf`).
    Ospf,
    /// A directly-connected prefix: the network of an address
    /// `nos-interfaced` applied to an interface/subinterface or a broadcast
    /// domain's SVI in this table (`reconcile::connected_entries`, from
    /// `InterfaceRequest::GetInterfaces`/`GetBroadcastDomain`). Rebuilt
    /// wholesale on every resync like `Static`. Its one next hop is the local
    /// address itself, for display only: the kernel installs a connected
    /// route on its own the moment the address is applied, so this source is
    /// never installed (`Rib::best_routes_for_kernel`) — and, as it wins,
    /// neither is any other source's route for that prefix. It exists so
    /// `igp_costs` can tell "directly connected" (cost 0) from "unresolvable"
    /// (absent) — RFC 4271 §9.1.2's next-hop feasibility check in `nos-bgpd`.
    Connected,
    /// An EVPN Type-5 route received over this table's L3 VNI (pushed by
    /// the underlay `nos-bgpd` over `RibRequest::PushEvpnRoutes`, filtered by
    /// `crate::evpn::desired`). Its one next hop is the remote VTEP, installed
    /// `onlink` through the L3 VNI's bridge (`RibDriver::sync_l3vni`).
    Evpn,
    /// A VPN route imported by Route Target (RFC 4364), pushed by the
    /// underlay `nos-bgpd` over `RibRequest::PushVpnRoutes`
    /// (`crate::server::apply_vpn_route_update`). Its next hop is the PE as
    /// resolved in the underlay table, so the driver installs it `onlink`
    /// over the underlay interface, pushing each hop's labels (#581).
    Vpn,
}

impl RouteSource {
    /// Lower wins, like an administrative distance. Connected beats Static
    /// beats Bgp beats Ospf, matching conventional (Cisco-style) router
    /// defaults: a directly-connected prefix beats an explicit operator
    /// override beats eBGP beats an interior IGP route beats a route learned over the
    /// overlay (EVPN, at iBGP's conventional distance).
    fn preference(self) -> u8 {
        match self {
            RouteSource::Connected => 0,
            RouteSource::Static => 1,
            RouteSource::Bgp => 20,
            RouteSource::Ospf => 110,
            RouteSource::Evpn | RouteSource::Vpn => 200,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RibEntry {
    pub prefix: IpNet,
    /// Every equal-cost next hop (one for `Static`/`Bgp`/`Connected`; one
    /// or more for `Ospf`, or none for an OSPF discard route — see
    /// `is_discard`), each with the local kernel
    /// interface it is reachable over when known (mirrors
    /// `nos_proto::OspfRoute::next_hops`: always `Some` from `nos-ospfv3d`,
    /// `None` otherwise) — required for Linux's netlink route install when
    /// the gateway is an IPv6 link-local address. Two or more are installed
    /// as one `RTA_MULTIPATH` kernel route. A `Vpn` hop carries the MPLS
    /// label stack it pushes (empty otherwise). Part of equality, like
    /// `backup`, so a label-only change re-installs the winner.
    pub next_hops: Vec<NextHop>,
    pub source: RouteSource,
    /// Pre-computed backup gateway (OSPF LFA / BGP runner-up), installed by
    /// the driver as a second route at a higher metric. Part of equality, so
    /// a backup-only change counts as a change of the winner.
    pub backup: Option<IpAddr>,
    /// `interface_id` of `backup` — it can leave over a different link than
    /// the primary, and an IPv6 link-local backup needs one just the same.
    pub backup_interface_id: Option<u32>,
    /// `backup` is an RFC 7490 remote LFA: a PQ node reached through this
    /// table's IP-in-IP device (`rlfa<table-id>`), not a neighbor.
    pub backup_tunnel: bool,
}

impl RibEntry {
    /// A discard (blackhole) route: no next hop at all — an OSPF ABR's route
    /// for an active advertised area range (`OspfRoute.discard`). Installed
    /// as `RTN_BLACKHOLE`, and never an IGP cost a BGP next hop resolves by.
    pub fn is_discard(&self) -> bool {
        self.next_hops.is_empty()
    }
}

/// Whether a mutation actually changed a prefix's *winning* candidate —
/// see `Rib::upsert_and_diff`/`remove_and_diff`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BestPathChange {
    /// The winner is the same as before this mutation (a losing candidate
    /// churned, or the value re-sent was identical) — nothing to do.
    Unchanged,
    /// The prefix now has no winner at all (its last candidate was removed).
    Removed,
    /// The prefix has a new (or first) winner.
    Installed(RibEntry),
}

/// The change between two winners (`RibEntry` equality, labels included).
fn diff_best(before: Option<&RibEntry>, after: Option<RibEntry>) -> BestPathChange {
    if before == after.as_ref() {
        BestPathChange::Unchanged
    } else {
        match after {
            Some(entry) => BestPathChange::Installed(entry),
            None => BestPathChange::Removed,
        }
    }
}

/// One routing table's candidate routes, keyed by prefix, potentially with
/// more than one source contending for a prefix. Three independent writers
/// mutate this: `crate::reconcile::resync` (config-driven, rebuilds the
/// whole `Static` side — and, from `nos-interfaced`'s applied addresses,
/// the whole `Connected` side — from scratch on every resync), and
/// `crate::server::apply_bgp_route_update`/`apply_ospf_route_update`
/// (push-driven, incremental). Each writer only ever touches its own
/// `RouteSource`'s candidates via `replace_source`/`upsert`/`remove`, so
/// none can clobber another's state.
#[derive(Debug, Clone, Default)]
pub struct Rib {
    entries: HashMap<IpNet, Vec<RibEntry>>,
    /// SPF cost per `Ospf`-sourced prefix, kept beside `entries` (not in
    /// `RibEntry`) since the kernel diff must not see a metric-only change.
    ospf_metrics: HashMap<IpNet, u32>,
    /// The table's EVPN IP-VRF state, beside `entries` like `ospf_metrics`.
    pub evpn: crate::evpn::EvpnState,
    /// PE and RD of each next hop per `Vpn`-sourced prefix, for `show route` only (beside
    /// `entries` like `ospf_metrics`: the kernel never sees it).
    pub vpn_info: HashMap<IpNet, Vec<nos_proto::VpnRouteInfo>>,
    /// This VRF's label (`vpn::VrfExport::label`), for `show route`.
    pub vpn_label: Option<u32>,
}

impl Rib {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, entry: RibEntry) {
        self.entries.entry(entry.prefix).or_default().push(entry);
    }

    /// Replaces every `source`-sourced candidate across the whole table with
    /// `entries`, leaving every other source's candidates untouched. Used
    /// for a config resync's wholesale `Static` rebuild and a BGP push's
    /// `Full` snapshot (on connect/reconnect) alike.
    pub fn replace_source(
        &mut self,
        source: RouteSource,
        entries: impl IntoIterator<Item = RibEntry>,
    ) {
        for candidates in self.entries.values_mut() {
            candidates.retain(|e| e.source != source);
        }
        for entry in entries {
            debug_assert_eq!(entry.source, source);
            self.entries.entry(entry.prefix).or_default().push(entry);
        }
        self.entries.retain(|_, c| !c.is_empty());
    }

    /// How many `source`-sourced candidates the table holds
    /// (`RibRequest::BgpRouteCount`).
    pub fn count_source(&self, source: RouteSource) -> u32 {
        let n = self
            .entries
            .values()
            .flatten()
            .filter(|e| e.source == source)
            .count();
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// Upserts one `source`-sourced candidate for `entry.prefix` — used for
    /// a BGP push's incremental `Add`.
    pub fn upsert(&mut self, entry: RibEntry) {
        let candidates = self.entries.entry(entry.prefix).or_default();
        candidates.retain(|e| e.source != entry.source);
        candidates.push(entry);
    }

    /// Removes `source`'s candidate for `prefix`, if any — used for a BGP
    /// push's incremental `Remove`. Prunes the prefix entirely if that was
    /// its last remaining candidate.
    pub fn remove(&mut self, prefix: &IpNet, source: RouteSource) {
        if let Some(candidates) = self.entries.get_mut(prefix) {
            candidates.retain(|e| e.source != source);
            if candidates.is_empty() {
                self.entries.remove(prefix);
            }
        }
    }

    /// Same as `upsert`, but reports whether the prefix's *winning*
    /// candidate changed as a result — a caller that only cares about
    /// kernel-visible state (e.g. `crate::server::apply_bgp_route_update`)
    /// can then skip pushing anything for a losing candidate's churn or a
    /// re-sent identical route, instead of recomputing/reinstalling the
    /// whole table on every single update.
    pub fn upsert_and_diff(&mut self, entry: RibEntry) -> BestPathChange {
        let prefix = entry.prefix;
        let before = self.best_route(&prefix).cloned();
        self.upsert(entry);
        diff_best(before.as_ref(), self.best_route(&prefix).cloned())
    }

    /// Same as `remove`, but reports whether the prefix's winning candidate
    /// changed — see `upsert_and_diff`.
    pub fn remove_and_diff(&mut self, prefix: &IpNet, source: RouteSource) -> BestPathChange {
        let before = self.best_route(prefix).cloned();
        self.remove(prefix, source);
        diff_best(before.as_ref(), self.best_route(prefix).cloned())
    }

    /// The winning candidate for one prefix, if any exist.
    pub fn best_route(&self, prefix: &IpNet) -> Option<&RibEntry> {
        self.entries
            .get(prefix)?
            .iter()
            .min_by_key(|e| e.source.preference())
    }

    /// The winning route for every known prefix.
    pub fn best_routes(&self) -> HashMap<IpNet, RibEntry> {
        self.entries
            .iter()
            .filter_map(|(prefix, candidates)| {
                candidates
                    .iter()
                    .min_by_key(|e| e.source.preference())
                    .cloned()
                    .map(|e| (*prefix, e))
            })
            .collect()
    }

    /// `best_routes` for the driver: every winner except a `Connected` one.
    /// A prefix whose winner is `Connected` is left to the kernel's own
    /// on-link route (it exists the instant `nos-interfaced` applies the
    /// address, and `driver::linux::extract_route` ignores it as an
    /// unmanaged, gateway-less route), so a `Static`/`Bgp`/`Ospf` candidate
    /// for that same prefix is not installed either: adding it would only
    /// collide with the kernel's route (EEXIST for IPv4, #139). Matches the
    /// delta path, whose `best_route` already counts `Connected`.
    /// ponytail: `Connected` is the configured address, not the observed
    /// link state — an admin-down link (kernel flushes its on-link route)
    /// still shadows the prefix; add an oper-state field if it ever matters.
    pub fn best_routes_for_kernel(&self) -> HashMap<IpNet, RibEntry> {
        let mut routes = self.best_routes();
        routes.retain(|_, e| e.source != RouteSource::Connected);
        routes
    }

    /// Every prefix's full candidate list, each sorted best (winner) to
    /// worst by source preference, with prefixes themselves in ascending
    /// CIDR order — for serving an unfiltered `show route <table>` query.
    pub fn all_routes(&self) -> Vec<(IpNet, Vec<RibEntry>)> {
        let mut out: Vec<(IpNet, Vec<RibEntry>)> = self
            .entries
            .iter()
            .map(|(prefix, candidates)| (*prefix, sorted_by_preference(candidates)))
            .collect();
        out.sort_by_key(|(prefix, _)| *prefix);
        out
    }

    /// The `limit` smallest prefixes strictly after `after` (all of them from
    /// the start when `None`), as `all_routes` would list them, and whether
    /// more follow. `entries` is a `HashMap`, so this is one O(n) pass with a
    /// bounded heap plus a sort of just the page, never a full sort.
    // ponytail: O(n) per page (~100 pages at 1M prefixes under the read
    // lock); a `BTreeMap` makes it a range scan if that is measured too slow.
    pub fn routes_page(
        &self,
        after: Option<IpNet>,
        limit: usize,
    ) -> (Vec<(IpNet, Vec<RibEntry>)>, bool) {
        let mut heap = std::collections::BinaryHeap::with_capacity(limit + 1);
        for prefix in self
            .entries
            .keys()
            .filter(|p| after.is_none_or(|a| **p > a))
        {
            heap.push(*prefix);
            if heap.len() > limit + 1 {
                heap.pop();
            }
        }
        let mut prefixes = heap.into_sorted_vec();
        let more = prefixes.len() > limit;
        prefixes.truncate(limit);
        let page = prefixes
            .into_iter()
            .map(|p| (p, sorted_by_preference(&self.entries[&p])))
            .collect();
        (page, more)
    }

    /// Longest-prefix-match lookup: the most specific configured prefix that
    /// covers `addr`, with its full candidate list sorted best to worst.
    /// `None` if no configured prefix covers `addr` (no default route).
    pub fn lookup(&self, addr: IpAddr) -> Option<(IpNet, Vec<RibEntry>)> {
        let (prefix, candidates) = self
            .entries
            .iter()
            .filter(|(net, _)| net.contains(&addr))
            .max_by_key(|(net, _)| net.prefix_len())?;
        Some((*prefix, sorted_by_preference(candidates)))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Replaces every recorded OSPF metric (a `Full` push).
    pub fn set_ospf_metrics(&mut self, metrics: impl IntoIterator<Item = (IpNet, u32)>) {
        self.ospf_metrics = metrics.into_iter().collect();
    }

    /// Records (`Some`) or forgets (`None`) one prefix's OSPF metric.
    pub fn set_ospf_metric(&mut self, prefix: IpNet, metric: Option<u32>) {
        match metric {
            Some(m) => self.ospf_metrics.insert(prefix, m),
            None => self.ospf_metrics.remove(&prefix),
        };
    }

    /// Rebuilds the `Evpn` candidates from `evpn.received` and `evpn.local`
    /// (none without a local L3 VNI), and the remote VTEPs they need.
    pub fn refresh_evpn(&mut self) {
        let entries = self.evpn.rebuild();
        self.replace_source(RouteSource::Evpn, entries);
    }

    /// Incremental `EvpnUpdate::Add`/`Remove` (#763): recomputes only the
    /// touched prefix. Returns its `Evpn` winner change and whether the remote
    /// VTEP set (or a VTEP's Router's MAC) changed; `None` if nothing changed.
    pub fn apply_evpn_diff(
        &mut self,
        key: &nos_proto::EvpnKey,
        route: Option<nos_proto::EvpnRoute>,
    ) -> Option<(IpNet, BestPathChange, bool)> {
        let (prefix, vtep, remotes_changed) = self.evpn.apply(key, route)?;
        let change = match vtep {
            Some(v) => self.upsert_and_diff(crate::evpn::entry_for(prefix, v)),
            None => self.remove_and_diff(&prefix, RouteSource::Evpn),
        };
        Some((prefix, change, remotes_changed))
    }

    /// The best candidate of the longest prefix covering `addr` that has
    /// one which may resolve a next hop (same filter as `igp_costs`):
    /// its gateway and ifindex, or `addr` itself on a `Connected` prefix.
    pub fn resolve(&self, addr: IpAddr) -> Option<nos_proto::ResolvedNextHop> {
        self.entries
            .iter()
            .filter(|(net, _)| net.contains(&addr))
            .filter_map(|(net, candidates)| Some((net, resolving_best(candidates)?)))
            .max_by_key(|(net, _)| net.prefix_len())
            .map(|(_, e)| {
                let (gateway, interface_id) = match e.source {
                    RouteSource::Connected => (addr, None),
                    _ => (e.next_hops[0].gateway, e.next_hops[0].interface_id),
                };
                nos_proto::ResolvedNextHop {
                    gateway,
                    interface_id,
                    source: crate::server::to_source_kind(e.source),
                }
            })
    }

    /// IGP cost per prefix: its best non-BGP candidate's cost (`Connected`/
    /// `Static` 0, `Ospf` its SPF metric). `Bgp`/`Evpn`/`Vpn` candidates never
    /// count (a next hop never resolves through the overlay), nor
    /// a discard route: a next hop only reachable through an area range's
    /// blackhole is unresolvable (RFC 4271 §9.1.2), not selectable-then-dropped.
    pub fn igp_costs(&self) -> Vec<(IpNet, u32)> {
        self.entries
            .iter()
            .filter_map(|(prefix, candidates)| {
                let best = resolving_best(candidates)?;
                let cost = match best.source {
                    RouteSource::Ospf => self.ospf_metrics.get(prefix).copied().unwrap_or(0),
                    _ => 0,
                };
                Some((*prefix, cost))
            })
            .collect()
    }
}

/// The best candidate a next hop may resolve through: no overlay source
/// (`Bgp`/`Evpn`/`Vpn`, so nothing resolves recursively) and no discard
/// route (RFC 4271 section 9.1.2: unresolvable, not selectable-then-dropped).
fn resolving_best(candidates: &[RibEntry]) -> Option<&RibEntry> {
    candidates
        .iter()
        .filter(|e| {
            !matches!(
                e.source,
                RouteSource::Bgp | RouteSource::Evpn | RouteSource::Vpn
            ) && !e.is_discard()
        })
        .min_by_key(|e| e.source.preference())
}

/// Clones and sorts a prefix's candidates best (lowest preference value)
/// first.
fn sorted_by_preference(candidates: &[RibEntry]) -> Vec<RibEntry> {
    let mut sorted = candidates.to_vec();
    sorted.sort_by_key(|e| e.source.preference());
    sorted
}

/// Builds a fresh `Rib` for `table_name` from a freshly fetched `Config`.
/// Returns `None` if no `RoutingTable` named `table_name` exists in `cfg` —
/// the caller (see `crate::reconcile::resync`) treats that as a
/// recoverable, possibly-transient condition, not fatal.
///
/// Only resolves `table.static_routing_instance` — `table.bgp_instance` is
/// intentionally not read here: `RouteSource::Bgp` entries never come from
/// config, only from the owning `nos-bgpd` instance's own IPC push (see
/// `crate::server::apply_bgp_route_update`).
///
/// A static route with a `bfd` reference is left out unless its gateway is in
/// `bfd_up` (`crate::bfd_client`): fail closed until `nos-bfdd` says `Up`.
#[allow(
    clippy::implicit_hasher,
    reason = "the one caller owns a default-hasher set"
)]
pub fn build_from_config(cfg: &Config, table_name: &str, bfd_up: &HashSet<IpAddr>) -> Option<Rib> {
    let table = cfg.routing_tables.iter().find(|t| t.name == table_name)?;
    let mut rib = Rib::new();

    if let Some(sri_name) = &table.static_routing_instance {
        if let Some(sri) = cfg
            .static_routing_instances
            .iter()
            .find(|i| &i.name == sri_name)
        {
            for route in &sri.routes {
                if route.bfd.is_some() && !bfd_up.contains(&route.gateway) {
                    continue;
                }
                rib.insert(RibEntry {
                    prefix: route.subnet,
                    next_hops: vec![(route.gateway, None).into()],
                    source: RouteSource::Static,
                    backup: None,
                    backup_interface_id: None,
                    backup_tunnel: false,
                });
            }
        } else {
            warn!(
                table = %table_name,
                static_routing_instance = %sri_name,
                "static_routing_instance referenced by routing table not found in config"
            );
        }
    }

    Some(rib)
}

/// The gateways of `table_name`'s static routes that name a `BfdProfile`,
/// with that profile (a reference to a missing profile is skipped: commit
/// validation rejects it). Two routes through one gateway share a session.
pub fn bfd_target(cfg: &Config, table_name: &str) -> crate::bfd_client::Target {
    let routes = cfg
        .routing_tables
        .iter()
        .find(|t| t.name == table_name)
        .and_then(|t| t.static_routing_instance.as_ref())
        .and_then(|n| cfg.static_routing_instances.iter().find(|i| &i.name == n))
        .map_or_default(|i| i.routes.as_slice());
    routes
        .iter()
        .filter_map(|r| {
            let profile = cfg
                .bfd_profiles
                .iter()
                .find(|p| Some(&p.name) == r.bfd.as_ref())?;
            Some((
                r.gateway,
                crate::bfd_client::Want {
                    profile: profile.clone(),
                    multihop: !cfg.is_connected(table_name, r.gateway),
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::schema::BfdProfile;
    use nos_proto::{RouteSourceKind, RoutingTable, StaticRoute, StaticRoutingInstance};

    fn cfg(tables: Vec<RoutingTable>, instances: Vec<StaticRoutingInstance>) -> Config {
        Config {
            routing_tables: tables,
            static_routing_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn igp_costs_use_best_non_bgp_candidate() {
        let mut rib = Rib::new();
        let entry = |p: &str, source| RibEntry {
            prefix: p.parse().unwrap(),
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        };
        rib.insert(entry("10.1.0.0/16", RouteSource::Ospf));
        rib.insert(entry("10.2.0.0/16", RouteSource::Static));
        rib.insert(entry("10.3.0.0/16", RouteSource::Bgp));
        rib.insert(entry("10.5.0.0/16", RouteSource::Evpn));
        // An area range's discard route is no IGP cost.
        rib.insert(RibEntry {
            next_hops: Vec::new(),
            ..entry("10.4.0.0/16", RouteSource::Ospf)
        });
        rib.set_ospf_metric("10.1.0.0/16".parse().unwrap(), Some(25));
        let mut costs = rib.igp_costs();
        costs.sort();
        assert_eq!(
            costs,
            vec![
                ("10.1.0.0/16".parse().unwrap(), 25),
                ("10.2.0.0/16".parse().unwrap(), 0)
            ]
        );
    }

    #[test]
    fn evpn_ranks_last_and_refresh_follows_the_local_l3vni() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.2.0.0/24".parse().unwrap();
        let rt = 0x0002_fde8_0000_1388;
        let key = nos_proto::EvpnKey::IpPrefix { rd: [0; 8], prefix };
        rib.evpn.received.insert(
            key.clone(),
            nos_proto::EvpnRoute {
                key,
                vni: 5000,
                next_hop: "10.50.0.3".parse().unwrap(),
                ext_communities: vec![rt, nos_proto::evpn_id::router_mac_ext([2; 6])],
                esi: [0; 10],
                l3_vni: None,
            },
        );
        // No local L3 VNI: nothing is installed.
        rib.refresh_evpn();
        assert!(rib.best_route(&prefix).is_none());
        rib.evpn.local = Some(crate::evpn::L3Vni {
            vni: 5000,
            rd: [0; 8],
            import: vec![rt],
            export: vec![rt],
            bgp_instance: "r1".into(),
            vtep: "10.50.0.2".parse().unwrap(),
            underlay: "eth0".into(),
        });
        rib.refresh_evpn();
        assert_eq!(rib.best_route(&prefix).unwrap().source, RouteSource::Evpn);
        assert_eq!(rib.evpn.remotes.len(), 1);
        // An OSPF route for the same prefix wins over the overlay's.
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Ospf,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        assert_eq!(rib.best_route(&prefix).unwrap().source, RouteSource::Ospf);
        rib.evpn.local = None;
        rib.refresh_evpn();
        assert_eq!(rib.all_routes()[0].1.len(), 1);
    }

    #[test]
    fn best_route_none_for_unknown_prefix() {
        let rib = Rib::new();
        assert!(rib.best_route(&"10.0.0.0/24".parse().unwrap()).is_none());
    }

    #[test]
    fn single_static_entry_is_its_own_best() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        assert_eq!(
            rib.best_route(&prefix).unwrap().next_hops[0].gateway,
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    /// Proves the tie-break logic actually discriminates by source, using a
    /// synthetic `RouteSource::Bgp` entry even though no real code
    /// constructs one today.
    #[test]
    fn static_beats_bgp_for_same_prefix() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        assert_eq!(rib.best_route(&prefix).unwrap().source, RouteSource::Static);
    }

    fn entry(prefix: &str, gateway: &str, source: RouteSource) -> RibEntry {
        RibEntry {
            prefix: prefix.parse().unwrap(),
            next_hops: vec![(gateway.parse().unwrap(), None).into()],
            source,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        }
    }

    fn vpn(prefix: &str, gateway: &str, label: u32) -> RibEntry {
        RibEntry {
            next_hops: vec![NextHop {
                gateway: gateway.parse().unwrap(),
                interface_id: None,
                labels: vec![label],
            }],
            ..entry(prefix, gateway, RouteSource::Vpn)
        }
    }

    #[test]
    fn a_vpn_candidate_loses_to_every_ce_source_and_shows_its_labels() {
        let mut rib = Rib::new();
        rib.insert(vpn("10.1.0.0/24", "192.0.2.9", 100));
        for source in [RouteSource::Static, RouteSource::Bgp, RouteSource::Ospf] {
            let mut r = rib.clone();
            r.insert(entry("10.1.0.0/24", "10.0.0.1", source));
            assert_eq!(
                r.best_route(&"10.1.0.0/24".parse().unwrap())
                    .unwrap()
                    .source,
                source
            );
        }
        let all = rib.all_routes();
        assert_eq!(all[0].1[0].next_hops[0].labels, vec![100]);
    }

    /// The CE-facing instance's `Full` must not wipe the VPN routes, nor the
    /// reverse.
    #[test]
    fn replace_source_vpn_and_bgp_leave_each_other_alone() {
        let mut rib = Rib::new();
        rib.insert(entry("10.2.0.0/24", "10.0.0.1", RouteSource::Bgp));
        rib.replace_source(RouteSource::Vpn, [vpn("10.1.0.0/24", "192.0.2.9", 100)]);
        rib.replace_source(
            RouteSource::Bgp,
            [entry("10.3.0.0/24", "10.0.0.1", RouteSource::Bgp)],
        );
        assert_eq!(rib.count_source(RouteSource::Vpn), 1);
        rib.replace_source(RouteSource::Vpn, []);
        assert_eq!(rib.count_source(RouteSource::Bgp), 1);
        assert_eq!(rib.count_source(RouteSource::Vpn), 0);
    }

    #[test]
    fn a_vpn_winner_is_installed_and_a_label_change_is_a_new_winner() {
        let mut rib = Rib::new();
        rib.insert(vpn("10.1.0.0/24", "192.0.2.9", 100));
        let p: IpNet = "10.1.0.0/24".parse().unwrap();
        assert_eq!(
            rib.best_routes_for_kernel()[&p].next_hops[0].labels,
            vec![100]
        );
        // A Bgp winner falling back to the Vpn one re-installs the Vpn route.
        assert!(matches!(
            rib.upsert_and_diff(entry("10.1.0.0/24", "10.0.0.1", RouteSource::Bgp)),
            BestPathChange::Installed(_)
        ));
        assert!(matches!(
            rib.remove_and_diff(&p, RouteSource::Bgp),
            BestPathChange::Installed(e) if e.source == RouteSource::Vpn
        ));
        assert!(matches!(
            rib.upsert_and_diff(vpn("10.1.0.0/24", "192.0.2.9", 200)),
            BestPathChange::Installed(e) if e.next_hops[0].labels == [200]
        ));
        assert_eq!(
            rib.remove_and_diff(&p, RouteSource::Vpn),
            BestPathChange::Removed
        );
    }

    #[test]
    fn resolve_uses_only_underlay_sources() {
        let mut rib = Rib::new();
        rib.insert(entry("10.0.0.0/24", "10.0.0.2", RouteSource::Connected));
        rib.insert(entry("192.0.2.0/24", "10.0.0.7", RouteSource::Ospf));
        rib.insert(RibEntry {
            next_hops: vec![("10.0.0.8".parse().unwrap(), Some(4)).into()],
            ..entry("198.51.100.0/24", "10.0.0.8", RouteSource::Static)
        });
        // More specific, but overlay or discard: never resolves.
        for (p, s) in [
            ("192.0.2.9/32", RouteSource::Bgp),
            ("192.0.2.8/30", RouteSource::Evpn),
            ("192.0.2.0/25", RouteSource::Vpn),
        ] {
            rib.insert(entry(p, "10.9.9.9", s));
        }
        rib.insert(RibEntry {
            next_hops: vec![],
            ..entry("198.51.100.0/25", "10.0.0.1", RouteSource::Ospf)
        });
        let r = |a: &str| rib.resolve(a.parse().unwrap());
        let hop = |gw: &str, ifi, source| {
            Some(nos_proto::ResolvedNextHop {
                gateway: gw.parse().unwrap(),
                interface_id: ifi,
                source,
            })
        };
        assert_eq!(
            r("10.0.0.5"),
            hop("10.0.0.5", None, RouteSourceKind::Connected)
        );
        assert_eq!(r("192.0.2.9"), hop("10.0.0.7", None, RouteSourceKind::Ospf));
        assert_eq!(
            r("198.51.100.1"),
            hop("10.0.0.8", Some(4), RouteSourceKind::Static)
        );
        assert_eq!(r("203.0.113.1"), None);
    }

    #[test]
    fn count_source_counts_only_that_source() {
        let mut rib = Rib::new();
        rib.insert(entry("10.0.0.0/24", "10.0.0.1", RouteSource::Bgp));
        rib.insert(entry("10.0.0.0/24", "10.0.0.2", RouteSource::Static));
        rib.insert(entry("10.0.1.0/24", "10.0.0.1", RouteSource::Bgp));
        assert_eq!(rib.count_source(RouteSource::Bgp), 2);
        assert_eq!(rib.count_source(RouteSource::Ospf), 0);
    }

    #[test]
    fn connected_beats_static_for_same_prefix() {
        let mut rib = Rib::new();
        rib.insert(entry("10.0.0.0/24", "10.0.0.1", RouteSource::Static));
        rib.insert(entry("10.0.0.0/24", "10.0.0.2", RouteSource::Connected));
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(
            rib.best_route(&prefix).unwrap().source,
            RouteSource::Connected
        );
        // and counts as an IGP destination at cost 0
        assert_eq!(rib.igp_costs(), vec![(prefix, 0)]);
    }

    #[test]
    fn best_routes_for_kernel_leaves_a_connected_prefix_to_the_kernel() {
        // #139: a static or OSPF route for a connected prefix would only
        // collide with the kernel's own on-link route.
        for other in [RouteSource::Static, RouteSource::Ospf] {
            let mut rib = Rib::new();
            rib.insert(entry("10.0.0.0/24", "10.0.0.2", RouteSource::Connected));
            rib.insert(entry("10.0.0.0/24", "10.0.0.1", other));
            let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
            assert!(rib.best_routes_for_kernel().is_empty());
            assert_eq!(rib.best_routes()[&prefix].source, RouteSource::Connected);
        }
    }

    #[test]
    fn best_routes_for_kernel_omits_connected_only_prefix_entirely() {
        let mut rib = Rib::new();
        rib.insert(entry("10.0.0.0/24", "10.0.0.2", RouteSource::Connected));
        rib.insert(entry("10.0.1.0/24", "10.0.0.1", RouteSource::Static));
        let kernel = rib.best_routes_for_kernel();
        assert_eq!(kernel.len(), 1);
        assert!(kernel.contains_key(&"10.0.1.0/24".parse::<IpNet>().unwrap()));
        assert_eq!(rib.best_routes().len(), 2);
    }

    #[test]
    fn best_routes_has_one_entry_per_prefix() {
        let mut rib = Rib::new();
        let p1: IpNet = "10.0.0.0/24".parse().unwrap();
        let p2: IpNet = "10.0.1.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix: p1,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.insert(RibEntry {
            prefix: p2,
            next_hops: vec![("10.0.1.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        assert_eq!(rib.best_routes().len(), 2);
    }

    #[test]
    fn routes_page_concatenated_equals_all_routes() {
        let mut rib = Rib::new();
        for (i, p) in [
            "10.0.1.0/24",
            "10.0.0.0/8",
            "2001:db8::/32",
            "10.0.0.0/24",
            "192.168.0.0/16",
        ]
        .iter()
        .enumerate()
        {
            rib.insert(entry(p, "10.0.0.1", RouteSource::Static));
            if i % 2 == 0 {
                rib.insert(entry(p, "10.0.0.2", RouteSource::Bgp));
            }
        }
        let all = rib.all_routes();
        for limit in 1..=6 {
            let (mut got, mut after) = (Vec::new(), None);
            loop {
                let (page, more) = rib.routes_page(after, limit);
                assert!(page.len() <= limit);
                after = page.last().map(|(p, _)| *p);
                got.extend(page);
                if !more {
                    break;
                }
            }
            assert_eq!(got, all, "limit {limit}");
        }
        // Empty table, a cursor past the end, a cursor on a removed prefix.
        assert_eq!(Rib::new().routes_page(None, 3), (vec![], false));
        let last = all.last().unwrap().0;
        assert_eq!(rib.routes_page(Some(last), 3), (vec![], false));
        let gone: IpNet = "10.0.0.128/25".parse().unwrap();
        let want = all.iter().map(|a| a.0).find(|p| *p > gone).unwrap();
        assert_eq!(rib.routes_page(Some(gone), 1).0[0].0, want);
    }

    #[test]
    fn all_routes_sorts_prefixes_and_candidates() {
        let mut rib = Rib::new();
        let p1: IpNet = "10.0.1.0/24".parse().unwrap();
        let p2: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix: p1,
            next_hops: vec![("10.0.1.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.insert(RibEntry {
            prefix: p2,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.insert(RibEntry {
            prefix: p2,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });

        let all = rib.all_routes();
        assert_eq!(all.len(), 2);
        // p2 (10.0.0.0/24) sorts before p1 (10.0.1.0/24).
        assert_eq!(all[0].0, p2);
        assert_eq!(all[1].0, p1);
        // p2's candidates are ordered best (Static) to worst (Bgp).
        assert_eq!(all[0].1.len(), 2);
        assert_eq!(all[0].1[0].source, RouteSource::Static);
        assert_eq!(all[0].1[1].source, RouteSource::Bgp);
    }

    #[test]
    fn lookup_performs_longest_prefix_match() {
        let mut rib = Rib::new();
        let broad: IpNet = "10.0.0.0/16".parse().unwrap();
        let narrow: IpNet = "10.0.1.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix: broad,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.insert(RibEntry {
            prefix: narrow,
            next_hops: vec![("10.0.1.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });

        let (matched, candidates) = rib.lookup("10.0.1.5".parse().unwrap()).unwrap();
        assert_eq!(matched, narrow);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].next_hops[0].gateway,
            "10.0.1.1".parse::<IpAddr>().unwrap()
        );

        let (matched, _) = rib.lookup("10.0.2.5".parse().unwrap()).unwrap();
        assert_eq!(matched, broad);

        assert!(rib.lookup("192.168.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn build_from_config_table_not_found_is_none() {
        assert!(build_from_config(&cfg(vec![], vec![]), "rt1", &HashSet::new()).is_none());
    }

    #[test]
    fn build_from_config_table_without_static_instance_is_empty() {
        let tables = vec![RoutingTable {
            rest_api: None,
            ssh_server: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: None,
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: Vec::new(),
        }];
        let rib = build_from_config(&cfg(tables, vec![]), "rt1", &HashSet::new()).unwrap();
        assert!(rib.is_empty());
    }

    #[test]
    fn replace_source_leaves_other_sources_untouched() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.replace_source(
            RouteSource::Static,
            vec![RibEntry {
                prefix,
                next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
                source: RouteSource::Static,
                backup: None,
                backup_interface_id: None,
                backup_tunnel: false,
            }],
        );
        let candidates = rib
            .all_routes()
            .into_iter()
            .find(|(p, _)| *p == prefix)
            .unwrap()
            .1;
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().any(|e| e.source == RouteSource::Bgp));
        assert!(candidates.iter().any(|e| e.source == RouteSource::Static));
    }

    #[test]
    fn replace_source_with_empty_clears_only_that_source_and_prunes() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.replace_source(RouteSource::Static, Vec::new());
        assert!(rib.is_empty());
    }

    #[test]
    fn upsert_replaces_prior_same_source_candidate_only() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.upsert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.upsert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.99".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        let candidates = rib
            .all_routes()
            .into_iter()
            .find(|(p, _)| *p == prefix)
            .unwrap()
            .1;
        assert_eq!(candidates.len(), 2);
        let bgp = candidates
            .iter()
            .find(|e| e.source == RouteSource::Bgp)
            .unwrap();
        assert_eq!(
            bgp.next_hops[0].gateway,
            "10.0.0.99".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn upsert_and_diff_reports_unchanged_for_an_identical_resend() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        let entry = RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        };
        assert_eq!(
            rib.upsert_and_diff(entry.clone()),
            BestPathChange::Installed(entry.clone())
        );
        assert_eq!(rib.upsert_and_diff(entry), BestPathChange::Unchanged);
    }

    #[test]
    fn upsert_and_diff_reports_unchanged_when_a_losing_candidate_churns() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        // Static already wins this prefix, so a new/changed Bgp candidate
        // never becomes the winner — no kernel-visible change.
        assert_eq!(
            rib.upsert_and_diff(RibEntry {
                prefix,
                next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
                source: RouteSource::Bgp,
                backup: None,
                backup_interface_id: None,
                backup_tunnel: false,
            }),
            BestPathChange::Unchanged
        );
    }

    #[test]
    fn upsert_and_diff_reports_installed_when_a_better_candidate_arrives() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        let bgp_entry = RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        };
        assert_eq!(
            rib.upsert_and_diff(bgp_entry),
            BestPathChange::Installed(RibEntry {
                prefix,
                next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
                source: RouteSource::Bgp,
                backup: None,
                backup_interface_id: None,
                backup_tunnel: false,
            })
        );
        let static_entry = RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        };
        assert_eq!(
            rib.upsert_and_diff(static_entry.clone()),
            BestPathChange::Installed(static_entry)
        );
    }

    #[test]
    fn remove_and_diff_reports_removed_when_the_last_candidate_goes() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        assert_eq!(
            rib.remove_and_diff(&prefix, RouteSource::Bgp),
            BestPathChange::Removed
        );
    }

    #[test]
    fn remove_and_diff_reports_unchanged_when_a_losing_candidate_is_removed() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        // Static still wins after Bgp's candidate is removed.
        assert_eq!(
            rib.remove_and_diff(&prefix, RouteSource::Bgp),
            BestPathChange::Unchanged
        );
    }

    #[test]
    fn remove_and_diff_reports_installed_when_the_winner_falls_back() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        assert_eq!(
            rib.remove_and_diff(&prefix, RouteSource::Static),
            BestPathChange::Installed(RibEntry {
                prefix,
                next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
                source: RouteSource::Bgp,
                backup: None,
                backup_interface_id: None,
                backup_tunnel: false,
            })
        );
    }

    #[test]
    fn remove_drops_only_named_source_and_prunes_if_last() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
        rib.remove(&prefix, RouteSource::Bgp);
        let candidates = rib
            .all_routes()
            .into_iter()
            .find(|(p, _)| *p == prefix)
            .unwrap()
            .1;
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].source, RouteSource::Static);

        rib.remove(&prefix, RouteSource::Static);
        assert!(rib.is_empty());
    }

    #[test]
    fn build_from_config_resolves_static_routes() {
        let tables = vec![RoutingTable {
            rest_api: None,
            ssh_server: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: None,
            ospf_instance: None,
            static_routing_instance: Some("sri1".into()),
            redistribute: Vec::new(),
        }];
        let instances = vec![StaticRoutingInstance {
            name: "sri1".into(),
            routes: vec![StaticRoute {
                bfd: None,
                subnet: "10.0.0.0/24".parse().unwrap(),
                gateway: "10.0.0.1".parse().unwrap(),
            }],
        }];
        let rib = build_from_config(&cfg(tables, instances), "rt1", &HashSet::new()).unwrap();
        let best = rib.best_route(&"10.0.0.0/24".parse().unwrap()).unwrap();
        assert_eq!(best.source, RouteSource::Static);
        assert_eq!(
            best.next_hops[0].gateway,
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn bfd_routes_wait_for_their_gateway_to_be_up() {
        let mut c = cfg(
            vec![RoutingTable {
                name: "rt1".into(),
                static_routing_instance: Some("sri1".into()),
                ..RoutingTable::default()
            }],
            vec![StaticRoutingInstance {
                name: "sri1".into(),
                routes: vec![
                    StaticRoute {
                        subnet: "10.1.0.0/24".parse().unwrap(),
                        gateway: "10.0.0.1".parse().unwrap(),
                        bfd: Some("fast".into()),
                    },
                    StaticRoute {
                        subnet: "10.2.0.0/24".parse().unwrap(),
                        gateway: "10.0.0.2".parse().unwrap(),
                        bfd: None,
                    },
                ],
            }],
        );
        c.bfd_profiles = vec![BfdProfile {
            name: "fast".into(),
            ..BfdProfile::default()
        }];
        let gw: IpAddr = "10.0.0.1".parse().unwrap();
        let held = build_from_config(&c, "rt1", &HashSet::new()).unwrap();
        assert!(held.best_route(&"10.1.0.0/24".parse().unwrap()).is_none());
        assert!(held.best_route(&"10.2.0.0/24".parse().unwrap()).is_some());
        let up = build_from_config(&c, "rt1", &HashSet::from([gw])).unwrap();
        assert!(up.best_route(&"10.1.0.0/24".parse().unwrap()).is_some());

        let target = bfd_target(&c, "rt1");
        assert_eq!(target.len(), 1);
        assert_eq!(target[&gw].profile.name, "fast");
        assert!(target[&gw].multihop, "no connected subnet in the config");
        assert!(bfd_target(&c, "nope").is_empty());
        c.interfaces = vec![nos_proto::Interface {
            name: "loopback-rt1".into(),
            routing_table: Some("rt1".into()),
            addresses: vec![nos_proto::schema::interface::InterfaceAddress {
                address: "10.0.0.254/24".parse().unwrap(),
                label: None,
            }],
            ..Default::default()
        }];
        assert!(!bfd_target(&c, "rt1")[&gw].multihop);
    }
}
