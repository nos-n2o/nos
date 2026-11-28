use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use nos_proto::{Config, IpNet, NextHop, RouteFilter, RouteSourceKind, SourceCount};
use tokio::time::Instant;
use tracing::{info, warn};

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
    pub(crate) fn preference(self) -> u8 {
        match self {
            RouteSource::Connected => 0,
            RouteSource::Static => 1,
            RouteSource::Bgp => 20,
            RouteSource::Ospf => 110,
            RouteSource::Evpn | RouteSource::Vpn => 200,
        }
    }
}

/// Who pushed an `Ospf` route: one OSPF daemon instance. The family is part of
/// the key because `ospf_instances` and `ospfv3_instances` are separate
/// sections that may reuse a name (#1277). Orders v2 before v3, then by name,
/// the final best-path tie-break.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OspfOwner {
    /// `true` for `nos-ospfv3d`.
    pub v3: bool,
    /// The instance name.
    pub name: String,
}

impl OspfOwner {
    /// The owner for the daemon `role` pushing as `instance`.
    pub fn new(v3: bool, instance: impl Into<String>) -> Self {
        Self {
            v3,
            name: instance.into(),
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
    /// A `Static` route's own administrative distance (#1523); `None` keeps
    /// the source default. Part of equality.
    pub distance: Option<u8>,
    /// A `Static` route's tag, shown by `show route`. Part of equality.
    pub tag: Option<u32>,
    /// A `Static` route's pinned outgoing interface NAME per gateway, resolved
    /// to an ifindex by the Linux driver at install (#1616). Empty for other
    /// sources. Part of equality.
    pub interfaces: BTreeMap<IpAddr, String>,
}

impl RibEntry {
    /// Lower wins: the entry's own `distance`, else its source's default.
    pub(crate) fn preference(&self) -> u8 {
        self.distance.unwrap_or_else(|| self.source.preference())
    }

    /// Best-path ordering key: preference, then the source default (a static
    /// with `distance 20` beats eBGP's 20: the tie rule, #1523).
    pub(crate) fn rank(&self) -> (u8, u8) {
        (self.preference(), self.source.preference())
    }

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
    /// MED per `Bgp`-sourced prefix, kept beside `entries` like `ospf_metrics`.
    bgp_metrics: HashMap<IpNet, u32>,
    /// When each candidate appeared or last changed its next hops, with a
    /// fingerprint of them: `show route`'s age. Beside `entries`, so time
    /// never counts as a change of the winner.
    first_seen: HashMap<(IpNet, RouteSource), (u64, Instant)>,
    /// Interface name of each `Connected` prefix (physical and subinterface
    /// only), for `show route`; set by `reconcile::resync`.
    pub connected_iface: HashMap<IpNet, String>,
    /// Each OSPF owner's own routes and SPF costs (#1277). `entries` holds one
    /// derived `Ospf` candidate per prefix, the best across owners
    /// (`refresh_ospf`), so the rest of the table never sees owners.
    ospf: BTreeMap<OspfOwner, HashMap<IpNet, (RibEntry, u32)>>,
    /// The table's EVPN IP-VRF state, beside `entries` like `ospf_metrics`.
    pub evpn: crate::evpn::EvpnState,
    /// PE and RD of each next hop per `Vpn`-sourced prefix, for `show route` only (beside
    /// `entries` like `ospf_metrics`: the kernel never sees it).
    pub vpn_info: HashMap<IpNet, Vec<nos_proto::VpnRouteInfo>>,
    /// This VRF's label (`vpn::VrfExport::label`), for `show route`.
    pub vpn_label: Option<u32>,
    /// Each OSPF owner's ILM set (`PushMplsRoutes`, #1165), beside `ospf`.
    ilm: BTreeMap<OspfOwner, Vec<nos_proto::IlmRoute>>,
    /// ILM entries given on the command line (`--test-ilm`, e2e only).
    pub ilm_fixed: Vec<nos_proto::IlmRoute>,
    /// Every configured `Static` entry as `build_from_config` made it (#1527):
    /// the source `reresolve` derives the installed entry from.
    static_cfg: HashMap<IpNet, RibEntry>,
    /// Recursive statics no covering route resolves: still a `Static`
    /// candidate (`show route`), never a winner, never a cover.
    unresolved: HashSet<IpNet>,
    /// The hops each resolved recursive static was last derived with.
    resolved_hops: HashMap<IpNet, Vec<NextHop>>,
}

/// Recursion depth of a static next hop (#1527): rounds of `Rib::reresolve`.
const MAX_RECURSION: usize = 4;

impl Rib {
    /// Replaces `owner`'s ILM set (empty removes it).
    pub fn set_ilm(&mut self, owner: OspfOwner, routes: Vec<nos_proto::IlmRoute>) {
        if routes.is_empty() {
            self.ilm.remove(&owner);
        } else {
            self.ilm.insert(owner, routes);
        }
    }

    /// Every ILM entry of the table by label: the fixed ones, then each owner
    /// in order; the first claim on a label wins, later ones are dropped
    /// (the clash is the caller's to log: see `ilm_clashes`).
    pub fn ilm_routes(&self) -> Vec<nos_proto::IlmRoute> {
        let mut seen = HashSet::new();
        let mut out: Vec<_> = self
            .ilm_fixed
            .iter()
            .chain(self.ilm.values().flatten())
            .filter(|r| seen.insert(r.label))
            .cloned()
            .collect();
        out.sort_by_key(|r| r.label);
        out
    }

    /// Labels claimed by more than one pusher.
    pub fn ilm_clashes(&self) -> Vec<u32> {
        let mut seen = HashSet::new();
        let mut dup: Vec<u32> = self
            .ilm_fixed
            .iter()
            .chain(self.ilm.values().flatten())
            .filter(|r| !seen.insert(r.label))
            .map(|r| r.label)
            .collect();
        dup.sort_unstable();
        dup.dedup();
        dup
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, entry: RibEntry) {
        let prefix = entry.prefix;
        self.entries.entry(prefix).or_default().push(entry);
        self.touch(&prefix);
    }

    /// Stamps `prefix`'s candidates: a candidate whose next hops are unchanged
    /// keeps its stamp, a new or changed one starts now, a gone one is dropped.
    fn touch(&mut self, prefix: &IpNet) {
        let now = Instant::now();
        let candidates = self.entries.get(prefix).map_or(&[][..], Vec::as_slice);
        for src in ALL_SOURCES {
            let key = (*prefix, src);
            match candidates.iter().find(|e| e.source == src) {
                Some(e) => {
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    e.next_hops.hash(&mut h);
                    let fp = h.finish();
                    match self.first_seen.get(&key) {
                        Some((old, _)) if *old == fp => {}
                        _ => {
                            self.first_seen.insert(key, (fp, now));
                        }
                    }
                }
                None => {
                    self.first_seen.remove(&key);
                }
            }
        }
    }

    /// Seconds `source`'s candidate for `prefix` has been as it is now.
    pub fn age_secs(&self, prefix: &IpNet, source: RouteSource) -> u64 {
        self.first_seen
            .get(&(*prefix, source))
            .map_or(0, |(_, t)| t.elapsed().as_secs())
    }

    /// The metric of `source`'s candidate for `prefix` (`Ospf` SPF cost,
    /// `Bgp` MED), if it has one.
    pub fn metric(&self, prefix: &IpNet, source: RouteSource) -> Option<u32> {
        match source {
            RouteSource::Ospf => self.ospf_metrics.get(prefix).copied(),
            RouteSource::Bgp => self.bgp_metrics.get(prefix).copied(),
            _ => None,
        }
    }

    /// Records (`Some`) or forgets (`None`) one prefix's BGP MED.
    pub fn set_bgp_metric(&mut self, prefix: IpNet, metric: Option<u32>) {
        match metric {
            Some(m) => self.bgp_metrics.insert(prefix, m),
            None => self.bgp_metrics.remove(&prefix),
        };
    }

    /// Replaces every prefix's BGP MED (a `Full` push).
    pub fn set_bgp_metrics(&mut self, metrics: HashMap<IpNet, u32>) {
        self.bgp_metrics = metrics;
    }

    /// The interface a next hop `addr` leaves over, by the longest
    /// `Connected` prefix covering it that has a name.
    pub fn iface_for_gateway(&self, addr: IpAddr) -> Option<&str> {
        self.connected_iface
            .iter()
            .filter(|(net, _)| net.contains(&addr))
            .max_by_key(|(net, _)| net.prefix_len())
            .map(|(_, n)| n.as_str())
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
        debug_assert_ne!(source, RouteSource::Ospf, "use replace_ospf");
        for candidates in self.entries.values_mut() {
            candidates.retain(|e| e.source != source);
        }
        let mut added = Vec::new();
        if source == RouteSource::Static {
            self.static_cfg.clear();
        }
        for entry in entries {
            debug_assert_eq!(entry.source, source);
            added.push(entry.prefix);
            if source == RouteSource::Static {
                self.static_cfg.insert(entry.prefix, entry.clone());
            }
            self.entries.entry(entry.prefix).or_default().push(entry);
        }
        self.entries.retain(|_, c| !c.is_empty());
        for prefix in &added {
            self.touch(prefix);
        }
        let entries = &self.entries;
        self.first_seen.retain(|(p, s), _| {
            *s != source
                || entries
                    .get(p)
                    .is_some_and(|c| c.iter().any(|e| e.source == *s))
        });
        if matches!(source, RouteSource::Static | RouteSource::Connected) {
            // The caller applies the whole table next.
            let _ = self.reresolve();
        }
    }

    /// Whether `e` is a recursive static with no resolution (#1527).
    pub(crate) fn is_unresolved(&self, prefix: &IpNet, e: &RibEntry) -> bool {
        e.source == RouteSource::Static && self.unresolved.contains(prefix)
    }

    /// `candidates` best (lowest preference value) first, an unresolved
    /// static after every other.
    fn sorted(&self, prefix: &IpNet, candidates: &[RibEntry]) -> Vec<RibEntry> {
        let mut sorted = candidates.to_vec();
        sorted.sort_by_key(|e| (self.is_unresolved(prefix, e), e.rank()));
        sorted
    }

    /// The best candidate a next hop may resolve through: no overlay source
    /// (`Bgp`/`Evpn`/`Vpn`), no discard route (RFC 4271 section 9.1.2) and no
    /// unresolved static.
    fn resolving_best<'a>(
        &self,
        prefix: &IpNet,
        candidates: &'a [RibEntry],
    ) -> Option<&'a RibEntry> {
        candidates
            .iter()
            .filter(|e| {
                !matches!(
                    e.source,
                    RouteSource::Bgp | RouteSource::Evpn | RouteSource::Vpn
                ) && !e.is_discard()
                    && !self.is_unresolved(prefix, e)
            })
            .min_by_key(|e| e.rank())
    }

    /// The longest prefix covering `addr` and its best resolving candidate.
    fn cover(&self, addr: IpAddr) -> Option<(&IpNet, &RibEntry)> {
        self.entries
            .iter()
            .filter(|(net, _)| net.contains(&addr))
            .filter_map(|(net, c)| Some((net, self.resolving_best(net, c)?)))
            .max_by_key(|(net, _)| net.prefix_len())
    }

    /// Replaces a prefix's `Static` candidate by `entry`.
    fn put_static(&mut self, entry: RibEntry) {
        let prefix = entry.prefix;
        let c = self.entries.entry(prefix).or_default();
        match c.iter_mut().find(|e| e.source == RouteSource::Static) {
            Some(old) if *old == entry => return,
            Some(old) => *old = entry,
            None => c.push(entry),
        }
        self.touch(&prefix);
    }

    /// Recursive static next hops (#1527): a static hop that is not on-link
    /// (no pinned interface, no `Connected` prefix covering the gateway)
    /// takes the next hops of the longest route covering it. Rounds: round n
    /// resolves only through entries resolved in earlier rounds, so depth is
    /// at most `MAX_RECURSION` and a cycle never resolves. A static no hop of
    /// which resolves stays an `unresolved` candidate. Returns the delta
    /// (`None` = no winner left) of every prefix whose winner changed.
    // ponytail: linear cover scan per recursive hop per round; a prefix trie
    // if a table ever holds thousands of recursive statics.
    pub fn reresolve(&mut self) -> HashMap<IpNet, Option<RibEntry>> {
        if self.static_cfg.is_empty() && self.unresolved.is_empty() && self.resolved_hops.is_empty()
        {
            return HashMap::new();
        }
        let connected: Vec<IpNet> = self
            .entries
            .values()
            .flatten()
            .filter(|e| e.source == RouteSource::Connected)
            .map(|e| e.prefix)
            .collect();
        let on_link = |e: &RibEntry, gw: IpAddr| {
            e.interfaces.contains_key(&gw) || connected.iter().any(|n| n.contains(&gw))
        };
        let recursive: Vec<RibEntry> = self
            .static_cfg
            .values()
            .filter(|e| e.next_hops.iter().any(|h| !on_link(e, h.gateway)))
            .cloned()
            .collect();
        let old_unresolved = std::mem::take(&mut self.unresolved);
        let old_resolved = std::mem::take(&mut self.resolved_hops);
        let mut before: HashMap<IpNet, Option<RibEntry>> = HashMap::new();
        for p in old_unresolved
            .iter()
            .chain(old_resolved.keys())
            .chain(recursive.iter().map(|e| &e.prefix))
        {
            before.insert(*p, self.best_route_in(p, &old_unresolved).cloned());
        }
        // Back to the configured entries; the recursive ones are pending.
        for p in old_resolved.keys() {
            if let Some(orig) = self.static_cfg.get(p).cloned() {
                self.put_static(orig);
            }
        }
        for e in &recursive {
            self.put_static(e.clone());
            self.unresolved.insert(e.prefix);
        }
        let mut resolved: HashMap<IpNet, Vec<NextHop>> = HashMap::new();
        for _ in 0..MAX_RECURSION {
            let mut round = Vec::new();
            for e in recursive
                .iter()
                .filter(|e| self.unresolved.contains(&e.prefix))
            {
                let mut hops = Vec::new();
                for h in &e.next_hops {
                    if on_link(e, h.gateway) {
                        hops.push(h.clone());
                    } else if let Some((_, c)) = self.cover(h.gateway) {
                        hops.extend(c.next_hops.iter().cloned());
                    }
                }
                hops.sort();
                hops.dedup();
                if !hops.is_empty() {
                    round.push((e, hops));
                }
            }
            if round.is_empty() {
                break;
            }
            for (e, hops) in round {
                self.unresolved.remove(&e.prefix);
                let mut derived = e.clone();
                derived.next_hops.clone_from(&hops);
                self.put_static(derived);
                resolved.insert(e.prefix, hops);
            }
        }
        for e in &recursive {
            let p = e.prefix;
            let gateway = e.next_hops[0].gateway;
            if let Some(hops) = resolved.get(&p) {
                if old_resolved.get(&p) != Some(hops) {
                    let via = hops[0].gateway;
                    info!(prefix = %p, %gateway, %via, "static next hop resolved");
                }
            } else if !old_unresolved.contains(&p) {
                warn!(prefix = %p, %gateway, "static next hop unresolved");
            }
        }
        self.resolved_hops = resolved;
        let mut deltas = HashMap::new();
        for (p, b) in before {
            let after = self.best_route(&p).cloned();
            if b != after {
                deltas.insert(p, after);
            }
        }
        deltas
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
        debug_assert_ne!(entry.source, RouteSource::Ospf, "use upsert_ospf_and_diff");
        let candidates = self.entries.entry(entry.prefix).or_default();
        candidates.retain(|e| e.source != entry.source);
        let prefix = entry.prefix;
        candidates.push(entry);
        self.touch(&prefix);
    }

    /// Removes `source`'s candidate for `prefix`, if any — used for a BGP
    /// push's incremental `Remove`. Prunes the prefix entirely if that was
    /// its last remaining candidate.
    pub fn remove(&mut self, prefix: &IpNet, source: RouteSource) {
        debug_assert_ne!(source, RouteSource::Ospf, "use remove_ospf_and_diff");
        if let Some(candidates) = self.entries.get_mut(prefix) {
            candidates.retain(|e| e.source != source);
            if candidates.is_empty() {
                self.entries.remove(prefix);
            }
            self.touch(prefix);
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
        self.best_route_in(prefix, &self.unresolved)
    }

    /// `best_route` with `unresolved` as the set of dormant statics.
    fn best_route_in(&self, prefix: &IpNet, unresolved: &HashSet<IpNet>) -> Option<&RibEntry> {
        let dormant = unresolved.contains(prefix);
        self.entries
            .get(prefix)?
            .iter()
            .filter(|e| !(dormant && e.source == RouteSource::Static))
            .min_by_key(|e| e.rank())
    }

    /// The winning route for every known prefix.
    pub fn best_routes(&self) -> HashMap<IpNet, RibEntry> {
        self.entries
            .keys()
            .filter_map(|prefix| self.best_route(prefix).cloned().map(|e| (*prefix, e)))
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
            .map(|(prefix, candidates)| (*prefix, self.sorted(prefix, candidates)))
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
    ///
    /// `filter` (#1445) selects prefixes (`prefix` exact, or covered-by with
    /// `longer`; `source`: has a candidate of it) and drops the other
    /// sources' candidates; `more` is over the filtered prefixes.
    pub fn routes_page(
        &self,
        after: Option<IpNet>,
        limit: usize,
        filter: &RouteFilter,
    ) -> (Vec<(IpNet, Vec<RibEntry>)>, bool) {
        let kind = |e: &RibEntry| crate::server::to_source_kind(e.source);
        let mut heap = std::collections::BinaryHeap::with_capacity(limit + 1);
        for prefix in self.entries.keys().filter(|p| {
            after.is_none_or(|a| **p > a)
                && filter.prefix.is_none_or(|f| {
                    if filter.longer {
                        f.contains(*p)
                    } else {
                        **p == f
                    }
                })
                && filter
                    .source
                    .is_none_or(|s| self.entries[*p].iter().any(|e| kind(e) == s))
        }) {
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
            .map(|p| {
                let mut c = self.sorted(&p, &self.entries[&p]);
                if let Some(s) = filter.source {
                    c.retain(|e| kind(e) == s);
                }
                (p, c)
            })
            .collect();
        (page, more)
    }

    /// Distinct prefixes per family (v4, v6) and the candidates per source
    /// (only sources with one), in `RouteSourceKind` declaration order.
    pub fn summary_counts(&self) -> (u32, u32, Vec<SourceCount>) {
        let n = |x: usize| u32::try_from(x).unwrap_or(u32::MAX);
        let v4 = self
            .entries
            .keys()
            .filter(|p| matches!(p, IpNet::V4(_)))
            .count();
        let sources = RouteSourceKind::ALL
            .into_iter()
            .filter_map(|source| {
                let count = |v4: bool| {
                    self.entries
                        .iter()
                        .filter(|(p, _)| matches!(p, IpNet::V4(_)) == v4)
                        .flat_map(|(_, c)| c)
                        .filter(|e| crate::server::to_source_kind(e.source) == source)
                        .count()
                };
                let (ipv4, ipv6) = (n(count(true)), n(count(false)));
                (ipv4 + ipv6 > 0).then_some(SourceCount { source, ipv4, ipv6 })
            })
            .collect();
        (n(v4), n(self.entries.len() - v4), sources)
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
        Some((*prefix, self.sorted(prefix, candidates)))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records (`Some`) or forgets (`None`) one prefix's OSPF metric.
    pub fn set_ospf_metric(&mut self, prefix: IpNet, metric: Option<u32>) {
        match metric {
            Some(m) => self.ospf_metrics.insert(prefix, m),
            None => self.ospf_metrics.remove(&prefix),
        };
    }

    /// Re-derives `prefix`'s single `Ospf` candidate and metric from every
    /// owner's route: a real route beats a discard, then the lowest SPF cost,
    /// then owner order. A discard of one owner never hides another's route.
    fn refresh_ospf(&mut self, prefix: &IpNet) {
        let best = self
            .ospf
            .iter()
            .filter_map(|(owner, routes)| Some((owner, routes.get(prefix)?)))
            .min_by_key(|(owner, (e, metric))| (e.is_discard(), *metric, *owner))
            .map(|(_, (e, metric))| (e.clone(), *metric));
        if let Some(candidates) = self.entries.get_mut(prefix) {
            candidates.retain(|e| e.source != RouteSource::Ospf);
        }
        if let Some((entry, metric)) = best {
            self.entries.entry(*prefix).or_default().push(entry);
            self.ospf_metrics.insert(*prefix, metric);
        } else {
            self.ospf_metrics.remove(prefix);
            if self.entries.get(prefix).is_some_and(Vec::is_empty) {
                self.entries.remove(prefix);
            }
        }
        self.touch(prefix);
    }

    /// Replaces every route of one OSPF owner (a `Full` push), leaving the
    /// other owners' untouched.
    pub fn replace_ospf(
        &mut self,
        owner: &OspfOwner,
        routes: impl IntoIterator<Item = (RibEntry, u32)>,
    ) {
        let new: HashMap<IpNet, (RibEntry, u32)> = routes
            .into_iter()
            .map(|(e, m)| (e.prefix, (e, m)))
            .collect();
        let mut touched: Vec<IpNet> = new.keys().copied().collect();
        if let Some(old) = self.ospf.insert(owner.clone(), new) {
            touched.extend(old.into_keys());
        }
        for prefix in touched {
            self.refresh_ospf(&prefix);
        }
        // The caller applies the whole table next.
        let _ = self.reresolve();
    }

    /// One owner's incremental `Add`; reports the prefix's winner change.
    pub fn upsert_ospf_and_diff(
        &mut self,
        owner: &OspfOwner,
        entry: RibEntry,
        metric: u32,
    ) -> BestPathChange {
        let prefix = entry.prefix;
        let before = self.best_route(&prefix).cloned();
        self.ospf
            .entry(owner.clone())
            .or_default()
            .insert(prefix, (entry, metric));
        self.refresh_ospf(&prefix);
        diff_best(before.as_ref(), self.best_route(&prefix).cloned())
    }

    /// One owner's incremental `Remove`; reports the prefix's winner change.
    pub fn remove_ospf_and_diff(&mut self, owner: &OspfOwner, prefix: &IpNet) -> BestPathChange {
        let before = self.best_route(prefix).cloned();
        if let Some(routes) = self.ospf.get_mut(owner) {
            routes.remove(prefix);
        }
        self.refresh_ospf(prefix);
        diff_best(before.as_ref(), self.best_route(prefix).cloned())
    }

    /// Drops every owner not in `keep` (its instance left the config) and
    /// returns them. The caller applies the table to the kernel afterwards.
    pub fn retain_ospf_owners(&mut self, keep: &HashSet<OspfOwner>) -> Vec<OspfOwner> {
        let gone: Vec<OspfOwner> = self
            .ospf
            .keys()
            .filter(|o| !keep.contains(*o))
            .cloned()
            .collect();
        self.ilm.retain(|o, _| keep.contains(o));
        for owner in &gone {
            if let Some(old) = self.ospf.remove(owner) {
                for prefix in old.into_keys() {
                    self.refresh_ospf(&prefix);
                }
            }
        }
        if !gone.is_empty() {
            let _ = self.reresolve();
        }
        gone
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
        self.cover(addr).map(|(_, e)| {
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
                let best = self.resolving_best(prefix, candidates)?;
                let cost = match best.source {
                    RouteSource::Ospf => self.ospf_metrics.get(prefix).copied().unwrap_or(0),
                    _ => 0,
                };
                Some((*prefix, cost))
            })
            .collect()
    }
}

const ALL_SOURCES: [RouteSource; 6] = [
    RouteSource::Static,
    RouteSource::Bgp,
    RouteSource::Ospf,
    RouteSource::Connected,
    RouteSource::Evpn,
    RouteSource::Vpn,
];

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
                // One entry per prefix (the Rib holds one `Static` per
                // prefix): the primary gateway plus every extra one, each
                // BFD-gated on its own profile (fail closed until `Up`).
                let mut hops: Vec<IpAddr> = Vec::new();
                if !route.blackhole {
                    hops = std::iter::once((route.gateway, route.bfd.is_some()))
                        .chain(route.next_hops.iter().map(|h| (h.gateway, h.bfd.is_some())))
                        .filter(|(gw, bfd)| !bfd || bfd_up.contains(gw))
                        .map(|(gw, _)| gw)
                        .collect();
                    if hops.is_empty() {
                        continue; // every hop BFD-down: not a discard route
                    }
                }
                // Config order must not change the entry (equality, replace).
                hops.sort();
                // Each hop pins its own link; the primary takes the route's.
                let mut interfaces = BTreeMap::new();
                if !route.blackhole {
                    let extra = route
                        .next_hops
                        .iter()
                        .filter_map(|h| Some((h.gateway, h.interface.clone()?)));
                    let all = route
                        .interface
                        .clone()
                        .map(|i| (route.gateway, i))
                        .into_iter()
                        .chain(extra);
                    // A BFD-dropped hop's pin goes with it.
                    interfaces.extend(all.filter(|(gw, _)| hops.contains(gw)));
                }
                rib.insert(RibEntry {
                    prefix: route.subnet,
                    // A blackhole is a discard: no next hop (`is_discard`).
                    next_hops: hops.into_iter().map(|gw| (gw, None).into()).collect(),
                    source: RouteSource::Static,
                    backup: None,
                    backup_interface_id: None,
                    backup_tunnel: false,
                    distance: route.distance,
                    tag: route.tag,
                    interfaces,
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
    // Primary and extra hops alike; one session per gateway, so hops sharing
    // a gateway share a profile (the last one listed wins).
    routes
        .iter()
        .flat_map(|r| {
            std::iter::once((r.gateway, r.bfd.as_ref()))
                .chain(r.next_hops.iter().map(|h| (h.gateway, h.bfd.as_ref())))
        })
        .filter_map(|(gateway, bfd)| {
            let profile = cfg.bfd_profiles.iter().find(|p| Some(&p.name) == bfd)?;
            Some((
                gateway,
                crate::bfd_client::Want {
                    profile: profile.clone(),
                    multihop: !cfg.is_connected(table_name, gateway),
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::schema::BfdProfile;
    use nos_proto::{
        RouteSourceKind, RoutingTable, StaticNextHop, StaticRoute, StaticRoutingInstance,
    };

    fn cfg(tables: Vec<RoutingTable>, instances: Vec<StaticRoutingInstance>) -> Config {
        Config {
            routing_tables: tables,
            static_routing_instances: instances,
            ..Default::default()
        }
    }

    fn hop_entry(p: &str, gw: &str, source: RouteSource) -> RibEntry {
        RibEntry {
            prefix: p.parse().unwrap(),
            next_hops: vec![(gw.parse().unwrap(), None).into()],
            source,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn age_is_outside_equality_and_restarts_on_a_next_hop_change() {
        let mut rib = Rib::new();
        let p: IpNet = "10.1.0.0/16".parse().unwrap();
        let e = hop_entry("10.1.0.0/16", "10.0.0.1", RouteSource::Bgp);
        rib.upsert_and_diff(e.clone());
        tokio::time::advance(std::time::Duration::from_secs(90)).await;
        assert_eq!(rib.age_secs(&p, RouteSource::Bgp), 90);
        // Re-sent identical: no change, stamp kept.
        assert_eq!(rib.upsert_and_diff(e), BestPathChange::Unchanged);
        assert_eq!(rib.age_secs(&p, RouteSource::Bgp), 90);
        // New next hop: restamped.
        rib.upsert_and_diff(hop_entry("10.1.0.0/16", "10.0.0.2", RouteSource::Bgp));
        assert_eq!(rib.age_secs(&p, RouteSource::Bgp), 0);
        // A wholesale replace keeps an unchanged candidate's stamp too.
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        rib.replace_source(
            RouteSource::Bgp,
            [hop_entry("10.1.0.0/16", "10.0.0.2", RouteSource::Bgp)],
        );
        assert_eq!(rib.age_secs(&p, RouteSource::Bgp), 5);
        rib.remove(&p, RouteSource::Bgp);
        assert_eq!(rib.age_secs(&p, RouteSource::Bgp), 0);
        assert!(rib.first_seen.is_empty());
    }

    #[test]
    fn a_metric_only_change_is_unchanged_but_visible() {
        let mut rib = Rib::new();
        let p: IpNet = "10.1.0.0/16".parse().unwrap();
        let e = hop_entry("10.1.0.0/16", "10.0.0.1", RouteSource::Bgp);
        rib.set_bgp_metric(p, Some(10));
        rib.upsert_and_diff(e.clone());
        rib.set_bgp_metric(p, Some(20));
        assert_eq!(rib.upsert_and_diff(e), BestPathChange::Unchanged);
        assert_eq!(rib.metric(&p, RouteSource::Bgp), Some(20));
        assert_eq!(rib.metric(&p, RouteSource::Static), None);
        let o = hop_entry("10.2.0.0/16", "10.0.0.1", RouteSource::Ospf);
        let owner = OspfOwner::new(false, "a");
        rib.upsert_ospf_and_diff(&owner, o.clone(), 5);
        assert_eq!(
            rib.upsert_ospf_and_diff(&owner, o, 9),
            BestPathChange::Unchanged
        );
        assert_eq!(
            rib.metric(&"10.2.0.0/16".parse().unwrap(), RouteSource::Ospf),
            Some(9)
        );
    }

    #[test]
    fn iface_for_gateway_takes_the_longest_named_prefix() {
        let mut rib = Rib::new();
        rib.connected_iface
            .insert("10.0.0.0/8".parse().unwrap(), "eth0".into());
        rib.connected_iface
            .insert("10.1.0.0/16".parse().unwrap(), "eth1.5".into());
        assert_eq!(
            rib.iface_for_gateway("10.1.2.3".parse().unwrap()),
            Some("eth1.5")
        );
        assert_eq!(
            rib.iface_for_gateway("10.9.2.3".parse().unwrap()),
            Some("eth0")
        );
        assert_eq!(rib.iface_for_gateway("192.0.2.1".parse().unwrap()), None);
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        });
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        });
        assert_eq!(rib.best_route(&prefix).unwrap().source, RouteSource::Static);
    }

    fn floating(prefix: &str, distance: u8) -> RibEntry {
        RibEntry {
            distance: Some(distance),
            ..entry(prefix, "10.0.0.1", RouteSource::Static)
        }
    }

    #[test]
    fn a_floating_static_loses_then_takes_over() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.9.0.0/24".parse().unwrap();
        rib.insert(floating("10.9.0.0/24", 250));
        let bgp = entry("10.9.0.0/24", "10.0.0.9", RouteSource::Bgp);
        assert!(matches!(
            rib.upsert_and_diff(bgp),
            BestPathChange::Installed(e) if e.source == RouteSource::Bgp
        ));
        assert!(matches!(
            rib.remove_and_diff(&prefix, RouteSource::Bgp),
            BestPathChange::Installed(e) if e.source == RouteSource::Static
        ));
    }

    #[test]
    fn a_lower_distance_static_beats_bgp_and_a_tie_goes_to_static() {
        let mut rib = Rib::new();
        let prefix: IpNet = "10.9.0.0/24".parse().unwrap();
        rib.insert(entry("10.9.0.0/24", "10.0.0.9", RouteSource::Ospf));
        rib.insert(floating("10.9.0.0/24", 100));
        assert_eq!(rib.best_route(&prefix).unwrap().source, RouteSource::Static);
        rib.insert(entry("10.9.0.0/24", "10.0.0.9", RouteSource::Bgp));
        // Static 100 vs eBGP 20: BGP wins; static 20 ties and wins.
        assert_eq!(rib.best_route(&prefix).unwrap().source, RouteSource::Bgp);
        rib.insert(floating("10.9.0.0/24", 20));
        assert_eq!(rib.best_route(&prefix).unwrap().source, RouteSource::Static);
    }

    #[test]
    fn build_from_config_copies_static_variants() {
        let tables = vec![RoutingTable {
            static_routing_instance: Some("sri1".into()),
            name: "rt1".into(),
            ..Default::default()
        }];
        let instances = vec![StaticRoutingInstance {
            name: "sri1".into(),
            routes: vec![
                StaticRoute {
                    subnet: "10.1.0.0/24".parse().unwrap(),
                    gateway: "10.0.0.1".parse().unwrap(),
                    distance: Some(200),
                    tag: Some(7),
                    interface: Some("eth1".into()),
                    ..Default::default()
                },
                StaticRoute {
                    subnet: "10.2.0.0/24".parse().unwrap(),
                    blackhole: true,
                    ..Default::default()
                },
            ],
        }];
        let rib = build_from_config(&cfg(tables, instances), "rt1", &HashSet::new()).unwrap();
        let a = rib.best_route(&"10.1.0.0/24".parse().unwrap()).unwrap();
        assert_eq!((a.distance, a.tag), (Some(200), Some(7)));
        assert_eq!(
            a.interfaces
                .get(&"10.0.0.1".parse().unwrap())
                .map(String::as_str),
            Some("eth1")
        );
        assert_eq!(a.preference(), 200);
        let b = rib.best_route(&"10.2.0.0/24".parse().unwrap()).unwrap();
        assert!(b.is_discard());
    }

    #[test]
    fn static_next_hops_merge_into_one_sorted_entry_with_per_hop_bfd() {
        let hop = |g: &str, bfd: Option<&str>| nos_proto::schema::static_route::StaticNextHop {
            gateway: g.parse().unwrap(),
            bfd: bfd.map(Into::into),
            ..Default::default()
        };
        let mk = |gw: &str, bfd: Option<&str>, extra: Vec<_>| {
            let mut c = cfg(
                vec![RoutingTable {
                    name: "rt1".into(),
                    static_routing_instance: Some("sri1".into()),
                    ..RoutingTable::default()
                }],
                vec![StaticRoutingInstance {
                    name: "sri1".into(),
                    routes: vec![StaticRoute {
                        subnet: "10.1.0.0/24".parse().unwrap(),
                        gateway: gw.parse().unwrap(),
                        bfd: bfd.map(Into::into),
                        distance: Some(5),
                        next_hops: extra,
                        ..Default::default()
                    }],
                }],
            );
            c.bfd_profiles = vec![BfdProfile {
                name: "fast".into(),
                ..BfdProfile::default()
            }];
            c
        };
        let p = "10.1.0.0/24".parse().unwrap();
        let gws = |c: &Config, up: &[&str]| {
            let up = up.iter().map(|g| g.parse().unwrap()).collect();
            build_from_config(c, "rt1", &up)
                .unwrap()
                .best_route(&p)
                .map(|e| {
                    (
                        e.next_hops
                            .iter()
                            .map(|h| h.gateway.to_string())
                            .collect::<Vec<_>>(),
                        e.distance,
                    )
                })
        };
        let fwd = mk("10.0.0.2", None, vec![hop("10.0.0.1", None)]);
        let rev = mk("10.0.0.1", None, vec![hop("10.0.0.2", None)]);
        // One entry, sorted: config order is irrelevant; distance carried.
        let want = Some((
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
            Some(5),
        ));
        assert_eq!(gws(&fwd, &[]), want);
        assert_eq!(gws(&rev, &[]), want);
        // Extra hop BFD-gated: dropped until up; primary BFD-gated likewise.
        let gated = mk("10.0.0.1", None, vec![hop("10.0.0.2", Some("fast"))]);
        assert_eq!(gws(&gated, &[]).unwrap().0, ["10.0.0.1"]);
        assert_eq!(gws(&gated, &["10.0.0.2"]).unwrap().0.len(), 2);
        let both = mk(
            "10.0.0.1",
            Some("fast"),
            vec![hop("10.0.0.2", Some("fast"))],
        );
        assert_eq!(
            gws(&both, &[]),
            None,
            "all hops down: no entry, not a discard"
        );
        assert_eq!(gws(&both, &["10.0.0.2"]).unwrap().0, ["10.0.0.2"]);
        // bfd_target lists the extra hop too.
        assert!(bfd_target(&gated, "rt1").contains_key(&"10.0.0.2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn each_static_hop_keeps_its_own_interface() {
        let route = |hops: Vec<StaticNextHop>| StaticRoute {
            subnet: "2001:db8:1::/48".parse().unwrap(),
            gateway: "fe80::1".parse().unwrap(),
            interface: Some("eth0".into()),
            next_hops: hops,
            ..Default::default()
        };
        let hop = |gw: &str, i: &str| StaticNextHop {
            gateway: gw.parse().unwrap(),
            interface: Some(i.into()),
            ..Default::default()
        };
        let build = |r: StaticRoute| {
            let instances = vec![StaticRoutingInstance {
                name: "sri1".into(),
                routes: vec![r],
            }];
            let tables = vec![RoutingTable {
                static_routing_instance: Some("sri1".into()),
                name: "rt1".into(),
                ..Default::default()
            }];
            build_from_config(&cfg(tables, instances), "rt1", &HashSet::new())
                .unwrap()
                .best_route(&"2001:db8:1::/48".parse().unwrap())
                .unwrap()
                .clone()
        };
        let a = build(route(vec![hop("fe80::2", "eth1"), hop("fe80::3", "eth2")]));
        assert_eq!(a.interfaces.len(), 3);
        assert_eq!(a.interfaces[&"fe80::2".parse::<IpAddr>().unwrap()], "eth1");
        // Config order of the extra hops does not change the entry.
        let b = build(route(vec![hop("fe80::3", "eth2"), hop("fe80::2", "eth1")]));
        assert_eq!(a, b);
    }

    #[test]
    fn variant_fields_are_part_of_equality() {
        let base = entry("10.0.0.0/24", "10.0.0.1", RouteSource::Static);
        assert_ne!(base, floating("10.0.0.0/24", 5));
        assert_ne!(
            base,
            RibEntry {
                tag: Some(1),
                ..base.clone()
            }
        );
        assert_ne!(
            base,
            RibEntry {
                interfaces: [("10.0.0.1".parse().unwrap(), "e".to_string())].into(),
                ..base.clone()
            }
        );
    }

    fn entry(prefix: &str, gateway: &str, source: RouteSource) -> RibEntry {
        RibEntry {
            prefix: prefix.parse().unwrap(),
            next_hops: vec![(gateway.parse().unwrap(), None).into()],
            source,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        });
        rib.insert(RibEntry {
            prefix: p2,
            next_hops: vec![("10.0.1.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
                let (page, more) = rib.routes_page(after, limit, &RouteFilter::default());
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
        let nf = RouteFilter::default();
        assert_eq!(Rib::new().routes_page(None, 3, &nf), (vec![], false));
        let last = all.last().unwrap().0;
        assert_eq!(rib.routes_page(Some(last), 3, &nf), (vec![], false));
        let gone: IpNet = "10.0.0.128/25".parse().unwrap();
        let want = all.iter().map(|a| a.0).find(|p| *p > gone).unwrap();
        assert_eq!(rib.routes_page(Some(gone), 1, &nf).0[0].0, want);
    }

    #[test]
    fn routes_page_filters_and_summary_counts() {
        let mut rib = Rib::new();
        for p in ["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24", "11.0.0.0/8"] {
            rib.insert(entry(p, "10.0.0.1", RouteSource::Static));
        }
        rib.insert(entry("10.1.0.0/16", "10.0.0.2", RouteSource::Bgp));
        rib.insert(entry("2001:db8::/32", "fe80::1", RouteSource::Bgp));
        let f = |source, prefix: Option<&str>, longer| RouteFilter {
            source,
            prefix: prefix.map(|p| p.parse().unwrap()),
            longer,
        };
        let names = |flt: &RouteFilter, limit| {
            let (p, more) = rib.routes_page(None, limit, flt);
            (
                p.iter().map(|(p, _)| p.to_string()).collect::<Vec<_>>(),
                more,
                p,
            )
        };
        // Source: only that source's prefixes and candidates.
        let (p, _, full) = names(&f(Some(RouteSourceKind::Bgp), None, false), 10);
        assert_eq!(p, ["10.1.0.0/16", "2001:db8::/32"]);
        assert!(full
            .iter()
            .all(|(_, c)| c.len() == 1 && c[0].source == RouteSource::Bgp));
        // Exact prefix, covered-by, longer without a match.
        assert_eq!(
            names(&f(None, Some("10.1.0.0/16"), false), 10).0,
            ["10.1.0.0/16"]
        );
        assert_eq!(
            names(&f(None, Some("10.0.0.0/8"), true), 10).0,
            ["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24"]
        );
        // Filtered paging never repeats and ends with no `more`.
        let flt = f(None, Some("10.0.0.0/8"), true);
        let (mut got, mut after) = (vec![], None);
        loop {
            let (page, more) = rib.routes_page(after, 2, &flt);
            after = page.last().map(|(p, _)| *p);
            got.extend(page.into_iter().map(|(p, _)| p.to_string()));
            if !more {
                break;
            }
        }
        assert_eq!(got, ["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24"]);
        let (v4, v6, sources) = rib.summary_counts();
        assert_eq!((v4, v6), (4, 1));
        assert_eq!(
            sources,
            [
                SourceCount {
                    source: RouteSourceKind::Static,
                    ipv4: 4,
                    ipv6: 0
                },
                SourceCount {
                    source: RouteSourceKind::Bgp,
                    ipv4: 1,
                    ipv6: 1
                },
            ]
        );
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        });
        rib.insert(RibEntry {
            prefix: p2,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        });
        rib.insert(RibEntry {
            prefix: p2,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        });
        rib.insert(RibEntry {
            prefix: narrow,
            next_hops: vec![("10.0.1.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: nos_proto::RoutingTableDistance::default(),
            rest_api: None,
            ssh_server: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instances: Vec::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
                distance: None,
                tag: None,
                interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        });
        rib.upsert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        });
        rib.upsert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.99".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
                distance: None,
                tag: None,
                interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
                distance: None,
                tag: None,
                interfaces: BTreeMap::new(),
            })
        );
        let static_entry = RibEntry {
            prefix,
            next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        });
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        });
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
                distance: None,
                tag: None,
                interfaces: BTreeMap::new(),
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
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        });
        rib.insert(RibEntry {
            prefix,
            next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
            source: RouteSource::Bgp,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
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
            distance: nos_proto::RoutingTableDistance::default(),
            rest_api: None,
            ssh_server: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instances: Vec::new(),
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
                ..Default::default()
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
                        ..Default::default()
                    },
                    StaticRoute {
                        subnet: "10.2.0.0/24".parse().unwrap(),
                        gateway: "10.0.0.2".parse().unwrap(),
                        bfd: None,
                        ..Default::default()
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

    // ------------------------------------------------ per-owner OSPF (#1277)

    fn owner(v3: bool, name: &str) -> OspfOwner {
        OspfOwner::new(v3, name)
    }

    fn ospf(prefix: &str, gateway: &str) -> RibEntry {
        entry(prefix, gateway, RouteSource::Ospf)
    }

    #[test]
    fn ospf_owners_replace_only_their_own_routes() {
        let mut rib = Rib::new();
        let (a, b) = (owner(false, "a"), owner(true, "a"));
        rib.replace_ospf(&a, [(ospf("10.1.0.0/24", "10.0.0.1"), 5)]);
        rib.replace_ospf(&b, [(ospf("10.2.0.0/24", "10.0.0.2"), 7)]);
        rib.replace_ospf(&a, [(ospf("10.3.0.0/24", "10.0.0.1"), 9)]);
        assert!(rib.best_route(&"10.1.0.0/24".parse().unwrap()).is_none());
        assert!(rib.best_route(&"10.2.0.0/24".parse().unwrap()).is_some());
        assert!(rib.best_route(&"10.3.0.0/24".parse().unwrap()).is_some());
        let mut costs = rib.igp_costs();
        costs.sort();
        assert_eq!(
            costs,
            vec![
                ("10.2.0.0/24".parse().unwrap(), 7),
                ("10.3.0.0/24".parse().unwrap(), 9)
            ]
        );
        // Add/Remove touch only their owner.
        let p: IpNet = "10.2.0.0/24".parse().unwrap();
        assert_eq!(rib.remove_ospf_and_diff(&a, &p), BestPathChange::Unchanged);
        assert_eq!(rib.remove_ospf_and_diff(&b, &p), BestPathChange::Removed);
        assert!(rib.best_route(&"10.3.0.0/24".parse().unwrap()).is_some());
    }

    #[test]
    fn same_prefix_lowest_metric_then_owner_order_wins() {
        let mut rib = Rib::new();
        let p: IpNet = "10.1.0.0/24".parse().unwrap();
        let (a, b) = (owner(false, "a"), owner(false, "b"));
        rib.replace_ospf(&b, [(ospf("10.1.0.0/24", "10.0.0.2"), 5)]);
        rib.replace_ospf(&a, [(ospf("10.1.0.0/24", "10.0.0.1"), 5)]);
        // Tie: owner order, so "a".
        assert_eq!(
            rib.best_route(&p).unwrap().next_hops[0].gateway.to_string(),
            "10.0.0.1"
        );
        rib.upsert_ospf_and_diff(&a, ospf("10.1.0.0/24", "10.0.0.1"), 50);
        assert_eq!(
            rib.best_route(&p).unwrap().next_hops[0].gateway.to_string(),
            "10.0.0.2"
        );
        assert_eq!(rib.igp_costs(), vec![(p, 5)]);
        // A winner flip with identical next hops is no kernel change.
        let mut rib = Rib::new();
        rib.replace_ospf(&a, [(ospf("10.1.0.0/24", "10.0.0.1"), 5)]);
        rib.replace_ospf(&b, [(ospf("10.1.0.0/24", "10.0.0.1"), 9)]);
        assert_eq!(
            rib.upsert_ospf_and_diff(&a, ospf("10.1.0.0/24", "10.0.0.1"), 99),
            BestPathChange::Unchanged
        );
        assert_eq!(rib.igp_costs(), vec![(p, 9)]);
    }

    #[test]
    fn a_discard_of_one_owner_never_hides_anothers_route() {
        let mut rib = Rib::new();
        let p: IpNet = "10.1.0.0/24".parse().unwrap();
        let mut discard = ospf("10.1.0.0/24", "10.0.0.1");
        discard.next_hops.clear();
        rib.replace_ospf(&owner(false, "a"), [(discard, 1)]);
        rib.replace_ospf(&owner(true, "a"), [(ospf("10.1.0.0/24", "10.0.0.2"), 40)]);
        assert!(!rib.best_route(&p).unwrap().is_discard());
        assert_eq!(rib.igp_costs(), vec![(p, 40)]);
    }

    #[test]
    fn retain_ospf_owners_drops_the_rest() {
        let mut rib = Rib::new();
        let (a, b) = (owner(false, "a"), owner(true, "a"));
        rib.replace_ospf(&a, [(ospf("10.1.0.0/24", "10.0.0.1"), 5)]);
        rib.replace_ospf(&b, [(ospf("10.2.0.0/24", "10.0.0.2"), 5)]);
        let gone = rib.retain_ospf_owners(&HashSet::from([a]));
        assert_eq!(gone, vec![b]);
        assert_eq!(rib.count_source(RouteSource::Ospf), 1);
        assert_eq!(rib.igp_costs().len(), 1);
    }

    // ------------------------------------------ recursive statics (#1527)

    /// A table with `10.0.0.0/24` connected, `statics` configured.
    fn recursive_rib(statics: &[(&str, &str)]) -> Rib {
        let mut rib = Rib::new();
        rib.replace_source(
            RouteSource::Connected,
            [entry("10.0.0.0/24", "10.0.0.1", RouteSource::Connected)],
        );
        rib.replace_source(
            RouteSource::Static,
            statics
                .iter()
                .map(|(p, g)| entry(p, g, RouteSource::Static)),
        );
        rib
    }

    fn hops(rib: &Rib, prefix: &str) -> Option<Vec<IpAddr>> {
        let e = rib.best_route(&prefix.parse().unwrap())?;
        Some(e.next_hops.iter().map(|h| h.gateway).collect())
    }

    fn gw(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn static_resolves_through_ospf_and_follows_it() {
        let mut rib = recursive_rib(&[("10.9.0.0/16", "172.16.0.1")]);
        let p9: IpNet = "10.9.0.0/16".parse().unwrap();
        assert_eq!(hops(&rib, "10.9.0.0/16"), None);
        // Still a candidate, not installed.
        let (_, cands) = rib.lookup(gw("10.9.1.1")).unwrap();
        assert!(rib.is_unresolved(&p9, &cands[0]));
        assert!(!rib.best_routes_for_kernel().contains_key(&p9));

        let o = owner(false, "o");
        let change = rib.upsert_ospf_and_diff(&o, ospf("172.16.0.0/24", "10.0.0.2"), 10);
        assert!(matches!(change, BestPathChange::Installed(_)));
        let d = rib.reresolve();
        assert!(matches!(&d[&p9], Some(e) if e.next_hops[0].gateway == gw("10.0.0.2")));
        assert_eq!(hops(&rib, "10.9.0.0/16"), Some(vec![gw("10.0.0.2")]));

        // The OSPF path moves: the static follows.
        rib.upsert_ospf_and_diff(&o, ospf("172.16.0.0/24", "10.0.0.3"), 10);
        assert_eq!(rib.reresolve().len(), 1);
        assert_eq!(hops(&rib, "10.9.0.0/16"), Some(vec![gw("10.0.0.3")]));

        // And withdraws with it.
        rib.remove_ospf_and_diff(&o, &"172.16.0.0/24".parse().unwrap());
        assert_eq!(rib.reresolve()[&p9], None);
        assert_eq!(hops(&rib, "10.9.0.0/16"), None);
    }

    #[test]
    fn on_link_static_is_untouched_and_ecmp_is_inherited() {
        let mut rib = recursive_rib(&[("10.9.0.0/16", "10.0.0.5"), ("10.8.0.0/16", "172.16.0.1")]);
        assert_eq!(hops(&rib, "10.9.0.0/16"), Some(vec![gw("10.0.0.5")]));
        let mut ecmp = ospf("172.16.0.0/24", "10.0.0.2");
        ecmp.next_hops.push((gw("10.0.0.3"), None).into());
        rib.replace_ospf(&owner(false, "o"), [(ecmp, 5)]);
        assert_eq!(
            hops(&rib, "10.8.0.0/16"),
            Some(vec![gw("10.0.0.2"), gw("10.0.0.3")])
        );
    }

    #[test]
    fn recursion_depth_is_four() {
        for (n, resolved) in [(4, true), (5, false)] {
            let c: Vec<(String, String)> = (0..n)
                .map(|i| {
                    (
                        format!("10.{}.0.0/16", 20 + i),
                        format!("10.{}.0.1", 21 + i),
                    )
                })
                .collect();
            let statics: Vec<(&str, &str)> =
                c.iter().map(|(p, g)| (p.as_str(), g.as_str())).collect();
            let mut rib = recursive_rib(&statics);
            // The last link's gateway is reached through OSPF.
            let last = format!("10.{}.0.0/16", 20 + n);
            rib.replace_ospf(&owner(false, "o"), [(ospf(&last, "10.0.0.2"), 1)]);
            assert_eq!(
                hops(&rib, "10.20.0.0/16").is_some(),
                resolved,
                "chain of {n}"
            );
        }
    }

    #[test]
    fn cycle_stays_unresolved_and_does_not_shadow() {
        let mut rib =
            recursive_rib(&[("10.20.0.0/16", "10.21.0.1"), ("10.21.0.0/16", "10.20.0.1")]);
        assert_eq!(hops(&rib, "10.20.0.0/16"), None);
        assert_eq!(hops(&rib, "10.21.0.0/16"), None);
        // A self-cover (gateway inside the route's own prefix) never resolves.
        rib.replace_source(
            RouteSource::Static,
            [entry("10.30.0.0/16", "10.30.0.1", RouteSource::Static)],
        );
        assert_eq!(hops(&rib, "10.30.0.0/16"), None);
    }

    #[test]
    fn unresolved_static_does_not_beat_a_lower_priority_route() {
        let mut rib = recursive_rib(&[("10.9.0.0/16", "172.16.0.1")]);
        rib.upsert(entry("10.9.0.0/16", "10.0.0.7", RouteSource::Bgp));
        assert_eq!(hops(&rib, "10.9.0.0/16"), Some(vec![gw("10.0.0.7")]));
    }

    #[test]
    fn bgp_only_cover_does_not_resolve() {
        let mut rib = recursive_rib(&[("10.9.0.0/16", "172.16.0.1")]);
        rib.upsert(entry("172.16.0.0/24", "10.0.0.7", RouteSource::Bgp));
        rib.reresolve();
        assert_eq!(hops(&rib, "10.9.0.0/16"), None);
    }
}
