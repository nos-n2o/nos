//! EVPN IP-VRF (RFC 9136 Type-5, RFC 9135 §4.4.1 "interface-less"): this
//! table's L3 VNI config, which received Type-5 routes become `Evpn`
//! candidates (`desired`), and which of the table's own best routes are
//! originated (`originated`). Pure — the devices are `RibDriver::sync_l3vni`'s,
//! the IPC is `server.rs`'s (received) and `evpn_client.rs`'s (originated).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::BuildHasher;
use std::net::IpAddr;

use nos_proto::evpn_id::{parse_router_mac, router_mac_ext, ENCAP_VXLAN};
use nos_proto::rib::EvpnIrb;
use nos_proto::{EvpnKey, EvpnRoute, IpNet};
use tracing::debug;

use crate::rib::{RibEntry, RouteSource};

pub type Mac = [u8; 6];

/// One table's resolved `RoutingTable.evpn`: parsed RD/RTs plus the VTEP
/// address and the device carrying it (the VXLAN device's underlay).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L3Vni {
    pub vni: u32,
    pub rd: [u8; 8],
    pub import: Vec<u64>,
    pub export: Vec<u64>,
    pub bgp_instance: String,
    pub vtep: IpAddr,
    pub underlay: String,
}

/// The EVPN side of a table's `Rib`.
#[derive(Debug, Clone, Default)]
pub struct EvpnState {
    /// `None` when the table has no `evpn` (or its VTEP never resolved yet).
    pub local: Option<L3Vni>,
    /// Our Router's MAC: the L3 bridge's own address, once the driver built it.
    pub rmac: Option<Mac>,
    /// Every Type-5 route `nos-bgpd` pushed, unfiltered.
    pub received: HashMap<EvpnKey, EvpnRoute>,
    /// Remote VTEP -> its Router's MAC, for every installed `Evpn` route: the
    /// neighbour and FDB entry each one needs. A VTEP advertising several
    /// Router's MACs gets the one of its lowest prefix.
    pub remotes: BTreeMap<IpAddr, Mac>,
    /// Reverse index of `received`: prefix -> the keys naming it (#763), so an
    /// incremental update recomputes one prefix, not the table.
    pub(crate) index: HashMap<IpNet, HashSet<EvpnKey>>,
    /// The installed winner per prefix: `(vtep, rmac)`.
    pub(crate) winners: BTreeMap<IpNet, (IpAddr, Mac)>,
    /// `winners` grouped by VTEP (its entry count is the VTEP's refcount).
    pub(crate) by_vtep: BTreeMap<IpAddr, BTreeMap<IpNet, Mac>>,
}

/// The prefix a received route is about (`None`: not an IP-VRF route type).
pub(crate) fn key_prefix(key: &EvpnKey) -> Option<IpNet> {
    match key {
        EvpnKey::IpPrefix { prefix, .. } => Some(*prefix),
        EvpnKey::MacIp { ip, .. } => Some(IpNet::from(*ip)),
        _ => None,
    }
}

/// `r` as an `Evpn` candidate for `l3`: its `(prefix, vtep, rmac)`. A route is
/// kept only if it carries one of our import Route Targets, names our L3 VNI,
/// carries a Router's MAC, isn't our own VTEP's, and its prefix and next hop
/// share our VTEP's family. Every Type-5, and every RFC 9135 symmetric IRB
/// MAC+IP (its Label2, `l3_vni`, set) as a host route.
fn candidate(r: &EvpnRoute, l3: &L3Vni) -> Option<(IpNet, IpAddr, Mac)> {
    let (prefix, vni, route_type) = match r.key {
        EvpnKey::IpPrefix { prefix, .. } => (prefix, Some(r.vni), 5),
        EvpnKey::MacIp { ip, .. } => (IpNet::from(ip), r.l3_vni, 2),
        _ => return None,
    };
    if !r.ext_communities.iter().any(|c| l3.import.contains(c))
        || vni != Some(l3.vni)
        || r.next_hop == l3.vtep
        || prefix.addr().is_ipv4() != l3.vtep.is_ipv4()
        || r.next_hop.is_ipv4() != l3.vtep.is_ipv4()
    {
        return None;
    }
    let Some(rmac) = r.ext_communities.iter().find_map(|c| parse_router_mac(*c)) else {
        debug!(%prefix, vtep = %r.next_hop, route_type, "evpn route without a router's mac skipped");
        return None;
    };
    Some((prefix, r.next_hop, rmac))
}

/// The winner for one prefix among the `keys` naming it: the lowest VTEP
/// (then lowest Router's MAC, so it is deterministic).
// ponytail: same-family only (an IPv6 prefix over an IPv4 underlay needs the
// RFC 5549-style `RTA_VIA` route), and one PE per prefix — the lowest VTEP —
// rather than ECMP over every PE advertising it (a multi-homed host's ESI is
// ignored here: no aliasing for host routes).
pub(crate) fn best_for<'a, S: BuildHasher>(
    received: &HashMap<EvpnKey, EvpnRoute, S>,
    keys: impl IntoIterator<Item = &'a EvpnKey>,
    l3: &L3Vni,
) -> Option<(IpAddr, Mac)> {
    keys.into_iter()
        .filter_map(|k| candidate(received.get(k)?, l3))
        .map(|(_, vtep, rmac)| (vtep, rmac))
        .min()
}

/// The winner per prefix of everything `received` gives `l3`.
fn winners<S: BuildHasher>(
    received: &HashMap<EvpnKey, EvpnRoute, S>,
    l3: &L3Vni,
) -> BTreeMap<IpNet, (IpAddr, Mac)> {
    let mut best: BTreeMap<IpNet, (IpAddr, Mac)> = BTreeMap::new();
    for (prefix, vtep, rmac) in received.values().filter_map(|r| candidate(r, l3)) {
        let e = best.entry(prefix).or_insert((vtep, rmac));
        *e = (*e).min((vtep, rmac));
    }
    best
}

fn group_by_vtep(
    winners: &BTreeMap<IpNet, (IpAddr, Mac)>,
) -> BTreeMap<IpAddr, BTreeMap<IpNet, Mac>> {
    let mut by_vtep: BTreeMap<IpAddr, BTreeMap<IpNet, Mac>> = BTreeMap::new();
    for (prefix, (vtep, rmac)) in winners {
        by_vtep.entry(*vtep).or_default().insert(*prefix, *rmac);
    }
    by_vtep
}

/// The remote VTEPs of `by_vtep`: each one's Router's MAC is its lowest prefix's.
fn remotes_of(by_vtep: &BTreeMap<IpAddr, BTreeMap<IpNet, Mac>>) -> BTreeMap<IpAddr, Mac> {
    by_vtep
        .iter()
        .filter_map(|(v, m)| Some((*v, *m.values().next()?)))
        .collect()
}

pub(crate) fn entry_for(prefix: IpNet, vtep: IpAddr) -> RibEntry {
    RibEntry {
        prefix,
        next_hops: vec![(vtep, None).into()],
        source: RouteSource::Evpn,
        backup: None,
        backup_interface_id: None,
        backup_tunnel: false,
        distance: None,
        tag: None,
        interfaces: BTreeMap::new(),
    }
}

/// The `Evpn` candidates `received` gives `l3`, and the remote VTEPs they use.
pub fn desired<S: BuildHasher>(
    received: &HashMap<EvpnKey, EvpnRoute, S>,
    l3: &L3Vni,
) -> (Vec<RibEntry>, BTreeMap<IpAddr, Mac>) {
    let best = winners(received, l3);
    let entries = best.iter().map(|(p, (v, _))| entry_for(*p, *v)).collect();
    (entries, remotes_of(&group_by_vtep(&best)))
}

impl EvpnState {
    /// Rebuilds the index and winners from `received` (a `Full`, or a new
    /// local L3 VNI); returns the `Evpn` candidates.
    pub(crate) fn rebuild(&mut self) -> Vec<RibEntry> {
        self.index.clear();
        for k in self.received.keys() {
            if let Some(p) = key_prefix(k) {
                self.index.entry(p).or_default().insert(k.clone());
            }
        }
        self.winners = self
            .local
            .as_ref()
            .map_or_default(|l3| winners(&self.received, l3));
        self.by_vtep = group_by_vtep(&self.winners);
        self.remotes = remotes_of(&self.by_vtep);
        self.winners
            .iter()
            .map(|(p, (v, _))| entry_for(*p, *v))
            .collect()
    }

    /// What `nos-fdbd` needs to make a domain's MAC+IP routes symmetric
    /// (`RibRequest::GetEvpnIrb`): `None` until the IP-VRF is up.
    #[must_use]
    pub fn irb(&self) -> Option<EvpnIrb> {
        let l3 = self.local.as_ref()?;
        Some(EvpnIrb {
            l3_vni: l3.vni,
            router_mac: self.rmac?,
            route_targets_export: l3.export.clone(),
        })
    }

    /// Records `route` (`Some`) or forgets `key` (`None`) in `received` and the
    /// index, and recomputes that one prefix: `Some((prefix, new winner's VTEP,
    /// remotes changed))` when the prefix's winner changed.
    pub(crate) fn apply(
        &mut self,
        key: &EvpnKey,
        route: Option<EvpnRoute>,
    ) -> Option<(IpNet, Option<IpAddr>, bool)> {
        let prefix = key_prefix(key);
        if let Some(r) = route {
            self.received.insert(key.clone(), r);
            if let Some(p) = prefix {
                self.index.entry(p).or_default().insert(key.clone());
            }
        } else {
            self.received.remove(key);
            if let Some(p) = prefix
                && let Some(set) = self.index.get_mut(&p)
            {
                set.remove(key);
                if set.is_empty() {
                    self.index.remove(&p);
                }
            }
        }
        let (prefix, l3) = (prefix?, self.local.as_ref()?);
        let new = self
            .index
            .get(&prefix)
            .and_then(|keys| best_for(&self.received, keys, l3));
        let old = self.winners.get(&prefix).copied();
        if new == old {
            // Same VTEP and Router's MAC: nothing to install.
            return None;
        }
        let mut touched = Vec::new();
        if let Some((v, _)) = old {
            if let Some(m) = self.by_vtep.get_mut(&v) {
                m.remove(&prefix);
                if m.is_empty() {
                    self.by_vtep.remove(&v);
                }
            }
            touched.push(v);
        }
        match new {
            Some((v, rmac)) => {
                self.winners.insert(prefix, (v, rmac));
                self.by_vtep.entry(v).or_default().insert(prefix, rmac);
                touched.push(v);
            }
            None => {
                self.winners.remove(&prefix);
            }
        }
        let mut remotes_changed = false;
        for v in touched {
            let now = self
                .by_vtep
                .get(&v)
                .and_then(|m| m.values().next())
                .copied();
            let before = self.remotes.get(&v).copied();
            if now != before {
                remotes_changed = true;
                match now {
                    Some(m) => self.remotes.insert(v, m),
                    None => self.remotes.remove(&v),
                };
            }
        }
        Some((prefix, new.map(|(v, _)| v), remotes_changed))
    }
}

/// One Type-5 per best route of the table that isn't itself `Evpn`-sourced
/// (the loop guard), connected subnets included.
// ponytail: no RPL policy on origination; every best route goes.
pub fn originated<S: BuildHasher>(
    best: &HashMap<IpNet, RibEntry, S>,
    l3: &L3Vni,
    rmac: Mac,
) -> Vec<EvpnRoute> {
    let mut ext: Vec<u64> = l3.export.clone();
    ext.extend([ENCAP_VXLAN, router_mac_ext(rmac)]);
    best.values()
        .filter(|e| e.source != RouteSource::Evpn)
        .map(|e| EvpnRoute {
            key: EvpnKey::IpPrefix {
                rd: l3.rd,
                prefix: e.prefix,
            },
            vni: l3.vni,
            next_hop: l3.vtep,
            ext_communities: ext.clone(),
            esi: [0; 10],
            l3_vni: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RT: u64 = 0x0002_fde8_0000_1388; // 65000:5000

    fn l3() -> L3Vni {
        L3Vni {
            vni: 5000,
            rd: [0; 8],
            import: vec![RT],
            export: vec![RT],
            bgp_instance: "r1".into(),
            vtep: "10.50.0.2".parse().unwrap(),
            underlay: "eth0".into(),
        }
    }

    fn route(prefix: &str, vtep: &str, ext: Vec<u64>, vni: u32) -> (EvpnKey, EvpnRoute) {
        let key = EvpnKey::IpPrefix {
            rd: [0, 0, 0, 0, 0, 0, 0, u8::try_from(vtep.len()).unwrap()],
            prefix: prefix.parse().unwrap(),
        };
        let r = EvpnRoute {
            key: key.clone(),
            vni,
            next_hop: vtep.parse().unwrap(),
            ext_communities: ext,
            esi: [0; 10],
            l3_vni: None,
        };
        (key, r)
    }

    #[test]
    fn desired_filters_on_rt_vni_rmac_own_vtep_and_family() {
        let rmac = router_mac_ext([2, 0, 0, 0, 0, 3]);
        let received: HashMap<_, _> = [
            route("10.2.0.0/24", "10.50.0.3", vec![RT, rmac], 5000),
            // Another RT, another VNI, no Router's MAC, our own VTEP, v6.
            route("10.3.0.0/24", "10.50.0.3", vec![1, rmac], 5000),
            route("10.4.0.0/24", "10.50.0.3", vec![RT, rmac], 5001),
            route("10.5.0.0/24", "10.50.0.3", vec![RT], 5000),
            route("10.6.0.0/24", "10.50.0.2", vec![RT, rmac], 5000),
            route("2001:db8::/64", "10.50.0.3", vec![RT, rmac], 5000),
            // The same prefix from a second PE: the lower VTEP wins.
            route("10.2.0.0/24", "10.50.0.33", vec![RT, rmac], 5000),
        ]
        .into_iter()
        .collect();
        let (entries, remotes) = desired(&received, &l3());
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].prefix, "10.2.0.0/24".parse::<IpNet>().unwrap());
        assert_eq!(entries[0].source, RouteSource::Evpn);
        assert_eq!(
            entries[0].next_hops,
            vec![("10.50.0.3".parse().unwrap(), None).into()]
        );
        assert_eq!(
            remotes,
            BTreeMap::from([("10.50.0.3".parse().unwrap(), [2, 0, 0, 0, 0, 3])])
        );
    }

    /// RFC 9135 symmetric IRB: a MAC+IP with our L3 VNI as Label2 is a host
    /// route; the same filters apply.
    #[test]
    fn desired_installs_symmetric_mac_ip_as_host_routes() {
        let rmac = router_mac_ext([2, 0, 0, 0, 0, 3]);
        let mac_ip = |ip: &str, vtep: &str, ext: Vec<u64>, l3_vni: Option<u32>| {
            let key = EvpnKey::MacIp {
                rd: [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    u8::try_from(ip.len() + vtep.len()).unwrap(),
                ],
                mac: [2, 0, 0, 0, 0, 9],
                ip: ip.parse().unwrap(),
            };
            let r = EvpnRoute {
                key: key.clone(),
                vni: 10_300,
                next_hop: vtep.parse().unwrap(),
                ext_communities: ext,
                esi: [0; 10],
                l3_vni,
            };
            (key, r)
        };
        let received: HashMap<_, _> = [
            mac_ip("10.72.0.20", "10.50.0.3", vec![RT, rmac], Some(5000)),
            // Wrong L3 VNI, asymmetric, no IP-VRF RT, no rmac, our own VTEP.
            mac_ip("10.72.0.21", "10.50.0.3", vec![RT, rmac], Some(5001)),
            mac_ip("10.72.0.22", "10.50.0.3", vec![RT, rmac], None),
            mac_ip("10.72.0.23", "10.50.0.3", vec![1, rmac], Some(5000)),
            mac_ip("10.72.0.24", "10.50.0.3", vec![RT], Some(5000)),
            mac_ip("10.72.0.25", "10.50.0.2", vec![RT, rmac], Some(5000)),
            // A Type-5 /32 for the same host collapses with it.
            route("10.72.0.20/32", "10.50.0.4", vec![RT, rmac], 5000),
        ]
        .into_iter()
        .collect();
        let (entries, remotes) = desired(&received, &l3());
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].prefix, "10.72.0.20/32".parse::<IpNet>().unwrap());
        assert_eq!(
            entries[0].next_hops,
            vec![("10.50.0.3".parse().unwrap(), None).into()]
        );
        assert_eq!(remotes.len(), 1);
    }

    #[test]
    fn originated_skips_evpn_routes_and_carries_rt_encap_and_rmac() {
        let entry = |p: &str, source| RibEntry {
            prefix: p.parse().unwrap(),
            next_hops: vec![("10.1.0.1".parse().unwrap(), None).into()],
            source,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        };
        let best: HashMap<IpNet, RibEntry> = [
            entry("10.1.0.0/24", RouteSource::Connected),
            entry("10.2.0.0/24", RouteSource::Evpn),
        ]
        .into_iter()
        .map(|e| (e.prefix, e))
        .collect();
        let out = originated(&best, &l3(), [2, 0, 0, 0, 0, 2]);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].key,
            EvpnKey::IpPrefix {
                rd: [0; 8],
                prefix: "10.1.0.0/24".parse().unwrap()
            }
        );
        assert_eq!((out[0].vni, out[0].next_hop), (5000, l3().vtep));
        assert_eq!(
            out[0].ext_communities,
            vec![RT, ENCAP_VXLAN, router_mac_ext([2, 0, 0, 0, 0, 2])]
        );
    }

    // ---- incremental updates (#763) ----

    use crate::rib::{BestPathChange, Rib};
    use proptest::prelude::*;

    fn rib_with_l3() -> Rib {
        let mut rib = Rib::new();
        rib.evpn.local = Some(l3());
        rib.refresh_evpn();
        rib
    }

    fn rt5(prefix: &str, vtep: &str, rd: u8, rmac: u8) -> EvpnRoute {
        let ext = vec![RT, router_mac_ext([2, 0, 0, 0, 0, rmac])];
        let mut r = route(prefix, vtep, ext, 5000).1;
        r.key = EvpnKey::IpPrefix {
            rd: [0, 0, 0, 0, 0, 0, 0, rd],
            prefix: prefix.parse().unwrap(),
        };
        r
    }

    fn add(rib: &mut Rib, r: &EvpnRoute) -> Option<(IpNet, BestPathChange, bool)> {
        rib.apply_evpn_diff(&r.key.clone(), Some(r.clone()))
    }

    fn gw(ch: &BestPathChange) -> Option<IpAddr> {
        match ch {
            BestPathChange::Installed(e) => Some(e.next_hops[0].gateway),
            _ => None,
        }
    }

    #[test]
    fn incremental_add_resend_replace_remove() {
        let mut rib = rib_with_l3();
        let p: IpNet = "10.2.0.0/24".parse().unwrap();
        let a = rt5("10.2.0.0/24", "10.50.0.33", 1, 3);
        let (pp, ch, remotes) = add(&mut rib, &a).unwrap();
        assert_eq!(pp, p);
        assert_eq!(gw(&ch), Some(a.next_hop));
        assert!(remotes);
        // Identical resend: no change at all.
        assert!(add(&mut rib, &a).is_none());
        // A second PE with a lower VTEP replaces the winner.
        let b = rt5("10.2.0.0/24", "10.50.0.3", 2, 4);
        let (_, ch, remotes) = add(&mut rib, &b).unwrap();
        assert_eq!(gw(&ch), Some(b.next_hop));
        assert!(remotes);
        // Removing the winner falls back to the other PE.
        let (_, ch, _) = rib.apply_evpn_diff(&b.key, None).unwrap();
        assert_eq!(gw(&ch), Some(a.next_hop));
        // Removing the last removes the route and the remote.
        let (_, ch, remotes) = rib.apply_evpn_diff(&a.key, None).unwrap();
        assert_eq!(ch, BestPathChange::Removed);
        assert!(remotes && rib.evpn.remotes.is_empty());
        // Removing again changes nothing.
        assert!(rib.apply_evpn_diff(&a.key, None).is_none());
    }

    #[test]
    fn remotes_change_only_on_first_and_last_route_of_a_vtep() {
        let mut rib = rib_with_l3();
        let r1 = rt5("10.2.0.0/24", "10.50.0.3", 1, 3);
        let r2 = rt5("10.3.0.0/24", "10.50.0.3", 1, 3);
        assert!(add(&mut rib, &r1).unwrap().2);
        assert!(!add(&mut rib, &r2).unwrap().2);
        assert!(!rib.apply_evpn_diff(&r1.key, None).unwrap().2);
        assert!(rib.apply_evpn_diff(&r2.key, None).unwrap().2);
    }

    #[test]
    fn one_vtep_with_several_rmacs_takes_the_lowest_prefix() {
        let mut rib = rib_with_l3();
        add(&mut rib, &rt5("10.9.0.0/24", "10.50.0.3", 1, 9));
        add(&mut rib, &rt5("10.2.0.0/24", "10.50.0.3", 1, 2));
        let vtep: IpAddr = "10.50.0.3".parse().unwrap();
        assert_eq!(rib.evpn.remotes[&vtep], [2, 0, 0, 0, 0, 2]);
        assert_eq!(desired(&rib.evpn.received, &l3()).1, rib.evpn.remotes);
    }

    #[test]
    fn mac_ip_host_route_is_incremental() {
        let mut rib = rib_with_l3();
        let key = EvpnKey::MacIp {
            rd: [0; 8],
            mac: [2, 0, 0, 0, 0, 9],
            ip: "10.72.0.20".parse().unwrap(),
        };
        let r = EvpnRoute {
            key: key.clone(),
            vni: 10_300,
            next_hop: "10.50.0.3".parse().unwrap(),
            ext_communities: vec![RT, router_mac_ext([2, 0, 0, 0, 0, 3])],
            esi: [0; 10],
            l3_vni: Some(5000),
        };
        let (p, ch, _) = add(&mut rib, &r).unwrap();
        assert_eq!(p, "10.72.0.20/32".parse::<IpNet>().unwrap());
        assert_eq!(gw(&ch), Some(r.next_hop));
        assert_eq!(
            rib.apply_evpn_diff(&key, None).unwrap().1,
            BestPathChange::Removed
        );
    }

    #[test]
    fn irrelevant_routes_change_nothing() {
        let mut rib = rib_with_l3();
        // Own VTEP, wrong VNI, and a Type-3 key.
        assert!(add(&mut rib, &rt5("10.2.0.0/24", "10.50.0.2", 1, 3)).is_none());
        let mut r = rt5("10.2.0.0/24", "10.50.0.3", 1, 3);
        r.vni = 1;
        assert!(add(&mut rib, &r).is_none());
        let imet = EvpnKey::Imet {
            rd: [0; 8],
            origin: "10.50.0.3".parse().unwrap(),
        };
        r.key = imet.clone();
        assert!(rib.apply_evpn_diff(&imet, Some(r)).is_none());
    }

    proptest! {
        /// Any Add/Remove sequence ends where a from-scratch `refresh_evpn` does.
        #[test]
        fn incremental_equals_from_scratch(
            ops in proptest::collection::vec((0u8..6, 0u8..3, 0u8..2, 0u8..3, any::<bool>()), 0..60)
        ) {
            let prefixes = ["10.2.0.0/24", "10.3.0.0/24", "10.4.0.0/24", "2001:db8::/64", "10.5.0.0/24", "10.6.0.0/24"];
            let vteps = ["10.50.0.3", "10.50.0.4", "10.50.0.2"];
            let mut inc = rib_with_l3();
            for (p, v, rd, rmac, is_add) in ops {
                let r = rt5(prefixes[p as usize], vteps[v as usize], rd, rmac + 1);
                if is_add {
                    add(&mut inc, &r);
                } else {
                    inc.apply_evpn_diff(&r.key, None);
                }
                let mut fresh = Rib::new();
                fresh.evpn.local = Some(l3());
                fresh.evpn.received = inc.evpn.received.clone();
                fresh.refresh_evpn();
                prop_assert_eq!(&inc.evpn.remotes, &fresh.evpn.remotes);
                prop_assert_eq!(&inc.evpn.winners, &fresh.evpn.winners);
                prop_assert_eq!(&inc.evpn.by_vtep, &fresh.evpn.by_vtep);
                prop_assert_eq!(&inc.evpn.index, &fresh.evpn.index);
                for p in prefixes {
                    let p: IpNet = p.parse().unwrap();
                    prop_assert_eq!(inc.best_route(&p), fresh.best_route(&p));
                }
            }
        }
    }
}
