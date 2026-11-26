//! One broadcast domain's MAC table: the local MACs the bridge learned, the
//! remote ones EVPN told us about, and the kernel state each implies. The
//! `nos-ribd` `Rib` counterpart — pure decisions here, kernel effects behind
//! `FdbDriver`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::pending;
use std::net::IpAddr;
use std::ops::Bound;
use std::sync::Arc;
use std::time::Duration;

use nos_proto::evpn_id::{
    df_election_ext, es_import_rt, esi_label_ext, format_esi, parse_df_election, parse_esi_label,
    router_mac_ext, Esi, DEFAULT_GATEWAY, DF_ALG_HRW, DF_ALG_MODULO, ENCAP_VXLAN,
};
use nos_proto::fdb::AD_TAG_ES;
use nos_proto::rib::EvpnIrb;
use nos_proto::{
    DfAlgorithm, EsEntry, EvpnKey, EvpnRoute, EvpnUpdate, FdbTable, MacEntry, MacSource, NeighEntry,
};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::{sleep_until, Instant};
use tracing::{debug, info, warn};

use crate::df;
use crate::driver::{is_advertisable_ip, vxlan_name, FdbDriver, Mac};

/// How often local MACs and kernel state are re-checked regardless of
/// notifications — the netlink feed can overflow, and readiness (bridge,
/// VTEP address) is an external condition no config diff signals.
pub const TICK: Duration = Duration::from_secs(10);
/// A burst of neighbour events is answered by one FDB dump.
const DEBOUNCE: Duration = Duration::from_millis(200);

/// This domain's config with everything resolved; absent while incomplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    pub vni: u32,
    pub bridge: String,
    pub vtep: IpAddr,
    /// The kernel device carrying `vtep`: the VXLAN device's underlay.
    pub underlay: String,
    pub rd: [u8; 8],
    pub rt_import: Vec<u64>,
    pub rt_export: Vec<u64>,
    pub bgp_instance: String,
    /// `redistribute from arp`: local ARP/ND bindings are originated too.
    pub arp: bool,
    /// `redistribute from connected`: these SVI addresses (already filtered
    /// to `is_advertisable_ip`) are originated with the bridge's MAC.
    pub connected: Vec<IpAddr>,
    /// The bridge ports of this domain that attach an Ethernet Segment (a
    /// port aggregate with an `esi`, member of this domain).
    pub es_ports: Vec<EsPort>,
    /// `neigh-suppress`: ARP/ND suppression on the VXLAN bridge port.
    pub neigh_suppress: bool,
    /// `max-remote-macs`: ceiling on installed remote MACs (lowest win).
    pub max_remote_macs: Option<u32>,
    /// RFC 9135 symmetric IRB: the IP-VRF of the routing table the SVI is in,
    /// when that table has an L3 VNI on our BGP instance (asked of its
    /// `nos-ribd`). `None` is asymmetric.
    pub irb: Option<EvpnIrb>,
}

/// A bridge port attached to an Ethernet Segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsPort {
    /// The kernel bridge-port device: the bond, or its `<bond>.<tag>` VLAN
    /// sub-link.
    pub port: String,
    pub esi: Esi,
    /// `redundancy-mode single-active` on the aggregate.
    pub single_active: bool,
    /// `df-algorithm` on the aggregate: what we ask for in our Type-4.
    pub df_algorithm: DfAlgorithm,
}

/// One attached segment's election outcome for this domain. The four bools
/// are independent facts (elected, still waiting, carrier, mode).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
struct Segment {
    esi: Esi,
    port: String,
    /// Every PE on the segment, ranked (see `df::candidates`).
    pes: Vec<IpAddr>,
    df: bool,
    /// Inside the DF wait timer: treated as non-DF whatever the election says
    /// (set by `sync_df`; `plan_df` itself stays pure).
    waiting: bool,
    /// The port has carrier. A down segment is neither DF nor advertised.
    up: bool,
    /// The other PEs whose per-ES Ethernet A-D route for this segment we hold.
    ad_pes: Vec<IpAddr>,
    /// Single-active: a non-DF is blocked outright, not just refused BUM.
    single_active: bool,
    /// The election algorithm in effect (RFC 8584 §2.2.3).
    algorithm: DfAlgorithm,
    /// Every PE's Type-4 carried AC-DF, so the per-EVI filter applied.
    ac_df: bool,
}

impl Segment {
    /// Whether two plans elect the same way — `ad_pes` changing alone is not
    /// a new election (it would only repeat the `df elected` log).
    fn same_election(&self, o: &Self) -> bool {
        (
            &self.esi,
            &self.port,
            &self.pes,
            self.df,
            self.waiting,
            self.up,
            self.single_active,
            self.algorithm,
            self.ac_df,
        ) == (
            &o.esi,
            &o.port,
            &o.pes,
            o.df,
            o.waiting,
            o.up,
            o.single_active,
            o.algorithm,
            o.ac_df,
        )
    }
}

/// What the Ethernet A-D routes we hold say about one segment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SegmentAds {
    /// The PEs whose per-ES Ethernet A-D route we hold (RFC 7432 §8.2): a
    /// remote MAC on the segment is only usable while its PE is in here, and
    /// withdrawing the route is the mass withdrawal that takes every such MAC
    /// away at once.
    pes: BTreeSet<IpAddr>,
    /// The PEs whose per-EVI A-D route for this domain's VNI we hold: the
    /// backup paths of a single-active segment (§8.4.1.2).
    evi: BTreeSet<IpAddr>,
    /// A per-ES route carried the Single-Active flag in its ESI Label.
    single_active: bool,
    /// The PEs whose Type-4 for this segment we hold: who the segment would
    /// elect as DF, so whom a single-active backup path points at.
    es_pes: BTreeSet<IpAddr>,
}

type Ads = HashMap<Esi, SegmentAds>;

/// What `bgp_client` keeps originated into the named BGP instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvpnTarget {
    pub domain: String,
    pub bgp_instance: Option<String>,
    pub routes: HashMap<EvpnKey, EvpnRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Installed {
    Mac {
        mac: Mac,
        vtep: IpAddr,
    },
    /// A MAC on an all-active segment, balanced over these PEs (sorted).
    MacGroup {
        mac: Mac,
        vteps: Vec<IpAddr>,
    },
    /// An IP-to-MAC binding on the bridge; `vtep` is only for `show fdb`.
    Neigh {
        mac: Mac,
        ip: IpAddr,
        vtep: IpAddr,
    },
    Flood {
        vtep: IpAddr,
    },
    /// A remote MAC on one of our own segments, pinned to its bridge port.
    SegmentMac {
        mac: Mac,
        port: String,
    },
}

/// RFC 7432 §7.6: a Type-4 is imported only by a PE attached to the segment,
/// which it recognises by the ES-Import RT derived from the ESI.
fn es_import_ok(route: &EvpnRoute, esi: &Esi) -> bool {
    route.ext_communities.contains(&es_import_rt(esi))
}

/// The (our ESI, origin) Type-4s received without that ESI's ES-Import RT:
/// ignored by `plan_df` and `ad_index`.
fn es_import_mismatches(
    r: &Ready,
    received: &HashMap<EvpnKey, EvpnRoute>,
) -> BTreeSet<(Esi, IpAddr)> {
    received
        .values()
        .filter_map(|route| match &route.key {
            EvpnKey::EthernetSegment { esi, origin, .. }
                if *origin != r.vtep
                    && r.es_ports.iter().any(|p| p.esi == *esi)
                    && !es_import_ok(route, esi) =>
            {
                Some((*esi, *origin))
            }
            _ => None,
        })
        .collect()
}

/// The A-D index of `received`: only routes carrying one of our import Route
/// Targets count (a per-ES route carries the RTs of the EVIs on the segment),
/// and never our own. A per-EVI route also has to name this domain's VNI.
/// Type-4s carry only an ES-Import RT: one counts, for any segment, when it
/// carries that segment's ES-Import RT (RFC 7432 §7.6); it only feeds the
/// single-active `backup_pe` (`plan_df` reads Type-4s itself, by exact ESI).
fn ad_index(r: &Ready, received: &HashMap<EvpnKey, EvpnRoute>) -> Ads {
    let mut out = Ads::new();
    for route in received.values() {
        if let EvpnKey::EthernetSegment { esi, origin, .. } = &route.key {
            if *origin != r.vtep && es_import_ok(route, esi) {
                out.entry(*esi).or_default().es_pes.insert(*origin);
            }
            continue;
        }
        let EvpnKey::EthernetAd {
            esi, tag, origin, ..
        } = &route.key
        else {
            continue;
        };
        if *origin == r.vtep
            || !route
                .ext_communities
                .iter()
                .any(|c| r.rt_import.contains(c))
        {
            continue;
        }
        let ads = out.entry(*esi).or_default();
        if *tag == AD_TAG_ES {
            ads.pes.insert(*origin);
            ads.single_active |= route
                .ext_communities
                .iter()
                .any(|c| parse_esi_label(*c) == Some(true));
        } else if route.vni == r.vni {
            ads.evi.insert(*origin);
        }
    }
    out
}

/// The PEs a MAC on an all-active segment is load-balanced over (aliasing,
/// RFC 7432 §8.4.1.1): those that advertise both the segment (per-ES A-D) and
/// the EVI (per-EVI A-D). Only when there are several, the MAC's own PE is one
/// of them, and they all share our VTEP's address family (the kernel refuses
/// a mixed group, or one whose family differs from the VXLAN device's).
fn alias_group(a: &SegmentAds, owner: IpAddr, own_vtep: IpAddr) -> Option<Vec<IpAddr>> {
    if a.single_active {
        return None;
    }
    let members: Vec<IpAddr> = a.pes.intersection(&a.evi).copied().collect();
    let same_family = members.iter().all(|m| m.is_ipv4() == own_vtep.is_ipv4());
    (members.len() > 1 && members.contains(&owner) && same_family).then_some(members)
}

/// A single-active segment's backup PE once the MAC's own PE lost its per-ES
/// A-D (RFC 7432 §8.4.1.2): among the PEs still advertising both the segment
/// and the EVI, the one the segment elects as DF, by its Type-4s; the lowest
/// address when none of their Type-4s is held (an RT-Constraint or reflector
/// may filter them, §7.6). `ponytail:` modulo only — the DF is not on the
/// wire, so a remote segment running HRW or Preference may disagree.
fn backup_pe(a: &SegmentAds, vni: u32) -> Option<IpAddr> {
    let usable: BTreeSet<IpAddr> = a.pes.intersection(&a.evi).copied().collect();
    let elected: BTreeSet<IpAddr> = a.es_pes.intersection(&usable).copied().collect();
    match elected.first() {
        Some(any) => Some(df::elect(*any, &elected, vni)),
        None => usable.first().copied(),
    }
}

/// The segment ports that can carry unicast, by ESI: up, and not a
/// single-active port held off its segment (non-DF, or still in its DF wait).
/// An all-active non-DF still forwards unicast — its flood flags gate BUM only.
fn pinnable(segments: &[Segment]) -> HashMap<Esi, String> {
    segments
        .iter()
        .filter(|s| s.up && !(s.single_active && (!s.df || s.waiting)))
        .map(|s| (s.esi, s.port.clone()))
        .collect()
}

// Calls of `desired` on this thread (the unit tests count them, #604).
#[cfg(test)]
thread_local!(static DESIRED_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) });

/// What a received route should become in the kernel, if anything: it must
/// carry one of our import Route Targets, name this VNI, and not be our own.
/// A Type-2 with an IP is both an FDB entry (its MAC) and a neighbour (its IP).
/// A Type-2 on a segment is only usable while its PE's per-ES A-D route for
/// that segment is held (`ads`) — except on one of our own segments whose port
/// can carry it (`pinnable`): the MAC is then pinned to that port (RFC 7432
/// §8.4: it is behind our own link too), whatever the PE's A-D routes say,
/// unless the bridge learned it behind another port (`local`). An unpinnable
/// own segment falls back to the remote PEs like any other.
fn desired(
    r: &Ready,
    route: &EvpnRoute,
    ads: &Ads,
    local: &BTreeMap<Mac, String>,
    pinnable: &HashMap<Esi, String>,
) -> Vec<Installed> {
    #[cfg(test)]
    DESIRED_CALLS.with(|c| c.set(c.get() + 1));
    if !route
        .ext_communities
        .iter()
        .any(|c| r.rt_import.contains(c))
    {
        return Vec::new();
    }
    let pin_port = (route.esi != [0; 10])
        .then(|| pinnable.get(&route.esi))
        .flatten();
    if let (Some(port), true) = (pin_port, route.vni == r.vni && route.next_hop != r.vtep) {
        let (mac, ip) = match &route.key {
            EvpnKey::Mac { mac, .. } => (*mac, None),
            EvpnKey::MacIp { mac, ip, .. } => (*mac, Some(*ip)),
            _ => return Vec::new(),
        };
        if local.get(&mac).is_some_and(|p| p != port) {
            return Vec::new();
        }
        let mut v = vec![Installed::SegmentMac {
            mac,
            port: port.clone(),
        }];
        if let Some(ip) = ip.filter(|ip| is_advertisable_ip(*ip)) {
            v.push(Installed::Neigh {
                mac,
                ip,
                vtep: route.next_hop,
            });
        }
        return v;
    }
    // The PE a MAC on a segment is reached through: the one that advertised it
    // while its per-ES A-D is held; on a single-active segment whose PE lost it,
    // a backup (a PE that advertised a per-EVI A-D for this VNI).
    let via = if route.esi == [0; 10] {
        Some(route.next_hop)
    } else {
        ads.get(&route.esi).and_then(|a| {
            if a.pes.contains(&route.next_hop) {
                Some(route.next_hop)
            } else if a.single_active {
                backup_pe(a, r.vni)
            } else {
                None
            }
        })
    };
    let foreign_type2 = route.vni == r.vni && route.next_hop != r.vtep && via.is_some();
    let vtep = via.unwrap_or(route.next_hop);
    // A MAC whose own PE's per-ES A-D is held is aliased over the segment's PEs.
    let group = (via == Some(route.next_hop))
        .then(|| {
            ads.get(&route.esi)
                .and_then(|a| alias_group(a, route.next_hop, r.vtep))
        })
        .flatten();
    let mac_item = |mac: Mac| match &group {
        Some(vteps) => Installed::MacGroup {
            mac,
            vteps: vteps.clone(),
        },
        None => Installed::Mac { mac, vtep },
    };
    match &route.key {
        EvpnKey::Mac { mac, .. } if foreign_type2 => vec![mac_item(*mac)],
        EvpnKey::MacIp { mac, ip, .. } if foreign_type2 => {
            let mut v = vec![mac_item(*mac)];
            if is_advertisable_ip(*ip) {
                v.push(Installed::Neigh {
                    mac: *mac,
                    ip: *ip,
                    vtep,
                });
            }
            v
        }
        // A Type-3's VNI comes from its PMSI attribute (0 = absent).
        EvpnKey::Imet { origin, .. }
            if (route.vni == 0 || route.vni == r.vni) && *origin != r.vtep =>
        {
            vec![Installed::Flood { vtep: *origin }]
        }
        _ => Vec::new(),
    }
}

/// The ESI a MAC learned behind `port` is advertised with (all-zero when the
/// port isn't a segment's).
fn esi_of(r: &Ready, port: Option<&String>) -> Esi {
    port.and_then(|port| r.es_ports.iter().find(|p| &p.port == port))
        .map_or([0; 10], |p| p.esi)
}

/// This domain's originated routes: one Type-3 for the domain, one Type-2
/// per local MAC and one Type-2 (MAC+IP) per local neighbour / SVI address
/// (carrying the ESI of the port the MAC sits behind, and — for an SVI
/// address, RFC 7432 §7.8 — the Default Gateway extended community), and,
/// per attached Ethernet Segment whose port has carrier (not in `down`), one
/// Type-4 and the two Type-1 Ethernet A-D routes (per-ES and per-EVI). A
/// segment going down withdraws all three — that is what tells the other PEs
/// to stop sending its MACs here.
fn local_routes(
    r: &Ready,
    macs: &BTreeMap<Mac, String>,
    neighbours: &BTreeSet<(Mac, IpAddr)>,
    down: &BTreeSet<String>,
) -> HashMap<EvpnKey, EvpnRoute> {
    let mut ext = r.rt_export.clone();
    ext.push(ENCAP_VXLAN);
    let route = |key: EvpnKey, esi: Esi| EvpnRoute {
        key,
        vni: r.vni,
        next_hop: r.vtep,
        ext_communities: ext.clone(),
        esi,
        l3_vni: None,
    };
    let mut out = HashMap::new();
    let imet = EvpnKey::Imet {
        rd: r.rd,
        origin: r.vtep,
    };
    out.insert(imet.clone(), route(imet, [0; 10]));
    for (m, port) in macs {
        let key = EvpnKey::Mac { rd: r.rd, mac: *m };
        out.insert(key.clone(), route(key, esi_of(r, Some(port))));
    }
    for (m, ip) in neighbours {
        let key = EvpnKey::MacIp {
            rd: r.rd,
            mac: *m,
            ip: *ip,
        };
        let mut evpn_route = route(key.clone(), esi_of(r, macs.get(m)));
        // RFC 7432 §7.8: mark the SVI's own address as the anycast gateway,
        // never a real ARP/ND-learned host behind a local port.
        if r.connected.contains(ip) {
            evpn_route.ext_communities.push(DEFAULT_GATEWAY);
        } else if let Some(irb) = &r.irb {
            // RFC 9135 §5.1: a host's MAC+IP carries the IP-VRF's L3 VNI as
            // Label2, its export RTs and the Router's MAC. Never the gateway
            // address: it is local on every PE.
            // ponytail: no per-table off switch (owner's call, #188); add a
            // `RoutingTableEvpn` field if a mixed deployment needs one.
            evpn_route.l3_vni = Some(irb.l3_vni);
            evpn_route
                .ext_communities
                .extend(irb.route_targets_export.iter().copied());
            evpn_route
                .ext_communities
                .push(router_mac_ext(irb.router_mac));
        }
        out.insert(key, evpn_route);
    }
    let mut esis: BTreeMap<Esi, (bool, DfAlgorithm)> = BTreeMap::new();
    for p in r.es_ports.iter().filter(|p| !down.contains(&p.port)) {
        let e = esis.entry(p.esi).or_default();
        e.0 |= p.single_active;
        e.1 = p.df_algorithm;
    }
    for (esi, (single_active, alg)) in esis {
        let key = EvpnKey::EthernetSegment {
            rd: r.rd,
            esi,
            origin: r.vtep,
        };
        // A Type-4 carries its ES-Import Route Target (RFC 7432 §7.6) — it is
        // for the PEs on the segment, not for a MAC-VRF's import — and the DF
        // Election community (RFC 8584 §2.2), always with AC-DF.
        let alg = match alg {
            DfAlgorithm::Modulo => DF_ALG_MODULO,
            DfAlgorithm::Hrw => DF_ALG_HRW,
        };
        out.insert(
            key.clone(),
            EvpnRoute {
                key,
                vni: 0,
                next_hop: r.vtep,
                ext_communities: vec![es_import_rt(&esi), df_election_ext(alg, true)],
                esi,
                l3_vni: None,
            },
        );
        // Per-ES A-D (RFC 7432 §8.2.1): MAX-ET, the export RTs of the EVIs on
        // the segment, and the ESI Label community (RFC 8365 §8.3.1: no label
        // with VXLAN, only its flags octet).
        let key = EvpnKey::EthernetAd {
            rd: r.rd,
            esi,
            tag: AD_TAG_ES,
            origin: r.vtep,
        };
        let mut es_ext = ext.clone();
        es_ext.push(esi_label_ext(single_active));
        out.insert(
            key.clone(),
            EvpnRoute {
                key,
                vni: 0,
                next_hop: r.vtep,
                ext_communities: es_ext,
                esi,
                l3_vni: None,
            },
        );
        // Per-EVI A-D (§8.4): tag 0, the VNI in the label, this domain's RTs.
        let key = EvpnKey::EthernetAd {
            rd: r.rd,
            esi,
            tag: 0,
            origin: r.vtep,
        };
        out.insert(key.clone(), route(key, esi));
    }
    out
}

/// What one PE's Type-4 routes for a segment ask for (RFC 8584 §2.2): the DF
/// algorithm (`None`: no DF Election community, or one we don't implement)
/// and the AC-DF capability. A PE has one Type-4 per domain (per RD); if they
/// disagree, the conservative reading wins (no algorithm, no AC-DF).
fn df_capabilities(route: &EvpnRoute) -> (Option<DfAlgorithm>, bool) {
    route
        .ext_communities
        .iter()
        .find_map(|c| parse_df_election(*c))
        .map_or((None, false), |(alg, ac_df)| {
            let alg = match alg {
                DF_ALG_MODULO => Some(DfAlgorithm::Modulo),
                DF_ALG_HRW => Some(DfAlgorithm::Hrw),
                _ => None,
            };
            (alg, ac_df)
        })
}

/// Elects the Designated Forwarder of every segment this domain attaches to,
/// from the Type-4 routes received so far. Other PEs are recognised by their
/// Type-4's originating address; our own is `r.vtep`. A segment whose port is
/// in `down` is never the DF.
///
/// RFC 8584 §2.2.3, strictly: only when every PE's Type-4 (ours always does)
/// carries AC-DF are the candidates restricted to PEs also attached to this
/// domain's own EVI (a held per-EVI Ethernet A-D for our VNI); otherwise the
/// candidates are RFC 7432's, every Type-4 origin. Separately, HRW runs only
/// when every candidate asks for it (`df::effective`), else modulo.
fn plan_df(
    r: &Ready,
    received: &HashMap<EvpnKey, EvpnRoute>,
    ads: &Ads,
    down: &BTreeSet<String>,
) -> Vec<Segment> {
    r.es_ports
        .iter()
        .map(|p| {
            let mut origins: BTreeMap<IpAddr, (Option<DfAlgorithm>, bool)> = BTreeMap::new();
            for route in received.values() {
                let EvpnKey::EthernetSegment { esi, origin, .. } = &route.key else {
                    continue;
                };
                if *esi != p.esi || *origin == r.vtep || !es_import_ok(route, esi) {
                    continue;
                }
                let (alg, ac_df) = df_capabilities(route);
                origins
                    .entry(*origin)
                    .and_modify(|e| {
                        if e.0 != alg {
                            e.0 = None;
                        }
                        e.1 &= ac_df;
                    })
                    .or_insert((alg, ac_df));
            }
            let ac_df = origins.values().all(|(_, ac)| *ac);
            let peers: BTreeSet<IpAddr> = origins
                .keys()
                .filter(|o| !ac_df || ads.get(&p.esi).is_some_and(|a| a.evi.contains(o)))
                .copied()
                .collect();
            let algorithm = df::effective(
                p.df_algorithm,
                r.vtep,
                peers.iter().map(|o| (*o, origins[o].0)),
            );
            let winner = match algorithm {
                DfAlgorithm::Modulo => df::elect(r.vtep, &peers, r.vni),
                DfAlgorithm::Hrw => df::elect_hrw(r.vtep, &peers, r.vni, &p.esi),
            };
            let up = !down.contains(&p.port);
            Segment {
                esi: p.esi,
                port: p.port.clone(),
                pes: df::candidates(r.vtep, &peers),
                df: up && winner == r.vtep,
                waiting: false,
                up,
                ad_pes: ads
                    .get(&p.esi)
                    .map_or_default(|a| a.pes.iter().copied().collect()),
                single_active: p.single_active,
                algorithm,
                ac_df,
            }
        })
        .collect()
}

/// What EVPN local bias (RFC 8365 §8.3.1) needs for the current plan: the
/// egress filters per all-active segment port and the ingress marking per
/// peer. Pure, so the bitmaps are testable without a kernel.
#[derive(Debug, Default, PartialEq, Eq)]
struct BiasPlan {
    /// Segment port -> (its bit, whether it also drops every core-origin BUM:
    /// a non-DF, a port in its DF wait or without carrier).
    ports: BTreeMap<String, (u16, bool)>,
    /// Every other PE of those segments -> the bits of the segments it is on.
    peers: BTreeMap<IpAddr, u16>,
    /// All-active ports beyond the 16 the mark has bits for: they keep DF-only
    /// flooding.
    overflow: Vec<String>,
}

/// Single-active segments are left out: their non-DF drops *everything* on the
/// port (STP disabled), so the DF has to deliver the BUM its peer received
/// locally — a local-bias drop there would lose it.
///
/// `ponytail:` 16 all-active segments per domain, one mark bit each (the mark's
/// top byte is the magic, the next one left to others).
fn plan_local_bias(vtep: IpAddr, plan: &[Segment]) -> BiasPlan {
    let mut out = BiasPlan::default();
    let mut all_active: Vec<&Segment> = plan.iter().filter(|s| !s.single_active).collect();
    all_active.sort_by(|a, b| a.port.cmp(&b.port));
    for (i, s) in all_active.into_iter().enumerate() {
        let Some(bit) = 1u16.checked_shl(u32::try_from(i).unwrap_or(u32::MAX)) else {
            out.overflow.push(s.port.clone());
            continue;
        };
        out.ports.insert(s.port.clone(), (bit, !s.df || s.waiting));
        for pe in s.pes.iter().filter(|pe| **pe != vtep) {
            *out.peers.entry(*pe).or_default() |= bit;
        }
    }
    out
}

fn algorithm_name(a: DfAlgorithm) -> &'static str {
    match a {
        DfAlgorithm::Modulo => "modulo",
        DfAlgorithm::Hrw => "hrw",
    }
}

fn join_ips(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub fn format_mac(mac: Mac) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Default)]
struct Inner {
    ready: Option<Ready>,
    received: HashMap<EvpnKey, EvpnRoute>,
    /// What each received route put in the kernel. Two routes can name the
    /// same entry (a MAC-only and a MAC+IP Type-2 for one MAC), so an item is
    /// only removed when no other key still holds it.
    installed: HashMap<EvpnKey, Vec<Installed>>,
    /// How many keys in `installed` hold each item (`installed`'s inverse),
    /// so "held by another key" is O(1). Written only by `set_installed`.
    holders: HashMap<Installed, u32>,
    /// Each MAC with the bridge port it sits behind.
    local: BTreeMap<Mac, String>,
    /// The last election result per attached segment.
    segments: Vec<Segment>,
    /// The `(unicast, bum)` flood setting last applied to each segment port.
    es_flood: BTreeMap<String, (bool, bool)>,
    /// The egress filters (`bit`, DF filter) last written on each segment port.
    es_filter: BTreeMap<String, (u16, bool)>,
    /// The segment ports whose local bias is fully in place (their egress
    /// filters *and* the ingress marking): what `show fdb` reports.
    es_bias: BTreeSet<String>,
    /// The peers (with their segment bitmaps) the ingress marking was last
    /// written for.
    bias_peers: BTreeMap<IpAddr, u16>,
    /// Ports already warned about for a failed local-bias setup.
    bias_warned: BTreeSet<String>,
    /// (ESI, origin) Type-4s already warned about for a missing ES-Import RT.
    es_import_warned: BTreeSet<(Esi, IpAddr)>,
    /// When the local-bias kernel state was last written unconditionally: an
    /// unchanged one is only re-asserted (healing a recreated bond or VXLAN
    /// device) about once per `TICK`, not on every pushed route.
    bias_healed: Option<Instant>,
    /// The forwarding state last applied to each segment port (only recorded
    /// once it left the kernel default, forwarding).
    es_fwd: BTreeMap<String, bool>,
    /// When each attached segment port's DF wait timer ends (RFC 7432 §8.5
    /// step 3). Set the first time the port is planned, dropped when it leaves.
    df_wait_until: BTreeMap<String, Instant>,
    /// Local ARP/ND bindings and SVI addresses, as (MAC, IP).
    local_neigh: BTreeSet<(Mac, IpAddr)>,
    /// The per-ES A-D routes held, see `Ads`. Kept current by `refresh_ads`.
    ads: Ads,
    /// Attached segment ports with no carrier (unknown counts as up).
    es_down: BTreeSet<String>,
    /// The `neigh_suppress` last applied by `ensure_vxlan` (what `show fdb`
    /// reports).
    neigh_suppress: bool,
    /// The remote MACs admitted under `max_remote_macs` (`None`: no ceiling).
    admitted: Option<BTreeSet<Mac>>,
    /// Ceiling bookkeeping, kept only while a ceiling is set: the MACs each
    /// route would install (`desired`, before the ceiling) and its inverse.
    /// `admitted` is always the lowest `max_remote_macs` keys of `cand`.
    cand_by_key: HashMap<EvpnKey, BTreeSet<Mac>>,
    cand: BTreeMap<Mac, HashSet<EvpnKey>>,
    /// The ceiling warning fired and the count has not dropped back since.
    ceiling_warned: bool,
}

/// Recomputes `g.ads` and returns the segments whose PE set changed.
fn refresh_ads(g: &mut Inner) -> Vec<Esi> {
    let new = g
        .ready
        .as_ref()
        .map_or_default(|r| ad_index(r, &g.received));
    let stale = new
        .keys()
        .chain(g.ads.keys())
        .filter(|e| new.get(*e) != g.ads.get(*e))
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    g.ads = new;
    stale
}

pub struct Fdb {
    domain: String,
    driver: Arc<dyn FdbDriver>,
    inner: Mutex<Inner>,
    target: watch::Sender<EvpnTarget>,
    df_wait: Duration,
    /// The earliest running DF wait timer, for `run_local` to sleep until.
    df_deadline: watch::Sender<Option<Instant>>,
}

impl Fdb {
    pub fn new(domain: String, driver: Arc<dyn FdbDriver>, df_wait: Duration) -> Arc<Self> {
        let (target, _) = watch::channel(EvpnTarget {
            domain: domain.clone(),
            ..EvpnTarget::default()
        });
        Arc::new(Self {
            domain,
            driver,
            inner: Mutex::default(),
            target,
            df_wait,
            df_deadline: watch::channel(None).0,
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<EvpnTarget> {
        self.target.subscribe()
    }

    fn publish(&self, g: &Inner) {
        let target = EvpnTarget {
            domain: self.domain.clone(),
            bgp_instance: g.ready.as_ref().map(|r| r.bgp_instance.clone()),
            routes: g
                .ready
                .as_ref()
                .map_or_default(|r| local_routes(r, &g.local, &g.local_neigh, &g.es_down)),
        };
        self.target.send_if_modified(|t| {
            let changed = *t != target;
            *t = target;
            changed
        });
    }

    /// Called by `reconcile` on every resync with the fully resolved config
    /// (or `None` while incomplete): (re)builds the VXLAN device and
    /// everything on it when that changed, and heals drift when it didn't.
    pub async fn set_ready(&self, ready: Option<Ready>) {
        let mut g = self.inner.lock().await;
        // `ensure_vxlan` applies a neigh-suppress toggle in place, and an IRB
        // change only re-publishes the local routes: no rebuild for either.
        if let (Some(old), Some(new)) = (g.ready.as_mut(), ready.as_ref()) {
            old.neigh_suppress = new.neigh_suppress;
            old.max_remote_macs = new.max_remote_macs;
            if old.irb != new.irb {
                old.irb.clone_from(&new.irb);
                info!(domain = %self.domain, l3_vni = ?new.irb.as_ref().map(|i| i.l3_vni), "symmetric irb changed");
                self.publish(&g);
            }
        }
        if g.ready != ready {
            if let Some(old) = g.ready.take() {
                let mut items: Vec<Installed> = Vec::new();
                g.holders.clear();
                for i in std::mem::take(&mut g.installed).into_values().flatten() {
                    if !items.contains(&i) {
                        items.push(i);
                    }
                }
                for i in &items {
                    self.uninstall(&old, i).await;
                }
                if ready.as_ref().map(|r| r.vni) != Some(old.vni)
                    && let Err(e) = self.driver.remove_vxlan(old.vni).await
                {
                    warn!(domain = %self.domain, error = %e, "failed to remove the old vxlan device");
                }
                g.local.clear();
                g.local_neigh.clear();
                // `remove_vxlan` took the ingress marking with the device.
                g.bias_peers.clear();
            }
            self.publish(&g);
        }
        let Some(want) = ready else {
            g.neigh_suppress = false;
            self.sync_df(&mut g).await;
            return;
        };
        // Idempotent: also the tick's repair path for a deleted/changed link.
        if let Err(e) = self
            .driver
            .ensure_vxlan(
                want.vni,
                want.vtep,
                &want.underlay,
                &want.bridge,
                want.neigh_suppress,
            )
            .await
        {
            debug!(domain = %self.domain, error = %e, "vxlan device not ready yet, retrying");
            g.neigh_suppress = false;
            g.ready = None;
            g.installed.clear();
            g.holders.clear();
            self.publish(&g);
            self.sync_df(&mut g).await;
            return;
        }
        g.neigh_suppress = want.neigh_suppress;
        if g.ready.is_none() {
            info!(
                domain = %self.domain, vni = want.vni, vxlan = %vxlan_name(want.vni),
                bridge = %want.bridge, vtep = %want.vtep, "vxlan device ready"
            );
            g.ready = Some(want);
            self.publish(&g);
        }
        refresh_ads(&mut g);
        // Every key is re-synced below, so the ceiling bookkeeping restarts
        // from scratch (a changed or lifted ceiling included).
        g.admitted = None;
        g.cand_by_key.clear();
        g.cand.clear();
        let keys: Vec<EvpnKey> = g.received.keys().cloned().collect();
        self.sync_keys(&mut g, keys).await;
        self.sync_df(&mut g).await;
    }

    /// Warns once per (ESI, origin) Type-4 ignored for lacking the ES-Import RT.
    fn warn_es_import(&self, g: &mut Inner) {
        let bad = g
            .ready
            .as_ref()
            .map_or_default(|r| es_import_mismatches(r, &g.received));
        for (esi, origin) in bad.difference(&g.es_import_warned) {
            warn!(
                domain = %self.domain, esi = %format_esi(esi), origin = %origin,
                "evpn type-4 ignored, es-import rt mismatch"
            );
        }
        g.es_import_warned = bad;
    }

    /// Re-elects the Designated Forwarder of every attached segment and
    /// applies it: a non-DF stops flooding BUM to the segment's port, a DF
    /// (and a port no longer on any segment) floods normally. A port is held
    /// blocked for `df_wait` after it first appears (RFC 7432 §8.5 step 3), so
    /// a PE that has just come up doesn't deliver BUM the DF already does. The
    /// block is re-asserted every call, so a port the kernel recreated is
    /// healed by the tick.
    async fn sync_df(&self, g: &mut Inner) {
        let was = pinnable(&g.segments);
        self.warn_es_import(g);
        let mut plan = g
            .ready
            .as_ref()
            .map_or_default(|r| plan_df(r, &g.received, &g.ads, &g.es_down));
        let now = Instant::now();
        for s in &mut plan {
            if !s.up {
                // No carrier: the wait starts over when it comes back.
                g.df_wait_until.remove(&s.port);
                s.waiting = true;
                continue;
            }
            let until = *g.df_wait_until.entry(s.port.clone()).or_insert_with(|| {
                info!(
                    domain = %self.domain, esi = %format_esi(&s.esi), port = %s.port,
                    seconds = self.df_wait.as_secs(), "df wait started"
                );
                now + self.df_wait
            });
            s.waiting = now < until;
        }
        g.df_wait_until
            .retain(|p, _| plan.iter().any(|s| &s.port == p));
        let next = g
            .df_wait_until
            .values()
            .filter(|u| **u > now)
            .min()
            .copied();
        self.df_deadline.send_if_modified(|d| {
            let changed = *d != next;
            *d = next;
            changed
        });
        // Local bias (RFC 8365 §8.3.1). The order is the safety property: the
        // egress filters, then the ingress marking, and only then do a port's
        // multicast/broadcast flood flags open (below). A missing piece leaves
        // that port on today's DF-only flooding: duplicates, never loss.
        let bias = g
            .ready
            .as_ref()
            .map(|r| (r.vni, plan_local_bias(r.vtep, &plan)));
        let mut filtered: BTreeSet<String> = BTreeSet::new();
        let mut marked = true;
        if let Some((vni, b)) = &bias {
            let heal = g.bias_healed.is_none_or(|t| now - t >= TICK / 2);
            if heal {
                g.bias_healed = Some(now);
            }
            for (port, (bit, df_filter)) in &b.ports {
                if self
                    .apply_segment_filter(g, port, *bit, *df_filter, heal)
                    .await
                {
                    filtered.insert(port.clone());
                }
            }
            marked = self.apply_local_bias(g, *vni, &b.peers, heal).await;
            if marked {
                g.bias_warned.remove("");
            }
            for port in &b.overflow {
                if g.bias_warned.insert(port.clone()) {
                    warn!(domain = %self.domain, port = %port, "more than 16 all-active segments, no local bias, df-only flooding");
                }
            }
        }
        // Filters of a port that left the plan or went single-active.
        let stale: Vec<String> = g
            .es_filter
            .keys()
            .filter(|p| bias.as_ref().is_none_or(|(_, b)| !b.ports.contains_key(*p)))
            .cloned()
            .collect();
        for port in stale {
            if self.driver.clear_segment_filter(&port).await.is_ok() {
                g.es_filter.remove(&port);
                info!(domain = %self.domain, port = %port, "segment filter cleared");
            }
        }
        g.es_bias.clear();
        for s in &plan {
            if !s.waiting
                && !g
                    .segments
                    .iter()
                    .find(|o| o.port == s.port)
                    .is_some_and(|o| o.same_election(s))
            {
                // `%`, not a bare str: a plain str field renders quoted.
                let role = if s.df { "df" } else { "non-df" };
                info!(
                    domain = %self.domain, esi = %format_esi(&s.esi), port = %s.port,
                    role = %role,
                    algorithm = %algorithm_name(s.algorithm), ac_df = s.ac_df,
                    pes = %s.pes.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
                    "df elected"
                );
            }
            // All-active with local bias: multicast and broadcast flood on
            // whatever the role (a frame from a local access port goes to the
            // segment regardless of the DF; core BUM is the egress filter's),
            // unknown unicast only on the DF. Without it, only the DF floods
            // anything. Single-active: the port floods normally but only the
            // DF's forwards anything.
            let active = s.df && !s.waiting;
            let biased = filtered.contains(&s.port) && marked;
            if biased {
                g.es_bias.insert(s.port.clone());
                g.bias_warned.remove(&s.port);
            }
            let (flood, forwarding) = if s.single_active {
                ((true, true), active)
            } else if biased {
                ((active, true), true)
            } else {
                ((active, active), true)
            };
            self.apply_port_flood(g, &s.port, flood).await;
            self.apply_port_forwarding(g, &s.port, forwarding).await;
        }
        let gone: Vec<String> = g
            .es_flood
            .keys()
            .chain(g.es_fwd.keys())
            .filter(|p| !plan.iter().any(|s| &s.port == *p))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for port in gone {
            // Best effort: if the port is gone too there is nothing to restore.
            if g.es_flood.remove(&port).is_some()
                && self.driver.set_port_flood(&port, true, true).await.is_ok()
            {
                info!(domain = %self.domain, port = %port, flood = true, "segment port flooding set");
            }
            if g.es_fwd.remove(&port) == Some(false)
                && self.driver.set_port_forwarding(&port, true).await.is_ok()
            {
                info!(domain = %self.domain, port = %port, forwarding = true, "segment port forwarding set");
            }
            g.bias_warned.remove(&port);
        }
        g.segments = plan;
        // A segment port that can (no longer) carry unicast re-decides its
        // remote MACs: pinned to the port, or sent to the other PEs.
        let now = pinnable(&g.segments);
        if now != was {
            let keys: Vec<EvpnKey> = g
                .received
                .iter()
                .filter(|(_, r)| {
                    now.get(&r.esi) != was.get(&r.esi)
                        && matches!(r.key, EvpnKey::Mac { .. } | EvpnKey::MacIp { .. })
                })
                .map(|(k, _)| k.clone())
                .collect();
            self.sync_keys(g, keys).await;
        }
    }

    /// Applies the flood setting `(unicast, bum)` of one segment port; anything
    /// but all-on is re-asserted on every call (a recreated port is healed by
    /// the tick).
    async fn apply_port_flood(&self, g: &mut Inner, port: &str, flood: (bool, bool)) {
        let prev = g.es_flood.get(port).copied();
        if prev == Some(flood) && flood == (true, true) {
            return;
        }
        match self.driver.set_port_flood(port, flood.0, flood.1).await {
            Ok(()) => {
                if prev != Some(flood) {
                    info!(
                        domain = %self.domain, port = %port, flood = flood.0 && flood.1,
                        unicast = flood.0, bum = flood.1, "segment port flooding set"
                    );
                }
                g.es_flood.insert(port.to_string(), flood);
            }
            Err(e) => {
                debug!(domain = %self.domain, port = %port, error = %e, "could not set port flooding yet, retrying");
                g.es_flood.remove(port);
            }
        }
    }

    /// Writes one segment port's local-bias egress filters; `false` (with a
    /// warning, once) leaves the port on DF-only flooding.
    async fn apply_segment_filter(
        &self,
        g: &mut Inner,
        port: &str,
        bit: u16,
        df_filter: bool,
        heal: bool,
    ) -> bool {
        if !heal && g.es_filter.get(port) == Some(&(bit, df_filter)) {
            return true;
        }
        match self.driver.set_segment_filter(port, bit, df_filter).await {
            Ok(()) => {
                if g.es_filter.insert(port.to_string(), (bit, df_filter)) != Some((bit, df_filter))
                {
                    info!(domain = %self.domain, port = %port, df_filter, "segment filter set");
                }
                true
            }
            Err(e) => {
                g.es_filter.remove(port);
                if g.bias_warned.insert(port.to_string()) {
                    warn!(domain = %self.domain, port = %port, error = %e, "local bias unavailable, df-only flooding");
                } else {
                    debug!(domain = %self.domain, port = %port, error = %e, "local bias filter not set yet, retrying");
                }
                false
            }
        }
    }

    /// Writes the ingress marking for `peers`; `false` leaves every segment
    /// port on DF-only flooding. Re-asserted on every call (the VXLAN device
    /// may have been recreated); an empty set removes it.
    async fn apply_local_bias(
        &self,
        g: &mut Inner,
        vni: u32,
        peers: &BTreeMap<IpAddr, u16>,
        heal: bool,
    ) -> bool {
        if (peers.is_empty() || !heal) && *peers == g.bias_peers {
            return true;
        }
        match self.driver.set_local_bias(vni, peers).await {
            Ok(()) => {
                if *peers != g.bias_peers
                    && let Some(r) = &g.ready
                {
                    info!(
                        domain = %self.domain, vtep = %r.vtep,
                        peers = %join_ips(&peers.keys().copied().collect::<Vec<_>>()),
                        segments = %format!("{:#06x}", peers.values().fold(0u16, |a, b| a | b)),
                        "local bias set"
                    );
                }
                g.bias_peers.clone_from(peers);
                true
            }
            Err(e) => {
                g.bias_peers.clear();
                debug!(domain = %self.domain, error = %e, "local bias marking not set yet, retrying");
                // Only a port that has none yet needs the warning: the one
                // `apply_segment_filter` gives is for its own filters.
                if !peers.is_empty() && g.bias_warned.insert(String::new()) {
                    warn!(domain = %self.domain, error = %e, "local bias unavailable, df-only flooding");
                }
                false
            }
        }
    }

    /// Applies the forwarding state of one segment port (single-active blocks
    /// a non-DF outright). Forwarding is the kernel default, so it is only
    /// asserted when the port was blocked before.
    async fn apply_port_forwarding(&self, g: &mut Inner, port: &str, forwarding: bool) {
        let prev = g.es_fwd.get(port).copied();
        if forwarding && prev != Some(false) {
            return;
        }
        match self.driver.set_port_forwarding(port, forwarding).await {
            Ok(()) => {
                if prev != Some(forwarding) {
                    info!(domain = %self.domain, port = %port, forwarding, "segment port forwarding set");
                }
                g.es_fwd.insert(port.to_string(), forwarding);
            }
            Err(e) => {
                debug!(domain = %self.domain, port = %port, error = %e, "could not set port forwarding yet, retrying");
                g.es_fwd.remove(port);
            }
        }
    }

    /// One `PushEvpnRoutes` from `nos-bgpd`.
    pub async fn apply_push(&self, update: EvpnUpdate) {
        let mut g = self.inner.lock().await;
        let keys: Vec<EvpnKey> = match update {
            EvpnUpdate::Full(routes) => {
                let new: HashMap<EvpnKey, EvpnRoute> =
                    routes.into_iter().map(|r| (r.key.clone(), r)).collect();
                let old = std::mem::replace(&mut g.received, new);
                old.into_keys().chain(g.received.keys().cloned()).collect()
            }
            EvpnUpdate::Add(r) => {
                let k = r.key.clone();
                g.received.insert(k.clone(), r);
                vec![k]
            }
            EvpnUpdate::Remove(k) => {
                g.received.remove(&k);
                vec![k]
            }
            // Staged by the connection handler (`EvpnUpdate::absorb`).
            EvpnUpdate::FullPart(_) => return,
        };
        let segments_changed = keys.iter().any(|k| {
            matches!(
                k,
                EvpnKey::EthernetSegment { .. } | EvpnKey::EthernetAd { .. }
            )
        });
        let mut keys = keys;
        if segments_changed {
            // A PE's per-ES A-D coming or going re-decides every MAC on that
            // segment at once (mass withdrawal, RFC 7432 §8.2.1); its Type-4
            // can move a single-active segment's backup PE.
            let stale = refresh_ads(&mut g);
            for esi in &stale {
                info!(
                    domain = %self.domain, esi = %format_esi(esi),
                    pes = %g.ads.get(esi).map_or_default(|a| a.pes.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")),
                    "segment per-es a-d changed"
                );
            }
            keys.extend(
                g.received
                    .iter()
                    .filter(|(_, r)| {
                        stale.contains(&r.esi)
                            && matches!(r.key, EvpnKey::Mac { .. } | EvpnKey::MacIp { .. })
                    })
                    .map(|(k, _)| k.clone()),
            );
        }
        self.sync_keys(&mut g, keys).await;
        if segments_changed {
            self.sync_df(&mut g).await;
        }
    }

    /// Syncs `keys` plus every route whose MAC the `max-remote-macs` ceiling
    /// admitted or evicted because of them.
    /// Without a ceiling this is O(keys). With one, only `keys` are re-decided
    /// and `admitted` is moved at its boundary in O(log n) per MAC (a lower
    /// MAC arriving later evicts a higher one: deterministic, arrival-order
    /// independent). Relies on every change that alters a route's `desired`
    /// passing that route in `keys` (`set_ready` passes them all).
    async fn sync_keys(&self, g: &mut Inner, mut keys: Vec<EvpnKey>) {
        let Some(ready) = g.ready.clone() else { return };
        let pins = pinnable(&g.segments);
        if ready.max_remote_macs.is_some() {
            self.update_ceiling(g, &ready, &pins, &mut keys);
        }
        for k in keys {
            self.sync_key(g, &k, &ready, &pins).await;
        }
    }

    /// Re-indexes `keys`' candidate MACs, moves `admitted`, and appends to
    /// `keys` the routes of every MAC that entered or left it.
    fn update_ceiling(
        &self,
        g: &mut Inner,
        ready: &Ready,
        pins: &HashMap<Esi, String>,
        keys: &mut Vec<EvpnKey>,
    ) {
        let n = ready.max_remote_macs.unwrap_or(u32::MAX) as usize;
        let mut vanished = Vec::new();
        let mut appeared = Vec::new();
        for k in keys.iter() {
            let new: BTreeSet<Mac> = g
                .received
                .get(k)
                .map_or_default(|r| desired(ready, r, &g.ads, &g.local, pins))
                .into_iter()
                .filter_map(|i| match i {
                    Installed::Mac { mac, .. } | Installed::MacGroup { mac, .. } => Some(mac),
                    _ => None,
                })
                .collect();
            let old = if new.is_empty() {
                g.cand_by_key.remove(k)
            } else {
                g.cand_by_key.insert(k.clone(), new.clone())
            }
            .unwrap_or_default();
            for m in old.difference(&new) {
                let Some(set) = g.cand.get_mut(m) else {
                    continue;
                };
                set.remove(k);
                if set.is_empty() {
                    g.cand.remove(m);
                    vanished.push(*m);
                }
            }
            for m in new.difference(&old) {
                let set = g.cand.entry(*m).or_default();
                if set.is_empty() {
                    appeared.push(*m);
                }
                set.insert(k.clone());
            }
        }
        let first = g.admitted.is_none();
        let adm = g.admitted.get_or_insert_with(BTreeSet::new);
        let mut moved: BTreeSet<Mac> = BTreeSet::new();
        for m in vanished {
            if adm.remove(&m) {
                moved.insert(m);
            }
        }
        // Admitted is the lowest-n prefix of `cand`: refill from just above
        // its top, then let a newcomer below the top displace it.
        while adm.len() < n {
            let next = match adm.last() {
                Some(top) => g
                    .cand
                    .range((Bound::Excluded(*top), Bound::Unbounded))
                    .next(),
                None => g.cand.iter().next(),
            };
            let Some((m, _)) = next else { break };
            adm.insert(*m);
            moved.insert(*m);
        }
        for m in appeared {
            if g.cand.contains_key(&m) && !adm.contains(&m) && adm.last().is_some_and(|t| m < *t) {
                adm.insert(m);
                moved.insert(m);
            }
        }
        while adm.len() > n {
            if let Some(top) = adm.pop_last() {
                moved.insert(top);
            }
        }
        // A fresh ceiling decides every candidate for the first time.
        if first {
            moved.extend(g.cand.keys().copied());
        }
        for m in &moved {
            if let Some(set) = g.cand.get(m) {
                keys.extend(set.iter().cloned());
            }
        }
        let over = g.cand.len() > n;
        if over && !g.ceiling_warned {
            warn!(domain = %self.domain, max = n, "remote mac ceiling reached");
        }
        g.ceiling_warned = over;
    }

    /// Records what `key` now holds in the kernel, keeping `holders` in step.
    fn set_installed(g: &mut Inner, key: &EvpnKey, now: &[Installed]) {
        let old = if now.is_empty() {
            g.installed.remove(key)
        } else {
            g.installed.insert(key.clone(), now.to_vec())
        };
        for i in old.iter().flatten() {
            if let Some(c) = g.holders.get_mut(i) {
                *c -= 1;
                if *c == 0 {
                    g.holders.remove(i);
                }
            }
        }
        for i in now {
            *g.holders.entry(i.clone()).or_default() += 1;
        }
    }

    /// Brings one route's kernel state in line with `received` + config.
    async fn sync_key(
        &self,
        g: &mut Inner,
        key: &EvpnKey,
        ready: &Ready,
        pins: &HashMap<Esi, String>,
    ) {
        let mut want = g
            .received
            .get(key)
            .map_or_default(|r| desired(ready, r, &g.ads, &g.local, pins));
        if let Some(adm) = &g.admitted {
            want.retain(|i| match i {
                Installed::Mac { mac, .. } | Installed::MacGroup { mac, .. } => adm.contains(mac),
                _ => true,
            });
        }
        let have = g.installed.get(key).cloned().unwrap_or_default();
        if want == have {
            return;
        }
        // `holders` counts `key`'s own occurrences too: another key holds `i`
        // when the count exceeds them.
        let held_elsewhere = |g: &Inner, i: &Installed| {
            g.holders.get(i).copied().unwrap_or(0) as usize
                > have.iter().filter(|h| *h == i).count()
        };
        for h in &have {
            if !want.contains(h) && !held_elsewhere(g, h) {
                self.uninstall(ready, h).await;
            }
        }
        let mut now = Vec::new();
        for w in want {
            // A pin over a MAC the bridge already learned there starts active,
            // so its Type-2 is not withdrawn until the CE goes quiet.
            let active =
                matches!(&w, Installed::SegmentMac { mac, port } if g.local.get(mac) == Some(port));
            if have.contains(&w) || held_elsewhere(g, &w) || self.install(ready, &w, active).await {
                now.push(w);
            }
        }
        Self::set_installed(g, key, &now);
    }

    async fn install(&self, r: &Ready, i: &Installed, active: bool) -> bool {
        let res = match i {
            Installed::Mac { mac, vtep } => self.driver.set_remote_mac(r.vni, *mac, *vtep).await,
            Installed::MacGroup { mac, vteps } => {
                self.driver.set_remote_mac_group(r.vni, *mac, vteps).await
            }
            Installed::Neigh { mac, ip, .. } => self.driver.set_neigh(&r.bridge, *mac, *ip).await,
            Installed::Flood { vtep } => self.driver.add_flood(r.vni, *vtep).await,
            Installed::SegmentMac { mac, port } => {
                self.driver.set_segment_mac(port, *mac, active).await
            }
        };
        match (res, i) {
            (Ok(()), Installed::Mac { mac, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vtep = %vtep, "remote mac installed");
                true
            }
            (Ok(()), Installed::MacGroup { mac, vteps }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vteps = %join_ips(vteps), "remote mac group installed");
                true
            }
            (Ok(()), Installed::Neigh { mac, ip, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), ip = %ip, vtep = %vtep, "remote neighbour installed");
                true
            }
            (Ok(()), Installed::Flood { vtep }) => {
                info!(domain = %self.domain, vtep = %vtep, "flood entry installed");
                true
            }
            (Ok(()), Installed::SegmentMac { mac, port }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), port = %port, "remote mac pinned");
                true
            }
            (Err(e), _) => {
                warn!(domain = %self.domain, error = %e, "failed to program the fdb, retrying");
                false
            }
        }
    }

    async fn uninstall(&self, r: &Ready, i: &Installed) {
        let res = match i {
            Installed::Mac { mac, vtep } => self.driver.del_remote_mac(r.vni, *mac, *vtep).await,
            Installed::MacGroup { mac, .. } => self.driver.del_remote_mac_group(r.vni, *mac).await,
            Installed::Neigh { mac, ip, .. } => self.driver.del_neigh(&r.bridge, *mac, *ip).await,
            Installed::Flood { vtep } => self.driver.del_flood(r.vni, *vtep).await,
            Installed::SegmentMac { mac, port } => self.driver.del_segment_mac(port, *mac).await,
        };
        match (res, i) {
            (Ok(()), Installed::Mac { mac, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vtep = %vtep, "remote mac removed");
            }
            (Ok(()), Installed::MacGroup { mac, vteps }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), vteps = %join_ips(vteps), "remote mac group removed");
            }
            (Ok(()), Installed::Neigh { mac, ip, vtep }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), ip = %ip, vtep = %vtep, "remote neighbour removed");
            }
            (Ok(()), Installed::Flood { vtep }) => {
                info!(domain = %self.domain, vtep = %vtep, "flood entry removed");
            }
            (Ok(()), Installed::SegmentMac { mac, port }) => {
                info!(domain = %self.domain, mac = %format_mac(*mac), port = %port, "remote mac unpinned");
            }
            // Deleting the device already dropped them; nothing left to do.
            (Err(e), _) => debug!(domain = %self.domain, error = %e, "fdb delete failed"),
        }
    }

    /// Re-reads the bridge's local MACs (and, when redistributing arp or
    /// connected, its IP bindings) and publishes any change to the BGP
    /// instance.
    pub async fn refresh_local(&self) {
        let mut g = self.inner.lock().await;
        let Some(r) = g.ready.clone() else { return };
        // Segment carrier first: a down segment withdraws its routes. A failed
        // read counts as up, so a transient netlink error withdraws nothing.
        let mut down = BTreeSet::new();
        for p in &r.es_ports {
            if !self.driver.port_up(&p.port).await.unwrap_or(true) {
                down.insert(p.port.clone());
            }
        }
        if down != g.es_down {
            for p in down.symmetric_difference(&g.es_down) {
                info!(domain = %self.domain, port = %p, up = !down.contains(p), "segment port carrier changed");
            }
            g.es_down = down;
            self.sync_df(&mut g).await;
            self.publish(&g);
        }
        let macs = match self.driver.local_macs(&r.bridge, r.vni).await {
            Ok(m) => m,
            Err(e) => {
                debug!(domain = %self.domain, error = %e, "could not read the bridge fdb");
                return;
            }
        };
        let mut neighbours = BTreeSet::new();
        if r.arp {
            match self.driver.local_neighbours(&r.bridge).await {
                // Only hosts behind a local port: a binding the SVI learned
                // over the VXLAN port belongs to the remote VTEP that
                // originated it, and re-originating it would be wrong.
                Ok(n) => neighbours.extend(n.into_iter().filter(|(m, _)| macs.contains_key(m))),
                Err(e) => {
                    debug!(domain = %self.domain, error = %e, "could not read the bridge neighbours");
                    return;
                }
            }
        }
        if !r.connected.is_empty() {
            match self.driver.bridge_mac(&r.bridge).await {
                Ok(m) => neighbours.extend(r.connected.iter().map(|ip| (m, *ip))),
                Err(e) => {
                    debug!(domain = %self.domain, error = %e, "could not read the bridge mac");
                    return;
                }
            }
        }
        if macs == g.local && neighbours == g.local_neigh {
            return;
        }
        for (m, ip) in neighbours.difference(&g.local_neigh) {
            info!(domain = %self.domain, mac = %format_mac(*m), ip = %ip, "local neighbour learned");
        }
        for (m, ip) in g.local_neigh.difference(&neighbours) {
            info!(domain = %self.domain, mac = %format_mac(*m), ip = %ip, "local neighbour removed");
        }
        g.local_neigh = neighbours;
        for (m, port) in &macs {
            if g.local.get(m) != Some(port) {
                info!(domain = %self.domain, mac = %format_mac(*m), port = %port, "local mac learned");
            }
        }
        for m in g.local.keys().filter(|m| !macs.contains_key(*m)) {
            info!(domain = %self.domain, mac = %format_mac(*m), "local mac removed");
        }
        let moved: BTreeSet<Mac> = macs
            .iter()
            .filter(|(m, p)| g.local.get(*m) != Some(*p))
            .map(|(m, _)| *m)
            .chain(g.local.keys().filter(|m| !macs.contains_key(*m)).copied())
            .collect();
        g.local = macs;
        self.publish(&g);
        // A remote MAC on our segment is not pinned while learned behind
        // another port.
        let keys: Vec<EvpnKey> = g
            .received
            .keys()
            .filter(|k| match k {
                EvpnKey::Mac { mac, .. } | EvpnKey::MacIp { mac, .. } => moved.contains(mac),
                _ => false,
            })
            .cloned()
            .collect();
        self.sync_keys(&mut g, keys).await;
    }

    /// The local-MAC loop: a kernel FDB notification (debounced) or the tick
    /// triggers a re-read. Runs until `shutdown`.
    pub async fn run_local(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut wake = self.driver.watch_neigh();
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut df_deadline = self.df_deadline.subscribe();
        loop {
            let df_at = *df_deadline.borrow_and_update();
            tokio::select! {
                ev = recv_opt(&mut wake) => {
                    if ev.is_none() {
                        wake = None; // feed died: the tick alone from here
                        continue;
                    }
                    tokio::time::sleep(DEBOUNCE).await;
                    if let Some(rx) = wake.as_mut() {
                        while rx.try_recv().is_ok() {}
                    }
                }
                _ = tick.tick() => {}
                // A DF wait timer ended: elect now rather than at the tick.
                () = sleep_until_opt(df_at) => {
                    let mut g = self.inner.lock().await;
                    self.sync_df(&mut g).await;
                    continue;
                }
                _ = df_deadline.changed() => continue,
                _ = shutdown.changed() => break,
            }
            self.refresh_local().await;
        }
    }

    /// `GetMacs`: what this domain's FDB currently holds. A `Local` MAC's age
    /// is read from the kernel per query, never stored.
    pub async fn table(&self) -> FdbTable {
        let g = self.inner.lock().await;
        let ages = match &g.ready {
            Some(r) => self
                .driver
                .local_mac_ages(&r.bridge, r.vni)
                .await
                .unwrap_or_else(|e| {
                    debug!(domain = %self.domain, error = %e, "could not read the mac ages");
                    BTreeMap::new()
                }),
            None => BTreeMap::new(),
        };
        let mut macs: Vec<MacEntry> = g
            .local
            .iter()
            .map(|(m, port)| MacEntry {
                mac: format_mac(*m),
                source: MacSource::Local,
                vtep: None,
                vteps: Vec::new(),
                esi: g
                    .ready
                    .as_ref()
                    .map(|r| esi_of(r, Some(port)))
                    .filter(|e| *e != [0; 10])
                    .map(|e| format_esi(&e)),
                interface: Some(port.clone()).filter(|p| !p.is_empty()),
                age_secs: ages.get(m).copied(),
            })
            .collect();
        let mut neighbours: Vec<NeighEntry> = g
            .local_neigh
            .iter()
            .map(|(m, ip)| NeighEntry {
                ip: *ip,
                mac: format_mac(*m),
                source: MacSource::Local,
                vtep: None,
            })
            .collect();
        let mut flood = Vec::new();
        // Several routes can hold one entry; list it once.
        let mut items: Vec<&Installed> = Vec::new();
        for i in g.installed.values().flatten() {
            if !items.contains(&i) {
                items.push(i);
            }
        }
        for i in items {
            match i {
                Installed::Mac { mac, vtep } => macs.push(MacEntry {
                    mac: format_mac(*mac),
                    source: MacSource::Remote,
                    vtep: Some(*vtep),
                    vteps: vec![*vtep],
                    esi: None,
                    interface: None,
                    age_secs: None,
                }),
                Installed::MacGroup { mac, vteps } => macs.push(MacEntry {
                    mac: format_mac(*mac),
                    source: MacSource::Remote,
                    vtep: vteps.first().copied(),
                    vteps: vteps.clone(),
                    esi: None,
                    interface: None,
                    age_secs: None,
                }),
                Installed::Neigh { mac, ip, vtep } => neighbours.push(NeighEntry {
                    ip: *ip,
                    mac: format_mac(*mac),
                    source: MacSource::Remote,
                    vtep: Some(*vtep),
                }),
                Installed::Flood { vtep } => flood.push(*vtep),
                // Behind our own segment port: no VTEP.
                Installed::SegmentMac { mac, port } => macs.push(MacEntry {
                    mac: format_mac(*mac),
                    source: MacSource::Remote,
                    vtep: None,
                    vteps: Vec::new(),
                    esi: g.ready.as_ref().map(|r| format_esi(&esi_of(r, Some(port)))),
                    interface: Some(port.clone()),
                    age_secs: None,
                }),
            }
        }
        macs.sort_by(|a, b| a.mac.cmp(&b.mac));
        neighbours.sort_by(|a, b| (a.ip, &a.mac).cmp(&(b.ip, &b.mac)));
        flood.sort();
        FdbTable {
            domain: self.domain.clone(),
            vni: g.ready.as_ref().map_or(0, |r| r.vni),
            bridge: g.ready.as_ref().map(|r| r.bridge.clone()),
            vxlan: g.ready.as_ref().map(|r| vxlan_name(r.vni)),
            macs,
            neighbours,
            flood,
            segments: g
                .segments
                .iter()
                .map(|s| EsEntry {
                    esi: format_esi(&s.esi),
                    port: s.port.clone(),
                    designated_forwarder: s.df && !s.waiting,
                    pes: s.pes.clone(),
                    ad_pes: s.ad_pes.clone(),
                    up: s.up,
                    single_active: s.single_active,
                    df_algorithm: s.algorithm,
                    local_bias: g.es_bias.contains(&s.port),
                })
                .collect(),
            neigh_suppress: g.neigh_suppress,
        }
    }
}

async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(at) => sleep_until(at).await,
        None => pending().await,
    }
}

async fn recv_opt(rx: &mut Option<mpsc::Receiver<()>>) -> Option<()> {
    match rx {
        Some(rx) => rx.recv().await,
        None => pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;

    use super::*;
    use crate::driver::DriverError;

    const RT: u64 = 0x0002_fde8_0000_2774;
    const VTEP: &str = "192.0.2.1";
    const REMOTE: &str = "192.0.2.9";

    fn ready() -> Ready {
        Ready {
            vni: 10100,
            bridge: "br1".to_string(),
            vtep: VTEP.parse().unwrap(),
            underlay: "eth0".to_string(),
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
            rt_import: vec![RT],
            rt_export: vec![RT],
            bgp_instance: "r1".to_string(),
            arp: false,
            connected: Vec::new(),
            es_ports: Vec::new(),
            neigh_suppress: false,
            max_remote_macs: None,
            irb: None,
        }
    }

    const ESI: Esi = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    fn ready_with_segment() -> Ready {
        Ready {
            es_ports: vec![EsPort {
                // The `Recorder` driver puts every local MAC behind `eth1`.
                port: "eth1".to_string(),
                esi: ESI,
                single_active: false,
                df_algorithm: DfAlgorithm::Modulo,
            }],
            ..ready()
        }
    }

    fn ready_single_active() -> Ready {
        let mut r = ready_with_segment();
        r.es_ports[0].single_active = true;
        r
    }

    /// The A-D index entry for a segment whose PEs' per-ES routes are held.
    fn ads_of(esi: Esi, pes: &[&str]) -> Ads {
        Ads::from([(
            esi,
            SegmentAds {
                pes: pes.iter().map(|p| p.parse().unwrap()).collect(),
                ..SegmentAds::default()
            },
        )])
    }

    /// `desired` with no per-ES A-D held.
    fn want(r: &Ready, route: &EvpnRoute) -> Vec<Installed> {
        desired(r, route, &Ads::new(), &BTreeMap::new(), &HashMap::new())
    }

    /// `desired` with these A-D routes, nothing local and no pinnable port.
    fn want_ads(r: &Ready, route: &EvpnRoute, ads: &Ads) -> Vec<Installed> {
        desired(r, route, ads, &BTreeMap::new(), &HashMap::new())
    }

    fn macip_route(mac: u8, ip: &str, vni: u32, rt: u64, next_hop: &str) -> EvpnRoute {
        EvpnRoute {
            key: EvpnKey::MacIp {
                rd: [0; 8],
                mac: [0, 0, 0, 0, 0, mac],
                ip: ip.parse().unwrap(),
            },
            vni,
            next_hop: next_hop.parse().unwrap(),
            ext_communities: vec![rt],
            esi: [0; 10],
            l3_vni: None,
        }
    }

    fn mac_route(mac: u8, vni: u32, rt: u64, next_hop: &str) -> EvpnRoute {
        EvpnRoute {
            key: EvpnKey::Mac {
                rd: [0; 8],
                mac: [0, 0, 0, 0, 0, mac],
            },
            vni,
            next_hop: next_hop.parse().unwrap(),
            ext_communities: vec![rt],
            esi: [0; 10],
            l3_vni: None,
        }
    }

    fn imet_route(origin: &str, rt: u64) -> EvpnRoute {
        EvpnRoute {
            key: EvpnKey::Imet {
                rd: [0; 8],
                origin: origin.parse().unwrap(),
            },
            vni: 0,
            next_hop: origin.parse().unwrap(),
            ext_communities: vec![rt],
            esi: [0; 10],
            l3_vni: None,
        }
    }

    #[test]
    fn only_matching_foreign_routes_are_wanted() {
        let r = ready();
        assert_ne!(want(&r, &mac_route(1, 10100, RT, REMOTE)), []);
        assert!(
            want(&r, &mac_route(1, 10100, 1, REMOTE)).is_empty(),
            "wrong RT"
        );
        assert!(
            want(&r, &mac_route(1, 999, RT, REMOTE)).is_empty(),
            "wrong VNI"
        );
        assert!(
            want(&r, &mac_route(1, 10100, RT, VTEP)).is_empty(),
            "our own"
        );
        assert_eq!(
            want(&r, &imet_route(REMOTE, RT)),
            vec![Installed::Flood {
                vtep: REMOTE.parse().unwrap()
            }]
        );
        assert_eq!(want(&r, &imet_route(VTEP, RT)), []);
    }

    #[test]
    fn a_type2_with_an_ip_is_an_fdb_entry_and_a_neighbour() {
        let r = ready();
        let vtep: IpAddr = REMOTE.parse().unwrap();
        assert_eq!(
            want(&r, &macip_route(1, "198.51.100.7", 10100, RT, REMOTE)),
            vec![
                Installed::Mac {
                    mac: [0, 0, 0, 0, 0, 1],
                    vtep
                },
                Installed::Neigh {
                    mac: [0, 0, 0, 0, 0, 1],
                    ip: "198.51.100.7".parse().unwrap(),
                    vtep
                }
            ]
        );
        // The same filters as a MAC-only route, and no link-local neighbour.
        assert_eq!(
            want(&r, &macip_route(1, "198.51.100.7", 10100, 1, REMOTE)),
            []
        );
        assert_eq!(
            want(&r, &macip_route(1, "198.51.100.7", 10100, RT, VTEP)),
            []
        );
        assert_eq!(
            want(&r, &macip_route(1, "fe80::1", 10100, RT, REMOTE)).len(),
            1
        );
    }

    #[test]
    fn local_routes_are_a_type3_plus_a_type2_per_mac_with_rt_and_encap() {
        let macs = BTreeMap::from([
            ([0, 0, 0, 0, 0, 1], "eth1".to_string()),
            ([0, 0, 0, 0, 0, 2], "eth1".to_string()),
        ]);
        let routes = local_routes(&ready(), &macs, &BTreeSet::new(), &BTreeSet::new());
        assert_eq!(routes.len(), 3);
        let r = routes.values().next().unwrap();
        assert_eq!(r.next_hop, VTEP.parse::<IpAddr>().unwrap());
        assert_eq!(r.ext_communities, vec![RT, ENCAP_VXLAN]);
    }

    #[test]
    fn neighbours_add_one_type2_with_the_ip_each() {
        let neighbours = BTreeSet::from([([0, 0, 0, 0, 0, 1], "198.51.100.7".parse().unwrap())]);
        let routes = local_routes(&ready(), &BTreeMap::new(), &neighbours, &BTreeSet::new());
        assert_eq!(routes.len(), 2, "the Type-3 and the MAC+IP");
        assert!(routes
            .keys()
            .any(|k| matches!(k, EvpnKey::MacIp { ip, .. } if ip.to_string() == "198.51.100.7")));
    }

    const IP_VRF_RT: u64 = 0x0002_fde8_0000_1388;

    fn irb() -> EvpnIrb {
        EvpnIrb {
            l3_vni: 5000,
            router_mac: [2, 0, 0, 0, 0, 0xaa],
            route_targets_export: vec![IP_VRF_RT],
        }
    }

    /// RFC 9135 §5.1: a host's MAC+IP gets Label2, the IP-VRF RT and the
    /// Router's MAC; the SVI gateway and the MAC-only routes don't.
    #[test]
    fn symmetric_irb_marks_only_host_mac_ip_routes() {
        let host: IpAddr = "198.51.100.7".parse().unwrap();
        let gw: IpAddr = "198.51.100.1".parse().unwrap();
        let r = Ready {
            connected: vec![gw],
            irb: Some(irb()),
            ..ready()
        };
        let macs = BTreeMap::from([([0, 0, 0, 0, 0, 1], "eth1".to_string())]);
        let neighbours = BTreeSet::from([([0, 0, 0, 0, 0, 1], host), ([0, 0, 0, 0, 0, 0xfe], gw)]);
        let routes = local_routes(&r, &macs, &neighbours, &BTreeSet::new());
        let symmetric: Vec<_> = routes.values().filter(|r| r.l3_vni.is_some()).collect();
        assert_eq!(symmetric.len(), 1, "{routes:?}");
        assert!(matches!(symmetric[0].key, EvpnKey::MacIp { ip, .. } if ip == host));
        assert_eq!(symmetric[0].l3_vni, Some(5000));
        assert_eq!(
            symmetric[0].ext_communities,
            vec![
                RT,
                ENCAP_VXLAN,
                IP_VRF_RT,
                router_mac_ext([2, 0, 0, 0, 0, 0xaa])
            ]
        );
        assert!(routes
            .values()
            .filter(|r| r.l3_vni.is_none())
            .all(|r| !r.ext_communities.contains(&IP_VRF_RT)));
    }

    /// An IRB-only change re-publishes the local routes and uninstalls nothing.
    #[tokio::test]
    async fn an_irb_change_is_applied_in_place() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(Ready {
            arp: true,
            ..ready()
        }))
        .await;
        fdb.apply_push(EvpnUpdate::Add(mac_route(1, 10100, RT, REMOTE)))
            .await;
        fdb.refresh_local().await;
        calls(&driver);
        let rx = fdb.subscribe();
        let before = rx.borrow().routes.clone();
        assert!(before.values().all(|r| r.l3_vni.is_none()));

        fdb.set_ready(Some(Ready {
            arp: true,
            irb: Some(irb()),
            ..ready()
        }))
        .await;
        assert_eq!(calls(&driver), ["ensure 10100"]);
        let after = rx.borrow().routes.clone();
        assert!(after.values().any(|r| r.l3_vni == Some(5000)), "{after:?}");
        assert_eq!(before.len(), after.len());
    }

    /// Records every driver call; the second field is the ports with no
    /// carrier, the third makes the local-bias setup fail.
    #[derive(Default)]
    struct Recorder(
        StdMutex<Vec<String>>,
        StdMutex<BTreeSet<String>>,
        std::sync::atomic::AtomicBool,
    );

    #[async_trait]
    impl FdbDriver for Recorder {
        async fn ensure_vxlan(
            &self,
            vni: u32,
            _: IpAddr,
            _: &str,
            _: &str,
            _: bool,
        ) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("ensure {vni}"));
            Ok(())
        }
        async fn remove_vxlan(&self, vni: u32) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("remove {vni}"));
            Ok(())
        }
        async fn set_remote_mac(&self, _: u32, m: Mac, v: IpAddr) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("set {} {v}", format_mac(m)));
            Ok(())
        }
        async fn del_remote_mac(&self, _: u32, m: Mac, v: IpAddr) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("del {} {v}", format_mac(m)));
            Ok(())
        }
        async fn set_remote_mac_group(
            &self,
            _: u32,
            m: Mac,
            v: &[IpAddr],
        ) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("group {} {}", format_mac(m), join_ips(v)));
            Ok(())
        }
        async fn del_remote_mac_group(&self, _: u32, m: Mac) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("group- {}", format_mac(m)));
            Ok(())
        }
        async fn set_segment_mac(
            &self,
            port: &str,
            m: Mac,
            active: bool,
        ) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("pin {port} {} {active}", format_mac(m)));
            Ok(())
        }
        async fn del_segment_mac(&self, port: &str, m: Mac) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("unpin {port} {}", format_mac(m)));
            Ok(())
        }
        async fn add_flood(&self, _: u32, v: IpAddr) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("flood+ {v}"));
            Ok(())
        }
        async fn del_flood(&self, _: u32, v: IpAddr) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("flood- {v}"));
            Ok(())
        }
        async fn local_macs(&self, _: &str, _: u32) -> Result<BTreeMap<Mac, String>, DriverError> {
            Ok(BTreeMap::from([([0, 0, 0, 0, 0, 7], "eth1".to_string())]))
        }
        async fn local_mac_ages(&self, _: &str, _: u32) -> Result<BTreeMap<Mac, u32>, DriverError> {
            Ok(BTreeMap::from([([0, 0, 0, 0, 0, 7], 12)]))
        }
        async fn set_port_flood(
            &self,
            port: &str,
            unicast: bool,
            bum: bool,
        ) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("flood {port} uni={unicast} bum={bum}"));
            Ok(())
        }
        async fn set_segment_filter(
            &self,
            port: &str,
            bit: u16,
            df: bool,
        ) -> Result<(), DriverError> {
            if self.2.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(DriverError::Other("no cls_fw".to_string()));
            }
            self.0
                .lock()
                .unwrap()
                .push(format!("filter {port} bit={bit} df={df}"));
            Ok(())
        }
        async fn clear_segment_filter(&self, port: &str) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("unfilter {port}"));
            Ok(())
        }
        async fn set_local_bias(
            &self,
            vni: u32,
            peers: &BTreeMap<IpAddr, u16>,
        ) -> Result<(), DriverError> {
            if self.2.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(DriverError::Other("no cls_flower".to_string()));
            }
            let peers = peers
                .iter()
                .map(|(p, b)| format!("{p}={b}"))
                .collect::<Vec<_>>()
                .join(",");
            self.0.lock().unwrap().push(format!("bias {vni} {peers}"));
            Ok(())
        }
        async fn set_port_forwarding(&self, port: &str, fwd: bool) -> Result<(), DriverError> {
            self.0.lock().unwrap().push(format!("fwd {port} {fwd}"));
            Ok(())
        }
        async fn port_up(&self, port: &str) -> Result<bool, DriverError> {
            Ok(!self.1.lock().unwrap().contains(port))
        }
        async fn local_neighbours(&self, _: &str) -> Result<BTreeSet<(Mac, IpAddr)>, DriverError> {
            // One host behind a local port, one only reachable over VXLAN.
            Ok(BTreeSet::from([
                ([0, 0, 0, 0, 0, 7], "198.51.100.7".parse().unwrap()),
                ([0, 0, 0, 0, 0, 8], "198.51.100.8".parse().unwrap()),
            ]))
        }
        async fn bridge_mac(&self, _: &str) -> Result<Mac, DriverError> {
            Ok([0, 0, 0, 0, 0, 0xfe])
        }
        async fn set_neigh(&self, _: &str, m: Mac, ip: IpAddr) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("neigh+ {} {ip}", format_mac(m)));
            Ok(())
        }
        async fn del_neigh(&self, _: &str, m: Mac, ip: IpAddr) -> Result<(), DriverError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("neigh- {} {ip}", format_mac(m)));
            Ok(())
        }
        fn watch_neigh(&self) -> Option<mpsc::Receiver<()>> {
            None
        }
    }

    fn calls(d: &Recorder) -> Vec<String> {
        std::mem::take(&mut *d.0.lock().unwrap())
    }

    #[test]
    fn type4_counts_for_any_esi_with_its_es_import_rt_and_never_our_own() {
        let other: Esi = [9; 10];
        let mut received = HashMap::new();
        for route in [
            es_route(ESI, "192.0.2.20"),
            es_route(other, "192.0.2.21"),
            // Not its ESI's ES-Import RT.
            EvpnRoute {
                ext_communities: vec![1],
                ..es_route(ESI, "192.0.2.22")
            },
            // Our own.
            es_route(ESI, VTEP),
        ] {
            received.insert(route.key.clone(), route);
        }
        let pes = |ads: &Ads, e: Esi| {
            ads[&e]
                .es_pes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        };
        // Attached or not, the same.
        for r in [ready_with_segment(), ready()] {
            let ads = ad_index(&r, &received);
            assert_eq!(ads.len(), 2);
            assert_eq!(pes(&ads, ESI), ["192.0.2.20"]);
            assert_eq!(pes(&ads, other), ["192.0.2.21"]);
        }
    }

    #[test]
    fn a_remote_single_active_segment_backup_follows_its_type4s_without_an_attachment() {
        // No `es_ports`: the segment is not ours. Backups .22 .23 .24 and VNI
        // 10100 % 3 == 2: the elected one is .24, not the lowest (.22).
        let r = ready();
        let mut received = HashMap::new();
        let mut routes = Vec::new();
        for pe in ["192.0.2.22", "192.0.2.23", "192.0.2.24"] {
            routes.push(es_route(ESI, pe));
            routes.push(es_ad(ESI, pe));
            routes.push(evi_ad(ESI, pe));
        }
        for route in routes {
            received.insert(route.key.clone(), route);
        }
        let mut ads = ad_index(&r, &received);
        ads.get_mut(&ESI).unwrap().single_active = true;
        let mut route = mac_route(1, 10100, RT, REMOTE);
        route.esi = ESI;
        let backup = |ads: &Ads| match want_ads(&r, &route, ads)[..] {
            [Installed::Mac { vtep, .. }] => vtep.to_string(),
            ref other => panic!("{other:?}"),
        };
        // The primary (REMOTE) has lost its per-ES A-D.
        assert_eq!(backup(&ads), "192.0.2.24");
        // Without the Type-4s it is the lowest address.
        received.retain(|k, _| !matches!(k, EvpnKey::EthernetSegment { .. }));
        let mut ads = ad_index(&r, &received);
        ads.get_mut(&ESI).unwrap().single_active = true;
        assert_eq!(backup(&ads), "192.0.2.22");
    }

    #[test]
    fn a_foreign_type4_does_not_change_an_attached_segments_election() {
        let base = vec![es_route(ESI, REMOTE), evi_ad(ESI, REMOTE)];
        let mut with_foreign = base.clone();
        with_foreign.push(es_route([9; 10], "192.0.2.50"));
        let a = plan_one(DfAlgorithm::Modulo, base);
        let b = plan_one(DfAlgorithm::Modulo, with_foreign);
        assert_eq!((a.df, a.pes), (b.df, b.pes));
    }

    /// The remote MACs `calls` shows as installed (`set`) minus removed (`del`).
    fn live(calls: &[String]) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for c in calls {
            match c.split_once(' ') {
                Some(("set", r)) => out.insert(r.to_string()),
                Some(("del", r)) => out.remove(r),
                _ => false,
            };
        }
        out
    }

    #[tokio::test]
    async fn max_remote_macs_keeps_the_lowest_whatever_the_arrival_order() {
        for order in [[1u8, 2], [2, 1]] {
            let driver = Arc::new(Recorder::default());
            let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
            fdb.set_ready(Some(Ready {
                max_remote_macs: Some(1),
                ..ready()
            }))
            .await;
            let mut all = Vec::new();
            for m in order {
                fdb.apply_push(EvpnUpdate::Add(mac_route(m, 10100, RT, REMOTE)))
                    .await;
                all.extend(calls(&driver));
            }
            assert_eq!(
                live(&all),
                BTreeSet::from([format!("{} {REMOTE}", format_mac([0, 0, 0, 0, 0, 1]))]),
                "{order:?}"
            );
        }
    }

    #[tokio::test]
    async fn max_remote_macs_admits_the_next_on_withdraw_and_lifts_in_place() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        let capped = Ready {
            max_remote_macs: Some(1),
            ..ready()
        };
        fdb.set_ready(Some(capped.clone())).await;
        for m in [1, 2] {
            fdb.apply_push(EvpnUpdate::Add(mac_route(m, 10100, RT, REMOTE)))
                .await;
        }
        let mut all = calls(&driver);
        let mac = |m: u8| format!("{} {REMOTE}", format_mac([0, 0, 0, 0, 0, m]));
        fdb.apply_push(EvpnUpdate::Remove(mac_route(1, 10100, RT, REMOTE).key))
            .await;
        all.extend(calls(&driver));
        assert_eq!(live(&all), BTreeSet::from([mac(2)]));
        // Back under the ceiling the warning flag resets; lifting it installs all.
        fdb.apply_push(EvpnUpdate::Add(mac_route(1, 10100, RT, REMOTE)))
            .await;
        fdb.set_ready(Some(ready())).await;
        all.extend(calls(&driver));
        assert_eq!(live(&all), BTreeSet::from([mac(1), mac(2)]));
    }

    /// #604: without a ceiling a push re-decides only its own route, never all
    /// of `received`.
    #[tokio::test]
    async fn a_push_without_a_ceiling_decides_only_its_own_route() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver, Duration::ZERO);
        fdb.set_ready(Some(ready())).await;
        let n = 2000u32;
        let route = |i: u32| {
            let mut r = mac_route(0, 10100, RT, REMOTE);
            r.key = EvpnKey::Mac {
                rd: [0; 8],
                mac: [0, 0, 0, 0, i.to_be_bytes()[2], i.to_be_bytes()[3]],
            };
            r
        };
        let before = DESIRED_CALLS.with(std::cell::Cell::get);
        for i in 0..n {
            fdb.apply_push(EvpnUpdate::Add(route(i))).await;
        }
        for i in 0..n {
            fdb.apply_push(EvpnUpdate::Remove(route(i).key)).await;
        }
        let calls = DESIRED_CALLS.with(std::cell::Cell::get) - before;
        assert!(calls <= 2 * n as usize, "{calls} desired calls");
        assert!(fdb.inner.lock().await.holders.is_empty());
    }

    #[tokio::test]
    async fn an_item_two_routes_share_goes_with_the_second_withdrawal() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready())).await;
        let a = mac_route(1, 10100, RT, REMOTE);
        let mut b = a.clone();
        b.key = EvpnKey::Mac {
            rd: [0, 0, 0, 0, 0, 0, 0, 7],
            mac: [0, 0, 0, 0, 0, 1],
        };
        for r in [&a, &b] {
            fdb.apply_push(EvpnUpdate::Add(r.clone())).await;
        }
        let mut all = calls(&driver);
        fdb.apply_push(EvpnUpdate::Remove(a.key.clone())).await;
        all.extend(calls(&driver));
        assert_eq!(live(&all).len(), 1, "{all:?}");
        fdb.apply_push(EvpnUpdate::Remove(b.key.clone())).await;
        all.extend(calls(&driver));
        assert!(live(&all).is_empty(), "{all:?}");
    }

    /// The incremental ceiling equals "the lowest N candidates" after any
    /// sequence of adds and withdrawals.
    #[tokio::test]
    async fn the_incremental_ceiling_matches_the_lowest_n() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        let capped = |n| Ready {
            max_remote_macs: Some(n),
            ..ready()
        };
        fdb.set_ready(Some(capped(3))).await;
        let mut present = BTreeSet::new();
        let mut all = Vec::new();
        let mut x = 12345u32;
        for step in 0..300 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let m = ((x >> 16) % 12) as u8 + 1;
            if (x >> 8) & 1 == 0 {
                present.insert(m);
                fdb.apply_push(EvpnUpdate::Add(mac_route(m, 10100, RT, REMOTE)))
                    .await;
            } else {
                present.remove(&m);
                fdb.apply_push(EvpnUpdate::Remove(mac_route(m, 10100, RT, REMOTE).key))
                    .await;
            }
            // A ceiling change or lift now and then.
            let n = match step {
                100 => Some(5),
                200 => Some(1),
                _ => None,
            };
            if let Some(n) = n {
                fdb.set_ready(Some(capped(n))).await;
            }
            all.extend(calls(&driver));
            let cap = match step {
                0..=99 => 3,
                100..=199 => 5,
                _ => 1,
            };
            let want: BTreeSet<String> = present
                .iter()
                .take(cap)
                .map(|m| format!("{} {REMOTE}", format_mac([0, 0, 0, 0, 0, *m])))
                .collect();
            assert_eq!(live(&all), want, "step {step}");
        }
        fdb.set_ready(Some(ready())).await;
        all.extend(calls(&driver));
        assert_eq!(live(&all).len(), present.len());
    }

    #[tokio::test]
    async fn neigh_suppress_is_applied_in_place_and_reported() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready())).await;
        fdb.apply_push(EvpnUpdate::Add(mac_route(1, 10100, RT, REMOTE)))
            .await;
        calls(&driver);
        assert!(!fdb.table().await.neigh_suppress);

        // A toggle doesn't tear down what's installed: only `ensure_vxlan` runs.
        let on = Ready {
            neigh_suppress: true,
            ..ready()
        };
        fdb.set_ready(Some(on)).await;
        assert_eq!(calls(&driver), ["ensure 10100"]);
        assert!(fdb.table().await.neigh_suppress);

        fdb.set_ready(None).await;
        assert!(!fdb.table().await.neigh_suppress);
    }

    #[tokio::test]
    async fn pushes_program_the_kernel_by_delta_and_survive_reconfiguration() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready())).await;
        assert_eq!(calls(&driver), ["ensure 10100"]);

        fdb.apply_push(EvpnUpdate::Add(mac_route(1, 10100, RT, REMOTE)))
            .await;
        fdb.apply_push(EvpnUpdate::Add(imet_route(REMOTE, RT)))
            .await;
        fdb.apply_push(EvpnUpdate::Add(mac_route(2, 10100, 1, REMOTE)))
            .await; // wrong RT
        assert_eq!(
            calls(&driver),
            ["set 00:00:00:00:00:01 192.0.2.9", "flood+ 192.0.2.9"]
        );
        // An identical re-push is not reprogrammed; a moved MAC is.
        fdb.apply_push(EvpnUpdate::Add(mac_route(1, 10100, RT, REMOTE)))
            .await;
        assert_eq!(calls(&driver), [] as [String; 0]);
        fdb.apply_push(EvpnUpdate::Add(mac_route(1, 10100, RT, "192.0.2.10")))
            .await;
        assert_eq!(
            calls(&driver),
            [
                "del 00:00:00:00:00:01 192.0.2.9",
                "set 00:00:00:00:00:01 192.0.2.10"
            ]
        );
        let table = fdb.table().await;
        assert_eq!(table.macs.len(), 1);
        assert_eq!(table.flood, vec![REMOTE.parse::<IpAddr>().unwrap()]);

        // A `Full` that drops both withdraws both.
        fdb.apply_push(EvpnUpdate::Full(vec![])).await;
        let mut c = calls(&driver);
        c.sort();
        assert_eq!(c, ["del 00:00:00:00:00:01 192.0.2.10", "flood- 192.0.2.9"]);

        // Unconfiguring removes the device.
        fdb.set_ready(None).await;
        assert_eq!(calls(&driver), ["remove 10100"]);
    }

    #[tokio::test]
    async fn a_mac_shared_by_two_routes_is_removed_only_with_the_last() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready())).await;
        calls(&driver);

        // MAC-only first, then the MAC+IP route for the same MAC.
        fdb.apply_push(EvpnUpdate::Add(mac_route(1, 10100, RT, REMOTE)))
            .await;
        fdb.apply_push(EvpnUpdate::Add(macip_route(
            1,
            "198.51.100.7",
            10100,
            RT,
            REMOTE,
        )))
        .await;
        assert_eq!(
            calls(&driver),
            [
                "set 00:00:00:00:00:01 192.0.2.9",
                "neigh+ 00:00:00:00:00:01 198.51.100.7"
            ],
            "the MAC is programmed once"
        );
        let t = fdb.table().await;
        assert_eq!((t.macs.len(), t.neighbours.len()), (1, 1));

        // Withdrawing the MAC-only route keeps the MAC (the other still names it).
        let k = mac_route(1, 10100, RT, REMOTE).key;
        fdb.apply_push(EvpnUpdate::Remove(k)).await;
        assert_eq!(calls(&driver), [] as [String; 0]);
        // Withdrawing the last one removes both.
        let k = macip_route(1, "198.51.100.7", 10100, RT, REMOTE).key;
        fdb.apply_push(EvpnUpdate::Remove(k)).await;
        let mut c = calls(&driver);
        c.sort();
        assert_eq!(
            c,
            [
                "del 00:00:00:00:00:01 192.0.2.9",
                "neigh- 00:00:00:00:00:01 198.51.100.7"
            ]
        );
    }

    #[tokio::test]
    async fn arp_and_connected_originate_type2_with_ip() {
        let fdb = Fdb::new(
            "bd1".to_string(),
            Arc::new(Recorder::default()),
            Duration::ZERO,
        );
        let mut rx = fdb.subscribe();
        let mut r = ready();
        r.arp = true;
        r.connected = vec!["203.0.113.1".parse().unwrap()];
        fdb.set_ready(Some(r)).await;
        fdb.refresh_local().await;
        let t = rx.borrow_and_update().clone();
        // Type-3, the local MAC 7, MAC+IP for host 7 (host 8 is not behind a
        // local port) and MAC+IP for the SVI with the bridge's own MAC.
        assert_eq!(t.routes.len(), 4);
        let svi = t
            .routes
            .iter()
            .find(|(k, _)| {
                matches!(k, EvpnKey::MacIp { mac, ip, .. }
                    if *mac == [0, 0, 0, 0, 0, 0xfe] && ip.to_string() == "203.0.113.1")
            })
            .expect("svi route");
        // RFC 7432 §7.8: only the SVI's own address is the anycast gateway.
        assert!(svi.1.ext_communities.contains(&DEFAULT_GATEWAY));
        let host = t
            .routes
            .iter()
            .find(
                |(k, _)| matches!(k, EvpnKey::MacIp { ip, .. } if ip.to_string() == "198.51.100.7"),
            )
            .expect("arp-learned host route");
        assert!(!host.1.ext_communities.contains(&DEFAULT_GATEWAY));
        assert!(!t.routes.keys().any(|k| matches!(k,
            EvpnKey::MacIp { ip, .. } if ip.to_string() == "198.51.100.8")));
        let table = fdb.table().await;
        assert_eq!(table.neighbours.len(), 2);
    }

    #[tokio::test]
    async fn local_macs_are_published_for_bgp_with_the_type3() {
        let fdb = Fdb::new(
            "bd1".to_string(),
            Arc::new(Recorder::default()),
            Duration::ZERO,
        );
        let mut rx = fdb.subscribe();
        fdb.set_ready(Some(ready())).await;
        assert_eq!(rx.borrow_and_update().routes.len(), 1, "just the Type-3");
        fdb.refresh_local().await;
        let t = rx.borrow_and_update().clone();
        assert_eq!(t.bgp_instance.as_deref(), Some("r1"));
        assert_eq!(t.routes.len(), 2);
        fdb.set_ready(None).await;
        assert!(rx.borrow().routes.is_empty() && rx.borrow().bgp_instance.is_none());
    }

    #[tokio::test]
    async fn table_reports_the_local_mac_port_and_age() {
        let fdb = Fdb::new(
            "bd1".to_string(),
            Arc::new(Recorder::default()),
            Duration::ZERO,
        );
        fdb.set_ready(Some(ready())).await;
        fdb.refresh_local().await;
        let t = fdb.table().await;
        let m = t
            .macs
            .iter()
            .find(|m| m.source == MacSource::Local)
            .unwrap();
        assert_eq!(m.interface.as_deref(), Some("eth1"));
        assert_eq!(m.age_secs, Some(12));
        for m in t.macs.iter().filter(|m| m.source == MacSource::Remote) {
            assert_eq!((m.interface.as_deref(), m.age_secs), (None, None));
        }
    }

    /// A Type-4 as another nos PE sends it: modulo, AC-DF.
    fn es_route(esi: Esi, origin: &str) -> EvpnRoute {
        es_route_df(esi, origin, Some(df_election_ext(DF_ALG_MODULO, true)))
    }

    /// A Type-4 with the given DF Election community, or none (as `GoBGP` sends).
    fn es_route_df(esi: Esi, origin: &str, df_election: Option<u64>) -> EvpnRoute {
        let origin: IpAddr = origin.parse().unwrap();
        EvpnRoute {
            key: EvpnKey::EthernetSegment {
                rd: [0; 8],
                esi,
                origin,
            },
            vni: 0,
            next_hop: origin,
            ext_communities: std::iter::once(es_import_rt(&esi))
                .chain(df_election)
                .collect(),
            esi,
            l3_vni: None,
        }
    }

    /// `plan_df` for one segment (ours asking for `ours`) against `routes`.
    fn plan_one(ours: DfAlgorithm, routes: Vec<EvpnRoute>) -> Segment {
        let mut r = ready_with_segment();
        r.es_ports[0].df_algorithm = ours;
        let received: HashMap<EvpnKey, EvpnRoute> =
            routes.into_iter().map(|x| (x.key.clone(), x)).collect();
        let ads = ad_index(&r, &received);
        plan_df(&r, &received, &ads, &BTreeSet::new()).remove(0)
    }

    // With us (192.0.2.1) and 192.0.1.9 on ESI for VNI 10100, modulo elects
    // [192.0.1.9, 192.0.2.1][10100 % 2] = 192.0.1.9 but HRW elects us
    // (weights 1081544908 vs 1754456132, see `df::hrw_weight`).
    const LOW_PE: &str = "192.0.1.9";

    #[test]
    fn a_type4_without_the_es_import_rt_is_no_df_candidate() {
        let no_rt = |esi, o| EvpnRoute {
            ext_communities: vec![df_election_ext(DF_ALG_MODULO, true)],
            ..es_route(esi, o)
        };
        let wrong_rt = EvpnRoute {
            ext_communities: vec![es_import_rt(&[9; 10])],
            ..es_route(ESI, LOW_PE)
        };
        // Lower-address peer: with the RT we are non-DF, without it we are DF.
        let with = plan_one(
            DfAlgorithm::Modulo,
            vec![es_route(ESI, LOW_PE), evi_ad(ESI, LOW_PE)],
        );
        assert!(!with.df);
        for bad in [no_rt(ESI, LOW_PE), wrong_rt] {
            let s = plan_one(DfAlgorithm::Modulo, vec![bad.clone(), evi_ad(ESI, LOW_PE)]);
            assert!(s.df);
            assert!(!s.pes.contains(&LOW_PE.parse().unwrap()));
            let r = ready_with_segment();
            let received = HashMap::from([(bad.key.clone(), bad)]);
            assert_eq!(es_import_mismatches(&r, &received).len(), 1);
        }
        // Another ESI's Type-4 is not ours to warn about.
        let r = ready_with_segment();
        let o = no_rt([7; 10], LOW_PE);
        assert!(es_import_mismatches(&r, &HashMap::from([(o.key.clone(), o)])).is_empty());
    }

    #[test]
    fn hrw_runs_only_when_every_pe_asks_for_it() {
        use DfAlgorithm::{Hrw, Modulo};
        let peer = |c: Option<u64>| vec![es_route_df(ESI, LOW_PE, c), evi_ad(ESI, LOW_PE)];
        let hrw = Some(df_election_ext(DF_ALG_HRW, true));
        let s = plan_one(Hrw, peer(hrw));
        assert_eq!((s.algorithm, s.df, s.ac_df), (Hrw, true, true));
        // A peer with no community, or alg 2 (Preference), or modulo: fallback.
        for c in [
            None,
            Some(df_election_ext(2, true)),
            Some(df_election_ext(DF_ALG_MODULO, true)),
        ] {
            let s = plan_one(Hrw, peer(c));
            assert_eq!((s.algorithm, s.df), (Modulo, false), "{c:?}");
        }
        // We are on modulo, the peer on HRW: modulo.
        let s = plan_one(Modulo, peer(hrw));
        assert_eq!((s.algorithm, s.df), (Modulo, false));
    }

    #[test]
    fn the_per_evi_filter_needs_ac_df_from_every_pe() {
        // AC-DF everywhere: the PE without this EVI's per-EVI A-D is no candidate.
        let s = plan_one(
            DfAlgorithm::Modulo,
            vec![
                es_route(ESI, REMOTE),
                evi_ad(ESI, REMOTE),
                es_route(ESI, LOW_PE),
            ],
        );
        assert!(s.ac_df);
        assert!(!s.pes.contains(&LOW_PE.parse().unwrap()));
        // One PE without AC-DF: back to RFC 7432's list, every Type-4 origin.
        let s = plan_one(
            DfAlgorithm::Modulo,
            vec![
                es_route(ESI, REMOTE),
                evi_ad(ESI, REMOTE),
                es_route_df(ESI, LOW_PE, None),
            ],
        );
        assert!(!s.ac_df);
        assert_eq!(s.pes.len(), 3);
    }

    #[test]
    fn our_type4_asks_for_the_configured_algorithm_with_ac_df() {
        let mut r = ready_with_segment();
        r.es_ports[0].df_algorithm = DfAlgorithm::Hrw;
        let routes = local_routes(&r, &BTreeMap::new(), &BTreeSet::new(), &BTreeSet::new());
        let es = routes
            .values()
            .find(|x| matches!(x.key, EvpnKey::EthernetSegment { .. }))
            .unwrap();
        assert_eq!(
            es.ext_communities,
            vec![es_import_rt(&ESI), df_election_ext(DF_ALG_HRW, true)]
        );
    }

    fn ad_route(esi: Esi, tag: u32, vni: u32, origin: &str) -> EvpnRoute {
        let origin: IpAddr = origin.parse().unwrap();
        EvpnRoute {
            key: EvpnKey::EthernetAd {
                rd: [0; 8],
                esi,
                tag,
                origin,
            },
            vni,
            next_hop: origin,
            ext_communities: vec![RT, esi_label_ext(false)],
            esi,
            l3_vni: None,
        }
    }

    fn es_ad(esi: Esi, origin: &str) -> EvpnRoute {
        ad_route(esi, AD_TAG_ES, 0, origin)
    }

    #[test]
    fn a_remote_mac_on_a_segment_needs_its_pes_per_es_ad_unless_pinned_to_our_own() {
        let mut route = mac_route(1, 10100, RT, REMOTE);
        route.esi = ESI;
        let ads = ads_of(ESI, &[REMOTE]);
        // Not usable until the PE that advertised it has advertised the segment.
        assert!(want(&ready(), &route).is_empty(), "no per-es a-d yet");
        assert_ne!(want_ads(&ready(), &route, &ads), []);
        // A different PE's A-D for the segment doesn't count.
        let other = ads_of(ESI, &["192.0.2.77"]);
        assert_eq!(want_ads(&ready(), &route, &other), []);
        // On our own segment whose port can carry it: pinned there, with or
        // without the PE's per-ES A-D.
        let r = ready_with_segment();
        let pins = HashMap::from([(ESI, "eth1".to_string())]);
        let none = BTreeMap::new();
        let pin = Installed::SegmentMac {
            mac: [0, 0, 0, 0, 0, 1],
            port: "eth1".to_string(),
        };
        assert_eq!(
            desired(&r, &route, &Ads::new(), &none, &pins),
            std::slice::from_ref(&pin)
        );
        assert_eq!(
            desired(&r, &route, &ads, &none, &pins),
            std::slice::from_ref(&pin)
        );
        // Learned on that port already: still pinned; behind another port: not.
        let on = |p: &str| BTreeMap::from([([0, 0, 0, 0, 0, 1], p.to_string())]);
        assert_eq!(
            desired(&r, &route, &ads, &on("eth1"), &pins),
            std::slice::from_ref(&pin)
        );
        assert_eq!(desired(&r, &route, &ads, &on("eth9"), &pins), []);
        // A MAC+IP: the pin and the neighbour.
        let mut mip = macip_route(1, "198.51.100.7", 10100, RT, REMOTE);
        mip.esi = ESI;
        assert_eq!(
            desired(&r, &mip, &Ads::new(), &none, &pins),
            [
                pin,
                Installed::Neigh {
                    mac: [0, 0, 0, 0, 0, 1],
                    ip: "198.51.100.7".parse().unwrap(),
                    vtep: REMOTE.parse().unwrap()
                }
            ]
        );
        // Port not pinnable (down, single-active non-DF): the remote PE, still
        // gated on its per-ES A-D.
        assert_eq!(
            want_ads(&r, &route, &ads),
            [Installed::Mac {
                mac: [0, 0, 0, 0, 0, 1],
                vtep: REMOTE.parse().unwrap()
            }]
        );
        assert_eq!(want(&r, &route), []);
        // A different segment's MAC is just as gated.
        route.esi = [9; 10];
        assert_eq!(want_ads(&ready_with_segment(), &route, &ads), []);
        let ads9 = ads_of([9; 10], &[REMOTE]);
        assert_ne!(want_ads(&ready_with_segment(), &route, &ads9), []);
    }

    #[tokio::test]
    async fn a_remote_mac_on_our_segment_is_pinned_while_the_port_carries_it() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready_with_segment())).await;
        fdb.refresh_local().await; // MAC 7 is local, behind eth1
        calls(&driver);
        let mut m1 = mac_route(1, 10100, RT, REMOTE);
        m1.esi = ESI;
        fdb.apply_push(EvpnUpdate::Add(m1.clone())).await;
        assert_eq!(calls(&driver), ["pin eth1 00:00:00:00:00:01 false"]);
        let t = fdb.table().await;
        assert_eq!(
            t.macs
                .iter()
                .filter(|m| m.source == MacSource::Remote)
                .count(),
            1
        );
        fdb.apply_push(EvpnUpdate::Add(es_ad(ESI, REMOTE))).await;
        assert_eq!(calls(&driver), [] as [String; 0]);

        // The segment loses carrier: the MAC goes to the PE that advertised it.
        driver.1.lock().unwrap().insert("eth1".to_string());
        fdb.refresh_local().await;
        assert_eq!(
            calls(&driver),
            [
                "filter eth1 bit=1 df=true",
                "flood eth1 uni=false bum=true",
                "unpin eth1 00:00:00:00:00:01",
                "set 00:00:00:00:00:01 192.0.2.9"
            ]
        );
        // Carrier back (no DF wait here): pinned again.
        driver.1.lock().unwrap().clear();
        fdb.refresh_local().await;
        let c = calls(&driver);
        assert!(
            c.ends_with(&[
                "del 00:00:00:00:00:01 192.0.2.9".to_string(),
                "pin eth1 00:00:00:00:00:01 false".to_string()
            ]),
            "{c:?}"
        );

        // A MAC the bridge already learned on the port is pinned active.
        let mut m7 = mac_route(7, 10100, RT, REMOTE);
        m7.esi = ESI;
        fdb.apply_push(EvpnUpdate::Add(m7)).await;
        assert_eq!(calls(&driver), ["pin eth1 00:00:00:00:00:07 true"]);

        // A withdrawal unpins.
        fdb.apply_push(EvpnUpdate::Remove(m1.key)).await;
        assert_eq!(calls(&driver), ["unpin eth1 00:00:00:00:00:01"]);
    }

    #[tokio::test]
    async fn a_single_active_non_df_never_pins_and_pins_once_it_is_the_df() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready_single_active())).await;
        for r in [
            es_route(ESI, LOW_PE),
            evi_ad(ESI, LOW_PE),
            es_ad(ESI, LOW_PE),
        ] {
            fdb.apply_push(EvpnUpdate::Add(r)).await;
        }
        assert!(!fdb.table().await.segments[0].designated_forwarder);
        calls(&driver);
        let mut m1 = mac_route(1, 10100, RT, LOW_PE);
        m1.esi = ESI;
        fdb.apply_push(EvpnUpdate::Add(m1)).await;
        assert_eq!(calls(&driver), ["set 00:00:00:00:00:01 192.0.1.9"]);

        // The DF leaves the segment: we are elected and the MAC is pinned.
        fdb.apply_push(EvpnUpdate::Remove(es_route(ESI, LOW_PE).key))
            .await;
        let c = calls(&driver);
        assert!(c.contains(&"fwd eth1 true".to_string()), "{c:?}");
        assert!(
            c.ends_with(&[
                "del 00:00:00:00:00:01 192.0.1.9".to_string(),
                "pin eth1 00:00:00:00:00:01 false".to_string()
            ]),
            "{c:?}"
        );
    }

    #[test]
    fn the_per_es_ad_index_counts_only_our_route_targets_and_never_our_own_pe() {
        let r = ready();
        let mut received = HashMap::new();
        for route in [
            es_ad(ESI, REMOTE),
            es_ad(ESI, VTEP),
            // A per-EVI route, and one for another domain (other RT).
            ad_route(ESI, 0, 10100, "192.0.2.10"),
            EvpnRoute {
                ext_communities: vec![1],
                ..es_ad(ESI, "192.0.2.11")
            },
        ] {
            received.insert(route.key.clone(), route);
        }
        // The per-EVI route counts as a backup path only for this domain's VNI.
        let mut expected = ads_of(ESI, &[REMOTE]);
        expected
            .get_mut(&ESI)
            .unwrap()
            .evi
            .insert("192.0.2.10".parse().unwrap());
        assert_eq!(ad_index(&r, &received), expected);
    }

    #[tokio::test]
    async fn withdrawing_a_pes_per_es_ad_takes_all_its_macs_at_once_and_readvertising_restores_them(
    ) {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready())).await;
        calls(&driver);
        let mut m1 = mac_route(1, 10100, RT, REMOTE);
        m1.esi = ESI;
        let mut m2 = mac_route(2, 10100, RT, REMOTE);
        m2.esi = ESI;
        // A MAC with no ESI is not affected by any of this.
        let plain = mac_route(3, 10100, RT, REMOTE);
        for r in [&m1, &m2, &plain] {
            fdb.apply_push(EvpnUpdate::Add(r.clone())).await;
        }
        assert_eq!(calls(&driver), ["set 00:00:00:00:00:03 192.0.2.9"]);

        fdb.apply_push(EvpnUpdate::Add(es_ad(ESI, REMOTE))).await;
        let mut c = calls(&driver);
        c.sort();
        assert_eq!(
            c,
            [
                "set 00:00:00:00:00:01 192.0.2.9",
                "set 00:00:00:00:00:02 192.0.2.9"
            ]
        );
        assert_eq!(fdb.table().await.macs.len(), 3);

        // Mass withdrawal: one route goes, both MACs go, the plain one stays.
        fdb.apply_push(EvpnUpdate::Remove(es_ad(ESI, REMOTE).key))
            .await;
        let mut c = calls(&driver);
        c.sort();
        assert_eq!(
            c,
            [
                "del 00:00:00:00:00:01 192.0.2.9",
                "del 00:00:00:00:00:02 192.0.2.9"
            ]
        );
        assert_eq!(fdb.table().await.macs.len(), 1);

        // A `Full` that brings it back reinstalls them.
        fdb.apply_push(EvpnUpdate::Full(vec![
            m1.clone(),
            m2.clone(),
            plain,
            es_ad(ESI, REMOTE),
        ]))
        .await;
        assert_eq!(fdb.table().await.macs.len(), 3);
    }

    #[tokio::test]
    async fn macs_behind_a_segment_port_carry_its_esi_and_a_type4_is_originated() {
        let fdb = Fdb::new(
            "bd1".to_string(),
            Arc::new(Recorder::default()),
            Duration::ZERO,
        );
        let mut rx = fdb.subscribe();
        fdb.set_ready(Some(ready_with_segment())).await;
        fdb.refresh_local().await;
        let t = rx.borrow_and_update().clone();
        // Type-3, Type-2 for MAC 7, Type-4, and the two Type-1.
        assert_eq!(t.routes.len(), 5);
        let mac = t
            .routes
            .values()
            .find(|r| matches!(r.key, EvpnKey::Mac { .. }))
            .unwrap();
        assert_eq!(mac.esi, ESI);
        let imet = t
            .routes
            .values()
            .find(|r| matches!(r.key, EvpnKey::Imet { .. }))
            .unwrap();
        assert_eq!(imet.esi, [0; 10]);
        let es = t
            .routes
            .values()
            .find(|r| matches!(r.key, EvpnKey::EthernetSegment { .. }))
            .unwrap();
        assert_eq!(
            es.ext_communities,
            vec![es_import_rt(&ESI), df_election_ext(DF_ALG_MODULO, true)]
        );
        // Per-ES A-D: MAX-ET, the RTs, encapsulation and an all-active ESI Label.
        let per_es = t
            .routes
            .values()
            .find(|r| matches!(r.key, EvpnKey::EthernetAd { tag, .. } if tag == AD_TAG_ES))
            .unwrap();
        assert_eq!(
            per_es.ext_communities,
            vec![RT, ENCAP_VXLAN, esi_label_ext(false)]
        );
        // Per-EVI A-D: tag 0, the VNI, the domain's RTs.
        let per_evi = t
            .routes
            .values()
            .find(|r| matches!(r.key, EvpnKey::EthernetAd { tag: 0, .. }))
            .unwrap();
        assert_eq!(per_evi.vni, 10100);
        assert_eq!(per_evi.ext_communities, vec![RT, ENCAP_VXLAN]);
        assert_eq!(
            fdb.table().await.macs[0].esi.as_deref(),
            Some("00:01:02:03:04:05:06:07:08:09")
        );
    }

    #[tokio::test]
    async fn the_non_df_stops_flooding_to_the_segment_and_gets_it_back() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready_with_segment())).await;
        // Alone on the segment: the DF, flooding explicitly enabled.
        assert_eq!(
            calls(&driver),
            [
                "ensure 10100",
                "filter eth1 bit=1 df=false",
                "flood eth1 uni=true bum=true"
            ]
        );
        assert!(fdb.table().await.segments[0].designated_forwarder);
        assert!(fdb.table().await.segments[0].local_bias);

        // A PE with a lower address, attached to this EVI too (a per-EVI A-D
        // for our VNI): [192.0.1.9, 192.0.2.1], 10100 % 2 == 0, so it is the
        // DF and we are not.
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        fdb.apply_push(EvpnUpdate::Add(evi_ad(ESI, "192.0.1.9")))
            .await;
        // The order is the safety property: the egress filters, then the
        // ingress marking, and only then the flood flags — the non-DF keeps
        // flooding multicast and broadcast (local bias), unicast goes off.
        assert_eq!(
            calls(&driver),
            [
                "filter eth1 bit=1 df=true",
                "bias 10100 192.0.1.9=1",
                "flood eth1 uni=false bum=true"
            ]
        );
        let t = fdb.table().await;
        assert!(!t.segments[0].designated_forwarder);
        assert!(t.segments[0].local_bias);
        assert_eq!(t.segments[0].pes.len(), 2);

        // The flood block is re-asserted on every resync; the filters are
        // already in place and are not rewritten.
        fdb.set_ready(Some(ready_with_segment())).await;
        assert_eq!(
            calls(&driver),
            ["ensure 10100", "flood eth1 uni=false bum=true"]
        );
        // The peer going: the DF filter is dropped first, then the flags open
        // and the (now empty) ingress marking goes.
        fdb.apply_push(EvpnUpdate::Remove(es_route(ESI, "192.0.1.9").key))
            .await;
        assert_eq!(
            calls(&driver),
            [
                "filter eth1 bit=1 df=false",
                "bias 10100 ",
                "flood eth1 uni=true bum=true"
            ]
        );

        // A Type-4 for another segment is none of our business.
        fdb.apply_push(EvpnUpdate::Add(es_route([7; 10], "192.0.1.9")))
            .await;
        assert_eq!(calls(&driver), [] as [String; 0]);

        // Unconfiguring while blocked restores flooding.
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        calls(&driver);
        fdb.set_ready(None).await;
        assert_eq!(
            calls(&driver),
            [
                "remove 10100",
                "unfilter eth1",
                "flood eth1 uni=true bum=true"
            ]
        );
        assert_eq!(fdb.table().await.segments.len(), 0);
    }

    #[tokio::test]
    async fn a_peer_with_no_per_evi_ad_is_not_a_df_candidate() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready_with_segment())).await;
        calls(&driver);

        // A lower-addressed PE's bare Type-4, with no per-EVI A-D for our
        // VNI, does not make it a candidate (RFC 7432 §8.5 / RFC 8584 §2.1):
        // it is on the segment but never joined this EVI, so we stay DF.
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        assert_eq!(calls(&driver), [] as [String; 0]);
        let t = fdb.table().await;
        assert!(t.segments[0].designated_forwarder);
        assert_eq!(t.segments[0].pes, vec![VTEP.parse::<IpAddr>().unwrap()]);

        // Its per-EVI A-D arriving makes it a real candidate: we lose the election.
        fdb.apply_push(EvpnUpdate::Add(evi_ad(ESI, "192.0.1.9")))
            .await;
        assert_eq!(
            calls(&driver),
            [
                "filter eth1 bit=1 df=true",
                "bias 10100 192.0.1.9=1",
                "flood eth1 uni=false bum=true"
            ]
        );
        assert!(!fdb.table().await.segments[0].designated_forwarder);
    }

    #[tokio::test]
    async fn a_new_segment_port_stays_blocked_until_the_df_wait_ends() {
        let driver = Arc::new(Recorder::default());
        let wait = Duration::from_millis(150);
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), wait);
        let (stop, shutdown) = watch::channel(false);
        let local = tokio::spawn(fdb.clone().run_local(shutdown));

        // Alone on the segment, so the DF — but not until the timer ends.
        fdb.set_ready(Some(ready_with_segment())).await;
        assert!(calls(&driver).ends_with(&["flood eth1 uni=false bum=true".to_string()]));
        assert!(!fdb.table().await.segments[0].designated_forwarder);

        // `run_local` wakes at the deadline by itself (the tick is 10s).
        tokio::time::sleep(wait * 3).await;
        assert!(calls(&driver).contains(&"flood eth1 uni=true bum=true".to_string()));
        assert!(fdb.table().await.segments[0].designated_forwarder);

        // A PE joining an already-elected port does not restart the wait.
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, REMOTE))).await;
        assert!(calls(&driver).is_empty(), "still the DF, still flooding");
        assert!(fdb.table().await.segments[0].designated_forwarder);

        // Leaving the segment clears the timer: coming back waits again.
        fdb.set_ready(None).await;
        calls(&driver);
        fdb.set_ready(Some(ready_with_segment())).await;
        assert!(calls(&driver).ends_with(&["flood eth1 uni=false bum=true".to_string()]));

        stop.send(true).unwrap();
        local.await.unwrap();
    }

    #[tokio::test]
    async fn a_segment_without_carrier_withdraws_its_routes_and_is_never_the_df() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        let mut rx = fdb.subscribe();
        fdb.set_ready(Some(ready_with_segment())).await;
        fdb.refresh_local().await;
        assert_eq!(rx.borrow_and_update().routes.len(), 5);
        assert!(fdb.table().await.segments[0].up);

        // The bond loses its last member: Type-4 and both Type-1 go.
        driver.1.lock().unwrap().insert("eth1".to_string());
        fdb.refresh_local().await;
        let routes = rx.borrow_and_update().routes.clone();
        assert_eq!(routes.len(), 2, "the Type-3 and the MAC: {routes:?}");
        assert!(!routes.keys().any(|k| matches!(
            k,
            EvpnKey::EthernetSegment { .. } | EvpnKey::EthernetAd { .. }
        )));
        let t = fdb.table().await;
        assert!(!t.segments[0].up);
        assert!(!t.segments[0].designated_forwarder);

        // Carrier back: everything is advertised again.
        driver.1.lock().unwrap().clear();
        fdb.refresh_local().await;
        assert_eq!(rx.borrow_and_update().routes.len(), 5);
        assert!(fdb.table().await.segments[0].up);
    }

    #[tokio::test]
    async fn a_single_active_non_df_is_blocked_outright_and_the_df_forwards() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready_single_active())).await;
        // Alone: the DF. It floods, and forwarding is the kernel default, so
        // it is never asserted.
        assert_eq!(
            calls(&driver),
            ["ensure 10100", "flood eth1 uni=true bum=true"]
        );
        let t = fdb.table().await;
        assert!(t.segments[0].single_active);
        // Local bias does not apply: the DF delivers what its peer got locally.
        assert!(!t.segments[0].local_bias);

        // A PE with a lower address, also attached to this EVI, is the DF:
        // the port is blocked, but it still floods (only forwarding decides).
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        fdb.apply_push(EvpnUpdate::Add(evi_ad(ESI, "192.0.1.9")))
            .await;
        assert_eq!(calls(&driver), ["fwd eth1 false"]);
        assert!(!fdb.table().await.segments[0].designated_forwarder);

        // The block is re-asserted on every resync, then lifted when it goes.
        fdb.set_ready(Some(ready_single_active())).await;
        assert!(calls(&driver).contains(&"fwd eth1 false".to_string()));
        fdb.apply_push(EvpnUpdate::Remove(es_route(ESI, "192.0.1.9").key))
            .await;
        assert_eq!(calls(&driver), ["fwd eth1 true"]);

        // Unconfiguring while blocked restores both.
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        calls(&driver);
        fdb.set_ready(None).await;
        assert_eq!(
            calls(&driver),
            [
                "remove 10100",
                "flood eth1 uni=true bum=true",
                "fwd eth1 true"
            ]
        );
    }

    #[tokio::test]
    async fn switching_the_mode_swaps_the_mechanism_and_undoes_the_old_one() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready_with_segment())).await;
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        fdb.apply_push(EvpnUpdate::Add(evi_ad(ESI, "192.0.1.9")))
            .await;
        calls(&driver);
        // All-active non-DF: BUM flooding off, forwarding untouched.
        fdb.set_ready(Some(ready_with_segment())).await;
        let c = calls(&driver);
        assert!(
            c.contains(&"flood eth1 uni=false bum=true".to_string()),
            "{c:?}"
        );
        assert!(!c.iter().any(|x| x.starts_with("fwd")), "{c:?}");

        // Single-active: the local-bias filters are removed, everything floods.
        fdb.set_ready(Some(ready_single_active())).await;
        let c = calls(&driver);
        assert!(c.contains(&"unfilter eth1".to_string()), "{c:?}");
        assert!(
            c.contains(&"flood eth1 uni=true bum=true".to_string()),
            "{c:?}"
        );
        assert!(c.contains(&"fwd eth1 false".to_string()), "{c:?}");

        fdb.set_ready(Some(ready_with_segment())).await;
        let c = calls(&driver);
        assert!(
            c.contains(&"filter eth1 bit=1 df=true".to_string()),
            "{c:?}"
        );
        assert!(
            c.contains(&"flood eth1 uni=false bum=true".to_string()),
            "{c:?}"
        );
        assert!(c.contains(&"fwd eth1 true".to_string()), "{c:?}");
    }

    fn seg(port: &str, pes: &[&str], df: bool, single_active: bool) -> Segment {
        Segment {
            esi: ESI,
            port: port.to_string(),
            pes: pes.iter().map(|p| p.parse().unwrap()).collect(),
            df,
            waiting: false,
            up: true,
            ad_pes: Vec::new(),
            single_active,
            algorithm: DfAlgorithm::Modulo,
            ac_df: true,
        }
    }

    #[test]
    fn the_local_bias_plan_gives_each_all_active_segment_a_bit_and_each_peer_its_segments() {
        let vtep: IpAddr = VTEP.parse().unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let plan = [
            // Sorted by port name, not plan order: bond1 -> bit 1, bond2 -> bit 2.
            seg("bond2", &[VTEP, "192.0.1.9", "192.0.3.3"], true, false),
            seg("bond1", &[VTEP, "192.0.1.9"], false, false),
            // Single-active and its peer are out of it.
            seg("bond3", &[VTEP, "192.0.9.9"], true, true),
        ];
        let b = plan_local_bias(vtep, &plan);
        assert_eq!(
            b.ports,
            BTreeMap::from([
                ("bond1".to_string(), (1, true)),
                ("bond2".to_string(), (2, false)),
            ])
        );
        assert_eq!(
            b.peers,
            BTreeMap::from([(ip("192.0.1.9"), 0b11), (ip("192.0.3.3"), 0b10)])
        );
        assert_eq!(b.overflow.len(), 0);

        // A port in its DF wait, or without carrier, also drops core BUM.
        let mut waiting = seg("bond1", &[VTEP, "192.0.1.9"], true, false);
        waiting.waiting = true;
        assert!(plan_local_bias(vtep, &[waiting]).ports["bond1"].1);
        assert_eq!(plan_local_bias(vtep, &[]), BiasPlan::default());
    }

    #[test]
    fn a_seventeenth_all_active_segment_has_no_bit_and_keeps_df_only_flooding() {
        let vtep: IpAddr = VTEP.parse().unwrap();
        let plan: Vec<Segment> = (0..17)
            .map(|i| seg(&format!("bond{i:02}"), &[VTEP, "192.0.1.9"], true, false))
            .collect();
        let b = plan_local_bias(vtep, &plan);
        assert_eq!(b.ports.len(), 16);
        assert_eq!(b.ports["bond15"].0, 1 << 15);
        assert_eq!(b.overflow, ["bond16"]);
        assert_eq!(b.peers.values().copied().collect::<Vec<_>>(), [0xFFFF]);
    }

    #[tokio::test]
    async fn a_failing_tc_setup_leaves_the_segment_on_df_only_flooding() {
        let driver = Arc::new(Recorder::default());
        driver.2.store(true, std::sync::atomic::Ordering::Relaxed);
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready_with_segment())).await;
        fdb.apply_push(EvpnUpdate::Add(es_route(ESI, "192.0.1.9")))
            .await;
        fdb.apply_push(EvpnUpdate::Add(evi_ad(ESI, "192.0.1.9")))
            .await;
        // Never "flood on, unfiltered": the non-DF refuses all BUM, as before.
        let c = calls(&driver);
        assert!(
            c.contains(&"flood eth1 uni=false bum=false".to_string()),
            "{c:?}"
        );
        assert!(
            !c.iter()
                .any(|x| x.contains("bum=true") && x.contains("uni=false")),
            "{c:?}"
        );
        assert!(!fdb.table().await.segments[0].local_bias);

        // The kernel comes good: the next resync switches it on, filters first.
        driver.2.store(false, std::sync::atomic::Ordering::Relaxed);
        fdb.set_ready(Some(ready_with_segment())).await;
        let c = calls(&driver);
        let at = |what: &str| c.iter().position(|x| x.starts_with(what)).unwrap();
        assert!(
            at("filter") < at("bias") && at("bias") < at("flood"),
            "{c:?}"
        );
        assert!(fdb.table().await.segments[0].local_bias);
    }

    #[test]
    fn the_per_es_ad_announces_the_redundancy_mode_in_its_esi_label() {
        let label = |r: &Ready| {
            local_routes(r, &BTreeMap::new(), &BTreeSet::new(), &BTreeSet::new())
                .values()
                .find(|x| matches!(x.key, EvpnKey::EthernetAd { tag, .. } if tag == AD_TAG_ES))
                .unwrap()
                .ext_communities
                .iter()
                .find_map(|c| parse_esi_label(*c))
        };
        assert_eq!(label(&ready_with_segment()), Some(false));
        assert_eq!(label(&ready_single_active()), Some(true));
    }

    #[test]
    fn a_single_active_segments_macs_fall_back_to_a_pe_with_a_per_evi_ad() {
        let backup = "192.0.2.77";
        let mut route = mac_route(1, 10100, RT, REMOTE);
        route.esi = [9; 10];
        let ads = |single_active: bool, evi: &[&str]| {
            Ads::from([(
                [9; 10],
                SegmentAds {
                    pes: BTreeSet::from([backup.parse().unwrap()]),
                    evi: evi.iter().map(|p| p.parse().unwrap()).collect(),
                    single_active,
                    ..SegmentAds::default()
                },
            )])
        };
        let mac = |vtep: &str| {
            vec![Installed::Mac {
                mac: [0, 0, 0, 0, 0, 1],
                vtep: vtep.parse().unwrap(),
            }]
        };
        // REMOTE's per-ES A-D is gone: the MAC moves to the backup PE...
        assert_eq!(
            want_ads(&ready(), &route, &ads(true, &[backup])),
            mac(backup)
        );
        // ... unless the segment is all-active (mass withdrawal), or the
        // backup never advertised the EVI.
        assert_eq!(want_ads(&ready(), &route, &ads(false, &[backup])), []);
        assert_eq!(want_ads(&ready(), &route, &ads(true, &[])), []);
        // While REMOTE's own per-ES A-D is held the MAC stays where it is.
        let mut held = ads(true, &[backup]);
        held.get_mut(&[9; 10])
            .unwrap()
            .pes
            .insert(REMOTE.parse().unwrap());
        assert_eq!(want_ads(&ready(), &route, &held), mac(REMOTE));
    }

    fn evi_ad(esi: Esi, origin: &str) -> EvpnRoute {
        ad_route(esi, 0, 10100, origin)
    }

    #[test]
    fn a_mac_is_aliased_only_over_pes_with_both_a_per_es_and_a_per_evi_ad() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let ads = |pes: &[&str], evi: &[&str], single_active: bool| SegmentAds {
            pes: pes.iter().map(|p| ip(p)).collect(),
            evi: evi.iter().map(|p| ip(p)).collect(),
            single_active,
            ..SegmentAds::default()
        };
        let (a, b) = ("192.0.2.9", "192.0.2.20");
        // Both PEs serve the segment and the EVI: balanced over both, sorted.
        assert_eq!(
            alias_group(&ads(&[b, a], &[a, b], false), ip(a), ip(a)),
            Some(vec![ip(a), ip(b)])
        );
        // One PE is no group; a PE without the EVI's A-D is left out.
        assert_eq!(alias_group(&ads(&[a], &[a], false), ip(a), ip(a)), None);
        assert_eq!(alias_group(&ads(&[a, b], &[a], false), ip(a), ip(a)), None);
        // The MAC's own PE has to be one of them.
        assert_eq!(
            alias_group(&ads(&[a, b], &[b, "192.0.2.30"], false), ip(a), ip(a)),
            None
        );
        // Single-active has a backup path, not aliasing.
        assert_eq!(
            alias_group(&ads(&[a, b], &[a, b], true), ip(a), ip(a)),
            None
        );
        // One address family, our VTEP's: an all-IPv6 set aliases over an
        // IPv6 underlay, never a mixed set or one of the other family.
        let (c, d) = ("2001:db8::1", "2001:db8::2");
        assert_eq!(
            alias_group(&ads(&[c, d], &[c, d], false), ip(c), ip("2001:db8::9")),
            Some(vec![ip(c), ip(d)])
        );
        assert_eq!(
            alias_group(&ads(&[a, c], &[a, c], false), ip(a), ip(a)),
            None
        );
        assert_eq!(
            alias_group(&ads(&[c, d], &[c, d], false), ip(c), ip(a)),
            None
        );
    }

    #[test]
    fn a_single_active_backup_is_the_segments_elected_df() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let set = |v: &[&str]| v.iter().map(|p| ip(p)).collect::<BTreeSet<_>>();
        let (b, c) = ("192.0.2.20", "192.0.2.30");
        let ads = |es: &[&str]| SegmentAds {
            pes: set(&[b, c]),
            evi: set(&[b, c]),
            single_active: true,
            es_pes: set(es),
        };
        // Ordered .20 .30, VNI 10101 % 2 == 1: the DF is .30, not the lowest.
        assert_eq!(backup_pe(&ads(&["192.0.2.10", b, c]), 10101), Some(ip(c)));
        assert_eq!(backup_pe(&ads(&[b, c]), 10100), Some(ip(b)));
        // No Type-4 held: the lowest usable address.
        assert_eq!(backup_pe(&ads(&[]), 10101), Some(ip(b)));
        // A Type-4 from a PE that lost its A-D routes doesn't count.
        assert_eq!(backup_pe(&ads(&["192.0.2.40"]), 10101), Some(ip(b)));
    }

    #[tokio::test]
    async fn a_segments_macs_move_between_one_pe_and_a_group_as_the_a_d_routes_come_and_go() {
        let driver = Arc::new(Recorder::default());
        let fdb = Fdb::new("bd1".to_string(), driver.clone(), Duration::ZERO);
        fdb.set_ready(Some(ready())).await;
        let (a, b, esi) = (REMOTE, "192.0.2.20", [9; 10]);
        let mut mac = mac_route(1, 10100, RT, a);
        mac.esi = esi;
        fdb.apply_push(EvpnUpdate::Add(mac)).await;
        calls(&driver);

        // One PE serving the segment: the plain entry.
        fdb.apply_push(EvpnUpdate::Add(es_ad(esi, a))).await;
        fdb.apply_push(EvpnUpdate::Add(evi_ad(esi, a))).await;
        assert_eq!(calls(&driver), ["set 00:00:00:00:00:01 192.0.2.9"]);

        // A second PE that serves the segment and the EVI: aliased.
        fdb.apply_push(EvpnUpdate::Add(es_ad(esi, b))).await;
        assert!(calls(&driver).is_empty(), "no per-EVI A-D from it yet");
        fdb.apply_push(EvpnUpdate::Add(evi_ad(esi, b))).await;
        assert_eq!(
            calls(&driver),
            [
                "del 00:00:00:00:00:01 192.0.2.9",
                "group 00:00:00:00:00:01 192.0.2.9,192.0.2.20"
            ]
        );
        let table = fdb.table().await;
        assert_eq!(table.macs.len(), 1);
        assert_eq!(table.macs[0].vteps.len(), 2);

        // It stops serving the EVI: back to the plain entry.
        fdb.apply_push(EvpnUpdate::Remove(evi_ad(esi, b).key)).await;
        assert_eq!(
            calls(&driver),
            [
                "group- 00:00:00:00:00:01",
                "set 00:00:00:00:00:01 192.0.2.9"
            ]
        );
        assert_eq!(fdb.table().await.macs[0].vteps.len(), 1);

        // Its own per-ES A-D going is still a mass withdrawal.
        fdb.apply_push(EvpnUpdate::Remove(es_ad(esi, a).key)).await;
        assert_eq!(calls(&driver), ["del 00:00:00:00:00:01 192.0.2.9"]);
        assert_eq!(fdb.table().await.macs, []);
    }

    #[test]
    fn two_routes_for_one_aliased_mac_want_one_and_the_same_group() {
        let (a, b) = (REMOTE, "192.0.2.20");
        let esi = [9; 10];
        let ads = Ads::from([(
            esi,
            SegmentAds {
                pes: [a, b].iter().map(|p| p.parse().unwrap()).collect(),
                evi: [a, b].iter().map(|p| p.parse().unwrap()).collect(),
                single_active: false,
                ..SegmentAds::default()
            },
        )]);
        // The MAC advertised by each PE (each under its own RD): the same item,
        // so the second route neither reinstalls nor flaps the first.
        let mut from_a = mac_route(1, 10100, RT, a);
        from_a.esi = esi;
        let mut from_b = mac_route(1, 10100, RT, b);
        from_b.esi = esi;
        assert_eq!(
            want_ads(&ready(), &from_a, &ads),
            want_ads(&ready(), &from_b, &ads)
        );
        assert!(matches!(
            want_ads(&ready(), &from_a, &ads)[..],
            [Installed::MacGroup { .. }]
        ));
    }
}
