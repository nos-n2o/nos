// Community/ASN values are conventionally written and read in decimal
// (`65000:100`) — hex/binary notation would make these test fixtures harder
// to read, not easier.
#![allow(clippy::decimal_bitwise_operands)]

use std::net::Ipv4Addr;

use nos_proto::BgpRole::{Customer, Peer, Provider, RouteServer, RouteServerClient};

use super::*;
use tokio::sync::mpsc;

mod add_path;
mod aggregate;
mod blackhole;
mod bmp_tap;
mod confed;
mod decision;
mod evpn;
mod evpn_gs;
mod evpn_import;
mod first_as;
mod flowspec;
mod flowspec_select;
mod flowspec_validation;
mod gr;
mod graceful_shutdown;
mod next_hop;
mod outbox;
mod policy;
mod propagation;
mod retain;
mod rpl_path;
mod rtc;
mod stats;
mod vpn;

fn prefix(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn addr(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn new_rib(local_asn: u32) -> BgpRib {
    let mut rib = BgpRib::new();
    rib.set_local_identity(local_asn, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED);
    rib
}

fn new_rib_with_identity(local_asn: u32, router_id: Ipv4Addr, cluster_id: Ipv4Addr) -> BgpRib {
    let mut rib = BgpRib::new();
    rib.set_local_identity(local_asn, router_id, cluster_id);
    rib
}

fn all_afs() -> HashSet<AddressFamily> {
    [AddressFamily::Ipv4Unicast, AddressFamily::Ipv6Unicast]
        .into_iter()
        .collect()
}

fn register_peer(
    rib: &mut BgpRib,
    peer: IpAddr,
    is_ibgp: bool,
    local_addr: IpAddr,
) -> mpsc::Receiver<OutboundUpdate> {
    register_peer_with_mode(rib, peer, is_ibgp, local_addr, None)
}

fn register_peer_with_mode(
    rib: &mut BgpRib,
    peer: IpAddr,
    is_ibgp: bool,
    local_addr: IpAddr,
    next_hop_mode: Option<NextHopMode>,
) -> mpsc::Receiver<OutboundUpdate> {
    let (tx, rx) = test_channel();
    rib.peer_established(
        peer,
        is_ibgp,
        Some(local_addr),
        all_afs(),
        false,
        next_hop_mode,
        false,
        false,
        HashSet::new(),
        accept_all_policy(),
        tx,
    );
    rx
}

/// Registers a peer that negotiated MP-BGP (so `Ipv4Unicast` too gets
/// encoded via `MP_REACH_NLRI`/`MP_UNREACH_NLRI`, per
/// `AdvertisedRoute::use_mp`), with a given negotiated AF set.
fn register_mp_peer(
    rib: &mut BgpRib,
    peer: IpAddr,
    is_ibgp: bool,
    local_addr: IpAddr,
    negotiated_afs: HashSet<AddressFamily>,
) -> mpsc::Receiver<OutboundUpdate> {
    let (tx, rx) = test_channel();
    rib.peer_established(
        peer,
        is_ibgp,
        Some(local_addr),
        negotiated_afs,
        true,
        None,
        false,
        false,
        HashSet::new(),
        accept_all_policy(),
        tx,
    );
    rx
}

/// Registers a peer with full control over route-reflector-client/
/// route-server-client/ADD-PATH — for RFC 4456/RFC 7911 tests.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::similar_names)]
fn register_peer_full(
    rib: &mut BgpRib,
    peer: IpAddr,
    is_ibgp: bool,
    local_addr: IpAddr,
    is_rr_client: bool,
    is_rs_client: bool,
    add_path_afs: HashSet<AddressFamily>,
) -> mpsc::Receiver<OutboundUpdate> {
    let (tx, rx) = test_channel();
    rib.peer_established(
        peer,
        is_ibgp,
        Some(local_addr),
        all_afs(),
        false,
        None,
        is_rr_client,
        is_rs_client,
        add_path_afs,
        accept_all_policy(),
        tx,
    );
    rx
}

fn accept_all_policy() -> Arc<CompiledPolicy> {
    Arc::new(nos_rpl::ACCEPT_ALL.clone())
}

fn deny_all_policy() -> Arc<CompiledPolicy> {
    Arc::new(nos_rpl::DENY_ALL.clone())
}

fn full_update(routes: Vec<(&str, &str)>) -> RedistributeUpdate {
    RedistributeUpdate::Full(
        routes
            .into_iter()
            .map(|(p, gw)| nos_proto::RedistributedRoute {
                prefix: prefix(p),
                gateway: addr(gw),
            })
            .collect(),
    )
}

fn recv_all(rx: &mut mpsc::Receiver<OutboundUpdate>) -> Vec<OutboundUpdate> {
    let mut out = Vec::new();
    while let Ok(update) = rx.try_recv() {
        out.push(update);
    }
    out
}

fn ebgp_update(nlri: Vec<&str>, as_path: Vec<u32>, next_hop: &str) -> UpdateMessage {
    UpdateMessage {
        withdrawn_routes: vec![],
        withdrawn_path_ids: vec![],
        nlri: nlri.into_iter().map(|s| s.parse().unwrap()).collect(),
        nlri_path_ids: vec![],
        attributes: Some(message::PathAttributes {
            origin: message::Origin::Igp,
            as_path: as_path.into(),
            next_hop: v4(next_hop),
            local_pref: None,
            med: None,
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            ipv6_extended_communities: Vec::new(),
            pmsi: None,
        }),
        mp_reach: vec![],
        mp_unreach: vec![],
        ..Default::default()
    }
}

fn empty_update() -> UpdateMessage {
    UpdateMessage {
        withdrawn_routes: vec![],
        withdrawn_path_ids: vec![],
        nlri: vec![],
        nlri_path_ids: vec![],
        attributes: None,
        mp_reach: vec![],
        mp_unreach: vec![],
        ..Default::default()
    }
}

fn evpn_nlri(mac_last: u8) -> EvpnNlri {
    EvpnNlri::MacIp {
        rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
        esi: [0; 10],
        tag: 0,
        mac: [0xaa, 0, 0, 0, 0, mac_last],
        ip: None,
        labels: vec![10_000],
    }
}

fn evpn_reach(nlris: Vec<EvpnNlri>, as_path: Vec<u32>) -> UpdateMessage {
    let mut u = ebgp_update(vec![], as_path, "0.0.0.0");
    u.attributes.as_mut().unwrap().extended_communities = vec![0x0002_fde8_0000_2710];
    u.mp_reach = vec![message::MpReachNlri {
        afi: message::AFI_L2VPN,
        safi: message::SAFI_EVPN,
        next_hop: addr("192.0.2.1"),
        nlri: vec![],
        nlri_path_ids: vec![],
        evpn: nlris,
        flowspec: Vec::new(),
        vpn: Vec::new(),
        rtc: Vec::new(),
    }];
    u
}

fn announced(rx: &mut mpsc::Receiver<OutboundUpdate>, p: &str) -> Option<AdvertisedRoute> {
    recv_all(rx).into_iter().find_map(|u| match u {
        OutboundUpdate::Announce(a) if a.prefix == prefix(p) => Some(a),
        _ => None,
    })
}

fn local_as(asn: u32, no_prepend: bool, replace_as: bool) -> nos_proto::BgpLocalAs {
    nos_proto::BgpLocalAs {
        asn,
        no_prepend,
        replace_as,
    }
}

fn update_with(
    nlri: &str,
    as_path: Vec<u32>,
    next_hop: &str,
    origin: message::Origin,
    med: Option<u32>,
) -> UpdateMessage {
    UpdateMessage {
        nlri: vec![nlri.parse().unwrap()],
        attributes: Some(message::PathAttributes {
            origin,
            as_path: as_path.into(),
            next_hop: v4(next_hop),
            local_pref: None,
            med,
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            ipv6_extended_communities: Vec::new(),
            pmsi: None,
        }),
        ..empty_update()
    }
}

const RT: u64 = 0x0002_fde8_0000_0064;

fn v6_update(nlri: Vec<&str>) -> UpdateMessage {
    let mut u = ebgp_update(vec![], vec![65001], "0.0.0.0");
    u.mp_reach = vec![message::MpReachNlri {
        afi: 2,
        safi: 1,
        next_hop: addr("2001:db8::1"),
        nlri: nlri.into_iter().map(prefix).collect(),
        nlri_path_ids: vec![],
        evpn: vec![],
        flowspec: Vec::new(),
        vpn: Vec::new(),
        rtc: Vec::new(),
    }];
    u
}

/// What `accepted_prefixes` must always equal: a full scan.
fn recount(rib: &BgpRib, peer: IpAddr) -> [u32; 3] {
    let table = rib.adj_rib_in.get(&peer);
    let count = |v6: bool| {
        table.map_or(0, |t| {
            let paths = t.iter().filter(|(p, _)| p.addr().is_ipv6() == v6);
            u32::try_from(paths.map(|(_, paths)| paths.len()).sum::<usize>()).unwrap()
        })
    };
    let evpn = rib.evpn_adj_rib_in.get(&peer).map_or(0, HashMap::len);
    [count(false), count(true), u32::try_from(evpn).unwrap()]
}

fn gr(notification: bool, families: &[(AddressFamily, bool)]) -> PeerGr {
    let mut cap = crate::gr::our_cap(120, &[], false, false);
    cap.notification = notification;
    cap.families = families
        .iter()
        .map(|(f, forwarding)| {
            let (afi, safi) = crate::gr::afi_safi(*f);
            message::GrFamily {
                afi,
                safi,
                forwarding: *forwarding,
            }
        })
        .collect();
    PeerGr::from_cap(&cap)
}

/// A peer with GR (`gr`) and v4+v6+EVPN negotiated, holding 1.0.0.0/24,
/// `2.0.0.0/24`, `2001:db8:1::/48` and one EVPN route; plus an observer.
fn gr_rib(gr: Option<PeerGr>) -> (BgpRib, IpAddr, mpsc::Receiver<OutboundUpdate>) {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    rib.set_peer_gr(peer, gr);
    register_gr_peer(&mut rib, peer);
    // A v6 session address: a v6 prefix needs a v6 next hop (#670), and
    // v4 over it is RFC 8950.
    let observer = register_peer(&mut rib, addr("10.0.0.2"), false, addr("2001:db8::fd"));
    for u in [
        ebgp_update(vec!["1.0.0.0/24", "2.0.0.0/24"], vec![65001], "10.0.0.1"),
        v6_update(vec!["2001:db8:1::/48"]),
        evpn_reach(vec![evpn_nlri(1)], vec![65001]),
    ] {
        rib.handle_update(peer, false, v4("192.0.2.1"), &u, &nos_rpl::ACCEPT_ALL);
    }
    (rib, peer, observer)
}

fn register_gr_peer(rib: &mut BgpRib, peer: IpAddr) -> mpsc::Receiver<OutboundUpdate> {
    let (tx, rx) = test_channel();
    let afs = HashSet::from([
        AddressFamily::Ipv4Unicast,
        AddressFamily::Ipv6Unicast,
        AddressFamily::L2vpnEvpn,
    ]);
    rib.peer_established(
        peer,
        false,
        Some(addr("10.0.0.254")),
        afs,
        true,
        None,
        false,
        false,
        HashSet::new(),
        accept_all_policy(),
        tx,
    );
    rx
}

fn withdrawn(rx: &mut mpsc::Receiver<OutboundUpdate>) -> Vec<String> {
    let mut out: Vec<String> = recv_all(rx)
        .into_iter()
        .filter_map(|u| match u {
            OutboundUpdate::Withdraw(p, _, _) => Some(p.to_string()),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

fn agg(p: &str, as_set: bool, summary_only: bool) -> nos_proto::BgpAggregate {
    nos_proto::BgpAggregate {
        prefix: prefix(p),
        as_set,
        summary_only,
    }
}

/// `(announced, withdrawn)` prefixes in `rx`, in order.
fn sent(rx: &mut mpsc::Receiver<OutboundUpdate>) -> (Vec<IpNet>, Vec<IpNet>) {
    let mut out = (Vec::new(), Vec::new());
    for u in recv_all(rx) {
        match u {
            OutboundUpdate::Announce(a) => out.0.push(a.prefix),
            OutboundUpdate::Withdraw(p, _, _) => out.1.push(p),
            _ => {}
        }
    }
    out
}

fn learn(rib: &mut BgpRib, update: &UpdateMessage) {
    rib.handle_update(
        addr("10.0.0.1"),
        false,
        v4("2.2.2.2"),
        update,
        &accept_all_policy(),
    );
}

fn withdraw(nlri: &str) -> UpdateMessage {
    UpdateMessage {
        withdrawn_routes: vec![nlri.parse().unwrap()],
        ..empty_update()
    }
}

/// One RFC 7911 path of `prefix` from AS 65001 with path id `id`.
fn path_update(prefix: &str, id: u32, next_hop: &str, med: Option<u32>) -> UpdateMessage {
    UpdateMessage {
        nlri_path_ids: vec![id],
        ..update_with(prefix, vec![65001], next_hop, message::Origin::Igp, med)
    }
}

fn held_ids(rib: &BgpRib, peer: IpAddr, p: &str) -> Vec<u32> {
    let mut ids: Vec<u32> = rib
        .adj_rib_in
        .get(&peer)
        .and_then(|t| t.get(&prefix(p)))
        .map(|paths| paths.iter().map(|(id, _)| *id).collect())
        .unwrap_or_default();
    ids.sort_unstable();
    ids
}
