//! VPN-IPv4/IPv6 Adj-RIB-In, best path, reflection, GR and refresh (#578).

use super::*;
use crate::rib::vpn_out::AdvertisedVpn;
use crate::vpn::{Rd, VpnNlri};

pub(super) const SRC: &str = "10.0.0.1"; // eBGP source, AS 65001
pub(super) const EBGP: &str = "10.0.0.3"; // eBGP observer, AS 65003
pub(super) const IBGP: &str = "10.0.0.4"; // iBGP observer, not a client
const CLIENT: &str = "10.0.0.5"; // iBGP observer, route-reflector client
const CLIENT_SRC: &str = "10.0.0.6"; // iBGP source, client
const I1: &str = "10.0.0.7"; // iBGP source, not a client

pub(super) const RD1: Rd = [0, 0, 0xfd, 0xe9, 0, 0, 0, 1]; // 65001:1
const RD2: Rd = [0, 0, 0xfd, 0xe9, 0, 0, 0, 2]; // 65001:2
pub(super) const RT: u64 = 0x0002_fde8_0000_0001; // RT:65000:1
pub(super) const P: &str = "10.10.0.0/24";

pub(super) fn nlri(rd: Rd, p: &str, label: u32) -> VpnNlri {
    VpnNlri {
        labels: vec![label],
        rd,
        prefix: prefix(p),
    }
}

fn key(rd: Rd, p: &str) -> VpnKey<IpNet> {
    (rd, prefix(p))
}

fn batch_afi(n: &VpnNlri) -> u16 {
    if n.prefix.addr().is_ipv6() {
        2
    } else {
        1
    }
}

pub(super) fn reach(next_hop: &str, as_path: Vec<u32>, vpn: Vec<VpnNlri>) -> UpdateMessage {
    let mut u = ebgp_update(vec![], as_path, "0.0.0.0");
    u.attributes.as_mut().unwrap().extended_communities = vec![RT];
    u.mp_reach = vec![message::MpReachNlri {
        afi: batch_afi(&vpn[0]),
        safi: message::SAFI_VPN,
        next_hop: addr(next_hop),
        nlri: vec![],
        nlri_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![],
        rtc: vec![],
        vpn,
    }];
    u
}

fn unreach(vpn: Vec<VpnNlri>) -> UpdateMessage {
    let mut u = empty_update();
    u.mp_unreach = vec![message::MpUnreachNlri {
        afi: batch_afi(&vpn[0]),
        safi: message::SAFI_VPN,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![],
        rtc: vec![],
        vpn,
    }];
    u
}

fn afs() -> HashSet<AddressFamily> {
    HashSet::from([
        AddressFamily::Ipv4Unicast,
        AddressFamily::Vpnv4Unicast,
        AddressFamily::Vpnv6Unicast,
    ])
}

fn reg(
    rib: &mut BgpRib,
    peer: &str,
    ibgp: bool,
    rr_client: bool,
    afs: HashSet<AddressFamily>,
) -> mpsc::Receiver<OutboundUpdate> {
    let (tx, rx) = test_channel();
    rib.peer_established(
        addr(peer),
        ibgp,
        Some(addr("10.0.0.254")),
        afs,
        true,
        None,
        rr_client,
        false,
        HashSet::new(),
        accept_all_policy(),
        tx,
    );
    rx
}

/// AS 65000, router-id/cluster-id 1.1.1.1; receivers in the order SRC,
/// EBGP, IBGP, CLIENT, `CLIENT_SRC`, I1.
pub(super) fn setup() -> (BgpRib, Vec<mpsc::Receiver<OutboundUpdate>>) {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.set_peer_asn(addr(SRC), 65001);
    rib.set_peer_asn(addr(EBGP), 65003);
    let rx = vec![
        reg(&mut rib, SRC, false, false, afs()),
        reg(&mut rib, EBGP, false, false, afs()),
        reg(&mut rib, IBGP, true, false, afs()),
        reg(&mut rib, CLIENT, true, true, afs()),
        reg(&mut rib, CLIENT_SRC, true, true, afs()),
        reg(&mut rib, I1, true, false, afs()),
    ];
    (rib, rx)
}

pub(super) fn feed(rib: &mut BgpRib, peer: &str, ibgp: bool, u: &UpdateMessage) {
    rib.handle_update(addr(peer), ibgp, v4("2.2.2.2"), u, &nos_rpl::ACCEPT_ALL);
}

fn vpns(rx: &mut mpsc::Receiver<OutboundUpdate>) -> Vec<OutboundUpdate> {
    recv_all(rx)
        .into_iter()
        .filter(|u| {
            matches!(
                u,
                OutboundUpdate::AnnounceVpn(_) | OutboundUpdate::WithdrawVpn(_)
            )
        })
        .collect()
}

pub(super) fn advs(rx: &mut mpsc::Receiver<OutboundUpdate>) -> Vec<AdvertisedVpn> {
    vpns(rx)
        .into_iter()
        .filter_map(|u| match u {
            OutboundUpdate::AnnounceVpn(a) => Some(a),
            _ => None,
        })
        .collect()
}

fn held(rib: &BgpRib, family: AddressFamily) -> Vec<(IpAddr, VpnKey<IpNet>, Vec<u32>, bool)> {
    rib.vpn_routes(family)
        .into_iter()
        .map(|(p, k, r, best)| (p, *k, r.labels.clone(), best))
        .collect()
}

/// #723: the paging keys list the same paths in the same order as the old
/// unpaged `vpn_routes`, honour the family and RD filters, and resolve to
/// their path (with `best`); a vanished path resolves to `None`.
#[test]
fn vpn_keys_match_the_unpaged_order_filter_and_resolve() {
    let (mut rib, _rx) = setup();
    let u = reach(
        SRC,
        vec![65001],
        vec![
            nlri(RD2, P, 200),
            nlri(RD1, "10.20.0.0/24", 101),
            nlri(RD1, P, 100),
        ],
    );
    feed(&mut rib, SRC, false, &u);
    let v4 = AddressFamily::Vpnv4Unicast;
    let keys = rib.vpn_keys(v4, None);
    let want: Vec<_> = rib
        .vpn_routes(v4)
        .into_iter()
        .map(|(p, k, ..)| (p, k.0, k.1))
        .collect();
    let got: Vec<_> = keys.iter().map(|c| (c.peer, c.rd, c.prefix)).collect();
    assert_eq!((got.len(), &got), (3, &want));
    for c in &keys {
        let (k, r, best) = rib.vpn_at(c).unwrap();
        assert_eq!((k.0, k.1, best), (c.rd, c.prefix, true));
        assert_eq!(r.labels.len(), 1);
    }
    assert_eq!(rib.vpn_keys(v4, Some(Some(RD1))).len(), 2);
    assert_eq!(rib.vpn_keys(v4, Some(Some(RD2))).len(), 1);
    // An unparsable RD matches nothing, and so does the other family.
    assert_eq!(rib.vpn_keys(v4, Some(None)).len(), 0);
    assert_eq!(rib.vpn_keys(AddressFamily::Vpnv6Unicast, None).len(), 0);
    rib.peer_disconnected(addr(SRC), Disconnect::Transport);
    assert!(keys.iter().all(|c| rib.vpn_at(c).is_none()));
}

#[test]
fn one_prefix_under_two_rds_is_two_routes_both_reflected_labels_unchanged() {
    let (mut rib, mut rx) = setup();
    let u = reach(SRC, vec![65001], vec![nlri(RD1, P, 100), nlri(RD2, P, 200)]);
    feed(&mut rib, SRC, false, &u);
    assert_eq!(
        held(&rib, AddressFamily::Vpnv4Unicast),
        vec![
            (addr(SRC), key(RD1, P), vec![100], true),
            (addr(SRC), key(RD2, P), vec![200], true),
        ]
    );
    assert_eq!(held(&rib, AddressFamily::Vpnv6Unicast).len(), 0);

    let mut to_ebgp = advs(&mut rx[1]);
    to_ebgp.sort_by_key(|a| a.key);
    assert_eq!(to_ebgp.len(), 2);
    assert_eq!(
        (to_ebgp[0].key, to_ebgp[0].labels.clone()),
        (key(RD1, P), vec![100])
    );
    assert_eq!(
        (to_ebgp[1].key, to_ebgp[1].labels.clone()),
        (key(RD2, P), vec![200])
    );
    // eBGP prepend, but the next hop stays the egress PE (the label is its).
    assert_eq!(to_ebgp[0].route.as_path, vec![65000u32, 65001]);
    assert_eq!(to_ebgp[0].route.next_hop, addr(SRC));
    assert_eq!(to_ebgp[0].route.extended_communities, vec![RT]);
    let internal = advs(&mut rx[2]);
    assert_eq!(internal.len(), 2);
    assert_eq!(internal[0].route.local_pref, Some(100));
    assert_eq!(advs(&mut rx[3]).len(), 2);
    // Split horizon.
    assert_eq!(vpns(&mut rx[0]).len(), 0);

    // A re-announcement replaces the stored copy and is re-sent.
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, P, 101)]),
    );
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast)[0].2, vec![101]);
    assert_eq!(advs(&mut rx[1])[0].labels, vec![101]);
    // An identical one is no change.
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, P, 101)]),
    );
    assert_eq!(vpns(&mut rx[1]).len(), 0);

    // An explicit withdrawal (no label) removes RD1 only.
    let mut w = nlri(RD1, P, 0);
    w.labels.clear();
    feed(&mut rib, SRC, false, &unreach(vec![w]));
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 1);
    assert_eq!(
        vpns(&mut rx[1]),
        vec![OutboundUpdate::WithdrawVpn(key(RD1, P))]
    );

    // Peer loss withdraws what is left.
    rib.peer_disconnected(addr(SRC), Disconnect::Hard);
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 0);
    assert_eq!(
        vpns(&mut rx[1]),
        vec![OutboundUpdate::WithdrawVpn(key(RD2, P))]
    );
}

#[test]
fn reflection_follows_rfc_4456_and_loops_are_dropped() {
    let (mut rib, mut rx) = setup();
    for r in &mut rx {
        recv_all(r);
    }
    // A client's route goes to clients, non-clients and eBGP.
    feed(
        &mut rib,
        CLIENT_SRC,
        true,
        &reach("10.0.0.6", vec![], vec![nlri(RD1, P, 100)]),
    );
    let to_ibgp = advs(&mut rx[2]);
    assert_eq!(to_ibgp.len(), 1, "client route to a non-client");
    assert_eq!(to_ibgp[0].route.originator_id, Some(v4("2.2.2.2")));
    assert_eq!(to_ibgp[0].route.cluster_list, vec![v4("1.1.1.1")]);
    assert_eq!(to_ibgp[0].labels, vec![100]);
    assert_eq!(to_ibgp[0].key, key(RD1, P));
    assert_eq!(advs(&mut rx[3]).len(), 1);
    assert_eq!(advs(&mut rx[1]).len(), 1);

    // A non-client's route goes to clients only (and eBGP).
    feed(
        &mut rib,
        I1,
        true,
        &reach("10.0.0.7", vec![], vec![nlri(RD2, P, 200)]),
    );
    assert_eq!(advs(&mut rx[2]).len(), 0, "non-client to non-client");
    assert_eq!(advs(&mut rx[3]).len(), 1);
    assert_eq!(advs(&mut rx[1]).len(), 1);

    // Our own cluster id: dropped, the held copy withdrawn.
    let mut looped = reach("10.0.0.6", vec![], vec![nlri(RD1, P, 100)]);
    looped.attributes.as_mut().unwrap().cluster_list = vec![v4("1.1.1.1")];
    feed(&mut rib, CLIENT_SRC, true, &looped);
    assert!(!held(&rib, AddressFamily::Vpnv4Unicast)
        .iter()
        .any(|(p, ..)| *p == addr(CLIENT_SRC)));
    assert_eq!(
        vpns(&mut rx[3]),
        vec![OutboundUpdate::WithdrawVpn(key(RD1, P))]
    );
    // Our own router id as ORIGINATOR_ID: dropped too.
    let mut own = reach("10.0.0.7", vec![], vec![nlri(RD2, P, 200)]);
    own.attributes.as_mut().unwrap().originator_id = Some(v4("1.1.1.1"));
    feed(&mut rib, I1, true, &own);
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 0);
}

#[test]
fn best_path_is_per_rd_and_prefix() {
    let (mut rib, mut rx) = setup();
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, P, 1), nlri(RD2, P, 2)]),
    );
    // I1 has the same (RD1, P) with a higher LOCAL_PREF: it wins RD1 only.
    let mut better = reach("10.0.0.7", vec![], vec![nlri(RD1, P, 7)]);
    better.attributes.as_mut().unwrap().local_pref = Some(200);
    feed(&mut rib, I1, true, &better);
    let best: Vec<_> = held(&rib, AddressFamily::Vpnv4Unicast)
        .into_iter()
        .filter(|h| h.3)
        .map(|h| (h.0, h.1))
        .collect();
    assert_eq!(
        best,
        vec![(addr(SRC), key(RD2, P)), (addr(I1), key(RD1, P))]
    );
    // SRC now gets I1's RD1 path (the best is not its own any more).
    let to_src = advs(&mut rx[0]);
    assert!(to_src
        .iter()
        .any(|a| a.key == key(RD1, P) && a.labels == [7]));
    // I1 withdraws: SRC's copy is best again.
    let mut w = nlri(RD1, P, 0);
    w.labels.clear();
    feed(&mut rib, I1, true, &unreach(vec![w]));
    assert!(held(&rib, AddressFamily::Vpnv4Unicast).iter().all(|h| h.3));
}

#[test]
fn import_policy_reject_drops_a_held_route_and_rts_never_gate_storage() {
    let (mut rib, mut rx) = setup();
    // No Route Target at all: still stored (RTs only gate VRF import).
    let mut u = reach(SRC, vec![65001], vec![nlri(RD1, P, 1)]);
    u.attributes.as_mut().unwrap().extended_communities.clear();
    feed(&mut rib, SRC, false, &u);
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 1);
    recv_all(&mut rx[1]);
    let reject = nos_rpl::compile(
        "if this.prefix == 10.10.0.0/24:\n    reject\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    rib.handle_update(addr(SRC), false, v4("2.2.2.2"), &u, &reject);
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 0);
    assert_eq!(rib.peer_stats(addr(SRC)).rejected, 1, "BMP stat 0");
    assert_eq!(
        vpns(&mut rx[1]),
        vec![OutboundUpdate::WithdrawVpn(key(RD1, P))]
    );
}

#[test]
fn a_family_not_negotiated_or_a_martian_next_hop_is_not_held() {
    let mut rib = new_rib(65000);
    let _rx = reg(
        &mut rib,
        SRC,
        false,
        false,
        HashSet::from([AddressFamily::Ipv4Unicast, AddressFamily::Vpnv4Unicast]),
    );
    let v6 = reach(SRC, vec![65001], vec![nlri(RD1, "2001:db8:1::/48", 5)]);
    feed(&mut rib, SRC, false, &v6);
    assert_eq!(held(&rib, AddressFamily::Vpnv6Unicast).len(), 0);

    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, P, 1)]),
    );
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 1);
    // A martian next hop is treat-as-withdraw.
    feed(
        &mut rib,
        SRC,
        false,
        &reach("0.0.0.0", vec![65001], vec![nlri(RD1, P, 1)]),
    );
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 0);
}

#[test]
fn graceful_restart_keeps_listed_vpn_families_until_end_of_rib() {
    assert_eq!(
        crate::gr::family_of(1, 128),
        Some(AddressFamily::Vpnv4Unicast)
    );
    assert_eq!(
        crate::gr::our_cap(60, &[AddressFamily::Vpnv6Unicast], false, false).families[0].safi,
        128
    );
    let (mut rib, mut rx) = setup();
    rib.set_peer_gr(
        addr(SRC),
        Some(gr(true, &[(AddressFamily::Vpnv4Unicast, true)])),
    );
    feed(
        &mut rib,
        SRC,
        false,
        &reach(
            SRC,
            vec![65001],
            vec![nlri(RD1, P, 1), nlri(RD2, "10.20.0.0/24", 2)],
        ),
    );
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, "2001:db8:1::/48", 3)]),
    );
    recv_all(&mut rx[1]);
    rib.peer_disconnected(addr(SRC), Disconnect::Transport);
    // VPNv4 retained (stale), VPNv6 not listed: gone.
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 2);
    assert_eq!(held(&rib, AddressFamily::Vpnv6Unicast).len(), 0);
    assert_eq!(rib.stale_count(addr(SRC)), 2);
    assert_eq!(
        vpns(&mut rx[1]),
        vec![OutboundUpdate::WithdrawVpn(key(RD1, "2001:db8:1::/48"))]
    );

    let _src = reg(&mut rib, SRC, false, false, afs());
    // Re-mentioned: no longer stale; the other one goes at End-of-RIB.
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, P, 1)]),
    );
    assert_eq!(rib.stale_count(addr(SRC)), 1);
    rib.end_of_rib(addr(SRC), AddressFamily::Vpnv4Unicast);
    assert_eq!(
        held(&rib, AddressFamily::Vpnv4Unicast)
            .into_iter()
            .map(|h| h.1)
            .collect::<Vec<_>>(),
        vec![key(RD1, P)]
    );
    assert_eq!(rib.stale_count(addr(SRC)), 0);
    assert!(vpns(&mut rx[1]).contains(&OutboundUpdate::WithdrawVpn(key(RD2, "10.20.0.0/24"))));
}

#[test]
fn route_refresh_resends_and_enhanced_refresh_purges_per_vpn_family() {
    let (mut rib, mut rx) = setup();
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, P, 1), nlri(RD2, P, 2)]),
    );
    recv_all(&mut rx[1]);
    rib.resend_all(addr(EBGP), AddressFamily::Vpnv4Unicast, true);
    let got = recv_all(&mut rx[1]);
    assert_eq!(got.len(), 4, "BoRR, two routes, EoRR: {got:?}");
    assert!(matches!(
        got[0],
        OutboundUpdate::RefreshMarker {
            family: AddressFamily::Vpnv4Unicast,
            subtype: message::REFRESH_BORR
        }
    ));
    assert!(matches!(got[1], OutboundUpdate::AnnounceVpn(_)));
    // Nothing of the other VPN family.
    rib.resend_all(addr(EBGP), AddressFamily::Vpnv6Unicast, false);
    assert_eq!(vpns(&mut rx[1]).len(), 0);

    // RFC 7313 inbound: only the re-announced key survives the EoRR.
    rib.begin_refresh_in(addr(SRC), AddressFamily::Vpnv4Unicast);
    assert_eq!(rib.stale_count(addr(SRC)), 2);
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD2, P, 2)]),
    );
    assert_eq!(
        rib.end_refresh_in(addr(SRC), AddressFamily::Vpnv4Unicast),
        1
    );
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast)[0].1, key(RD2, P));
}

#[test]
fn maximum_prefix_counts_the_vpn_families() {
    let (mut rib, _rx) = setup();
    let limit = Some(nos_proto::BgpPrefixLimit {
        limit: 1,
        warning_only: false,
        restart_interval: 0,
    });
    rib.set_peer_max_prefix(
        addr(SRC),
        nos_proto::BgpMaximumPrefix {
            vpnv6: limit,
            ..Default::default()
        },
    );
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, P, 1), nlri(RD2, P, 2)]),
    );
    assert_eq!(
        rib.check_max_prefix(addr(SRC)),
        None,
        "vpnv4 is not limited"
    );
    rib.set_peer_max_prefix(
        addr(SRC),
        nos_proto::BgpMaximumPrefix {
            vpnv4: limit,
            ..Default::default()
        },
    );
    let (family, l, count) = rib.check_max_prefix(addr(SRC)).expect("over");
    assert_eq!(
        (family, l.limit, count),
        (AddressFamily::Vpnv4Unicast, 1, 2)
    );
}

#[test]
fn a_lost_vpn_update_is_resent_from_the_backlog() {
    let (mut rib, mut rx) = setup();
    let (tx, mut tiny) = outbox_channel(addr("10.0.0.9"), 1);
    rib.peer_established(
        addr("10.0.0.9"),
        false,
        Some(addr("10.0.0.254")),
        afs(),
        true,
        None,
        false,
        false,
        HashSet::new(),
        accept_all_policy(),
        tx.clone(),
    );
    recv_all(&mut tiny);
    feed(
        &mut rib,
        SRC,
        false,
        &reach(
            SRC,
            vec![65001],
            vec![
                nlri(RD1, P, 1),
                nlri(RD2, P, 2),
                nlri(RD1, "10.30.0.0/24", 3),
            ],
        ),
    );
    recv_all(&mut rx[1]);
    let mut got = advs(&mut tiny);
    assert!(tx.pending(), "two of three did not fit");
    for _ in 0..10 {
        if !tx.pending() {
            break;
        }
        rib.drain_backlog(addr("10.0.0.9"));
        got.extend(advs(&mut tiny));
    }
    let mut keys: Vec<_> = got.into_iter().map(|a| a.key).collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), 3);
}

// ---- VRF import (#579) ----

const RT2: u64 = 0x0002_fde8_0000_0002; // RT:65000:2

fn vrfs() -> crate::vpn::VrfSet {
    let vrf = |table: &str, import: Vec<u64>| crate::vpn::Vrf {
        table: table.to_string(),
        rd: [0; 8],
        import,
        export: vec![],
        soo: None,
    };
    crate::vpn::VrfSet(vec![vrf("red", vec![RT]), vrf("blue", vec![RT2, RT])])
}

fn with_rts(mut u: UpdateMessage, rts: Vec<u64>) -> UpdateMessage {
    u.attributes.as_mut().unwrap().extended_communities = rts;
    u
}

/// (table, prefix, pe, labels, rd), sorted.
fn imported(rib: &BgpRib) -> Vec<(String, IpNet, IpAddr, Vec<u32>, Rd)> {
    let (_, imports) = rib.vpn_import_snapshot();
    let mut out: Vec<_> = imports
        .unwrap()
        .into_iter()
        .flat_map(|(t, m)| {
            m.into_iter().map(move |(p, i)| {
                let h = i.paths.into_iter().next().unwrap();
                (t.clone(), p, h.pe, h.labels, h.rd)
            })
        })
        .collect();
    out.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    out
}

#[test]
fn vrf_import_is_by_route_target_into_every_matching_table() {
    let (mut rib, _rx) = setup();
    rib.set_vpn_vrfs(vrfs());
    rib.set_routing_table(Some("core".into()));
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, P, 100)]),
    );
    let only_rt2 = with_rts(
        reach(SRC, vec![65001], vec![nlri(RD1, "10.20.0.0/24", 5)]),
        vec![RT2],
    );
    feed(&mut rib, SRC, false, &only_rt2);
    let no_rt = with_rts(
        reach(SRC, vec![65001], vec![nlri(RD1, "10.30.0.0/24", 6)]),
        vec![],
    );
    feed(&mut rib, SRC, false, &no_rt);
    let got = imported(&rib);
    let tp: Vec<_> = got.iter().map(|g| (g.0.as_str(), g.1)).collect();
    assert_eq!(
        tp,
        vec![
            ("blue", prefix(P)),
            ("blue", prefix("10.20.0.0/24")),
            ("red", prefix(P))
        ]
    );
    assert_eq!(
        (got[2].2, got[2].3.clone(), got[2].4),
        (addr(SRC), vec![100], RD1)
    );
    assert_eq!(rib.vpn_import_snapshot().0.as_deref(), Some("core"));

    // An RT change moves the route: P now carries RT2 only.
    let moved = with_rts(reach(SRC, vec![65001], vec![nlri(RD1, P, 100)]), vec![RT2]);
    feed(&mut rib, SRC, false, &moved);
    assert!(imported(&rib).iter().all(|g| g.0 == "blue"));
    // A VRF leaving the set leaves the snapshot; withdraw and peer loss empty it.
    rib.set_vpn_vrfs(crate::vpn::VrfSet(vrfs().0[1..].to_vec()));
    assert!(rib.vpn_import_snapshot().1.unwrap().keys().eq(["blue"]));
    let mut w = nlri(RD1, P, 0);
    w.labels.clear();
    feed(&mut rib, SRC, false, &unreach(vec![w]));
    assert_eq!(imported(&rib).len(), 1);
    rib.peer_disconnected(addr(SRC), crate::gr::Disconnect::Hard);
    assert_eq!(
        imported(&rib),
        [] as [(
            std::string::String,
            nos_proto::IpNet,
            std::net::IpAddr,
            std::vec::Vec<u32>,
            [u8; 8]
        ); 0]
    );
}

#[test]
fn rds_compete_inside_a_vrf_and_a_full_tie_picks_the_lowest_rd() {
    let (mut rib, _rx) = setup();
    rib.set_vpn_vrfs(vrfs());
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD2, P, 2), nlri(RD1, P, 1)]),
    );
    let red =
        |rib: &BgpRib| -> Vec<_> { imported(rib).into_iter().filter(|g| g.0 == "red").collect() };
    let r = red(&rib);
    assert_eq!((r.len(), r[0].4, r[0].3.clone()), (1, RD1, vec![1]));
    // A better path under RD2 from another peer wins the VRF prefix.
    let mut better = reach(I1, vec![], vec![nlri(RD2, P, 7)]);
    better.attributes.as_mut().unwrap().local_pref = Some(200);
    feed(&mut rib, I1, true, &better);
    let r = red(&rib);
    assert_eq!((r[0].2, r[0].4, r[0].3.clone()), (addr(I1), RD2, vec![7]));
}

#[test]
fn an_unfeasible_pe_is_not_imported_until_the_igp_covers_it() {
    let (mut rib, _rx) = setup();
    rib.set_vpn_vrfs(vrfs());
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, P, 1)]),
    );
    // Feasible until the first IGP poll.
    assert_eq!(imported(&rib).len(), 2);
    rib.set_igp(HashMap::from([(prefix("192.0.2.0/24"), 0)]));
    assert_eq!(
        imported(&rib),
        [] as [(
            std::string::String,
            nos_proto::IpNet,
            std::net::IpAddr,
            std::vec::Vec<u32>,
            [u8; 8]
        ); 0]
    );
    rib.set_igp(HashMap::from([(prefix("10.0.0.0/24"), 0)]));
    assert_eq!(imported(&rib).len(), 2);
}

#[test]
fn vrf_import_waits_for_the_end_of_a_graceful_restart_deferral() {
    let (mut rib, _rx) = setup();
    rib.set_vpn_vrfs(vrfs());
    rib.begin_deferral(5, 120, 360, [addr(SRC)]);
    assert_eq!(rib.vpn_import_snapshot(), (None, None));
}

// ------------------------------------------------------------ VRF export (#580)

const RD_RED: Rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1]; // 65000:1
const LOCAL: &str = "10.0.0.254"; // every `reg` session's own address

fn export(p: &str, label: u32) -> nos_proto::VpnPrefix {
    nos_proto::VpnPrefix {
        rd: RD_RED,
        prefix: prefix(p),
        labels: vec![label],
        ext_communities: vec![RT],
    }
}

fn full(routes: Vec<nos_proto::VpnPrefix>) -> nos_proto::VpnPrefixUpdate {
    nos_proto::VpnPrefixUpdate::Full(routes)
}

#[test]
fn a_vrf_export_goes_next_hop_self_with_its_label_to_every_peer_with_the_family() {
    let (mut rib, mut rx) = setup();
    let mut v4_only = reg(
        &mut rib,
        "10.0.0.8",
        true,
        false,
        HashSet::from([AddressFamily::Ipv4Unicast, AddressFamily::Vpnv4Unicast]),
    );
    let mut no_vpn = reg(
        &mut rib,
        "10.0.0.9",
        true,
        false,
        HashSet::from([AddressFamily::Ipv4Unicast]),
    );
    rib.apply_vpn_prefixes(
        "red",
        full(vec![export(P, 1000), export("2001:db8:1::/48", 1000)]),
    );

    let mut to_ebgp = advs(&mut rx[1]);
    to_ebgp.sort_by_key(|a| a.key.1);
    assert_eq!(to_ebgp.len(), 2);
    for a in &to_ebgp {
        assert_eq!(a.labels, vec![1000]);
        // VPNv6 too: the codec maps the IPv4 session address (RFC 4659).
        assert_eq!(a.route.next_hop, addr(LOCAL));
        assert_eq!(a.route.as_path, vec![65000u32]);
        assert_eq!(a.route.extended_communities, vec![RT]);
        assert_eq!(a.route.local_pref, None);
    }
    assert_eq!(to_ebgp[0].key, key(RD_RED, P));
    // iBGP: empty path, LOCAL_PREF, and a local route is no reflection.
    let internal = advs(&mut rx[2]);
    assert_eq!(internal.len(), 2);
    assert!(internal[0].route.as_path.is_empty());
    assert_eq!(internal[0].route.local_pref, Some(100));
    assert_eq!(internal[0].route.next_hop, addr(LOCAL));
    assert_eq!(internal[0].route.cluster_list, Vec::<Ipv4Addr>::new());
    let v4: Vec<_> = advs(&mut v4_only).into_iter().map(|a| a.key).collect();
    assert_eq!(v4, vec![key(RD_RED, P)]);
    assert_eq!(vpns(&mut no_vpn), [] as [OutboundUpdate; 0]);
    // Not shown as a received path.
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 0);
}

#[test]
fn a_label_change_reannounces_a_remove_withdraws_and_tables_are_isolated() {
    let (mut rib, mut rx) = setup();
    rib.apply_vpn_prefixes("red", full(vec![export(P, 1000)]));
    let other = nos_proto::VpnPrefix {
        rd: RD2,
        ..export("10.30.0.0/24", 1001)
    };
    rib.apply_vpn_prefixes("blue", full(vec![other.clone()]));
    assert_eq!(advs(&mut rx[1]).len(), 2);

    // Same route again: nothing; a new label: an implicit replace.
    rib.apply_vpn_prefixes("red", nos_proto::VpnPrefixUpdate::Add(export(P, 1000)));
    assert_eq!(vpns(&mut rx[1]), [] as [OutboundUpdate; 0]);
    rib.apply_vpn_prefixes("red", nos_proto::VpnPrefixUpdate::Add(export(P, 1002)));
    let got = vpns(&mut rx[1]);
    assert_eq!(got.len(), 1);
    assert!(matches!(&got[0], OutboundUpdate::AnnounceVpn(a) if a.labels == [1002]));

    // `red`'s `Full([])` (vpn removed) withdraws red's only.
    rib.apply_vpn_prefixes("red", full(vec![]));
    assert_eq!(
        vpns(&mut rx[1]),
        vec![OutboundUpdate::WithdrawVpn(key(RD_RED, P))]
    );
    rib.apply_vpn_prefixes(
        "blue",
        nos_proto::VpnPrefixUpdate::Remove(RD2, prefix("10.30.0.0/24")),
    );
    assert_eq!(
        vpns(&mut rx[1]),
        vec![OutboundUpdate::WithdrawVpn(key(RD2, "10.30.0.0/24"))]
    );
}

/// #791: parts are staged by `server.rs`; one reaching the RIB is a no-op
/// and creates no table slot.
#[test]
fn a_stray_full_part_changes_nothing() {
    let (mut rib, mut rx) = setup();
    rib.apply_vpn_prefixes("red", full(vec![export(P, 1000)]));
    assert_eq!(advs(&mut rx[1]).len(), 1);
    rib.apply_vpn_prefixes("red", nos_proto::VpnPrefixUpdate::FullPart(vec![]));
    rib.apply_vpn_prefixes(
        "blue",
        nos_proto::VpnPrefixUpdate::FullPart(vec![export("10.30.0.0/24", 1)]),
    );
    assert_eq!(vpns(&mut rx[1]), [] as [OutboundUpdate; 0]);
    assert_eq!(rib.vpn_local_len(), 1);
}

#[test]
fn the_export_policy_runs_on_a_vrf_export() {
    let mut rib = new_rib(65000);
    let (tx, mut rx) = test_channel();
    let reject = nos_rpl::compile(
        "if this.prefix == 10.10.0.0/24:\n    reject\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    rib.peer_established(
        addr(EBGP),
        false,
        Some(addr(LOCAL)),
        afs(),
        true,
        None,
        false,
        false,
        HashSet::new(),
        Arc::new(reject),
        tx,
    );
    rib.apply_vpn_prefixes(
        "red",
        full(vec![export(P, 1000), export("10.11.0.0/24", 1000)]),
    );
    let sent: Vec<_> = advs(&mut rx).into_iter().map(|a| a.key).collect();
    assert_eq!(sent, vec![key(RD_RED, "10.11.0.0/24")]);
}

#[test]
fn a_vrf_export_waits_for_the_end_of_a_deferral_and_reaches_a_late_peer() {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.set_peer_asn(addr(SRC), 65001);
    rib.begin_deferral(1, 120, 360, [addr(SRC)]);
    let mut src = reg(&mut rib, SRC, false, false, afs());
    rib.apply_vpn_prefixes("red", full(vec![export(P, 1000)]));
    assert_eq!(vpns(&mut src), [] as [OutboundUpdate; 0], "deferred");
    rib.apply_redistribute_update(RedistributeUpdate::Full(Vec::new()));
    for family in AddressFamily::ALL {
        rib.end_of_rib(addr(SRC), family);
    }
    assert!(!rib.deferring());
    assert_eq!(advs(&mut src).len(), 1);
    // A session coming up later gets it in its initial update; its loss
    // forgets what it was sent.
    let mut late = reg(&mut rib, EBGP, false, false, afs());
    assert_eq!(advs(&mut late).len(), 1);
    rib.peer_disconnected(addr(EBGP), Disconnect::Hard);
    rib.apply_vpn_prefixes("red", full(vec![]));
    assert_eq!(vpns(&mut late), [] as [OutboundUpdate; 0]);
    assert_eq!(
        vpns(&mut src),
        vec![OutboundUpdate::WithdrawVpn(key(RD_RED, P))]
    );
}

/// A local export and a received path under the same (RD, prefix): the
/// local one wins (decision step 2) and the peer gets it back.
#[test]
fn a_local_export_beats_a_received_copy_of_the_same_key() {
    let (mut rib, mut rx) = setup();
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD_RED, P, 5)]),
    );
    recv_all(&mut rx[0]);
    rib.apply_vpn_prefixes("red", full(vec![export(P, 1000)]));
    let to_src = advs(&mut rx[0]);
    assert_eq!(to_src.len(), 1);
    assert_eq!(
        (to_src[0].labels.clone(), to_src[0].route.next_hop),
        (vec![1000], addr(LOCAL))
    );
    assert!(!held(&rib, AddressFamily::Vpnv4Unicast)[0].3);
}

// ------------------------------------------------- Site of Origin, RPL hooks (#582)

const RT3: u64 = 0x0002_fde8_0000_0003; // RT:65000:3, imported nowhere
const SOO77: u64 = 0x0003_fde9_0000_004d; // 65001:77
const SOO99: u64 = 0x0003_fde9_0000_0063; // 65001:99

fn script(src: &str) -> nos_rpl::CompiledPolicy {
    nos_rpl::compile(src, &nos_rpl::Symbols::EMPTY).unwrap()
}

fn feed_with(rib: &mut BgpRib, u: &UpdateMessage, policy: &nos_rpl::CompiledPolicy) {
    rib.handle_update(addr(SRC), false, v4("2.2.2.2"), u, policy);
}

fn tables_of(rib: &BgpRib) -> Vec<String> {
    imported(rib).into_iter().map(|g| g.0).collect()
}

/// RFC 4364 section 7: a route carrying a VRF's own Site of Origin is not
/// imported into it (another table still takes it), a foreign one is, and it
/// returns the moment the table's Site of Origin changes.
#[test]
fn a_route_carrying_the_tables_own_site_of_origin_is_not_imported_back() {
    let (mut rib, _rx) = setup();
    let mut set = vrfs();
    set.0[0].soo = Some(SOO77);
    rib.set_vpn_vrfs(set.clone());
    let with = |soo: Option<u64>| {
        let mut ext = vec![RT];
        ext.extend(soo);
        with_rts(reach(SRC, vec![65001], vec![nlri(RD1, P, 100)]), ext)
    };
    feed(&mut rib, SRC, false, &with(Some(SOO77)));
    assert_eq!(tables_of(&rib), ["blue"], "red is the origin site");
    assert_eq!(
        rib.vpn_soo_skipped(),
        HashSet::from([("red".to_string(), RD1, prefix(P), SOO77)])
    );
    // A foreign SoO, then none: both import everywhere.
    for soo in [Some(SOO99), None] {
        feed(&mut rib, SRC, false, &with(soo));
        assert_eq!(tables_of(&rib), ["blue", "red"]);
        assert!(rib.vpn_soo_skipped().is_empty());
    }
    // Back to the own SoO, then the table's SoO changes: it is imported again.
    feed(&mut rib, SRC, false, &with(Some(SOO77)));
    assert_eq!(tables_of(&rib), ["blue"]);
    set.0[0].soo = Some(SOO99);
    rib.set_vpn_vrfs(set);
    assert_eq!(tables_of(&rib), ["blue", "red"]);
}

/// The import policy runs when the path is stored, before import by RT: an
/// RT added there steers the route into a table it did not match, and the
/// stored (and reflected) path carries the edit.
#[test]
fn an_import_policy_adding_an_rt_imports_into_a_table_that_did_not_match() {
    let (mut rib, _rx) = setup();
    rib.set_vpn_vrfs(vrfs());
    let foreign = with_rts(reach(SRC, vec![65001], vec![nlri(RD1, P, 100)]), vec![RT3]);
    feed(&mut rib, SRC, false, &foreign);
    assert_eq!(tables_of(&rib), [] as [String; 0]);
    feed_with(
        &mut rib,
        &foreign,
        &script("this.bgp.extended_communities.add(rt(65000:1))\naccept\n"),
    );
    assert_eq!(tables_of(&rib), ["blue", "red"]);
    let (_, _, route, _) = &rib.vpn_routes(AddressFamily::Vpnv4Unicast)[0].clone();
    assert_eq!(route.route.extended_communities, vec![RT3, RT]);
}

/// A reject by RD withdraws the held copy (and so its import); another RD
/// is untouched.
#[test]
fn an_import_policy_rejecting_by_rd_withdraws_a_held_route() {
    let (mut rib, _rx) = setup();
    rib.set_vpn_vrfs(vrfs());
    let both = reach(
        SRC,
        vec![65001],
        vec![nlri(RD1, P, 1), nlri(RD2, "10.20.0.0/24", 2)],
    );
    feed(&mut rib, SRC, false, &both);
    assert_eq!(imported(&rib).len(), 4);
    feed_with(
        &mut rib,
        &both,
        &script("if this.bgp.rd == rd(65001:1):\n    reject\naccept\n"),
    );
    let left = imported(&rib);
    assert_eq!(left.len(), 2);
    assert!(left
        .iter()
        .all(|g| g.1 == prefix("10.20.0.0/24") && g.4 == RD2));
}

/// The export policy runs after the RTs and Site of Origin ribd attached: it can remove
/// an RT and see the RD, and an unrelated community (the Site of Origin) rides on.
#[test]
fn an_export_policy_edits_the_rts_and_matches_the_rd() {
    let mut rib = new_rib(65000);
    let (tx, mut rx) = test_channel();
    rib.peer_established(
        addr(EBGP),
        false,
        Some(addr(LOCAL)),
        afs(),
        true,
        None,
        false,
        false,
        HashSet::new(),
        Arc::new(script(
            "if this.bgp.rd == rd(65000:9):\n    reject\nthis.bgp.extended_communities.remove(rt(65000:1))\nthis.bgp.extended_communities.add(rt(65000:2))\naccept\n",
        )),
        tx,
    );
    let mut red = export(P, 1000);
    red.ext_communities = vec![RT, SOO77];
    let mut other = export("10.11.0.0/24", 1000);
    other.rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 9]; // 65000:9
    rib.apply_vpn_prefixes("red", full(vec![red, other]));
    let sent = advs(&mut rx);
    assert_eq!(sent.len(), 1, "the RD match rejected the other");
    assert_eq!(sent[0].route.extended_communities, vec![SOO77, RT2]);
}

// ---- VRF import multipath (#595) ----

const PE1: &str = "10.0.0.11";
const PE2: &str = "10.0.0.12";
const PE3: &str = "10.0.0.13";
const RD3: Rd = [0, 0, 0xfd, 0xe9, 0, 0, 0, 3]; // 65001:3

/// Feeds `P` from `peer` (AS path `as_path`) with next hop `pe`, under `rd`.
fn learn(rib: &mut BgpRib, peer: &str, as_path: Vec<u32>, pe: &str, rd: Rd, label: u32) {
    feed(
        rib,
        peer,
        false,
        &reach(pe, as_path, vec![nlri(rd, P, label)]),
    );
}

/// (pe, labels, rd) of `red`'s paths for `P`.
fn red_paths(rib: &BgpRib) -> Vec<(IpAddr, Vec<u32>, Rd)> {
    let imports = rib.vpn_import_snapshot().1.unwrap();
    imports["red"][&prefix(P)]
        .paths
        .iter()
        .map(|p| (p.pe, p.labels.clone(), p.rd))
        .collect()
}

fn mp_rib(max: Option<u8>) -> BgpRib {
    let (mut rib, _rx) = setup();
    rib.set_vpn_vrfs(vrfs());
    rib.set_maximum_paths(max);
    rib
}

#[test]
fn import_multipath_takes_ties_across_rds_and_caps_at_maximum_paths() {
    let mut rib = mp_rib(Some(2));
    learn(&mut rib, SRC, vec![65001], PE2, RD2, 2);
    learn(&mut rib, SRC, vec![65001], PE1, RD1, 1);
    learn(&mut rib, SRC, vec![65001], PE3, RD3, 3);
    // The oldest path (RD2, step 8) is best, then the next in decision order.
    assert_eq!(
        red_paths(&rib),
        vec![(addr(PE1), vec![1], RD1), (addr(PE2), vec![2], RD2)]
    );
    rib.set_maximum_paths(Some(3));
    assert_eq!(red_paths(&rib).len(), 3);
    rib.set_maximum_paths(None);
    assert_eq!(red_paths(&rib), vec![(addr(PE2), vec![2], RD2)]);
}

#[test]
fn import_multipath_needs_the_same_neighbouring_as_and_equal_preference() {
    let mut rib = mp_rib(Some(4));
    learn(&mut rib, SRC, vec![65001], PE1, RD1, 1);
    // Other neighbouring AS: not eligible.
    learn(&mut rib, EBGP, vec![65003], PE2, RD2, 2);
    assert_eq!(red_paths(&rib).len(), 1);
    // Same AS but a longer path loses on step 3.
    learn(&mut rib, EBGP, vec![65001, 65009], PE2, RD2, 2);
    assert_eq!(red_paths(&rib).len(), 1);
    // Same AS, equal path: joins.
    learn(&mut rib, EBGP, vec![65001], PE2, RD2, 2);
    assert_eq!(red_paths(&rib).len(), 2);
}

#[test]
fn import_multipath_keeps_one_pe_under_two_labels_and_collapses_identical_pairs() {
    let mut rib = mp_rib(Some(4));
    learn(&mut rib, SRC, vec![65001], PE1, RD1, 1);
    learn(&mut rib, SRC, vec![65001], PE1, RD2, 2);
    assert_eq!(
        red_paths(&rib),
        vec![(addr(PE1), vec![1], RD1), (addr(PE1), vec![2], RD2)]
    );
    // Same PE and label under a third RD: one path.
    learn(&mut rib, SRC, vec![65001], PE1, RD3, 2);
    assert_eq!(red_paths(&rib).len(), 2);
}

#[test]
fn import_multipath_drops_an_unfeasible_pe() {
    let mut rib = mp_rib(Some(4));
    learn(&mut rib, SRC, vec![65001], PE1, RD1, 1);
    learn(&mut rib, SRC, vec![65001], "10.1.0.11", RD2, 2);
    assert_eq!(red_paths(&rib).len(), 2);
    rib.set_igp(HashMap::from([(prefix("10.0.0.0/24"), 0)]));
    assert_eq!(red_paths(&rib), vec![(addr(PE1), vec![1], RD1)]);
}

#[test]
fn import_multipath_defers_with_graceful_restart() {
    let mut rib = mp_rib(Some(2));
    learn(&mut rib, SRC, vec![65001], PE1, RD1, 1);
    rib.begin_deferral(5, 120, 360, [addr(SRC)]);
    assert_eq!(rib.vpn_import_snapshot(), (None, None));
}

/// RFC 1997 well-known communities gate VPN advertisements too (#873).
#[test]
fn no_export_blocks_vpn_to_ebgp_but_not_ibgp() {
    let (mut rib, mut rx) = setup();
    let mut u = reach(SRC, vec![65001], vec![nlri(RD1, P, 100)]);
    u.attributes.as_mut().unwrap().communities = vec![message::COMMUNITY_NO_EXPORT];
    feed(&mut rib, SRC, false, &u);
    assert_eq!(advs(&mut rx[1]).len(), 0, "eBGP observer");
    assert_eq!(advs(&mut rx[2]).len(), 1, "iBGP observer");
}

fn vpn_policies(script: &str) -> crate::rib::ImportPolicies {
    nos_rpl::compile(script, &nos_rpl::Symbols::EMPTY)
        .map(|p| crate::rib::ImportPolicies::from(Arc::new(p)))
        .unwrap()
}

#[test]
fn reevaluation_readmits_both_rds_and_a_withdrawal_drops_the_raw_copy() {
    let (mut rib, _rx) = setup();
    let src = addr(SRC);
    rib.set_peer_soft_reconfig(src, true);
    let u = reach(SRC, vec![65001], vec![nlri(RD1, P, 100), nlri(RD2, P, 200)]);
    rib.handle_update(src, false, v4("2.2.2.2"), &u, &nos_rpl::DENY_ALL);
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 0);
    assert_eq!(rib.retained_count(src), 2);
    // Loosen: both RDs return, each its own best.
    let fams = rib.reevaluate_peer(src, vpn_policies("accept\n"));
    let f = fams
        .iter()
        .find(|f| f.family == nos_proto::ReevalFamily::Vpnv4)
        .unwrap();
    assert_eq!((f.retained, f.accepted), (2, 2));
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 2);
    // A rewrite applies to the raw path, once.
    rib.reevaluate_peer(
        src,
        vpn_policies("this.bgp.communities.add(65000:7)\naccept\n"),
    );
    rib.reevaluate_peer(
        src,
        vpn_policies("this.bgp.communities.add(65000:9)\naccept\n"),
    );
    let communities: Vec<_> = rib.vpn_adj_rib_in[&src]
        .values()
        .map(|r| r.route.communities.clone())
        .collect();
    assert!(communities.iter().all(|c| *c == vec![(65000 << 16) | 9]));
    // Tighten, then withdraw one RD: its raw copy goes with it.
    rib.reevaluate_peer(src, vpn_policies("reject\n"));
    assert_eq!(held(&rib, AddressFamily::Vpnv4Unicast).len(), 0);
    assert_eq!(rib.retained_count(src), 2);
    rib.handle_update(
        src,
        false,
        v4("2.2.2.2"),
        &unreach(vec![nlri(RD1, P, 100)]),
        &nos_rpl::DENY_ALL,
    );
    assert_eq!(rib.retained_count(src), 1);
}
