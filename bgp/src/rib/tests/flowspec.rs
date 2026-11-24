use super::*;
use crate::flowspec::{Afi, FlowSpec};

fn rule(last: u8) -> FlowSpec {
    FlowSpec::decode(Afi::V4, &[5, 1, 24, 10, last, 0])
        .unwrap()
        .0
}

fn rule6() -> FlowSpec {
    FlowSpec::decode(Afi::V6, &[7, 1, 32, 0, 0x20, 0x01, 0x0d, 0xb8])
        .unwrap()
        .0
}

fn reach(afi: u16, rules: Vec<FlowSpec>) -> UpdateMessage {
    let mut u = ebgp_update(vec![], vec![65001], "0.0.0.0");
    u.attributes.as_mut().unwrap().extended_communities = vec![0x8006_0000_0000_0000];
    u.mp_reach = vec![message::MpReachNlri {
        afi,
        safi: message::SAFI_FLOWSPEC,
        next_hop: if afi == 1 {
            addr("0.0.0.0")
        } else {
            addr("::")
        },
        nlri: vec![],
        nlri_path_ids: vec![],
        evpn: vec![],
        flowspec: rules,
        flowspec_vpn: vec![],
        vpn: Vec::new(),
        rtc: Vec::new(),
    }];
    u
}

fn unreach(afi: u16, rules: Vec<FlowSpec>) -> UpdateMessage {
    let mut u = ebgp_update(vec![], vec![], "0.0.0.0");
    u.attributes = None;
    u.mp_unreach = vec![message::MpUnreachNlri {
        afi,
        safi: message::SAFI_FLOWSPEC,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![],
        flowspec: rules,
        flowspec_vpn: vec![],
        vpn: Vec::new(),
        rtc: Vec::new(),
    }];
    u
}

fn fs_afs() -> HashSet<AddressFamily> {
    HashSet::from([
        AddressFamily::Ipv4Unicast,
        AddressFamily::Ipv4Flowspec,
        AddressFamily::Ipv6Flowspec,
    ])
}

fn feed(rib: &mut BgpRib, peer: IpAddr, u: &UpdateMessage) {
    rib.handle_update(peer, false, v4("192.0.2.1"), u, &nos_rpl::ACCEPT_ALL);
}

fn texts(rib: &BgpRib) -> Vec<String> {
    rib.flowspec_routes()
        .into_iter()
        .map(|(_, r)| format!("{} {}", r.family, r.nlri))
        .collect()
}

/// #723: the paging keys list the same rules in the same order as the old
/// unpaged `flowspec_routes`, each resolves to its rule, a vanished one to
/// `None`.
#[test]
fn flowspec_keys_match_the_unpaged_order_and_resolve_to_their_rules() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_mp_peer(&mut rib, peer, false, addr("10.0.0.254"), fs_afs());
    feed(&mut rib, peer, &reach(1, vec![rule(9), rule(1), rule(5)]));
    feed(&mut rib, peer, &reach(2, vec![rule6()]));
    let keys = rib.flowspec_keys(&crate::rib::FlowFilter::default());
    let want: Vec<_> = rib
        .flowspec_routes()
        .into_iter()
        .map(|(p, r)| (p, r.family.to_string(), r.nlri.to_string()))
        .collect();
    let got: Vec<_> = keys
        .iter()
        .map(|k| {
            (
                k.cursor.peer,
                k.cursor.family.clone(),
                k.cursor.nlri.clone(),
            )
        })
        .collect();
    assert_eq!((got.len(), &got), (4, &want));
    for k in &keys {
        let shown = rib.flowspec_at(k).unwrap();
        assert_eq!(
            (shown.peer, shown.route.nlri.to_string()),
            (peer, k.cursor.nlri.clone())
        );
    }
    assert!(rib
        .flowspec_at(&crate::page::Keyed::at(keys[0].cursor.clone()))
        .is_none());
    feed(&mut rib, peer, &unreach(1, vec![rule(1)]));
    assert_eq!(
        keys.iter().filter(|k| rib.flowspec_at(k).is_none()).count(),
        1
    );
}

#[test]
fn learns_replaces_and_withdraws_per_family() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_mp_peer(&mut rib, peer, false, addr("10.0.0.254"), fs_afs());
    feed(&mut rib, peer, &reach(1, vec![rule(1), rule(2)]));
    feed(&mut rib, peer, &reach(2, vec![rule6()]));
    assert_eq!(rib.flowspec_routes().len(), 3);
    // The attribute set is kept for validation/policy.
    let (_, r) = &rib.flowspec_routes()[0];
    assert_eq!(
        r.attributes.extended_communities,
        vec![0x8006_0000_0000_0000]
    );
    // Same rule again is no change; a withdraw is per family.
    feed(&mut rib, peer, &reach(1, vec![rule(1)]));
    assert_eq!(rib.flowspec_routes().len(), 3);
    feed(&mut rib, peer, &unreach(1, vec![rule(1), rule(9)]));
    assert_eq!(rib.flowspec_routes().len(), 2);
    feed(&mut rib, peer, &unreach(1, vec![rule6()]));
    assert_eq!(
        rib.flowspec_routes().len(),
        2,
        "the v6 rule is not a v4 one"
    );
    assert_eq!(rib.accepted_flowspec(peer), [1, 1]);
    // Nothing leaks into the unicast or EVPN tables.
    assert_eq!(rib.accepted_prefixes(peer), [0, 0, 0]);
    assert_eq!(rib.evpn_routes().len(), 0);
    rib.peer_disconnected(peer, Disconnect::Transport);
    assert_eq!(rib.flowspec_routes().len(), 0);
}

#[test]
fn an_unnegotiated_family_is_ignored() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_mp_peer(
        &mut rib,
        peer,
        false,
        addr("10.0.0.254"),
        HashSet::from([AddressFamily::Ipv4Unicast, AddressFamily::Ipv4Flowspec]),
    );
    feed(&mut rib, peer, &reach(2, vec![rule6()]));
    assert_eq!(rib.flowspec_routes().len(), 0);
    feed(&mut rib, peer, &reach(1, vec![rule(1)]));
    assert_eq!(texts(&rib).len(), 1);
}

#[test]
fn maximum_prefix_counts_flowspec_per_family() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_mp_peer(&mut rib, peer, false, addr("10.0.0.254"), fs_afs());
    rib.set_peer_max_prefix(
        peer,
        nos_proto::BgpMaximumPrefix {
            ipv4_flowspec: Some(nos_proto::BgpPrefixLimit {
                limit: 2,
                warning_only: false,
                restart_interval: 0,
            }),
            ..Default::default()
        },
    );
    feed(&mut rib, peer, &reach(1, vec![rule(1), rule(2)]));
    assert_eq!(rib.check_max_prefix(peer), None);
    feed(&mut rib, peer, &reach(1, vec![rule(3)]));
    let (family, limit, count) = rib.check_max_prefix(peer).expect("over the limit");
    assert_eq!(
        (family, limit.limit, count),
        (AddressFamily::Ipv4Flowspec, 2, 3)
    );
    // The v6 table is counted apart.
    feed(&mut rib, peer, &reach(2, vec![rule6()]));
    assert_eq!(rib.accepted_flowspec(peer), [3, 1]);
}

/// RFC 4724: a listed family stays (stale) across the restart, a re-announced
/// rule loses its mark, End-of-RIB purges the rest, an unlisted family goes.
#[test]
fn graceful_restart_keeps_listed_flowspec_until_end_of_rib() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    rib.set_peer_gr(peer, Some(gr(true, &[(AddressFamily::Ipv4Flowspec, true)])));
    let _rx = register_mp_peer(&mut rib, peer, false, addr("10.0.0.254"), fs_afs());
    feed(&mut rib, peer, &reach(1, vec![rule(1), rule(2)]));
    feed(&mut rib, peer, &reach(2, vec![rule6()]));

    rib.peer_disconnected(peer, Disconnect::Transport);
    assert_eq!(texts(&rib).len(), 2, "v6 not listed: withdrawn");
    assert_eq!(rib.stale_count(peer), 2);
    assert!(rib.has_stale(peer, Some(AddressFamily::Ipv4Flowspec)));

    let _rx = register_mp_peer(&mut rib, peer, false, addr("10.0.0.254"), fs_afs());
    feed(&mut rib, peer, &reach(1, vec![rule(1)]));
    assert_eq!(rib.stale_count(peer), 1);
    rib.end_of_rib(peer, AddressFamily::Ipv4Flowspec);
    assert_eq!(texts(&rib), [format!("ipv4-flowspec {}", rule(1))]);
    assert_eq!(rib.stale_count(peer), 0);
}

/// RFC 7313 §4 (#625): `BoRR` marks the family's rules stale, a re-announced
/// rule is kept, `EoRR` purges the rest and leaves the other family alone.
#[test]
fn borr_eorr_purges_unrefreshed_flowspec_rules() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_mp_peer(&mut rib, peer, false, addr("10.0.0.254"), fs_afs());
    feed(&mut rib, peer, &reach(1, vec![rule(1), rule(2)]));
    feed(&mut rib, peer, &reach(2, vec![rule6()]));
    rib.begin_refresh_in(peer, AddressFamily::Ipv4Flowspec);
    assert_eq!(rib.stale_count(peer), 2);
    feed(&mut rib, peer, &reach(1, vec![rule(1)]));
    assert_eq!(rib.end_refresh_in(peer, AddressFamily::Ipv4Flowspec), 1);
    assert_eq!(texts(&rib).len(), 2, "rule(1) and the untouched v6 rule");
    assert!(!rib.has_stale(peer, None));
}
