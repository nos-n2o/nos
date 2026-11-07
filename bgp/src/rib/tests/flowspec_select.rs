//! Flowspec selection, import/export policy and propagation (#560).

use super::*;
use crate::flowspec::{Afi, FlowSpec};
use crate::rib::flowspec_out::flow_prefix;

const SRC: &str = "10.0.0.1"; // eBGP, AS 65001
const EBGP: &str = "10.0.0.3"; // eBGP observer, AS 65003
const IBGP: &str = "10.0.0.4"; // iBGP observer, not a client
const CLIENT: &str = "10.0.0.5"; // iBGP observer, route-reflector client
const I1: &str = "10.0.0.6"; // iBGP sources (not clients)
const I2: &str = "10.0.0.7";

/// 10.1.2.0/24
fn rule() -> FlowSpec {
    FlowSpec::decode(Afi::V4, &[5, 1, 24, 10, 1, 2]).unwrap().0
}

fn key() -> FlowspecKey {
    (AddressFamily::Ipv4Flowspec, rule())
}

fn afs() -> HashSet<AddressFamily> {
    HashSet::from([AddressFamily::Ipv4Unicast, AddressFamily::Ipv4Flowspec])
}

fn reg(
    rib: &mut BgpRib,
    peer: &str,
    ibgp: bool,
    rr_client: bool,
) -> mpsc::Receiver<OutboundUpdate> {
    let (tx, rx) = test_channel();
    rib.peer_established(
        addr(peer),
        ibgp,
        Some(addr("10.0.0.254")),
        afs(),
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

/// A rib (AS 65000, router-id/cluster-id 1.1.1.1) with the eBGP source and
/// the three observers registered.
fn setup() -> (BgpRib, [mpsc::Receiver<OutboundUpdate>; 4]) {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.set_peer_asn(addr(SRC), 65001);
    rib.set_peer_asn(addr(EBGP), 65003);
    let rx = [
        reg(&mut rib, SRC, false, false),
        reg(&mut rib, EBGP, false, false),
        reg(&mut rib, IBGP, true, false),
        reg(&mut rib, CLIENT, true, true),
    ];
    (rib, rx)
}

fn policy(script: &str) -> Arc<CompiledPolicy> {
    Arc::new(nos_rpl::compile(script, &nos_rpl::Symbols::EMPTY).unwrap())
}

fn flow_update(
    as_path: Vec<u32>,
    originator: Option<&str>,
    local_pref: Option<u32>,
) -> UpdateMessage {
    let mut u = ebgp_update(vec![], as_path, "0.0.0.0");
    let a = u.attributes.as_mut().unwrap();
    a.extended_communities = vec![0x8006_0000_0000_0000];
    a.originator_id = originator.map(v4);
    a.local_pref = local_pref;
    u.mp_reach = vec![message::MpReachNlri {
        afi: 1,
        safi: message::SAFI_FLOWSPEC,
        next_hop: addr("0.0.0.0"),
        nlri: vec![],
        nlri_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![rule()],
        vpn: Vec::new(),
        rtc: Vec::new(),
    }];
    u
}

fn unicast(as_path: Vec<u32>, originator: Option<&str>) -> UpdateMessage {
    let mut u = ebgp_update(vec!["10.1.0.0/16"], as_path, "10.0.0.1");
    u.attributes.as_mut().unwrap().originator_id = originator.map(v4);
    u
}

fn feed(rib: &mut BgpRib, peer: &str, ibgp: bool, bgp_id: &str, u: &UpdateMessage) {
    rib.handle_update(addr(peer), ibgp, v4(bgp_id), u, &nos_rpl::ACCEPT_ALL);
}

/// The eBGP source sends the covering unicast route then the flow: valid.
fn valid_flow_from_src(rib: &mut BgpRib) {
    feed(rib, SRC, false, "2.2.2.1", &unicast(vec![65001], None));
    feed(
        rib,
        SRC,
        false,
        "2.2.2.1",
        &flow_update(vec![65001], None, None),
    );
}

fn flows(rx: &mut mpsc::Receiver<OutboundUpdate>) -> Vec<OutboundUpdate> {
    recv_all(rx)
        .into_iter()
        .filter(|u| {
            matches!(
                u,
                OutboundUpdate::AnnounceFlowspec(_) | OutboundUpdate::WithdrawFlowspec(..)
            )
        })
        .collect()
}

fn announced(rx: &mut mpsc::Receiver<OutboundUpdate>) -> Option<AdvertisedFlowspec> {
    flows(rx).into_iter().find_map(|u| match u {
        OutboundUpdate::AnnounceFlowspec(a) => Some(a),
        _ => None,
    })
}

fn withdrawn(rx: &mut mpsc::Receiver<OutboundUpdate>) -> bool {
    flows(rx)
        .iter()
        .any(|u| matches!(u, OutboundUpdate::WithdrawFlowspec(AddressFamily::Ipv4Flowspec, r) if *r == rule()))
}

#[test]
fn the_policy_prefix_is_the_destination_or_the_default_route() {
    assert_eq!(
        flow_prefix(AddressFamily::Ipv4Flowspec, &rule()),
        prefix("10.1.2.0/24")
    );
    let proto_only = FlowSpec::decode(Afi::V4, &[3, 3, 0x81, 6]).unwrap().0;
    assert_eq!(
        flow_prefix(AddressFamily::Ipv4Flowspec, &proto_only),
        prefix("0.0.0.0/0")
    );
    let proto_only6 = FlowSpec::decode(Afi::V6, &[3, 3, 0x81, 6]).unwrap().0;
    assert_eq!(
        flow_prefix(AddressFamily::Ipv6Flowspec, &proto_only6),
        prefix("::/0")
    );
}

#[test]
fn a_valid_flow_is_propagated_with_unicast_rules_and_withdrawn_when_invalid() {
    let (mut rib, [mut src, mut ebgp, mut ibgp, mut client]) = setup();
    // No covering route yet: invalid, so nothing selected or sent.
    feed(
        &mut rib,
        SRC,
        false,
        "2.2.2.1",
        &flow_update(vec![65001], None, None),
    );
    assert_eq!(rib.flowspec_best(&key()), None);
    assert_eq!(flows(&mut ebgp).len(), 0);
    // The unicast route arrives: revalidated, selected, advertised.
    feed(&mut rib, SRC, false, "2.2.2.1", &unicast(vec![65001], None));
    assert_eq!(rib.flowspec_best(&key()), Some(addr(SRC)));
    let to_ebgp = announced(&mut ebgp).expect("advertised to eBGP");
    assert_eq!(to_ebgp.nlri, rule());
    assert_eq!(to_ebgp.route.as_path, vec![65000u32, 65001]);
    assert_eq!(to_ebgp.route.local_pref, None);
    // The traffic action is carried unchanged.
    assert_eq!(
        to_ebgp.route.extended_communities,
        vec![0x8006_0000_0000_0000]
    );
    let to_internal = announced(&mut ibgp).expect("eBGP-learned goes to iBGP");
    assert_eq!(to_internal.route.as_path, vec![65001u32]);
    assert_eq!(to_internal.route.local_pref, Some(100));
    assert!(announced(&mut client).is_some());
    // Split horizon: never back to the peer it came from.
    assert_eq!(flows(&mut src).len(), 0);
    // Validity lost: the selection goes and every peer gets a withdraw.
    let mut u = empty_update();
    u.withdrawn_routes = vec!["10.1.0.0/16".parse().unwrap()];
    feed(&mut rib, SRC, false, "2.2.2.1", &u);
    assert_eq!(rib.flowspec_best(&key()), None);
    assert!(withdrawn(&mut ebgp) && withdrawn(&mut ibgp) && withdrawn(&mut client));
    assert_eq!(flows(&mut src).len(), 0);
}

#[test]
fn a_withdrawn_flow_is_withdrawn_downstream() {
    let (mut rib, [_src, mut ebgp, ..]) = setup();
    valid_flow_from_src(&mut rib);
    assert!(announced(&mut ebgp).is_some());
    let mut u = empty_update();
    u.attributes = None;
    u.mp_unreach = vec![message::MpUnreachNlri {
        afi: 1,
        safi: message::SAFI_FLOWSPEC,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![rule()],
        vpn: Vec::new(),
        rtc: Vec::new(),
    }];
    feed(&mut rib, SRC, false, "2.2.2.1", &u);
    assert!(withdrawn(&mut ebgp));
    // The same again is no news.
    feed(&mut rib, SRC, false, "2.2.2.1", &u);
    assert_eq!(flows(&mut ebgp).len(), 0);
}

/// #562: what `nos-acld` gets is the selected rules, more specific first
/// (RFC 8955 section 5.1), and nothing while deferring.
#[test]
fn the_acld_snapshot_is_the_selected_rules_in_precedence_order() {
    let (mut rib, _rx) = setup();
    assert_eq!(rib.flowspec_push_snapshot(), Some(vec![]));
    feed(&mut rib, SRC, false, "2.2.2.1", &unicast(vec![65001], None));
    let narrow = FlowSpec::decode(Afi::V4, &[6, 1, 25, 10, 1, 2, 0])
        .unwrap()
        .0;
    let mut u = flow_update(vec![65001], None, None);
    u.mp_reach[0].flowspec = vec![rule(), narrow.clone()];
    feed(&mut rib, SRC, false, "2.2.2.1", &u);
    let snap = rib.flowspec_push_snapshot().unwrap();
    let shown: Vec<&str> = snap.iter().map(|r| r.flow.as_str()).collect();
    assert_eq!(shown, [narrow.to_string(), rule().to_string()]);
    assert_eq!(snap[0].actions, [nos_proto::FlowRuleAction::RateBytes(0.0)]);
    let held = rib.flowspec_routes();
    assert_eq!(held.len(), 2);
    assert!(held.iter().all(|(p, r)| rib.flowspec_selected(*p, r)));
    assert!(!rib.flowspec_selected(addr(EBGP), held[0].1));
    rib.begin_deferral(0, 120, 360, [addr(EBGP)]);
    assert_eq!(rib.flowspec_push_snapshot(), None);
}

/// #558 left this untested: an UPDATE treated as withdraw (here, a looped
/// `AS_PATH`) removes the Flowspec rules it announces too.
#[test]
fn treat_as_withdraw_removes_the_announced_flowspec_rules() {
    let (mut rib, [_src, mut ebgp, ..]) = setup();
    valid_flow_from_src(&mut rib);
    assert_eq!(rib.flowspec_routes().len(), 1);
    assert!(announced(&mut ebgp).is_some());
    feed(
        &mut rib,
        SRC,
        false,
        "2.2.2.1",
        &flow_update(vec![65001, 65000], None, None),
    );
    assert_eq!(rib.flowspec_routes().len(), 0);
    assert!(withdrawn(&mut ebgp));
}

#[test]
fn ibgp_sources_follow_split_horizon_and_reflection() {
    let (mut rib, [_src, mut ebgp, mut ibgp, mut client]) = setup();
    let _i1 = reg(&mut rib, I1, true, false);
    feed(
        &mut rib,
        I1,
        true,
        "2.2.2.6",
        &unicast(vec![65009], Some("9.9.9.9")),
    );
    feed(
        &mut rib,
        I1,
        true,
        "2.2.2.6",
        &flow_update(vec![65009], Some("9.9.9.9"), None),
    );
    assert_eq!(rib.flowspec_best(&key()), Some(addr(I1)));
    // A non-client iBGP peer never gets another non-client's route.
    assert!(announced(&mut ibgp).is_none());
    // A client does, reflected (RFC 4456), the ORIGINATOR_ID kept so the
    // next hop's validation rule (b) still holds.
    let r = announced(&mut client).expect("reflected to the client");
    assert_eq!(r.route.originator_id, Some(v4("9.9.9.9")));
    assert_eq!(r.route.cluster_list, vec![v4("1.1.1.1")]);
    assert!(announced(&mut ebgp).is_some());
}

#[test]
fn best_path_runs_the_unicast_decision_process() {
    let (mut rib, _rx) = setup();
    let _i1 = reg(&mut rib, I1, true, false);
    let _i2 = reg(&mut rib, I2, true, false);
    // Both copies validate against the one unicast route (same ORIGINATOR_ID).
    feed(
        &mut rib,
        I1,
        true,
        "2.2.2.6",
        &unicast(vec![65009], Some("9.9.9.9")),
    );
    let flow = |lp, path| flow_update(path, Some("9.9.9.9"), lp);
    feed(&mut rib, I2, true, "2.2.2.7", &flow(None, vec![65009]));
    feed(&mut rib, I1, true, "2.2.2.6", &flow(None, vec![65009]));
    // Step 9: the lowest router-id.
    assert_eq!(rib.flowspec_best(&key()), Some(addr(I1)));
    // Step 1: a higher LOCAL_PREF wins.
    feed(&mut rib, I2, true, "2.2.2.7", &flow(Some(200), vec![65009]));
    assert_eq!(rib.flowspec_best(&key()), Some(addr(I2)));
    // Step 3: then a shorter AS_PATH.
    feed(
        &mut rib,
        I2,
        true,
        "2.2.2.7",
        &flow(None, vec![65009, 65010]),
    );
    assert_eq!(rib.flowspec_best(&key()), Some(addr(I1)));
    // An invalid copy (no unicast route for its originator) never competes.
    feed(
        &mut rib,
        I1,
        true,
        "2.2.2.6",
        &flow_update(vec![65009], Some("8.8.8.8"), Some(500)),
    );
    assert_eq!(rib.flowspec_best(&key()), Some(addr(I2)));
}

#[test]
fn import_policy_rejects_rewrites_and_purges() {
    let (mut rib, [_src, mut ebgp, ..]) = setup();
    feed(&mut rib, SRC, false, "2.2.2.1", &unicast(vec![65001], None));
    // Reject: not stored, so not shown.
    rib.set_peer_flowspec_policies(addr(SRC), Some(policy("reject\n")), None);
    feed(
        &mut rib,
        SRC,
        false,
        "2.2.2.1",
        &flow_update(vec![65001], None, None),
    );
    assert_eq!(rib.flowspec_routes().len(), 0);
    assert_eq!(flows(&mut ebgp).len(), 0);
    assert_eq!(rib.peer_stats(addr(SRC)).rejected, 1, "BMP stat 0");
    // Accept with a rewrite: the stored attributes carry it.
    rib.set_peer_flowspec_policies(
        addr(SRC),
        Some(policy("this.bgp.communities.add(65000:7)\naccept\n")),
        None,
    );
    feed(
        &mut rib,
        SRC,
        false,
        "2.2.2.1",
        &flow_update(vec![65001], None, None),
    );
    let (_, r) = rib.flowspec_routes()[0];
    assert_eq!(r.attributes.communities, vec![(65000 << 16) | 7]);
    assert_eq!(
        announced(&mut ebgp).unwrap().route.communities,
        vec![(65000 << 16) | 7]
    );
    // A policy change re-runs the stored rule (a GR-kept one) and purges it.
    rib.set_peer_flowspec_policies(addr(SRC), Some(policy("reject\n")), None);
    assert_eq!(rib.flowspec_routes().len(), 0);
    assert!(withdrawn(&mut ebgp));
    // Unset accepts everything.
    rib.set_peer_flowspec_policies(addr(SRC), None, None);
    feed(
        &mut rib,
        SRC,
        false,
        "2.2.2.1",
        &flow_update(vec![65001], None, None),
    );
    assert_eq!(rib.flowspec_best(&key()), Some(addr(SRC)));
    assert!(announced(&mut ebgp).is_some());
    // A new accepting policy rewrites the stored rule and re-advertises it.
    rib.set_peer_flowspec_policies(
        addr(SRC),
        Some(policy("this.bgp.communities.add(65000:9)\naccept\n")),
        None,
    );
    assert_eq!(
        announced(&mut ebgp).unwrap().route.communities,
        vec![(65000 << 16) | 9]
    );
}

#[test]
fn import_policy_sees_the_destination_prefix() {
    let (mut rib, _rx) = setup();
    feed(&mut rib, SRC, false, "2.2.2.1", &unicast(vec![65001], None));
    rib.set_peer_flowspec_policies(
        addr(SRC),
        Some(policy(
            "if this.prefix == 10.1.2.0/24:\n    reject\naccept\n",
        )),
        None,
    );
    feed(
        &mut rib,
        SRC,
        false,
        "2.2.2.1",
        &flow_update(vec![65001], None, None),
    );
    assert_eq!(rib.flowspec_routes().len(), 0);
}

#[test]
fn export_policy_is_per_peer_and_unset_accepts() {
    let (mut rib, [_src, mut ebgp, mut ibgp, _client]) = setup();
    rib.set_peer_flowspec_policies(addr(EBGP), None, Some(policy("reject\n")));
    valid_flow_from_src(&mut rib);
    assert_eq!(flows(&mut ebgp).len(), 0);
    assert!(announced(&mut ibgp).is_some());
}

#[test]
fn a_new_peer_gets_the_table_and_a_refresh_resends_it() {
    let (mut rib, _rx) = setup();
    valid_flow_from_src(&mut rib);
    let mut late = reg(&mut rib, "10.0.0.9", false, false);
    let got = recv_all(&mut late);
    assert!(got
        .iter()
        .any(|u| matches!(u, OutboundUpdate::AnnounceFlowspec(a) if a.nlri == rule())));
    rib.resend_all(addr("10.0.0.9"), AddressFamily::Ipv4Flowspec, true);
    let got = recv_all(&mut late);
    assert_eq!(got.len(), 3, "BoRR, the rule, EoRR: {got:?}");
    assert!(matches!(got[1], OutboundUpdate::AnnounceFlowspec(_)));
    // A unicast refresh sends no Flowspec.
    rib.resend_all(addr("10.0.0.9"), AddressFamily::Ipv4Unicast, false);
    assert_eq!(flows(&mut late).len(), 0);
}

#[test]
fn graceful_restart_deferral_holds_flowspec_until_it_ends() {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.set_peer_asn(addr(SRC), 65001);
    rib.begin_deferral(1, 120, 360, [addr(SRC)]);
    let _src = reg(&mut rib, SRC, false, false);
    let mut ebgp = reg(&mut rib, EBGP, false, false);
    valid_flow_from_src(&mut rib);
    assert_eq!(rib.flowspec_best(&key()), Some(addr(SRC)));
    assert!(flows(&mut ebgp).is_empty(), "deferred");
    rib.apply_redistribute_update(RedistributeUpdate::Full(Vec::new()));
    for family in AddressFamily::ALL {
        rib.end_of_rib(addr(SRC), family);
    }
    assert!(!rib.deferring());
    assert!(announced(&mut ebgp).is_some());
}

/// Drains `peer`'s backlog to the end (a one-slot queue takes several
/// rounds), returning everything sent.
fn drain_all(
    rib: &mut BgpRib,
    peer: IpAddr,
    tx: &OutboxTx,
    rx: &mut mpsc::Receiver<OutboundUpdate>,
) -> Vec<OutboundUpdate> {
    let mut got = recv_all(rx);
    while tx.pending() {
        rib.drain_backlog(peer);
        got.extend(recv_all(rx));
    }
    got
}

#[test]
fn a_lost_flowspec_update_is_resent_from_the_backlog() {
    let (mut rib, _rx) = setup();
    let peer = addr("10.0.0.9");
    let (tx, mut rx) = outbox_channel(peer, 1);
    rib.peer_established(
        peer,
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
    // Fill the one-slot queue so the rule is parked.
    tx.send(OutboundUpdate::EndOfRib(AddressFamily::Ipv4Unicast));
    valid_flow_from_src(&mut rib);
    assert!(tx.pending());
    let got = drain_all(&mut rib, peer, &tx, &mut rx);
    assert!(
        got.iter()
            .any(|u| matches!(u, OutboundUpdate::AnnounceFlowspec(a) if a.nlri == rule())),
        "{got:?}"
    );
    // A lost withdraw is re-sent as a withdraw.
    tx.send(OutboundUpdate::EndOfRib(AddressFamily::Ipv4Unicast));
    rib.set_peer_flowspec_policies(addr(SRC), Some(policy("reject\n")), None);
    assert!(tx.pending());
    let got = drain_all(&mut rib, peer, &tx, &mut rx);
    assert!(
        got.iter()
            .any(|u| matches!(u, OutboundUpdate::WithdrawFlowspec(..))),
        "{got:?}"
    );
}

#[test]
fn ipv6_address_specific_communities_follow_the_transitive_bit() {
    let (mut rib, [_src, mut ebgp, mut ibgp, _client]) = setup();
    let mut transitive = [0u8; 20];
    transitive[1] = 0x0d; // RFC 8956 redirect
    let mut local = transitive;
    local[0] = 0x40;
    feed(&mut rib, SRC, false, "2.2.2.1", &unicast(vec![65001], None));
    let mut u = flow_update(vec![65001], None, None);
    u.attributes.as_mut().unwrap().ipv6_extended_communities = vec![transitive, local];
    feed(&mut rib, SRC, false, "2.2.2.1", &u);
    assert_eq!(
        announced(&mut ibgp).unwrap().ipv6_extended_communities,
        vec![transitive, local]
    );
    assert_eq!(
        announced(&mut ebgp).unwrap().ipv6_extended_communities,
        vec![transitive]
    );
}

/// RFC 1997 well-known communities gate Flowspec advertisements too (#873).
#[test]
fn no_advertise_blocks_flowspec_readvertisement() {
    let (mut rib, mut rx) = setup();
    feed(&mut rib, SRC, false, "2.2.2.1", &unicast(vec![65001], None));
    let mut u = flow_update(vec![65001], None, None);
    u.attributes.as_mut().unwrap().communities = vec![message::COMMUNITY_NO_ADVERTISE];
    feed(&mut rib, SRC, false, "2.2.2.1", &u);
    assert!(announced(&mut rx[1]).is_none(), "eBGP");
    assert!(announced(&mut rx[2]).is_none(), "iBGP");
    // control: untagged is announced
    feed(
        &mut rib,
        SRC,
        false,
        "2.2.2.1",
        &flow_update(vec![65001], None, None),
    );
    assert!(announced(&mut rx[1]).is_some());
}

fn flow_policies(flowspec: &str) -> crate::rib::ImportPolicies {
    crate::rib::ImportPolicies {
        unicast: accept_all_policy(),
        evpn: None,
        flowspec: Some(policy(flowspec)),
    }
}

#[test]
fn reevaluation_readmits_a_rejected_rule_and_never_rewrites_twice() {
    let (mut rib, [_src, mut ebgp, ..]) = setup();
    let src = addr(SRC);
    rib.set_peer_soft_reconfig(src, true);
    feed(&mut rib, SRC, false, "2.2.2.1", &unicast(vec![65001], None));
    rib.set_peer_flowspec_policies(src, Some(policy("reject\n")), None);
    feed(
        &mut rib,
        SRC,
        false,
        "2.2.2.1",
        &flow_update(vec![65001], None, None),
    );
    assert_eq!(rib.flowspec_routes().len(), 0);
    // Loosen with a rewrite: the rule is back, selected and advertised.
    let fams = rib.reevaluate_peer(
        src,
        flow_policies("this.bgp.communities.add(65000:7)\naccept\n"),
    );
    let f = fams
        .iter()
        .find(|f| f.family == nos_proto::ReevalFamily::Ipv4Flowspec)
        .unwrap();
    assert_eq!((f.retained, f.accepted), (1, 1));
    assert_eq!(rib.flowspec_best(&key()), Some(src));
    assert_eq!(
        announced(&mut ebgp).unwrap().route.communities,
        vec![(65000 << 16) | 7]
    );
    // A different rewrite starts from the raw rule, not from the first one.
    rib.reevaluate_peer(
        src,
        flow_policies("this.bgp.communities.add(65000:9)\naccept\n"),
    );
    let (_, r) = rib.flowspec_routes()[0];
    assert_eq!(r.attributes.communities, vec![(65000 << 16) | 9]);
    // Tighten: removed and withdrawn; the raw copy stays for later.
    rib.reevaluate_peer(src, flow_policies("reject\n"));
    assert_eq!(rib.flowspec_routes().len(), 0);
    assert!(rib.retained_count(src) >= 1);
    // A withdrawal from the peer drops the raw copy.
    let mut u = ebgp_update(vec![], vec![], "0.0.0.0");
    u.attributes = None;
    u.mp_unreach = vec![message::MpUnreachNlri {
        afi: 1,
        safi: message::SAFI_FLOWSPEC,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![rule()],
        vpn: vec![],
        rtc: Vec::new(),
    }];
    let before = rib.retained_count(src);
    feed(&mut rib, SRC, false, "2.2.2.1", &u);
    assert_eq!(rib.retained_count(src), before - 1);
}
