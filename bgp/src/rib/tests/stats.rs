//! BMP statistics counters and gauges (#864).
use super::*;
use crate::bmp::stats::Stat;

const PEER: &str = "10.0.0.1";
const P: &str = "198.51.100.0/24";

fn rib() -> BgpRib {
    let mut rib = new_rib_with_identity(65000, v4("9.9.9.9"), v4("8.8.8.8"));
    let _rx = register_peer(&mut rib, addr(PEER), false, addr("10.0.0.254"));
    rib
}

fn feed(rib: &mut BgpRib, u: &UpdateMessage) {
    rib.handle_update(addr(PEER), false, v4("1.1.1.1"), u, &accept_all_policy());
}

fn stats(rib: &BgpRib) -> PeerStats {
    rib.peer_stats(addr(PEER))
}

#[test]
fn rejected_counts_each_prefix_the_policy_drops() {
    let mut rib = rib();
    let u = ebgp_update(vec![P, "198.51.101.0/24"], vec![65001], "192.0.2.1");
    rib.handle_update(addr(PEER), false, v4("1.1.1.1"), &u, &deny_all_policy());
    assert_eq!(stats(&rib).rejected, 2);
}

#[test]
fn duplicate_advertisement_and_withdraw() {
    let mut rib = rib();
    let u = ebgp_update(vec![P], vec![65001], "192.0.2.1");
    feed(&mut rib, &u);
    assert_eq!(stats(&rib).dup_adv, 0);
    feed(&mut rib, &u);
    assert_eq!(stats(&rib).dup_adv, 1);
    let mut w = empty_update();
    w.withdrawn_routes = vec![P.parse().unwrap()];
    feed(&mut rib, &w);
    assert_eq!(stats(&rib).dup_withdraw, 0);
    feed(&mut rib, &w);
    assert_eq!(stats(&rib).dup_withdraw, 1);
}

#[test]
fn loops_are_counted_per_kind() {
    let mut rib = rib();
    feed(
        &mut rib,
        &ebgp_update(vec![P], vec![65001, 65000], "192.0.2.1"),
    );
    let mut u = ebgp_update(vec![P], vec![65001], "192.0.2.1");
    u.attributes.as_mut().unwrap().cluster_list = vec![v4("8.8.8.8")];
    feed(&mut rib, &u);
    let mut u = ebgp_update(vec![P], vec![65001], "192.0.2.1");
    u.attributes.as_mut().unwrap().originator_id = Some(v4("9.9.9.9"));
    feed(&mut rib, &u);
    let s = stats(&rib);
    assert_eq!((s.as_loop, s.cluster_loop, s.originator), (1, 1, 1));
    assert_eq!(s.confed_loop, 0);

    let mut confed = new_rib(65101);
    confed.set_confederation(Some(65100));
    let _rx = register_peer(&mut confed, addr(PEER), false, addr("10.0.0.254"));
    confed.set_peer_confed(addr(PEER), true);
    let mut u = ebgp_update(vec![P], vec![65003], "192.0.2.1");
    u.attributes
        .as_mut()
        .unwrap()
        .as_path
        .prepend_confed_seq(65101);
    feed(&mut confed, &u);
    assert_eq!((stats(&confed).confed_loop, stats(&confed).as_loop), (1, 0));
}

#[test]
fn treat_as_withdraw_counts_codec_and_handle_update_cases() {
    let mut rib = rib();
    let mut w = empty_update();
    w.withdrawn_routes = vec![P.parse().unwrap()];
    w.treat_as_withdraw_prefixes = 3;
    feed(&mut rib, &w);
    let s = stats(&rib);
    assert_eq!((s.tw_updates, s.tw_prefixes), (1, 3));
    // A martian next hop (handle_update level), two prefixes.
    feed(
        &mut rib,
        &ebgp_update(vec![P, "198.51.101.0/24"], vec![65001], "127.0.0.1"),
    );
    // A stray confederation segment outside a confederation.
    let mut u = ebgp_update(vec![P], vec![65001], "192.0.2.1");
    u.attributes
        .as_mut()
        .unwrap()
        .as_path
        .prepend_confed_seq(65007);
    feed(&mut rib, &u);
    let s = stats(&rib);
    assert_eq!((s.tw_updates, s.tw_prefixes), (3, 6));
}

#[test]
fn counters_reset_on_a_new_session_and_go_with_the_peer() {
    let mut rib = rib();
    let u = ebgp_update(vec![P], vec![65001], "192.0.2.1");
    feed(&mut rib, &u);
    feed(&mut rib, &u);
    assert_eq!(stats(&rib).dup_adv, 1);
    let _rx = register_peer(&mut rib, addr(PEER), false, addr("10.0.0.254"));
    assert_eq!(stats(&rib), PeerStats::default());
    feed(&mut rib, &u);
    feed(&mut rib, &u);
    rib.peer_disconnected(addr(PEER), Disconnect::Hard);
    assert_eq!(stats(&rib), PeerStats::default());
    assert!(
        rib.bmp_stats(addr(PEER), rib.loc_totals(), nos_proto::BmpMonitorOut::None)
            .len()
            >= 9
    );
}

fn gauge(stats: &[Stat], t: u16) -> Option<u64> {
    stats.iter().find_map(|s| match s {
        Stat::Gauge(ty, v) if *ty == t => Some(*v),
        _ => None,
    })
}

fn per_family(stats: &[Stat], t: u16, afi: u16) -> Option<u64> {
    stats.iter().find_map(|s| match s {
        Stat::AfiSafi(ty, a, 1, v) if *ty == t && *a == afi => Some(*v),
        _ => None,
    })
}

#[test]
fn gauges_total_the_adj_rib_in_and_the_loc_rib() {
    let mut rib = rib();
    feed(
        &mut rib,
        &ebgp_update(vec![P, "198.51.101.0/24"], vec![65001], "192.0.2.1"),
    );
    let s = rib.bmp_stats(addr(PEER), rib.loc_totals(), nos_proto::BmpMonitorOut::None);
    assert_eq!(gauge(&s, 7), Some(2));
    assert_eq!(gauge(&s, 8), Some(2));
    assert_eq!(per_family(&s, 9, 1), Some(2));
    assert_eq!(per_family(&s, 9, 2), Some(0));
    assert_eq!(per_family(&s, 10, 1), Some(2));
    assert_eq!(per_family(&s, 10, 2), Some(0));
    // The counters come first, in type order.
    assert_eq!(s[0], Stat::Counter(0, 0));
}
