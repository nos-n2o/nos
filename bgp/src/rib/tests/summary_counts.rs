//! `advertised_prefixes` / `received_prefixes` (#1442).

use super::*;

#[test]
fn advertised_prefixes_split_by_family_and_follow_the_peer() {
    let mut rib = BgpRib::new();
    let peer: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(rib.advertised_prefixes(peer), [0, 0, 0]);
    let sent = rib.adj_rib_out.entry(peer).or_default();
    sent.insert("10.1.0.0/16".parse().unwrap());
    sent.insert("10.1.0.0/16".parse().unwrap());
    sent.insert("10.2.0.0/16".parse().unwrap());
    sent.insert("2001:db8::/32".parse().unwrap());
    assert_eq!(rib.advertised_prefixes(peer), [2, 1, 0]);
    rib.adj_rib_out.remove(&peer);
    assert_eq!(rib.advertised_prefixes(peer), [0, 0, 0]);
}

#[test]
fn received_prefixes_need_soft_reconfiguration() {
    let mut rib = BgpRib::new();
    let peer: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(rib.received_prefixes(peer), None);
    rib.set_peer_soft_reconfig(peer, true);
    assert_eq!(rib.received_prefixes(peer), Some([0, 0, 0]));
    rib.set_peer_soft_reconfig(peer, false);
    assert_eq!(rib.received_prefixes(peer), None);
}
