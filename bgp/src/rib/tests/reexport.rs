//! `BgpRib::reexport_peer` (#629): an export policy swapped under an
//! established peer withdraws what it now refuses and announces what it
//! now accepts, and re-sends nothing that did not change.

use super::*;

fn announced(updates: &[OutboundUpdate]) -> Vec<IpNet> {
    updates
        .iter()
        .filter_map(|u| match u {
            OutboundUpdate::Announce(a) => Some(a.prefix),
            _ => None,
        })
        .collect()
}

fn withdrawn(updates: &[OutboundUpdate]) -> Vec<IpNet> {
    updates
        .iter()
        .filter_map(|u| match u {
            OutboundUpdate::Withdraw(p, ..) => Some(*p),
            _ => None,
        })
        .collect()
}

fn learn(rib: &mut BgpRib) {
    let source = addr("10.0.0.1");
    let rx = register_peer(rib, source, false, addr("10.0.0.254"));
    std::mem::forget(rx); // keep the outbox open
    let u = ebgp_update(vec!["1.0.0.0/24", "2.0.0.0/24"], vec![65001], "10.0.0.1");
    rib.handle_update(source, false, v4("192.0.2.1"), &u, &nos_rpl::ACCEPT_ALL);
}

#[test]
fn tighten_withdraws_loosen_announces_unchanged_sends_nothing() {
    let mut rib = new_rib(65000);
    learn(&mut rib);
    let obs = addr("10.0.0.2");
    let mut rx = register_peer(&mut rib, obs, false, addr("10.0.0.253"));
    assert_eq!(announced(&recv_all(&mut rx)).len(), 2);

    rib.reexport_peer(obs, deny_all_policy(), None);
    let sent = recv_all(&mut rx);
    assert_eq!(withdrawn(&sent).len(), 2);
    assert_eq!(announced(&sent).len(), 0);

    // Same policy again: nothing was sent, nothing to withdraw.
    rib.reexport_peer(obs, deny_all_policy(), None);
    assert_eq!(recv_all(&mut rx).len(), 0);

    rib.reexport_peer(obs, accept_all_policy(), None);
    assert_eq!(announced(&recv_all(&mut rx)).len(), 2);

    // An equivalent policy: identical advertisements are not re-sent.
    rib.reexport_peer(obs, accept_all_policy(), None);
    assert_eq!(recv_all(&mut rx).len(), 0);
}

#[test]
fn a_peer_not_established_is_ignored() {
    let mut rib = new_rib(65000);
    rib.reexport_peer(addr("10.0.0.9"), deny_all_policy(), None);
}

#[test]
fn add_path_peer_gives_up_the_refused_paths() {
    let mut rib = new_rib(65000);
    learn(&mut rib);
    let obs = addr("10.0.0.3");
    let mut rx = register_peer_full(
        &mut rib,
        obs,
        false,
        addr("10.0.0.252"),
        false,
        true,
        [AddressFamily::Ipv4Unicast].into_iter().collect(),
    );
    assert_eq!(announced(&recv_all(&mut rx)).len(), 2);

    rib.reexport_peer(obs, deny_all_policy(), None);
    assert_eq!(withdrawn(&recv_all(&mut rx)).len(), 2);

    rib.reexport_peer(obs, accept_all_policy(), None);
    assert_eq!(announced(&recv_all(&mut rx)).len(), 2);
}
