//! RFC 7999 blackhole community (#861): tagging, `NO_EXPORT`, discard push.

use super::*;
use crate::message::{COMMUNITY_BLACKHOLE as BH, COMMUNITY_NO_EXPORT as NO_EXPORT};

const HOST: &str = "192.0.2.7/32";

fn list(entries: &[(&str, Option<(u8, u8)>)]) -> Arc<Vec<nos_rpl::PrefixListEntry>> {
    Arc::new(
        entries
            .iter()
            .map(|(c, range)| nos_rpl::PrefixListEntry {
                cidr: c.parse().unwrap(),
                range: *range,
            })
            .collect(),
    )
}

fn update(p: &str, tag: bool) -> UpdateMessage {
    let mut u = ebgp_update(vec![p], vec![65001], "10.0.0.1");
    if tag {
        u.attributes.as_mut().unwrap().communities = vec![BH];
    }
    u
}

fn learn(rib: &mut BgpRib, u: &UpdateMessage, policy: &CompiledPolicy) {
    rib.handle_update(addr("10.0.0.1"), false, v4("2.2.2.2"), u, policy);
}

fn setup(l: Option<Arc<Vec<nos_rpl::PrefixListEntry>>>) -> BgpRib {
    let mut rib = new_rib(65000);
    rib.set_peer_blackhole(addr("10.0.0.1"), l);
    let _rx = register_peer(&mut rib, addr("10.0.0.1"), false, addr("10.0.0.254"));
    rib
}

fn pushed(rib: &BgpRib, p: &str) -> Option<crate::rib::Hops> {
    rib.push_snapshot().1.get(&prefix(p)).cloned()
}

#[test]
fn covered_tagged_host_route_is_a_discard_with_no_export() {
    let mut rib = setup(Some(list(&[("192.0.2.0/24", Some((32, 32)))])));
    learn(&mut rib, &update(HOST, true), &nos_rpl::ACCEPT_ALL);
    assert_eq!(pushed(&rib, HOST), Some((vec![], None, true)));
    let stored = &rib.loc_rib[&prefix(HOST)];
    assert!(stored.communities.contains(&BH) && stored.communities.contains(&NO_EXPORT));
}

#[test]
fn uncovered_untagged_or_unconfigured_stays_ordinary() {
    // Not covered by the list.
    let mut rib = setup(Some(list(&[("198.51.100.0/24", Some((32, 32)))])));
    learn(&mut rib, &update(HOST, true), &nos_rpl::ACCEPT_ALL);
    assert_eq!(pushed(&rib, HOST).map(|h| h.2), Some(false));
    assert!(!rib.loc_rib[&prefix(HOST)].communities.contains(&NO_EXPORT));
    // Covered but untagged.
    let mut rib = setup(Some(list(&[("192.0.2.0/24", Some((32, 32)))])));
    learn(&mut rib, &update(HOST, false), &nos_rpl::ACCEPT_ALL);
    assert_eq!(pushed(&rib, HOST).map(|h| h.2), Some(false));
    // Plain entry (no range) covers only the exact prefix.
    let mut rib = setup(Some(list(&[("192.0.2.0/24", None)])));
    learn(&mut rib, &update(HOST, true), &nos_rpl::ACCEPT_ALL);
    assert_eq!(pushed(&rib, HOST).map(|h| h.2), Some(false));
    // Peer without a blackhole list.
    let mut rib = setup(None);
    learn(&mut rib, &update(HOST, true), &nos_rpl::ACCEPT_ALL);
    assert_eq!(pushed(&rib, HOST).map(|h| h.2), Some(false));
}

#[test]
fn the_import_policy_still_applies() {
    let mut rib = setup(Some(list(&[("192.0.2.0/24", Some((32, 32)))])));
    learn(&mut rib, &update(HOST, true), &nos_rpl::DENY_ALL);
    assert_eq!(pushed(&rib, HOST), None, "deny-all drops it (D-A b)");
}

#[test]
fn withdraw_removes_the_discard() {
    let mut rib = setup(Some(list(&[("192.0.2.0/24", Some((32, 32)))])));
    learn(&mut rib, &update(HOST, true), &nos_rpl::ACCEPT_ALL);
    assert!(pushed(&rib, HOST).is_some());
    let mut w = update(HOST, true);
    w.withdrawn_routes = vec![HOST.parse().unwrap()];
    w.nlri = vec![];
    w.attributes = None;
    learn(&mut rib, &w, &nos_rpl::ACCEPT_ALL);
    assert_eq!(pushed(&rib, HOST), None);
}

#[test]
fn padded_announce_is_withdrawn_by_clean_withdraw() {
    use crate::message::{BgpCodec, BgpMessage};
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};
    // #603: a peer announces 10.0.15.0/20 (host bits set) and withdraws 10.0.0.0/20.
    let wire = |u: UpdateMessage| {
        let mut buf = BytesMut::new();
        BgpCodec::default()
            .encode(BgpMessage::Update(u), &mut buf)
            .unwrap();
        match BgpCodec::default().decode(&mut buf).unwrap().unwrap() {
            BgpMessage::Update(u) => u,
            _ => unreachable!(),
        }
    };
    let mut rib = setup(None);
    let mut ann = update("10.0.0.0/20", false);
    ann.nlri = vec!["10.0.15.0/20".parse().unwrap()];
    learn(&mut rib, &wire(ann), &nos_rpl::ACCEPT_ALL);
    assert!(rib.loc_rib.contains_key(&prefix("10.0.0.0/20")));
    let mut w = update("10.0.0.0/20", false);
    w.withdrawn_routes = vec!["10.0.0.0/20".parse().unwrap()];
    w.nlri = vec![];
    w.attributes = None;
    learn(&mut rib, &wire(w), &nos_rpl::ACCEPT_ALL);
    assert!(rib.loc_rib.is_empty());
}
