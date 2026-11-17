//! RFC 4271 section 5 (#1035): an unrecognized optional transitive attribute
//! learned from one peer is advertised on to others; local routes carry none.

use super::*;
use crate::message::RawAttribute;

#[test]
fn transit_route_carries_unknown_attributes_to_ibgp_and_ebgp_peers() {
    let mut rib = new_rib(65000);
    let _src = register_peer(&mut rib, addr("10.0.0.1"), false, addr("10.0.0.254"));
    let mut u = ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1");
    let raw = RawAttribute {
        flags: 0xc0,
        attr_type: 99,
        value: bytes::Bytes::from_static(&[1, 2]),
    };
    u.attributes.as_mut().unwrap().unknown = vec![raw.clone()].into();
    rib.handle_update(
        addr("10.0.0.1"),
        false,
        v4("2.2.2.2"),
        &u,
        &nos_rpl::ACCEPT_ALL,
    );
    for (peer, ibgp) in [("10.0.0.8", true), ("10.0.0.9", false)] {
        let mut rx = register_peer(&mut rib, addr(peer), ibgp, addr("10.0.0.253"));
        let a = announced(&mut rx, "1.2.3.0/24").expect("advertised");
        assert_eq!(&*a.unknown, std::slice::from_ref(&raw), "ibgp={ibgp}");
    }
}
