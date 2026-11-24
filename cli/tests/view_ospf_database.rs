//! Goldens of `show ospf database` / `show ospfv3 database` (#1436).
//! Goldens are in `tests/goldens/`; edit them by hand from the failing diff.

use std::net::Ipv4Addr;

use nos_cli::format::{
    filter_ospf_database, render_ospf_database, render_ospf_database_filtered,
    render_ospfv3_database,
};
use nos_proto::{LsaSummary, Ospfv3LsaSummary};

fn check(name: &str, got: &str) {
    let path = format!("{}/tests/goldens/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    let want = std::fs::read_to_string(&path).unwrap();
    assert_eq!(want, format!("{got}\n"), "golden {name}");
}

fn v2(t: u8, rid: &str) -> LsaSummary {
    LsaSummary {
        area_id: Ipv4Addr::UNSPECIFIED,
        lsa_type: t,
        link_state_id: rid.parse().unwrap(),
        advertising_router: rid.parse().unwrap(),
        sequence_number: 0x8000_0001u32.cast_signed(),
        age: 42,
        checksum: 0xabcd,
        external_metric: None,
        external_type2: false,
        router_flags: None,
        virtual_links: Vec::new(),
    }
}

fn v3(t: u16, link: Option<&str>) -> Ospfv3LsaSummary {
    Ospfv3LsaSummary {
        area_id: Ipv4Addr::UNSPECIFIED,
        lsa_type: t,
        link_state_id: Ipv4Addr::UNSPECIFIED,
        advertising_router: "2.2.2.2".parse().unwrap(),
        sequence_number: 0x8000_0002u32.cast_signed(),
        age: 7,
        checksum: 0x1234,
        link: link.map(String::from),
        router_flags: None,
        virtual_links: Vec::new(),
    }
}

fn all_v2() -> Vec<LsaSummary> {
    let mut router = v2(1, "1.1.1.1");
    router.router_flags = Some(0x07);
    router.virtual_links = vec!["3.3.3.3".parse().unwrap()];
    let mut e1 = v2(5, "2.2.2.2");
    e1.external_metric = Some(20);
    let mut e2 = v2(5, "2.2.2.2");
    e2.external_metric = Some(100);
    e2.external_type2 = true;
    e2.link_state_id = "10.0.0.0".parse().unwrap();
    let mut nssa = v2(7, "2.2.2.2");
    nssa.external_metric = Some(5);
    let mut plain_router = v2(1, "2.2.2.2");
    plain_router.router_flags = Some(0);
    vec![
        router,
        plain_router,
        v2(2, "1.1.1.1"),
        v2(3, "1.1.1.1"),
        v2(4, "1.1.1.1"),
        e1,
        e2,
        nssa,
        v2(9, "1.1.1.1"),
        v2(10, "1.1.1.1"),
        v2(11, "1.1.1.1"),
        v2(99, "1.1.1.1"),
    ]
}

#[test]
fn ospf_empty() {
    check("ospf_database_empty", &render_ospf_database("o1", &[]));
}

#[test]
fn ospf_every_type() {
    check(
        "ospf_database_types",
        &render_ospf_database("o1", &all_v2()),
    );
}

#[test]
fn ospf_filtered() {
    let r: Ipv4Addr = "2.2.2.2".parse().unwrap();
    let kept = filter_ospf_database(&all_v2(), Some(5), Some(r));
    check(
        "ospf_database_filtered",
        &render_ospf_database_filtered("o1", &kept),
    );
    let none = filter_ospf_database(&all_v2(), Some(2), Some(r));
    check(
        "ospf_database_no_match",
        &render_ospf_database_filtered("o1", &none),
    );
}

#[test]
fn ospfv3_every_type() {
    let mut router = v3(0x2001, None);
    router.router_flags = Some(0x03);
    router.virtual_links = vec!["3.3.3.3".parse().unwrap()];
    let all = vec![
        router,
        v3(0x2002, None),
        v3(0x2003, None),
        v3(0x2004, None),
        v3(0x4005, None),
        v3(0x2007, None),
        v3(0x0008, Some("eth0.0")),
        v3(0x2009, None),
        v3(0x000b, Some("eth0.0")),
        v3(0xa021, None),
        v3(0x8028, Some("eth1.0")),
        v3(0x1234, None),
    ];
    check("ospfv3_database_types", &render_ospfv3_database("v3", &all));
    check("ospfv3_database_empty", &render_ospfv3_database("v3", &[]));
}
