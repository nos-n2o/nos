//! Goldens of `show ospf route` / `show ospfv3 route` (#1453).
//! Goldens are in `tests/goldens/`; edit them by hand from the failing diff.

use std::net::Ipv4Addr;

use nos_cli::view::render;
use nos_proto::{Ospfv3RouteSummary, RoutePathClass, RouteSummary};

fn check(name: &str, got: &str) {
    let path = format!("{}/tests/goldens/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    let want = std::fs::read_to_string(&path).unwrap();
    assert_eq!(want, format!("{got}\n"), "golden {name}");
}

fn row(prefix: &str, class: RoutePathClass, cost: u32, hops: &[&str]) -> RouteSummary {
    RouteSummary {
        prefix: prefix.into(),
        class,
        cost,
        type2_cost: None,
        area: Ipv4Addr::UNSPECIFIED,
        next_hops: hops.iter().map(|h| (*h).to_string()).collect(),
        advertising_router: Some(Ipv4Addr::new(2, 2, 2, 2)),
    }
}

fn v2() -> Vec<RouteSummary> {
    vec![
        // Listed out of order: the table sorts by prefix.
        row(
            "192.0.2.2/32",
            RoutePathClass::IntraArea,
            11,
            &["10.0.0.2 dev eth0", "10.1.0.2 dev eth1"],
        ),
        RouteSummary {
            area: Ipv4Addr::new(0, 0, 0, 1),
            ..row(
                "172.16.0.0/16",
                RoutePathClass::InterArea,
                21,
                &["10.0.0.2 dev eth0"],
            )
        },
        row(
            "198.51.100.0/24",
            RoutePathClass::External1,
            30,
            &["10.0.0.2"],
        ),
        RouteSummary {
            type2_cost: Some(100),
            ..row(
                "203.0.113.0/24",
                RoutePathClass::External2,
                10,
                &["10.0.0.2 dev eth0"],
            )
        },
        RouteSummary {
            advertising_router: None,
            ..row("10.0.0.0/8", RoutePathClass::InterArea, 1, &[])
        },
    ]
}

fn v3() -> Vec<Ospfv3RouteSummary> {
    vec![
        Ospfv3RouteSummary {
            prefix: "2001:db8:2::/64".into(),
            class: RoutePathClass::IntraArea,
            cost: 2,
            type2_cost: None,
            area: Ipv4Addr::UNSPECIFIED,
            next_hops: vec!["fe80::2 dev eth0".into()],
            advertising_router: Some(Ipv4Addr::new(2, 2, 2, 2)),
        },
        Ospfv3RouteSummary {
            prefix: "2001:db8:9::/64".into(),
            class: RoutePathClass::External2,
            cost: 1,
            type2_cost: Some(20),
            area: Ipv4Addr::UNSPECIFIED,
            next_hops: vec!["fe80::2 dev eth0".into()],
            advertising_router: Some(Ipv4Addr::new(3, 3, 3, 3)),
        },
    ]
}

#[test]
fn ospf_routes() {
    check(
        "ospf_routes_empty",
        &render(&Vec::<RouteSummary>::new(), "no ospf routes"),
    );
    check("ospf_routes_populated", &render(&v2(), ""));
}

#[test]
fn ospfv3_routes() {
    check("ospf_routes_v3_populated", &render(&v3(), ""));
}
