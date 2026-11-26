//! Goldens of `show ospf interface` / `show ospfv3 interface` (#1438).
//! Goldens are in `tests/goldens/`; edit them by hand from the failing diff.

use std::net::Ipv4Addr;

use nos_cli::view::render;
use nos_proto::schema::NetworkType;
use nos_proto::{InterfaceSummary, LinkInterfaceState, Ospfv3InterfaceSummary};

fn check(name: &str, got: &str) {
    let path = format!("{}/tests/goldens/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    let want = std::fs::read_to_string(&path).unwrap();
    assert_eq!(want, format!("{got}\n"), "golden {name}");
}

fn v2() -> Vec<InterfaceSummary> {
    let p2p = InterfaceSummary {
        link: "eth0.0".into(),
        kernel_interface: "eth0".into(),
        area_id: Ipv4Addr::UNSPECIFIED,
        address: "10.0.0.1/30".into(),
        network_type: NetworkType::PointToPoint,
        state: LinkInterfaceState::PointToPoint,
        cost: 10,
        hello_interval: 10,
        dead_interval: 40,
        retransmit_interval: 5,
        priority: 1,
        dr: None,
        bdr: None,
        neighbor_count: 1,
        full_neighbor_count: 1,
        mtu: 1500,
        mtu_ignore: false,
    };
    let lan = InterfaceSummary {
        link: "eth1.0".into(),
        kernel_interface: "eth1".into(),
        area_id: Ipv4Addr::new(0, 0, 0, 1),
        address: "10.1.0.1/24".into(),
        network_type: NetworkType::Broadcast,
        state: LinkInterfaceState::Dr,
        cost: 1,
        dr: Some(Ipv4Addr::new(1, 1, 1, 1)),
        bdr: Some(Ipv4Addr::new(3, 3, 3, 3)),
        neighbor_count: 2,
        full_neighbor_count: 1,
        ..p2p.clone()
    };
    vec![p2p, lan]
}

fn v3() -> Vec<Ospfv3InterfaceSummary> {
    vec![Ospfv3InterfaceSummary {
        link: "eth0.0".into(),
        kernel_interface: "eth0".into(),
        interface_id: 2,
        area_id: Ipv4Addr::UNSPECIFIED,
        address: "fe80::1".parse().unwrap(),
        network_type: NetworkType::Broadcast,
        state: LinkInterfaceState::Backup,
        cost: 1,
        hello_interval: 10,
        dead_interval: 40,
        retransmit_interval: 5,
        priority: 1,
        dr: Some(Ipv4Addr::new(2, 2, 2, 2)),
        bdr: Some(Ipv4Addr::new(1, 1, 1, 1)),
        neighbor_count: 1,
        full_neighbor_count: 1,
        mtu: 1500,
        mtu_ignore: false,
        prefixes: vec!["2001:db8::/64".into()],
    }]
}

#[test]
fn ospf_interfaces() {
    check(
        "ospf_interfaces_empty",
        &render(
            &Vec::<InterfaceSummary>::new(),
            "no ospf interfaces running",
        ),
    );
    check("ospf_interfaces_populated", &render(&v2(), ""));
}

#[test]
fn ospfv3_interfaces() {
    check(
        "ospfv3_interfaces_empty",
        &render(
            &Vec::<Ospfv3InterfaceSummary>::new(),
            "no ospfv3 interfaces running",
        ),
    );
    check("ospfv3_interfaces_populated", &render(&v3(), ""));
}
