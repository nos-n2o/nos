use std::time::Instant;

use futures::{SinkExt, StreamExt};
use nos_lldp::link::{Port, SharedPorts};
use nos_lldp::packet::{
    Id, LinkAggregation, Lldpdu, MacPhy, OrgTlvs, CHASSIS_SUBTYPE_MAC, PORT_SUBTYPE_IF_NAME,
};
use nos_lldp::server;
use nos_pki::testing::shared;
use nos_proto::{IpcCodec, LldpEvent, LldpLinkStats, LldpNeighbor, LldpRequest};
use tokio_util::codec::{FramedRead, FramedWrite};

async fn request(path: &std::path::Path, request: LldpRequest) -> LldpEvent {
    let stream = shared()
        .identity("user", "tester")
        .connect(path, &nos_pki::PeerId::new("lldpd", ""))
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<LldpEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<LldpRequest>::default());
    writer.send(request).await.unwrap();
    reader.next().await.unwrap().unwrap()
}

async fn query(path: &std::path::Path) -> Vec<LldpNeighbor> {
    match request(path, LldpRequest::GetNeighbors).await {
        LldpEvent::Neighbors(neighbors) => neighbors,
        other @ LldpEvent::Statistics(_) => panic!("unexpected reply {other:?}"),
    }
}

#[tokio::test]
async fn get_statistics_lists_every_port_sorted_and_named() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("lldp.sock");
    let ports = SharedPorts::default();
    for (iface, frames_out) in [("eth2", 7), ("eth1", 3)] {
        ports.lock().unwrap().insert(
            iface.to_string(),
            Port {
                stats: LldpLinkStats {
                    frames_out,
                    ..LldpLinkStats::default()
                },
                ..Port::default()
            },
        );
    }
    let _server = server::start(&path, ports, &shared().identity("lldpd", "")).unwrap();

    let LldpEvent::Statistics(stats) = request(&path, LldpRequest::GetStatistics).await else {
        panic!("expected statistics");
    };
    assert_eq!(
        stats
            .iter()
            .map(|s| (s.interface.as_str(), s.frames_out))
            .collect::<Vec<_>>(),
        [("eth1", 3), ("eth2", 7)]
    );
}

fn pdu(chassis: u8, port: &str, name: &str) -> Lldpdu {
    Lldpdu {
        chassis_id: Id {
            subtype: CHASSIS_SUBTYPE_MAC,
            value: vec![2, 0, 0, 0, 0, chassis],
        },
        port_id: Id {
            subtype: PORT_SUBTYPE_IF_NAME,
            value: port.as_bytes().to_vec(),
        },
        ttl: 120,
        port_description: Some(port.to_string()),
        system_name: Some(name.to_string()),
        system_description: None,
        capabilities: None,
        management_addresses: Vec::new(),
        org: OrgTlvs {
            port_vlan_id: Some(1),
            vlan_names: vec![(100, "bd-x".to_string())],
            link_aggregation: Some(LinkAggregation {
                capable: true,
                enabled: true,
                port_id: 9,
            }),
            max_frame_size: Some(9018),
            mac_phy: Some(MacPhy {
                autoneg_supported: true,
                autoneg_enabled: true,
                advertised: 1,
                mau_type: 30,
            }),
            ..OrgTlvs::default()
        },
    }
}

#[tokio::test]
async fn get_neighbors_lists_every_interface_sorted() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("lldp.sock");
    let neighbors = SharedPorts::default();
    let now = Instant::now();
    for (iface, chassis, name) in [("eth2", 3, "router-c"), ("eth1", 2, "router-b")] {
        let mut port = Port::default();
        port.neighbors.apply(pdu(chassis, "eth0", name), now);
        neighbors.lock().unwrap().insert(iface.to_string(), port);
    }
    let _server = server::start(&path, neighbors, &shared().identity("lldpd", "")).unwrap();

    let all = query(&path).await;
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].local_interface, "eth1");
    assert_eq!(all[0].system_name.as_deref(), Some("router-b"));
    assert_eq!(all[0].chassis_id, "02:00:00:00:00:02");
    assert_eq!(all[0].port_id, "eth0");
    assert!(all[0].ttl_remaining_secs > 100);
    // The org TLVs survive the IPC round trip.
    assert_eq!(all[0].port_vlan_id, Some(1));
    assert_eq!(
        all[0].vlan_names,
        [nos_proto::lldp::LldpVlanName {
            id: 100,
            name: "bd-x".to_string()
        }]
    );
    assert_eq!(all[0].link_aggregation.map(|a| a.port_id), Some(9));
    assert_eq!(all[0].max_frame_size, Some(9018));
    assert_eq!(all[0].mac_phy.map(|m| m.mau_type), Some(30));
    assert_eq!(all[1].local_interface, "eth2");
}

#[tokio::test]
async fn get_neighbors_with_no_links_is_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("lldp.sock");
    let _server = server::start(
        &path,
        SharedPorts::default(),
        &shared().identity("lldpd", ""),
    )
    .unwrap();
    assert_eq!(query(&path).await, [] as [nos_proto::LldpNeighbor; 0]);
}
