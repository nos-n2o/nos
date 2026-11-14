use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_interface::driver::{
    BridgePortRef, DriverError, InterfaceDriver, LinkWatch, NoopInterfaceDriver,
};
use nos_interface::state::{BroadcastDomainState, InterfaceState, PortAggregateState};
use nos_interface::{server, Interfaces};
use nos_pki::testing::shared;
use nos_proto::{InterfaceAddress, InterfaceEvent, InterfaceRequest, InterfaceStatus, IpcCodec};
use tokio::sync::RwLock;
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_address() -> InterfaceAddress {
    InterfaceAddress {
        address: "10.0.0.1/24".parse().unwrap(),
        label: None,
    }
}

async fn sample_interfaces() -> Interfaces {
    // `Interfaces` has no public constructor from a map, so build it through
    // the same path production code uses.
    let cfg = nos_proto::Config {
        interfaces: vec![
            nos_proto::Interface {
                ospfv3_profile: None,
                name: "eth0".to_string(),
                addresses: vec![],
                routing_table: None,
                ospf_profile: None,
                switching_profile: None,
                port_aggregate: None,
                lacp_port_priority: None,
                lacp_link_number: None,
                lacp_mode: nos_proto::LacpMode::default(),
                mtu: None,
                lldp_transmit: false,
                lldp_receive: false,
                lldp_destination: nos_proto::LldpDestination::default(),
                subinterfaces: vec![nos_proto::Subinterface {
                    mtu: None,
                    acl_in: None,
                    acl_out: None,
                    flowspec: false,
                    ospfv3_profile: None,
                    bfd_unsolicited: None,
                    tag: 0,
                    addresses: vec![sample_address()],
                    routing_table: Some("rt1".to_string()),
                    ospf_profile: None,
                }],
                ..Default::default()
            },
            nos_proto::Interface {
                ospfv3_profile: None,
                name: "eth1".to_string(),
                addresses: vec![],
                routing_table: None,
                ospf_profile: None,
                switching_profile: None,
                port_aggregate: None,
                lacp_port_priority: None,
                lacp_link_number: None,
                lacp_mode: nos_proto::LacpMode::default(),
                mtu: None,
                lldp_transmit: false,
                lldp_receive: false,
                lldp_destination: nos_proto::LldpDestination::default(),
                subinterfaces: vec![],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    nos_interface::state::build_from_config(&cfg, &NoopInterfaceDriver, &Interfaces::new()).await
}

/// A bounded read: a dead dispatcher fails the test in seconds instead of
/// hanging (or ending a mutant as a Timeout, #374).
async fn next_event(
    r: &mut FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<InterfaceEvent>>,
) -> InterfaceEvent {
    tokio::time::timeout(std::time::Duration::from_secs(5), r.next())
        .await
        .expect("no reply within 5s")
        .expect("connection closed without a reply")
        .expect("undecodable reply")
}

/// `Noop` that remembers every `apply` (interface name, member active), so a
/// push's immediate re-apply is observable (#374).
#[derive(Default)]
struct RecordingDriver {
    applied: std::sync::Mutex<Vec<(String, bool)>>,
}

#[async_trait::async_trait]
impl InterfaceDriver for RecordingDriver {
    async fn apply(&self, d: &InterfaceState) -> Result<(), DriverError> {
        self.applied
            .lock()
            .unwrap()
            .push((d.name.clone(), d.port_aggregate_active));
        Ok(())
    }
    async fn remove(&self, n: &str) -> Result<(), DriverError> {
        NoopInterfaceDriver.remove(n).await
    }
    async fn ensure_broadcast_domain(
        &self,
        d: &BroadcastDomainState,
    ) -> Result<String, DriverError> {
        NoopInterfaceDriver.ensure_broadcast_domain(d).await
    }
    async fn remove_broadcast_domain(&self, d: &str) -> Result<(), DriverError> {
        NoopInterfaceDriver.remove_broadcast_domain(d).await
    }
    async fn ensure_port_aggregate(&self, d: &PortAggregateState) -> Result<String, DriverError> {
        NoopInterfaceDriver.ensure_port_aggregate(d).await
    }
    async fn remove_port_aggregate(&self, n: &str) -> Result<(), DriverError> {
        NoopInterfaceDriver.remove_port_aggregate(n).await
    }
    async fn link_local_address(&self, k: &str) -> Option<std::net::Ipv6Addr> {
        NoopInterfaceDriver.link_local_address(k).await
    }
    async fn set_bridge_port_state(
        &self,
        p: &BridgePortRef,
        s: nos_proto::StpPortState,
    ) -> Result<(), DriverError> {
        NoopInterfaceDriver.set_bridge_port_state(p, s).await
    }
    async fn flush_bridge_port(&self, p: &BridgePortRef) -> Result<(), DriverError> {
        NoopInterfaceDriver.flush_bridge_port(p).await
    }
    fn watch_links(&self) -> LinkWatch {
        NoopInterfaceDriver.watch_links()
    }
}

impl RecordingDriver {
    fn applied(&self) -> Vec<(String, bool)> {
        self.applied.lock().unwrap().clone()
    }

    /// Waits (bounded) until `eth0` was applied with this `active` value.
    async fn wait_applied(&self, active: bool) {
        for _ in 0..100 {
            if self.applied().contains(&("eth0".to_string(), active)) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!(
            "eth0 never applied with active={active}: {:?}",
            self.applied()
        );
    }
}

/// `eth0` in `bond1` (mode `mode`, optionally BFD-tracked), the server running
/// over a `RecordingDriver`, and a writer connected as `role`.
async fn bond_server(
    mode: nos_proto::PortAggregateMode,
    bfd: bool,
    role: &str,
    dir: &std::path::Path,
) -> (
    Arc<RecordingDriver>,
    Arc<RwLock<Interfaces>>,
    FramedWrite<nos_pki::Stream, IpcCodec<InterfaceRequest>>,
    tokio::task::JoinHandle<()>,
) {
    let path = dir.join("interface.sock");
    let cfg = nos_proto::Config {
        interfaces: vec![nos_proto::Interface {
            name: "eth0".to_string(),
            port_aggregate: Some("bond1".to_string()),
            ..Default::default()
        }],
        port_aggregates: vec![nos_proto::PortAggregate {
            name: "bond1".to_string(),
            mode,
            bfd: bfd.then(|| "fast".to_string()),
            bfd_peer: bfd.then(|| "10.0.0.2".parse().unwrap()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let interfaces = Arc::new(RwLock::new(
        nos_interface::state::build_from_config(&cfg, &NoopInterfaceDriver, &Interfaces::new())
            .await,
    ));
    let driver = Arc::new(RecordingDriver::default());
    let server = server::start(
        &path,
        interfaces.clone(),
        driver.clone(),
        &shared().identity("interfaced", ""),
    )
    .unwrap();
    let stream = shared()
        .identity(role, "")
        .connect(&path, &nos_pki::PeerId::new("interfaced", ""))
        .await
        .unwrap();
    (
        driver,
        interfaces,
        FramedWrite::new(stream, IpcCodec::<InterfaceRequest>::default()),
        server,
    )
}

async fn connect(
    path: &std::path::Path,
) -> (
    FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<InterfaceEvent>>,
    FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<InterfaceRequest>>,
) {
    let stream = shared()
        .identity("user", "tester")
        .connect(path, &nos_pki::PeerId::new("interfaced", ""))
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    (
        FramedRead::new(r, IpcCodec::<InterfaceEvent>::default()),
        FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default()),
    )
}

#[tokio::test]
async fn get_interfaces_returns_every_interface_sorted_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let interfaces = Arc::new(RwLock::new(sample_interfaces().await));
    let _server = server::start(
        &path,
        interfaces,
        Arc::new(NoopInterfaceDriver),
        &shared().identity("interfaced", ""),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(InterfaceRequest::GetInterfaces).await.unwrap();
    let event = next_event(&mut reader).await;

    let InterfaceEvent::Interfaces(statuses) = event else {
        panic!("expected Interfaces, got {event:?}");
    };
    assert_eq!(statuses.len(), 2);
    assert_eq!(statuses[0].name, "eth0");
    assert_eq!(statuses[1].name, "eth1");
}

#[tokio::test]
async fn get_interfaces_reports_the_err_disabled_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let mut held = sample_interfaces().await;
    held.set_err_disabled("eth0", true);
    let _server = server::start(
        &path,
        Arc::new(RwLock::new(held)),
        Arc::new(NoopInterfaceDriver),
        &shared().identity("interfaced", ""),
    )
    .unwrap();
    let (mut reader, mut writer) = connect(&path).await;
    writer.send(InterfaceRequest::GetInterfaces).await.unwrap();
    let InterfaceEvent::Interfaces(statuses) = next_event(&mut reader).await else {
        panic!("expected Interfaces");
    };
    assert!(statuses[0].err_disabled && !statuses[1].err_disabled);
}

#[tokio::test]
async fn get_interface_returns_matching_status() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let interfaces = Arc::new(RwLock::new(sample_interfaces().await));
    let _server = server::start(
        &path,
        interfaces,
        Arc::new(NoopInterfaceDriver),
        &shared().identity("interfaced", ""),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(InterfaceRequest::GetInterface {
            name: "eth0".to_string(),
        })
        .await
        .unwrap();
    let event = next_event(&mut reader).await;

    let InterfaceEvent::Interface(InterfaceStatus {
        name,
        subinterfaces,
        ..
    }) = event
    else {
        panic!("expected Interface, got {event:?}");
    };
    assert_eq!(name, "eth0");
    let tag0 = subinterfaces.iter().find(|s| s.tag == 0).unwrap();
    assert_eq!(tag0.addresses, vec![sample_address()]);
    assert_eq!(tag0.routing_table.as_deref(), Some("rt1"));
}

#[tokio::test]
async fn get_interface_missing_returns_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let interfaces = Arc::new(RwLock::new(sample_interfaces().await));
    let _server = server::start(
        &path,
        interfaces,
        Arc::new(NoopInterfaceDriver),
        &shared().identity("interfaced", ""),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(InterfaceRequest::GetInterface {
            name: "eth9".to_string(),
        })
        .await
        .unwrap();
    let event = next_event(&mut reader).await;

    assert!(matches!(event, InterfaceEvent::NotFound));
}

#[tokio::test]
async fn push_bfd_members_enslaves_the_up_member_immediately() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let cfg = nos_proto::Config {
        interfaces: vec![nos_proto::Interface {
            name: "eth0".to_string(),
            port_aggregate: Some("bond1".to_string()),
            ..Default::default()
        }],
        port_aggregates: vec![nos_proto::PortAggregate {
            name: "bond1".to_string(),
            bfd: Some("fast".to_string()),
            bfd_peer: Some("10.0.0.2".parse().unwrap()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let interfaces = Arc::new(RwLock::new(
        nos_interface::state::build_from_config(&cfg, &NoopInterfaceDriver, &Interfaces::new())
            .await,
    ));
    assert!(
        !interfaces
            .read()
            .await
            .get("eth0")
            .unwrap()
            .port_aggregate_active
    );
    let _server = server::start(
        &path,
        interfaces.clone(),
        Arc::new(NoopInterfaceDriver),
        &shared().identity("interfaced", ""),
    )
    .unwrap();

    let stream = shared()
        .identity("bfdd", "")
        .connect(&path, &nos_pki::PeerId::new("interfaced", ""))
        .await
        .unwrap();
    let mut writer = FramedWrite::new(stream, IpcCodec::<InterfaceRequest>::default());
    writer
        .send(InterfaceRequest::PushBfdMembers(
            nos_proto::BfdAggregateMembers {
                aggregate: "bond1".to_string(),
                up_members: vec!["eth0".to_string()],
            },
        ))
        .await
        .unwrap();

    for _ in 0..50 {
        if interfaces
            .read()
            .await
            .get("eth0")
            .unwrap()
            .port_aggregate_active
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("eth0 never became active");
}

#[tokio::test]
async fn push_bfd_members_applies_the_member_immediately() {
    let tmp = tempfile::tempdir().unwrap();
    let (driver, interfaces, mut w, _server) =
        bond_server(nos_proto::PortAggregateMode::Xor, true, "bfdd", tmp.path()).await;
    w.send(InterfaceRequest::PushBfdMembers(
        nos_proto::BfdAggregateMembers {
            aggregate: "bond1".to_string(),
            up_members: vec!["eth0".to_string()],
        },
    ))
    .await
    .unwrap();
    driver.wait_applied(true).await;
    assert!(
        interfaces
            .read()
            .await
            .get("eth0")
            .unwrap()
            .port_aggregate_active
    );
}

#[tokio::test]
async fn push_lacp_members_applies_the_active_member() {
    let tmp = tempfile::tempdir().unwrap();
    let (driver, interfaces, mut w, _server) = bond_server(
        nos_proto::PortAggregateMode::Lacp,
        false,
        "lacpd",
        tmp.path(),
    )
    .await;
    assert_eq!(driver.applied().len(), 0);

    w.send(InterfaceRequest::PushLacpMembers(
        nos_proto::LacpAggregateMembers {
            aggregate: "bond1".to_string(),
            active_members: vec!["eth0".to_string()],
        },
    ))
    .await
    .unwrap();
    driver.wait_applied(true).await;
    assert!(
        interfaces
            .read()
            .await
            .get("eth0")
            .unwrap()
            .port_aggregate_active
    );

    // Emptying the set re-applies the member as inactive.
    w.send(InterfaceRequest::PushLacpMembers(
        nos_proto::LacpAggregateMembers {
            aggregate: "bond1".to_string(),
            active_members: vec![],
        },
    ))
    .await
    .unwrap();
    driver.wait_applied(false).await;
}

#[tokio::test]
async fn push_for_an_unknown_aggregate_applies_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (driver, _interfaces, mut w, _server) = bond_server(
        nos_proto::PortAggregateMode::Lacp,
        false,
        "lacpd",
        tmp.path(),
    )
    .await;
    w.send(InterfaceRequest::PushLacpMembers(
        nos_proto::LacpAggregateMembers {
            aggregate: "nope".to_string(),
            active_members: vec!["eth0".to_string()],
        },
    ))
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(driver.applied().len(), 0, "{:?}", driver.applied());
}

// ---- live role gate (#364): refused roles are disconnected, others served ----

async fn connect_role(
    path: &std::path::Path,
    role: nos_proto::Role,
) -> (
    FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<InterfaceEvent>>,
    FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<InterfaceRequest>>,
) {
    let stream = shared()
        .identity(role.as_str(), "x")
        .connect(path, &nos_pki::PeerId::new("interfaced", ""))
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    (
        FramedRead::new(r, IpcCodec::<InterfaceEvent>::default()),
        FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default()),
    )
}

#[tokio::test]
async fn queries_and_pushes_are_gated_by_role_over_the_live_server() {
    use nos_proto::Role;
    use std::time::Duration;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("interface.sock");
    let interfaces = Arc::new(RwLock::new(sample_interfaces().await));
    let _server = server::start(
        &path,
        interfaces,
        Arc::new(NoopInterfaceDriver),
        &shared().identity("interfaced", ""),
    )
    .unwrap();

    let queriers = [
        Role::User,
        Role::Restd,
        Role::Bgpd,
        Role::Ribd,
        Role::Ospfd,
        Role::Ospfv3d,
        Role::Fdbd,
        Role::Stpd,
    ];
    for role in Role::ALL {
        // A query: a real reply for the allow list, a closed connection else.
        let (mut r, mut w) = connect_role(&path, role).await;
        w.send(InterfaceRequest::GetInterfaces).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), r.next())
            .await
            .unwrap_or_else(|_| panic!("{role:?}: connection left open with no reply"));
        if queriers.contains(&role) {
            assert!(
                matches!(reply, Some(Ok(InterfaceEvent::Interfaces(ref v))) if v.len() == 2),
                "{role:?}: {reply:?}"
            );
        } else {
            assert!(
                reply.is_none_or(|e| e.is_err()),
                "{role:?} must get no reply"
            );
        }

        // The pushes are fire-and-forget: kept open for the one owner,
        // disconnected for everyone else.
        let pushes: [(Role, InterfaceRequest); 3] = [
            (
                Role::Lacpd,
                InterfaceRequest::PushLacpMembers(nos_proto::LacpAggregateMembers {
                    aggregate: "nope".to_string(),
                    active_members: vec![],
                }),
            ),
            (
                Role::Bfdd,
                InterfaceRequest::PushBfdMembers(nos_proto::BfdAggregateMembers {
                    aggregate: "nope".to_string(),
                    up_members: vec![],
                }),
            ),
            (Role::Stpd, InterfaceRequest::SetStpPortStates(Vec::new())),
        ];
        for (owner, req) in pushes {
            let (mut r, mut w) = connect_role(&path, role).await;
            w.send(req).await.unwrap();
            let next = tokio::time::timeout(
                Duration::from_secs(if role == owner { 1 } else { 5 }),
                r.next(),
            )
            .await;
            if role == owner {
                assert!(next.is_err(), "{role:?} owns this push but was refused");
            } else {
                let closed = next.unwrap_or_else(|_| {
                    panic!("{role:?}: a refused push left the connection open")
                });
                assert!(closed.is_none_or(|e| e.is_err()), "{role:?}");
            }
        }
    }
}
