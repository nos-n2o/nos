//! The post-policy BMP tap (#864): which Adj-RIB-In changes reach a station.

use super::*;
use crate::bmp::{Hub, PeerUpInfo, Scope, StationCfg};
use crate::message::{BgpCodec, BgpMessage};
use bytes::BytesMut;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Decoder;

const PEER: &str = "10.0.0.1";

async fn frame(s: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut h = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut h))
        .await
        .expect("a BMP frame in time")
        .unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(h[1..5].try_into().unwrap()) as usize - 6];
    s.read_exact(&mut body).await.unwrap();
    (h[5], body)
}

/// The next Route Monitoring frame: (L flag, decoded UPDATE).
async fn route(s: &mut TcpStream) -> (bool, UpdateMessage) {
    let (t, body) = frame(s).await;
    assert_eq!(t, 0, "Route Monitoring");
    let mut b = BytesMut::from(&body[42..]);
    let Some(BgpMessage::Update(u)) = BgpCodec::default().decode(&mut b).unwrap() else {
        panic!("an UPDATE")
    };
    (body[1] & 0x40 != 0, u)
}

async fn setup() -> (BgpRib, Arc<Hub>, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub = Hub::new();
    hub.set_stations(vec![StationCfg {
        name: "s".into(),
        addr: listener.local_addr().unwrap(),
        vrf: None,
        sys_name: "x".into(),
        table: None,
        scope: Scope::default(),
        monitor: nos_proto::BmpMonitor::PostPolicy,
    }])
    .await;
    let (mut c, _) = listener.accept().await.unwrap();
    assert_eq!(frame(&mut c).await.0, 4, "Initiation");
    hub.peer_up(PeerUpInfo {
        peer: addr(PEER),
        asn: 65001,
        bgp_id: v4("192.0.2.1"),
        two_octet_as: false,
        local: addr("10.0.0.254"),
        local_port: 179,
        remote_port: 1,
        sent_open: bytes::Bytes::new(),
        recv_open: bytes::Bytes::new(),
        time: Duration::ZERO,
        add_path_afis: HashSet::new(),
    });
    assert_eq!(frame(&mut c).await.0, 3, "Peer Up");
    let mut rib = new_rib(65000);
    rib.set_bmp(hub.clone());
    std::mem::forget(register_peer(
        &mut rib,
        addr(PEER),
        false,
        addr("10.0.0.254"),
    ));
    (rib, hub, c)
}

fn learn(rib: &mut BgpRib, prefixes: &[&str], policy: &nos_rpl::CompiledPolicy) {
    let u = ebgp_update(prefixes.to_vec(), vec![65001], PEER);
    rib.handle_update(addr(PEER), false, v4("192.0.2.1"), &u, policy);
}

fn withdraw(rib: &mut BgpRib, p: &str) {
    let u = UpdateMessage {
        withdrawn_routes: vec![p.parse().unwrap()],
        ..empty_update()
    };
    rib.handle_update(addr(PEER), false, v4("192.0.2.1"), &u, &nos_rpl::ACCEPT_ALL);
}

#[tokio::test]
async fn announce_withdraw_and_state_compression() {
    let (mut rib, hub, mut c) = setup().await;
    learn(&mut rib, &["1.0.0.0/24"], &nos_rpl::ACCEPT_ALL);
    let (post, u) = route(&mut c).await;
    assert!(post, "L flag set");
    assert_eq!(u.nlri, vec!["1.0.0.0/24".parse().unwrap()]);
    assert_eq!(u.attributes.unwrap().as_path.flat(), [65001]);

    // An identical re-announcement and a policy-rejected prefix send nothing:
    // the next frame is the sentinel.
    learn(&mut rib, &["1.0.0.0/24"], &nos_rpl::ACCEPT_ALL);
    learn(&mut rib, &["9.0.0.0/24"], &nos_rpl::DENY_ALL);
    learn(&mut rib, &["2.0.0.0/24"], &nos_rpl::ACCEPT_ALL);
    assert_eq!(
        route(&mut c).await.1.nlri,
        vec!["2.0.0.0/24".parse().unwrap()]
    );

    // A rejected re-announcement of a held prefix is a withdraw.
    learn(&mut rib, &["2.0.0.0/24"], &nos_rpl::DENY_ALL);
    assert_eq!(
        route(&mut c).await.1.withdrawn_routes,
        vec!["2.0.0.0/24".parse().unwrap()]
    );

    withdraw(&mut rib, "1.0.0.0/24");
    assert_eq!(
        route(&mut c).await.1.withdrawn_routes,
        vec!["1.0.0.0/24".parse().unwrap()]
    );
    // Withdrawing what is not held sends nothing.
    withdraw(&mut rib, "1.0.0.0/24");
    learn(&mut rib, &["3.0.0.0/24"], &nos_rpl::ACCEPT_ALL);
    assert_eq!(
        route(&mut c).await.1.nlri,
        vec!["3.0.0.0/24".parse().unwrap()]
    );
    hub.shutdown().await;
}

#[tokio::test]
async fn re_evaluation_reaches_the_station() {
    let (mut rib, hub, mut c) = setup().await;
    let peer = addr(PEER);
    rib.set_peer_soft_reconfig(peer, true);
    learn(&mut rib, &["1.0.0.0/24"], &nos_rpl::DENY_ALL);
    // Loosening the policy admits the retained route: announced post-policy.
    rib.reevaluate_peer(peer, Arc::new(nos_rpl::ACCEPT_ALL.clone()));
    assert_eq!(
        route(&mut c).await.1.nlri,
        vec!["1.0.0.0/24".parse().unwrap()]
    );
    // Tightening withdraws it.
    rib.reevaluate_peer(peer, Arc::new(nos_rpl::DENY_ALL.clone()));
    assert_eq!(
        route(&mut c).await.1.withdrawn_routes,
        vec!["1.0.0.0/24".parse().unwrap()]
    );
    hub.shutdown().await;
}

#[test]
fn an_unmonitored_rib_does_no_work() {
    let mut rib = new_rib(65000);
    rib.set_bmp(Hub::new());
    assert!(
        super::super::bmp_tap::tap(rib.bmp.as_ref()).is_none(),
        "no station: gate closed"
    );
    std::mem::forget(register_peer(
        &mut rib,
        addr(PEER),
        false,
        addr("10.0.0.254"),
    ));
    learn(&mut rib, &["1.0.0.0/24"], &nos_rpl::ACCEPT_ALL);
    assert_eq!(rib.bmp_keys(addr(PEER), true).len(), 1);
}

#[test]
fn dump_reads_the_current_paths_and_skips_withdrawn_keys() {
    let mut rib = new_rib(65000);
    let peer = addr(PEER);
    std::mem::forget(register_peer(&mut rib, peer, false, addr("10.0.0.254")));
    rib.set_peer_soft_reconfig(peer, true);
    learn(&mut rib, &["1.0.0.0/24", "2.0.0.0/24"], &nos_rpl::DENY_ALL);
    assert!(
        rib.bmp_keys(peer, true).is_empty(),
        "rejected: not post-policy"
    );
    let mut pre = rib.bmp_keys(peer, false);
    pre.sort();
    assert_eq!(pre, vec![prefix("1.0.0.0/24"), prefix("2.0.0.0/24")]);
    withdraw(&mut rib, "2.0.0.0/24");
    // The snapshot predates the withdrawal: its key yields nothing.
    let paths = rib.bmp_paths(peer, false, &pre);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].0, prefix("1.0.0.0/24"));
    assert_eq!(
        rib.bmp_families(peer).len(),
        2,
        "both unicast families negotiated"
    );
    assert_eq!(rib.bmp_families(addr("10.9.9.9")), Vec::<u16>::new());
}
