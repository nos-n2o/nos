//! The pre-policy Adj-RIB-Out hook (#867, RFC 8671): candidates before the
//! export policy, and nothing for a peer no station monitors.

use super::*;
use crate::bmp::{Hub, PeerUpInfo, Scope, StationCfg};
use crate::message::{BgpCodec, BgpMessage};
use bytes::BytesMut;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Decoder;

const SRC: &str = "10.0.0.1";
const DST: &str = "10.0.0.2";

/// The next Route Monitoring frame: (flags byte, decoded UPDATE).
async fn out_frame(s: &mut TcpStream) -> (u8, UpdateMessage) {
    let mut h = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut h))
        .await
        .expect("a BMP frame in time")
        .unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(h[1..5].try_into().unwrap()) as usize - 6];
    s.read_exact(&mut body).await.unwrap();
    if h[5] != 0 {
        return Box::pin(out_frame(s)).await;
    }
    let mut b = BytesMut::from(&body[42..]);
    let Some(BgpMessage::Update(u)) = BgpCodec::default().decode(&mut b).unwrap() else {
        panic!("an UPDATE")
    };
    (body[1], u)
}

/// A station with `out`, `DST` reported up, a RIB with `SRC` (the route
/// source, not monitored) and `DST` whose export policy denies everything.
async fn setup(out: nos_proto::BmpMonitorOut) -> (BgpRib, Arc<Hub>, TcpStream) {
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
        statistics_interval: None,
        monitor_out: out,
    }])
    .await;
    let (mut c, _) = listener.accept().await.unwrap();
    // The Initiation means the station queue is live.
    let mut h = [0u8; 6];
    c.read_exact(&mut h).await.unwrap();
    let mut rest = vec![0u8; u32::from_be_bytes(h[1..5].try_into().unwrap()) as usize - 6];
    c.read_exact(&mut rest).await.unwrap();
    assert_eq!(h[5], 4);
    hub.peer_up(PeerUpInfo {
        peer: addr(DST),
        asn: 65002,
        bgp_id: v4("192.0.2.2"),
        two_octet_as: false,
        local: addr("10.0.0.254"),
        local_port: 179,
        remote_port: 1,
        sent_open: bytes::Bytes::new(),
        recv_open: bytes::Bytes::new(),
        time: Duration::ZERO,
        add_path_afis: HashSet::new(),
    });
    let mut rib = new_rib(65000);
    rib.set_bmp(hub.clone());
    std::mem::forget(register_mp_peer(
        &mut rib,
        addr(SRC),
        false,
        addr("10.0.0.254"),
        all_afs(),
    ));
    let (tx, rx) = test_channel();
    std::mem::forget(rx);
    rib.peer_established(
        addr(DST),
        false,
        Some(addr("10.0.0.254")),
        all_afs(),
        true,
        None,
        false,
        false,
        HashSet::new(),
        deny_all_policy(),
        tx,
    );
    (rib, hub, c)
}

fn learn(rib: &mut BgpRib, p: &str) {
    let u = ebgp_update(vec![p], vec![65001], SRC);
    rib.handle_update(addr(SRC), false, v4("192.0.2.1"), &u, &nos_rpl::ACCEPT_ALL);
}

#[tokio::test]
async fn export_denied_prefix_is_announced_pre_policy_and_withdrawn_with_its_source() {
    let (mut rib, hub, mut c) = setup(nos_proto::BmpMonitorOut::PrePolicy).await;
    learn(&mut rib, "1.0.0.0/24");
    let (flags, u) = out_frame(&mut c).await;
    assert_eq!(flags & 0x70, 0x10, "O set, L and A clear");
    assert_eq!(u.nlri, vec!["1.0.0.0/24".parse().unwrap()]);
    assert_eq!(u.attributes.unwrap().next_hop, Ipv4Addr::UNSPECIFIED);
    assert!(rib.bmp_pre_out[&addr(DST)].contains(&"1.0.0.0/24".parse().unwrap()));

    // The source's own session is not reported up: nothing is recorded for it.
    assert!(!rib.bmp_pre_out.contains_key(&addr(SRC)));

    let w = UpdateMessage {
        withdrawn_routes: vec!["1.0.0.0/24".parse().unwrap()],
        ..empty_update()
    };
    rib.handle_update(addr(SRC), false, v4("192.0.2.1"), &w, &nos_rpl::ACCEPT_ALL);
    let (flags, u) = out_frame(&mut c).await;
    assert_eq!(flags & 0x70, 0x10);
    assert_eq!(u.withdrawn_routes, vec!["1.0.0.0/24".parse().unwrap()]);
    assert!(rib.bmp_pre_out[&addr(DST)].is_empty());
    hub.shutdown().await;
}

#[tokio::test]
async fn nothing_is_tracked_when_no_station_wants_the_pre_policy_view() {
    let (mut rib, hub, _c) = setup(nos_proto::BmpMonitorOut::PostPolicy).await;
    learn(&mut rib, "1.0.0.0/24");
    assert!(rib.bmp_pre_out.is_empty());
    hub.shutdown().await;
}

#[tokio::test]
async fn snapshot_resets_the_tracking_to_the_candidates() {
    let (mut rib, hub, _c) = setup(nos_proto::BmpMonitorOut::PrePolicy).await;
    learn(&mut rib, "1.0.0.0/24");
    rib.bmp_pre_out.clear();
    let snap = rib.bmp_out_snapshot(addr(DST), true, true);
    assert_eq!(snap.pre.len(), 1);
    assert!(snap.post.is_empty(), "export policy denied it");
    assert_eq!(rib.bmp_pre_out[&addr(DST)].len(), 1);
    let c = rib.bmp_out_counts(addr(DST));
    assert_eq!((c.pre, c.pre_v4, c.post), (1, 1, 0));
    hub.shutdown().await;
}

/// A rib with an accepting destination (`DST`, optionally ADD-PATH) and a
/// route learned from `SRC`; no hub (the snapshot needs none).
fn accepting(add_path: bool) -> BgpRib {
    let mut rib = new_rib(65000);
    std::mem::forget(register_mp_peer(
        &mut rib,
        addr(SRC),
        false,
        addr("10.0.0.254"),
        all_afs(),
    ));
    let (tx, rx) = test_channel();
    std::mem::forget(rx);
    rib.peer_established(
        addr(DST),
        false,
        Some(addr("10.0.0.254")),
        all_afs(),
        true,
        None,
        false,
        false,
        if add_path {
            [AddressFamily::Ipv4Unicast].into_iter().collect()
        } else {
            HashSet::new()
        },
        accept_all_policy(),
        tx,
    );
    learn(&mut rib, "1.0.0.0/24");
    rib
}

#[test]
fn post_snapshot_rebuilds_what_the_peer_was_sent() {
    let mut rib = accepting(false);
    let snap = rib.bmp_out_snapshot(addr(DST), true, false);
    assert!(snap.pre.is_empty() && snap.tx_afis.is_empty());
    let [OutboundUpdate::Announce(adv)] = &snap.post[..] else {
        panic!("{:?}", snap.post.len())
    };
    assert_eq!(adv.prefix, "1.0.0.0/24".parse().unwrap());
    assert_eq!(
        adv.as_path,
        vec![65000, 65001],
        "export prepend is in the post view"
    );
    let c = rib.bmp_out_counts(addr(DST));
    assert_eq!((c.post, c.post_v4, c.post_v6), (1, 1, 0));
    let s = rib.bmp_stats(addr(DST), rib.loc_totals(), nos_proto::BmpMonitorOut::Both);
    for t in [14, 15, 16, 17] {
        assert!(
            s.iter().any(|x| matches!(x,
                crate::bmp::stats::Stat::Gauge(n, _) | crate::bmp::stats::Stat::AfiSafi(n, ..) if *n == t)),
            "type {t}"
        );
    }
}

#[test]
fn add_path_snapshot_keeps_the_path_ids_it_sent() {
    let mut rib = accepting(true);
    let snap = rib.bmp_out_snapshot(addr(DST), true, false);
    assert_eq!(snap.tx_afis, HashSet::from([1]), "AFI 1 carries ids");
    let ids: Vec<_> = snap
        .post
        .iter()
        .map(|u| match u {
            OutboundUpdate::Announce(a) => a.path_id,
            _ => panic!("announce expected"),
        })
        .collect();
    assert_eq!(ids.len(), 1);
    assert!(ids[0].is_some());
    assert_eq!(rib.bmp_out_counts(addr(DST)).post_v4, 1);
}
