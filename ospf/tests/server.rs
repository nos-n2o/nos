//! Live role gate of the OSPF IPC server over real mutual TLS (#364): a role
//! that may not send a request is disconnected with no reply, a role that may
//! gets a real answer. Complements the pure `allowed` tests in `server.rs`,
//! which cannot see the `handle_connection` glue.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_ospf::boot::BootCounter;
use nos_ospf::link::LinkManager;
use nos_pki::testing::shared;
use nos_pki::{PeerId, Stream};
use nos_proto::{IpcCodec, OspfEvent, OspfRequest, RedistributeUpdate, Role};
use tokio_util::codec::{FramedRead, FramedWrite};

type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<OspfEvent>>;
type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<OspfRequest>>;

async fn connect_as(path: &std::path::Path, role: Role) -> (Reader, Writer) {
    let stream = shared()
        .identity(role.as_str(), "x")
        .connect(path, &PeerId::new("ospfd", "r1"))
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    (
        FramedRead::new(r, IpcCodec::default()),
        FramedWrite::new(w, IpcCodec::default()),
    )
}

/// `true` while the server keeps the connection open and sends nothing.
async fn stays_open(reader: &mut Reader) -> bool {
    tokio::time::timeout(Duration::from_secs(1), reader.next())
        .await
        .is_err()
}

/// The next frame, or `None` when the server closed (or reset) instead.
async fn next_event(reader: &mut Reader) -> Option<OspfEvent> {
    tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("connection left open with no reply")
        .and_then(Result::ok)
}

fn start() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    tokio::task::JoinHandle<()>,
) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("ospf.sock");
    // Nothing configured: every query answers with an empty list.
    let links = LinkManager::new(1, None, BootCounter::in_memory());
    let server = nos_ospf::server::start(
        &path,
        "r1".to_string(),
        links,
        &shared().identity("ospfd", "r1"),
    )
    .unwrap();
    (tmp, path, server)
}

#[tokio::test]
async fn only_people_get_the_show_queries_answered() {
    let (_tmp, path, _server) = start();
    for role in Role::ALL {
        for kind in 0..3 {
            let (mut r, mut w) = connect_as(&path, role).await;
            let req = match kind {
                0 => OspfRequest::GetNeighbors,
                1 => OspfRequest::GetDatabase,
                _ => OspfRequest::GetInterfaces,
            };
            w.send(req).await.unwrap();
            let reply = next_event(&mut r).await;
            if !matches!(role, Role::User | Role::Restd) {
                assert!(reply.is_none(), "{role:?} kind={kind}: no reply");
                continue;
            }
            let empty = match reply {
                Some(OspfEvent::Neighbors(v)) if kind == 0 => v.is_empty(),
                Some(OspfEvent::Database(v)) if kind == 1 => v.is_empty(),
                Some(OspfEvent::Interfaces(v)) if kind == 2 => v.is_empty(),
                other => panic!("{role:?} kind={kind}: unexpected {other:?}"),
            };
            assert!(empty);
        }
    }
}

#[tokio::test]
async fn segment_routing_query_is_for_people() {
    let (_tmp, path, _server) = start();
    for role in Role::ALL {
        let (mut r, mut w) = connect_as(&path, role).await;
        w.send(OspfRequest::GetSegmentRouting).await.unwrap();
        let reply = next_event(&mut r).await;
        if matches!(role, Role::User | Role::Restd) {
            assert!(matches!(reply, Some(OspfEvent::SegmentRouting(s)) if s.srgb.is_empty()));
        } else {
            assert!(reply.is_none(), "{role:?}: no reply");
        }
    }
}

/// The redistribution feed is fire-and-forget: `ribd` keeps its connection
/// open with no reply, any other role is disconnected.
#[tokio::test]
async fn only_ribd_may_feed_redistribution() {
    let (_tmp, path, _server) = start();
    for role in Role::ALL {
        let (mut r, mut w) = connect_as(&path, role).await;
        w.send(OspfRequest::RedistributeRoutes(RedistributeUpdate::Full(
            vec![],
        )))
        .await
        .unwrap();
        if role == Role::Ribd {
            assert!(stays_open(&mut r).await, "ribd was refused");
        } else {
            assert!(
                next_event(&mut r).await.is_none(),
                "{role:?} must be disconnected"
            );
        }
    }
}

/// #728: a `RedistributeRoutes` `Full` past the codec's 16 MiB `MAX_FRAME`,
/// cut by `RedistributeUpdate::split`, crosses the real codec as `ribd` and
/// is staged until its closing `Full`: nothing is held from the `FullPart`s
/// alone, then the whole set lands at once (parts applied one by one would
/// leave only the last chunk, each `Full` clearing the raw set).
#[tokio::test]
async fn redistribution_past_max_frame_is_staged_until_the_closing_full() {
    use nos_proto::RedistributedRoute;
    use tokio_util::codec::Encoder;
    // ~11 encoded bytes per IPv4 route (OSPFv2 keeps IPv4 only): 1.6M is
    // ~17 MiB.
    const N: u32 = 1_600_000;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("ospf.sock");
    let links = LinkManager::new(1, None, BootCounter::in_memory());
    let _server = nos_ospf::server::start(
        &path,
        "r1".to_string(),
        links.clone(),
        &shared().identity("ospfd", "r1"),
    )
    .unwrap();

    let all: Vec<RedistributedRoute> = (0..N)
        .map(|i| RedistributedRoute {
            prefix: nos_proto::IpNet::new(std::net::Ipv4Addr::from(0x0a00_0000 | i).into(), 32)
                .unwrap(),
            gateway: std::net::Ipv4Addr::new(192, 0, 2, 1).into(),
        })
        .collect();
    assert!(
        IpcCodec::<OspfRequest>::default()
            .encode(
                OspfRequest::RedistributeRoutes(RedistributeUpdate::Full(all.clone())),
                &mut tokio_util::bytes::BytesMut::new()
            )
            .is_err(),
        "the unchunked snapshot must exceed MAX_FRAME"
    );
    let mut frames = RedistributeUpdate::Full(all).split();
    let last = frames.pop().unwrap();
    assert!(frames.len() > 1);
    let (mut r, mut w) = connect_as(&path, Role::Ribd).await;
    for frame in frames {
        w.feed(OspfRequest::RedistributeRoutes(frame))
            .await
            .unwrap();
    }
    w.flush().await.unwrap();
    // Fire-and-forget: no reply to wait on, so give the server time.
    assert!(stays_open(&mut r).await, "ribd disconnected mid-snapshot");
    assert_eq!(
        links.redistribute_raw_len().await,
        0,
        "half a snapshot held"
    );

    w.send(OspfRequest::RedistributeRoutes(last)).await.unwrap();
    for _ in 0..200 {
        if links.redistribute_raw_len().await == N as usize {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(links.redistribute_raw_len().await, N as usize);
}
