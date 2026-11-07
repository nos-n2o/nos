use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_config::{BgpInstance, Config, ConfigStore, ListenAddr};
use nos_pki::testing::TestPki;
use nos_pki::{Identity, PeerId, Stream};
use nos_proto::{
    BgpInstanceOp, ConfigOp, DiffScope, DiffStatus, Event, IpcCodec, Request, Topic,
    TransactionBase,
};
use tokio_util::codec::{FramedRead, FramedWrite};

fn instance(name: &str, asn: u32) -> BgpInstance {
    BgpInstance {
        name: name.to_string(),
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        asn,
        peer_groups: Vec::new(),
        peers: Vec::new(),
        cluster_id: None,
        maximum_paths: None,
        confederation: nos_proto::BgpConfederation::default(),
        rpki_caches: Vec::new(),
        bmp_stations: Vec::new(),
        aggregates: Vec::new(),
        graceful_restart: nos_proto::BgpGracefulRestart::default(),
        routing_table: None,
        redistribute_policy: None,
    }
}

fn ensure_op(name: &str) -> ConfigOp {
    ConfigOp::BgpInstance(BgpInstanceOp::Ensure {
        name: name.to_string(),
    })
}

fn set_asn_op(name: &str, asn: u32) -> ConfigOp {
    ConfigOp::BgpInstance(BgpInstanceOp::SetAsn {
        name: name.to_string(),
        asn,
    })
}

fn ensure_routing_table_op(name: &str) -> ConfigOp {
    ConfigOp::RoutingTable(nos_proto::RoutingTableOp::Ensure {
        name: name.to_string(),
    })
}

fn set_routing_table_bgp_instance_op(name: &str, bgp_instance: &str) -> ConfigOp {
    ConfigOp::RoutingTable(nos_proto::RoutingTableOp::SetBgpInstance {
        name: name.to_string(),
        bgp_instance: bgp_instance.to_string(),
    })
}

fn ensure_static_routing_instance_op(name: &str) -> ConfigOp {
    ConfigOp::StaticRoutingInstance(nos_proto::StaticRoutingInstanceOp::Ensure {
        name: name.to_string(),
    })
}

/// One CA per test binary: the server identity `start_ipc_server` is given
/// and every client `connect`s with come from it.
static PKI: std::sync::LazyLock<TestPki> = std::sync::LazyLock::new(TestPki::new);

fn server_identity() -> Identity {
    PKI.identity("configd", "")
}

fn configd() -> PeerId {
    PeerId::new("configd", "")
}

type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<Event>>;
type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<Request>>;

/// Connects as a person: the role allowed to do everything.
async fn connect(socket_path: &std::path::Path) -> (Reader, Writer) {
    connect_as(socket_path, "user", "tester").await
}

async fn connect_as(socket_path: &std::path::Path, role: &str, name: &str) -> (Reader, Writer) {
    let stream = PKI
        .identity(role, name)
        .connect(socket_path, &configd())
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    (
        FramedRead::new(r, IpcCodec::<Event>::default()),
        FramedWrite::new(w, IpcCodec::<Request>::default()),
    )
}

/// A bounded read: a dead dispatcher/forwarder fails the test in seconds
/// instead of hanging (or ending a mutant as a Timeout, #374).
async fn next_event(reader: &mut Reader) -> Event {
    tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("no reply within 5s")
        .expect("connection closed without a reply")
        .expect("undecodable reply")
}

#[tokio::test]
async fn get_returns_current_config() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    store
        .open_transaction("t1", TransactionBase::Blank)
        .await
        .unwrap();
    store.apply_op("t1", ensure_op("default")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("default", 65000))
        .await
        .unwrap();
    store.commit_transaction("t1", None).await.unwrap();
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(Request::Get).await.unwrap();

    let event = next_event(&mut reader).await;
    match event {
        Event::Config(c) => {
            assert_eq!(c.bgp_instances.len(), 1);
            assert_eq!(c.bgp_instances[0].name, "default");
        }
        other => panic!("expected Config event, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribe_receives_initial_snapshot_then_updates() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    // Give the accept loop a moment to be ready.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(Request::Subscribe).await.unwrap();

    // Initial snapshot — empty config.
    let event = next_event(&mut reader).await;
    assert!(matches!(event, Event::Config(c) if c.bgp_instances.is_empty()));

    // Commit a change directly through the store (in-process, as a future
    // daemon-internal caller would).
    store
        .open_transaction("t1", TransactionBase::Blank)
        .await
        .unwrap();
    store.apply_op("t1", ensure_op("vrf-a")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("vrf-a", 65001))
        .await
        .unwrap();
    store.commit_transaction("t1", None).await.unwrap();

    // Receive the update.
    let event = next_event(&mut reader).await;
    match event {
        Event::Config(c) => assert_eq!(c.bgp_instances[0].name, "vrf-a"),
        other => panic!("expected Config event, got {other:?}"),
    }
}

#[tokio::test]
async fn unsubscribe_stops_updates() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(Request::Subscribe).await.unwrap();

    // Consume initial snapshot.
    next_event(&mut reader).await;

    // Unsubscribe, then commit.
    writer.send(Request::Unsubscribe).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await; // let server process Unsubscribe

    store
        .open_transaction("t1", TransactionBase::Blank)
        .await
        .unwrap();
    store.apply_op("t1", ensure_op("vrf-b")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("vrf-b", 65002))
        .await
        .unwrap();
    store.commit_transaction("t1", None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;

    // No event should arrive within a short timeout.
    let result = tokio::time::timeout(Duration::from_millis(50), reader.next()).await;
    assert!(
        result.is_err(),
        "expected timeout, but received an event after Unsubscribe"
    );
}

/// Regression test: a `Subscribe` client is documented (`client::subscribe`)
/// to send its request then drop its write half — "the caller owns its
/// lifetime" — so the connection must keep delivering events after that
/// half-close, not just the initial snapshot. Over TLS the halves come from
/// `tokio::io::split`, so dropping `writer` must leave `reader` (and the
/// stream behind it) untouched, mirroring real client usage exactly.
#[tokio::test]
async fn subscribe_survives_client_dropping_its_write_half() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let mut reader = {
        let (mut reader, mut writer) = connect(&path).await;
        writer.send(Request::Subscribe).await.unwrap();
        next_event(&mut reader).await; // initial snapshot
        reader
        // `writer` dropped here — the connection's write-to-server half closes.
    };

    store
        .open_transaction("t1", TransactionBase::Blank)
        .await
        .unwrap();
    store.apply_op("t1", ensure_op("vrf-c")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("vrf-c", 65003))
        .await
        .unwrap();
    store.commit_transaction("t1", None).await.unwrap();

    let event = tokio::time::timeout(Duration::from_millis(200), reader.next())
        .await
        .expect("expected a Config event after commit, connection closed instead")
        .unwrap()
        .unwrap();
    match event {
        Event::Config(c) => assert_eq!(c.bgp_instances[0].name, "vrf-c"),
        other => panic!("expected Config event, got {other:?}"),
    }
}

/// Same regression as `subscribe_survives_client_dropping_its_write_half`,
/// for the `SubscribeDiff` path.
#[tokio::test]
async fn subscribe_diff_survives_client_dropping_its_write_half() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let mut reader = {
        let (mut reader, mut writer) = connect(&path).await;
        writer
            .send(Request::SubscribeDiff {
                scopes: vec![DiffScope::BgpInstances],
            })
            .await
            .unwrap();
        next_event(&mut reader).await; // initial diff
        reader
        // `writer` dropped here — the connection's write-to-server half closes.
    };

    store
        .open_transaction("t1", TransactionBase::Blank)
        .await
        .unwrap();
    store.apply_op("t1", ensure_op("vrf-d")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("vrf-d", 65004))
        .await
        .unwrap();
    store.commit_transaction("t1", None).await.unwrap();

    let event = tokio::time::timeout(Duration::from_millis(200), reader.next())
        .await
        .expect("expected a Diff event after commit, connection closed instead")
        .unwrap()
        .unwrap();
    match event {
        Event::Diff(diff) => {
            assert_eq!(diff.bgp_instances.len(), 1);
            assert_eq!(diff.bgp_instances[0].name, "vrf-d");
            assert_eq!(diff.bgp_instances[0].status, DiffStatus::Added);
        }
        other => panic!("expected Diff event, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribe_diff_reports_pre_existing_instance_as_added_then_incremental_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    store
        .open_transaction("t1", TransactionBase::Blank)
        .await
        .unwrap();
    store.apply_op("t1", ensure_op("r1")).await.unwrap();
    store.apply_op("t1", set_asn_op("r1", 65000)).await.unwrap();
    store.commit_transaction("t1", None).await.unwrap();

    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(Request::SubscribeDiff {
            scopes: vec![DiffScope::BgpInstances],
        })
        .await
        .unwrap();

    // Initial diff: the pre-existing instance shows up as Added, since it's
    // synthesized against an empty config.
    let event = next_event(&mut reader).await;
    match event {
        Event::Diff(diff) => {
            assert_eq!(diff.bgp_instances.len(), 1);
            assert_eq!(diff.bgp_instances[0].name, "r1");
            assert_eq!(diff.bgp_instances[0].status, DiffStatus::Added);
        }
        other => panic!("expected Diff event, got {other:?}"),
    }

    // Add a second instance and remove the first in one commit.
    store
        .open_transaction("t2", TransactionBase::Current)
        .await
        .unwrap();
    store.apply_op("t2", ensure_op("r2")).await.unwrap();
    store.apply_op("t2", set_asn_op("r2", 65001)).await.unwrap();
    store
        .apply_op(
            "t2",
            ConfigOp::BgpInstance(BgpInstanceOp::Delete {
                name: "r1".to_string(),
            }),
        )
        .await
        .unwrap();
    store.commit_transaction("t2", None).await.unwrap();

    let event = next_event(&mut reader).await;
    match event {
        Event::Diff(diff) => {
            assert_eq!(diff.bgp_instances.len(), 2);
            let added = diff
                .bgp_instances
                .iter()
                .find(|s| s.status == DiffStatus::Added)
                .expect("added section");
            let removed = diff
                .bgp_instances
                .iter()
                .find(|s| s.status == DiffStatus::Removed)
                .expect("removed section");
            assert_eq!(added.name, "r2");
            assert_eq!(removed.name, "r1");
        }
        other => panic!("expected Diff event, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribe_diff_skips_commits_outside_requested_scope() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(Request::SubscribeDiff {
            scopes: vec![DiffScope::BgpInstances],
        })
        .await
        .unwrap();

    // Initial diff — nothing configured yet, so it's empty.
    let event = next_event(&mut reader).await;
    assert!(matches!(event, Event::Diff(d) if d.is_empty()));

    // A hostname-only commit is out of scope and must never be forwarded.
    store
        .open_transaction("t1", TransactionBase::Blank)
        .await
        .unwrap();
    store
        .apply_op("t1", ConfigOp::SetHostname("router-b".to_string()))
        .await
        .unwrap();
    store.commit_transaction("t1", None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;

    let result = tokio::time::timeout(Duration::from_millis(50), reader.next()).await;
    assert!(
        result.is_err(),
        "expected timeout, but received a Diff event for an out-of-scope commit"
    );
}

#[tokio::test]
async fn save_persists_running_config_to_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");
    let config_path = tmp.path().join("config.yaml");

    let store = ConfigStore::new(Config::default(), Some(config_path.clone()));
    store
        .open_transaction("t1", TransactionBase::Blank)
        .await
        .unwrap();
    store.apply_op("t1", ensure_op("default")).await.unwrap();
    store
        .apply_op("t1", set_asn_op("default", 65000))
        .await
        .unwrap();
    store.commit_transaction("t1", None).await.unwrap();
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer.send(Request::Save).await.unwrap();

    let event = next_event(&mut reader).await;
    assert!(matches!(event, Event::Saved));

    let saved = nos_config::persistence::load_or_default(&config_path).unwrap();
    assert_eq!(saved.bgp_instances.len(), 1);
    assert_eq!(saved.bgp_instances[0].name, "default");
}

#[tokio::test]
async fn save_without_configured_path_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer.send(Request::Save).await.unwrap();

    let event = next_event(&mut reader).await;
    assert!(matches!(event, Event::Error(_)));
}

#[tokio::test]
async fn open_transaction_blank_and_current_over_ipc() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(
        Config {
            bgp_instances: vec![instance("default", 65000)],
            ..Default::default()
        },
        None,
    );
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "blank1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    match next_event(&mut reader).await {
        Event::Transaction(snap) => {
            assert_eq!(
                snap.config.bgp_instances,
                [] as [nos_config::BgpInstance; 0]
            );
            assert!(!snap.resumed);
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "current1".to_string(),
            base: TransactionBase::Current,
        })
        .await
        .unwrap();
    match next_event(&mut reader).await {
        Event::Transaction(snap) => {
            assert_eq!(snap.config.bgp_instances.len(), 1);
            assert!(!snap.resumed);
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn resume_by_reopening_over_new_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    // Connection A: open + edit, then drop.
    {
        let (mut reader, mut writer) = connect(&sock_path).await;
        writer
            .send(Request::OpenTransaction {
                actor: None,
                name: "t1".to_string(),
                base: TransactionBase::Blank,
            })
            .await
            .unwrap();
        next_event(&mut reader).await;

        writer
            .send(Request::ApplyOp {
                actor: None,
                name: "t1".to_string(),
                op: ensure_op("r1"),
            })
            .await
            .unwrap();
        next_event(&mut reader).await;
    }

    // Connection B: reopen the same name.
    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Current,
        })
        .await
        .unwrap();
    match next_event(&mut reader).await {
        Event::Transaction(snap) => {
            assert!(snap.resumed);
            assert!(snap.dirty);
            assert_eq!(snap.config.bgp_instances.len(), 1);
            assert_eq!(snap.config.bgp_instances[0].name, "r1");
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn apply_op_over_ipc_reflects_in_get_transaction() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    next_event(&mut reader).await;

    writer
        .send(Request::ApplyOp {
            actor: None,
            name: "t1".to_string(),
            op: ensure_op("r1"),
        })
        .await
        .unwrap();
    next_event(&mut reader).await;

    writer
        .send(Request::GetTransaction {
            name: "t1".to_string(),
        })
        .await
        .unwrap();
    match next_event(&mut reader).await {
        Event::Transaction(snap) => {
            assert_eq!(snap.config.bgp_instances.len(), 1);
            assert_eq!(snap.config.bgp_instances[0].name, "r1");
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn commit_over_ipc_updates_running_visible_to_fresh_get() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    next_event(&mut reader).await;
    writer
        .send(Request::ApplyOp {
            actor: None,
            name: "t1".to_string(),
            op: ensure_op("r1"),
        })
        .await
        .unwrap();
    next_event(&mut reader).await;
    writer
        .send(Request::ApplyOp {
            actor: None,
            name: "t1".to_string(),
            op: set_asn_op("r1", 65001),
        })
        .await
        .unwrap();
    next_event(&mut reader).await;
    writer
        .send(Request::CommitTransaction {
            actor: None,
            name: "t1".to_string(),
            if_match: None,
        })
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut reader).await,
        Event::Committed { warnings } if warnings.is_empty()
    ));

    // Fresh connection, one-shot Get, matching the CLI's actual usage pattern.
    let (mut reader2, mut writer2) = connect(&sock_path).await;
    writer2.send(Request::Get).await.unwrap();
    match next_event(&mut reader2).await {
        Event::Config(c) => {
            assert_eq!(c.bgp_instances.len(), 1);
            assert_eq!(c.bgp_instances[0].name, "r1");
            assert_eq!(c.bgp_instances[0].asn, 65001);
        }
        other => panic!("expected Config event, got {other:?}"),
    }
}

#[tokio::test]
async fn commit_invalid_over_ipc_returns_error_and_transaction_still_resumable() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    next_event(&mut reader).await;
    // Ensure leaves asn at the invalid placeholder 0.
    writer
        .send(Request::ApplyOp {
            actor: None,
            name: "t1".to_string(),
            op: ensure_op("bad"),
        })
        .await
        .unwrap();
    next_event(&mut reader).await;

    writer
        .send(Request::CommitTransaction {
            actor: None,
            name: "t1".to_string(),
            if_match: None,
        })
        .await
        .unwrap();
    assert!(matches!(next_event(&mut reader).await, Event::Error(_)));

    writer
        .send(Request::GetTransaction {
            name: "t1".to_string(),
        })
        .await
        .unwrap();
    match next_event(&mut reader).await {
        Event::Transaction(snap) => assert_eq!(snap.config.bgp_instances.len(), 1),
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn stale_if_match_over_ipc_returns_precondition_error_and_keeps_transaction() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    next_event(&mut reader).await;
    writer
        .send(Request::SetTransactionPath {
            name: "t1".to_string(),
            path: vec!["hostname".to_string()],
            value: Some("\"h1\"".to_string()),
            if_match: Some(vec![0]),
            position: None,
        })
        .await
        .unwrap();
    match next_event(&mut reader).await {
        Event::Transaction(snap) => assert_eq!(snap.generation, 1),
        other => panic!("expected Transaction event, got {other:?}"),
    }

    for req in [
        Request::SetTransactionPath {
            name: "t1".to_string(),
            path: vec!["hostname".to_string()],
            value: Some("\"h2\"".to_string()),
            if_match: Some(vec![0]),
            position: None,
        },
        Request::CommitTransaction {
            actor: None,
            name: "t1".to_string(),
            if_match: Some(vec![0]),
        },
    ] {
        writer.send(req).await.unwrap();
        match next_event(&mut reader).await {
            Event::Error(msg) => assert!(msg.starts_with("precondition failed"), "{msg}"),
            other => panic!("expected Error event, got {other:?}"),
        }
    }
    writer
        .send(Request::GetTransaction {
            name: "t1".to_string(),
        })
        .await
        .unwrap();
    match next_event(&mut reader).await {
        Event::Transaction(snap) => {
            assert_eq!((snap.generation, snap.config.hostname.as_str()), (1, "h1"));
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn edit_transaction_path_over_ipc_replies_with_the_subsection_only() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");
    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();
    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    next_event(&mut reader).await;
    let path = vec!["bgp-instance".to_string(), "r1".to_string()];
    let edit = |value: Option<String>, if_match| Request::EditTransactionPath {
        name: "t1".to_string(),
        path: path.clone(),
        value,
        if_match,
        position: None,
    };
    let body = serde_json::to_value(instance("r1", 65000)).unwrap();

    writer
        .send(edit(Some(body.to_string()), Some(vec![0])))
        .await
        .unwrap();
    match next_event(&mut reader).await {
        Event::TransactionEdit {
            generation: 1,
            dirty: true,
            value: Some(v),
        } => assert_eq!(serde_json::from_str::<serde_json::Value>(&v).unwrap(), body),
        other => panic!("expected TransactionEdit, got {other:?}"),
    }
    // A stale generation: 412-style error, nothing changed.
    writer.send(edit(None, Some(vec![0]))).await.unwrap();
    match next_event(&mut reader).await {
        Event::Error(msg) => assert!(msg.starts_with("precondition failed"), "{msg}"),
        other => panic!("expected Error event, got {other:?}"),
    }
    // A remove carries no subsection.
    writer.send(edit(None, Some(vec![1]))).await.unwrap();
    match next_event(&mut reader).await {
        Event::TransactionEdit {
            generation: 2,
            dirty: true,
            value: None,
        } => {}
        other => panic!("expected TransactionEdit, got {other:?}"),
    }
    // Removing it again: not found.
    writer.send(edit(None, None)).await.unwrap();
    assert!(matches!(next_event(&mut reader).await, Event::Error(_)));
}

#[tokio::test]
async fn positioned_set_over_ipc_reorders_and_shows_in_the_diff() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");
    let group = |n: &str| nos_proto::BgpPeerGroup {
        name: n.to_string(),
        ..Default::default()
    };
    let mut inst = instance("r1", 1);
    inst.peer_groups = vec![group("a"), group("b")];
    let running = Config {
        bgp_instances: vec![inst],
        ..Default::default()
    };
    let store = ConfigStore::new(running, None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Current,
        })
        .await
        .unwrap();
    next_event(&mut reader).await;
    writer
        .send(Request::SetTransactionPath {
            name: "t1".to_string(),
            path: ["bgp-instance", "r1", "peer-group", "b"]
                .map(String::from)
                .to_vec(),
            value: Some(serde_json::to_string(&group("b")).unwrap()),
            if_match: None,
            position: Some(nos_proto::config_path::ListPosition::First),
        })
        .await
        .unwrap();
    match next_event(&mut reader).await {
        Event::Transaction(snap) => {
            let names: Vec<_> = snap.config.bgp_instances[0]
                .peer_groups
                .iter()
                .map(|g| g.name.as_str())
                .collect();
            assert_eq!(names, ["b", "a"]);
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }
    writer
        .send(Request::DiffTransaction {
            name: "t1".to_string(),
        })
        .await
        .unwrap();
    match next_event(&mut reader).await {
        Event::Diff(d) => {
            assert_eq!(d.bgp_instances[0].status, DiffStatus::Modified);
            assert!(d.bgp_instances[0].fields[0].label.ends_with("order"));
        }
        other => panic!("expected Diff event, got {other:?}"),
    }
}

#[tokio::test]
async fn commit_missing_transaction_over_ipc_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::CommitTransaction {
            actor: None,
            name: "missing".to_string(),
            if_match: None,
        })
        .await
        .unwrap();
    assert!(matches!(next_event(&mut reader).await, Event::Error(_)));
}

#[tokio::test]
async fn discard_over_ipc_removes_transaction_so_reopen_is_fresh() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&sock_path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    next_event(&mut reader).await;
    writer
        .send(Request::ApplyOp {
            actor: None,
            name: "t1".to_string(),
            op: ensure_op("r1"),
        })
        .await
        .unwrap();
    next_event(&mut reader).await;

    writer
        .send(Request::DiscardTransaction {
            name: "t1".to_string(),
            if_match: None,
        })
        .await
        .unwrap();
    assert!(matches!(next_event(&mut reader).await, Event::Discarded));

    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    match next_event(&mut reader).await {
        Event::Transaction(snap) => {
            assert!(!snap.resumed);
            assert_eq!(
                snap.config.bgp_instances,
                [] as [nos_config::BgpInstance; 0]
            );
        }
        other => panic!("expected Transaction event, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribed_client_receives_broadcast_after_named_transaction_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Connection A: subscribes (stands in for a future daemon like nos-bgp).
    let (mut reader_a, mut writer_a) = connect(&sock_path).await;
    writer_a.send(Request::Subscribe).await.unwrap();
    let initial = next_event(&mut reader_a).await;
    assert!(matches!(initial, Event::Config(c) if c.bgp_instances.is_empty()));

    // Connection B: opens, edits, and commits a named transaction.
    let (mut reader_b, mut writer_b) = connect(&sock_path).await;
    writer_b
        .send(Request::OpenTransaction {
            actor: None,
            name: "demo".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    next_event(&mut reader_b).await;
    writer_b
        .send(Request::ApplyOp {
            actor: None,
            name: "demo".to_string(),
            op: ensure_op("r1"),
        })
        .await
        .unwrap();
    next_event(&mut reader_b).await;
    writer_b
        .send(Request::ApplyOp {
            actor: None,
            name: "demo".to_string(),
            op: set_asn_op("r1", 65001),
        })
        .await
        .unwrap();
    next_event(&mut reader_b).await;
    writer_b
        .send(Request::CommitTransaction {
            actor: None,
            name: "demo".to_string(),
            if_match: None,
        })
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut reader_b).await,
        Event::Committed { .. }
    ));

    // Connection A must receive the broadcast update.
    let update = tokio::time::timeout(Duration::from_millis(200), reader_a.next())
        .await
        .expect("subscribed connection did not receive a broadcast update")
        .unwrap()
        .unwrap();
    match update {
        Event::Config(c) => {
            assert_eq!(c.bgp_instances.len(), 1);
            assert_eq!(c.bgp_instances[0].name, "r1");
            assert_eq!(c.bgp_instances[0].asn, 65001);
        }
        other => panic!("expected Config event, got {other:?}"),
    }
}

#[tokio::test]
async fn hostname_change_is_broadcast_to_all_subscribers() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(sock_path.clone()), &server_identity())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Two independently-connected subscribers, standing in for two `nos`
    // shells watching the same daemon.
    let (mut reader_a, mut writer_a) = connect(&sock_path).await;
    writer_a.send(Request::Subscribe).await.unwrap();
    let initial_a = next_event(&mut reader_a).await;
    assert!(matches!(initial_a, Event::Config(c) if c.hostname == "nos"));

    let (mut reader_b, mut writer_b) = connect(&sock_path).await;
    writer_b.send(Request::Subscribe).await.unwrap();
    let initial_b = next_event(&mut reader_b).await;
    assert!(matches!(initial_b, Event::Config(c) if c.hostname == "nos"));

    // A third connection commits a hostname change.
    let (mut reader_c, mut writer_c) = connect(&sock_path).await;
    writer_c
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    next_event(&mut reader_c).await;
    writer_c
        .send(Request::ApplyOp {
            actor: None,
            name: "t1".to_string(),
            op: ConfigOp::SetHostname("router1".to_string()),
        })
        .await
        .unwrap();
    next_event(&mut reader_c).await;
    writer_c
        .send(Request::CommitTransaction {
            actor: None,
            name: "t1".to_string(),
            if_match: None,
        })
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut reader_c).await,
        Event::Committed { .. }
    ));

    // Both subscribers — every connected client — must see the new hostname.
    for reader in [&mut reader_a, &mut reader_b] {
        let update = tokio::time::timeout(Duration::from_millis(200), reader.next())
            .await
            .expect("subscribed connection did not receive the hostname broadcast")
            .unwrap()
            .unwrap();
        assert!(matches!(update, Event::Config(c) if c.hostname == "router1"));
    }
}

#[tokio::test]
async fn routing_table_and_static_routing_instance_round_trip_over_ipc() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    next_event(&mut reader).await;

    for op in [
        ensure_op("r1"),
        set_asn_op("r1", 65000),
        ensure_static_routing_instance_op("sri1"),
        ConfigOp::StaticRoute(nos_proto::StaticRouteOp::Set {
            instance: "sri1".to_string(),
            subnet: "10.0.0.0/24".parse().unwrap(),
            gateway: "10.0.0.1".parse().unwrap(),
        }),
        ensure_routing_table_op("rt1"),
        set_routing_table_bgp_instance_op("rt1", "r1"),
        ConfigOp::RoutingTable(nos_proto::RoutingTableOp::SetStaticRoutingInstance {
            name: "rt1".to_string(),
            static_routing_instance: "sri1".to_string(),
        }),
    ] {
        writer
            .send(Request::ApplyOp {
                actor: None,
                name: "t1".to_string(),
                op,
            })
            .await
            .unwrap();
        next_event(&mut reader).await;
    }

    writer
        .send(Request::CommitTransaction {
            actor: None,
            name: "t1".to_string(),
            if_match: None,
        })
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut reader).await,
        Event::Committed { .. }
    ));

    let (mut reader2, mut writer2) = connect(&path).await;
    writer2.send(Request::Get).await.unwrap();
    match next_event(&mut reader2).await {
        Event::Config(c) => {
            assert_eq!(c.routing_tables.len(), 1);
            assert_eq!(c.routing_tables[0].bgp_instance.as_deref(), Some("r1"));
            assert_eq!(
                c.routing_tables[0].static_routing_instance.as_deref(),
                Some("sri1")
            );
            assert_eq!(c.static_routing_instances.len(), 1);
            assert_eq!(c.static_routing_instances[0].routes.len(), 1);
        }
        other => panic!("expected Config event, got {other:?}"),
    }
}

#[tokio::test]
async fn commit_fails_when_static_routing_instance_referenced_table_is_missing_over_ipc() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "t1".to_string(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    next_event(&mut reader).await;

    writer
        .send(Request::ApplyOp {
            actor: None,
            name: "t1".to_string(),
            op: ensure_routing_table_op("rt1"),
        })
        .await
        .unwrap();
    next_event(&mut reader).await;
    writer
        .send(Request::ApplyOp {
            actor: None,
            name: "t1".to_string(),
            op: set_routing_table_bgp_instance_op("rt1", "does-not-exist"),
        })
        .await
        .unwrap();
    next_event(&mut reader).await;

    writer
        .send(Request::CommitTransaction {
            actor: None,
            name: "t1".to_string(),
            if_match: None,
        })
        .await
        .unwrap();
    assert!(matches!(next_event(&mut reader).await, Event::Error(_)));
}

#[tokio::test]
async fn describe_returns_the_requested_topics_doc() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");

    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(Request::Describe {
            topic: Topic::Hostname,
        })
        .await
        .unwrap();

    let event = next_event(&mut reader).await;
    match event {
        Event::Description(doc) => {
            assert_eq!(doc.topic, Topic::Hostname);
            assert_ne!(doc.summary, "");
            assert_ne!(doc.detail, "");
        }
        other => panic!("expected Description event, got {other:?}"),
    }
}

/// A daemon may read the config but not edit it; the refusal is reported and
/// the connection closed, while the daemon's *read* on another connection is
/// unaffected.
#[tokio::test]
async fn a_daemon_role_can_read_but_not_edit() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    writer.send(Request::Get).await.unwrap();
    assert!(matches!(next_event(&mut reader).await, Event::Config(_)));

    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: "sneaky".into(),
            base: TransactionBase::Blank,
        })
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut reader).await,
        Event::Error(m) if m == "permission denied"
    ));
    assert!(
        reader.next().await.is_none_or(|r| r.is_err()),
        "connection should close"
    );
    assert!(
        store.get_transaction("sneaky").await.is_err(),
        "the edit must not have happened"
    );
}

/// `Restd` edits on behalf of a user, so it must be let through.
#[tokio::test]
async fn restd_and_users_can_edit() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    for (role, name) in [("restd", "rt1"), ("user", "alice")] {
        let (mut reader, mut writer) = connect_as(&path, role, name).await;
        writer
            .send(Request::OpenTransaction {
                actor: None,
                name: format!("t-{role}"),
                base: TransactionBase::Blank,
            })
            .await
            .unwrap();
        assert!(
            matches!(next_event(&mut reader).await, Event::Transaction(_)),
            "{role} should be allowed to edit"
        );
    }
}

/// A certificate from some other CA never gets as far as a request.
#[tokio::test]
async fn a_peer_from_another_ca_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let outsider = TestPki::new().identity("user", "mallory");
    let outcome = async {
        let stream = outsider.connect(&path, &configd()).await?;
        let (r, w) = tokio::io::split(stream);
        let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
        let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
        writer.send(Request::Get).await?;
        reader.next().await.transpose()
    }
    .await;
    assert!(
        !matches!(outcome, Ok(Some(_))),
        "an outsider must not get a config back"
    );
}

/// Every role against a read, an edit and a password-hash upgrade (#364):
/// a refused request gets `permission denied` and the connection is closed,
/// a permitted one gets any other reply. Bounded waits, so a broken gate
/// fails fast instead of hanging.
#[tokio::test]
async fn every_role_is_gated_live_for_reads_edits_and_hash_upgrades() {
    use nos_proto::Role;

    async fn next(reader: &mut Reader) -> Option<Event> {
        tokio::time::timeout(Duration::from_secs(5), reader.next())
            .await
            .expect("no reply and the connection is still open")
            .and_then(Result::ok)
    }
    fn denied(e: Option<&Event>) -> bool {
        matches!(e, Some(Event::Error(m)) if m == "permission denied")
    }

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let store = ConfigStore::new(Config::default(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    for role in Role::ALL {
        let people = matches!(role, Role::User | Role::Restd);

        let (mut reader, mut writer) = connect_as(&path, role.as_str(), "x").await;
        writer.send(Request::Get).await.unwrap();
        assert!(
            matches!(next(&mut reader).await, Some(Event::Config(_))),
            "{role:?} must read"
        );

        writer
            .send(Request::OpenTransaction {
                actor: None,
                name: format!("tx-{}", role.as_str()),
                base: TransactionBase::Blank,
            })
            .await
            .unwrap();
        let reply = next(&mut reader).await;
        assert_eq!(
            denied(reply.as_ref()),
            !people,
            "{role:?} editing: {reply:?}"
        );
        assert_eq!(
            store
                .get_transaction(&format!("tx-{}", role.as_str()))
                .await
                .is_ok(),
            people,
            "{role:?}: the transaction must exist only if the edit was allowed"
        );

        let (mut reader, mut writer) = connect_as(&path, role.as_str(), "x").await;
        writer
            .send(Request::UpgradePasswordHash {
                user: "nobody".into(),
                old: "a".into(),
                new: "b".into(),
            })
            .await
            .unwrap();
        let reply = next(&mut reader).await;
        assert_eq!(
            denied(reply.as_ref()),
            role != Role::Watchdog,
            "{role:?} hash upgrade: {reply:?}"
        );
    }
}

/// A running config with a user, a BGP-referenced key and an unreferenced one.
fn config_with_secrets() -> Config {
    let key = |l: &str| nos_proto::AdminKey {
        label: l.into(),
        secret: format!("SECRET-{l}"),
    };
    let mut c = Config::default();
    c.admin.keys = vec![key("kbgp"), key("kspare")];
    c.users = vec![nos_proto::User {
        name: "u".into(),
        password: "SECRET-hash".into(),
    }];
    let mut i = instance("default", 65000);
    i.peer_groups = vec![nos_proto::BgpPeerGroup {
        auth: Some(nos_proto::BgpAuth::Md5 {
            key_ref: "kbgp".into(),
        }),
        ..Default::default()
    }];
    c.bgp_instances = vec![i];
    c
}

#[tokio::test]
async fn get_and_subscribe_hand_each_role_only_its_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let store = ConfigStore::new(config_with_secrets(), None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    // (role, sees the user hash, sees the BGP key, sees the spare key)
    let cases = [
        ("lldpd", false, false, false),
        ("lacpd", false, false, false),
        ("ribd", false, false, false),
        ("watchdog", true, false, false),
        ("bgpd", false, true, false),
        ("user", true, true, true),
        ("restd", true, true, true),
    ];
    for (role, hash, bgp, spare) in cases {
        for req in [Request::Get, Request::Subscribe] {
            let req = format!("{req:?}");
            let (mut reader, mut writer) = connect_as(&path, role, "x").await;
            writer
                .send(if req == "Get" {
                    Request::Get
                } else {
                    Request::Subscribe
                })
                .await
                .unwrap();
            let Event::Config(c) = next_event(&mut reader).await else {
                panic!("{role}: not a config")
            };
            let labels = format!("{:?}", c.admin.keys);
            assert_eq!(!c.users.is_empty(), hash, "{role} {req:?} users");
            assert_eq!(labels.contains("kbgp"), bgp, "{role} {req:?} bgp key");
            assert_eq!(labels.contains("kspare"), spare, "{role} {req:?} spare key");
            // Non-secret content is always there.
            assert_eq!(c.bgp_instances.len(), 1, "{role}");
        }
    }
}

#[tokio::test]
async fn diffs_are_projected_per_role_too() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let mut cfg = config_with_secrets();
    cfg.bgp_instances.clear(); // a peer-group without a name would fail the commit
    let store = ConfigStore::new(cfg, None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();
    let scopes = vec![DiffScope::Hostname, DiffScope::Admin, DiffScope::Users];

    let mut subs = Vec::new();
    for role in ["ribd", "user"] {
        let (mut reader, mut writer) = connect_as(&path, role, "x").await;
        writer
            .send(Request::SubscribeDiff {
                scopes: scopes.clone(),
            })
            .await
            .unwrap();
        let initial = format!("{:?}", next_event(&mut reader).await);
        assert_eq!(initial.contains("kspare"), role == "user", "{role} initial");
        subs.push((role, reader, writer));
    }

    store
        .open_transaction("t", TransactionBase::Current)
        .await
        .unwrap();
    for op in [
        ConfigOp::SetHostname("renamed".into()),
        ConfigOp::Admin(nos_proto::AdminOp::SetKey {
            label: "knew".into(),
            secret: "SECRET-new".into(),
        }),
    ] {
        store.apply_op("t", op).await.unwrap();
    }
    store.commit_transaction("t", None).await.unwrap();

    for (role, mut reader, _w) in subs {
        let after = format!("{:?}", next_event(&mut reader).await);
        assert!(after.contains("renamed"), "{role}: {after}");
        assert_eq!(after.contains("knew"), role == "user", "{role}: {after}");
    }
}

#[test]
fn a_listen_address_displays_with_its_scheme() {
    let addr = ListenAddr::Unix("/run/nos/config.sock".into());
    assert_eq!(addr.to_string(), "unix:/run/nos/config.sock");
}

/// #755: the auth probe answers present/absent, only for `Restd`; anyone
/// else is refused and disconnected.
#[tokio::test]
async fn user_exists_round_trips_for_restd_only() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let cfg = Config {
        users: vec![nos_proto::User {
            name: "alice".into(),
            password: "pw".into(),
        }],
        ..Config::default()
    };
    let store = ConfigStore::new(cfg, None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect_as(&path, "restd", "rt1").await;
    for (name, want) in [("alice", true), ("bob", false)] {
        writer
            .send(Request::UserExists { name: name.into() })
            .await
            .unwrap();
        assert!(matches!(next_event(&mut reader).await, Event::UserExists(b) if b == want));
    }

    let (mut reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    writer
        .send(Request::UserExists {
            name: "alice".into(),
        })
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut reader).await,
        Event::Error(m) if m == "permission denied"
    ));
}

/// #759: instance-name lists and the per-table `rest_api` probe, Restd only.
#[tokio::test]
async fn instance_lists_and_rest_api_round_trip_for_restd_only() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let api = nos_proto::RestApi {
        address: "10.0.0.1".parse().unwrap(),
        port: 8443,
    };
    let cfg = Config {
        bgp_instances: vec![nos_proto::BgpInstance {
            name: "b1".into(),
            ..Default::default()
        }],
        routing_tables: vec![
            nos_proto::RoutingTable {
                name: "rt1".into(),
                rest_api: Some(api.clone()),
                ..Default::default()
            },
            nos_proto::RoutingTable {
                name: "rt2".into(),
                ..Default::default()
            },
        ],
        ..Config::default()
    };
    let store = ConfigStore::new(cfg, None);
    let _srv = store
        .start_ipc_server(&ListenAddr::Unix(path.clone()), &server_identity())
        .unwrap();

    let (mut reader, mut writer) = connect_as(&path, "restd", "rt1").await;
    writer.send(Request::ListBgpInstances).await.unwrap();
    assert!(matches!(next_event(&mut reader).await, Event::InstanceNames(n) if n == ["b1"]));
    writer.send(Request::ListOspfInstances).await.unwrap();
    assert!(matches!(next_event(&mut reader).await, Event::InstanceNames(n) if n.is_empty()));
    writer.send(Request::ListOspfv3Instances).await.unwrap();
    assert!(matches!(next_event(&mut reader).await, Event::InstanceNames(n) if n.is_empty()));
    for (t, want) in [("rt1", Some(api)), ("rt2", None), ("nope", None)] {
        writer
            .send(Request::GetRestApi { table: t.into() })
            .await
            .unwrap();
        assert!(matches!(next_event(&mut reader).await, Event::RestApi(r) if r == want));
    }

    let (mut reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    writer.send(Request::ListBgpInstances).await.unwrap();
    assert!(matches!(
        next_event(&mut reader).await,
        Event::Error(m) if m == "permission denied"
    ));
}
