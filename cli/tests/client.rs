use std::net::Ipv4Addr;

use futures::{SinkExt, StreamExt};
use nos_cli::client::{
    apply_op, commit_transaction, describe, discard_transaction, fetch_running_config,
    get_transaction, open_transaction, save_running_config, subscribe, ClientError,
};
use nos_pki::testing::shared;
use nos_proto::{
    BgpInstance, BgpInstanceOp, CommandDoc, Config, ConfigOp, Event, IpcCodec, Request, Topic,
    TransactionBase, TransactionSnapshot,
};
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_config() -> Config {
    Config {
        bgp_instances: vec![BgpInstance {
            name: "default".to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
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
        }],
        ..Default::default()
    }
}

fn sample_snapshot() -> TransactionSnapshot {
    TransactionSnapshot {
        name: "demo".to_string(),
        config: sample_config(),
        dirty: true,
        resumed: false,
        generation: 0,
    }
}

/// Accepts a single connection, reads one `Request`, asserts it matches
/// `expected`, and replies with the given `Event`.
async fn serve_once(listener: nos_pki::Listener, expected: Request, reply: Event) {
    let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<Request>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Event>::default());

    let got = reader.next().await.unwrap().unwrap();
    assert_eq!(format!("{got:?}"), format!("{expected:?}"));
    writer.send(reply).await.unwrap();
}

#[tokio::test]
async fn returns_config_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::Get,
        Event::Config(sample_config()),
    ));

    let cfg = fetch_running_config(&path).await.unwrap();
    assert_eq!(cfg, sample_config());

    server.await.unwrap();
}

#[tokio::test]
async fn returns_daemon_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::Get,
        Event::Error("boom".to_string()),
    ));

    let err = fetch_running_config(&path).await.unwrap_err();
    assert!(matches!(err, ClientError::Daemon(msg) if msg == "boom"));

    server.await.unwrap();
}

#[tokio::test]
async fn returns_connect_error_for_missing_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("does-not-exist.sock");

    let err = fetch_running_config(&path).await.unwrap_err();
    assert!(matches!(err, ClientError::Connect { .. }));
}

#[tokio::test]
async fn subscribe_returns_initial_snapshot_then_committed_update() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let updated = Config {
        hostname: "router1".to_string(),
        ..sample_config()
    };
    let server = tokio::spawn({
        let updated = updated.clone();
        async move {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            let (r, w) = tokio::io::split(stream);
            let mut reader = FramedRead::new(r, IpcCodec::<Request>::default());
            let mut writer = FramedWrite::new(w, IpcCodec::<Event>::default());

            let got = reader.next().await.unwrap().unwrap();
            assert!(matches!(got, Request::Subscribe));

            writer.send(Event::Config(sample_config())).await.unwrap();
            writer.send(Event::Config(updated)).await.unwrap();
        }
    });

    let mut reader = subscribe(&path).await.unwrap();
    let first = reader.next().await.unwrap().unwrap();
    assert!(matches!(first, Event::Config(c) if c == sample_config()));
    let second = reader.next().await.unwrap().unwrap();
    assert!(matches!(second, Event::Config(c) if c.hostname == "router1"));

    server.await.unwrap();
}

#[tokio::test]
async fn save_returns_ok_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(listener, Request::Save, Event::Saved));

    save_running_config(&path).await.unwrap();

    server.await.unwrap();
}

#[tokio::test]
async fn save_returns_daemon_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::Save,
        Event::Error("disk full".to_string()),
    ));

    let err = save_running_config(&path).await.unwrap_err();
    assert!(matches!(err, ClientError::Daemon(msg) if msg == "disk full"));

    server.await.unwrap();
}

#[tokio::test]
async fn save_returns_connect_error_for_missing_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("does-not-exist.sock");

    let err = save_running_config(&path).await.unwrap_err();
    assert!(matches!(err, ClientError::Connect { .. }));
}

#[tokio::test]
async fn open_transaction_returns_snapshot_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::OpenTransaction {
            actor: None,
            name: "demo".to_string(),
            base: TransactionBase::Blank,
        },
        Event::Transaction(sample_snapshot()),
    ));

    let snap = open_transaction(&path, "demo", TransactionBase::Blank)
        .await
        .unwrap();
    assert_eq!(snap.name, "demo");
    assert_eq!(snap.config, sample_config());

    server.await.unwrap();
}

#[tokio::test]
async fn open_transaction_returns_daemon_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::OpenTransaction {
            actor: None,
            name: "demo".to_string(),
            base: TransactionBase::Current,
        },
        Event::Error("boom".to_string()),
    ));

    let err = open_transaction(&path, "demo", TransactionBase::Current)
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::Daemon(msg) if msg == "boom"));

    server.await.unwrap();
}

#[tokio::test]
async fn apply_op_returns_snapshot_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let op = ConfigOp::BgpInstance(BgpInstanceOp::Ensure {
        name: "r1".to_string(),
    });
    let server = tokio::spawn(serve_once(
        listener,
        Request::ApplyOp {
            actor: None,
            name: "demo".to_string(),
            op: op.clone(),
        },
        Event::Transaction(sample_snapshot()),
    ));

    let snap = apply_op(&path, "demo", op).await.unwrap();
    assert_eq!(snap.name, "demo");

    server.await.unwrap();
}

#[tokio::test]
async fn apply_op_returns_daemon_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let op = ConfigOp::BgpInstance(BgpInstanceOp::Delete {
        name: "r1".to_string(),
    });
    let server = tokio::spawn(serve_once(
        listener,
        Request::ApplyOp {
            actor: None,
            name: "demo".to_string(),
            op: op.clone(),
        },
        Event::Error("bgp instance 'r1' not found".to_string()),
    ));

    let err = apply_op(&path, "demo", op).await.unwrap_err();
    assert!(matches!(err, ClientError::Daemon(_)));

    server.await.unwrap();
}

#[tokio::test]
async fn get_transaction_returns_snapshot_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::GetTransaction {
            name: "demo".to_string(),
        },
        Event::Transaction(sample_snapshot()),
    ));

    let snap = get_transaction(&path, "demo").await.unwrap();
    assert_eq!(snap.name, "demo");

    server.await.unwrap();
}

#[tokio::test]
async fn get_transaction_returns_daemon_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::GetTransaction {
            name: "missing".to_string(),
        },
        Event::Error("no transaction named 'missing'".to_string()),
    ));

    let err = get_transaction(&path, "missing").await.unwrap_err();
    assert!(matches!(err, ClientError::Daemon(_)));

    server.await.unwrap();
}

#[tokio::test]
async fn commit_transaction_returns_ok_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::CommitTransaction {
            actor: None,
            name: "demo".to_string(),
            if_match: None,
        },
        Event::Committed { warnings: vec![] },
    ));

    commit_transaction(&path, "demo").await.unwrap();

    server.await.unwrap();
}

#[tokio::test]
async fn commit_transaction_returns_daemon_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::CommitTransaction {
            actor: None,
            name: "demo".to_string(),
            if_match: None,
        },
        Event::Error("validation failed".to_string()),
    ));

    let err = commit_transaction(&path, "demo").await.unwrap_err();
    assert!(matches!(err, ClientError::Daemon(_)));

    server.await.unwrap();
}

#[tokio::test]
async fn discard_transaction_returns_ok_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::DiscardTransaction {
            name: "demo".to_string(),
            if_match: None,
        },
        Event::Discarded,
    ));

    discard_transaction(&path, "demo").await.unwrap();

    server.await.unwrap();
}

#[tokio::test]
async fn discard_transaction_returns_daemon_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::DiscardTransaction {
            name: "missing".to_string(),
            if_match: None,
        },
        Event::Error("no transaction named 'missing'".to_string()),
    ));

    let err = discard_transaction(&path, "missing").await.unwrap_err();
    assert!(matches!(err, ClientError::Daemon(_)));

    server.await.unwrap();
}

#[tokio::test]
async fn describe_returns_doc_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let doc = CommandDoc {
        topic: Topic::Hostname,
        summary: "Set the configuration's hostname.".to_string(),
        detail: "Sets the top-level hostname field.".to_string(),
    };
    let server = tokio::spawn(serve_once(
        listener,
        Request::Describe {
            topic: Topic::Hostname,
        },
        Event::Description(doc.clone()),
    ));

    let got = describe(&path, Topic::Hostname).await.unwrap();
    assert_eq!(got.topic, Topic::Hostname);
    assert_eq!(got.summary, doc.summary);

    server.await.unwrap();
}

#[tokio::test]
async fn describe_returns_daemon_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.sock");
    let listener = shared().identity("configd", "").listen(&path).unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        Request::Describe { topic: Topic::Save },
        Event::Error("boom".to_string()),
    ));

    let err = describe(&path, Topic::Save).await.unwrap_err();
    assert!(matches!(err, ClientError::Daemon(msg) if msg == "boom"));

    server.await.unwrap();
}
