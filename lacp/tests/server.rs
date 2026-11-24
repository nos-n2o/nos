use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_lacp::aggregate::{AggregateManager, PortNumbers};
use nos_lacp::reconcile::SharedAggregates;
use nos_lacp::server;
use nos_pki::testing::shared;
use nos_proto::{IpcCodec, LacpEvent, LacpRate, LacpRequest};
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};

async fn query(path: &std::path::Path) -> Vec<nos_proto::PortAggregateLacpSummary> {
    let stream = shared()
        .identity("user", "tester")
        .connect(path, &nos_pki::PeerId::new("lacpd", ""))
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<LacpEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<LacpRequest>::default());
    writer.send(LacpRequest::GetSummary).await.unwrap();
    let LacpEvent::Summary(summaries) = reader.next().await.unwrap().unwrap();
    summaries
}

#[tokio::test]
async fn get_summary_lists_every_aggregate_sorted_with_its_rate() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("lacp.sock");
    let (push_tx, _push_rx) = mpsc::channel(4);

    let aggregates = SharedAggregates::default();
    for (name, key, rate) in [("bond-b", 2, LacpRate::Fast), ("bond-a", 1, LacpRate::Slow)] {
        let manager = AggregateManager::new(
            name,
            key,
            push_tx.clone(),
            PortNumbers::default(),
            tokio::sync::watch::channel(nos_lacp::link_client::LinkTable::default()).1,
        );
        // No members: exercises the summary/rate plumbing without needing a
        // raw socket (which needs CAP_NET_RAW).
        manager.reconcile(Vec::new(), rate, None, 32768, 1);
        aggregates
            .lock()
            .unwrap()
            .insert(name.to_string(), Arc::clone(&manager));
    }
    let _server = server::start(&path, aggregates, &shared().identity("lacpd", "")).unwrap();

    let summaries = query(&path).await;
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].aggregate, "bond-a");
    assert_eq!(summaries[0].rate, LacpRate::Slow);
    assert_eq!(summaries[0].actor_key, 1);
    assert_eq!(summaries[1].aggregate, "bond-b");
    assert_eq!(summaries[1].rate, LacpRate::Fast);
    assert_eq!(summaries[0].ports, [] as [nos_proto::LacpPortStatus; 0]);
}

#[tokio::test]
async fn get_summary_with_no_aggregates_is_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("lacp.sock");
    let _server = server::start(
        &path,
        SharedAggregates::default(),
        &shared().identity("lacpd", ""),
    )
    .unwrap();
    assert_eq!(
        query(&path).await,
        [] as [nos_proto::PortAggregateLacpSummary; 0]
    );
}
