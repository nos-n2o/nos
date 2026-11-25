use futures::{SinkExt, StreamExt};
use nos_cli::fdb_client::get_table;
use nos_pki::testing::shared;
use nos_proto::{FdbEvent, FdbRequest, FdbTable, IpcCodec, MacEntry, MacSource};
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample() -> FdbTable {
    FdbTable {
        domain: "bd1".to_string(),
        vni: 10100,
        bridge: Some("br1".to_string()),
        vxlan: Some("vx10100".to_string()),
        macs: vec![MacEntry {
            mac: "02:00:00:00:00:01".to_string(),
            source: MacSource::Remote,
            vtep: Some("192.0.2.9".parse().unwrap()),
            vteps: vec!["192.0.2.9".parse().unwrap()],
            esi: None,
            interface: None,
            age_secs: None,
        }],
        neighbours: Vec::new(),
        flood: vec!["192.0.2.9".parse().unwrap()],
        segments: Vec::new(),
        neigh_suppress: false,
    }
}

#[tokio::test]
async fn get_table_returns_the_domains_fdb() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("fdb.sock");
    let listener = shared().identity("fdbd", "bd1").listen(&path).unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
        let (r, w) = tokio::io::split(stream);
        let mut reader = FramedRead::new(r, IpcCodec::<FdbRequest>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<FdbEvent>::default());
        assert!(matches!(
            reader.next().await.unwrap().unwrap(),
            FdbRequest::GetMacs
        ));
        writer.send(FdbEvent::Table(sample())).await.unwrap();
    });

    assert_eq!(get_table(&path).await.unwrap(), sample());
    server.await.unwrap();
}

#[tokio::test]
async fn get_table_reports_a_connect_error_when_nothing_listens() {
    let tmp = tempfile::tempdir().unwrap();
    let err = get_table(&tmp.path().join("missing.sock"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("could not connect to nos-fdbd"));
}
