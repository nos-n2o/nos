use futures::{SinkExt, StreamExt};
use nos_cli::lacp_client::get_summary;
use nos_pki::testing::shared;
use nos_proto::{
    IpcCodec, LacpEvent, LacpMuxState, LacpPortStatus, LacpRate, LacpReceiveState, LacpRequest,
    PortAggregateLacpSummary,
};
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample() -> PortAggregateLacpSummary {
    PortAggregateLacpSummary {
        aggregate: "bond1".to_string(),
        actor_system_id: [2, 0, 0, 0, 0, 1],
        actor_key: 1,
        actor_system_priority: 32768,
        rate: LacpRate::Fast,
        min_links: 1,
        min_links_met: true,
        ports: vec![LacpPortStatus {
            interface: "eth1".to_string(),
            actor_port_number: 4,
            receive_state: LacpReceiveState::Current,
            mux_state: LacpMuxState::Distributing,
            partner_system_id: Some([2, 0, 0, 0, 0, 2]),
            partner_key: Some(1),
            partner_port_number: Some(4),
            actor_port_priority: 32768,
            mode: nos_proto::LacpMode::Active,
            partner_system_priority: Some(32768),
            partner_port_priority: Some(32768),
            selected: true,
            synchronized: true,
            actor_churn: false,
            partner_churn: false,
            individual: false,
            unsupported_version_pdus: 0,
            partner_version: None,
            partner_port_algorithm: None,
        }],
        version: nos_proto::LacpVersion::V1,
        port_algorithm: nos_proto::LacpPortAlgorithm::Unspecified,
        agreement: nos_proto::LacpAgreement::NotApplicable,
        conversations_per_link: Vec::new(),
    }
}

#[tokio::test]
async fn get_summary_returns_summaries_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("lacp.sock");
    let listener = shared().identity("lacpd", "").listen(&path).unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
        let (r, w) = tokio::io::split(stream);
        let mut reader = FramedRead::new(r, IpcCodec::<LacpRequest>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<LacpEvent>::default());
        let got = reader.next().await.unwrap().unwrap();
        assert!(matches!(got, LacpRequest::GetSummary));
        writer
            .send(LacpEvent::Summary(vec![sample()]))
            .await
            .unwrap();
    });

    assert_eq!(get_summary(&path).await.unwrap(), vec![sample()]);
    server.await.unwrap();
}

#[tokio::test]
async fn get_summary_reports_a_connect_error_when_nothing_listens() {
    let tmp = tempfile::tempdir().unwrap();
    let err = get_summary(&tmp.path().join("missing.sock"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("could not connect to nos-lacpd"));
}
