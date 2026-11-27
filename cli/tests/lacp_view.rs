//! Goldens of `show lacp` (tables) and `show lacp detail` (#1465).
//! Goldens are in `tests/goldens/`; edit them by hand from the failing diff.

use nos_cli::format::{render_lacp_counters, render_lacp_detail, render_lacp_tables};
use nos_proto::{
    LacpAgreement, LacpMode, LacpMuxState, LacpPortAlgorithm, LacpPortStatus, LacpRate,
    LacpReceiveState, LacpVersion, PortAggregateLacpSummary,
};

fn check(name: &str, got: &str) {
    let path = format!("{}/tests/goldens/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    let want = std::fs::read_to_string(&path).unwrap();
    assert_eq!(want, format!("{got}\n"), "golden {name}");
}

const BAD: &str = "x\nFORGED\u{1b}[2J";

fn port(name: &str, receive: LacpReceiveState, mux: LacpMuxState) -> LacpPortStatus {
    LacpPortStatus {
        interface: name.into(),
        actor_port_number: 4,
        receive_state: receive,
        mux_state: mux,
        partner_system_id: Some([2, 0, 0, 0, 0, 1]),
        partner_key: Some(3),
        partner_port_number: Some(9),
        actor_port_priority: 50,
        mode: LacpMode::Passive,
        partner_system_priority: Some(200),
        partner_port_priority: Some(60),
        selected: true,
        synchronized: true,
        actor_churn: false,
        partner_churn: false,
        individual: false,
        unsupported_version_pdus: 0,
        partner_version: None,
        partner_port_algorithm: None,
        lacpdus_rx: 0,
        lacpdus_tx: 0,
        illegal_pdus: 0,
        marker_pdus_rx: 0,
        marker_responses_tx: 0,
        marker_responses_rx: 0,
        fallback: nos_proto::LacpFallback::Disabled,
    }
}

fn agg(name: &str, ports: Vec<LacpPortStatus>) -> PortAggregateLacpSummary {
    PortAggregateLacpSummary {
        aggregate: name.into(),
        actor_system_id: [2, 0, 0, 0, 0, 0xab],
        actor_key: 7,
        actor_system_priority: 100,
        rate: LacpRate::Fast,
        min_links: 2,
        min_links_met: false,
        ports,
        version: LacpVersion::V1,
        port_algorithm: LacpPortAlgorithm::Unspecified,
        agreement: LacpAgreement::NotApplicable,
        conversations_per_link: Vec::new(),
    }
}

fn populated() -> Vec<PortAggregateLacpSummary> {
    let mut defaulted = port("eth2", LacpReceiveState::Defaulted, LacpMuxState::Detached);
    defaulted.selected = false;
    defaulted.synchronized = false;
    defaulted.actor_churn = true;
    defaulted.partner_churn = true;
    defaulted.individual = true;
    defaulted.mode = LacpMode::Active;
    defaulted.unsupported_version_pdus = 3;
    defaulted.lacpdus_rx = u64::MAX;
    defaulted.lacpdus_tx = 1234;
    defaulted.illegal_pdus = 2;
    defaulted.marker_pdus_rx = 7;
    defaulted.marker_responses_tx = 5;
    defaulted.marker_responses_rx = 1;
    let mut v2 = agg(
        "bond22",
        vec![port(
            "eth3",
            LacpReceiveState::Current,
            LacpMuxState::Distributing,
        )],
    );
    v2.version = LacpVersion::V2;
    v2.port_algorithm = LacpPortAlgorithm::CVlan;
    v2.agreement = LacpAgreement::Agreed;
    v2.min_links_met = true;
    v2.conversations_per_link = vec![("eth3".into(), 4094)];
    v2.ports[0].partner_version = Some(2);
    v2.ports[0].partner_port_algorithm = Some(LacpPortAlgorithm::CVlan);
    vec![
        agg(
            "bond1",
            vec![
                port(
                    "eth1",
                    LacpReceiveState::Current,
                    LacpMuxState::Distributing,
                ),
                defaulted,
            ],
        ),
        v2,
    ]
}

fn forged() -> Vec<PortAggregateLacpSummary> {
    vec![agg(
        BAD,
        vec![port(BAD, LacpReceiveState::Current, LacpMuxState::Waiting)],
    )]
}

#[test]
fn lacp_goldens() {
    check("lacp_empty", &render_lacp_tables(&[]));
    check("lacp_populated", &render_lacp_tables(&populated()));
    check("lacp_forged", &render_lacp_tables(&forged()));
    check("lacp_detail_populated", &render_lacp_detail(&populated()));
    check("lacp_detail_forged", &render_lacp_detail(&forged()));
    check("lacp_counters_empty", &render_lacp_counters(&[]));
    check(
        "lacp_counters_populated",
        &render_lacp_counters(&populated()),
    );
    check("lacp_counters_forged", &render_lacp_counters(&forged()));
}
