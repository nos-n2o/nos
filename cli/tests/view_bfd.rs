//! Goldens of `show bfd sessions` through the generic view engine (#1422).
//! Goldens are in `tests/goldens/`; edit them by hand from the failing diff.

use nos_cli::view::{render, render_detail, render_detail_list, to_value};
use nos_proto::schema::BfdAuthMethod;
use nos_proto::view::view_of;
use nos_proto::{BfdDiag, BfdSessionKind, BfdSessionView, BfdState, SessionKey};

fn base(peer: &str, state: BfdState, diag: BfdDiag, interface: Option<&str>) -> BfdSessionView {
    BfdSessionView {
        key: SessionKey {
            aggregate: None,
            table: "rt1".into(),
            peer: peer.parse().unwrap(),
            local: None,
            interface: interface.map(String::from),
            multihop: false,
        },
        state,
        diag,
        local_discriminator: 1,
        remote_discriminator: 2,
        tx_interval_us: 100_000,
        detection_time_us: 300_000,
        auth_method: None,
        auth_key_id: None,
        auth_failures: 0,
        echo_active: false,
        echo_interval_us: 0,
        echo_only: false,
        tx_pdu_bytes: 0,
        kind: BfdSessionKind::Classical,
        uptime_secs: None,
        last_change_secs: 0,
        down_count: 0,
        tx_packets: 0,
        rx_packets: 0,
        remote_min_rx_us: None,
        remote_desired_min_tx_us: None,
        remote_detect_mult: None,
        clients: vec![],
        demand: false,
        remote_demand: false,
    }
}

fn up() -> BfdSessionView {
    base("192.0.2.1", BfdState::Up, BfdDiag::NoDiagnostic, None)
}

fn check(name: &str, got: &str) {
    let path = format!("{}/tests/goldens/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    let want = std::fs::read_to_string(&path).unwrap();
    assert_eq!(want, format!("{got}\n"), "golden {name}");
}

fn show(v: &[BfdSessionView]) -> String {
    render(&v.to_vec(), "no bfd sessions")
}

#[test]
fn empty() {
    check("bfd_sessions_empty", &show(&[]));
}

#[test]
fn populated_classical() {
    // Old: `rt1: peer 192.0.2.2 on eth1, down, diag control-detection-time-expired,
    // tx 100ms, detect 300ms, discriminators 1/2` (state and diag now raw serde names).
    let down = base(
        "192.0.2.2",
        BfdState::Down,
        BfdDiag::ControlDetectionTimeExpired,
        Some("eth1"),
    );
    let mut multi = up();
    multi.key.multihop = true;
    multi.key.local = Some("192.0.2.9".parse().unwrap());
    check("bfd_sessions_populated", &show(&[down, up(), multi]));
}

#[test]
fn micro_bfd() {
    let mut m = base(
        "10.0.0.2",
        BfdState::Up,
        BfdDiag::NoDiagnostic,
        Some("eth1"),
    );
    m.key.aggregate = Some("bond0".into());
    m.key.table = String::new();
    m.key.local = Some("10.0.0.1".parse().unwrap());
    check("bfd_sessions_micro", &show(&[m]));
}

#[test]
fn auth_echo_pdu_sbfd() {
    let mut a = up();
    a.auth_method = Some(BfdAuthMethod::KeyedSha1);
    a.auth_key_id = Some(2);
    a.auth_failures = 5;
    let mut e = up();
    e.echo_active = true;
    e.echo_interval_us = 50_000;
    e.echo_only = true;
    let mut p = up();
    p.tx_pdu_bytes = 1400;
    p.kind = BfdSessionKind::SbfdInitiator;
    let mut u = up();
    u.kind = BfdSessionKind::Unsolicited;
    check("bfd_sessions_extras", &show(&[a, e, p, u]));
}

#[test]
fn forged_interface_stays_one_row() {
    let mut s = up();
    s.key.interface = Some("eth0\nFORGED  up".into());
    let mut t = up();
    t.key.interface = Some("\u{1b}[2J".into());
    let out = show(&[s, t.clone()]);
    assert_eq!(out.lines().count(), 4, "{out}");
    assert!(!out.contains('\u{1b}'));
    let node = view_of::<BfdSessionView>().unwrap();
    let d = render_detail(node, &to_value(&t));
    assert!(!d.contains('\u{1b}'));
}

#[test]
fn detail_shows_every_field() {
    let mut s = up();
    s.key.local = Some("192.0.2.9".parse().unwrap());
    s.key.interface = Some("eth7".into());
    s.key.aggregate = Some("ae9".into());
    s.auth_method = Some(BfdAuthMethod::MeticulousMd5);
    s.auth_key_id = Some(9);
    s.auth_failures = 4;
    s.echo_active = true;
    s.echo_interval_us = 50_000;
    s.tx_pdu_bytes = 1400;
    s.kind = BfdSessionKind::SbfdInitiator;
    let node = view_of::<BfdSessionView>().unwrap();
    let d = render_detail(node, &to_value(&s));
    for needle in [
        "Up",
        "NoDiagnostic",
        "rt1",
        "192.0.2.1",
        "192.0.2.9",
        "eth7",
        "ae9",
        "MeticulousMd5",
        "SbfdInitiator",
        "100ms",
        "300ms",
        "50ms",
        "1.4 KB",
    ] {
        assert!(d.contains(needle), "{needle} missing in\n{d}");
    }
    for f in node.details() {
        assert!(d.contains(f.header), "{} missing", f.header);
    }
    check("bfd_session_detail", &d);
}

fn list(v: &[BfdSessionView]) -> String {
    render_detail_list(&v.to_vec(), "no bfd sessions")
}

#[test]
fn detail_up() {
    let mut s = up();
    s.uptime_secs = Some(3720);
    s.last_change_secs = 3720;
    s.down_count = 2;
    s.tx_packets = 123_456;
    s.rx_packets = 120_000;
    s.remote_min_rx_us = Some(3300);
    s.remote_desired_min_tx_us = Some(3300);
    s.remote_detect_mult = Some(3);
    s.clients = vec!["static".into(), "bgp".into()];
    check("bfd_detail_up", &list(&[s]));
}

#[test]
fn detail_down() {
    let s = base(
        "192.0.2.2",
        BfdState::Down,
        BfdDiag::ControlDetectionTimeExpired,
        Some("eth1"),
    );
    check("bfd_detail_down", &list(&[s]));
}

#[test]
fn detail_extras() {
    let mut a = up();
    a.auth_method = Some(BfdAuthMethod::KeyedSha1);
    a.auth_key_id = Some(2);
    a.echo_active = true;
    a.echo_interval_us = 50_000;
    a.kind = BfdSessionKind::SbfdInitiator;
    let mut u = up();
    u.kind = BfdSessionKind::Unsolicited;
    let mut m = base(
        "10.0.0.2",
        BfdState::Up,
        BfdDiag::NoDiagnostic,
        Some("eth1"),
    );
    m.key.aggregate = Some("bond0".into());
    m.key.table = String::new();
    m.clients = vec!["micro-bfd".into()];
    check("bfd_detail_extras", &list(&[a, u, m]));
}

#[test]
fn detail_several() {
    let d = base("192.0.2.2", BfdState::Down, BfdDiag::NoDiagnostic, None);
    let out = list(&[up(), d, up()]);
    assert_eq!(out.matches("\n\n").count(), 2, "{out}");
    check("bfd_detail_several", &out);
}

#[test]
fn detail_empty() {
    check("bfd_detail_empty", &list(&[]));
}

#[test]
fn detail_forged_stays_one_line() {
    let mut s = up();
    s.key.interface = Some("eth0\nFORGED  up".into());
    s.clients = vec!["a\u{1b}[2J\nFORGED".into()];
    let out = list(&[s]);
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(!out.contains("\nFORGED"), "{out:?}");
}
