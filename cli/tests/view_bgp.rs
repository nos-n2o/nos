//! Goldens of `show bgp summary` through the generic view engine (#1440).
//! Goldens are in `tests/goldens/`; edit them by hand from the failing diff.

use nos_cli::view::{render, render_detail_list};
use nos_proto::{
    AddressFamily, BgpSessionState, GrFamily, GrSummary, MessageCounts, NotificationInfo,
    PeerIdleStatus, PeerSummary, PrefixCounts, ResetReason,
};

fn base(addr: &str) -> PeerSummary {
    PeerSummary {
        remote_address: addr.parse().unwrap(),
        peer_group: "pg1".into(),
        shutdown: false,
        remote_as: None,
        remote_bgp_id: None,
        state: BgpSessionState::Idle,
        uptime_secs: None,
        negotiated_hold_time: None,
        negotiated_keepalive: None,
        ao_current_key: None,
        ao_rnext_key: None,
        ao_packets_good: None,
        ao_packets_bad: None,
        ao_packets_key_not_found: None,
        max_prefix_held: false,
        accepted_prefixes: None,
        graceful_restart: None,
        stale_prefixes: 0,
        status: PeerIdleStatus::None,
        msg_received: MessageCounts::default(),
        msg_sent: MessageCounts::default(),
        messages_received: 0,
        messages_sent: 0,
        last_notification_sent: None,
        last_notification_received: None,
        last_reset_reason: None,
        flap_count: 0,
    }
}

fn check(name: &str, got: &str) {
    let path = format!("{}/tests/goldens/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    let want = std::fs::read_to_string(&path).unwrap();
    assert_eq!(want, format!("{got}\n"), "golden {name}");
}

fn show(v: &[PeerSummary]) -> String {
    render(&v.to_vec(), "bgp instance r1: no peers configured")
}

fn established() -> PeerSummary {
    let mut p = base("10.0.0.2");
    p.remote_as = Some(65002);
    p.remote_bgp_id = Some("2.2.2.2".parse().unwrap());
    p.state = BgpSessionState::Established;
    p.uptime_secs = Some(3725);
    p.negotiated_hold_time = Some(90);
    p.negotiated_keepalive = Some(30);
    p.accepted_prefixes = Some(PrefixCounts {
        ipv4: 3,
        ipv6: 0,
        evpn: 2,
    });
    p.msg_received = MessageCounts {
        open: 1,
        update: 4,
        notification: 0,
        keepalive: 120,
        route_refresh: 0,
    };
    p.msg_sent = MessageCounts {
        open: 1,
        update: 3,
        notification: 0,
        keepalive: 121,
        route_refresh: 1,
    };
    p.messages_received = 125;
    p.messages_sent = 126;
    p.last_notification_sent = Some(NotificationInfo {
        code: 6,
        subcode: 9,
        seconds_ago: 3800,
    });
    p.last_reset_reason = Some(ResetReason::NotificationSent);
    p.flap_count = 2;
    p
}

#[test]
fn empty() {
    check("bgp_summary_empty", &show(&[]));
}

#[test]
fn established_with_prefixes() {
    check("bgp_summary_established", &show(&[established()]));
}

#[test]
fn idle_statuses() {
    let mut shut = base("10.0.0.1");
    shut.shutdown = true;
    shut.status = PeerIdleStatus::AdminShutdown;
    let mut held = base("10.0.0.3");
    held.max_prefix_held = true;
    held.status = PeerIdleStatus::MaxPrefix;
    let mut stale = base("10.0.0.4");
    stale.stale_prefixes = 4;
    stale.status = PeerIdleStatus::GrStale;
    let mut forged = base("10.0.0.5");
    forged.peer_group = "x\ny".into();
    check(
        "bgp_summary_idle_statuses",
        &show(&[stale, forged, held, shut, established()]),
    );
}

#[test]
fn ao_and_gr_stay_in_the_detail() {
    let mut p = established();
    p.ao_current_key = Some(1);
    p.ao_rnext_key = Some(2);
    p.ao_packets_good = Some(42);
    p.ao_packets_bad = Some(1);
    p.ao_packets_key_not_found = Some(0);
    p.graceful_restart = Some(GrSummary {
        restart_time: 120,
        notification: true,
        restarting: false,
        families: vec![
            GrFamily {
                family: AddressFamily::Ipv4Unicast,
                forwarding: true,
            },
            GrFamily {
                family: AddressFamily::Ipv6Unicast,
                forwarding: false,
            },
        ],
    });
    check("bgp_summary_ao_gr", &render_detail_list(&vec![p], "none"));
}
