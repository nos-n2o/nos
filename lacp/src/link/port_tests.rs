//! `Port` and `drive` against a fake link: no `AF_PACKET` socket, no
//! `CAP_NET_RAW` (#346).

use std::io;
use std::sync::Mutex as StdMutex;

use tokio::sync::mpsc;

use super::*;
use crate::packet::{decode, encode, Lacpdu};

const ENETDOWN: i32 = 100;
const EIO: i32 = 5;
const PARTNER: [u8; 6] = [9; 6];

/// Records every PDU and can be told to fail the send.
#[derive(Default)]
struct VecSink {
    sent: StdMutex<Vec<Vec<u8>>>,
    fail_with: StdMutex<Option<i32>>,
}

impl FrameSink for VecSink {
    fn send(&self, pdu: &[u8]) -> io::Result<()> {
        self.sent.lock().unwrap().push(pdu.to_vec());
        match *self.fail_with.lock().unwrap() {
            Some(code) => Err(io::Error::from_raw_os_error(code)),
            None => Ok(()),
        }
    }
}

impl VecSink {
    fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
    fn last_pdu_partner(&self) -> PortInfo {
        decode(self.sent.lock().unwrap().last().expect("a PDU was sent"))
            .unwrap()
            .partner
    }
    fn last_actor(&self) -> PortInfo {
        decode(self.sent.lock().unwrap().last().expect("a PDU was sent"))
            .unwrap()
            .actor
    }
}

fn config(active: bool, rate: LacpRate, selected_rx: watch::Receiver<bool>) -> LinkConfig {
    LinkConfig {
        interface: "eth1".into(),
        actor_system_id: [1; 6],
        actor_system_priority: 100,
        actor_key: 7,
        actor_port_priority: 200,
        actor_port_number: 1,
        actor_active: active,
        rate,
        selected_rx,
        churn_time: Duration::from_secs(5),
    }
}

struct Rig {
    port: Port,
    sink: VecSink,
    observations: Arc<Mutex<HashMap<String, PortObservation>>>,
    _selected_tx: watch::Sender<bool>,
}

fn rig(active: bool, rate: LacpRate) -> Rig {
    let (tx, rx) = watch::channel(false);
    let observations = Arc::new(Mutex::new(HashMap::new()));
    let port = Port::new(
        config(active, rate, rx),
        observations.clone(),
        Arc::new(Notify::new()),
        3,
    );
    Rig {
        port,
        sink: VecSink::default(),
        observations,
        _selected_tx: tx,
    }
}

impl Rig {
    /// A fresh LACPDU budget (the limiter is 3 per second, wall clock).
    fn refill(&mut self) {
        self.port.tx.limiter = TxLimiter::new(Instant::now(), MAX_TX_PER_WINDOW);
    }

    fn observed(&self) -> PortObservation {
        *self.observations.lock().unwrap().get("eth1").unwrap()
    }
}

fn partner_info(state: u8) -> PortInfo {
    PortInfo {
        system_priority: 1,
        system: PARTNER,
        key: 1,
        port_priority: 1,
        port: 7,
        state,
    }
}

fn partner_frame(state: u8) -> Vec<u8> {
    encode(&Lacpdu {
        actor: partner_info(state),
        partner: our_view(),
        collector_max_delay: 0,
        v2: None,
    })
}

/// The Partner block of a partner that has heard us: our rig actor identity.
fn our_view() -> PortInfo {
    PortInfo {
        system_priority: 100,
        system: [1; 6],
        key: 7,
        port_priority: 200,
        port: 3,
        state: state_bit::AGGREGATION,
    }
}

fn frame_with_view(state: u8, view: PortInfo) -> Vec<u8> {
    encode(&Lacpdu {
        actor: partner_info(state),
        partner: view,
        collector_max_delay: 0,
        v2: None,
    })
}

fn marker_request(txid: u32) -> Vec<u8> {
    let mut b = vec![0x02, 0x01, 0x01, 16, 0x00, 0x2a];
    b.extend_from_slice(&PARTNER);
    b.extend_from_slice(&txid.to_be_bytes());
    b.resize(packet::LACPDU_LEN, 0);
    b
}

const ACTIVE_PARTNER: u8 = state_bit::ACTIVITY | state_bit::AGGREGATION;

#[test]
fn start_reports_expired_and_sends_the_first_pdu_at_once() {
    let mut r = rig(true, LacpRate::Slow);
    let o = r.observed();
    assert_eq!(o.receive_state, ReceiveState::Expired);
    assert_eq!(o.mux_state, MuxState::Detached);
    assert_eq!(o.actor_port, 3);
    assert!(o.partner.is_none() && !o.current());
    assert!(
        !o.selectable(),
        "an Expired-from-start port is not selectable"
    );

    r.port.on_periodic(&r.sink);
    let actor = r.sink.last_actor();
    assert_eq!(actor.system, [1; 6]);
    assert_eq!((actor.key, actor.port, actor.port_priority), (7, 3, 200));
    assert!(actor.has_state(state_bit::ACTIVITY) && actor.has_state(state_bit::EXPIRED));
    assert!(!actor.has_state(state_bit::TIMEOUT) && !actor.has_state(state_bit::SYNCHRONIZATION));
    assert!(r.port.tx.next_periodic_send > Instant::now());
}

#[test]
fn a_passive_port_with_no_partner_sends_nothing() {
    let mut r = rig(false, LacpRate::Slow);
    assert!(r.port.tx.no_periodic);
    r.port.on_periodic(&r.sink);
    assert_eq!(r.sink.count(), 0);
}

#[test]
fn a_partner_lacpdu_makes_the_port_current_and_is_answered_once() {
    let mut r = rig(false, LacpRate::Fast);
    r.port.on_frame(&partner_frame(ACTIVE_PARTNER), &r.sink);
    let o = r.observed();
    assert!(o.current());
    assert_eq!(o.partner, Some(partner_info(ACTIVE_PARTNER)));
    assert!(
        !r.port.tx.no_periodic,
        "an active partner wakes a passive port"
    );
    assert_eq!(r.sink.count(), 1);
    assert_eq!(
        r.sink.last_actor().state & state_bit::TIMEOUT,
        state_bit::TIMEOUT
    );
    let reply = decode(&r.sink.sent.lock().unwrap()[0]).unwrap();
    assert_eq!(reply.partner, partner_info(ACTIVE_PARTNER));

    r.port.on_frame(&partner_frame(ACTIVE_PARTNER), &r.sink);
    assert_eq!(
        r.sink.count(),
        1,
        "an identical advertisement is not repeated"
    );

    r.port.on_frame(&[1, 2, 3], &r.sink);
    r.port.on_frame(&[0xff; packet::LACPDU_LEN], &r.sink);
    assert_eq!(r.sink.count(), 1, "undecodable frames are ignored");
}

#[test]
fn unsupported_versions_are_counted_and_v1_v2_are_not() {
    let mut r = rig(true, LacpRate::Slow);
    let mut v3 = partner_frame(ACTIVE_PARTNER);
    v3[1] = 3;
    r.port.on_frame(&v3, &r.sink);
    assert_eq!(r.observed().unsupported_version_pdus, 1);
    assert!(r.observed().partner.is_none(), "a v3 PDU is not processed");
    // Other decode errors are not counted.
    r.port.on_frame(&[1, 2, 3], &r.sink);
    assert_eq!(r.observed().unsupported_version_pdus, 1);
    // v2 (longer) is processed like v1 and not counted.
    let mut v2 = partner_frame(ACTIVE_PARTNER);
    v2[1] = 2;
    v2.extend_from_slice(&[0x04, 0x06, 0x80, 0xc2, 0, 1]);
    r.port.on_frame(&v2, &r.sink);
    assert_eq!(r.observed().unsupported_version_pdus, 1);
    assert!(r.observed().partner.is_some());
}

#[test]
fn the_mux_walks_to_distributing_with_the_partner() {
    let mut r = rig(true, LacpRate::Slow);
    r.port.on_selection(true, &r.sink);
    assert_eq!(r.observed().mux_state, MuxState::Waiting);
    assert!(r.port.wait_while_deadline < Instant::now() + Duration::from_secs(3));

    r.port.on_wait_while_expired(&r.sink);
    assert_eq!(r.observed().mux_state, MuxState::Attached);
    assert!(r.sink.last_actor().has_state(state_bit::SYNCHRONIZATION));
    assert!(r.port.wait_while_deadline > Instant::now() + Duration::from_secs(3600));

    r.port.on_frame(
        &partner_frame(ACTIVE_PARTNER | state_bit::SYNCHRONIZATION),
        &r.sink,
    );
    assert_eq!(r.observed().mux_state, MuxState::Collecting);

    let both = ACTIVE_PARTNER | state_bit::SYNCHRONIZATION | state_bit::COLLECTING;
    r.refill();
    r.port.on_frame(&partner_frame(both), &r.sink);
    assert_eq!(r.observed().mux_state, MuxState::Distributing);
    assert!(r.sink.last_actor().has_state(state_bit::DISTRIBUTING));
    r.refill();

    r.port.on_selection(false, &r.sink);
    assert_eq!(r.observed().mux_state, MuxState::Detached);
    assert!(!r.sink.last_actor().has_state(state_bit::SYNCHRONIZATION));
}

#[test]
fn a_silent_partner_expires_then_defaults_and_disarms_the_timer() {
    let mut r = rig(true, LacpRate::Fast);
    r.port.on_selection(true, &r.sink);
    r.port.on_wait_while_expired(&r.sink);
    let both = ACTIVE_PARTNER | state_bit::SYNCHRONIZATION | state_bit::COLLECTING;
    r.port.on_frame(&partner_frame(both), &r.sink);
    r.port.on_frame(&partner_frame(both), &r.sink);
    assert_eq!(r.observed().mux_state, MuxState::Distributing);
    assert!(r.observed().current());

    r.refill();
    r.port.on_current_while_expired(&r.sink);
    let o = r.observed();
    assert_eq!(o.receive_state, ReceiveState::Expired);
    let kept = o.partner.expect("Expired keeps the learned partner");
    assert!(!kept.has_state(state_bit::SYNCHRONIZATION | state_bit::COLLECTING));
    assert!(o.selectable() && !o.current());
    assert_eq!(
        o.mux_state,
        MuxState::Attached,
        "mux told the partner left sync"
    );
    assert!(r.sink.last_actor().has_state(state_bit::EXPIRED));

    r.refill();
    r.port.on_current_while_expired(&r.sink);
    assert_eq!(r.observed().receive_state, ReceiveState::Defaulted);
    assert!(r.observed().partner.is_none() && !r.observed().selectable());
    assert_eq!(r.sink.last_pdu_partner(), PortInfo::ADMINISTRATIVE_DEFAULT);
    assert!(r.sink.last_actor().has_state(state_bit::DEFAULTED));
    assert!(r.port.current_while_deadline > Instant::now() + Duration::from_secs(3600));
}

#[test]
fn one_missed_pdu_keeps_the_port_selected_and_recovers_without_waiting() {
    let mut r = rig(true, LacpRate::Fast);
    r.port.on_selection(true, &r.sink);
    r.port.on_wait_while_expired(&r.sink);
    let both = ACTIVE_PARTNER | state_bit::SYNCHRONIZATION | state_bit::COLLECTING;
    r.port.on_frame(&partner_frame(both), &r.sink);
    r.port.on_frame(&partner_frame(both), &r.sink);
    assert_eq!(r.observed().mux_state, MuxState::Distributing);

    r.refill();
    r.port.on_current_while_expired(&r.sink);
    assert_eq!(r.observed().mux_state, MuxState::Attached);
    r.refill();
    r.port.on_frame(&partner_frame(both), &r.sink);
    let o = r.observed();
    assert_eq!(o.receive_state, ReceiveState::Current);
    assert_ne!(o.mux_state, MuxState::Detached);
    assert_ne!(o.mux_state, MuxState::Waiting, "no 2s re-wait");
    assert!(r.port.wait_while_deadline > Instant::now() + Duration::from_secs(3600));
}

#[test]
fn markers_are_echoed_within_budget_and_send_errors_are_not_fatal() {
    let mut r = rig(true, LacpRate::Slow);
    for txid in 0..5 {
        r.port.on_frame(&marker_request(txid), &r.sink);
    }
    assert_eq!(r.sink.count(), 5);
    let resp = &r.sink.sent.lock().unwrap()[4].clone();
    assert_eq!(resp[2], 0x02, "a Marker Response TLV");
    assert_eq!(&resp[4..6], &[0x00, 0x2a]);
    assert_eq!(&resp[6..12], &PARTNER);
    assert_eq!(&resp[12..16], &4u32.to_be_bytes());

    r.port.on_frame(&marker_request(99), &r.sink);
    assert_eq!(r.sink.count(), 5, "the sixth in a window is dropped");

    for code in [ENETDOWN, EIO] {
        let mut r = rig(true, LacpRate::Slow);
        *r.sink.fail_with.lock().unwrap() = Some(code);
        r.port.on_frame(&marker_request(1), &r.sink);
        assert_eq!(r.sink.count(), 1, "attempted");
    }
}

#[test]
fn the_limiter_defers_the_fourth_pdu_to_the_next_refill() {
    let mut r = rig(true, LacpRate::Slow);
    let pdu = r.port.pdu();
    for _ in 0..3 {
        r.port.tx.transmit(&r.sink, "eth1", pdu.clone());
    }
    assert_eq!(r.sink.count(), 3);
    r.port.tx.transmit(&r.sink, "eth1", pdu.clone());
    assert_eq!(r.sink.count(), 3);
    assert_eq!(
        r.port.tx.next_periodic_send,
        r.port.tx.limiter.next_refill()
    );
}

#[test]
fn leaving_no_periodic_arms_an_immediate_send() {
    let mut tx = TxState::new();
    tx.update_periodic("eth1", false, ReceiveState::Current, None);
    assert!(tx.no_periodic);
    assert!(tx.next_periodic_send > Instant::now() + Duration::from_secs(3600));

    tx.update_periodic(
        "eth1",
        false,
        ReceiveState::Current,
        Some(partner_info(ACTIVE_PARTNER)),
    );
    assert!(!tx.no_periodic);
    assert!(tx.next_periodic_send <= Instant::now());
}

#[test]
fn lacpdu_send_errors_are_logged_not_propagated() {
    for code in [ENETDOWN, EIO] {
        let mut r = rig(true, LacpRate::Slow);
        *r.sink.fail_with.lock().unwrap() = Some(code);
        r.port.on_periodic(&r.sink);
        assert_eq!(r.sink.count(), 1);
    }
}

#[test]
fn observation_predicates_follow_the_partner_and_churn() {
    let mut o = PortObservation {
        receive_state: ReceiveState::Current,
        mux_state: MuxState::Detached,
        actor_port: 1,
        partner: None,
        actor_churn: ChurnState::NoChurn,
        partner_churn: ChurnState::NoChurn,
        unsupported_version_pdus: 0,
    };
    assert!(o.current() && !o.is_churned() && !o.partner_individual());
    o.partner = Some(partner_info(state_bit::ACTIVITY));
    assert!(o.partner_individual(), "no Aggregation bit: individual");
    o.partner = Some(partner_info(ACTIVE_PARTNER));
    assert!(!o.partner_individual());
    o.partner_churn = ChurnState::Churn;
    assert!(o.is_churned());
    o.receive_state = ReceiveState::Expired;
    assert!(!o.current());
}

#[test]
fn churn_timers_fire_through_the_port() {
    let mut r = rig(true, LacpRate::Slow);
    assert_eq!(r.observed().actor_churn, ChurnState::Monitor);
    r.port.on_actor_churn();
    r.port.on_partner_churn();
    let o = r.observed();
    assert_eq!(
        (o.actor_churn, o.partner_churn),
        (ChurnState::Churn, ChurnState::Churn)
    );
    assert!(o.is_churned());
}

#[tokio::test]
async fn run_returns_when_the_interface_cannot_be_opened() {
    let (_tx, rx) = watch::channel(false);
    let observations = Arc::new(Mutex::new(HashMap::new()));
    let mut c = config(true, LacpRate::Slow, rx);
    c.interface = "nos-no-such0".into();
    tokio::time::timeout(
        Duration::from_secs(5),
        run(c, observations.clone(), Arc::new(Notify::new())),
    )
    .await
    .expect("returns at once");
    assert!(observations.lock().unwrap().is_empty());
}

/// A link whose receive side is a channel the test feeds.
struct ChanLink {
    sink: VecSink,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<io::Result<Vec<u8>>>>,
}

impl FrameSink for ChanLink {
    fn send(&self, pdu: &[u8]) -> io::Result<()> {
        self.sink.send(pdu)
    }
}

impl FrameLink for ChanLink {
    async fn recv(&self) -> io::Result<Vec<u8>> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .unwrap_or_else(|| Err(io::Error::other("closed")))
    }
}

#[tokio::test(start_paused = true)]
async fn drive_follows_timers_selection_and_frames_until_the_link_fails() {
    let (sel_tx, sel_rx) = watch::channel(false);
    let (frames_tx, frames_rx) = mpsc::unbounded_channel();
    let observations = Arc::new(Mutex::new(HashMap::new()));
    let port = Port::new(
        config(true, LacpRate::Fast, sel_rx.clone()),
        observations.clone(),
        Arc::new(Notify::new()),
        3,
    );
    let link = ChanLink {
        sink: VecSink::default(),
        rx: tokio::sync::Mutex::new(frames_rx),
    };
    let observed = || *observations.lock().unwrap().get("eth1").unwrap();
    let mut driver = Box::pin(drive(port, sel_rx, &link));
    let settle = |secs: u64| async move {
        tokio::time::sleep(Duration::from_secs(secs)).await;
    };

    // Time only advances while the driver is polled: race it with a sleep.
    macro_rules! advance {
        ($secs:expr) => {
            tokio::select! {
                () = &mut driver => panic!("driver ended early"),
                () = settle($secs) => {}
            }
        };
    }

    advance!(1);
    assert!(link.sink.count() >= 1, "periodic transmission");
    assert_eq!(observed().receive_state, ReceiveState::Expired);

    frames_tx.send(Ok(partner_frame(ACTIVE_PARTNER))).unwrap();
    advance!(1);
    assert!(observed().current());

    sel_tx.send(true).unwrap();
    advance!(1);
    assert_eq!(observed().mux_state, MuxState::Waiting);
    advance!(3);
    assert_eq!(observed().mux_state, MuxState::Attached, "wait-while fired");

    // Fast rate: the partner is declared gone after 3 s, then defaults.
    advance!(10);
    assert_eq!(observed().receive_state, ReceiveState::Defaulted);
    advance!(10);
    let o = observed();
    assert!(o.actor_churn == ChurnState::Churn || o.partner_churn == ChurnState::Churn);

    frames_tx
        .send(Err(io::Error::other("socket gone")))
        .unwrap();
    driver.await;
}

#[tokio::test(start_paused = true)]
async fn drive_exits_when_the_aggregate_manager_is_gone() {
    let (sel_tx, sel_rx) = watch::channel(false);
    let (_frames_tx, frames_rx) = mpsc::unbounded_channel();
    let port = Port::new(
        config(true, LacpRate::Slow, sel_rx.clone()),
        Arc::new(Mutex::new(HashMap::new())),
        Arc::new(Notify::new()),
        3,
    );
    let link = ChanLink {
        sink: VecSink::default(),
        rx: tokio::sync::Mutex::new(frames_rx),
    };
    drop(sel_tx);
    drive(port, sel_rx, &link).await;
}

#[tokio::test(start_paused = true)]
async fn lacpdus_beyond_the_rx_budget_are_dropped_and_refill_after_a_second() {
    let mut r = rig(true, LacpRate::Slow);
    let sync = state_bit::SYNCHRONIZATION | ACTIVE_PARTNER;
    for _ in 0..MAX_RX_PER_WINDOW {
        r.port.on_frame(&partner_frame(ACTIVE_PARTNER), &r.sink);
    }
    assert_eq!(r.port.rx_dropped, 0);
    let before = r.observed();
    r.port.on_frame(&partner_frame(sync), &r.sink);
    assert_eq!(r.port.rx_dropped, 1);
    assert_eq!(r.observed(), before, "a dropped LACPDU changes no state");
    // Markers have their own budget.
    let sent = r.sink.count();
    r.port.on_frame(&marker_request(1), &r.sink);
    assert_eq!(r.sink.count(), sent + 1);

    tokio::time::advance(TX_WINDOW).await;
    r.port.on_frame(&partner_frame(sync), &r.sink);
    assert_eq!(r.port.rx_dropped, 0);
    assert_ne!(r.observed(), before);
}

const BOTH: u8 = ACTIVE_PARTNER | state_bit::SYNCHRONIZATION | state_bit::COLLECTING;

fn distributing_rig() -> Rig {
    let mut r = rig(true, LacpRate::Fast);
    r.port.on_selection(true, &r.sink);
    r.port.on_wait_while_expired(&r.sink);
    r.port.on_frame(&partner_frame(BOTH), &r.sink);
    r.port.on_frame(&partner_frame(BOTH), &r.sink);
    assert_eq!(r.observed().mux_state, MuxState::Distributing);
    r
}

#[test]
fn a_stale_partner_view_never_advances_the_mux() {
    let stale = [
        PortInfo {
            system: [2; 6],
            ..our_view()
        },
        PortInfo {
            system_priority: 1,
            ..our_view()
        },
        PortInfo {
            key: 8,
            ..our_view()
        },
        PortInfo {
            port_priority: 1,
            ..our_view()
        },
        PortInfo {
            port: 4,
            ..our_view()
        },
        PortInfo {
            state: 0,
            ..our_view()
        },
    ];
    for view in stale {
        let mut r = rig(true, LacpRate::Fast);
        r.port.on_selection(true, &r.sink);
        r.port.on_wait_while_expired(&r.sink);
        r.port.on_frame(&frame_with_view(BOTH, view), &r.sink);
        let o = r.observed();
        assert_eq!(o.mux_state, MuxState::Attached, "{view:?}");
        assert!(!o.partner.unwrap().has_state(state_bit::SYNCHRONIZATION));
    }
    let mut r = rig(true, LacpRate::Fast);
    r.port.on_selection(true, &r.sink);
    r.port.on_wait_while_expired(&r.sink);
    r.port.on_frame(&frame_with_view(BOTH, our_view()), &r.sink);
    r.port.on_frame(&frame_with_view(BOTH, our_view()), &r.sink);
    assert_eq!(r.observed().mux_state, MuxState::Distributing);
}

#[test]
fn a_stale_view_mid_distributing_leaves_it() {
    let mut r = distributing_rig();
    r.refill();
    r.port.on_frame(
        &frame_with_view(
            BOTH,
            PortInfo {
                system: [2; 6],
                ..our_view()
            },
        ),
        &r.sink,
    );
    assert_eq!(r.observed().mux_state, MuxState::Attached);
    assert!(!r.port.partner_view_matches);
}

#[test]
fn a_changed_partner_identity_deselects_the_port() {
    let mut r = distributing_rig();
    r.refill();
    r.port.on_frame(&frame_with_view(BOTH, our_view()), &r.sink);
    assert_eq!(
        r.observed().mux_state,
        MuxState::Distributing,
        "same partner"
    );
    let mut new = partner_info(BOTH);
    new.system = [8; 6];
    let pdu = Lacpdu {
        actor: new,
        partner: our_view(),
        collector_max_delay: 0,
        v2: None,
    };
    r.port.on_frame(&encode(&pdu), &r.sink);
    assert_eq!(r.observed().partner.unwrap().system, [8; 6]);
    assert_ne!(r.observed().mux_state, MuxState::Distributing);
}

#[test]
fn an_individual_partner_skips_the_match() {
    let mut r = rig(true, LacpRate::Fast);
    r.port.on_frame(
        &frame_with_view(
            state_bit::ACTIVITY,
            PortInfo {
                system: [2; 6],
                ..our_view()
            },
        ),
        &r.sink,
    );
    assert!(r.port.partner_view_matches);
}

#[test]
fn matching_compares_the_key() {
    let ours = our_view();
    assert!(partner_matches_actor(&our_view(), &ours));
    assert!(!partner_matches_actor(
        &PortInfo {
            key: 9,
            ..our_view()
        },
        &ours
    ));
}

#[test]
fn own_system_id_lacpdus_are_dropped_and_warn_once() {
    let mut r = rig(true, LacpRate::Fast);
    r.port.on_selection(true, &r.sink);
    let before = r.observed();
    let sent = r.sink.count();
    // Same system id, another priority: still ours (#658).
    let looped = |prio| {
        encode(&Lacpdu {
            actor: PortInfo {
                system: [1; 6],
                system_priority: prio,
                ..partner_info(ACTIVE_PARTNER)
            },
            partner: our_view(),
            collector_max_delay: 0,
            v2: None,
        })
    };
    r.port.on_frame(&looped(100), &r.sink);
    assert!(r.port.loopback_logged);
    r.port.on_frame(&looped(5), &r.sink);
    assert_eq!(r.observed(), before);
    assert!(r.port.partner.is_none());
    assert_eq!(r.sink.count(), sent);
    r.port.on_frame(&partner_frame(ACTIVE_PARTNER), &r.sink);
    assert!(!r.port.loopback_logged);
    assert!(r.port.partner.is_some());
}
