//! One member port's own Receive/Periodic-Transmission/Mux machines and I/O
//! — the LACP counterpart of `ospf::link.rs`'s per-link `run()` shape.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nos_proto::LacpRate;
use tokio::sync::{watch, Notify};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::churn_machine::{self, ChurnState};
use crate::mux_machine::{self, MuxState};
use crate::packet::{self, state_bit, Lacpdu, PortInfo};
use crate::periodic_tx_machine::interval_for;
use crate::receive_machine::{self, ReceiveState};
use crate::socket::LacpSocket;

/// Static, aggregate-wide identity handed to every one of its member ports
/// — see `aggregate.rs`'s doc comment for how `system_id`/`key` are
/// derived.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    pub interface: String,
    pub actor_system_id: [u8; 6],
    pub actor_system_priority: u16,
    pub actor_key: u16,
    pub actor_port_priority: u16,
    /// 802.1AX §6.3.4 Port Number: unique and non-zero across the daemon
    /// (`aggregate::PortNumbers`), never derived from the ifindex.
    pub actor_port_number: u16,
    /// `LACP_Activity`: `false` = Passive (see `periodic_tx_machine`).
    pub actor_active: bool,
    /// How fast we ask the partner to send (our advertised `LACP_Timeout`),
    /// and so how long we wait for it — see `receive_machine`.
    pub rate: LacpRate,
    /// This aggregate's `selected_rx.borrow()` reflects Selection Logic's
    /// current verdict for this specific port — updated by `aggregate.rs`
    /// whenever it re-runs `selection::select` (on any port's observation
    /// change).
    pub selected_rx: watch::Receiver<bool>,
    /// 802.1AX `Churn_Detection_Time` (60s; shortened only by tests/e2e via
    /// `NOS_LACP_CHURN_SECS`, see `aggregate.rs`).
    pub churn_time: Duration,
}

/// One member port's currently-observed state, as reported up to
/// `aggregate.rs` after every event that could change it — the input to
/// `selection::select`, the active-member-set computation, and `show lacp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortObservation {
    pub receive_state: ReceiveState,
    pub mux_state: MuxState,
    pub actor_port: u16,
    /// The partner's last recorded Actor information — `None` until a
    /// LACPDU has been heard, and again once the Receive Machine gives up
    /// (Defaulted): `None` means "the administrative default". While
    /// `Expired` it is kept (Synchronization/Collecting cleared), like Linux.
    pub partner: Option<PortInfo>,
    pub actor_churn: ChurnState,
    pub partner_churn: ChurnState,
    /// LACPDUs dropped for a Version byte other than 1 or 2 since this link
    /// task started (in memory only).
    pub unsupported_version_pdus: u64,
}

impl PortObservation {
    /// A churned port (either side stuck out of sync for a whole
    /// `Churn_Detection_Time`) carries no traffic: `aggregate.rs` leaves it
    /// out of the active-member set.
    pub fn is_churned(&self) -> bool {
        self.actor_churn == ChurnState::Churn || self.partner_churn == ChurnState::Churn
    }

    /// The partner's last LACPDU cleared `Actor_State.Aggregation`: it treats
    /// the link as an Individual one, not aggregatable with any other.
    pub fn partner_individual(&self) -> bool {
        self.partner
            .is_some_and(|p| !p.has_state(state_bit::AGGREGATION))
    }

    pub fn current(&self) -> bool {
        self.receive_state == ReceiveState::Current
    }

    /// May take part in selection: `Current`, or `Expired` with a partner
    /// actually learned from a LACPDU (kept through one missed PDU, 802.1AX
    /// §6.4.12). A never-heard (Expired from start) or `Defaulted` port has
    /// `partner == None` and is never selectable, so defaulted ports cannot
    /// form a bogus all-default partner group.
    pub fn selectable(&self) -> bool {
        self.current() || (self.receive_state == ReceiveState::Expired && self.partner.is_some())
    }
}

/// A deadline far enough in the future to act as "this timer is disabled" —
/// simpler than threading `Option<Instant>` through every `tokio::select!`
/// branch for a state (`Waiting`) this port spends only a couple of seconds
/// in per selection change.
fn far_future() -> Instant {
    Instant::now() + Duration::from_hours(24)
}

/// What the engine needs of the member's socket to transmit: the seam that
/// lets tests drive a [`Port`] without `CAP_NET_RAW` (#346).
trait FrameSink {
    fn send(&self, pdu: &[u8]) -> io::Result<()>;
}

/// A [`FrameSink`] that also yields the next received PDU.
trait FrameLink: FrameSink {
    async fn recv(&self) -> io::Result<Vec<u8>>;
}

impl FrameSink for LacpSocket {
    fn send(&self, pdu: &[u8]) -> io::Result<()> {
        LacpSocket::send(self, pdu)
    }
}

impl FrameLink for LacpSocket {
    async fn recv(&self) -> io::Result<Vec<u8>> {
        LacpSocket::recv(self).await
    }
}

/// Runs one member port's LACP engine until its socket dies or the
/// aggregate drops it (the caller aborts this task — see
/// `aggregate.rs::reconcile`, mirroring `ospf::link::LinkManager`'s own
/// abort-based teardown). Reports every observable state change into
/// `observations[interface]`, then signals `changed` so `aggregate.rs` can
/// re-run Selection Logic and recompute the aggregate's active-member set.
#[allow(clippy::implicit_hasher)] // always the default hasher; never needs to be generic here
pub async fn run(
    config: LinkConfig,
    observations: Arc<Mutex<HashMap<String, PortObservation>>>,
    changed: Arc<Notify>,
) {
    let socket = match crate::socket::open(&config.interface) {
        Ok(s) => s,
        Err(e) => {
            warn!(interface = %config.interface, error = %e, "failed to open lacp socket");
            return;
        }
    };
    let port_number = config.actor_port_number;
    let selected_rx = config.selected_rx.clone();
    let p = Port::new(config, observations, changed, port_number);
    drive(p, selected_rx, &socket).await;
}

/// The event loop of one port: timers, Selection Logic verdicts and received
/// PDUs, until the aggregate is gone or the link's receive side fails.
async fn drive<L: FrameLink>(mut p: Port, mut selected_rx: watch::Receiver<bool>, link: &L) {
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(p.tx.next_periodic_send) => p.on_periodic(link),
            () = tokio::time::sleep_until(p.current_while_deadline) => {
                p.on_current_while_expired(link);
            }
            () = tokio::time::sleep_until(p.churn.actor_deadline) => p.on_actor_churn(),
            () = tokio::time::sleep_until(p.churn.partner_deadline) => p.on_partner_churn(),
            () = tokio::time::sleep_until(p.wait_while_deadline) => {
                p.on_wait_while_expired(link);
            }
            result = selected_rx.changed() => {
                if result.is_err() {
                    debug!(interface = %p.config.interface, "aggregate manager gone, lacp link task exiting");
                    return;
                }
                let selected = *selected_rx.borrow_and_update();
                p.on_selection(selected, link);
            }
            recv = link.recv() => {
                let Ok(bytes) = recv else {
                    warn!(interface = %p.config.interface, error = ?recv.err(), "lacp socket closed, link task exiting");
                    return;
                };
                p.on_frame(&bytes, link);
            }
        }
    }
}

/// One member port's whole state: the three machines, their deadlines, the
/// transmit state and what was last reported. One method per event of
/// [`run`]'s loop, so tests can drive them with a fake [`FrameSink`].
struct Port {
    config: LinkConfig,
    observations: Arc<Mutex<HashMap<String, PortObservation>>>,
    changed: Arc<Notify>,
    number: u16,
    receive_state: ReceiveState,
    mux_state: MuxState,
    partner: Option<PortInfo>,
    current_while_deadline: Instant,
    wait_while_deadline: Instant,
    tx: TxState,
    marker_limiter: TxLimiter,
    /// Inbound LACPDU budget (802.3 Annex 57A: 10 slow-protocol frames/s).
    rx_limiter: TxLimiter,
    /// LACPDUs dropped since the last accepted one (warned once per burst).
    rx_dropped: u64,
    /// Whether the loopback warning already fired for the current run of
    /// looped LACPDUs (reset by the next accepted one).
    loopback_logged: bool,
    /// LACPDUs with an unsupported Version byte (`show lacp`).
    unsupported_version_pdus: u64,
    churn: Churn,
    /// Whether the last LACPDU's Partner block described us (recordPDU).
    partner_view_matches: bool,
}

impl Port {
    /// The Receive machine's `Started` event, the first (immediate) periodic
    /// send armed, and the initial observation reported.
    fn new(
        config: LinkConfig,
        observations: Arc<Mutex<HashMap<String, PortObservation>>>,
        changed: Arc<Notify>,
        port_number: u16,
    ) -> Self {
        let mut current_while_deadline = Instant::now();
        let (receive_state, action) = receive_machine::step(
            ReceiveState::Current, // overwritten by Started
            receive_machine::Event::Started,
        );
        apply_receive_action(action, &mut current_while_deadline);

        // First send is immediate; each later one is scheduled from the state
        // at the time of the previous send (see `interval_for`).
        let mut tx = TxState::new();
        tx.update_periodic(&config.interface, config.actor_active, receive_state, None);
        let mut churn = Churn::new(&config.interface, config.churn_time);
        churn.eval(MuxState::Detached, None);
        let port = Self {
            config,
            observations,
            changed,
            number: port_number,
            receive_state,
            mux_state: MuxState::Detached,
            partner: None,
            current_while_deadline,
            wait_while_deadline: far_future(),
            tx,
            marker_limiter: TxLimiter::new(Instant::now(), MAX_MARKER_PER_WINDOW),
            rx_limiter: TxLimiter::new(Instant::now(), MAX_RX_PER_WINDOW),
            rx_dropped: 0,
            loopback_logged: false,
            unsupported_version_pdus: 0,
            churn,
            partner_view_matches: true,
        };
        port.report();
        port
    }

    fn pdu(&self) -> Lacpdu {
        build_pdu(
            &self.config,
            self.number,
            self.receive_state,
            self.mux_state,
            self.partner,
        )
    }

    fn report(&self) {
        report(
            &self.observations,
            &self.changed,
            &self.config.interface,
            self.number,
            self.receive_state,
            self.mux_state,
            self.partner,
            &self.churn,
            self.unsupported_version_pdus,
        );
    }

    /// Re-evaluates what depends on the machines' state after any event, then
    /// reports it.
    fn settle(&mut self) {
        self.churn.eval(self.mux_state, self.partner);
        self.report();
    }

    fn on_periodic(&mut self, sink: &dyn FrameSink) {
        let pdu = self.pdu();
        // Must move the deadline forward every time it fires, or the elapsed
        // deadline re-fires immediately: a hot loop. A send denied by the
        // limiter retries at the next refill instead (`transmit` sets that).
        self.tx.next_periodic_send = Instant::now()
            + interval_for(
                self.receive_state,
                self.config.actor_active,
                self.partner
                    .is_some_and(|p| p.has_state(state_bit::ACTIVITY)),
                self.partner
                    .is_some_and(|p| p.has_state(state_bit::TIMEOUT)),
            )
            .unwrap_or(Duration::from_hours(24));
        self.tx.transmit(sink, &self.config.interface, pdu);
    }

    fn on_current_while_expired(&mut self, sink: &dyn FrameSink) {
        let (rs, action) = receive_machine::step(
            self.receive_state,
            receive_machine::Event::CurrentWhileTimerExpired,
        );
        self.receive_state = rs;
        apply_receive_action(action, &mut self.current_while_deadline);
        if self.receive_state != ReceiveState::Current {
            // Expired keeps the partner (only its Sync/Collecting drop, its
            // timeout turns short); Defaulted records the admin default.
            self.partner = match self.receive_state {
                ReceiveState::Expired => self.partner.map(|mut p| {
                    p.state &= !(state_bit::SYNCHRONIZATION | state_bit::COLLECTING);
                    p.state |= state_bit::TIMEOUT;
                    p
                }),
                _ => None,
            };
            let (ms, mux_action) = mux_machine::step(
                self.mux_state,
                mux_machine::Event::PartnerStateChanged {
                    synchronized: false,
                    collecting: false,
                },
            );
            self.mux_state = ms;
            apply_mux_action(mux_action, &mut self.wait_while_deadline);
        }
        info!(interface = %self.config.interface, receive_state = ?self.receive_state, "lacp receive machine transitioned");
        self.tx.update_periodic(
            &self.config.interface,
            self.config.actor_active,
            self.receive_state,
            self.partner,
        );
        self.settle();
        self.tx
            .send_if_changed(sink, &self.config.interface, self.pdu());
    }

    fn on_actor_churn(&mut self) {
        self.churn.expire_actor();
        self.report();
    }

    fn on_partner_churn(&mut self) {
        self.churn.expire_partner();
        self.report();
    }

    fn on_wait_while_expired(&mut self, sink: &dyn FrameSink) {
        let (ms, action) =
            mux_machine::step(self.mux_state, mux_machine::Event::WaitWhileTimerExpired);
        self.mux_state = ms;
        apply_mux_action(action, &mut self.wait_while_deadline);
        info!(interface = %self.config.interface, mux_state = ?self.mux_state, "lacp mux machine transitioned");
        self.settle();
        self.tx
            .send_if_changed(sink, &self.config.interface, self.pdu());
    }

    fn on_selection(&mut self, selected: bool, sink: &dyn FrameSink) {
        let (ms, action) = mux_machine::step(
            self.mux_state,
            mux_machine::Event::SelectionChanged { selected },
        );
        self.mux_state = ms;
        apply_mux_action(action, &mut self.wait_while_deadline);
        info!(interface = %self.config.interface, mux_state = ?self.mux_state, selected, "lacp mux machine transitioned");
        self.settle();
        self.tx
            .send_if_changed(sink, &self.config.interface, self.pdu());
    }

    fn on_frame(&mut self, bytes: &[u8], sink: &dyn FrameSink) {
        if let Some(m) = packet::decode_marker(bytes) {
            // §6.5.4.2 responder: stateless, same port, no effect on the LACP machines.
            if self.marker_limiter.try_take(Instant::now()) {
                match sink.send(&packet::encode_marker_response(&m)) {
                    Ok(()) => {
                        info!(interface = %self.config.interface, requester_port = m.requester_port, requester_system = ?m.requester_system, transaction_id = m.transaction_id, "lacp marker answered");
                    }
                    Err(e) if crate::socket::is_link_down(&e) => {
                        debug!(interface = %self.config.interface, "link down, marker response not sent");
                    }
                    Err(e) => {
                        warn!(interface = %self.config.interface, error = %e, "failed to send marker response");
                    }
                }
            } else {
                debug!(interface = %self.config.interface, "marker rate limit hit, dropping");
            }
            return;
        }
        let decoded = packet::decode(bytes);
        // Dropped before touching any machine: a flood costs one decode.
        if decoded.is_err() && !matches!(decoded, Err(packet::PacketError::UnsupportedVersion(_))) {
            return;
        }
        if !self.rx_limiter.try_take(Instant::now()) {
            self.rx_dropped += 1;
            if self.rx_dropped == 1 {
                warn!(interface = %self.config.interface, "lacp receive rate limit hit, dropping");
            }
            return;
        }
        if self.rx_dropped > 0 {
            debug!(interface = %self.config.interface, dropped = self.rx_dropped, "lacp receive rate limit burst over");
            self.rx_dropped = 0;
        }
        let Ok(pdu) = decoded else {
            // Silent in the log (flood vector); counted, and rate-limited
            // above so a flood cannot spin selection.
            self.unsupported_version_pdus += 1;
            self.report();
            return;
        };
        // Our own system id on the wire: a looped link (the source-MAC filter
        // cannot catch members that keep their own MACs). Never a partner.
        if pdu.actor.system == self.config.actor_system_id {
            if self.loopback_logged {
                debug!(interface = %self.config.interface, "lacp loopback LACPDU ignored");
            } else {
                self.loopback_logged = true;
                warn!(interface = %self.config.interface, "lacp loopback detected, ignoring own LACPDUs");
            }
            return;
        }
        self.loopback_logged = false;
        let before = (self.receive_state, self.mux_state, self.partner);
        // update_Selected: a changed partner identity deselects the port at
        // once (mux leaves Collecting/Distributing); selection re-runs from
        // the fresh observation.
        if self
            .partner
            .is_some_and(|old| partner_identity(&old) != partner_identity(&pdu.actor))
        {
            let (ms, a) = mux_machine::step(
                self.mux_state,
                mux_machine::Event::PartnerStateChanged {
                    synchronized: false,
                    collecting: false,
                },
            );
            self.mux_state = ms;
            apply_mux_action(a, &mut self.wait_while_deadline);
        }
        // recordPDU match; an Individual partner has no tuple to match.
        let ours = actor_info(
            &self.config,
            self.number,
            actor_state_byte(
                self.receive_state,
                self.mux_state,
                self.config.rate,
                self.config.actor_active,
            ),
        );
        let matched = !pdu.actor.has_state(state_bit::AGGREGATION)
            || partner_matches_actor(&pdu.partner, &ours);
        if self.partner_view_matches && !matched {
            info!(interface = %self.config.interface, partner_system = ?pdu.actor.system, "lacp partner view mismatch");
        }
        self.partner_view_matches = matched;
        let mut recorded = pdu.actor;
        if !matched {
            recorded.state &= !state_bit::SYNCHRONIZATION;
        }
        self.partner = Some(recorded);
        let (rs, action) = receive_machine::step(
            self.receive_state,
            receive_machine::Event::LacpduReceived {
                we_advertise_short_timeout: self.config.rate == LacpRate::Fast,
            },
        );
        self.receive_state = rs;
        apply_receive_action(action, &mut self.current_while_deadline);
        let (ms, mux_action) = mux_machine::step(
            self.mux_state,
            mux_machine::Event::PartnerStateChanged {
                synchronized: matched && pdu.actor.has_state(state_bit::SYNCHRONIZATION),
                collecting: matched && pdu.actor.has_state(state_bit::COLLECTING),
            },
        );
        self.mux_state = ms;
        apply_mux_action(mux_action, &mut self.wait_while_deadline);
        if before == (self.receive_state, self.mux_state, self.partner) {
            debug!(interface = %self.config.interface, "lacp lacpdu received, unchanged");
        } else {
            info!(
                interface = %self.config.interface,
                receive_state = ?self.receive_state,
                mux_state = ?self.mux_state,
                partner_system = ?pdu.actor.system,
                partner_view_matches = matched,
                "lacp lacpdu received"
            );
        }
        self.tx.update_periodic(
            &self.config.interface,
            self.config.actor_active,
            self.receive_state,
            self.partner,
        );
        self.settle();
        self.tx
            .send_if_changed(sink, &self.config.interface, self.pdu());
    }
}

fn apply_receive_action(action: receive_machine::Action, current_while_deadline: &mut Instant) {
    match action {
        receive_machine::Action::StartCurrentWhileTimer(duration) => {
            *current_while_deadline = Instant::now() + duration.as_duration();
        }
        // `Defaulted` has no timer of its own — it waits indefinitely for a
        // fresh LACPDU (`Event::LacpduReceived`, handled separately below).
        // Without disabling the deadline here, the just-elapsed short timer
        // that triggered this very transition would immediately re-fire on
        // the next loop iteration.
        // `RecordDefault` (entering `Defaulted`) and `None` (`Defaulted`
        // re-expiring) both leave no live timer: `Defaulted` waits
        // indefinitely for a fresh LACPDU. Without disarming here, the
        // just-elapsed timer would re-fire on the next loop iteration.
        receive_machine::Action::RecordDefault | receive_machine::Action::None => {
            *current_while_deadline = far_future();
        }
    }
}

fn apply_mux_action(action: mux_machine::Action, wait_while_deadline: &mut Instant) {
    match action {
        mux_machine::Action::StartWaitWhileTimer => {
            *wait_while_deadline = Instant::now() + mux_machine::AGGREGATE_WAIT_TIME;
        }
        // `None` means nothing happened (e.g. a LACPDU arrived while still
        // `Waiting`): a pending wait must keep running.
        mux_machine::Action::None => {}
        // Every other action means the wait (if any) is over or moot. Leaving
        // the just-elapsed deadline in place would make the `sleep_until`
        // branch in `run` fire on every loop iteration — a hot loop that
        // floods the log and the wire.
        _ => {
            *wait_while_deadline = far_future();
        }
    }
}

#[allow(clippy::implicit_hasher, clippy::too_many_arguments)] // default hasher only; one call-site shape
fn report(
    observations: &Arc<Mutex<HashMap<String, PortObservation>>>,
    changed: &Arc<Notify>,
    interface: &str,
    actor_port: u16,
    receive_state: ReceiveState,
    mux_state: MuxState,
    partner: Option<PortInfo>,
    churn: &Churn,
    unsupported_version_pdus: u64,
) {
    let observation = PortObservation {
        receive_state,
        mux_state,
        actor_port,
        partner,
        actor_churn: churn.actor,
        partner_churn: churn.partner,
        unsupported_version_pdus,
    };
    let mut observations = observations.lock().unwrap();
    // Only signal on a real change: `aggregate.rs` reacts to every
    // notification by re-running Selection Logic and feeding verdicts back to
    // the ports, so a redundant signal is one turn of a potential feedback
    // loop.
    if observations.get(interface) == Some(&observation) {
        return;
    }
    observations.insert(interface.to_string(), observation);
    drop(observations);
    changed.notify_one();
}

/// Both Churn Detection machines (§6.4.17) with their timer deadlines.
struct Churn {
    interface: String,
    actor: ChurnState,
    partner: ChurnState,
    actor_deadline: Instant,
    partner_deadline: Instant,
    time: Duration,
}

impl Churn {
    fn new(interface: &str, time: Duration) -> Self {
        Self {
            interface: interface.to_string(),
            actor: ChurnState::NoChurn,
            partner: ChurnState::NoChurn,
            actor_deadline: far_future(),
            partner_deadline: far_future(),
            time,
        }
    }

    /// Re-evaluates both sides' Synchronization bit after any state change.
    fn eval(&mut self, mux_state: MuxState, partner: Option<PortInfo>) {
        let actor_sync = matches!(
            mux_state,
            MuxState::Attached | MuxState::Collecting | MuxState::Distributing
        );
        let partner_sync = partner.is_some_and(|p| p.has_state(state_bit::SYNCHRONIZATION));
        let sync = |in_sync| churn_machine::Event::Sync { in_sync };
        self.feed_actor(sync(actor_sync));
        self.feed_partner(sync(partner_sync));
    }

    fn expire_actor(&mut self) {
        self.feed_actor(churn_machine::Event::TimerExpired);
    }

    fn expire_partner(&mut self) {
        self.feed_partner(churn_machine::Event::TimerExpired);
    }

    fn feed_actor(&mut self, event: churn_machine::Event) {
        let before = self.actor;
        Self::feed(&mut self.actor, &mut self.actor_deadline, event, self.time);
        self.log("actor", before, self.actor);
    }

    fn feed_partner(&mut self, event: churn_machine::Event) {
        let before = self.partner;
        Self::feed(
            &mut self.partner,
            &mut self.partner_deadline,
            event,
            self.time,
        );
        self.log("partner", before, self.partner);
    }

    fn log(&self, side: &str, before: ChurnState, after: ChurnState) {
        if before != after {
            info!(interface = %self.interface, churn = ?after, "lacp {side} churn machine transitioned");
        }
    }

    fn feed(
        state: &mut ChurnState,
        deadline: &mut Instant,
        event: churn_machine::Event,
        time: Duration,
    ) {
        let (next, action) = churn_machine::step(*state, event);
        *state = next;
        match action {
            churn_machine::Action::StartTimer => *deadline = Instant::now() + time,
            // Only `None` after an expiry leaves an elapsed deadline armed
            // (a hot loop) — disarm on anything but a still-running timer.
            churn_machine::Action::StopTimer => *deadline = far_future(),
            churn_machine::Action::None => {
                if next != ChurnState::Monitor {
                    *deadline = far_future();
                }
            }
        }
    }
}

/// This port's own advertised `Actor_State` byte — see 802.1AX Table 6-4.
/// `Activity` follows the configured `lacp-mode`; `Aggregation` is always set
/// (our own bit stays set: only configured member ports run LACP at all, so
/// we never declare ourselves Individual — see `docs/internals/lacp.md`);
/// `Timeout` is the aggregate's `LacpRate` (set = Fast, asking the partner
/// to send every second); the rest reflect the live state machines.
fn actor_state_byte(
    receive_state: ReceiveState,
    mux_state: MuxState,
    rate: LacpRate,
    active: bool,
) -> u8 {
    let mut state = state_bit::AGGREGATION;
    if active {
        state |= state_bit::ACTIVITY;
    }
    if rate == LacpRate::Fast {
        state |= state_bit::TIMEOUT;
    }
    if matches!(
        mux_state,
        MuxState::Attached | MuxState::Collecting | MuxState::Distributing
    ) {
        state |= state_bit::SYNCHRONIZATION;
    }
    if matches!(mux_state, MuxState::Collecting | MuxState::Distributing) {
        state |= state_bit::COLLECTING;
    }
    if mux_state == MuxState::Distributing {
        state |= state_bit::DISTRIBUTING;
    }
    match receive_state {
        ReceiveState::Defaulted => state |= state_bit::DEFAULTED,
        ReceiveState::Expired => state |= state_bit::EXPIRED,
        ReceiveState::Current => {}
    }
    state
}

/// Our Actor information block: shared by the PDU we send and by
/// [`partner_matches_actor`], so they cannot drift.
fn actor_info(config: &LinkConfig, port_number: u16, state: u8) -> PortInfo {
    PortInfo {
        system_priority: config.actor_system_priority,
        system: config.actor_system_id,
        key: config.actor_key,
        port_priority: config.actor_port_priority,
        port: port_number,
        state,
    }
}

/// 802.1AX §6.4.9 recordPDU "match": does the partner's view of us (the
/// Partner block of its LACPDU) describe our current Actor identity? Same
/// fields as Linux `bond_3ad.c` `__record_pdu`/`__choose_matched`: port,
/// port priority, system, system priority, key and the Aggregation bit.
fn partner_matches_actor(pdu_partner: &PortInfo, our_actor: &PortInfo) -> bool {
    pdu_partner.port == our_actor.port
        && pdu_partner.port_priority == our_actor.port_priority
        && pdu_partner.system == our_actor.system
        && pdu_partner.system_priority == our_actor.system_priority
        && pdu_partner.key == our_actor.key
        && pdu_partner.has_state(state_bit::AGGREGATION)
            == our_actor.has_state(state_bit::AGGREGATION)
}

/// §6.4.9 `update_Selected`: the identity fields whose change means the
/// partner is no longer the one we selected against.
fn partner_identity(p: &PortInfo) -> (u16, u16, [u8; 6], u16, u16, bool) {
    (
        p.port,
        p.port_priority,
        p.system,
        p.system_priority,
        p.key,
        p.has_state(state_bit::AGGREGATION),
    )
}

fn build_pdu(
    config: &LinkConfig,
    port_number: u16,
    receive_state: ReceiveState,
    mux_state: MuxState,
    partner: Option<PortInfo>,
) -> Lacpdu {
    let actor = actor_info(
        config,
        port_number,
        actor_state_byte(receive_state, mux_state, config.rate, config.actor_active),
    );
    // No (or a given-up) partner: advertise 802.1AX's administrative default.
    let partner = partner.unwrap_or(PortInfo::ADMINISTRATIVE_DEFAULT);
    Lacpdu {
        actor,
        partner,
        collector_max_delay: 0,
    }
}

fn send_lacpdu(socket: &dyn FrameSink, interface: &str, pdu: &Lacpdu) {
    match socket.send(&packet::encode(pdu)) {
        Ok(()) => {}
        // Expected while the link is down; the fast periodic send retries.
        Err(e) if crate::socket::is_link_down(&e) => {
            debug!(interface = %interface, "link down, lacpdu not sent");
        }
        Err(e) => warn!(interface = %interface, error = %e, "failed to send lacpdu"),
    }
}

/// 802.1AX §6.4.16: at most 3 LACPDUs per `Fast_Periodic_Time`, whatever the
/// NTT events. A fixed window refilled once per second.
const MAX_TX_PER_WINDOW: u8 = 3;
/// Marker Responses get their own budget so a Marker flood can't starve
/// LACPDUs; 3 + 5 stays under 802.3 Annex 57A's 10 slow-protocol frames/s.
const MAX_MARKER_PER_WINDOW: u8 = 5;
/// Inbound LACPDUs per `TX_WINDOW`; LACPDUs only (Markers have their own limiter).
const MAX_RX_PER_WINDOW: u8 = 10;
const TX_WINDOW: Duration = Duration::from_secs(1);

struct TxLimiter {
    max: u8,
    tokens: u8,
    window_start: Instant,
}

impl TxLimiter {
    fn new(now: Instant, max: u8) -> Self {
        Self {
            max,
            tokens: max,
            window_start: now,
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= TX_WINDOW {
            self.tokens = self.max;
            self.window_start = now;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn next_refill(&self) -> Instant {
        self.window_start + TX_WINDOW
    }
}

/// The Transmit machine's state: what we last sent (NTT), the rate limiter,
/// and when the periodic timer next fires.
struct TxState {
    last_sent: Option<Lacpdu>,
    limiter: TxLimiter,
    next_periodic_send: Instant,
    /// 802.1AX `NO_PERIODIC`: both ends Passive. Nothing is transmitted at all
    /// (periodic or event-driven) until a partner LACPDU says it is Active.
    no_periodic: bool,
}

fn needs_transmit(last_sent: Option<&Lacpdu>, pdu: &Lacpdu) -> bool {
    last_sent != Some(pdu)
}

impl TxState {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            last_sent: None,
            limiter: TxLimiter::new(now, MAX_TX_PER_WINDOW),
            // First send is immediate.
            next_periodic_send: now,
            no_periodic: false,
        }
    }

    /// Re-evaluates `NO_PERIODIC` after anything that changes the partner
    /// view or receive state; arms the first send on leaving it.
    fn update_periodic(
        &mut self,
        interface: &str,
        actor_active: bool,
        receive_state: ReceiveState,
        partner: Option<PortInfo>,
    ) {
        let interval = interval_for(
            receive_state,
            actor_active,
            partner.is_some_and(|p| p.has_state(state_bit::ACTIVITY)),
            partner.is_some_and(|p| p.has_state(state_bit::TIMEOUT)),
        );
        let no_periodic = interval.is_none();
        if no_periodic {
            self.next_periodic_send = far_future();
        } else if self.no_periodic {
            self.next_periodic_send = Instant::now();
        }
        if no_periodic != self.no_periodic {
            self.no_periodic = no_periodic;
            info!(interface = %interface, no_periodic, "lacp periodic transmission machine transitioned");
        }
    }

    /// Sends `pdu` if the limiter allows. A denied send leaves `last_sent`
    /// untouched (so the change still counts as unsent) and pulls the
    /// periodic timer forward to the next refill, which rebuilds the PDU from
    /// live state — so a suppressed change is delayed, never lost.
    fn transmit(&mut self, socket: &dyn FrameSink, interface: &str, pdu: Lacpdu) {
        if self.no_periodic {
            return;
        }
        if self.limiter.try_take(Instant::now()) {
            send_lacpdu(socket, interface, &pdu);
            self.last_sent = Some(pdu);
        } else {
            debug!(interface = %interface, "lacpdu rate limit hit, deferring");
            self.next_periodic_send = self.limiter.next_refill();
        }
    }

    /// 802.1AX's NTT ("need to transmit"): an event-driven send happens only
    /// if what we'd advertise differs from what we last sent. Replying to
    /// every received LACPDU unconditionally made two peers ping-pong at wire
    /// speed; with this they settle as soon as their states agree, and the
    /// periodic timer alone keeps the partner's `Current_While_Timer` alive.
    fn send_if_changed(&mut self, socket: &dyn FrameSink, interface: &str, pdu: Lacpdu) {
        if needs_transmit(self.last_sent.as_ref(), &pdu) {
            self.transmit(socket, interface, pdu);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_observation_does_not_notify() {
        use futures::FutureExt;

        let observations = Arc::new(Mutex::new(HashMap::new()));
        let changed = Arc::new(Notify::new());
        let report_once = || {
            report(
                &observations,
                &changed,
                "eth1",
                1,
                ReceiveState::Expired,
                MuxState::Detached,
                None,
                &Churn::new("eth1", Duration::from_secs(60)),
                0,
            );
        };

        report_once();
        assert!(
            changed.notified().now_or_never().is_some(),
            "first report notifies"
        );

        report_once();
        assert!(
            changed.notified().now_or_never().is_none(),
            "an identical report must not notify"
        );
    }

    #[test]
    fn limiter_allows_three_per_window() {
        let t0 = Instant::now();
        let mut l = TxLimiter::new(t0, MAX_TX_PER_WINDOW);
        assert!((0..3).all(|_| l.try_take(t0)));
        assert!(!l.try_take(t0 + Duration::from_millis(999)));
        assert_eq!(l.next_refill(), t0 + TX_WINDOW);
        assert!(l.try_take(t0 + TX_WINDOW));
    }

    /// Regression: a LACPDU arriving while `Waiting` yields `Action::None`;
    /// disarming the wait timer on it meant the port never left `Waiting`.
    #[test]
    fn a_no_op_event_leaves_a_pending_wait_armed() {
        let (state, action) = mux_machine::step(
            MuxState::Waiting,
            mux_machine::Event::PartnerStateChanged {
                synchronized: false,
                collecting: false,
            },
        );
        assert_eq!(state, MuxState::Waiting);
        let pending = Instant::now() + Duration::from_secs(2);
        let mut deadline = pending;
        apply_mux_action(action, &mut deadline);
        assert_eq!(deadline, pending);
    }

    #[test]
    fn fast_rate_sets_the_advertised_timeout_bit_and_slow_clears_it() {
        let state = |rate| actor_state_byte(ReceiveState::Current, MuxState::Detached, rate, true);
        assert_ne!(state(LacpRate::Fast) & state_bit::TIMEOUT, 0);
        assert_eq!(state(LacpRate::Slow) & state_bit::TIMEOUT, 0);
    }

    #[test]
    fn passive_clears_the_activity_bit() {
        let state = |active| {
            actor_state_byte(
                ReceiveState::Current,
                MuxState::Detached,
                LacpRate::Slow,
                active,
            )
        };
        assert_ne!(state(true) & state_bit::ACTIVITY, 0);
        assert_eq!(state(false) & state_bit::ACTIVITY, 0);
    }

    #[test]
    fn identical_advertisement_is_not_retransmitted() {
        let config_pdu = |state: u8| Lacpdu {
            actor: PortInfo {
                system_priority: 1,
                system: [1; 6],
                key: 1,
                port_priority: 1,
                port: 1,
                state,
            },
            partner: PortInfo {
                system_priority: 0,
                system: [0; 6],
                key: 0,
                port_priority: 0,
                port: 0,
                state: 0,
            },
            collector_max_delay: 0,
        };
        let sent = config_pdu(1);
        assert!(needs_transmit(None, &sent), "first send goes out");
        assert!(
            !needs_transmit(Some(&sent), &config_pdu(1)),
            "unchanged: no reply"
        );
        assert!(
            needs_transmit(Some(&sent), &config_pdu(9)),
            "changed state goes out"
        );
    }

    fn elapsed() -> Instant {
        Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("monotonic clock is more than 1s past its origin")
    }

    /// The regression guard for a real hot loop: `run`'s `sleep_until` arms
    /// resolve immediately for a deadline in the past, so if handling an
    /// elapsed timer leaves that deadline elapsed, the loop spins — flooding
    /// the log and the wire (it once grew `nos-logd` to ~14 GB). After
    /// handling a timer-expiry event, its deadline must be in the future.
    #[test]
    fn handling_wait_while_expiry_disarms_the_timer() {
        let (state, action) =
            mux_machine::step(MuxState::Waiting, mux_machine::Event::WaitWhileTimerExpired);
        assert_eq!(state, MuxState::Attached);
        let mut deadline = elapsed();
        apply_mux_action(action, &mut deadline);
        assert!(deadline > Instant::now());
    }

    #[test]
    fn handling_current_while_expiry_never_leaves_an_elapsed_deadline() {
        for state in [
            ReceiveState::Expired,
            ReceiveState::Current,
            ReceiveState::Defaulted,
        ] {
            let (_, action) =
                receive_machine::step(state, receive_machine::Event::CurrentWhileTimerExpired);
            let mut deadline = elapsed();
            apply_receive_action(action, &mut deadline);
            assert!(
                deadline > Instant::now(),
                "{state:?} left an elapsed deadline"
            );
        }
    }

    #[test]
    fn every_mux_transition_other_than_starting_the_wait_disarms_it() {
        for state in [
            MuxState::Detached,
            MuxState::Waiting,
            MuxState::Attached,
            MuxState::Collecting,
            MuxState::Distributing,
        ] {
            for event in [
                mux_machine::Event::WaitWhileTimerExpired,
                mux_machine::Event::SelectionChanged { selected: false },
                mux_machine::Event::PartnerStateChanged {
                    synchronized: true,
                    collecting: true,
                },
                mux_machine::Event::PartnerStateChanged {
                    synchronized: false,
                    collecting: false,
                },
            ] {
                let (_, action) = mux_machine::step(state, event);
                if action == mux_machine::Action::None {
                    continue;
                }
                let mut deadline = elapsed();
                apply_mux_action(action, &mut deadline);
                assert!(
                    deadline > Instant::now(),
                    "{state:?} + {event:?} left an elapsed wait-while deadline"
                );
            }
        }
    }
}

#[cfg(test)]
mod port_tests;

#[cfg(test)]
mod churn_tests {
    use super::*;

    #[test]
    fn expiry_never_leaves_an_elapsed_deadline_and_sync_recovers() {
        let mut c = Churn::new("eth1", Duration::from_millis(1));
        c.eval(MuxState::Detached, None);
        assert_eq!(
            (c.actor, c.partner),
            (ChurnState::Monitor, ChurnState::Monitor)
        );
        c.expire_actor();
        c.expire_partner();
        assert_eq!((c.actor, c.partner), (ChurnState::Churn, ChurnState::Churn));
        assert!(c.actor_deadline > Instant::now() && c.partner_deadline > Instant::now());
        c.eval(MuxState::Attached, None);
        assert_eq!(c.actor, ChurnState::NoChurn);
        assert_eq!(c.partner, ChurnState::Churn, "no partner sync yet");
    }
}
