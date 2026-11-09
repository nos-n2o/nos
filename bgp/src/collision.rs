//! RFC 4271 §6.8 connection collision resolution.
//!
//! Both an actively-initiated (outbound) and passively-accepted (inbound)
//! TCP connection for the same peer are allowed to proceed through OPEN
//! exchange — each side needs the other's BGP Identifier before a winner can
//! be decided. The rule implemented here (matching how production BGP
//! stacks apply §6.8, not a literal "first past `OpenConfirm` wins" reading,
//! which would be timing-dependent):
//!
//! - local BGP Identifier > remote BGP Identifier: keep the connection this
//!   system initiated (active); close the accepted (passive) one.
//! - local BGP Identifier < remote BGP Identifier: keep the connection the
//!   peer initiated (passive); close the one this system initiated (active).
//! - equal (duplicate/misconfigured router-id): keep whichever reached this
//!   decision point first, log a warning — RFC 4271 doesn't resolve true
//!   ties.
//! - Established-precedence override: a connection already `Established`
//!   always beats a later collision, regardless of ID comparison.
//!
//! The loser is torn down with `NOTIFICATION(Cease, ConnectionCollisionResolution)`,
//! signaled via its `Notify` handle so its own `fsm::run` task can send that
//! notification itself before closing — never a bare socket drop.
//!
//! RFC 4724 §4.2 overrides the Established-precedence rule for a peer that
//! advertised graceful restart: a connection started *after* the session
//! came up means the peer restarted without us seeing the old connection
//! close, so the new one replaces the old (closed with no NOTIFICATION, its
//! routes kept as stale). One started before it came up is an ordinary
//! collision and still loses.

use std::cmp::Ordering;
use std::net::Ipv4Addr;
use std::sync::Arc;

use std::time::Duration;

use tokio::sync::{mpsc, watch, Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::warn;

use crate::session::{ResolvedAuth, ResolvedPeer};
use crate::status::{PeerStatus, StatusHandle};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Active,
    Passive,
}

impl Role {
    fn other(self) -> Role {
        match self {
            Role::Active => Role::Passive,
            Role::Passive => Role::Active,
        }
    }
}

/// An operator-triggered action against a peer's live session, delivered
/// through `PeerSlot`'s command channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmCommand {
    /// `clear bgp <instance> <peer> soft-in` — ask this peer to resend its
    /// Adj-RIB-Out to us, for every address family this session negotiated.
    SendRouteRefresh,
    /// Send a Cease NOTIFICATION with this subcode and data (already
    /// encoded by the caller, e.g. an RFC 9003 shutdown communication or the
    /// RFC 4486 §4 maximum-prefix AFI/SAFI/limit) and close.
    Cease {
        subcode: crate::message::CeaseSubcode,
        data: bytes::Bytes,
    },
    /// RFC 9384: BFD declared this peer's path down. `flush` (BFD runs
    /// independently of the control plane at both ends, RFC 5882 §4.3.1)
    /// sends Cease/10 wrapped in a Hard Reset, so the peer flushes our routes
    /// instead of keeping them stale; otherwise a plain Cease/10 and the
    /// peer's graceful restart applies as for any NOTIFICATION.
    BfdDown { flush: bool },
    /// Apply a TCP-AO key-list change to this live session's socket (see
    /// `session::ao_delta`); on failure the session resets with Cease/Other
    /// Configuration Change and the reconnect uses `PeerSlot::auth`.
    UpdateAo(crate::session::AoDelta),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    PostOpen,
    Established,
}

struct ConnectionRecord {
    stage: Stage,
    remote_bgp_id: Ipv4Addr,
    cease: Arc<Notify>,
    /// Set by `mark_established`: when, whether the peer advertised
    /// graceful restart, and how to tell this connection it was replaced.
    established: Option<(Instant, bool, Arc<Notify>)>,
}

impl ConnectionRecord {
    /// RFC 4724 §4.2: a connection that began at `began` replaces this one.
    fn replaced_by(&self, began: Option<Instant>) -> Option<Arc<Notify>> {
        match (&self.established, began) {
            (Some((at, true, replaced)), Some(began)) if began > *at => Some(replaced.clone()),
            _ => None,
        }
    }
}

/// How long a replacing connection waits for the one it replaces to end.
const REPLACE_GRACE: Duration = Duration::from_secs(1);

#[derive(Default)]
struct RoleState {
    /// Set while a connection for this role is being processed (from
    /// accept/connect success through the FSM ending), independent of
    /// whether it has received an OPEN yet — guards the degenerate
    /// double-inbound case, distinct from real active/passive collision.
    occupied: bool,
    /// When `begin` reserved it.
    began: Option<Instant>,
    connection: Option<ConnectionRecord>,
}

#[derive(Default)]
struct CollisionState {
    active: RoleState,
    passive: RoleState,
}

pub enum Decision {
    Proceed,
    Lose,
}

/// One configured peer's collision-arbitration state, shared between its
/// active-connect task and the shared passive listener's accept handler.
/// Also the canonical owner of `status` (see `crate::status`) — since both
/// an active and a passive connection can be in flight for the same peer at
/// once but only one becomes canonical, `PeerSlot` (already the single
/// per-peer arbitration point) is the natural place for `fsm::run` to report
/// into, rather than either individual connection owning it.
pub struct PeerSlot {
    pub peer: ResolvedPeer,
    /// `peer.auth`, but replaceable: a TCP-AO key-list change is applied in
    /// place, so every new connection must start from the current keys.
    auth: std::sync::Mutex<Option<ResolvedAuth>>,
    state: Mutex<CollisionState>,
    pub status: StatusHandle,
    command_tx: mpsc::UnboundedSender<FsmCommand>,
    /// Locked fresh on every poll by whichever `fsm::run` task currently owns
    /// this peer's `Established` session — see `recv_command`. Created once
    /// here (peer lifetime, not per-connection), so no take/hand-off dance is
    /// needed across a peer's active/passive reconnects.
    command_rx: Mutex<mpsc::UnboundedReceiver<FsmCommand>>,
    /// The currently-running passively-accepted session's task, if any.
    ///
    /// The active side's task is owned by `SessionManager::peer_tasks`, but a
    /// passive session is spawned per accepted connection
    /// (`SessionManager::handle_inbound`) and would otherwise be tracked
    /// nowhere — so reconciliation had no way to stop it, and a peer whose
    /// config changed kept serving an established *passive* session with the
    /// `ResolvedPeer` it was accepted with: stale policies, auth and timers,
    /// indefinitely. Parked here because the slot is already the one
    /// per-peer object shared across both roles.
    passive_task: Mutex<Option<JoinHandle<()>>>,
    /// Set when the peer tripped its RFC 4486 maximum-prefix limit: when, and
    /// the `restart_interval` (seconds) after which it may reconnect — `0`
    /// holds it until `clear_max_prefix`. A shut/no-shut or config change
    /// replaces the whole slot, which releases it too.
    max_prefix_hold: std::sync::Mutex<Option<(Instant, u16)>>,
    /// Set once the slot is being taken down (shutdown or peer removal):
    /// `active_connect_loop` must not redial during the Cease grace, or the
    /// fresh session ends in a bare abort instead of the Cease (#444, #455).
    stopping: std::sync::atomic::AtomicBool,
    /// `peer.import_policy`, but replaceable: a policy change on a peer with
    /// soft reconfiguration inbound is applied in place (#859), so the live
    /// session and every new one read the current policy from here.
    import_policy: std::sync::Mutex<Arc<nos_rpl::CompiledPolicy>>,
    /// The EVPN and Flowspec import policies, replaceable like `import_policy`.
    evpn_import: std::sync::Mutex<Option<Arc<nos_rpl::CompiledPolicy>>>,
    flowspec_import: std::sync::Mutex<Option<Arc<nos_rpl::CompiledPolicy>>>,
    /// `peer.soft_reconfiguration_inbound`, replaceable for the same reason.
    soft_reconfig: std::sync::atomic::AtomicBool,
    /// What the established session negotiated: bit 0 RFC 2918 Route Refresh,
    /// bit 1 RFC 7313 Enhanced Route Refresh; 0 outside `Established`.
    refresh_caps: std::sync::atomic::AtomicU8,
    /// The running re-evaluation pass, if any (see `reeval_begin`).
    reeval: std::sync::Mutex<ReevalState>,
}

/// Why a `soft-in` got no counts: a policy change started a newer pass, the
/// session went down, or the pass tripped a maximum-prefix limit.
pub const REEVAL_SUPERSEDED: &str = "import policy changed during re-evaluation";
pub const REEVAL_SESSION_DOWN: &str = "session down";
pub const REEVAL_MAX_PREFIX: &str = "maximum prefix exceeded during re-evaluation";

/// Answer to a `soft-in` waiting on a pass: the per-family counts, or why it
/// ended early (see `REEVAL_SUPERSEDED` and friends).
pub type ReevalResult = Result<Vec<nos_proto::FamilyReeval>, String>;

#[derive(Default)]
struct ReevalState {
    generation: u64,
    running: bool,
    waiters: Vec<tokio::sync::oneshot::Sender<ReevalResult>>,
}

impl PeerSlot {
    pub fn new(peer: ResolvedPeer) -> Arc<Self> {
        let (status, _) = watch::channel(PeerStatus::default());
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            auth: std::sync::Mutex::new(peer.auth.clone()),
            state: Mutex::new(CollisionState::default()),
            status,
            command_tx,
            command_rx: Mutex::new(command_rx),
            passive_task: Mutex::new(None),
            max_prefix_hold: std::sync::Mutex::new(None),
            stopping: std::sync::atomic::AtomicBool::new(false),
            import_policy: std::sync::Mutex::new(peer.import_policy.clone()),
            evpn_import: std::sync::Mutex::new(peer.evpn_import_policy.clone()),
            flowspec_import: std::sync::Mutex::new(peer.flowspec_import_policy.clone()),
            soft_reconfig: std::sync::atomic::AtomicBool::new(peer.soft_reconfiguration_inbound),
            refresh_caps: std::sync::atomic::AtomicU8::new(0),
            reeval: std::sync::Mutex::new(ReevalState::default()),
            peer,
        })
    }

    /// Quiesces the slot: no further outbound dial (see `stopping`).
    pub fn stop(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The peer's current auth (see the `auth` field).
    pub fn auth(&self) -> Option<ResolvedAuth> {
        self.auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn set_auth(&self, auth: Option<ResolvedAuth>) {
        *self
            .auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = auth;
    }

    /// The peer's current import policy (see the `import_policy` field).
    pub fn import_policy(&self) -> Arc<nos_rpl::CompiledPolicy> {
        self.import_policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The peer's current EVPN import policy (`None` accepts all).
    pub fn evpn_import_policy(&self) -> Option<Arc<nos_rpl::CompiledPolicy>> {
        self.evpn_import
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The peer's current Flowspec import policy (`None` accepts all).
    pub fn flowspec_import_policy(&self) -> Option<Arc<nos_rpl::CompiledPolicy>> {
        self.flowspec_import
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// All three import policies, for a re-evaluation pass.
    pub fn import_policies(&self) -> crate::rib::ImportPolicies {
        crate::rib::ImportPolicies {
            unicast: self.import_policy(),
            evpn: self.evpn_import_policy(),
            flowspec: self.flowspec_import_policy(),
        }
    }

    /// Replaces the EVPN and Flowspec import policies (an in-place change).
    pub fn set_family_import_policies(
        &self,
        evpn: Option<Arc<nos_rpl::CompiledPolicy>>,
        flowspec: Option<Arc<nos_rpl::CompiledPolicy>>,
    ) {
        *self
            .evpn_import
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = evpn;
        *self
            .flowspec_import
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = flowspec;
    }

    pub fn set_import_policy(&self, policy: Arc<nos_rpl::CompiledPolicy>) {
        *self
            .import_policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = policy;
    }

    pub fn soft_reconfig(&self) -> bool {
        self.soft_reconfig
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_soft_reconfig(&self, on: bool) {
        self.soft_reconfig
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn route_refresh_negotiated(&self) -> bool {
        self.refresh_caps.load(std::sync::atomic::Ordering::Relaxed) & 1 != 0
    }

    pub fn enhanced_refresh_negotiated(&self) -> bool {
        self.refresh_caps.load(std::sync::atomic::Ordering::Relaxed) & 2 != 0
    }

    pub fn set_refresh_caps(&self, route_refresh: bool, enhanced: bool) {
        self.refresh_caps.store(
            u8::from(route_refresh) | (u8::from(enhanced) << 1),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn reeval_state(&self) -> std::sync::MutexGuard<'_, ReevalState> {
        self.reeval
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers a re-evaluation pass. `supersede` (a policy change or flag
    /// enable) starts a new generation and answers the old waiters
    /// `REEVAL_SUPERSEDED`; otherwise (`soft-in`) a running pass is joined: the
    /// waiter is queued and `None` returned. `Some(generation)`: the caller
    /// must run the pass.
    pub fn reeval_begin(
        &self,
        supersede: bool,
        waiter: Option<tokio::sync::oneshot::Sender<ReevalResult>>,
    ) -> Option<u64> {
        let mut st = self.reeval_state();
        if supersede {
            st.generation += 1;
            for w in std::mem::take(&mut st.waiters) {
                let _ = w.send(Err(REEVAL_SUPERSEDED.into()));
            }
        } else if st.running {
            st.waiters.extend(waiter);
            return None;
        }
        st.running = true;
        st.waiters.extend(waiter);
        Some(st.generation)
    }

    /// Whether pass `generation` is still the current one.
    pub fn reeval_current(&self, generation: u64) -> bool {
        self.reeval_state().generation == generation
    }

    /// Ends pass `generation`, answering its waiters; a no-op if superseded.
    pub fn reeval_finish(&self, generation: u64, result: &ReevalResult) {
        let mut st = self.reeval_state();
        if st.generation != generation {
            return;
        }
        st.running = false;
        for w in std::mem::take(&mut st.waiters) {
            let _ = w.send(result.clone());
        }
    }

    /// Records the task running this peer's passively-accepted session,
    /// replacing (and aborting) any previous one.
    pub async fn set_passive_task(&self, task: JoinHandle<()>) {
        let guarded = self.passive_task.lock().await.replace(task);
        if let Some(previous) = guarded {
            previous.abort();
        }
    }

    /// Stops this peer's passively-accepted session, if one is running —
    /// called when the peer is being torn down or respawned with a changed
    /// `ResolvedPeer`.
    pub async fn stop_passive(&self) {
        let guarded = self.passive_task.lock().await.take();
        if let Some(task) = guarded {
            task.abort();
        }
    }

    /// Holds the peer down after a maximum-prefix trip (see `max_prefix_hold`).
    pub fn trip_max_prefix(&self, restart_interval: u16) {
        *self.hold() = Some((Instant::now(), restart_interval));
    }

    /// Releases a maximum-prefix hold (`clear bgp <instance> <peer>`).
    pub fn clear_max_prefix(&self) {
        *self.hold() = None;
    }

    /// Whether the peer is held down by its maximum-prefix limit: no session
    /// is dialed or accepted while it is.
    pub fn max_prefix_held(&self) -> bool {
        match *self.hold() {
            None => false,
            Some((_, 0)) => true,
            Some((at, secs)) => at.elapsed() < Duration::from_secs(u64::from(secs)),
        }
    }

    fn hold(&self) -> std::sync::MutexGuard<'_, Option<(Instant, u16)>> {
        self.max_prefix_hold
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A snapshot receiver for `session::SessionManager::peer_summaries` to
    /// read the current status from.
    pub fn status_receiver(&self) -> watch::Receiver<PeerStatus> {
        self.status.subscribe()
    }

    /// Delivers an operator command to this peer's live session. `false` if
    /// no `fsm::run` task is around to receive it (channel closed).
    pub fn send_command(&self, cmd: FsmCommand) -> bool {
        self.command_tx.send(cmd).is_ok()
    }

    /// Waits for the next operator command. Callers must only poll this while
    /// their own connection is `Established` (e.g. a `tokio::select!` guard)
    /// — collision resolution always happens before either side reaches
    /// `Established`, so gating on it guarantees only the one canonical
    /// session ever locks this shared receiver, never a connection that's
    /// about to lose (or has lost) the collision.
    pub async fn recv_command(&self) -> Option<FsmCommand> {
        self.command_rx.lock().await.recv().await
    }

    /// Whether this peer already has an `Established` session, in either
    /// role. `active_connect_loop` checks this before dialing out again on
    /// its retry timer — without it, a stable session held open by the
    /// passive side would still see a redundant outbound connect attempt,
    /// and thus a real (harmlessly-resolved-by-precedence, but pointless)
    /// collision, every `CONNECT_RETRY_TIME`.
    pub async fn is_established(&self) -> bool {
        let state = self.state.lock().await;
        let is_established = |role: &RoleState| {
            matches!(
                role.connection,
                Some(ConnectionRecord {
                    stage: Stage::Established,
                    ..
                })
            )
        };
        is_established(&state.active) || is_established(&state.passive)
    }

    /// Reserves this role's slot. `false` means a connection for this same
    /// role is already being processed (e.g. a second inbound connection
    /// arriving before the first finished) — the caller must reject the new
    /// connection outright without engaging the FSM.
    ///
    /// RFC 4724 §4.2: when that connection is an `Established` session with
    /// a peer that advertised graceful restart, the new one replaces it
    /// instead (see the module doc), once it has ended.
    pub async fn begin(&self, role: Role) -> bool {
        let replaced = {
            let mut state = self.state.lock().await;
            let this = role_state_mut(&mut state, role);
            if !this.occupied {
                this.occupied = true;
                this.began = Some(Instant::now());
                return true;
            }
            match this
                .connection
                .as_ref()
                .and_then(|c| c.replaced_by(Some(Instant::now())))
            {
                Some(replaced) => replaced,
                None => return false,
            }
        };
        replaced.notify_one();
        if !self.wait_cleared(role).await {
            return false;
        }
        let mut state = self.state.lock().await;
        let this = role_state_mut(&mut state, role);
        if this.occupied {
            return false;
        }
        this.occupied = true;
        this.began = Some(Instant::now());
        true
    }

    /// Waits (up to `REPLACE_GRACE`) for `role`'s connection to end; `true`
    /// once it has.
    async fn wait_cleared(&self, role: Role) -> bool {
        tokio::time::timeout(REPLACE_GRACE, async {
            while role_state_mut(&mut *self.state.lock().await, role).occupied {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .is_ok()
    }

    /// Called once this connection has received a structurally-valid OPEN,
    /// just before its FSM would otherwise commit to `OpenConfirm`. Records
    /// this connection and, if the other role already has one, resolves the
    /// collision per RFC 4271 §6.8 — notifying the loser's `cease` handle
    /// and dropping its record when this side wins. `local_router_id` is
    /// supplied by the caller (read fresh from `SessionManager`'s current
    /// config at connect/accept time) rather than stored on the slot, so a
    /// router-id config change is picked up by the next connection attempt
    /// without needing to recreate the slot.
    ///
    /// `peer_restarting`: this OPEN's graceful restart capability has the R
    /// bit — required for it to replace an `Established` session in the
    /// other role (RFC 4724 §4.2). Without it, a connection in the other role
    /// is the far side of an ordinary collision race (dialed just before its
    /// own side came up), which must not tear the session down.
    pub async fn on_open(
        &self,
        role: Role,
        local_router_id: Ipv4Addr,
        remote_bgp_id: Ipv4Addr,
        cease: Arc<Notify>,
        peer_restarting: bool,
    ) -> Decision {
        let mut state = self.state.lock().await;
        let (this, other) = role_states_mut(&mut state, role);
        this.connection = Some(ConnectionRecord {
            stage: Stage::PostOpen,
            remote_bgp_id,
            cease,
            established: None,
        });

        let Some(other_conn) = other.connection.take() else {
            return Decision::Proceed;
        };

        if other_conn.stage == Stage::Established {
            if let Some(replaced) = other_conn
                .replaced_by(this.began)
                .filter(|_| peer_restarting)
            {
                // RFC 4724 §4.2: the peer restarted; the old session goes
                // (its routes kept as stale) before this one registers.
                other.connection = Some(other_conn);
                replaced.notify_one();
                drop(state);
                if self.wait_cleared(role.other()).await {
                    return Decision::Proceed;
                }
                let mut state = self.state.lock().await;
                role_state_mut(&mut state, role).connection = None;
                return Decision::Lose;
            }
            this.connection = None;
            other.connection = Some(other_conn);
            return Decision::Lose;
        }

        match collision_winner(local_router_id, other_conn.remote_bgp_id, role) {
            Decision::Proceed => {
                other_conn.cease.notify_one();
                Decision::Proceed
            }
            Decision::Lose => {
                this.connection = None;
                other.connection = Some(other_conn);
                Decision::Lose
            }
        }
    }

    /// `gr_capable`: the peer advertised graceful restart (and it's on
    /// here), which lets a later connection replace this one (RFC 4724
    /// §4.2), signalled through `replaced`.
    ///
    /// Returns `false` when this connection's record is gone: the other role
    /// won the §6.8 collision (`on_open` took the record and signalled
    /// `cease`) while this one was already on its way to `Established`, so
    /// `select!` handed the KEEPALIVE to the FSM before the `cease` permit.
    /// The caller must then not register with the RIB (#965): `BgpRib` is
    /// keyed by peer address, and the winner owns that entry. The check and
    /// the winner's `on_open` share the state lock, so exactly one of
    /// "loser lands in `Established`" and "winner is known" happens first.
    pub async fn mark_established(
        &self,
        role: Role,
        gr_capable: bool,
        replaced: Arc<Notify>,
    ) -> bool {
        let mut state = self.state.lock().await;
        let Some(conn) = role_state_mut(&mut state, role).connection.as_mut() else {
            return false;
        };
        conn.stage = Stage::Established;
        conn.established = Some((Instant::now(), gr_capable, replaced));
        true
    }

    pub async fn clear(&self, role: Role) {
        let mut state = self.state.lock().await;
        let this = role_state_mut(&mut state, role);
        this.occupied = false;
        this.began = None;
        this.connection = None;
    }
}

fn role_state_mut(state: &mut CollisionState, role: Role) -> &mut RoleState {
    match role {
        Role::Active => &mut state.active,
        Role::Passive => &mut state.passive,
    }
}

fn role_states_mut(state: &mut CollisionState, role: Role) -> (&mut RoleState, &mut RoleState) {
    match role {
        Role::Active => (&mut state.active, &mut state.passive),
        Role::Passive => (&mut state.passive, &mut state.active),
    }
}

/// The actual §6.8 comparison. `role` is the side whose `on_open` call
/// triggered this decision — i.e. the *later* of the two connections to
/// receive its OPEN, since the earlier one already proceeded trivially (the
/// other role had no record yet).
fn collision_winner(local_id: Ipv4Addr, remote_id: Ipv4Addr, role: Role) -> Decision {
    match local_id.cmp(&remote_id) {
        Ordering::Greater => {
            if role == Role::Active {
                Decision::Proceed
            } else {
                Decision::Lose
            }
        }
        Ordering::Less => {
            if role == Role::Passive {
                Decision::Proceed
            } else {
                Decision::Lose
            }
        }
        Ordering::Equal => {
            warn!(
                %local_id, %remote_id,
                "bgp collision: tied router-ids, keeping the earlier-established connection"
            );
            Decision::Lose
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;

    use super::*;

    fn addr(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn higher_local_id_keeps_active() {
        let local = addr(10, 0, 0, 2);
        let remote = addr(10, 0, 0, 1);
        assert!(matches!(
            collision_winner(local, remote, Role::Active),
            Decision::Proceed
        ));
        assert!(matches!(
            collision_winner(local, remote, Role::Passive),
            Decision::Lose
        ));
    }

    #[test]
    fn higher_remote_id_keeps_passive() {
        let local = addr(10, 0, 0, 1);
        let remote = addr(10, 0, 0, 2);
        assert!(matches!(
            collision_winner(local, remote, Role::Passive),
            Decision::Proceed
        ));
        assert!(matches!(
            collision_winner(local, remote, Role::Active),
            Decision::Lose
        ));
    }

    #[test]
    fn tied_ids_keep_the_earlier_connection() {
        let id = addr(10, 0, 0, 1);
        assert!(matches!(
            collision_winner(id, id, Role::Active),
            Decision::Lose
        ));
        assert!(matches!(
            collision_winner(id, id, Role::Passive),
            Decision::Lose
        ));
    }

    fn peer_slot() -> Arc<PeerSlot> {
        PeerSlot::new(ResolvedPeer {
            remote_address: "10.0.0.1".parse().unwrap(),
            source_address: None,
            remote_as: 65000,
            peer_group: "pg1".to_string(),
            hold_time: 90,
            keepalive_interval: None,
            connect_retry_time: std::time::Duration::from_secs(120),
            mrai: std::time::Duration::ZERO,
            route_refresh_stale_time: std::time::Duration::ZERO,
            damping: None,
            max_hops: None,
            auth: None,
            next_hop: None,
            address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
            route_reflector_client: false,
            route_server_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            evpn_import_policy: None,
            flowspec_import_policy: None,
            flowspec_export_policy: None,
            enforce_first_as: true,
            flowspec_validation: nos_proto::BgpFlowspecValidation::default(),
            shutdown: None,
            maximum_prefix: nos_proto::BgpMaximumPrefix::default(),
            announce_rpki_state: false,
            blackhole: None,
            soft_reconfiguration_inbound: false,
            local_as: None,
            add_path: None,
            add_path_send_count: None,
            role: None,
            strict_mode: false,
            confed_id: None,
            confed_member: false,
            graceful_restart: None,
        })
    }

    #[tokio::test]
    async fn first_side_proceeds_when_the_other_has_not_opened_yet() {
        let slot = peer_slot();
        let decision = slot
            .on_open(
                Role::Active,
                addr(1, 1, 1, 1),
                addr(2, 2, 2, 2),
                Arc::new(Notify::new()),
                false,
            )
            .await;
        assert!(matches!(decision, Decision::Proceed));
    }

    /// #965: the loser's OPEN passed `on_open` first; the winner's `on_open`
    /// then took its record and signalled `cease`; the loser's KEEPALIVE won
    /// the `select!` against that permit, so it reaches `Established` with
    /// the winner already known. It must be told so, and must not become the
    /// slot's established connection.
    #[tokio::test]
    async fn a_loser_reaching_established_after_the_winner_is_known_is_refused() {
        let slot = peer_slot();
        // Local 1.1.1.1 < remote 2.2.2.2: the passive connection wins.
        let (local_id, remote_id) = (addr(1, 1, 1, 1), addr(2, 2, 2, 2));
        let active_cease = Arc::new(Notify::new());
        let d = slot
            .on_open(
                Role::Active,
                local_id,
                remote_id,
                active_cease.clone(),
                false,
            )
            .await;
        assert!(matches!(d, Decision::Proceed));
        let d = slot
            .on_open(
                Role::Passive,
                local_id,
                remote_id,
                Arc::new(Notify::new()),
                false,
            )
            .await;
        assert!(matches!(d, Decision::Proceed));
        // The loser has been told (a stored permit), but races ahead.
        tokio::time::timeout(Duration::from_secs(1), active_cease.notified())
            .await
            .expect("cease permit");
        assert!(
            !slot
                .mark_established(Role::Active, true, Arc::new(Notify::new()))
                .await,
            "the loser must not register"
        );
        assert!(!slot.is_established().await);
        // The winner is unaffected.
        assert!(
            slot.mark_established(Role::Passive, true, Arc::new(Notify::new()))
                .await
        );
        assert!(slot.is_established().await);
    }

    #[tokio::test]
    async fn second_arrival_resolves_by_id_higher_local_keeps_active() {
        let slot = peer_slot();
        let local_id = addr(10, 0, 0, 2);
        let remote_id = addr(10, 0, 0, 1);

        let passive_cease = Arc::new(Notify::new());
        let decision = slot
            .on_open(
                Role::Passive,
                local_id,
                remote_id,
                passive_cease.clone(),
                false,
            )
            .await;
        assert!(matches!(decision, Decision::Proceed));

        let decision = slot
            .on_open(
                Role::Active,
                local_id,
                remote_id,
                Arc::new(Notify::new()),
                false,
            )
            .await;
        assert!(matches!(decision, Decision::Proceed));

        // The passive connection, recorded first, must have been signaled to
        // tear itself down once the (higher-local-id-favored) active side
        // arrived and won.
        assert!(
            passive_cease.notified().now_or_never().is_some(),
            "expected the earlier passive connection's cease handle to be notified"
        );
    }

    #[tokio::test]
    async fn second_arrival_resolves_by_id_higher_remote_keeps_passive() {
        let slot = peer_slot();
        let local_id = addr(10, 0, 0, 1);
        let remote_id = addr(10, 0, 0, 2);

        let active_cease = Arc::new(Notify::new());
        let decision = slot
            .on_open(
                Role::Active,
                local_id,
                remote_id,
                active_cease.clone(),
                false,
            )
            .await;
        assert!(matches!(decision, Decision::Proceed));

        let decision = slot
            .on_open(
                Role::Passive,
                local_id,
                remote_id,
                Arc::new(Notify::new()),
                false,
            )
            .await;
        assert!(matches!(decision, Decision::Proceed));

        assert!(
            active_cease.notified().now_or_never().is_some(),
            "expected the earlier active connection's cease handle to be notified"
        );
    }

    #[tokio::test]
    async fn established_connection_beats_a_later_collision_regardless_of_id() {
        let slot = peer_slot();
        // IDs alone would favor the passive side (remote > local), but the
        // active side is already Established, so it must win regardless.
        let local_id = addr(10, 0, 0, 1);
        let remote_id = addr(10, 0, 0, 2);

        let decision = slot
            .on_open(
                Role::Active,
                local_id,
                remote_id,
                Arc::new(Notify::new()),
                false,
            )
            .await;
        assert!(matches!(decision, Decision::Proceed));
        slot.mark_established(Role::Active, false, Arc::new(Notify::new()))
            .await;

        let decision = slot
            .on_open(
                Role::Passive,
                local_id,
                remote_id,
                Arc::new(Notify::new()),
                false,
            )
            .await;
        assert!(matches!(decision, Decision::Lose));
    }

    /// RFC 4724 §4.2: an Established GR session is replaced by a connection
    /// begun after it came up — in the other role through `on_open`, in the
    /// same role through `begin` — once the old one has ended. Without GR,
    /// or for a connection begun before, today's collision rules apply.
    #[tokio::test]
    async fn graceful_restart_new_connection_replaces_the_established_one() {
        let (local_id, remote_id) = (addr(10, 0, 0, 2), addr(10, 0, 0, 1));
        for gr in [true, false] {
            // Other role: established passive, new active.
            let slot = peer_slot();
            assert!(slot.begin(Role::Passive).await);
            slot.on_open(
                Role::Passive,
                local_id,
                remote_id,
                Arc::new(Notify::new()),
                false,
            )
            .await;
            let replaced = Arc::new(Notify::new());
            slot.mark_established(Role::Passive, gr, replaced.clone())
                .await;
            // Began before the session came up: an ordinary collision.
            let early = peer_slot();
            assert!(early.begin(Role::Active).await);
            assert!(early.begin(Role::Passive).await);
            early
                .on_open(
                    Role::Passive,
                    local_id,
                    remote_id,
                    Arc::new(Notify::new()),
                    false,
                )
                .await;
            early
                .mark_established(Role::Passive, gr, Arc::new(Notify::new()))
                .await;
            let decision = early
                .on_open(
                    Role::Active,
                    local_id,
                    remote_id,
                    Arc::new(Notify::new()),
                    false,
                )
                .await;
            assert!(matches!(decision, Decision::Lose), "gr={gr}");

            tokio::time::sleep(Duration::from_millis(2)).await;
            assert!(slot.begin(Role::Active).await);
            let old = slot.clone();
            let waiter = replaced.clone();
            let ender = tokio::spawn(async move {
                // The old session's fsm: ends when told it was replaced.
                waiter.notified().await;
                old.clear(Role::Passive).await;
            });
            // Without the R bit, the other role is an ordinary collision.
            let decision = slot
                .on_open(
                    Role::Active,
                    local_id,
                    remote_id,
                    Arc::new(Notify::new()),
                    false,
                )
                .await;
            assert!(matches!(decision, Decision::Lose), "gr={gr}");
            let decision = slot
                .on_open(
                    Role::Active,
                    local_id,
                    remote_id,
                    Arc::new(Notify::new()),
                    true,
                )
                .await;
            assert_eq!(matches!(decision, Decision::Proceed), gr, "gr={gr}");
            if !gr {
                ender.abort();
                continue;
            }
            ender.await.unwrap();

            // Same role: established active, a new active `begin`.
            slot.mark_established(Role::Active, true, replaced.clone())
                .await;
            tokio::time::sleep(Duration::from_millis(2)).await;
            let old = slot.clone();
            let waiter = replaced.clone();
            let ender = tokio::spawn(async move {
                waiter.notified().await;
                old.clear(Role::Active).await;
            });
            assert!(slot.begin(Role::Active).await);
            ender.await.unwrap();
        }
    }

    #[tokio::test]
    async fn degenerate_double_begin_for_the_same_role_is_rejected() {
        let slot = peer_slot();
        assert!(slot.begin(Role::Passive).await);
        assert!(!slot.begin(Role::Passive).await);
        slot.clear(Role::Passive).await;
        assert!(slot.begin(Role::Passive).await);
    }

    #[tokio::test(start_paused = true)]
    async fn max_prefix_hold_lasts_until_cleared_or_the_restart_interval() {
        let slot = peer_slot();
        assert!(!slot.max_prefix_held());
        slot.trip_max_prefix(0);
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert!(slot.max_prefix_held(), "0 holds until cleared");
        slot.clear_max_prefix();
        assert!(!slot.max_prefix_held());

        slot.trip_max_prefix(5);
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(slot.max_prefix_held());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(!slot.max_prefix_held(), "released after the interval");
    }

    #[tokio::test]
    async fn is_established_reflects_either_role() {
        let slot = peer_slot();
        assert!(!slot.is_established().await);

        slot.on_open(
            Role::Passive,
            addr(1, 1, 1, 1),
            addr(2, 2, 2, 2),
            Arc::new(Notify::new()),
            false,
        )
        .await;
        assert!(!slot.is_established().await);

        slot.mark_established(Role::Passive, false, Arc::new(Notify::new()))
            .await;
        assert!(slot.is_established().await);

        slot.clear(Role::Passive).await;
        assert!(!slot.is_established().await);
    }

    #[tokio::test]
    async fn concurrent_soft_ins_share_one_pass_and_a_policy_change_supersedes_it() {
        use tokio::sync::oneshot::channel;
        let slot = peer_slot();
        let (t1, mut r1) = channel();
        let (t2, mut r2) = channel();
        let generation = slot.reeval_begin(false, Some(t1)).expect("first starts");
        assert_eq!(slot.reeval_begin(false, Some(t2)), None, "second joins");
        slot.reeval_finish(generation, &Ok(Vec::new()));
        assert_eq!(r1.try_recv().unwrap(), Ok(Vec::new()));
        assert_eq!(r2.try_recv().unwrap(), Ok(Vec::new()));

        let (t3, mut r3) = channel();
        let old = slot.reeval_begin(false, Some(t3)).unwrap();
        let newer = slot.reeval_begin(true, None).unwrap();
        assert!(!slot.reeval_current(old) && slot.reeval_current(newer));
        assert_eq!(r3.try_recv().unwrap(), Err(REEVAL_SUPERSEDED.to_string()));
        slot.reeval_finish(old, &Ok(Vec::new())); // a stale finish is a no-op
        let (t4, mut r4) = channel();
        assert_eq!(slot.reeval_begin(false, Some(t4)), None, "still running");
        slot.reeval_finish(newer, &Err("disabled".into()));
        assert_eq!(r4.try_recv().unwrap(), Err("disabled".to_string()));
    }
}
