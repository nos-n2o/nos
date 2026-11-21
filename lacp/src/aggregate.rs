//! `AggregateManager` — one per configured `Lacp`-mode `PortAggregate`,
//! the LACP analogue of `ospf::link::LinkManager`: spawns/stops one
//! `link::run` task per currently-configured member port, re-runs
//! `selection::select` whenever any port's observation changes, and pushes
//! the resulting `Distributing`-state port set to `nos-interfaced`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nos_proto::{
    LacpAggregateConversations, LacpAggregateMembers, LacpLinkConversations, LacpMode,
    LacpMuxState, LacpPortStatus, LacpRate, LacpReceiveState, PortAggregateLacpSummary,
};
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::churn_machine::{ChurnState, CHURN_DETECTION_TIME};
use crate::cscd::{self, Advert, Agreement, PortIn, V2Cfg};
use crate::interface_client::LacpPush;
use crate::link::{self, LinkConfig, PortObservation};
use crate::mux_machine::MuxState;
use crate::packet::{state_bit, PortInfo};
use crate::receive_machine::ReceiveState;
use crate::selection::{self, PortCandidate};

/// Pushes to `nos-interfaced` are at most one per this window (leading edge
/// immediate, newest set trailing): a flapping partner can't churn rtnetlink.
const PUSH_COALESCE: Duration = Duration::from_secs(1);

/// 802.1AX default for both the system and the port priority (0x8000).
pub const DEFAULT_PRIORITY: u16 = 32768;

/// `NOS_LACP_CHURN_SECS` shortens 802.1AX's 60s `Churn_Detection_Time` so the
/// e2e harness doesn't wait a minute; read only in a `dev-args` build (#1214).
fn churn_time() -> std::time::Duration {
    #[cfg(feature = "dev-args")]
    return std::env::var("NOS_LACP_CHURN_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map_or(CHURN_DETECTION_TIME, std::time::Duration::from_secs);
    #[cfg(not(feature = "dev-args"))]
    CHURN_DETECTION_TIME
}

/// Daemon-wide 802.1AX §6.3.4 Port Number allocator: the system ID is shared
/// by every aggregate, so a number must be unique (and non-zero) across all
/// of them. Lowest free in `1..=65535`, sticky while the member stays
/// configured, not persisted across restarts.
#[derive(Clone, Default)]
pub struct PortNumbers(Arc<Mutex<HashMap<String, u16>>>);

impl PortNumbers {
    /// The member's number, or `None` when all 65535 are taken.
    pub fn get_or_assign(&self, interface: &str) -> Option<u16> {
        let mut map = self.0.lock().unwrap();
        if let Some(n) = map.get(interface) {
            return Some(*n);
        }
        let used: HashSet<u16> = map.values().copied().collect();
        let n = (1..=u16::MAX).find(|n| !used.contains(n))?;
        map.insert(interface.to_string(), n);
        Some(n)
    }

    pub fn release(&self, interface: &str) {
        self.0.lock().unwrap().remove(interface);
    }
}

/// The v2 state shared by the manager, its `selection_loop` and `summary`.
pub struct V2Shared {
    cfg: Mutex<V2Cfg>,
    advert_tx: watch::Sender<Advert>,
    out: Mutex<V2Out>,
    /// Our `(system priority, system id)`, for the `Link_Number` adoption
    /// comparison; kept current by `reconcile_v2`.
    actor: Mutex<(u16, [u8; 6])>,
}

/// What `selection_loop` last decided, for `show lacp`.
struct V2Out {
    agreement: Agreement,
    conversations_per_link: Vec<(String, u16)>,
}

impl V2Shared {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cfg: Mutex::new(V2Cfg::default()),
            advert_tx: watch::channel(Advert::default()).0,
            actor: Mutex::new((DEFAULT_PRIORITY, [0; 6])),
            out: Mutex::new(V2Out {
                agreement: Agreement::NotRequested,
                conversations_per_link: Vec::new(),
            }),
        })
    }
}

type SelectedTxs = Arc<Mutex<HashMap<String, watch::Sender<bool>>>>;

pub struct AggregateManager {
    name: String,
    /// The rate the currently-running member tasks were started with — a
    /// change restarts them all (their advertised `LACP_Timeout` and timers
    /// are fixed for a task's lifetime).
    rate: Mutex<LacpRate>,
    /// Config's `min-links`, read live by `selection_loop`: a pure
    /// selection-side policy, so a change restarts no link.
    min_links: Arc<AtomicU16>,
    /// Same, for the Actor System Priority.
    system_priority: Mutex<u16>,
    /// The port priority each running member task was started with; a
    /// change restarts only that member.
    port_priorities: Arc<Mutex<HashMap<String, u16>>>,
    /// Same, for each member's `lacp-mode`.
    modes: Mutex<HashMap<String, LacpMode>>,
    /// Per running member, the live `lacp-mode` (`true` = Active).
    active_txs: Mutex<HashMap<String, watch::Sender<bool>>>,
    /// Assigned once, sequentially, the first time `reconcile.rs` sees this
    /// aggregate name (see `reconcile.rs`) — not persisted, only needs to
    /// differ between simultaneously-active aggregates on this instance.
    key: u16,
    members: Mutex<HashMap<String, JoinHandle<()>>>,
    selected_txs: SelectedTxs,
    observations: Arc<Mutex<HashMap<String, PortObservation>>>,
    changed: Arc<Notify>,
    /// This aggregate's Actor System ID — see [`derive_system_id`]. Fixed for
    /// the life of the process: it must not depend on any member port,
    /// because bonding rewrites a slave's MAC (the first slave enslaved lends
    /// its MAC to the bond, and every other slave takes it over), so a
    /// port-derived ID changed whenever enslavement order did, restarting
    /// every link in a loop.
    system_id: Mutex<[u8; 6]>,
    /// The id used when config gives no override — computed once (it reads
    /// the hostname and machine-id).
    derived_system_id: [u8; 6],
    selection_task: JoinHandle<()>,
    port_numbers: PortNumbers,
    v2: Arc<V2Shared>,
}

impl AggregateManager {
    pub fn new(
        name: &str,
        key: u16,
        push_tx: mpsc::Sender<LacpPush>,
        port_numbers: PortNumbers,
    ) -> Arc<Self> {
        let derived = local_system_id();
        let observations = Arc::new(Mutex::new(HashMap::new()));
        let changed = Arc::new(Notify::new());
        let selected_txs: SelectedTxs = Arc::new(Mutex::new(HashMap::new()));
        let port_priorities = Arc::new(Mutex::new(HashMap::new()));
        let min_links = Arc::new(AtomicU16::new(1));
        let v2 = V2Shared::new();
        let selection_task = tokio::spawn(selection_loop(
            name.to_string(),
            observations.clone(),
            changed.clone(),
            selected_txs.clone(),
            port_priorities.clone(),
            min_links.clone(),
            v2.clone(),
            push_tx,
        ));
        Arc::new(Self {
            name: name.to_string(),
            rate: Mutex::new(LacpRate::default()),
            min_links,
            system_priority: Mutex::new(DEFAULT_PRIORITY),
            port_priorities,
            modes: Mutex::new(HashMap::new()),
            active_txs: Mutex::new(HashMap::new()),
            key,
            members: Mutex::new(HashMap::new()),
            selected_txs,
            observations,
            changed,
            system_id: Mutex::new(derived),
            derived_system_id: derived,
            selection_task,
            port_numbers,
            v2,
        })
    }

    /// Diffs `desired_members` (real kernel interface names) against the
    /// currently-running set, spawning/stopping `link::run` tasks as needed.
    /// A changed `rate` restarts every member (each renegotiates from
    /// scratch, briefly dropping out of the active set).
    ///
    /// `system_id` overrides the derived Actor System ID (config's
    /// `lacp-system-id`, so two PEs sharing an Ethernet Segment can present
    /// the same actor); `None` goes back to the derived one. A change
    /// restarts every member, like a rate change: the id is fixed for a
    /// link task's lifetime. `system_priority` (config's
    /// `lacp-system-priority`) restarts every member the same way, and a
    /// member's own `(name, port_priority)` change restarts just that member; a
    /// `lacp-mode` change restarts nothing (applied in place).
    /// `min_links` (config's `min-links`) restarts nothing: it only gates the
    /// pushed active set.
    pub fn reconcile(
        &self,
        desired: Vec<(String, u16, LacpMode)>,
        rate: LacpRate,
        system_id: Option<[u8; 6]>,
        system_priority: u16,
        min_links: u16,
    ) {
        self.reconcile_v2(
            desired,
            rate,
            system_id,
            system_priority,
            min_links,
            &V2Cfg::default(),
        );
    }

    /// [`Self::reconcile`] plus the v2 settings (#894). A changed version or
    /// algorithm restarts every member, a changed `lacp-link-number` only that
    /// member (both are fixed for a link task's lifetime); a changed map only
    /// republishes the advert.
    pub fn reconcile_v2(
        &self,
        mut desired: Vec<(String, u16, LacpMode)>,
        rate: LacpRate,
        system_id: Option<[u8; 6]>,
        system_priority: u16,
        min_links: u16,
        v2: &V2Cfg,
    ) {
        let old_v2 = std::mem::replace(&mut *self.v2.cfg.lock().unwrap(), v2.clone());
        let v2_changed = old_v2.version != v2.version || old_v2.algorithm != v2.algorithm;
        self.min_links.store(min_links, Ordering::Relaxed);
        desired.sort_by(|a, b| a.0.cmp(&b.0));
        let desired_members: Vec<String> = desired.iter().map(|(n, _, _)| n.clone()).collect();
        let system_id = system_id.unwrap_or(self.derived_system_id);
        let rate_changed = {
            let mut current = self.rate.lock().unwrap();
            let mut id = self.system_id.lock().unwrap();
            let mut prio = self.system_priority.lock().unwrap();
            let changed =
                *current != rate || *id != system_id || *prio != system_priority || v2_changed;
            *current = rate;
            *id = system_id;
            *prio = system_priority;
            *self.v2.actor.lock().unwrap() = (system_priority, system_id);
            changed
        };
        let mut port_priorities = self.port_priorities.lock().unwrap();
        let mut modes = self.modes.lock().unwrap();

        let mut members = self.members.lock().unwrap();
        let mut selected_txs = self.selected_txs.lock().unwrap();
        let mut observations = self.observations.lock().unwrap();
        let mut active_txs = self.active_txs.lock().unwrap();

        let to_remove: Vec<String> = members
            .keys()
            .filter(|k| {
                rate_changed
                    || !desired_members.contains(k)
                    || old_v2.link_numbers.get(*k) != v2.link_numbers.get(*k)
                    || desired
                        .iter()
                        .any(|(n, p, _)| n == *k && port_priorities.get(*k) != Some(p))
            })
            .cloned()
            .collect();
        for interface in to_remove {
            if let Some(task) = members.remove(&interface) {
                task.abort();
            }
            selected_txs.remove(&interface);
            active_txs.remove(&interface);
            observations.remove(&interface);
            // A restart (rate/priority change) keeps its number; only a
            // member that left the aggregate frees it.
            if !desired_members.contains(&interface) {
                self.port_numbers.release(&interface);
            }
        }

        for (interface, port_priority, mode) in &desired {
            // A task that ended on its own (its socket failed hard, e.g. the
            // interface vanished) is not "running" — fall through and
            // respawn it on this pass, like `ospf::link::LinkManager` does.
            if members.get(interface).is_some_and(|t| !t.is_finished()) {
                // A `lacp-mode` change is applied in place, no restart.
                modes.insert(interface.clone(), *mode);
                if let Some(tx) = active_txs.get(interface) {
                    tx.send_replace(*mode == LacpMode::Active);
                }
                continue;
            }
            let Some(actor_port_number) = self.port_numbers.get_or_assign(interface) else {
                warn!(%interface, "lacp port numbers exhausted, member skipped");
                continue;
            };
            port_priorities.insert(interface.clone(), *port_priority);
            modes.insert(interface.clone(), *mode);
            let (selected_tx, selected_rx) = watch::channel(false);
            let (active_tx, active_rx) = watch::channel(*mode == LacpMode::Active);
            active_txs.insert(interface.clone(), active_tx);
            let config = LinkConfig {
                interface: interface.clone(),
                actor_system_id: system_id,
                actor_system_priority: system_priority,
                actor_key: self.key,
                actor_port_priority: *port_priority,
                actor_port_number,
                actor_active: *mode == LacpMode::Active,
                active_rx,
                rate,
                selected_rx,
                churn_time: churn_time(),
                version_pref: v2.version_pref(),
                link_number: v2.link_numbers.get(interface).copied(),
                advert_rx: self.v2.advert_tx.subscribe(),
            };
            let task = tokio::spawn(link::run(
                config,
                self.observations.clone(),
                self.changed.clone(),
            ));
            members.insert(interface.clone(), task);
            selected_txs.insert(interface.clone(), selected_tx);
        }
        port_priorities.retain(|k, _| members.contains_key(k));
        modes.retain(|k, _| members.contains_key(k));
        drop((
            members,
            selected_txs,
            observations,
            port_priorities,
            modes,
            active_txs,
        ));
        self.changed.notify_one();
    }

    /// This aggregate's current LACP state, for `show lacp`.
    pub fn summary(&self) -> PortAggregateLacpSummary {
        let cfg = self.v2.cfg.lock().unwrap().clone();
        let out = self.v2.out.lock().unwrap();
        let observations = self.observations.lock().unwrap();
        let selected_txs = self.selected_txs.lock().unwrap();
        let mut ports: Vec<LacpPortStatus> = observations
            .iter()
            .map(|(interface, obs)| {
                let pd = obs.partner.unwrap_or(PortInfo::ADMINISTRATIVE_DEFAULT);
                LacpPortStatus {
                    interface: interface.clone(),
                    actor_port_number: obs.actor_port,
                    receive_state: wire_receive_state(obs.receive_state),
                    mux_state: wire_mux_state(obs.mux_state),
                    partner_system_id: Some(pd.system),
                    partner_key: Some(pd.key),
                    partner_port_number: Some(pd.port),
                    actor_port_priority: self
                        .port_priorities
                        .lock()
                        .unwrap()
                        .get(interface)
                        .copied()
                        .unwrap_or(DEFAULT_PRIORITY),
                    mode: self
                        .modes
                        .lock()
                        .unwrap()
                        .get(interface)
                        .copied()
                        .unwrap_or_default(),
                    partner_system_priority: Some(pd.system_priority),
                    partner_port_priority: Some(pd.port_priority),
                    selected: selected_txs.get(interface).is_some_and(|tx| *tx.borrow()),
                    individual: obs.partner_individual(),
                    unsupported_version_pdus: obs.unsupported_version_pdus,
                    synchronized: obs
                        .partner
                        .is_some_and(|p| p.has_state(state_bit::SYNCHRONIZATION)),
                    actor_churn: obs.actor_churn == ChurnState::Churn,
                    partner_churn: obs.partner_churn == ChurnState::Churn,
                    partner_version: obs.v2.version,
                    partner_port_algorithm: obs.v2.algorithm.and_then(cscd::proto_algorithm),
                }
            })
            .collect();
        ports.sort_by(|a, b| a.interface.cmp(&b.interface));
        let selected: HashSet<String> = selected_txs
            .iter()
            .filter(|(_, tx)| *tx.borrow())
            .map(|(i, _)| i.clone())
            .collect();
        let min_links = self.min_links.load(Ordering::Relaxed);
        let min_links_met = min_links_met(active_set(&observations, &selected).len(), min_links);
        PortAggregateLacpSummary {
            aggregate: self.name.clone(),
            actor_system_id: *self.system_id.lock().unwrap(),
            actor_key: self.key,
            actor_system_priority: *self.system_priority.lock().unwrap(),
            rate: *self.rate.lock().unwrap(),
            min_links,
            min_links_met,
            ports,
            version: cfg.version,
            port_algorithm: cfg.algorithm,
            agreement: out.agreement.to_wire(),
            conversations_per_link: out.conversations_per_link.clone(),
        }
    }

    /// Stops every member task and the selection loop — called when this
    /// aggregate is removed from config entirely (see `reconcile.rs`).
    pub fn shutdown(&self) {
        for (interface, task) in self.members.lock().unwrap().drain() {
            task.abort();
            self.port_numbers.release(&interface);
        }
        self.selection_task.abort();
    }
}

/// What one push round carries: the active members, the per-link conversation
/// masks of the Distributing links (empty = plain hashing) and whether the
/// partner agreed (`Discard_Wrong_Conversation`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Want {
    members: Vec<String>,
    conversations: Vec<LacpLinkConversations>,
    discard_wrong: bool,
}

/// Re-runs Selection Logic and recomputes the active (`Distributing`)
/// member set every time any port's observation changes, feeds each
/// port's own `selected_tx` (driving its `mux_machine::Event::
/// SelectionChanged`), republishes the v2 advertisement, decides the
/// conversation agreement, and pushes the members and conversations when they
/// change — the one natural edge-triggered mutation point `interface_client`'s
/// own doc comment refers to.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // one task, one call site
async fn selection_loop(
    aggregate: String,
    observations: Arc<Mutex<HashMap<String, PortObservation>>>,
    changed: Arc<Notify>,
    selected_txs: SelectedTxs,
    port_priorities: Arc<Mutex<HashMap<String, u16>>>,
    min_links: Arc<AtomicU16>,
    v2: Arc<V2Shared>,
    push_tx: mpsc::Sender<LacpPush>,
) {
    let mut last_pushed: Option<Want> = None;
    let mut last_push_at: Option<Instant> = None;
    // Newest computed set held back by the 1 s coalescing window.
    let mut pending: Option<Want> = None;
    let mut last_agreement: Option<Agreement> = None;
    let mut last_numbers: std::collections::BTreeMap<String, u16> =
        std::collections::BTreeMap::new();
    loop {
        let deadline = match (&pending, last_push_at) {
            (Some(_), Some(t)) => t + PUSH_COALESCE,
            _ => Instant::now() + Duration::from_hours(24),
        };
        tokio::select! {
            () = changed.notified() => {}
            () = tokio::time::sleep_until(deadline), if pending.is_some() => {
                // Trailing edge: disarmed by taking `pending`.
                let want = pending.take().expect("guarded by pending.is_some()");
                if last_pushed.as_ref() != Some(&want) {
                    if !push(&push_tx, &aggregate, &want, last_pushed.as_ref()).await {
                        return;
                    }
                    last_pushed = Some(want);
                    last_push_at = Some(Instant::now());
                }
                continue;
            }
        }

        let snapshot: HashMap<String, PortObservation> = observations.lock().unwrap().clone();
        let priorities = port_priorities.lock().unwrap().clone();
        let candidates: Vec<PortCandidate> = snapshot
            .iter()
            .map(|(interface, obs)| PortCandidate {
                interface: interface.clone(),
                current: obs.selectable(),
                partner_system_id: obs.partner.map_or_default(|p| p.system),
                partner_key: obs.partner.map_or_default(|p| p.key),
                partner_individual: obs.partner_individual(),
                actor_port_priority: priorities
                    .get(interface)
                    .copied()
                    .unwrap_or(DEFAULT_PRIORITY),
                actor_port_number: obs.actor_port,
            })
            .collect();
        let selected = selection::select(&candidates);

        for (interface, tx) in selected_txs.lock().unwrap().iter() {
            set_if_changed(tx, selected.contains(interface));
        }

        let mut active_members = active_set(&snapshot, &selected);
        active_members.sort();

        // v2 (802.1AX 6.6): the advert (algorithm, admin-map digest) is config
        // only; the vector, `Link_Number` adoption and the agreement flags come
        // from the Collecting ports (p.93, 99). Pushes list Distributing only.
        let cfg = v2.cfg.lock().unwrap().clone();
        let (mut advert, map) = cscd::compute(&cfg);
        let (sys_prio, sys_id) = *v2.actor.lock().unwrap();
        let mut ports: Vec<PortIn> = snapshot
            .iter()
            .map(|(interface, obs)| PortIn {
                name: interface.clone(),
                collecting: selected.contains(interface)
                    && matches!(obs.mux_state, MuxState::Collecting | MuxState::Distributing)
                    && !obs.is_churned()
                    && obs
                        .partner
                        .is_some_and(|p| p.has_state(state_bit::SYNCHRONIZATION)),
                distributing: obs.mux_state == MuxState::Distributing,
                partner_lower: obs.partner.is_some_and(|p| {
                    cscd::partner_is_lower(
                        (sys_prio, sys_id),
                        (
                            priorities
                                .get(interface)
                                .copied()
                                .unwrap_or(DEFAULT_PRIORITY),
                            obs.actor_port,
                        ),
                        &p,
                    )
                }),
                v2: obs.v2,
            })
            .collect();
        ports.sort_by(|a, b| a.name.cmp(&b.name));
        let resolved = cscd::resolve(&cfg, &advert, map.as_ref(), &ports);
        advert.link_numbers.clone_from(&resolved.link_numbers);
        for (interface, n) in &resolved.link_numbers {
            let before = last_numbers
                .get(interface)
                .or(cfg.link_numbers.get(interface));
            if before != Some(n) && cfg.link_numbers.get(interface) != Some(n) {
                info!(interface = %interface, from = before.copied().unwrap_or(0), to = *n, "lacp link number adopted");
            }
        }
        last_numbers.clone_from(&resolved.link_numbers);
        v2.advert_tx.send_if_modified(|cur| {
            if *cur == advert {
                false
            } else {
                cur.clone_from(&advert);
                true
            }
        });
        let agreement = resolved.agreement;
        if last_agreement != Some(agreement) {
            let (state, reason) = agreement.label();
            info!(aggregate = %aggregate, state = %state, reason = %reason, "lacp conversation agreement");
            last_agreement = Some(agreement);
        }

        let min = min_links.load(Ordering::Relaxed);
        let min_met = min_links_met(active_members.len(), min);
        if !min_met {
            // Only the pushed set is gated: ports stay selected and keep
            // negotiating, so the bond refills the moment the count is met.
            if last_pushed.as_ref().is_some_and(|l| !l.members.is_empty()) {
                info!(
                    aggregate = %aggregate,
                    members = active_members.len(),
                    min_links = min,
                    "lacp min-links not met, bond emptied"
                );
            }
            active_members.clear();
        }

        let conversations: Vec<LacpLinkConversations> = if min_met {
            resolved
                .steer
                .into_iter()
                .map(|s| LacpLinkConversations {
                    member: s.member,
                    link_number: s.link_number,
                    mask: s.mask,
                })
                .collect()
        } else {
            Vec::new()
        };
        let discard_wrong = resolved.discard_wrong && !conversations.is_empty();
        *v2.out.lock().unwrap() = V2Out {
            agreement,
            conversations_per_link: conversations
                .iter()
                .map(|l| {
                    let n: u32 = l.mask.iter().map(|b| b.count_ones()).sum();
                    (l.member.clone(), u16::try_from(n).unwrap_or(u16::MAX))
                })
                .collect(),
        };
        let want = Want {
            members: active_members,
            conversations,
            discard_wrong,
        };

        if last_pushed.as_ref() == Some(&want) {
            // A->B->A inside the window: nothing to push.
            pending = None;
        } else if last_push_at.is_some_and(|t| t.elapsed() < PUSH_COALESCE) {
            pending = Some(want);
        } else {
            pending = None;
            if !push(&push_tx, &aggregate, &want, last_pushed.as_ref()).await {
                return;
            }
            last_pushed = Some(want);
            last_push_at = Some(Instant::now());
        }
    }
}

/// Pushes what differs from `last` (everything on the first round); `false`
/// when the interface client is gone. Members go first.
async fn push(
    push_tx: &mpsc::Sender<LacpPush>,
    aggregate: &str,
    want: &Want,
    last: Option<&Want>,
) -> bool {
    if last.is_none_or(|l| l.members != want.members) {
        info!(aggregate = %aggregate, members = want.members.len(), "lacp reconciled aggregate members");
        let msg = LacpPush::Members(LacpAggregateMembers {
            aggregate: aggregate.to_string(),
            active_members: want.members.clone(),
        });
        if push_tx.send(msg).await.is_err() {
            warn!(aggregate = %aggregate, "lacp interface_client channel closed, stopping selection loop");
            return false;
        }
    }
    if last.is_none_or(|l| {
        l.conversations != want.conversations || l.discard_wrong != want.discard_wrong
    }) {
        info!(aggregate = %aggregate, links = want.conversations.len(), discard_wrong = want.discard_wrong, "lacp conversations pushed");
        let msg = LacpPush::Conversations(LacpAggregateConversations {
            aggregate: aggregate.to_string(),
            links: want.conversations.clone(),
            discard_wrong: want.discard_wrong,
        });
        if push_tx.send(msg).await.is_err() {
            warn!(aggregate = %aggregate, "lacp interface_client channel closed, stopping selection loop");
            return false;
        }
    }
    true
}

/// Ports that belong in the bond: selected, `Distributing` and not churned.
fn active_set(
    snapshot: &HashMap<String, PortObservation>,
    selected: &HashSet<String>,
) -> Vec<String> {
    snapshot
        .iter()
        .filter(|(interface, obs)| {
            selected.contains(*interface)
                && obs.mux_state == MuxState::Distributing
                && !obs.is_churned()
        })
        .map(|(interface, _)| interface.clone())
        .collect()
}

/// `min-links` gate: 0 and 1 both mean "any one active port is enough".
fn min_links_met(active: usize, min_links: u16) -> bool {
    active >= usize::from(min_links)
}

fn wire_receive_state(state: ReceiveState) -> LacpReceiveState {
    match state {
        ReceiveState::Expired => LacpReceiveState::Expired,
        ReceiveState::Defaulted => LacpReceiveState::Defaulted,
        ReceiveState::Current => LacpReceiveState::Current,
    }
}

fn wire_mux_state(state: MuxState) -> LacpMuxState {
    match state {
        MuxState::Detached => LacpMuxState::Detached,
        MuxState::Waiting => LacpMuxState::Waiting,
        MuxState::Attached => LacpMuxState::Attached,
        MuxState::Collecting => LacpMuxState::Collecting,
        MuxState::Distributing => LacpMuxState::Distributing,
    }
}

/// This machine's Actor System ID: a locally-administered unicast MAC
/// derived from stable per-machine identity (hostname + machine-id), never
/// from a port — see `AggregateManager::system_id`. `ponytail:` two machines
/// sharing both (e.g. cloned images with the default hostname) would collide
/// and each see the other as itself; upgrade path is a persisted random id
/// file.
fn local_system_id() -> [u8; 6] {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    derive_system_id(
        read("/proc/sys/kernel/hostname").trim(),
        read("/etc/machine-id").trim(),
    )
}

fn derive_system_id(hostname: &str, machine_id: &str) -> [u8; 6] {
    // FNV-1a — no dependency needed for a non-cryptographic 48-bit spread.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in hostname.bytes().chain([0]).chain(machine_id.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let b = hash.to_be_bytes();
    // 0x02: locally administered, unicast.
    [0x02, b[3], b[4], b[5], b[6], b[7]]
}

/// Updates `tx` only if the verdict actually changed. `watch::Sender::send`
/// wakes the receiver even for an identical value, and a woken link task
/// reports back, which re-runs this loop — sending unconditionally made an
/// infinite feedback loop that flooded the log.
fn set_if_changed(tx: &watch::Sender<bool>, value: bool) -> bool {
    tx.send_if_modified(|current| {
        if *current == value {
            false
        } else {
            *current = value;
            true
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_id_is_stable_distinct_and_locally_administered_unicast() {
        let a = derive_system_id("router-a", "m1");
        assert_eq!(a, derive_system_id("router-a", "m1"));
        assert_ne!(a, derive_system_id("router-b", "m1"));
        assert_ne!(a, derive_system_id("router-a", "m2"));
        assert_eq!(a[0], 0x02);
    }

    #[tokio::test]
    async fn configured_system_id_overrides_the_derived_one_and_reverts() {
        let (tx, _rx) = mpsc::channel(1);
        let agg = AggregateManager::new("bond1", 1, tx, PortNumbers::default());
        let derived = agg.summary().actor_system_id;
        let mine = [0x02, 0, 0, 0, 0, 0x99];
        agg.reconcile(Vec::new(), LacpRate::Slow, Some(mine), DEFAULT_PRIORITY, 1);
        assert_eq!(agg.summary().actor_system_id, mine);
        agg.reconcile(Vec::new(), LacpRate::Slow, None, DEFAULT_PRIORITY, 1);
        assert_eq!(agg.summary().actor_system_id, derived);
        agg.shutdown();
    }

    #[test]
    fn port_numbers_are_non_zero_lowest_free_sticky_and_reused() {
        let p = PortNumbers::default();
        assert_eq!(p.get_or_assign("eth1"), Some(1));
        assert_eq!(p.get_or_assign("eth2"), Some(2));
        assert_eq!(p.get_or_assign("eth1"), Some(1));
        p.release("eth1");
        assert_eq!(p.get_or_assign("eth3"), Some(1));
        assert_eq!(p.get_or_assign("eth2"), Some(2));
    }

    #[test]
    fn port_numbers_exhaustion_returns_none_without_panicking() {
        let p = PortNumbers::default();
        for i in 1..=u16::MAX {
            p.0.lock().unwrap().insert(format!("i{i}"), i);
        }
        assert_eq!(p.get_or_assign("last"), None);
        p.release("i7");
        assert_eq!(p.get_or_assign("last"), Some(7));
    }

    #[tokio::test]
    async fn two_aggregates_never_share_a_port_number() {
        let (tx, _rx) = mpsc::channel(1);
        let ports = PortNumbers::default();
        let a = AggregateManager::new("bond1", 1, tx.clone(), ports.clone());
        let b = AggregateManager::new("bond2", 2, tx, ports.clone());
        let m = |n: &str| vec![(n.to_string(), DEFAULT_PRIORITY, LacpMode::Active)];
        a.reconcile(m("noif-a"), LacpRate::Slow, None, DEFAULT_PRIORITY, 1);
        b.reconcile(m("noif-b"), LacpRate::Slow, None, DEFAULT_PRIORITY, 1);
        assert_eq!(ports.get_or_assign("noif-a"), Some(1));
        assert_eq!(ports.get_or_assign("noif-b"), Some(2));
        b.reconcile(Vec::new(), LacpRate::Slow, None, DEFAULT_PRIORITY, 1);
        assert_eq!(ports.get_or_assign("noif-c"), Some(2));
        a.shutdown();
        b.shutdown();
        assert_eq!(ports.get_or_assign("noif-d"), Some(1));
    }

    #[test]
    fn min_links_gate() {
        // 0 and 1 are equivalent; N-1 fails, N and N+1 pass.
        assert!(min_links_met(1, 0));
        assert!(min_links_met(0, 0));
        assert!(!min_links_met(0, 1));
        assert!(min_links_met(1, 1));
        assert!(!min_links_met(1, 2));
        assert!(min_links_met(2, 2));
        assert!(min_links_met(3, 2));
    }

    #[test]
    fn unchanged_verdict_does_not_wake_the_port() {
        let (tx, mut rx) = watch::channel(false);
        assert!(!set_if_changed(&tx, false));
        assert!(!rx.has_changed().unwrap());

        assert!(set_if_changed(&tx, true));
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();

        assert!(!set_if_changed(&tx, true));
        assert!(!rx.has_changed().unwrap());
    }

    fn obs(distributing: bool) -> PortObservation {
        PortObservation {
            receive_state: ReceiveState::Current,
            mux_state: if distributing {
                MuxState::Distributing
            } else {
                MuxState::Detached
            },
            actor_port: 1,
            partner: None,
            actor_churn: ChurnState::NoChurn,
            partner_churn: ChurnState::NoChurn,
            unsupported_version_pdus: 0,
            v2: crate::cscd::PartnerV2::default(),
        }
    }

    /// The next `Members` push (conversation pushes are skipped).
    fn next_members(rx: &mut mpsc::Receiver<LacpPush>) -> Option<Vec<String>> {
        while let Ok(m) = rx.try_recv() {
            if let LacpPush::Members(m) = m {
                return Some(m.active_members);
            }
        }
        None
    }

    #[tokio::test(start_paused = true)]
    async fn pushes_are_coalesced_to_one_per_second() {
        let observations = Arc::new(Mutex::new(HashMap::new()));
        let changed = Arc::new(Notify::new());
        let selected = Arc::new(Mutex::new(HashMap::new()));
        let (tx, mut rx) = mpsc::channel(8);
        let o = observations.clone();
        let c = changed.clone();
        tokio::spawn(selection_loop(
            "bond1".into(),
            o,
            c,
            selected,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(AtomicU16::new(1)),
            V2Shared::new(),
            tx,
        ));
        let set = |d: bool| {
            observations.lock().unwrap().insert("eth1".into(), obs(d));
            changed.notify_one();
        };
        let settle = || tokio::time::sleep(Duration::from_millis(10));

        // Leading edge: first change (empty -> empty is a push of []).
        set(false);
        settle().await;
        assert_eq!(next_members(&mut rx).unwrap().len(), 0);
        // Two changes inside the window: one trailing push of the latest.
        set(true);
        settle().await;
        assert!(next_members(&mut rx).is_none());
        set(false);
        settle().await;
        set(true);
        settle().await;
        assert!(next_members(&mut rx).is_none());
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(next_members(&mut rx).unwrap(), vec!["eth1"]);
        assert!(next_members(&mut rx).is_none());
        // A change after >= 1s is pushed at once; A->B->A inside the window
        // then pushes nothing.
        tokio::time::sleep(Duration::from_secs(2)).await;
        set(false);
        settle().await;
        assert_eq!(next_members(&mut rx).unwrap().len(), 0);
        set(true);
        settle().await;
        set(false);
        settle().await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(next_members(&mut rx).is_none());
    }
    /// Steers whenever a map and a Distributing link exist, and sets
    /// `discard_wrong` only once agreed; `summary` reports the agreement and
    /// the per-link counts.
    #[tokio::test(start_paused = true)]
    async fn conversations_are_steered_and_discard_wrong_needs_agreement() {
        use crate::conversation::PortAlgorithm;
        use crate::packet::ConvDigest;
        let observations = Arc::new(Mutex::new(HashMap::new()));
        let changed = Arc::new(Notify::new());
        let v2 = V2Shared::new();
        let cfg = V2Cfg {
            version: nos_proto::LacpVersion::V2,
            algorithm: nos_proto::LacpPortAlgorithm::CVlan,
            map: Vec::new(),
            link_numbers: [("eth1".to_string(), 1)].into(),
            members: vec!["eth1".to_string()],
        };
        *v2.cfg.lock().unwrap() = cfg.clone();
        let (advert, _) = cscd::compute(&cfg);
        let (tx, mut rx) = mpsc::channel(16);
        tokio::spawn(selection_loop(
            "bond1".into(),
            observations.clone(),
            changed.clone(),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(AtomicU16::new(1)),
            v2.clone(),
            tx,
        ));
        let set = |digest: [u8; 16]| {
            let mut o = obs(true);
            o.partner = Some(PortInfo {
                system: [9; 6],
                state: state_bit::AGGREGATION | state_bit::SYNCHRONIZATION,
                ..PortInfo::ADMINISTRATIVE_DEFAULT
            });
            o.v2 = crate::cscd::PartnerV2 {
                version: Some(2),
                algorithm: Some(PortAlgorithm::CVid),
                digest: Some(ConvDigest {
                    link_number: 1,
                    digest,
                }),
            };
            observations.lock().unwrap().insert("eth1".into(), o);
            changed.notify_one();
        };
        let last_conversations = |rx: &mut mpsc::Receiver<LacpPush>| {
            let mut last = None;
            while let Ok(m) = rx.try_recv() {
                if let LacpPush::Conversations(c) = m {
                    last = Some((c.links, c.discard_wrong));
                }
            }
            last
        };

        set([0; 16]);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            v2.out.lock().unwrap().agreement,
            Agreement::Mismatch("digest")
        );
        // Mismatch: still steered, but the collection filter stays off.
        let (links, discard_wrong) = last_conversations(&mut rx).expect("steered");
        assert_eq!((links.len(), discard_wrong), (1, false));

        set(advert.digest.unwrap());
        tokio::time::sleep(Duration::from_secs(2)).await;
        let out = v2.out.lock().unwrap();
        assert_eq!(out.agreement, Agreement::Agreed);
        assert_eq!(out.conversations_per_link, vec![("eth1".to_string(), 4096)]);
        drop(out);
        let (links, discard_wrong) = last_conversations(&mut rx).expect("pushed once agreed");
        assert!(discard_wrong);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_number, 1);
        assert_eq!(
            links[0].mask.len(),
            nos_proto::interface::LACP_CONVERSATION_MASK_LEN
        );
        assert!(links[0].mask.iter().all(|b| *b == 0xff));
    }
}
