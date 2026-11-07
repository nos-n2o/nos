use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use garde::Validate as _;
use nos_proto::{
    config_path::ListPosition, diff_configs, diff_configs_for_role, schema::redact::ViewClass,
    sync_routing_table_refs, Config, ConfigDiff, ConfigOp, DiffScope, Event, Role, TransactionBase,
    TransactionSnapshot,
};
use tokio::sync::{broadcast, mpsc, Mutex, OnceCell, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::error::ConfigError;
use crate::path_edit::{self, Planned};
use crate::secrets::unmask_op;
use crate::users::{hash_clear_passwords, is_clear, normalize_names};

const BROADCAST_CAPACITY: usize = 16;
/// Set by `main` once its dhat profiler runs (`HeapStats::get` panics without
/// one); then every commit logs the live heap (#796).
#[cfg(feature = "dhat-heap")]
pub static DHAT_PROFILING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
/// Most open transactions at once; a new name past this is refused (#388).
pub const MAX_TRANSACTIONS: usize = 32;
pub const MAX_TX_NAME: usize = 64;
/// A transaction untouched this long is dropped when the next one is opened.
const TX_IDLE_TTL: Duration = Duration::from_hours(4);
/// Clear-text passwords one edit may carry: each costs an argon2id hash.
pub const MAX_CLEAR_PASSWORDS_PER_EDIT: usize = 4;

/// What [`ConfigStore::edit_transaction_path`] replies with
/// (`Event::TransactionEdit`, #774).
#[derive(Debug)]
pub struct PathEdit {
    pub generation: u64,
    pub dirty: bool,
    /// JSON text of the subsection at the edited path; `None` after a remove.
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
struct Transaction {
    /// Shared with running after `open(Current)` until the first edit.
    config: Arc<Config>,
    dirty: bool,
    /// See `TransactionSnapshot::generation`.
    generation: u64,
    /// Last open/edit/read; drives the idle sweep in `open_transaction`.
    last_used: Instant,
}

impl Transaction {
    fn snapshot(&self, name: &str, resumed: bool) -> TransactionSnapshot {
        TransactionSnapshot {
            name: name.to_string(),
            config: (*self.config).clone(),
            dirty: self.dirty,
            resumed,
            generation: self.generation,
        }
    }

    /// RFC 9110 §13.1.1: `Some(list)` must contain the current generation
    /// (an empty list never does); `None` is unconditional.
    fn check(&self, if_match: Option<&[u64]>) -> Result<(), ConfigError> {
        match if_match {
            Some(expected) if !expected.contains(&self.generation) => {
                Err(ConfigError::PreconditionFailed {
                    expected: expected.to_vec(),
                    actual: self.generation,
                })
            }
            _ => Ok(()),
        }
    }
}

/// An edit `finish_edit` hashes off-lock, then stores.
enum Edit {
    Whole(Box<Config>),
    Users(Vec<nos_proto::User>),
}

/// One committed change, broadcast to every subscriber connection — the new
/// running config, shared with `running` (no copy). `Subscribe` projects it
/// for its role (`Config::for_role`); `SubscribeDiff` takes
/// [`CommitUpdate::diff_for`]. Internal only — never sent over the wire.
///
/// A ring slot stays lean (#773): the previous config is held only until
/// every visibility class with a live diff subscriber at send time has its
/// diff, then released, so a slot keeps `config` plus delta-sized diffs.
pub(crate) struct CommitUpdate {
    pub config: Arc<Config>,
    state: std::sync::Mutex<DiffState>,
}

struct DiffState {
    /// The running config before this commit (#384); `None` once released.
    prev: Option<Arc<Config>>,
    /// Classes whose diff is still owed to a subscriber; empty releases `prev`.
    pending: HashSet<ViewClass>,
    /// One diff per visibility class, computed once for all subscribers (#751).
    diffs: HashMap<ViewClass, Arc<OnceCell<Arc<ConfigDiff>>>>,
}

impl CommitUpdate {
    /// `pending`: the visibility classes of the live diff subscribers.
    pub(crate) fn new(config: Arc<Config>, prev: Arc<Config>, pending: HashSet<ViewClass>) -> Self {
        Self {
            config,
            state: std::sync::Mutex::new(DiffState {
                prev: (!pending.is_empty()).then_some(prev),
                pending,
                diffs: HashMap::new(),
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, DiffState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The diff of `role`'s own view (a key it may not see never shows up as
    /// an Added/Modified field), shared by every role of its visibility
    /// class and computed off the runtime threads. `None` when the
    /// computation panicked, or `prev` was already released (a class not
    /// subscribed at send time): that subscriber skips this commit.
    pub(crate) async fn diff_for(self: &Arc<Self>, role: Role) -> Option<Arc<ConfigDiff>> {
        let class = ViewClass::of(role);
        let (cell, prev) = {
            let mut s = self.state();
            let cell = Arc::clone(s.diffs.entry(class).or_default());
            (cell, s.prev.clone())
        };
        let config = Arc::clone(&self.config);
        let init = || async move {
            let prev = prev.ok_or("previous config already released")?;
            tokio::task::spawn_blocking(move || {
                // No whole-config projection per class (#778).
                Arc::new(diff_configs_for_role(&prev, &config, role))
            })
            .await
            .map_err(|e| e.to_string())
        };
        let res = cell.get_or_try_init(init).await.map(Arc::clone);
        let mut s = self.state();
        if s.pending.remove(&class) && s.pending.is_empty() {
            s.prev = None;
        }
        drop(s);
        match res {
            Ok(d) => Some(d),
            Err(e) => {
                warn!(error = %e, "commit diff failed, subscribers skip this commit");
                None
            }
        }
    }
}

/// Live diff subscriber count per visibility class; dropping it unregisters.
struct DiffSubscriber {
    store: ConfigStore,
    class: ViewClass,
}

impl Drop for DiffSubscriber {
    fn drop(&mut self) {
        let mut subs = self.store.diff_subscribers();
        if let Some(n) = subs.get_mut(&self.class) {
            *n -= 1;
            if *n == 0 {
                subs.remove(&self.class);
            }
        }
    }
}

struct Inner {
    running: RwLock<Arc<Config>>,
    transactions: Mutex<HashMap<String, Transaction>>,
    tx: broadcast::Sender<Arc<CommitUpdate>>,
    /// Held across registering and `tx.subscribe()`, and across reading it
    /// and `tx.send()`, so a commit's `pending` classes are exactly those of
    /// the receivers that get it.
    diff_subscribers: std::sync::Mutex<HashMap<ViewClass, usize>>,
    config_path: Option<PathBuf>,
    idle_ttl: Duration,
}

/// A cheap, cloneable handle to the daemon's config state: the running
/// config, all named in-progress transactions, and the broadcast channel
/// used to notify subscribers of committed changes.
///
/// Lock ordering: always lock `transactions` before `running` to avoid
/// deadlock (every method below follows this).
#[derive(Clone)]
pub struct ConfigStore(Arc<Inner>);

impl ConfigStore {
    pub fn new(initial: Config, config_path: Option<PathBuf>) -> Self {
        let mut initial = initial;
        sync_routing_table_refs(&mut initial);
        // A name loaded from the file is PRECIS-normalized before a clear-text
        // password seeded in the file (or by `seed_default_user`) is hashed here.
        normalize_names(&mut initial.users);
        hash_clear_passwords(&mut initial.users, &[]);
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self(Arc::new(Inner {
            running: RwLock::new(Arc::new(initial)),
            transactions: Mutex::new(HashMap::new()),
            tx,
            diff_subscribers: std::sync::Mutex::default(),
            config_path,
            idle_ttl: TX_IDLE_TTL,
        }))
    }

    /// The running config, shared (no copy).
    pub async fn running_snapshot(&self) -> Arc<Config> {
        Arc::clone(&*self.0.running.read().await)
    }

    /// Whether the running config has a user `name`; scans under the read
    /// lock, no clone (#755).
    pub async fn user_exists(&self, name: &str) -> bool {
        self.0
            .running
            .read()
            .await
            .users
            .iter()
            .any(|u| u.name == name)
    }

    /// BGP instance names of the running config (no config clone, #759).
    pub async fn bgp_instance_names(&self) -> Vec<String> {
        let r = self.0.running.read().await;
        r.bgp_instances.iter().map(|i| i.name.clone()).collect()
    }

    /// OSPF instance names of the running config (no config clone, #759).
    pub async fn ospf_instance_names(&self) -> Vec<String> {
        let r = self.0.running.read().await;
        r.ospf_instances.iter().map(|i| i.name.clone()).collect()
    }

    /// `OSPFv3` instance names of the running config (no config clone, #759).
    pub async fn ospfv3_instance_names(&self) -> Vec<String> {
        let r = self.0.running.read().await;
        r.ospfv3_instances.iter().map(|i| i.name.clone()).collect()
    }

    /// `rest_api` pinned to routing table `table` in the running config (#759).
    pub async fn rest_api(&self, table: &str) -> Option<nos_proto::RestApi> {
        let r = self.0.running.read().await;
        r.routing_tables
            .iter()
            .find(|t| t.name == table)
            .and_then(|t| t.rest_api.clone())
    }

    fn diff_subscribers(&self) -> std::sync::MutexGuard<'_, HashMap<ViewClass, usize>> {
        self.0
            .diff_subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Hands a commit to every subscriber, owing a diff to each live class.
    fn broadcast(&self, config: Arc<Config>, prev: Arc<Config>) {
        let subs = self.diff_subscribers();
        let pending = subs.keys().copied().collect();
        // Ignore send errors — no active receivers is not a failure.
        let _ = self
            .0
            .tx
            .send(Arc::new(CommitUpdate::new(config, prev, pending)));
    }

    /// `Request::Subscribe`: forwards every later commit to `out` as
    /// `role`'s `Event::Config`, and returns the initial event (the current
    /// config) with the forwarder task (abort it to unsubscribe).
    pub async fn subscribe_config(
        &self,
        role: Role,
        out: mpsc::Sender<Event>,
    ) -> (Event, JoinHandle<()>) {
        let rx = self.0.tx.subscribe();
        let task = forward(rx, None, out, move |u| async move {
            Some(Event::Config(u.config.for_role(role)))
        });
        let initial = Event::Config(self.running_snapshot().await.for_role(role));
        (initial, task)
    }

    /// `Request::SubscribeDiff`: forwards every later commit's diff of
    /// `role`'s view, scoped, skipping empty ones; returns the initial diff
    /// (everything running, as `Added`) with the forwarder task.
    pub async fn subscribe_diff(
        &self,
        role: Role,
        scopes: Vec<DiffScope>,
        out: mpsc::Sender<Event>,
    ) -> (Event, JoinHandle<()>) {
        let class = ViewClass::of(role);
        let rx = {
            let mut subs = self.diff_subscribers();
            *subs.entry(class).or_default() += 1;
            self.0.tx.subscribe()
        };
        let guard = DiffSubscriber {
            store: self.clone(),
            class,
        };
        let task_scopes = scopes.clone();
        let task = forward(rx, Some(guard), out, move |u| {
            let wanted = task_scopes.clone();
            async move {
                let diff = u.diff_for(role).await?.scoped(&wanted);
                (!diff.is_empty()).then_some(Event::Diff(diff))
            }
        });
        let initial = Event::Diff(self.initial_diff(role).await.scoped(&scopes));
        (initial, task)
    }

    /// Serializes the running config to disk at the daemon's configured
    /// `--config-file` path. Errors if none was configured.
    pub async fn save_to_disk(&self) -> Result<(), ConfigError> {
        let path = self
            .0
            .config_path
            .as_ref()
            .ok_or(ConfigError::PersistenceNotConfigured)?;
        let cfg = self.running_snapshot().await;
        crate::persistence::save_to_disk(&cfg, path)
    }

    /// Opens a named transaction: creates it from `base` if it doesn't
    /// already exist, or resumes its current in-progress config unchanged
    /// (ignoring `base`) if it does. Creating is bounded: name charset and
    /// length, `MAX_TRANSACTIONS` open at once (idle ones are swept first).
    pub async fn open_transaction(
        &self,
        name: &str,
        base: TransactionBase,
    ) -> Result<TransactionSnapshot, ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        let ttl = self.0.idle_ttl;
        txs.retain(|_, t| t.last_used.elapsed() <= ttl);
        if let Some(existing) = txs.get_mut(name) {
            existing.last_used = Instant::now();
            debug!(transaction = %name, resumed = true, "opened transaction");
            return Ok(existing.snapshot(name, true));
        }
        if name.is_empty()
            || name.len() > MAX_TX_NAME
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(ConfigError::InvalidTransactionName);
        }
        if txs.len() >= MAX_TRANSACTIONS {
            return Err(ConfigError::TooManyTransactions(MAX_TRANSACTIONS));
        }
        let config = match base {
            TransactionBase::Blank => Arc::new(Config::default()),
            TransactionBase::Current => self.running_snapshot().await,
        };
        let txn = Transaction {
            config,
            dirty: false,
            generation: 0,
            last_used: Instant::now(),
        };
        let snap = txn.snapshot(name, false);
        txs.insert(name.to_string(), txn);
        debug!(transaction = %name, ?base, resumed = false, "opened transaction");
        Ok(snap)
    }

    /// Applies one edit to a named transaction's in-progress config. Never
    /// runs `garde` validation — only `commit_transaction` does.
    pub async fn apply_op(
        &self,
        name: &str,
        op: ConfigOp,
    ) -> Result<TransactionSnapshot, ConfigError> {
        let (base, generation) = self.checkout(name, None).await?;
        // The kind only: an op may carry a secret (and `?op` goes to `nos-logd`).
        debug!(transaction = %name, op = op.kind(), "applying op");
        let op = unmask_op(op, &[&base, &*self.running_snapshot().await])?;
        let users_before = base.users.clone();
        // ponytail: one Config copy per op, since an op may fail half-applied
        // and has no plan step; only the shell sends ops (REST/provision PUTs
        // are O(edit), #775). Fix: a per-op section snapshot to roll back.
        let mut config = (*base).clone();
        drop(base);
        op.apply(&mut config)?;
        self.finish_edit(
            name,
            Edit::Whole(Box::new(config)),
            users_before,
            generation,
            |t, n| t.snapshot(n, true),
        )
        .await
    }

    /// Sets or removes the subsection of a named transaction's in-progress
    /// config addressed by `path` (see `nos_proto::config_path`). Atomic: a
    /// failed edit changes nothing. Costs the addressed section (one element
    /// of a top-level list, one static route), not the config (#775). Never
    /// runs `garde` validation.
    /// `if_match` refuses the edit once the generation has moved on.
    pub async fn set_transaction_path(
        &self,
        name: &str,
        path: &[String],
        value: Option<&str>,
        if_match: Option<Vec<u64>>,
        position: Option<ListPosition>,
    ) -> Result<TransactionSnapshot, ConfigError> {
        self.edit_path(name, path, value, if_match, position, |t, n| {
            t.snapshot(n, true)
        })
        .await
    }

    /// [`Self::set_transaction_path`] without the full-config snapshot
    /// reply (#774): the new generation and the edited subsection, which
    /// costs that subsection, not the config.
    pub async fn edit_transaction_path(
        &self,
        name: &str,
        path: &[String],
        value: Option<&str>,
        if_match: Option<Vec<u64>>,
        position: Option<ListPosition>,
    ) -> Result<PathEdit, ConfigError> {
        let set = value.is_some();
        self.edit_path(name, path, value, if_match, position, |t, _| {
            Ok(PathEdit {
                generation: t.generation,
                dirty: t.dirty,
                value: set
                    .then(|| path_edit::get(&t.config, path).map(|v| v.to_string()))
                    .transpose()?,
            })
        })
        .await?
    }

    /// O(edit) (#775): the edit is planned on the shared config under the
    /// lock, then applied in place (`Arc::make_mut`: the first edit after
    /// `open(Current)` copies once, later ones don't). A user-list edit
    /// hashes off-lock through `finish_edit`.
    async fn edit_path<R>(
        &self,
        name: &str,
        path: &[String],
        value: Option<&str>,
        if_match: Option<Vec<u64>>,
        position: Option<ListPosition>,
        reply: impl FnOnce(&Transaction, &str) -> R,
    ) -> Result<R, ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        let txn = txs
            .get_mut(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        txn.check(if_match.as_deref())?;
        txn.last_used = Instant::now();
        let json = value.map(serde_json::from_str).transpose()?;
        let running = self.running_snapshot().await;
        let planned = path_edit::plan(&txn.config, &running, path, json, position.as_ref())?;
        drop(running);
        debug!(transaction = %name, path = %path.join("/"), remove = value.is_none(), "set transaction path");
        let edit = match planned {
            Planned::Apply(apply) => {
                apply(Arc::make_mut(&mut txn.config));
                txn.dirty = true;
                txn.generation += 1;
                return Ok(reply(txn, name));
            }
            Planned::Users(users) => Edit::Users(users),
            Planned::Whole(config) => Edit::Whole(config),
        };
        let (users_before, generation) = (txn.config.users.clone(), txn.generation);
        drop(txs);
        self.finish_edit(name, edit, users_before, generation, reply)
            .await
    }

    /// Shares a transaction's config out under the lock (checking `if_match`,
    /// no copy), so the edit and the argon2 hashing run with no lock held.
    async fn checkout(
        &self,
        name: &str,
        if_match: Option<Vec<u64>>,
    ) -> Result<(Arc<Config>, u64), ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        let txn = txs
            .get_mut(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        txn.check(if_match.as_deref())?;
        txn.last_used = Instant::now();
        Ok((Arc::clone(&txn.config), txn.generation))
    }

    /// PRECIS-normalizes every user name, hashes any clear-text password (on
    /// the blocking pool, reusing a matching hash from the transaction's
    /// previous users or the running config), then stores `config` unless the
    /// transaction moved past `generation` meanwhile (a retryable
    /// `PreconditionFailed`, like a stale `if_match`).
    async fn finish_edit<R>(
        &self,
        name: &str,
        mut edit: Edit,
        users_before: Vec<nos_proto::User>,
        generation: u64,
        reply: impl FnOnce(&Transaction, &str) -> R,
    ) -> Result<R, ConfigError> {
        let users = match &mut edit {
            Edit::Whole(config) => &mut config.users,
            Edit::Users(users) => users,
        };
        normalize_names(users);
        let clear = users.iter().filter(|u| is_clear(u)).count();
        if clear > MAX_CLEAR_PASSWORDS_PER_EDIT {
            return Err(ConfigError::TooManyClearPasswords(
                MAX_CLEAR_PASSWORDS_PER_EDIT,
            ));
        }
        if clear > 0 {
            let running = self.0.running.read().await.users.clone();
            let mut taken = std::mem::take(users);
            *users = tokio::task::spawn_blocking(move || {
                hash_clear_passwords(&mut taken, &[&users_before, &running]);
                taken
            })
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        let mut txs = self.0.transactions.lock().await;
        let txn = txs
            .get_mut(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        txn.check(Some(&[generation]))?;
        match edit {
            Edit::Whole(config) => txn.config = Arc::new(*config),
            Edit::Users(users) => Arc::make_mut(&mut txn.config).users = users,
        }
        txn.dirty = true;
        txn.generation += 1;
        txn.last_used = Instant::now();
        Ok(reply(txn, name))
    }

    pub async fn get_transaction(&self, name: &str) -> Result<TransactionSnapshot, ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        let txn = txs
            .get_mut(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        txn.last_used = Instant::now();
        Ok(txn.snapshot(name, true))
    }

    /// Validates the named transaction and, if valid, atomically promotes it
    /// to running, broadcasts the change to subscribers, and removes the
    /// transaction. If invalid (or `if_match` names a stale generation), the
    /// transaction is left intact so the caller can keep editing and retry.
    pub async fn commit_transaction(
        &self,
        name: &str,
        if_match: Option<Vec<u64>>,
    ) -> Result<Vec<String>, ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        let txn = txs
            .get(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        txn.check(if_match.as_deref())?;
        // Pass the config itself as the validation context (cross-reference checks).
        txn.config.validate_with(&txn.config)?;
        check_syslog_trust_anchors(&txn.config)?;
        if txn.config.users.is_empty() && !self.0.running.read().await.users.is_empty() {
            return Err(ConfigError::NoUsersLeft);
        }
        let mut config = txs
            .remove(name)
            .map(|t| t.config)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?;
        drop(txs);
        // Unshared once the transaction is gone (no copy), unless it was never
        // edited since `open(Current)`; the same Arc then becomes running.
        sync_routing_table_refs(Arc::make_mut(&mut config));
        let warnings = crate::warnings::commit_warnings(&config);

        let mut running = self.0.running.write().await;
        let prev = std::mem::replace(&mut *running, Arc::clone(&config));
        drop(running);
        info!(transaction = %name, "config committed");
        self.broadcast(config, prev);
        #[cfg(feature = "dhat-heap")]
        if DHAT_PROFILING.load(std::sync::atomic::Ordering::Relaxed) {
            let s = dhat::HeapStats::get();
            info!(
                curr_bytes = s.curr_bytes,
                max_bytes = s.max_bytes,
                "heap after commit"
            );
        }
        Ok(warnings)
    }

    /// Swaps `user`'s password hash `old` for `new` in the running config
    /// (see `Request::UpgradePasswordHash`), broadcasting it like a commit.
    pub async fn upgrade_password_hash(
        &self,
        user: &str,
        old: &str,
        new: String,
    ) -> Result<(), ConfigError> {
        if !nos_password::is_hash(&new) {
            return Err(ConfigError::HashUpgradeRefused);
        }
        let mut running = self.0.running.write().await;
        let Some(i) = running
            .users
            .iter()
            .position(|u| u.name == user && u.password == old)
        else {
            return Err(ConfigError::HashUpgradeRefused);
        };
        // Copies once: `prev` must stay intact for the diff subscribers.
        let mut config = Arc::clone(&running);
        Arc::make_mut(&mut config).users[i].password = new;
        let prev = std::mem::replace(&mut *running, Arc::clone(&config));
        drop(running);
        info!(user = ?user, "password hash upgraded");
        self.broadcast(config, prev);
        Ok(())
    }

    /// The diff a fresh `SubscribeDiff` connection should see as its initial
    /// event: everything currently in the running config, reported as
    /// `Added` (diffing against an empty config can never produce
    /// `Removed`/`Modified`).
    pub(crate) async fn initial_diff(&self, role: nos_proto::Role) -> ConfigDiff {
        diff_configs_for_role(&Config::default(), &*self.running_snapshot().await, role)
    }

    /// Computes the structural difference between the running config and a
    /// named transaction's in-progress config. Runs no validation — matches
    /// `get_transaction`'s behavior, so an invalid in-progress config can
    /// still be diffed.
    pub async fn diff_transaction(&self, name: &str) -> Result<ConfigDiff, ConfigError> {
        let txs = self.0.transactions.lock().await;
        let candidate = Arc::clone(
            &txs.get(name)
                .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?
                .config,
        );
        drop(txs);
        let running = self.running_snapshot().await;
        Ok(diff_configs(&running, &candidate))
    }

    /// Deletes a named transaction without touching the running config
    /// (refused, and kept, if `if_match` names a stale generation).
    pub async fn discard_transaction(
        &self,
        name: &str,
        if_match: Option<Vec<u64>>,
    ) -> Result<(), ConfigError> {
        let mut txs = self.0.transactions.lock().await;
        txs.get(name)
            .ok_or_else(|| ConfigError::TransactionNotFound(name.to_string()))?
            .check(if_match.as_deref())?;
        txs.remove(name);
        debug!(transaction = %name, "discarded transaction");
        Ok(())
    }

    /// Binds the given address and starts the IPC server in the background.
    ///
    /// Returns a `JoinHandle` — keep it alive for the server to continue running.
    pub fn start_ipc_server(
        &self,
        addr: &crate::server::ListenAddr,
        identity: &nos_pki::Identity,
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
        crate::server::start(addr, self.clone(), identity)
    }
}

/// Bridges the store's commit broadcast to one subscriber's `mpsc`.
/// `to_event` builds the event this subscriber wants from each commit;
/// `None` skips it (how a `SubscribeDiff` subscriber is never woken for a
/// commit outside its scopes). `guard` lives as long as the task.
fn forward<Fut>(
    mut rx: broadcast::Receiver<Arc<CommitUpdate>>,
    guard: Option<DiffSubscriber>,
    tx: mpsc::Sender<Event>,
    to_event: impl Fn(Arc<CommitUpdate>) -> Fut + Send + 'static,
) -> JoinHandle<()>
where
    Fut: std::future::Future<Output = Option<Event>> + Send,
{
    tokio::spawn(async move {
        let _guard = guard;
        loop {
            match rx.recv().await {
                Ok(update) => {
                    let Some(event) = to_event(update).await else {
                        continue;
                    };
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(lagged = n, "IPC subscriber lagged, dropped messages");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// A syslog server's `trust_anchor` must parse as PEM certificates. Done here,
/// not in `nos-proto`'s garde rules: proto must not gain an X.509 crate (the
/// same split as password hashing).
fn check_syslog_trust_anchors(config: &Config) -> Result<(), ConfigError> {
    for s in &config.logging.syslog {
        if let Some(pem) = s.tls.as_ref().and_then(|t| t.trust_anchor.as_deref()) {
            nos_pki::syslog::parse_trust_anchor(pem).map_err(|e| {
                ConfigError::SyslogTrustAnchor {
                    server: s.name.clone(),
                    reason: e.to_string(),
                }
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nos_proto::{BgpInstance, BgpInstanceOp};

    use super::*;

    /// #755: `user_exists` follows the running config, not open transactions.
    #[tokio::test]
    async fn user_exists_tracks_the_running_config() {
        let store = ConfigStore::new(
            Config {
                users: vec![nos_proto::User {
                    name: "alice".into(),
                    password: "pw".into(),
                }],
                ..Config::default()
            },
            None,
        );
        assert!(store.user_exists("alice").await);
        assert!(!store.user_exists("bob").await);
        store
            .open_transaction("t", nos_proto::TransactionBase::Current)
            .await
            .unwrap();
        store
            .apply_op(
                "t",
                nos_proto::ConfigOp::User(nos_proto::UserOp::SetPassword {
                    name: "bob".into(),
                    password: "pw".into(),
                }),
            )
            .await
            .unwrap();
        assert!(!store.user_exists("bob").await, "uncommitted");
        store.commit_transaction("t", None).await.unwrap();
        assert!(store.user_exists("bob").await);
        store
            .open_transaction("d", nos_proto::TransactionBase::Current)
            .await
            .unwrap();
        store
            .apply_op(
                "d",
                nos_proto::ConfigOp::User(nos_proto::UserOp::Delete {
                    name: "alice".into(),
                }),
            )
            .await
            .unwrap();
        store.commit_transaction("d", None).await.unwrap();
        assert!(!store.user_exists("alice").await);
    }

    fn update_adding_a_user() -> Arc<CommitUpdate> {
        let user = nos_proto::User {
            name: "u".into(),
            password: "hash".into(),
        };
        let pending = [Role::User, Role::Bgpd, Role::Watchdog]
            .into_iter()
            .map(ViewClass::of)
            .collect();
        Arc::new(CommitUpdate::new(
            Arc::new(Config {
                users: vec![user],
                ..Config::default()
            }),
            Arc::default(),
            pending,
        ))
    }

    /// #751: concurrent subscribers of one visibility class share one
    /// computation; a role that cannot see `users` never sees the change.
    #[tokio::test]
    async fn diff_for_is_computed_once_per_visibility_class() {
        let u = update_adding_a_user();
        let (user, restd, bgpd1, bgpd2, wd) = tokio::join!(
            u.diff_for(Role::User),
            u.diff_for(Role::Restd),
            u.diff_for(Role::Bgpd),
            u.diff_for(Role::Bgpd),
            u.diff_for(Role::Watchdog),
        );
        let (user, restd) = (user.unwrap(), restd.unwrap());
        let (bgpd1, bgpd2, wd) = (bgpd1.unwrap(), bgpd2.unwrap(), wd.unwrap());
        assert!(
            Arc::ptr_eq(&user, &restd),
            "User and Restd see the same config"
        );
        assert!(Arc::ptr_eq(&bgpd1, &bgpd2));
        assert!(!Arc::ptr_eq(&user, &bgpd1));
        assert_eq!(user.users.len(), 1);
        assert_eq!(wd.users.len(), 1);
        assert!(
            bgpd1.is_empty(),
            "bgpd must not see a user change: {bgpd1:?}"
        );
        let s = u.state();
        assert_eq!(s.diffs.len(), 3);
        assert!(
            s.prev.is_none(),
            "prev released once every owed diff exists"
        );
    }

    /// #773: `prev` stays until the last owed class has its diff; a commit
    /// with no diff subscriber keeps no `prev` at all.
    #[tokio::test]
    async fn prev_is_released_after_the_owed_diffs() {
        let u = update_adding_a_user();
        u.diff_for(Role::User).await.unwrap();
        u.diff_for(Role::Bgpd).await.unwrap();
        assert!(u.state().prev.is_some(), "Watchdog's diff still owed");
        u.diff_for(Role::Watchdog).await.unwrap();
        assert!(u.state().prev.is_none());
        // A class nobody owed after the release: skipped, not a stale diff.
        assert!(u.diff_for(Role::Ospfd).await.is_none());
        let lone = CommitUpdate::new(Arc::default(), Arc::default(), HashSet::new());
        assert!(lone.state().prev.is_none());
    }

    /// #773: the store registers each live diff subscriber's class, so a
    /// commit owes exactly those diffs, and unregisters on unsubscribe.
    #[tokio::test]
    async fn subscribe_diff_registers_its_class_until_dropped() {
        let store = ConfigStore::new(Config::default(), None);
        let (out, mut rx) = mpsc::channel(4);
        let (initial, task) = store
            .subscribe_diff(Role::User, vec![DiffScope::Hostname], out)
            .await;
        assert!(matches!(initial, Event::Diff(_)));
        store
            .open_transaction("t", TransactionBase::Current)
            .await
            .unwrap();
        store
            .set_transaction_path("t", &segs("hostname"), Some("\"h\""), None, None)
            .await
            .unwrap();
        store.commit_transaction("t", None).await.unwrap();
        let Some(Event::Diff(d)) = rx.recv().await else {
            panic!("no diff")
        };
        assert!(!d.is_empty());
        assert_eq!(
            store.diff_subscribers().get(&ViewClass::of(Role::User)),
            Some(&1)
        );
        task.abort();
        let _ = task.await;
        assert!(store.diff_subscribers().is_empty());
    }

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(10, 0, 0, 1),
            asn,
            peer_groups: Vec::new(),
            peers: Vec::new(),
            cluster_id: None,
            maximum_paths: None,
            confederation: nos_proto::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            bmp_stations: Vec::new(),
            aggregates: Vec::new(),
            graceful_restart: nos_proto::BgpGracefulRestart::default(),
            routing_table: None,
            redistribute_policy: None,
        }
    }

    fn set_asn_op(name: &str, asn: u32) -> ConfigOp {
        ConfigOp::BgpInstance(BgpInstanceOp::SetAsn {
            name: name.to_string(),
            asn,
        })
    }

    fn ensure_op(name: &str) -> ConfigOp {
        ConfigOp::BgpInstance(BgpInstanceOp::Ensure {
            name: name.to_string(),
        })
    }

    fn ensure_routing_table_op(name: &str) -> ConfigOp {
        ConfigOp::RoutingTable(nos_proto::RoutingTableOp::Ensure {
            name: name.to_string(),
        })
    }

    fn set_routing_table_bgp_instance_op(name: &str, bgp_instance: &str) -> ConfigOp {
        ConfigOp::RoutingTable(nos_proto::RoutingTableOp::SetBgpInstance {
            name: name.to_string(),
            bgp_instance: bgp_instance.to_string(),
        })
    }

    fn set_routing_table_static_routing_instance_op(name: &str, sri: &str) -> ConfigOp {
        ConfigOp::RoutingTable(nos_proto::RoutingTableOp::SetStaticRoutingInstance {
            name: name.to_string(),
            static_routing_instance: sri.to_string(),
        })
    }

    fn ensure_static_routing_instance_op(name: &str) -> ConfigOp {
        ConfigOp::StaticRoutingInstance(nos_proto::StaticRoutingInstanceOp::Ensure {
            name: name.to_string(),
        })
    }

    fn segs(p: &str) -> Vec<String> {
        p.split('/')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    }

    #[tokio::test]
    async fn set_transaction_path_threads_the_list_position() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t", TransactionBase::Blank)
            .await
            .unwrap();
        let put = |name: &'static str, pos: Option<ListPosition>| {
            let store = store.clone();
            async move {
                let body = serde_json::to_string(&instance(name, 1)).unwrap();
                store
                    .set_transaction_path(
                        "t",
                        &segs(&format!("bgp-instance/{name}")),
                        Some(&body),
                        None,
                        pos,
                    )
                    .await
            }
        };
        put("a", None).await.unwrap();
        put("b", None).await.unwrap();
        put("c", Some(ListPosition::First)).await.unwrap();
        let snap = put("a", Some(ListPosition::After("b".into())))
            .await
            .unwrap();
        let order: Vec<_> = snap
            .config
            .bgp_instances
            .iter()
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(order, ["c", "b", "a"]);
        // An unknown anchor is refused and changes nothing.
        assert!(put("a", Some(ListPosition::Before("zz".into())))
            .await
            .is_err());
        // A position without a value is refused.
        let err = store
            .set_transaction_path(
                "t",
                &segs("bgp-instance/a"),
                None,
                None,
                Some(ListPosition::Last),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("needs a value"), "{err}");
        let snap = store.get_transaction("t").await.unwrap();
        assert_eq!(snap.config.bgp_instances.len(), 3);
    }

    #[tokio::test]
    async fn set_transaction_path_sets_subsection_and_marks_dirty() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t", TransactionBase::Blank)
            .await
            .unwrap();
        let body = serde_json::to_string(&instance("r1", 65000)).unwrap();
        let snap = store
            .set_transaction_path("t", &segs("bgp-instance/r1"), Some(&body), None, None)
            .await
            .unwrap();
        assert!(snap.dirty);
        assert_eq!(snap.config.bgp_instances.len(), 1);

        let snap = store
            .set_transaction_path("t", &segs("hostname"), Some("\"rest-host\""), None, None)
            .await
            .unwrap();
        assert_eq!(snap.config.hostname, "rest-host");

        let snap = store
            .set_transaction_path("t", &segs("bgp-instance/r1"), None, None, None)
            .await
            .unwrap();
        assert_eq!(snap.config.bgp_instances, [] as [nos_proto::BgpInstance; 0]);
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );
    }

    #[tokio::test]
    async fn set_transaction_path_whole_config_and_failures_leave_it_untouched() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t", TransactionBase::Blank)
            .await
            .unwrap();
        let whole = Config {
            hostname: "whole".to_string(),
            bgp_instances: vec![instance("r1", 1)],
            ..Default::default()
        };
        store
            .set_transaction_path(
                "t",
                &[],
                Some(&serde_json::to_string(&whole).unwrap()),
                None,
                None,
            )
            .await
            .unwrap();

        // Type mismatch: rejected, transaction unchanged.
        assert!(store
            .set_transaction_path("t", &segs("hostname"), Some("42"), None, None)
            .await
            .is_err());
        // Unknown path / unknown transaction.
        assert!(store
            .set_transaction_path("t", &segs("nope"), Some("1"), None, None)
            .await
            .is_err());
        assert!(store
            .set_transaction_path("missing", &[], Some("{}"), None, None)
            .await
            .is_err());
        assert_eq!(store.get_transaction("t").await.unwrap().config, whole);
    }

    #[tokio::test]
    async fn new_derives_routing_table_refs_from_initial_config() {
        let store = ConfigStore::new(
            Config {
                bgp_instances: vec![instance("r1", 65000)],
                routing_tables: vec![nos_proto::RoutingTable {
                    rest_api: None,
                    evpn: nos_proto::RoutingTableEvpn::default(),
                    vpn: nos_proto::RoutingTableVpn::default(),
                    ospfv3_instance: None,
                    name: "rt1".to_string(),
                    bgp_instance: Some("r1".to_string()),
                    ospf_instance: None,
                    static_routing_instance: None,
                    redistribute: Vec::new(),
                }],
                ..Default::default()
            },
            None,
        );
        let running = store.running_snapshot().await;
        assert_eq!(
            running.bgp_instances[0].routing_table.as_deref(),
            Some("rt1")
        );
    }

    #[tokio::test]
    async fn open_blank_starts_empty_even_if_running_is_not() {
        let store = ConfigStore::new(
            Config {
                bgp_instances: vec![instance("default", 65000)],
                ..Default::default()
            },
            None,
        );
        let snap = store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        assert_eq!(snap.config.bgp_instances, [] as [nos_proto::BgpInstance; 0]);
        assert!(!snap.dirty);
        assert!(!snap.resumed);
    }

    #[tokio::test]
    async fn open_current_clones_running() {
        let store = ConfigStore::new(
            Config {
                bgp_instances: vec![instance("default", 65000)],
                ..Default::default()
            },
            None,
        );
        let snap = store
            .open_transaction("t1", TransactionBase::Current)
            .await
            .unwrap();
        assert_eq!(snap.config.bgp_instances.len(), 1);
        assert!(!snap.resumed);
    }

    #[tokio::test]
    async fn reopen_resumes_existing_transaction_and_ignores_base() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        store.apply_op("t1", ensure_op("r1")).await.unwrap();

        let snap = store
            .open_transaction("t1", TransactionBase::Current)
            .await
            .unwrap();
        assert!(snap.resumed);
        assert!(snap.dirty);
        assert_eq!(snap.config.bgp_instances.len(), 1);
        assert_eq!(snap.config.bgp_instances[0].name, "r1");
    }

    #[tokio::test]
    async fn apply_op_updates_transaction_leaves_running_unchanged() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        let snap = store.apply_op("t1", ensure_op("r1")).await.unwrap();
        assert_eq!(snap.config.bgp_instances.len(), 1);
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );
    }

    #[tokio::test]
    async fn apply_op_missing_transaction_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        let err = store
            .apply_op("missing", ensure_op("r1"))
            .await
            .unwrap_err();
        assert!(matches!(err, ConfigError::TransactionNotFound(n) if n == "missing"));
    }

    #[tokio::test]
    async fn commit_valid_transaction_updates_running_and_removes_transaction() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        store.apply_op("t1", ensure_op("r1")).await.unwrap();
        store.apply_op("t1", set_asn_op("r1", 65000)).await.unwrap();

        store.commit_transaction("t1", None).await.unwrap();

        let running = store.running_snapshot().await;
        assert_eq!(running.bgp_instances.len(), 1);
        assert_eq!(running.bgp_instances[0].name, "r1");
        assert!(matches!(
            store.get_transaction("t1").await,
            Err(ConfigError::TransactionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn commit_invalid_transaction_leaves_running_unchanged_and_keeps_transaction_alive() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        // ASN 0 is invalid, and Ensure leaves asn at the placeholder 0.
        store.apply_op("t1", ensure_op("bad")).await.unwrap();

        assert!(store.commit_transaction("t1", None).await.is_err());
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );

        // The transaction must still be there, editable, for a retry.
        let snap = store.get_transaction("t1").await.unwrap();
        assert_eq!(snap.config.bgp_instances.len(), 1);
    }

    #[tokio::test]
    async fn commit_missing_transaction_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        assert!(matches!(
            store.commit_transaction("missing", None).await,
            Err(ConfigError::TransactionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn diff_transaction_reports_changes_against_running() {
        let store = ConfigStore::new(
            Config {
                bgp_instances: vec![instance("r1", 65000)],
                ..Default::default()
            },
            None,
        );
        store
            .open_transaction("t1", TransactionBase::Current)
            .await
            .unwrap();
        store.apply_op("t1", set_asn_op("r1", 65001)).await.unwrap();

        let diff = store.diff_transaction("t1").await.unwrap();
        assert_eq!(diff.bgp_instances.len(), 1);
        assert_eq!(diff.bgp_instances[0].header, "bgp instance r1");
    }

    #[tokio::test]
    async fn diff_transaction_missing_transaction_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        assert!(matches!(
            store.diff_transaction("missing").await,
            Err(ConfigError::TransactionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn discard_removes_transaction_without_touching_running() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        store.apply_op("t1", ensure_op("r1")).await.unwrap();

        store.discard_transaction("t1", None).await.unwrap();

        assert!(matches!(
            store.get_transaction("t1").await,
            Err(ConfigError::TransactionNotFound(_))
        ));
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );
    }

    #[tokio::test]
    async fn generation_counts_edits_and_a_stale_if_match_is_refused_untouched() {
        let store = ConfigStore::new(Config::default(), None);
        assert_eq!(
            store
                .open_transaction("t", TransactionBase::Blank)
                .await
                .unwrap()
                .generation,
            0
        );
        assert_eq!(
            store
                .apply_op("t", ensure_op("r1"))
                .await
                .unwrap()
                .generation,
            1
        );
        // A matching precondition passes and bumps; `None` is unconditional.
        let snap = store
            .set_transaction_path("t", &segs("hostname"), Some("\"h1\""), Some(vec![1]), None)
            .await
            .unwrap();
        assert_eq!(snap.generation, 2);
        let snap = store
            .set_transaction_path("t", &segs("hostname"), Some("\"h2\""), None, None)
            .await
            .unwrap();
        assert_eq!(snap.generation, 3);

        // Stale: refused, nothing changed, the transaction stays.
        let stale = Some(vec![2]);
        assert!(matches!(
            store
                .set_transaction_path("t", &segs("hostname"), Some("\"h3\""), stale.clone(), None)
                .await,
            Err(ConfigError::PreconditionFailed { ref expected, actual: 3 }) if expected == &[2]
        ));
        // An empty list never matches (a list with the current entry does: see discard below).
        assert!(matches!(
            store.commit_transaction("t", Some(vec![])).await,
            Err(ConfigError::PreconditionFailed { .. })
        ));
        assert!(matches!(
            store.commit_transaction("t", stale.clone()).await,
            Err(ConfigError::PreconditionFailed { .. })
        ));
        assert!(matches!(
            store.discard_transaction("t", stale).await,
            Err(ConfigError::PreconditionFailed { .. })
        ));
        let snap = store.get_transaction("t").await.unwrap();
        assert_eq!((snap.generation, snap.config.hostname.as_str()), (3, "h2"));
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );

        // Current: discard goes through.
        store
            .discard_transaction("t", Some(vec![2, 3]))
            .await
            .unwrap();
        assert!(matches!(
            store.get_transaction("t").await,
            Err(ConfigError::TransactionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn discard_missing_transaction_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        assert!(matches!(
            store.discard_transaction("missing", None).await,
            Err(ConfigError::TransactionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn commit_refuses_a_malformed_syslog_trust_anchor() {
        use nos_proto::{LoggingOp, SyslogTransport};
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        let name = || "c1".to_string();
        for op in [
            LoggingOp::EnsureSyslog { name: name() },
            LoggingOp::SetSyslogAddress {
                name: name(),
                address: "192.0.2.9".parse().unwrap(),
            },
            LoggingOp::SetSyslogTransport {
                name: name(),
                transport: SyslogTransport::Tls,
            },
            LoggingOp::SetSyslogTlsTrustAnchor {
                name: name(),
                pem: Some("not a certificate".into()),
            },
        ] {
            store.apply_op("t1", ConfigOp::Logging(op)).await.unwrap();
        }
        let err = store.commit_transaction("t1", None).await.unwrap_err();
        assert!(
            matches!(err, ConfigError::SyslogTrustAnchor { .. }),
            "{err}"
        );
    }

    /// `ConfigOp` cannot construct two `BgpInstance`s with the same name
    /// through the public op API (`Ensure` is idempotent per name), so this
    /// seeds the duplicate directly into the transaction map (test-only
    /// access via `super::*`) to confirm `garde` validation genuinely still
    /// runs at commit regardless of how the transaction's `Config` was
    /// populated.
    #[tokio::test]
    async fn commit_duplicate_names_returns_error() {
        let store = ConfigStore::new(Config::default(), None);
        let bad_config = Config {
            bgp_instances: vec![instance("vrf-a", 65001), instance("vrf-a", 65002)],
            ..Default::default()
        };
        store.0.transactions.lock().await.insert(
            "t1".to_string(),
            Transaction {
                config: Arc::new(bad_config),
                dirty: true,
                generation: 0,
                last_used: Instant::now(),
            },
        );

        assert!(store.commit_transaction("t1", None).await.is_err());
        assert_eq!(
            store.running_snapshot().await.bgp_instances,
            [] as [nos_proto::BgpInstance; 0]
        );
    }

    #[tokio::test]
    async fn routing_table_with_both_associations_round_trips_through_commit() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        store.apply_op("t1", ensure_op("r1")).await.unwrap();
        store.apply_op("t1", set_asn_op("r1", 65000)).await.unwrap();
        store
            .apply_op("t1", ensure_static_routing_instance_op("sri1"))
            .await
            .unwrap();
        store
            .apply_op("t1", ensure_routing_table_op("rt1"))
            .await
            .unwrap();
        store
            .apply_op("t1", set_routing_table_bgp_instance_op("rt1", "r1"))
            .await
            .unwrap();
        store
            .apply_op(
                "t1",
                set_routing_table_static_routing_instance_op("rt1", "sri1"),
            )
            .await
            .unwrap();

        store.commit_transaction("t1", None).await.unwrap();

        let running = store.running_snapshot().await;
        assert_eq!(running.routing_tables.len(), 1);
        assert_eq!(
            running.routing_tables[0].bgp_instance.as_deref(),
            Some("r1")
        );
        assert_eq!(
            running.bgp_instances[0].routing_table.as_deref(),
            Some("rt1"),
            "commit must derive the reflexive BgpInstance.routing_table reference"
        );
        assert_eq!(
            running.routing_tables[0].static_routing_instance.as_deref(),
            Some("sri1")
        );
    }

    #[tokio::test]
    async fn commit_fails_when_routing_table_references_missing_bgp_instance() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        store
            .apply_op("t1", ensure_routing_table_op("rt1"))
            .await
            .unwrap();
        store
            .apply_op(
                "t1",
                set_routing_table_bgp_instance_op("rt1", "does-not-exist"),
            )
            .await
            .unwrap();

        assert!(store.commit_transaction("t1", None).await.is_err());
        assert_eq!(
            store.running_snapshot().await.routing_tables,
            [] as [nos_proto::RoutingTable; 0]
        );
    }

    #[tokio::test]
    async fn commit_fails_when_two_routing_tables_claim_same_bgp_instance() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        store.apply_op("t1", ensure_op("r1")).await.unwrap();
        store
            .apply_op("t1", ensure_routing_table_op("rt1"))
            .await
            .unwrap();
        store
            .apply_op("t1", ensure_routing_table_op("rt2"))
            .await
            .unwrap();
        store
            .apply_op("t1", set_routing_table_bgp_instance_op("rt1", "r1"))
            .await
            .unwrap();
        store
            .apply_op("t1", set_routing_table_bgp_instance_op("rt2", "r1"))
            .await
            .unwrap();

        assert!(store.commit_transaction("t1", None).await.is_err());
        assert_eq!(
            store.running_snapshot().await.routing_tables,
            [] as [nos_proto::RoutingTable; 0]
        );
    }

    #[tokio::test]
    async fn commit_fails_when_two_routing_tables_claim_same_static_routing_instance() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        store
            .apply_op("t1", ensure_static_routing_instance_op("sri1"))
            .await
            .unwrap();
        store
            .apply_op("t1", ensure_routing_table_op("rt1"))
            .await
            .unwrap();
        store
            .apply_op("t1", ensure_routing_table_op("rt2"))
            .await
            .unwrap();
        store
            .apply_op(
                "t1",
                set_routing_table_static_routing_instance_op("rt1", "sri1"),
            )
            .await
            .unwrap();
        store
            .apply_op(
                "t1",
                set_routing_table_static_routing_instance_op("rt2", "sri1"),
            )
            .await
            .unwrap();

        assert!(store.commit_transaction("t1", None).await.is_err());
        assert_eq!(
            store.running_snapshot().await.routing_tables,
            [] as [nos_proto::RoutingTable; 0]
        );
    }

    #[tokio::test]
    async fn static_routing_instance_with_route_round_trips_through_commit() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t1", TransactionBase::Blank)
            .await
            .unwrap();
        store
            .apply_op("t1", ensure_static_routing_instance_op("sri1"))
            .await
            .unwrap();
        store
            .apply_op(
                "t1",
                ConfigOp::StaticRoute(nos_proto::StaticRouteOp::Set {
                    instance: "sri1".to_string(),
                    subnet: "10.0.0.0/24".parse().unwrap(),
                    gateway: "10.0.0.1".parse().unwrap(),
                }),
            )
            .await
            .unwrap();

        store.commit_transaction("t1", None).await.unwrap();

        let running = store.running_snapshot().await;
        assert_eq!(running.static_routing_instances.len(), 1);
        assert_eq!(running.static_routing_instances[0].routes.len(), 1);
    }

    fn set_password_op(name: &str, password: &str) -> ConfigOp {
        ConfigOp::User(nos_proto::UserOp::SetPassword {
            name: name.to_string(),
            password: password.to_string(),
        })
    }

    async fn commit_password(store: &ConfigStore, tx: &str, name: &str, password: &str) {
        store
            .open_transaction(tx, TransactionBase::Current)
            .await
            .unwrap();
        store
            .apply_op(tx, set_password_op(name, password))
            .await
            .unwrap();
        store.commit_transaction(tx, None).await.unwrap();
    }

    #[tokio::test]
    async fn clear_password_is_hashed_and_resetting_the_same_one_is_no_diff() {
        let store = ConfigStore::new(Config::default(), None);
        commit_password(&store, "t1", "alice", "hunter2").await;
        let hash = store.running_snapshot().await.users[0].password.clone();
        assert!(nos_password::verify("hunter2", &hash));

        // Same clear password again: hash untouched, so the transaction diff is empty.
        store
            .open_transaction("t2", TransactionBase::Current)
            .await
            .unwrap();
        let snap = store
            .apply_op("t2", set_password_op("alice", "hunter2"))
            .await
            .unwrap();
        assert_eq!(snap.config.users[0].password, hash);
        assert!(store.diff_transaction("t2").await.unwrap().is_empty());
        store.discard_transaction("t2", None).await.unwrap();

        // A different password does change it, and shows up as a (hidden) diff.
        store
            .open_transaction("t3", TransactionBase::Current)
            .await
            .unwrap();
        store
            .apply_op("t3", set_password_op("alice", "other"))
            .await
            .unwrap();
        let diff = store.diff_transaction("t3").await.unwrap();
        assert_eq!(diff.users.len(), 1);
        assert_ne!(
            store.get_transaction("t3").await.unwrap().config.users[0].password,
            hash
        );
    }

    #[tokio::test]
    async fn password_hash_upgrade_is_a_compare_and_swap_of_hashes() {
        let store = ConfigStore::new(Config::default(), None);
        commit_password(&store, "t1", "alice", "one").await;
        let old = store.running_snapshot().await.users[0].password.clone();
        let new = nos_password::hash("one");
        let mut rx = store.0.tx.subscribe();

        assert!(store
            .upgrade_password_hash("alice", "stale", new.clone())
            .await
            .is_err());
        assert!(store
            .upgrade_password_hash("alice", &old, "clear".into())
            .await
            .is_err());
        assert!(store
            .upgrade_password_hash("bob", &old, new.clone())
            .await
            .is_err());
        store
            .upgrade_password_hash("alice", &old, new.clone())
            .await
            .unwrap();
        assert_eq!(store.running_snapshot().await.users[0].password, new);
        assert_eq!(rx.recv().await.unwrap().config.users[0].password, new);
    }

    #[tokio::test]
    async fn reverting_to_the_running_password_inside_a_transaction_is_no_diff() {
        let store = ConfigStore::new(Config::default(), None);
        commit_password(&store, "t1", "alice", "one").await;
        store
            .open_transaction("t2", TransactionBase::Current)
            .await
            .unwrap();
        store
            .apply_op("t2", set_password_op("alice", "two"))
            .await
            .unwrap();
        store
            .apply_op("t2", set_password_op("alice", "one"))
            .await
            .unwrap();
        assert!(store.diff_transaction("t2").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn clear_password_set_through_a_path_put_is_hashed() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t", TransactionBase::Blank)
            .await
            .unwrap();
        let snap = store
            .set_transaction_path(
                "t",
                &segs("user/bob"),
                Some(r#"{"name":"bob","password":"pw"}"#),
                None,
                None,
            )
            .await
            .unwrap();
        assert!(nos_password::verify("pw", &snap.config.users[0].password));
    }

    #[tokio::test]
    async fn clear_password_seeded_at_startup_is_hashed() {
        let mut cfg = Config::default();
        crate::users::seed_default_user(&mut cfg);
        let store = ConfigStore::new(cfg, None);
        let users = store.running_snapshot().await.users.clone();
        assert!(nos_password::verify("admin", &users[0].password));
    }

    #[tokio::test]
    async fn commit_that_removes_every_user_is_refused() {
        let store = ConfigStore::new(Config::default(), None);
        commit_password(&store, "t1", "alice", "pw").await;
        store
            .open_transaction("t2", TransactionBase::Current)
            .await
            .unwrap();
        store
            .apply_op(
                "t2",
                ConfigOp::User(nos_proto::UserOp::Delete {
                    name: "alice".into(),
                }),
            )
            .await
            .unwrap();
        assert!(matches!(
            store.commit_transaction("t2", None).await,
            Err(ConfigError::NoUsersLeft)
        ));
        assert_eq!(store.running_snapshot().await.users.len(), 1);
    }

    fn set_key_op(label: &str, secret: &str) -> ConfigOp {
        ConfigOp::Admin(nos_proto::AdminOp::SetKey {
            label: label.into(),
            secret: secret.into(),
        })
    }

    #[tokio::test]
    async fn the_mask_keeps_a_stored_secret_through_ops_and_paths() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t", TransactionBase::Blank)
            .await
            .unwrap();
        store.apply_op("t", set_key_op("k", "real")).await.unwrap();

        // Op: the mask keeps the value in the transaction.
        let snap = store
            .apply_op("t", set_key_op("k", "<hidden>"))
            .await
            .unwrap();
        assert_eq!(snap.config.key("k"), Some("real"));
        // Op on a label that exists nowhere: refused, nothing changed.
        assert!(store
            .apply_op("t", set_key_op("new", "<hidden>"))
            .await
            .is_err());

        // Path: a GET'd (redacted) whole config PUT back keeps the secret.
        let redacted = serde_json::to_string(&snap.config.redacted()).unwrap();
        let snap = store
            .set_transaction_path("t", &[], Some(&redacted), None, None)
            .await
            .unwrap();
        assert_eq!(snap.config.key("k"), Some("real"));
        // Section path, new label with the mask: refused, transaction unchanged.
        let body = r#"{"label":"n","secret":"<hidden>"}"#;
        assert!(store
            .set_transaction_path("t", &segs("admin/key/n"), Some(body), None, None)
            .await
            .is_err());
        assert_eq!(
            store
                .get_transaction("t")
                .await
                .unwrap()
                .config
                .admin
                .keys
                .len(),
            1
        );

        // Once committed, a later transaction's mask resolves against running.
        store.commit_transaction("t", None).await.unwrap();
        store
            .open_transaction("u", TransactionBase::Blank)
            .await
            .unwrap();
        let snap = store
            .apply_op("u", set_key_op("k", "<hidden>"))
            .await
            .unwrap();
        assert_eq!(snap.config.key("k"), Some("real"));
    }

    fn user_json(n: usize) -> String {
        let users: Vec<_> = (0..n)
            .map(|i| serde_json::json!({"name": format!("u{i}"), "password": "pw"}))
            .collect();
        serde_json::to_string(&users).unwrap()
    }

    #[tokio::test]
    async fn transaction_count_is_capped_and_a_slot_frees_on_discard() {
        let store = ConfigStore::new(Config::default(), None);
        for i in 0..MAX_TRANSACTIONS {
            store
                .open_transaction(&format!("t{i}"), TransactionBase::Blank)
                .await
                .unwrap();
        }
        let err = store
            .open_transaction("extra", TransactionBase::Blank)
            .await
            .unwrap_err();
        assert!(matches!(err, ConfigError::TooManyTransactions(_)));
        // Resuming at the cap still works.
        assert!(
            store
                .open_transaction("t0", TransactionBase::Blank)
                .await
                .unwrap()
                .resumed
        );
        store.discard_transaction("t1", None).await.unwrap();
        store
            .open_transaction("extra", TransactionBase::Blank)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn transaction_names_are_bounded() {
        let store = ConfigStore::new(Config::default(), None);
        for bad in ["", "a/b", "sp ace", &"x".repeat(MAX_TX_NAME + 1)] {
            let err = store
                .open_transaction(bad, TransactionBase::Blank)
                .await
                .unwrap_err();
            assert!(matches!(err, ConfigError::InvalidTransactionName), "{bad}");
        }
        store
            .open_transaction(&"x".repeat(MAX_TX_NAME), TransactionBase::Blank)
            .await
            .unwrap();
        store
            .open_transaction("cli.1_a-b", TransactionBase::Blank)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn idle_transactions_are_swept_on_open() {
        let mut store = ConfigStore::new(Config::default(), None);
        Arc::get_mut(&mut store.0).unwrap().idle_ttl = Duration::from_millis(30);
        store
            .open_transaction("old", TransactionBase::Blank)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        store
            .open_transaction("new", TransactionBase::Blank)
            .await
            .unwrap();
        assert!(store.get_transaction("old").await.is_err());
        assert!(store.get_transaction("new").await.is_ok());
    }

    #[tokio::test]
    async fn too_many_clear_passwords_in_one_edit_is_refused_unhashed() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t", TransactionBase::Blank)
            .await
            .unwrap();
        let body = user_json(50);
        let started = Instant::now();
        let err = store
            .set_transaction_path("t", &segs("users"), Some(&body), None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ConfigError::TooManyClearPasswords(_)));
        assert!(started.elapsed() < Duration::from_millis(500));
        let ok = user_json(MAX_CLEAR_PASSWORDS_PER_EDIT);
        let snap = store
            .set_transaction_path("t", &segs("users"), Some(&ok), None, None)
            .await
            .unwrap();
        assert!(snap.config.users.iter().all(|u| !is_clear(u)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hashing_does_not_block_other_transactions() {
        let store = ConfigStore::new(Config::default(), None);
        for t in ["a", "b"] {
            store
                .open_transaction(t, TransactionBase::Blank)
                .await
                .unwrap();
        }
        let body = user_json(MAX_CLEAR_PASSWORDS_PER_EDIT);
        let s2 = store.clone();
        let hashing = tokio::spawn(async move {
            s2.set_transaction_path("a", &segs("users"), Some(&body), None, None)
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        let started = Instant::now();
        store.get_transaction("b").await.unwrap();
        store.running_snapshot().await;
        let quick = started.elapsed();
        hashing.await.unwrap();
        assert!(quick < Duration::from_millis(50), "{quick:?}");
    }

    /// #773: a transaction opened from running shares its Arc until the first
    /// edit, which never reaches running; a committed config stays put while
    /// a later transaction edits; a failed edit changes nothing.
    #[tokio::test]
    async fn shared_configs_are_never_edited_in_place() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t", TransactionBase::Current)
            .await
            .unwrap();
        let running = store.running_snapshot().await;
        let txn = store.checkout("t", None).await.unwrap().0;
        assert!(Arc::ptr_eq(&running, &txn), "open(Current) shares running");
        drop(txn);
        store.apply_op("t", ensure_op("a")).await.unwrap();
        store.apply_op("t", set_asn_op("a", 65000)).await.unwrap();
        assert_eq!(store.running_snapshot().await.bgp_instances.len(), 0);
        store.commit_transaction("t", None).await.unwrap();
        let committed = store.running_snapshot().await;

        store
            .open_transaction("u", TransactionBase::Current)
            .await
            .unwrap();
        store.apply_op("u", ensure_op("b")).await.unwrap();
        store
            .set_transaction_path("u", &segs("hostname"), Some("\"x\""), None, None)
            .await
            .unwrap();
        assert_eq!(committed.bgp_instances.len(), 1);
        assert_eq!(store.running_snapshot().await.hostname, committed.hostname);

        let before = store.get_transaction("u").await.unwrap();
        assert!(store.apply_op("u", set_asn_op("zz", 1)).await.is_err());
        assert!(store
            .set_transaction_path("u", &segs("hostname"), Some("{"), None, None)
            .await
            .is_err());
        // Planned on the unshared config, refused before it is touched.
        let other = r#"{"name":"other"}"#;
        assert!(store
            .edit_transaction_path("u", &segs("bgp-instance/b"), Some(other), None, None)
            .await
            .is_err());
        let after = store.get_transaction("u").await.unwrap();
        assert_eq!(after.config, before.config);
        assert_eq!(after.generation, before.generation);
        // A stale generation is still refused.
        let err = store
            .set_transaction_path("u", &segs("hostname"), Some("\"y\""), Some(vec![0]), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ConfigError::PreconditionFailed { .. }));
        let g = store
            .edit_transaction_path("u", &segs("hostname"), Some("\"y\""), Some(vec![2]), None)
            .await
            .unwrap();
        assert_eq!((g.generation, g.dirty), (3, true));
        assert_eq!(g.value.as_deref(), Some("\"y\""));
        assert_eq!(
            store.get_transaction("u").await.unwrap().config.hostname,
            "y"
        );
    }

    #[tokio::test]
    async fn an_edit_that_lost_the_race_is_refused() {
        let store = ConfigStore::new(Config::default(), None);
        store
            .open_transaction("t", TransactionBase::Blank)
            .await
            .unwrap();
        let (config, generation) = store.checkout("t", None).await.unwrap();
        store.apply_op("t", ensure_op("x")).await.unwrap();
        let err = store
            .finish_edit(
                "t",
                Edit::Whole(Box::new((*config).clone())),
                Vec::new(),
                generation,
                |_, _| (),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ConfigError::PreconditionFailed { .. }));
    }
}
