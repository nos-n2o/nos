use serde::{Deserialize, Serialize};

use crate::diff::{ConfigDiff, DiffScope};
use crate::docs::{CommandDoc, Topic};
use crate::ops::ConfigOp;
use crate::schema::Config;

/// The person `nos-restd` calls on behalf of (#1360): the REST user's name
/// and, for a user with no local entry, the role RADIUS granted at login.
/// `nos-configd` trusts it only from a `Restd` connection and ignores `claim`
/// for any name the config has a local entry for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// The authenticated REST user.
    pub name: String,
    /// The role an external login backend granted (never client supplied:
    /// `nos-restd` takes it from the watchdog's `RestSessionLive`).
    pub claim: Option<crate::UserRole>,
}

impl Actor {
    /// An actor with no claim (a local user).
    #[must_use]
    pub fn local(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            claim: None,
        }
    }
}

/// Messages sent from a component client to the config daemon.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// One-shot: receive the current full config snapshot then stop.
    Get,
    /// Start streaming: receive the current snapshot, then all future commits.
    Subscribe,
    /// Stop streaming updates (connection stays open for further requests).
    Unsubscribe,
    /// Persist the current running config to disk at the daemon's configured
    /// config-file path.
    Save {
        /// As on `OpenTransaction`.
        actor: Option<Actor>,
    },
    /// Opens a named transaction, creating it from `base` if it doesn't
    /// already exist, or resuming its current in-progress config unchanged
    /// (ignoring `base`) if it does.
    OpenTransaction {
        /// Transaction name.
        name: String,
        /// What the transaction starts from.
        base: TransactionBase,
        /// The person on whose behalf `nos-restd` calls (its authenticated
        /// REST user), for the audit log. `None` from every other client;
        /// `nos-configd` ignores it unless the caller is `Restd` and uses
        /// the certificate name for a `User`.
        actor: Option<Actor>,
    },
    /// Applies one edit to a named transaction's in-progress config.
    ApplyOp {
        /// Transaction to edit.
        name: String,
        /// The edit to apply.
        op: ConfigOp,
        /// As on `OpenTransaction`.
        actor: Option<Actor>,
    },
    /// One-shot fetch of a named transaction's current in-progress config.
    GetTransaction {
        /// Transaction name.
        name: String,
    },
    /// Validates a named transaction and, if valid, atomically promotes it
    /// to the running config, broadcasts the change to subscribers, and
    /// removes the transaction. If invalid, the transaction is left intact.
    /// `if_match` is an RFC 9110 §13.1.1 precondition: `Some(g)` refuses the
    /// commit unless the transaction's `generation` is still `g`; `None` is
    /// unconditional.
    CommitTransaction {
        /// Transaction name.
        name: String,
        /// Only act if the transaction is at this revision.
        if_match: Option<Vec<u64>>,
        /// As on `OpenTransaction`.
        actor: Option<Actor>,
        /// Confirmed commit (RFC 6241 8.4, #1144): `Some(secs)` (30..=86400)
        /// rolls the commit back unless confirmed within `secs`.
        confirm_timeout: Option<u32>,
    },
    /// Confirms a pending confirmed commit (#1144): disarms its rollback timer.
    ConfirmCommit {
        /// As on `OpenTransaction`.
        actor: Option<Actor>,
    },
    /// Rolls a pending confirmed commit back now (#1144).
    CancelCommit {
        /// As on `OpenTransaction`.
        actor: Option<Actor>,
    },
    /// Deletes a named transaction without touching the running config.
    /// `if_match` as on `CommitTransaction`.
    DiscardTransaction {
        /// Transaction name.
        name: String,
        /// Only act if the transaction is at this revision.
        if_match: Option<Vec<u64>>,
    },
    /// One-shot: fetch the daemon-authored documentation for one operation
    /// (see `nos_proto::docs::CommandDoc`), so any client can show
    /// consistent help text without hardcoding its own copy. Scoped to a
    /// single `Topic` rather than the whole catalog, so a client only ever
    /// pays for the docs it actually displays.
    Describe {
        /// The topic to describe.
        topic: Topic,
    },
    /// One-shot: compute and return the structural difference between the
    /// running config and a named transaction's in-progress config.
    DiffTransaction {
        /// Transaction name.
        name: String,
    },
    /// Start streaming diffs: an initial diff synthesized against an empty
    /// config (so a fresh subscriber sees every currently-configured item in
    /// `scopes` as `Added`), then one more `Event::Diff` per future commit
    /// that touches at least one requested scope — other commits are not
    /// sent at all.
    SubscribeDiff {
        /// Scopes whose diffs the subscriber wants.
        scopes: Vec<DiffScope>,
    },
    /// Watchdog-only compare-and-swap: replace `user`'s stored password hash
    /// `old` with the stronger re-hash `new` of the same password, straight
    /// in the running config (no transaction). Refused if `old` is no longer
    /// the stored hash or `new` is not a hash.
    UpgradePasswordHash {
        /// User who made the change.
        user: String,
        /// Previous value.
        old: String,
        /// New value.
        new: String,
    },
    /// Sets (`value` = `Some(json)`) or removes (`value` = `None`) the
    /// subsection of a named transaction's in-progress config addressed by
    /// `path` — see `nos_proto::config_path` for the path grammar. An empty
    /// `path` addresses the whole config. Like `ApplyOp`, never validates;
    /// replies with `Event::Transaction`. `if_match` as on
    /// `CommitTransaction`. Unused in tree since #774 (a full snapshot per
    /// edit): kept for wire compatibility, use `EditTransactionPath`.
    SetTransactionPath {
        /// Transaction name.
        name: String,
        /// Config path of the node to edit.
        path: Vec<String>,
        /// Value to set; `None` clears the node.
        value: Option<String>,
        /// Only act if the transaction is at this revision.
        if_match: Option<Vec<u64>>,
        /// Where to insert (or move) the list element `path` names; `None`
        /// replaces in place / appends. Postcard wire change (#539): every
        /// consumer must pass it.
        position: Option<crate::config_path::ListPosition>,
        /// As on `OpenTransaction`.
        actor: Option<Actor>,
    },
    /// Cheap auth probe (#755): is there a user called `name` in the running
    /// config? Replies `Event::UserExists`, carrying no config data.
    UserExists {
        /// User name to look for.
        name: String,
    },
    /// Names of the running config's BGP instances (#759). Replies
    /// `Event::InstanceNames`, carrying no other config data.
    ListBgpInstances,
    /// Names of the running config's OSPF instances (#759). Replies
    /// `Event::InstanceNames`.
    ListOspfInstances,
    /// Names of the running config's `OSPFv3` instances (#759). Replies
    /// `Event::InstanceNames`.
    ListOspfv3Instances,
    /// The `rest_api` pinned to routing table `table` in the running config
    /// (#759, #758). Replies `Event::RestApi`.
    GetRestApi {
        /// Routing table name.
        table: String,
    },
    /// `SetTransactionPath` replying with `Event::TransactionEdit` instead
    /// of a full snapshot (#774): the reply costs the edited subsection,
    /// not the config.
    EditTransactionPath {
        /// Transaction name.
        name: String,
        /// Config path of the node to edit.
        path: Vec<String>,
        /// Value to set; `None` clears the node.
        value: Option<String>,
        /// Only act if the transaction is at this revision.
        if_match: Option<Vec<u64>>,
        /// As on `SetTransactionPath`.
        position: Option<crate::config_path::ListPosition>,
        /// As on `OpenTransaction`.
        actor: Option<Actor>,
    },
    /// `nos-sshd`-only set-if-absent (#1104): stores `seed` (base64 of a
    /// 32-byte ed25519 seed) as the admin key `ssh-host-key` in the running
    /// config, broadcast like a commit. Refused with `Event::Error` if the
    /// label already exists (the caller re-reads and adopts that key), so
    /// racing per-table daemons agree on one key. Replies `Event::Committed`.
    SetSshHostKey {
        /// Base64 of the 32-byte seed.
        seed: String,
    },
    /// Is the running config unsaved (#1139)? Replies `Event::SaveStatus`.
    SaveStatus,
    /// The commit history (#1141), newest first. Replies `Event::History`.
    ListHistory,
    /// Restores the running config as it was before the last `index` commits
    /// (`1` = undo the latest commit; `0` does nothing), as a normal commit:
    /// validated, broadcast, itself a new history entry. Replies
    /// `Event::Committed`; an `index` beyond the history is an `Event::Error`.
    Rollback {
        /// How many commits to go back.
        index: u32,
        /// As on `OpenTransaction`.
        actor: Option<Actor>,
    },
}

/// Messages sent from the config daemon to a component client.
#[derive(Debug, Serialize, Deserialize)]
pub enum Event {
    /// A full config snapshot — sent as the initial response to Get/Subscribe
    /// and on every subsequent commit while subscribed. This variant always
    /// carries the daemon's authoritative *running* config, never a
    /// transaction's in-progress state — see `Event::Transaction` for that.
    Config(Config),
    /// A human-readable error message from the daemon.
    Error(String),
    /// The running config was successfully persisted to disk, in reply to `Save`.
    Saved,
    /// A named transaction's current state, in reply to `OpenTransaction`,
    /// `ApplyOp`, or `GetTransaction`.
    Transaction(TransactionSnapshot),
    /// A named transaction was successfully committed, in reply to
    /// `CommitTransaction` (or a password-hash upgrade, with no warnings).
    /// `warnings` are non-blocking advice about the committed config (#501).
    Committed {
        /// Non-blocking advice about the committed config.
        warnings: Vec<String>,
        /// The running config now differs from the saved one (#1139).
        unsaved: bool,
    },
    /// Reply to `SaveStatus`; also pushed on a `Subscribe` to `Role::User`
    /// (now, then on every change), so the shell's prompt follows it live.
    /// Running differs from what `Save` last wrote (#1139).
    SaveStatus {
        /// True when a commit, rehash or host-key set is not on disk.
        unsaved: bool,
    },
    /// A named transaction was successfully discarded, in reply to
    /// `DiscardTransaction`.
    Discarded,
    /// One operation's documentation, in reply to `Describe`.
    Description(CommandDoc),
    /// The structural difference between the running config and a named
    /// transaction's in-progress config, in reply to `DiffTransaction`.
    Diff(ConfigDiff),
    /// Reply to `UserExists`: whether the user is in the running config.
    UserExists(bool),
    /// Reply to `ListBgpInstances` / `ListOspfInstances` / `ListOspfv3Instances`.
    InstanceNames(Vec<String>),
    /// Reply to `GetRestApi`: `None` = table absent or not pinned.
    RestApi(Option<crate::RestApi>),
    /// Reply to `EditTransactionPath` (#774).
    TransactionEdit {
        /// The transaction's generation after the edit.
        generation: u64,
        /// The transaction's `dirty` flag after the edit.
        dirty: bool,
        /// JSON text of the subsection at the edited path, unredacted
        /// (postcard cannot carry a `serde_json::Value`); `None` after a
        /// remove.
        value: Option<String>,
    },
    /// Reply to `ListHistory`: newest first.
    History(Vec<HistoryEntry>),
}

/// One kept running config (#1141). `index` is what `Rollback` takes: `1` is
/// the config replaced by the latest commit.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Argument to `Rollback`.
    pub index: u32,
    /// Seconds since the Unix epoch of the commit that replaced this config.
    pub time: u64,
    /// Who made that commit (empty when unknown).
    pub actor: String,
    /// `commit` or `rollback`: what made that commit.
    pub kind: String,
}

/// What a newly opened transaction's in-progress config should start from.
/// Ignored when `OpenTransaction` resumes an already-existing transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionBase {
    /// Start from an empty `Config::default()`.
    Blank,
    /// Start from a clone of the current running config.
    Current,
}

/// A named transaction's current state, returned after `OpenTransaction`,
/// `ApplyOp`, and `GetTransaction`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSnapshot {
    /// Name of the config.
    pub name: String,
    /// The config itself.
    pub config: Config,
    /// True once any `ApplyOp` has succeeded since the transaction was
    /// (re)created.
    pub dirty: bool,
    /// True if `OpenTransaction` attached to a pre-existing transaction
    /// rather than creating a new one.
    pub resumed: bool,
    /// Monotonic per-transaction edit counter: 0 when created, +1 on every
    /// successful `ApplyOp`/`SetTransactionPath`. The value an `if_match`
    /// precondition (and `nos-restd`'s `ETag`) compares against.
    pub generation: u64,
}
