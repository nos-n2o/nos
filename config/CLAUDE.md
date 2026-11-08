# nos-config — Configuration Daemon

Owns the running configuration and exposes it to all component processes via a Unix socket IPC server.

## Responsibilities

- **Config store**: named, server-held transactions (each an independent in-progress `Config`) plus the running config, with atomic commit and garde-based validation.
- **IPC server**: accepts connections from component processes, handles `Get`, `Subscribe`/`SubscribeDiff`/`Unsubscribe`, `Save`, and the transaction lifecycle requests (`OpenTransaction`, `ApplyOp`, `GetTransaction`, `CommitTransaction`, `DiscardTransaction`, `DiffTransaction`).
- **Change propagation**: broadcasts each commit's new and previous config to all subscribers; `Subscribe` gets the full config, `SubscribeDiff` the diff, scoped. Every reply is `Config::for_role(caller.role)` (#384: users/keys per role, `docs/architecture/ipc-security.md`).
- **Persistence**: loads the running config from disk at startup and writes it back out on `Save`.

## What lives here vs nos-proto

All **wire types** (`Config`, `BgpInstance`, `Request`, `Event`, `ConfigOp`, `IpcCodec`) live in `nos-proto`.  
`nos-config` owns the **store logic** and the **server** — nothing about wire types.

## Key types

| Type | File | Role |
|------|------|------|
| `ConfigStore` | `store.rs` | Cheap `Clone` handle (`Arc<Inner>`) over `running: RwLock<Arc<Config>>` + `transactions: Mutex<HashMap<String, Transaction>>` (`Arc<Config>` each, #773) + `broadcast::Sender<Arc<CommitUpdate>>` + `config_path` |
| `CommitUpdate` | `store.rs` | Internal — one commit: `config` (running's `Arc`) + `prev` until each live diff class has its diff (#773) |
| `ConfigError` | `error.rs` | `Validation`, `NoUsersLeft` (a commit may not remove every user), `TransactionNotFound`, `PreconditionFailed` (an `if_match` named a stale generation — message prefixed `precondition failed`, which `nos-restd` maps to 412), `Op`, `PersistenceNotConfigured`, `Io`, `Persistence`, `Serialization` |
| `server::start()` | `server.rs` | Binds a TLS `nos_pki::Listener` on a Unix socket (`ListenAddr::Unix` only — the TCP listener was removed, since it would bypass mTLS), spawns per-connection tasks (handshake inside the task) each holding a cloned `ConfigStore` and the peer's role/name from its certificate |
| `authz::allowed()` | `authz.rs` | Pure per-request allow-list: config reads (`Get`/`Subscribe*`/`Describe`) for every authenticated daemon and `User`; edits/`Save` for `User`/`Restd` only. No wildcard arm — a new `Request` variant won't compile until classified. A refused request gets `Event::Error("permission denied")` and the connection is closed |
| `users::{hash_clear_passwords, seed_default_user}` | `users.rs` | Replaces clear-text `User.password`s with argon2id hashes (reusing an earlier hash the clear text still verifies against, so re-setting a password is no diff); called by `ConfigStore` after every edit and on load. `seed_default_user` adds `admin`/`admin` when there are no users (called from `main.rs`) |
| `docs::command_doc()` | `docs.rs` | The CLI help text for every `nos_proto::Topic` (`Request::Describe`), one arm per topic — an exhaustive `match`, so a topic without text doesn't compile. Topics are one per config-tree node or field (the `#[cli(topic)]` on a schema field, see `nos_proto::cli`), per sugar word, and per non-edit request; the text is written for the shell's user. The schema's `///` doc comments are the REST API's text, deliberately separate (#109) |
| `persistence::{save_to_disk, load_or_default}` | `persistence.rs` | Serialize/atomically write (0600), and load-with-fallback (warns when the file is group/other readable), the config file |
| `secrets::{restore_masked, unmask_op}` | `secrets.rs` | A `<hidden>` sent back by a client (GET-then-PUT) keeps the stored admin secret / user hash; refused when nothing earlier exists (#507). `apply_op` logs `op.kind()`, never the op |

## IPC server

`server::start()` binds a `UnixListener` and spawns an accept loop, each connection sharing a cloned `ConfigStore`. Per-connection:
- `Request::Get` → send `Event::Config(current_running)` once.
- `Request::Subscribe` → `store.subscribe_config(role, sub_tx)`: the current config for the role, plus a forwarder task bridging the commit broadcast → `mpsc::Sender<Event>` (`Event::Config(config.for_role(role))` per commit). The select loop drains the `mpsc::Receiver` to the client.
- `Request::SubscribeDiff { scopes }` → `store.subscribe_diff(role, scopes, sub_tx)`: the initial diff, then `CommitUpdate::diff_for(role)` per commit (one `Arc<ConfigDiff>` per visibility class, #751; `diff_configs_for_role`, no projection clone, #778), scoped, skipped when empty. Forwarders live in `store.rs` (tests need no PKI).
- `Request::Unsubscribe` → abort the active forwarder task.
- `UserExists`, `List*Instances`, `GetRestApi` → `Restd`-only, no clone (#755, #759).
- `Request::Save` → serializes the running config as YAML and atomically writes it to the daemon's `--config-file` path; replies `Event::Saved` on success, `Event::Error` if no `--config-file` was configured or the write fails.
- `Request::OpenTransaction`/`ApplyOp`/`GetTransaction`/`CommitTransaction`/`DiscardTransaction`/`DiffTransaction` → thin calls into the matching `ConfigStore` method (see `dispatch_request` in `server.rs`), replying `Event::Transaction`/`Event::Committed { warnings }` (advice from `warnings::commit_warnings`, #501)/`Event::Discarded`/`Event::Diff`/`Event::Error`.
- Connection drop → forwarder task is aborted, connection task exits. **Transactions have no lifecycle tie to connections** — they live purely in `ConfigStore`, keyed by name, so a dropped connection never loses or discards one; only an explicit `DiscardTransaction` does.

**Half-closed subscriber connections stay open.** A `Subscribe`/`SubscribeDiff` client is documented (see `client::subscribe` in `nos-cli`) to send its request then never write to the connection again — "the caller owns its lifetime." If the per-connection loop treated EOF/an error on the *request* read side as reason to tear down the whole connection, every such client would stop receiving events right after their first one. The fix: once a subscription (`sub_task`) is active, EOF/an error on `reader` only disables further request reads (`reader_open = false`) — it does not `break` the connection. The connection then stays alive purely to keep draining `sub_rx` into `writer` until a write actually fails (the client is truly gone), at which point it closes and aborts the forwarder task. Without an active subscription, EOF/error still ends the connection immediately, as before.

## Socket path convention

By convention the socket is `/run/nos/config.sock`; tests use a tempdir.

## Config file convention

By convention (not yet enforced elsewhere), the persisted config file lives at `/var/lib/nos/configd/config.yaml`, overridable via `--config-file`. A missing file at startup gives `Config::default()`; a primary that is unreadable, unparseable or fails `validate_config` falls back to `.bak` (must validate; primary rewritten), then to a blank config with the seeded admin; never fails (reverses #401). See `docs/architecture/config-protocol.md`.

## ConfigStore rules

- Lock ordering: always lock `transactions` before `running`.
- Path edits (#775, `path_edit.rs`): plan on `&Config`, then apply via `Arc::make_mut`; a new `Config` field joins `sections!`.
- Every `Transaction` carries `generation: u64` (0 at open, +1 per successful `apply_op`/`set_transaction_path`), in every snapshot. `if_match: Option<Vec<u64>>` (a list; empty never matches) on `set_transaction_path`/`commit_transaction`/`discard_transaction` is an RFC 9110 §13.1.1 compare-and-set under the `transactions` lock; a mismatch is `ConfigError::PreconditionFailed`, nothing changed. Only `nos-restd` sends one.
- Bounded (#388): 32 open transactions, names `[A-Za-z0-9._-]{1,64}`, 4h idle sweep, 4 clear passwords per edit; hashing runs on `spawn_blocking` with no lock held.

Details: [internals](../docs/internals/config.md) (the `ConfigStore` method list).
