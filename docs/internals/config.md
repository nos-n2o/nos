# Configuration daemon internals

How `nos-config` is built, moved from `config/CLAUDE.md` (#264) so the always-loaded file keeps only rules and pitfalls. The rules to respect when editing the crate are in [`config/CLAUDE.md`](../../config/CLAUDE.md).

## ConfigStore API

```rust
ConfigStore::new(initial, config_path)          // create with an initial running config + optional persistence path
store.running_snapshot().await                  // Arc<Config> — the running config, shared (no copy)
store.subscribe_config(role, out).await         // (initial Event::Config, forwarder JoinHandle) — Request::Subscribe; abort the handle to unsubscribe
store.subscribe_diff(role, scopes, out).await   // (initial Event::Diff, forwarder JoinHandle) — Request::SubscribeDiff; registers role's ViewClass while the task lives
store.initial_diff(role).await                  // ConfigDiff — running vs. Config::default(), for a fresh SubscribeDiff connection's first event
store.save_to_disk().await                      // persist running config to config_path

store.open_transaction(name, base).await        // Result<TransactionSnapshot, ConfigError> — create from Blank/Current, or resume if `name` exists
store.apply_op(name, op).await                  // Result<TransactionSnapshot, ConfigError> — mutate a transaction, no validation
store.set_transaction_path(name, path, value, if_match, position).await  // set/remove one JSON subsection, optionally at a list `position` (needs a value), no validation; O(edit) (#775)
store.edit_transaction_path(name, path, value, if_match, position).await // PathEdit { generation, dirty, value }: the same edit, replying the edited subsection instead of a snapshot (#774)
store.get_transaction(name).await               // Result<TransactionSnapshot, ConfigError>
store.commit_transaction(name, if_match).await  // validate → promote to running → broadcast → remove transaction
store.discard_transaction(name, if_match).await // remove transaction without touching running
store.diff_transaction(name).await              // Result<ConfigDiff, ConfigError> — running vs. transaction, no validation

store.start_ipc_server(&addr, &identity)        // bind TLS socket, start accept loop
```

Lock ordering: always lock `transactions` before `running` to avoid deadlock.

Limits on the transaction surface (#388), all in `store.rs`:
- At most `MAX_TRANSACTIONS` (32) open at once; a new name past that is `ConfigError::TooManyTransactions` (`nos-restd`: `429` + `Retry-After`). Resuming an existing name always works; commit or discard frees a slot.
- A new name is 1-`MAX_TX_NAME` (64) characters of letters, digits, `.`, `_`, `-` (`InvalidTransactionName`, `400`).
- A transaction untouched for 4 hours is dropped when the next `open_transaction` runs (no background task).
- One edit may carry at most `MAX_CLEAR_PASSWORDS_PER_EDIT` (4) clear-text passwords (`TooManyClearPasswords`, `400`); a bulk user import needs several edits.
- `apply_op` (and a `set_transaction_path` on `users` or the empty path) build the edited config or user list and hash (`spawn_blocking`) with no lock held, then store the result only if the generation is unchanged; otherwise `PreconditionFailed` and the caller retries. Other path edits are planned and applied in place under the lock (#775). A failed edit never touches the stored config.

Config sharing (#773):
- `running` and every `Transaction.config` are `Arc<Config>`. `open_transaction(Current)` shares running's Arc; a path edit goes through `Arc::make_mut` (the first one copies) and `apply_op` stores a new Arc, so running never changes under a transaction.
- `Transaction.base` (#1034): `Some(running's Arc at open)` for `Current`, `None` for `Blank`. Commit with `ptr_eq(base, running)` validates before the `running` write guard and swaps as before; otherwise it merges and validates under the guard. A stale base pins one old `Arc<Config>` per open transaction (max 32, 4h sweep). `upgrade_password_hash` locks `transactions` first and rewrites each transaction's base/config for the user.
- `commit_transaction` removes the transaction, runs `sync_routing_table_refs` through `Arc::make_mut` (no copy: the Arc is unshared by then), and hands the same Arc to `running` and to the broadcast `CommitUpdate`.
- `apply_op` still copies the config once per op (an op may fail half-applied); only the shell sends ops.

Every `Transaction` carries a `generation: u64` (0 when created, +1 per successful `apply_op`/`set_transaction_path`), reported in every `TransactionSnapshot`. `if_match: Option<u64>` on `set_transaction_path`/`commit_transaction`/`discard_transaction` (and the matching `Request` variants) is an RFC 9110 §13.1.1 precondition: `Some(g)` is compared against the current generation under the same `transactions` lock the mutation takes, so it is a real compare-and-set, and a mismatch is `ConfigError::PreconditionFailed` with nothing changed (the transaction stays); `None` is unconditional — `nos-cli`/`nos-provision` never send one, only `nos-restd` does (its `ETag`/`If-Match`).
