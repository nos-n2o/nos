# nos-cli — Interactive Shell

The main user-facing entry point of NOS. A small REPL (binary name `nos`) built on `reedline`.

## What lives here vs nos-proto / nos-config

`nos-cli` depends only on `nos-proto` for wire types — it does **not** depend on `nos-config` internals, matching the rule in the root `CLAUDE.md` that client components never depend on the config daemon directly. It dials each daemon's Unix socket the same way any future component client would; every `*_client.rs` is a thin one-shot IPC call (`nos_pki::connect`/`connect_role`) against a daemon resolved through the watchdog broker.

## Login

`main.rs::login` reads the watchdog's public `ca.crt` (`--pki-ca`, default `/run/nos/pki/ca.crt`), prompts `login:`/`password:` (no echo, `rpassword`), sends `WatchdogRequest::Login` with a fresh CSR (`watchdog_client::login`; 3 attempts, then exit 1). The certificate lives in memory only (`nos_pki::Identity::set_certificate`); `keep_certificate_fresh` renews it at half-life via `RenewCert`. It **fails closed**: no reachable watchdog, no shell. `nos-cli` never sees password hashes: `set user <name> password <clear>` edits the users, `show config` prints `<hidden>` (a `#[cli(secret)]` field) and `diff` `<hidden>`/`<changed>`; the `admin` keystore section is left out of `show config` and printed by `show config admin`. Flow: `docs/architecture/auth.md`.

**SSH login-shell mode (#991).** When `NOS_LOGIN_TICKET` is set, `main` decodes it into a `Zeroizing` buffer and `login::redeem_ticket` trades it (`watchdog_client::redeem`) before any prompt. `Denied` falls back to the prompt; any other error fails closed. The ticket is never printed and the variable is not unset (no `unsafe` in this crate). `nos -c <cmd>` is refused (exit 2) in every mode. Docs: `docs/cli.md`.

## Modules

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--watchdog-socket`), login, the reedline REPL (completer, menus, keybindings), mode-aware prompt, the stdin commit/discard/leave question on `exit` — only interactive glue |
| `actions.rs` | What every `session::Resolved` action does (`handle_action`), `resolve_config_socket` (broker lookup, default-socket fallback), `subscribe_hostname_task`, `DocCache`/`doc_for`/`doc_for_blocking`. `handle_action` takes the exit question as `fn(&str) -> LeaveChoice`, so `tests/actions.rs` drives every action against fake daemons (#131) and `tests/actions_unhappy.rs` every not-running/error/populated arm (#345, own binary: `EDITOR` is process-global; fakes in `tests/common/`) |
| `command.rs` | `Command::parse` — pure, no I/O, no mode. Show/shell commands go through `spec::parse`; any other `edit`/`set`/`delete`/`move` line becomes `Command::Config(line)` |
| `config_grammar.rs` | The config half of the grammar (#109), generated from the schema's CLI tree: `parse`/`complete`/`usages`, resolving to `Request::EditTransactionPath` writes (optional list `position`: `set <element> first/last/before k/after k`, `move`; #539). Knows no object or field by name; `tests/config_grammar.rs` pins it on `config_corpus.jsonl` |
| `session.rs` | `Mode`, `Path` (position as REST segments; `up` drops one list+key pair), `resolve(&Mode, Command) -> Resolved` — the pure semantic layer |
| `spec.rs` | `COMMAND_SPECS`: one `cmd!` row per show/shell command (tokens, `Doc`, `Availability`, `Command`), so the parser can't accept a command without its doc. `CONFIG_VERBS` documents `edit`/`set`/`delete`/`move` |
| `completer.rs`, `help_menu.rs` | `NosCompleter` (Tab and live `?`, one injected config source for the tree and `*Name` slots), `HelpMenu` (the `?` menu) |
| `client.rs` | One-shot calls to `nos-configd`, plus `subscribe`, the one long-lived exception |
| `*_client.rs` | `watchdog`, `rib`, `interface`, `log` (also long-lived `tail`), `bgp`, `lacp`, `lldp`, `stp`, `bfd`, `fdb`, `ospf`, `ospfv3`: one-shot query per daemon |
| `format.rs` | Human-readable rendering. `render_config`/`render_transaction` are one call into `nos_proto::cli::render`, so a field can't be missing (`tests/render.rs`). `render_diff` is the only ANSI emitter (hand-rolled); `render_log_entry` the only `time` use |

## Commands

- Config commands (`edit`/`set`/`delete`) are not declared in this crate: every schema object and field is reachable, absolute or relative to the `edit` position, in the canonical `#[cli(words)]` spelling (`bgp instance`) or the REST segment (`bgp-instance`); `set`/a deep `edit` creates any missing object with its `Default`, like REST's `PUT`.
- Matching is exact-token only (no case-folding or abbreviations).
- Delete forms: `delete <field>` is relative-only (no qualified form); `edit eth0.100` cascade-creates the parent interface; OSPF profile names are unique across the whole config.
- Full row table (every `show`, `edit`, `set`, `delete`): `docs/cli.md` "Command table".

## Help, `?`, Tab

- `help`, `?` and Tab read the same two sources (`cmd!` rows filtered by `spec::availability_matches`, and the schema tree through `config_grammar`), so they always agree.
- Help text is authored in `nos-config`'s `docs.rs` (`Request::Describe`), never here; only local shell mechanics carry `spec::Doc::Local`. Each topic is fetched lazily, at most once per session, cached in `DocCache`; unreachable `nos-configd` yields a placeholder, not a failure.
- `?` is a keybinding (`main.rs::keybindings()`), not a command; `HelpMenu` is read-only. Menu mechanics: `docs/cli.md` "Help, `?` and Tab mechanics".

## Mode and connection

- `Mode` is client-side UI state only; transactions live in `nos-configd`, so an abnormal exit never loses one.
- Each command dials the daemon fresh. Two long-lived exceptions: `show log --follow` (foreground, not reconnected) and the hostname subscription task (`Request::Subscribe`, retry every 1s, repaints the prompt).
- `nos-configd` is resolved once through the broker (`--watchdog-socket`, default `/run/nos/watchdog.sock`); unreachable, it warns and falls back to `/run/nos/config.sock`. Other daemons are resolved per command.

Details: [CLI guide, command table and internals](../docs/cli.md#command-table-developer-reference).
