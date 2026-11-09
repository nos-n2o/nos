# User and session authentication

Contributor-facing; moved from the root `CLAUDE.md` (#260). Operator view: [docs/README.md](../README.md).


`Config.users` (`nos_proto::User { name, password }`) holds the local users — every user is a full administrator, there are no roles. `password` is an **argon2id PHC hash** at rest (`nos-password`); a garde check rejects anything else at commit, so a committed config never holds clear text. `set user <name> password <clear>` (`UserOp::SetPassword`, also `PUT …/user/<name>` over REST, or a clear password in a seeded `config.yaml`) is the clear-text entry point: `nos-configd` (`config/src/users.rs`, called from `ConfigStore::apply_op`/`set_transaction_path`/`new`) replaces a clear password with a hash right after applying the edit — and, if the clear text still verifies against the user's earlier hash (the transaction's previous value, then the running config's), **reuses that hash verbatim** instead of salting a new one, so re-setting the same password is not a diff. Hashing lives in `nos-config`, not `nos-proto` (`ConfigOp::apply` is pure and also runs client-side in `nos-e2e`; proto must not gain a crypto crate). `UserOp`'s `Debug` and `User`'s hide the password, since ops are logged and forwarded to `nos-logd`. A commit that would leave zero users is refused (`ConfigError::NoUsersLeft`); on startup `nos-configd` creates `admin`/`admin` when the config has no users (first boot, or a config saved before users existed) — change it.

`nos-cli` (and `nos-provision`) log in through `nos-watchdogd`, not `nos-configd`: it prompts `login:`/`password:` (no echo), sends them over a server-authenticated TLS connection to the broker socket (trusting only the published `ca.crt`), and the watchdog checks them against the running config's users with `nos-password`, then certifies a key the client generated — see "IPC security". The hashes never leave the daemons, and it fails closed if the watchdog is unreachable. `nos-restd` requires a **client certificate** on every route (incl. `/openapi.json`, `/swagger-ui/`, the SSE stream) except `POST /v1/login`, which trades a password for one: it forwards to the watchdog (`WatchdogRequest::RestLogin`, `restd` only), which verifies with `nos-password` and issues a `user/<name>` certificate from the **REST CA** for the public key the client sent. The password crosses the network once; every later request carries only the certificate, and the user must still exist in the running config (fetched from `nos-configd` per request, as its own `restd` identity) — a deleted user is refused on the next request, not when the certificate expires. The watchdog also vouches for the very certificate (`RestCertCheck`): a password change revokes it, and renewals stop `--pki-rest-session-max` (7 days) after the password login. Password checks are bounded in four layers (#381): per user (`nos-restd`'s `LoginGate`, 1 at a time, lockout after 5 failures per user and source address), per source address (20 failures in 60s, `429`), 8 REST logins in flight, and in `nos-watchdogd` 2 concurrent argon2id verifications (extra callers wait up to 5s, then `login busy`, which is neither a failure nor a lockout). REST, being network-reachable, is the boundary for network callers; see `rest/CLAUDE.md`.



A `BgpPeerGroup` carries an optional `auth` field (RFC 2385 TCP MD5, or RFC 5925 TCP-AO with key rotation — see `docs/protocols/bgp-internals.md`'s "Session authentication" for the wire-level detail). Neither mechanism has a maintained Rust binding, so the raw `setsockopt(TCP_MD5SIG)`/`setsockopt(TCP_AO_*)` calls live in their own crate, `tcp-auth/` (`nos-tcp-auth`) — no NOS dependencies, like `nos-proto`, and the one crate in the workspace whose whole purpose is `unsafe` FFI (every other crate stays within the workspace's `unsafe_code = "warn"` default). Secrets are stored **clear-text** in config, like every other field — this system has no encryption-at-rest anywhere. They are not shown, though: see "Secrets and the admin keystore" below.

## Login ticket (#990)

- A caller that holds the password but cannot (or should not) hold the key, such as PAM during an ssh login, trades it for a ticket with `WatchdogRequest::LoginTicket`; `nos`, started later, redeems it (`RedeemTicket`) for a certificate on its own key. No certificate is issued until redemption, and the redeem time is the session start (#637).
- The ticket travels in the `NOS_LOGIN_TICKET` environment variable (unpadded base64url). Accepted exposure: it is readable through `/proc/<pid>/environ` by the same uid and root for at most 60 s, once.

## Secrets and the admin keystore (#383, #507)

- `Config.admin` is a keystore of `label -> secret`; sections that need a key reference the label (BGP MD5/TCP-AO and RPKI cache auth do since #508; OSPFv2/OSPFv3 simple and crypto keys, incl. virtual links, since #509; BFD profile auth since #510). `nos-bgpd`, `nos-ospfd`, `nos-ospfv3d` and `nos-bfdd` resolve their labels themselves, subscribed to `DiffScope::Admin`. It is the one place daemons read a secret from, via `Config::key`.
- Masking happens at the presentation edges only, never in the stored `Config` (daemons read the real value over IPC):
  - **Logs:** `ConfigStore::apply_op` logs `ConfigOp::kind()`, not `?op`; `AdminKey`, `Admin`, `AdminOp` and `UserOp` also have a `Debug` that prints `<hidden>`.
  - **REST:** `Config::redacted()` backs `GET /v1/config` and every transaction response.
  - **Shell and diff:** `#[cli(secret)]` fields render `<hidden>` (`<changed>` in a diff); `show config` omits the `admin` section.
- **Mask round trip:** `nos-configd` (`config/src/secrets.rs`) swaps a `<hidden>` in an op or a path write for the stored value (transaction first, then running), and refuses it on a label or user with no earlier value. Done there, not in `nos-restd`, so every client is covered.
- **At rest:** `config.yaml` is written by an atomic temp-file rename, so it is 0600; `nos-configd` warns at load when a file is group/other readable (it does not refuse: the e2e harness seeds the file). Encryption at rest is not done.

## Audit identity (#400)

- `OpenTransaction`, `ApplyOp` and `CommitTransaction` carry `actor: Option<String>`. `nos-restd` fills it with the REST user from the client certificate; the CLI sends `None`.
- `nos-configd` decides the effective actor itself: a `User` connection is attributed to its own certificate name (a body `actor` is ignored), `Restd` is trusted to name the REST user, and other roles are attributed to their certificate name.
- Every commit logs `config commit audit transaction=<tx> actor=<user>` at info; open and apply log the actor at debug.
- `nos-restd` logs `rest request user=<user> method=<m> path=<p>` for every authenticated request.
- Not enforced: any user may commit or discard another's transaction (every user is an administrator); this is an audit trail only. `DiscardTransaction`, `SetTransactionPath` and `Save` carry no actor.
