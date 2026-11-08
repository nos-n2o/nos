# Config protocol and transactions

Contributor-facing; moved from the root `CLAUDE.md` (#260). Operator view: [docs/README.md](../README.md).


```
Client → Server:
  Request::Get                 one-shot read of the current running config
  Request::Subscribe           receive current snapshot + all future commits
  Request::Unsubscribe         stop receiving updates (connection stays open)
  Request::Save                persist the current running config to disk
  Request::OpenTransaction     open (or resume) a named transaction from blank/current
  Request::ApplyOp             apply one edit (e.g. a BgpInstanceOp) to a named transaction
  Request::GetTransaction      one-shot read of a named transaction's in-progress config
  Request::CommitTransaction   validate, promote to running, broadcast, and delete the transaction (if_match: optional generation precondition, RFC 9110 §13.1.1)
  Request::DiscardTransaction  delete a named transaction without touching running config (if_match as above)
  Request::Describe            one-shot fetch of one operation's documentation, by Topic
  Request::SetTransactionPath  set/remove one subsection of a named transaction by URL-style path (whole config for an empty path) — see nos_proto::config_path (if_match as above); an optional `position` (`ListPosition`: First/Last/Before(k)/After(k)) inserts or moves the list element the path names (#539)
  Request::EditTransactionPath the same edit, replying Event::TransactionEdit (#774); what nos-restd, nos and nos-provision send. SetTransactionPath is unused in tree, kept for wire compatibility
  Request::UserExists          cheap auth probe (#755): is this name in `Config.users`? `Restd` only; replies with no config data
  Request::ListBgpInstances / ListOspfInstances / ListOspfv3Instances   instance names only (#759): what `nos-restd`'s show routes iterate, without shipping the config. `Restd` only
  Request::GetRestApi { table }  that routing table's pinned `rest_api` (#759, #758): the listener's per-tick "what is wanted" probe. `Restd` only

Server → Client:
  Event::Config(Config)             config snapshot (initial + on every commit, incl. via a transaction commit)
  Event::Error(String)              error from the daemon
  Event::Saved                      confirms the running config was persisted (reply to Save)
  Event::Transaction(Snapshot)      a named transaction's current state (reply to Open/Apply/Get/SetTransactionPath), incl. its generation (0 at open, +1 per edit — nos-restd's ETag)
  Event::Committed { warnings }     confirms a commit, with non-blocking advice (#501)
  Event::Discarded                  confirms a transaction was discarded
  Event::Description(CommandDoc)    one operation's documentation (reply to Describe)
  Event::UserExists(bool)           reply to UserExists
  Event::InstanceNames(Vec<String>) reply to the three List*Instances requests
  Event::RestApi(Option<RestApi>)   reply to GetRestApi (`None` = table absent or not pinned)
  Event::TransactionEdit { generation, dirty, value }  reply to EditTransactionPath: `value` is the JSON text of the edited subsection, unredacted (`None` after a remove)
```

`Describe`/`Description` exist so that the shell's help text (what a command does, in human terms, for the CLI's user) is authored once in `nos-config` and shared by every client, rather than duplicated per-client. A `Topic` is one config-tree node or field — named by the mandatory `#[cli(topic = …)]` on every schema field (`nos-proto-derive`, see [Schema reference](../schema-reference.md)), so a field can't exist without its CLI help — or one show/shell command (`nos-cli`'s `spec.rs` rows). `nos-cli`'s config commands (`edit`/`set`/`delete`), their help, `?`, Tab and usage are all generated from that schema tree (`cli/src/config_grammar.rs`, #109) and sent as `SetTransactionPath`, the same generic write REST uses. The schema's `///` comments are the REST API's (Swagger) text, deliberately separate. It's scoped to a single `Topic` per request (not a bulk catalog fetch) so a client only ever fetches the docs it actually displays.

### Named transactions

Editing the config happens inside a **named transaction**, held server-side in `nos-config`, not tied to any one connection. `OpenTransaction` creates it from a blank config or a clone of the running config (`TransactionBase::Blank`/`Current`), or — if a transaction with that name already exists — resumes its current in-progress state unchanged. `CommitTransaction` validates the transaction and, if valid, atomically replaces the running config and broadcasts it to every `Subscribe`d connection (the same fan-out `Get`/`Subscribe` already use); on invalid input the transaction is left alive so the caller can keep editing. `DiscardTransaction` deletes it outright. Because transactions live only in the daemon and are addressed by name, a client can disconnect (crash, Ctrl-C, network drop) and resume the same transaction later from a fresh connection — see `nos-cli`'s `configure <name>` command.

### Persistence

- `save_to_disk` writes a temp file, fsyncs it, renames it over `config.yaml`, then fsyncs the directory.
- Before each save the previous `config.yaml` is copied (same durable write) to `config.yaml.bak`, but only if it parses and passes `validate_config`, so a bad primary never replaces the last good backup.
- On start every candidate must read, parse and pass `validate_config` (the commit check plus syslog trust anchors, run after seeding/normalizing/hashing on a clone). Order: primary, then `config.yaml.bak`, then a blank config with the seeded `admin`.
- A missing primary is a first run (default config, `warn!`). Any other rejection (read error such as permission denied, parse error, validation failure) logs an `error!` with the path and the full report; the rejected file is not preserved.
- When the backup wins, the primary is rewritten from it (a failed restore is logged; the load still succeeds).
- `load_or_default` never fails, so a bad config cannot stop `nos-configd` from starting. This reverses #401's "never silently discard". The next `Save` overwrites whatever the primary was, so a transient read error can lose the operator's config; the `.bak` copy rule limits that to the primary.

### Framing limit

- `IpcCodec` frames are a 4-byte LE length plus a postcard payload of at most `nos_proto::codec::MAX_FRAME` (16 MiB).
- A longer length is `InvalidData` on decode (checked before any buffer is reserved, so a hostile `ff ff ff ff` costs nothing) and the connection is dropped.
- An incomplete frame reserves at most `RESERVE_CHUNK` (64 KiB) per `decode` call, so memory grows as bytes arrive, never the full declared length up front.
- Encode rejects an over-cap payload too, so an oversize message fails at the sender.
- Payloads that can legitimately grow past the cap are cut to fit:
  - `nos-bgpd` → `nos-ribd` `PushBgpRoutes` (a full IPv4 table is ~1M routes, 10 MB and up with backups, multipath and IPv6): `BgpRouteUpdate::frames` sends at most `BGP_PUSH_CHUNK` (2048) routes per frame. A larger `Full` goes as `FullPart`s closed by a `Full`; `nos-ribd` stages the parts per connection and swaps the whole set in at the closing `Full` (log: `assembled chunked bgp route snapshot … parts=N`), so it never publishes half a table. A connection lost mid-snapshot drops what was staged; the reconnect sends a fresh `Full`.
  - `nos-bgpd` `GetRoutesPage`, `GetEvpnRoutesPage`, `GetFlowspecRoutesPage`, `GetVpnRoutesPage` (`show bgp routes|evpn|flowspec|vpnv4|vpnv6`, `GET /v1/bgp/...`, #722/#723): same count limit and byte budget, keyed by `BgpRouteCursor`, but over a per-connection sorted key snapshot (`bgp/src/page.rs`, [BGP internals](../protocols/bgp-internals.md)) because the BGP RIB is not ordered.
  - `nos-ribd` `GetRoutesPage` (`show route`, `GET /v1/routes/{table}`, #713): at most `ROUTES_PAGE_MAX` (1000) prefixes per reply and cut early at a ~8 MiB encoded estimate (half of `MAX_FRAME`); the cursor is the last prefix returned. Keyset paging, no snapshot: a table that changes mid-walk never loops or repeats a prefix, but a walk may miss or include a concurrent change. `Rib` stays a `HashMap`, so a page is one O(n) pass under the read lock.
  - `nos-logd` `GetLogs`/`Tail` replies: capped at `store::REPLY_BYTES` (just under 16 MiB), newest entries kept, oldest left out.
  - `nos-bgpd` → `nos-ribd`/`nos-fdbd` `PushEvpnRoutes` (#719, #720): `EvpnUpdate::split()` cuts a `Full` by encoded bytes (`evpn_push_budget()`, 4 MiB). Receivers stage the `FullPart`s per connection (`EvpnUpdate::absorb`) and apply the whole set once, on the closing `Full` (log: `assembled chunked evpn route snapshot … parts=N`, `table=` on ribd, `domain=` on fdbd). The sender is `bgp/src/fdb_push_client.rs` (`send_split`). Staged parts are uncapped; a lost connection drops them. `NOS_EVPN_PUSH_BYTES` overrides the budget for unit tests and dev runs only: the watchdog clears its children's environment, so it does not reach a supervised `nos-bgpd` (`nos-e2e evpn-l3-chunked` sends 75k real routes instead).
  - `nos-fdbd`/`nos-ribd` → `nos-bgpd` `RedistributeMacs`/`RedistributeEvpnPrefixes` (#724 receiver, #725 senders): same `EvpnUpdate::split_with(evpn_push_budget())` chunks, for the `Full` on connect and the `Full([])` on detach; the senders are `fdb/src/bgp_client.rs` (`send`) and `rib/src/push_client.rs` (`send`, `Feed::split`, overridden by the EVPN and VPN feeds). Every chunked sender writes through `nos_proto::chunk::send_all` (in order, stops at the first write error, then reconnects with a fresh `Full`). `nos-bgpd` stages them per connection and per source (`EvpnSource::{Domain, Table}`, so a domain and a table of one name never mix) and applies the whole set once (log: `assembled chunked evpn route snapshot source=table:<t> routes=… parts=N`).
  - `nos-bgpd` → `nos-ribd` `PushVpnRoutes` (#715, an internet VRF imports ~1M prefixes): `VpnRouteUpdate::frames` weighs a route as its paths plus one and sends at most `VPN_PUSH_CHUNK` (32768) per frame (~7 MiB worst case: IPv6 PE, 28 labels). A heavier `Full` goes as `FullPart`s closed by a `Full`; `nos-ribd` stages them (`server::FullStaging`) and applies once (log: `assembled chunked vpn route snapshot table=… routes=… parts=N`). Diff pushes are cut the same way.
  - `nos-ospfd`/`nos-ospfv3d` → `nos-ribd` `PushOspfRoutes` (#726 receiver, #727 senders): `OspfRouteUpdate::frames_with` weighs a route as its next hops plus one and sends at most `OSPF_PUSH_CHUNK` (65536) per frame, on the `Full` at connect, the diff pushes and the `Full([])` on a table switch. The senders are `ospf{,v3}/src/rib_push_client.rs` (`push`, through `nos_proto::chunk::send_all`); `last_sent` moves only once every frame is out, and a write error reconnects with a fresh `Full`. `nos-ribd` stages the `FullPart`s (`server::FullStaging`) and applies once (log: `assembled chunked ospf route snapshot table=… routes=… parts=N`). The budget is `ospf_push_chunk()` (env `NOS_OSPF_PUSH_CHUNK`, unit tests and dev runs only) unless the hidden daemon flag `--push-chunk` sets it; the flag is how `nos-e2e ospf-push-chunked` reaches a supervised daemon (`--ospfd-arg`), since the watchdog clears its children's environment.
  - `nos-ribd` → `nos-bgpd`/`nos-ospfd`/`nos-ospfv3d` `RedistributeRoutes` (#728 receivers, #729 senders): `RedistributeUpdate::split_with` cuts the `Full` sent on connect into at most `redistribute_chunk()` routes per request (`REDISTRIBUTE_CHUNK` = 65536, ~2.6 MiB worst case; env `NOS_REDISTRIBUTE_CHUNK` for unit tests and dev runs only). The senders are `rib/src/{bgp,ospf}_client.rs` (through `nos_proto::chunk::send_all`, in order; `last_sent` moves only once every frame is out); `Add`/`Remove` and the `Full([])` on detach go as they are. The hidden `nos-ribd --redistribute-chunk` flag sets the budget for a supervised daemon (`--ribd-arg`, `nos-e2e ospf-push-chunked`). Each receiver stages the `FullPart`s per connection (`RedistributeUpdate::absorb`) and applies once, on the closing `Full` (log: `assembled chunked redistribute snapshot instance=… routes=… parts=N`): `BgpRib` diffs the whole raw set and OSPF replaces it, so half a set would withdraw the rest.
  - `nos-ribd` → `nos-bgpd` `RedistributeVpnPrefixes` (#791): `VpnPrefixUpdate::split_with(evpn_push_budget())` cuts by encoded bytes (a `VpnPrefix` carries every export RT and the SoO, so a route count is unsafe), for the `Full` on connect and the `Full([])` on detach. The sender is `rib/src/vpn_client.rs` (the VPN `Feed::split`/`Feed::budget` override over `push_client`). `nos-bgpd` stages the parts per connection and per table (`server.rs`'s `VpnStaging`) and applies the whole set once (log: `assembled chunked vpn export snapshot table=<t> routes=… parts=N instance=<i>`); a stray part reaching `BgpRib::apply_vpn_prefixes` is a no-op. Its e2e phase is `nos-e2e vpn-export-chunked`.

### Commit diffs (#751)

- A commit builds one `ConfigDiff` per visibility class (`ViewClass::of(role)`, what `Config::for_role` hides), not one per `SubscribeDiff` subscriber: `CommitUpdate::diff_for(role)` fills a lazy `OnceCell` per class, so concurrent subscribers wait for a single computation and share an `Arc<ConfigDiff>`.
- The diff runs in `spawn_blocking`, off the runtime workers. If it panics, those subscribers skip that commit (warning logged).
- `diff_configs` indexes each keyed list by key and skips equal elements: O(n) in the list length, no `Value` cloned. Duplicate keys still pair with the first match.
- `Subscribe` (full config) keeps its per-subscriber `for_role` clone.
- Lean ring slots (#773): a `CommitUpdate` shares its `config` with running, and holds the previous config only until every visibility class with a live `SubscribeDiff` subscriber at send time has its diff, then drops it. A slot then keeps `config` plus the diffs.
  - The store counts live diff subscribers per class (`ConfigStore::subscribe_diff`, released when the forwarder task ends). Registering and `broadcast::Sender::subscribe` happen under one lock, so a commit owes exactly the classes of the receivers that get it.
  - The class that sees everything (`User`, `Restd`) diffs the shared configs directly. Other classes build their `for_role` projections inside the diff task and drop them with it.
  - A commit with no diff subscriber keeps no previous config.
- Ordering (#631): `commit_transaction` and `upgrade_password_hash` swap `running` and call `broadcast` under one `running` write guard, so broadcast order equals swap order. The `NoUsersLeft` check runs under that guard too.
- Each `CommitUpdate` carries a `seq` bumped under the guard. A subscriber subscribes to the channel first, then reads `(snapshot, seq)` under the read guard; its forwarder drops updates with `seq <=` that value (already in the initial event), so there is no duplicate and no gap.
- A subscriber that falls more than `BROADCAST_CAPACITY` (16) commits behind (a stalled writer) is sent a terminal `Event::Error("lagged")` and disconnected (#632), for `Subscribe` and `SubscribeDiff` alike. It must resubscribe; the first event of the new connection is authoritative (`nos-watchdogd` `follow` and every resync-trigger daemon already reconnect on close).
- The diff is typed (#778): `diff_configs` compares root fields and keyed-list elements with `==` and serializes only what differs, so its transient is the JSON of the change, not of both configs.
  - Every keyed root list is paired by its typed key; a modified static routing instance pairs its `routes` by `subnet` the same way, so a one-route change in 22k routes serializes one route.
  - The singleton root fields (`hostname`, `lldp`, `logging`, `admin`, ...) are always walked as JSON: they are small, and a duplicate key inside one is reported even between equal sides.
  - The output is the full-JSON walk's (`diff_values`, kept as the test oracle): a differential test runs random edit sequences through both.
  - Restricted classes use `diff_configs_for_role`: `for_role` only changes `users` and `admin` (`Config::role_secrets`), so only those two slots are re-diffed from projections, without two whole-config clones per class.
- `config-mem` (#776) after #778: the ~50 MB step per wave is gone, but `nos-configd`'s `VmRSS` still creeps ~1.6 MB per 5500-route wave (34.9 MB after wave 2, 49.1 MB after wave 11), over the gate's ±25%. The config itself only grows ~0.35 MB per wave; the rest is an allocator follow-up, not the diff.

### Memory profiling (#766, #767)

- Image: `CARGO_FEATURES="nos-config/dhat-heap nos-rest/dhat-heap" make docker-build` (the Dockerfile passes one `--features` to the multi-`--bin` build; cargo resolves both `pkg/feature` entries). Default and release builds are unchanged. The dhat image inflates RSS: read RSS only from a default image.
- Watchdog args: `--configd-arg=--profile-memory-out=/tmp/dhat-configd.json --restd-arg=--profile-memory-out=/tmp/dhat-restd-{name}.json`. The watchdog replaces a literal `{name}` in pass-through flags with the instance name, so each `nos-restd` (one per table) gets its own file. The lab takes extra watchdog args from `NOS_E2E_WATCHDOG_ARGS` (space-separated) on `nos-e2e up`.
- Wave load: `LOGD_MEM_ROUTER=b [WAVE_COUNT=12] [WAVE_ROUTES=5500] [WAVE_IDLE=0] cargo run -p nos-e2e -- mem-wave`. Each wave opens a transaction on running, `PUT`s `WAVE_ROUTES` static routes one per request (spread over `ceil(total/25000)` instances), commits, and logs every `nos-*` daemon's `VmRSS`/`VmHWM` plus the cgroup after the commit and after `WAVE_IDLE` seconds. It fails if `nos-configd` or `nos-restd` changes pid.
- Gate (#776): `cargo run -p nos-e2e -- config-memory-lab` (`up`, `established`, phase `config-mem`; manual, not in CI) runs the same load on router-b with the same `WAVE_*` knobs and asserts `nos-configd`'s `VmRSS` after each commit from wave 2 on within ±25% of wave 2's, the sampled cgroup `memory.current` under 1.5 GiB, and the watchdog's `starting process=nos-configd ... env=MALLOC_ARENA_MAX=1` line. `VmHWM` and the idle samples are logged only. The watchdog starts `nos-configd` with `MALLOC_ARENA_MAX=1` (glibc per-thread arenas held about half its `VmHWM` in #766).
- At the end it prints the running config's JSON size, SIGINTs `nos-configd` and `nos-restd`, and prints their dhat `t-gmax`/`t-end` and the top 8 program points by max bytes, total bytes and bytes live at exit (2 frames below the allocator plus the first 3 `nos_*` frames). A non-dhat image just logs that there is no report. Not a phase (asserts nothing, not in `phases::ALL`).
- On the dhat image use a smaller load, e.g. `WAVE_COUNT=4 WAVE_ROUTES=2500`: dhat slows each allocation, so the default 12 x 5500 takes long. Read RSS from the default image, attribution from dhat.
- For a deeper split than the log lines, copy the report out before `down` (`docker exec router-b cat /tmp/dhat-configd.json > configd.json`) and load it in https://nnethercote.github.io/dh_view/dh_view.html.
- `cargo test -p nos-config --test resident -- --nocapture`: counting allocator over ~66k static routes with three `SubscribeDiff` subscribers (`User`, `Watchdog`, `Bgpd`, one per kind of visibility class) through `ConfigStore::subscribe_diff`. It runs 4 commits sharing 2000 single-route edits (`NOS_RESIDENT_PUTS` overrides) and prints one `Config`'s live size and these peaks:
  - per-`PUT` transient of `edit_transaction_path` (the edit without the snapshot reply), asserted at most 8 KiB;
  - the first `PUT` of each transaction, which unshares running (one copy), asserted at most 1.5 `Config`s;
  - store-level commit transient, asserted at most a quarter `Config`;
  - the subscribers' diff transient for the three classes, asserted at most 2.6 `Config`s (#778);
  - live heap after the commits, broadcast ring included, asserted at most an eighth of a `Config`. Tokio drops a ring slot's value once every receiver has read it, so only a lagging receiver keeps a commit alive.
- Measured at 66k in a debug build (#773): commit transient 0.14 `Config`, live after 4 commits ~0, per-`PUT` transient 11.6 `Config`s.
- After #775: per-`PUT` transient 1.7 KB (was 11.6 `Config`s, ~49 MB), first `PUT` 1.38 `Config`s, live after 4 commits below the seed (running re-cloned with exact capacities).
- After #778: diff transient 1.3 `Config`s for the three classes (was ~75, ~317 MB), asserted at most 2.6.
- Per-commit live heap (#796, dhat image only): `nos-configd` logs `heap after commit curr_bytes=… max_bytes=…` (`dhat::HeapStats`) after each commit, and `mem-wave` prints it per wave as `HEAP wave<n> configd VmRSS=… kB …`, next to that wave's RSS.
- #796 measurements, router-b, `nos-configd` after each commit:

  | Wave | dhat `curr_bytes`, 2500 routes/wave | `VmRSS` kB, default image, 5500/wave, before | `VmRSS` kB, after `MALLOC_TRIM_THRESHOLD_` |
  |---|---|---|---|
  | 2 | 2 578 365 | 33 716 | 29 240 |
  | 5 | 4 693 192 | 37 280 | 34 316 |
  | 8 | 6 863 090 | 44 432 | 39 280 |
  | 11 | 9 651 014 | 57 024 | 42 424 |

- Reading: live heap grows ~0.31 MB per 1000 routes (running config, the previous config still held for the subscribers' diffs, and per-connection write buffers sized to the largest frame), so ~15 MB from wave 2 (16.5k routes) to wave 11 (66k) at the default load. With the trim env, RSS grows by less than that (+13 MB): the remaining creep is live heap, not fragmentation.
- The watchdog starts `nos-configd` with `MALLOC_TRIM_THRESHOLD_=131072` and `MALLOC_TOP_PAD_=0` next to `MALLOC_ARENA_MAX=1` (#796). Setting the trim threshold also turns off glibc's dynamic mmap threshold, so large freed buffers go back to the kernel; wave 11 RSS went from 57.0 to 42.4 MB.
- The broadcast ring retains nothing (no `CommitUpdate` in dhat's live-at-exit points), so `BROADCAST_CAPACITY` stays 16.
- `nos-restd` live heap (#798, dhat image only): `kill -USR1 <pid>` makes it log `restd heap stats curr_bytes=… max_bytes=… total_bytes=…` (`dhat::HeapStats`). A default build has no handler, and SIGUSR1 kills it.
- `mem-wave` sends that SIGUSR1 at every sample when `nos-restd` runs with `--profile-memory-out` (only a dhat build accepts it), and prints `HEAP <label> restd VmRSS=… kB …`. It also prints each wave's `OPEN wave<n> <ms> ms <bytes> bytes` (`POST ?base=current`, the whole-config reply) and `COMMIT wave<n> …`.
- #798 measurements, router-b, `nos-restd` `VmRSS` MiB after each commit (default image, 12 x 5500 routes; experiments set through a local, uncommitted env hook):

  | Variant | Wave 2 | Wave 5 | Wave 8 | Wave 11 |
  |---|---|---|---|---|
  | baseline (run 1) | 93 | 177 | 294 | 314 |
  | baseline (run 2) | 96 | 207 | 263 | 271 |
  | `MALLOC_ARENA_MAX=1` | 106 | 190 | 277 | 397 |
  | `MALLOC_TRIM_THRESHOLD_=131072 MALLOC_TOP_PAD_=0` | 99 | 249 | 298 | 317 |
  | `POST ?base=current` replies `{}` | 76 | 143 | 266 | 294 |
  | `malloc_trim(0)` every second | 42 | 60 | 61 | 54 |

- Reading: the growth is free memory glibc keeps inside its heaps, not live data. On the dhat image (4 x 2500) the live heap after each commit stays at 13.8 MB while `VmRSS` goes 67 -> 156 MB. The once-per-wave whole-config reply (3.8 MB, 74 ms at 66k routes) is not the cause, and neither one arena nor a fixed trim threshold helps, because those only trim the top of a heap. An explicit `malloc_trim(0)`, which also releases free pages in the middle of a heap, keeps `VmRSS` flat.
- The allocation churn comes mostly from the harness's own `GET /v1/logs?follow` stream: `show::logs_follow` builds a `Vec<sse::Event>` per log batch (largest allocator by total and peak, 10.5 MB), next to a 4.7 MB live read buffer. Each `PUT` also allocates three fresh 8 KiB `FramedRead` buffers (`ipc::exchange`: two from `client_auth`, one to the broker and one to `nos-configd`, plus the `PUT`'s own call).

- Allocator (#801): `nos-restd` links `tikv-jemallocator` (`rest/src/main.rs`, off under `nos-rest/dhat-heap`). Jemalloc purges free pages back to the OS, which the glibc env knobs above could not do.
- `config-mem` baseline (#801): the median of waves 2-4, not wave 2 alone, because one sample can sit on a peak or a trough of the allocator's purge cycle. `nos-restd`'s `VmRSS` after each commit from wave 2 on must stay within ±25% or +15 MB (15 360 kB) of it, whichever is wider; the lower bound has no slack. `nos-configd` uses the same median and ±25%, no slack. The `nos-configd` band is a known-creep tolerance for the live-heap growth of #796 (closed as won't fix), not a proof that its RSS is flat.
- #801 measurements, router-b, `nos-restd` `VmRSS` MiB after each commit (default image, 12 x 5500 routes; glibc rows from #798):

  | Variant | Wave 2 | Wave 4 | Wave 7 | Wave 11 |
  |---|---|---|---|---|
  | glibc baseline (run 1) | 93 | - | - | 314 |
  | glibc baseline (run 2) | 96 | - | - | 271 |
  | jemalloc | 63 | 63 | 95 | 88 |
  | mimalloc | 58 | 99 | 61 | 75 |

- Reading: both allocators cut wave 11 from ~270-314 MiB to ~75-95 MiB but neither is flat: RSS saw-tooths between ~40 and ~100 MiB as the allocator's purge fires, so no baseline makes the +15 MB band reliable. mimalloc was not clearly better (similar swing, higher cgroup peak: 328 vs 272 MB), so jemalloc stays.

### Path edits (#775)

- `set_transaction_path` costs the addressed part, not the config (`config/src/path_edit.rs`):
  - one element of a top-level list (`bgp-instance/r1/...`) or one top-level section goes through JSON and back;
  - `static-routing-instance/<n>/route/<subnet>[/...]` touches one route of the typed list (key scan without allocation);
  - an empty path takes the whole-config route (the config through JSON and back).
- The edit is planned on the transaction's config under the lock; every check (path, key, anchor, JSON body, `<hidden>` masks) runs first, then the change applies in place with `Arc::make_mut`. A failed edit changes nothing. The first edit after `open(Current)` copies running once.
- A `users` edit goes through the off-lock argon2 hashing, then stores only the user list if the generation did not move.
- A differential unit test replays random edit sequences through both routes and requires the same configs and the same errors.
- `edit_transaction_path` is the same edit returning only the new generation, `dirty` and the edited subsection.

### Edit replies (#774)

- `EditTransactionPath` replies `Event::TransactionEdit { generation, dirty, value }`, not a full `TransactionSnapshot`: no copy or postcard of the config per `PUT`.
- `value` is read back from the edited section only (`path_edit::get`: one list element, one static route, or one top-level section); an empty path is the whole config.
- `nos-restd` masks secrets on that subsection with `nos_proto::redact_at(value, path)`, which walks `cli::root()` along the path; a unit test holds it to `Config::redacted()` at every path of a config with keys, users and BGP/OSPF auth. The REST contract is unchanged (`PUT` still replies with the stored, redacted subsection and the `ETag`).
- `nos` sends its writes, then reads the transaction once to check that its position still exists.
- `SetTransactionPath` (full-snapshot reply) stays in the enum for wire compatibility; no in-tree client sends it.

### Config plane vs data plane

| Plane | Transport | Pattern |
|-------|-----------|---------|
| Config | Unix socket + postcard | Request/subscribe |
| Data (e.g. BGP→RIB routes) | Unix socket + postcard | Fire-and-forget push over a persistent connection |

Both planes use the same transport stack. In practice the data plane so far reuses each target daemon's existing per-instance socket and request/event enum (e.g. `nos-ribd`'s `RibRequest::PushBgpRoutes`, `nos-bgpd`'s `BgpRequest::RedistributeRoutes`) rather than a dedicated separate socket/message-type pair — a fire-and-forget variant appended to the same `Request`-style enum the config plane already frames with `IpcCodec`, sent over one long-lived connection (`Full` snapshot on connect, incremental `Add`/`Remove` after), same pattern as `nos-logd`'s `LogRequest::Push`. A future high-enough-volume feed could still justify a dedicated socket/message-type pair instead.

