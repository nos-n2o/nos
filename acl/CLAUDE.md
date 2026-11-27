# nos-acl — access lists on tc (`nos-acld`)

A single fixed process (like `nos-stpd`): every `acl in`/`acl out` on an `Interface`, `Subinterface` or `PortAggregate` becomes tc flower filters on that kernel device. Stateless: no conntrack (`established` is "ACK or RST set").

## Flow

- `reconcile.rs`: `SubscribeDiff` on `Acls`/`Interfaces`/`PortAggregates` is only a trigger; every diff (and a 10 s tick) re-fetches the config into a `plan::Plan`.
- `plan.rs` (pure): `Compiler` compiles each ACL once per change (logs `compiled acl acl= rules= filters= levels= shadowed= trailing=`, the e2e anchor); a failed compile keeps the last good one (fail closed). `attachments` lists every attach point as a `Device` (`Kernel(name)` or `Aggregate { name, tag }`).
- `link_client.rs`: `nos-interfaced`'s `SubscribeLinks` stream, reimplemented per crate (`LinkAdded` folds like `LinkChanged`). Until a snapshot with `observed: true` arrives nothing is applied (a `noop` interfaced never gives one).
- `engine.rs`: per (device, direction) holds `{ifindex, chain, name, compiled}`; a pass resolves devices (a bond through `LinkState.port_aggregate`, never by deriving `bond<id>`), detaches what is no longer wanted, installs what changed. Driver calls block: the engine is a `Shared<D>` (`Arc<Mutex<Engine>>`) and a pass runs on `spawn_blocking` under the lock.
- `compile/` (pure): `compile(&Acl) -> Compiled { levels, default_action, rules, shadowed, trailing }` (the last two are rule indices = cookies, #543). `rule.rs` splits by family (prefix family, else `icmp` v4 / `icmpv6` v6, else both) and `established` into two filters (ACK, RST).
- `server.rs` + `status.rs` (#543): `--listen-socket` (watchdog `--acld-listen-socket`, `ServiceRef::Acl`) serves `AclRequest::Show`/`ClearCounters` to `User`/`Restd`. `Engine::show` dumps each installed chain (`Driver::counters`, `gact` rows by kind) under the same lock a pass takes; `status::status` (pure) sums per cookie across filters and devices, ignores stale cookies, marks dropped rules. Counters reset on any recompile (new chain; `ponytail:` carry-over left out); `ClearCounters` (#1419) is `Engine::clear_counters`: the same idle-chain install+switch forced through `apply_with`, logs `acl counters cleared acl= attachments=`; flowspec untouched. Every ACL of the last plan is listed, unattached ones at 0.
- `logger/` (#544): `Logger` (pure: sample -> `acl log` line, token bucket per (ifindex, direction, rule), overrun throttle), `packet.rs` (frame -> 5-tuple), and a detached `acl-log` thread on psample, started by `engine::run` (Linux driver only) once a `log` rule is installed; it names samples via `Engine::log_target`.
- Flowspec (#561): `flowspec.rs` (pure `lower(&FlowRule) -> Lowered`, refuse what flower cannot express), `engine_flowspec.rs` (per-(instance, VRF) snapshots, `FlowspecSet.table`, #1083; from `AclRequest::PushFlowspec`, `Role::Bgpd` only; one chain-0 prio per rule in 10..99, rewritten per changed prio), `flowspec_file.rs` (hidden `--flowspec-file` test hook). `nos-bgpd` pushes with `devices` empty (#562): `plan.flowspec` ((instance, table) -> the `flowspec` devices of its own table, or of a VRF whose `vpn` rides the instance) adds them; a rule no device holds shows `not attached`. Layout and lowering table: `docs/architecture/linux-drivers.md`.
- `driver/`: `Driver` trait (`live_chain`, `install`, `switch`, `flush`, `detach`, `counters`, `flowspec_set`/`_prios`/`_counters`), `noop.rs` (records calls, tests), `linux.rs` (only `nos-tc` calls; coverage-excluded). Request building (`chain_requests`, `entry_request`, `live_from`) is pure, in `driver/mod.rs`.

## Kernel layout (details: `docs/architecture/linux-drivers.md`)

- Chain 0, prio `ACL_PRIO` 100, handle 1: keyless flower `goto chain` 1000/1001; its gact cookie is the live chain (read back on start).
- Level `l`: prios `2l+1` (`ip`) and `2l+2` (`ipv6`) (the kernel refuses two protocols at one prio); a level holds every filter of the rules packed there. Defaults: one keyless filter per family after the rules. Cookies: user rule index (not the level), `u32::MAX` for defaults (`show acl` reads them).
- Update = install idle chain, replace chain 999 then the entry (`NLM_F_REPLACE`, last = commit point), flush old. A failed `switch` is re-switched to the old chain (first attach: detached) before the idle chain is flushed (#698). Flush tolerates `ENOENT`/`EINVAL`.
- Never delete the `clsact` qdisc; stay off other owners' priorities (`tc/CLAUDE.md`).
- `switch` also keeps chain 999 (`flowspec::EXIT_CHAIN`) pointing at the live ACL chain: a flowspec rule without the T bit jumps there, so the ACL still runs.

## Optimiser (`compile/optimize.rs`, `keys.rs`)

- Passes, in order: split rules into filters (`rule.rs`) -> drop shadowed (all filters of a rule inside filters of ONE earlier kept rule) -> pop trailing rules whose action is the default's (never a `log` rule) -> pack: level = 1 + max level of earlier kept rules that overlap, else 0.
- Invariant: overlap may over-approximate (costs levels), never under-approximate; contains may under-approximate (a shadowed rule is kept). `tests/equivalence.rs` (proptest: naive first-match vs flower evaluation of the levels) guards it.
- `ponytail:` ceilings: O(n^2) pair tests; single-rule shadow cover (no union); no cross-rule prefix merge (counters stay per rule). Levels beyond `MAX_LEVELS` fail the compile (previous ACL stays).

## Rules that bite

- Fail closed: a crash or a clean stop (SIGINT/SIGTERM) leaves filters and flowspec rules enforcing (#663); a closed plan/link feed makes the process exit non-zero so the watchdog restarts it; on start the first link snapshot is swept (chain-0 dump per device and hook) and what a previous run left is adopted, then replaced or detached. A refused install flushes the idle chain and keeps the old one live; retried on the next pass.
- An attach point whose device is absent logs `acl pending interface= direction= acl= reason="absent"` once and applies when the link shows up. A device that disappears is dropped without driver calls (its qdisc went with it).
- The untagged (tag 0) subinterface is its parent's device: the commit refuses both setting one direction (`schema::acl::one_per_device`).
- `log`: `sample` (group `ACL_PSAMPLE_GROUP`, one packet in `SAMPLE_RATE` = 100, `LOG_TRUNC`) then `gact`, one cookie (#699: the verdict counters stay exact, log lines are statistical). Flowspec S uses the same `sample_kind` and keeps its cookie on the action after the sample. `LinuxDriver::install` refuses a `log` ACL when psample cannot pass the cookie (`check_log`, owner decision L2); egress samples carry `out` = device, ingress `in` = device and `out` = 0.
- Under a `deny` default `compile` adds four implicit IPv6 ND permit filters (ICMPv6 133-136, cookie `IMPLICIT_ND_COOKIE` = `u32::MAX-1`, `Compiled.implicit`) as a synthetic last rule: user rules covering one shadow it, and a trailing user `deny` that overlaps them is not popped as the default's twin (#1530). `show acl` has an `implicit nd permit` row.
- L4 keys never match any fragment (flower never parses L4 of a first fragment either, measured in `tests/kernel.rs`, Linux 7.2), so `rule::filters` gives every `deny` with an L4 key an any-fragment twin per family (same cookie: `show acl` counts it on the rule; `docs/architecture/linux-drivers.md`); permits need none; `dscp`/`ttl` (#1540) are exact `ip_tos`/`ip_ttl` keys (twin too); `fragments` (#1539) adds `LATER_FRAGMENT` flags and the validator refuses it with L4 keys.

## Tests

- Unit: compile shapes, plan resolution, engine with `NoopDriver` (attach, A/B alternation, pending device, sweep, refused install, filters survive shutdown, closed feed is fatal), request bytes via `nos-tc` types.
- Kernel: `unshare -Urn cargo test -p nos-acl --test kernel -- --ignored` (`tc` as the oracle; a foreign prio-1 filter survives).
- e2e: `cargo run -p nos-e2e -- acl` (group `drivers`): attach, `?before=` drops BGP, `?after=` restores it, detach, `show acl` counters after the drop, `acl log` lines, packed `EDGE2`, `EDGE7` fragments, `EDGE8` dscp/ttl.
