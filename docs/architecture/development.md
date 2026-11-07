# Development: toolchain, CI and containers

Contributor-facing; moved from the root `CLAUDE.md` (#260).

**Rust toolchain.** Local `make` and CI run the same commands on the same toolchain (#153, #180):

- `ci.yml` pins `RUST_TOOLCHAIN` (fmt, clippy, test, coverage) and `MIRI_TOOLCHAIN` (a dated nightly, for `make miri`); `rust-toolchain.toml` pins the same stable. Every CI job runs the Makefile target (`make fmt`, `make clippy`, …), so commands, flags and `RUSTFLAGS` live in one place.
- Every Rust `make` target depends on `toolchain-check`, which fails when `rust-toolchain.toml` ≠ `RUST_TOOLCHAIN` and prints where cargo runs: `toolchain: 1.99.0 (native)` when local `rustc` is the pin (rustup, CI), else `(docker nos-ci:<pin>-<nightly>)` — the `tools/ci/Dockerfile` image (`make ci-image`, built on first use), with its own `target/ci` and cargo home under `target/`. A host without rustup (Fedora's older `rustc`) therefore still gets CI's exact clippy lints and nightly.
- The nightly cron runs two canaries that only warn: `Clippy (stable canary)` on the newest stable (also on every push/PR) and `Miri (nightly canary)` on the newest nightly.
- The `alert` job opens one `ci-red` issue (or comments on the open one) when any job or canary is red outside a PR. Branch protection isn't available on this plan, so nothing blocks a red merge: merge only after `gh pr checks <N> --watch` is all green.

**CI budgets (#827).** How to diagnose a job that dies or hangs:

- `Test`/`Coverage` set `CARGO_PROFILE_{DEV,TEST}_DEBUG=line-tables-only` in `ci.yml` only (local builds keep full debuginfo) and start with a "Free runner disk space" step that prints `df -h /` before and after. `rustc-LLVM ERROR: No space left on device` followed by `ld terminated with signal 7` is a full disk, not a linker bug: read those two `df` lines first.
- `Miri (UB check)` has `timeout-minutes: 45`; a hang fails fast instead of running to GitHub's 6 h cap.
- A test too slow for the interpreter gets `#[cfg_attr(miri, ignore = "reason")]` (as in `rpl/src/codegen.rs`, `proto/src/bgp.rs`, `ospf-common/src/drouters.rs`). Find outliers with `cargo +<MIRI_TOOLCHAIN> miri test -p <crate> -- -Zunstable-options --report-time`; a test printed without a result after minutes is the culprit. Miri runs tests serially, so one slow test blocks the rest. Measured on the nightly pin (#827): `nos-rpl` ~2 min, `nos-ospf-common` ~2 min, `nos-proto` ~13 min; the tests that do large-N loops, ~16 MiB frames or full-`Config` diffs are ignored under Miri (and `the_typed_diff_matches_the_full_json_walk` runs 3 rounds instead of 300).

To bump:

- Change `RUST_TOOLCHAIN` (ci.yml) and `channel` (rust-toolchain.toml) together; `make toolchain-check` enforces it.
- Bump `MIRI_TOOLCHAIN` to a recent nightly date that ships `miri`.
- Run `make ci-image check miri` — on a host without the new toolchain it runs in the new `nos-ci` image automatically.
- Fix the new lints and deprecations in the same PR. A lint an older toolchain doesn't know only prints an `unknown_lints` warning, which `-D warnings` doesn't promote.
- The PR touches `ci.yml`, so every job runs on it: don't merge until `gh pr checks` is all green, Miri included.
- Close any open `ci-red` issue the bump fixes.

The release `Dockerfile` floats on `rust:1-slim-bookworm`, harmless since release builds don't use `-D warnings`.

**Image hardening (#405)**:
- Both base images are pinned by manifest-list digest (tag kept beside it); `.github/dependabot.yml` (docker ecosystem, weekly) bumps them. apt packages stay unpinned (DL3008 ignored): pinned versions break on every bookworm security update.
- File capabilities are `=ep` (the inheritable bit is dead weight for a non-root exec).
- `watchdog` and `cli` run with `read_only: true` and a `/tmp` tmpfs; state lives in the `/run/nos` and `/var/lib/nos` volumes. `nos-e2e` mirrors this in `Dock::start` (it does not use compose).

`watchdog/tests/system.rs` is the unprivileged whole-stack smoke test: the real `nos-watchdogd` supervising every real daemon (`--driver noop`, every socket and state file under a temp dir — `--run-dir` moves the per-instance `<prefix>-<name>.sock` sockets off `/run/nos`), provisioned by the real `nos-provision`, reconfigured, then stopped with SIGTERM. It needs every daemon binary built next to `nos-watchdogd`, which is why each daemon crate has at least one integration test (`tests/bin.rs` where nothing else existed); a single-package run without them skips.

**Fake IPC servers for tests** (`nos-test-support`, #347):

- Use it instead of a per-crate `serve_once`: `FakeConfigd`, `FakeWatchdog`, `FakeRibd`, `FakeInterfaced`, or `Fakes::start(&[Fake::Configd(cfg), Fake::Watchdog, Fake::Ribd("rt1".into()), Fake::Interfaced])` for a whole set with one watchdog pre-filled for exactly the started services.
- A service left out of `Fakes::start` has no socket and the watchdog answers `NotAvailable` for it: that is how a test reaches a daemon's "unreachable" branch.
- Every fake loops on accept and speaks real mutual TLS. The client must dial the fake's identity: configd, watchdog and interfaced use the empty name, ribd uses the routing-table name (`nos_pki::connect(path, "ribd", "rt1")`).
- Resync tests: `connections()` counts accepted dials, `close_connections()` (`close_stream()` on configd) forces a redial, `FakeConfigd::push_diff` feeds `SubscribeDiff` subscribers, `FakeInterfaced::push_link` feeds `SubscribeLinks`.
- Fire-and-forget requests (`Push*`, `SetStpPortStates`, `FlushFdb`, `SetErrDisabled`) are recorded: `take_pushed()` drains them. `serve` + `Reply` builds a one-off fake for any other protocol.
- Dev-dependency only, with the feature: `nos-test-support = { workspace = true, features = ["fakes"] }`. Without `fakes` the crate is empty, so `cargo build --workspace` never turns on `nos-pki/testing` for the daemons.

Containerized test environment:

```bash
make docker-build                        # build the nos-watchdogd/nos-configd/nos-bgpd/nos-ribd/nos-interfaced/nos-logd/nos-ospfd/nos-ospfv3d/nos-lacpd/nos-lldpd/nos-fdbd/nos-restd/nos Docker image
docker compose up -d watchdog            # run the watchdog (which starts nos-configd + nos-bgpd + nos-ribd + nos-interfaced + nos-logd + nos-ospfd + nos-ospfv3d + nos-lacpd + nos-lldpd, a nos-fdbd per broadcast domain with a vni, and a nos-restd per pinned routing table) in a container
docker compose run --rm cli              # interactive shell, as its own container, sharing configd's socket
```

`watchdog` and `cli` share the same image and an `nos-run` volume mounted at `/run/nos`, so `cli` reaches the daemon over the same Unix socket path both binaries default to. `watchdog` also gets an `nos-data` volume at `/var/lib/nos` (one `0700` directory per daemon role, made by the watchdog) so `save`d config survives container restarts. `docker compose exec watchdog nos` still works too — it just runs the shell inside the watchdog's own container instead of a separate one.

**Memory profiling**: `docker build --build-arg CARGO_FEATURES=nos-bgp/dhat-heap -t nos .` builds `nos-bgpd` with `dhat` heap profiling (see `docs/protocols/bgp-internals.md`'s "Memory profiling"); run it via `docker compose run --rm watchdog --bgpd-arg --profile-memory-out=/var/lib/nos/bgpd/dhat-heap.json` (`--bgpd-arg` is `nos-watchdogd`'s existing opaque pass-through to every spawned `nos-bgpd` instance — no watchdog code involved) and load the resulting report from the `nos-data` volume at https://nnethercote.github.io/dh_view/dh_view.html. `nos-configd` and `nos-restd` have the same feature: see "Memory profiling" in [config-protocol.md](config-protocol.md).

Or run the underlying commands directly:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all
```

## Function length lint

- `clippy::too_many_lines` is `warn` (denied in CI) at `too-many-lines-threshold = 150` in `clippy.toml`; nesting depth is `excessive-nesting-threshold`. Both live next to each other in `Cargo.toml`'s `[workspace.lints.clippy]`.
- Split a long function into named helpers next to it (per phase, or per match arm); never change a log string or lock order doing so.
- A flat one-arm-per-topic table opts out with `#[allow(clippy::too_many_lines, reason = "...")]` on that function only (`config/src/docs.rs` `command_doc`, `nos-provision`'s `build_ops`).
- The lint counts code lines (comments and blanks excluded) and applies to `--all-targets`, so test functions are held to it too.

## Mutation testing

- Run: `make mutants` (nightly; `MUTANTS_JOBS` default 2, `MUTANTS_MEM` default 20G, `MUTANTS_ARGS` for e.g. `-f rpl/src/parser.rs` or `--shard 0/8`). `CARGO_TARGET_DIR` is unset for the run so each job builds its own copy of the tree under `MUTANTS_TMPDIR` (`~/.cache/nos-mutants`, ~20 GB per job).
- A shared `CARGO_TARGET_DIR` across `-j` jobs makes a mutant run another job's binary (false MISSED), hence the unset above.
- Memory: each test process runs under `ulimit -v` (`NOS_MUTANTS_AS_KB`, default 6 GiB) through the nextest `mutants` profile's run-wrapper (`.config/nextest.toml`); a runaway mutant aborts itself. `systemd-run --scope -p MemoryMax` wraps the whole local run as a backstop when available. A global `ulimit -v` is not used: it would break rustc.
- Config: `.cargo/mutants.toml`. Its `exclude_globs` mirror `make coverage`'s `--ignore-filename-regex`; keep both in sync. `exclude_re` skips daemon glue (`main`, `wait_or_shutdown`, `resolve_once`, `resolve_with_retry`), which only `nos-e2e` can test.
- Looping mutants end as TIMEOUT after `max(60s, 3x baseline)`.
- CI (`ci.yml` `mutants`, nightly or `workflow_dispatch`): 8 shards (`--shard k/8`), `make mutants` reports survivors and timeouts (cargo-mutants exit 2/3) without failing; only infra errors fail; `mutants-out-<k>` artifacts hold the results.
- Resume or re-check one mutant: `make mutants MUTANTS_ARGS="-F '^exact name$'"`.

## Dependency policy

- `cargo deny check` (`deny.toml`) runs in CI: unmaintained crates fail (`unmaintained = "all"`), duplicate versions only warn (`multiple-versions = "warn"`).
- A duplicate that a NOS manifest causes (a pinned older major, a second crate for the same job) gets fixed; duplicates reached only through third-party crates are left alone.
- An advisory that NOS cannot fix is ignored in `deny.toml` with a `reason` (today: `atomic-polyfill`, via `postcard` 1).
- YAML is `serde_norway` (maintained fork of `serde_yaml` 0.9, same on-disk format); timestamps use `time`, not `chrono`.
- `tokio` has no `full`: the workspace entry lists the common features, crates add `signal`/`process`.

## Pinned GitHub Actions

- Every `uses:` in `.github/workflows` is a full commit SHA with the release tag as a comment (`uses: o/r@<sha> # v1.2.3`); the `semgrep` job image is pinned by digest. Workflows default to `permissions: contents: read`.
- `tools/ci/pin-actions.sh` pins any unpinned ref; `--update` moves each pin to the newest tag of the same major; `--check` fails on an unpinned ref or a SHA that is not the commented tag (needs an authenticated `gh`).
- `.github/dependabot.yml` opens weekly grouped bumps and rewrites the tag comment too.
- `dtolnay/rust-toolchain` has no per-toolchain tags: it is pinned at `master` and always gets an explicit `toolchain:` (the canaries pass `stable`/`nightly`, so they still float). `taiki-e/install-action` is pinned at a release and selects the tool with `with: tool:`.
- To add an action: write `uses: o/r@v1`, run `tools/ci/pin-actions.sh`, commit the result.
- Repo setting (admin, after the pins are merged): Settings, Actions, General, "Require actions to be pinned to a full-length commit SHA".

## Fuzzing

- `fuzz/` (`nos-fuzz`, own workspace, so `make check`/deny/coverage/mutants never see it) holds one `cargo-fuzz` target per untrusted-bytes decoder: `bgp_codec` (flags from the first input byte, multi-frame), `ospfv3_lsa`, `ospfv3_packet`, `ospf_packet` (also `ospf::lsa`), `evpn_nlris`, `rtr_codec` (version from the first byte), `lldp_packet`, `lacp_packet`. Property: no panic, abort or OOM.
- Install: `make tools` (adds `cargo-fuzz`); needs a nightly toolchain.
- Smoke run: `make fuzz-smoke` (`FUZZ_SECS` per target, default 60; `FUZZ_TARGETS` to narrow; `FUZZ_RSS_MB` caps libFuzzer memory, default 2048 — do not use `ulimit -v`, ASan cannot start under it; the target sets `RUSTFLAGS=--cap-lints allow` because cargo-fuzz adds `-D warnings`, which trips on nightly-only deprecations). CI runs it as `fuzz-smoke` (nightly cron or `workflow_dispatch`); a crash fails the job, feeds the `ci-red` alert and uploads `fuzz-artifacts`.
- Longer run of one target: `cd fuzz && cargo +nightly fuzz run <target> -- -max_total_time=600`.
- Reproduce a crash: `cd fuzz && cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>`.
- A found crash becomes a regression unit test in the owning crate (minimised input as a `const` byte array) before the fix.
- No seeds are committed (no binaries in the repo): `fuzz/corpus`, `fuzz/artifacts` and `fuzz/target` are git-ignored. Locally the corpus builds up in `fuzz/corpus/<target>/`; CI keeps it between nightly runs with `actions/cache`. Add a target by adding a `[[bin]]` plus a file under `fuzz/fuzz_targets/`, and its name to `FUZZ_TARGETS`.

## tokio pitfalls

- Register sockets with the per-crate `register_fd` (`l2-socket`, `ospf`, `ospfv3`, `bfd`), never `AsyncFd::new` (deprecated, RUSTSEC-2026-0386); the workspace floor is tokio 1.53.3.
- A `start_paused` test that does real socket I/O must `tokio::time::advance` by hand: the paused clock no longer auto-advances while I/O is pending (see `run_reapplies_on_the_tick_without_a_diff`).
- An e2e phase must not wait on a log line emitted just before a flood of thousands of lines: `nos-logd`'s 1024-entry tail channel drops entries for the REST follower (`log tail subscriber lagged`). Count the container stdout instead (`stdout_count` in `tools/e2e/src/phases/bgp.rs`, #838).
