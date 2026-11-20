# How the e2e harness drives NOS

Contributor-facing; moved from the root `CLAUDE.md` (#260). Phase list: [e2e-phases.md](../e2e-phases.md).

**How the harness drives NOS.** `nos-cli`'s interactive shell (reedline) can't be scripted over a plain pipe, so `nos-e2e` uses the REST API (`nos-restd`, see `rest/CLAUDE.md`) for everything:

- **Bootstrap.** REST only exists once the config pins it (`rest-api` on `rt1`), so a router's *first* config is seeded rather than sent: `nos-e2e` builds it in memory, writes it as `/var/lib/nos/configd/config.yaml` into the created-but-not-started container (`nos-configd` loads that path at startup), then starts it and polls `GET /v1/config` until the API answers. The pin stays in the config for every later provisioning, so REST stays up for the whole run.
- **Provisioning.** `nos-provision` (a lib plus a bin) owns the flag → `ConfigOp` mapping (`nos_provision::build_ops`). `nos-e2e` parses the same flags, opens a transaction over REST (`base=current`), applies the ops locally onto the returned `Config` (`ConfigOp::apply`), `PUT`s the config back (one request, or whole-subsection `PUT`s when it exceeds `nos-restd`'s 2 MiB body limit, e.g. tens of thousands of static routes, #754) and commits. The `nos-provision` *binary* (the same ops over `nos-configd`'s IPC socket) is still used by `tools/bench-bgp.sh`.
- **Assertions.** Each router's logs are collected by a background task holding `GET /v1/logs/follow` (SSE) open, de-duplicating across reconnects — so assertions never depend on the `nos-logd` ring buffer not wrapping. Patterns are the old `grep` (POSIX BRE) patterns, matched against `<message> k=v k=v` (`logs::bre` translates them). Containers run with `RUST_LOG=debug` (not the daemons' default `trace`): at trace, serving the log stream makes `nos-restd` log poller activity that is forwarded and streamed again.
- **The one place REST can't be used** is checking what happens when REST itself goes away: the `rest` phase's "address not on the VRF is retried" and "unpinning stops the process and closes the port" checks run on a throwaway `router-r` container and read its `docker logs` (through `bollard`), since the API and its log stream are exactly what those checks sever.
- Containers run with a read-only rootfs and a `/tmp` tmpfs (`Dock::start`), mirroring `docker-compose.yml`; the seeded config lands in the `/var/lib/nos` volume, in `configd/`. `Dock::exec` runs as the client user `nos`; `exec_root` is for signalling a daemon (each role has its own uid) or reading its private state.
- The image is **not** built by the harness (BuildKit is required for this Dockerfile): run `make docker-build` first — CI already builds `nos:local`.
- **Per-worktree image (#1048).** `nos-e2e` runs the image named by `NOS_E2E_IMAGE` (default `nos:local`) for every NOS container, including `router-r` and restarted routers. Two worktrees must not share the mutable `nos:local` tag: build `make docker-build IMAGE=nos:issue-<N>` and run `NOS_E2E_IMAGE=nos:issue-<N> cargo run -p nos-e2e -- <phase>`; `make e2e-preflight IMAGE=nos:issue-<N>` checks that image.
- `make e2e-preflight` (`tools/ci/e2e-preflight.sh`, the same script `verify-e2e.yml` runs before the harness) checks the host has every kernel module the lab needs and that the image's `nos-ribd` still carries its `cap_net_admin` file capability — run it when `up` fails with "REST API never came up". Which modules, which phases each blocks, and how to load them: [Host kernel modules](#host-kernel-modules).
- **Phases must undo what they set.** Provisioning is cumulative and docker networks outlive a phase, so a leftover leaks into every later phase of a group: `ospf-opaque` disconnects router-a from the FRR network (else `link_veths` reuses that NIC as `eth1` instead of a veth to router-b), clears its `redistribute … to ospf` rule (else `ospfv3-asbr` never sees a *new* Type-5), and `ospf-bfd`/`ospfv3-bfd` clear their loopback profile (else `ospfv3-lfa` re-provisions an identical config and sees no new route). When a phase passes alone but fails in its group, bisect the earlier phases for such a leftover before touching the failing one (#456).

## Parallel labs (#1049)

Two labs run side by side on one docker host (`NOS_E2E_LAB=<k>`, `k` in 0..1); lab 0 is the historical lab, byte for byte, and is what CI uses.

- **Slots.** `tools/ci/e2e-lab.sh acquire` takes the first free slot (`/tmp/nos-e2e.lock.<k>`, `NOS_E2E_LABS`, default 2), records worktree/pid/start time and prints `k`; `release <k>` frees it; `status` lists the slots and flags one whose pid is gone as STALE. Run every `nos-e2e` command of one session with `NOS_E2E_LAB=$k`. The lock spans several `cargo run -p nos-e2e` invocations (`up`, phases, `down`), so it is a script convention, not harness code. A caller whose shell exits between commands (an agent) is flagged STALE too: check `docker ps` for `l<k>-` containers before releasing.
- **Failure dump.** A failed group dumps `docker logs` of the one container the error names, from the start of the failing phase (10x the tail); with no culprit in the message, every container's tail.
- **Keep going (`NOS_E2E_KEEP_GOING=1`).** Set by the nightly only (`schedule`; PRs, dispatch and local runs stay fail-fast). A failing phase is recorded, its docker logs are dumped right then (from that phase's start) and the next phase runs; `up`/`established` stay fatal.
  - After the group a summary lists every phase `OK`/`FAILED`; exit is non-zero with `N phase(s) failed, first <phase>: <err>`. `all` then runs every group.
  - Failures after the first are tagged `may be a cascade` (a failed phase skips its cleanup and leaks state): fix the first failure and re-run.
  - `tools/ci/e2e-result-line.sh` reports the first failed phase.
- **Names.** At the `Dock` boundary (`tools/e2e/src/docker.rs`) every container, network and volume name gets the prefix `l<k>-` for `k>0` (`l1-router-a`, `l1-nos-verify-net`); phases keep writing `"router-a"`. `router-r`'s `docker logs` and the `nos` uid rule see the unprefixed name.
- **Labels.** Every container, network and volume carries `nos-e2e.lab=<k>`, and `down` / group teardown remove everything with that label, so one lab's `down` never touches the other's. A container from before #1049 has no label: remove it by hand once.
- **Subnets.** Docker rejects overlapping pools, so each network with explicit IPAM moves with `k` (`tools/e2e/src/lab.rs`, the `Addr` constants in `consts.rs`; use `.s()` for a `&'static str`, `{ADDR}` in `format!`): `10.50/51/52.x` becomes `10.60/61/62.x`, `fd00:10:50::` `fd00:10:60::`, the CE/L3 networks `198.18.x` `198.19.x`, `fd18:`/`fd19:` `fd28:`/`fd29:`. A new explicit subnet must be an `Addr`, never a literal. Auto-allocated networks and addresses inside containers need nothing.
- **Ports, netns, images.** No port is published (REST goes to the container IP) and veths are created into each container's netns by pid, so nothing collides on the host. The NOS image is per lab (`NOS_E2E_IMAGE`). The shared helper images (`nos-e2e-gobgp:local`, FRR, the netns helper...) are built or pulled under an `flock` on `/tmp/nos-e2e-helper-build.lock`, so two labs never race on a tag.
- **Memory** (peak summed `docker stats` of one lab's containers, sampled every ~3 s):

| Group | Peak (MiB) | Containers at peak |
|---|---|---|
| `base` | 397 | 2 |
| `drivers` | 198 | 2 |
| `ospf-suite` | 457 | 5 |
| `multi` | 290 (stopped by #928 at `vpn`, so a lower bound) | 6 |

  Measured with both labs running at once on the 31 GB, 24-core host. A lab is under 0.5 GB, far below the ~8 GB threshold at which `multi` would be kept to slot 0, so every group may run on either slot, and a third slot would fit memory-wise (the 2 GiB per-container cap is the limit, not the sum). The host's real consumers are the implementers' release builds (`CARGO_BUILD_JOBS=8` while two labs are up).

## Build requirements (#1250)

- `nos-e2e` links `ssh2` (libssh2) against the system OpenSSL: the host needs `libssl-dev` and `pkg-config` to build it (Debian/Ubuntu: `apt install libssl-dev pkg-config`; Fedora: `openssl-devel pkgconf`). `ci.yml` and `tools/ci/Dockerfile` install them.
- Why not `russh`: its `russh-util` pulls `chrono` (RUSTSEC-2026-0543). libssh2 cannot open `direct-streamlocal`, so `ssh-login-shell` checks `sshd -T` for `allowstreamlocalforwarding no` instead.

## Host kernel modules

A container cannot `modprobe`, so the docker host must have every module the lab uses; a missing one makes a phase fail like a product regression (`stp-mstp`, `ospf-graceful-restart`, `vpn` did on a host without `cls_fw act_skbedit act_sample psample mpls_router mpls_iptunnel`, #897). The per-phase table is in [e2e-phases.md](../e2e-phases.md#kernel-modules).

- Load them once: `sudo modprobe -a vrf dummy bonding vxlan 8021q bridge ipip cls_flower cls_fw act_skbedit act_mirred act_gact sch_ingress cls_u32 act_sample psample mpls_router mpls_iptunnel`. Without `-a` every name after the first is taken as a parameter of the first.
- Load them at every boot: put one module name per line in `/etc/modules-load.d/nos-e2e.conf` (same list), then `sudo systemctl restart systemd-modules-load`.
- Load `mpls_router` before the lab starts: `/proc/sys/net/mpls` only exists in network namespaces created after it loads.
- Check: `make e2e-preflight` exits 1 naming every missing module and the phases it blocks. Built-in modules count (`modules.builtin`). `NOS_E2E_PREFLIGHT_ASSUME_MISSING="cls_u32 psample"` makes it pretend those are absent, to see the message.
- A failed `nos-e2e` run checks the same list on its own host and prints the missing modules that block the phases it ran (`tools/e2e/src/modules.rs`); no output means the modules are not the cause.
- Add a module (a feature needing a new tc action, as `act_mirred` was for #865/#891): one row in the `table` of `tools/ci/e2e-preflight.sh` (the script and `nos-e2e` both read it), one row in the table of `docs/e2e-phases.md`, and the module in the `modprobe` line and snippet above. `cargo test -p nos-e2e` fails if a row names an unknown phase.

## Diagnosing and measuring flaky checks

- **Quiet checks** (`assert_quiet`): take the baseline with `Router::count_fresh` (waits for the log store to go quiet first), never baseline 0 (take `count` at phase start), scope the pattern (neighbor id, link, prefix), anchor the window to a real convergence event, after a reset the test caused, wait for the re-establishment on BOTH routers before baselining, and widen a window at most 2x with a comment saying why.
- **Failure output**: `assert_quiet` lists each offending line as `+<ms>ms <line>` (offset from the baseline-th match, or the last stored line when the baseline is 0; max 10 lines, then "and N more") plus the window. `wait_new` and `assert_quiet` log `baseline=<n>` when they start; `wait_new`'s timeout error shows the last 3 matching lines, so a stale-line false pass is visible.
- **`Logs::barrier`**: returns when the store length is unchanged for 2 consecutive 250ms polls (capped at 10s, then it warns and returns). It is quiescence, not a guarantee that every line was delivered.
- **Soak**: `make e2e-soak GROUP=<g> N=<n>` (`tools/ci/e2e-soak.sh`) runs one group n times serially (groups create and tear down their own containers, so runs are independent). Groups: `base`, `drivers`, `rpl`, `ospf-suite`, `pki-suite`; `multi` is refused until the `evpn-l3-chunked` hang is fixed, and `all` is not accepted (it is the groups in sequence, one soak per group).
  - It acquires a lab slot (`tools/ci/e2e-lab.sh acquire`, [Parallel labs](#parallel-labs-1049)) for the whole loop, runs on it (`NOS_E2E_LAB`) and fails fast when both slots are held.
  - Output goes to `$TMPDIR/e2e-soak/<group>-<ts>/`: `results.txt` (`<i> PASS|FAIL <secs>s`, plus the failing phase and error on FAIL) and the logs of the last 3 failed runs (passing runs' logs are deleted).
  - The closing table counts failures per phase and error; paste it in the PR. Use N=10 to rank flaky checks; N=1 only proves the script.
- **Soak on GitHub runners (#1050)**: dispatch `verify-e2e` instead of holding the local lab (a 10-run soak is ~10 h locally, ~1 h on runners).
  - Dispatch: `gh workflow run verify-e2e.yml --ref <branch> -f group=base -f runs=10` (`group`: one group or `all`, default `all`; `runs`: 1-20 per group, default 1; `ref`: branch/tag/sha to test, default the dispatched ref). The `plan` job expands `group x run` into the matrix; every cell is its own runner and builds the image with `NOS_BUILD_REV` set to the tested sha. The nightly schedule is `all` x 1.
  - Result: the `Results summary` job writes, per group, the soak format (`<i> PASS|FAIL <secs>s <phase> | <error>`, from `tools/ci/e2e-result-line.sh`, which `e2e-soak.sh` shares) and the per-check failure counts to the run's summary page. Cells use `fail-fast: false`, so one red run never cancels the rest.
  - Cost: every cell is a full runner-job (image build from the gha cache, then the group), so `runs=10` of `ospf-suite` is 10 runner-jobs; use `base` x 3 to check a change to the workflow itself.
  - Versus the local lab: a runner is a stock Ubuntu VM, so its kernel may lack modules the host loads by hand; the `tools/ci/e2e-preflight.sh` step (the `make e2e-preflight` script) fails the cell naming them before the group runs, so a preflight failure is not a flake. Timings differ from the local host (2 vCPU), so a check that is flaky only on runners is a real timing finding, not a runner bug. `multi` is allowed here (the local soak refuses it, #839); a hang runs to the 6 h job default.

## Host tools

- `restconf-conformance` (#1177) runs `yanglint` (`libyang2-tools`) on the host as an independent oracle against `docs/yang/nos-config.yang`; it is never in the runtime image. A missing binary fails the phase (no silent skip). CI installs it in `verify-e2e.yml`; locally `apt-get install libyang2-tools`.
