#!/usr/bin/env bash
# BGP performance benchmark: nos-bgpd vs GoBGP / BIRD / FRR.
#
# Same shape as tools/verify-e2e.sh (docker network, subcommands, everything
# observed from outside the container), but measuring instead of asserting.
# One daemon under test at a time, in a fixed three-container topology:
#
#   exabgp x PEERS (injectors)     DUT under test          gobgp (monitor)
#   10.60.0.11 .. 10.60.0.1n  ─▶  10.60.0.2  ─────────▶  10.60.0.3
#   each announces the same N       nos | gobgp |          counts the best
#   prefixes, AS 65100+k            bird | frr             paths that survive
#                                   AS 65001               AS 65200
#
# Every injector announces the same N prefixes, so the DUT holds PEERS paths
# per prefix and runs best-path selection over all of them; AS_PATH padding
# hands each peer an even share of the winning paths (peer k wins prefix i
# when i % PEERS == k-1), so convergence needs every peer's view, not one.
# With POLICY=1 (the default) each injector session also carries an import
# policy -- reject anything tagged $DROP_COMMUNITY (every DROP_EVERY-th
# prefix), set local-pref on the rest -- expressed natively per daemon: RPL
# for nos, a filter for BIRD, a route-map for FRR, a policy-definition for
# GoBGP. That is what the numbers are meant to represent: a router taking
# several full views through real policy, not one clean table.
#
# The monitor is how every daemon is measured uniformly: `nos`'s shell is
# reedline-only (no one-shot command mode) and nos-bgpd's IPC surface has no
# route counters at all, so there is no scriptable way to ask nos how many
# routes it holds. A GoBGP monitor peering the DUT counts prefixes the same
# way for all four, and measures the whole receive -> best-path ->
# re-advertise pipeline rather than just "bytes arrived".
#
# The nos DUT advertises RFC 4724 graceful restart (on by default), but
# neither ExaBGP nor the GoBGP monitor advertises it back here, so it sends no
# End-of-RIB and keeps no stale routes: the capability is inert in this
# topology and killing the injectors is still a hard flap.
#
# Fairness notes, because the numbers are meaningless without them:
#   * All five rows now install their received best paths into a real
#     kernel routing table, not just three of the previous four:
#       - nos/nos-quiet: nos-bgpd pushes its loc-rib to the owning nos-ribd
#         instance (RibRequest::PushBgpRoutes, root CLAUDE.md's "Config
#         plane vs data plane"), which installs it via LinuxRibDriver into
#         a VRF-scoped table.
#       - gobgp: bundled with a real zebra (a second process in the same
#         container, see $GOBGP_ZEBRA_IMAGE) and its own [zebra.config],
#         since gobgpd has no kernel installer of its own.
#       - frr: run with zebra enabled alongside bgpd (see
#         $WORKDIR/frr-daemons), not bgpd alone as before.
#       - bird: `protocol kernel { ipv4 { export all; }; }` (see
#         gen_dut_configs), in-process -- no second daemon involved.
#     This benchmark still samples the BGP decision process alone
#     (nos-bgpd/gobgpd/bgpd), never the container as a whole -- so for
#     nos/gobgp/frr, the second process actually doing the kernel work
#     (nos-ribd/zebra) is NOT folded into peak_rss_mb/cpu_s. BIRD is the
#     one exception: its kernel sync runs in the same process being
#     sampled, so its numbers already include that cost -- not a bug, just
#     a real structural difference between "kernel install is a separate
#     process" (nos, frr, gobgp) and "kernel install is the same process"
#     (bird) that no amount of container-level sampling can paper over.
#     `kernel_routes`/`kernel_deploy_s` in the results table are what
#     confirm the install actually happened and how long it took -- see
#     wait_for_kernel_routes (nos, via a log line) and
#     wait_for_main_table_routes (gobgp/bird/frr, via /proc/net/route,
#     since they install into their container's ordinary main table rather
#     than a VRF-scoped one).
#   * The nos container runs five daemons under the watchdog, so memory/CPU
#     is sampled per *process* (nos-bgpd only), never per container.
#   * nos is measured twice: `nos` as it ships (per-route `info!` logging in
#     bgp/src/rib.rs, plus rtnetlink TRACE dumps from the other daemons) and
#     `nos-quiet` (RUST_LOG=info,nos_bgp::rib=warn), which is the comparable
#     number -- the other three do not log per route by default.
#   * No per-daemon tuning: default timers, one peer-group per neighbour, and
#     one import policy shared by every injector session -- the same rule in
#     four syntaxes, never a different rule per daemon.
#
# Usage: tools/bench-bgp.sh {up|run <dut> [N]|all [N]|report|logs [n]|down}
#        dut = nos | nos-quiet | gobgp | bird | frr
#        N   = prefixes announced *per peer*
#        env: PEERS=<n>          how many full views to take (default 4)
#             POLICY=0|1         apply the import policy above (default 1)
#             PROFILE_MEMORY=1   nos/nos-quiet only: pass --profile-memory-out
#                                to the DUT's nos-bgpd (needs an image built
#                                with CARGO_FEATURES=nos-bgp/dhat-heap, see
#                                docs/architecture/development.md's "Memory profiling"); the
#                                report is copied to
#                                target/bench-bgp/dhat-heap-<dut>-<N>.json
#                                before the DUT container is torn down
#             KERNEL_DEPLOY_TIMEOUT=<s>  cap on waiting for the DUT to
#                                finish installing its routes into the
#                                kernel table (default 180; all five duts)
#        e.g. PEERS=1 POLICY=0 tools/bench-bgp.sh run nos 1000   # smoke test
#             CARGO_FEATURES=nos-bgp/dhat-heap tools/bench-bgp.sh up
#             PROFILE_MEMORY=1 tools/bench-bgp.sh run nos-quiet 100000
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Same split-target-dir reasoning as verify-e2e.sh: nos-provision must be
# built against trixie's glibc to run inside the runtime image.
PROVISION_BIN="$REPO/target/docker-verify/release/nos-provision"
WORKDIR="$REPO/target/bench-bgp"
RESULTS="$WORKDIR/results.tsv"

NOS_IMAGE=${NOS_IMAGE:-nos:local}
GOBGP_IMAGE=${GOBGP_IMAGE:-nos-bench-gobgp:local}
GOBGP_VERSION=${GOBGP_VERSION:-4.9.0}
# GoBGP has no built-in kernel installer of its own -- only a real zebra,
# spoken to over FRR's zapi protocol, can get its routes into the kernel.
# This second image bundles gobgpd with zebra itself (see
# build_gobgp_zebra_image), used only for the gobgp DUT; $GOBGP_IMAGE (no
# zebra) is still used for the monitor, which only ever reads gobgpd's own
# RIB over its API and never touches a kernel table.
GOBGP_ZEBRA_IMAGE=${GOBGP_ZEBRA_IMAGE:-nos-bench-gobgp-zebra:local}
# Deliberately pinned independently of $FRR_IMAGE below (the FRR DUT's own
# version): GoBGP 4.9.0's bundled zapi v6 client (pkg/zebra/zapi.go) is a
# static struct-offset implementation written against a specific FRR
# release (its own `MaxSoftware = NewSoftware(MaxZapiVer, "frr8.2")`) --
# newer zebra releases have since drifted the zapi6 wire format enough to
# break decoding (confirmed empirically against 8.5.4 and 10.7.1 while
# adding this). 8.2.2 is the exact version its comments target.
GOBGP_ZEBRA_FRR_IMAGE=${GOBGP_ZEBRA_FRR_IMAGE:-quay.io/frrouting/frr:8.2.2}
BIRD_IMAGE=${BIRD_IMAGE:-pierky/bird:2.17.1}
# quay.io, not docker.io: FRR's Docker Hub mirror stopped at v8.4.1 in 2022.
FRR_IMAGE=${FRR_IMAGE:-quay.io/frrouting/frr:10.7.1}
# 5.0.13, not 5.0.0: the published 5.0.0 image is broken (its own
# `exabgp.version` module fails to import), and `latest` is 6.x/unpinned.
EXABGP_IMAGE=${EXABGP_IMAGE:-ghcr.io/exa-networks/exabgp:5.0.13}

NET=nos-bench-net
SUBNET=10.60.0.0/24
DUT=bench-dut
MON=bench-mon
INJ=bench-inj
DUT_IP=10.60.0.2
MON_IP=10.60.0.3
INJ_IP=10.60.0.10
DUT_AS=65001
MON_AS=65200

# Injector peers. Each announces the SAME N prefixes -- one "full view" per
# transit provider -- so the DUT holds PEERS paths per prefix and has to run
# best-path selection on every one of them, rather than just inserting a
# table nobody competes for. Peer k is AS 65100+k at 10.60.0.(10+k), and wins
# every PEERS-th prefix on AS_PATH length (see gen_exabgp_config) -- an even
# share each, with the other PEERS-1 paths kept as backups.
PEERS=${PEERS:-4}
INJ_AS_BASE=65100
# Private ASN used purely to pad AS_PATH; never originates anything.
PAD_AS=64600

# Import policy applied by every daemon to every injector session when
# POLICY=1 (the default): drop anything tagged with $DROP_COMMUNITY -- every
# DROP_EVERY-th prefix carries it -- and set local-pref on what survives.
# Community matching plus an attribute write is the most common shape of
# real transit policy, and it is expressible in all four daemons without
# favouring any one of them.
POLICY=${POLICY:-1}
DROP_COMMUNITY=65000:666
DROP_EVERY=4
SET_LOCAL_PREF=150

inj_name() { echo "$INJ-$1"; }
inj_ip()   { echo "10.60.0.$(( 10 + $1 ))"; }
inj_as()   { echo $(( INJ_AS_BASE + $1 )); }

# Prefixes only this peer announces, out of 101.<k>.0.0/16, sent after its
# share of the common view. Without them, convergence could not be told apart
# from "whichever peer finished first": the monitor only ever sees one best
# path per prefix, so a common view announced by everyone is fully counted as
# soon as any single peer's copy lands, no matter what the other peers are
# still sending. A block only peer k has forces the count to wait for peer k.
UNIQUE_TAIL=${UNIQUE_TAIL:-1000}

# How many of `n` prefixes survive the import policy (it rejects every
# DROP_EVERY-th one).
kept_prefixes() {
  if [[ "$POLICY" == 1 ]]; then
    echo $(( $1 - ($1 + DROP_EVERY - 1) / DROP_EVERY ))
  else
    echo "$1"
  fi
}

# What the monitor should end up holding: one best path per common prefix,
# plus every peer's own tail block, minus everything the policy rejected.
expected_prefixes() {
  echo $(( $(kept_prefixes "$1") + PEERS * $(kept_prefixes "$UNIQUE_TAIL") ))
}

# Default prefix count. 10k is too small to tell these daemons apart -- every
# one of them absorbs it inside a couple of poll intervals -- so the default
# is 100k, about a quarter of a real IPv4 DFZ table. Pass a smaller N when
# smoke-testing a change to this script itself.
DEFAULT_PREFIXES=100000
# How long to wait for all N prefixes to reach the monitor before calling the
# run a timeout. Scales with N so a bigger run does not need a new constant.
# 200 prefixes/s is a floor none of these daemons should ever approach, so a
# run that hits this really is stuck rather than merely slow.
converge_timeout() { echo $(( 60 + $1 / 200 )); }
# Independent cap on every dut's kernel-deployment wait (see cmd_run's "2b"
# step) -- deliberately not scaled with N like converge_timeout above,
# since nos's un-batched netlink adds are measured far slower than BGP
# convergence at this table size (the other three have not been measured
# as thoroughly, but there is no reason to assume they are immune); a
# partial kernel_routes count after this many seconds is still a useful
# rate, so there is no reason to let one slow phase stretch the whole
# comparison run.
KERNEL_DEPLOY_TIMEOUT=${KERNEL_DEPLOY_TIMEOUT:-180}

log() { echo "[bench-bgp] $*" >&2; }

now_ms() { date +%s%3N; }

# Elapsed seconds, 2dp, from a now_ms() baseline.
since() { awk -v a="$1" -v b="$(now_ms)" 'BEGIN { printf "%.2f", (b - a) / 1000 }'; }

# --- Images and network -----------------------------------------------------

build_provision_tool() {
  log "building nos-provision (trixie-glibc-compatible, matching the runtime image)"
  docker run --rm \
    -v "$REPO:$REPO:z" \
    -w "$REPO" \
    rust:1-slim-trixie \
    cargo build --release -p nos-provision --target-dir target/docker-verify
}

build_nos_image() {
  log "building $NOS_IMAGE"
  (cd "$REPO" && make docker-build)
}

# GoBGP publishes release tarballs but no maintained container image, so
# build a two-line one from the official release rather than trusting a
# random community tag.
build_gobgp_image() {
  if docker image inspect "$GOBGP_IMAGE" >/dev/null 2>&1; then
    return 0
  fi
  log "building $GOBGP_IMAGE from the gobgp $GOBGP_VERSION release tarball"
  docker build -t "$GOBGP_IMAGE" - <<EOF
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \\
    && curl -fsSL https://github.com/osrg/gobgp/releases/download/v$GOBGP_VERSION/gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz \\
       | tar -xz -C /usr/local/bin gobgp gobgpd \\
    && apt-get purge -y --auto-remove curl && rm -rf /var/lib/apt/lists/*
EOF
}

# See $GOBGP_ZEBRA_IMAGE/$GOBGP_ZEBRA_FRR_IMAGE above for why this exists
# and why it is pinned to a specific old FRR release rather than reusing
# $FRR_IMAGE. Built the same way build_gobgp_image is (curl -> tar into
# /usr/local/bin), just FROM the FRR image instead of debian:bookworm-slim
# -- that gets zebra, watchfrr and /proc/net/route-readable capability
# plumbing for free, and keeps gobgpd a plain static-linked drop-in
# regardless of base distro (musl here, glibc in $GOBGP_IMAGE).
build_gobgp_zebra_image() {
  if docker image inspect "$GOBGP_ZEBRA_IMAGE" >/dev/null 2>&1; then
    return 0
  fi
  log "building $GOBGP_ZEBRA_IMAGE ($GOBGP_ZEBRA_FRR_IMAGE + gobgp $GOBGP_VERSION)"
  docker build -t "$GOBGP_ZEBRA_IMAGE" - <<EOF
FROM $GOBGP_ZEBRA_FRR_IMAGE
RUN wget -q -O /tmp/gobgp.tar.gz \\
      https://github.com/osrg/gobgp/releases/download/v$GOBGP_VERSION/gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz \\
    && tar -xz -C /usr/local/bin gobgp gobgpd -f /tmp/gobgp.tar.gz \\
    && rm -f /tmp/gobgp.tar.gz
EOF
}

pull_images() {
  for image in "$BIRD_IMAGE" "$FRR_IMAGE" "$GOBGP_ZEBRA_FRR_IMAGE" "$EXABGP_IMAGE"; do
    log "pulling $image"
    docker pull -q "$image" >/dev/null
  done
}

ensure_network() {
  if ! docker network inspect "$NET" >/dev/null 2>&1; then
    log "creating network $NET ($SUBNET)"
    docker network create --subnet "$SUBNET" "$NET" >/dev/null
  fi
}

# --- Config generation ------------------------------------------------------
#
# Every config is generated into $WORKDIR and bind-mounted in, so nothing
# daemon-specific is checked into the repo and the peer addresses above stay
# the single source of truth.

# One config per injector. All of them announce the same N host routes out of
# 100.0.0.0/8 (nowhere near the 10.60.0.0/24 the containers themselves use),
# and every DROP_EVERY-th route carries $DROP_COMMUNITY for the import policy
# to reject.
#
# AS_PATH padding is what decides which peer wins each prefix: injector k
# announces prefix i unpadded when i % PEERS == k-1 and padded otherwise, so
# the best paths are spread evenly across all PEERS peers. That matters for
# more than realism (a multi-homed router does not take everything from one
# transit): if one peer won every prefix, the monitor would reach the
# expected count as soon as that peer's view was processed, while the other
# peers' updates were still in flight -- and converge_s would be timing one
# full view while claiming to time PEERS of them.
gen_exabgp_config() {
  local count=$1 k=$2
  local pad=""
  local i
  for (( i = 0; i < k; i++ )); do
    pad="$pad $PAD_AS"
  done
  {
    cat <<EOF
neighbor $DUT_IP {
    router-id $(inj_ip "$k");
    local-address $(inj_ip "$k");
    local-as $(inj_as "$k");
    peer-as $DUT_AS;
    family {
        ipv4 unicast;
    }
    static {
EOF
    awk -v n="$count" -v nh="$(inj_ip "$k")" -v pad="$pad" -v drop="$DROP_COMMUNITY" \
        -v every="$DROP_EVERY" -v peers="$PEERS" -v k="$k" 'BEGIN {
      for (i = 0; i < n; i++) {
        line = sprintf("        route 100.%d.%d.%d/32 next-hop %s",
                       int(i / 65536) % 256, int(i / 256) % 256, i % 256, nh)
        if (i % peers != k - 1)
          line = line " as-path [" pad " ]"
        if (i % every == 0)
          line = line " community [" drop "]"
        print line ";"
      }
    }'
    awk -v n="$UNIQUE_TAIL" -v nh="$(inj_ip "$k")" -v drop="$DROP_COMMUNITY" \
        -v every="$DROP_EVERY" -v k="$k" 'BEGIN {
      for (i = 0; i < n; i++) {
        line = sprintf("        route 101.%d.%d.%d/32 next-hop %s",
                       k, int(i / 256) % 256, i % 256, nh)
        if (i % every == 0)
          line = line " community [" drop "]"
        print line ";"
      }
    }'
    printf '    }\n}\n'
  } >"$WORKDIR/exabgp-$k.conf"
}

gen_dut_configs() {
  local k

  # --- BIRD ---------------------------------------------------------------
  {
    cat <<EOF
router id $DUT_IP;
log stderr all;
protocol device {
}
# Installs every accepted route into the container's real (main) kernel
# routing table -- BIRD's kernel-sync runs in this same process, unlike
# nos-ribd/zebra for the other DUTs, so (unlike them) its cost is NOT a
# separate, unsampled process here; see this script's "Fairness notes".
protocol kernel {
    ipv4 { export all; };
}
EOF
    if [[ "$POLICY" == 1 ]]; then
      cat <<EOF
filter bench_in {
    if ($(echo "$DROP_COMMUNITY" | tr ':' ',')) ~ bgp_community then reject;
    bgp_local_pref = $SET_LOCAL_PREF;
    accept;
}
EOF
    fi
    for (( k = 1; k <= PEERS; k++ )); do
      cat <<EOF
protocol bgp inj$k {
    local $DUT_IP as $DUT_AS;
    neighbor $(inj_ip "$k") as $(inj_as "$k");
    ipv4 { import $([[ "$POLICY" == 1 ]] && echo "filter bench_in" || echo all); export all; };
}
EOF
    done
    cat <<EOF
protocol bgp mon {
    local $DUT_IP as $DUT_AS;
    neighbor $MON_IP as $MON_AS;
    ipv4 { import all; export all; };
}
EOF
  } >"$WORKDIR/bird.conf"

  # --- FRR ----------------------------------------------------------------
  {
    echo "log stdout"
    if [[ "$POLICY" == 1 ]]; then
      cat <<EOF
bgp community-list standard BENCH-DROP permit $DROP_COMMUNITY
route-map BENCH-IN deny 10
 match community BENCH-DROP
route-map BENCH-IN permit 20
 set local-preference $SET_LOCAL_PREF
EOF
    fi
    cat <<EOF
router bgp $DUT_AS
 bgp router-id $DUT_IP
 no bgp ebgp-requires-policy
EOF
    for (( k = 1; k <= PEERS; k++ )); do
      echo " neighbor $(inj_ip "$k") remote-as $(inj_as "$k")"
    done
    echo " neighbor $MON_IP remote-as $MON_AS"
    echo " address-family ipv4 unicast"
    for (( k = 1; k <= PEERS; k++ )); do
      echo "  neighbor $(inj_ip "$k") activate"
      [[ "$POLICY" == 1 ]] && echo "  neighbor $(inj_ip "$k") route-map BENCH-IN in"
    done
    echo "  neighbor $MON_IP activate"
    echo " exit-address-family"
  } >"$WORKDIR/bgpd.conf"
  chmod 644 "$WORKDIR/bgpd.conf"

  # The image's own default /etc/frr/daemons ships bgpd=no -- flip it on.
  # zebra/staticd/mgmtd are forced on by frrcommon.sh's daemon_list()
  # regardless of what is written here (they are always started), so this
  # only needs to actually toggle bgpd; started via the image's normal
  # tini/docker-start/watchfrr entrypoint (see start_dut) rather than
  # invoking bgpd directly, since bgpd on its own has no path to zebra and
  # a hand-rolled `zebra & bgpd` pairing (tried while developing this)
  # breaks mgmtd's northbound plumbing that modern FRR expects present.
  cat >"$WORKDIR/frr-daemons" <<'EOF'
bgpd=yes
zebra=yes
staticd=yes
mgmtd=yes
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
mgmtd_options="  -A 127.0.0.1"
bgpd_options="   -A 127.0.0.1"
staticd_options="-A 127.0.0.1"
EOF
  chmod 644 "$WORKDIR/frr-daemons"

  # --- GoBGP --------------------------------------------------------------
  {
    cat <<EOF
[global.config]
  as = $DUT_AS
  router-id = "$DUT_IP"

[zebra.config]
  enabled = true
  url = "unix:/var/run/frr/zserv.api"
  version = 6
  redistribute-route-type-list = []
EOF
    # GoBGP attaches import policy *globally* for ordinary peers -- a
    # per-neighbour `apply-policy` is only honoured for route-server clients
    # ("non-rs-client peer X doesn't have per peer policy"), which is how
    # this silently accepted everything the first time round. Global is
    # equivalent here: the monitor is the only other session and it never
    # announces anything for the policy to act on.
    if [[ "$POLICY" == 1 ]]; then
      cat <<EOF
  [global.apply-policy.config]
    import-policy-list = ["bench-in"]
    default-import-policy = "accept-route"
EOF
    fi
    for (( k = 1; k <= PEERS; k++ )); do
      cat <<EOF

[[neighbors]]
  [neighbors.config]
    neighbor-address = "$(inj_ip "$k")"
    peer-as = $(inj_as "$k")
EOF
    done
    cat <<EOF

[[neighbors]]
  [neighbors.config]
    neighbor-address = "$MON_IP"
    peer-as = $MON_AS
EOF
    if [[ "$POLICY" == 1 ]]; then
      cat <<EOF

[[defined-sets.bgp-defined-sets.community-sets]]
  community-set-name = "bench-drop"
  community-list = ["$DROP_COMMUNITY"]

[[policy-definitions]]
  name = "bench-in"
  [[policy-definitions.statements]]
    name = "drop-tagged"
    [policy-definitions.statements.conditions.bgp-conditions.match-community-set]
      community-set = "bench-drop"
      match-set-options = "any"
    [policy-definitions.statements.actions]
      route-disposition = "reject-route"
  [[policy-definitions.statements]]
    name = "prefer-rest"
    [policy-definitions.statements.actions]
      route-disposition = "accept-route"
      [policy-definitions.statements.actions.bgp-actions]
        set-local-pref = $SET_LOCAL_PREF
EOF
    fi
  } >"$WORKDIR/gobgpd.conf"

  # --- GoBGP monitor (never filters: it is the measuring instrument) ------
  cat >"$WORKDIR/gobgpd-mon.conf" <<EOF
[global.config]
  as = $MON_AS
  router-id = "$MON_IP"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "$DUT_IP"
    peer-as = $DUT_AS
EOF

  # --- nos (RPL) ----------------------------------------------------------
  # Written even when POLICY=0 so the path is always there to mount; it is
  # only referenced as an import policy when POLICY=1.
  cat >"$WORKDIR/bench-in.rpl" <<EOF
if this.bgp.communities.contains($DROP_COMMUNITY):
    reject
else:
    set this.bgp.local_pref = $SET_LOCAL_PREF
    accept
EOF
  # nos-provision runs as the container's unprivileged `nos` user, a
  # different uid than this shell (same reason verify-e2e.sh chmods its own
  # policy file).
  chmod 644 "$WORKDIR/bench-in.rpl"
}

# --- Containers -------------------------------------------------------------

start_monitor() {
  docker rm -f "$MON" >/dev/null 2>&1 || true
  log "starting monitor (gobgp, AS $MON_AS) at $MON_IP"
  docker run -d --name "$MON" --network "$NET" --ip "$MON_IP" \
    -v "$WORKDIR/gobgpd-mon.conf:/etc/gobgpd.conf:ro,z" \
    "$GOBGP_IMAGE" gobgpd -f /etc/gobgpd.conf -t toml >/dev/null
}

start_injector() {
  local k=$1
  local name
  name=$(inj_name "$k")
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --network "$NET" --ip "$(inj_ip "$k")" \
    -e exabgp_daemon_daemonize=false \
    -e exabgp_log_destination=stdout \
    -v "$WORKDIR/exabgp-$k.conf:/etc/exabgp/exabgp.conf:ro,z" \
    "$EXABGP_IMAGE" /etc/exabgp/exabgp.conf >/dev/null
}

start_injectors() {
  log "starting $PEERS injector(s) (exabgp, AS $(inj_as 1)..$(inj_as "$PEERS"))"
  local k
  for (( k = 1; k <= PEERS; k++ )); do
    start_injector "$k"
  done
}

stop_injectors() {
  local k
  for (( k = 1; k <= PEERS; k++ )); do
    docker rm -f "$(inj_name "$k")" >/dev/null 2>&1 || true
  done
}

# nos's DUT container is the whole watchdog-supervised stack, exactly as
# verify-e2e.sh starts it -- plus an optional RUST_LOG, which reaches
# nos-bgpd because watchdog/src/supervisor.rs spawns children with a plain
# Command that inherits the environment.
start_nos_dut() {
  local rust_log=${1:-}
  docker volume create "${DUT}-run" >/dev/null
  docker volume create "${DUT}-data" >/dev/null
  docker rm -f "$DUT" >/dev/null 2>&1 || true
  log "starting nos DUT at $DUT_IP${rust_log:+ (RUST_LOG=$rust_log)}"
  docker run -d --name "$DUT" \
    --network "$NET" --ip "$DUT_IP" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
    ${rust_log:+-e "RUST_LOG=$rust_log"} \
    -v "${DUT}-run:/run/nos" \
    -v "${DUT}-data:/var/lib/nos" \
    "$NOS_IMAGE" ${PROFILE_MEMORY:+--bgpd-arg --profile-memory-out=/var/lib/nos/bgpd/dhat-heap.json} >/dev/null

  log "waiting for the nos DUT's nos-configd socket"
  local ready=1
  for _ in $(seq 1 60); do
    if docker run --rm --entrypoint /bin/sh -v "${DUT}-run:/run/nos" "$NOS_IMAGE" \
        -c 'test -S /run/nos/config.sock'; then
      ready=0
      break
    fi
    sleep 1
  done
  if [[ $ready -ne 0 ]]; then
    log "timed out waiting for the nos DUT's config socket"
    return 1
  fi

  # One nos-provision call per neighbour: BgpPeerOp::Set upserts, so each
  # call adds a peer rather than replacing the previous one (the same way
  # verify-e2e.sh's reflector scenario adds a second client). The injector
  # peer-groups get the RPL import policy; the monitor's never does -- it is
  # the measuring instrument, not part of the test.
  local k
  for (( k = 1; k <= PEERS; k++ )); do
    provision_nos_peer "inj$k" "$(inj_as "$k")" "$(inj_ip "$k")" policy
  done
  provision_nos_peer mon "$MON_AS" "$MON_IP"

  # nos-interfaced enslaves eth0 into the routing table's VRF a few seconds
  # after the commit, which kills any TCP session opened before it. Waiting
  # for both the enslavement and nos-bgpd's listener keeps that churn out of
  # the establishment measurement -- without it, the monitor's first connect
  # attempt is torn down and its retry backoff (which doubles) shows up as a
  # ~100s "establishment time" that is really gobgp's idle-hold timer.
  wait_for_dut_log "enslaved interface to vrf" 60 || return 1
  wait_for_dut_log "bgp listener bound" 60 || return 1
}

wait_for_dut_log() {
  local pattern=$1 timeout=${2:-60} logs
  for _ in $(seq 1 "$timeout"); do
    # Captured into a variable rather than piped into `grep -q`: under
    # pipefail, grep's early exit SIGPIPEs `docker logs` and the pipeline
    # reports failure even on a match (see verify-e2e.sh's wait_for_log).
    logs=$(docker logs "$DUT" 2>&1) || true
    if grep -q "$pattern" <<<"$logs"; then
      return 0
    fi
    sleep 1
  done
  log "timed out waiting for '$pattern' in the DUT's logs"
  return 1
}

provision_nos_peer() {
  local group=$1 remote_as=$2 peer=$3 with_policy=${4:-}
  local policy_args=()
  if [[ -n "$with_policy" && "$POLICY" == 1 ]]; then
    policy_args=(
      --policy-name bench-in
      --policy-source-file /tmp/bench-in.rpl
      --import-policy bench-in
    )
  fi
  log "provisioning nos peer-group $group (remote-as $remote_as, peer $peer${policy_args:+, import policy bench-in})"
  docker run --rm --entrypoint /usr/local/bin/nos-provision \
    -v "$PROVISION_BIN:/usr/local/bin/nos-provision:ro,z" \
    -v "$WORKDIR/bench-in.rpl:/tmp/bench-in.rpl:ro,z" \
    -v "${DUT}-run:/run/nos" \
    "$NOS_IMAGE" \
    --config-socket /run/nos/config.sock \
    --login-user admin --login-password admin \
    --address "$DUT_IP/24" \
    --asn "$DUT_AS" \
    --router-id "$DUT_IP" \
    --peer-group "$group" \
    --remote-as "$remote_as" \
    --peer "$peer" \
    "${policy_args[@]}" >>"$WORKDIR/provision.log" 2>&1
}

start_dut() {
  local kind=$1
  case "$kind" in
    nos) start_nos_dut ;;
    # Not a blanket `warn`: the harness itself waits on two `info!` lines
    # (VRF enslavement, listener bound) to know the stack has settled. This
    # silences the per-route firehose in nos_bgp::rib and the netlink TRACE
    # dumps from the other daemons, which is the whole point.
    nos-quiet) start_nos_dut "info,nos_bgp::rib=warn" ;;
    gobgp)
      docker rm -f "$DUT" >/dev/null 2>&1 || true
      # $GOBGP_ZEBRA_IMAGE (gobgpd + a compatible zebra, see that var's
      # comment) started by a small wrapper: the image's own tini/
      # docker-start/watchfrr entrypoint brings zebra (+staticd/mgmtd,
      # always forced on) up in the background, then gobgpd is exec'd once
      # its zapi socket exists -- gobgpd's own [zebra.config] (see
      # gen_dut_configs) is what actually pushes its routes into it.
      log "starting gobgp DUT (+ zebra for kernel install) at $DUT_IP"
      docker run -d --name "$DUT" --network "$NET" --ip "$DUT_IP" \
        --cap-add NET_ADMIN --cap-add SYS_ADMIN \
        -v "$WORKDIR/gobgpd.conf:/etc/gobgpd.conf:ro,z" \
        --entrypoint sh \
        "$GOBGP_ZEBRA_IMAGE" -c '
          /usr/lib/frr/docker-start &
          for _ in $(seq 1 30); do
            [ -S /var/run/frr/zserv.api ] && break
            sleep 1
          done
          exec /usr/local/bin/gobgpd -f /etc/gobgpd.conf -t toml
        ' >/dev/null
      ;;
    bird)
      docker rm -f "$DUT" >/dev/null 2>&1 || true
      log "starting bird DUT at $DUT_IP"
      docker run -d --name "$DUT" --network "$NET" --ip "$DUT_IP" \
        --cap-add NET_ADMIN \
        --entrypoint /usr/local/sbin/bird \
        -v "$WORKDIR/bird.conf:/etc/bird/bird.conf:ro,z" \
        "$BIRD_IMAGE" -f -c /etc/bird/bird.conf >/dev/null
      ;;
    frr)
      docker rm -f "$DUT" >/dev/null 2>&1 || true
      # Default tini/docker-start/watchfrr entrypoint (not a direct `bgpd`
      # invocation): zebra/staticd/mgmtd are always started regardless of
      # $WORKDIR/frr-daemons's content, this just flips bgpd=yes -- see
      # that file's own generation comment in gen_dut_configs for why a
      # hand-rolled `zebra & bgpd` pairing doesn't work on its own.
      log "starting frr DUT (+ zebra for kernel install) at $DUT_IP"
      docker run -d --name "$DUT" --network "$NET" --ip "$DUT_IP" \
        --user root \
        --cap-add NET_ADMIN --cap-add SYS_ADMIN \
        -v "$WORKDIR/frr-daemons:/etc/frr/daemons:ro,z" \
        -v "$WORKDIR/bgpd.conf:/etc/frr/bgpd.conf:ro,z" \
        "$FRR_IMAGE" >/dev/null
      ;;
    *) log "unknown dut '$kind'"; return 2 ;;
  esac
}

# The BGP process to sample inside the DUT container, per daemon.
dut_process() {
  case "$1" in
    nos|nos-quiet) echo nos-bgpd ;;
    gobgp) echo gobgpd ;;
    bird) echo bird ;;
    frr) echo bgpd ;;
  esac
}

# --- Measurement ------------------------------------------------------------

# Everything the monitor knows comes from one line of `gobgp neighbor`'s
# summary table, which carries both the session state and the received-prefix
# count -- one `docker exec` per poll rather than one per metric:
#
#   Peer         AS  Up/Down State       |#Received  Accepted
#   10.60.0.2 65001 00:00:07 Establ      |        0         0
#
# (The per-neighbour detail view has the same numbers, but spells the state
# `SESSION_STATE_ESTABLISHED` in gobgp 4.x and costs a second call.)
mon_line() {
  docker exec "$MON" gobgp neighbor 2>/dev/null \
    | awk -v peer="$DUT_IP" '$1 == peer { print; exit }'
}

mon_established() {
  [[ "$(mon_line)" == *Estab* ]]
}

mon_received() {
  mon_line | awk '{ print $(NF - 1) }'
}

# Polls are deadline-driven rather than iteration-counted, at 0.2s, because a
# fast daemon converges a small table inside a single 1s tick and would
# otherwise be reported as 0.00s. A `docker exec` round trip is ~50-100ms, so
# 0.2s is about as fine as this can usefully get.
POLL=0.2

# A daemon that swallows the whole table between two polls measures 0.00s,
# which reads as "0 prefixes/s". Flooring at the poll interval turns that into
# a lower bound instead ("at least this fast"), and is why small-N runs are
# not worth reading -- use N >= 10000.
floor_poll() {
  awk -v s="$1" -v p="$POLL" 'BEGIN { printf("%.2f", s > p ? s : p) }'
}

wait_for_established() {
  local timeout=${1:-120} start=$2
  local deadline=$(( $(now_ms) + timeout * 1000 ))
  while [[ "$(now_ms)" -lt "$deadline" ]]; do
    if mon_established; then
      since "$start"
      return 0
    fi
    sleep "$POLL"
  done
  echo "timeout"
  return 1
}

# Polls the monitor until it holds `count` prefixes, and prints the elapsed
# seconds *since the first prefix arrived* rather than since the injector
# container was started -- roughly 1.5s of that is exabgp's own startup, which
# would otherwise be charged to whichever daemon is under test. `start` is
# only the fallback for a run that finishes inside a single poll.
wait_for_prefixes() {
  local count=$1 timeout=$2 start=$3
  local got=0 first=
  local deadline=$(( $(now_ms) + timeout * 1000 ))
  while [[ "$(now_ms)" -lt "$deadline" ]]; do
    got=$(mon_received || echo 0)
    [[ -z "$first" && "${got:-0}" -gt 0 ]] && first=$(now_ms)
    if [[ "${got:-0}" -ge "$count" ]]; then
      since "${first:-$start}"
      return 0
    fi
    sleep "$POLL"
  done
  log "timed out at ${got:-0}/$count prefixes"
  echo "timeout"
  return 1
}

# Tails the DUT's combined log to a local file for the run's duration, so
# `wait_for_kernel_routes` below can grep a local, already-fetched file
# every poll instead of re-running `docker logs $DUT` (which re-reads the
# *entire* log history from the container's logging driver on every call --
# fine for the other waiters here, which only ever call it once, but with
# `nos` (unfiltered RUST_LOG=trace, including rtnetlink's own TRACE dumps
# from nos-ribd's real netlink work) the log grows fast enough that
# re-fetching it every second turned an O(n) poll into an O(n^2) one and the
# wait blew through its own timeout). Same start/stop shape as `sampler_*`.
dut_log_pid=
dut_log_start() {
  : >"$WORKDIR/dut-tail.log"
  docker logs -f "$DUT" >"$WORKDIR/dut-tail.log" 2>&1 &
  dut_log_pid=$!
}

dut_log_stop() {
  [[ -n "$dut_log_pid" ]] || return 0
  kill "$dut_log_pid" >/dev/null 2>&1 || true
  wait "$dut_log_pid" 2>/dev/null || true
  dut_log_pid=
}

# Polls the local tail of the DUT's log (see `dut_log_start`) until
# nos-ribd has logged `count` real "added route" lines (one per prefix
# actually installed into the kernel routing table via the BGP->RIB push,
# see bgp/src/rib_push_client.rs) or `timeout` elapses. There is no
# equivalent one-line counter to ask nos-ribd for instead (see this
# script's header).
wait_for_kernel_routes() {
  local count=$1 timeout=$2
  local got=0
  local deadline=$(( $(now_ms) + timeout * 1000 ))
  while [[ "$(now_ms)" -lt "$deadline" ]]; do
    got=$(grep -c "added route" "$WORKDIR/dut-tail.log") || true
    if [[ "${got:-0}" -ge "$count" ]]; then
      echo "$got"
      return 0
    fi
    sleep 1
  done
  log "timed out at ${got:-0}/$count kernel routes installed"
  echo "${got:-0}"
  return 1
}

# gobgp/bird/frr all install straight into their container's real *main*
# kernel table (table 254) rather than a VRF-scoped one like nos -- so
# unlike nos (see wait_for_kernel_routes above), their install can be read
# directly with no daemon-specific log parsing at all: /proc/net/route is a
# kernel-provided pseudo-file, one line per route plus a header, readable
# in any Linux container with a plain `cat`/`wc`, no `ip`/iproute2 needed.
main_table_route_count() {
  docker exec "$DUT" sh -c 'wc -l < /proc/net/route' 2>/dev/null | tr -d '[:space:]'
}

# Same shape as wait_for_kernel_routes, but counting real kernel-table
# lines above `baseline` (the container's own default+connected routes,
# captured right after start_dut, before any injector has announced
# anything) instead of grepping a log for a fixed string.
wait_for_main_table_routes() {
  local baseline=$1 count=$2 timeout=$3
  local got=0 raw
  local deadline=$(( $(now_ms) + timeout * 1000 ))
  while [[ "$(now_ms)" -lt "$deadline" ]]; do
    raw=$(main_table_route_count) || raw=0
    got=$(( ${raw:-0} - baseline ))
    [[ "$got" -lt 0 ]] && got=0
    if [[ "$got" -ge "$count" ]]; then
      echo "$got"
      return 0
    fi
    sleep 1
  done
  log "timed out at ${got:-0}/$count kernel routes installed"
  echo "${got:-0}"
  return 1
}

# One long-lived `docker exec` sampling loop, not one exec per sample. Emits
# "peak_rss_kb cpu_ticks" per second for the DUT's BGP process; the pid is
# re-resolved every tick because nos-bgpd is spawned (and respawned) by the
# watchdog rather than being the container's own pid 1. The runtime images
# have no ps/pgrep, hence the /proc/*/comm scan (same trick as
# verify-e2e.sh's kill_process_by_name).
sampler_pid=
sampler_start() {
  local proc=$1
  : >"$WORKDIR/samples.txt"
  docker exec "$DUT" sh -c "
    while :; do
      for p in /proc/[0-9]*; do
        [ -r \"\$p/comm\" ] || continue
        [ \"\$(cat \"\$p/comm\" 2>/dev/null)\" = '$proc' ] || continue
        rss=\$(awk '/VmHWM/ { print \$2 }' \"\$p/status\" 2>/dev/null)
        cpu=\$(awk '{ print \$14 + \$15 }' \"\$p/stat\" 2>/dev/null)
        [ -n \"\$rss\" ] && [ -n \"\$cpu\" ] && echo \"\$rss \$cpu\"
      done
      sleep 1
    done
  " >"$WORKDIR/samples.txt" 2>/dev/null &
  sampler_pid=$!
}

sampler_stop() {
  [[ -n "$sampler_pid" ]] || return 0
  kill "$sampler_pid" >/dev/null 2>&1 || true
  wait "$sampler_pid" 2>/dev/null || true
  sampler_pid=
}

# Peak RSS in MB and total CPU seconds (USER_HZ is 100 on Linux/x86_64).
sampler_peak_rss_mb() {
  awk 'BEGIN { m = 0 } { if ($1 > m) m = $1 } END { printf "%.1f", m / 1024 }' \
    "$WORKDIR/samples.txt"
}

sampler_cpu_secs() {
  awk 'NR == 1 { lo = $2 } { if ($2 > hi) hi = $2 } END { printf "%.2f", (hi - lo) / 100 }' \
    "$WORKDIR/samples.txt"
}

# --- Phases -----------------------------------------------------------------

cmd_up() {
  mkdir -p "$WORKDIR"
  build_nos_image
  build_provision_tool
  build_gobgp_image
  pull_images
  build_gobgp_zebra_image
  ensure_network
  gen_dut_configs
  log "ready -- run 'tools/bench-bgp.sh all' or 'run <dut>'"
}

cmd_run() {
  local kind=$1 count=${2:-$DEFAULT_PREFIXES}
  local timeout expected
  timeout=$(converge_timeout "$count")
  expected=$(expected_prefixes "$count")
  mkdir -p "$WORKDIR"
  gen_dut_configs
  local k
  for (( k = 1; k <= PEERS; k++ )); do
    gen_exabgp_config "$count" "$k"
  done

  log "=== $kind, ($count common + $UNIQUE_TAIL unique) prefixes x $PEERS peer(s), policy=$POLICY, expecting $expected in the monitor ==="
  docker rm -f "$DUT" "$MON" >/dev/null 2>&1 || true
  stop_injectors
  docker volume rm "${DUT}-run" "${DUT}-data" >/dev/null 2>&1 || true

  start_dut "$kind"
  sampler_start "$(dut_process "$kind")"
  [[ "$kind" == nos* ]] && dut_log_start
  # Baseline main-table route count (default + connected routes already
  # present before any injector announces anything) for gobgp/bird/frr's
  # kernel_routes measurement below -- see main_table_route_count.
  local main_table_baseline=0
  [[ "$kind" == gobgp || "$kind" == bird || "$kind" == frr ]] && main_table_baseline=$(main_table_route_count)

  # 1. Session establishment, timed from the monitor's start: the DUT is
  #    already up and configured, so this is how fast the pair gets to
  #    Established (dominated by whichever side's connect-retry timer fires
  #    first -- for nos that is usually the monitor's, since nos's own
  #    CONNECT_RETRY_TIME default is 120s).
  local t0 establish
  t0=$(now_ms)
  start_monitor
  establish=$(wait_for_established 120 "$t0") || true
  log "$kind: established in ${establish}s"

  # 2. Convergence: every injector announces the same N prefixes at once,
  #    measured until the surviving best paths have all been re-advertised
  #    into the monitor. The DUT does PEERS x N updates of work to get there.
  local converge pps
  t0=$(now_ms)
  start_injectors
  converge=$(wait_for_prefixes "$expected" "$timeout" "$t0") || true
  if [[ "$converge" == "timeout" ]]; then
    pps=0
  else
    converge=$(floor_poll "$converge")
    # Parenthesised on purpose: bare `printf "...", s > 0 ? ...` parses the
    # `>` as output redirection in awk.
    pps=$(awk -v n="$(( (count + UNIQUE_TAIL) * PEERS ))" -v s="$converge" \
      'BEGIN { printf("%.0f", s > 0 ? n / s : 0) }')
  fi
  log "$kind: converged to $expected prefixes in ${converge}s ($pps updates/s)"

  # 2b. Kernel deployment: every daemon now installs its received best
  #     paths into a real kernel routing table --
  #       nos/nos-quiet: nos-bgpd pushes its loc-rib to the owning
  #         nos-ribd instance (poll interval 1s, see
  #         bgp/src/rib_push_client.rs), which installs it via
  #         LinuxRibDriver into a VRF-scoped table (root CLAUDE.md's
  #         "Config plane vs data plane") -- counted via a log line (see
  #         wait_for_kernel_routes), since that table isn't the container's
  #         main one.
  #       gobgp/frr: a real zebra (bundled alongside gobgpd for gobgp, see
  #         $GOBGP_ZEBRA_IMAGE; always-on alongside bgpd for frr, see
  #         $WORKDIR/frr-daemons) installs into the container's main table.
  #       bird: its own in-process `protocol kernel` (see gen_dut_configs)
  #         installs into the container's main table directly.
  #     gobgp/frr/bird are counted via /proc/net/route (see
  #     wait_for_main_table_routes) -- no daemon-specific log parsing
  #     needed, since they all use the same real (main) kernel table.
  #
  #     Timed from the same `t0` as convergence above, so kernel_deploy_s
  #     is directly comparable to converge_s -- the gap between them is
  #     the extra latency each daemon's kernel install adds on top of
  #     ordinary BGP convergence. For nos/gobgp/frr this is NOT a
  #     performance number for the process actually doing the kernel work
  #     (nos-ribd/zebra are second, unsampled processes, see this script's
  #     "Fairness notes") -- only for bird, whose kernel sync runs
  #     in-process, does peak_rss_mb/cpu_s above already include it.
  #
  #     Capped independently of `timeout` (which scales with N for BGP
  #     convergence) at $KERNEL_DEPLOY_TIMEOUT: nos's `LinuxRibDriver::add_route`
  #     issues one un-batched, awaited netlink call per route, measured at
  #     roughly 25-450 routes/s depending on RUST_LOG volume -- installing
  #     a full run's ~kept_prefixes routes this way can take far longer
  #     than BGP convergence ever does, so above a few hundred routes this
  #     can legitimately time out with a partial count rather than
  #     stalling the whole comparison. A partial count is still a valid
  #     rate (kernel_routes / kernel_deploy_s), just not a completion time.
  local kernel_routes=n/a kernel_deploy_s=n/a
  local kernel_timeout=$(( timeout < KERNEL_DEPLOY_TIMEOUT ? timeout : KERNEL_DEPLOY_TIMEOUT ))
  if [[ "$kind" == nos* ]]; then
    kernel_routes=$(wait_for_kernel_routes "$expected" "$kernel_timeout") || true
    kernel_deploy_s=$(floor_poll "$(since "$t0")")
    log "$kind: installed $kernel_routes/$expected route(s) into the kernel routing table (rt1) in ${kernel_deploy_s}s"
  elif [[ "$kind" == gobgp || "$kind" == bird || "$kind" == frr ]]; then
    kernel_routes=$(wait_for_main_table_routes "$main_table_baseline" "$expected" "$kernel_timeout") || true
    kernel_deploy_s=$(floor_poll "$(since "$t0")")
    log "$kind: installed $kernel_routes/$expected route(s) into the kernel routing table in ${kernel_deploy_s}s"
  fi

  # 3. Churn: drop every injector (closing TCP, so the DUT withdraws
  #    everything) and bring them all back, then re-measure. Dropping a
  #    single peer would be the more operational test, but only part of it
  #    is timeable from here: its unique block's withdrawal shows up in the
  #    monitor's count, while the far larger job -- repathing the prefixes
  #    it was winning onto another peer's backup path -- does not move the
  #    count at all. Not worth a phase that measures the small half.
  local churn
  log "$kind: restarting the injectors to measure reconvergence"
  stop_injectors
  for _ in $(seq 1 60); do
    [[ "$(mon_received || echo 0)" -lt "$expected" ]] && break
    sleep 1
  done
  t0=$(now_ms)
  start_injectors
  churn=$(wait_for_prefixes "$expected" "$timeout" "$t0") || true
  [[ "$churn" == "timeout" ]] || churn=$(floor_poll "$churn")
  log "$kind: reconverged in ${churn}s"

  # What the monitor actually ended up holding. The convergence waits above
  # stop at ">= expected", so without this a daemon whose filter silently did
  # nothing would converge to 1000 prefixes and still look like a pass --
  # this puts the real number in the table next to the expectation.
  sleep 2
  local final
  final=$(mon_received || echo 0)
  if [[ "${final:-0}" != "$expected" ]]; then
    log "$kind: WARNING: monitor holds ${final:-0} prefixes, expected $expected -- check this daemon's import policy"
  fi

  sampler_stop
  dut_log_stop
  local rss cpu
  rss=$(sampler_peak_rss_mb)
  cpu=$(sampler_cpu_secs)
  log "$kind: peak rss ${rss}MB, cpu ${cpu}s"

  [[ -s "$RESULTS" ]] || printf 'daemon\tprefixes\tpeers\tpolicy\tkept_pfx\testablish_s\tconverge_s\tupdates_per_s\tpeak_rss_mb\tcpu_s\treconverge_s\tkernel_routes\tkernel_deploy_s\n' >"$RESULTS"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$kind" "$count" "$PEERS" "$POLICY" "${final:-0}/$expected" "$establish" "$converge" "$pps" "$rss" "$cpu" "$churn" "$kernel_routes" "$kernel_deploy_s" >>"$RESULTS"

  # dhat only writes its report file when nos-bgpd exits -- SIGTERM (docker
  # stop's default) reaches it the same way SIGINT does (see root
  # `docs/architecture/supervision.md`), so this has to happen before the
  # unconditional `docker rm -f` below, not after.
  if [[ -n "${PROFILE_MEMORY:-}" && "$kind" == nos* ]]; then
    local profile_out="$WORKDIR/dhat-heap-$kind-$count.json"
    log "$kind: stopping DUT to flush the dhat heap-profile report"
    docker stop "$DUT" >/dev/null 2>&1 || true
    if docker cp "$DUT:/var/lib/nos/bgpd/dhat-heap.json" "$profile_out" >/dev/null 2>&1; then
      log "$kind: wrote heap-profile report to $profile_out"
    else
      log "$kind: WARNING: could not extract dhat-heap.json -- was \$NOS_IMAGE built with CARGO_FEATURES=nos-bgp/dhat-heap?"
    fi
  fi

  docker rm -f "$DUT" "$MON" >/dev/null 2>&1 || true
  stop_injectors
  docker volume rm "${DUT}-run" "${DUT}-data" >/dev/null 2>&1 || true
}

cmd_all() {
  local count=${1:-$DEFAULT_PREFIXES}
  : >"$RESULTS"
  for kind in nos nos-quiet gobgp bird frr; do
    cmd_run "$kind" "$count" || log "$kind: run failed, continuing"
  done
  cmd_report
}

cmd_report() {
  if [[ ! -s "$RESULTS" ]]; then
    log "no results yet -- run 'tools/bench-bgp.sh all' first"
    return 1
  fi
  echo
  column -t -s $'\t' "$RESULTS"
  cat <<'EOF'

Read these with the caveats in this script's header: all five rows now
install into a real kernel routing table, but memory/cpu is still the BGP
decision process alone (nos-bgpd/gobgpd/bgpd) -- for nos/gobgp/frr the
process actually doing the kernel work (nos-ribd/zebra) is a second,
unsampled process, so its cost is NOT in peak_rss_mb/cpu_s below; bird is
the one exception, since its kernel sync runs in-process (see the header's
"Fairness notes" for why that is a real asymmetry, not an oversight).
`nos` is the shipping default (an info! per learned route, plus rtnetlink
TRACE from the other daemons) and `nos-quiet` is the row comparable to the
other three. converge_s and reconverge_s measure receive -> best-path ->
re-advertise into the monitor, so they include nos-bgpd's
one-prefix-per-UPDATE outbound path.

kept_pfx is what the monitor actually held at the end over what the policy
should have let through -- anything other than n/n means that daemon's filter
did not do what the other three did, and its row is not comparable.

kernel_routes/kernel_deploy_s: how many real kernel routes each dut
installed, and how long that took measured from the same t0 as converge_s --
the gap between the two is the extra latency each daemon's kernel install
adds on top of ordinary BGP convergence. nos/nos-quiet are counted via a log
line (nos-ribd's own VRF-scoped table isn't visible from the container's
main routing table); gobgp/bird/frr are counted directly from
/proc/net/route, since they all install into their container's ordinary
main table. A partial count below the expected total means
KERNEL_DEPLOY_TIMEOUT was hit -- see this script's header for why that is
expected at full scale, not a failure.

updates_per_s counts (prefixes + tail) x peers (every path the DUT had to
consider),
not the prefixes that survived policy -- the rejected quarter still costs a
decode, a policy evaluation and a RIB lookup.

Two things the table still cannot show. Within one injector every prefix
carries the same attributes, which flatters an implementation that shares one
attribute set across routes (BIRD's rta hashing above all) over one that
stores a copy per route -- so peak_rss_mb is a best case, not a
table-of-the-internet figure. And the injectors are themselves a ceiling:
when two daemons report the same converge_s, the honest reading is "both kept
up with exabgp", not "both are equally fast".
EOF
}

cmd_logs() {
  local n=${1:-200} c k
  local containers=("$DUT" "$MON")
  for (( k = 1; k <= PEERS; k++ )); do
    containers+=("$(inj_name "$k")")
  done
  for c in "${containers[@]}"; do
    if docker inspect "$c" >/dev/null 2>&1; then
      echo "--- $c ---"
      docker logs --tail "$n" "$c" 2>&1 || true
    fi
  done
}

cmd_down() {
  sampler_stop
  docker rm -f "$DUT" "$MON" >/dev/null 2>&1 || true
  # Not just $PEERS: a previous run may have used a larger peer count.
  docker ps -aq --filter "name=^$INJ-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker volume rm "${DUT}-run" "${DUT}-data" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}

case "${1:-}" in
  up) cmd_up ;;
  run) shift; [[ $# -ge 1 ]] || { echo "usage: $0 run <nos|nos-quiet|gobgp|bird|frr> [N]" >&2; exit 2; }; cmd_run "$@" ;;
  all) shift; cmd_all "$@" ;;
  report) cmd_report ;;
  logs) shift; cmd_logs "$@" ;;
  down) cmd_down ;;
  *)
    echo "Usage: $0 {up|run <nos|nos-quiet|gobgp|bird|frr> [N]|all [N]|report|logs [n]|down}" >&2
    exit 2
    ;;
esac
