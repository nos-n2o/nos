# syntax=docker/dockerfile:1

# Base images are digest-pinned (manifest-list, multi-arch); Dependabot bumps
# the digests weekly. apt packages stay unpinned (DL3008 ignored): pinning
# versions in the slim images breaks on every security update.
FROM rust:1.100.0-slim-trixie@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe AS builder
WORKDIR /app

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpam0g-dev \
        make \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Empty by default (no new deps, no behavior change). Set to
# "nos-bgp/dhat-heap" to build nos-bgpd with dhat heap profiling — see
# docs/architecture/development.md's "Memory profiling" note.
ARG CARGO_FEATURES=
# Short git revision baked into `nos_proto::version::REVISION` (`make docker-build` sets it).
ARG NOS_BUILD_REV=unknown
ENV NOS_BUILD_REV=$NOS_BUILD_REV
RUN cargo build --release ${CARGO_FEATURES:+--features "$CARGO_FEATURES"} --bin nos-configd --bin nos-bgpd --bin nos-ribd --bin nos-interfaced --bin nos-logd --bin nos-ospfd --bin nos-ospfv3d --bin nos-lacpd --bin nos-lldpd --bin nos-stpd --bin nos-acld --bin nos-bfdd --bin nos-fdbd --bin nos-restd --bin nos-sshd --bin nos-watchdogd --bin nos-sandbox-exec --bin nos --bin nos-provision --bin nos-rtr-stub --bin nos-radius-stub --bin nos-tacacs-stub \
    && cargo build --release -p nos-pam -p nos-nss

# trixie, not bookworm: bookworm's OpenSSH 9.2 has no `PAMServiceName`; trixie ships 10.0p2,
# which `sshd -T` accepts it in (#994). The builder is trixie too, so build and runtime glibc match.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime

# Fixed numeric ids (the ENTRYPOINT's --child-gid names group `nos`):
# `nos-wd` runs the watchdog (both CAs in memory); each daemon role runs as its
# own `nos-<role>` (uids 10001+ in `Role` order, the table in
# watchdog/src/uids.rs - a unit test checks these lines against it); `nos` is
# the shared client user (CLI, nos-provision, nos-e2e execs). All share primary
# group `nos`, which owns the 0660 IPC sockets.
# /run/nos is 1770 `nos-wd:nos`: children create sockets there but cannot
# unlink each other's. /var/lib/nos is `nos-wd:nos` 0755 and the watchdog makes
# `/var/lib/nos/<role>` (0700, `nos-<role>`) at startup, also on a volume an
# older image left behind (needs cap_chown below).
RUN groupadd --system --gid 991 nos \
    && useradd --system --uid 991 --gid nos --no-create-home --home-dir /nonexistent nos \
    && useradd --system --uid 990 --gid nos --no-create-home --home-dir /nonexistent nos-wd \
    && useradd --system --uid 10001 --gid nos --no-create-home --home-dir /nonexistent nos-configd \
    && useradd --system --uid 10002 --gid nos --no-create-home --home-dir /nonexistent nos-logd \
    && useradd --system --uid 10003 --gid nos --no-create-home --home-dir /nonexistent nos-bgpd \
    && useradd --system --uid 10004 --gid nos --no-create-home --home-dir /nonexistent nos-ribd \
    && useradd --system --uid 10005 --gid nos --no-create-home --home-dir /nonexistent nos-ospfd \
    && useradd --system --uid 10006 --gid nos --no-create-home --home-dir /nonexistent nos-ospfv3d \
    && useradd --system --uid 10007 --gid nos --no-create-home --home-dir /nonexistent nos-interfaced \
    && useradd --system --uid 10008 --gid nos --no-create-home --home-dir /nonexistent nos-lacpd \
    && useradd --system --uid 10009 --gid nos --no-create-home --home-dir /nonexistent nos-lldpd \
    && useradd --system --uid 10010 --gid nos --no-create-home --home-dir /nonexistent nos-fdbd \
    && useradd --system --uid 10011 --gid nos --no-create-home --home-dir /nonexistent nos-restd \
    && useradd --system --uid 10012 --gid nos --no-create-home --home-dir /nonexistent nos-bfdd \
    && useradd --system --uid 10013 --gid nos --no-create-home --home-dir /nonexistent nos-stpd \
    && useradd --system --uid 10014 --gid nos --no-create-home --home-dir /nonexistent nos-acld \
    && mkdir -p /run/nos /var/lib/nos \
    && chown nos-wd:nos /run/nos && chmod 1770 /run/nos \
    && chown nos-wd:nos /var/lib/nos

COPY --from=builder /app/target/release/nos-configd    /usr/local/bin/nos-configd
COPY --from=builder /app/target/release/nos-bgpd       /usr/local/bin/nos-bgpd
COPY --from=builder /app/target/release/nos-ribd       /usr/local/bin/nos-ribd
COPY --from=builder /app/target/release/nos-interfaced /usr/local/bin/nos-interfaced
COPY --from=builder /app/target/release/nos-logd       /usr/local/bin/nos-logd
COPY --from=builder /app/target/release/nos-ospfd      /usr/local/bin/nos-ospfd
COPY --from=builder /app/target/release/nos-ospfv3d    /usr/local/bin/nos-ospfv3d
COPY --from=builder /app/target/release/nos-lacpd      /usr/local/bin/nos-lacpd
COPY --from=builder /app/target/release/nos-lldpd      /usr/local/bin/nos-lldpd
COPY --from=builder /app/target/release/nos-stpd       /usr/local/bin/nos-stpd
COPY --from=builder /app/target/release/nos-acld       /usr/local/bin/nos-acld
COPY --from=builder /app/target/release/nos-bfdd       /usr/local/bin/nos-bfdd
COPY --from=builder /app/target/release/nos-fdbd       /usr/local/bin/nos-fdbd
COPY --from=builder /app/target/release/nos-restd      /usr/local/bin/nos-restd
COPY --from=builder /app/target/release/nos-sshd       /usr/local/bin/nos-sshd
COPY --from=builder /app/target/release/nos-watchdogd  /usr/local/bin/nos-watchdogd
COPY --from=builder /app/target/release/nos-sandbox-exec /usr/local/bin/nos-sandbox-exec
COPY --from=builder /app/target/release/nos            /usr/local/bin/nos
# A scriptable client (logs in like `nos` does) — for `nos-e2e`'s login checks
# and for operators who want to provision without the interactive shell.
COPY --from=builder /app/target/release/nos-provision  /usr/local/bin/nos-provision

# nos-ribd/nos-interfaced's Linux drivers need CAP_NET_ADMIN/CAP_NET_RAW to
# program the kernel (VRF devices, addresses, routes) via rtnetlink, even
# though they run as the unprivileged `nos` user — file capabilities let an
# exec'd non-root process gain exactly these two capabilities, no more.
# nos-bgpd needs CAP_NET_RAW to scope its TCP sockets into a VRF via
# SO_BINDTODEVICE, and CAP_NET_BIND_SERVICE to listen on BGP's well-known
# port 179 (<1024) as the unprivileged `nos` user.
# nos-ospfd needs CAP_NET_RAW too, for its own VRF-scoped (SO_BINDTODEVICE)
# raw protocol-89 socket used to send/receive OSPF Hello packets.
# nos-ospfv3d needs CAP_NET_RAW for the same reason, over a raw IPv6
# protocol-89 socket instead (RFC 5340 Hello/DBD/LSR/LSU/LSAck).
# nos-lacpd needs CAP_NET_RAW too, for its own raw AF_PACKET/SOCK_RAW
# slow-protocols socket per member port (real LACPDU exchange) — no
# CAP_NET_ADMIN, since it never touches rtnetlink (see lacp/CLAUDE.md).
# nos-lldpd needs CAP_NET_RAW for the same reason, over a raw AF_PACKET
# socket per LLDP-enabled interface (see lldp/CLAUDE.md).
# nos-stpd needs CAP_NET_RAW for its ETH_P_ALL AF_PACKET BPDU socket per STP
# port (see stp/CLAUDE.md); like nos-lacpd it never touches rtnetlink.
# nos-acld needs CAP_NET_ADMIN for its tc filters (clsact + flower, sent with
# nos-tc over a plain NETLINK_ROUTE socket; see acl/CLAUDE.md).
# nos-bfdd needs CAP_NET_RAW for SO_BINDTODEVICE into each table's VRF and
# CAP_NET_BIND_SERVICE for its receive socket on UDP 3784 (see bfd/CLAUDE.md).
# nos-fdbd needs CAP_NET_ADMIN, like nos-ribd, to create its VXLAN device and
# program the bridge FDB via rtnetlink (see fdb/CLAUDE.md).
# nos-restd needs CAP_NET_RAW for SO_BINDTODEVICE, to bind its HTTP listener
# inside its routing table's VRF (see rest/CLAUDE.md).
# nos-sshd has no file capabilities: it runs as root (uid 0) and drops its own
# bounding set at startup (see ssh/CLAUDE.md). Root is inherent: OpenSSH only switches
# to the login user when uid 0, even with CAP_SETUID/SETGID (#1187).
# nos-sandbox-exec (#1211) is the trampoline every daemon but nos-sshd is exec'd
# through (NO_NEW_PRIVS): it must hold, in permitted, every capability any daemon
# gets, so it carries the union of the lines above (keep them equal). It trims itself
# to the target's own file capabilities before exec, so it grants nothing extra.
# nos-watchdogd runs as `nos-wd` and needs CAP_SETUID/CAP_SETGID to start every
# child as its role's user, and CAP_CHOWN to create their state directories; the
# children's own file capabilities above are computed at their exec, so they
# are unaffected.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcap2-bin \
    && setcap 'cap_net_admin,cap_net_raw=ep' /usr/local/bin/nos-ribd \
    && setcap 'cap_net_admin,cap_net_raw=ep' /usr/local/bin/nos-interfaced \
    && setcap 'cap_net_raw,cap_net_bind_service=ep' /usr/local/bin/nos-bgpd \
    && setcap 'cap_net_raw=ep' /usr/local/bin/nos-ospfd \
    && setcap 'cap_net_raw=ep' /usr/local/bin/nos-ospfv3d \
    && setcap 'cap_net_raw=ep' /usr/local/bin/nos-lacpd \
    && setcap 'cap_net_raw=ep' /usr/local/bin/nos-lldpd \
    && setcap 'cap_net_raw=ep' /usr/local/bin/nos-stpd \
    && setcap 'cap_net_admin=ep' /usr/local/bin/nos-acld \
    && setcap 'cap_net_raw,cap_net_bind_service=ep' /usr/local/bin/nos-bfdd \
    && setcap 'cap_net_admin=ep' /usr/local/bin/nos-fdbd \
    && setcap 'cap_net_raw=ep' /usr/local/bin/nos-restd \
    && setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service=ep' /usr/local/bin/nos-sandbox-exec \
    && setcap 'cap_setuid,cap_setgid,cap_chown,cap_kill=ep' /usr/local/bin/nos-watchdogd \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# `nos`'s `edit source` (policy-definition editing, see root CLAUDE.md's
# "nos-cli editing UX") shells out to $EDITOR/$VISUAL, falling back to nano
# — kept installed (unlike libcap2-bin above) since it's a runtime tool, not
# a build-time one.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        nano \
    && rm -rf /var/lib/apt/lists/*

# Host keys are not baked in (every container would share them): nos-sshd owns its one
# persisted key (#994/#995). /run/sshd is the privsep dir.
# The PAM module sshd loads (#987, docs/architecture/pam.md): root-owned 0644, no file
# capabilities (it runs inside sshd). The multiarch dir differs per platform
# (x86_64-linux-gnu, aarch64-linux-gnu), so it is taken from where libpam sits.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpam0g \
        openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_* \
    && mkdir -p /run/sshd && chmod 0755 /run/sshd
COPY --from=builder /app/target/release/libpam_nos.so /tmp/pam_nos.so
RUN d="$(dirname "$(readlink -f /usr/lib/*-linux-gnu/libpam.so.0)")/security" \
    && install -D -m 0644 -o root -g root /tmp/pam_nos.so "$d/pam_nos.so" \
    && rm /tmp/pam_nos.so
COPY pam/nos-sshd.pam /etc/pam.d/nos-sshd
# The NSS shell path (#999) is /usr/bin/nos; sshd runs it as the login shell (#992).
# A NOS user's uid is outside group `nos`, which alone reaches /run/nos (the CA and the
# 0660 sockets): setgid `nos` gives the login shell exactly that group, nothing else.
RUN ln -s /usr/local/bin/nos /usr/bin/nos && echo /usr/bin/nos >> /etc/shells \
    && chgrp nos /usr/local/bin/nos && chmod 2755 /usr/local/bin/nos

# The NSS module that makes NOS users resolvable (#999): glibc reads
# /run/nos-users/passwd, which nos-configd writes (docs/architecture/pam.md).
# `nos` is appended to the `passwd` database only, after `files`, and
# /run/nos-users is created at start by nos-wd (a tmpfs in compose/nos-e2e).
COPY --from=builder /app/target/release/libnss_nos.so /tmp/libnss_nos.so
RUN d="$(dirname "$(readlink -f /usr/lib/*-linux-gnu/libpam.so.0)")" \
    && install -m 0644 -o root -g root /tmp/libnss_nos.so "$d/libnss_nos.so.2" \
    && rm /tmp/libnss_nos.so \
    && sed -i 's/^passwd:.*/passwd:         files nos/' /etc/nsswitch.conf \
    && mkdir -p /run/nos-users && chown nos-configd:nos /run/nos-users && chmod 0755 /run/nos-users

# The `cli` compose service and `nos-e2e`'s execs run as `nos` (group `nos`
# reaches the 0660 sockets).
USER nos-wd
ENTRYPOINT ["nos-watchdogd", "--child-gid", "991"]

# The lab image (`make docker-build`, nos-e2e): the runtime plus `pamtester`, which
# drives the PAM stack without sshd (`nos-e2e`'s `pam` phase), and a test-only RTR cache
# (`rpki` phase, #498; it signs its TCP session with TCP-MD5, which StayRTR cannot, so
# it needs CAP_NET_ADMIN). `make docker-build` builds it with the `dev-args` features
# (tools/ci/dev-features.txt); a production build is `--target runtime` with none (#1214).
FROM runtime AS lab
USER root
COPY --from=builder /app/target/release/nos-rtr-stub   /usr/local/bin/nos-rtr-stub
COPY --from=builder /app/target/release/nos-radius-stub /usr/local/bin/nos-radius-stub
COPY --from=builder /app/target/release/nos-tacacs-stub /usr/local/bin/nos-tacacs-stub
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        pamtester libcap2-bin \
    && setcap 'cap_net_admin=ep' /usr/local/bin/nos-rtr-stub \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
USER nos-wd
ENTRYPOINT ["nos-watchdogd", "--child-gid", "991"]
