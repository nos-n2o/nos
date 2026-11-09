//! BFD (RFC 5880/5881) phases.

use reqwest::Method;

use crate::consts::*;
use crate::router::{log, strings, A, B};
use crate::world::World;

/// `--static-route` flags: a BFD-guarded static route to `prefix` via `gateway`.
pub(super) fn bfd_route(prefix: &str, gateway: &str) -> Vec<String> {
    strings(&[
        "--static-route",
        prefix,
        "--static-gateway",
        gateway,
        "--bfd-static",
    ])
}

/// `tc <args>` in router-a's network namespace (the runtime image has no iproute2).
pub(super) async fn tc(dock: &crate::docker::Dock, args: &[&str]) -> anyhow::Result<String> {
    let mut cmd = vec!["tc"];
    cmd.extend_from_slice(args);
    dock.in_netns(NETNS_HELPER_IMAGE, "router-a", &cmd).await
}

/// Polls `GET /v1/bfd/sessions?peer=<peer>` on `r` until its one session has
/// `state` (and `diag`, if given) — REST is a snapshot, not a log.
pub(super) async fn session_is(
    r: &crate::router::Router,
    peer: &str,
    state: &str,
    diag: Option<&str>,
    secs: u64,
) -> anyhow::Result<()> {
    let path = format!("/v1/bfd/sessions?peer={peer}");
    let mut last = String::new();
    for _ in 0..secs * 5 {
        last = r.rest_expect(Method::GET, &path, None, 200).await?;
        let v: serde_json::Value = serde_json::from_str(&last)?;
        if let Some(s) = v.as_array().and_then(|a| a.first())
            && s["state"] == state
            && diag.is_none_or(|d| s["diag"] == d)
            && s["key"]["peer"] == peer
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    anyhow::bail!(
        "{}: bfd session to {peer} never reached {state} {diag:?}: {last}",
        r.name()
    )
}

/// #659: router-a retiring its session tells router-b AdminDown, so b logs
/// `neighbor-signaled-session-down` and never waits out its detection time.
async fn graceful_down(
    b: &crate::router::Router,
    trigger: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let signaled = format!("bfd session down peer={IP_A} diag=neighbor-signaled-session-down");
    let expired = format!("bfd session down peer={IP_A} diag=control-detection-time-expired");
    let (n_sig, n_exp) = (b.count(&signaled), b.count(&expired));
    trigger.await?;
    b.wait_new(&signaled, n_sig, 5).await?;
    b.assert_quiet(&expired, n_exp, 2).await
}

/// `bfd`, self-contained. Each router has a static route to a test prefix via
/// the other, guarded by `bfd-profile fast` (100 ms x 3): the route is
/// installed only once the session is Up. A `tc` filter in router-a's
/// namespace then drops UDP 3784 (the BFD port) on ingress: the session goes
/// Down by detection time and ribd withdraws the route; lifting it brings both
/// back. Finally a real FRR `bfdd` (`router-f`) reaches Up with router-a.
pub async fn bfd(w: &mut World) -> anyhow::Result<()> {
    let mut fa = A.base_flags();
    fa.extend(bfd_route(BFD_PREFIX_B, IP_B));
    let mut fb = B.base_flags();
    fb.extend(bfd_route(BFD_PREFIX_A, IP_A));
    w.start(A, Some(fa), &[]).await?;
    w.start(B, Some(fb), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);

    let up_a = format!("bfd session up peer={IP_B}");
    let up_b = format!("bfd session up peer={IP_A}");
    let down_a = format!("bfd session down peer={IP_B} diag=control-detection-time-expired");
    let added = format!("added route prefix={BFD_PREFIX_B} gateway={IP_B}");
    let removed = format!("removed route prefix={BFD_PREFIX_B}");

    log("both ways: sessions Up, then the guarded routes are installed");
    a.wait(&up_a).await?;
    b.wait(&up_b).await?;
    a.wait(&added).await?;

    log("GET /v1/bfd/sessions: Up; a bad ?peer= is 400");
    session_is(a, IP_B, "Up", None, 5).await?;
    session_is(b, IP_A, "Up", None, 5).await?;
    a.rest_expect(Method::GET, "/v1/bfd/sessions?peer=nope", None, 400)
        .await?;

    log("reaching Up opens a Poll sequence (#694): it completes without a flap");
    let (any_down_a, any_down_b) = (a.count("bfd session down"), b.count("bfd session down"));
    a.assert_quiet("bfd session down", any_down_a, 5).await?;
    b.assert_quiet("bfd session down", any_down_b, 5).await?;

    log("dropping UDP 3784 on router-a: Down by detection time, route withdrawn");
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    let (n_down, n_removed, n_up, n_added) = (
        a.count(&down_a),
        a.count(&removed),
        a.count(&up_a),
        a.count(&added),
    );
    tc(&w.dock, &["qdisc", "add", "dev", "eth0", "clsact"]).await?;
    let dropped = tc(
        &w.dock,
        &[
            "filter", "add", "dev", "eth0", "ingress", "protocol", "ip", "u32", "match", "ip",
            "protocol", "17", "0xff", "match", "ip", "dport", "3784", "0xffff", "action", "drop",
        ],
    )
    .await;
    let result = async {
        dropped?;
        a.wait_new(&down_a, n_down, 10).await?;
        a.wait_new(&removed, n_removed, 10).await?;
        session_is(a, IP_B, "Down", Some("ControlDetectionTimeExpired"), 5).await
    }
    .await;
    // Lift it whatever happened, so a failure does not leave the lab broken.
    let lifted = tc(&w.dock, &["qdisc", "del", "dev", "eth0", "clsact"]).await;
    result?;
    lifted?;

    log("filter lifted: Up again and the route is re-added");
    a.wait_new(&up_a, n_up, 30).await?;
    a.wait_new(&added, n_added, 30).await?;
    // The diag is whatever last took the session down: it sticks while Up,
    // so Up is only asserted without one.
    session_is(a, IP_B, "Up", None, 5).await?;

    log("#659: router-a's last client leaves: router-b sees AdminDown, not a timeout");
    graceful_down(b, a.provision(&["--remove-static-route", BFD_PREFIX_B])).await?;
    let n_up_b = b.count(&up_b);
    a.provision(&bfd_route(BFD_PREFIX_B, IP_B)).await?;
    b.wait_new(&up_b, n_up_b, 30).await?;

    log("#659: nos-bfdd on router-a stops on SIGTERM: router-b sees AdminDown");
    graceful_down(b, async {
        w.dock.signal_process("router-a", "nos-bfdd", "-TERM").await
    })
    .await?;
    // The watchdog restarts it and ribd registers the route's session again.
    b.wait_new(&up_b, n_up_b + 1, 60).await?;

    // #660: the VRF device deleted and recreated (a new ifindex) leaves the
    // session's transmit and the table's receive sockets on the dead index.
    log("#660: router-a's VRF deleted and recreated: sockets rebuilt, the session returns");
    let (n_tx, n_rx, n_up_a) = (
        a.count("bfd transmit socket recreated"),
        a.count("bfd receive socket recreated table="),
        a.count(&up_a),
    );
    // `nos-ribd` and `nos-interfaced` put the VRF and the enslavement back.
    w.dock
        .ip(
            NETNS_HELPER_IMAGE,
            Some("router-a"),
            false,
            &["link", "del", BFD_VRF],
        )
        .await?;
    a.wait_new("bfd transmit socket recreated", n_tx, 30)
        .await?;
    a.wait_new("bfd receive socket recreated table=", n_rx, 30)
        .await?;
    a.wait_new(&up_a, n_up_a, 30).await?;

    log("interop: FRR bfdd reaches Up with router-a");
    let conf = format!(
        "frr defaults traditional\nhostname router-f\n!\nbfd\n peer {IP_A}\n  \
         detect-multiplier 3\n  receive-interval 100\n  transmit-interval 100\n  \
         no shutdown\n exit\nexit\n"
    );
    w.dock.container_remove("router-f").await;
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    w.dock
        .start_plain_caps(
            "router-f",
            FRR_IMAGE,
            NET,
            IP_G,
            &[
                "sh",
                "-c",
                "sed -i 's/^bfdd=no/bfdd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start",
            ],
            ("/etc/frr", "frr.conf", conf.as_bytes()),
            &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        )
        .await?;
    // FRR only answers sessions it has configured; router-a registers one
    // when a BFD static route points at FRR.
    w.a()?.provision(&bfd_route(BFD_PREFIX_F, IP_G)).await?;
    w.a()?.wait(&format!("bfd session up peer={IP_G}")).await?;
    // FRR answers the Up-time Poll sequence (P=1) with F and stays Up.
    let down_g = format!("bfd session down peer={IP_G}");
    let n_down_g = w.a()?.count(&down_g);
    w.a()?.assert_quiet(&down_g, n_down_g, 5).await?;
    super::ospf::frr_until(w, "show bfd peers json", 60, |out| {
        out.contains("\"status\":\"up\"")
    })
    .await?;
    w.dock.container_remove("router-f").await;
    Ok(())
}

/// Drops UDP `port` on router-a's ingress and waits for both routers to close
/// their BGP session on the resulting BFD Down (Cease/10 wrapped in a Hard
/// Reset), then lifts the filter and waits for both to re-establish.
async fn drop_udp_and_recover(w: &World, port: &str) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let est = "bgp session established";
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    let closing = format!("bgp: bfd session down, closing peer={IP_B}");
    let sent = format!("sent cease notification peer={IP_B} .*subcode=10 hard_reset=true");
    // Router-b's own BFD goes Down a moment later (the peer signals it), so
    // both close at once and neither reads the other's NOTIFICATION.
    let closing_b = format!("bgp: bfd session down, closing peer={IP_A}");
    let sent_b = format!("sent cease notification peer={IP_A} .*subcode=10 hard_reset=true");
    let (n_closing, n_sent, n_closing_b, n_sent_b, est_a, est_b) = (
        a.count(&closing),
        a.count(&sent),
        b.count(&closing_b),
        b.count(&sent_b),
        a.count(est),
        b.count(est),
    );
    tc(&w.dock, &["qdisc", "add", "dev", "eth0", "clsact"]).await?;
    let dropped = tc(
        &w.dock,
        &[
            "filter", "add", "dev", "eth0", "ingress", "protocol", "ip", "u32", "match", "ip",
            "protocol", "17", "0xff", "match", "ip", "dport", port, "0xffff", "action", "drop",
        ],
    )
    .await;
    let result = async {
        dropped?;
        a.wait_new(&closing, n_closing, 10).await?;
        a.wait_new(&sent, n_sent, 10).await?;
        b.wait_new(&closing_b, n_closing_b, 10).await?;
        b.wait_new(&sent_b, n_sent_b, 10).await
    }
    .await;
    let lifted = tc(&w.dock, &["qdisc", "del", "dev", "eth0", "clsact"]).await;
    result?;
    lifted?;

    a.wait_new(est, est_a, 60).await?;
    b.wait_new(est, est_b, 60).await?;
    Ok(())
}

/// `bgp-bfd`, on the base lab (run after `established`). Both peer-groups get
/// `bfd fast` (100 ms x 3) without resetting the session; dropping UDP 3784
/// on router-a's ingress takes the BFD session Down by detection time and
/// both routers close the BGP session at once (Cease/10 wrapped in a Hard
/// Reset, RFC 9384 + RFC 5882 §4.3.1: N is exchanged and both ends set the C
/// bit) while the 90 s hold time is nowhere near expiring; lifting the drop
/// re-establishes; `max-hops 2` turns both into multihop sessions (UDP 4784,
/// #287) with the same behaviour; removing `bfd` again resets nothing.
pub async fn bgp_bfd(w: &mut World) -> anyhow::Result<()> {
    // Fresh pair on the base config: an earlier BFD phase leaves `nos-ribd`
    // holding the single-hop session to the peer, so BGP's `max-hops 1`
    // would rejoin it silently and never log `bfd session registered` (#739).
    w.start(A, None, &[]).await?;
    w.start(B, None, &[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let cease = "sent cease notification";
    let est = "bgp session established";

    a.established().await?;
    b.established().await?;
    log("adding bfd to the peer-group must not reset the session");
    let (cease_a, cease_b, est_a, est_b) =
        (a.count(cease), b.count(cease), a.count(est), b.count(est));
    a.provision(&["--bfd-bgp"]).await?;
    b.provision(&["--bfd-bgp"]).await?;
    session_is(a, IP_B, "Up", None, 30).await?;
    session_is(b, IP_A, "Up", None, 30).await?;
    a.assert_quiet(cease, cease_a, 3).await?;
    b.assert_quiet(cease, cease_b, 0).await?;
    a.assert_quiet(est, est_a, 0).await?;
    b.assert_quiet(est, est_b, 0).await?;

    log("dropping UDP 3784 on router-a: BFD Down closes the BGP session within seconds");
    drop_udp_and_recover(w, "3784").await?;
    session_is(a, IP_B, "Up", None, 30).await?;

    log("max-hops 2 makes both sessions multihop (RFC 5883, UDP 4784, TTL >= 254)");
    let registered =
        |peer: &str, hop: bool| format!("bfd session registered peer={peer} .*multihop={hop}");
    let (reg_a, reg_b) = (
        a.count(&registered(IP_B, true)),
        b.count(&registered(IP_A, true)),
    );
    a.provision(&["--max-hops", "2"]).await?;
    b.provision(&["--max-hops", "2"]).await?;
    a.wait_new(&registered(IP_B, true), reg_a, 30).await?;
    b.wait_new(&registered(IP_A, true), reg_b, 30).await?;
    a.established().await?;
    session_is(a, IP_B, "Up", None, 30).await?;
    session_is(b, IP_A, "Up", None, 30).await?;
    let path = format!("/v1/bfd/sessions?peer={IP_B}");
    let sessions = a.rest_expect(Method::GET, &path, None, 200).await?;
    let v: serde_json::Value = serde_json::from_str(&sessions)?;
    anyhow::ensure!(
        v[0]["key"]["multihop"] == true && v[0]["key"]["interface"].is_null(),
        "expected one multihop session without an interface: {sessions}"
    );
    log("dropping UDP 4784 on router-a: the multihop session closes BGP too");
    drop_udp_and_recover(w, "4784").await?;
    session_is(a, IP_B, "Up", None, 30).await?;

    log("max-hops 1 again: back to single-hop sessions");
    let (reg_a, reg_b) = (
        a.count(&registered(IP_B, false)),
        b.count(&registered(IP_A, false)),
    );
    a.provision(&["--max-hops", "1"]).await?;
    b.provision(&["--max-hops", "1"]).await?;
    a.wait_new(&registered(IP_B, false), reg_a, 30).await?;
    b.wait_new(&registered(IP_A, false), reg_b, 30).await?;
    a.established().await?;
    session_is(a, IP_B, "Up", None, 30).await?;

    // #659: router-a retires its session first and says AdminDown, so
    // router-b's BGP closes on `neighbor-signaled-session-down` (before this
    // change b waited out its detection time, usually beaten by its own
    // removal below). Removing bfd on one side is therefore not silent.
    log("removing bfd on router-a alone: router-b sees AdminDown, not a detection timeout");
    graceful_down(b, a.provision(&["--no-bfd-bgp"])).await?;
    b.provision(&["--no-bfd-bgp"]).await?;
    a.established().await?;
    b.established().await
}

/// `bfd-padded`, self-contained (RFC 9764, #293). Both routers run `bfd-profile
/// fast` (100 ms x 3) with `padded-pdu-size 1400`: Up, and REST shows
/// `tx_pdu_bytes` 1400. Lowering router-a's eth0 MTU to 1300 makes its padded
/// sends fail (`IP_PMTUDISC_DO` gives `EMSGSIZE`): it logs `bfd padded packet
/// exceeds the path mtu` once and router-b's session goes Down by detection
/// time; restoring the MTU brings it Up again. An FRR `bfdd` (`router-f`)
/// ignores the padding and reaches Up with router-a.
pub async fn bfd_padded(w: &mut World) -> anyhow::Result<()> {
    let padded = strings(&["--bfd-padded-pdu-size", "1400"]);
    let mut fa = A.base_flags();
    fa.extend(bfd_route(BFD_PREFIX_B, IP_B));
    fa.extend(padded.clone());
    let mut fb = B.base_flags();
    fb.extend(bfd_route(BFD_PREFIX_A, IP_A));
    fb.extend(padded);
    w.start(A, Some(fa), &[]).await?;
    w.start(B, Some(fb), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);

    let up_a = format!("bfd session up peer={IP_B}");
    let up_b = format!("bfd session up peer={IP_A}");
    let down_b = format!("bfd session down peer={IP_A} diag=control-detection-time-expired");
    let toobig = format!("bfd padded packet exceeds the path mtu peer={IP_B}");

    log("both Up with 1400-byte packets; REST reports the padded size");
    a.wait(&up_a).await?;
    b.wait(&up_b).await?;
    let body = a
        .rest_expect(
            Method::GET,
            &format!("/v1/bfd/sessions?peer={IP_B}"),
            None,
            200,
        )
        .await?;
    anyhow::ensure!(
        body.contains("\"tx_pdu_bytes\":1400"),
        "expected tx_pdu_bytes 1400: {body}"
    );

    log("router-a eth0 mtu 1300: padded sends fail, router-b detects the loss");
    let (n_down, n_up, n_big) = (b.count(&down_b), a.count(&up_a), a.count(&toobig));
    a.provision(&["--mtu", "1300"]).await?;
    let result = async {
        a.wait_new(&toobig, n_big, 15).await?;
        b.wait_new(&down_b, n_down, 15).await
    }
    .await;
    let restored = a.provision(&["--clear-mtu"]).await;
    result?;
    restored?;

    log("mtu restored: Up again");
    a.wait_new(&up_a, n_up, 30).await?;
    session_is(a, IP_B, "Up", None, 5).await?;

    log("interop: FRR bfdd ignores the padding and reaches Up with router-a");
    let conf = format!(
        "frr defaults traditional\nhostname router-f\n!\nbfd\n peer {IP_A}\n  \
         detect-multiplier 3\n  receive-interval 100\n  transmit-interval 100\n  \
         no shutdown\n exit\nexit\n"
    );
    w.dock.container_remove("router-f").await;
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    w.dock
        .start_plain_caps(
            "router-f",
            FRR_IMAGE,
            NET,
            IP_G,
            &[
                "sh",
                "-c",
                "sed -i 's/^bfdd=no/bfdd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start",
            ],
            ("/etc/frr", "frr.conf", conf.as_bytes()),
            &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        )
        .await?;
    a.provision(&bfd_route(BFD_PREFIX_F, IP_G)).await?;
    a.wait(&format!("bfd session up peer={IP_G}")).await?;
    session_is(a, IP_G, "Up", None, 5).await?;
    w.dock.container_remove("router-f").await;
    Ok(())
}

/// Starts an FRR `bfdd` (`router-f`, `IP_G`) with a classical session to router-a.
async fn start_frr_bfd(w: &World) -> anyhow::Result<()> {
    let conf = format!(
        "frr defaults traditional\nhostname router-f\n!\nbfd\n peer {IP_A}\n  \
         detect-multiplier 3\n  receive-interval 100\n  transmit-interval 100\n  \
         no shutdown\n exit\nexit\n"
    );
    w.dock.container_remove("router-f").await;
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    w.dock
        .start_plain_caps(
            "router-f",
            FRR_IMAGE,
            NET,
            IP_G,
            &[
                "sh",
                "-c",
                "sed -i 's/^bfdd=no/bfdd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start",
            ],
            ("/etc/frr", "frr.conf", conf.as_bytes()),
            &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        )
        .await
}

/// Polls `GET /v1/bfd/reflector` on `r` until `done` holds for it.
async fn reflector_is(
    r: &crate::router::Router,
    secs: u64,
    what: &str,
    done: impl Fn(&serde_json::Value) -> bool,
) -> anyhow::Result<serde_json::Value> {
    let mut last = String::new();
    for _ in 0..secs * 5 {
        last = r
            .rest_expect(Method::GET, "/v1/bfd/reflector", None, 200)
            .await?;
        let v: serde_json::Value = serde_json::from_str(&last)?;
        if done(&v) {
            return Ok(v);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    anyhow::bail!("{}: reflector never showed {what}: {last}", r.name())
}

/// `bfd-sbfd`, self-contained (RFC 7880/7881, #294). Router-b runs an S-BFD
/// reflector for discriminator 10.50.0.3 (its own address) and nothing else;
/// router-a guards a static route via router-b with `bfd-profile sb` (mode
/// sbfd, 100 ms x 3, no remote discriminator: the peer's address). The
/// initiator comes Up from reflections alone (REST: kind `SbfdInitiator`,
/// remote discriminator 171048963; router-b holds no session and its
/// `GET /v1/bfd/reflector` counts the replies) and the route is installed.
/// An FRR `bfdd` (`router-f`) keeps a classical session with router-a
/// throughout. Router-b then answers for 10.77.0.1 instead: router-a goes
/// Down by `control-detection-time-expired`, the route is withdrawn, the
/// reflector counts the probes as `unknown_discriminator` and the classical
/// session never blinks; naming 10.77.0.1 as `sbfd-remote-discriminator` on
/// router-a brings it Up and the route back.
pub async fn bfd_sbfd(w: &mut World) -> anyhow::Result<()> {
    let mut fa = A.base_flags();
    fa.extend(strings(&[
        "--static-route",
        BFD_PREFIX_B,
        "--static-gateway",
        IP_B,
        "--sbfd-static-route",
        BFD_PREFIX_B,
    ]));
    let mut fb = B.base_flags();
    fb.extend(strings(&["--sbfd-reflector", IP_B]));
    w.start(A, Some(fa), &[]).await?;
    w.start(B, Some(fb), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);

    let up = format!("bfd session up peer={IP_B}");
    let down = format!("bfd session down peer={IP_B} diag=control-detection-time-expired");
    let added = format!("added route prefix={BFD_PREFIX_B} gateway={IP_B}");
    let removed = format!("removed route prefix={BFD_PREFIX_B}");
    let frr_down = format!("bfd session down peer={IP_G}");

    log("the S-BFD initiator comes Up from reflections and guards the route");
    a.wait(&up).await?;
    a.wait(&added).await?;
    let body = a
        .rest_expect(
            Method::GET,
            &format!("/v1/bfd/sessions?peer={IP_B}"),
            None,
            200,
        )
        .await?;
    anyhow::ensure!(
        body.contains("\"kind\":\"SbfdInitiator\"")
            && body.contains("\"remote_discriminator\":171048963"),
        "expected an S-BFD session probing 10.50.0.3: {body}"
    );
    session_is(a, IP_B, "Up", None, 5).await?;

    log("the reflector keeps no session, only counters");
    let sessions = b
        .rest_expect(Method::GET, "/v1/bfd/sessions", None, 200)
        .await?;
    anyhow::ensure!(
        sessions.trim() == "[]",
        "reflector side holds no session: {sessions}"
    );
    let v = reflector_is(b, 10, "replies", |v| v["replied"].as_u64() > Some(0)).await?;
    anyhow::ensure!(
        v["discriminators"] == serde_json::json!([171_048_963]),
        "reflector discriminators: {v}"
    );

    log("interop: a classical session with FRR bfdd on the same link");
    start_frr_bfd(w).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.provision(&bfd_route(BFD_PREFIX_F, IP_G)).await?;
    a.wait(&format!("bfd session up peer={IP_G}")).await?;

    log("router-b answers for another discriminator: Down, route withdrawn, counted");
    let (n_down, n_removed, n_up, n_added, n_frr) = (
        a.count(&down),
        a.count(&removed),
        a.count(&up),
        a.count(&added),
        a.count(&frr_down),
    );
    b.provision(&["--sbfd-reflector", "10.77.0.1"]).await?;
    a.wait_new(&down, n_down, 10).await?;
    a.wait_new(&removed, n_removed, 10).await?;
    session_is(a, IP_B, "Down", Some("ControlDetectionTimeExpired"), 5).await?;
    reflector_is(b, 10, "unknown_discriminator drops", |v| {
        v["discarded"]["unknown_discriminator"].as_u64() > Some(0)
    })
    .await?;
    a.assert_quiet(&frr_down, n_frr, 0).await?;

    log("naming that discriminator on router-a: Up again, route re-added");
    a.provision(&[
        "--sbfd-static-route",
        BFD_PREFIX_B,
        "--sbfd-remote-discriminator",
        "10.77.0.1",
    ])
    .await?;
    a.wait_new(&up, n_up, 30).await?;
    a.wait_new(&added, n_added, 30).await?;
    session_is(a, IP_B, "Up", None, 5).await?;
    a.assert_quiet(&frr_down, n_frr, 3).await?;
    w.dock.container_remove("router-f").await;
    Ok(())
}

/// `bfd-unsolicited`, self-contained (RFC 9468, #295). Router-a has no BFD
/// client at all, only `bfd-unsolicited fast` (100 ms x 3) on its eth0
/// subinterface; router-b guards a static route via router-a. Router-b's first
/// packet (Your Discriminator 0) makes router-a log `bfd unsolicited session
/// created`, both reach Up, the route is added and REST on router-a lists the
/// session as `Unsolicited`; a real FRR `bfdd` (`router-f`) as the active end
/// gets its own session. Dropping UDP 3784 on router-a (`tc`) takes it Down
/// and, after the 60 s aging time, `bfd unsolicited session aged out`; lifting
/// the filter lets router-b's next packet create a fresh one. Removing
/// `bfd-unsolicited` drops the session (`removed: no longer configured`) and
/// router-b's packets get no answer and create nothing.
pub async fn bfd_unsolicited(w: &mut World) -> anyhow::Result<()> {
    let mut fa = A.base_flags();
    fa.push("--bfd-unsolicited".to_string());
    let mut fb = B.base_flags();
    fb.extend(bfd_route(BFD_PREFIX_A, IP_A));
    w.start(A, Some(fa), &[]).await?;
    w.start(B, Some(fb), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);

    let created = |p: &str| format!("bfd unsolicited session created peer={p}");
    let up_a = |p: &str| format!("bfd session up peer={p}");
    let up_b = format!("bfd session up peer={IP_A}");
    let added = format!("added route prefix={BFD_PREFIX_A} gateway={IP_A}");

    log("router-b's packets create a passive session on router-a, route added on router-b");
    a.wait(&created(IP_B)).await?;
    a.wait(&up_a(IP_B)).await?;
    b.wait(&up_b).await?;
    b.wait(&added).await?;
    session_is(a, IP_B, "Up", None, 5).await?;
    let body = a
        .rest_expect(
            Method::GET,
            &format!("/v1/bfd/sessions?peer={IP_B}"),
            None,
            200,
        )
        .await?;
    anyhow::ensure!(
        body.contains("\"kind\":\"Unsolicited\""),
        "expected an unsolicited session: {body}"
    );

    log("interop: FRR bfdd as the active end");
    start_frr_bfd(w).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.wait(&created(IP_G)).await?;
    a.wait(&up_a(IP_G)).await?;
    session_is(a, IP_G, "Up", None, 5).await?;
    w.dock.container_remove("router-f").await;

    log("UDP 3784 dropped on router-a: Down, then aged out after the aging time");
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    let aged = format!("bfd unsolicited session aged out peer={IP_B}");
    let (n_aged, n_created) = (a.count(&aged), a.count(&created(IP_B)));
    tc(&w.dock, &["qdisc", "add", "dev", "eth0", "clsact"]).await?;
    let dropped = tc(
        &w.dock,
        &[
            "filter", "add", "dev", "eth0", "ingress", "protocol", "ip", "u32", "match", "ip",
            "protocol", "17", "0xff", "match", "ip", "dport", "3784", "0xffff", "action", "drop",
        ],
    )
    .await;
    let result = async {
        dropped?;
        a.wait_new(&aged, n_aged, 100).await
    }
    .await;
    let lifted = tc(&w.dock, &["qdisc", "del", "dev", "eth0", "clsact"]).await;
    result?;
    lifted?;

    log("filter lifted: router-b's next packet creates a fresh session");
    a.wait_new(&created(IP_B), n_created, 30).await?;
    session_is(a, IP_B, "Up", None, 30).await?;

    log("bfd-unsolicited removed: session dropped, no answer, nothing created");
    let gone = format!("bfd unsolicited session removed: no longer configured peer={IP_B}");
    let (n_gone, n_created, n_up_b) = (a.count(&gone), a.count(&created(IP_B)), b.count(&up_b));
    a.provision(&["--no-bfd-unsolicited"]).await?;
    a.wait_new(&gone, n_gone, 30).await?;
    a.assert_quiet(&created(IP_B), n_created, 8).await?;
    b.assert_quiet(&up_b, n_up_b, 0).await?;
    let sessions = a
        .rest_expect(Method::GET, "/v1/bfd/sessions", None, 200)
        .await?;
    anyhow::ensure!(
        sessions.trim() == "[]",
        "router-a holds no session without bfd-unsolicited: {sessions}"
    );
    Ok(())
}
