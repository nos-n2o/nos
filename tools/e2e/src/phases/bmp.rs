//! `bmp` (#878): the RFC 7854 exporter against a real GoBMP collector.
//!
//! GoBMP (`--dump=console -v=5`) prints one JSON object per Peer Up/Down
//! (`msg_type` 10) and logs `client ... accepted`; it parses Initiation and
//! discards it (an error is logged only when it does not parse) and prints
//! nothing for Termination. Those two are covered by the codec unit tests.

use std::time::Duration;

use anyhow::bail;
use reqwest::Method;

use crate::consts::*;
use crate::router::{log, strings, A, B};
use crate::world::World;

/// GoBMP's JSON for a Statistics Report (`"msg_type":1`, recorded from the
/// real collector): the rejected-prefix counter at 1 (the one rejection of
/// router-a's route) and one route held in the Adj-RIB-In after the revert.
const STATS_REJECTED: &str = "\"prefixes_rejected_inbound\":1";
const STATS_ADJ_RIB_IN: &str = "\"ads_rib_in\":1";

/// How often the collector's log is re-read while waiting.
const POLL: Duration = Duration::from_millis(500);

async fn collector_log(w: &World) -> anyhow::Result<String> {
    w.dock.logs(BMP_COLLECTOR).await
}

/// Collector log lines containing every `needle`.
fn lines_with(log: &str, needles: &[&str]) -> usize {
    log.lines()
        .filter(|l| needles.iter().all(|n| l.contains(n)))
        .count()
}

/// Waits (60 s) for more than `baseline` collector lines containing all `needles`.
async fn wait_collector(w: &World, needles: &[&str], baseline: usize) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if lines_with(&collector_log(w).await?, needles) > baseline {
            log(format!("collector: saw {needles:?}"));
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("no new collector line with {needles:?} within 60s (baseline {baseline})");
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn start_collector(w: &World) -> anyhow::Result<()> {
    w.dock
        .start_plain_unseeded(
            BMP_COLLECTOR,
            GOBMP_IMAGE,
            NET,
            IP_BMP,
            &[
                "--dump=console",
                &format!("--source-port={BMP_PORT}"),
                "-v=5",
            ],
        )
        .await
}

/// Router-a exports to GoBMP; see the module docs and `docs/e2e-phases.md`.
pub async fn bmp(w: &mut World) -> anyhow::Result<()> {
    w.dock.ensure_pulled(GOBMP_IMAGE).await?;
    w.ensure_network().await?;
    // Before provisioning: the router's redial backoff would only slow the wait.
    start_collector(w).await?;
    let mut a_flags = A.base_flags();
    a_flags.extend(strings(&["--bmp-station", &format!("{IP_BMP}:{BMP_PORT}")]));
    w.start(A, Some(a_flags.clone()), &[]).await?;
    w.start(B, Some(B.base_flags()), &[]).await?;
    let a = w.a()?;
    a.established().await?;

    log("the collector accepts the station and decodes Initiation and Peer Up");
    a.wait("bmp station connected").await?;
    a.wait("bmp initiation sent").await?;
    a.wait(&format!("bmp peer up sent .*peer={IP_B}")).await?;
    let gobmp = collector_log(w).await?;
    if !gobmp.contains("accepted, calling bmpWorker") {
        bail!("GoBMP never accepted the connection:\n{gobmp}");
    }
    if gobmp.contains("fail to recover BMP") {
        bail!("GoBMP could not parse a message:\n{gobmp}");
    }
    let add = [
        "\"msg_type\":10",
        "\"action\":\"add\"",
        &format!("\"remote_ip\":\"{IP_B}\""),
    ];
    wait_collector(w, &add, 0).await?;
    let gobmp = collector_log(w).await?;
    let line = gobmp
        .lines()
        .find(|l| add.iter().all(|n| l.contains(n)))
        .unwrap_or_default();
    for want in [
        format!("\"remote_asn\":{ASN_B}"),
        format!("\"remote_ip\":\"{IP_B}\""),
        format!("\"local_ip\":\"{IP_A}\""),
        "\"peer_type\":0".to_string(),
        format!("\"local_asn\":{ASN_A}"),
    ] {
        if !line.contains(&want) {
            bail!("Peer Up line lacks {want}: {line}");
        }
    }

    log("a peer shutdown is a Peer Down with reason 1 (NOTIFICATION sent)");
    let down = ["\"action\":\"down\"", "\"bmp_reason\":1"];
    let (down_base, sent_base) = (
        lines_with(&collector_log(w).await?, &down),
        a.count("bmp peer down sent"),
    );
    let mut shut = a_flags.clone();
    shut.extend(strings(&["--shutdown-peer", "bmp phase"]));
    a.provision_flags(&shut).await?;
    wait_collector(w, &down, down_base).await?;
    a.wait_new("bmp peer down sent", sent_base, 30).await?;

    log("the peer back, then the collector restarting: redial and replay");
    let (up_base, conn_base) = (
        lines_with(&collector_log(w).await?, &add),
        a.count("bmp station connected"),
    );
    let mut unshut = a_flags.clone();
    unshut.push("--unshutdown-peer".to_string());
    a.provision_flags(&unshut).await?;
    a.established().await?;
    wait_collector(w, &add, up_base).await?;
    w.dock.container_remove(BMP_COLLECTOR).await;
    a.wait_new("bmp station disconnected", 0, 30).await?;
    start_collector(w).await?;
    // The new container's log starts empty: any `add` line is the replay.
    wait_collector(w, &add, 0).await?;
    a.wait_new("bmp station connected", conn_base, 60).await?;
    route_monitoring(w, &a_flags).await
}

/// The first station of `r`'s `GET /v1/bgp/bmp` (#864).
async fn bmp_status(r: &crate::router::Router) -> anyhow::Result<serde_json::Value> {
    let body = r.rest_expect(Method::GET, "/v1/bgp/bmp", None, 200).await?;
    let v: serde_json::Value = serde_json::from_str(&body)?;
    let st = v[0]["result"][0].clone();
    if st.is_object() {
        Ok(st)
    } else {
        bail!("GET /v1/bgp/bmp has no station: {body}")
    }
}

/// Needles of a unicast prefix line of the collector for the redistributed
/// prefix (GoBMP's JSON keys, recorded from the real collector).
fn route_line(post: bool, action: &str) -> Vec<String> {
    vec![
        format!(
            "\"prefix\":\"{}\"",
            REDISTRIBUTE_PREFIX.split('/').next().unwrap_or("")
        ),
        format!("\"is_adj_rib_in_post_policy\":{post}"),
        format!("\"action\":\"{action}\""),
    ]
}

fn count_route(log: &str, post: bool, action: &str) -> usize {
    let n = route_line(post, action);
    lines_with(log, &n.iter().map(String::as_str).collect::<Vec<_>>())
}

async fn wait_route(w: &World, post: bool, action: &str, baseline: usize) -> anyhow::Result<()> {
    let n = route_line(post, action);
    wait_collector(
        w,
        &n.iter().map(String::as_str).collect::<Vec<_>>(),
        baseline,
    )
    .await
}

/// #864: Route Monitoring on router-b (the receiver of router-a's route):
/// a policy-rejected prefix is pre-policy only, the dump after a collector
/// restart comes from the retained table, a reverted policy adds the
/// post-policy view, a withdrawn route is deleted on both views.
async fn route_monitoring(w: &mut World, a_flags: &[String]) -> anyhow::Result<()> {
    log("route monitoring: router-b rejects the prefix, the collector sees it pre-policy only");
    let station = format!("{IP_BMP}:{BMP_PORT}");
    let mut b_flags = B.base_flags();
    b_flags.extend(strings(&[
        "--bmp-station",
        &station,
        "--bmp-monitor",
        "both",
        "--bmp-statistics-interval",
        "5",
        "--soft-reconfiguration-inbound",
    ]));
    let file = super::bgp::policy_file(
        "bmp-reject",
        &format!("if this.prefix in {REDISTRIBUTE_PREFIX}:\n    reject\nelse:\n    accept\n"),
    )?;
    let mut rejecting = b_flags.clone();
    rejecting.extend(strings(&[
        "--policy-name",
        "bmp-reject",
        "--policy-source-file",
        &file,
        "--import-policy",
        "bmp-reject",
    ]));
    let (a, b) = (w.a()?, w.b()?);
    // Policy and the soft-reconfiguration flag apply in place: no new session.
    b.provision_flags(&rejecting).await?;
    b.wait("bmp station connected").await?;
    let mut redist = a_flags.to_vec();
    redist.extend(strings(&super::bgp::redistribute()));
    a.provision_flags(&redist).await?;
    b.wait(&format!(
        "bmp rib dump sent peer={IP_A} stream=post-policy routes=0"
    ))
    .await?;
    wait_route(w, false, "add", 0).await?;
    let gobmp = collector_log(w).await?;
    if count_route(&gobmp, true, "add") != 0 {
        bail!("a rejected prefix reached the collector post-policy:\n{gobmp}");
    }

    log("route monitoring: the collector restarts, the dump comes from the retained routes");
    let dump = format!("bmp rib dump sent peer={IP_A} stream=pre-policy routes=1");
    let dump_base = b.count(&dump);
    w.dock.container_remove(BMP_COLLECTOR).await;
    start_collector(w).await?;
    let b = w.b()?;
    b.wait_new(&dump, dump_base, 90).await?;
    b.wait(&format!(
        "bmp end-of-rib sent peer={IP_A} stream=pre-policy"
    ))
    .await?;
    wait_route(w, false, "add", 0).await?;
    let eor = [
        "\"is_eor\":true",
        &format!("\"peer_ip\":\"{IP_A}\""),
        "\"is_adj_rib_in_post_policy\":false",
    ];
    wait_collector(w, &eor, 0).await?;
    if count_route(&collector_log(w).await?, true, "add") != 0 {
        bail!("a rejected prefix reached the new collector post-policy");
    }

    log("show bgp bmp: the dump left the station connected with its counters set");
    let st = bmp_status(b).await?;
    let sent = |k: &str| st["frames_sent"][k].as_u64().unwrap_or(0);
    if st["state"] != "Connected"
        || sent("initiation") == 0
        || sent("peer_up") == 0
        || sent("route_monitoring_pre") == 0
        || sent("end_of_rib") == 0
    {
        bail!("GET /v1/bgp/bmp does not show a dumped, connected station: {st}");
    }

    log("route monitoring: reverting the policy re-admits the retained route post-policy");
    b.provision_flags(&b_flags).await?;
    wait_route(w, true, "add", 0).await?;

    log("statistics: a report for router-a's peer counts the rejected prefix and the held route");
    b.wait(&format!("bmp statistics sent peer={IP_A}")).await?;
    let stats = [
        "\"msg_type\":1".to_string(),
        format!("\"remote_ip\":\"{IP_A}\""),
        STATS_REJECTED.to_string(),
        STATS_ADJ_RIB_IN.to_string(),
    ];
    wait_collector(w, &stats.iter().map(String::as_str).collect::<Vec<_>>(), 0).await?;

    log("route monitoring: router-a withdraws the prefix, both views delete it");
    let mut gone = a_flags.to_vec();
    gone.extend(strings(&["--remove-static-route", REDISTRIBUTE_PREFIX]));
    w.a()?.provision_flags(&gone).await?;
    wait_route(w, true, "del", 0).await?;
    wait_route(w, false, "del", 0).await?;
    adj_rib_out(w, a_flags).await?;
    other_families(w).await
}

/// A prefix router-a's export policy toward router-b rejects (#867).
const DENIED_PREFIX: &str = "203.0.113.0/24";

/// Needles of an Adj-RIB-Out unicast line of the collector (#867).
fn out_line(prefix: &str, post: bool, action: &str) -> Vec<String> {
    vec![
        format!("\"prefix\":\"{}\"", prefix.split('/').next().unwrap_or("")),
        "\"is_adj_rib_out\":true".to_string(),
        format!("\"is_adj_rib_out_post_policy\":{post}"),
        format!("\"action\":\"{action}\""),
    ]
}

fn count_out(log: &str, prefix: &str, post: bool, action: &str) -> usize {
    let n = out_line(prefix, post, action);
    lines_with(log, &n.iter().map(String::as_str).collect::<Vec<_>>())
}

async fn wait_out(w: &World, prefix: &str, post: bool, action: &str) -> anyhow::Result<()> {
    let n = out_line(prefix, post, action);
    wait_collector(w, &n.iter().map(String::as_str).collect::<Vec<_>>(), 0).await
}

/// #867: RFC 8671 Adj-RIB-Out on router-a (`monitor-out both`): the prefix it
/// advertises to router-b is seen pre- and post-policy, the prefix its export
/// policy rejects pre-policy only, a withdrawal deletes both, and
/// `monitor-out none` ends the Out stream.
async fn adj_rib_out(w: &mut World, a_flags: &[String]) -> anyhow::Result<()> {
    log("adj-rib-out: router-a monitors what it sends; the denied prefix is pre-policy only");
    let file = super::bgp::policy_file(
        "bmp-out-deny",
        &format!("if this.prefix in {DENIED_PREFIX}:\n    reject\nelse:\n    accept\n"),
    )?;
    let mut flags = a_flags.to_vec();
    flags.extend(strings(&super::bgp::redistribute()));
    flags.extend(strings(&[
        "--static-route",
        DENIED_PREFIX,
        "--policy-name",
        "bmp-out-deny",
        "--policy-source-file",
        &file,
        "--export-policy",
        "bmp-out-deny",
    ]));
    let mut both = flags.clone();
    both.extend(strings(&["--bmp-monitor-out", "both"]));
    w.a()?.provision_flags(&both).await?;
    wait_out(w, REDISTRIBUTE_PREFIX, true, "add").await?;
    wait_out(w, REDISTRIBUTE_PREFIX, false, "add").await?;
    wait_out(w, DENIED_PREFIX, false, "add").await?;
    let gobmp = collector_log(w).await?;
    if count_out(&gobmp, DENIED_PREFIX, true, "add") != 0 {
        bail!("an export-denied prefix reached the collector post-policy:\n{gobmp}");
    }

    log("adj-rib-out: a mode change bounces the station and the dump rebuilds the current state");
    // Established stays up: only the station restarts, so the connect-time
    // dump has the peer. Candidates: both statics; sent: the allowed one.
    let a = w.a()?;
    let dump = format!("bmp adj-rib-out dump sent peer={IP_B}");
    let (only_post, with_pre) = (
        format!("{dump} pre=0 post=1"),
        format!("{dump} pre=2 post=1"),
    );
    let (base_post, base_pre) = (a.count(&only_post), a.count(&with_pre));
    let mut post_only = flags.clone();
    post_only.extend(strings(&["--bmp-monitor-out", "post-policy"]));
    a.provision_flags(&post_only).await?;
    a.wait_new(&only_post, base_post, 90).await?;
    a.provision_flags(&both).await?;
    a.wait_new(&with_pre, base_pre, 90).await?;

    log("adj-rib-out: withdrawing the advertised prefix deletes it on both views");
    let mut gone = both.clone();
    gone.extend(strings(&["--remove-static-route", REDISTRIBUTE_PREFIX]));
    w.a()?.provision_flags(&gone).await?;
    wait_out(w, REDISTRIBUTE_PREFIX, true, "del").await?;
    wait_out(w, REDISTRIBUTE_PREFIX, false, "del").await?;

    log("adj-rib-out: monitor-out none bounces the station and ends the Out stream");
    let a = w.a()?;
    let conn_base = a.count("bmp station connected");
    let mut none = flags.clone();
    none.extend(strings(&["--bmp-monitor-out", "none"]));
    a.provision_flags(&none).await?;
    a.wait_new("bmp station connected", conn_base, 90).await?;
    let before = count_all_out(&collector_log(w).await?);
    let mut again = none.clone();
    again.extend(strings(&["--remove-static-route", DENIED_PREFIX]));
    w.a()?.provision_flags(&again).await?;
    tokio::time::sleep(Duration::from_secs(8)).await;
    let after = count_all_out(&collector_log(w).await?);
    if after != before {
        bail!("Adj-RIB-Out lines kept coming after monitor-out none ({before} -> {after})");
    }
    Ok(())
}

fn count_all_out(log: &str) -> usize {
    lines_with(log, &["\"is_adj_rib_out\":true"])
}

/// #864: EVPN and VPNv4 routes of a GoBGP speaker peering router-a (the
/// router that exports to the collector) reach the collector post-policy,
/// and leave it again when withdrawn.
async fn other_families(w: &mut World) -> anyhow::Result<()> {
    use super::bgp::{gobgp, mpls_ready, start_gobgp, vpn_flags};
    log("route monitoring: EVPN and VPN routes of a GoBGP peer reach the collector post-policy");
    let mut flags = vpn_flags("65000:1");
    flags.extend(strings(&[
        "--evpn",
        "--bmp-station",
        &format!("{IP_BMP}:{BMP_PORT}"),
    ]));
    w.start(A, Some(flags), &[]).await?;
    mpls_ready(w, &["router-a"]).await?;
    start_gobgp(w, &["l2vpn-evpn", "l3vpn-ipv4-unicast"]).await?;
    let a = w.a()?;
    a.wait("bmp station connected").await?;
    let (mac, ip, rd, rt) = ("aa:bb:cc:00:00:01", "192.0.2.10", "65010:1", "65010:10000");
    gobgp(
        w,
        &[
            "global", "rib", "add", "-a", "evpn", "macadv", mac, ip, "etag", "0", "label", "10000",
            "rd", rd, "rt", rt, "encap", "vxlan",
        ],
    )
    .await?;
    gobgp(
        w,
        &[
            "global",
            "rib",
            "add",
            "-a",
            "vpnv4",
            "10.10.0.0/24",
            "label",
            "100",
            "rd",
            "65001:1",
            "rt",
            "65000:1",
        ],
    )
    .await?;
    // GoBMP keys (recorded from the real collector): EVPN is `msg_type` 14
    // with `mac`, VPN is 114 with `vpn_rd` and `prefix`.
    let evpn = |post: bool, action: &str| {
        vec![
            "\"msg_type\":14".to_string(),
            format!("\"action\":\"{action}\""),
            format!("\"mac\":\"{mac}\""),
            format!("\"is_adj_rib_in_post_policy\":{post}"),
        ]
    };
    let vpn = |post: bool, action: &str| {
        vec![
            "\"msg_type\":114".to_string(),
            format!("\"action\":\"{action}\""),
            "\"vpn_rd\":\"65001:1\"".to_string(),
            "\"prefix\":\"10.10.0.0\"".to_string(),
            format!("\"is_adj_rib_in_post_policy\":{post}"),
        ]
    };
    for n in [
        evpn(true, "add"),
        evpn(false, "add"),
        vpn(true, "add"),
        vpn(false, "add"),
    ] {
        wait_collector(w, &n.iter().map(String::as_str).collect::<Vec<_>>(), 0).await?;
    }

    log("route monitoring: after a collector restart the dump carries both families and their End-of-RIB");
    let dump = format!("bmp rib dump sent peer={IP_G} stream=post-policy routes=2");
    let base = w.a()?.count(&dump);
    w.dock.container_remove(BMP_COLLECTOR).await;
    start_collector(w).await?;
    w.a()?.wait_new(&dump, base, 90).await?;
    for n in [evpn(true, "add"), vpn(true, "add")] {
        wait_collector(w, &n.iter().map(String::as_str).collect::<Vec<_>>(), 0).await?;
    }
    for (msg_type, post) in [(14, true), (114, true), (14, false), (114, false)] {
        let eor = [
            format!("\"msg_type\":{msg_type}"),
            "\"is_eor\":true".to_string(),
            format!("\"peer_ip\":\"{IP_G}\""),
            format!("\"is_adj_rib_in_post_policy\":{post}"),
        ];
        wait_collector(w, &eor.iter().map(String::as_str).collect::<Vec<_>>(), 0).await?;
    }

    log("route monitoring: withdrawing both deletes them post-policy");
    gobgp(
        w,
        &[
            "global", "rib", "del", "-a", "evpn", "macadv", mac, ip, "etag", "0", "label", "10000",
            "rd", rd,
        ],
    )
    .await?;
    gobgp(
        w,
        &[
            "global",
            "rib",
            "del",
            "-a",
            "vpnv4",
            "10.10.0.0/24",
            "label",
            "100",
            "rd",
            "65001:1",
        ],
    )
    .await?;
    for n in [evpn(true, "del"), vpn(true, "del")] {
        wait_collector(w, &n.iter().map(String::as_str).collect::<Vec<_>>(), 0).await?;
    }

    log("show bgp bmp: with the collector gone the station backs off and redials");
    w.dock.container_remove(BMP_COLLECTOR).await;
    let a = w.a()?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let st = bmp_status(a).await?;
        if st["state"] == "Backoff"
            && st["reconnects"].as_u64().unwrap_or(0) >= 1
            && st["last_error"].is_string()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("the station never showed backoff with a redial: {st}");
        }
        tokio::time::sleep(POLL).await;
    }
}
