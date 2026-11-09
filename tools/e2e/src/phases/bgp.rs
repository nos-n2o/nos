//! BGP phases: sessions, redistribution, authentication, RPL policy, and the
//! reflector / route-server topologies.

use std::fmt::Write as _;
use std::time::Duration;

use anyhow::{bail, Context};
use reqwest::Method;

use nos_proto::{
    BgpPeerGroupOp, ConfigOp, InterfaceOp, RoutingTableOp, StaticRouteOp, StaticRoutingInstanceOp,
};

use crate::consts::*;
use crate::logs::bre;
use crate::router::{log, strings, Id, Router, A, B, C};
use crate::world::World;

/// `--static-route` + `--redistribute` flags: router-a (or a client) redistributes
/// `REDISTRIBUTE_PREFIX` from static into bgp.
pub(super) fn redistribute() -> Vec<&'static str> {
    vec![
        "--static-route",
        REDISTRIBUTE_PREFIX,
        "--static-gateway",
        REDISTRIBUTE_GATEWAY,
        "--redistribute",
    ]
}

/// The ASN router-a's export policy prepends twice in the `communities` phase.
const PREPEND_ASN: u32 = 64999;

fn loc_rib() -> String {
    format!("loc-rib best path for {REDISTRIBUTE_PREFIX} updated")
}

pub(super) fn learned() -> String {
    format!("learned route for {REDISTRIBUTE_PREFIX} into adj-rib-in")
}

/// Writes an RPL source file `nos-provision` reads on the host.
pub(super) fn policy_file(name: &str, source: &str) -> anyhow::Result<String> {
    let path = std::env::temp_dir().join(format!("nos-e2e-{}-{name}.rpl", std::process::id()));
    std::fs::write(&path, source).with_context(|| format!("writing {}", path.display()))?;
    Ok(path.to_string_lossy().into_owned())
}

/// A *new* session after `baseline` (a config change restarts sessions).
pub(super) async fn reestablished(r: &Router, baseline: usize) -> anyhow::Result<()> {
    r.wait_new("bgp session established", baseline, 60).await
}

/// `nos-restd`'s baked-in build revision, over `GET /v1/version`.
async fn revision(r: &Router) -> anyhow::Result<String> {
    let body = r.rest_expect(Method::GET, "/v1/version", None, 200).await?;
    let v: serde_json::Value = serde_json::from_str(&body)?;
    Ok(v["revision"].as_str().unwrap_or_default().to_string())
}

/// State-based for the session (`Router::established`), log-based for the
/// capabilities below (only visible in logs): re-runnable after a
/// log-flooding phase for the session part only. Callers following such a
/// phase use `Router::established()`, not this phase.
pub async fn established(w: &mut World) -> anyhow::Result<()> {
    let waited = async {
        w.a()?.established().await?;
        w.b()?.established().await
    };
    if let Err(e) = waited.await {
        dump_bgp_state(w).await;
        return Err(e);
    }
    // RFC 8654: both nos-bgpd always advertise Extended Message, so each side
    // must have negotiated it with the other.
    w.a()?
        .wait("extended message negotiated extended_message=true")
        .await?;
    w.b()?
        .wait("extended message negotiated extended_message=true")
        .await?;
    // RFC 4724 / RFC 8538 graceful restart is on by default, with N.
    w.a()?
        .wait(&format!(
            "graceful restart negotiated peer={IP_B} .*notification=true"
        ))
        .await?;
    w.b()?
        .wait(&format!(
            "graceful restart negotiated peer={IP_A} .*notification=true"
        ))
        .await?;
    // #473: both images were built from one tree, so `nos-restd` reports the
    // same baked-in revision; `unknown` means `NOS_BUILD_REV` never arrived.
    let (ra, rb) = (revision(w.a()?).await?, revision(w.b()?).await?);
    if ra == "unknown" || ra.is_empty() || ra != rb {
        bail!("/v1/version revision: a={ra:?} b={rb:?} (want equal and not unknown)");
    }
    Ok(())
}

/// On an `established` timeout (#158): each router's port-179 sockets
/// (`/proc/net/tcp*` — the image has no `ss`; `00B3` is 179, `st` 02 is
/// SYN_SENT) and its recent BGP log lines, so a flake arrives with evidence.
async fn dump_bgp_state(w: &World) {
    for r in [w.a(), w.b()].into_iter().flatten() {
        let tcp = w
            .dock
            .exec(r.name(), &["cat", "/proc/net/tcp", "/proc/net/tcp6"])
            .await
            .map_or_else(|e| e.to_string(), |(_, out)| out);
        log(format!("{}: port 179 sockets:", r.name()));
        for l in tcp.lines().filter(|l| l.contains(":00B3")) {
            log(format!("  {l}"));
        }
        log(format!("{}: last bgp log lines:", r.name()));
        for l in r.logs.tail("bgp", 40) {
            log(format!("  {l}"));
        }
    }
}

pub async fn reconnect(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let (base_a, base_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    log("killing router-b's nos-bgpd to force a hold-timer/reconnect cycle on router-a");
    w.dock.kill_process("router-b", "nos-bgpd").await?;
    a.wait_new(
        "outbound bgp session ended\\|inbound bgp session ended",
        0,
        120,
    )
    .await?;
    log("waiting for the watchdog to respawn router-b's nos-bgpd and re-establish");
    reestablished(b, base_b).await?;
    reestablished(a, base_a).await
}

pub async fn collision(w: &mut World) -> anyhow::Result<()> {
    // Baselines first: the sessions killed below already logged "established",
    // so the next phase must wait for a *new* one on each side or it provisions
    // a router whose restarted nos-bgpd has no session yet.
    let (base_a, base_b) = (
        w.a()?.count("bgp session established"),
        w.b()?.count("bgp session established"),
    );
    log("restarting both nos-bgpd processes at once to try to trigger a real collision");
    w.dock.kill_process("router-a", "nos-bgpd").await?;
    w.dock.kill_process("router-b", "nos-bgpd").await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Scoped to nos_bgp's own CollisionLost outcome — a bare "collision"
    // also hits rtnetlink's unrelated per-link packet-stat counter.
    let seen = w.a()?.count("nos_bgp::.*CollisionLost") + w.b()?.count("nos_bgp::.*CollisionLost");
    if seen > 0 {
        log("observed a collision-resolution log line");
    } else {
        log("no collision observed this cycle (timing-dependent, not a failure by itself)");
    }
    reestablished(w.a()?, base_a).await?;
    reestablished(w.b()?, base_b).await
}

pub async fn redistribute_phase(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    // router-b has no static routes of its own here, so a new "added route" on
    // it can only be this BGP-learned route landing in its kernel table (rt1).
    let kernel_baseline = b.count("added route");
    a.provision(&redistribute()).await?;
    a.wait(&loc_rib()).await?;
    b.wait(&learned()).await?;
    b.wait(&loc_rib()).await?;
    b.wait_new("added route", kernel_baseline, 60).await?;

    // #160: a soft-in makes router-a re-announce the prefix unchanged; that
    // must not count as a new best path on router-b.
    let base = b.count(&loc_rib());
    let eorr = format!("bgp: received EoRR peer={IP_A}");
    let eorr_base = b.count(&eorr);
    b.rest_expect(
        Method::POST,
        &format!("/v1/bgp/r1/peer/{IP_A}/soft-in"),
        None,
        200,
    )
    .await?;
    b.wait_new(&eorr, eorr_base, 30).await?;
    b.assert_quiet(&loc_rib(), base, 8).await
}

/// `bgp-routes-paging` (#722): `GET /v1/bgp/routes` is paged per instance. 25
/// extra statics redistributed into BGP on router-a (and learned by router-b)
/// against a page size of 10 force three pages; walking `pagination.next`
/// must return each exactly once, in ascending order, on both routers. The
/// 1000-route server default is covered by unit tests; 1M routes are too
/// heavy for CI.
pub async fn bgp_routes_paging(w: &mut World) -> anyhow::Result<()> {
    const N: usize = 25;
    let (a, b) = (w.a()?, w.b()?);
    let prefixes: Vec<String> = (0..N).map(|i| format!("10.89.{i}.0/24")).collect();
    let flags = |flag: &str| -> Vec<String> {
        prefixes
            .iter()
            .flat_map(|p| [flag.to_string(), p.clone()])
            .collect()
    };
    let mut add = flags("--static-route");
    add.extend(strings(&[
        "--static-gateway",
        REDISTRIBUTE_GATEWAY,
        "--redistribute",
    ]));
    a.provision(&add).await?;

    let ours = |items: &[serde_json::Value]| -> Vec<String> {
        items
            .iter()
            .filter_map(|p| p["prefix"].as_str())
            .filter(|p| p.starts_with("10.89."))
            .map(String::from)
            .collect()
    };
    for r in [a, b] {
        let mut seen = Vec::new();
        for _ in 0..60 {
            seen = ours(&r.bgp_routes_walk("r1", Some(10)).await?);
            if seen.len() == N {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        if seen != prefixes {
            bail!(
                "{}: paged walk returned {seen:?}, expected {prefixes:?}",
                r.name()
            );
        }
    }

    log("the first page is full and points at the next one");
    let body = a
        .rest_expect(
            Method::GET,
            "/v1/bgp/routes?instance=r1&limit=10",
            None,
            200,
        )
        .await?;
    let page: serde_json::Value = serde_json::from_str(&body)?;
    let result = &page[0]["result"];
    if result["items"].as_array().map(Vec::len) != Some(10)
        || result["pagination"]["limit"] != 10
        || !result["pagination"]["next"].is_string()
    {
        bail!("first page of GET /v1/bgp/routes?instance=r1&limit=10 is wrong: {body}");
    }
    a.rest_expect(Method::GET, "/v1/bgp/routes?limit=10", None, 400)
        .await?;
    a.rest_expect(
        Method::GET,
        "/v1/bgp/routes?instance=r1&after=nope",
        None,
        400,
    )
    .await?;
    a.rest_expect(Method::GET, "/v1/bgp/routes?instance=nope", None, 404)
        .await?;

    a.provision(&flags("--remove-static-route")).await?;
    Ok(())
}

/// #723: walking `path` (a paged BGP show endpoint, instance `r1`) one item
/// per page returns exactly the items of the single full page, in the same
/// order, and at least `min` of them: every route once, none lost or
/// repeated across the cursors.
async fn expect_paged_walk(r: &Router, path: &str, min: usize) -> anyhow::Result<()> {
    let full = r.bgp_walk(path, "r1", None).await?;
    let paged = r.bgp_walk(path, "r1", Some(1)).await?;
    if paged.len() < min || paged != full {
        bail!(
            "{}: {path} walked at limit=1 returned {} items, the full page {} (want >= {min} and equal): {paged:?} vs {full:?}",
            r.name(),
            paged.len(),
            full.len()
        );
    }
    Ok(())
}

/// Whether, among `r`'s log lines matching `first`, `then` or `not`, the one
/// right after the last `first` is a `then` — i.e. no `not` came between.
fn followed_by(r: &Router, first: &str, then: &str, not: &str) -> anyhow::Result<()> {
    let lines = r.logs.tail(&format!("{first}\\|{then}\\|{not}"), 20);
    let (first_re, then_re) = (bre(first), bre(then));
    let i = lines
        .iter()
        .rposition(|l| first_re.is_match(l))
        .context("no line matching the first pattern")?;
    match lines.get(i + 1) {
        Some(next) if then_re.is_match(next) => Ok(()),
        next => bail!(
            "{}: after '{first}' expected '{then}', got {next:?}",
            r.name()
        ),
    }
}

/// RFC 4724 / RFC 8538 graceful restart, on by default (#12). Needs
/// `redistribute` (router-a's prefix on router-b). In order: the capability
/// and End-of-RIB between two nos routers with no config; router-a's
/// `nos-bgpd` killed while its `nos-ribd` holds router-b's route: it restarts
/// gracefully (selection deferral, R and F set), and neither kernel loses the
/// other's route — router-b keeps router-a's until its End-of-RIB; a Cease/Other Configuration Change kept
/// graceful by N (same process, F=1: kept until End-of-RIB, never removed); a
/// `clear` sent as a Hard Reset (flushed); and router-a with graceful restart
/// disabled (no capability: flushed on return, a kill is a hard flap, and
/// router-b sends it no End-of-RIB), then back to the default.
pub async fn bgp_graceful_restart(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let removed = format!("removed route prefix={REDISTRIBUTE_PREFIX}");
    let retaining = format!("peer down, retaining routes as stale peer={IP_A}");
    let est = "bgp session established";

    log("default-on: capability with N, and an End-of-RIB each way");
    b.wait(&format!(
        "graceful restart negotiated peer={IP_A} .*notification=true"
    ))
    .await?;
    a.wait(&format!(
        "graceful restart negotiated peer={IP_B} .*notification=true"
    ))
    .await?;
    b.wait(&format!("received end-of-rib peer={IP_A} family=ipv4"))
        .await?;
    a.wait(&format!("received end-of-rib peer={IP_B} family=ipv4"))
        .await?;

    log("router-b redistributes a prefix of its own, installed in router-a's kernel");
    let removed_gr_b = format!("removed route prefix={GR_B_PREFIX}");
    let added_gr_b = format!("added route prefix={GR_B_PREFIX}");
    let added_a = a.count(&added_gr_b);
    b.provision(&[
        "--static-route",
        GR_B_PREFIX,
        "--static-gateway",
        REDISTRIBUTE_GATEWAY,
        "--redistribute",
    ])
    .await?;
    a.wait_new(&added_gr_b, added_a, 60).await?;

    log("killing router-a's nos-bgpd: its nos-ribd kept router-b's route, so it restarts gracefully");
    let deferring = "graceful restart: forwarding state preserved, deferring route selection";
    let deferral_ended = "route selection deferral ended reason=end-of-rib";
    let restarting = format!("graceful restart negotiated peer={IP_A} .*restarting=true");
    let purged = format!("purged stale routes after end-of-rib peer={IP_A} family=ipv4 count=0");
    let (est_a, est_b, ret_b, purged_b, removed_a, removed_b) = (
        a.count(est),
        b.count(est),
        b.count(&retaining),
        b.count(&purged),
        a.count(&removed_gr_b),
        b.count(&removed),
    );
    let (deferring_a, ended_a, restarting_b) = (
        a.count(deferring),
        a.count(deferral_ended),
        b.count(&restarting),
    );
    w.dock.kill_process("router-a", "nos-bgpd").await?;
    b.wait_new(&retaining, ret_b, 30).await?;
    a.wait_new(deferring, deferring_a, 60).await?;
    // The R bit, and F=1: router-b keeps router-a's route until its End-of-RIB.
    b.wait_new(&restarting, restarting_b, 60).await?;
    a.wait_new(deferral_ended, ended_a, 60).await?;
    b.wait_new(&purged, purged_b, 60).await?;
    followed_by(b, &retaining, &purged, &removed)?;
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;
    // Neither kernel lost the other's route at any point.
    a.assert_quiet(&removed_gr_b, removed_a, 3).await?;
    b.assert_quiet(&removed, removed_b, 1).await?;

    log("a graceful Cease (other configuration change, N): kept until End-of-RIB, never removed");
    let config_change = format!("received notification peer={IP_A} code=6 subcode=6 ");
    for mrai in ["1", "0"] {
        let (est_b, ret_b, purged_b, removed_b, cease_b) = (
            b.count(est),
            b.count(&retaining),
            b.count(&purged),
            b.count(&removed),
            b.count(&config_change),
        );
        let mut flags = redistribute();
        flags.extend(["--mrai", mrai]);
        a.provision(&flags).await?;
        b.wait_new(&config_change, cease_b, 30).await?;
        b.wait_new(&retaining, ret_b, 30).await?;
        b.wait_new(&purged, purged_b, 60).await?;
        reestablished(b, est_b).await?;
        followed_by(b, &retaining, &purged, &removed)?;
        b.assert_quiet(&removed, removed_b, 3).await?;
    }

    log("clear: a Hard Reset wrapping Administrative Reset, the route flushed and re-learned");
    // Asserted on the Loc-RIB, not the kernel: the session is back within a
    // second, inside one `rib_push_client` poll, so the kernel may never see
    // the withdrawal.
    let withdrawn = format!("loc-rib route for {REDISTRIBUTE_PREFIX} withdrawn");
    let (withdrawn_b, loc_b) = (b.count(&withdrawn), b.count(&loc_rib()));
    a.rest_expect(
        Method::POST,
        &format!("/v1/bgp/r1/peer/{IP_B}/clear"),
        None,
        200,
    )
    .await?;
    b.wait(&format!(
        "received notification peer={IP_A} code=6 subcode=9 hard_reset_code=6 hard_reset_subcode=4"
    ))
    .await?;
    b.wait_new(&withdrawn, withdrawn_b, 30).await?;
    b.wait_new(&loc_rib(), loc_b, 60).await?;

    log("graceful restart off on router-a: flushed on return, a kill is a hard flap");
    let no_cap = format!("flushing stale routes peer={IP_A} .*reason=.*no-capability");
    let (est_a, est_b, no_cap_b) = (a.count(est), b.count(est), b.count(&no_cap));
    let mut off = redistribute();
    off.push("--no-graceful-restart");
    a.provision(&off).await?;
    b.wait_new(&no_cap, no_cap_b, 60).await?;
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;
    let eor_from_b = format!("received end-of-rib peer={IP_B}");
    let (est_a, est_b, eor_a, ret_b, withdrawn_b) = (
        a.count(est),
        b.count(est),
        a.count(&eor_from_b),
        b.count(&retaining),
        b.count(&withdrawn),
    );
    w.dock.kill_process("router-a", "nos-bgpd").await?;
    b.wait_new(&withdrawn, withdrawn_b, 30).await?;
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;
    anyhow::ensure!(
        b.count(&retaining) == ret_b,
        "router-b kept routes of a peer without graceful restart"
    );
    a.assert_quiet(&eor_from_b, eor_a, 5).await?;

    log("back to the default: graceful restart on again");
    let negotiated = format!("graceful restart negotiated peer={IP_B} ");
    let (est_b, neg_a) = (b.count(est), a.count(&negotiated));
    let mut on = redistribute();
    on.push("--clear-graceful-restart");
    a.provision(&on).await?;
    reestablished(b, est_b).await?;
    a.wait_new(&negotiated, neg_a, 60).await?;

    log("router-b stops redistributing its own prefix");
    let removed_a = a.count(&removed_gr_b);
    b.provision(&["--remove-static-route", GR_B_PREFIX]).await?;
    a.wait_new(&removed_gr_b, removed_a, 60).await
}

/// #654: a crash-restarted `nos-ribd` keeps the kernel routes its predecessor
/// left (the startup hold) until `nos-bgpd` re-pushes its `Full`. Needs
/// `redistribute`. router-b redistributes a static, so router-a's kernel holds
/// it as a BGP route; router-a's `nos-ribd` is SIGKILLed (no teardown): the
/// new process holds, and releases once `nos-bgpd`'s `Full` is applied — the
/// route is never removed from router-a's kernel meanwhile.
pub async fn ribd_crash_hold(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let removed_gr_b = format!("removed route prefix={GR_B_PREFIX}");
    let added_gr_b = format!("added route prefix={GR_B_PREFIX}");
    let added_a = a.count(&added_gr_b);
    b.provision(&[
        "--static-route",
        GR_B_PREFIX,
        "--static-gateway",
        REDISTRIBUTE_GATEWAY,
        "--redistribute",
    ])
    .await?;
    a.wait_new(&added_gr_b, added_a, 60).await?;

    log("SIGKILL router-a's nos-ribd: the kernel keeps router-b's route through the hold");
    let hold = "startup hold: keeping existing kernel routes";
    let released = "startup hold released";
    let (hold_a, released_a, removed_a) =
        (a.count(hold), a.count(released), a.count(&removed_gr_b));
    w.dock.kill_process("router-a", "nos-ribd").await?;
    a.wait_new(hold, hold_a, 60).await?;
    a.wait_new(released, released_a, 90).await?;
    a.assert_quiet(&removed_gr_b, removed_a, 3).await?;
    a.established().await?;

    log("router-b stops redistributing its own prefix");
    let removed_a = a.count(&removed_gr_b);
    b.provision(&["--remove-static-route", GR_B_PREFIX]).await?;
    a.wait_new(&removed_gr_b, removed_a, 60).await
}

/// `CHUNKED_ROUTES` /32s in 100.64.0.0/16, as repeated `<flag>` arguments.
fn chunked_routes(flag: &str) -> Vec<String> {
    (0..CHUNKED_ROUTES)
        .flat_map(|i| {
            [
                flag.to_string(),
                format!("100.64.{}.{}/32", i / 256, i % 256),
            ]
        })
        .collect()
}

/// Waits (up to `secs`) until router `r`'s `rt1` holds a BGP count `ok` accepts.
async fn wait_bgp_count(r: &Router, secs: u64, ok: impl Fn(usize) -> bool) -> anyhow::Result<()> {
    let mut n = 0;
    for _ in 0..secs {
        n = r.rt1_count("Bgp").await?;
        if ok(n) {
            log(format!("{}: rt1 holds {n} bgp routes", r.name()));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("{}: rt1 stuck at {n} bgp routes", r.name())
}

/// #380 follow-up: a BGP push to `nos-ribd` larger than one `PushBgpRoutes`
/// frame (`nos_proto::rib::BGP_PUSH_CHUNK` routes) is cut into frames. Needs
/// `redistribute`. router-a redistributes `CHUNKED_ROUTES` extra statics, so
/// router-b's `nos-bgpd` pushes them as multi-frame `Add`s; then its
/// `nos-bgpd` is killed: graceful restart keeps its `nos-ribd` (and kernel)
/// routes, and after End-of-RIB the new process pushes one `Full` in 3
/// frames (`FullPart`, `FullPart`, `Full`), which `nos-ribd` assembles before
/// publishing — no route is removed from the kernel meanwhile. Removing the
/// statics again is a multi-frame `Remove` push.
pub async fn bgp_push_chunked(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let mut flags: Vec<String> = redistribute().into_iter().map(String::from).collect();
    flags.extend(chunked_routes("--static-route"));
    a.provision(&flags).await?;
    wait_bgp_count(b, 120, |n| n > CHUNKED_ROUTES).await?;

    let assembled = "assembled chunked bgp route snapshot table=rt1 routes=50[0-9][0-9] parts=3";
    let (est_a, est_b, asm_b, removed_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
        b.count(assembled),
        b.count("removed route"),
    );
    w.dock.kill_process("router-b", "nos-bgpd").await?;
    reestablished(b, est_b).await?;
    reestablished(a, est_a).await?;
    b.wait_new(assembled, asm_b, 120).await?;
    b.assert_quiet("removed route", removed_b, 3).await?;
    wait_bgp_count(b, 30, |n| n > CHUNKED_ROUTES).await?;

    log("router-a stops redistributing the extra statics");
    a.provision(&chunked_routes("--remove-static-route"))
        .await?;
    wait_bgp_count(b, 120, |n| n < 10).await
}

/// RFC 4724 against FRR (`router-f`, self-contained), so a symmetric encoding
/// bug between two nos routers can't hide: FRR's default (helper only) keeps
/// nothing of its own; with `bgp graceful-restart` router-a decodes its
/// capability and End-of-RIB, FRR sees ours, and killing FRR's bgpd leaves
/// router-a retaining its route until FRR's restarted bgpd either flushes it
/// (F=0) or replaces it and sends End-of-RIB (F=1).
pub async fn bgp_gr_frr(w: &mut World) -> anyhow::Result<()> {
    let flags = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
    ]);
    w.start(A, Some(flags), &[]).await?;
    w.dock.container_remove("router-g").await;
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    let conf = |gr: &str| {
        format!(
            "frr defaults traditional\nhostname router-f\n!\n\
             router bgp {ASN_G}\n bgp router-id {RID_G}\n no bgp ebgp-requires-policy\n \
             no bgp network import-check\n{gr} neighbor {IP_A} remote-as {ASN_A}\n \
             address-family ipv4 unicast\n  network {FRR_BGP_PREFIX}\n exit-address-family\nexit\n"
        )
    };
    let dock = &w.dock;
    let start = move |gr: &'static str| {
        let conf = conf(gr);
        async move {
            dock
                .start_plain_caps(
                    "router-f",
                    FRR_IMAGE,
                    NET,
                    IP_G,
                    &[
                        "sh",
                        "-c",
                        "sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start",
                    ],
                    ("/etc/frr", "frr.conf", conf.as_bytes()),
                    &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
                )
                .await
        }
    };
    let a = w.a()?;
    let learned = format!("loc-rib best path for {FRR_BGP_PREFIX} updated");
    let retaining = format!("peer down, retaining routes as stale peer={IP_G}");
    let negotiated = format!("graceful restart negotiated peer={IP_G} ");

    log("FRR with its default graceful restart (helper only): router-a keeps nothing of it");
    start("").await?;
    a.established().await?;
    a.wait(&learned).await?;
    let gone = format!("loc-rib route for {FRR_BGP_PREFIX} withdrawn");
    let (gone_a, neg_a, ret_a) = (a.count(&gone), a.count(&negotiated), a.count(&retaining));
    if neg_a > 0 {
        log(format!(
            "FRR's default capability: {}",
            a.logs.last(&negotiated).unwrap_or_default()
        ));
    }
    w.dock.kill_process("router-f", "bgpd").await?;
    a.wait_new(&gone, gone_a, 60).await?;
    anyhow::ensure!(
        a.count(&retaining) == ret_a,
        "router-a kept routes of a helper-only FRR"
    );

    log("FRR with `bgp graceful-restart`: capability and End-of-RIB both ways");
    let est = a.count("bgp session established");
    start(" bgp graceful-restart\n").await?;
    a.wait_new("bgp session established", est, 90).await?;
    a.wait_new(&format!("{negotiated}.*families=\\[Ipv4Unicast\\]"), 0, 30)
        .await?;
    a.wait(&format!("received end-of-rib peer={IP_G} family=ipv4"))
        .await?;
    a.wait(&learned).await?;
    super::ospf::frr_until(w, &format!("show bgp neighbors {IP_A} json"), 60, |out| {
        out.contains("\"nBitReceived\":true")
            && out.contains("\"remoteGrMode\":\"Restart\"")
            && out.contains("\"endOfRibRecv\":true")
    })
    .await?;

    log("killing FRR's bgpd: router-a keeps its route, then flushes (F=0) or purges after End-of-RIB (F=1)");
    let (ret_a, est) = (a.count(&retaining), a.count("bgp session established"));
    w.dock.kill_process("router-f", "bgpd").await?;
    a.wait_new(&retaining, ret_a, 60).await?;
    a.wait_new("bgp session established", est, 120).await?;
    a.wait_new(
        &format!(
            "flushing stale routes peer={IP_G} .*reason=.*forwarding-not-preserved\\|\
             purged stale routes after end-of-rib peer={IP_G} family=ipv4"
        ),
        0,
        60,
    )
    .await
}

pub async fn auth(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let password = "correct-horse-battery-staple";
    // Baselines first: the matching-password change itself re-establishes the
    // session, and that (delayed) event must not count as a mismatched one.
    let (base_a, base_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    a.provision(&["--md5-password", password]).await?;
    b.provision(&["--md5-password", password]).await?;
    reestablished(a, base_a).await?;
    reestablished(b, base_b).await?;

    let (before_a, before_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    log("reconfiguring router-a with a mismatched md5 password");
    a.provision(&["--md5-password", "wrong-password"]).await?;
    log("waiting 8s to confirm the session does NOT (re-)establish with mismatched md5 passwords");
    a.assert_quiet("bgp session established", before_a, 8)
        .await?;
    if b.count("bgp session established") > before_b {
        bail!("session established despite mismatched md5 passwords");
    }

    log("restoring the matching md5 password on router-a");
    a.provision(&["--md5-password", password]).await?;
    reestablished(a, before_a).await?;

    log("the secret lives in the admin keystore only: not in the config view, not in any log (#508)");
    for r in [a, b] {
        no_leak(r, &[password, "wrong-password"]).await?;
    }

    log("rotating the secret under the same admin label re-establishes the session");
    let rotated = "rotated-horse-battery-staple";
    let (base_a, base_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    for r in [a, b] {
        r.provision(&["--md5-password", rotated]).await?;
    }
    reestablished(a, base_a).await?;
    reestablished(b, base_b).await?;
    for r in [a, b] {
        no_leak(r, &[rotated]).await?;
    }
    Ok(())
}

/// Fails if any of `secrets` shows in the running config as `GET /v1/config`
/// serves it or in the log lines streamed from the daemons (#383, #508).
pub(super) async fn no_leak(r: &Router, secrets: &[&str]) -> anyhow::Result<()> {
    // Let the log follower catch up with anything just emitted.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let config = r.rest_expect(Method::GET, "/v1/config", None, 200).await?;
    for secret in secrets {
        if config.contains(secret) {
            bail!("{}: secret '{secret}' appears in GET /v1/config", r.name());
        }
        if r.count(secret) > 0 {
            bail!("{}: secret '{secret}' appears in the logs", r.name());
        }
    }
    Ok(())
}

fn expect_body(body: &str, needle: &str) -> anyhow::Result<()> {
    if body.contains(needle) {
        Ok(())
    } else {
        bail!("body lacks '{needle}': {body}")
    }
}

/// RFC 5925 TCP-AO: `exclude_options` must match on both sides to establish
/// (changing a kept key's material restarts the session), `TCP_AO_INFO`
/// readback surfaces sane current/rnext key ids, and a real key rollover
/// (add key 2 as rnext, promote it to current, remove key 1) is *hitless*
/// (#83): each step is applied to the live socket in place, the kernel
/// advances `current_key` on the peer's RNextKeyID (§7.5.2), and no session
/// ends or re-establishes throughout. Last, removing the key the peer still
/// signs with is refused by the kernel (`EBUSY`) and falls back to a reset.
pub async fn ao(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let secret = "correct-horse-battery-staple";

    let (base_a, base_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    for r in [a, b] {
        r.provision(&[
            "--ao-send-id",
            "1",
            "--ao-key-secret",
            secret,
            "--ao-current",
        ])
        .await?;
    }
    reestablished(a, base_a).await?;
    reestablished(b, base_b).await?;

    let (before_a, before_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    log("setting exclude-options on router-a only (mismatched with router-b)");
    a.provision(&[
        "--ao-send-id",
        "1",
        "--ao-key-secret",
        secret,
        "--ao-current",
        "--ao-exclude-options",
    ])
    .await?;
    log("waiting 8s to confirm the session does NOT (re-)establish with mismatched TCP-AO exclude-options");
    a.assert_quiet("bgp session established", before_a, 8)
        .await?;
    if b.count("bgp session established") > before_b {
        bail!("session established despite mismatched TCP-AO exclude-options");
    }

    log("matching exclude-options on router-b too");
    b.provision(&[
        "--ao-send-id",
        "1",
        "--ao-key-secret",
        secret,
        "--ao-current",
        "--ao-exclude-options",
    ])
    .await?;
    reestablished(a, before_a).await?;
    reestablished(b, before_b).await?;

    log("checking TCP_AO_INFO readback surfaces key 1 as current on both sides");
    expect_body(
        &a.rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?,
        "\"ao_current_key\":1",
    )?;
    expect_body(
        &b.rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?,
        "\"ao_current_key\":1",
    )?;

    log("rolling over to a second TCP-AO key (RFC 5925 §7.5), expecting no session reset");
    let ended = "outbound bgp session ended\\|inbound bgp session ended";
    let (est_a, est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    let (end_a, end_b) = (a.count(ended), b.count(ended));
    let updated = "bgp tcp-ao keys updated in place";
    let (upd_a, upd_b) = (a.count(updated), b.count(updated));
    for r in [a, b] {
        r.provision(&[
            "--ao-send-id",
            "2",
            "--ao-key-secret",
            "second-secret",
            "--ao-rnext",
            "--ao-exclude-options",
        ])
        .await?;
    }
    a.wait_new(updated, upd_a, 30).await?;
    b.wait_new(updated, upd_b, 30).await?;
    log("waiting for the kernel's RNextKeyID auto-advance: both live sessions sign with key 2");
    for r in [a, b] {
        wait_summary(r, &["\"ao_current_key\":2", "\"ao_rnext_key\":2"], 60).await?;
    }

    for flags in [["--ao-promote-current", "2"], ["--ao-remove-key", "1"]] {
        let (upd_a, upd_b) = (a.count(updated), b.count(updated));
        for r in [a, b] {
            r.provision(&flags).await?;
        }
        a.wait_new(updated, upd_a, 30).await?;
        b.wait_new(updated, upd_b, 30).await?;
    }

    log("checking no session reset happened across the whole rollover");
    for (r, est, end) in [(a, est_a, end_a), (b, est_b, end_b)] {
        r.assert_quiet("bgp session established", est, 3).await?;
        r.assert_quiet(ended, end, 1).await?;
        let body = r
            .rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?;
        expect_body(&body, "\"ao_current_key\":2")?;
        expect_body(&body, "\"ao_packets_bad\":0")?;
    }

    log("re-adding key 1 everywhere, then removing key 2 on router-a only: the peer still signs with it");
    let key1 = [
        "--ao-send-id",
        "1",
        "--ao-key-secret",
        secret,
        "--ao-exclude-options",
    ];
    let (upd_a, upd_b) = (a.count(updated), b.count(updated));
    for r in [a, b] {
        r.provision(&key1).await?;
    }
    a.wait_new(updated, upd_a, 30).await?;
    b.wait_new(updated, upd_b, 30).await?;
    let (est_a, fail_a) = (
        a.count("bgp session established"),
        a.count("failed to update tcp-ao keys in place, resetting session"),
    );
    a.provision(&["--ao-promote-current", "1"]).await?;
    a.provision(&["--ao-remove-key", "2"]).await?;
    a.wait_new(
        "failed to update tcp-ao keys in place, resetting session",
        fail_a,
        30,
    )
    .await?;
    reestablished(a, est_a).await?;

    log("removing key 2 on router-b too: key 1 only, current on both");
    let est_b = b.count("bgp session established");
    let upd_b = b.count(updated);
    b.provision(&["--ao-promote-current", "1"]).await?;
    b.provision(&["--ao-remove-key", "2"]).await?;
    b.wait_new(updated, upd_b, 30).await?;
    b.assert_quiet("bgp session established", est_b, 3).await?;
    for r in [a, b] {
        wait_summary(r, &["\"ao_current_key\":1"], 60).await?;
    }

    log("the secrets live in the admin keystore only: not in the config view, not in any log (#508)");
    for r in [a, b] {
        no_leak(r, &[secret, "second-secret"]).await?;
    }

    log("rotating key 1's secret under the same admin label: material changed, so a fresh session");
    let rotated = "rotated-ao-secret";
    let (est_a, est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    for r in [a, b] {
        r.provision(&[
            "--ao-send-id",
            "1",
            "--ao-key-secret",
            rotated,
            "--ao-current",
            "--ao-exclude-options",
        ])
        .await?;
    }
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;
    for r in [a, b] {
        no_leak(r, &[rotated]).await?;
    }
    Ok(())
}

/// Polls `GET /v1/bgp/summary` until the body holds every needle (the next
/// KEEPALIVE carries the peer's new RNextKeyID, so up to a minute).
async fn wait_summary(r: &Router, needles: &[&str], secs: u64) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        let body = r
            .rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?;
        if needles.iter().all(|n| body.contains(n)) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("{}: summary never held {needles:?}: {body}", r.name());
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// RFC 4456 route reflector: router-a reflects between router-b and router-c,
/// which are not peered with each other.
pub async fn reflector(w: &mut World) -> anyhow::Result<()> {
    let hub = |peer: &str| {
        strings(&[
            "--address",
            &format!("{IP_A}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--peer-group",
            "pg1",
            "--remote-as",
            &ASN_A.to_string(),
            "--peer",
            peer,
            "--route-reflector-client",
            "--cluster-id",
            RID_A,
        ])
    };
    let client = |rid: &str, ip: &str| {
        strings(&[
            "--address",
            &format!("{ip}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            rid,
            "--remote-as",
            &ASN_A.to_string(),
            "--peer",
            IP_A,
        ])
    };
    w.start(A, Some(hub(IP_B)), &[]).await?;
    w.start(B, Some(client(RID_B, IP_B)), &[]).await?;
    w.start(C, Some(client(RID_C, IP_C)), &[]).await?;
    w.a()?.provision_flags(&hub(IP_C)).await?;

    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    for r in [a, b, c] {
        r.established().await?;
    }
    let mut flags = client(RID_B, IP_B);
    flags.extend(strings(&redistribute()));
    b.provision_flags(&flags).await?;
    log("waiting for router-c to learn the prefix purely via the reflector");
    c.wait(&learned()).await?;
    c.wait(&loc_rib()).await
}

/// RFC 7947 route server: router-a relays between two eBGP clients in distinct
/// ASes, transparently (its own ASN is never prepended).
pub async fn route_server(w: &mut World) -> anyhow::Result<()> {
    let hub = |pg: &str, remote_as: u32, peer: &str| {
        strings(&[
            "--address",
            &format!("{IP_A}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--peer-group",
            pg,
            "--remote-as",
            &remote_as.to_string(),
            "--peer",
            peer,
            "--route-server-client",
        ])
    };
    // router-b sets a MED on export, so the hub has a received MED to pass
    // through (RFC 7947 §2.2). Seeded rather than provisioned: a later policy
    // change would restart the session.
    let med_file = policy_file(
        "route-server-med",
        &format!("set this.bgp.med = {MED}\naccept\n"),
    )?;
    let mut b_flags = B.base_flags();
    b_flags.extend(strings(&[
        "--policy-name",
        "route-server-med",
        "--policy-source-file",
        &med_file,
        "--export-policy",
        "route-server-med",
    ]));
    w.start(A, Some(hub("pg-b", ASN_B, IP_B)), &[]).await?;
    w.start(B, Some(b_flags.clone()), &[]).await?;
    w.start(C, None, &[]).await?;
    w.a()?.provision_flags(&hub("pg-c", ASN_C, IP_C)).await?;

    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    for r in [a, b, c] {
        r.established().await?;
    }
    // The policy flags stay: provision_flags replaces the whole flag list.
    b_flags.extend(strings(&redistribute()));
    b.provision_flags(&b_flags).await?;
    log("waiting for router-c to learn the prefix via the route server");
    c.wait(&learned()).await?;
    c.wait(&loc_rib()).await?;

    log("confirming router-c sees router-b's asn but not router-a's — rfc 7947 transparency");
    let line = c.logs.last(&loc_rib()).unwrap_or_default();
    if !line.contains(&format!("as_path=[{ASN_B}]")) || line.contains(&ASN_A.to_string()) {
        bail!("expected as_path [{ASN_B}] with no route-server asn prepended, got: {line}")
    }
    // No `next-hop` is provisioned: the route-server default is `unchanged`
    // (RFC 7947 §2.2.1), so router-c sees router-b's address, not the hub's.
    if !line.contains(&format!("next_hop=Some({IP_B})")) {
        bail!("expected next_hop {IP_B} passed through unchanged, got: {line}")
    }
    log("confirming router-c sees router-b's med — passed through by the route server");
    c.wait(&format!("{} .*med=Some({MED})", loc_rib())).await
}

/// BGP multipath (#70): router-b and router-c, both in `ASN_B`, redistribute
/// the same prefix to router-a (`maximum-paths 2`), whose nos-ribd installs
/// one kernel route over both; a sibling leaving shrinks it without moving
/// the best path, and `maximum-paths 1` turns the sibling into the backup.
pub async fn bgp_multipath(w: &mut World) -> anyhow::Result<()> {
    let hub = |pg: &str, peer: &str, max: &str| {
        strings(&[
            "--address",
            &format!("{IP_A}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--peer-group",
            pg,
            "--remote-as",
            &ASN_B.to_string(),
            "--peer",
            peer,
            "--maximum-paths",
            max,
        ])
    };
    // Same neighbouring AS on both: the strict (non-relaxed) multipath rule.
    let spoke = |ip: &str, rid: &str| {
        strings(&[
            "--address",
            &format!("{ip}/24"),
            "--asn",
            &ASN_B.to_string(),
            "--router-id",
            rid,
            "--remote-as",
            &ASN_A.to_string(),
            "--peer",
            IP_A,
        ])
    };
    let advertising = |ip: &str, rid: &str| {
        let mut f = spoke(ip, rid);
        f.extend(strings(&redistribute()));
        f
    };
    // A router-b/router-c left over from an earlier phase would peer the
    // fresh router-a with its old config before being replaced, and the
    // `loc_rib` baseline below would count its route.
    w.remove(B).await;
    w.remove(C).await;
    w.start(A, Some(hub("pg-b", IP_B, "2")), &[]).await?;
    w.start(B, Some(spoke(IP_B, RID_B)), &[]).await?;
    w.start(C, Some(spoke(IP_C, RID_C)), &[]).await?;
    w.a()?.provision_flags(&hub("pg-c", IP_C, "2")).await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    for r in [b, c] {
        r.established().await?;
    }

    // router-b first, so its path is the older one (decision step 8) and
    // stays best while router-c's comes and goes as the sibling.
    b.provision_flags(&advertising(IP_B, RID_B)).await?;
    a.wait(&loc_rib()).await?;
    let best_moves = a.count(&loc_rib());
    c.provision_flags(&advertising(IP_C, RID_C)).await?;
    let both =
        format!("added route prefix={REDISTRIBUTE_PREFIX} gateway={IP_B},{IP_C} next_hops=2 ");
    log("waiting for router-a to install one kernel route over both next hops");
    a.wait(&both).await?;
    let table = a.routes_walk("rt1", None).await?;
    let gateways = table
        .iter()
        .find(|p| p["prefix"] == REDISTRIBUTE_PREFIX)
        .map(|p| p["candidates"][0]["gateways"].clone());
    if gateways != Some(serde_json::json!([IP_B, IP_C])) {
        bail!("GET /v1/routes/rt1: expected gateways [{IP_B}, {IP_C}], got {gateways:?}");
    }

    log("router-c withdraws: the route shrinks to router-b alone");
    let reject = policy_file("multipath-reject", "reject\n")?;
    let mut withdrawn = advertising(IP_C, RID_C);
    withdrawn.extend(strings(&[
        "--policy-name",
        "multipath-reject",
        "--policy-source-file",
        &reject,
        "--redistribute-policy",
        "multipath-reject",
    ]));
    let one = format!("added route prefix={REDISTRIBUTE_PREFIX} gateway={IP_B} next_hops=1 ");
    let removed = format!("removed route prefix={REDISTRIBUTE_PREFIX} ");
    let (base, base_removed) = (a.count(&one), a.count(&removed));
    c.provision_flags(&withdrawn).await?;
    a.wait_new(&one, base, 60).await?;
    // The shrink replaced the route in place: nothing was removed (#598).
    a.assert_quiet(&removed, base_removed, 5).await?;

    log("router-c advertises again: both next hops are back");
    let base = a.count(&both);
    c.provision_flags(&advertising(IP_C, RID_C)).await?;
    a.wait_new(&both, base, 60).await?;
    if a.count(&loc_rib()) != best_moves {
        bail!("router-a's best path moved while only the multipath sibling changed");
    }

    log("maximum-paths 1: router-b's next hop alone, router-c's as the backup");
    let backup = format!(
        "added route prefix={REDISTRIBUTE_PREFIX} gateway={IP_C} next_hops=1 .*backup=true"
    );
    let (base_one, base_backup) = (a.count(&one), a.count(&backup));
    a.provision_flags(&hub("pg-c", IP_C, "1")).await?;
    a.wait_new(&one, base_one, 60).await?;
    a.wait_new(&backup, base_backup, 60).await
}

/// An import policy on router-b rejecting the redistributed prefix, then reverted.
pub async fn policy(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let before = b.count(&learned());
    let (est_a, est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    let file = policy_file(
        "reject-redistribute-prefix",
        // Neighbor context (`peer_as`) and an as-path regex, on a real
        // session: router-a's route arrives with the path [ASN_A] from ASN_A.
        &format!(
            "if this.bgp.peer_as == {ASN_A} and this.bgp.as_path.matches(\"^{ASN_A}$\") and this.bgp.med == 0 and this.bgp.first_as == {ASN_A} and this.bgp.neighbor_as == {ASN_A} and this.bgp.origin_as == {ASN_A} and this.bgp.as_path.path_length == 1 and this.bgp.next_hop in {SUBNET}:\n    reject\nelse:\n    accept\n"
        ),
    )?;
    b.provision(&[
        "--policy-name",
        "reject-redistribute-prefix",
        "--policy-source-file",
        &file,
        "--import-policy",
        "reject-redistribute-prefix",
    ])
    .await?;
    // A genuinely new session: provisioning `redistribute` on router-a while
    // router-b's is still coming back up leaves both Idle on a retry timer.
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;

    a.provision(&redistribute()).await?;
    a.wait(&loc_rib()).await?;
    log("waiting 6s to confirm router-b's import policy rejects the prefix");
    b.assert_quiet(&learned(), before, 6).await?;

    log("reverting router-b's import policy to the accept-all default");
    let after = b.count(&learned());
    b.provision::<&str>(&[]).await?;
    b.wait_new(&learned(), after, 60).await?;
    soft_reconfig(w).await?;
    as_set_export_policy(w).await?;
    call_chain(w).await
}

/// #870: `call NAME` composes two stored policies. Router-b's import policy
/// calls a callee that rejects (route not learned), then one that accepts
/// (route learned); a call cycle is refused at commit.
async fn call_chain(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    for (callee, verdict, entry) in [
        ("chain-filter-reject", "reject", "chain-entry-reject"),
        ("chain-filter-accept", "accept", "chain-entry-accept"),
    ] {
        log(format!("call chain: {entry} calls {callee} ({verdict})"));
        // Defined through a bare edit: it touches no peering config, so no
        // session restart lands after the baseline below.
        b.edit(|c| {
            c.policy_definitions.push(nos_proto::PolicyDefinition {
                name: callee.into(),
                source: format!("{verdict}\n"),
            });
            Ok(())
        })
        .await?;
        let entry_file = policy_file(
            entry,
            &format!("call {callee}\nset this.bgp.local_pref = 150\naccept\n"),
        )?;
        let before = b.count(&learned());
        let (est_a, est_b) = (
            a.count("bgp session established"),
            b.count("bgp session established"),
        );
        b.provision(&[
            "--policy-name",
            entry,
            "--policy-source-file",
            &entry_file,
            "--import-policy",
            entry,
        ])
        .await?;
        reestablished(a, est_a).await?;
        reestablished(b, est_b).await?;
        if verdict == "reject" {
            b.assert_quiet(&learned(), before, 6).await?;
        } else {
            b.wait_new(&learned(), before, 60).await?;
        }
    }

    log("call chain: a call cycle is refused at commit");
    let err = b
        .edit(|c| {
            for (name, other) in [("cycle-a", "cycle-b"), ("cycle-b", "cycle-a")] {
                c.policy_definitions.push(nos_proto::PolicyDefinition {
                    name: name.into(),
                    source: format!("call {other}\naccept\n"),
                });
            }
            Ok(())
        })
        .await
        .expect_err("a call cycle must be rejected");
    anyhow::ensure!(
        format!("{err:#}").contains("cycle"),
        "unexpected rejection: {err:#}"
    );

    log("call chain: restoring router-b's accept-all import policy");
    let before = b.count(&learned());
    b.provision::<&str>(&[]).await?;
    b.wait_new(&learned(), before, 60).await
}

/// Turns router-b's `soft-reconfiguration-inbound` on or off through the
/// config tree (`nos-provision` only ever enables it).
async fn set_soft_reconfig(r: &Router, enabled: bool) -> anyhow::Result<()> {
    r.edit(|config| {
        BgpPeerGroupOp::SetSoftReconfigurationInbound {
            instance: "r1".into(),
            name: "pg1".into(),
            enabled,
        }
        .apply(config)
        .map_err(|e| anyhow::anyhow!("{e}"))
    })
    .await
    .map(drop)
}

/// #859: soft reconfiguration inbound against a Route-Refresh-capable peer
/// (router-a). Enabling on the live session asks for a refresh instead of
/// restarting it; an import-policy change is then re-evaluated from the
/// retained routes (no new session, no new refresh); disabling frees them.
async fn soft_reconfig(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let flag = ["--soft-reconfiguration-inbound"];
    let (est_a, est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    let (enabled, refresh) = (
        b.count("soft reconfiguration: retention enabled"),
        b.count("sent route refresh request"),
    );
    log("soft reconfiguration: enabling on router-b's live session");
    b.provision(&flag).await?;
    b.wait_new("soft reconfiguration: retention enabled", enabled, 30)
        .await?;
    b.wait_new("sent route refresh request", refresh, 30)
        .await?;
    b.assert_quiet("bgp session established", est_b, 6).await?;
    a.assert_quiet("bgp session established", est_a, 1).await?;

    log("tightening router-b's import policy: re-evaluated in place, route rejected");
    let file = policy_file(
        "reject-soft-reconfig",
        &format!(
            "if this.bgp.peer_as == {ASN_A} and this.bgp.as_path.matches(\"^{ASN_A}$\") and this.bgp.med == 0 and this.bgp.first_as == {ASN_A} and this.bgp.neighbor_as == {ASN_A} and this.bgp.origin_as == {ASN_A} and this.bgp.as_path.path_length == 1 and this.bgp.next_hop in {SUBNET}:\n    reject\nelse:\n    accept\n"
        ),
    )?;
    let reeval = |accepted: u32| {
        format!(
            "re-evaluated import policy peer={IP_A} family=ipv4-unicast retained=[0-9]* accepted={accepted} "
        )
    };
    let (rejected, refresh) = (b.count(&reeval(0)), b.count("sent route refresh request"));
    let mut tight = strings(&flag);
    tight.extend(strings(&[
        "--policy-name",
        "reject-soft-reconfig",
        "--policy-source-file",
        &file,
        "--import-policy",
        "reject-soft-reconfig",
    ]));
    b.provision(&tight).await?;
    b.wait_new(&reeval(0), rejected, 30).await?;
    b.assert_quiet("bgp session established", est_b, 6).await?;

    log("loosening it again: the retained copy re-admits the route, no new refresh");
    let (learned_before, accepted) = (b.count(&learned()), b.count(&reeval(1)));
    b.provision(&flag).await?;
    b.wait_new(&learned(), learned_before, 30).await?;
    b.wait_new(&reeval(1), accepted, 30).await?;
    b.assert_quiet("bgp session established", est_b, 6).await?;
    b.assert_quiet("sent route refresh request", refresh, 3)
        .await?;

    log("`soft-in` re-evaluates locally and sends nothing");
    let body = b
        .rest_expect(
            Method::POST,
            &format!("/v1/bgp/r1/peer/{IP_A}/soft-in"),
            None,
            200,
        )
        .await?;
    anyhow::ensure!(
        body.contains("\"route_refresh\":\"none\"") && body.contains("ipv4-unicast"),
        "soft-in reply: {body}"
    );
    b.assert_quiet("sent route refresh request", refresh, 2)
        .await?;

    log("disabling frees the retained routes without a restart");
    let disabled = b.count("soft reconfiguration: retention disabled");
    set_soft_reconfig(b, false).await?;
    b.wait_new("soft reconfiguration: retention disabled", disabled, 30)
        .await?;
    b.assert_quiet("bgp session established", est_b, 3).await
}

/// #859 against FRR without Route Refresh (`router-f`, self-contained):
/// `dont-capability-negotiate` makes FRR send a capability-less OPEN, so
/// router-a cannot ask it to resend. With `soft-reconfiguration-inbound` the
/// route FRR announced is still retained when router-a's import policy
/// rejects it, and loosening the policy re-admits it locally, with no new
/// session and no refresh. Enabling the flag on a live no-refresh session is
/// the one case that must restart it.
pub async fn soft_reconfig_frr(w: &mut World) -> anyhow::Result<()> {
    let seed = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
    ]);
    let file = policy_file("reject-frr-prefix", "reject\n")?;
    let mut tight = seed.clone();
    tight.extend(strings(&[
        "--soft-reconfiguration-inbound",
        "--policy-name",
        "reject-frr-prefix",
        "--policy-source-file",
        &file,
        "--import-policy",
        "reject-frr-prefix",
    ]));
    w.start(A, Some(tight), &[]).await?;
    w.dock.container_remove("router-g").await;
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    let conf = format!(
        "frr defaults traditional\nhostname router-f\n!\n\
         router bgp {ASN_G}\n bgp router-id {RID_G}\n no bgp ebgp-requires-policy\n \
         no bgp network import-check\n neighbor {IP_A} remote-as {ASN_A}\n \
         neighbor {IP_A} dont-capability-negotiate\n \
         address-family ipv4 unicast\n  network {FRR_BGP_PREFIX}\n exit-address-family\nexit\n"
    );
    w.dock
        .start_plain_caps(
            "router-f",
            FRR_IMAGE,
            NET,
            IP_G,
            &[
                "sh",
                "-c",
                "sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start",
            ],
            ("/etc/frr", "frr.conf", conf.as_bytes()),
            &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        )
        .await?;
    let a = w.a()?;
    let learned_frr = format!("learned route for {FRR_BGP_PREFIX} into adj-rib-in");
    let reeval = |accepted: u32| {
        format!(
            "re-evaluated import policy peer={IP_G} family=ipv4-unicast retained=[0-9]* accepted={accepted} "
        )
    };

    a.established().await?;
    a.wait(&format!(
        "route refresh capability peer={IP_G} route_refresh=false"
    ))
    .await?;
    super::ospf::frr_until(w, &format!("show bgp neighbors {IP_A} json"), 60, |out| {
        // FRR's `routeRefresh` is "received" (ours reached it); it never
        // "advertised" one, which is what leaves router-a unable to ask.
        out.contains("\"bgpState\":\"Established\"")
            && out.contains("\"routeRefresh\":\"received\"")
            && !out.contains("\"routeRefresh\":\"advertised")
    })
    .await?;

    log("import policy rejects FRR's prefix: not learned, yet retained");
    a.assert_quiet(&learned_frr, 0, 10).await?;
    let body = a
        .rest_expect(
            Method::POST,
            &format!("/v1/bgp/r1/peer/{IP_G}/soft-in"),
            None,
            200,
        )
        .await?;
    anyhow::ensure!(
        body.contains("\"route_refresh\":\"none\"")
            && body.contains("\"retained\":1,\"accepted\":0"),
        "soft-in on a peer without route refresh: {body}"
    );

    log("loosening the policy re-admits it from the retained copy: same session, no refresh");
    let (est, accepted) = (a.count("bgp session established"), a.count(&reeval(1)));
    let mut loose = seed;
    loose.push("--soft-reconfiguration-inbound".into());
    a.provision_flags(&loose).await?;
    a.wait_new(&learned_frr, 0, 30).await?;
    a.wait_new(&reeval(1), accepted, 30).await?;
    a.assert_quiet("bgp session established", est, 6).await?;
    a.assert_quiet("route refresh not sent", 0, 1).await?;

    log("disabling is in place; enabling on a peer without route refresh restarts the session");
    set_soft_reconfig(a, false).await?;
    a.wait_new("soft reconfiguration: retention disabled", 0, 30)
        .await?;
    a.assert_quiet("bgp session established", est, 5).await?;
    let seen = a.count(&learned_frr);
    set_soft_reconfig(a, true).await?;
    a.wait_new("bgp session established", est, 90).await?;
    a.wait_new(&learned_frr, seen, 60).await
}

/// Router-a's aggregate flags with the named export policy.
fn flags<'a>(name: &'a str, file: &'a str) -> Vec<&'a str> {
    let mut f = redistribute();
    f.extend([
        "--aggregate-address",
        AGGREGATE_PREFIX,
        "--aggregate-as-set",
        "--policy-name",
        name,
        "--policy-source-file",
        file,
        "--export-policy",
        name,
    ]);
    f
}

/// #667: an export policy sees the AS_SET as `{ASN_B}`, not a flat `ASN_B`.
/// Router-a's `as-set` aggregate carries `AS_SET {ASN_B}`; router-b drops it
/// (own ASN in the path) only if router-a exported it, which is the signal.
async fn as_set_export_policy(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let looped = "dropping bgp update: as_path already contains our own asn";
    log("as-set export policy: router-b gets a second /24, router-a aggregates with as-set");
    let learned_b = format!("learned route for {AGGREGATE_CONTRIBUTOR_B} into adj-rib-in");
    let a_learned = a.count(&learned_b);
    b.provision(&[
        "--static-route",
        AGGREGATE_CONTRIBUTOR_B,
        "--static-gateway",
        REDISTRIBUTE_GATEWAY,
        "--redistribute",
    ])
    .await?;
    a.wait_new(&learned_b, a_learned, 30).await?;
    let (positive, negative) = (
        policy_file(
            "set-segment-match",
            &format!(
                "if this.bgp.as_path.matches(\"^\\{{{ASN_B}\\}}$\"):\n    accept\nelse:\n    reject\n"
            ),
        )?,
        policy_file(
            "set-flat-match",
            &format!("if this.bgp.as_path.matches(\"^{ASN_B}$\"):\n    accept\nelse:\n    reject\n"),
        )?,
    );

    log("export policy matching the segment form `{ASN_B}` lets the aggregate out");
    let loop_before = b.count(looped);
    a.provision(&flags("set-segment-match", &positive)).await?;
    b.wait_new(looped, loop_before, 60).await?;

    log("export policy matching the flat form `ASN_B` must not match the set member");
    let (est_a, est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    let loop_before = b.count(looped);
    a.provision(&flags("set-flat-match", &negative)).await?;
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;
    log("waiting 6s to confirm the aggregate is not exported");
    b.assert_quiet(looped, loop_before, 6).await?;

    log("restoring the baseline");
    a.provision(&redistribute()).await?;
    let mut restore = redistribute();
    restore.extend(["--remove-static-route", AGGREGATE_CONTRIBUTOR_B]);
    b.provision(&restore).await
}

/// A policy on router-a's own `redistribute` rule: filtering must happen at the
/// redistribution point, before router-a's own loc-rib.
pub async fn redistribute_policy(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let (before_a, before_b) = (a.count(&loc_rib()), b.count(&learned()));
    let file = policy_file(
        "reject-at-redistribute",
        &format!("if this.prefix in {REDISTRIBUTE_PREFIX}:\n    reject\nelse:\n    accept\n"),
    )?;
    let mut flags = redistribute();
    flags.extend([
        "--policy-name",
        "reject-at-redistribute",
        "--policy-source-file",
        &file,
        "--redistribute-policy",
        "reject-at-redistribute",
    ]);
    a.provision(&flags).await?;
    log("waiting 6s to confirm the redistribute policy filters the prefix at the source");
    tokio::time::sleep(Duration::from_secs(6)).await;
    let (after_a, after_b) = (a.count(&loc_rib()), b.count(&learned()));
    if after_a > before_a {
        bail!("router-a installed the prefix into its own loc-rib despite its redistribute policy");
    }
    if after_b > before_b {
        bail!("router-b learned the prefix despite router-a's redistribute policy");
    }

    log("reverting router-a's redistribute rule to accept-all (no policy)");
    a.provision(&redistribute()).await?;
    a.wait_new(&loc_rib(), after_a, 60).await?;
    b.wait_new(&learned(), after_b, 60).await
}

/// RFC 4271 §9.1.2 next-hop feasibility. Requires `ospf-spf` to have run:
/// router-b's loopback (`OSPF_SPF_LOOPBACK_ADDRESS`) exists but is out of OSPF
/// again, so router-a has no route to it. Router-b advertises `NHR_PREFIX` with
/// that loopback as NEXT_HOP (an export policy): router-a must see the
/// candidate and exclude it, then admit it once the loopback is back in OSPF
/// and its own SPF route makes the next hop resolvable — with no BGP event in
/// between, purely off the IGP poll. First checks that nos-ribd lists
/// router-a's own connected prefixes (its eth0 subnet and its ospf SVI's) as
/// `Connected` — what makes a directly-connected next hop resolvable at all.
/// The kernel side of the accepted route (a gateway that is itself only
/// reachable via another route — Linux has no recursive next hops) is out of
/// scope here.
pub async fn next_hop_reachability(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);

    for subnet in [SUBNET, OSPF_BROADCAST_SUBNET] {
        a.wait_connected(subnet).await?;
    }

    let next_hop = OSPF_SPF_LOOPBACK_ADDRESS
        .split('/')
        .next()
        .unwrap_or_default();
    let file = policy_file(
        "next-hop-loopback",
        &format!("set this.bgp.next_hop = {next_hop}\naccept\n"),
    )?;
    // Two commits: the export policy alone first (it restarts the session),
    // then the prefix. In one commit, nos-ribd's redistribution push can
    // reach the old session before the restart and announce the prefix under
    // the previous policy, with router-b's own (resolvable) address (#159).
    let policy = vec![
        "--policy-name",
        "next-hop-loopback",
        "--policy-source-file",
        &file,
        "--export-policy",
        "next-hop-loopback",
    ];
    let mut advertise = policy.clone();
    advertise.extend([
        "--static-route",
        NHR_PREFIX,
        "--static-gateway",
        REDISTRIBUTE_GATEWAY,
        "--redistribute",
    ]);
    let mut with_ospf = advertise.clone();
    with_ospf.extend(["--ospf-loopback-profile", OSPF_PROFILE]);
    let mut withdraw = advertise.clone();
    withdraw.extend([
        "--redistribute-policy",
        "deny-all",
        "--clear-ospf-loopback-profile",
    ]);

    let excluded = format!("candidate excluded, next hop unresolvable.*prefix={NHR_PREFIX}");
    let loc = format!("loc-rib best path for {NHR_PREFIX} updated");
    let via_loopback = format!("{loc}.*next_hop=Some({next_hop})");
    let (ex0, loc0, via0) = (a.count(&excluded), a.count(&loc), a.count(&via_loopback));
    let (est_a, est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    b.provision(&policy).await?;
    // A new export policy restarts router-b's session.
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;
    // Same policy, so no restart: the first UPDATE already carries the loopback.
    b.provision(&advertise).await?;
    a.wait(&format!("learned route for {NHR_PREFIX} into adj-rib-in"))
        .await?;
    a.wait_new(&excluded, ex0, 60).await?;
    log("waiting 6s to confirm router-a keeps the unfeasible route out of its loc-rib");
    a.assert_quiet(&loc, loc0, 6).await?;

    log("putting router-b's loopback back into ospf: the next hop becomes resolvable via spf");
    let route = format!("added route prefix={OSPF_SPF_LOOPBACK_ADDRESS}.*source=Some(Ospf)");
    let r0 = a.count(&route);
    b.provision(&with_ospf).await?;
    a.wait_new(&route, r0, 60).await?;
    a.wait_new(&via_loopback, via0, 60).await?;

    log("withdrawing the prefix and taking router-b's loopback out of ospf again");
    let withdrawn = format!("loc-rib route for {NHR_PREFIX} withdrawn");
    let w0 = a.count(&withdrawn);
    b.provision(&withdraw).await?;
    a.wait_new(&withdrawn, w0, 60).await?;

    log("#670: an unconditional IPv4 next-hop literal on an ipv6 group is rejected at commit");
    let err = a
        .edit(|c| {
            c.policy_definitions.push(nos_proto::PolicyDefinition {
                name: "v4-next-hop".into(),
                source: "set this.bgp.next_hop = 192.0.2.1\naccept\n".into(),
            });
            for g in c
                .bgp_instances
                .iter_mut()
                .flat_map(|i| i.peer_groups.iter_mut())
            {
                g.address_families
                    .push(nos_proto::AddressFamily::Ipv6Unicast);
                g.export_policy = Some("v4-next-hop".into());
            }
            Ok(())
        })
        .await
        .expect_err("commit must be rejected");
    anyhow::ensure!(
        format!("{err:#}").contains("IPv4"),
        "unexpected rejection: {err:#}"
    );

    // `ospf-lfa` puts the loopback back next and waits for a *new* install,
    // which never comes if the route is still up.
    a.wait_ospf_route_gone(OSPF_SPF_LOOPBACK_ADDRESS, 15).await
}

/// RFC 4271 §9.2.1.1 pacing: with `mrai 30` on router-a's peer-group, the first
/// advertisement of the prefix goes out at once, a withdrawal is never held,
/// and a re-advertisement seconds later is held until 30s after the first.
/// Flapped through router-a's redistribute policy, like `redistribute-policy`.
pub async fn mrai(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let withdrawn = format!("loc-rib route for {REDISTRIBUTE_PREFIX} withdrawn");
    let file = policy_file(
        "reject-for-mrai",
        &format!("if this.prefix in {REDISTRIBUTE_PREFIX}:\n    reject\nelse:\n    accept\n"),
    )?;
    let mut accept = redistribute();
    accept.extend(["--mrai", "30"]);
    let mut reject = accept.clone();
    reject.extend([
        "--policy-name",
        "reject-for-mrai",
        "--policy-source-file",
        &file,
        "--redistribute-policy",
        "reject-for-mrai",
    ]);

    // A new mrai restarts the session, so the first advertisement is a fresh one.
    let (est, learned_before) = (a.count("bgp session established"), b.count(&learned()));
    a.provision(&accept).await?;
    reestablished(a, est).await?;
    b.wait_new(&learned(), learned_before, 60).await?;

    log("withdrawing the prefix: must reach router-b at once, not after the mrai");
    let withdrawn_before = b.count(&withdrawn);
    a.provision(&reject).await?;
    b.wait_new(&withdrawn, withdrawn_before, 10).await?;

    log("re-advertising the prefix: must be held back until the mrai elapses");
    let learned_before = b.count(&learned());
    a.provision(&accept).await?;
    b.assert_quiet(&learned(), learned_before, 8).await?;
    b.wait_new(&learned(), learned_before, 40).await
}

/// RFC 2439 flap damping: router-a damps what it receives from router-b
/// (half-life 20s, suppress 2000, reuse 750). Router-b flaps its redistributed
/// prefix three times (via its redistribute policy) -> router-a suppresses it,
/// so a fourth announcement reaches adj-rib-in but never loc-rib, until the
/// penalty decays below reuse and the route is released.
pub async fn damping(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let withdrawn = format!("loc-rib route for {REDISTRIBUTE_PREFIX} withdrawn");
    let file = policy_file(
        "reject-for-damping",
        &format!("if this.prefix in {REDISTRIBUTE_PREFIX}:\n    reject\nelse:\n    accept\n"),
    )?;
    let accept = redistribute();
    let mut reject = accept.clone();
    reject.extend([
        "--policy-name",
        "reject-for-damping",
        "--policy-source-file",
        &file,
        "--redistribute-policy",
        "reject-for-damping",
    ]);

    // Earlier phases leave router-a redistributing the same prefix, and its own
    // `Local` copy outranks router-b's in best-path: router-b's flaps would then
    // never reach router-a's Loc-RIB. Reject it at router-a's source for the phase.
    let mut a_damped = reject.clone();
    a_damped.extend([
        "--damping-half-life",
        "20",
        "--damping-reuse",
        "750",
        "--damping-suppress",
        "2000",
        "--damping-max-suppress",
        "40",
    ]);
    let (est, own_withdrawn) = (a.count("bgp session established"), a.count(&withdrawn));
    a.provision(&a_damped).await?;
    reestablished(a, est).await?;
    a.wait_new(&withdrawn, own_withdrawn, 30).await?;

    log("flapping router-b's prefix three times: router-a must suppress it");
    let suppressed = format!("route suppressed by flap damping.*{REDISTRIBUTE_PREFIX}");
    let suppressed_before = a.count(&suppressed);
    for _ in 0..3 {
        let learned_before = a.count(&learned());
        b.provision(&accept).await?;
        a.wait_new(&learned(), learned_before, 30).await?;
        let withdrawn_before = a.count(&withdrawn);
        b.provision(&reject).await?;
        a.wait_new(&withdrawn, withdrawn_before, 30).await?;
    }
    a.wait_new(&suppressed, suppressed_before, 10).await?;

    log("announcing it again: learned into adj-rib-in, but held out of loc-rib");
    let (learned_before, loc_before) = (a.count(&learned()), a.count(&loc_rib()));
    b.provision(&accept).await?;
    a.wait_new(&learned(), learned_before, 30).await?;
    a.assert_quiet(&loc_rib(), loc_before, 8).await?;

    log("waiting for the penalty to decay below reuse: the route must be released");
    a.wait_new(
        &format!("route released from flap damping.*{REDISTRIBUTE_PREFIX}"),
        0,
        90,
    )
    .await?;
    a.wait_new(&loc_rib(), loc_before, 10).await?;

    log("removing damping from router-a's peer-group, redistributing its prefix again");
    let est = a.count("bgp session established");
    let mut a_restored = accept.clone();
    a_restored.push("--clear-damping");
    a.provision(&a_restored).await?;
    reestablished(a, est).await
}

/// RFC 4271 §9.2.2.2 aggregation on router-a over its own redistributed
/// `REDISTRIBUTE_PREFIX` and a static router-b redistributes for the phase
/// (router-b stops redistributing `REDISTRIBUTE_PREFIX` meanwhile, so the
/// only copy it has is router-a's): the aggregate with ATOMIC_AGGREGATE +
/// AGGREGATOR, then `as-set` (router-b sees its own ASN and drops the route
/// as a loop, which withdraws the earlier copy), then `summary-only` (router-b
/// loses router-a's /24), then removal. Restores router-b's state after.
pub async fn aggregate(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let loc_rib = |p: &str| format!("loc-rib best path for {p} updated");
    let withdrawn = |p: &str| format!("loc-rib route for {p} withdrawn");
    let learned_b = format!("learned route for {AGGREGATE_CONTRIBUTOR_B} into adj-rib-in");
    let learned_agg = format!("learned route for {AGGREGATE_PREFIX} into adj-rib-in");
    let a_flags = |extra: &[&'static str]| {
        let mut f = redistribute();
        f.extend(["--aggregate-address", AGGREGATE_PREFIX]);
        f.extend(extra);
        f
    };

    log("router-b: redistribute a second /24, stop redistributing its own copy of router-a's");
    let (a_learned, b_loc) = (a.count(&learned_b), b.count(&loc_rib(REDISTRIBUTE_PREFIX)));
    b.provision(&[
        "--static-route",
        AGGREGATE_CONTRIBUTOR_B,
        "--static-gateway",
        REDISTRIBUTE_GATEWAY,
        "--redistribute",
        "--remove-static-route",
        REDISTRIBUTE_PREFIX,
    ])
    .await?;
    a.wait_new(&learned_b, a_learned, 30).await?;
    b.wait_new(&loc_rib(REDISTRIBUTE_PREFIX), b_loc, 30).await?;

    log("router-a: aggregate-address, with ATOMIC_AGGREGATE and AGGREGATOR");
    // Both contributors are already in the Loc-RIB: the config change's seed
    // scan activates it with two at once.
    let activated = format!("aggregate activated aggregate={AGGREGATE_PREFIX} contributors=2 ");
    let (act, learned) = (a.count(&activated), b.count(&learned_agg));
    a.provision(&a_flags(&[])).await?;
    a.wait_new(&activated, act, 30).await?;
    b.wait_new(
        &format!(
            "{learned_agg} peer={IP_A} .*atomic_aggregate=true aggregator=Some(({ASN_A}, {RID_A}))"
        ),
        learned,
        30,
    )
    .await?;

    log("as-set: router-b sees its own ASN in the AS_SET and drops (withdraws) the aggregate");
    let a_set = format!(
        "{} origin=Local as_path=\\[{{{ASN_B}}}\\]",
        loc_rib(AGGREGATE_PREFIX)
    );
    let looped = "dropping bgp update: as_path already contains our own asn";
    let (set_before, loop_before, wd_before) = (
        a.count(&a_set),
        b.count(looped),
        b.count(&withdrawn(AGGREGATE_PREFIX)),
    );
    a.provision(&a_flags(&["--aggregate-as-set"])).await?;
    a.wait_new(&a_set, set_before, 30).await?;
    b.wait_new(looped, loop_before, 30).await?;
    b.wait_new(&withdrawn(AGGREGATE_PREFIX), wd_before, 30)
        .await?;

    log("summary-only: router-b gets the aggregate back and loses the /24 under it");
    let (learned, wd_before) = (
        b.count(&learned_agg),
        b.count(&withdrawn(REDISTRIBUTE_PREFIX)),
    );
    a.provision(&a_flags(&["--aggregate-summary-only"])).await?;
    b.wait_new(&learned_agg, learned, 30).await?;
    b.wait_new(&withdrawn(REDISTRIBUTE_PREFIX), wd_before, 30)
        .await?;

    log("removing the aggregate: router-b loses it and learns the /24 again");
    let (wd_before, loc_before) = (
        b.count(&withdrawn(AGGREGATE_PREFIX)),
        b.count(&loc_rib(REDISTRIBUTE_PREFIX)),
    );
    let mut remove = redistribute();
    remove.extend(["--remove-aggregate-address", AGGREGATE_PREFIX]);
    a.provision(&remove).await?;
    b.wait_new(&withdrawn(AGGREGATE_PREFIX), wd_before, 30)
        .await?;
    b.wait_new(&loc_rib(REDISTRIBUTE_PREFIX), loc_before, 30)
        .await?;

    log("router-b: back to redistributing its own copy of the /24 alone");
    let gone = withdrawn(AGGREGATE_CONTRIBUTOR_B);
    let gone_before = a.count(&gone);
    let mut restore = redistribute();
    restore.extend(["--remove-static-route", AGGREGATE_CONTRIBUTOR_B]);
    b.provision(&restore).await?;
    a.wait_new(&gone, gone_before, 30).await
}

/// RFC 4486 / RFC 9003 administrative shutdown: shutting router-a's peer-group,
/// then its one peer alone, must send router-b a Cease/Administrative Shutdown
/// carrying the operator's message, and keep the session down (router-b keeps
/// dialling, router-a refuses) until it is cleared; removing the peer from
/// router-a's config must send Cease/Peer De-configured.
pub async fn shutdown(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let sent =
        |subcode: u8| format!("sent cease notification peer=.* subcode={subcode} hard_reset=true");
    // RFC 8538: graceful restart (on by default) exchanged N, so each Cease
    // goes out as a Hard Reset wrapping it (§5.1), logged with the inner one.
    let received = |subcode: u8, msg: &str| {
        format!(
            "received notification peer=.* code=6 subcode=9 hard_reset_code=6 \
             hard_reset_subcode={subcode} shutdown_message=.*{msg}"
        )
    };
    let rejected = "rejecting inbound tcp connection from administratively shut peer";

    for (what, set, clear, msg) in [
        (
            "peer-group",
            "--shutdown-peer-group",
            "--unshutdown-peer-group",
            "group maintenance",
        ),
        (
            "peer",
            "--shutdown-peer",
            "--unshutdown-peer",
            "peer maintenance",
        ),
    ] {
        log(format!("shutting router-a's {what} with a message"));
        let (sent_before, recv_before, est_b, rej_before) = (
            a.count(&sent(2)),
            b.count(&received(2, msg)),
            b.count("bgp session established"),
            a.count(rejected),
        );
        a.provision(&[set, msg]).await?;
        a.wait_new(&sent(2), sent_before, 20).await?;
        b.wait_new(&received(2, msg), recv_before, 20).await?;
        // The session stays down: router-b keeps dialling, router-a refuses.
        a.wait_new(rejected, rej_before, 20).await?;
        b.assert_quiet("bgp session established", est_b, 10).await?;

        log(format!("clearing the {what} shutdown"));
        let (est_a, est_b) = (
            a.count("bgp session established"),
            b.count("bgp session established"),
        );
        a.provision(&[clear]).await?;
        reestablished(a, est_a).await?;
        reestablished(b, est_b).await?;
    }

    log("removing the peer from router-a's config: Cease / Peer De-configured");
    let recv_before = b.count(&received(3, ""));
    let est_b = b.count("bgp session established");
    a.edit(|config| {
        for instance in &mut config.bgp_instances {
            instance.peers.clear();
        }
        Ok(())
    })
    .await?;
    b.wait_new(&received(3, ""), recv_before, 20).await?;
    // The base flags upsert the peer again.
    a.provision::<&str>(&[]).await?;
    reestablished(b, est_b).await
}

/// RFC 7999 (#861): router-a tags two /32s with BLACKHOLE; router-b's
/// `blackhole` prefix-list covers only one, which `nos-ribd` installs as a
/// discard (`RTN_BLACKHOLE`) route. The other stays an ordinary route, and
/// dropping the config turns the discard back into a normal route.
/// (NO_EXPORT on the stored route is proven by the unit tests: the lab
/// has no third eBGP peer in this phase.)
pub async fn blackhole(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let discard = |p: &str| format!("added route prefix={p} .*discard=true");
    let (est_a, est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    let before = b.count(&discard(BLACKHOLE_COVERED));
    let before_other = b.count(&discard(BLACKHOLE_UNCOVERED));
    let file = policy_file(
        "tag-blackhole",
        "this.bgp.communities.add(65535:666)\naccept\n",
    )?;
    a.provision(&[
        "--static-route",
        BLACKHOLE_COVERED,
        "--static-route",
        BLACKHOLE_UNCOVERED,
        "--static-gateway",
        REDISTRIBUTE_GATEWAY,
        "--redistribute",
        "--policy-name",
        "tag-blackhole",
        "--policy-source-file",
        &file,
        "--export-policy",
        "tag-blackhole",
    ])
    .await?;
    b.provision(&[
        "--blackhole-prefix-list",
        "bh",
        "--blackhole-prefix",
        BLACKHOLE_NET,
    ])
    .await?;
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;

    log("router-b installs the covered /32 as a discard route");
    b.wait_new(&discard(BLACKHOLE_COVERED), before, 60).await?;
    // The uncovered one is learned (as an ordinary route) but never a discard.
    b.wait(&format!(
        "learned route for {BLACKHOLE_UNCOVERED} into adj-rib-in"
    ))
    .await?;
    b.assert_quiet(&discard(BLACKHOLE_UNCOVERED), before_other, 10)
        .await?;
    // `show rib` over REST names it a BGP blackhole.
    let rib = b
        .rest_expect(Method::GET, "/v1/routes/rt1", None, 200)
        .await?;
    anyhow::ensure!(
        rib.contains("\"blackhole\":true"),
        "show rib does not report blackhole: {rib}"
    );

    log("router-b drops the blackhole config: the discard becomes an ordinary route");
    // The kernel slot flips from blackhole to the peer's gateway in place
    // (`replaced=true`), so the proof is the ordinary route, not a removal.
    let ordinary = format!(
        "added route prefix={BLACKHOLE_COVERED} gateway={IP_A} .*source=Some(Bgp) backup=false discard=false"
    );
    let before_ordinary = b.count(&ordinary);
    b.provision(&["--clear-blackhole"]).await?;
    b.wait_new(&ordinary, before_ordinary, 60).await?;

    log("restoring the baseline");
    a.provision(&[
        "--remove-static-route",
        BLACKHOLE_COVERED,
        "--remove-static-route",
        BLACKHOLE_UNCOVERED,
    ])
    .await?;
    Ok(())
}

/// An export policy tagging the prefix with an RFC 1997 community that must
/// survive encoding, the real session, and decoding into router-b's loc-rib.
pub async fn communities(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let (est_a, est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    let (listener_a, listener_b) = (a.count("bgp listener bound"), b.count("bgp listener bound"));
    // Taken before any restart: nos-ribd's restart-triggered resend can land
    // within ~100ms of nos-bgpd's listener coming back.
    let local_a = format!("{} origin=Local", loc_rib());
    let before_local_a = a.count(&local_a);

    let file = policy_file(
        "tag-redistribute-with-community",
        // The prepend lands behind router-a's own ASN (added on export).
        &format!(
            "this.bgp.communities.add({STRIP_AA}:7)\nthis.bgp.communities.add({COMMUNITY_AA}:{COMMUNITY_NN})\nthis.bgp.communities.remove_matching(\"^{STRIP_AA}:\")\nthis.bgp.communities.add(65535:65281)\nthis.bgp.as_path.prepend({PREPEND_ASN}, 2)\nset this.bgp.med = {MED}\naccept\n"
        ),
    )?;
    let mut flags = redistribute();
    flags.extend([
        "--policy-name",
        "tag-redistribute-with-community",
        "--policy-source-file",
        &file,
        "--export-policy",
        "tag-redistribute-with-community",
    ]);
    a.provision(&flags).await?;

    // Then restart both sides, so the policy is resolved from each fresh
    // process's own startup config fetch with no Established session left. A
    // policy change on its own restarts the session, and can lose RFC 4271
    // §6.8 collision resolution against an already-Established connection —
    // which leaves both sides Idle on a connect-retry timer. (Applying the
    // policy *after* the restart races the first session coming back up.)
    // nos-ribd is killed too: its push connection to nos-bgpd is write-only,
    // so it only notices a dead peer on its next write, and a fresh connection
    // is what triggers the full re-send.
    log("restarting both sides' nos-bgpd (and router-a's nos-ribd)");
    w.dock.kill_process("router-a", "nos-bgpd").await?;
    w.dock.kill_process("router-a", "nos-ribd").await?;
    w.dock.kill_process("router-b", "nos-bgpd").await?;
    a.wait_new("bgp listener bound", listener_a, 60).await?;
    b.wait_new("bgp listener bound", listener_b, 60).await?;

    a.wait_new(&local_a, before_local_a, 60).await?;
    reestablished(a, est_a).await?;
    reestablished(b, est_b).await?;
    // The tagged route can land a moment after the session is up.
    b.wait(&format!(
        "{} .*communities=\\[{COMMUNITY_PACKED}, {NO_EXPORT_PACKED}\\]",
        loc_rib()
    ))
    .await?;
    b.wait(&format!(
        "{} .*as_path=\\[{ASN_A}, {PREPEND_ASN}, {PREPEND_ASN}\\]",
        loc_rib()
    ))
    .await?;
    // An export-policy MED reaches an eBGP peer (RFC 4271 §5.1.4, #120).
    b.wait(&format!("{} .*med=Some({MED})", loc_rib())).await?;
    // `remove_matching("^<STRIP_AA>:")` stripped the other tag before encoding
    // (the wait above closes the bracket, so it is the only survivor).
    anyhow::ensure!(
        b.count(&format!("{} .*communities=.*{STRIP_PACKED}", loc_rib())) == 0,
        "router-b saw the community stripped by remove_matching"
    );

    // RFC 8326 (#860): `graceful-shutdown` on router-a tags what it advertises;
    // router-b demotes the tagged route to LOCAL_PREF 0, with no session
    // reset on either side; `graceful-shutdown-receive disable` on router-b
    // restores 100 once the Route Refresh re-sends the route.
    log("graceful-shutdown: router-a tags its export, router-b demotes it");
    let (gs_est_a, gs_est_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    let tagged = |lp: u32| {
        format!(
            "{} .*communities=\\[.*{GRACEFUL_SHUTDOWN_PACKED}.*\\] local_pref={lp}",
            learned()
        )
    };
    let demoted_before = b.count(&tagged(0));
    let mut gs_flags = flags.clone();
    gs_flags.push("--graceful-shutdown");
    a.provision(&gs_flags).await?;
    b.wait_new(&tagged(0), demoted_before, 60).await?;
    let restored_before = b.count(&tagged(100));
    b.provision(&["--no-graceful-shutdown-receive"]).await?;
    b.wait_new(&tagged(100), restored_before, 60).await?;
    a.assert_quiet("bgp session established", gs_est_a, 10)
        .await?;
    b.assert_quiet("bgp session established", gs_est_b, 0)
        .await?;

    // RFC 1997 (#873): the route carries NO_EXPORT, so router-b (eBGP to
    // router-c) must not pass it on, while its own untagged prefix goes.
    log("router-c peers router-b: the NO_EXPORT route must not be re-advertised");
    let c_flags = strings(&[
        "--address",
        &format!("{IP_C}/24"),
        "--asn",
        &ASN_C.to_string(),
        "--router-id",
        RID_C,
        "--remote-as",
        &ASN_B.to_string(),
        "--peer",
        IP_B,
    ]);
    w.start(C, Some(c_flags), &[]).await?;
    let b = w.b()?;
    let b_flags = strings(&[
        "--address",
        &format!("{IP_B}/24"),
        "--asn",
        &ASN_B.to_string(),
        "--router-id",
        RID_B,
        "--peer-group",
        "pg-c",
        "--remote-as",
        &ASN_C.to_string(),
        "--peer",
        IP_C,
        "--static-route",
        CONTROL_PREFIX,
        "--static-gateway",
        REDISTRIBUTE_GATEWAY,
        "--redistribute",
    ]);
    b.provision_flags(&b_flags).await?;
    let c = w.c()?;
    c.established().await?;
    c.wait(&format!(
        "learned route for {CONTROL_PREFIX} into adj-rib-in"
    ))
    .await?;
    b.wait(&format!(
        "advertisement suppressed by well-known community peer=.*prefix={REDISTRIBUTE_PREFIX}"
    ))
    .await?;
    anyhow::ensure!(
        c.count(&learned()) == 0,
        "router-c learned the NO_EXPORT route {REDISTRIBUTE_PREFIX}"
    );
    Ok(())
}

/// RFC 6793 against a real old speaker: ExaBGP with `asn4 disable` never sends
/// the four-octet AS capability, so router-a (ASN > 65535) must talk 2-byte
/// AS_PATH with AS_TRANS + AS4_PATH both ways.
///
/// Send: router-a redistributes a static route; its path is `[ASN_A4]`, which
/// ExaBGP must receive as AS_PATH `[23456]` plus AS4_PATH `[ASN_A4]`. Receive:
/// ExaBGP announces a route with AS_PATH `[65010 23456]` and an AS4_PATH
/// carrying `AS4_HIDDEN_ASN`; router-a's Loc-RIB must hold the merged path. The
/// same route carries ATOMIC_AGGREGATE and an AGGREGATOR/AS4_AGGREGATOR pair
/// (`AS4_AGGREGATOR_ASN`), which router-a must store merged (RFC 4271 §5.1.6,
/// RFC 6793 §4.2.3; re-advertisement is covered by unit tests).
pub async fn as4(w: &mut World) -> anyhow::Result<()> {
    let mut flags = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A4.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
    ]);
    flags.extend(redistribute().into_iter().map(str::to_string));
    w.start(A, Some(flags), &[]).await?;

    log("building/starting the 2-byte-AS ExaBGP speaker (router-g)");
    ensure_exabgp(w).await?;
    // AS4_PATH (type 17, optional transitive): one AS_SEQUENCE of one ASN.
    let as4_value = format!("0201{AS4_HIDDEN_ASN:08X}");
    // AGGREGATOR (type 7, 2-byte AS = AS_TRANS) + AS4_AGGREGATOR (type 18), and
    // ATOMIC_AGGREGATE (type 6, empty): router-a must merge the real ASN.
    let agg_value = format!("{AS_TRANS:04X}C0000209");
    let as4_agg_value = format!("{AS4_AGGREGATOR_ASN:08X}C0000209");
    let conf = format!(
        "process rx {{\n    run /bin/sh -c \"cat > /tmp/rx.json\";\n    encoder json;\n}}\n\
         neighbor {IP_A} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {AS_TRANS};\n    capability {{ asn4 disable; }}\n    \
         family {{ ipv4 unicast; }}\n    \
         api {{ processes [ rx ]; receive {{ parsed; update; }} }}\n    \
         static {{\n        route {AS4_LEARNED_PREFIX} next-hop {IP_G} \
         as-path [ {ASN_G} {AS_TRANS} ] atomic-aggregate \
         attribute [ 0x11 0xc0 0x{as4_value} ] \
         attribute [ 0x07 0xc0 0x{agg_value} ] attribute [ 0x12 0xc0 0x{as4_agg_value} ];\n    }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;

    let a = w.a()?;
    a.established().await?;

    log("receive: ExaBGP's 2-byte AS_PATH + AS4_PATH must merge into the real path");
    a.wait(&format!(
        "loc-rib best path for {AS4_LEARNED_PREFIX} updated .*as_path=\\[{ASN_G}, {AS4_HIDDEN_ASN}\\]"
    ))
    .await?;

    log("receive: ATOMIC_AGGREGATE kept, AGGREGATOR merged with AS4_AGGREGATOR");
    a.wait(&format!(
        "learned route for {AS4_LEARNED_PREFIX} into adj-rib-in .*atomic_aggregate=true aggregator=Some(({AS4_AGGREGATOR_ASN}, {AS4_AGGREGATOR_ID}))"
    ))
    .await?;

    // ExaBGP 5.0.13 parses both attributes (its debug log shows them) and then
    // crashes in its own AS4_PATH merge (`'ASPath' object has no attribute
    // 'as_seq'`), answering with a NOTIFICATION — so the session flaps and the
    // wire bytes, as decoded by an independent implementation's parser, are
    // what we assert on instead of an API dump.
    log("send: router-a's redistributed route must reach ExaBGP as AS_TRANS + AS4_PATH");
    let as_path_wire = format!("as-path .* payload 0201 {AS_TRANS:04X}");
    let as4_path_wire = format!(
        "as4-path .* payload 0201 {:04X} {:04X}",
        ASN_A4 >> 16,
        ASN_A4 & 0xFFFF
    );
    let mut last = String::new();
    for _ in 0..30 {
        last = w.dock.logs("router-g").await?;
        let seen = |pat: &str| last.lines().any(|l| bre(pat).is_match(l));
        if seen(&as_path_wire) && seen(&as4_path_wire) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("ExaBGP never parsed AS_PATH [{AS_TRANS}] + AS4_PATH [{ASN_A4}]: {last}")
}

/// RFC 7606: an UPDATE whose COMMUNITY has a 3-byte value (malformed) must be
/// treated as a withdraw, not reset the session. ExaBGP announces such a route
/// beside a good one; router-a (no redistribution, so nothing that crashes
/// ExaBGP's AS4 merge, see `as4`) must learn only the good one and stay up.
/// A third route with next hop 240.0.0.1 (RFC 4271 §6.3) must be withdrawn too.
pub async fn malformed_update(w: &mut World) -> anyhow::Result<()> {
    let flags = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
    ]);
    w.start(A, Some(flags), &[]).await?;
    ensure_exabgp(w).await?;
    let conf = format!(
        "neighbor {IP_A} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {ASN_A};\n    family {{ ipv4 unicast; }}\n    \
         static {{\n        route {AS4_LEARNED_PREFIX} next-hop {IP_G} as-path [ {ASN_G} ];\n        \
         route {AS4_BAD_PREFIX} next-hop {IP_G} as-path [ {ASN_G} ] \
         attribute [ 0x08 0xc0 0x010203 ];\n        \
         route {BAD_NEXT_HOP_PREFIX} next-hop 240.0.0.1 as-path [ {ASN_G} ];\n    }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;
    let a = w.a()?;
    a.established().await?;
    let established = a.count("bgp session established");
    a.wait(&format!(
        "loc-rib best path for {AS4_LEARNED_PREFIX} updated"
    ))
    .await?;
    a.wait("treating announced routes as withdrawn").await?;
    a.wait("treating bgp update as withdraw: invalid next hop")
        .await?;
    anyhow::ensure!(
        a.count(&format!("loc-rib best path for {BAD_NEXT_HOP_PREFIX}")) == 0,
        "router-a learned {BAD_NEXT_HOP_PREFIX} despite its class-E next hop"
    );
    anyhow::ensure!(
        a.count(&format!("loc-rib best path for {AS4_BAD_PREFIX}")) == 0,
        "router-a learned {AS4_BAD_PREFIX} despite its malformed COMMUNITY"
    );
    anyhow::ensure!(
        a.count("bgp session established") == established,
        "the malformed UPDATE reset the session"
    );
    Ok(())
}

/// RFC 7313 §4 (#80): a scripted speaker (`borr.py`, router-g) sends a BoRR,
/// re-announces only one of its two prefixes and never sends the EoRR. With
/// `route-refresh-stale-time 5`, router-a purges the other one when the timer
/// expires, keeps the session, and a later complete BoRR/EoRR cancels it.
pub async fn route_refresh_stale(w: &mut World) -> anyhow::Result<()> {
    let flags = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
        "--route-refresh-stale-time",
        "5",
    ]);
    w.start(A, Some(flags), &[]).await?;
    w.dock
        .ensure_image(
            PY_SPEAKER_IMAGE,
            &format!(
                "FROM ghcr.io/exa-networks/exabgp:{EXABGP_VERSION}\n\
                 ENTRYPOINT [\"python3\", \"-u\"]\n"
            ),
        )
        .await?;
    let script = include_str!("borr.py")
        .replace("@IP_A@", IP_A)
        .replace("@IP_G@", IP_G)
        .replace("@ASN@", &ASN_G.to_string())
        .replace("@RID@", RID_G)
        .replace("@KEPT@", RR_STALE_KEPT)
        .replace("@PURGED@", RR_STALE_PURGED);
    w.dock
        .start_plain(
            "router-g",
            PY_SPEAKER_IMAGE,
            NET,
            IP_G,
            &["/etc/borr.py"],
            ("/etc", "borr.py", script.as_bytes()),
        )
        .await?;
    let a = w.a()?;
    a.established().await?;
    let established = a.count("bgp session established");
    let expired = "bgp: route refresh stale timer expired";
    a.wait(&format!("loc-rib best path for {RR_STALE_PURGED} updated"))
        .await?;
    a.wait(&format!("bgp: received BoRR peer={IP_G}")).await?;

    log("no EoRR: the stale timer purges the prefix the refresh left out");
    a.wait_new(&format!("{expired}.* peer={IP_G} afi=1"), 0, 15)
        .await?;
    a.wait(&format!(
        "bgp: purged stale route peer={IP_G} prefix={RR_STALE_PURGED}"
    ))
    .await?;
    anyhow::ensure!(
        a.count(&format!("purged stale route.*prefix={RR_STALE_KEPT}")) == 0,
        "router-a purged {RR_STALE_KEPT}, which the refresh re-announced"
    );
    anyhow::ensure!(
        a.count("bgp session established") == established,
        "the stale timer reset the session"
    );

    log("a complete refresh: EoRR cancels the timer");
    a.wait(&format!("bgp: received EoRR peer={IP_G}")).await?;
    a.assert_quiet(expired, a.count(expired), 10).await?;
    Ok(())
}

/// RFC 5065 confederation (#15): router-a (member AS `CONFED_ASN_A`) and
/// router-b (`CONFED_ASN_B`) form confederation `CONFED_ID` and peer as
/// confederation-external; ExaBGP (router-g) is outside it and peers router-a
/// with `peer-as CONFED_ID`, so the session coming up proves router-a's OPEN
/// carries the identifier. Then: ExaBGP's route reaches router-b behind an
/// AS_CONFED_SEQUENCE of router-a's member AS; router-b's redistributed route
/// reaches router-a the same way and ExaBGP with only the identifier
/// (asserted on ExaBGP's parser log, like `as4`); a path holding the
/// identifier is a loop; and a confed segment from ExaBGP is treat-as-withdraw
/// without resetting the session.
pub async fn confederation(w: &mut World) -> anyhow::Result<()> {
    let confed = |own: u32, peer: u32| {
        strings(&[
            "--confederation-id",
            &CONFED_ID.to_string(),
            "--confederation-peer",
            &peer.to_string(),
            "--asn",
            &own.to_string(),
        ])
    };
    let mut a_flags = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--router-id",
        RID_A,
        "--peer-group",
        "pg-b",
        "--remote-as",
        &CONFED_ASN_B.to_string(),
        "--peer",
        IP_B,
    ]);
    a_flags.extend(confed(CONFED_ASN_A, CONFED_ASN_B));
    let mut b_flags = strings(&[
        "--address",
        &format!("{IP_B}/24"),
        "--router-id",
        RID_B,
        "--remote-as",
        &CONFED_ASN_A.to_string(),
        "--peer",
        IP_A,
    ]);
    b_flags.extend(confed(CONFED_ASN_B, CONFED_ASN_A));
    b_flags.extend(strings(&redistribute()));
    w.start(A, Some(a_flags), &[]).await?;
    w.start(B, Some(b_flags), &[]).await?;
    let mut g_flags = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--router-id",
        RID_A,
        "--peer-group",
        "pg-g",
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
    ]);
    g_flags.extend(confed(CONFED_ASN_A, CONFED_ASN_B));
    w.a()?.provision_flags(&g_flags).await?;

    ensure_exabgp(w).await?;
    // ExaBGP's config syntax has no way to write a confed segment (`{` opens
    // a block), so the bad route carries a raw AS_PATH: AS_CONFED_SEQUENCE
    // [65109] then AS_SEQUENCE [ASN_G].
    let bad_as_path = format!("0301{:08X}0201{ASN_G:08X}", 65109);
    let conf = format!(
        "neighbor {IP_A} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {CONFED_ID};\n    family {{ ipv4 unicast; }}\n    \
         static {{\n        route {CONFED_LEARNED_PREFIX} next-hop {IP_G} as-path [ {ASN_G} ];\n        \
         route {CONFED_LOOP_PREFIX} next-hop {IP_G} as-path [ {ASN_G} {CONFED_ID} ];\n        \
         route {CONFED_BAD_PREFIX} next-hop {IP_G} attribute [ 0x02 0x40 0x{bad_as_path} ];\n    }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;

    let (a, b) = (w.a()?, w.b()?);
    log("member ASes in OPEN between router-a and router-b, the identifier toward ExaBGP");
    b.wait(&format!(
        "bgp session established peer={IP_A} remote_asn={CONFED_ASN_A}"
    ))
    .await?;
    a.wait(&format!(
        "bgp session established peer={IP_G} remote_asn={ASN_G}"
    ))
    .await?;
    let established = a.count("bgp session established");

    log("ExaBGP's route reaches router-b behind router-a's member AS, as a confed segment");
    b.wait(&format!(
        "loc-rib best path for {CONFED_LEARNED_PREFIX} updated .*as_path=\\[({CONFED_ASN_A}), {ASN_G}\\] .*next_hop=Some({IP_G})"
    ))
    .await?;
    log("router-b's route reaches router-a as a confed segment");
    a.wait(&format!("{} .*as_path=\\[({CONFED_ASN_B})\\]", loc_rib()))
        .await?;

    log("a path holding the confederation identifier is a loop");
    a.wait(&format!(
        "dropping bgp update: as_path already contains our own asn .*peer={IP_G} as_path=\\[{ASN_G}, {CONFED_ID}\\]"
    ))
    .await?;
    log("a confed segment from outside the confederation is treat-as-withdraw");
    a.wait(&format!(
        "treating bgp update as withdraw: as_path has confederation segments .*peer={IP_G}"
    ))
    .await?;
    for p in [CONFED_LOOP_PREFIX, CONFED_BAD_PREFIX] {
        anyhow::ensure!(
            a.count(&format!("loc-rib best path for {p}")) == 0,
            "router-a installed {p}"
        );
    }
    anyhow::ensure!(
        a.count("bgp session established") == established,
        "a confederation check reset a session"
    );

    log("ExaBGP sees router-b's route with only the identifier: AS_SEQUENCE [65100]");
    // `len 0x06`: one segment holding one ASN, nothing else.
    let identifier_only = format!(
        "as-path .* len 0x06 payload 0201 {:04X} {:04X}",
        CONFED_ID >> 16,
        CONFED_ID & 0xFFFF
    );
    let mut last = String::new();
    for _ in 0..30 {
        last = w.dock.logs("router-g").await?;
        let as_paths: Vec<&str> = last
            .lines()
            .filter(|l| bre("as-path .* payload").is_match(l))
            .collect();
        if as_paths.iter().any(|l| bre(&identifier_only).is_match(l)) {
            // A member AS or a confed segment type would mean a leak.
            let leak = as_paths.iter().find(|l| {
                l.contains(&format!("{CONFED_ASN_A:04X}"))
                    || l.contains(&format!("{CONFED_ASN_B:04X}"))
                    || l.contains("payload 03")
                    || l.contains("payload 04")
            });
            if let Some(l) = leak {
                bail!("router-a leaked the confederation to ExaBGP: {l}");
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("ExaBGP never parsed AS_PATH [{CONFED_ID}]: {last}")
}

/// Vendor `local-as` (#166): router-a (`ASN_A`) presents `LOCAL_AS` to
/// ExaBGP (router-g), configured with `peer-as LOCAL_AS`, so the session
/// coming up proves the OPEN carries it. ExaBGP's route is stored as
/// `[LOCAL_AS, ASN_G]`, a path holding `LOCAL_AS` is a loop, and router-a's
/// redistributed route reaches ExaBGP as `[LOCAL_AS, ASN_A]` (ExaBGP's parser
/// log, like `as4`). Then `no-prepend` + `replace-as`: the route is stored as
/// `[ASN_G]` and ExaBGP sees `[LOCAL_AS]` alone, `ASN_A` nowhere.
pub async fn local_as(w: &mut World) -> anyhow::Result<()> {
    let mut base = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
        "--local-as",
        &LOCAL_AS.to_string(),
    ]);
    base.extend(strings(&redistribute()));
    let with = |extra: &[&str]| {
        let mut f = base.clone();
        f.extend(strings(extra));
        f
    };
    w.start(A, Some(base.clone()), &[]).await?;
    ensure_exabgp(w).await?;
    let conf = format!(
        "neighbor {IP_A} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {LOCAL_AS};\n    family {{ ipv4 unicast; }}\n    \
         static {{\n        route {LOCAL_AS_LEARNED_PREFIX} next-hop {IP_G} as-path [ {ASN_G} ];\n        \
         route {LOCAL_AS_LOOP_PREFIX} next-hop {IP_G} as-path [ {ASN_G} {LOCAL_AS} ];\n        \
         route {LOCAL_AS_FORGED_PREFIX} next-hop {IP_G} as-path [ {FORGED_FIRST_AS} ];\n    }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;
    let a = w.a()?;
    let est = format!("bgp session established peer={IP_G} remote_asn={ASN_G}");
    log("ExaBGP expects peer-as LOCAL_AS: the session coming up proves the OPEN carries it");
    a.wait(&est).await?;

    log("inbound: LOCAL_AS is prepended to ExaBGP's path");
    a.wait(&format!(
        "loc-rib best path for {LOCAL_AS_LEARNED_PREFIX} updated .*as_path=\\[{LOCAL_AS}, {ASN_G}\\]"
    ))
    .await?;
    log("a path holding LOCAL_AS from this peer is a loop");
    a.wait(&format!(
        "dropping bgp update: as_path already contains our own asn .*peer={IP_G} as_path=\\[{ASN_G}, {LOCAL_AS}\\]"
    ))
    .await?;
    anyhow::ensure!(
        a.count(&format!("loc-rib best path for {LOCAL_AS_LOOP_PREFIX}")) == 0,
        "router-a installed {LOCAL_AS_LOOP_PREFIX}"
    );

    log("first-AS check (#392): a path not starting with the peer's AS is treated as a withdraw");
    a.wait("first AS of as_path is not the peer's AS").await?;
    anyhow::ensure!(
        a.count(&format!("loc-rib best path for {LOCAL_AS_FORGED_PREFIX}")) == 0,
        "router-a installed {LOCAL_AS_FORGED_PREFIX}"
    );

    log("outbound: ExaBGP parses router-a's route as AS_SEQUENCE [LOCAL_AS, ASN_A]");
    let both = format!("as-path .* len 0x0a payload 0202 0000 {LOCAL_AS:04X} 0000 {ASN_A:04X}");
    exabgp_parsed(w, &both, 0, None).await?;

    log("no-prepend + replace-as: a new session, ExaBGP's path stored unchanged");
    let seen = w.dock.logs("router-g").await?.lines().count();
    let est_before = a.count(&est);
    a.provision_flags(&with(&["--local-as-no-prepend", "--local-as-replace-as"]))
        .await?;
    a.wait_new(&est, est_before, 60).await?;
    let unchanged =
        format!("loc-rib best path for {LOCAL_AS_LEARNED_PREFIX} updated .*as_path=\\[{ASN_G}\\]");
    a.wait_new(&unchanged, 0, 30).await?;

    log("replace-as: ExaBGP parses [LOCAL_AS] alone, ASN_A nowhere");
    let only = format!("as-path .* len 0x06 payload 0201 0000 {LOCAL_AS:04X}");
    exabgp_parsed(w, &only, seen, Some(&format!("{ASN_A:04X}"))).await?;

    log("no-enforce-first-as: a new session accepts the forged route");
    let est_before = a.count(&est);
    a.provision_flags(&with(&[
        "--local-as-no-prepend",
        "--local-as-replace-as",
        "--no-enforce-first-as",
    ]))
    .await?;
    a.wait_new(&est, est_before, 60).await?;
    a.wait(&format!(
        "loc-rib best path for {LOCAL_AS_FORGED_PREFIX} updated .*as_path=\\[{FORGED_FIRST_AS}\\]"
    ))
    .await
}

/// Waits for ExaBGP's parser log (router-g) to show a line matching `want`
/// among the lines after the first `skip`; with `leak`, fails if any
/// `as-path` line there contains it.
async fn exabgp_parsed(
    w: &World,
    want: &str,
    skip: usize,
    leak: Option<&str>,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..30 {
        last = w.dock.logs("router-g").await?;
        let as_paths: Vec<&str> = last
            .lines()
            .skip(skip)
            .filter(|l| bre("as-path .* payload").is_match(l))
            .collect();
        if as_paths.iter().any(|l| bre(want).is_match(l)) {
            if let Some(l) = leak.and_then(|x| as_paths.iter().find(|l| l.contains(x))) {
                bail!("router-a leaked an AS to ExaBGP: {l}");
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("ExaBGP never parsed `{want}`: {last}")
}

/// RFC 7911 ADD-PATH (#13). Receive: router-a (`add-path receive`) peers
/// ExaBGP (router-g, `add-path send`), which announces `ADD_PATH_PREFIX` as
/// path 1 (MED 50) and path 2 (MED 10) through its API — a command file
/// `tail -F` feeds it, so a path can be withdrawn without restarting ExaBGP
/// (which would drop the session and every path with it). router-a keeps
/// both paths and picks path 2; withdrawing path 2 alone makes path 1 the
/// best path, and the prefix is never withdrawn. Send: `add_path_send`.
pub async fn add_path(w: &mut World) -> anyhow::Result<()> {
    let flags = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
        "--add-path",
        "receive",
    ]);
    w.start(A, Some(flags), &[]).await?;
    ensure_exabgp(w).await?;
    let conf = format!(
        "process cmd {{\n    run /bin/sh -c \"touch /tmp/exa.cmd; tail -F /tmp/exa.cmd\";\n    \
         encoder text;\n}}\n\
         neighbor {IP_A} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {ASN_A};\n    family {{ ipv4 unicast; }}\n    \
         capability {{ add-path send; }}\n    api {{ processes [ cmd ]; }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;
    exabgp_api(w, &add_path_announce(1, ADD_PATH_MED_1)).await?;
    exabgp_api(w, &add_path_announce(2, ADD_PATH_MED_2)).await?;

    let a = w.a()?;
    a.established().await?;
    log("the capability is negotiated in router-a's receive direction");
    a.wait(&format!("add-path negotiated peer={IP_G} ipv4=\"receive\""))
        .await?;
    log("both paths are kept, path 2 (lower MED) is the best path");
    for id in [1, 2] {
        a.wait(&format!(
            "learned route for {ADD_PATH_PREFIX} into adj-rib-in peer={IP_G} path_id={id}"
        ))
        .await?;
    }
    let best =
        |med: u32| format!("loc-rib best path for {ADD_PATH_PREFIX} updated .*med=Some({med})");
    a.wait(&best(ADD_PATH_MED_2)).await?;
    log("path 1's eBGP LOCAL_PREF 1000 is ignored (RFC 4271 §5.1.5, #601)");
    a.wait(&format!(
        "loc-rib best path for {ADD_PATH_PREFIX} updated .*local_pref=100"
    ))
    .await?;
    a.assert_quiet(
        &format!("best path for {ADD_PATH_PREFIX} updated .*local_pref=1000"),
        0,
        5,
    )
    .await?;

    log("withdrawing path 2 alone: path 1 takes over, the prefix stays");
    let established = a.count("bgp session established");
    let withdrawn = format!("loc-rib route for {ADD_PATH_PREFIX} withdrawn");
    let back_to_1 = a.count(&best(ADD_PATH_MED_1));
    exabgp_api(
        w,
        &format!("withdraw route {ADD_PATH_PREFIX} next-hop {IP_G} path-information 2"),
    )
    .await?;
    a.wait(&format!(
        "withdrew path for {ADD_PATH_PREFIX} from adj-rib-in peer={IP_G} path_id=2"
    ))
    .await?;
    a.wait_new(&best(ADD_PATH_MED_1), back_to_1, 30).await?;
    a.assert_quiet(&withdrawn, 0, 10).await?;
    anyhow::ensure!(
        a.count("bgp session established") == established,
        "withdrawing one path reset the session"
    );
    add_path_send(w).await
}

/// ExaBGP's API line announcing `ADD_PATH_PREFIX` as path `id`.
fn add_path_announce(id: u32, med: u32) -> String {
    // Path 1 carries LOCAL_PREF 1000, which an eBGP peer must not get to use (#601).
    let lp = if id == 1 {
        "local-preference 1000 "
    } else {
        ""
    };
    format!(
        "announce route {ADD_PATH_PREFIX} next-hop {IP_G} med {med} {lp}community [ 65000:{id} ] \
         as-path [ {ASN_G} ] path-information {id}"
    )
}

/// RFC 7911 ADD-PATH send (#13), after `add_path`: ExaBGP's paths 2 and 3
/// join path 1, router-a ranks them 2, 3, 1 and sends router-b (`add-path
/// receive`) the best 2 (`add-path send`, `add-path-send-count 2`) — paths
/// told apart by community. Withdrawing path 2 makes path 1 take its id in
/// place (no withdrawal on router-b); withdrawing path 1 too leaves one path,
/// so router-b sees that id withdrawn and keeps the prefix.
async fn add_path_send(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let learned_3 =
        format!("learned route for {ADD_PATH_PREFIX} into adj-rib-in peer={IP_G} path_id=3");
    exabgp_api(w, &add_path_announce(2, ADD_PATH_MED_2)).await?;
    exabgp_api(w, &add_path_announce(3, ADD_PATH_MED_3)).await?;
    a.wait(&learned_3).await?;

    let b_flags = strings(&[
        "--address",
        &format!("{IP_B}/24"),
        "--asn",
        &ASN_B.to_string(),
        "--router-id",
        RID_B,
        "--remote-as",
        &ASN_A.to_string(),
        "--peer",
        IP_A,
        "--add-path",
        "receive",
    ]);
    w.start(B, Some(b_flags), &[]).await?;
    w.a()?
        .provision_flags(&strings(&[
            "--address",
            &format!("{IP_A}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--peer-group",
            "pg-b",
            "--remote-as",
            &ASN_B.to_string(),
            "--peer",
            IP_B,
            "--add-path",
            "send",
            "--add-path-send-count",
            "2",
        ]))
        .await?;
    let (a, b) = (w.a()?, w.b()?);
    a.wait(&format!("add-path negotiated peer={IP_B} ipv4=\"send\""))
        .await?;

    let learned = |id: u32, path: u32| {
        format!(
            "learned route for {ADD_PATH_PREFIX} into adj-rib-in peer={IP_A} path_id={id} \
             .*communities=\\[{}\\]",
            add_path_community(path)
        )
    };
    log("router-b gets router-a's best 2 of 3 paths: path 2 under id 1, path 3 under id 2");
    b.wait(&learned(1, 2)).await?;
    b.wait(&learned(2, 3)).await?;
    let any_learned = format!("learned route for {ADD_PATH_PREFIX} into adj-rib-in peer={IP_A}");
    let path_1 = format!(
        "learned route for {ADD_PATH_PREFIX} .*communities=\\[{}\\]",
        add_path_community(1)
    );
    b.assert_quiet(&any_learned, 2, 10).await?;
    b.assert_quiet(&path_1, 0, 0).await?;

    log("withdrawing path 2: path 1 takes id 1 in place, nothing withdrawn on router-b");
    let withdrew = format!("withdrew path for {ADD_PATH_PREFIX} from adj-rib-in peer={IP_A}");
    exabgp_api(
        w,
        &format!("withdraw route {ADD_PATH_PREFIX} next-hop {IP_G} path-information 2"),
    )
    .await?;
    b.wait(&learned(1, 1)).await?;
    b.assert_quiet(&withdrew, 0, 10).await?;

    log("withdrawing path 1: one path left, router-b sees id 1 withdrawn and keeps the prefix");
    exabgp_api(
        w,
        &format!("withdraw route {ADD_PATH_PREFIX} next-hop {IP_G} path-information 1"),
    )
    .await?;
    b.wait(&format!("{withdrew} path_id=1")).await?;
    b.assert_quiet(
        &format!("loc-rib route for {ADD_PATH_PREFIX} withdrawn"),
        0,
        10,
    )
    .await?;
    b.assert_quiet(&format!("{withdrew} path_id=2"), 0, 0)
        .await?;
    Ok(())
}

/// Hands ExaBGP (router-g) one API command, through the command file its
/// `process cmd` follows.
async fn exabgp_api(w: &World, line: &str) -> anyhow::Result<()> {
    let (code, out) = w
        .dock
        .exec(
            "router-g",
            &["sh", "-c", &format!("echo '{line}' >> /tmp/exa.cmd")],
        )
        .await?;
    anyhow::ensure!(code == 0, "writing ExaBGP's command file: {out}");
    Ok(())
}

/// RFC 4486 §4 maximum-prefix (#79): ExaBGP (router-g) announces
/// `MAX_PREFIX_ROUTES` (3) IPv4 routes to router-a, whose peer-group allows
/// fewer. A trip closes the session with Cease subcode 1 and holds the peer
/// down until a REST clear or a shut/no-shut; raising the limit lets the
/// routes in; `warning-only` only logs; a restart interval retries by itself.
pub async fn maximum_prefix(w: &mut World) -> anyhow::Result<()> {
    let base = strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
    ]);
    let with = |extra: &[&str]| {
        let mut f = base.clone();
        f.extend(strings(extra));
        f
    };
    w.start(A, Some(with(&["--maximum-prefix", "ipv4=2"])), &[])
        .await?;
    ensure_exabgp(w).await?;
    let routes = MAX_PREFIX_ROUTES
        .map(|p| format!("        route {p} next-hop {IP_G} as-path [ {ASN_G} ];\n"))
        .concat();
    let conf = format!(
        "neighbor {IP_A} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {ASN_A};\n    family {{ ipv4 unicast; }}\n    \
         static {{\n{routes}    }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;
    let a = w.a()?;
    let est = "bgp session established";
    let tripped = "maximum prefix limit exceeded.*family=ipv4 count=3 limit=2 warning_only=false";
    let cease1 = "sent cease notification peer=.* subcode=1";
    let summary = || a.rest_expect(Method::GET, "/v1/bgp/summary", None, 200);

    log("limit 2: the third prefix trips it, and the peer stays down");
    a.wait(tripped).await?;
    a.wait(cease1).await?;
    let held_since = a.count(est);
    a.assert_quiet(est, held_since, 12).await?;
    anyhow::ensure!(
        summary().await?.contains("\"max_prefix_held\":true"),
        "show bgp brief does not report the max-prefix hold"
    );

    log("a REST clear releases the hold; ExaBGP still sends 3, so it trips again");
    let ceases = a.count(cease1);
    a.rest_expect(
        Method::POST,
        &format!("/v1/bgp/r1/peer/{IP_G}/clear"),
        None,
        200,
    )
    .await?;
    a.wait_new(est, held_since, 30).await?;
    a.wait_new(cease1, ceases, 30).await?;

    log("a shutdown and un-shutdown releases it too");
    let (est_before, ceases) = (a.count(est), a.count(cease1));
    a.provision_flags(&with(&["--shutdown-peer-group", ""]))
        .await?;
    a.provision_flags(&with(&["--unshutdown-peer-group"]))
        .await?;
    a.wait_new(est, est_before, 30).await?;
    a.wait_new(cease1, ceases, 30).await?;

    log("limit 5: all three routes are learned, no cease");
    let (est_before, ceases) = (a.count(est), a.count(cease1));
    a.provision_flags(&with(&["--maximum-prefix", "ipv4=5"]))
        .await?;
    a.wait_new(est, est_before, 30).await?;
    let mut counted = false;
    for _ in 0..30 {
        if summary().await?.contains("\"accepted_prefixes\":[3,0,0]") {
            counted = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::ensure!(
        counted,
        "show bgp brief never counted the 3 accepted prefixes"
    );
    a.assert_quiet(cease1, ceases, 8).await?;

    log("limit 2 warning-only: a warning, the session stays up");
    let (est_before, ceases) = (a.count(est), a.count(cease1));
    let warned = "maximum prefix limit exceeded.*count=3 limit=2 warning_only=true";
    let warned_before = a.count(warned);
    a.provision_flags(&with(&[
        "--maximum-prefix",
        "ipv4=2",
        "--maximum-prefix-warning-only",
    ]))
    .await?;
    a.wait_new(est, est_before, 30).await?;
    a.wait_new(warned, warned_before, 30).await?;
    let est_now = a.count(est);
    a.assert_quiet(cease1, ceases, 10).await?;
    anyhow::ensure!(a.count(est) == est_now, "warning-only reset the session");

    log("limit 2 restart-interval 5: it trips and retries by itself");
    let ceases = a.count(cease1);
    a.provision_flags(&with(&[
        "--maximum-prefix",
        "ipv4=2",
        "--maximum-prefix-restart-interval",
        "5",
    ]))
    .await?;
    a.wait_new(cease1, ceases + 1, 40).await?;

    log("#501: an eBGP group without a limit commits with a warning, with one it does not");
    let warn = "commit warning.*no maximum-prefix for ipv4";
    let warned_before = a.count(warn);
    let body = a
        .provision_flags_body(&with(&["--clear-maximum-prefix", "ipv4"]))
        .await?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    anyhow::ensure!(
        json["warnings"].as_array().is_some_and(|w| w.len() == 1
            && w[0]
                .as_str()
                .is_some_and(|m| m.contains("'r1'") && m.contains("no maximum-prefix for ipv4"))),
        "commit without a limit did not warn once: {body}"
    );
    a.wait_new(warn, warned_before, 10).await?;
    let body = a
        .provision_flags_body(&with(&["--maximum-prefix", "ipv4=5"]))
        .await?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    anyhow::ensure!(
        json["warnings"].as_array().is_some_and(Vec::is_empty),
        "commit with a limit still warned: {body}"
    );

    log("#396: limit 0 is explicitly uncapped: no warning, all routes in, no cease");
    let (est_before, ceases) = (a.count(est), a.count(cease1));
    let body = a
        .provision_flags_body(&with(&["--maximum-prefix", "ipv4=0"]))
        .await?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    anyhow::ensure!(
        json["warnings"].as_array().is_some_and(Vec::is_empty),
        "commit with limit 0 warned: {body}"
    );
    a.wait_new(est, est_before, 30).await?;
    a.assert_quiet(cease1, ceases, 8).await?;
    Ok(())
}

/// StayRTR's VRP file (`-cache`): one VRP for `REDISTRIBUTE_PREFIX`, and
/// one making ExaBGP's `RPKI_INVALID_PREFIX` invalid.
fn rpki_vrps(asn: u32) -> String {
    format!(
        "{{\"roas\":[{{\"prefix\":\"{REDISTRIBUTE_PREFIX}\",\"maxLength\":24,\"asn\":\"AS{asn}\"}},\
         {{\"prefix\":\"{RPKI_INVALID_PREFIX}\",\"maxLength\":24,\"asn\":\"AS{RPKI_WRONG_ASN}\"}}]}}\n"
    )
}

/// The ExaBGP image every ExaBGP phase runs as `router-g`, with its parser's
/// debug log on stdout.
async fn ensure_exabgp(w: &World) -> anyhow::Result<()> {
    w.dock
        .ensure_image(
            EXABGP_IMAGE,
            &format!(
                "FROM ghcr.io/exa-networks/exabgp:{EXABGP_VERSION}\n\
                 ENV exabgp_daemon_daemonize=false exabgp_log_destination=stdout \\\n    \
                 exabgp_log_level=DEBUG exabgp_log_all=true\n"
            ),
        )
        .await
}

/// #500: polls `GET /v1/bgp/routes` until `prefix` is listed with
/// `validation_state` `want` (`Valid`/`Invalid`/`NotFound`) and, with `best`,
/// the best-path flag.
async fn expect_route_state(
    r: &Router,
    prefix: &str,
    want: &str,
    best: bool,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..30 {
        last = r
            .rest_expect(Method::GET, "/v1/bgp/routes", None, 200)
            .await?;
        let json: serde_json::Value = serde_json::from_str(&last)?;
        let hit = json.as_array().into_iter().flatten().any(|inst| {
            inst["result"]["items"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|rt| {
                    rt["prefix"] == prefix
                        && rt["validation_state"] == want
                        && (!best || rt["best"] == true)
                })
        });
        if hit {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{}: GET /v1/bgp/routes never listed {prefix} as {want} (best={best}): {last}",
        r.name()
    )
}

/// RFC 6811 origin validation fed over RFC 8210 by a real cache (StayRTR,
/// self-contained): router-a validates router-b's redistributed prefix and
/// its import policy rejects `rpki.invalid`.
///
/// - router-a's preferred cache doesn't answer; it fails over to StayRTR;
/// - the VRP set authorizes another AS: the prefix is invalid, not learned;
/// - the VRP file changes: StayRTR's Serial Notify brings the new set, router-a
///   asks router-b for a route refresh and learns it as valid — no session reset;
/// - RFC 8097 (#162): router-c, an iBGP peer of router-a with no cache, takes
///   each route's state from router-a's `announce-rpki-state` community
///   (valid, invalid, not-found); ExaBGP (eBGP, `router-g`) gets no
///   non-transitive extended community, and its own RFC 8097 tag is ignored;
/// - `GET /v1/bgp/routes` (#500) shows the state: valid on router-a after the
///   serial update, invalid on router-c (RFC 8097; router-a's reject-invalid
///   policy never stores the invalid route), not-found after the expiry;
/// - StayRTR goes away: after its 10s expire interval the VRPs are dropped and
///   the prefix is not-found (still accepted).
pub async fn rpki(w: &mut World) -> anyhow::Result<()> {
    w.dock.ensure_pulled(STAYRTR_IMAGE).await?;
    w.ensure_network().await?;
    w.dock
        .start_plain(
            RPKI_CACHE,
            STAYRTR_IMAGE,
            NET,
            IP_RPKI,
            &[
                "-cache",
                "/vrps.json",
                "-checktime=false",
                "-refresh",
                "2",
                // Refresh well inside the 10s expire, or a healthy session's
                // VRPs would expire between two serial queries.
                "-rtr.refresh",
                "4",
                "-rtr.retry",
                "2",
                "-rtr.expire",
                "10",
                "-bind",
                ":323",
            ],
            ("/", "vrps.json", rpki_vrps(RPKI_WRONG_ASN).as_bytes()),
        )
        .await?;
    let policy = policy_file(
        "rpki-reject-invalid",
        "if this.bgp.validation_state == rpki.invalid:\n    reject\naccept\n",
    )?;
    let mut a_flags = A.base_flags();
    a_flags.extend(strings(&[
        "--policy-name",
        "rpki-reject-invalid",
        "--policy-source-file",
        &policy,
        "--import-policy",
        "rpki-reject-invalid",
        "--rpki-cache",
        &format!("{IP_RPKI_DEAD}:323"),
        "--rpki-cache",
        &format!("{IP_RPKI}:323"),
    ]));
    let mut b_flags = B.base_flags();
    b_flags.extend(strings(&redistribute()));
    w.start(A, Some(a_flags), &[]).await?;
    w.start(B, Some(b_flags), &[]).await?;
    // RFC 8097: router-c is an iBGP peer with no cache of its own; ExaBGP is
    // an eBGP peer whose export policy carries one non-transitive (the RFC
    // 8097 type) and one transitive (a route target) extended community.
    let ibgp = |ip: &str, rid: &str, peer: &str| {
        strings(&[
            "--address",
            &format!("{ip}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            rid,
            "--remote-as",
            &ASN_A.to_string(),
            "--peer",
            peer,
            "--announce-rpki-state",
        ])
    };
    w.start(C, Some(ibgp(IP_C, RID_C, IP_A)), &[]).await?;
    let mut pg_c = ibgp(IP_A, RID_A, IP_C);
    pg_c.extend(strings(&["--peer-group", "pg-c"]));
    w.a()?.provision_flags(&pg_c).await?;
    let tag_out = policy_file(
        "rpki-tag-out",
        "this.bgp.extended_communities.add(67:0:0)\n\
         this.bgp.extended_communities.add(0:2:279172874340)\naccept\n",
    )?;
    w.a()?
        .provision_flags(&strings(&[
            "--address",
            &format!("{IP_A}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--peer-group",
            "pg-g",
            "--remote-as",
            &ASN_G.to_string(),
            "--peer",
            IP_G,
            "--policy-name",
            "rpki-tag-out",
            "--policy-source-file",
            &tag_out,
            "--export-policy",
            "rpki-tag-out",
        ]))
        .await?;
    ensure_exabgp(w).await?;
    let conf = format!(
        "process rx {{\n    run /bin/sh -c \"cat > /tmp/rx.json\";\n    encoder json;\n}}\n\
         neighbor {IP_A} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {ASN_A};\n    family {{ ipv4 unicast; }}\n    \
         api {{ processes [ rx ]; receive {{ parsed; update; }} }}\n    \
         static {{\n        route {RPKI_INVALID_PREFIX} next-hop {IP_G} as-path [ {ASN_G} ];\n        \
         route {RPKI_TAGGED_PREFIX} next-hop {IP_G} as-path [ {ASN_G} ] \
         attribute [ 0x10 0xc0 0x4300000000000002 ];\n    }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let cache = format!("cache={IP_RPKI}:323");

    log("the preferred cache never answers: router-a fails over to StayRTR");
    a.wait(&format!("rpki cache unreachable cache={IP_RPKI_DEAD}:323"))
        .await?;
    a.wait(&format!("rpki cache connected {cache} version=1"))
        .await?;
    a.wait(&format!("rpki end of data {cache} .*vrps=2"))
        .await?;
    a.established().await?;
    let summary = a
        .rest_expect(Method::GET, "/v1/bgp/rpki", None, 200)
        .await?;
    anyhow::ensure!(
        summary.contains(&format!(
            "\"address\":\"{IP_RPKI}\",\"port\":323,\"preference\":1,\"state\":\"Established\",\"active\":true,\"version\":1"
        )) && summary.contains("\"vrp_count\":2"),
        "GET /v1/bgp/rpki does not show the StayRTR session in use: {summary}"
    );

    log(format!(
        "VRPs authorize AS{RPKI_WRONG_ASN}: router-b's prefix is invalid and rejected"
    ));
    b.wait(&loc_rib()).await?;
    // It can reach router-a before the first End of Data (then it is
    // not-found, accepted, and only dropped by the route refresh that follows
    // the VRP change): wait until rt1 no longer holds it from BGP.
    let mut gone = false;
    for _ in 0..30 {
        if !a.rt1_has(REDISTRIBUTE_PREFIX, "Bgp").await? {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::ensure!(gone, "router-a still holds the invalid route");
    let learned_before = a.count(&learned());
    a.assert_quiet(&learned(), learned_before, 8).await?;

    log(format!(
        "the VRP file now authorizes AS{ASN_B}: serial update, route refresh, learned as valid"
    ));
    // From here on the session must never reset (the start-up one may have
    // flapped once already: that is router-b provisioning, not RPKI).
    c.established().await?;
    a.wait(&format!("bgp session established peer={IP_G}"))
        .await?;
    let mut peers = String::new();
    for _ in 0..30 {
        peers = a
            .rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?;
        if peers.contains("\"state\":\"Established\"") {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::ensure!(
        peers.contains("\"state\":\"Established\""),
        "the session with router-b is not up: {peers}"
    );
    let sessions = a.count("bgp session established");
    let refreshes = a.count("rpki change: requesting route refresh");
    let valid = format!("{} .*validation_state=Valid", learned());
    let valid_before = a.count(&valid);
    w.dock
        .upload(RPKI_CACHE, "/", "vrps.json", rpki_vrps(ASN_B).as_bytes())
        .await?;
    a.wait(&format!("rpki end of data {cache} .*serial=1 vrps=2"))
        .await?;
    a.wait_new(
        &format!("rpki change: requesting route refresh .*peer={IP_B}"),
        refreshes,
        30,
    )
    .await?;
    a.wait_new(&valid, valid_before, 30).await?;
    log("GET /v1/bgp/routes (#500): router-a lists the route as valid and best");
    expect_route_state(a, REDISTRIBUTE_PREFIX, "Valid", true).await?;

    log("RFC 8097: router-c (no cache) takes each state from router-a's community");
    let learned_as = |prefix: &str, state: &str| {
        format!("learned route for {prefix} into adj-rib-in .*validation_state={state}")
    };
    c.wait(&learned_as(REDISTRIBUTE_PREFIX, "Valid")).await?;
    c.wait(&learned_as(RPKI_INVALID_PREFIX, "Invalid")).await?;
    log("GET /v1/bgp/routes (#500): router-c lists the RFC 8097 route as invalid");
    expect_route_state(c, RPKI_INVALID_PREFIX, "Invalid", false).await?;
    log("RFC 8097: ExaBGP's own \"invalid\" tag is ignored over eBGP");
    a.wait(&learned_as(RPKI_TAGGED_PREFIX, "NotFound")).await?;
    c.wait(&learned_as(RPKI_TAGGED_PREFIX, "NotFound")).await?;
    anyhow::ensure!(
        c.count(&learned_as(RPKI_TAGGED_PREFIX, "Invalid")) == 0,
        "ExaBGP's RFC 8097 tag reached router-c"
    );
    log("RFC 4360: toward eBGP only the transitive extended community is left");
    // ExaBGP prints the payload in 4-hex-digit groups: target 65:100.
    let rt_wire = "extended-community .* payload 0002 0041 0000 0064";
    let mut last = String::new();
    let mut seen_rt = false;
    for _ in 0..30 {
        last = w.dock.logs("router-g").await?;
        seen_rt = last.lines().any(|l| bre(rt_wire).is_match(l));
        if seen_rt {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::ensure!(
        seen_rt,
        "ExaBGP never parsed router-a's route target: {last}"
    );
    anyhow::ensure!(
        !last
            .lines()
            .any(|l| bre("extended-community .* payload .*4300 0000 0000 000").is_match(l)),
        "a non-transitive extended community reached ExaBGP: {last}"
    );

    log("StayRTR goes away: its VRPs expire after 10s and the prefix is not-found");
    let not_found = format!("{} .*validation_state=NotFound", learned());
    let not_found_before = a.count(&not_found);
    let refreshes = a.count("rpki change: requesting route refresh");
    w.dock.container_remove(RPKI_CACHE).await;
    a.wait("rpki data expired").await?;
    a.wait_new(
        &format!("rpki change: requesting route refresh .*peer={IP_B}"),
        refreshes,
        30,
    )
    .await?;
    a.wait_new(&not_found, not_found_before, 30).await?;
    expect_route_state(a, REDISTRIBUTE_PREFIX, "NotFound", true).await?;
    anyhow::ensure!(
        a.count("bgp session established") == sessions,
        "a VRP change reset the BGP session"
    );

    rpki_cache_auth(w).await
}

/// #498, RFC 8210 §9: the RTR session to a cache that requires TCP-MD5
/// (`nos-rtr-stub`, because StayRTR cannot sign its session).
///
/// - router-a is configured with the wrong key: the kernel drops the unsigned
///   SYN-ACK, the cache is unreachable and the stub accepts nothing;
/// - with the right key the session comes up (RTR v1, one VRP) and
///   `GET /v1/bgp/rpki` reports it active and `authenticated`.
async fn rpki_cache_auth(w: &mut World) -> anyhow::Result<()> {
    w.dock
        .start_nos_tool(
            RTR_STUB,
            NET,
            IP_RTR_STUB,
            &[
                "nos-rtr-stub",
                "0.0.0.0:323",
                "192.0.2.0/24",
                "24",
                "64496",
                RTR_STUB_KEY,
                IP_A,
            ],
            &["NET_ADMIN"],
        )
        .await?;
    let a = w.a()?;
    let cache = format!("cache={IP_RTR_STUB}:323");
    let with_key = |key: &str| {
        let mut flags = A.base_flags();
        flags.extend(strings(&[
            "--rpki-cache",
            &format!("{IP_RTR_STUB}:323"),
            "--rpki-cache-md5-password",
            key,
        ]));
        flags
    };

    log("a wrong key: the unsigned SYN-ACK is dropped and the stub accepts nothing");
    a.provision_flags(&with_key("not-the-key")).await?;
    a.wait(&format!("rpki cache unreachable {cache}")).await?;
    anyhow::ensure!(
        !w.dock.logs(RTR_STUB).await?.contains("accepted"),
        "the stub accepted a session signed with the wrong key"
    );

    log("the right key: the session comes up and is reported authenticated");
    let a = w.a()?;
    a.provision_flags(&with_key(RTR_STUB_KEY)).await?;
    a.wait(&format!("rpki cache connected {cache} version=1"))
        .await?;
    a.wait(&format!("rpki end of data {cache} .*vrps=1"))
        .await?;
    let summary = a
        .rest_expect(Method::GET, "/v1/bgp/rpki", None, 200)
        .await?;
    let entry = summary
        .split("\"address\":")
        .find(|e| e.starts_with(&format!("\"{IP_RTR_STUB}\"")))
        .unwrap_or_default();
    anyhow::ensure!(
        entry.contains("\"state\":\"Established\"")
            && entry.contains("\"active\":true")
            && entry.contains("\"authenticated\":true"),
        "GET /v1/bgp/rpki does not show the signed session in use: {summary}"
    );
    anyhow::ensure!(
        w.dock
            .logs(RTR_STUB)
            .await?
            .contains(&format!("accepted peer={IP_A}")),
        "the stub never accepted router-a"
    );
    Ok(())
}

/// GoBGP release image, built once — same recipe as `tools/bench-bgp.sh`.
fn gobgp_dockerfile() -> String {
    format!(
        "FROM debian:bookworm-slim\n\
         RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \\\n \
         && curl -fsSL https://github.com/osrg/gobgp/releases/download/v{GOBGP_VERSION}/gobgp_{GOBGP_VERSION}_linux_amd64.tar.gz \\\n \
         | tar -xz -C /usr/local/bin gobgp gobgpd \\\n \
         && apt-get purge -y --auto-remove curl && rm -rf /var/lib/apt/lists/*\n"
    )
}

/// Runs one `gobgp` CLI command inside the GoBGP container; its output.
pub(super) async fn gobgp(w: &World, args: &[&str]) -> anyhow::Result<String> {
    let mut cmd = vec!["gobgp"];
    cmd.extend_from_slice(args);
    let (code, out) = w.dock.exec("router-g", &cmd).await?;
    if code != 0 {
        bail!("gobgp {}: exit {code}: {}", args.join(" "), out.trim());
    }
    Ok(out)
}

/// router-a's flags for both EVPN phases: one eBGP peer-group toward GoBGP
/// with `address-family l2vpn-evpn`.
fn evpn_flags() -> Vec<String> {
    strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--peer-group",
        "pg-evpn",
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
        "--evpn",
    ])
}

/// #866: soft reconfiguration inbound on an EVPN peer. Enabling asks GoBGP
/// for a refresh (it answers EVPN); a reject-all EVPN import policy then
/// takes the Type-3 route out of `show bgp evpn` in place, accept-all brings
/// it back from the retained copy, and neither restarts the session.
async fn evpn_soft_reconfig<F, Fut>(a: &Router, show: &F) -> anyhow::Result<()>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<String>>,
{
    let flag = "--soft-reconfiguration-inbound";
    let with = |extra: &[&str]| {
        let mut f = evpn_flags();
        f.extend(strings(extra));
        f
    };
    log("soft reconfiguration (#866): enabling on router-a's live EVPN session");
    let (sessions, enabled, refresh) = (
        a.count("bgp session established"),
        a.count("soft reconfiguration: retention enabled"),
        a.count("sent route refresh request"),
    );
    a.provision_flags(&with(&[flag])).await?;
    a.wait_new("soft reconfiguration: retention enabled", enabled, 30)
        .await?;
    a.wait_new("sent route refresh request", refresh, 30)
        .await?;
    a.assert_quiet("bgp session established", sessions, 6)
        .await?;
    tokio::time::sleep(Duration::from_secs(3)).await;

    let reeval = |accepted: u32| {
        format!(
            "re-evaluated import policy peer={IP_G} family=l2vpn-evpn retained=[0-9]* accepted={accepted} "
        )
    };
    log("a reject-all EVPN import policy applies in place");
    let reject = policy_file("evpn-reject-soft", "reject\n")?;
    let (rejected, dropped, refresh) = (
        a.count(&reeval(0)),
        a.count("evpn route rejected by import policy"),
        a.count("sent route refresh request"),
    );
    a.provision_flags(&with(&[
        flag,
        "--policy-name",
        "evpn-reject-soft",
        "--policy-source-file",
        &reject,
        "--evpn-import-policy",
        "evpn-reject-soft",
    ]))
    .await?;
    a.wait_new(&reeval(0), rejected, 30).await?;
    a.wait_new("evpn route rejected by import policy", dropped, 30)
        .await?;
    a.assert_quiet("bgp session established", sessions, 6)
        .await?;
    if show().await?.contains("\"route_type\":3") {
        bail!("a rejected EVPN route is still in show bgp evpn");
    }

    log("accept-all brings it back from the retained copy, no new route refresh");
    let accepted = a.count(&reeval(1));
    a.provision_flags(&with(&[flag, "--evpn-import-policy", "accept-all"]))
        .await?;
    a.wait_new(&reeval(1), accepted, 30).await?;
    a.assert_quiet("bgp session established", sessions, 6)
        .await?;
    a.assert_quiet("sent route refresh request", refresh, 3)
        .await?;
    if !show().await?.contains("\"route_type\":3") {
        bail!("the retained EVPN route did not come back");
    }

    log("`soft-in` re-evaluates the EVPN routes locally");
    let body = a
        .rest_expect(
            Method::POST,
            &format!("/v1/bgp/r1/peer/{IP_G}/soft-in"),
            None,
            200,
        )
        .await?;
    anyhow::ensure!(
        body.contains("\"route_refresh\":\"none\"") && body.contains("l2vpn-evpn"),
        "soft-in reply: {body}"
    );
    Ok(())
}

/// Starts router-a with `evpn_flags` (and `watchdog_args`), builds/starts the GoBGP speaker
/// (router-g) peering it over l2vpn-evpn, and waits for the session and
/// gobgpd's gRPC API.
async fn evpn_speaker(w: &mut World, watchdog_args: &[&str]) -> anyhow::Result<()> {
    gobgp_speaker(w, evpn_flags(), &["l2vpn-evpn"], watchdog_args).await
}

/// `evpn_speaker` for any AFI-SAFI list (`afi_safis`: GoBGP's spelling, which
/// is also the neighbor's `afi-safi-name`).
async fn gobgp_speaker(
    w: &mut World,
    flags: Vec<String>,
    afi_safis: &[&str],
    watchdog_args: &[&str],
) -> anyhow::Result<()> {
    w.start(A, Some(flags), watchdog_args).await?;
    start_gobgp(w, afi_safis).await
}

/// Builds/starts the GoBGP speaker (router-g) peering router-a over
/// `afi_safis`, and waits for a router-a session and gobgpd's gRPC API.
pub(super) async fn start_gobgp(w: &World, afi_safis: &[&str]) -> anyhow::Result<()> {
    start_gobgp_as(w, afi_safis, ASN_G).await
}

/// `start_gobgp` with GoBGP in AS `asn` (`ASN_A` makes it an iBGP peer).
async fn start_gobgp_as(w: &World, afi_safis: &[&str], asn: u32) -> anyhow::Result<()> {
    start_gobgp_gr(w, afi_safis, asn, false).await
}

/// `start_gobgp_as`, with `gr`: RFC 4724 graceful restart (restart and helper
/// roles) enabled for every family in `afi_safis`.
async fn start_gobgp_gr(w: &World, afi_safis: &[&str], asn: u32, gr: bool) -> anyhow::Result<()> {
    log("building/starting the GoBGP speaker (router-g)");
    w.dock
        .ensure_image(GOBGP_IMAGE, &gobgp_dockerfile())
        .await?;
    let mut conf = format!(
        "[global.config]\n  as = {asn}\n  router-id = \"{RID_G}\"\n\n\
         [[neighbors]]\n  [neighbors.config]\n    neighbor-address = \"{IP_A}\"\n    peer-as = {ASN_A}\n  \
         [neighbors.transport.config]\n    local-address = \"{IP_G}\"\n  \
         [neighbors.timers.config]\n    connect-retry = 5\n"
    );
    if gr {
        conf.push_str(
            "  [neighbors.graceful-restart.config]\n    enabled = true\n    restart-time = 120\n",
        );
    }
    for n in afi_safis {
        let _ = write!(
            conf,
            "  [[neighbors.afi-safis]]\n    [neighbors.afi-safis.config]\n      afi-safi-name = \"{n}\"\n"
        );
        if gr {
            conf.push_str(
                "    [neighbors.afi-safis.mp-graceful-restart.config]\n      enabled = true\n",
            );
        }
    }
    w.dock
        .start_plain(
            "router-g",
            GOBGP_IMAGE,
            NET,
            IP_G,
            &["gobgpd", "-f", "/etc/gobgpd.toml"],
            ("/etc", "gobgpd.toml", conf.as_bytes()),
        )
        .await?;

    let a = w.a()?;
    a.established().await?;
    // gobgpd's gRPC API can lag its BGP listener by a moment.
    let mut ready = Err(anyhow::anyhow!("gobgpd never answered"));
    for _ in 0..30 {
        ready = gobgp(w, &["global"]).await.map(drop);
        if ready.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    ready
}

/// router-a's flags for the flowspec phase: `evpn_flags` with Flowspec
/// instead of EVPN.
fn flowspec_flags() -> Vec<String> {
    evpn_flags()
        .into_iter()
        .map(|f| match f.as_str() {
            "--evpn" => "--flowspec".to_string(),
            "pg-evpn" => "pg-flowspec".to_string(),
            _ => f,
        })
        .collect()
}

/// RFC 8955/8956 Flowspec, receive side (#558). GoBGP originates one IPv4 and
/// one IPv6 rule (destination, TCP, port 25, traffic-rate 0 = discard);
/// router-a, with `address-family ipv4-flowspec`/`ipv6-flowspec` on its
/// peer-group, must negotiate SAFI 133, decode both (the action community
/// from another implementation's encoding), serve them on `show bgp
/// flowspec` (`GET /v1/bgp/flowspec`) and drop them on an explicit
/// withdrawal. RFC 8955 section 6 validation (#559): with no covering unicast
/// route each rule is `invalid:no-covering-unicast-route`; GoBGP announcing a
/// covering prefix flips it to `valid` (revalidation, logged as `flowspec
/// validity changed`) and withdrawing that prefix flips it back.
/// RFC 9117 (#572): an iBGP GoBGP flow with an empty AS_PATH is valid
/// without a covering route; `rfc8955-strict` makes it invalid.
/// Propagation (#560): router-a re-advertises the valid IPv4 rule (never the
/// invalid IPv6 one) to router-b over eBGP; router-b's Flowspec import
/// policy (matching the destination prefix) and router-a's Flowspec export
/// policy each stop it, and the covering prefix's withdrawal withdraws it
/// from router-b. Nothing is enforced (no dataplane).
pub async fn flowspec(w: &mut World) -> anyhow::Result<()> {
    gobgp_speaker(
        w,
        flowspec_flags(),
        &["ipv4-unicast", "ipv4-flowspec", "ipv6-flowspec"],
        &[],
    )
    .await?;
    // router-b peers router-a over eBGP, Flowspec on both ends.
    let a_to_b = |extra: &[&str]| {
        let mut f = strings(&[
            "--address",
            &format!("{IP_A}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--peer-group",
            "pg-b",
            "--remote-as",
            &ASN_B.to_string(),
            "--peer",
            IP_B,
            "--flowspec",
        ]);
        f.extend(strings(extra));
        f
    };
    let b_flags = |extra: &[&str]| {
        let mut f = B.base_flags();
        f.push("--flowspec".into());
        f.extend(strings(extra));
        f
    };
    w.a()?.provision_flags(&a_to_b(&[])).await?;
    w.start(B, Some(b_flags(&[])), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    b.established().await?;

    let rules: [(&str, &[&str], &str); 2] = [
        (
            "ipv4-flowspec",
            &["destination", "192.0.2.0/24"],
            "dest 192.0.2.0/24",
        ),
        (
            "ipv6-flowspec",
            &["destination", "2001:db8:f::/48"],
            "dest 2001:db8:f::/48",
        ),
    ];
    let rule = |family: &str, dest: &[&str], verb: &'static str| {
        let mut args = vec!["global", "rib", verb, "-a", family, "match"];
        args.extend_from_slice(dest);
        args.extend_from_slice(&["protocol", "tcp", "destination-port", "==25"]);
        if verb == "add" {
            args.extend_from_slice(&["then", "discard"]);
        }
        args.into_iter().map(str::to_string).collect::<Vec<_>>()
    };
    for (family, dest, _) in &rules {
        gobgp_owned(w, rule(family, dest, "add")).await?;
    }

    let learned = |family: &str| format!("flowspec route learned peer={IP_G} family={family}");
    let withdrawn = |family: &str| format!("flowspec route withdrawn peer={IP_G} family={family}");
    for (family, ..) in &rules {
        a.wait(&learned(family)).await?;
    }

    // `show bgp flowspec`, over REST: the components and the traffic-rate
    // community, decoded from another implementation's encoding.
    let show = || a.rest_expect(reqwest::Method::GET, "/v1/bgp/flowspec", None, 200);
    let body = show().await?;
    for want in [
        "dest 192.0.2.0/24",
        "dest 2001:db8:f::/48",
        "proto =6",
        "dst-port =25",
        "traffic-rate:0:0",
        IP_G,
    ] {
        if !body.contains(want) {
            bail!("show bgp flowspec is missing {want}: {body}");
        }
    }
    log("flowspec rules walked one per page come back once each (#723)");
    expect_paged_walk(a, "/v1/bgp/flowspec", rules.len()).await?;

    // RFC 8955 section 6: no unicast route covers either destination yet.
    let changed = |family: &str, validity: &str| {
        format!("flowspec validity changed peer={IP_G} family={family}.*validity={validity}")
    };
    for (family, ..) in &rules {
        a.wait(&changed(family, "invalid:no-covering-unicast-route"))
            .await?;
    }
    let body = show().await?;
    for want in ["invalid:no-covering-unicast-route", "discard"] {
        if !body.contains(want) {
            bail!("show bgp flowspec is missing {want}: {body}");
        }
    }

    // The sender also announces a covering unicast prefix: the IPv4 rule turns
    // valid. IPv4 only: the session is IPv4 and the lab network gives no
    // router an IPv6 address, so an IPv6 unicast next hop would stay
    // unresolvable and never reach the Loc-RIB (IPv6 is covered by unit
    // tests); the IPv6 rule stays invalid.
    let (family, prefix) = ("ipv4", "192.0.0.0/16");
    let base = a.count(&changed("ipv4-flowspec", "valid"));
    gobgp(w, &["global", "rib", "add", "-a", family, prefix]).await?;
    a.wait_new(&changed("ipv4-flowspec", "valid"), base, 30)
        .await?;
    let body = show().await?;
    if !body.contains("\"validity\":\"valid\"") || !body.contains("invalid:") {
        bail!("expected the IPv4 rule valid and the IPv6 one invalid: {body}");
    }

    flowspec_propagation(w, &a_to_b, &b_flags).await?;
    let (a, b) = (w.a()?, w.b()?);

    // Withdrawing the covering prefix revalidates it again, and router-b
    // loses the rule.
    let invalid = changed("ipv4-flowspec", "invalid:no-covering-unicast-route");
    let base = a.count(&invalid);
    let b_withdrawn = format!("flowspec route withdrawn peer={IP_A} family=ipv4-flowspec");
    let b_base = b.count(&b_withdrawn);
    gobgp(w, &["global", "rib", "del", "-a", family, prefix]).await?;
    a.wait_new(&invalid, base, 30).await?;
    b.wait_new(&b_withdrawn, b_base, 30).await?;

    log("withdrawing the IPv4 rule explicitly");
    let base = a.count(&withdrawn("ipv4-flowspec"));
    gobgp_owned(w, rule(rules[0].0, rules[0].1, "del")).await?;
    a.wait_new(&withdrawn("ipv4-flowspec"), base, 30).await?;
    let body = show().await?;
    if body.contains("dest 192.0.2.0/24") || !body.contains("dest 2001:db8:f::/48") {
        bail!("expected only the IPv6 rule after the withdrawal: {body}");
    }
    flowspec_rfc9117(w).await
}

/// RFC 9117 (#572), the default procedure: GoBGP turns iBGP and announces a
/// flow with an empty AS_PATH and no covering unicast route. Rule (b.2)
/// makes it valid; `rfc8955-strict` makes it `no-covering-unicast-route`.
async fn flowspec_rfc9117(w: &World) -> anyhow::Result<()> {
    log("RFC 9117: GoBGP as an iBGP controller, empty AS_PATH, no covering route");
    w.dock.container_remove("router-g").await;
    let a = w.a()?;
    a.edit(|c| {
        for g in c
            .bgp_instances
            .iter_mut()
            .flat_map(|i| i.peer_groups.iter_mut())
        {
            if g.name == "pg-flowspec" {
                g.remote_as = ASN_A;
            }
        }
        Ok(())
    })
    .await?;
    start_gobgp_as(w, &["ipv4-unicast", "ipv4-flowspec"], ASN_A).await?;
    let a = w.a()?;
    let changed = |validity: &str| {
        format!("flowspec validity changed peer={IP_G} family=ipv4-flowspec.*validity={validity}")
    };
    let base = a.count(&changed("valid"));
    gobgp(
        w,
        &[
            "global",
            "rib",
            "add",
            "-a",
            "ipv4-flowspec",
            "match",
            "destination",
            "198.51.100.0/24",
            "protocol",
            "tcp",
            "destination-port",
            "==25",
            "then",
            "discard",
        ],
    )
    .await?;
    a.wait_new(&changed("valid"), base, 60).await?;

    log("rfc8955-strict restores the no-covering-unicast-route result");
    let (sessions, base) = (
        a.count("bgp session established"),
        a.count(&changed("invalid:no-covering-unicast-route")),
    );
    a.edit(|c| {
        for g in c
            .bgp_instances
            .iter_mut()
            .flat_map(|i| i.peer_groups.iter_mut())
        {
            if g.name == "pg-flowspec" {
                g.flowspec_validation.rfc8955_strict = true;
            }
        }
        Ok(())
    })
    .await?;
    reestablished(a, sessions).await?;
    a.wait_new(&changed("invalid:no-covering-unicast-route"), base, 60)
        .await
}

/// The #560 half of `flowspec`, run while router-a holds GoBGP's IPv4 rule
/// as valid and its IPv6 one as invalid: router-b learns and validates the
/// IPv4 rule only; its import policy, then router-a's export policy, keep it
/// out (each change restarts the session), and accept-all brings it back.
async fn flowspec_propagation(
    w: &World,
    a_to_b: &dyn Fn(&[&str]) -> Vec<String>,
    b_flags: &dyn Fn(&[&str]) -> Vec<String>,
) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let learned = format!("flowspec route learned peer={IP_A} family=ipv4-flowspec");
    let b_show = || b.rest_expect(Method::GET, "/v1/bgp/flowspec", None, 200);

    log("router-a re-advertises the valid IPv4 rule to router-b, not the invalid IPv6 one");
    a.wait(&format!(
        "flowspec route advertised peer={IP_B} family=ipv4-flowspec"
    ))
    .await?;
    b.wait(&learned).await?;
    b.wait(&format!(
        "flowspec validity changed peer={IP_A} family=ipv4-flowspec.*validity=valid"
    ))
    .await?;
    let body = b_show().await?;
    for want in ["dest 192.0.2.0/24", "traffic-rate:0:0", "discard", IP_A] {
        if !body.contains(want) {
            bail!("router-b's show bgp flowspec is missing {want}: {body}");
        }
    }
    if body.contains("2001:db8:f::/48") {
        bail!("an invalid rule was propagated to router-b: {body}");
    }

    log("router-b's flowspec import policy rejects the rule by its destination prefix");
    let reject = policy_file(
        "flowspec-reject-dest",
        "if this.prefix == 192.0.2.0/24:\n    reject\naccept\n",
    )?;
    let rejected =
        format!("flowspec route rejected by import policy peer={IP_A} family=ipv4-flowspec");
    let (base, sessions) = (b.count(&rejected), b.count("bgp session established"));
    b.provision_flags(&b_flags(&[
        "--policy-name",
        "flowspec-reject-dest",
        "--policy-source-file",
        &reject,
        "--flowspec-import-policy",
        "flowspec-reject-dest",
    ]))
    .await?;
    reestablished(b, sessions).await?;
    b.wait_new(&rejected, base, 60).await?;
    if b_show().await?.contains("dest 192.0.2.0/24") {
        bail!("router-b still shows a rule its import policy rejects");
    }
    let (base, sessions) = (b.count(&learned), b.count("bgp session established"));
    b.provision_flags(&b_flags(&["--flowspec-import-policy", "accept-all"]))
        .await?;
    reestablished(b, sessions).await?;
    b.wait_new(&learned, base, 60).await?;

    flowspec_soft_reconfig(w, b_flags).await?;

    log("router-a's flowspec export policy toward router-b keeps the rule from it");
    let deny = policy_file("flowspec-export-deny", "reject\n")?;
    let (base, sessions) = (b.count(&learned), b.count("bgp session established"));
    a.provision_flags(&a_to_b(&[
        "--policy-name",
        "flowspec-export-deny",
        "--policy-source-file",
        &deny,
        "--flowspec-export-policy",
        "flowspec-export-deny",
    ]))
    .await?;
    reestablished(b, sessions).await?;
    b.assert_quiet(&learned, base, 15).await?;
    if b_show().await?.contains("dest 192.0.2.0/24") {
        bail!("router-a advertised a rule its export policy rejects");
    }
    let sessions = b.count("bgp session established");
    a.provision_flags(&a_to_b(&["--flowspec-export-policy", "accept-all"]))
        .await?;
    reestablished(b, sessions).await?;
    b.wait_new(&learned, base, 60).await
}

/// #866: router-b keeps the raw Flowspec rules router-a sends, so the import
/// policy flip that restarts the session above is applied in place: the rule
/// leaves `show bgp flowspec` and comes back from the retained copy, with no
/// new session and no new route refresh.
async fn flowspec_soft_reconfig(
    w: &World,
    b_flags: &dyn Fn(&[&str]) -> Vec<String>,
) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let flag = "--soft-reconfiguration-inbound";
    let b_show = || b.rest_expect(Method::GET, "/v1/bgp/flowspec", None, 200);
    log("soft reconfiguration (#866): enabling on router-b's live session");
    let (sessions, enabled, resent) = (
        b.count("bgp session established"),
        b.count("soft reconfiguration: retention enabled"),
        a.count("bgp: received route refresh, resending loc-rib"),
    );
    b.provision_flags(&b_flags(&[flag, "--flowspec-import-policy", "accept-all"]))
        .await?;
    b.wait_new("soft reconfiguration: retention enabled", enabled, 30)
        .await?;
    a.wait_new("bgp: received route refresh, resending loc-rib", resent, 30)
        .await?;
    b.assert_quiet("bgp session established", sessions, 6)
        .await?;

    let reeval = |accepted: u32| {
        format!(
            "re-evaluated import policy peer={IP_A} family=ipv4-flowspec retained=[0-9]* accepted={accepted} "
        )
    };
    log("tightening the flowspec import policy in place: the rule leaves, the session stays");
    let reject = policy_file(
        "flowspec-reject-soft",
        "if this.prefix == 192.0.2.0/24:\n    reject\naccept\n",
    )?;
    let (rejected, refresh) = (b.count(&reeval(0)), b.count("sent route refresh request"));
    b.provision_flags(&b_flags(&[
        flag,
        "--policy-name",
        "flowspec-reject-soft",
        "--policy-source-file",
        &reject,
        "--flowspec-import-policy",
        "flowspec-reject-soft",
    ]))
    .await?;
    b.wait_new(&reeval(0), rejected, 30).await?;
    b.assert_quiet("bgp session established", sessions, 6)
        .await?;
    if b_show().await?.contains("dest 192.0.2.0/24") {
        bail!("router-b still shows a rule its import policy rejects");
    }

    log("loosening it: the retained copy brings the rule back, no new route refresh");
    let learned = format!("flowspec route learned peer={IP_A} family=ipv4-flowspec");
    let (accepted, learned_before) = (b.count(&reeval(1)), b.count(&learned));
    b.provision_flags(&b_flags(&[flag, "--flowspec-import-policy", "accept-all"]))
        .await?;
    b.wait_new(&reeval(1), accepted, 30).await?;
    b.wait_new(&learned, learned_before, 30).await?;
    b.assert_quiet("bgp session established", sessions, 6)
        .await?;
    b.assert_quiet("sent route refresh request", refresh, 3)
        .await?;
    if !b_show().await?.contains("dest 192.0.2.0/24") {
        bail!("router-b lost the rule after the in-place re-evaluation");
    }
    Ok(())
}

/// RFC 4364/4659 VPN-IPv4/VPN-IPv6 (SAFI 128), receive side (#578). GoBGP
/// announces labelled VPN routes to router-a, whose peer-group has
/// `address-family vpnv4`/`vpnv6`: router-a must negotiate AFI 1/2 SAFI 128,
/// decode the label, RD and Route Target from another implementation's
/// encoding, keep one prefix under two RDs as two routes, serve them on
/// `show bgp vpnv4|vpnv6` (`GET /v1/bgp/vpnv4|vpnv6`, `?rd=` filtered), and
/// drop them on an explicit withdrawal and when the session goes away.
///
/// VRF import (#579): router-a's `VPN_TABLE` imports RT 65000:1 from r1, so
/// GoBGP's routes land there as `Vpn` routes (label, PE next hop resolved in
/// rt1), a foreign-RT route does not, moving the import RT over REST swaps
/// them, and a withdrawal or the session's end unimports.
pub async fn vpn(w: &mut World) -> anyhow::Result<()> {
    gobgp_speaker(
        w,
        vpn_flags("65000:1"),
        &["l3vpn-ipv4-unicast", "l3vpn-ipv6-unicast"],
        &[],
    )
    .await?;
    mpls_ready(w, &["router-a"]).await?;
    let a = w.a()?;
    a.wait(&format!(
        "address families negotiated peer={IP_G} families=\\[.*\"vpnv4\", \"vpnv6\"\\]"
    ))
    .await?;

    // (family, prefix, label, rd); GoBGP sends an AFI 2 next hop IPv4-mapped.
    let routes = [
        ("vpnv4", "10.10.0.0/24", "100", "65001:1"),
        ("vpnv4", "10.10.0.0/24", "200", "65001:2"),
        ("vpnv6", "2001:db8:10::/48", "300", "65001:1"),
    ];
    let rib = |verb: &'static str, (family, prefix, label, rd): (&str, &str, &str, &str)| {
        let mut v = vec![
            "global", "rib", verb, "-a", family, prefix, "label", label, "rd", rd,
        ];
        if verb == "add" {
            v.extend(["rt", "65000:1"]);
        }
        v.into_iter().map(str::to_string).collect::<Vec<_>>()
    };
    for r in routes {
        gobgp_owned(w, rib("add", r)).await?;
    }
    for (family, prefix, label, rd) in routes {
        a.wait(&format!(
            "vpn route learned peer={IP_G} family={family} rd={rd} prefix={prefix} labels=\\[{label}\\] next_hop={IP_G}"
        ))
        .await?;
    }
    // Before the later steps add more: GoBGP's two RDs of 10.10.0.0/24.
    log("vpn paths walked one per page come back once each, the RD filter kept (#723)");
    expect_paged_walk(a, "/v1/bgp/vpnv4", 2).await?;
    expect_paged_walk(a, "/v1/bgp/vpnv4?rd=65001:2", 1).await?;
    vrf_import(w, &vpn_flags).await?;
    vpn_soo_and_policy(w, &vpn_flags).await?;

    let show = |q: &str| {
        let path = format!("/v1/bgp/{q}");
        async move { a.rest_expect(Method::GET, &path, None, 200).await }
    };
    let body = show("vpnv4").await?;
    for want in [
        "\"rd\":\"65001:1\"",
        "\"rd\":\"65001:2\"",
        "\"labels\":[100]",
        "\"labels\":[200]",
        "RT:65000:1",
        "\"best\":true",
    ] {
        if !body.contains(want) {
            bail!("show bgp vpnv4 is missing {want}: {body}");
        }
    }
    if body.matches("10.10.0.0/24").count() != 2 {
        bail!("one prefix under two RDs must be two routes: {body}");
    }
    let body = show("vpnv4?rd=65001:2").await?;
    if !body.contains("\"labels\":[200]") || body.contains("\"labels\":[100]") {
        bail!("show bgp vpnv4 rd 65001:2 is not filtered: {body}");
    }
    let body = show("vpnv6").await?;
    if !body.contains("2001:db8:10::/48") || !body.contains("\"labels\":[300]") {
        bail!("show bgp vpnv6 is missing GoBGP's route: {body}");
    }

    vpn_soft_reconfig(w, &vpn_flags).await?;

    log("withdrawing the second RD's route explicitly");
    let withdrawn = |family: &str, rd: &str, prefix: &str| {
        format!("vpn route withdrawn peer={IP_G} family={family} rd={rd} prefix={prefix}")
    };
    let gone = withdrawn("vpnv4", "65001:2", "10.10.0.0/24");
    let base = a.count(&gone);
    gobgp_owned(w, rib("del", routes[1])).await?;
    a.wait_new(&gone, base, 30).await?;
    let body = show("vpnv4").await?;
    if body.contains("65001:2") || !body.contains("65001:1") {
        bail!("expected only RD 65001:1 after the withdrawal: {body}");
    }

    log("removing the speaker: its remaining VPN routes must go with the session");
    let (v4, v6) = (
        withdrawn("vpnv4", "65001:1", "10.10.0.0/24"),
        withdrawn("vpnv6", "65001:1", "2001:db8:10::/48"),
    );
    let (b4, b6) = (a.count(&v4), a.count(&v6));
    let unimported = |p: &str| format!("vpn route unimported table={VPN_TABLE} prefix={p}");
    let (u4, u6) = (unimported("10.10.0.0/24"), unimported("2001:db8:10::/48"));
    let (c4, c6) = (a.count(&u4), a.count(&u6));
    w.dock.container_remove("router-g").await;
    a.wait_new(&v4, b4, 60).await?;
    a.wait_new(&v6, b6, 60).await?;
    a.wait_new(&u4, c4, 30).await?;
    a.wait_new(&u6, c6, 30).await?;
    if vrf_routes(a).await?.contains("\"Vpn\"") {
        bail!("{VPN_TABLE} kept VPN routes after the session went away");
    }
    for q in ["vpnv4", "vpnv6"] {
        let body = show(q).await?;
        if body.contains("\"prefix\"") {
            bail!("VPN routes outlived their session: {body}");
        }
    }
    vpn_chunked(w).await
}

/// #866: soft reconfiguration inbound on a VPN peer. A reject policy for
/// 10.10.0.0/24 (both RDs) drops it from `show bgp vpnv4` and the VRF in
/// place; accepting again brings both RDs back from the raw retained copies,
/// with no new session and no new route refresh.
async fn vpn_soft_reconfig(
    w: &World,
    vpn_flags: &dyn Fn(&str) -> Vec<String>,
) -> anyhow::Result<()> {
    let a = w.a()?;
    let flag = ["--soft-reconfiguration-inbound"];
    let with = |extra: &[&str]| {
        let mut f = vpn_flags("65000:1");
        f.extend(strings(extra));
        f
    };
    let show = || a.rest_expect(Method::GET, "/v1/bgp/vpnv4", None, 200);
    log("soft reconfiguration (#866): enabling on router-a's live session");
    let (sessions, enabled, refresh) = (
        a.count("bgp session established"),
        a.count("soft reconfiguration: retention enabled"),
        a.count("sent route refresh request"),
    );
    a.provision_flags(&with(&flag)).await?;
    a.wait_new("soft reconfiguration: retention enabled", enabled, 30)
        .await?;
    a.wait_new("sent route refresh request", refresh, 30)
        .await?;
    a.assert_quiet("bgp session established", sessions, 6)
        .await?;
    // The refresh answer is asynchronous: wait for GoBGP to have sent it.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let reeval = |accepted: u32| {
        format!(
            "re-evaluated import policy peer={IP_G} family=vpnv4 retained=[0-9]* accepted={accepted} "
        )
    };
    log("rejecting 10.10.0.0/24 in place: both RDs leave the table and the VRF");
    let reject = policy_file(
        "vpn-reject-soft",
        "if this.prefix == 10.10.0.0/24:\n    reject\naccept\n",
    )?;
    let unimported = format!("vpn route unimported table={VPN_TABLE} prefix=10.10.0.0/24");
    let (rejected, gone, refresh) = (
        a.count(&reeval(0)),
        a.count(&unimported),
        a.count("sent route refresh request"),
    );
    let mut tight = strings(&flag);
    tight.extend(strings(&[
        "--policy-name",
        "vpn-reject-soft",
        "--policy-source-file",
        &reject,
        "--import-policy",
        "vpn-reject-soft",
    ]));
    a.provision_flags(&with(&tight.iter().map(String::as_str).collect::<Vec<_>>()))
        .await?;
    a.wait_new(&reeval(0), rejected, 30).await?;
    a.wait_new(&unimported, gone, 30).await?;
    a.assert_quiet("bgp session established", sessions, 6)
        .await?;
    if show().await?.contains("10.10.0.0/24") {
        bail!("a rejected VPN prefix is still in show bgp vpnv4");
    }

    log("accepting it again: both RDs return from the retained copies, no new refresh");
    let accepted = a.count(&reeval(2));
    a.provision_flags(&with(&[
        "--soft-reconfiguration-inbound",
        "--import-policy",
        "accept-all",
    ]))
    .await?;
    a.wait_new(&reeval(2), accepted, 30).await?;
    a.assert_quiet("bgp session established", sessions, 6)
        .await?;
    a.assert_quiet("sent route refresh request", refresh, 3)
        .await?;
    let body = show().await?;
    if body.matches("10.10.0.0/24").count() != 2 {
        bail!("both RDs of 10.10.0.0/24 must be back: {body}");
    }
    Ok(())
}

/// `VPN_TABLE`'s routes from the `10.100.0.0/16` burst, over REST (20 000
/// `added route` lines overrun the harness's log follower).
async fn vpn_burst_in_table(a: &Router) -> anyhow::Result<usize> {
    Ok(a.routes_walk(VPN_TABLE, None)
        .await?
        .iter()
        .filter(|p| {
            p["prefix"]
                .as_str()
                .is_some_and(|s| s.starts_with("10.100."))
                && p["candidates"][0]["source"] == "Vpn"
        })
        .count())
}

/// Polls until `vpn_burst_in_table` is `want`, for at most `secs`.
async fn wait_vpn_burst(a: &Router, want: usize, secs: u64) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    loop {
        let n = vpn_burst_in_table(a).await?;
        if n == want {
            log(format!(
                "{VPN_TABLE} holds {n} burst routes after {}s",
                started.elapsed().as_secs()
            ));
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(secs) {
            bail!("{VPN_TABLE} holds {n} of {want} burst routes after {secs}s");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// `vpn`'s chunked stage (#715): GoBGP (restarted) announces
/// `VPN_CHUNKED_ROUTES` VPNv4 /32s, heavier than one `PushVpnRoutes` frame
/// (`VPN_PUSH_CHUNK`). Killing `VPN_TABLE`'s `nos-ribd` (only that one) makes
/// `nos-bgpd` resend the whole set as one `Full` on reconnect: two frames,
/// which the new `nos-ribd` must assemble and apply once. Killing `nos-bgpd`
/// instead would not do: without a graceful-restart deferral (the underlay
/// holds no BGP route here) a fresh `nos-bgpd` pushes an empty `Full` at once
/// and the routes come back as `Add`s. Removing the speaker then withdraws
/// them all.
async fn vpn_chunked(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    start_gobgp(w, &["l3vpn-ipv4-unicast"]).await?;
    let n = VPN_CHUNKED_ROUTES;
    log(format!("GoBGP announces {n} VPNv4 routes into {VPN_TABLE}"));
    let announce = format!(
        "seq 0 {} | xargs -P 16 -I{{}} sh -c 'i={{}}; gobgp global rib add -a vpnv4 \
         10.100.$((i/250)).$((i%250+1))/32 label 1000 rd 65001:9 rt 65000:1'",
        n - 1
    );
    let (code, out) = w.dock.exec("router-g", &["sh", "-c", &announce]).await?;
    if code != 0 {
        bail!("announcing the burst: exit {code}: {}", out.trim());
    }
    wait_vpn_burst(a, n, 600).await?;
    let _ = crate::logd_mem::sample(w, a, "vpn-burst").await;

    log(format!(
        "killing {VPN_TABLE}'s nos-ribd: the reconnect Full is chunked"
    ));
    let assembled = format!(
        "assembled chunked vpn route snapshot table={VPN_TABLE} routes=20[0-9][0-9][0-9] parts=2"
    );
    let base = a.count(&assembled);
    w.dock
        .kill_process_matching("router-a", "nos-ribd", &format!("--table {VPN_TABLE} "))
        .await?;
    a.wait_new(&assembled, base, 120).await?;
    wait_vpn_burst(a, n, 120).await?;
    let _ = crate::logd_mem::sample(w, a, "vpn-chunked").await;

    log("removing the speaker withdraws the whole burst");
    w.dock.container_remove("router-g").await;
    wait_vpn_burst(a, 0, 300).await
}

/// router-a's flags for the VPN phases: `evpn_flags` with VPNv4/VPNv6
/// toward GoBGP, and `VPN_TABLE` (RD `VPN_RD_A`, export RT `VPN_RD_A`)
/// importing `import_rt`.
pub(super) fn vpn_flags(import_rt: &str) -> Vec<String> {
    let mut f: Vec<String> = evpn_flags()
        .into_iter()
        .map(|f| match f.as_str() {
            "--evpn" => "--vpn".to_string(),
            "pg-evpn" => "pg-vpn".to_string(),
            _ => f,
        })
        .collect();
    f.extend(strings(&[
        "--vpn-table",
        VPN_TABLE,
        "--vpn-rd",
        VPN_RD_A,
        "--vpn-rt-export",
        VPN_RD_A,
        "--vpn-rt-import",
        import_rt,
    ]));
    f
}

/// VRF export (#580). GoBGP must see router-a's `VPN_TABLE` loopback
/// (`VPN_EXPORT_A`, a connected route) as a VPNv4 route with RD and RT
/// `VPN_RD_A`, label `VPN_LABEL` and next hop router-a's session address;
/// removing the route, then `vpn` itself, withdraws it, and setting `vpn`
/// again brings back the same label. Then two nos PEs (router-a, router-b,
/// VPNv4 between them) each export their own VRF route and import the
/// other's, PE next hop and label included.
pub async fn vpn_export(w: &mut World) -> anyhow::Result<()> {
    let with = |extra: &[&str]| {
        let mut f = vpn_flags("65000:1");
        f.extend(strings(extra));
        f
    };
    let add = ["--vpn-loopback-address", VPN_EXPORT_A];
    gobgp_speaker(
        w,
        with(&add),
        &["l3vpn-ipv4-unicast", "l3vpn-ipv6-unicast"],
        &[],
    )
    .await?;
    mpls_ready(w, &["router-a"]).await?;
    let a = w.a()?;
    let advertised = format!(
        "vpn route advertised peer={IP_G} family=vpnv4 rd={VPN_RD_A} prefix={VPN_EXPORT_A} labels=\\[{VPN_LABEL}\\] next_hop={IP_A}"
    );
    a.wait(&format!(
        "sent initial vpn snapshot to nos-bgpd table={VPN_TABLE} bgp_instance=r1"
    ))
    .await?;
    a.wait(&advertised).await?;
    let in_gobgp = format!("{VPN_RD_A}:{VPN_EXPORT_A}");
    let gobgp_until = |present: bool| gobgp_vpn_until(w, "vpnv4", &in_gobgp, present);
    let out = gobgp_until(true).await?;
    let line = out
        .lines()
        .find(|l| l.contains(&in_gobgp))
        .unwrap_or_default();
    for want in [
        &format!("[{VPN_LABEL}]"),
        IP_A,
        &format!("{ASN_A}"),
        VPN_RD_A,
    ] {
        if !line.contains(want) {
            bail!("GoBGP's route lacks {want}: {line}");
        }
    }
    if line.matches(VPN_RD_A).count() < 2 {
        bail!("GoBGP's route lacks the export RT {VPN_RD_A}: {line}");
    }

    log("removing the loopback address withdraws the VPN route");
    let withdrawn = format!(
        "vpn route advertisement withdrawn peer={IP_G} family=vpnv4 rd={VPN_RD_A} prefix={VPN_EXPORT_A}"
    );
    let base = a.count(&withdrawn);
    a.provision_flags(&with(&["--vpn-loopback-remove-address", VPN_EXPORT_A]))
        .await?;
    a.wait_new(&withdrawn, base, 60).await?;
    gobgp_until(false).await?;

    log("unsetting vpn withdraws everything; setting it again keeps the label");
    let (b_adv, b_wd) = (a.count(&advertised), a.count(&withdrawn));
    a.provision_flags(&with(&add)).await?;
    a.wait_new(&advertised, b_adv, 60).await?;
    a.provision_flags(&with(&["--vpn-clear"])).await?;
    a.wait_new(&withdrawn, b_wd, 60).await?;
    gobgp_until(false).await?;
    let b_adv = a.count(&advertised);
    a.provision_flags(&with(&add)).await?;
    a.wait_new(&advertised, b_adv, 60).await?;
    gobgp_until(true).await?;

    // RFC 8326 (#860): `graceful-shutdown` re-advertises the VPN route with
    // 65535:0 (GoBGP prints it as `65535:0`, `graceful-shutdown` or `planned-shut`), live.
    log("graceful-shutdown tags the VPN export, session untouched");
    let est_a = a.count("bgp session established");
    a.provision_flags(&with_gs(&with(&add))).await?;
    let mut tagged = false;
    let mut out = String::new();
    for _ in 0..30 {
        out = gobgp(w, &["global", "rib", "-a", "vpnv4"]).await?;
        tagged = out.lines().any(|l| {
            l.contains(&in_gobgp)
                && (l.contains("65535:0")
                    || l.contains("graceful-shutdown")
                    || l.contains("planned-shut"))
        });
        if tagged {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::ensure!(tagged, "GoBGP's VPN route never carried 65535:0: {out}");
    a.assert_quiet("bgp session established", est_a, 0).await?;
    w.dock.container_remove("router-g").await;

    two_pes(w).await
}

fn with_gs(flags: &[String]) -> Vec<String> {
    let mut f = flags.to_vec();
    f.push("--graceful-shutdown".into());
    f
}

/// Polls GoBGP's `family` (`vpnv4`/`vpnv6`) table until it does (or no
/// longer does) hold `needle`; the last output.
async fn gobgp_vpn_until(
    w: &World,
    family: &str,
    needle: &str,
    present: bool,
) -> anyhow::Result<String> {
    let mut out = String::new();
    for _ in 0..30 {
        out = gobgp(w, &["global", "rib", "-a", family]).await?;
        if out.contains(needle) == present {
            return Ok(out);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let what = if present { "showed" } else { "dropped" };
    bail!("GoBGP's {family} rib never {what} {needle}: {out}")
}

/// `vpn_export`'s second half: router-a and router-b as two PEs over one
/// VPNv4/VPNv6 eBGP session, sharing RT `VPN_RT` with their own RDs.
async fn two_pes(w: &mut World) -> anyhow::Result<()> {
    log("two nos PEs export their VRF route and import each other's");
    let pe = |id: Id, rd: &str, address: &str| {
        let mut f = id.base_flags();
        f.extend(strings(&[
            "--vpn",
            "--vpn-table",
            VPN_TABLE,
            "--vpn-rd",
            rd,
            "--vpn-rt-export",
            VPN_RT,
            "--vpn-rt-import",
            VPN_RT,
            "--vpn-loopback-address",
            address,
        ]));
        f
    };
    w.start(A, Some(pe(A, VPN_RD_A, VPN_EXPORT_A)), &[]).await?;
    w.start(B, Some(pe(B, VPN_RD_B, VPN_EXPORT_B)), &[]).await?;
    mpls_ready(w, &["router-a", "router-b"]).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.established().await?;
    let imported = |prefix: &str, rd: &str, pe: &str| {
        format!(
            "vpn route imported table={VPN_TABLE} prefix={prefix} labels=\\[{VPN_LABEL}\\] rd={rd} next_hop={pe}"
        )
    };
    a.wait(&imported(VPN_EXPORT_B, VPN_RD_B, IP_B)).await?;
    b.wait(&imported(VPN_EXPORT_A, VPN_RD_A, IP_A)).await?;
    let body = vrf_routes(a).await?;
    if !body.contains(VPN_EXPORT_B.split('/').next().unwrap_or_default())
        || !body.contains("\"Vpn\"")
    {
        bail!("router-a's {VPN_TABLE} lacks router-b's VPN route: {body}");
    }
    if a.count(&imported(VPN_EXPORT_A, VPN_RD_A, IP_B)) > 0 {
        bail!("router-a imported its own export back");
    }
    Ok(())
}

/// `GET /v1/routes/<VPN_TABLE>` on router-a.
async fn vrf_routes(a: &Router) -> anyhow::Result<String> {
    // `GET /v1/routes/<table>` is paged (#713): walk it into the old array.
    Ok(serde_json::Value::Array(a.routes_walk(VPN_TABLE, None).await?).to_string())
}

/// `vpn-dataplane` (#581): RFC 4364 forwarding for real. router-a and
/// router-b are two PEs over one VPNv4 session on the shared network (the
/// MPLS core link, PEs adjacent, so the VPN label is the only one), each with
/// a CE host on its own network behind `eth1`, in `VPN_TABLE`. Each `nos-ribd`
/// installs its label's AF_MPLS pop route into the VRF and the other PE's
/// subnet as a labelled route (`encap mpls <label> via <PE> dev eth0
/// onlink`); the CEs ping each other across the MPLS link but not the core.
/// A label change re-programs both sides; unsetting `vpn` removes them.
pub async fn vpn_dataplane(w: &mut World) -> anyhow::Result<()> {
    vpn_dp_setup(w, false).await?;
    let (a, b) = (w.a()?, w.b()?);

    log("the CEs ping each other across the MPLS link");
    ping_until(w, CE_HOST, L3_HOST_IP_B, 30).await?;
    ping_until(w, H_HOST, L3_HOST_IP_A, 30).await?;

    log("the VRF does not reach the core: a CE cannot ping router-b's underlay address");
    host_sh(w, CE_HOST, &format!("ip route add {IP_B}/32 via {L3_GW_A}")).await?;
    let (code, out) = w
        .dock
        .exec(CE_HOST, &["ping", "-c", "2", "-W", "1", IP_B])
        .await?;
    if code == 0 {
        bail!("{CE_HOST} reached {IP_B} through {VPN_TABLE}: {out}");
    }
    host_sh(w, CE_HOST, &format!("ip route del {IP_B}/32")).await?;

    log("router-b's label changes to 2000: both PEs re-program it");
    let new_label = 2000;
    let (base_rm, base_a) = (
        b.count(&dp_removed_pop(VPN_LABEL)),
        a.count(&dp_labelled(L3_SUBNET_B, new_label, IP_B)),
    );
    b.provision_flags(&dp_pe(
        B,
        VPN_RD_B,
        &format!("{L3_GW_B}/24"),
        &["--vpn-label", &new_label.to_string()],
    ))
    .await?;
    b.wait_new(&dp_removed_pop(VPN_LABEL), base_rm, 60).await?;
    b.wait(&dp_pop(new_label)).await?;
    a.wait_new(&dp_labelled(L3_SUBNET_B, new_label, IP_B), base_a, 60)
        .await?;
    ping_until(w, CE_HOST, L3_HOST_IP_B, 30).await?;
    ping_until(w, H_HOST, L3_HOST_IP_A, 30).await?;

    log("router-b's vpn unset: its pop route and router-a's labelled route go");
    let gone =
        format!("removed labelled route prefix={L3_SUBNET_B} labels=\\[\\[{new_label}\\]\\]");
    let (base_rm, base_gone) = (b.count(&dp_removed_pop(new_label)), a.count(&gone));
    let clear = {
        let mut f = dp_base(B);
        f.extend(strings(&["--vpn-table", VPN_TABLE, "--vpn-clear"]));
        f
    };
    b.provision_flags(&clear).await?;
    b.wait_new(&dp_removed_pop(new_label), base_rm, 60).await?;
    a.wait_new(&gone, base_gone, 60).await?;
    let (code, _) = w
        .dock
        .exec(CE_HOST, &["ping", "-c", "2", "-W", "1", L3_HOST_IP_B])
        .await?;
    if code == 0 {
        bail!("{CE_HOST} still reaches {L3_HOST_IP_B} after router-b's vpn was unset");
    }
    vpn_dp_teardown(w).await;
    Ok(())
}

/// `vpn-v6` (#582): VPN-IPv6 (RFC 4659) for real, the IPv6 twin of the VPN
/// phases, over an IPv4 session so the next hop is IPv4-mapped.
/// First against GoBGP (an `ipv6-l3vpn` route with a mapped next hop is
/// imported into `VPN_TABLE`, its PE resolved in the IPv4 underlay; router-a's
/// VRF loopback reaches GoBGP with RD, RT, label and next hop), then on two nos
/// PEs with IPv6 CE hosts: the labelled route is installed for an `AF_INET6`
/// destination and the hosts ping6 each other over the VPN label.
pub async fn vpn_v6(w: &mut World) -> anyhow::Result<()> {
    let mut flags = vpn_flags("65000:1");
    flags.extend(strings(&["--vpn-loopback-address", VPN6_EXPORT_A]));
    gobgp_speaker(w, flags, &["l3vpn-ipv4-unicast", "l3vpn-ipv6-unicast"], &[]).await?;
    mpls_ready(w, &["router-a"]).await?;
    let a = w.a()?;
    a.wait(&format!(
        "address families negotiated peer={IP_G} families=\\[.*\"vpnv6\""
    ))
    .await?;

    log("GoBGP's VPNv6 route (IPv4-mapped next hop) is imported, its PE resolved over IPv4");
    let prefix = "2001:db8:10::/48";
    gobgp(
        w,
        &[
            "global", "rib", "add", "-a", "vpnv6", prefix, "label", "300", "rd", "65001:1", "rt",
            "65000:1",
        ],
    )
    .await?;
    a.wait(&format!(
        "vpn route learned peer={IP_G} family=vpnv6 rd=65001:1 prefix={prefix} labels=\\[300\\] next_hop={IP_G}"
    ))
    .await?;
    a.wait(&format!(
        "vpn route imported table={VPN_TABLE} prefix={prefix} labels=\\[300\\] rd=65001:1 next_hop={IP_G}"
    ))
    .await?;
    let mut body = vrf_routes(a).await?;
    for _ in 0..10 {
        if body.contains(prefix) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        body = vrf_routes(a).await?;
    }
    let table: serde_json::Value = serde_json::from_str(&body)?;
    let route = table
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["prefix"] == prefix)
        .and_then(|p| p["candidates"].get(0))
        .with_context(|| format!("{VPN_TABLE} has no {prefix}: {body}"))?;
    if route["source"] != "Vpn"
        || route["vpn"][0]["pe_next_hop"] != IP_G
        || route["gateways"][0] != IP_G
        || route["mpls_labels"] != serde_json::json!([[300]])
    {
        bail!("{VPN_TABLE}'s {prefix} is not the imported VPNv6 route (IPv4 PE, IPv4 gateway): {route}");
    }

    log("router-a's VRF loopback is a VPNv6 route for GoBGP, next hop the session address");
    let advertised = format!(
        "vpn route advertised peer={IP_G} family=vpnv6 rd={VPN_RD_A} prefix={VPN6_EXPORT_A} labels=\\[{VPN_LABEL}\\] next_hop={IP_A}"
    );
    a.wait(&advertised).await?;
    let in_gobgp = format!("{VPN_RD_A}:{VPN6_EXPORT_A}");
    let out = gobgp_vpn_until(w, "vpnv6", &in_gobgp, true).await?;
    let line = out
        .lines()
        .find(|l| l.contains(&in_gobgp))
        .unwrap_or_default();
    for want in [
        &format!("[{VPN_LABEL}]"),
        IP_A,
        &format!("{ASN_A}"),
        VPN_RD_A,
    ] {
        if !line.contains(want) {
            bail!("GoBGP's VPNv6 route lacks {want}: {line}");
        }
    }
    if line.matches(VPN_RD_A).count() < 2 {
        bail!("GoBGP's VPNv6 route lacks the export RT {VPN_RD_A}: {line}");
    }
    w.dock.container_remove("router-g").await;

    log("two nos PEs with IPv6 CE hosts: ping6 both ways over the VPN label");
    vpn_dp_setup(w, true).await?;
    let (a, b) = (w.a()?, w.b()?);
    ping_until(w, CE_HOST, L3V6_HOST_B, 30).await?;
    ping_until(w, H_HOST, L3V6_HOST_A, 30).await?;

    log("router-b's vpn unset: the IPv6 labelled route goes and the ping stops");
    let gone =
        format!("removed labelled route prefix={L3V6_SUBNET_B} labels=\\[\\[{VPN_LABEL}\\]\\]");
    let base_gone = a.count(&gone);
    let clear = {
        let mut f = dp_base(B);
        f.extend(strings(&["--vpn-table", VPN_TABLE, "--vpn-clear"]));
        f
    };
    b.provision_flags(&clear).await?;
    a.wait_new(&gone, base_gone, 60).await?;
    let (code, _) = w
        .dock
        .exec(CE_HOST, &["ping", "-c", "2", "-W", "1", L3V6_HOST_B])
        .await?;
    if code == 0 {
        bail!("{CE_HOST} still reaches {L3V6_HOST_B} after router-b's vpn was unset");
    }
    vpn_dp_teardown(w).await;
    Ok(())
}

/// router-c as `vpn-multipath` runs it: in router-b's AS, so a sees the same
/// neighbouring AS on both paths (the multipath eligibility rule).
const C_IN_AS_B: Id = Id { asn: ASN_B, ..C };

/// `vpn-multipath` (#595): VPN import multipath for real. router-a imports
/// `L3_SUBNET_B` into `VPN_TABLE` from router-b and router-c (one AS, one RT,
/// two RDs, labels 3001 and 3002) with `maximum-paths 2`: its `nos-ribd`
/// installs ONE labelled route with both next hops and both labels, and the
/// CE behind a pings the host behind b and c. router-c then unsets `vpn`: the
/// route is replaced in place by one with router-b's hop alone (#598: one
/// `NLM_F_REPLACE`, no `removed labelled route`), and re-provisioning it grows
/// the route back the same way. A continuous ping from the CE across both
/// changes loses nothing.
pub async fn vpn_multipath(w: &mut World) -> anyhow::Result<()> {
    const LABEL_B: &str = "3001";
    const LABEL_C: &str = "3002";
    const RD_C: &str = "65000:300";
    w.start(A, Some(dp_base(A)), &[]).await?;
    w.start(B, Some(dp_base(B)), &[]).await?;
    w.start(C_IN_AS_B, Some(dp_base(C_IN_AS_B)), &[]).await?;
    mpls_ready(w, &["router-a", "router-b", "router-c"]).await?;

    log("a CE host behind router-a, a host behind both router-b and router-c");
    w.dock
        .ensure_image(
            HOST_IMAGE,
            "FROM debian:bookworm-slim\n\
             RUN apt-get update && apt-get install -y --no-install-recommends \\\n \
             iproute2 iputils-ping iputils-arping tcpdump && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    for net in [NET_L3_A, NET_L3_B] {
        if !w.dock.network_exists(net).await {
            let subnet = if net == NET_L3_A {
                L3_SUBNET_A
            } else {
                L3_SUBNET_B
            };
            w.dock.network_create(net, &[subnet], false).await?;
        }
    }
    let gw_c = "198.18.2.3";
    w.dock
        .network_connect_ip(NET_L3_A, "router-a", L3_GW_A)
        .await?;
    w.dock
        .network_connect_ip(NET_L3_B, "router-b", L3_GW_B)
        .await?;
    w.dock
        .network_connect_ip(NET_L3_B, "router-c", gw_c)
        .await?;
    for (host, net, ip, other, gw) in [
        (CE_HOST, NET_L3_A, L3_HOST_IP_A, L3_SUBNET_B, L3_GW_A),
        (H_HOST, NET_L3_B, L3_HOST_IP_B, L3_SUBNET_A, L3_GW_B),
    ] {
        w.dock.start_host(host, HOST_IMAGE, net).await?;
        host_sh(
            w,
            host,
            &format!(
                "set -e; ip addr flush dev eth0; ip addr add {ip}/24 dev eth0; \
                 ip route add {other} via {gw}"
            ),
        )
        .await?;
    }

    log("router-a peers router-b and router-c (one AS) with maximum-paths 2; all three export their VRF");
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let pe_a = |group: &str, peer: &str| {
        let mut flags = dp_pe(
            A,
            VPN_RD_A,
            &format!("{L3_GW_A}/24"),
            &["--maximum-paths", "2"],
        );
        let at = flags
            .iter()
            .position(|x| x == "--peer")
            .expect("base flags");
        flags[at + 1] = peer.to_string();
        flags.extend(strings(&["--peer-group", group]));
        flags
    };
    a.provision_flags(&pe_a("pg1", IP_B)).await?;
    a.provision_flags(&pe_a("pg-c", IP_C)).await?;
    b.provision_flags(&dp_pe(
        B,
        VPN_RD_B,
        &format!("{L3_GW_B}/24"),
        &["--vpn-label", LABEL_B],
    ))
    .await?;
    c.provision_flags(&dp_pe(
        C_IN_AS_B,
        RD_C,
        &format!("{gw_c}/24"),
        &["--vpn-label", LABEL_C],
    ))
    .await?;

    log("router-a installs ONE labelled route with both next hops and both labels");
    let both = format!(
        "installed labelled route prefix={L3_SUBNET_B} labels=\\[\\[{LABEL_B}\\], \\[{LABEL_C}\\]\\] gateway={IP_B},{IP_C} interfaces="
    );
    a.wait(&both).await?;
    ping_until(w, CE_HOST, L3_HOST_IP_B, 30).await?;
    ping_until(w, H_HOST, L3_HOST_IP_A, 30).await?;

    log("router-c unsets vpn: the route shrinks to router-b's hop");
    let single = format!(
        "installed labelled route prefix={L3_SUBNET_B} labels=\\[\\[{LABEL_B}\\]\\] gateway={IP_B} interfaces="
    );
    let removed = format!("removed labelled route prefix={L3_SUBNET_B} ");
    let replaced = |p: &str| format!("{p}.* replaced=true");
    let (single, both) = (replaced(&single), replaced(&both));
    let (base_single, base_both, base_removed) =
        (a.count(&single), a.count(&both), a.count(&removed));
    // Every change of the set below is a replace: a loss-free ping proves
    // the route never left the table.
    host_sh(
        w,
        CE_HOST,
        &format!(
            "nohup ping -i 0.2 -c 100000 {L3_HOST_IP_B} > /tmp/ping.out 2>&1 & echo $! > /tmp/ping.pid"
        ),
    )
    .await?;
    let (a, c) = (w.a()?, w.c()?);
    let mut clear = dp_base(C_IN_AS_B);
    clear.extend(strings(&["--vpn-table", VPN_TABLE, "--vpn-clear"]));
    c.provision_flags(&clear).await?;
    a.wait_new(&single, base_single, 60).await?;
    a.assert_quiet(&removed, base_removed, 10).await?;
    ping_until(w, CE_HOST, L3_HOST_IP_B, 30).await?;
    ping_until(w, H_HOST, L3_HOST_IP_A, 30).await?;

    log("router-c sets vpn again: the route grows back to both hops, in place");
    let (a, c) = (w.a()?, w.c()?);
    c.provision_flags(&dp_pe(
        C_IN_AS_B,
        RD_C,
        &format!("{gw_c}/24"),
        &["--vpn-label", LABEL_C],
    ))
    .await?;
    a.wait_new(&both, base_both, 60).await?;
    a.assert_quiet(&removed, base_removed, 10).await?;
    ping_until(w, CE_HOST, L3_HOST_IP_B, 30).await?;

    let out = host_sh(
        w,
        CE_HOST,
        "kill -INT $(cat /tmp/ping.pid); sleep 1; cat /tmp/ping.out",
    )
    .await?;
    if !out.contains(" 0% packet loss") {
        bail!("the CE lost packets while the route was replaced:\n{out}");
    }

    w.dock.network_disconnect(NET_L3_B, "router-c").await;
    vpn_dp_teardown(w).await;
    w.remove(C).await;
    Ok(())
}

/// The `Log` pattern of a label's AF_MPLS pop route install.
fn dp_pop(label: u32) -> String {
    format!("installed mpls pop route table={VPN_TABLE} vrf=.* label={label}")
}

/// The `Log` pattern of a label's pop route removal.
fn dp_removed_pop(label: u32) -> String {
    format!("removed mpls pop route table={VPN_TABLE} vrf=.* label={label}")
}

/// The `Log` pattern of the labelled route to `prefix` via the PE `pe`.
fn dp_labelled(prefix: &str, label: u32, pe: &str) -> String {
    format!("installed labelled route prefix={prefix} labels=\\[\\[{label}\\]\\] gateway={pe} interfaces=\\[[0-9]")
}

/// A data-plane PE's base flags: the session to the other PE and `--vpn`.
fn dp_base(id: Id) -> Vec<String> {
    let mut f = id.base_flags();
    f.push("--vpn".into());
    f
}

/// A data-plane PE's whole config: `dp_base` plus `VPN_TABLE` (its RD, the
/// shared RT both ways) with its CE-facing `eth1` in it at `l3_address`
/// (`--l3vni-interface` only puts eth1 in the table here: no L3 VNI).
fn dp_pe(id: Id, rd: &str, l3_address: &str, extra: &[&str]) -> Vec<String> {
    let mut f = dp_base(id);
    f.extend(strings(&[
        "--vpn-table",
        VPN_TABLE,
        "--vpn-rd",
        rd,
        "--vpn-rt-export",
        VPN_RT,
        "--vpn-rt-import",
        VPN_RT,
        "--l3vni-table",
        VPN_TABLE,
        "--l3vni-interface",
        "eth1",
        "--l3vni-address",
        l3_address,
    ]));
    f.extend(strings(extra));
    f
}

/// The operator's part of an MPLS PE (docker mounts /proc/sys read-only, so
/// `nos-ribd` only reads these): label space (it withholds a VRF's export
/// without it), MPLS input on the core link, forwarding. Per container start.
pub(super) async fn mpls_ready(w: &World, routers: &[&str]) -> anyhow::Result<()> {
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    for router in routers {
        netns(
            w,
            router,
            &[
                "sh",
                "-c",
                "echo 1048575 > /proc/sys/net/mpls/platform_labels; \
                 echo 1 > /proc/sys/net/mpls/conf/eth0/input; \
                 echo 1 > /proc/sys/net/ipv4/ip_forward; \
                 echo 1 > /proc/sys/net/ipv6/conf/all/forwarding",
            ],
        )
        .await?;
    }
    Ok(())
}

/// `vpn-dataplane`/`vpn-v6`'s topology, up and converged: router-a and
/// router-b as VPN PEs, a CE host (`CE_HOST`, `H_HOST`) on its own docker
/// network behind each PE's `eth1` in `VPN_TABLE`, the MPLS sysctls set, and
/// each PE with the other's CE subnet installed as a labelled route.
/// `v6` gives the CEs IPv6 addresses (and the PEs IPv6 `eth1` addresses)
/// instead of IPv4: the VPN session itself stays IPv4.
async fn vpn_dp_setup(w: &mut World, v6: bool) -> anyhow::Result<()> {
    w.start(A, Some(dp_base(A)), &[]).await?;
    w.start(B, Some(dp_base(B)), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.established().await?;
    b.established().await?;

    mpls_ready(w, &["router-a", "router-b"]).await?;

    log("a CE host behind each PE, each on its own network and subnet");
    w.dock
        .ensure_image(
            HOST_IMAGE,
            "FROM debian:bookworm-slim\n\
             RUN apt-get update && apt-get install -y --no-install-recommends \\\n \
             iproute2 iputils-ping iputils-arping tcpdump && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    // (network, docker subnets, router, docker address, host, host address,
    // the other site's subnet, the PE's eth1 address)
    let v4 = |net, subnet, router, gw: &str, host, ip, other| {
        (
            net,
            vec![subnet],
            router,
            gw.to_string(),
            host,
            ip,
            other,
            format!("{gw}/24"),
        )
    };
    let v6s = |net, subnet, subnet6, router, gw: &str, gw6: &str, host, ip, other| {
        (
            net,
            vec![subnet, subnet6],
            router,
            gw.to_string(),
            host,
            ip,
            other,
            format!("{gw6}/64"),
        )
    };
    let sites = if v6 {
        [
            v6s(
                NET_L3_A,
                L3_SUBNET_A,
                L3V6_SUBNET_A,
                "router-a",
                L3_GW_A,
                L3V6_GW_A,
                CE_HOST,
                L3V6_HOST_A,
                L3V6_SUBNET_B,
            ),
            v6s(
                NET_L3_B,
                L3_SUBNET_B,
                L3V6_SUBNET_B,
                "router-b",
                L3_GW_B,
                L3V6_GW_B,
                H_HOST,
                L3V6_HOST_B,
                L3V6_SUBNET_A,
            ),
        ]
    } else {
        [
            v4(
                NET_L3_A,
                L3_SUBNET_A,
                "router-a",
                L3_GW_A,
                CE_HOST,
                L3_HOST_IP_A,
                L3_SUBNET_B,
            ),
            v4(
                NET_L3_B,
                L3_SUBNET_B,
                "router-b",
                L3_GW_B,
                H_HOST,
                L3_HOST_IP_B,
                L3_SUBNET_A,
            ),
        ]
    };
    for (net, subnets, router, gw, host, ip, other, _) in &sites {
        if !w.dock.network_exists(net).await {
            w.dock.network_create(net, subnets, v6).await?;
        }
        w.dock.network_connect_ip(net, router, gw).await?;
        w.dock.start_host(host, HOST_IMAGE, net).await?;
        let script = if v6 {
            let gw6 = if *router == "router-a" {
                L3V6_GW_A
            } else {
                L3V6_GW_B
            };
            format!(
                "set -e; ip addr flush dev eth0; ip -6 addr add {ip}/64 dev eth0 nodad; \
                 ip -6 route add {other} via {gw6}"
            )
        } else {
            format!(
                "set -e; ip addr flush dev eth0; ip addr add {ip}/24 dev eth0; \
                 ip route add {other} via {gw}"
            )
        };
        host_sh(w, host, &script).await?;
    }

    log("each PE's VRF gets vpn and its CE-facing eth1");
    a.provision_flags(&dp_pe(A, VPN_RD_A, &sites[0].7, &[]))
        .await?;
    b.provision_flags(&dp_pe(B, VPN_RD_B, &sites[1].7, &[]))
        .await?;
    a.wait(&dp_pop(VPN_LABEL)).await?;
    b.wait(&dp_pop(VPN_LABEL)).await?;
    a.wait(&dp_labelled(sites[0].6, VPN_LABEL, IP_B)).await?;
    b.wait(&dp_labelled(sites[1].6, VPN_LABEL, IP_A)).await
}

/// Removes `vpn_dp_setup`'s hosts and networks.
async fn vpn_dp_teardown(w: &World) {
    for host in [CE_HOST, H_HOST] {
        w.dock.container_remove(host).await;
    }
    for (net, router) in [(NET_L3_A, "router-a"), (NET_L3_B, "router-b")] {
        w.dock.network_disconnect(net, router).await;
        w.dock.network_remove(net).await;
    }
}

/// `vpn`'s Site of Origin (RFC 4364 section 7, #582) and RPL steps, on top of
/// `vrf_import`'s state (`flags("65000:1")` provisioned, GoBGP peering). GoBGP
/// cannot put a Site of Origin on a VPN route from its CLI, so a global import
/// policy adds `soo:65001:77` to 10.30.0.0/24 and `soo:65001:99` to 10.31.0.0/24
/// as they are injected, and 10.40.0.0/24 carries a foreign RT.
///
/// Setting `vpn site-of-origin 65001:77` on `VPN_TABLE` must skip 10.30.0.0/24
/// (log, not in `show route`, the SoO shown by `show bgp vpnv4`) and still
/// import 10.31.0.0/24; the VRF loopback exported to GoBGP carries the SoO;
/// clearing it imports 10.30.0.0/24. A peer-group import policy adding
/// `rt(65000:1)` imports 10.40.0.0/24, removing it unimports it.
async fn vpn_soo_and_policy(w: &World, flags: &dyn Fn(&str) -> Vec<String>) -> anyhow::Result<()> {
    let a = w.a()?;
    let soo = "65001:77";
    let with = |extra: &[&str]| {
        let mut f = flags("65000:1");
        f.extend(strings(&["--vpn-loopback-address", VPN_EXPORT_A]));
        f.extend(strings(extra));
        f
    };
    let imported = |p: &str| format!("vpn route imported table={VPN_TABLE} prefix={p}");

    log("GoBGP tags 10.30.0.0/24 with SoO 65001:77 and 10.31.0.0/24 with 65001:99");
    for (set, prefix, value) in [
        ("ps77", "10.30.0.0/24", "65001:77"),
        ("ps99", "10.31.0.0/24", "65001:99"),
    ] {
        let st = format!("st{}", &set[2..]);
        let community = format!("soo:{value}");
        for args in [
            vec!["policy", "prefix", "add", set, prefix],
            vec![
                "policy",
                "statement",
                &st,
                "add",
                "condition",
                "prefix",
                set,
            ],
            vec![
                "policy",
                "statement",
                &st,
                "add",
                "action",
                "ext-community",
                "add",
                &community,
            ],
            vec!["policy", "statement", &st, "add", "action", "accept"],
        ] {
            gobgp(w, &args).await?;
        }
    }
    gobgp(w, &["policy", "add", "psoo", "st77", "st99"]).await?;
    gobgp(
        w,
        &[
            "global", "policy", "import", "add", "psoo", "default", "accept",
        ],
    )
    .await?;

    log("vpn site-of-origin 65001:77 on the VRF");
    let advertised = format!(
        "vpn route advertised peer={IP_G} family=vpnv4 rd={VPN_RD_A} prefix={VPN_EXPORT_A}"
    );
    let adv_before = a.count(&advertised);
    a.provision_flags(&with(&["--vpn-site-of-origin", soo]))
        .await?;
    for (prefix, label) in [("10.30.0.0/24", "500"), ("10.31.0.0/24", "501")] {
        gobgp(
            w,
            &[
                "global", "rib", "add", "-a", "vpnv4", prefix, "label", label, "rd", "65001:4",
                "rt", "65000:1",
            ],
        )
        .await?;
    }
    a.wait(&format!(
        "vpn route skipped by site of origin table={VPN_TABLE} rd=65001:4 prefix=10.30.0.0/24 soo={soo}"
    ))
    .await?;
    a.wait(&imported("10.31.0.0/24")).await?;
    // The import log precedes `nos-ribd` installing the route: poll.
    let mut table = vrf_routes(a).await?;
    for _ in 0..10 {
        if table.contains("10.31.0.0/24") {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        table = vrf_routes(a).await?;
    }
    if table.contains("10.30.0.0/24") || !table.contains("10.31.0.0/24") {
        bail!("{VPN_TABLE} must lack the own-SoO route and hold the foreign-SoO one: {table}");
    }
    let shown = a
        .rest_expect(Method::GET, "/v1/bgp/vpnv4?rd=65001:4", None, 200)
        .await?;
    for want in [
        format!("\"site_of_origin\":\"{soo}\""),
        "\"site_of_origin\":\"65001:99\"".to_string(),
    ] {
        if !shown.contains(&want) {
            bail!("show bgp vpnv4 lacks {want}: {shown}");
        }
    }

    log("the exported VRF loopback carries the SoO to GoBGP");
    // Bisects a failure: bgpd never advertised it vs GoBGP dropped it (#746).
    a.wait_new(&advertised, adv_before, 30).await?;
    let in_gobgp = format!("{VPN_RD_A}:{VPN_EXPORT_A}");
    gobgp_vpn_until(w, "vpnv4", &in_gobgp, true).await?;
    let json: serde_json::Value =
        serde_json::from_str(&gobgp(w, &["global", "rib", "-a", "vpnv4", "-j"]).await?)?;
    let has_soo = json[&in_gobgp][0]["attrs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|attr| attr["type"] == 16)
        .flat_map(|attr| attr["value"].as_array().into_iter().flatten())
        .any(|ec| ec["subtype"] == 3 && ec["value"] == soo);
    if !has_soo {
        bail!("GoBGP's {in_gobgp} lacks SoO {soo}: {}", json[&in_gobgp]);
    }

    log("clearing the SoO imports the held route");
    let base = a.count(&imported("10.30.0.0/24"));
    a.provision_flags(&with(&[])).await?;
    a.wait_new(&imported("10.30.0.0/24"), base, 30).await?;

    log("a peer-group import policy adds the VRF's RT to a route with a foreign one");
    let steered = "10.40.0.0/24";
    gobgp(
        w,
        &[
            "global", "rib", "add", "-a", "vpnv4", steered, "label", "600", "rd", "65001:6", "rt",
            "65000:99",
        ],
    )
    .await?;
    a.wait(&format!(
        "vpn route learned peer={IP_G} family=vpnv4 rd=65001:6 prefix={steered}"
    ))
    .await?;
    let base = a.count(&imported(steered));
    a.assert_quiet(&imported(steered), base, 5).await?;
    let file = policy_file(
        "vpn-rt-steer",
        "this.bgp.extended_communities.add(rt(65000:1))\naccept\n",
    )?;
    a.provision_flags(&with(&[
        "--policy-name",
        "vpn-rt-steer",
        "--policy-source-file",
        &file,
        "--import-policy",
        "vpn-rt-steer",
    ]))
    .await?;
    a.wait_new(&imported(steered), base, 60).await?;
    log("removing the policy unimports it again");
    let unimported = format!("vpn route unimported table={VPN_TABLE} prefix={steered}");
    let base = a.count(&unimported);
    // A policy change restarts the session: wait for GoBGP's routes to come
    // back before `vpn` goes on to read them.
    let relearned =
        format!("vpn route learned peer={IP_G} family=vpnv4 rd=65001:1 prefix=10.10.0.0/24");
    let base_relearned = a.count(&relearned);
    a.provision_flags(&with(&[])).await?;
    a.wait_new(&unimported, base, 60).await?;
    a.wait_new(&relearned, base_relearned, 60).await
}

/// `vpn`'s VRF import part (#579), with GoBGP holding 10.10.0.0/24 under
/// RDs 65001:1/65001:2 (labels 100/200) and 2001:db8:10::/48 (label 300),
/// all with RT 65000:1; `flags(rt)` is router-a's provisioning importing `rt`.
async fn vrf_import(w: &World, flags: &dyn Fn(&str) -> Vec<String>) -> anyhow::Result<()> {
    let a = w.a()?;
    let imported = |p: &str, labels: &str, rd: &str| {
        format!(
            "vpn route imported table={VPN_TABLE} prefix={p} labels=\\[{labels}\\] rd={rd} next_hop={IP_G}"
        )
    };
    // The two RDs compete for one VRF prefix: either may win.
    let (v4, v6) = (
        imported("10.10.0.0/24", "[12]00", "65001:[12]"),
        imported("2001:db8:10::/48", "300", "65001:1"),
    );
    a.wait(&v4).await?;
    a.wait(&v6).await?;
    let body = vrf_routes(a).await?;
    let table: serde_json::Value = serde_json::from_str(&body)?;
    let vpn = table
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["prefix"] == "10.10.0.0/24")
        .and_then(|p| p["candidates"].get(0))
        .with_context(|| format!("{VPN_TABLE} has no 10.10.0.0/24: {body}"))?;
    let labels = vpn["mpls_labels"].to_string();
    if vpn["source"] != "Vpn"
        || !(labels == "[[100]]" || labels == "[[200]]")
        || vpn["vpn"][0]["pe_next_hop"] != IP_G
        || vpn["gateways"][0] != IP_G
    {
        bail!("{VPN_TABLE}'s 10.10.0.0/24 is not the imported VPN route: {vpn}");
    }

    log("a route with a foreign RT is not imported");
    let foreign = "10.20.0.0/24";
    let foreign_in = format!("vpn route imported table={VPN_TABLE} prefix={foreign}");
    let base = a.count(&foreign_in);
    let add_foreign = [
        "global", "rib", "add", "-a", "vpnv4", foreign, "label", "400", "rd", "65001:3", "rt",
        "65000:99",
    ];
    gobgp(w, &add_foreign).await?;
    a.wait(&format!(
        "vpn route learned peer={IP_G} family=vpnv4 rd=65001:3 prefix={foreign}"
    ))
    .await?;
    a.assert_quiet(&foreign_in, base, 5).await?;
    if vrf_routes(a).await?.contains(foreign) {
        bail!("{VPN_TABLE} imported {foreign} without a matching RT");
    }

    log("moving the import RT to 65000:99 over REST");
    let out = |p: &str| format!("vpn route unimported table={VPN_TABLE} prefix={p}");
    let (out4, b_out) = (out("10.10.0.0/24"), a.count(&out("10.10.0.0/24")));
    a.provision_flags(&flags("65000:99")).await?;
    a.wait_new(&foreign_in, base, 30).await?;
    a.wait_new(&out4, b_out, 30).await?;

    log("withdrawing the foreign-RT route unimports it");
    let (gone, b_gone) = (out(foreign), a.count(&out(foreign)));
    gobgp(
        w,
        &[
            "global", "rib", "del", "-a", "vpnv4", foreign, "label", "400", "rd", "65001:3",
        ],
    )
    .await?;
    a.wait_new(&gone, b_gone, 30).await?;

    log("restoring the import RT 65000:1");
    let (b4, b6) = (a.count(&v4), a.count(&v6));
    a.provision_flags(&flags("65000:1")).await?;
    a.wait_new(&v4, b4, 30).await?;
    a.wait_new(&v6, b6, 30).await
}

/// RFC 7432 EVPN, receive side. No NOS router originates EVPN yet, so an
/// independent implementation does: GoBGP announces one MAC/IP (Type 2) and
/// one Inclusive Multicast (Type 3) route, with a Route Target and the VXLAN
/// Encapsulation community, to router-a. Router-a must negotiate AFI 25 /
/// SAFI 70 (its peer-group's only family besides IPv4 unicast), decode both,
/// hold them per peer, serve them on `show bgp evpn`, and drop them on an
/// explicit withdrawal and, for what is left, when the session goes away.
pub async fn evpn(w: &mut World) -> anyhow::Result<()> {
    evpn_speaker(w, &[]).await?;
    let a = w.a()?;

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
            "evpn",
            "multicast",
            IP_G,
            "etag",
            "0",
            "rd",
            rd,
            "rt",
            rt,
            "encap",
            "vxlan",
        ],
    )
    .await?;

    let learned = |t: u8| format!("evpn route learned peer={IP_G} route_type={t}");
    let withdrawn = |t: u8| format!("evpn route withdrawn peer={IP_G} route_type={t}");
    a.wait(&learned(2)).await?;
    a.wait(&learned(3)).await?;

    // `show bgp evpn`, over REST: NLRI fields, Route Target and VXLAN encap
    // all decoded from another implementation's encoding.
    let show = || a.rest_expect(reqwest::Method::GET, "/v1/bgp/evpn", None, 200);
    let body = show().await?;
    for want in [
        "\"route_type\":2",
        "\"route_type\":3",
        mac,
        ip,
        rd,
        "RT:65010:10000",
        "encap:8",
    ] {
        if !body.contains(want) {
            bail!("show bgp evpn is missing {want}: {body}");
        }
    }
    log("evpn routes walked one per page come back once each (#723)");
    expect_paged_walk(a, "/v1/bgp/evpn", 2).await?;

    log("withdrawing the Type-2 route explicitly");
    let base = a.count(&withdrawn(2));
    gobgp(
        w,
        &[
            "global", "rib", "del", "-a", "evpn", "macadv", mac, ip, "etag", "0", "label", "10000",
            "rd", rd,
        ],
    )
    .await?;
    a.wait_new(&withdrawn(2), base, 30).await?;
    let body = show().await?;
    if body.contains("\"route_type\":2") || !body.contains("\"route_type\":3") {
        bail!("expected only the Type-3 route after the withdrawal: {body}");
    }

    evpn_soft_reconfig(a, &show).await?;

    // RFC 9136 Type-5 + RFC 9135 Router's MAC from an independent
    // implementation: router-a's IP-VRF imports GoBGP's Route Target, and its
    // nos-ribd installs the prefix through its L3 VNI (control plane and the
    // kernel route only; `evpn-l3` forwards).
    log("type-5 interop: GoBGP's IP prefix route lands in router-a's IP-VRF");
    let mut flags = evpn_flags();
    flags.extend(strings(&[
        "--l3vni-table",
        L3_TABLE,
        "--l3vni",
        &L3_VNI.to_string(),
        "--l3vni-rd",
        L3_RD_A,
        "--l3vni-rt",
        L3_GOBGP_RT,
        "--l3vni-vtep-source-interface",
        "eth0",
    ]));
    a.provision_flags(&flags).await?;
    a.wait(&format!(
        "created l3 vni vxlan device vxlan=vx{L3_VNI} vni={L3_VNI} vtep={IP_A}"
    ))
    .await?;
    gobgp(
        w,
        &[
            "global",
            "rib",
            "add",
            "-a",
            "evpn",
            "prefix",
            L3_GOBGP_PREFIX,
            // GoBGP needs it spelled out; zero is RFC 9136's "no overlay index".
            "gw",
            "0.0.0.0",
            "etag",
            "0",
            "label",
            &L3_VNI.to_string(),
            "rd",
            "65010:5",
            "rt",
            L3_GOBGP_RT,
            "encap",
            "vxlan",
            "router-mac",
            L3_GOBGP_RMAC,
        ],
    )
    .await?;
    a.wait(&learned(5)).await?;
    a.wait(&format!(
        "evpn remote vtep installed vni={L3_VNI} vtep={IP_G} rmac={L3_GOBGP_RMAC}"
    ))
    .await?;
    a.wait(&format!(
        "added route prefix={L3_GOBGP_PREFIX} gateway={IP_G} next_hops=1 .*source=Some(Evpn)"
    ))
    .await?;
    let body = show().await?;
    if !body.contains(&format!("rmac:{L3_GOBGP_RMAC}")) {
        bail!("show bgp evpn does not decode GoBGP's Router's MAC: {body}");
    }
    if !tenant_has_evpn(a, L3_GOBGP_PREFIX).await? {
        bail!("router-a's {L3_TABLE} does not list {L3_GOBGP_PREFIX} as an evpn route");
    }

    // RFC 9135 symmetric IRB from an independent implementation: a MAC+IP
    // whose Label2 is the L3 VNI becomes a host route in the IP-VRF.
    log("symmetric irb interop: GoBGP's MAC+IP with Label2 lands as a host route");
    gobgp(
        w,
        &[
            "global",
            "rib",
            "add",
            "-a",
            "evpn",
            "macadv",
            "aa:bb:cc:00:00:09",
            L3_GOBGP_HOST,
            "etag",
            "0",
            "label",
            &format!("10100,{L3_VNI}"),
            "rd",
            "65010:6",
            "rt",
            L3_GOBGP_RT,
            "encap",
            "vxlan",
            "router-mac",
            L3_GOBGP_RMAC,
        ],
    )
    .await?;
    a.wait(&format!(
        "added route prefix={L3_GOBGP_HOST}/32 gateway={IP_G} next_hops=1 .*source=Some(Evpn)"
    ))
    .await?;
    if !tenant_has_evpn(a, &format!("{L3_GOBGP_HOST}/32")).await? {
        bail!("router-a's {L3_TABLE} does not list {L3_GOBGP_HOST}/32 as an evpn route");
    }

    // RFC 8326 on EVPN (#874): GoBGP announces one MAC+IP and one Type-5
    // prefix under two RDs, one plain and one with GRACEFUL_SHUTDOWN. A
    // single next hop means the Type-2 winner is not observable on the VTEP,
    // so this asserts the stored LOCAL_PREF/communities (log + show) and, for
    // Type-5, that a lone tagged route is still pushed.
    log("graceful shutdown on evpn: tagged copies are learned at local-pref 0");
    let (gmac, gip, gprefix) = ("aa:bb:cc:00:00:0a", "192.0.2.20", "198.18.10.0/24");
    let (plain_rd, tagged_rd) = ("65010:7", "65010:8");
    let (plain5, tagged5) = ("65010:57", "65010:58");
    let gs_learned = |t: u8, rd: &str, lp: u32, c: &str| {
        format!("evpn route learned peer={IP_G} route_type={t} route=.*{rd}.* local_pref={lp} communities=\\[{c}\\]")
    };
    for (rd, tag) in [(plain_rd, false), (tagged_rd, true)] {
        let mut args = vec![
            "global", "rib", "add", "-a", "evpn", "macadv", gmac, gip, "etag", "0", "label",
            "10100", "rd", rd, "rt", rt, "encap", "vxlan",
        ];
        if tag {
            args.extend(["community", "65535:0"]);
        }
        gobgp(w, &args).await?;
    }
    a.wait(&gs_learned(2, plain_rd, 100, "")).await?;
    a.wait(&gs_learned(2, tagged_rd, 0, EVPN_GS_NAME)).await?;
    let body = show().await?;
    // 4294901760 = 65535:0 packed; the REST wire carries the number.
    if !body.contains("\"local_pref\":0") || !body.contains("4294901760") {
        bail!("show bgp evpn does not carry the demoted local_pref and community: {body}");
    }
    let l3vni = L3_VNI.to_string();
    for (rd, tag) in [(tagged5, true), (plain5, false)] {
        let mut args = vec![
            "global",
            "rib",
            "add",
            "-a",
            "evpn",
            "prefix",
            gprefix,
            "gw",
            "0.0.0.0",
            "etag",
            "0",
            "label",
            &l3vni,
            "rd",
            rd,
            "rt",
            L3_GOBGP_RT,
            "encap",
            "vxlan",
            "router-mac",
            L3_GOBGP_RMAC,
        ];
        if tag {
            args.extend(["community", "65535:0"]);
        }
        gobgp(w, &args).await?;
        if tag {
            // Alone, the demoted route is still the only path: it is pushed.
            a.wait(&gs_learned(5, rd, 0, EVPN_GS_NAME)).await?;
            a.wait(&format!(
                "added route prefix={gprefix} gateway={IP_G} next_hops=1 .*source=Some(Evpn)"
            ))
            .await?;
        }
    }
    a.wait(&gs_learned(5, plain5, 100, "")).await?;

    log("removing the speaker: its remaining routes must go with the session");
    let base = a.count(&withdrawn(3));
    w.dock.container_remove("router-g").await;
    a.wait_new(&withdrawn(3), base, 60).await?;
    let body = show().await?;
    if body.contains("\"route_type\"") {
        bail!("EVPN routes outlived their session: {body}");
    }
    Ok(())
}

/// Reads the real bridge port `dev` back, in `container`'s netns, until its
/// flood flags read as a segment port's should: `df` floods everything; a
/// non-DF (`!df`) has unicast flood off but multicast and broadcast flood *on*
/// (EVPN local bias, #24: it delivers what its own hosts send, and the egress
/// filters drop what the other PEs of the segment sent).
async fn bridge_port_flood(w: &World, container: &str, dev: &str, df: bool) -> anyhow::Result<()> {
    let (uni, bum) = if df { ("on", "on") } else { ("off", "on") };
    let mut last = String::new();
    for _ in 0..30 {
        last = w
            .dock
            .in_netns(
                NETNS_HELPER_IMAGE,
                container,
                &["bridge", "-d", "link", "show", "dev", dev],
            )
            .await?;
        if last.contains(&format!(" flood {uni}"))
            && last.contains(&format!("mcast_flood {bum}"))
            && last.contains(&format!("bcast_flood {bum}"))
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("bridge port {dev} never read unicast flood {uni}, bum flood {bum}: {last}")
}

/// Waits until `tc filter show dev <dev> <hook>` in `container`'s netns does
/// (`present`) or does not contain `needle`.
async fn tc_has(
    w: &World,
    container: &str,
    dev: &str,
    hook: &str,
    needle: &str,
    present: bool,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..30 {
        last = w
            .dock
            .in_netns(
                NETNS_HELPER_IMAGE,
                container,
                &["tc", "filter", "show", "dev", dev, hook],
            )
            .await?;
        if last.contains(needle) == present {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{container}: `tc filter show dev {dev} {hook}` never {} {needle:?}: {last}",
        if present { "listed" } else { "stopped listing" }
    )
}

/// EVPN local bias, read back from the kernel (#24): the segment port `bond`
/// of `container` carries the local-bias drop (`fw` handle `0xe5000001`, the
/// segment's bit) and, only while it is a non-DF, the DF drop (`0xe5000000`);
/// `vxlan`'s ingress marks frames from `peer`, the other PE of the segment
/// (`enc_src_ip`, which tc prints for IPv6 too); and the flood flags read as
/// `bridge_port_flood` says.
async fn local_bias_readback(
    w: &World,
    container: &str,
    bond: &str,
    vxlan: &str,
    peer: &str,
    non_df: bool,
) -> anyhow::Result<()> {
    tc_has(w, container, bond, "egress", "handle 0xe5000001", true).await?;
    tc_has(w, container, bond, "egress", "handle 0xe5000000", non_df).await?;
    tc_has(
        w,
        container,
        vxlan,
        "ingress",
        &format!("enc_src_ip {peer}"),
        true,
    )
    .await?;
    bridge_port_flood(w, container, bond, !non_df).await
}

/// The local-bias tc state with hit counters on both segment PEs, for a failed
/// BUM count (#460): which of marking, port drop or another path let a frame by.
async fn bias_counters(w: &World, bonds: [&str; 2], vxlan: &str) -> String {
    let mut out = String::new();
    for (router, bond) in ["router-a", "router-b"].into_iter().zip(bonds) {
        for (dev, hook) in [(bond, "egress"), (vxlan, "ingress")] {
            let shown = w
                .dock
                .in_netns(
                    NETNS_HELPER_IMAGE,
                    router,
                    &["tc", "-s", "filter", "show", "dev", dev, hook],
                )
                .await
                .unwrap_or_else(|e| e.to_string());
            let _ = write!(out, "\n{router} {dev} {hook}:\n{shown}");
        }
    }
    out
}

/// One ARP broadcast, as `(CE eth0, CE eth1, host)` request counts: sent by the
/// CE out of its `link` (`Some`; `eth0` is its link to router-a, `eth1` to
/// router-b) or by the host (`None`). The CE's counts are what arrived *in* on
/// each of its links (so an echo of its own request shows), the host's what
/// reached the host.
async fn arp_broadcast(w: &World, ce_link: Option<&str>) -> anyhow::Result<(usize, usize, usize)> {
    let (target, sender) = if ce_link.is_some() {
        (H_IP, CE_IP)
    } else {
        (CE_IP, H_IP)
    };
    host_sh(
        w,
        CE_HOST,
        "rm -f /tmp/e0 /tmp/e1; \
         timeout 12 tcpdump -l -n -Q in -i eth0 arp and ether broadcast >/tmp/e0 2>&1 & \
         timeout 12 tcpdump -l -n -Q in -i eth1 arp and ether broadcast >/tmp/e1 2>&1 & \
         sleep 2",
    )
    .await?;
    host_sh(
        w,
        H_HOST,
        "rm -f /tmp/h; timeout 12 tcpdump -l -n -Q in -i eth0 arp and ether broadcast >/tmp/h 2>&1 & sleep 2",
    )
    .await?;
    // arping's exit code says whether a reply came back, which is none of this
    // check's business.
    let _ = match ce_link {
        Some(link) => {
            w.dock
                .exec(
                    CE_HOST,
                    &[
                        "arping", "-c", "1", "-w", "3", "-I", link, "-s", CE_IP, H_IP,
                    ],
                )
                .await?
        }
        None => {
            w.dock
                .exec(
                    H_HOST,
                    &[
                        "arping", "-c", "1", "-w", "3", "-I", "eth0", "-s", H_IP, CE_IP,
                    ],
                )
                .await?
        }
    };
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok((
        arp_requests(w, CE_HOST, "/tmp/e0", target, sender).await?,
        arp_requests(w, CE_HOST, "/tmp/e1", target, sender).await?,
        arp_requests(w, H_HOST, "/tmp/h", target, sender).await?,
    ))
}

pub(super) async fn gobgp_owned(w: &World, args: Vec<String>) -> anyhow::Result<String> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    gobgp(w, &refs).await
}

/// Runs an iproute2 command inside router-a's network namespace.
async fn netns_a(w: &World, cmd: &[&str]) -> anyhow::Result<String> {
    w.dock.in_netns(NETNS_HELPER_IMAGE, "router-a", cmd).await
}

/// Takes `router` off `nets` from below: docker deletes its interfaces there,
/// so a bond whose only members they were loses carrier and `nos-interfaced`
/// has nothing to revert. `ip link set <bond> down` would not hold: the bond
/// is a link `nos-interfaced` owns, so its next reconcile tick (≤10s) brings
/// it back up (#169).
async fn link_lost(w: &World, router: &str, nets: &[&str]) {
    for net in nets {
        w.dock.network_disconnect(net, router).await;
    }
}

/// Undoes `link_lost`: reconnects `router` to each of `nets` and, should docker
/// pick another name, renames the new interface (found by its MAC) back to the
/// matching entry of `names`, so `nos-interfaced`'s next tick re-enslaves it.
async fn link_back(w: &World, router: &str, nets: &[&str], names: &[&str]) -> anyhow::Result<()> {
    for (net, name) in nets.iter().zip(names) {
        w.dock.network_connect(net, router).await;
        let mac = w.dock.mac(router, net).await?;
        let script = format!(
            "for i in /sys/class/net/eth*; do [ \"$(cat $i/address)\" = {mac} ] && n=${{i##*/}}; done; \
             [ \"$n\" = {name} ] || {{ ip link set \"$n\" down && ip link set \"$n\" name {name}; }}"
        );
        w.dock
            .in_netns(NETNS_HELPER_IMAGE, router, &["sh", "-c", &script])
            .await?;
    }
    Ok(())
}

/// Polls GoBGP's EVPN RIB until `want(rib)` holds.
async fn gobgp_evpn_rib(w: &World, what: &str, want: impl Fn(&str) -> bool) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..30 {
        last = gobgp(w, &["global", "rib", "-a", "evpn"]).await?;
        if want(&last) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("GoBGP's EVPN RIB never {what}: {last}")
}

/// `nos-fdbd`, both directions, against GoBGP as the remote VTEP. A broadcast
/// domain with a VNI, RD, import/export Route Targets, a VTEP source and
/// `redistribute from mac to bgp` gets a real VXLAN device on its bridge.
///
/// Remote -> kernel: GoBGP's Type-3 becomes a flood entry, its Type-2 (with a
/// matching Route Target) a remote MAC; a Type-2 with another Route Target is
/// ignored; a withdrawal removes the MAC. Local -> BGP: a MAC pinned on a
/// port of the domain's bridge (by a helper container in router-a's netns —
/// the runtime image has no iproute2) is originated as a Type-2, next to the
/// domain's Type-3, and GoBGP sees both; removing it withdraws it. Finally
/// unsetting the VNI must stop `nos-fdbd` and delete the VXLAN device.
///
/// Type-2 with an IP: GoBGP's `macadv <mac> <ip>` also becomes a kernel
/// neighbour on the bridge (`remote neighbour installed`); `redistribute from
/// connected` originates the domain's SVI address with the bridge's MAC, and
/// `redistribute from arp` an ARP binding pinned on the bridge (`ip neigh add
/// ... nud permanent`) for a MAC behind a local port — both seen by GoBGP.
pub async fn evpn_fdb(w: &mut World) -> anyhow::Result<()> {
    evpn_speaker(w, &[]).await?;
    let a = w.a()?;

    let mut flags = evpn_flags();
    flags.extend(strings(&[
        "--broadcast-domain",
        EVPN_DOMAIN,
        "--evpn-vni",
        &EVPN_VNI.to_string(),
        "--evpn-rd",
        EVPN_RD,
        "--evpn-rt-import",
        EVPN_RT_IMPORT,
        "--evpn-rt-export",
        EVPN_RT_EXPORT,
        "--evpn-vtep-source-interface",
        "eth0",
        "--evpn-redistribute-bgp",
        "r1",
        "--evpn-redistribute-arp-bgp",
        "r1",
        "--evpn-redistribute-connected-bgp",
        "r1",
        "--broadcast-domain-svi-address",
        EVPN_SVI_ADDRESS,
    ]));
    a.provision_flags(&flags).await?;
    let vxlan = format!("vx{EVPN_VNI}");
    a.wait(&format!(
        "vxlan device ready domain={EVPN_DOMAIN} vni={EVPN_VNI} vxlan={vxlan}"
    ))
    .await?;

    log("remote -> kernel: GoBGP originates a Type-3 and Type-2 routes");
    let (rd_g, rt_g) = ("65010:1", EVPN_RT_IMPORT);
    gobgp(
        w,
        &[
            "global",
            "rib",
            "add",
            "-a",
            "evpn",
            "multicast",
            IP_G,
            "etag",
            "0",
            "rd",
            rd_g,
            "rt",
            rt_g,
            "encap",
            "vxlan",
        ],
    )
    .await?;
    a.wait(&format!(
        "flood entry installed domain={EVPN_DOMAIN} vtep={IP_G}"
    ))
    .await?;
    let macadv = |verb: &'static str, mac: &'static str, rt: &'static str| {
        let vni = EVPN_VNI.to_string();
        let mut v = strings(&[
            "global",
            "rib",
            verb,
            "-a",
            "evpn",
            "macadv",
            mac,
            EVPN_REMOTE_IP,
            "etag",
            "0",
            "label",
            &vni,
            "rd",
            rd_g,
        ]);
        if verb == "add" {
            v.extend(strings(&["rt", rt, "encap", "vxlan"]));
        }
        v
    };
    let installed =
        |mac: &str| format!("remote mac installed domain={EVPN_DOMAIN} mac={mac} vtep={IP_G}");
    let removed =
        |mac: &str| format!("remote mac removed domain={EVPN_DOMAIN} mac={mac} vtep={IP_G}");

    let other_base = a.count(&installed(EVPN_OTHER_RT_MAC));
    gobgp_owned(w, macadv("add", EVPN_OTHER_RT_MAC, "65010:99")).await?;
    gobgp_owned(w, macadv("add", EVPN_REMOTE_MAC, rt_g)).await?;
    a.wait(&installed(EVPN_REMOTE_MAC)).await?;
    // Its IP is a kernel neighbour on the bridge too.
    let neigh_installed = format!(
        "remote neighbour installed domain={EVPN_DOMAIN} mac={EVPN_REMOTE_MAC} ip={EVPN_REMOTE_IP} vtep={IP_G}"
    );
    a.wait(&neigh_installed).await?;
    // Same UPDATE cadence as the accepted route, so a few seconds is proof.
    a.assert_quiet(&installed(EVPN_OTHER_RT_MAC), other_base, 5)
        .await?;

    log("`show fdb` over REST reflects the kernel-facing table");
    let body = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    for want in [EVPN_REMOTE_MAC, EVPN_REMOTE_IP, IP_G, &vxlan] {
        if !body.contains(want) {
            bail!("show fdb is missing {want}: {body}");
        }
    }
    if body.contains(EVPN_OTHER_RT_MAC) {
        bail!("a route with a foreign Route Target reached the fdb: {body}");
    }
    let fdb: serde_json::Value = serde_json::from_str(&body)?;
    let bridge = fdb["bridge"]
        .as_str()
        .context("show fdb has no bridge name")?
        .to_string();

    log("EVPN import policy (#502): a reject-all policy keeps the MAC out, accept-all brings it back");
    let reject_file = policy_file("evpn-reject-all", "reject\n")?;
    let rejected = "evpn route rejected by import policy";
    let rejected_base = a.count(rejected);
    let mut with_policy = flags.clone();
    with_policy.extend(strings(&[
        "--policy-name",
        "evpn-reject-all",
        "--policy-source-file",
        &reject_file,
        "--evpn-import-policy",
        "evpn-reject-all",
    ]));
    a.provision_flags(&with_policy).await?;
    a.wait_new(rejected, rejected_base, 60).await?;
    let body = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    if body.contains(EVPN_REMOTE_MAC) {
        bail!("a route the EVPN import policy rejects reached the fdb: {body}");
    }
    let installed_base = a.count(&installed(EVPN_REMOTE_MAC));
    let mut accept = flags.clone();
    accept.extend(strings(&["--evpn-import-policy", "accept-all"]));
    a.provision_flags(&accept).await?;
    a.wait_new(&installed(EVPN_REMOTE_MAC), installed_base, 60)
        .await?;

    log("remote MAC ceiling (#503): max-remote-macs 1 evicts the higher of two MACs, lifting it brings it back");
    gobgp_owned(
        w,
        macadv("add", EVPN_EXTRA_MAC, rt_g)
            .into_iter()
            // Its own IP: a second MAC on EVPN_REMOTE_IP would replace the first neighbour.
            .map(|x| {
                if x == EVPN_REMOTE_IP {
                    EVPN_EXTRA_IP.to_string()
                } else {
                    x
                }
            })
            .collect(),
    )
    .await?;
    a.wait(&installed(EVPN_EXTRA_MAC)).await?;
    let ceiling = "remote mac ceiling reached";
    let (ceiling_base, evict_base) = (a.count(ceiling), a.count(&removed(EVPN_EXTRA_MAC)));
    let mut capped = flags.clone();
    capped.extend(strings(&["--evpn-max-remote-macs", "1"]));
    a.provision_flags(&capped).await?;
    a.wait_new(ceiling, ceiling_base, 60).await?;
    a.wait_new(&removed(EVPN_EXTRA_MAC), evict_base, 30).await?;
    let body = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    // Only MAC entries count: the evicted MAC's neighbour stays.
    let macs: Vec<String> = serde_json::from_str::<serde_json::Value>(&body)?["macs"]
        .as_array()
        .context("show fdb has no macs")?
        .iter()
        .filter_map(|m| m["mac"].as_str().map(String::from))
        .collect();
    if macs != [EVPN_REMOTE_MAC] {
        bail!("the ceiling did not keep exactly the lowest MAC: {body}");
    }
    let readmit_base = a.count(&installed(EVPN_EXTRA_MAC));
    let mut lifted = flags.clone();
    lifted.extend(strings(&["--evpn-max-remote-macs", "0"]));
    a.provision_flags(&lifted).await?;
    a.wait_new(&installed(EVPN_EXTRA_MAC), readmit_base, 60)
        .await?;
    let base = a.count(&removed(EVPN_EXTRA_MAC));
    gobgp_owned(
        w,
        macadv("del", EVPN_EXTRA_MAC, rt_g)
            .into_iter()
            .map(|x| {
                if x == EVPN_REMOTE_IP {
                    EVPN_EXTRA_IP.to_string()
                } else {
                    x
                }
            })
            .collect(),
    )
    .await?;
    a.wait_new(&removed(EVPN_EXTRA_MAC), base, 30).await?;

    log("a withdrawal removes the MAC again");
    let base = a.count(&removed(EVPN_REMOTE_MAC));
    gobgp_owned(w, macadv("del", EVPN_REMOTE_MAC, rt_g)).await?;
    a.wait_new(&removed(EVPN_REMOTE_MAC), base, 30).await?;
    a.wait(&format!(
        "remote neighbour removed domain={EVPN_DOMAIN} mac={EVPN_REMOTE_MAC} ip={EVPN_REMOTE_IP} vtep={IP_G}"
    ))
    .await?;

    log("local -> BGP: pinning a MAC on a port of the domain's bridge");
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    netns_a(w, &["ip", "link", "add", EVPN_PORT, "type", "dummy"]).await?;
    netns_a(w, &["ip", "link", "set", EVPN_PORT, "master", &bridge]).await?;
    netns_a(w, &["ip", "link", "set", EVPN_PORT, "up"]).await?;
    netns_a(
        w,
        &[
            "bridge",
            "fdb",
            "add",
            EVPN_LOCAL_MAC,
            "dev",
            EVPN_PORT,
            "master",
            "static",
        ],
    )
    .await?;
    a.wait(&format!(
        "local mac learned domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC}"
    ))
    .await?;
    // GoBGP sees the Type-2 (with our RD) and the domain's own Type-3.
    gobgp_evpn_rib(w, "showed the local MAC", |rib| {
        rib.contains(EVPN_LOCAL_MAC) && rib.contains(&format!("rd:{EVPN_RD}"))
    })
    .await?;
    gobgp_evpn_rib(w, "showed router-a's Type-3", |rib| {
        rib.lines()
            .any(|l| l.contains("multicast") && l.contains(&format!("rd:{EVPN_RD}")))
    })
    .await?;

    // RFC 8326 (#860): EVPN bypasses export policy, so `graceful-shutdown`
    // tags the Type-3 unconditionally and re-announces it live.
    log("graceful-shutdown tags the Type-3, session untouched");
    let est_a = a.count("bgp session established");
    let mut gs = flags.clone();
    gs.push("--graceful-shutdown".into());
    a.provision_flags(&gs).await?;
    gobgp_evpn_rib(w, "showed router-a's Type-3 with 65535:0", |rib| {
        rib.lines().any(|l| {
            l.contains("multicast")
                && l.contains(&format!("rd:{EVPN_RD}"))
                && (l.contains("65535:0")
                    || l.contains("graceful-shutdown")
                    || l.contains("planned-shut"))
        })
    })
    .await?;
    a.assert_quiet("bgp session established", est_a, 0).await?;

    log("redistribute from connected: the SVI address is a Type-2 with the bridge's MAC");
    a.wait(&format!(
        "local neighbour learned domain={EVPN_DOMAIN} mac=.* ip={EVPN_SVI_IP}"
    ))
    .await?;
    gobgp_evpn_rib(w, "showed the SVI address", |rib| {
        rib.lines()
            .any(|l| l.contains("macadv") && l.contains(EVPN_SVI_IP))
    })
    .await?;
    // RFC 7432 §7.8: the SVI's own Type-2 carries the Default Gateway
    // extended community, so a remote PE knows it may proxy ARP/ND for it.
    gobgp_evpn_rib(w, "tagged the SVI address as the default gateway", |rib| {
        rib.lines()
            .any(|l| l.contains(EVPN_SVI_IP) && l.contains("[default-gateway]"))
    })
    .await?;

    log("redistribute from arp: a neighbour behind a local port is a Type-2 with the IP");
    netns_a(
        w,
        &[
            "ip",
            "neigh",
            "add",
            EVPN_HOST_IP,
            "lladdr",
            EVPN_LOCAL_MAC,
            "dev",
            &bridge,
            "nud",
            "permanent",
        ],
    )
    .await?;
    a.wait(&format!(
        "local neighbour learned domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC} ip={EVPN_HOST_IP}"
    ))
    .await?;
    gobgp_evpn_rib(w, "showed the neighbour's MAC+IP", |rib| {
        rib.lines()
            .any(|l| l.contains(EVPN_LOCAL_MAC) && l.contains(EVPN_HOST_IP))
    })
    .await?;
    // The default-gateway community is scoped to the SVI's own route, never
    // a real ARP-learned host.
    gobgp_evpn_rib(w, "did not tag the ARP-learned host as a gateway", |rib| {
        rib.lines()
            .any(|l| l.contains(EVPN_HOST_IP) && !l.contains("[default-gateway]"))
    })
    .await?;
    let base = a.count(&format!(
        "local neighbour removed domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC} ip={EVPN_HOST_IP}"
    ));
    netns_a(w, &["ip", "neigh", "del", EVPN_HOST_IP, "dev", &bridge]).await?;
    a.wait_new(
        &format!(
            "local neighbour removed domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC} ip={EVPN_HOST_IP}"
        ),
        base,
        30,
    )
    .await?;
    gobgp_evpn_rib(w, "withdrew the neighbour's MAC+IP", |rib| {
        !rib.contains(EVPN_HOST_IP)
    })
    .await?;

    log("removing the MAC withdraws it");
    let base = a.count(&format!(
        "local mac removed domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC}"
    ));
    netns_a(
        w,
        &[
            "bridge",
            "fdb",
            "del",
            EVPN_LOCAL_MAC,
            "dev",
            EVPN_PORT,
            "master",
        ],
    )
    .await?;
    a.wait_new(
        &format!("local mac removed domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC}"),
        base,
        30,
    )
    .await?;
    gobgp_evpn_rib(w, "dropped the local MAC", |rib| {
        !rib.contains(EVPN_LOCAL_MAC)
    })
    .await?;

    log("mac mobility (RFC 7432 §15): GoBGP announces a MAC, then the local helper pins the same one — the local claim must win");
    gobgp_owned(w, macadv("add", EVPN_MOBILE_MAC, rt_g)).await?;
    a.wait(&installed(EVPN_MOBILE_MAC)).await?;
    let removed_base = a.count(&removed(EVPN_MOBILE_MAC));
    // A real frame's dynamic learning clears the kernel's own extern_learn
    // bridge entry as it moves to the new port; this manual pin (standing in
    // for that, like the earlier `EVPN_LOCAL_MAC` one) has to do the same
    // explicitly, or `bridge fdb add` refuses the still-conflicting entry
    // nos-fdbd installed for GoBGP's remote copy.
    netns_a(
        w,
        &[
            "bridge",
            "fdb",
            "del",
            EVPN_MOBILE_MAC,
            "dev",
            &vxlan,
            "master",
        ],
    )
    .await?;
    netns_a(
        w,
        &[
            "bridge",
            "fdb",
            "add",
            EVPN_MOBILE_MAC,
            "dev",
            EVPN_PORT,
            "master",
            "static",
        ],
    )
    .await?;
    a.wait(&format!(
        "local mac learned domain={EVPN_DOMAIN} mac={EVPN_MOBILE_MAC}"
    ))
    .await?;
    // A genuine local re-learn always outranks GoBGP's stale (sequence-0)
    // remote copy (RFC 7432 §7.7), so nos-bgpd stops advertising it to
    // nos-fdbd and the earlier remote installation is torn down.
    a.wait_new(&removed(EVPN_MOBILE_MAC), removed_base, 30)
        .await?;

    log("unsetting the vni stops nos-fdbd and deletes the vxlan device");
    netns_a(w, &["ip", "link", "del", EVPN_PORT]).await?;
    let mut clear = evpn_flags();
    clear.extend(strings(&[
        "--broadcast-domain",
        EVPN_DOMAIN,
        "--evpn-clear",
        "--evpn-rt-import",
        EVPN_RT_IMPORT,
        "--evpn-rt-export",
        EVPN_RT_EXPORT,
    ]));
    a.provision_flags(&clear).await?;
    a.wait(&format!(
        "broadcast domain removed from config, stopping nos-fdbd name={EVPN_DOMAIN}"
    ))
    .await?;
    // `nos-fdbd` deletes the device on SIGINT, after its own log forwarding has
    // already shut down — so, like the `rest` phase's teardown checks, read the
    // container's stdout (which carries ANSI colour, hence two separate checks).
    for _ in 0..30 {
        let logs = w.dock.logs("router-a").await?;
        if logs.contains("deleted vxlan device") && logs.contains(&vxlan) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("nos-fdbd never logged deleting {vxlan}")
}

/// GoBGP's spelling of `ESI` (`arbitrary` + the nine value bytes).
const GOBGP_ESI: [&str; 2] = ["arbitrary", "11:22:33:44:55:66:77:88:99"];
/// How GoBGP prints that ESI in its RIB.
const GOBGP_ESI_TEXT: &str = "ESI_ARBITRARY | 11:22:33:44:55:66:77:88:99";
/// What GoBGP (4.9.0) logs on router-a's Type-4: it has no decoder for the
/// RFC 8584 DF Election community (EVPN extended community subtype 6) and,
/// against RFC 4360/7606, treats the whole UPDATE as a withdraw rather than
/// ignoring the unknown community — so the Type-4 never reaches its RIB.
const GOBGP_DF_ELECTION_REJECT: &str = "unknown evpn subtype: 6";

/// Waits for GoBGP to log rejecting one more of router-a's Type-4 routes than
/// `base` (see `GOBGP_DF_ELECTION_REJECT`): the evidence a Type-4 was sent.
async fn wait_gobgp_type4(w: &World, base: usize) -> anyhow::Result<()> {
    for _ in 0..30 {
        if gobgp_type4_count(w).await? > base {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("GoBGP never logged receiving (and rejecting) router-a's Type-4 with its DF Election community")
}

async fn gobgp_type4_count(w: &World) -> anyhow::Result<usize> {
    Ok(w.dock
        .logs("router-g")
        .await?
        .matches(GOBGP_DF_ELECTION_REJECT)
        .count())
}

/// EVPN multi-homing (RFC 7432 §8): a port aggregate with an `esi` that is an
/// untagged member of the EVPN broadcast domain.
///
/// A MAC pinned behind the bond is originated as a Type-2 carrying the ESI, a
/// MAC behind an ordinary port keeps ESI 0, and the domain originates a
/// Type-4 Ethernet Segment route — all seen by GoBGP. GoBGP then plays a
/// second PE on the segment with a lower address, which wins the DF election
/// for the (even) VNI: router-a must become the non-DF and turn flooding off on
/// the bond in the real kernel (read back with the helper's `bridge -d link`);
/// when that PE's Type-4 is withdrawn router-a is the DF again and floods.
/// Clearing the ESI while non-DF must restore flooding and withdraw the
/// Type-4 and the Type-2's ESI. Control plane and kernel port state only, not
/// forwarding.
pub async fn evpn_esi(w: &mut World) -> anyhow::Result<()> {
    evpn_speaker(w, &[DF_WAIT_ARG]).await?;
    w.connect_bond_networks().await?;
    let a = w.a()?;

    let mut flags = evpn_flags();
    flags.extend(strings(&[
        "--broadcast-domain",
        EVPN_DOMAIN,
        "--evpn-vni",
        &EVPN_VNI.to_string(),
        "--evpn-rd",
        EVPN_RD,
        "--evpn-rt-import",
        EVPN_RT_IMPORT,
        "--evpn-rt-export",
        EVPN_RT_EXPORT,
        "--evpn-vtep-source-interface",
        "eth0",
        "--evpn-redistribute-bgp",
        "r1",
        "--port-aggregate",
        "bond1",
        "--port-aggregate-esi",
        ESI,
        "--port-aggregate-df-algorithm",
        "hrw",
        "--port-aggregate-untagged-domain",
        EVPN_DOMAIN,
        "--enslave-interface-into-port-aggregate",
        "eth1",
        "--enslave-interface-into-port-aggregate",
        "eth2",
    ]));
    a.provision_flags(&flags).await?;
    let vxlan = format!("vx{EVPN_VNI}");
    a.wait(&format!(
        "vxlan device ready domain={EVPN_DOMAIN} vni={EVPN_VNI} vxlan={vxlan}"
    ))
    .await?;

    let bond = bond_name(a, "bond1").await?;
    let role = |r: &str| format!("df elected domain={EVPN_DOMAIN} esi={ESI} port={bond} role={r}");
    let flooding =
        |on: bool| format!("segment port flooding set domain={EVPN_DOMAIN} port={bond} flood={on}");

    // The DF wait timer, against the real kernel: the port is held blocked
    // (whatever the election would say) until it ends, and only then elected.
    // The wait is long enough (12s) for the helper container to read the port.
    log("DF wait timer: the bond is blocked before any election is applied");
    a.wait(&format!(
        "df wait started domain={EVPN_DOMAIN} esi={ESI} port={bond} seconds={DF_WAIT_SECS}"
    ))
    .await?;
    if a.count(&role("df")) != 0 {
        bail!("router-a elected before its DF wait timer ended");
    }
    a.wait(&flooding(false)).await?;
    bridge_port_flood(w, "router-a", &bond, false).await?;
    // Local bias (#24): a port in its DF wait drops core BUM through the DF
    // filter, and floods multicast/broadcast (read above) for its own hosts.
    tc_has(w, "router-a", &bond, "egress", "handle 0xe5000000", true).await?;
    let table = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    let table: serde_json::Value = serde_json::from_str(&table)?;
    if table["segments"][0]["designated_forwarder"] != false {
        bail!("show fdb lists router-a as the DF during its wait timer: {table}");
    }

    log("alone on the segment: once the timer ends router-a is the DF (hrw, nobody disagrees) and the bond floods");
    a.wait(&format!(
        "{} algorithm=hrw ac_df=true pes={IP_A}",
        role("df")
    ))
    .await?;
    a.wait(&flooding(true)).await?;

    log("pinning a MAC behind the bond and another behind an ordinary port");
    let body = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    let fdb: serde_json::Value = serde_json::from_str(&body)?;
    let bridge = fdb["bridge"]
        .as_str()
        .context("show fdb has no bridge name")?
        .to_string();
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    netns_a(w, &["ip", "link", "add", EVPN_PORT, "type", "dummy"]).await?;
    netns_a(w, &["ip", "link", "set", EVPN_PORT, "master", &bridge]).await?;
    netns_a(w, &["ip", "link", "set", EVPN_PORT, "up"]).await?;
    for (mac, dev) in [(ESI_MAC, bond.as_str()), (EVPN_LOCAL_MAC, EVPN_PORT)] {
        netns_a(
            w,
            &["bridge", "fdb", "add", mac, "dev", dev, "master", "static"],
        )
        .await?;
    }
    a.wait(&format!(
        "local mac learned domain={EVPN_DOMAIN} mac={ESI_MAC} port={bond}"
    ))
    .await?;
    a.wait(&format!(
        "local mac learned domain={EVPN_DOMAIN} mac={EVPN_LOCAL_MAC} port={EVPN_PORT}"
    ))
    .await?;

    log("GoBGP sees the ESI on the Type-2 behind the bond, none on the other, and a Type-4");
    gobgp_evpn_rib(w, "showed the segment's Type-2", |rib| {
        rib.lines()
            .any(|l| l.contains(ESI_MAC) && l.contains(GOBGP_ESI_TEXT))
    })
    .await?;
    gobgp_evpn_rib(w, "showed the other MAC without an ESI", |rib| {
        rib.lines()
            .any(|l| l.contains(EVPN_LOCAL_MAC) && !l.contains(GOBGP_ESI_TEXT))
    })
    .await?;
    let es_route = |rib: &str| {
        rib.lines().any(|l| {
            l.contains("[type:esi]")
                && l.contains(&format!("rd:{EVPN_RD}"))
                && l.contains(GOBGP_ESI_TEXT)
                && l.contains(&format!("ip:{IP_A}"))
        })
    };
    // RFC 8584 §2.2: router-a's Type-4 carries the DF Election community.
    // GoBGP can't decode it and drops the Type-4 (`GOBGP_DF_ELECTION_REJECT`),
    // which is the evidence the community is on the wire; the rest of the
    // routes (separate UPDATEs, other attributes) are unaffected.
    log("router-a's Type-4 carries the DF Election community (GoBGP rejects it as unknown)");
    wait_gobgp_type4(w, 0).await?;

    // Type-1 (RFC 7432 §8.2/§8.4): per-ES is MAX-ET with an ESI Label community
    // (all-active here), per-EVI is tag 0 with the VNI in the label.
    log("Type-1: GoBGP sees router-a's per-ES A-D (MAX-ET, ESI Label) and per-EVI A-D (VNI)");
    let ad_route = |rib: &str, per_es: bool| {
        rib.lines().any(|l| {
            l.contains("[type:A-D]")
                && l.contains(&format!("rd:{EVPN_RD}"))
                && l.contains(GOBGP_ESI_TEXT)
                && l.contains(EVPN_RT_EXPORT)
                && if per_es {
                    l.contains("[etag:4294967295]") && l.contains("[esi-label: 0]")
                } else {
                    l.contains("[etag:0]")
                        && l.contains(&format!("[{EVPN_VNI}]"))
                        && !l.contains("esi-label")
                }
        })
    };
    gobgp_evpn_rib(w, "showed router-a's per-ES A-D", |rib| ad_route(rib, true)).await?;
    gobgp_evpn_rib(w, "showed router-a's per-EVI A-D", |rib| {
        ad_route(rib, false)
    })
    .await?;

    let body = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    let table: serde_json::Value = serde_json::from_str(&body)?;
    if table["segments"][0]["designated_forwarder"] != true
        || table["segments"][0]["port"] != bond
        || table["segments"][0]["up"] != true
    {
        bail!("show fdb does not list the segment up with router-a as DF: {body}");
    }

    let peer_es = |verb: &'static str| {
        let mut v = strings(&["global", "rib", verb, "-a", "evpn", "esi", ESI_PEER_ORIGIN]);
        v.push("esi".to_string());
        v.extend(strings(&GOBGP_ESI));
        v.extend(strings(&["rd", "65010:1"]));
        if verb == "add" {
            v.extend(strings(&["rt", "65010:1", "encap", "vxlan"]));
        }
        v
    };
    bridge_port_flood(w, "router-a", &bond, true).await?;

    // RFC 8584 §2.2.3, strictly: GoBGP's Type-4 carries no DF Election
    // community, so no AC-DF — the per-EVI filter is off and RFC 7432's
    // candidate list (every Type-4 origin) applies, and HRW falls back to
    // modulo. The bare-Type-4 PE is a candidate and, lower than router-a,
    // wins the even VNI (see `consts::ESI_PEER_NO_EVI_ORIGIN`).
    log("a peer with only a bare Type-4 and no AC-DF is a df candidate again (RFC 7432 list), and hrw falls back to modulo");
    let peer_es_no_evi = |verb: &'static str| {
        let mut v = strings(&[
            "global",
            "rib",
            verb,
            "-a",
            "evpn",
            "esi",
            ESI_PEER_NO_EVI_ORIGIN,
        ]);
        v.push("esi".to_string());
        v.extend(strings(&GOBGP_ESI));
        v.extend(strings(&["rd", "65010:2"]));
        if verb == "add" {
            v.extend(strings(&["rt", "65010:2", "encap", "vxlan"]));
        }
        v
    };
    let fallback = |r: &str| {
        format!(
            "{} algorithm=modulo ac_df=false pes={ESI_PEER_NO_EVI_ORIGIN},{IP_A}",
            role(r)
        )
    };
    let base = a.count(&fallback("non-df"));
    gobgp_owned(w, peer_es_no_evi("add")).await?;
    a.wait_new(&fallback("non-df"), base, 30).await?;
    bridge_port_flood(w, "router-a", &bond, false).await?;
    let base = a.count(&role("df"));
    gobgp_owned(w, peer_es_no_evi("del")).await?;
    a.wait_new(&role("df"), base, 30).await?;
    bridge_port_flood(w, "router-a", &bond, true).await?;

    log("a second PE on the segment, also attached to this EVI (per-EVI A-D), with a lower address wins the election");
    let base = a.count(&role("non-df"));
    gobgp_owned(w, peer_es("add")).await?;
    gobgp_owned(
        w,
        gobgp_ad("add", &GOBGP_ESI, false, (ESI_PEER_ORIGIN, "65010:1")),
    )
    .await?;
    a.wait_new(&role("non-df"), base, 30).await?;
    a.wait(&flooding(false)).await?;
    bridge_port_flood(w, "router-a", &bond, false).await?;
    log("local bias: router-a marks what the second PE sends (enc_src_ip on vx ingress) and drops it on the bond");
    local_bias_readback(w, "router-a", &bond, &vxlan, ESI_PEER_ORIGIN, true).await?;

    log("its Type-4 and per-EVI A-D withdrawn: router-a is the DF again and the bond floods");
    let base = a.count(&role("df"));
    gobgp_owned(w, peer_es("del")).await?;
    gobgp_owned(
        w,
        gobgp_ad("del", &GOBGP_ESI, false, (ESI_PEER_ORIGIN, "65010:1")),
    )
    .await?;
    a.wait_new(&role("df"), base, 30).await?;
    bridge_port_flood(w, "router-a", &bond, true).await?;
    // No other PE on the segment: no marking, no DF filter, only the port's own.
    tc_has(
        w,
        "router-a",
        &vxlan,
        "ingress",
        &format!("enc_src_ip {ESI_PEER_ORIGIN}"),
        false,
    )
    .await?;
    tc_has(w, "router-a", &bond, "egress", "handle 0xe5000000", false).await?;

    log("mass withdrawal: MACs of a segment router-a is not on wait for their PE's per-ES A-D");
    let vni = EVPN_VNI.to_string();
    let macadv2 = |verb: &'static str, mac: &'static str, ip: &'static str| {
        let mut v = strings(&[
            "global", "rib", verb, "-a", "evpn", "macadv", mac, ip, "esi",
        ]);
        v.extend(strings(&ESI2));
        v.extend(strings(&["etag", "0", "label", &vni, "rd", ESI2_RD]));
        if verb == "add" {
            v.extend(strings(&["rt", EVPN_RT_IMPORT, "encap", "vxlan"]));
        }
        v
    };
    let ad2 = |verb: &'static str| {
        let mut v = strings(&["global", "rib", verb, "-a", "evpn", "a-d", "esi"]);
        v.extend(strings(&ESI2));
        v.extend(strings(&[
            "etag",
            "4294967295",
            "label",
            "0",
            "rd",
            ESI2_RD,
        ]));
        if verb == "add" {
            v.extend(strings(&[
                "rt",
                EVPN_RT_IMPORT,
                "encap",
                "vxlan",
                "esi-label",
                "0",
                "all-active",
            ]));
        }
        v
    };
    let installed =
        |mac: &str| format!("remote mac installed domain={EVPN_DOMAIN} mac={mac} vtep={IP_G}");
    let removed =
        |mac: &str| format!("remote mac removed domain={EVPN_DOMAIN} mac={mac} vtep={IP_G}");
    let installed_base: Vec<usize> = ESI2_MACS
        .iter()
        .map(|(m, _)| a.count(&installed(m)))
        .collect();
    for (m, ip) in ESI2_MACS {
        gobgp_owned(w, macadv2("add", m, ip)).await?;
    }
    // Their PE has not advertised the segment yet: the MACs are not usable.
    a.assert_quiet(&installed(ESI2_MACS[0].0), installed_base[0], 5)
        .await?;
    gobgp_owned(w, ad2("add")).await?;
    for (i, (m, _)) in ESI2_MACS.iter().enumerate() {
        a.wait_new(&installed(m), installed_base[i], 30).await?;
    }
    let body = a
        .rest_expect(Method::GET, "/v1/bgp/evpn", None, 200)
        .await?;
    if !body.contains("esi-label:all-active") {
        bail!("show bgp evpn does not decode the ESI Label community: {body}");
    }
    log("withdrawing that one route takes every MAC of the segment away at once");
    let removed_base: Vec<usize> = ESI2_MACS
        .iter()
        .map(|(m, _)| a.count(&removed(m)))
        .collect();
    gobgp_owned(w, ad2("del")).await?;
    for (i, (m, _)) in ESI2_MACS.iter().enumerate() {
        a.wait_new(&removed(m), removed_base[i], 30).await?;
    }
    log("advertising it again brings them back");
    let installed_base: Vec<usize> = ESI2_MACS
        .iter()
        .map(|(m, _)| a.count(&installed(m)))
        .collect();
    gobgp_owned(w, ad2("add")).await?;
    for (i, (m, _)) in ESI2_MACS.iter().enumerate() {
        a.wait_new(&installed(m), installed_base[i], 30).await?;
    }
    gobgp_owned(w, ad2("del")).await?;
    for (m, ip) in ESI2_MACS {
        gobgp_owned(w, macadv2("del", m, ip)).await?;
    }

    log("aliasing: a MAC on a segment two PEs serve is balanced over both, in the real kernel");
    let alias_mac = ESI3_MAC.0;
    let [pe1, pe2] = ESI3_PES;
    let group_installed = format!(
        "remote mac group installed domain={EVPN_DOMAIN} mac={alias_mac} vteps={},{}",
        pe1.0, pe2.0
    );
    let group_base = a.count(&group_installed);
    gobgp_owned(w, gobgp_macadv("add", &ESI3, ESI3_MAC, pe1)).await?;
    for pe in [pe1, pe2] {
        gobgp_owned(w, gobgp_ad("add", &ESI3, true, pe)).await?;
        gobgp_owned(w, gobgp_ad("add", &ESI3, false, pe)).await?;
    }
    a.wait_new(&group_installed, group_base, 30).await?;
    let (nexthops, entry) = kernel_aliasing(w, alias_mac).await?;
    if !entry.contains("nhid") {
        bail!("the aliased MAC's FDB entry does not use a nexthop group: {entry:?}");
    }
    let groups = nexthops.lines().filter(|l| l.contains("group ")).count();
    if groups != 1
        || !nexthops.contains(&format!("via {}", pe1.0))
        || !nexthops.contains(&format!("via {}", pe2.0))
    {
        bail!("expected one FDB group over both PEs: {nexthops}");
    }
    let body = a
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    let table: serde_json::Value = serde_json::from_str(&body)?;
    let aliased = table["macs"]
        .as_array()
        .and_then(|m| m.iter().find(|e| e["mac"] == alias_mac))
        .context("show fdb lacks the aliased MAC")?;
    if aliased["vteps"].as_array().map(Vec::len) != Some(2) {
        bail!("show fdb does not list both VTEPs of the aliased MAC: {aliased}");
    }

    log("the second PE stops serving the EVI: the MAC is back on the one PE that does");
    let removed = format!(
        "remote mac group removed domain={EVPN_DOMAIN} mac={alias_mac} vteps={},{}",
        pe1.0, pe2.0
    );
    let removed_base = a.count(&removed);
    gobgp_owned(w, gobgp_ad("del", &ESI3, false, pe2)).await?;
    a.wait_new(&removed, removed_base, 30).await?;
    a.wait(&format!(
        "remote mac installed domain={EVPN_DOMAIN} mac={alias_mac} vtep={}",
        pe1.0
    ))
    .await?;
    let (_, entry) = kernel_aliasing(w, alias_mac).await?;
    if entry.contains("nhid") || !entry.contains(&format!("dst {}", pe1.0)) {
        bail!("the MAC did not fall back to its one PE: {entry:?}");
    }

    log("cleaning up the aliasing routes");
    gobgp_owned(w, gobgp_macadv("del", &ESI3, ESI3_MAC, pe1)).await?;
    for pe in [pe1, pe2] {
        gobgp_owned(w, gobgp_ad("del", &ESI3, true, pe)).await?;
    }
    gobgp_owned(w, gobgp_ad("del", &ESI3, false, pe1)).await?;

    single_active_backup(w).await?;

    log("ES down: the bond losing both members withdraws Type-4 and both Type-1, their return restores them");
    let carrier_up =
        format!("segment port carrier changed domain={EVPN_DOMAIN} port={bond} up=true");
    let base = a.count(&carrier_up);
    // The bond has no link monitoring: it only loses carrier once every member is gone.
    link_lost(w, "router-a", &[NET_BOND1, NET_BOND2]).await;
    a.wait(&format!(
        "segment port carrier changed domain={EVPN_DOMAIN} port={bond} up=false"
    ))
    .await?;
    gobgp_evpn_rib(w, "dropped router-a's segment routes", |rib| {
        !es_route(rib) && !ad_route(rib, true) && !ad_route(rib, false)
    })
    .await?;
    let type4_base = gobgp_type4_count(w).await?;
    link_back(w, "router-a", &[NET_BOND1, NET_BOND2], &["eth1", "eth2"]).await?;
    a.wait_new(&carrier_up, base, 30).await?;
    gobgp_evpn_rib(w, "re-advertised router-a's segment routes", |rib| {
        ad_route(rib, true) && ad_route(rib, false)
    })
    .await?;
    // The Type-4 itself only shows as GoBGP rejecting it again.
    wait_gobgp_type4(w, type4_base).await?;

    log("back to non-DF, then clearing the ESI restores flooding and withdraws it");
    let base = a.count(&role("non-df"));
    gobgp_owned(w, peer_es("add")).await?;
    gobgp_owned(
        w,
        gobgp_ad("add", &GOBGP_ESI, false, (ESI_PEER_ORIGIN, "65010:1")),
    )
    .await?;
    a.wait_new(&role("non-df"), base, 30).await?;
    bridge_port_flood(w, "router-a", &bond, false).await?;
    let mut clear = flags.clone();
    let at = clear
        .iter()
        .position(|f| f == "--port-aggregate-esi")
        .context("the ESI flag is in the base flags")?;
    clear.drain(at..=at + 1);
    clear.push("--delete-port-aggregate-esi".to_string());
    // A df-algorithm needs an esi (commit-time check): back to the default.
    for f in &mut clear {
        if f == "hrw" {
            "modulo".clone_into(f);
        }
    }
    a.provision_flags(&clear).await?;
    bridge_port_flood(w, "router-a", &bond, true).await?;
    gobgp_evpn_rib(
        w,
        "dropped router-a's Type-4, Type-1s and the Type-2's ESI",
        |rib| {
            !es_route(rib)
                && !ad_route(rib, true)
                && !ad_route(rib, false)
                && rib
                    .lines()
                    .any(|l| l.contains(ESI_MAC) && !l.contains(GOBGP_ESI_TEXT))
        },
    )
    .await
}

/// `evpn-esi`, RFC 7432 §8.4.1.2: on a single-active segment router-a is not
/// on, a MAC whose own PE loses its per-ES A-D moves to the PE the segment
/// elects as DF among the remaining ones (by their Type-4s), not to the
/// lowest address — and to the lowest address once no Type-4 is held. Read
/// back from the real kernel FDB (see `consts::ESI4_PES`). GoBGP can't send a
/// Type-4 with the ES-Import RT `nos-fdbd` requires, so the one Type-4 comes
/// from a real FRR (`router-f`, see `start_frr_segment`).
async fn single_active_backup(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    log("single-active backup: the MAC moves to the segment's elected DF, not the lowest address");
    let single = |v: Vec<String>| -> Vec<String> {
        v.into_iter()
            .map(|s| {
                if s == "all-active" {
                    "single-active".to_string()
                } else {
                    s
                }
            })
            .collect()
    };
    let mac = ESI4_MAC.0;
    let at = |pe: &str| format!("remote mac installed domain={EVPN_DOMAIN} mac={mac} vtep={pe}");
    let in_kernel = |pe: &'static str| async move {
        let (_, entry) = kernel_aliasing(w, mac).await?;
        if entry.contains("nhid") || !entry.contains(&format!("dst {pe}")) {
            bail!("the MAC's FDB entry is not a plain one to {pe}: {entry:?}");
        }
        anyhow::Ok(())
    };
    let [p1, p2, _, p4] = ESI4_PES;
    let base = a.count(&at(p1.0));
    for pe in ESI4_PES {
        gobgp_owned(w, single(gobgp_ad("add", &ESI4, true, pe))).await?;
        gobgp_owned(w, gobgp_ad("add", &ESI4, false, pe)).await?;
    }
    gobgp_owned(w, gobgp_macadv("add", &ESI4, ESI4_MAC, p1)).await?;
    a.wait_new(&at(p1.0), base, 30).await?;
    in_kernel(p1.0).await?;

    log("its PE loses its per-ES A-D: the backup is the PE whose Type-4 (with the ES-Import RT) is held (.24)");
    start_frr_segment(w).await?;
    let base = a.count(&at(p4.0));
    gobgp_owned(w, gobgp_ad("del", &ESI4, true, p1)).await?;
    a.wait_new(&at(p4.0), base, 30).await?;
    in_kernel(p4.0).await?;

    log("its Type-4 withdrawn: the lowest address (.22)");
    let base = a.count(&at(p2.0));
    w.dock.container_remove("router-f").await;
    gobgp_owned(w, strings(&["neighbor", "del", p4.0])).await?;
    a.wait_new(&at(p2.0), base, 30).await?;
    in_kernel(p2.0).await?;

    gobgp_owned(w, gobgp_macadv("del", &ESI4, ESI4_MAC, p1)).await?;
    for pe in ESI4_PES {
        gobgp_owned(w, gobgp_ad("del", &ESI4, false, pe)).await?;
    }
    for pe in &ESI4_PES[1..] {
        gobgp_owned(w, gobgp_ad("del", &ESI4, true, *pe)).await?;
    }
    Ok(())
}

/// Starts FRR (`router-f`) at the fourth `ESI4` PE's address as a PE on the
/// segment: a bond with `evpn mh es-id` makes it originate the Type-4 with the
/// ES-Import RT. It peers GoBGP, which relays the route to router-a; a
/// route-map strips FRR's DF Election community, which GoBGP can't decode and
/// would treat the whole UPDATE as a withdraw. Returns once GoBGP holds it.
async fn start_frr_segment(w: &World) -> anyhow::Result<()> {
    let (vtep, _) = ESI4_PES[3];
    let esi = format!("00:{}", ESI4[1]);
    let conf = format!(
        "frr defaults traditional\nhostname router-f\n!\n\
         bgp extcommunity-list expanded NODF permit DF\n\
         route-map NODF permit 10\n set extended-comm-list NODF delete\nexit\n\
         interface bond1\n evpn mh es-id {esi}\nexit\n\
         router bgp {ESI4_FRR_ASN}\n bgp router-id {vtep}\n no bgp ebgp-requires-policy\n \
         neighbor {IP_G} remote-as {ASN_G}\n address-family l2vpn evpn\n  \
         neighbor {IP_G} activate\n  neighbor {IP_G} route-map NODF out\n  \
         advertise-all-vni\n exit-address-family\nexit\n"
    );
    // A bond with an up member is the segment's port; the VXLAN device on its
    // bridge makes zebra's EVPN run.
    let setup = format!(
        "sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons && \
         ip link add br0 type bridge && \
         ip link add vx{EVPN_VNI} type vxlan id {EVPN_VNI} local {vtep} dstport 4789 nolearning && \
         ip link set vx{EVPN_VNI} master br0 && ip link add d1 type dummy && \
         ip link add bond1 type bond mode 802.3ad && ip link set d1 master bond1 && \
         ip link set bond1 master br0 && \
         ip link set d1 up && ip link set bond1 up && ip link set br0 up && \
         ip link set vx{EVPN_VNI} up && exec /usr/lib/frr/docker-start"
    );
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    w.dock
        .start_plain_caps(
            "router-f",
            FRR_IMAGE,
            NET,
            vtep,
            &["sh", "-c", &setup],
            ("/etc/frr", "frr.conf", conf.as_bytes()),
            &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        )
        .await?;
    gobgp_owned(
        w,
        strings(&[
            "neighbor",
            "add",
            vtep,
            "as",
            &ESI4_FRR_ASN.to_string(),
            "family",
            "l2vpn-evpn",
        ]),
    )
    .await?;
    gobgp_evpn_rib(w, "learned FRR's Type-4", |rib| {
        rib.contains("es-import rt: 11:22:33:44:55:66")
    })
    .await
}

/// GoBGP arguments to add/delete one PE's A-D route for `esi`: per-ES (MAX-ET,
/// all-active ESI Label) or per-EVI (tag 0, the VNI in the label), advertised
/// with `nexthop` as its VTEP.
fn gobgp_ad(
    verb: &'static str,
    esi: &[&str; 2],
    per_es: bool,
    (nexthop, rd): (&str, &str),
) -> Vec<String> {
    let (etag, label) = if per_es {
        ("4294967295".to_string(), "0".to_string())
    } else {
        ("0".to_string(), EVPN_VNI.to_string())
    };
    let mut v = strings(&["global", "rib", verb, "-a", "evpn", "a-d", "esi"]);
    v.extend(strings(esi));
    v.extend(strings(&["etag", &etag, "label", &label, "rd", rd]));
    if verb == "add" {
        v.extend(strings(&["rt", EVPN_RT_IMPORT, "encap", "vxlan"]));
        if per_es {
            v.extend(strings(&["esi-label", "0", "all-active"]));
        }
        v.extend(strings(&["nexthop", nexthop]));
    }
    v
}

/// GoBGP arguments to add/delete a MAC (with an IP, which GoBGP requires) on
/// `esi`, advertised by the PE `nexthop`.
fn gobgp_macadv(
    verb: &'static str,
    esi: &[&str; 2],
    (mac, ip): (&str, &str),
    (nexthop, rd): (&str, &str),
) -> Vec<String> {
    let mut v = strings(&[
        "global", "rib", verb, "-a", "evpn", "macadv", mac, ip, "esi",
    ]);
    v.extend(strings(esi));
    v.extend(strings(&[
        "etag",
        "0",
        "label",
        &EVPN_VNI.to_string(),
        "rd",
        rd,
    ]));
    if verb == "add" {
        v.extend(strings(&[
            "rt",
            EVPN_RT_IMPORT,
            "encap",
            "vxlan",
            "nexthop",
            nexthop,
        ]));
    }
    v
}

/// `evpn-esi`'s kernel read-back: router-a's FDB nexthop groups, and the
/// `vx<vni>` FDB entry for `mac` (empty when there is none).
async fn kernel_aliasing(w: &World, mac: &str) -> anyhow::Result<(String, String)> {
    let nexthops = netns_a(w, &["ip", "nexthop", "show"]).await?;
    let fdb = netns_a(
        w,
        &["bridge", "fdb", "show", "dev", &format!("vx{EVPN_VNI}")],
    )
    .await?;
    let entry = fdb
        .lines()
        .filter(|l| l.contains(mac) && l.contains(" self"))
        .collect::<Vec<_>>()
        .join("\n");
    Ok((nexthops, entry))
}

/// The kernel name `router`'s `nos-interfaced` gave the port aggregate `name`.
async fn bond_name(r: &Router, name: &str) -> anyhow::Result<String> {
    for _ in 0..30 {
        let body = r
            .rest_expect(Method::GET, "/v1/port-aggregates", None, 200)
            .await?;
        let aggregates: serde_json::Value = serde_json::from_str(&body)?;
        if let Some(bond) = aggregates
            .as_array()
            .and_then(|v| v.iter().find(|s| s["name"] == name))
            .and_then(|s| s["bond_name"].as_str())
        {
            return Ok(bond.to_string());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{}: nos-interfaced never created a bond for {name}",
        r.name()
    )
}

/// `evpn-dataplane`: one PE's whole EVPN config — an eBGP session to the other
/// PE with `address-family l2vpn-evpn` and the domain, sharing one Route Target.
fn evpn_pe_flags(id: Id, rd: &str) -> Vec<String> {
    let mut flags = id.base_flags();
    flags.extend(strings(&[
        "--peer-group",
        "pg-evpn",
        "--evpn",
        "--broadcast-domain",
        EVPN_DOMAIN,
        "--evpn-vni",
        &EVPN_VNI.to_string(),
        "--evpn-rd",
        rd,
        "--evpn-rt-import",
        EVPN_DP_RT,
        "--evpn-rt-export",
        EVPN_DP_RT,
        "--evpn-vtep-source-interface",
        "eth0",
        "--evpn-redistribute-bgp",
        "r1",
    ]));
    flags
}

/// A one-member static port aggregate, untagged in the EVPN domain, on the
/// docker-network `member` link; `esi` makes it an Ethernet Segment.
fn bond_flags(name: &str, esi: bool, member: &str) -> Vec<String> {
    let mut flags = strings(&["--port-aggregate", name]);
    if esi {
        flags.extend(strings(&["--port-aggregate-esi", ESI]));
    }
    flags.extend(strings(&[
        "--port-aggregate-untagged-domain",
        EVPN_DOMAIN,
        "--enslave-interface-into-port-aggregate",
        member,
    ]));
    flags
}

/// Runs a shell script in an end-host container; errors on a non-zero exit.
async fn host_sh(w: &World, host: &str, script: &str) -> anyhow::Result<String> {
    let (code, out) = w.dock.exec(host, &["sh", "-c", script]).await?;
    if code != 0 {
        bail!("{host}: `{script}` exited {code}: {}", out.trim());
    }
    Ok(out)
}

/// How many ARP requests for `target` from `sender` a capture file on `host`
/// holds. `arping` prints the target MAC (`who-has X (ff:ff:..) tell Y`), the
/// kernel's own requests don't.
async fn arp_requests(
    w: &World,
    host: &str,
    file: &str,
    target: &str,
    sender: &str,
) -> anyhow::Result<usize> {
    let script = format!("grep -c -E 'who-has {target}( .*)? tell {sender}' {file} || true");
    let out = host_sh(w, host, &script).await?;
    out.trim()
        .parse()
        .with_context(|| format!("counting ARP requests in {file}: {out:?}"))
}

/// `hrw` sets `df-algorithm hrw` on both PEs' bonds; the DF is then router-b
/// (see the HRW note in `consts.rs`), modulo's router-a. Returns (router-a's bond,
/// router-b's bond).
async fn dataplane_setup(
    w: &mut World,
    single_active: bool,
    hrw: bool,
) -> anyhow::Result<(String, String)> {
    w.start(A, Some(evpn_pe_flags(A, EVPN_DP_RD_A)), &[])
        .await?;
    w.start(B, Some(evpn_pe_flags(B, EVPN_DP_RD_B)), &[])
        .await?;
    let (a, b) = (w.a()?, w.b()?);
    a.established().await?;
    b.established().await?;

    // The underlay is in a VRF (`rt1`): its VXLAN sockets only accept packets
    // that came in through a VRF slave with this set. Nothing in nos sets it
    // (the daemons are unprivileged and /proc/sys is read-only in the
    // container), so it is an operator prerequisite the harness applies.
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    for router in ["router-a", "router-b"] {
        w.dock
            .in_netns(
                NETNS_HELPER_IMAGE,
                router,
                &["sh", "-c", "echo 1 > /proc/sys/net/ipv4/udp_l3mdev_accept"],
            )
            .await?;
    }

    log("wiring the CE (to both PEs) and the host (to router-b) over docker networks");
    for net in [NET_CE_A, NET_CE_B, NET_H] {
        if !w.dock.network_exists(net).await {
            w.dock.network_create(net, &[], false).await?;
        }
    }
    w.dock.network_connect(NET_CE_A, "router-a").await;
    w.dock.network_connect(NET_CE_B, "router-b").await;
    w.dock.network_connect(NET_H, "router-b").await;
    w.dock
        .ensure_image(
            HOST_IMAGE,
            "FROM debian:bookworm-slim\n\
             RUN apt-get update && apt-get install -y --no-install-recommends \\\n \
             iproute2 iputils-ping iputils-arping tcpdump && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    w.dock.start_host(CE_HOST, HOST_IMAGE, NET_CE_A).await?;
    w.dock.network_connect(NET_CE_B, CE_HOST).await;
    w.dock.start_host(H_HOST, HOST_IMAGE, NET_H).await?;

    let segment_flags = |rd: &str, router: Id| {
        let mut f = evpn_pe_flags(router, rd);
        f.extend(bond_flags("bond1", true, "eth1"));
        if single_active {
            f.extend(strings(&[
                "--port-aggregate-redundancy-mode",
                "single-active",
            ]));
        }
        if hrw {
            f.extend(strings(&["--port-aggregate-df-algorithm", "hrw"]));
        }
        f
    };
    a.provision_flags(&segment_flags(EVPN_DP_RD_A, A)).await?;
    b.provision_flags(&segment_flags(EVPN_DP_RD_B, B)).await?;
    let mut host_port = evpn_pe_flags(B, EVPN_DP_RD_B);
    host_port.extend(bond_flags("bond2", false, "eth2"));
    b.provision_flags(&host_port).await?;

    let vxlan = format!("vx{EVPN_VNI}");
    for r in [a, b] {
        r.wait(&format!(
            "vxlan device ready domain={EVPN_DOMAIN} vni={EVPN_VNI} vxlan={vxlan}"
        ))
        .await?;
    }
    a.wait(&format!(
        "flood entry installed domain={EVPN_DOMAIN} vtep={IP_B}"
    ))
    .await?;
    b.wait(&format!(
        "flood entry installed domain={EVPN_DOMAIN} vtep={IP_A}"
    ))
    .await?;

    // Both PEs always advertise AC-DF (both nos), so `ac_df=true`; `pes=`
    // names both, so a PE's own lone election before the other's Type-4
    // arrives can't match.
    let (alg, a_role, b_role) = if hrw {
        log("election (hrw): router-b wins on weight, router-a does not");
        ("hrw", "non-df", "df")
    } else {
        log("election (modulo): router-a (lower address) is the segment's DF, router-b is not");
        ("modulo", "df", "non-df")
    };
    let (bond_a, bond_b) = (bond_name(a, "bond1").await?, bond_name(b, "bond1").await?);
    let role = |bond: &str, r: &str| {
        format!(
            "df elected domain={EVPN_DOMAIN} esi={ESI} port={bond} role={r} \
             algorithm={alg} ac_df=true pes={IP_A},{IP_B}"
        )
    };
    a.wait(&role(&bond_a, a_role)).await?;
    b.wait(&role(&bond_b, b_role)).await?;
    // Each decodes the other's DF Election community (RFC 8584 §2.2).
    let community = format!("df-election:{alg},ac-df");
    let evpn = a
        .rest_expect(Method::GET, "/v1/bgp/evpn", None, 200)
        .await?;
    if !evpn.contains(&community) {
        bail!("router-a's show bgp evpn does not show router-b's {community}: {evpn}");
    }
    Ok((bond_a, bond_b))
}

/// The dual-homed CE's bond (`bond_opts` picks its mode) and the host's address.
async fn dataplane_ce(w: &World, bond_opts: &str) -> anyhow::Result<()> {
    host_sh(
        w,
        CE_HOST,
        &format!(
            "set -e; for i in eth0 eth1; do ip addr flush dev $i; ip link set $i down; done; \
             ip link add bond0 type bond {bond_opts}; \
             ip link set eth0 master bond0; ip link set eth1 master bond0; \
             ip link set bond0 up; ip addr add {CE_IP}/24 dev bond0"
        ),
    )
    .await?;
    host_sh(w, H_HOST, &format!("ip addr add {H_IP}/24 dev eth0")).await?;

    Ok(())
}

/// Removes the CE, the host and their networks.
async fn dataplane_teardown(w: &World) -> anyhow::Result<()> {
    for host in [CE_HOST, H_HOST] {
        w.dock.container_remove(host).await;
    }
    for (net, router) in [
        (NET_CE_A, "router-a"),
        (NET_CE_B, "router-b"),
        (NET_H, "router-b"),
    ] {
        w.dock.network_disconnect(net, router).await;
        w.dock.network_remove(net).await;
    }
    Ok(())
}

/// The EVPN data plane, for real: two `nos` PEs over a VXLAN underlay in a
/// VRF, a CE dual-homed to both through one Ethernet Segment (a bond of one
/// docker-network link to each PE), and a host behind router-b. Unlike
/// `evpn-fdb`/`evpn-esi` (control plane and kernel state, against GoBGP) this
/// sends frames.
///
/// Both PEs run RFC 8584 HRW (`df-algorithm hrw`), which elects router-b
/// where modulo would elect router-a (the HRW note in `consts.rs`), so the DF read
/// back from the kernel proves HRW ran. With the CE's link to router-b gone
/// (from below, so router-b's bond loses carrier and its segment is down),
/// every frame the CE sends enters router-a and must cross the VXLAN to reach
/// the host, and back: router-b reaches the CE through router-a (its remote
/// Type-2 falls back to a VXLAN entry). With the link back, router-b pins the
/// CE's MAC to its own bond (#173, read back from the kernel, as is learning
/// off on the VXLAN port); one broadcast from the host reaches the CE through
/// the DF only — once — while the non-DF's link stays silent; with the CE's
/// link to router-a down instead, the CE is bridged locally on router-b.
pub async fn evpn_dataplane(w: &mut World) -> anyhow::Result<()> {
    let (bond_a, bond_b) = dataplane_setup(w, false, true).await?;
    let (a, b) = (w.a()?, w.b()?);
    bridge_port_flood(w, "router-a", &bond_a, false).await?;
    bridge_port_flood(w, "router-b", &bond_b, true).await?;
    let vxlan = format!("vx{EVPN_VNI}");
    for router in ["router-a", "router-b"] {
        let link = w
            .dock
            .in_netns(
                NETNS_HELPER_IMAGE,
                router,
                &["bridge", "-d", "link", "show", "dev", &vxlan],
            )
            .await?;
        if !link.contains("learning off") {
            bail!("{router}'s {vxlan} does not read learning off: {link}");
        }
    }
    log("local bias in the kernel: router-a (non-DF) drops core BUM too, router-b (DF) only the other PE's");
    local_bias_readback(w, "router-a", &bond_a, &vxlan, IP_B, true).await?;
    local_bias_readback(w, "router-b", &bond_b, &vxlan, IP_A, false).await?;

    log("the CE bonds its two links; the host takes an address");
    dataplane_ce(w, "mode balance-xor miimon 100 xmit_hash_policy layer2").await?;
    let ce_mac = host_sh(w, CE_HOST, "cat /sys/class/net/bond0/address")
        .await?
        .trim()
        .to_string();

    log("unicast across the VXLAN: router-b loses its CE link, so every frame enters router-a");
    let carrier_b = |up: bool| {
        format!("segment port carrier changed domain={EVPN_DOMAIN} port={bond_b} up={up}")
    };
    // Before router-b's Type-4 arrived, router-a may have elected itself alone.
    let df_a = format!("df elected domain={EVPN_DOMAIN} esi={ESI} port={bond_a} role=df");
    let df_a_base = a.count(&df_a);
    host_sh(w, CE_HOST, "ip link set eth1 down").await?;
    link_lost(w, "router-b", &[NET_CE_B]).await;
    b.wait(&carrier_b(false)).await?;
    a.wait_new(&df_a, df_a_base, 60).await?;
    ping_until(w, CE_HOST, H_IP, 30).await?;
    host_sh(w, CE_HOST, &format!("ping -c 3 -W 2 {H_IP}")).await?;
    host_sh(w, H_HOST, &format!("ping -c 3 -W 2 {CE_IP}")).await?;
    // Router-b's own segment is down: the CE's MAC goes to router-a.
    b.wait(&format!(
        "remote mac installed domain={EVPN_DOMAIN} mac={ce_mac} vtep={IP_A}"
    ))
    .await?;

    neigh_suppression(w).await?;

    log("router-b's CE link back: it is the DF again and pins the CE's MAC to its bond");
    let df_b = format!("df elected domain={EVPN_DOMAIN} esi={ESI} port={bond_b} role=df");
    let pinned = format!("remote mac pinned domain={EVPN_DOMAIN} mac={ce_mac} port={bond_b}");
    let (df_base, pin_base) = (b.count(&df_b), b.count(&pinned));
    link_back(w, "router-b", &[NET_CE_B], &["eth1"]).await?;
    b.wait(&carrier_b(true)).await?;
    b.wait_new(&pinned, pin_base, 30).await?;
    b.wait_new(&df_b, df_base, 60).await?;
    let mut fdb = String::new();
    for _ in 0..10 {
        fdb = w
            .dock
            .in_netns(
                NETNS_HELPER_IMAGE,
                "router-b",
                &["bridge", "fdb", "show", "dev", &bond_b],
            )
            .await?;
        if fdb
            .lines()
            .any(|l| l.contains(&ce_mac) && l.contains("static"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !fdb
        .lines()
        .any(|l| l.contains(&ce_mac) && l.contains("static"))
    {
        bail!("router-b's {bond_b} holds no pin for the CE's MAC {ce_mac}: {fdb}");
    }

    log("BUM: one broadcast from the host reaches the CE once, through the DF (router-b) only");
    host_sh(w, CE_HOST, "ip link set eth1 up; sleep 1").await?;
    let (via_non_df, via_df, _) = arp_broadcast(w, None).await?;
    if (via_df, via_non_df) != (1, 0) {
        bail!(
            "the host's broadcast reached the CE {via_df}x through router-b (the DF) and \
             {via_non_df}x through router-a (the non-DF); expected exactly 1 and 0\n\
             captures: {}",
            host_sh(w, CE_HOST, "tail -n +1 /tmp/e0 /tmp/e1").await?
        );
    }

    // The echo local bias removes (RFC 8365 §8.3.1): the CE broadcasts on its
    // link to router-a (non-DF), router-a floods it to router-b, and router-b
    // — the DF — used to send it back out of the segment.
    log("local bias: the CE's broadcast out of its link to router-a is not echoed back through router-b (the DF), and the host gets it once");
    // The link flaps and DF re-elections above rewrote the filters: read them
    // back again, so a missing one fails here by name rather than as a count.
    local_bias_readback(w, "router-a", &bond_a, &vxlan, IP_B, true).await?;
    local_bias_readback(w, "router-b", &bond_b, &vxlan, IP_A, false).await?;
    let (echo_a, echo_b, host) = arp_broadcast(w, Some("eth0")).await?;
    if (echo_a, echo_b, host) != (0, 0, 1) {
        bail!(
            "the CE's own broadcast came back {echo_a}x on its link to router-a and {echo_b}x on \
             its link to router-b, and reached the host {host}x; expected 0, 0 and 1\n\
             captures: {}\ntc:{}",
            host_sh(w, CE_HOST, "tail -n +1 /tmp/e0 /tmp/e1").await?,
            bias_counters(w, [&bond_a, &bond_b], &vxlan).await
        );
    }

    // Local bias changes who delivers a non-DF's own hosts' BUM: with modulo
    // router-a is the DF and router-b, the host's PE, the non-DF. The host's
    // broadcast must now reach the CE once through router-b (a non-DF delivers
    // what it sourced locally) and never through router-a.
    log("modulo instead of hrw: router-a becomes the DF; the host's broadcast still reaches the CE once, through its own PE router-b (the non-DF)");
    let df_alg = |id: Id, rd: &str| {
        let mut f = evpn_pe_flags(id, rd);
        f.extend(bond_flags("bond1", true, "eth1"));
        f.extend(strings(&["--port-aggregate-df-algorithm", "modulo"]));
        f
    };
    let role = |bond: &str, r: &str| {
        format!(
            "df elected domain={EVPN_DOMAIN} esi={ESI} port={bond} role={r} \
             algorithm=modulo ac_df=true pes={IP_A},{IP_B}"
        )
    };
    let (base_a, base_b) = (
        a.count(&role(&bond_a, "df")),
        b.count(&role(&bond_b, "non-df")),
    );
    a.provision_flags(&df_alg(A, EVPN_DP_RD_A)).await?;
    b.provision_flags(&df_alg(B, EVPN_DP_RD_B)).await?;
    a.wait_new(&role(&bond_a, "df"), base_a, 60).await?;
    b.wait_new(&role(&bond_b, "non-df"), base_b, 60).await?;
    local_bias_readback(w, "router-a", &bond_a, &vxlan, IP_B, false).await?;
    local_bias_readback(w, "router-b", &bond_b, &vxlan, IP_A, true).await?;
    let (via_a, via_b, _) = arp_broadcast(w, None).await?;
    if (via_b, via_a) != (1, 0) {
        bail!(
            "the host's broadcast reached the CE {via_b}x through router-b (the non-DF, its own PE) \
             and {via_a}x through router-a (the DF); expected exactly 1 and 0\n\
             captures: {}",
            host_sh(w, CE_HOST, "tail -n +1 /tmp/e0 /tmp/e1").await?
        );
    }

    log("the CE's link to router-a goes down: it is bridged locally on router-b");
    host_sh(w, CE_HOST, "ip link set eth0 down; sleep 1").await?;
    host_sh(w, CE_HOST, &format!("ping -c 3 -W 2 {H_IP}")).await?;
    // The CE now sends through router-b's pin, so router-b advertises it too.
    same_segment_no_move(w, &ce_mac, [(A, IP_B), (B, IP_A)]).await?;

    dataplane_teardown(w).await
}

/// #172: the CE's MAC behind the all-active segment, advertised by both PEs
/// (RFC 7432 §8.4), is not an RFC 7432 §15 MAC move. Each PE holds the
/// other's Type-2 for it on `ESI`, and through 10s of `nos-fdbd` re-push
/// ticks (when the flap used to start) neither withdraws its own nor freezes
/// the MAC — at any point in the phase, since the routers are fresh.
async fn same_segment_no_move(w: &World, mac: &str, pes: [(Id, &str); 2]) -> anyhow::Result<()> {
    log("the CE's MAC on both PEs' segment is not a mac move (#172)");
    for (id, other) in pes {
        w.get(id)?
            .wait(&format!(
                "evpn route learned .*:\\[{ESI}\\]:\\[0\\]:\\[48\\]:\\[{mac}\\].* next_hop={other}$"
            ))
            .await?;
    }
    for (id, _) in pes {
        let r = w.get(id)?;
        r.assert_quiet("local mac mobility lost", 0, 10).await?;
        r.assert_quiet("duplicate mac detected", 0, 0).await?;
    }
    Ok(())
}

/// The CE ARPs for the host once (`arping` from its bond, entering router-a);
/// returns arping's exit code and how many of those requests reached the host
/// across the VXLAN.
async fn ce_arps_host(w: &World) -> anyhow::Result<(i64, usize)> {
    host_sh(
        w,
        H_HOST,
        "rm -f /tmp/h; timeout 8 tcpdump -l -n -Q in -i eth0 arp >/tmp/h 2>&1 & sleep 2",
    )
    .await?;
    let (code, _) = w
        .dock
        .exec(
            CE_HOST,
            &[
                "arping", "-c", "1", "-w", "3", "-I", "bond0", "-s", CE_IP, H_IP,
            ],
        )
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok((code, arp_requests(w, H_HOST, "/tmp/h", H_IP, CE_IP).await?))
}

/// ARP suppression (`neigh-suppress`, RFC 7432 §10): with the CE's link to
/// router-b down, the CE's ARP for the host enters router-a. Once router-b
/// originates the host's MAC+IP (`redistribute from arp`, its binding pinned
/// on router-b's bridge) and router-a holds it as a neighbour, router-a's
/// bridge answers the request itself and nothing crosses the VXLAN; with the
/// setting cleared the request floods to the host again.
async fn neigh_suppression(w: &World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let vxlan = format!("vx{EVPN_VNI}");

    log("neigh-suppress: without it, the CE's ARP for the host crosses the VXLAN");
    let (code, seen) = ce_arps_host(w).await?;
    if code != 0 || seen != 1 {
        bail!("control: arping exited {code}, the host saw {seen} request(s); expected 0 and 1");
    }

    log("neigh-suppress on router-a; router-b originates the host's MAC+IP");
    let mut on_a = evpn_pe_flags(A, EVPN_DP_RD_A);
    on_a.extend(strings(&["--evpn-neigh-suppress", "true"]));
    a.provision_flags(&on_a).await?;
    let mut on_b = evpn_pe_flags(B, EVPN_DP_RD_B);
    on_b.extend(strings(&["--evpn-redistribute-arp-bgp", "r1"]));
    b.provision_flags(&on_b).await?;
    let fdb: serde_json::Value = serde_json::from_str(
        &b.rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
            .await?,
    )?;
    let bridge_b = fdb["bridge"]
        .as_str()
        .context("router-b's show fdb has no bridge name")?
        .to_string();
    let h_mac = host_sh(w, H_HOST, "cat /sys/class/net/eth0/address")
        .await?
        .trim()
        .to_string();
    w.dock
        .in_netns(
            NETNS_HELPER_IMAGE,
            "router-b",
            &[
                "ip",
                "neigh",
                "add",
                H_IP,
                "lladdr",
                &h_mac,
                "dev",
                &bridge_b,
                "nud",
                "permanent",
            ],
        )
        .await?;
    a.wait(&format!(
        "vxlan neigh suppression set vxlan={vxlan} suppress=true"
    ))
    .await?;
    a.wait(&format!(
        "remote neighbour installed domain={EVPN_DOMAIN} mac={h_mac} ip={H_IP} vtep={IP_B}"
    ))
    .await?;
    let link = w
        .dock
        .in_netns(
            NETNS_HELPER_IMAGE,
            "router-a",
            &["bridge", "-d", "link", "show", "dev", &vxlan],
        )
        .await?;
    if !link.contains("neigh_suppress on") {
        bail!("router-a's {vxlan} does not read neigh_suppress on: {link}");
    }
    let fdb: serde_json::Value = serde_json::from_str(
        &a.rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
            .await?,
    )?;
    if fdb["neigh_suppress"] != true {
        bail!("router-a's show fdb does not report neigh_suppress: {fdb}");
    }

    log("router-a's bridge answers the CE's ARP itself: nothing reaches the host");
    let (code, seen) = ce_arps_host(w).await?;
    if code != 0 || seen != 0 {
        bail!("suppressed: arping exited {code}, the host saw {seen} request(s); expected 0 and 0");
    }

    log("neigh-suppress off again: the request floods to the host");
    let base = a.count(&format!(
        "vxlan neigh suppression set vxlan={vxlan} suppress=false"
    ));
    let mut off_a = evpn_pe_flags(A, EVPN_DP_RD_A);
    off_a.extend(strings(&["--evpn-neigh-suppress", "false"]));
    a.provision_flags(&off_a).await?;
    a.wait_new(
        &format!("vxlan neigh suppression set vxlan={vxlan} suppress=false"),
        base,
        30,
    )
    .await?;
    let (code, seen) = ce_arps_host(w).await?;
    if code != 0 || seen != 1 {
        bail!(
            "unsuppressed: arping exited {code}, the host saw {seen} request(s); expected 0 and 1"
        );
    }

    w.dock
        .in_netns(
            NETNS_HELPER_IMAGE,
            "router-b",
            &["ip", "neigh", "del", H_IP, "dev", &bridge_b],
        )
        .await?;
    Ok(())
}

/// Reads the real bridge port `dev` back, in `container`'s netns, until its STP
/// state is `want` (`disabled` / `forwarding`).
async fn bridge_port_state(
    w: &World,
    container: &str,
    dev: &str,
    want: &str,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..30 {
        last = w
            .dock
            .in_netns(
                NETNS_HELPER_IMAGE,
                container,
                &["bridge", "-d", "link", "show", "dev", dev],
            )
            .await?;
        if last.contains(&format!(" state {want}")) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("bridge port {dev} never read state {want}: {last}")
}

/// Pings `ip` from `host` until one reply comes back, for at most `secs`.
async fn ping_until(w: &World, host: &str, ip: &str, secs: u32) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..secs {
        let (code, out) = w
            .dock
            .exec(host, &["ping", "-c", "1", "-W", "1", ip])
            .await?;
        if code == 0 {
            return Ok(());
        }
        last = out;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("{host} never reached {ip} within {secs}s: {}", last.trim())
}

/// `evpn-single-active`: EVPN single-active multi-homing (RFC 7432 §8.5), for
/// real. The same topology as `evpn-dataplane` — two `nos` PEs, a CE dual-homed
/// to both through one Ethernet Segment, a host behind router-b — with
/// `redundancy-mode single-active` on both PEs' bonds and the CE running an
/// ARP-monitored active-backup bond instead of an all-active one.
///
/// Router-a (the lower address) is the DF, so its port forwards and router-b's
/// is *disabled* in the kernel (STP state, read back with `bridge -d link`) —
/// unicast included, not just BUM — while its flooding flags stay on. Router-a
/// sees router-b's per-ES A-D carrying the Single-Active ESI Label. The CE talks
/// to the host through the DF. Router-a then loses its CE link (docker
/// disconnects it, so the bond's only member is gone and it loses carrier): it
/// withdraws the segment, router-b becomes the DF and unblocks, and the CE (its
/// ARP probes unanswered on router-a's dead link) moves over; when the link
/// returns router-a is elected again and router-b is blocked again.
pub async fn evpn_single_active(w: &mut World) -> anyhow::Result<()> {
    let (bond_a, bond_b) = dataplane_setup(w, true, false).await?;
    let (a, b) = (w.a()?, w.b()?);
    let role = |bond: &str, r: &str| {
        format!("df elected domain={EVPN_DOMAIN} esi={ESI} port={bond} role={r}")
    };
    let carrier = |bond: &str, up: bool| {
        format!("segment port carrier changed domain={EVPN_DOMAIN} port={bond} up={up}")
    };

    log("single-active: the non-DF's port is blocked outright, the DF's forwards");
    bridge_port_state(w, "router-b", &bond_b, "disabled").await?;
    bridge_port_state(w, "router-a", &bond_a, "forwarding").await?;
    // It is the state that blocks, not the flood flags.
    bridge_port_flood(w, "router-b", &bond_b, true).await?;
    // Local bias does not apply to a single-active segment (#24): its non-DF
    // drops everything already, so the DF delivers what its peer got locally.
    for (router, bond) in [("router-a", &bond_a), ("router-b", &bond_b)] {
        tc_has(w, router, bond, "egress", "handle 0xe5", false).await?;
    }
    for (r, want_df) in [(a, true), (b, false)] {
        let body = r
            .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
            .await?;
        let table: serde_json::Value = serde_json::from_str(&body)?;
        if table["segments"][0]["single_active"] != true
            || table["segments"][0]["designated_forwarder"] != want_df
        {
            bail!(
                "{}: show fdb does not list a single-active segment (DF={want_df}): {body}",
                r.name()
            );
        }
    }

    log("router-a decodes router-b's per-ES A-D and its Single-Active ESI Label");
    let body = a
        .rest_expect(Method::GET, "/v1/bgp/evpn", None, 200)
        .await?;
    if !body.contains("esi-label:single-active") {
        bail!("router-a does not show router-b's Single-Active ESI Label: {body}");
    }

    log("the CE: an ARP-monitored active-backup bond preferring router-a's link");
    dataplane_ce(
        w,
        &format!("mode active-backup arp_interval 200 arp_ip_target {H_IP} primary eth0"),
    )
    .await?;
    ping_until(w, CE_HOST, H_IP, 30).await?;
    ping_until(w, H_HOST, CE_IP, 30).await?;
    let active = host_sh(w, CE_HOST, "cat /sys/class/net/bond0/bonding/active_slave").await?;
    if active.trim() != "eth0" {
        bail!(
            "the CE is active on {:?}, expected eth0 (router-a, the DF)",
            active.trim()
        );
    }

    log("router-a loses its CE link: router-b takes over and unblocks, the CE follows");
    let df_base = b.count(&role(&bond_b, "df"));
    let up_base = a.count(&carrier(&bond_a, true));
    // The link itself (the bond's only member) goes away, so the bond loses
    // carrier and nothing can bring it back until the link returns.
    link_lost(w, "router-a", &[NET_CE_A]).await;
    a.wait(&carrier(&bond_a, false)).await?;
    // Longer than nos-interfaced's 10s reconcile tick, which re-upped a bond
    // taken down with `ip link set` (#169).
    a.assert_quiet(&carrier(&bond_a, true), up_base, 12).await?;
    b.wait_new(&role(&bond_b, "df"), df_base, 60).await?;
    bridge_port_state(w, "router-b", &bond_b, "forwarding").await?;
    ping_until(w, CE_HOST, H_IP, 30).await?;
    ping_until(w, H_HOST, CE_IP, 30).await?;

    log("CE link back: router-a is elected again and router-b is blocked again");
    let a_df = a.count(&role(&bond_a, "df"));
    let b_non_df = b.count(&role(&bond_b, "non-df"));
    link_back(w, "router-a", &[NET_CE_A], &["eth1"]).await?;
    a.wait_new(&carrier(&bond_a, true), up_base, 30).await?;
    a.wait_new(&role(&bond_a, "df"), a_df, 60).await?;
    b.wait_new(&role(&bond_b, "non-df"), b_non_df, 60).await?;
    bridge_port_state(w, "router-b", &bond_b, "disabled").await?;
    bridge_port_state(w, "router-a", &bond_a, "forwarding").await?;
    ping_until(w, CE_HOST, H_IP, 30).await?;

    dataplane_teardown(w).await
}

/// `evpn-l3`: one PE's flags — the underlay session to the other PE with
/// `address-family l2vpn-evpn` in `rt1`, and its IP-VRF `L3_TABLE` with the
/// L3 VNI (VTEP on eth0) and its host's subnet on eth1.
fn l3_pe_flags(id: Id, rd: &str, gw: &str) -> Vec<String> {
    let mut f = id.base_flags();
    f.extend(strings(&["--peer-group", "pg-evpn", "--evpn"]));
    f.extend(strings(&[
        "--l3vni-table",
        L3_TABLE,
        "--l3vni",
        &L3_VNI.to_string(),
        "--l3vni-rd",
        rd,
        "--l3vni-rt",
        L3_RT,
        "--l3vni-vtep-source-interface",
        "eth0",
        "--l3vni-interface",
        "eth1",
        "--l3vni-address",
        &format!("{gw}/24"),
    ]));
    f
}

/// Whether `r`'s `L3_TABLE` lists `prefix` as an `Evpn` route, over REST.
async fn tenant_has_evpn(r: &Router, prefix: &str) -> anyhow::Result<bool> {
    table_has_evpn(r, L3_TABLE, L3_VNI, prefix).await
}

/// Whether `r`'s `table` lists `prefix` as an `Evpn` route of `vni`.
async fn table_has_evpn(r: &Router, table: &str, vni: u32, prefix: &str) -> anyhow::Result<bool> {
    let routes = r.routes_walk(table, Some(1000)).await?;
    Ok(routes.iter().any(|p| {
        p["prefix"] == prefix
            && p["candidates"].as_array().into_iter().flatten().any(|c| {
                c["source"] == "Evpn" && c["evpn"]["vni"] == vni && c["evpn"]["router_mac"] != ""
            })
    }))
}

/// `evpn-l3`'s symmetric IRB flags: `IRB_DOMAIN` with its SVI (`IRB_GW`, the
/// same anycast gateway on both PEs) in `L3_TABLE`, `redistribute from mac`
/// and `arp` into r1.
fn irb_flags(rd: &str) -> Vec<String> {
    strings(&[
        "--broadcast-domain",
        IRB_DOMAIN,
        "--evpn-vni",
        &IRB_VNI.to_string(),
        "--evpn-rd",
        rd,
        "--evpn-rt-import",
        IRB_RT,
        "--evpn-rt-export",
        IRB_RT,
        "--evpn-vtep-source-interface",
        "eth0",
        "--evpn-redistribute-bgp",
        "r1",
        "--evpn-redistribute-arp-bgp",
        "r1",
        "--broadcast-domain-svi-address",
        &format!("{IRB_GW}/24"),
        "--broadcast-domain-svi-table",
        L3_TABLE,
    ])
}

/// `evpn-l3`'s RFC 9135 symmetric IRB stage. `IRB_DOMAIN` is stretched over
/// both PEs, its SVI in the IP-VRF; its only host sits behind router-b. So
/// router-a holds the subnet as connected and, without a host route, would
/// ARP and bridge over the L2 VNI (asymmetric): the host's MAC+IP carrying the
/// L3 VNI as Label2, router-a's /32 for it and the echo request arriving on
/// router-b's L3 VNI device (not the L2 one) are what prove symmetric.
async fn symmetric_irb(w: &World, flags_a: &[String], flags_b: &[String]) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    log("symmetric irb: a stretched domain whose SVI is in the IP-VRF, a host behind router-b");
    if !w.dock.network_exists(NET_IRB).await {
        w.dock.network_create(NET_IRB, &[], false).await?;
    }
    w.dock.network_connect(NET_IRB, "router-b").await;
    // Docker's own address on the new link would sit beside the bridge.
    netns(w, "router-b", &["ip", "addr", "flush", "dev", "eth2"]).await?;
    w.dock.start_host(IRB_HOST, HOST_IMAGE, NET_IRB).await?;
    host_sh(
        w,
        IRB_HOST,
        &format!(
            "set -e; ip addr flush dev eth0; ip addr add {IRB_HOST_IP}/24 dev eth0; \
             ip route add {L3_SUBNET_A} via {IRB_GW}"
        ),
    )
    .await?;
    host_sh(
        w,
        CE_HOST,
        &format!("ip route add {IRB_HOST_IP}/32 via {L3_GW_A}"),
    )
    .await?;

    let with = |base: &[String], extra: Vec<String>| {
        let mut f = base.to_vec();
        f.extend(extra);
        f
    };
    a.provision_flags(&with(flags_a, irb_flags(IRB_RD_A)))
        .await?;
    let mut b_flags = irb_flags(IRB_RD_B);
    b_flags.extend(strings(&[
        "--link-interface",
        "eth2",
        "--switching-profile",
        "sp-irb",
        "--switching-profile-member",
        &format!("{IRB_DOMAIN}:untagged"),
    ]));
    b.provision_flags(&with(flags_b, b_flags)).await?;

    log("the domain on another bgp instance than the IP-VRF's l3 vni is refused at commit");
    let refused = a
        .edit(|c| {
            let mut other = c.bgp_instances[0].clone();
            other.name = "r-irb".to_string();
            other.router_id = "192.0.2.99".parse()?;
            other.peer_groups.clear();
            other.peers.clear();
            other.routing_table = None;
            c.bgp_instances.push(other);
            let d = c
                .broadcast_domains
                .iter_mut()
                .find(|d| d.name == IRB_DOMAIN)
                .context("no irb domain")?;
            d.mac_redistribute = Some("r-irb".to_string());
            d.arp_redistribute = Some("r-irb".to_string());
            Ok(())
        })
        .await;
    match refused {
        Err(e) if format!("{e:#}").contains("symmetric irb") => {}
        other => bail!("expected the symmetric irb instance mismatch refused: {other:?}"),
    }

    log("the host's ARP binding on router-b becomes a MAC+IP with the L3 VNI as Label2");
    ping_until(w, IRB_HOST, IRB_GW, 30).await?;
    a.wait(&format!(
        "evpn route learned peer={IP_B} route_type=2 .*\\[{IRB_HOST_IP}\\]:\\[{IRB_VNI}\\]:\\[{L3_VNI}\\]"
    ))
    .await?;
    let evpn = a
        .rest_expect(Method::GET, "/v1/bgp/evpn", None, 200)
        .await?;
    if !evpn.contains(&format!("[{IRB_HOST_IP}]:[{IRB_VNI}]:[{L3_VNI}]")) {
        bail!("router-a's show bgp evpn lacks the host's two labels: {evpn}");
    }
    let host_route = format!("{IRB_HOST_IP}/32");
    a.wait(&format!(
        "added route prefix={host_route} gateway={IP_B} next_hops=1 .*source=Some(Evpn)"
    ))
    .await?;
    if !tenant_has_evpn(a, &host_route).await? {
        bail!("router-a's {L3_TABLE} does not list {host_route} as an evpn route");
    }

    log("routed traffic to the host crosses the L3 VNI, not the L2 one");
    let vx = format!("vx{L3_VNI}");
    let filter = format!("icmp and dst host {IRB_HOST_IP}");
    let tcpdump = ["timeout", "30", "tcpdump", "-c", "1", "-ni", &vx, &filter];
    let (captured, pinged) =
        tokio::join!(w.dock.in_netns(HOST_IMAGE, "router-b", &tcpdump), async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            ping_until(w, CE_HOST, IRB_HOST_IP, 25).await
        });
    pinged?;
    let captured =
        captured.with_context(|| format!("no echo request to {IRB_HOST_IP} on router-b's {vx}"))?;
    log(format!("router-b's {vx}: {}", captured.trim()));

    log("router-b stops redistributing arp: router-a removes the host route");
    let removed = format!("removed route prefix={host_route}");
    let base = a.count(&removed);
    b.edit(|c| {
        if let Some(d) = c
            .broadcast_domains
            .iter_mut()
            .find(|d| d.name == IRB_DOMAIN)
        {
            d.arp_redistribute = None;
        }
        Ok(())
    })
    .await?;
    a.wait_new(&removed, base, 30).await?;

    for r in [a, b] {
        r.edit(|c| {
            c.broadcast_domains.retain(|d| d.name != IRB_DOMAIN);
            c.switching_profiles.retain(|p| p.name != "sp-irb");
            c.interfaces.retain(|i| i.name != "eth2");
            Ok(())
        })
        .await?;
    }
    host_sh(w, CE_HOST, &format!("ip route del {IRB_HOST_IP}/32")).await?;
    w.dock.container_remove(IRB_HOST).await;
    w.dock.network_disconnect(NET_IRB, "router-b").await;
    w.dock.network_remove(NET_IRB).await;
    Ok(())
}

/// `evpn-l3-chunked`'s IP-VRFs: `(table, L3 VNI)`. The first is `L3_TABLE`
/// (VNI `L3_VNI`, its gateway on eth1); the others get a `loopback-<table>`
/// for their statics' gateway. A static routing instance is one list of at
/// most `CHUNKED_PER_TABLE` routes, and a table references one instance.
const CHUNKED_TABLES: [(&str, u32); 3] = [(L3_TABLE, L3_VNI), ("tenant2", 5001), ("tenant3", 5002)];
const CHUNKED_PER_TABLE: u32 = 25_000;
/// Extra export RTs on router-b's `L3_TABLE` (`65000:9000` + i, imported by
/// nothing): each adds ~8 encoded bytes to every route it originates, so its
/// 25 000 routes weigh ~7.5 MiB, past the 4 MiB `EVPN_PUSH_BYTES`, and its
/// `nos-ribd`'s `RedistributeEvpnPrefixes` `Full` is chunked (#725). A table
/// cannot simply hold more statics: one static routing instance is one list,
/// and a list must fit one 2 MiB REST `PUT`.
const CHUNKED_EXTRA_RTS: u32 = 32;

/// Lines of `name`'s container stdout (ANSI colors stripped) matching the BRE
/// `pattern`: the lossless counterpart of `Router::count`, for a pattern that
/// is logged just before a flood the REST log follower cannot keep up with.
async fn stdout_count(w: &World, name: &str, pattern: &str) -> anyhow::Result<usize> {
    let ansi = regex::Regex::new("\x1b\\[[0-9;]*m")?;
    let re = bre(pattern);
    let out = w.dock.logs(name).await?;
    Ok(ansi
        .replace_all(&out, "")
        .lines()
        .filter(|l| re.is_match(l))
        .count())
}

/// The i-th `evpn-l3-chunked` prefix of table `t`: `100.64.0.0 + t * 25000 + i`.
fn chunked_prefix(t: usize, i: u32) -> nos_proto::IpNet {
    let n = u32::try_from(t).unwrap_or(0) * CHUNKED_PER_TABLE + i;
    let addr = std::net::Ipv4Addr::from(u32::from(std::net::Ipv4Addr::new(100, 64, 0, 0)) + n);
    nos_proto::IpNet::new(addr.into(), 32).expect("a /32")
}

/// Polls `GET /v1/bgp/summary` until some peer's accepted EVPN prefixes
/// (`accepted_prefixes[2]`) reach `want`.
async fn wait_evpn_accepted(r: &Router, want: usize, secs: u64) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let body = r
            .rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?;
        let v: serde_json::Value = serde_json::from_str(&body)?;
        let mut best = 0;
        let mut stack = vec![&v];
        while let Some(n) = stack.pop() {
            match n {
                serde_json::Value::Object(m) => {
                    if let Some(c) = m.get("accepted_prefixes").and_then(|a| a.get(2)) {
                        best = best.max(c.as_u64().unwrap_or(0));
                    }
                    stack.extend(m.values());
                }
                serde_json::Value::Array(a) => stack.extend(a),
                _ => {}
            }
        }
        if usize::try_from(best)? >= want {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("{}: only {best} of {want} evpn prefixes accepted", r.name());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// One PE's flags for IP-VRF `table`/`vni` with no host interface.
fn chunked_table_flags(id: Id, table: &str, vni: u32) -> Vec<String> {
    let asn = if id.name == A.name { 65001 } else { 65002 };
    let mut f = id.base_flags();
    f.extend(strings(&["--peer-group", "pg-evpn", "--evpn"]));
    f.extend(strings(&[
        "--l3vni-table",
        table,
        "--l3vni",
        &vni.to_string(),
        "--l3vni-rd",
        &format!("{asn}:{vni}"),
        "--l3vni-rt",
        &format!("65000:{vni}"),
        "--l3vni-vtep-source-interface",
        "eth0",
    ]));
    f
}

/// `evpn-l3-chunked` (#721): a Type-5 `Full` larger
/// than `EVPN_PUSH_BYTES` (4 MiB) crosses `nos-bgpd` -> `nos-ribd` as
/// `FullPart`s and is applied once. Router-b originates 75 000 static /32s
/// (~60 B each as an `EvpnRoute`, a little over 4 MiB) spread over three
/// IP-VRFs, 25 000 per static routing instance, provisioned through
/// `Router::edit`'s batched subsection PUTs in one commit; a session clear
/// then overflows router-b's outbox for sure, which must coalesce, not
/// cease (#764). Router-a's bgpd learns them all
/// while router-a has no IP-VRF; then router-a's three tables are created and
/// each new `nos-ribd` gets one chunked `Full` from bgpd, which it must
/// assemble and apply once. There is no budget knob (the watchdog clears its
/// children's environment), so only real volume works. Last, the origination
/// direction (#725): router-b's tenant routes carry `CHUNKED_EXTRA_RTS` more
/// RTs, so a restart of its `nos-ribd` sends a chunked
/// `RedistributeEvpnPrefixes` `Full`, which router-b's bgpd assembles with
/// nothing withdrawn on router-a.
///
/// Why the order: the same routes arriving as individual `Add`s are applied
/// one by one, each rebuilding and reconciling the whole table
/// (`apply_evpn_route_update`), which is quadratic and takes hours; that
/// path is out of scope here (own issue) and this phase must not depend on it.
pub async fn evpn_l3_chunked(w: &mut World) -> anyhow::Result<()> {
    let base = |id: Id| {
        let mut f = id.base_flags();
        f.extend(strings(&["--peer-group", "pg-evpn", "--evpn"]));
        f
    };
    w.start(A, Some(base(A)), &[]).await?;
    w.start(B, Some(base(B)), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.established().await?;
    b.established().await?;

    // The tenant subnet on eth1 makes the first table's gateway on-link.
    for (net, subnet, router, gw) in [
        (NET_L3_A, L3_SUBNET_A, "router-a", L3_GW_A),
        (NET_L3_B, L3_SUBNET_B, "router-b", L3_GW_B),
    ] {
        if !w.dock.network_exists(net).await {
            w.dock.network_create(net, &[subnet], false).await?;
        }
        w.dock.network_connect_ip(net, router, gw).await?;
    }

    let total = CHUNKED_PER_TABLE as usize * CHUNKED_TABLES.len();
    log(format!(
        "router-b originates {total} static /32s in {} IP-VRFs; router-a has none yet",
        CHUNKED_TABLES.len()
    ));
    b.provision_flags(&l3_pe_flags(B, L3_RD_B, L3_GW_B)).await?;
    for (table, vni) in &CHUNKED_TABLES[1..] {
        b.provision_flags(&chunked_table_flags(B, table, *vni))
            .await?;
    }
    let started = std::time::Instant::now();
    let closed = b.count("diff stream closed");
    // One commit, one burst (#764): 75 000 Type-5 updates, which may or may
    // not overflow router-b's 8 192-entry per-peer outbox (the FSM drains it
    // concurrently), and must never reset the session.
    let lasts: Vec<_> = (0..CHUNKED_TABLES.len())
        .map(|t| chunked_prefix(t, CHUNKED_PER_TABLE - 1))
        .collect();
    let flaps = "bgp session established\\|sent cease notification\\|received notification";
    let (flaps_a, flaps_b) = (a.count(flaps), b.count(flaps));
    b.edit(|config| {
        let tenant = config
            .routing_tables
            .iter_mut()
            .find(|t| t.name == L3_TABLE)
            .context("router-b has no tenant table")?;
        tenant
            .evpn
            .route_targets_export
            .extend((0..CHUNKED_EXTRA_RTS).map(|i| format!("65000:{}", 9000 + i)));
        for (t, (table, _)) in CHUNKED_TABLES.iter().enumerate() {
            let instance = format!("sri-chunked{t}");
            let gateway: std::net::IpAddr = if t == 0 {
                L3_HOST_IP_B.parse()?
            } else {
                format!("198.19.{t}.2").parse()?
            };
            let mut ops = Vec::new();
            if t > 0 {
                // `loopback-<table>` is enslaved to the table's VRF by name.
                let lo = format!("loopback-{table}");
                ops.push(ConfigOp::Interface(InterfaceOp::Ensure {
                    name: lo.clone(),
                }));
                ops.push(ConfigOp::Interface(InterfaceOp::AddAddress {
                    name: lo,
                    address: format!("198.19.{t}.1/24").parse()?,
                    label: None,
                }));
            }
            ops.push(ConfigOp::StaticRoutingInstance(
                StaticRoutingInstanceOp::Ensure {
                    name: instance.clone(),
                },
            ));
            ops.push(ConfigOp::RoutingTable(
                RoutingTableOp::SetStaticRoutingInstance {
                    name: (*table).to_string(),
                    static_routing_instance: instance.clone(),
                },
            ));
            ops.extend((0..CHUNKED_PER_TABLE).map(|i| {
                ConfigOp::StaticRoute(StaticRouteOp::Set {
                    instance: instance.clone(),
                    subnet: chunked_prefix(t, i),
                    gateway,
                })
            }));
            for op in ops {
                op.apply(config).map_err(|e| anyhow::anyhow!("{e}"))?;
            }
        }
        Ok(())
    })
    .await
    .context("committing the statics (did nos-configd die?)")?;
    // A configd that dies on a commit shows as every daemon's diff stream
    // closing: fail at once, not after an hour.
    if b.count("diff stream closed") != closed {
        bail!("router-b: nos-configd died committing the statics");
    }
    log(format!(
        "router-b: {total} statics committed in one burst after {}s",
        started.elapsed().as_secs()
    ));
    // Counted over REST: 75 000 `evpn route learned` lines overrun the
    // harness's log follower.
    wait_evpn_accepted(a, total, 600).await?;
    // Per-daemon RSS and the cgroup after the burst (`SAMPLE burst` lines).
    let _ = crate::logd_mem::sample(&*w, b, "burst").await;
    log(format!(
        "router-a's bgpd holds all {total} Type-5 routes after {}s",
        started.elapsed().as_secs()
    ));
    a.assert_quiet(flaps, flaps_a, 1).await?;
    b.assert_quiet(flaps, flaps_b, 1).await?;

    // The deterministic overflow: on re-establishment `announce_evpn_to` sends
    // all 75 003 routes from the FSM task itself, which cannot drain the queue
    // meanwhile, so the outbox must coalesce; before #764 it ceased the
    // session, and the next establishment overflowed again, forever.
    log("router-b clears its session: the initial EVPN dump overflows the outbox");
    let (coalescing, drained) = (
        format!("bgp: outbox full, coalescing peer={IP_A}"),
        format!("bgp: outbox backlog drained peer={IP_A}"),
    );
    let established = "bgp session established";
    let (coalescing_base, drained_base, est_base) = (
        b.count(&coalescing),
        b.count(&drained),
        b.count(established),
    );
    b.rest_expect(
        Method::POST,
        &format!("/v1/bgp/r1/peer/{IP_A}/clear"),
        None,
        200,
    )
    .await?;
    b.wait_new(established, est_base, 60).await?;
    b.wait_new(&coalescing, coalescing_base, 120).await?;
    b.wait_new(&drained, drained_base, 300).await?;
    wait_evpn_accepted(a, total, 600).await?;
    let (flaps_a, flaps_b) = (a.count(flaps), b.count(flaps));
    a.assert_quiet(flaps, flaps_a, 5).await?;
    b.assert_quiet(flaps, flaps_b, 1).await?;

    log("router-a gets its three IP-VRFs: each nos-ribd must assemble one chunked Full");
    let assembled = |t: &str| {
        format!("assembled chunked evpn route snapshot table={t} routes=7[0-9][0-9][0-9][0-9] parts=[2-9]")
    };
    let mut asm_base = Vec::new();
    for (t, _) in CHUNKED_TABLES {
        asm_base.push(stdout_count(w, a.name(), &assembled(t)).await?);
    }
    let removed = a.count("removed route");
    let applied = std::time::Instant::now();
    a.provision_flags(&l3_pe_flags(A, L3_RD_A, L3_GW_A)).await?;
    for (table, vni) in &CHUNKED_TABLES[1..] {
        a.provision_flags(&chunked_table_flags(A, table, *vni))
            .await?;
    }
    // Counted on the container's stdout, not the REST log follower: the
    // 75 000 `added route` lines that follow overrun logd's 1024-entry tail
    // channel and the follower silently drops lines, `assembled` included
    // (#838: tenant3's line was lost on tokio 1.53.1 and 1.53.2 alike).
    for ((t, _), base) in CHUNKED_TABLES.iter().zip(&asm_base) {
        let deadline = std::time::Instant::now() + Duration::from_mins(15);
        while stdout_count(w, a.name(), &assembled(t)).await? <= *base {
            if std::time::Instant::now() > deadline {
                bail!("router-a: no 'assembled' line for {t} within 900s");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        log(format!("router-a: assembled chunked snapshot for {t}"));
    }
    // The routes are in each table (REST, not the log: 75 000 `added route`
    // lines overrun the harness's log follower, which then drops lines).
    for ((table, vni), last) in CHUNKED_TABLES.iter().zip(&lasts) {
        let mut found = false;
        for _ in 0..60 {
            if table_has_evpn(a, table, *vni, &last.to_string()).await? {
                found = true;
                break;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        if !found {
            bail!("router-a: {table} never listed {last} as an evpn route");
        }
    }
    log(format!(
        "router-a installed all tables {}s after creating them",
        applied.elapsed().as_secs()
    ));
    a.assert_quiet("removed route", removed, 3).await?;
    if !tenant_has_evpn(a, &lasts[0].to_string()).await? {
        bail!(
            "router-a: {L3_TABLE} lacks {} after the chunked Full",
            lasts[0]
        );
    }

    // The origination direction (#725): router-b's tenant `nos-ribd` pushed
    // its statics as `Add`s (it was connected before the commit); a restart
    // makes it send them as one `RedistributeEvpnPrefixes` `Full`, ~7.5 MiB
    // with the extra RTs, so chunked, and router-b's bgpd must assemble it
    // and apply it once: the same set, so router-a withdraws nothing.
    log("router-b restarts its tenant nos-ribd: its Type-5 Full reaches bgpd chunked");
    let originated = format!(
        "assembled chunked evpn route snapshot source=table:{L3_TABLE} routes=250[0-9][0-9] parts=[2-9]"
    );
    let (orig_base, removed) = (b.count(&originated), a.count("removed route"));
    let withdrawn = a.count("evpn route withdrawn");
    w.dock
        .kill_process_matching("router-b", "nos-ribd", &format!("--table {L3_TABLE} "))
        .await?;
    b.wait_new(&originated, orig_base, 300).await?;
    let _ = crate::logd_mem::sample(&*w, b, "origination").await;
    a.assert_quiet("removed route", removed, 10).await?;
    a.assert_quiet("evpn route withdrawn", withdrawn, 1).await?;
    wait_evpn_accepted(a, total, 60).await?;
    if !tenant_has_evpn(a, &lasts[0].to_string()).await? {
        bail!(
            "router-a: {L3_TABLE} lost {} after router-b's chunked origination",
            lasts[0]
        );
    }
    Ok(())
}

/// GoBGP's VPNv4 destination count (`gobgp global rib summary -a vpnv4`).
async fn gobgp_vpnv4_count(w: &World) -> anyhow::Result<usize> {
    let out = gobgp(w, &["global", "rib", "summary", "-a", "vpnv4"]).await?;
    out.split("Destination:")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .with_context(|| format!("no destination count in: {out}"))
}

/// `vpn-export-chunked` (#791): a VRF export `Full` heavier than
/// `EVPN_PUSH_BYTES` (4 MiB) crosses `nos-ribd` -> `nos-bgpd` as
/// `FullPart`s and is applied once. Router-a's `VPN_TABLE` gets
/// `CHUNKED_PER_TABLE` static /32s and `CHUNKED_EXTRA_RTS` more export RTs
/// (~320 encoded bytes per `VpnPrefix`, ~8 MiB), exported to GoBGP over
/// VPNv4. Killing only that table's `nos-ribd` makes the new one send the
/// whole set as one `Full`, which bgpd must assemble; the set is unchanged,
/// so GoBGP loses nothing. No budget knob reaches a supervised `nos-ribd`
/// (the watchdog clears its children's environment): only real volume works.
pub async fn vpn_export_chunked(w: &mut World) -> anyhow::Result<()> {
    gobgp_speaker(w, vpn_flags("65000:1"), &["l3vpn-ipv4-unicast"], &[]).await?;
    mpls_ready(w, &["router-a"]).await?;
    let a = w.a()?;
    a.wait(&format!(
        "sent initial vpn snapshot to nos-bgpd table={VPN_TABLE} bgp_instance=r1"
    ))
    .await?;
    let n = CHUNKED_PER_TABLE as usize;
    log(format!(
        "router-a exports {n} static /32s from {VPN_TABLE} with {} export RTs",
        CHUNKED_EXTRA_RTS + 1
    ));
    let started = std::time::Instant::now();
    a.edit(|config| {
        let red = config
            .routing_tables
            .iter_mut()
            .find(|t| t.name == VPN_TABLE)
            .context("router-a has no vpn table")?;
        red.vpn
            .route_targets_export
            .extend((0..CHUNKED_EXTRA_RTS).map(|i| format!("65000:{}", 9000 + i)));
        let instance = "sri-vpn-chunked".to_string();
        // `loopback-<table>` is enslaved to the table's VRF by name; its
        // subnet makes the statics' gateway on-link.
        let lo = format!("loopback-{VPN_TABLE}");
        let mut ops = vec![
            ConfigOp::Interface(InterfaceOp::Ensure { name: lo.clone() }),
            ConfigOp::Interface(InterfaceOp::AddAddress {
                name: lo,
                address: "198.19.0.1/24".parse()?,
                label: None,
            }),
            ConfigOp::StaticRoutingInstance(StaticRoutingInstanceOp::Ensure {
                name: instance.clone(),
            }),
            ConfigOp::RoutingTable(RoutingTableOp::SetStaticRoutingInstance {
                name: VPN_TABLE.to_string(),
                static_routing_instance: instance.clone(),
            }),
        ];
        let gateway: std::net::IpAddr = "198.19.0.2".parse()?;
        ops.extend((0..CHUNKED_PER_TABLE).map(|i| {
            ConfigOp::StaticRoute(StaticRouteOp::Set {
                instance: instance.clone(),
                subnet: chunked_prefix(0, i),
                gateway,
            })
        }));
        for op in ops {
            op.apply(config).map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        Ok(())
    })
    .await?;
    // Counted on GoBGP: 25 000 `vpn route advertised` lines overrun the
    // harness's log follower.
    let mut held = 0;
    for _ in 0..120 {
        held = gobgp_vpnv4_count(w).await?;
        if held >= n {
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    if held < n {
        bail!("GoBGP holds only {held} of {n} VPNv4 routes");
    }
    log(format!(
        "GoBGP holds {held} VPNv4 routes after {}s",
        started.elapsed().as_secs()
    ));
    let _ = crate::logd_mem::sample(&*w, a, "vpn-export").await;

    log(format!(
        "killing {VPN_TABLE}'s nos-ribd: its export Full reaches bgpd chunked"
    ));
    let assembled = format!(
        "assembled chunked vpn export snapshot table={VPN_TABLE} routes=250[0-9][0-9] parts=[2-9] instance=r1"
    );
    let withdrawn = format!(
        "vpn route advertisement withdrawn peer={IP_G} family=vpnv4 rd={VPN_RD_A} prefix=100\\."
    );
    let (asm_base, wd_base) = (a.count(&assembled), a.count(&withdrawn));
    w.dock
        .kill_process_matching("router-a", "nos-ribd", &format!("--table {VPN_TABLE} "))
        .await?;
    a.wait_new(&assembled, asm_base, 300).await?;
    let _ = crate::logd_mem::sample(&*w, a, "vpn-export-chunked").await;
    a.assert_quiet(&withdrawn, wd_base, 10).await?;
    let after = gobgp_vpnv4_count(w).await?;
    if after != held {
        bail!("GoBGP went from {held} to {after} VPNv4 routes across the chunked Full");
    }
    w.dock.container_remove("router-g").await;
    Ok(())
}

/// `evpn-l3`: RFC 9136 Type-5 routes over an RFC 9135 §4.4.1 L3 VNI, for real.
/// Two `nos` PEs peer `l2vpn-evpn` over the underlay (`rt1`); each has an
/// IP-VRF (`L3_TABLE`) with `l3-vni`, whose `nos-ribd` builds `vx<vni>` on a
/// bridge in the VRF, and a host on its own docker network behind it, in its
/// own subnet. Each originates its connected subnet as a Type-5 carrying its
/// Router's MAC; the other installs it `via <VTEP> dev brv<vni> onlink`, with
/// the neighbour and FDB entry behind it, and the hosts ping each other
/// across the VXLAN. Removing router-b's `evpn` withdraws its route and
/// deletes its devices.
pub async fn evpn_l3(w: &mut World) -> anyhow::Result<()> {
    let base = |id: Id| {
        let mut f = id.base_flags();
        f.extend(strings(&["--peer-group", "pg-evpn", "--evpn"]));
        f
    };
    w.start(A, Some(base(A)), &[]).await?;
    w.start(B, Some(base(B)), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.established().await?;
    b.established().await?;

    // VXLAN in a VRF needs `udp_l3mdev_accept` (as `evpn-dataplane`); routing
    // between the host's interface and the L3 bridge needs forwarding. Both
    // operator prerequisites nothing in nos sets.
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    for router in ["router-a", "router-b"] {
        w.dock
            .in_netns(
                NETNS_HELPER_IMAGE,
                router,
                &[
                    "sh",
                    "-c",
                    "echo 1 > /proc/sys/net/ipv4/udp_l3mdev_accept; \
                     echo 1 > /proc/sys/net/ipv4/ip_forward",
                ],
            )
            .await?;
    }

    log("a host behind each PE, each on its own network and subnet");
    w.dock
        .ensure_image(
            HOST_IMAGE,
            "FROM debian:bookworm-slim\n\
             RUN apt-get update && apt-get install -y --no-install-recommends \\\n \
             iproute2 iputils-ping iputils-arping tcpdump && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    for (net, subnet, router, gw, host, ip, other) in [
        (
            NET_L3_A,
            L3_SUBNET_A,
            "router-a",
            L3_GW_A,
            CE_HOST,
            L3_HOST_IP_A,
            L3_SUBNET_B,
        ),
        (
            NET_L3_B,
            L3_SUBNET_B,
            "router-b",
            L3_GW_B,
            H_HOST,
            L3_HOST_IP_B,
            L3_SUBNET_A,
        ),
    ] {
        if !w.dock.network_exists(net).await {
            w.dock.network_create(net, &[subnet], false).await?;
        }
        w.dock.network_connect_ip(net, router, gw).await?;
        w.dock.start_host(host, HOST_IMAGE, net).await?;
        host_sh(
            w,
            host,
            &format!(
                "set -e; ip addr flush dev eth0; ip addr add {ip}/24 dev eth0; \
                 ip route add {other} via {gw}"
            ),
        )
        .await?;
    }

    log("each PE's IP-VRF gets the L3 VNI");
    a.provision_flags(&l3_pe_flags(A, L3_RD_A, L3_GW_A)).await?;
    b.provision_flags(&l3_pe_flags(B, L3_RD_B, L3_GW_B)).await?;
    let vxlan = format!("vx{L3_VNI}");
    for (r, vtep) in [(a, IP_A), (b, IP_B)] {
        r.wait(&format!(
            "created l3 vni vxlan device vxlan={vxlan} vni={L3_VNI} vtep={vtep} underlay=eth0"
        ))
        .await?;
    }

    log("each learns the other's subnet as a Type-5 with a Router's MAC, and installs it");
    for (r, peer, prefix) in [(a, IP_B, L3_SUBNET_B), (b, IP_A, L3_SUBNET_A)] {
        r.wait(&format!(
            "evpn route learned peer={peer} route_type=5 .*{prefix}"
        ))
        .await?;
        r.wait(&format!(
            "evpn remote vtep installed vni={L3_VNI} vtep={peer} rmac="
        ))
        .await?;
        r.wait(&format!(
            "added route prefix={prefix} gateway={peer} next_hops=1 .*source=Some(Evpn)"
        ))
        .await?;
        let evpn = r
            .rest_expect(Method::GET, "/v1/bgp/evpn", None, 200)
            .await?;
        if !evpn.contains("rmac:") || !evpn.contains("\"route_type\":5") {
            bail!(
                "{}: show bgp evpn lacks the Type-5 / rmac: {evpn}",
                r.name()
            );
        }
        if !tenant_has_evpn(r, prefix).await? {
            bail!(
                "{}: {L3_TABLE} does not list {prefix} as an evpn route",
                r.name()
            );
        }
    }

    log("the hosts ping each other across the L3 VNI");
    ping_until(w, CE_HOST, L3_HOST_IP_B, 30).await?;
    ping_until(w, H_HOST, L3_HOST_IP_A, 30).await?;

    symmetric_irb(
        w,
        &l3_pe_flags(A, L3_RD_A, L3_GW_A),
        &l3_pe_flags(B, L3_RD_B, L3_GW_B),
    )
    .await?;

    l3_gobgp_burst(w).await?;

    log("router-b's evpn removed: its Type-5 is withdrawn and its devices deleted");
    let removed = format!("removed route prefix={L3_SUBNET_B} gateway={IP_B}");
    let base_removed = a.count(&removed);
    let clear: Vec<String> = {
        // Keep the table and its subnet; drop the L3 VNI.
        let mut out = base(B);
        out.extend(strings(&["--l3vni-table", L3_TABLE, "--l3vni-clear"]));
        out
    };
    b.provision_flags(&clear).await?;
    b.wait(&format!("deleted l3 vni devices vni={L3_VNI}"))
        .await?;
    a.wait_new(&removed, base_removed, 30).await?;
    a.wait(&format!(
        "evpn remote vtep removed vni={L3_VNI} vtep={IP_B}"
    ))
    .await?;
    if tenant_has_evpn(a, L3_SUBNET_B).await? {
        bail!("router-a still lists {L3_SUBNET_B} after router-b's withdrawal");
    }

    for host in [CE_HOST, H_HOST] {
        w.dock.container_remove(host).await;
    }
    for (net, router) in [(NET_L3_A, "router-a"), (NET_L3_B, "router-b")] {
        w.dock.network_disconnect(net, router).await;
        w.dock.network_remove(net).await;
    }
    Ok(())
}

/// `evpn-l3`'s burst stage (#763): GoBGP announces `L3_BURST_ROUTES` Type-5
/// host routes (several `gobgp` CLI processes in parallel, so far faster than
/// the 12 routes/s `nos-ribd` used to manage) into router-a's IP-VRF. They must
/// all be installed in `L3_BURST_SECS`, with none of the kernel errors a stale
/// whole-table dump-diff racing the previous push used to give, and one
/// `del all` must remove them again.
async fn l3_gobgp_burst(w: &World) -> anyhow::Result<()> {
    log("burst: router-a also peers GoBGP, which announces many Type-5 routes at once");
    let a = w.a()?;
    a.provision_flags(&strings(&[
        "--address",
        &format!("{IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--peer-group",
        "pg-gobgp",
        "--remote-as",
        &ASN_G.to_string(),
        "--peer",
        IP_G,
        "--evpn",
    ]))
    .await?;
    start_gobgp(w, &["l2vpn-evpn"]).await?;
    let mut last = String::new();
    for _ in 0..60 {
        last = gobgp(w, &["neighbor", IP_A]).await.unwrap_or_default();
        if last.contains("BGP state = SESSION_STATE_ESTABLISHED") {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !last.contains("BGP state = SESSION_STATE_ESTABLISHED") {
        bail!("GoBGP never established with router-a: {last}");
    }

    let installed =
        format!("added route prefix=10\\.200\\..*gateway={IP_G} next_hops=1 .*source=Some(Evpn)");
    let removed = format!("removed route prefix=10\\.200\\..*gateway={IP_G}");
    let errors = [
        "failed to apply routes to kernel",
        "failed to apply evpn route delta to kernel",
        "File exists",
        "Device or resource busy",
    ];
    let error_base: Vec<usize> = errors.iter().map(|e| a.count(e)).collect();
    let (installed_base, removed_base) = (a.count(&installed), a.count(&removed));

    let n = L3_BURST_ROUTES;
    let announce = format!(
        "seq 0 {} | xargs -P 16 -I{{}} sh -c 'i={{}}; gobgp global rib add -a evpn prefix \
         10.200.$((i/250)).$((i%250+1))/32 gw 0.0.0.0 etag 0 label {L3_VNI} rd 65010:7 \
         rt {L3_RT} encap vxlan router-mac {L3_GOBGP_RMAC}'",
        n - 1
    );
    let started = std::time::Instant::now();
    let (code, out) = w.dock.exec("router-g", &["sh", "-c", &announce]).await?;
    if code != 0 {
        bail!("announcing the burst: exit {code}: {}", out.trim());
    }
    let mut seen = 0;
    while started.elapsed() < Duration::from_secs(L3_BURST_SECS) {
        seen = a.count(&installed) - installed_base;
        if seen >= n {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    log(format!(
        "burst: {seen}/{n} routes installed in {}s",
        started.elapsed().as_secs()
    ));
    if seen < n {
        bail!("only {seen}/{n} burst routes installed within {L3_BURST_SECS}s");
    }
    let table = a.routes_walk(L3_TABLE, None).await?;
    let listed = table
        .iter()
        .filter(|p| {
            p["prefix"]
                .as_str()
                .is_some_and(|s| s.starts_with("10.200."))
        })
        .count();
    if listed != n {
        bail!("{L3_TABLE} lists {listed} of the {n} burst routes over REST");
    }

    gobgp(w, &["global", "rib", "del", "all", "-a", "evpn"]).await?;
    let started = std::time::Instant::now();
    loop {
        let gone = a.count(&removed) - removed_base;
        if gone >= n {
            break;
        }
        if started.elapsed() > Duration::from_secs(L3_BURST_SECS) {
            bail!("only {gone}/{n} burst routes removed within {L3_BURST_SECS}s");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    for (e, base) in errors.iter().zip(error_base) {
        a.assert_quiet(e, base, 1).await?;
    }
    w.dock.container_remove("router-g").await;
    Ok(())
}

/// `evpn-v6`: one PE's flags toward one peer over the IPv6 underlay — eth0
/// keeps its IPv4 address (REST) plus `v6` (labelled, so it is the VTEP), one
/// `l2vpn-evpn` peer-group per peer (their ASes differ), and the domain.
fn v6_pe_flags(
    me: Id,
    me6: &str,
    rd: &str,
    (pg, peer_as, peer6): (&str, u32, &str),
) -> Vec<String> {
    strings(&[
        "--address",
        &format!("{}/24", me.ip),
        "--address6",
        &format!("{me6}/64"),
        "--address6-label",
        V6_LABEL,
        "--asn",
        &me.asn.to_string(),
        "--router-id",
        me.rid,
        "--peer-group",
        pg,
        "--remote-as",
        &peer_as.to_string(),
        "--peer",
        peer6,
        "--evpn",
        "--broadcast-domain",
        EVPN_DOMAIN,
        "--evpn-vni",
        &EVPN_VNI.to_string(),
        "--evpn-rd",
        rd,
        "--evpn-rt-import",
        EVPN_DP_RT,
        "--evpn-rt-export",
        EVPN_DP_RT,
        "--evpn-vtep-source-interface",
        "eth0",
        "--evpn-vtep-source-label",
        V6_LABEL,
        "--evpn-redistribute-bgp",
        "r1",
    ])
}

/// Runs a command inside `router`'s network namespace.
async fn netns(w: &World, router: &str, cmd: &[&str]) -> anyhow::Result<String> {
    w.dock.in_netns(NETNS_HELPER_IMAGE, router, cmd).await
}

/// `evpn-v6`'s router-c: its FDB nexthops and the CE MAC's `vx<vni>` entry.
async fn kernel_c(w: &World, mac: &str) -> anyhow::Result<(String, String)> {
    let nexthops = netns(w, "router-c", &["ip", "nexthop", "show"]).await?;
    let fdb = netns(
        w,
        "router-c",
        &["bridge", "fdb", "show", "dev", &format!("vx{EVPN_VNI}")],
    )
    .await?;
    let entry = fdb
        .lines()
        .filter(|l| l.contains(mac) && l.contains(" self"))
        .collect::<Vec<_>>()
        .join("\n");
    Ok((nexthops, entry))
}

/// `evpn-v6`: no BUM from the CE once the host's address is resolved —
/// static neighbours both ways and no IPv6 on the CE (no ND/MLD). Not for
/// nos's sake: each CE link crosses a docker network, a *learning* bridge.
/// A broadcast the CE sends through one PE that comes back to it through the
/// other (a PE not set up yet, or local bias missing, see
/// docs/protocols/evpn-vxlan.md "Implementation notes") makes that docker bridge
/// learn the CE's MAC behind the PE's side and drop every unicast the PE sends it. A
/// direct link has no such switch in between. IPv6 goes before the CE's bond
/// is built (`dataplane_ce`), so the bond never sends any.
async fn quiet_ce(w: &World) -> anyhow::Result<()> {
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    netns(
        w,
        CE_HOST,
        &[
            "sh",
            "-c",
            "for c in all default eth0 eth1; do \
             echo 1 > /proc/sys/net/ipv6/conf/$c/disable_ipv6; done",
        ],
    )
    .await?;
    dataplane_ce(w, "mode balance-xor miimon 100 xmit_hash_policy layer2").await?;
    let h_mac = host_sh(w, H_HOST, "cat /sys/class/net/eth0/address").await?;
    let ce_mac = host_sh(w, CE_HOST, "cat /sys/class/net/bond0/address").await?;
    host_sh(
        w,
        CE_HOST,
        &format!(
            "ip neigh replace {H_IP} lladdr {} dev bond0 nud permanent",
            h_mac.trim()
        ),
    )
    .await?;
    host_sh(
        w,
        H_HOST,
        &format!(
            "ip neigh replace {CE_IP} lladdr {} dev eth0 nud permanent",
            ce_mac.trim()
        ),
    )
    .await?;
    Ok(())
}

/// `evpn-v6`: the CE sends through each PE alone, so each sees it locally
/// and advertises its MAC — what #172's check (`same_segment_no_move`) needs.
/// Forwarding doesn't: a PE that never saw the CE has it pinned to its bond
/// from the other's Type-2 (#173). A link downed on the CE side only is one
/// its PE can't see, so a reply hashed there is lost: `|| true`.
async fn ce_on_each_link(w: &World) -> anyhow::Result<()> {
    for link in ["eth1", "eth0"] {
        host_sh(
            w,
            CE_HOST,
            &format!(
                "ip link set {link} down; sleep 1; ping -c 2 -W 1 {H_IP} || true; \
                 ip link set {link} up; sleep 1"
            ),
        )
        .await?;
    }
    Ok(())
}

/// EVPN over an IPv6-only underlay, with aliasing (RFC 7432 §8.4.1.1) and real
/// forwarding. Three `nos` PEs in a full mesh of IPv6 eBGP sessions, `l2vpn-evpn`
/// only, each VTEP the labelled IPv6 address on eth0 (in `rt1`'s VRF). A CE is
/// dual-homed to router-a and router-b through one all-active Ethernet
/// Segment, a host is behind router-c. Router-c balances the CE's MAC over an
/// IPv6 FDB nexthop group of both PEs (read back from the kernel), the CE and
/// the host ping across the IPv6 VXLAN both ways; router-c shutting its
/// session to router-a shrinks the group to router-b alone and un-shutting
/// restores it; unsetting the VNI removes the VXLAN device and its IPv6
/// nexthops.
pub async fn evpn_v6(w: &mut World) -> anyhow::Result<()> {
    const RD_C: &str = "65003:1";
    w.require_ipv6().await?;
    let a_b = ("pg-b", ASN_B, V6_B);
    let a_c = ("pg-c", ASN_C, V6_C);
    let b_a = ("pg-a", ASN_A, V6_A);
    let c_a = ("pg-a", ASN_A, V6_A);
    w.start(A, Some(v6_pe_flags(A, V6_A, EVPN_DP_RD_A, a_b)), &[])
        .await?;
    w.start(B, Some(v6_pe_flags(B, V6_B, EVPN_DP_RD_B, b_a)), &[])
        .await?;
    w.start(C, Some(v6_pe_flags(C, V6_C, RD_C, c_a)), &[])
        .await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    a.provision_flags(&v6_pe_flags(A, V6_A, EVPN_DP_RD_A, a_c))
        .await?;
    b.provision_flags(&v6_pe_flags(B, V6_B, EVPN_DP_RD_B, ("pg-c", ASN_C, V6_C)))
        .await?;
    c.provision_flags(&v6_pe_flags(C, V6_C, RD_C, ("pg-b", ASN_B, V6_B)))
        .await?;

    log("the IPv6 sessions: each PE peers the other two over its v6 address");
    for (r, peers) in [(a, [V6_B, V6_C]), (b, [V6_A, V6_C]), (c, [V6_A, V6_B])] {
        for peer in peers {
            r.wait(&format!("bgp session established.*{peer}")).await?;
        }
        let summary = r
            .rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?;
        for peer in peers {
            if !summary.contains(peer) {
                bail!("{}: /v1/bgp/summary lacks {peer}: {summary}", r.name());
            }
        }
    }

    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    for router in ["router-a", "router-b", "router-c"] {
        // Also governs udp6 sockets (`udp_sk_bound_dev_eq`): there is no
        // IPv6 twin of this sysctl.
        netns(
            w,
            router,
            &["sh", "-c", "echo 1 > /proc/sys/net/ipv4/udp_l3mdev_accept"],
        )
        .await?;
    }

    log("wiring the CE (to router-a and router-b) and the host (to router-c)");
    for net in [NET_CE_A, NET_CE_B, NET_H] {
        if !w.dock.network_exists(net).await {
            w.dock.network_create(net, &[], false).await?;
        }
    }
    w.dock.network_connect(NET_CE_A, "router-a").await;
    w.dock.network_connect(NET_CE_B, "router-b").await;
    w.dock.network_connect(NET_H, "router-c").await;
    w.dock
        .ensure_image(
            HOST_IMAGE,
            "FROM debian:bookworm-slim\n\
             RUN apt-get update && apt-get install -y --no-install-recommends \\\n \
             iproute2 iputils-ping iputils-arping tcpdump && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    w.dock.start_host(H_HOST, HOST_IMAGE, NET_H).await?;

    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let mut fa = v6_pe_flags(A, V6_A, EVPN_DP_RD_A, a_b);
    fa.extend(bond_flags("bond1", true, "eth1"));
    a.provision_flags(&fa).await?;
    let mut fb = v6_pe_flags(B, V6_B, EVPN_DP_RD_B, b_a);
    fb.extend(bond_flags("bond1", true, "eth1"));
    b.provision_flags(&fb).await?;
    let mut fc = v6_pe_flags(C, V6_C, RD_C, c_a);
    fc.extend(bond_flags("bond2", false, "eth1"));
    c.provision_flags(&fc).await?;

    let vxlan = format!("vx{EVPN_VNI}");
    for (r, me) in [(a, V6_A), (b, V6_B), (c, V6_C)] {
        r.wait(&format!(
            "vxlan device ready domain={EVPN_DOMAIN} vni={EVPN_VNI} vxlan={vxlan} .*vtep={me}"
        ))
        .await?;
    }
    for peer in [V6_A, V6_B] {
        c.wait(&format!(
            "flood entry installed domain={EVPN_DOMAIN} vtep={peer}"
        ))
        .await?;
    }
    // Modulo over [::a, ::b] (HRW needs IPv4): 10100 % 2 == 0, router-a.
    let bond_a = bond_name(a, "bond1").await?;
    a.wait(&format!(
        "df elected domain={EVPN_DOMAIN} esi={ESI} port={bond_a} role=df algorithm=modulo ac_df=true pes={V6_A},{V6_B}"
    ))
    .await?;
    let bond_b = bond_name(b, "bond1").await?;
    b.wait(&format!(
        "df elected domain={EVPN_DOMAIN} esi={ESI} port={bond_b} role=non-df algorithm=modulo ac_df=true pes={V6_A},{V6_B}"
    ))
    .await?;
    // #460: the CE comes up only now. A fresh container's IPv6 RS/MLD burst
    // that a PE floods back before its segment port is set up teaches that
    // CE link's docker bridge the CE's MAC behind the PE, for 300s.
    local_bias_readback(w, "router-a", &bond_a, &vxlan, V6_B, false).await?;
    local_bias_readback(w, "router-b", &bond_b, &vxlan, V6_A, true).await?;
    w.dock.start_host(CE_HOST, HOST_IMAGE, NET_CE_A).await?;
    w.dock.network_connect(NET_CE_B, CE_HOST).await;

    log("the CE bonds its two links; the host takes an address; they ping across the IPv6 VXLAN");
    quiet_ce(w).await?;
    let ce_mac = host_sh(w, CE_HOST, "cat /sys/class/net/bond0/address")
        .await?
        .trim()
        .to_string();
    ping_until(w, CE_HOST, H_IP, 30).await?;
    ping_until(w, H_HOST, CE_IP, 30).await?;

    // #173: the CE sends through whichever PE its hash picks; the other
    // learns nothing locally, yet must deliver what router-c balances onto
    // it — its pin does.
    log("the segment PE the CE doesn't send through pins its MAC to its own bond");
    let pin =
        |bond: &str| format!("remote mac pinned domain={EVPN_DOMAIN} mac={ce_mac} port={bond}");
    let mut pinned = false;
    for _ in 0..30 {
        if a.count(&pin(&bond_a)) + b.count(&pin(&bond_b)) > 0 {
            pinned = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !pinned {
        bail!("neither segment PE pinned the CE's MAC {ce_mac} to its bond");
    }

    log("router-c aliases the CE's MAC over an IPv6 FDB nexthop group of both PEs");
    let group =
        format!("remote mac group installed domain={EVPN_DOMAIN} mac={ce_mac} vteps={V6_A},{V6_B}");
    c.wait(&group).await?;
    let (nexthops, entry) = kernel_c(w, &ce_mac).await?;
    if !entry.contains("nhid") {
        bail!("the CE MAC's FDB entry on router-c does not use a nexthop group: {entry:?}");
    }
    if nexthops.lines().filter(|l| l.contains("group ")).count() != 1
        || !nexthops.contains(&format!("via {V6_A}"))
        || !nexthops.contains(&format!("via {V6_B}"))
    {
        bail!("expected one IPv6 FDB group over both PEs on router-c: {nexthops}");
    }
    let body = c
        .rest_expect(Method::GET, &format!("/v1/fdb/{EVPN_DOMAIN}"), None, 200)
        .await?;
    let table: serde_json::Value = serde_json::from_str(&body)?;
    let vteps = table["macs"]
        .as_array()
        .and_then(|m| m.iter().find(|e| e["mac"] == ce_mac.as_str()))
        .map(|e| e["vteps"].to_string())
        .context("router-c's show fdb lacks the CE's MAC")?;
    if !vteps.contains(V6_A) || !vteps.contains(V6_B) {
        bail!("router-c's show fdb does not list both VTEPs of the CE's MAC: {vteps}");
    }
    // Flows balanced over both PEs: whichever one router-c picks delivers.
    host_sh(w, H_HOST, &format!("ping -c 3 -W 2 {CE_IP}")).await?;
    host_sh(w, CE_HOST, &format!("ping -c 3 -W 2 {H_IP}")).await?;
    ce_on_each_link(w).await?;
    same_segment_no_move(w, &ce_mac, [(A, V6_B), (B, V6_A)]).await?;

    // Local bias (#24) over an IPv6 underlay: `enc_src_ip` matches the outer
    // IPv6 source on the VXLAN device itself. Router-a is the DF, router-b the
    // non-DF.
    log("local bias: router-a and router-b mark each other's VTEP; core BUM from router-c reaches the CE once, through the DF router-a");
    local_bias_readback(w, "router-a", &bond_a, &vxlan, V6_B, false).await?;
    local_bias_readback(w, "router-b", &bond_b, &vxlan, V6_A, true).await?;
    let (via_a, via_b, _) = arp_broadcast(w, None).await?;
    if (via_a, via_b) != (1, 0) {
        bail!(
            "the host's broadcast reached the CE {via_a}x through router-a (the DF) and {via_b}x \
             through router-b (the non-DF); expected exactly 1 and 0\ncaptures: {}",
            host_sh(w, CE_HOST, "tail -n +1 /tmp/e0 /tmp/e1").await?
        );
    }
    log("local bias: the CE's broadcast out of its link to router-b (non-DF) is not echoed through router-a, and the host gets it once");
    let (echo_a, echo_b, host) = arp_broadcast(w, Some("eth1")).await?;
    if (echo_a, echo_b, host) != (0, 0, 1) {
        bail!(
            "the CE's own broadcast came back {echo_a}x on its link to router-a and {echo_b}x on \
             its link to router-b, and reached the host {host}x; expected 0, 0 and 1\ncaptures: {}\ntc:{}",
            host_sh(w, CE_HOST, "tail -n +1 /tmp/e0 /tmp/e1").await?,
            bias_counters(w, [&bond_a, &bond_b], &vxlan).await
        );
    }

    // A control-plane withdrawal, not router-a's bond going down: nos-interfaced
    // brings a downed bond back up within seconds (#169).
    log("router-c shuts its session to router-a: router-a's A-D routes go, the group with them, the CE still reaches the host");
    let removed =
        format!("remote mac group removed domain={EVPN_DOMAIN} mac={ce_mac} vteps={V6_A},{V6_B}");
    let only_b = format!("segment per-es a-d changed domain={EVPN_DOMAIN} esi={ESI} pes={V6_B}$");
    let (base, base_b) = (c.count(&removed), c.count(&only_b));
    let mut shut = v6_pe_flags(C, V6_C, RD_C, c_a);
    shut.extend(strings(&["--shutdown-peer", ""]));
    c.provision_flags(&shut).await?;
    c.wait_new(&removed, base, 60).await?;
    c.wait_new(&only_b, base_b, 60).await?;
    let (_, entry) = kernel_c(w, &ce_mac).await?;
    if entry.contains("nhid") || (!entry.is_empty() && !entry.contains(&format!("dst {V6_B}"))) {
        bail!("router-c still sends the CE's MAC to router-a: {entry:?}");
    }
    // Router-a has lost router-c's routes too: the CE's link to it would
    // black-hole whatever the CE hashes onto it.
    host_sh(w, CE_HOST, "ip link set eth0 down; sleep 1").await?;
    ping_until(w, CE_HOST, H_IP, 30).await?;
    ping_until(w, H_HOST, CE_IP, 30).await?;

    log("the session back: the group over both returns");
    let base = c.count(&group);
    let mut unshut = v6_pe_flags(C, V6_C, RD_C, c_a);
    unshut.push("--unshutdown-peer".to_string());
    c.provision_flags(&unshut).await?;
    host_sh(w, CE_HOST, "ip link set eth0 up; sleep 1").await?;
    c.wait_new(&group, base, 60).await?;
    let (_, entry) = kernel_c(w, &ce_mac).await?;
    if !entry.contains("nhid") {
        bail!("router-c's CE MAC entry did not go back to a group: {entry:?}");
    }
    ping_until(w, H_HOST, CE_IP, 30).await?;
    ping_until(w, CE_HOST, H_IP, 30).await?;

    log("unsetting router-c's vni removes its VXLAN device and IPv6 nexthops");
    // `v6_pe_flags`' route targets are the ones `--evpn-clear` removes.
    let mut clear = v6_pe_flags(C, V6_C, RD_C, c_a);
    clear.push("--evpn-clear".to_string());
    // `--evpn-clear` refuses the other `--evpn-*` setting flags.
    for flag in [
        "--evpn-vni",
        "--evpn-rd",
        "--evpn-vtep-source-interface",
        "--evpn-vtep-source-label",
        "--evpn-redistribute-bgp",
    ] {
        let at = clear
            .iter()
            .position(|f| f == flag)
            .context("a flag v6_pe_flags sets")?;
        clear.drain(at..=at + 1);
    }
    c.provision_flags(&clear).await?;
    let mut left = String::new();
    for _ in 0..30 {
        left = netns(w, "router-c", &["ip", "nexthop", "show"]).await?;
        let gone = netns(w, "router-c", &["ip", "link", "show", &vxlan])
            .await
            .is_err();
        if gone && left.trim().is_empty() {
            for host in [CE_HOST, H_HOST] {
                w.dock.container_remove(host).await;
            }
            for (net, router) in [
                (NET_CE_A, "router-a"),
                (NET_CE_B, "router-b"),
                (NET_H, "router-c"),
            ] {
                w.dock.network_disconnect(net, router).await;
                w.dock.network_remove(net).await;
            }
            w.remove(C).await;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("router-c kept {vxlan} or its IPv6 nexthops: {left}")
}

/// RFC 5082 GTSM: `max-hops 1` on both peer-groups (TTL 255 out, kernel drops
/// below 255 in) still establishes in both directions over the directly
/// connected network — proving the SYN-ACK and accepted sockets really carry
/// TTL 255. No negative check: a peer with max-hops only on one side still
/// gets a session, since the listener always sends 255 (see `bind_listener`),
/// so the packets that side would drop never exist in this topology.
pub async fn gtsm(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let (base_a, base_b) = (
        a.count("bgp session established"),
        b.count("bgp session established"),
    );
    a.provision(&["--max-hops", "1"]).await?;
    b.provision(&["--max-hops", "1"]).await?;
    a.wait("max hops applied").await?;
    b.wait("max hops applied").await?;
    reestablished(a, base_a).await?;
    reestablished(b, base_b).await
}

/// RFC 9234 BGP roles (#220) between router-a and router-b: provider/customer
/// negotiates (`bgp role negotiated`); provider/provider is refused with a Role
/// Mismatch NOTIFICATION (OPEN Message Error subcode 11) and never
/// establishes; a strict-mode speaker refuses a peer with no role, while a
/// non-strict one just establishes with no role negotiated.
pub async fn bgp_role(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.established().await?;
    b.established().await?;
    let est = "bgp session established";
    let negotiated = |local: &str, remote: &str| {
        format!("bgp role negotiated peer=.* local=\"{local}\" remote=\"{remote}\"")
    };
    let sent = "sent notification peer=.* code=2 subcode=11";
    let set_role = |r: Option<nos_proto::BgpRole>, strict: bool| {
        move |c: &mut nos_proto::Config| {
            let g = &mut c.bgp_instances[0].peer_groups[0];
            g.role = r;
            g.strict_mode = strict;
            Ok(())
        }
    };

    log("provider / customer: a legal pair negotiates");
    let (na, nb) = (
        a.count("bgp role negotiated"),
        b.count("bgp role negotiated"),
    );
    a.provision(&["--role", "provider"]).await?;
    b.provision(&["--role", "customer"]).await?;
    a.wait_new(&negotiated("provider", "customer"), na, 60)
        .await?;
    b.wait_new(&negotiated("customer", "provider"), nb, 60)
        .await?;

    log("provider / provider: Role Mismatch both ways, no session");
    // Each side rejects the other's OPEN on its own, so both send one.
    let (sa, sb) = (a.count(sent), b.count(sent));
    b.provision(&["--role", "provider"]).await?;
    a.wait_new(sent, sa, 60).await?;
    b.wait_new(sent, sb, 60).await?;
    let (ea, eb) = (a.count(est), b.count(est));
    let (na, nb) = (
        a.count("bgp role negotiated"),
        b.count("bgp role negotiated"),
    );
    a.assert_quiet(est, ea, 10).await?;
    b.assert_quiet(est, eb, 0).await?;
    anyhow::ensure!(
        a.count("bgp role negotiated") == na && b.count("bgp role negotiated") == nb,
        "a role was negotiated for a mismatched pair"
    );

    log("a strict vs b with no role: refused");
    b.edit(set_role(None, false)).await?;
    let sa = a.count(sent);
    a.provision(&["--role", "provider", "--strict-mode"])
        .await?;
    a.wait_new(sent, sa, 60).await?;
    let ea = a.count(est);
    a.assert_quiet(est, ea, 10).await?;

    log("a non-strict vs b with no role: established, no role negotiated");
    let (ea, na) = (a.count(est), a.count("bgp role negotiated"));
    a.edit(set_role(Some(nos_proto::BgpRole::Provider), false))
        .await?;
    a.wait_new(est, ea, 60).await?;
    a.assert_quiet("bgp role negotiated", na, 3).await?;
    otc(w).await
}

/// RFC 9234 §5 Only-to-Customer (#221), router-b in the middle: a and c are
/// its providers (a provider-learned route is not re-advertised between them),
/// then c its customer (it receives a's route carrying OTC = a's ASN), and an
/// ExaBGP customer sending a raw OTC is a leak, dropped by the ingress rule
/// even though ExaBGP sent no Role capability (the configured role applies).
async fn otc(w: &mut World) -> anyhow::Result<()> {
    let est = "bgp session established";
    let b_group = |group: &str, asn: u32, peer: &str, role: &str| {
        strings(&[
            "--address",
            &format!("{IP_B}/24"),
            "--asn",
            &ASN_B.to_string(),
            "--router-id",
            RID_B,
            "--peer-group",
            group,
            "--remote-as",
            &asn.to_string(),
            "--peer",
            peer,
            "--role",
            role,
        ])
    };
    let c_flags = |role: &str| {
        strings(&[
            "--address",
            &format!("{IP_C}/24"),
            "--asn",
            &ASN_C.to_string(),
            "--router-id",
            RID_C,
            "--remote-as",
            &ASN_B.to_string(),
            "--peer",
            IP_B,
            "--role",
            role,
        ])
    };

    log("otc: a and c are both providers of b; a's route is not passed from one to the other");
    let mut flags = redistribute();
    flags.extend(["--role", "provider"]);
    w.a()?.provision(&flags).await?;
    w.b()?.provision(&["--role", "customer"]).await?;
    w.b()?
        .provision_flags(&b_group("pg-c", ASN_C, IP_C, "customer"))
        .await?;
    w.start(C, Some(c_flags("provider")), &[]).await?;
    let (b, c) = (w.b()?, w.c()?);
    c.wait(est).await?;
    b.wait(&format!("{} .*otc=Some({ASN_A})", learned()))
        .await?;
    b.wait(&loc_rib()).await?;
    c.assert_quiet(&learned(), 0, 10).await?;

    log("otc: c becomes b's customer; it now receives a's route carrying OTC = a's asn");
    let base = c.count(est);
    c.provision_flags(&c_flags("customer")).await?;
    b.provision_flags(&b_group("pg-c", ASN_C, IP_C, "provider"))
        .await?;
    c.wait_new(est, base, 60).await?;
    c.wait(&format!("{} .*otc=Some({ASN_A})", learned()))
        .await?;

    // #872: RPL role/OTC fields on b's session to a (b is a's customer, so
    // local_role customer, remote_role provider, post-ingress otc = a's ASN).
    log("otc: an import policy matching the roles and OTC rejects a's route");
    let matches = format!(
        "this.bgp.local_role == role.customer and this.bgp.remote_role == role.provider and this.bgp.otc == {ASN_A}"
    );
    let on_a = |name: &str, src: &str| -> anyhow::Result<Vec<String>> {
        let file = policy_file(name, src)?;
        Ok(strings(&[
            "--role",
            "customer",
            "--policy-name",
            name,
            "--policy-source-file",
            &file,
            "--import-policy",
            name,
        ]))
    };
    let est_b = w.b()?.count(est);
    w.b()?
        .provision(&on_a(
            "otc-reject",
            &format!("if {matches}:\n    reject\nelse:\n    accept\n"),
        )?)
        .await?;
    reestablished(w.b()?, est_b).await?;
    let learned_otc = format!("{} .*otc=Some({ASN_A})", learned());
    let base = w.b()?.count(&learned_otc);
    w.b()?.assert_quiet(&learned_otc, base, 10).await?;

    log("otc: the same condition as an accept finds a's route again");
    let base = w.b()?.count(&learned_otc);
    w.b()?
        .provision(&on_a(
            "otc-accept",
            &format!("if {matches}:\n    accept\nelse:\n    reject\n"),
        )?)
        .await?;
    w.b()?.wait_new(&learned_otc, base, 60).await?;

    log("otc: a customer's OTC is a route leak, dropped although it sent no Role capability");
    // The role-less customer's remote_role is unset: only `!=` matches it.
    let unset = policy_file(
        "otc-unset-role",
        "if this.bgp.remote_role != role.provider and this.bgp.remote_role != role.customer and this.bgp.local_role == role.provider:\n    accept\nelse:\n    reject\n",
    )?;
    let mut g_flags = b_group("pg-g", ASN_G, IP_G, "provider");
    g_flags.extend(strings(&[
        "--policy-name",
        "otc-unset-role",
        "--policy-source-file",
        &unset,
        "--import-policy",
        "otc-unset-role",
    ]));
    w.b()?.provision_flags(&g_flags).await?;
    ensure_exabgp(w).await?;
    let conf = format!(
        "neighbor {IP_B} {{\n    router-id {RID_G};\n    local-address {IP_G};\n    \
         local-as {ASN_G};\n    peer-as {ASN_B};\n    family {{ ipv4 unicast; }}\n    \
         static {{\n        route {OTC_LEAK_PREFIX} next-hop {IP_G} as-path [ {ASN_G} ] \
         attribute [ 0x23 0xc0 0x0000fde8 ];\n        \
         route {OTC_PLAIN_PREFIX} next-hop {IP_G} as-path [ {ASN_G} ];\n    }}\n}}\n"
    );
    w.dock
        .start_plain(
            "router-g",
            EXABGP_IMAGE,
            NET,
            IP_G,
            &["/etc/exabgp.conf"],
            ("/etc", "exabgp.conf", conf.as_bytes()),
        )
        .await?;
    let b = w.b()?;
    b.wait("route leak detected").await?;
    b.wait(&format!(
        "learned route for {OTC_PLAIN_PREFIX} into adj-rib-in"
    ))
    .await?;
    anyhow::ensure!(
        b.count(&format!("loc-rib best path for {OTC_LEAK_PREFIX}")) == 0
            && b.count(&format!("learned route for {OTC_LEAK_PREFIX}")) == 0,
        "router-b kept the leaked {OTC_LEAK_PREFIX}"
    );
    w.dock.container_remove("router-g").await;
    w.remove(C).await;
    Ok(())
}

/// router-a's flags for `rtc`: `vpn_flags` (VRF `VPN_TABLE` importing
/// `import_rt`) plus EVPN, `rt-constraint` and the `evpn-fdb` broadcast
/// domain, all toward GoBGP.
fn rtc_flags(import_rt: &str) -> Vec<String> {
    let mut f = vpn_flags(import_rt);
    f.extend(strings(&[
        "--evpn",
        "--rtc",
        "--vpn-loopback-address",
        VPN_EXPORT_A,
        "--broadcast-domain",
        EVPN_DOMAIN,
        "--evpn-vni",
        &EVPN_VNI.to_string(),
        "--evpn-rd",
        EVPN_RD,
        "--evpn-rt-import",
        EVPN_RT_IMPORT,
        "--evpn-rt-export",
        EVPN_RT_EXPORT,
        "--evpn-vtep-source-interface",
        "eth0",
        "--evpn-redistribute-bgp",
        "r1",
    ]));
    f
}

/// Polls GoBGP's `family` RIB (`gobgp global rib -a <family>`) until
/// `want(rib)` holds.
async fn gobgp_rib_until(
    w: &World,
    family: &str,
    what: &str,
    want: impl Fn(&str) -> bool,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..30 {
        last = gobgp(w, &["global", "rib", "-a", family]).await?;
        if want(&last) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("GoBGP's {family} RIB never {what}: {last}")
}

/// RFC 4684 Route Target Constraint against GoBGP (#875). router-a has a VRF
/// (import `RTC_IMPORT`, export `VPN_RD_A`), a VNI domain (import
/// `EVPN_RT_IMPORT`, export `EVPN_RT_EXPORT`) and `rt-constraint`.
///
/// - GoBGP sends no membership: router-a holds back its VPN route and
///   Type-3 (GoBGP's VPNv4 and EVPN RIBs stay empty);
/// - GoBGP's membership for the VRF's export RT releases the VPN route,
///   its withdrawal takes it back; the Type-3 follows its own RT;
/// - the default membership route releases everything, its withdrawal takes
///   everything back;
/// - reverse: router-a originates its import RTs (origin AS router-a's AS),
///   a commit changing the VRF import RT swaps them;
/// - graceful restart (GoBGP carries (1, 132) in its GR capability): killing
///   router-a's `nos-bgpd` keeps GoBGP's copy of the VPN route, and
///   router-a's selection deferral ends only after GoBGP's membership is back.
pub async fn rtc(w: &mut World) -> anyhow::Result<()> {
    w.start(A, Some(rtc_flags(RTC_IMPORT)), &[]).await?;
    start_gobgp_gr(w, &["l3vpn-ipv4-unicast", "l2vpn-evpn", "rtc"], ASN_G, true).await?;
    mpls_ready(w, &["router-a"]).await?;
    let a = w.a()?;
    a.wait(&format!(
        "address families negotiated peer={IP_G} families=\\[.*\"rt-constraint\""
    ))
    .await?;
    let advertised = format!(
        "vpn route advertised peer={IP_G} family=vpnv4 rd={VPN_RD_A} prefix={VPN_EXPORT_A} "
    );
    let withdrawn = format!(
        "vpn route advertisement withdrawn peer={IP_G} family=vpnv4 rd={VPN_RD_A} prefix={VPN_EXPORT_A}"
    );
    let in_gobgp = format!("{VPN_RD_A}:{VPN_EXPORT_A}");
    let has_vpn = |present: bool| gobgp_vpn_until(w, "vpnv4", &in_gobgp, present);
    let type3 = |rib: &str| {
        rib.lines()
            .any(|l| l.contains("multicast") && l.contains(&format!("rd:{EVPN_RD}")))
    };
    let rtc = |verb: &'static str, spec: &[&str]| {
        let mut v = strings(&["global", "rib", "-a", "rtc", verb]);
        v.extend(strings(spec));
        gobgp_owned(w, v)
    };
    let g_asn = ASN_G.to_string();

    log("no membership from GoBGP: nothing is advertised");
    a.wait("vxlan device ready").await?;
    let base = a.count(&advertised);
    a.assert_quiet(&advertised, base, 8).await?;
    let out = gobgp(w, &["global", "rib", "-a", "vpnv4"]).await?;
    anyhow::ensure!(!out.contains(&in_gobgp), "VPN route leaked: {out}");
    let out = gobgp(w, &["global", "rib", "-a", "evpn"]).await?;
    anyhow::ensure!(!type3(&out), "Type-3 leaked: {out}");

    log("membership for the VRF's export RT releases the VPN route, not the Type-3");
    let base = a.count(&advertised);
    rtc("add", &["asn", &g_asn, "rt", VPN_RD_A]).await?;
    a.wait_new(&advertised, base, 30).await?;
    has_vpn(true).await?;
    let out = gobgp(w, &["global", "rib", "-a", "evpn"]).await?;
    anyhow::ensure!(!type3(&out), "Type-3 sent without its RT: {out}");

    log("membership for the domain's export RT releases the Type-3");
    rtc("add", &["asn", &g_asn, "rt", EVPN_RT_EXPORT]).await?;
    gobgp_rib_until(w, "evpn", "showed router-a's Type-3", type3).await?;

    log("withdrawing the VRF membership withdraws the VPN route");
    let base = a.count(&withdrawn);
    rtc("del", &["asn", &g_asn, "rt", VPN_RD_A]).await?;
    a.wait_new(&withdrawn, base, 30).await?;
    has_vpn(false).await?;
    rtc("del", &["asn", &g_asn, "rt", EVPN_RT_EXPORT]).await?;
    gobgp_rib_until(w, "evpn", "dropped the Type-3", |r| !type3(r)).await?;

    log("the default membership route wants everything");
    let base = a.count(&advertised);
    rtc("add", &["default"]).await?;
    a.wait_new(&advertised, base, 30).await?;
    has_vpn(true).await?;
    gobgp_rib_until(w, "evpn", "showed router-a's Type-3", type3).await?;
    let base = a.count(&withdrawn);
    rtc("del", &["default"]).await?;
    a.wait_new(&withdrawn, base, 30).await?;
    has_vpn(false).await?;
    gobgp_rib_until(w, "evpn", "dropped the Type-3", |r| !type3(r)).await?;

    log("reverse: router-a originates its VRF and domain import RTs");
    let member = |asn: u32, rt: &str| format!("{asn}:{rt}/96");
    let held = |rt: &'static str| {
        let want = member(ASN_A, rt);
        move |r: &str| r.contains(&want)
    };
    gobgp_rib_until(w, "rtc", "showed the VRF import RT", held(RTC_IMPORT)).await?;
    gobgp_rib_until(
        w,
        "rtc",
        "showed the domain import RT",
        held(EVPN_RT_IMPORT),
    )
    .await?;
    log("changing the VRF import RT swaps the membership route");
    a.provision_flags(&rtc_flags(RTC_IMPORT_2)).await?;
    gobgp_rib_until(w, "rtc", "showed the new import RT", held(RTC_IMPORT_2)).await?;
    gobgp_rib_until(w, "rtc", "dropped the old import RT", |r| {
        !r.contains(&member(ASN_A, RTC_IMPORT))
    })
    .await?;
    a.provision_flags(&rtc_flags(RTC_IMPORT)).await?;
    gobgp_rib_until(w, "rtc", "showed the VRF import RT again", held(RTC_IMPORT)).await?;

    rtc_graceful_restart(w).await
}

/// `rtc`'s last step: GoBGP's graceful restart capability lists `rtc` and so
/// does router-a's; with GoBGP's membership `default`, router-a's `nos-bgpd`
/// is killed and must re-learn the membership, receive GoBGP's RTC
/// End-of-RIB and re-advertise the VPN route.
// ponytail: GoBGP does not send its unicast routes once RT-Constraint is
// negotiated, so `nos-ribd` holds no BGP route across the kill: router-a's
// restart is not deferred here, and "the deferral waits for the RTC
// End-of-RIB" is covered by a unit test only.
async fn rtc_graceful_restart(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    let in_gobgp = format!("{VPN_RD_A}:{VPN_EXPORT_A}");
    let learned = format!("rtc membership learned peer={IP_G} ");
    let eor = format!("received end-of-rib peer={IP_G} family=rt-constraint");
    let advertised = format!(
        "vpn route advertised peer={IP_G} family=vpnv4 rd={VPN_RD_A} prefix={VPN_EXPORT_A} "
    );
    let est = "bgp session established";
    gobgp_owned(
        w,
        strings(&["global", "rib", "-a", "rtc", "add", "default"]),
    )
    .await?;
    gobgp_vpn_until(w, "vpnv4", &in_gobgp, true).await?;
    // Both capabilities carry (1, 132): GoBGP lists `rtc` among router-a's
    // restartable families.
    let neighbor = gobgp(w, &["neighbor", IP_A]).await?;
    let remote = neighbor
        .split("Remote:")
        .nth(1)
        .context("GoBGP shows no remote graceful restart capability")?;
    anyhow::ensure!(
        remote.contains("rtc"),
        "router-a's graceful restart capability lacks rtc: {neighbor}"
    );

    log("killing router-a's nos-bgpd: it re-learns the membership and GoBGP's End-of-RIB");
    let (learned_n, eor_n, adv_n, est_n) = (
        a.count(&learned),
        a.count(&eor),
        a.count(&advertised),
        a.count(est),
    );
    w.dock.kill_process("router-a", "nos-bgpd").await?;
    a.wait_new(est, est_n, 90).await?;
    a.wait_new(&learned, learned_n, 60).await?;
    a.wait_new(&eor, eor_n, 60).await?;
    a.wait_new(&advertised, adv_n, 60).await?;
    gobgp_vpn_until(w, "vpnv4", &in_gobgp, true).await?;
    Ok(())
}
