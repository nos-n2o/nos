//! OSPFv2 / OSPFv3 phases: real Hello/DBD/LSR/LSU/LSAck adjacencies over raw
//! protocol-89 sockets between real containers, SPF routes into real kernel
//! tables, DR/BDR election on a real Linux bridge, authentication, aging.

use std::time::Duration;

use anyhow::{bail, Context};
use reqwest::Method;

use super::bgp::no_leak;
use crate::consts::*;
use crate::router::{keep_ospfv3_profiles, log, strings, Id, Router, A, B, C, D, E};
use crate::world::World;

const BD: &str = OSPF_BROADCAST_DOMAIN;

// --- provisioning flags (each mirrors one `provision_*` of the old script) ---

/// An OSPF instance + area + profile, attached to eth0's tag-0 subinterface.
fn ospf(router_id: &str) -> Vec<String> {
    let mut f = ospf_instance_only(router_id);
    f.extend(strings(&["--ospf-interface-profile", OSPF_PROFILE]));
    f
}

/// Same, but never attached to eth0.0 — for router-c, which must not form a
/// second, unwanted point-to-point adjacency there (raw sockets have no
/// per-peer demux) and only joins OSPF via the broadcast-domain bridge.
fn ospf_instance_only(router_id: &str) -> Vec<String> {
    strings(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        router_id,
        "--ospf-area",
        OSPF_AREA,
        "--ospf-profile",
        OSPF_PROFILE,
    ])
}

fn with_mtu(mut f: Vec<String>) -> Vec<String> {
    f.extend(strings(&[
        "--ospf-profile-mtu",
        &OSPF_SPLIT_MTU_VALUE.to_string(),
    ]));
    f
}

/// A static route redistributed into OSPF — makes this router a real ASBR.
/// (Overwrites rt1's single `redistribute` rule: that is why `asbr` runs
/// after every bgp-redistribution-dependent phase.)
fn asbr(mut f: Vec<String>) -> Vec<String> {
    f.extend(strings(&[
        "--static-route",
        ASBR_PREFIX,
        "--static-gateway",
        ASBR_GATEWAY.s(),
        "--redistribute-to-ospf",
    ]));
    f
}

/// Trunks eth0 into the ospf broadcast domain (dot1q 400), addresses the
/// domain's bridge (an SVI) and points the domain's ospf field at the profile.
fn ospf_broadcast(svi: &str) -> Vec<String> {
    ospf_broadcast_profile(svi, OSPF_PROFILE)
}

fn ospf_broadcast_profile(svi: &str, profile: &str) -> Vec<String> {
    strings(&[
        "--routing-table",
        "rt1",
        "--switching-profile",
        "sp-ospf",
        "--switching-profile-member",
        &format!("{BD}:{OSPF_BROADCAST_TAG}"),
        "--broadcast-domain",
        BD,
        "--broadcast-domain-svi-address",
        svi,
        "--ospf-broadcast-domain-profile",
        profile,
    ])
}

fn ospfv3_instance_only(router_id: &str) -> Vec<String> {
    strings(&[
        "--ospfv3-instance",
        OSPFV3_INSTANCE,
        "--ospfv3-router-id",
        router_id,
        "--ospfv3-area",
        OSPFV3_AREA,
        "--ospfv3-profile",
        OSPFV3_PROFILE,
    ])
}

fn ospfv3(address: &str, router_id: &str) -> Vec<String> {
    let mut f = strings(&["--address6", address]);
    f.extend(ospfv3_instance_only(router_id));
    f.extend(strings(&["--ospfv3-interface-profile", OSPFV3_PROFILE]));
    f
}

fn ospfv3_broadcast(svi6: &str) -> Vec<String> {
    strings(&[
        "--routing-table",
        "rt1",
        "--broadcast-domain",
        BD,
        "--ospfv3-broadcast-domain-svi-address",
        svi6,
        "--ospfv3-broadcast-domain-profile",
        OSPFV3_PROFILE,
    ])
}

/// `ospfv3_broadcast` for a router whose bridge isn't set up yet: also trunks
/// eth0 into the domain and gives it an IPv4 SVI address (which is what
/// associates the domain with `rt1` — the IPv6-only flags don't, and OSPFv3
/// refuses a domain without a routing table). After `ospf-aging` and the
/// pagination phases restart router-a/b, that setup no longer exists.
fn ospfv3_broadcast_with_l2(svi4: &str, svi6: &str) -> Vec<String> {
    strings(&[
        "--routing-table",
        "rt1",
        "--switching-profile",
        "sp-ospf",
        "--switching-profile-member",
        &format!("{BD}:{OSPF_BROADCAST_TAG}"),
        "--broadcast-domain",
        BD,
        "--broadcast-domain-svi-address",
        svi4,
        "--ospfv3-broadcast-domain-svi-address",
        svi6,
        "--ospfv3-broadcast-domain-profile",
        OSPFV3_PROFILE,
    ])
}

// --- shared checks ---

fn full_p2p(neighbor: &str) -> String {
    format!("ospf neighbor reached full link=eth0.0 neighbor={neighbor}")
}

async fn both_full_p2p(a: &Router, b: &Router) -> anyhow::Result<()> {
    a.wait(&full_p2p(OSPF_ROUTER_ID_B)).await?;
    b.wait(&full_p2p(OSPF_ROUTER_ID)).await
}

/// At least one router logged a DBD chunk with more remaining.
async fn paginated(a: &Router, b: &Router) -> anyhow::Result<()> {
    paginated_with(a, b, "ospf dbd chunk sent, more remaining").await
}

async fn paginated_with(a: &Router, b: &Router, pat: &str) -> anyhow::Result<()> {
    if a.wait(pat).await.is_ok() || b.wait(pat).await.is_ok() {
        log("pagination triggered: a dbd chunk with more remaining was sent");
        Ok(())
    } else {
        bail!("no paginated dbd chunk was ever sent")
    }
}

/// Pagination needs router-a's Router-LSA *and* its redistributed AS-external
/// LSA already in its LSDB when the DBD exchange starts: a single-LSA summary
/// fits in one chunk at any size. REST provisioning is fast enough now that
/// router-b can be up before the static route has become an LSA, so wait for it.
async fn router_a_holds_two_lsas(a: &Router) -> anyhow::Result<()> {
    a.wait("ospf lsa originated.*lsa_type=5").await
}

// --- phases ---

/// Instant negative check (#886): lets lines still in flight land first, so a
/// 0s window judges the settled log store, not the moment it was opened.
async fn quiet_settled(r: &Router, pat: &str, baseline: usize) -> anyhow::Result<()> {
    r.count_fresh(pat).await;
    r.assert_quiet(pat, baseline, 0).await
}

/// Waits (60s at most) until no router has installed or originated a Router-,
/// Network- or other topology LSA for 8s. LSAs are flooded every 5s and held
/// back by MinLSInterval, so a change made just before a restart reaches a
/// helper after it entered grace and, per RFC 3623 §3.2 (c), ends it: a
/// conformant transient that is not what a restart phase measures (#1027).
async fn topology_settled(routers: &[&Router]) -> anyhow::Result<()> {
    let pat = "ospf lsa installed.*lsa_type=[1-57] \\|ospf lsa originated";
    for _ in 0..8 {
        let mut before = Vec::new();
        for r in routers {
            before.push(r.count_fresh(pat).await);
        }
        tokio::time::sleep(Duration::from_secs(8)).await;
        let mut quiet = true;
        for (r, n) in routers.iter().zip(before) {
            quiet &= r.count_fresh(pat).await == n;
        }
        if quiet {
            return Ok(());
        }
    }
    anyhow::bail!("the ospf topology LSAs never settled for 8s within 64s")
}

/// #1437: the operator columns of `GET /v1/<proto>/neighbors` for the row of
/// `peer` on `link`: its address (`addr` exact, or just present when `None`),
/// `Full`, uptime, dead-in within the 40s dead interval and the DR/BDR role.
/// Polled: the snapshot may predate the Full transition by a moment.
async fn assert_neighbor_fields(
    r: &Router,
    proto: &str,
    link: &str,
    peer: &str,
    addr: Option<&str>,
    role: serde_json::Value,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..15 {
        let body = r
            .rest_expect(Method::GET, &format!("/v1/{proto}/neighbors"), None, 200)
            .await?;
        let report: serde_json::Value = serde_json::from_str(&body)?;
        let row = report[0]["result"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|n| n["neighbor_router_id"] == peer && n["link"] == link);
        if let Some(n) = row {
            let ok = n["state"] == "Full"
                && n["address"]
                    .as_str()
                    .is_some_and(|a| addr.is_none_or(|w| a == w))
                && n["uptime_secs"].is_u64()
                && n["dead_in_secs"].as_u64().is_some_and(|d| d <= 40)
                && n["role"] == role;
            if ok {
                return Ok(());
            }
            last = n.to_string();
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    anyhow::bail!("{proto} neighbor {peer} on {link} lacks the #1437 fields: {last}")
}

/// #1438: `GET /v1/<proto>/interfaces` lists `link` as a running
/// point-to-point interface with the fixture's timers, one known and one
/// `Full` neighbor (polled: the counts follow the adjacency).
async fn assert_interface_row(r: &Router, proto: &str, link: &str) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..15 {
        let body = r
            .rest_expect(Method::GET, &format!("/v1/{proto}/interfaces"), None, 200)
            .await?;
        let report: serde_json::Value = serde_json::from_str(&body)?;
        let row = report[0]["result"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|i| i["link"] == link);
        if let Some(i) = row {
            let address_ok = if proto == "ospfv3" {
                i["address"]
                    .as_str()
                    .is_some_and(|a| a.starts_with("fe80::"))
            } else {
                i["address"].as_str().is_some_and(|a| a.contains('/'))
            };
            if i["network_type"] == "PointToPoint"
                && i["state"] == "PointToPoint"
                && i["hello_interval"] == 10
                && i["dead_interval"] == 40
                && i["retransmit_interval"] == 5
                && i["cost"].as_u64().is_some_and(|c| c >= 1)
                && i["neighbor_count"] == 1
                && i["full_neighbor_count"] == 1
                && address_ok
            {
                return Ok(());
            }
            last = i.to_string();
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    anyhow::bail!("{proto} interface {link} is not the expected running p2p row: {last}")
}

pub async fn ospf_phase(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let age0 = a.count_fresh("ospf lsa installed.*age=0$").await;
    let init_b =
        format!("ospf neighbor state changed to init link=eth0.0 neighbor={OSPF_ROUTER_ID_B}");
    let init0 = a.count_fresh(&init_b).await;

    // RFC 2328 §10.5's Hello packet-validity check (issue #31): a mismatched
    // hello-interval must be dropped before the neighbor even reaches Init,
    // not accepted into the FSM (where a real mismatch would just flap the
    // adjacency at whichever dead interval is shorter).
    let hello_interval = |mut f: Vec<String>, secs: u16| {
        f.extend(strings(&[
            "--ospf-profile-hello-interval",
            &secs.to_string(),
        ]));
        f
    };
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, hello_interval(ospf(OSPF_ROUTER_ID_B), 5)))
        .await?;
    a.wait("dropping ospf hello with mismatched hello-interval")
        .await?;
    // #1211: nos-ospfd keeps CAP_NET_RAW through the sandbox trampoline.
    super::drivers::assert_sandbox(w, "nos-ospfd", 1, Some(CAP_EFF_NET_RAW)).await?;
    log("confirming the mismatched-hello-interval neighbor never reaches init");
    a.assert_quiet(&init_b, init0, 8).await?;

    // Restore explicitly to router-a's own default (10s, `HELLO_INTERVAL_DEFAULT`)
    // rather than just re-provisioning `ospf(...)` with no override — a
    // transaction is built onto the *current* running config, so omitting
    // the flag would leave the mismatched value from above still set.
    log("restoring router-b's matching hello-interval");
    b.provision_flags(&with_base(B, hello_interval(ospf(OSPF_ROUTER_ID_B), 10)))
        .await?;

    // nos-watchdogd really spawned a nos-ospfd for the new OspfInstance, and
    // it resolved its own instance/area/profile over IPC to nos-configd.
    a.wait(&format!(
        "ospf instance config resolved instance={OSPF_INSTANCE}"
    ))
    .await?;
    a.wait(&format!(
        "ospf area resolved instance={OSPF_INSTANCE} area={OSPF_AREA}"
    ))
    .await?;
    a.wait(&format!(
        "ospf profile resolved instance={OSPF_INSTANCE} area={OSPF_AREA} profile={OSPF_PROFILE}"
    ))
    .await?;

    // A real RFC 2328 Hello exchange over a real VRF-scoped raw protocol-89
    // socket, on eth0.0 (already carrying the BGP session's address), reaching
    // 2-Way then — after real DBD/LSR/LSU/LSAck — Full.
    a.wait(&format!(
        "ospf neighbor reached two-way link=eth0.0 neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospf neighbor reached two-way link=eth0.0 neighbor={OSPF_ROUTER_ID}"
    ))
    .await?;
    both_full_p2p(a, b).await?;
    assert_neighbor_fields(
        a,
        "ospf",
        "eth0.0",
        OSPF_ROUTER_ID_B,
        None,
        serde_json::Value::Null,
    )
    .await?;
    assert_interface_row(a, "ospf", "eth0.0").await?;
    // Real LSA content flows and is installed. Not pinned to a link: a
    // router's LSDB is per-area, so which link sees an LSA first is a race.
    a.wait(&format!("ospf lsa installed.*neighbor={OSPF_ROUTER_ID_B}"))
        .await?;
    b.wait(&format!("ospf lsa installed.*neighbor={OSPF_ROUTER_ID}"))
        .await?;
    // RFC 2328 §13.3: every LSA crosses the link with InfTransDelay added to
    // its age, so nothing ever lands at age 0 — not even a just-originated one.
    a.wait_new("ospf lsa installed.*age=[1-9]", 0, 15).await?;
    quiet_settled(a, "ospf lsa installed.*age=0$", age0).await?;

    // The same profile on a broadcast (multi-access) link: each router's own
    // bd-ospf bridge, trunked from eth0 over dot1q. Equal priority, so the
    // higher router-id wins DR and the other becomes Backup.
    a.provision_flags(&with_base(A, ospf_broadcast(OSPF_BROADCAST_ADDRESS_A)))
        .await?;
    b.provision_flags(&with_base(B, ospf_broadcast(OSPF_BROADCAST_ADDRESS_B)))
        .await?;
    let link = format!("link=broadcast-domain:{BD}");
    a.wait(&format!(
        "ospf neighbor reached two-way {link} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospf neighbor reached two-way {link} neighbor={OSPF_ROUTER_ID}"
    ))
    .await?;
    b.wait(&format!(
        "ospf interface became dr {link} dr={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    a.wait(&format!(
        "ospf interface became backup {link} dr={OSPF_ROUTER_ID_B} bdr={OSPF_ROUTER_ID}"
    ))
    .await?;
    a.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID}"
    ))
    .await?;
    let bd = format!("broadcast-domain:{BD}");
    let host = |a: &str| a.split('/').next().unwrap_or(a).to_string();
    assert_neighbor_fields(
        a,
        "ospf",
        &bd,
        OSPF_ROUTER_ID_B,
        Some(&host(OSPF_BROADCAST_ADDRESS_B)),
        "Dr".into(),
    )
    .await?;
    assert_neighbor_fields(
        b,
        "ospf",
        &bd,
        OSPF_ROUTER_ID,
        Some(&host(OSPF_BROADCAST_ADDRESS_A)),
        "Bdr".into(),
    )
    .await
}

/// `Router::provision_flags` wants the *complete* flag list; this prepends the
/// router's own base flags to a scenario's extras.
fn with_base(id: crate::router::Id, extra: Vec<String>) -> Vec<String> {
    let mut f = id.base_flags();
    f.extend(extra);
    f
}

pub async fn asbr_phase(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let originated = a.count("ospf lsa originated.*lsa_type=5");
    let installed = b.count("ospf lsa installed.*lsa_type=5");
    let route_pat = |p: &str| format!("added route prefix={p} .*source=Some(Ospf)");
    let route = b.count(&route_pat(ASBR_PREFIX));
    let route_specific = b.count(&route_pat(ASBR_PREFIX_SPECIFIC));
    // RFC 2328 Appendix E: a second static sharing ASBR_PREFIX's network
    // address gets its own Type-5 at the host-bits link state id.
    let specific_pat =
        format!("ospf lsa originated lsa_type=5 link_state_id={ASBR_PREFIX_SPECIFIC_LSID} ");
    let originated_specific = a.count(&specific_pat);
    a.provision_flags(&with_base(A, specific(asbr(ospf(OSPF_ROUTER_ID)))))
        .await?;

    a.wait_new("ospf lsa originated.*lsa_type=5", originated, 60)
        .await?;
    a.wait_new(&specific_pat, originated_specific, 60).await?;
    b.wait_new("ospf lsa installed.*lsa_type=5", installed, 60)
        .await?;
    // `add_route`'s source is an `Option<RouteSource>`, so it renders "Some(Ospf)".
    b.wait_new(&route_pat(ASBR_PREFIX), route, 60).await?;
    b.wait_new(&route_pat(ASBR_PREFIX_SPECIFIC), route_specific, 60)
        .await?;

    // #216: no metric configured -> metric 20, Type 1. Then `metric 50
    // metric-type 2`: the LSA is re-originated with the E bit, and flipping
    // to type 1 clears it again (the sequence number moves each time).
    let prefix_lsid = ASBR_PREFIX.split('/').next().unwrap_or_default();
    // #1453: the default metric type is 1.
    expect_route(
        b,
        "/v1/ospf/routes",
        ASBR_PREFIX,
        WantRoute {
            class: "external-1",
            adv_router: OSPF_ROUTER_ID,
            hops: 0,
            e2_cost: None,
        },
    )
    .await?;
    let reorig_pat = format!("ospf lsa originated lsa_type=5 link_state_id={prefix_lsid} ");
    wait_external_lsa(b, OSPF_ROUTER_ID, prefix_lsid, 20, false).await?;
    for (metric_type, type2) in [("2", true), ("1", false)] {
        let before = a.count(&reorig_pat);
        let mut flags = with_base(A, specific(asbr(ospf(OSPF_ROUTER_ID))));
        flags.extend(strings(&[
            "--redistribute-metric",
            "50",
            "--redistribute-metric-type",
            metric_type,
        ]));
        a.provision_flags(&flags).await?;
        a.wait_new(&reorig_pat, before, 60).await?;
        wait_external_lsa(b, OSPF_ROUTER_ID, prefix_lsid, 50, type2).await?;
        expect_route(
            b,
            "/v1/ospf/routes",
            ASBR_PREFIX,
            WantRoute {
                class: if type2 { "external-2" } else { "external-1" },
                adv_router: OSPF_ROUTER_ID,
                hops: 0,
                e2_cost: type2.then_some(50),
            },
        )
        .await?;
    }
    // Back to the defaults for the flush checks below.
    a.provision_flags(&with_base(A, specific(asbr(ospf(OSPF_ROUTER_ID)))))
        .await?;
    wait_external_lsa(b, OSPF_ROUTER_ID, prefix_lsid, 20, false).await?;

    // RFC 2328 §14.1: dropping the redistribute rule must flush the Type-5 —
    // prematurely aged on router-a, MaxAge-flushed on router-b and its kernel
    // route removed — in seconds, not after the 3600s MaxAge. The static route
    // itself stays. (nos-ospfd re-filters its redistributed set on its 10s
    // resync, so the bound is that plus one resend period plus the MaxAge hold.)
    let aged = a.count("ospf lsa prematurely aged.*lsa_type=5");
    let flushed_pat =
        format!("ospf lsa maxage flushed.*lsa_type=5.*advertising_router={OSPF_ROUTER_ID}");
    let flushed = b.count(&flushed_pat);
    let removed_pat = |p: &str| format!("removed route prefix={p} ");
    let removed = b.count(&removed_pat(ASBR_PREFIX));
    let removed_specific = b.count(&removed_pat(ASBR_PREFIX_SPECIFIC));
    log("removing the redistribute rule on router-a; its type-5s must be flushed");
    a.provision(&["--clear-redistribute-to-ospf"]).await?;
    a.wait_new("ospf lsa prematurely aged.*lsa_type=5", aged, 30)
        .await?;
    b.wait_new(&flushed_pat, flushed, 30).await?;
    b.wait_new(&removed_pat(ASBR_PREFIX), removed, 30).await?;
    b.wait_new(&removed_pat(ASBR_PREFIX_SPECIFIC), removed_specific, 30)
        .await?;
    // Later phases redistribute rt1's statics again: keep that to ASBR_PREFIX.
    a.provision(&["--remove-static-route", ASBR_PREFIX_SPECIFIC])
        .await?;

    // RFC 2328 §13.5 delayed acknowledgment: router-b acks the Type-5s it
    // installed through the 1 s delayed-ack tick (latency is `ospf-flood`'s).
    b.wait_new("ospf lsack sent.*delayed_ms=", 0, 30).await
}

/// #1517, RFC 2328 §13.3/§13.6: a new LSA is flooded the moment it is
/// installed, not on a sweep, and a settled LSDB is not resent. Router-a
/// attaches a loopback to OSPF; router-b must hold its new Router-LSA within
/// seconds of router-a originating it (the old 5 s sweep made that 0-5 s), and
/// afterwards neither router floods anything for 15 s (no whole-LSDB resend).
pub async fn ospf_flood(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let lsa_a = format!("ospf lsa installed.*advertising_router={OSPF_ROUTER_ID}");
    let originated0 = a.count("ospf lsa originated.*lsa_type=1");
    let installed0 = b.count(&lsa_a);
    a.provision(&[
        "--loopback-address",
        OSPF_FLOOD_LOOPBACK_ADDRESS,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    a.wait_new("ospf lsa originated.*lsa_type=1", originated0, 30)
        .await?;
    b.wait_new(&lsa_a, installed0, 3).await?;
    // Let the relays and acks of this change land, then nothing may flood.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let (fa, fb) = (
        a.count_fresh("ospf lsu flooded").await,
        b.count_fresh("ospf lsu flooded").await,
    );
    a.assert_quiet("ospf lsu flooded", fa, 15).await?;
    b.assert_quiet("ospf lsu flooded", fb, 15).await?;
    // Back to the base lab: the clearing re-originates and floods once.
    let installed1 = b.count(&lsa_a);
    a.provision(&["--clear-ospf-loopback-profile"]).await?;
    b.wait_new(&lsa_a, installed1, 30).await?;
    // The address must go too (#887): `nos-ospfd` advertises only a loopback's
    // first address, so one left behind hides a later phase's loopback
    // address (`ospf-graceful-restart`'s 203.0.113.112/32) from OSPF.
    a.provision(&["--loopback-remove-address", OSPF_FLOOD_LOOPBACK_ADDRESS])
        .await
}

/// Polls `r`'s `GET /v1/ospf/database` until `advertiser`'s live Type-5 for
/// `link_state_id` carries `metric` and the E bit `type2` (60s).
async fn wait_external_lsa(
    r: &Router,
    advertiser: &str,
    link_state_id: &str,
    metric: u32,
    type2: bool,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..60 {
        let body = r
            .rest_expect(Method::GET, "/v1/ospf/database", None, 200)
            .await?;
        let report: serde_json::Value = serde_json::from_str(&body)?;
        let found = report[0]["result"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|l| {
                l["lsa_type"] == 5
                    && l["advertising_router"] == advertiser
                    && l["link_state_id"] == link_state_id
                    && l["age"].as_u64().is_some_and(|a| a < 3600)
                    && l["external_metric"] == metric
                    && l["external_type2"] == type2
            });
        if found {
            return Ok(());
        }
        last = body;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{}: no type-5 {link_state_id} with metric {metric} type2={type2} in its database: {last}",
        r.name()
    )
}

/// Polls `r`'s `GET <path>` (`/v1/ospf/instance` or `/v1/ospfv3/instance`,
/// #1439) until the instance has `router_id`, the given `abr`, `asbr` false, a
/// counted SPF run, and every area in `areas` holds at least one LSA (60s).
/// Returns the instance's summary.
async fn wait_instance(
    r: &Router,
    path: &str,
    router_id: &str,
    abr: bool,
    areas: &[&str],
) -> anyhow::Result<serde_json::Value> {
    let mut last = String::new();
    for _ in 0..60 {
        let body = r.rest_expect(Method::GET, path, None, 200).await?;
        let report: serde_json::Value = serde_json::from_str(&body)?;
        let s = &report[0]["result"];
        let has_area = |id: &str| {
            s["areas"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|a| a["area_id"] == id && a["lsa_count"].as_u64().is_some_and(|n| n >= 1))
        };
        if s["router_id"] == router_id
            && s["abr"] == abr
            && s["asbr"] == false
            && s["spf_runs"].as_u64().is_some_and(|n| n >= 1)
            && s["last_spf_age_secs"].is_u64()
            && areas.iter().all(|id| has_area(id))
        {
            return Ok(s.clone());
        }
        last = body;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{}: {path} never matched abr={abr} {areas:?}: {last}",
        r.name()
    )
}

/// A third router with a lower router-id joins the broadcast segment: the
/// incumbent DR/BDR stay put (RFC 2328 §9.4 stability) and it settles as
/// DrOther, still forming Full adjacencies with the DR and BDR (§8).
pub async fn ospf_dr(w: &mut World) -> anyhow::Result<()> {
    w.start(crate::router::C, None, &[]).await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    c.provision_flags(&with_base(
        crate::router::C,
        ospf_instance_only(OSPF_ROUTER_ID_C),
    ))
    .await?;
    c.provision_flags(&with_base(
        crate::router::C,
        ospf_broadcast(OSPF_BROADCAST_ADDRESS_C),
    ))
    .await?;

    let link = format!("link=broadcast-domain:{BD}");
    c.wait(&format!(
        "ospf neighbor reached two-way {link} neighbor={OSPF_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospf neighbor reached two-way {link} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    c.wait(&format!(
        "ospf interface became dr-other {link} dr={OSPF_ROUTER_ID_B} bdr={OSPF_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    a.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_C}"
    ))
    .await?;
    b.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_C}"
    ))
    .await?;
    // #855: the DR (b) and BDR (a) join 224.0.0.6. The DROther (c) may join
    // transiently (its wait timer can end before it hears a Hello, so it
    // briefly elects itself DR), but must leave once demoted and stay out.
    for r in [a, b] {
        r.wait(&format!(
            "ospf all-drouters membership changed {link} joined=true"
        ))
        .await?;
    }
    c.wait(&format!(
        "ospf all-drouters membership changed {link} joined=false"
    ))
    .await?;
    let joins = c.count("ospf all-drouters membership changed.*joined=true");
    c.assert_quiet(
        "ospf all-drouters membership changed.*joined=true",
        joins,
        10,
    )
    .await?;
    // #879 (RFC 2328 §13.3): on the broadcast bridge the DROther floods to
    // AllDRouters, the DR and BDR to AllSPFRouters.
    c.wait(&format!(
        "ospf lsu flood destination changed {link} dest=all-drouters"
    ))
    .await?;
    for r in [a, b] {
        r.wait(&format!(
            "ospf lsu flood destination changed {link} dest=all-spf-routers"
        ))
        .await?;
    }
    // Data plane: router-c's new Router-LSA has no unicast path to the DR/BDR
    // any more, so its arrival at both proves 224.0.0.6 delivery in the kernel.
    let lsa_c = format!("ospf lsa installed.*advertising_router={OSPF_ROUTER_ID_C}");
    let (a0, b0) = (a.count(&lsa_c), b.count(&lsa_c));
    let mut flags = ospf_instance_only(OSPF_ROUTER_ID_C);
    flags.extend(strings(&[
        "--loopback-address",
        OSPF_DR_LOOPBACK_ADDRESS_C,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ]));
    c.provision_flags(&with_base(crate::router::C, flags))
        .await?;
    a.wait_new(&lsa_c, a0, 60).await?;
    b.wait_new(&lsa_c, b0, 60).await?;
    c.provision(&["--clear-ospf-loopback-profile"]).await?;

    // #139: router-c's eth0.0 subnet is connected in rt1 but not in OSPF, so
    // router-a/b advertise it to c as a stub and c's SPF computes an OSPF
    // route for it. The connected route wins: nos-ribd must leave the prefix
    // to the kernel — no add (which used to fail with EEXIST every 10s
    // reapply), no add-then-remove flap. Over 15s, more than one reapply tick.
    // The baseline is taken once the previous steps' lines have landed (#886).
    let subnet_pat = format!("route prefix={SUBNET}");
    let subnet0 = c.count_fresh(&subnet_pat).await;
    c.assert_quiet(&subnet_pat, subnet0, 15).await?;

    // RFC 2328 §13.4 (#731): router-b, the bridge's DR, restarts under
    // another router-id. router-a/c still hold its old Network-LSA, whose
    // Link State ID is router-b's bridge address: ours under a stale
    // router-id, so the restarted router-b flushes it. Then the id is restored.
    let stale0 = b.count("ospf stale network lsa flushed");
    let base1 = p2p_baseline(a, OSPF_ROUTER_ID_B);
    log("renumbering router-b's router-id; it must flush its previous incarnation's network-lsa");
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B_RENUMBERED)))
        .await?;
    // Running links keep the router-id they were spawned with: restart.
    w.dock.kill_process("router-b", "nos-ospfd").await?;
    b.wait_new("ospf stale network lsa flushed", stale0, 90)
        .await?;
    // #956: on the point-to-point link the renumbered router-b comes from the
    // same address, so router-a evicts the old entry at once (never on the
    // broadcast bridge) and the sweep frees it one dead interval (40s) later.
    p2p_replaced(a, OSPF_ROUTER_ID_B, OSPF_ROUTER_ID_B_RENUMBERED, base1).await?;
    let base2 = p2p_baseline(a, OSPF_ROUTER_ID_B_RENUMBERED);
    let full0 = a.count(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_B}"
    ));
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    w.dock.kill_process("router-b", "nos-ospfd").await?;
    a.wait_new(
        &format!("ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_B}"),
        full0,
        90,
    )
    .await?;
    p2p_replaced(a, OSPF_ROUTER_ID_B_RENUMBERED, OSPF_ROUTER_ID_B, base2).await
}

/// Log counts of `r`'s eviction and removal lines for neighbor `old`.
fn p2p_baseline(r: &crate::router::Router, old: &str) -> (usize, usize) {
    (
        r.count(&format!("ospf neighbor evicted.*neighbor={old} ")),
        r.count(&format!("ospf neighbor entry removed.*neighbor={old}")),
    )
}

/// #956: `r`'s point-to-point neighbor `old` was replaced by `new` from the
/// same address: evicted on the first Hello, entry removed after the dead
/// interval.
async fn p2p_replaced(
    r: &crate::router::Router,
    old: &str,
    new: &str,
    (evicted0, removed0): (usize, usize),
) -> anyhow::Result<()> {
    r.wait_new(
        &format!("ospf neighbor evicted.*neighbor={old} replaced_by={new}"),
        evicted0,
        60,
    )
    .await?;
    r.wait_new(
        &format!("ospf neighbor entry removed.*neighbor={old}"),
        removed0,
        90,
    )
    .await
}

/// OSPF on router-b's loopback (a destination with no neighbor of its own):
/// router-a must compute a route to it via a real SPF over its LSDB and install
/// it into its kernel table — over both of its equal-cost links to router-b
/// (ECMP) — then withdraw it.
pub async fn ospf_spf(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let installed = format!("ospf lsa installed.*advertising_router={OSPF_ROUTER_ID_B}");
    let before = a.count(&installed);
    b.provision(&[
        "--loopback-address",
        OSPF_SPF_LOOPBACK_ADDRESS,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    a.wait_new(
        &format!("ospf lsa installed.*advertising_router={OSPF_ROUTER_ID_B}"),
        before,
        60,
    )
    .await?;
    // RFC 2328 §16.1 2(d) ECMP (#33): router-b is one hop away over both the
    // p2p eth0.0 link and the bd-ospf bridge, both at cost 1, so the route
    // carries both of router-b's addresses as one RTA_MULTIPATH kernel route.
    a.wait(&format!(
        "added route prefix={OSPF_SPF_LOOPBACK_ADDRESS}.*next_hops=2.*source=Some(Ospf)"
    ))
    .await?;
    // #1453: `show ospf route` reports the same route.
    expect_route(
        a,
        "/v1/ospf/routes",
        OSPF_SPF_LOOPBACK_ADDRESS,
        WantRoute {
            class: "intra-area",
            adv_router: OSPF_ROUTER_ID_B,
            hops: 2,
            e2_cost: None,
        },
    )
    .await?;
    // Issue #20: router-a's nos-bgpd polls nos-ribd's IGP costs (BGP decision
    // step d) and must see the OSPF route with its real, non-zero SPF metric.
    a.wait(&format!(
        "igp costs updated.*{OSPF_SPF_LOOPBACK_ADDRESS}: [1-9]"
    ))
    .await?;

    let removed = format!("removed route prefix={OSPF_SPF_LOOPBACK_ADDRESS}");
    let removed0 = a.count(&removed);
    // #1212: the SPF throttle (ospf-common `Timers::default`) stays in
    // `long_wait` (5 s) until `holddown` (10 s) passes without a change, so
    // after the churn above the removal would be delayed 5 s by design, not
    // by the event-driven push. Let it fall back to `quiet` first.
    for _ in 0..6 {
        let spf = a.count_fresh("ospf spf scheduled").await;
        tokio::time::sleep(Duration::from_secs(11)).await;
        if a.count("ospf spf scheduled") == spf {
            break;
        }
    }
    // Time from the first install after this point, not the newest one
    // before the removal.
    let installed0 = a.count_fresh(&installed).await;
    b.provision(&["--clear-ospf-loopback-profile"]).await?;
    a.wait_new(&removed, removed0, 60).await?;
    // #190: the route push is event-driven, so once router-b's new Router-LSA
    // is installed the route leaves the kernel table well inside the old 2s
    // poll (the LSA's own arrival is still bounded by origination/flooding).
    a.assert_delay_under((&installed, installed0), (&removed, removed0), 1000)?;
    // `next-hop-reachability` needs the loopback unreachable from its start.
    a.wait_ospf_route_gone(OSPF_SPF_LOOPBACK_ADDRESS, 15).await
}

/// router-b's RIB must hold the OSPF route to router-a's loopback at every
/// 500 ms sample (strict, #1209). On a loss it first prints a timeline of the
/// daemon events since SIGTERM (`marks` = each router's last log stamp just
/// before it) so the next flake names its cause (#1212).
async fn route_held(
    a: &Router,
    b: &Router,
    c: Option<&Router>,
    marks: (u64, u64, u64),
) -> anyhow::Result<()> {
    let started = tokio::time::Instant::now();
    loop {
        if !b.rt1_has(OSPF_GR_LOOPBACK_ADDRESS, "Ospf").await? {
            // The sample clock (this host's `started`) and the daemons'
            // log stamps are different clocks; only the offsets since SIGTERM
            // within the dump are comparable.
            let lost_after = started.elapsed().as_millis();
            let lo = OSPF_GR_LOOPBACK_ADDRESS;
            let mut entries = b
                .timeline_since(
                    &format!(
                        "removed route prefix={lo}\\|added route prefix={lo}\\|ospf lsa installed.*lsa_type=[12] \\|ospf neighbor\\|ospf spf\\|ospf graceful\\|ospf helper\\|ospf interface became\\|ospf lsa originated\\|ospf restart mode"
                    ),
                    marks.1,
                )
                .await;
            entries.extend(
                a.timeline_since(
                    "ospf lsa originated\\|ospf neighbor\\|ospf graceful\\|ospf helper\\|ospf interface became\\|ospf restart mode\\|ospf lsa installed.*lsa_type=[12] ",
                    marks.0,
                )
                .await,
            );
            if let Some(c) = c {
                entries.extend(
                    c.timeline_since(
                        "ospf lsa originated\\|ospf neighbor\\|ospf helper\\|ospf graceful\\|ospf interface became\\|ospf lsa installed.*lsa_type=[12] ",
                        marks.2,
                    )
                    .await,
                );
            }
            let lines = format_timeline(entries, 120);
            for l in &lines {
                log(l);
            }
            // How long the gap lasts, and router-b's OSPF state during it (#1027).
            let mut gap = Vec::new();
            for _ in 0..12 {
                gap.push(format!(
                    "{}ms:{}",
                    started.elapsed().as_millis(),
                    b.rt1_has(lo, "Ospf").await.unwrap_or(false)
                ));
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            let mut state = Vec::new();
            for route in ["/v1/ospf/neighbors", "/v1/ospf/database"] {
                let body = b.rest_expect(Method::GET, route, None, 200).await;
                state.push(format!(
                    "{route}: {}",
                    body.unwrap_or_else(|e| e.to_string())
                ));
            }
            let state = state.join("\n");
            bail!(
                "router-b lost its ospf route to {lo} during the restart (sample {lost_after}ms after SIGTERM, own clock); route present at {gap:?}; router-b state after:\n{state}\ndaemon timeline ({} lines):\n{}",
                lines.len(),
                lines.join("\n")
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Sorts `(ms since SIGTERM, "<router> <line>")` entries and renders
/// `t+<ms> <line>`, at most `cap` of them.
fn format_timeline(mut entries: Vec<(i64, String)>, cap: usize) -> Vec<String> {
    entries.sort();
    entries
        .into_iter()
        .take(cap)
        .map(|(t, l)| format!("t+{t}ms {l}"))
        .collect()
}

/// RFC 5286 loop-free alternate: with router-c also on the broadcast segment,
/// router-a can reach router-b's loopback via b itself (primary) or via c (c's
/// own shortest path to b doesn't run back through a). `nos-ospfd` must push
/// both and `nos-ribd` install the backup as a second kernel route (higher
/// metric), and remove both again when the loopback leaves OSPF.
pub async fn ospf_lfa(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let prefix = OSPF_SPF_LOOPBACK_ADDRESS;
    let primary = format!("added route prefix={prefix}.*source=Some(Ospf) backup=false");
    let backup = format!("added route prefix={prefix}.*source=Some(Ospf) backup=true");
    let (p0, b0) = (a.count(&primary), a.count(&backup));
    b.provision(&[
        "--loopback-address",
        prefix,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    a.wait_new(&primary, p0, 60).await?;
    a.wait_new(&backup, b0, 60).await?;

    let removed = format!("removed route prefix={prefix}.*backup=true");
    let r0 = a.count(&removed);
    b.provision(&["--clear-ospf-loopback-profile"]).await?;
    a.wait_new(&removed, r0, 60).await
}

/// RFC 6987 stub router on router-c (requires `ospf-lfa`: router-c on the
/// bridge, router-b's loopback addressed but out of OSPF). Router-c is
/// router-a's loop-free alternate to router-b's loopback; while router-c
/// advertises max-metric transit links, RFC 5286 §3.5 forbids it as an
/// alternate, so router-a drops the backup route and keeps the primary.
/// Administrative first, then on-shutdown and on-startup across one restart.
#[allow(clippy::too_many_lines)]
pub async fn ospf_stub_router(w: &mut World) -> anyhow::Result<()> {
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let lo = OSPF_SPF_LOOPBACK_ADDRESS;
    let primary = format!("added route prefix={lo}.*source=Some(Ospf) backup=false");
    let backup_added = format!("added route prefix={lo}.*source=Some(Ospf) backup=true");
    let backup_removed = format!("removed route prefix={lo}.*backup=true");
    let primary_removed = format!("removed route prefix={lo}.*backup=false");
    let c_flags = |extra: &[&str]| {
        let mut flags = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID_C,
        ]);
        flags.extend(strings(extra));
        flags
    };
    let changed = |active: bool, reason: &str| {
        format!("ospf stub router max-metric changed active={active} reason=\"{reason}\"")
    };

    let (p0, b0) = (a.count(&primary), a.count(&backup_added));
    b.provision(&[
        "--loopback-address",
        lo,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    a.wait_new(&primary, p0, 60).await?;
    a.wait_new(&backup_added, b0, 60).await?;
    let primary_removed0 = a.count(&primary_removed);

    log("router-c: max-metric router-lsa administrative; router-a must drop its lfa via c");
    let (r0, on0) = (
        a.count(&backup_removed),
        c.count(&changed(true, "administrative")),
    );
    c.provision(&c_flags(&["--ospf-max-metric-administrative", "true"]))
        .await?;
    c.wait_new(&changed(true, "administrative"), on0, 30)
        .await?;
    a.wait_new(&backup_removed, r0, 60).await?;

    log("router-c: administrative off; router-a must re-add the lfa");
    let (b0, off0) = (a.count(&backup_added), c.count(&changed(false, "cleared")));
    c.provision(&c_flags(&["--ospf-max-metric-administrative", "false"]))
        .await?;
    c.wait_new(&changed(false, "cleared"), off0, 30).await?;
    a.wait_new(&backup_added, b0, 60).await?;

    // On-shutdown + on-startup across one stop. No grace period on router-c,
    // so no graceful-restart marker. On-startup is armed only by a fresh start.
    // 60s: long enough to outlast the respawn and the new adjacency.
    let resolved = "ospf instance config resolved.*max_metric_on_startup=Some(60) max_metric_on_shutdown=Some(3)";
    let (res0, armed0) = (c.count(resolved), c.count(&changed(true, "on-startup")));
    c.provision(&c_flags(&[
        "--ospf-max-metric-on-shutdown",
        "3",
        "--ospf-max-metric-on-startup",
        "60",
    ]))
    .await?;
    c.wait_new(resolved, res0, 30).await?;
    // Clear of MinLSInterval since c's last Router-LSA change, so on-shutdown
    // isn't skipped; and on-startup must not arm on a running process.
    c.assert_quiet(&changed(true, "on-startup"), armed0, 6)
        .await?;

    // A fresh (age below MaxAge) router-c Router-LSA on router-a: the
    // origination tick is gated off after the signal, so only on-shutdown
    // produces one before the flush (the respawned process's own first
    // instance waits for the flushed copy's MaxAge hold to expire).
    // (`logs::bre` has no `\{m,n\}`: one to three digits, never MaxAge 3600.)
    let fresh = ["[0-9]", "[0-9][0-9]", "[0-9][0-9][0-9]"]
        .map(|age| {
            format!(
                "ospf lsa installed.*lsa_type=1 link_state_id={OSPF_ROUTER_ID_C} advertising_router={OSPF_ROUTER_ID_C} age={age}$"
            )
        })
        .join("\\|");
    let full_c = format!(
        "ospf neighbor reached full link=broadcast-domain:{BD} neighbor={OSPF_ROUTER_ID_C}"
    );
    let (fresh0, sd0, flush0, r0, st0, full0, exp0) = (
        a.count(&fresh),
        c.count(&changed(true, "on-shutdown")),
        c.count("ospf flushing self-originated lsas before shutdown"),
        a.count(&backup_removed),
        c.count(&changed(true, "on-startup")),
        a.count(&full_c),
        c.count(&changed(false, "expired")),
    );
    log("sending SIGINT to router-c's nos-ospfd; it must advertise max-metric before flushing");
    w.dock
        .signal_process("router-c", "nos-ospfd", "-INT")
        .await?;
    c.wait_new(&changed(true, "on-shutdown"), sd0, 30).await?;
    a.wait_new(&fresh, fresh0, 10).await?;
    a.wait_new(&backup_removed, r0, 30).await?;
    c.wait_new(
        "ospf flushing self-originated lsas before shutdown",
        flush0,
        30,
    )
    .await?;

    log("router-c respawns with on-startup max-metric: back in the lsdb, not an lfa");
    c.wait_new(&changed(true, "on-startup"), st0, 90).await?;
    a.wait_new(&full_c, full0, 90).await?;
    let b0 = a.count(&backup_added);
    a.assert_quiet(&backup_added, b0, 10).await?;
    // Still inside the period: the quiet window above proved something.
    c.assert_quiet(&changed(false, "expired"), exp0, 0).await?;
    c.wait_new(&changed(false, "expired"), exp0, 90).await?;
    a.wait_new(&backup_added, b0, 60).await?;
    a.assert_quiet(&primary_removed, primary_removed0, 0)
        .await?;

    log("restoring: router-c's max-metric off, router-b's loopback out of ospf");
    c.provision(&c_flags(&[
        "--ospf-max-metric-on-shutdown",
        "0",
        "--ospf-max-metric-on-startup",
        "0",
    ]))
    .await?;
    b.provision(&["--clear-ospf-loopback-profile"]).await?;
    a.wait_ospf_route_gone(lo, 15).await
}

/// RFC 8770 host router on router-c (requires `ospf-lfa`, like
/// `ospf-stub-router`). All three routers are nos, so all advertise host-router
/// support in their RI LSA and router-a/router-b honour router-c's H-bit:
/// router-c is no longer transit, nor router-a's loop-free alternate to
/// router-b's loopback. Cleared again, the alternate comes back.
pub async fn ospf_host_router(w: &mut World) -> anyhow::Result<()> {
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let lo = OSPF_SPF_LOOPBACK_ADDRESS;
    let primary = format!("added route prefix={lo}.*source=Some(Ospf) backup=false");
    let backup_added = format!("added route prefix={lo}.*source=Some(Ospf) backup=true");
    let backup_removed = format!("removed route prefix={lo}.*backup=true");
    let primary_removed = format!("removed route prefix={lo}.*backup=false");
    let state = |hosts: u8| {
        format!("ospf host-bit state changed area={OSPF_AREA} honoured=true host_routers={hosts}")
    };
    let host_router = |on: bool| {
        strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID_C,
            "--ospf-host-router",
            &on.to_string(),
        ])
    };

    let (p0, b0) = (a.count(&primary), a.count(&backup_added));
    b.provision(&[
        "--loopback-address",
        lo,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    a.wait_new(&primary, p0, 60).await?;
    a.wait_new(&backup_added, b0, 60).await?;
    let pr0 = a.count(&primary_removed);

    log("router-c: host-router; router-a and router-b must honour its h-bit, router-a drop its lfa via c");
    let (r0, sa0, sb0) = (
        a.count(&backup_removed),
        a.count(&state(1)),
        b.count(&state(1)),
    );
    c.provision(&host_router(true)).await?;
    c.wait("ospf instance config resolved.*host_router=true")
        .await?;
    a.wait_new(&state(1), sa0, 30).await?;
    b.wait_new(&state(1), sb0, 30).await?;
    a.wait_new(&backup_removed, r0, 60).await?;

    log("router-c: host-router off; router-a must re-add the lfa");
    let (b0, sa0) = (a.count(&backup_added), a.count(&state(0)));
    c.provision(&host_router(false)).await?;
    a.wait_new(&state(0), sa0, 30).await?;
    a.wait_new(&backup_added, b0, 60).await?;
    a.assert_quiet(&primary_removed, pr0, 0).await?;

    b.provision(&["--clear-ospf-loopback-profile"]).await?;
    a.wait_ospf_route_gone(lo, 15).await
}

/// Waits up to `secs` until `r`'s rt1 does (`want`) or doesn't list an OSPF
/// candidate for `SUBNET`.
async fn subnet_ospf_candidate(r: &Router, want: bool, secs: u32) -> anyhow::Result<()> {
    for _ in 0..secs {
        if r.rt1_has(SUBNET.s(), "Ospf").await? == want {
            log(format!(
                "{}: ospf candidate for {SUBNET} present={want}",
                r.name()
            ));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{}: ospf candidate for {SUBNET} never became present={want}",
        r.name()
    )
}

/// RFC 3630 traffic engineering LSAs (requires `ospf-lfa`, which leaves
/// router-a and router-b in OSPF): with `traffic-engineering` on both, each
/// installs the other's Router Address LSA (opaque type 1, area scope) and
/// logs the address it carries; turning it off again leaves the session up.
pub async fn ospf_te(w: &mut World) -> anyhow::Result<()> {
    let te = |rid: &str, on: bool| {
        strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            rid,
            "--ospf-traffic-engineering",
            &on.to_string(),
        ])
    };
    let seen = |rid: &str| {
        format!("ospf te router address received area={OSPF_AREA} router={rid} address={rid}")
    };
    // #1369: the Link LSA bandwidth is the advertiser's eth0 speed in bytes/s
    // (0 when sysfs says unknown), read from the container so a veth reporting
    // 10000 and one reporting nothing both pass. tracing prints the f32 as f64.
    let mut want_bw = Vec::new();
    for (name, rid) in [("router-a", OSPF_ROUTER_ID), ("router-b", OSPF_ROUTER_ID_B)] {
        let (_, raw) = w
            .dock
            .exec(name, &["cat", "/sys/class/net/eth0/speed"])
            .await?;
        let mbps = raw.trim().parse::<u32>().ok().filter(|&v| v > 0);
        #[allow(
            clippy::cast_precision_loss,
            reason = "mirrors nos-ospfd's f32 wire value"
        )]
        let bw = mbps.map_or(0.0, |m| f64::from(m as f32 * 125_000.0));
        log(format!(
            "{name}: eth0 speed reads {raw:?}, expect bandwidth {bw:?}"
        ));
        want_bw.push(format!(
            "ospf te link received area={OSPF_AREA} router={rid} local=.* max_bandwidth={bw:?} max_reservable={bw:?}$"
        ));
    }
    let (a, b) = (w.a()?, w.b()?);
    let (a0, b0) = (
        a.count(&seen(OSPF_ROUTER_ID_B)),
        b.count(&seen(OSPF_ROUTER_ID)),
    );
    let (al0, bl0) = (a.count(&want_bw[1]), b.count(&want_bw[0]));
    log("enabling traffic-engineering on router-a and router-b");
    a.provision(&te(OSPF_ROUTER_ID, true)).await?;
    b.provision(&te(OSPF_ROUTER_ID_B, true)).await?;
    a.wait_new(&seen(OSPF_ROUTER_ID_B), a0, 60).await?;
    b.wait_new(&seen(OSPF_ROUTER_ID), b0, 60).await?;
    a.wait_new(&want_bw[1], al0, 60).await?;
    b.wait_new(&want_bw[0], bl0, 60).await?;

    log("restoring: traffic-engineering off");
    a.provision(&te(OSPF_ROUTER_ID, false)).await?;
    b.provision(&te(OSPF_ROUTER_ID_B, false)).await?;
    both_full_p2p(a, b).await
}

/// RFC 6860 prefix suppression (requires `ospf-lfa`: router-c on the bridge,
/// router-b's loopback addressed but out of OSPF). Router-c's eth0 is on
/// `SUBNET` too, so the connected route always wins its kernel table (#139):
/// the check reads nos-ribd's OSPF *candidate* for router-a/b's p2p subnet.
pub async fn ospf_prefix_suppression(w: &mut World) -> anyhow::Result<()> {
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let candidate = subnet_ospf_candidate;
    let suppression = |rid: &str, on: bool| {
        strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            rid,
            "--ospf-prefix-suppression",
            &on.to_string(),
        ])
    };

    // Baseline: router-c learns the p2p subnet from a/b's type-3 stubs.
    candidate(c, true, 30).await?;

    let network_lsa = format!(
        "ospf lsa originated lsa_type=2 link_state_id={} advertising_router={OSPF_ROUTER_ID_B} refreshed=false",
        OSPF_BROADCAST_ADDRESS_B.split('/').next().unwrap_or_default()
    );
    let n0 = b.count(&network_lsa);
    let resolved = "ospf instance config resolved.*prefix_suppression=true";
    let (ra0, rb0) = (a.count(resolved), b.count(resolved));
    log("enabling rfc 6860 prefix suppression on router-a and router-b");
    a.provision(&suppression(OSPF_ROUTER_ID, true)).await?;
    b.provision(&suppression(OSPF_ROUTER_ID_B, true)).await?;
    a.wait_new(resolved, ra0, 30).await?;
    b.wait_new(resolved, rb0, 30).await?;
    // Router-b is DR on the bridge: its Network-LSA is re-originated, /32 mask.
    b.wait_new(&network_lsa, n0, 30).await?;
    // §2.1: the type-3 stub for eth0.0's subnet is gone from both Router-LSAs.
    c.wait_ospf_route_gone(SUBNET.s(), 15).await?;

    // Transit is untouched: router-b's loopback (a stub, never hidden) is
    // reached by router-a over both links — one of them across the bridge's
    // network vertex, whose Network-LSA now has a /32 mask — and by router-c
    // only across it.
    let lo = OSPF_SPF_LOOPBACK_ADDRESS;
    let ecmp = format!("added route prefix={lo}.*next_hops=2.*source=Some(Ospf)");
    let on_c = format!("added route prefix={lo}.*source=Some(Ospf)");
    let (e0, c0) = (a.count(&ecmp), c.count(&on_c));
    b.provision(&[
        "--loopback-address",
        lo,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    a.wait_new(&ecmp, e0, 60).await?;
    c.wait_new(&on_c, c0, 60).await?;
    // Still hidden after the topology change.
    candidate(c, false, 1).await?;

    log("restoring: loopback out of ospf, prefix suppression off");
    b.provision(&["--clear-ospf-loopback-profile"]).await?;
    a.wait_ospf_route_gone(lo, 15).await?;
    a.provision(&suppression(OSPF_ROUTER_ID, false)).await?;
    b.provision(&suppression(OSPF_ROUTER_ID_B, false)).await?;
    candidate(c, true, 60).await
}

/// Router-b's loopback moves into a second area, making it a real ABR: it must
/// originate a Type-3 summary-LSA, and router-a (backbone only) must install a
/// kernel route to a prefix that is not in its own area.
pub async fn abr(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let originated = b.count("ospf lsa originated.*lsa_type=3");
    let installed = a.count("ospf lsa installed.*lsa_type=3");
    b.provision(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        OSPF_ROUTER_ID_B,
        "--ospf-area",
        OSPF_AREA_1,
        "--ospf-profile",
        OSPF_PROFILE_AREA1,
        "--loopback-remove-address",
        OSPF_SPF_LOOPBACK_ADDRESS,
        "--loopback-address",
        OSPF_ABR_LOOPBACK_ADDRESS,
        "--ospf-loopback-profile",
        OSPF_PROFILE_AREA1,
    ])
    .await?;
    b.wait_new("ospf lsa originated.*lsa_type=3", originated, 60)
        .await?;
    a.wait_new("ospf lsa installed.*lsa_type=3", installed, 60)
        .await?;
    // A fresh prefix no earlier phase installed, so a baseline of 0 is right.
    a.wait(&format!(
        "added route prefix={OSPF_ABR_LOOPBACK_ADDRESS}.*source=Some(Ospf)"
    ))
    .await?;

    // #1453: the area-1 loopback is an inter-area route via the ABR.
    expect_route(
        a,
        "/v1/ospf/routes",
        OSPF_ABR_LOOPBACK_ADDRESS,
        WantRoute {
            class: "inter-area",
            adv_router: OSPF_ROUTER_ID_B,
            hops: 0,
            e2_cost: None,
        },
    )
    .await?;

    // RFC 3509 §2.1 (Cisco, #1170): the backbone counts only with a Full
    // adjacency. A mismatched hello-interval on router-b kills it (dead
    // interval), so router-b stops being an ABR and flushes its summary;
    // restoring it brings both back.
    let abr_up = "ospf abr backbone attachment changed abr=true";
    let abr_down = "ospf abr backbone attachment changed abr=false";
    b.wait(abr_up).await?;
    // `show ospf` (#1439): an ABR over area 0 and area 1, SPF counted.
    wait_instance(
        b,
        "/v1/ospf/instance",
        OSPF_ROUTER_ID_B,
        true,
        &[OSPF_AREA, OSPF_AREA_1],
    )
    .await?;
    let (down0, up0) = (b.count(abr_down), b.count(abr_up));
    let flushed3 = b.count("ospf lsa prematurely aged.*lsa_type=3");
    let originated3 = b.count("ospf lsa originated.*lsa_type=3");
    let mut broken = ospf_instance_only(OSPF_ROUTER_ID_B);
    broken.extend(strings(&["--ospf-profile-hello-interval", "5"]));
    log("breaking the backbone adjacency on router-b: no longer an ABR");
    b.provision_flags(&with_base(B, broken)).await?;
    b.wait_new(abr_down, down0, 90).await?;
    // RFC 3509: the derived role follows the lost backbone adjacency.
    wait_instance(b, "/v1/ospf/instance", OSPF_ROUTER_ID_B, false, &[]).await?;
    b.wait_new("ospf lsa prematurely aged.*lsa_type=3", flushed3, 30)
        .await?;
    log("restoring the backbone adjacency: an ABR again");
    let mut fixed = ospf_instance_only(OSPF_ROUTER_ID_B);
    fixed.extend(strings(&["--ospf-profile-hello-interval", "10"]));
    b.provision_flags(&with_base(B, fixed)).await?;
    b.wait_new(abr_up, up0, 90).await?;
    b.wait_new("ospf lsa originated.*lsa_type=3", originated3, 30)
        .await?;

    // RFC 2328 §14.1: the loopback leaving area 1 (router-b's only presence
    // there) must flush the Type-3 — prematurely aged on router-b, MaxAge-
    // flushed on router-a and its kernel route removed — within seconds.
    let aged = b.count("ospf lsa prematurely aged.*lsa_type=3");
    let flushed = a.count("ospf lsa maxage flushed.*lsa_type=3");
    log("removing router-b's area-1 loopback; its type-3 summary must be flushed");
    b.provision(&[
        "--loopback-remove-address",
        OSPF_ABR_LOOPBACK_ADDRESS,
        "--clear-ospf-loopback-profile",
    ])
    .await?;
    b.wait_new("ospf lsa prematurely aged.*lsa_type=3", aged, 30)
        .await?;
    a.wait_new("ospf lsa maxage flushed.*lsa_type=3", flushed, 30)
        .await?;
    a.wait(&format!("removed route prefix={OSPF_ABR_LOOPBACK_ADDRESS}"))
        .await
}

/// RFC 5709 HMAC-SHA-256: matching keys reach/stay Full with real per-packet
/// digest checks; a mismatched key on router-a logs a real verification failure
/// on router-b and blocks a new Full; restoring it lets Full form again.
/// Restores no authentication and ext-seq off at the end.
pub async fn ospf_auth(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let key = |k: &str| {
        [
            "--ospf-crypto-key".to_string(),
            format!("1:hmac-sha256:{k}"),
        ]
    };
    let with_key = |k: &str, rid: &str| {
        let mut f = ospf(rid);
        f.extend(key(k));
        f
    };
    a.provision_flags(&with_base(A, with_key("topsecretkey", OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, with_key("topsecretkey", OSPF_ROUTER_ID_B)))
        .await?;
    both_full_p2p(a, b).await?;

    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    log("reconfiguring router-a with a mismatched crypto key");
    a.provision_flags(&with_base(A, with_key("wrong-key", OSPF_ROUTER_ID)))
        .await?;
    b.wait_new("ospf packet authentication failed link=eth0.0", 0, 30)
        .await?;
    log("waiting 8s to confirm no new ospf full adjacency forms with mismatched crypto keys");
    a.assert_quiet(&full_p2p(OSPF_ROUTER_ID_B), before, 8)
        .await?;

    log("restoring the matching crypto key on router-a");
    a.provision_flags(&with_base(A, with_key("topsecretkey", OSPF_ROUTER_ID)))
        .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 60).await?;

    log("the secrets live in the admin keystore only: not in the config view, not in any log (#509)");
    for r in [a, b] {
        no_leak(r, &["topsecretkey", "wrong-key"]).await?;
    }

    log("rotating the secret under the same admin label on both routers re-forms Full");
    let rotated = "rotated-ospf-secret";
    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    a.provision_flags(&with_base(A, with_key(rotated, OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, with_key(rotated, OSPF_ROUTER_ID_B)))
        .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 60).await?;
    for r in [a, b] {
        no_leak(r, &[rotated]).await?;
    }

    log("rotating back to the original secret on both routers");
    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    a.provision_flags(&with_base(A, with_key("topsecretkey", OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, with_key("topsecretkey", OSPF_ROUTER_ID_B)))
        .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 60).await?;

    // RFC 7474: AuType 3 with a persisted boot count. Both ends enabled reach
    // Full again; one end alone is an auth-type mismatch and blocks it.
    let ext = |k: &str, rid: &str, on: bool| {
        let mut f = with_key(k, rid);
        f.extend(["--ospf-extended-seq".to_string(), on.to_string()]);
        f
    };
    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    log("enabling rfc 7474 extended sequence numbers on router-a only");
    let auth_failures = b.count("ospf packet authentication failed link=eth0.0");
    a.provision_flags(&with_base(A, ext("topsecretkey", OSPF_ROUTER_ID, true)))
        .await?;
    b.wait_new(
        "ospf packet authentication failed link=eth0.0",
        auth_failures,
        30,
    )
    .await?;
    a.assert_quiet(&full_p2p(OSPF_ROUTER_ID_B), before, 8)
        .await?;

    log("enabling rfc 7474 extended sequence numbers on router-b too");
    b.provision_flags(&with_base(B, ext("topsecretkey", OSPF_ROUTER_ID_B, true)))
        .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 60).await?;
    a.wait("ospf link using rfc 7474 extended sequence numbers")
        .await?;

    // Restart router-b's nos-ospfd: a fresh process must take a higher boot
    // count from the persisted file, so router-a's replay check accepts it.
    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    let boots = b.count("ospf link using rfc 7474 extended sequence numbers");
    let replays = a.count("crypto sequence number not increasing");
    // RFC 2328 §13.4 (#731): the restarted router-b learns its own previous
    // Router-LSA back from router-a with a newer sequence number and must
    // re-originate above it.
    let reflected = b.count("ospf self-originated lsa received with newer sequence");
    log("killing router-b's nos-ospfd; it must return to Full without replay drops");
    w.dock.kill_process("router-b", "nos-ospfd").await?;
    b.wait_new(
        "ospf link using rfc 7474 extended sequence numbers",
        boots,
        60,
    )
    .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 90).await?;
    b.wait_new(
        "ospf self-originated lsa received with newer sequence",
        reflected,
        30,
    )
    .await?;
    b.wait(&format!(
        "ospf lsa originated.*advertising_router={OSPF_ROUTER_ID_B}.*reflected=true"
    ))
    .await?;
    a.assert_quiet("crypto sequence number not increasing", replays, 5)
        .await?;

    // Restore: leaked auth/ext-seq broke the phases after this one (#1292).
    log("restoring no authentication and extended sequence numbers off on both routers");
    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    for r in [a, b] {
        r.edit(|c| {
            for p in c
                .ospf_instances
                .iter_mut()
                .flat_map(|i| i.areas.iter_mut())
                .flat_map(|ar| ar.profiles.iter_mut())
            {
                p.auth = None;
                p.extended_sequence_numbers = false;
            }
            Ok(())
        })
        .await?;
    }
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 90).await?;
    both_full_p2p(a, b).await
}

/// RFC 5613 Link-Local Signaling (requires `ospf`, runs before `ospf-auth` so
/// the profile starts without authentication): `lls` on both routers exchanges
/// the EOF TLV under Null, Simple and classic Crypto auth (a bad CA-TLV would
/// log no "received" line); one side off is ignored by the peer and records
/// nothing; under RFC 7474 it is ignored with a warning and the adjacency
/// still forms. Restores `lls` off and no authentication at the end.
pub async fn ospf_lls(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let got = |peer: &str| format!("ospf lls received link=eth0.0 neighbor={peer} eof=1");
    let (from_b, from_a) = (got(OSPF_ROUTER_ID_B), got(OSPF_ROUTER_ID));
    let flags = |rid: &str, lls: bool, extra: &[&str]| {
        let mut f = ospf(rid);
        f.extend(strings(&["--ospf-lls", &lls.to_string()]));
        f.extend(strings(extra));
        f
    };
    // Reprovisions both ends (a link restart each) and waits for Full again.
    let apply = |a_lls: bool, b_lls: bool, extra: Vec<&'static str>| {
        let (fa, fb) = (
            flags(OSPF_ROUTER_ID, a_lls, &extra),
            flags(OSPF_ROUTER_ID_B, b_lls, &extra),
        );
        async move {
            let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
            a.provision_flags(&with_base(A, fa)).await?;
            b.provision_flags(&with_base(B, fb)).await?;
            a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 90).await
        }
    };

    let crypto = vec!["--ospf-crypto-key", "1:hmac-sha256:lls-secret"];
    for (label, extra) in [
        ("null", vec![]),
        ("simple", vec!["--ospf-simple-password", "lls-pw"]),
        ("crypto", crypto.clone()),
    ] {
        log(format!("lls on both routers, {label} authentication"));
        let (ca, cb) = (a.count(&from_b), b.count(&from_a));
        apply(true, true, extra.clone()).await?;
        a.wait_new(&from_b, ca, 90).await?;
        b.wait_new(&from_a, cb, 90).await?;

        log(format!("lls on router-a only, {label} authentication"));
        let (ca, cb) = (a.count("ospf lls received"), b.count("ospf lls received"));
        apply(true, false, extra.clone()).await?;
        a.assert_quiet("ospf lls received", ca, 15).await?;
        b.assert_quiet("ospf lls received", cb, 15).await?;
    }

    log("lls with rfc 7474 extended sequence numbers: ignored with a warning");
    let (ca, cb) = (a.count("ospf lls received"), b.count("ospf lls received"));
    let mut ext = crypto;
    ext.extend(["--ospf-extended-seq", "true"]);
    apply(true, true, ext).await?;
    a.wait("ospf lls enabled but ignored with rfc 7474").await?;
    b.wait("ospf lls enabled but ignored with rfc 7474").await?;
    a.assert_quiet("ospf lls received", ca, 15).await?;
    b.assert_quiet("ospf lls received", cb, 15).await?;

    log("restoring lls off and no authentication on both routers");
    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    for r in [a, b] {
        r.edit(|c| {
            for p in c
                .ospf_instances
                .iter_mut()
                .flat_map(|i| i.areas.iter_mut())
                .flat_map(|ar| ar.profiles.iter_mut())
            {
                p.lls = false;
                p.auth = None;
                p.extended_sequence_numbers = false;
            }
            Ok(())
        })
        .await?;
    }
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 90).await?;
    both_full_p2p(a, b).await
}

/// RFC 2328 §10.6 Interface MTU check (requires `ospf`, runs after
/// `ospf-auth`): an OSPF MTU of 1400 on router-a alone makes it reject
/// router-b's 1500-byte DBDs and stay out of Full; `mtu-ignore` lets the
/// adjacency form anyway; clearing both restores the defaults.
pub async fn ospf_mtu_mismatch(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let reject = "ospf dbd rejected.*local_mtu=1400 neighbor_mtu=1500";
    let with = |extra: &[&str]| {
        let mut f = ospf(OSPF_ROUTER_ID);
        f.extend(strings(extra));
        with_base(A, f)
    };
    let (before, rejects) = (a.count(&full_p2p(OSPF_ROUTER_ID_B)), a.count(reject));
    log("setting mtu 1400 on router-a's profile only");
    a.provision_flags(&with(&["--ospf-profile-mtu", "1400"]))
        .await?;
    a.wait_new(reject, rejects, 60).await?;
    log("waiting 30s to confirm no new ospf full adjacency forms with a larger neighbor mtu");
    a.assert_quiet(&full_p2p(OSPF_ROUTER_ID_B), before, 30)
        .await?;

    log("setting mtu-ignore on router-a");
    a.provision_flags(&with(&["--ospf-mtu-ignore", "true"]))
        .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 60).await?;

    log("clearing the mtu override and mtu-ignore");
    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    a.edit(|c| {
        let (instance, area_id, name) = (
            OSPF_INSTANCE.to_string(),
            OSPF_AREA.parse()?,
            OSPF_PROFILE.to_string(),
        );
        nos_proto::OspfProfileOp::SetMtuIgnore {
            instance: instance.clone(),
            area_id,
            name: name.clone(),
            enabled: false,
        }
        .apply(c)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        nos_proto::OspfProfileOp::ClearMtu {
            instance,
            area_id,
            name,
        }
        .apply(c)
        .map_err(|e| anyhow::anyhow!("{e}"))
    })
    .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 60).await?;
    ospf_bridge_mtu(w).await
}

/// RFC 3623 graceful restart (requires `ospf`, runs after `ospf-auth`):
/// router-a, with a grace period configured and its loopback in OSPF, is
/// restarted with SIGTERM. It must send a Grace-LSA and keep its LSAs instead
/// of flushing them, and router-b must help: hold the eth0.0 adjacency and
/// keep router-a's loopback route installed through the whole restart, then
/// resynchronize with the respawned process. With RFC 6987 on-shutdown and
/// on-startup also configured, neither may change the Router-LSA across the
/// restart (RFC 3623 §3.2 (c)): on-shutdown is skipped under the grace period,
/// and the respawned process skips on-startup through the marker file.
#[allow(clippy::too_many_lines)]
pub async fn ospf_graceful_restart(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    both_full_p2p(a, b).await?;
    let instance = |extra: &[&str]| {
        let mut f = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID,
        ]);
        f.extend(strings(extra));
        f
    };
    a.provision_flags(&with_base(
        A,
        instance(&[
            "--ospf-graceful-restart-grace-period",
            "120",
            "--ospf-max-metric-on-startup",
            "30",
            "--ospf-max-metric-on-shutdown",
            "3",
            "--loopback-address",
            OSPF_GR_LOOPBACK_ADDRESS,
            "--ospf-loopback-profile",
            OSPF_PROFILE,
        ]),
    ))
    .await?;
    a.wait("ospf instance config resolved.*graceful_restart_grace_period=Some(120).*max_metric_on_startup=Some(30) max_metric_on_shutdown=Some(3)")
        .await?;
    b.wait(&format!(
        "added route prefix={OSPF_GR_LOOPBACK_ADDRESS}.*source=Some(Ospf)"
    ))
    .await?;

    // router-b helps for at most 60s, whatever router-a's Grace-LSA asks
    // for (a link-config change: the adjacency re-forms first).
    let helper_cap = |extra: &[&str]| {
        let mut f = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID_B,
        ]);
        f.extend(strings(extra));
        with_base(B, f)
    };
    let peer_route0 = a.count(&format!(
        "added route prefix={OSPF_GR_PEER_LOOPBACK_ADDRESS}.*source=Some(Ospf)"
    ));
    let full_again0 = b.count(&full_p2p(OSPF_ROUTER_ID));
    let full_again_a0 = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    let cap60 = "ospf instance config resolved.*graceful_restart_helper_max_grace_period=Some(60)";
    let cap60_0 = b.count_fresh(cap60).await;
    b.provision_flags(&helper_cap(&[
        "--ospf-graceful-restart-helper-max-grace-period",
        "60",
        "--loopback-address",
        OSPF_GR_PEER_LOOPBACK_ADDRESS,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ]))
    .await?;
    b.wait_new(cap60, cap60_0, 60).await?;
    // router-a holds an OSPF route to router-b's loopback before it restarts.
    a.wait_new(
        &format!("added route prefix={OSPF_GR_PEER_LOOPBACK_ADDRESS}.*source=Some(Ospf)"),
        peer_route0,
        60,
    )
    .await?;
    b.wait_new(&full_p2p(OSPF_ROUTER_ID), full_again0, 60)
        .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), full_again_a0, 60)
        .await?;
    // The restarted link's SPF run puts the route back a tick later.
    for _ in 0..60 {
        if b.rt1_has(OSPF_GR_LOOPBACK_ADDRESS, "Ospf").await? {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Let this phase's own provisioning finish flooding before the restart (#1027).
    let mut settle: Vec<&Router> = vec![a, b];
    settle.extend(w.c().ok());
    topology_settled(&settle).await?;

    // Scoped to the restarter on the p2p link: the bridge adjacency may log down on its own (#886).
    let torn = format!(
        "ospf neighbor adjacency torn down, back to init link=eth0.0 neighbor={OSPF_ROUTER_ID}\\|ospf neighbor state changed to down link=eth0.0 neighbor={OSPF_ROUTER_ID}"
    );
    let torn = torn.as_str();
    let flushed = format!("ospf lsa maxage flushed.*advertising_router={OSPF_ROUTER_ID}$");
    let flush_on_a = "ospf flushing self-originated lsas before shutdown";
    let (full_on_b, full_on_a) = (full_p2p(OSPF_ROUTER_ID), full_p2p(OSPF_ROUTER_ID_B));
    let (torn0, flushed0, flush_a0, full_b0, full_a0) = (
        b.count_fresh(torn).await,
        b.count_fresh(&flushed).await,
        a.count(flush_on_a),
        b.count(&full_on_b),
        a.count(&full_on_a),
    );
    let max_metric_on = "ospf stub router max-metric changed active=true";
    let marker = "ospf graceful restart marker written";
    let skipped = "ospf stub router on-startup skipped after graceful restart";
    let (mm0, marker0, skipped0) = (a.count(max_metric_on), a.count(marker), a.count(skipped));
    // RFC 3623 §2 restarting router (#1145): the respawn enters restart mode,
    // pushes no routes until its neighbor is Full again, so router-a's own
    // kernel route to router-b's loopback is never removed (#1027-safe: the
    // removal is logged by `nos-ribd` on router-a itself).
    let restart_in = "ospf restart mode: entered neighbors=[12]";
    let restart_out = "ospf restart mode: exited reason=complete";
    let grace_flush =
        format!("ospf graceful restart: grace-lsa flushed link=eth0.0 neighbor={OSPF_ROUTER_ID_B}");
    let removed = format!("removed route prefix={OSPF_GR_PEER_LOOPBACK_ADDRESS}");
    let (in0, out0, flush0, removed0) = (
        a.count(restart_in),
        a.count(restart_out),
        a.count(&grace_flush),
        a.count(&removed),
    );
    let router_c = w.c().ok();
    let marks = (
        a.log_mark(),
        b.log_mark(),
        router_c.map_or(0, Router::log_mark),
    );
    log("sending SIGTERM to router-a's nos-ospfd; it must announce a grace period first");
    w.dock
        .signal_process("router-a", "nos-ospfd", "-TERM")
        .await?;
    let restart = async {
        a.wait("ospf graceful restart: announcing grace period before shutdown grace_period=120")
            .await?;
        a.wait(&format!(
            "ospf graceful restart: grace-lsa sent link=eth0.0 neighbor={OSPF_ROUTER_ID_B} grace_period=120"
        ))
        .await?;
        b.wait(&format!(
            "ospf helper: grace period entered link=eth0.0 neighbor={OSPF_ROUTER_ID} grace_period=120 restart_reason=1 effective_grace=60"
        ))
        .await?;
        a.wait_new(marker, marker0, 30).await?;
        a.wait_new(skipped, skipped0, 90).await?;
        // The watchdog respawns router-a; the fresh process resynchronizes
        // with the neighbor that held it Full the whole time.
        b.wait_new(&full_on_b, full_b0, 90).await?;
        a.wait_new(&full_on_a, full_a0, 90).await?;
        a.wait_new(restart_in, in0, 90).await?;
        a.wait_new(restart_out, out0, 90).await?;
        a.wait_new(&grace_flush, flush0, 30).await?;
        // Reaching Full ended the grace period. A topology change now (router-b's
        // own Router-LSA gains a stub link) must find no grace to exit; the exit
        // itself (RFC 3623 §3.2 (c)) is a unit test in `link/tests/grace.rs`, as
        // provoking it mid-restart races router-a's return (#1213).
        let topology = format!(
            "ospf helper: topology change, exiting grace link=eth0.0 neighbor={OSPF_ROUTER_ID}"
        );
        let topology0 = b.count(&topology);
        b.provision_flags(&helper_cap(&[
            "--loopback-address",
            OSPF_GR_TOPOLOGY_LOOPBACK_ADDRESS,
            "--ospf-loopback-profile",
            OSPF_PROFILE,
        ]))
        .await?;
        b.assert_quiet(&topology, topology0, 5).await?;
        tokio::time::sleep(Duration::from_secs(5)).await;
        anyhow::Ok(())
    };
    // router-b's RIB must hold the OSPF route at every sample of the restart.
    // (Its next hops may still change — the bridge adjacency, not covered by
    // this phase, can come up meanwhile — which the kernel driver logs as a
    // remove + add, so the kernel log alone can't tell a drop from that.)
    let route_held = route_held(a, b, router_c, marks);
    tokio::select! {
        r = restart => r?,
        r = route_held => r?,
    }
    log("router-b held its ospf route to router-a's loopback through the restart");
    // RFC 3623 §2: the restarter keeps its LSAs; the helper never tears the
    // adjacency down and never flushes them.
    quiet_settled(a, flush_on_a, flush_a0).await?;
    quiet_settled(a, &removed, removed0).await?;
    quiet_settled(b, torn, torn0).await?;
    quiet_settled(b, &flushed, flushed0).await?;
    // Neither on-shutdown nor on-startup ever turned max-metric on.
    a.assert_quiet(max_metric_on, mm0, 10).await?;

    log("restoring router-a: loopback out of ospf, graceful restart off");
    a.provision_flags(&with_base(
        A,
        instance(&[
            "--ospf-graceful-restart-grace-period",
            "0",
            "--ospf-max-metric-on-startup",
            "0",
            "--ospf-max-metric-on-shutdown",
            "0",
            "--loopback-remove-address",
            OSPF_GR_LOOPBACK_ADDRESS,
            "--clear-ospf-loopback-profile",
        ]),
    ))
    .await?;
    b.provision_flags(&helper_cap(&[
        "--ospf-graceful-restart-helper-max-grace-period",
        "0",
        "--loopback-remove-address",
        OSPF_GR_TOPOLOGY_LOOPBACK_ADDRESS,
    ]))
    .await?;
    b.provision_flags(&helper_cap(&[
        "--loopback-remove-address",
        OSPF_GR_PEER_LOOPBACK_ADDRESS,
        "--clear-ospf-loopback-profile",
    ]))
    .await?;
    b.wait_ospf_route_gone(OSPF_GR_LOOPBACK_ADDRESS, 5).await
}

/// RFC 4812 restart signaling over RFC 5613 LLS (requires `ospf`, runs after
/// `ospf-graceful-restart`): with `lls` on both routers and a grace period on
/// router-a, SIGTERM on router-a's `nos-ospfd` makes its last Hello carry the
/// RS bit. Router-b must log the signal, keep the eth0.0 adjacency and
/// router-a's loopback route through the restart, and see it `Full` again.
/// Router-b gets an explicit helper cap of 60 so the phase does not depend on
/// what an earlier phase left (#1236); restores `lls` off, no graceful restart
/// and the default cap (`None`: nos-provision maps 0 to it) at the end.
pub async fn ospf_lls_resync(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let flags = |rid: &str, extra: &[&str]| {
        let mut f = ospf(rid);
        f.extend(strings(&["--ospf-lls", "true"]));
        f.extend(strings(extra));
        f
    };
    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    a.provision_flags(&with_base(
        A,
        flags(
            OSPF_ROUTER_ID,
            &[
                "--ospf-graceful-restart-grace-period",
                "120",
                "--loopback-address",
                OSPF_GR_LOOPBACK_ADDRESS,
                "--ospf-loopback-profile",
                OSPF_PROFILE,
            ],
        ),
    ))
    .await?;
    let cap = |v: &str| {
        format!("ospf instance config resolved.*graceful_restart_helper_max_grace_period={v}")
    };
    let cap60_0 = b.count_fresh(&cap("Some(60)")).await;
    b.provision_flags(&with_base(
        B,
        flags(
            OSPF_ROUTER_ID_B,
            &["--ospf-graceful-restart-helper-max-grace-period", "60"],
        ),
    ))
    .await?;
    b.wait_new(&cap("Some(60)"), cap60_0, 60).await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 90).await?;
    b.wait(&format!(
        "added route prefix={OSPF_GR_LOOPBACK_ADDRESS}.*source=Some(Ospf)"
    ))
    .await?;
    for _ in 0..60 {
        if b.rt1_has(OSPF_GR_LOOPBACK_ADDRESS, "Ospf").await? {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let signal = format!("ospf lls restart signal link=eth0.0 neighbor={OSPF_ROUTER_ID}");
    let torn = format!(
        "ospf neighbor adjacency torn down, back to init link=eth0.0 neighbor={OSPF_ROUTER_ID}\\|ospf neighbor state changed to down link=eth0.0 neighbor={OSPF_ROUTER_ID}"
    );
    let (signal0, torn0) = (b.count(&signal), b.count_fresh(&torn).await);
    let mut settle: Vec<&Router> = vec![a, b];
    settle.extend(w.c().ok());
    topology_settled(&settle).await?;
    let (full_on_b, full_on_a) = (full_p2p(OSPF_ROUTER_ID), full_p2p(OSPF_ROUTER_ID_B));
    let (full_b0, full_a0) = (b.count(&full_on_b), a.count(&full_on_a));
    let router_c = w.c().ok();
    let marks = (
        a.log_mark(),
        b.log_mark(),
        router_c.map_or(0, Router::log_mark),
    );
    log("sending SIGTERM to router-a's nos-ospfd; its last Hello carries RS");
    w.dock
        .signal_process("router-a", "nos-ospfd", "-TERM")
        .await?;
    let restart = async {
        b.wait_new(&signal, signal0, 30).await.with_context(|| {
            format!(
                "router-b helper cap was set to 60 (RS is ignored when the cap is 0); last config: {}; last lls/grace lines: {:?}",
                b.logs
                    .last("ospf instance config resolved")
                    .unwrap_or_default(),
                b.logs.tail("ospf lls\\|ospf helper", 3)
            )
        })?;
        b.wait_new(&full_on_b, full_b0, 90).await?;
        a.wait_new(&full_on_a, full_a0, 90).await?;
        tokio::time::sleep(Duration::from_secs(5)).await;
        anyhow::Ok(())
    };
    let route_held = route_held(a, b, router_c, marks);
    tokio::select! {
        r = restart => r?,
        r = route_held => r?,
    }
    quiet_settled(b, &torn, torn0).await?;

    // RFC 4811 out-of-band resync (#1371): router-a starts it on its `Full`,
    // LR-announcing neighbor. Both sides must keep the adjacency, the routes
    // and their Router-LSAs, and finish `Full` with the flag cleared.
    log("router-a starts an RFC 4811 out-of-band resync");
    topology_settled(&settle).await?;
    let started = format!("ospf lls resync started link=eth0.0 neighbor={OSPF_ROUTER_ID_B}");
    let done = "ospf lls resync complete link=eth0.0";
    let churn = format!(
        "ospf neighbor sequence mismatch\\|ospf neighbor adjacency torn down\\|ospf neighbor state changed to down\\|removed route prefix={OSPF_GR_LOOPBACK_ADDRESS}\\|ospf lsa originated"
    );
    let (started0, done_a0, done_b0) = (a.count(&started), a.count(done), b.count(done));
    let (churn_a0, churn_b0) = (a.count_fresh(&churn).await, b.count_fresh(&churn).await);
    a.provision_flags(&with_base(
        A,
        flags(OSPF_ROUTER_ID, &["--ospf-oob-resync", "true"]),
    ))
    .await?;
    a.wait_new(&started, started0, 30).await?;
    a.wait_new(done, done_a0, 30).await?;
    b.wait_new(done, done_b0, 30).await?;
    for _ in 0..10 {
        anyhow::ensure!(
            b.rt1_has(OSPF_GR_LOOPBACK_ADDRESS, "Ospf").await?,
            "router-b lost router-a's loopback route during the OOB resync"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    for (r, base) in [(a, churn_a0), (b, churn_b0)] {
        r.assert_quiet(&churn, base, 0).await?;
    }
    a.provision_flags(&with_base(
        A,
        flags(OSPF_ROUTER_ID, &["--ospf-oob-resync", "false"]),
    ))
    .await?;

    // RFC 4812 RS alone (#1371): without a Grace-LSA the helper's hold can
    // only come from the RS bit of the last Hello.
    log("router-a restarts with the restart signal only, no Grace-LSA");
    let before_full = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    a.provision_flags(&with_base(
        A,
        flags(OSPF_ROUTER_ID, &["--ospf-restart-signal-only", "true"]),
    ))
    .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before_full, 90)
        .await?;
    topology_settled(&settle).await?;
    let (signal1, torn1) = (b.count(&signal), b.count_fresh(&torn).await);
    let grace_lsa = "ospf helper: grace period entered";
    let grace0 = b.count(grace_lsa);
    let (full_b1, full_a1) = (b.count(&full_on_b), a.count(&full_on_a));
    w.dock
        .signal_process("router-a", "nos-ospfd", "-TERM")
        .await?;
    b.wait_new(&signal, signal1, 30).await?;
    b.wait_new(&full_on_b, full_b1, 90).await?;
    a.wait_new(&full_on_a, full_a1, 90).await?;
    anyhow::ensure!(
        b.count(grace_lsa) == grace0,
        "router-b saw a Grace-LSA although restart-signal-only was set"
    );
    quiet_settled(b, &torn, torn1).await?;
    a.provision_flags(&with_base(
        A,
        flags(OSPF_ROUTER_ID, &["--ospf-restart-signal-only", "false"]),
    ))
    .await?;

    log("restoring lls off and graceful restart off");
    let before = a.count(&full_p2p(OSPF_ROUTER_ID_B));
    for r in [a, b] {
        r.edit(|c| {
            for p in c
                .ospf_instances
                .iter_mut()
                .flat_map(|i| i.areas.iter_mut())
                .flat_map(|ar| ar.profiles.iter_mut())
            {
                p.lls = false;
            }
            Ok(())
        })
        .await?;
    }
    a.provision_flags(&with_base(
        A,
        strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID,
            "--ospf-graceful-restart-grace-period",
            "0",
            "--loopback-remove-address",
            OSPF_GR_LOOPBACK_ADDRESS,
            "--clear-ospf-loopback-profile",
        ]),
    ))
    .await?;
    // Back to the default cap (a 0 clears it to None).
    let cap_none0 = b.count_fresh(&cap("None")).await;
    b.provision_flags(&with_base(
        B,
        strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID_B,
            "--ospf-graceful-restart-helper-max-grace-period",
            "0",
        ]),
    ))
    .await?;
    b.wait_new(&cap("None"), cap_none0, 60).await?;
    b.wait_ospf_route_gone(OSPF_GR_LOOPBACK_ADDRESS, 30).await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 90).await?;
    both_full_p2p(a, b).await
}

/// RFC 2328 §14 aging. Self-contained: both nos-ospfd processes start with a
/// real `--lsa-age-multiplier` (1800s/3600s become 10s/20s).
pub async fn ospf_aging(w: &mut World) -> anyhow::Result<()> {
    let mult = format!("--ospfd-arg=--lsa-age-multiplier={OSPF_AGE_MULTIPLIER}");
    w.up(&[&mult]).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    both_full_p2p(a, b).await?;

    // router-a's Router-LSA content never changes here, so a bumped sequence
    // number with refreshed=true can only come from the age-based refresh path.
    a.wait_new(
        &format!("ospf lsa originated.*advertising_router={OSPF_ROUTER_ID}.*refreshed=true"),
        0,
        45,
    )
    .await?;
    b.wait_new(
        &format!("ospf lsa installed.*advertising_router={OSPF_ROUTER_ID}"),
        0,
        20,
    )
    .await?;

    // Graceful shutdown (SIGTERM — a SIGKILL never reaches the handler):
    // router-b's nos-ospfd must prematurely age its own LSAs (RFC 2328 §14.1)
    // and keep flooding long enough for router-a to flush them within
    // seconds. The watchdog then respawns it; reconverge before the
    // router-a-focused steps below.
    let flushed_pat = format!("ospf lsa maxage flushed.*advertising_router={OSPF_ROUTER_ID_B}");
    let flushed = a.count(&flushed_pat);
    let (full_a, full_b) = (
        a.count(&full_p2p(OSPF_ROUTER_ID_B)),
        b.count(&full_p2p(OSPF_ROUTER_ID)),
    );
    log("sending SIGTERM to router-b's nos-ospfd; it must flush its lsas before exiting");
    w.dock
        .signal_process("router-b", "nos-ospfd", "-TERM")
        .await?;
    b.wait("ospf flushing self-originated lsas before shutdown")
        .await?;
    a.wait_new(&flushed_pat, flushed, 30).await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), full_a, 90).await?;
    b.wait_new(&full_p2p(OSPF_ROUTER_ID), full_b, 90).await?;

    // Stop router-a's nos-ospfd so it stops refreshing: router-b's held copy
    // must then age out purely on its own local clock.
    log("killing router-a's nos-ospfd to stop further refreshes");
    w.dock.kill_process("router-a", "nos-ospfd").await?;
    b.wait_new(
        &format!("ospf lsa maxage flushed.*advertising_router={OSPF_ROUTER_ID}"),
        0,
        45,
    )
    .await
}

const MTU_REJECT: &str = "ospf dbd rejected.*local_mtu=1400 neighbor_mtu=1500";

/// RFC 2328 §10.8 DBD pagination, forced by `--dbd-max-headers=1`. router-a
/// also redistributes a static route (two distinct LSAs before the exchange
/// starts), since a single-LSA summary fits in one chunk even at 1.
/// #607: `--dbd-fault=drop:2,dup:3` makes each daemon lose its 2nd and
/// duplicate its 3rd exchange DBD; RFC 2328 §10.6 retransmission/duplicate
/// handling must recover without a sequence-mismatch restart.
pub async fn ospf_dbd_pagination(w: &mut World) -> anyhow::Result<()> {
    w.up(&[
        "--ospfd-arg=--dbd-max-headers=1",
        "--ospfd-arg=--dbd-fault=drop:2,dup:3",
    ])
    .await?;
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, asbr(ospf(OSPF_ROUTER_ID))))
        .await?;
    router_a_holds_two_lsas(a).await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    paginated(a, b).await?;
    both_full_p2p(a, b).await?;
    dbd_faults_survived(a, b, "ospf").await?;
    // #1140 (RFC 5243): an adjacency re-forming against LSDBs both sides
    // already hold must trim its summary and still reach Full. A 1400 MTU on
    // router-a only drops it out of Full (as in `ospf-mtu-mismatch`);
    // `mtu-ignore` then lets it re-form.
    let trimmed = "ospf dbd summary trimmed removed=";
    let (base_a, base_b) = (a.count(trimmed), b.count(trimmed));
    let (full, rejects) = (a.count(&full_p2p(OSPF_ROUTER_ID_B)), a.count(MTU_REJECT));
    let with = |extra: &[&str]| {
        let mut f = asbr(ospf(OSPF_ROUTER_ID));
        f.extend(strings(extra));
        with_base(A, f)
    };
    a.provision_flags(&with(&["--ospf-profile-mtu", "1400"]))
        .await?;
    a.wait_new(MTU_REJECT, rejects, 60).await?;
    a.provision_flags(&with(&["--ospf-mtu-ignore", "true"]))
        .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), full, 60).await?;
    if a.wait_new(trimmed, base_a, 5).await.is_err()
        && b.wait_new(trimmed, base_b, 5).await.is_err()
    {
        bail!("no dbd summary was ever trimmed (RFC 5243)");
    }
    Ok(())
}

/// #607: the injected DBD loss/duplicate fired and still cost no restart.
async fn dbd_faults_survived(a: &Router, b: &Router, daemon: &str) -> anyhow::Result<()> {
    let fault = format!("{daemon} dbd fault injected");
    if a.wait(&fault).await.is_err() && b.wait(&fault).await.is_err() {
        bail!("no dbd fault was ever injected");
    }
    let restart = format!("{daemon} neighbor sequence mismatch, restarting negotiation");
    quiet_settled(a, &restart, 0).await?;
    quiet_settled(b, &restart, 0).await
}

/// The same, driven purely by a real `OspfProfile.mtu` override (200 bytes)
/// via `exchange::mtu_based_max_headers` — no `--dbd-max-headers` flag — and
/// with enough Type-5 LSAs that LSR/LSU/LSAck also split to the MTU (#806):
/// router-a must log `ospf lsu split`, and router-b must end up holding the
/// last LSA.
pub async fn ospf_mtu_pagination(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let mut a_flags = asbr(with_mtu(ospf(OSPF_ROUTER_ID)));
    a_flags.extend(ospf_chunked_routes(OSPF_SPLIT_ROUTES - 1));
    let last = format!("100.64.0.{}", OSPF_SPLIT_ROUTES - 2);
    let split = "ospf lsu split.*packets=";
    let split_a = a.count(split);
    a.provision_flags(&with_base(A, a_flags)).await?;
    a.wait(&format!(
        "ospf lsa originated.*lsa_type=5 link_state_id={last} "
    ))
    .await?;
    b.provision_flags(&with_base(B, with_mtu(ospf(OSPF_ROUTER_ID_B))))
        .await?;
    a.wait(&format!("ospf profile resolved instance={OSPF_INSTANCE}"))
        .await?;
    paginated(a, b).await?;
    both_full_p2p(a, b).await?;
    a.wait_new(split, split_a, 60).await?;
    b.wait(&format!("ospf lsa installed.*link_state_id={last} "))
        .await
}

/// `n` /32 statics in 100.64.0.0/16 as repeated `--static-route` arguments.
fn ospf_chunked_routes(n: usize) -> Vec<String> {
    (0..n)
        .flat_map(|i| {
            [
                "--static-route".to_string(),
                format!("100.64.{}.{}/32", i / 256, i % 256),
            ]
        })
        .collect()
}

/// Waits (up to `secs`) until router `r`'s `rt1` holds an OSPF count `ok`
/// accepts. A REST error (`nos-ribd` restarting) counts as "not yet".
async fn wait_ospf_count(r: &Router, secs: u64, ok: impl Fn(usize) -> bool) -> anyhow::Result<()> {
    let mut n = None;
    for _ in 0..secs {
        n = r.rt1_count("Ospf").await.ok();
        if n.is_some_and(&ok) {
            log(format!("{}: rt1 holds {n:?} ospf routes", r.name()));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("{}: rt1 stuck at {n:?} ospf routes", r.name())
}

/// #727/#729: a `Full` heavier than one frame crosses as `FullPart`s closed
/// by a `Full`, assembled by the receiver before anything is applied, in both
/// directions between `nos-ospfd` and `nos-ribd`. Self-contained:
/// `nos-ospfd --push-chunk` and `nos-ribd --redistribute-chunk` (test-only)
/// make ~80 routes 3 frames. router-a redistributes `OSPF_CHUNKED_ROUTES`
/// statics, router-b learns them.
/// - `PushOspfRoutes`: killing router-b's `nos-ribd` closes router-b's
///   `nos-ospfd` push connection, which reconnects at once (it reads for EOF)
///   with one chunked `Full`.
/// - `RedistributeRoutes`: killing router-a's `nos-ospfd` closes router-a's
///   `nos-ribd` redistribution connection, which reconnects to the successor
///   with one chunked `Full`; the externals still reach router-b.
pub async fn ospf_push_chunked(w: &mut World) -> anyhow::Result<()> {
    w.up(&[
        &format!("--ospfd-arg=--push-chunk={OSPF_PUSH_CHUNK_TEST}"),
        &format!("--ribd-arg=--redistribute-chunk={REDISTRIBUTE_CHUNK_TEST}"),
    ])
    .await?;
    let (a, b) = (w.a()?, w.b()?);
    let mut a_flags = asbr(ospf(OSPF_ROUTER_ID));
    a_flags.extend(ospf_chunked_routes(OSPF_CHUNKED_ROUTES));
    a.provision_flags(&with_base(A, a_flags)).await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    both_full_p2p(a, b).await?;
    wait_ospf_count(b, 120, |n| n > OSPF_CHUNKED_ROUTES).await?;

    let assembled = "assembled chunked ospf route snapshot table=rt1 routes=8[0-9] parts=3";
    let asm_b = b.count(assembled);
    log("killing router-b's nos-ribd: router-b's nos-ospfd reconnects with a chunked Full");
    w.dock.kill_process("router-b", "nos-ribd").await?;
    b.wait_new(assembled, asm_b, 60).await?;
    // Only the assembled Full is applied: no half table, so no route removed.
    let removed0 = b.count_fresh("removed route").await;
    b.assert_quiet("removed route", removed0, 3).await?;
    wait_ospf_count(b, 30, |n| n > OSPF_CHUNKED_ROUTES).await?;

    let redistributed = "assembled chunked redistribute snapshot instance=.* routes=8[0-9] parts=3";
    let full_a = full_p2p(OSPF_ROUTER_ID_B);
    let (asm_a, full_before) = (a.count(redistributed), a.count(&full_a));
    log("killing router-a's nos-ospfd: router-a's nos-ribd reconnects with a chunked Full");
    w.dock.kill_process("router-a", "nos-ospfd").await?;
    a.wait_new(redistributed, asm_a, 60).await?;
    a.wait_new(&full_a, full_before, 120).await?;
    wait_ospf_count(b, 120, |n| n > OSPF_CHUNKED_ROUTES).await
}

/// RFC 2328 §3.5/§3.6 stub areas and area ranges, self-contained. eth0.0 is
/// in area 1, router-a's only area; router-b's loopback and the bd-ospf bridge
/// shared with router-c are in area 0, making router-b the ABR (a loopback
/// alone does not attach it, RFC 3509), and router-b redistributes a static route (a Type-5 that
/// must never reach the stub area).
#[allow(clippy::too_many_lines)]
pub async fn ospf_stub(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    w.start(C, None, &[]).await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let loopback = OSPF_STUB_LOOPBACK_ADDRESS;
    let loopback_id = loopback.trim_end_matches("/32");
    let range = OSPF_STUB_RANGE;
    let range_id = range.split('/').next().unwrap_or(range);
    let area = |router_id: &str, extra: &[&str]| {
        let mut flags = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            router_id,
            "--ospf-area",
            OSPF_AREA_1,
        ]);
        flags.extend(strings(extra));
        flags
    };
    let on_eth0 = |router_id: &str, area_type: &str| {
        area(
            router_id,
            &[
                "--ospf-area-type",
                area_type,
                "--ospf-profile",
                OSPF_PROFILE_AREA1,
                "--ospf-interface-profile",
                OSPF_PROFILE_AREA1,
            ],
        )
    };

    // Area 1 a stub on router-a only: the Hello E-bits disagree.
    let mismatch = "dropping ospf hello with mismatched e-bit";
    let init_b =
        format!("ospf neighbor state changed to init link=eth0.0 neighbor={OSPF_ROUTER_ID_B}");
    let type5 = "ospf lsa installed.*lsa_type=5";
    let (init0, type5_0) = (a.count_fresh(&init_b).await, a.count_fresh(type5).await);
    a.provision_flags(&with_base(A, on_eth0(OSPF_ROUTER_ID, "stub")))
        .await?;
    b.provision_flags(&with_base(B, asbr(on_eth0(OSPF_ROUTER_ID_B, "normal"))))
        .await?;
    // Router-b is an ABR only with a Full area-0 adjacency (RFC 3509, #1170): a
    // loopback alone does not attach, so router-c joins it in area 0 on bd-ospf.
    let abr_up = "ospf abr backbone attachment changed abr=true";
    let abr0 = b.count_fresh(abr_up).await;
    let mut b_area0 = ospf_instance_only(OSPF_ROUTER_ID_B);
    b_area0.extend(strings(&[
        "--loopback-address",
        loopback,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ]));
    b_area0.extend(ospf_broadcast(OSPF_BROADCAST_ADDRESS_B));
    b.provision(&b_area0).await?;
    let mut c_flags = ospf_instance_only(OSPF_ROUTER_ID_C);
    c_flags.extend(ospf_broadcast(OSPF_BROADCAST_ADDRESS_C));
    c.provision_flags(&with_base(C, c_flags)).await?;
    b.wait_new(abr_up, abr0, 60).await?;
    a.wait(mismatch).await?;
    b.wait(mismatch).await?;
    b.wait("ospf lsa originated.*lsa_type=5").await?;
    log("confirming the e-bit mismatch never reaches init");
    a.assert_quiet(&init_b, init0, 8).await?;

    // Stub on both: Full; router-b (ABR) originates a default Type-3 and a
    // summary of its loopback; router-a installs both as kernel routes and
    // never a Type-5.
    b.provision(&area(OSPF_ROUTER_ID_B, &["--ospf-area-type", "stub"]))
        .await?;
    both_full_p2p(a, b).await?;
    a.wait("ospf lsa installed.*lsa_type=3 link_state_id=0.0.0.0")
        .await?;
    a.wait("added route prefix=0.0.0.0/0 .*source=Some(Ospf)")
        .await?;
    a.wait(&format!(
        "added route prefix={loopback} .*source=Some(Ospf)"
    ))
    .await?;
    log("confirming no as-external lsa reaches the stub area");
    a.assert_quiet(type5, type5_0, 10).await?;

    // A range over the loopback on area 0: router-a gets the range instead of
    // the /32 (flushed), and router-b installs a discard route for it.
    let discard =
        format!("added route prefix={range} .*source=Some(Ospf) backup=false discard=true");
    b.provision(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        OSPF_ROUTER_ID_B,
        "--ospf-area",
        OSPF_AREA,
        "--ospf-area-range",
        range,
    ])
    .await?;
    a.wait(&format!(
        "ospf lsa installed.*lsa_type=3 link_state_id={range_id}"
    ))
    .await?;
    a.wait(&format!("added route prefix={range} .*source=Some(Ospf)"))
        .await?;
    b.wait(&format!(
        "ospf lsa prematurely aged.*lsa_type=3 link_state_id={loopback_id}"
    ))
    .await?;
    a.wait(&format!("removed route prefix={loopback}")).await?;
    b.wait(&discard).await?;
    if !b.rt1_has(range, "Ospf").await? {
        bail!("router-b's rt1 does not list the discard route {range}");
    }
    // The dumped RTN_BLACKHOLE is recognised as ours: no EEXIST re-add on the
    // next 10s reapply.
    log("confirming router-b's discard route survives a reapply");
    let failed = format!("failed to add route prefix={range}");
    let (failed0, discard0) = (b.count_fresh(&failed).await, b.count_fresh(&discard).await);
    b.assert_quiet(&failed, failed0, 15).await?;
    quiet_settled(b, &discard, discard0).await?;

    // not-advertise: the range Type-3 is flushed, router-a's route and
    // router-b's discard route removed.
    b.provision(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        OSPF_ROUTER_ID_B,
        "--ospf-area",
        OSPF_AREA,
        "--ospf-area-range",
        &format!("{range}:not-advertise"),
    ])
    .await?;
    a.wait(&format!(
        "ospf lsa maxage flushed.*lsa_type=3 link_state_id={range_id}"
    ))
    .await?;
    a.wait(&format!("removed route prefix={range}")).await?;
    b.wait(&format!("removed route prefix={range} .*discard=true"))
        .await?;

    // Totally stubby: with the range gone the /32 summary is back, then
    // flushed again, and only the default is left.
    let added = format!("added route prefix={loopback} .*source=Some(Ospf)");
    let added_before = a.count(&added);
    b.provision(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        OSPF_ROUTER_ID_B,
        "--ospf-area",
        OSPF_AREA,
        "--ospf-clear-area-range",
        range,
    ])
    .await?;
    a.wait_new(&added, added_before, 60).await?;
    let removed = format!("removed route prefix={loopback}");
    let removed_before = a.count(&removed);
    let default_removed = "removed route prefix=0.0.0.0/0";
    let default0 = a.count_fresh(default_removed).await;
    b.provision(&area(
        OSPF_ROUTER_ID_B,
        &["--ospf-area-type", "totally-stubby"],
    ))
    .await?;
    a.wait_new(&removed, removed_before, 60).await?;
    log("confirming the default route stays in the totally-stubby area");
    a.assert_quiet(default_removed, default0, 10).await?;
    if !a.rt1_has("0.0.0.0/0", "Ospf").await? {
        bail!("router-a lost its default route in the totally-stubby area");
    }
    Ok(())
}

/// RFC 3101 NSSA, self-contained, three routers. eth0.0 (a-b) is the
/// backbone; the bd-ospf bridge (a, b and c) is NSSA area 1, so router-a and
/// router-b are its two ABRs and router-c is internal to it. Router-c
/// redistributes a static route as a Type-7; router-b, the higher router-id,
/// is the elected translator and floods the Type-5 into the backbone, which
/// router-a learns over eth0.0. No Type-5 ever enters the NSSA.
pub async fn ospf_nssa(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    w.start(C, None, &[]).await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let lsid = ASBR_PREFIX.split('/').next().unwrap_or(ASBR_PREFIX);
    let nssa = |router_id: &str, svi: &str| {
        let mut flags = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            router_id,
            "--ospf-area",
            OSPF_AREA_1,
            "--ospf-area-type",
            "nssa",
            "--ospf-profile",
            OSPF_PROFILE_AREA1,
        ]);
        flags.extend(ospf_broadcast_profile(svi, OSPF_PROFILE_AREA1));
        flags
    };
    // Baselines at phase start, before anything can originate/install a Type-5 (#886).
    let a_type5 = "ospf lsa originated.*lsa_type=5";
    let c_type5 = "ospf lsa installed.*lsa_type=5";
    let (a_type5_0, c_type5_0) = (a.count_fresh(a_type5).await, c.count_fresh(c_type5).await);
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    a.provision_flags(&with_base(
        A,
        nssa(OSPF_ROUTER_ID, OSPF_BROADCAST_ADDRESS_A),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        nssa(OSPF_ROUTER_ID_B, OSPF_BROADCAST_ADDRESS_B),
    ))
    .await?;
    c.provision_flags(&with_base(
        C,
        asbr(nssa(OSPF_ROUTER_ID_C, OSPF_BROADCAST_ADDRESS_C)),
    ))
    .await?;

    both_full_p2p(a, b).await?;
    let link = format!("link=broadcast-domain:{BD}");
    for neighbor in [OSPF_ROUTER_ID, OSPF_ROUTER_ID_B] {
        c.wait(&format!(
            "ospf neighbor reached full {link} neighbor={neighbor}"
        ))
        .await?;
    }
    // Router-c's Type-7, translated by router-b alone into a Type-5 that
    // router-a learns over the backbone and routes.
    c.wait(&format!(
        "ospf lsa originated.*lsa_type=7 link_state_id={lsid}"
    ))
    .await?;
    b.wait(&format!(
        "ospf nssa translator role changed area={OSPF_AREA_1} translating=true"
    ))
    .await?;
    b.wait(&format!(
        "ospf lsa originated.*lsa_type=5 link_state_id={lsid}"
    ))
    .await?;
    a.wait(&format!(
        "ospf lsa installed link=eth0.0 .*lsa_type=5 link_state_id={lsid} advertising_router={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    a.wait(&format!(
        "added route prefix={ASBR_PREFIX} .*source=Some(Ospf)"
    ))
    .await?;
    log("confirming router-a doesn't translate too and no type-5 enters the nssa");
    a.assert_quiet(a_type5, a_type5_0, 10).await?;
    quiet_settled(c, c_type5, c_type5_0).await?;

    // Redistribution removed: the Type-7 and the Type-5 translated from it
    // are both flushed (RFC 2328 §14.1) and router-a's route goes.
    let removed = format!("removed route prefix={ASBR_PREFIX}");
    c.provision(&["--clear-redistribute-to-ospf"]).await?;
    c.wait(&format!(
        "ospf lsa prematurely aged.*lsa_type=7 link_state_id={lsid}"
    ))
    .await?;
    b.wait(&format!(
        "ospf lsa prematurely aged.*lsa_type=5 link_state_id={lsid}"
    ))
    .await?;
    a.wait(&removed).await
}

/// RFC 2328 §3.6 ABR external flooding, self-contained, three routers.
/// router-a is in the backbone only (eth0.0); router-b is the ABR (eth0.0 in
/// area 0, the bd-ospf bridge in normal area 1); router-c, on the bridge only,
/// redistributes a static route. router-a must learn router-c's Type-5 (metric
/// 20) only because router-b copies it into the backbone, route it, and lose
/// both when the rule is cleared and the flush is carried across too.
pub async fn ospf_external_flood(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    w.start(C, None, &[]).await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let lsid = ASBR_PREFIX.split('/').next().unwrap_or(ASBR_PREFIX);
    let area1 = |router_id: &str, svi: &str| {
        let mut flags = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            router_id,
            "--ospf-area",
            OSPF_AREA_1,
            "--ospf-profile",
            OSPF_PROFILE_AREA1,
        ]);
        flags.extend(ospf_broadcast_profile(svi, OSPF_PROFILE_AREA1));
        flags
    };
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    b.provision_flags(&with_base(
        B,
        area1(OSPF_ROUTER_ID_B, OSPF_BROADCAST_ADDRESS_B),
    ))
    .await?;
    c.provision_flags(&with_base(
        C,
        asbr(area1(OSPF_ROUTER_ID_C, OSPF_BROADCAST_ADDRESS_C)),
    ))
    .await?;

    both_full_p2p(a, b).await?;
    c.wait(&format!(
        "ospf neighbor reached full link=broadcast-domain:{BD} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;
    c.wait(&format!(
        "ospf lsa originated.*lsa_type=5 link_state_id={lsid}"
    ))
    .await?;

    log("router-b (ABR) copies router-c's type-5 into the backbone; router-a routes it");
    let copy = |maxage: bool| {
        format!(
            "ospf external lsa copied across areas from_area={OSPF_AREA_1} to_area={OSPF_AREA} advertising_router={OSPF_ROUTER_ID_C} link_state_id={lsid} maxage={maxage}"
        )
    };
    b.wait(&copy(false)).await?;
    wait_external_lsa(a, OSPF_ROUTER_ID_C, lsid, 20, false).await?;
    a.wait(&format!(
        "added route prefix={ASBR_PREFIX} .*source=Some(Ospf)"
    ))
    .await?;

    log("clearing the rule: the flush crosses the ABR and router-a drops the route");
    let removed = format!("removed route prefix={ASBR_PREFIX}");
    c.provision(&["--clear-redistribute-to-ospf"]).await?;
    c.wait(&format!(
        "ospf lsa prematurely aged.*lsa_type=5 link_state_id={lsid}"
    ))
    .await?;
    b.wait(&copy(true)).await?;
    a.wait(&removed).await
}

/// RFC 2328 §15 virtual link, self-contained, three routers (the
/// `ospf-external-flood` topology): router-a in the backbone only (eth0.0),
/// router-b the ABR (eth0.0 in area 0, the bd-ospf bridge in area 1), router-c
/// on the bridge only with its loopback in area 2 — detached from the backbone
/// until a virtual link b<->c through area 1 joins it. The virtual adjacency
/// must reach Full over the real VRF raw sockets, both Router-LSAs carry the
/// type-4 link in area 0 and the V bit in area 1, router-c's area-2 summary
/// reaches router-a through it, both install a kernel route to router-c's
/// loopback over it (#226), and router-c dropping its end takes the adjacency
/// down on router-b within the dead interval and both routes with it.
pub async fn ospf_virtual_link(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    w.start(C, None, &[]).await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let area1 = |router_id: &str, svi: &str| {
        let mut flags = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            router_id,
            "--ospf-area",
            OSPF_AREA_1,
            "--ospf-profile",
            OSPF_PROFILE_AREA1,
        ]);
        flags.extend(ospf_broadcast_profile(svi, OSPF_PROFILE_AREA1));
        flags
    };
    let vlink = |router_id: &str, endpoint: &str, flag: &str| {
        strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            router_id,
            flag,
            &format!("{OSPF_AREA_1}:{endpoint}"),
        ])
    };
    let loopback_id = OSPF_VLINK_LOOPBACK_ADDRESS.trim_end_matches("/32");
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    b.provision_flags(&with_base(
        B,
        area1(OSPF_ROUTER_ID_B, OSPF_BROADCAST_ADDRESS_B),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        vlink(OSPF_ROUTER_ID_B, OSPF_ROUTER_ID_C, "--ospf-virtual-link"),
    ))
    .await?;
    c.provision_flags(&with_base(
        C,
        area1(OSPF_ROUTER_ID_C, OSPF_BROADCAST_ADDRESS_C),
    ))
    .await?;
    let mut c_area2 = strings(&[
        "--ospf-area",
        OSPF_AREA_2,
        "--ospf-profile",
        OSPF_PROFILE_AREA2,
        "--loopback-address",
        OSPF_VLINK_LOOPBACK_ADDRESS,
        "--ospf-loopback-profile",
        OSPF_PROFILE_AREA2,
    ]);
    c_area2.extend(vlink(
        OSPF_ROUTER_ID_C,
        OSPF_ROUTER_ID_B,
        "--ospf-virtual-link",
    ));
    c.provision_flags(&with_base(C, c_area2)).await?;

    both_full_p2p(a, b).await?;
    c.wait(&format!(
        "ospf neighbor reached full link=broadcast-domain:{BD} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;

    log("the virtual link b<->c comes up from area 1's spf and reaches full");
    let b_link = format!("vlink-{OSPF_AREA_1}-{OSPF_ROUTER_ID_C}");
    let c_link = format!("vlink-{OSPF_AREA_1}-{OSPF_ROUTER_ID_B}");
    b.wait(&format!("ospf virtual link up link={b_link} "))
        .await?;
    c.wait(&format!("ospf virtual link up link={c_link} "))
        .await?;
    b.wait(&format!(
        "ospf neighbor reached full link={b_link} neighbor={OSPF_ROUTER_ID_C}"
    ))
    .await?;
    c.wait(&format!(
        "ospf neighbor reached full link={c_link} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;

    log("type-4 links in area 0 (at router-a), V bits in area 1, c's summary at router-a");
    for (holder, router, far) in [
        (a, OSPF_ROUTER_ID_B, OSPF_ROUTER_ID_C),
        (a, OSPF_ROUTER_ID_C, OSPF_ROUTER_ID_B),
    ] {
        wait_lsa(holder, &format!("{router}'s type-4 link to {far}"), |l| {
            l["area_id"] == OSPF_AREA
                && l["lsa_type"] == 1
                && l["advertising_router"] == router
                && l["virtual_links"]
                    .as_array()
                    .is_some_and(|v| v.iter().any(|x| x == far))
        })
        .await?;
    }
    for (holder, router) in [(c, OSPF_ROUTER_ID_B), (b, OSPF_ROUTER_ID_C)] {
        wait_lsa(holder, &format!("{router}'s area-1 V bit"), |l| {
            l["area_id"] == OSPF_AREA_1
                && l["lsa_type"] == 1
                && l["advertising_router"] == router
                && l["router_flags"].as_u64().is_some_and(|f| f & 0x04 != 0)
        })
        .await?;
    }
    wait_lsa(a, "router-c's area-2 summary in area 0", |l| {
        l["area_id"] == OSPF_AREA
            && l["lsa_type"] == 3
            && l["advertising_router"] == OSPF_ROUTER_ID_C
            && l["link_state_id"] == loopback_id
            && l["age"].as_u64().is_some_and(|a| a < 3600)
    })
    .await?;

    // #226: SPF across the type-4 link (RFC 2328 §16.1). Router-a routes to
    // router-c's loopback through router-b (its only neighbor); router-b
    // through the transit area, to router-c's bridge address, never the
    // virtual neighbor address as such.
    log("kernel routes to router-c's area-2 loopback over the virtual link");
    let c_bridge = OSPF_BROADCAST_ADDRESS_C
        .split('/')
        .next()
        .unwrap_or_default();
    let added = |gateway: &str| {
        format!(
            "added route prefix={OSPF_VLINK_LOOPBACK_ADDRESS} gateway={gateway} next_hops=1 .*source=Some(Ospf)"
        )
    };
    a.wait(&added(IP_B.s())).await?;
    b.wait(&added(c_bridge)).await?;

    log("router-c drops its end: router-b's virtual neighbor dies within the dead interval");
    c.provision(&vlink(
        OSPF_ROUTER_ID_C,
        OSPF_ROUTER_ID_B,
        "--ospf-clear-virtual-link",
    ))
    .await?;
    c.wait(&format!("ospf virtual link down link={c_link}"))
        .await?;
    b.wait_new(
        &format!("ospf neighbor state changed to down link={b_link}"),
        0,
        60,
    )
    .await?;

    // §16.2: router-b, a backbone ABR, doesn't route on area 1's summaries, so
    // both routes go with the virtual link; router-c, now in areas 1 and 2
    // with no backbone, is no ABR (RFC 2328 §3.1) and flushes its summary.
    log("both routes are removed, and router-c flushes its area-1 summary");
    let removed = format!("removed route prefix={OSPF_VLINK_LOOPBACK_ADDRESS} ");
    b.wait_new(&removed, 0, 30).await?;
    a.wait_new(&removed, 0, 30).await?;
    c.wait(&format!(
        "ospf lsa prematurely aged.*lsa_type=3 link_state_id={loopback_id} advertising_router={OSPF_ROUTER_ID_C}"
    ))
    .await
}

/// RFC 2328 §12.4.3 ABR transit (#610), self-contained, three routers (the
/// `ospf-external-flood` topology): router-c, on the bd-ospf bridge in area 1,
/// is an ASBR with an area-1 loopback; router-b is the ABR (area 0 over
/// eth0.0, area 1 on the bridge); router-a is area 0 plus a loopback in area 2,
/// so it is a second ABR behind the backbone. router-a must re-summarize what
/// it only learns from router-b's backbone Type-3/Type-4 into area 2: a
/// Type-3 for router-c's loopback and a Type-4 for the ASBR router-c. Removing
/// both at router-c flushes them again.
pub async fn ospf_abr_transit(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    w.start(C, None, &[]).await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let lsid = ASBR_PREFIX.split('/').next().unwrap_or(ASBR_PREFIX);
    let loopback = OSPF_ABR_LOOPBACK_ADDRESS.trim_end_matches("/32");
    let area1 = |router_id: &str, svi: &str| {
        let mut flags = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            router_id,
            "--ospf-area",
            OSPF_AREA_1,
            "--ospf-profile",
            OSPF_PROFILE_AREA1,
        ]);
        flags.extend(ospf_broadcast_profile(svi, OSPF_PROFILE_AREA1));
        flags
    };
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    a.provision_flags(&with_base(
        A,
        strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID,
            "--ospf-area",
            OSPF_AREA_2,
            "--ospf-profile",
            OSPF_PROFILE_AREA2,
            "--loopback-address",
            OSPF_VLINK_LOOPBACK_ADDRESS,
            "--ospf-loopback-profile",
            OSPF_PROFILE_AREA2,
        ]),
    ))
    .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    b.provision_flags(&with_base(
        B,
        area1(OSPF_ROUTER_ID_B, OSPF_BROADCAST_ADDRESS_B),
    ))
    .await?;
    let mut c_flags = area1(OSPF_ROUTER_ID_C, OSPF_BROADCAST_ADDRESS_C);
    c_flags.extend(strings(&[
        "--loopback-address",
        OSPF_ABR_LOOPBACK_ADDRESS,
        "--ospf-loopback-profile",
        OSPF_PROFILE_AREA1,
    ]));
    c.provision_flags(&with_base(C, asbr(c_flags))).await?;

    both_full_p2p(a, b).await?;
    c.wait(&format!(
        "ospf neighbor reached full link=broadcast-domain:{BD} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;

    log("router-a re-summarizes router-b's backbone Type-3 and Type-4 into area 2");
    let t3 = format!(
        "ospf lsa originated lsa_type=3 link_state_id={loopback} advertising_router={OSPF_ROUTER_ID}"
    );
    let t4 = format!(
        "ospf lsa originated lsa_type=4 link_state_id={OSPF_ROUTER_ID_C} advertising_router={OSPF_ROUTER_ID}"
    );
    a.wait(&t3).await?;
    a.wait(&t4).await?;
    for (lsa_type, id) in [(3, loopback), (4, OSPF_ROUTER_ID_C)] {
        wait_lsa(a, &format!("a type-{lsa_type} for {id} in area 2"), |l| {
            l["area_id"] == OSPF_AREA_2
                && l["lsa_type"] == lsa_type
                && l["advertising_router"] == OSPF_ROUTER_ID
                && l["link_state_id"] == id
                && l["age"].as_u64().is_some_and(|age| age < 3600)
        })
        .await?;
    }
    // The type-5 crossed into area 2 too, and nothing area 1 offered went
    // sideways: router-a's area-2 loopback is the only thing it summarizes
    // into area 0 on its own.
    wait_lsa(a, "router-c's type-5 in area 2", |l| {
        l["area_id"] == OSPF_AREA_2 && l["lsa_type"] == 5 && l["link_state_id"] == lsid
    })
    .await?;

    log("router-c stops being an ASBR and drops its loopback: both summaries are flushed");
    c.provision(&[
        "--clear-redistribute-to-ospf",
        "--loopback-remove-address",
        OSPF_ABR_LOOPBACK_ADDRESS,
        "--clear-ospf-loopback-profile",
    ])
    .await?;
    a.wait(&format!(
        "ospf lsa prematurely aged.*lsa_type=3 link_state_id={loopback} advertising_router={OSPF_ROUTER_ID}"
    ))
    .await?;
    a.wait(&format!(
        "ospf lsa prematurely aged.*lsa_type=4 link_state_id={OSPF_ROUTER_ID_C} advertising_router={OSPF_ROUTER_ID}"
    ))
    .await
}

/// Polls `r`'s `GET /v1/ospf/database` until one LSA satisfies `pred` (60s).
async fn wait_lsa(
    r: &Router,
    what: &str,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..60 {
        let body = r
            .rest_expect(Method::GET, "/v1/ospf/database", None, 200)
            .await?;
        let report: serde_json::Value = serde_json::from_str(&body)?;
        if report[0]["result"]
            .as_array()
            .into_iter()
            .flatten()
            .any(&pred)
        {
            return Ok(());
        }
        last = body;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("{}: no {what} in its database: {last}", r.name())
}

/// #608 / RFC 2328 A.3.2 against an independent implementation, self-contained.
/// FRR (`router-f`, priority 0, so never DR/BDR) joins the OSPF broadcast
/// domain through a dot1q 400 sub-interface of its `NET` interface; router-b
/// (higher router-id) becomes DR and router-a BDR. Router IDs (9.9.9.x) differ
/// from the bridge addresses (203.0.113.x), so FRR only identifies the DR/BDR,
/// and only forms Full adjacencies as a DROther, if router-a/b's Hellos carry
/// their interface addresses: FRR's own `drAddress`/`bdrAddress` must be those.
pub async fn ospf_dr_frr(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    // #887: a router-c left running by an earlier phase is still on the
    // bd-ospf segment (9.9.9.8, priority 1); whoever comes up first wins the
    // BDR election, so it could take BDR from router-a and leave router-a a
    // DROther that stays 2-Way with FRR. Only a/b/f may be on the segment.
    w.remove(C).await;
    let (a, b) = (w.a()?, w.b()?);
    let mut fa = ospf_instance_only(OSPF_ROUTER_ID);
    fa.extend(ospf_broadcast(OSPF_BROADCAST_ADDRESS_A));
    a.provision_flags(&with_base(A, fa)).await?;
    let mut fb = ospf_instance_only(OSPF_ROUTER_ID_B);
    fb.extend(ospf_broadcast(OSPF_BROADCAST_ADDRESS_B));
    b.provision_flags(&with_base(B, fb)).await?;

    w.dock.container_remove("router-f").await;
    w.dock.container_remove("router-g").await;
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    let full0 = format!(
        "ospf neighbor reached full link=broadcast-domain:{BD} neighbor={OSPF_ROUTER_ID_F}"
    );
    let (fa0, fb0) = (a.count_fresh(&full0).await, b.count_fresh(&full0).await);
    let dr0 = b
        .count_fresh(&format!(
            "ospf interface became dr link=broadcast-domain:{BD} dr={OSPF_ROUTER_ID_B}"
        ))
        .await;
    let conf = format!(
        "frr defaults traditional\nhostname router-f\n!\n\
         interface eth0.{OSPF_BROADCAST_TAG}\n ip ospf area {OSPF_AREA}\n ip ospf priority 0\nexit\n!\n\
         router ospf\n ospf router-id {OSPF_ROUTER_ID_F}\nexit\n"
    );
    let setup = format!(
        "ip link add link eth0 name eth0.{OSPF_BROADCAST_TAG} type vlan id {OSPF_BROADCAST_TAG} && \
         ip addr add {OSPF_BROADCAST_ADDRESS_F} dev eth0.{OSPF_BROADCAST_TAG} && \
         ip link set eth0.{OSPF_BROADCAST_TAG} up && \
         sed -i 's/^ospfd=no/ospfd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start"
    );
    w.dock
        .start_plain_caps(
            "router-f",
            FRR_IMAGE,
            NET,
            IP_G.s(),
            &["sh", "-c", &setup],
            ("/etc/frr", "frr.conf", conf.as_bytes()),
            &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        )
        .await?;

    let link = format!("link=broadcast-domain:{BD}");
    let full = format!("ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_F}");
    // FRR cold-starts and a broadcast interface waits RouterDeadInterval (40s)
    // before DR election: 120s, not the default 60s (#1468).
    let waited = async {
        b.wait_new(
            &format!("ospf interface became dr {link} dr={OSPF_ROUTER_ID_B}"),
            dr0,
            120,
        )
        .await?;
        a.wait_new(&full, fa0, 120).await?;
        b.wait_new(&full, fb0, 120).await
    }
    .await;
    if let Err(e) = waited {
        let mut dump: Vec<String> = Vec::new();
        for c in ["show ip ospf neighbor", "show ip ospf interface"] {
            let out = w.dock.exec("router-f", &["vtysh", "-c", c]).await;
            dump.push(format!(
                "\n--- FRR `{c}`:\n{}",
                out.map_or_else(|e| e.to_string(), |o| o.1)
            ));
        }
        for (r, pat) in [
            (a, "ospf interface\\|ospf neighbor"),
            (b, "ospf interface\\|ospf neighbor"),
        ] {
            dump.push(format!(
                "\n--- {} last lines:\n{}",
                r.name(),
                r.tail(pat, 15).join("\n")
            ));
        }
        bail!("{e:#}{}", dump.join(""));
    }
    let ifc = format!("show ip ospf interface eth0.{OSPF_BROADCAST_TAG} json");
    let dr = OSPF_BROADCAST_ADDRESS_B.split('/').next().unwrap();
    let bdr = OSPF_BROADCAST_ADDRESS_A.split('/').next().unwrap();
    frr_until(w, &ifc, 60, |out| {
        let out: String = out.chars().filter(|c| !c.is_whitespace()).collect();
        out.contains(&format!("\"drAddress\":\"{dr}\""))
            && out.contains(&format!("\"bdrAddress\":\"{bdr}\""))
            && out.contains(&format!("\"drId\":\"{OSPF_ROUTER_ID_B}\""))
    })
    .await
}

/// RFC 5250 opaque LSAs against a real third-party router, self-contained.
/// FRR (`router-f`) peers router-a over router-a's eth1 on its own network
/// and originates a type 10 (segment routing's Extended Link, opaque type 8)
/// and a type 11 (Router Information, AS scope) — which FRR only does once a
/// neighbor's DBD carried the O-bit — then a type 9 (an RFC 3623 Grace-LSA, `graceful-restart
/// prepare`, which FRR sends without restarting). router-a must install all
/// three, flood the type 10 and 11 on to router-b over eth0.0, and never the
/// type 9 (link-local scope).
pub async fn ospf_opaque(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    if !w.dock.network_exists(NET_OSPF_FRR).await {
        w.dock
            .network_create(NET_OSPF_FRR, &[OSPF_FRR_SUBNET.s()], false)
            .await?;
    }
    w.dock
        .network_connect_ip(NET_OSPF_FRR, "router-a", OSPF_FRR_IP_A.s())
        .await?;
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    // eth1 is router-a's second subinterface: its own base flags with eth1's
    // address instead of eth0's, the same instance/area/profile attached.
    let mut eth1 = strings(&[
        "--interface",
        "eth1",
        "--address",
        &format!("{OSPF_FRR_IP_A}/24"),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_B.to_string(),
        "--peer",
        IP_B.s(),
    ]);
    eth1.extend(ospf(OSPF_ROUTER_ID));
    a.provision_flags(&eth1).await?;
    both_full_p2p(a, b).await?;

    log("starting FRR (router-f) on router-a's eth1");
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    // Not `mpls-te` for the type 10: FRR 10.7.1's ospfd segfaults with it
    // here (in `ospf_read`, and with `router-info as` in type-11 origination).
    let conf = format!(
        "frr defaults traditional\nhostname router-f\n!\n\
         interface eth0\n ip ospf network point-to-point\n ip ospf area {OSPF_AREA}\nexit\n!\n\
         router ospf\n ospf router-id {OSPF_ROUTER_ID_F}\n capability opaque\n \
         router-info as\n segment-routing on\n \
         graceful-restart grace-period 120\nexit\n"
    );
    w.dock
        .start_plain_caps(
            "router-f",
            FRR_IMAGE,
            NET_OSPF_FRR,
            OSPF_FRR_IP_F.s(),
            &[
                "sh",
                "-c",
                "sed -i 's/^ospfd=no/ospfd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start",
            ],
            ("/etc/frr", "frr.conf", conf.as_bytes()),
            &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        )
        .await?;

    let link = "link=eth1.0";
    a.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_F}"
    ))
    .await?;
    // "installed on `at` (link and neighbor), of type `t`, originated by FRR"
    let from_frr = |at: &str, t: u8| {
        format!("ospf lsa installed {at} lsa_type={t} .*advertising_router={OSPF_ROUTER_ID_F} ")
    };
    let on_a = format!("{link} neighbor={OSPF_ROUTER_ID_F}");
    let on_b = format!("link=eth0.0 neighbor={OSPF_ROUTER_ID}");
    for t in [10, 11] {
        a.wait(&from_frr(&on_a, t)).await?;
        // Flooded on by router-a, which set the O-bit in its DBD to router-b.
        b.wait(&from_frr(&on_b, t)).await?;
    }

    // RFC 7770: router-a's own Router Information LSA (type 10, opaque type
    // 4, one 8-byte capabilities TLV) reaches router-b and FRR. FRR 10.7
    // decodes an RI body only in the scope of its own `router-info` (AS
    // here; `router-info area` is turned into `as`), so it is checked to the
    // header and length; `lsa::tests` pins the body bytes.
    log("router-a originates a router information lsa; router-b and FRR must accept it");
    b.wait(&format!(
        r"ospf lsa installed {on_b} lsa_type=10 link_state_id=4\.0\.0\.0 advertising_router={OSPF_ROUTER_ID} "
    ))
    .await?;
    frr_until(
        w,
        &format!("show ip ospf database opaque-area adv-router {OSPF_ROUTER_ID}"),
        60,
        |out| {
            out.contains("Link State ID: 4.0.0.0")
                && out.contains("Length: 28")
                && out.contains("Opaque-Type 4 (Router Information LSA)")
        },
    )
    .await?;

    // RFC 6987 against an independent SPF: with router-a a stub router, FRR
    // (whose only way to router-b is through router-a) reaches router-b's
    // loopback at a cost of at least 65535 — used, since it is the only path
    // — while router-a's own eth0.0 subnet (a type-3 stub, which keeps its
    // cost) stays cheap.
    log("router-a: max-metric router-lsa administrative; FRR must route through it at >= 65535");
    let lo = OSPF_SPF_LOOPBACK_ADDRESS;
    b.provision(&[
        "--loopback-address",
        lo,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    frr_until(w, "show ip ospf route", 60, |out| {
        frr_route_cost(out, lo).is_some_and(|c| c < 65535)
    })
    .await?;
    let max_metric = |on: bool| {
        strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID,
            "--ospf-max-metric-administrative",
            &on.to_string(),
        ])
    };
    a.provision(&max_metric(true)).await?;
    frr_until(w, "show ip ospf route", 60, |out| {
        frr_route_cost(out, lo).is_some_and(|c| c >= 65535)
            && frr_route_cost(out, SUBNET.s()).is_some_and(|c| c < 65535)
    })
    .await?;
    a.provision(&max_metric(false)).await?;
    frr_until(w, "show ip ospf route", 60, |out| {
        frr_route_cost(out, lo).is_some_and(|c| c < 65535)
    })
    .await?;

    // RFC 8770 §5 against a router without host-router support: FRR's RI
    // lacks bit 7, so router-b sees router-a's H-bit but doesn't honour it,
    // and FRR still routes through router-a over its 65535 transit links.
    log("router-a: host-router; router-b must not honour it (FRR lacks support), FRR routes via it at >= 65535");
    let host_router = |on: bool| {
        strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID,
            "--ospf-host-router",
            &on.to_string(),
        ])
    };
    a.provision(&host_router(true)).await?;
    b.wait(&format!(
        "ospf host-bit state changed area={OSPF_AREA} honoured=false host_routers=1"
    ))
    .await?;
    frr_until(w, "show ip ospf route", 60, |out| {
        frr_route_cost(out, lo).is_some_and(|c| c >= 65535)
            && frr_route_cost(out, SUBNET.s()).is_some_and(|c| c < 65535)
    })
    .await?;
    a.provision(&host_router(false)).await?;
    frr_until(w, "show ip ospf route", 60, |out| {
        frr_route_cost(out, lo).is_some_and(|c| c < 65535)
    })
    .await?;
    b.provision(&["--clear-ospf-loopback-profile"]).await?;

    // RFC 2328 A.4.2 (#34): router-a becomes an ASBR (a redistributed static)
    // and an ABR (a loopback in area 1). FRR builds a router route — needed to
    // resolve a Type-5's ASBR or a Type-3's ABR — only from a Router-LSA with
    // E or B set, so without the bits it never lists router-a as a border
    // router nor installs either prefix.
    log("making router-a an asbr and an abr; FRR must see its E and B bits");
    a.provision_flags(&with_base(
        A,
        specific(asbr(strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID,
            "--ospf-area",
            OSPF_AREA_1,
            "--ospf-profile",
            OSPF_PROFILE_AREA1,
            "--loopback-address",
            OSPF_ABR_LOOPBACK_ADDRESS,
            "--ospf-loopback-profile",
            OSPF_PROFILE_AREA1,
        ]))),
    ))
    .await?;
    frr_until(w, "show ip ospf border-routers", 60, |out| {
        out.lines()
            .any(|l| l.contains(OSPF_ROUTER_ID) && l.contains("ABR,") && l.contains("ASBR"))
    })
    .await?;
    // ASBR_PREFIX_SPECIFIC travels at a host-bits link state id (RFC 2328
    // Appendix E): FRR must still read it as its own prefix.
    frr_until(w, "show ip ospf route", 60, |out| {
        out.contains(ASBR_PREFIX)
            && out.contains(ASBR_PREFIX_SPECIFIC)
            && out.contains(OSPF_ABR_LOOPBACK_ADDRESS)
    })
    .await?;

    // The other direction: FRR's own overlapping pair, one of them at a
    // host-bits link state id, must become two routes with the right prefixes.
    log("FRR redistributes two overlapping statics; router-a must learn both");
    let (code, out) = w
        .dock
        .exec(
            "router-f",
            &[
                "vtysh",
                "-c",
                "configure terminal",
                "-c",
                &format!("ip route {OSPF_FRR_EXTERNAL_WIDE} blackhole"),
                "-c",
                &format!("ip route {OSPF_FRR_EXTERNAL_NARROW} blackhole"),
                "-c",
                "router ospf",
                "-c",
                "redistribute static",
            ],
        )
        .await?;
    anyhow::ensure!(code == 0, "FRR static redistribution failed: {out}");
    // Any non-zero last octet: .127 (the /25) or .255 (the /24), depending
    // on FRR's origination order.
    a.wait(&format!(
        r"ospf lsa installed {on_a} lsa_type=5 link_state_id=198\.18\.100\.[1-9][0-9]* .*advertising_router={OSPF_ROUTER_ID_F} "
    ))
    .await?;
    for prefix in [OSPF_FRR_EXTERNAL_WIDE, OSPF_FRR_EXTERNAL_NARROW] {
        a.wait(&format!("added route prefix={prefix} .*source=Some(Ospf)"))
            .await?;
    }

    // FRR's default type-2 redistribution (#214): router-a floods FRR's LSA
    // to router-b with the E bit intact, so FRR never sees an echo as newer
    // and re-originates (every 5s) — no new install of it on either router.
    log("FRR's type-2 externals are not re-originated after nos floods them");
    let from_frr5 =
        format!(r"ospf lsa installed .* lsa_type=5 .*advertising_router={OSPF_ROUTER_ID_F} ");
    b.wait(&from_frr5).await?;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let (a5, b5) = (a.count(&from_frr5), b.count(&from_frr5));
    a.assert_quiet(&from_frr5, a5, 15).await?;
    b.assert_quiet(&from_frr5, b5, 1).await?;

    // RFC 2328 §16.4 step 3 (#215): FRR sets the forwarding address to its
    // static's next hop, an unused address on the shared OSPF subnet.
    log("a forwarding address is honoured: router-a routes via it, not via FRR");
    let (code, out) = w
        .dock
        .exec(
            "router-f",
            &[
                "vtysh",
                "-c",
                "configure terminal",
                "-c",
                &format!("ip route {OSPF_FRR_FA_PREFIX} {OSPF_FRR_FA}"),
            ],
        )
        .await?;
    anyhow::ensure!(code == 0, "FRR forwarding-address static failed: {out}");
    a.wait(&format!(
        r"added route prefix={} gateway={OSPF_FRR_FA} .*source=Some(Ospf)",
        OSPF_FRR_FA_PREFIX.replace('.', r"\.")
    ))
    .await?;

    log("FRR announces a graceful restart: a type-9 grace-lsa, link-local");
    let b9 = b.count(&from_frr(".*", 9));
    let (code, out) = w
        .dock
        .exec(
            "router-f",
            &["vtysh", "-c", "graceful-restart prepare ip ospf"],
        )
        .await?;
    anyhow::ensure!(code == 0, "graceful-restart prepare failed: {out}");
    a.wait(&from_frr(&on_a, 9)).await?;
    a.wait(&format!(
        "ospf helper: grace period entered {link} neighbor={OSPF_ROUTER_ID_F} grace_period=120"
    ))
    .await?;
    // Three RXMT_INTERVALs of periodic resend: never flooded past eth1.
    b.assert_quiet(&from_frr(".*", 9), b9, 15).await?;

    let body = a
        .rest_expect(Method::GET, "/v1/ospf/database", None, 200)
        .await?;
    let report: serde_json::Value = serde_json::from_str(&body)?;
    let mut types: Vec<u64> = report[0]["result"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("ospf database has no result: {body}"))?
        .iter()
        .filter(|row| row["advertising_router"] == OSPF_ROUTER_ID_F)
        .filter_map(|row| row["lsa_type"].as_u64())
        .filter(|t| *t >= 9)
        .collect();
    types.sort_unstable();
    anyhow::ensure!(
        types == [10, 11],
        "router-a's database lists FRR opaque types {types:?}, want [10, 11]: {body}"
    );

    w.dock.container_remove("router-f").await;
    // Give eth1 back: left attached, router-a's eth1 is this FRR network's
    // veth-less NIC, so `link_veths` (ospfv3's second link) reuses it in place
    // of a veth to router-b and that adjacency never forms (#456).
    w.dock.network_disconnect(NET_OSPF_FRR, "router-a").await;
    // Likewise the `redistribute from static to ospf` rule set above:
    // `ospfv3-asbr` waits for a *new* Type-5 origination, and re-applying an
    // identical rule originates nothing.
    a.provision(&["--clear-redistribute-to-ospf"]).await?;
    Ok(())
}

/// Adds ASBR_PREFIX_SPECIFIC next to `asbr`'s ASBR_PREFIX: an overlapping
/// pair, so one of the two Type-5s carries a host-bits link state id.
fn specific(mut f: Vec<String>) -> Vec<String> {
    f.extend(strings(&["--static-route", ASBR_PREFIX_SPECIFIC]));
    f
}

/// Polls `vtysh -c <cmd>` on router-f every second until `ok` holds.
/// The cost FRR's `show ip ospf route` lists for `prefix`
/// (`N    203.0.113.80/32    [65537] area: 0.0.0.0`).
fn frr_route_cost(out: &str, prefix: &str) -> Option<u32> {
    out.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.nth(1)? == prefix).then_some(())?;
        words
            .next()?
            .strip_prefix('[')?
            .strip_suffix(']')?
            .parse()
            .ok()
    })
}

pub(super) async fn frr_until(
    w: &World,
    cmd: &str,
    secs: u64,
    ok: impl Fn(&str) -> bool,
) -> anyhow::Result<()> {
    let mut out = String::new();
    for _ in 0..secs {
        out = w.dock.exec("router-f", &["vtysh", "-c", cmd]).await?.1;
        if ok(&out) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("FRR `{cmd}` never matched within {secs}s:\n{out}")
}

// --- OSPFv3 (RFC 5340) ---

/// `ospf_mtu_pagination` for `OSPFv3`, self-contained: a real
/// `Ospfv3Profile.mtu` override alone (200, no `--dbd-max-headers`) drives
/// `exchange::mtu_based_max_headers`, and router-a redistributes
/// `OSPFV3_SPLIT_ROUTES` statics (AS-External-LSAs) so the LSU/LSR/LSAck are
/// also cut to the MTU (#807): router-a must log `ospfv3 lsu split` and
/// router-b must learn the last prefix, which one oversize LSU would lose.
pub async fn ospfv3_mtu_pagination(w: &mut World) -> anyhow::Result<()> {
    w.up(&["--ospfv3d-arg=--dbd-fault=drop:2,dup:3"]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let mtu = |mut f: Vec<String>| {
        f.extend(strings(&[
            "--ospfv3-profile-mtu",
            &OSPF_SPLIT_MTU_VALUE.to_string(),
        ]));
        f
    };
    let prefix = |i: usize| format!("2001:db8:{:x}::/48", 0x100 + i);
    let mut a_flags = mtu(ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID));
    for i in 0..OSPFV3_SPLIT_ROUTES {
        a_flags.extend(strings(&["--static-route", &prefix(i)]));
    }
    a_flags.extend(strings(&[
        "--static-gateway",
        OSPFV3_ASBR_GATEWAY,
        "--redistribute-to-ospfv3",
    ]));
    let split = "ospfv3 lsu split.*packets=";
    let split_a = a.count(split);
    let last = format!(
        "added route prefix={}.*source=Some(Ospf)",
        prefix(OSPFV3_SPLIT_ROUTES - 1)
    );
    a.provision_flags(&with_base(A, a_flags)).await?;
    b.provision_flags(&with_base(
        B,
        mtu(ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)),
    ))
    .await?;
    paginated_with(a, b, "ospfv3 dbd chunk sent, more remaining").await?;
    a.wait(&format!(
        "ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    a.wait_new(split, split_a, 60).await?;
    b.wait(&last).await?;
    dbd_faults_survived(a, b, "ospfv3").await
}

/// #853, self-contained: `nos-ospfv3d --router-lsa-max-links=1` (test-only)
/// splits router-a's Router-LSA, which carries two links (the `eth0.0`
/// point-to-point and the bridge's transit link, both `Full` with router-b),
/// into fragments with Link State IDs router-id and 0.0.0.1. Router-a lists
/// both over REST; router-b installs fragment 1 and still holds the routes
/// behind both links. Which link sits in which fragment is HashMap order, so
/// only the aggregate is asserted.
pub async fn ospfv3_router_lsa_split(w: &mut World) -> anyhow::Result<()> {
    w.up(&["--ospfv3d-arg=--router-lsa-max-links=1"]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let a_flags = |mut f: Vec<String>, svi4, svi6| {
        f.extend(ospfv3_broadcast_with_l2(svi4, svi6));
        f
    };
    let a_split = a.count("ospfv3 router-lsa split");
    let installed = either_form(0x2001, LSA_TYPE_E_ROUTER, |t| {
        format!(
            "ospfv3 lsa installed.*lsa_type={t} .*link_state_id=0.0.0.1.*advertising_router={OSPFV3_ROUTER_ID}"
        )
    });
    a.provision_flags(&with_base(
        A,
        a_flags(
            ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
            OSPF_BROADCAST_ADDRESS_A,
            OSPFV3_BROADCAST_ADDRESS_A,
        ),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        a_flags(
            ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
            OSPF_BROADCAST_ADDRESS_B,
            OSPFV3_BROADCAST_ADDRESS_B,
        ),
    ))
    .await?;
    let link = format!("link=broadcast-domain:{BD}");
    for (x, peer) in [(a, OSPFV3_ROUTER_ID_B), (b, OSPFV3_ROUTER_ID)] {
        x.wait(&format!(
            "ospfv3 neighbor reached full link=eth0.0 neighbor={peer}"
        ))
        .await?;
        x.wait(&format!(
            "ospfv3 neighbor reached full {link} neighbor={peer}"
        ))
        .await?;
    }
    a.wait_new("ospfv3 router-lsa split", a_split, 60).await?;
    b.wait(&installed).await?;

    // Router-a's own database: both fragments, advertised by itself.
    let mut ids = Vec::new();
    for _ in 0..30 {
        let body = a
            .rest_expect(Method::GET, "/v1/ospfv3/database", None, 200)
            .await?;
        let report: serde_json::Value = serde_json::from_str(&body)?;
        ids = report[0]["result"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("ospfv3 database has no result: {body}"))?
            .iter()
            .filter(|r| {
                r["advertising_router"] == OSPFV3_ROUTER_ID
                    && r["age"].as_u64().is_none_or(|age| age < 3600)
                    && matches!(r["lsa_type"].as_u64(), Some(0x2001 | 0xA021))
            })
            .filter_map(|r| r["link_state_id"].as_str().map(str::to_string))
            .collect();
        if ids.iter().any(|i| i == OSPFV3_ROUTER_ID) && ids.iter().any(|i| i == "0.0.0.1") {
            log(format!("router-a holds router-lsa fragments {ids:?}"));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("router-a never listed router-lsa fragments {OSPFV3_ROUTER_ID} and 0.0.0.1: {ids:?}")
}

/// RFC 7166: matching HMAC-SHA-256 trailer keys on both routers' eth0.0
/// profile reach/stay Full with real per-packet digest checks; a mismatched
/// key on router-a logs a real verification failure on router-b and blocks a
/// new Full; restoring it lets Full form again. `ospf_auth` minus its RFC
/// 7474 half (no OSPFv3 equivalent). Requires `ospfv3` to have run. Leaves
/// the profile unauthenticated again, for `ospfv3-dr`'s keyless router-c.
pub async fn ospfv3_auth(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let full =
        |neighbor: &str| format!("ospfv3 neighbor reached full link=eth0.0 neighbor={neighbor}");
    let with_key = |k: &str, addr: &str, rid: &str| {
        let mut f = ospfv3(addr, rid);
        f.extend([
            "--ospfv3-crypto-key".to_string(),
            format!("300:hmac-sha256:{k}"),
        ]);
        f
    };
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    log("configuring a matching rfc 7166 key (sa id 300, hmac-sha256) on both routers");
    a.provision_flags(&with_base(
        A,
        with_key("topsecretkey", OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        with_key("topsecretkey", OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
    ))
    .await?;
    a.wait("ospfv3 link driver started link=eth0.0.*authenticated=true")
        .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await?;

    let before = a.count(&full(OSPFV3_ROUTER_ID_B));
    let failures = b.count("ospfv3 packet authentication failed link=eth0.0");
    log("reconfiguring router-a with a mismatched key");
    a.provision_flags(&with_base(
        A,
        with_key("wrong-key", OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    b.wait_new(
        "ospfv3 packet authentication failed link=eth0.0",
        failures,
        30,
    )
    .await?;
    log("waiting 8s to confirm no new ospfv3 full adjacency forms with mismatched keys");
    a.assert_quiet(&full(OSPFV3_ROUTER_ID_B), before, 8).await?;

    log("restoring the matching key on router-a");
    a.provision_flags(&with_base(
        A,
        with_key("topsecretkey", OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), before, 60).await?;

    log("the secrets live in the admin keystore only: not in the config view, not in any log (#509)");
    for r in [a, b] {
        no_leak(r, &["topsecretkey", "wrong-key"]).await?;
    }

    log("rotating the secret under the same admin label on both routers re-forms Full");
    let rotated = "rotated-v3-secret";
    let before = a.count(&full(OSPFV3_ROUTER_ID_B));
    a.provision_flags(&with_base(
        A,
        with_key(rotated, OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        with_key(rotated, OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
    ))
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), before, 60).await?;
    for r in [a, b] {
        no_leak(r, &[rotated]).await?;
    }
    let replays = a.count("ospfv3 packet crypto sequence number not increasing");
    a.assert_quiet(
        "ospfv3 packet crypto sequence number not increasing",
        replays,
        5,
    )
    .await?;

    // RFC 7166 §4.1 (#612): a SIGKILLed nos-ospfv3d takes a higher persisted
    // boot count (high 32 bits of the trailer sequence), so router-a's replay
    // check accepts the respawn instead of dropping it as a replay.
    let before = a.count(&full(OSPFV3_ROUTER_ID_B));
    let drivers = b.count("ospfv3 link driver started link=eth0.0.*authenticated=true");
    let replays = a.count("ospfv3 packet crypto sequence number not increasing");
    log("killing router-b's nos-ospfv3d; it must return to Full without replay drops");
    w.dock.kill_process("router-b", "nos-ospfv3d").await?;
    b.wait_new(
        "ospfv3 link driver started link=eth0.0.*authenticated=true",
        drivers,
        60,
    )
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), before, 90).await?;
    a.assert_quiet(
        "ospfv3 packet crypto sequence number not increasing",
        replays,
        5,
    )
    .await?;

    // `provision_flags` edits on top of the running config, so leaving the
    // flag out would keep the key: clear it, since `ospfv3-dr` reuses this
    // profile on the bridge with a keyless router-c (#138).
    log("clearing the rfc 7166 key on both routers");
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    for r in [a, b] {
        r.edit(|c| {
            nos_proto::Ospfv3ProfileOp::ClearAuth {
                instance: OSPFV3_INSTANCE.into(),
                area_id: OSPFV3_AREA.parse()?,
                name: OSPFV3_PROFILE.into(),
            }
            .apply(c)
            .map_err(|e| anyhow::anyhow!("{e}"))
        })
        .await?;
    }
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await
}

/// RFC 5340 A.3.3 Interface MTU check, `ospf-mtu-mismatch`'s twin (requires
/// `ospfv3`, runs after `ospfv3-auth`).
pub async fn ospfv3_mtu_mismatch(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let full =
        |neighbor: &str| format!("ospfv3 neighbor reached full link=eth0.0 neighbor={neighbor}");
    let reject = "ospfv3 dbd rejected.*local_mtu=1400 neighbor_mtu=1500";
    let with = |extra: &[&str]| {
        let mut f = ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID);
        f.extend(strings(extra));
        with_base(A, f)
    };
    let trimmed = "ospf dbd summary trimmed removed=";
    let (trim_a, trim_b) = (a.count(trimmed), w.b()?.count(trimmed));
    let (before, rejects) = (a.count(&full(OSPFV3_ROUTER_ID_B)), a.count(reject));
    log("setting mtu 1400 on router-a's profile only");
    a.provision_flags(&with(&["--ospfv3-profile-mtu", "1400"]))
        .await?;
    a.wait_new(reject, rejects, 60).await?;
    log("waiting 30s to confirm no new ospfv3 full adjacency forms with a larger neighbor mtu");
    a.assert_quiet(&full(OSPFV3_ROUTER_ID_B), before, 30)
        .await?;

    log("setting mtu-ignore on router-a");
    a.provision_flags(&with(&["--ospfv3-mtu-ignore", "true"]))
        .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), before, 60).await?;
    // #1140 (RFC 5243, shared code): the re-formed adjacency met populated
    // LSDBs, so one side trimmed its summary.
    if a.wait_new(trimmed, trim_a, 5).await.is_err()
        && w.b()?.wait_new(trimmed, trim_b, 5).await.is_err()
    {
        bail!("no ospfv3 dbd summary was ever trimmed (RFC 5243)");
    }

    log("clearing the mtu override and mtu-ignore");
    let before = a.count(&full(OSPFV3_ROUTER_ID_B));
    a.edit(|c| {
        let (instance, area_id, name) = (
            OSPFV3_INSTANCE.to_string(),
            OSPFV3_AREA.parse()?,
            OSPFV3_PROFILE.to_string(),
        );
        nos_proto::Ospfv3ProfileOp::SetMtuIgnore {
            instance: instance.clone(),
            area_id,
            name: name.clone(),
            enabled: false,
        }
        .apply(c)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        nos_proto::Ospfv3ProfileOp::ClearMtu {
            instance,
            area_id,
            name,
        }
        .apply(c)
        .map_err(|e| anyhow::anyhow!("{e}"))
    })
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), before, 60).await?;
    ospfv3_bridge_mtu(w).await
}

/// Passive interface (#1142, requires `ospfv3`, `ospf-passive`'s twin):
/// router-a attaches a second, passive profile to a routed subinterface
/// (`eth0.300`, `fd77:300::1/64`). Its prefix is advertised (router-b installs
/// it over the active link) but no link starts and no OSPFv3 event ever names
/// it; clearing `passive` starts the link in place, setting it again stops it;
/// the subinterface is deleted at the end.
pub async fn ospfv3_passive(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let tag = SUBINTERFACE_TAG;
    let link = format!("eth0.{tag}");
    let lan = "fd77:300::/64";
    let passive_p = "ospfv3-passive-profile";
    let flags = |extra: &[&str]| {
        let mut f = strings(&[
            "--address",
            SUBINTERFACE_ADDRESS,
            "--address6",
            "fd77:300::1/64",
            "--subinterface-tag",
            &tag.to_string(),
            "--routing-table",
            "rt1",
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--remote-as",
            &ASN_B.to_string(),
            "--peer",
            IP_B.s(),
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            OSPFV3_ROUTER_ID,
            "--ospfv3-area",
            OSPFV3_AREA,
            "--ospfv3-profile",
            passive_p,
            "--ospfv3-interface-profile",
            passive_p,
        ]);
        f.extend(strings(extra));
        f
    };
    let advertised = format!("ospfv3 passive interface advertised attach_point={link}");
    let started = format!("ospfv3 link driver started link={link}");
    let stopped = format!("ospfv3 link stopped link={link}");
    let route = format!("added route prefix={lan}.*source=Some(Ospf)");
    let (adv0, route0) = (a.count(&advertised), b.count(&route));

    log("attaching a passive profile to router-a's eth0.300");
    a.provision_flags(&flags(&["--ospfv3-passive", "true"]))
        .await?;
    a.wait_new(&advertised, adv0, 60).await?;
    b.wait_new(&route, route0, 60).await?;
    // #1212: "no link starts, no OSPF event names it". Not bare `link={link}`:
    // that also matches `kernel interface down ... reason=absent`, logged
    // while nos-interfaced has not yet created the device (`GET /v1/interfaces`
    // is config-derived, so it cannot tell when the device exists).
    let events = format!(
        "ospfv3 link driver started link={link}\\|ospfv3 link stopped link={link}\\|ospfv3 neighbor .*link={link}\\|ospfv3 hello.*link={link}"
    );
    a.assert_quiet(&events, a.count(&events), 15).await?;

    log("clearing passive: the link starts in place");
    let adv1 = a.count(&advertised);
    a.provision_flags(&flags(&["--ospfv3-passive", "false"]))
        .await?;
    a.wait(&started).await?;

    log("passive again: the link stops, the prefix returns");
    a.provision_flags(&flags(&["--ospfv3-passive", "true"]))
        .await?;
    a.wait(&stopped).await?;
    a.wait_new(&advertised, adv1, 60).await?;

    a.provision_flags(&strings(&[
        "--address",
        SUBINTERFACE_ADDRESS,
        "--subinterface-tag",
        &tag.to_string(),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_B.to_string(),
        "--peer",
        IP_B.s(),
        "--delete-subinterface",
    ]))
    .await?;
    // The profile would otherwise stay in the area and trip #1161's
    // "every profile's instance-id must be 64-95" in `ospfv3-instance-id`.
    a.edit(|c| {
        nos_proto::Ospfv3ProfileOp::Delete {
            instance: OSPFV3_INSTANCE.into(),
            area_id: OSPFV3_AREA.parse()?,
            name: passive_p.into(),
        }
        .apply(c)
        .map_err(|e| anyhow::anyhow!("{e}"))
    })
    .await?;
    Ok(())
}

/// RFC 5340 §A.3.1 Instance ID: instance-id 1 on router-a alone gets its
/// packets dropped by router-b (logged at debug) and no new Full forms; 1 on
/// both reaches Full with a non-zero id on the wire both ways. Requires
/// `ospfv3` to have run; leaves both back at 0 for `ospfv3-dr`'s router-c.
pub async fn ospfv3_instance_id(w: &mut World) -> anyhow::Result<()> {
    let result = ospfv3_instance_id_steps(w).await;
    keep_ospfv3_profiles(false);
    if result.is_err() {
        // A failed step must not leave instance-id != 0 on a/b: `ospfv3-dr`'s
        // router-c would never two-way with them. Best effort; the original
        // error wins.
        let (a, b) = (w.a()?, w.b()?);
        // Extra instances left by a failed step would break `ospfv3-dr` too.
        for r in [a, b] {
            if let Err(e) = drop_extra_instances(r).await {
                log(format!("extra instance cleanup failed: {e:#}"));
            }
        }
        for (r, id, addr, rid) in [
            (a, A, OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
            (b, B, OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
        ] {
            let mut f = ospfv3(addr, rid);
            f.extend(strings(&[
                "--ospfv3-instance-id",
                "0",
                "--ospfv3-address-family",
                "ipv6-unicast",
            ]));
            if let Err(e) = r.provision_flags(&with_base(id, f)).await {
                log(format!("instance-id restore failed: {e:#}"));
            }
        }
        // Apart: each errors when its static route is absent.
        let mut f = ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID);
        f.extend(strings(&[
            "--remove-static-route",
            OSPFV3_INSTANCE_2_PREFIX,
        ]));
        let _ = a.provision_flags(&with_base(A, f)).await;
        let mut f = ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B);
        f.extend(strings(&CLEAR_B_STATIC));
        let _ = b.provision_flags(&with_base(B, f)).await;
    }
    result
}

/// Router-b's static route into instance 1 and the rule feeding it, undone.
const CLEAR_B_STATIC: [&str; 5] = [
    "--remove-static-route",
    OSPFV3_INSTANCE_1_PREFIX,
    "--clear-redistribute-to-ospfv3",
    "--redistribute-to-ospfv3-instance",
    OSPFV3_INSTANCE,
];

/// Removes `ospfv3-instance-id`'s extra instances 3 and 2 (attach, claim,
/// section; the redistribute rule goes with the claim) from `r`. Every op that
/// finds nothing to remove is skipped, so it is safe on a clean lab.
async fn drop_extra_instances(r: &Router) -> anyhow::Result<()> {
    r.edit(|c| {
        for (inst, prof) in [
            (OSPFV3_INSTANCE_3, OSPFV3_PROFILE_3),
            (OSPFV3_INSTANCE_2, OSPFV3_PROFILE_2),
        ] {
            let _ = nos_proto::SubinterfaceOp::RemoveOspfv3Profile {
                interface: "eth0".into(),
                tag: 0,
                ospfv3_profile: prof.into(),
            }
            .apply(c);
            let _ = nos_proto::RoutingTableOp::RemoveOspfv3Instance {
                name: "rt1".into(),
                ospfv3_instance: inst.into(),
            }
            .apply(c);
            let _ = nos_proto::Ospfv3InstanceOp::Delete { name: inst.into() }.apply(c);
        }
        Ok(())
    })
    .await
    .map(drop)
}

/// Switches `extended-lsa` off on `r` (#1402): RFC 5838 AF instances use the
/// legacy LSA formats, so the validator rejects Full extended-lsa left on by
/// the `ospfv3` phase. An absent instance is fine (the error is ignored).
async fn ospfv3_extended_lsa_off(r: &Router) -> anyhow::Result<()> {
    r.edit(|c| {
        let _ = nos_proto::Ospfv3InstanceOp::SetExtendedLsa {
            name: OSPFV3_INSTANCE.into(),
            enabled: false,
        }
        .apply(c);
        Ok(())
    })
    .await
    .map(drop)
}

async fn ospfv3_instance_id_steps(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    // A lab left dirty by an aborted run: start from instance 1 alone.
    drop_extra_instances(a).await?;
    drop_extra_instances(b).await?;
    ospfv3_extended_lsa_off(a).await?;
    ospfv3_extended_lsa_off(b).await?;
    // `ospfv3-abr`/`-area-range` leave router-b's area-1 profile (instance-id
    // 0) behind; #1161's validator then refuses the ipv4-unicast step below
    // ("every profile's instance-id must be 64-95"). Drop the area if present.
    b.edit(|c| {
        // Absent area is fine (standalone run): the error is ignored.
        let _ = nos_proto::Ospfv3AreaOp::Delete {
            instance: OSPFV3_INSTANCE.into(),
            area_id: OSPFV3_AREA_1.parse()?,
        }
        .apply(c);
        Ok(())
    })
    .await?;
    let full =
        |neighbor: &str| format!("ospfv3 neighbor reached full link=eth0.0 neighbor={neighbor}");
    let with_id = |id: &str, addr: &str, rid: &str| {
        let mut f = ospfv3(addr, rid);
        f.extend(strings(&["--ospfv3-instance-id", id]));
        f
    };
    let mismatch =
        "ospfv3 packet instance id mismatch, dropping link=eth0.0.*received=1 expected=0";
    let (a_full, drops) = (a.count(&full(OSPFV3_ROUTER_ID_B)), b.count(mismatch));
    log("setting instance-id 1 on router-a only");
    a.provision_flags(&with_base(
        A,
        with_id("1", OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    b.wait_new(mismatch, drops, 30).await?;
    log("waiting 8s to confirm no new ospfv3 full adjacency forms with mismatched instance ids");
    a.assert_quiet(&full(OSPFV3_ROUTER_ID_B), a_full, 8).await?;

    log("setting instance-id 1 on router-b too");
    let b_full = b.count(&full(OSPFV3_ROUTER_ID));
    b.provision_flags(&with_base(
        B,
        with_id("1", OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
    ))
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await?;

    // RFC 5838: an IPv4-unicast instance (ids 64-95, AF-bit set) on router-a
    // alone is dropped by router-b (id 1); on both it reaches Full.
    let with_af = |af: &str, id: &str, addr: &str, rid: &str| {
        let mut f = with_id(id, addr, rid);
        f.extend(strings(&["--ospfv3-address-family", af]));
        f
    };
    log("setting the ipv4-unicast address family (instance-id 64) on router-a only");
    let drops = b.count("ospfv3 packet instance id mismatch, dropping link=eth0.0.*received=64");
    a.provision_flags(&with_base(
        A,
        with_af("ipv4-unicast", "64", OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    b.wait_new(
        "ospfv3 packet instance id mismatch, dropping link=eth0.0.*received=64",
        drops,
        30,
    )
    .await?;
    log("setting the ipv4-unicast address family on router-b too");
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    b.provision_flags(&with_base(
        B,
        with_af("ipv4-unicast", "64", OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
    ))
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await?;

    log("resetting to ipv6-unicast, instance-id 0 on both routers");
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    let with_id = |id: &str, addr: &str, rid: &str| with_af("ipv6-unicast", id, addr, rid);
    a.provision_flags(&with_base(
        A,
        with_id("0", OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        with_id("0", OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
    ))
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await?;
    keep_ospfv3_profiles(true);
    ospfv3_several_instances(w).await
}

/// `ospfv3-instance-id` second half (#1280): instances 2 (IPv6, id 1) and 3
/// (`ipv4-unicast`, id 64) on the same link as instance 1 (id 0), without
/// cross-talk, with each instance's routes surviving the others' SPF pushes
/// (#1277), then removed again so `ospfv3-dr` finds the lab as `ospfv3` left it.
#[allow(
    clippy::needless_range_loop,
    reason = "`s` also indexes the peer (1 - s)"
)]
async fn ospfv3_several_instances(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let full = |n: &str| format!("ospfv3 neighbor reached full link=eth0.0 neighbor={n}");
    let removed = |p: &str| format!("removed route prefix={p}");
    // (router, id, address, instance-1 rid, instance-2 rid, instance-3 rid)
    let sides = [
        (
            a,
            A,
            OSPFV3_ADDRESS_A,
            OSPFV3_ROUTER_ID,
            OSPFV3_RID_2_A,
            OSPFV3_RID_3_A,
        ),
        (
            b,
            B,
            OSPFV3_ADDRESS_B,
            OSPFV3_ROUTER_ID_B,
            OSPFV3_RID_2_B,
            OSPFV3_RID_3_B,
        ),
    ];
    let flags = |s: usize, extra: &[&str]| {
        let (_, id, addr, rid, ..) = sides[s];
        let mut f = ospfv3(addr, rid);
        f.extend(strings(extra));
        with_base(id, f)
    };
    let spec2 = |s: usize| format!("{OSPFV3_INSTANCE_2}:{}:{OSPFV3_PROFILE_2}:1", sides[s].4);
    let spec3 = |s: usize| {
        format!(
            "{OSPFV3_INSTANCE_3}:{}:{OSPFV3_PROFILE_3}:{OSPFV3_INSTANCE_3_ID}:ipv4",
            sides[s].5
        )
    };
    // Full lines per router: (instance 1, 2, 3) toward the peer's router-ids.
    let fulls = |s: usize| {
        let peer = sides[1 - s];
        [full(peer.3), full(peer.4), full(peer.5)]
    };
    let counts = |s: usize| fulls(s).map(|p| sides[s].0.count(&p));

    log("instance 2 (IPv6, id 1) next to instance 1 (id 0) on both routers");
    let base = [counts(0), counts(1)];
    // The Instance ID filter runs before authentication, so a shared link must
    // raise no authentication failure.
    let auth = "ospfv3 packet authentication failed\\|crypto sequence number not increasing";
    let auth0 = [a.count(auth), b.count(auth)];
    for s in 0..2 {
        sides[s]
            .0
            .provision_flags(&flags(s, &["--ospfv3-extra-instance", &spec2(s)]))
            .await?;
    }
    for s in 0..2 {
        sides[s].0.wait_new(&fulls(s)[1], base[s][1], 60).await?;
    }
    for s in 0..2 {
        sides[s].0.assert_quiet(&fulls(s)[0], base[s][0], 8).await?;
        sides[s].0.assert_quiet(auth, auth0[s], 1).await?;
    }

    log("routes of one instance survive the other's SPF pushes (#1277)");
    // Each router originates one static into one instance only and learns the
    // other's: router-b holds instance 2's route, router-a instance 1's.
    let (p1, p2) = (OSPFV3_INSTANCE_1_PREFIX, OSPFV3_INSTANCE_2_PREFIX);
    a.provision_flags(&flags(
        0,
        &[
            "--static-route",
            p2,
            "--static-gateway",
            OSPFV3_ASBR_GATEWAY,
            "--redistribute-to-ospfv3",
            "--redistribute-to-ospfv3-instance",
            OSPFV3_INSTANCE_2,
        ],
    ))
    .await?;
    b.provision_flags(&flags(
        1,
        &[
            "--static-route",
            p1,
            "--static-gateway",
            OSPFV3_GATEWAY_A,
            "--redistribute-to-ospfv3",
            "--redistribute-to-ospfv3-instance",
            OSPFV3_INSTANCE,
        ],
    ))
    .await?;
    // Polled, not a new log line: a leftover from an earlier failed run may
    // already have installed either route.
    for (r, p) in [(b, p2), (a, p1)] {
        for _ in 0..60 {
            if r.rt1_has(p, "Ospf").await? {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        if !r.rt1_has(p, "Ospf").await? {
            bail!("{} never installed {p}", r.name());
        }
    }
    // A cost change on instance 1 makes router-b recompute and push instance
    // 1's routes; instance 2's prefix must not be withdrawn by it.
    let (rm2, rm1) = (b.count(&removed(p2)), a.count(&removed(p1)));
    a.provision_flags(&flags(0, &["--ospfv3-profile-cost", "7"]))
        .await?;
    b.assert_quiet(&removed(p2), rm2, 15).await?;
    // And the other way round: instance 2's push on router-a leaves instance
    // 1's route there.
    a.edit(|c| {
        nos_proto::Ospfv3ProfileOp::SetCost {
            instance: OSPFV3_INSTANCE_2.into(),
            area_id: OSPFV3_AREA.parse()?,
            name: OSPFV3_PROFILE_2.into(),
            cost: 9,
        }
        .apply(c)
        .map_err(|e| anyhow::anyhow!("{e}"))
    })
    .await?;
    a.assert_quiet(&removed(p1), rm1, 15).await?;
    a.provision_flags(&flags(0, &["--ospfv3-profile-cost", "1"]))
        .await?;
    if !b.rt1_has(p2, "Ospf").await? || !a.rt1_has(p1, "Ospf").await? {
        bail!("a route was lost to the other instance's SPF push");
    }

    log("instance 3 (ipv4-unicast, id 64) next to instances 1 and 2");
    let base = [counts(0), counts(1)];
    for s in 0..2 {
        sides[s]
            .0
            .provision_flags(&flags(s, &["--ospfv3-extra-instance", &spec3(s)]))
            .await?;
    }
    for s in 0..2 {
        sides[s].0.wait_new(&fulls(s)[2], base[s][2], 60).await?;
    }
    for s in 0..2 {
        sides[s].0.assert_quiet(&fulls(s)[0], base[s][0], 8).await?;
        sides[s].0.assert_quiet(&fulls(s)[1], base[s][1], 1).await?;
    }

    log("removing instances 3 then 2: instance 1 stays Full");
    let base = [counts(0), counts(1)];
    let rm2 = b.count(&removed(p2));
    for (inst, prof) in [
        (OSPFV3_INSTANCE_3, OSPFV3_PROFILE_3),
        (OSPFV3_INSTANCE_2, OSPFV3_PROFILE_2),
    ] {
        for s in 0..2 {
            let spec = format!("{inst}:{prof}");
            sides[s]
                .0
                .provision_flags(&flags(s, &["--ospfv3-remove-extra-instance", &spec]))
                .await?;
        }
    }
    b.wait_new(&removed(p2), rm2, 60).await?;
    for s in 0..2 {
        sides[s].0.assert_quiet(&fulls(s)[0], base[s][0], 8).await?;
    }
    if !a.rt1_has(p1, "Ospf").await? {
        bail!("router-a lost instance 1's route {p1} when instances 2 and 3 were removed");
    }

    log("reset: no extra static route or redistribute rule left");
    a.provision_flags(&flags(0, &["--remove-static-route", p2]))
        .await?;
    b.provision_flags(&flags(1, &CLEAR_B_STATIC)).await
}

/// RFC 5838 IPv4 unicast address family (#1162; requires `ospfv3`): an
/// `ipv4-unicast` instance (id 64) next to instance 1 on both routers learns
/// router-b's IPv4 loopback over the IPv6 link-local transport and
/// router-a's `nos-ribd` installs it as an IPv4 route; clearing the
/// loopback removes it again.
pub async fn ospfv3_ipv4_af(w: &mut World) -> anyhow::Result<()> {
    keep_ospfv3_profiles(true);
    let result = ospfv3_ipv4_af_steps(w).await;
    keep_ospfv3_profiles(false);
    if result.is_err() {
        // Best effort; the original error wins.
        for r in [w.a()?, w.b()?] {
            if let Err(e) = drop_extra_instances(r).await {
                log(format!("extra instance cleanup failed: {e:#}"));
            }
        }
    }
    result
}

#[allow(
    clippy::needless_range_loop,
    reason = "`s` also indexes `sides` and the flag closures"
)]
async fn ospfv3_ipv4_af_steps(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    drop_extra_instances(a).await?;
    drop_extra_instances(b).await?;
    ospfv3_extended_lsa_off(a).await?;
    ospfv3_extended_lsa_off(b).await?;
    // (router, id, address, own rid, peer's rid in instance 3, own rid in instance 3)
    let sides = [
        (
            a,
            A,
            OSPFV3_ADDRESS_A,
            OSPFV3_ROUTER_ID,
            OSPFV3_RID_3_B,
            OSPFV3_RID_3_A,
        ),
        (
            b,
            B,
            OSPFV3_ADDRESS_B,
            OSPFV3_ROUTER_ID_B,
            OSPFV3_RID_3_A,
            OSPFV3_RID_3_B,
        ),
    ];
    let flags = |s: usize, extra: &[&str]| {
        let (_, id, addr, rid, ..) = sides[s];
        let mut f = ospfv3(addr, rid);
        f.extend(strings(extra));
        with_base(id, f)
    };
    let spec3 = |s: usize| {
        format!(
            "{OSPFV3_INSTANCE_3}:{}:{OSPFV3_PROFILE_3}:{OSPFV3_INSTANCE_3_ID}:ipv4",
            sides[s].5
        )
    };
    let full = format!("ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_RID_3_B}");
    let full0 = a.count(&full);
    log("adding the ipv4-unicast instance (id 64) on both routers");
    for s in 0..2 {
        sides[s]
            .0
            .provision_flags(&flags(s, &["--ospfv3-extra-instance", &spec3(s)]))
            .await?;
    }
    a.wait_new(&full, full0, 60).await?;

    let prefix = OSPFV3_IPV4_LOOPBACK;
    let route = format!("added route prefix={prefix}.*source=Some(Ospf)");
    let route0 = a.count(&route);
    log("router-b advertises an IPv4 loopback into the ipv4-unicast instance");
    b.provision(&[
        "--ospfv3-loopback-address",
        prefix,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE_3,
    ])
    .await?;
    a.wait_new(&route, route0, 60).await?;
    if !a.rt1_has(prefix, "Ospf").await? {
        bail!("router-a's rt1 has no OSPF candidate for {prefix}");
    }

    log("clearing the loopback withdraws the route");
    b.provision(&["--clear-ospfv3-loopback-profile", OSPFV3_PROFILE_3])
        .await?;
    b.provision(&["--loopback-remove-address", prefix]).await?;
    a.wait_ospf_route_gone(prefix, 3).await?;

    log("removing the extra instance again");
    for s in 0..2 {
        let spec = format!("{OSPFV3_INSTANCE_3}:{OSPFV3_PROFILE_3}");
        sides[s]
            .0
            .provision_flags(&flags(s, &["--ospfv3-remove-extra-instance", &spec]))
            .await?;
    }
    Ok(())
}

/// #957: router-b comes back under a new router-id from the same link-local
/// address on the point-to-point link. router-a evicts the old neighbor on the
/// first Hello, reaches Full with the new id, removes the old entry after the
/// dead interval and installs router-b's loopback; then the id is restored for
/// `ospfv3-bfd`/`-dr`/`-lfa`. Requires `ospfv3` to have run.
pub async fn ospfv3_p2p_rid_change(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let link = "link=eth0.0";
    let full = |n: &str| format!("ospfv3 neighbor reached full {link} neighbor={n}");
    let evicted = |n: &str| {
        format!("ospfv3 neighbor evicted, same address new router id {link} neighbor={n} ")
    };
    let removed = |n: &str| format!("ospfv3 neighbor entry removed {link} neighbor={n}");
    let b_flags = |rid: &str, loopback: bool| {
        let mut f = ospfv3(OSPFV3_ADDRESS_B, rid);
        if loopback {
            f.extend(strings(&[
                "--ospfv3-loopback-address",
                OSPFV3_LFA_LOOPBACK_ADDRESS,
                "--ospfv3-loopback-profile",
                OSPFV3_PROFILE,
            ]));
        }
        f
    };
    let route = format!("added route prefix={OSPFV3_LFA_LOOPBACK_ADDRESS}.*source=Some(Ospf)");

    for (old, new, loopback) in [
        (OSPFV3_ROUTER_ID_B, OSPFV3_ROUTER_ID_B_NEW, true),
        (OSPFV3_ROUTER_ID_B_NEW, OSPFV3_ROUTER_ID_B, false),
    ] {
        log(format!("router-b changes router-id {old} -> {new}"));
        let (evicted0, removed0, full0, route0) = (
            a.count(&evicted(old)),
            a.count(&removed(old)),
            a.count(&full(new)),
            a.count(&route),
        );
        b.provision_flags(&with_base(B, b_flags(new, loopback)))
            .await?;
        // The running link keeps its router-id: restart so the new one is used
        // (as `ospf-dr`'s renumbering does).
        w.dock.kill_process("router-b", "nos-ospfv3d").await?;
        a.wait_new(&evicted(old), evicted0, 60).await?;
        a.wait_new(&full(new), full0, 90).await?;
        // The old entry stays Down until a full dead interval of silence.
        a.wait_new(&removed(old), removed0, 90).await?;
        if loopback {
            a.wait_new(&route, route0, 60).await?;
        }
    }
    Ok(())
}

pub async fn ospfv3_phase(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    // RFC 5340 §4.2.2.1 (#650): a Hello with a mismatched hello-interval is
    // dropped before the neighbor reaches Init.
    let hello_interval = |secs: u16| {
        let mut f = ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B);
        f.extend(strings(&[
            "--ospfv3-profile-hello-interval",
            &secs.to_string(),
        ]));
        with_base(B, f)
    };
    let init_b =
        format!("ospfv3 neighbor state changed to init link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}");
    let init0 = a.count_fresh(&init_b).await;
    a.provision_flags(&with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)))
        .await?;
    b.provision_flags(&hello_interval(5)).await?;
    a.wait("dropping ospfv3 hello with mismatched hello-interval")
        .await?;
    log("confirming the mismatched-hello-interval ospfv3 neighbor never reaches init");
    a.assert_quiet(&init_b, init0, 8).await?;
    // Restore explicitly to the default (10s): a transaction builds on running config.
    log("restoring router-b's matching ospfv3 hello-interval");
    b.provision_flags(&hello_interval(10)).await?;

    a.wait(&format!(
        "ospfv3 instance config resolved instance={OSPFV3_INSTANCE}"
    ))
    .await?;
    a.wait(&format!(
        "ospfv3 area resolved instance={OSPFV3_INSTANCE} area={OSPFV3_AREA}"
    ))
    .await?;
    a.wait(&format!("ospfv3 profile resolved instance={OSPFV3_INSTANCE} area={OSPFV3_AREA} profile={OSPFV3_PROFILE}")).await?;

    a.wait(&format!(
        "ospfv3 neighbor reached two-way link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 neighbor reached two-way link=eth0.0 neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    a.wait(&format!(
        "ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    wait_instance(
        a,
        "/v1/ospfv3/instance",
        OSPFV3_ROUTER_ID,
        false,
        &[OSPFV3_AREA],
    )
    .await?;
    b.wait(&format!(
        "ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    assert_neighbor_fields(
        a,
        "ospfv3",
        "eth0.0",
        OSPFV3_ROUTER_ID_B,
        None,
        serde_json::Value::Null,
    )
    .await?;
    assert_interface_row(a, "ospfv3", "eth0.0").await?;
    a.wait(&format!(
        "ospfv3 lsa installed.*neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 lsa installed.*neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;

    // router-a's loopback: a destination with no neighbor of its own, so
    // router-b can only learn it via its own RFC 5340 §16 SPF computation.
    let route_pat = format!("added route prefix={OSPFV3_LOOPBACK_ADDRESS}.*source=Some(Ospf)");
    // #1247: the bound times the route push, not LSA origination pacing. Let
    // both routers' LSA churn settle for longer than MinLSInterval (5 s) so
    // the loopback's Intra-Area-Prefix-LSA is not held back by the pacing of
    // its previous instance, and anchor on that very LSA (0x2009 = 8201).
    let churn = "ospfv3 lsa installed\\|ospfv3 lsa originated";
    for _ in 0..10 {
        let n = (b.count_fresh(churn).await, a.count_fresh(churn).await);
        tokio::time::sleep(Duration::from_secs(6)).await;
        if (b.count_fresh(churn).await, a.count_fresh(churn).await) == n {
            break;
        }
    }
    let prefix_lsa = format!(
        "ospfv3 lsa installed.*neighbor={OSPFV3_ROUTER_ID}.*lsa_type=8201.*advertising_router={OSPFV3_ROUTER_ID}"
    );
    let route_before = b.count_fresh(&route_pat).await;
    let lsa_installed = b.count_fresh(&prefix_lsa).await;
    let (mark_a, mark_b) = (a.log_mark(), b.log_mark());
    a.provision(&[
        "--ospfv3-loopback-address",
        OSPFV3_LOOPBACK_ADDRESS,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ])
    .await?;
    a.wait("ospfv3 lsa originated").await?;
    b.wait_new(&prefix_lsa, lsa_installed, 60).await?;
    b.wait_new(&route_pat, route_before, 60).await?;
    expect_route(
        b,
        "/v1/ospfv3/routes",
        OSPFV3_LOOPBACK_ADDRESS,
        WantRoute {
            class: "intra-area",
            adv_router: OSPFV3_ROUTER_ID,
            hops: 0,
            e2_cost: None,
        },
    )
    .await?;
    // #190: pushed on the LSDB change, not on the next 2s poll.
    if let Err(e) = b.assert_delay_under(
        (&prefix_lsa, lsa_installed),
        (&route_pat, route_before),
        1000,
    ) {
        let mut entries = b
            .timeline_since(
                &format!("ospfv3 lsa installed\\|{route_pat}\\|ospfv3 spf"),
                mark_b,
            )
            .await;
        entries.extend(a.timeline_since("ospfv3 lsa originated", mark_a).await);
        let lines = format_timeline(entries, 60);
        for l in &lines {
            log(l);
        }
        bail!("{e}; timeline since provisioning:\n{}", lines.join("\n"));
    }

    // RFC 8362 Full mode on both routers: adjacency survives (mixed or not,
    // E-LSAs are known types), each originates E-LSAs, and the peer decodes
    // and installs them (E-Router 0xA021, E-Link 0x8028, E-Intra-Area-Prefix
    // 0xA029). The SPF side is covered by a unit test; a secondary address
    // below proves the E-Link/E-Intra-Area-Prefix prefixes route (#952).
    let e_pat = format!("ospfv3 lsa originated lsa_type={LSA_TYPE_E_ROUTER}");
    let (a_before, b_before) = (a.count(&e_pat), b.count(&e_pat));
    // The legacy Router-LSA (0x2001) each side flushes on the switch (#149).
    let flushed =
        |id: &str| format!("ospfv3 lsa maxage flushed.*lsa_type=8193 .*advertising_router={id}");
    let (a_flushed, b_flushed) = (
        a.count(&flushed(OSPFV3_ROUTER_ID_B)),
        b.count(&flushed(OSPFV3_ROUTER_ID)),
    );
    a.provision_flags(&with_base(
        A,
        [
            ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
            strings(&["--ospfv3-extended-lsa"]),
        ]
        .concat(),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        [
            ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
            strings(&["--ospfv3-extended-lsa"]),
        ]
        .concat(),
    ))
    .await?;
    a.wait_new(&e_pat, a_before, 60).await?;
    b.wait_new(&e_pat, b_before, 60).await?;
    for lsa_type in [0xA021u16, 0x8028, 0xA029] {
        b.wait(&format!(
            "ospfv3 lsa installed.*lsa_type={lsa_type}.*advertising_router={OSPFV3_ROUTER_ID}"
        ))
        .await?;
    }

    // RFC 2328 §14.1 on the switch (#149): each side prematurely ages its
    // own legacy set, the peer flushes it, and no legacy LSA from it is left.
    a.wait(&format!(
        "ospfv3 lsa prematurely aged lsa_type=8193 .*advertising_router={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 lsa prematurely aged lsa_type=8193 .*advertising_router={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    b.wait_new(&flushed(OSPFV3_ROUTER_ID), b_flushed, 30)
        .await?;
    a.wait_new(&flushed(OSPFV3_ROUTER_ID_B), a_flushed, 30)
        .await?;
    assert_no_legacy_lsas(b, OSPFV3_ROUTER_ID).await?;
    assert_no_legacy_lsas(a, OSPFV3_ROUTER_ID_B).await?;

    // #952: a secondary IPv6 address of router-b's attach point is advertised
    // (E-Link-LSA + E-Intra-Area-Prefix-LSA) and routed by router-a; removing
    // it withdraws the route. The address list is part of the wholesale-diffed
    // link config, so the link restarts each time: wait for both sides Full.
    let net = OSPFV3_EXTRA_NET_B;
    let (added, removed) = (
        format!("added route prefix={net}.*source=Some(Ospf)"),
        format!("removed route prefix={net}"),
    );
    let full = |peer: &str| format!("ospfv3 neighbor reached full link=eth0.0 neighbor={peer}");
    let b_flags = |extra: &[&str]| {
        with_base(
            B,
            [
                ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
                strings(&["--ospfv3-extended-lsa"]),
                strings(extra),
            ]
            .concat(),
        )
    };
    let (a_added, a_removed) = (a.count(&added), a.count(&removed));
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    b.provision_flags(&b_flags(&["--address6-extra", OSPFV3_EXTRA_PREFIX_B]))
        .await?;
    a.wait_new(&added, a_added, 60).await?;
    b.provision_flags(&b_flags(&[
        "--remove-address6-extra",
        OSPFV3_EXTRA_PREFIX_B,
    ]))
    .await?;
    a.wait_new(&removed, a_removed, 60).await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await?;
    ospfv3_link_state(w).await
}

/// Waits for a fresh `reconciled interfaces` on `r` (#1338): `nos-interfaced`
/// re-ups every configured link on each 10 s reapply tick, so a `link set
/// down` must land right after one to survive the next 5 s of assertions.
async fn sync_to_reapply(r: &Router) -> anyhow::Result<()> {
    let base = r.count("reconciled interfaces");
    r.wait_new("reconciled interfaces", base, 12).await
}

/// `ip link set <dev> <state>` in `router`'s netns.
async fn set_link(w: &World, router: &str, dev: &str, state: &str) -> anyhow::Result<()> {
    w.dock
        .ip(
            NETNS_HELPER_IMAGE,
            Some(router),
            false,
            &["link", "set", dev, state],
        )
        .await
        .map(drop)
}

/// #276: `nos-ospfv3d` follows `nos-interfaced`'s link stream on a second
/// OSPFv3 link, `eth1.0` over a direct veth pair (`eth0.0` carries the REST
/// API, so it cannot be cut). A `nos-interfaced` kill plus a config change
/// tears nothing down; carrier loss and admin-down are seen within 15s with no
/// dead timer; a deleted device is `absent`. Leaves eth1 deleted.
async fn ospfv3_link_state(w: &mut World) -> anyhow::Result<()> {
    w.link_veths().await?;
    let (a, b) = (w.a()?, w.b()?);
    let eth1 = |id: crate::router::Id, address: &str, router_id: &str| {
        // `--address` is required; eth1's IPv4 address is incidental.
        let v4 = if address == OSPFV3_ETH1_ADDRESS_A {
            "10.77.0.1/24"
        } else {
            "10.77.0.2/24"
        };
        let mut f = strings(&[
            "--interface",
            "eth1",
            "--address",
            v4,
            "--address6",
            address,
            "--asn",
            &id.asn.to_string(),
            "--router-id",
            id.rid,
            "--remote-as",
            &id.remote_as.to_string(),
            "--peer",
            id.peer_ip.s(),
        ]);
        f.extend(ospfv3_instance_only(router_id));
        f.extend(strings(&["--ospfv3-interface-profile", OSPFV3_PROFILE]));
        f
    };
    let full = |peer: &str| format!("ospfv3 neighbor reached full link=eth1.0 neighbor={peer}");
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    a.provision_flags(&eth1(A, OSPFV3_ETH1_ADDRESS_A, OSPFV3_ROUTER_ID))
        .await?;
    b.provision_flags(&eth1(B, OSPFV3_ETH1_ADDRESS_B, OSPFV3_ROUTER_ID_B))
        .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 90).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 90).await?;

    // A nos-interfaced kill followed at once by a config change: a resync runs
    // while its answers are refused, and the running links keep their values.
    let down = "ospfv3 neighbor state changed to down";
    let stopped = "ospfv3 link stopped";
    let (stop0, down0) = (
        (a.count(stopped), b.count(stopped)),
        (a.count(down), b.count(down)),
    );
    let (fallback0, stream0) = (
        a.count("ospfv3 link resolution failed, keeping running link"),
        a.count("ospfv3 link stream connected"),
    );
    log("killing router-a's nos-interfaced");
    w.dock.kill_process("router-a", "nos-interfaced").await?;
    a.provision_flags(&with_base(
        A,
        [
            ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
            strings(&["--ospfv3-graceful-restart-grace-period", "30"]),
        ]
        .concat(),
    ))
    .await?;
    a.wait_new(
        "ospfv3 link resolution failed, keeping running link",
        fallback0,
        10,
    )
    .await?;
    a.wait_new("ospfv3 link stream connected", stream0, 20)
        .await?;
    tokio::time::sleep(Duration::from_secs(15)).await;
    for (r, n_stop, n_down) in [(a, stop0.0, down0.0), (b, stop0.1, down0.1)] {
        for (pat, n) in [(stopped, n_stop), (down, n_down)] {
            if r.count(pat) > n {
                bail!("{}: '{pat}' moved after a nos-interfaced kill", r.name());
            }
        }
    }

    // Carrier loss: router-b's end goes admin-down, router-a's loses carrier;
    // neither waits for a dead timer.
    let reason = |r: &str| format!("ospfv3 link kernel interface down link=eth1.0 .*reason={r}");
    // #1028: fresh baselines (in-flight lines from the restart settle first) and a
    // 15s window, still well under the 40s dead interval the `down` check below
    // guards.
    let (nc0, ad0) = (
        a.count_fresh(&reason("no-carrier")).await,
        b.count_fresh(&reason("admin-down")).await,
    );
    let down1 = (a.count_fresh(down).await, b.count_fresh(down).await);
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    // #1028: the cut only logs a transition from an up link, so require every
    // earlier `down` on eth1.0 to have been followed by its `up`.
    let (kdown, kup) = (
        "ospfv3 link kernel interface down link=eth1.0",
        "ospfv3 link kernel interface up link=eth1.0",
    );
    for r in [a, b] {
        let (downs, ups) = (r.count(kdown), r.count(kup));
        if downs > ups {
            bail!(
                "{}: eth1.0 not up before the cut (down {downs} > up {ups})",
                r.name()
            );
        }
    }
    sync_to_reapply(b).await?;
    set_link(w, "router-b", "eth1", "down").await?;
    let diag = "link kernel interface\\|link stream\\|link state changed";
    for (r, pat, n) in [
        (a, reason("no-carrier"), nc0),
        (b, reason("admin-down"), ad0),
    ] {
        if let Err(e) = r.wait_new(&pat, n, 15).await {
            bail!("{e}\n{}: link events: {:#?}", r.name(), r.tail(diag, 15));
        }
    }
    if a.count(down) > down1.0 || b.count(down) > down1.1 {
        bail!("a dead timer expired: link-down detection did not come from the stream");
    }
    set_link(w, "router-b", "eth1", "up").await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await?;

    // A deleted device is absent.
    let absent0 = a.count(&reason("absent"));
    w.unlink_veths().await;
    a.wait_new(&reason("absent"), absent0, 15).await
}

/// Polls `router`'s `GET /v1/ospfv3/database` (up to 15s: the Link- and
/// Intra-Area-Prefix-LSAs are evicted around the Router-LSA's flush, not on
/// the same tick) until it holds no legacy Router (0x2001), Link (0x0008) or
/// Intra-Area-Prefix (0x2009) LSA from `router_id`.
async fn assert_no_legacy_lsas(router: &Router, router_id: &str) -> anyhow::Result<()> {
    let mut left = Vec::new();
    for _ in 0..15 {
        let body = router
            .rest_expect(Method::GET, "/v1/ospfv3/database", None, 200)
            .await?;
        let report: serde_json::Value = serde_json::from_str(&body)?;
        left = report[0]["result"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("ospfv3 database has no result: {body}"))?
            .iter()
            .filter(|row| {
                row["advertising_router"] == router_id
                    && matches!(row["lsa_type"].as_u64(), Some(0x2001 | 0x0008 | 0x2009))
            })
            .cloned()
            .collect();
        if left.is_empty() {
            log(format!("no legacy lsa from {router_id} left"));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("legacy lsas from {router_id} still held: {left:?}")
}

/// `pat(legacy)\|pat(extended)`: an `OSPFv3` LSA in either RFC 8362 form —
/// `ospfv3` leaves both routers in extended mode, but a phase that runs on its
/// own may find them in legacy mode (`logs::bre` has top-level `\|` only).
fn either_form(legacy: u16, extended: u16, pat: impl Fn(u16) -> String) -> String {
    format!(r"{}\|{}", pat(legacy), pat(extended))
}

/// RFC 5340 ASBR (requires `ospfv3`, hence `ospf`), and one routing table
/// redistributing into OSPF and OSPFv3 at once (#222): an IPv4 static with
/// `redistribute ospf` and an IPv6 static with `redistribute ospfv3` on
/// router-a's `rt1` make it originate both an OSPFv2 Type-5 and an
/// AS-External-LSA (0x4005, or E-AS-External 0xC025); router-b installs both
/// over the real adjacencies and its SPFs push two real kernel routes.
/// Dropping the OSPFv3 rule alone prematurely ages only its LSA (the Type-5
/// and its route stay); dropping the OSPF rule then flushes the Type-5.
/// Also checks router-b's OSPFv3 acks are delayed (RFC 2328 §13.5).
/// Leaves the table with no redistribute rule.
pub async fn ospfv3_asbr(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let (legacy, extended) = (LSA_TYPE_AS_EXTERNAL_V3, LSA_TYPE_E_AS_EXTERNAL);
    let originated = either_form(legacy, extended, |t| {
        format!("ospfv3 lsa originated lsa_type={t} ")
    });
    let installed = either_form(legacy, extended, |t| {
        format!("ospfv3 lsa installed.*lsa_type={t} .*advertising_router={OSPFV3_ROUTER_ID}")
    });
    let route = format!("added route prefix={OSPFV3_ASBR_PREFIX}.*source=Some(Ospf)");
    let v2_route = format!("added route prefix={ASBR_PREFIX} .*source=Some(Ospf)");
    // #1297/#1306: own the v2 base on both routers (no dependence on earlier
    // v2 phases or a leftover bridge profile); replacing each config clears
    // any such leftover, and router-b keeps its v3 instance.
    let (full_a0, full_b0) = (
        a.count(&full_p2p(OSPF_ROUTER_ID_B)),
        b.count(&full_p2p(OSPF_ROUTER_ID)),
    );
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(
        B,
        [
            ospf(OSPF_ROUTER_ID_B),
            ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
        ]
        .concat(),
    ))
    .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), full_a0, 90).await?;
    b.wait_new(&full_p2p(OSPF_ROUTER_ID), full_b0, 90).await?;
    let (v2_o0, v2_i0, v2_r0) = (
        a.count("ospf lsa originated.*lsa_type=5"),
        b.count("ospf lsa installed.*lsa_type=5"),
        b.count(&v2_route),
    );
    let (o0, i0, r0) = (a.count(&originated), b.count(&installed), b.count(&route));
    // Two calls: every static route of one call shares one gateway, and the
    // two families need their own. The OSPF rule survives the second call.
    a.provision_flags(&with_base(A, asbr(ospf(OSPF_ROUTER_ID))))
        .await?;
    a.provision_flags(&with_base(
        A,
        [
            ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
            strings(&[
                "--static-route",
                OSPFV3_ASBR_PREFIX,
                "--static-gateway",
                OSPFV3_ASBR_GATEWAY,
                "--redistribute-to-ospfv3",
            ]),
        ]
        .concat(),
    ))
    .await?;
    a.wait_new(&originated, o0, 60).await?;
    b.wait_new(&installed, i0, 60).await?;
    b.wait_new(&route, r0, 60).await?;
    expect_route(
        b,
        "/v1/ospfv3/routes",
        OSPFV3_ASBR_PREFIX,
        WantRoute {
            class: "external-1",
            adv_router: OSPFV3_ROUTER_ID,
            hops: 0,
            e2_cost: None,
        },
    )
    .await?;
    a.wait_new("ospf lsa originated.*lsa_type=5", v2_o0, 60)
        .await?;
    b.wait_new("ospf lsa installed.*lsa_type=5", v2_i0, 60)
        .await?;
    b.wait_new(&v2_route, v2_r0, 60).await?;
    let prefix_lsid = ASBR_PREFIX.split('/').next().unwrap_or_default();
    wait_external_lsa(b, OSPF_ROUTER_ID, prefix_lsid, 20, false).await?;

    // #1277: one `nos-ribd` table holds the v2 and v3 route sets of two
    // owners. Restarting one daemon (it pushes a fresh `Full`) must leave the
    // other family's route installed on router-b.
    let removed = format!("removed route prefix={OSPFV3_ASBR_PREFIX}");
    let v2_removed = format!("removed route prefix={ASBR_PREFIX} ");
    let v3_removed0 = b.count(&removed);
    let full_v2 = full_p2p(OSPF_ROUTER_ID);
    let full_v2_0 = b.count(&full_v2);
    let v2_added0 = b.count(&v2_route);
    let v3_added0 = b.count(&route);
    log("killing router-b's nos-ospfd; router-b's ospfv3 route must stay installed");
    w.dock.kill_process("router-b", "nos-ospfd").await?;
    b.wait_new(&full_v2, full_v2_0, 90).await?;
    b.assert_quiet(&removed, v3_removed0, 1).await?;
    // The restarted daemon's own route returns once its SPF has run.
    b.wait_new(&v2_route, v2_added0, 150).await?;
    let v2_removed0 = b.count(&v2_removed);
    let full_v3 = format!("ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID}");
    let full_v3_0 = b.count(&full_v3);
    log("killing router-b's nos-ospfv3d; router-b's ospf route must stay installed");
    w.dock.kill_process("router-b", "nos-ospfv3d").await?;
    b.wait_new(&full_v3, full_v3_0, 90).await?;
    b.assert_quiet(&v2_removed, v2_removed0, 1).await?;
    b.wait_new(&route, v3_added0, 150).await?;
    wait_external_lsa(b, OSPF_ROUTER_ID, prefix_lsid, 20, false).await?;

    let aged = either_form(legacy, extended, |t| {
        format!("ospfv3 lsa prematurely aged lsa_type={t} ")
    });
    let flushed = either_form(legacy, extended, |t| {
        format!("ospfv3 lsa maxage flushed .*lsa_type={t} .*advertising_router={OSPFV3_ROUTER_ID}")
    });
    let (aged0, flushed0, removed0) = (a.count(&aged), b.count(&flushed), b.count(&removed));
    let v2_aged = "ospf lsa prematurely aged.*lsa_type=5";
    let (v2_aged0, v2_removed0) = (a.count(v2_aged), b.count(&v2_removed));
    log("removing router-a's ospfv3 redistribute rule; only its as-external-lsa must be flushed");
    a.provision(&["--clear-redistribute-to-ospfv3"]).await?;
    a.wait_new(&aged, aged0, 30).await?;
    b.wait_new(&flushed, flushed0, 30).await?;
    b.wait_new(&removed, removed0, 30).await?;
    // The `redistribute ospf` rule is untouched: its Type-5 and route stay.
    a.assert_quiet(v2_aged, v2_aged0, 12).await?;
    b.assert_quiet(&v2_removed, v2_removed0, 1).await?;
    wait_external_lsa(b, OSPF_ROUTER_ID, prefix_lsid, 20, false).await?;

    let v2_flushed_pat =
        format!("ospf lsa maxage flushed.*lsa_type=5.*advertising_router={OSPF_ROUTER_ID}");
    let v2_flushed0 = b.count(&v2_flushed_pat);
    log("removing router-a's ospf redistribute rule; its type-5 must now be flushed");
    a.provision(&["--clear-redistribute-to-ospf"]).await?;
    a.wait_new(v2_aged, v2_aged0, 30).await?;
    b.wait_new(&v2_flushed_pat, v2_flushed0, 30).await?;
    b.wait_new(&v2_removed, v2_removed0, 30).await?;

    // RFC 2328 §13.5 delayed acknowledgment, as `asbr` checks for OSPFv2:
    // some batch is held a second or more before router-b's sweep sends it.
    b.wait_new("ospfv3 lsack sent.*delayed_ms=[1-9][0-9][0-9][0-9]", 0, 30)
        .await
}

/// RFC 5340 ABR (requires `ospfv3`): router-b's IPv6 loopback joins a second
/// area, making router-b an ABR; it originates an Inter-Area-Prefix-LSA
/// (0x2003, or E-Inter-Area-Prefix 0xA023) for it into the backbone, router-a
/// installs it and its SPF pushes a real kernel route to a prefix outside its
/// own area. Then the loopback leaves: the LSA is prematurely aged, flushed on
/// router-a and the route removed. Removes the address again, so
/// `ospfv3-lfa`'s loopback address is the first IPv6 one there.
pub async fn ospfv3_abr(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let (legacy, extended) = (LSA_TYPE_INTER_AREA_PREFIX_V3, LSA_TYPE_E_INTER_AREA_PREFIX);
    let originated = either_form(legacy, extended, |t| {
        format!("ospfv3 lsa originated lsa_type={t} ")
    });
    let installed = either_form(legacy, extended, |t| {
        format!("ospfv3 lsa installed.*lsa_type={t} .*advertising_router={OSPFV3_ROUTER_ID_B}")
    });
    let route = format!("added route prefix={OSPFV3_ABR_LOOPBACK_ADDRESS}.*source=Some(Ospf)");
    let (o0, i0, r0) = (b.count(&originated), a.count(&installed), a.count(&route));
    b.provision(&[
        "--ospfv3-instance",
        OSPFV3_INSTANCE,
        "--ospfv3-router-id",
        OSPFV3_ROUTER_ID_B,
        "--ospfv3-area",
        OSPFV3_AREA_1,
        "--ospfv3-profile",
        OSPFV3_PROFILE_AREA1,
        "--ospfv3-loopback-address",
        OSPFV3_ABR_LOOPBACK_ADDRESS,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE_AREA1,
    ])
    .await?;
    b.wait_new(&originated, o0, 60).await?;
    a.wait_new(&installed, i0, 60).await?;
    a.wait_new(&route, r0, 60).await?;
    expect_route(
        a,
        "/v1/ospfv3/routes",
        OSPFV3_ABR_LOOPBACK_ADDRESS,
        WantRoute {
            class: "inter-area",
            adv_router: OSPFV3_ROUTER_ID_B,
            hops: 0,
            e2_cost: None,
        },
    )
    .await?;

    let aged = either_form(legacy, extended, |t| {
        format!("ospfv3 lsa prematurely aged lsa_type={t} ")
    });
    let flushed = either_form(legacy, extended, |t| {
        format!(
            "ospfv3 lsa maxage flushed .*lsa_type={t} .*advertising_router={OSPFV3_ROUTER_ID_B}"
        )
    });
    let removed = format!("removed route prefix={OSPFV3_ABR_LOOPBACK_ADDRESS}");
    let (aged0, flushed0, removed0) = (b.count(&aged), a.count(&flushed), a.count(&removed));
    log("removing router-b's area-1 loopback; its inter-area-prefix-lsa must be flushed");
    b.provision(&[
        "--loopback-remove-address",
        OSPFV3_ABR_LOOPBACK_ADDRESS,
        "--clear-ospfv3-loopback-profile",
        OSPFV3_PROFILE_AREA1,
    ])
    .await?;
    b.wait_new(&aged, aged0, 30).await?;
    a.wait_new(&flushed, flushed0, 30).await?;
    a.wait_new(&removed, removed0, 30).await
}

/// RFC 5340 §4.4.3.3 area range (requires `ospfv3`): router-b, an ABR, has
/// a loopback in area 1 inside a range. Router-a installs only the
/// range's route (never the `/128`), router-b a real discard route for
/// it; `not-advertise` removes both; clearing the range brings the `/128`
/// back. Removes the loopback address again.
pub async fn ospfv3_area_range(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let range = OSPFV3_RANGE;
    let l1 = OSPFV3_RANGE_LOOPBACK;
    let routes = |p: &str| format!("added route prefix={p} .*source=Some(Ospf)");
    let singles = routes(l1);
    let (single0, range0) = (
        a.count_fresh(&singles).await,
        a.count_fresh(&routes(range)).await,
    );
    let discard =
        format!("added route prefix={range} .*source=Some(Ospf) backup=false discard=true");
    let discard0 = b.count_fresh(&discard).await;
    let area = |extra: &[&str]| {
        let mut f = strings(&[
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            OSPFV3_ROUTER_ID_B,
            "--ospfv3-area",
            OSPFV3_AREA_1,
        ]);
        f.extend(strings(extra));
        f
    };
    log("router-b: an area-1 loopback inside one range");
    b.provision(&area(&[
        "--ospfv3-area-range",
        range,
        "--ospfv3-profile",
        OSPFV3_PROFILE_AREA1,
        "--ospfv3-loopback-address",
        l1,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE_AREA1,
    ]))
    .await?;
    a.wait_new(&routes(range), range0, 60).await?;
    b.wait_new(&discard, discard0, 60).await?;
    if !b.rt1_has(range, "Ospf").await? {
        bail!("router-b's rt1 does not list the discard route {range}");
    }
    log("router-a must never see the /128");
    a.assert_quiet(&singles, single0, 10).await?;

    log("not-advertise: the range and its discard route go");
    let removed = format!("removed route prefix={range}");
    let (rem_a0, rem_b0) = (a.count(&removed), b.count(&removed));
    b.provision(&area(&[
        "--ospfv3-area-range",
        &format!("{range}:not-advertise"),
    ]))
    .await?;
    a.wait_new(&removed, rem_a0, 60).await?;
    b.wait_new(&removed, rem_b0, 60).await?;
    a.assert_quiet(&singles, single0, 10).await?;

    log("range cleared: the /128 is summarized on its own again");
    b.provision(&area(&["--ospfv3-clear-area-range", range]))
        .await?;
    a.wait_new(&routes(l1), single0, 60).await?;

    b.provision(&[
        "--loopback-remove-address",
        l1,
        "--clear-ospfv3-loopback-profile",
        OSPFV3_PROFILE_AREA1,
    ])
    .await
}

/// RFC 5340 §4.4.3 stub areas (self-contained). eth0 is area 1; router-b is
/// the ABR (a loopback in area 0) and an ASBR (an IPv6 static redistributed
/// into `ospfv3`). Area 1 a stub on router-a only is refused on both ends
/// (`mismatched e-bit`, never Init); stub on both reaches `Full`, router-a
/// installs router-b's `::/0` and the loopback's summary but never the
/// external; totally-stubby on the ABR leaves the default as the only
/// summary.
pub async fn ospfv3_stub(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let loopback = OSPFV3_STUB_LOOPBACK;
    let on_eth0 = |address: &str, router_id: &str, area_type: &str| {
        let mut f = strings(&["--address6", address]);
        f.extend(strings(&[
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            router_id,
            "--ospfv3-area",
            OSPFV3_AREA_1,
            "--ospfv3-area-type",
            area_type,
            "--ospfv3-profile",
            OSPFV3_PROFILE_AREA1,
            "--ospfv3-interface-profile",
            OSPFV3_PROFILE_AREA1,
        ]));
        f
    };
    let route = |p: &str| format!("added route prefix={p} .*source=Some(Ospf)");
    let default_route = route("::/0");
    let loopback_route = route(loopback);
    let external_route = route(OSPFV3_ASBR_PREFIX);
    let gateway = OSPFV3_ADDRESS_A.trim_end_matches("/64");

    // Area 1 a stub on router-a only: the Hello E-bits disagree.
    let mismatch = "dropping ospfv3 hello with mismatched e-bit";
    let init_b =
        format!("ospfv3 neighbor state changed to init link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}");
    let (init0, external0) = (
        a.count_fresh(&init_b).await,
        a.count_fresh(&external_route).await,
    );
    a.provision_flags(&with_base(
        A,
        on_eth0(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID, "stub"),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        on_eth0(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B, "normal"),
    ))
    .await?;
    b.provision(&[
        "--ospfv3-instance",
        OSPFV3_INSTANCE,
        "--ospfv3-router-id",
        OSPFV3_ROUTER_ID_B,
        "--ospfv3-area",
        OSPFV3_AREA,
        "--ospfv3-profile",
        OSPFV3_PROFILE,
        "--ospfv3-loopback-address",
        loopback,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
        "--static-route",
        OSPFV3_ASBR_PREFIX,
        "--static-gateway",
        gateway,
        "--redistribute-to-ospfv3",
    ])
    .await?;
    a.wait(mismatch).await?;
    b.wait(mismatch).await?;
    log("confirming the e-bit mismatch never reaches init");
    a.assert_quiet(&init_b, init0, 8).await?;

    // Stub on both: Full; router-a installs the default and the loopback's
    // summary, never the external.
    b.provision(&[
        "--ospfv3-instance",
        OSPFV3_INSTANCE,
        "--ospfv3-router-id",
        OSPFV3_ROUTER_ID_B,
        "--ospfv3-area",
        OSPFV3_AREA_1,
        "--ospfv3-area-type",
        "stub",
    ])
    .await?;
    a.wait("ospfv3 neighbor reached full").await?;
    b.wait("ospfv3 neighbor reached full").await?;
    a.wait(&default_route).await?;
    a.wait(&loopback_route).await?;
    log("confirming no external route reaches the stub area");
    a.assert_quiet(&external_route, external0, 10).await?;

    // Totally stubby on the ABR: the loopback summary goes, the default stays.
    let removed = format!("removed route prefix={loopback}");
    let removed0 = a.count(&removed);
    let default_removed = "removed route prefix=::/0";
    let default0 = a.count_fresh(default_removed).await;
    b.provision(&[
        "--ospfv3-instance",
        OSPFV3_INSTANCE,
        "--ospfv3-router-id",
        OSPFV3_ROUTER_ID_B,
        "--ospfv3-area",
        OSPFV3_AREA_1,
        "--ospfv3-area-type",
        "totally-stubby",
    ])
    .await?;
    a.wait_new(&removed, removed0, 60).await?;
    log("confirming the default route stays in the totally-stubby area");
    a.assert_quiet(default_removed, default0, 10).await?;
    if !a.rt1_has("::/0", "Ospf").await? {
        bail!("router-a lost its default route in the totally-stubby area");
    }
    Ok(())
}

/// RFC 2328 §16.2/§16.4 `LSInfinity` (self-contained). router-b is an ABR
/// (area-1 loopback) and an ASBR (IPv6 static redistributed into `ospfv3`).
/// A control run installs both routes on router-a; a second run, with
/// `nos-ospfv3d --originate-lsinfinity` (test-only, via `--ospfv3d-arg`), has
/// router-b originate the Inter-Area-Prefix and AS-External LSAs at
/// `0xFFFFFF`: router-a holds both LSAs yet installs neither route. The
/// Inter-Area-Router (ASBR distance) path is `ospfv3-lsinfinity-asbr`.
pub async fn ospfv3_lsinfinity(w: &mut World) -> anyhow::Result<()> {
    for infinity in [false, true] {
        if infinity {
            w.up(&["--ospfv3d-arg=--originate-lsinfinity"]).await?;
        } else {
            w.up(&[]).await?;
        }
        let (a, b) = (w.a()?, w.b()?);
        let installed = |legacy, extended| {
            either_form(legacy, extended, |t| {
                format!(
                    "ospfv3 lsa installed.*lsa_type={t} .*advertising_router={OSPFV3_ROUTER_ID_B}"
                )
            })
        };
        let prefix_lsa = installed(LSA_TYPE_INTER_AREA_PREFIX_V3, LSA_TYPE_E_INTER_AREA_PREFIX);
        let external_lsa = installed(LSA_TYPE_AS_EXTERNAL_V3, LSA_TYPE_E_AS_EXTERNAL);
        let abr_route =
            format!("added route prefix={OSPFV3_ABR_LOOPBACK_ADDRESS}.*source=Some(Ospf)");
        let asbr_route = format!("added route prefix={OSPFV3_ASBR_PREFIX}.*source=Some(Ospf)");
        let gateway = OSPFV3_ADDRESS_A.trim_end_matches("/64");
        // Baselines at phase start (#886), before either LSA can arrive.
        let (abr0, asbr0) = (
            a.count_fresh(&abr_route).await,
            a.count_fresh(&asbr_route).await,
        );
        a.provision_flags(&with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)))
            .await?;
        b.provision_flags(&with_base(B, ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)))
            .await?;
        b.provision(&[
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            OSPFV3_ROUTER_ID_B,
            "--ospfv3-area",
            OSPFV3_AREA_1,
            "--ospfv3-profile",
            OSPFV3_PROFILE_AREA1,
            "--ospfv3-loopback-address",
            OSPFV3_ABR_LOOPBACK_ADDRESS,
            "--ospfv3-loopback-profile",
            OSPFV3_PROFILE_AREA1,
            "--static-route",
            OSPFV3_ASBR_PREFIX,
            "--static-gateway",
            gateway,
            "--redistribute-to-ospfv3",
        ])
        .await?;
        a.wait_new(&prefix_lsa, 0, 90).await?;
        a.wait_new(&external_lsa, 0, 90).await?;
        if infinity {
            log("LSInfinity LSAs held; no route may be installed from them");
            a.assert_quiet(&abr_route, abr0, 20).await?;
            a.assert_quiet(&asbr_route, asbr0, 1).await?;
        } else {
            a.wait_new(&abr_route, 0, 60).await?;
            a.wait_new(&asbr_route, 0, 60).await?;
        }
    }
    Ok(())
}

/// RFC 5340 §3.8.7.1/§16.4 `LSInfinity` on the Inter-Area-Router path
/// (self-contained, #733): router-a -(area 0)- router-b -(area 1, own docker
/// network)- router-c, an ASBR redistributing an IPv6 static. router-b is the
/// ABR, so it originates the Inter-Area-Router-LSA for router-c into area 0.
/// Control: router-a installs router-c's external route. Second run, only
/// router-b with `--originate-lsinfinity` (router-a and router-c without, or
/// the AS-External itself would be infinite): router-a holds both LSAs but the
/// ASBR distance is unreachable, so no route (`asbr_distance` in `spf.rs`).
pub async fn ospfv3_lsinfinity_asbr(w: &mut World) -> anyhow::Result<()> {
    w.require_ipv6().await?;
    if !w.dock.network_exists(NET_OSPFV3_A1).await {
        w.dock
            .network_create(
                NET_OSPFV3_A1,
                &[OSPFV3_A1_SUBNET.s(), OSPFV3_A1_SUBNET6.s()],
                true,
            )
            .await?;
    }
    for infinity in [false, true] {
        w.start(A, None, &[]).await?;
        // The flag goes to router-b alone — see the doc comment.
        let b_args: &[&str] = if infinity {
            &["--ospfv3d-arg=--originate-lsinfinity"]
        } else {
            &[]
        };
        w.start(B, None, b_args).await?;
        w.start(C, None, &[]).await?;
        w.dock
            .network_connect_ip(NET_OSPFV3_A1, "router-b", OSPFV3_A1_IP_B.s())
            .await?;
        w.dock
            .network_connect_ip(NET_OSPFV3_A1, "router-c", OSPFV3_A1_IP_C.s())
            .await?;
        let (a, b, c) = (w.a()?, w.b()?, w.c()?);
        let route = format!("added route prefix={OSPFV3_A1_ASBR_PREFIX}.*source=Some(Ospf)");
        // Baseline at phase start (#886), before the LSAs can arrive.
        let route0 = a.count_fresh(&route).await;

        // An eth1 attachment in area 1 (docker names the second NIC `eth1`).
        let area1 = |id: Id, v4: &str, v6: &str, router_id: &str| {
            strings(&[
                "--interface",
                "eth1",
                "--address",
                v4,
                "--address6",
                v6,
                "--asn",
                &id.asn.to_string(),
                "--router-id",
                id.rid,
                "--remote-as",
                &id.remote_as.to_string(),
                "--peer",
                id.peer_ip.s(),
                "--ospfv3-instance",
                OSPFV3_INSTANCE,
                "--ospfv3-router-id",
                router_id,
                "--ospfv3-area",
                OSPFV3_AREA_1,
                "--ospfv3-profile",
                OSPFV3_PROFILE_AREA1,
                "--ospfv3-interface-profile",
                OSPFV3_PROFILE_AREA1,
            ])
        };
        a.provision_flags(&with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)))
            .await?;
        b.provision_flags(&with_base(B, ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)))
            .await?;
        b.provision_flags(&area1(
            B,
            &format!("{OSPFV3_A1_IP_B}/24"),
            OSPFV3_A1_ADDRESS_B.s(),
            OSPFV3_ROUTER_ID_B,
        ))
        .await?;
        // router-c: no OSPFv3 on eth0 (`ospfv3_instance_only` attaches nothing).
        c.provision_flags(&with_base(C, vec![])).await?;
        let mut c_flags = area1(
            C,
            &format!("{OSPFV3_A1_IP_C}/24"),
            OSPFV3_A1_ADDRESS_C.s(),
            OSPFV3_ROUTER_ID_C,
        );
        c_flags.extend(strings(&[
            "--static-route",
            OSPFV3_A1_ASBR_PREFIX,
            "--static-gateway",
            OSPFV3_A1_ADDRESS_B.s().trim_end_matches("/64"),
            "--redistribute-to-ospfv3",
        ]));
        c.provision_flags(&c_flags).await?;

        a.wait_new(
            &format!("ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}"),
            0,
            90,
        )
        .await?;
        b.wait_new(
            &format!("ospfv3 neighbor reached full link=eth1.0 neighbor={OSPFV3_ROUTER_ID_C}"),
            0,
            90,
        )
        .await?;
        let installed = |legacy, extended, router_id: &str| {
            either_form(legacy, extended, |t| {
                format!("ospfv3 lsa installed.*lsa_type={t} .*advertising_router={router_id}")
            })
        };
        a.wait_new(
            &installed(
                LSA_TYPE_INTER_AREA_ROUTER,
                LSA_TYPE_E_INTER_AREA_ROUTER,
                OSPFV3_ROUTER_ID_B,
            ),
            0,
            90,
        )
        .await?;
        a.wait_new(
            &installed(
                LSA_TYPE_AS_EXTERNAL_V3,
                LSA_TYPE_E_AS_EXTERNAL,
                OSPFV3_ROUTER_ID_C,
            ),
            0,
            90,
        )
        .await?;
        if infinity {
            log("LSInfinity Inter-Area-Router-LSA held; the external route must not be installed");
            a.assert_quiet(&route, route0, 20).await?;
        } else {
            a.wait_new(&route, 0, 60).await?;
        }
        w.remove(C).await;
        w.dock.network_disconnect(NET_OSPFV3_A1, "router-b").await;
    }
    w.dock.network_remove(NET_OSPFV3_A1).await;
    Ok(())
}

/// RFC 5340 §4.4.3.4 / RFC 2328 §12.4.3 ABR transit (#610), self-contained,
/// the `ospfv3-lsinfinity-asbr` topology: router-c (ASBR, area-1 link to
/// router-b over eth1) — router-b (ABR, area 0 over eth0.0) — router-a, which
/// also has a loopback in area 2 and is therefore a second ABR behind the
/// backbone. Router-a must pass router-b's backbone Inter-Area-Router-LSA for
/// router-c on into area 2 (its own Inter-Area-Router-LSA), and flush it when
/// router-c stops being an ASBR.
pub async fn ospfv3_abr_transit(w: &mut World) -> anyhow::Result<()> {
    w.require_ipv6().await?;
    if !w.dock.network_exists(NET_OSPFV3_A1).await {
        w.dock
            .network_create(
                NET_OSPFV3_A1,
                &[OSPFV3_A1_SUBNET.s(), OSPFV3_A1_SUBNET6.s()],
                true,
            )
            .await?;
    }
    w.start(A, None, &[]).await?;
    w.start(B, None, &[]).await?;
    w.start(C, None, &[]).await?;
    w.dock
        .network_connect_ip(NET_OSPFV3_A1, "router-b", OSPFV3_A1_IP_B.s())
        .await?;
    w.dock
        .network_connect_ip(NET_OSPFV3_A1, "router-c", OSPFV3_A1_IP_C.s())
        .await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let area1 = |id: Id, v4: &str, v6: &str, router_id: &str| {
        strings(&[
            "--interface",
            "eth1",
            "--address",
            v4,
            "--address6",
            v6,
            "--asn",
            &id.asn.to_string(),
            "--router-id",
            id.rid,
            "--remote-as",
            &id.remote_as.to_string(),
            "--peer",
            id.peer_ip.s(),
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            router_id,
            "--ospfv3-area",
            OSPFV3_AREA_1,
            "--ospfv3-profile",
            OSPFV3_PROFILE_AREA1,
            "--ospfv3-interface-profile",
            OSPFV3_PROFILE_AREA1,
        ])
    };
    a.provision_flags(&with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)))
        .await?;
    a.provision(&[
        "--ospfv3-instance",
        OSPFV3_INSTANCE,
        "--ospfv3-router-id",
        OSPFV3_ROUTER_ID,
        "--ospfv3-area",
        OSPFV3_AREA_2,
        "--ospfv3-profile",
        OSPFV3_PROFILE_AREA2,
        "--ospfv3-loopback-address",
        OSPFV3_TRANSIT_LOOPBACK_ADDRESS,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE_AREA2,
    ])
    .await?;
    b.provision_flags(&with_base(B, ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)))
        .await?;
    b.provision_flags(&area1(
        B,
        &format!("{OSPFV3_A1_IP_B}/24"),
        OSPFV3_A1_ADDRESS_B.s(),
        OSPFV3_ROUTER_ID_B,
    ))
    .await?;
    c.provision_flags(&with_base(C, vec![])).await?;
    let mut c_flags = area1(
        C,
        &format!("{OSPFV3_A1_IP_C}/24"),
        OSPFV3_A1_ADDRESS_C.s(),
        OSPFV3_ROUTER_ID_C,
    );
    c_flags.extend(strings(&[
        "--static-route",
        OSPFV3_A1_ASBR_PREFIX,
        "--static-gateway",
        OSPFV3_A1_ADDRESS_B.s().trim_end_matches("/64"),
        "--redistribute-to-ospfv3",
    ]));
    c.provision_flags(&c_flags).await?;

    a.wait_new(
        &format!("ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}"),
        0,
        90,
    )
    .await?;
    b.wait_new(
        &format!("ospfv3 neighbor reached full link=eth1.0 neighbor={OSPFV3_ROUTER_ID_C}"),
        0,
        90,
    )
    .await?;

    log("router-a re-summarizes router-b's backbone Inter-Area-Router-LSA into area 2");
    let originated = either_form(
        LSA_TYPE_INTER_AREA_ROUTER,
        LSA_TYPE_E_INTER_AREA_ROUTER,
        |t| {
            format!(
                "ospfv3 lsa originated lsa_type={t} link_state_id={OSPFV3_ROUTER_ID_C} advertising_router={OSPFV3_ROUTER_ID}"
            )
        },
    );
    a.wait_new(&originated, 0, 90).await?;

    log("router-c stops redistributing: the Inter-Area-Router-LSAs are flushed");
    c.provision(&["--clear-redistribute-to-ospfv3"]).await?;
    let aged = either_form(
        LSA_TYPE_INTER_AREA_ROUTER,
        LSA_TYPE_E_INTER_AREA_ROUTER,
        |t| {
            format!(
                "ospfv3 lsa prematurely aged lsa_type={t} link_state_id={OSPFV3_ROUTER_ID_C} advertising_router={OSPFV3_ROUTER_ID}"
            )
        },
    );
    let flushed = a.wait_new(&aged, 0, 60).await;
    w.remove(C).await;
    w.dock.network_disconnect(NET_OSPFV3_A1, "router-b").await;
    w.dock.network_remove(NET_OSPFV3_A1).await;
    flushed
}

/// Polls `r`'s `GET /v1/ospfv3/database` until one LSA satisfies `pred` (60s).
async fn wait_lsa3(
    r: &Router,
    what: &str,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..60 {
        let body = r
            .rest_expect(Method::GET, "/v1/ospfv3/database", None, 200)
            .await?;
        let report: serde_json::Value = serde_json::from_str(&body)?;
        if report[0]["result"]
            .as_array()
            .into_iter()
            .flatten()
            .any(&pred)
        {
            return Ok(());
        }
        last = body;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("{}: no {what} in its database: {last}", r.name())
}

/// RFC 5340 §4.7 virtual link (#1158), self-contained, three routers (the
/// `ospfv3-abr-transit` topology): router-a in the backbone only (eth0.0),
/// router-b the ABR (eth0.0 in area 0, eth1 in area 1), router-c on eth1 in
/// area 1 only, detached from the backbone until a virtual link b<->c through
/// area 1 joins it. Each end advertises an area-1 loopback: its `/128` LA
/// prefix is the virtual link's address. The virtual adjacency must reach Full
/// over the real VRF raw sockets (unicast to the far loopback, hop limit 64),
/// both Router-LSAs carry the type-4 link in area 0 (seen at router-a) and the
/// V bit in area 1, and router-c dropping its end takes the adjacency down on
/// router-b within the dead interval, with the type-4 link and the V bit.
pub async fn ospfv3_virtual_link(w: &mut World) -> anyhow::Result<()> {
    w.require_ipv6().await?;
    if !w.dock.network_exists(NET_OSPFV3_A1).await {
        w.dock
            .network_create(
                NET_OSPFV3_A1,
                &[OSPFV3_A1_SUBNET.s(), OSPFV3_A1_SUBNET6.s()],
                true,
            )
            .await?;
    }
    w.start(A, None, &[]).await?;
    w.start(B, None, &[]).await?;
    w.start(C, None, &[]).await?;
    w.dock
        .network_connect_ip(NET_OSPFV3_A1, "router-b", OSPFV3_A1_IP_B.s())
        .await?;
    w.dock
        .network_connect_ip(NET_OSPFV3_A1, "router-c", OSPFV3_A1_IP_C.s())
        .await?;
    let result = ospfv3_virtual_link_run(w).await;
    w.remove(C).await;
    w.dock.network_disconnect(NET_OSPFV3_A1, "router-b").await;
    w.dock.network_remove(NET_OSPFV3_A1).await;
    result
}

#[allow(clippy::too_many_lines)]
async fn ospfv3_virtual_link_run(w: &mut World) -> anyhow::Result<()> {
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let area1 = |id: Id, v4: &str, v6: &str, router_id: &str| {
        strings(&[
            "--interface",
            "eth1",
            "--address",
            v4,
            "--address6",
            v6,
            "--asn",
            &id.asn.to_string(),
            "--router-id",
            id.rid,
            "--remote-as",
            &id.remote_as.to_string(),
            "--peer",
            id.peer_ip.s(),
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            router_id,
            "--ospfv3-area",
            OSPFV3_AREA_1,
            "--ospfv3-profile",
            OSPFV3_PROFILE_AREA1,
            "--ospfv3-interface-profile",
            OSPFV3_PROFILE_AREA1,
        ])
    };
    // The area-1 loopback (the endpoint address) and the virtual link.
    let vlink = |router_id: &str, loopback: &str, endpoint: &str| {
        strings(&[
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            router_id,
            "--ospfv3-area",
            OSPFV3_AREA_1,
            "--ospfv3-profile",
            OSPFV3_PROFILE_AREA1,
            "--ospfv3-loopback-address",
            loopback,
            "--ospfv3-loopback-profile",
            OSPFV3_PROFILE_AREA1,
            "--ospfv3-virtual-link",
            &format!("{OSPFV3_AREA_1}:{endpoint}"),
        ])
    };
    a.provision_flags(&with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)))
        .await?;
    b.provision_flags(&area1(
        B,
        &format!("{OSPFV3_A1_IP_B}/24"),
        OSPFV3_A1_ADDRESS_B.s(),
        OSPFV3_ROUTER_ID_B,
    ))
    .await?;
    b.provision(&vlink(
        OSPFV3_ROUTER_ID_B,
        OSPFV3_VLINK_LOOPBACK_B,
        OSPFV3_ROUTER_ID_C,
    ))
    .await?;
    c.provision_flags(&with_base(C, vec![])).await?;
    c.provision_flags(&area1(
        C,
        &format!("{OSPFV3_A1_IP_C}/24"),
        OSPFV3_A1_ADDRESS_C.s(),
        OSPFV3_ROUTER_ID_C,
    ))
    .await?;
    c.provision(&vlink(
        OSPFV3_ROUTER_ID_C,
        OSPFV3_VLINK_LOOPBACK_C,
        OSPFV3_ROUTER_ID_B,
    ))
    .await?;
    // #1159: router-b does not summarize the backbone's a-b segment into
    // area 1 (a not-advertise range), so router-c can only learn it over the
    // virtual link.
    b.provision(&strings(&[
        "--ospfv3-instance",
        OSPFV3_INSTANCE,
        "--ospfv3-router-id",
        OSPFV3_ROUTER_ID_B,
        "--ospfv3-area",
        OSPFV3_AREA,
        "--ospfv3-area-range",
        &format!("{OSPFV3_VLINK_BACKBONE}:not-advertise"),
    ]))
    .await?;

    a.wait_new(
        &format!("ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}"),
        0,
        90,
    )
    .await?;
    b.wait_new(
        &format!("ospfv3 neighbor reached full link=eth1.0 neighbor={OSPFV3_ROUTER_ID_C}"),
        0,
        90,
    )
    .await?;

    log("the virtual link b<->c comes up from area 1's spf and reaches full");
    let b_link = format!("vlink-{OSPFV3_AREA_1}-{OSPFV3_ROUTER_ID_C}");
    let c_link = format!("vlink-{OSPFV3_AREA_1}-{OSPFV3_ROUTER_ID_B}");
    b.wait(&format!("ospfv3 virtual link up link={b_link} "))
        .await?;
    c.wait(&format!("ospfv3 virtual link up link={c_link} "))
        .await?;
    b.wait(&format!(
        "ospfv3 neighbor reached full link={b_link} neighbor={OSPFV3_ROUTER_ID_C}"
    ))
    .await?;
    c.wait(&format!(
        "ospfv3 neighbor reached full link={c_link} neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;

    // Router-LSA (legacy 0x2001, or RFC 8362 E-Router 0xA021) of `router`.
    let router_lsa = |l: &serde_json::Value, router: &str, area: &str| {
        l["area_id"] == area
            && l["advertising_router"] == router
            && matches!(l["lsa_type"].as_u64(), Some(0x2001 | 0xA021))
            && l["age"].as_u64().is_some_and(|a| a < 3600)
    };
    log("type-4 links in area 0 (at router-a) and V bits in area 1");
    for (router, far) in [
        (OSPFV3_ROUTER_ID_B, OSPFV3_ROUTER_ID_C),
        (OSPFV3_ROUTER_ID_C, OSPFV3_ROUTER_ID_B),
    ] {
        wait_lsa3(a, &format!("{router}'s type-4 link to {far}"), |l| {
            router_lsa(l, router, OSPFV3_AREA)
                && l["virtual_links"]
                    .as_array()
                    .is_some_and(|v| v.iter().any(|x| x == far))
        })
        .await?;
    }
    for (holder, router) in [(c, OSPFV3_ROUTER_ID_B), (b, OSPFV3_ROUTER_ID_C)] {
        wait_lsa3(holder, &format!("{router}'s area-1 V bit"), |l| {
            router_lsa(l, router, OSPFV3_AREA_1)
                && l["router_flags"].as_u64().is_some_and(|f| f & 0x04 != 0)
        })
        .await?;
    }

    log("router-c, in area 1 only, routes the backbone segment over the virtual link");
    let backbone_route = format!("added route prefix={OSPFV3_VLINK_BACKBONE} .*source=Some(Ospf)");
    c.wait(&backbone_route).await?;
    if !c.rt1_has(OSPFV3_VLINK_BACKBONE, "Ospf").await? {
        bail!("router-c's rt1 does not list the backbone route {OSPFV3_VLINK_BACKBONE}");
    }

    log("router-c drops its end: router-b's virtual neighbor dies within the dead interval");
    c.provision(&strings(&[
        "--ospfv3-instance",
        OSPFV3_INSTANCE,
        "--ospfv3-router-id",
        OSPFV3_ROUTER_ID_C,
        "--ospfv3-clear-virtual-link",
        &format!("{OSPFV3_AREA_1}:{OSPFV3_ROUTER_ID_B}"),
    ]))
    .await?;
    c.wait(&format!("ospfv3 virtual link down link={c_link}"))
        .await?;
    log("router-c loses the backbone route with the link");
    c.wait(&format!("removed route prefix={OSPFV3_VLINK_BACKBONE}"))
        .await?;
    b.wait_new(
        &format!("ospfv3 neighbor state changed to down link={b_link}"),
        0,
        60,
    )
    .await?;
    log("router-b withdraws its type-4 link and V bit");
    wait_lsa3(
        a,
        "router-b's backbone Router-LSA without its type-4 link",
        |l| {
            router_lsa(l, OSPFV3_ROUTER_ID_B, OSPFV3_AREA)
                && l["virtual_links"].as_array().is_some_and(Vec::is_empty)
        },
    )
    .await?;
    wait_lsa3(c, "router-b's area-1 Router-LSA without the V bit", |l| {
        router_lsa(l, OSPFV3_ROUTER_ID_B, OSPFV3_AREA_1)
            && l["router_flags"].as_u64().is_some_and(|f| f & 0x04 == 0)
    })
    .await
}

/// RFC 3101 NSSA over OSPFv3 (#1156), self-contained, the `ospfv3-abr-transit`
/// topology with area 1 an NSSA: router-c (ASBR, eth1) redistributes an IPv6
/// static as an NSSA-LSA (0x2007) that router-b, the only ABR and so the
/// elected translator, turns into its own AS-External-LSA. Router-a installs
/// that over the backbone and routes it; router-a never translates and no
/// AS-External-LSA enters the NSSA. Clearing the rule flushes both LSAs and
/// removes router-a's route.
pub async fn ospfv3_nssa(w: &mut World) -> anyhow::Result<()> {
    w.require_ipv6().await?;
    if !w.dock.network_exists(NET_OSPFV3_A1).await {
        w.dock
            .network_create(
                NET_OSPFV3_A1,
                &[OSPFV3_A1_SUBNET.s(), OSPFV3_A1_SUBNET6.s()],
                true,
            )
            .await?;
    }
    w.start(A, None, &[]).await?;
    w.start(B, None, &[]).await?;
    w.start(C, None, &[]).await?;
    w.dock
        .network_connect_ip(NET_OSPFV3_A1, "router-b", OSPFV3_A1_IP_B.s())
        .await?;
    w.dock
        .network_connect_ip(NET_OSPFV3_A1, "router-c", OSPFV3_A1_IP_C.s())
        .await?;
    let result = ospfv3_nssa_run(w).await;
    w.remove(C).await;
    w.dock.network_disconnect(NET_OSPFV3_A1, "router-b").await;
    w.dock.network_remove(NET_OSPFV3_A1).await;
    result
}

#[allow(clippy::too_many_lines)]
async fn ospfv3_nssa_run(w: &mut World) -> anyhow::Result<()> {
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let nssa = |id: Id, v4: &str, v6: &str, router_id: &str| {
        strings(&[
            "--interface",
            "eth1",
            "--address",
            v4,
            "--address6",
            v6,
            "--asn",
            &id.asn.to_string(),
            "--router-id",
            id.rid,
            "--remote-as",
            &id.remote_as.to_string(),
            "--peer",
            id.peer_ip.s(),
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            router_id,
            "--ospfv3-area",
            OSPFV3_AREA_1,
            "--ospfv3-area-type",
            "nssa",
            "--ospfv3-profile",
            OSPFV3_PROFILE_AREA1,
            "--ospfv3-interface-profile",
            OSPFV3_PROFILE_AREA1,
        ])
    };
    let external =
        |pat: fn(u16) -> String| either_form(LSA_TYPE_AS_EXTERNAL_V3, LSA_TYPE_E_AS_EXTERNAL, pat);
    let type5_originated = external(|t| format!("ospfv3 lsa originated lsa_type={t} "));
    let type5_installed = external(|t| format!("ospfv3 lsa installed.*lsa_type={t} "));
    let route = format!("added route prefix={OSPFV3_A1_ASBR_PREFIX}.*source=Some(Ospf)");
    // Baselines at phase start (#886), before anything can originate or
    // install an AS-External-LSA.
    let (a_orig0, c_inst0) = (
        a.count_fresh(&type5_originated).await,
        c.count_fresh(&type5_installed).await,
    );

    let a_base = with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID));
    let b_base = with_base(B, ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B));
    let b_nssa = nssa(
        B,
        &format!("{OSPFV3_A1_IP_B}/24"),
        OSPFV3_A1_ADDRESS_B.s(),
        OSPFV3_ROUTER_ID_B,
    );
    a.provision_flags(&a_base).await?;
    b.provision_flags(&b_base).await?;
    b.provision_flags(&b_nssa).await?;
    let c_base = with_base(C, vec![]);
    c.provision_flags(&c_base).await?;
    let mut c_flags = nssa(
        C,
        &format!("{OSPFV3_A1_IP_C}/24"),
        OSPFV3_A1_ADDRESS_C.s(),
        OSPFV3_ROUTER_ID_C,
    );
    c_flags.extend(strings(&[
        "--static-route",
        OSPFV3_A1_ASBR_PREFIX,
        "--static-gateway",
        OSPFV3_A1_ADDRESS_B.s().trim_end_matches("/64"),
        "--redistribute-to-ospfv3",
    ]));
    c.provision_flags(&c_flags).await?;
    let c_nssa = c_flags.clone();

    a.wait_new(
        &format!("ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}"),
        0,
        90,
    )
    .await?;
    b.wait_new(
        &format!("ospfv3 neighbor reached full link=eth1.0 neighbor={OSPFV3_ROUTER_ID_C}"),
        0,
        90,
    )
    .await?;

    // Router-c's NSSA-LSA, translated by router-b alone.
    let type7 = format!("ospfv3 lsa originated lsa_type={LSA_TYPE_NSSA_V3} ");
    c.wait_new(&type7, 0, 60).await?;
    b.wait_new("ospfv3 nssa translator role changed areas=.*0.0.0.1", 0, 60)
        .await?;
    b.wait_new(&type5_originated, 0, 60).await?;
    let from_b = external(|t| {
        format!("ospfv3 lsa installed.*lsa_type={t} .*advertising_router={OSPFV3_ROUTER_ID_B}")
    });
    a.wait_new(&from_b, 0, 60).await?;
    a.wait_new(&route, 0, 60).await?;
    log("confirming router-a doesn't translate and no AS-External-LSA enters the NSSA");
    a.assert_quiet(&type5_originated, a_orig0, 10).await?;
    c.assert_quiet(&type5_installed, c_inst0, 1).await?;

    // Redistribution removed: the NSSA-LSA and its translation are flushed
    // (RFC 2328 §14.1) and router-a's route goes.
    let removed = format!("removed route prefix={OSPFV3_A1_ASBR_PREFIX}");
    let removed0 = a.count(&removed);
    let aged5 = external(|t| format!("ospfv3 lsa prematurely aged lsa_type={t} "));
    let aged5_0 = b.count(&aged5);
    c.provision(&["--clear-redistribute-to-ospfv3"]).await?;
    c.wait_new(
        &format!("ospfv3 lsa prematurely aged lsa_type={LSA_TYPE_NSSA_V3} "),
        0,
        60,
    )
    .await?;
    b.wait_new(&aged5, aged5_0, 60).await?;
    a.wait_new(&removed, removed0, 60).await?;

    // RFC 8362 (#1157): extended-lsa on all three routers re-originates the
    // NSSA-LSA as an E-NSSA-LSA (0xA027, the legacy one ages), router-b
    // translates it into an E-AS-External-LSA (0xC025) and router-a routes
    // it again.
    log("switching all routers to extended-lsa: E-NSSA-LSA 0xA027 translated to 0xC025");
    let e_type5 = format!("ospfv3 lsa originated lsa_type={LSA_TYPE_E_AS_EXTERNAL} ");
    let e_type5_0 = b.count_fresh(&e_type5).await;
    let added = format!("added route prefix={OSPFV3_A1_ASBR_PREFIX}");
    let added0 = a.count_fresh(&added).await;
    let ext = strings(&["--ospfv3-extended-lsa"]);
    for (r, base) in [(a, &a_base), (b, &b_base), (c, &c_base)] {
        r.provision_flags(&[base.clone(), ext.clone()].concat())
            .await?;
    }
    b.provision_flags(&[b_nssa, ext.clone()].concat()).await?;
    c.provision_flags(&[c_nssa, ext].concat()).await?;
    c.wait_new(
        &format!("ospfv3 lsa originated lsa_type={LSA_TYPE_E_NSSA} "),
        0,
        60,
    )
    .await?;
    b.wait_new(&e_type5, e_type5_0, 60).await?;
    a.wait_new(&added, added0, 60).await
}

/// RFC 5187 graceful restart (requires `ospfv3`): router-a, with a grace
/// period configured, is restarted with SIGTERM. It must send a Grace-LSA
/// before exiting, and router-b must help: hold the adjacency and keep
/// router-a's loopback route (learned in `ospfv3`) installed through the whole
/// restart, then resynchronize with the restarted process.
pub async fn ospfv3_graceful_restart(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let full_on_b = format!("ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID}");
    let full_on_a =
        format!("ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}");
    a.provision_flags(&with_base(
        A,
        [
            ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
            strings(&["--ospfv3-graceful-restart-grace-period", "120"]),
        ]
        .concat(),
    ))
    .await?;
    // No link config changed, so the adjacency from `ospfv3` stays up.
    a.wait("ospfv3 instance config resolved.*graceful_restart_grace_period=Some(120)")
        .await?;
    // router-b helps for at most 60s, whatever router-a's Grace-LSA asks for
    // (a link-config change: the adjacency re-forms first).
    let helper_cap = |extra: &[&str]| {
        with_base(
            B,
            [
                ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
                strings(&["--ospfv3-graceful-restart-helper-max-grace-period", "60"]),
                strings(extra),
            ]
            .concat(),
        )
    };
    let (again_b0, again_a0) = (b.count(&full_on_b), a.count(&full_on_a));
    b.provision_flags(&helper_cap(&[])).await?;
    b.wait("ospfv3 instance config resolved.*graceful_restart_helper_max_grace_period=Some(60)")
        .await?;
    b.wait_new(&full_on_b, again_b0, 60).await?;
    a.wait_new(&full_on_a, again_a0, 60).await?;
    for _ in 0..60 {
        if b.rt1_has(OSPFV3_LOOPBACK_ADDRESS, "Ospf").await? {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Scoped to the restarter on the p2p link (#886).
    let torn = format!(
        "ospfv3 neighbor adjacency torn down, back to init link=eth0.0 neighbor={OSPFV3_ROUTER_ID}\\|ospfv3 neighbor state changed to down link=eth0.0 neighbor={OSPFV3_ROUTER_ID}"
    );
    let removed = format!("removed route prefix={OSPFV3_LOOPBACK_ADDRESS}");
    let (torn_before, removed_before, full_b_before, full_a_before) = (
        b.count_fresh(&torn).await,
        b.count_fresh(&removed).await,
        b.count(&full_on_b),
        a.count(&full_on_a),
    );
    log("sending SIGTERM to router-a's nos-ospfv3d; it must announce a grace period first");
    w.dock
        .signal_process("router-a", "nos-ospfv3d", "-TERM")
        .await?;
    a.wait("ospfv3 graceful restart: announcing grace period before shutdown grace_period=120")
        .await?;
    a.wait(&format!(
        "ospfv3 graceful restart: grace-lsa sent link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B} grace_period=120"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 helper: grace period entered link=eth0.0 neighbor={OSPFV3_ROUTER_ID} grace_period=120 restart_reason=1 effective_grace=60"
    ))
    .await?;

    // The watchdog respawns router-a; the fresh process resynchronizes with
    // the neighbor that held it Full the whole time.
    b.wait_new(&full_on_b, full_b_before, 90).await?;
    a.wait_new(&full_on_a, full_a_before, 90).await?;
    b.wait(&format!(
        "ospfv3 helper: neighbor reformed, exiting grace early link=eth0.0 neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    // The respawn is a restarting router (#1163): restart mode, then done.
    a.wait("ospfv3 restart mode: entered neighbors=[0-9]* remaining_secs=[0-9]* unplanned=false")
        .await?;
    a.wait("ospfv3 restart mode: exited reason=complete")
        .await?;
    quiet_settled(b, &torn, torn_before).await?;
    b.assert_quiet(&removed, removed_before, 5).await?;

    // RFC 3623 §3.2 item 3: restart router-a again; while router-b helps, its
    // own Intra-Area-Prefix-LSA gains a prefix (a topology change; the address is the one later phases use) and the
    // grace period ends at once.
    let entered =
        format!("ospfv3 helper: grace period entered link=eth0.0 neighbor={OSPFV3_ROUTER_ID}");
    let topology = format!(
        "ospfv3 helper: topology change, exiting grace link=eth0.0 neighbor={OSPFV3_ROUTER_ID}"
    );
    let (entered0, topology0, full_b0, full_a0) = (
        b.count(&entered),
        b.count(&topology),
        b.count(&full_on_b),
        a.count(&full_on_a),
    );
    let running0 = a.count("ospfv3 running marker written");
    log("second SIGTERM to router-a's nos-ospfv3d; router-b changes topology meanwhile");
    w.dock
        .signal_process("router-a", "nos-ospfv3d", "-TERM")
        .await?;
    b.wait_new(&entered, entered0, 30).await?;
    b.provision_flags(&helper_cap(&[
        "--ospfv3-loopback-address",
        OSPFV3_LFA_LOOPBACK_ADDRESS,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ]))
    .await?;
    b.wait_new(&topology, topology0, 30).await?;
    b.wait_new(&full_on_b, full_b0, 90).await?;
    a.wait_new(&full_on_a, full_a0, 90).await?;
    // The loopback address stays on router-b (flags cannot remove one) and
    // OSPFV3_LFA_LOOPBACK_ADDRESS is the one later phases use, so only the
    // OSPFv3 attachment is cleared: they re-attach it and see a fresh route.
    let clear = helper_cap(&["--clear-ospfv3-loopback-profile", OSPFV3_PROFILE]);

    // RFC 5187 unplanned restart (#1163): router-a, which keeps a running
    // marker while a grace period is configured, is SIGKILLed. The respawn
    // announces itself before its first Hello, enters restart mode and keeps
    // router-a's own kernel route to router-b's loopback.
    let running = "ospfv3 running marker written";
    a.wait_new(running, running0, 90).await?;
    b.provision_flags(&helper_cap(&[
        "--ospfv3-loopback-address",
        OSPFV3_LFA_LOOPBACK_ADDRESS,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ]))
    .await?;
    for _ in 0..60 {
        if a.rt1_has(OSPFV3_LFA_LOOPBACK_ADDRESS, "Ospf").await? {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let (in_p, out_p) = (
        "ospfv3 restart mode: entered neighbors=[0-9]* remaining_secs=[0-9]* unplanned=true",
        "ospfv3 restart mode: exited reason=complete",
    );
    let startup = "ospfv3 graceful restart: grace-lsa sent at startup link=eth0.0 grace_period=[0-9]* reason=0";
    let helper = format!(
        "ospfv3 helper: grace period entered link=eth0.0 neighbor={OSPFV3_ROUTER_ID} grace_period=[0-9]* restart_reason=0 effective_grace="
    );
    let removed_a = format!("removed route prefix={OSPFV3_LFA_LOOPBACK_ADDRESS}");
    let (in0, out0, st0, helper0, removed0, torn0, full_b0, full_a0) = (
        a.count(in_p),
        a.count(out_p),
        a.count(startup),
        b.count(&helper),
        a.count(&removed_a),
        b.count_fresh(&torn).await,
        b.count(&full_on_b),
        a.count(&full_on_a),
    );
    log("SIGKILL to router-a's nos-ospfv3d: an unplanned restart");
    w.dock
        .signal_process("router-a", "nos-ospfv3d", "-KILL")
        .await?;
    a.wait_new(in_p, in0, 90).await?;
    a.wait_new(startup, st0, 90).await?;
    b.wait_new(&helper, helper0, 90).await?;
    a.wait_new(out_p, out0, 90).await?;
    b.wait_new(&full_on_b, full_b0, 90).await?;
    a.wait_new(&full_on_a, full_a0, 90).await?;
    quiet_settled(b, &torn, torn0).await?;
    a.assert_quiet(&removed_a, removed0, 5).await?;
    b.provision_flags(&clear).await
}

/// RFC 5340 §4.5.1 (#46): every Link-LSA (legacy 8 or RFC 8362 E-Link
/// 0x8028 — both may coexist after `ospfv3` toggled extended-lsa) router-c
/// holds from `router_id` must belong to the bridge link, the only link it
/// shares with that router — router-a/b also run `eth0.0` in the same area,
/// and its Link-LSA must never have been offered over the bridge.
async fn assert_only_broadcast_link_lsas(c: &Router, router_id: &str) -> anyhow::Result<()> {
    let body = c
        .rest_expect(Method::GET, "/v1/ospfv3/database", None, 200)
        .await?;
    let report: serde_json::Value = serde_json::from_str(&body)?;
    let rows = report[0]["result"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("ospfv3 database has no result: {body}"))?;
    let want = serde_json::json!(format!("broadcast-domain:{BD}"));
    let mut seen = 0;
    for row in rows {
        if row["advertising_router"] == router_id
            && matches!(row["lsa_type"].as_u64(), Some(8 | 0x8028))
        {
            seen += 1;
            if row["link"] != want {
                bail!("leaked link-local lsa from {router_id} on router-c: {row}");
            }
        }
    }
    if seen == 0 {
        bail!("router-c holds no link-lsa from {router_id} at all: {body}");
    }
    Ok(())
}

/// Reuses `ospf-dr`'s router-c and the same bd-ospf bridge (a BroadcastDomain
/// has independent `ospf_profile`/`ospfv3_profile` fields, so both protocols
/// run over one real bridge): the identical DR/BDR election and DrOther-Full
/// restriction, over the new address family. Then, with router-c `Full` to
/// both, that no Link-LSA from router-a/b's *other* link leaked onto the
/// bridge — right at `Full` (the DBD-summary path) and again after a
/// periodic full resend (`RXMT_INTERVAL`, the flood path).
pub async fn ospfv3_dr(w: &mut World) -> anyhow::Result<()> {
    // `ospf-dr-frr` removes router-c (#887), so it may not be running here.
    if w.c().is_err() {
        // The same router-c `ospf-dr` leaves behind (OSPFv2 instance + the
        // bridge's routing table, which the ospfv3 bridge profile requires).
        w.start(crate::router::C, None, &[]).await?;
        let c = w.c()?;
        for flags in [
            ospf_instance_only(OSPF_ROUTER_ID_C),
            ospf_broadcast(OSPF_BROADCAST_ADDRESS_C),
        ] {
            c.provision_flags(&with_base(crate::router::C, flags))
                .await?;
        }
    }
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    c.provision_flags(&with_base(
        crate::router::C,
        ospfv3_instance_only(OSPFV3_ROUTER_ID_C),
    ))
    .await?;
    a.provision_flags(&with_base(
        A,
        ospfv3_broadcast_with_l2(OSPF_BROADCAST_ADDRESS_A, OSPFV3_BROADCAST_ADDRESS_A),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        ospfv3_broadcast_with_l2(OSPF_BROADCAST_ADDRESS_B, OSPFV3_BROADCAST_ADDRESS_B),
    ))
    .await?;
    c.provision_flags(&with_base(
        crate::router::C,
        ospfv3_broadcast(OSPFV3_BROADCAST_ADDRESS_C),
    ))
    .await?;

    let link = format!("link=broadcast-domain:{BD}");
    let joined = format!("ospfv3 all-drouters membership changed {link} joined=true");
    let base_c = c.count(&joined);
    a.wait(&format!(
        "ospfv3 neighbor reached two-way {link} neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 neighbor reached two-way {link} neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 interface became dr {link} dr={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    a.wait(&format!(
        "ospfv3 interface became backup {link} dr={OSPFV3_ROUTER_ID_B} bdr={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospfv3 neighbor reached two-way {link} neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospfv3 neighbor reached two-way {link} neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    c.wait(&format!(
        "ospfv3 interface became dr-other {link} dr={OSPFV3_ROUTER_ID_B} bdr={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospfv3 neighbor reached full {link} neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
    c.wait(&format!(
        "ospfv3 neighbor reached full {link} neighbor={OSPFV3_ROUTER_ID_B}"
    ))
    .await?;
    a.wait(&format!(
        "ospfv3 neighbor reached full {link} neighbor={OSPFV3_ROUTER_ID_C}"
    ))
    .await?;
    b.wait(&format!(
        "ospfv3 neighbor reached full {link} neighbor={OSPFV3_ROUTER_ID_C}"
    ))
    .await?;

    log("only the dr and bdr join ff02::6 (rfc 5340 a.1)");
    b.wait(&joined).await?;
    a.wait(&joined).await?;
    c.assert_quiet(&joined, base_c, 10).await?;

    // #879: as `ospf-dr`, over ff02::6 / ff02::5.
    c.wait(&format!(
        "ospfv3 lsu flood destination changed {link} dest=all-drouters"
    ))
    .await?;
    for r in [a, b] {
        r.wait(&format!(
            "ospfv3 lsu flood destination changed {link} dest=all-spf-routers"
        ))
        .await?;
    }
    let lsa_c = format!("ospfv3 lsa installed.*advertising_router={OSPFV3_ROUTER_ID_C}");
    let (a0, b0) = (a.count(&lsa_c), b.count(&lsa_c));
    let mut flags = ospfv3_instance_only(OSPFV3_ROUTER_ID_C);
    flags.extend(strings(&[
        "--ospfv3-loopback-address",
        OSPFV3_DR_LOOPBACK_ADDRESS_C,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ]));
    c.provision_flags(&with_base(crate::router::C, flags))
        .await?;
    a.wait_new(&lsa_c, a0, 60).await?;
    b.wait_new(&lsa_c, b0, 60).await?;
    c.provision(&["--clear-ospfv3-loopback-profile", OSPFV3_PROFILE])
        .await?;

    log("router-c holds only the bridge's own link-lsas (rfc 5340 §4.5.1)");
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID).await?;
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID_B).await?;
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID).await?;
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID_B).await
}

/// RFC 8362 Sparse mode (#1179; requires `ospfv3-dr`, which puts router-c on
/// the shared bridge): router-a sparse, router-b full, router-c legacy-only in
/// one area. Every adjacency stays `Full`, a's legacy Router-LSA reaches the
/// full-mode b, b's E-Router-LSA reaches the sparse a, and a loopback of each
/// router is installed as a kernel route on the other two.
pub async fn ospfv3_extended_lsa_sparse(w: &mut World) -> anyhow::Result<()> {
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let [lo_a, lo_b, lo_c] = OSPFV3_SPARSE_LOOPBACKS;
    // The loopbacks are unique to this phase, so a first-occurrence wait is safe.
    let route = |p: &str| format!("added route prefix={p}.*source=Some(Ospf) backup=false");
    let legacy_a = format!(
        "ospfv3 lsa installed.*lsa_type={LSA_TYPE_ROUTER_V3}.*advertising_router={OSPFV3_ROUTER_ID}"
    );
    let ext_b = format!(
        "ospfv3 lsa installed.*lsa_type={LSA_TYPE_E_ROUTER}.*advertising_router={OSPFV3_ROUTER_ID_B}"
    );
    let lo = |prefix: &'static str, mode: &'static str| {
        let mut flags = vec![
            "--ospfv3-loopback-address",
            prefix,
            "--ospfv3-loopback-profile",
            OSPFV3_PROFILE,
        ];
        flags.extend(Some(mode).filter(|m| !m.is_empty()));
        flags
    };
    // Only the loopback's first IPv6 address is originated: drop the earlier
    // phases' (`ospfv3-lfa`'s on router-b, `ospfv3-dr`'s on router-c) first.
    for (r, old) in [
        (a, OSPFV3_LOOPBACK_ADDRESS),
        (b, OSPFV3_LFA_LOOPBACK_ADDRESS),
        (c, OSPFV3_DR_LOOPBACK_ADDRESS_C),
    ] {
        // Absent when a phase before already removed it.
        let _ = r.provision(&["--loopback-remove-address", old]).await;
    }
    a.provision(&lo(lo_a, "--ospfv3-extended-lsa-sparse"))
        .await?;
    b.provision(&lo(lo_b, "--ospfv3-extended-lsa")).await?;
    c.provision(&lo(lo_c, "")).await?;

    b.wait(&legacy_a).await?;
    a.wait(&ext_b).await?;
    let link = format!("link=broadcast-domain:{BD}");
    for (r, peers) in [
        (a, [OSPFV3_ROUTER_ID_B, OSPFV3_ROUTER_ID_C]),
        (b, [OSPFV3_ROUTER_ID, OSPFV3_ROUTER_ID_C]),
        (c, [OSPFV3_ROUTER_ID, OSPFV3_ROUTER_ID_B]),
    ] {
        for n in peers {
            r.wait(&format!("ospfv3 neighbor reached full {link} neighbor={n}"))
                .await?;
        }
    }
    let wants = [(a, [lo_b, lo_c]), (b, [lo_a, lo_c]), (c, [lo_a, lo_b])];
    for (r, ps) in wants {
        for p in ps {
            r.wait(&route(p)).await?;
        }
    }

    // Leave full mode on both (what `ospfv3` left) and no loopback behind.
    a.provision(&[
        "--ospfv3-extended-lsa",
        "--clear-ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ])
    .await?;
    b.provision(&["--clear-ospfv3-loopback-profile", OSPFV3_PROFILE])
        .await?;
    c.provision(&["--clear-ospfv3-loopback-profile", OSPFV3_PROFILE])
        .await?;
    for (r, mine) in [(a, lo_a), (b, lo_b), (c, lo_c)] {
        r.provision(&["--loopback-remove-address", mine]).await?;
    }
    // Give router-b `ospfv3-lfa`'s address back (`ospfv3-spf-ecmp` removes it).
    b.provision(&lo(OSPFV3_LFA_LOOPBACK_ADDRESS, "")).await?;
    b.provision(&["--clear-ospfv3-loopback-profile", OSPFV3_PROFILE])
        .await
}

/// RFC 5286 loop-free alternate over OSPFv3 (requires `ospfv3-dr`, which puts
/// router-c on the shared bridge): router-a reaches router-b's loopback via b
/// itself (primary) or via c, whose own shortest path to b doesn't run back
/// through a. The backup is a link-local next hop, so `nos-ribd` must install
/// it with its own outgoing interface and at a metric *above* the primary's
/// (an IPv6 primary is 1024).
pub async fn ospfv3_lfa(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let prefix = OSPFV3_LFA_LOOPBACK_ADDRESS;
    let primary = format!("added route prefix={prefix}.*source=Some(Ospf) backup=false");
    let backup = format!("added route prefix={prefix}.*source=Some(Ospf) backup=true");
    let (p0, b0) = (a.count(&primary), a.count(&backup));
    b.provision(&[
        "--ospfv3-loopback-address",
        prefix,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ])
    .await?;
    a.wait_new(&primary, p0, 60).await?;
    a.wait_new(&backup, b0, 60).await?;

    let removed = format!("removed route prefix={prefix}.*backup=true");
    let r0 = a.count(&removed);
    b.provision(&["--clear-ospfv3-loopback-profile", OSPFV3_PROFILE])
        .await?;
    a.wait_new(&removed, r0, 60).await
}

/// RFC 5340 §4.2 point-to-multipoint (requires `ospfv3`): the shared profile's
/// network type forced to `point-to-multipoint` on both routers. `eth0.0`
/// must still reach `Full` with no DR election, and router-a must learn
/// router-b's own address as a /128 host route (the stub is the address, not
/// the /64); clearing the override restores point-to-point and drops it.
pub async fn ospfv3_p2mp(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let full =
        |neighbor: &str| format!("ospfv3 neighbor reached full link=eth0.0 neighbor={neighbor}");
    let set = |addr: &str, rid: &str, kind: &str| {
        let mut f = ospfv3(addr, rid);
        f.extend(strings(&["--ospfv3-profile-network-type", kind]));
        f
    };
    let host = format!(
        "{}/128",
        OSPFV3_ADDRESS_B.split('/').next().unwrap_or_default()
    );
    let (added, removed) = (
        format!("added route prefix={host}.*source=Some(Ospf)"),
        format!("removed route prefix={host}"),
    );
    let became_dr = "ospfv3 interface became dr link=eth0.0";
    let (a_full, b_full, dr0, r0) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
        a.count(became_dr),
        a.count(&removed),
    );
    let h0 = a.count(&added);
    log("forcing network-type point-to-multipoint on both routers' shared profile");
    a.provision_flags(&with_base(
        A,
        set(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID, "point-to-multipoint"),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        set(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B, "point-to-multipoint"),
    ))
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 90).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 90).await?;
    a.wait_new(&added, h0, 60).await?;
    a.assert_quiet(became_dr, dr0, 6).await?;

    log("clearing the network-type override: point-to-point again, the /128 is gone");
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    a.provision_flags(&with_base(
        A,
        set(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID, "clear"),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        set(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B, "clear"),
    ))
    .await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 90).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 90).await?;
    a.wait_new(&removed, r0, 60).await
}

/// RFC 6845 hybrid broadcast and point-to-multipoint (#1180; requires
/// `ospfv3-dr`, which stands up router-c on the shared bridge): a second
/// profile forced to `hybrid` on the bridge of all three routers. The
/// election, Hello and database sync are the broadcast ones (an election
/// logged, every pair Full as the DR/BDR are adjacent to the DROther), but the
/// Router-LSAs list point-to-point links and the DR originates no Network-LSA
/// (§4.5): each router installs the others' /128 host routes and router-c's
/// loopback. Switching the bridge back to the broadcast profile re-elects.
pub async fn ospfv3_hybrid(w: &mut World) -> anyhow::Result<()> {
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let hybrid = |rid: &str| {
        strings(&[
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            rid,
            "--ospfv3-area",
            OSPFV3_AREA,
            "--ospfv3-profile",
            OSPFV3_HYBRID_PROFILE,
            "--ospfv3-profile-network-type",
            "hybrid",
            "--routing-table",
            "rt1",
            "--broadcast-domain",
            BD,
            "--ospfv3-broadcast-domain-profile",
            OSPFV3_HYBRID_PROFILE,
        ])
    };
    let link = format!("link=broadcast-domain:{BD}");
    let became = format!("ospfv3 interface became .* {link}");
    let full = |n: &str| format!("ospfv3 neighbor reached full {link} neighbor={n}");
    let host = |addr: &str| addr.split('/').next().unwrap_or_default().to_string();
    let added = |addr: &str| format!("added route prefix={}/128.*source=Some(Ospf)", host(addr));
    let loopback = format!("added route prefix={OSPFV3_DR_LOOPBACK_ADDRESS_C}.*source=Some(Ospf)");

    let routers = [
        (a, OSPFV3_ROUTER_ID, OSPFV3_ROUTER_ID_B, OSPFV3_ROUTER_ID_C),
        (b, OSPFV3_ROUTER_ID_B, OSPFV3_ROUTER_ID, OSPFV3_ROUTER_ID_C),
        (c, OSPFV3_ROUTER_ID_C, OSPFV3_ROUTER_ID, OSPFV3_ROUTER_ID_B),
    ];
    let base: Vec<_> = routers
        .iter()
        .map(|(r, _, p, q)| (r.count(&became), r.count(&full(p)), r.count(&full(q))))
        .collect();
    let (a_b, a_c, b_a, b_c, c_a, c_b) = (
        a.count(&added(OSPFV3_BROADCAST_ADDRESS_B)),
        a.count(&added(OSPFV3_BROADCAST_ADDRESS_C)),
        b.count(&added(OSPFV3_BROADCAST_ADDRESS_A)),
        b.count(&added(OSPFV3_BROADCAST_ADDRESS_C)),
        c.count(&added(OSPFV3_BROADCAST_ADDRESS_A)),
        c.count(&added(OSPFV3_BROADCAST_ADDRESS_B)),
    );
    let (loop_a, loop_b) = (a.count(&loopback), b.count(&loopback));

    log("forcing a hybrid profile (rfc 6845) on the bridge of all three routers");
    a.provision_flags(&with_base(A, hybrid(OSPFV3_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, hybrid(OSPFV3_ROUTER_ID_B)))
        .await?;
    c.provision_flags(&with_base(crate::router::C, hybrid(OSPFV3_ROUTER_ID_C)))
        .await?;
    for ((r, _, p, q), (e0, p0, q0)) in routers.iter().zip(&base) {
        r.wait_new(&became, *e0, 120).await?;
        r.wait_new(&full(p), *p0, 120).await?;
        r.wait_new(&full(q), *q0, 120).await?;
    }
    // Point-to-point links in the Router-LSAs: the peers' own addresses are
    // /128 host routes, not the bridge's /64.
    a.wait_new(&added(OSPFV3_BROADCAST_ADDRESS_B), a_b, 60)
        .await?;
    a.wait_new(&added(OSPFV3_BROADCAST_ADDRESS_C), a_c, 60)
        .await?;
    b.wait_new(&added(OSPFV3_BROADCAST_ADDRESS_A), b_a, 60)
        .await?;
    b.wait_new(&added(OSPFV3_BROADCAST_ADDRESS_C), b_c, 60)
        .await?;
    c.wait_new(&added(OSPFV3_BROADCAST_ADDRESS_A), c_a, 60)
        .await?;
    c.wait_new(&added(OSPFV3_BROADCAST_ADDRESS_B), c_b, 60)
        .await?;

    let mut flags = strings(&[
        "--ospfv3-instance",
        OSPFV3_INSTANCE,
        "--ospfv3-router-id",
        OSPFV3_ROUTER_ID_C,
        "--ospfv3-area",
        OSPFV3_AREA,
        "--ospfv3-profile",
        OSPFV3_PROFILE,
    ]);
    flags.extend(strings(&[
        "--ospfv3-loopback-address",
        OSPFV3_DR_LOOPBACK_ADDRESS_C,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ]));
    c.provision_flags(&with_base(crate::router::C, flags))
        .await?;
    a.wait_new(&loopback, loop_a, 60).await?;
    b.wait_new(&loopback, loop_b, 60).await?;
    c.provision(&["--clear-ospfv3-loopback-profile", OSPFV3_PROFILE])
        .await?;

    log("no Network-LSA is held (rfc 6845 4.5)");
    let mut left = String::new();
    for _ in 0..30 {
        let body = a
            .rest_expect(Method::GET, "/v1/ospfv3/database", None, 200)
            .await?;
        let report: serde_json::Value = serde_json::from_str(&body)?;
        let rows = report[0]["result"].as_array().cloned().unwrap_or_default();
        left = rows
            .iter()
            .filter(|r| {
                r["lsa_type"].as_u64().is_some_and(|t| t & 0x1fff == 2)
                    && r["age"].as_u64().is_some_and(|age| age < 3600)
            })
            .map(ToString::to_string)
            .collect();
        if left.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    if !left.is_empty() {
        bail!("a network-lsa is still held on a hybrid bridge: {left}");
    }

    log("switching the bridge back to the broadcast profile re-elects");
    let base: Vec<_> = routers.iter().map(|(r, ..)| r.count(&became)).collect();
    a.provision_flags(&with_base(
        A,
        ospfv3_broadcast_with_l2(OSPF_BROADCAST_ADDRESS_A, OSPFV3_BROADCAST_ADDRESS_A),
    ))
    .await?;
    b.provision_flags(&with_base(
        B,
        ospfv3_broadcast_with_l2(OSPF_BROADCAST_ADDRESS_B, OSPFV3_BROADCAST_ADDRESS_B),
    ))
    .await?;
    c.provision_flags(&with_base(
        crate::router::C,
        ospfv3_broadcast(OSPFV3_BROADCAST_ADDRESS_C),
    ))
    .await?;
    for ((r, ..), e0) in routers.iter().zip(&base) {
        r.wait_new(&became, *e0, 120).await?;
    }
    Ok(())
}

/// RFC 2328 §16.1 ECMP over OSPFv3 (#1135, requires `ospfv3-dr`): router-b is
/// reachable from router-a over both the p2p `eth0.0` and the shared bridge at
/// the same cost, so its loopback is one `RTA_MULTIPATH` route (`next_hops=2`).
pub async fn ospfv3_spf_ecmp(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let prefix = OSPFV3_ECMP_LOOPBACK_ADDRESS;
    // Both paths up whatever an earlier phase left: the p2p `eth0.0` and the
    // bridge, each at the default cost.
    let both = |id, svi4, svi6, address, router_id| {
        let mut f = ospfv3(address, router_id);
        f.extend(ospfv3_broadcast_with_l2(svi4, svi6));
        with_base(id, f)
    };
    a.provision_flags(&both(
        A,
        OSPF_BROADCAST_ADDRESS_A,
        OSPFV3_BROADCAST_ADDRESS_A,
        OSPFV3_ADDRESS_A,
        OSPFV3_ROUTER_ID,
    ))
    .await?;
    b.provision_flags(&both(
        B,
        OSPF_BROADCAST_ADDRESS_B,
        OSPFV3_BROADCAST_ADDRESS_B,
        OSPFV3_ADDRESS_B,
        OSPFV3_ROUTER_ID_B,
    ))
    .await?;
    let added = format!("added route prefix={prefix}.*next_hops=2.*source=Some(Ospf)");
    let a0 = a.count(&added);
    // Only the loopback's first IPv6 address is originated, so `ospfv3-lfa`'s
    // goes first (as `ospfv3-abr` does) and ours is removed again at the end.
    b.provision(&["--loopback-remove-address", OSPFV3_LFA_LOOPBACK_ADDRESS])
        .await?;
    b.provision(&[
        "--ospfv3-loopback-address",
        prefix,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ])
    .await?;
    a.wait_new(&added, a0, 60).await?;

    let removed = format!("removed route prefix={prefix}");
    let r0 = a.count(&removed);
    b.provision(&[
        "--loopback-remove-address",
        prefix,
        "--clear-ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ])
    .await?;
    a.wait_new(&removed, r0, 60).await
}

/// RFC 6987 stub router over OSPFv3 on router-c (requires `ospfv3-dr`: router-c
/// on the shared bridge). Router-a and router-b are first split to one OSPFv3
/// link, the bridge: their `eth0.0` goes into a passive profile, so router-b's
/// second path is gone and router-c is router-a's only loop-free alternate to
/// router-b's loopback. While router-c advertises MaxLinkMetric, RFC 5286 3.5
/// forbids it as an alternate, so router-a drops the backup and keeps the
/// primary. Administrative first, then on-shutdown and on-startup across one
/// SIGINT restart (`nos-ospfv3d` flushes nothing on stop, so the hold is the
/// whole shutdown delay).
#[allow(clippy::too_many_lines)]
pub async fn ospfv3_stub_router(w: &mut World) -> anyhow::Result<()> {
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    let lo = OSPFV3_LFA_LOOPBACK_ADDRESS;
    let primary = format!("added route prefix={lo}.*source=Some(Ospf) backup=false");
    let backup_added = format!("added route prefix={lo}.*source=Some(Ospf) backup=true");
    let backup_removed = format!("removed route prefix={lo}.*backup=true");
    let primary_removed = format!("removed route prefix={lo}.*backup=false");
    let c_flags = |extra: &[&str]| {
        let mut flags = strings(&[
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            OSPFV3_ROUTER_ID_C,
        ]);
        flags.extend(strings(extra));
        flags
    };
    let changed = |active: bool, reason: &str| {
        format!("ospfv3 stub router max-metric changed active={active} reason=\"{reason}\"")
    };
    // `eth0.0` in a passive profile (router-a/b), so only the bridge peers.
    let passive_p = "ospfv3-stub-passive";
    let detach = |id: crate::router::Id, address: &str, router_id: &str| {
        with_base(
            id,
            strings(&[
                "--address6",
                address,
                "--ospfv3-instance",
                OSPFV3_INSTANCE,
                "--ospfv3-router-id",
                router_id,
                "--ospfv3-area",
                OSPFV3_AREA,
                "--ospfv3-profile",
                passive_p,
                "--ospfv3-passive",
                "true",
                "--ospfv3-interface-profile",
                passive_p,
            ]),
        )
    };
    let stopped = "ospfv3 link stopped link=eth0.0";

    log("detaching eth0.0 from OSPFv3 adjacencies on router-a and router-b (passive)");
    let (sa0, sb0) = (a.count(stopped), b.count(stopped));
    a.provision_flags(&detach(A, OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID))
        .await?;
    b.provision_flags(&detach(B, OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B))
        .await?;
    a.wait_new(stopped, sa0, 60).await?;
    b.wait_new(stopped, sb0, 60).await?;

    let (p0, b0) = (a.count(&primary), a.count(&backup_added));
    b.provision(&[
        "--ospfv3-loopback-address",
        lo,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ])
    .await?;
    a.wait_new(&primary, p0, 60).await?;
    a.wait_new(&backup_added, b0, 60).await?;
    // Barrier (#1344): let the detach's resync and the backup slot churn settle,
    // so a late re-install of the primary cannot land inside the window below.
    let p1 = a.count(&primary);
    a.assert_quiet(&primary, p1, 5).await?;
    let primary_removed0 = a.count(&primary_removed);

    log("router-c: max-metric router-lsa administrative; router-a must drop its lfa via c");
    let (r0, on0) = (
        a.count(&backup_removed),
        c.count(&changed(true, "administrative")),
    );
    c.provision(&c_flags(&["--ospfv3-max-metric-administrative", "true"]))
        .await?;
    c.wait_new(&changed(true, "administrative"), on0, 30)
        .await?;
    a.wait_new(&backup_removed, r0, 60).await?;

    log("router-c: administrative off; router-a must re-add the lfa");
    let (b0, off0) = (a.count(&backup_added), c.count(&changed(false, "cleared")));
    c.provision(&c_flags(&["--ospfv3-max-metric-administrative", "false"]))
        .await?;
    c.wait_new(&changed(false, "cleared"), off0, 30).await?;
    a.wait_new(&backup_added, b0, 60).await?;

    // On-shutdown + on-startup across one stop, with graceful restart off on
    // router-c. On-startup is armed only by a fresh start; 60s outlasts the
    // respawn and the new adjacency.
    let resolved = "ospfv3 instance config resolved.*max_metric_on_startup=Some(60) max_metric_on_shutdown=Some(3)";
    let (res0, armed0) = (c.count(resolved), c.count(&changed(true, "on-startup")));
    c.provision(&c_flags(&[
        "--ospfv3-max-metric-on-shutdown",
        "3",
        "--ospfv3-max-metric-on-startup",
        "60",
    ]))
    .await?;
    c.wait_new(resolved, res0, 30).await?;
    // On-startup must not arm on a running process.
    c.assert_quiet(&changed(true, "on-startup"), armed0, 6)
        .await?;

    let full_c = format!(
        "ospfv3 neighbor reached full link=broadcast-domain:{BD} neighbor={OSPFV3_ROUTER_ID_C}"
    );
    let (sd0, r0, st0, full0, exp0) = (
        c.count(&changed(true, "on-shutdown")),
        a.count(&backup_removed),
        c.count(&changed(true, "on-startup")),
        a.count(&full_c),
        c.count(&changed(false, "expired")),
    );
    log("sending SIGINT to router-c's nos-ospfv3d; it must advertise max-metric before exiting");
    w.dock
        .signal_process("router-c", "nos-ospfv3d", "-INT")
        .await?;
    c.wait_new(&changed(true, "on-shutdown"), sd0, 30).await?;
    a.wait_new(&backup_removed, r0, 30).await?;

    log("router-c respawns with on-startup max-metric: back in the lsdb, not an lfa");
    c.wait_new(&changed(true, "on-startup"), st0, 90).await?;
    a.wait_new(&full_c, full0, 90).await?;
    let b0 = a.count(&backup_added);
    a.assert_quiet(&backup_added, b0, 10).await?;
    // Still inside the period: the quiet window above proved something.
    c.assert_quiet(&changed(false, "expired"), exp0, 0).await?;
    c.wait_new(&changed(false, "expired"), exp0, 90).await?;
    a.wait_new(&backup_added, b0, 60).await?;
    a.assert_quiet(&primary_removed, primary_removed0, 0)
        .await?;

    log("restoring: router-c's max-metric off, eth0.0 back in the profile, loopback out");
    c.provision(&c_flags(&[
        "--ospfv3-max-metric-on-shutdown",
        "0",
        "--ospfv3-max-metric-on-startup",
        "0",
    ]))
    .await?;
    let (fa0, fb0) = (
        a.count("ospfv3 link driver started link=eth0.0"),
        b.count("ospfv3 link driver started link=eth0.0"),
    );
    a.provision_flags(&with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)))
        .await?;
    a.wait_new("ospfv3 link driver started link=eth0.0", fa0, 60)
        .await?;
    b.wait_new("ospfv3 link driver started link=eth0.0", fb0, 60)
        .await?;
    let removed0 = a.count(&primary_removed);
    b.provision(&["--clear-ospfv3-loopback-profile", OSPFV3_PROFILE])
        .await?;
    a.wait_new(&primary_removed, removed0, 60).await
}

/// #618 (requires `ospfv3`): `eth1` (a veth) carries two VLAN subinterfaces,
/// so router-b's link-local address is the same on both (they share the
/// parent's MAC). router-a reaches router-b's loopback over VLAN 10; raising
/// VLAN 10's cost moves the next hop to the same gateway over VLAN 20, which
/// `nos-ribd` must install as one `NLM_F_REPLACE` (the slot key carries the
/// interface of a link-local gateway), and nothing replaces it again.
pub async fn ospfv3_vlan_nexthop_move(w: &mut World) -> anyhow::Result<()> {
    w.link_veths().await?;
    let (a, b) = (w.a()?, w.b()?);
    let t10 = OSPFV3_VLAN_TAGS[0];
    let prefix = OSPFV3_VLAN_LOOPBACK_ADDRESS_B;
    // `delete` removes the subinterface instead (cleanup).
    let vlan = |id: Id, router_id: &str, tag: u16, cost: u16, delete: bool| {
        let host = if id.rid == A.rid { 1 } else { 2 };
        let profile = format!("vlan{tag}");
        let mut f = strings(&[
            "--interface",
            "eth1",
            "--subinterface-tag",
            &tag.to_string(),
            "--address",
            &format!("10.78.{tag}.{host}/24"),
            "--address6",
            &format!("fd77:{tag}::{host}/64"),
            "--asn",
            &id.asn.to_string(),
            "--router-id",
            id.rid,
            "--remote-as",
            &id.remote_as.to_string(),
            "--peer",
            id.peer_ip.s(),
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            router_id,
            "--ospfv3-area",
            OSPFV3_AREA,
            "--ospfv3-profile",
            &profile,
            "--ospfv3-profile-cost",
            &cost.to_string(),
            "--ospfv3-interface-profile",
            &profile,
        ]);
        if delete {
            // A profile on a deleted subinterface fails validation.
            f.truncate(f.len() - 2);
            f.push("--delete-subinterface".into());
        }
        f
    };
    // Keep every other path (eth0.0, eth1.0) well behind the VLANs on router-a.
    let other_cost = |cost: u16| {
        with_base(
            A,
            [
                ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
                strings(&["--ospfv3-profile-cost", &cost.to_string()]),
            ]
            .concat(),
        )
    };
    a.provision_flags(&other_cost(OSPFV3_VLAN_OTHER_COST))
        .await?;
    for (tag, cost) in OSPFV3_VLAN_TAGS.into_iter().zip(OSPFV3_VLAN_COSTS) {
        a.provision_flags(&vlan(A, OSPFV3_ROUTER_ID, tag, cost, false))
            .await?;
        b.provision_flags(&vlan(B, OSPFV3_ROUTER_ID_B, tag, cost, false))
            .await?;
    }
    for tag in OSPFV3_VLAN_TAGS {
        a.wait(&format!(
            "ospfv3 neighbor reached full link=eth1.{tag} neighbor={OSPFV3_ROUTER_ID_B}"
        ))
        .await?;
    }

    // Only the loopback's first IPv6 address is originated: drop the one
    // `ospfv3-stub-router` leaves first (absent when run standalone) (#1313).
    let _ = b
        .provision(&["--loopback-remove-address", OSPFV3_LFA_LOOPBACK_ADDRESS])
        .await;
    let primary = format!("added route prefix={prefix}.*source=Some(Ospf) backup=false");
    let p0 = a.count(&primary);
    b.provision(&[
        "--ospfv3-loopback-address",
        prefix,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ])
    .await?;
    a.wait_new(&primary, p0, 60).await?;

    // The move: one replace of the installed route, then quiet.
    let replaced = format!("added route prefix={prefix}.*backup=false.* replaced=true");
    let r0 = a.count(&replaced);
    a.provision_flags(&vlan(
        A,
        OSPFV3_ROUTER_ID,
        t10,
        OSPFV3_VLAN_MOVED_COST,
        false,
    ))
    .await?;
    a.wait_new(&replaced, r0, 60).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let r1 = a.count(&replaced);
    a.assert_quiet(&replaced, r1, 20).await?;

    // Cleanup so the following phases see the lab they expect.
    b.provision(&["--clear-ospfv3-loopback-profile", OSPFV3_PROFILE])
        .await?;
    b.provision(&["--loopback-remove-address", prefix]).await?;
    for tag in OSPFV3_VLAN_TAGS {
        a.provision_flags(&vlan(A, OSPFV3_ROUTER_ID, tag, 1, true))
            .await?;
        b.provision_flags(&vlan(B, OSPFV3_ROUTER_ID_B, tag, 1, true))
            .await?;
    }
    a.provision_flags(&other_cost(1)).await
}

/// #157, RFC 2328 §14.1 (requires `ospfv3-dr`): router-a and router-c leave
/// the bridge, so router-b — its DR — loses its last `Full` neighbor there
/// and prematurely ages its Network-LSA (legacy 0x2002 or, after `ospfv3`
/// turned extended-lsa on, E-Network 0xa022); router-a, still adjacent over
/// `eth0.0`, flushes it within seconds instead of at `MaxAge` an hour later.
pub async fn ospfv3_flush(w: &mut World) -> anyhow::Result<()> {
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    // `logs::bre` has top-level `\|` only, no `\( \)` groups.
    let either = |f: &dyn Fn(u16) -> String| format!(r"{}\|{}", f(0x2002), f(0xa022));
    let aged = either(&|t| format!("ospfv3 lsa prematurely aged lsa_type={t} "));
    let flushed = either(&|t| {
        format!(
            "ospfv3 lsa maxage flushed .*lsa_type={t} .*advertising_router={OSPFV3_ROUTER_ID_B}"
        )
    });
    let (aged0, flushed0) = (b.count(&aged), a.count(&flushed));
    let leave = strings(&[
        "--broadcast-domain",
        BD,
        "--clear-ospfv3-broadcast-domain-profile",
        OSPFV3_PROFILE,
    ]);
    a.provision(&leave).await?;
    c.provision_flags(&with_base(crate::router::C, leave))
        .await?;
    // Dead interval (40s) on router-b, then one origination tick.
    b.wait_new(&aged, aged0, 90).await?;
    a.wait_new(&flushed, flushed0, 60).await?;

    // RFC 2328 §13.4 (#731): a SIGKILLed router-b restarts with an empty
    // LSDB and gets its own Router-LSA back from router-a with a newer
    // sequence number (its links changed above); it re-originates above it.
    let full_on_a =
        format!("ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}");
    let (reflected0, full0) = (
        b.count("ospfv3 self-originated lsa received with newer sequence"),
        a.count(&full_on_a),
    );
    log("killing router-b's nos-ospfv3d; it must re-originate above its reflected router-lsa");
    w.dock.kill_process("router-b", "nos-ospfv3d").await?;
    b.wait_new(
        "ospfv3 self-originated lsa received with newer sequence",
        reflected0,
        90,
    )
    .await?;
    b.wait(&format!(
        "ospfv3 lsa originated.*advertising_router={OSPFV3_ROUTER_ID_B}.*reflected=true"
    ))
    .await?;
    a.wait_new(&full_on_a, full0, 90).await
}

/// Passive interface (#1137, requires `ospf`): router-a attaches a second,
/// passive profile to a routed subinterface (`eth0.300`, 192.0.2.1/24).
/// Its subnet is advertised as a stub network (router-b installs it over the
/// active link) but no link starts and no OSPF event ever names it; clearing
/// `passive` starts the link in place, setting it again stops it; the
/// subinterface is deleted at the end.
pub async fn ospf_passive(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let tag = SUBINTERFACE_TAG;
    let link = format!("eth0.{tag}");
    let lan = "192.0.2.0/24";
    let passive_p = "ospf-passive-profile";
    let flags = |extra: &[&str]| {
        let mut f = strings(&[
            "--address",
            SUBINTERFACE_ADDRESS,
            "--subinterface-tag",
            &tag.to_string(),
            "--routing-table",
            "rt1",
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--remote-as",
            &ASN_B.to_string(),
            "--peer",
            IP_B.s(),
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            OSPF_ROUTER_ID,
            "--ospf-area",
            OSPF_AREA,
            "--ospf-profile",
            passive_p,
            "--ospf-interface-profile",
            passive_p,
        ]);
        f.extend(strings(extra));
        f
    };
    let advertised = format!("ospf passive interface advertised attach_point={link}");
    let started = format!("ospf link driver started link={link}");
    let stopped = format!("ospf link stopped link={link}");
    let route = format!("added route prefix={lan}.*source=Some(Ospf)");
    let (adv0, route0) = (a.count(&advertised), b.count(&route));

    log("attaching a passive profile to router-a's eth0.300");
    a.provision_flags(&flags(&["--ospf-passive", "true"]))
        .await?;
    a.wait_new(&advertised, adv0, 60).await?;
    b.wait_new(&route, route0, 60).await?;
    // #1212: "no link starts, no OSPF event names it". Not bare `link={link}`:
    // that also matches `kernel interface down ... reason=absent`, logged
    // while nos-interfaced has not yet created the device (`GET /v1/interfaces`
    // is config-derived, so it cannot tell when the device exists).
    let events = format!(
        "ospf link driver started link={link}\\|ospf link stopped link={link}\\|ospf neighbor .*link={link}\\|ospf hello.*link={link}"
    );
    a.assert_quiet(&events, a.count(&events), 15).await?;

    log("clearing passive: the link starts in place");
    let adv1 = a.count(&advertised);
    a.provision_flags(&flags(&["--ospf-passive", "false"]))
        .await?;
    a.wait(&started).await?;

    log("passive again: the link stops, the stub returns");
    a.provision_flags(&flags(&["--ospf-passive", "true"]))
        .await?;
    a.wait(&stopped).await?;
    a.wait_new(&advertised, adv1, 60).await?;

    a.provision_flags(&strings(&[
        "--address",
        SUBINTERFACE_ADDRESS,
        "--subinterface-tag",
        &tag.to_string(),
        "--asn",
        &ASN_A.to_string(),
        "--router-id",
        RID_A,
        "--remote-as",
        &ASN_B.to_string(),
        "--peer",
        IP_B.s(),
        "--delete-subinterface",
    ]))
    .await
}

/// RFC 2328 §9.5 point-to-multipoint (requires `ospf`): the shared profile's
/// network type forced to `point-to-multipoint` on router-a/router-b's eth0.0
/// and bd-ospf bridge. Hello must still reach `Full` on both links with no
/// DR election, router-a must learn router-b's own interface address as a /32
/// stub (§12.4.1.4) and route to a loopback behind it; clearing the override
/// restores point-to-point and the bridge's DR/BDR election.
pub async fn ospf_p2mp(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let bridge = format!("link=broadcast-domain:{BD}");
    let full_bridge =
        |neighbor: &str| format!("ospf neighbor reached full {bridge} neighbor={neighbor}");
    let became_dr = format!("ospf interface became dr {bridge}");
    let set = |rid: &str, kind: &str| {
        let mut f = ospf(rid);
        f.extend(strings(&["--ospf-profile-network-type", kind]));
        f
    };
    let stub = format!(
        "{}/32",
        OSPF_BROADCAST_ADDRESS_B
            .split('/')
            .next()
            .unwrap_or_default()
    );

    let (p0, q0, bq0) = (
        a.count(&full_p2p(OSPF_ROUTER_ID_B)),
        a.count(&full_bridge(OSPF_ROUTER_ID_B)),
        b.count(&full_bridge(OSPF_ROUTER_ID)),
    );
    log("forcing network-type point-to-multipoint on both routers' shared profile");
    a.provision_flags(&with_base(A, set(OSPF_ROUTER_ID, "point-to-multipoint")))
        .await?;
    b.provision_flags(&with_base(B, set(OSPF_ROUTER_ID_B, "point-to-multipoint")))
        .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), p0, 90).await?;
    a.wait_new(&full_bridge(OSPF_ROUTER_ID_B), q0, 90).await?;
    // No election ever runs on a point-to-multipoint link. (The baseline is
    // taken once both ends have restarted: router-b was still broadcast, and
    // elected itself DR again, while only router-a had flipped.)
    b.wait_new(&full_bridge(OSPF_ROUTER_ID), bq0, 90).await?;
    let dr0 = b.count(&became_dr);
    b.assert_quiet(&became_dr, dr0, 6).await?;

    // §12.4.1.4: router-b's Router-LSA carries a /32 stub for its own bridge
    // address (the subnet stub is gone), which router-a's SPF turns into a route.
    for _ in 0..60 {
        if a.rt1_has(&stub, "Ospf").await? {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !a.rt1_has(&stub, "Ospf").await? {
        bail!("router-a never learned router-b's {stub} stub over point-to-multipoint");
    }

    let lo = OSPF_SPF_LOOPBACK_ADDRESS;
    let route = format!("added route prefix={lo}.*source=Some(Ospf)");
    let r0 = a.count(&route);
    b.provision(&[
        "--loopback-address",
        lo,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    a.wait_new(&route, r0, 60).await?;
    b.provision(&["--clear-ospf-loopback-profile"]).await?;
    a.wait_ospf_route_gone(lo, 15).await?;

    log("clearing the network-type override: point-to-point and the bridge election are back");
    let (p0, dr0) = (a.count(&full_p2p(OSPF_ROUTER_ID_B)), b.count(&became_dr));
    a.provision_flags(&with_base(A, set(OSPF_ROUTER_ID, "clear")))
        .await?;
    b.provision_flags(&with_base(B, set(OSPF_ROUTER_ID_B, "clear")))
        .await?;
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), p0, 90).await?;
    b.wait_new(&became_dr, dr0, 60).await?;
    a.wait_ospf_route_gone(&stub, 10).await
}

// --- RFC 7490 remote LFA ---

/// The ring, in order: ring link `i` joins `RING[i-1]`'s eth1 to the next
/// router's eth2.
const RING: [Id; 5] = [A, B, C, D, E];

fn ring_router_id(n: usize) -> String {
    format!("9.9.10.{n}")
}

fn ring_loopback(n: usize) -> String {
    format!("{RLFA_LOOPBACK_PREFIX}.{n}")
}

/// Router `n` (1-based) of the ring: `iface`'s tag-0 subinterface at
/// `address` in OSPF, its loopback in OSPF, and `remote-lfa` set to `on`.
fn ring_flags(id: Id, n: usize, iface: &str, address: &str, on: bool) -> Vec<String> {
    strings(&[
        "--interface",
        iface,
        "--address",
        address,
        "--asn",
        &id.asn.to_string(),
        "--router-id",
        id.rid,
        "--remote-as",
        &id.remote_as.to_string(),
        "--peer",
        id.peer_ip.s(),
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        &ring_router_id(n),
        "--ospf-area",
        OSPF_AREA,
        "--ospf-profile",
        OSPF_PROFILE,
        "--ospf-interface-profile",
        OSPF_PROFILE,
        "--ospf-remote-lfa",
        &on.to_string(),
        "--loopback-address",
        &format!("{}/32", ring_loopback(n)),
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
}

/// Ring link `n`: a direct veth pair from `RING[n-1]`'s eth1 to the next
/// router's eth2, created by the privileged helper (as `link_veths`).
async fn ring_link(w: &World, n: usize) -> anyhow::Result<()> {
    let (from, to) = (RING[n - 1].name, RING[n % RING.len()].name);
    let (pid_from, pid_to) = (
        w.dock.pid(from).await?.to_string(),
        w.dock.pid(to).await?.to_string(),
    );
    log(format!("creating ring link {n}: {from} eth1 <-> {to} eth2"));
    w.dock
        .ip(
            NETNS_HELPER_IMAGE,
            None,
            true,
            &[
                "link", "add", "eth1", "netns", &pid_from, "type", "veth", "peer", "name", "eth2",
                "netns", &pid_to,
            ],
        )
        .await
        .map(drop)
}

/// `ip link set eth2 <state>` in router-b's netns (the end of ring link 1).
async fn set_eth2(w: &World, state: &str) -> anyhow::Result<()> {
    w.dock
        .ip(
            NETNS_HELPER_IMAGE,
            Some("router-b"),
            false,
            &["link", "set", "eth2", state],
        )
        .await
        .map(drop)
}

/// RFC 7490 remote LFA over a real five-router ring (a-b-c-d-e-a, direct veth
/// pairs, unit costs, `remote-lfa` on all five). For router-a, router-b's
/// loopback has no basic LFA — router-e's shortest path to it runs back
/// through router-a — but one PQ node, router-d (P-space {e, d}, Q-space
/// {c, d}): router-a installs a backup that tunnels to router-d's loopback.
/// Cutting router-a's link to router-b then carries a ping as IP-in-IP
/// through router-d until SPF moves the primary to router-e.
#[allow(clippy::too_many_lines)]
pub async fn ospf_remote_lfa(w: &mut World) -> anyhow::Result<()> {
    for id in RING {
        w.start(id, None, &[]).await?;
    }
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    w.dock
        .ensure_image(
            HOST_IMAGE,
            "FROM debian:trixie-slim\n\
             RUN apt-get update && apt-get install -y --no-install-recommends \\\n \
             iproute2 iputils-ping iputils-arping tcpdump && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    for n in 1..=RING.len() {
        ring_link(w, n).await?;
    }
    // Containers start with forwarding off, and the PQ node and the routers
    // between it and router-b forward the decapsulated packets.
    for id in RING {
        w.dock
            .in_netns(
                NETNS_HELPER_IMAGE,
                id.name,
                &["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
            )
            .await?;
    }
    for (i, id) in RING.into_iter().enumerate() {
        let n = i + 1;
        let prev = if n == 1 { RING.len() } else { n - 1 };
        let r = w.get(id)?;
        r.provision_flags(&ring_flags(
            id,
            n,
            "eth1",
            &format!("{RLFA_RING_PREFIX}.{n}.1/24"),
            true,
        ))
        .await?;
        r.provision_flags(&ring_flags(
            id,
            n,
            "eth2",
            &format!("{RLFA_RING_PREFIX}.{prev}.2/24"),
            true,
        ))
        .await?;
    }
    let (a, d) = (w.a()?, w.get(D)?);
    for (link, neighbor) in [("eth1.0", 2), ("eth2.0", 5)] {
        a.wait_new(
            &format!(
                "ospf neighbor reached full link={link} neighbor={}",
                ring_router_id(neighbor)
            ),
            0,
            90,
        )
        .await?;
    }
    // Every rLFA router builds the decapsulating device: any may be a PQ node.
    d.wait(&format!(
        "created remote lfa tunnel device device={RLFA_DEVICE}"
    ))
    .await?;

    let (b_lo, d_lo) = (ring_loopback(2), ring_loopback(4));
    let b_prefix = format!("{b_lo}/32");
    let tunnel =
        format!("added route prefix={b_prefix} gateway={d_lo} .*backup=true .*tunnel=true");
    a.wait_new(&tunnel, 0, 90).await?;
    let table = a.routes_walk("rt1", None).await?;
    let shown = table.iter().any(|p| {
        p["prefix"] == b_prefix.as_str()
            && p["candidates"][0]["backup"] == d_lo.as_str()
            && p["candidates"][0]["backup_tunnel"] == true
    });
    if !shown {
        bail!("router-a's GET /v1/routes/rt1 shows no tunnel backup via {d_lo} for {b_prefix}: {table:?}");
    }

    // #277: a nos-interfaced kill tears no link down. The kill is followed at
    // once by a config change, so a resync runs while its answers are refused;
    // the running links keep their values and every adjacency stays up.
    let b = w.get(B)?;
    let stops = (a.count("ospf link stopped"), b.count("ospf link stopped"));
    let downs = (
        a.count("ospf neighbor state changed to down"),
        b.count("ospf neighbor state changed to down"),
    );
    let (fallback0, stream0) = (
        a.count("ospf link resolution failed, keeping running link"),
        a.count("ospf link stream connected"),
    );
    // The refused window is the watchdog's 1 s restart backoff: the fallback
    // line lands 0.2 s after the kill when the provision is quick, but a
    // loaded host can finish the resync after nos-interfaced is back, and
    // then nothing falls back (#1343). A miss is retried with a new kill and
    // a config change that really changes the link set (max-metric 5, 6, 7);
    // the crash backoff grows, so each retry widens the window.
    let mut fell_back = false;
    for metric in ["5", "6", "7"] {
        log("killing router-a's nos-interfaced");
        w.dock.kill_process("router-a", "nos-interfaced").await?;
        let mut flags = ring_flags(A, 1, "eth1", &format!("{RLFA_RING_PREFIX}.1.1/24"), true);
        flags.extend(strings(&["--ospf-max-metric-on-startup", metric]));
        a.provision_flags(&flags).await?;
        if a.wait_new(
            "ospf link resolution failed, keeping running link",
            fallback0,
            6,
        )
        .await
        .is_ok()
        {
            fell_back = true;
            break;
        }
        log("resync ran after nos-interfaced was back, retrying the kill");
    }
    if !fell_back {
        bail!("router-a: no 'ospf link resolution failed' line after three nos-interfaced kills");
    }
    a.wait_new("ospf link stream connected", stream0, 20)
        .await?;
    tokio::time::sleep(Duration::from_secs(15)).await;
    for (r, n_stop, n_down) in [(a, stops.0, downs.0), (b, stops.1, downs.1)] {
        for (pat, n) in [
            ("ospf link stopped", n_stop),
            ("ospf neighbor state changed to down", n_down),
        ] {
            if r.count(pat) > n {
                bail!("{}: '{pat}' moved after a nos-interfaced kill", r.name());
            }
        }
    }
    let mut flags = ring_flags(A, 1, "eth1", &format!("{RLFA_RING_PREFIX}.1.1/24"), true);
    flags.extend(strings(&["--ospf-max-metric-on-startup", "0"]));
    a.provision_flags(&flags).await?;

    // The data plane: cut router-a's link to router-b (deleting the veth
    // flushes the primary at once) and ping router-b's loopback from
    // router-a's VRF. The echo requests must reach router-d as IP-in-IP to
    // its loopback, while SPF has not yet moved the primary.
    let via_e =
        format!("added route prefix={b_prefix} gateway={RLFA_RING_PREFIX}.5.1 .*backup=false");
    let via_e0 = a.count(&via_e);
    let absent = "ospf link kernel interface down link=eth1.0 .*reason=absent";
    let absent0 = a.count(absent);
    let filter = format!("ip proto 4 and dst host {d_lo}");
    let tcpdump = ["timeout", "30", "tcpdump", "-c", "1", "-ni", "any", &filter];
    // The ping starts before the cut and runs across it: one started after
    // the cut pays container-start latency and can miss the short window in
    // which the tunnel backup is the only route (#735).
    let ping = [
        "ping", "-I", RLFA_VRF, "-c", "100", "-i", "0.2", "-W", "1", &b_lo,
    ];
    let dock = &w.dock;
    let (captured, pinged, cut) = tokio::join!(
        dock.in_netns(HOST_IMAGE, "router-d", &tcpdump),
        dock.in_netns(HOST_IMAGE, "router-a", &ping),
        async {
            tokio::time::sleep(Duration::from_secs(6)).await;
            log("cutting router-a's link to router-b");
            dock.ip(
                NETNS_HELPER_IMAGE,
                Some("router-a"),
                false,
                &["link", "del", "eth1"],
            )
            .await
        }
    );
    cut?;
    let pinged = pinged?;
    log(format!("router-a's ping to {b_lo}: {}", pinged.trim()));
    let captured =
        captured.map_err(|e| anyhow::anyhow!("no ip-in-ip to {d_lo} on router-d: {e:#}"))?;
    log(format!("router-d: {}", captured.trim()));

    // SPF reconverges: the primary moves to router-e and, the ring now being
    // a line, no backup is left.
    a.wait_new(absent, absent0, 5).await?;
    a.wait_new(&via_e, via_e0, 15).await?;
    a.wait(&format!("removed route prefix={b_prefix} .*backup=true"))
        .await?;

    // The link back: the direct primary and the tunnel backup return.
    let direct =
        format!("added route prefix={b_prefix} gateway={RLFA_RING_PREFIX}.1.2 .*backup=false");
    let (direct0, tunnel0) = (a.count(&direct), a.count(&tunnel));
    ring_link(w, 1).await?;
    a.wait_new(&direct, direct0, 90).await?;
    a.wait_new(&tunnel, tunnel0, 60).await?;

    // #277: carrier loss alone tears the link down at once, with no dead
    // timer. router-b sets its end down; router-a sees the peer's carrier go.
    let full = format!(
        "ospf neighbor reached full link=eth1.0 neighbor={}",
        ring_router_id(2)
    );
    let (nc, ad, full0) = (
        a.count("ospf link kernel interface down link=eth1.0 .*reason=no-carrier"),
        b.count("ospf link kernel interface down link=eth2.0 .*reason=admin-down"),
        a.count(&full),
    );
    let dead0 = (
        a.count("ospf neighbor state changed to down"),
        b.count("ospf neighbor state changed to down"),
    );
    sync_to_reapply(b).await?;
    set_eth2(w, "down").await?;
    a.wait_new(
        "ospf link kernel interface down link=eth1.0 .*reason=no-carrier",
        nc,
        5,
    )
    .await?;
    b.wait_new(
        "ospf link kernel interface down link=eth2.0 .*reason=admin-down",
        ad,
        5,
    )
    .await?;
    if a.count("ospf neighbor state changed to down") > dead0.0
        || b.count("ospf neighbor state changed to down") > dead0.1
    {
        bail!("a dead timer expired: link-down detection did not come from the stream");
    }
    set_eth2(w, "up").await?;
    a.wait_new(&full, full0, 60).await?;

    // remote-lfa off deletes the device.
    d.provision_flags(&ring_flags(
        D,
        4,
        "eth1",
        &format!("{RLFA_RING_PREFIX}.4.1/24"),
        false,
    ))
    .await?;
    d.wait(&format!(
        "deleted remote lfa tunnel device device={RLFA_DEVICE}"
    ))
    .await?;
    w.remove(D).await;
    w.remove(E).await;
    Ok(())
}

/// What differs between `ospf-bfd` and `ospfv3-bfd`.
struct BfdScenario {
    /// Daemon name in log lines: `ospf` or `ospfv3`.
    daemon: &'static str,
    /// `--ospf-bfd` / `--ospfv3-bfd` and their removal.
    on: &'static str,
    off: &'static str,
    /// The neighbor's BFD peer address as a log pattern (`fe80::` for v3).
    peer: String,
    /// router-b's loopback flags and prefix: the route that must vanish.
    loopback: Vec<String>,
    prefix: &'static str,
    /// The v3 UDP filter matches `ipv6`.
    v6: bool,
    full_a: String,
    base_a: Vec<String>,
    base_b: Vec<String>,
}

/// Drops (or lifts) UDP 3784 on router-a's ingress; `tc` knows only IPv4 or
/// IPv6 per filter.
async fn bfd_filter(w: &World, v6: bool, drop: bool) -> anyhow::Result<()> {
    use super::bfd::tc;
    if !drop {
        return tc(&w.dock, &["qdisc", "del", "dev", "eth0", "clsact"])
            .await
            .map(|_| ());
    }
    tc(&w.dock, &["qdisc", "add", "dev", "eth0", "clsact"]).await?;
    let (proto, sel) = if v6 { ("ipv6", "ip6") } else { ("ip", "ip") };
    tc(
        &w.dock,
        &[
            "filter", "add", "dev", "eth0", "ingress", "protocol", proto, "u32", "match", sel,
            "protocol", "17", "0xff", "match", sel, "dport", "3784", "0xffff", "action", "drop",
        ],
    )
    .await
    .map(|_| ())
}

/// #288, RFC 5882 §4.1: OSPF over BFD. Both routers get `bfd fast` (100 ms x
/// 3) on the shared profile without resetting the adjacency; a silent UDP 3784
/// drop on router-a takes the session Down and `nos-ospf*d` kills the neighbor
/// within a second (the dead interval is 40 s) and withdraws the route;
/// lifting the drop restores Full and the route; a local `shutdown` on the BFD
/// profile (`AdminDown`) kills nothing.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
async fn bfd_scenario(w: &mut World, s: BfdScenario) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let daemon = s.daemon;
    let down = format!(
        "bfd session down peer={} diag=control-detection-time-expired",
        s.peer
    );
    let up = format!("bfd session up peer={}", s.peer);
    let killing = format!("bfd session down, killing {daemon} neighbor link=eth0.0");
    let add = format!("added route prefix={} .*source=Some(Ospf)", s.prefix);
    // #443: the route may survive on another hop (router-c on the bridge), so a
    // changed hop set (re-add with one next hop) counts as much as a removal.
    let removed = format!(
        "removed route prefix={0}\\|added route prefix={0} .*next_hops=1",
        s.prefix
    );

    log("bfd on the shared profile must not reset the adjacency");
    let torn =
        format!("{daemon} neighbor adjacency torn down\\|{daemon} neighbor state changed to down");
    let (torn_a, torn_b, full_a) = (
        a.count_fresh(&torn).await,
        b.count_fresh(&torn).await,
        a.count_fresh(&s.full_a).await,
    );
    let with = |base: &[String], extra: &[String]| {
        let mut f = base.to_vec();
        f.extend(extra.iter().cloned());
        f
    };
    let (on, off) = (vec![s.on.to_string()], vec![s.off.to_string()]);
    a.provision_flags(&with(&s.base_a, &on)).await?;
    b.provision_flags(&with(&s.base_b, &[on.clone(), s.loopback.clone()].concat()))
        .await?;
    a.wait_new(&up, 0, 30).await?;
    b.wait("bfd session up peer=").await?;
    a.wait_new(&add, 0, 60).await?;
    a.assert_quiet(&torn, torn_a, 3).await?;
    quiet_settled(b, &torn, torn_b).await?;
    quiet_settled(a, &s.full_a, full_a).await?;

    log("UDP 3784 dropped on router-a: BFD Down kills the neighbor in under a second");
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    let (n_down, n_kill, n_removed) = (a.count(&down), a.count(&killing), a.count(&removed));
    let full_base = a.count(&s.full_a);
    let n_add = a.count(&add);
    bfd_filter(w, s.v6, true).await?;
    let result = async {
        a.wait_new(&down, n_down, 10).await?;
        a.wait_new(&killing, n_kill, 5).await?;
        a.assert_delay_under((&down, n_down), (&killing, n_kill), 1000)?;
        a.wait_new(&removed, n_removed, 15).await
    }
    .await;
    let lifted = bfd_filter(w, s.v6, false).await;
    result?;
    lifted?;

    log("drop lifted: Full and the route come back");
    a.wait_new(&s.full_a, full_base, 90).await?;
    a.wait_new(&add, n_add, 60).await?;

    log("local shutdown on the BFD profile is AdminDown: no neighbor is killed");
    let n_kill = a.count(&killing);
    a.edit(|c| {
        c.bfd_profiles.iter_mut().for_each(|p| p.shutdown = true);
        Ok(())
    })
    .await?;
    a.assert_quiet(&killing, n_kill, 5).await?;
    a.edit(|c| {
        c.bfd_profiles.iter_mut().for_each(|p| p.shutdown = false);
        Ok(())
    })
    .await?;

    // #659: a removed session tells its peer AdminDown, so the neighbour's
    // adjacency closes at once (RFC 5882 §3.2) and re-forms without bfd.
    log("removing bfd: a peer's AdminDown may tear the adjacency down once, then it re-forms");
    a.wait_new(&s.full_a, 0, 90).await?;
    let (torn_a, full_a) = (a.count(&torn), a.count(&s.full_a));
    a.provision_flags(&with(&s.base_a, &off)).await?;
    b.provision_flags(&with(&s.base_b, &[off, s.loopback.clone()].concat()))
        .await?;
    // Whether router-a sees it depends on which side retires first: only a
    // torn adjacency has to come back.
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    if a.count(&torn) > torn_a {
        a.wait_new(&s.full_a, full_a, 90).await?;
    }
    // Leave no loopback behind: `ospfv3-lfa` re-provisions this very prefix
    // and waits for a *new* route add, which an identical config never gives.
    let clear = format!("--clear-{}-loopback-profile", s.daemon);
    // The OSPFv3 flag names the profile to remove (#1278); the OSPFv2 one is a switch.
    let mut flags = vec![clear.as_str()];
    if s.v6 {
        flags.push(OSPFV3_PROFILE);
    }
    b.provision(&flags).await?;
    if !s.v6 {
        // The address left on the loopback made `ospf-graceful-restart`'s
        // second loopback address vanish from router-b's LSA (#1293).
        b.provision(&["--loopback-remove-address", s.prefix])
            .await?;
    }
    Ok(())
}

/// `ospf-bfd` (#288), on the `ospf` lab.
pub async fn ospf_bfd(w: &mut World) -> anyhow::Result<()> {
    bfd_scenario(
        w,
        BfdScenario {
            daemon: "ospf",
            on: "--ospf-bfd",
            off: "--no-ospf-bfd",
            peer: IP_B.s().to_string(),
            loopback: strings(&[
                "--loopback-address",
                OSPF_SPF_LOOPBACK_ADDRESS,
                "--ospf-loopback-profile",
                OSPF_PROFILE,
            ]),
            prefix: OSPF_SPF_LOOPBACK_ADDRESS,
            v6: false,
            full_a: full_p2p(OSPF_ROUTER_ID_B),
            base_a: with_base(A, ospf(OSPF_ROUTER_ID)),
            base_b: with_base(B, ospf(OSPF_ROUTER_ID_B)),
        },
    )
    .await
}

/// `ospfv3-bfd` (#288), on the `ospfv3` lab: sessions between link-local
/// addresses, scoped by `eth0.0`.
pub async fn ospfv3_bfd(w: &mut World) -> anyhow::Result<()> {
    bfd_scenario(
        w,
        BfdScenario {
            daemon: "ospfv3",
            on: "--ospfv3-bfd",
            off: "--no-ospfv3-bfd",
            peer: "fe80::.*".to_string(),
            loopback: strings(&[
                "--ospfv3-loopback-address",
                OSPFV3_LFA_LOOPBACK_ADDRESS,
                "--ospfv3-loopback-profile",
                OSPFV3_PROFILE,
            ]),
            prefix: OSPFV3_LFA_LOOPBACK_ADDRESS,
            v6: true,
            full_a: format!(
                "ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID_B}"
            ),
            base_a: with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)),
            base_b: with_base(B, ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)),
        },
    )
    .await
}

// --- #959: SPF two-way connectivity check ---

/// One protocol's run of `ospf_forged_lsa`.
struct Forge {
    /// `forged_lsa.py`'s mode.
    mode: &'static str,
    /// The daemon `comm` to freeze on router-b.
    daemon: &'static str,
    /// Log prefix (`ospf`/`ospfv3`).
    log: &'static str,
    database: &'static str,
    a_rid: &'static str,
    b_rid: &'static str,
    forged: &'static str,
    control: &'static str,
}

/// The highest sequence number of `advertiser`'s Router-LSA in `r`'s database.
async fn router_lsa_seq(r: &Router, database: &str, advertiser: &str) -> anyhow::Result<i32> {
    let body = r.rest_expect(Method::GET, database, None, 200).await?;
    let report: serde_json::Value = serde_json::from_str(&body)?;
    report[0]["result"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|l| l["lsa_type"] == 1 && l["advertising_router"] == advertiser)
        .filter_map(|l| l["sequence_number"].as_i64())
        .max()
        .and_then(|s| i32::try_from(s).ok())
        .ok_or_else(|| anyhow::anyhow!("no router-lsa of {advertiser} in {body}"))
}

/// RFC 2328 §16.1 step 2(b) / RFC 5340 §4.8.1 against real packets: router-b's
/// daemon is frozen (`SIGSTOP`) so it cannot refute, and `forged_lsa.py` floods
/// router-a a one-sided link from router-b to a router that does not exist.
/// The LSAs are installed but no route follows; once the fake router links back
/// (control) its prefix is routed; MaxAge flushes it. Always resumes router-b.
async fn forge(w: &World, f: &Forge) -> anyhow::Result<()> {
    let a = w.a()?;
    w.dock
        .ensure_image(
            PYTHON_HELPER_IMAGE,
            "FROM debian:trixie-slim\n\
            RUN apt-get update && apt-get install -y --no-install-recommends python3-minimal \\\n \
            && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    // Let the adjacency's own LSA exchange settle: an LSA of router-b's
    // installed just before the forged one would make MinLSArrival drop it.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let seq = if f.mode == "v2" {
        // router-b's own copy is authoritative (router-a's may lag a flood);
        // the margin covers one origination between this read and the freeze.
        router_lsa_seq(w.b()?, f.database, f.b_rid).await? + 100
    } else {
        0
    }
    .to_string();
    let b_ip = if f.mode == "v2" { IP_B.s() } else { "-" };
    let inject = |step: &'static str, prefix: &'static str| {
        let args = [
            "python3",
            "-c",
            include_str!("forged_lsa.py"),
            f.mode,
            step,
            OSPF_AREA,
            f.b_rid,
            f.a_rid,
            FORGED_ROUTER_ID,
            &seq,
            b_ip,
            prefix,
        ];
        async move {
            let out = w
                .dock
                .in_netns(PYTHON_HELPER_IMAGE, "router-b", &args)
                .await?;
            log(out.trim());
            anyhow::Ok(())
        }
    };
    let route = |p: &str| format!("added route prefix={p}.*source=Some(Ospf)");
    let installed = format!(
        "{} lsa installed.*advertising_router={FORGED_ROUTER_ID}",
        f.log
    );
    let (i0, fr0, cr0) = (
        a.count(&installed),
        a.count(&route(f.forged)),
        a.count(&route(f.control)),
    );
    let removed = format!("removed route prefix={}", f.control);
    let rm0 = a.count(&removed);
    let refuted = format!("{} lsa installed.*advertising_router={}", f.log, f.b_rid);
    let refuted0 = a.count(&refuted);

    log(format!(
        "freezing router-b's {} (must stay << 40s)",
        f.daemon
    ));
    w.dock.signal_process("router-b", f.daemon, "-STOP").await?;
    let run = async {
        inject("forged", f.forged).await?;
        a.wait_new(&installed, i0, 20).await?;
        if f.mode == "v2" {
            // The replaced Router-LSA is held (not dropped by MinLSArrival).
            a.wait_new(&refuted, refuted0, 5).await?;
        }
        a.assert_quiet(&route(f.forged), fr0, 6).await?;
        inject("control", f.control).await?;
        a.wait_new(&route(f.control), cr0, 20).await?;
        // MinLSArrival (1s) would drop an instance sent right behind the last.
        tokio::time::sleep(Duration::from_secs(2)).await;
        inject("flush", f.control).await?;
        a.wait_new(&removed, rm0, 20).await
    }
    .await;
    // Always thaw, even when a check failed.
    let held = a.count(&refuted);
    let thaw = w.dock.signal_process("router-b", f.daemon, "-CONT").await;
    run?;
    thaw?;
    if f.mode == "v2" {
        // router-b sees its replaced Router-LSA flooded back and reoriginates.
        a.wait_new(&refuted, held, 60).await?;
    }
    Ok(())
}

/// #959 (self-contained): OSPFv2 and OSPFv3 SPF reject an edge whose far side
/// does not link back, so one forged LSA cannot attract routes (see `forge`).
pub async fn ospf_forged_lsa(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    for (r, id, rid, addr, rid3) in [
        (a, A, OSPF_ROUTER_ID, OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID),
        (b, B, OSPF_ROUTER_ID_B, OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B),
    ] {
        let mut f = ospf(rid);
        f.extend(ospfv3(addr, rid3));
        r.provision_flags(&with_base(id, f)).await?;
    }
    both_full_p2p(a, b).await?;
    for (x, peer) in [(a, OSPFV3_ROUTER_ID_B), (b, OSPFV3_ROUTER_ID)] {
        x.wait(&format!(
            "ospfv3 neighbor reached full link=eth0.0 neighbor={peer}"
        ))
        .await?;
    }
    forge(
        w,
        &Forge {
            mode: "v2",
            daemon: "nos-ospfd",
            log: "ospf",
            database: "/v1/ospf/database",
            a_rid: OSPF_ROUTER_ID,
            b_rid: OSPF_ROUTER_ID_B,
            forged: FORGED_V4_PREFIX,
            control: FORGED_V4_CONTROL,
        },
    )
    .await?;
    forge(
        w,
        &Forge {
            mode: "v3",
            daemon: "nos-ospfv3d",
            log: "ospfv3",
            database: "/v1/ospfv3/database",
            a_rid: OSPFV3_ROUTER_ID,
            b_rid: OSPFV3_ROUTER_ID_B,
            forged: FORGED_V6_PREFIX,
            control: FORGED_V6_CONTROL,
        },
    )
    .await?;
    a.established().await
}

// --- #1146: LSDB overload limit ---

/// `max-lsa` on router-a in `ospf-max-lsa`: small enough to hit with one injection.
const MAX_LSA_CAP: usize = 10;
/// Distinct fake LSAs injected past it.
const MAX_LSA_INJECTED: usize = 40;
/// Sequence number of the injected LSAs (above the initial one).
const MAX_LSA_SEQ: &str = "2147484000";

/// How many `9.9.1.*` (injected) LSAs `r`'s database holds, and the highest
/// sequence number of one of `r`'s own LSAs (`own`).
async fn max_lsa_counts(r: &Router, database: &str, own: &str) -> anyhow::Result<(usize, i64)> {
    let body = r.rest_expect(Method::GET, database, None, 200).await?;
    let report: serde_json::Value = serde_json::from_str(&body)?;
    let lsas = report[0]["result"].as_array().cloned().unwrap_or_default();
    let fake = lsas
        .iter()
        .filter(|l| {
            l["advertising_router"]
                .as_str()
                .is_some_and(|r| r.starts_with("9.9.1."))
        })
        .count();
    let seq = lsas
        .iter()
        .filter(|l| l["advertising_router"] == own)
        .filter_map(|l| l["sequence_number"].as_i64())
        .max()
        .ok_or_else(|| anyhow::anyhow!("no lsa of {own} in {body}"))?;
    Ok((fake, seq))
}

/// One protocol's run of `ospf_max_lsa`: router-a caps non-self LSAs at
/// `MAX_LSA_CAP`; router-b's netns floods `MAX_LSA_INJECTED` distinct fake
/// Router-LSAs. The limit is logged, the store stops at the cap, and router-a's
/// own LSA still re-originates (a metric change); the fakes are then flushed.
#[allow(clippy::too_many_arguments)]
async fn max_lsa_run(
    w: &World,
    mode: &str,
    log_prefix: &str,
    database: &str,
    a_rid: &str,
    b_rid: &str,
    flags: &[String],
) -> anyhow::Result<()> {
    let a = w.a()?;
    // The shared `nos-ospf-common` line, so one text serves both daemons.
    let limit = "ospf lsdb limit reached";
    let l0 = a.count(limit);
    let seq0 = max_lsa_counts(a, database, a_rid).await?.1;
    let injected = MAX_LSA_INJECTED.to_string();
    let inject = |step: &'static str| {
        let args = [
            "python3",
            "-c",
            include_str!("max_lsa.py"),
            mode,
            step,
            OSPF_AREA,
            b_rid,
            if mode == "v2" { IP_B.s() } else { "-" },
            &injected,
            MAX_LSA_SEQ,
        ];
        async move {
            let out = w
                .dock
                .in_netns(PYTHON_HELPER_IMAGE, "router-b", &args)
                .await?;
            log(out.trim());
            anyhow::Ok(())
        }
    };
    inject("flood").await?;
    a.wait_new(limit, l0, 20).await?;
    // Delayed acks, MinLSArrival and the periodic resend settle in a few seconds.
    tokio::time::sleep(Duration::from_secs(8)).await;
    let (held, _) = max_lsa_counts(a, database, a_rid).await?;
    anyhow::ensure!(
        (1..=MAX_LSA_CAP).contains(&held),
        "{mode}: {held} injected LSAs held with max-lsa {MAX_LSA_CAP}"
    );
    log(format!(
        "{mode}: {held} of {MAX_LSA_INJECTED} injected LSAs held"
    ));
    // Own origination is never blocked: a metric change re-originates.
    let mut stub = flags.to_vec();
    stub.extend(strings(&[
        &format!("--{log_prefix}-max-metric-administrative"),
        "true",
    ]));
    a.provision_flags(&with_base(A, stub)).await?;
    let mut reoriginated = false;
    for _ in 0..30 {
        if max_lsa_counts(a, database, a_rid).await?.1 > seq0 {
            reoriginated = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::ensure!(
        reoriginated,
        "{mode}: own LSA did not re-originate at the cap"
    );
    a.provision_flags(&with_base(A, flags.to_vec())).await?;
    // Leave no fake LSA behind for the next phase.
    tokio::time::sleep(Duration::from_secs(2)).await;
    inject("flush").await
}

/// #1146 (self-contained): `max-lsa` bounds the LSDB a neighbor can grow, in
/// OSPFv2 and OSPFv3 (see `max_lsa_run`).
pub async fn ospf_max_lsa(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let cap = MAX_LSA_CAP.to_string();
    let mut fa = ospf(OSPF_ROUTER_ID);
    fa.extend(ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID));
    fa.extend(strings(&["--ospf-max-lsa", &cap, "--ospfv3-max-lsa", &cap]));
    let mut fb = ospf(OSPF_ROUTER_ID_B);
    fb.extend(ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B));
    a.provision_flags(&with_base(A, fa.clone())).await?;
    b.provision_flags(&with_base(B, fb)).await?;
    both_full_p2p(a, b).await?;
    for (x, peer) in [(a, OSPFV3_ROUTER_ID_B), (b, OSPFV3_ROUTER_ID)] {
        x.wait(&format!(
            "ospfv3 neighbor reached full link=eth0.0 neighbor={peer}"
        ))
        .await?;
    }
    w.dock
        .ensure_image(
            PYTHON_HELPER_IMAGE,
            "FROM debian:trixie-slim\n\
            RUN apt-get update && apt-get install -y --no-install-recommends python3-minimal \\\n \
            && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    max_lsa_run(
        w,
        "v2",
        "ospf",
        "/v1/ospf/database",
        OSPF_ROUTER_ID,
        OSPF_ROUTER_ID_B,
        &fa,
    )
    .await?;
    max_lsa_run(
        w,
        "v3",
        "ospfv3",
        "/v1/ospfv3/database",
        OSPFV3_ROUTER_ID,
        OSPFV3_ROUTER_ID_B,
        &fa,
    )
    .await?;
    a.established().await
}

/// #954: a broadcast-domain attach point reads its bridge's observed kernel
/// MTU. `--mtu 1400` on router-a's eth0 lowers the `eth0.<tag>` bridge port
/// and so `br<N>` (no profile override): router-a rejects router-b's
/// 1500-byte DBDs on the bridge link only; the same on router-b reaches Full;
/// clearing both restores 1500 and Full.
async fn ospf_bridge_mtu(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let link = format!("link=broadcast-domain:{BD}");
    let full = format!("ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_B}");
    let reject = format!("ospf dbd rejected.*local_mtu=1400 neighbor_mtu=1500 {link}");
    let fa = |extra: &[&str]| {
        let mut f = ospf(OSPF_ROUTER_ID);
        f.extend(ospf_broadcast(OSPF_BROADCAST_ADDRESS_A));
        f.extend(strings(extra));
        with_base(A, f)
    };
    let fb = |extra: &[&str]| {
        let mut f = ospf(OSPF_ROUTER_ID_B);
        f.extend(ospf_broadcast(OSPF_BROADCAST_ADDRESS_B));
        f.extend(strings(extra));
        with_base(B, f)
    };
    log("bridge segment: ospf on the broadcast domain at mtu 1500");
    a.provision_flags(&fa(&[])).await?;
    b.provision_flags(&fb(&[])).await?;
    a.wait(&full).await?;
    let (before, rejects) = (a.count(&full), a.count(&reject));
    log("eth0 mtu 1400 on router-a only: the bridge follows its port");
    a.provision_flags(&fa(&["--mtu", "1400"])).await?;
    a.wait_new(&reject, rejects, 90).await?;
    a.assert_quiet(&full, before, 30).await?;
    log("eth0 mtu 1400 on router-b too");
    b.provision_flags(&fb(&["--mtu", "1400"])).await?;
    a.wait_new(&full, before, 90).await?;
    log("clearing both eth0 mtus");
    let before = a.count(&full);
    let full_b = format!("ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID}");
    let before_b = b.count(&full_b);
    let dr = format!("ospf interface became dr {link} dr={OSPF_ROUTER_ID_B}");
    let backup = format!("ospf interface became backup {link} dr={OSPF_ROUTER_ID_B}");
    // router-c (on the bridge since ospf-dr) would otherwise win or hold the
    // DR/BDR role while the restarted links elect, and an existing DR/BDR is
    // not preempted (RFC 2328 §9.4, #1321): detach its OSPF from the bridge so
    // the election between a and b is deterministic, then restore it.
    let c = w.c()?;
    c.edit(|cfg| {
        for d in &mut cfg.broadcast_domains {
            if d.name == BD {
                d.ospf_profile = None;
            }
        }
        Ok(())
    })
    .await?;
    let (dr0, backup0) = (b.count(&dr), a.count(&backup));
    a.provision_flags(&fa(&["--clear-mtu"])).await?;
    b.provision_flags(&fb(&["--clear-mtu"])).await?;
    a.wait_new(&full, before, 90).await?;
    b.wait_new(&full_b, before_b, 90).await?;
    // The restarted bridge links must have left Waiting (DR/BDR elected)
    // before the next phase starts.
    b.wait_new(&dr, dr0, 90).await?;
    a.wait_new(&backup, backup0, 90).await?;
    log("restoring router-c's ospf on the bridge");
    c.provision_flags(&with_base(C, ospf_broadcast(OSPF_BROADCAST_ADDRESS_C)))
        .await?;
    let full_c = format!("ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_C}");
    a.wait(&full_c).await?;
    b.wait(&full_c).await?;
    let started = format!("ospf link driver started {link}");
    for _ in 0..6 {
        let counts = (a.count(&started), b.count(&started));
        tokio::time::sleep(Duration::from_secs(45)).await;
        if counts == (a.count(&started), b.count(&started)) {
            return Ok(());
        }
    }
    anyhow::bail!("bridge links keep restarting after the mtu was cleared")
}

/// `ospf_bridge_mtu` for OSPFv3.
async fn ospfv3_bridge_mtu(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let link = format!("link=broadcast-domain:{BD}");
    let full = format!("ospfv3 neighbor reached full {link} neighbor={OSPFV3_ROUTER_ID_B}");
    let reject = format!("ospfv3 dbd rejected.*local_mtu=1400 neighbor_mtu=1500 {link}");
    let fa = |extra: &[&str]| {
        let mut f = ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID);
        f.extend(ospfv3_broadcast_with_l2(
            OSPF_BROADCAST_ADDRESS_A,
            OSPFV3_BROADCAST_ADDRESS_A,
        ));
        f.extend(strings(extra));
        with_base(A, f)
    };
    let fb = |extra: &[&str]| {
        let mut f = ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B);
        f.extend(ospfv3_broadcast_with_l2(
            OSPF_BROADCAST_ADDRESS_B,
            OSPFV3_BROADCAST_ADDRESS_B,
        ));
        f.extend(strings(extra));
        with_base(B, f)
    };
    log("bridge segment: ospfv3 on the broadcast domain at mtu 1500");
    a.provision_flags(&fa(&[])).await?;
    b.provision_flags(&fb(&[])).await?;
    a.wait(&full).await?;
    let (before, rejects) = (a.count(&full), a.count(&reject));
    log("eth0 mtu 1400 on router-a only: the bridge follows its port");
    a.provision_flags(&fa(&["--mtu", "1400"])).await?;
    a.wait_new(&reject, rejects, 90).await?;
    a.assert_quiet(&full, before, 30).await?;
    log("eth0 mtu 1400 on router-b too");
    b.provision_flags(&fb(&["--mtu", "1400"])).await?;
    a.wait_new(&full, before, 90).await?;
    log("clearing both eth0 mtus");
    let before = a.count(&full);
    let full_b = format!("ospfv3 neighbor reached full {link} neighbor={OSPFV3_ROUTER_ID}");
    let before_b = b.count(&full_b);
    let dr = format!("ospfv3 interface became dr {link} dr={OSPFV3_ROUTER_ID_B}");
    let backup = format!(
        "ospfv3 interface became backup {link} dr={OSPFV3_ROUTER_ID_B} bdr={OSPFV3_ROUTER_ID}"
    );
    let (dr0, backup0) = (b.count(&dr), a.count(&backup));
    a.provision_flags(&fa(&["--clear-mtu"])).await?;
    b.provision_flags(&fb(&["--clear-mtu"])).await?;
    a.wait_new(&full, before, 90).await?;
    b.wait_new(&full_b, before_b, 90).await?;
    // The restarted bridge links must have left Waiting (DR/BDR elected)
    // before the next phase starts.
    b.wait_new(&dr, dr0, 90).await?;
    a.wait_new(&backup, backup0, 90).await?;
    // The bridge MTU reaches each daemon a resync or two apart, and every
    // change restarts the link into Waiting: leave only once no link
    // restarts for longer than the 40s wait.
    // `ospfv3-dr` expects to bring the bridge up itself: detach OSPFv3 from
    // the domain again and let both routers drop the links.
    let leave = strings(&[
        "--broadcast-domain",
        BD,
        "--clear-ospfv3-broadcast-domain-profile",
        OSPFV3_PROFILE,
    ]);
    a.provision_flags(&with_base(A, leave.clone())).await?;
    b.provision_flags(&with_base(B, leave)).await?;
    tokio::time::sleep(Duration::from_secs(20)).await;
    Ok(())
}

/// `ospf-throttle` (#1138, RFC 8405): flapping a redistributed static's
/// metric re-originates its Type-5 every ~2 s; router-b's SPF throttle must
/// back off to the long delay, schedule no more SPFs than flaps, and return
/// to the initial delay after a quiet period.
pub async fn ospf_throttle(w: &mut World) -> anyhow::Result<()> {
    const FLAPS: usize = 8;
    // Fresh lab (#1303): `ospf-aging` leaves `--lsa-age-multiplier` on, whose
    // refresh-driven SPFs would keep the throttle from ever going quiet.
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let base = with_base(A, asbr(ospf(OSPF_ROUTER_ID)));
    a.provision_flags(&base).await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    both_full_p2p(a, b).await?;
    let prefix_lsid = ASBR_PREFIX.split('/').next().unwrap_or_default();
    let reorig_pat = format!("ospf lsa originated lsa_type=5 link_state_id={prefix_lsid} ");
    a.wait(&reorig_pat).await?;
    let sched = "ospf spf scheduled";
    let sched0 = b.count(sched);
    let long0 = b.count("ospf spf scheduled delay_ms=5000");
    for i in 0..FLAPS {
        let before = a.count(&reorig_pat);
        let metric = if i % 2 == 0 { "50" } else { "20" };
        let mut flags = base.clone();
        flags.extend(strings(&["--redistribute-metric", metric]));
        a.provision_flags(&flags).await?;
        a.wait_new(&reorig_pat, before, 60).await?;
    }
    b.wait_new("ospf spf scheduled delay_ms=5000", long0, 30)
        .await?;
    let scheduled = b.count(sched) - sched0;
    anyhow::ensure!(
        scheduled <= FLAPS * 2,
        "{scheduled} SPFs scheduled for {FLAPS} flaps"
    );
    log(format!("{scheduled} SPFs scheduled for {FLAPS} flaps"));

    // Quiet for longer than the 10 s hold-down, then one change: back to 50 ms.
    tokio::time::sleep(std::time::Duration::from_secs(12)).await;
    let quiet0 = b.count("ospf spf scheduled delay_ms=50 state=\"quiet\"");
    let before = a.count(&reorig_pat);
    let mut flags = base.clone();
    flags.extend(strings(&["--redistribute-metric", "50"]));
    a.provision_flags(&flags).await?;
    a.wait_new(&reorig_pat, before, 60).await?;
    b.wait_new("ospf spf scheduled delay_ms=50 state=\"quiet\"", quiet0, 30)
        .await?;

    // #1171: a configured initial delay replaces the default, no restart.
    let mut cfg = with_base(B, ospf(OSPF_ROUTER_ID_B));
    cfg.extend(strings(&["--ospf-spf-initial-ms", "200"]));
    b.provision_flags(&cfg).await?;
    tokio::time::sleep(std::time::Duration::from_secs(12)).await;
    let q200 = b.count("ospf spf scheduled delay_ms=200 state=\"quiet\"");
    let before = a.count(&reorig_pat);
    let mut flags = base.clone();
    flags.extend(strings(&["--redistribute-metric", "20"]));
    a.provision_flags(&flags).await?;
    a.wait_new(&reorig_pat, before, 60).await?;
    b.wait_new("ospf spf scheduled delay_ms=200 state=\"quiet\"", q200, 30)
        .await?;
    let mut cfg = with_base(B, ospf(OSPF_ROUTER_ID_B));
    cfg.extend(strings(&["--ospf-spf-initial-ms", "50"]));
    b.provision_flags(&cfg).await?;
    a.provision(&["--clear-redistribute-to-ospf"]).await?;
    Ok(())
}

/// RFC 8665 SRGB and Prefix-SID (requires `ospf-lfa`, like `ospf-te`): each
/// router advertises the default SRGB and a Prefix-SID for its router id (the
/// two use different indexes); the peer decodes and logs both. Turning
/// segment routing off again leaves the session up.
pub async fn ospf_sr_sid(w: &mut World) -> anyhow::Result<()> {
    let (ra, rb) = (w.a()?, w.b()?);
    let sr = |rid: &str, prefix_sid: Option<&str>| {
        let mut flags = strings(&["--ospf-instance", OSPF_INSTANCE, "--ospf-router-id", rid]);
        match prefix_sid {
            Some(sid) => flags.extend(strings(&["--ospf-prefix-sid", sid])),
            None => flags.extend(strings(&["--ospf-segment-routing", "off"])),
        }
        flags
    };
    let caps = |rid: &str| {
        format!(
            "ospf sr capabilities received area={OSPF_AREA} router={rid} algorithms=\\[0\\] srgb=\\[(16000, 8000)\\]"
        )
    };
    let sid = |rid: &str, index: u32| {
        format!("ospf prefix-sid received area={OSPF_AREA} router={rid} prefix={rid} index={index} flags=0")
    };
    let (a0, b0) = (
        ra.count(&sid(OSPF_ROUTER_ID_B, 2)),
        rb.count(&sid(OSPF_ROUTER_ID, 1)),
    );
    let (ac, bc) = (
        ra.count(&caps(OSPF_ROUTER_ID_B)),
        rb.count(&caps(OSPF_ROUTER_ID)),
    );
    log("advertising SRGB and a Prefix-SID on router-a (index 1) and router-b (index 2)");
    ra.provision(&sr(OSPF_ROUTER_ID, Some(&format!("{OSPF_ROUTER_ID}=1"))))
        .await?;
    rb.provision(&sr(
        OSPF_ROUTER_ID_B,
        Some(&format!("{OSPF_ROUTER_ID_B}=2")),
    ))
    .await?;
    ra.wait_new(&caps(OSPF_ROUTER_ID_B), ac, 60).await?;
    rb.wait_new(&caps(OSPF_ROUTER_ID), bc, 60).await?;
    ra.wait_new(&sid(OSPF_ROUTER_ID_B, 2), a0, 60).await?;
    rb.wait_new(&sid(OSPF_ROUTER_ID, 1), b0, 60).await?;

    log("restoring: segment routing off");
    ra.provision(&sr(OSPF_ROUTER_ID, None)).await?;
    rb.provision(&sr(OSPF_ROUTER_ID_B, None)).await?;
    both_full_p2p(ra, rb).await
}

/// Total MPLS packets (received, sent) over every interface of `router`
/// (`ip stats`, afstats/mpls): the kernel's own proof a labelled packet went by.
async fn mpls_packets(w: &World, router: &str) -> anyhow::Result<(u64, u64)> {
    let out = w
        .dock
        .in_netns(
            NETNS_HELPER_IMAGE,
            router,
            &[
                "ip", "-s", "stats", "show", "group", "afstats", "subgroup", "mpls",
            ],
        )
        .await?;
    // "RX:  bytes packets ..." / "TX: ..." header lines, the numbers on the next one.
    let (mut rx, mut tx) = (0, 0);
    let mut lines = out.lines();
    while let Some(l) = lines.next() {
        let dir = l.trim_start();
        if dir.starts_with("RX:") || dir.starts_with("TX:") {
            let packets: u64 = lines
                .next()
                .and_then(|n| n.split_whitespace().nth(1))
                .and_then(|n| n.parse().ok())
                .with_context(|| format!("{router}: unparsable mpls stats: {out}"))?;
            if dir.starts_with("RX:") {
                rx += packets;
            } else {
                tx += packets;
            }
        }
    }
    Ok((rx, tx))
}

/// Runs one `ip ...` argv in router-a's netns.
async fn router_a_ip(w: &World, cmd: &[String]) -> anyhow::Result<String> {
    let cmd: Vec<&str> = cmd.iter().map(String::as_str).collect();
    w.dock.in_netns(NETNS_HELPER_IMAGE, "router-a", &cmd).await
}

/// `ping -I vrf100` from router-a, requiring no loss.
async fn ping_from_a(w: &World, dst: &str, count: u32) -> anyhow::Result<()> {
    let out = w
        .dock
        .in_netns(
            HOST_IMAGE,
            "router-a",
            &[
                "ping",
                "-I",
                RLFA_VRF,
                "-c",
                &count.to_string(),
                "-i",
                "0.3",
                "-W",
                "2",
                dst,
            ],
        )
        .await?;
    if !out.contains(" 0% packet loss") {
        bail!("router-a: ping {dst} lost packets: {out}");
    }
    Ok(())
}

/// #1383 / #1169 (self-contained): RFC 8665 segment routing forwards. A line
/// a - b - c (a on eth0.0 only, c on the bd-ospf bridge only, b on both; all
/// area 0), each with a loopback and a Prefix-SID. a and c share the docker L2
/// of eth0 but no loopback route: the only path to c's loopback is through b.
/// A ping alone would also pass over plain IP, so the proof is the kernel's
/// MPLS packet counters on router-b (and a), read around the ping; then an
/// explicit-path packet to c's bridge address rides b's Adj-SID alone.
pub async fn ospf_sr(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    w.start(C, None, &[]).await?;
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    w.dock
        .ensure_image(
            HOST_IMAGE,
            "FROM debian:trixie-slim\n\
             RUN apt-get update && apt-get install -y --no-install-recommends \\\n \
             iproute2 iputils-ping iputils-arping tcpdump && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    let (a, b, c) = (w.a()?, w.b()?, w.c()?);
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    b.provision_flags(&with_base(B, ospf_broadcast(OSPF_BROADCAST_ADDRESS_B)))
        .await?;
    c.provision_flags(&with_base(C, ospf_instance_only(OSPF_ROUTER_ID_C)))
        .await?;
    c.provision_flags(&with_base(C, ospf_broadcast(OSPF_BROADCAST_ADDRESS_C)))
        .await?;
    both_full_p2p(a, b).await?;
    let link = format!("link=broadcast-domain:{BD}");
    c.wait(&format!(
        "ospf neighbor reached full {link} neighbor={OSPF_ROUTER_ID_B}"
    ))
    .await?;

    // The interfaces exist now: MPLS input on all of them, platform labels
    // before ribd reads them (it re-applies every 10 s).
    super::bgp::mpls_ready(w, &["router-a", "router-b", "router-c"]).await?;

    let label = |index: u32| 16000 + index;
    let (la, lc) = (label(OSPF_SR_INDEX_A), label(OSPF_SR_INDEX_C));
    let labelled = |lo: &str, l: u32| {
        format!("installed labelled route prefix={lo}/32 labels=\\[\\[{l}\\]\\]")
    };
    let ilm = |l: u32| format!("installed mpls ilm route table=rt1 label={l} ");
    let (a_c0, c_a0) = (
        a.count_fresh(&labelled(OSPF_SR_LOOPBACK_C, lc)).await,
        c.count_fresh(&labelled(OSPF_SR_LOOPBACK_A, la)).await,
    );
    let (b_la0, b_lc0) = (b.count_fresh(&ilm(la)).await, b.count_fresh(&ilm(lc)).await);
    log("loopbacks with Prefix-SIDs on all three routers");
    for (r, rid, lo, index, iface) in [
        (a, OSPF_ROUTER_ID, OSPF_SR_LOOPBACK_A, OSPF_SR_INDEX_A, true),
        (
            b,
            OSPF_ROUTER_ID_B,
            OSPF_SR_LOOPBACK_B,
            OSPF_SR_INDEX_B,
            true,
        ),
        (
            c,
            OSPF_ROUTER_ID_C,
            OSPF_SR_LOOPBACK_C,
            OSPF_SR_INDEX_C,
            false,
        ),
    ] {
        let mut flags = if iface {
            ospf(rid)
        } else {
            ospf_instance_only(rid)
        };
        flags.extend(strings(&[
            "--loopback-address",
            &format!("{lo}/32"),
            "--ospf-loopback-profile",
            OSPF_PROFILE,
            "--ospf-prefix-sid",
            &format!("{lo}={index}"),
        ]));
        r.provision(&flags).await?;
    }
    a.wait_new(&labelled(OSPF_SR_LOOPBACK_C, lc), a_c0, 90)
        .await?;
    c.wait_new(&labelled(OSPF_SR_LOOPBACK_A, la), c_a0, 90)
        .await?;
    b.wait_new(&ilm(la), b_la0, 90).await?;
    b.wait_new(&ilm(lc), b_lc0, 90).await?;

    log("a ping to c's loopback must cross b as MPLS");
    let (rx0, _) = mpls_packets(w, "router-b").await?;
    let (_, atx0) = mpls_packets(w, "router-a").await?;
    ping_from_a(w, OSPF_SR_LOOPBACK_C, 5).await?;
    let (rx1, _) = mpls_packets(w, "router-b").await?;
    let (_, atx1) = mpls_packets(w, "router-a").await?;
    log(format!(
        "mpls packets: router-b rx {rx0} -> {rx1}, router-a tx {atx0} -> {atx1}"
    ));
    if rx1 < rx0 + 5 || atx1 < atx0 + 5 {
        bail!("no labelled packets across router-b: rx {rx0}->{rx1}, a tx {atx0}->{atx1}");
    }

    log("explicit path: router-b's Adj-SID toward router-c as the only label");
    let sid = b_adj_sid_to_c(w).await?;
    let target = OSPF_BROADCAST_ADDRESS_C.trim_end_matches("/28");
    let host = format!("{target}/32");
    let (rx0, _) = mpls_packets(w, "router-b").await?;
    let sid_s = sid.to_string();
    // #1512: not in table 100, which nos-ribd owns and reconciles away (a
    // foreign route is deleted within ms to 10 s). Table 200 is allocated by
    // no scenario (`rt1` is always 100); the rule at pref 900 sits before the
    // VRF l3mdev rule, so the VRF-bound ping still hits it.
    let ip = |args: &[&str]| -> Vec<String> {
        std::iter::once("ip")
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect()
    };
    let cleanup = [
        ip(&["rule", "del", "to", &host, "pref", "900"]),
        ip(&["route", "flush", "table", "200"]),
    ];
    let setup = [
        ip(&[
            "route",
            "replace",
            &host,
            "encap",
            "mpls",
            &sid_s,
            "via",
            IP_B.s(),
            "dev",
            "eth0",
            "onlink",
            "table",
            "200",
        ]),
        ip(&["rule", "add", "to", &host, "lookup", "200", "pref", "900"]),
    ];
    let mut res: anyhow::Result<()> = Ok(());
    for cmd in &setup {
        if let Err(e) = router_a_ip(w, cmd).await {
            res = Err(e);
            break;
        }
    }
    let ping = if res.is_ok() {
        ping_from_a(w, target, 10).await
    } else {
        Ok(())
    };
    let diag = router_a_ip(w, &ip(&["route", "get", target, "oif", RLFA_VRF]))
        .await
        .unwrap_or_else(|e| e.to_string());
    for cmd in &cleanup {
        let _ = router_a_ip(w, cmd).await;
    }
    res?;
    ping?;
    let (rx1, _) = mpls_packets(w, "router-b").await?;
    let (_, atx2) = mpls_packets(w, "router-a").await?;
    if rx1 <= rx0 {
        bail!(
            "adj-sid {sid}: router-b mpls rx {rx0}->{rx1}, router-a tx {atx1} -> {atx2}\nroute get: {diag}"
        );
    }

    log("router-c drops its Prefix-SID: the ILM entry on router-b goes, the ping stays up");
    let gone = format!("removed mpls ilm route table=rt1 label={lc}");
    let removed0 = b.count_fresh(&gone).await;
    let mut flags = ospf_instance_only(OSPF_ROUTER_ID_C);
    flags.extend(strings(&["--ospf-segment-routing", "off"]));
    c.provision(&flags).await?;
    b.wait_new(&gone, removed0, 60).await?;
    // router-a keeps the labelled route until it hears c's new Extended
    // Prefix LSA and recomputes; then the plain OSPF route carries it.
    let mut last = Ok(());
    for _ in 0..30 {
        last = ping_from_a(w, OSPF_SR_LOOPBACK_C, 2).await;
        if last.is_ok() {
            break;
        }
    }
    last?;
    both_full_p2p(a, b).await?;
    a.established().await
}

/// What `expect_route` checks of one route of `GET /v1/{ospf,ospfv3}/routes`.
struct WantRoute<'a> {
    class: &'a str,
    adv_router: &'a str,
    /// Exact next-hop count; 0 = any (but at least one).
    hops: usize,
    /// An external-2 route's own metric.
    e2_cost: Option<u64>,
}

/// Polls `r`'s `path` (up to 60s) until the route for `prefix` matches `want`
/// (#1453): class, advertising router, next-hop count, E2 metric.
async fn expect_route(
    r: &Router,
    path: &str,
    prefix: &str,
    want: WantRoute<'_>,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..60 {
        let body = r.rest_expect(Method::GET, path, None, 200).await?;
        let v: serde_json::Value = serde_json::from_str(&body)?;
        let hit = v[0]["result"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|x| x["prefix"] == prefix);
        if let Some(x) = hit {
            let hops = x["next_hops"].as_array().map_or(0, Vec::len);
            if x["class"] == want.class
                && x["advertising_router"] == want.adv_router
                && (hops == want.hops || (want.hops == 0 && hops > 0))
                && want.e2_cost.is_none_or(|c| x["type2_cost"] == c)
                && x["cost"].as_u64().is_some_and(|c| c >= 1)
            {
                return Ok(());
            }
        }
        last = body;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{path} never held {prefix} as {} via {}: {last}",
        want.class,
        want.adv_router
    )
}

/// The label of router-b's Adj-SID toward router-c, from router-a's
/// `GET /v1/ospf/segment-routing` (a LAN Adj-SID names the neighbour).
async fn b_adj_sid_to_c(w: &World) -> anyhow::Result<u32> {
    let a = w.a()?;
    let mut last = String::new();
    for _ in 0..60 {
        let body = a
            .rest_expect(Method::GET, "/v1/ospf/segment-routing", None, 200)
            .await?;
        let v: serde_json::Value = serde_json::from_str(&body)?;
        let found = v[0]["result"]["adj_sids"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|s| s["router"] == OSPF_ROUTER_ID_B && s["neighbor"] == OSPF_ROUTER_ID_C)
            .and_then(|s| s["label"].as_u64());
        if let Some(l) = found {
            return Ok(u32::try_from(l)?);
        }
        last = body;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("router-a never saw router-b's Adj-SID toward router-c: {last}")
}

/// #1386 (self-contained): the default link cost is
/// `reference-bandwidth / link speed`. A docker veth reports 10 Gbit/s, so the
/// default (10000 Mbit/s) costs 1; raising the reference bandwidth to 100000
/// makes it 10 in place (no restart), and clearing it restores 1.
pub async fn ospf_cost(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, ospf(OSPF_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    both_full_p2p(a, b).await?;
    let changed =
        |old: u32, new: u32| format!("ospf link cost changed link=eth0.0 old={old} cost={new}");
    let up0 = a.count_fresh(&changed(1, 10)).await;
    let mut fa = ospf(OSPF_ROUTER_ID);
    fa.extend(strings(&["--ospf-reference-bandwidth", "100000"]));
    a.provision_flags(&with_base(A, fa)).await?;
    a.wait_new(&changed(1, 10), up0, 60).await?;
    let down0 = a.count_fresh(&changed(10, 1)).await;
    let mut fa = ospf(OSPF_ROUTER_ID);
    fa.extend(strings(&["--ospf-reference-bandwidth", "0"]));
    a.provision_flags(&with_base(A, fa)).await?;
    a.wait_new(&changed(10, 1), down0, 60).await?;
    both_full_p2p(a, b).await?;
    a.established().await
}

/// #1387 (self-contained): OSPFv3's default link cost is
/// `reference-bandwidth / link speed`, like `ospf-cost`: the 10 Gbit/s docker
/// veth costs 1; reference bandwidth 100000 makes it 10 in place, clearing it
/// restores 1.
pub async fn ospfv3_cost(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let full = |peer: &str| format!("ospfv3 neighbor reached full link=eth0.0 neighbor={peer}");
    a.provision_flags(&with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)))
        .await?;
    a.wait(&full(OSPFV3_ROUTER_ID_B)).await?;
    b.wait(&full(OSPFV3_ROUTER_ID)).await?;
    let changed =
        |old: u32, new: u32| format!("ospfv3 link cost changed link=eth0.0 old={old} cost={new}");
    for (bw, old, new) in [("100000", 1, 10), ("0", 10, 1)] {
        let base = a.count_fresh(&changed(old, new)).await;
        let mut fa = ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID);
        fa.extend(strings(&["--ospfv3-reference-bandwidth", bw]));
        a.provision_flags(&with_base(A, fa)).await?;
        a.wait_new(&changed(old, new), base, 60).await?;
    }
    a.established().await
}

#[cfg(test)]
mod timeline_tests {
    use super::format_timeline;

    #[test]
    fn timeline_sorted_offset_and_capped() {
        let e = vec![
            (30, "b y".to_string()),
            (-2, "a x".into()),
            (10, "b z".into()),
        ];
        assert_eq!(
            format_timeline(e, 2),
            vec!["t+-2ms a x".to_string(), "t+10ms b z".into()]
        );
    }
}
