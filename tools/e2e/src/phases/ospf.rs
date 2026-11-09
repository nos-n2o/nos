//! OSPFv2 / OSPFv3 phases: real Hello/DBD/LSR/LSU/LSAck adjacencies over raw
//! protocol-89 sockets between real containers, SPF routes into real kernel
//! tables, DR/BDR election on a real Linux bridge, authentication, aging.

use std::time::Duration;

use anyhow::bail;
use reqwest::Method;

use super::bgp::no_leak;
use crate::consts::*;
use crate::router::{log, strings, Id, Router, A, B, C, D, E};
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
        ASBR_GATEWAY,
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

pub async fn ospf_phase(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);

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
    log("confirming the mismatched-hello-interval neighbor never reaches init");
    a.assert_quiet(
        &format!("ospf neighbor state changed to init link=eth0.0 neighbor={OSPF_ROUTER_ID_B}"),
        0,
        8,
    )
    .await?;

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
    // Real LSA content flows and is installed. Not pinned to a link: a
    // router's LSDB is per-area, so which link sees an LSA first is a race.
    a.wait(&format!("ospf lsa installed.*neighbor={OSPF_ROUTER_ID_B}"))
        .await?;
    b.wait(&format!("ospf lsa installed.*neighbor={OSPF_ROUTER_ID}"))
        .await?;
    // RFC 2328 §13.3: every LSA crosses the link with InfTransDelay added to
    // its age, so nothing ever lands at age 0 — not even a just-originated one.
    a.wait_new("ospf lsa installed.*age=[1-9]", 0, 15).await?;
    a.assert_quiet("ospf lsa installed.*age=0$", 0, 0).await?;

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

    // RFC 2328 §13.5 delayed acknowledgment: router-b acks router-a's periodic
    // LSUs on its own RxmtInterval sweep, so some batch is held a second or
    // more before it goes out — impossible with an immediate per-LSU ack.
    b.wait_new("ospf lsack sent.*delayed_ms=[1-9][0-9][0-9][0-9]", 0, 30)
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
    c.assert_quiet(&format!("route prefix={SUBNET}"), 0, 15)
        .await?;

    // RFC 2328 §13.4 (#731): router-b, the bridge's DR, restarts under
    // another router-id. router-a/c still hold its old Network-LSA, whose
    // Link State ID is router-b's bridge address: ours under a stale
    // router-id, so the restarted router-b flushes it. Then the id is restored.
    let stale0 = b.count("ospf stale network lsa flushed");
    log("renumbering router-b's router-id; it must flush its previous incarnation's network-lsa");
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B_RENUMBERED)))
        .await?;
    // Running links keep the router-id they were spawned with: restart.
    w.dock.kill_process("router-b", "nos-ospfd").await?;
    b.wait_new("ospf stale network lsa flushed", stale0, 90)
        .await?;
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
    .await
}

/// OSPF on router-b's loopback (a destination with no neighbor of its own):
/// router-a must compute a route to it via a real SPF over its LSDB and install
/// it into its kernel table — over both of its equal-cost links to router-b
/// (ECMP) — then withdraw it.
pub async fn ospf_spf(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let before = a.count(&format!(
        "ospf lsa installed.*advertising_router={OSPF_ROUTER_ID_B}"
    ));
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
    // Issue #20: router-a's nos-bgpd polls nos-ribd's IGP costs (BGP decision
    // step d) and must see the OSPF route with its real, non-zero SPF metric.
    a.wait(&format!(
        "igp costs updated.*{OSPF_SPF_LOOPBACK_ADDRESS}: [1-9]"
    ))
    .await?;

    let removed = format!("removed route prefix={OSPF_SPF_LOOPBACK_ADDRESS}");
    let removed0 = a.count(&removed);
    b.provision(&["--clear-ospf-loopback-profile"]).await?;
    a.wait_new(&removed, removed0, 60).await?;
    // #190: the route push is event-driven, so once router-b's new Router-LSA
    // is installed the route leaves the kernel table well inside the old 2s
    // poll (the LSA's own arrival is still bounded by origination/flooding).
    a.assert_delay_under(
        &format!("ospf lsa installed.*advertising_router={OSPF_ROUTER_ID_B}"),
        &removed,
        removed0,
        1000,
    )?;
    // `next-hop-reachability` needs the loopback unreachable from its start.
    a.wait_ospf_route_gone(OSPF_SPF_LOOPBACK_ADDRESS, 15).await
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
        if r.rt1_has(SUBNET, "Ospf").await? == want {
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
    c.wait_ospf_route_gone(SUBNET, 15).await?;

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
        .await
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
    a.wait_new(&full_p2p(OSPF_ROUTER_ID_B), before, 60).await
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

    let torn = "ospf neighbor adjacency torn down, back to init link=eth0.0\\|ospf neighbor state changed to down link=eth0.0";
    let flushed = format!("ospf lsa maxage flushed.*advertising_router={OSPF_ROUTER_ID}$");
    let flush_on_a = "ospf flushing self-originated lsas before shutdown";
    let (full_on_b, full_on_a) = (full_p2p(OSPF_ROUTER_ID), full_p2p(OSPF_ROUTER_ID_B));
    let (torn0, flushed0, flush_a0, full_b0, full_a0) = (
        b.count(torn),
        b.count(&flushed),
        a.count(flush_on_a),
        b.count(&full_on_b),
        a.count(&full_on_a),
    );
    let max_metric_on = "ospf stub router max-metric changed active=true";
    let marker = "ospf graceful restart marker written";
    let skipped = "ospf stub router on-startup skipped after graceful restart";
    let (mm0, marker0, skipped0) = (a.count(max_metric_on), a.count(marker), a.count(skipped));
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
            "ospf helper: grace period entered link=eth0.0 neighbor={OSPF_ROUTER_ID} grace_period=120 restart_reason=1"
        ))
        .await?;
        a.wait_new(marker, marker0, 30).await?;
        a.wait_new(skipped, skipped0, 90).await?;
        // The watchdog respawns router-a; the fresh process resynchronizes
        // with the neighbor that held it Full the whole time.
        b.wait_new(&full_on_b, full_b0, 90).await?;
        a.wait_new(&full_on_a, full_a0, 90).await?;
        b.wait(&format!(
            "ospf helper: neighbor reformed, exiting grace early link=eth0.0 neighbor={OSPF_ROUTER_ID}"
        ))
        .await?;
        tokio::time::sleep(Duration::from_secs(5)).await;
        anyhow::Ok(())
    };
    // router-b's RIB must hold the OSPF route at every sample of the restart.
    // (Its next hops may still change — the bridge adjacency, not covered by
    // this phase, can come up meanwhile — which the kernel driver logs as a
    // remove + add, so the kernel log alone can't tell a drop from that.)
    let route_held = async {
        loop {
            if !b.rt1_has(OSPF_GR_LOOPBACK_ADDRESS, "Ospf").await? {
                bail!(
                    "router-b lost its ospf route to {OSPF_GR_LOOPBACK_ADDRESS} during the restart"
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    tokio::select! {
        r = restart => r?,
        r = route_held => r?,
    }
    log("router-b held its ospf route to router-a's loopback through the restart");
    // RFC 3623 §2: the restarter keeps its LSAs; the helper never tears the
    // adjacency down and never flushes them.
    a.assert_quiet(flush_on_a, flush_a0, 0).await?;
    b.assert_quiet(torn, torn0, 0).await?;
    b.assert_quiet(&flushed, flushed0, 0).await?;
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
    b.wait_ospf_route_gone(OSPF_GR_LOOPBACK_ADDRESS, 5).await
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

/// RFC 2328 §10.8 DBD pagination, forced by `--dbd-max-headers=1`. router-a
/// also redistributes a static route (two distinct LSAs before the exchange
/// starts), since a single-LSA summary fits in one chunk even at 1.
pub async fn ospf_dbd_pagination(w: &mut World) -> anyhow::Result<()> {
    w.up(&["--ospfd-arg=--dbd-max-headers=1"]).await?;
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, asbr(ospf(OSPF_ROUTER_ID))))
        .await?;
    router_a_holds_two_lsas(a).await?;
    b.provision_flags(&with_base(B, ospf(OSPF_ROUTER_ID_B)))
        .await?;
    paginated(a, b).await?;
    both_full_p2p(a, b).await
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
    b.assert_quiet("removed route", b.count("removed route"), 3)
        .await?;
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
/// in area 1, router-a's only area; router-b's loopback is in area 0, making
/// router-b the ABR, and router-b redistributes a static route (a Type-5 that
/// must never reach the stub area).
#[allow(clippy::too_many_lines)]
pub async fn ospf_stub(w: &mut World) -> anyhow::Result<()> {
    w.up(&[]).await?;
    let (a, b) = (w.a()?, w.b()?);
    let loopback = OSPF_STUB_LOOPBACK_ADDRESS;
    let loopback_id = loopback.trim_end_matches("/32");
    let range = OSPF_STUB_RANGE;
    let range_id = range.split('/').next().unwrap_or(range);
    let area = |router_id: &str, extra: &[&str]| {
        let mut f = strings(&[
            "--ospf-instance",
            OSPF_INSTANCE,
            "--ospf-router-id",
            router_id,
            "--ospf-area",
            OSPF_AREA_1,
        ]);
        f.extend(strings(extra));
        f
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
    a.provision_flags(&with_base(A, on_eth0(OSPF_ROUTER_ID, "stub")))
        .await?;
    b.provision_flags(&with_base(B, asbr(on_eth0(OSPF_ROUTER_ID_B, "normal"))))
        .await?;
    b.provision(&[
        "--ospf-instance",
        OSPF_INSTANCE,
        "--ospf-router-id",
        OSPF_ROUTER_ID_B,
        "--ospf-area",
        OSPF_AREA,
        "--ospf-profile",
        OSPF_PROFILE,
        "--loopback-address",
        loopback,
        "--ospf-loopback-profile",
        OSPF_PROFILE,
    ])
    .await?;
    a.wait(mismatch).await?;
    b.wait(mismatch).await?;
    b.wait("ospf lsa originated.*lsa_type=5").await?;
    log("confirming the e-bit mismatch never reaches init");
    a.assert_quiet(
        &format!("ospf neighbor state changed to init link=eth0.0 neighbor={OSPF_ROUTER_ID_B}"),
        0,
        8,
    )
    .await?;

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
    a.assert_quiet("ospf lsa installed.*lsa_type=5", 0, 10)
        .await?;

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
    b.assert_quiet(&failed, b.count(&failed), 15).await?;
    b.assert_quiet(&discard, 1, 0).await?;

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
    b.provision(&area(
        OSPF_ROUTER_ID_B,
        &["--ospf-area-type", "totally-stubby"],
    ))
    .await?;
    a.wait_new(&removed, removed_before, 60).await?;
    log("confirming the default route stays in the totally-stubby area");
    a.assert_quiet(default_removed, 0, 10).await?;
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
    let a_type5 = "ospf lsa originated.*lsa_type=5";
    a.assert_quiet(a_type5, a.count(a_type5), 10).await?;
    c.assert_quiet("ospf lsa installed.*lsa_type=5", 0, 0)
        .await?;

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
    a.wait(&added(IP_B)).await?;
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

    // §16.2: router-c still summarizes its loopback into area 1, but
    // router-b, a backbone ABR, doesn't route on area 1's summaries, so
    // both routes go with the virtual link.
    log("both routes are removed, while router-c's area-1 summary stays at router-b");
    let removed = format!("removed route prefix={OSPF_VLINK_LOOPBACK_ADDRESS} ");
    b.wait_new(&removed, 0, 30).await?;
    a.wait_new(&removed, 0, 30).await?;
    wait_lsa(b, "router-c's area-2 summary in area 1", |l| {
        l["area_id"] == OSPF_AREA_1
            && l["lsa_type"] == 3
            && l["advertising_router"] == OSPF_ROUTER_ID_C
            && l["link_state_id"] == loopback_id
            && l["age"].as_u64().is_some_and(|a| a < 3600)
    })
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
            .network_create(NET_OSPF_FRR, &[OSPF_FRR_SUBNET], false)
            .await?;
    }
    w.dock
        .network_connect_ip(NET_OSPF_FRR, "router-a", OSPF_FRR_IP_A)
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
        IP_B,
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
            OSPF_FRR_IP_F,
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
            && frr_route_cost(out, SUBNET).is_some_and(|c| c < 65535)
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
            && frr_route_cost(out, SUBNET).is_some_and(|c| c < 65535)
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
    w.up(&[]).await?;
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
    b.wait(&last).await
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
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), before, 60).await
}

/// RFC 5340 §A.3.1 Instance ID: instance-id 1 on router-a alone gets its
/// packets dropped by router-b (logged at debug) and no new Full forms; 1 on
/// both reaches Full with a non-zero id on the wire both ways. Requires
/// `ospfv3` to have run; leaves both back at 0 for `ospfv3-dr`'s router-c.
pub async fn ospfv3_instance_id(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
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

    log("resetting instance-id to 0 on both routers");
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
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
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await
}

pub async fn ospfv3_phase(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    a.provision_flags(&with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)))
        .await?;

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
    b.wait(&format!(
        "ospfv3 neighbor reached full link=eth0.0 neighbor={OSPFV3_ROUTER_ID}"
    ))
    .await?;
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
    let route_before = b.count(&route_pat);
    let lsa_installed = b.count(&format!(
        "ospfv3 lsa installed.*neighbor={OSPFV3_ROUTER_ID}"
    ));
    a.provision(&[
        "--ospfv3-loopback-address",
        OSPFV3_LOOPBACK_ADDRESS,
        "--ospfv3-loopback-profile",
        OSPFV3_PROFILE,
    ])
    .await?;
    a.wait("ospfv3 lsa originated").await?;
    // (The old script's baseline of 1 here was a fixed guess at the install
    // count; a live baseline is exact.)
    b.wait_new(
        &format!("ospfv3 lsa installed.*neighbor={OSPFV3_ROUTER_ID}"),
        lsa_installed,
        60,
    )
    .await?;
    b.wait_new(
        &format!("added route prefix={OSPFV3_LOOPBACK_ADDRESS}.*source=Some(Ospf)"),
        route_before,
        60,
    )
    .await?;
    // #190: pushed on the LSDB change, not on the next 2s poll.
    b.assert_delay_under(
        &format!("ospfv3 lsa installed.*neighbor={OSPFV3_ROUTER_ID}"),
        &route_pat,
        route_before,
        1000,
    )?;

    // RFC 8362 Full mode on both routers: adjacency survives (mixed or not,
    // E-LSAs are known types), each originates E-LSAs, and the peer decodes
    // and installs them (E-Router 0xA021, E-Link 0x8028, E-Intra-Area-Prefix
    // 0xA029). The SPF side is covered by a unit test: the loopback route is
    // already installed from the legacy LSAs, and the daemon only advertises
    // an interface's first IPv6 address, so no new route can prove it here.
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
    ospfv3_link_state(w).await
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
/// tears nothing down; carrier loss and admin-down are seen within 5s with no
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
            id.peer_ip,
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
    let (nc0, ad0, down1) = (
        a.count(&reason("no-carrier")),
        b.count(&reason("admin-down")),
        (a.count(down), b.count(down)),
    );
    let (a_full, b_full) = (
        a.count(&full(OSPFV3_ROUTER_ID_B)),
        b.count(&full(OSPFV3_ROUTER_ID)),
    );
    set_link(w, "router-b", "eth1", "down").await?;
    a.wait_new(&reason("no-carrier"), nc0, 5).await?;
    b.wait_new(&reason("admin-down"), ad0, 5).await?;
    if a.count(down) > down1.0 || b.count(down) > down1.1 {
        bail!("a dead timer expired: link-down detection did not come from the stream");
    }
    set_link(w, "router-b", "eth1", "up").await?;
    a.wait_new(&full(OSPFV3_ROUTER_ID_B), a_full, 60).await?;
    b.wait_new(&full(OSPFV3_ROUTER_ID), b_full, 60).await?;

    // A deleted device is absent.
    let absent0 = a.count(&reason("absent"));
    w.unlink_veths().await;
    a.wait_new(&reason("absent"), absent0, 5).await
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
    a.wait_new("ospf lsa originated.*lsa_type=5", v2_o0, 60)
        .await?;
    b.wait_new("ospf lsa installed.*lsa_type=5", v2_i0, 60)
        .await?;
    b.wait_new(&v2_route, v2_r0, 60).await?;
    let prefix_lsid = ASBR_PREFIX.split('/').next().unwrap_or_default();
    wait_external_lsa(b, OSPF_ROUTER_ID, prefix_lsid, 20, false).await?;

    let aged = either_form(legacy, extended, |t| {
        format!("ospfv3 lsa prematurely aged lsa_type={t} ")
    });
    let flushed = either_form(legacy, extended, |t| {
        format!("ospfv3 lsa maxage flushed .*lsa_type={t} .*advertising_router={OSPFV3_ROUTER_ID}")
    });
    let removed = format!("removed route prefix={OSPFV3_ASBR_PREFIX}");
    let (aged0, flushed0, removed0) = (a.count(&aged), b.count(&flushed), b.count(&removed));
    let v2_aged = "ospf lsa prematurely aged.*lsa_type=5";
    let v2_removed = format!("removed route prefix={ASBR_PREFIX} ");
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
    ])
    .await?;
    b.wait_new(&aged, aged0, 30).await?;
    a.wait_new(&flushed, flushed0, 30).await?;
    a.wait_new(&removed, removed0, 30).await
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
            a.assert_quiet(&abr_route, 0, 20).await?;
            a.assert_quiet(&asbr_route, 0, 1).await?;
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
            .network_create(NET_OSPFV3_A1, &[OSPFV3_A1_SUBNET, OSPFV3_A1_SUBNET6], true)
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
            .network_connect_ip(NET_OSPFV3_A1, "router-b", OSPFV3_A1_IP_B)
            .await?;
        w.dock
            .network_connect_ip(NET_OSPFV3_A1, "router-c", OSPFV3_A1_IP_C)
            .await?;
        let (a, b, c) = (w.a()?, w.b()?, w.c()?);

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
                id.peer_ip,
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
            OSPFV3_A1_ADDRESS_B,
            OSPFV3_ROUTER_ID_B,
        ))
        .await?;
        // router-c: no OSPFv3 on eth0 (`ospfv3_instance_only` attaches nothing).
        c.provision_flags(&with_base(C, vec![])).await?;
        let mut c_flags = area1(
            C,
            &format!("{OSPFV3_A1_IP_C}/24"),
            OSPFV3_A1_ADDRESS_C,
            OSPFV3_ROUTER_ID_C,
        );
        c_flags.extend(strings(&[
            "--static-route",
            OSPFV3_A1_ASBR_PREFIX,
            "--static-gateway",
            OSPFV3_A1_ADDRESS_B.trim_end_matches("/64"),
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
        let route = format!("added route prefix={OSPFV3_A1_ASBR_PREFIX}.*source=Some(Ospf)");
        if infinity {
            log("LSInfinity Inter-Area-Router-LSA held; the external route must not be installed");
            a.assert_quiet(&route, 0, 20).await?;
        } else {
            a.wait_new(&route, 0, 60).await?;
        }
        w.remove(C).await;
        w.dock.network_disconnect(NET_OSPFV3_A1, "router-b").await;
    }
    w.dock.network_remove(NET_OSPFV3_A1).await;
    Ok(())
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

    let torn = "ospfv3 neighbor adjacency torn down\\|ospfv3 neighbor state changed to down";
    let removed = format!("removed route prefix={OSPFV3_LOOPBACK_ADDRESS}");
    let (torn_before, removed_before, full_b_before, full_a_before) = (
        b.count(torn),
        b.count(&removed),
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
        "ospfv3 helper: grace period entered link=eth0.0 neighbor={OSPFV3_ROUTER_ID} grace_period=120 restart_reason=1"
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
    b.assert_quiet(torn, torn_before, 0).await?;
    b.assert_quiet(&removed, removed_before, 5).await
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
    c.provision(&["--clear-ospfv3-loopback-profile"]).await?;

    log("router-c holds only the bridge's own link-lsas (rfc 5340 §4.5.1)");
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID).await?;
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID_B).await?;
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID).await?;
    assert_only_broadcast_link_lsas(c, OSPFV3_ROUTER_ID_B).await
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
    b.provision(&["--clear-ospfv3-loopback-profile"]).await?;
    a.wait_new(&removed, r0, 60).await
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
        id.peer_ip,
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
            "FROM debian:bookworm-slim\n\
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
    log("killing router-a's nos-interfaced");
    w.dock.kill_process("router-a", "nos-interfaced").await?;
    let mut flags = ring_flags(A, 1, "eth1", &format!("{RLFA_RING_PREFIX}.1.1/24"), true);
    flags.extend(strings(&["--ospf-max-metric-on-startup", "5"]));
    a.provision_flags(&flags).await?;
    a.wait_new(
        "ospf link resolution failed, keeping running link",
        fallback0,
        10,
    )
    .await?;
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
    let (torn_a, torn_b, full_a) = (a.count(&torn), b.count(&torn), a.count(&s.full_a));
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
    b.assert_quiet(&torn, torn_b, 0).await?;
    a.assert_quiet(&s.full_a, full_a, 0).await?;

    log("UDP 3784 dropped on router-a: BFD Down kills the neighbor in under a second");
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    let (n_down, n_kill, n_removed) = (a.count(&down), a.count(&killing), a.count(&removed));
    let full_base = a.count(&s.full_a);
    let n_add = a.count(&add);
    bfd_filter(w, s.v6, true).await?;
    let result = async {
        a.wait_new(&down, n_down, 10).await?;
        a.wait_new(&killing, n_kill, 5).await?;
        a.assert_delay_under(&down, &killing, n_kill, 1000)?;
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
    b.provision(&[&format!("--clear-{}-loopback-profile", s.daemon)])
        .await
}

/// `ospf-bfd` (#288), on the `ospf` lab.
pub async fn ospf_bfd(w: &mut World) -> anyhow::Result<()> {
    bfd_scenario(
        w,
        BfdScenario {
            daemon: "ospf",
            on: "--ospf-bfd",
            off: "--no-ospf-bfd",
            peer: IP_B.to_string(),
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
