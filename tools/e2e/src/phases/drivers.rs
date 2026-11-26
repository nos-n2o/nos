//! Driver phases: what nos-interfaced / nos-ribd / nos-lacpd / nos-lldpd
//! actually program into a real kernel, proven by the log line each driver
//! emits when it does.

use std::time::Duration;

use anyhow::{bail, Context as _};
use nos_proto::{StpRole, StpState};
use reqwest::Method;

use crate::consts::*;
use crate::router::{log, strings, Router, R};
use crate::world::World;

pub async fn loopback(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    // #275: the link watcher streams the kernel's own view; baselines because
    // an earlier phase may already have created lo100.
    let changed = format!("link state changed name={LOOPBACK_DEVICE}");
    let removed = format!("link removed name={LOOPBACK_DEVICE}");
    let (changed_base, removed_base) = (a.count(&changed), a.count(&removed));
    a.provision(&["--loopback-address", LOOPBACK_ADDRESS])
        .await?;
    a.wait(&format!("created loopback device device={LOOPBACK_DEVICE}"))
        .await?;
    a.wait_new(&changed, changed_base, 30).await?;
    a.wait("enslaved interface to vrf interface=loopback-rt1")
        .await?;
    a.wait(&format!(
        "added interface address interface=loopback-rt1 address={LOOPBACK_ADDRESS}"
    ))
    .await?;
    // #117: `--loopback-address` sets no routing-table; the name alone puts
    // it in rt1, connected route included.
    a.wait_connected(LOOPBACK_ADDRESS).await?;

    // #655: a prefix-length change on one IPv6 address must converge
    // (remove old, then add new) instead of failing with EEXIST.
    a.provision(&[
        "--loopback-remove-address",
        LOOPBACK_ADDRESS,
        "--loopback-address",
        LOOPBACK_V6_OLD,
    ])
    .await?;
    a.wait(&format!(
        "added interface address interface=loopback-rt1 address={LOOPBACK_V6_OLD}"
    ))
    .await?;
    let failed = "failed to .* interface address";
    let failed_base = a.count(failed);
    let added_new =
        format!("added interface address interface=loopback-rt1 address={LOOPBACK_V6_NEW}");
    let removed_old =
        format!("removed interface address interface=loopback-rt1 address={LOOPBACK_V6_OLD}");
    let removed_old_base = a.count(&removed_old);
    let added_base = a.count(&added_new);
    a.provision(&[
        "--loopback-remove-address",
        LOOPBACK_V6_OLD,
        "--loopback-address",
        LOOPBACK_V6_NEW,
    ])
    .await?;
    a.wait_new(&removed_old, removed_old_base, 30).await?;
    a.wait_new(&added_new, added_base, 30).await?;
    a.assert_quiet(failed, failed_base, 5).await?;

    log("removing router-a's loopback interface");
    a.provision(&["--delete-loopback"]).await?;
    a.wait(&format!(
        "deleted loopback device interface=loopback-rt1 device={LOOPBACK_DEVICE}"
    ))
    .await?;
    a.wait_new(&removed, removed_base, 30).await?;

    // #639: remove a routing table and re-add it at once. The watchdog must
    // wait for the old `nos-ribd` to exit before starting the new one, or the
    // old teardown deletes the new one's VRF.
    let waiting = "waiting for previous nos-ribd to exit name=rt-drain";
    let spawning = "spawning nos-ribd for new routing table name=rt-drain";
    let (waiting_base, spawning_base) = (a.count(waiting), a.count(spawning));
    let add = |c: &mut nos_proto::Config| {
        c.routing_tables.push(nos_proto::RoutingTable {
            name: "rt-drain".to_string(),
            ..Default::default()
        });
        Ok(())
    };
    a.edit(add).await?;
    a.wait_new(spawning, spawning_base, 30).await?;
    a.edit(|c| {
        c.routing_tables.retain(|t| t.name != "rt-drain");
        Ok(())
    })
    .await?;
    a.edit(add).await?;
    a.wait_new(waiting, waiting_base, 30).await?;
    a.wait_new(spawning, spawning_base + 1, 30).await?;
    a.edit(|c| {
        c.routing_tables.retain(|t| t.name != "rt-drain");
        Ok(())
    })
    .await?;
    Ok(())
}

/// #615: an unanswerable `nos-ribd` ("which VRF?") is unknown, not "no VRF":
/// while router-a's `nos-ribd` is dead eth0 stays enslaved to rt1's VRF across
/// several 10 s re-apply ticks, and the session survives.
pub async fn vrf_unknown(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let removed = "removed interface from master enslavement";
    let released = "startup hold released";
    let (removed_base, released_base) = (a.count(removed), a.count(released));
    log("SIGKILL router-a's nos-ribd: its VRF name is unanswerable until it is back");
    // One kill leaves a restart window shorter than the 10 s re-apply tick
    // (and `nos-restd` is down with it, so no config commit can resync
    // meanwhile). Kill it again as it respawns: the watchdog's crash backoff
    // doubles, so `nos-ribd` is down across at least one tick.
    for _ in 0..30 {
        w.dock.kill_process("router-a", "nos-ribd").await?;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    a.assert_quiet(removed, removed_base, 3).await?;
    a.wait_new(released, released_base, 90).await?;
    a.assert_quiet(removed, removed_base, 12).await?;
    a.established().await
}

/// Sets eth0's MTU, then clears it: unset is 1500, enforced (#117), and
/// REST reports what the link is held at. Leaves eth0 at the docker default
/// for later phases.
pub async fn mtu(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.provision(&["--mtu", &MTU_VALUE.to_string()]).await?;
    a.wait(&format!(
        "applied interface mtu interface=eth0 mtu={MTU_VALUE}"
    ))
    .await?;
    expect_eth0_mtu(a, MTU_VALUE).await?;

    let reset = "applied interface mtu interface=eth0 mtu=1500";
    let base = a.count(reset);
    a.provision(&["--clear-mtu"]).await?;
    a.wait_new(reset, base, 30).await?;
    expect_eth0_mtu(a, 1500).await?;
    vlan_sub_link_mtu(a).await
}

/// #843: a VLAN sub-link follows its parent's MTU (parent raised first, so
/// a sub-link created at 1500 reaches 9000), an override wins, clearing the
/// override restores the parent's value, and lowering the parent brings the
/// sub-link back down.
async fn vlan_sub_link_mtu(a: &Router) -> anyhow::Result<()> {
    let tag = SUBINTERFACE_TAG;
    let sub = |extra: &[&str]| {
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
        ]);
        f.extend(strings(extra));
        f
    };
    let applied = |mtu: u32| {
        format!("applied sub-interface mtu interface=eth0 sub_interface=eth0.{tag} mtu={mtu}")
    };
    // Created at the parent's 1500.
    let created = format!("created vlan sub-interface interface=eth0 sub_interface=eth0.{tag}");
    let base = a.count(&created);
    a.provision_flags(&sub(&[])).await?;
    a.wait_new(&created, base, 30).await?;
    expect_sub_mtu(a, 1500).await?;

    // Parent raised first: the existing sub-link follows.
    let (p9000, base) = (applied(MTU_VALUE), a.count(&applied(MTU_VALUE)));
    a.provision_flags(&sub(&["--mtu", &MTU_VALUE.to_string()]))
        .await?;
    a.wait_new(&p9000, base, 30).await?;
    expect_sub_mtu(a, MTU_VALUE).await?;

    // An override below the parent wins.
    let (p1400, base) = (applied(1400), a.count(&applied(1400)));
    a.provision_flags(&sub(&["--subinterface-mtu", "1400"]))
        .await?;
    a.wait_new(&p1400, base, 30).await?;
    expect_sub_mtu(a, 1400).await?;

    // Clearing it follows the parent again.
    let base = a.count(&p9000);
    a.provision_flags(&sub(&["--clear-subinterface-mtu"]))
        .await?;
    a.wait_new(&p9000, base, 30).await?;
    expect_sub_mtu(a, MTU_VALUE).await?;

    // Lowering the parent: the kernel clamps the sub-link itself, so the
    // driver logs the parent's change only.
    let reset = "applied interface mtu interface=eth0 mtu=1500";
    let base = a.count(reset);
    a.provision_flags(&sub(&["--clear-mtu"])).await?;
    a.wait_new(reset, base, 30).await?;
    expect_sub_mtu(a, 1500).await?;

    a.provision_flags(&sub(&["--delete-subinterface"])).await?;
    a.wait(&format!(
        "deleted vlan sub-interface interface=eth0 sub_interface=eth0.{tag}"
    ))
    .await
}

async fn expect_sub_mtu(a: &Router, want: u32) -> anyhow::Result<()> {
    let body = a
        .rest_expect(Method::GET, "/v1/interfaces/eth0", None, 200)
        .await?;
    let status: serde_json::Value = serde_json::from_str(&body)?;
    let tag = SUBINTERFACE_TAG;
    let got = status["subinterfaces"]
        .as_array()
        .and_then(|v| v.iter().find(|s| s["tag"] == tag))
        .map(|s| s["mtu"].clone());
    if got != Some(want.into()) {
        bail!("router-a: eth0 subinterface {tag} reports mtu {got:?}, want {want}");
    }
    log(format!("router-a: rest reports eth0.{tag} mtu {want}"));
    Ok(())
}

const COUNTER_KEYS: [&str; 4] = ["rx_packets", "tx_packets", "rx_bytes", "tx_bytes"];

/// #1368: `speed_mbps` on the interface status is the kernel's
/// `/sys/class/net/<dev>/speed` read at query time (null when it reads -1/0),
/// and never set for `lo`. What a veth really reports is logged, not assumed.
pub async fn interface_speed(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let (_, raw) = w
        .dock
        .exec("router-a", &["cat", "/sys/class/net/eth0/speed"])
        .await?;
    let want = raw.trim().parse::<u32>().ok().filter(|&v| v > 0);
    log(format!("router-a: kernel eth0 speed reads {raw:?}"));
    let body = a
        .rest_expect(Method::GET, "/v1/interfaces/eth0", None, 200)
        .await?;
    let status: serde_json::Value = serde_json::from_str(&body)?;
    let got = status["speed_mbps"].as_u64();
    if got != want.map(u64::from) {
        bail!("router-a: GET /v1/interfaces/eth0 reports speed_mbps {got:?}, sysfs says {want:?}");
    }
    log(format!("router-a: rest reports eth0 speed_mbps {got:?}"));
    // #1454: the observed link state of the same device.
    let link = &status["link"];
    if link["admin_up"] != true
        || link["oper_up"] != true
        || !link["down_reason"].is_null()
        || !link["last_change_secs"].is_u64()
    {
        bail!("router-a: eth0 link is not up with an age: {link}");
    }
    log(format!("router-a: rest reports eth0 link {link}"));
    // #1455: kernel counters, non-zero after the BGP session, then monotonic.
    let first: Vec<u64> = COUNTER_KEYS
        .iter()
        .map(|k| link["counters"][k].as_u64().unwrap_or(0))
        .collect();
    if first.contains(&0) {
        bail!(
            "router-a: eth0 counters missing or zero: {}",
            link["counters"]
        );
    }
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let body = a
        .rest_expect(Method::GET, "/v1/interfaces/eth0", None, 200)
        .await?;
    let again: serde_json::Value = serde_json::from_str(&body)?;
    for (k, f) in COUNTER_KEYS.iter().zip(&first) {
        let n = again["link"]["counters"][k].as_u64().unwrap_or(0);
        if n < *f {
            bail!("router-a: eth0 {k} went backwards: {f} -> {n}");
        }
    }
    log(format!("router-a: rest reports eth0 counters {first:?}"));
    // `lo` is not a configured interface (404), or if listed has no speed.
    let (code, text) = a.rest(Method::GET, "/v1/interfaces/lo", None).await?;
    if code == 200 {
        let lo: serde_json::Value = serde_json::from_str(&text)?;
        if !lo["speed_mbps"].is_null() {
            bail!("router-a: lo reports speed_mbps {}", lo["speed_mbps"]);
        }
    }
    Ok(())
}

async fn expect_eth0_mtu(a: &Router, want: u32) -> anyhow::Result<()> {
    let body = a
        .rest_expect(Method::GET, "/v1/interfaces/eth0", None, 200)
        .await?;
    let status: serde_json::Value = serde_json::from_str(&body)?;
    if status["mtu"] != want {
        bail!(
            "router-a: GET /v1/interfaces/eth0 reports mtu {}, want {want}",
            status["mtu"]
        );
    }
    log(format!("router-a: rest reports eth0 mtu {want}"));
    Ok(())
}

pub async fn port_aggregate(w: &mut World) -> anyhow::Result<()> {
    w.connect_bond_networks().await?;
    let a = w.a()?;
    let members = [
        "--port-aggregate",
        "bond1",
        "--enslave-interface-into-port-aggregate",
        "eth1",
        "--enslave-interface-into-port-aggregate",
        "eth2",
    ];
    a.provision(&members).await?;
    a.wait("created port aggregate bond port_aggregate=bond1 bond=bond1 mode=Xor")
        .await?;
    a.wait("enslaved interface to bond interface=eth1 bond=bond1")
        .await?;
    a.wait("enslaved interface to bond interface=eth2 bond=bond1")
        .await?;
    // #117: a bond subinterface's address is a connected route too.
    a.provision(
        &[
            &members[..],
            &["--port-aggregate-address", PORT_AGGREGATE_ADDRESS],
        ]
        .concat(),
    )
    .await?;
    a.wait_connected(PORT_AGGREGATE_SUBNET).await?;
    // #1454: the bond device's own observed link state (up or not depends on
    // its slaves' carrier, so only its shape is asserted).
    let body = a
        .rest_expect(Method::GET, "/v1/port-aggregates/bond1", None, 200)
        .await?;
    let bond: serde_json::Value = serde_json::from_str(&body)?;
    let link = &bond["link"];
    if link["admin_up"] != true || !link["last_change_secs"].is_u64() {
        bail!("router-a: bond1 link is not admin up with an age: {link}");
    }
    log(format!("router-a: rest reports bond1 link {link}"));

    let mut delete = members.to_vec();
    delete.push("--delete-port-aggregate");
    a.provision(&delete).await?;
    // Deleting the bond already releases both slaves as a kernel side effect
    // of destroying their master, so there is no separate "unenslaved" line:
    // the bond's own deletion is this phase's teardown assertion.
    a.wait("deleted port aggregate bond port_aggregate=bond1 bond=bond1")
        .await
}

fn lacp_flags(extra: &[&str]) -> Vec<String> {
    let mut f = strings(&[
        "--port-aggregate",
        LACP_AGGREGATE,
        "--port-aggregate-mode",
        "lacp",
    ]);
    f.extend(strings(extra));
    f
}

pub async fn lacp(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    // The kernel bond is named from nos-interfaced's registry id (bond<id>),
    // which depends on which aggregates earlier phases created — so match any
    // bond name, with baselines taken before provisioning.
    let mut enslave_base = Vec::new();
    for r in [a, b] {
        for iface in ["eth1", "eth2"] {
            enslave_base.push(r.count(&format!(
                "enslaved interface to bond interface={iface} bond=bond"
            )));
        }
    }
    let release_base = a.count("removed interface from master enslavement interface=eth2");

    w.link_veths().await?;
    let both = [
        "--enslave-interface-into-port-aggregate",
        "eth1",
        "--enslave-interface-into-port-aggregate",
        "eth2",
    ];
    // A configured Actor System ID per router (`lacp-system-id`), proven on
    // the wire below by each side seeing the other's as its partner.
    let mut on = lacp_flags(&["--lacp-rate", "fast"]);
    on.extend(strings(&both));
    let mut on_a = on.clone();
    on_a.extend(strings(&["--lacp-system-id", LACP_SYSTEM_ID_A]));
    on_a.extend(strings(&[
        "--lacp-system-priority",
        &LACP_SYSTEM_PRIORITY_A.to_string(),
        "--lacp-port-priority",
        &LACP_PORT_PRIORITY_A.to_string(),
    ]));
    let mut on_b = on;
    on_b.extend(strings(&["--lacp-system-id", LACP_SYSTEM_ID_B]));
    on_b.extend(strings(&[
        "--lacp-system-priority",
        &LACP_SYSTEM_PRIORITY_B.to_string(),
        "--lacp-port-priority",
        &LACP_PORT_PRIORITY_B.to_string(),
    ]));
    a.provision(&on_a).await?;
    b.provision(&on_b).await?;

    let reconciled =
        format!("lacp reconciled aggregate members aggregate={LACP_AGGREGATE} members=2");
    a.wait(&reconciled).await?;
    b.wait(&reconciled).await?;

    log("waiting for real lacpdu negotiation to reach Distributing on both routers/both links");
    for r in [a, b] {
        for iface in ["eth1", "eth2"] {
            r.wait(&format!(
                "interface={iface} receive_state=Current mux_state=Distributing"
            ))
            .await?;
        }
    }

    log("actor port numbers are allocated 1..n (not the ifindex), and the partner sees them");
    for r in [a, b] {
        for (iface, want) in [("eth1", 1), ("eth2", 2)] {
            let p = lacp_port(r, iface).await?;
            if p["actor_port_number"] != want {
                bail!("{}: {iface} actor_port_number is not {want}: {p}", r.name());
            }
            if p["partner_port_number"] != want {
                bail!(
                    "{}: {iface} partner_port_number is not {want}: {p}",
                    r.name()
                );
            }
        }
    }

    log("the configured lacp-system-id is the actor id, and the partner sees it");
    let body = a
        .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
        .await?;
    let summary: serde_json::Value = serde_json::from_str(&body)?;
    let agg = summary
        .as_array()
        .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
        .with_context(|| format!("no {LACP_AGGREGATE} in show lacp: {body}"))?;
    let id = |mac: [u8; 6]| serde_json::json!(mac);
    if agg["actor_system_id"] != id([2, 0, 0, 0, 0x0a, 1]) {
        bail!("router-a's actor system id is not the configured one: {body}");
    }
    if !agg["ports"].as_array().is_some_and(|p| {
        p.iter()
            .all(|p| p["partner_system_id"] == id([2, 0, 0, 0, 0x0b, 1]))
    }) {
        bail!("router-a's partners are not router-b's configured system id: {body}");
    }

    log("configured system/port priorities are advertised, and each side sees the other's");
    for (r, sys, port, p_sys, p_port) in [
        (
            a,
            LACP_SYSTEM_PRIORITY_A,
            LACP_PORT_PRIORITY_A,
            LACP_SYSTEM_PRIORITY_B,
            LACP_PORT_PRIORITY_B,
        ),
        (
            b,
            LACP_SYSTEM_PRIORITY_B,
            LACP_PORT_PRIORITY_B,
            LACP_SYSTEM_PRIORITY_A,
            LACP_PORT_PRIORITY_A,
        ),
    ] {
        let body = r
            .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
            .await?;
        let summary: serde_json::Value = serde_json::from_str(&body)?;
        let agg = summary
            .as_array()
            .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
            .with_context(|| format!("no {LACP_AGGREGATE} in show lacp: {body}"))?;
        if agg["actor_system_priority"] != sys
            || !agg["ports"].as_array().is_some_and(|ports| {
                ports.iter().all(|p| {
                    p["actor_port_priority"] == port
                        && p["partner_system_priority"] == p_sys
                        && p["partner_port_priority"] == p_port
                })
            })
        {
            bail!("lacp priorities are not the configured ones (want sys {sys} port {port}, partner {p_sys}/{p_port}): {body}");
        }
    }

    log("waiting for both routers to actually enslave eth1/eth2 into the real kernel bond");
    let mut base = enslave_base.into_iter();
    for r in [a, b] {
        for iface in ["eth1", "eth2"] {
            r.wait_new(
                &format!("enslaved interface to bond interface={iface} bond=bond"),
                base.next().unwrap_or(0),
                60,
            )
            .await?;
        }
    }

    // 802.1AX §6.5 Marker responder: a real Marker PDU injected on router-b's
    // eth1 (source = its own MAC, so only router-a answers) must come back as
    // a byte-correct Marker Response, and router-a logs it.
    log("router-a answers a real injected Marker PDU on eth1");
    w.dock
        .ensure_image(
            PYTHON_HELPER_IMAGE,
            "FROM debian:trixie-slim\n\
            RUN apt-get update && apt-get install -y --no-install-recommends python3-minimal \\\n \
            && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    let marker_base = a.count("lacp marker answered interface=eth1");
    w.dock
        .in_netns(
            PYTHON_HELPER_IMAGE,
            "router-b",
            &["python3", "-c", include_str!("marker.py")],
        )
        .await?;
    a.wait_new(
        "lacp marker answered interface=eth1 requester_port=7 .* transaction_id=1313821529",
        marker_base,
        15,
    )
    .await?;

    // #688: a version-2 LACPDU (longer than 110 bytes, extra TLVs) must reach
    // the Receive machine; a version-3 one is dropped and only counted.
    log("router-a accepts an injected v2 LACPDU and counts a v3 one on eth1");
    let v2_seen = "lacp lacpdu received interface=eth1 .*partner_system=\\[2, 0, 0, 0, 10, 2\\]";
    let v2_base = a.count(v2_seen);
    let unsupported_before = lacp_port(a, "eth1").await?["unsupported_version_pdus"]
        .as_u64()
        .context("unsupported_version_pdus missing from GET /v1/lacp")?;
    w.dock
        .in_netns(
            PYTHON_HELPER_IMAGE,
            "router-b",
            &["python3", "-c", include_str!("lacpdu.py")],
        )
        .await?;
    a.wait_new(v2_seen, v2_base, 15).await?;
    let unsupported_after = lacp_port(a, "eth1").await?["unsupported_version_pdus"]
        .as_u64()
        .context("unsupported_version_pdus missing from GET /v1/lacp")?;
    anyhow::ensure!(
        unsupported_after == unsupported_before + 1,
        "v3 LACPDU should add exactly one: {unsupported_before} -> {unsupported_after}"
    );
    anyhow::ensure!(
        a.count("lacp lacpdu received interface=eth1 .*partner_system=\\[2, 0, 0, 0, 10, 3\\]")
            == 0,
        "the v3 LACPDU must not reach the Receive machine"
    );

    // #658: a LACPDU carrying router-a's own system id (a looped link) is
    // dropped with a warning and never becomes a partner.
    log("router-a ignores an injected LACPDU carrying its own system id");
    // The injector sends from router-b's eth1: it must be settled too, or the
    // send fails ENETDOWN while the bond re-enslavement still cycles the link
    // (#1332, run 4). The script also retries ENETDOWN.
    lacp_settled(a, 0).await?;
    lacp_settled(b, 0).await?;
    let loop_pattern = "lacp loopback detected, ignoring own LACPDUs interface=eth1";
    let loop_base = a.count(loop_pattern);
    let released = "removed interface from master enslavement interface=eth1";
    let released_base = a.count(released);
    w.dock
        .in_netns(
            PYTHON_HELPER_IMAGE,
            "router-b",
            &["python3", "-c", include_str!("lacp_loop.py")],
        )
        .await?;
    a.wait_new(loop_pattern, loop_base, 15).await?;
    // No partner recorded from the injected id: eth1 still shows router-b's
    // configured system id and keeps Distributing (and so its enslavement).
    let eth1 = lacp_port(a, "eth1").await?;
    if eth1["partner_system_id"] != serde_json::json!([2, 0, 0, 0, 0x0b, 1])
        || eth1["mux_state"] != "Distributing"
    {
        let dump = a.lacp_dump(a.log_mark().saturating_sub(20_000)).await;
        bail!("the looped LACPDU disturbed eth1: {eth1}{dump}");
    }
    a.assert_quiet(released, released_base, 5).await?;

    // Withdraw eth2 from router-b's aggregate (its veth stays up): router-a's
    // nos-lacpd must detect the silence via its real Receive Machine timeout
    // and nos-interfaced must release eth2 — proving the enslavement is
    // dynamic. Both sides run `lacp-rate fast`, so the 30s budget is far under
    // the 90s Long timer, which proves the fast rate is really in effect. The
    // Expired baseline is taken here since a port also passes through Expired
    // while first starting up.
    let expired_base = a.count("interface=eth2 receive_state=Expired");
    let churn = "lacp partner churn machine transitioned interface=eth2 churn=Churn";
    let churn_base = a.count(churn);
    let mut withdraw = lacp_flags(&["--lacp-rate", "fast"]);
    withdraw.extend(strings(&[
        "--enslave-interface-into-port-aggregate",
        "eth1",
        "--clear-port-aggregate-member",
        "eth2",
    ]));
    b.provision(&withdraw).await?;
    let detached = "interface=eth2 mux_state=Detached";
    let detached_base = a.count(detached);
    a.wait_new("interface=eth2 receive_state=Expired", expired_base, 30)
        .await?;
    // #687: Expired keeps the partner and the selection (the short timeout
    // gives it 3s before Defaulted), so the Mux must not fall to Detached yet.
    log("Expired does not detach the member (partner kept, still selected)");
    a.assert_quiet(detached, detached_base, 1).await?;
    a.wait_new(
        "removed interface from master enslavement interface=eth2",
        release_base,
        30,
    )
    .await?;

    // 802.1AX churn detection: eth2 stays out of sync past the (shortened)
    // churn-detection time, so it is flagged churned — and, being kept out of
    // the active set, stays out of the bond — while eth1 is untouched.
    log("the silent partner port is flagged as churned in show lacp");
    a.wait_new(churn, churn_base, 30).await?;
    let body = a
        .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
        .await?;
    let summary: serde_json::Value = serde_json::from_str(&body)?;
    let port = |name: &str| {
        summary
            .as_array()
            .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
            .and_then(|s| s["ports"].as_array())
            .and_then(|p| p.iter().find(|p| p["interface"] == name))
            .cloned()
    };
    let (eth1, eth2) = (port("eth1"), port("eth2"));
    if eth2.is_none_or(|p| p["partner_churn"] != true)
        || eth1.is_none_or(|p| p["partner_churn"] != false)
    {
        bail!("expected eth2 partner_churn=true and eth1 partner_churn=false: {body}");
    }

    // Recovery: router-b takes eth2 back, the partner syncs again, so the
    // churn flag clears and nos-interfaced enslaves eth2 into the bond anew.
    log("the partner port comes back: churn clears and eth2 rejoins the bond");
    let cleared = "lacp partner churn machine transitioned interface=eth2 churn=NoChurn";
    let cleared_base = a.count(cleared);
    let rejoin_base = a.count("enslaved interface to bond interface=eth2 bond=bond");
    let mut restore = lacp_flags(&["--lacp-rate", "fast"]);
    restore.extend(strings(&both));
    b.provision(&restore).await?;
    a.wait_new(cleared, cleared_base, 60).await?;
    a.wait_new(
        "enslaved interface to bond interface=eth2 bond=bond",
        rejoin_base,
        60,
    )
    .await?;
    let body = a
        .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
        .await?;
    if body.contains("\"partner_churn\":true") {
        bail!("a partner is still flagged churned after recovery: {body}");
    }

    // A changed system priority restarts router-a's members, which
    // renegotiate: router-b ends up seeing the new value from a Current,
    // Distributing partner again.
    log("changing router-a's system priority restarts its members and they renegotiate");
    let mut changed = lacp_flags(&["--lacp-rate", "fast"]);
    changed.extend(strings(&both));
    changed.extend(strings(&[
        "--lacp-system-priority",
        &LACP_SYSTEM_PRIORITY_A_CHANGED.to_string(),
    ]));
    a.provision(&changed).await?;
    let mut seen = false;
    for _ in 0..30 {
        let body = b
            .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
            .await?;
        let summary: serde_json::Value = serde_json::from_str(&body)?;
        seen = summary
            .as_array()
            .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
            .and_then(|s| s["ports"].as_array())
            .is_some_and(|ports| {
                ports.iter().all(|p| {
                    p["partner_system_priority"] == LACP_SYSTEM_PRIORITY_A_CHANGED
                        && p["mux_state"] == "Distributing"
                })
            });
        if seen {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if !seen {
        bail!("router-b never saw router-a's changed system priority on Distributing ports");
    }

    lacp_system_id_change(a, b, &both).await?;
    lacp_passive(a, b, &both).await?;
    lacp_min_links(w, &both).await?;
    lacp_v2(w, &both).await?;
    lacp_steering(w, &both).await?;
    lacp_recreated_member(w, a).await?;

    let mut off = lacp_flags(&[]);
    off.extend(strings(&both));
    off.push("--delete-port-aggregate".into());
    // router-b's aggregate is deleted inside `lacp_linux_peer`, which then
    // plays a kernel 802.3ad bond on its veth against router-a's v2 config.
    lacp_linux_peer(w, a, b, &off).await?;
    a.provision(&off).await?;
    let deleted = format!("deleted port aggregate bond port_aggregate={LACP_AGGREGATE} bond=");
    a.wait(&deleted).await?;
    b.wait(&deleted).await?;

    w.unlink_veths().await;
    Ok(())
}

/// #1333: a member netdev deleted and recreated under the same name (new
/// ifindex) must be picked up again: the old `AF_PACKET` socket is bound to
/// the dead ifindex and never sees a frame. An in-container veth pair
/// `lpx0`/`lpx1` on router-a, `lpx0` in a throwaway Lacp aggregate, `lpx1`
/// played by `lacp_partner.py`. `nos-lacpd` is told by `nos-interfaced`
/// (`LinkAdded`), the task exits and `reconcile`'s 10 s tick respawns it.
async fn lacp_recreated_member(w: &World, a: &Router) -> anyhow::Result<()> {
    log("a recreated member netdev is reopened by nos-lacpd");
    let netns = async |script: &str| {
        w.dock
            .in_netns(NETNS_HELPER_IMAGE, "router-a", &["sh", "-c", script])
            .await
    };
    let mkpair =
        "ip link add lpx0 type veth peer name lpx1 && ip link set lpx0 up && ip link set lpx1 up";
    let heard = "lacp lacpdu received interface=lpx0";
    let partner = async |secs: &str| {
        w.dock
            .in_netns(
                PYTHON_HELPER_IMAGE,
                "router-a",
                &["python3", "-c", include_str!("lacp_partner.py"), secs],
            )
            .await
    };
    netns(mkpair).await?;
    let flags = strings(&[
        "--port-aggregate",
        "lpxagg",
        "--port-aggregate-mode",
        "lacp",
        "--lacp-rate",
        "fast",
        "--enslave-interface-into-port-aggregate",
        "lpx0",
    ]);
    let base = a.count(heard);
    a.provision(&flags).await?;
    let result = async {
        partner("8").await?;
        a.wait_new(heard, base, 20).await?;

        let (heard_base, exit_base) = (
            a.count(heard),
            a.count("lacp interface recreated, link task exiting interface=lpx0"),
        );
        netns("ip link del lpx0").await?;
        netns(mkpair).await?;
        // The task exits on `nos-interfaced`'s LinkRemoved/LinkAdded within
        // seconds (no 5 s poll, #1431); `reconcile`'s 10 s tick respawns it.
        a.wait_new(
            "lacp interface recreated, link task exiting interface=lpx0",
            exit_base,
            3,
        )
        .await?;
        partner("25").await?;
        a.wait_new(heard, heard_base, 15).await?;
        Ok(())
    }
    .await;
    let mut del = flags;
    del.push("--delete-port-aggregate".into());
    let _ = a.provision(&del).await;
    let _ = netns("ip link del lpx0").await;
    result
}

/// #657: three live `lacp-system-id` changes on router-a against the real
/// Linux peer. Router-b's bond still describes the old id until it hears
/// router-a's first LACPDU, so a stale Partner block can reach router-a; it
/// must never advance a mux (race-dependent whether one arrives at all: the
/// mismatch line is only logged, the unit tests carry the guarantee).
async fn lacp_system_id_change(a: &Router, b: &Router, both: &[&str]) -> anyhow::Result<()> {
    for n in 1..=3u8 {
        let new = format!("02:00:00:00:00:a{n}");
        log(format!("changing router-a's lacp-system-id to {new}"));
        let advanced = "lacp lacpdu received.*mux_state=\\(Collecting\\|Distributing\\).*partner_view_matches=false";
        let base = a.count(advanced);
        let matched_base = ["eth1", "eth2"].map(|i| {
            a.count(&format!(
                "lacp lacpdu received interface={i} .*partner_view_matches=true"
            ))
        });
        let mismatch = "lacp partner view mismatch";
        let mismatch_base = a.count(mismatch);
        let mut flags = lacp_flags(&["--lacp-rate", "fast"]);
        flags.extend(strings(both));
        flags.extend(strings(&["--lacp-system-id", &new]));
        a.provision(&flags).await?;
        let id = serde_json::json!([2, 0, 0, 0, 0, 0xa0 + n]);
        let sees_a = |p: &serde_json::Value| {
            p["partner_system_id"] == id && p["mux_state"] == "Distributing"
        };
        wait_lacp_ports(b, "router-b sees router-a's new system id", sees_a).await?;
        wait_lacp_ports(a, "router-a Distributing", |p| {
            p["mux_state"] == "Distributing"
        })
        .await?;
        for (iface, base) in ["eth1", "eth2"].into_iter().zip(matched_base) {
            a.wait_new(
                &format!("lacp lacpdu received interface={iface} .*partner_view_matches=true"),
                base,
                30,
            )
            .await?;
        }
        a.assert_quiet(advanced, base, 1).await?;
        if a.count(mismatch) > mismatch_base {
            log("a stale partner view was seen and ignored");
        }
    }
    Ok(())
}

/// Polls `GET /v1/lacp` on `r` until every port of the aggregate satisfies
/// `want` (and there is at least one), up to 40s.
async fn wait_lacp_ports(
    r: &Router,
    what: &str,
    want: impl Fn(&serde_json::Value) -> bool,
) -> anyhow::Result<()> {
    let mut body = String::new();
    for _ in 0..40 {
        body = r
            .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
            .await?;
        let summary: serde_json::Value = serde_json::from_str(&body)?;
        if summary
            .as_array()
            .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
            .and_then(|s| s["ports"].as_array())
            .is_some_and(|ports| !ports.is_empty() && ports.iter().all(&want))
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let dump = r.lacp_dump(r.log_mark().saturating_sub(40_000)).await;
    bail!("{}: {what} never held: {body}{dump}", r.name())
}

/// State barrier (#1337): every port Distributing, in sync with its partner
/// and not churned, held for `hold_ms` (re-checked after it, so a dip inside
/// the window is not missed). Replaces counting log lines until they stop.
async fn lacp_settled(r: &Router, hold_ms: u64) -> anyhow::Result<()> {
    let settled = |p: &serde_json::Value| {
        p["mux_state"] == "Distributing"
            && p["synchronized"] == true
            && p["actor_churn"] == false
            && p["partner_churn"] == false
            && p["individual"] == false
    };
    wait_lacp_ports(r, "all ports Distributing, in sync, no churn", settled).await?;
    tokio::time::sleep(std::time::Duration::from_millis(hold_ms)).await;
    wait_lacp_ports(r, "all ports still settled after the hold", settled).await
}

/// One member port of `LACP_AGGREGATE` in `r`'s `GET /v1/lacp`.
async fn lacp_port(r: &Router, name: &str) -> anyhow::Result<serde_json::Value> {
    let body = r
        .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
        .await?;
    let summary: serde_json::Value = serde_json::from_str(&body)?;
    summary
        .as_array()
        .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
        .and_then(|s| s["ports"].as_array())
        .and_then(|p| p.iter().find(|p| p["interface"] == name))
        .cloned()
        .with_context(|| format!("no port {name} in show lacp: {body}"))
}

/// `min-links`: with 2 and one member silent the bond is emptied (the other
/// port keeps negotiating), and refills when it returns; then a scripted
/// partner that clears Actor_State.Aggregation makes eth2 an Individual port,
/// which is never selected. (No kernel bond can play that partner: bonding
/// always sets Aggregation, even on an unknown-duplex slave.)
async fn lacp_min_links(w: &World, both: &[&str]) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let min_links = |n: &str| {
        let mut f = lacp_flags(&["--lacp-rate", "fast", "--min-links", n]);
        f.extend(strings(both));
        f
    };
    let reconciled = format!("lacp reconciled aggregate members aggregate={LACP_AGGREGATE}");
    // The previous step ends as soon as REST shows Distributing, but the push
    // that follows is coalesced (PUSH_COALESCE, 1s): hold a settled state
    // across one full window (+margin) on both routers, then let the log
    // store drain, so a late push is not mistaken for a min-links effect.
    lacp_settled(b, 0).await?;
    lacp_settled(a, 2500).await?;
    a.count_fresh(&reconciled).await;
    let base = a.count_fresh(&reconciled).await;
    log("min-links 2 with both members Distributing changes nothing");
    a.provision(&min_links("2")).await?;
    a.assert_quiet(&reconciled, base, 5).await?;

    log("router-b withdraws eth2: below min-links the bond is emptied, eth1 keeps negotiating");
    let emptied = "lacp min-links not met, bond emptied";
    let emptied_base = a.count(emptied);
    let release_base = a.count("removed interface from master enslavement interface=eth1");
    let enslave_base = a.count("enslaved interface to bond interface=eth1 bond=bond");
    let mut withdraw = lacp_flags(&["--lacp-rate", "fast"]);
    withdraw.extend(strings(&[
        "--enslave-interface-into-port-aggregate",
        "eth1",
        "--clear-port-aggregate-member",
        "eth2",
    ]));
    b.provision(&withdraw).await?;
    a.wait_new(emptied, emptied_base, 30).await?;
    a.wait_new(
        "removed interface from master enslavement interface=eth1",
        release_base,
        30,
    )
    .await?;
    let eth1 = lacp_port(a, "eth1").await?;
    if eth1["mux_state"] != "Distributing" || eth1["selected"] != true {
        bail!("eth1 stopped negotiating when min-links emptied the bond: {eth1}");
    }

    log("a partner that clears Aggregation makes eth2 an Individual port: never selected");
    w.dock
        .ensure_image(
            PYTHON_HELPER_IMAGE,
            "FROM debian:trixie-slim\n\
            RUN apt-get update && apt-get install -y --no-install-recommends python3-minimal \\\n \
            && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    log("the same LACPDUs behind an 802.1Q tag are ignored (#690)");
    w.dock
        .in_netns(
            PYTHON_HELPER_IMAGE,
            "router-b",
            &["python3", "-c", include_str!("individual.py"), "tagged"],
        )
        .await?;
    let eth2 = lacp_port(a, "eth2").await?;
    if eth2["individual"] != false
        || eth2["partner_system_id"] == serde_json::json!([2, 0, 0, 0, 12, 1])
    {
        bail!("a tagged LACPDU reached nos-lacpd on eth2 (#690): {eth2}");
    }
    let inject = w.dock.in_netns(
        PYTHON_HELPER_IMAGE,
        "router-b",
        &["python3", "-c", include_str!("individual.py")],
    );
    let check = async {
        for _ in 0..8 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let eth2 = lacp_port(a, "eth2").await?;
            if eth2["individual"] == true {
                let eth1 = lacp_port(a, "eth1").await?;
                if eth2["receive_state"] != "Current"
                    || eth2["selected"] != false
                    || eth2["mux_state"] == "Distributing"
                    || eth1["selected"] != true
                {
                    bail!("individual eth2 was selected or cost eth1 its selection: {eth2} {eth1}");
                }
                return Ok(());
            }
        }
        bail!("eth2 never showed individual=true")
    };
    let (injected, checked) = tokio::join!(inject, check);
    injected?;
    checked?;

    log("router-b restores eth2: the bond refills");
    let mut restore = lacp_flags(&["--lacp-rate", "fast"]);
    restore.extend(strings(both));
    b.provision(&restore).await?;
    a.wait_new(
        "enslaved interface to bond interface=eth1 bond=bond",
        enslave_base,
        60,
    )
    .await?;
    wait_lacp_ports(a, "both ports Distributing again", |p| {
        p["mux_state"] == "Distributing" && p["individual"] == false
    })
    .await?;

    a.provision(&min_links("1")).await
}

/// `show lacp` of `LACP_AGGREGATE` on `r`.
async fn lacp_aggregate(r: &Router) -> anyhow::Result<serde_json::Value> {
    let body = r
        .rest_expect(reqwest::Method::GET, "/v1/lacp", None, 200)
        .await?;
    let summary: serde_json::Value = serde_json::from_str(&body)?;
    summary
        .as_array()
        .and_then(|v| v.iter().find(|s| s["aggregate"] == LACP_AGGREGATE))
        .cloned()
        .with_context(|| format!("no {LACP_AGGREGATE} in show lacp: {body}"))
}

/// Polls the aggregate summary on `r` until `want` holds (40s).
async fn wait_lacp_aggregate(
    r: &Router,
    what: &str,
    want: impl Fn(&serde_json::Value) -> bool,
) -> anyhow::Result<()> {
    let mut last = serde_json::Value::Null;
    for _ in 0..40 {
        last = lacp_aggregate(r).await?;
        if want(&last) {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    bail!("{}: {what} never held: {last}", r.name())
}

/// #894 (LACP v2, 802.1AX-2020 6.6): `lacp-version 2` is an explicit opt-in
/// (the default is 1, so a v1-only partner never sees a v2 PDU). Two NOS
/// routers agree on a map (flap invariance of the digest is unit-tested: interfaced re-ups a downed veth and a recreated veth leaves the link task on a stale socket); a
/// swapped `lacp-link-number` is reconciled by Link_Number adoption;
/// `unspecified` advertises only the algorithm; a v1 partner makes a v2 router
/// downgrade; and a different map digest is a mismatch. Conversations are
/// steered whenever a map exists, the collection filter needs agreement.
async fn lacp_v2(w: &World, both: &[&str]) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let flags = |version: &str, algorithm: &str, map: Option<&str>| {
        let mut f = lacp_flags(&[
            "--lacp-rate",
            "fast",
            "--lacp-version",
            version,
            "--lacp-port-algorithm",
            algorithm,
            "--lacp-link-number",
            "1",
        ]);
        f.extend(strings(both));
        if let Some(m) = map {
            f.extend(strings(&["--lacp-conversation-map", m]));
        }
        f
    };
    let state = |r: &Router, s: &str| {
        let p = format!("lacp conversation agreement aggregate={LACP_AGGREGATE} state={s}");
        let base = r.count(&p);
        (p, base)
    };
    let agreement_is = |want: &'static str| {
        move |s: &serde_json::Value| {
            s["agreement"] == want
                && s["ports"]
                    .as_array()
                    .is_some_and(|p| p.iter().all(|p| p["mux_state"] == "Distributing"))
        }
    };

    log("lacp-version 2 + c-vlan on both routers: the maps agree and are split 2048/2048");
    let (pa, ba) = state(a, "Agreed");
    let (pb, bb) = state(b, "Agreed");
    a.provision(&flags("2", "c-vlan", None)).await?;
    b.provision(&flags("2", "c-vlan", None)).await?;
    a.wait_new(&pa, ba, 90).await?;
    b.wait_new(&pb, bb, 90).await?;
    for r in [a, b] {
        wait_lacp_aggregate(r, "agreement Agreed", agreement_is("Agreed")).await?;
        let s = lacp_aggregate(r).await?;
        if s["conversations_per_link"] != serde_json::json!([["eth1", 2048], ["eth2", 2048]])
            || s["ports"].as_array().is_none_or(|p| {
                p.iter()
                    .any(|p| p["partner_version"] != 2 || p["partner_port_algorithm"] != "CVlan")
            })
        {
            bail!("{}: unexpected v2 summary: {s}", r.name());
        }
    }
    a.wait(&format!(
        "lacp conversations pushed aggregate={LACP_AGGREGATE} links=2"
    ))
    .await?;

    log("router-b numbers its members the other way round: still Agreed, one end adopts the other's Link_Numbers");
    let adopted = "lacp link number adopted";
    let (adopted_a, adopted_b) = (a.count(adopted), b.count(adopted));
    let mut swapped = flags("2", "c-vlan", None);
    swapped.push("--lacp-link-number-descending".into());
    b.provision(&swapped).await?;
    let mut seen = false;
    for _ in 0..90 {
        if a.count(adopted) > adopted_a || b.count(adopted) > adopted_b {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !seen {
        bail!("neither router adopted its partner's Link_Numbers after the swap");
    }
    for r in [a, b] {
        wait_lacp_aggregate(r, "Agreed with split conversations after the swap", |s| {
            agreement_is("Agreed")(s)
                && s["conversations_per_link"]
                    == serde_json::json!([["eth1", 2048], ["eth2", 2048]])
        })
        .await?;
    }

    log(
        "unspecified algorithm: v2 stays on the wire, agreement is not requested, no conversations",
    );
    let (pa, ba) = state(a, "NotRequested");
    let empty = format!("lacp conversations pushed aggregate={LACP_AGGREGATE} links=0");
    let push_base = a.count(&empty);
    a.provision(&flags("2", "unspecified", None)).await?;
    b.provision(&flags("2", "unspecified", None)).await?;
    a.wait_new(&pa, ba, 90).await?;
    a.wait_new(&empty, push_base, 30).await?;
    wait_lacp_aggregate(a, "v2 partner, no agreement", |s| {
        s["agreement"] == "NotApplicable"
            && s["ports"].as_array().is_some_and(|p| {
                p.iter().all(|p| {
                    p["partner_version"] == 2 && p["partner_port_algorithm"] == "Unspecified"
                })
            })
    })
    .await?;

    log("router-b stays on version 1: router-a downgrades to v1 and the ports still bundle");
    let down = "lacp sent version changed interface=eth1 version=1";
    let down_base = a.count(down);
    let (pa, ba) = state(a, "PartnerV1");
    let steer =
        format!("lacp conversations pushed aggregate={LACP_AGGREGATE} links=2 discard_wrong=false");
    let steer_base = a.count(&steer);
    a.provision(&flags("2", "c-vlan", None)).await?;
    b.provision(&flags("1", "unspecified", None)).await?;
    a.wait_new(down, down_base, 90).await?;
    a.wait_new(&pa, ba, 90).await?;
    wait_lacp_aggregate(a, "V1Partner and Distributing", agreement_is("V1Partner")).await?;
    // Steering needs no agreement; the collection filter stays off.
    a.wait_new(&steer, steer_base, 30).await?;
    let s = lacp_aggregate(a).await?;
    if s["conversations_per_link"] != serde_json::json!([["eth1", 2048], ["eth2", 2048]]) {
        bail!("no steering towards a v1 partner: {s}");
    }

    log("router-b back on v2 with a different explicit map: digest mismatch, plain hashing");
    let up = "lacp sent version changed interface=eth1 version=2";
    let up_base = a.count(up);
    let (pa, ba) = state(a, "Mismatch reason=digest");
    b.provision(&flags("2", "c-vlan", Some("0-99:eth1,100-4095:eth2")))
        .await?;
    a.wait_new(up, up_base, 90).await?;
    a.wait_new(&pa, ba, 90).await?;
    wait_lacp_aggregate(a, "Mismatch and Distributing", agreement_is("Mismatch")).await?;
    let s = lacp_aggregate(a).await?;
    if s["conversations_per_link"] != serde_json::json!([["eth1", 2048], ["eth2", 2048]]) {
        bail!("a digest mismatch must still steer (filter off): {s}");
    }
    Ok(())
}

/// One member's steering row of `GET /v1/port-aggregates` (#895).
#[derive(Debug, Clone, PartialEq)]
struct SteerRow {
    member: String,
    conversations: u64,
    redirected: u64,
    dropped: u64,
}

async fn steering_rows(r: &Router) -> anyhow::Result<Vec<SteerRow>> {
    let body = r
        .rest_expect(Method::GET, "/v1/port-aggregates", None, 200)
        .await?;
    let all: serde_json::Value = serde_json::from_str(&body)?;
    let agg = all
        .as_array()
        .and_then(|v| v.iter().find(|a| a["name"] == LACP_AGGREGATE))
        .with_context(|| format!("no {LACP_AGGREGATE} in port aggregates: {body}"))?;
    let n = |row: &serde_json::Value, k: &str| row[k].as_u64().unwrap_or(0);
    Ok(agg["steering"]
        .as_array()
        .context("no steering field")?
        .iter()
        .map(|row| SteerRow {
            member: row["member"].as_str().unwrap_or_default().to_string(),
            conversations: n(row, "conversations"),
            redirected: n(row, "redirected_packets"),
            dropped: n(row, "dropped_packets"),
        })
        .collect())
}

fn row<'a>(rows: &'a [SteerRow], member: &str) -> anyhow::Result<&'a SteerRow> {
    rows.iter()
        .find(|r| r.member == member)
        .with_context(|| format!("no steering row for {member}: {rows:?}"))
}

async fn lacp_vlan(w: &World, router: &str, args: &[&str]) -> anyhow::Result<()> {
    let mut cmd = vec!["python3", "-c", include_str!("lacp_vlan.py")];
    cmd.extend(args);
    w.dock.in_netns(PYTHON_HELPER_IMAGE, router, &cmd).await?;
    Ok(())
}

/// #895: conversation steering on the real kernel. Both routers run `c-vlan`
/// with the same explicit map (VLAN 10 on eth1, VLAN 20 on eth2) and routed
/// VLAN sub-interfaces on the aggregate: tc redirects on the bond egress pin
/// each VLAN to its link, ingress drops on the members implement the
/// collection filter, and the per-link counters on `show port-aggregate`
/// (REST `steering`) prove both. Untagged traffic (conversation 0) cannot be
/// matched by flower and stays on the bond hash, so the LACPDUs themselves
/// (untagged) are the proof it is unaffected: both ports stay Distributing.
async fn lacp_steering(w: &World, both: &[&str]) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let flags = |me: u8, algorithm: &str, mapped: bool| {
        let mut f = lacp_flags(&[
            "--lacp-rate",
            "fast",
            "--lacp-version",
            "2",
            "--lacp-port-algorithm",
            algorithm,
            "--lacp-link-number",
            "1",
            "--lacp-conversation-map",
            // a map needs an algorithm: unspecified clears it (empty value)
            if algorithm == "unspecified" || !mapped {
                ""
            } else {
                "0-15:eth1,16-4095:eth2"
            },
        ]);
        f.extend(strings(both));
        for vlan in [10, 20] {
            f.extend(strings(&[
                "--port-aggregate-vlan-address",
                &format!("{vlan}=10.{vlan}.0.{me}/24"),
            ]));
        }
        f
    };
    let installed = |links: u8| {
        format!(
            "lacp conversation steering installed aggregate={LACP_AGGREGATE} conversations=4094 links={links}"
        )
    };
    let distributing = |s: &serde_json::Value| {
        s["ports"]
            .as_array()
            .is_some_and(|p| p.iter().all(|p| p["mux_state"] == "Distributing"))
    };

    log("c-vlan + identical explicit maps: both routers install the steering with the collection filter");
    let full = format!("{} discard_wrong=true", installed(2));
    let bases = [a.count(&full), b.count(&full)];
    a.provision(&flags(1, "c-vlan", true)).await?;
    b.provision(&flags(2, "c-vlan", true)).await?;
    a.wait_new(&full, bases[0], 90).await?;
    b.wait_new(&full, bases[1], 90).await?;
    for r in [a, b] {
        let rows = steering_rows(r).await?;
        if rows.iter().map(|x| x.conversations).sum::<u64>() != 4094 || rows.len() != 2 {
            bail!(
                "{}: expected 4094 conversations over 2 links: {rows:?}",
                r.name()
            );
        }
    }

    log("VLAN 10 traffic leaves on eth1 only, VLAN 20 on eth2 only, and nothing is dropped");
    // ARP/ND of the other VLAN's interface is background noise, hence the slack.
    let (before_a, before_b) = (steering_rows(a).await?, steering_rows(b).await?);
    lacp_vlan(w, "router-a", &["udp", "10", "200", "1"]).await?;
    let mid = steering_rows(a).await?;
    let d10 = |m: &str| -> anyhow::Result<u64> {
        Ok(row(&mid, m)?.redirected - row(&before_a, m)?.redirected)
    };
    if d10("eth1")? < 150 || d10("eth2")? > 30 {
        bail!(
            "VLAN 10 was not pinned to eth1: eth1 +{} eth2 +{}",
            d10("eth1")?,
            d10("eth2")?
        );
    }
    lacp_vlan(w, "router-a", &["udp", "20", "200", "1"]).await?;
    let after = steering_rows(a).await?;
    let d20 = |m: &str| -> anyhow::Result<u64> {
        Ok(row(&after, m)?.redirected - row(&mid, m)?.redirected)
    };
    if d20("eth2")? < 150 || d20("eth1")? > 30 {
        bail!(
            "VLAN 20 was not pinned to eth2: eth1 +{} eth2 +{}",
            d20("eth1")?,
            d20("eth2")?
        );
    }
    let after_b = steering_rows(b).await?;
    for (rows, base, who) in [
        (&after, &before_a, "router-a"),
        (&after_b, &before_b, "router-b"),
    ] {
        for m in ["eth1", "eth2"] {
            if row(rows, m)?.dropped != row(base, m)?.dropped {
                bail!("{who}: {m} dropped steered traffic: {rows:?}");
            }
        }
    }

    log("a frame for VLAN 10 arriving on eth2 (mapped to eth1) is dropped by router-b's collection filter");
    let dropped = row(&after_b, "eth2")?.dropped;
    lacp_vlan(w, "router-a", &["raw", "10", "20"]).await?;
    let now = steering_rows(b).await?;
    if row(&now, "eth2")?.dropped < dropped + 20
        || row(&now, "eth1")?.dropped != row(&after_b, "eth1")?.dropped
    {
        bail!("the wrong-link VLAN 10 frames were not dropped on eth2 only: {now:?}");
    }

    log("LACPDUs (untagged) keep flowing with the filters installed");
    for r in [a, b] {
        wait_lacp_aggregate(r, "Agreed and Distributing", |s| {
            s["agreement"] == "Agreed" && distributing(s)
        })
        .await?;
    }

    log("router-b withdraws eth1: router-a steers everything over eth2, and again over both after the return");
    let one = installed(1);
    let one_base = a.count(&one);
    let mut withdraw = lacp_flags(&["--lacp-rate", "fast"]);
    withdraw.extend(strings(&[
        "--enslave-interface-into-port-aggregate",
        "eth2",
        "--clear-port-aggregate-member",
        "eth1",
        // the map may not name a non-member
        "--lacp-conversation-map",
        "0-4095:eth2",
    ]));
    b.provision(&withdraw).await?;
    a.wait_new(&one, one_base, 60).await?;
    let (e1, e2) = {
        let rows = steering_rows(a).await?;
        (
            row(&rows, "eth1").map_or(0, |r| r.redirected),
            row(&rows, "eth2")?.redirected,
        )
    };
    lacp_vlan(w, "router-a", &["udp", "10", "100", "1"]).await?;
    let rows = steering_rows(a).await?;
    if row(&rows, "eth2")?.redirected < e2 + 80
        || row(&rows, "eth1").map_or(0, |r| r.redirected) != e1
    {
        bail!("VLAN 10 did not move to eth2 when eth1 left: {rows:?}");
    }
    let back_base = a.count(&full);
    b.provision(&flags(2, "c-vlan", true)).await?;
    a.wait_new(&full, back_base, 90).await?;
    wait_lacp_aggregate(a, "Agreed and Distributing again", |s| {
        s["agreement"] == "Agreed" && distributing(s)
    })
    .await?;

    log("lacp-port-algorithm unspecified removes the steering on both routers");
    let removed = format!("lacp conversation steering removed aggregate={LACP_AGGREGATE}");
    let bases = [a.count(&removed), b.count(&removed)];
    a.provision(&flags(1, "unspecified", true)).await?;
    b.provision(&flags(2, "unspecified", true)).await?;
    a.wait_new(&removed, bases[0], 60).await?;
    b.wait_new(&removed, bases[1], 60).await?;
    for r in [a, b] {
        let rows = steering_rows(r).await?;
        if !rows.is_empty() {
            bail!("{}: steering rows left after removal: {rows:?}", r.name());
        }
    }
    // Leave router-a as `lacp_v2` did (c-vlan, no map) for the next step.
    a.provision(&flags(1, "c-vlan", false)).await?;
    wait_lacp_aggregate(a, "Distributing again", distributing).await?;
    Ok(())
}

/// #894 / #865: a real kernel 802.3ad bond (v1 only) as the peer of a
/// `lacp-version 2` router-a on eth1: router-a downgrades to v1, the port
/// bundles and is steered every conversation (the collection filter is off). router-b's NOS aggregate is deleted
/// first; the helper image creates `bond0` in its namespace.
async fn lacp_linux_peer(w: &World, a: &Router, b: &Router, off: &[String]) -> anyhow::Result<()> {
    log("a kernel 802.3ad bond as router-a's peer on eth1: v1 only, tolerated");
    let down = "lacp sent version changed interface=eth1 version=1";
    let down_base = a.count(down);
    // Delete router-b's eth1/eth2 `Interface`s too: `nos-interfaced` re-applies
    // every configured interface's master each 10 s and would release the
    // kernel bond's slave (#1332).
    let released = "removed interface from master enslavement interface=eth1";
    let released_base = b.count(released);
    let mut b_flags = off.to_vec();
    b_flags.extend(strings(&[
        "--delete-interface",
        "eth1",
        "--delete-interface",
        "eth2",
    ]));
    b.provision(&b_flags).await?;
    b.wait(&format!(
        "deleted port aggregate bond port_aggregate={LACP_AGGREGATE} bond="
    ))
    .await?;
    // The resync that drops the interfaces may still release eth1; let it
    // finish before the script enslaves it (the line is absent if the
    // aggregate delete already released it, so a miss is fine).
    let _ = b.wait_new(released, released_base, 5).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // A bond slave must be down when enslaved; nothing brings eth1 up again.
    let script = "ip link add bond0 type bond mode 802.3ad lacp_rate fast && \
        ip link set eth1 down && ip link set eth1 master bond0 && \
        ip link set bond0 up && ip link set eth1 up";
    w.dock
        .in_netns(NETNS_HELPER_IMAGE, "router-b", &["sh", "-c", script])
        .await?;
    let result = async {
        wait_lacp_ports_named(a, "eth1", "Distributing against the kernel bond", |p| {
            p["mux_state"] == "Distributing" && p["partner_version"] == 1
        })
        .await?;
        a.wait_new(down, down_base, 60).await?;
        let s = lacp_aggregate(a).await?;
        if s["agreement"] != "V1Partner"
            || s["conversations_per_link"] != serde_json::json!([["eth1", 4096]])
        {
            bail!("a kernel v1 bond: eth1 carries every conversation, filter off: {s}");
        }
        Ok(())
    }
    .await;
    let _ = w
        .dock
        .in_netns(
            NETNS_HELPER_IMAGE,
            "router-b",
            &["ip", "link", "del", "bond0"],
        )
        .await;
    result
}

/// Like `wait_lacp_ports` for the one port `name`.
async fn wait_lacp_ports_named(
    r: &Router,
    name: &str,
    what: &str,
    want: impl Fn(&serde_json::Value) -> bool,
) -> anyhow::Result<()> {
    let mut last = serde_json::Value::Null;
    for _ in 0..60 {
        last = lacp_port(r, name).await?;
        if want(&last) {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    bail!("{}: {what} never held: {last}", r.name())
}

/// `lacp-mode` (802.1AX LACP_Activity, NO_PERIODIC): passive against active
/// still converges, passive against passive never forms a bundle and stays
/// silent, and back to active converges again.
async fn lacp_passive(a: &Router, b: &Router, both: &[&str]) -> anyhow::Result<()> {
    let flags = |mode: &str| {
        let mut f = lacp_flags(&["--lacp-rate", "fast", "--lacp-mode", mode]);
        f.extend(strings(both));
        f
    };
    let distributing = |p: &serde_json::Value| p["mux_state"] == "Distributing";

    log("router-a passive, router-b active: the passive port still answers and both converge");
    a.provision(&flags("passive")).await?;
    wait_lacp_ports(a, "passive port Distributing", |p| {
        distributing(p) && p["mode"] == "Passive"
    })
    .await?;
    wait_lacp_ports(b, "active port Distributing", distributing).await?;

    log("both passive: nobody speaks, no port is Distributing and the bond is emptied");
    let none = "lacp periodic transmission machine transitioned interface=eth1 no_periodic=true";
    let (none_a, none_b) = (a.count(none), b.count(none));
    let release = a.count("removed interface from master enslavement interface=eth1");
    b.provision(&flags("passive")).await?;
    a.wait_new(none, none_a, 30).await?;
    b.wait_new(none, none_b, 30).await?;
    a.wait_new(
        "removed interface from master enslavement interface=eth1",
        release,
        30,
    )
    .await?;
    for r in [a, b] {
        wait_lacp_ports(r, "no port Distributing", |p| !distributing(p)).await?;
    }
    // Let the last in-flight LACPDUs drain, then nothing may arrive.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let rx = "lacp lacpdu received";
    let (rx_a, rx_b) = (a.count(rx), b.count(rx));
    a.assert_quiet(rx, rx_a, 10).await?;
    b.assert_quiet(rx, rx_b, 0).await?;

    log("router-a back to active: the pair converges again");
    // The bond refills after the push (coalesced, and under CPU starvation
    // `nos-interfaced` lags): enslaving cycles the link, which costs a fast
    // LACPDU window. Wait for both enslavements so the next step starts after
    // that flap, not during it (#1337, run8: eth1 enslaved at +2ms of the
    // min-links window, Expired 2s later).
    let enslaved = |i: &str| format!("enslaved interface to bond interface={i} bond=bond");
    let enslave_bases: Vec<_> = [a, b]
        .into_iter()
        .flat_map(|r| ["eth1", "eth2"].map(|i| (r, i, r.count(&enslaved(i)))))
        .collect();
    a.provision(&flags("active")).await?;
    for r in [a, b] {
        wait_lacp_ports(r, "Distributing again", distributing).await?;
    }
    // b is still passive; put it back so later phases see the default.
    b.provision(&flags("active")).await?;
    for r in [a, b] {
        wait_lacp_ports(r, "Distributing, both active", |p| {
            distributing(p) && p["mode"] == "Active"
        })
        .await?;
    }
    for (r, i, base) in enslave_bases {
        r.wait_new(&enslaved(i), base, 30).await?;
    }
    for r in [a, b] {
        lacp_settled(r, 1500).await?;
    }
    Ok(())
}

/// Polls `GET /v1/bfd/sessions` on `r` until the aggregate's micro-BFD
/// sessions are exactly `want` (member, state) pairs.
async fn micro_sessions_are(r: &Router, want: &[(&str, &str)], secs: u64) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..secs * 5 {
        last = r
            .rest_expect(Method::GET, "/v1/bfd/sessions", None, 200)
            .await?;
        let v: serde_json::Value = serde_json::from_str(&last)?;
        let mut got: Vec<(String, String)> = v
            .as_array()
            .into_iter()
            .flatten()
            .filter(|s| s["key"]["aggregate"] == MICRO_AGGREGATE)
            .map(|s| {
                (
                    s["key"]["interface"].as_str().unwrap_or("").to_string(),
                    s["state"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        got.sort();
        if got
            .iter()
            .map(|(m, s)| (m.as_str(), s.as_str()))
            .eq(want.iter().copied())
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    bail!(
        "{}: micro-bfd sessions never became {want:?}: {last}",
        r.name()
    )
}

/// `micro-bfd` (RFC 7130): a static (`xor`) aggregate over the `lacp` phase's
/// veth pairs with `bfd fast` (100 ms x 3) on both routers. A member is
/// enslaved only while its micro-BFD session is Up; the sessions run on the
/// member itself, so they must keep receiving once it is enslaved (the packet
/// socket is bound to the member, the bond's rx_handler re-targets the skb).
/// Dropping UDP 6784 on router-a's eth2 takes that member out of the bond
/// within the detection time, eth1 untouched; lifting it puts it back.
/// #1064: on a micro-BFD "stay Up" failure, each router's recent bfd/enslave/
/// link lines and the member rx counters (`/proc/net/dev`), to tell "no frames
/// reached the enslaved member" from "frames arrived late" (CPU starvation).
async fn dump_micro_bfd_state(w: &World) {
    for r in [w.a(), w.b()].into_iter().flatten() {
        let dev = w
            .dock
            .exec(r.name(), &["cat", "/proc/net/dev"])
            .await
            .map_or_else(|e| e.to_string(), |(_, out)| out);
        log(format!("{}: member rx counters:", r.name()));
        for l in dev.lines().filter(|l| l.contains("eth")) {
            log(format!("  {l}"));
        }
        log(format!("{}: last bfd/enslave/link lines:", r.name()));
        for l in r.logs.tail("bfd\\|enslav\\|link state", 60) {
            log(format!("  {l}"));
        }
    }
}

pub async fn micro_bfd(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let enslaved = |iface: &str| format!("enslaved interface to bond interface={iface} bond=bond");
    let released =
        |iface: &str| format!("removed interface from master enslavement interface={iface}");
    let mut enslave_base = Vec::new();
    for r in [a, b] {
        for iface in ["eth1", "eth2"] {
            enslave_base.push(r.count(&enslaved(iface)));
        }
    }
    w.link_veths().await?;
    let flags = |addr: &str, peer: &str| {
        strings(&[
            "--port-aggregate",
            MICRO_AGGREGATE,
            "--port-aggregate-address",
            addr,
            "--port-aggregate-bfd",
            "fast",
            "--port-aggregate-bfd-peer",
            peer,
            "--enslave-interface-into-port-aggregate",
            "eth1",
            "--enslave-interface-into-port-aggregate",
            "eth2",
        ])
    };
    let (ip_a, ip_b) = (
        MICRO_ADDRESS_A.split('/').next().unwrap_or_default(),
        MICRO_ADDRESS_B.split('/').next().unwrap_or_default(),
    );
    a.provision(&flags(MICRO_ADDRESS_A, ip_b)).await?;
    b.provision(&flags(MICRO_ADDRESS_B, ip_a)).await?;

    log("micro-bfd sessions reach Up on every member, then the members are enslaved");
    for (r, peer) in [(a, ip_b), (b, ip_a)] {
        for iface in ["eth1", "eth2"] {
            r.wait(&format!(
                "bfd session up aggregate={MICRO_AGGREGATE} member={iface} peer={peer}"
            ))
            .await?;
        }
    }
    let mut base = enslave_base.into_iter();
    for r in [a, b] {
        for iface in ["eth1", "eth2"] {
            r.wait_new(&enslaved(iface), base.next().unwrap_or(0), 60)
                .await?;
        }
    }

    // The risk of the whole design: with both members enslaved the sessions
    // must stay Up, i.e. frames still reach the member-bound packet sockets.
    log("enslaved members keep receiving: the sessions stay Up");
    let down = format!("bfd session down aggregate={MICRO_AGGREGATE}");
    let stayed_up = async {
        // #839: the last enslave can still cost one detection-time expiry (a
        // `down` +87ms into the window); let both sides settle Up first, then
        // baseline, so the quiet window judges only the steady state.
        // #1064: an `Up` read right after the enslave bounce can still be the
        // stale state: the peer's bounce silences us for one detection time
        // (3 x 100 ms) and the expiry lands later, under CPU starvation even
        // inside the window. So wait until no `down` was logged on either side
        // for 2 s (> 6 detection times) before the Up check and the baseline.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        loop {
            let (ca, cb) = (a.count_fresh(&down).await, b.count_fresh(&down).await);
            tokio::time::sleep(Duration::from_secs(2)).await;
            if (a.count_fresh(&down).await, b.count_fresh(&down).await) == (ca, cb) {
                break;
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "micro-bfd sessions keep flapping after the enslave"
            );
        }
        micro_sessions_are(a, &[("eth1", "Up"), ("eth2", "Up")], 30).await?;
        micro_sessions_are(b, &[("eth1", "Up"), ("eth2", "Up")], 30).await?;
        let down_base = a.count_fresh(&down).await;
        a.assert_quiet(&down, down_base, 5).await?;
        micro_sessions_are(a, &[("eth1", "Up"), ("eth2", "Up")], 10).await?;
        micro_sessions_are(b, &[("eth1", "Up"), ("eth2", "Up")], 10).await
    };
    if let Err(e) = stayed_up.await {
        dump_micro_bfd_state(w).await;
        return Err(e);
    }

    log("dropping UDP 6784 on router-a's eth2: it leaves the bond, eth1 stays");
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    let up_eth2 = format!("bfd session up aggregate={MICRO_AGGREGATE} member=eth2");
    let down_eth2 = format!("{down} member=eth2");
    let (down2, rel2, rel1, up2, ens2) = (
        a.count(&down_eth2),
        a.count(&released("eth2")),
        a.count(&released("eth1")),
        a.count(&up_eth2),
        a.count(&enslaved("eth2")),
    );
    super::bfd::tc(&w.dock, &["qdisc", "add", "dev", "eth2", "clsact"]).await?;
    let dropped = super::bfd::tc(
        &w.dock,
        &[
            "filter", "add", "dev", "eth2", "ingress", "protocol", "ip", "u32", "match", "ip",
            "protocol", "17", "0xff", "match", "ip", "dport", "6784", "0xffff", "action", "drop",
        ],
    )
    .await;
    let result = async {
        dropped?;
        a.wait_new(&down_eth2, down2, 10).await?;
        a.wait_new(&released("eth2"), rel2, 10).await?;
        micro_sessions_are(a, &[("eth1", "Up"), ("eth2", "Down")], 10).await?;
        a.assert_quiet(&released("eth1"), rel1, 2).await
    }
    .await;
    // Lift it whatever happened, so a failure does not leave the lab broken.
    let lifted = super::bfd::tc(&w.dock, &["qdisc", "del", "dev", "eth2", "clsact"]).await;
    result?;
    lifted?;

    log("filter lifted: eth2 is Up again and rejoins the bond");
    a.wait_new(&up_eth2, up2, 30).await?;
    a.wait_new(&enslaved("eth2"), ens2, 30).await?;
    micro_sessions_are(a, &[("eth1", "Up"), ("eth2", "Up")], 10).await?;

    // #693: a deleted and recreated member leaves the receive sockets on a
    // stale ifindex; the loops must rebuild them instead of exiting for good.
    log("eth2 deleted and recreated: the receive sockets are rebuilt, the session returns");
    let (recreated, up2, ens2) = (
        a.count("bfd micro receive socket recreated member=eth2"),
        a.count(&up_eth2),
        a.count(&enslaved("eth2")),
    );
    w.dock
        .ip(
            NETNS_HELPER_IMAGE,
            Some("router-a"),
            false,
            &["link", "del", "eth2"],
        )
        .await?;
    w.link_veths().await?;
    a.wait_new(
        "bfd micro receive socket recreated member=eth2",
        recreated,
        30,
    )
    .await?;
    a.wait_new(&up_eth2, up2, 30).await?;
    a.wait_new(&enslaved("eth2"), ens2, 30).await?;
    micro_sessions_are(a, &[("eth1", "Up"), ("eth2", "Up")], 10).await?;

    log("removing the aggregate stops the sessions");
    for r in [a, b] {
        r.provision(&[
            "--port-aggregate",
            MICRO_AGGREGATE,
            "--enslave-interface-into-port-aggregate",
            "eth1",
            "--enslave-interface-into-port-aggregate",
            "eth2",
            "--delete-port-aggregate",
        ])
        .await?;
        micro_sessions_are(r, &[], 10).await?;
    }
    w.unlink_veths().await;
    Ok(())
}

pub async fn lldp(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let learned_a = |extra: &str| {
        format!("lldp neighbor learned interface=eth1 .* system_name=router-b system_description=.*{extra}")
    };
    let learned_b = |extra: &str| {
        format!("lldp neighbor learned interface=eth1 .* system_name=router-a system_description=.*{extra}")
    };
    let shutdown = "lldp neighbor removed interface=eth1 .* reason=\"shutdown\"";
    // Each router advertises its container name as its System Name.
    let host = |name: &'static str, extra: &[&str]| {
        let mut f = vec!["--hostname", name];
        f.extend_from_slice(extra);
        f.into_iter().map(String::from).collect::<Vec<_>>()
    };
    let (base_a, base_b) = (a.count(&learned_a("")), b.count(&learned_b("")));
    let started_a = a.count("lldp link started interface=eth1 transmit=true receive=false");
    // The last frame of an 802.1AB fast-start burst (txFastInit = 4 at 1s).
    let burst_done = "lldp fast-start tx interface=eth1 remaining=0";
    let (burst_a, burst_b) = (a.count(burst_done), b.count(burst_done));

    w.link_veths().await?;
    let on = [
        "--lldp-transmit-interface",
        "eth1",
        "--lldp-receive-interface",
        "eth1",
    ];
    a.provision(&host("router-a", &on)).await?;
    b.provision(&host("router-b", &on)).await?;

    log("waiting for both routers' nos-lldpd to learn the other over the real veth");
    // ttl=120 is the 802.1AB default (tx-interval 30 x tx-hold 4), and the
    // System Description defaults to a bare "nos" (no version).
    let dflt = |p: String| {
        p.replace(".* system_name", ".* port_id=eth1 system_name")
            .replace("system_description=.* ttl", "system_description=nos ttl")
    };
    a.wait_new(&dflt(learned_a(" ttl=120")), base_a, 60).await?;
    b.wait_new(&dflt(learned_b(" ttl=120")), base_b, 60).await?;
    // Link start and the new neighbor each open a fast-start burst: all four
    // frames go out within seconds (at 1s spacing), not one per 30s interval.
    a.wait_new(burst_done, burst_a, 15).await?;
    b.wait_new(burst_done, burst_b, 15).await?;

    lldp_tagged(w).await?;

    // Tunable timers + Management Address TLVs: tx-interval 5 x tx-hold 3 must
    // show up as the TTL the neighbor learned (15), and each router's own
    // address as a management address carrying its eth0's real ifIndex
    // (resolved in the sender's netns; docker keeps the veth's host-side
    // index, so only non-zero is checked). router-b also advertises an
    // address on no interface, sent with the "unknown" numbering: two TLVs in
    // one LLDPDU.
    let on_if = |ip: &str| format!("{ip} (ifindex [1-9][0-9]*)");
    let mgmt_a = learned_a(&format!(
        " ttl=15 management_addresses={},{MGMT_NOWHERE} capabilities=",
        on_if(IP_B.s())
    ));
    let mgmt_b = learned_b(&format!(
        " ttl=15 management_addresses={} capabilities=",
        on_if(IP_A.s())
    ));
    let (base_ma, base_mb) = (a.count(&mgmt_a), b.count(&mgmt_b));
    a.provision(&host(
        "router-a",
        &[
            "--lldp-tx-interval",
            "5",
            "--lldp-tx-hold",
            "3",
            "--lldp-management-address",
            IP_A.s(),
        ],
    ))
    .await?;
    b.provision(&host(
        "router-b",
        &[
            "--lldp-tx-interval",
            "5",
            "--lldp-tx-hold",
            "3",
            "--lldp-management-address",
            IP_B.s(),
            "--lldp-management-address",
            MGMT_NOWHERE,
        ],
    ))
    .await?;
    a.wait_new(&mgmt_a, base_ma, 60).await?;
    b.wait_new(&mgmt_b, base_mb, 60).await?;

    // Removing one address restarts router-b's link; router-a relearns it
    // with only the other.
    let only_b = learned_a(&format!(
        " ttl=15 management_addresses={} capabilities=",
        on_if(IP_B.s())
    ));
    let base_ob = a.count(&only_b);
    b.provision(&host(
        "router-b",
        &["--no-lldp-management-address", MGMT_NOWHERE],
    ))
    .await?;
    a.wait_new(&only_b, base_ob, 60).await?;

    // The System Description knob: router-b learns router-a's custom text
    // (the link restarts on the change).
    let custom = learned_b(" ttl=15").replace("description=.* ttl", "description=e2e-edge ttl");
    let base_custom = b.count(&custom);
    a.provision(&host(
        "router-a",
        &["--lldp-system-description", "e2e-edge"],
    ))
    .await?;
    b.wait_new(&custom, base_custom, 60).await?;

    lldp_org_tlvs(w).await?;

    // 802.1AB counters over REST: both sides sent and received real frames,
    // none of them bad, and nos sends only TLVs nos recognizes.
    for r in [a, b] {
        let s = lldp_eth1_stats(r).await?;
        if s.frames_out == 0
            || s.frames_in == 0
            || s.frames_in_errors != 0
            || s.tlvs_unrecognized != 0
        {
            bail!("{}: unexpected lldp counters on eth1: {s:?}", r.name());
        }
    }

    // TTL expiry for real: freeze router-b's nos-lldpd (no shutdown frame) and
    // router-a must age it out on the 15s TTL alone, counting it, then learn
    // it again once it resumes.
    let expired = "lldp neighbor removed interface=eth1 .* reason=\"expired\"";
    let (base_exp, ageouts) = (a.count(expired), lldp_eth1_stats(a).await?.ageouts);
    log("freezing router-b's nos-lldpd: router-a must age it out within its 15s ttl");
    w.dock
        .signal_process("router-b", "nos-lldpd", "-STOP")
        .await?;
    let aged = a.wait_new(expired, base_exp, 25).await;
    let base_a = a.count(&learned_a(""));
    w.dock
        .signal_process("router-b", "nos-lldpd", "-CONT")
        .await?;
    aged?;
    if lldp_eth1_stats(a).await?.ageouts != ageouts + 1 {
        bail!("router-a's lldp ageouts counter did not go up by one");
    }
    a.wait_new(&learned_a(""), base_a, 30).await?;

    // Destination group. Both on customer-bridge: still neighbors. Then only
    // router-b back on nearest-bridge: the groups never see each other, though
    // both keep transmitting. Then router-a follows and both learn again.
    let (base_a, base_b) = (a.count(&learned_a("")), b.count(&learned_b("")));
    let cb = ["--lldp-destination-interface", "eth1=customer-bridge"];
    a.provision(&host("router-a", &cb)).await?;
    b.provision(&host("router-b", &cb)).await?;
    a.wait_new(&learned_a(""), base_a, 60).await?;
    b.wait_new(&learned_b(""), base_b, 60).await?;

    let removed = a.count(shutdown);
    let nb = ["--lldp-destination-interface", "eth1=nearest-bridge"];
    b.provision(&host("router-b", &nb)).await?;
    a.wait_new(shutdown, removed, 30).await?;
    let (base_a, base_b) = (a.count(&learned_a("")), b.count(&learned_b("")));
    log("mismatched destination groups: neither side may learn the other (waiting 15s)");
    tokio::time::sleep(Duration::from_secs(15)).await;
    if a.count(&learned_a("")) != base_a || b.count(&learned_b("")) != base_b {
        bail!("a neighbor was learned across mismatched destination groups");
    }
    a.provision(&host("router-a", &nb)).await?;
    a.wait_new(&learned_a(""), base_a, 60).await?;
    b.wait_new(&learned_b(""), base_b, 60).await?;

    // router-b stops transmitting: on the way out its link sends a real TTL-0
    // shutdown LLDPDU, which router-a must act on within seconds (far under the
    // 120s TTL) — proving shutdown handling rather than aging.
    let removed = a.count(shutdown);
    b.provision(&host("router-b", &["--no-lldp-transmit-interface", "eth1"]))
        .await?;
    a.wait_new(shutdown, removed, 30).await?;

    // Transmit comes back: router-a learns router-b again, and router-b (which
    // restarted with an empty table) learns router-a quickly, because learning
    // a *new* neighbor triggers a fast-start burst.
    let (base_a, base_b) = (a.count(&learned_a("")), b.count(&learned_b("")));
    b.provision(&host("router-b", &["--lldp-transmit-interface", "eth1"]))
        .await?;
    a.wait_new(&learned_a(""), base_a, 30).await?;
    b.wait_new(&learned_b(""), base_b, 15).await?;

    // #1431: the veth deleted and recreated under the same name (new ifindex):
    // both nos-lldpd reopen their sockets on nos-interfaced's LinkAdded and
    // learn each other again, without a send error on the dead socket.
    let (base_a, base_b) = (a.count(&learned_a("")), b.count(&learned_b("")));
    let reopened = "lldp socket reopened interface=eth1";
    let (re_a, re_b) = (a.count(reopened), b.count(reopened));
    let send_err = "failed to send lldpdu interface=eth1";
    let (err_a, err_b) = (a.count(send_err), b.count(send_err));
    log("recreating the eth1 veth: both nos-lldpd must reopen their sockets");
    w.unlink_veth("eth1").await;
    w.ensure_veth("eth1").await?;
    a.wait_new(reopened, re_a, 20).await?;
    b.wait_new(reopened, re_b, 20).await?;
    a.wait_new(&learned_a(""), base_a, 30).await?;
    b.wait_new(&learned_b(""), base_b, 30).await?;
    a.assert_quiet(send_err, err_a, 5).await?;
    b.assert_quiet(send_err, err_b, 5).await?;

    // Drop receive on router-a: its link restarts as transmit-only.
    a.provision(&host("router-a", &["--no-lldp-receive-interface", "eth1"]))
        .await?;
    a.wait_new(
        "lldp link started interface=eth1 transmit=true receive=false",
        started_a,
        30,
    )
    .await?;

    // Tear down. The baseline is taken here: every restart above also logs a
    // "link stopped" line.
    let stopped = a.count("lldp link stopped interface=eth1");
    a.provision(&host("router-a", &["--no-lldp-transmit-interface", "eth1"]))
        .await?;
    b.provision(&host(
        "router-b",
        &[
            "--no-lldp-transmit-interface",
            "eth1",
            "--no-lldp-receive-interface",
            "eth1",
        ],
    ))
    .await?;
    a.wait_new("lldp link stopped interface=eth1", stopped, 30)
        .await?;

    w.unlink_veths().await;
    Ok(())
}

/// 802.1/802.3 org TLVs (#63), router-a sending, router-b receiving. The
/// domain and profile are `switching`'s own `bd1`/`sp1`: bridge ids are
/// allocated once per name and never freed, so a new domain here would take
/// the `br1` that phase expects for `bd1`.
/// #690: an LLDPDU behind an 802.1Q tag is not a neighbor of the physical port.
/// The untagged copy sent right after it must be learned, so the check is not
/// vacuous.
async fn lldp_tagged(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    w.dock
        .ensure_image(
            PYTHON_HELPER_IMAGE,
            "FROM debian:trixie-slim\n\
            RUN apt-get update && apt-get install -y --no-install-recommends python3-minimal \\\n \
            && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    let learned = |port: &str| format!("lldp neighbor learned interface=eth1 .* port_id={port} ");
    let (base_tagged, base_ctl) = (
        a.count(&learned("tagged-vlan")),
        a.count(&learned("untagged-ctl")),
    );
    w.dock
        .in_netns(
            PYTHON_HELPER_IMAGE,
            "router-b",
            &["python3", "-c", include_str!("lldp_tagged.py")],
        )
        .await?;
    a.wait_new(&learned("untagged-ctl"), base_ctl, 15).await?;
    if a.count(&learned("tagged-vlan")) != base_tagged {
        bail!("router-a learned an 802.1Q-tagged LLDPDU on eth1 (#690)");
    }
    Ok(())
}

async fn lldp_org_tlvs(w: &World) -> anyhow::Result<()> {
    let host = |name: &str, extra: &[&str]| {
        let mut f = vec!["--hostname", name];
        f.extend_from_slice(extra);
        strings(&f)
    };
    let (a, b) = (w.a()?, w.b()?);
    let learned = |iface: &str, extra: &str| {
        format!("lldp neighbor learned interface={iface} .* system_name=router-a .*{extra}$")
    };
    // A switching-profile port with a jumbo MTU: the Bridge bit, Maximum
    // Frame Size (MTU + 18) and one VLAN Name per dot1q member. The link
    // restarts on the change (shutdown frame, then a fresh "learned").
    let trunk = learned(
        "eth1",
        " capabilities=bridge,router max_frame_size=9018 vlans=100:bd1 aggregation=-",
    );
    let base = b.count(&trunk);
    a.provision(&host(
        "router-a",
        &[
            "--link-interface",
            "eth1",
            "--mtu",
            "9000",
            "--switching-profile",
            "sp1",
            "--switching-profile-member",
            "bd1:100",
        ],
    ))
    .await?;
    b.wait_new(&trunk, base, 60).await?;

    // A port-aggregate member, enslaved first so the very first LLDPDU
    // already carries the bond's ifIndex (only non-zero is checked: it
    // depends on how many links the container created before).
    let bond = [
        "--port-aggregate",
        "po-lldp",
        "--enslave-interface-into-port-aggregate",
        "eth2",
    ];
    let enslaved = "enslaved interface to bond interface=eth2 bond=";
    let base = a.count(enslaved);
    a.provision(&host("router-a", &bond)).await?;
    a.wait_new(enslaved, base, 60).await?;
    let member = learned(
        "eth2",
        " max_frame_size=1518 vlans= aggregation=enabled/[1-9][0-9]*",
    );
    let base = b.count(&member);
    a.provision(&host("router-a", &["--lldp-transmit-interface", "eth2"]))
        .await?;
    b.provision(&host("router-b", &["--lldp-receive-interface", "eth2"]))
        .await?;
    b.wait_new(&member, base, 60).await?;

    // Back to the base state the rest of the phase expects.
    let plain = learned(
        "eth1",
        " capabilities=router max_frame_size=1518 vlans= aggregation=-",
    );
    let base = b.count(&plain);
    let mut undo = bond.to_vec();
    undo.extend([
        "--delete-port-aggregate",
        "--no-lldp-transmit-interface",
        "eth2",
        "--link-interface",
        "eth1",
        "--clear-mtu",
        "--delete-switching-profile",
    ]);
    a.provision(&host("router-a", &undo)).await?;
    b.provision(&host("router-b", &["--no-lldp-receive-interface", "eth2"]))
        .await?;
    b.wait_new(&plain, base, 60).await
}

/// `eth1`'s row of `GET /v1/lldp/statistics`.
async fn lldp_eth1_stats(r: &Router) -> anyhow::Result<nos_proto::LldpLinkStats> {
    let body = r
        .rest_expect(Method::GET, "/v1/lldp/statistics", None, 200)
        .await?;
    let rows: Vec<nos_proto::LldpLinkStats> = serde_json::from_str(&body)?;
    rows.into_iter()
        .find(|s| s.interface == "eth1")
        .with_context(|| format!("{}: no eth1 row in lldp statistics: {body}", r.name()))
}

pub async fn switching(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.provision(&[
        "--switching-profile",
        "sp1",
        "--switching-profile-member",
        "bd1:100",
        "--switching-profile-member",
        "bd2:200",
    ])
    .await?;
    a.wait("created broadcast domain bridge domain=bd1 bridge=br1")
        .await?;
    a.wait("created broadcast domain bridge domain=bd2 bridge=br2")
        .await?;
    a.wait("created vlan sub-interface interface=eth0 sub_interface=eth0.100 tag=100")
        .await?;
    a.wait("created vlan sub-interface interface=eth0 sub_interface=eth0.200 tag=200")
        .await?;
    a.wait("enslaved interface to bridge interface=eth0.100 bridge=br1")
        .await?;
    a.wait("enslaved interface to bridge interface=eth0.200 bridge=br2")
        .await?;

    a.provision(&["--delete-switching-profile"]).await?;
    a.wait("deleted vlan sub-interface interface=eth0 sub_interface=eth0.100")
        .await?;
    a.wait("deleted vlan sub-interface interface=eth0 sub_interface=eth0.200")
        .await
}

/// #326: with `spanning-tree mode` on and no `nos-stpd` yet, a trunk's bridge
/// port is enslaved blocking and BPDU-trapped; turning STP off restores it.
pub async fn stp_failsafe(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let port = "interface=eth0.100";
    a.provision(&[
        "--switching-profile",
        "sp1",
        "--switching-profile-member",
        "bd1:100",
        "--stp-mode",
        "rstp",
    ])
    .await?;
    a.wait(&format!("bridge port enslaved blocking {port}"))
        .await?;
    a.wait(&format!("bpdu trap installed {port}")).await?;
    let restored = a.count(&format!("bridge port forwarding restored {port}"));
    let removed = a.count(&format!("bpdu trap removed {port}"));
    a.provision(&["--stp-mode", "disabled"]).await?;
    a.wait_new(
        &format!("bridge port forwarding restored {port}"),
        restored,
        30,
    )
    .await?;
    a.wait_new(&format!("bpdu trap removed {port}"), removed, 30)
        .await?;

    a.provision(&["--delete-switching-profile"]).await?;
    a.wait("deleted vlan sub-interface interface=eth0 sub_interface=eth0.100")
        .await?;
    a.established().await
}

/// `GET /v1/spanning-tree` (#328).
async fn stp_summary(r: &Router) -> anyhow::Result<nos_proto::StpSummary> {
    let body = r
        .rest_expect(Method::GET, "/v1/spanning-tree", None, 200)
        .await?;
    Ok(serde_json::from_str(&body)?)
}

/// `GET /v1/spanning-tree/counters` (#323): the CIST row of `port`.
async fn stp_counters(r: &Router, port: &str) -> anyhow::Result<nos_proto::StpPortCounters> {
    let body = r
        .rest_expect(Method::GET, "/v1/spanning-tree/counters", None, 200)
        .await?;
    let rows: serde_json::Value = serde_json::from_str(&body)?;
    let row = rows
        .as_array()
        .and_then(|a| a.iter().find(|r| r["tree"] == "cist" && r["port"] == port))
        .ok_or_else(|| anyhow::anyhow!("no counters row for {port}: {body}"))?;
    Ok(serde_json::from_value(row["counters"].clone())?)
}

/// `key`'s value on the latest line matching `pattern`.
fn last_value(r: &Router, pattern: &str, key: &str) -> Option<String> {
    let line = r.logs.last(pattern)?;
    line.rsplit(&format!("{key}=")).next().map(str::to_string)
}

/// The last STP lines of `r`'s log, for failure messages (#1188).
fn stp_log_tail(r: &Router) -> String {
    let p = r"port role changed\|port state changed\|root bridge changed\|port carrier\|topology change";
    format!("{} log tail:\n{}", r.name(), r.logs.tail(p, 30).join("\n"))
}

/// Router-b's (root, alternate) ports from its REST summary, polled up to
/// 10s until it shows exactly one of each (#1188: not from the last role log
/// line, which can be stale while the tree is still settling).
async fn stp_b_roles(b: &Router) -> anyhow::Result<(&'static str, &'static str)> {
    let mut last = String::new();
    for _ in 0..40 {
        let sb = stp_summary(b).await?;
        let role = |p: &str| sb.ports.iter().find(|x| x.name == p).map(|x| x.role);
        match (role("eth1"), role("eth2")) {
            (Some(StpRole::Root), Some(StpRole::Alternate)) => return Ok(("eth1", "eth2")),
            (Some(StpRole::Alternate), Some(StpRole::Root)) => return Ok(("eth2", "eth1")),
            _ => last = format!("{:?}", sb.ports),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!(
        "router-b should have one root and one alternate port: {last}\n{}",
        stp_log_tail(b)
    )
}

/// Polls until the four STP ports (both routers' `eth1`/`eth2`) hold exactly
/// one `Discarding` and three `Forwarding` for three seconds in a row. The
/// states come from `GET /v1/spanning-tree`, not the last log line (#1251: a
/// port that stays `Discarding` looked the same as one that never got its
/// `Forwarding`).
async fn stp_settle(routers: [&Router; 2], secs: u64) -> anyhow::Result<()> {
    let mut stable = 0;
    let mut last = String::new();
    for _ in 0..secs {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut states = Vec::new();
        for r in routers {
            let s = stp_summary(r).await?;
            for p in ["eth1", "eth2"] {
                states.push(
                    s.ports
                        .iter()
                        .find(|x| x.name == p)
                        .map(|x| format!("{:?}", x.state)),
                );
            }
        }
        let n = |want: &str| states.iter().filter(|s| s.as_deref() == Some(want)).count();
        last = format!("{states:?}");
        if n("Discarding") == 1 && n("Forwarding") == 3 {
            stable += 1;
            if stable >= 3 {
                return Ok(());
            }
        } else {
            stable = 0;
        }
    }
    let mut diag = Vec::new();
    for r in routers {
        let ports = stp_summary(r).await.map(|s| s.ports);
        diag.push(format!("{ports:?}\n{}", stp_log_tail(r)));
    }
    let diag = diag.join("\n");
    bail!("spanning tree did not settle on one blocking port in {secs}s: {last}\n{diag}")
}

/// #327: `nos-stpd` runs RSTP over the two parallel veth links of one
/// domain: one root, one blocking port, no BPDU storm, sub-second failover
/// on a cut link, and reconvergence when it comes back.
pub async fn stp(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let routers = [a, b];
    let state = |p: &str| format!("port state changed port={p} state=");

    w.link_veths().await?;
    // One profile per link, both holding the same untagged domain. Every
    // provision must repeat `--stp-mode rstp`: unset means disabled.
    for r in routers {
        r.provision(&[
            "--link-interface",
            "eth2",
            "--switching-profile",
            "stp-sp2",
            "--switching-profile-member",
            "stp-d:untagged",
        ])
        .await?;
        let mut on = strings(&[
            "--link-interface",
            "eth1",
            "--switching-profile",
            "stp-sp1",
            "--switching-profile-member",
            "stp-d:untagged",
            "--stp-mode",
            "rstp",
        ]);
        if r.name() == "router-a" {
            on.extend(strings(&["--stp-priority", "4096"]));
        }
        r.provision(&on).await?;
    }

    log("waiting for one root bridge and exactly one blocking port");
    stp_settle(routers, 60).await?;
    let root = "root bridge changed root=";
    let (ra, rb) = (last_value(a, root, "root"), last_value(b, root, "root"));
    if ra.is_none() || ra != rb || !ra.as_deref().is_some_and(|r| r.starts_with("1000.")) {
        bail!(
            "routers disagree on the root, or it is not router-a (priority 4096): {ra:?} vs {rb:?}"
        );
    }

    // #328: `GET /v1/spanning-tree` on both routers agrees with the logs.
    let (sa, sb) = (stp_summary(a).await?, stp_summary(b).await?);
    if !sa.enabled || sa.root_id != sb.root_id || sa.root_id != sa.bridge_id {
        bail!("summaries disagree on the root (router-a has priority 4096): {sa:?} vs {sb:?}");
    }
    if sa.root_port.is_some() || sb.root_port.is_none() {
        bail!("only router-b has a root port: {sa:?} vs {sb:?}");
    }
    let blocked = sa
        .ports
        .iter()
        .chain(&sb.ports)
        .filter(|p| p.role == StpRole::Alternate && p.state == StpState::Discarding)
        .count();
    if blocked != 1 || sa.ports.len() != 2 || sb.ports.len() != 2 {
        bail!("want exactly one alternate/discarding port: {sa:?} vs {sb:?}");
    }

    // No BPDU storm: a hello is 2s, so a 10s summary is ~5 per port.
    for r in routers {
        for p in ["eth1", "eth2"] {
            let sum = format!("bpdu rx port={p} count=");
            r.wait_new(&sum, r.count(&sum), 15).await?;
            let n: u32 = last_value(r, &sum, "count").unwrap_or_default().parse()?;
            log(format!("{}: {p} received {n} BPDUs in 10s", r.name()));
            if n >= 20 {
                bail!("{}: {p} received {n} BPDUs in 10s (storm?)", r.name());
            }
        }
    }

    // Cut router-b's root port; its alternate must take over within 1s of
    // the carrier loss, both lines from router-b's own log.
    let (root_if, alt_if) = stp_b_roles(b).await?;
    let takeover = format!("{}Forwarding", state(alt_if));
    let base_takeover = b.count(&takeover);
    let base_lost = b.count(&format!("port carrier lost port={root_if}"));
    // #323: the change shows in the logs of both routers, and in the counters.
    let tc = "topology change port=";
    let tc_rx = "topology change port=.*cause=received";
    let (tc_b, tc_a) = (b.count(tc), a.count(tc_rx));
    let counters_before = stp_counters(b, alt_if).await?;
    log(format!(
        "cutting router-b {root_if}; {alt_if} must take over"
    ));
    let up = format!("port carrier up port={root_if}");
    let base_up = b.count(&up);
    w.set_link("router-b", root_if, false).await?;
    b.wait_new(&takeover, base_takeover, 10).await?;
    b.assert_delay_under(
        (&format!("port carrier lost port={root_if}"), base_lost),
        (&takeover, base_takeover),
        1000,
    )?;
    // #1188: `nos-interfaced`'s 10s re-apply tick (#615) sets the cut link
    // admin-up again, at a per-run phase offset. If it landed before this
    // read, `root_if` is Root again and the summary can no longer show the
    // takeover (a poll would not help); the Forwarding line proved it.
    let sb = stp_summary(b).await?;
    let took_over = sb.ports.iter().find(|p| p.name == alt_if);
    let ok = took_over.is_some_and(|p| p.role == StpRole::Root && p.state == StpState::Forwarding)
        && sb.root_port.as_deref() == Some(alt_if);
    if !ok {
        if b.count(&up) <= base_up {
            bail!(
                "router-b's {alt_if} should be the forwarding root port: {sb:?}\n{}",
                stp_log_tail(b)
            );
        }
        log(format!(
            "router-b: {root_if} re-upped before the summary read; takeover proven by the log"
        ));
    }

    // #323: topology-change tracking, RFC 4318 counters and the REST paths.
    b.wait_new(tc, tc_b, 15).await?;
    a.wait_new(tc_rx, tc_a, 15).await?;
    let sb = stp_summary(b).await?;
    if sb.topology.count == 0 || sb.topology.last_port.is_none() || sb.topology.last_cause.is_none()
    {
        bail!(
            "router-b logged a topology change but reports none: {:?}",
            sb.topology
        );
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    let counters_after = stp_counters(b, alt_if).await?;
    if counters_after.in_rstp_bpdu <= counters_before.in_rstp_bpdu
        || counters_after.out_rstp_bpdu <= counters_before.out_rstp_bpdu
        || counters_after.forward_transitions <= counters_before.forward_transitions
    {
        bail!("router-b {alt_if} counters did not grow: {counters_before:?} -> {counters_after:?}");
    }
    b.rest_expect(Method::GET, "/v1/spanning-tree/instance/999", None, 404)
        .await?;

    // The link comes back: reconverge to exactly one blocking port.
    w.set_link("router-b", root_if, true).await?;
    stp_settle(routers, 60).await?;

    stp_live_edit(w).await?;

    for r in routers {
        for iface in ["eth1", "eth2"] {
            r.provision(&["--link-interface", iface, "--delete-switching-profile"])
                .await?;
        }
    }
    w.unlink_veths().await;
    a.established().await?;
    b.established().await
}

/// #662: on the converged tree, router-a (the root) gets a port cost edit and
/// a new port that sorts before `eth1` (`eth05`), then loses it again. Each
/// is applied in place: no existing port leaves Forwarding, no rebuild is
/// logged, and router-b still sees the same designated Port Identifiers
/// (a renumbering would change them on the wire).
async fn stp_live_edit(w: &World) -> anyhow::Result<()> {
    const IN_PLACE: &str = "spanning tree plan updated in place";
    const REBUILT: &str = "spanning tree plan applied";
    const DISCARD: &str = "port state changed port=eth[12] state=Discarding";
    let (a, b) = (w.a()?, w.b()?);
    let designated = |s: &nos_proto::StpSummary| -> Vec<(String, String)> {
        s.ports
            .iter()
            .map(|p| (p.name.clone(), p.designated_port.clone()))
            .collect()
    };
    let before = designated(&stp_summary(b).await?);
    let rebuilt = a.count(REBUILT);
    let discard = a.count(DISCARD);
    let root_b = b.count("root bridge changed");
    w.ensure_veth("eth05").await?;
    // router-b has no config for it, so nothing else brings its end up.
    w.set_link("router-b", "eth05", true).await?;

    // The same provision as the phase's, plus the edit; priority stays.
    let on = |extra: &[&str]| {
        let mut args = strings(&[
            "--link-interface",
            "eth1",
            "--switching-profile",
            "stp-sp1",
            "--switching-profile-member",
            "stp-d:untagged",
            "--stp-mode",
            "rstp",
            "--stp-priority",
            "4096",
        ]);
        args.extend(strings(extra));
        args
    };
    log("router-a: eth1 cost edit, applied in place");
    let in_place = a.count(IN_PLACE);
    a.provision(&on(&[
        "--stp-profile-interface",
        "eth1",
        "--stp-profile-field",
        "cost=500",
    ]))
    .await?;
    a.wait_new(IN_PLACE, in_place, 20).await?;

    log("router-a: new port eth05 (sorts before eth1), applied in place");
    let in_place = a.count(IN_PLACE);
    a.provision(&strings(&[
        "--link-interface",
        "eth05",
        "--switching-profile",
        "stp-sp3",
        "--switching-profile-member",
        "stp-d:untagged",
        "--stp-mode",
        "rstp",
        "--stp-priority",
        "4096",
    ]))
    .await?;
    a.wait_new(IN_PLACE, in_place, 20).await?;
    a.wait_new("port state changed port=eth05 state=Forwarding", 0, 60)
        .await?;
    let sa = stp_summary(a).await?;
    if sa.ports.len() != 3 {
        bail!("router-a should have three STP ports: {sa:?}");
    }

    log("router-a: eth05 removed again, applied in place");
    let in_place = a.count(IN_PLACE);
    a.provision(&strings(&[
        "--link-interface",
        "eth05",
        "--delete-switching-profile",
        "--stp-mode",
        "rstp",
        "--stp-priority",
        "4096",
    ]))
    .await?;
    a.wait_new(IN_PLACE, in_place, 20).await?;
    let sa = stp_summary(a).await?;
    if sa.ports.len() != 2 {
        bail!("router-a should be back to two STP ports: {sa:?}");
    }

    a.assert_quiet(REBUILT, rebuilt, 5).await?;
    a.assert_quiet(DISCARD, discard, 5).await?;
    b.assert_quiet("root bridge changed", root_b, 5).await?;
    let after = designated(&stp_summary(b).await?);
    if before != after {
        bail!("router-b sees other designated ports of router-a: {before:?} -> {after:?}");
    }
    a.provision(&on(&[
        "--stp-profile-interface",
        "eth1",
        "--stp-profile-field",
        "cost=",
    ]))
    .await?;
    w.unlink_veth("eth05").await;
    Ok(())
}

/// #319: router-b is the root, forced to 802.1D (`force-version stp`), router-a stays
/// RSTP. Router-a's ports fall back to STP when they hear its Config BPDUs,
/// the tree still settles on one blocking port (legacy Listening/Learning, so
/// ~30 s), `mcheck` sends router-a back to RSTP and a legacy peer pulls it
/// straight down again; once router-b is RSTP again `mcheck` sticks.
pub async fn stp_legacy(w: &mut World) -> anyhow::Result<()> {
    const TO_STP: &str = "port migrated to STP";
    const TO_RSTP: &str = "port migrated to RSTP";
    let (a, b) = (w.a()?, w.b()?);
    let routers = [a, b];
    let a_stp = a.count(TO_STP);

    w.link_veths().await?;
    for r in routers {
        r.provision(&[
            "--link-interface",
            "eth2",
            "--switching-profile",
            "stp-sp2",
            "--switching-profile-member",
            "stp-d:untagged",
        ])
        .await?;
        let mut on = strings(&[
            "--link-interface",
            "eth1",
            "--switching-profile",
            "stp-sp1",
            "--switching-profile-member",
            "stp-d:untagged",
            "--stp-mode",
            "rstp",
        ]);
        // Router-b (legacy) is the root: a non-designated 802.1D port sends
        // no Config BPDU, so a root b is what keeps feeding router-a (#1229).
        if r.name() == "router-b" {
            on.extend(strings(&[
                "--stp-priority",
                "4096",
                "--stp-force-version",
                "stp",
            ]));
        } else {
            // #839: the `stp` phase left router-a at 4096; an equal priority
            // makes the root a coin flip on the random MACs.
            on.extend(strings(&["--stp-priority", "32768"]));
        }
        r.provision(&on).await?;
    }

    // Both of router-a's ports hear Config BPDUs and fall back, router-b
    // never leaves STP.
    log("waiting for router-a to migrate both ports to STP");
    a.wait_new(TO_STP, a_stp, 30).await?;
    for r in routers {
        let sum = stp_summary(r).await?;
        if sum.ports.len() != 2 {
            bail!("{}: want two spanning-tree ports: {sum:?}", r.name());
        }
    }
    if b.count(TO_STP) == 0 {
        bail!("router-b should have been forced to STP");
    }

    log("waiting for one root bridge and exactly one blocking port (legacy timers)");
    stp_settle(routers, 150).await?;
    let (sa, sb) = (stp_summary(a).await?, stp_summary(b).await?);
    let blocked = sa
        .ports
        .iter()
        .chain(&sb.ports)
        .filter(|p| p.role == StpRole::Alternate && p.state == StpState::Discarding)
        .count();
    if !sb.enabled || sb.root_id != sb.bridge_id || sa.root_id != sb.root_id || blocked != 1 {
        bail!("legacy tree: router-b must be root with one alternate port: {sa:?} vs {sb:?}");
    }
    for r in routers {
        for p in ["eth1", "eth2"] {
            let sum = format!("bpdu rx port={p} count=");
            r.wait_new(&sum, r.count(&sum), 15).await?;
            let n: u32 = last_value(r, &sum, "count").unwrap_or_default().parse()?;
            if n >= 20 {
                bail!("{}: {p} received {n} BPDUs in 10s (storm?)", r.name());
            }
        }
    }

    // mcheck: back to RSTP, then the STP peer pulls the port down again.
    let (stp_base, rstp_base) = (a.count(TO_STP), a.count(TO_RSTP));
    a.rest_expect(Method::POST, "/v1/spanning-tree/mcheck", None, 200)
        .await?;
    a.wait_new(TO_RSTP, rstp_base, 10).await?;
    a.wait_new(TO_STP, stp_base, 20).await?;
    a.rest_expect(
        Method::POST,
        "/v1/spanning-tree/port/not-a-port/mcheck",
        None,
        404,
    )
    .await?;

    // Router-b upgrades: the same mcheck now leaves router-a on RSTP.
    let rstp_base = a.count(TO_RSTP);
    b.provision(&[
        "--link-interface",
        "eth1",
        "--switching-profile",
        "stp-sp1",
        "--switching-profile-member",
        "stp-d:untagged",
        "--stp-mode",
        "rstp",
        "--stp-force-version",
        "rstp",
    ])
    .await?;
    a.rest_expect(Method::POST, "/v1/spanning-tree/mcheck", None, 200)
        .await?;
    a.wait_new(TO_RSTP, rstp_base, 30).await?;
    let stp_base = a.count(TO_STP);
    a.rest_expect(Method::POST, "/v1/spanning-tree/mcheck", None, 200)
        .await?;
    a.assert_quiet(TO_STP, stp_base, 10).await?;

    for r in routers {
        for iface in ["eth1", "eth2"] {
            r.provision(&["--link-interface", iface, "--delete-switching-profile"])
                .await?;
        }
    }
    w.unlink_veths().await;
    a.established().await?;
    b.established().await
}

/// Polls `GET /v1/spanning-tree` on `r` until `want` holds for `port`.
async fn stp_wait_port(
    r: &Router,
    port: &str,
    secs: u64,
    want: impl Fn(&nos_proto::StpPortInfo) -> bool,
) -> anyhow::Result<()> {
    let mut last = String::new();
    for _ in 0..secs {
        let sum = stp_summary(r).await?;
        if let Some(p) = sum.ports.iter().find(|p| p.name == port) {
            if want(p) {
                return Ok(());
            }
            last = format!("{p:?}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{}: {port} never reached the wanted state in {secs}s: {last}",
        r.name()
    )
}

/// One `stp-protections` provision of `eth1`: RSTP at `prio`, and on router-a
/// the `e2e-prot` profile with `fields` (`name=json`, empty value deletes).
/// Every provision repeats `--stp-mode rstp`: unset means disabled.
async fn stp_prot_provision(r: &Router, prio: &str, fields: &[&str]) -> anyhow::Result<()> {
    let mut args = strings(&[
        "--link-interface",
        "eth1",
        "--switching-profile",
        "stp-sp1",
        "--switching-profile-member",
        "stp-d:untagged",
        "--stp-mode",
        "rstp",
        "--stp-priority",
        prio,
    ]);
    if r.name() == "router-a" {
        args.extend(strings(&["--stp-profile-interface", "eth1"]));
        for f in fields {
            args.extend(strings(&["--stp-profile-field", f]));
        }
    }
    r.provision(&args).await
}

/// #320: port protections on the second link only (`eth1`; `eth0` is the
/// management/BGP path and is never err-disabled). Root guard holds router-a's
/// port Discarding while router-b is the better root; BPDU guard on an
/// `edge-port admin` port err-disables it on the first BPDU, and the recovery
/// timer, `clear` and removing the guard each bring it back.
pub async fn stp_protections(w: &mut World) -> anyhow::Result<()> {
    const DISABLED: &str = "port err-disabled port=eth1 reason=bpdu-guard";
    const RECOVERED: &str = "port err-disabled recovered port=eth1";
    const CLEAR: &str = "/v1/spanning-tree/port/eth1/err-disabled/clear";
    let (a, b) = (w.a()?, w.b()?);
    w.link_veths().await?;

    // Router-b is the better root (4096): a root-guarded eth1 on router-a is
    // root-inconsistent and stays Discarding, router-a keeps believing it is
    // the root.
    log("root guard on router-a eth1, router-b is the better root");
    let inconsistent = a.count("port root-inconsistent port=eth1");
    stp_prot_provision(b, "4096", &[]).await?;
    stp_prot_provision(a, "32768", &["root-guard=true"]).await?;
    a.wait_new("port root-inconsistent port=eth1", inconsistent, 40)
        .await?;
    stp_wait_port(a, "eth1", 20, |p| {
        p.root_guard
            && p.root_inconsistent
            && p.role == StpRole::Alternate
            && p.state == StpState::Discarding
    })
    .await?;
    if stp_summary(a).await?.root_port.is_some() {
        bail!("a root-guarded port must not become router-a's root port");
    }
    log("root guard removed: eth1 becomes the root port");
    stp_prot_provision(a, "32768", &["root-guard=false"]).await?;
    stp_wait_port(a, "eth1", 40, |p| {
        !p.root_guard && p.role == StpRole::Root && p.state == StpState::Forwarding
    })
    .await?;

    // BPDU guard: eth1 is an admin edge port, router-b's first BPDU shuts it.
    log("bpdu guard (edge admin, recovery 5s) on router-a eth1");
    let (down, up) = (a.count(DISABLED), a.count(RECOVERED));
    stp_prot_provision(
        a,
        "32768",
        &[
            "edge-port=\"Admin\"",
            "bpdu-guard=true",
            "bpdu-guard-recovery=5",
        ],
    )
    .await?;
    a.wait_new(DISABLED, down, 40).await?;
    stp_wait_port(a, "eth1", 3, |p| {
        p.err_disabled && p.err_recovery_secs.is_some()
    })
    .await?;
    // The recovery timer lifts it; router-b's BPDU shuts it again.
    a.wait_new(RECOVERED, up, 15).await?;
    a.wait_new(DISABLED, down + 1, 20).await?;

    // Recovery off: only `clear` (or removing the guard) lifts it.
    log("recovery off: manual clear");
    stp_prot_provision(a, "32768", &["bpdu-guard-recovery="]).await?;
    let _up = a.count(RECOVERED);
    stp_wait_port(a, "eth1", 40, |p| {
        p.err_disabled && p.err_recovery_secs.is_none()
    })
    .await?;
    a.rest_expect(
        Method::POST,
        "/v1/spanning-tree/port/not-a-port/err-disabled/clear",
        None,
        404,
    )
    .await?;
    // A restarted nos-stpd must not release what nos-interfaced still holds
    // down (#697): the full (here: manual) recovery applies again.
    log("nos-stpd restart: the err-disabled port stays down");
    let (applied, up) = (a.count("spanning tree plan applied"), a.count(RECOVERED));
    w.dock.kill_process("router-a", "nos-stpd").await?;
    a.wait_new("spanning tree plan applied", applied, 40)
        .await?;
    a.assert_quiet(RECOVERED, up, 8).await?;
    let body = a
        .rest_expect(Method::GET, "/v1/interfaces/eth1", None, 200)
        .await?;
    let iface: serde_json::Value = serde_json::from_str(&body)?;
    if iface["err_disabled"] != true {
        bail!("eth1 must still be err_disabled after the restart: {body}");
    }
    stp_wait_port(a, "eth1", 20, |p| {
        p.err_disabled && p.err_recovery_secs.is_none()
    })
    .await?;
    let down = a.count(DISABLED);
    a.rest_expect(Method::POST, CLEAR, None, 200).await?;
    a.wait_new(RECOVERED, up, 10).await?;
    // The guard is still on, so router-b's next BPDU shuts it again.
    a.wait_new(DISABLED, down, 30).await?;

    // Removing the guard from the profile recovers the port at once.
    log("guard removed: the port comes back");
    let up = a.count(RECOVERED);
    stp_prot_provision(a, "32768", &["bpdu-guard=false"]).await?;
    a.wait_new(RECOVERED, up, 10).await?;
    stp_wait_port(a, "eth1", 40, |p| {
        !p.err_disabled && !p.bpdu_guard && p.role == StpRole::Root
    })
    .await?;

    for r in [a, b] {
        r.provision(&[
            "--link-interface",
            "eth1",
            "--delete-switching-profile",
            "--stp-priority",
            "32768",
        ])
        .await?;
    }
    a.provision(&[
        "--stp-profile-interface",
        "eth1",
        "--stp-profile-detach",
        "--stp-priority",
        "32768",
    ])
    .await?;
    w.unlink_veths().await;
    a.established().await?;
    b.established().await
}

/// `GET /v1/spanning-tree/instance/<id>`.
async fn mst_instance(r: &Router, id: u16) -> anyhow::Result<nos_proto::StpInstance> {
    let body = r
        .rest_expect(
            Method::GET,
            &format!("/v1/spanning-tree/instance/{id}"),
            None,
            200,
        )
        .await?;
    Ok(serde_json::from_str(&body)?)
}

/// Polls instance `id` on `r` until `want` holds twice in a row (a state that
/// merely passes through is not settled).
async fn mst_wait(
    r: &Router,
    id: u16,
    secs: u64,
    want: impl Fn(&nos_proto::StpInstance) -> bool,
) -> anyhow::Result<nos_proto::StpInstance> {
    let mut last = String::new();
    let mut stable = 0;
    for _ in 0..secs {
        if let Ok(i) = mst_instance(r, id).await {
            if want(&i) {
                stable += 1;
                if stable >= 2 {
                    return Ok(i);
                }
            } else {
                stable = 0;
            }
            last = format!("{i:?}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{}: instance {id} never settled as wanted in {secs}s: {last}",
        r.name()
    )
}

/// `GET /v1/spanning-tree/mst-config`.
async fn mst_config(r: &Router) -> anyhow::Result<nos_proto::StpMst> {
    let body = r
        .rest_expect(Method::GET, "/v1/spanning-tree/mst-config", None, 200)
        .await?;
    Ok(serde_json::from_str(&body)?)
}

/// The state `nos-interfaced` last wrote to bridge port `link` on `r`:
/// `None` when it never wrote one (the port is still in its blocking
/// failsafe).
fn kernel_port_state(r: &Router, link: &str) -> Option<String> {
    last_value(
        r,
        &format!("bridge port state set interface={link} state="),
        "state",
    )
}

/// Waits until `link` is blocked (`blocked`) or forwarding on `r`.
async fn kernel_wait(r: &Router, link: &str, blocked: bool, secs: u64) -> anyhow::Result<()> {
    let mut last = None;
    for _ in 0..secs {
        last = kernel_port_state(r, link);
        let ok = if blocked {
            last.as_deref().is_none_or(|s| s == "Blocking")
        } else {
            last.as_deref() == Some("Forwarding")
        };
        if ok {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{}: {link} should be {} in the kernel, last write {last:?}",
        r.name(),
        if blocked { "blocking" } else { "forwarding" }
    )
}

/// One `stp-mstp` provision of `eth1` on `r`: region `lab` at `revision`, the
/// trunk `mstp-sp1` into `mst-d1` (VLAN 10, MSTI 1) and `mst-d2` (VLAN 20,
/// MSTI 2). Router-a is the CIST root and the root of MSTI 1, router-b the
/// root of MSTI 2; the other router's `eth1` is expensive in the tree it is
/// not the root of, so MSTI 1 blocks router-b's `eth1` and MSTI 2 router-a's.
async fn mstp_provision(r: &Router, revision: u16) -> anyhow::Result<()> {
    mstp_provision_with(r, revision, &[]).await
}

/// [`mstp_provision`] plus `extra` flags, applied after the base (so a repeated
/// `--stp-mst-instance` or cost overrides it).
async fn mstp_provision_with(r: &Router, revision: u16, extra: &[&str]) -> anyhow::Result<()> {
    let a = r.name() == "router-a";
    let mut args = strings(&[
        "--link-interface",
        "eth1",
        "--switching-profile",
        "mstp-sp1",
        "--switching-profile-member",
        "mst-d1:10",
        "--switching-profile-member",
        "mst-d2:20",
        "--stp-mode",
        "mstp",
        "--stp-priority",
        if a { "4096" } else { "32768" },
        "--stp-region",
        &format!("lab:{revision}"),
        "--stp-mst-instance",
        if a { "1:4096" } else { "1:32768" },
        "--stp-mst-instance",
        if a { "2:32768" } else { "2:4096" },
        "--stp-domain-instance",
        "mst-d1:1",
        "--stp-domain-instance",
        "mst-d2:2",
        "--stp-profile-interface",
        "eth1",
        "--stp-profile-mst-cost",
        if a { "2:100000" } else { "1:100000" },
    ]);
    args.extend(strings(extra));
    r.provision(&args).await
}

/// #321: MSTP over the two parallel veth links of the `stp` phase, two
/// domains (VLAN 10 in MSTI 1, VLAN 20 in MSTI 2). Both routers must compute
/// the same MST configuration digest and join one region; MSTI 1 then blocks
/// router-b's `eth1` and MSTI 2 router-a's, each only on its own domain's
/// `ethX.<tag>` bridge port in the kernel. A different `revision` on
/// router-b makes the ports boundary ports with a single CIST (the second
/// link blocked for both domains), restoring it rejoins the region.
pub async fn stp_mstp(w: &mut World) -> anyhow::Result<()> {
    const MATCH: &str = "mst region match port=eth1";
    const BOUNDARY: &str = "mst boundary port port=eth1 reason=revision";
    const IN_PLACE: &str = "spanning tree plan updated in place";
    const REBUILT: &str = "spanning tree plan applied";
    const APPLY_FAILED: &str = "failed to apply interface configuration.*Network is down";
    let (a, b) = (w.a()?, w.b()?);
    let routers = [a, b];
    let matched = routers.map(|r| r.count(MATCH));

    w.link_veths().await?;
    // router-a's fresh veths stay admin-down, but earlier phases leave a bare
    // `Interface eth1` behind, so `nos-interfaced` may already have raised
    // them: the raise itself is no anchor here (#355) and is proven by the
    // driver's kernel test (#338). router-b's are raised here so router-a's
    // ports have carrier the moment they come up (a carrierless bridge port is
    // DISABLED, so the kernel forwards on carrier with no state write to log
    // until the next resync).
    for iface in ["eth1", "eth2"] {
        w.set_link("router-b", iface, true).await?;
    }
    let enetdown = routers.map(|r| r.count(APPLY_FAILED));
    for r in routers {
        r.provision(&[
            "--link-interface",
            "eth2",
            "--switching-profile",
            "mstp-sp2",
            "--switching-profile-member",
            "mst-d1:10",
            "--switching-profile-member",
            "mst-d2:20",
        ])
        .await?;
        mstp_provision(r, 1).await?;
    }

    log("waiting for both routers to join one MST region");
    for (r, base) in routers.iter().zip(matched) {
        r.wait_new(MATCH, base, 40).await?;
        r.wait("mst configuration name=lab revision=1").await?;
    }
    // One REAPPLY tick later: no ENETDOWN retry loop on the admin-down parents.
    for (r, base) in routers.iter().zip(enetdown) {
        r.assert_quiet(APPLY_FAILED, base, 20).await?;
    }
    let (ca, cb) = (mst_config(a).await?, mst_config(b).await?);
    if ca.digest != cb.digest || ca.digest == "ac36177f50283cd4b83821d8ab26de62" {
        bail!("the routers must compute the same non-default digest: {ca:?} vs {cb:?}");
    }
    let vlans = |c: &nos_proto::StpMst, id: u16| {
        c.instances
            .iter()
            .find(|i| i.id == id)
            .map(|i| i.vlans.clone())
    };
    if (vlans(&ca, 1), vlans(&ca, 2)) != (Some("10".into()), Some("20".into())) {
        bail!("instance to VLAN map is wrong: {ca:?}");
    }

    log("waiting for MSTI 1 to block router-b eth1 and MSTI 2 router-a eth1");
    let blocked = |name: &str| {
        let name = name.to_string();
        move |i: &nos_proto::StpInstance| {
            i.ports.iter().all(|p| !p.boundary)
                && i.ports.iter().any(|p| {
                    p.name == name
                        && p.role == StpRole::Alternate
                        && p.state == StpState::Discarding
                })
                && i.ports
                    .iter()
                    .any(|p| p.name != name && p.state == StpState::Forwarding)
        }
    };
    let b1 = mst_wait(b, 1, 90, blocked("eth1")).await?;
    let a2 = mst_wait(a, 2, 90, blocked("eth1")).await?;
    // Each router is the root of the other tree, and forwards everywhere there.
    let a1 = mst_wait(a, 1, 30, |i| i.root_port.is_none()).await?;
    let b2 = mst_wait(b, 2, 30, |i| i.root_port.is_none()).await?;
    if a1.root_id != a1.bridge_id
        || b2.root_id != b2.bridge_id
        || b1.root_port.as_deref() != Some("eth2")
        || a2.root_port.as_deref() != Some("eth2")
    {
        bail!("wrong MSTI roots: {a1:?} {b1:?} {a2:?} {b2:?}");
    }
    if a1
        .ports
        .iter()
        .chain(&b2.ports)
        .any(|p| p.state != StpState::Forwarding)
    {
        bail!("the root of an instance forwards on every port: {a1:?} {b2:?}");
    }

    // The logs name the tree and domain, and the kernel state is per
    // domain-bridge port: MSTI 1's block is on VLAN 10 only.
    b.wait("msti port state changed port=eth1 msti=1 state=Discarding domains=mst-d1")
        .await?;
    a.wait("msti port state changed port=eth1 msti=2 state=Discarding domains=mst-d2")
        .await?;
    kernel_wait(b, "eth1.10", true, 30).await?;
    kernel_wait(b, "eth1.20", false, 30).await?;
    kernel_wait(b, "eth2.10", false, 30).await?;
    kernel_wait(a, "eth1.20", true, 30).await?;
    kernel_wait(a, "eth1.10", false, 30).await?;
    kernel_wait(a, "eth2.20", false, 30).await?;

    // The CIST still has one root (router-a) and a root port on router-b.
    let (sa, sb) = (stp_summary(a).await?, stp_summary(b).await?);
    if sa.root_id != sa.bridge_id || sa.root_id != sb.root_id || sb.root_port.is_none() {
        bail!("the CIST must be rooted at router-a: {sa:?} vs {sb:?}");
    }

    // A different revision splits the region: every MSTI port is a boundary
    // port following the CIST, which blocks router-b's second link for both
    // domains.
    log("revision 2 on router-b: boundary ports, one CIST");
    let boundary = routers.map(|r| r.count(BOUNDARY));
    mstp_provision(b, 2).await?;
    for (r, base) in routers.iter().zip(boundary) {
        r.wait_new(BOUNDARY, base, 40).await?;
    }
    // router-b hears router-a's BPDUs on both ports. router-a only learns of
    // the split where router-b still transmits: its alternate port is silent,
    // and since the revision edit is applied in place (#1123) no restart makes
    // it send, so only `eth1` is required there.
    for (r, only_eth1) in [(a, true), (b, false)] {
        for id in [1, 2] {
            mst_wait(r, id, 40, |i| {
                let mut ports = i.ports.iter().filter(|p| !only_eth1 || p.name == "eth1");
                ports.clone().count() > 0 && ports.all(|p| p.boundary)
            })
            .await?;
        }
    }
    kernel_wait(b, "eth1.10", false, 40).await?;
    kernel_wait(b, "eth1.20", false, 40).await?;
    kernel_wait(b, "eth2.10", true, 40).await?;
    kernel_wait(b, "eth2.20", true, 40).await?;
    kernel_wait(a, "eth1.20", false, 40).await?;

    // Restoring the revision rejoins the region and the per-tree blocking.
    log("revision 1 again: the region is back");
    let matched = routers.map(|r| r.count(MATCH));
    mstp_provision(b, 1).await?;
    for (r, base) in routers.iter().zip(matched) {
        r.wait_new(MATCH, base, 40).await?;
    }
    mst_wait(b, 1, 90, blocked("eth1")).await?;
    mst_wait(a, 2, 90, blocked("eth1")).await?;
    kernel_wait(b, "eth1.10", true, 30).await?;
    kernel_wait(a, "eth1.20", true, 30).await?;

    // #1123: edits of router-b's MSTP plan are applied in place, instance by
    // instance; its CIST ports and MSTI 1's states and designated ports stay.
    let view = |i: &nos_proto::StpInstance| -> Vec<(String, String, String)> {
        i.ports
            .iter()
            .map(|p| {
                (
                    p.name.clone(),
                    format!("{:?}", p.state),
                    p.designated_port.clone(),
                )
            })
            .collect()
    };
    let snapshot = || -> Vec<Option<String>> {
        ["eth1.10", "eth2.10", "eth1.20", "eth2.20"]
            .map(|l| kernel_port_state(b, l))
            .to_vec()
    };
    let cist = |s: &nos_proto::StpSummary| -> Vec<(String, String, String)> {
        s.ports
            .iter()
            .map(|p| {
                (
                    p.name.clone(),
                    format!("{:?}", p.state),
                    p.designated_port.clone(),
                )
            })
            .collect()
    };
    let snap = || async {
        anyhow::Ok((
            cist(&stp_summary(b).await?),
            view(&mst_wait(b, 1, 30, |i| !i.ports.is_empty()).await?),
            snapshot(),
        ))
    };
    // #1251: the snapshot must be steady, so wait for both routers' port
    // states to stop changing first.
    let (st, ms) = ("port state changed", "msti port state changed");
    for _ in 0..12 {
        let base = routers.map(|r| r.count(st) + r.count(ms));
        tokio::time::sleep(Duration::from_secs(5)).await;
        if routers
            .iter()
            .zip(base)
            .all(|(r, n)| r.count(st) + r.count(ms) == n)
        {
            break;
        }
    }
    let before = snap().await?;
    let rebuilt = b.count(REBUILT);

    log("router-b: MSTI 2 priority and MSTI 1 eth1 cost, applied in place");
    let in_place = b.count(IN_PLACE);
    let edits = [
        "--stp-mst-instance",
        "2:8192",
        "--stp-profile-mst-cost",
        "1:150000",
    ];
    mstp_provision_with(b, 1, &edits).await?;
    b.wait_new(IN_PLACE, in_place, 20).await?;
    // 8192 is `2000` in a bridge id.
    mst_wait(b, 2, 30, |i| i.bridge_id.starts_with("2000.")).await?;
    mst_wait(b, 1, 30, |i| {
        i.ports
            .iter()
            .any(|p| p.name == "eth1" && p.cost == 150_000)
    })
    .await?;

    log("router-b: a third instance, applied in place");
    let in_place = b.count(IN_PLACE);
    let mut with_3 = edits.to_vec();
    with_3.extend(["--stp-mst-instance", "3:8192"]);
    mstp_provision_with(b, 1, &with_3).await?;
    b.wait_new(IN_PLACE, in_place, 20).await?;
    let t3 = mst_wait(b, 3, 60, |i| {
        !i.ports.is_empty() && i.ports.iter().all(|p| p.state == StpState::Forwarding)
    })
    .await?;
    if t3.root_id != t3.bridge_id {
        bail!("router-b should root its own MSTI 3: {t3:?}");
    }

    log("router-b: the third instance removed again, applied in place");
    let in_place = b.count(IN_PLACE);
    let mut without_3 = edits.to_vec();
    without_3.extend(["--stp-delete-mst-instance", "3"]);
    mstp_provision_with(b, 1, &without_3).await?;
    b.wait_new(IN_PLACE, in_place, 20).await?;
    let ids: Vec<u16> = mst_config(b)
        .await?
        .instances
        .iter()
        .map(|i| i.id)
        .collect();
    if ids != [0, 1, 2] {
        bail!("router-b should be back to the CIST and MSTIs 1 and 2: {ids:?}");
    }

    b.assert_quiet(REBUILT, rebuilt, 5).await?;
    // The edits may re-elect for a moment: poll for the steady state to come
    // back (20s: two hello periods plus the 10s re-apply tick).
    let mut after = snap().await?;
    for _ in 0..20 {
        if before == after {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        after = snap().await?;
    }
    if before != after {
        let tail = b
            .logs
            .tail("bridge port state set\\|msti port state changed", 30)
            .join("\n");
        bail!("router-b's CIST or MSTI 1 moved: {before:?} -> {after:?}\n{tail}");
    }
    // Back to the base plan (also in place).
    mstp_provision(b, 1).await?;

    for r in routers {
        for iface in ["eth1", "eth2"] {
            r.provision(&["--link-interface", iface, "--delete-switching-profile"])
                .await?;
        }
    }
    for r in routers {
        r.provision(&[
            "--stp-profile-interface",
            "eth1",
            "--stp-profile-detach",
            "--stp-priority",
            "32768",
        ])
        .await?;
    }
    w.unlink_veths().await;
    a.established().await?;
    b.established().await
}

/// `GET /v1/spanning-tree/domain/<bd>`.
async fn pvst_domain(r: &Router, bd: &str) -> anyhow::Result<nos_proto::StpInstance> {
    let body = r
        .rest_expect(
            Method::GET,
            &format!("/v1/spanning-tree/domain/{bd}"),
            None,
            200,
        )
        .await?;
    Ok(serde_json::from_str(&body)?)
}

/// Polls domain `bd` on `r` until `want` holds twice in a row.
async fn pvst_wait(
    r: &Router,
    bd: &str,
    secs: u64,
    want: impl Fn(&nos_proto::StpInstance) -> bool,
) -> anyhow::Result<nos_proto::StpInstance> {
    let mut last = String::new();
    let mut stable = 0;
    for _ in 0..secs {
        if let Ok(i) = pvst_domain(r, bd).await {
            if want(&i) {
                stable += 1;
                if stable >= 2 {
                    return Ok(i);
                }
            } else {
                stable = 0;
            }
            last = format!("{i:?}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "{}: domain {bd} never settled as wanted in {secs}s: {last}",
        r.name()
    )
}

/// Provisions `iface` of `r` for `stp-pvst`: the trunk `profile` into
/// `pv-d1` (VLAN 110), `pv-d2` (VLAN 120) and the untagged `pv-nat`. With
/// `rapid` it also turns `rapid-pvst` on (an unset `--stp-mode` means
/// disabled): router-a roots `pv-d1`, router-b `pv-d2`, and the other
/// router's member of the tree it does not root is expensive on one link, so
/// `pv-d1` blocks router-b's `eth1` and `pv-d2` router-a's `eth2`.
async fn pvst_provision(r: &Router, iface: &str, profile: &str, rapid: bool) -> anyhow::Result<()> {
    let a = r.name() == "router-a";
    let mut args = strings(&[
        "--link-interface",
        iface,
        "--switching-profile",
        profile,
        "--switching-profile-member",
        "pv-d1:110",
        "--switching-profile-member",
        "pv-d2:120",
        "--switching-profile-member",
        "pv-nat:untagged",
    ]);
    let expensive = match (a, iface) {
        (false, "eth1") => Some("pv-d1"),
        (true, "eth2") => Some("pv-d2"),
        _ => None,
    };
    if let Some(bd) = expensive {
        args.extend(strings(&[
            "--stp-member-cost",
            &format!("{profile}:{bd}:100000"),
        ]));
    }
    if rapid {
        args.extend(strings(&[
            "--stp-mode",
            "rapid-pvst",
            "--stp-priority",
            "32768",
            "--stp-domain-priority",
            if a { "pv-d1:4096" } else { "pv-d1:32768" },
            "--stp-domain-priority",
            if a { "pv-d2:32768" } else { "pv-d2:4096" },
        ]));
    }
    r.provision(&args).await
}

/// #322: Rapid-PVST+ over the `stp` phase's two veth links, with two tagged
/// domains (`pv-d1` VLAN 110, `pv-d2` VLAN 120) and an untagged one (`pv-nat`,
/// the native VLAN) on both. Each domain is its own RSTP tree: router-a roots
/// `pv-d1` and router-b `pv-d2`, and the per-member `stp-cost` makes `pv-d1`
/// block router-b's `eth1` and `pv-d2` block router-a's `eth2`, each only on
/// its own `ethX.<tag>` bridge port in the kernel. The untagged tree converges
/// over the links themselves (SSTP plus the IEEE form). Cutting the root port
/// of `pv-d1` moves it to the blocked link.
pub async fn stp_pvst(w: &mut World) -> anyhow::Result<()> {
    const IN_PLACE: &str = "spanning tree plan updated in place";
    const REBUILT: &str = "spanning tree plan applied";
    let (a, b) = (w.a()?, w.b()?);
    let routers = [a, b];

    w.link_veths().await?;
    // A tagged trunk needs its parent up before `nos-interfaced` can bring the
    // `ethX.<tag>` sub-links up (it fails with ENETDOWN otherwise).
    for router in ["router-a", "router-b"] {
        for iface in ["eth1", "eth2"] {
            w.set_link(router, iface, true).await?;
        }
    }
    for r in routers {
        pvst_provision(r, "eth2", "pvst-sp2", false).await?;
        pvst_provision(r, "eth1", "pvst-sp1", true).await?;
    }

    log("waiting for pv-d1 to block router-b eth1 and pv-d2 router-a eth2");
    let blocked = |name: &'static str| {
        move |i: &nos_proto::StpInstance| {
            i.ports.iter().any(|p| {
                p.name == name && p.role == StpRole::Alternate && p.state == StpState::Discarding
            }) && i
                .ports
                .iter()
                .any(|p| p.name != name && p.state == StpState::Forwarding)
        }
    };
    let b1 = pvst_wait(b, "pv-d1", 90, blocked("eth1")).await?;
    let a2 = pvst_wait(a, "pv-d2", 90, blocked("eth2")).await?;
    let a1 = pvst_wait(a, "pv-d1", 30, |i| i.root_port.is_none()).await?;
    let b2 = pvst_wait(b, "pv-d2", 30, |i| i.root_port.is_none()).await?;
    // The VLAN rides in the bridge id: priority 4096 + VLAN 110 is 0x106e.
    if a1.root_id != a1.bridge_id
        || !a1.bridge_id.starts_with("106e.")
        || b2.root_id != b2.bridge_id
        || !b2.bridge_id.starts_with("1078.")
        || b1.root_id != a1.bridge_id
        || a2.root_id != b2.bridge_id
        || b1.root_port.as_deref() != Some("eth2")
        || a2.root_port.as_deref() != Some("eth1")
    {
        bail!("wrong per-VLAN roots: {a1:?} {b1:?} {a2:?} {b2:?}");
    }
    if a1
        .ports
        .iter()
        .chain(&b2.ports)
        .any(|p| p.state != StpState::Forwarding)
    {
        bail!("the root of a tree forwards on every port: {a1:?} {b2:?}");
    }
    if [&a1, &b1, &a2, &b2]
        .iter()
        .flat_map(|i| &i.ports)
        .any(|p| p.inconsistent || p.compat)
    {
        bail!("two NOS bridges must not see PVID inconsistency or PVST+ peers");
    }

    // The logs name the tree, and the kernel state is per domain bridge port:
    // pv-d1's block is on VLAN 110 only.
    b.wait("pvst port role changed domain=pv-d1 port=eth1 role=Alternate")
        .await?;
    a.wait("pvst port role changed domain=pv-d2 port=eth2 role=Alternate")
        .await?;
    b.wait("pvst root bridge changed domain=pv-d1 root=106e")
        .await?;
    kernel_wait(b, "eth1.110", true, 30).await?;
    kernel_wait(b, "eth1.120", false, 30).await?;
    kernel_wait(b, "eth2.110", false, 30).await?;
    kernel_wait(a, "eth2.120", true, 30).await?;
    kernel_wait(a, "eth2.110", false, 30).await?;
    kernel_wait(a, "eth1.120", false, 30).await?;

    // The native VLAN: one tree over the links themselves, one root, one block.
    log("waiting for the untagged pv-nat tree to converge");
    let both = |i: &nos_proto::StpInstance| {
        i.ports.len() == 2 && i.ports.iter().all(|p| p.role != StpRole::Disabled)
    };
    let (na, nb) = (
        pvst_wait(a, "pv-nat", 90, both).await?,
        pvst_wait(b, "pv-nat", 90, both).await?,
    );
    let discarding = na
        .ports
        .iter()
        .chain(&nb.ports)
        .filter(|p| p.role == StpRole::Alternate && p.state == StpState::Discarding)
        .count();
    if na.root_id != nb.root_id || !na.root_id.starts_with("8001.") || discarding != 1 {
        bail!(
            "pv-nat must have one root (8001. = priority 32768, VLAN 1) and one block: {na:?} {nb:?}"
        );
    }

    let (sa, sb) = (stp_summary(a).await?, stp_summary(b).await?);
    if sa.mode != nos_proto::StpMode::RapidPvst || sa.pvst.len() != 3 || sb.pvst.len() != 3 {
        bail!("GET /v1/spanning-tree should list three trees: {sa:?} {sb:?}");
    }

    // Cut router-b's pv-d1 root port: eth1 (blocked in pv-d1) takes over.
    log("cutting router-b eth2: pv-d1 must move to eth1");
    w.unlink_veth("eth2").await;
    pvst_wait(b, "pv-d1", 30, |i| {
        i.root_port.as_deref() == Some("eth1")
            && i.ports
                .iter()
                .any(|p| p.name == "eth1" && p.state == StpState::Forwarding)
    })
    .await?;
    w.ensure_veth("eth2").await?;
    pvst_wait(b, "pv-d1", 90, blocked("eth1")).await?;
    pvst_wait(a, "pv-d2", 90, blocked("eth2")).await?;

    // #1122: edits of router-a's plan are applied in place, tree by tree, and
    // router-b's untouched trees (pv-d2, pv-nat) do not move.
    let view = |i: &nos_proto::StpInstance| -> Vec<(String, String, String)> {
        i.ports
            .iter()
            .map(|p| {
                (
                    p.name.clone(),
                    format!("{:?}", p.state),
                    p.designated_port.clone(),
                )
            })
            .collect()
    };
    let before = [
        view(&pvst_domain(b, "pv-d2").await?),
        view(&pvst_domain(b, "pv-nat").await?),
    ];
    let rebuilt = a.count(REBUILT);
    // The base provision of `pvst_provision`, plus the edit; `eth1` carries
    // the rapid settings, `eth2` only the members.
    let edit = |iface: &str, profile: &str, extra: &[&str]| {
        let mut args = strings(&[
            "--link-interface",
            iface,
            "--switching-profile",
            profile,
            "--switching-profile-member",
            "pv-d1:110",
            "--switching-profile-member",
            "pv-d2:120",
            "--switching-profile-member",
            "pv-nat:untagged",
        ]);
        args.extend(strings(extra));
        args
    };
    let rapid = [
        "--stp-mode",
        "rapid-pvst",
        "--stp-priority",
        "32768",
        "--stp-domain-priority",
        "pv-d2:32768",
        "--stp-domain-priority",
        "pv-d1:8192",
    ];

    log("router-a: pv-d1 priority and member cost edit, applied in place");
    let in_place = a.count(IN_PLACE);
    let mut extra = vec!["--stp-member-cost", "pvst-sp1:pv-d1:200"];
    extra.extend(rapid);
    a.provision(&edit("eth1", "pvst-sp1", &extra)).await?;
    a.wait_new(IN_PLACE, in_place, 20).await?;
    pvst_wait(a, "pv-d1", 30, |i| i.bridge_id.starts_with("206e.")).await?;

    log("router-a: third tagged domain pv-x on eth2, applied in place");
    let in_place = a.count(IN_PLACE);
    let mut extra = vec!["--switching-profile-member", "pv-x:130"];
    extra.extend(["--stp-domain-priority", "pv-x:4096"]);
    extra.extend(rapid);
    let with_x = edit("eth2", "pvst-sp2", &extra);
    a.provision(&with_x).await?;
    a.wait_new(IN_PLACE, in_place, 20).await?;
    pvst_wait(a, "pv-x", 30, |i| i.ports.len() == 1).await?;
    if stp_summary(a).await?.pvst.len() != 4 {
        bail!("router-a should list four trees with pv-x");
    }

    log("router-a: pv-x removed again (eth2 moves to a profile without it)");
    let in_place = a.count(IN_PLACE);
    // (the new profile repeats the expensive pv-d2 member of `pvst-sp2`)
    let mut extra = vec!["--stp-member-cost", "pvst-sp3:pv-d2:100000"];
    extra.extend(rapid);
    let sp3 = edit("eth2", "pvst-sp3", &extra);
    a.provision(&sp3).await?;
    a.wait_new(IN_PLACE, in_place, 20).await?;
    if stp_summary(a).await?.pvst.len() != 3 {
        bail!("router-a should be back to three trees");
    }

    a.assert_quiet(REBUILT, rebuilt, 5).await?;
    let after = [
        view(&pvst_domain(b, "pv-d2").await?),
        view(&pvst_domain(b, "pv-nat").await?),
    ];
    if before != after {
        bail!("router-b's pv-d2/pv-nat moved: {before:?} -> {after:?}");
    }
    kernel_wait(a, "eth2.120", true, 30).await?;

    for r in routers {
        for iface in ["eth1", "eth2"] {
            r.provision(&["--link-interface", iface, "--delete-switching-profile"])
                .await?;
        }
    }
    w.unlink_veths().await;
    a.established().await?;
    b.established().await
}

pub async fn svi(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.provision(&[
        "--routing-table",
        "rt1",
        "--broadcast-domain",
        "bd-svi",
        "--broadcast-domain-svi-address",
        SVI_ADDRESS,
    ])
    .await?;
    // bd-svi's bridge id depends on how many domains this container allocated
    // before, so its name is read from the line the driver just emitted.
    let created = "created broadcast domain bridge domain=bd-svi bridge=br[0-9]*";
    a.wait(created).await?;
    let line = a.logs.last(created).unwrap_or_default();
    let Some(bridge) = regex::Regex::new(r"domain=bd-svi bridge=(br[0-9]+)")?
        .captures(&line)
        .map(|c| c[1].to_string())
    else {
        bail!("no bridge name in: {line}");
    };
    log(format!("router-a: created {bridge} for bd-svi"));
    a.wait(&format!("enslaved interface to vrf interface={bridge}"))
        .await?;
    a.wait(&format!(
        "added interface address interface={bridge} address={SVI_ADDRESS}"
    ))
    .await?;

    a.provision(&[
        "--broadcast-domain",
        "bd-svi",
        "--delete-broadcast-domain-svi",
    ])
    .await?;
    a.wait(&format!(
        "deleted broadcast domain bridge domain=bd-svi bridge={bridge}"
    ))
    .await
}

pub async fn routed_subinterface(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let tag = SUBINTERFACE_TAG;
    let sub = |extra: &[&str]| {
        let mut f = strings(&[
            "--address",
            SUBINTERFACE_ADDRESS,
            "--subinterface-tag",
            &tag.to_string(),
        ]);
        f.extend(strings(&[
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--remote-as",
            &ASN_B.to_string(),
            "--peer",
            IP_B.s(),
        ]));
        f.extend(strings(extra));
        f
    };
    a.provision_flags(&sub(&["--routing-table", "rt1"])).await?;
    a.wait(&format!(
        "created vlan sub-interface interface=eth0 sub_interface=eth0.{tag} tag={tag}"
    ))
    .await?;
    // The same VRF eth0 itself is already a member of — a VRF has many members.
    a.wait(&format!("enslaved interface to vrf interface=eth0.{tag}"))
        .await?;
    a.wait(&format!(
        "added interface address interface=eth0.{tag} address={SUBINTERFACE_ADDRESS}"
    ))
    .await?;

    a.provision_flags(&sub(&["--delete-subinterface"])).await?;
    a.wait(&format!(
        "deleted vlan sub-interface interface=eth0 sub_interface=eth0.{tag}"
    ))
    .await
}

/// `source-address` is resolved by nos-bgpd itself over a real IPC round trip to
/// nos-interfaced, including `loopback` derived from its own routing table.
pub async fn source_address(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    a.provision(&["--source-address-interface", "eth0"]).await?;
    a.wait(&format!(
        "resolved peer-group source-address peer_group=pg1 addresses=\\[{IP_A}\\]"
    ))
    .await?;
    a.established().await?;
    b.established().await?;

    a.provision(&["--loopback-address", LOOPBACK_ADDRESS])
        .await?;
    a.wait(&format!(
        "added interface address interface=loopback-rt1 address={LOOPBACK_ADDRESS}"
    ))
    .await?;

    a.provision(&["--source-address-loopback"]).await?;
    let loopback_ip = LOOPBACK_ADDRESS
        .split('/')
        .next()
        .unwrap_or(LOOPBACK_ADDRESS);
    a.wait(&format!(
        "resolved peer-group source-address peer_group=pg1 addresses=\\[{loopback_ip}\\]"
    ))
    .await?;

    a.provision(&["--clear-source-address"]).await?;
    a.provision(&["--delete-loopback"]).await?;
    a.established().await
}

/// Polls `container`'s docker logs for `needle` — only for the checks below,
/// where REST (and so its log stream) is exactly what is being killed.
async fn wait_docker_log(
    w: &World,
    container: &str,
    needle: &str,
    secs: u64,
) -> anyhow::Result<()> {
    for _ in 0..secs {
        if w.dock.logs(container).await?.contains(needle) {
            log(format!("{container}: saw '{needle}'"));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("{container}: no '{needle}' in its logs within {secs}s")
}

pub async fn rest(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let tx = format!("/v1/transactions/{REST_TX}");

    // Every router in this harness is booted with its REST API pinned, so the
    // pin's own effects are already in the log.
    a.wait("spawning nos-restd for new REST API").await?;
    a.wait(&format!(
        "rest api listening table=rt1 .* address={IP_A} port={REST_PORT}"
    ))
    .await?;

    // Authentication is mutual TLS: every route refuses a client with no
    // certificate, and the one way to get a certificate — `POST /v1/login` —
    // refuses a wrong password and an unknown user alike.
    let anonymous = a.rest.anonymous()?;
    for path in ["/v1/config", "/openapi.json", "/swagger-ui/"] {
        let (status, body) = a.rest_with(&anonymous, Method::GET, path, None).await?;
        if status != 401 {
            bail!("router-a: GET {path} without a certificate -> {status}, want 401");
        }
        // Errors are RFC 9457 problem documents, whose status repeats the HTTP one.
        let problem: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
            anyhow::anyhow!("router-a: GET {path} 401 body is not JSON ({e}): {body}")
        })?;
        if problem["status"] != 401
            || problem["type"] != "about:blank"
            || problem["title"] != "Unauthorized"
        {
            bail!("router-a: GET {path} 401 body is not a problem document: {body}");
        }
    }
    // The same over an authenticated request: an unknown transaction is a 404
    // problem document, not a bare status.
    let (status, body) = a
        .rest(Method::GET, "/v1/transactions/no-such-tx", None)
        .await?;
    if status != 404 || !body.contains(r#""status":404"#) {
        bail!("router-a: GET of an unknown transaction -> {status} {body}, want a 404 problem");
    }
    for (user, password) in [(E2E_USER, "wrong-password"), ("nobody", E2E_PASSWORD)] {
        match a.rest.login(user, password).await? {
            Err(401) => {}
            Err(status) => bail!("router-a: login as {user} -> {status}, want 401"),
            Ok(_) => bail!("router-a: login as {user} with '{password}' was accepted"),
        }
    }
    log("router-a: REST refuses no certificate, a wrong password and an unknown user with 401");
    rest_transport(a).await?;

    // Show endpoints, answered by other daemons (config, rib, bgp, interface).
    let config = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
    let config: serde_json::Value = serde_json::from_str(&config)?;
    let Some(orig_hostname) = config["hostname"].as_str().map(str::to_string) else {
        bail!("no hostname in /v1/config");
    };
    a.rest_expect(Method::GET, "/v1/routes/rt1", None, 200)
        .await?;
    expect_body(
        &a.rest_expect(Method::GET, "/v1/interfaces", None, 200)
            .await?,
        "\"eth0\"",
    )?;
    expect_body(
        &a.rest_expect(Method::GET, "/v1/bgp/summary", None, 200)
            .await?,
        "\"instance\":\"r1\"",
    )?;
    // #759: router-wide show routes list instance names with the cheap
    // `List*Instances` probes; the OSPF families have no instance here, so
    // they answer 200 with an empty report.
    for route in [
        "/v1/bgp/rpki",
        "/v1/ospf/neighbors",
        "/v1/ospf/interfaces",
        "/v1/ospf/database",
        "/v1/ospf/segment-routing",
        "/v1/ospf/routes",
        "/v1/ospfv3/neighbors",
        "/v1/ospfv3/interfaces",
        "/v1/ospfv3/database",
        "/v1/ospfv3/routes",
    ] {
        a.rest_expect(Method::GET, route, None, 200).await?;
    }
    a.rest_expect(Method::GET, "/v1/routes/nonexistent-table", None, 503)
        .await?;
    expect_body(
        &a.rest_expect(
            Method::GET,
            "/v1/logs?source=nos-configd&limit=3",
            None,
            200,
        )
        .await?,
        "\"source\":\"nos-configd\"",
    )?;

    // `clear bgp r1 <peer> soft-in` as a POST: the Established session to
    // router-b really gets a ROUTE-REFRESH, and a peer with no session is a 404.
    let refresh = format!("bgp: sent route refresh request to peer peer={IP_B}");
    let refresh_base = a.count(&refresh);
    // RFC 7313: both nos speakers negotiate Enhanced Route Refresh, so the
    // resend comes back bracketed by BoRR/EoRR.
    let borr = format!("bgp: received BoRR peer={IP_B}");
    let eorr = format!("bgp: received EoRR peer={IP_B}");
    let (borr_base, eorr_base) = (a.count(&borr), a.count(&eorr));
    expect_body(
        &a.rest_expect(
            Method::POST,
            &format!("/v1/bgp/r1/peer/{IP_B}/soft-in"),
            None,
            200,
        )
        .await?,
        "\"route_refresh\":\"sent\"",
    )?;
    a.wait_new(&refresh, refresh_base, 30).await?;
    a.wait_new(&borr, borr_base, 30).await?;
    a.wait_new(&eorr, eorr_base, 30).await?;
    a.rest_expect(
        Method::POST,
        &format!("/v1/bgp/r1/peer/{REDISTRIBUTE_GATEWAY}/soft-in"),
        None,
        404,
    )
    .await?;

    // A transaction driven purely through the config-tree URLs.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    expect_body(
        &a.rest_expect(
            Method::PUT,
            &format!("{tx}/hostname"),
            Some("\"rest-host\""),
            200,
        )
        .await?,
        "\"rest-host\"",
    )?;
    expect_body(
        &a.rest_expect(
            Method::PUT,
            &format!("{tx}/prefix-list/rest-pl"),
            Some(r#"{"name":"rest-pl","entries":[{"cidr":"10.0.0.0/8","range":null}]}"#),
            200,
        )
        .await?,
        "\"rest-pl\"",
    )?;
    // A key containing '/' travels as one percent-encoded segment.
    expect_body(
        &a.rest_expect(
            Method::GET,
            &format!("{tx}/prefix-list/rest-pl/entry/10.0.0.0%2F8"),
            None,
            200,
        )
        .await?,
        "\"10.0.0.0/8\"",
    )?;
    // PATCH (#1151): RFC 7396 merge-patch. The array is replaced, the sibling
    // `name` is untouched, and a stale If-Match is a 412 that changes nothing.
    let pl = format!("{tx}/prefix-list/rest-pl");
    let (_, _, snap) = a
        .rest_full(&a.rest.client().await?, Method::GET, &tx, None, None)
        .await?;
    let snap: serde_json::Value = serde_json::from_str(&snap)?;
    let stale = format!("\"{}\"", snap["generation"].as_u64().unwrap_or(0) + 100);
    let (status, ..) = a
        .rest_full(
            &a.rest.client().await?,
            Method::PATCH,
            &pl,
            Some(r#"{"entries":[]}"#),
            Some(("if-match", &stale)),
        )
        .await?;
    if status != 412 {
        bail!("router-a: PATCH with a stale If-Match -> {status}, want 412");
    }
    let patched = a
        .rest_expect(
            Method::PATCH,
            &pl,
            Some(
                r#"{"entries":[{"cidr":"10.0.0.0/8","range":null},{"cidr":"172.16.0.0/12","range":null}]}"#,
            ),
            200,
        )
        .await?;
    if !patched.contains("172.16.0.0/12") || !patched.contains("\"name\":\"rest-pl\"") {
        bail!("router-a: PATCH reply lost the merge: {patched}");
    }
    a.wait(&format!("rest request user=\"{E2E_USER}\" method=PATCH"))
        .await?;
    a.rest_expect(
        Method::PUT,
        &format!("{tx}/hostname"),
        Some(r#"{"bad":true}"#),
        400,
    )
    .await?;
    a.rest_expect(Method::GET, &format!("{tx}/diff"), None, 200)
        .await?;
    // Nothing is running yet.
    if a.rest_expect(Method::GET, "/v1/config", None, 200)
        .await?
        .contains("rest-pl")
    {
        bail!("uncommitted transaction leaked into the running config");
    }
    expect_body(
        &a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
            .await?,
        &format!("\"committed\":\"{REST_TX}\",\"unsaved\":true"),
    )?;
    // A commit is live but unsaved (#1139); a save clears it.
    expect_body(
        &a.rest_expect(Method::GET, "/v1/config/status", None, 200)
            .await?,
        "\"unsaved\":true",
    )?;
    let running = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
    if !running.contains("\"rest-pl\"")
        || !running.contains("172.16.0.0/12")
        || !running.contains("\"hostname\":\"rest-host\"")
    {
        bail!("committed transaction is not in the running config");
    }
    // The audit trail names the REST user, not just `restd`: configd's commit
    // line and restd's request line both carry it (#400).
    a.wait(&format!(
        "config commit audit transaction=\"{REST_TX}\" actor=\"{E2E_USER}\""
    ))
    .await?;
    a.wait(&format!("rest request user=\"{E2E_USER}\" method=POST"))
        .await?;
    // Persisted only once saved: the real nos-configd writes its real
    // --config-file. Any later phase that restarts nos-configd boots from this
    // file (with the undo below still unsaved) rather than from the seed.
    let saved_path = "/var/lib/nos/configd/config.yaml";
    a.rest_expect(Method::POST, "/v1/config/save", None, 204)
        .await?;
    match w.dock.exec_root("router-a", &["cat", saved_path]).await? {
        (0, saved) if saved.contains("rest-pl") && saved.contains("rest-host") => {}
        (code, saved) => bail!("router-a: {saved_path} after save (exit {code}):\n{saved}"),
    }
    expect_body(
        &a.rest_expect(Method::GET, "/v1/config/status", None, 200)
            .await?,
        "\"unsaved\":false",
    )?;
    log("router-a: POST /v1/config/save wrote the running config to disk");

    // Undo it the same way, exercising DELETE on a subsection and on the tx.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(
        Method::DELETE,
        &format!("{tx}/prefix-list/rest-pl"),
        None,
        204,
    )
    .await?;
    a.rest_expect(
        Method::PUT,
        &format!("{tx}/hostname"),
        Some(&format!("\"{orig_hostname}\"")),
        200,
    )
    .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    if a.rest_expect(Method::GET, "/v1/config", None, 200)
        .await?
        .contains("rest-pl")
    {
        bail!("rest-pl still present after DELETE + commit");
    }
    // Commit history (#1141): `rollback 1` re-applies the config the undo
    // replaced, as a normal commit; rolling back again undoes that.
    expect_body(
        &a.rest_expect(Method::GET, "/v1/history", None, 200).await?,
        "\"index\":1",
    )?;
    // #1458: the config `n` commits back, before the rollback moves it.
    let running_now = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
    let old = a
        .rest_expect(Method::GET, "/v1/history/1", None, 200)
        .await?;
    if !old.contains("\"rest-pl\"") || running_now.contains("rest-pl") {
        bail!("GET /v1/history/1 is not the config the undo replaced: {old}");
    }
    let zero = a
        .rest_expect(Method::GET, "/v1/history/0", None, 200)
        .await?;
    if zero != running_now {
        bail!("GET /v1/history/0 differs from GET /v1/config:\n{zero}\n{running_now}");
    }
    a.rest_expect(Method::GET, "/v1/history/999", None, 404)
        .await?;
    let audit = "config rollback audit index=1";
    let before = a.count(audit);
    expect_body(
        &a.rest_expect(Method::POST, "/v1/rollback/1", None, 200)
            .await?,
        "\"committed\":\"rollback 1\"",
    )?;
    a.wait_new(audit, before, 30).await?;
    let running = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
    if !running.contains("\"rest-pl\"") || !running.contains("\"hostname\":\"rest-host\"") {
        bail!("rollback 1 did not re-apply the rest-pl config: {running}");
    }
    expect_body(
        &a.rest_expect(Method::GET, "/v1/history", None, 200).await?,
        "\"kind\":\"rollback\"",
    )?;
    a.rest_expect(Method::POST, "/v1/rollback/0", None, 200)
        .await?;
    a.rest_expect(Method::POST, "/v1/rollback/99", None, 404)
        .await?;
    a.rest_expect(Method::POST, "/v1/rollback/1", None, 200)
        .await?;
    if a.rest_expect(Method::GET, "/v1/config", None, 200)
        .await?
        .contains("rest-pl")
    {
        bail!("the second rollback 1 did not undo the first");
    }
    log("router-a: GET /v1/history, GET /v1/history/N and POST /v1/rollback/N re-apply and undo a commit");
    // Confirmed commit (#1144): unconfirmed it rolls back on its own, a
    // second one is refused (409), a confirmed one stays. 30s is the minimum.
    for (host, confirm) in [("expire-host", false), ("keep-host", true)] {
        a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
            .await?;
        a.rest_expect(
            Method::PUT,
            &format!("{tx}/hostname"),
            Some(&format!("\"{host}\"")),
            200,
        )
        .await?;
        a.rest_expect(
            Method::POST,
            &format!("{tx}/commit?confirm-timeout=30"),
            None,
            200,
        )
        .await?;
        let running = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
        if !running.contains(host) {
            bail!("{host}: confirmed commit not applied: {running}");
        }
        a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
            .await?;
        a.rest_expect(
            Method::POST,
            &format!("{tx}/commit?confirm-timeout=30"),
            None,
            409,
        )
        .await?;
        a.rest_expect(Method::DELETE, &tx, None, 204).await?;
        if confirm {
            a.rest_expect(Method::POST, "/v1/commit/confirm", None, 200)
                .await?;
            a.rest_expect(Method::POST, "/v1/commit/confirm", None, 409)
                .await?;
            tokio::time::sleep(std::time::Duration::from_secs(35)).await;
            let running = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
            if !running.contains(host) {
                bail!("a confirmed commit was rolled back anyway: {running}");
            }
        } else {
            a.wait("confirmed commit not confirmed in time, rolling back")
                .await?;
            let mut back = false;
            for _ in 0..40 {
                let running = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
                if !running.contains(host) {
                    back = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            if !back {
                bail!("the unconfirmed commit was not rolled back");
            }
            expect_body(
                &a.rest_expect(Method::GET, "/v1/history", None, 200).await?,
                "\"kind\":\"auto-rollback\"",
            )?;
        }
    }
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(
        Method::PUT,
        &format!("{tx}/hostname"),
        Some(&format!("\"{orig_hostname}\"")),
        200,
    )
    .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    log("router-a: commit?confirm-timeout rolls back unconfirmed, 409 on a second, /v1/commit/confirm keeps");
    a.rest_expect(Method::POST, &format!("{tx}?base=blank"), None, 201)
        .await?;
    a.rest_expect(Method::DELETE, &tx, None, 204).await?;
    a.rest_expect(Method::GET, &tx, None, 404).await?;
    rest_etag(a).await?;

    expect_body(
        &a.rest_expect(Method::GET, "/openapi.json", None, 200)
            .await?,
        "/v1/transactions/{tx}/bgp-instance/{bgp_instance}/peer-group/{peer_group}",
    )?;
    expect_body(
        &a.rest_expect(Method::GET, "/swagger-ui/", None, 200)
            .await?,
        "Swagger UI",
    )?;

    // `show log --follow`: an SSE stream carrying a *live* entry, not just the
    // backlog. Follow nos-configd, then commit an empty transaction so it logs
    // "config committed" while the stream is open.
    let follow = |query: &str| {
        let url = format!("{}/v1/logs/follow?{query}", a.rest.base());
        let client = a.rest.client();
        async move {
            let client = client.await?;
            anyhow::Ok(tokio::spawn(async move {
                let mut text = String::new();
                let Ok(resp) = client.get(&url).send().await else {
                    return text;
                };
                let mut chunks = futures::StreamExt::boxed(resp.bytes_stream());
                let _ = tokio::time::timeout(Duration::from_secs(6), async {
                    while let Some(Ok(chunk)) = futures::StreamExt::next(&mut chunks).await {
                        text.push_str(&String::from_utf8_lossy(&chunk));
                    }
                })
                .await;
                text
            }))
        }
    };
    let stream = follow("source=nos-configd&limit=1").await?;
    // #1451: the same stream restricted to warn and above must not carry the
    // info-level "config committed".
    let filtered = follow("source=nos-configd&level=warn&limit=1").await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    let streamed = stream.await?;
    if !streamed.contains("event: log") || !streamed.contains("config committed") {
        bail!("the log follow stream carried no live 'config committed' entry:\n{streamed}");
    }
    let filtered = filtered.await?;
    if filtered.contains("config committed")
        || filtered.contains("\"level\":\"info\"")
        || filtered.contains("\"level\":\"debug\"")
    {
        bail!("level=warn follow stream carried a below-warn entry:\n{filtered}");
    }
    log("router-a: log follow streamed a live entry over sse, level=warn filtered it");

    // #1451: `level`/`match` on the snapshot. The commit above logged
    // "config committed" (info), so it is in the buffer by now.
    let levels = |body: &str| -> anyhow::Result<Vec<String>> {
        let v: serde_json::Value = serde_json::from_str(body)?;
        Ok(v.as_array().map_or_else(Vec::new, |a| {
            a.iter().map(|e| e["level"].to_string()).collect()
        }))
    };
    let errors = a
        .rest_expect(
            Method::GET,
            "/v1/logs?source=nos-configd&level=error&limit=100000000",
            None,
            200,
        )
        .await?;
    if let Some(l) = levels(&errors)?.iter().find(|l| *l != "\"error\"") {
        bail!("level=error returned a {l} entry:\n{errors}");
    }
    let hit = a
        .rest_expect(
            Method::GET,
            "/v1/logs?source=nos-configd&match=CONFIG%20COMMITTED&limit=100000000",
            None,
            200,
        )
        .await?;
    let n = levels(&hit)?.len();
    if n == 0 || hit.to_lowercase().matches("config committed").count() < n {
        bail!("match=CONFIG COMMITTED: {n} entries, not all containing it:\n{hit}");
    }
    expect_body(
        &a.rest_expect(
            Method::GET,
            "/v1/logs?source=nos-configd&match=zzz-no-such",
            None,
            200,
        )
        .await?,
        "[]",
    )?;
    a.rest_expect(Method::GET, "/v1/logs?level=bogus", None, 400)
        .await?;
    log("router-a: /v1/logs level and match filters");

    rest_users(&w.dock, a).await?;
    rest_secrets(&w.dock, a).await?;
    rest_destructive(w).await
}

/// RFC 9110 §8.8/§13.1 on the transaction endpoints, against the real daemon:
/// a strong `ETag` on every reply, a stale `If-Match` refused with 412 and
/// nothing changed, the current one (alone or in a list) accepted,
/// `If-None-Match` → 304 (lists, weak tags), `If-Match` on GET and on a missing transaction → 412.
async fn rest_etag(a: &Router) -> anyhow::Result<()> {
    let tx = format!("/v1/transactions/{REST_TX}");
    let host = format!("{tx}/hostname");
    let quoted = |etag: &Option<String>| -> anyhow::Result<String> {
        let Some(e) = etag else {
            bail!("router-a: reply carried no ETag")
        };
        let digits = e.strip_prefix('"').and_then(|s| s.strip_suffix('"'));
        if digits.is_none_or(|d| d.is_empty() || !d.bytes().all(|b| b.is_ascii_digit())) {
            bail!("router-a: ETag {e} is not a quoted decimal");
        }
        Ok(e.clone())
    };
    let orig = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
    let orig: serde_json::Value = serde_json::from_str(&orig)?;
    let orig_hostname = orig["hostname"].as_str().unwrap_or_default().to_string();

    let (etag, _) = a
        .rest_expect_full(Method::POST, &format!("{tx}?base=current"), None, None, 201)
        .await?;
    let opened = quoted(&etag)?;
    let (etag, _) = a
        .rest_expect_full(Method::GET, &tx, None, None, 200)
        .await?;
    if quoted(&etag)? != opened {
        bail!("router-a: GET ETag {etag:?} differs from the opened one {opened}");
    }

    // Stale If-Match: 412 problem document, the value untouched.
    let stale = "\"999999\"";
    let (_, body) = a
        .rest_expect_full(
            Method::PUT,
            &host,
            Some("\"etag-host\""),
            Some(("if-match", stale)),
            412,
        )
        .await?;
    expect_body(&body, "\"status\":412")?;
    let (_, body) = a
        .rest_expect_full(Method::GET, &host, None, None, 200)
        .await?;
    if body != format!("\"{orig_hostname}\"") {
        bail!("router-a: hostname changed by a refused PUT: {body}");
    }
    // The current one (in a list): accepted, and the reply's tag moves on.
    let (etag, _) = a
        .rest_expect_full(
            Method::PUT,
            &host,
            Some("\"etag-host\""),
            Some(("if-match", &format!("{stale}, {opened}"))),
            200,
        )
        .await?;
    let after_put = quoted(&etag)?;
    if after_put == opened {
        bail!("router-a: ETag did not change after a PUT ({opened})");
    }

    // A subsection DELETE: stale → 412, current → 204 with the new tag.
    a.rest_expect_full(
        Method::PUT,
        &format!("{tx}/prefix-list/etag-pl"),
        Some(r#"{"name":"etag-pl","entries":[]}"#),
        Some(("if-match", &after_put)),
        200,
    )
    .await?;
    a.rest_expect_full(
        Method::DELETE,
        &format!("{tx}/prefix-list/etag-pl"),
        None,
        Some(("if-match", &after_put)),
        412,
    )
    .await?;
    let (etag, _) = a
        .rest_expect_full(
            Method::DELETE,
            &format!("{tx}/prefix-list/etag-pl"),
            None,
            Some(("if-match", "*")),
            204,
        )
        .await?;
    let current = quoted(&etag)?;

    // If-None-Match: current → 304 with no body; stale → 200 with the value.
    let (etag, body) = a
        .rest_expect_full(
            Method::GET,
            &tx,
            None,
            Some(("if-none-match", &current)),
            304,
        )
        .await?;
    if quoted(&etag)? != current || !body.is_empty() {
        bail!("router-a: 304 carried ETag {etag:?} and body {body:?}");
    }
    let (_, body) = a
        .rest_expect_full(
            Method::GET,
            &host,
            None,
            Some(("if-none-match", &opened)),
            200,
        )
        .await?;
    expect_body(&body, "\"etag-host\"")?;
    // Lists and weak tags (weak comparison) on If-None-Match.
    a.rest_expect_full(
        Method::GET,
        &tx,
        None,
        Some(("if-none-match", &format!("{stale}, W/{current}"))),
        304,
    )
    .await?;
    // If-Match on GET is strong and wins over If-None-Match; a weak tag never matches.
    for m in [stale.to_string(), format!("W/{current}")] {
        a.rest_expect_full(Method::GET, &tx, None, Some(("if-match", &m)), 412)
            .await?;
    }
    // Any If-Match on a missing transaction is 412 (no current representation).
    a.rest_expect_full(
        Method::PUT,
        "/v1/transactions/etag-absent/hostname",
        Some("\"x\""),
        Some(("if-match", "*")),
        412,
    )
    .await?;
    a.rest_expect_full(
        Method::PUT,
        "/v1/transactions/etag-absent/hostname",
        Some("\"x\""),
        None,
        404,
    )
    .await?;

    // Commit: stale → 412 and the transaction stays open; current → 200.
    a.rest_expect_full(
        Method::POST,
        &format!("{tx}/commit"),
        None,
        Some(("if-match", stale)),
        412,
    )
    .await?;
    a.rest_expect(Method::GET, &tx, None, 200).await?;
    a.rest_expect_full(
        Method::POST,
        &format!("{tx}/commit"),
        None,
        Some(("if-match", &current)),
        200,
    )
    .await?;
    expect_body(
        &a.rest_expect(Method::GET, "/v1/config", None, 200).await?,
        "\"hostname\":\"etag-host\"",
    )?;
    log("router-a: transaction ETag/If-Match (412) and If-None-Match (304) verified");

    // Put the hostname back the way the other phases expect it.
    a.edit(|c| {
        c.hostname = orig_hostname;
        Ok(())
    })
    .await
    .map(drop)
}

/// The transport itself: post-quantum key exchange is mandatory, and requests
/// share connections instead of paying a handshake each — HTTP/2 multiplexing
/// on the client side, pooled IPC connections behind it.
async fn rest_transport(a: &Router) -> anyhow::Result<()> {
    // A client offering only classical X25519 is refused at the handshake.
    let failed = a.count("rest tls handshake failed");
    if classical_handshake(a).await.is_ok() {
        bail!(
            "router-a: the REST listener completed a handshake without post-quantum key exchange"
        );
    }
    a.wait_new("rest tls handshake failed", failed, 15).await?;
    log("router-a: REST refuses a classical-only key exchange");

    // One connection carries every request of a client: a warm-up call learns
    // that the server speaks h2, then 40 concurrent ones multiplex over it.
    let Ok(identity) = a.rest.login(E2E_USER, E2E_PASSWORD).await? else {
        bail!("router-a: login as {E2E_USER} failed");
    };
    let client = a.rest.with_identity(&identity)?;
    let handshake = "rest tls handshake ok user=\"e2e\" alpn=h2 kx=Some(X25519MLKEM768)";
    let before = a.count(handshake);
    a.rest_with(&client, Method::GET, "/v1/interfaces", None)
        .await?;
    let calls = (0..40).map(|_| a.rest_with(&client, Method::GET, "/v1/interfaces", None));
    for (status, _) in futures::future::try_join_all(calls).await? {
        if status != 200 {
            bail!("router-a: a multiplexed request -> {status}");
        }
    }
    a.wait_new(handshake, before, 15).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let opened = a.count(handshake) - before;
    if opened != 1 {
        bail!("router-a: 41 requests took {opened} TLS handshakes, want exactly 1 (h2 over post-quantum TLS 1.3)");
    }
    log("router-a: 41 requests shared one post-quantum h2 connection");

    // Behind it, nos-restd reuses its IPC connections: a request that touches
    // the config, the broker and nos-ribd used to cost three handshakes, so 40
    // of them would show >=120 server-side handshakes across the daemons. The
    // margin is wide because other daemons reconnect in the background too.
    let ipc = "ipc tls handshake ok side=server";
    a.rest_with(&client, Method::GET, "/v1/routes/rt1", None)
        .await?;
    let before = a.count(ipc);
    for _ in 0..40 {
        a.rest_with(&client, Method::GET, "/v1/routes/rt1", None)
            .await?;
    }
    let opened = a.count(ipc) - before;
    if opened >= 30 {
        bail!("router-a: 40 sequential requests opened {opened} IPC handshakes — connections are not being reused");
    }
    log(format!(
        "router-a: 40 requests opened {opened} IPC handshakes (pooled)"
    ));
    Ok(())
}

/// Dials the REST port offering only the classical X25519 key exchange.
async fn classical_handshake(a: &Router) -> anyhow::Result<()> {
    use rustls::crypto::aws_lc_rs;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};

    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(a.rest.ca_pem())?)?;
    let cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect((a.id.ip.s(), REST_PORT)).await?;
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg))
        .connect(
            ServerName::IpAddress(a.id.ip.s().parse::<std::net::IpAddr>()?.into()),
            tcp,
        )
        .await?;
    Ok(())
}

/// A clear password set through the config tree is stored as a hash; setting
/// the same one again changes nothing (no diff, identical hash); a different
/// one replaces it and the old one stops working.
async fn rest_users(dock: &crate::docker::Dock, a: &Router) -> anyhow::Result<()> {
    let tx = format!("/v1/transactions/{REST_TX}");
    let user = format!("{tx}/user/{REST_USER}");
    let set = |password: &str| format!(r#"{{"name":"{REST_USER}","password":"{password}"}}"#);
    // `POST /v1/login` as the user: 200 with a certificate, or the refusal.
    let login = |password: &'static str| async move {
        a.rest
            .login(REST_USER, password)
            .await
            .map(|r| r.map_or_else(|status| status, |_| 200))
    };
    // REST masks the hash (#507), so read it from the file `save` writes.
    let stored_hash = || async {
        let masked = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
        if masked.contains("$argon2id$") {
            bail!("router-a: GET /v1/config returned a password hash");
        }
        a.rest_expect(Method::POST, "/v1/config/save", None, 204)
            .await?;
        let (_, yaml) = dock.exec_root("router-a", &["cat", SAVED_CONFIG]).await?;
        let lines: Vec<&str> = yaml.lines().map(str::trim).collect();
        let at = lines
            .iter()
            .position(|l| l.trim_start_matches("- ") == format!("name: {REST_USER}"))
            .with_context(|| format!("no user {REST_USER} in {SAVED_CONFIG}"))?;
        lines[at..]
            .iter()
            .find_map(|l| l.strip_prefix("password:"))
            .map(|h| h.trim().trim_matches(['\'', '"']).to_string())
            .with_context(|| format!("no password for {REST_USER} in {SAVED_CONFIG}"))
    };

    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(Method::PUT, &user, Some(&set("first")), 200)
        .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    let hash = stored_hash().await?;
    if !hash.starts_with("$argon2id$") || hash.contains("first") {
        bail!("router-a: password is not stored as an argon2id hash: {hash}");
    }
    // The certificate that login issued is what the user's later calls carry.
    let Ok(identity) = a.rest.login(REST_USER, "first").await? else {
        bail!("router-a: the new user cannot log in with its password");
    };
    let as_user = a.rest.with_identity(&identity)?;
    let (status, _) = a
        .rest_with(&as_user, Method::GET, "/v1/config", None)
        .await?;
    if status != 200 {
        bail!("router-a: the new user's certificate is refused: {status}");
    }

    // Same clear password again: empty diff, identical hash after commit.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(Method::PUT, &user, Some(&set("first")), 200)
        .await?;
    let diff = a
        .rest_expect(Method::GET, &format!("{tx}/diff"), None, 200)
        .await?;
    let diff: serde_json::Value = serde_json::from_str(&diff)?;
    if diff["users"].as_array().is_none_or(|u| !u.is_empty()) {
        bail!("router-a: re-setting the same password shows a diff: {diff}");
    }
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    if stored_hash().await? != hash {
        bail!("router-a: re-setting the same password changed its hash");
    }
    log("router-a: re-setting the same password left the hash and diff unchanged");

    // A different password replaces it; the old one stops working.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(Method::PUT, &user, Some(&set("second")), 200)
        .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    if stored_hash().await? == hash {
        bail!("router-a: a different password kept the old hash");
    }
    if login("first").await? != 401 || login("second").await? != 200 {
        bail!("router-a: after the change only the new password should log in");
    }

    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(Method::DELETE, &user, None, 204).await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    if login("second").await? != 401 {
        bail!("router-a: a deleted user can still log in");
    }
    // Their certificate is still valid for hours, but the user is gone: it is
    // refused on the very next request, even on the connection already open.
    let (status, _) = a
        .rest_with(&as_user, Method::GET, "/v1/config", None)
        .await?;
    if status != 401 {
        bail!("router-a: a deleted user's certificate still works: {status}");
    }
    log("router-a: user password change and deletion verified over REST");
    Ok(())
}

const SAVED_CONFIG: &str = "/var/lib/nos/configd/config.yaml";
/// Distinctive secrets: a log line or REST body holding one is a leak.
const SECRET_ONE: &str = "e2e-admin-secret-7f3a91-one";
const SECRET_TWO: &str = "e2e-admin-secret-7f3a91-two";

/// The admin keystore (#507) against the real daemons: a secret set over REST
/// never comes back (reply, transaction GET, `/v1/config`) and never reaches
/// `nos-logd`; a GET-then-PUT round trip keeps the stored value (the mask is
/// not the value); rotation replaces it; the saved file is owner-only.
async fn rest_secrets(dock: &crate::docker::Dock, a: &Router) -> anyhow::Result<()> {
    let tx = format!("/v1/transactions/{REST_TX}");
    let key = format!("{tx}/admin/key/e2e-k1");
    let no_leak = |what: &str, body: &str| -> anyhow::Result<()> {
        if body.contains(SECRET_ONE) || body.contains(SECRET_TWO) {
            bail!("router-a: {what} leaked an admin secret: {body}");
        }
        Ok(())
    };
    let saved = || async {
        a.rest_expect(Method::POST, "/v1/config/save", None, 204)
            .await?;
        Ok::<_, anyhow::Error>(dock.exec_root("router-a", &["cat", SAVED_CONFIG]).await?.1)
    };
    let set = |secret: &str| format!(r#"{{"label":"e2e-k1","secret":"{secret}"}}"#);

    let commits = a.count("config committed");
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    let put = a
        .rest_expect(Method::PUT, &key, Some(&set(SECRET_ONE)), 200)
        .await?;
    no_leak("the PUT reply", &put)?;
    let whole = a.rest_expect(Method::GET, &tx, None, 200).await?;
    no_leak("GET of the transaction", &whole)?;
    no_leak(
        "GET of the key",
        &a.rest_expect(Method::GET, &key, None, 200).await?,
    )?;
    if !whole.contains("<hidden>") {
        bail!("router-a: the transaction does not show the masked secret: {whole}");
    }
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    let running = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
    no_leak("GET /v1/config", &running)?;
    if !running.contains("e2e-k1") {
        bail!("router-a: the committed key label is missing from /v1/config");
    }

    // GET-then-PUT of the whole (masked) config keeps the stored secret.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    let snapshot = a.rest_expect(Method::GET, &tx, None, 200).await?;
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot)?;
    a.rest_expect(Method::PUT, &tx, Some(&snapshot["config"].to_string()), 200)
        .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    let file = saved().await?;
    if !file.contains(SECRET_ONE) || file.contains("<hidden>") {
        bail!(
            "router-a: the mask round trip changed the stored secret:
{file}"
        );
    }
    // A mask for a label that holds nothing is refused, not stored.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(
        Method::PUT,
        &format!("{tx}/admin/key/ghost"),
        Some(r#"{"label":"ghost","secret":"<hidden>"}"#),
        422,
    )
    .await?;
    a.rest_expect(Method::DELETE, &tx, None, 204).await?;

    // Rotation under the same label: the old value is gone, the new one stored.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    no_leak(
        "the rotation PUT",
        &a.rest_expect(Method::PUT, &key, Some(&set(SECRET_TWO)), 200)
            .await?,
    )?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    let file = saved().await?;
    if file.contains(SECRET_ONE) || !file.contains(SECRET_TWO) {
        bail!(
            "router-a: rotation did not replace the stored secret:
{file}"
        );
    }
    match dock
        .exec_root("router-a", &["stat", "-c", "%a", SAVED_CONFIG])
        .await?
    {
        (0, mode) if mode.trim() == "600" => {}
        (code, mode) => bail!("router-a: {SAVED_CONFIG} mode is {mode:?} (exit {code}), want 600"),
    }

    // Clean up, then check nothing the daemons logged (the stream nos-logd
    // collects) ever held a secret.
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    a.rest_expect(Method::DELETE, &key, None, 204).await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    a.wait_new("config committed", commits + 3, 30).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let logs = a
        .rest_expect(Method::GET, "/v1/logs?limit=20000", None, 200)
        .await?;
    no_leak("GET /v1/logs", &logs)?;
    for secret in [SECRET_ONE, SECRET_TWO] {
        if a.count(secret) != 0 {
            bail!("router-a: a log line holds the admin secret {secret}");
        }
    }
    log("router-a: admin secrets stay out of REST and logs; the mask round trip and rotation keep the stored value");
    Ok(())
}

/// The two checks that sever the very channel they are driven over, run on a
/// throwaway router: an address that is not on the VRF is retried rather than
/// fatal, and unpinning stops the process and closes the port.
async fn rest_destructive(w: &mut World) -> anyhow::Result<()> {
    w.start(R, None, &[]).await?;
    let r = w.get(R)?;
    // A commit that deletes every user is a semantic refusal: 422 (#675), not
    // 400, and the transaction stays open.
    let tx = format!("/v1/transactions/{REST_TX}");
    r.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    r.rest_expect(Method::DELETE, &format!("{tx}/user"), None, 204)
        .await?;
    r.rest_expect(Method::POST, &format!("{tx}/commit"), None, 422)
        .await?;
    r.rest_expect(Method::GET, &tx, None, 200).await?;
    r.rest_expect(Method::DELETE, &tx, None, 204).await?;
    log("router-r: committing a config with no users is 422 and keeps the transaction");
    r.provision(&[
        "--rest-api-address",
        REST_ABSENT_ADDRESS.s(),
        "--rest-api-port",
        &REST_PORT.to_string(),
    ])
    .await?;
    wait_docker_log(w, "router-r", "rest api stopped listening", 30).await?;
    wait_docker_log(w, "router-r", "rest api not listening yet", 30).await?;

    w.start(R, None, &[]).await?;
    let r = w.get(R)?;
    r.provision(&["--clear-rest-api"]).await?;
    wait_docker_log(
        w,
        "router-r",
        "REST API removed from config, stopping nos-restd",
        30,
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    if let Ok((200, _)) = r.rest(Method::GET, "/v1/config", None).await {
        bail!("the rest api still answers after being unpinned");
    }
    log("router-r: the rest api port is closed after unpinning");

    w.remove(R).await;
    Ok(())
}

// --- syslog (#71) ---

const SYSLOG_UDP_LOG: &str = "/var/log/udp.log";
const SYSLOG_TCP_LOG: &str = "/var/log/tcp.log";
/// One file per TLS listener: 6514 (defaults), 6515 (TLS 1.2 only, RSA leaf),
/// 6516 (TLS 1.3 with a classical group only).
const SYSLOG_TLS_LOG: &str = "/var/log/tls.log";
const SYSLOG_TLS12_LOG: &str = "/var/log/tls12.log";
const SYSLOG_TLSC_LOG: &str = "/var/log/tlsc.log";

/// A collector that parses RFC 5424 itself (syslog-ng's `syslog()` source),
/// writing one `HOST|PROGRAM|PID|LEVEL|FACILITY|SDATA|MSG` line per message
/// to a file per transport.
fn syslog_dockerfile() -> &'static str {
    "FROM debian:trixie-slim\n\
     RUN apt-get update && apt-get install -y --no-install-recommends syslog-ng-core \\\n \
     && rm -rf /var/lib/apt/lists/*\n"
}

fn syslog_conf() -> String {
    // peer-verify(no): nos presents no client certificate (server auth only).
    let tls = |port: u16, cert: &str, extra: &str| {
        format!(
            "syslog(ip(0.0.0.0) transport(\"tls\") port({port}) \
             tls(key-file(\"/etc/syslog-ng/{cert}.key\") cert-file(\"/etc/syslog-ng/{cert}.crt\") \
             peer-verify(no) {extra}));"
        )
    };
    let (s_tls, s_tls12, s_tlsc) = (
        tls(6514, "ecdsa", ""),
        // RFC 9662's SHOULD-offer TLS 1.2 suite, and nothing newer.
        tls(
            6515,
            "rsa",
            "ssl-options(no-tlsv13) cipher-suite(\"ECDHE-RSA-AES128-GCM-SHA256\")",
        ),
        // TLS 1.3, but only a classical group: must be refused in every case.
        tls(
            6516,
            "ecdsa",
            "ssl-options(no-tlsv12) ecdh-curve-list(\"X25519\")",
        ),
    );
    format!(
        "@version: current\n\
         options {{ keep-hostname(yes); chain-hostnames(no); }};\n\
         source s_udp {{ syslog(ip(0.0.0.0) transport(\"udp\") port(514)); }};\n\
         source s_tcp {{ syslog(ip(0.0.0.0) transport(\"tcp\") port(601)); }};\n\
         source s_tls {{ {s_tls} }};\n\
         source s_tls12 {{ {s_tls12} }};\n\
         source s_tlsc {{ {s_tlsc} }};\n\
         template t_line {{ template(\"$HOST|$PROGRAM|$PID|$LEVEL|$FACILITY|$SDATA|$MSG\\n\"); }};\n\
         destination d_udp {{ file(\"{SYSLOG_UDP_LOG}\" template(t_line)); }};\n\
         destination d_tcp {{ file(\"{SYSLOG_TCP_LOG}\" template(t_line)); }};\n\
         destination d_tls {{ file(\"{SYSLOG_TLS_LOG}\" template(t_line)); }};\n\
         destination d_tls12 {{ file(\"{SYSLOG_TLS12_LOG}\" template(t_line)); }};\n\
         destination d_tlsc {{ file(\"{SYSLOG_TLSC_LOG}\" template(t_line)); }};\n\
         log {{ source(s_udp); destination(d_udp); }};\n\
         log {{ source(s_tcp); destination(d_tcp); }};\n\
         log {{ source(s_tls); destination(d_tls); }};\n\
         log {{ source(s_tls12); destination(d_tls12); }};\n\
         log {{ source(s_tlsc); destination(d_tlsc); }};\n"
    )
}

/// The collector's certificates, generated per run: one CA signing an ECDSA
/// and an RSA-2048 leaf (an IP SAN for the collector's address plus a DNS SAN),
/// and an unrelated CA to be refused.
struct SyslogCerts {
    ecdsa_crt: String,
    ecdsa_key: String,
    rsa_crt: String,
    rsa_key: String,
    /// `SHA-256:AB:CD:...` of the ECDSA leaf and of a certificate that is not
    /// the collector's.
    ecdsa_fingerprint: String,
    wrong_fingerprint: String,
    /// Host files for `--syslog-trust-anchor-file`.
    ca_file: std::path::PathBuf,
    other_ca_file: std::path::PathBuf,
}

const SYSLOG_DNS_NAME: &str = "syslog.e2e";

impl SyslogCerts {
    fn generate() -> anyhow::Result<Self> {
        use rcgen::{
            BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, RsaKeySize, SanType,
            PKCS_RSA_SHA256,
        };
        use sha2::{Digest, Sha256};
        let ca = |name: &str| -> anyhow::Result<(String, Issuer<'static, KeyPair>)> {
            let key = KeyPair::generate()?;
            let mut p = CertificateParams::new(Vec::<String>::new())?;
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.distinguished_name
                .push(rcgen::DnType::CommonName, name.to_string());
            let cert = p.self_signed(&key)?;
            Ok((cert.pem(), Issuer::new(p, key)))
        };
        let (ca_pem, issuer) = ca("nos-e2e syslog CA")?;
        let (other_pem, _) = ca("nos-e2e unrelated CA")?;
        let leaf = |key: &KeyPair| -> anyhow::Result<rcgen::Certificate> {
            let mut p = CertificateParams::new(vec![SYSLOG_DNS_NAME.to_string()])?;
            p.subject_alt_names
                .push(SanType::IpAddress(IP_SYSLOG.s().parse()?));
            Ok(p.signed_by(key, &issuer)?)
        };
        let ecdsa = KeyPair::generate()?;
        let rsa = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)?;
        let (ecdsa_cert, rsa_cert) = (leaf(&ecdsa)?, leaf(&rsa)?);
        let fingerprint = |der: &[u8]| {
            let hex: Vec<String> = Sha256::digest(der)
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect();
            format!("SHA-256:{}", hex.join(":"))
        };
        // nosemgrep: rust.lang.security.temp-dir.temp-dir -- public CA certificates, not secrets.
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let write = |name: &str, pem: &str| -> anyhow::Result<std::path::PathBuf> {
            let path = dir.join(format!("nos-e2e-syslog-{pid}-{name}.pem"));
            std::fs::write(&path, pem)?;
            Ok(path)
        };
        Ok(Self {
            ecdsa_crt: ecdsa_cert.pem(),
            ecdsa_key: ecdsa.serialize_pem(),
            rsa_crt: rsa_cert.pem(),
            rsa_key: rsa.serialize_pem(),
            ecdsa_fingerprint: fingerprint(ecdsa_cert.der()),
            wrong_fingerprint: fingerprint(rsa_cert.der()),
            ca_file: write("ca", &ca_pem)?,
            other_ca_file: write("other-ca", &other_pem)?,
        })
    }
}

/// Starts the collector. syslog-ng reads its certificates at startup, so the
/// container waits for a `ready` file uploaded after them.
async fn start_syslog_collector(w: &World, certs: &SyslogCerts) -> anyhow::Result<()> {
    let conf = syslog_conf();
    w.dock
        .start_plain(
            SYSLOG_COLLECTOR,
            SYSLOG_IMAGE,
            NET,
            IP_SYSLOG.s(),
            &[
                "sh",
                "-c",
                "while [ ! -e /etc/syslog-ng/ready ]; do sleep 0.2; done; \
                 exec syslog-ng -F --no-caps -f /etc/syslog-ng/syslog-ng.conf",
            ],
            ("/etc/syslog-ng", "syslog-ng.conf", conf.as_bytes()),
        )
        .await?;
    for (file, contents) in [
        ("ecdsa.crt", &certs.ecdsa_crt),
        ("ecdsa.key", &certs.ecdsa_key),
        ("rsa.crt", &certs.rsa_crt),
        ("rsa.key", &certs.rsa_key),
        ("ready", &String::new()),
    ] {
        w.dock
            .upload(
                SYSLOG_COLLECTOR,
                "/etc/syslog-ng",
                file,
                contents.as_bytes(),
            )
            .await?;
    }
    Ok(())
}

/// Every line the collector wrote to `file` (empty before the first one).
async fn collected(w: &World, file: &str) -> anyhow::Result<Vec<Vec<String>>> {
    let (_, out) = w.dock.exec(SYSLOG_COLLECTOR, &["cat", file]).await?;
    Ok(out
        .lines()
        .filter(|l| l.matches('|').count() >= 6)
        .map(|l| l.splitn(7, '|').map(str::to_string).collect())
        .collect())
}

/// Waits for a collected line `f` accepts and returns it.
async fn wait_collected(
    w: &World,
    file: &str,
    what: &str,
    secs: u64,
    f: impl Fn(&[String]) -> bool,
) -> anyhow::Result<Vec<String>> {
    for _ in 0..secs {
        if let Some(l) = collected(w, file).await?.into_iter().find(|l| f(l)) {
            log(format!("collector {file}: saw {what}"));
            return Ok(l);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("collector {file}: no line matching {what} within {secs}s")
}

/// `docker logs` of `container` with ANSI colour codes removed (the daemons'
/// `fmt` layer colours field names even into a pipe).
async fn plain_docker_logs(w: &World, container: &str) -> anyhow::Result<String> {
    let raw = w.dock.logs(container).await?;
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for e in chars.by_ref() {
                if e.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// RFC 5424 export from `nos-logd` to a real syslog-ng, over both transports,
/// from inside `rt1`'s VRF (eth0 is enslaved to it, so an unscoped socket
/// could not reach the collector): hostname, program, instance, facility and
/// level parsed by an independent implementation, the level filter, a TCP
/// reconnect after the collector restarts, and removal.
pub async fn syslog(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    log("building/starting the syslog collector");
    w.dock
        .ensure_image(SYSLOG_IMAGE, syslog_dockerfile())
        .await?;
    let certs = SyslogCerts::generate()?;
    start_syslog_collector(w, &certs).await?;

    let addr = IP_SYSLOG.s().to_string();
    a.provision(&["--hostname", SYSLOG_HOSTNAME]).await?;
    for (name, transport) in [("c-udp", "udp"), ("c-tcp", "tcp")] {
        a.provision(&[
            "--hostname",
            SYSLOG_HOSTNAME,
            "--syslog-server",
            name,
            "--syslog-address",
            &addr,
            "--syslog-transport",
            transport,
            "--syslog-routing-table",
            "rt1",
            "--syslog-facility",
            "local3",
        ])
        .await?;
    }

    // Nothing logs at info in steady state, and each sink only sees what is
    // logged after it connected: one more commit gives both a line.
    a.provision(&["--hostname", SYSLOG_HOSTNAME]).await?;
    for file in [SYSLOG_UDP_LOG, SYSLOG_TCP_LOG] {
        // nos-configd's own commit line, with the hostname we configured,
        // the facility and an info level; its PROCID is the NILVALUE.
        let mut found = None;
        for _ in 0..30 {
            // A sink that connected late missed the earlier commits.
            a.provision(&["--hostname", SYSLOG_HOSTNAME]).await?;
            found = collected(w, file).await?.into_iter().find(|l| {
                l[0] == SYSLOG_HOSTNAME
                    && l[1] == "nos-configd"
                    && l[3] == "info"
                    && l[4] == "local3"
            });
            if found.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let l = found.with_context(|| format!("{file}: no nos-configd info line"))?;
        if !l[5].contains("timeQuality") || !l[6].contains("config committed") {
            bail!("unexpected structured data or text in {l:?}");
        }
    }

    // The routers run with RUST_LOG=debug; the default minimum is info, so a
    // collector with no level never sees a debug line.
    let debug = |l: &[String]| l[3] == "debug";
    if collected(w, SYSLOG_TCP_LOG).await?.iter().any(|l| debug(l)) {
        bail!("a debug line reached a collector at the default level");
    }
    a.provision(&[
        "--hostname",
        SYSLOG_HOSTNAME,
        "--syslog-server",
        "c-tcp",
        "--syslog-level",
        "debug",
    ])
    .await?;
    wait_collected(w, SYSLOG_TCP_LOG, "a debug line", 60, debug).await?;
    // An instance daemon: APP-NAME nos-ribd/nos-bgpd, PROCID its instance.
    wait_collected(w, SYSLOG_TCP_LOG, "an instance daemon's line", 60, |l| {
        (l[1] == "nos-ribd" && l[2] == "rt1") || (l[1] == "nos-bgpd" && l[2] == "r1")
    })
    .await?;
    if collected(w, SYSLOG_UDP_LOG).await?.iter().any(|l| debug(l)) {
        bail!("a debug line reached the udp collector, still at the default level");
    }

    log("restarting the collector: the tcp sink must reconnect");
    let connected = |logs: &str| logs.matches("syslog connected server=c-tcp").count();
    let before = connected(&plain_docker_logs(w, "router-a").await?);
    start_syslog_collector(w, &certs).await?;
    let mut after = before;
    for _ in 0..60 {
        after = connected(&plain_docker_logs(w, "router-a").await?);
        if after > before {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if after <= before {
        bail!("nos-logd never logged a new 'syslog connected server=c-tcp'");
    }
    wait_collected(w, SYSLOG_TCP_LOG, "a line after the restart", 60, |_| true).await?;

    log("removing both collectors");
    a.provision(&[
        "--hostname",
        SYSLOG_HOSTNAME,
        "--no-syslog-server",
        "c-udp",
        "--no-syslog-server",
        "c-tcp",
    ])
    .await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (udp, tcp) = (
        collected(w, SYSLOG_UDP_LOG).await?.len(),
        collected(w, SYSLOG_TCP_LOG).await?.len(),
    );
    tokio::time::sleep(Duration::from_secs(10)).await;
    if collected(w, SYSLOG_UDP_LOG).await?.len() != udp
        || collected(w, SYSLOG_TCP_LOG).await?.len() != tcp
    {
        bail!("a collector kept receiving lines after its removal");
    }

    syslog_tls(w, &certs).await?;

    a.provision(&["--hostname", "nos"]).await?;
    w.dock.container_remove(SYSLOG_COLLECTOR).await;
    Ok(())
}

/// Polls router-a's `docker logs` (nos-logd does not forward its own logs to
/// the REST stream) until `pattern` shows up more often than `before` times.
async fn wait_router_a_log(w: &World, pattern: &str, before: usize) -> anyhow::Result<()> {
    for _ in 0..60 {
        if plain_docker_logs(w, "router-a")
            .await?
            .matches(pattern)
            .count()
            > before
        {
            log(format!("router-a: saw '{pattern}'"));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("nos-logd never logged '{pattern}'")
}

async fn router_a_log_count(w: &World, pattern: &str) -> anyhow::Result<usize> {
    Ok(plain_docker_logs(w, "router-a")
        .await?
        .matches(pattern)
        .count())
}

/// Adds/updates TLS collector `name` on `port`; `extra` are the trust flags.
async fn tls_server(w: &World, name: &str, port: u16, extra: &[&str]) -> anyhow::Result<()> {
    let (addr, port) = (IP_SYSLOG.s().to_string(), port.to_string());
    let mut args = vec![
        "--hostname",
        SYSLOG_HOSTNAME,
        "--syslog-server",
        name,
        "--syslog-address",
        &addr,
        "--syslog-transport",
        "tls",
        "--syslog-port",
        &port,
        "--syslog-routing-table",
        "rt1",
        "--syslog-facility",
        "local3",
    ];
    args.extend_from_slice(extra);
    w.a()?.provision(&args).await
}

/// The collector received a line `file` did not hold before: commits keep
/// producing `nos-configd` info lines until a connected sink forwards one.
async fn expect_tls_delivery(w: &World, file: &str) -> anyhow::Result<()> {
    let before = collected(w, file).await?.len();
    for _ in 0..30 {
        w.a()?.provision(&["--hostname", SYSLOG_HOSTNAME]).await?;
        if collected(w, file).await?.len() > before {
            log(format!("collector {file}: a line arrived over tls"));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("collector {file}: no line arrived over tls")
}

/// The handshake was refused: `nos-logd` logs it and no collector file grows.
async fn expect_tls_refused(
    w: &World,
    name: &str,
    file: &str,
    before: usize,
) -> anyhow::Result<()> {
    wait_router_a_log(
        w,
        &format!("syslog collector unavailable server={name} error=tls handshake"),
        before,
    )
    .await?;
    let lines = collected(w, file).await?.len();
    for _ in 0..3 {
        w.a()?.provision(&["--hostname", SYSLOG_HOSTNAME]).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if collected(w, file).await?.len() != lines {
        bail!("a line reached {file} from '{name}', whose handshake was refused");
    }
    Ok(())
}

async fn remove_syslog_server(w: &World, name: &str) -> anyhow::Result<()> {
    w.a()?
        .provision(&["--hostname", SYSLOG_HOSTNAME, "--no-syslog-server", name])
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}

/// RFC 5425 / RFC 9662 against syslog-ng (OpenSSL 3.5, which offers
/// `X25519MLKEM768`): trust by CA and by fingerprint over post-quantum TLS 1.3;
/// an unrelated CA, a wrong fingerprint, a wrong name, a TLS 1.2-only collector
/// and a TLS 1.3 collector with a classical group only are all refused by
/// default; `allow-tls12` reaches the TLS 1.2 one (classical, warned) but still
/// never a classical TLS 1.3 one, and turning it off again refuses it once more.
async fn syslog_tls(w: &World, certs: &SyslogCerts) -> anyhow::Result<()> {
    let ca = certs.ca_file.to_str().context("ca path")?;
    let other_ca = certs.other_ca_file.to_str().context("other ca path")?;
    let connected = |name: &str, version: &str, kx: &str| {
        format!("syslog connected server={name} version={version} kx={kx}")
    };
    let refused =
        |name: &str| format!("syslog collector unavailable server={name} error=tls handshake");

    log("tls: trust anchor, then fingerprint, on the default (post-quantum TLS 1.3) listener");
    for (name, trust) in [
        ("c-tls-ca", ["--syslog-trust-anchor-file", ca]),
        (
            "c-tls-fp",
            ["--syslog-fingerprint", &certs.ecdsa_fingerprint],
        ),
    ] {
        tls_server(w, name, 6514, &trust).await?;
        wait_router_a_log(w, &connected(name, "TLSv1_3", "X25519MLKEM768"), 0).await?;
        expect_tls_delivery(w, SYSLOG_TLS_LOG).await?;
        remove_syslog_server(w, name).await?;
    }

    log("tls: server-name, right and wrong");
    tls_server(
        w,
        "c-tls-name",
        6514,
        &[
            "--syslog-trust-anchor-file",
            ca,
            "--syslog-server-name",
            SYSLOG_DNS_NAME,
        ],
    )
    .await?;
    wait_router_a_log(w, &connected("c-tls-name", "TLSv1_3", "X25519MLKEM768"), 0).await?;
    remove_syslog_server(w, "c-tls-name").await?;
    tls_server(
        w,
        "c-tls-badname",
        6514,
        &[
            "--syslog-trust-anchor-file",
            ca,
            "--syslog-server-name",
            "other.e2e",
        ],
    )
    .await?;
    expect_tls_refused(w, "c-tls-badname", SYSLOG_TLS_LOG, 0).await?;
    remove_syslog_server(w, "c-tls-badname").await?;

    log("tls: an unrelated CA and a wrong fingerprint are refused");
    tls_server(
        w,
        "c-tls-badca",
        6514,
        &["--syslog-trust-anchor-file", other_ca],
    )
    .await?;
    expect_tls_refused(w, "c-tls-badca", SYSLOG_TLS_LOG, 0).await?;
    remove_syslog_server(w, "c-tls-badca").await?;
    tls_server(
        w,
        "c-tls-badfp",
        6514,
        &["--syslog-fingerprint", &certs.wrong_fingerprint],
    )
    .await?;
    expect_tls_refused(w, "c-tls-badfp", SYSLOG_TLS_LOG, 0).await?;
    remove_syslog_server(w, "c-tls-badfp").await?;

    log("tls: policy refuses TLS 1.2 and classical TLS 1.3 by default");
    tls_server(w, "c-tls12", 6515, &["--syslog-trust-anchor-file", ca]).await?;
    expect_tls_refused(w, "c-tls12", SYSLOG_TLS12_LOG, 0).await?;
    tls_server(w, "c-tlsc", 6516, &["--syslog-trust-anchor-file", ca]).await?;
    expect_tls_refused(w, "c-tlsc", SYSLOG_TLSC_LOG, 0).await?;

    log("tls: allow-tls12 reaches the TLS 1.2 collector, nothing classical on TLS 1.3");
    tls_server(w, "c-tls12", 6515, &["--syslog-allow-tls12"]).await?;
    wait_router_a_log(w, &connected("c-tls12", "TLSv1_2", ""), 0).await?;
    wait_router_a_log(w, "syslog tls12 classical key exchange server=c-tls12", 0).await?;
    wait_router_a_log(w, "suite=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0).await?;
    expect_tls_delivery(w, SYSLOG_TLS12_LOG).await?;
    // The opt-in never downgrades a collector that does the hybrid exchange.
    remove_syslog_server(w, "c-tlsc").await?;
    tls_server(
        w,
        "c-tls-ca",
        6514,
        &["--syslog-trust-anchor-file", ca, "--syslog-allow-tls12"],
    )
    .await?;
    wait_router_a_log(w, &connected("c-tls-ca", "TLSv1_3", "X25519MLKEM768"), 1).await?;
    remove_syslog_server(w, "c-tls-ca").await?;
    // ... and still refuses the TLS 1.3 listener that offers a classical group only.
    let before = router_a_log_count(w, &refused("c-tlsc")).await?;
    tls_server(
        w,
        "c-tlsc",
        6516,
        &["--syslog-trust-anchor-file", ca, "--syslog-allow-tls12"],
    )
    .await?;
    expect_tls_refused(w, "c-tlsc", SYSLOG_TLSC_LOG, before).await?;
    remove_syslog_server(w, "c-tlsc").await?;

    log("tls: allow-tls12 off again refuses the TLS 1.2 collector");
    let before = router_a_log_count(w, &refused("c-tls12")).await?;
    tls_server(w, "c-tls12", 6515, &["--no-syslog-allow-tls12"]).await?;
    expect_tls_refused(w, "c-tls12", SYSLOG_TLS12_LOG, before).await?;
    remove_syslog_server(w, "c-tls12").await
}

fn expect_body(body: &str, needle: &str) -> anyhow::Result<()> {
    if body.contains(needle) {
        Ok(())
    } else {
        bail!("body lacks '{needle}': {body}")
    }
}

/// #691: an `AF_PACKET` socket created with a protocol is hooked on every
/// device until it is bound, so a frame arriving on *another* interface in
/// that window used to be queued on it. router-b floods eth2 with LLDPDUs
/// (port id `race-eth2`) while router-a's `nos-lldpd` reopens its eth1 socket
/// again and again (every tx-interval change restarts the link); router-a
/// must never learn that neighbor on eth1.
pub async fn l2_socket_race(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    w.link_veths().await?;
    w.dock
        .ensure_image(
            PYTHON_HELPER_IMAGE,
            "FROM debian:trixie-slim\n\
            RUN apt-get update && apt-get install -y --no-install-recommends python3-minimal \\\n \
            && rm -rf /var/lib/apt/lists/*\n",
        )
        .await?;
    // eth2 carries no config in this phase: bring both ends up by hand.
    for router in ["router-a", "router-b"] {
        w.dock
            .ip(
                NETNS_HELPER_IMAGE,
                Some(router),
                false,
                &["link", "set", "eth2", "up"],
            )
            .await?;
    }
    let on = [
        "--hostname",
        "router-a",
        "--lldp-transmit-interface",
        "eth1",
        "--lldp-receive-interface",
        "eth1",
    ];
    a.provision(&on).await?;
    let link = "lldp link started interface=eth1 transmit=true receive=true";
    a.wait(link).await?;

    let leaked = "lldp neighbor learned interface=eth1 .* port_id=race-eth2";
    let (base, started) = (a.count(leaked), a.count(link));
    log("flooding eth2 while router-a's nos-lldpd reopens its eth1 socket");
    let flood = w.dock.in_netns(
        PYTHON_HELPER_IMAGE,
        "router-b",
        &["python3", "-c", include_str!("lldp_flood.py")],
    );
    let restarts = async {
        for i in 0..30 {
            let interval = (31 + i % 2).to_string();
            a.provision(&["--hostname", "router-a", "--lldp-tx-interval", &interval])
                .await?;
        }
        anyhow::Ok(())
    };
    let (flooded, restarted) = tokio::join!(flood, restarts);
    flooded?;
    restarted?;
    // Every provision above restarted the link: the socket really was reopened.
    if a.count(link) < started + 10 {
        bail!("router-a's lldp link was not restarted under the flood");
    }
    if a.count(leaked) != base {
        bail!("router-a learned an eth2 frame on its eth1 socket (#691)");
    }

    // Back to the default interval (the `lldp` phase expects ttl=120).
    a.provision(&[
        "--lldp-tx-interval",
        "30",
        "--no-lldp-transmit-interface",
        "eth1",
        "--no-lldp-receive-interface",
        "eth1",
    ])
    .await?;
    w.unlink_veths().await;
    Ok(())
}

/// `routes-paging` (#713): `GET /v1/routes/<table>` is paged. 25 extra
/// statics against a page size of 10 force three pages; the walk over
/// `pagination.next` must return each exactly once, in ascending order, and
/// a cursor past the end is an empty last page. (The 1000-prefix server
/// default is covered by unit tests; 1M routes are too heavy for CI.)
pub async fn routes_paging(w: &mut World) -> anyhow::Result<()> {
    const N: usize = 25;
    let a = w.a()?;
    let prefixes: Vec<String> = (0..N).map(|i| format!("10.88.{i}.0/24")).collect();
    let flags = |flag: &str| -> Vec<String> {
        prefixes
            .iter()
            .flat_map(|p| [flag.to_string(), p.clone()])
            .collect()
    };
    let mut add = flags("--static-route");
    add.extend(strings(&["--static-gateway", REDISTRIBUTE_GATEWAY.s()]));
    a.provision(&add).await?;

    let ours = |items: &[serde_json::Value]| -> Vec<String> {
        items
            .iter()
            .filter_map(|p| p["prefix"].as_str())
            .filter(|p| p.starts_with("10.88."))
            .map(String::from)
            .collect()
    };
    let mut seen = Vec::new();
    for _ in 0..30 {
        seen = ours(&a.routes_walk("rt1", Some(10)).await?);
        if seen.len() == N {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if seen != prefixes {
        bail!("paged walk of rt1 returned {seen:?}, expected {prefixes:?}");
    }

    log("a static candidate carries its attributes (#1444)");
    let all = a.routes_walk("rt1", None).await?;
    let cand = |prefix: &str, source: &str| {
        all.iter()
            .filter(|p| p["prefix"] == prefix)
            .flat_map(|p| p["candidates"].as_array().cloned().unwrap_or_default())
            .find(|c| c["source"] == source)
    };
    let st = cand("10.88.0.0/24", "Static")
        .ok_or_else(|| anyhow::anyhow!("no static candidate for 10.88.0.0/24"))?;
    if st["preference"] != 1
        || st["installed"] != true
        || st["interfaces"] != serde_json::json!([ROUTES_PAGING_IFACE])
        || st["age_secs"].as_u64().is_none_or(|n| n >= 120)
    {
        bail!("static candidate attributes are wrong: {st}");
    }
    let conn = cand(SUBNET.s(), "Connected")
        .ok_or_else(|| anyhow::anyhow!("no connected candidate for {}", SUBNET.s()))?;
    if conn["preference"] != 0 || conn["installed"] != false {
        bail!("connected candidate attributes are wrong: {conn}");
    }

    log("the first page is full and points at the next one");
    let body = a
        .rest_expect(Method::GET, "/v1/routes/rt1?limit=10", None, 200)
        .await?;
    let page: serde_json::Value = serde_json::from_str(&body)?;
    if page["items"].as_array().map(Vec::len) != Some(10)
        || page["pagination"]["limit"] != 10
        || !page["pagination"]["next"].is_string()
    {
        bail!("first page of GET /v1/routes/rt1?limit=10 is wrong: {body}");
    }
    let body = a
        .rest_expect(
            Method::GET,
            "/v1/routes/rt1?after=255.255.255.255/32",
            None,
            200,
        )
        .await?;
    let page: serde_json::Value = serde_json::from_str(&body)?;
    if page["items"] != serde_json::json!([]) || !page["pagination"]["next"].is_null() {
        bail!("a cursor past the end must be an empty last page: {body}");
    }
    a.rest_expect(Method::GET, "/v1/routes/rt1?after=nope", None, 400)
        .await?;

    a.provision(&flags("--remove-static-route")).await?;
    Ok(())
}

/// #1150: a daemon that stops (SIGSTOP: the process lives, its runtime does
/// not turn) stops beating; `nos-watchdogd` kills and restarts it. `nos-lldpd`
/// is the victim: a fixed singleton nothing else here depends on.
pub async fn daemon_heartbeat(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    // It must have beaten once for the watchdog to expect more; every beat
    // is one 5 s tick after start, so allow for the first one.
    let starting = "starting process=nos-lldpd";
    let base = a.count(starting);
    log("freezing router-a's nos-lldpd with SIGSTOP");
    tokio::time::sleep(Duration::from_secs(12)).await;
    w.dock
        .signal_process("router-a", "nos-lldpd", "-STOP")
        .await?;
    let a = w.a()?;
    a.wait_new(
        "heartbeat missed, killing the hung process process=nos-lldpd",
        a.count("heartbeat missed, killing the hung process process=nos-lldpd"),
        90,
    )
    .await?;
    a.wait_new(starting, base, 60).await?;
    Ok(())
}

/// `/proc/<pid>/status` of router-a's first process whose `comm` is `comm` (no `ps` or
/// `pgrep` in the image; status is world-readable).
pub(super) async fn proc_status(w: &World, comm: &str) -> anyhow::Result<String> {
    let script = format!(
        "for p in /proc/[0-9]*; do [ \"$(cat $p/comm 2>/dev/null)\" = {comm} ] && cat $p/status && break; done"
    );
    let (_, out) = w.dock.exec("router-a", &["sh", "-c", &script]).await?;
    if !out.contains("NoNewPrivs:") {
        bail!("no running process {comm} on router-a");
    }
    Ok(out)
}

/// `comm` must run with `NoNewPrivs` `nnp` and, if given, exactly the effective capabilities `cap_eff`.
pub(super) async fn assert_sandbox(
    w: &World,
    comm: &str,
    nnp: u8,
    cap_eff: Option<&str>,
) -> anyhow::Result<()> {
    let st = proc_status(w, comm).await?;
    let want_nnp = format!("NoNewPrivs:\t{nnp}");
    // #1217: the deny-list is one seccomp filter stacked on whatever the container already has
    // (Docker's default profile). Baseline = the unsandboxed `nos-watchdogd` in the same
    // container, so the check holds whatever the lab's profile; `nos-sshd` has no deny-list.
    let filters = |st: &str| {
        st.lines()
            .find_map(|l| l.strip_prefix("Seccomp_filters:"))
            .and_then(|v| v.trim().parse::<u32>().ok())
    };
    let base = filters(&proc_status(w, "nos-watchdogd").await?)
        .context("nos-watchdogd: no Seccomp_filters (host kernel < 5.9?)")?;
    let want_seccomp = format!("Seccomp_filters:\t{}", base + u32::from(nnp));
    let want_cap = cap_eff.map_or(String::new(), |c| format!("CapEff:\t{c}"));
    if !st.contains(&want_nnp) || !st.contains(&want_cap) || !st.contains(&want_seccomp) {
        bail!("{comm}: wanted `{want_nnp}`, `{want_seccomp}` and `{want_cap}`, got:\n{st}");
    }
    log(format!("{comm}: {want_nnp}, {want_seccomp}, {want_cap}"));
    Ok(())
}

/// #1211: every daemon is exec'd through `nos-sandbox-exec`, which sets `NO_NEW_PRIVS` and
/// keeps exactly the target's file capabilities (the same `CapEff` as a direct exec).
/// `nos-ospfd` is checked in `ospf`, `nos-sshd` (exempt, `NoNewPrivs: 0`) in `ssh-hostkey`.
pub async fn sandbox_nnp(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.wait("starting process=nos-ribd.*sandbox=/usr/local/bin/nos-sandbox-exec")
        .await?;
    assert_sandbox(w, "nos-ribd", 1, Some(CAP_EFF_NET_ADMIN_RAW)).await?;
    assert_sandbox(w, "nos-interfaced", 1, Some(CAP_EFF_NET_ADMIN_RAW)).await?;
    assert_sandbox(w, "nos-bgpd", 1, Some(CAP_EFF_NET_RAW_BIND)).await?;
    assert_sandbox(w, "nos-configd", 1, Some(CAP_EFF_NONE)).await?;
    assert_sandbox(w, "nos-logd", 1, Some(CAP_EFF_NONE)).await?;
    // #1217: no daemon was killed by the seccomp deny-list (SIGSYS) since the run began.
    a.assert_quiet("exited.*signal: 31", 0, 1).await?;
    Ok(())
}

/// MPLS ILM entries (segment routing, #1165): `--ribd-arg=--test-ilm` stands
/// in for the OSPF SR daemon, so the real `nos-ribd` programs real `AF_MPLS`
/// routes, one of each kind: a swap, a PHP pop toward router-b, and a pop
/// followed by a lookup in `rt1`. Self-contained. The proof is `nos-ribd`'s
/// own log line, written only after the kernel accepted the route; removal
/// is the daemon's clean shutdown (SIGINT, `teardown`; read from `docker logs`, the forwarder is already stopped), after which the
/// watchdog's restart installs them again.
pub async fn mpls_ilm(w: &mut World) -> anyhow::Result<()> {
    let gw = IP_B.s();
    w.up(&[
        &format!("--ribd-arg=--test-ilm={ILM_SWAP}={gw},{ILM_SWAP_OUT}"),
        &format!("--ribd-arg=--test-ilm={ILM_PHP}={gw}"),
        &format!("--ribd-arg=--test-ilm={ILM_LOCAL}"),
    ])
    .await?;
    // docker mounts /proc/sys read-only: the label space is the operator's.
    super::bgp::mpls_ready(w, &["router-a"]).await?;
    let a = w.a()?;
    let installed = |label: u32, out: &str| {
        format!("installed mpls ilm route table=rt1 label={label} out={out}")
    };
    a.wait_new(
        &installed(ILM_SWAP, &format!("\\[\\[{ILM_SWAP_OUT}\\]\\]")),
        0,
        60,
    )
    .await?;
    a.wait_new(&installed(ILM_PHP, "\\[\\[\\]\\]"), 0, 30)
        .await?;
    a.wait_new(&installed(ILM_LOCAL, "\\[\\]"), 0, 30).await?;
    // A steady state rewrites nothing: the 10 s re-apply finds each entry in
    // the kernel and in its shadow.
    let steady = a.count_fresh("installed mpls ilm route").await;
    a.assert_quiet("installed mpls ilm route", steady, 25)
        .await?;

    let labels = [ILM_SWAP, ILM_PHP, ILM_LOCAL];
    let removed = |label: u32| format!("removed mpls ilm route table=rt1 label={label}");
    let reinstalled = a.count("installed mpls ilm route");
    let since = i32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?;
    w.dock
        .signal_process("router-a", "nos-ribd", "-INT")
        .await?;
    // `teardown` runs after the log forwarder is stopped, so the removal lines
    // reach `docker logs` (colour codes stripped) but never `nos-logd`.
    let mut plain = String::new();
    for _ in 0..30 {
        plain = strip_ansi(&w.dock.logs_since("router-a", since).await?);
        if labels.iter().all(|&l| plain.contains(&removed(l))) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    for &l in &labels {
        if !plain.contains(&removed(l)) {
            bail!("router-a: no '{}' in docker logs after SIGINT", removed(l));
        }
    }
    a.wait_new("installed mpls ilm route", reinstalled, 60)
        .await?;
    Ok(())
}

/// The operator's write of `net.mpls.conf.eth0.input` on router-a.
async fn set_mpls_kernel(w: &World, v: &str) -> anyhow::Result<()> {
    w.dock
        .in_netns(
            NETNS_HELPER_IMAGE,
            "router-a",
            &[
                "sh",
                "-c",
                &format!("echo {v} > /proc/sys/net/mpls/conf/eth0/input"),
            ],
        )
        .await?;
    Ok(())
}

/// `Interface.mpls_input` (#1380) against the real kernel file
/// `net.mpls.conf.eth0.input`. Docker mounts `/proc/sys` read-only, so
/// `nos-interfaced` can never write it here (the operator helper does, like
/// `mpls_ready`); what is proven is that the driver reads the real value and
/// decides to write exactly when it differs: a set knob over a 0 logs the
/// failed write, over a 1 stays quiet, and an unset knob it had satisfied
/// tries to write the 0 back. The write itself is unit-tested over a tempdir
/// (`driver/mpls_input.rs`). Self-contained; needs the host module `mpls_router`.
pub async fn mpls_input(w: &mut World) -> anyhow::Result<()> {
    const FAILED: &str = "failed to set mpls input interface=eth0 error=net.mpls.conf.eth0.input";
    w.up(&[]).await?;
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    // The kernel says 0, the knob wants 1: the driver tries to write.
    set_mpls_kernel(w, "0").await?;
    let base = w.a()?.count(FAILED);
    w.a()?
        .provision(&["--mpls-input-interface", "eth0"])
        .await?;
    w.a()?.wait_new(FAILED, base, 60).await?;
    // The kernel says 1: nothing to write, over two re-apply ticks.
    set_mpls_kernel(w, "1").await?;
    tokio::time::sleep(Duration::from_secs(12)).await;
    let base = w.a()?.count(FAILED);
    w.a()?.assert_quiet(FAILED, base, 25).await?;
    // Unset: the driver switched it on (it was already right), so it tries
    // to put the 0 back.
    w.a()?
        .provision(&["--no-mpls-input-interface", "eth0"])
        .await?;
    w.a()?.wait_new(FAILED, base, 60).await?;
    Ok(())
}

/// `s` without ANSI colour sequences (`docker logs` keeps the daemons' own).
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for d in chars.by_ref() {
                if d == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}
