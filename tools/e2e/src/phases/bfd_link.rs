//! BFD demux by arrival interface (#1603, follow-up of #1532/#1602).

use anyhow::bail;

use super::bfd::session_on_interface;
use super::ospf::{bfd_filter, ospfv3, with_base};
use crate::consts::*;
use crate::router::{log, strings, Id, A, B};
use crate::world::World;

/// `ospfv3-bfd-two-link`: router-a and router-b share a second docker network
/// (`eth1`), and router-b's `eth1` carries the same `fe80::` as its `eth0`, so
/// router-a holds two BFD sessions to one peer address, told apart only by the
/// arrival interface (`eth0.0` / `eth1.0`). UDP 3784 dropped on router-a's
/// `eth1` takes down the `eth1.0` session and neighbor alone; `eth0.0` stays Up.
/// Fails if the demux collapses the two sessions or `IP_PKTINFO` names the VRF.
pub async fn ospfv3_bfd_two_link(w: &mut World) -> anyhow::Result<()> {
    w.require_ipv6().await?;
    if !w.dock.network_exists(NET_OSPFV3_BFD2).await {
        w.dock
            .network_create(
                NET_OSPFV3_BFD2,
                &[OSPFV3_BFD2_SUBNET.s(), OSPFV3_BFD2_SUBNET6.s()],
                true,
            )
            .await?;
    }
    w.start(A, None, &[]).await?;
    w.start(B, None, &[]).await?;
    w.dock
        .network_connect_ip(NET_OSPFV3_BFD2, "router-a", OSPFV3_BFD2_IP_A.s())
        .await?;
    w.dock
        .network_connect_ip(NET_OSPFV3_BFD2, "router-b", OSPFV3_BFD2_IP_B.s())
        .await?;
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;

    let result = scenario(w).await;
    // Undo what the phase set, pass or fail.
    let _ = bfd_filter(w, "eth1", true, false).await;
    for r in ["router-a", "router-b"] {
        w.dock.network_disconnect(NET_OSPFV3_BFD2, r).await;
    }
    w.dock.network_remove(NET_OSPFV3_BFD2).await;
    result
}

/// Router-b's `eth1` gets `eth0`'s link-local (done before `nos-interfaced`
/// reads the first link-scope address of `eth1` at apply).
async fn share_link_local(w: &World) -> anyhow::Result<()> {
    async fn ip(w: &World, args: &[&str]) -> anyhow::Result<String> {
        let mut c = vec!["ip", "-6"];
        c.extend_from_slice(args);
        w.dock.in_netns(NETNS_HELPER_IMAGE, "router-b", &c).await
    }
    let shown = ip(w, &["-o", "addr", "show", "dev", "eth0", "scope", "link"]).await?;
    let ll = shown
        .split_whitespace()
        .skip_while(|t| *t != "inet6")
        .nth(1)
        .and_then(|a| a.split('/').next())
        .filter(|a| a.starts_with("fe80::"))
        .map(str::to_string);
    let Some(ll) = ll else {
        bail!("router-b eth0 has no link-local: {shown}")
    };
    ip(w, &["addr", "flush", "dev", "eth1", "scope", "link"]).await?;
    ip(
        w,
        &["addr", "add", &format!("{ll}/64"), "dev", "eth1", "nodad"],
    )
    .await?;
    log(format!("router-b eth1 now shares {ll} with eth0"));
    Ok(())
}

/// An `eth1` attachment in area 0 on the shared OSPFv3 profile.
fn eth1_flags(id: Id, v4: &str, v6: &str, router_id: &str, ospf: bool) -> Vec<String> {
    let mut f = strings(&[
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
    ]);
    if ospf {
        f.extend(strings(&[
            "--ospfv3-instance",
            OSPFV3_INSTANCE,
            "--ospfv3-router-id",
            router_id,
            "--ospfv3-area",
            OSPFV3_AREA,
            "--ospfv3-profile",
            OSPFV3_PROFILE,
            "--ospfv3-interface-profile",
            OSPFV3_PROFILE,
            "--ospfv3-bfd",
        ]));
    }
    f
}

async fn scenario(w: &mut World) -> anyhow::Result<()> {
    let (a, b) = (w.a()?, w.b()?);
    let full =
        |l: &str| format!("ospfv3 neighbor reached full link={l} neighbor={OSPFV3_ROUTER_ID_B}");
    let down = "bfd session down peer=fe80::[0-9a-f:]* diag=control-detection-time-expired";
    let killing = |l: &str| format!("bfd session down, killing ospfv3 neighbor link={l}");
    let (full0, full1) = (
        a.count_fresh(&full("eth0.0")).await,
        a.count_fresh(&full("eth1.0")).await,
    );

    a.provision_flags(&with_base(A, ospfv3(OSPFV3_ADDRESS_A, OSPFV3_ROUTER_ID)))
        .await?;
    b.provision_flags(&with_base(B, ospfv3(OSPFV3_ADDRESS_B, OSPFV3_ROUTER_ID_B)))
        .await?;
    a.provision_flags(&eth1_flags(
        A,
        &format!("{OSPFV3_BFD2_IP_A}/24"),
        OSPFV3_BFD2_ADDRESS_A.s(),
        OSPFV3_ROUTER_ID,
        true,
    ))
    .await?;
    // VRF enslavement flushes eth1's IPv6 addresses, so share the link-local
    // only after eth1 sits in rt1, and attach OSPFv3 after that.
    let (v4_b, v6_b) = (format!("{OSPFV3_BFD2_IP_B}/24"), OSPFV3_BFD2_ADDRESS_B.s());
    b.provision_flags(&eth1_flags(B, &v4_b, v6_b, OSPFV3_ROUTER_ID_B, false))
        .await?;
    share_link_local(w).await?;
    b.provision_flags(&eth1_flags(B, &v4_b, v6_b, OSPFV3_ROUTER_ID_B, true))
        .await?;
    a.wait_new(&full("eth0.0"), full0, 90).await?;
    a.wait_new(&full("eth1.0"), full1, 90).await?;

    log("two sessions to one fe80:: peer, one per arrival interface");
    session_on_interface(a, "eth0", "Up", 30).await?;
    session_on_interface(a, "eth1", "Up", 30).await?;

    log("UDP 3784 dropped on router-a eth1 only: eth1.0 goes down, eth0.0 stays Up");
    let (n_down, n_kill1, n_kill0) = (
        a.count(down),
        a.count(&killing("eth1.0")),
        a.count(&killing("eth0.0")),
    );
    bfd_filter(w, "eth1", true, true).await?;
    let result = async {
        a.wait_new(down, n_down, 10).await?;
        a.wait_new(&killing("eth1.0"), n_kill1, 5).await?;
        a.assert_delay_under((down, n_down), (&killing("eth1.0"), n_kill1), 1000)?;
        // The killed neighbor deregisters its session, so eth1 is absent from REST.
        session_on_interface(a, "eth0", "Up", 1).await?;
        a.assert_quiet(&killing("eth0.0"), n_kill0, 5).await?;
        a.assert_quiet(down, n_down + 1, 5).await
    }
    .await;
    let lifted = bfd_filter(w, "eth1", true, false).await;
    result?;
    lifted?;

    log("drop lifted: eth1.0 is Full and Up again");
    a.wait_new(&full("eth1.0"), full1 + 1, 90).await?;
    session_on_interface(a, "eth1", "Up", 30).await?;
    session_on_interface(a, "eth0", "Up", 5).await
}
