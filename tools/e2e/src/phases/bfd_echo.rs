//! BFD Echo function (RFC 5880 §6.4, RFC 5881 §4, #290).

use reqwest::Method;

use super::bfd::{bfd_route, session_is, tc};
use crate::consts::*;
use crate::router::{log, strings, Router, A, B};
use crate::world::World;

/// Profile flags: `echo-mode affiliated` with 50 ms echoes.
fn echo() -> Vec<String> {
    strings(&["--bfd-echo-mode", "affiliated", "--bfd-echo-interval", "50"])
}

/// Polls `r`'s session to `peer` until REST reports Echo running and Control
/// slowed to at least a second (the Poll sequence of RFC 5880 §6.8.3 done).
async fn echo_running(r: &Router, peer: &str, secs: u64) -> anyhow::Result<()> {
    let path = format!("/v1/bfd/sessions?peer={peer}");
    let mut last = String::new();
    for _ in 0..secs * 5 {
        last = r.rest_expect(Method::GET, &path, None, 200).await?;
        let v: serde_json::Value = serde_json::from_str(&last)?;
        let s = &v[0];
        if s["echo_active"] == true
            && s["tx_interval_us"].as_u64().is_some_and(|t| t >= 1_000_000)
            && s["echo_interval_us"].as_u64().is_some_and(|t| t >= 50_000)
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    anyhow::bail!(
        "{}: no echo running with a slow control rate for {peer}: {last}",
        r.name()
    )
}

/// `bfd-echo`, self-contained. Both routers run `bfd-profile fast` (100 ms x
/// 3) with `echo-mode affiliated` (50 ms): once Up each logs `bfd echo
/// active` and REST shows `echo_active` with the control interval raised to
/// 1 s or more. A `tc` filter dropping only UDP 3785 on router-a (the Echo
/// port: Control keeps flowing) takes the session Down with
/// `echo-function-failed` within about `echo-interval x multiplier`, long
/// before a control detection time at 1 s would; lifting it brings it back Up
/// with Echo running again. Finally a real FRR `bfdd` (`router-f`) that
/// accepts Echo reaches Up and Echo runs through its forwarding too.
pub async fn bfd_echo(w: &mut World) -> anyhow::Result<()> {
    let mut fa = A.base_flags();
    fa.extend(bfd_route(BFD_PREFIX_B, IP_B.s()));
    fa.extend(echo());
    let mut fb = B.base_flags();
    fb.extend(bfd_route(BFD_PREFIX_A, IP_A.s()));
    fb.extend(echo());
    w.start(A, Some(fa), &[]).await?;
    w.start(B, Some(fb), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);

    let up_a = format!("bfd session up peer={IP_B}");
    let echo_a = format!("bfd echo active peer={IP_B}");
    let echo_b = format!("bfd echo active peer={IP_A}");
    let failed_a = format!("bfd session down peer={IP_B} diag=echo-function-failed");

    log("both Up, then Echo runs on both and Control slows to >= 1 s");
    a.wait(&up_a).await?;
    a.wait(&echo_a).await?;
    b.wait(&echo_b).await?;
    echo_running(a, IP_B.s(), 15).await?;
    echo_running(b, IP_A.s(), 15).await?;
    session_is(a, IP_B.s(), "Up", None, 5).await?;

    log("dropping UDP 3785 on router-a: Down by echo-function-failed, Control untouched");
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    let (n_failed, n_up, n_echo) = (a.count(&failed_a), a.count(&up_a), a.count(&echo_a));
    tc(&w.dock, &["qdisc", "add", "dev", "eth0", "clsact"]).await?;
    let dropped = tc(
        &w.dock,
        &[
            "filter", "add", "dev", "eth0", "ingress", "protocol", "ip", "u32", "match", "ip",
            "protocol", "17", "0xff", "match", "ip", "dport", "3785", "0xffff", "action", "drop",
        ],
    )
    .await;
    let result = async {
        dropped?;
        a.wait_new(&failed_a, n_failed, 5).await?;
        // Control still flows, so the session re-Ups at once and fails again
        // (the REST snapshot may show either state): the diag is what sticks.
        let path = format!("/v1/bfd/sessions?peer={IP_B}");
        let body = a.rest_expect(Method::GET, &path, None, 200).await?;
        anyhow::ensure!(
            body.contains("\"diag\":\"EchoFunctionFailed\""),
            "expected diag EchoFunctionFailed: {body}"
        );
        Ok(())
    }
    .await;
    let lifted = tc(&w.dock, &["qdisc", "del", "dev", "eth0", "clsact"]).await;
    result?;
    lifted?;

    log("filter lifted: Up again and Echo runs again");
    a.wait_new(&up_a, n_up, 30).await?;
    a.wait_new(&echo_a, n_echo, 30).await?;
    echo_running(a, IP_B.s(), 15).await?;

    log("interop: FRR bfdd accepting Echo reaches Up with Echo running through it");
    let conf = format!(
        "frr defaults traditional\nhostname router-f\n!\nbfd\n peer {IP_A}\n  \
         detect-multiplier 3\n  receive-interval 100\n  transmit-interval 100\n  \
         echo receive-interval 50\n  no shutdown\n exit\nexit\n"
    );
    w.dock.container_remove("router-f").await;
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    w.dock
        .start_plain_caps(
            "router-f",
            FRR_IMAGE,
            NET,
            IP_G.s(),
            &[
                "sh",
                "-c",
                "sed -i 's/^bfdd=no/bfdd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start",
            ],
            ("/etc/frr", "frr.conf", conf.as_bytes()),
            &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        )
        .await?;
    a.provision(&bfd_route(BFD_PREFIX_F, IP_G.s())).await?;
    a.wait(&format!("bfd session up peer={IP_G}")).await?;
    a.wait(&format!("bfd echo active peer={IP_G}")).await?;
    echo_running(a, IP_G.s(), 20).await?;
    session_is(a, IP_G.s(), "Up", None, 5).await?;
    w.dock.container_remove("router-f").await;
    Ok(())
}

/// `bfd-echo-unaffiliated`, self-contained (RFC 9747, #291). Router-a runs
/// `bfd-profile fast` with `echo-mode unaffiliated` (50 ms) under a static
/// route via router-b, which runs no BFD session at all and only forwards
/// (the gateway needs `ip_forward`, set here). Router-a's own Control
/// packets, looped back through router-b, bring the session Up (`bfd session
/// up`, REST `echo_only`) and the guarded route in; a `tc` filter dropping UDP
/// 3785 on router-a's ingress takes it Down by `echo-function-failed` within
/// about `echo-interval x multiplier` and ribd removes the route; lifting it
/// brings both back.
pub async fn bfd_echo_unaffiliated(w: &mut World) -> anyhow::Result<()> {
    let mut fa = A.base_flags();
    fa.extend(bfd_route(BFD_PREFIX_B, IP_B.s()));
    fa.extend(strings(&[
        "--bfd-echo-mode",
        "unaffiliated",
        "--bfd-echo-interval",
        "50",
    ]));
    w.start(A, Some(fa), &[]).await?;
    w.start(B, Some(B.base_flags()), &[]).await?;
    let a = w.a()?;

    log("router-b only forwards: ip_forward on, no BFD session on it");
    w.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
    w.dock
        .in_netns(
            NETNS_HELPER_IMAGE,
            "router-b",
            &["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
        )
        .await?;

    let up = format!("bfd session up peer={IP_B}");
    let failed = format!("bfd session down peer={IP_B} diag=echo-function-failed");
    let added = format!("added route prefix={BFD_PREFIX_B} gateway={IP_B}");
    let removed = format!("removed route prefix={BFD_PREFIX_B}");

    log("looped Control packets bring the session Up and the route in");
    a.wait(&up).await?;
    a.wait(&added).await?;
    let path = format!("/v1/bfd/sessions?peer={IP_B}");
    let body = a.rest_expect(Method::GET, &path, None, 200).await?;
    anyhow::ensure!(
        body.contains("\"echo_only\":true") && body.contains("\"echo_active\":true"),
        "expected an echo-only session: {body}"
    );
    session_is(a, IP_B.s(), "Up", None, 5).await?;

    log("dropping UDP 3785 on router-a: Down by echo-function-failed, route withdrawn");
    let (n_failed, n_removed, n_up, n_added) = (
        a.count(&failed),
        a.count(&removed),
        a.count(&up),
        a.count(&added),
    );
    tc(&w.dock, &["qdisc", "add", "dev", "eth0", "clsact"]).await?;
    let dropped = tc(
        &w.dock,
        &[
            "filter", "add", "dev", "eth0", "ingress", "protocol", "ip", "u32", "match", "ip",
            "protocol", "17", "0xff", "match", "ip", "dport", "3785", "0xffff", "action", "drop",
        ],
    )
    .await;
    let result = async {
        dropped?;
        a.wait_new(&failed, n_failed, 5).await?;
        a.wait_new(&removed, n_removed, 5).await?;
        session_is(a, IP_B.s(), "Down", Some("EchoFunctionFailed"), 5).await
    }
    .await;
    let lifted = tc(&w.dock, &["qdisc", "del", "dev", "eth0", "clsact"]).await;
    result?;
    lifted?;

    log("filter lifted: Up again and the route is back");
    a.wait_new(&up, n_up, 30).await?;
    a.wait_new(&added, n_added, 30).await?;
    session_is(a, IP_B.s(), "Up", None, 5).await?;
    Ok(())
}
