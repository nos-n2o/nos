//! `acl` (#541, #543): `nos-acld` compiles an ACL to tc on router-a's `eth0`
//! ingress; the BGP session from router-b is the signal, and `show acl`
//! (`GET /v1/acl/EDGE`) reads the matching counters. Step 6 (#561) feeds
//! flowspec rules through `nos-acld --flowspec-file`.

use std::time::{Duration, Instant};

use reqwest::Method;

use crate::consts::*;
use crate::docker::Dock;
use crate::lab::Addr;
use crate::router::{log, Router};
use crate::world::World;

const ESTABLISHED: &str = "bgp session established";
const STARTING: &str = "nos-acld starting";
const ENDED: &str = "bgp session ended";
/// `wait_new` counts its own pattern, so each compile has its full line.
/// The optimiser (#542) decides the numbers, all deterministic:
/// - step 1: `p-bgp` and `p-icmp` both permit, as the default does, so both
///   are trailing and dropped: no level, only the two default filters;
/// - step 2: `d-bgp` (deny tcp from router-b) precedes `p-bgp`, which it
///   hides (same match): shadowed=1, `p-icmp` trailing; one level with one
///   IPv4 filter, plus the defaults = 3 filters;
/// - step 3: `p-bgp` first now hides `d-bgp`, and `p-bgp`/`p-icmp` are
///   trailing: back to the defaults alone.
const COMPILED_1: &str = "compiled acl acl=EDGE rules=2 filters=2 levels=0 shadowed=0";
const COMPILED_2: &str = "compiled acl acl=EDGE rules=3 filters=3 levels=1 shadowed=1";
const COMPILED_3: &str = "compiled acl acl=EDGE rules=3 filters=2 levels=0 shadowed=1";
/// Step 5, `EDGE2`: 8 `deny udp` rules on distinct /25s (one filter each:
/// the prefix fixes IPv4), 2 `deny tcp` port ranges (no prefix: IPv4 and
/// IPv6 = 4 filters), `p-bgp` permit tcp 179, a `deny udp` /26 inside the
/// first /25 (shadowed) and a trailing `permit` any. Shadowing runs first,
/// then the trailing `permit` and `p-bgp` (permit = the default) are popped;
/// the 10 left are pairwise disjoint: levels=1, filters = 8 + 4 + 2 defaults.
const COMPILED_5: &str = "compiled acl acl=EDGE2 rules=13 filters=14 levels=1 shadowed=1";
const ATTACHED_5: &str = "acl attached interface=eth0 direction=in acl=EDGE2";
const ATTACHED: &str = "acl attached interface=eth0 direction=in acl=EDGE";
/// Step 2b (#544): router-b's TCP from its address, denied and sampled on
/// router-a's `eth0` ingress (`sport`/`dport` depend on who connects).
fn logged_line() -> String {
    format!("acl log acl=EDGE rule=d-bgp interface=eth0 direction=in src={IP_B} dst={IP_A} proto=6")
}
const DETACHED: &str = "acl detached interface=eth0 direction=in";
/// Step 6: the snapshot `nos-acld` reads, and what it logs. Rule 0 drops
/// router-b's TCP (prio 10); rule 1 (packet length) has no flower key.
const FS_RECEIVED: &str = "flowspec rules received instance=e2e rules=2 installable=1 devices=1";
const FS_APPLIED: &str = "flowspec applied interface=eth0 rules=1";
const FS_UNSUPPORTED: &str =
    "flowspec rule unsupported instance=e2e flow=len =64 reason=packet length: no flower key";
const FS_CLEARED: &str = "flowspec applied interface=eth0 rules=0";
/// Short enough that a blocked session drops within a wait; negotiated
/// down on both sides (the lower hold time wins, RFC 4271 §4.2).
const HOLD_TIME: &str = "9";

/// `PUT`s rule `d-bgp` (deny every TCP segment from router-b, `log` as
/// given) at `place` (`before=p-bgp`, `after=p-bgp`) in one REST
/// transaction, then commits.
async fn put_d_bgp(a: &Router, place: &str, log: bool) -> anyhow::Result<()> {
    let tx = format!("/v1/transactions/{REST_TX}");
    let _ = a.rest(Method::DELETE, &tx, None).await;
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    let rule = serde_json::json!({
        "name": "d-bgp",
        "action": "Deny",
        "protocol": "tcp",
        "source": format!("{IP_B}/32"),
        "log": log,
    });
    a.rest_expect(
        Method::PUT,
        &format!("{tx}/acl/EDGE/rule/d-bgp?{place}"),
        Some(&rule.to_string()),
        200,
    )
    .await?;
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await
        .map(drop)
}

/// One rule's entry in a `GET /v1/acl/<name>` body.
fn rule_of<'a>(acl: &'a serde_json::Value, name: &str) -> Option<&'a serde_json::Value> {
    acl["rules"].as_array()?.iter().find(|r| r["name"] == name)
}

/// Polls `GET /v1/acl/EDGE` until `d-bgp` has counted a packet. Router-b
/// keeps retrying its session, and every segment of it is denied.
async fn wait_d_bgp_counted(a: &Router) -> anyhow::Result<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let body = a
            .rest_expect(Method::GET, "/v1/acl/EDGE", None, 200)
            .await?;
        let acl: serde_json::Value = serde_json::from_str(&body)?;
        if rule_of(&acl, "d-bgp").is_some_and(|r| r["packets"].as_u64() > Some(0)) {
            return Ok(acl);
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "d-bgp never counted a packet: {body}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// `show acl`: attachments, counters of the live rule, the dropped rules at
/// 0 and a 404 for an unknown name.
async fn check_counters(a: &Router) -> anyhow::Result<()> {
    let acl = wait_d_bgp_counted(a).await?;
    anyhow::ensure!(
        acl["attached"] == serde_json::json!([{"interface": "eth0", "direction": "In"}]),
        "attached: {acl}"
    );
    let d = rule_of(&acl, "d-bgp").ok_or_else(|| anyhow::anyhow!("no d-bgp: {acl}"))?;
    anyhow::ensure!(
        d["bytes"].as_u64() > Some(0) && d["dropped"].is_null(),
        "d-bgp: {d}"
    );
    // `p-bgp` is hidden by `d-bgp`, `p-icmp` equals the default: no filter.
    for (name, why) in [("p-bgp", "shadowed"), ("p-icmp", "trailing")] {
        let r = rule_of(&acl, name).ok_or_else(|| anyhow::anyhow!("no {name}: {acl}"))?;
        anyhow::ensure!(r["dropped"] == why && r["packets"] == 0, "{name}: {r}");
    }
    let (status, _) = a.rest(Method::GET, "/v1/acl/NOPE", None).await?;
    anyhow::ensure!(status == 404, "unknown acl: {status}");
    let all = a.rest_expect(Method::GET, "/v1/acl", None, 200).await?;
    anyhow::ensure!(all.contains("\"EDGE\""), "GET /v1/acl: {all}");
    Ok(())
}

/// Writes router-a's flowspec file: instance `e2e` on `eth0`, `rules`.
async fn write_flowspec(dock: &Dock, a: &Router, rules: serde_json::Value) -> anyhow::Result<()> {
    let set = serde_json::json!({ "instance": "e2e", "devices": ["eth0"], "rules": rules });
    dock.upload(
        a.name(),
        FLOWSPEC_DIR,
        FLOWSPEC_FILE,
        set.to_string().as_bytes(),
    )
    .await
}

/// Polls `GET /v1/flowspec` until rule 0 has counted a packet.
async fn wait_flowspec_counted(a: &Router) -> anyhow::Result<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let body = a
            .rest_expect(Method::GET, "/v1/flowspec", None, 200)
            .await?;
        let rows: serde_json::Value = serde_json::from_str(&body)?;
        if rows[0]["packets"].as_u64() > Some(0) {
            return Ok(rows);
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "flowspec rule 0 never counted a packet: {body}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Step 6 (#561): a flowspec drop of router-b's TCP ends the session and
/// counts; a packet-length rule is unsupported, logged once; an empty
/// snapshot clears both and the session comes back.
async fn flowspec(dock: &Dock, a: &Router) -> anyhow::Result<()> {
    let num = |value: u64| serde_json::json!([{"and": false, "lt": false, "gt": false, "eq": true, "value": value}]);
    let rules = serde_json::json!([
        {
            "flow": format!("src {IP_B}/32 proto =6"),
            "ipv6": false,
            "components": [
                {"Source": {"prefix": format!("{IP_B}/32"), "offset": 0}},
                {"Protocol": num(6)},
            ],
            "actions": [{"RateBytes": 0.0}],
        },
        {
            "flow": "len =64",
            "ipv6": false,
            "components": [{"PacketLen": num(64)}],
            "actions": [{"RateBytes": 0.0}],
        },
    ]);
    let (received, applied, unsupported, ended) = (
        a.count(FS_RECEIVED),
        a.count(FS_APPLIED),
        a.count(FS_UNSUPPORTED),
        a.count(ENDED),
    );
    write_flowspec(dock, a, rules).await?;
    a.wait_new(FS_RECEIVED, received, 30).await?;
    a.wait_new(FS_APPLIED, applied, 30).await?;
    a.wait_new(FS_UNSUPPORTED, unsupported, 30).await?;
    a.wait_new(ENDED, ended, 60).await?;
    let rows = wait_flowspec_counted(a).await?;
    anyhow::ensure!(
        rows.as_array().map(Vec::len) == Some(2)
            && rows[0]["unsupported"].is_null()
            && rows[0]["bytes"].as_u64() > Some(0)
            && rows[0]["actions"] == serde_json::json!(["rate 0 bytes/s"])
            && rows[1]["unsupported"] == "packet length: no flower key"
            && rows[1]["packets"] == 0,
        "GET /v1/flowspec: {rows}"
    );
    anyhow::ensure!(
        a.count(FS_UNSUPPORTED) == unsupported + 1,
        "the unsupported rule logged more than once"
    );

    log("step 6b: an empty flowspec snapshot clears the rules: the session comes back");
    let (est, cleared) = (a.count(ESTABLISHED), a.count(FS_CLEARED));
    write_flowspec(dock, a, serde_json::json!([])).await?;
    a.wait_new(FS_CLEARED, cleared, 30).await?;
    a.wait_new(ESTABLISHED, est, 60).await?;
    let body = a
        .rest_expect(Method::GET, "/v1/flowspec", None, 200)
        .await?;
    anyhow::ensure!(
        body.trim() == "[]",
        "GET /v1/flowspec after clearing: {body}"
    );
    Ok(())
}

pub async fn acl(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    // A hold-time change restarts the session (`diff_peers`).
    let est = a.count(ESTABLISHED);
    a.provision(&["--hold-time", HOLD_TIME]).await?;
    a.wait_new(ESTABLISHED, est, 60).await?;

    // The rules match router-b's address, not port 179: who opened the
    // session (so which side owns port 179) is collision resolution's
    // choice, and router-a's REST API (from the harness host) must stay
    // reachable through every step.
    log("step 1: EDGE (default permit, p-bgp, p-icmp) on eth0 in: the session stays");
    let (compiled, attached, ended) = (a.count(COMPILED_1), a.count(ATTACHED), a.count(ENDED));
    a.provision(&[
        "--acl-default",
        "EDGE=permit",
        "--acl-rule",
        &format!("EDGE,p-bgp,permit,tcp,{IP_B}/32,any,any"),
        "--acl-rule",
        "EDGE,p-icmp,permit,icmp,any,any,any",
        "--acl-in",
        "eth0=EDGE",
    ])
    .await?;
    a.wait_new(COMPILED_1, compiled, 30).await?;
    a.wait_new(ATTACHED, attached, 30).await?;
    a.assert_quiet(ENDED, ended, 12).await?;

    log("step 2: d-bgp inserted before p-bgp: the session drops, show acl counts it");
    let (compiled, ended) = (a.count(COMPILED_2), a.count(ENDED));
    put_d_bgp(a, "before=p-bgp", false).await?;
    a.wait_new(COMPILED_2, compiled, 30).await?;
    a.wait_new(ENDED, ended, 60).await?;
    check_counters(a).await?;

    log("step 2a (#663): nos-acld stops and restarts: the drop keeps holding");
    let (started, detached, est, compiled) = (
        a.count(STARTING),
        a.count(DETACHED),
        a.count(ESTABLISHED),
        a.count(COMPILED_2),
    );
    w.dock
        .signal_process("router-a", "nos-acld", "-INT")
        .await?;
    a.wait_new(STARTING, started, 60).await?;
    a.wait_new(COMPILED_2, compiled, 30).await?;
    a.assert_quiet(ESTABLISHED, est, 20).await?;
    anyhow::ensure!(
        a.count(DETACHED) == detached,
        "stopping nos-acld detached a filter"
    );

    log("step 2b: d-bgp logs: router-b's retries show as acl log lines");
    let (compiled, logged) = (a.count(COMPILED_2), a.count(&logged_line()));
    put_d_bgp(a, "before=p-bgp", true).await?;
    a.wait_new(COMPILED_2, compiled, 30).await?;
    // The kernel samples one packet in 100 (#699): the session's few retries
    // would rarely log, so router-b opens 800 TCP connections to router-a
    // (each a denied SYN; P(none sampled) = 0.99^800, under 0.04%). Router-b's
    // address sits in its VRF, so a plain `/dev/tcp` connect from the default
    // netns is "Network is unreachable" and sends nothing (#933): perl binds
    // each socket to the VRF device (SO_BINDTODEVICE = 25; root: `CAP_NET_RAW`). The new chain
    // lands a moment after `compiled`: repeat until a line shows.
    let script = format!(
        "use Socket; use Fcntl; my @s; for (1..800) {{ \
         socket(my $f, AF_INET, SOCK_STREAM, 0) or next; \
         setsockopt($f, SOL_SOCKET, 25, \"{RLFA_VRF}\") or die \"bind: $!\"; \
         fcntl($f, F_SETFL, O_NONBLOCK); \
         connect($f, sockaddr_in(179, inet_aton(\"{IP_A}\"))); push @s, $f }} sleep 2"
    );
    for _ in 0..6 {
        let (code, out) = w
            .dock
            .exec_root("router-b", &["perl", "-e", &script])
            .await?;
        anyhow::ensure!(code == 0, "router-b SYN burst failed ({code}): {out}");
        if a.count(&logged_line()) > logged {
            break;
        }
    }
    a.wait_new(&logged_line(), logged, 30).await?;

    log("step 3: d-bgp moved after p-bgp: the session comes back");
    let (est, compiled) = (a.count(ESTABLISHED), a.count(COMPILED_3));
    put_d_bgp(a, "after=p-bgp", false).await?;
    a.wait_new(COMPILED_3, compiled, 30).await?;
    a.wait_new(ESTABLISHED, est, 60).await?;

    log("step 4: acl in removed: detached, the session stays");
    let (detached, ended) = (a.count(DETACHED), a.count(ENDED));
    a.provision(&["--acl-in", "eth0="]).await?;
    a.wait_new(DETACHED, detached, 30).await?;
    a.assert_quiet(ENDED, ended, 12).await?;

    log("step 5: EDGE2, disjoint rules packed into one level, a shadowed and a trailing rule");
    let mut flags = vec!["--acl-default".to_string(), "EDGE2=permit".to_string()];
    let mut rule = |spec: String| flags.extend(["--acl-rule".to_string(), format!("EDGE2,{spec}")]);
    for (i, net) in (0..4)
        .flat_map(|o| {
            [
                format!("198.51.{}.0/25", 100 + o),
                format!("198.51.{}.128/25", 100 + o),
            ]
        })
        .enumerate()
    {
        rule(format!("u{i},deny,udp,any,{net},any"));
    }
    rule("t1,deny,tcp,any,any,1000-2000".into());
    rule("t2,deny,tcp,any,any,3000-4000".into());
    rule("p-bgp,permit,tcp,any,any,179".into());
    rule("shadowed,deny,udp,any,198.51.100.0/26,any".into());
    rule("trailing,permit,any,any,any,any".into());
    flags.extend(["--acl-in".to_string(), "eth0=EDGE2".to_string()]);
    let (compiled, attached, ended) = (a.count(COMPILED_5), a.count(ATTACHED_5), a.count(ENDED));
    a.provision(&flags).await?;
    a.wait_new(COMPILED_5, compiled, 30).await?;
    a.wait_new(ATTACHED_5, attached, 30).await?;
    a.assert_quiet(ENDED, ended, 12).await?;
    let detached = a.count(DETACHED);
    a.provision(&["--acl-in", "eth0="]).await?;
    a.wait_new(DETACHED, detached, 30).await?;

    log("step 6: flowspec (#561): a drop rule ends the session, show counts it");
    flowspec(&w.dock, a).await?;

    // Leave the default hold time to the phases after this one.
    let est = a.count(ESTABLISHED);
    a.provision(&["--no-hold-time"]).await?;
    a.wait_new(ESTABLISHED, est, 60).await
}

/// `flowspec-dataplane` (#562): the destination of every rule, router-a's
/// own address, so router-g's probes arrive on its `eth0`. Not port 8080:
/// that is the REST API the harness drives router-a through.
const FSD_DEST: Addr = Addr("10.50.0.2/32");
const FSD_TCP_PORT: &str = "9999";
const FSD_UDP_PORT: &str = "9998";
/// nos-provision's default BGP instance, the `instance` of every push.
const FSD_INSTANCE: &str = "r1";

/// `flowspec applied` with `n` rules on router-a's `eth0`.
fn fsd_applied(n: usize) -> String {
    format!("flowspec applied interface=eth0 rules={n}")
}

/// `gobgp global rib <verb> -a ipv4-flowspec match <m> [then <then>]`.
fn fsd_rule(verb: &str, m: &[&str], then: &[&str]) -> Vec<String> {
    let mut args = vec!["global", "rib", verb, "-a", "ipv4-flowspec", "match"];
    args.extend_from_slice(m);
    if verb == "add" {
        args.push("then");
        args.extend_from_slice(then);
    }
    args.into_iter().map(str::to_string).collect()
}

/// Sends `script` (a bash `/dev/tcp` or `/dev/udp` probe) from router-g
/// until `GET /v1/flowspec`'s row whose actions contain `action` counts a
/// packet; that row.
async fn fsd_counted(w: &World, script: &str, action: &str) -> anyhow::Result<serde_json::Value> {
    let a = w.a()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        // A dropped SYN would retry for minutes: `timeout` bounds it. The
        // exit code is the probe's, refused or timed out, and is ignored.
        w.dock
            .exec("router-g", &["timeout", "2", "bash", "-c", script])
            .await?;
        let body = a
            .rest_expect(Method::GET, "/v1/flowspec", None, 200)
            .await?;
        let rows: serde_json::Value = serde_json::from_str(&body)?;
        let row = rows.as_array().and_then(|r| {
            r.iter().find(|r| {
                r["actions"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|x| x == action))
            })
        });
        if let Some(row) = row.filter(|r| r["packets"].as_u64() > Some(0)) {
            return Ok(row.clone());
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "no flowspec rule with '{action}' counted a packet: {body}"
        );
    }
}

/// `show bgp flowspec` over REST must contain `want`.
async fn fsd_show_contains(a: &Router, want: &str) -> anyhow::Result<()> {
    let body = a
        .rest_expect(Method::GET, "/v1/bgp/flowspec", None, 200)
        .await?;
    anyhow::ensure!(
        body.contains(want),
        "show bgp flowspec lacks {want}: {body}"
    );
    Ok(())
}

/// `flowspec-dataplane` (#562): GoBGP (router-g) originates flowspec rules
/// to router-a, whose `nos-bgpd` validates them (a covering unicast route
/// from GoBGP too), pushes the valid best ones to `nos-acld`, which installs
/// them on `eth0` (`flowspec` set on it): a TCP drop counts router-g's
/// probes, a rate limit (police) counts its UDP, a packet-length rule is
/// unsupported, and withdrawing them clears `eth0`.
pub async fn flowspec_dataplane(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let g_up = format!("bgp session established peer={IP_G}");
    let base = a.count(&g_up);
    log("router-a: a flowspec peer-group toward GoBGP, flowspec on eth0");
    let flags = |on: &str| {
        crate::router::strings(&[
            "--address",
            &format!("{IP_A}/24"),
            "--asn",
            &ASN_A.to_string(),
            "--router-id",
            RID_A,
            "--peer-group",
            "pg-fs",
            "--remote-as",
            &ASN_G.to_string(),
            "--peer",
            IP_G.s(),
            "--flowspec",
            "--flowspec-interface",
            &format!("eth0={on}"),
        ])
    };
    a.provision_flags(&flags("on")).await?;
    super::bgp::start_gobgp(w, &["ipv4-unicast", "ipv4-flowspec"]).await?;
    let a = w.a()?;
    a.wait_new(&g_up, base, 60).await?;
    // RFC 8955 section 6: the rules' destination needs a unicast route from
    // the same originator. The connected route stays the one installed.
    super::bgp::gobgp(w, &["global", "rib", "add", "-a", "ipv4", SUBNET.s()]).await?;

    log("step 1: drop TCP from router-g: installed, counted, shown");
    let tcp = [
        "destination",
        FSD_DEST.s(),
        "source",
        &format!("{IP_G}/32"),
        "protocol",
        "tcp",
        "destination-port",
        &format!("=={FSD_TCP_PORT}"),
    ];
    let applied = a.count(&fsd_applied(1));
    super::bgp::gobgp_owned(w, fsd_rule("add", &tcp, &["discard"])).await?;
    a.wait_new(&fsd_applied(1), applied, 60).await?;
    let probe = format!("echo > /dev/tcp/{IP_A}/{FSD_TCP_PORT}");
    let row = fsd_counted(w, &probe, "rate 0 bytes/s").await?;
    anyhow::ensure!(
        row["instance"] == FSD_INSTANCE && row["unsupported"].is_null(),
        "drop rule: {row}"
    );
    fsd_show_contains(a, "\"dataplane\":\"installed\"").await?;

    log("step 2: rate-limit UDP: a police filter that counts");
    let udp = [
        "destination",
        FSD_DEST.s(),
        "protocol",
        "udp",
        "destination-port",
        &format!("=={FSD_UDP_PORT}"),
    ];
    let applied = a.count(&fsd_applied(2));
    super::bgp::gobgp_owned(w, fsd_rule("add", &udp, &["rate-limit", "1000"])).await?;
    a.wait_new(&fsd_applied(2), applied, 60).await?;
    let probe = format!("echo x > /dev/udp/{IP_A}/{FSD_UDP_PORT}");
    fsd_counted(w, &probe, "rate 1000 bytes/s").await?;

    log("step 3: a packet-length rule is unsupported, logged and shown");
    let len = ["destination", FSD_DEST.s(), "packet-length", "==64"];
    let unsupported = format!(
        "flowspec rule unsupported instance={FSD_INSTANCE} flow=.*reason=packet length: no flower key"
    );
    let base = a.count(&unsupported);
    super::bgp::gobgp_owned(w, fsd_rule("add", &len, &["discard"])).await?;
    a.wait_new(&unsupported, base, 60).await?;
    fsd_show_contains(a, "unsupported (packet length: no flower key)").await?;

    log("step 4: nos-acld is killed: nos-bgpd reconnects and re-pushes, rules count again");
    let reconnect = "connected to nos-acld, pushing flowspec rules";
    let (rebase, applied) = (a.count(reconnect), a.count(&fsd_applied(2)));
    w.dock.kill_process("router-a", "nos-acld").await?;
    let a = w.a()?;
    a.wait_new(reconnect, rebase, 60).await?;
    a.wait_new(&fsd_applied(2), applied, 60).await?;
    let probe = format!("echo > /dev/tcp/{IP_A}/{FSD_TCP_PORT}");
    fsd_counted(w, &probe, "rate 0 bytes/s").await?;
    let a = w.a()?;
    fsd_show_contains(a, "\"dataplane\":\"installed\"").await?;

    log("step 5: GoBGP withdraws every rule: eth0 is cleared");
    let cleared = a.count(&fsd_applied(0));
    for m in [&tcp[..], &udp[..], &len[..]] {
        super::bgp::gobgp_owned(w, fsd_rule("del", m, &[])).await?;
    }
    a.wait_new(&fsd_applied(0), cleared, 60).await?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let body = a
            .rest_expect(Method::GET, "/v1/flowspec", None, 200)
            .await?;
        if body.trim() == "[]" {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "rules left after the withdrawal: {body}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Leave router-a as the phases after this one expect it.
    w.dock.container_remove("router-g").await;
    w.a()?.provision_flags(&flags("off")).await
}
