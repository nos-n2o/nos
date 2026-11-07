//! `bmp` (#878): the RFC 7854 exporter against a real GoBMP collector.
//!
//! GoBMP (`--dump=console -v=5`) prints one JSON object per Peer Up/Down
//! (`msg_type` 10) and logs `client ... accepted`; it parses Initiation and
//! discards it (an error is logged only when it does not parse) and prints
//! nothing for Termination. Those two are covered by the codec unit tests.

use std::time::Duration;

use anyhow::bail;

use crate::consts::*;
use crate::router::{log, strings, A, B};
use crate::world::World;

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
    Ok(())
}
