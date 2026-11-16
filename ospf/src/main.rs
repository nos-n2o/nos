use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

use nos_daemon::{bootstrap, watchdog};
use nos_ospf::boot::{self, BootCounter};
use nos_ospf::link::LinkManager;
use nos_ospf::{reconcile, rib_push_client, server};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;

#[derive(Parser)]
#[command(name = "nos-ospfd", about = "NOS OSPF daemon")]
struct Args {
    /// Name of the OSPF instance (from the running config's
    /// `ospf_instances`) this process is responsible for.
    #[arg(long)]
    instance: String,

    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address rather than assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket this instance's IPC query server (`OspfRequest::
    /// GetNeighbors`, backing `show ospf neigh`) listens on. Assigned and
    /// passed by `nos-watchdogd` at spawn time, mirroring `nos-bgpd`'s own
    /// `--listen-socket`.
    #[arg(long)]
    listen_socket: Option<PathBuf>,

    /// Unix socket to forward this process's log events to. Passed directly
    /// by nos-watchdog to every process it spawns (see `docs/architecture/supervision.md`).
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// Multiplies the per-second LSA-age-clock increment (default 1 = real
    /// time). Test/debug only — never set by nos-watchdogd's normal config-
    /// driven spawn path, only reachable via its opaque `--ospfd-arg` pass-
    /// through (see root `CLAUDE.md`'s "Memory profiling" for the identical
    /// pattern). Do not wire this into OspfProfile/nos-cli.
    #[arg(long, default_value_t = 1)]
    lsa_age_multiplier: u16,

    /// RFC 2328 §10.8's per-DBD-packet LSA-header budget override. Left
    /// unset (the real production default), each link derives its own
    /// budget from its effective MTU (`OspfProfile.mtu` if set, else the
    /// real resolved interface MTU) — see `exchange::mtu_based_max_headers`.
    /// Set only by `tools/verify-e2e.sh`'s `ospf-dbd-pagination` phase, via
    /// the same opaque `--ospfd-arg` pass-through, to force every link to a
    /// fixed value regardless of MTU, for deterministic multi-packet
    /// pagination over a small lab LSDB.
    #[arg(long)]
    dbd_max_headers: Option<usize>,

    /// Drop or duplicate the Nth outgoing exchange DBD, e.g. `drop:2,dup:3`
    /// (#607). Test-only, via `--ospfd-arg`; never a config field.
    #[arg(long, hide = true)]
    dbd_fault: Option<String>,

    /// Directory for this daemon's persisted state: the RFC 7474 boot count
    /// (`<instance>.boot`), which must survive restarts, and the RFC 3623
    /// graceful-restart marker (`<instance>.gr`, consumed at start).
    #[arg(long, default_value = "/var/lib/nos/ospfd")]
    state_dir: PathBuf,

    /// Weight budget per `PushOspfRoutes` frame (`OspfRouteUpdate::frames_with`).
    /// Unset: `nos_proto::rib::ospf_push_chunk()`. Test-only, via `--ospfd-arg`
    /// (the watchdog clears its children's environment, so `NOS_OSPF_PUSH_CHUNK`
    /// cannot reach a supervised daemon); never a config field.
    #[arg(long, hide = true)]
    push_chunk: Option<usize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let identity = bootstrap::identity()?;
    if let Some(spec) = &args.dbd_fault {
        nos_ospf_common::dbd_fault::install(spec).map_err(anyhow::Error::msg)?;
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // Log forwarding gets its own shutdown signal, flipped only once the
    // reconcile task is done: its exit runs `LinkManager::shutdown`'s RFC
    // 2328 §14.1 flush, whose log lines would otherwise never reach
    // `nos-logd` (the forwarding loop stops as soon as its signal flips).
    let (log_shutdown_tx, log_shutdown_rx) = watch::channel(false);
    bootstrap::init_tracing(
        format!("nos-ospfd[{}]", args.instance),
        args.log_socket.clone(),
        identity.clone(),
        log_shutdown_rx,
    );
    nos_daemon::liveness::start(args.watchdog_socket.clone());
    info!(instance = %args.instance, "nos-ospfd starting");

    let Some(config_socket) = watchdog::resolve_with_retry(
        &args.watchdog_socket,
        ServiceRef::Config,
        &mut shutdown_rx.clone(),
    )
    .await
    else {
        info!(instance = %args.instance, "shutdown signal received while resolving nos-configd, exiting");
        return Ok(());
    };

    let listen_socket = args
        .listen_socket
        .unwrap_or_else(|| PathBuf::from(format!("/run/nos/ospf-{}.sock", args.instance)));

    let (routing_table_tx, routing_table_rx) = watch::channel(None::<String>);
    let links = LinkManager::new(
        args.lsa_age_multiplier,
        args.dbd_max_headers,
        BootCounter::persistent(args.state_dir.join(format!("{}.boot", args.instance))),
    );
    let grace_marker = args.state_dir.join(format!("{}.gr", args.instance));
    links.set_after_graceful_restart(boot::take_grace_marker(&grace_marker, unix_now()));
    let (link_tx, link_rx) = watch::channel(nos_ospf::link_client::LinkTable::default());
    let link_task = tokio::spawn(nos_ospf::link_client::run(
        args.watchdog_socket.clone(),
        link_tx,
        shutdown_rx.clone(),
    ));
    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        args.watchdog_socket.clone(),
        args.instance.clone(),
        links.clone(),
        routing_table_tx,
        link_rx,
        shutdown_rx.clone(),
    ));
    let bfd_task = nos_ospf::bfd_client::spawn(
        args.watchdog_socket.clone(),
        links.clone(),
        routing_table_rx.clone(),
        shutdown_rx.clone(),
    );
    let rib_push_task = rib_push_client::spawn(
        args.watchdog_socket.clone(),
        links.clone(),
        routing_table_rx,
        shutdown_rx,
        args.push_chunk
            .filter(|&n| n > 0)
            .unwrap_or_else(nos_proto::rib::ospf_push_chunk),
    );
    let server_task = server::start(
        &listen_socket,
        args.instance.clone(),
        links.clone(),
        &identity,
    )
    .inspect_err(|e| {
        tracing::error!(instance = %args.instance, error = %e, "failed to start OSPF IPC server");
    })
    .context("starting OSPF IPC server")?;

    let planned_restart = wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!(instance = %args.instance, planned_restart, "shutdown signal received");
    // RFC 3623: announced before `shutdown_tx`, so the link tasks are still
    // running to send the Grace-LSAs, and `LinkManager::shutdown` (run when
    // the reconcile loop exits) then keeps this router's LSAs.
    if planned_restart {
        let grace_period = links.grace_period();
        if grace_period != 0 {
            // Lets the respawned process skip RFC 6987's on-startup period.
            match boot::write_grace_marker(&grace_marker, unix_now() + u64::from(grace_period)) {
                Ok(()) => info!(instance = %args.instance, "ospf graceful restart marker written"),
                Err(e) => {
                    tracing::warn!(instance = %args.instance, error = %e, "cannot write ospf graceful restart marker");
                }
            }
        }
        links.announce_graceful_restart().await;
    }

    let _ = shutdown_tx.send(true);
    if let Err(e) = reconcile_task.await {
        tracing::warn!(instance = %args.instance, error = %e, "reconcile task ended abnormally");
    }
    link_task.abort();
    rib_push_task.abort();
    bfd_task.abort();
    server_task.abort();

    info!(instance = %args.instance, "shutting down");
    let _ = log_shutdown_tx.send(true);
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Waits for SIGTERM or SIGINT. SIGINT is what `nos-watchdog` sends
/// (`supervisor::shutdown_child`) to stop or remove an instance; SIGTERM is
/// handled too so a directly-run or container-stopped `nos-ospfd` still
/// shuts down cleanly. Returns `true` for SIGTERM — a planned restart, the
/// only case that announces an RFC 3623 grace period.
async fn wait_for_shutdown_signal() -> anyhow::Result<bool> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    Ok(tokio::select! {
        _ = sigterm.recv() => true,
        _ = sigint.recv() => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn args_parse() {
        Args::command().debug_assert();
        let args = Args::try_parse_from(["nos-ospfd", "--instance", "o1"]).unwrap();
        assert_eq!((args.instance.as_str(), args.lsa_age_multiplier), ("o1", 1));
    }
}
