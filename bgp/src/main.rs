use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_bgp::session::SessionManager;
use nos_bgp::{
    acl_push_client, fdb_push_client, reconcile, rib_push_client, server, vpn_push_client,
};
use nos_daemon::{bootstrap, watchdog};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{info, warn};

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Parser)]
#[command(name = "nos-bgpd", about = "NOS BGP-4 daemon")]
struct Args {
    /// Name of the BGP instance (from the running config's `bgp_instances`)
    /// this process is responsible for.
    #[arg(long)]
    instance: String,

    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address rather than assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to listen on for session-summary queries (e.g. from `nos
    /// show bgp brief`). Defaults to a path derived from `--instance` for
    /// standalone/dev runs; nos-watchdog always passes this explicitly for
    /// supervised instances.
    #[arg(long)]
    listen_socket: Option<PathBuf>,

    /// Unix socket to forward this process's log events to. Passed directly
    /// by nos-watchdog to every process it spawns (see `docs/architecture/supervision.md`).
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// Only present when built with `--features dhat-heap`. Path to write
    /// the dhat heap-profile report to on exit — load it at
    /// <https://nnethercote.github.io/dh_view/dh_view.html>.
    #[cfg(feature = "dhat-heap")]
    #[arg(long, default_value = "dhat-heap.json")]
    profile_memory_out: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::builder()
        .file_name(args.profile_memory_out.clone())
        .build();

    // Handed over by nos-watchdogd on stdin; there is no plaintext fallback.
    let identity = bootstrap::identity()?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    bootstrap::init_tracing(
        format!("nos-bgpd[{}]", args.instance),
        args.log_socket.clone(),
        identity.clone(),
        shutdown_rx.clone(),
    );
    nos_daemon::liveness::start(args.watchdog_socket.clone());
    info!(instance = %args.instance, peer = ?identity.peer(), "nos-bgpd starting");
    #[cfg(feature = "dhat-heap")]
    info!(out = %args.profile_memory_out.display(), "memory profiling enabled (dhat)");

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
        .unwrap_or_else(|| PathBuf::from(format!("/run/nos/bgp-{}.sock", args.instance)));

    let sessions = SessionManager::new(args.instance.clone());
    let rib_push_task = rib_push_client::spawn(
        args.watchdog_socket.clone(),
        sessions.clone(),
        shutdown_rx.clone(),
    );
    let igp_task = nos_bgp::igp_client::spawn(
        args.watchdog_socket.clone(),
        sessions.clone(),
        shutdown_rx.clone(),
    );
    let fdb_push_task = fdb_push_client::spawn(
        args.watchdog_socket.clone(),
        sessions.clone(),
        fdb_push_client::Feed::Domains,
        shutdown_rx.clone(),
    );
    let ip_vrf_push_task = fdb_push_client::spawn(
        args.watchdog_socket.clone(),
        sessions.clone(),
        fdb_push_client::Feed::Tables,
        shutdown_rx.clone(),
    );
    let vpn_push_task = vpn_push_client::spawn(
        args.watchdog_socket.clone(),
        sessions.clone(),
        shutdown_rx.clone(),
    );
    let bfd_task = nos_bgp::bfd_client::spawn(
        args.watchdog_socket.clone(),
        sessions.clone(),
        shutdown_rx.clone(),
    );
    let damping_task = tokio::spawn({
        let sessions = sessions.clone();
        async move {
            let mut tick = tokio::time::interval(nos_bgp::damping::TICK);
            loop {
                tick.tick().await;
                sessions.damping_tick().await;
                sessions.mac_mobility_tick().await;
            }
        }
    });
    let acl_push_task = acl_push_client::spawn(
        args.watchdog_socket.clone(),
        sessions.clone(),
        shutdown_rx.clone(),
    );
    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        args.watchdog_socket.clone(),
        args.instance.clone(),
        sessions.clone(),
        shutdown_rx,
    ));
    let server_task = server::start(
        &listen_socket,
        args.instance.clone(),
        sessions,
        &identity,
        args.watchdog_socket.clone(),
    )
    .inspect_err(|e| {
        tracing::error!(instance = %args.instance, error = %e, "failed to start BGP IPC server");
    })
    .context("starting BGP IPC server")?;

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!(instance = %args.instance, "shutdown signal received");

    let _ = shutdown_tx.send(true);
    if let Err(e) = reconcile_task.await {
        warn!(instance = %args.instance, error = %e, "reconcile task ended abnormally");
    }
    if let Err(e) = rib_push_task.await {
        warn!(instance = %args.instance, error = %e, "rib push task ended abnormally");
    }
    if let Err(e) = fdb_push_task.await {
        warn!(instance = %args.instance, error = %e, "fdb push task ended abnormally");
    }
    if let Err(e) = ip_vrf_push_task.await {
        warn!(instance = %args.instance, error = %e, "ip-vrf push task ended abnormally");
    }
    if let Err(e) = vpn_push_task.await {
        warn!(instance = %args.instance, error = %e, "vpn push task ended abnormally");
    }
    if let Err(e) = acl_push_task.await {
        warn!(instance = %args.instance, error = %e, "acl push task ended abnormally");
    }
    if let Err(e) = igp_task.await {
        warn!(instance = %args.instance, error = %e, "igp task ended abnormally");
    }
    if let Err(e) = bfd_task.await {
        warn!(instance = %args.instance, error = %e, "bfd task ended abnormally");
    }
    server_task.abort();
    damping_task.abort();

    info!(instance = %args.instance, "shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT. SIGINT is what `nos-watchdog` sends
/// (`supervisor::shutdown_child`); SIGTERM is handled too so a directly-run
/// or container-stopped `nos-bgpd` still shuts down its sessions cleanly
/// instead of relying on a forced kill.
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn args_parse() {
        Args::command().debug_assert();
        let args = Args::try_parse_from(["nos-bgpd", "--instance", "r1"]).unwrap();
        assert_eq!(args.instance, "r1");
    }
}
