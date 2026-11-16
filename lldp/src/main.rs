use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_daemon::{bootstrap, watchdog};
use nos_lldp::{link::SharedPorts, reconcile, server};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{info, warn};

/// Default listen socket. Like `nos-lacpd`/`nos-interfaced`, `nos-lldpd` is a
/// single process handling every LLDP-enabled interface, so there's exactly
/// one fixed default rather than one derived per instance name.
const DEFAULT_LISTEN_SOCKET: &str = "/run/nos/lldp.sock";

#[derive(Parser)]
#[command(name = "nos-lldpd", about = "NOS LLDP (IEEE 802.1AB) daemon")]
#[allow(clippy::struct_field_names)] // matches lacp::main::Args's own *_socket naming
struct Args {
    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address rather than assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to listen on for LLDP neighbor queries (`nos show lldp
    /// neighbors`).
    #[arg(long, default_value = DEFAULT_LISTEN_SOCKET)]
    listen_socket: PathBuf,

    /// Unix socket to forward this process's log events to.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let identity = bootstrap::identity()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    bootstrap::init_tracing(
        "nos-lldpd",
        args.log_socket.clone(),
        identity.clone(),
        shutdown_rx.clone(),
    );
    nos_daemon::liveness::start(args.watchdog_socket.clone());
    info!(listen_socket = %args.listen_socket.display(), "nos-lldpd starting");

    let Some(config_socket) = watchdog::resolve_with_retry(
        &args.watchdog_socket,
        ServiceRef::Config,
        &mut shutdown_rx.clone(),
    )
    .await
    else {
        info!("shutdown signal received while resolving nos-configd, exiting");
        return Ok(());
    };

    let ports = SharedPorts::default();
    let server_task = server::start(&args.listen_socket, ports.clone(), &identity)
        .inspect_err(|e| tracing::error!(error = %e, "failed to start lldp IPC server"))
        .context("starting lldp IPC server")?;
    let reconcile_task = tokio::spawn(reconcile::run(config_socket, ports, shutdown_rx.clone()));

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");

    // Every running link sends its shutdown LLDPDU on the way out, so
    // neighbors drop us immediately rather than waiting out our TTL.
    let _ = shutdown_tx.send(true);
    if let Err(e) = reconcile_task.await {
        warn!(error = %e, "reconcile task ended abnormally");
    }
    server_task.abort();

    info!("shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT — SIGINT is what `nos-watchdog` sends
/// (`supervisor::shutdown_child`); SIGTERM is handled too so a directly-run
/// or container-stopped `nos-lldpd` still shuts down cleanly.
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
        let args = Args::try_parse_from(["nos-lldpd"]).unwrap();
        assert_eq!(
            args.listen_socket,
            std::path::PathBuf::from(DEFAULT_LISTEN_SOCKET)
        );
    }
}
