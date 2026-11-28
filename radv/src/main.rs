use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_daemon::{bootstrap, watchdog};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use nos_radv::{link_client, reconcile};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "nos-radvd", about = "NOS IPv6 Router Advertisement daemon")]
#[allow(clippy::struct_field_names)]
struct Args {
    /// Path to nos-watchdogd's broker socket.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Accepted because the watchdog always passes it; nothing listens until
    /// the `show` surface (#1585).
    #[arg(long, default_value = "/run/nos/radv.sock")]
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
        "nos-radvd",
        args.log_socket.clone(),
        identity,
        shutdown_rx.clone(),
    );
    nos_daemon::liveness::start(args.watchdog_socket.clone());
    info!("nos-radvd starting");

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

    let (links_tx, links_rx) = watch::channel(link_client::LinkTable::default());
    let link_client_task = tokio::spawn(link_client::run(
        args.watchdog_socket.clone(),
        links_tx,
        shutdown_rx.clone(),
    ));
    let reconcile_task = tokio::spawn(reconcile::run(config_socket, links_rx, shutdown_rx.clone()));

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");

    // Every link sends its final lifetime-0 RAs on the way out.
    let _ = shutdown_tx.send(true);
    let _ = link_client_task.await;
    if let Err(e) = reconcile_task.await {
        warn!(error = %e, "reconcile task ended abnormally");
    }
    info!("shutting down");
    Ok(())
}

/// SIGINT is what `nos-watchdog` sends; SIGTERM covers a directly-run daemon.
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
        let args = Args::try_parse_from(["nos-radvd"]).unwrap();
        assert_eq!(args.listen_socket, PathBuf::from("/run/nos/radv.sock"));
    }
}
