use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use nos_bfd::manager::{Demux, Manager};
use nos_bfd::micro_sessions::{self, Micro};
use nos_bfd::socket::{ReflectorNet, UdpNet};
use nos_bfd::{interface_client, server};
use nos_daemon::{bootstrap, watchdog};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};
use tracing::info;

/// One system-wide process, like `nos-lldpd`, so one fixed socket.
const DEFAULT_LISTEN_SOCKET: &str = "/run/nos/bfd.sock";

#[derive(Parser)]
#[command(name = "nos-bfdd", about = "NOS BFD (RFC 5880/5881) daemon")]
#[allow(clippy::struct_field_names)] // matches the other daemons' *_socket naming
struct Args {
    /// Path to nos-watchdogd's broker socket, used to find each table's
    /// nos-ribd (for its VRF device).
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to listen on for session registrations and queries.
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
        "nos-bfdd",
        args.log_socket.clone(),
        identity.clone(),
        shutdown_rx.clone(),
    );
    info!(listen_socket = %args.listen_socket.display(), "nos-bfdd starting");

    let demux = Demux::default();
    let net = UdpNet::new(args.watchdog_socket.clone(), demux.clone());
    let manager = Manager::new(net, demux);
    let server_task = server::start(&args.listen_socket, manager.clone(), &identity)
        .inspect_err(|e| tracing::error!(error = %e, "failed to start bfd IPC server"))
        .context("starting bfd IPC server")?;

    // RFC 7130 micro-BFD: the only config this daemon follows. Its sessions
    // go through the same manager; their Up sets go to nos-interfaced.
    let (push_tx, push_rx) = mpsc::channel(16);
    let sweep_task = tokio::spawn(nos_bfd::manager::sweep_loop(manager.clone()));
    let micro = Micro::new(manager.clone(), push_tx);
    let reflector = Arc::new(ReflectorNet::new(
        args.watchdog_socket.clone(),
        manager.reflector(),
    ));
    let (watchdog, mut sd) = (args.watchdog_socket.clone(), shutdown_rx.clone());
    let micro_task = tokio::spawn(async move {
        if let Some(config) =
            watchdog::resolve_with_retry(&watchdog, ServiceRef::Config, &mut sd).await
        {
            micro_sessions::run(config, micro, reflector, sd).await;
        }
    });
    let interface_task = tokio::spawn(interface_client::run(
        args.watchdog_socket.clone(),
        push_rx,
        shutdown_rx.clone(),
    ));

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(true);
    server_task.abort();
    manager.shutdown_all().await;
    sweep_task.abort();
    let _ = tokio::join!(micro_task, interface_task);
    info!("shutting down");
    Ok(())
}

/// SIGINT is what `nos-watchdog` sends; SIGTERM too for a container stop.
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
        let args = Args::try_parse_from(["nos-bfdd"]).unwrap();
        assert_eq!(args.listen_socket, PathBuf::from(DEFAULT_LISTEN_SOCKET));
    }
}
