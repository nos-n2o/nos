use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use nos_daemon::{bootstrap, watchdog};
use nos_interface::driver::{InterfaceDriver, LinuxInterfaceDriver, NoopInterfaceDriver};
use nos_interface::{reconcile, server, Interfaces};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{watch, RwLock};
use tracing::{info, warn};

/// Default listen socket. Unlike `nos-ribd` (one instance per routing
/// table), `nos-interfaced` is a single process managing every configured
/// interface, so there's exactly one fixed default rather than one derived
/// per instance name.
const DEFAULT_LISTEN_SOCKET: &str = "/run/nos/interface.sock";

/// Which backend applies desired interface state to the OS. `Noop` is the
/// portable default off Linux (and for tests); `Linux` is the real
/// `rtnetlink`-backed implementation. Deliberately not shared with
/// `nos-ribd`'s own `DriverKind` — each crate defines its own, per the
/// star-dependency rule.
#[derive(Clone, Copy, clap::ValueEnum)]
enum DriverKind {
    Noop,
    Linux,
}

#[cfg(target_os = "linux")]
fn default_driver_kind() -> DriverKind {
    DriverKind::Linux
}
#[cfg(not(target_os = "linux"))]
fn default_driver_kind() -> DriverKind {
    DriverKind::Noop
}

#[derive(Parser)]
#[command(name = "nos-interfaced", about = "NOS interface reconciliation daemon")]
struct Args {
    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address rather than assuming a hardcoded default, and (with
    /// `--driver linux`) to resolve the owning `nos-ribd` instance for a
    /// routing table's VRF interface name.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to listen on for interface queries (e.g. from `nos show
    /// interface`).
    #[arg(long, default_value = DEFAULT_LISTEN_SOCKET)]
    listen_socket: PathBuf,

    /// Which backend applies desired interface state to the OS.
    #[arg(long, value_enum, default_value_t = default_driver_kind())]
    driver: DriverKind,

    /// Path to this driver's own private persisted broadcast-domain-name ->
    /// bridge-id map (`--driver linux` only) — mirrors `nos-ribd`'s
    /// `--table-registry-path`, living in the same `interfaced/`
    /// directory since every daemon here runs inside one watchdog
    /// container/shared `nos-data` volume.
    #[arg(long, default_value = "/var/lib/nos/interfaced/bridge-ids.yaml")]
    bridge_registry_path: PathBuf,

    /// Path to this driver's own private persisted port-aggregate-name ->
    /// bond-id map (`--driver linux` only) — same shape and directory as
    /// `--bridge-registry-path`.
    #[arg(
        long,
        default_value = "/var/lib/nos/interfaced/port-aggregate-ids.yaml"
    )]
    port_aggregate_registry_path: PathBuf,

    /// Unix socket to forward this process's log events to. Passed directly
    /// by nos-watchdog to every process it spawns (see `docs/architecture/supervision.md`), the same way `--config-socket` is.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // Handed over by nos-watchdogd on stdin; there is no plaintext fallback.
    let identity = bootstrap::identity()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    bootstrap::init_tracing(
        "nos-interfaced",
        args.log_socket.clone(),
        identity.clone(),
        shutdown_rx.clone(),
    );
    nos_daemon::liveness::start(args.watchdog_socket.clone());
    info!("nos-interfaced starting");

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

    let driver: Arc<dyn InterfaceDriver> = match args.driver {
        DriverKind::Noop => {
            info!("using noop interface driver (no OS effect)");
            Arc::new(NoopInterfaceDriver)
        }
        DriverKind::Linux => {
            info!("using linux interface driver (rtnetlink)");
            Arc::new(
                LinuxInterfaceDriver::new(
                    args.watchdog_socket.clone(),
                    args.bridge_registry_path.clone(),
                    args.port_aggregate_registry_path.clone(),
                )
                .inspect_err(|e| {
                    tracing::error!(error = %e, "failed to initialize linux interface driver");
                })
                .context("initializing linux interface driver")?,
            )
        }
    };

    let interfaces = Arc::new(RwLock::new(Interfaces::new()));
    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        interfaces.clone(),
        driver.clone(),
        shutdown_rx,
    ));
    let server_task = server::start(&args.listen_socket, interfaces, driver, &identity)
        .inspect_err(|e| tracing::error!(error = %e, "failed to start interface IPC server"))
        .context("starting interface IPC server")?;

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");

    let _ = shutdown_tx.send(true);
    if let Err(e) = reconcile_task.await {
        warn!(error = %e, "reconcile task ended abnormally");
    }
    server_task.abort();

    info!("shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT. SIGINT is what `nos-watchdog` sends
/// (`supervisor::shutdown_child`); SIGTERM is handled too so a directly-run
/// or container-stopped `nos-interfaced` still shuts down cleanly instead of
/// relying on a forced kill.
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
        let args = Args::try_parse_from(["nos-interfaced"]).unwrap();
        assert_eq!(
            args.listen_socket,
            std::path::PathBuf::from(DEFAULT_LISTEN_SOCKET)
        );
    }
}
