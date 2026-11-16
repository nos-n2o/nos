use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_acl::driver::{Driver, LinuxDriver, NoopDriver};
use nos_acl::engine::{self, Engine};
use nos_acl::flowspec_file;
use nos_acl::link_client::{self, LinkTable};
use nos_acl::reconcile;
use nos_acl::server;
use nos_daemon::{bootstrap, watchdog};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use std::sync::{Arc, Mutex};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{info, warn};

/// One fixed instance, like `nos-stpd`.
const DEFAULT_LISTEN_SOCKET: &str = "/run/nos/acl.sock";

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum DriverKind {
    Noop,
    Linux,
}

#[derive(Parser)]
#[command(name = "nos-acld", about = "NOS access-list (tc flower) daemon")]
#[allow(clippy::struct_field_names)] // matches the other daemons' *_socket naming
struct Args {
    /// Path to nos-watchdogd's broker socket.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to forward this process's log events to.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// Unix socket to listen on for `show acl` queries.
    #[arg(long, default_value = DEFAULT_LISTEN_SOCKET)]
    listen_socket: PathBuf,

    /// `linux` programs tc; `noop` leaves the kernel alone.
    #[arg(long, value_enum, default_value_t = DriverKind::Linux)]
    driver: DriverKind,

    /// Test hook: a JSON flowspec snapshot applied as if `nos-bgpd` pushed
    /// it, re-read when it changes (`docs/architecture/linux-drivers.md`).
    #[arg(long, hide = true)]
    flowspec_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let identity = bootstrap::identity()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    bootstrap::init_tracing(
        "nos-acld",
        args.log_socket.clone(),
        identity.clone(),
        shutdown_rx.clone(),
    );
    nos_daemon::liveness::start(args.watchdog_socket.clone());
    info!(driver = ?args.driver, "nos-acld starting");
    match args.driver {
        DriverKind::Linux => {
            serve(args, LinuxDriver, true, identity, shutdown_tx, shutdown_rx).await
        }
        DriverKind::Noop => {
            serve(
                args,
                NoopDriver::default(),
                false,
                identity,
                shutdown_tx,
                shutdown_rx,
            )
            .await
        }
    }
}

async fn serve<D: Driver>(
    args: Args,
    driver: D,
    log: bool,
    identity: nos_pki::Identity,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
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

    let (plan_tx, plan_rx) = watch::channel(None);
    let (links_tx, links_rx) = watch::channel(LinkTable::default());
    let reconcile_task = tokio::spawn(reconcile::run(config_socket, plan_tx, shutdown_rx.clone()));
    let link_task = tokio::spawn(link_client::run(
        args.watchdog_socket.clone(),
        links_tx,
        shutdown_rx.clone(),
    ));
    let engine = Arc::new(Mutex::new(Engine::new(driver)));
    let server_task = server::start(&args.listen_socket, engine.clone(), &identity)
        .inspect_err(|e| tracing::error!(error = %e, "failed to start acl IPC server"))
        .context("starting acl IPC server")?;
    let file_task = args
        .flowspec_file
        .clone()
        .map(|p| tokio::spawn(flowspec_file::run(p, engine.clone(), shutdown_rx.clone())));
    let mut engine_task = tokio::spawn(engine::run(engine, plan_rx, links_rx, shutdown_rx, log));

    // The engine only ends on its own when a feeder task died: exit non-zero
    // so the watchdog restarts us (filters keep enforcing meanwhile, #663).
    tokio::select! {
        r = wait_for_shutdown_signal() => {
            r.context("waiting for shutdown signal")?;
            info!("shutdown signal received");
        }
        r = &mut engine_task => {
            tracing::error!("acl engine ended without a shutdown signal");
            server_task.abort();
            return match r {
                Ok(Ok(())) => Err(anyhow::anyhow!("engine ended unexpectedly")),
                Ok(Err(e)) => Err(e.context("engine failed")),
                Err(e) => Err(anyhow::Error::new(e).context("engine panicked")),
            };
        }
    }
    let _ = shutdown_tx.send(true);
    let tasks = [("reconcile", reconcile_task), ("link_client", link_task)];
    for (name, task) in tasks
        .into_iter()
        .chain(file_task.map(|t| ("flowspec_file", t)))
    {
        if let Err(e) = task.await {
            warn!(error = %e, task = name, "task ended abnormally");
        }
    }
    // The filters stay enforcing after the process exits.
    if let Err(e) = engine_task.await {
        warn!(error = %e, task = "engine", "task ended abnormally");
    }
    server_task.abort();
    info!("shutting down");
    Ok(())
}

/// SIGINT is what `nos-watchdog` sends; SIGTERM covers a container stop.
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
        let args = Args::try_parse_from(["nos-acld"]).unwrap();
        assert!(matches!(args.driver, DriverKind::Linux));
        assert_eq!(args.listen_socket, PathBuf::from(DEFAULT_LISTEN_SOCKET));
        let args = Args::try_parse_from(["nos-acld", "--driver", "noop"]).unwrap();
        assert!(matches!(args.driver, DriverKind::Noop));
        assert_eq!(args.flowspec_file, None);
        let args = Args::try_parse_from(["nos-acld", "--flowspec-file", "/x.json"]).unwrap();
        assert_eq!(args.flowspec_file, Some(PathBuf::from("/x.json")));
    }
}
