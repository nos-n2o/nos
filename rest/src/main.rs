use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_daemon::{bootstrap, watchdog};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use nos_rest::{api, ipc::Daemons, listen::Listener};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// dhat and jemalloc are mutually exclusive: `dhat-heap` keeps profiling the live heap.
#[cfg(not(feature = "dhat-heap"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser)]
#[command(name = "nos-restd", about = "NOS REST API daemon")]
struct Args {
    /// The routing table this API is pinned to — it listens inside that
    /// table's VRF, on the address its `rest-api` config names.
    #[arg(long)]
    table: String,

    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd
    /// and every other daemon this API queries.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to forward this process's log events to.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// Only present when built with `--features dhat-heap`. Path to write
    /// the dhat heap-profile report to on exit (SIGINT).
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
    let identity = bootstrap::identity()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    bootstrap::init_tracing(
        format!("nos-restd[{}]", args.table),
        args.log_socket.clone(),
        identity.clone(),
        shutdown_rx.clone(),
    );
    info!(table = %args.table, "nos-restd starting");
    // Dhat build only (#798): SIGUSR1 logs the live heap, so `mem-wave` can
    // put it next to `VmRSS`. A default build keeps SIGUSR1's default action.
    #[cfg(feature = "dhat-heap")]
    {
        let mut usr1 = signal(SignalKind::user_defined1()).context("installing SIGUSR1 handler")?;
        tokio::spawn(async move {
            while usr1.recv().await.is_some() {
                let s = dhat::HeapStats::get();
                info!(
                    curr_bytes = s.curr_bytes,
                    max_bytes = s.max_bytes,
                    total_bytes = s.total_bytes,
                    "restd heap stats"
                );
            }
        });
    }

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

    let daemons = Daemons::new(args.watchdog_socket, config_socket.clone());
    tokio::spawn(nos_rest::login::follow_policy(
        daemons.login_gate(),
        config_socket,
    ));
    let listener = Listener {
        table: args.table,
        router: api::router(daemons.clone()),
        daemons,
    };
    let task = tokio::spawn(listener.run(shutdown_rx.clone()));

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(true);
    let _ = task.await;
    info!("shutting down");
    Ok(())
}

/// SIGINT is what `nos-watchdog` sends (`supervisor::shutdown_child`); SIGTERM
/// is handled too so a directly-run or container-stopped `nos-restd` exits cleanly.
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
        let args = Args::try_parse_from(["nos-restd", "--table", "rt1"]).unwrap();
        assert_eq!(args.table, "rt1");
    }

    #[cfg(feature = "dhat-heap")]
    #[test]
    fn profile_memory_out_parses() {
        let args = Args::try_parse_from([
            "nos-restd",
            "--table",
            "rt1",
            "--profile-memory-out",
            "/tmp/x.json",
        ])
        .unwrap();
        assert_eq!(args.profile_memory_out, PathBuf::from("/tmp/x.json"));
    }
}
