use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_log::{persistence, server, syslog, LogStore};
use nos_pki::Identity;
use nos_proto::{DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

/// Default location for the persisted log store — under `/var/lib/nos` (the
/// `nos-data` volume) so recent history survives a `nos-logd` restart. Never
/// read by any other process; other daemons and `nos-cli` only ever see
/// entries over IPC.
const DEFAULT_LOG_STORE_PATH: &str = "/var/lib/nos/logd/entries.jsonl";

/// Budget, from the shutdown signal, for flushing the persist queue.
const PERSIST_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Parser)]
#[command(name = "nos-logd", about = "NOS log collection daemon")]
struct Args {
    /// Unix socket to listen on — every other component process pushes its
    /// log entries here over one long-lived connection, and `nos-cli`
    /// queries it for `show log`/`show log --follow`.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    listen_socket: PathBuf,

    /// Where the in-memory buffer is persisted, so recent history survives a
    /// restart. The file is compacted back down to `--capacity` lines once
    /// it grows past twice that.
    #[arg(long, default_value = DEFAULT_LOG_STORE_PATH)]
    log_store_path: PathBuf,

    /// Maximum number of log entries kept in memory (and, after compaction,
    /// on disk). Oldest entries are evicted first.
    #[arg(long, default_value_t = 10_000)]
    capacity: usize,

    /// nos-watchdogd's broker socket, to find nos-configd (the syslog
    /// collectors to export to) and a collector's `nos-ribd` (its VRF).
    /// Resolved in the background: startup never waits for it.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Only present when built with `--features dhat-heap`. Path to write
    /// the dhat heap-profile report to on exit — load it at
    /// <https://nnethercote.github.io/dh_view/dh_view.html>.
    #[cfg(feature = "dhat-heap")]
    #[arg(long, default_value = "dhat-heap.json")]
    profile_memory_out: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::builder()
        .file_name(args.profile_memory_out.clone())
        .build();
    // Handed over by nos-watchdogd on stdin; there is no plaintext fallback.
    let identity = Identity::from_stdin().context("reading this daemon's ipc identity")?;
    info!(peer = ?identity.peer(), "ipc identity loaded");
    info!(
        listen_socket = %args.listen_socket.display(),
        capacity = args.capacity,
        "nos-logd starting"
    );

    let seed = persistence::load_recent(&args.log_store_path, args.capacity);
    info!(entries = seed.len(), path = %args.log_store_path.display(), "loaded persisted log store");

    let (persist_tx, persist_rx) = mpsc::unbounded_channel();
    let (drain_tx, drain_rx) = watch::channel(false);
    let store = LogStore::new(args.capacity, seed, persist_tx);
    let persistence_task = tokio::spawn(persistence::run(
        args.log_store_path.clone(),
        args.capacity,
        persist_rx,
        store.persist_queue_bytes(),
        drain_rx,
    ));

    let server_task = server::start(&args.listen_socket, store.clone(), &identity)
        .context("starting log IPC server")?;
    nos_daemon::liveness::start(args.watchdog_socket.clone());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let syslog_task = tokio::spawn(syslog::reconcile::run(
        args.watchdog_socket.clone(),
        store,
        shutdown_rx,
    ));

    wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!("shutdown signal received");

    // Stop accepting, then tell persistence to flush. Every live connection
    // holds a `store` clone so `persist_tx` never drops: the persistence task
    // closes its receiver itself on the trigger (#679). The trigger goes out
    // before the syslog await, and the flush is bounded 5s from the signal
    // (not stacked on the syslog grace), well inside the watchdog's 10s.
    let deadline = tokio::time::Instant::now() + PERSIST_DRAIN_TIMEOUT;
    server_task.abort();
    let _ = drain_tx.send(true);
    // Syslog sinks close their TCP connections cleanly before the exit.
    let _ = shutdown_tx.send(true);
    let _ = syslog_task.await;
    let mut persistence_task = persistence_task;
    if tokio::time::timeout_at(deadline, &mut persistence_task)
        .await
        .is_err()
    {
        warn!("log persistence flush timed out, dropping queued entries");
        persistence_task.abort();
    }

    info!("shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT. SIGINT is what `nos-watchdog` sends
/// (`supervisor::shutdown_child`); SIGTERM is handled too so a directly-run
/// or container-stopped `nos-logd` still flushes its persistence queue
/// cleanly instead of relying on a forced kill.
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
        let args = Args::try_parse_from(["nos-logd"]).unwrap();
        assert_eq!(args.capacity, 10_000);
    }
}
