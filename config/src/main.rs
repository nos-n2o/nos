use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_config::{persistence, users, ConfigStore, ListenAddr};
use nos_log_client::ForwardingLayer;
use nos_pki::Identity;
use nos_proto::DEFAULT_LOG_SOCKET;
use tokio::sync::watch;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Parser)]
#[command(name = "nos-configd", about = "NOS configuration daemon")]
struct Args {
    /// Unix socket path to listen on for IPC connections
    /// (/run/nos/config.sock, config.sock). TLS only — no TCP.
    #[arg(long, default_value = "/run/nos/config.sock")]
    listen: ListenAddr,

    /// Path to the persisted config file. Loaded at startup — falling back
    /// to an empty default config if it does not exist — and written to
    /// when a client sends the `save` command.
    #[arg(long, default_value = "/var/lib/nos/configd/config.yaml")]
    config_file: PathBuf,

    /// Unix socket to forward this process's log events to. Passed directly
    /// by nos-watchdog to every process it spawns (see `docs/architecture/supervision.md`).
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
    #[cfg(feature = "dhat-heap")]
    nos_config::store::DHAT_PROFILING.store(true, std::sync::atomic::Ordering::Relaxed);
    // Handed over by nos-watchdogd on stdin; there is no plaintext fallback.
    let identity = Identity::from_stdin().context("reading this daemon's ipc identity")?;
    // No graceful-shutdown signal of its own (see the bare `ctrl_c()` wait
    // below) — this channel exists purely so the forwarder's reconnect loop
    // has something to stop on if it's ever given one; kept alive for the
    // whole process so the forwarder doesn't see it as closed immediately.
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    tracing_subscriber::registry()
        // `RUST_LOG` support: defaults to `trace`, i.e. exactly the
        // unfiltered behavior this process had before, so an unset
        // `RUST_LOG` changes nothing. Added so `tools/bench-bgp.sh` can run
        // the stack quietly enough to measure BGP rather than logging.
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("trace")),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(ForwardingLayer::install(
            "nos-configd",
            args.log_socket.clone(),
            identity.clone(),
            shutdown_rx,
        ))
        .init();
    nos_log_client::install_panic_hook();

    let mut initial = persistence::load_or_default(&args.config_file);
    users::seed_default_user(&mut initial);

    let store = ConfigStore::new(initial, Some(args.config_file.clone()));
    let _handle = store
        .start_ipc_server(&args.listen, &identity)
        .inspect_err(|e| {
            tracing::error!(error = %e, listen = %args.listen, "failed to bind config IPC server");
        })
        .with_context(|| format!("failed to bind {}", args.listen))?;

    tracing::info!(peer = ?identity.peer(), "ipc identity loaded");
    tracing::info!(config_file = %args.config_file.display(), "config file path");

    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;

    tracing::info!("shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn args_parse() {
        Args::command().debug_assert();
        let args = Args::try_parse_from(["nos-configd"]).unwrap();
        assert_eq!(
            args.config_file,
            std::path::PathBuf::from("/var/lib/nos/configd/config.yaml")
        );
    }

    #[cfg(feature = "dhat-heap")]
    #[test]
    fn profile_memory_out_parses() {
        let args =
            Args::try_parse_from(["nos-configd", "--profile-memory-out", "/tmp/x.json"]).unwrap();
        assert_eq!(args.profile_memory_out, PathBuf::from("/tmp/x.json"));
    }
}
