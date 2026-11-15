use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use nos_daemon::{bootstrap, watchdog};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use nos_ssh::conn::{Limits, Spec};
use nos_ssh::listen::{config_trigger, Daemons, LinuxBinder, Listener};
use nos_ssh::{caps, hostkey, sshd_config};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;

#[derive(Parser)]
#[command(
    name = "nos-sshd",
    about = "NOS SSH server (VRF-bound wrapper around sshd -i)"
)]
struct Args {
    /// The routing table this server is pinned to: it listens inside that
    /// table's VRF, on the address its `ssh-server` config names.
    #[arg(long)]
    table: String,

    /// Path to nos-watchdogd's broker socket.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket to forward this process's log events to.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// The OpenSSH server run once per connection. Its file name selects the
    /// PAM service (`/etc/pam.d/<name>`), so the image makes it a symlink to
    /// `/usr/sbin/sshd` called `nos-sshd`.
    #[arg(long, default_value = "/usr/libexec/nos-sshd/nos-sshd")]
    sshd_bin: PathBuf,

    /// Root-owned tmpfs directory for the rendered `sshd_config`.
    #[arg(long, default_value = "/run/nos-sshd")]
    run_dir: PathBuf,

    /// Persistent directory for the host key, shared by every table's daemon.
    #[arg(long, default_value = "/var/lib/nos/sshd")]
    host_key_dir: PathBuf,

    /// Open connections at once.
    #[arg(long, default_value_t = nos_ssh::conn::MAX_CONNECTIONS)]
    max_connections: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // Before stdin, before any socket: nothing below may run with the full root set.
    caps::restrict().context("dropping capabilities (refusing to run with the full set)")?;

    let identity = bootstrap::identity()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    bootstrap::init_tracing(
        format!("nos-sshd[{}]", args.table),
        args.log_socket.clone(),
        identity,
        shutdown_rx.clone(),
    );
    info!(table = %args.table, "nos-sshd starting");

    let config_path = prepare(
        Path::new("/run/sshd"),
        &args.run_dir,
        &args.host_key_dir,
        &args.table,
    )?;

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

    let spec = Spec::new(
        args.table.clone(),
        args.sshd_bin,
        config_path,
        Limits {
            global: args.max_connections,
            ..Limits::default()
        },
    );
    let listener = Listener {
        trigger: config_trigger(&config_socket).await,
        source: Daemons {
            table: args.table,
            watchdog_socket: args.watchdog_socket,
            config_socket,
        },
        binder: LinuxBinder,
        spec: Arc::new(spec),
    };
    let task = tokio::spawn(listener.run(shutdown_rx.clone()));

    wait_for_shutdown_signal().await?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(true);
    let _ = task.await;
    info!("shutting down");
    Ok(())
}

/// Host key, rendered `sshd_config`, and the directories sshd needs; returns
/// the config path.
fn prepare(
    privsep_dir: &Path,
    run_dir: &Path,
    host_key_dir: &Path,
    table: &str,
) -> anyhow::Result<PathBuf> {
    // sshd's privilege-separation chroot; absent in the container image.
    mkdir(privsep_dir, 0o755)?;
    let dir = run_dir.join(table);
    mkdir(run_dir, 0o755)?;
    mkdir(&dir, 0o700)?;
    let host_key = hostkey::ensure(host_key_dir).context("host key")?;
    let path = dir.join("sshd_config");
    sshd_config::write_if_changed(
        &path,
        &sshd_config::render(&sshd_config::Settings { host_key }),
    )
    .context("writing sshd_config")?;
    Ok(path)
}

fn mkdir(path: &Path, mode: u32) -> anyhow::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .with_context(|| format!("creating {}", path.display()))
}

/// SIGINT is what `nos-watchdog` sends; SIGTERM too, for a directly-run or
/// container-stopped `nos-sshd`.
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
    fn args_parse_with_defaults() {
        Args::command().debug_assert();
        let a = Args::try_parse_from(["nos-sshd", "--table", "rt1"]).unwrap();
        assert_eq!(a.table, "rt1");
        assert_eq!(a.sshd_bin, PathBuf::from("/usr/libexec/nos-sshd/nos-sshd"));
        assert_eq!(a.run_dir, PathBuf::from("/run/nos-sshd"));
        assert_eq!(a.host_key_dir, PathBuf::from("/var/lib/nos/sshd"));
        assert_eq!(a.max_connections, 64);
    }

    #[test]
    fn prepare_creates_dirs_key_and_config() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let (privsep, run, keys) = (
            d.path().join("sshd"),
            d.path().join("run"),
            d.path().join("keys"),
        );
        let cfg = prepare(&privsep, &run, &keys, "rt1").unwrap();
        assert_eq!(cfg, run.join("rt1/sshd_config"));
        let text = std::fs::read_to_string(&cfg).unwrap();
        assert!(text.contains(&format!(
            "HostKey {}",
            keys.join("ssh_host_ed25519_key").display()
        )));
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            (mode(&privsep), mode(&run.join("rt1")), mode(&cfg)),
            (0o755, 0o700, 0o600)
        );
        // A second start keeps the same key and config.
        assert_eq!(prepare(&privsep, &run, &keys, "rt1").unwrap(), cfg);
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), text);
    }

    #[test]
    fn prepare_fails_when_a_directory_cannot_be_made() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        assert!(prepare(&file.join("sub"), d.path(), d.path(), "rt1").is_err());
    }
}
