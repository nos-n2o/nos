use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use nos_daemon::{bootstrap, watchdog};
use nos_ospfv3::link::LinkManager;
use nos_ospfv3::{reconcile, rib_push_client, server};
use nos_proto::{ServiceRef, DEFAULT_LOG_SOCKET, DEFAULT_WATCHDOG_SOCKET};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;

#[derive(Parser)]
#[command(name = "nos-ospfv3d", about = "NOS OSPFv3 (RFC 5340) daemon")]
struct Args {
    /// Name of the `OSPFv3` instance (from the running config's
    /// `ospfv3_instances`) this process is responsible for.
    #[arg(long)]
    instance: String,

    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address rather than assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// Unix socket this instance's IPC query server (`Ospfv3Request::
    /// GetNeighbors`, backing `show ospfv3 neigh`) listens on. Assigned and
    /// passed by `nos-watchdogd` at spawn time, mirroring `nos-ospfd`'s own
    /// `--listen-socket`.
    #[arg(long)]
    listen_socket: Option<PathBuf>,

    /// Unix socket to forward this process's log events to. Passed directly
    /// by nos-watchdog to every process it spawns.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// Multiplies the per-second LSA-age-clock increment (default 1 = real
    /// time). Test/debug only — mirrors `nos-ospfd`'s identical flag,
    /// reachable only via `nos-watchdogd`'s opaque `--ospfv3d-arg`
    /// pass-through. Do not wire this into `Ospfv3Profile`/`nos-cli`.
    #[arg(long, default_value_t = 1)]
    lsa_age_multiplier: u16,

    /// RFC 2328 §10.8's per-DBD-packet LSA-header budget override
    /// (unchanged by RFC 5340), test/debug only — when unset each link
    /// derives it from its own MTU (`exchange::mtu_based_max_headers`).
    #[arg(long)]
    dbd_max_headers: Option<usize>,

    /// Drop or duplicate the Nth outgoing exchange DBD, e.g. `drop:2,dup:3`
    /// (#607). Test-only, via `--ospfv3d-arg`; never a config field.
    #[arg(long, hide = true)]
    dbd_fault: Option<String>,

    /// Originate every summary/external LSA at `LSInfinity` (`ospfv3-lsinfinity`
    /// e2e). Test-only, via `--ospfv3d-arg`; never a config field.
    #[arg(long, hide = true)]
    originate_lsinfinity: bool,

    /// Weight budget per `PushOspfRoutes` frame (`OspfRouteUpdate::frames_with`).
    /// Unset: `nos_proto::rib::ospf_push_chunk()`. Test-only, via `--ospfv3d-arg`
    /// (the watchdog clears its children's environment, so `NOS_OSPF_PUSH_CHUNK`
    /// cannot reach a supervised daemon); never a config field.
    #[arg(long, hide = true)]
    push_chunk: Option<usize>,

    /// Cap on links per Router-LSA fragment (`ospfv3-router-lsa-split` e2e).
    /// Test-only, via `--ospfv3d-arg`; never a config field.
    #[arg(long, hide = true)]
    router_lsa_max_links: Option<usize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let identity = bootstrap::identity()?;
    if let Some(spec) = &args.dbd_fault {
        nos_ospf_common::dbd_fault::install(spec).map_err(anyhow::Error::msg)?;
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    bootstrap::init_tracing(
        format!("nos-ospfv3d[{}]", args.instance),
        args.log_socket.clone(),
        identity.clone(),
        shutdown_rx.clone(),
    );
    info!(instance = %args.instance, "nos-ospfv3d starting");

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
        .unwrap_or_else(|| PathBuf::from(format!("/run/nos/ospfv3-{}.sock", args.instance)));

    let (routing_table_tx, routing_table_rx) = watch::channel(None::<String>);
    let links = LinkManager::new(args.lsa_age_multiplier, args.dbd_max_headers);
    links.set_originate_lsinfinity(args.originate_lsinfinity);
    links.set_router_lsa_max_links(args.router_lsa_max_links);
    let (link_tx, link_rx) = watch::channel(nos_ospfv3::link_client::LinkTable::default());
    let link_task = tokio::spawn(nos_ospfv3::link_client::run(
        args.watchdog_socket.clone(),
        link_tx,
        shutdown_rx.clone(),
    ));
    let reconcile_task = tokio::spawn(reconcile::run(
        config_socket,
        args.watchdog_socket.clone(),
        args.instance.clone(),
        links.clone(),
        routing_table_tx,
        link_rx,
        shutdown_rx.clone(),
    ));
    let bfd_task = nos_ospfv3::bfd_client::spawn(
        args.watchdog_socket.clone(),
        links.clone(),
        routing_table_rx.clone(),
        shutdown_rx.clone(),
    );
    let rib_push_task = rib_push_client::spawn(
        args.watchdog_socket.clone(),
        links.clone(),
        routing_table_rx,
        shutdown_rx,
        args.push_chunk
            .filter(|&n| n > 0)
            .unwrap_or_else(nos_proto::rib::ospf_push_chunk),
    );
    let server_task = server::start(
        &listen_socket,
        args.instance.clone(),
        links.clone(),
        &identity,
    )
    .inspect_err(|e| {
        tracing::error!(instance = %args.instance, error = %e, "failed to start OSPFv3 IPC server");
    })
    .context("starting OSPFv3 IPC server")?;

    let planned_restart = wait_for_shutdown_signal()
        .await
        .context("waiting for shutdown signal")?;
    info!(instance = %args.instance, planned_restart, "shutdown signal received");
    // Before `shutdown_tx`: the log forwarder stops on it, and these lines
    // are what a neighbor's operator (and nos-e2e) looks for.
    if planned_restart {
        links.announce_graceful_restart().await;
    }

    let _ = shutdown_tx.send(true);
    if let Err(e) = reconcile_task.await {
        tracing::warn!(instance = %args.instance, error = %e, "reconcile task ended abnormally");
    }
    link_task.abort();
    rib_push_task.abort();
    bfd_task.abort();
    server_task.abort();

    info!(instance = %args.instance, "shutting down");
    Ok(())
}

/// Waits for SIGTERM or SIGINT — mirrors `nos-ospfd`'s own identical
/// handler. Returns `true` for SIGTERM — a planned restart, the only case
/// that announces an RFC 5187 grace period (the watchdog stops or removes an
/// instance with SIGINT, after which nothing comes back).
async fn wait_for_shutdown_signal() -> anyhow::Result<bool> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    Ok(tokio::select! {
        _ = sigterm.recv() => true,
        _ = sigint.recv() => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn args_parse() {
        Args::command().debug_assert();
        let args = Args::try_parse_from(["nos-ospfv3d", "--instance", "o1"]).unwrap();
        assert_eq!((args.instance.as_str(), args.lsa_age_multiplier), ("o1", 1));
        assert!(!args.originate_lsinfinity);
        let on =
            Args::try_parse_from(["nos-ospfv3d", "--instance", "o1", "--originate-lsinfinity"])
                .unwrap();
        assert!(on.originate_lsinfinity);
        let cap = Args::try_parse_from([
            "nos-ospfv3d",
            "--instance",
            "o1",
            "--router-lsa-max-links",
            "2",
        ])
        .unwrap();
        assert_eq!(cap.router_lsa_max_links, Some(2));
    }
}
