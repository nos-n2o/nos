use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use nos_log_client::ForwardingLayer;
use nos_proto::diff::REST_API_LABEL;
use nos_proto::diff::VNI_LABEL;
use nos_proto::{
    ConfigDiff, DiffScope, Role, SectionDiff, DEFAULT_CONFIG_SOCKET, DEFAULT_LOG_SOCKET,
    DEFAULT_PKI_DIR, DEFAULT_WATCHDOG_SOCKET,
};
use nos_watchdog::{
    broker::{self, Sockets},
    instances, supervise_one, BackoffPolicy, Endpoint, EndpointKind, EndpointRegistry, Managed,
    Pki, ProcessSpec,
};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(name = "nos-watchdogd", about = "NOS process supervisor")]
struct Args {
    /// Path to the nos-configd binary to supervise.
    #[arg(long, default_value = "/usr/local/bin/nos-configd")]
    configd_bin: PathBuf,

    /// Extra arguments forwarded to nos-configd (e.g. --listen, --config-file).
    #[arg(long = "configd-arg", allow_hyphen_values = true)]
    configd_flags: Vec<String>,

    /// Path to the nos-bgpd binary to supervise (one instance is spawned per
    /// BGP instance in the running config).
    #[arg(long, default_value = "/usr/local/bin/nos-bgpd")]
    bgpd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-bgpd instance.
    #[arg(long = "bgpd-arg", allow_hyphen_values = true)]
    bgpd_flags: Vec<String>,

    /// Path to the nos-ribd binary to supervise (one instance is spawned per
    /// routing table in the running config).
    #[arg(long, default_value = "/usr/local/bin/nos-ribd")]
    ribd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-ribd instance.
    #[arg(long = "ribd-arg", allow_hyphen_values = true)]
    ribd_flags: Vec<String>,

    /// Path to the nos-fdbd binary to supervise (one instance is spawned per
    /// broadcast domain that has a `vni`).
    #[arg(long, default_value = "/usr/local/bin/nos-fdbd")]
    fdbd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-fdbd instance.
    #[arg(long = "fdbd-arg", allow_hyphen_values = true)]
    fdbd_flags: Vec<String>,

    /// Path to the nos-ospfd binary to supervise (one instance is spawned
    /// per OSPF instance in the running config).
    #[arg(long, default_value = "/usr/local/bin/nos-ospfd")]
    ospfd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-ospfd instance.
    #[arg(long = "ospfd-arg", allow_hyphen_values = true)]
    ospfd_flags: Vec<String>,

    /// Path to the nos-ospfv3d binary to supervise (one instance is spawned
    /// per `OSPFv3` instance in the running config) — the RFC 5340 (IPv6)
    /// counterpart of nos-ospfd, a fully independent daemon family.
    #[arg(long, default_value = "/usr/local/bin/nos-ospfv3d")]
    ospfv3d_bin: PathBuf,

    /// Extra arguments forwarded to every nos-ospfv3d instance.
    #[arg(long = "ospfv3d-arg", allow_hyphen_values = true)]
    ospfv3d_flags: Vec<String>,

    /// Path to the nos-restd binary to supervise (one instance is spawned
    /// per routing table that has `rest-api` pinned to it).
    #[arg(long, default_value = "/usr/local/bin/nos-restd")]
    restd_bin: PathBuf,

    /// Extra arguments forwarded to every nos-restd instance; a literal
    /// `{name}` is replaced by the table name.
    #[arg(long = "restd-arg", allow_hyphen_values = true)]
    restd_flags: Vec<String>,

    /// Path to the nos-interfaced binary to supervise. Unlike nos-bgpd/
    /// nos-ribd, exactly one instance is always supervised regardless of how
    /// many interfaces are configured — see `interface/CLAUDE.md`.
    #[arg(long, default_value = "/usr/local/bin/nos-interfaced")]
    interfaced_bin: PathBuf,

    /// Extra arguments forwarded to nos-interfaced.
    #[arg(long = "interfaced-arg", allow_hyphen_values = true)]
    interfaced_flags: Vec<String>,

    /// Unix socket nos-interfaced listens on for interface queries (e.g.
    /// from `nos show interface`). Also served out as the resolved address
    /// for `ServiceRef::Interfaces` broker queries, the same way
    /// `--config-socket` is for `ServiceRef::Config`.
    #[arg(long, default_value = "/run/nos/interface.sock")]
    interfaced_listen_socket: PathBuf,

    /// Path to the nos-logd binary to supervise. Like nos-interfaced, exactly
    /// one instance is always supervised regardless of how many other
    /// daemons are running.
    #[arg(long, default_value = "/usr/local/bin/nos-logd")]
    logd_bin: PathBuf,

    /// Extra arguments forwarded to nos-logd.
    #[arg(long = "logd-arg", allow_hyphen_values = true)]
    logd_flags: Vec<String>,

    /// Unix socket nos-logd listens on for pushed log entries and queries
    /// (e.g. from `nos show log`). Also served out as the resolved address
    /// for `ServiceRef::Log` broker queries, the same way
    /// `--interfaced-listen-socket` is for `ServiceRef::Interfaces` — and
    /// passed via `--log-socket` to every other supervised process so it can
    /// forward its own logs here.
    #[arg(long, default_value = DEFAULT_LOG_SOCKET)]
    log_socket: PathBuf,

    /// Path to the nos-lacpd binary to supervise. Like nos-interfaced/
    /// nos-logd, exactly one instance is always supervised regardless of how
    /// many `Lacp`-mode port aggregates are configured — see
    /// `lacp/CLAUDE.md`.
    #[arg(long, default_value = "/usr/local/bin/nos-lacpd")]
    lacpd_bin: PathBuf,

    /// Extra arguments forwarded to nos-lacpd.
    #[arg(long = "lacpd-arg", allow_hyphen_values = true)]
    lacpd_flags: Vec<String>,

    /// Unix socket nos-lacpd listens on for LACP status queries (e.g. from
    /// `nos show lacp`). Also served out as the resolved address for
    /// `ServiceRef::Lacp` broker queries, the same way
    /// `--interfaced-listen-socket` is for `ServiceRef::Interfaces`.
    #[arg(long, default_value = "/run/nos/lacp.sock")]
    lacpd_listen_socket: PathBuf,

    /// Path to the nos-lldpd binary to supervise. Like nos-lacpd, exactly
    /// one instance is always supervised regardless of how many interfaces
    /// have LLDP enabled — see `lldp/CLAUDE.md`.
    #[arg(long, default_value = "/usr/local/bin/nos-lldpd")]
    lldpd_bin: PathBuf,

    /// Extra arguments forwarded to nos-lldpd.
    #[arg(long = "lldpd-arg", allow_hyphen_values = true)]
    lldpd_flags: Vec<String>,

    /// Unix socket nos-lldpd listens on for LLDP neighbor queries (e.g. from
    /// `nos show lldp neighbors`). Also served out as the resolved address
    /// for `ServiceRef::Lldp` broker queries, the same way
    /// `--lacpd-listen-socket` is for `ServiceRef::Lacp`.
    #[arg(long, default_value = "/run/nos/lldp.sock")]
    lldpd_listen_socket: PathBuf,

    /// Path to the nos-bfdd binary to supervise. Like nos-lldpd, exactly one
    /// instance is always supervised — see `bfd/CLAUDE.md`.
    #[arg(long, default_value = "/usr/local/bin/nos-bfdd")]
    bfdd_bin: PathBuf,

    /// Extra arguments forwarded to nos-bfdd.
    #[arg(long = "bfdd-arg", allow_hyphen_values = true)]
    bfdd_flags: Vec<String>,

    /// Unix socket nos-bfdd listens on. Also served out as the resolved
    /// address for `ServiceRef::Bfd` broker queries.
    #[arg(long, default_value = "/run/nos/bfd.sock")]
    bfdd_listen_socket: PathBuf,

    /// Path to the nos-stpd binary to supervise. Like nos-lldpd, exactly one
    /// instance is always supervised — see `stp/CLAUDE.md`.
    #[arg(long, default_value = "/usr/local/bin/nos-stpd")]
    stpd_bin: PathBuf,

    /// Extra arguments forwarded to nos-stpd.
    #[arg(long = "stpd-arg", allow_hyphen_values = true)]
    stpd_flags: Vec<String>,

    /// Unix socket nos-stpd listens on. Also served out as the resolved
    /// address for `ServiceRef::Stp` broker queries.
    #[arg(long, default_value = "/run/nos/stp.sock")]
    stpd_listen_socket: PathBuf,

    /// Unix socket nos-acld listens on. Also served out as the resolved
    /// address for `ServiceRef::Acl` broker queries.
    #[arg(long, default_value = "/run/nos/acl.sock")]
    acld_listen_socket: PathBuf,

    /// Path to the nos-acld binary to supervise. Like nos-stpd, exactly one
    /// instance is always supervised — see `acl/CLAUDE.md`.
    #[arg(long, default_value = "/usr/local/bin/nos-acld")]
    acld_bin: PathBuf,

    /// Extra arguments forwarded to nos-acld.
    #[arg(long = "acld-arg", allow_hyphen_values = true)]
    acld_flags: Vec<String>,

    /// Path to nos-configd's IPC Unix socket, used by the watchdog itself to
    /// subscribe to BGP instance and routing table changes. Independent of
    /// `--configd-arg`, which is an opaque pass-through to the child — if
    /// the child's actual listen address is overridden via `--configd-arg
    /// --listen=...`, this must be updated to match. Also served out as the
    /// resolved address for `ServiceRef::Config` broker queries, since the
    /// watchdog itself is the one process every other client asks instead of
    /// assuming this default.
    #[arg(long, default_value = DEFAULT_CONFIG_SOCKET)]
    config_socket: PathBuf,

    /// Directory the per-instance daemon sockets (`bgp-<name>.sock`,
    /// `rib-<name>.sock`, …) are created in. The fixed sockets have their
    /// own flags.
    #[arg(long, default_value = "/run/nos")]
    run_dir: PathBuf,

    /// Unix socket the endpoint-resolution broker listens on. Every other
    /// daemon/CLI dials this first to learn where to reach nos-configd or a
    /// specific nos-ribd instance, instead of assuming a hardcoded default.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    listen_socket: PathBuf,

    /// Directory the watchdog publishes `ca.crt` in — the public trust
    /// anchor every IPC client (including `nos-cli`, from another container
    /// sharing this volume) bootstraps from.
    #[arg(long, default_value = DEFAULT_PKI_DIR)]
    pki_dir: PathBuf,

    /// Group every supervised child runs in, and the switch for per-role uids:
    /// each child gets its role's own uid (`uids::role_uid`, set before exec,
    /// so file capabilities still apply) and its `--state-dir/<role>` is
    /// created. The image passes `nos`'s gid; unset (tests, non-container
    /// runs) children inherit the watchdog's ids.
    #[arg(long)]
    child_gid: Option<u32>,

    /// Parent of the per-role state directories (`<dir>/<role>`, `0700`
    /// `nos-<role>`), created at startup when `--child-gid` is set.
    #[arg(long, default_value = "/var/lib/nos")]
    state_dir: PathBuf,

    /// Seconds a daemon's IPC certificate is valid for.
    #[arg(long, default_value_t = 24 * 3600)]
    pki_leaf_lifetime: u64,

    /// Seconds between fresh certificates pushed to every running daemon.
    /// Must be shorter than `--pki-leaf-lifetime`. (Short values let
    /// `nos-e2e` exercise rotation in seconds.)
    #[arg(long, default_value_t = 8 * 3600)]
    pki_rotate_every: u64,

    /// Seconds a logged-in user's certificate (`nos` shell, `nos-provision`)
    /// is valid for; the client renews it at half-life.
    #[arg(long, default_value_t = 8 * 3600)]
    pki_user_lifetime: u64,

    /// Seconds a REST login (`nos-restd`) may be extended by certificate
    /// renewals; after that the client logs in with its password again.
    #[arg(long, default_value_t = 7 * 24 * 3600)]
    pki_rest_session_max: u64,

    /// Seconds an IPC login (`nos` shell, `nos-provision`) may be extended by
    /// certificate renewals; after that the client logs in with its password.
    #[arg(long, default_value_t = 24 * 3600)]
    pki_ipc_session_max: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // Before tracing: the log forwarder itself needs an identity to reach
    // nos-logd, so the CA has to exist first.
    let pki = Pki::start(
        &args.pki_dir,
        Duration::from_secs(args.pki_leaf_lifetime),
        Duration::from_secs(args.pki_rotate_every),
        Duration::from_secs(args.pki_user_lifetime),
    )
    .context("starting the ipc certificate authority")?;
    pki.set_rest_session_max(Duration::from_secs(args.pki_rest_session_max));
    pki.set_ipc_session_max(Duration::from_secs(args.pki_ipc_session_max));
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
            "nos-watchdogd",
            args.log_socket.clone(),
            pki.identity.clone(),
            shutdown_rx.clone(),
        ))
        .init();
    nos_log_client::install_panic_hook();

    info!(
        ca = %args.pki_dir.join("ca.crt").display(),
        leaf_lifetime_secs = args.pki_leaf_lifetime,
        rotate_every_secs = args.pki_rotate_every,
        "ipc certificate authority ready"
    );
    let policy = BackoffPolicy::default();
    let registry = EndpointRegistry::default();
    let managed = managed_families(&args, &pki, policy, &registry);
    let mut tasks = vec![
        pki.spawn_self_rotation(shutdown_rx.clone()),
        tokio::spawn(
            pki.clone()
                .follow_users(args.config_socket.clone(), shutdown_rx.clone()),
        ),
    ];

    // nos-logd is spawned first (still just one more supervised process,
    // with no ordering guarantee enforced) so the window in which every
    // other process's own forwarder has nothing to connect to is as short
    // as possible — a fixed 1s retry (see `nos_log_client`) covers the
    // rest.
    let logd_args = std::iter::once("--listen-socket".to_string())
        .chain(std::iter::once(args.log_socket.display().to_string()))
        .chain(std::iter::once("--watchdog-socket".to_string()))
        .chain(std::iter::once(args.listen_socket.display().to_string()))
        .chain(args.logd_flags.iter().cloned())
        .collect();
    let child_gid = args.child_gid;
    if let Some(gid) = child_gid {
        // `/proc/self` is owned by our effective ids (std has no `geteuid`).
        use std::os::unix::fs::MetadataExt;
        let me = std::fs::metadata("/proc/self").context("reading our own ids")?;
        nos_watchdog::uids::ensure_state_dirs(&args.state_dir, (me.uid(), me.gid()), gid)?;
    }
    let logd_spec = ProcessSpec::new("nos-logd", args.logd_bin.clone(), logd_args)
        .with_identity(pki.clone(), Role::Logd, "")
        .with_role_uid(child_gid)
        // #756: glibc per-thread arenas fragment nos-logd's churn into
        // 7-17x its live heap; one arena keeps RSS flat (measured, #757).
        .with_env("MALLOC_ARENA_MAX", "1");
    tasks.push(tokio::spawn(supervise_one(
        logd_spec,
        policy,
        shutdown_rx.clone(),
    )));

    tasks.push(tokio::spawn(supervise_one(
        configd_spec(&args, &pki),
        policy,
        shutdown_rx.clone(),
    )));
    for m in managed {
        tasks.push(tokio::spawn(instances::manage(m, shutdown_rx.clone())));
    }

    let sup = FixedSupervision {
        pki: &pki,
        policy,
        shutdown_rx: &shutdown_rx,
        child_gid,
        watchdog_socket: &args.listen_socket,
        log_socket: &args.log_socket,
    };
    tasks.extend(sup.spawn_all(&args));

    let broker_task = broker::start(
        &args.listen_socket,
        registry,
        Sockets {
            config: args.config_socket,
            interfaces: args.interfaced_listen_socket,
            log: args.log_socket,
            lacp: args.lacpd_listen_socket,
            lldp: args.lldpd_listen_socket,
            bfd: args.bfdd_listen_socket,
            stp: args.stpd_listen_socket,
            acl: args.acld_listen_socket,
        },
        pki.clone(),
    )
    .inspect_err(|e| tracing::error!(error = %e, "failed to start broker IPC server"))
    .context("starting broker IPC server")?;

    info!(task_count = tasks.len(), "nos-watchdogd supervising tasks");

    wait_for_shutdown_signal().await?;
    info!("shutdown signal received, stopping supervised processes");

    let _ = shutdown_tx.send(true);
    for task in tasks {
        if let Err(e) = task.await {
            error!(error = %e, "supervisor task panicked");
        }
    }
    // The broker's accept loop has no shutdown signal of its own (it never
    // needs to drain in-flight state the way a supervised process does) —
    // aborting it directly avoids blocking shutdown on a loop that would
    // otherwise run forever.
    broker_task.abort();

    info!("shutting down");
    Ok(())
}

/// What every fixed daemon (`nos-interfaced`, `nos-lacpd`, `nos-lldpd`,
/// `nos-bfdd`, `nos-stpd`, `nos-acld`) is spawned with besides its own binary, role and
/// socket; split out of `main` for length (#425).
struct FixedSupervision<'a> {
    pki: &'a Arc<Pki>,
    policy: BackoffPolicy,
    shutdown_rx: &'a watch::Receiver<bool>,
    child_gid: Option<u32>,
    watchdog_socket: &'a Path,
    log_socket: &'a Path,
}

impl FixedSupervision<'_> {
    /// Every fixed daemon, each under its own supervisor.
    fn spawn_all(&self, args: &Args) -> Vec<tokio::task::JoinHandle<()>> {
        let fixed = [
            (
                "nos-interfaced",
                args.interfaced_bin.clone(),
                Role::Interfaced,
                Some(&args.interfaced_listen_socket),
                args.interfaced_flags.clone(),
            ),
            (
                "nos-lacpd",
                args.lacpd_bin.clone(),
                Role::Lacpd,
                Some(&args.lacpd_listen_socket),
                args.lacpd_flags.clone(),
            ),
            (
                "nos-lldpd",
                args.lldpd_bin.clone(),
                Role::Lldpd,
                Some(&args.lldpd_listen_socket),
                args.lldpd_flags.clone(),
            ),
            (
                "nos-bfdd",
                args.bfdd_bin.clone(),
                Role::Bfdd,
                Some(&args.bfdd_listen_socket),
                args.bfdd_flags.clone(),
            ),
            (
                "nos-stpd",
                args.stpd_bin.clone(),
                Role::Stpd,
                Some(&args.stpd_listen_socket),
                args.stpd_flags.clone(),
            ),
            (
                "nos-acld",
                args.acld_bin.clone(),
                Role::Acld,
                Some(&args.acld_listen_socket),
                args.acld_flags.clone(),
            ),
        ];
        fixed
            .into_iter()
            .map(|(name, bin, role, listen, flags)| {
                self.spawn(name, bin, role, listen.map(PathBuf::as_path), flags)
            })
            .collect()
    }

    fn spawn(
        &self,
        name: &'static str,
        bin: PathBuf,
        role: Role,
        listen: Option<&Path>,
        flags: Vec<String>,
    ) -> tokio::task::JoinHandle<()> {
        let args = fixed_args(listen, self.watchdog_socket, self.log_socket, flags);
        let spec = ProcessSpec::new(name, bin, args)
            .with_identity(self.pki.clone(), role, "")
            .with_role_uid(self.child_gid);
        tokio::spawn(supervise_one(spec, self.policy, self.shutdown_rx.clone()))
    }
}

/// The argument vector of a single fixed daemon (`nos-interfaced`,
/// `nos-lacpd`, `nos-lldpd`, `nos-bfdd`, `nos-stpd`, `nos-acld`): its own
/// listen socket if it serves one, the broker and log sockets, then the
/// operator's pass-through flags.
fn fixed_args(
    listen: Option<&Path>,
    watchdog: &Path,
    log: &Path,
    extra: Vec<String>,
) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(listen) = listen {
        v.extend(["--listen-socket".to_string(), listen.display().to_string()]);
    }
    v.extend([
        "--watchdog-socket".to_string(),
        watchdog.display().to_string(),
        "--log-socket".to_string(),
        log.display().to_string(),
    ]);
    v.extend(extra);
    v
}

/// The dynamically-spawned daemon families: one process per named config
/// object, all supervised by the same `instances::manage`.
fn managed_families(
    args: &Args,
    pki: &Arc<Pki>,
    policy: BackoffPolicy,
    registry: &EndpointRegistry,
) -> Vec<Managed> {
    let family = |scope,
                  section: fn(&ConfigDiff) -> &[SectionDiff],
                  bin: &PathBuf,
                  flags: &Vec<String>,
                  name_flag,
                  daemon,
                  role,
                  noun,
                  endpoint,
                  claim_label| Managed {
        scope,
        section,
        bin: bin.clone(),
        flags: flags.clone(),
        name_flag,
        daemon,
        role,
        pki: pki.clone(),
        noun,
        endpoint,
        claim_label,
        config_socket: args.config_socket.clone(),
        log_socket: args.log_socket.clone(),
        watchdog_listen_socket: args.listen_socket.clone(),
        run_dir: args.run_dir.clone(),
        policy,
        registry: registry.clone(),
        child_gid: args.child_gid,
    };
    let ep = |kind, socket_prefix| {
        Some(Endpoint {
            kind,
            socket_prefix,
        })
    };
    vec![
        family(
            DiffScope::BgpInstances,
            |d| &d.bgp_instances,
            &args.bgpd_bin,
            &args.bgpd_flags,
            "--instance",
            "nos-bgpd",
            Role::Bgpd,
            "BGP instance",
            ep(EndpointKind::BgpInstance, "bgp"),
            None,
        ),
        family(
            DiffScope::RoutingTables,
            |d| &d.routing_tables,
            &args.ribd_bin,
            &args.ribd_flags,
            "--table",
            "nos-ribd",
            Role::Ribd,
            "routing table",
            ep(EndpointKind::RibTable, "rib"),
            None,
        ),
        family(
            DiffScope::OspfInstances,
            |d| &d.ospf_instances,
            &args.ospfd_bin,
            &args.ospfd_flags,
            "--instance",
            "nos-ospfd",
            Role::Ospfd,
            "OSPF instance",
            ep(EndpointKind::OspfInstance, "ospf"),
            None,
        ),
        family(
            DiffScope::Ospfv3Instances,
            |d| &d.ospfv3_instances,
            &args.ospfv3d_bin,
            &args.ospfv3d_flags,
            "--instance",
            "nos-ospfv3d",
            Role::Ospfv3d,
            "OSPFv3 instance",
            ep(EndpointKind::Ospfv3Instance, "ospfv3"),
            None,
        ),
        // One `nos-fdbd` per broadcast domain, but only while the domain has a
        // `vni` (`claim_label`, like `nos-restd` on `rest-api`) - a plain L2
        // domain has no EVPN/VXLAN state for a daemon to own.
        family(
            DiffScope::BroadcastDomains,
            |d| &d.broadcast_domains,
            &args.fdbd_bin,
            &args.fdbd_flags,
            "--domain",
            "nos-fdbd",
            Role::Fdbd,
            "broadcast domain",
            ep(EndpointKind::FdbDomain, "fdb"),
            Some(VNI_LABEL),
        ),
        // Opt-in per routing table (its `rest_api` field), not one per
        // table - hence `claim_label`. No IPC query listener of its own, so
        // no endpoint registration.
        family(
            DiffScope::RoutingTables,
            |d| &d.routing_tables,
            &args.restd_bin,
            &args.restd_flags,
            "--table",
            "nos-restd",
            Role::Restd,
            "REST API",
            None,
            Some(REST_API_LABEL),
        ),
    ]
}

/// Waits for either SIGTERM (the signal `docker stop` sends) or SIGINT
/// (Ctrl-C, for interactive/local runs).
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;

    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}

/// `nos-configd`'s spec. `MALLOC_ARENA_MAX=1` (#776): glibc per-thread arenas
/// doubled its `VmHWM` under route-PUT churn (1232 -> 616 MB at 66k routes
/// with one arena, #766; same net as nos-logd's #756).
fn configd_spec(args: &Args, pki: &Arc<Pki>) -> ProcessSpec {
    let configd_args = std::iter::once("--log-socket".to_string())
        .chain(std::iter::once(args.log_socket.display().to_string()))
        .chain(args.configd_flags.iter().cloned())
        .collect();
    ProcessSpec::new("nos-configd", args.configd_bin.clone(), configd_args)
        .with_identity(pki.clone(), Role::Configd, "")
        .with_role_uid(args.child_gid)
        .with_env("MALLOC_ARENA_MAX", "1")
        // #796: a fixed trim threshold also pins the mmap threshold at 128 KiB
        // (glibc turns off its dynamic raise), so big freed buffers go back to
        // the kernel: 66k-route RSS 57.0 -> 42.4 MB in config-mem.
        .with_env("MALLOC_TRIM_THRESHOLD_", "131072")
        .with_env("MALLOC_TOP_PAD_", "0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn args_parse() {
        Args::command().debug_assert();
        let args = Args::try_parse_from(["nos-watchdogd", "--bgpd-arg", "--profile-memory-out=x"])
            .unwrap();
        assert_eq!(args.bgpd_flags, ["--profile-memory-out=x"]);
    }

    #[test]
    fn defaults_name_the_installed_binaries_and_sockets() {
        let a = Args::try_parse_from(["x"]).unwrap();
        assert_eq!(a.configd_bin, PathBuf::from("/usr/local/bin/nos-configd"));
        assert_eq!(a.stpd_bin, PathBuf::from("/usr/local/bin/nos-stpd"));
        assert_eq!(a.stpd_listen_socket, PathBuf::from("/run/nos/stp.sock"));
        assert_eq!(a.acld_listen_socket, PathBuf::from("/run/nos/acl.sock"));
        assert_eq!(a.acld_bin, PathBuf::from("/usr/local/bin/nos-acld"));
        assert_eq!(a.run_dir, PathBuf::from("/run/nos"));
        assert_eq!(a.log_socket, PathBuf::from(DEFAULT_LOG_SOCKET));
        assert_eq!(a.listen_socket, PathBuf::from(DEFAULT_WATCHDOG_SOCKET));
        assert_eq!(a.config_socket, PathBuf::from(DEFAULT_CONFIG_SOCKET));
        assert_eq!(a.pki_dir, PathBuf::from(DEFAULT_PKI_DIR));
        assert_eq!(
            (a.pki_leaf_lifetime, a.pki_rotate_every, a.pki_user_lifetime),
            (86_400, 28_800, 28_800)
        );
        assert_eq!(a.pki_rest_session_max, 604_800);
        assert_eq!(a.pki_ipc_session_max, 86_400);
        assert_eq!(a.child_gid, None);
        assert_eq!(a.state_dir, PathBuf::from("/var/lib/nos"));
        let a = Args::try_parse_from(["x", "--child-gid", "992"]).unwrap();
        assert_eq!(a.child_gid, Some(992));
        assert!(a.logd_flags.is_empty() && a.restd_flags.is_empty());
    }

    #[test]
    fn fixed_args_orders_sockets_then_extra_flags() {
        let (l, w, g) = (
            Path::new("/l.sock"),
            Path::new("/w.sock"),
            Path::new("/g.sock"),
        );
        let base = [
            "--listen-socket",
            "/l.sock",
            "--watchdog-socket",
            "/w.sock",
            "--log-socket",
            "/g.sock",
        ];
        assert_eq!(fixed_args(Some(l), w, g, vec![]), base);
        assert_eq!(
            fixed_args(Some(l), w, g, vec!["--driver".into(), "noop".into()]),
            [&base[..], &["--driver", "noop"]].concat()
        );
        // A daemon without a socket gets none.
        assert_eq!(fixed_args(None, w, g, vec![]), base[2..]);
    }

    #[test]
    fn configd_runs_with_one_trimmed_malloc_arena() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::start(
            dir.path(),
            Duration::from_secs(3600),
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .unwrap();
        let args = Args::try_parse_from(["x", "--configd-arg", "--listen"]).unwrap();
        let spec = configd_spec(&args, &pki);
        assert_eq!(spec.name, "nos-configd");
        assert_eq!(spec.args.last().map(String::as_str), Some("--listen"));
        let env: Vec<(&str, &str)> = spec
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            env,
            [
                ("MALLOC_ARENA_MAX", "1"),
                ("MALLOC_TRIM_THRESHOLD_", "131072"),
                ("MALLOC_TOP_PAD_", "0"),
            ]
        );
    }

    #[test]
    fn managed_families_wire_each_family_to_its_own_flags() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::start(
            dir.path(),
            Duration::from_secs(3600),
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .unwrap();
        let mut cli_args = vec!["x".to_string()];
        for f in ["bgpd", "ribd", "ospfd", "ospfv3d", "fdbd", "restd"] {
            cli_args.push(format!("--{f}-bin"));
            cli_args.push(format!("/bin/{f}"));
            cli_args.push(format!("--{f}-arg"));
            cli_args.push(format!("--{f}-flag"));
        }
        let args = Args::try_parse_from(cli_args).unwrap();
        let ms = managed_families(
            &args,
            &pki,
            BackoffPolicy::default(),
            &EndpointRegistry::default(),
        );
        assert_eq!(ms.len(), 6);
        // (daemon, name_flag, role, scope, noun, endpoint prefix, claim label)
        let want = [
            (
                "nos-bgpd",
                "--instance",
                Role::Bgpd,
                DiffScope::BgpInstances,
                "BGP instance",
                Some("bgp"),
                None,
            ),
            (
                "nos-ribd",
                "--table",
                Role::Ribd,
                DiffScope::RoutingTables,
                "routing table",
                Some("rib"),
                None,
            ),
            (
                "nos-ospfd",
                "--instance",
                Role::Ospfd,
                DiffScope::OspfInstances,
                "OSPF instance",
                Some("ospf"),
                None,
            ),
            (
                "nos-ospfv3d",
                "--instance",
                Role::Ospfv3d,
                DiffScope::Ospfv3Instances,
                "OSPFv3 instance",
                Some("ospfv3"),
                None,
            ),
            (
                "nos-fdbd",
                "--domain",
                Role::Fdbd,
                DiffScope::BroadcastDomains,
                "broadcast domain",
                Some("fdb"),
                Some(VNI_LABEL),
            ),
            (
                "nos-restd",
                "--table",
                Role::Restd,
                DiffScope::RoutingTables,
                "REST API",
                None,
                Some(REST_API_LABEL),
            ),
        ];
        for (m, (daemon, name_flag, role, scope, noun, prefix, label)) in ms.iter().zip(want) {
            assert_eq!(m.daemon, daemon);
            assert_eq!(m.name_flag, name_flag);
            assert_eq!(m.role, role);
            assert_eq!(m.scope, scope);
            assert_eq!(m.noun, noun);
            assert_eq!(m.endpoint.as_ref().map(|e| e.socket_prefix), prefix);
            assert_eq!(m.claim_label, label);
            let short = daemon.trim_start_matches("nos-");
            assert_eq!(m.bin, PathBuf::from(format!("/bin/{short}")));
            assert_eq!(m.flags, [format!("--{short}-flag")]);
            assert_eq!(m.config_socket, args.config_socket);
            assert_eq!(m.watchdog_listen_socket, args.listen_socket);
            assert_eq!(m.run_dir, args.run_dir);
        }
    }

    #[test]
    fn managed_sections_select_the_matching_diff_field() {
        // The `section` fn pointers are the one thing a literal can swap
        // silently (ribd vs restd share RoutingTables).
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::start(
            dir.path(),
            Duration::from_secs(3600),
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .unwrap();
        let args = Args::try_parse_from(["x"]).unwrap();
        let ms = managed_families(
            &args,
            &pki,
            BackoffPolicy::default(),
            &EndpointRegistry::default(),
        );
        let sec = |name: &str| SectionDiff {
            header: String::new(),
            name: name.into(),
            status: nos_proto::DiffStatus::Added,
            fields: vec![],
            subsections: vec![],
        };
        let diff = ConfigDiff {
            bgp_instances: vec![sec("bgp")],
            routing_tables: vec![sec("rt")],
            ospf_instances: vec![sec("ospf")],
            ospfv3_instances: vec![sec("ospfv3")],
            broadcast_domains: vec![sec("bd")],
            ..ConfigDiff::default()
        };
        let got: Vec<_> = ms
            .iter()
            .map(|m| (m.section)(&diff)[0].name.clone())
            .collect();
        assert_eq!(got, ["bgp", "rt", "ospf", "ospfv3", "bd", "rt"]);
    }

    #[test]
    fn pki_rejects_rotation_slower_than_the_leaf_lifetime() {
        let dir = tempfile::tempdir().unwrap();
        let err = Pki::start(
            dir.path(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .err()
        .expect("rotate_every >= leaf_lifetime");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
