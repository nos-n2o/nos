//! One-shot config provisioning tool: speaks nos-configd's IPC protocol
//! directly (nos-cli's interactive shell can't be driven over a plain pipe).
//! The op list itself lives in `nos_provision::build_ops`; this bin only
//! opens a transaction, applies it, commits, and (with `--save`) persists.
//! Still used by `tools/bench-bgp.sh`; `tools/e2e` reuses `build_ops` and
//! provisions over the REST API instead.
//!
//! Every daemon socket is mutually authenticated TLS, so like `nos-cli` this
//! logs in first: it trusts the watchdog's published `ca.crt`, trades a
//! username and password for a certificate on a key generated here, and only
//! then opens its transaction.

use anyhow::{bail, Context};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use nos_pki::{Bundle, Identity};
use nos_proto::{
    Event, IpcCodec, Request, Role, TransactionBase, WatchdogEvent, WatchdogRequest,
    DEFAULT_PKI_CA, DEFAULT_WATCHDOG_SOCKET, LOGIN_BUSY,
};
use nos_provision::{bfd_paths, build_ops, Args};
use std::path::PathBuf;
use tokio::io::{ReadHalf, WriteHalf};
use tokio_util::codec::{FramedRead, FramedWrite};

type Stream = nos_pki::Stream;

/// `nos-provision`'s own flags, alongside the shared config-building ones.
#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    args: Args,

    /// User to log in as (a local NOS user; a fresh router has `admin`).
    /// Required unless `--pki-cert-in` supplies a certificate instead.
    #[arg(long, required_unless_present = "pki_cert_in")]
    login_user: Option<String>,

    /// That user's password. Falls back to `NOS_LOGIN_PASSWORD`, which keeps
    /// it out of the process list.
    #[arg(long)]
    login_password: Option<String>,

    /// `nos-watchdogd`'s broker socket, where login happens.
    #[arg(long, default_value = DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// The watchdog's published CA certificate.
    #[arg(long, default_value = DEFAULT_PKI_CA)]
    pki_ca: PathBuf,

    /// Test fixture: after logging in, also write the certificate and its
    /// private key here (`nos-e2e pki` reuses them after a revocation).
    #[arg(long)]
    pki_cert_out: Option<PathBuf>,

    /// Test fixture: skip login and present the certificate `--pki-cert-out`
    /// wrote instead.
    #[arg(long, conflicts_with = "pki_cert_out")]
    pki_cert_in: Option<PathBuf>,

    /// Test fixture (`nos-e2e pki-crl`, #677): log in N times as
    /// `--login-user`, discarding every certificate, then exit without
    /// touching `nos-configd`. Each login is a certificate the watchdog must
    /// list in the CRL when the user's password changes.
    #[arg(long, requires = "login_user", conflicts_with_all = ["pki_cert_in", "pki_cert_out"])]
    login_burst: Option<usize>,

    /// Test fixture (`nos-e2e pki-rotation`, #637): present the
    /// `--pki-cert-in` certificate to the watchdog's `RenewCert`, overwrite
    /// that file with the renewed certificate and exit, without touching
    /// `nos-configd`. A refusal exits non-zero and prints its reason.
    #[arg(long, requires = "pki_cert_in")]
    renew_probe: bool,
}

/// Logins in flight at once: the broker verifies two passwords at a time
/// (argon2id, 64 MiB each) and refuses with `LOGIN_BUSY` after 5s of queueing.
const BURST_IN_FLIGHT: usize = 4;

/// One login on a fresh connection and key; retries while the broker is busy.
async fn login_once(cli: &Cli, user: &str, password: &str) -> anyhow::Result<()> {
    loop {
        let (csr, _key) = nos_pki::generate_csr()?;
        let stream = nos_pki::connect(&cli.watchdog_socket, Role::Watchdog, "").await?;
        let (r, w) = tokio::io::split(stream);
        let mut reader = FramedRead::new(r, IpcCodec::<WatchdogEvent>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default());
        writer
            .send(WatchdogRequest::Login {
                user: user.to_string(),
                password: password.to_string(),
                csr_der: csr,
            })
            .await?;
        match reader.next().await {
            Some(Ok(WatchdogEvent::Issued { .. })) => return Ok(()),
            Some(Ok(WatchdogEvent::Denied(m))) if m == LOGIN_BUSY => {}
            other => bail!("burst login failed: {other:?}"),
        }
    }
}

async fn burst(cli: &Cli, n: usize) -> anyhow::Result<()> {
    use futures::stream::{self, TryStreamExt};
    let ca = std::fs::read(&cli.pki_ca)
        .with_context(|| format!("reading the ipc trust anchor {}", cli.pki_ca.display()))?;
    nos_pki::install(
        Identity::anonymous_from_pem(&ca).context("the ipc trust anchor is unusable")?,
    );
    let user = cli.login_user.clone().context("--login-user is required")?;
    let password = cli
        .login_password
        .clone()
        .or_else(|| std::env::var("NOS_LOGIN_PASSWORD").ok())
        .context("--login-password (or NOS_LOGIN_PASSWORD) is required")?;
    let (user, password) = (&user, &password);
    stream::iter((0..n).map(Ok))
        .try_for_each_concurrent(BURST_IN_FLIGHT, |_| login_once(cli, user, password))
        .await?;
    println!("burst complete logins={n}");
    Ok(())
}

/// Trades the password for a certificate and installs it as this process's
/// identity, so every later `nos_pki::connect` is authenticated.
async fn log_in(cli: &Cli) -> anyhow::Result<()> {
    let ca = std::fs::read(&cli.pki_ca)
        .with_context(|| format!("reading the ipc trust anchor {}", cli.pki_ca.display()))?;
    let identity = Identity::anonymous_from_pem(&ca).context("the ipc trust anchor is unusable")?;
    nos_pki::install(identity.clone());
    if let Some(path) = &cli.pki_cert_in {
        let saved = Bundle::read_from(&mut std::fs::read(path)?.as_slice())?
            .context("empty certificate file")?;
        identity.set_certificate(saved.cert, saved.key)?;
        return Ok(());
    }
    let user = cli.login_user.clone().context("--login-user is required")?;
    let password = cli
        .login_password
        .clone()
        .or_else(|| std::env::var("NOS_LOGIN_PASSWORD").ok())
        .context("--login-password (or NOS_LOGIN_PASSWORD) is required")?;

    let (csr, key) = nos_pki::generate_csr()?;
    let stream = nos_pki::connect(&cli.watchdog_socket, Role::Watchdog, "")
        .await
        .with_context(|| format!("connecting to {}", cli.watchdog_socket.display()))?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<WatchdogEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default());
    writer
        .send(WatchdogRequest::Login {
            user,
            password,
            csr_der: csr,
        })
        .await
        .context("sending login")?;
    match reader.next().await {
        Some(Ok(WatchdogEvent::Issued { cert_der, .. })) => {
            if let Some(path) = &cli.pki_cert_out {
                let saved = Bundle {
                    ca: Vec::new(),
                    cert: cert_der.clone(),
                    key: key.clone(),
                    crl: Vec::new(),
                };
                std::fs::write(path, saved.encode())?;
            }
            identity.set_certificate(cert_der, key)?;
            Ok(())
        }
        Some(Ok(WatchdogEvent::Denied(reason))) => bail!("login refused: {reason}"),
        other => bail!("unexpected reply to login: {other:?}"),
    }
}

/// One `RenewCert` over a connection that presents the saved certificate.
async fn renew_probe(cli: &Cli) -> anyhow::Result<()> {
    log_in(cli).await?;
    let path = cli.pki_cert_in.as_ref().context("--pki-cert-in")?;
    let (csr, key) = nos_pki::generate_csr()?;
    let stream = nos_pki::connect(&cli.watchdog_socket, Role::Watchdog, "").await?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<WatchdogEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default());
    writer
        .send(WatchdogRequest::RenewCert { csr_der: csr })
        .await?;
    match reader.next().await {
        Some(Ok(WatchdogEvent::Issued { cert_der, .. })) => {
            let saved = Bundle {
                ca: Vec::new(),
                cert: cert_der,
                key,
                crl: Vec::new(),
            };
            std::fs::write(path, saved.encode())?;
            println!("renewed");
            Ok(())
        }
        Some(Ok(WatchdogEvent::Denied(reason))) => bail!("renew refused: {reason}"),
        other => bail!("unexpected reply to renew: {other:?}"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Some(n) = cli.login_burst {
        return burst(&cli, n).await;
    }
    if cli.renew_probe {
        return renew_probe(&cli).await;
    }
    let args = &cli.args;
    let config_socket = args
        .config_socket
        .clone()
        .context("--config-socket is required")?;
    let ops = build_ops(args)?;
    if nos_provision::acl_flags(args) {
        bail!("--acl-* and --flowspec-interface flags are applied by nos-e2e only, not over the config socket");
    }

    log_in(&cli).await?;
    let stream = nos_pki::connect(&config_socket, Role::Configd, "")
        .await
        .with_context(|| format!("connecting to {}", config_socket.display()))?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());

    let txn = "verify".to_string();

    send(
        &mut writer,
        &mut reader,
        Request::OpenTransaction {
            actor: None,
            name: txn.clone(),
            base: TransactionBase::Current,
        },
    )
    .await?;

    for op in ops {
        send(
            &mut writer,
            &mut reader,
            Request::ApplyOp {
                actor: None,
                name: txn.clone(),
                op,
            },
        )
        .await?;
    }

    for (path, value) in bfd_paths(args) {
        send(
            &mut writer,
            &mut reader,
            Request::EditTransactionPath {
                name: txn.clone(),
                path,
                value,
                if_match: None,
                position: None,
            },
        )
        .await?;
    }

    send(
        &mut writer,
        &mut reader,
        Request::CommitTransaction {
            actor: None,
            name: txn.clone(),
            if_match: None,
        },
    )
    .await?;

    if args.save {
        send(&mut writer, &mut reader, Request::Save).await?;
    }

    println!("provisioning complete");
    Ok(())
}

async fn send(
    writer: &mut FramedWrite<WriteHalf<Stream>, IpcCodec<Request>>,
    reader: &mut FramedRead<ReadHalf<Stream>, IpcCodec<Event>>,
    req: Request,
) -> anyhow::Result<()> {
    let label = format!("{req:?}");
    writer.send(req).await.context("sending request")?;
    match reader.next().await {
        Some(Ok(Event::Error(e))) => bail!("{label} -> error: {e}"),
        Some(Ok(event)) => {
            eprintln!("{label} -> {event:?}");
            Ok(())
        }
        Some(Err(e)) => bail!("{label} -> transport error: {e}"),
        None => bail!("{label} -> connection closed"),
    }
}
