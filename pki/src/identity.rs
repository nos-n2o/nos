//! A process's TLS identity — hot-swappable, so rotation never touches a
//! connection or a config — and the connect/listen halves that use it.
//!
//! Chain, expiry and key-usage are checked by rustls's stock `WebPKI`
//! verifiers. Who the peer *is* (`nos://role/name`) is checked right after
//! the handshake, before either side sends a byte of application data.
//!
//! TLS 1.3 only, and session resumption/tickets are off: a resumed session
//! skips certificate verification, which would let an expired or rotated-out
//! identity straight back in.

use std::fmt;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use rustls::client::{ClientConfig, ResolvesClientCert, Resumption, WebPkiServerVerifier};
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use rustls::server::{
    ClientHello, NoServerSessionStorage, ResolvesServerCert, ServerConfig, WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tracing::{debug, error, info, warn};
use x509_parser::prelude::FromDer;
use zeroize::Zeroizing;

use crate::ca::{err, Bundle, SERVER_NAME};
use crate::policy::{key_alg_name, Policy};
use crate::PeerId;

static GLOBAL: OnceLock<Identity> = OnceLock::new();

/// Makes `identity` this process's identity for every outbound `connect`.
/// A process has exactly one — from its stdin (daemons) or its login (`nos`) —
/// so call sites dial with `connect` rather than threading a handle through
/// every session manager and driver. Installing twice keeps the first.
pub fn install(identity: Identity) {
    let _ = GLOBAL.set(identity);
}

/// The installed identity. Panics if `install` was never called: that is a
/// missing line in `main` (or a test), never a runtime condition.
pub fn global() -> &'static Identity {
    // Test builds only (`testing` is a dev-dependency feature): any test that
    // dials without installing an identity gets a person's, from the shared
    // test CA, so fake servers can be `testing::shared().identity(..)`.
    #[cfg(feature = "testing")]
    return GLOBAL.get_or_init(|| crate::testing::shared().identity("user", "test"));
    #[cfg(not(feature = "testing"))]
    GLOBAL
        .get()
        .expect("nos_pki::install was never called in this process")
}

/// Dials `path` as this process and returns only once the server proved it is
/// `role`/`name` (`name` is `""` for the singleton daemons).
pub async fn connect(path: &Path, role: impl AsRef<str>, name: &str) -> io::Result<Stream> {
    global()
        .connect(path, &PeerId::new(role.as_ref(), name))
        .await
}

/// As `connect`, for callers that know only the peer's role — a socket path
/// from the broker, not which instance is behind it.
pub async fn connect_role(path: &Path, role: impl AsRef<str>) -> io::Result<Stream> {
    global().connect_role(path, role.as_ref()).await
}

/// A TLS stream over a Unix socket. `tokio::io::split` gives the halves
/// `FramedRead`/`FramedWrite` want, where `UnixStream::into_split` used to.
///
/// A peer that hangs up without a TLS `close_notify` reads as a clean EOF, the
/// way a plaintext socket's does. Every one-shot client here just drops its
/// connection, and rustls would otherwise report each as an `UnexpectedEof`
/// *error* — a warning per query in every server's log. Truncation is still
/// caught where it matters: `FramedRead` fails a frame cut short at EOF, and on
/// a local socket nobody sits between two authenticated peers to cut it.
pub struct Stream(TlsStream<UnixStream>);

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Stream")
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.0).poll_read(cx, buf) {
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Poll::Ready(Ok(())),
            other => other,
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

/// What a finished handshake settled on — the post-quantum policy made visible
/// (tests assert on it, and every handshake logs it at debug level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The key-exchange group, e.g. `X25519MLKEM768`.
    pub kx: String,
    /// The peer certificate's key algorithm, e.g. `ML-DSA-65`; `none` when
    /// the peer sent no certificate.
    pub peer_key: &'static str,
}

impl Stream {
    /// The verified peer leaf's serial (hex, as `Serial`'s `Display`), so a
    /// server can tell *which* certificate a caller presented (#637).
    pub fn peer_serial(&self) -> Option<String> {
        let certs = match &self.0 {
            TlsStream::Client(c) => c.get_ref().1.peer_certificates(),
            TlsStream::Server(c) => c.get_ref().1.peer_certificates(),
        };
        crate::ca::Serial::of(certs?.first()?)
            .ok()
            .map(|s| s.to_string())
    }

    /// What the finished handshake settled on (version, key exchange, suite, peer key algorithm).
    pub fn negotiated(&self) -> Negotiated {
        let (kx, certs) = match &self.0 {
            TlsStream::Client(c) => {
                let (_, conn) = c.get_ref();
                (
                    conn.negotiated_key_exchange_group(),
                    conn.peer_certificates(),
                )
            }
            TlsStream::Server(c) => {
                let (_, conn) = c.get_ref();
                (
                    conn.negotiated_key_exchange_group(),
                    conn.peer_certificates(),
                )
            }
        };
        Negotiated {
            kx: kx.map_or_else(|| "none".to_string(), |g| format!("{:?}", g.name())),
            peer_key: certs
                .and_then(|c| c.first())
                .map_or("none", |c| key_alg_name(c)),
        }
    }

    fn log_handshake(&self, side: &str) {
        let n = self.negotiated();
        debug!(side = %side, kx = %n.kx, peer_key = %n.peer_key, "ipc tls handshake ok");
    }
}

/// A peer that can't finish a handshake this fast is dropped rather than left
/// holding a connection slot.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

struct Current {
    key: Arc<CertifiedKey>,
    peer: PeerId,
}

struct Shared {
    ca: Vec<u8>,
    current: ArcSwapOption<Current>,
}

/// Serves whatever certificate is current *at handshake time* to rustls.
struct Resolver(Arc<Shared>);

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Resolver")
    }
}

impl ResolvesClientCert for Resolver {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.0.current.load().as_ref().map(|c| c.key.clone())
    }
    fn has_certs(&self) -> bool {
        self.0.current.load().is_some()
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.current.load().as_ref().map(|c| c.key.clone())
    }
}

/// The rustls configs of one identity. Rebuilt whenever the CRL changes; the
/// certificate is not in them (the `Resolver` reads it per handshake).
struct Configs {
    client: Arc<ClientConfig>,
    server_required: Arc<ServerConfig>,
    server_optional: Arc<ServerConfig>,
}

struct Inner {
    shared: Arc<Shared>,
    roots: Arc<RootCertStore>,
    /// The CRL `configs` enforce (DER, empty for none yet).
    crl: Mutex<Vec<u8>>,
    configs: ArcSwap<Configs>,
}

/// A swappable handle on this process's certificate and trust anchors; rotation affects new handshakes only.
#[derive(Clone)]
pub struct Identity(Arc<Inner>);

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({:?})", self.peer())
    }
}

/// Builds the client and both server configs trusting `roots`, refusing any
/// peer whose leaf `crl` lists (none when `crl` is empty).
fn configs(roots: &Arc<RootCertStore>, crl: &[u8], shared: &Arc<Shared>) -> io::Result<Configs> {
    let provider = crate::policy::provider(Policy::Ipc);
    let crls: Vec<CertificateRevocationListDer<'static>> = if crl.is_empty() {
        Vec::new()
    } else {
        vec![CertificateRevocationListDer::from(crl.to_vec())]
    };
    let resolver = Arc::new(Resolver(shared.clone()));
    let versions = &[&rustls::version::TLS13];

    // Only the leaf is checked: the one CA is the trust anchor, never revoked.
    // "Unknown status" can't happen with a CRL from that CA; it is allowed so
    // that no CRL at all (before the first one arrives) means no checking.
    let server_verifier =
        WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
            .with_crls(crls.clone())
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status()
            .build()
            .map_err(err)?;
    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .map_err(err)?
        .with_webpki_verifier(server_verifier)
        .with_client_cert_resolver(resolver.clone());
    client.resumption = Resumption::disabled();

    let server = |optional: bool| -> io::Result<Arc<ServerConfig>> {
        let builder = WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone())
            .with_crls(crls.clone())
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();
        let verifier = if optional {
            builder.allow_unauthenticated()
        } else {
            builder
        }
        .build()
        .map_err(err)?;
        let mut cfg = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .map_err(err)?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver.clone());
        cfg.send_tls13_tickets = 0;
        cfg.session_storage = Arc::new(NoServerSessionStorage {});
        Ok(Arc::new(cfg))
    };

    Ok(Configs {
        client: Arc::new(client),
        server_required: server(false)?,
        server_optional: server(true)?,
    })
}

fn certify(b: &Bundle) -> io::Result<Current> {
    let peer = PeerId::from_cert_der(&b.cert)
        .ok_or_else(|| err("certificate carries no nos:// identity"))?;
    Ok(Current {
        key: certified_key(&b.cert, &b.key)?,
        peer,
    })
}

/// A leaf certificate and its PKCS#8 key as rustls wants them, checked to
/// belong together.
pub(crate) fn certified_key(cert_der: &[u8], key_der: &[u8]) -> io::Result<Arc<CertifiedKey>> {
    let key = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)))
        .map_err(err)?;
    let key = CertifiedKey::new(vec![CertificateDer::from(cert_der.to_vec())], key);
    key.keys_match().map_err(err)?;
    Ok(Arc::new(key))
}

impl Identity {
    /// An identity that trusts `ca_der` but holds no certificate of its own:
    /// it can verify servers and connect to a socket that allows unauthenticated
    /// clients (the login path), nothing else. `update` gives it a certificate.
    pub fn anonymous(ca_der: &[u8]) -> io::Result<Self> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_der.to_vec()))
            .map_err(err)?;
        let roots = Arc::new(roots);
        let shared = Arc::new(Shared {
            ca: ca_der.to_vec(),
            current: ArcSwapOption::empty(),
        });
        let configs = configs(&roots, &[], &shared)?;
        Ok(Self(Arc::new(Inner {
            shared,
            roots,
            crl: Mutex::new(Vec::new()),
            configs: ArcSwap::from_pointee(configs),
        })))
    }

    /// `anonymous`, from the PEM a `ca.crt` file holds.
    pub fn anonymous_from_pem(pem: &[u8]) -> io::Result<Self> {
        Self::anonymous(&CertificateDer::from_pem_slice(pem).map_err(err)?)
    }

    /// Builds an identity from a [`Bundle`] (CA, leaf, key, CRL).
    pub fn from_bundle(b: &Bundle) -> io::Result<Self> {
        let id = Self::anonymous(&b.ca)?;
        id.update(b)?;
        Ok(id)
    }

    /// Swaps in a fresh certificate/key, and the bundle's CRL if it carries a
    /// new one. New handshakes use both at once; established connections are
    /// untouched — revocation stops new handshakes only. The CA must be the
    /// same one: the trust anchor is fixed for an identity's lifetime.
    pub fn update(&self, b: &Bundle) -> io::Result<()> {
        if b.ca != self.0.shared.ca {
            return Err(err("bundle is from a different CA"));
        }
        let current = certify(b);
        // A revocation must never be dropped because the leaf was bad.
        let crl = self.set_crl(&b.crl);
        self.0.shared.current.store(Some(Arc::new(current?)));
        crl
    }

    /// Enforces `crl` (DER, signed by this identity's CA) on every handshake
    /// from now on, on both sides. An empty or unchanged `crl` is a no-op.
    pub fn set_crl(&self, crl: &[u8]) -> io::Result<()> {
        let mut held = self.0.crl.lock().unwrap_or_else(PoisonError::into_inner);
        if crl.is_empty() || *held == crl {
            return Ok(());
        }
        let entries = crl_entries(crl)?;
        self.0
            .configs
            .store(Arc::new(configs(&self.0.roots, crl, &self.0.shared)?));
        crl.clone_into(&mut held);
        info!(entries, "ipc crl updated");
        Ok(())
    }

    /// Installs a certificate the CA issued for a key *this process* generated
    /// (`generate_csr` → `Ca::sign_csr`, e.g. after a login). The trust anchor
    /// stays the one this identity already holds.
    pub fn set_certificate(
        &self,
        cert_der: Vec<u8>,
        key_der: Zeroizing<Vec<u8>>,
    ) -> io::Result<()> {
        self.update(&Bundle {
            ca: self.0.shared.ca.clone(),
            cert: cert_der,
            key: key_der,
            crl: Vec::new(),
        })
    }

    /// Who this identity's current certificate says we are.
    pub fn peer(&self) -> Option<PeerId> {
        self.0
            .shared
            .current
            .load()
            .as_ref()
            .map(|c| c.peer.clone())
    }

    /// The identity `nos-watchdogd` handed this daemon on its stdin, and a
    /// background thread that applies every rotation it pushes afterwards.
    /// There is deliberately no plaintext fallback: no identity, no daemon.
    ///
    /// A plain thread rather than a tokio task: a blocked stdin read would
    /// otherwise stall runtime shutdown until the watchdog closed the pipe.
    pub fn from_stdin() -> io::Result<Self> {
        let id = Self::read_stdin()?;
        install(id.clone());
        Ok(id)
    }

    fn read_stdin() -> io::Result<Self> {
        let first = Bundle::read_from(&mut std::io::stdin().lock())?.ok_or_else(|| {
            err("no identity on stdin — daemons are started by nos-watchdogd, which provides one")
        })?;
        let id = Self::from_bundle(&first)?;
        let rotating = id.clone();
        std::thread::Builder::new()
            .name("nos-pki-rotate".into())
            .spawn(move || {
                rotate_from(&mut std::io::stdin().lock(), &rotating, |e| {
                    // The stream is desynchronised after a bad frame, so it
                    // cannot be resumed: exit and let the supervisor respawn
                    // this daemon with a fresh identity (#677).
                    error!(error = %e, "identity pipe broke, exiting so the supervisor respawns this daemon");
                    std::process::exit(1)
                });
            })?;
        Ok(id)
    }

    /// Dials `path` and only returns once the server proved it is `expect`.
    pub async fn connect(&self, path: &Path, expect: &PeerId) -> io::Result<Stream> {
        self.dial(path, |got| got == expect, &expect.to_string())
            .await
    }

    /// As `connect`, but only the peer's role is checked.
    pub async fn connect_role(&self, path: &Path, role: &str) -> io::Result<Stream> {
        self.dial(path, |got| got.role == role, &format!("{role}/*"))
            .await
    }

    async fn dial(
        &self,
        path: &Path,
        accept: impl Fn(&PeerId) -> bool,
        expected: &str,
    ) -> io::Result<Stream> {
        let sock = UnixStream::connect(path).await?;
        let name = ServerName::try_from(SERVER_NAME)
            .expect("valid dns name")
            .to_owned();
        let connector = TlsConnector::from(self.0.configs.load().client.clone());
        let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(name, sock))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tls handshake timed out"))??;
        let stream = Stream(TlsStream::Client(tls));
        stream.log_handshake("client");
        match peer_of(&stream) {
            Some(got) if accept(&got) => Ok(stream),
            got => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("expected {expected} at {}, found {got:?}", path.display()),
            )),
        }
    }

    /// Binds `path` (replacing a stale socket file) for peers that must
    /// present a certificate.
    pub fn listen(&self, path: &Path) -> io::Result<Listener> {
        self.listen_with(path, false)
    }

    /// As `listen`, but a peer *without* a certificate is let through (its
    /// `PeerId` is `None`) — for the one socket where login happens, before a
    /// client has a certificate. The caller must refuse everything but login
    /// to an unauthenticated peer.
    pub fn listen_optional_client_auth(&self, path: &Path) -> io::Result<Listener> {
        self.listen_with(path, true)
    }

    fn listen_with(&self, path: &Path, optional: bool) -> io::Result<Listener> {
        if self.peer().is_none() {
            return Err(err("an anonymous identity cannot serve"));
        }
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let inner = UnixListener::bind(path)?;
        // The socket is created with the process umask; set it to 0660 (group
        // `nos`, which every NOS uid has as primary group: the watchdog runs
        // on another uid than its children and must `connect()`) before any
        // accept. A socket we cannot set must not serve; mTLS is the gate.
        // ponytail: a brief bind-to-chmod window at umask mode (no safe umask
        // API); /run/nos is 1770 so only `nos-wd:nos` reach it, upgrade to a
        // umask guard if sockets ever live elsewhere.
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o660))?;
        Ok(Listener {
            inner,
            identity: self.0.clone(),
            optional,
        })
    }
}

/// How many certificates a CRL lists — for the log line only.
fn crl_entries(crl: &[u8]) -> io::Result<usize> {
    let (_, parsed) =
        x509_parser::revocation_list::CertificateRevocationList::from_der(crl).map_err(err)?;
    Ok(parsed.iter_revoked_certificates().count())
}

fn peer_of(s: &Stream) -> Option<PeerId> {
    let certs = match &s.0 {
        TlsStream::Client(c) => c.get_ref().1.peer_certificates(),
        TlsStream::Server(c) => c.get_ref().1.peer_certificates(),
    };
    PeerId::from_cert_der(certs?.first()?)
}

/// Reads the identity's *current* server config on every accept, so a CRL
/// that arrives after `listen` still applies to the next peer.
pub struct Listener {
    inner: UnixListener,
    identity: Arc<Inner>,
    optional: bool,
}

impl Listener {
    /// Accepts a raw connection. The TLS handshake is left to `Incoming::handshake`
    /// so callers run it inside their per-connection task — a slow or hostile
    /// peer then never stalls the accept loop.
    pub async fn accept(&self) -> io::Result<Incoming> {
        let (stream, _) = self.inner.accept().await?;
        let configs = self.identity.configs.load();
        let config = if self.optional {
            &configs.server_optional
        } else {
            &configs.server_required
        };
        Ok(Incoming {
            stream,
            config: config.clone(),
        })
    }
}

/// An accepted connection before its TLS handshake; the caller handshakes in its own task.
pub struct Incoming {
    stream: UnixStream,
    config: Arc<ServerConfig>,
}

impl Incoming {
    /// `handshake` for a `listen` (certificate required) socket, returning
    /// the peer's role — via `parse`, e.g. `Role::parse` — and instance name.
    /// A peer whose certificate carries no role `parse` recognises is refused.
    pub async fn handshake_as<R>(
        self,
        parse: impl Fn(&str) -> Option<R>,
    ) -> io::Result<(Stream, R, String)> {
        let (stream, peer) = self.handshake().await?;
        let (role, name) = peer
            .and_then(|p| Some((parse(&p.role)?, p.name)))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "peer certificate carries no recognised role",
                )
            })?;
        Ok((stream, role, name))
    }

    /// Completes the handshake. The `PeerId` is `None` only on a
    /// `listen_optional_client_auth` socket, for a peer that sent no certificate.
    pub async fn handshake(self) -> io::Result<(Stream, Option<PeerId>)> {
        let tls = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            TlsAcceptor::from(self.config).accept(self.stream),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tls handshake timed out"))??;
        let stream = Stream(TlsStream::Server(tls));
        stream.log_handshake("server");
        let peer = peer_of(&stream);
        Ok((stream, peer))
    }
}

/// Applies every rotation frame from `r` to `id` until a clean EOF. A frame
/// that fails to read (oversize, short, I/O) calls `on_broken` and ends the
/// loop; a bundle that merely fails to apply is only a warning (the stream is
/// still in sync).
pub(crate) fn rotate_from(
    r: &mut impl std::io::Read,
    id: &Identity,
    on_broken: impl Fn(io::Error),
) {
    loop {
        match Bundle::read_from(r) {
            Ok(Some(b)) => match id.update(&b) {
                Ok(()) => info!(peer = ?id.peer(), "ipc identity rotated"),
                Err(e) => warn!(error = %e, "ignoring bad identity rotation"),
            },
            Ok(None) => {
                debug!("identity pipe closed, no further rotations");
                return;
            }
            Err(e) => {
                on_broken(e);
                return;
            }
        }
    }
}

#[cfg(test)]
mod crl_tests {
    use super::*;
    use crate::{KeyAlg, PeerId};
    use std::time::Duration;

    /// An empty-crl frame keeps the CRL held; a frame with a bad leaf still
    /// installs its CRL (a revocation is never dropped).
    #[test]
    fn crl_survives_empty_frames_and_a_bad_leaf() {
        let ca = crate::Ca::new(KeyAlg::MlDsa65).unwrap();
        let mut b = ca
            .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
            .unwrap();
        let id = Identity::from_bundle(&b).unwrap();
        let held = |id: &Identity| id.0.crl.lock().unwrap().clone();
        assert_eq!(held(&id).len(), 0);

        let crl = ca.crl_der().unwrap();
        let mut bad = b.clone();
        bad.cert = vec![1, 2, 3];
        bad.crl.clone_from(&crl);
        assert!(id.update(&bad).is_err());
        assert_eq!(held(&id), crl);

        b.crl.clear();
        id.update(&b).unwrap();
        id.update(&b).unwrap();
        assert_eq!(held(&id), crl);
    }
}
