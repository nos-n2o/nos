//! TLS for `nos-restd`'s TCP listener and its clients — the one place other
//! crates get rustls from, so the post-quantum policy stays here.
//!
//! Same key exchange as the IPC transport (hybrid `X25519MLKEM768` only) but
//! ECDSA P-256 certificates (`Policy::Rest`, chaining to the REST CA), so a
//! browser or stock client can still hold and present one. Client
//! authentication is *optional* at the TLS layer — the login route must be
//! reachable without a certificate — and the caller refuses everything else
//! to an anonymous peer. Resumption and tickets are off, for the same reason
//! as IPC: a resumed session skips certificate verification, which would let a
//! deleted user's session live on.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use rustls::client::Resumption;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{
    ClientHello, NoServerSessionStorage, ResolvesServerCert, WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::debug;

use crate::ca::err;
use crate::identity::certified_key;
use crate::policy::{provider, Policy};
use crate::{PeerId, Serial};

/// The server side of an accepted REST TLS connection.
pub type RestStream = tokio_rustls::server::TlsStream<TcpStream>;

const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

fn roots(ca_der: &[u8]) -> io::Result<Arc<RootCertStore>> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .map_err(err)?;
    Ok(Arc::new(roots))
}

/// Serves whatever server certificate is current at handshake time.
struct Current(ArcSwapOption<CertifiedKey>);

impl fmt::Debug for Current {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Current")
    }
}

impl ResolvesServerCert for Current {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.load_full()
    }
}

/// The listener's TLS: trusts the REST CA for client certificates, presents a
/// server certificate that can be swapped without touching a connection.
pub struct RestServer {
    current: Arc<Current>,
    acceptor: TlsAcceptor,
}

/// A completed handshake.
pub struct Accepted {
    /// The established TLS stream.
    pub stream: RestStream,
    /// The user the client's certificate names; `None` if it sent none.
    pub user: Option<String>,
    /// Hex serial of that certificate (`Serial`'s spelling), for the watchdog's liveness check.
    pub serial: Option<String>,
    /// The role claim SAN (`Ca::sign_csr_claiming`) of that certificate, if any (#1360).
    pub claim: Option<String>,
    /// `true` when HTTP/2 was negotiated.
    pub h2: bool,
}

impl RestServer {
    /// Builds a server trusting `rest_ca_der` for client certificates (optional at TLS level).
    pub fn new(rest_ca_der: &[u8]) -> io::Result<Self> {
        let provider = provider(Policy::Rest);
        let verifier =
            WebPkiClientVerifier::builder_with_provider(roots(rest_ca_der)?, provider.clone())
                .allow_unauthenticated()
                .build()
                .map_err(err)?;
        let current = Arc::new(Current(ArcSwapOption::empty()));
        let mut cfg = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(err)?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(current.clone());
        cfg.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
        cfg.send_tls13_tickets = 0;
        cfg.session_storage = Arc::new(NoServerSessionStorage {});
        Ok(Self {
            current,
            acceptor: TlsAcceptor::from(Arc::new(cfg)),
        })
    }

    /// Swaps in the server certificate (`Ca::sign_server_csr` on a key this
    /// process generated). New handshakes use it at once.
    pub fn set_certificate(&self, cert_der: &[u8], key_der: &[u8]) -> io::Result<()> {
        self.current
            .0
            .store(Some(certified_key(cert_der, key_der)?));
        Ok(())
    }

    /// Whether a server certificate has been installed yet.
    pub fn has_certificate(&self) -> bool {
        self.current.0.load().is_some()
    }

    /// Runs the handshake on an accepted connection — call it inside the
    /// connection's own task so a slow peer never stalls the accept loop.
    pub async fn accept(&self, tcp: TcpStream) -> io::Result<Accepted> {
        let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tls handshake timed out"))??;
        let (_, conn) = stream.get_ref();
        let leaf = conn.peer_certificates().and_then(|c| c.first());
        let user = leaf
            .and_then(|c| PeerId::from_cert_der(c))
            .filter(|p| p.role == "user")
            .map(|p| p.name);
        let serial = leaf
            .and_then(|c| Serial::of(c).ok())
            .filter(|_| user.is_some())
            .map(|s| s.to_string());
        let claim = leaf
            .and_then(|c| PeerId::claim_from_cert_der(c))
            .filter(|_| user.is_some());
        let h2 = conn.alpn_protocol() == Some(b"h2");
        debug!(
            user = ?user.as_deref().unwrap_or("none"),
            alpn = %if h2 { "h2" } else { "http/1.1" },
            kx = ?conn.negotiated_key_exchange_group()
                .map(rustls::crypto::SupportedKxGroup::name),
            "rest tls handshake ok"
        );
        Ok(Accepted {
            stream,
            user,
            serial,
            claim,
            h2,
        })
    }
}

/// A client's TLS for the REST listener: trusts `rest_ca_pem` (the
/// `rest-ca.crt` the watchdog publishes), presents `identity` — a REST-CA
/// certificate and its PKCS#8 key, both DER — if given. For `reqwest`
/// (`use_preconfigured_tls`), the e2e harness and tests.
pub fn client_config(
    rest_ca_pem: &[u8],
    identity: Option<(&[u8], &[u8])>,
) -> io::Result<ClientConfig> {
    let ca = CertificateDer::from_pem_slice(rest_ca_pem).map_err(err)?;
    let builder = ClientConfig::builder_with_provider(provider(Policy::Rest))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(err)?
        .with_root_certificates(roots(&ca)?);
    let mut cfg = match identity {
        Some((cert, key)) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(cert.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())), // ponytail: rustls needs an owned key; this copy is not zeroized (test/e2e client only)
            )
            .map_err(err)?,
        None => builder.with_no_client_auth(),
    };
    cfg.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    cfg.resumption = Resumption::disabled();
    Ok(cfg)
}
