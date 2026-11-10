use std::io;
use std::path::PathBuf;
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair, SanType};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::testing::TestPki;
use crate::{generate_csr, Bundle, Ca, Identity, KeyAlg, Negotiated, PeerId, Policy};

fn sock(name: &str) -> (tempdir::Guard, PathBuf) {
    let g = tempdir::Guard::new();
    let p = g.0.join(name);
    (g, p)
}

/// A dir removed on drop — no `tempfile` dependency for one directory.
mod tempdir {
    use std::path::PathBuf;
    pub struct Guard(pub PathBuf);
    impl Guard {
        pub fn new() -> Self {
            // nosemgrep: rust.lang.security.temp-dir.temp-dir -- test scratch dir, not a security boundary.
            let p = std::env::temp_dir().join(format!(
                "nos-pki-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// Serves one connection: echoes what it reads, returns who the peer was.
async fn echo_once(l: crate::Listener) -> io::Result<Option<PeerId>> {
    let (mut s, peer) = l.accept().await?.handshake().await?;
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).await?;
    s.write_all(&buf).await?;
    s.flush().await?;
    Ok(peer)
}

async fn ping(mut s: crate::Stream) -> io::Result<()> {
    s.write_all(b"hello").await?;
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"hello");
    Ok(())
}

#[tokio::test]
async fn mutual_auth_and_identity_on_both_ends() {
    let pki = TestPki::new();
    let (_g, path) = sock("a.sock");
    let server = tokio::spawn(echo_once(
        pki.identity("ribd", "rt1").listen(&path).unwrap(),
    ));
    let client = pki.identity("bgpd", "r1");
    let stream = client
        .connect(&path, &PeerId::new("ribd", "rt1"))
        .await
        .unwrap();
    ping(stream).await.unwrap();
    assert_eq!(
        server.await.unwrap().unwrap(),
        Some(PeerId::new("bgpd", "r1"))
    );
}

#[tokio::test]
async fn client_refuses_a_server_that_is_not_who_it_expected() {
    let pki = TestPki::new();
    let (_g, path) = sock("b.sock");
    let _server = tokio::spawn(echo_once(
        pki.identity("ribd", "rt2").listen(&path).unwrap(),
    ));
    let e = pki
        .identity("bgpd", "r1")
        .connect(&path, &PeerId::new("ribd", "rt1"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn a_peer_certified_by_another_ca_is_rejected() {
    let (ours, theirs) = (TestPki::new(), TestPki::new());
    let (_g, path) = sock("c.sock");
    let server = tokio::spawn(echo_once(
        ours.identity("ribd", "rt1").listen(&path).unwrap(),
    ));
    let outcome = async {
        let s = theirs
            .identity("bgpd", "r1")
            .connect(&path, &PeerId::new("ribd", "rt1"))
            .await?;
        ping(s).await
    }
    .await;
    assert!(outcome.is_err());
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn an_expired_certificate_is_rejected() {
    let ca = Ca::new(KeyAlg::MlDsa65).unwrap();
    let now = OffsetDateTime::now_utc();
    let expired = ca
        .issue_between(
            &PeerId::new("bgpd", "r1"),
            now - time::Duration::hours(2),
            now - time::Duration::hours(1),
        )
        .unwrap();
    let live = ca
        .issue(&PeerId::new("ribd", "rt1"), Duration::from_secs(60))
        .unwrap();
    let (_g, path) = sock("d.sock");
    let server = tokio::spawn(echo_once(
        Identity::from_bundle(&live).unwrap().listen(&path).unwrap(),
    ));
    let outcome = async {
        let s = Identity::from_bundle(&expired)
            .unwrap()
            .connect(&path, &PeerId::new("ribd", "rt1"))
            .await?;
        ping(s).await
    }
    .await;
    assert!(outcome.is_err());
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn anonymous_clients_only_reach_the_optional_auth_socket() {
    let pki = TestPki::new();
    let (_g, strict) = sock("strict.sock");
    let (_g2, open) = sock("open.sock");
    let server = pki.identity("watchdog", "");
    let strict_l = server.listen(&strict).unwrap();
    let open_l = server.listen_optional_client_auth(&open).unwrap();
    let strict_task = tokio::spawn(echo_once(strict_l));
    let open_task = tokio::spawn(echo_once(open_l));

    let anon = pki.anonymous();
    let want = PeerId::new("watchdog", "");
    let refused = async {
        let s = anon.connect(&strict, &want).await?;
        ping(s).await
    }
    .await;
    assert!(refused.is_err());
    assert!(strict_task.await.unwrap().is_err());

    ping(anon.connect(&open, &want).await.unwrap())
        .await
        .unwrap();
    assert_eq!(open_task.await.unwrap().unwrap(), None);
}

#[tokio::test]
async fn ipc_sockets_are_group_readable_for_the_nos_group() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let (_g, path) = sock("perm.sock");
    let id = TestPki::new().identity("ribd", "rt1");
    let _l = id.listen(&path).unwrap();
    assert_eq!(mode(&path), 0o660);
    // Re-binding over a stale file, and the optional-client-auth variant.
    let _l2 = id.listen_optional_client_auth(&path).unwrap();
    assert_eq!(mode(&path), 0o660);
}

#[test]
fn an_anonymous_identity_cannot_serve() {
    let (_g, path) = sock("e.sock");
    assert!(TestPki::new().anonymous().listen(&path).is_err());
}

#[test]
fn csr_signing_takes_the_key_but_never_the_identity() {
    let ca = Ca::new(KeyAlg::MlDsa65).unwrap();
    // A hostile client asks for someone else's identity in its CSR.
    let key = KeyPair::generate_for(&rcgen::PKCS_ML_DSA_65).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.subject_alt_names
        .push(SanType::URI("nos://configd/".try_into().unwrap()));
    let csr = p.serialize_request(&key).unwrap();

    let cert = ca
        .sign_csr(
            csr.der(),
            &PeerId::new("user", "alice"),
            Duration::from_secs(60),
        )
        .unwrap();
    assert_eq!(
        PeerId::from_cert_der(&cert),
        Some(PeerId::new("user", "alice"))
    );

    // …and the result is a usable identity on the client's own key.
    let (csr, key) = generate_csr().unwrap();
    let cert = ca
        .sign_csr(&csr, &PeerId::new("user", "bob"), Duration::from_secs(60))
        .unwrap();
    let id = Identity::from_bundle(&Bundle {
        ca: ca.cert_der().to_vec(),
        cert,
        key,
        crl: Vec::new(),
    })
    .unwrap();
    assert_eq!(id.peer(), Some(PeerId::new("user", "bob")));
}

#[test]
fn a_garbage_csr_is_an_error_not_a_panic() {
    let ca = Ca::new(KeyAlg::MlDsa65).unwrap();
    assert!(ca
        .sign_csr(
            b"not a csr",
            &PeerId::new("user", "x"),
            Duration::from_secs(1)
        )
        .is_err());
}

#[tokio::test]
async fn rotation_reaches_new_connections_and_spares_old_ones() {
    let pki = TestPki::new();
    let (_g, path) = sock("f.sock");
    let l = pki.identity("ribd", "rt1").listen(&path).unwrap();
    let client = pki.identity("bgpd", "r1");
    let expect = PeerId::new("ribd", "rt1");

    let (old, srv) = tokio::join!(client.connect(&path, &expect), async {
        l.accept().await.unwrap().handshake().await.unwrap()
    });
    let (mut old, (mut old_srv, peer)) = (old.unwrap(), srv);
    assert_eq!(peer, Some(PeerId::new("bgpd", "r1")));

    client
        .update(
            &pki.ca()
                .issue(&PeerId::new("bgpd", "r2"), Duration::from_secs(60))
                .unwrap(),
        )
        .unwrap();

    let (new, srv) = tokio::join!(client.connect(&path, &expect), async {
        l.accept().await.unwrap().handshake().await.unwrap()
    });
    let (_new, (_new_srv, peer)) = (new.unwrap(), srv);
    assert_eq!(peer, Some(PeerId::new("bgpd", "r2")));

    // The connection opened before the rotation still works.
    old.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    old_srv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[test]
fn update_refuses_a_bundle_from_another_ca() {
    let (a, b) = (TestPki::new(), TestPki::new());
    let id = a.identity("bgpd", "r1");
    let foreign = b
        .ca()
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    assert!(id.update(&foreign).is_err());
}

#[test]
fn bundle_frames_round_trip_and_reject_garbage() {
    let ca = Ca::new(KeyAlg::MlDsa65).unwrap();
    let b = ca
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    let mut wire = b.encode();
    wire.extend(b.encode().iter().copied());
    let mut r = wire.as_slice();
    assert_eq!(Bundle::read_from(&mut r).unwrap(), Some(b.clone()));
    assert_eq!(Bundle::read_from(&mut r).unwrap(), Some(b));
    assert_eq!(Bundle::read_from(&mut r).unwrap(), None);

    assert!(Bundle::read_from(&mut &u32::MAX.to_le_bytes()[..]).is_err());
    // A frame whose inner lengths overrun it.
    let mut bad = 8u32.to_le_bytes().to_vec();
    bad.extend(1000u32.to_le_bytes());
    bad.extend([0u8; 4]);
    assert!(Bundle::read_from(&mut bad.as_slice()).is_err());
}

#[test]
fn debug_output_never_shows_key_material() {
    let ca = Ca::new(KeyAlg::MlDsa65).unwrap();
    let b = ca
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    assert!(!format!("{b:?}").contains(&format!("{:?}", &b.key[..8])));
}

/// One-shot clients just drop their connection. That must read as a plain EOF
/// on the server, not as an error every server would log.
#[tokio::test]
async fn a_peer_that_hangs_up_without_close_notify_reads_as_clean_eof() {
    let pki = TestPki::new();
    let (_g, path) = sock("g.sock");
    let listener = pki.identity("ribd", "rt1").listen(&path).unwrap();
    let client = pki.identity("bgpd", "r1");

    let expect = PeerId::new("ribd", "rt1");
    let (stream, server) = tokio::join!(client.connect(&path, &expect), async {
        listener.accept().await.unwrap().handshake().await.unwrap()
    });
    let mut stream = stream.unwrap();
    let (mut server_stream, _) = server;
    stream.write_all(b"hi").await.unwrap();
    stream.flush().await.unwrap();
    drop(stream); // no shutdown, no close_notify

    let mut got = Vec::new();
    server_stream
        .read_to_end(&mut got)
        .await
        .expect("a hang-up is EOF, not an error");
    assert_eq!(got, b"hi");
}

// ---- post-quantum policy ------------------------------------------------

#[tokio::test]
async fn handshake_is_hybrid_ml_kem_with_ml_dsa_certificates() {
    let pki = TestPki::new();
    let (_g, path) = sock("pq.sock");
    let listener = pki.identity("ribd", "rt1").listen(&path).unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await?.handshake().await?;
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await?;
        io::Result::Ok(s.negotiated())
    });
    let mut s = pki
        .identity("bgpd", "r1")
        .connect(&path, &PeerId::new("ribd", "rt1"))
        .await
        .unwrap();
    let want = Negotiated {
        kx: "X25519MLKEM768".into(),
        peer_key: "ML-DSA-65",
    };
    assert_eq!(s.negotiated(), want);
    s.write_all(b"hello").await.unwrap();
    assert_eq!(server.await.unwrap().unwrap(), want);
}

/// A classical client — right CA, but only X25519 key exchange — must fail the
/// handshake rather than negotiate down.
#[tokio::test]
async fn classical_key_exchange_is_refused() {
    use rustls::crypto::aws_lc_rs;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    let pki = TestPki::new();
    let (_g, path) = sock("classical.sock");
    let listener = pki.identity("ribd", "rt1").listen(&path).unwrap();
    let server =
        tokio::spawn(async move { listener.accept().await?.handshake().await.map(|_| ()) });

    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(pki.ca().cert_der().to_vec()))
        .unwrap();
    let b = pki
        .ca()
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![CertificateDer::from(b.cert)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(b.key.to_vec())),
        )
        .unwrap();
    let sock = tokio::net::UnixStream::connect(&path).await.unwrap();
    let res = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg))
        .connect(ServerName::try_from("nos.internal").unwrap(), sock)
        .await;
    assert!(res.is_err(), "a classical-only client must not connect");
    assert!(server.await.unwrap().is_err());
}

/// A classical (ECDSA) certificate is refused by the IPC policy even when it
/// chains to a CA the server trusts.
#[tokio::test]
async fn ecdsa_certificates_are_refused_on_ipc() {
    let pki = TestPki::new();
    let (_g, path) = sock("ecdsa.sock");
    let listener = pki.identity("ribd", "rt1").listen(&path).unwrap();
    let server =
        tokio::spawn(async move { listener.accept().await?.handshake().await.map(|_| ()) });

    let ecdsa_ca = Ca::new(KeyAlg::EcdsaP256).unwrap();
    let b = ecdsa_ca
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    // Trusts the server's ML-DSA CA, presents an ECDSA leaf from another CA.
    let id = Identity::anonymous(pki.ca().cert_der()).unwrap();
    id.set_certificate(b.cert, b.key).unwrap();
    let _ = id.connect(&path, &PeerId::new("ribd", "rt1")).await;
    assert!(server.await.unwrap().is_err());
}

/// A CA only certifies keys of its own algorithm.
#[test]
fn a_ca_refuses_a_key_of_another_algorithm() {
    let ca = Ca::new(KeyAlg::MlDsa65).unwrap();
    let (csr, _) = crate::generate_csr_for(KeyAlg::EcdsaP256).unwrap();
    assert!(ca
        .sign_csr(&csr, &PeerId::new("user", "eve"), Duration::from_secs(60))
        .is_err());
}

// ---- REST listener TLS --------------------------------------------------

mod rest {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use rustls::pki_types::ServerName;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    use crate::rest::{client_config, RestServer};
    use crate::{generate_csr_for, Ca, KeyAlg, PeerId};

    const HOUR: Duration = Duration::from_secs(3600);

    struct Fixture {
        ca: Ca,
        server: Arc<RestServer>,
        listener: TcpListener,
    }

    async fn fixture() -> Fixture {
        let ca = Ca::new(KeyAlg::EcdsaP256).unwrap();
        let server = RestServer::new(ca.cert_der()).unwrap();
        let (csr, key) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
        let cert = ca
            .sign_server_csr(&csr, &[Ipv4Addr::LOCALHOST.into()], HOUR)
            .unwrap();
        server.set_certificate(&cert, &key).unwrap();
        Fixture {
            ca,
            server: Arc::new(server),
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
        }
    }

    fn user_cert(ca: &Ca, name: &str) -> (Vec<u8>, Vec<u8>) {
        let (csr, key) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
        let cert = ca.sign_csr(&csr, &PeerId::new("user", name), HOUR).unwrap();
        (cert, key.to_vec())
    }

    /// Connects with `cfg`; returns what the client saw (`h2`, kx group) or
    /// the error, plus what the server saw (user, h2) or its error.
    async fn handshake(
        f: &Fixture,
        cfg: rustls::ClientConfig,
    ) -> (
        std::io::Result<(bool, String)>,
        std::io::Result<(Option<String>, bool)>,
    ) {
        let addr = f.listener.local_addr().unwrap();
        let server = f.server.clone();
        let tcp = TcpStream::connect(addr).await;
        let client = async move {
            let tls = TlsConnector::from(Arc::new(cfg))
                .connect(ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()), tcp?)
                .await?;
            let (_, conn) = tls.get_ref();
            let kx = format!("{:?}", conn.negotiated_key_exchange_group().unwrap().name());
            std::io::Result::Ok((conn.alpn_protocol() == Some(b"h2"), kx))
        };
        let accept = async {
            let (tcp, _) = f.listener.accept().await?;
            let a = server.accept(tcp).await?;
            std::io::Result::Ok((a.user, a.h2))
        };
        tokio::join!(client, accept)
    }

    #[tokio::test]
    async fn a_user_certificate_names_the_user_over_post_quantum_h2() {
        let f = fixture().await;
        let (cert, key) = user_cert(&f.ca, "alice");
        let cfg = client_config(f.ca.cert_pem().as_bytes(), Some((&cert, &key))).unwrap();
        let (c, s) = handshake(&f, cfg).await;
        assert_eq!(c.unwrap(), (true, "X25519MLKEM768".to_string()));
        assert_eq!(s.unwrap(), (Some("alice".to_string()), true));
    }

    #[tokio::test]
    async fn a_client_without_a_certificate_is_let_through_anonymous() {
        let f = fixture().await;
        let cfg = client_config(f.ca.cert_pem().as_bytes(), None).unwrap();
        let (c, s) = handshake(&f, cfg).await;
        c.unwrap();
        assert_eq!(s.unwrap().0, None);
    }

    #[tokio::test]
    async fn a_certificate_from_another_ca_is_refused() {
        let f = fixture().await;
        let other = Ca::new(KeyAlg::EcdsaP256).unwrap();
        let (cert, key) = user_cert(&other, "mallory");
        let cfg = client_config(f.ca.cert_pem().as_bytes(), Some((&cert, &key))).unwrap();
        let (_, s) = handshake(&f, cfg).await;
        assert!(s.is_err());
    }

    #[tokio::test]
    async fn a_classical_key_exchange_is_refused() {
        use rustls::crypto::aws_lc_rs;
        let f = fixture().await;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                f.ca.cert_der().to_vec(),
            ))
            .unwrap();
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let (c, s) = handshake(&f, cfg).await;
        assert!(c.is_err() && s.is_err());
    }
}

/// The gate for revocation (#72): webpki must verify an ML-DSA-65-signed CRL
/// and refuse a leaf it lists, on both verifier sides, while an unlisted leaf
/// from the same CA still passes.
#[test]
fn an_ml_dsa_crl_is_enforced_by_both_verifiers() {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, ServerName, UnixTime};
    use rustls::server::WebPkiClientVerifier;

    let ca = Ca::new(KeyAlg::MlDsa65).unwrap();
    let live = ca
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    let gone = ca
        .issue(&PeerId::new("bgpd", "r2"), Duration::from_secs(60))
        .unwrap();
    let crl = ca
        .revoke(&[crate::Serial::of(&gone.cert).unwrap()])
        .unwrap();

    let provider = crate::policy::provider(crate::Policy::Ipc);
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.cert_der().to_vec()))
        .unwrap();
    let roots = std::sync::Arc::new(roots);
    let crls = vec![CertificateRevocationListDer::from(crl)];
    let client_v = WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone())
        .with_crls(crls.clone())
        .only_check_end_entity_revocation()
        .allow_unknown_revocation_status()
        .build()
        .unwrap();
    let server_v = WebPkiServerVerifier::builder_with_provider(roots, provider)
        .with_crls(crls)
        .only_check_end_entity_revocation()
        .allow_unknown_revocation_status()
        .build()
        .unwrap();
    let now = UnixTime::now();
    let name = ServerName::try_from(crate::ca::SERVER_NAME).unwrap();
    let check = |b: &Bundle| {
        let ee = CertificateDer::from(b.cert.clone());
        (
            client_v.verify_client_cert(&ee, &[], now).is_ok(),
            server_v
                .verify_server_cert(&ee, &[], &name, &[], now)
                .is_ok(),
        )
    };
    assert_eq!(check(&live), (true, true));
    assert_eq!(check(&gone), (false, false));
}

/// Revocation end to end over real handshakes: a listener made *before* the
/// CRL arrived refuses a revoked client, a client refuses a revoked server,
/// an unrevoked peer still gets in, and a connection opened before the
/// revocation keeps working.
#[tokio::test]
async fn a_revoked_peer_is_refused_on_both_sides_but_open_streams_survive() {
    let pki = TestPki::new();
    let (_g, path) = sock("crl.sock");
    let server = pki.identity("ribd", "rt1");
    let l = server.listen(&path).unwrap();
    let revoked = pki
        .ca()
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    let client = Identity::from_bundle(&revoked).unwrap();
    let expect = PeerId::new("ribd", "rt1");

    let (old, srv) = tokio::join!(client.connect(&path, &expect), async {
        l.accept().await.unwrap().handshake().await.unwrap()
    });
    let (mut old, (mut old_srv, _)) = (old.unwrap(), srv);

    let crl = pki
        .ca()
        .revoke(&[crate::Serial::of(&revoked.cert).unwrap()])
        .unwrap();
    server.set_crl(&crl).unwrap();

    // The revoked client is refused by the listener that predates the CRL.
    let (c, s) = tokio::join!(
        async { ping(client.connect(&path, &expect).await?).await },
        async { l.accept().await.unwrap().handshake().await }
    );
    assert!(c.is_err() && s.is_err());

    // Another client from the same CA is let through.
    let other = pki.identity("bgpd", "r2");
    let (c, s) = tokio::join!(other.connect(&path, &expect), async {
        l.accept().await.unwrap().handshake().await
    });
    assert!(c.is_ok() && s.is_ok());

    // A client holding the CRL refuses the revoked identity as a *server*.
    let (_g2, path2) = sock("crl2.sock");
    let l2 = client.listen(&path2).unwrap();
    let checker = pki.identity("configd", "");
    checker.set_crl(&crl).unwrap();
    let revoked_peer = PeerId::new("bgpd", "r1");
    let (c, _) = tokio::join!(checker.connect(&path2, &revoked_peer), async {
        l2.accept().await.unwrap().handshake().await
    });
    assert!(c.is_err());

    // Established before the revocation: untouched.
    old.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    old_srv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[test]
fn the_crl_prunes_expired_entries_and_its_number_grows() {
    use x509_parser::prelude::FromDer;
    use x509_parser::revocation_list::CertificateRevocationList;
    let ca = Ca::new(KeyAlg::MlDsa65).unwrap();
    let now = OffsetDateTime::now_utc();
    let expired = ca
        .issue_between(
            &PeerId::new("bgpd", "old"),
            now - time::Duration::hours(3),
            now - time::Duration::hours(2),
        )
        .unwrap();
    let live = ca
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    let parse = |der: &[u8]| {
        let (_, crl) = CertificateRevocationList::from_der(der).unwrap();
        (
            crl.crl_number().unwrap().clone(),
            crl.iter_revoked_certificates().count(),
        )
    };
    let (n0, e0) = parse(&ca.crl_der().unwrap());
    let (n1, e1) = parse(
        &ca.revoke(&[
            crate::Serial::of(&expired.cert).unwrap(),
            crate::Serial::of(&live.cert).unwrap(),
        ])
        .unwrap(),
    );
    assert_eq!((e0, e1), (0, 1), "the expired leaf is never listed");
    assert!(n1 > n0);
}

#[test]
fn a_bundle_carries_its_crl_through_the_frame() {
    let ca = Ca::new(KeyAlg::MlDsa65).unwrap();
    let mut b = ca
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    b.crl = ca.crl_der().unwrap();
    assert_eq!(
        Bundle::read_from(&mut b.encode().as_slice()).unwrap(),
        Some(b)
    );
}

/// #677: a CRL of ~28k serials (> the old 1 MiB frame cap) still crosses the
/// pipe; a frame past the 16 MiB cap is still refused.
#[test]
fn a_crl_over_one_mib_fits_a_frame_but_the_cap_holds() {
    let ca = Ca::new(KeyAlg::MlDsa65).unwrap();
    let mut b = ca
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    b.crl = vec![7u8; 28_000 * 39];
    assert!(b.crl.len() > 1 << 20);
    assert_eq!(
        Bundle::read_from(&mut b.encode().as_slice()).unwrap(),
        Some(b)
    );
    let over = u32::try_from((16 << 20) + 1).unwrap().to_le_bytes();
    assert!(Bundle::read_from(&mut &over[..]).is_err());
}

/// #677: a frame that cannot be read ends the rotation loop through
/// `on_broken` (the daemon exits); a clean EOF and a bad-but-in-sync bundle do
/// not.
#[test]
fn a_broken_rotation_pipe_is_fatal_but_eof_and_a_bad_bundle_are_not() {
    use std::cell::Cell;
    let ca = Ca::new(KeyAlg::MlDsa65).unwrap();
    let b = ca
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    let id = Identity::from_bundle(&b).unwrap();
    let broken = Cell::new(0);
    let run = |wire: &[u8]| {
        crate::identity::rotate_from(&mut &wire[..], &id, |_| broken.set(broken.get() + 1));
        broken.get()
    };
    assert_eq!(run(&b.encode()), 0, "a good rotation then EOF");
    let foreign = Ca::new(KeyAlg::MlDsa65)
        .unwrap()
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    assert_eq!(run(&foreign.encode()), 0, "a bad bundle only warns");
    assert_eq!(run(&u32::MAX.to_le_bytes()), 1, "an oversize frame");
    assert_eq!(run(&[1, 0]), 1, "a truncated length is a clean EOF");
    let mut short = 8u32.to_le_bytes().to_vec();
    short.extend([0u8; 3]);
    assert_eq!(run(&short), 2, "a truncated body");
}

/// Pins today's IPC and REST algorithms, so an edit to the `Syslog` arm (or
/// the `allow_tls12` opt-in beside it) cannot leak into either.
#[test]
fn ipc_and_rest_policies_are_unchanged() {
    use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
    use rustls::SignatureScheme;
    for policy in [Policy::Ipc, Policy::Rest, Policy::Syslog] {
        let p = crate::policy::provider(policy);
        assert_eq!(p.kx_groups.len(), 1);
        assert_eq!(p.kx_groups[0].name(), kx_group::X25519MLKEM768.name());
        assert_eq!(p.cipher_suites.len(), 1);
        assert_eq!(
            p.cipher_suites[0].suite(),
            cipher_suite::TLS13_AES_256_GCM_SHA384.suite()
        );
    }
    let schemes = |p| {
        crate::policy::provider(p)
            .signature_verification_algorithms
            .supported_schemes()
    };
    assert_eq!(schemes(Policy::Ipc), [SignatureScheme::ML_DSA_65]);
    assert_eq!(
        schemes(Policy::Rest),
        [SignatureScheme::ECDSA_NISTP256_SHA256]
    );
}

/// The `allow_tls12` opt-in's client (TLS 1.2, classical groups) gets nowhere
/// on an IPC socket or the REST listener.
#[tokio::test]
async fn tls12_client_is_refused_on_ipc_and_rest() {
    use rustls::pki_types::{CertificateDer, ServerName};
    let mut p = (*crate::syslog::allow_tls12_provider()).clone();
    p.signature_verification_algorithms =
        rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
    let client = |ca: &[u8]| {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ca.to_vec())).unwrap();
        std::sync::Arc::new(
            rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(p.clone()))
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    };

    let pki = TestPki::new();
    let (_g, path) = sock("tls12.sock");
    let listener = pki.identity("ribd", "rt1").listen(&path).unwrap();
    let server =
        tokio::spawn(async move { listener.accept().await?.handshake().await.map(|_| ()) });
    let sock = tokio::net::UnixStream::connect(&path).await.unwrap();
    let res = tokio_rustls::TlsConnector::from(client(pki.ca().cert_der()))
        .connect(ServerName::try_from("nos.internal").unwrap(), sock)
        .await;
    assert!(res.is_err());
    assert!(server.await.unwrap().is_err());

    let rest_ca = Ca::new(KeyAlg::EcdsaP256).unwrap();
    let rest = crate::rest::RestServer::new(rest_ca.cert_der()).unwrap();
    let (csr, key) = crate::generate_csr_for(KeyAlg::EcdsaP256).unwrap();
    let cert = rest_ca
        .sign_server_csr(
            &csr,
            &["127.0.0.1".parse().unwrap()],
            Duration::from_secs(60),
        )
        .unwrap();
    rest.set_certificate(&cert, &key).unwrap();
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = l.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        rest.accept(tcp).await.map(|_| ())
    });
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let res = tokio_rustls::TlsConnector::from(client(rest_ca.cert_der()))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await;
    assert!(res.is_err());
    assert!(srv.await.unwrap().is_err());
}

/// The server learns *which* certificate the client presented (#637).
#[tokio::test]
async fn peer_serial_is_the_presented_leaf_serial() {
    let pki = TestPki::new();
    let (_g, path) = sock("h.sock");
    let l = pki.identity("ribd", "rt1").listen(&path).unwrap();
    let bundle = pki
        .ca()
        .issue(&PeerId::new("bgpd", "r1"), Duration::from_secs(60))
        .unwrap();
    let client = crate::Identity::from_bundle(&bundle).unwrap();
    let expect = PeerId::new("ribd", "rt1");
    let (c, s) = tokio::join!(client.connect(&path, &expect), async {
        l.accept().await.unwrap().handshake().await.unwrap()
    });
    let want = crate::ca::Serial::of(&bundle.cert).unwrap().to_string();
    assert_eq!(s.0.peer_serial(), Some(want));
    assert!(c.unwrap().peer_serial().is_some());
}
