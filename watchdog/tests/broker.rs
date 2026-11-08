use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use nos_pki::{generate_csr, generate_csr_for, Identity, KeyAlg, PeerId};
use nos_proto::{
    Config, Event, IpcCodec, Request, Role, ServiceRef, User, WatchdogEvent, WatchdogRequest,
};
use nos_watchdog::broker::{self, Sockets};
use nos_watchdog::{EndpointKind, EndpointRegistry, Pki};
use tokio::io::split;
use tokio_util::codec::{FramedRead, FramedWrite};

struct Env {
    tmp: tempfile::TempDir,
    pki: Arc<Pki>,
    broker: PathBuf,
    users: Arc<Mutex<Vec<User>>>,
}

/// A broker plus a stand-in `nos-configd` (a real TLS server holding the
/// `configd` identity) answering `Get` with `users`.
async fn env(users: Vec<User>) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let pki = Pki::start(
        tmp.path(),
        Duration::from_secs(60),
        Duration::from_secs(30),
        Duration::from_secs(120),
    )
    .unwrap();
    let users = Arc::new(Mutex::new(users));

    let config_socket = tmp.path().join("config.sock");
    let configd = Identity::from_bundle(&pki.mint(Role::Configd, "").unwrap()).unwrap();
    let listener = configd.listen(&config_socket).unwrap();
    let served = users.clone();
    tokio::spawn(async move {
        loop {
            let incoming = listener.accept().await.unwrap();
            let served = served.clone();
            tokio::spawn(async move {
                let Ok((stream, _)) = incoming.handshake().await else {
                    return;
                };
                let (r, w) = split(stream);
                let mut reader = FramedRead::new(r, IpcCodec::<Request>::default());
                let mut writer = FramedWrite::new(w, IpcCodec::<Event>::default());
                while let Some(Ok(request)) = reader.next().await {
                    let Some(event) = stub_reply(&served, request) else {
                        return;
                    };
                    writer.send(event).await.unwrap();
                }
            });
        }
    });

    let registry = EndpointRegistry::default();
    registry
        .set(
            EndpointKind::RibTable,
            "rt1",
            PathBuf::from("/run/nos/rib-rt1.sock"),
        )
        .await;
    let broker_socket = tmp.path().join("watchdog.sock");
    let task = broker::start(
        &broker_socket,
        registry,
        Sockets {
            config: config_socket,
            interfaces: PathBuf::from("/run/nos/interface.sock"),
            log: PathBuf::from("/run/nos/log.sock"),
            lacp: PathBuf::from("/run/nos/lacp.sock"),
            lldp: PathBuf::from("/run/nos/lldp.sock"),
            bfd: PathBuf::from("/run/nos/bfd.sock"),
            stp: PathBuf::from("/run/nos/stp.sock"),
            acl: PathBuf::from("/run/nos/acl.sock"),
        },
        pki.clone(),
    )
    .unwrap();
    std::mem::forget(task); // runs for the test's lifetime
    Env {
        tmp,
        pki,
        broker: broker_socket,
        users,
    }
}

/// The stand-in `nos-configd`'s answer to one request.
fn stub_reply(users: &Mutex<Vec<User>>, request: Request) -> Option<Event> {
    Some(match request {
        Request::Get => Event::Config(Config {
            users: users.lock().unwrap().clone(),
            ..Config::default()
        }),
        Request::UpgradePasswordHash { user, old, new } => {
            let mut users = users.lock().unwrap();
            match users
                .iter_mut()
                .find(|u| u.name == user && u.password == old)
            {
                Some(u) => {
                    u.password = new;
                    Event::Committed { warnings: vec![] }
                }
                None => Event::Error("stale".into()),
            }
        }
        _ => return None,
    })
}

fn user(name: &str, password: &str) -> User {
    User {
        name: name.to_string(),
        password: nos_password::hash(password),
    }
}

impl Env {
    /// What `nos-cli` does before it has logged in: trust `ca.crt`, present nothing.
    fn anonymous(&self) -> Identity {
        Identity::anonymous_from_pem(&std::fs::read(self.tmp.path().join("ca.crt")).unwrap())
            .unwrap()
    }

    fn daemon(&self, role: Role, name: &str) -> Identity {
        Identity::from_bundle(&self.pki.mint(role, name).unwrap()).unwrap()
    }
}

type Conn = (
    FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<WatchdogEvent>>,
    FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<WatchdogRequest>>,
);

async fn dial(identity: &Identity, path: &Path) -> Conn {
    let stream = identity
        .connect(path, &PeerId::new(Role::Watchdog.as_str(), ""))
        .await
        .unwrap();
    let (r, w) = split(stream);
    (
        FramedRead::new(r, IpcCodec::<WatchdogEvent>::default()),
        FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default()),
    )
}

async fn ask(conn: &mut Conn, request: WatchdogRequest) -> WatchdogEvent {
    conn.1.send(request).await.unwrap();
    conn.0.next().await.unwrap().unwrap()
}

fn login(user: &str, password: &str, csr: Vec<u8>) -> WatchdogRequest {
    WatchdogRequest::Login {
        user: user.to_string(),
        password: password.to_string(),
        csr_der: csr,
    }
}

#[tokio::test]
async fn resolves_config_and_registered_rib_table() {
    let e = env(vec![]).await;
    let mut conn = dial(&e.daemon(Role::Bgpd, "r1"), &e.broker).await;

    let event = ask(
        &mut conn,
        WatchdogRequest::ResolveEndpoint {
            service: ServiceRef::Config,
        },
    )
    .await;
    assert!(matches!(event, WatchdogEvent::Endpoint(p) if p.ends_with("config.sock")));

    let event = ask(
        &mut conn,
        WatchdogRequest::ResolveEndpoint {
            service: ServiceRef::RibTable("rt1".to_string()),
        },
    )
    .await;
    assert!(matches!(event, WatchdogEvent::Endpoint(p) if p == Path::new("/run/nos/rib-rt1.sock")));

    let event = ask(
        &mut conn,
        WatchdogRequest::ResolveEndpoint {
            service: ServiceRef::RibTable("nope".to_string()),
        },
    )
    .await;
    assert!(matches!(event, WatchdogEvent::NotAvailable));
}

#[tokio::test]
async fn an_unauthenticated_peer_can_only_log_in() {
    let e = env(vec![]).await;
    let mut conn = dial(&e.anonymous(), &e.broker).await;
    let event = ask(
        &mut conn,
        WatchdogRequest::ResolveEndpoint {
            service: ServiceRef::Config,
        },
    )
    .await;
    assert!(matches!(event, WatchdogEvent::Denied(_)), "{event:?}");
    // ...and the broker hangs up after that first refusal.
    assert!(conn.0.next().await.is_none_or(|r| r.is_err()));
    let mut conn = dial(&e.anonymous(), &e.broker).await;
    let event = ask(&mut conn, WatchdogRequest::RenewCert { csr_der: vec![] }).await;
    assert!(matches!(event, WatchdogEvent::Denied(_)), "{event:?}");
    assert!(conn.0.next().await.is_none_or(|r| r.is_err()));
}

#[tokio::test]
async fn an_authenticated_wrong_role_peer_stays_connected_after_a_denial() {
    let e = env(vec![]).await;
    let mut conn = dial(&e.daemon(Role::Bgpd, "r1"), &e.broker).await;
    for _ in 0..2 {
        let event = ask(&mut conn, WatchdogRequest::RenewCert { csr_der: vec![] }).await;
        assert!(matches!(event, WatchdogEvent::Denied(_)), "{event:?}");
    }
}

#[tokio::test]
async fn login_issues_a_certificate_for_the_authenticated_user_on_the_callers_key() {
    let e = env(vec![user("alice", "s3cret")]).await;
    let (csr, key) = generate_csr().unwrap();
    let id = e.anonymous();
    let mut conn = dial(&id, &e.broker).await;

    let WatchdogEvent::Issued {
        cert_der,
        lifetime_secs,
    } = ask(&mut conn, login("alice", "s3cret", csr)).await
    else {
        panic!("login refused");
    };
    assert_eq!(lifetime_secs, 120);

    id.set_certificate(cert_der, key).unwrap();
    assert_eq!(id.peer(), Some(PeerId::new("user", "alice")));

    // …and the broker now treats that same identity as authenticated.
    let mut conn = dial(&id, &e.broker).await;
    let event = ask(
        &mut conn,
        WatchdogRequest::ResolveEndpoint {
            service: ServiceRef::Config,
        },
    )
    .await;
    assert!(matches!(event, WatchdogEvent::Endpoint(_)), "{event:?}");
}

#[tokio::test]
async fn wrong_password_and_unknown_user_are_indistinguishable_and_slow() {
    let e = env(vec![user("alice", "s3cret")]).await;
    let mut conn = dial(&e.anonymous(), &e.broker).await;
    let (csr, _) = generate_csr().unwrap();

    let started = Instant::now();
    let wrong = ask(&mut conn, login("alice", "nope", csr.clone())).await;
    let unknown = ask(&mut conn, login("mallory", "s3cret", csr)).await;
    let (WatchdogEvent::Denied(a), WatchdogEvent::Denied(b)) = (wrong, unknown) else {
        panic!("a bad login was accepted");
    };
    assert_eq!(a, b, "the reply must not reveal which usernames exist");
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "each failure should cost a delay"
    );
}

#[tokio::test]
async fn three_failed_logins_drop_the_connection() {
    let e = env(vec![user("alice", "s3cret")]).await;
    let mut conn = dial(&e.anonymous(), &e.broker).await;
    let (csr, _) = generate_csr().unwrap();
    for _ in 0..3 {
        let event = ask(&mut conn, login("alice", "nope", csr.clone())).await;
        assert!(matches!(event, WatchdogEvent::Denied(_)));
    }
    conn.1.send(login("alice", "s3cret", csr)).await.ok();
    assert!(
        conn.0.next().await.is_none_or(|r| r.is_err()),
        "connection should be closed"
    );
}

#[tokio::test]
async fn a_garbage_csr_is_refused_after_a_correct_password() {
    let e = env(vec![user("alice", "s3cret")]).await;
    let mut conn = dial(&e.anonymous(), &e.broker).await;
    let event = ask(&mut conn, login("alice", "s3cret", b"not a csr".to_vec())).await;
    assert!(matches!(event, WatchdogEvent::Denied(_)), "{event:?}");
}

#[tokio::test]
async fn a_user_can_renew_until_they_are_deleted_and_daemons_cannot_renew_at_all() {
    let e = env(vec![user("alice", "s3cret")]).await;
    let id = e.anonymous();
    let (csr, key) = generate_csr().unwrap();
    let WatchdogEvent::Issued { cert_der, .. } = ask(
        &mut dial(&id, &e.broker).await,
        login("alice", "s3cret", csr),
    )
    .await
    else {
        panic!("login refused");
    };
    id.set_certificate(cert_der, key).unwrap();

    let (csr, key) = generate_csr().unwrap();
    let mut conn = dial(&id, &e.broker).await;
    let WatchdogEvent::Issued { cert_der, .. } =
        ask(&mut conn, WatchdogRequest::RenewCert { csr_der: csr }).await
    else {
        panic!("renewal refused");
    };
    id.set_certificate(cert_der, key).unwrap();
    assert_eq!(id.peer(), Some(PeerId::new("user", "alice")));

    let (csr, _) = generate_csr().unwrap();
    let daemon = ask(
        &mut dial(&e.daemon(Role::Bgpd, "r1"), &e.broker).await,
        WatchdogRequest::RenewCert {
            csr_der: csr.clone(),
        },
    )
    .await;
    assert!(matches!(daemon, WatchdogEvent::Denied(_)), "{daemon:?}");

    e.users.lock().unwrap().clear();
    let gone = ask(
        &mut dial(&id, &e.broker).await,
        WatchdogRequest::RenewCert { csr_der: csr },
    )
    .await;
    assert!(matches!(gone, WatchdogEvent::Denied(_)), "{gone:?}");
}

/// `revoke_user` locks out every IPC certificate the user was issued (the
/// broker enforces the CRL at once), and `revoke` a daemon's, while other
/// identities are untouched.
#[tokio::test]
async fn revoked_user_and_daemon_certificates_no_longer_open_the_broker() {
    let e = env(vec![user("alice", "s3cret"), user("bob", "s3cret")]).await;
    let logged_in = |name: &'static str| {
        let e = &e;
        async move {
            let id = e.anonymous();
            let (csr, key) = generate_csr().unwrap();
            let WatchdogEvent::Issued { cert_der, .. } =
                ask(&mut dial(&id, &e.broker).await, login(name, "s3cret", csr)).await
            else {
                panic!("login refused");
            };
            id.set_certificate(cert_der, key).unwrap();
            id
        }
    };
    let (alice1, alice2, bob) = (
        logged_in("alice").await,
        logged_in("alice").await,
        logged_in("bob").await,
    );
    let bundle = e.pki.mint(Role::Bgpd, "r1").unwrap();
    let daemon = Identity::from_bundle(&bundle).unwrap();
    let watchdog = PeerId::new(Role::Watchdog.as_str(), "");
    let opens = |id: &Identity| {
        let (id, path, watchdog) = (id.clone(), e.broker.clone(), watchdog.clone());
        async move {
            match id.connect(&path, &watchdog).await {
                // A TLS 1.3 client learns of a refused certificate on its first read.
                Ok(s) => {
                    let (r, w) = split(s);
                    let mut conn = (
                        FramedRead::new(r, IpcCodec::<WatchdogEvent>::default()),
                        FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default()),
                    );
                    conn.1
                        .send(WatchdogRequest::ResolveEndpoint {
                            service: ServiceRef::Config,
                        })
                        .await
                        .is_ok()
                        && matches!(conn.0.next().await, Some(Ok(WatchdogEvent::Endpoint(_))))
                }
                Err(_) => false,
            }
        }
    };
    assert!(opens(&alice1).await && opens(&alice2).await && opens(&daemon).await);

    e.pki.revoke_user("alice");
    e.pki.revoke(
        Role::Bgpd,
        "r1",
        vec![nos_pki::Serial::of(&bundle.cert).unwrap()],
    );
    assert!(!opens(&alice1).await);
    assert!(!opens(&alice2).await);
    assert!(!opens(&daemon).await);
    assert!(opens(&bob).await, "another user is untouched");
    assert!(
        opens(&e.daemon(Role::Bgpd, "r1")).await,
        "a fresh leaf is fine"
    );
}

fn rest_login(user: &str, password: &str, csr: Vec<u8>) -> WatchdogRequest {
    WatchdogRequest::RestLogin {
        user: user.to_string(),
        password: password.to_string(),
        csr_der: csr,
    }
}

#[tokio::test]
async fn only_restd_may_use_the_rest_requests() {
    let e = env(vec![user("alice", "s3cret")]).await;
    let (csr, _) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
    let requests = || {
        [
            rest_login("alice", "s3cret", csr.clone()),
            WatchdogRequest::RestRenew {
                user: "alice".into(),
                serial: "00".into(),
                csr_der: csr.clone(),
            },
            WatchdogRequest::RestCertCheck {
                user: "alice".into(),
                serial: "00".into(),
            },
            WatchdogRequest::IssueRestServerCert {
                addresses: vec!["127.0.0.1".parse().unwrap()],
                csr_der: csr.clone(),
            },
        ]
    };
    for role in [Role::Bgpd, Role::User, Role::Configd] {
        let mut conn = dial(&e.daemon(role, "x"), &e.broker).await;
        for request in requests() {
            let event = ask(&mut conn, request).await;
            assert!(
                matches!(event, WatchdogEvent::Denied(_)),
                "{role:?}: {event:?}"
            );
        }
    }
    for request in requests() {
        // The broker hangs up on an anonymous peer after a refusal.
        let mut conn = dial(&e.anonymous(), &e.broker).await;
        let event = ask(&mut conn, request).await;
        assert!(matches!(event, WatchdogEvent::Denied(_)), "{event:?}");
    }
    let mut conn = dial(&e.daemon(Role::Restd, "rt1"), &e.broker).await;
    for request in requests() {
        // Allowed for restd; the made-up serial is just not a live certificate.
        let unknown_serial = matches!(
            request,
            WatchdogRequest::RestRenew { .. } | WatchdogRequest::RestCertCheck { .. }
        );
        let event = ask(&mut conn, request).await;
        match event {
            WatchdogEvent::Denied(m) => assert!(unknown_serial && m == "session expired"),
            _ => assert!(!unknown_serial || matches!(event, WatchdogEvent::Ok)),
        }
    }
}

#[tokio::test]
async fn restd_gets_rest_certificates_that_do_not_open_ipc_sockets() {
    let e = env(vec![user("alice", "s3cret")]).await;
    let mut conn = dial(&e.daemon(Role::Restd, "rt1"), &e.broker).await;

    let (csr, key) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
    let WatchdogEvent::Issued { cert_der, .. } =
        ask(&mut conn, rest_login("alice", "s3cret", csr)).await
    else {
        panic!("rest login refused");
    };

    // The REST CA is published beside the IPC one, and is a different root.
    let rest_ca = std::fs::read_to_string(e.tmp.path().join("rest-ca.crt")).unwrap();
    assert_ne!(
        rest_ca,
        std::fs::read_to_string(e.tmp.path().join("ca.crt")).unwrap()
    );
    nos_pki::rest::client_config(rest_ca.as_bytes(), Some((&cert_der, &key))).unwrap();

    // Presenting it to the IPC broker fails: wrong CA and wrong algorithm.
    let id = e.anonymous();
    id.set_certificate(cert_der, key).unwrap();
    let stream = id
        .connect(&e.broker, &PeerId::new(Role::Watchdog.as_str(), ""))
        .await;
    if let Ok(stream) = stream {
        let (r, w) = split(stream);
        let mut conn: Conn = (
            FramedRead::new(r, IpcCodec::<WatchdogEvent>::default()),
            FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default()),
        );
        conn.1
            .send(WatchdogRequest::ResolveEndpoint {
                service: ServiceRef::Config,
            })
            .await
            .ok();
        assert!(
            !matches!(conn.0.next().await, Some(Ok(WatchdogEvent::Endpoint(_)))),
            "a REST certificate must not authenticate on the IPC broker"
        );
    }
}

#[tokio::test]
async fn rest_login_failures_are_not_throttled_by_the_broker_connection() {
    let e = env(vec![user("alice", "s3cret")]).await;
    let mut conn = dial(&e.daemon(Role::Restd, "rt1"), &e.broker).await;
    let (csr, _) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
    let started = Instant::now();
    for _ in 0..4 {
        let event = ask(&mut conn, rest_login("alice", "nope", csr.clone())).await;
        assert!(matches!(event, WatchdogEvent::Denied(_)));
    }
    // …so the shared connection survives, and a correct login still works.
    let event = ask(&mut conn, rest_login("alice", "s3cret", csr)).await;
    assert!(matches!(event, WatchdogEvent::Issued { .. }), "{event:?}");
    assert!(started.elapsed() < Duration::from_secs(4));
}

/// A REST login as `user` (password `s3cret`), returning the certificate's serial.
async fn rest_serial(conn: &mut Conn, user: &str) -> String {
    let (csr, _) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
    let WatchdogEvent::Issued { cert_der, .. } = ask(conn, rest_login(user, "s3cret", csr)).await
    else {
        panic!("rest login refused");
    };
    nos_pki::Serial::of(&cert_der).unwrap().to_string()
}

fn check(user: &str, serial: &str) -> WatchdogRequest {
    WatchdogRequest::RestCertCheck {
        user: user.into(),
        serial: serial.into(),
    }
}

/// A revoked user's REST certificates fail the per-request check and cannot
/// renew; other users and fresh logins are untouched.
#[tokio::test]
async fn revoking_a_user_kills_their_rest_certificates() {
    let e = env(vec![user("alice", "s3cret"), user("bob", "s3cret")]).await;
    let mut conn = dial(&e.daemon(Role::Restd, "rt1"), &e.broker).await;
    let (csr, _) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
    let (a, b) = (
        rest_serial(&mut conn, "alice").await,
        rest_serial(&mut conn, "bob").await,
    );
    assert!(matches!(
        ask(&mut conn, check("alice", &a)).await,
        WatchdogEvent::Ok
    ));
    // A certificate is only good for the user it names.
    assert!(matches!(
        ask(&mut conn, check("bob", &a)).await,
        WatchdogEvent::Denied(_)
    ));

    e.pki.revoke_user("alice");
    assert!(matches!(
        ask(&mut conn, check("alice", &a)).await,
        WatchdogEvent::Denied(_)
    ));
    let renew = WatchdogRequest::RestRenew {
        user: "alice".into(),
        serial: a,
        csr_der: csr,
    };
    assert!(matches!(
        ask(&mut conn, renew).await,
        WatchdogEvent::Denied(_)
    ));
    assert!(matches!(
        ask(&mut conn, check("bob", &b)).await,
        WatchdogEvent::Ok
    ));
    let fresh = rest_serial(&mut conn, "alice").await;
    assert!(matches!(
        ask(&mut conn, check("alice", &fresh)).await,
        WatchdogEvent::Ok
    ));
}

/// Renewals inherit the login time, so they stop at the session cap.
#[tokio::test]
async fn rest_renewals_stop_at_the_session_cap() {
    let e = env(vec![user("alice", "s3cret")]).await;
    let mut conn = dial(&e.daemon(Role::Restd, "rt1"), &e.broker).await;
    let (csr, _) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
    e.pki.set_rest_session_max(Duration::from_secs(3));

    let first = rest_serial(&mut conn, "alice").await;
    let renew = |serial: &str| WatchdogRequest::RestRenew {
        user: "alice".into(),
        serial: serial.into(),
        csr_der: csr.clone(),
    };
    let WatchdogEvent::Issued { cert_der, .. } = ask(&mut conn, renew(&first)).await else {
        panic!("renewal inside the cap refused");
    };
    let second = nos_pki::Serial::of(&cert_der).unwrap().to_string();

    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(matches!(
        ask(&mut conn, check("alice", &second)).await,
        WatchdogEvent::Denied(_)
    ));
    assert!(matches!(
        ask(&mut conn, renew(&second)).await,
        WatchdogEvent::Denied(_)
    ));
    // Logging in with the password starts a new session.
    let third = rest_serial(&mut conn, "alice").await;
    assert!(matches!(
        ask(&mut conn, check("alice", &third)).await,
        WatchdogEvent::Ok
    ));
}

#[tokio::test]
async fn rest_renewal_is_refused_for_a_deleted_user_and_server_certs_carry_the_rest_ca() {
    let e = env(vec![user("alice", "s3cret")]).await;
    let mut conn = dial(&e.daemon(Role::Restd, "rt1"), &e.broker).await;
    let (csr, _) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();

    let serial = rest_serial(&mut conn, "alice").await;
    let renew = |user: &str| WatchdogRequest::RestRenew {
        user: user.into(),
        serial: serial.clone(),
        csr_der: csr.clone(),
    };
    assert!(matches!(
        ask(&mut conn, renew("alice")).await,
        WatchdogEvent::Issued { .. }
    ));
    e.users.lock().unwrap().clear();
    assert!(matches!(
        ask(&mut conn, renew("alice")).await,
        WatchdogEvent::Denied(_)
    ));

    let WatchdogEvent::RestServerCert { ca_der, .. } = ask(
        &mut conn,
        WatchdogRequest::IssueRestServerCert {
            addresses: vec!["10.0.0.1".parse().unwrap()],
            csr_der: csr,
        },
    )
    .await
    else {
        panic!("server certificate refused");
    };
    assert_ne!(ca_der, [] as [u8; 0]);
}

#[tokio::test]
async fn a_weak_hash_is_upgraded_on_login_once() {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let weak = argon2::Argon2::default()
        .hash_password(b"s3cret", &SaltString::generate(&mut OsRng))
        .unwrap()
        .to_string();
    let e = env(vec![User {
        name: "alice".into(),
        password: weak.clone(),
    }])
    .await;
    let mut conn = dial(&e.anonymous(), &e.broker).await;
    let (csr, _) = generate_csr().unwrap();

    let event = ask(&mut conn, login("alice", "nope", csr.clone())).await;
    assert!(matches!(event, WatchdogEvent::Denied(_)));
    assert_eq!(
        e.users.lock().unwrap()[0].password,
        weak,
        "wrong password must not upgrade"
    );

    let event = ask(&mut conn, login("alice", "s3cret", csr.clone())).await;
    assert!(matches!(event, WatchdogEvent::Issued { .. }));
    let upgraded = e.users.lock().unwrap()[0].password.clone();
    assert!(upgraded.contains("m=65536,t=3,p=4"), "{upgraded}");
    assert!(nos_password::verify("s3cret", &upgraded));

    let event = ask(&mut conn, login("alice", "s3cret", csr)).await;
    assert!(matches!(event, WatchdogEvent::Issued { .. }));
    assert_eq!(
        e.users.lock().unwrap()[0].password,
        upgraded,
        "no second upgrade"
    );
}
