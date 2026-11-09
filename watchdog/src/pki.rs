//! The watchdog as certificate authority: one ephemeral CA per watchdog run,
//! a fresh leaf identity for every child it spawns (`supervisor`), the
//! public trust anchor published as `ca.crt`, and user certificates issued
//! at login (`broker`).
//!
//! There are two CAs, because the two transports have different audiences: the
//! IPC CA (ML-DSA-65, quantum-safe authentication) for daemons and `nos`, and
//! the REST CA (ECDSA P-256, so browsers and stock clients can present a
//! certificate) for `nos-restd`'s TCP listener and its clients. A REST
//! certificate never opens an IPC socket, and vice versa.
//!
//! The CA keys exist only in this process's memory. A watchdog restart
//! re-keys everything, which costs nothing: every child is restarted with it.
//! That is also why there is no CA roll: a child cannot outlive its watchdog
//! (the watchdog is PID 1, and the child's identity pipe goes to it alone).
//!
//! Revocation: the REST CA has no CRL; instead `rest_sessions` is an allowlist
//! of live REST certificates that `nos-restd` consults on every request
//! (`rest_session`), emptied of a user's entries by the same triggers as the
//! IPC CRL, and capping how long renewals can extend one login.
//!
//! The IPC CA keeps a CRL (RFC 5280 §5). A child's certificates
//! are revoked when it exits, a user's when it is deleted or its password
//! changes; every revocation re-signs the CRL, which `supervisor` pushes down
//! every child's stdin and `revoke` applies to the watchdog's own identity.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures::StreamExt;
use nos_pki::{Bundle, Ca, Identity, KeyAlg, PeerId, Serial};
use nos_proto::{DiffScope, DiffStatus, Event, Role, SectionDiff};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::supervisor::wait_or_shutdown;
use crate::tickets::Tickets;
use crate::users_client;

pub struct Pki {
    ca: Ca,
    rest_ca: Ca,
    /// The watchdog's own identity, for its config subscriptions, log
    /// forwarding and the broker socket. Rotated by `spawn_self_rotation`.
    pub identity: Identity,
    /// How long a daemon's certificate is valid…
    pub leaf_lifetime: Duration,
    /// …and how often a fresh one is pushed down its stdin.
    pub rotate_every: Duration,
    /// How long a logged-in user's certificate is valid.
    pub user_lifetime: Duration,
    /// The IPC CA's current CRL (DER), for every child's identity pusher.
    crl: watch::Sender<Vec<u8>>,
    /// Every IPC certificate issued to each user, so they can be revoked.
    users: Mutex<HashMap<String, Vec<Serial>>>,
    /// Every live REST certificate (hex serial) and the login it belongs to.
    rest_sessions: Mutex<HashMap<String, RestSession>>,
    /// Seconds a REST login may be extended by renewals (`set_rest_session_max`).
    rest_session_max: AtomicU64,
    /// Hashes the broker itself re-hashed at login (user → new hash): that
    /// `Modified` user diff is not a password change and revokes nothing.
    rehashed: Mutex<HashMap<String, String>>,
    /// Outstanding login tickets (#990); `revoke_user` drops a user's.
    pub tickets: Tickets,
}

/// One REST certificate: whose, when the password login behind it happened
/// (renewals inherit it), and its expiry for pruning.
struct RestSession {
    user: String,
    started: Instant,
    cert: Serial,
}

/// Default for `--pki-rest-session-max`: 7 days.
pub const REST_SESSION_MAX: Duration = Duration::from_hours(168);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Pki {
    /// Creates both CAs, writes their public certificates to `<dir>/ca.crt`
    /// and `<dir>/rest-ca.crt` (world-readable: they only let a client
    /// recognise the watchdog), and issues the watchdog's own identity.
    pub fn start(
        dir: &Path,
        leaf_lifetime: Duration,
        rotate_every: Duration,
        user_lifetime: Duration,
    ) -> io::Result<Arc<Self>> {
        if rotate_every >= leaf_lifetime {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--pki-rotate-every must be shorter than --pki-leaf-lifetime, or certificates expire before their replacement arrives",
            ));
        }
        let ca = Ca::new(KeyAlg::MlDsa65)?;
        let rest_ca = Ca::new(KeyAlg::EcdsaP256)?;
        std::fs::create_dir_all(dir)?;
        // Public certs and the CRL only: any uid may read them (`nos` clients).
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        publish(dir, "ca.crt", &ca.cert_pem())?;
        publish(dir, "rest-ca.crt", &rest_ca.cert_pem())?;

        let mut own = ca.issue(&peer(Role::Watchdog, ""), leaf_lifetime)?;
        own.crl = ca.crl_der()?;
        let identity = Identity::from_bundle(&own)?;
        Ok(Arc::new(Self {
            crl: watch::Sender::new(own.crl),
            ca,
            rest_ca,
            identity,
            leaf_lifetime,
            rotate_every,
            user_lifetime,
            users: Mutex::default(),
            rest_sessions: Mutex::default(),
            rest_session_max: AtomicU64::new(REST_SESSION_MAX.as_secs()),
            rehashed: Mutex::default(),
            tickets: Tickets::default(),
        }))
    }

    /// A fresh keypair and leaf for a daemon about to be (re)started, or due
    /// its next rotation.
    pub fn mint(&self, role: Role, name: &str) -> io::Result<Bundle> {
        self.ca.issue(&peer(role, name), self.leaf_lifetime)
    }

    /// Certifies the public key in a client's CSR as `user`. Returns the leaf
    /// certificate DER; the client keeps its private key.
    pub fn sign_user(&self, csr_der: &[u8], user: &str) -> io::Result<Vec<u8>> {
        let cert = self
            .ca
            .sign_csr(csr_der, &peer(Role::User, user), self.user_lifetime)?;
        let mut users = lock(&self.users);
        let issued = users.entry(user.to_string()).or_default();
        issued.retain(|s| !s.expired());
        issued.push(Serial::of(&cert)?);
        Ok(cert)
    }

    /// The current IPC CRL, and every change to it from now on.
    pub fn crl(&self) -> watch::Receiver<Vec<u8>> {
        self.crl.subscribe()
    }

    /// Revokes `serials` (certificates issued to `role`/`name`): re-signs the
    /// CRL, enforces it on the watchdog's own identity at once, and publishes
    /// it for every child's pusher. Already-expired certificates are skipped.
    pub fn revoke(&self, role: Role, name: &str, mut serials: Vec<Serial>) {
        serials.retain(|s| !s.expired());
        if serials.is_empty() {
            return;
        }
        let crl = match self.ca.revoke(&serials) {
            Ok(crl) => crl,
            Err(e) => {
                warn!(role = %role.as_str(), name = %name, error = %e, "failed to sign the crl");
                return;
            }
        };
        if let Err(e) = self.identity.set_crl(&crl) {
            warn!(error = %e, "failed to apply the crl to the watchdog's own identity");
        }
        self.crl.send_replace(crl);
        info!(role = %role.as_str(), name = %name, serials = serials.len(), "certificates revoked");
    }

    /// Revokes every IPC certificate issued to `user` so far, and forgets its
    /// REST ones (which `nos-restd` then refuses).
    pub fn revoke_user(&self, user: &str) {
        lock(&self.rest_sessions).retain(|_, s| s.user != user);
        self.tickets.forget_user(user);
        let serials = lock(&self.users).remove(user).unwrap_or_default();
        self.revoke(Role::User, user, serials);
    }

    /// Records that the broker is about to store `hash` for `user` itself (a
    /// re-hash at login, same password): the resulting diff revokes nothing.
    pub fn note_rehash(&self, user: &str, hash: &str) {
        lock(&self.rehashed).insert(user.to_string(), hash.to_string());
    }

    /// Whether `user` now holds exactly the hash the broker re-hashed to —
    /// consuming the note either way.
    fn was_rehash(&self, user: &str, current: Option<&str>) -> bool {
        lock(&self.rehashed)
            .remove(user)
            .is_some_and(|h| Some(h.as_str()) == current)
    }

    /// Follows the `Users` section of the running config and revokes a user's
    /// IPC and REST certificates when the user is removed or its password
    /// changes. Reconnects on a fixed 1s delay, like every config subscriber.
    pub async fn follow_users(
        self: Arc<Self>,
        config_socket: PathBuf,
        mut shutdown: watch::Receiver<bool>,
    ) {
        while !*shutdown.borrow() {
            match users_client::subscribe_diff(
                &self.identity,
                &config_socket,
                vec![DiffScope::Users],
            )
            .await
            {
                Ok(mut reader) => {
                    let mut first = true;
                    loop {
                        let event = tokio::select! {
                            e = reader.next() => e,
                            _ = shutdown.changed() => return,
                        };
                        let Some(Ok(event)) = event else { break };
                        if let Event::Diff(diff) = event {
                            self.users_changed(&config_socket, &diff.users, first).await;
                            first = false;
                        }
                    }
                    warn!("users diff stream closed, reconnecting");
                }
                Err(e) => warn!(error = %e, "failed to subscribe to users"),
            }
            if wait_or_shutdown(Duration::from_secs(1), &mut shutdown).await {
                return;
            }
        }
    }

    /// One users diff. The `initial` one on a connection is all-`Added`, the
    /// full user list: anyone we issued to who is missing from it was removed
    /// while we were away.
    async fn users_changed(&self, config_socket: &Path, users: &[SectionDiff], initial: bool) {
        if initial {
            let mut gone: Vec<String> = lock(&self.users).keys().cloned().collect();
            gone.extend(lock(&self.rest_sessions).values().map(|s| s.user.clone()));
            gone.retain(|u| !users.iter().any(|s| &s.name == u));
            gone.dedup();
            for u in &gone {
                self.revoke_user(u);
            }
            return;
        }
        for s in users {
            match s.status {
                DiffStatus::Added => {}
                DiffStatus::Removed => self.revoke_user(&s.name),
                DiffStatus::Modified => self.password_changed(config_socket, &s.name).await,
            }
        }
    }

    /// A `Modified` user is a new password hash: revoke, unless the broker
    /// re-hashed the same password itself.
    async fn password_changed(&self, config_socket: &Path, user: &str) {
        let noted = lock(&self.rehashed).contains_key(user);
        if noted {
            let current = users_client::fetch_users(&self.identity, config_socket)
                .await
                .ok()
                .and_then(|us| us.into_iter().find(|u| u.name == user))
                .map(|u| u.password);
            if self.was_rehash(user, current.as_deref()) {
                return;
            }
        }
        self.revoke_user(user);
    }

    /// `sign_user`, from the REST CA: the certificate a REST client presents
    /// to `nos-restd` (a different trust domain from IPC). `started` is when
    /// the password login behind it happened; the serial is allowlisted.
    pub fn sign_rest_user(
        &self,
        csr_der: &[u8],
        user: &str,
        started: Instant,
    ) -> io::Result<Vec<u8>> {
        let cert = self
            .rest_ca
            .sign_csr(csr_der, &peer(Role::User, user), self.user_lifetime)?;
        let serial = Serial::of(&cert)?;
        let mut sessions = lock(&self.rest_sessions);
        sessions.retain(|_, s| !s.cert.expired());
        sessions.insert(
            serial.to_string(),
            RestSession {
                user: user.to_string(),
                started,
                cert: serial,
            },
        );
        Ok(cert)
    }

    /// Caps how long renewals may extend one password login.
    pub fn set_rest_session_max(&self, max: Duration) {
        self.rest_session_max
            .store(max.as_secs(), Ordering::Relaxed);
    }

    /// The login time behind the REST certificate `serial` of `user`, if it is
    /// still live: allowlisted, unexpired and within the session cap.
    pub fn rest_session(&self, serial: &str, user: &str) -> Option<Instant> {
        let max = Duration::from_secs(self.rest_session_max.load(Ordering::Relaxed));
        lock(&self.rest_sessions)
            .get(serial)
            .filter(|s| s.user == user && !s.cert.expired() && s.started.elapsed() < max)
            .map(|s| s.started)
    }

    /// The listener certificate for `nos-restd`, and the REST CA's own
    /// certificate — the trust anchor it verifies client certificates against.
    pub fn sign_rest_server(
        &self,
        csr_der: &[u8],
        addresses: &[IpAddr],
    ) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let cert = self
            .rest_ca
            .sign_server_csr(csr_der, addresses, self.leaf_lifetime)?;
        Ok((cert, self.rest_ca.cert_der().to_vec()))
    }

    /// Keeps the watchdog's own identity from expiring, the way
    /// `supervisor` does for each child.
    pub fn spawn_self_rotation(
        self: &Arc<Self>,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        let pki = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(pki.rotate_every) => {}
                    _ = shutdown.changed() => return,
                }
                match pki
                    .mint(Role::Watchdog, "")
                    .and_then(|b| pki.identity.update(&b))
                {
                    Ok(()) => info!(peer = ?pki.identity.peer(), "ipc identity rotated"),
                    Err(e) => warn!(error = %e, "failed to rotate the watchdog's own identity"),
                }
            }
        })
    }
}

/// Write-then-rename so a client never reads half a certificate.
fn publish(dir: &Path, name: &str, pem: &str) -> io::Result<()> {
    let (tmp, dest) = (dir.join(format!(".{name}.tmp")), dir.join(name));
    std::fs::write(&tmp, pem)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&tmp, &dest)
}

fn peer(role: Role, name: &str) -> PeerId {
    PeerId::new(role.as_str(), name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_pki::{generate_csr, generate_csr_for};
    use x509_parser::prelude::*;

    fn pki() -> (tempfile::TempDir, Arc<Pki>) {
        let tmp = tempfile::tempdir().unwrap();
        let pki = Pki::start(
            tmp.path(),
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_secs(60),
        )
        .unwrap();
        (tmp, pki)
    }

    fn issue(pki: &Pki, user: &str) {
        pki.sign_user(&generate_csr().unwrap().0, user).unwrap();
    }

    fn diff(name: &str, status: DiffStatus) -> SectionDiff {
        SectionDiff {
            header: format!("user {name}"),
            name: name.to_string(),
            status,
            fields: vec![],
            subsections: vec![],
        }
    }

    fn issued(pki: &Pki, user: &str) -> bool {
        lock(&pki.users).contains_key(user)
    }

    #[tokio::test]
    async fn initial_diff_revokes_only_users_missing_from_the_list() {
        let (_tmp, pki) = pki();
        issue(&pki, "alice");
        issue(&pki, "bob");
        let crl = pki.crl();
        let none = Path::new("/nonexistent");

        // Everyone listed: nobody revoked, CRL untouched.
        let all = [
            diff("alice", DiffStatus::Added),
            diff("bob", DiffStatus::Added),
        ];
        pki.users_changed(none, &all, true).await;
        assert!(issued(&pki, "alice") && issued(&pki, "bob"));
        assert!(!crl.has_changed().unwrap());

        // alice missing: she is revoked, bob kept.
        pki.users_changed(none, &all[1..], true).await;
        assert!(!issued(&pki, "alice"));
        assert!(issued(&pki, "bob"));
        assert!(crl.has_changed().unwrap());
    }

    #[tokio::test]
    async fn non_initial_diff_revokes_removed_users_only() {
        let (_tmp, pki) = pki();
        issue(&pki, "alice");
        issue(&pki, "bob");
        let crl = pki.crl();
        let none = Path::new("/nonexistent");

        // A non-initial diff must not apply the "missing from the list" rule.
        pki.users_changed(none, &[diff("bob", DiffStatus::Added)], false)
            .await;
        assert!(issued(&pki, "alice") && issued(&pki, "bob"));
        assert!(!crl.has_changed().unwrap());

        pki.users_changed(none, &[diff("alice", DiffStatus::Removed)], false)
            .await;
        assert!(!issued(&pki, "alice"));
        assert!(issued(&pki, "bob"));
        assert!(crl.has_changed().unwrap());
    }

    #[test]
    fn rest_sessions_follow_revocation_and_the_cap() {
        let (_tmp, pki) = pki();
        let sign = |user: &str| {
            let (csr, _) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
            let cert = pki.sign_rest_user(&csr, user, Instant::now()).unwrap();
            Serial::of(&cert).unwrap().to_string()
        };
        let (a, b) = (sign("alice"), sign("bob"));
        assert!(pki.rest_session(&a, "alice").is_some());
        assert!(pki.rest_session(&a, "bob").is_none(), "wrong user");
        assert!(
            pki.rest_session("nope", "alice").is_none(),
            "unknown serial"
        );

        pki.revoke_user("alice");
        assert!(pki.rest_session(&a, "alice").is_none());
        assert!(pki.rest_session(&b, "bob").is_some());

        pki.set_rest_session_max(Duration::ZERO);
        assert!(pki.rest_session(&b, "bob").is_none(), "past the cap");
    }

    #[tokio::test]
    async fn initial_diff_also_drops_rest_only_users_that_vanished() {
        let (_tmp, pki) = pki();
        let (csr, _) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
        let cert = pki.sign_rest_user(&csr, "alice", Instant::now()).unwrap();
        let serial = Serial::of(&cert).unwrap().to_string();
        let none = Path::new("/nonexistent");
        pki.users_changed(none, &[diff("alice", DiffStatus::Added)], true)
            .await;
        assert!(pki.rest_session(&serial, "alice").is_some());
        pki.users_changed(none, &[], true).await;
        assert!(pki.rest_session(&serial, "alice").is_none());
    }

    #[test]
    fn a_noted_rehash_is_recognised_once() {
        let (_tmp, pki) = pki();
        assert!(!pki.was_rehash("u", Some("h")));
        pki.note_rehash("u", "h");
        assert!(pki.was_rehash("u", Some("h")));
        assert!(!pki.was_rehash("u", Some("h")), "consumed");
        pki.note_rehash("u", "h");
        assert!(!pki.was_rehash("u", Some("other")));
        pki.note_rehash("u", "h");
        assert!(!pki.was_rehash("u", None));
    }

    #[test]
    fn rest_server_cert_has_the_addresses_and_chains_to_the_rest_ca() {
        let (tmp, pki) = pki();
        let (csr, _key) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
        let addrs: [IpAddr; 2] = ["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()];
        let (cert_der, ca_der) = pki.sign_rest_server(&csr, &addrs).unwrap();

        let pem = std::fs::read(tmp.path().join("rest-ca.crt")).unwrap();
        let (_, on_disk) = x509_parser::pem::parse_x509_pem(&pem).unwrap();
        assert_eq!(ca_der, on_disk.contents);

        let (_, cert) = parse_x509_certificate(&cert_der).unwrap();
        let (_, ca) = parse_x509_certificate(&ca_der).unwrap();
        cert.verify_signature(Some(ca.public_key())).unwrap();
        let san = cert.subject_alternative_name().unwrap().unwrap();
        let names = &san.value.general_names;
        let mut v6 = [0u8; 16];
        v6[15] = 1;
        assert!(names.contains(&GeneralName::DNSName("nos.internal")));
        assert!(names.contains(&GeneralName::IPAddress(&[127, 0, 0, 1])));
        assert!(names.contains(&GeneralName::IPAddress(&v6)));

        assert!(pki.sign_rest_server(b"garbage", &addrs).is_err());
    }
}
