use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use serde::{Deserialize, Serialize};

/// Identifies one addressable IPC service that a client might want to reach.
/// Resolved by `nos-watchdogd`'s broker (`Request::ResolveEndpoint` in
/// `WatchdogRequest`) rather than assumed from a hardcoded default, since the
/// watchdog is the one process that actually spawns every other daemon and
/// knows where it currently lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceRef {
    /// `nos-configd`'s own IPC socket. The watchdog always knows this — it's
    /// passed to the watchdog itself via its own `--config-socket` arg.
    Config,
    /// The `nos-ribd` instance currently serving one routing table, named by
    /// the table's config key.
    RibTable(String),
    /// The single `nos-interfaced` instance, which manages every configured
    /// interface in one process (unlike `RibTable`, there is no per-name
    /// variant — see `docs/architecture/endpoint-broker.md`).
    Interfaces,
    /// The single `nos-logd` instance, resolved directly like `Config`/
    /// `Interfaces` rather than through the registry — there is exactly one
    /// log collector regardless of how many other daemons are running.
    Log,
    /// The `nos-bgpd` instance currently serving one BGP instance, named by
    /// the instance's config key — resolved through the registry the same
    /// way as `RibTable`, since there can be many.
    BgpInstance(String),
    /// The `nos-ospfd` instance currently serving one OSPF instance, named by
    /// the instance's config key — resolved through the registry the same
    /// way as `RibTable`/`BgpInstance`.
    OspfInstance(String),
    /// The `nos-ospfv3d` instance currently serving one `OSPFv3` instance,
    /// named by the instance's config key — resolved through the registry
    /// the same way as `OspfInstance`, a separate variant since v2/v3 are
    /// two independent daemon families.
    Ospfv3Instance(String),
    /// The single `nos-lacpd` instance, resolved directly like `Interfaces`/
    /// `Log` rather than through the registry — there is exactly one LACP
    /// engine regardless of how many `Lacp`-mode `PortAggregate`s exist.
    Lacp,
    /// The single `nos-lldpd` instance, resolved directly like `Lacp` — one
    /// LLDP engine handles every LLDP-enabled interface.
    Lldp,
    /// The `nos-fdbd` instance serving one EVPN `BroadcastDomain`, named by
    /// the domain's config key — through the registry, like `RibTable`.
    FdbDomain(String),
    /// The single `nos-bfdd` instance, resolved directly like `Lldp`.
    Bfd,
    /// The single `nos-stpd` instance, resolved directly like `Bfd`.
    Stp,
    /// The single `nos-acld` instance, resolved directly like `Stp`.
    Acl,
}

impl ServiceRef {
    /// The role the daemon behind this service authenticates as — what a
    /// client must see in its certificate before it sends anything.
    pub fn role(&self) -> Role {
        match self {
            ServiceRef::Config => Role::Configd,
            ServiceRef::RibTable(_) => Role::Ribd,
            ServiceRef::Interfaces => Role::Interfaced,
            ServiceRef::Log => Role::Logd,
            ServiceRef::BgpInstance(_) => Role::Bgpd,
            ServiceRef::OspfInstance(_) => Role::Ospfd,
            ServiceRef::Ospfv3Instance(_) => Role::Ospfv3d,
            ServiceRef::Lacp => Role::Lacpd,
            ServiceRef::Lldp => Role::Lldpd,
            ServiceRef::FdbDomain(_) => Role::Fdbd,
            ServiceRef::Bfd => Role::Bfdd,
            ServiceRef::Stp => Role::Stpd,
            ServiceRef::Acl => Role::Acld,
        }
    }

    /// The instance name in that daemon's certificate: the table/instance key,
    /// or `""` for the singleton daemons.
    pub fn instance(&self) -> &str {
        match self {
            ServiceRef::RibTable(n)
            | ServiceRef::BgpInstance(n)
            | ServiceRef::OspfInstance(n)
            | ServiceRef::Ospfv3Instance(n)
            | ServiceRef::FdbDomain(n) => n,
            ServiceRef::Config
            | ServiceRef::Interfaces
            | ServiceRef::Log
            | ServiceRef::Lacp
            | ServiceRef::Lldp
            | ServiceRef::Bfd
            | ServiceRef::Stp
            | ServiceRef::Acl => "",
        }
    }
}

impl AsRef<str> for Role {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// What kind of process an authenticated IPC peer is, as asserted by the
/// `nos://<role>/<name>` URI SAN in its certificate (`nos-pki`). Servers
/// allow-list by role; clients check the role of whoever they dialed. Never
/// on the wire — it lives in the certificate — so no serde derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// `nos-watchdogd`.
    Watchdog,
    /// `nos-configd`.
    Configd,
    /// `nos-logd`.
    Logd,
    /// `nos-bgpd`.
    Bgpd,
    /// `nos-ribd`.
    Ribd,
    /// `nos-ospfd`.
    Ospfd,
    /// `nos-ospfv3d`.
    Ospfv3d,
    /// `nos-interfaced`.
    Interfaced,
    /// `nos-lacpd`.
    Lacpd,
    /// `nos-lldpd`.
    Lldpd,
    /// `nos-fdbd`.
    Fdbd,
    /// `nos-restd`.
    Restd,
    /// `nos-bfdd`.
    Bfdd,
    /// `nos-stpd`.
    Stpd,
    /// `nos-acld`.
    Acld,
    /// A person, authenticated by login; the certificate's name is the username.
    User,
}

impl Role {
    /// Every role, in declaration order.
    pub const ALL: [Role; 16] = [
        Role::Watchdog,
        Role::Configd,
        Role::Logd,
        Role::Bgpd,
        Role::Ribd,
        Role::Ospfd,
        Role::Ospfv3d,
        Role::Interfaced,
        Role::Lacpd,
        Role::Lldpd,
        Role::Fdbd,
        Role::Restd,
        Role::Bfdd,
        Role::Stpd,
        Role::Acld,
        Role::User,
    ];

    /// The role's name as used in `nos://<role>/<name>` identities.
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Watchdog => "watchdog",
            Role::Configd => "configd",
            Role::Logd => "logd",
            Role::Bgpd => "bgpd",
            Role::Ribd => "ribd",
            Role::Ospfd => "ospfd",
            Role::Ospfv3d => "ospfv3d",
            Role::Interfaced => "interfaced",
            Role::Lacpd => "lacpd",
            Role::Lldpd => "lldpd",
            Role::Fdbd => "fdbd",
            Role::Restd => "restd",
            Role::Bfdd => "bfdd",
            Role::Stpd => "stpd",
            Role::Acld => "acld",
            Role::User => "user",
        }
    }

    /// Parses a role name; the inverse of `as_str`.
    pub fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// Every role except `User` — the daemons `nos-watchdogd` itself spawns.
    pub fn is_daemon(self) -> bool {
        self != Role::User
    }
}

/// The one `WatchdogEvent::Denied` message for a failed login, identical for an
/// unknown user and a wrong password so it reveals nothing about which exist.
pub const INVALID_CREDENTIALS: &str = "invalid credentials";

/// `Denied` text when the watchdog has too many password checks in flight to
/// start another (#381). Not `INVALID_CREDENTIALS`: it is not a failed guess.
pub const LOGIN_BUSY: &str = "login busy";

/// The `Denied` message for a REST certificate that was revoked or whose
/// session hit its renewal cap: `nos-restd` answers 401.
pub const SESSION_EXPIRED: &str = "session expired";

/// `Denied` text for a login ticket that is unknown, expired, already used or
/// whose user is gone: one opaque message, so `nos` falls back to the prompt.
pub const INVALID_TICKET: &str = "invalid ticket";

/// Environment variable carrying a login ticket (`ticket_to_env`) from PAM to `nos`.
pub const LOGIN_TICKET_ENV: &str = "NOS_LOGIN_TICKET";

/// Length of a login ticket in bytes.
pub const LOGIN_TICKET_LEN: usize = 32;

/// How long an unredeemed login ticket stays valid.
pub const LOGIN_TICKET_TTL: Duration = Duration::from_secs(60);

/// Encodes a ticket for `LOGIN_TICKET_ENV`: unpadded URL-safe base64.
pub fn ticket_to_env(ticket: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(ticket)
}

/// Decodes `ticket_to_env`; `None` unless it is exactly `LOGIN_TICKET_LEN` bytes.
pub fn ticket_from_env(s: &str) -> Option<Vec<u8>> {
    let b = URL_SAFE_NO_PAD.decode(s.trim()).ok()?;
    (b.len() == LOGIN_TICKET_LEN).then_some(b)
}

/// Messages sent from a client to `nos-watchdogd`'s broker socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Serialize, Deserialize)]
pub enum WatchdogRequest {
    /// One-shot: resolve where to reach the given service right now.
    /// Requires a client certificate.
    ResolveEndpoint {
        /// The service to resolve.
        service: ServiceRef,
    },
    /// The only request an unauthenticated peer may send: prove who you are
    /// with a local user's password and get a short-lived client certificate
    /// for the public key in `csr_der` (the private key never leaves the
    /// caller). Answered with `Issued` or `Denied`.
    Login {
        /// Login name.
        user: String,
        /// Cleartext password, verified against the local-user hash.
        password: String,
        /// DER-encoded certificate signing request.
        csr_der: Vec<u8>,
    },
    /// Trade a still-valid `user` certificate for a fresh one on the key in
    /// `csr_der`, with no password. Refused if the user no longer exists.
    RenewCert {
        /// DER-encoded certificate signing request.
        csr_der: Vec<u8>,
    },
    /// `nos-restd` only: a TLS *server* certificate for its listener, valid
    /// for `addresses`, on the key in `csr_der`. Answered with `RestServerCert`.
    IssueRestServerCert {
        /// Addresses to put in the certificate's SAN.
        addresses: Vec<IpAddr>,
        /// DER-encoded certificate signing request.
        csr_der: Vec<u8>,
    },
    /// `nos-restd` only, on behalf of a REST client: `Login`, but the
    /// certificate is issued by the REST CA (`Issued`). The failed-login
    /// throttle is `nos-restd`'s, not the broker connection's.
    RestLogin {
        /// Login name.
        user: String,
        /// Cleartext password, verified against the local-user hash.
        password: String,
        /// DER-encoded certificate signing request.
        csr_der: Vec<u8>,
    },
    /// `nos-restd` only: `RenewCert` for a REST client whose still-valid
    /// certificate `nos-restd` has just verified. Refused if the user is gone,
    /// the certificate was revoked (password change) or the session outlived
    /// `--pki-rest-session-max`.
    RestRenew {
        /// Login name.
        user: String,
        /// Hex serial of the certificate the client presented.
        serial: String,
        /// DER-encoded certificate signing request.
        csr_der: Vec<u8>,
    },
    /// `nos-restd` only, on every authenticated REST request: is the
    /// certificate with this serial, issued to `user`, still live? Answered
    /// with `Ok` or `Denied` (the REST CA has no CRL; the watchdog keeps the
    /// allowlist).
    RestCertCheck {
        /// Login name the certificate names.
        user: String,
        /// Hex serial of the presented certificate.
        serial: String,
    },
    /// Anonymous like `Login`: verify the password but issue no certificate;
    /// answered with a single-use `Ticket` that `RedeemTicket` trades for one.
    LoginTicket {
        /// Login name.
        user: String,
        /// Cleartext password, verified against the local-user hash.
        password: String,
    },
    /// Anonymous: trade a `Ticket` for a user certificate on the key in
    /// `csr_der`. Answered with `Issued` or `Denied(INVALID_TICKET)`.
    RedeemTicket {
        /// The secret ticket bytes.
        ticket: Vec<u8>,
        /// DER-encoded certificate signing request.
        csr_der: Vec<u8>,
    },
}

// Manual `Debug`: a `Login` is one log line away from leaking a password.
impl fmt::Debug for WatchdogRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WatchdogRequest::ResolveEndpoint { service } => f
                .debug_struct("ResolveEndpoint")
                .field("service", service)
                .finish(),
            WatchdogRequest::Login { user, .. } => f
                .debug_struct("Login")
                .field("user", user)
                .field("password", &"<hidden>")
                .finish_non_exhaustive(),
            WatchdogRequest::RestLogin { user, .. } => f
                .debug_struct("RestLogin")
                .field("user", user)
                .field("password", &"<hidden>")
                .finish_non_exhaustive(),
            WatchdogRequest::RenewCert { .. } => {
                f.debug_struct("RenewCert").finish_non_exhaustive()
            }
            WatchdogRequest::IssueRestServerCert { addresses, .. } => f
                .debug_struct("IssueRestServerCert")
                .field("addresses", addresses)
                .finish_non_exhaustive(),
            WatchdogRequest::RestRenew { user, .. } => f
                .debug_struct("RestRenew")
                .field("user", user)
                .finish_non_exhaustive(),
            WatchdogRequest::RestCertCheck { user, serial } => f
                .debug_struct("RestCertCheck")
                .field("user", user)
                .field("serial", serial)
                .finish(),
            WatchdogRequest::LoginTicket { user, .. } => f
                .debug_struct("LoginTicket")
                .field("user", user)
                .field("password", &"<hidden>")
                .finish_non_exhaustive(),
            WatchdogRequest::RedeemTicket { .. } => {
                f.debug_struct("RedeemTicket").finish_non_exhaustive()
            }
        }
    }
}

/// Messages sent from `nos-watchdogd` to a broker client.
#[derive(Serialize, Deserialize)]
pub enum WatchdogEvent {
    /// The service is currently reachable at this Unix socket path.
    Endpoint(PathBuf),
    /// No such service is currently running/known (e.g. the routing table
    /// isn't configured, or its `nos-ribd` hasn't finished starting yet).
    NotAvailable,
    /// Reply to `Login`/`RenewCert`: the DER client certificate, and how long
    /// it is valid for so the caller knows when to renew.
    Issued {
        /// DER-encoded certificate issued.
        cert_der: Vec<u8>,
        /// Validity of the issued certificate, in seconds.
        lifetime_secs: u64,
    },
    /// Reply to `Login`/`RenewCert`: refused. Deliberately one opaque
    /// message for unknown user and wrong password alike.
    Denied(String),
    /// Reply to `RestCertCheck`: the certificate is live.
    Ok,
    /// Reply to `IssueRestServerCert`: the listener's certificate, the REST CA
    /// that signed it (the trust anchor for client certificates), and how long
    /// the certificate is valid.
    RestServerCert {
        /// DER-encoded certificate issued.
        cert_der: Vec<u8>,
        /// DER-encoded CA certificate to trust.
        ca_der: Vec<u8>,
        /// Validity of the issued certificate, in seconds.
        lifetime_secs: u64,
    },
    /// Reply to `LoginTicket`: a single-use secret, valid for `ttl_secs`.
    Ticket {
        /// The secret ticket bytes.
        ticket: Vec<u8>,
        /// Seconds until it expires unredeemed.
        ttl_secs: u64,
    },
}

// Manual `Debug`: a `Ticket` is a credential.
impl fmt::Debug for WatchdogEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WatchdogEvent::Endpoint(p) => f.debug_tuple("Endpoint").field(p).finish(),
            WatchdogEvent::NotAvailable => f.write_str("NotAvailable"),
            WatchdogEvent::Issued {
                cert_der,
                lifetime_secs,
            } => f
                .debug_struct("Issued")
                .field("cert_der", cert_der)
                .field("lifetime_secs", lifetime_secs)
                .finish(),
            WatchdogEvent::Denied(m) => f.debug_tuple("Denied").field(m).finish(),
            WatchdogEvent::Ok => f.write_str("Ok"),
            WatchdogEvent::RestServerCert {
                cert_der,
                ca_der,
                lifetime_secs,
            } => f
                .debug_struct("RestServerCert")
                .field("cert_der", cert_der)
                .field("ca_der", ca_der)
                .field("lifetime_secs", lifetime_secs)
                .finish(),
            WatchdogEvent::Ticket { ttl_secs, .. } => f
                .debug_struct("Ticket")
                .field("ticket", &"<hidden>")
                .field("ttl_secs", ttl_secs)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_round_trip_through_their_certificate_spelling() {
        for r in Role::ALL {
            assert_eq!(Role::parse(r.as_str()), Some(r));
        }
        assert_eq!(Role::parse("root"), None);
    }

    #[test]
    fn a_service_is_expected_to_authenticate_as_its_own_daemon() {
        let rib = ServiceRef::RibTable("rt1".into());
        assert_eq!((rib.role(), rib.instance()), (Role::Ribd, "rt1"));
        assert_eq!(
            (ServiceRef::Config.role(), ServiceRef::Config.instance()),
            (Role::Configd, "")
        );
        assert_eq!(ServiceRef::Ospfv3Instance("a".into()).role(), Role::Ospfv3d);
        assert_eq!(
            (ServiceRef::Bfd.role(), ServiceRef::Bfd.instance()),
            (Role::Bfdd, "")
        );
        assert_eq!(
            (ServiceRef::Stp.role(), ServiceRef::Stp.instance()),
            (Role::Stpd, "")
        );
        assert_eq!(
            (ServiceRef::Acl.role(), ServiceRef::Acl.instance()),
            (Role::Acld, "")
        );
    }

    #[test]
    fn login_debug_never_shows_the_password() {
        let req = WatchdogRequest::Login {
            user: "alice".into(),
            password: "hunter2".into(),
            csr_der: vec![1, 2, 3],
        };
        let shown = format!("{req:?}");
        assert!(shown.contains("alice") && !shown.contains("hunter2"));
    }

    #[test]
    fn ticket_messages_round_trip_and_never_print_secrets() {
        let ticket = vec![0xAB; LOGIN_TICKET_LEN];
        let reqs = [
            WatchdogRequest::LoginTicket {
                user: "alice".into(),
                password: "hunter2".into(),
            },
            WatchdogRequest::RedeemTicket {
                ticket: ticket.clone(),
                csr_der: vec![1, 2],
            },
        ];
        for r in &reqs {
            let bytes = postcard::to_allocvec(r).unwrap();
            let back: WatchdogRequest = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(format!("{r:?}"), format!("{back:?}"));
            let shown = format!("{r:?}");
            assert!(!shown.contains("hunter2") && !shown.contains("171"));
        }
        let ev = WatchdogEvent::Ticket {
            ticket: ticket.clone(),
            ttl_secs: 60,
        };
        let back: WatchdogEvent =
            postcard::from_bytes(&postcard::to_allocvec(&ev).unwrap()).unwrap();
        assert!(matches!(back, WatchdogEvent::Ticket { ttl_secs: 60, ticket: t } if t == ticket));
        let shown = format!("{ev:?}");
        assert!(
            shown.contains("60")
                && !shown.contains("171")
                && !shown.contains(&ticket_to_env(&ticket))
        );
    }

    #[test]
    fn ticket_env_form_round_trips_and_rejects_bad_input() {
        let t = vec![7u8; LOGIN_TICKET_LEN];
        assert_eq!(ticket_from_env(&ticket_to_env(&t)), Some(t));
        assert_eq!(ticket_from_env(&ticket_to_env(&[1u8; 31])), None);
        assert_eq!(ticket_from_env("not base64!"), None);
        assert_eq!(ticket_from_env(""), None);
    }
}
