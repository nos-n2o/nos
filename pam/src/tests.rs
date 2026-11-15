//! The module's logic against a fake login broker (`nos-test-support`) speaking
//! real mutual TLS. No real PAM stack: the `PamModule` impl is a thin adapter over
//! `authenticate_user`/`check_account`, covered by #998's `pamtester` phase.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use futures::StreamExt;
use nonstick::ErrorCode;
use nos_proto::{WatchdogEvent, WatchdogRequest, INVALID_CREDENTIALS, LOGIN_BUSY};
use nos_test_support::{FakeLogin, Reply};
use tempfile::TempDir;
use tokio::runtime::Runtime;

use crate::module::{authenticate_user, check_account, guard};
use crate::options::Options;
use crate::session::NosTicket;

const T: Duration = Duration::from_secs(10);

struct Env {
    // Keeps the fake's workers running while the test calls the blocking `login`.
    _rt: Runtime,
    dir: TempDir,
    opts: Options,
}

fn pw(s: &str) -> OsString {
    s.into()
}

/// `make` runs inside the runtime (the fake spawns); `None` = no broker at all.
fn env<F>(make: impl FnOnce(&std::path::Path) -> F) -> (Env, F) {
    let rt = Runtime::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("watchdog.sock");
    let ca = dir.path().join("ca.crt");
    std::fs::write(&ca, nos_pki::testing::shared().ca().cert_pem()).unwrap();
    let fake = rt.block_on(async { make(&socket) });
    let opts = Options {
        socket,
        ca,
        ..Options::default()
    };
    (Env { _rt: rt, dir, opts }, fake)
}

fn replying(reply: fn() -> Reply<WatchdogEvent>) -> impl FnOnce(&std::path::Path) -> FakeLogin {
    move |p| FakeLogin::new(p, move |_| reply())
}

fn accepting(p: &std::path::Path) -> FakeLogin {
    FakeLogin::accepting(p, "alice", "s3cret", 600)
}

fn denied(m: &str) -> Reply<WatchdogEvent> {
    Reply::One(WatchdogEvent::Denied(m.to_string()))
}

#[test]
fn success_hands_back_a_ticket_via_login_ticket() {
    let (e, fake) = env(accepting);
    let s = authenticate_user(&e.opts, "alice".as_ref(), pw("s3cret"), T).unwrap();
    assert_eq!(s.user, "alice");
    assert_eq!(s.encoded.as_str(), nos_proto::ticket_to_env(&[7; 32]));
    let seen = fake.take_seen();
    assert_eq!(seen.len(), 1);
    assert!(matches!(seen[0], WatchdogRequest::LoginTicket { .. }));
}

#[test]
fn wrong_password_is_an_authentication_error() {
    let (e, _f) = env(accepting);
    let r = authenticate_user(&e.opts, "alice".as_ref(), pw("nope"), T);
    assert_eq!(r.unwrap_err(), ErrorCode::AuthenticationError);
}

#[test]
fn no_broker_is_auth_info_unavailable() {
    let (e, ()) = env(|_| ());
    let r = authenticate_user(&e.opts, "alice".as_ref(), pw("s3cret"), T);
    assert_eq!(r.unwrap_err(), ErrorCode::AuthInfoUnavailable);
}

#[test]
fn a_broker_from_another_ca_fails_the_handshake() {
    let (mut e, _f) = env(accepting);
    let other = e.dir.path().join("other-ca.crt");
    std::fs::write(&other, nos_pki::testing::TestPki::new().ca().cert_pem()).unwrap();
    e.opts.ca = other;
    let r = authenticate_user(&e.opts, "alice".as_ref(), pw("s3cret"), T);
    assert_eq!(r.unwrap_err(), ErrorCode::AuthInfoUnavailable);
}

#[test]
fn missing_or_garbage_ca_file_fails_closed() {
    let (mut e, f) = env(accepting);
    e.opts.ca = PathBuf::from("/nonexistent/ca.crt");
    let r = authenticate_user(&e.opts, "alice".as_ref(), pw("s3cret"), T);
    assert_eq!(r.unwrap_err(), ErrorCode::AuthInfoUnavailable);
    let junk = e.dir.path().join("junk.crt");
    std::fs::write(&junk, "not a certificate").unwrap();
    e.opts.ca = junk;
    let r = authenticate_user(&e.opts, "alice".as_ref(), pw("s3cret"), T);
    assert_eq!(r.unwrap_err(), ErrorCode::AuthInfoUnavailable);
    assert!(f.take_seen().is_empty());
}

#[test]
fn hang_up_mid_request_is_unavailable() {
    let (e, _f) = env(replying(|| Reply::Close));
    let r = authenticate_user(&e.opts, "alice".as_ref(), pw("s3cret"), T);
    assert_eq!(r.unwrap_err(), ErrorCode::AuthInfoUnavailable);
}

#[test]
fn a_silent_broker_hits_the_deadline() {
    let (e, _f) = env(replying(|| {
        Reply::Stream(vec![], futures::stream::pending().boxed())
    }));
    let start = Instant::now();
    let r = authenticate_user(
        &e.opts,
        "alice".as_ref(),
        pw("s3cret"),
        Duration::from_millis(200),
    );
    assert_eq!(r.unwrap_err(), ErrorCode::AuthInfoUnavailable);
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn busy_unavailable_and_other_denials_are_all_unavailable() {
    for m in [LOGIN_BUSY, "login unavailable", "not permitted"] {
        let (e, _f) = env(|p| {
            let m = m.to_string();
            FakeLogin::new(p, move |_| denied(&m))
        });
        let r = authenticate_user(&e.opts, "alice".as_ref(), pw("s3cret"), T);
        assert_eq!(r.unwrap_err(), ErrorCode::AuthInfoUnavailable, "{m}");
    }
}

#[test]
fn an_unexpected_event_is_unavailable() {
    let (e, _f) = env(replying(|| Reply::One(WatchdogEvent::NotAvailable)));
    let r = authenticate_user(&e.opts, "alice".as_ref(), pw("s3cret"), T);
    assert_eq!(r.unwrap_err(), ErrorCode::AuthInfoUnavailable);
}

#[test]
fn invalid_credentials_is_the_only_authentication_error() {
    let (e, _f) = env(replying(|| denied(INVALID_CREDENTIALS)));
    let r = authenticate_user(&e.opts, "alice".as_ref(), pw("s3cret"), T);
    assert_eq!(r.unwrap_err(), ErrorCode::AuthenticationError);
}

#[test]
fn bad_names_and_passwords_never_reach_the_broker() {
    use std::os::unix::ffi::OsStringExt;
    let (e, f) = env(accepting);
    let cases = [
        ("alice", pw("")),
        ("", pw("s3cret")),
        ("alice", OsString::from_vec(vec![0xff, 0xfe])),
    ];
    for (user, password) in cases {
        let r = authenticate_user(&e.opts, user.as_ref(), password, T);
        assert_eq!(r.unwrap_err(), ErrorCode::AuthenticationError);
    }
    let r = authenticate_user(
        &e.opts,
        OsString::from_vec(vec![0xff]).as_os_str(),
        pw("x"),
        T,
    );
    assert_eq!(r.unwrap_err(), ErrorCode::AuthenticationError);
    assert!(f.take_seen().is_empty());
}

fn session(user: &str) -> NosTicket {
    NosTicket {
        user: user.into(),
        encoded: "TICKET".to_string().into(),
    }
}

#[test]
fn account_management_needs_a_matching_session() {
    assert_eq!(
        check_account(None, "alice".as_ref()),
        Err(ErrorCode::AuthenticationError)
    );
    assert_eq!(
        check_account(Some(&session("alice")), "bob".as_ref()),
        Err(ErrorCode::AuthenticationError)
    );
    assert_eq!(
        check_account(Some(&session("alice")), "alice".as_ref()),
        Ok(())
    );
}

#[test]
fn account_management_after_a_real_authenticate() {
    let (e, _f) = env(accepting);
    let s = authenticate_user(&e.opts, "alice".as_ref(), pw("s3cret"), T).unwrap();
    assert_eq!(check_account(Some(&s), "alice".as_ref()), Ok(()));
}

#[test]
fn guard_turns_a_panic_into_service_error() {
    let r: nonstick::Result<()> = guard(|| panic!("boom"));
    assert_eq!(r, Err(ErrorCode::ServiceError));
    assert_eq!(guard(|| Ok(1)), Ok(1));
    assert_eq!(
        guard::<()>(|| Err(ErrorCode::UserUnknown)),
        Err(ErrorCode::UserUnknown)
    );
}

#[test]
fn session_debug_shows_only_the_user() {
    let d = format!("{:?}", session("alice"));
    assert!(d.contains("alice"));
    assert!(!d.contains("TICKET") && !d.contains("encoded"));
}
