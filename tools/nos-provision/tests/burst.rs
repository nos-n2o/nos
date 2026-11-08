#![allow(
    clippy::disallowed_types,
    reason = "test code spawns the built binaries (#228)"
)]
//! `--login-burst` (#677) against an in-process fake broker: every login is
//! a fresh connection, `LOGIN_BUSY` is retried, any other denial fails.

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, WatchdogEvent, WatchdogRequest, LOGIN_BUSY};
use tokio_util::codec::{FramedRead, FramedWrite};

/// Serves logins until aborted: the first is answered busy, the rest `reply`.
/// A connection that fails mid-handshake or sends no login is skipped (the
/// tool cancels the loser of a concurrent burst), and the listener stays up so
/// a retry never meets a refused connect (#921).
async fn broker(listener: nos_pki::Listener, reply: fn() -> WatchdogEvent) {
    let mut seen = 0;
    loop {
        let Ok(conn) = listener.accept().await else {
            continue;
        };
        let Ok((stream, _)) = conn.handshake().await else {
            continue;
        };
        let (r, w) = tokio::io::split(stream);
        let mut reader = FramedRead::new(r, IpcCodec::<WatchdogRequest>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogEvent>::default());
        let Some(Ok(WatchdogRequest::Login { user, .. })) = reader.next().await else {
            continue;
        };
        assert_eq!(user, "burster");
        let event = if seen == 0 {
            WatchdogEvent::Denied(LOGIN_BUSY.to_string())
        } else {
            reply()
        };
        seen += 1;
        let _ = writer.send(event).await;
    }
}

async fn run_burst(reply: fn() -> WatchdogEvent, n: &str) -> (bool, String) {
    let pki = nos_pki::testing::shared();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("watchdog.sock");
    let ca = dir.path().join("ca.crt");
    std::fs::write(&ca, pki.ca().cert_pem()).unwrap();
    let listener = pki
        .identity("watchdog", "")
        .listen_optional_client_auth(&sock)
        .unwrap();
    let server = tokio::spawn(broker(listener, reply));
    let (sock, ca, n) = (sock.clone(), ca.clone(), n.to_string());
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_nos-provision"))
            .args(["--address", "10.0.0.1/24", "--asn", "1", "--router-id"])
            .args(["1.1.1.1", "--remote-as", "2", "--peer", "10.0.0.2"])
            .args(["--login-user", "burster", "--login-password", "pw"])
            .args(["--login-burst", &n])
            .arg("--watchdog-socket")
            .arg(&sock)
            .arg("--pki-ca")
            .arg(&ca)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    server.abort();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_burst_logs_in_n_times_and_retries_a_busy_broker() {
    let (ok, out) = run_burst(
        || WatchdogEvent::Issued {
            cert_der: Vec::new(),
            lifetime_secs: 60,
        },
        "3",
    )
    .await;
    assert!(ok, "{out}");
    assert!(out.contains("burst complete logins=3"), "{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_burst_login_fails_the_tool() {
    let (ok, out) = run_burst(|| WatchdogEvent::Denied("invalid credentials".into()), "2").await;
    assert!(!ok);
    assert!(out.contains("burst login failed"), "{out}");
}
