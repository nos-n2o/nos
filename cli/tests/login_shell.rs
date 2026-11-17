//! The real `nos` binary in login-shell mode (#991).
#![allow(clippy::disallowed_types, reason = "runs the built binary")]

use std::process::Command;

const SECRET: &str = "SECRETTICKETVALUE";

fn nos() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nos"));
    c.env(nos_proto::LOGIN_TICKET_ENV, SECRET);
    c
}

#[test]
fn dash_c_is_refused_with_exit_2() {
    let out = nos().args(["-c", "show version"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not supported"), "{err}");
    assert!(!err.contains(SECRET));
}

#[cfg(feature = "dev-args")]
#[test]
fn ticket_with_no_watchdog_fails_closed_without_echoing_the_ticket() {
    let tmp = tempfile::tempdir().unwrap();
    let out = nos()
        .args(["--pki-ca", "/nonexistent/ca.crt", "--watchdog-socket"])
        .arg(tmp.path().join("w.sock"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    let all = [out.stdout, out.stderr].concat();
    assert!(!String::from_utf8_lossy(&all).contains(SECRET));
}

/// A release build rejects the dev flags before any watchdog contact (#1214).
#[cfg(not(feature = "dev-args"))]
#[test]
fn dev_flags_are_rejected_in_release() {
    for flag in ["--pki-ca", "--watchdog-socket"] {
        let out = nos().args([flag, "/x"]).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{flag}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("unexpected argument"), "{flag}: {err}");
        assert!(!err.contains(SECRET));
    }
}
