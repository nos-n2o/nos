#![allow(
    clippy::disallowed_types,
    reason = "test code spawns the built binaries (#228)"
)]
//! The built binary's flags (#1214).

/// A release build rejects the test-only flags before doing anything (#1214).
#[cfg(not(feature = "dev-args"))]
#[test]
fn dev_flags_are_rejected_in_release() {
    for flag in ["--pki-cert-out=/x", "--pki-cert-in=/x", "--renew-probe"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_nos-provision"))
            .arg(flag)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{flag}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("unexpected argument"),
            "{flag}"
        );
    }
}
