//! Runs the built binary: a target outside `/usr/local/bin` is refused (fail closed).
//! The success path needs file capabilities and a container: `nos-e2e`'s `sandbox-nnp`.

#[test]
#[allow(
    clippy::disallowed_types,
    reason = "runs the built binary under test (#228)"
)]
fn refuses_a_target_outside_the_daemon_dir() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_nos-sandbox-exec"))
        .args(["--profile", "probe", "--", "/bin/true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(126));
    let msg = String::from_utf8_lossy(&out.stderr);
    assert!(
        msg.contains("nos-sandbox-exec:") && msg.contains("outside"),
        "{msg}"
    );
}

#[test]
#[allow(
    clippy::disallowed_types,
    reason = "runs the built binary under test (#228)"
)]
fn bad_usage_exits_126() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_nos-sandbox-exec"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(126));
}
