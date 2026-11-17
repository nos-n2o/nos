#![allow(
    clippy::disallowed_types,
    reason = "test code spawns the built binaries (#228)"
)]
//! Built only with `--features dev-args` (it passes `--driver=noop`, a dev flag, #1214).
//!
//! The whole stack, unprivileged (#131): the real `nos-watchdogd` supervising
//! every real daemon (Linux drivers swapped for `noop`, every path under a
//! temp dir), provisioned by the real `nos-provision` through a real login,
//! reconfigured once, then stopped with SIGTERM. Daemons that need a
//! capability (raw sockets, VRF binds) log the failure and keep running, so
//! this still exercises every `main.rs`, reconcile loop and push client.
//!
//! Needs the sibling binaries in the same target directory, which
//! `cargo test --workspace` (and `make test`/`make coverage`) builds; a
//! single-package run without them skips with a note.

#![cfg(feature = "dev-args")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const DAEMONS: [&str; 14] = [
    "nos-configd",
    "nos-bgpd",
    "nos-ribd",
    "nos-fdbd",
    "nos-ospfd",
    "nos-ospfv3d",
    "nos-restd",
    "nos-interfaced",
    "nos-logd",
    "nos-lacpd",
    "nos-lldpd",
    "nos-stpd",
    "nos-acld",
    "nos-provision",
];

fn bin_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_BIN_EXE_nos-watchdogd"))
        .parent()?
        .to_path_buf();
    DAEMONS.iter().all(|d| dir.join(d).exists()).then_some(dir)
}

fn log_text(path: &Path) -> String {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    // Strip ANSI colours so field matches are plain `key=value`.
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn wait_for(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("timed out waiting for {what}");
}

struct Stack {
    dir: tempfile::TempDir,
    bins: PathBuf,
    watchdog: Child,
}

impl Stack {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn log(&self) -> String {
        log_text(&self.path("watchdog.log"))
    }

    fn start(bins: PathBuf) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let d = |n: &str| dir.path().join(n).display().to_string();
        let b = |n: &str| bins.join(n).display().to_string();
        let log = std::fs::File::create(dir.path().join("watchdog.log")).unwrap();
        let watchdog = Command::new(bins.join("nos-watchdogd"))
            .env("RUST_LOG", "debug")
            .args(["--configd-bin", &b("nos-configd")])
            .args(["--bgpd-bin", &b("nos-bgpd")])
            .args(["--ribd-bin", &b("nos-ribd")])
            .args(["--fdbd-bin", &b("nos-fdbd")])
            .args(["--ospfd-bin", &b("nos-ospfd")])
            .args(["--ospfv3d-bin", &b("nos-ospfv3d")])
            .args(["--restd-bin", &b("nos-restd")])
            .args(["--interfaced-bin", &b("nos-interfaced")])
            .args(["--logd-bin", &b("nos-logd")])
            .args(["--lacpd-bin", &b("nos-lacpd")])
            .args(["--lldpd-bin", &b("nos-lldpd")])
            .args(["--stpd-bin", &b("nos-stpd")])
            .args(["--acld-bin", &b("nos-acld")])
            .args(["--config-socket", &d("config.sock")])
            .args(["--listen-socket", &d("watchdog.sock")])
            .args(["--pki-dir", &d("pki")])
            .args(["--log-socket", &d("log.sock")])
            .args(["--interfaced-listen-socket", &d("interface.sock")])
            .args(["--lacpd-listen-socket", &d("lacp.sock")])
            .args(["--lldpd-listen-socket", &d("lldp.sock")])
            .args(["--stpd-listen-socket", &d("stp.sock")])
            .args(["--acld-listen-socket", &d("acl.sock")])
            .args(["--run-dir", &d("")])
            .arg(format!("--configd-arg=--listen={}", d("config.sock")))
            .arg(format!("--configd-arg=--config-file={}", d("config.yaml")))
            .args(["--ribd-arg=--driver=noop", "--interfaced-arg=--driver=noop"])
            .args(["--fdbd-arg=--driver=noop", "--acld-arg=--driver=noop"])
            .arg(format!(
                "--ribd-arg=--table-registry-path={}",
                d("tables.yaml")
            ))
            .arg(format!(
                "--interfaced-arg=--bridge-registry-path={}",
                d("bridges.yaml")
            ))
            .arg(format!(
                "--interfaced-arg=--port-aggregate-registry-path={}",
                d("bonds.yaml")
            ))
            .arg(format!("--logd-arg=--log-store-path={}", d("log.jsonl")))
            .arg(format!("--ospfd-arg=--state-dir={}", d("ospf")))
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        Self {
            dir,
            bins,
            watchdog,
        }
    }

    /// Runs `nos-provision` (a real login, then one transaction).
    fn provision(&self, flags: &[&str]) {
        let d = |n: &str| self.path(n).display().to_string();
        let out = Command::new(self.bins.join("nos-provision"))
            .args(["--config-socket", &d("config.sock")])
            .args(["--watchdog-socket", &d("watchdog.sock")])
            .args(["--pki-ca", &d("pki/ca.crt")])
            .args(["--login-user", "admin", "--login-password", "admin"])
            .args(flags)
            .stdout(Stdio::null())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "nos-provision failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        let _ = self.watchdog.kill();
    }
}

const BASE: &[&str] = &[
    "--address",
    "10.0.0.1/24",
    "--asn",
    "65000",
    "--router-id",
    "1.1.1.1",
    "--remote-as",
    "65001",
    "--peer",
    "10.0.0.2",
    "--static-route",
    "198.51.100.0/24",
    "--static-gateway",
    "10.0.0.9",
    "--redistribute",
    "--ospf-instance",
    "o1",
    "--ospf-router-id",
    "1.1.1.1",
    "--ospf-area",
    "0.0.0.0",
    "--ospf-profile",
    "p1",
    "--ospf-interface-profile",
    "p1",
    "--ospfv3-instance",
    "v3",
    "--ospfv3-router-id",
    "1.1.1.1",
    "--ospfv3-area",
    "0.0.0.0",
    "--ospfv3-profile",
    "p3",
    "--ospfv3-interface-profile",
    "p3",
    "--address6",
    "2001:db8::1/64",
    "--broadcast-domain",
    "bd1",
    "--evpn",
    "--port-aggregate",
    "bond1",
    "--port-aggregate-mode",
    "lacp",
    "--enslave-interface-into-port-aggregate",
    "eth1",
    "--lldp-transmit-interface",
    "eth2",
    "--lldp-receive-interface",
    "eth2",
];

const EVPN: &[&str] = &[
    "--evpn-vni",
    "100",
    "--evpn-rd",
    "1.1.1.1:100",
    "--evpn-rt-import",
    "65000:100",
    "--evpn-rt-export",
    "65000:100",
    "--evpn-vtep-source-interface",
    "eth0",
    "--evpn-redistribute-bgp",
    "r1",
];

#[test]
fn whole_stack_starts_reconfigures_and_stops_cleanly() {
    let Some(bins) = bin_dir() else {
        eprintln!("skipping: the daemon binaries aren't built next to nos-watchdogd (run the workspace tests)");
        return;
    };
    let mut stack = Stack::start(bins);
    wait_for("the ipc ca and nos-configd", 30, || {
        stack.path("pki/ca.crt").exists() && stack.path("config.sock").exists()
    });

    let first: Vec<&str> = BASE.iter().chain(EVPN).copied().collect();
    stack.provision(&first);
    for daemon in [
        "nos-bgpd",
        "nos-ribd",
        "nos-ospfd",
        "nos-ospfv3d",
        "nos-fdbd",
    ] {
        wait_for(daemon, 30, || {
            stack.log().contains(&format!("spawning {daemon} for new"))
        });
    }
    // Let every daemon run through at least one 10s re-apply tick.
    std::thread::sleep(Duration::from_secs(12));

    // Clearing the vni stops nos-fdbd; the rest keeps running.
    let second: Vec<&str> = BASE
        .iter()
        .copied()
        .chain([
            "--evpn-clear",
            "--evpn-rt-import",
            "65000:100",
            "--evpn-rt-export",
            "65000:100",
        ])
        .collect();
    stack.provision(&second);
    wait_for("nos-fdbd to stop", 30, || {
        stack.log().contains("exited cleanly process=nos-fdbd[bd1]")
    });

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(stack.watchdog.id()).unwrap()),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = stack.watchdog.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "nos-watchdogd didn't stop");
        std::thread::sleep(Duration::from_millis(200));
    };
    let log = stack.log();
    assert!(
        status.success(),
        "nos-watchdogd exited with {status}:\n{log}"
    );
    for process in [
        "nos-configd",
        "nos-logd",
        "nos-interfaced",
        "nos-lacpd",
        "nos-lldpd",
        "nos-stpd",
        "nos-acld",
        "nos-bgpd[r1]",
        "nos-ribd[rt1]",
        "nos-ospfd[o1]",
        "nos-ospfv3d[v3]",
    ] {
        assert!(
            log.contains(&format!("exited cleanly process={process}")),
            "{process} didn't exit cleanly:\n{log}"
        );
    }
    assert!(!log.contains("panicked"), "a daemon panicked:\n{log}");
}
