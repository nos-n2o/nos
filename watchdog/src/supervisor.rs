use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use nos_proto::Role;
use tokio::io::{AsyncWrite, AsyncWriteExt};
#[allow(
    clippy::disallowed_types,
    reason = "the supervisor's whole job is spawning the daemons (#228)"
)]
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use nos_pki::Serial;

use crate::pki::Pki;

/// One child process to keep running.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub name: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    /// `Some`: each spawn gets a fresh certificate identity down its stdin
    /// (and rotations after it). `None` only for tests that supervise
    /// `/bin/true`; every real daemon has one.
    pub identity: Option<SpawnIdentity>,
    /// `Some((uid, gid))`: the child runs as that user (set before exec, so
    /// its file capabilities still apply). `None`: it inherits ours.
    pub uid: Option<(u32, u32)>,
    /// Extra variables for this child only, applied after the scrubbed
    /// `CHILD_ENV` allowlist (which stays untouched for everyone else).
    pub env: Vec<(String, String)>,
}

/// Which certificate a child is issued: `nos://<role>/<name>`.
#[derive(Clone)]
pub struct SpawnIdentity {
    pub pki: Arc<Pki>,
    pub role: Role,
    pub name: String,
}

impl std::fmt::Debug for SpawnIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.role.as_str(), self.name)
    }
}

impl ProcessSpec {
    pub fn new(name: impl Into<String>, program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self {
            name: name.into(),
            program: program.into(),
            args,
            identity: None,
            uid: None,
            env: Vec::new(),
        }
    }

    /// Adds one environment variable to this child (on top of the allowlist).
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// With `Some(gid)`, runs the child as its role's own uid (`uids::role_uid`)
    /// and group `gid`. Call after `with_identity`: the role is the key, so the
    /// uid cannot disagree with the certificate. `None`: inherit ours.
    #[must_use]
    pub fn with_role_uid(mut self, gid: Option<u32>) -> Self {
        let uid = self
            .identity
            .as_ref()
            .and_then(|i| crate::uids::role_uid(i.role));
        self.uid = uid.zip(gid);
        self
    }

    #[must_use]
    pub fn with_identity(mut self, pki: Arc<Pki>, role: Role, name: impl Into<String>) -> Self {
        self.identity = Some(SpawnIdentity {
            pki,
            role,
            name: name.into(),
        });
        self
    }
}

/// Exponential backoff policy for respawns.
#[derive(Debug, Clone, Copy)]
pub struct BackoffPolicy {
    pub base: Duration,
    pub max: Duration,
    pub multiplier: u32,
    pub stable_after: Duration,
    /// A child that has beaten (`Heartbeat`) and then falls silent for this
    /// long is restarted (#1150); `None` disables it (`--no-heartbeat-kill`).
    pub liveness_timeout: Option<Duration>,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(30),
            multiplier: 2,
            stable_after: Duration::from_secs(60),
            // 3 x the daemons' 5 s beat interval + 5 s grace.
            liveness_timeout: Some(Duration::from_secs(20)),
        }
    }
}

impl BackoffPolicy {
    fn grow(&self, current: Duration) -> Duration {
        current.saturating_mul(self.multiplier).min(self.max)
    }

    /// The delay to wait after a run of `ran_for`: a run that survived
    /// `stable_after` decays the level one step (never straight to `base`, so
    /// a process crashing every 61 s stays near `max`); a rapid crash keeps it.
    #[must_use]
    pub fn next_delay(&self, current: Duration, ran_for: Duration) -> Duration {
        if ran_for >= self.stable_after {
            (current / self.multiplier.max(1)).max(self.base)
        } else {
            current
        }
    }
}

/// Environment variables a child inherits; everything else (`LD_PRELOAD`,
/// proxies, secrets) is dropped. Identity goes through stdin, not the env.
/// `NOS_LACP_CHURN_SECS` (the e2e's short LACP churn timer) only in a `dev-args` build (#1214).
#[cfg(feature = "dev-args")]
const CHILD_ENV: &[&str] = &["RUST_LOG", "PATH", "TZ", "NOS_LACP_CHURN_SECS"];
#[cfg(not(feature = "dev-args"))]
const CHILD_ENV: &[&str] = &["RUST_LOG", "PATH", "TZ"];

/// Keeps only the `CHILD_ENV` entries of `vars`.
fn allowed_env(
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    vars.filter(|(k, _)| CHILD_ENV.iter().any(|a| k == a))
        .collect()
}

// Linux `include/uapi/linux/prctl.h` (6.3); newer than the `libc` release pinned.
const PR_SET_MDWE: libc::c_int = 65;
const PR_GET_MDWE: libc::c_int = 66;
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;

/// `PR_GET_MDWE` of this process: is `REFUSE_EXEC_GAIN` set? Children inherit
/// it across fork and exec, so this is also their state.
pub fn mdwe_active() -> bool {
    // SAFETY: a prctl read with integer arguments.
    #[allow(unsafe_code, reason = "one prctl read, integer args only (#1210)")]
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- integer-arg prctl
    let got = unsafe { libc::prctl(PR_GET_MDWE, 0, 0, 0, 0) };
    got >= 0 && got & 1 != 0 // 1 = PR_MDWE_REFUSE_EXEC_GAIN
}

/// Memory-Deny-Write-Execute for this process (#1210): no W+X mapping, no
/// `mprotect` to X of a writable one. Irrevocable and inherited by every child
/// across fork and exec (so the spawn path stays `posix_spawn`, no `pre_exec`).
/// Called once at watchdog start; fails on kernels < 6.3 (`EINVAL`), and the
/// watchdog then refuses to start: nothing may run without it.
pub fn enable_mdwe() -> std::io::Result<()> {
    // SAFETY: a prctl syscall with integer arguments.
    #[allow(unsafe_code, reason = "one prctl syscall, integer args only (#1210)")]
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- integer-arg prctl
    let set = unsafe { libc::prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) };
    if set != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if !mdwe_active() {
        return Err(std::io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(())
}

/// Consecutive rapid crashes at which (and every 10th after) an alarm is logged.
const CRASH_LOOP_ALARM: u32 = 5;

/// Supervises one child process: spawn, wait, restart with exponential
/// backoff, forever, until `shutdown` reports `true`.
#[allow(
    clippy::disallowed_types,
    reason = "the supervisor's whole job is spawning the daemons (#228)"
)]
pub async fn supervise_one(
    spec: ProcessSpec,
    policy: BackoffPolicy,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut delay = policy.base;
    let mut consecutive_crashes: u32 = 0;

    while !*shutdown.borrow() {
        info!(
            process = %spec.name,
            program = %spec.program.display(),
            uid = spec.uid.map(|i| i.0),
            gid = spec.uid.map(|i| i.1),
            env = %spec.env.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(","),
            "starting"
        );
        let start = Instant::now();

        let mut command = Command::new(&spec.program);
        command.args(&spec.args);
        command.env_clear().envs(allowed_env(std::env::vars_os()));
        command.envs(spec.env.iter().cloned());
        if let Some((uid, gid)) = spec.uid {
            command.uid(uid).gid(gid);
        }
        if spec.identity.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = match command.spawn() {
            Ok(child) => {
                // The child inherits our MDWE (set once at start, irrevocable).
                info!(process = %spec.name, pid = child.id(), mdwe = mdwe_active(), "spawned");
                child
            }
            Err(e) => {
                error!(process = %spec.name, error = %e, "failed to spawn");
                if wait_or_shutdown(delay, &mut shutdown).await {
                    return;
                }
                delay = policy.grow(delay);
                continue;
            }
        };
        if let Some(id) = &spec.identity {
            crate::heartbeat::forget(id.role.as_str(), &id.name);
        }
        let issued = Arc::new(Mutex::new(Vec::new()));
        let pusher = spec
            .identity
            .clone()
            .zip(child.stdin.take())
            .map(|(id, stdin)| push_identity(spec.name.clone(), id, stdin, issued.clone()));

        let mut check = tokio::time::interval(
            policy
                .liveness_timeout
                .map_or(Duration::from_secs(3600), |t| {
                    (t / 4).max(Duration::from_millis(10))
                }),
        );
        let child_exited = loop {
            tokio::select! {
                status = child.wait() => {
                    match status {
                        Ok(status) => warn!(process = %spec.name, %status, "exited"),
                        Err(e) => error!(process = %spec.name, error = %e, "wait() failed"),
                    }
                    break true;
                }
                _ = shutdown.changed() => break false,
                _ = check.tick() => {
                    let hung = spec.identity.as_ref().zip(policy.liveness_timeout).filter(|(id, t)| {
                        crate::heartbeat::missed(
                            crate::heartbeat::last(id.role.as_str(), &id.name),
                            tokio::time::Instant::now(),
                            *t,
                        )
                    });
                    if hung.is_some() {
                        warn!(process = %spec.name, "heartbeat missed, killing the hung process");
                        shutdown_child(&spec.name, &mut child).await;
                        break true;
                    }
                }
            }
        };

        if !child_exited {
            // Shutdown requested while the child was still running — the
            // whole watchdog stopping, or this instance removed/unpinned.
            shutdown_child(&spec.name, &mut child).await;
            if let Some(p) = pusher {
                p.abort();
            }
            revoke_spawn(&spec, &issued);
            return;
        }
        if let Some(p) = pusher {
            p.abort(); // closes the dead child's pipe
        }
        // Before the backoff, so the replacement's first frame already
        // carries a CRL naming its predecessor's certificates.
        revoke_spawn(&spec, &issued);
        if *shutdown.borrow() {
            return;
        }

        // A stable run decays the backoff one step; a rapid one is a crash.
        let ran_for = start.elapsed();
        delay = policy.next_delay(delay, ran_for);
        if ran_for >= policy.stable_after {
            consecutive_crashes = 0;
        } else {
            consecutive_crashes += 1;
            if consecutive_crashes >= CRASH_LOOP_ALARM
                && (consecutive_crashes - CRASH_LOOP_ALARM).is_multiple_of(10)
            {
                error!(process = %spec.name, consecutive_crashes, "crash loop");
            }
        }

        info!(process = %spec.name, delay_secs = delay.as_secs(), "restarting after backoff");
        if wait_or_shutdown(delay, &mut shutdown).await {
            return;
        }
        delay = policy.grow(delay);
    }
}

/// Revokes every certificate minted for one spawn of `spec`, now that its
/// process is gone. A key that outlives its process is only a liability.
fn revoke_spawn(spec: &ProcessSpec, issued: &Mutex<Vec<Serial>>) {
    if let Some(id) = &spec.identity {
        let serials = std::mem::take(&mut *issued.lock().unwrap_or_else(PoisonError::into_inner));
        id.pki.revoke(id.role, &id.name, serials);
    }
}

/// Delivers a child's identity down its stdin: the first frame right away, a
/// fresh leaf every `rotate_every`, and the current leaf again with the new
/// CRL whenever the CRL changes. The CRL itself rides only the first frame and
/// those CRL-change frames; rotation frames send it empty (= "keep the one you
/// hold"), so a big CRL is not re-sent to every child on every rotation. The key travels only through this pipe:
/// never argv, environment or disk. Every leaf minted is recorded in `issued`
/// for `revoke_spawn`. Ends when the child stops reading (it exited) or the
/// supervisor aborts it.
fn push_identity<W: AsyncWrite + Unpin + Send + 'static>(
    name: String,
    id: SpawnIdentity,
    mut stdin: W,
    issued: Arc<Mutex<Vec<Serial>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut crl = id.pki.crl();
        let mut current = None;
        let mut rotate = true;
        let mut crl_pending = true;
        let mut next_rotation = tokio::time::Instant::now();
        loop {
            if rotate {
                next_rotation += id.pki.rotate_every;
                match id.pki.mint(id.role, &id.name) {
                    Ok(bundle) => {
                        if let Ok(serial) = Serial::of(&bundle.cert) {
                            issued
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .push(serial);
                        }
                        current = Some(bundle);
                    }
                    Err(e) => warn!(process = %name, error = %e, "failed to mint an identity"),
                }
            }
            if let Some(bundle) = &mut current {
                crl_pending |= crl.has_changed().unwrap_or(false);
                if crl_pending {
                    bundle.crl.clone_from(&crl.borrow_and_update());
                } else {
                    bundle.crl.clear();
                }
                crl_pending = false;
                info!(process = %name, crl_bytes = bundle.crl.len(), "identity pushed");
                if let Err(e) = stdin.write_all(&bundle.encode()).await {
                    debug!(process = %name, error = %e, "child no longer reads its identity");
                    return;
                }
            }
            tokio::select! {
                () = tokio::time::sleep_until(next_rotation) => rotate = true,
                changed = crl.changed() => {
                    if changed.is_err() {
                        return; // the Pki is gone: the watchdog is exiting
                    }
                    rotate = false;
                    crl_pending = true;
                }
            }
        }
    })
}

/// Sleeps for `delay`, or returns early (`true`) if shutdown fires first.
pub(crate) async fn wait_or_shutdown(
    delay: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

/// Sends SIGINT (not SIGTERM — see main.rs doc comment), then force-kills
/// after a grace period if the child hasn't exited.
async fn shutdown_child(name: &str, child: &mut Child) {
    if let Some(pid) = child.id() {
        info!(process = %name, "sending SIGINT");
        let pid = Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX));
        if let Err(e) = signal::kill(pid, Signal::SIGINT) {
            warn!(process = %name, error = %e, "failed to send SIGINT");
        }
    }

    if tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .is_ok()
    {
        info!(process = %name, "exited cleanly");
    } else {
        warn!(process = %name, "did not exit within 10s, killing");
        if let Err(e) = child.kill().await {
            warn!(process = %name, error = %e, "failed to force-kill process");
        }
        let _ = child.wait().await;
    }
}

#[cfg(test)]
mod push_tests {
    use super::*;
    use nos_pki::Bundle;
    use tokio::io::{duplex, AsyncReadExt, DuplexStream};

    async fn frame(r: &mut DuplexStream) -> Bundle {
        let mut len = [0u8; 4];
        r.read_exact(&mut len).await.unwrap();
        let mut buf = len.to_vec();
        buf.resize(4 + u32::from_le_bytes(len) as usize, 0);
        r.read_exact(&mut buf[4..]).await.unwrap();
        Bundle::read_from(&mut buf.as_slice()).unwrap().unwrap()
    }

    fn setup() -> (tempfile::TempDir, Arc<Pki>, DuplexStream) {
        let tmp = tempfile::tempdir().unwrap();
        let pki = Pki::start(
            tmp.path(),
            Duration::from_secs(600),
            Duration::from_millis(400),
            Duration::from_secs(60),
        )
        .unwrap();
        let (w, r) = duplex(1 << 24);
        let id = SpawnIdentity {
            pki: pki.clone(),
            role: Role::Configd,
            name: "x".into(),
        };
        push_identity("x".into(), id, w, Arc::new(Mutex::new(Vec::new())));
        (tmp, pki, r)
    }

    #[tokio::test]
    async fn crl_rides_first_and_changed_frames_only() {
        let (_t, pki, mut r) = setup();
        assert_ne!(frame(&mut r).await.crl.len(), 0);
        assert_eq!(frame(&mut r).await.crl.len(), 0, "rotation: keep");
        let cert = pki.mint(Role::Configd, "y").unwrap().cert;
        pki.revoke(Role::Configd, "y", vec![Serial::of(&cert).unwrap()]);
        assert_ne!(frame(&mut r).await.crl.len(), 0, "change: sent once");
        assert_eq!(frame(&mut r).await.crl.len(), 0);
    }
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn rapid_crash_keeps_level_then_grows_to_max() {
        let p = BackoffPolicy::default();
        assert_eq!(p.next_delay(4 * S, 2 * S), 4 * S);
        let mut d = p.base;
        for _ in 0..10 {
            d = p.grow(d);
        }
        assert_eq!(d, p.max);
    }

    #[test]
    fn stable_run_decays_one_step_never_to_base_from_max() {
        let p = BackoffPolicy::default();
        assert_eq!(p.next_delay(p.max, 61 * S), 15 * S);
        assert_eq!(p.next_delay(p.base, 61 * S), p.base);
        // 61 s crash cycle at the cap: wait, grow, decay stays at 15 s.
        let mut d = p.max;
        for _ in 0..5 {
            d = p.next_delay(d, 61 * S);
            assert!(d > p.base);
            d = p.grow(d);
        }
    }

    #[test]
    fn with_role_uid_maps_the_role_and_defaults_to_none() {
        let pki = Pki::start(
            tempfile::tempdir().unwrap().path(),
            Duration::from_secs(60),
            Duration::from_secs(30),
            Duration::from_secs(60),
        )
        .unwrap();
        let s = ProcessSpec::new("x", "/bin/true", vec![]);
        assert_eq!(s.uid, None);
        let s = s.with_identity(pki, Role::Bgpd, "r1");
        assert_eq!(s.clone().with_role_uid(None).uid, None);
        assert_eq!(s.with_role_uid(Some(992)).uid, Some((10003, 992)));
        // No identity, no role, no uid.
        let bare = ProcessSpec::new("x", "/bin/true", vec![]);
        assert_eq!(bare.with_role_uid(Some(992)).uid, None);
    }

    #[allow(unsafe_code, reason = "raw mmap/mprotect probe (#1210)")]
    fn assert_wx_refused() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only mmap probe
        let map = |prot| unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        let rwx = map(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        assert_eq!(rwx, libc::MAP_FAILED, "RWX mapping must be refused");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        let w = map(libc::PROT_READ | libc::PROT_WRITE);
        assert_ne!(w, libc::MAP_FAILED);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only mprotect probe
        let r = unsafe { libc::mprotect(w, 4096, libc::PROT_READ | libc::PROT_EXEC) };
        assert_eq!(r, -1, "W then X must be refused");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    }

    /// Re-runs this test binary on one `--exact` test with `env` set.
    #[allow(
        clippy::disallowed_types,
        reason = "runs the test binary itself (#228)"
    )]
    fn rerun(test: &str, env: &str) -> std::process::Output {
        // nosemgrep: rust.lang.security.current-exe.current-exe -- test re-execs itself, nothing security-relevant
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env(env, "1")
            .output()
            .unwrap()
    }

    fn mdwe_supported() -> bool {
        let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
        let mut it = rel.split(['.', '-']).map(|p| p.parse::<u32>().unwrap_or(0));
        let ok = (it.next().unwrap_or(0), it.next().unwrap_or(0)) >= (6, 3);
        if !ok {
            eprintln!("kernel {rel} < 6.3: skipping");
        }
        ok
    }

    /// Process side of `enable_mdwe_refuses_wx_and_children_inherit_it`: a
    /// no-op unless re-run by it (`enable_mdwe` is irrevocable, so it must not
    /// run in the shared test process).
    #[test]
    fn mdwe_probe() {
        if std::env::var_os("NOS_MDWE_PROBE").is_none() {
            return;
        }
        assert!(!mdwe_active());
        enable_mdwe().unwrap();
        assert!(mdwe_active());
        assert_wx_refused();
        let out = rerun("backoff_tests::mdwe_grandchild", "NOS_MDWE_GRANDCHILD");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Grandchild: spawned by the probe after `enable_mdwe`, never calls it.
    #[test]
    fn mdwe_grandchild() {
        if std::env::var_os("NOS_MDWE_GRANDCHILD").is_some() {
            assert!(mdwe_active());
            assert_wx_refused();
        }
    }

    #[test]
    fn enable_mdwe_refuses_wx_and_children_inherit_it() {
        if !mdwe_supported() {
            return;
        }
        let out = rerun("backoff_tests::mdwe_probe", "NOS_MDWE_PROBE");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A child spawned with our own uid/gid still runs (an unprivileged
    /// `setuid` to oneself is allowed), and the `starting` path takes it.
    #[tokio::test]
    async fn a_child_spawns_with_an_explicit_uid() {
        use std::os::unix::fs::MetadataExt;
        let me = std::fs::metadata("/proc/self").unwrap();
        let ids = (me.uid(), me.gid());
        let mut spec = ProcessSpec::new("t", "/bin/sleep", vec!["30".into()]);
        spec.uid = Some(ids);
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(supervise_one(spec, BackoffPolicy::default(), rx));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!task.is_finished(), "the child must be running");
        tx.send(true).unwrap();
        task.await.unwrap();
    }

    /// A child that beat once and then fell silent is killed and respawned; one
    /// that never beat, or keeps beating, is left alone (#1150).
    #[tokio::test]
    async fn a_silent_child_is_restarted_only_after_it_beat() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::start(
            dir.path(),
            Duration::from_secs(600),
            Duration::from_secs(300),
            Duration::from_secs(60),
        )
        .unwrap();
        let spawns =
            |name: &str| {
                let log = dir.path().join(name);
                let script = format!("echo x >> {}; exec sleep 300", log.display());
                let spec = ProcessSpec::new(name, "/bin/sh", vec!["-c".into(), script])
                    .with_identity(pki.clone(), Role::Configd, name);
                (spec, log)
            };
        let policy = BackoffPolicy {
            base: Duration::from_millis(50),
            liveness_timeout: Some(Duration::from_millis(800)),
            ..BackoffPolicy::default()
        };
        let count =
            |p: &std::path::Path| std::fs::read_to_string(p).map_or(0, |s| s.lines().count());
        let (tx, rx) = watch::channel(false);
        let (silent, silent_log) = spawns("hb-silent");
        let (quiet, quiet_log) = spawns("hb-never");
        let (steady, steady_log) = spawns("hb-steady");
        let tasks: Vec<_> = [silent, quiet, steady]
            .into_iter()
            .map(|s| tokio::spawn(supervise_one(s, policy, rx.clone())))
            .collect();
        tokio::time::sleep(Duration::from_millis(300)).await;
        crate::heartbeat::record("configd", "hb-silent");
        for _ in 0..40 {
            crate::heartbeat::record("configd", "hb-steady");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(count(&silent_log) >= 2, "silent child restarted");
        assert_eq!(count(&quiet_log), 1, "never-beat child exempt");
        assert_eq!(count(&steady_log), 1, "beating child untouched");
        tx.send(true).unwrap();
        for t in tasks {
            t.await.unwrap();
        }
    }

    #[test]
    fn env_allow_list_drops_the_rest() {
        let v = |s: &str| std::ffi::OsString::from(s);
        let out = allowed_env(
            [
                ("LD_PRELOAD", "x"),
                ("HTTP_PROXY", "y"),
                ("RUST_LOG", "info"),
                ("PATH", "/bin"),
            ]
            .into_iter()
            .map(|(k, x)| (v(k), v(x))),
        );
        let keys: Vec<_> = out.iter().map(|(k, _)| k.to_str().unwrap()).collect();
        assert_eq!(keys, ["RUST_LOG", "PATH"]);
    }

    #[tokio::test]
    async fn with_env_reaches_the_child_only_when_asked() {
        async fn seen(spec: ProcessSpec, out: &std::path::Path) -> String {
            let (tx, rx) = watch::channel(false);
            let task = tokio::spawn(supervise_one(spec, BackoffPolicy::default(), rx));
            tokio::time::sleep(Duration::from_millis(500)).await;
            tx.send(true).unwrap();
            task.await.unwrap();
            std::fs::read_to_string(out)
                .unwrap_or_default()
                .trim()
                .to_string()
        }
        let dir = tempfile::tempdir().unwrap();
        let spec = |name: &str| {
            let out = dir.path().join(name);
            let args = vec![
                "-c".into(),
                format!(
                    "echo \"x${{MALLOC_ARENA_MAX}}\" > {}; exec sleep 30",
                    out.display()
                ),
            ];
            (ProcessSpec::new("t", "/bin/sh", args), out)
        };
        let (with, out) = spec("with");
        assert_eq!(
            seen(with.with_env("MALLOC_ARENA_MAX", "1"), &out).await,
            "x1"
        );
        let (without, out) = spec("without");
        assert_eq!(seen(without, &out).await, "x");
    }
}
