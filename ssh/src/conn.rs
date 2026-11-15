//! Accepts SSH connections and hands each to its own `sshd -i` process (#994).
//!
//! `-i` makes `MaxStartups` meaningless (one process per connection), so the
//! brakes here are a global cap and a per-source-address cap, both applied
//! before anything is spawned.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

/// Open connections per source address.
pub const MAX_PER_SOURCE: usize = 8;
/// Open connections in total.
pub const MAX_CONNECTIONS: usize = 64;
/// SIGTERM to SIGKILL; the whole shutdown must fit the watchdog's 10 s window.
const TERM_GRACE: Duration = Duration::from_secs(5);
/// One sshd log line is cut here before it reaches `nos-logd`.
const MAX_LINE: usize = 512;

pub struct Limits {
    pub global: usize,
    pub per_source: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            global: MAX_CONNECTIONS,
            per_source: MAX_PER_SOURCE,
        }
    }
}

type LineSink = Arc<dyn Fn(SocketAddr, &str) + Send + Sync>;

pub struct Spec {
    pub table: String,
    pub sshd_bin: PathBuf,
    pub config: PathBuf,
    pub limits: Limits,
    /// Where sshd's stderr lines go (`-e` sends its log there).
    pub on_line: LineSink,
}

impl Spec {
    pub fn new(table: String, sshd_bin: PathBuf, config: PathBuf, limits: Limits) -> Self {
        let t = table.clone();
        Self {
            table,
            sshd_bin,
            config,
            limits,
            on_line: Arc::new(move |peer, line| info!(table = %t, %peer, "sshd: {line}")),
        }
    }
}

/// Counts open connections per source; the guard releases on drop.
#[derive(Default)]
struct PerSource(Mutex<HashMap<IpAddr, usize>>);

struct SourceGuard(Arc<PerSource>, IpAddr);

impl PerSource {
    fn take(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<SourceGuard> {
        let mut m = self.0.lock().expect("per-source map");
        let n = m.entry(ip).or_default();
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(SourceGuard(self.clone(), ip))
    }
}

impl Drop for SourceGuard {
    fn drop(&mut self) {
        let mut m = self.0 .0.lock().expect("per-source map");
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

/// Accepts until `stop`, then terminates every child (SIGTERM, SIGKILL after 5 s).
pub async fn serve(listener: TcpListener, spec: Arc<Spec>, mut stop: watch::Receiver<bool>) {
    let slots = Arc::new(Semaphore::new(spec.limits.global));
    let sources = Arc::new(PerSource::default());
    let mut children = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            a = listener.accept() => a,
            () = async { let _ = stop.wait_for(|s| *s).await; } => break,
        };
        while children.try_join_next().is_some() {}
        let (tcp, peer) = match accepted {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "ssh accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let (Ok(slot), Some(source)) = (
            slots.clone().try_acquire_owned(),
            sources.take(peer.ip(), spec.limits.per_source),
        ) else {
            debug!(table = %spec.table, %peer, "ssh connection refused: connection limit");
            continue; // `tcp` dropped before anything is spawned
        };
        let (spec, stop) = (spec.clone(), stop.clone());
        children.spawn(async move {
            let _held = (slot, source);
            if let Err(e) = run_child(&spec, tcp, peer, stop).await {
                warn!(table = %spec.table, %peer, error = %e, "ssh connection failed");
            }
        });
    }
    drop(listener);
    while children.join_next().await.is_some() {}
}

#[allow(
    clippy::disallowed_types,
    reason = "stock OpenSSH sshd is an external binary with no VRF or inherited-listener support (#988)"
)]
async fn run_child(
    spec: &Spec,
    tcp: TcpStream,
    peer: SocketAddr,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    // tokio left the socket non-blocking; the flag is shared with the dups sshd gets.
    let std = tcp.into_std()?;
    std.set_nonblocking(false)?;
    let stdin: OwnedFd = std.into();
    let stdout = stdin.try_clone()?;
    let mut child = {
        let mut cmd = tokio::process::Command::new(&spec.sshd_bin);
        cmd.args(["-i", "-e", "-f"])
            .arg(&spec.config)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/bin")
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd.spawn()?
    }; // the command (and the parent's socket fds) is dropped here
    debug!(table = %spec.table, %peer, pid = ?child.id(), "ssh connection accepted");

    let stderr = child.stderr.take().expect("stderr is piped");
    let on_line = spec.on_line.clone();
    let pump = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            on_line(peer, truncate(&line));
        }
    });

    tokio::select! {
        _ = child.wait() => {}
        () = async { let _ = stop.wait_for(|s| *s).await; } => {
            if let Some(pid) = child.id() {
                let _ = kill(Pid::from_raw(pid.cast_signed()), Signal::SIGTERM);
            }
            if tokio::time::timeout(TERM_GRACE, child.wait()).await.is_err() {
                let _ = child.kill().await;
            }
        }
    }
    let _ = pump.await;
    Ok(())
}

fn truncate(line: &str) -> &str {
    match line.char_indices().nth(MAX_LINE) {
        Some((i, _)) => &line[..i],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn script(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("fake-sshd");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    struct Rig {
        addr: SocketAddr,
        stop: watch::Sender<bool>,
        task: tokio::task::JoinHandle<()>,
        lines: Arc<Mutex<Vec<String>>>,
    }

    async fn rig(bin: PathBuf, limits: Limits) -> Rig {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        let mut spec = Spec::new("rt1".into(), bin, "/dev/null".into(), limits);
        spec.on_line = Arc::new(move |_, l| sink.lock().unwrap().push(l.to_string()));
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(serve(listener, Arc::new(spec), rx));
        Rig {
            addr,
            stop,
            task,
            lines,
        }
    }

    async fn is_closed(c: &mut TcpStream) -> bool {
        let mut b = [0u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_secs(2), c.read(&mut b)).await,
            Ok(Ok(0) | Err(_))
        )
    }

    #[tokio::test]
    async fn data_flows_env_is_clean_and_stderr_is_forwarded() {
        let d = tempfile::tempdir().unwrap();
        let bin = script(
            d.path(),
            "echo \"ENV:$(env | sort | tr '\\n' ' ')\" >&2\nexec cat",
        );
        let r = rig(bin, Limits::default()).await;
        let mut c = TcpStream::connect(r.addr).await.unwrap();
        c.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        drop(c);
        let _ = r.stop.send(true);
        r.task.await.unwrap();
        let lines = r.lines.lock().unwrap();
        let env = lines
            .iter()
            .find(|l| l.starts_with("ENV:"))
            .expect("stderr line");
        assert!(env.contains("PATH=/usr/sbin:/usr/bin:/bin"), "{env}");
        assert!(!env.contains("CARGO") && !env.contains("HOME="), "{env}");
    }

    #[tokio::test]
    async fn global_and_per_source_caps_refuse_without_spawning() {
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("spawned");
        let bin = script(
            d.path(),
            &format!("echo x >> {}\nexec sleep 30", log.display()),
        );
        for limits in [
            Limits {
                global: 1,
                per_source: 8,
            },
            Limits {
                global: 64,
                per_source: 1,
            },
        ] {
            let r = rig(bin.clone(), limits).await;
            let mut first = TcpStream::connect(r.addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            let mut second = TcpStream::connect(r.addr).await.unwrap();
            assert!(is_closed(&mut second).await);
            assert!(!is_closed_quick(&mut first).await);
            let _ = r.stop.send(true);
            r.task.await.unwrap();
            assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 1);
            std::fs::remove_file(&log).unwrap();
        }
    }

    async fn is_closed_quick(c: &mut TcpStream) -> bool {
        let mut b = [0u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_millis(200), c.read(&mut b)).await,
            Ok(Ok(0) | Err(_))
        )
    }

    #[tokio::test]
    async fn slot_frees_when_the_child_exits() {
        let d = tempfile::tempdir().unwrap();
        let bin = script(d.path(), "echo ok");
        let r = rig(
            bin,
            Limits {
                global: 1,
                per_source: 1,
            },
        )
        .await;
        for _ in 0..3 {
            // The slot is released a moment after the child exits; retry until served.
            let mut served = false;
            for _ in 0..40 {
                let mut c = TcpStream::connect(r.addr).await.unwrap();
                let mut got = Vec::new();
                let _ = tokio::time::timeout(Duration::from_secs(2), c.read_to_end(&mut got)).await;
                if got == b"ok\n" {
                    served = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(served);
        }
        let _ = r.stop.send(true);
        r.task.await.unwrap();
    }

    #[tokio::test]
    async fn stop_terminates_a_sleeping_child() {
        let d = tempfile::tempdir().unwrap();
        let pidfile = d.path().join("pid");
        let bin = script(
            d.path(),
            &format!("echo $$ > {}\nexec sleep 30", pidfile.display()),
        );
        let r = rig(bin, Limits::default()).await;
        let _c = TcpStream::connect(r.addr).await.unwrap();
        for _ in 0..50 {
            if std::fs::read_to_string(&pidfile).is_ok_and(|s| !s.is_empty()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let pid = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .to_string();
        let t = std::time::Instant::now();
        let _ = r.stop.send(true);
        r.task.await.unwrap();
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(!Path::new("/proc").join(pid).exists());
    }

    #[test]
    fn truncates_long_lines_on_a_char_boundary() {
        assert_eq!(truncate("short"), "short");
        let long = "é".repeat(MAX_LINE + 10);
        assert_eq!(truncate(&long).chars().count(), MAX_LINE);
    }
}
