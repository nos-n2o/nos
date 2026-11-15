//! Owns the SSH listener: which address it is bound to, inside which VRF.
//!
//! Modelled on `nos-restd`'s `listen.rs`: every tick (and at once on a
//! routing-table config change) it compares what the table's `ssh_server`
//! *wants* with what is *bound*, then binds, rebinds or drops. "Not possible
//! yet" (no VRF, address not on an interface yet) is retried every tick.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nos_daemon::{config, ipc, watchdog};
use nos_proto::{DiffScope, Event, Request, RibEvent, RibRequest, Role, ServiceRef, SshServer};
use socket2::SockRef;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::conn::{self, Spec};

const TICK: Duration = Duration::from_secs(1);

/// Where the wanted state and the VRF name come from.
#[allow(
    async_fn_in_trait,
    reason = "crate-internal, only used with concrete types"
)]
pub trait Source {
    /// The table's `ssh_server` (`Some(None)` = read fine, not pinned);
    /// `None` if the config could not be read, so a blip keeps the listener.
    async fn wanted(&self) -> Option<Option<SshServer>>;
    async fn vrf_name(&self) -> Option<String>;
}

pub trait Binder {
    fn bind(&self, local: SocketAddr, vrf: &str) -> io::Result<TcpListener>;
    /// The VRF device's ifindex: `SO_BINDTODEVICE` resolves the name once, so a
    /// recreated VRF leaves the socket on a dead device.
    fn ifindex(&self, vrf: &str) -> Option<u32>;
}

/// The real thing: `SO_BINDTODEVICE` + bind, ifindex from sysfs.
pub struct LinuxBinder;

impl Binder for LinuxBinder {
    fn bind(&self, local: SocketAddr, vrf: &str) -> io::Result<TcpListener> {
        // A third per-crate copy of `nos-bgpd`/`nos-restd`'s helper: extracting
        // it would pull `socket2` into every daemon for ten lines.
        let socket = if local.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        SockRef::from(&socket).bind_device(Some(vrf.as_bytes()))?;
        socket.bind(local)?;
        socket.listen(128)
    }

    fn ifindex(&self, vrf: &str) -> Option<u32> {
        std::fs::read_to_string(Path::new("/sys/class/net").join(vrf).join("ifindex"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }
}

/// Production [`Source`]: `nos-configd` for the config, `nos-ribd` for the VRF.
pub struct Daemons {
    pub table: String,
    pub watchdog_socket: PathBuf,
    pub config_socket: PathBuf,
}

impl Source for Daemons {
    async fn wanted(&self) -> Option<Option<SshServer>> {
        match config::fetch_config(&self.config_socket).await {
            Ok(cfg) => Some(
                cfg.routing_tables
                    .into_iter()
                    .find(|t| t.name == self.table)
                    .and_then(|t| t.ssh_server),
            ),
            Err(e) => {
                debug!(error = ?e, "could not read config; keeping current listener");
                None
            }
        }
    }

    async fn vrf_name(&self) -> Option<String> {
        let rib = watchdog::resolve_once(
            &self.watchdog_socket,
            &ServiceRef::RibTable(self.table.clone()),
        )
        .await?;
        match ipc::one_shot::<_, RibEvent>(&rib, Role::Ribd, RibRequest::GetVrfName).await {
            Some(RibEvent::VrfName(name)) => name,
            _ => None,
        }
    }
}

impl crate::hostkey::Keys for Daemons {
    async fn get(&self) -> Option<Option<String>> {
        let cfg = config::fetch_config(&self.config_socket).await.ok()?;
        Some(cfg.key(nos_proto::SSH_HOST_KEY_LABEL).map(str::to_owned))
    }

    async fn set(&self, seed: &str) {
        let req = Request::SetSshHostKey { seed: seed.into() };
        // Refused when another table's daemon won: `get` then adopts its key.
        let _ = ipc::one_shot::<_, Event>(&self.config_socket, Role::Configd, req).await;
    }
}

struct Bound {
    want: SshServer,
    vrf: String,
    ifindex: Option<u32>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

pub struct Listener<S, B> {
    pub spec: Arc<Spec>,
    pub source: S,
    pub binder: B,
    /// Fires when routing-table config changes; `None` = tick only.
    pub trigger: Option<mpsc::Receiver<()>>,
}

/// A channel that fires on routing-table config changes. Best effort: `None`
/// if `nos-configd` can't be subscribed to right now (the tick still converges).
/// ponytail: not resubscribed if the stream later drops; the 1s tick covers it.
pub async fn config_trigger(config_socket: &Path) -> Option<mpsc::Receiver<()>> {
    let mut reader = config::subscribe_diff(config_socket, vec![DiffScope::RoutingTables])
        .await
        .ok()?;
    let (tx, rx) = mpsc::channel(4);
    tokio::spawn(async move {
        while let Some(Ok(_)) = reader.next().await {
            if tx.send(()).await.is_err() {
                break;
            }
        }
    });
    Some(rx)
}

impl<S: Source, B: Binder> Listener<S, B> {
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        let mut bound: Option<Bound> = None;
        // Last "can't bind" reason logged, so a retry loop logs once per change.
        let mut last_problem = String::new();
        let mut trigger = self.trigger.take();
        while !*shutdown.borrow() {
            self.converge(&mut bound, &mut last_problem).await;
            tokio::select! {
                () = tokio::time::sleep(TICK) => {}
                Some(()) = async { match trigger.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {}
                _ = shutdown.changed() => {}
            }
        }
        if let Some(b) = bound.take() {
            self.stop(b).await;
        }
    }

    async fn converge(&self, bound: &mut Option<Bound>, last_problem: &mut String) {
        let Some(want) = self.source.wanted().await else {
            return; // config unreadable: keep whatever is bound
        };
        if let Some(b) = bound.as_ref() {
            let vrf_now = self.source.vrf_name().await;
            let stale = want.as_ref() != Some(&b.want)
                || vrf_now.as_deref() != Some(b.vrf.as_str())
                || self.binder.ifindex(&b.vrf) != b.ifindex;
            if stale && let Some(b) = bound.take() {
                self.stop(b).await;
            }
        }
        let (Some(want), None) = (want, bound.as_ref()) else {
            return;
        };
        match self.bind(&want).await {
            Ok(b) => {
                info!(table = %self.spec.table, vrf = %b.vrf, address = %want.address, port = want.port, "ssh listening");
                *bound = Some(b);
                last_problem.clear();
            }
            Err(problem) => {
                if *last_problem != problem {
                    warn!(table = %self.spec.table, address = %want.address, port = want.port, "ssh not listening yet: {problem}");
                    *last_problem = problem;
                }
            }
        }
    }

    async fn bind(&self, want: &SshServer) -> Result<Bound, String> {
        let vrf = self
            .source
            .vrf_name()
            .await
            .ok_or_else(|| format!("vrf of table '{}' does not exist yet", self.spec.table))?;
        let listener = self
            .binder
            .bind(SocketAddr::new(want.address, want.port), &vrf)
            .map_err(|e| format!("bind in vrf {vrf} failed: {e}"))?;
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(conn::serve(listener, self.spec.clone(), rx));
        Ok(Bound {
            want: want.clone(),
            ifindex: self.binder.ifindex(&vrf),
            vrf,
            stop,
            task,
        })
    }

    async fn stop(&self, b: Bound) {
        let _ = b.stop.send(true);
        // `serve` bounds itself (SIGTERM, then SIGKILL after 5 s).
        let _ = tokio::time::timeout(Duration::from_secs(7), b.task).await;
        info!(table = %self.spec.table, vrf = %b.vrf, address = %b.want.address, port = b.want.port, "ssh stopped listening");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::Limits;
    use futures::SinkExt;
    use nos_proto::IpcCodec;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::sync::Mutex;
    use tokio_util::codec::{FramedRead, FramedWrite};

    #[derive(Default)]
    struct Fake {
        #[allow(clippy::option_option, reason = "unreadable / unpinned / pinned")]
        wanted: Mutex<Option<Option<SshServer>>>,
        vrf: Mutex<Option<String>>,
        ifindex: Mutex<Option<u32>>,
        binds: Mutex<Vec<(SocketAddr, String)>>,
        fail_bind: Mutex<bool>,
    }

    struct Shared(Arc<Fake>);

    #[allow(clippy::unused_async_trait_impl, reason = "fake: no await needed")]
    impl Source for Shared {
        async fn wanted(&self) -> Option<Option<SshServer>> {
            self.0.wanted.lock().unwrap().clone()
        }
        async fn vrf_name(&self) -> Option<String> {
            self.0.vrf.lock().unwrap().clone()
        }
    }

    impl Binder for Shared {
        fn bind(&self, local: SocketAddr, vrf: &str) -> io::Result<TcpListener> {
            if *self.0.fail_bind.lock().unwrap() {
                return Err(io::Error::from(io::ErrorKind::AddrNotAvailable));
            }
            self.0.binds.lock().unwrap().push((local, vrf.to_string()));
            // A plain loopback bind stands in for SO_BINDTODEVICE.
            let std = std::net::TcpListener::bind("127.0.0.1:0")?;
            std.set_nonblocking(true)?;
            TcpListener::from_std(std)
        }
        fn ifindex(&self, _: &str) -> Option<u32> {
            *self.0.ifindex.lock().unwrap()
        }
    }

    fn ssh(port: u16) -> SshServer {
        SshServer {
            address: "10.0.0.1".parse().unwrap(),
            port,
        }
    }

    fn fixture() -> (Arc<Fake>, Listener<Shared, Shared>) {
        let fake = Arc::new(Fake::default());
        *fake.vrf.lock().unwrap() = Some("vrf1".into());
        *fake.ifindex.lock().unwrap() = Some(7);
        let spec = Spec::new(
            "rt1".into(),
            "/bin/true".into(),
            "/dev/null".into(),
            Limits::default(),
        );
        let l = Listener {
            spec: Arc::new(spec),
            source: Shared(fake.clone()),
            binder: Shared(fake.clone()),
            trigger: None,
        };
        (fake, l)
    }

    #[tokio::test]
    async fn binds_rebinds_on_each_change_and_stops_on_unpin() {
        let (fake, l) = fixture();
        let (mut bound, mut problem) = (None, String::new());
        let binds = || fake.binds.lock().unwrap().len();

        // Not pinned: nothing.
        *fake.wanted.lock().unwrap() = Some(None);
        l.converge(&mut bound, &mut problem).await;
        assert!(bound.is_none());

        *fake.wanted.lock().unwrap() = Some(Some(ssh(22)));
        l.converge(&mut bound, &mut problem).await;
        assert_eq!(binds(), 1);
        assert_eq!(fake.binds.lock().unwrap()[0].1, "vrf1");
        l.converge(&mut bound, &mut problem).await;
        assert_eq!(binds(), 1, "unchanged: no rebind");

        *fake.wanted.lock().unwrap() = Some(Some(ssh(2222))); // port
        l.converge(&mut bound, &mut problem).await;
        assert_eq!(binds(), 2);
        *fake.wanted.lock().unwrap() = Some(Some(SshServer {
            address: "10.0.0.2".parse().unwrap(),
            port: 2222,
        })); // address
        l.converge(&mut bound, &mut problem).await;
        assert_eq!(binds(), 3);
        *fake.vrf.lock().unwrap() = Some("vrf2".into()); // vrf name
        l.converge(&mut bound, &mut problem).await;
        assert_eq!(binds(), 4);
        *fake.ifindex.lock().unwrap() = Some(9); // vrf recreated
        l.converge(&mut bound, &mut problem).await;
        assert_eq!(binds(), 5);

        *fake.wanted.lock().unwrap() = None; // config read error keeps it
        l.converge(&mut bound, &mut problem).await;
        assert!(bound.is_some());

        *fake.wanted.lock().unwrap() = Some(None); // unpinned
        l.converge(&mut bound, &mut problem).await;
        assert!(bound.is_none());
    }

    #[tokio::test]
    async fn unbindable_is_logged_once_per_change_and_retried() {
        let (fake, l) = fixture();
        let (mut bound, mut problem) = (None, String::new());
        *fake.wanted.lock().unwrap() = Some(Some(ssh(22)));
        *fake.fail_bind.lock().unwrap() = true;
        l.converge(&mut bound, &mut problem).await;
        let first = problem.clone();
        assert!(first.contains("bind in vrf vrf1 failed"));
        assert!(bound.is_none());
        *fake.vrf.lock().unwrap() = None;
        l.converge(&mut bound, &mut problem).await;
        assert!(problem.contains("does not exist yet"));
        *fake.vrf.lock().unwrap() = Some("vrf1".into());
        *fake.fail_bind.lock().unwrap() = false;
        l.converge(&mut bound, &mut problem).await;
        assert!(bound.is_some() && problem.is_empty());
    }

    #[tokio::test]
    async fn stopping_a_bound_listener_returns() {
        let (fake, l) = fixture();
        let (mut bound, mut problem) = (None, String::new());
        *fake.wanted.lock().unwrap() = Some(Some(ssh(22)));
        l.converge(&mut bound, &mut problem).await;
        let b = bound.take().unwrap();
        let _ = b.stop.send(true);
        b.task.await.unwrap();
    }

    /// Serves `reply` to every request on `path`, as the daemon `identity` names.
    fn serve<Req, Ev>(path: &Path, identity: &str, reply: impl Fn() -> Ev + Send + Sync + 'static)
    where
        Req: DeserializeOwned + Send + 'static,
        Ev: Serialize + Send + 'static,
    {
        let listener = nos_pki::testing::shared()
            .identity(identity, if identity == "ribd" { "rt1" } else { "" })
            .listen(path)
            .unwrap();
        let reply = std::sync::Arc::new(reply);
        tokio::spawn(async move {
            loop {
                let Ok(conn) = listener.accept().await else {
                    break;
                };
                let Ok((stream, _)) = conn.handshake().await else {
                    continue;
                };
                let reply = reply.clone();
                tokio::spawn(async move {
                    let (r, w) = tokio::io::split(stream);
                    let mut r = FramedRead::new(r, IpcCodec::<Req>::default());
                    let mut w = FramedWrite::new(w, IpcCodec::<Ev>::default());
                    while r.next().await.is_some() && w.send(reply()).await.is_ok() {}
                });
            }
        });
    }

    fn table_with(ssh: Option<SshServer>) -> nos_proto::Config {
        let mut cfg = nos_proto::Config::default();
        cfg.routing_tables.push(nos_proto::RoutingTable {
            name: "rt1".into(),
            ssh_server: ssh,
            ..nos_proto::RoutingTable::default()
        });
        cfg
    }

    #[tokio::test]
    async fn daemons_read_the_table_config_and_the_vrf_name() {
        let d = tempfile::tempdir().unwrap();
        let (cfg_sock, wd_sock, rib_sock) = (
            d.path().join("c.sock"),
            d.path().join("w.sock"),
            d.path().join("r.sock"),
        );
        serve::<nos_proto::Request, _>(&cfg_sock, "configd", || {
            nos_proto::Event::Config(table_with(Some(ssh(22))))
        });
        serve::<nos_proto::WatchdogRequest, _>(&wd_sock, "watchdog", {
            let p = rib_sock.clone();
            move || nos_proto::WatchdogEvent::Endpoint(p.clone())
        });
        serve::<RibRequest, _>(&rib_sock, "ribd", || RibEvent::VrfName(Some("vrf1".into())));
        let src = Daemons {
            table: "rt1".into(),
            watchdog_socket: wd_sock,
            config_socket: cfg_sock,
        };
        assert_eq!(src.wanted().await, Some(Some(ssh(22))));
        assert_eq!(src.vrf_name().await.as_deref(), Some("vrf1"));
        let other = Daemons {
            table: "nope".into(),
            ..src
        };
        assert_eq!(
            other.wanted().await,
            Some(None),
            "unknown table is unpinned"
        );
    }

    #[tokio::test]
    async fn daemons_keep_going_when_the_peers_are_down() {
        let d = tempfile::tempdir().unwrap();
        let src = Daemons {
            table: "rt1".into(),
            watchdog_socket: d.path().join("no-w.sock"),
            config_socket: d.path().join("no-c.sock"),
        };
        assert_eq!(src.wanted().await, None, "unreadable config");
        assert_eq!(src.vrf_name().await, None);
        assert!(config_trigger(&src.config_socket).await.is_none());
    }

    #[tokio::test]
    async fn config_trigger_fires_on_a_diff() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("c.sock");
        serve::<nos_proto::Request, _>(&sock, "configd", || nos_proto::Event::Saved);
        let mut rx = config_trigger(&sock).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .is_some());
    }

    #[test]
    fn linux_binder_reports_no_ifindex_for_a_missing_device() {
        assert_eq!(LinuxBinder.ifindex("no-such-vrf0"), None);
        assert!(LinuxBinder.ifindex("lo").is_some());
    }

    #[tokio::test]
    async fn run_stops_on_shutdown() {
        let (fake, l) = fixture();
        *fake.wanted.lock().unwrap() = Some(Some(ssh(22)));
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(l.run(rx));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(fake.binds.lock().unwrap().len(), 1);
        tx.send(true).unwrap();
        task.await.unwrap();
    }
}
