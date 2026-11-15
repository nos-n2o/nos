//! The single actor that owns the [`Engine`] and every port's BPDU socket.
//!
//! The core is bridge-wide, so one task drives it deterministically: port
//! reader tasks, the link table, plan changes and a 1 s tick all arrive as
//! events on this task, no locks. A changed plan is applied in place when
//! the engine can take it (`Engine::apply_plan`: priority, cost, timers,
//! edge, protections, ports added or removed); anything structural rebuilds
//! the bridge (and the protocol restarts). Sockets of ports that stay are kept.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use nos_l2_socket::L2Socket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use nos_proto::schema::VlanTag;

use crate::bpdu::{decode_frame_any, encode_frame, encode_mst_frame};
use crate::engine::{Engine, Out};
use crate::events;
use crate::identity;
use crate::interface_client::Push;
use crate::link;
use crate::link_client::{gate, Gate, LinkTable};
use crate::ports::Plan;
use crate::pvst::{self, Outs, Pvst, Wire};
use crate::server::{Cmd, Snapshot};
use crate::sstp;
use nos_proto::StpSummary;

const TICK: Duration = Duration::from_secs(1);
/// Seconds between full re-pushes of the kernel port states.
const RESYNC_EVERY: u32 = 10;
/// Seconds between the per-port BPDU receive summaries.
const SUMMARY_EVERY: u32 = 10;

/// A Rapid-PVST+ member: port name, tag, configured cost, link type.
type PvstPort = (String, VlanTag, Option<u32>, nos_proto::schema::LinkType);

/// What the actor needs of one port's BPDU socket: the seam that lets tests
/// drive the daemon without `CAP_NET_RAW` (#346).
trait BpduIo: Send + Sync {
    fn send_frame(&self, frame: &[u8]) -> io::Result<()>;
    fn own_hw_addr(&self) -> [u8; 6];
}

impl BpduIo for L2Socket {
    fn send_frame(&self, frame: &[u8]) -> io::Result<()> {
        L2Socket::send_frame(self, frame)
    }
    fn own_hw_addr(&self) -> [u8; 6] {
        L2Socket::own_hw_addr(self)
    }
}

struct Io {
    socket: Arc<dyn BpduIo>,
    reader: JoinHandle<()>,
}

type Frames = mpsc::Sender<(String, Vec<u8>)>;

/// Opens the BPDU socket of a link (`None`: the IEEE group only, `Some(ieee)`:
/// the SSTP group, plus the IEEE one when `ieee`) and starts the task that
/// forwards its frames to the actor.
type Opener = Arc<dyn Fn(&str, Option<bool>, &Frames) -> io::Result<Io> + Send + Sync>;

/// The production opener: a real raw `AF_PACKET` socket and its reader task.
fn open_l2(name: &str, pvst: Option<bool>, frames: &Frames) -> io::Result<Io> {
    let s = match pvst {
        None => L2Socket::open_bpdu(name)?,
        Some(ieee) => L2Socket::open_pvst(name, ieee)?,
    };
    let socket = Arc::new(s);
    let reader = tokio::spawn(read_loop(socket.clone(), name.to_string(), frames.clone()));
    Ok(Io { socket, reader })
}

/// Which ports `nos-interfaced` holds err-disabled; `None`: unreachable. The
/// test seam of the start-up read-back (#697).
type HeldReader =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Option<HashSet<String>>> + Send>> + Send + Sync>;

#[derive(Default)]
struct PortRt {
    /// Last carrier verdict logged; `None` before the first.
    carrier: Option<bool>,
    /// What the core was last told.
    enabled: bool,
    open_warned: bool,
    rx: u64,
    /// The plan changed in place: tell the core the link's cost/type again.
    resync: bool,
}

struct Daemon {
    mac: [u8; 6],
    plan: Option<Plan>,
    engine: Option<Engine>,
    rt: Vec<PortRt>,
    /// Rapid-PVST+ instead of `engine` (#322): the trees, their per-port
    /// runtime, and which `(tree, port)` each BPDU link serves.
    pvst: Option<Pvst>,
    prt: Vec<Vec<PortRt>>,
    plinks: HashMap<String, (usize, usize)>,
    io: HashMap<String, Io>,
    links: LinkTable,
    push_tx: mpsc::Sender<Push>,
    frames_tx: Frames,
    opener: Opener,
    held_reader: HeldReader,
    ticks: u32,
    /// What `show spanning-tree` serves; refreshed after every event.
    snapshot: Snapshot,
}

pub async fn run(
    watchdog_socket: PathBuf,
    plan_rx: watch::Receiver<Option<Plan>>,
    links_rx: watch::Receiver<LinkTable>,
    push_tx: mpsc::Sender<Push>,
    snapshot: Snapshot,
    cmds: mpsc::Receiver<Cmd>,
    shutdown: watch::Receiver<bool>,
) {
    let held_reader: HeldReader = Arc::new(move || {
        let socket = watchdog_socket.clone();
        Box::pin(async move { crate::interface_client::read_err_disabled(&socket).await })
    });
    run_with(
        Arc::new(open_l2),
        held_reader,
        identity::local_mac(),
        plan_rx,
        links_rx,
        push_tx,
        snapshot,
        cmds,
        shutdown,
    )
    .await;
}

#[allow(clippy::too_many_arguments)] // `run`'s six plus the three test seams
async fn run_with(
    opener: Opener,
    held_reader: HeldReader,
    mac: [u8; 6],
    mut plan_rx: watch::Receiver<Option<Plan>>,
    mut links_rx: watch::Receiver<LinkTable>,
    push_tx: mpsc::Sender<Push>,
    snapshot: Snapshot,
    mut cmds: mpsc::Receiver<Cmd>,
    mut shutdown: watch::Receiver<bool>,
) {
    let (frames_tx, mut frames_rx) = mpsc::channel(256);
    let mut d = Daemon {
        mac,
        plan: None,
        engine: None,
        rt: Vec::new(),
        pvst: None,
        prt: Vec::new(),
        plinks: HashMap::new(),
        io: HashMap::new(),
        links: LinkTable::default(),
        push_tx,
        frames_tx,
        opener,
        held_reader,
        ticks: 0,
        snapshot,
    };
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            r = plan_rx.changed() => {
                if r.is_err() { break }
                let plan = plan_rx.borrow_and_update().clone();
                d.apply_plan(plan).await;
            }
            r = links_rx.changed() => {
                if r.is_err() { break }
                d.links = links_rx.borrow_and_update().clone();
                d.sync_links().await;
            }
            Some((name, frame)) = frames_rx.recv() => d.receive(&name, &frame).await,
            Some(cmd) = cmds.recv() => d.command(cmd).await,
            _ = tick.tick() => d.on_tick().await,
            _ = shutdown.changed() => if *shutdown.borrow() { break },
        }
        d.publish();
    }
    for (_, io) in d.io.drain() {
        io.reader.abort();
    }
    info!("stp engine stopped");
}

/// Forwards every frame of one port to the actor until the socket fails.
async fn read_loop(socket: Arc<L2Socket>, name: String, tx: Frames) {
    loop {
        match socket.recv_frame().await {
            Ok(f) => {
                if tx.send((name.clone(), f)).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                warn!(port = %name, error = %e, "bpdu socket failed");
                return;
            }
        }
    }
}

/// Trees of a Rapid-PVST+ bridge that are not hidden slots.
fn pv_live(pv: Option<&Pvst>) -> usize {
    pv.map_or(0, |p| p.trees().iter().filter(|t| !t.is_gone()).count())
}

impl Daemon {
    /// Disabled mode (no engine) answers `enabled: false`.
    fn publish(&self) {
        let s = match (&self.engine, &self.pvst) {
            (Some(e), _) => e.summary(),
            (None, Some(p)) => p.summary(),
            (None, None) => StpSummary::default(),
        };
        *self.snapshot.write().expect("snapshot lock") = s;
    }

    async fn apply_plan(&mut self, plan: Option<Plan>) {
        if plan == self.plan {
            return;
        }
        if let (Some(pv), Some(p)) = (self.pvst.as_mut(), plan.as_ref())
            && let Ok((out, restarted)) = pv.apply_plan(p)
        {
            self.pvst_updated(&restarted);
            info!(
                trees = pv_live(self.pvst.as_ref()),
                priority = p.priority,
                "{}",
                events::PLAN_UPDATED_IN_PLACE
            );
            self.plan = plan;
            self.emit_pvst(out).await;
            self.sync_links().await;
            return;
        }
        if let (Some(e), Some(p)) = (self.engine.as_mut(), plan.as_ref())
            && let Ok(out) = e.apply_plan(p)
        {
            self.rt.resize_with(e.ports().len(), PortRt::default);
            self.rt.iter_mut().for_each(|r| r.resync = true);
            self.io.retain(|name, io| {
                let keep = p.ports.iter().any(|c| &c.name == name);
                if !keep {
                    io.reader.abort();
                }
                keep
            });
            info!(
                ports = p.ports.len(),
                priority = p.priority,
                "{}",
                events::PLAN_UPDATED_IN_PLACE
            );
            self.plan = plan;
            self.emit(out).await;
            self.sync_links().await;
            return;
        }
        let names: Vec<String> = plan
            .iter()
            .flat_map(|p| match &p.pvst {
                Some(trees) => trees
                    .iter()
                    .flat_map(|t| {
                        t.plan
                            .ports
                            .iter()
                            .zip(&t.tags)
                            .map(|(p, &tag)| pvst::link_name(&p.name, tag))
                    })
                    .collect::<Vec<_>>(),
                None => p.ports.iter().map(|p| p.name.clone()).collect(),
            })
            .collect();
        self.io.retain(|name, io| {
            let keep = names.contains(name);
            if !keep {
                io.reader.abort();
            }
            keep
        });
        self.rt = plan
            .iter()
            .flat_map(|p| p.ports.iter().map(|_| PortRt::default()))
            .collect();
        // A rebuilt bridge must not silently recover err-disabled ports.
        let mut carried = self.engine.as_ref().map_or_default(Engine::err_disabled);
        let numbers = self.engine.as_ref().map_or_default(Engine::numbers);
        let first = self.engine.is_none() && self.pvst.is_none();
        // A fresh start asks `nos-interfaced` which ports it still holds down
        // (#697): they stay down with the full recovery timer; unreachable,
        // nothing is released.
        if first && plan.is_some() {
            if let Some(held) = (self.held_reader)().await {
                carried.extend(held.into_iter().map(|p| (p, None)));
            } else {
                warn!("{}", events::ERR_DISABLED_READ_FAILED);
            }
        }
        self.engine = None;
        self.pvst = None;
        self.prt.clear();
        self.plinks.clear();
        let mut init = Vec::new();
        let mut pvst_init = Vec::new();
        if let Some(p) = &plan {
            info!(
                ports = p.ports.len(),
                priority = p.priority,
                "spanning tree plan applied"
            );
            if p.pvst.is_some() {
                pvst_init = self.build_pvst(p);
            } else {
                match Engine::new_keeping(p, self.mac, &numbers) {
                    Ok((e, out)) => {
                        self.engine = Some(e);
                        init = out;
                    }
                    Err(e) => error!(error = %e, "cannot build the spanning tree bridge"),
                }
            }
        } else {
            info!("spanning tree idle (mode is disabled)");
        }
        let release = |port: String| Out::ErrDisabled {
            port,
            disabled: false,
        };
        for (port, remaining) in carried {
            let kept = self
                .engine
                .as_mut()
                .is_some_and(|e| e.restore_err_disabled(&port, remaining));
            if kept {
                // Seeds the push client's resend cache after a restart.
                if first {
                    init.push(Out::ErrDisabled {
                        port,
                        disabled: true,
                    });
                }
            } else {
                info!(port = %port, "{}", events::PORT_ERR_RECOVERED);
                init.push(release(port));
            }
        }
        self.plan = plan;
        self.emit(init).await;
        self.emit_pvst(pvst_init).await;
        self.sync_links().await;
    }

    /// After `Pvst::apply_plan`: size `prt` to the slots, reset the trees
    /// that got a fresh engine, rebuild the link table from the live slots
    /// and close the sockets nothing uses any more.
    fn pvst_updated(&mut self, restarted: &[usize]) {
        let Some(pv) = self.pvst.as_ref() else { return };
        self.prt.resize_with(pv.trees().len(), Vec::new);
        self.plinks.clear();
        for (t, tree) in pv.trees().iter().enumerate() {
            let n = tree.engine().ports().len();
            if restarted.contains(&t) {
                self.prt[t].clear();
            }
            self.prt[t].resize_with(n, PortRt::default);
            self.prt[t].iter_mut().for_each(|r| r.resync = true);
            if tree.is_gone() {
                continue;
            }
            for (j, (port, &tag)) in tree.engine().ports().iter().zip(&tree.tags).enumerate() {
                if tree.engine().is_live(j) {
                    self.plinks.insert(pvst::link_name(&port.name, tag), (t, j));
                }
            }
        }
        let plinks = &self.plinks;
        self.io.retain(|name, io| {
            let keep = plinks.contains_key(name);
            if !keep {
                io.reader.abort();
            }
            keep
        });
    }

    /// Builds the Rapid-PVST+ trees and the link table of their sockets.
    fn build_pvst(&mut self, p: &Plan) -> Outs {
        let (pv, out) = match Pvst::new(p, self.mac) {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "cannot build the rapid-pvst trees");
                return Vec::new();
            }
        };
        for (t, tree) in pv.trees().iter().enumerate() {
            let ports = tree.engine().ports();
            self.prt
                .push(ports.iter().map(|_| PortRt::default()).collect());
            for (j, (port, &tag)) in ports.iter().zip(&tree.tags).enumerate() {
                self.plinks.insert(pvst::link_name(&port.name, tag), (t, j));
            }
        }
        self.pvst = Some(pv);
        out
    }

    /// Opens missing sockets and tells the core each port's `portEnabled`,
    /// `operPointToPoint` and cost when they changed.
    async fn sync_links(&mut self) {
        if self.pvst.is_some() {
            return self.sync_pvst_links().await;
        }
        let Some(n) = self.engine.as_ref().map(|e| e.ports().len()) else {
            return;
        };
        for i in 0..n {
            let engine = self.engine.as_ref().expect("checked");
            if !engine.is_live(i) {
                continue;
            }
            let cfg = engine.ports()[i].clone();
            let g = gate(&self.links, &cfg.name);
            let carrier = !matches!(g, Gate::Down(_));
            if self.rt[i].carrier != Some(carrier) {
                if carrier {
                    info!(port = %cfg.name, "port carrier up");
                } else {
                    info!(port = %cfg.name, "port carrier lost");
                }
            }
            if carrier {
                self.ensure_io(i, &cfg.name);
            }
            let enabled = carrier && self.io.contains_key(&cfg.name);
            if self.rt[i].carrier == Some(carrier)
                && self.rt[i].enabled == enabled
                && !self.rt[i].resync
            {
                continue;
            }
            self.rt[i].carrier = Some(carrier);
            self.rt[i].enabled = enabled;
            self.rt[i].resync = false;
            let info = link::read(&cfg.name);
            if enabled && info.speed_mbps.is_none() {
                warn!(port = %cfg.name, fallback_mbps = link::FALLBACK_SPEED_MBPS, "link speed unknown, using the fallback cost");
            }
            let out = self.engine.as_mut().expect("checked").set_link(
                i,
                enabled,
                link::point_to_point(cfg.link_type, info),
                link::path_cost(cfg.cost, info),
            );
            self.emit(out).await;
        }
    }

    fn ensure_io(&mut self, i: usize, name: &str) {
        let mut warned = self.rt[i].open_warned;
        self.open_io(name, None, &mut warned);
        self.rt[i].open_warned = warned;
    }

    /// Opens the BPDU socket of link `name` unless it is open: the IEEE group
    /// only (`None`), or the SSTP group with (`Some(true)`) or without the
    /// IEEE group. `warned` limits the failure log to once per outage.
    fn open_io(&mut self, name: &str, pvst: Option<bool>, warned: &mut bool) {
        if self.io.get(name).is_some_and(|io| io.reader.is_finished()) {
            self.io.remove(name);
        }
        if self.io.contains_key(name) {
            return;
        }
        match (self.opener)(name, pvst, &self.frames_tx) {
            Ok(io) => {
                self.io.insert(name.to_string(), io);
                *warned = false;
                info!(port = %name, "bpdu socket open");
            }
            Err(e) => {
                if !*warned {
                    warn!(port = %name, error = %e, "cannot open the bpdu socket, will retry");
                }
                *warned = true;
            }
        }
    }

    /// `sync_links` for Rapid-PVST+: every `(tree, port)` rides its own link
    /// (the sub-link of a tagged member), so carrier is per link.
    async fn sync_pvst_links(&mut self) {
        let Some(pv) = self.pvst.as_ref() else { return };
        // A gone tree or port keeps its slot but is skipped (`None`).
        let shape: Vec<Vec<Option<PvstPort>>> = pv
            .trees()
            .iter()
            .map(|t| {
                t.engine()
                    .ports()
                    .iter()
                    .zip(&t.tags)
                    .enumerate()
                    .map(|(j, (p, &tag))| {
                        (!t.is_gone() && t.engine().is_live(j))
                            .then(|| (p.name.clone(), tag, p.cost, p.link_type))
                    })
                    .collect()
            })
            .collect();
        for (t, ports) in shape.into_iter().enumerate() {
            for (j, slot) in ports.into_iter().enumerate() {
                let Some((port, tag, cost, link_type)) = slot else {
                    continue;
                };
                let link = pvst::link_name(&port, tag);
                let carrier = !matches!(gate(&self.links, &link), Gate::Down(_));
                if self.prt[t][j].carrier != Some(carrier) {
                    if carrier {
                        info!(port = %link, "port carrier up");
                    } else {
                        info!(port = %link, "port carrier lost");
                    }
                }
                if carrier {
                    let mut warned = self.prt[t][j].open_warned;
                    self.open_io(&link, Some(tag == VlanTag::Untagged), &mut warned);
                    self.prt[t][j].open_warned = warned;
                }
                let enabled = carrier && self.io.contains_key(&link);
                if self.prt[t][j].carrier == Some(carrier)
                    && self.prt[t][j].enabled == enabled
                    && !self.prt[t][j].resync
                {
                    continue;
                }
                self.prt[t][j].carrier = Some(carrier);
                self.prt[t][j].enabled = enabled;
                self.prt[t][j].resync = false;
                let info = link::read(&port);
                if enabled && info.speed_mbps.is_none() {
                    warn!(port = %port, fallback_mbps = link::FALLBACK_SPEED_MBPS, "link speed unknown, using the fallback cost");
                }
                let out = self.pvst.as_mut().expect("checked").set_link(
                    t,
                    j,
                    enabled,
                    link::point_to_point(link_type, info),
                    link::path_cost(cost, info),
                );
                self.emit_pvst(out).await;
            }
        }
    }

    /// A frame of a Rapid-PVST+ link: SSTP (any member) or the IEEE group
    /// (the native member only).
    async fn receive_pvst(&mut self, name: &str, frame: &[u8]) {
        let Some(&(t, j)) = self.plinks.get(name) else {
            return;
        };
        let Some(pv) = self.pvst.as_mut() else { return };
        let tag = pv.trees()[t].tags[j];
        let (bpdu, pvid, wire) = if frame.starts_with(&sstp::SSTP_GROUP_MAC) {
            match sstp::decode_frame(frame) {
                Ok((_, s)) => (s.bpdu, s.pvid, Wire::Sstp),
                Err(e) => {
                    pv.note_invalid(t, j);
                    return debug!(port = %name, error = %e, "dropping malformed sstp bpdu");
                }
            }
        } else {
            match crate::bpdu::decode_frame(frame) {
                Ok((_, b)) => (b, None, Wire::Ieee),
                Err(e) => {
                    pv.note_invalid(t, j);
                    return debug!(port = %name, error = %e, "dropping malformed bpdu");
                }
            }
        };
        if !pvst::accepts(tag, wire) {
            return;
        }
        self.prt[t][j].rx += 1;
        let out = pv.receive(t, j, bpdu, pvid);
        self.emit_pvst(out).await;
    }

    async fn receive(&mut self, name: &str, frame: &[u8]) {
        if self.pvst.is_some() {
            return self.receive_pvst(name, frame).await;
        }
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        let Some(i) = engine.live_slot(name) else {
            return;
        };
        self.rt[i].rx += 1;
        match decode_frame_any(frame) {
            Ok((_, rx)) => {
                let out = engine.receive_rx(i, rx);
                self.emit(out).await;
            }
            Err(e) => {
                engine.note_invalid(i);
                debug!(port = %name, error = %e, "dropping malformed bpdu");
            }
        }
    }

    async fn command(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Mcheck { interface, reply } => {
                let Some(engine) = self.engine.as_mut() else {
                    let _ = reply.send(0);
                    return;
                };
                let (ports, out) = engine.mcheck(interface.as_deref());
                info!(ports, "mcheck requested");
                let _ = reply.send(ports);
                self.emit(out).await;
            }
            Cmd::ClearErrDisabled { interface, reply } => {
                let Some(engine) = self.engine.as_mut() else {
                    let _ = reply.send(false);
                    return;
                };
                let (cleared, out) = engine.clear_err_disabled(&interface);
                let _ = reply.send(cleared);
                self.emit(out).await;
            }
        }
    }

    async fn on_tick(&mut self) {
        if let Some(pv) = self.pvst.as_mut() {
            let out = pv.tick();
            self.emit_pvst(out).await;
            self.ticks += 1;
            if self.ticks.is_multiple_of(RESYNC_EVERY)
                && let Some(pv) = &self.pvst
            {
                let out = pv.all_states();
                self.emit_pvst(out).await;
            }
            return self.sync_links().await;
        }
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        let out = engine.tick();
        self.emit(out).await;
        self.ticks += 1;
        // ponytail: a full re-push every RESYNC_EVERY seconds heals a state
        // that a concurrent `nos-interfaced` resync overwrote with a stale one
        // (seen after a plan rebuild); upgrade path is an ack from interfaced.
        if self.ticks.is_multiple_of(RESYNC_EVERY)
            && let Some(e) = &self.engine
        {
            let out = e.all_states();
            self.emit(out).await;
        }
        if self.ticks.is_multiple_of(SUMMARY_EVERY)
            && let Some(e) = &self.engine
        {
            for (p, rt) in e.ports().iter().zip(self.rt.iter_mut()) {
                if rt.enabled {
                    info!(port = %p.name, count = rt.rx, "bpdu rx");
                }
                rt.rx = 0;
            }
        }
        // Retries a failed socket open and notices a finished reader.
        self.sync_links().await;
    }

    /// The outputs of Rapid-PVST+ trees: BPDUs go out on the member's link,
    /// the rest is tree-independent.
    async fn emit_pvst(&mut self, outs: Outs) {
        for (t, out) in outs {
            match out {
                Out::Tx { port, bpdu } => {
                    let Some(pv) = self.pvst.as_ref() else {
                        continue;
                    };
                    let tree = &pv.trees()[t];
                    let tag = tree.tags[port];
                    let link = pvst::link_name(&tree.engine().ports()[port].name, tag);
                    let Some(io) = self.io.get(&link) else {
                        continue;
                    };
                    let src = io.socket.own_hw_addr();
                    for wire in pvst::tx_wires(tag) {
                        let frame = match wire {
                            Wire::Sstp => sstp::encode_frame(src, &bpdu, tree.vid),
                            Wire::Ieee => encode_frame(src, &bpdu),
                        };
                        match io.socket.send_frame(&frame) {
                            Err(e) if !nos_l2_socket::is_link_down(&e) => {
                                warn!(port = %link, error = %e, "bpdu send failed");
                            }
                            _ => {}
                        }
                    }
                }
                other => self.emit(vec![other]).await,
            }
        }
    }

    async fn emit(&mut self, outs: Vec<Out>) {
        for out in outs {
            match out {
                Out::Tx { port, bpdu } => {
                    let name = &self
                        .engine
                        .as_ref()
                        .expect("outputs imply an engine")
                        .ports()[port]
                        .name;
                    if let Some(io) = self.io.get(name) {
                        let frame = encode_frame(io.socket.own_hw_addr(), &bpdu);
                        match io.socket.send_frame(&frame) {
                            Err(e) if !nos_l2_socket::is_link_down(&e) => {
                                warn!(port = %name, error = %e, "bpdu send failed");
                            }
                            _ => {}
                        }
                    }
                }
                Out::TxMst { port, bpdu } => {
                    let name = &self
                        .engine
                        .as_ref()
                        .expect("outputs imply an engine")
                        .ports()[port]
                        .name;
                    if let Some(io) = self.io.get(name) {
                        let frame = encode_mst_frame(io.socket.own_hw_addr(), &bpdu);
                        match io.socket.send_frame(&frame) {
                            Err(e) if !nos_l2_socket::is_link_down(&e) => {
                                warn!(port = %name, error = %e, "bpdu send failed");
                            }
                            _ => {}
                        }
                    }
                }
                Out::States(list) => {
                    let _ = self.push_tx.send(Push::States(list)).await;
                }
                Out::Flush(list) => {
                    let _ = self.push_tx.send(Push::Flush(list)).await;
                }
                Out::ErrDisabled { port, disabled } => {
                    let _ = self
                        .push_tx
                        .send(Push::ErrDisabled { port, disabled })
                        .await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
