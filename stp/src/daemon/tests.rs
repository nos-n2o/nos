use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};

use nos_proto::schema::{EdgePort, LinkType};
use nos_proto::LinkState;
use tokio::sync::oneshot;

use super::*;
use crate::bpdu::Bpdu;
use crate::machines::Protections;
use crate::mst::MstPlan;
use crate::ports::PortCfg;
use crate::timers::Timers;

const OWN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 9];
/// A lower MAC than ours: the peer wins the root election.
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const OWN_HW: [u8; 6] = [0xaa; 6];
const ENETDOWN: i32 = 100;
const EIO: i32 = 5;

/// A socket that records every frame handed to it and can be told to fail.
#[derive(Default)]
struct FakeIo {
    sent: Mutex<Vec<Vec<u8>>>,
    fail_with: Mutex<Option<i32>>,
}

impl BpduIo for FakeIo {
    fn send_frame(&self, frame: &[u8]) -> io::Result<()> {
        self.sent.lock().unwrap().push(frame.to_vec());
        match *self.fail_with.lock().unwrap() {
            Some(code) => Err(io::Error::from_raw_os_error(code)),
            None => Ok(()),
        }
    }
    fn own_hw_addr(&self) -> [u8; 6] {
        OWN_HW
    }
}

type Opens = Arc<Mutex<Vec<(String, Option<bool>)>>>;
type Ios = Arc<Mutex<HashMap<String, Arc<FakeIo>>>>;

/// The injectable opener and what it did.
#[derive(Clone, Default)]
struct Fakes {
    ios: Ios,
    opens: Opens,
    deny: Arc<AtomicBool>,
    short_lived: Arc<AtomicBool>,
    /// What the interfaced read-back answers; `unreachable` makes it `None`.
    held: Arc<Mutex<Vec<String>>>,
    unreachable: Arc<AtomicBool>,
}

impl Fakes {
    fn opener(&self) -> Opener {
        let f = self.clone();
        Arc::new(move |name, pvst, _frames| {
            f.opens.lock().unwrap().push((name.to_string(), pvst));
            if f.deny.load(Ordering::SeqCst) {
                return Err(io::Error::other("no CAP_NET_RAW"));
            }
            let socket = f
                .ios
                .lock()
                .unwrap()
                .entry(name.to_string())
                .or_default()
                .clone();
            let reader = if f.short_lived.load(Ordering::SeqCst) {
                tokio::spawn(async {})
            } else {
                tokio::spawn(std::future::pending())
            };
            Ok(Io { socket, reader })
        })
    }
    fn held_reader(&self) -> HeldReader {
        let f = self.clone();
        Arc::new(move || {
            let f = f.clone();
            Box::pin(async move {
                (!f.unreachable.load(Ordering::SeqCst))
                    .then(|| f.held.lock().unwrap().iter().cloned().collect())
            })
        })
    }
    fn io(&self, name: &str) -> Arc<FakeIo> {
        self.ios.lock().unwrap().get(name).cloned().expect("opened")
    }
    fn sent(&self, name: &str) -> Vec<Vec<u8>> {
        self.io(name).sent.lock().unwrap().clone()
    }
    fn opened(&self) -> usize {
        self.opens.lock().unwrap().len()
    }
}

struct Lab {
    d: Daemon,
    fakes: Fakes,
    push_rx: mpsc::Receiver<Push>,
    _keep_frames: mpsc::Receiver<(String, Vec<u8>)>,
}

impl Lab {
    fn new() -> Self {
        let fakes = Fakes::default();
        let (push_tx, push_rx) = mpsc::channel(256);
        let (frames_tx, frames_rx) = mpsc::channel(8);
        let d = Daemon {
            mac: OWN_MAC,
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
            opener: fakes.opener(),
            held_reader: fakes.held_reader(),
            ticks: 0,
            snapshot: Arc::new(RwLock::new(StpSummary::default())),
        };
        Lab {
            d,
            fakes,
            push_rx,
            _keep_frames: frames_rx,
        }
    }

    fn pushes(&mut self) -> Vec<Push> {
        std::iter::from_fn(|| self.push_rx.try_recv().ok()).collect()
    }

    fn summary(&self) -> StpSummary {
        self.d.publish();
        self.d.snapshot.read().unwrap().clone()
    }

    fn engine_counters(&self, port: usize) -> nos_proto::StpPortCounters {
        self.d.engine.as_ref().unwrap().summary().ports[port].counters
    }

    fn pvst_counters(&self, t: usize, port: usize) -> nos_proto::StpPortCounters {
        self.d.pvst.as_ref().unwrap().trees()[t]
            .engine()
            .summary()
            .ports[port]
            .counters
    }
}

fn port(name: &str, prot: Protections, edge: EdgePort) -> PortCfg {
    PortCfg {
        name: name.into(),
        domains: vec!["d1".into()],
        priority: 128,
        cost: None,
        edge,
        link_type: LinkType::Auto,
        prot,
        mst: Vec::new(),
        members: Vec::new(),
    }
}

fn plan(names: &[&str]) -> Plan {
    Plan {
        priority: 32768,
        rstp_version: true,
        timers: Timers::default(),
        ports: names
            .iter()
            .map(|n| port(n, Protections::default(), EdgePort::Disabled))
            .collect(),
        mst: None,
        ext: 0,
        domain: None,
        pvst: None,
    }
}

fn table(links: &[(&str, bool)]) -> LinkTable {
    LinkTable {
        snapshot: true,
        observed: true,
        links: links
            .iter()
            .map(|&(n, up)| {
                (
                    n.to_string(),
                    LinkState {
                        name: n.into(),
                        ifindex: 1,
                        admin_up: true,
                        carrier: up,
                        port_aggregate: None,
                    },
                )
            })
            .collect(),
    }
}

fn first_tx(outs: Vec<Out>) -> Bpdu {
    outs.into_iter()
        .find_map(|o| match o {
            Out::Tx { bpdu, .. } => Some(bpdu),
            _ => None,
        })
        .expect("a transmit")
}

/// A Config/RST frame from a peer bridge that out-ranks us.
fn peer_frame(p: &Plan) -> Vec<u8> {
    let (mut e, _) = Engine::new(p, PEER_MAC).unwrap();
    encode_frame(PEER_MAC, &first_tx(e.set_link(0, true, true, 20_000)))
}

fn is_states(p: &Push) -> bool {
    matches!(p, Push::States(_))
}

#[tokio::test]
async fn plan_lifecycle_builds_rebuilds_and_drops_the_engine() {
    let mut l = Lab::new();
    l.d.apply_plan(None).await;
    assert!(l.pushes().is_empty(), "no plan, no change");

    let p = plan(&["eth1", "eth2"]);
    l.d.apply_plan(Some(p.clone())).await;
    assert!(l.d.engine.is_some());
    assert!(l.pushes().iter().any(is_states), "initial states pushed");
    assert_eq!(l.fakes.opened(), 2, "ungated: both sockets open");
    assert!(!l.fakes.sent("eth1").is_empty(), "set_link announces");
    assert!(l.summary().enabled);

    l.d.apply_plan(Some(p)).await;
    assert!(l.pushes().is_empty(), "the same plan is a no-op");
    assert_eq!(l.fakes.opened(), 2);

    l.d.apply_plan(Some(plan(&["eth1"]))).await;
    assert_eq!(l.d.io.keys().collect::<Vec<_>>(), ["eth1"]);

    l.d.apply_plan(None).await;
    assert!(l.d.engine.is_none() && l.d.io.is_empty());
    assert_eq!(l.summary(), StpSummary::default());
}

#[tokio::test]
async fn an_invalid_plan_leaves_no_engine() {
    let mut l = Lab::new();
    let mut p = plan(&["eth1"]);
    p.priority = 1;
    l.d.apply_plan(Some(p)).await;
    assert!(l.d.engine.is_none());
    assert_eq!(l.summary(), StpSummary::default());
}

#[tokio::test]
async fn err_disabled_ports_survive_a_rebuild_and_release_when_dropped() {
    let mut l = Lab::new();
    let mut p = plan(&["eth1", "eth2"]);
    p.ports[0].prot.bpdu_guard = true;
    p.ports[0].edge = EdgePort::Admin;
    let released = |pushes: &[Push]| {
        pushes
            .iter()
            .filter(|x| matches!(x, Push::ErrDisabled { port, disabled: false } if port == "eth1"))
            .count()
    };

    l.d.apply_plan(Some(p.clone())).await;
    assert_eq!(released(&l.pushes()), 0, "nothing held, nothing released");

    l.d.receive("eth1", &peer_frame(&plan(&["eth1"]))).await;
    assert!(l
        .pushes()
        .iter()
        .any(|x| matches!(x, Push::ErrDisabled { disabled: true, .. })));

    let mut rebuilt = p.clone();
    rebuilt.priority = 4096;
    l.d.apply_plan(Some(rebuilt)).await;
    assert_eq!(released(&l.pushes()), 0, "kept: restored, not released");
    assert_eq!(l.d.engine.as_ref().unwrap().err_disabled().len(), 1);

    l.d.apply_plan(Some(plan(&["eth2"]))).await;
    assert_eq!(released(&l.pushes()), 1, "dropped: released");
}

fn guarded_plan() -> Plan {
    let mut p = plan(&["eth1", "eth2"]);
    p.ports[0].prot.bpdu_guard = true;
    p.ports[0].prot.recovery = Some(300);
    p.ports[0].edge = EdgePort::Admin;
    p
}

fn err_pushes(pushes: &[Push], disabled_flag: bool, name: &str) -> usize {
    pushes
        .iter()
        .filter(|x| matches!(x, Push::ErrDisabled { port, disabled } if port == name && *disabled == disabled_flag))
        .count()
}

#[tokio::test]
async fn a_restart_keeps_held_guarded_ports_down_with_the_full_timer() {
    let mut l = Lab::new();
    *l.fakes.held.lock().unwrap() = vec!["eth1".into(), "eth2".into(), "gone".into()];
    l.d.apply_plan(Some(guarded_plan())).await;
    let pushes = l.pushes();
    assert_eq!(err_pushes(&pushes, false, "eth1"), 0, "stays down");
    assert_eq!(err_pushes(&pushes, true, "eth1"), 1, "cache seeded");
    assert_eq!(
        l.d.engine.as_ref().unwrap().err_disabled(),
        [("eth1".to_string(), Some(300))]
    );
    // Held but unguarded or gone from the plan: released.
    assert_eq!(err_pushes(&pushes, false, "eth2"), 1);
    assert_eq!(err_pushes(&pushes, false, "gone"), 1);
}

#[tokio::test]
async fn an_unreachable_interfaced_releases_nothing() {
    let mut l = Lab::new();
    l.fakes.unreachable.store(true, Ordering::SeqCst);
    *l.fakes.held.lock().unwrap() = vec!["eth1".into()];
    l.d.apply_plan(Some(guarded_plan())).await;
    assert!(!l
        .pushes()
        .iter()
        .any(|x| matches!(x, Push::ErrDisabled { .. })));
    assert_eq!(
        l.d.engine.as_ref().unwrap().err_disabled(),
        [] as [(std::string::String, std::option::Option<u32>); 0]
    );
}

#[tokio::test]
async fn sync_links_follows_carrier_and_toggles_once() {
    let mut l = Lab::new();
    l.d.links = table(&[("eth1", true), ("eth2", false)]);
    l.d.apply_plan(Some(plan(&["eth1", "eth2"]))).await;
    assert_eq!(l.fakes.opened(), 1, "only the link with carrier opens");
    assert!(l.d.rt[0].enabled && !l.d.rt[1].enabled);
    assert_eq!(l.d.rt[1].carrier, Some(false));
    l.pushes();

    l.d.sync_links().await;
    assert!(l.pushes().is_empty(), "unchanged table, nothing to tell");

    l.d.links = table(&[("eth1", false), ("eth2", false)]);
    l.d.sync_links().await;
    assert!(!l.d.rt[0].enabled);
    assert!(l.d.io.contains_key("eth1"), "the socket is kept");

    l.d.links = table(&[("eth1", true), ("eth2", false)]);
    l.d.sync_links().await;
    assert!(l.d.rt[0].enabled);
    assert_eq!(l.fakes.opened(), 1, "reopened never: the socket stayed");
}

#[tokio::test]
async fn an_open_failure_is_warned_once_and_retried() {
    let mut l = Lab::new();
    l.fakes.deny.store(true, Ordering::SeqCst);
    l.d.apply_plan(Some(plan(&["eth1"]))).await;
    assert!(l.d.rt[0].open_warned && !l.d.rt[0].enabled);
    l.d.on_tick().await;
    assert!(l.d.rt[0].open_warned);
    assert_eq!(l.fakes.opened(), 2, "retried on the next tick");

    l.fakes.deny.store(false, Ordering::SeqCst);
    l.d.on_tick().await;
    assert!(!l.d.rt[0].open_warned && l.d.rt[0].enabled);
}

#[tokio::test]
async fn a_finished_reader_is_replaced() {
    let mut l = Lab::new();
    l.fakes.short_lived.store(true, Ordering::SeqCst);
    l.d.apply_plan(Some(plan(&["eth1"]))).await;
    tokio::task::yield_now().await;
    l.d.sync_links().await;
    assert_eq!(l.fakes.opened(), 2);
}

#[tokio::test]
async fn receive_feeds_the_engine_and_counts_malformed_frames() {
    let mut l = Lab::new();
    let p = plan(&["eth1"]);
    l.d.receive("eth1", &peer_frame(&p)).await;
    assert!(l.d.engine.is_none(), "no engine: ignored");

    l.d.apply_plan(Some(p.clone())).await;
    l.d.receive("nope", &peer_frame(&p)).await;
    assert_eq!(l.d.rt[0].rx, 0, "unknown port ignored");

    l.d.receive("eth1", &peer_frame(&p)).await;
    assert_eq!(l.d.rt[0].rx, 1);
    assert_eq!(l.engine_counters(0).invalid_bpdu, 0);

    l.d.receive("eth1", &[0u8; 20]).await;
    assert_eq!(l.engine_counters(0).invalid_bpdu, 1);
    assert_eq!(l.d.rt[0].rx, 2);
}

#[tokio::test]
async fn commands_answer_with_and_without_an_engine() {
    let mut l = Lab::new();
    let mcheck = |interface: Option<&str>| {
        let (reply, rx) = oneshot::channel();
        (
            Cmd::Mcheck {
                interface: interface.map(str::to_string),
                reply,
            },
            rx,
        )
    };
    let clear = |interface: &str| {
        let (reply, rx) = oneshot::channel();
        (
            Cmd::ClearErrDisabled {
                interface: interface.into(),
                reply,
            },
            rx,
        )
    };
    let (c, rx) = mcheck(None);
    l.d.command(c).await;
    assert_eq!(rx.await.unwrap(), 0);
    let (c, rx) = clear("eth1");
    l.d.command(c).await;
    assert!(!rx.await.unwrap());

    l.d.apply_plan(Some(plan(&["eth1", "eth2"]))).await;
    let (c, rx) = mcheck(None);
    l.d.command(c).await;
    assert_eq!(rx.await.unwrap(), 2);
    let (c, rx) = mcheck(Some("eth2"));
    l.d.command(c).await;
    assert_eq!(rx.await.unwrap(), 1);
    let (c, rx) = clear("eth1");
    l.d.command(c).await;
    assert!(!rx.await.unwrap(), "not err-disabled");
}

#[tokio::test]
async fn ticks_repush_states_and_reset_the_rx_summary() {
    let mut l = Lab::new();
    l.d.on_tick().await;
    assert_eq!(l.d.ticks, 0, "no engine: a no-op");

    l.d.apply_plan(Some(plan(&["eth1"]))).await;
    l.pushes();
    l.d.rt[0].rx = 7;
    for _ in 0..9 {
        l.d.on_tick().await;
    }
    l.pushes();
    assert_eq!(l.d.rt[0].rx, 7);
    l.d.on_tick().await;
    assert!(l.pushes().iter().any(is_states), "full re-push");
    assert_eq!(l.d.rt[0].rx, 0, "summary logged and reset");
}

#[tokio::test]
async fn emit_writes_the_right_frame_and_survives_send_errors() {
    let mut l = Lab::new();
    let p = plan(&["eth1", "eth2"]);
    l.d.apply_plan(Some(p.clone())).await;
    l.pushes();
    let (mut peer, _) = Engine::new(&p, PEER_MAC).unwrap();
    let bpdu = first_tx(peer.set_link(0, true, true, 1));
    let before = l.fakes.sent("eth2").len();
    l.d.emit(vec![Out::Tx { port: 1, bpdu }]).await;
    let sent = l.fakes.sent("eth2");
    assert_eq!(sent.len(), before + 1);
    assert_eq!(sent.last().unwrap(), &encode_frame(OWN_HW, &bpdu));

    for code in [ENETDOWN, EIO] {
        *l.fakes.io("eth2").fail_with.lock().unwrap() = Some(code);
        l.d.emit(vec![Out::Tx { port: 1, bpdu }]).await;
    }
    assert_eq!(
        l.fakes.sent("eth2").len(),
        before + 3,
        "attempted, not fatal"
    );

    l.d.io.remove("eth2");
    l.d.emit(vec![Out::Tx { port: 1, bpdu }]).await;
    assert_eq!(l.fakes.sent("eth2").len(), before + 3, "no socket, skipped");

    l.d.emit(vec![
        Out::Flush(vec![("eth1".into(), "d1".into())]),
        Out::States(vec![]),
        Out::ErrDisabled {
            port: "eth1".into(),
            disabled: true,
        },
    ])
    .await;
    let kinds: Vec<_> = l.pushes().iter().map(|p| format!("{p:?}")).collect();
    assert!(kinds[0].starts_with("Flush") && kinds[1].starts_with("States"));
    assert!(kinds[2].starts_with("ErrDisabled"));
}

#[tokio::test]
async fn mstp_ports_send_and_receive_version_3_frames() {
    let mut p = plan(&["eth1"]);
    p.mst = Some(MstPlan {
        name: "r1".into(),
        revision: 1,
        digest: [0; 16],
        max_hops: 20,
        instances: vec![],
        domains: vec![],
    });
    let mut l = Lab::new();
    l.d.apply_plan(Some(p.clone())).await;
    let frames = l.fakes.sent("eth1");
    assert!(
        frames.iter().any(|f| decode_frame_any(f).is_ok()),
        "a v3 BPDU went out"
    );

    let (mut peer, _) = Engine::new(&p, PEER_MAC).unwrap();
    let Some(Out::TxMst { bpdu, .. }) = peer
        .set_link(0, true, true, 20_000)
        .into_iter()
        .find(|o| matches!(o, Out::TxMst { .. }))
    else {
        panic!("an mstp peer transmits version 3");
    };
    l.d.receive("eth1", &encode_mst_frame(PEER_MAC, &bpdu))
        .await;
    assert_eq!(l.d.rt[0].rx, 1);
    assert_eq!(l.engine_counters(0).in_mst_bpdu, 1);
}

fn pvst_plan() -> Plan {
    crate::pvst::tests::plan([32768, 32768], [[None; 2]; 2])
}

/// Tree 0 untagged (the native VLAN), tree 1 tagged.
fn native_pvst_plan() -> Plan {
    let mut p = pvst_plan();
    p.pvst.as_mut().unwrap()[0].tags = vec![VlanTag::Untagged; 2];
    p
}

fn pvst_peer_bpdu(p: &Plan) -> Bpdu {
    let (mut pv, _) = Pvst::new(p, PEER_MAC).unwrap();
    pv.set_link(0, 0, true, true, 20_000)
        .into_iter()
        .find_map(|(_, o)| match o {
            Out::Tx { bpdu, .. } => Some(bpdu),
            _ => None,
        })
        .expect("a transmit")
}

#[tokio::test]
async fn pvst_tagged_members_ride_sub_links_and_speak_sstp_only() {
    let mut l = Lab::new();
    let p = pvst_plan();
    l.d.apply_plan(Some(p.clone())).await;
    assert!(l.d.engine.is_none() && l.d.pvst.is_some());
    assert_eq!(l.d.plinks.len(), 4);
    assert!(l
        .fakes
        .opens
        .lock()
        .unwrap()
        .iter()
        .all(|(n, ieee)| n.contains('.') && *ieee == Some(false)));
    let sent = l.fakes.sent("eth1.10");
    assert_ne!(sent.len(), 0, "the port announced itself");
    assert!(sent.iter().all(|f| f.starts_with(&sstp::SSTP_GROUP_MAC)));
    assert!(l.summary().enabled);

    let bpdu = pvst_peer_bpdu(&p);
    let sstp_frame = sstp::encode_frame(PEER_MAC, &bpdu, 10);
    l.d.receive("eth1.10", &sstp_frame).await;
    assert_eq!(l.d.prt[0][0].rx, 1);

    l.d.receive("eth1.10", &encode_frame(PEER_MAC, &bpdu)).await;
    assert_eq!(l.d.prt[0][0].rx, 1, "IEEE on a tagged member is dropped");

    l.d.receive("nope.10", &sstp_frame).await;
    let mut bad = sstp::SSTP_GROUP_MAC.to_vec();
    bad.extend_from_slice(&[0; 20]);
    l.d.receive("eth1.10", &bad).await;
    l.d.receive("eth1.10", &[0u8; 20]).await;
    assert_eq!(l.pvst_counters(0, 0).invalid_bpdu, 2);
}

#[tokio::test]
async fn pvst_native_member_speaks_both_wires_and_accepts_ieee() {
    let mut l = Lab::new();
    let p = native_pvst_plan();
    l.d.apply_plan(Some(p.clone())).await;
    assert!(l
        .fakes
        .opens
        .lock()
        .unwrap()
        .contains(&("eth1".to_string(), Some(true))));
    let sent = l.fakes.sent("eth1");
    assert!(sent.iter().any(|f| f.starts_with(&sstp::SSTP_GROUP_MAC)));
    assert!(sent
        .iter()
        .any(|f| f.starts_with(&crate::bpdu::STP_GROUP_MAC)));

    l.d.receive("eth1", &encode_frame(PEER_MAC, &pvst_peer_bpdu(&p)))
        .await;
    assert_eq!(l.d.prt[0][0].rx, 1);
}

#[tokio::test]
async fn pvst_ticks_resync_every_ten_seconds_and_follow_links() {
    let mut l = Lab::new();
    l.d.links = table(&[("eth1.10", true), ("eth2.10", false)]);
    l.d.apply_plan(Some(pvst_plan())).await;
    assert!(l.d.prt[0][0].enabled && !l.d.prt[0][1].enabled);
    l.pushes();
    for _ in 0..9 {
        l.d.on_tick().await;
    }
    l.pushes();
    l.d.on_tick().await;
    assert_eq!(l.d.ticks, 10);
    assert!(l.pushes().iter().any(is_states));

    let (reply, rx) = oneshot::channel();
    l.d.command(Cmd::Mcheck {
        interface: None,
        reply,
    })
    .await;
    assert_eq!(rx.await.unwrap(), 0, "mcheck is a classic-mode command");
}

#[tokio::test]
async fn pvst_plan_edit_in_place_keeps_the_other_trees_sockets() {
    let mut l = Lab::new();
    l.d.links = table(&[
        ("eth1.10", true),
        ("eth2.10", true),
        ("eth1.20", true),
        ("eth2.20", true),
        ("eth1", true),
        ("eth2", true),
    ]);
    let p = pvst_plan();
    l.d.apply_plan(Some(p.clone())).await;
    let opened = l.fakes.opened();
    assert_eq!(opened, 4);
    // bd1's priority is edited in place: nothing reopens.
    let mut q = p.clone();
    q.pvst.as_mut().unwrap()[0].plan.priority = 4096;
    l.d.apply_plan(Some(q.clone())).await;
    assert_eq!(l.fakes.opened(), opened);
    assert!(l.d.prt[1][0].enabled, "bd2 untouched");
    // Remove bd2: its sockets close, bd1's stay.
    q.pvst.as_mut().unwrap().remove(1);
    l.d.apply_plan(Some(q.clone())).await;
    assert_eq!(l.fakes.opened(), opened);
    assert_eq!(l.d.plinks.len(), 2);
    assert_eq!(l.d.io.len(), 2);
    assert_eq!(l.summary().pvst.len(), 1);
    // A tag change on bd1 restarts that tree only and opens its new links.
    q.pvst.as_mut().unwrap()[0].tags = vec![VlanTag::Untagged; 2];
    l.d.apply_plan(Some(q)).await;
    assert!(l.d.plinks.contains_key("eth1") && !l.d.plinks.contains_key("eth1.10"));
    assert_eq!(l.d.io.len(), 2);
    assert_eq!(l.fakes.opened(), opened + 2);
    assert!(l.d.prt[0][0].enabled);
}

#[tokio::test(start_paused = true)]
async fn run_with_applies_plans_serves_commands_and_stops() {
    let fakes = Fakes::default();
    let (plan_tx, plan_rx) = watch::channel(None);
    let (links_tx, links_rx) = watch::channel(LinkTable::default());
    let (push_tx, mut push_rx) = mpsc::channel(256);
    let snapshot: Snapshot = Arc::new(RwLock::new(StpSummary::default()));
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let (stop_tx, stop_rx) = watch::channel(false);
    let task = tokio::spawn(run_with(
        fakes.opener(),
        fakes.held_reader(),
        OWN_MAC,
        plan_rx,
        links_rx,
        push_tx,
        snapshot.clone(),
        cmd_rx,
        stop_rx,
    ));

    plan_tx.send(Some(plan(&["eth1"]))).unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(snapshot.read().unwrap().enabled);
    assert!(push_rx.try_recv().is_ok());

    links_tx.send(table(&[("eth1", false)])).unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (reply, rx) = oneshot::channel();
    cmd_tx
        .send(Cmd::Mcheck {
            interface: None,
            reply,
        })
        .await
        .unwrap();
    assert_eq!(rx.await.unwrap(), 1);

    stop_tx.send(true).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn a_cost_priority_or_port_edit_applies_in_place() {
    let mut l = Lab::new();
    l.d.apply_plan(Some(plan(&["eth1", "eth3"]))).await;
    l.d.sync_links().await;
    for _ in 0..40 {
        l.d.on_tick().await;
    }
    let before = l.d.engine.as_ref().unwrap().port_state(0);
    assert_eq!(before, crate::actions::PortState::Forwarding);
    l.pushes();
    let opened = l.fakes.opened();

    let mut p = plan(&["eth1", "eth2", "eth3"]);
    p.priority = 4096;
    p.ports[0].cost = Some(1000);
    l.d.apply_plan(Some(p.clone())).await;
    let e = l.d.engine.as_ref().unwrap();
    assert_eq!(e.port_state(0), crate::actions::PortState::Forwarding);
    assert_eq!(e.numbers()["eth3"], 2, "eth3 keeps its port number");
    assert_eq!(l.d.rt.len(), 3);
    assert_eq!(l.fakes.opened(), opened + 1, "only eth2 opens");
    assert_eq!(l.d.plan.as_ref(), Some(&p));

    l.d.apply_plan(Some(plan(&["eth1", "eth2"]))).await;
    assert_eq!(l.d.io.len(), 2, "eth3's socket closed");
    assert_eq!(l.summary().ports.len(), 2);

    // A structural change rebuilds and renumbers from the kept names.
    let mut q = plan(&["eth1", "eth2"]);
    q.rstp_version = false;
    l.d.apply_plan(Some(q)).await;
    assert_eq!(
        l.d.engine.as_ref().unwrap().numbers()["eth2"],
        3,
        "a rebuild keeps numbers too"
    );
}
