//! Pushes this instance's valid best flowspec rules to `nos-acld` (#562),
//! which enforces them on the `flowspec` devices of this instance's routing
//! table. Same shape as `fdb_push_client` (woken by
//! `SessionManager::push_changed`, `HOLD_DOWN`, `FALLBACK_TICK`,
//! `RETRY_DELAY`, one persistent connection watched for EOF), but each push
//! is a whole snapshot (`AclRequest::PushFlowspec`, answered by
//! `AclEvent::Ack`): a lost one heals with the next, and a reconnect resends
//! it. A snapshot equal to the last acknowledged one is not resent.
//!
//! Graceful restart: while the RIB defers selection
//! (`BgpRib::flowspec_push_snapshot` is `None`) nothing is pushed, so
//! `nos-acld` keeps what it holds. On shutdown an empty snapshot removes
//! this instance's rules.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{
    AclEvent, AclRequest, AddressFamily, FlowBitOp, FlowComponent, FlowNumOp, FlowRule,
    FlowRuleAction, FlowspecRuleStatus, FlowspecSet, IpcCodec, Role, ServiceRef,
};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

use crate::flowspec::{BitOp, Component, NumOp};
use crate::flowspec_action::{decode_actions, decode_redirect_ipv6, ignored, FlowAction};
use crate::rib::FlowspecRoute;
use crate::session::SessionManager;
use nos_daemon::ipc::one_shot;
use nos_daemon::watchdog::resolve_once;

/// Safety-net re-check when no change was signalled.
const FALLBACK_TICK: Duration = Duration::from_secs(10);
/// Coalesces a burst of RIB mutations into one snapshot.
const HOLD_DOWN: Duration = Duration::from_millis(50);
/// Reconnect cadence while `nos-acld` is not reachable.
const RETRY_DELAY: Duration = Duration::from_secs(1);
/// How long a push waits for its `Ack` (and the shutdown push for anything).
const ACK_TIMEOUT: Duration = Duration::from_secs(5);

pub fn spawn(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(run(watchdog_socket, sessions, shutdown))
}

struct Conn {
    reader: FramedRead<ReadHalf<nos_pki::Stream>, IpcCodec<AclEvent>>,
    writer: FramedWrite<WriteHalf<nos_pki::Stream>, IpcCodec<AclRequest>>,
}

impl Conn {
    async fn connect(watchdog_socket: &Path) -> Option<Self> {
        let socket = resolve_once(watchdog_socket, &ServiceRef::Acl).await?;
        let stream = match nos_pki::connect(&socket, Role::Acld, "").await {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "nos-acld not reachable yet, retrying");
                return None;
            }
        };
        let (r, w) = tokio::io::split(stream);
        Some(Self {
            reader: FramedRead::new(r, IpcCodec::default()),
            writer: FramedWrite::new(w, IpcCodec::default()),
        })
    }

    /// Sends one snapshot; `true` once `nos-acld` acknowledged it.
    async fn push(&mut self, set: FlowspecSet) -> bool {
        if self
            .writer
            .send(AclRequest::PushFlowspec(set))
            .await
            .is_err()
        {
            return false;
        }
        matches!(
            tokio::time::timeout(ACK_TIMEOUT, self.reader.next()).await,
            Ok(Some(Ok(AclEvent::Ack)))
        )
    }
}

/// One set to push: the rules of `table` (`None` = the instance's own).
type Sets = Vec<(Option<String>, Vec<FlowRule>)>;

fn snapshot(instance: &str, table: Option<String>, rules: Vec<FlowRule>) -> FlowspecSet {
    FlowspecSet {
        instance: instance.to_string(),
        table,
        devices: Vec::new(),
        rules,
    }
}

async fn run(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    mut shutdown: watch::Receiver<bool>,
) {
    let instance = sessions.instance().to_string();
    // Subscribed before the first snapshot: a change after it is never lost.
    let mut changed = sessions.push_changed();
    let mut conn: Option<Conn> = None;
    // The last snapshot taken outside a deferral, and the last one
    // `nos-acld` acknowledged over `conn`.
    let mut want: Option<Sets> = None;
    let mut sent: Sets = Vec::new();
    while !*shutdown.borrow() {
        if let Some(rules) = sessions.flowspec_push_snapshot().await {
            let mut sets = vec![(None, rules)];
            let vrfs = sessions.vpn_flowspec_push_snapshot().await;
            sets.extend(vrfs.into_iter().flatten().map(|(t, r)| (Some(t), r)));
            want = Some(sets);
        }
        if let Some(sets) = &want {
            if conn.is_none() {
                conn = Conn::connect(&watchdog_socket).await;
                sent.clear();
                if conn.is_some() {
                    info!(instance = %instance, routes = sets[0].1.len(), "connected to nos-acld, pushing flowspec rules");
                }
            }
            // A table that left the VRF set (its `vpn` was removed) is
            // pushed empty once, then forgotten (#1086).
            let gone: Sets = sent
                .iter()
                .filter(|(t, _)| !sets.iter().any(|(w, _)| w == t))
                .map(|(t, _)| (t.clone(), Vec::new()))
                .collect();
            for set in gone {
                let Some(c) = conn.as_mut() else { break };
                if c.push(snapshot(&instance, set.0.clone(), Vec::new())).await {
                    sent.retain(|(t, _)| *t != set.0);
                } else {
                    warn!(instance = %instance, "flowspec push to nos-acld failed, reconnecting");
                    conn = None;
                }
            }
            for set in sets {
                let Some(c) = conn.as_mut() else { break };
                if sent.contains(set) {
                    continue;
                }
                let (table, rules) = set;
                if c.push(snapshot(&instance, table.clone(), rules.clone()))
                    .await
                {
                    debug!(instance = %instance, routes = rules.len(), "flowspec push");
                    sent.retain(|(t, _)| t != table);
                    sent.push(set.clone());
                } else {
                    warn!(instance = %instance, "flowspec push to nos-acld failed, reconnecting");
                    conn = None;
                }
            }
        }
        let tick = if want.is_some() && conn.is_none() {
            RETRY_DELAY
        } else {
            FALLBACK_TICK
        };
        // `nos-acld` only writes in answer to a push: anything else read
        // here (EOF included) means the connection is gone.
        let lost = async {
            match conn.as_mut() {
                Some(c) => {
                    c.reader.next().await;
                }
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = tokio::time::sleep(tick) => {}
            r = changed.changed() => {
                if r.is_ok() {
                    tokio::time::sleep(HOLD_DOWN).await;
                    // Covered by the snapshot taken next.
                    changed.borrow_and_update();
                }
            }
            () = lost => conn = None,
            _ = shutdown.changed() => {}
        }
    }
    if want.is_some() {
        let clear = async {
            let mut c = match conn {
                Some(c) => c,
                None => Conn::connect(&watchdog_socket).await?,
            };
            let mut tables: Vec<&Option<String>> = want.iter().flatten().map(|(t, _)| t).collect();
            tables.extend(
                sent.iter()
                    .map(|(t, _)| t)
                    .filter(|t| !tables.contains(t))
                    .collect::<Vec<_>>(),
            );
            for table in tables {
                if !c.push(snapshot(&instance, table.clone(), Vec::new())).await {
                    return None;
                }
            }
            Some(())
        };
        if let Ok(Some(())) = tokio::time::timeout(ACK_TIMEOUT, clear).await {
            info!(instance = %instance, "flowspec rules withdrawn from nos-acld");
        } else {
            warn!(instance = %instance, "could not withdraw the flowspec rules from nos-acld");
        }
    }
}

/// `nos-acld`'s view of every flow rule (`AclRequest::ShowFlowspec`), for
/// `show bgp flowspec`; `None` when it cannot be asked.
pub async fn show(watchdog_socket: &Path) -> Option<Vec<FlowspecRuleStatus>> {
    let socket = resolve_once(watchdog_socket, &ServiceRef::Acl).await?;
    match one_shot(&socket, Role::Acld, AclRequest::ShowFlowspec).await? {
        AclEvent::Flowspec(rows) => Some(rows),
        _ => None,
    }
}

/// The `dataplane` column of a selected rule (of `table`, a VRF, for a
/// SAFI 134 one; `None` for the instance's own): `installed`, `unsupported
/// (<why>)` or `not-attached` (no `flowspec` device, or not pushed yet), and
/// `unknown` while `nos-acld` cannot be asked.
pub fn dataplane(
    instance: &str,
    table: Option<&str>,
    flow: &str,
    acld: Option<&[FlowspecRuleStatus]>,
) -> String {
    let Some(rows) = acld else {
        return "unknown".to_string();
    };
    match rows
        .iter()
        .find(|r| r.instance == instance && r.table.as_deref() == table && r.flow == flow)
    {
        Some(FlowspecRuleStatus {
            unsupported: None, ..
        }) => "installed".to_string(),
        Some(FlowspecRuleStatus {
            unsupported: Some(why),
            ..
        }) if why != "not attached" => format!("unsupported ({why})"),
        _ => "not-attached".to_string(),
    }
}

/// `r` as `nos-acld` lowers it: the components mirrored one to one, the
/// actions in attribute order without a shadowed traffic-rate (RFC 8955
/// section 7.7, `flowspec_action::ignored`), a redirect as `Unsupported`.
pub fn flow_rule(r: &FlowspecRoute) -> FlowRule {
    let a = &r.attributes;
    let mut actions = match decode_actions(&a.extended_communities) {
        Ok(decoded) => decoded
            .iter()
            .zip(ignored(&decoded))
            .filter(|(_, ign)| !ign)
            .map(|(x, _)| action(x))
            .collect(),
        // The UPDATE parser treats this as withdraw; never install it.
        Err(e) => vec![FlowRuleAction::Unsupported(e.to_string())],
    };
    actions.extend(
        a.ipv6_extended_communities
            .iter()
            .filter_map(decode_redirect_ipv6)
            .map(|x| action(&x)),
    );
    FlowRule {
        flow: r.nlri.to_string(),
        ipv6: r.family == AddressFamily::Ipv6Flowspec,
        components: r.nlri.components.iter().map(component).collect(),
        actions,
    }
}

fn action(a: &FlowAction) -> FlowRuleAction {
    match *a {
        FlowAction::RateBytes(r) => FlowRuleAction::RateBytes(r),
        FlowAction::RatePackets(r) => FlowRuleAction::RatePackets(r),
        FlowAction::TrafficAction { sample, terminal } => {
            FlowRuleAction::TrafficAction { sample, terminal }
        }
        FlowAction::Dscp(d) => FlowRuleAction::Dscp(d),
        FlowAction::RedirectRt { .. } | FlowAction::RedirectIpv6 { .. } => {
            FlowRuleAction::Unsupported(a.to_string())
        }
    }
}

fn nums(ops: &[NumOp]) -> Vec<FlowNumOp> {
    ops.iter()
        .map(|o| FlowNumOp {
            and: o.and,
            lt: o.lt,
            gt: o.gt,
            eq: o.eq,
            value: o.value,
        })
        .collect()
}

fn bits(ops: &[BitOp]) -> Vec<FlowBitOp> {
    ops.iter()
        .map(|o| FlowBitOp {
            and: o.and,
            not: o.not,
            m: o.m,
            value: o.value,
        })
        .collect()
}

fn component(c: &Component) -> FlowComponent {
    match c {
        Component::Dest(p) => FlowComponent::Dest {
            prefix: p.net,
            offset: p.offset,
        },
        Component::Source(p) => FlowComponent::Source {
            prefix: p.net,
            offset: p.offset,
        },
        Component::Protocol(o) => FlowComponent::Protocol(nums(o)),
        Component::Port(o) => FlowComponent::Port(nums(o)),
        Component::DstPort(o) => FlowComponent::DstPort(nums(o)),
        Component::SrcPort(o) => FlowComponent::SrcPort(nums(o)),
        Component::IcmpType(o) => FlowComponent::IcmpType(nums(o)),
        Component::IcmpCode(o) => FlowComponent::IcmpCode(nums(o)),
        Component::TcpFlags(o) => FlowComponent::TcpFlags(bits(o)),
        Component::PacketLen(o) => FlowComponent::PacketLen(nums(o)),
        Component::Dscp(o) => FlowComponent::Dscp(nums(o)),
        Component::Fragment(o) => FlowComponent::Fragment(bits(o)),
        Component::FlowLabel(o) => FlowComponent::FlowLabel(nums(o)),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use nos_test_support::{serve, FakeWatchdog, Reply};

    use super::*;
    use crate::flowspec::{FlowSpec, Prefix};
    use crate::flowspec_action::{MARKING, RATE_BYTES, REDIRECT_AS2, TRAFFIC_ACTION};
    use crate::message::{Origin, PathAttributes};

    fn comm(t: u16, rest: [u8; 6]) -> u64 {
        let mut b = [0u8; 8];
        b[..2].copy_from_slice(&t.to_be_bytes());
        b[2..].copy_from_slice(&rest);
        u64::from_be_bytes(b)
    }

    fn route(family: AddressFamily, components: Vec<Component>, ext: Vec<u64>) -> FlowspecRoute {
        let mut redirect6 = [0u8; 20];
        redirect6[1] = 0x0d;
        FlowspecRoute {
            family,
            nlri: FlowSpec { components },
            attributes: PathAttributes {
                origin: Origin::Igp,
                as_path: vec![65001].into(),
                next_hop: "0.0.0.0".parse().unwrap(),
                local_pref: None,
                med: None,
                originator_id: None,
                cluster_list: vec![],
                communities: vec![],
                extended_communities: ext,
                large_communities: vec![],
                ipv6_extended_communities: if family == AddressFamily::Ipv6Flowspec {
                    vec![redirect6]
                } else {
                    vec![]
                },
                pmsi: None,
                atomic_aggregate: false,
                aggregator: None,
                otc: None,
                unknown: std::sync::Arc::default(),
            },
            learned_via_ibgp: false,
            router_id: "2.2.2.2".parse().unwrap(),
            received_at: Instant::now(),
            validity: None,
        }
    }

    fn num(value: u64) -> NumOp {
        NumOp {
            and: false,
            lt: false,
            gt: false,
            eq: true,
            value,
        }
    }

    #[test]
    fn a_route_mirrors_into_a_flow_rule() {
        let bit = BitOp {
            and: true,
            not: true,
            m: false,
            value: 2,
        };
        let comps = vec![
            Component::Dest(Prefix::v4("192.0.2.1/32".parse().unwrap())),
            Component::Source(Prefix::v4("198.51.100.0/24".parse().unwrap())),
            Component::Protocol(vec![num(6)]),
            Component::Port(vec![num(1)]),
            Component::DstPort(vec![num(8080)]),
            Component::SrcPort(vec![num(2)]),
            Component::IcmpType(vec![num(3)]),
            Component::IcmpCode(vec![num(4)]),
            Component::TcpFlags(vec![bit]),
            Component::PacketLen(vec![num(64)]),
            Component::Dscp(vec![num(10)]),
            Component::Fragment(vec![bit]),
        ];
        let rate = |r: f32| {
            let b = r.to_be_bytes();
            comm(RATE_BYTES, [0, 0, b[0], b[1], b[2], b[3]])
        };
        let ext = vec![
            rate(0.0),
            rate(100.0), // shadowed: left out
            comm(TRAFFIC_ACTION, [0, 0, 0, 0, 0, 0x03]),
            comm(MARKING, [0, 0, 0, 0, 0, 46]),
            comm(REDIRECT_AS2, [0xfd, 0xe8, 0, 0, 0, 1]),
            0x0003_0000_0000_0000, // not an action
        ];
        let r = route(AddressFamily::Ipv4Flowspec, comps, ext);
        let rule = flow_rule(&r);
        assert_eq!(rule.flow, r.nlri.to_string());
        assert!(!rule.ipv6);
        assert_eq!(rule.components.len(), 12);
        assert_eq!(
            rule.components[0],
            FlowComponent::Dest {
                prefix: "192.0.2.1/32".parse().unwrap(),
                offset: 0
            }
        );
        assert_eq!(
            rule.components[8],
            FlowComponent::TcpFlags(vec![FlowBitOp {
                and: true,
                not: true,
                m: false,
                value: 2
            }])
        );
        assert_eq!(
            rule.components[4],
            FlowComponent::DstPort(vec![FlowNumOp {
                and: false,
                lt: false,
                gt: false,
                eq: true,
                value: 8080
            }])
        );
        assert_eq!(
            rule.actions,
            [
                FlowRuleAction::RateBytes(0.0),
                FlowRuleAction::TrafficAction {
                    sample: true,
                    terminal: true
                },
                FlowRuleAction::Dscp(46),
                FlowRuleAction::Unsupported("redirect rt 65000:1".into()),
            ]
        );
        // IPv6: flow label, the RFC 5701 redirect, a packets rate.
        let b = 5.0f32.to_be_bytes();
        let ext = vec![comm(
            crate::flowspec_action::RATE_PACKETS,
            [0, 0, b[0], b[1], b[2], b[3]],
        )];
        let r = route(
            AddressFamily::Ipv6Flowspec,
            vec![Component::FlowLabel(vec![num(7)])],
            ext,
        );
        let rule = flow_rule(&r);
        assert!(rule.ipv6);
        assert_eq!(
            rule.components,
            [FlowComponent::FlowLabel(vec![FlowNumOp {
                and: false,
                lt: false,
                gt: false,
                eq: true,
                value: 7
            }])]
        );
        assert_eq!(rule.actions[0], FlowRuleAction::RatePackets(5.0));
        assert!(
            matches!(&rule.actions[1], FlowRuleAction::Unsupported(s) if s.starts_with("redirect ipv6"))
        );
        // A NaN rate cannot be decoded: never installed.
        let nan = f32::NAN.to_be_bytes();
        let r = route(
            AddressFamily::Ipv4Flowspec,
            vec![],
            vec![comm(RATE_BYTES, [0, 0, nan[0], nan[1], nan[2], nan[3]])],
        );
        assert!(matches!(
            &flow_rule(&r).actions[..],
            [FlowRuleAction::Unsupported(_)]
        ));
    }

    #[test]
    fn dataplane_joins_on_instance_and_flow() {
        let row = |instance: &str, flow: &str, unsupported: Option<&str>| FlowspecRuleStatus {
            instance: instance.into(),
            table: None,
            flow: flow.into(),
            actions: vec![],
            unsupported: unsupported.map(Into::into),
            packets: 0,
            bytes: 0,
        };
        let rows = [
            row("b1", "dest 192.0.2.1/32", None),
            row("b2", "dest 192.0.2.2/32", None),
            row("b1", "dest 192.0.2.2/32", Some("not attached")),
            row("b1", "len =64", Some("packet length: no flower key")),
        ];
        let d = |flow| dataplane("b1", None, flow, Some(&rows));
        assert_eq!(d("dest 192.0.2.1/32"), "installed");
        assert_eq!(d("dest 192.0.2.2/32"), "not-attached");
        assert_eq!(d("len =64"), "unsupported (packet length: no flower key)");
        assert_eq!(d("dest 192.0.2.9/32"), "not-attached");
        assert_eq!(dataplane("b1", None, "x", None), "unknown");
        // A VRF's row is never another table's (or the instance's) status.
        let mut red = row("b1", "dest 192.0.2.9/32", None);
        red.table = Some("red".into());
        let rows = [red, row("b1", "dest 192.0.2.7/32", None)];
        let d = |t, f| dataplane("b1", t, f, Some(&rows));
        assert_eq!(d(Some("red"), "dest 192.0.2.9/32"), "installed");
        assert_eq!(d(None, "dest 192.0.2.9/32"), "not-attached");
        assert_eq!(d(Some("blue"), "dest 192.0.2.9/32"), "not-attached");
        assert_eq!(d(Some("red"), "dest 192.0.2.7/32"), "not-attached");
    }

    /// The requests `acld` received, once there are some.
    async fn pushes(acld: &nos_test_support::Server<AclRequest>, n: usize) -> Vec<AclRequest> {
        for _ in 0..100 {
            let seen = acld.take_seen();
            if !seen.is_empty() {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no push #{n}");
    }

    /// Against a fake `nos-acld` behind a fake broker: the snapshot is
    /// pushed on connect, again after `nos-acld` drops the connection, and
    /// an empty one on shutdown; `show` reads the rows back.
    #[tokio::test]
    async fn pushes_on_connect_after_a_drop_and_clears_on_shutdown() {
        let tmp = tempfile::tempdir().unwrap();
        let acld_path = tmp.path().join("acl.sock");
        let rows = vec![FlowspecRuleStatus {
            instance: "b1".into(),
            table: None,
            flow: "f".into(),
            actions: vec![],
            unsupported: None,
            packets: 1,
            bytes: 2,
        }];
        let shown = rows.clone();
        let acld = serve(&acld_path, "acld", "", move |req: &AclRequest| match req {
            AclRequest::PushFlowspec(_) => Reply::One(AclEvent::Ack),
            AclRequest::ShowFlowspec => Reply::One(AclEvent::Flowspec(shown.clone())),
            AclRequest::Show { .. } | AclRequest::ClearCounters { .. } => Reply::Close,
        });
        let watchdog = FakeWatchdog::new(&tmp.path().join("wd.sock"));
        assert_eq!(show(watchdog.path()).await, None);
        watchdog.set(ServiceRef::Acl, acld_path.clone());
        assert_eq!(show(watchdog.path()).await, Some(rows));
        acld.take_seen();

        let sessions = SessionManager::new("b1".into());
        let (tx, rx) = watch::channel(false);
        let task = spawn(watchdog.path().to_path_buf(), sessions, rx);
        let first = pushes(&acld, 1).await;
        assert!(
            matches!(&first[..], [AclRequest::PushFlowspec(s)] if s.instance == "b1" && s.rules.is_empty()),
            "{first:?}"
        );
        acld.close_connections();
        assert_eq!(pushes(&acld, 2).await.len(), 1);
        tx.send(true).unwrap();
        task.await.unwrap();
        assert!(matches!(
            &acld.take_seen()[..],
            [AclRequest::PushFlowspec(s)] if s.rules.is_empty() && s.devices.is_empty()
        ));
    }

    /// A VRF whose `vpn` is removed is pushed empty once; an unchanged set
    /// is not pushed again (#1086).
    #[tokio::test]
    async fn a_table_that_left_the_vrf_set_is_cleared_once() {
        use crate::vpn::{Vrf, VrfSet};
        let tmp = tempfile::tempdir().unwrap();
        let acld_path = tmp.path().join("acl.sock");
        let acld = serve(&acld_path, "acld", "", |req: &AclRequest| match req {
            AclRequest::PushFlowspec(_) => Reply::One(AclEvent::Ack),
            _ => Reply::Close,
        });
        let watchdog = FakeWatchdog::new(&tmp.path().join("wd.sock"));
        watchdog.set(ServiceRef::Acl, acld_path);
        let sessions = SessionManager::new("b1".into());
        let red = Vrf {
            table: "red".into(),
            rd: [0; 8],
            import: vec![],
            export: vec![],
            soo: None,
        };
        sessions.set_vpn_vrfs(VrfSet(vec![red])).await;
        let (tx, rx) = watch::channel(false);
        let task = spawn(watchdog.path().to_path_buf(), sessions.clone(), rx);
        let tables = |seen: &[AclRequest]| -> Vec<Option<String>> {
            seen.iter()
                .filter_map(|r| match r {
                    AclRequest::PushFlowspec(s) => Some(s.table.clone()),
                    _ => None,
                })
                .collect()
        };
        let mut seen = Vec::new();
        for _ in 0..100 {
            seen.extend(acld.take_seen());
            if seen.len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(tables(&seen), [None, Some("red".to_string())]);
        sessions.set_vpn_vrfs(VrfSet::default()).await;
        let mut seen = Vec::new();
        for _ in 0..100 {
            seen.extend(acld.take_seen());
            if !seen.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            matches!(&seen[..], [AclRequest::PushFlowspec(s)] if s.table.as_deref() == Some("red") && s.rules.is_empty()),
            "{seen:?}"
        );
        // Nothing more: red is forgotten, unicast is unchanged.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(acld.take_seen().is_empty());
        tx.send(true).unwrap();
        task.await.unwrap();
    }
}
