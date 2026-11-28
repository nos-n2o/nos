//! The kernel side, per (device, direction) on the device's `clsact` qdisc:
//!
//! - chain 0, priority [`ACL_PRIO`], handle 1: one keyless flower filter,
//!   `goto chain <live>`, whose action cookie is the live chain number;
//! - the ACL itself in chain [`ACL_CHAIN_A`] or [`ACL_CHAIN_B`].
//!
//! An update fills the idle chain, replaces the entry (one RCU swap: no
//! packet sees no ACL or half of one), then flushes the old chain.
//! `nos-fdbd`/`nos-interfaced` own lower priorities on chain 0 (`tc/CLAUDE.md`):
//! nothing here deletes the qdisc or touches their priorities.
//!
//! Flowspec (#561) sits on chain 0 ingress too, one priority per rule in the
//! band [`flowspec::PRIO_FIRST`]..=[`flowspec::PRIO_LAST`], before the ACL
//! entry. A rule that stops flowspec evaluation jumps to
//! [`flowspec::EXIT_CHAIN`], whose one filter (kept by [`Driver::switch`])
//! jumps on to the live ACL chain.

mod linux;
mod noop;

use std::collections::BTreeMap;
use std::fmt;
use std::io;

pub use linux::LinuxDriver;
pub use noop::{Call, NoopDriver};

use nos_proto::schema::AclAction;
use nos_tc::{
    Action, ActionKind, Filter, FilterStats, FlowerKeys, Hook, Kind, Protocol, Request, Verdict,
};

use crate::compile::{prio, Compiled, DEFAULT_COOKIE};
use crate::flowspec::{self, Lowered};

/// Chain 0 priority of the entry filter: above every priority `nos-fdbd` and
/// `nos-interfaced` use (1, 2), so theirs run first.
pub const ACL_PRIO: u16 = 100;
/// The two chains an ACL alternates between.
pub const ACL_CHAIN_A: u32 = 1000;
pub const ACL_CHAIN_B: u32 = 1001;
/// The entry filter's fixed handle.
const ENTRY_HANDLE: u32 = 1;

/// `acl in` is clsact ingress, `acl out` clsact egress (no ifb).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    pub const BOTH: [Direction; 2] = [Direction::In, Direction::Out];

    pub fn hook(self) -> Hook {
        match self {
            Self::In => Hook::Ingress,
            Self::Out => Hook::Egress,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::In => "in",
            Self::Out => "out",
        })
    }
}

/// The chain an update fills: the one not live.
pub fn idle(live: Option<u32>) -> u32 {
    if live == Some(ACL_CHAIN_A) {
        ACL_CHAIN_B
    } else {
        ACL_CHAIN_A
    }
}

/// What the kernel holds for one (device, direction). Blocking: the daemon
/// calls it from `spawn_blocking`.
pub trait Driver: Send + 'static {
    /// The chain the entry filter points at, `None` without one.
    fn live_chain(&mut self, ifindex: u32, dir: Direction) -> io::Result<Option<u32>>;
    /// Ensures `clsact`, empties `chain`, fills it with `acl`.
    fn install(
        &mut self,
        ifindex: u32,
        dir: Direction,
        chain: u32,
        acl: &Compiled,
    ) -> io::Result<()>;
    /// Creates or replaces the entry filter to point at `chain`; `old` is the
    /// chain it pointed at (`None`: first attach). On error the entry must
    /// still name `old` (best effort: the engine re-switches to it).
    fn switch(
        &mut self,
        ifindex: u32,
        dir: Direction,
        chain: u32,
        old: Option<u32>,
    ) -> io::Result<()>;
    /// Removes every filter of `chain` (absent is fine).
    fn flush(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<()>;
    /// Removes the entry filter, then both chains.
    fn detach(&mut self, ifindex: u32, dir: Direction) -> io::Result<()>;
    /// The counters of `chain`'s filters, one per action cookie (`show acl`).
    fn counters(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<Vec<Counter>>;
    /// Replaces flowspec priority `prio` on `ifindex`'s ingress: removes what
    /// it holds, then (with `rule`) installs it with cookie `rule.0`.
    fn flowspec_set(
        &mut self,
        ifindex: u32,
        prio: u16,
        rule: Option<(u32, &Lowered)>,
    ) -> io::Result<()>;
    /// The flowspec priorities holding filters (the start sweep).
    fn flowspec_prios(&mut self, ifindex: u32) -> io::Result<Vec<u16>>;
    /// Matched `(packets, bytes)` per flowspec priority.
    fn flowspec_counters(&mut self, ifindex: u32) -> io::Result<BTreeMap<u16, (u64, u64)>>;
}

/// One filter's `gact` counters: the action cookie (a rule index, or
/// [`DEFAULT_COOKIE`]) and what matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counter {
    pub cookie: u32,
    pub packets: u64,
    pub bytes: u64,
}

/// The `gact` rows of a chain dump. Read by kind, not position: a filter may
/// carry a `sample` action (#544) whose counters are not the verdict's.
pub fn counters_from(rows: &[FilterStats]) -> Vec<Counter> {
    rows.iter()
        .filter(|r| r.action == "gact")
        .filter_map(|r| {
            Some(Counter {
                cookie: u32::from_be_bytes(<[u8; 4]>::try_from(r.cookie.as_slice()).ok()?),
                packets: r.packets,
                bytes: r.bytes,
            })
        })
        .collect()
}

fn verdict(a: AclAction) -> Verdict {
    match a {
        AclAction::Permit => Verdict::Ok,
        AclAction::Deny => Verdict::Shot,
    }
}

/// The psample group of every `log` rule's `sample` action ("NOS").
pub const ACL_PSAMPLE_GROUP: u32 = 0x4e_4f53;
/// Bytes of a logged packet handed to psample: Ethernet, IPv6 with a few
/// extension headers and the L4 ports fit.
pub const LOG_TRUNC: u32 = 128;

/// A `log` rule needs the kernel to hand the action cookie to psample
/// (Linux 6.11): without it a sample does not name its rule, so the ACL is
/// refused at attach (owner decision L2 of #544), not logged half-blind.
pub fn check_log(p: &nos_tc::Psample) -> io::Result<()> {
    if p.user_cookie {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "acl log needs a kernel passing the psample cookie (Linux 6.11)",
        ))
    }
}

/// One packet in this many is handed to psample by a `log` rule or a
/// flowspec S bit (#699). The kernel builds and multicasts a message per
/// sampled packet, so sampling every packet made a flood cost CPU and
/// overflowed the psample socket. A gate (`police` plus a twin filter) was
/// tried and the kernel refuses it: two flower filters with the same keys at
/// one priority give `EEXIST`. The price: a lone denied packet logs only
/// about 1 time in this many, and sampled counts are statistical (the
/// verdict counters stay exact).
pub const SAMPLE_RATE: u32 = 100;

/// The `sample` action shared by `log` rules and flowspec S.
pub fn sample_kind(trunc: u32, group: u32) -> ActionKind {
    ActionKind::Sample {
        rate: SAMPLE_RATE,
        trunc,
        group,
    }
}

/// The filters of `chain` for `acl`, levels then defaults. A `log` rule's
/// filters sample one packet in [`SAMPLE_RATE`] (the daemon rate-limits the
/// lines) before the verdict, with the same cookie.
pub fn chain_requests(ifindex: u32, dir: Direction, chain: u32, acl: &Compiled) -> Vec<Request> {
    let filter = |level, protocol, keys, action, cookie: u32, log: bool| {
        let cookie = cookie.to_be_bytes().to_vec();
        let sample = log.then(|| Action {
            kind: sample_kind(LOG_TRUNC, ACL_PSAMPLE_GROUP),
            cookie: cookie.clone(),
        });
        let gact = Action {
            kind: ActionKind::Gact(verdict(action)),
            cookie,
        };
        Request::AddFilter(Filter {
            ifindex,
            hook: dir.hook(),
            chain,
            prio: prio(level, protocol),
            protocol,
            handle: 0,
            kind: Kind::Flower(keys),
            actions: sample.into_iter().chain([gact]).collect(),
            replace: false,
        })
    };
    let mut v: Vec<Request> = acl
        .levels
        .iter()
        .enumerate()
        .flat_map(|(i, l)| {
            l.filters
                .iter()
                .map(move |f| filter(i, f.protocol, f.keys.clone(), f.action, f.rule, f.log))
        })
        .collect();
    for p in [Protocol::Ip, Protocol::Ipv6] {
        let keys = FlowerKeys::default();
        v.push(filter(
            acl.levels.len(),
            p,
            keys,
            acl.default_action,
            DEFAULT_COOKIE,
            false,
        ));
    }
    v
}

/// The chain-0 entry filter (`NLM_F_REPLACE`: creates or swaps in place).
pub fn entry_request(ifindex: u32, dir: Direction, chain: u32) -> Request {
    Request::AddFilter(Filter {
        ifindex,
        hook: dir.hook(),
        chain: 0,
        prio: ACL_PRIO,
        protocol: Protocol::All,
        handle: ENTRY_HANDLE,
        kind: Kind::Flower(FlowerKeys::default()),
        actions: vec![Action {
            kind: ActionKind::Gact(Verdict::GotoChain(chain)),
            cookie: chain.to_be_bytes().to_vec(),
        }],
        replace: true,
    })
}

/// Deletes the entry filter (the whole of our priority on chain 0).
pub fn entry_delete(ifindex: u32, dir: Direction) -> Request {
    Request::DelFilter {
        ifindex,
        hook: dir.hook(),
        chain: 0,
        prio: ACL_PRIO,
        protocol: Protocol::All,
        handle: 0,
    }
}

/// The filter of [`flowspec::EXIT_CHAIN`]: on to the live ACL `chain`, so a
/// flowspec rule that stops flowspec evaluation still meets the ACL.
pub fn exit_request(ifindex: u32, dir: Direction, chain: u32) -> Request {
    match entry_request(ifindex, dir, chain) {
        Request::AddFilter(f) => Request::AddFilter(Filter {
            chain: flowspec::EXIT_CHAIN,
            ..f
        }),
        other => other,
    }
}

/// The filters of flowspec priority `prio` for `rule`; the cookie (the rule
/// index) is on the first action only, so a dump counts each filter once;
/// a leading `sample` (S bit, 1 in [`SAMPLE_RATE`]) never carries it, the
/// next action does, so the counts stay exact.
pub fn flowspec_requests(ifindex: u32, prio: u16, cookie: u32, rule: &Lowered) -> Vec<Request> {
    let first = rule
        .actions
        .iter()
        .position(|k| !matches!(k, ActionKind::Sample { .. }))
        .unwrap_or(0);
    let actions: Vec<Action> = rule
        .actions
        .iter()
        .enumerate()
        .map(|(i, kind)| Action {
            kind: kind.clone(),
            cookie: if i == first {
                cookie.to_be_bytes().to_vec()
            } else {
                Vec::new()
            },
        })
        .collect();
    rule.filters
        .iter()
        .map(|keys| {
            Request::AddFilter(Filter {
                ifindex,
                hook: Hook::Ingress,
                chain: 0,
                prio,
                protocol: rule.protocol,
                handle: 0,
                kind: Kind::Flower(keys.clone()),
                actions: actions.clone(),
                replace: false,
            })
        })
        .collect()
}

/// Deletes every filter at flowspec priority `prio` if it holds `protocol`:
/// the kernel answers `EINVAL` for another protocol, `ENOENT` for none (a
/// swept priority's protocol is unknown, so the driver tries both).
pub fn flowspec_delete(ifindex: u32, prio: u16, protocol: Protocol) -> Request {
    Request::DelFilter {
        ifindex,
        hook: Hook::Ingress,
        chain: 0,
        prio,
        protocol,
        handle: 0,
    }
}

fn in_band(r: &FilterStats) -> bool {
    r.chain == 0 && (flowspec::PRIO_FIRST..=flowspec::PRIO_LAST).contains(&r.prio)
}

/// The flowspec priorities of a chain-0 dump.
pub fn flowspec_prios_from(rows: &[FilterStats]) -> Vec<u16> {
    let mut v: Vec<u16> = rows.iter().filter(|r| in_band(r)).map(|r| r.prio).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// `(packets, bytes)` per flowspec priority: the cookie-carrying (first)
/// action of each filter, summed.
pub fn flowspec_counters_from(rows: &[FilterStats]) -> BTreeMap<u16, (u64, u64)> {
    let mut out: BTreeMap<u16, (u64, u64)> = BTreeMap::new();
    for r in rows.iter().filter(|r| in_band(r) && r.cookie.len() == 4) {
        let s = out.entry(r.prio).or_default();
        s.0 = s.0.saturating_add(r.packets);
        s.1 = s.1.saturating_add(r.bytes);
    }
    out
}

/// The live chain from a chain-0 dump: our entry's cookie.
pub fn live_from(rows: &[FilterStats]) -> Option<u32> {
    rows.iter()
        .find(|r| r.prio == ACL_PRIO && r.handle == ENTRY_HANDLE)
        .and_then(|r| <[u8; 4]>::try_from(r.cookie.as_slice()).ok())
        .map(u32::from_be_bytes)
        .filter(|c| [ACL_CHAIN_A, ACL_CHAIN_B].contains(c))
}

#[cfg(test)]
mod tests {
    use nos_proto::schema::{Acl, AclRule};

    use super::*;
    use crate::compile::compile;

    #[test]
    fn flowspec_filters_share_a_priority_and_count_once() {
        let rule = Lowered {
            protocol: Protocol::Ipv6,
            filters: vec![
                FlowerKeys {
                    ip_proto: Some(6),
                    ..Default::default()
                },
                FlowerKeys {
                    ip_proto: Some(17),
                    ..Default::default()
                },
            ],
            actions: vec![
                ActionKind::Pedit(nos_tc::Pedit::Dscp {
                    value: 1,
                    family: nos_tc::PeditFamily::Ipv6,
                }),
                ActionKind::Gact(Verdict::Shot),
            ],
        };
        let reqs = flowspec_requests(4, 12, 3, &rule);
        assert_eq!(reqs.len(), 2);
        for r in &reqs {
            let Request::AddFilter(f) = r else { panic!() };
            assert_eq!(
                (f.ifindex, f.hook, f.chain, f.prio, f.protocol, f.handle, f.replace),
                (4, Hook::Ingress, 0, 12, Protocol::Ipv6, 0, false)
            );
            assert_eq!(f.actions[0].cookie, vec![0, 0, 0, 3]);
            assert_eq!(f.actions[1].cookie, Vec::<u8>::new());
        }
        assert_eq!(
            flowspec_delete(4, 12, Protocol::Ipv6),
            Request::DelFilter {
                ifindex: 4,
                hook: Hook::Ingress,
                chain: 0,
                prio: 12,
                protocol: Protocol::Ipv6,
                handle: 0,
            }
        );
        let row = |chain, prio, cookie: &[u8], packets| FilterStats {
            chain,
            prio,
            cookie: cookie.to_vec(),
            packets,
            bytes: packets * 10,
            action: "gact".into(),
            ..Default::default()
        };
        let rows = [
            row(0, 1, &[0, 0, 0, 0], 99),
            row(0, 12, &[0, 0, 0, 3], 2),
            row(0, 12, &[], 1),
            row(0, 12, &[0, 0, 0, 3], 5),
            row(0, 10, &[0, 0, 0, 0], 4),
            row(0, ACL_PRIO, &ACL_CHAIN_A.to_be_bytes(), 7),
            row(5, 20, &[0, 0, 0, 1], 8),
        ];
        assert_eq!(flowspec_prios_from(&rows), [10, 12]);
        assert_eq!(
            flowspec_counters_from(&rows),
            BTreeMap::from([(10, (4, 40)), (12, (7, 70))])
        );
        let Request::AddFilter(x) = exit_request(4, Direction::In, ACL_CHAIN_B) else {
            panic!()
        };
        assert_eq!(
            (x.chain, x.prio, x.handle, x.replace),
            (flowspec::EXIT_CHAIN, ACL_PRIO, 1, true)
        );
        assert_eq!(
            x.actions[0].kind,
            ActionKind::Gact(Verdict::GotoChain(ACL_CHAIN_B))
        );
    }

    #[test]
    fn a_flowspec_sample_is_sparse_and_the_cookie_sits_on_the_next_action() {
        let rule = Lowered {
            protocol: Protocol::Ip,
            filters: vec![FlowerKeys::default()],
            actions: vec![sample_kind(128, 7), ActionKind::Gact(Verdict::Unspec)],
        };
        let Request::AddFilter(f) = &flowspec_requests(4, 12, 3, &rule)[0] else {
            panic!()
        };
        assert_eq!(f.actions[0].kind, sample_kind(128, 7));
        assert_eq!(f.actions[0].cookie, Vec::<u8>::new());
        assert_eq!(f.actions[1].cookie, vec![0, 0, 0, 3]);
        assert_eq!(SAMPLE_RATE, 100);
    }

    #[test]
    fn idle_alternates() {
        assert_eq!(idle(None), ACL_CHAIN_A);
        assert_eq!(idle(Some(ACL_CHAIN_A)), ACL_CHAIN_B);
        assert_eq!(idle(Some(ACL_CHAIN_B)), ACL_CHAIN_A);
    }

    #[test]
    fn directions_are_clsact_hooks() {
        assert_eq!(Direction::In.hook(), Hook::Ingress);
        assert_eq!(Direction::Out.hook(), Hook::Egress);
        assert_eq!(format!("{} {}", Direction::In, Direction::Out), "in out");
    }

    #[test]
    fn chain_holds_levels_then_one_default_per_family() {
        let acl = Acl {
            rules: vec![AclRule {
                name: "p".into(),
                action: AclAction::Permit,
                ..Default::default()
            }],
            ..Default::default()
        };
        let reqs = chain_requests(9, Direction::Out, ACL_CHAIN_B, &compile(&acl).unwrap());
        let got: Vec<_> = reqs
            .iter()
            .map(|r| match r {
                Request::AddFilter(f) => {
                    assert_eq!(
                        (f.ifindex, f.hook, f.chain, f.handle),
                        (9, Hook::Egress, ACL_CHAIN_B, 0)
                    );
                    assert!(!f.replace);
                    (f.prio, f.protocol, f.actions[0].clone())
                }
                other => panic!("{other:?}"),
            })
            .collect();
        let act = |v, c: u32| Action {
            kind: ActionKind::Gact(v),
            cookie: c.to_be_bytes().to_vec(),
        };
        assert_eq!(
            got,
            [
                (1, Protocol::Ip, act(Verdict::Ok, 0)),
                (2, Protocol::Ipv6, act(Verdict::Ok, 0)),
                (4, Protocol::Ip, act(Verdict::Shot, DEFAULT_COOKIE)),
                (5, Protocol::Ipv6, act(Verdict::Shot, DEFAULT_COOKIE)),
            ]
        );
    }

    #[test]
    fn a_log_rule_samples_then_decides_with_one_cookie() {
        let acl = Acl {
            rules: vec![AclRule {
                name: "l".into(),
                action: AclAction::Deny,
                destination: Some("192.0.2.0/24".parse().unwrap()),
                log: true,
                ..Default::default()
            }],
            default_action: AclAction::Permit,
            ..Default::default()
        };
        let reqs = chain_requests(9, Direction::In, ACL_CHAIN_A, &compile(&acl).unwrap());
        let acts: Vec<Vec<Action>> = reqs
            .iter()
            .map(|r| match r {
                Request::AddFilter(f) => f.actions.clone(),
                other => panic!("{other:?}"),
            })
            .collect();
        let sample = Action {
            kind: sample_kind(LOG_TRUNC, ACL_PSAMPLE_GROUP),
            cookie: vec![0; 4],
        };
        let gact = |v, c: u32| Action {
            kind: ActionKind::Gact(v),
            cookie: c.to_be_bytes().to_vec(),
        };
        assert_eq!(acts[0], [sample, gact(Verdict::Shot, 0)]);
        // The defaults never sample.
        assert_eq!(acts[1], [gact(Verdict::Ok, DEFAULT_COOKIE)]);
        assert_eq!(acts.len(), 3);
        let p = |user_cookie| nos_tc::Psample {
            family: 30,
            group: 9,
            user_cookie,
        };
        assert!(check_log(&p(true)).is_ok());
        let e = check_log(&p(false)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn counters_come_from_the_gact_rows_by_kind() {
        let row = |action: &str, cookie: &[u8], packets| FilterStats {
            action: action.into(),
            cookie: cookie.to_vec(),
            packets,
            bytes: packets * 10,
            ..Default::default()
        };
        let c = |cookie, packets| Counter {
            cookie,
            packets,
            bytes: packets * 10,
        };
        let rows = [
            row("sample", &[0, 0, 0, 1], 99),
            row("gact", &[0, 0, 0, 1], 3),
            row("gact", &DEFAULT_COOKIE.to_be_bytes(), 5),
            row("gact", &[1, 2], 7),
            row("gact", &[], 8),
        ];
        assert_eq!(counters_from(&rows), [c(1, 3), c(DEFAULT_COOKIE, 5)]);
    }

    #[test]
    fn entry_points_at_the_chain_and_names_it_in_its_cookie() {
        let Request::AddFilter(f) = entry_request(3, Direction::In, ACL_CHAIN_A) else {
            panic!()
        };
        assert_eq!(
            (f.chain, f.prio, f.handle, f.protocol),
            (0, ACL_PRIO, 1, Protocol::All)
        );
        assert!(f.replace);
        assert_eq!(f.kind, Kind::Flower(FlowerKeys::default()));
        assert_eq!(
            f.actions[0].kind,
            ActionKind::Gact(Verdict::GotoChain(ACL_CHAIN_A))
        );
        let row = |prio, handle, cookie: Vec<u8>| FilterStats {
            prio,
            handle,
            cookie,
            ..Default::default()
        };
        assert_eq!(
            live_from(&[row(ACL_PRIO, 1, f.actions[0].cookie.clone())]),
            Some(ACL_CHAIN_A)
        );
        assert_eq!(
            live_from(&[row(1, 1, ACL_CHAIN_A.to_be_bytes().to_vec())]),
            None
        );
        assert_eq!(live_from(&[row(ACL_PRIO, 1, vec![1, 2])]), None);
        assert_eq!(
            live_from(&[row(ACL_PRIO, 1, 7u32.to_be_bytes().to_vec())]),
            None
        );
        assert_eq!(live_from(&[]), None);
        assert_eq!(
            entry_delete(3, Direction::Out),
            Request::DelFilter {
                ifindex: 3,
                hook: Hook::Egress,
                chain: 0,
                prio: ACL_PRIO,
                protocol: Protocol::All,
                handle: 0,
            }
        );
    }
}
