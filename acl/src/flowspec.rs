//! A Flow Specification rule to tc flower filters (pure, #561 part B).
//!
//! One rule is one family (its tc `protocol`) and one chain-0 priority in
//! the band [`PRIO_FIRST`]..=[`PRIO_LAST`]: every filter of the rule (the
//! alternatives a numeric expression or a type-4 port expands to) sits at
//! that priority with the same actions. What flower cannot express exactly
//! is refused, never approximated (owner decision D3 of #16).

use crate::compile::LATER_FRAGMENT;
use crate::driver::sample_kind;
use nos_proto::{FlowBitOp, FlowComponent, FlowNumOp, FlowRule, FlowRuleAction};
use nos_tc::{
    ActionKind, FlowerKeys, Pedit, PeditFamily, Protocol, RateUnit, Verdict, FLAG_FRAG_IS_FIRST,
    FLAG_IS_FRAGMENT,
};

/// The flowspec band on chain 0: below the ACL entry (100), above
/// `nos-fdbd`/`nos-interfaced` (1, 2). One priority per rule.
pub const PRIO_FIRST: u16 = 10;
pub const PRIO_LAST: u16 = 99;
/// Rules per device. ponytail: one priority per rule caps it at the band;
/// a chain of our own would lift it but a `goto chain` miss ends
/// classification (#563 spike), skipping the ACL.
pub const RULE_CAP: usize = (PRIO_LAST - PRIO_FIRST + 1) as usize;
/// Filters one rule may expand to.
pub const MAX_FILTERS: usize = 64;
/// Where a rule that stops flowspec evaluation (T bit clear) goes: a chain
/// whose one filter jumps to the live ACL chain (`driver::exit_request`),
/// so the ACL still applies. Empty (no ACL): classification ends, the
/// packet passes.
pub const EXIT_CHAIN: u32 = 999;
/// The psample group of a flowspec `sample` action ("FSP"), distinct from
/// the ACL's so `acl log` never names a flowspec cookie. ponytail: nothing
/// reads it yet; a consumer would log like `acl log`.
pub const PSAMPLE_GROUP: u32 = 0x46_5350;
/// Bytes of a sampled packet, as the ACL's `log`.
const SAMPLE_TRUNC: u32 = 128;
/// Smallest police burst in bytes: a jumbo frame and then some.
const MIN_BURST_BYTES: u64 = 16_384;

/// What a rule installs: one priority of `protocol` filters, one per key
/// set, each with `actions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lowered {
    pub protocol: Protocol,
    pub filters: Vec<FlowerKeys>,
    pub actions: Vec<ActionKind>,
}

/// Sorted, disjoint, inclusive intervals.
type Set = Vec<(u64, u64)>;

fn union(mut v: Set) -> Set {
    v.sort_unstable();
    let mut out: Set = Vec::new();
    for (lo, hi) in v {
        match out.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

fn intersect(a: &Set, b: &Set) -> Set {
    let mut out = Vec::new();
    for &(alo, ahi) in a {
        for &(blo, bhi) in b {
            let (lo, hi) = (alo.max(blo), ahi.min(bhi));
            if lo <= hi {
                out.push((lo, hi));
            }
        }
    }
    union(out)
}

/// One operator over `0..=max` (RFC 8955 Table 1).
fn op_set(o: &FlowNumOp, max: u64) -> Set {
    let v = o.value;
    let below = |hi: u64| (v > 0).then(|| (0, hi.min(max)));
    let above = |lo: u64| (lo <= max).then_some((lo, max));
    let s: Vec<Option<(u64, u64)>> = match (o.lt, o.gt, o.eq) {
        (false, false, false) => vec![],
        (false, false, true) => vec![(v <= max).then_some((v, v))],
        (false, true, false) => vec![v.checked_add(1).and_then(above)],
        (false, true, true) => vec![above(v)],
        (true, false, false) => vec![below(v.saturating_sub(1))],
        (true, false, true) => vec![Some((0, v.min(max)))],
        (true, true, false) => vec![below(v.saturating_sub(1)), v.checked_add(1).and_then(above)],
        (true, true, true) => vec![Some((0, max))],
    };
    union(s.into_iter().flatten().collect())
}

/// The values a numeric expression accepts: AND binds tighter than OR
/// (RFC 8955 section 4.2.1.1).
fn num_set(ops: &[FlowNumOp], max: u64) -> Set {
    let mut groups: Vec<Set> = Vec::new();
    for o in ops {
        let s = op_set(o, max);
        match groups.last_mut() {
            Some(g) if o.and => *g = intersect(g, &s),
            _ => groups.push(s),
        }
    }
    union(groups.concat())
}

fn count(s: &Set) -> u64 {
    s.iter().map(|(lo, hi)| hi - lo + 1).sum()
}

/// Every value of `s` (capped by the caller through [`count`]).
fn values(s: &Set) -> impl Iterator<Item = u64> + '_ {
    s.iter().flat_map(|&(lo, hi)| lo..=hi)
}

fn too_many() -> String {
    format!("more than {MAX_FILTERS} filters")
}

/// A bitmask expression as alternatives of `(bits, mask)` over the packet's
/// field, `None` when one operator has no exact form. `m` with `not` (not
/// all set) is exact only for a single bit.
fn bit_alternatives(ops: &[FlowBitOp]) -> Option<Vec<(u64, u64)>> {
    let mut groups: Vec<Vec<(u64, u64)>> = Vec::new();
    for o in ops {
        let v = o.value;
        let single = v.is_power_of_two();
        let alts: Vec<(u64, u64)> = match (o.m, o.not) {
            (true, false) => vec![(v, v)],
            (false, true) => vec![(0, v)],
            (_, true) if single => vec![(0, v)],
            (false, false) => (0..64)
                .map(|i| 1u64 << i)
                .filter(|b| v & b != 0)
                .map(|b| (b, b))
                .collect(),
            (true, true) => return None,
        };
        match groups.last_mut() {
            Some(g) if o.and => {
                let mut merged = Vec::new();
                for &(b1, m1) in g.iter() {
                    for &(b2, m2) in &alts {
                        // Consistent where both masks constrain the same bit.
                        if (b1 ^ b2) & m1 & m2 == 0 {
                            merged.push((b1 | b2, m1 | m2));
                        }
                    }
                }
                *g = merged;
            }
            _ => groups.push(alts),
        }
    }
    let mut out = groups.concat();
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// Fragment states flower tells apart: `(flags, mask)` of each.
const NOT_FRAGMENT: (u32, u32) = (0, FLAG_IS_FRAGMENT);
const FIRST_FRAGMENT: (u32, u32) = (
    FLAG_IS_FRAGMENT | FLAG_FRAG_IS_FIRST,
    FLAG_IS_FRAGMENT | FLAG_FRAG_IS_FIRST,
);

/// RFC 8955 type 12 bits.
const IS_F: u64 = 0x02;
const FF: u64 = 0x04;

/// A fragment expression as the flower states it accepts, by evaluating it
/// on each state's bits. DF and LF have no flower key: refused.
fn fragment_alternatives(ops: &[FlowBitOp]) -> Result<Vec<(u32, u32)>, String> {
    if ops.iter().any(|o| o.value & !(IS_F | FF) != 0) {
        return Err("fragment DF/LF bits: no flower key".into());
    }
    let states = [
        (NOT_FRAGMENT, 0),
        (FIRST_FRAGMENT, IS_F | FF),
        (LATER_FRAGMENT, IS_F),
    ];
    let eval = |bits: u64| {
        let mut acc: Option<bool> = None;
        let mut any = false;
        for o in ops {
            let hit = if o.m {
                bits & o.value == o.value
            } else {
                bits & o.value != 0
            };
            let hit = hit != o.not;
            acc = Some(match acc {
                Some(a) if o.and => a && hit,
                Some(a) => {
                    any |= a;
                    hit
                }
                None => hit,
            });
        }
        any || acc.unwrap_or(false)
    };
    let hits: Vec<(u32, u32)> = states
        .iter()
        .filter(|(_, b)| eval(*b))
        .map(|(s, _)| *s)
        .collect();
    Ok(match hits.as_slice() {
        [_, _, _] => vec![],
        [FIRST_FRAGMENT, LATER_FRAGMENT] => vec![(FLAG_IS_FRAGMENT, FLAG_IS_FRAGMENT)],
        [] => return Err("matches no packet".into()),
        _ => hits,
    })
}

/// `alts` times `n` stays under the cap.
fn fits(alts: &[FlowerKeys], n: u64) -> Result<(), String> {
    if (alts.len() as u64).saturating_mul(n) > MAX_FILTERS as u64 {
        Err(too_many())
    } else {
        Ok(())
    }
}

/// Each alternative once per value of `vals`, set by `set`.
fn expand<T: Copy>(
    alts: Vec<FlowerKeys>,
    vals: &[T],
    set: impl Fn(&mut FlowerKeys, T) -> bool,
) -> Result<Vec<FlowerKeys>, String> {
    fits(&alts, vals.len() as u64)?;
    let mut out = Vec::new();
    for a in alts {
        for &v in vals {
            let mut k = a.clone();
            if set(&mut k, v) {
                out.push(k);
            }
        }
    }
    Ok(out)
}

fn byte_values(ops: &[FlowNumOp], max: u64) -> Result<Vec<u8>, String> {
    let s = num_set(ops, max);
    if count(&s) > MAX_FILTERS as u64 {
        return Err(too_many());
    }
    Ok(values(&s).filter_map(|v| u8::try_from(v).ok()).collect())
}

fn port_ranges(ops: &[FlowNumOp]) -> Vec<(u16, u16)> {
    num_set(ops, u64::from(u16::MAX))
        .into_iter()
        .filter_map(|(lo, hi)| Some((u16::try_from(lo).ok()?, u16::try_from(hi).ok()?)))
        .collect()
}

/// `slot` narrowed to `r`; `false` when they do not overlap.
fn narrow(slot: &mut Option<(u16, u16)>, r: (u16, u16)) -> bool {
    let (lo, hi) = slot.map_or(r, |(a, b)| (a.max(r.0), b.min(r.1)));
    *slot = Some((lo, hi));
    lo <= hi
}

/// The protocols a key set may carry: ports TCP or UDP, TCP flags TCP,
/// ICMP keys the family's ICMP. `None`: unconstrained.
fn allowed_protocols(k: &FlowerKeys, icmp: u8) -> Option<Vec<u8>> {
    let mut allowed: Option<Vec<u8>> = None;
    let mut need = |set: &[u8]| {
        allowed = Some(match allowed.take() {
            Some(a) => a.into_iter().filter(|p| set.contains(p)).collect(),
            None => set.to_vec(),
        });
    };
    if k.src_port.is_some() || k.dst_port.is_some() {
        need(&[6, 17]);
    }
    if k.tcp_flags.is_some() {
        need(&[6]);
    }
    if k.icmp_type.is_some() || k.icmp_code.is_some() {
        need(&[icmp]);
    }
    allowed
}

fn keys(rule: &FlowRule) -> Result<Vec<FlowerKeys>, String> {
    let icmp = if rule.ipv6 { 58 } else { 1 };
    let mut alts = vec![FlowerKeys::default()];
    for c in &rule.components {
        alts = match c {
            FlowComponent::Dest { prefix, offset } | FlowComponent::Source { prefix, offset } => {
                if *offset != 0 {
                    return Err("ipv6 prefix offset".into());
                }
                let p = Some((prefix.addr(), prefix.prefix_len()));
                let dest = matches!(c, FlowComponent::Dest { .. });
                for a in &mut alts {
                    if dest {
                        a.dst_ip = p;
                    } else {
                        a.src_ip = p;
                    }
                }
                alts
            }
            FlowComponent::Protocol(ops) => expand(alts, &byte_values(ops, 255)?, |k, v| {
                k.ip_proto = Some(v);
                true
            })?,
            FlowComponent::Port(ops) => {
                let r = port_ranges(ops);
                let either: Vec<(bool, (u16, u16))> =
                    r.iter().flat_map(|&x| [(true, x), (false, x)]).collect();
                expand(alts, &either, |k, (src, x)| {
                    narrow(
                        if src {
                            &mut k.src_port
                        } else {
                            &mut k.dst_port
                        },
                        x,
                    )
                })?
            }
            FlowComponent::DstPort(ops) => {
                expand(alts, &port_ranges(ops), |k, x| narrow(&mut k.dst_port, x))?
            }
            FlowComponent::SrcPort(ops) => {
                expand(alts, &port_ranges(ops), |k, x| narrow(&mut k.src_port, x))?
            }
            FlowComponent::IcmpType(ops) => expand(alts, &byte_values(ops, 255)?, |k, v| {
                k.icmp_type = Some(v);
                true
            })?,
            FlowComponent::IcmpCode(ops) => expand(alts, &byte_values(ops, 255)?, |k, v| {
                k.icmp_code = Some(v);
                true
            })?,
            FlowComponent::TcpFlags(ops) => {
                let flags: Vec<(u16, u16)> = bit_alternatives(ops)
                    .and_then(|f| {
                        f.into_iter()
                            .map(|(b, m)| Some((u16::try_from(b).ok()?, u16::try_from(m).ok()?)))
                            .collect()
                    })
                    .ok_or_else(|| "tcp flags: no flags/mask form".to_string())?;
                expand(alts, &flags, |k, f| {
                    k.tcp_flags = Some(f);
                    true
                })?
            }
            FlowComponent::PacketLen(_) => return Err("packet length: no flower key".into()),
            FlowComponent::Dscp(ops) => expand(alts, &byte_values(ops, 63)?, |k, v| {
                k.ip_tos = Some(v);
                true
            })?,
            FlowComponent::Fragment(ops) => {
                let f = fragment_alternatives(ops)?;
                if f.is_empty() {
                    alts
                } else {
                    expand(alts, &f, |k, x| {
                        k.flags = Some(x);
                        true
                    })?
                }
            }
            FlowComponent::FlowLabel(_) => return Err("flow label: no flower key".into()),
        };
    }
    // Ports, TCP flags and ICMP keys need their protocol: set it when the
    // rule has none, drop the alternatives where it contradicts them.
    let mut out = Vec::new();
    for k in alts {
        match (allowed_protocols(&k, icmp), k.ip_proto) {
            (None, _) => out.push(k),
            (Some(set), Some(p)) => {
                if set.contains(&p) {
                    out.push(k);
                }
            }
            (Some(set), None) => out.extend(set.into_iter().map(|p| FlowerKeys {
                ip_proto: Some(p),
                ..k.clone()
            })),
        }
    }
    if out.is_empty() {
        return Err("matches no packet".into());
    }
    if out.len() > MAX_FILTERS {
        return Err(too_many());
    }
    Ok(out)
}

/// The tc actions, in order: sample, DSCP rewrite, police or drop, then the
/// verdict. The first traffic-rate and marking win (the sender already
/// drops shadowed rates).
fn actions(rule: &FlowRule) -> Result<Vec<ActionKind>, String> {
    let (mut sample, mut terminal) = (false, false);
    let (mut dscp, mut rate) = (None, None);
    for a in &rule.actions {
        match a {
            FlowRuleAction::Unsupported(why) => return Err(why.clone()),
            FlowRuleAction::RateBytes(r) => {
                rate.get_or_insert((*r, RateUnit::Bytes));
            }
            FlowRuleAction::RatePackets(r) => {
                rate.get_or_insert((*r, RateUnit::Packets));
            }
            FlowRuleAction::TrafficAction {
                sample: s,
                terminal: t,
            } => {
                sample |= s;
                terminal |= t;
            }
            FlowRuleAction::Dscp(d) => {
                dscp.get_or_insert(*d & 0x3f);
            }
        }
    }
    let mut out = Vec::new();
    if sample {
        out.push(sample_kind(SAMPLE_TRUNC, PSAMPLE_GROUP));
    }
    if let Some(value) = dscp {
        let family = if rule.ipv6 {
            PeditFamily::Ipv6
        } else {
            PeditFamily::Ip
        };
        out.push(ActionKind::Pedit(Pedit::Dscp { value, family }));
    }
    match rate {
        // 0 (a negative rate decodes to 0) discards: final whatever T says.
        Some((r, _)) if r <= 0.0 => {
            out.push(ActionKind::Gact(Verdict::Shot));
            return Ok(out);
        }
        Some((r, unit)) => {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "saturating, positive"
            )]
            let rate = r.ceil() as u64;
            // ponytail: burst = one second of rate; a burst knob if it bites.
            let floor = match unit {
                RateUnit::Bytes => MIN_BURST_BYTES,
                RateUnit::Packets => 1,
            };
            let burst = u32::try_from(rate.max(floor)).unwrap_or(u32::MAX);
            out.push(ActionKind::Police { rate, burst, unit });
        }
        None => {}
    }
    // The T bit set: later rules also apply (RFC 8955 section 7.3).
    let verdict = if terminal {
        Verdict::Unspec
    } else {
        Verdict::GotoChain(EXIT_CHAIN)
    };
    out.push(ActionKind::Gact(verdict));
    Ok(out)
}

/// `rule` as one priority of filters, or why it cannot be installed.
pub fn lower(rule: &FlowRule) -> Result<Lowered, String> {
    let actions = actions(rule)?;
    let filters = keys(rule)?;
    let protocol = if rule.ipv6 {
        Protocol::Ipv6
    } else {
        Protocol::Ip
    };
    Ok(Lowered {
        protocol,
        filters,
        actions,
    })
}

#[cfg(test)]
#[path = "flowspec_tests.rs"]
mod tests;
