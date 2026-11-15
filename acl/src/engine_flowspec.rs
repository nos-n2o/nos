//! The engine's flowspec source (#561): per pushing BGP instance a snapshot
//! of rules and devices; per device the band priority each rule holds.
//! Pushes and passes share the engine lock, like the ACL.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use nos_proto::{FlowRule, FlowspecRuleStatus, FlowspecSet};
use tracing::{error, info, warn};

use super::{resolve, Engine};
use crate::driver::Driver;
use crate::flowspec::{lower, Lowered, PRIO_FIRST, RULE_CAP};
use crate::plan::FlowspecDevices;

/// One snapshot's owner: (BGP instance, VRF), `None` = its own table.
type Key = (String, Option<String>);

const CAPPED: &str = "rule cap";
/// A rule no device holds: no `flowspec` device in the instance's table,
/// or the device is absent.
const NOT_ATTACHED: &str = "not attached";

/// One instance's last snapshot, each rule lowered once.
#[derive(Debug)]
struct Set {
    devices: Vec<String>,
    rules: Vec<FlowRule>,
    lowered: Vec<Result<Arc<Lowered>, String>>,
}

/// What one band priority holds.
#[derive(Debug, Clone, PartialEq)]
enum Held {
    Empty,
    /// Found at start (a previous run's) or left by a refused install:
    /// rewritten by the next pass.
    Unknown,
    /// `(owner, rule index, rule)`.
    Rule(Key, usize, Arc<Lowered>),
}

#[derive(Debug)]
struct Device {
    ifindex: u32,
    /// Index `i` is priority `PRIO_FIRST + i`.
    slots: Vec<Held>,
}

#[derive(Debug, Default)]
pub(super) struct State {
    sets: BTreeMap<Key, Set>,
    devices: BTreeMap<String, Device>,
    /// `(owner, flow, reason)` already logged as unsupported.
    logged: BTreeSet<(Key, String, String)>,
    /// Rules left out on some device by the cap: `(owner, index)`.
    capped: BTreeSet<(Key, usize)>,
    /// Devices named but absent, logged once.
    pending: BTreeSet<String>,
    /// Per owner, the `flowspec` devices of the last plan (#562, #1083),
    /// added to the devices its snapshot names.
    pub(super) attached: FlowspecDevices,
}

impl State {
    fn log_unsupported(&mut self, owner: &Key, flow: &str, reason: &str) {
        let key = (owner.clone(), flow.to_string(), reason.to_string());
        if self.logged.insert(key) {
            let table = owner.1.as_ref().map(tracing::field::display);
            warn!(instance = %owner.0, table, flow = %flow, reason = %reason, "flowspec rule unsupported");
        }
    }
}

fn prio(slot: usize) -> u16 {
    PRIO_FIRST + u16::try_from(slot).expect("slots stay inside the band")
}

impl<D: Driver> Engine<D> {
    /// Replaces `set.instance`'s rules (empty clears them) and applies.
    pub fn push_flowspec(&mut self, set: FlowspecSet) {
        let FlowspecSet {
            instance,
            table,
            devices,
            rules,
        } = set;
        let owner: Key = (instance, table);
        let flows: BTreeSet<&str> = rules.iter().map(|r| r.flow.as_str()).collect();
        // A rule logs once while it stays in its instance's snapshots.
        self.fs
            .logged
            .retain(|(o, f, _)| *o != owner || flows.contains(f.as_str()));
        let lowered: Vec<_> = rules.iter().map(|r| lower(r).map(Arc::new)).collect();
        for (r, l) in rules.iter().zip(&lowered) {
            if let Err(why) = l {
                self.fs.log_unsupported(&owner, &r.flow, why);
            }
        }
        let installable = lowered.iter().filter(|l| l.is_ok()).count();
        let vrf = owner.1.as_ref().map(tracing::field::display);
        info!(instance = %owner.0, table = vrf, rules = rules.len(), installable, devices = devices.len(), "flowspec rules received");
        if rules.is_empty() && devices.is_empty() {
            self.fs.sets.remove(&owner);
        } else {
            let set = Set {
                devices,
                rules,
                lowered,
            };
            self.fs.sets.insert(owner, set);
        }
        self.apply_flowspec();
    }

    /// Adopts what a previous run left in `ifindex`'s band (fail closed:
    /// enforced until a pass rewrites or clears it).
    pub(super) fn sweep_flowspec(&mut self, name: &str, ifindex: u32) {
        match self.driver.flowspec_prios(ifindex) {
            Ok(prios) if !prios.is_empty() => {
                let mut slots = Vec::new();
                for p in prios {
                    let i = usize::from(p - PRIO_FIRST);
                    slots.resize(slots.len().max(i + 1), Held::Empty);
                    slots[i] = Held::Unknown;
                }
                self.fs
                    .devices
                    .insert(name.to_string(), Device { ifindex, slots });
            }
            Ok(_) => {}
            Err(e) => warn!(interface = %name, error = %e, "could not read the flowspec filters"),
        }
    }

    /// Holds every device to the snapshots: per device, the instances in
    /// name order, their rules in order, one priority each up to the cap.
    pub(super) fn apply_flowspec(&mut self) {
        if !self.links.known || !self.swept {
            return;
        }
        let links = &self.links.links;
        // A device that went away took its qdisc, and our filters, with it.
        self.fs
            .devices
            .retain(|dev, d| links.get(dev).is_some_and(|l| l.ifindex == d.ifindex));

        let mut desired: BTreeMap<String, (u32, Vec<Held>)> = BTreeMap::new();
        let mut capped = BTreeSet::new();
        let mut pending = BTreeSet::new();
        for (owner, set) in &self.fs.sets {
            let attached = self.fs.attached.get(owner).into_iter().flatten();
            let named: BTreeSet<Result<String, String>> = set
                .devices
                .iter()
                .cloned()
                .map(Ok)
                .chain(attached.map(|d| resolve(d, &self.links)))
                .collect();
            for dev in named {
                let Some(link) = dev.as_ref().ok().and_then(|n| links.get(n)) else {
                    let (Ok(shown) | Err(shown)) = dev;
                    pending.insert(shown);
                    continue;
                };
                let (_, want) = desired
                    .entry(link.name.clone())
                    .or_insert_with(|| (link.ifindex, Vec::new()));
                for (i, l) in set.lowered.iter().enumerate() {
                    let Ok(l) = l else { continue };
                    if want.len() == RULE_CAP {
                        capped.insert((owner.clone(), i));
                    } else {
                        want.push(Held::Rule(owner.clone(), i, l.clone()));
                    }
                }
            }
        }
        for dev in pending.difference(&self.fs.pending) {
            info!(interface = %dev, reason = "absent", "flowspec pending");
        }
        self.fs.pending = pending;
        for (owner, i) in &capped {
            let flow = self.fs.sets[owner].rules[*i].flow.clone();
            self.fs.log_unsupported(owner, &flow, CAPPED);
        }
        self.fs.capped = capped;
        for (dev, d) in &self.fs.devices {
            desired
                .entry(dev.clone())
                .or_insert_with(|| (d.ifindex, Vec::new()));
        }
        for (dev, (ifindex, want)) in desired {
            self.apply_device(&dev, ifindex, &want);
        }
    }

    /// Rewrites the priorities of `dev` whose content differs from `want`.
    fn apply_device(&mut self, dev: &str, ifindex: u32, want: &[Held]) {
        let mut slots = self.fs.devices.remove(dev).map_or_default(|d| d.slots);
        let len = slots.len().max(want.len());
        slots.resize(len, Held::Empty);
        let mut changed = false;
        for (i, slot) in slots.iter_mut().enumerate() {
            let target = want.get(i).unwrap_or(&Held::Empty);
            if slot == target {
                continue;
            }
            changed = true;
            let rule = match target {
                Held::Rule(_, r, l) => Some((u32::try_from(*r).unwrap_or(u32::MAX), &**l)),
                _ => None,
            };
            *slot = match self.driver.flowspec_set(ifindex, prio(i), rule) {
                Ok(()) => target.clone(),
                Err(e) => {
                    error!(interface = %dev, prio = prio(i), error = %e, "flowspec rule not applied");
                    Held::Unknown
                }
            };
        }
        while slots.last() == Some(&Held::Empty) {
            slots.pop();
        }
        if changed {
            info!(interface = %dev, rules = want.len(), "flowspec applied");
        }
        if !slots.is_empty() {
            self.fs
                .devices
                .insert(dev.to_string(), Device { ifindex, slots });
        }
    }

    /// Every rule of every instance, with its state and counters summed over
    /// the devices it is installed on. A device whose dump fails is skipped.
    pub fn show_flowspec(&mut self) -> Vec<FlowspecRuleStatus> {
        let mut sums: BTreeMap<(&Key, usize), (u64, u64)> = BTreeMap::new();
        for (dev, d) in &self.fs.devices {
            let counts = match self.driver.flowspec_counters(d.ifindex) {
                Ok(c) => c,
                Err(e) => {
                    warn!(interface = %dev, error = %e, "could not read the flowspec counters");
                    continue;
                }
            };
            for (i, slot) in d.slots.iter().enumerate() {
                if let (Held::Rule(owner, r, _), Some((p, b))) = (slot, counts.get(&prio(i))) {
                    let s = sums.entry((owner, *r)).or_default();
                    s.0 = s.0.saturating_add(*p);
                    s.1 = s.1.saturating_add(*b);
                }
            }
        }
        let held: BTreeSet<(&Key, usize)> = self
            .fs
            .devices
            .values()
            .flat_map(|d| &d.slots)
            .filter_map(|s| match s {
                Held::Rule(owner, r, _) => Some((owner, *r)),
                _ => None,
            })
            .collect();
        let mut out = Vec::new();
        for (owner, set) in &self.fs.sets {
            for (i, (rule, l)) in set.rules.iter().zip(&set.lowered).enumerate() {
                let unsupported = match l {
                    Err(why) => Some(why.clone()),
                    Ok(_) if self.fs.capped.contains(&(owner.clone(), i)) => {
                        Some(CAPPED.to_string())
                    }
                    Ok(_) if !held.contains(&(owner, i)) => Some(NOT_ATTACHED.to_string()),
                    Ok(_) => None,
                };
                let (packets, bytes) = sums.get(&(owner, i)).copied().unwrap_or_default();
                out.push(FlowspecRuleStatus {
                    instance: owner.0.clone(),
                    table: owner.1.clone(),
                    flow: rule.flow.clone(),
                    actions: rule.actions.iter().map(ToString::to_string).collect(),
                    unsupported,
                    packets,
                    bytes,
                });
            }
        }
        out
    }
}

#[cfg(test)]
#[path = "engine_flowspec_tests.rs"]
mod tests;
