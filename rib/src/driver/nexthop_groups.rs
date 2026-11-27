//! Pure bookkeeping of the kernel nexthop objects `nos-ribd` owns for one
//! table (#1587): which hop and group ids exist, which slots use which group.
//! No netlink here; `linux.rs` does the I/O and feeds the results back.
//!
//! Ids are `table_id << 20 | seq` (`seq` from 1; hops and groups share the
//! space; freed seqs are reused). Nothing outside `range()` is ever listed or
//! deleted.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::ops::RangeInclusive;

use nos_nexthop::NexthopRecord;
use nos_proto::IpNet;

/// Bits of an id below the table id.
const SEQ_BITS: u32 = 20;
const SEQ_MAX: u32 = (1 << SEQ_BITS) - 1;

/// A kernel route slot (prefix, backup), as `linux.rs` calls it.
pub type Slot = (IpNet, bool);

/// What a gateway nexthop object carries: `(gateway, oif, onlink, labels)`.
/// Unlike the route `Key`, it holds the oif and onlink actually sent.
pub type HopKey = (IpAddr, Option<u32>, bool, Vec<u32>);
/// A group's members, sorted.
pub type GroupKey = Vec<HopKey>;

/// The ids `ensure` reserved: what `linux.rs` must still create, in order
/// (hops first, the group last).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub group: u32,
    /// `group` was not known: it must be created.
    pub new_group: bool,
    /// Every member id, in `GroupKey` order.
    pub members: Vec<u32>,
    /// The hops to create.
    pub new_hops: Vec<(u32, HopKey)>,
}

#[derive(Debug)]
pub struct NexthopTable {
    base: u32,
    hops: HashMap<HopKey, u32>,
    groups: HashMap<GroupKey, u32>,
    /// Member ids of each group, for the garbage collection.
    members: HashMap<u32, Vec<u32>>,
    next_seq: u32,
    free: BTreeSet<u32>,
    /// The group each slot's installed route uses.
    slots: HashMap<Slot, u32>,
    refs: HashMap<u32, usize>,
}

impl NexthopTable {
    pub fn new(table_id: u32) -> Self {
        Self {
            base: table_id << SEQ_BITS,
            hops: HashMap::new(),
            groups: HashMap::new(),
            members: HashMap::new(),
            next_seq: 1,
            free: BTreeSet::new(),
            slots: HashMap::new(),
            refs: HashMap::new(),
        }
    }

    /// The ids this table may list or delete.
    pub fn range(&self) -> RangeInclusive<u32> {
        self.base..=self.base + SEQ_MAX
    }

    fn alloc(&mut self) -> Option<u32> {
        if let Some(seq) = self.free.pop_first() {
            return Some(self.base | seq);
        }
        (self.next_seq <= SEQ_MAX).then(|| {
            self.next_seq += 1;
            self.base | (self.next_seq - 1)
        })
    }

    fn release_id(&mut self, id: u32) {
        self.free.insert(id & SEQ_MAX);
    }

    /// Reserves the ids a group over `key` needs (nothing for what exists).
    /// `None`: out of ids, the caller installs inline. The reservation stays
    /// until `forget` (creation failed) or until the garbage collection.
    pub fn ensure(&mut self, key: &GroupKey) -> Option<Plan> {
        let mut plan = Plan::default();
        for hop in key {
            let id = match self.hops.get(hop) {
                Some(id) => *id,
                None => match self.alloc() {
                    Some(id) => {
                        self.hops.insert(hop.clone(), id);
                        plan.new_hops.push((id, hop.clone()));
                        id
                    }
                    None => {
                        self.forget(&plan);
                        return None;
                    }
                },
            };
            plan.members.push(id);
        }
        match self.groups.get(key) {
            Some(id) => plan.group = *id,
            None => {
                let Some(id) = self.alloc() else {
                    self.forget(&plan);
                    return None;
                };
                self.groups.insert(key.clone(), id);
                self.members.insert(id, plan.members.clone());
                plan.group = id;
                plan.new_group = true;
            }
        }
        Some(plan)
    }

    /// Undoes `ensure`'s reservations (the kernel refused the creation).
    pub fn forget(&mut self, plan: &Plan) {
        for (id, hop) in &plan.new_hops {
            self.hops.remove(hop);
            self.release_id(*id);
        }
        if plan.new_group {
            self.groups.retain(|_, id| *id != plan.group);
            self.members.remove(&plan.group);
            self.release_id(plan.group);
        }
    }

    /// Slot `slot`'s installed route now uses group `gid` (none: inline or
    /// gone).
    pub fn set_slot(&mut self, slot: Slot, gid: Option<u32>) {
        let old = match gid {
            Some(g) => self.slots.insert(slot, g),
            None => self.slots.remove(&slot),
        };
        if old == gid {
            return;
        }
        if let Some(o) = old
            && let Some(n) = self.refs.get_mut(&o)
        {
            *n -= 1;
            if *n == 0 {
                self.refs.remove(&o);
            }
        }
        if let Some(g) = gid {
            *self.refs.entry(g).or_default() += 1;
        }
    }

    /// Replaces every slot's group at once; `extra` are groups kept alive by
    /// routes the shadow does not hold (stale routes kept by the startup
    /// hold, #654).
    pub fn reset_slots(&mut self, slots: HashMap<Slot, u32>, extra: impl IntoIterator<Item = u32>) {
        self.refs.clear();
        for g in slots.values().copied().chain(extra) {
            *self.refs.entry(g).or_default() += 1;
        }
        self.slots = slots;
    }

    /// Takes the objects nothing uses: groups first, then the hops no
    /// remaining group has. The caller deletes them in that order.
    pub fn take_unreferenced(&mut self) -> (Vec<u32>, Vec<u32>) {
        let mut groups: Vec<u32> = self
            .groups
            .values()
            .copied()
            .filter(|g| !self.refs.contains_key(g))
            .collect();
        groups.sort_unstable();
        for g in &groups {
            self.members.remove(g);
            self.release_id(*g);
        }
        self.groups.retain(|_, id| !groups.contains(id));
        let used: HashSet<u32> = self.members.values().flatten().copied().collect();
        let mut hops: Vec<u32> = self
            .hops
            .values()
            .copied()
            .filter(|h| !used.contains(h))
            .collect();
        hops.sort_unstable();
        for h in &hops {
            self.release_id(*h);
        }
        self.hops.retain(|_, id| used.contains(id));
        (groups, hops)
    }

    /// Rebuilds the hop and group maps from a kernel dump, so a restarted
    /// `nos-ribd` adopts its own objects instead of recreating them. Slots
    /// and refs are left to `reset_slots`.
    pub fn seed(&mut self, records: &[NexthopRecord]) {
        let range = self.range();
        let mut hop_of: HashMap<u32, HopKey> = HashMap::new();
        for r in records.iter().filter(|r| range.contains(&r.id)) {
            if let (Some(gw), false) = (r.gateway, r.fdb) {
                hop_of.insert(r.id, (gw, r.oif, r.onlink, r.labels.clone()));
            }
        }
        self.hops = hop_of.iter().map(|(id, h)| (h.clone(), *id)).collect();
        self.groups.clear();
        self.members.clear();
        let mut max = 0;
        for r in records.iter().filter(|r| range.contains(&r.id)) {
            max = max.max(r.id & SEQ_MAX);
            let Some(group) = &r.group else { continue };
            let ids: Vec<u32> = group.iter().map(|(id, _)| *id).collect();
            let mut key: Option<GroupKey> = ids.iter().map(|i| hop_of.get(i).cloned()).collect();
            if let Some(k) = key.as_mut() {
                // Same order as `key`'s sort; members follow it.
                let mut paired: Vec<_> = k.drain(..).zip(ids).collect();
                paired.sort();
                let (k2, ids2): (Vec<_>, Vec<_>) = paired.into_iter().unzip();
                self.groups.insert(k2, r.id);
                self.members.insert(r.id, ids2);
            }
        }
        self.next_seq = max + 1;
        let used: HashSet<u32> = records
            .iter()
            .filter(|r| range.contains(&r.id))
            .map(|r| r.id & SEQ_MAX)
            .collect();
        self.free = (1..=max).filter(|s| !used.contains(s)).collect();
    }

    /// The group an installed route (id `gid`) belongs to, for a log line.
    #[cfg(test)]
    fn group_len(&self, gid: u32) -> usize {
        self.members.get(&gid).map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(gw: &str, oif: u32) -> HopKey {
        (gw.parse().unwrap(), Some(oif), false, vec![])
    }
    fn key(hops: &[HopKey]) -> GroupKey {
        let mut k = hops.to_vec();
        k.sort();
        k
    }
    fn slot(p: &str) -> Slot {
        (p.parse().unwrap(), false)
    }

    #[test]
    fn ids_live_in_the_tables_range() {
        let mut t = NexthopTable::new(100);
        let p = t
            .ensure(&key(&[hop("10.0.0.1", 2), hop("10.0.0.2", 3)]))
            .unwrap();
        assert!(p.new_group);
        assert_eq!(p.new_hops.len(), 2);
        for id in p.members.iter().chain([&p.group]) {
            assert!(t.range().contains(id));
            assert_eq!(id >> SEQ_BITS, 100);
        }
        assert_eq!(*t.range().start(), 100 << 20);
        assert_eq!(t.group_len(p.group), 2);
    }

    #[test]
    fn the_same_hop_set_shares_one_group_and_hops_are_shared() {
        let mut t = NexthopTable::new(100);
        let a = hop("10.0.0.1", 2);
        let b = hop("10.0.0.2", 3);
        let c = hop("10.0.0.3", 4);
        let p1 = t.ensure(&key(&[a.clone(), b.clone()])).unwrap();
        let p2 = t.ensure(&key(&[b.clone(), a.clone()])).unwrap();
        assert!(!p2.new_group && p2.new_hops.is_empty());
        assert_eq!(p1.group, p2.group);
        let p3 = t.ensure(&key(&[a, c])).unwrap();
        assert!(p3.new_group);
        assert_eq!(p3.new_hops.len(), 1);
        assert_ne!(p3.group, p1.group);
    }

    #[test]
    fn a_label_stack_makes_another_hop() {
        let mut t = NexthopTable::new(100);
        let plain = hop("10.0.0.1", 2);
        let mut labelled = plain.clone();
        labelled.3 = vec![100];
        let other = hop("10.0.0.2", 3);
        let p1 = t.ensure(&key(&[plain, other.clone()])).unwrap();
        let p2 = t.ensure(&key(&[labelled, other])).unwrap();
        assert_ne!(p1.group, p2.group);
        assert_eq!(p2.new_hops.len(), 1);
    }

    #[test]
    fn refcounts_hold_a_group_until_its_last_slot_goes() {
        let mut t = NexthopTable::new(100);
        let p = t
            .ensure(&key(&[hop("10.0.0.1", 2), hop("10.0.0.2", 3)]))
            .unwrap();
        t.set_slot(slot("10.1.0.0/16"), Some(p.group));
        t.set_slot(slot("10.2.0.0/16"), Some(p.group));
        assert_eq!(t.take_unreferenced(), (vec![], vec![]));
        t.set_slot(slot("10.1.0.0/16"), None);
        assert_eq!(t.take_unreferenced(), (vec![], vec![]));
        // Moving a slot between groups releases the old one.
        let q = t
            .ensure(&key(&[hop("10.0.0.1", 2), hop("10.0.0.9", 3)]))
            .unwrap();
        t.set_slot(slot("10.2.0.0/16"), Some(q.group));
        let (groups, hops) = t.take_unreferenced();
        assert_eq!(groups, vec![p.group]);
        // 10.0.0.2 is used by no remaining group; 10.0.0.1 still is.
        assert_eq!(hops, vec![p.members[1]]);
    }

    #[test]
    fn collection_lists_groups_before_hops_and_reuses_ids() {
        let mut t = NexthopTable::new(100);
        let p = t
            .ensure(&key(&[hop("10.0.0.1", 2), hop("10.0.0.2", 3)]))
            .unwrap();
        let (groups, hops) = t.take_unreferenced();
        assert_eq!(groups, vec![p.group]);
        assert_eq!(hops.len(), 2);
        // Freed ids come back, smallest first.
        let again = t.ensure(&key(&[hop("10.0.0.5", 2)])).unwrap();
        assert_eq!(again.new_hops[0].0 & SEQ_MAX, 1);
    }

    #[test]
    fn forget_gives_a_failed_creation_back() {
        let mut t = NexthopTable::new(100);
        let k = key(&[hop("10.0.0.1", 2), hop("10.0.0.2", 3)]);
        let p = t.ensure(&k).unwrap();
        t.forget(&p);
        assert_eq!(t.take_unreferenced(), (vec![], vec![]));
        let p2 = t.ensure(&k).unwrap();
        assert!(p2.new_group && p2.new_hops.len() == 2);
    }

    #[test]
    fn running_out_of_ids_is_none_and_leaves_nothing_behind() {
        let mut t = NexthopTable::new(100);
        t.next_seq = SEQ_MAX; // one id left
        assert!(t
            .ensure(&key(&[hop("10.0.0.1", 2), hop("10.0.0.2", 3)]))
            .is_none());
        assert!(t.hops.is_empty() && t.groups.is_empty());
        // The id the rollback freed is back in the pool.
        assert_eq!(t.free.len(), 1);
    }

    #[test]
    fn seed_adopts_the_kernels_objects() {
        let mut t = NexthopTable::new(100);
        let a = hop("10.0.0.1", 2);
        let b = hop("10.0.0.2", 3);
        let id = |n: u32| (100 << SEQ_BITS) | n;
        let rec = |n, h: &HopKey| NexthopRecord {
            id: id(n),
            gateway: Some(h.0),
            oif: h.1,
            onlink: h.2,
            labels: h.3.clone(),
            ..Default::default()
        };
        let records = vec![
            rec(1, &a),
            rec(2, &b),
            NexthopRecord {
                id: id(5),
                group: Some(vec![(id(2), 1), (id(1), 1)]),
                ..Default::default()
            },
        ];
        t.seed(&records);
        let p = t.ensure(&key(&[a.clone(), b.clone()])).unwrap();
        assert!(!p.new_group && p.new_hops.is_empty());
        assert_eq!(p.group, id(5));
        // Members follow the key's sort order.
        assert_eq!(p.members, vec![id(1), id(2)]);
        // Seqs 3 and 4 are free, the next fresh one is 6.
        let n = t.ensure(&key(&[hop("10.0.0.7", 2)])).unwrap();
        assert_eq!(n.new_hops[0].0, id(3));
        t.reset_slots(HashMap::from([(slot("10.1.0.0/16"), id(5))]), []);
        assert_eq!(t.take_unreferenced().0, vec![n.group]);
    }

    #[test]
    fn stale_routes_keep_their_group() {
        let mut t = NexthopTable::new(100);
        let p = t
            .ensure(&key(&[hop("10.0.0.1", 2), hop("10.0.0.2", 3)]))
            .unwrap();
        t.reset_slots(HashMap::new(), [p.group]);
        assert_eq!(t.take_unreferenced(), (vec![], vec![]));
        t.reset_slots(HashMap::new(), []);
        assert_eq!(t.take_unreferenced().0, vec![p.group]);
    }

    #[test]
    fn foreign_ids_are_ignored_by_seed() {
        let mut t = NexthopTable::new(100);
        t.seed(&[NexthopRecord {
            id: 7,
            gateway: Some("10.0.0.1".parse().unwrap()),
            ..Default::default()
        }]);
        assert!(t.hops.is_empty());
    }
}
