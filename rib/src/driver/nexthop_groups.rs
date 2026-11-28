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
    /// `reset_slots` ran: the slots are the kernel's truth, so unreferenced
    /// objects really are garbage. Before that (a delta before the first
    /// full `apply`) nothing is collected.
    reconciled: bool,
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
            reconciled: false,
        }
    }

    /// The group slot `slot`'s installed route uses.
    pub fn slot_gid(&self, slot: &Slot) -> Option<u32> {
        self.slots.get(slot).copied()
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
        let mut plan = self.reserve_hops(key)?;
        if let Some(id) = self.groups.get(key) {
            plan.group = *id;
        } else {
            let Some(id) = self.alloc() else {
                self.forget(&plan);
                return None;
            };
            self.groups.insert(key.clone(), id);
            self.members.insert(id, plan.members.clone());
            plan.group = id;
            plan.new_group = true;
        }
        Some(plan)
    }

    /// Reserves the hop ids of `key` only (no group): `Plan.group` is 0.
    /// `None`: out of ids, nothing is left reserved.
    pub fn reserve_hops(&mut self, key: &GroupKey) -> Option<Plan> {
        let mut plan = Plan::default();
        for hop in key {
            let id = if let Some(id) = self.hops.get(hop) {
                *id
            } else if let Some(id) = self.alloc() {
                self.hops.insert(hop.clone(), id);
                plan.new_hops.push((id, hop.clone()));
                id
            } else {
                self.forget(&plan);
                return None;
            };
            plan.members.push(id);
        }
        Some(plan)
    }

    /// Group `gid` now has the members of `key` (the kernel replaced it in
    /// place, #1588): the key map follows, the slots keep their group.
    pub fn repoint(&mut self, gid: u32, key: GroupKey, members: Vec<u32>) {
        self.groups.retain(|_, id| *id != gid);
        self.groups.insert(key, gid);
        self.members.insert(gid, members);
    }

    /// The groups a batch may replace in place instead of moving each of
    /// their slots (#1588). `want` holds every touched slot that now uses a
    /// group, with the group key it wants (`None`: leaves group form or
    /// cannot say). A group is repointed to `K'` when every slot using it is
    /// in `want` (an untouched user would be moved too), all want the same
    /// `K'` (2+ hops, not the current key), and no other live or already
    /// chosen group has `K'` (the key map stays injective).
    pub fn plan_repoints(&self, want: &HashMap<Slot, Option<GroupKey>>) -> Vec<(u32, GroupKey)> {
        let mut by_group: HashMap<u32, (usize, Option<&Option<GroupKey>>, bool)> = HashMap::new();
        for (slot, k) in want {
            let Some(g) = self.slots.get(slot) else {
                continue;
            };
            let e = by_group.entry(*g).or_insert((0, None, true));
            e.0 += 1;
            match e.1 {
                None => e.1 = Some(k),
                Some(first) => e.2 &= first == k,
            }
        }
        let mut claimed: HashSet<GroupKey> = HashSet::new();
        let mut out: Vec<(u32, GroupKey)> = by_group
            .into_iter()
            .filter_map(|(g, (n, k, same))| {
                let k = k?.as_ref()?;
                (same && n == self.refs.get(&g).copied().unwrap_or(0)).then_some((g, k))
            })
            .filter(|(g, k)| {
                k.len() >= 2 && !self.groups.contains_key(*k) && self.members.contains_key(g)
            })
            .map(|(g, k)| (g, k.clone()))
            .collect();
        out.sort_by_key(|(g, _)| *g);
        out.retain(|(_, k)| claimed.insert(k.clone()));
        out
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
        self.reconciled = true;
    }

    /// Takes the objects nothing uses: groups first, then the hops no
    /// remaining group has. The caller deletes them in that order.
    pub fn take_unreferenced(&mut self) -> (Vec<u32>, Vec<u32>) {
        if !self.reconciled {
            return (vec![], vec![]);
        }
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

    fn table() -> NexthopTable {
        NexthopTable {
            reconciled: true,
            ..NexthopTable::new(100)
        }
    }

    #[test]
    fn nothing_is_collected_before_the_first_reconcile() {
        let mut t = NexthopTable::new(100);
        t.ensure(&key(&[hop("10.0.0.1", 2)])).unwrap();
        assert_eq!(t.take_unreferenced(), (vec![], vec![]));
    }

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
        let mut t = table();
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
        let mut t = table();
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
        let mut t = table();
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
        let mut t = table();
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
        let mut t = table();
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
        let mut t = table();
        let k = key(&[hop("10.0.0.1", 2), hop("10.0.0.2", 3)]);
        let p = t.ensure(&k).unwrap();
        t.forget(&p);
        assert_eq!(t.take_unreferenced(), (vec![], vec![]));
        let p2 = t.ensure(&k).unwrap();
        assert!(p2.new_group && p2.new_hops.len() == 2);
    }

    #[test]
    fn running_out_of_ids_is_none_and_leaves_nothing_behind() {
        let mut t = table();
        t.next_seq = SEQ_MAX; // one id left
        assert!(t
            .ensure(&key(&[hop("10.0.0.1", 2), hop("10.0.0.2", 3)]))
            .is_none());
        assert!(t.hops.is_empty() && t.groups.is_empty());
        // The id the rollback freed is back in the pool.
        assert_eq!(t.free.len(), 1);
    }

    #[test]
    #[allow(clippy::many_single_char_names, reason = "a, b: two hops")]
    fn seed_adopts_the_kernels_objects() {
        let mut t = table();
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
        let mut t = table();
        let p = t
            .ensure(&key(&[hop("10.0.0.1", 2), hop("10.0.0.2", 3)]))
            .unwrap();
        t.reset_slots(HashMap::new(), [p.group]);
        assert_eq!(t.take_unreferenced(), (vec![], vec![]));
        t.reset_slots(HashMap::new(), []);
        assert_eq!(t.take_unreferenced().0, vec![p.group]);
    }

    #[test]
    #[allow(
        clippy::many_single_char_names,
        clippy::similar_names,
        reason = "hops a..d and their keys"
    )]
    fn repoint_planning() {
        let mut t = table();
        let (a, b, c) = (hop("10.0.0.1", 2), hop("10.0.0.2", 3), hop("10.0.0.3", 4));
        let k_ab = key(&[a.clone(), b.clone()]);
        let k_ac = key(&[a.clone(), c.clone()]);
        let p = t.ensure(&k_ab).unwrap();
        let n = 1000;
        let slots: Vec<Slot> = (0..n)
            .map(|i| slot(&format!("10.{}.{}.0/24", i / 256, i % 256)))
            .collect();
        for s in &slots {
            t.set_slot(*s, Some(p.group));
        }
        let all = |k: Option<GroupKey>| -> HashMap<Slot, Option<GroupKey>> {
            slots.iter().map(|s| (*s, k.clone())).collect()
        };
        // 1000 slots, one group: one request instead of 1000 route replaces.
        assert_eq!(
            t.plan_repoints(&all(Some(k_ac.clone()))),
            vec![(p.group, k_ac.clone())]
        );
        // An untouched user, a single hop, no key, the current key: no.
        let mut part = all(Some(k_ac.clone()));
        part.remove(&slots[0]);
        assert_eq!(t.plan_repoints(&part), vec![]);
        assert_eq!(t.plan_repoints(&all(Some(key(std::slice::from_ref(&a))))), vec![]);
        assert_eq!(t.plan_repoints(&all(None)), vec![]);
        assert_eq!(t.plan_repoints(&all(Some(k_ab.clone()))), vec![]);
        // Users disagree.
        let mut mixed = all(Some(k_ac.clone()));
        mixed.insert(slots[0], Some(key(&[b.clone(), c.clone()])));
        assert_eq!(t.plan_repoints(&mixed), vec![]);
        // K' is another live group.
        let q = t.ensure(&k_ac).unwrap();
        assert_eq!(t.plan_repoints(&all(Some(k_ac.clone()))), vec![]);
        t.set_slot(slot("11.0.0.0/8"), Some(q.group));
        // Commit: the key map follows, the old key is free again.
        t.repoint(p.group, k_ac.clone(), vec![p.members[0], q.members[1]]);
        assert_eq!(t.ensure(&k_ac).unwrap().group, p.group);
    }

    #[test]
    #[allow(clippy::many_single_char_names, reason = "hops a..d")]
    fn two_groups_never_repoint_to_one_key() {
        let mut t = table();
        let (a, b, c, d) = (
            hop("10.0.0.1", 2),
            hop("10.0.0.2", 3),
            hop("10.0.0.3", 4),
            hop("10.0.0.4", 5),
        );
        let g1 = t.ensure(&key(&[a.clone(), b.clone()])).unwrap().group;
        let g2 = t.ensure(&key(&[a.clone(), d.clone()])).unwrap().group;
        t.set_slot(slot("10.1.0.0/16"), Some(g1));
        t.set_slot(slot("10.2.0.0/16"), Some(g2));
        let k = key(&[a, c]);
        let want = HashMap::from([
            (slot("10.1.0.0/16"), Some(k.clone())),
            (slot("10.2.0.0/16"), Some(k)),
        ]);
        assert_eq!(t.plan_repoints(&want).len(), 1);
    }

    #[test]
    fn foreign_ids_are_ignored_by_seed() {
        let mut t = table();
        t.seed(&[NexthopRecord {
            id: 7,
            gateway: Some("10.0.0.1".parse().unwrap()),
            ..Default::default()
        }]);
        assert!(t.hops.is_empty());
    }
}
