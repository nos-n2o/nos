//! LACP conversation steering (#895), the pure half: what the tc filters of
//! one aggregate should be, and the ordered operations that get from what is
//! installed to that. `linux.rs` executes the operations through `nos-tc`.
//!
//! The two masks of 802.1AX 6.6: the bond's egress redirect is the
//! Distribution mask (conversation -> its link), a member's ingress drop is
//! the Collection mask (conversations mapped to another link). Conversations
//! `1..=4094` only: 0 (untagged) cannot be matched by flower and 4095 is
//! reserved.

use std::collections::{BTreeMap, BTreeSet};

use nos_proto::interface::LACP_CONVERSATION_MASK_LEN;

/// The tc priority both hooks use (`tc/CLAUDE.md`'s table).
pub const STEERING_PRIO: u16 = 3;

/// The whole desired steering of one aggregate: empty `links` = remove all.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SteeringState {
    pub aggregate: String,
    /// `lacp-port-algorithm s-vlan`: match the 802.1ad tag instead of 802.1Q.
    pub s_vlan: bool,
    /// Install the member ingress drops (the partner agreed, 6.6.3).
    pub discard_wrong: bool,
    /// Member interface name and the conversations its mask carries, in the
    /// order the push listed the links.
    pub links: Vec<(String, Vec<u16>)>,
}

/// Conversation ids `1..=4094` set in `mask` (bit `0x80 >> (c % 8)` of byte
/// `c / 8`); empty for a malformed mask.
pub fn conversations_of(mask: &[u8]) -> Vec<u16> {
    if mask.len() != LACP_CONVERSATION_MASK_LEN {
        return Vec::new();
    }
    (1u16..=4094)
        .filter(|c| mask[usize::from(c / 8)] & (0x80 >> (c % 8)) != 0)
        .collect()
}

/// Filters of one aggregate: conversation -> member for the bond egress, and
/// the conversations each member drops on ingress.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Wanted {
    pub redirects: BTreeMap<u16, String>,
    pub drops: BTreeMap<String, BTreeSet<u16>>,
}

impl Wanted {
    pub fn from_state(s: &SteeringState) -> Self {
        let mut redirects = BTreeMap::new();
        for (member, convs) in &s.links {
            for c in convs {
                redirects.entry(*c).or_insert_with(|| member.clone());
            }
        }
        let mut drops = BTreeMap::new();
        if s.discard_wrong {
            for (member, convs) in &s.links {
                let own: BTreeSet<u16> = convs.iter().copied().collect();
                let d: BTreeSet<u16> = redirects
                    .keys()
                    .copied()
                    .filter(|c| !own.contains(c))
                    .collect();
                if !d.is_empty() {
                    drops.insert(member.clone(), d);
                }
            }
        }
        Self { redirects, drops }
    }

    pub fn is_empty(&self) -> bool {
        self.redirects.is_empty() && self.drops.is_empty()
    }
}

/// One tc change, in the order it must run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    AddDrop(String, u16),
    Redirect(u16, String),
    DelRedirect(u16),
    DelDrop(String, u16),
}

/// From `have` to `want`: drops first added, then the redirects re-pointed,
/// then the obsolete drops removed, so a conversation is never collectable on
/// two links at once (802.1AX p.98, NOTE 1 p.102). A `have` redirect whose
/// target is unknown is the empty string: always rewritten.
pub fn plan(want: &Wanted, have: &Wanted) -> Vec<Op> {
    let mut ops = Vec::new();
    for (m, ds) in &want.drops {
        for c in ds {
            if !have.drops.get(m).is_some_and(|h| h.contains(c)) {
                ops.push(Op::AddDrop(m.clone(), *c));
            }
        }
    }
    for (c, m) in &want.redirects {
        if have.redirects.get(c) != Some(m) {
            ops.push(Op::Redirect(*c, m.clone()));
        }
    }
    for c in have.redirects.keys() {
        if !want.redirects.contains_key(c) {
            ops.push(Op::DelRedirect(*c));
        }
    }
    for (m, hs) in &have.drops {
        for c in hs {
            if !want.drops.get(m).is_some_and(|w| w.contains(c)) {
                ops.push(Op::DelDrop(m.clone(), *c));
            }
        }
    }
    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(links: &[(&str, &[u16])], discard_wrong: bool) -> SteeringState {
        SteeringState {
            aggregate: "a".into(),
            s_vlan: false,
            discard_wrong,
            links: links
                .iter()
                .map(|(m, c)| ((*m).to_string(), c.to_vec()))
                .collect(),
        }
    }

    fn mask(ids: &[u16]) -> Vec<u8> {
        let mut m = vec![0u8; LACP_CONVERSATION_MASK_LEN];
        for c in ids {
            m[usize::from(c / 8)] |= 0x80 >> (c % 8);
        }
        m
    }

    #[test]
    fn mask_decoding_skips_zero_and_reserved() {
        assert_eq!(conversations_of(&mask(&[0, 10, 4094, 4095])), [10, 4094]);
        assert!(conversations_of(&[0xff; 3]).is_empty(), "malformed");
    }

    #[test]
    fn wanted_redirects_every_conversation_and_drops_the_others() {
        let w = Wanted::from_state(&state(&[("e1", &[10]), ("e2", &[20, 30])], true));
        assert_eq!(w.redirects[&10], "e1");
        assert_eq!(w.redirects[&30], "e2");
        assert_eq!(w.drops["e1"], BTreeSet::from([20, 30]));
        assert_eq!(w.drops["e2"], BTreeSet::from([10]));
    }

    #[test]
    fn no_discard_wrong_installs_no_drops() {
        let w = Wanted::from_state(&state(&[("e1", &[10]), ("e2", &[20])], false));
        assert!(w.drops.is_empty());
        assert_eq!(w.redirects.len(), 2);
    }

    #[test]
    fn empty_state_wants_nothing() {
        assert!(Wanted::from_state(&state(&[], true)).is_empty());
    }

    #[test]
    fn fresh_install_adds_drops_before_redirects() {
        let w = Wanted::from_state(&state(&[("e1", &[10]), ("e2", &[20])], true));
        let ops = plan(&w, &Wanted::default());
        let first_redirect = ops
            .iter()
            .position(|o| matches!(o, Op::Redirect(..)))
            .unwrap();
        assert!(ops[..first_redirect]
            .iter()
            .all(|o| matches!(o, Op::AddDrop(..))));
        assert_eq!(ops.len(), 4);
    }

    #[test]
    fn remap_never_leaves_a_conversation_collectable_on_two_links() {
        let have = Wanted::from_state(&state(&[("e1", &[10]), ("e2", &[20])], true));
        let want = Wanted::from_state(&state(&[("e1", &[20]), ("e2", &[10])], true));
        let ops = plan(&want, &have);
        // Replay: a conversation is collectable on a link when it has no drop there.
        let mut drops = have.drops.clone();
        for op in &ops {
            match op {
                Op::AddDrop(m, c) => {
                    drops.entry(m.clone()).or_default().insert(*c);
                }
                Op::DelDrop(m, c) => {
                    drops.get_mut(m).unwrap().remove(c);
                }
                _ => {}
            }
            for c in [10u16, 20] {
                let open = ["e1", "e2"]
                    .iter()
                    .filter(|m| !drops.get(**m).is_some_and(|d| d.contains(&c)))
                    .count();
                assert!(open <= 1, "{c} open on {open} links after {op:?}");
            }
        }
        assert!(matches!(ops.last(), Some(Op::DelDrop(..))));
    }

    #[test]
    fn empty_want_removes_everything_and_unchanged_is_a_noop() {
        let s = state(&[("e1", &[10]), ("e2", &[20])], true);
        let have = Wanted::from_state(&s);
        assert!(plan(&have, &have).is_empty(), "unchanged");
        let ops = plan(&Wanted::default(), &have);
        assert_eq!(
            ops.iter()
                .filter(|o| matches!(o, Op::DelRedirect(_)))
                .count(),
            2
        );
        assert_eq!(
            ops.iter().filter(|o| matches!(o, Op::DelDrop(..))).count(),
            2
        );
    }

    #[test]
    fn unknown_target_is_rewritten() {
        let want = Wanted::from_state(&state(&[("e1", &[10])], false));
        let have = Wanted {
            redirects: BTreeMap::from([(10, String::new())]),
            drops: BTreeMap::new(),
        };
        assert_eq!(plan(&want, &have), [Op::Redirect(10, "e1".into())]);
    }
}
