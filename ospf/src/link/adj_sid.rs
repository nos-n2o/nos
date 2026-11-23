//! Adj-SID origination (RFC 8665 §6/§7, #1382): a dynamic label per adjacency,
//! the Extended Link LSAs carrying them and the pop entries of the ILM.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use super::originate::router_lsa_links;
use super::{
    lsa, LinkConfig, LinkStatus, NeighborState, LINK_TYPE_POINT_TO_POINT, LINK_TYPE_TRANSIT_NETWORK,
};

/// First dynamic Adj-SID label: above the default SRGB (16000-23999, so a
/// label never doubles as a Prefix-SID) and the VPN labels (from 1000).
const ADJ_SID_BASE: u32 = 24000;
/// The highest label `nos-ribd` accepts (RFC 3032).
const MAX_LABEL: u32 = 1_048_574;

/// Labels handed out per `(local interface address, neighbour router id)`, so
/// an adjacency that flaps keeps its label. `ponytail:` never freed; ceiling:
/// one label per neighbour ever seen, 1M total.
#[derive(Debug, Default)]
pub(super) struct AdjLabels(BTreeMap<(Ipv4Addr, Ipv4Addr), u32>);

impl AdjLabels {
    /// `None` once the label space is exhausted.
    fn label(&mut self, key: (Ipv4Addr, Ipv4Addr)) -> Option<u32> {
        let next = ADJ_SID_BASE + u32::try_from(self.0.len()).ok()?;
        if !self.0.contains_key(&key) && next > MAX_LABEL {
            return None;
        }
        Some(*self.0.entry(key).or_insert(next))
    }
}

/// One adjacency with its Adj-SID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Adjacency {
    /// The Router-LSA link this extends (RFC 7684 §3.1).
    pub link_type: u8,
    pub link_id: Ipv4Addr,
    pub link_data: Ipv4Addr,
    pub neighbor: Ipv4Addr,
    /// A LAN Adj-SID (names the neighbour) rather than a plain Adj-SID.
    pub lan: bool,
    /// The neighbour's address on the link: where the pop entry sends.
    pub gateway: Ipv4Addr,
    pub label: u32,
}

/// Every fully adjacent neighbour of `links` (Router-LSA types 1 and 2, the
/// same adjacencies `router_lsa_links` advertises) with its label.
pub(super) fn adjacencies(
    local_router_id: Ipv4Addr,
    links: &[(LinkConfig, LinkStatus)],
    labels: &mut AdjLabels,
) -> Vec<Adjacency> {
    let up = |n: &super::NeighborInfo| n.state == NeighborState::Full || n.grace_deadline.is_some();
    let mut out = Vec::new();
    for pair in links {
        let (cfg, status) = pair;
        for l in router_lsa_links(local_router_id, std::slice::from_ref(pair), true, false) {
            let members: Vec<(Ipv4Addr, bool)> = match l.link_type {
                LINK_TYPE_POINT_TO_POINT => vec![(l.link_id, false)],
                LINK_TYPE_TRANSIT_NETWORK => status
                    .neighbors
                    .iter()
                    .filter(|(_, n)| up(n))
                    .map(|(id, _)| (*id, true))
                    .collect(),
                _ => continue,
            };
            for (neighbor, lan) in members {
                let (Some(n), Some(label)) = (
                    status.neighbors.get(&neighbor),
                    labels.label((cfg.local_addr, neighbor)),
                ) else {
                    continue;
                };
                out.push(Adjacency {
                    link_type: l.link_type,
                    link_id: l.link_id,
                    link_data: l.link_data,
                    neighbor,
                    lan,
                    gateway: n.address,
                    label,
                });
            }
        }
    }
    out.sort_by_key(|a| (a.link_id, a.link_data, a.neighbor));
    out
}

/// One Extended Link per Router-LSA link, its Adj-SID sub-TLVs concatenated.
pub(super) fn extended_links(adjs: &[Adjacency]) -> Vec<lsa::ExtendedLink> {
    let mut out: Vec<lsa::ExtendedLink> = Vec::new();
    for a in adjs {
        let sid = lsa::encode_adj_sid(a.label, 0, false, a.lan.then_some(a.neighbor));
        match out.iter_mut().find(|l| {
            (l.link_type, l.link_id, l.link_data) == (a.link_type, a.link_id, a.link_data)
        }) {
            Some(l) => l.sub_tlvs.extend(sid),
            None => out.push(lsa::ExtendedLink {
                link_type: a.link_type,
                link_id: a.link_id,
                link_data: a.link_data,
                sub_tlvs: sid,
            }),
        }
    }
    out
}

/// The ILM pop entry of each Adj-SID: the label leaves toward the neighbour
/// with an empty stack, whatever the rest of the network does (RFC 8665 §6).
pub(super) fn ilm(adjs: &[Adjacency]) -> Vec<nos_proto::IlmRoute> {
    adjs.iter()
        .map(|a| nos_proto::IlmRoute {
            label: a.label,
            hops: vec![nos_proto::NextHop {
                gateway: a.gateway.into(),
                interface_id: None,
                labels: Vec::new(),
            }],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_stable_and_distinct() {
        let mut l = AdjLabels::default();
        let a = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(2, 2, 2, 2));
        let b = (Ipv4Addr::new(10, 0, 1, 1), Ipv4Addr::new(3, 3, 3, 3));
        assert_eq!(l.label(a), Some(24000));
        assert_eq!(l.label(b), Some(24001));
        assert_eq!(l.label(a), Some(24000));
    }

    #[test]
    fn extended_links_group_lan_sids_per_link() {
        let adj = |n: u8, label| Adjacency {
            link_type: LINK_TYPE_TRANSIT_NETWORK,
            link_id: Ipv4Addr::new(10, 0, 0, 1),
            link_data: Ipv4Addr::new(10, 0, 0, 3),
            neighbor: Ipv4Addr::new(n, n, n, n),
            lan: true,
            gateway: Ipv4Addr::new(10, 0, 0, n),
            label,
        };
        let links = extended_links(&[adj(1, 24000), adj(2, 24001)]);
        assert_eq!(links.len(), 1);
        let sids = lsa::decode_adj_sids(&links[0].sub_tlvs);
        assert_eq!(
            sids.iter()
                .map(|s| (s.value, s.neighbor))
                .collect::<Vec<_>>(),
            [
                (24000, Some(Ipv4Addr::new(1, 1, 1, 1))),
                (24001, Some(Ipv4Addr::new(2, 2, 2, 2)))
            ]
        );
        let ilm = ilm(&[adj(1, 24000)]);
        assert_eq!(ilm[0].label, 24000);
        assert_eq!(ilm[0].hops[0].labels, Vec::<u32>::new());
    }
}
