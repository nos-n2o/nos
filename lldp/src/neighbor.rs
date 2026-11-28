//! Per-interface neighbor table (IEEE 802.1AB §9.2.7 remote systems MIB, cut
//! down to what `show lldp neighbors` needs). Pure — the caller passes `now`
//! in, so aging is unit-tested without sleeping.

use std::collections::{hash_map, HashMap};
use std::time::{Duration, Instant};

use nos_proto::lldp::{LldpLinkAggregation, LldpMacPhy, LldpVlanName};
use nos_proto::LldpNeighbor;

use crate::packet::{Id, Lldpdu};

/// Bounds memory against a hostile or misbehaving segment flooding distinct
/// chassis IDs. 802.1AB models the same limit as "too many neighbors".
pub const MAX_NEIGHBORS_PER_LINK: usize = 32;

/// What `apply` did with a received LLDPDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Update {
    /// First time this neighbor (chassis + port) was heard.
    New,
    /// Already known; TTL and content refreshed.
    Refreshed,
    /// TTL 0 — the neighbor announced it is going away.
    Removed,
    /// A shutdown for a neighbor we never had.
    Ignored,
    /// 802.1AB tooManyNeighbors: a new neighbor refused because the table is
    /// full. `first` is set on the first refusal since the table last had
    /// room, so the caller warns once rather than once per frame.
    TableFull { first: bool },
}

struct Entry {
    pdu: Lldpdu,
    expires_at: Instant,
}

#[derive(Default)]
pub struct NeighborTable {
    entries: HashMap<(Id, Id), Entry>,
    /// A `TableFull { first: true }` was already returned and no entry has
    /// left since.
    full_reported: bool,
}

impl NeighborTable {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether any neighbor sent an LLDP-MED Capabilities TLV (the MED gate).
    pub fn has_med_caps(&self) -> bool {
        self.entries.values().any(|e| e.pdu.org.med_caps.is_some())
    }

    pub fn apply(&mut self, pdu: Lldpdu, now: Instant) -> Update {
        let key = (pdu.chassis_id.clone(), pdu.port_id.clone());
        if pdu.ttl == 0 {
            return if self.entries.remove(&key).is_some() {
                self.full_reported = false;
                Update::Removed
            } else {
                Update::Ignored
            };
        }
        let expires_at = now + Duration::from_secs(u64::from(pdu.ttl));
        let full = self.entries.len() >= MAX_NEIGHBORS_PER_LINK;
        match self.entries.entry(key) {
            hash_map::Entry::Occupied(mut slot) => {
                slot.insert(Entry { pdu, expires_at });
                Update::Refreshed
            }
            hash_map::Entry::Vacant(_) if full => Update::TableFull {
                first: !std::mem::replace(&mut self.full_reported, true),
            },
            hash_map::Entry::Vacant(slot) => {
                slot.insert(Entry { pdu, expires_at });
                Update::New
            }
        }
    }

    /// Drops every entry whose TTL has lapsed and returns them.
    pub fn expire(&mut self, now: Instant) -> Vec<Lldpdu> {
        let expired: Vec<(Id, Id)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        if !expired.is_empty() {
            self.full_reported = false;
        }
        expired
            .into_iter()
            .filter_map(|k| self.entries.remove(&k))
            .map(|e| e.pdu)
            .collect()
    }

    /// When the soonest entry ages out, if any.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.entries.values().map(|e| e.expires_at).min()
    }

    pub fn snapshot(&self, local_interface: &str, now: Instant) -> Vec<LldpNeighbor> {
        self.entries
            .values()
            .map(|e| LldpNeighbor {
                local_interface: local_interface.to_string(),
                chassis_id: e.pdu.chassis_display(),
                port_id: e.pdu.port_display(),
                port_description: e.pdu.port_description.clone(),
                system_name: e.pdu.system_name.clone(),
                system_description: e.pdu.system_description.clone(),
                capabilities: e.pdu.enabled_capability_names(),
                management_addresses: e
                    .pdu
                    .management_addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                ttl_remaining_secs: u32::try_from(
                    e.expires_at.saturating_duration_since(now).as_secs(),
                )
                .unwrap_or(u32::MAX),
                port_vlan_id: e.pdu.org.port_vlan_id,
                vlan_names: e
                    .pdu
                    .org
                    .vlan_names
                    .iter()
                    .map(|(id, name)| LldpVlanName {
                        id: *id,
                        name: name.clone(),
                    })
                    .collect(),
                link_aggregation: e.pdu.org.link_aggregation.map(|a| LldpLinkAggregation {
                    capable: a.capable,
                    enabled: a.enabled,
                    port_id: a.port_id,
                }),
                max_frame_size: e.pdu.org.max_frame_size,
                mac_phy: e.pdu.org.mac_phy.map(|m| LldpMacPhy {
                    autoneg_supported: m.autoneg_supported,
                    autoneg_enabled: m.autoneg_enabled,
                    advertised: m.advertised,
                    mau_type: m.mau_type,
                }),
                med: crate::med::to_proto(&e.pdu.org),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{CHASSIS_SUBTYPE_MAC, PORT_SUBTYPE_IF_NAME};

    fn pdu(chassis: u8, port: &str, ttl: u16) -> Lldpdu {
        Lldpdu {
            chassis_id: Id {
                subtype: CHASSIS_SUBTYPE_MAC,
                value: vec![2, 0, 0, 0, 0, chassis],
            },
            port_id: Id {
                subtype: PORT_SUBTYPE_IF_NAME,
                value: port.as_bytes().to_vec(),
            },
            ttl,
            port_description: None,
            system_name: Some(format!("r{chassis}")),
            system_description: None,
            capabilities: None,
            management_addresses: Vec::new(),
            org: crate::packet::OrgTlvs::default(),
        }
    }

    #[test]
    fn new_then_refresh_then_shutdown() {
        let now = Instant::now();
        let mut t = NeighborTable::default();
        assert_eq!(t.apply(pdu(1, "eth1", 120), now), Update::New);
        assert_eq!(t.apply(pdu(1, "eth1", 120), now), Update::Refreshed);
        assert_eq!(t.apply(pdu(1, "eth1", 0), now), Update::Removed);
        assert_eq!(t.apply(pdu(1, "eth1", 0), now), Update::Ignored);
        assert_eq!(t.snapshot("eth0", now), []);
    }

    #[test]
    fn same_chassis_different_port_is_a_distinct_neighbor() {
        let now = Instant::now();
        let mut t = NeighborTable::default();
        assert_eq!(t.apply(pdu(1, "eth1", 120), now), Update::New);
        assert_eq!(t.apply(pdu(1, "eth2", 120), now), Update::New);
        assert_eq!(t.snapshot("eth0", now).len(), 2);
    }

    #[test]
    fn entries_age_out_at_their_ttl_and_refresh_extends_it() {
        let now = Instant::now();
        let mut t = NeighborTable::default();
        t.apply(pdu(1, "eth1", 10), now);
        t.apply(pdu(2, "eth1", 100), now);
        assert_eq!(t.next_expiry(), Some(now + Duration::from_secs(10)));

        assert_eq!(t.expire(now + Duration::from_secs(9)), []);
        // Refresh neighbor 1 just before it lapses.
        t.apply(pdu(1, "eth1", 10), now + Duration::from_secs(9));
        assert_eq!(t.expire(now + Duration::from_secs(10)), []);

        let gone = t.expire(now + Duration::from_secs(19));
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].system_name.as_deref(), Some("r1"));
        assert_eq!(t.snapshot("eth0", now).len(), 1);
    }

    #[test]
    fn snapshot_reports_remaining_ttl() {
        let now = Instant::now();
        let mut t = NeighborTable::default();
        t.apply(pdu(1, "eth1", 120), now);
        let n = &t.snapshot("eth0", now + Duration::from_secs(20))[0];
        assert_eq!(n.local_interface, "eth0");
        assert_eq!(n.ttl_remaining_secs, 100);
        assert_eq!(n.chassis_id, "02:00:00:00:00:01");
    }

    #[test]
    fn table_is_bounded_against_a_flood_of_distinct_neighbors() {
        let now = Instant::now();
        let mut t = NeighborTable::default();
        for i in 0..=u8::try_from(MAX_NEIGHBORS_PER_LINK).unwrap() {
            t.apply(pdu(i, "eth1", 120), now);
        }
        assert_eq!(t.snapshot("eth0", now).len(), MAX_NEIGHBORS_PER_LINK);
        // The 33rd was refused, reported once; later refusals are not "first".
        assert_eq!(
            t.apply(pdu(200, "eth1", 120), now),
            Update::TableFull { first: false }
        );
        // An existing neighbor can still refresh when the table is full.
        assert_eq!(t.apply(pdu(0, "eth1", 120), now), Update::Refreshed);
        // A shutdown for a neighbor we never had is not a table drop.
        assert_eq!(t.apply(pdu(201, "eth1", 0), now), Update::Ignored);

        // Room again (one ages out, one refills it): the next refusal is
        // reported afresh.
        t.apply(pdu(1, "eth1", 5), now);
        assert_eq!(t.expire(now + Duration::from_secs(5)).len(), 1);
        assert_eq!(t.apply(pdu(202, "eth1", 120), now), Update::New);
        assert_eq!(
            t.apply(pdu(203, "eth1", 120), now),
            Update::TableFull { first: true }
        );
    }
}
