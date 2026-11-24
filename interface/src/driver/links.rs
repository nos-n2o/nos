//! Kernel link-state table behind `InterfaceRequest::SubscribeLinks`.
//!
//! `LinkHub` is pure (no netlink): the Linux driver's watcher feeds it
//! decoded `RTM_NEWLINK`/`RTM_DELLINK` messages and dumps, the server calls
//! `watch()` per subscriber. Sends happen under the table lock, so a
//! subscriber's snapshot and its receiver can neither miss nor repeat an event.

use std::collections::BTreeMap;
use std::sync::Mutex;

use nos_proto::LinkState;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage, State};
use rtnetlink::packet_route::RouteNetlinkMessage;
use tokio::sync::broadcast;
use tracing::debug;

/// Production broadcast capacity; a slower subscriber gets a fresh snapshot.
pub const HUB_CAPACITY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    /// A netdev appeared under this name (first sight, or recreated).
    Added(LinkState),
    /// Flags/carrier/aggregate of the same device.
    Changed(LinkState),
    Removed(String),
}

/// What `InterfaceDriver::watch_links` hands a subscriber. `rx: None` means
/// the driver never reports anything (noop): `observed` is then false.
pub struct LinkWatch {
    pub observed: bool,
    pub links: Vec<LinkState>,
    pub rx: Option<broadcast::Receiver<LinkEvent>>,
}

pub struct LinkHub {
    observed: bool,
    inner: Mutex<Table>,
    tx: broadcast::Sender<LinkEvent>,
}

#[derive(Default)]
struct Table {
    links: BTreeMap<String, LinkState>,
    /// Bond kernel name -> its `PortAggregate` config name, stamped on every
    /// `LinkState` of that name (`LinkState::port_aggregate`).
    aggregates: BTreeMap<String, String>,
}

impl Table {
    /// Stores `link` (its `port_aggregate` stamped) and returns the events.
    fn upsert(&mut self, mut link: LinkState) -> Vec<LinkEvent> {
        link.port_aggregate = self.aggregates.get(&link.name).cloned();
        let existing = self.links.get(&link.name);
        if existing == Some(&link) {
            return Vec::new();
        }
        let mut events = Vec::new();
        // Same name, other ifindex: the old device is gone (its DELLINK was
        // lost or folded into a dump), so owners of its sockets must reopen.
        let recreated = existing.is_some_and(|e| e.ifindex != link.ifindex);
        if recreated {
            debug!(name = %link.name, "link recreated");
            events.push(LinkEvent::Removed(link.name.clone()));
        }
        let announce = existing.is_none() || recreated;
        // A rename arrives as RTM_NEWLINK only: drop the old name.
        let stale: Vec<String> = self
            .links
            .values()
            .filter(|l| l.ifindex == link.ifindex && l.name != link.name)
            .map(|l| l.name.clone())
            .collect();
        for old in stale {
            self.links.remove(&old);
            debug!(name = %old, "link removed");
            events.push(LinkEvent::Removed(old));
        }
        debug!(
            name = %link.name, ifindex = link.ifindex,
            admin_up = link.admin_up, carrier = link.carrier,
            "link state changed"
        );
        self.links.insert(link.name.clone(), link.clone());
        events.push(if announce {
            LinkEvent::Added(link)
        } else {
            LinkEvent::Changed(link)
        });
        events
    }
}

impl LinkHub {
    pub fn new(capacity: usize) -> Self {
        Self {
            observed: true,
            inner: Mutex::new(Table::default()),
            tx: broadcast::channel(capacity).0,
        }
    }

    fn send(&self, events: Vec<LinkEvent>) {
        for e in events {
            let _ = self.tx.send(e);
        }
    }

    pub fn upsert(&self, link: LinkState) {
        let mut table = self.inner.lock().unwrap();
        let events = table.upsert(link);
        self.send(events);
    }

    /// Names (or, with `None`, forgets) the aggregate whose bond is `bond`;
    /// a link already known under that name is re-sent with it.
    pub fn set_port_aggregate(&self, bond: &str, aggregate: Option<&str>) {
        let mut table = self.inner.lock().unwrap();
        match aggregate {
            Some(a) => table.aggregates.insert(bond.to_string(), a.to_string()),
            None => table.aggregates.remove(bond),
        };
        if let Some(link) = table.links.get(bond).cloned() {
            let events = table.upsert(link);
            self.send(events);
        }
    }

    pub fn remove(&self, name: &str) {
        self.remove_if(name, None);
    }

    /// Removes `name`; with `Some(ifindex)` only when it is still that device
    /// (a delayed `RTM_DELLINK` for a replaced device must not delete the new one).
    pub fn remove_if(&self, name: &str, ifindex: Option<u32>) {
        let mut table = self.inner.lock().unwrap();
        if ifindex.is_some_and(|i| table.links.get(name).is_some_and(|l| l.ifindex != i)) {
            return;
        }
        if table.links.remove(name).is_some() {
            debug!(name = %name, "link removed");
            let _ = self.tx.send(LinkEvent::Removed(name.to_string()));
        }
    }

    /// A full dump: upsert each, drop every stored name not listed.
    pub fn replace_all(&self, links: Vec<LinkState>) {
        let keep: Vec<String> = links.iter().map(|l| l.name.clone()).collect();
        let gone: Vec<String> = {
            let table = self.inner.lock().unwrap();
            table
                .links
                .keys()
                .filter(|k| !keep.contains(k))
                .cloned()
                .collect()
        };
        for l in links {
            self.upsert(l);
        }
        for n in gone {
            self.remove(&n);
        }
    }

    pub fn watch(&self) -> LinkWatch {
        let table = self.inner.lock().unwrap();
        LinkWatch {
            observed: self.observed,
            links: table.links.values().cloned().collect(),
            rx: Some(self.tx.subscribe()),
        }
    }
}

pub enum Delta {
    Upsert(LinkState),
    Remove(String, u32),
}

pub fn link_state(msg: &LinkMessage) -> Option<LinkState> {
    let name = msg.attributes.iter().find_map(|a| match a {
        LinkAttribute::IfName(n) => Some(n.clone()),
        _ => None,
    })?;
    let oper = msg
        .attributes
        .iter()
        .find_map(|a| match a {
            LinkAttribute::OperState(s) => Some(*s),
            _ => None,
        })
        .unwrap_or(State::Unknown);
    Some(LinkState {
        name,
        ifindex: msg.header.index,
        admin_up: msg.header.flags.contains(LinkFlags::Up),
        carrier: msg.header.flags.contains(LinkFlags::LowerUp)
            && matches!(oper, State::Up | State::Unknown),
        port_aggregate: None,
    })
}

pub fn decode(msg: NetlinkPayload<RouteNetlinkMessage>) -> Option<Delta> {
    match msg {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(m)) => {
            link_state(&m).map(Delta::Upsert)
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(m)) => {
            link_state(&m).map(|l| Delta::Remove(l.name, l.ifindex))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(name: Option<&str>, flags: LinkFlags, oper: Option<State>) -> LinkMessage {
        let mut m = LinkMessage::default();
        m.header.index = 7;
        m.header.flags = flags;
        if let Some(n) = name {
            m.attributes.push(LinkAttribute::IfName(n.into()));
        }
        if let Some(o) = oper {
            m.attributes.push(LinkAttribute::OperState(o));
        }
        m
    }

    fn l(name: &str, ifindex: u32, up: bool) -> LinkState {
        LinkState {
            name: name.into(),
            ifindex,
            admin_up: up,
            carrier: up,
            port_aggregate: None,
        }
    }

    #[test]
    fn link_state_flags() {
        let up = LinkFlags::Up | LinkFlags::LowerUp;
        let s = link_state(&msg(Some("a"), up, Some(State::Up))).unwrap();
        assert!(s.admin_up && s.carrier && s.ifindex == 7);
        let s = link_state(&msg(Some("a"), LinkFlags::LowerUp, Some(State::Up))).unwrap();
        assert!(!s.admin_up && s.carrier);
        let s = link_state(&msg(Some("a"), LinkFlags::Up, Some(State::Up))).unwrap();
        assert!(s.admin_up && !s.carrier);
        let s = link_state(&msg(Some("a"), up, Some(State::Down))).unwrap();
        assert!(!s.carrier);
        assert!(
            link_state(&msg(Some("a"), up, Some(State::Unknown)))
                .unwrap()
                .carrier
        );
        assert!(link_state(&msg(Some("a"), up, None)).unwrap().carrier);
        assert!(link_state(&msg(None, up, None)).is_none());
    }

    #[test]
    fn decode_kinds() {
        let m = msg(Some("a"), LinkFlags::Up, None);
        let new = NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(m.clone()));
        assert!(matches!(decode(new), Some(Delta::Upsert(s)) if s.name == "a"));
        let del = NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(m));
        assert!(matches!(decode(del), Some(Delta::Remove(n, 7)) if n == "a"));
        assert!(decode(NetlinkPayload::Noop).is_none());
    }

    #[test]
    fn hub_dedupes_changes_and_removes() {
        let hub = LinkHub::new(16);
        let mut rx = hub.watch().rx.unwrap();
        hub.upsert(l("a", 1, true));
        hub.upsert(l("a", 1, true));
        hub.upsert(l("a", 1, false));
        hub.remove("a");
        hub.remove("a");
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Added(l("a", 1, true)));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Changed(l("a", 1, false)));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Removed("a".into()));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn delete_then_recreate_is_removed_then_added() {
        let hub = LinkHub::new(16);
        hub.upsert(l("eth2", 5, true));
        let mut rx = hub.watch().rx.unwrap();
        hub.remove_if("eth2", Some(5));
        hub.upsert(l("eth2", 9, true));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Removed("eth2".into()));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Added(l("eth2", 9, true)));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn missed_dellink_synthesizes_the_pair() {
        let hub = LinkHub::new(16);
        hub.upsert(l("eth2", 5, true));
        let mut rx = hub.watch().rx.unwrap();
        hub.upsert(l("eth2", 9, true));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Removed("eth2".into()));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Added(l("eth2", 9, true)));
        // A re-dump listing a new ifindex does the same.
        hub.replace_all(vec![l("eth2", 11, true)]);
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Removed("eth2".into()));
        assert_eq!(
            rx.try_recv().unwrap(),
            LinkEvent::Added(l("eth2", 11, true))
        );
    }

    #[test]
    fn stale_dellink_is_ignored() {
        let hub = LinkHub::new(16);
        hub.upsert(l("eth2", 9, true));
        let mut rx = hub.watch().rx.unwrap();
        hub.remove_if("eth2", Some(5));
        assert!(rx.try_recv().is_err());
        assert_eq!(hub.watch().links, vec![l("eth2", 9, true)]);
    }

    #[test]
    fn hub_rename_removes_old_name() {
        let hub = LinkHub::new(16);
        hub.upsert(l("old", 3, true));
        let mut rx = hub.watch().rx.unwrap();
        hub.upsert(l("new", 3, true));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Removed("old".into()));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Added(l("new", 3, true)));
        assert_eq!(hub.watch().links, vec![l("new", 3, true)]);
    }

    #[test]
    fn a_bond_carries_its_aggregate_name() {
        let hub = LinkHub::new(16);
        hub.set_port_aggregate("bond1", Some("agg"));
        let mut rx = hub.watch().rx.unwrap();
        hub.upsert(l("bond1", 4, true));
        let named = LinkState {
            port_aggregate: Some("agg".into()),
            ..l("bond1", 4, true)
        };
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Added(named.clone()));
        // Re-sent without it once forgotten; a name never seen is a no-op.
        hub.set_port_aggregate("bond1", None);
        assert_eq!(
            rx.try_recv().unwrap(),
            LinkEvent::Changed(l("bond1", 4, true))
        );
        hub.set_port_aggregate("bond2", Some("other"));
        hub.set_port_aggregate("bond1", Some("agg"));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Changed(named));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn replace_all_emits_only_differences() {
        let hub = LinkHub::new(16);
        hub.replace_all(vec![l("a", 1, true), l("b", 2, true)]);
        let mut rx = hub.watch().rx.unwrap();
        hub.replace_all(vec![l("a", 1, true), l("c", 3, true)]);
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Added(l("c", 3, true)));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Removed("b".into()));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn watch_snapshot_then_later_events_only() {
        let hub = LinkHub::new(16);
        hub.upsert(l("a", 1, true));
        let w = hub.watch();
        assert!(w.observed);
        assert_eq!(w.links, vec![l("a", 1, true)]);
        let mut rx = w.rx.unwrap();
        assert!(rx.try_recv().is_err());
        hub.upsert(l("b", 2, true));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Added(l("b", 2, true)));
    }
}
