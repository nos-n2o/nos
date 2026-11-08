//! `OSPFv3`'s side of the RFC 2328 §10.6-10.8 exchange (RFC 5340 keeps it
//! unchanged) and §13 flooding receive. The machine is
//! `nos_ospf_common::exchange`'s, shared with `nos-ospfd`; this module only
//! supplies v3's closures (S2/S1 scope, the Grace-LSA `MaxAge` exemption)
//! and store layout (area, link-local and AS-scope stores, RFC 5340
//! §4.5.1).

use std::time::Instant;

use nos_ospf_common::exchange as common;
pub use nos_ospf_common::exchange::{
    mtu_acceptable, on_lsack_received, take_all_pending_acks, take_pending_acks, Params,
    DEFAULT_DBD_MAX_HEADERS,
};

use crate::lsa::{self, Lsa, LsaHeader};
use crate::lsdb::Lsdb;
use crate::neighbor::NeighborState;
use crate::packet::{DbdPacket, LsrPacket, LsuPacket};

pub type AdjacencyData = common::AdjacencyData<Lsa>;
pub type Action = common::Action<Lsa>;

/// LSA headers per DBD on a link of this MTU: IPv6 (40) + `OSPFv3` header
/// (16) + DBD body (12) of overhead (`nos_ospf_common::exchange`).
pub fn mtu_based_max_headers(mtu: u16) -> usize {
    common::mtu_based_max_headers(mtu, 40 + 16 + 12)
}

/// `nos_ospf_common::exchange::on_dbd_received` for v3: no stub/NSSA scope
/// (RFC 5340 §3.4 deprecated it) and no opaque LSAs. `p.dbd_options` is
/// `link::link_options`, so every DBD carries the link's Options (RFC 5340
/// A.3.3), the AT-bit included.
pub fn on_dbd_received(
    adj: &mut AdjacencyData,
    state: NeighborState,
    p: &Params,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
) -> Vec<Action> {
    common::on_dbd_received(adj, state, p, dbd, local_lsdb_headers, |_| true, |_| false)
}

/// `nos_ospf_common::exchange::on_lsr_received` over v3's stores: the
/// link's area store, its own link-local store, then the AS-scope store (a
/// key only ever lives in one).
pub fn on_lsr_received(
    adj: &mut AdjacencyData,
    area_lsdb: &Lsdb,
    link_local_lsdb: &Lsdb,
    as_lsdb: &Lsdb,
    lsr: &LsrPacket,
) -> Vec<Action> {
    common::on_lsr_received(adj, &[area_lsdb, link_local_lsdb, as_lsdb], &lsr.requests)
}

/// `nos_ospf_common::exchange::on_lsu_received` with v3's closures: a
/// link-local-scoped LSA (RFC 5340 §4.5.1, Link-LSA) lands in this link's
/// own store, an AS-scoped one (AS-External-LSA) in `as_lsdb`, anything else
/// in the area's; S2/S1 "reserved" is discarded unacked (§4.5 step 3); a
/// Grace-LSA is exempt from the `MaxAge` discard (never held: `handle_lsu`
/// acts on it at once, and its `MaxAge` copy is what ends a grace).
pub fn on_lsu_received(
    adj: &mut AdjacencyData,
    area_lsdb: &mut Lsdb,
    link_local_lsdb: &mut Lsdb,
    as_lsdb: &mut Lsdb,
    lsu: &LsuPacket,
    now: Instant,
) -> (Vec<Action>, Vec<LsaHeader>) {
    let mut stores = common::Stores {
        area: area_lsdb,
        link_local: link_local_lsdb,
        as_scope: Some(as_lsdb),
    };
    common::on_lsu_received(
        adj,
        &mut stores,
        &lsu.lsas,
        now,
        |h| {
            if lsa::is_link_local_scope(h.lsa_type) {
                common::Scope::LinkLocal
            } else if lsa::is_as_scope(h.lsa_type) {
                common::Scope::As
            } else {
                common::Scope::Area
            }
        },
        |h| lsa::is_reserved_scope(h.lsa_type),
        |h| h.lsa_type == lsa::LSA_TYPE_GRACE,
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::neighbor::Event;

    #[test]
    fn mtu_derived_budget() {
        assert_eq!(mtu_based_max_headers(1500), 71);
        assert_eq!(mtu_based_max_headers(68), 1);
    }

    #[test]
    fn dbd_replies_carry_the_link_options() {
        let p = Params {
            local_router_id: router_id("9.9.9.9"),
            max_headers: 100,
            mtu: 1500,
            dbd_options: 0x0413,
            peer_opaque_capable: false,
        };
        let poll = DbdPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            options: 0x13,
            interface_mtu: 1500,
            init: false,
            more: false,
            master: true,
            dd_sequence_number: 7,
            lsa_headers: vec![header("1.1.1.1", 1)],
        };
        let mut adj = AdjacencyData::default();
        let actions = on_dbd_received(&mut adj, NeighborState::ExStart, &p, &poll, &[]);
        assert!(
            matches!(&actions[0], Action::SendDbd(reply) if reply.options == 0x0413),
            "{actions:?}"
        );
    }

    fn router_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn header(link_state_id: &str, seq: i32) -> LsaHeader {
        LsaHeader {
            age: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: router_id(link_state_id),
            advertising_router: router_id(link_state_id),
            sequence_number: seq,
            checksum: 0,
            length: 24,
        }
    }

    fn full_lsa(link_state_id: &str, seq: i32) -> Lsa {
        Lsa {
            header: header(link_state_id, seq),
            body: lsa::LsaBody::Router(lsa::RouterLsaBody {
                flags: 0,
                options: 0,
                links: Vec::new(),
            }),
        }
    }

    fn link_lsa(seq: i32) -> Lsa {
        let mut l = full_lsa("1.1.1.1", seq);
        l.header.lsa_type = lsa::LSA_TYPE_LINK;
        l.header.link_state_id = Ipv4Addr::new(0, 0, 0, 3);
        l.body = lsa::LsaBody::Link(lsa::LinkLsaBody {
            priority: 1,
            options: 0,
            link_local_address: "fe80::1".parse().unwrap(),
            prefixes: Vec::new(),
        });
        l
    }

    #[test]
    fn lsr_is_answered_from_whichever_store_holds_the_key() {
        let mut adj = AdjacencyData::default();
        let mut area = Lsdb::new();
        let mut link_local = Lsdb::new();
        let router = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        let link = link_lsa(0x8000_0001u32.cast_signed());
        area.install(router.clone());
        link_local.install(link.clone());
        let lsr = LsrPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![router.header.key(), link.header.key()],
        };
        let actions = on_lsr_received(&mut adj, &area, &link_local, &Lsdb::new(), &lsr);
        assert!(matches!(&actions[0], Action::SendLsu(lsas) if lsas.len() == 2));
        // A Link-LSA held only by a *different* link's store is not servable
        // here — that is exactly the RFC 5340 §4.5.1 leak this guards.
        let actions = on_lsr_received(&mut adj, &area, &Lsdb::new(), &Lsdb::new(), &lsr);
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::SeqNumberMismatch)]
        );
    }

    #[test]
    fn lsu_routes_each_lsa_to_its_scope_store() {
        let mut adj = AdjacencyData::default();
        let mut area = Lsdb::new();
        let mut link_local = Lsdb::new();
        let router = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        let link = link_lsa(0x8000_0001u32.cast_signed());
        let lsu = LsuPacket {
            discarded: 0,
            last_error: None,
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![router.clone(), link.clone()],
        };
        let mut external = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
        external.header.lsa_type = lsa::LSA_TYPE_AS_EXTERNAL;
        let mut lsu = lsu;
        lsu.lsas.push(external.clone());
        let mut as_scope = Lsdb::new();
        let (_, newly_installed) = on_lsu_received(
            &mut adj,
            &mut area,
            &mut link_local,
            &mut as_scope,
            &lsu,
            Instant::now(),
        );
        assert_eq!(newly_installed.len(), 3);
        assert!(as_scope.get(&external.header.key()).is_some());
        assert!(area.get(&external.header.key()).is_none());
        assert!(area.get(&router.header.key()).is_some());
        assert!(area.get(&link.header.key()).is_none());
        assert!(link_local.get(&link.header.key()).is_some());
        assert!(link_local.get(&router.header.key()).is_none());
    }

    /// RFC 5340 §2.9/§4.5: unknown types land by effective scope; a reserved
    /// scope is discarded without an ack.
    #[test]
    fn lsu_stores_unknown_types_by_effective_scope() {
        let mut adj = AdjacencyData::default();
        let (mut area, mut link_local, mut as_scope) = (Lsdb::new(), Lsdb::new(), Lsdb::new());
        let mk = |t: u16| {
            let mut l = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
            l.header.lsa_type = t;
            l.body = lsa::LsaBody::Opaque(vec![9; 8]);
            l
        };
        let (u_area, u_as, u_link, no_u, reserved) =
            (mk(0xA0FF), mk(0xC0FF), mk(0x80FF), mk(0x20FF), mk(0xE0FF));
        let lsu = LsuPacket {
            discarded: 0,
            last_error: None,
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![
                u_area.clone(),
                u_as.clone(),
                u_link.clone(),
                no_u.clone(),
                reserved.clone(),
            ],
        };
        let (_, installed) = on_lsu_received(
            &mut adj,
            &mut area,
            &mut link_local,
            &mut as_scope,
            &lsu,
            Instant::now(),
        );
        assert_eq!(installed.len(), 4);
        assert!(area.get(&u_area.header.key()).is_some());
        assert!(as_scope.get(&u_as.header.key()).is_some());
        assert!(link_local.get(&u_link.header.key()).is_some());
        assert!(link_local.get(&no_u.header.key()).is_some());
        assert!(area.get(&no_u.header.key()).is_none());
        for s in [&area, &link_local, &as_scope] {
            assert!(s.get(&reserved.header.key()).is_none());
        }
        assert_eq!(adj.pending_acks.len(), 4);
    }

    /// RFC 5187: an unheld `MaxAge` Grace-LSA is installed (it ends a
    /// grace), where any other unheld `MaxAge` LSA is only acked.
    #[test]
    fn unheld_max_age_grace_lsa_is_not_discarded() {
        let mk = |t: u16| {
            let mut l = full_lsa("1.1.1.1", 0x8000_0001u32.cast_signed());
            l.header.lsa_type = t;
            l.header.age = lsa::MAX_AGE;
            l.body = lsa::LsaBody::Opaque(vec![9; 8]);
            l
        };
        let (grace, router) = (mk(lsa::LSA_TYPE_GRACE), mk(lsa::LSA_TYPE_ROUTER));
        let lsu = LsuPacket {
            discarded: 0,
            last_error: None,
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![grace.clone(), router],
        };
        let mut adj = AdjacencyData::default();
        let (_, installed) = on_lsu_received(
            &mut adj,
            &mut Lsdb::new(),
            &mut Lsdb::new(),
            &mut Lsdb::new(),
            &lsu,
            Instant::now(),
        );
        assert_eq!(installed, vec![grace.header]);
        assert_eq!(adj.pending_acks.len(), 2);
    }
}
