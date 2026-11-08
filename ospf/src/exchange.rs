//! `OSPFv2`'s side of the RFC 2328 §10.6-10.8 exchange and §13 flooding
//! receive. The machine (DBD negotiation, pagination, LSR/LSU handling,
//! delayed acks, `LSAck`) is `nos_ospf_common::exchange`'s, shared with
//! `nos-ospfv3`; this module only supplies v2's closures (stub/NSSA scope,
//! opaque LSAs, type-9 store routing, the DBD Options) and store layout (one
//! area store plus the link's type-9 store).

use std::time::Instant;

use nos_ospf_common::exchange as common;
pub use nos_ospf_common::exchange::{
    mtu_acceptable, on_lsack_received, take_all_pending_acks, take_pending_acks, Params,
    DEFAULT_DBD_MAX_HEADERS,
};

use crate::lsa::{self, Lsa, LsaHeader};
use crate::lsdb::Lsdb;
use crate::neighbor::NeighborState;
use crate::packet::{DbdPacket, LsrPacket, LsuPacket, OPTION_E, OPTION_O};

pub type AdjacencyData = common::AdjacencyData<Lsa>;
pub type Action = common::Action<Lsa>;

/// Options this router sends in every DBD of a normal area: RFC 2328's
/// E-bit (as in its Hellos) and RFC 5250's O-bit.
pub const DBD_OPTIONS: u32 = (OPTION_E | OPTION_O) as u32;

/// The DBD options for a link: `DBD_OPTIONS`, without the E-bit in a stub
/// area (RFC 2328 §3.6).
pub fn dbd_options(stub: bool) -> u32 {
    if stub {
        u32::from(OPTION_O)
    } else {
        DBD_OPTIONS
    }
}

/// RFC 5250 §3: the neighbor's DBD set the O-bit, so it may be sent opaque
/// LSAs (`Params::peer_opaque_capable`).
pub fn peer_opaque_capable(dbd: &DbdPacket) -> bool {
    dbd.options & u32::from(OPTION_O) != 0
}

/// LSA headers per DBD on a link of this MTU: IPv4 (20) + OSPF header (24)
/// + DBD body (8) of overhead (`nos_ospf_common::exchange`).
pub fn mtu_based_max_headers(mtu: u16) -> usize {
    common::mtu_based_max_headers(mtu, 20 + 24 + 8)
}

/// `nos_ospf_common::exchange::on_dbd_received` with v2's scope rule
/// (`lsa::in_area_scope`: Type-5/11 out of stub/NSSA, Type-7 only in an
/// NSSA) and RFC 5250 opaque filtering.
pub fn on_dbd_received(
    adj: &mut AdjacencyData,
    state: NeighborState,
    p: &Params,
    dbd: &DbdPacket,
    local_lsdb_headers: &[LsaHeader],
) -> Vec<Action> {
    let (stub, nssa) = (adj.stub, adj.nssa);
    common::on_dbd_received(
        adj,
        state,
        p,
        dbd,
        local_lsdb_headers,
        |h| lsa::in_area_scope(h.lsa_type, stub, nssa),
        |h| lsa::is_opaque(h.lsa_type),
    )
}

/// `nos_ospf_common::exchange::on_lsr_received` over v2's stores: the area,
/// then this link's own (type 9, RFC 5250).
pub fn on_lsr_received(
    adj: &mut AdjacencyData,
    lsdb: &Lsdb,
    link_local_lsdb: &Lsdb,
    lsr: &LsrPacket,
) -> Vec<Action> {
    common::on_lsr_received(adj, &[lsdb, link_local_lsdb], &lsr.requests)
}

/// `nos_ospf_common::exchange::on_lsu_received` with v2's closures: a type-9
/// LSA lands in the link's own store (RFC 5250 §3, so no other link's resend
/// floods it), everything else in the area's; an AS-external (or AS-scope
/// opaque) LSA on a stub area's or NSSA's link, or a Type-7 outside an NSSA
/// (RFC 3101 §2.4), is discarded unacked (RFC 2328 §13 step 3); no AS store
/// and no `MaxAge` exemption.
pub fn on_lsu_received(
    adj: &mut AdjacencyData,
    area_lsdb: &mut Lsdb,
    link_local_lsdb: &mut Lsdb,
    lsu: &LsuPacket,
    now: Instant,
) -> (Vec<Action>, Vec<LsaHeader>) {
    let (stub, nssa) = (adj.stub, adj.nssa);
    let mut stores = common::Stores {
        area: area_lsdb,
        link_local: link_local_lsdb,
        as_scope: None,
    };
    common::on_lsu_received(
        adj,
        &mut stores,
        &lsu.lsas,
        now,
        |h| {
            if lsa::is_link_local_scope(h.lsa_type) {
                common::Scope::LinkLocal
            } else {
                common::Scope::Area
            }
        },
        |h| !lsa::in_area_scope(h.lsa_type, stub, nssa),
        |_| false,
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::neighbor::Event;

    fn router_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn negotiation_dbd(router_id: Ipv4Addr, seq: u32) -> DbdPacket {
        DbdPacket {
            router_id,
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 0,
            options: DBD_OPTIONS,
            init: true,
            more: true,
            master: true,
            dd_sequence_number: seq,
            lsa_headers: Vec::new(),
        }
    }

    fn header(link_state_id: &str, seq: i32) -> LsaHeader {
        LsaHeader {
            age: 0,
            options: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: router_id(link_state_id),
            advertising_router: router_id(link_state_id),
            sequence_number: seq,
            checksum: 0,
            length: 24,
        }
    }

    /// Runs `dbd` from 9.9.9.10 (the higher id, so we are slave) in `state`.
    fn dbd_in(
        adj: &mut AdjacencyData,
        state: NeighborState,
        dbd: &DbdPacket,
        local: &[LsaHeader],
    ) -> Vec<Action> {
        let p = Params {
            local_router_id: router_id("9.9.9.9"),
            max_headers: 100,
            mtu: 1500,
            dbd_options: dbd_options(adj.stub),
            peer_opaque_capable: peer_opaque_capable(dbd),
        };
        on_dbd_received(adj, state, &p, dbd, local)
    }

    #[test]
    fn mtu_budget_uses_the_ipv4_overhead() {
        assert_eq!(mtu_based_max_headers(1500), 72);
    }

    fn opaque(lsa_type: u8) -> Lsa {
        Lsa {
            header: LsaHeader {
                lsa_type,
                link_state_id: router_id("4.0.0.1"),
                ..header("9.9.9.10", 1)
            },
            body: lsa::LsaBody::Opaque(vec![1, 2, 3, 4]),
        }
    }

    /// RFC 5250: a type-9 LSA lands in the link store, a type-10 in the area
    /// store, and an LSR for either is answered.
    #[test]
    fn opaque_lsas_are_stored_by_scope_and_requestable() {
        let mut adj = AdjacencyData::default();
        let (mut area, mut link) = (Lsdb::new(), Lsdb::new());
        let (l9, l10) = (
            opaque(lsa::LSA_TYPE_OPAQUE_LINK),
            opaque(lsa::LSA_TYPE_OPAQUE_AREA),
        );
        let lsu = LsuPacket {
            discarded: 0,
            last_error: None,
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![l9.clone(), l10.clone()],
        };
        on_lsu_received(&mut adj, &mut area, &mut link, &lsu, Instant::now());
        assert!(link.get(&l9.header.key()).is_some());
        assert!(area.get(&l9.header.key()).is_none());
        assert!(area.get(&l10.header.key()).is_some());
        assert!(link.get(&l10.header.key()).is_none());

        let lsr = LsrPacket {
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![l9.header.key(), l10.header.key()],
        };
        let actions = on_lsr_received(&mut adj, &area, &link, &lsr);
        assert!(matches!(&actions[..], [Action::SendLsu(lsas)] if lsas.len() == 2));
    }

    /// RFC 5250 §3: opaque headers are summarized only to a neighbor whose
    /// DBD set the O-bit.
    #[test]
    fn opaque_headers_are_summarized_only_to_an_opaque_capable_neighbor() {
        let local = [
            header("1.1.1.1", 1),
            opaque(lsa::LSA_TYPE_OPAQUE_AREA).header,
            opaque(lsa::LSA_TYPE_OPAQUE_AS).header,
        ];
        for (options, expected) in [(DBD_OPTIONS, 3), (u32::from(OPTION_E), 1)] {
            let mut adj = AdjacencyData::default();
            let dbd = DbdPacket {
                options,
                ..negotiation_dbd(router_id("9.9.9.10"), 1)
            };
            let actions = dbd_in(&mut adj, NeighborState::ExStart, &dbd, &local);
            assert_eq!(adj.opaque_capable, options & u32::from(OPTION_O) != 0);
            assert!(
                matches!(&actions[0], Action::SendDbd(reply) if reply.lsa_headers.len() == expected),
                "{actions:?}"
            );
        }
    }

    /// RFC 2328 §3.6: on a stub area's link, AS-scope LSAs are never
    /// summarized, a DBD listing one restarts the exchange, an LSU carrying
    /// one is dropped unacked, and our DBDs go without the E-bit.
    #[test]
    fn stub_link_keeps_as_scope_lsas_out() {
        let as_scope = opaque(lsa::LSA_TYPE_OPAQUE_AS);
        let local = [header("1.1.1.1", 1), as_scope.header];
        let mut adj = AdjacencyData {
            stub: true,
            ..Default::default()
        };
        let negotiation = negotiation_dbd(router_id("9.9.9.10"), 1);
        let actions = dbd_in(&mut adj, NeighborState::ExStart, &negotiation, &local);
        assert!(
            matches!(&actions[0], Action::SendDbd(reply)
                if reply.lsa_headers == [local[0]] && reply.options & u32::from(OPTION_E) == 0),
            "{actions:?}"
        );
        assert_eq!(dbd_options(false), DBD_OPTIONS);

        let listing = DbdPacket {
            lsa_headers: vec![as_scope.header],
            ..negotiation_dbd(router_id("9.9.9.10"), 1)
        };
        let actions = dbd_in(&mut adj, NeighborState::Exchange, &listing, &[]);
        assert_eq!(
            actions,
            vec![Action::NeighborEvent(Event::SeqNumberMismatch)]
        );

        let (mut area, mut link) = (Lsdb::default(), Lsdb::default());
        let lsu = LsuPacket {
            discarded: 0,
            last_error: None,
            router_id: router_id("9.9.9.10"),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![as_scope.clone()],
        };
        on_lsu_received(&mut adj, &mut area, &mut link, &lsu, Instant::now());
        assert!(area.get(&as_scope.header.key()).is_none());
        assert_eq!(adj.pending_acks, vec![]);
    }

    /// RFC 3101 §2.4: a Type-7 is accepted only on an NSSA's link, and a
    /// Type-5 never there.
    #[test]
    fn type7_only_in_an_nssa_and_type5_never_there() {
        let external = |lsa_type| {
            let mut l = Lsa {
                header: LsaHeader {
                    lsa_type,
                    link_state_id: router_id("192.0.2.0"),
                    ..header("9.9.9.10", 0x8000_0001u32.cast_signed())
                },
                body: lsa::LsaBody::AsExternal(lsa::AsExternalLsaBody {
                    tos: Vec::new(),
                    network_mask: router_id("255.255.255.0"),
                    metric: 0,
                    e_type2: false,
                    forwarding_address: Ipv4Addr::UNSPECIFIED,
                    external_route_tag: 0,
                }),
            };
            lsa::fill_checksum(&mut l);
            l
        };
        let (type5, type7) = (
            external(lsa::LSA_TYPE_AS_EXTERNAL),
            external(lsa::LSA_TYPE_NSSA_EXTERNAL),
        );
        for (stub, nssa, installed) in [(false, false, [true, false]), (true, true, [false, true])]
        {
            let mut adj = AdjacencyData {
                stub,
                nssa,
                ..Default::default()
            };
            let (mut area, mut link) = (Lsdb::default(), Lsdb::default());
            let lsu = LsuPacket {
                discarded: 0,
                last_error: None,
                router_id: router_id("9.9.9.10"),
                area_id: Ipv4Addr::UNSPECIFIED,
                lsas: vec![type5.clone(), type7.clone()],
            };
            on_lsu_received(&mut adj, &mut area, &mut link, &lsu, Instant::now());
            for (l, want) in [&type5, &type7].into_iter().zip(installed) {
                assert_eq!(area.get(&l.header.key()).is_some(), want, "nssa={nssa}");
            }
            assert_eq!(adj.pending_acks.len(), 1);
        }
    }
}
