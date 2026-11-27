use std::net::Ipv4Addr;

use super::*;

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([b[at], b[at + 1]])
}

fn v4(id: u32, a: [u8; 4]) -> Gateway {
    Gateway::fdb(id, Ipv4Addr::from(a).into())
}

fn plain(id: u32) -> Gateway {
    Gateway {
        fdb: false,
        ..v4(id, [10, 0, 0, 1])
    }
}

#[test]
fn an_fdb_gateway_is_an_id_a_v4_gateway_and_the_fdb_flag() {
    let m = encode(&Nexthop::Gateway(v4(0x0102_0304, [10, 50, 0, 7])), 9).unwrap();
    assert_eq!(
        u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize,
        m.len()
    );
    assert_eq!(u16_at(&m, 4), RTM_NEWNEXTHOP);
    assert_eq!(
        u16_at(&m, 6),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
    );
    assert_eq!(u32::from_ne_bytes(m[8..12].try_into().unwrap()), 9);
    // nhmsg: AF_INET, scope 0 (the kernel rejects anything else), no flags
    assert_eq!(&m[16..24], &[AF_INET, 0, RTPROT_STATIC, 0, 0, 0, 0, 0]);
    assert_eq!((u16_at(&m, 24), u16_at(&m, 26)), (8, NHA_ID));
    assert_eq!(&m[28..32], &0x0102_0304u32.to_ne_bytes());
    assert_eq!((u16_at(&m, 32), u16_at(&m, 34)), (8, NHA_GATEWAY));
    assert_eq!(&m[36..40], &[10, 50, 0, 7]);
    assert_eq!((u16_at(&m, 40), u16_at(&m, 42)), (4, NHA_FDB));
    assert_eq!(m.len(), 44);
}

#[test]
fn a_v6_gateway_is_af_inet6_with_16_octets() {
    let gw: std::net::Ipv6Addr = "fd00:10:50::a".parse().unwrap();
    let m = encode(&Nexthop::Gateway(Gateway::fdb(1, gw.into())), 1).unwrap();
    assert_eq!(&m[16..20], &[AF_INET6, 0, RTPROT_STATIC, 0]);
    assert_eq!((u16_at(&m, 32), u16_at(&m, 34)), (4 + 16, NHA_GATEWAY));
    assert_eq!(&m[36..52], &gw.octets());
    assert_eq!((u16_at(&m, 52), u16_at(&m, 54)), (4, NHA_FDB));
    assert_eq!(m.len(), 56);
}

#[test]
fn onlink_sets_the_nhmsg_flag_and_oif_adds_an_attribute() {
    let g = Gateway {
        onlink: true,
        oif: Some(7),
        replace: false,
        ..plain(3)
    };
    let m = encode(&Nexthop::Gateway(g), 1).unwrap();
    assert_eq!(&m[20..24], &RTNH_F_ONLINK.to_ne_bytes());
    assert_eq!(u16_at(&m, 6), NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE);
    assert_eq!((u16_at(&m, 40), u16_at(&m, 42)), (8, NHA_OIF));
    assert_eq!(&m[44..48], &7u32.to_ne_bytes());
    assert_eq!(m.len(), 48, "no fdb flag");
}

#[test]
fn an_mpls_stack_is_a_nested_encap_with_the_bottom_bit_on_the_last() {
    let g = Gateway {
        labels: vec![100, 200],
        ..plain(3)
    };
    let m = encode(&Nexthop::Gateway(g), 1).unwrap();
    // after NHA_ID (24..32) and NHA_GATEWAY (32..40)
    assert_eq!((u16_at(&m, 40), u16_at(&m, 42)), (6, NHA_ENCAP_TYPE));
    assert_eq!(u16_at(&m, 44), LWTUNNEL_ENCAP_MPLS);
    assert_eq!(
        (u16_at(&m, 48), u16_at(&m, 50)),
        (4 + 4 + 8, NHA_ENCAP | NLA_F_NESTED)
    );
    assert_eq!((u16_at(&m, 52), u16_at(&m, 54)), (4 + 8, MPLS_IPTUNNEL_DST));
    assert_eq!(&m[56..60], &(100u32 << 12).to_be_bytes());
    assert_eq!(&m[60..64], &((200u32 << 12) | 0x100).to_be_bytes());
    assert_eq!(m.len(), 64);
}

#[test]
fn a_group_lists_its_members_with_weights_minus_one() {
    let m = encode(
        &Nexthop::Group(Group {
            id: 7,
            members: vec![(1, 1), (2, 3)],
            fdb: true,
        }),
        1,
    )
    .unwrap();
    assert_eq!(m[16], 0, "a group has no address family");
    assert_eq!(u16_at(&m, 26), NHA_ID);
    assert_eq!((u16_at(&m, 32), u16_at(&m, 34)), (4 + 16, NHA_GROUP));
    assert_eq!(&m[36..40], &1u32.to_ne_bytes());
    assert_eq!(&m[40..44], &[0, 0, 0, 0], "weight 1 is stored as 0");
    assert_eq!(&m[44..48], &2u32.to_ne_bytes());
    assert_eq!(&m[48..52], &[2, 0, 0, 0], "weight 3 is stored as 2");
    assert_eq!((u16_at(&m, 52), u16_at(&m, 54)), (4, NHA_FDB));
}

#[test]
fn a_big_weight_spills_into_weight_high_and_a_plain_group_has_no_fdb_flag() {
    let m = encode(
        &Nexthop::Group(Group {
            id: 7,
            members: vec![(1, 300)],
            fdb: false,
        }),
        1,
    )
    .unwrap();
    assert_eq!(&m[40..44], &[43, 1, 0, 0], "299 = 0x012b");
    assert_eq!(m.len(), 44);
}

#[test]
fn a_delete_names_only_the_id() {
    let m = encode(&Nexthop::Delete { id: 5 }, 1).unwrap();
    assert_eq!(&m[16..24], &[0; 8], "the whole nhmsg is zero");
    assert_eq!(u16_at(&m, 4), RTM_DELNEXTHOP);
    assert_eq!(u16_at(&m, 6), NLM_F_REQUEST | NLM_F_ACK);
    assert_eq!(m.len(), 16 + 8 + 8);
}

#[test]
fn a_dump_request_is_an_empty_nhmsg() {
    let m = dump_request(4);
    assert_eq!(u16_at(&m, 4), RTM_GETNEXTHOP);
    assert_eq!(u16_at(&m, 6), NLM_F_REQUEST | NLM_F_DUMP);
    assert_eq!(&m[16..], &[0; 8]);
}

#[test]
fn what_the_kernel_would_reject_obscurely_is_refused_here() {
    let refused = |nh: Nexthop| {
        assert_eq!(
            encode(&nh, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "{nh:?}"
        );
    };
    let grp = |id, members: Vec<(u32, u16)>| {
        Nexthop::Group(Group {
            id,
            members,
            fdb: false,
        })
    };
    refused(Nexthop::Gateway(plain(0)));
    refused(Nexthop::Delete { id: 0 });
    refused(grp(0, vec![(1, 1)]));
    refused(grp(5, vec![]));
    refused(grp(5, vec![(5, 1)]));
    refused(grp(5, vec![(0, 1)]));
    refused(grp(5, vec![(1, 0)]));
    refused(Nexthop::Gateway(Gateway {
        fdb: true,
        oif: Some(1),
        ..plain(1)
    }));
    refused(Nexthop::Gateway(Gateway {
        fdb: true,
        onlink: true,
        ..plain(1)
    }));
    refused(Nexthop::Gateway(Gateway {
        fdb: true,
        labels: vec![16],
        ..plain(1)
    }));
    refused(Nexthop::Gateway(Gateway {
        labels: vec![1 << 20],
        ..plain(1)
    }));
    refused(Nexthop::Gateway(Gateway {
        labels: vec![16; MAX_LABELS + 1],
        ..plain(1)
    }));
    encode(
        &Nexthop::Gateway(Gateway {
            labels: vec![16; MAX_LABELS],
            ..plain(1)
        }),
        1,
    )
    .unwrap();
}
