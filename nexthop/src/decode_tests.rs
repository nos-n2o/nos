use super::*;

fn nla(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    out.extend_from_slice(&u16::try_from(4 + payload.len()).unwrap().to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len().next_multiple_of(4), 0);
}

/// An `RTM_NEWNEXTHOP` message as a dump carries it.
fn msg(kind: u16, flags: u32, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = vec![2, 0, 4, 0];
    body.extend_from_slice(&flags.to_ne_bytes());
    for (k, p) in attrs {
        nla(&mut body, *k, p);
    }
    let mut out = u32::try_from(16 + body.len())
        .unwrap()
        .to_ne_bytes()
        .to_vec();
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&[2, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&body);
    out
}

fn id(n: u32) -> (u16, Vec<u8>) {
    (NHA_ID, n.to_ne_bytes().to_vec())
}

fn done() -> Vec<u8> {
    let mut m = 20u32.to_ne_bytes().to_vec();
    m.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
    m.resize(20, 0);
    m
}

fn parse(buf: &[u8], range: RangeInclusive<u32>) -> (Vec<NexthopRecord>, bool) {
    let mut out = Vec::new();
    let end = dump_part(buf, &range, &mut out).unwrap();
    (out, end)
}

#[test]
fn a_gateway_with_oif_and_onlink() {
    let m = msg(
        RTM_NEWNEXTHOP,
        RTNH_F_ONLINK,
        &[
            id(5),
            (NHA_GATEWAY, vec![10, 0, 0, 1]),
            (NHA_OIF, 9u32.to_ne_bytes().to_vec()),
        ],
    );
    let (r, end) = parse(&m, 0..=u32::MAX);
    assert!(!end);
    assert_eq!(
        r,
        vec![NexthopRecord {
            id: 5,
            gateway: Some("10.0.0.1".parse().unwrap()),
            oif: Some(9),
            onlink: true,
            ..Default::default()
        }]
    );
}

#[test]
fn an_mpls_encap_gives_the_labels_and_an_unknown_attribute_is_skipped() {
    let mut inner = Vec::new();
    let mut stack = (100u32 << 12).to_be_bytes().to_vec();
    stack.extend_from_slice(&((200u32 << 12) | 0x100).to_be_bytes());
    nla(&mut inner, MPLS_IPTUNNEL_DST, &stack);
    let m = msg(
        RTM_NEWNEXTHOP,
        0,
        &[
            id(6),
            (
                NHA_GATEWAY,
                "fd00::1".parse::<Ipv6Addr>().unwrap().octets().to_vec(),
            ),
            (99, vec![1, 2, 3]),
            (NHA_ENCAP_TYPE, LWTUNNEL_ENCAP_MPLS.to_ne_bytes().to_vec()),
            (NHA_ENCAP | NLA_F_NESTED, inner),
        ],
    );
    let (r, _) = parse(&m, 0..=u32::MAX);
    assert_eq!(r[0].labels, vec![100, 200]);
    assert_eq!(r[0].gateway, Some("fd00::1".parse().unwrap()));
}

#[test]
fn a_group_restores_weights_and_fdb_and_blackhole_are_flags() {
    let mut grp = 1u32.to_ne_bytes().to_vec();
    grp.extend_from_slice(&[0, 0, 0, 0]);
    grp.extend_from_slice(&2u32.to_ne_bytes());
    grp.extend_from_slice(&[43, 1, 0, 0]);
    let g = msg(
        RTM_NEWNEXTHOP,
        0,
        &[id(7), (NHA_GROUP, grp), (NHA_FDB, vec![])],
    );
    let b = msg(RTM_NEWNEXTHOP, 0, &[id(8), (NHA_BLACKHOLE, vec![])]);
    let (r, _) = parse(&[g, b].concat(), 0..=u32::MAX);
    assert_eq!(r[0].group, Some(vec![(1, 1), (2, 300)]));
    assert!(r[0].fdb && !r[0].blackhole);
    assert!(r[1].blackhole && r[1].group.is_none());
}

#[test]
fn the_id_range_filters_and_done_ends_the_dump() {
    let buf = [
        msg(RTM_NEWNEXTHOP, 0, &[id(5)]),
        msg(RTM_NEWNEXTHOP, 0, &[id(1 << 20)]),
        done(),
        msg(RTM_NEWNEXTHOP, 0, &[id(6)]),
    ]
    .concat();
    let (r, end) = parse(&buf, 0..=100);
    assert!(end);
    assert_eq!(r.iter().map(|r| r.id).collect::<Vec<_>>(), vec![5]);
}

#[test]
fn an_error_message_and_garbage_are_errors() {
    let mut e = 36u32.to_ne_bytes().to_vec();
    e.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
    e.resize(16, 0);
    e.extend_from_slice(&(-22i32).to_ne_bytes());
    e.resize(36, 0);
    let mut out = Vec::new();
    let err = dump_part(&e, &(0..=1), &mut out).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(22));
    assert!(dump_part(
        &[40, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &(0..=1),
        &mut out
    )
    .is_err());
    assert!(record(&[0; 4]).is_err());
    // an attribute longer than the buffer
    let mut bad = vec![0u8; 8];
    bad.extend_from_slice(&[40, 0, 1, 0]);
    assert!(record(&bad).is_err());
}

#[test]
fn an_ack_carries_the_negated_errno() {
    let mut reply = vec![0u8; 36];
    reply[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    reply[16..20].copy_from_slice(&(-2i32).to_ne_bytes());
    assert_eq!(ack_errno(&reply).unwrap(), -2);
    assert!(ack_errno(&reply[..8]).is_err());
}
