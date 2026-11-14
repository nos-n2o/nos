use super::*;
use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn eq(v: u64) -> NumOp {
    NumOp {
        and: false,
        lt: false,
        gt: false,
        eq: true,
        value: v,
    }
}

#[allow(clippy::fn_params_excessive_bools, reason = "the RFC's operator bits")]
fn op(and: bool, lt: bool, gt: bool, eq: bool, value: u64) -> NumOp {
    NumOp {
        and,
        lt,
        gt,
        eq,
        value,
    }
}

fn v4(a: [u8; 4], len: u8) -> Prefix {
    Prefix::v4(Ipv4Net::new(Ipv4Addr::from(a), len).unwrap())
}

fn v6(s: &str, len: u8, offset: u8) -> Prefix {
    Prefix {
        net: IpNet::V6(Ipv6Net::new(s.parse().unwrap(), len).unwrap()),
        offset,
    }
}

fn fs(components: Vec<Component>) -> FlowSpec {
    FlowSpec { components }
}

/// Decodes `bytes`, checks the result and that it re-encodes to `bytes`.
fn roundtrip(afi: Afi, bytes: &[u8], want: &FlowSpec) {
    let (got, used) = FlowSpec::decode(afi, bytes).unwrap();
    assert_eq!(&got, want);
    assert_eq!(used, bytes.len());
    let mut out = Vec::new();
    want.encode(&mut out).unwrap();
    assert_eq!(out, bytes);
}

#[test]
fn rfc8955_example_1() {
    let want = fs(vec![
        Component::Dest(v4([192, 0, 2, 0], 24)),
        Component::Protocol(vec![eq(6)]),
        Component::Port(vec![eq(25)]),
    ]);
    roundtrip(
        Afi::V4,
        &[0x0b, 1, 0x18, 0xc0, 0, 2, 3, 0x81, 6, 4, 0x81, 0x19],
        &want,
    );
    assert_eq!(want.to_string(), "dest 192.0.2.0/24 proto =6 port =25");
}

#[test]
fn rfc8955_example_2() {
    let want = fs(vec![
        Component::Dest(v4([192, 0, 2, 0], 24)),
        Component::Source(v4([203, 0, 113, 0], 24)),
        Component::Port(vec![
            op(false, false, true, true, 137),
            op(true, true, false, true, 139),
            eq(8080),
        ]),
    ]);
    roundtrip(
        Afi::V4,
        &[
            0x12, 1, 0x18, 0xc0, 0, 2, 2, 0x18, 0xcb, 0, 0x71, 4, 0x03, 0x89, 0x45, 0x8b, 0x91,
            0x1f, 0x90,
        ],
        &want,
    );
    assert_eq!(
        want.to_string(),
        "dest 192.0.2.0/24 source 203.0.113.0/24 port >=137 && <=139 || =8080"
    );
}

#[test]
fn rfc8955_example_3() {
    let want = fs(vec![
        Component::Dest(v4([192, 0, 2, 1], 32)),
        Component::Fragment(vec![BitOp {
            and: false,
            not: false,
            m: false,
            value: 0x05,
        }]),
    ]);
    roundtrip(
        Afi::V4,
        &[0x09, 1, 0x20, 0xc0, 0, 2, 1, 0x0c, 0x80, 0x05],
        &want,
    );
    assert_eq!(want.to_string(), "dest 192.0.2.1/32 fragment any 0x5");
}

#[test]
fn rfc8956_example_1() {
    // The RFC's table prints 0x0d 0xbb for the destination; its decoded
    // column (and 2001:db8::/32) says 0xb8.
    let want = fs(vec![
        Component::Dest(v6("2001:db8::", 32, 0)),
        Component::Source(v6("::1234:5678:9a00:0", 104, 64)),
        Component::Protocol(vec![eq(6)]),
    ]);
    roundtrip(
        Afi::V6,
        &[
            0x12, 1, 0x20, 0, 0x20, 0x01, 0x0d, 0xb8, 2, 0x68, 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a,
            3, 0x81, 6,
        ],
        &want,
    );
    assert_eq!(
        want.to_string(),
        "dest 2001:db8::/32 offset 0 source ::1234:5678:9a00:0/104 offset 64 proto =6"
    );
}

#[test]
fn rfc8956_example_2_padding() {
    // 104 - 65 = 39 pattern bits, so the fifth pattern octet ends in one padding bit.
    let (got, _) = FlowSpec::decode(
        Afi::V6,
        &[
            0x0f, 1, 0x20, 0, 0x20, 0x01, 0x0d, 0xb8, 2, 0x68, 0x41, 0x24, 0x68, 0xac, 0xf1, 0x34,
        ],
    )
    .unwrap();
    let Component::Source(p) = &got.components[1] else {
        panic!()
    };
    assert_eq!((p.net.prefix_len(), p.offset), (104, 65));
    let mut out = Vec::new();
    got.encode(&mut out).unwrap();
    assert_eq!(out[10..], [0x41, 0x24, 0x68, 0xac, 0xf1, 0x34]);
    // A set padding bit is ignored on decode and zeroed on encode.
    let (dirty, _) = FlowSpec::decode(
        Afi::V6,
        &[
            0x0f, 1, 0x20, 0, 0x20, 0x01, 0x0d, 0xb8, 2, 0x68, 0x41, 0x24, 0x68, 0xac, 0xf1, 0x35,
        ],
    )
    .unwrap();
    assert_eq!(dirty, got);
}

#[test]
fn long_length_form() {
    // 80 ports of 3 octets each plus the type: 241 octets, so 0xf0f1.
    let ops: Vec<NumOp> = (0..80).map(|i| eq(1000 + i)).collect();
    let want = fs(vec![Component::Port(ops)]);
    let mut out = Vec::new();
    want.encode(&mut out).unwrap();
    assert_eq!(out[..2], [0xf0, 0xf1]);
    assert_eq!(out.len(), 243);
    assert_eq!(FlowSpec::decode(Afi::V4, &out).unwrap(), (want, 243));
}

#[test]
fn decode_stops_at_the_nlri_end() {
    let mut b = vec![0x03, 3, 0x81, 6, 0xaa];
    let (_, used) = FlowSpec::decode(Afi::V4, &b).unwrap();
    assert_eq!(used, 4);
    b.truncate(4);
    assert!(FlowSpec::decode(Afi::V4, &b).is_ok());
}

#[test]
fn malformed_nlris_are_errors() {
    let cases: &[(&str, Afi, &[u8])] = &[
        ("empty input", Afi::V4, &[]),
        ("zero length", Afi::V4, &[0]),
        ("length overrun", Afi::V4, &[5, 3, 0x81, 6]),
        ("truncated long length", Afi::V4, &[0xf0]),
        ("truncated value", Afi::V4, &[3, 3, 0x81, 6][..3]),
        ("op without value", Afi::V4, &[2, 3, 0x81]),
        ("value cut short", Afi::V4, &[3, 3, 0x91, 6]),
        ("missing end-of-list", Afi::V4, &[3, 3, 0x01, 6]),
        ("unsorted", Afi::V4, &[6, 4, 0x81, 1, 3, 0x81, 6]),
        ("duplicate type", Afi::V4, &[6, 3, 0x81, 1, 3, 0x81, 6]),
        ("type 0", Afi::V4, &[3, 0, 0x81, 1]),
        ("unknown type 14", Afi::V4, &[3, 14, 0x81, 1]),
        ("flow label on IPv4", Afi::V4, &[3, 13, 0x81, 1]),
        ("IPv4 prefix too long", Afi::V4, &[6, 1, 33, 1, 2, 3, 4]),
        ("IPv4 prefix truncated", Afi::V4, &[3, 1, 24, 192]),
        ("IPv6 len < offset", Afi::V6, &[3, 1, 8, 16]),
        ("IPv6 len == offset", Afi::V6, &[3, 1, 16, 16]),
        (
            "IPv6 len 129",
            Afi::V6,
            &[
                19, 1, 129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ),
        ("IPv6 len 0 offset 1", Afi::V6, &[3, 1, 0, 1]),
        ("IPv6 pattern truncated", Afi::V6, &[4, 1, 32, 0, 0x20]),
        ("DF bit on IPv6", Afi::V6, &[3, 12, 0x80, 0x01]),
    ];
    for (name, afi, bytes) in cases {
        assert!(FlowSpec::decode(*afi, bytes).is_err(), "{name}");
    }
    // Length 0 and offset 0 is the one allowed "match everything".
    assert!(FlowSpec::decode(Afi::V6, &[3, 1, 0, 0]).is_ok());
}

#[test]
fn first_and_bit_is_ignored_on_decode() {
    let (f, _) = FlowSpec::decode(Afi::V4, &[3, 4, 0xc1, 25]).unwrap();
    let Component::Port(ops) = &f.components[0] else {
        panic!()
    };
    assert!(!ops[0].and);
    let mut out = Vec::new();
    f.encode(&mut out).unwrap();
    assert_eq!(out, [3, 4, 0x81, 25]);
}

#[test]
fn encoding_is_canonical() {
    // Wider than needed on the wire, minimal after a round trip.
    let (f, _) = FlowSpec::decode(Afi::V4, &[6, 4, 0xa1, 0, 0, 0, 25]).unwrap();
    let mut out = Vec::new();
    f.encode(&mut out).unwrap();
    assert_eq!(out, [3, 4, 0x81, 25]);
    // u64 operand widths.
    for (v, n) in [
        (0xff, 1),
        (0x100, 2),
        (0xffff, 2),
        (0x1_0000, 4),
        (u64::MAX, 8),
    ] {
        let mut out = Vec::new();
        fs(vec![Component::PacketLen(vec![eq(v)])])
            .encode(&mut out)
            .unwrap();
        assert_eq!(out.len(), 1 + 1 + 1 + n);
    }
}

#[test]
fn ipv6_only_components() {
    let want = fs(vec![
        Component::Fragment(vec![BitOp {
            and: false,
            not: true,
            m: true,
            value: 0x0e,
        }]),
        Component::FlowLabel(vec![eq(0xabcde)]),
    ]);
    let mut out = Vec::new();
    want.encode(&mut out).unwrap();
    assert_eq!(out, [9, 12, 0x83, 0x0e, 13, 0xa1, 0, 0x0a, 0xbc, 0xde]);
    assert_eq!(FlowSpec::decode(Afi::V6, &out).unwrap().0, want);
    assert!(FlowSpec::decode(Afi::V4, &out).is_err());
    assert_eq!(
        want.to_string(),
        "fragment not match 0xe flow-label =703710"
    );
}

#[test]
fn encode_rejects_unencodable_rules() {
    let mut out = Vec::new();
    assert!(fs(vec![]).encode(&mut out).is_err());
    assert!(fs(vec![Component::Port(vec![])]).encode(&mut out).is_err());
    assert!(fs(vec![
        Component::Port(vec![eq(1)]),
        Component::Protocol(vec![eq(6)]),
    ])
    .encode(&mut out)
    .is_err());
    assert!(fs(vec![Component::Dest(v6("::", 10, 10))])
        .encode(&mut out)
        .is_err());
    let mut with_offset = v4([10, 0, 0, 0], 8);
    with_offset.offset = 3;
    assert!(fs(vec![Component::Dest(with_offset)])
        .encode(&mut out)
        .is_err());
    let huge = Component::Port((0..2000).map(eq).collect());
    assert!(fs(vec![huge]).encode(&mut out).is_err());
}

#[test]
fn vpn_form_round_trips_with_the_rd() {
    let rd: Rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1];
    let want = FlowSpecVpn {
        rd,
        flow: fs(vec![
            Component::Dest(v4([192, 0, 2, 0], 24)),
            Component::Protocol(vec![eq(6)]),
        ]),
    };
    let mut out = Vec::new();
    want.encode(&mut out).unwrap();
    assert_eq!(out[0], 8 + 5 + 3);
    assert_eq!(out[1..9], rd);
    assert_eq!(
        FlowSpecVpn::decode(Afi::V4, &out).unwrap(),
        (want.clone(), out.len())
    );
    assert_eq!(want.to_string(), "rd 65000:1 dest 192.0.2.0/24 proto =6");
    // Shorter than an RD, or an RD and nothing else.
    assert!(FlowSpecVpn::decode(Afi::V4, &[3, 0, 0, 0]).is_err());
    assert!(FlowSpecVpn::decode(Afi::V4, &[8, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
}

#[test]
fn display_operators() {
    let f = fs(vec![
        Component::PacketLen(vec![
            op(false, true, true, false, 0),
            op(false, true, false, false, 1),
            op(false, false, false, false, 2),
            op(true, true, true, true, 3),
        ]),
        Component::TcpFlags(vec![
            BitOp {
                and: false,
                not: false,
                m: true,
                value: 0x12,
            },
            BitOp {
                and: true,
                not: true,
                m: false,
                value: 0x04,
            },
        ]),
    ]);
    assert_eq!(
        f.to_string(),
        "len !=0 || <1 || false && true tcp-flags match 0x12 && not any 0x4"
    );
}

fn ord(a: &FlowSpec, b: &FlowSpec) -> Ordering {
    cmp_precedence(a, b)
}

#[test]
fn ordering_table() {
    let port = |p| Component::Port(vec![eq(p)]);
    let dest = |a, l| Component::Dest(v4(a, l));
    let rules = [
        // (higher precedence, lower precedence)
        (
            fs(vec![dest([10, 0, 0, 0], 24)]),
            fs(vec![dest([10, 0, 0, 0], 8)]),
        ), // more specific prefix
        (
            fs(vec![dest([10, 0, 0, 0], 8)]),
            fs(vec![dest([11, 0, 0, 0], 8)]),
        ), // disjoint: lowest address
        (fs(vec![port(25)]), fs(vec![port(80)])), // lowest value
        (
            fs(vec![Component::Protocol(vec![eq(6)])]),
            fs(vec![port(80)]),
        ), // lower type
        (
            fs(vec![dest([10, 0, 0, 0], 8), port(25)]),
            fs(vec![dest([10, 0, 0, 0], 8)]),
        ), // a strict prefix of the other loses
        (
            fs(vec![Component::Port(vec![eq(25), eq(26)])]),
            fs(vec![port(25)]),
        ), // memcmp common prefix equal: longer wins
        (
            fs(vec![Component::Port(vec![eq(1)])]),
            fs(vec![Component::Port(vec![eq(300)])]),
        ), // 0x81 01 vs 0x91 01 2c
        (
            fs(vec![Component::Dest(v6("::", 0, 0))]),
            fs(vec![Component::Dest(v6("0:0:0:0:1::", 80, 64))]),
        ), // IPv6: lowest offset wins
        (
            fs(vec![Component::Dest(v6("2001:db8::", 48, 0))]),
            fs(vec![Component::Dest(v6("2001:db8::", 32, 0))]),
        ),
    ];
    for (hi, lo) in rules {
        assert_eq!(ord(&hi, &lo), Ordering::Less, "{hi} before {lo}");
        assert_eq!(ord(&lo, &hi), Ordering::Greater, "{lo} after {hi}");
        assert_eq!(ord(&hi, &hi), Ordering::Equal);
    }
}

// ---- Appendix A cross-check -------------------------------------------

#[derive(Clone)]
enum RefVal {
    Net(IpNet, u8),
    Bytes(Vec<u8>),
}

/// Literal transcription of RFC 8955 / 8956 Appendix A `flow_rule_cmp`
/// (1 = `A_HAS_PRECEDENCE`, 2 = `B_HAS_PRECEDENCE`, 0 = EQUAL).
#[allow(clippy::many_single_char_names, reason = "mirrors the RFC's Python")]
fn flow_rule_cmp(a: &[(u8, RefVal)], b: &[(u8, RefVal)]) -> u8 {
    let n = a.len().max(b.len());
    for i in 0..n {
        let (Some(ca), Some(cb)) = (a.get(i), b.get(i)) else {
            return if a.get(i).is_none() { 2 } else { 1 };
        };
        if ca.0 < cb.0 {
            return 1;
        }
        if ca.0 > cb.0 {
            return 2;
        }
        match (&ca.1, &cb.1) {
            (RefVal::Net(x, xo), RefVal::Net(y, yo)) => {
                if xo < yo {
                    return 1;
                }
                if xo > yo {
                    return 2;
                }
                let overlaps = x.contains(y) || y.contains(x);
                if overlaps {
                    if x.prefix_len() > y.prefix_len() {
                        return 1;
                    }
                    if x.prefix_len() < y.prefix_len() {
                        return 2;
                    }
                } else if x.addr() > y.addr() {
                    return 2;
                } else if x.addr() < y.addr() {
                    return 1;
                }
            }
            (RefVal::Bytes(x), RefVal::Bytes(y)) => {
                if x.len() == y.len() {
                    if x > y {
                        return 2;
                    }
                    if x < y {
                        return 1;
                    }
                } else {
                    let common = x.len().min(y.len());
                    if x[..common] > y[..common] {
                        return 2;
                    } else if x[..common] < y[..common] || x.len() > y.len() {
                        return 1;
                    }
                    return 2;
                }
            }
            _ => unreachable!(),
        }
    }
    0
}

fn to_ref(f: &FlowSpec) -> Vec<(u8, RefVal)> {
    f.components
        .iter()
        .map(|c| {
            let v = match c {
                Component::Dest(p) | Component::Source(p) => RefVal::Net(p.net, p.offset),
                other => RefVal::Bytes(other.body_bytes()),
            };
            (c.type_code(), v)
        })
        .collect()
}

// ---- generators ----------------------------------------------------------

fn arb_value() -> impl Strategy<Value = u64> {
    prop_oneof![
        0u64..4,
        any::<u8>().prop_map(u64::from),
        any::<u16>().prop_map(u64::from),
        any::<u32>().prop_map(u64::from),
        any::<u64>(),
    ]
}

fn arb_num() -> impl Strategy<Value = Vec<NumOp>> {
    prop::collection::vec((any::<bool>(), 0u8..8, arb_value()), 1..4).prop_map(|v| {
        v.into_iter()
            .enumerate()
            .map(|(i, (and, f, value))| NumOp {
                and: i > 0 && and,
                lt: f & 4 != 0,
                gt: f & 2 != 0,
                eq: f & 1 != 0,
                value,
            })
            .collect()
    })
}

fn arb_bit(v6: bool) -> impl Strategy<Value = Vec<BitOp>> {
    prop::collection::vec((any::<bool>(), 0u8..4, arb_value()), 1..4).prop_map(move |v| {
        v.into_iter()
            .enumerate()
            .map(|(i, (and, f, value))| BitOp {
                and: i > 0 && and,
                not: f & 2 != 0,
                m: f & 1 != 0,
                value: if v6 { value & !1 } else { value },
            })
            .collect()
    })
}

fn arb_v4_prefix() -> impl Strategy<Value = Prefix> {
    (any::<u32>(), 0u8..=32)
        .prop_map(|(a, l)| Prefix::v4(Ipv4Net::new(Ipv4Addr::from(a), l).unwrap()))
}

fn arb_v6_prefix() -> impl Strategy<Value = Prefix> {
    (any::<u128>(), 0u8..=128)
        .prop_flat_map(|(a, len)| (Just(a), Just(len), 0u8..len.max(1)))
        .prop_map(|(a, len, offset)| {
            let mut keep = 0u128;
            for pos in offset..len {
                keep |= 1u128 << (127 - u32::from(pos));
            }
            Prefix {
                net: IpNet::V6(Ipv6Net::new(Ipv6Addr::from(a & keep), len).unwrap()),
                offset,
            }
        })
}

fn arb_flowspec(afi: Afi) -> impl Strategy<Value = FlowSpec> {
    let v6 = afi == Afi::V6;
    let prefix = move || -> BoxedStrategy<Prefix> {
        if v6 {
            arb_v6_prefix().boxed()
        } else {
            arb_v4_prefix().boxed()
        }
    };
    let comp = prop_oneof![
        prefix().prop_map(Component::Dest),
        prefix().prop_map(Component::Source),
        arb_num().prop_map(Component::Protocol),
        arb_num().prop_map(Component::Port),
        arb_num().prop_map(Component::DstPort),
        arb_num().prop_map(Component::SrcPort),
        arb_num().prop_map(Component::IcmpType),
        arb_num().prop_map(Component::IcmpCode),
        arb_bit(false).prop_map(Component::TcpFlags),
        arb_num().prop_map(Component::PacketLen),
        arb_num().prop_map(Component::Dscp),
        arb_bit(v6).prop_map(Component::Fragment),
        arb_num().prop_map(move |o| if v6 {
            Component::FlowLabel(o)
        } else {
            Component::Dscp(o)
        }),
    ];
    prop::collection::vec(comp, 1..6).prop_map(|mut c| {
        c.sort_by_key(Component::type_code);
        c.dedup_by_key(|x| x.type_code());
        FlowSpec { components: c }
    })
}

proptest! {
    #[test]
    fn v4_round_trip(f in arb_flowspec(Afi::V4)) {
        let mut out = Vec::new();
        f.encode(&mut out).unwrap();
        prop_assert_eq!(FlowSpec::decode(Afi::V4, &out).unwrap(), (f, out.len()));
    }

    #[test]
    fn v6_round_trip(f in arb_flowspec(Afi::V6)) {
        let mut out = Vec::new();
        f.encode(&mut out).unwrap();
        prop_assert_eq!(FlowSpec::decode(Afi::V6, &out).unwrap(), (f, out.len()));
    }

    #[test]
    fn decode_never_panics(b in prop::collection::vec(any::<u8>(), 0..64), v6 in any::<bool>()) {
        let afi = if v6 { Afi::V6 } else { Afi::V4 };
        let _ = FlowSpec::decode(afi, &b);
        let _ = FlowSpecVpn::decode(afi, &b);
    }

    #[test]
    fn matches_appendix_a(a in arb_flowspec(Afi::V6), b in arb_flowspec(Afi::V6)) {
        let want = match flow_rule_cmp(&to_ref(&a), &to_ref(&b)) {
            1 => Ordering::Less,
            2 => Ordering::Greater,
            _ => Ordering::Equal,
        };
        prop_assert_eq!(cmp_precedence(&a, &b), want);
    }

    #[test]
    fn matches_appendix_a_v4(a in arb_flowspec(Afi::V4), b in arb_flowspec(Afi::V4)) {
        let want = match flow_rule_cmp(&to_ref(&a), &to_ref(&b)) {
            1 => Ordering::Less,
            2 => Ordering::Greater,
            _ => Ordering::Equal,
        };
        prop_assert_eq!(cmp_precedence(&a, &b), want);
    }
}

#[test]
fn action_communities_render_as_text() {
    assert_eq!(format_action(0x8006_0000_0000_0000), "traffic-rate:0:0");
    assert_eq!(
        format_action(0x8006_fde8_476a_6000),
        "traffic-rate:65000:60000"
    );
    assert_eq!(format_action(0x8008_fde8_0000_000a), "redirect:65000:10");
    assert_eq!(format_action(0x8009_0000_0000_000a), "traffic-marking:10");
    assert_eq!(format_action(0x0002_fde8_0000_2710), "RT:65000:10000");
}

#[test]
fn dest_prefix_host_bits_are_truncated() {
    // #603: component 1, /20 with host bits set in the third octet.
    let mut b: &[u8] = &[20, 10, 0, 0x0f];
    let p = decode_prefix(Afi::V4, &mut b).unwrap();
    assert_eq!(p, v4([10, 0, 0, 0], 20));
}
