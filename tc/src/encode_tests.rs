use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        write!(s, "{x:02x}").unwrap();
        s
    })
}
fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}

/// The `(kind, payload)` attributes of a block, one level deep.
fn attrs(b: &[u8]) -> Vec<(u16, &[u8])> {
    let mut v = Vec::new();
    let mut at = 0;
    while at + 4 <= b.len() {
        let len = usize::from(u16_at(b, at));
        v.push((u16_at(b, at + 2) & !NLA_F_NESTED, &b[at + 4..at + len]));
        at += len.next_multiple_of(4);
    }
    v
}

fn add(f: Filter) -> Vec<u8> {
    encode(&Request::AddFilter(f), 1).unwrap()
}

fn filter(protocol: Protocol, kind: Kind, actions: Vec<Action>) -> Filter {
    Filter {
        ifindex: 5,
        hook: Hook::Ingress,
        chain: 0,
        prio: 1,
        protocol,
        handle: 1,
        kind,
        actions,
        replace: false,
    }
}

fn flower(protocol: Protocol, keys: FlowerKeys) -> Vec<u8> {
    add(filter(
        protocol,
        Kind::Flower(keys),
        vec![Action::new(ActionKind::Gact(Verdict::Ok))],
    ))
}

/// The flower keys of a message, the action table dropped.
fn keys(m: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let top = attrs(&m[36..]);
    let opts = top.iter().find(|(k, _)| *k == TCA_OPTIONS).unwrap().1;
    attrs(opts)
        .into_iter()
        .filter(|(k, _)| *k != TCA_FLOWER_ACT)
        .map(|(k, v)| (k, v.to_vec()))
        .collect()
}

/// The parameters of action `n` (from 0) of a flower message.
fn action_attrs(m: &[u8], n: usize) -> Vec<(u16, Vec<u8>)> {
    let top = attrs(&m[36..]);
    let opts = attrs(top.iter().find(|(k, _)| *k == TCA_OPTIONS).unwrap().1);
    let table = opts.iter().find(|(k, _)| *k == TCA_FLOWER_ACT).unwrap().1;
    attrs(attrs(table)[n].1)
        .into_iter()
        .map(|(k, v)| (k, v.to_vec()))
        .collect()
}

fn verdict_of(m: &[u8]) -> i32 {
    let act = action_attrs(m, 0);
    let parms = attrs(&act[1].1)[0].1;
    i32::from_ne_bytes(parms[8..12].try_into().unwrap())
}

// Golden messages: the bytes `nos-fdbd`'s and `nos-interfaced`'s own
// encoders produced before they moved onto this crate (#545), on a
// little-endian host. A change here is a byte regression of local bias or the
// BPDU trap.
const MCAST_MAC: [u8; 6] = [1, 0, 0, 0, 0, 0];
const MAC_SSTP: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd];

fn fdb_mark(ifindex: u32, prio: u16, handle: u32, src: Option<IpAddr>, bits: u32) -> Filter {
    Filter {
        ifindex,
        hook: Hook::Ingress,
        chain: 0,
        prio,
        protocol: Protocol::All,
        handle,
        kind: Kind::Flower(FlowerKeys {
            eth_dst: Some((MCAST_MAC, Some(MCAST_MAC))),
            enc_src_ip: src,
            ..FlowerKeys::default()
        }),
        actions: vec![Action::new(ActionKind::Skbedit {
            mark: 0xE500_0000 | bits,
            mask: 0xFF00_FFFF,
            verdict: Verdict::Pipe,
        })],
        replace: false,
    }
}

fn fdb_drop(prio: u16, bits: u32) -> Filter {
    Filter {
        ifindex: 3,
        hook: Hook::Egress,
        chain: 0,
        prio,
        protocol: Protocol::All,
        handle: 0xE500_0000 | bits,
        kind: Kind::Fw {
            mask: 0xFF00_0000 | bits,
        },
        actions: vec![Action::new(ActionKind::Gact(Verdict::Shot))],
        replace: false,
    }
}

#[test]
#[cfg(target_endian = "little")]
fn fdb_messages_are_byte_identical_to_its_former_encoder() {
    let clsact = encode(&Request::Clsact { ifindex: 7 }, 3).unwrap();
    assert_eq!(
        hex(&clsact),
        "3000000024000506030000000000000000000000070000000000fffff1ffffff000000000b000100636c736163740000"
    );
    let v4 = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(
        hex(&add(fdb_mark(9, 1, 4, v4, 0b101))),
        "940000002c0005040100000000000000000000000900000004000000f2ffffff000301000b000100666c6f7765720000640002800a00040001000000000000000a000500010000000000000008001b000a000002400003803c0001800c000100736b6265646974002c00028018000200000000000000000003000000000000000000000008000500050000e508000800ffff00ff"
    );
    let v6 = Some("fd00::2".parse().unwrap());
    assert_eq!(
        hex(&add(fdb_mark(1, 1, 1, v6, 1))),
        "a00000002c0005040100000000000000000000000100000001000000f2ffffff000301000b000100666c6f7765720000700002800a00040001000000000000000a000500010000000000000014001f00fd000000000000000000000000000002400003803c0001800c000100736b6265646974002c00028018000200000000000000000003000000000000000000000008000500010000e508000800ffff00ff"
    );
    assert_eq!(
        hex(&add(fdb_mark(1, 2, 1, None, 0))),
        "8c0000002c0005040100000000000000000000000100000001000000f2ffffff000302000b000100666c6f77657200005c0002800a00040001000000000000000a0005000100000000000000400003803c0001800c000100736b6265646974002c00028018000200000000000000000003000000000000000000000008000500000000e508000800ffff00ff"
    );
    assert_eq!(
        hex(&add(fdb_drop(1, 0x10))),
        "680000002c00050401000000000000000000000003000000100000e5f3ffffff0003010007000100667700003c00028008000500100000ff300004802c0001800900010067616374000000001c000280180002000000000000000000020000000000000000000000"
    );
    assert_eq!(
        hex(&add(fdb_drop(2, 0))),
        "680000002c00050401000000000000000000000003000000000000e5f3ffffff0003020007000100667700003c00028008000500000000ff300004802c0001800900010067616374000000001c000280180002000000000000000000020000000000000000000000"
    );
    let del = Request::DelFilter {
        ifindex: 4,
        hook: Hook::Egress,
        chain: 0,
        prio: 2,
        protocol: Protocol::All,
        handle: 0,
    };
    assert_eq!(
        hex(&encode(&del, 1).unwrap()),
        "240000002d0005000100000000000000000000000400000000000000f3ffffff00030200"
    );
}

#[test]
#[cfg(target_endian = "little")]
fn interfaced_messages_are_byte_identical_to_its_former_encoder() {
    let trap = Filter {
        ifindex: 9,
        hook: Hook::Ingress,
        chain: 0,
        prio: 1,
        protocol: Protocol::Llc802_2,
        handle: 2,
        kind: Kind::Flower(FlowerKeys {
            eth_dst: Some((MAC_SSTP, None)),
            ..FlowerKeys::default()
        }),
        actions: vec![Action::new(ActionKind::Gact(Verdict::Shot))],
        replace: false,
    };
    assert_eq!(
        hex(&add(trap)),
        "700000002c0005040100000000000000000000000900000002000000f2ffffff000401000b000100666c6f7765720000400002800a00040001000ccccccd0000300003802c0001800900010067616374000000001c000280180002000000000000000000020000000000000000000000"
    );
    let del = Request::DelFilter {
        ifindex: 4,
        hook: Hook::Ingress,
        chain: 0,
        prio: 1,
        protocol: Protocol::Llc802_2,
        handle: 1,
    };
    assert_eq!(
        hex(&encode(&del, 1).unwrap()),
        "240000002d0005000100000000000000000000000400000001000000f2ffffff00040100"
    );
}

#[test]
fn clsact_is_created_exclusively_on_the_clsact_parent() {
    let m = encode(&Request::Clsact { ifindex: 7 }, 3).unwrap();
    assert_eq!(u32_at(&m, 0) as usize, m.len());
    assert_eq!(u16_at(&m, 4), RTM_NEWQDISC);
    assert_eq!(
        u16_at(&m, 6),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    );
    assert_eq!(u32_at(&m, 8), 3);
    assert_eq!(u32_at(&m, 20), 7, "ifindex");
    assert_eq!(u32_at(&m, 24), 0xFFFF_0000, "handle");
    assert_eq!(u32_at(&m, 28), CLSACT, "parent");
    assert_eq!(attrs(&m[36..]), [(TCA_KIND, &b"clsact\0"[..])]);
}

#[test]
fn ip_filters_carry_their_ethertype_in_tcm_info_and_as_a_key() {
    let m = flower(Protocol::Ip, FlowerKeys::default());
    assert_eq!(u32_at(&m, 32), (1 << 16) | 0x0008, "prio 1, htons(0x0800)");
    assert_eq!(keys(&m), [(TCA_FLOWER_KEY_ETH_TYPE, vec![0x08, 0x00])]);
    let m = flower(Protocol::Ipv6, FlowerKeys::default());
    assert_eq!(u32_at(&m, 32) & 0xFFFF, 0xDD86);
    assert_eq!(keys(&m), [(TCA_FLOWER_KEY_ETH_TYPE, vec![0x86, 0xDD])]);
    // A keyless flower on every protocol is the match-all: no key at all.
    assert_eq!(keys(&flower(Protocol::All, FlowerKeys::default())), []);
}

#[test]
fn prefixes_send_the_address_and_its_mask() {
    let m = flower(
        Protocol::Ip,
        FlowerKeys {
            src_ip: Some((IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16)),
            dst_ip: Some((IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32)),
            ..FlowerKeys::default()
        },
    );
    assert_eq!(
        keys(&m)[1..],
        [
            (TCA_FLOWER_KEY_IPV4_SRC, vec![10, 1, 0, 0]),
            (TCA_FLOWER_KEY_IPV4_SRC_MASK, vec![255, 255, 0, 0]),
            (TCA_FLOWER_KEY_IPV4_DST, vec![192, 0, 2, 1]),
            (TCA_FLOWER_KEY_IPV4_DST_MASK, vec![255; 4]),
        ]
    );
    let m = flower(
        Protocol::Ipv6,
        FlowerKeys {
            src_ip: Some((
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                32,
            )),
            dst_ip: Some((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)),
            ..FlowerKeys::default()
        },
    );
    let mut src_mask = vec![0u8; 16];
    src_mask[..4].fill(255);
    assert_eq!(
        keys(&m)[1..],
        [
            (
                TCA_FLOWER_KEY_IPV6_SRC,
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)
                    .octets()
                    .to_vec()
            ),
            (TCA_FLOWER_KEY_IPV6_SRC_MASK, src_mask),
            (TCA_FLOWER_KEY_IPV6_DST, vec![0; 16]),
            (TCA_FLOWER_KEY_IPV6_DST_MASK, vec![0; 16]),
        ]
    );
}

#[test]
fn port_ranges_use_min_max_and_an_exact_port_the_protocol_key() {
    let m = flower(
        Protocol::Ip,
        FlowerKeys {
            ip_proto: Some(IPPROTO_TCP),
            src_port: Some((1024, 65535)),
            dst_port: Some((179, 179)),
            ..FlowerKeys::default()
        },
    );
    assert_eq!(
        keys(&m)[1..],
        [
            (TCA_FLOWER_KEY_IP_PROTO, vec![6]),
            (TCA_FLOWER_KEY_PORT_SRC_MIN, vec![0x04, 0x00]),
            (TCA_FLOWER_KEY_PORT_SRC_MAX, vec![0xff, 0xff]),
            (TCA_FLOWER_KEY_TCP_DST, vec![0, 179]),
        ]
    );
    let m = flower(
        Protocol::Ipv6,
        FlowerKeys {
            ip_proto: Some(IPPROTO_UDP),
            src_port: Some((53, 53)),
            dst_port: Some((5000, 5010)),
            ..FlowerKeys::default()
        },
    );
    assert_eq!(
        keys(&m)[2..],
        [
            (TCA_FLOWER_KEY_UDP_SRC, vec![0, 53]),
            (TCA_FLOWER_KEY_PORT_DST_MIN, 5000u16.to_be_bytes().to_vec()),
            (TCA_FLOWER_KEY_PORT_DST_MAX, 5010u16.to_be_bytes().to_vec()),
        ]
    );
}

#[test]
fn tcp_flags_icmp_and_fragment_flags_are_network_order() {
    let m = flower(
        Protocol::Ip,
        FlowerKeys {
            ip_proto: Some(IPPROTO_TCP),
            tcp_flags: Some((0x10, 0x14)),
            flags: Some((FLAG_IS_FRAGMENT, FLAG_IS_FRAGMENT | FLAG_FRAG_IS_FIRST)),
            ..FlowerKeys::default()
        },
    );
    assert_eq!(
        keys(&m)[2..],
        [
            (TCA_FLOWER_KEY_TCP_FLAGS, vec![0, 0x10]),
            (TCA_FLOWER_KEY_TCP_FLAGS_MASK, vec![0, 0x14]),
            (TCA_FLOWER_KEY_FLAGS, vec![0, 0, 0, 1]),
            (TCA_FLOWER_KEY_FLAGS_MASK, vec![0, 0, 0, 3]),
        ]
    );
    let icmp = |p| FlowerKeys {
        ip_proto: Some(if p == Protocol::Ip { 1 } else { 58 }),
        icmp_type: Some(8),
        icmp_code: Some(0),
        ..FlowerKeys::default()
    };
    assert_eq!(
        keys(&flower(Protocol::Ip, icmp(Protocol::Ip)))[2..],
        [
            (TCA_FLOWER_KEY_ICMPV4_TYPE, vec![8]),
            (TCA_FLOWER_KEY_ICMPV4_CODE, vec![0]),
        ]
    );
    assert_eq!(
        keys(&flower(Protocol::Ipv6, icmp(Protocol::Ipv6)))[2..],
        [
            (TCA_FLOWER_KEY_ICMPV6_TYPE, vec![8]),
            (TCA_FLOWER_KEY_ICMPV6_CODE, vec![0]),
        ]
    );
}

#[test]
fn a_chain_is_sent_only_when_not_zero_and_replace_adds_its_flag() {
    let mut f = filter(
        Protocol::All,
        Kind::Flower(FlowerKeys::default()),
        vec![Action::new(ActionKind::Gact(Verdict::GotoChain(1000)))],
    );
    let m = add(f.clone());
    assert!(attrs(&m[36..]).iter().all(|(k, _)| *k != TCA_CHAIN));
    assert_eq!(u16_at(&m, 6), NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE);
    f.chain = 1001;
    f.replace = true;
    let m = add(f);
    assert_eq!(attrs(&m[36..])[1], (TCA_CHAIN, &1001u32.to_ne_bytes()[..]));
    assert_eq!(
        u16_at(&m, 6),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
    );
    let del = Request::DelFilter {
        ifindex: 1,
        hook: Hook::Ingress,
        chain: 1000,
        prio: 3,
        protocol: Protocol::Ip,
        handle: 0,
    };
    let m = encode(&del, 1).unwrap();
    assert_eq!(attrs(&m[36..]), [(TCA_CHAIN, &1000u32.to_ne_bytes()[..])]);
}

#[test]
fn goto_chain_encodes_the_opcode_above_bit_28() {
    let m = flower(Protocol::All, FlowerKeys::default());
    assert_eq!(verdict_of(&m), TC_ACT_OK);
    let m = add(filter(
        Protocol::All,
        Kind::Flower(FlowerKeys::default()),
        vec![Action::new(ActionKind::Gact(Verdict::GotoChain(1000)))],
    ));
    assert_eq!(verdict_of(&m), 0x2000_03E8);
}

#[test]
fn every_action_is_numbered_and_carries_its_cookie() {
    let acts = vec![
        Action {
            kind: ActionKind::Gact(Verdict::Pipe),
            cookie: vec![1, 2, 3, 4],
        },
        Action {
            kind: ActionKind::Gact(Verdict::Shot),
            cookie: vec![0xAB; 16],
        },
    ];
    let m = add(filter(
        Protocol::Ip,
        Kind::Flower(FlowerKeys::default()),
        acts,
    ));
    let top = attrs(&m[36..]);
    let opts = attrs(top[1].1);
    let table = attrs(opts[1].1);
    assert_eq!(table.iter().map(|(k, _)| *k).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(action_attrs(&m, 0)[2], (TCA_ACT_COOKIE, vec![1, 2, 3, 4]));
    assert_eq!(action_attrs(&m, 1)[2], (TCA_ACT_COOKIE, vec![0xAB; 16]));
}

#[test]
fn an_actionless_filter_sends_no_action_table() {
    let m = add(filter(Protocol::All, Kind::Fw { mask: 1 }, vec![]));
    let opts = attrs(attrs(&m[36..])[1].1);
    assert_eq!(opts, [(TCA_FW_MASK, &1u32.to_ne_bytes()[..])]);
}

#[test]
fn flush_is_a_delchain_naming_the_chain() {
    let m = encode(
        &Request::FlushChain {
            ifindex: 6,
            hook: Hook::Egress,
            chain: 1000,
        },
        2,
    )
    .unwrap();
    assert_eq!(u16_at(&m, 4), RTM_DELCHAIN);
    assert_eq!(u16_at(&m, 6), NLM_F_REQUEST | NLM_F_ACK);
    assert_eq!(u32_at(&m, 20), 6);
    assert_eq!(u32_at(&m, 28), HOOK_EGRESS);
    assert_eq!(u32_at(&m, 32), 0);
    assert_eq!(attrs(&m[36..]), [(TCA_CHAIN, &1000u32.to_ne_bytes()[..])]);
}

#[test]
fn a_dump_request_names_the_hook_and_chain_without_an_ack() {
    let m = dump_request(8, Hook::Ingress, 0, 4);
    assert_eq!(u32_at(&m, 0) as usize, m.len());
    assert_eq!(u16_at(&m, 4), RTM_GETTFILTER);
    assert_eq!(u16_at(&m, 6), NLM_F_REQUEST | NLM_F_DUMP);
    assert_eq!(u32_at(&m, 20), 8);
    assert_eq!(u32_at(&m, 28), HOOK_INGRESS);
    assert_eq!(attrs(&m[36..]), [(TCA_CHAIN, &0u32.to_ne_bytes()[..])]);
}

#[test]
fn what_the_kernel_would_reject_is_refused_first() {
    let bad = |keys: FlowerKeys, acts: Vec<Action>| {
        let f = filter(Protocol::Ip, Kind::Flower(keys), acts);
        encode(&Request::AddFilter(f), 1).unwrap_err().kind()
    };
    let gact = |v| vec![Action::new(ActionKind::Gact(v))];
    let none = FlowerKeys::default;
    assert_eq!(
        bad(none(), gact(Verdict::GotoChain(1 << 28))),
        io::ErrorKind::InvalidInput
    );
    let long = vec![Action {
        kind: ActionKind::Gact(Verdict::Ok),
        cookie: vec![0; 17],
    }];
    assert_eq!(bad(none(), long), io::ErrorKind::InvalidInput);
    let skb = vec![Action::new(ActionKind::Skbedit {
        mark: 1,
        mask: 1,
        verdict: Verdict::GotoChain(u32::MAX),
    })];
    assert_eq!(bad(none(), skb), io::ErrorKind::InvalidInput);
    for keys in [
        FlowerKeys {
            ip_proto: Some(IPPROTO_TCP),
            src_port: Some((10, 9)),
            ..none()
        },
        FlowerKeys {
            ip_proto: Some(1),
            dst_port: Some((10, 10)),
            ..none()
        },
        FlowerKeys {
            src_ip: Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 33)),
            ..none()
        },
        FlowerKeys {
            dst_ip: Some((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 129)),
            ..none()
        },
    ] {
        assert_eq!(bad(keys, gact(Verdict::Ok)), io::ErrorKind::InvalidInput);
    }
}

#[test]
fn sample_pipes_to_its_psample_group_with_the_cookie() {
    let sample = Action {
        kind: ActionKind::Sample {
            rate: 1,
            trunc: 128,
            group: 0x4e_4f53,
        },
        cookie: 7u32.to_be_bytes().to_vec(),
    };
    let m = add(filter(
        Protocol::Ip,
        Kind::Flower(FlowerKeys::default()),
        vec![sample, Action::new(ActionKind::Gact(Verdict::Shot))],
    ));
    let act = action_attrs(&m, 0);
    assert_eq!(act[0], (TCA_ACT_KIND, b"sample\0".to_vec()));
    let opts: Vec<_> = attrs(&act[1].1)
        .into_iter()
        .map(|(k, v)| (k, v.to_vec()))
        .collect();
    assert_eq!(opts[0].0, TCA_SAMPLE_PARMS);
    assert_eq!(
        i32::from_ne_bytes(opts[0].1[8..12].try_into().unwrap()),
        TC_ACT_PIPE
    );
    assert_eq!(opts[1], (TCA_SAMPLE_RATE, 1u32.to_ne_bytes().to_vec()));
    assert_eq!(
        opts[2],
        (TCA_SAMPLE_TRUNC_SIZE, 128u32.to_ne_bytes().to_vec())
    );
    assert_eq!(
        opts[3],
        (
            TCA_SAMPLE_PSAMPLE_GROUP,
            0x4e_4f53u32.to_ne_bytes().to_vec()
        )
    );
    assert_eq!(act[2], (TCA_ACT_COOKIE, vec![0, 0, 0, 7]));
    assert_eq!(action_attrs(&m, 1)[0].1, b"gact\0".to_vec());
}

fn one(protocol: Protocol, keys: FlowerKeys, kind: ActionKind) -> Vec<u8> {
    add(filter(
        protocol,
        Kind::Flower(keys),
        vec![Action::new(kind)],
    ))
}

fn refused(protocol: Protocol, keys: FlowerKeys, kind: ActionKind) -> io::ErrorKind {
    let f = filter(protocol, Kind::Flower(keys), vec![Action::new(kind)]);
    encode(&Request::AddFilter(f), 1).unwrap_err().kind()
}

fn nested_attrs(v: &[u8]) -> Vec<(u16, Vec<u8>)> {
    attrs(v).into_iter().map(|(k, v)| (k, v.to_vec())).collect()
}

#[test]
fn unspec_verdict_is_minus_one_in_every_verdict_field() {
    for kind in [
        ActionKind::Gact(Verdict::Unspec),
        ActionKind::Skbedit {
            mark: 1,
            mask: 1,
            verdict: Verdict::Unspec,
        },
    ] {
        let m = one(Protocol::Ip, FlowerKeys::default(), kind);
        let opts = nested_attrs(&action_attrs(&m, 0)[1].1);
        assert_eq!(
            i32::from_ne_bytes(opts[0].1[8..12].try_into().unwrap()),
            -1,
            "{opts:?}"
        );
    }
}

#[test]
fn police_bytes_carry_rate_burst_ticks_and_a_pipe_result() {
    let m = one(
        Protocol::Ip,
        FlowerKeys::default(),
        ActionKind::Police {
            rate: 125_000,
            burst: 10_000,
            unit: RateUnit::Bytes,
        },
    );
    let act = action_attrs(&m, 0);
    assert_eq!(act[0], (TCA_ACT_KIND, b"police\0".to_vec()));
    let opts = nested_attrs(&act[1].1);
    let kinds: Vec<_> = opts.iter().map(|o| o.0).collect();
    assert_eq!(kinds, [TCA_POLICE_TBF, TCA_POLICE_RATE, TCA_POLICE_RESULT]);
    let tbf = &opts[0].1;
    assert_eq!(tbf.len(), 56);
    assert_eq!(u32_at(tbf, 4), TC_ACT_SHOT as u32, "exceed drops");
    // 10 kB at 125 kB/s = 80 ms = 1_250_000 ticks of 64 ns.
    assert_eq!(u32_at(tbf, 12), 1_250_000);
    assert_eq!(tbf[20], 3, "cell_log");
    assert_eq!(u32_at(tbf, 28), 125_000, "rate");
    assert_eq!(opts[1].1.len(), 1024, "rate table");
    assert_eq!(opts[2].1, (TC_ACT_PIPE as u32).to_ne_bytes());
}

#[test]
fn police_above_32_bits_sends_rate64_and_all_ones() {
    let m = one(
        Protocol::Ip,
        FlowerKeys::default(),
        ActionKind::Police {
            rate: 10_000_000_000,
            burst: 1000,
            unit: RateUnit::Bytes,
        },
    );
    let opts = nested_attrs(&action_attrs(&m, 0)[1].1);
    assert_eq!(u32_at(&opts[0].1, 28), u32::MAX);
    let r64 = opts.iter().find(|o| o.0 == TCA_POLICE_RATE64).unwrap();
    assert_eq!(r64.1, 10_000_000_000u64.to_ne_bytes());
}

#[test]
fn police_packets_send_pps_and_the_burst_in_the_tbf_and_pktburst() {
    let m = one(
        Protocol::Ip,
        FlowerKeys::default(),
        ActionKind::Police {
            rate: 100,
            burst: 5,
            unit: RateUnit::Packets,
        },
    );
    let opts = nested_attrs(&action_attrs(&m, 0)[1].1);
    let kinds: Vec<_> = opts.iter().map(|o| o.0).collect();
    assert_eq!(
        kinds,
        [
            TCA_POLICE_TBF,
            TCA_POLICE_PKTRATE64,
            TCA_POLICE_PKTBURST64,
            TCA_POLICE_RESULT
        ]
    );
    // 5 packets at 100 pps = 50 ms = 781_250 ticks.
    assert_eq!(u32_at(&opts[0].1, 12), 781_250);
    assert_eq!(u32_at(&opts[0].1, 28), 0, "no byte rate");
    assert_eq!(opts[1].1, 100u64.to_ne_bytes());
    assert_eq!(opts[2].1, 781_250u64.to_ne_bytes());
}

#[test]
fn pedit_dscp_ipv4_keeps_ecn_and_is_followed_by_a_header_csum() {
    let m = one(
        Protocol::Ip,
        FlowerKeys::default(),
        ActionKind::Pedit(Pedit::Dscp {
            value: 46,
            family: PeditFamily::Ip,
        }),
    );
    let act = action_attrs(&m, 0);
    assert_eq!(act[0], (TCA_ACT_KIND, b"pedit\0".to_vec()));
    let opts = nested_attrs(&act[1].1);
    let sel = &opts[0].1;
    assert_eq!(opts[0].0, TCA_PEDIT_PARMS_EX);
    assert_eq!(sel.len(), 20 + 4 + 24);
    assert_eq!(
        i32::from_ne_bytes(sel[8..12].try_into().unwrap()),
        TC_ACT_PIPE
    );
    assert_eq!(sel[20], 1, "nkeys");
    assert_eq!(hex(&sel[24..28]), "ff03ffff", "mask keeps ECN");
    assert_eq!(hex(&sel[28..32]), "00b80000", "46 << 2 in the TOS byte");
    assert_eq!(u32_at(sel, 32), 0, "offset 0 from the IPv4 header");
    let key_ex = nested_attrs(&opts[1].1);
    let key = nested_attrs(&key_ex[0].1);
    assert_eq!(
        key[0],
        (TCA_PEDIT_KEY_EX_HTYPE, 2u16.to_ne_bytes().to_vec())
    );
    assert_eq!(key[1], (TCA_PEDIT_KEY_EX_CMD, 0u16.to_ne_bytes().to_vec()));
    // The second table entry is the checksum action.
    let csum = action_attrs(&m, 1);
    assert_eq!(csum[0], (TCA_ACT_KIND, b"csum\0".to_vec()));
    let parms = &nested_attrs(&csum[1].1)[0];
    assert_eq!(parms.0, TCA_CSUM_PARMS);
    assert_eq!(u32_at(&parms.1, 20), TCA_CSUM_UPDATE_FLAG_IPV4HDR);
}

#[test]
fn pedit_dscp_ipv6_straddles_the_first_word_and_needs_no_csum() {
    let m = one(
        Protocol::Ipv6,
        FlowerKeys::default(),
        ActionKind::Pedit(Pedit::Dscp {
            value: 0b10_1110,
            family: PeditFamily::Ipv6,
        }),
    );
    let sel = &nested_attrs(&action_attrs(&m, 0)[1].1)[0].1;
    // DSCP 101110 = traffic class bits 7..2: 1011 in byte 0, 10 in byte 1.
    assert_eq!(
        hex(&sel[24..28]),
        "f03fffff",
        "keeps version, ECN, flow label"
    );
    assert_eq!(hex(&sel[28..32]), "0b800000");
    let key_ex = nested_attrs(&nested_attrs(&action_attrs(&m, 0)[1].1)[1].1);
    let key = nested_attrs(&key_ex[0].1);
    assert_eq!(key[0].1, 3u16.to_ne_bytes());
    // No second action: the table has one entry.
    let top = attrs(&m[36..]);
    let opts = attrs(top.iter().find(|(k, _)| *k == TCA_OPTIONS).unwrap().1);
    let table = opts.iter().find(|(k, _)| *k == TCA_FLOWER_ACT).unwrap().1;
    assert_eq!(attrs(table).len(), 1);
}

#[test]
fn pedit_csum_shifts_the_following_action_index() {
    let f = filter(
        Protocol::Ip,
        Kind::Flower(FlowerKeys::default()),
        vec![
            Action::new(ActionKind::Pedit(Pedit::Dscp {
                value: 1,
                family: PeditFamily::Ip,
            })),
            Action::new(ActionKind::Gact(Verdict::Shot)),
        ],
    );
    let m = add(f);
    let top = attrs(&m[36..]);
    let opts = attrs(top.iter().find(|(k, _)| *k == TCA_OPTIONS).unwrap().1);
    let table = opts.iter().find(|(k, _)| *k == TCA_FLOWER_ACT).unwrap().1;
    let idx: Vec<_> = attrs(table).iter().map(|(k, _)| *k).collect();
    assert_eq!(idx, [1, 2, 3], "pedit, csum, gact");
}

#[test]
fn ip_tos_key_is_the_dscp_shifted_with_the_ecn_masked_out() {
    let k = keys(&flower(
        Protocol::Ip,
        FlowerKeys {
            ip_tos: Some(46),
            ..FlowerKeys::default()
        },
    ));
    assert!(k.contains(&(TCA_FLOWER_KEY_IP_TOS, vec![0xB8])), "{k:?}");
    assert!(
        k.contains(&(TCA_FLOWER_KEY_IP_TOS_MASK, vec![0xFC])),
        "{k:?}"
    );
}

#[test]
fn police_pedit_and_tos_refusals() {
    let none = FlowerKeys::default;
    let police = |rate, burst| ActionKind::Police {
        rate,
        burst,
        unit: RateUnit::Bytes,
    };
    let dscp = |value| {
        ActionKind::Pedit(Pedit::Dscp {
            value,
            family: PeditFamily::Ip,
        })
    };
    for kind in [police(0, 10), police(10, 0), dscp(64)] {
        assert_eq!(
            refused(Protocol::Ip, none(), kind),
            io::ErrorKind::InvalidInput
        );
    }
    let tos = FlowerKeys {
        ip_tos: Some(64),
        ..none()
    };
    assert_eq!(
        refused(Protocol::Ip, tos, ActionKind::Gact(Verdict::Ok)),
        io::ErrorKind::InvalidInput
    );
    // The edge values are accepted.
    one(Protocol::Ip, none(), police(1, 1));
    one(Protocol::Ip, none(), dscp(63));
}

fn mirred(ifindex: u32) -> ActionKind {
    ActionKind::Mirred { ifindex }
}

fn vlan(v: Option<u16>) -> FlowerKeys {
    FlowerKeys {
        vlan_id: v,
        ..FlowerKeys::default()
    }
}

fn dot1q(keys: FlowerKeys, actions: Vec<Action>) -> Vec<u8> {
    add(filter(Protocol::Dot1Q, Kind::Flower(keys), actions))
}

#[test]
fn dot1q_vlan_mirred_golden_bytes() {
    let m = dot1q(vlan(Some(10)), vec![Action::new(mirred(7))]);
    // tcm_info: prio 1, htons(0x8100).
    assert_eq!(
        u32_at(&m, 32),
        1 << 16 | u32::from(u16::from_ne_bytes([0x81, 0x00]))
    );
    let k = keys(&m);
    assert_eq!(k[0], (TCA_FLOWER_KEY_ETH_TYPE, vec![0x81, 0x00]));
    assert_eq!(k[1], (TCA_FLOWER_KEY_VLAN_ID, 10u16.to_ne_bytes().to_vec()));
    let act = action_attrs(&m, 0);
    assert_eq!(act[0].1, b"mirred\0");
    let opts = attrs(&act[1].1);
    assert_eq!(opts[0].0, TCA_MIRRED_PARMS);
    // tc_gen (action = TC_ACT_STOLEN), eaction = egress redirect, ifindex.
    let want = format!(
        "{}{}{}",
        "0000000000000000",
        hex(&TC_ACT_STOLEN.to_ne_bytes()) + "0000000000000000",
        hex(&1i32.to_ne_bytes()) + &hex(&7u32.to_ne_bytes())
    );
    assert_eq!(hex(opts[0].1), want);
    assert_eq!(opts[0].1.len(), 28);
}

#[test]
fn dot1q_without_vlan_still_sends_the_ethertype() {
    let m = dot1q(vlan(None), vec![Action::new(mirred(7))]);
    assert_eq!(keys(&m), [(TCA_FLOWER_KEY_ETH_TYPE, vec![0x81, 0x00])]);
}

#[test]
fn mirred_in_a_table_keeps_index_and_cookie() {
    let acts = vec![
        Action::new(ActionKind::Gact(Verdict::Pipe)),
        Action {
            kind: mirred(9),
            cookie: vec![1, 2],
        },
    ];
    let m = dot1q(vlan(Some(1)), acts);
    let top = attrs(&m[36..]);
    let opts = attrs(top.iter().find(|(k, _)| *k == TCA_OPTIONS).unwrap().1);
    let table = opts.iter().find(|(k, _)| *k == TCA_FLOWER_ACT).unwrap().1;
    let idx: Vec<u16> = attrs(table).iter().map(|a| a.0).collect();
    assert_eq!(idx, [1, 2]);
    let second = action_attrs(&m, 1);
    assert_eq!(second[0].1, b"mirred\0");
    assert_eq!(second.last().unwrap(), &(TCA_ACT_COOKIE, vec![1, 2]));
}

#[test]
fn vlan_and_mirred_refusals_and_edges() {
    let g = || ActionKind::Gact(Verdict::Ok);
    let bad = io::ErrorKind::InvalidInput;
    for v in [4095, 65535] {
        assert_eq!(refused(Protocol::Dot1Q, vlan(Some(v)), g()), bad);
    }
    for p in [Protocol::All, Protocol::Ip] {
        assert_eq!(refused(p, vlan(Some(10)), g()), bad);
    }
    assert_eq!(refused(Protocol::Dot1Q, vlan(None), mirred(0)), bad);
    let l4 = FlowerKeys {
        ip_proto: Some(6),
        ..vlan(Some(10))
    };
    assert_eq!(refused(Protocol::Dot1Q, l4, g()), bad);
    one(Protocol::Dot1Q, vlan(Some(0)), g());
    one(Protocol::Dot1Q, vlan(Some(4094)), mirred(1));
}
