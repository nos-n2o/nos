//! The optimiser keeps first-match semantics (#542): for random ACLs and
//! packets, the verdict of the compiled levels (flower semantics: the first
//! level with a matching filter wins, then the per-family default) equals a
//! naive first-match over the user rules. Neither oracle shares code with
//! `compile/keys.rs`.

use std::net::IpAddr;

use ipnet::IpNet;
use nos_acl::compile::{compile, Compiled};
use nos_proto::schema::{Acl, AclAction, AclEthertype, AclProtocol, AclRule, MacMatch, PortRange};
use nos_tc::{FlowerKeys, Protocol};
use proptest::prelude::*;

const ACK: u16 = 0x10;
const RST: u16 = 0x04;

#[derive(Debug, Clone)]
struct Packet {
    v6: bool,
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    flags: u16,
    icmp: (u8, u8),
    non_first_fragment: bool,
    /// Offset 0 with more fragments: carries the L4 header, which flower
    /// still never parses.
    first_fragment: bool,
    dscp: u8,
    ttl: u8,
    /// An IP packet (EtherType 0x0800/0x86dd by `v6`); else `ether` is it.
    is_ip: bool,
    ether: u16,
    smac: [u8; 6],
    dmac: [u8; 6],
}

const MACS: [&str; 5] = [
    "aa:bb:cc:00:00:01",
    "aa:bb:cc:00:00:02",
    "aa:bb:dd:00:00:01",
    "ff:ff:ff:ff:ff:ff",
    "02:00:00:00:00:09",
];
const MAC_RULES: [&str; 7] = [
    "aa:bb:cc:00:00:01",
    "aa:bb:cc:00:00:02",
    "aa:bb:cc:00:00:00/24",
    "aa:bb:cc:00:00:00/40",
    "aa:bb:00:00:00:00/16",
    "ff:ff:ff:ff:ff:ff",
    "00:00:00:00:00:00/1",
];
const ETHERS: [u16; 3] = [0x0806, 0x88cc, 0x88b5];

fn mac_bytes(s: &str) -> [u8; 6] {
    s.parse::<MacMatch>().unwrap().bytes()
}

fn mac_hit(m: Option<MacMatch>, v: [u8; 6]) -> bool {
    m.is_none_or(|m| {
        v.iter()
            .zip(m.bytes().iter().zip(m.mask()))
            .all(|(v, (a, k))| v & k == *a)
    })
}

const DSCPS: [u8; 3] = [0, 46, 48];
const TTLS: [u8; 3] = [1, 64, 255];

/// Oracle A: the schema's meaning of a rule, written from its doc comments.
fn rule_matches(r: &AclRule, p: &Packet) -> bool {
    let ip_keys = r.protocol.is_some()
        || r.source.is_some()
        || r.destination.is_some()
        || r.source_port.is_some()
        || r.destination_port.is_some()
        || r.established
        || r.icmp_type.is_some()
        || r.icmp_code.is_some()
        || r.fragments
        || r.dscp.is_some()
        || r.ttl.is_some();
    let l2 = mac_hit(r.source_mac, p.smac)
        && mac_hit(r.destination_mac, p.dmac)
        && match r.ethertype {
            None => true,
            Some(AclEthertype::Ipv4) => p.is_ip && !p.v6,
            Some(AclEthertype::Ipv6) => p.is_ip && p.v6,
            Some(e) => !p.is_ip && p.ether == e.value(),
        };
    // A rule with no L2/L3 key at all is an IP "any" rule (never ARP).
    let any = r.source_mac.is_none() && r.destination_mac.is_none() && r.ethertype.is_none();
    if !l2 || (!p.is_ip && (ip_keys || any)) {
        return false;
    }
    let family6 = match (r.source.or(r.destination), r.protocol) {
        (Some(n), _) => Some(n.addr().is_ipv6()),
        (None, Some(AclProtocol::Icmp)) => Some(false),
        (None, Some(AclProtocol::Icmpv6)) => Some(true),
        (None, _) => None,
    };
    let l4 = !p.non_first_fragment && !p.first_fragment;
    let tcp_udp = matches!(p.proto, 6 | 17);
    let l3 = family6.is_none_or(|f| f == p.v6)
        && r.protocol.is_none_or(|x| x.number() == p.proto)
        && r.source.is_none_or(|n| n.contains(&p.src))
        && r.destination.is_none_or(|n| n.contains(&p.dst))
        && r.dscp.is_none_or(|d| d == p.dscp)
        && r.ttl.is_none_or(|t| t == p.ttl);
    // An L4-keyed deny also drops every fragment of its L3 match (#1539).
    let twin = r.action == AclAction::Deny
        && (r.source_port.is_some()
            || r.destination_port.is_some()
            || r.established
            || r.icmp_type.is_some()
            || r.icmp_code.is_some());
    (twin && !l4 && l3) || (l3 && l4_conds(r, p, l4, tcp_udp))
}

fn l4_conds(r: &AclRule, p: &Packet, l4: bool, tcp_udp: bool) -> bool {
    r.source_port
        .is_none_or(|x| l4 && tcp_udp && (x.start..=x.end).contains(&p.sport))
        && r.destination_port
            .is_none_or(|x| l4 && tcp_udp && (x.start..=x.end).contains(&p.dport))
        && (!r.fragments || p.non_first_fragment)
        && (!r.established || (l4 && p.proto == 6 && p.flags & (ACK | RST) != 0))
        && r.icmp_type
            .is_none_or(|t| l4 && matches!(p.proto, 1 | 58) && p.icmp.0 == t)
        && r.icmp_code
            .is_none_or(|c| l4 && matches!(p.proto, 1 | 58) && p.icmp.1 == c)
}

fn first_match(acl: &Acl, p: &Packet) -> AclAction {
    // A deny default permits ICMPv6 133..=136 after the rules (#1530).
    let nd = p.is_ip
        && p.v6
        && p.proto == 58
        && !p.non_first_fragment
        && !p.first_fragment
        && (133..=136).contains(&p.icmp.0);
    acl.rules.iter().find(|r| rule_matches(r, p)).map_or(
        if !p.is_ip || (acl.default_action == AclAction::Deny && nd) {
            // The default applies to IP only (D2-A): other frames pass.
            AclAction::Permit
        } else {
            acl.default_action
        },
        |r| r.action,
    )
}

/// What the kernel's flower does with one filter.
fn flower_matches(protocol: Protocol, k: &FlowerKeys, p: &Packet) -> bool {
    let net = |(a, l): (IpAddr, u8), x: IpAddr| IpNet::new(a, l).unwrap().contains(&x);
    let l4 = !p.non_first_fragment && !p.first_fragment;
    // ip_flags bits: 1 = is fragment, 2 = first fragment.
    let bits =
        u32::from(p.non_first_fragment || p.first_fragment) | (u32::from(p.first_fragment) << 1);
    let ether = if !p.is_ip {
        p.ether
    } else if p.v6 {
        0x86dd
    } else {
        0x0800
    };
    let mac = |m: Option<([u8; 6], Option<[u8; 6]>)>, v: [u8; 6]| {
        m.is_none_or(|(a, k)| {
            let k = k.unwrap_or([0xff; 6]);
            (0..6).all(|i| v[i] & k[i] == a[i] & k[i])
        })
    };
    let family = match protocol {
        Protocol::Ip => ether == 0x0800,
        Protocol::Ipv6 => ether == 0x86dd,
        _ => true,
    };
    family
        && k.eth_type.is_none_or(|t| t == ether)
        && mac(k.eth_src, p.smac)
        && mac(k.eth_dst, p.dmac)
        && k.ip_proto.is_none_or(|x| x == p.proto)
        && k.src_ip.is_none_or(|n| net(n, p.src))
        && k.dst_ip.is_none_or(|n| net(n, p.dst))
        && k.src_port
            .is_none_or(|(lo, hi)| l4 && matches!(p.proto, 6 | 17) && (lo..=hi).contains(&p.sport))
        && k.dst_port
            .is_none_or(|(lo, hi)| l4 && matches!(p.proto, 6 | 17) && (lo..=hi).contains(&p.dport))
        // A non-first fragment has is_fragment=1, first_frag=0; any other packet 0, 0.
        && k.flags
            .is_none_or(|(v, m)| (bits ^ v) & m == 0)
        && k.ip_tos.is_none_or(|d| d == p.dscp)
        && k.ip_ttl.is_none_or(|t| t == p.ttl)
        && k.tcp_flags
            .is_none_or(|(v, m)| l4 && p.proto == 6 && p.flags & m == v & m)
        && k.icmp_type
            .is_none_or(|t| l4 && matches!(p.proto, 1 | 58) && p.icmp.0 == t)
        && k.icmp_code
            .is_none_or(|c| l4 && matches!(p.proto, 1 | 58) && p.icmp.1 == c)
}

/// Oracle B: the compiled levels; also checks a level never mixes actions
/// among the filters that match (so its order is irrelevant).
fn compiled_verdict(c: &Compiled, p: &Packet) -> AclAction {
    for level in &c.levels {
        let hits: Vec<AclAction> = level
            .filters
            .iter()
            .filter(|f| flower_matches(f.protocol, &f.keys, p))
            .map(|f| f.action)
            .collect();
        if let Some(&first) = hits.first() {
            assert!(
                hits.iter().all(|&a| a == first),
                "level mixes actions for {p:?}"
            );
            return first;
        }
    }
    // The default filters are IP only.
    if p.is_ip {
        c.default_action
    } else {
        AclAction::Permit
    }
}

const V4_NETS: [&str; 6] = [
    "10.0.0.0/24",
    "10.0.0.0/25",
    "10.0.0.128/25",
    "10.0.0.1/32",
    "10.0.0.130/32",
    "10.0.0.0/8",
];
const V6_NETS: [&str; 5] = [
    "2001:db8::/32",
    "2001:db8::/64",
    "2001:db8:0:1::/64",
    "2001:db8::1/128",
    "::/0",
];
const V4_ADDRS: [&str; 5] = [
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.130",
    "10.0.0.200",
    "10.9.9.9",
];
const V6_ADDRS: [&str; 4] = [
    "2001:db8::1",
    "2001:db8::2",
    "2001:db8:0:1::5",
    "2001:db9::1",
];
const RANGES: [(u16, u16); 6] = [
    (0, 65535),
    (80, 80),
    (1, 1023),
    (1024, 65535),
    (80, 443),
    (443, 443),
];
const PORTS: [u16; 6] = [0, 80, 443, 1000, 1024, 40000];

fn pick<T: Copy + std::fmt::Debug>(pool: &'static [T]) -> impl Strategy<Value = T> {
    (0..pool.len()).prop_map(move |i| pool[i])
}

fn rule() -> impl Strategy<Value = AclRule> {
    let proto = prop::option::of(0usize..5);
    let nets = (
        any::<bool>(),
        prop::option::of(0usize..6),
        prop::option::of(0usize..6),
    );
    let ports = (
        prop::option::of(pick(&RANGES)),
        prop::option::of(pick(&RANGES)),
    );
    let extra = (
        any::<bool>(),
        prop::option::of(0u8..5),
        prop::option::of(0u8..2),
    );
    (
        proto,
        nets,
        ports,
        extra,
        (any::<bool>(), any::<bool>()),
        any::<bool>(),
        (prop::option::of(0usize..3), prop::option::of(0usize..3)),
        (
            prop::option::of(0usize..MAC_RULES.len()),
            prop::option::of(0usize..MAC_RULES.len()),
            prop::option::of(0usize..5),
        ),
    )
        .prop_map(
            |(
                proto,
                (v6, s, d),
                (sp, dp),
                (est, ity, ico),
                (deny, log),
                frag,
                (dscp, ttl),
                (smac, dmac, ether),
            )| {
                let source_mac = smac.map(|i| MAC_RULES[i].parse::<MacMatch>().unwrap());
                let destination_mac = dmac.map(|i| MAC_RULES[i].parse::<MacMatch>().unwrap());
                let action = if deny {
                    AclAction::Deny
                } else {
                    AclAction::Permit
                };
                // 3 and 4 are the non-IP EtherTypes: no IP key (the validator).
                if let Some(e @ 2..=4) = ether {
                    return AclRule {
                        action,
                        log,
                        source_mac,
                        destination_mac,
                        ethertype: Some(match e {
                            2 => AclEthertype::Arp,
                            3 => AclEthertype::Lldp,
                            _ => AclEthertype::Number(0x88b5),
                        }),
                        ..Default::default()
                    };
                }
                let protocol = proto.map(|i| match i {
                    0 => AclProtocol::Tcp,
                    1 => AclProtocol::Udp,
                    2 => AclProtocol::Icmp,
                    3 => AclProtocol::Icmpv6,
                    _ => AclProtocol::Number(89),
                });
                // The commit's rules: prefixes agree with each other and with
                // the ICMP flavour; L4 fields need the matching protocol.
                let v6 = match protocol {
                    Some(AclProtocol::Icmp) => false,
                    Some(AclProtocol::Icmpv6) => true,
                    _ => v6,
                };
                let net = |i: Option<usize>| {
                    i.map(|i| {
                        let pool: &[&str] = if v6 { &V6_NETS } else { &V4_NETS };
                        pool[i % pool.len()].parse::<IpNet>().unwrap()
                    })
                };
                let tcp_udp = matches!(protocol, Some(AclProtocol::Tcp | AclProtocol::Udp));
                let icmp = matches!(protocol, Some(AclProtocol::Icmp | AclProtocol::Icmpv6));
                let range = |r: Option<(u16, u16)>| {
                    r.filter(|_| tcp_udp)
                        .map(|(start, end)| PortRange { start, end })
                };
                let icmp_type = ity
                    .filter(|_| icmp)
                    .map(|t| [8, 0, 135, 136, 134][usize::from(t)]);
                AclRule {
                    action: if deny {
                        AclAction::Deny
                    } else {
                        AclAction::Permit
                    },
                    protocol,
                    source: net(s),
                    destination: net(d),
                    source_port: range(sp),
                    destination_port: range(dp),
                    established: est && protocol == Some(AclProtocol::Tcp),
                    icmp_code: ico.filter(|_| icmp_type.is_some()),
                    icmp_type,
                    log,
                    // The validator refuses `fragments` next to an L4 key.
                    fragments: frag && sp.is_none() && dp.is_none() && !est && icmp_type.is_none(),
                    dscp: dscp.map(|i| DSCPS[i]),
                    ttl: ttl.map(|i| TTLS[i]),
                    source_mac,
                    destination_mac,
                    // 0 / 1 ask for ipv4 / ipv6, kept when the family agrees.
                    ethertype: match ether {
                        Some(0) if !v6 => Some(AclEthertype::Ipv4),
                        Some(1) if v6 => Some(AclEthertype::Ipv6),
                        _ => None,
                    },
                    ..Default::default()
                }
            },
        )
}

fn packet() -> impl Strategy<Value = Packet> {
    (
        pick(&[6u8, 17, 1, 58, 89]),
        any::<bool>(),
        (0usize..5, 0usize..5),
        (pick(&PORTS), pick(&PORTS)),
        pick(&[0u16, ACK, RST, 0x02, ACK | 0x08]),
        (pick(&[8u8, 0, 135, 133, 134, 136]), 0u8..2),
        (prop::bool::weighted(0.2), prop::bool::weighted(0.1)),
        (pick(&DSCPS), pick(&TTLS)),
        (prop::bool::weighted(0.8), pick(&ETHERS)),
        (pick(&MACS), pick(&MACS)),
    )
        .prop_map(
            |(
                proto,
                v6,
                (s, d),
                (sport, dport),
                flags,
                icmp,
                (nff, first),
                (dscp, ttl),
                (is_ip, ether),
                (smac, dmac),
            )| {
                let v6 = match proto {
                    1 => false,
                    58 => true,
                    _ => v6,
                };
                let addr = |i: usize| -> IpAddr {
                    if v6 {
                        V6_ADDRS[i % V6_ADDRS.len()].parse().unwrap()
                    } else {
                        V4_ADDRS[i % V4_ADDRS.len()].parse().unwrap()
                    }
                };
                Packet {
                    v6,
                    proto,
                    src: addr(s),
                    dst: addr(d),
                    sport,
                    dport,
                    flags,
                    icmp,
                    non_first_fragment: nff,
                    first_fragment: first && !nff,
                    dscp,
                    ttl,
                    is_ip,
                    ether,
                    smac: mac_bytes(smac),
                    dmac: mac_bytes(dmac),
                }
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn compiled_levels_match_first_match(
        rules in prop::collection::vec(rule(), 0..=12),
        deny_default in any::<bool>(),
        packets in prop::collection::vec(packet(), 40),
    ) {
        let acl = Acl {
            name: "A".into(),
            default_action: if deny_default { AclAction::Deny } else { AclAction::Permit },
            rules: rules
                .into_iter()
                .enumerate()
                .map(|(i, mut r)| { r.name = format!("r{i}"); r })
                .collect(),
        };
        let c = compile(&acl).unwrap();
        prop_assert!(c.levels.len() <= acl.rules.len() + 1);
        prop_assert_eq!(c.rules, acl.rules.len());
        for p in &packets {
            prop_assert_eq!(compiled_verdict(&c, p), first_match(&acl, p), "{:?}", p);
        }
    }
}
