//! One user rule to its flower filters.

use nos_proto::schema::{AclProtocol, AclRule};
use nos_tc::{FlowerKeys, Protocol, FLAG_FRAG_IS_FIRST, FLAG_IS_FRAGMENT};

use super::{Filter, IMPLICIT_ND_COOKIE};
use nos_proto::schema::AclAction;

/// TCP header flag bits (RFC 9293 §3.1).
const TCP_RST: u16 = 0x04;
const TCP_ACK: u16 = 0x10;

/// Flower `ip_flags` of a non-first fragment: fragment set, first-fragment clear.
pub(crate) const LATER_FRAGMENT: (u32, u32) =
    (FLAG_IS_FRAGMENT, FLAG_IS_FRAGMENT | FLAG_FRAG_IS_FIRST);

/// The families a rule applies to: its prefixes' (validated to agree), else
/// its ICMP flavour's, else both.
fn families(r: &AclRule) -> Vec<Protocol> {
    let family = |v4: bool| if v4 { Protocol::Ip } else { Protocol::Ipv6 };
    match (r.source.or(r.destination), r.protocol) {
        (Some(net), _) => vec![family(net.addr().is_ipv4())],
        (None, Some(AclProtocol::Icmp)) => vec![Protocol::Ip],
        (None, Some(AclProtocol::Icmpv6)) => vec![Protocol::Ipv6],
        (None, _) => vec![Protocol::Ip, Protocol::Ipv6],
    }
}

/// `r`'s filters, every one carrying `index` as its cookie. `established` is
/// two filters (ACK set, RST set): flower matches one flag mask per filter.
///
/// flower never parses the L4 header of a fragment, first ones included
/// (measured, `tests/kernel.rs`), so an L4 key (ports, TCP flags, ICMP
/// type/code) never matches any fragment. A `permit` thus falls through (fail
/// closed); a `deny` would let every fragment pass, so it gets one twin filter
/// per family with its L3 keys that denies ANY fragment (#1539, RFC 1858 style).
/// The twin has the rule's cookie: `show acl` counts it into the user rule.
///
/// ponytail: IPv6 `ip_proto` of a fragment is not verified (e2e covers IPv4).
pub(super) fn filters(r: &AclRule, index: u32) -> Vec<Filter> {
    let base = FlowerKeys {
        ip_proto: r.protocol.map(AclProtocol::number),
        src_ip: r.source.map(|n| (n.network(), n.prefix_len())),
        dst_ip: r.destination.map(|n| (n.network(), n.prefix_len())),
        src_port: r.source_port.map(|p| (p.start, p.end)),
        dst_port: r.destination_port.map(|p| (p.start, p.end)),
        icmp_type: r.icmp_type,
        icmp_code: r.icmp_code,
        flags: r.fragments.then_some(LATER_FRAGMENT),
        ..Default::default()
    };
    let flags: Vec<Option<(u16, u16)>> = if r.established {
        vec![Some((TCP_ACK, TCP_ACK)), Some((TCP_RST, TCP_RST))]
    } else {
        vec![None]
    };
    let l4 = r.source_port.is_some()
        || r.destination_port.is_some()
        || r.established
        || r.icmp_type.is_some()
        || r.icmp_code.is_some();
    let twin = l4 && r.action == AclAction::Deny;
    let mut out: Vec<Filter> = families(r)
        .into_iter()
        .flat_map(|protocol| flags.iter().map(move |&tcp_flags| (protocol, tcp_flags)))
        .map(|(protocol, tcp_flags)| Filter {
            protocol,
            keys: FlowerKeys {
                tcp_flags,
                ..base.clone()
            },
            action: r.action,
            rule: index,
            log: r.log,
        })
        .collect();
    if twin {
        let any_fragment = (FLAG_IS_FRAGMENT, FLAG_IS_FRAGMENT);
        out.extend(families(r).into_iter().map(|protocol| Filter {
            protocol,
            keys: FlowerKeys {
                src_port: None,
                dst_port: None,
                icmp_type: None,
                icmp_code: None,
                flags: Some(any_fragment),
                ..base.clone()
            },
            action: r.action,
            rule: index,
            log: r.log,
        }));
    }
    out
}

/// The implicit IPv6 Neighbor Discovery permit (RFC 4861: RS, RA, NS, NA)
/// after a deny default: one filter per type, flower matches a single one.
///
/// ponytail: the hop limit of 255 is not matchable by flower, so a forwarded
/// ND-typed packet passes too.
pub(super) fn implicit_nd() -> Vec<Filter> {
    (133u8..=136)
        .map(|t| Filter {
            protocol: Protocol::Ipv6,
            keys: FlowerKeys {
                ip_proto: Some(AclProtocol::Icmpv6.number()),
                icmp_type: Some(t),
                ..Default::default()
            },
            action: AclAction::Permit,
            rule: IMPLICIT_ND_COOKIE,
            log: false,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use nos_proto::schema::{AclAction, PortRange};

    use super::*;

    fn rule(f: impl FnOnce(&mut AclRule)) -> AclRule {
        let mut r = AclRule {
            name: "r".into(),
            action: AclAction::Permit,
            ..Default::default()
        };
        f(&mut r);
        r
    }

    fn protocols(r: &AclRule) -> Vec<Protocol> {
        filters(r, 0).iter().map(|f| f.protocol).collect()
    }

    #[test]
    fn family_comes_from_prefixes_then_icmp_flavour() {
        assert_eq!(protocols(&rule(|_| {})), [Protocol::Ip, Protocol::Ipv6]);
        let v4 = rule(|r| r.destination = Some("192.0.2.0/24".parse().unwrap()));
        assert_eq!(protocols(&v4), [Protocol::Ip]);
        let v6 = rule(|r| r.source = Some("2001:db8::/32".parse().unwrap()));
        assert_eq!(protocols(&v6), [Protocol::Ipv6]);
        let icmp = rule(|r| r.protocol = Some(AclProtocol::Icmp));
        assert_eq!(protocols(&icmp), [Protocol::Ip]);
        let icmpv6 = rule(|r| r.protocol = Some(AclProtocol::Icmpv6));
        assert_eq!(protocols(&icmpv6), [Protocol::Ipv6]);
        let ospf = rule(|r| r.protocol = Some(AclProtocol::Number(89)));
        assert_eq!(protocols(&ospf), [Protocol::Ip, Protocol::Ipv6]);
    }

    #[test]
    fn every_match_field_becomes_its_key() {
        let r = rule(|r| {
            r.action = AclAction::Deny;
            r.protocol = Some(AclProtocol::Tcp);
            r.source = Some("10.1.2.3/8".parse().unwrap());
            r.destination = Some("192.0.2.1/32".parse().unwrap());
            r.source_port = Some(PortRange {
                start: 1024,
                end: 65535,
            });
            r.destination_port = Some(PortRange {
                start: 179,
                end: 179,
            });
        });
        let f = filters(&r, 7);
        // The filter, plus the any-fragment twin of an L4 deny.
        assert_eq!(f.len(), 2);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(
            f[0].keys,
            FlowerKeys {
                ip_proto: Some(6),
                src_ip: Some((ip("10.0.0.0"), 8)),
                dst_ip: Some((ip("192.0.2.1"), 32)),
                src_port: Some((1024, 65535)),
                dst_port: Some((179, 179)),
                ..Default::default()
            }
        );
        assert_eq!((f[0].action, f[0].rule), (AclAction::Deny, 7));
    }

    #[test]
    fn icmp_type_and_code() {
        let r = rule(|r| {
            r.protocol = Some(AclProtocol::Icmpv6);
            r.icmp_type = Some(135);
            r.icmp_code = Some(0);
        });
        let f = filters(&r, 0);
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].keys.ip_proto, f[0].keys.icmp_type, f[0].keys.icmp_code),
            (Some(58), Some(135), Some(0))
        );
    }

    #[test]
    fn fragments_adds_the_later_fragment_flags_per_family() {
        let r = rule(|r| r.fragments = true);
        let f = filters(&r, 0);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|f| f.keys.flags == Some((1, 3))));
        assert!(filters(&rule(|_| {}), 0)
            .iter()
            .all(|f| f.keys.flags.is_none()));
    }

    #[test]
    fn an_l4_deny_gets_an_any_fragment_twin_per_family() {
        let l4 = |action| {
            rule(|r| {
                r.action = action;
                r.protocol = Some(AclProtocol::Tcp);
                r.source = Some("10.0.0.0/8".parse().unwrap());
                r.destination_port = Some(PortRange { start: 22, end: 22 });
            })
        };
        let f = filters(&l4(AclAction::Deny), 4);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].keys.dst_port, Some((22, 22)));
        assert_eq!(f[0].keys.flags, None);
        let t = &f[1];
        assert_eq!(
            (t.keys.flags, t.keys.dst_port, t.rule),
            (Some((1, 1)), None, 4)
        );
        assert_eq!((t.keys.ip_proto, t.protocol), (Some(6), Protocol::Ip));
        assert!(t.keys.src_ip.is_some());
        // A permit, or a deny without an L4 key, needs none.
        assert_eq!(filters(&l4(AclAction::Permit), 0).len(), 1);
        let l3 = rule(|r| r.action = AclAction::Deny);
        assert!(filters(&l3, 0).iter().all(|f| f.keys.flags.is_none()));
    }

    #[test]
    fn established_is_an_ack_and_a_rst_filter_per_family() {
        let r = rule(|r| {
            r.protocol = Some(AclProtocol::Tcp);
            r.established = true;
        });
        let f = filters(&r, 3);
        let got: Vec<_> = f.iter().map(|f| (f.protocol, f.keys.tcp_flags)).collect();
        assert_eq!(
            got,
            [
                (Protocol::Ip, Some((TCP_ACK, TCP_ACK))),
                (Protocol::Ip, Some((TCP_RST, TCP_RST))),
                (Protocol::Ipv6, Some((TCP_ACK, TCP_ACK))),
                (Protocol::Ipv6, Some((TCP_RST, TCP_RST))),
            ]
        );
        assert!(f.iter().all(|f| f.rule == 3 && f.keys.ip_proto == Some(6)));
    }
}
