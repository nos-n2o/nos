//! Overlap and containment of two filters' matches (pure). Exact on the
//! fields `rule::filters` sets: family, IP protocol, prefixes, port ranges,
//! TCP flags, fragment flags, ICMP type/code. Anything else a `FlowerKeys`
//! can hold (MAC, tunnel) is never set by a rule and is ignored here. An
//! L4-keyed filter and a `fragments` one never share a packet, yet overlap is
//! reported (over-approximation only costs a level).

use std::net::IpAddr;

use super::Filter;

/// An address prefix as an inclusive `[lo, hi]` range.
fn span((addr, len): (IpAddr, u8)) -> (u128, u128) {
    let (v, bits) = match addr {
        IpAddr::V4(a) => (u128::from(u32::from(a)), 32),
        IpAddr::V6(a) => (u128::from(a), 128),
    };
    let host = if len >= bits {
        0
    } else {
        u128::MAX >> (128 - (bits - len))
    };
    (v & !host, (v & !host) | host)
}

/// The two ranges share a value; an absent side is "anything".
fn meet<T: Ord + Copy>(a: Option<(T, T)>, b: Option<(T, T)>) -> bool {
    a.zip(b).is_none_or(|(a, b)| a.0 <= b.1 && b.0 <= a.1)
}

/// `a` holds every value of `b`: an absent `a` holds anything, an absent `b`
/// only an absent `a`.
fn holds<T: Ord + Copy>(a: Option<(T, T)>, b: Option<(T, T)>) -> bool {
    match (a, b) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(a), Some(b)) => a.0 <= b.0 && b.1 <= a.1,
    }
}

fn point<T: Copy>(x: Option<T>) -> Option<(T, T)> {
    x.map(|x| (x, x))
}

/// Every dimension as a range pair, `(a, b)`.
type Dims = [(Option<(u128, u128)>, Option<(u128, u128)>); 7];

fn dims(a: &Filter, b: &Filter) -> Dims {
    let (ka, kb) = (&a.keys, &b.keys);
    let wide = |p: Option<(u16, u16)>| p.map(|(lo, hi)| (u128::from(lo), u128::from(hi)));
    let byte = |p: Option<u8>| point(p.map(u128::from));
    [
        (byte(ka.ip_proto), byte(kb.ip_proto)),
        (ka.src_ip.map(span), kb.src_ip.map(span)),
        (ka.dst_ip.map(span), kb.dst_ip.map(span)),
        (wide(ka.src_port), wide(kb.src_port)),
        (wide(ka.dst_port), wide(kb.dst_port)),
        (byte(ka.icmp_type), byte(kb.icmp_type)),
        (byte(ka.icmp_code), byte(kb.icmp_code)),
    ]
}

/// Some packet matches both filters. Over-approximating is safe (only costs
/// levels); under-approximating would reorder rules.
pub(super) fn overlap(a: &Filter, b: &Filter) -> bool {
    a.protocol == b.protocol
        && dims(a, b).iter().all(|&(x, y)| meet(x, y))
        && match (a.keys.tcp_flags, b.keys.tcp_flags) {
            (Some((av, am)), Some((bv, bm))) => (av ^ bv) & am & bm == 0,
            _ => true,
        }
        && match (a.keys.flags, b.keys.flags) {
            (Some((av, am)), Some((bv, bm))) => (av ^ bv) & am & bm == 0,
            _ => true,
        }
}

/// Every packet `b` matches, `a` matches too. Under-approximating is safe
/// (a shadowed rule is just kept).
pub(super) fn contains(a: &Filter, b: &Filter) -> bool {
    a.protocol == b.protocol
        && dims(a, b).iter().all(|&(x, y)| holds(x, y))
        && match (a.keys.tcp_flags, b.keys.tcp_flags) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some((av, am)), Some((bv, bm))) => am & !bm == 0 && (av ^ bv) & am == 0,
        }
        && match (a.keys.flags, b.keys.flags) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some((av, am)), Some((bv, bm))) => am & !bm == 0 && (av ^ bv) & am == 0,
        }
}

#[cfg(test)]
mod tests {
    use nos_proto::schema::AclAction;
    use nos_tc::{FlowerKeys, Protocol};

    use super::*;

    fn f(protocol: Protocol, keys: FlowerKeys) -> Filter {
        Filter {
            protocol,
            keys,
            action: AclAction::Deny,
            rule: 0,
            log: false,
        }
    }

    fn v4(f2: impl FnOnce(&mut FlowerKeys)) -> Filter {
        let mut k = FlowerKeys::default();
        f2(&mut k);
        f(Protocol::Ip, k)
    }

    fn net(s: &str) -> Option<(IpAddr, u8)> {
        #![allow(clippy::unnecessary_wraps, reason = "assigned to `Option` key fields")]
        let n: ipnet::IpNet = s.parse().unwrap();
        Some((n.network(), n.prefix_len()))
    }

    /// `(overlap, a contains b, b contains a)`.
    fn rel(a: &Filter, b: &Filter) -> (bool, bool, bool) {
        assert_eq!(overlap(a, b), overlap(b, a));
        (overlap(a, b), contains(a, b), contains(b, a))
    }

    #[test]
    fn families_never_meet() {
        let a = f(Protocol::Ip, FlowerKeys::default());
        let b = f(Protocol::Ipv6, FlowerKeys::default());
        assert_eq!(rel(&a, &b), (false, false, false));
        assert_eq!(rel(&a, &a), (true, true, true));
    }

    #[test]
    fn prefixes_nest_or_split() {
        let any = v4(|_| {});
        let wide = v4(|k| k.dst_ip = net("10.0.0.0/24"));
        let narrow = v4(|k| k.dst_ip = net("10.0.0.128/25"));
        let other = v4(|k| k.dst_ip = net("10.0.1.0/24"));
        let host = v4(|k| k.dst_ip = net("10.0.0.130/32"));
        assert_eq!(rel(&wide, &narrow), (true, true, false));
        assert_eq!(rel(&wide, &other), (false, false, false));
        assert_eq!(rel(&any, &host), (true, true, false));
        assert_eq!(rel(&narrow, &host), (true, true, false));
        let zero = v4(|k| k.dst_ip = net("0.0.0.0/0"));
        assert_eq!(rel(&zero, &host), (true, true, false));
        let v6 = |s| {
            f(
                Protocol::Ipv6,
                FlowerKeys {
                    src_ip: net(s),
                    ..Default::default()
                },
            )
        };
        assert_eq!(
            rel(&v6("2001:db8::/32"), &v6("2001:db8:1::/48")),
            (true, true, false)
        );
        assert_eq!(
            rel(&v6("2001:db8::/32"), &v6("2001:db9::/32")),
            (false, false, false)
        );
        assert_eq!(rel(&v6("::/0"), &v6("::1/128")), (true, true, false));
    }

    #[test]
    fn protocols_and_ports() {
        let tcp = v4(|k| k.ip_proto = Some(6));
        let udp = v4(|k| k.ip_proto = Some(17));
        let any = v4(|_| {});
        assert_eq!(rel(&tcp, &udp), (false, false, false));
        assert_eq!(rel(&any, &tcp), (true, true, false));
        let r = |lo, hi| v4(|k| k.dst_port = Some((lo, hi)));
        assert_eq!(rel(&r(10, 20), &r(20, 30)), (true, false, false));
        assert_eq!(rel(&r(10, 20), &r(21, 30)), (false, false, false));
        assert_eq!(rel(&r(10, 30), &r(15, 15)), (true, true, false));
        assert_eq!(rel(&r(10, 30), &any), (true, false, true));
        let s = v4(|k| k.src_port = Some((10, 20)));
        assert_eq!(rel(&r(10, 20), &s), (true, false, false));
    }

    #[test]
    fn tcp_flags_are_ternary() {
        let fl = |v, m| v4(|k| k.tcp_flags = Some((v, m)));
        let (ack, rst, both) = (fl(0x10, 0x10), fl(0x04, 0x04), fl(0x14, 0x14));
        let not_ack = fl(0, 0x10);
        assert_eq!(rel(&ack, &rst), (true, false, false));
        assert_eq!(rel(&ack, &not_ack), (false, false, false));
        assert_eq!(rel(&ack, &both), (true, true, false));
        assert_eq!(rel(&v4(|_| {}), &ack), (true, true, false));
    }

    #[test]
    fn fragment_flags_are_ternary() {
        let later = v4(|k| k.flags = Some((1, 3)));
        let any_frag = v4(|k| k.flags = Some((1, 1)));
        let first = v4(|k| k.flags = Some((3, 3)));
        assert_eq!(rel(&later, &later), (true, true, true));
        assert_eq!(rel(&any_frag, &later), (true, true, false));
        assert_eq!(rel(&later, &first), (false, false, false));
        assert_eq!(rel(&v4(|_| {}), &later), (true, true, false));
    }

    #[test]
    fn icmp_type_and_code() {
        let t = |ty, code| {
            v4(|k| {
                k.icmp_type = ty;
                k.icmp_code = code;
            })
        };
        assert_eq!(
            rel(&t(Some(8), None), &t(Some(0), None)),
            (false, false, false)
        );
        assert_eq!(
            rel(&t(Some(8), None), &t(Some(8), Some(0))),
            (true, true, false)
        );
        assert_eq!(
            rel(&t(Some(3), Some(1)), &t(Some(3), Some(2))),
            (false, false, false)
        );
        assert_eq!(rel(&t(None, None), &t(Some(8), None)), (true, true, false));
    }
}
