//! Route Target (subtype 0x02) and Site of Origin (subtype 0x03) helpers over
//! the `u64` form `PathAttributes.extended_communities` stores (type octet in
//! the high byte). Only the three transitive types RFC 4364 uses: 0x00
//! two-octet AS, 0x01 IPv4 address, 0x02 four-octet AS.

const SUB_RT: u8 = 0x02;
const SUB_SOO: u8 = 0x03;

fn is_vpn_type(c: u64, subtype: u8) -> bool {
    let b = c.to_be_bytes();
    b[0] <= 0x02 && b[1] == subtype
}

/// Whether `c` is a Route Target.
#[must_use]
pub fn is_route_target(c: u64) -> bool {
    is_vpn_type(c, SUB_RT)
}

/// The Route Targets among `communities`, in order.
#[must_use]
pub fn route_targets(communities: &[u64]) -> Vec<u64> {
    communities
        .iter()
        .copied()
        .filter(|c| is_route_target(*c))
        .collect()
}

/// The Sites of Origin among `communities`, in order.
#[must_use]
pub fn sites_of_origin(communities: &[u64]) -> Vec<u64> {
    communities
        .iter()
        .copied()
        .filter(|c| is_vpn_type(*c, SUB_SOO))
        .collect()
}

pub use nos_proto::evpn_id::soo_from_rt;

/// Whether `communities` carries exactly the Site of Origin `soo`.
#[must_use]
pub fn has_soo(communities: &[u64], soo: u64) -> bool {
    communities.contains(&soo)
}

/// A Site of Origin as `asn:nn` / `a.b.c.d:nn` (no `RO:` prefix).
#[must_use]
pub fn format_soo(soo: u64) -> String {
    let s = crate::evpn::format_ext_community(soo);
    s.strip_prefix("RO:").map_or(s.clone(), str::to_string)
}

/// A Route Target of wire type `ty` (0x00: `admin` is a 16-bit AS and
/// `assigned` 32 bits; 0x01: an IPv4 address and 16 bits; 0x02: a 32-bit AS
/// and 16 bits). `None` for another type or a value that does not fit.
#[must_use]
pub fn rt(ty: u8, admin: u32, assigned: u32) -> Option<u64> {
    let mut b = [ty, SUB_RT, 0, 0, 0, 0, 0, 0];
    match ty {
        0x00 => {
            b[2..4].copy_from_slice(&u16::try_from(admin).ok()?.to_be_bytes());
            b[4..8].copy_from_slice(&assigned.to_be_bytes());
        }
        0x01 | 0x02 => {
            b[2..6].copy_from_slice(&admin.to_be_bytes());
            b[6..8].copy_from_slice(&u16::try_from(assigned).ok()?.to_be_bytes());
        }
        _ => return None,
    }
    Some(u64::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evpn::format_ext_community;
    use nos_proto::evpn_id::parse_rt;

    #[test]
    fn route_targets_of_the_three_types_are_extracted_and_soo_is_not() {
        let a = rt(0, 65000, 100).unwrap();
        let b = rt(1, 0x0a00_0001, 7).unwrap();
        let c = rt(2, 4_200_000_000, 9).unwrap();
        let soo = 0x0003_fde8_0000_0001_u64;
        let encap = 0x030c_0000_0000_0008_u64;
        let all = [a, soo, b, encap, c];
        assert_eq!(route_targets(&all), vec![a, b, c]);
        assert_eq!(sites_of_origin(&all), vec![soo]);
        assert!(is_route_target(a) && !is_route_target(soo) && !is_route_target(encap));
        // Non-transitive twins (type 0x40+) are out.
        assert!(!is_route_target(a | (0x40 << 56)));
    }

    #[test]
    fn rt_constructors_match_parse_rt_and_format() {
        assert_eq!(rt(0, 65000, 100), parse_rt("65000:100"));
        assert_eq!(rt(2, 4_200_000_000, 9), parse_rt("4200000000:9"));
        assert_eq!(rt(1, 0x0a00_0001, 7), parse_rt("10.0.0.1:7"));
        assert_eq!(
            format_ext_community(rt(0, 65000, 100).unwrap()),
            "RT:65000:100"
        );
        assert_eq!(
            format_ext_community(rt(1, 0x0a00_0001, 7).unwrap()),
            "RT:10.0.0.1:7"
        );
        assert_eq!(
            format_ext_community(rt(2, 4_200_000_000, 9).unwrap()),
            "RT:4200000000:9"
        );
    }

    #[test]
    fn soo_helpers_follow_the_rt_encoding() {
        use nos_proto::evpn_id::parse_soo;
        for text in ["65001:77", "10.0.0.1:7", "4200000000:9"] {
            let (r, s) = (parse_rt(text).unwrap(), parse_soo(text).unwrap());
            assert_eq!(soo_from_rt(r), s);
            assert!(!is_route_target(s) && is_route_target(r));
            assert_eq!(sites_of_origin(&[r, s]), vec![s]);
            assert!(has_soo(&[r, s], s) && !has_soo(&[r], s));
        }
        assert_eq!(
            format_ext_community(parse_soo("65001:77").unwrap()),
            "RO:65001:77"
        );
        assert_eq!(format_soo(parse_soo("65001:77").unwrap()), "65001:77");
    }

    fn route_input(prefix: ipnet::IpNet) -> nos_rpl::Input<'static> {
        nos_rpl::Input {
            prefix,
            bgp: nos_rpl::BgpInput {
                tag: 0,
                origin: nos_rpl::Origin::Igp,
                as_path: &[],
                as_path_segments: &[],
                local_pref: 100,
                med: None,
                next_hop: None,
                learned_via_ibgp: false,
                router_id: None,
                originator_id: None,
                cluster_list: &[],
                peer: None,
                peer_as: 0,
                communities: &[],
                extended_communities: &[],
                large_communities: &[],
                validation_state: nos_rpl::ValidationState::default(),
                rd: None,
                local_role: None,
                remote_role: None,
                otc: None,
            },
        }
    }

    /// `nos-rpl` cannot depend on `nos-proto`, so it carries its own encoder
    /// for `rt()`/`soo()`/`rd()`; this pins it to the config-side parsers.
    #[test]
    fn rpl_literals_equal_the_config_parsers() {
        use nos_proto::evpn_id::{parse_rd, parse_soo};
        use nos_rpl::{compile, vm, Symbols, Verdict};
        let ext_of = |lit: &str| {
            let p = compile(
                &format!("this.bgp.extended_communities.add({lit})\naccept\n"),
                &Symbols::EMPTY,
            )
            .unwrap();
            let prefix = "10.0.0.0/8".parse().unwrap();
            let route = route_input(prefix);
            match vm::run(&p, &route) {
                Verdict::Accept {
                    extended_communities,
                    ..
                } => extended_communities,
                Verdict::Reject => panic!("accept expected"),
            }
        };
        for v in [
            "65000:1",
            "0:7",
            "65535:4294967295",
            "65536:1",
            "4200000000:65535",
            "10.0.0.1:7",
            "255.255.255.255:65535",
        ] {
            assert_eq!(
                ext_of(&format!("rt({v})")),
                vec![parse_rt(v).unwrap()],
                "rt {v}"
            );
            assert_eq!(
                ext_of(&format!("soo({v})")),
                vec![parse_soo(v).unwrap()],
                "soo {v}"
            );
            let rd = u64::from_be_bytes(parse_rd(v).unwrap());
            let p = compile(
                &format!("if this.bgp.rd == rd({v}):\n    accept\nelse:\n    reject\n"),
                &Symbols::EMPTY,
            )
            .unwrap();
            let mut input = route_input("10.0.0.0/8".parse().unwrap());
            input.bgp.rd = Some(rd);
            assert!(
                matches!(vm::run(&p, &input), Verdict::Accept { .. }),
                "rd {v}"
            );
        }
    }

    #[test]
    fn rt_rejects_values_that_do_not_fit() {
        assert_eq!(rt(0, 70_000, 1), None);
        assert_eq!(rt(1, 1, 70_000), None);
        assert_eq!(rt(2, 1, 70_000), None);
        assert_eq!(rt(3, 1, 1), None);
    }
}
