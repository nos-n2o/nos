//! Non-blocking advice computed on commit (#501).

use nos_proto::Config;

/// One message per eBGP peer-group family with no `maximum-prefix` (any
/// explicit limit silences it). Deterministic: config order, then family order.
pub fn commit_warnings(config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    for inst in &config.bgp_instances {
        for g in inst.peer_groups.iter().filter(|g| g.remote_as != inst.asn) {
            for af in g
                .address_families
                .iter()
                .filter(|af| g.maximum_prefix.get(**af).is_none())
            {
                out.push(format!(
                    "bgp-instance '{}' peer-group '{}': eBGP, no maximum-prefix for {af} (set 'maximum-prefix {af} limit <n>')",
                    inst.name, g.name
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nos_proto::{
        AddressFamily::{self, Ipv4Unicast, Ipv6Unicast},
        BgpInstance, BgpPeerGroup, BgpPrefixLimit,
    };

    use super::*;

    fn group(name: &str, remote_as: u32, afs: Vec<AddressFamily>) -> BgpPeerGroup {
        BgpPeerGroup {
            name: name.into(),
            remote_as,
            address_families: afs,
            ..Default::default()
        }
    }

    fn cfg(groups: Vec<BgpPeerGroup>) -> Config {
        let mut c = Config::default();
        c.bgp_instances.push(BgpInstance {
            name: "r1".into(),
            router_id: Ipv4Addr::new(10, 0, 0, 1),
            asn: 65000,
            peer_groups: groups,
            peers: Vec::new(),
            cluster_id: None,
            maximum_paths: None,
            confederation: nos_proto::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            bmp_stations: Vec::new(),
            aggregates: Vec::new(),
            graceful_restart: nos_proto::BgpGracefulRestart::default(),
            routing_table: None,
            redistribute_policy: None,
        });
        c
    }

    #[test]
    fn ebgp_without_limit_warns_per_family() {
        let w = commit_warnings(&cfg(vec![group(
            "ext",
            65001,
            vec![Ipv4Unicast, Ipv6Unicast],
        )]));
        assert_eq!(w.len(), 2);
        assert!(w[0].contains("'r1'") && w[0].contains("'ext'") && w[0].contains("ipv4"));
        assert!(w[1].contains("ipv6"));
    }

    #[test]
    fn ibgp_and_unnegotiated_family_never_warn() {
        assert_eq!(
            commit_warnings(&cfg(vec![group("in", 65000, vec![Ipv4Unicast])])),
            [] as [std::string::String; 0]
        );
        assert_eq!(
            commit_warnings(&cfg(vec![group("ext", 65001, vec![])])),
            [] as [std::string::String; 0]
        );
    }

    #[test]
    fn explicit_and_zero_limit_silence() {
        for limit in [0, 100] {
            let mut g = group("ext", 65001, vec![Ipv4Unicast]);
            g.maximum_prefix.ipv4 = Some(BgpPrefixLimit {
                limit,
                ..Default::default()
            });
            assert_eq!(
                commit_warnings(&cfg(vec![g])),
                [] as [std::string::String; 0]
            );
        }
    }

    #[test]
    fn two_groups_are_ordered() {
        let w = commit_warnings(&cfg(vec![
            group("a", 65001, vec![Ipv4Unicast]),
            group("b", 65002, vec![Ipv4Unicast]),
        ]));
        assert!(w[0].contains("'a'") && w[1].contains("'b'"));
    }
}
