//! Addresses, ASNs, names and IDs shared by the phases. Every prefix/address
//! comes from an RFC 5737 (IPv4) / RFC 3849 (IPv6) documentation block, with a
//! distinct sub-block per scenario so log lines from different phases are
//! never confusable.

/// The user every router's *seeded* config carries, and what the harness logs
/// in as (`POST /v1/login`) to get the client certificate its REST calls use.
pub const E2E_USER: &str = "e2e";
pub const E2E_PASSWORD: &str = "e2e-password";
/// The `rest` phase's throwaway user for password-change checks.
pub const REST_USER: &str = "rest-user";
/// Where `nos-watchdogd` publishes the CA REST client certificates chain to —
/// read out of the container over the docker API, never fetched over the network.
pub const REST_CA_PATH: &str = "/run/nos/pki/rest-ca.crt";

pub const NET: &str = "nos-verify-net";
/// Two extra single-purpose docker networks, connected only to router-a, for
/// `port-aggregate` — bonding needs >=2 real distinct links, which no other
/// scenario's shared eth0 can provide. Docker names interfaces in connection
/// order, so router-a ends up with eth1/eth2.
pub const NET_BOND1: &str = "nos-verify-net-bond1";
pub const NET_BOND2: &str = "nos-verify-net-bond2";
pub const SUBNET: &str = "10.50.0.0/24";
/// A fixed ULA (RFC 4193) block so the docker network itself — and thus each
/// container's eth0 — has IPv6 enabled at the kernel level at all. Never
/// assigned to nos's own config.
pub const SUBNET6: &str = "fd00:10:50::/64";

pub const IP_A: &str = "10.50.0.2";
pub const IP_B: &str = "10.50.0.3";
pub const IP_C: &str = "10.50.0.4";
/// The throwaway router of the `rest` phase's destructive checks.
pub const IP_R: &str = "10.50.0.5";
/// `ospf-remote-lfa`'s fourth and fifth ring routers.
pub const IP_D: &str = "10.50.0.13";
pub const IP_E: &str = "10.50.0.14";
/// The `lldp` phase's second management address on router-b: TEST-NET-1, on
/// no interface, so it is advertised with the "unknown" interface numbering.
pub const MGMT_NOWHERE: &str = "192.0.2.1";
/// The `evpn` phase's third-party speaker (GoBGP), which originates the EVPN
/// routes no NOS router can yet.
pub const IP_G: &str = "10.50.0.6";
pub const ASN_G: u32 = 65010;
pub const RID_G: &str = "6.6.6.6";
pub const GOBGP_IMAGE: &str = "nos-e2e-gobgp:local";
/// Same release `tools/bench-bgp.sh` pins.
pub const GOBGP_VERSION: &str = "4.9.0";
pub const ASN_A: u32 = 65001;
/// `as4`: router-a's four-octet ASN, and the 2-byte-only ExaBGP speaker
/// (`router-g`) it peers, which an RFC 6793 "old" speaker sees as AS_TRANS.
pub const AS_TRANS: u32 = 23456;
pub const ASN_A4: u32 = 4_200_000_001;
/// ExaBGP's route for router-a to learn, and the four-octet ASN hidden in its
/// AS4_PATH (0xFA56EA02) behind an AS_TRANS in the 2-byte AS_PATH.
pub const AS4_LEARNED_PREFIX: &str = "203.0.113.0/24";
pub const AS4_HIDDEN_ASN: u32 = 4_200_000_002;
/// The four-octet AGGREGATOR ASN ExaBGP hides behind AS_TRANS + AS4_AGGREGATOR
/// (RFC 6793 §4.2.3) in the `as4` phase, and the aggregating router-id.
pub const AS4_AGGREGATOR_ASN: u32 = 4_200_000_003;
pub const AS4_AGGREGATOR_ID: &str = "192.0.2.9";
/// RFC 7606: ExaBGP announces this with a 3-byte (malformed) COMMUNITY, which
/// router-a must treat as a withdraw instead of resetting the session.
pub const AS4_BAD_PREFIX: &str = "203.0.114.0/24";
/// RFC 4271 §6.3: ExaBGP announces this with the class-E next hop `240.0.0.1`,
/// which router-a must treat as a withdraw (session kept).
pub const BAD_NEXT_HOP_PREFIX: &str = "203.0.130.0/24";
/// `bgp-role`: the route ExaBGP, a customer of router-b, announces carrying an
/// OTC attribute (RFC 9234 §5: a leak, since a customer never sets it).
pub const OTC_LEAK_PREFIX: &str = "203.0.115.0/24";
/// `bgp-role` (#872): a plain route from the role-less ExaBGP customer, to
/// show an unset `this.bgp.remote_role` compares `!=` true and `==` false.
pub const OTC_PLAIN_PREFIX: &str = "203.0.131.0/24";
/// `maximum-prefix`: the IPv4 routes ExaBGP announces to router-a — one more
/// than the limit the phase trips.
pub const MAX_PREFIX_ROUTES: [&str; 3] = ["203.0.113.0/24", "203.0.115.0/24", "203.0.116.0/24"];
/// `confederation` (RFC 5065): router-a and router-b are member ASes of
/// `CONFED_ID`; ExaBGP (router-g, `ASN_G`) is outside it, peering router-a.
/// ExaBGP announces `CONFED_LEARNED_PREFIX` normally, `CONFED_LOOP_PREFIX`
/// with `CONFED_ID` in its path, and `CONFED_BAD_PREFIX` with an
/// AS_CONFED_SEQUENCE (which an external peer must never send).
pub const CONFED_ID: u32 = 65100;
pub const CONFED_ASN_A: u32 = 65101;
pub const CONFED_ASN_B: u32 = 65102;
pub const CONFED_LEARNED_PREFIX: &str = "203.0.117.0/24";
pub const CONFED_LOOP_PREFIX: &str = "203.0.118.0/24";
pub const CONFED_BAD_PREFIX: &str = "203.0.119.0/24";
/// `local-as`: the AS router-a (`ASN_A`) presents to ExaBGP (router-g,
/// `ASN_G`, configured with `peer-as LOCAL_AS`). ExaBGP announces
/// `LOCAL_AS_LEARNED_PREFIX` normally and `LOCAL_AS_LOOP_PREFIX` with
/// `LOCAL_AS` in its path.
pub const LOCAL_AS: u32 = 65020;
pub const LOCAL_AS_LEARNED_PREFIX: &str = "203.0.122.0/24";
pub const LOCAL_AS_LOOP_PREFIX: &str = "203.0.123.0/24";
/// `local-as` (#392): announced with a first AS (`FORGED_FIRST_AS`) that is
/// not ExaBGP's (`ASN_G`), the peer AS router-a is configured with.
pub const LOCAL_AS_FORGED_PREFIX: &str = "198.18.77.0/24";
pub const FORGED_FIRST_AS: u32 = 65777;
/// `add-path`: the prefix ExaBGP (router-g) announces to router-a as RFC
/// 7911 path 1 (MED `ADD_PATH_MED_1`), path 2 (`ADD_PATH_MED_2`, the best)
/// and, for the send half, path 3 (`ADD_PATH_MED_3`): router-a ranks them 2,
/// 3, 1. Path N carries community 65000:N (`add_path_community`), which —
/// unlike MED — crosses router-a's eBGP session to router-b.
pub const ADD_PATH_PREFIX: &str = "203.0.124.0/24";
pub const ADD_PATH_MED_1: u32 = 50;
pub const ADD_PATH_MED_2: u32 = 10;
pub const ADD_PATH_MED_3: u32 = 30;

/// Community 65000:`id` as the `u32` nos-bgpd logs.
pub const fn add_path_community(id: u32) -> u32 {
    (65000 << 16) | id
}
/// `rpki`: the StayRTR cache (RFC 8210) router-a validates against, and an
/// address nothing answers on, configured as the more preferred cache so the
/// phase sees the failover. The ASN the first VRP set wrongly authorizes for
/// `REDISTRIBUTE_PREFIX` (router-b, `ASN_B`, really originates it).
pub const RPKI_CACHE: &str = "rpki-cache";
pub const IP_RPKI: &str = "10.50.0.8";
pub const IP_RPKI_DEAD: &str = "10.50.0.9";
pub const RPKI_WRONG_ASN: u32 = 64999;
/// `rpki`, #498: `nos-rtr-stub`, a cache requiring TCP-MD5 from router-a
/// (StayRTR cannot sign its session), and the key it and router-a share.
pub const RTR_STUB: &str = "rtr-stub";
pub const IP_RTR_STUB: &str = "10.50.0.10";
pub const RTR_STUB_KEY: &str = "rtr-s3cr3t";
/// `rpki`, RFC 8097 (#162): ExaBGP's two routes to router-a — one a VRP makes
/// invalid (authorizes `RPKI_WRONG_ASN`), one no VRP covers but tagged with
/// RFC 8097 "invalid", which router-a must ignore from eBGP.
pub const RPKI_INVALID_PREFIX: &str = "203.0.120.0/24";
pub const RPKI_TAGGED_PREFIX: &str = "203.0.121.0/24";
pub const STAYRTR_IMAGE: &str = "rpki/stayrtr:v0.6.4";
/// `bmp` (#878): the GoBMP collector, pinned by digest (its last tagged
/// release is from 2022; `:latest` moves), dumping to the console. 10.50.0.40
/// is free in the lab network. `FROM scratch`: no shell, no healthcheck.
pub const GOBMP_IMAGE: &str =
    "sbezverk/gobmp@sha256:e905f70d90f30d1eee60d04ac74c1fc4d41116fd3e53ba8bba7ae9b4201bfb30";
pub const BMP_COLLECTOR: &str = "bmp-collector";
pub const IP_BMP: &str = "10.50.0.40";
pub const BMP_PORT: u16 = 5000;
pub const EXABGP_IMAGE: &str = "nos-e2e-exabgp:local";
/// Same release `tools/bench-bgp.sh` pins.
pub const EXABGP_VERSION: &str = "5.0.13";
/// `route-refresh-stale`: the ExaBGP image's own python3, running the scripted
/// speaker `phases/borr.py` instead of ExaBGP.
pub const PY_SPEAKER_IMAGE: &str = "nos-e2e-pyspeaker:local";
/// `route-refresh-stale`: the prefix the scripted speaker re-announces inside
/// its unterminated refresh, and the one it doesn't.
pub const RR_STALE_KEPT: &str = "203.0.130.0/24";
pub const RR_STALE_PURGED: &str = "203.0.131.0/24";
/// `evpn-fdb`: router-a's broadcast domain and its EVPN identity. The import
/// Route Target is the one GoBGP tags its routes with (`65010:10000`); the
/// export one is router-a's own. `EVPN_LOCAL_MAC` is what the helper pins on
/// the bridge, `EVPN_REMOTE_MAC` what GoBGP announces.
pub const EVPN_DOMAIN: &str = "bd-evpn";
pub const EVPN_VNI: u32 = 10100;
pub const EVPN_RD: &str = "65001:1";
pub const EVPN_RT_IMPORT: &str = "65010:10000";
pub const EVPN_RT_EXPORT: &str = "65001:10100";
pub const EVPN_LOCAL_MAC: &str = "02:00:00:00:00:01";
pub const EVPN_REMOTE_MAC: &str = "aa:bb:cc:00:00:01";
pub const EVPN_OTHER_RT_MAC: &str = "aa:bb:cc:00:00:02";
/// A second matching-RT MAC, numerically above `EVPN_REMOTE_MAC`: the one a
/// `max-remote-macs 1` ceiling evicts (the lowest MAC address wins).
pub const EVPN_EXTRA_MAC: &str = "aa:bb:cc:00:00:03";
pub const EVPN_EXTRA_IP: &str = "192.0.2.11";
/// How `nos_proto::bgp::community_name` renders RFC 8326 GRACEFUL_SHUTDOWN.
pub const EVPN_GS_NAME: &str = "graceful-shutdown";
pub const EVPN_PORT: &str = "evpn0";
/// `evpn-fdb`'s Type-2-with-IP checks: an ARP binding pinned on the bridge for
/// `EVPN_LOCAL_MAC`, the domain's SVI address (`redistribute from connected`),
/// and the address GoBGP's `macadv` carries (`macadv` in `evpn_fdb`).
pub const EVPN_HOST_IP: &str = "198.51.100.7";
pub const EVPN_SVI_ADDRESS: &str = "203.0.113.1/24";
pub const EVPN_SVI_IP: &str = "203.0.113.1";
pub const EVPN_REMOTE_IP: &str = "192.0.2.10";
/// `evpn-fdb`'s MAC mobility check (RFC 7432 §7.7/§15): GoBGP announces this
/// one first, then the local helper pins the *same* MAC on `EVPN_PORT` — a
/// local-vs-remote conflict — and router-a's own local claim must win.
pub const EVPN_MOBILE_MAC: &str = "aa:bb:cc:00:00:03";
/// `lacp`: each router's configured LACP Actor System ID (`lacp-system-id`).
pub const LACP_SYSTEM_ID_A: &str = "02:00:00:00:0a:01";
pub const LACP_SYSTEM_ID_B: &str = "02:00:00:00:0b:01";
/// Actor System/Port Priorities the `lacp` phase configures per router (any
/// distinct non-default values do), and the system priority it changes
/// router-a to afterwards to prove a change restarts and renegotiates.
pub const LACP_SYSTEM_PRIORITY_A: u16 = 100;
pub const LACP_SYSTEM_PRIORITY_B: u16 = 200;
pub const LACP_PORT_PRIORITY_A: u16 = 1000;
pub const LACP_PORT_PRIORITY_B: u16 = 2000;
pub const LACP_SYSTEM_PRIORITY_A_CHANGED: u16 = 150;
/// `evpn-esi`: the Ethernet Segment on router-a's bond, the origin address of
/// the peer PE GoBGP plays (below router-a's, so it wins the DF election for
/// the even `EVPN_VNI`), and a MAC pinned behind the bond.
pub const ESI: &str = "00:11:22:33:44:55:66:77:88:99";
pub const ESI_PEER_ORIGIN: &str = "10.50.0.1";
/// `evpn-esi`: a PE that advertises only a bare Type-4 for `ESI` — no per-EVI
/// A-D for `EVPN_VNI` — and, being GoBGP, no DF Election community, so no
/// AC-DF. RFC 8584 §2.2.3 (strictly): the per-EVI filter only applies when
/// every PE advertises AC-DF, so this PE *is* a candidate (RFC 7432's list),
/// and router-a's `hrw` falls back to modulo. Ranked [10.49.0.1, `IP_A`
/// (10.50.0.2)], 10100 % 2 == 0: it wins and router-a is the non-DF. The
/// filter itself (AC-DF everywhere) is covered by `nos-fdb`'s unit tests:
/// GoBGP's CLI can't attach a DF Election community to its Type-4.
pub const ESI_PEER_NO_EVI_ORIGIN: &str = "10.49.0.1";
/// `evpn-esi`: router-a's `--df-wait` — long enough to read the port's real
/// flood flags while it is still blocked.
pub const DF_WAIT_SECS: u32 = 12;
pub const DF_WAIT_ARG: &str = "--fdbd-arg=--df-wait=12";
/// `evpn-esi`: a second segment router-a is *not* attached to, on which GoBGP
/// plays the PE that advertises two MACs (with an IP each, GoBGP requires one)
/// and, later, its per-ES A-D route. GoBGP's spelling, and how its RIB prints it.
pub const ESI2: [&str; 2] = ["arbitrary", "11:22:33:44:55:66:77:88:aa"];
pub const ESI2_MACS: [(&str, &str); 2] = [
    ("aa:bb:cc:00:00:03", "192.0.2.31"),
    ("aa:bb:cc:00:00:04", "192.0.2.32"),
];
pub const ESI2_RD: &str = "65010:9";
/// `evpn-esi`, aliasing: a third segment router-a is not on, served by two PEs
/// GoBGP plays with distinct next hops (fake VTEPs — only the kernel state
/// router-a builds for them is read back) and one MAC advertised by the first.
pub const ESI3: [&str; 2] = ["arbitrary", "11:22:33:44:55:66:77:88:bb"];
pub const ESI3_PES: [(&str, &str); 2] = [("10.50.0.11", "65010:11"), ("10.50.0.12", "65010:12")];
pub const ESI3_MAC: (&str, &str) = ("aa:bb:cc:00:00:05", "192.0.2.35");
/// `evpn-dataplane`: the two PEs share one Route Target both ways, each has
/// its own RD; a dual-homed CE (`ce`, one link to each PE) and a host (`h`)
/// behind router-b sit in the same L2 domain. Docker networks are the wires.
pub const EVPN_DP_RT: &str = "65000:10100";
pub const EVPN_DP_RD_A: &str = "65001:1";
pub const EVPN_DP_RD_B: &str = "65002:1";
// `evpn-dataplane` runs HRW on both PEs. With `ESI` and `EVPN_VNI` (CRC-32 of
// the tag + ESI = 1003094399), RFC 8584 §3.2 weighs `IP_A` (10.50.0.2) at
// 51651125 and `IP_B` (10.50.0.3) at 1988780236 — router-b is the HRW DF,
// where modulo ([.2, .3][10100 % 2]) would pick router-a. Deterministic: the
// addresses, ESI and VNI are all fixed constants.
pub const NET_CE_A: &str = "nos-verify-net-ce-a";
pub const NET_CE_B: &str = "nos-verify-net-ce-b";
pub const NET_H: &str = "nos-verify-net-h";
pub const HOST_IMAGE: &str = "nos-verify-host:local";
pub const CE_HOST: &str = "e2e-ce";
pub const H_HOST: &str = "e2e-h";
pub const CE_IP: &str = "192.168.10.10";
pub const H_IP: &str = "192.168.10.20";
pub const ESI_MAC: &str = "02:00:00:00:00:0e";
/// `evpn-l3`: each PE's IP-VRF (`L3_TABLE`, one shared Route Target, its own
/// RD) with a host on its own docker network behind it. The subnets differ
/// (RFC 2544 benchmarking blocks, so no other docker network on the host
/// collides), so only a Type-5 route can join them.
pub const L3_TABLE: &str = "tenant";
/// `vpn`: router-a's L3VPN VRF (RFC 4364 import, #579), `nos-provision`'s
/// `--vpn-table` default.
pub const VPN_TABLE: &str = "vrf-red";
/// `vpn`'s chunked stage (#715): single-path VPNv4 routes GoBGP announces.
/// Each weighs 2 (`VpnRoute::weight`, paths + 1), so 20 000 are 40 000 >
/// `VPN_PUSH_CHUNK` (32 768): `vrf-red`'s `Full` crosses as two frames.
pub const VPN_CHUNKED_ROUTES: usize = 20_000;
/// `vpn`/`vpn-export`: router-a's RD (also its export RT toward GoBGP).
pub const VPN_RD_A: &str = "65000:100";
/// `vpn-export`: router-b's RD and the RT both PEs export and import.
pub const VPN_RD_B: &str = "65000:200";
pub const VPN_RT: &str = "65000:1";
/// `rtc`: router-a's VRF import RT (originated as RT-Constraint membership
/// with origin AS `ASN_A`) and the one a commit swaps it for.
pub const RTC_IMPORT: &str = "65000:1";
pub const RTC_IMPORT_2: &str = "65000:2";
/// `vpn-export`: each PE's VRF loopback, the connected route it exports.
pub const VPN_EXPORT_A: &str = "192.0.2.10/32";
pub const VPN_EXPORT_B: &str = "192.0.2.20/32";
/// `vpn-export`: `VPN_TABLE` is the only VRF any scenario gives a `vpn`, with
/// no explicit label, so `nos-ribd`'s registry always hands it the first
/// allocated label (`LABEL_BASE`), and never frees it.
pub const VPN_LABEL: u32 = 1000;
/// `vpn-v6`: router-a's VRF loopback (the VPNv6 route GoBGP must see) and the
/// IPv6 twin of `vpn-dataplane`'s CE networks (ULA, next to their IPv4
/// `L3_SUBNET_*`): each PE's address, the host's, and the subnet.
pub const VPN6_EXPORT_A: &str = "2001:db8:a::1/128";
pub const L3V6_SUBNET_A: &str = "fd18:1::/64";
pub const L3V6_SUBNET_B: &str = "fd18:2::/64";
pub const L3V6_GW_A: &str = "fd18:1::2";
pub const L3V6_GW_B: &str = "fd18:2::2";
pub const L3V6_HOST_A: &str = "fd18:1::10";
pub const L3V6_HOST_B: &str = "fd18:2::10";
pub const L3_VNI: u32 = 5000;
pub const L3_RT: &str = "65000:5000";
pub const L3_RD_A: &str = "65001:5000";
pub const L3_RD_B: &str = "65002:5000";
pub const NET_L3_A: &str = "nos-verify-net-l3-a";
pub const NET_L3_B: &str = "nos-verify-net-l3-b";
pub const L3_SUBNET_A: &str = "198.18.1.0/24";
pub const L3_SUBNET_B: &str = "198.18.2.0/24";
/// Each PE's address on its host's network (docker assigns it, nos configures
/// the same one), and the host's own.
pub const L3_GW_A: &str = "198.18.1.2";
pub const L3_GW_B: &str = "198.18.2.2";
pub const L3_HOST_IP_A: &str = "198.18.1.10";
pub const L3_HOST_IP_B: &str = "198.18.2.10";
/// `evpn`'s interop check: the Type-5 GoBGP announces into router-a's IP-VRF.
pub const L3_GOBGP_PREFIX: &str = "198.18.9.0/24";
pub const L3_GOBGP_RT: &str = "65010:5000";
pub const L3_GOBGP_RMAC: &str = "aa:bb:cc:00:00:50";
/// `evpn-l3`'s burst stage (#763): how many Type-5 host routes GoBGP announces
/// at once, and the seconds to install (or remove) all of them. The old
/// per-route whole-table reconcile managed about 12 routes/s, so 2000 took
/// minutes; the incremental path is limited by GoBGP's announce rate.
pub const L3_BURST_ROUTES: usize = 2000;
pub const L3_BURST_SECS: u64 = 90;
/// `evpn`'s symmetric IRB interop check: GoBGP's MAC+IP with Label2 = the L3
/// VNI, installed by router-a's IP-VRF as a host route.
pub const L3_GOBGP_HOST: &str = "198.18.8.9";
/// `evpn-l3`'s symmetric IRB stage (RFC 9135): a domain stretched over both
/// PEs with its SVI (the same anycast gateway on each) in `L3_TABLE`, and a
/// host behind router-b only, on its own docker network (router-b's eth2).
pub const NET_IRB: &str = "nos-verify-net-irb";
pub const IRB_DOMAIN: &str = "irb";
pub const IRB_VNI: u32 = 10300;
pub const IRB_RT: &str = "65000:10300";
pub const IRB_RD_A: &str = "65001:10300";
pub const IRB_RD_B: &str = "65002:10300";
pub const IRB_GW: &str = "198.18.3.1";
pub const IRB_HOST: &str = "e2e-irb";
pub const IRB_HOST_IP: &str = "198.18.3.20";
/// `evpn-v6`: each PE's IPv6 VTEP/BGP address on eth0 (in `SUBNET6`, above
/// the low addresses docker hands out — nos-interfaced removes docker's own
/// anyway), selected as the VTEP by its label.
pub const V6_A: &str = "fd00:10:50::a";
pub const V6_B: &str = "fd00:10:50::b";
pub const V6_C: &str = "fd00:10:50::c";
pub const V6_LABEL: &str = "v6";
/// `evpn-esi`, DF-aware backup: a fourth, single-active segment router-a is
/// not on, served by four PEs GoBGP plays (fake VTEPs). The MAC's own PE is
/// the first; once it loses its per-ES A-D the other three are the backup
/// candidates, ordered .22 .23 .24: 10100 % 3 == 2 elects .24, where the
/// lowest-address fallback picks .22. Only .24 sends a Type-4 (a real FRR),
/// so with the Type-4 held the backup is .24, and without it .22.
pub const ESI4: [&str; 2] = ["arbitrary", "11:22:33:44:55:66:77:88:cc"];
pub const ESI4_PES: [(&str, &str); 4] = [
    ("10.50.0.21", "65010:21"),
    ("10.50.0.22", "65010:22"),
    ("10.50.0.23", "65010:23"),
    ("10.50.0.24", "65010:24"),
];
/// The AS of the FRR PE (`router-f`) that originates ESI4's Type-4 with its
/// ES-Import RT, which GoBGP's CLI can't set.
pub const ESI4_FRR_ASN: u32 = 65024;
pub const ESI4_MAC: (&str, &str) = ("aa:bb:cc:00:00:06", "192.0.2.36");
pub const ASN_B: u32 = 65002;
/// Only `route-server` (router-b and router-c must be in distinct ASes from
/// each other and from router-a) and `ospf-dr`'s router-c use this.
pub const ASN_C: u32 = 65003;
pub const RID_A: &str = "1.1.1.1";
pub const RID_B: &str = "2.2.2.2";
pub const RID_C: &str = "3.3.3.3";

/// TEST-NET-2 — a fake redistributed prefix.
pub const REDISTRIBUTE_PREFIX: &str = "198.51.100.0/24";
pub const REDISTRIBUTE_GATEWAY: &str = "10.50.0.99";
/// `blackhole` (#861): TEST-NET-3 host routes router-a tags BLACKHOLE;
/// router-b's prefix-list covers `BLACKHOLE_NET` at /32 only, so the first is
/// authorised and the second (TEST-NET-1) is not.
pub const BLACKHOLE_NET: &str = "203.0.113.64/28";
pub const BLACKHOLE_COVERED: &str = "203.0.113.66/32";
pub const BLACKHOLE_UNCOVERED: &str = "192.0.2.77/32";
/// `aggregate`: router-a's aggregate, covering `REDISTRIBUTE_PREFIX` and the
/// static router-b redistributes for the phase.
pub const AGGREGATE_PREFIX: &str = "198.51.0.0/16";
pub const AGGREGATE_CONTRIBUTOR_B: &str = "198.51.200.0/24";
/// TEST-NET-3 — the loopback scenario's address.
pub const LOOPBACK_ADDRESS: &str = "203.0.113.1/32";
/// `loopback` (#655): the same IPv6 host address, /64 then /48 — the kernel
/// refuses a second copy of an IPv6 address, so the old one must go first.
pub const LOOPBACK_V6_OLD: &str = "2001:db8:655::1/64";
pub const LOOPBACK_V6_NEW: &str = "2001:db8:655::1/48";
/// TEST-NET-3 — `port-aggregate`'s bond address (tag 0, in rt1), and the
/// connected route nos-ribd derives from it.
pub const PORT_AGGREGATE_ADDRESS: &str = "203.0.113.33/29";
pub const PORT_AGGREGATE_SUBNET: &str = "203.0.113.32/29";
/// TEST-NET-1 — the routed-subinterface scenario. The tag is distinct from
/// `switching`'s 100/200 and the ospf broadcast tag (400).
pub const SUBINTERFACE_TAG: u16 = 300;
pub const SUBINTERFACE_ADDRESS: &str = "192.0.2.1/24";
/// router-a's table-id registry starts empty and allocates from 100; `rt1` is
/// the only routing table any scenario configures, so it is always the first
/// and gets id 100 and kernel device name `lo100`.
pub const LOOPBACK_DEVICE: &str = "lo100";
pub const SVI_ADDRESS: &str = "203.0.113.9/32";

pub const OSPF_INSTANCE: &str = "ospf1";
pub const OSPF_ROUTER_ID: &str = "9.9.9.9";
pub const OSPF_ROUTER_ID_B: &str = "9.9.9.10";
/// `ospf-dr`: router-b's temporary router-id, so its restart finds its old
/// Network-LSA (advertised under `OSPF_ROUTER_ID_B`) as a stale own LSA.
pub const OSPF_ROUTER_ID_B_RENUMBERED: &str = "9.9.9.11";
/// Deliberately lower than both, so router-b stays DR and router-a Backup
/// (RFC 2328 §9.4 incumbent stickiness) and router-c settles as DrOther.
pub const OSPF_ROUTER_ID_C: &str = "9.9.9.8";
pub const OSPF_AREA: &str = "0.0.0.0";
pub const OSPF_PROFILE: &str = "ospf-profile1";
pub const OSPF_BROADCAST_DOMAIN: &str = "bd-ospf";
pub const OSPF_BROADCAST_TAG: u16 = 400;
pub const OSPF_BROADCAST_ADDRESS_A: &str = "203.0.113.65/28";
pub const OSPF_BROADCAST_ADDRESS_B: &str = "203.0.113.66/28";
pub const OSPF_BROADCAST_ADDRESS_C: &str = "203.0.113.67/28";
/// A destination with no neighbor of its own, on router-b's loopback, so
/// router-a can only learn it through a real SPF computation.
pub const OSPF_SPF_LOOPBACK_ADDRESS: &str = "203.0.113.80/32";
/// router-c's loopback for the `ospf-dr` multicast data-plane proof (#879).
pub const OSPF_DR_LOOPBACK_ADDRESS_C: &str = "203.0.113.98/32";
/// `ospf-remote-lfa`: the five-router ring a-b-c-d-e-a. Ring link `i` (from
/// the `i`-th router's eth1 to the next one's eth2) is `10.61.i.0/24`, `.1`
/// on eth1 and `.2` on eth2; router `i`'s loopback is `10.62.0.i/32`.
pub const RLFA_RING_PREFIX: &str = "10.61";
pub const RLFA_LOOPBACK_PREFIX: &str = "10.62.0";
/// The ring's routing table is every router's first (`rt1`), kernel table
/// id 100 (see `LOOPBACK_DEVICE`), so its VRF and tunnel device names are fixed.
pub const RLFA_VRF: &str = "vrf100";
/// `bfd` (#660): router-a's only table is `rt1`, kernel table 100, so the VRF is `vrf100` too.
pub const BFD_VRF: &str = RLFA_VRF;
pub const RLFA_DEVICE: &str = "rlfa100";
/// `next-hop-reachability`: what router-b advertises with its own loopback
/// (`OSPF_SPF_LOOPBACK_ADDRESS`) as NEXT_HOP — a TEST-NET-2 sub-block, so a
/// log grep for it never matches `REDISTRIBUTE_PREFIX`'s /24 line and vice
/// versa (the strings differ).
pub const NHR_PREFIX: &str = "198.51.100.192/26";
/// The connected subnet of `OSPF_BROADCAST_ADDRESS_A`, as nos-ribd lists it.
pub const OSPF_BROADCAST_SUBNET: &str = "203.0.113.64/28";
/// `abr`: a fresh prefix in a second area (reusing the same prefix would
/// recompute to the identical next-hop and produce no new "added route").
pub const OSPF_AREA_1: &str = "0.0.0.1";
pub const OSPF_PROFILE_AREA1: &str = "ospf-profile-area1";
pub const OSPF_ABR_LOOPBACK_ADDRESS: &str = "203.0.113.96/32";
/// `ospf-virtual-link`: router-c's area-2 loopback, behind a virtual link
/// through area 1 — a prefix no other phase uses.
pub const OSPF_AREA_2: &str = "0.0.0.2";
pub const OSPF_PROFILE_AREA2: &str = "ospf-profile-area2";
pub const OSPF_VLINK_LOOPBACK_ADDRESS: &str = "203.0.113.104/32";
/// `ospf-stub`: router-b's (the ABR's) area-0 loopback, and the area range
/// over it. Not the range's own network address, so its Type-3 keeps a
/// different link-state id from the range's and is flushed, not rewritten.
pub const OSPF_STUB_LOOPBACK_ADDRESS: &str = "203.0.113.121/32";
pub const OSPF_STUB_RANGE: &str = "203.0.113.120/29";
/// `ospf-graceful-restart`: router-a's loopback, which router-b must keep a
/// route to through router-a's `nos-ospfd` restart. A prefix no earlier phase
/// installs.
pub const OSPF_GR_LOOPBACK_ADDRESS: &str = "203.0.113.112/32";
/// `ospf-graceful-restart`: a loopback added to router-b's OSPF while it
/// helps, so its own Router-LSA changes (a topology change). No other phase
/// uses it.
pub const OSPF_GR_TOPOLOGY_LOOPBACK_ADDRESS: &str = "203.0.113.113/32";
/// `ospf-opaque`: an FRR router (`router-f`, pulled, same tag as
/// `tools/bench-bgp.sh`'s `FRR_IMAGE`) on its own network with router-a's
/// eth1 only, so router-b can hear FRR's LSAs only through router-a.
pub const FRR_IMAGE: &str = "quay.io/frrouting/frr:10.7.1";
/// `bgp-gr-frr`: the prefix FRR (`router-f`, at `IP_G` on `NET`) announces to
/// router-a over eBGP.
pub const FRR_BGP_PREFIX: &str = "198.18.210.0/24";
/// `bfd`: the BFD-guarded static route each router holds towards the other
/// (`BFD_PREFIX_B` on router-a via router-b, `BFD_PREFIX_A` on router-b via
/// router-a) and the one router-a holds via FRR (`BFD_PREFIX_F`).
pub const BFD_PREFIX_A: &str = "198.18.230.0/24";
pub const BFD_PREFIX_B: &str = "198.18.231.0/24";
pub const BFD_PREFIX_F: &str = "198.18.232.0/24";
/// `bgp-graceful-restart`: a static router-b redistributes, so router-a's
/// `nos-ribd` holds a BGP route when its `nos-bgpd` restarts.
pub const GR_B_PREFIX: &str = "198.18.211.0/24";
/// `bgp-push-chunked`: extra /32 statics router-a redistributes (in
/// 100.64.0.0/16). With `REDISTRIBUTE_PREFIX` router-b's push is 5001 routes,
/// over two `BGP_PUSH_CHUNK`s (2048): a `Full` of 3 frames.
pub const CHUNKED_ROUTES: usize = 5000;
/// `ospf-push-chunked`: extra /32 statics router-a redistributes into OSPF
/// (in 100.64.0.0/16). With `ASBR_PREFIX` and
/// the intra-area routes router-b holds 80-odd single-hop routes (weight 2
/// each, `OspfRoute::weight`), so `OSPF_PUSH_CHUNK_TEST` cuts its `Full` into
/// 32-route frames: 3 of them. Kept under ~100: every Type-5 travels in one
/// unsplit LSU and the 4 KB receive buffer truncates a bigger one (#606).
pub const OSPF_CHUNKED_ROUTES: usize = 80;
/// `ospf-push-chunked`: `nos-ospfd --push-chunk` (the real
/// `OSPF_PUSH_CHUNK` is 65 536, far too many routes for a CI phase).
pub const OSPF_PUSH_CHUNK_TEST: usize = 64;
/// `ospf-push-chunked`: `nos-ribd --redistribute-chunk` (the real
/// `REDISTRIBUTE_CHUNK` is 65 536 routes). router-a redistributes
/// `OSPF_CHUNKED_ROUTES` plus `ASBR_PREFIX`, so its `RedistributeRoutes`
/// `Full` is 3 frames.
pub const REDISTRIBUTE_CHUNK_TEST: usize = 32;
pub const NET_OSPF_FRR: &str = "nos-verify-net-ospf-frr";
pub const OSPF_FRR_SUBNET: &str = "10.51.0.0/24";
pub const OSPF_FRR_IP_A: &str = "10.51.0.2";
pub const OSPF_FRR_IP_F: &str = "10.51.0.6";
pub const OSPF_ROUTER_ID_F: &str = "9.9.9.6";
/// Scales nos-ospfd's LSA age clock: 1800/180 = 10s, 3600/180 = 20s.
pub const OSPF_AGE_MULTIPLIER: u32 = 180;
pub const ASBR_PREFIX: &str = "192.0.2.128/25";
/// `asbr`/`ospf-opaque`: shares `ASBR_PREFIX`'s network address, so RFC 2328
/// Appendix E gives its Type-5 the host-bits ID `ASBR_PREFIX_SPECIFIC_LSID`.
pub const ASBR_PREFIX_SPECIFIC: &str = "192.0.2.128/26";
pub const ASBR_PREFIX_SPECIFIC_LSID: &str = "192.0.2.191";
/// `ospf-opaque`: FRR redistributes this overlapping pair; FRR's Appendix E
/// is stateful, so which one carries host bits depends on origination order.
pub const OSPF_FRR_EXTERNAL_WIDE: &str = "198.18.100.0/24";
pub const OSPF_FRR_EXTERNAL_NARROW: &str = "198.18.100.0/25";
/// `ospf-opaque`: FRR's static with a next hop on the router-a/FRR subnet
/// (nobody owns `OSPF_FRR_FA`); FRR puts that address in the Type-5's
/// forwarding address, and router-a must route via it, not via FRR (#215).
pub const OSPF_FRR_FA_PREFIX: &str = "198.18.101.0/24";
pub const OSPF_FRR_FA: &str = "10.51.0.9";
pub const ASBR_GATEWAY: &str = "10.50.0.98";
pub const MTU_VALUE: u32 = 9000;
/// `ospf-mtu-pagination` (v2 LSU/LSR/LSAck split, #806): with no auth the LSU
/// budget is 200-20-24-4 = 152 bytes (4 Type-5s of 36), the LSR/LSAck budget
/// 156 (13 requests, 7 acks), a DBD holds ~7 headers: several entries per
/// packet yet `OSPF_SPLIT_ROUTES` LSAs still need several packets.
pub const OSPF_SPLIT_MTU_VALUE: u32 = 200;
/// Type-5 LSAs router-a originates in `ospf-mtu-pagination`: `ASBR_PREFIX`
/// plus 19 /32s from `ospf_chunked_routes` (so 21 LSAs with the Router-LSA).
pub const OSPF_SPLIT_ROUTES: usize = 20;

pub const OSPFV3_INSTANCE: &str = "ospfv3-1";
pub const OSPFV3_ROUTER_ID: &str = "9.9.9.9";
pub const OSPFV3_ROUTER_ID_B: &str = "9.9.9.10";
pub const OSPFV3_ROUTER_ID_C: &str = "9.9.9.8";
/// router-b's temporary router-id in `ospfv3-p2p-rid-change` (#957). A fixed
/// value is deterministic: no other phase uses 9.9.9.11, and router-b is the
/// only router that changes id, once, then back.
pub const OSPFV3_ROUTER_ID_B_NEW: &str = "9.9.9.11";
pub const OSPFV3_AREA: &str = "0.0.0.0";
pub const OSPFV3_PROFILE: &str = "ospfv3-profile1";
pub const OSPFV3_ADDRESS_A: &str = "2001:db8:1::1/64";
pub const OSPFV3_ADDRESS_B: &str = "2001:db8:1::2/64";
/// The second OSPFv3 link of `ospfv3` (#276): `eth1`, a direct veth pair.
pub const OSPFV3_ETH1_ADDRESS_A: &str = "2001:db8:5::1/64";
pub const OSPFV3_ETH1_ADDRESS_B: &str = "2001:db8:5::2/64";
pub const OSPFV3_LOOPBACK_ADDRESS: &str = "2001:db8:2::1/128";
/// router-b's loopback for `ospfv3-lfa` (`OSPFV3_LOOPBACK_ADDRESS` is router-a's).
pub const OSPFV3_LFA_LOOPBACK_ADDRESS: &str = "2001:db8:4::1/128";
/// router-c's loopback for the `ospfv3-dr` multicast data-plane proof (#879).
pub const OSPFV3_DR_LOOPBACK_ADDRESS_C: &str = "2001:db8:4::8/128";
/// 0xA021 (E-Router-LSA) as `lsa_type` prints in the logs.
pub const LSA_TYPE_E_ROUTER: u16 = 0xA021;
/// RFC 5340 AS-External-LSA (0x4005) and RFC 8362 E-AS-External-LSA (0xC025),
/// as `lsa_type` prints in the logs — `ospfv3-asbr` matches either, since
/// `ospfv3` leaves both routers in extended mode.
pub const LSA_TYPE_AS_EXTERNAL_V3: u16 = 0x4005;
pub const LSA_TYPE_E_AS_EXTERNAL: u16 = 0xC025;
/// RFC 5340 Inter-Area-Prefix-LSA (0x2003) and E-Inter-Area-Prefix (0xA023).
pub const LSA_TYPE_INTER_AREA_PREFIX_V3: u16 = 0x2003;
pub const LSA_TYPE_E_INTER_AREA_PREFIX: u16 = 0xA023;
/// `ospfv3-asbr`'s redistributed IPv6 static: via router-b's eth0 address,
/// so router-a's kernel can install it too.
pub const OSPFV3_ASBR_PREFIX: &str = "2001:db8:77::/48";
/// AS-External-LSAs router-a originates in `ospfv3-mtu-pagination` (#807): at
/// `OSPF_SPLIT_MTU_VALUE` the LSU budget is 200-40-16-4 = 140 bytes (~3 of
/// ~44), so 20 of them need several LSUs.
pub const OSPFV3_SPLIT_ROUTES: usize = 20;
pub const OSPFV3_ASBR_GATEWAY: &str = "2001:db8:1::2";
/// `ospfv3-abr`'s second area, its profile and router-b's loopback in it (a
/// prefix no other phase uses, so `nos-ribd` logs a fresh install).
pub const OSPFV3_AREA_1: &str = "0.0.0.1";
pub const OSPFV3_PROFILE_AREA1: &str = "ospfv3-profile-area1";
pub const OSPFV3_ABR_LOOPBACK_ADDRESS: &str = "2001:db8:5::1/128";
/// `ospfv3-lsinfinity-asbr`: the area-1 link between router-b (the ABR) and
/// router-c (the ASBR), a docker network of its own so the two areas sit on
/// different L2 segments (docker names it `eth1` on both).
pub const NET_OSPFV3_A1: &str = "nos-verify-net-ospfv3-a1";
pub const OSPFV3_A1_SUBNET: &str = "10.52.0.0/24";
pub const OSPFV3_A1_SUBNET6: &str = "fd19:3::/64";
pub const OSPFV3_A1_IP_B: &str = "10.52.0.2";
pub const OSPFV3_A1_IP_C: &str = "10.52.0.3";
pub const OSPFV3_A1_ADDRESS_B: &str = "fd19:3::2/64";
pub const OSPFV3_A1_ADDRESS_C: &str = "fd19:3::3/64";
/// RFC 5340 A.4.1 Inter-Area-Router-LSA (0x2004) and RFC 8362 E-Inter-Area-Router (0xA024).
pub const LSA_TYPE_INTER_AREA_ROUTER: u16 = 0x2004;
pub const LSA_TYPE_E_INTER_AREA_ROUTER: u16 = 0xA024;
/// router-c's redistributed IPv6 static, behind router-b's address on the area-1 link.
pub const OSPFV3_A1_ASBR_PREFIX: &str = "2001:db8:78::/48";
pub const OSPFV3_BROADCAST_ADDRESS_A: &str = "2001:db8:3::1/64";
pub const OSPFV3_BROADCAST_ADDRESS_B: &str = "2001:db8:3::2/64";
pub const OSPFV3_BROADCAST_ADDRESS_C: &str = "2001:db8:3::3/64";

/// Distinct from `port-aggregate`'s "bond1" so the two phases' log greps never collide.
pub const LACP_AGGREGATE: &str = "bond-lacp";
/// `micro-bfd`'s aggregate and the two routers' bond addresses (a /30 no other phase uses).
pub const MICRO_AGGREGATE: &str = "bond-micro";
pub const MICRO_ADDRESS_A: &str = "203.0.113.201/30";
pub const MICRO_ADDRESS_B: &str = "203.0.113.202/30";
pub const NETNS_HELPER_IMAGE: &str = "nos-verify-netns-helper:local";
/// Debian + python3 (raw `AF_PACKET` injection, `lacp`'s Marker PDU).
pub const PYTHON_HELPER_IMAGE: &str = "nos-verify-python-helper:local";

pub const COMMUNITY_AA: u32 = 65001;
pub const COMMUNITY_NN: u32 = 100;
pub const COMMUNITY_PACKED: u32 = (COMMUNITY_AA << 16) | COMMUNITY_NN;
/// RFC 1997 NO_EXPORT (`65535:65281`), packed.
pub const NO_EXPORT_PACKED: u32 = 0xFFFF_FF01;
/// RFC 8326 GRACEFUL_SHUTDOWN (`65535:0`), packed (`communities`, #860).
pub const GRACEFUL_SHUTDOWN_PACKED: u32 = 0xFFFF_0000;
/// `communities` (#873): router-b's own, untagged prefix, the control that
/// router-c must learn while the NO_EXPORT-tagged one never reaches it.
pub const CONTROL_PREFIX: &str = "198.18.101.0/24";
/// `communities`: tagged on then stripped by `remove_matching("^<STRIP_AA>:")`,
/// so it must never reach router-b.
pub const STRIP_AA: u32 = 65002;
pub const STRIP_PACKED: u32 = (STRIP_AA << 16) | 7;
/// MED set by an export policy: router-a's in `communities`, router-b's in `route-server`.
pub const MED: u32 = 4242;

pub const REST_PORT: u16 = 8080;
/// Not assigned to any interface, so binding it fails with EADDRNOTAVAIL.
pub const REST_ABSENT_ADDRESS: &str = "10.50.0.77";
pub const REST_TX: &str = "rest-e2e";
/// Where every router's `nos-acld --flowspec-file` looks (#561): the data
/// volume, writable by the harness through `bollard`.
pub const FLOWSPEC_DIR: &str = "/var/lib/nos";
pub const FLOWSPEC_FILE: &str = "flowspec.json";

/// The `syslog` phase's collector (syslog-ng, an independent RFC 5424
/// receiver) on the shared network.
pub const SYSLOG_COLLECTOR: &str = "syslog-collector";
pub const IP_SYSLOG: &str = "10.50.0.30";
pub const SYSLOG_IMAGE: &str = "nos-e2e-syslog:local";
/// Router-a's hostname while the phase runs (the default `nos` says nothing).
pub const SYSLOG_HOSTNAME: &str = "e2e-a";

/// `pki-rotation` runs the watchdog with certificates this short-lived and a
/// rotation this frequent, so a daemon that never applied a rotation would be
/// holding an *expired* certificate within seconds. Rotation must come well
/// inside the lifetime (the watchdog refuses a config where it doesn't).
pub const PKI_LEAF_LIFETIME_SECS: u64 = 20;
pub const PKI_ROTATE_EVERY_SECS: u64 = 6;
/// `--pki-ipc-session-max` for `pki-rotation` (#637): short enough to pass
/// during the phase's rotation wait, long enough for the first renewal.
pub const PKI_IPC_SESSION_MAX_SECS: u64 = 15;

/// `ospf-forged-lsa` (#959): the router id of a router that does not exist,
/// and the prefixes its forged (one-sided) and control (reciprocal) LSAs carry.
pub const FORGED_ROUTER_ID: &str = "9.9.9.99";
pub const FORGED_V4_PREFIX: &str = "198.18.110.0/24";
pub const FORGED_V4_CONTROL: &str = "198.18.111.0/24";
pub const FORGED_V6_PREFIX: &str = "2001:db8:99::/64";
pub const FORGED_V6_CONTROL: &str = "2001:db8:98::/64";
