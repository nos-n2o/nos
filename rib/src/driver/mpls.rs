//! The kernel MPLS pieces of L3VPN (#581) that need no netlink socket: label
//! checks, the `AF_MPLS` pop route, reading a route's pushed labels back, and
//! the `net.mpls` sysctls (plain `/proc/sys` file I/O, no external command,
//! #228). `LinuxRibDriver` sends what these build; kept out of `linux.rs` so
//! it counts toward `COVERAGE_MIN`.

use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use netlink_packet_core::{Emitable as _, NlaBuffer, ParseableParametrized as _};
use nos_proto::{IlmRoute, NextHop};
use rtnetlink::packet_route::route::{
    MplsLabel, RouteAddress, RouteAttribute, RouteLwEnCapType, RouteLwTunnelEncap, RouteMessage,
    RouteMplsIpTunnel, RouteNextHop, RouteNextHopFlags, RouteProtocol,
};
use rtnetlink::RouteMessageBuilder;

use super::DriverError;

/// What `RibDriver::sync_mpls` programs for a table with `vpn`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mpls {
    /// The VRF's label: pop, then an IP lookup in the VRF.
    pub label: u32,
    /// The underlay table (`vpn.bgp_instance`'s): its interfaces receive the
    /// labelled packets, and an imported route's PE next hop leaves over one
    /// of them.
    pub underlay: Option<String>,
}

/// The largest 20-bit label; `net.mpls.platform_labels` tops out here too.
pub const MAX_LABEL: u32 = (1 << 20) - 1;

/// Labels 0-15 are reserved (RFC 3032 section 2.1): refused even though
/// config validation already does, defence in depth.
pub fn check_label(label: u32) -> Result<(), DriverError> {
    if (16..MAX_LABEL).contains(&label) {
        Ok(())
    } else {
        Err(DriverError::Other(format!(
            "mpls label {label} is outside 16..{MAX_LABEL}"
        )))
    }
}

/// A label stack as the kernel takes it: bottom-of-stack on the last entry
/// only, TTL and traffic class zero (it refuses anything else).
pub fn stack(labels: &[u32]) -> Vec<MplsLabel> {
    labels
        .iter()
        .enumerate()
        .map(|(i, &label)| MplsLabel {
            label,
            traffic_class: 0,
            bottom_of_stack: i + 1 == labels.len(),
            ttl: 0,
        })
        .collect()
}

/// `<label> dev <vrf>`: pop and look the payload up in the VRF's table. One
/// route serves IPv4 and IPv6 (the kernel reads the payload's version).
pub fn pop_route_msg(label: u32, vrf: u32) -> RouteMessage {
    RouteMessageBuilder::<MplsLabel>::new()
        .label(stack(&[label])[0])
        .output_interface(vrf)
        .build()
}

/// Most labels the kernel takes in one pushed or swapped-to stack
/// (`MAX_NEW_LABELS`).
const MAX_STACK: usize = 30;

/// An ILM entry the kernel would take: the incoming label is unreserved
/// (`check_label`), each outgoing one is unreserved or an explicit null (0, 2;
/// PHP is an empty stack, never label 3), the stack is at most 30 deep.
pub fn check_ilm(r: &IlmRoute) -> Result<(), DriverError> {
    check_label(r.label)?;
    for hop in &r.hops {
        if hop.labels.len() > MAX_STACK {
            return Err(DriverError::Other(format!(
                "ilm {}: more than {MAX_STACK} out labels",
                r.label
            )));
        }
        for &l in &hop.labels {
            if l != 0 && l != 2 {
                check_label(l)?;
            }
        }
    }
    Ok(())
}

/// `LABEL[=GATEWAY[,OUT[/OUT..]]]`, the test-only `--test-ilm` syntax.
pub fn parse_ilm(s: &str) -> Result<IlmRoute, String> {
    let bad = |what: &str| format!("--test-ilm {s:?}: {what}");
    let (label, rest) = s.split_once('=').map_or((s, None), |(l, r)| (l, Some(r)));
    let label = label.parse().map_err(|_| bad("bad label"))?;
    let hops = match rest {
        None => Vec::new(),
        Some(r) => {
            let (gw, out) = r.split_once(',').map_or((r, ""), |(g, o)| (g, o));
            let labels = out
                .split('/')
                .filter(|l| !l.is_empty())
                .map(|l| l.parse().map_err(|_| bad("bad out label")))
                .collect::<Result<_, _>>()?;
            vec![NextHop {
                gateway: gw.parse().map_err(|_| bad("bad gateway"))?,
                interface_id: None,
                labels,
            }]
        }
    };
    Ok(IlmRoute { label, hops })
}

/// The protocol of every ILM route installed for the segment routing source:
/// how a crashed predecessor's routes are found again.
pub const ILM_PROTOCOL: RouteProtocol = RouteProtocol::Ospf;

/// An ILM entry: `<label> [as <out>/..] via inet <gw> dev <if>` for one hop
/// (a pop when its stack is empty: PHP), `RTA_MULTIPATH` for several, and no
/// hop is a pop followed by a lookup in `vrf`. Every hop needs its ifindex.
pub fn ilm_route_msg(r: &IlmRoute, vrf: u32) -> RouteMessage {
    let mut m = RouteMessageBuilder::<MplsLabel>::new()
        .label(stack(&[r.label])[0])
        .protocol(ILM_PROTOCOL)
        .build();
    let hop_attrs = |h: &NextHop| {
        let mut a = vec![RouteAttribute::Via(h.gateway.into())];
        if !h.labels.is_empty() {
            a.push(RouteAttribute::NewDestination(stack(&h.labels)));
        }
        a
    };
    match r.hops.as_slice() {
        [] => m.attributes.push(RouteAttribute::Oif(vrf)),
        [h] => {
            m.attributes.extend(hop_attrs(h));
            m.attributes
                .push(RouteAttribute::Oif(h.interface_id.unwrap_or(0)));
        }
        hops => {
            let nhs = hops
                .iter()
                .map(|h| {
                    let mut nh = RouteNextHop::default();
                    nh.interface_index = h.interface_id.unwrap_or(0);
                    nh.flags = RouteNextHopFlags::empty();
                    nh.attributes = hop_attrs(h);
                    nh
                })
                .collect();
            m.attributes.push(RouteAttribute::MultiPath(nhs));
        }
    }
    m
}

/// `(label, every oif)` of a dumped `AF_MPLS` route installed by
/// [`ilm_route_msg`] (our protocol), `None` for any other.
pub fn ilm_of(route: &RouteMessage) -> Option<(u32, Vec<u32>)> {
    if route.header.protocol != ILM_PROTOCOL {
        return None;
    }
    let (label, oif) = pop_route_of(route)?;
    let mut oifs: Vec<u32> = oif.into_iter().collect();
    for a in &route.attributes {
        if let RouteAttribute::MultiPath(nhs) = a {
            oifs.extend(nhs.iter().map(|n| n.interface_index));
        }
    }
    Some((label, oifs))
}

/// `(label, oif)` of a dumped `AF_MPLS` route.
pub fn pop_route_of(route: &RouteMessage) -> Option<(u32, Option<u32>)> {
    let label = route.attributes.iter().find_map(|a| match a {
        RouteAttribute::Destination(RouteAddress::Mpls(l)) => Some(l.label),
        _ => None,
    })?;
    let oif = route.attributes.iter().find_map(|a| match a {
        RouteAttribute::Oif(i) => Some(*i),
        _ => None,
    });
    Some((label, oif))
}

/// The labels a route or one of its `RTA_MULTIPATH` next hops pushes
/// (`RTA_ENCAP` of type MPLS in `attrs`), empty without. `netlink-packet-route`
/// decodes a next hop's encap with the route-level `RTA_ENCAP_TYPE`, which a
/// multipath route has none of, so a dumped hop's MPLS encap arrives as an
/// opaque `Other` attribute: it is re-emitted and decoded as MPLS here.
pub fn labels_of(attrs: &[RouteAttribute]) -> Vec<u32> {
    let mpls = attrs
        .iter()
        .any(|a| matches!(a, RouteAttribute::EncapType(RouteLwEnCapType::Mpls)));
    attrs
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Encap(encaps) => encaps.iter().find_map(|e| match e {
                RouteLwTunnelEncap::Mpls(RouteMplsIpTunnel::Destination(l)) => Some(l.clone()),
                RouteLwTunnelEncap::Other(nla) if mpls => {
                    let mut buf = vec![0; nla.buffer_len()];
                    nla.emit(&mut buf);
                    match RouteLwTunnelEncap::parse_with_param(
                        &NlaBuffer::new(&buf),
                        RouteLwEnCapType::Mpls,
                    ) {
                        Ok(RouteLwTunnelEncap::Mpls(RouteMplsIpTunnel::Destination(l))) => Some(l),
                        _ => None,
                    }
                }
                _ => None,
            }),
            _ => None,
        })
        .map_or_default(|l| l.iter().map(|l| l.label).collect())
}

/// The `RTA_ENCAP_TYPE` + `RTA_ENCAP` pushing `labels`, for one
/// `RTA_MULTIPATH` next hop (`RouteNextHopBuilder` has no MPLS helper; a
/// single-hop route uses `RouteMessageBuilder::output_mpls`). Empty for none.
pub fn hop_encap(labels: &[u32]) -> Vec<RouteAttribute> {
    if labels.is_empty() {
        return Vec::new();
    }
    vec![
        RouteAttribute::EncapType(RouteLwEnCapType::Mpls),
        RouteAttribute::Encap(vec![RouteLwTunnelEncap::Mpls(
            RouteMplsIpTunnel::Destination(stack(labels)),
        )]),
    ]
}

/// A labelled route's hops, each given the device it leaves `onlink` over
/// (`devs`, in hop order: its own ifindex, or the underlay lookup's), and
/// the gateways of the hops dropped for having none.
pub fn onlink_hops(hops: Vec<NextHop>, devs: &[Option<u32>]) -> (Vec<NextHop>, Vec<IpAddr>) {
    let mut unresolved = Vec::new();
    let kept = hops
        .into_iter()
        .zip(devs)
        .filter_map(|(mut hop, dev)| {
            if let Some(dev) = dev {
                hop.interface_id = Some(*dev);
                Some(hop)
            } else {
                unresolved.push(hop.gateway);
                None
            }
        })
        .collect();
    (kept, unresolved)
}

/// The `net.mpls` sysctls, under `root` (`/proc/sys`, a tempdir in tests).
/// Each is read first and written only when not already enough, so a value
/// the operator set (or the e2e helper did) is never rewritten.
#[derive(Debug, Clone)]
pub struct Sysctl {
    root: PathBuf,
}

impl Default for Sysctl {
    fn default() -> Self {
        Self::new("/proc/sys")
    }
}

impl Sysctl {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn mpls(&self) -> Result<PathBuf, DriverError> {
        let dir = self.root.join("net/mpls");
        if dir.is_dir() {
            Ok(dir)
        } else {
            Err(DriverError::Other(
                "MPLS is not available: load the mpls_router kernel module \
                 (mpls_iptunnel for labelled routes)"
                    .into(),
            ))
        }
    }

    /// `net.mpls.platform_labels` above `label`: grown to the next multiple
    /// of 1024 when short, never shrunk (that would delete routes).
    pub fn ensure_platform_labels(&self, label: u32) -> Result<(), DriverError> {
        let path = self.mpls()?.join("platform_labels");
        let current: u32 = read(&path)?.parse().unwrap_or(0);
        if current > label {
            return Ok(());
        }
        let want = (label + 1).next_multiple_of(1024).min(MAX_LABEL);
        write(&path, "net.mpls.platform_labels", want)
    }

    /// `net.mpls.conf.<ifname>.input = 1`. A device without an MPLS conf
    /// directory is skipped.
    pub fn ensure_input(&self, ifname: &str) -> Result<(), DriverError> {
        let path = self.mpls()?.join("conf").join(ifname).join("input");
        match std::fs::read_to_string(&path) {
            Ok(v) if v.trim() == "1" => Ok(()),
            Ok(_) => write(&path, &format!("net.mpls.conf.{ifname}.input"), 1),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(DriverError::Registry(e)),
        }
    }
}

fn read(path: &Path) -> Result<String, DriverError> {
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

fn write(path: &Path, name: &str, value: u32) -> Result<(), DriverError> {
    std::fs::write(path, value.to_string()).map_err(|e| match e.kind() {
        ErrorKind::ReadOnlyFilesystem | ErrorKind::PermissionDenied => DriverError::Other(format!(
            "cannot write {name}={value}: set it on the host or with docker's --sysctl \
             (docker mounts /proc/sys read-only)"
        )),
        _ => DriverError::Other(format!("cannot write {name}={value}: {e}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn labels_are_checked_and_stacked_bottom_last() {
        assert!(check_label(15).is_err());
        assert!(check_label(MAX_LABEL).is_err());
        check_label(16).unwrap();
        let s = stack(&[100, 200]);
        assert_eq!(
            (
                s[0].label,
                s[0].bottom_of_stack,
                s[1].label,
                s[1].bottom_of_stack
            ),
            (100, false, 200, true)
        );
        assert_eq!((s[1].ttl, s[1].traffic_class), (0, 0));
    }

    #[test]
    fn pop_route_round_trips() {
        let m = pop_route_msg(1000, 7);
        assert_eq!(m.header.destination_prefix_length, 20);
        assert_eq!(pop_route_of(&m), Some((1000, Some(7))));
        assert_eq!(labels_of(&m.attributes), [] as [u32; 0]);
        assert_eq!(pop_route_of(&RouteMessage::default()), None);
    }

    #[test]
    fn pushed_labels_read_back_v4_and_v6() {
        for (dst, len, gw) in [
            ("10.1.0.0", 24, "10.0.0.2"),
            ("2001:db8:1::", 48, "2001:db8::2"),
        ] {
            let m = RouteMessageBuilder::<std::net::IpAddr>::new()
                .destination_prefix(dst.parse().unwrap(), len)
                .unwrap()
                .gateway(gw.parse().unwrap())
                .unwrap()
                .output_mpls(stack(&[2000]))
                .build();
            assert_eq!(labels_of(&m.attributes), vec![2000]);
        }
    }

    /// A next hop's encap read back both ways: as built, and as a dump
    /// decodes it without a route-level encap type (`Other`).
    #[test]
    fn hop_encap_reads_back_typed_and_opaque() {
        assert_eq!(
            hop_encap(&[]),
            [] as [netlink_packet_route::route::RouteAttribute; 0]
        );
        let attrs = hop_encap(&[300, 16]);
        assert_eq!(labels_of(&attrs), vec![300, 16]);
        let RouteAttribute::Encap(encaps) = &attrs[1] else {
            panic!("{attrs:?}");
        };
        let mut buf = vec![0; encaps[0].buffer_len()];
        encaps[0].emit(&mut buf);
        let opaque =
            RouteLwTunnelEncap::parse_with_param(&NlaBuffer::new(&buf), RouteLwEnCapType::None)
                .unwrap();
        assert!(matches!(opaque, RouteLwTunnelEncap::Other(_)));
        let dumped = vec![
            attrs[0].clone(),
            RouteAttribute::Encap(vec![opaque.clone()]),
        ];
        assert_eq!(labels_of(&dumped), vec![300, 16]);
        // Without RTA_ENCAP_TYPE=MPLS an opaque encap is not ours to read.
        assert_eq!(
            labels_of(&[RouteAttribute::Encap(vec![opaque])]),
            [] as [u32; 0]
        );
    }

    #[test]
    fn unresolved_hops_are_dropped_and_named() {
        let hop = |gw: &str, labels: Vec<u32>| NextHop {
            gateway: gw.parse().unwrap(),
            interface_id: None,
            labels,
        };
        let hops = vec![hop("10.0.0.2", vec![100]), hop("10.0.0.3", vec![200])];
        let (kept, unresolved) = onlink_hops(hops.clone(), &[None, Some(4)]);
        assert_eq!(unresolved, vec!["10.0.0.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            kept,
            vec![NextHop {
                interface_id: Some(4),
                ..hops[1].clone()
            }]
        );
        let (kept, unresolved) = onlink_hops(hops, &[None, None]);
        assert_eq!(kept, [] as [nos_proto::NextHop; 0]);
        assert_eq!(unresolved.len(), 2);
    }

    fn hop(gw: &str, ifx: u32, labels: Vec<u32>) -> NextHop {
        NextHop {
            gateway: gw.parse().unwrap(),
            interface_id: Some(ifx),
            labels,
        }
    }

    #[test]
    fn ilm_messages_round_trip_and_are_checked() {
        let swap = IlmRoute {
            label: 16001,
            hops: vec![hop("10.0.0.2", 4, vec![16002])],
        };
        let m = ilm_route_msg(&swap, 9);
        assert_eq!(m.header.destination_prefix_length, 20);
        assert_eq!(ilm_of(&m), Some((16001, vec![4])));
        assert!(m
            .attributes
            .iter()
            .any(|a| matches!(a, RouteAttribute::NewDestination(l) if l[0].label == 16002)));
        // PHP: a hop with no stack has no `as`.
        let php = IlmRoute {
            label: 16001,
            hops: vec![hop("10.0.0.2", 4, vec![])],
        };
        assert!(!ilm_route_msg(&php, 9)
            .attributes
            .iter()
            .any(|a| matches!(a, RouteAttribute::NewDestination(_))));
        // Local pop: the VRF.
        let local = IlmRoute {
            label: 16001,
            hops: vec![],
        };
        assert_eq!(ilm_of(&ilm_route_msg(&local, 9)), Some((16001, vec![9])));
        // ECMP: one multipath attribute, every ifindex found.
        let ecmp = IlmRoute {
            label: 16001,
            hops: vec![hop("10.0.0.2", 4, vec![1000]), hop("10.0.1.2", 5, vec![])],
        };
        assert_eq!(ilm_of(&ilm_route_msg(&ecmp, 9)), Some((16001, vec![4, 5])));
        // Not ours: the L3VPN pop route has the default protocol.
        assert_eq!(ilm_of(&pop_route_msg(1000, 7)), None);

        for ok in [&swap, &php, &local, &ecmp] {
            check_ilm(ok).unwrap();
        }
        let bad = |label, out: Vec<u32>| IlmRoute {
            label,
            hops: vec![hop("10.0.0.2", 4, out)],
        };
        assert!(check_ilm(&bad(3, vec![])).is_err());
        assert!(check_ilm(&bad(16001, vec![3])).is_err());
        assert!(check_ilm(&bad(16001, vec![2, 0])).is_ok());
        assert!(check_ilm(&bad(16001, vec![16; 31])).is_err());
    }

    #[test]
    fn test_ilm_syntax() {
        let r = parse_ilm("16001=10.0.0.2,16002/16003").unwrap();
        assert_eq!(
            (r.label, r.hops[0].labels.clone()),
            (16001, vec![16002, 16003])
        );
        assert_eq!(
            parse_ilm("16001=10.0.0.2").unwrap().hops[0].labels,
            Vec::<u32>::new()
        );
        assert_eq!(parse_ilm("16001").unwrap().hops.len(), 0);
        for bad in ["x", "1=nope", "1=10.0.0.2,x"] {
            assert!(parse_ilm(bad).is_err(), "{bad}");
        }
    }

    fn tree(platform: &str, inputs: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mpls = dir.path().join("net/mpls");
        std::fs::create_dir_all(&mpls).unwrap();
        std::fs::write(mpls.join("platform_labels"), platform).unwrap();
        for (ifname, v) in inputs {
            std::fs::create_dir_all(mpls.join("conf").join(ifname)).unwrap();
            std::fs::write(mpls.join("conf").join(ifname).join("input"), v).unwrap();
        }
        dir
    }

    fn get(dir: &tempfile::TempDir, rel: &str) -> String {
        std::fs::read_to_string(dir.path().join("net/mpls").join(rel)).unwrap()
    }

    #[test]
    fn a_missing_module_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let e = Sysctl::new(dir.path())
            .ensure_platform_labels(1000)
            .unwrap_err();
        assert!(e.to_string().contains("mpls_router"), "{e}");
        assert!(Sysctl::new(dir.path()).ensure_input("eth0").is_err());
        assert_eq!(Sysctl::default().root, PathBuf::from("/proc/sys"));
    }

    #[test]
    fn platform_labels_only_grow() {
        let t = tree("0\n", &[]);
        let s2 = Sysctl::new(t.path());
        s2.ensure_platform_labels(1000).unwrap();
        assert_eq!(get(&t, "platform_labels"), "1024");
        s2.ensure_platform_labels(1024).unwrap();
        assert_eq!(get(&t, "platform_labels"), "2048");
        s2.ensure_platform_labels(100).unwrap();
        assert_eq!(get(&t, "platform_labels"), "2048", "never shrinks");
        s2.ensure_platform_labels(MAX_LABEL - 1).unwrap();
        assert_eq!(get(&t, "platform_labels"), MAX_LABEL.to_string());
        // Enough already: left as the operator wrote it.
        let t = tree("1048575\n", &[]);
        Sysctl::new(t.path()).ensure_platform_labels(5000).unwrap();
        assert_eq!(get(&t, "platform_labels"), "1048575\n");
    }

    #[test]
    fn input_is_set_once_and_unknown_devices_skipped() {
        let t = tree("0", &[("eth0", "0\n"), ("eth1", "1\n")]);
        let s = Sysctl::new(t.path());
        s.ensure_input("eth0").unwrap();
        s.ensure_input("eth1").unwrap();
        s.ensure_input("nope").unwrap();
        assert_eq!(get(&t, "conf/eth0/input"), "1");
        assert_eq!(get(&t, "conf/eth1/input"), "1\n", "not rewritten");
    }

    #[test]
    fn an_unwritable_sysctl_says_where_to_set_it() {
        let t = tree("0", &[("eth0", "0")]);
        let files = [
            t.path().join("net/mpls/platform_labels"),
            t.path().join("net/mpls/conf/eth0/input"),
        ];
        for f in &files {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        // Root ignores file modes: nothing to assert then.
        if std::fs::OpenOptions::new()
            .write(true)
            .open(&files[0])
            .is_ok()
        {
            return;
        }
        let s = Sysctl::new(t.path());
        let e = s.ensure_platform_labels(1000).unwrap_err().to_string();
        assert!(
            e.contains("net.mpls.platform_labels=1024") && e.contains("--sysctl"),
            "{e}"
        );
        let e = s.ensure_input("eth0").unwrap_err().to_string();
        assert!(e.contains("net.mpls.conf.eth0.input=1"), "{e}");
    }
}
