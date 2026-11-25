use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::mpsc;

pub mod linux;
mod nexthop;
pub mod noop;

pub use linux::LinuxFdbDriver;
pub use noop::NoopFdbDriver;

pub type Mac = [u8; 6];

/// UDP port every VXLAN device here uses (RFC 7348's IANA port).
pub const VXLAN_PORT: u16 = 4789;

/// Shared with `nos-ribd`'s L3 VNI devices: one VXLAN device name per VNI.
pub use nos_proto::evpn_id::vxlan_name;

/// Errors from applying state to a real (or simulated) backend — never fatal
/// to the daemon: every call site logs and the next tick retries.
#[derive(Debug, Error)]
pub enum DriverError {
    #[error("netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),
    #[error("{0}")]
    Other(String),
}

/// Applies one broadcast domain's EVPN state to the OS. Every method is
/// idempotent; callers pass what they want and never diff against the kernel.
#[async_trait]
pub trait FdbDriver: Send + Sync {
    /// Ensures `vx<vni>` exists with this VNI, local VTEP address and
    /// `underlay` device (the one carrying `vtep` — required to bind the UDP
    /// socket when that address lives in a VRF), has learning off, and is
    /// enslaved to (and up under) `bridge`. A device with a different
    /// VNI/address/underlay is recreated. `Err` also when `bridge` or
    /// `underlay` doesn't exist yet — the caller retries next tick.
    /// `neigh_suppress` is the port's `IFLA_BRPORT_NEIGH_SUPPRESS` (ARP/ND
    /// suppression), set or cleared to match.
    async fn ensure_vxlan(
        &self,
        vni: u32,
        vtep: IpAddr,
        underlay: &str,
        bridge: &str,
        neigh_suppress: bool,
    ) -> Result<(), DriverError>;

    /// Deletes `vx<vni>` (and with it every FDB entry on it). No-op if absent.
    async fn remove_vxlan(&self, vni: u32) -> Result<(), DriverError>;

    /// A remote MAC reachable via `vtep`, marked `extern_learn` so the kernel
    /// neither ages nor relearns it.
    async fn set_remote_mac(&self, vni: u32, mac: Mac, vtep: IpAddr) -> Result<(), DriverError>;
    async fn del_remote_mac(&self, vni: u32, mac: Mac, vtep: IpAddr) -> Result<(), DriverError>;

    /// A remote MAC reachable through *several* VTEPs, which the kernel
    /// balances by flow hash (an FDB nexthop group): how a MAC on an
    /// all-active Ethernet Segment is aliased over the segment's PEs. The
    /// same `extern_learn` marking as `set_remote_mac`; replaces whatever
    /// entry the MAC had. One address family, the VXLAN device's. Groups and their nexthops are
    /// created as needed and kept until `remove_vxlan`.
    async fn set_remote_mac_group(
        &self,
        vni: u32,
        mac: Mac,
        vteps: &[IpAddr],
    ) -> Result<(), DriverError>;
    /// Removes the entry `set_remote_mac_group` wrote.
    async fn del_remote_mac_group(&self, vni: u32, mac: Mac) -> Result<(), DriverError>;

    /// A remote MAC on one of our own Ethernet Segments, pinned to the
    /// segment's bridge port `port` (a static bridge FDB entry that is never
    /// aged nor moved by the VXLAN side). It tracks activity: it starts
    /// inactive (`active == false`) and the kernel marks it active when the CE
    /// sends through `port` — only then does `local_macs` report it (RFC 7432
    /// §8.4: a PE advertises what it sees locally, never what it was told).
    /// `active` is for pinning over a MAC already learned on `port`.
    async fn set_segment_mac(&self, port: &str, mac: Mac, active: bool) -> Result<(), DriverError>;
    async fn del_segment_mac(&self, port: &str, mac: Mac) -> Result<(), DriverError>;

    /// One head-end-replication flood destination (the all-zero MAC entry).
    async fn add_flood(&self, vni: u32, vtep: IpAddr) -> Result<(), DriverError>;
    async fn del_flood(&self, vni: u32, vtep: IpAddr) -> Result<(), DriverError>;

    /// MACs the bridge learned (or an operator pinned) on its local ports,
    /// each with the name of the port it sits behind: not `extern_learn`, not
    /// on the VXLAN port, not the ports' own (permanent/local) addresses, no
    /// group addresses, and a `set_segment_mac` pin only while it is active.
    async fn local_macs(
        &self,
        bridge: &str,
        vni: u32,
    ) -> Result<BTreeMap<Mac, String>, DriverError>;

    /// Seconds since the kernel last saw a frame from each MAC `local_macs`
    /// reports (`NDA_CACHEINFO` `used`); a MAC without cache info is omitted.
    async fn local_mac_ages(
        &self,
        bridge: &str,
        vni: u32,
    ) -> Result<BTreeMap<Mac, u32>, DriverError>;

    /// Sets the flooding of the bridge port `port`: `unicast` is
    /// unknown-unicast, `bum` multicast and broadcast (`bridge link set ...
    /// flood .. mcast_flood .. bcast_flood ..`). How a non-Designated-Forwarder
    /// PE stops delivering core BUM to an Ethernet Segment. `Err` while the
    /// port doesn't exist (yet).
    async fn set_port_flood(&self, port: &str, unicast: bool, bum: bool)
        -> Result<(), DriverError>;

    /// Local bias, egress half (RFC 8365 §8.3.1, see `tc`): on the segment
    /// port `port`, drop a frame marked as coming from a PE on the segment
    /// whose bit is set in `bit` (one bit per local all-active segment), and,
    /// with `df_filter`, every core-origin BUM frame (a non-DF's rule).
    /// Creates the `clsact` qdisc if needed; idempotent. `Err` while the port
    /// doesn't exist (yet).
    async fn set_segment_filter(
        &self,
        port: &str,
        bit: u16,
        df_filter: bool,
    ) -> Result<(), DriverError>;

    /// Removes what `set_segment_filter` put on `port` (the qdisc stays). Ok
    /// when there is nothing, or no port.
    async fn clear_segment_filter(&self, port: &str) -> Result<(), DriverError>;

    /// Local bias, ingress half: on `vx<vni>`, mark every multi-destination
    /// frame received from one of `peers` (the other PEs of our segments) with
    /// its segment bitmap, and every other one with the magic byte alone, so
    /// a segment port's egress filter can tell them apart. An empty map removes
    /// it all. Idempotent; replaces whatever it wrote before.
    async fn set_local_bias(
        &self,
        vni: u32,
        peers: &BTreeMap<IpAddr, u16>,
    ) -> Result<(), DriverError>;

    /// Puts the bridge port `port` in the `forwarding` or `disabled` STP state
    /// (`bridge link set ... state 3|0`): a disabled port drops every frame in
    /// both directions, unicast included — how a single-active non-DF is kept
    /// off its Ethernet Segment. (Not `blocking`: with the bridge's STP off the
    /// kernel undoes that at once, but leaves a disabled port alone.) `Err`
    /// while the port doesn't exist (yet), or when kernel STP owns the state.
    async fn set_port_forwarding(&self, port: &str, forwarding: bool) -> Result<(), DriverError>;

    /// Whether `port` has carrier (`IFF_LOWER_UP`); `false` while it doesn't
    /// exist. A bond with no live member has none, which is how an Ethernet
    /// Segment is noticed to be down.
    async fn port_up(&self, port: &str) -> Result<bool, DriverError>;

    /// IP-to-MAC bindings (ARP / IPv6 ND) on the bridge itself, i.e. the SVI's
    /// neighbour table: not `extern_learn` (our own `set_neigh` writes — the
    /// loop guard), only usable states, and only `is_advertisable_ip`
    /// addresses.
    async fn local_neighbours(&self, bridge: &str) -> Result<BTreeSet<(Mac, IpAddr)>, DriverError>;

    /// The bridge's own MAC — what an SVI address is originated with.
    async fn bridge_mac(&self, bridge: &str) -> Result<Mac, DriverError>;

    /// A remote host's IP-to-MAC binding on the bridge (the SVI's neighbour
    /// table), marked `extern_learn` so the kernel neither ages nor probes it.
    async fn set_neigh(&self, bridge: &str, mac: Mac, ip: IpAddr) -> Result<(), DriverError>;
    async fn del_neigh(&self, bridge: &str, mac: Mac, ip: IpAddr) -> Result<(), DriverError>;

    /// A wake-up on every kernel neighbour/FDB or link change (the receiver
    /// only signals "look again" — `local_macs`/`port_up` are the source of
    /// truth). `None`
    /// when the backend has no such feed; the caller then relies on its tick.
    fn watch_neigh(&self) -> Option<mpsc::Receiver<()>>;
}

/// Signals a `watch_neigh` receiver. The signal carries no data, so a wake-up
/// already pending absorbs this one (#395: a bounded channel, not an unbounded
/// queue a slow consumer could grow). `false` once the receiver is gone.
pub fn wake(tx: &mpsc::Sender<()>) -> bool {
    !matches!(tx.try_send(()), Err(mpsc::error::TrySendError::Closed(())))
}

/// Whether an address belongs in a Type-2 route: link-local, loopback,
/// multicast and unspecified addresses only ever mean something on one link.
#[must_use]
pub fn is_advertisable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.is_link_local()
                || a.is_broadcast())
        }
        IpAddr::V6(a) => {
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || (a.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Whether a neighbour dump entry is a binding this domain should originate.
/// `usable` = the state carries a resolved MAC (reachable/stale/delay/probe/
/// permanent, not incomplete/failed/none/noarp).
#[must_use]
pub fn is_local_neigh(
    mac: Mac,
    ip: IpAddr,
    usable: bool,
    ext_learned: bool,
    ifindex: u32,
    bridge_ifindex: u32,
) -> bool {
    ifindex == bridge_ifindex
        && usable
        && !ext_learned
        && mac != [0; 6]
        && mac[0] & 1 == 0
        && is_advertisable_ip(ip)
}

/// Whether a bridge FDB dump entry is a MAC this domain should originate.
/// `active` is `Some` for an entry that tracks activity (a `set_segment_mac`
/// pin): only an active one counts. Pure so the rules are testable without a
/// kernel.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn is_local_mac(
    mac: Mac,
    permanent: bool,
    ext_learned: bool,
    active: Option<bool>,
    port_ifindex: u32,
    master: Option<u32>,
    bridge_ifindex: u32,
    vxlan_ifindex: Option<u32>,
) -> bool {
    master == Some(bridge_ifindex)
        && Some(port_ifindex) != vxlan_ifindex
        && !ext_learned
        && active != Some(false)
        && !permanent
        && mac != [0; 6]
        && mac[0] & 1 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: Mac = [0, 0x11, 0x22, 0x33, 0x44, 0x55];

    #[test]
    fn only_dynamic_or_static_entries_on_a_local_port_count() {
        assert!(is_local_mac(M, false, false, None, 5, Some(2), 2, Some(9)));
        // the port's own (permanent) address
        assert!(!is_local_mac(M, true, false, None, 5, Some(2), 2, Some(9)));
        // our own extern_learn write, and anything seen on the vxlan port
        assert!(!is_local_mac(M, false, true, None, 9, Some(2), 2, Some(9)));
        assert!(!is_local_mac(M, false, false, None, 9, Some(2), 2, Some(9)));
        // a segment pin: only once the CE has sent through it
        assert!(!is_local_mac(
            M,
            false,
            false,
            Some(false),
            5,
            Some(2),
            2,
            Some(9)
        ));
        assert!(is_local_mac(
            M,
            false,
            false,
            Some(true),
            5,
            Some(2),
            2,
            Some(9)
        ));
        // another bridge's entry, the flood entry, a group address
        assert!(!is_local_mac(M, false, false, None, 5, Some(3), 2, Some(9)));
        assert!(!is_local_mac(
            [0; 6],
            false,
            false,
            None,
            5,
            Some(2),
            2,
            Some(9)
        ));
        assert!(!is_local_mac(
            [1, 0, 0x5e, 0, 0, 1],
            false,
            false,
            None,
            5,
            Some(2),
            2,
            None
        ));
    }

    #[test]
    fn only_resolved_global_neighbours_on_the_bridge_count() {
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert!(is_local_neigh(M, ip, true, false, 2, 2));
        // our own extern_learn write, an unresolved entry, another device
        assert!(!is_local_neigh(M, ip, true, true, 2, 2));
        assert!(!is_local_neigh(M, ip, false, false, 2, 2));
        assert!(!is_local_neigh(M, ip, true, false, 3, 2));
        assert!(!is_local_neigh([0; 6], ip, true, false, 2, 2));
    }

    #[test]
    fn link_local_and_special_addresses_are_not_advertised() {
        for ip in ["198.51.100.7", "2001:db8::7"] {
            assert!(is_advertisable_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "169.254.1.1",
            "fe80::1",
            "127.0.0.1",
            "::1",
            "224.0.0.1",
            "ff02::1",
            "0.0.0.0",
            "::",
        ] {
            assert!(!is_advertisable_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn wake_ups_collapse_into_one() {
        let (tx, mut rx) = mpsc::channel(1);
        assert!(wake(&tx) && wake(&tx));
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
        drop(rx);
        assert!(!wake(&tx));
    }

    #[test]
    fn vxlan_names_fit_ifnamsiz() {
        assert_eq!(vxlan_name(10100), "vx10100");
        assert!(vxlan_name(0x00ff_ffff).len() <= 15);
    }
}
