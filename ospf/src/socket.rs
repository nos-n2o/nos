//! Raw protocol-89 (OSPF) socket, bound via `SO_BINDTODEVICE` to this
//! link's own real L3 interface — the same mechanism `bgp/src/tcp.rs` uses
//! for TCP, but scoped to the specific interface (subinterface, or a
//! `BroadcastDomain`'s bridge/SVI), not the shared VRF device, since OSPF
//! has no transport layer of its own. Joins the `AllSPFRouters` (224.0.0.5)
//! multicast group on the link's own local address, since RFC 2328 Hello is
//! always multicast, point-to-point links included (see `docs/protocols/ospf-internals.md`).
//!
//! # Why the specific interface, not the VRF
//! TCP's own VRF-wide bind (`bgp/src/tcp.rs`) is safe because a TCP socket
//! demultiplexes by the full 4-tuple regardless of which slave interface a
//! SYN arrived on. A raw IP socket has no such demux: binding to the VRF
//! device receives every OSPF packet from *every* interface enslaved to
//! that VRF, so two links sharing one VRF (e.g. a point-to-point
//! subinterface and a broadcast domain's SVI on the same router) would each
//! see the other's DBD/LSR/LSU traffic too — harmless for Hello (fully
//! idempotent to a stray copy), but not for the stateful sequence-number/
//! master-slave exchange, where a stray packet meant for the other link
//! reads as corruption and forces a spurious restart. Binding directly to
//! the enslaved interface still sends/receives correctly within that
//! interface's VRF (Linux's VRF driver applies L3 rules per-device,
//! independent of which device a socket names in `SO_BINDTODEVICE`), while
//! scoping reception to just this link.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;

use nix::sys::socket::{recv, MsgFlags};
use nos_ospf_common::exchange::{truncated, RECV_BUF_LEN};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tracing::warn;

/// Registers `fd` with the tokio reactor. `AsyncFd::new` is deprecated
/// (RUSTSEC-2026-0386): registering is `unsafe`, as the fd must stay open and
/// keep the same raw fd for the `AsyncFd`'s life.
#[allow(
    unsafe_code,
    reason = "socket2::Socket owns its fd for the AsyncFd's life"
)]
fn register_fd<T: std::os::fd::AsRawFd>(fd: T) -> io::Result<AsyncFd<T>> {
    // SAFETY: callers pass an owning `socket2::Socket`, which keeps its fd
    // open and unchanged until it is dropped with the `AsyncFd`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- AsyncFd::register contract above
    unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)
}

pub const OSPF_IP_PROTO: i32 = 89;
pub const ALL_SPF_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);

/// A raw protocol-89 socket bound to one specific L3 interface and joined
/// to 224.0.0.5 on that interface's local address — one per OSPF link.
pub struct OspfSocket {
    inner: AsyncFd<Socket>,
    local_addr: Ipv4Addr,
    /// 224.0.0.6 membership, driven by the election outcome (`link::rx::sync_all_drouters`).
    drouters: nos_ospf_common::drouters::AllDRouters,
}

impl OspfSocket {
    /// Opens the socket, scopes it to `interface` (this link's own kernel
    /// device — see `link::LinkConfig::kernel_interface`), and joins
    /// 224.0.0.5 on the interface owning `local_addr`.
    pub fn open(interface: &str, local_addr: Ipv4Addr) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(OSPF_IP_PROTO)))?;
        socket.bind_device(Some(interface.as_bytes()))?;
        socket.join_multicast_v4(&ALL_SPF_ROUTERS, &local_addr)?;
        // A multicast destination has no unicast route in the VRF's FIB, so
        // an outbound send would otherwise fail with `ENETUNREACH` despite
        // `bind_device` — `IP_MULTICAST_IF` picks the egress interface for
        // multicast traffic independently of any route lookup.
        socket.set_multicast_if_v4(&local_addr)?;
        // Linux defaults multicast loopback to on: without disabling it, a
        // router receives its own Hello back and — since nothing else
        // distinguishes it from a real peer's — treats itself as a
        // neighbor, chasing its own DBD negotiation over unicast loopback.
        socket.set_multicast_loop_v4(false)?;
        // Link-local scope only (a virtual link has its own socket, above).
        socket.set_ttl_v4(1)?;
        socket.set_multicast_ttl_v4(1)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: register_fd(socket)?,
            local_addr,
            drouters: nos_ospf_common::drouters::AllDRouters::default(),
        })
    }

    /// Join/leave 224.0.0.6 so membership equals `want`; whether it changed.
    pub fn set_all_drouters(&self, want: bool) -> io::Result<bool> {
        self.drouters.sync(
            self.inner.get_ref(),
            nos_ospf_common::drouters::Iface::V4(self.local_addr),
            want,
        )
    }

    /// A virtual link's socket (RFC 2328 §15): unicast only, so no multicast
    /// group, scoped to the VRF device (the endpoint may be several hops
    /// away, over any transit-area interface) and bound to `local_addr`, so
    /// the kernel only hands it packets addressed to us. That still includes
    /// the transit link's own unicast traffic from the same neighbor (same
    /// addresses); `link::run` drops it by Area ID and source.
    pub fn open_virtual(vrf: &str, local_addr: Ipv4Addr) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(OSPF_IP_PROTO)))?;
        socket.bind_device(Some(vrf.as_bytes()))?;
        socket.bind(&SockAddr::from(SocketAddrV4::new(local_addr, 0)))?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: register_fd(socket)?,
            local_addr,
            drouters: nos_ospf_common::drouters::AllDRouters::default(),
        })
    }

    /// Sends `payload` (an already-encoded OSPF packet, see `crate::packet`)
    /// to 224.0.0.5 — Hello is always multicast, point-to-point links
    /// included (see `docs/protocols/ospf-internals.md`). The kernel fills in the IP header
    /// (no `IP_HDRINCL` set).
    pub fn send_multicast(&self, payload: &[u8]) -> io::Result<()> {
        let dest = SockAddr::from(SocketAddrV4::new(ALL_SPF_ROUTERS, 0));
        self.inner.get_ref().send_to(payload, &dest)?;
        Ok(())
    }

    /// Sends `payload` to 224.0.0.6 (RFC 2328 §13.3/§13.5: a non-DR router's
    /// LSU and delayed `LSAck` on a broadcast link). Same socket options as
    /// `send_multicast`.
    pub fn send_all_drouters(&self, payload: &[u8]) -> io::Result<()> {
        let dest = SockAddr::from(SocketAddrV4::new(
            nos_ospf_common::drouters::ALL_D_ROUTERS_V4,
            0,
        ));
        self.inner.get_ref().send_to(payload, &dest)?;
        Ok(())
    }

    /// Sends `payload` directly to `dest` — DBD/LSR/LSU/LSAck are unicast to
    /// one specific neighbor (RFC 2328 §10.8), unlike Hello.
    pub fn send_unicast(&self, dest: Ipv4Addr, payload: &[u8]) -> io::Result<()> {
        let dest = SockAddr::from(SocketAddrV4::new(dest, 0));
        self.inner.get_ref().send_to(payload, &dest)?;
        Ok(())
    }

    /// Waits for and returns one received OSPF packet's IP source address
    /// and payload, with the IP header already stripped. The source address
    /// is what DBD/LSR/LSU/LSAck unicast replies target — Hello's own
    /// neighbor identity still comes from its body's router-id field (see
    /// `crate::packet::HelloPacket`), not this.
    ///
    /// Raw IPv4 sockets on Linux always deliver the IP header on receive,
    /// even without `IP_HDRINCL` — the IHL nibble in the first header byte
    /// gives the header's real length (it may carry options, so it isn't
    /// always the minimum 20 bytes), and the source address always sits at
    /// a fixed offset (bytes 12..16) regardless of options.
    pub async fn recv_packet(&self) -> io::Result<(Ipv4Addr, Vec<u8>)> {
        // Heap, once per call: 64 KB is too big for the async loop's stack.
        let mut buf = vec![0u8; RECV_BUF_LEN];
        loop {
            let mut guard = self.inner.readable().await?;
            // `MSG_TRUNC`: the return value is the datagram's real length.
            let fd = self.inner.get_ref().as_raw_fd();
            match guard.try_io(|_| recv(fd, &mut buf, MsgFlags::MSG_TRUNC).map_err(io::Error::from))
            {
                Ok(Ok(n)) => {
                    if n == 0 {
                        continue;
                    }
                    if truncated(n, RECV_BUF_LEN) {
                        warn!(bytes = n, "ospf packet truncated, dropped");
                        continue;
                    }
                    let ihl = usize::from(buf[0] & 0x0f) * 4;
                    if ihl < 20 || n < ihl {
                        continue;
                    }
                    let source = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                    return Ok((source, buf[ihl..n].to_vec()));
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }
}

impl AsRawFd for OspfSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}
