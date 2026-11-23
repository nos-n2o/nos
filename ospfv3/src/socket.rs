//! Raw protocol-89 (OSPF) socket over IPv6, bound via `SO_BINDTODEVICE` to
//! this link's own real L3 interface — the IPv6 counterpart of
//! `ospf::socket`. Joins the `AllSPFRouters` (`FF02::5`) multicast group on
//! the link's own interface, since RFC 5340 Hello is always multicast,
//! point-to-point links included, exactly like RFC 2328.
//!
//! # Why the specific interface, not the VRF
//! Identical reasoning to `ospf::socket`'s own doc comment: a raw IP socket
//! has no 4-tuple demux, so binding to the VRF device would also receive
//! every *other* `OSPFv3` link's traffic in the same VRF, corrupting each
//! link's own DBD/LSR/LSU sequence-number/role state. Binding directly to
//! the enslaved interface still sends/receives correctly within that
//! interface's VRF (Linux's VRF driver applies L3 rules per-device,
//! independent of what `SO_BINDTODEVICE` names).
//!
//! # Checksum — the one real mechanical difference from `ospf::socket`
//! RFC 5340's packet checksum (§A.3.1) is the standard IPv6 upper-layer
//! checksum (a pseudo-header sum, like UDP/TCP/ICMPv6), not v2's bare RFC
//! 1071 sum — see `packet.rs`'s own doc comment for why this module, not
//! that one, is the right place to handle it: `IPV6_CHECKSUM` (`IPPROTO_
//! IPV6` level), set once at socket-open time with the checksum field's
//! byte offset in the `OSPFv3` header (12), makes the kernel fill it in on
//! send and verify it (silently dropping bad packets) on receive — the same
//! mechanism Linux already uses for `ICMPv6` raw sockets. `socket2` doesn't
//! wrap this option directly, so it's set via `nos_tcp_auth::set_ipv6_checksum`
//! (the same raw-`setsockopt` helper `set_max_hops` uses, not reimplemented
//! here). **Not set on an authenticated link**: RFC 7166
//! §2.2/§4.2 omit the checksum entirely when the authentication trailer is
//! in use (the field stays 0 and the digest covers the packet instead), so
//! the kernel must neither fill it in on send nor verify it on receive.
//!
//! # Signing (RFC 7166)
//! An authenticated socket appends the trailer to every packet it sends
//! (`packet::TrailerAuth::sign`) — the trailer wraps an already-encoded
//! packet, so this is the one place every send path already funnels
//! through, and the strictly increasing sequence number lives here with it
//! (RFC 7166 §4.1: the high 32 bits are a persisted boot count, taken fresh
//! on every link (re)start, the low 32 bits count packets — strictly
//! increasing across cold restarts, see `initial_seq`). Verification stays in `link.rs`, next to the
//! per-neighbor anti-replay state it feeds.
//!
//! # No manual header strip (the other real difference)
//! `ospf::socket::recv_packet` manually strips the IPv4 header raw IPv4
//! sockets always deliver on receive. Linux IPv6 raw sockets don't do this —
//! `recv_from` already returns just the upper-layer payload — so there's
//! nothing to strip here at all.

use std::borrow::Cow;
use std::io::{self, IoSliceMut};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};

use nix::sys::socket::{recvmsg, MsgFlags, SockaddrIn6};
use nos_ospf_common::exchange::{truncated, RECV_BUF_LEN};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tracing::warn;

use crate::packet::{self, TrailerAuth};

/// Registers `fd` with the tokio reactor. `AsyncFd::new` is deprecated
/// (RUSTSEC-2026-0386): registering is `unsafe`, as the fd must stay open and
/// keep the same raw fd for the `AsyncFd`'s life.
#[allow(
    unsafe_code,
    reason = "socket2::Socket owns its fd for the AsyncFd's life"
)]
fn register_fd<T: AsRawFd>(fd: T) -> io::Result<AsyncFd<T>> {
    // SAFETY: callers pass an owning `socket2::Socket`, which keeps its fd
    // open and unchanged until it is dropped with the `AsyncFd`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- AsyncFd::register contract above
    unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)
}

pub const OSPF_IP_PROTO: i32 = 89;
pub const ALL_SPF_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5);

/// Byte offset of the `Checksum` field within the `OSPFv3` common header
/// (§A.3.1: Version/Type/Length(4) + Router ID(4) + Area ID(4) = 12 bytes
/// precede it) — see the module doc comment.
const CHECKSUM_OFFSET: libc::c_int = 12;

/// A raw protocol-89 IPv6 socket bound to one specific L3 interface and
/// joined to `FF02::5` on it — one per `OSPFv3` link.
pub struct OspfSocket {
    inner: AsyncFd<Socket>,
    /// RFC 7166 signing state: the link's keys, the link-local address the
    /// packets leave from (bound into the digest via `Apad`), and the
    /// outgoing sequence number.
    auth: Option<(TrailerAuth, Ipv6Addr, AtomicU64)>,
    /// RFC 5340 §A.3.1 Instance ID stamped into every packet sent.
    instance_id: u8,
    /// `FF02::6` membership, driven by the election outcome (`link::run_election`).
    drouters: nos_ospf_common::drouters::AllDRouters,
    /// A virtual link's far end (`open_virtual`): every send, Hello
    /// included, is unicast there with no scope id.
    virtual_dest: Option<Ipv6Addr>,
}

/// RFC 5340 §4.4.3.1: a virtual link's packets cross routers, so unlike
/// every other send they leave with a hop limit above 1.
pub const VIRTUAL_HOP_LIMIT: u32 = 64;

/// RFC 7166 §4.1's starting outgoing sequence number: the boot count in the
/// high 32 bits, zero below.
fn initial_seq(boot_count: u32) -> u64 {
    u64::from(boot_count) << 32
}

impl OspfSocket {
    /// Opens the socket, scopes it to `interface` (this link's own kernel
    /// device), and joins `FF02::5` on it. `auth` (keys plus the link's own
    /// link-local source address) makes it sign every packet it sends — and
    /// skips the kernel checksum, per RFC 7166 §2.2/§4.2 (see the module
    /// doc comment). Every packet sent carries `instance_id`.
    pub fn open(
        interface: &str,
        ifindex: u32,
        auth: Option<(TrailerAuth, Ipv6Addr)>,
        instance_id: u8,
        boot_count: u32,
    ) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::from(OSPF_IP_PROTO)))?;
        socket.bind_device(Some(interface.as_bytes()))?;
        socket.join_multicast_v6(&ALL_SPF_ROUTERS, ifindex)?;
        // Linux defaults multicast loopback to on — without disabling it, a
        // router would receive its own Hello back and treat itself as a
        // neighbor (identical reasoning to `ospf::socket`'s own note).
        socket.set_multicast_loop_v6(false)?;
        if auth.is_none() {
            nos_tcp_auth::set_ipv6_checksum(socket.as_raw_fd(), CHECKSUM_OFFSET)?;
        }
        // Link-local scope only (a virtual link has its own socket, below).
        socket.set_unicast_hops_v6(1)?;
        socket.set_multicast_hops_v6(1)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: register_fd(socket)?,
            auth: auth
                .map(|(keys, source)| (keys, source, AtomicU64::new(initial_seq(boot_count)))),
            instance_id,
            drouters: nos_ospf_common::drouters::AllDRouters::default(),
            virtual_dest: None,
        })
    }

    /// A virtual link's socket (RFC 5340 §4.4.3.1): unicast only, so no
    /// multicast group, scoped to the VRF device (the endpoint is several
    /// hops away, over any transit-area interface) and bound to `local`, so
    /// the kernel only hands it packets addressed to us. Sends go to `dest`
    /// with hop limit `VIRTUAL_HOP_LIMIT`; `auth` and `instance_id` as in
    /// `open`.
    pub fn open_virtual(
        vrf: &str,
        local: Ipv6Addr,
        dest: Ipv6Addr,
        auth: Option<(TrailerAuth, Ipv6Addr)>,
        instance_id: u8,
        boot_count: u32,
    ) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::from(OSPF_IP_PROTO)))?;
        socket.bind_device(Some(vrf.as_bytes()))?;
        socket.bind(&SockAddr::from(SocketAddrV6::new(local, 0, 0, 0)))?;
        if auth.is_none() {
            nos_tcp_auth::set_ipv6_checksum(socket.as_raw_fd(), CHECKSUM_OFFSET)?;
        }
        socket.set_unicast_hops_v6(VIRTUAL_HOP_LIMIT)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: register_fd(socket)?,
            auth: auth
                .map(|(keys, source)| (keys, source, AtomicU64::new(initial_seq(boot_count)))),
            instance_id,
            drouters: nos_ospf_common::drouters::AllDRouters::default(),
            virtual_dest: Some(dest),
        })
    }

    /// Where a send to `dest` on `ifindex` really goes: a virtual link's one
    /// unicast peer, scope-less.
    fn target(&self, dest: Ipv6Addr, ifindex: u32) -> SockAddr {
        match self.virtual_dest {
            Some(far) => SockAddr::from(SocketAddrV6::new(far, 0, 0, 0)),
            None => SockAddr::from(SocketAddrV6::new(dest, 0, 0, ifindex)),
        }
    }

    /// Join/leave `FF02::6` so membership equals `want`; whether it changed.
    pub fn set_all_drouters(&self, ifindex: u32, want: bool) -> io::Result<bool> {
        self.drouters.sync(
            self.inner.get_ref(),
            nos_ospf_common::drouters::Iface::V6(ifindex),
            want,
        )
    }

    /// `payload` with the link's Instance ID stamped in and, when
    /// authenticated, the RFC 7166 trailer appended (after the stamp: the
    /// digest covers the header) — the sequence number is one past the
    /// previous send, starting from `boot_count << 32`.
    fn signed<'a>(&self, payload: &'a [u8]) -> Cow<'a, [u8]> {
        if self.auth.is_none() && self.instance_id == 0 {
            return Cow::Borrowed(payload);
        }
        let mut packet = payload.to_vec();
        packet::set_instance_id(&mut packet, self.instance_id);
        if let Some((keys, source, seq)) = &self.auth {
            let next = seq.fetch_add(1, Ordering::SeqCst).saturating_add(1);
            keys.sign(&mut packet, next, *source);
        }
        Cow::Owned(packet)
    }

    /// Sends `payload` (an already-encoded `OSPFv3` packet, see
    /// `crate::packet`) to `FF02::5` — Hello is always multicast, including
    /// on point-to-point links.
    pub fn send_multicast(&self, ifindex: u32, payload: &[u8]) -> io::Result<()> {
        let dest = self.target(ALL_SPF_ROUTERS, ifindex);
        self.inner.get_ref().send_to(&self.signed(payload), &dest)?;
        Ok(())
    }

    /// Sends `payload` to `FF02::6` (RFC 2328 §13.3/§13.5 via RFC 5340 §4.5:
    /// a non-DR router's LSU and delayed `LSAck` on a broadcast link). Signed
    /// like every send; the trailer binds only the source, so one packet is
    /// valid for every receiver.
    pub fn send_all_drouters(&self, ifindex: u32, payload: &[u8]) -> io::Result<()> {
        let dest = self.target(nos_ospf_common::drouters::ALL_D_ROUTERS_V6, ifindex);
        self.inner.get_ref().send_to(&self.signed(payload), &dest)?;
        Ok(())
    }

    /// Sends `payload` directly to `dest` — DBD/LSR/LSU/LSAck are unicast to
    /// one specific neighbor's link-local address, unlike Hello.
    pub fn send_unicast(&self, dest: Ipv6Addr, ifindex: u32, payload: &[u8]) -> io::Result<()> {
        let dest = self.target(dest, ifindex);
        self.inner.get_ref().send_to(&self.signed(payload), &dest)?;
        Ok(())
    }

    /// Waits for and returns one received `OSPFv3` packet's source link-local
    /// address and payload. Unlike `ospf::socket::recv_packet`, there is no
    /// IP header to strip — see the module doc comment — but the source
    /// address (needed for DBD/LSR/LSU/LSAck's unicast replies, and to
    /// identify which neighbor a Hello came from) has to come from
    /// `recv_from` itself rather than a stripped header.
    pub async fn recv_packet(&self) -> io::Result<(Ipv6Addr, Vec<u8>)> {
        // Heap, once per call: 64 KB is too big for the async loop's stack.
        let mut buf = vec![0u8; RECV_BUF_LEN];
        loop {
            let mut guard = self.inner.readable().await?;
            let fd = self.inner.get_ref().as_raw_fd();
            // `MSG_TRUNC`: `bytes` is the datagram's real length.
            let io_result = guard.try_io(|_| {
                let mut iov = [IoSliceMut::new(&mut buf)];
                recvmsg::<SockaddrIn6>(fd, &mut iov, None, MsgFlags::MSG_TRUNC)
                    .map(|m| (m.bytes, m.address))
                    .map_err(io::Error::from)
            });
            match io_result {
                Ok(Ok((n, addr))) => {
                    if n == 0 {
                        continue;
                    }
                    if truncated(n, RECV_BUF_LEN) {
                        warn!(bytes = n, "ospfv3 packet truncated, dropped");
                        continue;
                    }
                    let Some(source) = addr.map(|a| a.ip()) else {
                        continue;
                    };
                    return Ok((source, buf[..n].to_vec()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_is_boot_count_in_the_high_half_and_increases_across_reopen() {
        assert_eq!(initial_seq(0), 0);
        assert_eq!(initial_seq(3), 3 << 32);
        // A reopened socket (higher boot count) starts above anything the
        // old one could send within its 32-bit low half.
        let old_last = initial_seq(3) + u64::from(u32::MAX);
        assert!(initial_seq(4) > old_last);
    }
}
