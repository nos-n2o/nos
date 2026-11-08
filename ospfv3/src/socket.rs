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
//! (seeded from wall-clock unix-seconds and floored there on every bump, so
//! it never regresses across a link restart — `ospf::link`'s classic
//! `AuType` 2 scheme). Verification stays in `link.rs`, next to the
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
use std::time::{SystemTime, UNIX_EPOCH};

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
}

/// Wall-clock floor for the outgoing sequence number — mirrors
/// `ospf::link::crypto_seq_floor`.
fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
        // Link-local scope only (conventional; no virtual links here).
        socket.set_unicast_hops_v6(1)?;
        socket.set_multicast_hops_v6(1)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: register_fd(socket)?,
            auth: auth.map(|(keys, source)| (keys, source, AtomicU64::new(unix_secs()))),
            instance_id,
            drouters: nos_ospf_common::drouters::AllDRouters::default(),
        })
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
    /// previous send or the current wall-clock second, whichever is larger.
    fn signed<'a>(&self, payload: &'a [u8]) -> Cow<'a, [u8]> {
        if self.auth.is_none() && self.instance_id == 0 {
            return Cow::Borrowed(payload);
        }
        let mut packet = payload.to_vec();
        packet::set_instance_id(&mut packet, self.instance_id);
        if let Some((keys, source, seq)) = &self.auth {
            let floor = unix_secs();
            let next = |prev: u64| prev.saturating_add(1).max(floor);
            let prev = seq
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |p| Some(next(p)))
                .unwrap_or(0);
            keys.sign(&mut packet, next(prev), *source);
        }
        Cow::Owned(packet)
    }

    /// Sends `payload` (an already-encoded `OSPFv3` packet, see
    /// `crate::packet`) to `FF02::5` — Hello is always multicast, including
    /// on point-to-point links.
    pub fn send_multicast(&self, ifindex: u32, payload: &[u8]) -> io::Result<()> {
        let dest = SockAddr::from(SocketAddrV6::new(ALL_SPF_ROUTERS, 0, 0, ifindex));
        self.inner.get_ref().send_to(&self.signed(payload), &dest)?;
        Ok(())
    }

    /// Sends `payload` to `FF02::6` (RFC 2328 §13.3/§13.5 via RFC 5340 §4.5:
    /// a non-DR router's LSU and delayed `LSAck` on a broadcast link). Signed
    /// like every send; the trailer binds only the source, so one packet is
    /// valid for every receiver.
    pub fn send_all_drouters(&self, ifindex: u32, payload: &[u8]) -> io::Result<()> {
        let dest = SockAddr::from(SocketAddrV6::new(
            nos_ospf_common::drouters::ALL_D_ROUTERS_V6,
            0,
            0,
            ifindex,
        ));
        self.inner.get_ref().send_to(&self.signed(payload), &dest)?;
        Ok(())
    }

    /// Sends `payload` directly to `dest` — DBD/LSR/LSU/LSAck are unicast to
    /// one specific neighbor's link-local address, unlike Hello.
    pub fn send_unicast(&self, dest: Ipv6Addr, ifindex: u32, payload: &[u8]) -> io::Result<()> {
        let dest = SockAddr::from(SocketAddrV6::new(dest, 0, 0, ifindex));
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
