//! Raw `ICMPv6` socket for `nos-radvd`: bound to one device, filtered to Router
//! Solicitation/Advertisement, hop limit 255 both ways, `IPV6_RECVHOPLIMIT` so the
//! receiver can apply RFC 4861 s6.1 validation. A leaf crate with no NOS
//! dependencies (like `nos-bfd-socket`): every `unsafe` block lives here.
//! Excluded from coverage: only a real kernel exercises it (`nos-e2e radv`).

#![allow(
    unsafe_code,
    reason = "recvmsg cmsg handling, ICMP6_FILTER and AsyncFd registration: socket2 exposes none"
)]

use std::ffi::CString;
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

/// `ICMPv6` Router Solicitation.
pub const ROUTER_SOLICITATION: u8 = 133;
/// `ICMPv6` Router Advertisement.
pub const ROUTER_ADVERTISEMENT: u8 = 134;
/// `ff02::1`, all nodes.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// `ff02::2`, all routers.
pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

const ICMP6_FILTER: libc::c_int = 1;

/// The interface index of `name`, 0 if unknown.
pub fn ifindex(name: &str) -> u32 {
    CString::new(name)
        .ok()
        // SAFETY: a valid NUL-terminated string.
        .map_or(0, |c| unsafe { libc::if_nametoindex(c.as_ptr()) })
}

/// `ENETDOWN`: what a send returns while the link is down.
pub fn is_link_down(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENETDOWN)
}

/// The `ICMP6_FILTER` words (RFC 3542 s3.2): a set bit blocks the type.
/// Passes exactly `ROUTER_SOLICITATION` and `ROUTER_ADVERTISEMENT`.
pub fn filter_words() -> [u32; 8] {
    let mut f = [u32::MAX; 8];
    for t in [ROUTER_SOLICITATION, ROUTER_ADVERTISEMENT] {
        f[usize::from(t >> 5)] &= !(1u32 << (t & 31));
    }
    f
}

fn set_opt<T>(fd: RawFd, level: libc::c_int, opt: libc::c_int, v: &T) -> io::Result<()> {
    // SAFETY: `v` outlives the call and the length is its size.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            std::ptr::from_ref(v).cast(),
            libc::socklen_t::try_from(size_of::<T>()).unwrap_or(0),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One received message: the source, its hop limit (from the cmsg) and the
/// `ICMPv6` message (the kernel strips the IPv6 header).
pub struct Received {
    /// Source address.
    pub src: Ipv6Addr,
    /// Hop limit, `None` if the kernel gave none.
    pub hop_limit: Option<u8>,
    /// The `ICMPv6` message.
    pub data: Vec<u8>,
}

fn recv_one(fd: RawFd, buf: &mut [u8]) -> io::Result<Received> {
    // SAFETY: every pointer handed to recvmsg points into locals that live to
    // the end of the function; the cmsg walk stays inside `msg_controllen`.
    unsafe {
        let mut name: socket2::SockAddrStorage = std::mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut ctrl = [0u64; 32];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&raw mut name).cast();
        msg.msg_namelen =
            libc::socklen_t::try_from(size_of::<socket2::SockAddrStorage>()).unwrap_or(128);
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&ctrl) as _;
        let n = libc::recvmsg(fd, &raw mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let src = SockAddr::new(name, msg.msg_namelen)
            .as_socket_ipv6()
            .map(|s| *s.ip())
            .ok_or_else(|| io::Error::other("datagram without an IPv6 source"))?;
        let mut hop_limit = None;
        let mut c = libc::CMSG_FIRSTHDR(&raw const msg);
        while !c.is_null() {
            let h = &*c;
            if h.cmsg_level == libc::IPPROTO_IPV6 && h.cmsg_type == libc::IPV6_HOPLIMIT {
                let v = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::c_int>());
                hop_limit = u8::try_from(v).ok();
            }
            c = libc::CMSG_NXTHDR(&raw const msg, c);
        }
        let len = usize::try_from(n).unwrap_or(0).min(buf.len());
        Ok(Received {
            src,
            hop_limit,
            data: buf[..len].to_vec(),
        })
    }
}

/// A raw `ICMPv6` socket on one device, joined to `ff02::2`.
pub struct RaSocket {
    inner: AsyncFd<Socket>,
    ifindex: u32,
}

impl RaSocket {
    /// Opens the socket on `interface`; fails if the device does not exist.
    pub fn open(interface: &str) -> io::Result<Self> {
        let ifindex = ifindex(interface);
        if ifindex == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no such interface {interface}"),
            ));
        }
        let s = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        s.bind_device(Some(interface.as_bytes()))?;
        let fd = s.as_raw_fd();
        set_opt(fd, libc::IPPROTO_ICMPV6, ICMP6_FILTER, &filter_words())?;
        s.set_multicast_hops_v6(255)?;
        s.set_unicast_hops_v6(255)?;
        s.set_multicast_loop_v6(false)?;
        set_opt(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, &1i32)?;
        set_opt(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, &1i32)?;
        s.join_multicast_v6(&ALL_ROUTERS, ifindex)?;
        s.set_nonblocking(true)?;
        // SAFETY: `s` is an owning socket2::Socket: its fd stays open and
        // unchanged until it drops with the AsyncFd.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- AsyncFd::register contract above
        let inner = unsafe { AsyncFd::register(s) }.map_err(io::Error::from)?;
        Ok(Self { inner, ifindex })
    }

    /// Sends `pkt` (an `ICMPv6` message) to `dst` out of this device.
    pub fn send_to(&self, dst: Ipv6Addr, pkt: &[u8]) -> io::Result<()> {
        let addr = SockAddr::from(SocketAddrV6::new(dst, 0, 0, self.ifindex));
        self.inner.get_ref().send_to(pkt, &addr).map(|_| ())
    }

    /// Waits for the next RS/RA.
    pub async fn recv(&self) -> io::Result<Received> {
        let mut buf = [0u8; 2048];
        loop {
            let mut guard = self.inner.readable().await?;
            if let Ok(r) = guard.try_io(|fd| recv_one(fd.get_ref().as_raw_fd(), &mut buf)) {
                return r;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_passes_only_133_and_134() {
        let f = filter_words();
        let blocked = |t: u8| f[usize::from(t >> 5)] & (1 << (t & 31)) != 0;
        assert!(!blocked(133) && !blocked(134));
        assert!(blocked(0) && blocked(128) && blocked(135) && blocked(255));
    }

    #[test]
    fn unknown_interface_is_not_found() {
        assert_eq!(ifindex("nos-no-such0"), 0);
        let e = RaSocket::open("nos-no-such0").err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }
}
