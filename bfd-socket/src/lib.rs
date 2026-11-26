//! Raw-libc UDP FFI for `nos-bfd`: `recvmsg`/`sendmsg` with TTL and `IP_PKTINFO` ancillary
//! data, `setsockopt`, `if_nametoindex`. std and socket2 expose none of these. A leaf
//! crate with no NOS dependencies (like `nos-l2-socket`): every `unsafe` block lives here.

#![allow(
    unsafe_code,
    reason = "recvmsg/sendmsg cmsg handling and setsockopt: std and socket2 expose no TTL/pktinfo ancillary data"
)]

use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;

use socket2::SockAddr;

/// The name of interface `index`, `None` if it is gone.
pub fn ifname(index: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buf` is IF_NAMESIZE bytes, as if_indextoname requires.
    let r = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if r.is_null() {
        return None;
    }
    // SAFETY: on success the buffer holds a NUL-terminated name.
    let c = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    c.to_str().ok().map(str::to_owned)
}

/// The interface index of `name`, 0 if unknown.
pub fn ifindex(name: &str) -> u32 {
    CString::new(name)
        .ok()
        // SAFETY: a valid NUL-terminated string.
        .map_or(0, |c| unsafe { libc::if_nametoindex(c.as_ptr()) })
}

/// `setsockopt(fd, level, opt, v)` with an int value.
pub fn set_int(fd: RawFd, level: libc::c_int, opt: libc::c_int, v: libc::c_int) -> io::Result<()> {
    // SAFETY: `v` outlives the call and the length is its size.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            (&raw const v).cast(),
            libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or(4),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One datagram: its source, TTL/hop limit and, when `IP_PKTINFO` /
/// `IPV6_RECVPKTINFO` is on, the arrival interface index and the address it
/// was sent to (the kernel's own, in a VRF possibly the VRF device's index).
pub struct Datagram {
    pub src: IpAddr,
    pub ttl: Option<u8>,
    pub len: usize,
    pub ifindex: u32,
    pub dst: Option<IpAddr>,
}

/// The `(destination, ifindex)` of an `IP_PKTINFO`/`IPV6_PKTINFO` cmsg.
///
/// # Safety
/// `c` must point to a valid cmsg header inside a received message.
unsafe fn pktinfo(c: *const libc::cmsghdr) -> Option<(IpAddr, u32)> {
    // SAFETY: the caller's contract; the data is a pktinfo of the matching type.
    unsafe {
        let h = &*c;
        if h.cmsg_level == libc::IPPROTO_IP && h.cmsg_type == libc::IP_PKTINFO {
            let i = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::in_pktinfo>());
            let a = IpAddr::V4(Ipv4Addr::from(u32::from_be(i.ipi_addr.s_addr)));
            Some((a, u32::try_from(i.ipi_ifindex).unwrap_or(0)))
        } else if h.cmsg_level == libc::IPPROTO_IPV6 && h.cmsg_type == libc::IPV6_PKTINFO {
            let i = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::in6_pktinfo>());
            Some((
                IpAddr::V6(Ipv6Addr::from(i.ipi6_addr.s6_addr)),
                i.ipi6_ifindex,
            ))
        } else {
            None
        }
    }
}

pub fn recv_one(fd: RawFd, buf: &mut [u8]) -> io::Result<Datagram> {
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
            .as_socket()
            .map(|s| s.ip())
            .ok_or_else(|| io::Error::other("datagram without an IP source"))?;
        let mut ttl = None;
        let (mut dst, mut ifindex) = (None, 0);
        let mut c = libc::CMSG_FIRSTHDR(&raw const msg);
        while !c.is_null() {
            let h = &*c;
            if let Some((a, i)) = pktinfo(c) {
                (dst, ifindex) = (Some(a), i);
            }
            let is_ttl = (h.cmsg_level == libc::IPPROTO_IP && h.cmsg_type == libc::IP_TTL)
                || (h.cmsg_level == libc::IPPROTO_IPV6 && h.cmsg_type == libc::IPV6_HOPLIMIT);
            if is_ttl {
                let v = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::c_int>());
                ttl = u8::try_from(v).ok();
            }
            c = libc::CMSG_NXTHDR(&raw const msg, c);
        }
        Ok(Datagram {
            src,
            ttl,
            len: usize::try_from(n).unwrap_or(0),
            ifindex,
            dst,
        })
    }
}

/// One datagram for the reflector: who sent it, which of our addresses it
/// was sent to (`IP_PKTINFO`), and the raw sender address to answer to.
pub struct Probe {
    pub src: SocketAddr,
    pub dst: IpAddr,
    pub name: SockAddr,
    pub len: usize,
}

pub fn recv_probe(fd: RawFd, buf: &mut [u8]) -> io::Result<Probe> {
    // SAFETY: as `recv_one`: every pointer is to a local that outlives the
    // call, the cmsg walk stays inside `msg_controllen`.
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
        let name = SockAddr::new(name, msg.msg_namelen);
        let src = name
            .as_socket()
            .ok_or_else(|| io::Error::other("datagram without an IP source"))?;
        let mut dst = if src.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let mut c = libc::CMSG_FIRSTHDR(&raw const msg);
        while !c.is_null() {
            if let Some((a, _)) = pktinfo(c) {
                dst = a;
            }
            c = libc::CMSG_NXTHDR(&raw const msg, c);
        }
        Ok(Probe {
            src,
            dst,
            name,
            len: usize::try_from(n).unwrap_or(0),
        })
    }
}

/// Sends `data` to `to` with `from` as the IP source (`IP_PKTINFO`'s
/// `ipi_spec_dst`): RFC 7881 §6.1 answers from the address that was probed,
/// which a wildcard-bound socket would not otherwise pick.
pub fn send_from(fd: RawFd, to: &SockAddr, from: Option<IpAddr>, data: &[u8]) -> io::Result<()> {
    // SAFETY: the buffers outlive the call; the control message is built with
    // the `CMSG_*` macros inside a buffer larger than `CMSG_SPACE` of either.
    unsafe {
        let mut ctrl = [0u64; 8];
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = to.as_ptr().cast_mut().cast();
        msg.msg_namelen = to.len();
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        if let Some(from) = from {
            msg.msg_control = ctrl.as_mut_ptr().cast();
            let (level, kind, size) = match from {
                IpAddr::V4(_) => (
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    size_of::<libc::in_pktinfo>(),
                ),
                IpAddr::V6(_) => (
                    libc::IPPROTO_IPV6,
                    libc::IPV6_PKTINFO,
                    size_of::<libc::in6_pktinfo>(),
                ),
            };
            let size = u32::try_from(size).unwrap_or(0);
            msg.msg_controllen = libc::CMSG_SPACE(size) as _;
            let h = libc::CMSG_FIRSTHDR(&raw const msg);
            (*h).cmsg_level = level;
            (*h).cmsg_type = kind;
            (*h).cmsg_len = libc::CMSG_LEN(size) as _;
            match from {
                IpAddr::V4(a) => {
                    let mut i: libc::in_pktinfo = std::mem::zeroed();
                    i.ipi_spec_dst.s_addr = u32::from(a).to_be();
                    std::ptr::write_unaligned(libc::CMSG_DATA(h).cast(), i);
                }
                IpAddr::V6(a) => {
                    let mut i: libc::in6_pktinfo = std::mem::zeroed();
                    i.ipi6_addr.s6_addr = a.octets();
                    std::ptr::write_unaligned(libc::CMSG_DATA(h).cast(), i);
                }
            }
        }
        if libc::sendmsg(fd, &raw const msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
