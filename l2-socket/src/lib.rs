//! Raw `AF_PACKET`/`SOCK_RAW` socket bound to **one physical interface**,
//! carrying one ethertype to/from one link-local multicast group — the shared
//! transport of `nos-lacp` (slow protocols) and `nos-lldp`. A leaf crate with
//! no NOS dependencies, like `nos-tcp-auth`, so both daemons can use it
//! without depending on each other.
//!
//! `L2Socket::accept_own_unicast` and `open_udp` are the opt-ins of `nos-bfd`'s
//! RFC 7130 micro-BFD (IP/UDP frames to a multicast MAC, also accepted when
//! unicast to our own MAC); LACP/LLDP leave them off.
//!
//! `L2Unicast` is the second type: one interface, one ethertype, frames sent
//! to an explicit neighbour MAC (BFD Echo, RFC 5881 §4: an IP packet addressed
//! to ourselves, looped by the neighbour's forwarding).
//!
//! # Why the specific interface
//! A raw socket has no port/connection concept to demultiplex by — binding
//! wider than the one link a protocol runs on would receive every other
//! link's frames too.
//!
//! # `unsafe` scope
//! `AF_PACKET` needs a `sockaddr_ll` (interface index, not a name) for both
//! `bind` and multicast-group membership, which `socket2` doesn't wrap — this
//! crate is where that raw `libc` socket work lives. So is
//! `ifindex_of_address` (`getifaddrs`), which LLDP's Management Address TLV
//! needs.
#![warn(missing_docs)]

use std::io::{self, Read};
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

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

const ETH_HEADER_LEN: usize = 14;

// Field names deliberately mirror `linux/if_packet.h`'s own `sockaddr_ll`/
// `packet_mreq` exactly, for auditability against the kernel ABI.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

/// `PACKET_ADD_MEMBERSHIP`'s payload (`linux/if_packet.h`'s `packet_mreq`) —
/// used to join the multicast group, since an ordinary NIC otherwise only
/// passes up unicast-to-self/broadcast frames, not an arbitrary multicast
/// destination.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct PacketMreq {
    mr_ifindex: i32,
    mr_type: u16,
    mr_alen: u16,
    mr_address: [u8; 8],
}

const SOL_PACKET: i32 = 263;
const PACKET_ADD_MEMBERSHIP: i32 = 1;
const PACKET_MR_MULTICAST: u16 = 0;

const LINK_DOWN_RETRY: std::time::Duration = std::time::Duration::from_millis(500);

/// A raw `AF_PACKET` socket bound to `ifindex`, receiving `ethertype` only.
///
/// Order matters (#691): a socket created with a non-zero protocol is hooked
/// on *every* device and queues matching frames from all of them until `bind`
/// re-hooks it, and neither `bind` nor a later `SO_ATTACH_FILTER` flushes that
/// queue. So create with protocol 0 (hooked nowhere), attach the filter, and
/// only then `bind` with the ethertype, which hooks it on `ifindex` alone.
fn open_raw(
    ifindex: i32,
    ethertype: u16,
    mut filter: Option<Vec<libc::sock_filter>>,
) -> io::Result<Socket> {
    let socket = Socket::new(
        Domain::from(libc::AF_PACKET),
        Type::RAW,
        Some(Protocol::from(0)),
    )?;
    if let Some(prog) = filter.as_mut() {
        attach_filter(&socket, prog)?;
    }

    // SAFETY: `addr` is a plain, fully-initialized `sockaddr_ll`; `bind`
    // is called with its own correct size, matching the kernel's
    // expectation for this socket family.
    #[allow(unsafe_code)]
    {
        let addr = SockaddrLl {
            sll_family: u16::try_from(libc::AF_PACKET).expect("AF_PACKET always fits u16"),
            sll_protocol: ethertype.to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let ret = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
                libc::socklen_t::try_from(std::mem::size_of::<SockaddrLl>())
                    .expect("fixed, small struct size"),
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(socket)
}

/// The STP/RSTP BPDU group (IEEE 802.1D bridge group address).
pub const BPDU_GROUP: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00];
/// Cisco's PVST+/Rapid-PVST+ group (SSTP, #322).
pub const SSTP_GROUP: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCD];
const ETH_P_ALL: u16 = 0x0003;
/// An 802.3 header, LLC and a BPDU: an MST BPDU with 64 MSTI messages is the
/// longest (14 + 3 + 102 + 64 * 16 = 1143 bytes); 1500 is the 802.3 maximum.
const BPDU_RECV_BUF_LEN: usize = 1536;

/// A raw L2 socket for one ethertype and one multicast group on one interface.
pub struct L2Socket {
    inner: AsyncFd<Socket>,
    interface: String,
    own_hw_addr: [u8; 6],
    ifindex: i32,
    ethertype: u16,
    group: [u8; 6],
    recv_buf_len: usize,
    /// Also accept frames addressed to `own_hw_addr` (RFC 7130 §2.3: a peer
    /// may move micro-BFD to our unicast MAC). Off for LACP/LLDP.
    accept_own_unicast: bool,
}

impl L2Socket {
    /// Opens the socket, restricts it to `interface`'s `ethertype` traffic, and
    /// joins `group` on it. `recv_buf_len` is the largest *frame* (header
    /// included) worth receiving; a longer one is truncated by the kernel.
    pub fn open(
        interface: &str,
        ethertype: u16,
        group: [u8; 6],
        recv_buf_len: usize,
    ) -> io::Result<Self> {
        Self::open_filtered(interface, ethertype, group, recv_buf_len, None)
    }

    /// Like [`Self::open`], but a frame that carried an 802.1Q tag is dropped in
    /// the kernel, even when the NIC/veth offloaded the tag into skb metadata
    /// (invisible in the bytes `read` returns, so it would pass for an untagged
    /// frame of this link). For LACP/LLDP (#690).
    pub fn open_untagged(
        interface: &str,
        ethertype: u16,
        group: [u8; 6],
        recv_buf_len: usize,
    ) -> io::Result<Self> {
        let prog = drop_tagged(vec![ins(0x06, 0, 0, 0xffff)]); // body: accept all
        Self::open_filtered(interface, ethertype, group, recv_buf_len, Some(prog))
    }

    /// Like [`Self::open`], also kernel-filtering received frames to UDP
    /// datagrams for `udp_dst_port` (IPv4 or IPv6 `ethertype` only), so a raw
    /// IP socket does not wake for all the port's other traffic. The filter is
    /// attached before the bind, so no frame ever bypasses it.
    pub fn open_udp(
        interface: &str,
        ethertype: u16,
        group: [u8; 6],
        recv_buf_len: usize,
        udp_dst_port: u16,
    ) -> io::Result<Self> {
        let prog = udp_port_program(ethertype, udp_dst_port)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ethertype is not IP"))?;
        Self::open_filtered(interface, ethertype, group, recv_buf_len, Some(prog))
    }

    fn open_filtered(
        interface: &str,
        ethertype: u16,
        group: [u8; 6],
        recv_buf_len: usize,
        filter: Option<Vec<libc::sock_filter>>,
    ) -> io::Result<Self> {
        let own_hw_addr = read_hw_addr(interface)?;
        let ifindex = if_index(interface)?;

        let socket = open_raw(ifindex, ethertype, filter)?;
        join_multicast(&socket, ifindex, group)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: register_fd(socket)?,
            interface: interface.to_owned(),
            own_hw_addr,
            ifindex,
            ethertype,
            group,
            recv_buf_len,
            accept_own_unicast: false,
        })
    }

    /// Opens the spanning-tree BPDU socket on `interface` (802.3 + LLC `42 42 03`
    /// to [`BPDU_GROUP`]). It is an `ETH_P_ALL` socket on purpose: a protocol
    /// tap sees the frame before tc ingress and the bridge `rx_handler`, where
    /// `nos-interfaced`'s BPDU trap drops it (an `ETH_P_802_2` socket would see
    /// nothing). Use [`Self::send_frame`]/[`Self::recv_frame`]: the frame
    /// carries a length field, not an ethertype.
    pub fn open_bpdu(interface: &str) -> io::Result<Self> {
        Self::open_stp(interface, true, false)
    }

    /// Rapid-PVST+ (#322): the SSTP group (802.3 + LLC/SNAP `AA AA 03`, OUI
    /// `00:00:0c`, PID `0x010b`) and, when `ieee` (the native VLAN), also the
    /// IEEE BPDU group. Like [`Self::open_bpdu`] otherwise.
    pub fn open_pvst(interface: &str, ieee: bool) -> io::Result<Self> {
        Self::open_stp(interface, ieee, true)
    }

    fn open_stp(interface: &str, ieee: bool, sstp: bool) -> io::Result<Self> {
        let own_hw_addr = read_hw_addr(interface)?;
        let ifindex = if_index(interface)?;
        let mut blocks = Vec::new();
        if ieee {
            blocks.push((BPDU_GROUP, [0x42, 0x42, 0x03]));
        }
        if sstp {
            blocks.push((SSTP_GROUP, [0xAA, 0xAA, 0x03]));
        }
        let socket = open_raw(ifindex, ETH_P_ALL, Some(bpdu_program(&blocks, true)))?;
        for (group, _) in &blocks {
            join_multicast(&socket, ifindex, *group)?;
        }
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: register_fd(socket)?,
            interface: interface.to_owned(),
            own_hw_addr,
            ifindex,
            ethertype: ETH_P_ALL,
            group: if sstp { SSTP_GROUP } else { BPDU_GROUP },
            recv_buf_len: BPDU_RECV_BUF_LEN,
            accept_own_unicast: false,
        })
    }

    /// Sends a complete, already-built frame (header included).
    pub fn send_frame(&self, frame: &[u8]) -> io::Result<()> {
        self.inner.get_ref().send(frame)?;
        Ok(())
    }

    /// Waits for the next complete frame, header included, that this port did
    /// not send itself (an `ETH_P_ALL` socket also sees `PACKET_OUTGOING`).
    pub async fn recv_frame(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.recv_buf_len];
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(Ok(n)) => {
                    if n >= ETH_HEADER_LEN
                        && buf[6..12] != self.own_hw_addr
                        && self.ethertype_ok(&buf[..n])
                    {
                        return Ok(buf[..n].to_vec());
                    }
                }
                Ok(Err(e)) if is_link_down(&e) => {
                    if self.is_stale() {
                        return Err(recreated_error());
                    }
                    tokio::time::sleep(LINK_DOWN_RETRY).await;
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }

    /// Whether the netdev this socket was opened on has been recreated: the
    /// name now resolves to another ifindex or MAC, or to nothing. A socket is
    /// bound to an ifindex, so the kernel unhooks it when the netdev is
    /// unregistered (veth deleted, VF removed, driver reload) and it never
    /// sees a frame again. Callers must treat it as fatal for the task and
    /// reopen (the recv paths return a `NotConnected` error once they see it).
    pub fn is_stale(&self) -> bool {
        is_recreated(self.ifindex, if_index(&self.interface).ok())
    }

    /// Whether `frame` carries the bound ethertype. An `AF_PACKET` socket also
    /// delivers VLAN-tagged frames (kernel fallback) whose payload starts
    /// after the tag; those are not ours. An `ETH_P_ALL` socket takes anything.
    fn ethertype_ok(&self, frame: &[u8]) -> bool {
        self.ethertype == ETH_P_ALL || ethertype_matches(frame, self.ethertype)
    }

    /// Also receive frames addressed to this port's own MAC, not just `group`.
    #[must_use]
    pub fn accept_own_unicast(mut self) -> Self {
        self.accept_own_unicast = true;
        self
    }

    /// This port's own real MAC address — this socket's Ethernet source.
    pub fn own_hw_addr(&self) -> [u8; 6] {
        self.own_hw_addr
    }

    /// This port's real kernel interface index.
    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    /// Sends an already-encoded PDU, wrapping it in an Ethernet header
    /// addressed to this socket's multicast group.
    pub fn send(&self, pdu: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(ETH_HEADER_LEN + pdu.len());
        frame.extend_from_slice(&self.group);
        frame.extend_from_slice(&self.own_hw_addr);
        frame.extend_from_slice(&self.ethertype.to_be_bytes());
        frame.extend_from_slice(pdu);
        self.inner.get_ref().send(&frame)?;
        Ok(())
    }

    /// Waits for and returns one received PDU's payload, Ethernet header
    /// already stripped. Frames that are runts, sent by this port itself, or
    /// not addressed to this socket's group are skipped.
    pub async fn recv(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.recv_buf_len];
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(Ok(n)) => {
                    if let Some(payload) = payload_of_foreign_frame(
                        &buf[..n],
                        self.own_hw_addr,
                        self.group,
                        self.accept_own_unicast,
                    ) && self.ethertype_ok(&buf[..n])
                    {
                        return Ok(payload.to_vec());
                    }
                }
                // A link that is administratively down (or just coming up)
                // surfaces as `ENETDOWN` on read — a normal, recoverable
                // state, so wait and retry rather than end the caller's task.
                Ok(Err(e)) if is_link_down(&e) => {
                    if self.is_stale() {
                        return Err(recreated_error());
                    }
                    tokio::time::sleep(LINK_DOWN_RETRY).await;
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }
}

/// A raw L2 socket for one ethertype on one interface, sending to unicast
/// MACs; the kernel filters received frames to UDP packets for one
/// destination port.
pub struct L2Unicast {
    inner: AsyncFd<Socket>,
    own_hw_addr: [u8; 6],
    ethertype: u16,
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const RECV_BUF_LEN: usize = 2048;

impl L2Unicast {
    /// Opens the socket on `interface` for IPv4 or IPv6 `ethertype`, with a
    /// kernel filter that passes only (unfragmented, for IPv4) UDP datagrams
    /// whose destination port is `udp_dst_port`.
    pub fn open(interface: &str, ethertype: u16, udp_dst_port: u16) -> io::Result<Self> {
        let own_hw_addr = read_hw_addr(interface)?;
        let prog = udp_port_program(ethertype, udp_dst_port)
            .map(drop_tagged)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ethertype is not IP"))?;
        let socket = open_raw(if_index(interface)?, ethertype, Some(prog))?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: register_fd(socket)?,
            own_hw_addr,
            ethertype,
        })
    }

    /// Sends `ip_packet` in an Ethernet frame to `dst`.
    pub fn send(&self, dst: [u8; 6], ip_packet: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(ETH_HEADER_LEN + ip_packet.len());
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&self.own_hw_addr);
        frame.extend_from_slice(&self.ethertype.to_be_bytes());
        frame.extend_from_slice(ip_packet);
        self.inner.get_ref().send(&frame)?;
        Ok(())
    }

    /// The next received IP packet (Ethernet header stripped). Frames this
    /// port sent itself are skipped: a packet socket also sees those.
    pub async fn recv(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; RECV_BUF_LEN];
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(Ok(n)) => {
                    if let Some(p) = payload_of_unicast_frame(&buf[..n], self.own_hw_addr) {
                        return Ok(p.to_vec());
                    }
                }
                Ok(Err(e)) if is_link_down(&e) => {
                    tokio::time::sleep(LINK_DOWN_RETRY).await;
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }
}

/// The payload of a frame that is no runt and was not sent by `own`.
fn payload_of_unicast_frame(frame: &[u8], own: [u8; 6]) -> Option<&[u8]> {
    if frame.len() < ETH_HEADER_LEN || frame[6..12] == own {
        return None;
    }
    Some(&frame[ETH_HEADER_LEN..])
}

/// `SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT` (`linux/filter.h`).
const VLAN_TAG_PRESENT: u32 = 0xFFFF_F030;
/// `SKF_AD_OFF + SKF_AD_PKTTYPE`.
const PKTTYPE: u32 = 0xFFFF_F004;
const PACKET_OTHERHOST: u32 = 3;

fn ins(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Wraps a classic-BPF `body` (relative jumps, a mismatch falls off its end)
/// so a frame that carried an 802.1Q tag is dropped first (#690). Two checks:
/// - the skb's VLAN-tag metadata (a NIC with rx-vlan-offload);
/// - `pkt_type == PACKET_OTHERHOST`: on a veth pair (kernel 7.2.11) the tag is
///   stripped from the bytes and invisible to BPF, yet the frame arrives as
///   OTHERHOST (the kernel's "tag with no VLAN device" marking), which a
///   group-multicast or own-MAC socket never sees otherwise.
///
/// ponytail: real-NIC offload was not tested; the `pkt_type` check is what is
/// proven (`nos-e2e lldp`/`lacp`).
fn drop_tagged(body: Vec<libc::sock_filter>) -> Vec<libc::sock_filter> {
    let n = u8::try_from(body.len()).expect("a short program");
    let mut p = vec![
        ins(0x20, 0, 0, VLAN_TAG_PRESENT), // ld  vlan_tag_present
        ins(0x15, 0, n + 2, 0),            // jeq 0, else the drop below
        ins(0x20, 0, 0, PKTTYPE),          // ld  pkt_type
        ins(0x15, n, 0, PACKET_OTHERHOST), // jeq OTHERHOST: drop
    ];
    p.extend(body);
    p.push(ins(0x06, 0, 0, 0)); // drop
    p
}

/// Classic BPF (offsets include the 14-byte Ethernet header: a packet socket
/// of type `SOCK_RAW` filters the whole frame).
fn udp_port_program(ethertype: u16, port: u16) -> Option<Vec<libc::sock_filter>> {
    let port = u32::from(port);
    match ethertype {
        // ldb [protocol]; jeq UDP; ldh [frag]; jset MF|offset; ldxb 4*ihl;
        // ldh [x + dport]; jeq port; ret all / ret none.
        ETH_P_IP => Some(vec![
            ins(0x30, 0, 0, 23),
            ins(0x15, 0, 6, 17),
            ins(0x28, 0, 0, 20),
            ins(0x45, 4, 0, 0x1fff),
            ins(0xb1, 0, 0, 14),
            ins(0x48, 0, 0, 16),
            ins(0x15, 0, 1, port),
            ins(0x06, 0, 0, 0xffff),
            ins(0x06, 0, 0, 0),
        ]),
        // ldb [next header]; jeq UDP; ldh [dport]; jeq port; ret.
        ETH_P_IPV6 => Some(vec![
            ins(0x30, 0, 0, 20),
            ins(0x15, 0, 3, 17),
            ins(0x28, 0, 0, 56),
            ins(0x15, 0, 1, port),
            ins(0x06, 0, 0, 0xffff),
            ins(0x06, 0, 0, 0),
        ]),
        _ => None,
    }
}

/// Classic BPF accepting a frame to one of the `(group, llc)` pairs whose
/// first three bytes after the 802.3 length field are that LLC. Each block
/// is 11 instructions and a mismatch jumps to its end (the next block, or
/// the final drop). With `untagged` (always, from `open_stp`) a frame that carried an 802.1Q tag is
/// dropped first: a tag in the skb metadata (veth, offloading NICs) is not in
/// the bytes a raw socket reads, so the tagged BPDUs of a VLAN would pass for
/// the untagged (native) ones of the link. A VLAN sub-link's own socket sees
/// the tag already removed.
fn bpdu_program(blocks: &[([u8; 6], [u8; 3])], untagged: bool) -> Vec<libc::sock_filter> {
    let mut p = Vec::new();
    for (g, llc) in blocks {
        p.extend([
            ins(0x20, 0, 0, 0), // ld  [0]
            ins(0x15, 0, 9, u32::from_be_bytes([g[0], g[1], g[2], g[3]])),
            ins(0x28, 0, 0, 4), // ldh [4]
            ins(0x15, 0, 7, u32::from(u16::from_be_bytes([g[4], g[5]]))),
            ins(0x30, 0, 0, 14), // ldb [14]
            ins(0x15, 0, 5, u32::from(llc[0])),
            ins(0x30, 0, 0, 15),
            ins(0x15, 0, 3, u32::from(llc[1])),
            ins(0x30, 0, 0, 16),
            ins(0x15, 0, 1, u32::from(llc[2])),
            ins(0x06, 0, 0, 0xffff), // accept
        ]);
    }
    if untagged {
        return drop_tagged(p);
    }
    p.push(ins(0x06, 0, 0, 0)); // drop
    p
}

fn attach_filter(socket: &Socket, prog: &mut [libc::sock_filter]) -> io::Result<()> {
    let fprog = libc::sock_fprog {
        len: u16::try_from(prog.len()).expect("fixed, small program"),
        filter: prog.as_mut_ptr(),
    };
    // SAFETY: `fprog` points at `prog`, which outlives the call; the kernel
    // copies the program during `setsockopt`.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            std::ptr::from_ref(&fprog).cast::<libc::c_void>(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::sock_fprog>())
                .expect("fixed, small struct size"),
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl AsRawFd for L2Socket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

/// `ENETDOWN` — see `recv`. Also what `send` returns while the link is down.
pub fn is_link_down(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENETDOWN)
}

fn recreated_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "interface recreated")
}

/// Pure core of [`L2Socket::is_stale`]: `now_ifindex` is the live lookup
/// (`None` when the interface is gone). The MAC is deliberately not compared:
/// bonding rewrites an enslaved member's MAC while its ifindex stays.
fn is_recreated(ifindex: i32, now_ifindex: Option<i32>) -> bool {
    now_ifindex != Some(ifindex)
}

/// Whether the frame's ethertype field (bytes 12..14) is `bound`. False for a
/// frame shorter than the header; a VLAN-tagged frame has 0x8100 there.
fn ethertype_matches(frame: &[u8], bound: u16) -> bool {
    frame.get(12..14) == Some(&bound.to_be_bytes()[..])
}

/// The payload of a received frame, or `None` for a runt, a frame not
/// addressed to `group` (or, with `own_unicast`, to `own`), or one this port sent itself. An `AF_PACKET` socket
/// also sees its own *outgoing* frames; treating those as the peer's makes a
/// port "talk to itself" and, where each receive triggers a reply, loop at
/// line rate.
fn payload_of_foreign_frame(
    frame: &[u8],
    own: [u8; 6],
    group: [u8; 6],
    own_unicast: bool,
) -> Option<&[u8]> {
    if frame.len() < ETH_HEADER_LEN
        || (frame[..6] != group && !(own_unicast && frame[..6] == own))
        || frame[6..12] == own
    {
        return None;
    }
    Some(&frame[ETH_HEADER_LEN..])
}

/// Resolves a kernel interface name to its ifindex (`if_nametoindex(3)`).
/// `Err` for a name with an embedded NUL or one the kernel doesn't know.
pub fn if_index(interface: &str) -> io::Result<i32> {
    let name = std::ffi::CString::new(interface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name has a NUL"))?;
    // SAFETY: `name` is a valid, NUL-terminated C string for this call.
    #[allow(unsafe_code)]
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(i32::try_from(index).expect("kernel ifindex always fits i32"))
}

/// The ifindex of the interface carrying `addr` in this network namespace
/// (`getifaddrs(3)`), the lowest one if several do; `None` if none does or the
/// call fails. Used for LLDP's Management Address TLV.
pub fn ifindex_of_address(addr: std::net::IpAddr) -> Option<u32> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a valid out-pointer; on success the list is freed below.
    #[allow(unsafe_code)]
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return None;
    }
    let mut best: Option<u32> = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list `getifaddrs` returned, not yet freed;
        // `ifa_addr` (when non-null) points at a sockaddr of the family it names,
        // and `ifa_name` is a NUL-terminated string.
        #[allow(unsafe_code)]
        let (found, name, next) = unsafe {
            let ifa = &*cur;
            let found = match ifa.ifa_addr.as_ref().map(|sa| i32::from(sa.sa_family)) {
                Some(libc::AF_INET) => {
                    let sin = &*ifa.ifa_addr.cast::<libc::sockaddr_in>();
                    // Network byte order in memory: its bytes are the octets.
                    Some(std::net::IpAddr::from(sin.sin_addr.s_addr.to_ne_bytes()))
                }
                Some(libc::AF_INET6) => {
                    let sin6 = &*ifa.ifa_addr.cast::<libc::sockaddr_in6>();
                    Some(std::net::IpAddr::from(sin6.sin6_addr.s6_addr))
                }
                _ => None,
            };
            (found, ifa.ifa_name, ifa.ifa_next)
        };
        if found == Some(addr) {
            // SAFETY: `name` is the node's NUL-terminated interface name.
            #[allow(unsafe_code)]
            let index = unsafe { libc::if_nametoindex(name) };
            if index != 0 && best.is_none_or(|b| index < b) {
                best = Some(index);
            }
        }
        cur = next;
    }
    // SAFETY: `head` came from a successful `getifaddrs` and is freed once.
    #[allow(unsafe_code)]
    unsafe {
        libc::freeifaddrs(head);
    };
    best
}

/// Joins `group` via `PACKET_ADD_MEMBERSHIP` — without this most NIC drivers
/// never pass an arbitrary multicast destination up to userspace.
fn join_multicast(socket: &Socket, ifindex: i32, group: [u8; 6]) -> io::Result<()> {
    let mut addr = [0u8; 8];
    addr[..6].copy_from_slice(&group);
    let mreq = PacketMreq {
        mr_ifindex: ifindex,
        mr_type: PACKET_MR_MULTICAST,
        mr_alen: 6,
        mr_address: addr,
    };
    let len = libc::socklen_t::try_from(std::mem::size_of::<PacketMreq>())
        .expect("fixed, small struct size");
    // SAFETY: `mreq` is a plain, fully-initialized value of the size
    // `setsockopt` is told, matching the kernel's `packet_mreq` layout.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_PACKET,
            PACKET_ADD_MEMBERSHIP,
            std::ptr::from_ref(&mreq).cast::<libc::c_void>(),
            len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reads `interface`'s own MAC address from sysfs — no netlink/ioctl needed.
fn read_hw_addr(interface: &str) -> io::Result<[u8; 6]> {
    let path = format!("/sys/class/net/{interface}/address");
    let text = std::fs::read_to_string(path)?;
    parse_hw_addr(text.trim()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unrecognized MAC address format for {interface}"),
        )
    })
}

fn parse_hw_addr(text: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = text.split(':');
    for byte in &mut out {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn recreated_detects_new_ifindex_and_gone() {
        assert!(!is_recreated(3, Some(3)));
        assert!(is_recreated(3, Some(4)));
        assert!(is_recreated(3, None));
    }

    use super::*;

    const GROUP: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];

    #[test]
    fn enetdown_is_recognized_as_link_down() {
        assert!(is_link_down(&io::Error::from_raw_os_error(libc::ENETDOWN)));
        assert!(!is_link_down(&io::Error::from_raw_os_error(libc::ENODEV)));
    }

    #[test]
    fn own_frames_runts_and_foreign_groups_are_dropped() {
        let own = [2, 0, 0, 0, 0, 1];
        let other = [2, 0, 0, 0, 0, 2];
        let frame = |dst: [u8; 6], src: [u8; 6]| {
            let mut f = dst.to_vec();
            f.extend_from_slice(&src);
            f.extend_from_slice(&0x88CCu16.to_be_bytes());
            f.extend_from_slice(b"pdu");
            f
        };
        assert_eq!(
            payload_of_foreign_frame(&frame(GROUP, other), own, GROUP, false),
            Some(&b"pdu"[..])
        );
        assert_eq!(
            payload_of_foreign_frame(&frame(GROUP, own), own, GROUP, false),
            None
        );
        // Addressed to a different group than this socket joined.
        assert_eq!(
            payload_of_foreign_frame(
                &frame([0x01, 0x80, 0xC2, 0, 0, 0], other),
                own,
                GROUP,
                false
            ),
            None
        );
        assert_eq!(payload_of_foreign_frame(&[0; 5], own, GROUP, false), None);
        // Unicast to us: dropped by default, accepted when opted in; a foreign
        // unicast and our own frames never are.
        assert_eq!(
            payload_of_foreign_frame(&frame(own, other), own, GROUP, false),
            None
        );
        assert_eq!(
            payload_of_foreign_frame(&frame(own, other), own, GROUP, true),
            Some(&b"pdu"[..])
        );
        assert_eq!(
            payload_of_foreign_frame(&frame([2, 0, 0, 0, 0, 9], other), own, GROUP, true),
            None
        );
        assert_eq!(
            payload_of_foreign_frame(&frame(own, own), own, GROUP, true),
            None
        );
    }

    #[test]
    fn ethertype_check_rejects_tagged_and_short_frames() {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&0x88CCu16.to_be_bytes());
        assert!(ethertype_matches(&f, 0x88CC));
        assert!(!ethertype_matches(&f, 0x8809));
        f[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        assert!(!ethertype_matches(&f, 0x88CC));
        assert!(!ethertype_matches(&f[..13], 0x88CC));
        assert!(!ethertype_matches(&[], 0x88CC));
    }

    #[test]
    fn unicast_frames_skip_runts_and_our_own() {
        let own = [2, 0, 0, 0, 0, 1];
        let mut f = vec![2, 0, 0, 0, 0, 9, 2, 0, 0, 0, 0, 2, 8, 0];
        f.extend_from_slice(b"ip");
        assert_eq!(payload_of_unicast_frame(&f, own), Some(&b"ip"[..]));
        f[6..12].copy_from_slice(&own);
        assert_eq!(payload_of_unicast_frame(&f, own), None);
        assert_eq!(payload_of_unicast_frame(&f[..13], own), None);
    }

    const IEEE_BLOCK: ([u8; 6], [u8; 3]) = (BPDU_GROUP, [0x42, 0x42, 0x03]);
    const SSTP_BLOCK: ([u8; 6], [u8; 3]) = (SSTP_GROUP, [0xAA, 0xAA, 0x03]);

    /// Interprets `bpdu_program` over a frame (only the ops it uses).
    fn bpf_accepts(frame: &[u8]) -> bool {
        bpf_runs(&bpdu_program(&[IEEE_BLOCK], false), frame, false)
    }

    /// `tagged`: the frame carried a VLAN tag in its metadata.
    fn bpf_runs(prog: &[libc::sock_filter], frame: &[u8], tagged: bool) -> bool {
        bpf_runs_pkt(prog, frame, tagged, 2)
    }

    /// `pkt_type`: 2 = multicast, 3 = otherhost.
    fn bpf_runs_pkt(prog: &[libc::sock_filter], frame: &[u8], tagged: bool, pkt_type: u32) -> bool {
        let (mut pc, mut a) = (0usize, 0u32);
        loop {
            let i = &prog[pc];
            let k = i.k as usize;
            let get = |n: usize| frame.get(k..k + n);
            match i.code {
                0x20 if i.k == VLAN_TAG_PRESENT => a = u32::from(tagged),
                0x20 if i.k == PKTTYPE => a = pkt_type,
                0x20 => a = get(4).map_or(u32::MAX, |b| u32::from_be_bytes(b.try_into().unwrap())),
                0x28 => {
                    a = get(2).map_or(u32::MAX, |b| {
                        u32::from(u16::from_be_bytes(b.try_into().unwrap()))
                    });
                }
                0x30 => a = get(1).map_or(u32::MAX, |b| u32::from(b[0])),
                0x15 => pc += usize::from(if a == i.k { i.jt } else { i.jf }),
                0x06 => return i.k != 0,
                c => panic!("op {c:#x}"),
            }
            pc += 1;
        }
    }

    #[test]
    fn bpdu_filter_takes_only_group_llc_frames() {
        let mut f = BPDU_GROUP.to_vec();
        f.extend_from_slice(&[2, 0, 0, 0, 0, 1, 0, 38, 0x42, 0x42, 0x03, 0, 0]);
        assert!(bpf_accepts(&f));
        let mut other_group = f.clone();
        other_group[5] = 0x0E;
        assert!(!bpf_accepts(&other_group));
        let mut other_llc = f.clone();
        other_llc[16] = 0x04;
        assert!(!bpf_accepts(&other_llc));
        assert!(!bpf_accepts(&f[..10]), "a runt never matches");
    }

    #[test]
    fn pvst_filter_takes_either_group_with_its_own_llc() {
        let prog = bpdu_program(&[SSTP_BLOCK, IEEE_BLOCK], true);
        let frame = |g: [u8; 6], llc: [u8; 3]| {
            let mut f = g.to_vec();
            f.extend_from_slice(&[2, 0, 0, 0, 0, 1, 0, 38]);
            f.extend_from_slice(&llc);
            f
        };
        assert!(bpf_runs(
            &prog,
            &frame(SSTP_GROUP, [0xAA, 0xAA, 0x03]),
            false
        ));
        assert!(bpf_runs(
            &prog,
            &frame(BPDU_GROUP, [0x42, 0x42, 0x03]),
            false
        ));
        assert!(!bpf_runs(
            &prog,
            &frame(SSTP_GROUP, [0x42, 0x42, 0x03]),
            false
        ));
        assert!(!bpf_runs(
            &prog,
            &frame(BPDU_GROUP, [0xAA, 0xAA, 0x03]),
            false
        ));
        // an SSTP-only socket (a tagged sub-link) drops the IEEE group
        let sstp_only = bpdu_program(&[SSTP_BLOCK], true);
        assert!(!bpf_runs(
            &sstp_only,
            &frame(BPDU_GROUP, [0x42, 0x42, 0x03]),
            false
        ));
        // a frame whose VLAN tag sits in the metadata is another VLAN's BPDU
        let sstp = frame(SSTP_GROUP, [0xAA, 0xAA, 0x03]);
        assert!(bpf_runs(&sstp_only, &sstp, false));
        assert!(!bpf_runs(&sstp_only, &sstp, true));
        assert!(!bpf_runs(&prog, &sstp, true));
    }

    #[test]
    fn drop_tagged_wrapper_drops_tagged_and_keeps_untagged() {
        let frame = [0u8; 20];
        let p = drop_tagged(vec![ins(0x06, 0, 0, 0xffff)]);
        assert!(bpf_runs(&p, &frame, false));
        assert!(!bpf_runs(&p, &frame, true));
        // tag invisible to BPF (veth), frame marked OTHERHOST
        assert!(!bpf_runs_pkt(&p, &frame, false, 3));
        // the wrapped UDP programs keep every jump in range
        for et in [ETH_P_IP, ETH_P_IPV6] {
            let p = drop_tagged(udp_port_program(et, 3785).unwrap());
            for (i, x) in p.iter().enumerate() {
                if x.code & 0x07 == 0x05 {
                    assert!(i + 1 + usize::from(x.jt.max(x.jf)) < p.len());
                }
            }
            assert_eq!(p[1].jf as usize, p.len() - 3);
            assert_eq!(usize::from(p[3].jt), p.len() - 5);
        }
    }

    #[test]
    fn plain_bpdu_filter_drops_tagged_frames() {
        let prog = bpdu_program(&[IEEE_BLOCK], true);
        let mut f = vec![0u8; 20];
        f[..6].copy_from_slice(&BPDU_GROUP);
        f[14..17].copy_from_slice(&[0x42, 0x42, 0x03]);
        assert!(bpf_runs(&prog, &f, false));
        assert!(!bpf_runs(&prog, &f, true));
        assert!(!bpf_runs_pkt(&prog, &f, false, 3));
    }

    #[test]
    fn udp_filters_exist_for_ip_only_and_end_in_a_return() {
        for et in [ETH_P_IP, ETH_P_IPV6] {
            let p = udp_port_program(et, 3785).unwrap();
            assert_eq!(p[p.len() - 1].code, 0x06);
            // every jump lands inside the program
            for (i, ins) in p.iter().enumerate() {
                if ins.code & 0x07 == 0x05 {
                    assert!(i + 1 + usize::from(ins.jt.max(ins.jf)) < p.len());
                }
            }
        }
        assert!(udp_port_program(0x88cc, 1).is_none());
    }

    #[test]
    fn ifindex_of_address_finds_loopback_only() {
        let lo = u32::try_from(if_index("lo").unwrap()).unwrap();
        assert_eq!(ifindex_of_address([127, 0, 0, 1].into()), Some(lo));
        assert_eq!(ifindex_of_address([192, 0, 2, 1].into()), None);
    }

    #[test]
    fn parses_colon_separated_mac() {
        assert_eq!(
            parse_hw_addr("02:00:00:00:00:01"),
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        );
        assert_eq!(parse_hw_addr("not-a-mac"), None);
        assert_eq!(parse_hw_addr("02:00:00:00:00"), None);
        assert_eq!(parse_hw_addr("02:00:00:00:00:01:02"), None);
    }
}
