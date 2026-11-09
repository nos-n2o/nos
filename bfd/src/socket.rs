//! The UDP side of RFC 5881 single-hop (3784) and RFC 5883 multihop (4784) BFD (excluded from coverage: it only
//! runs against a real kernel, `nos-e2e`'s `bfd` phase is its test).
//!
//! - One receive socket per (table, address family): UDP 3784 wildcard,
//!   `SO_BINDTODEVICE` to the table's VRF, `IP_RECVTTL`/`IPV6_RECVHOPLIMIT` so
//!   every datagram's TTL is checked (RFC 5881 §5: must be exactly 255).
//! - Echo (RFC 5881 §4): per single-hop session one `AF_PACKET` socket
//!   (`nos_l2_socket::L2Unicast`, filtered to UDP 3785) on the session's
//!   interface, sending to the neighbour's MAC read from the kernel; the
//!   returned packet has our own address as source, which the IP stack would
//!   drop as a martian, so it is received at the packet layer too.
//! - One connected transmit socket per session, a fixed random source port in
//!   49152-65535 (§4), TTL/hop limit 255, bound to the session's interface or
//!   else the VRF.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use nos_proto::{RibEvent, RibRequest, Role, ServiceRef, SessionKey};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::echo;
use crate::manager::{Demux, Net};
use crate::micro;
use crate::neigh;
use crate::packet;
use crate::reflector::Reflector;
use crate::sbfd::{self, SbfdPath};
use crate::session::{rand_u32, EchoPath, EchoTx, Looped, Tx};
use nos_bfd_socket::{ifindex, recv_one, recv_probe, send_from, set_int};
use nos_daemon::{ipc, watchdog};
use nos_l2_socket::{L2Socket, L2Unicast};

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

/// The Linux VRF device of routing table `table`, `None` while `nos-ribd`
/// is unreachable or has not created it.
pub async fn vrf_name(watchdog_socket: &std::path::Path, table: &str) -> Option<String> {
    let rib =
        watchdog::resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string())).await?;
    match ipc::one_shot(&rib, Role::Ribd, RibRequest::GetVrfName).await? {
        RibEvent::VrfName(name) => name,
        _ => None,
    }
}

pub const BFD_PORT: u16 = 3784;
/// RFC 5883 §2: multihop control packets.
pub const BFD_MULTIHOP_PORT: u16 = 4784;

const fn port(multihop: bool) -> u16 {
    if multihop {
        BFD_MULTIHOP_PORT
    } else {
        BFD_PORT
    }
}
const TTL: u32 = 255;
/// Largest micro-BFD frame worth reading (Ethernet + IP + UDP + a 24-byte-plus-auth PDU).
const RX_FRAME: usize = 256;

fn domain(v6: bool) -> Domain {
    if v6 {
        Domain::IPV6
    } else {
        Domain::IPV4
    }
}

fn rx_socket(vrf: &str, v6: bool, port: u16) -> io::Result<AsyncFd<Socket>> {
    let s = Socket::new(domain(v6), Type::DGRAM, Some(Protocol::UDP))?;
    s.bind_device(Some(vrf.as_bytes()))?;
    let fd = s.as_raw_fd();
    let bind: SocketAddr = if v6 {
        s.set_only_v6(true)?;
        set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, 1)?;
        (Ipv6Addr::UNSPECIFIED, port).into()
    } else {
        set_int(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, 1)?;
        (Ipv4Addr::UNSPECIFIED, port).into()
    };
    s.bind(&bind.into())?;
    s.set_nonblocking(true)?;
    register_fd(s)
}

const BACKOFF_MIN: Duration = Duration::from_millis(10);
const BACKOFF_MAX: Duration = Duration::from_secs(1);

/// The next retry delay: doubled, capped at `BACKOFF_MAX`.
fn next_backoff(d: Duration) -> Duration {
    d.saturating_mul(2).min(BACKOFF_MAX)
}

/// Retry pacing of a receive loop (#693): 10 ms doubling to 1 s, reset by a
/// good receive; only the first failure of a streak is a `warn!`.
struct Backoff {
    delay: Duration,
    failing: bool,
}

impl Backoff {
    const fn new() -> Self {
        Backoff {
            delay: BACKOFF_MIN,
            failing: false,
        }
    }

    /// A failure: whether it opens a streak, and how long to wait.
    fn failed(&mut self) -> (bool, Duration) {
        let first = !self.failing;
        self.failing = true;
        let d = self.delay;
        self.delay = next_backoff(d);
        (first, d)
    }

    /// A success: whether it ends a streak.
    fn ok(&mut self) -> bool {
        let was = self.failing;
        *self = Self::new();
        was
    }

    async fn fail(&mut self, what: &str, e: &io::Error) {
        let (first, d) = self.failed();
        if first {
            warn!(what = %what, error = %e, "bfd receive failing, retrying with backoff");
        } else {
            debug!(what = %what, error = %e, "bfd receive still failing");
        }
        tokio::time::sleep(d).await;
    }

    fn recovered(&mut self, what: &str) {
        if self.ok() {
            info!(what = %what, "bfd receive recovered");
        }
    }
}

/// How often an L2 receive loop checks that its interface still has the
/// index its socket was bound to: `recv` on a packet socket whose interface
/// was deleted and recreated blocks silently, it never errors (#693).
const IFINDEX_CHECK: Duration = Duration::from_secs(1);

/// `Some(new index)` when `iface` now has an index other than `have`.
fn ifindex_changed(iface: &str, have: i32) -> Option<i32> {
    nos_l2_socket::if_index(iface).ok().filter(|i| *i != have)
}

/// Calls `make` until it succeeds, backing off between failures: a failed
/// recreation (VRF or interface absent for a while) never ends the task.
async fn reopen<T>(what: &str, b: &mut Backoff, mut make: impl FnMut() -> io::Result<T>) -> T {
    loop {
        match make() {
            Ok(t) => return t,
            Err(e) => b.fail(what, &e).await,
        }
    }
}

/// The receive loop of a UDP socket, which never ends (#693): a receive error
/// backs off and retries; a failed readiness wait (`readable()`) rebuilds the
/// socket through `remake`, retried with backoff until it works. `step` does
/// one non-blocking receive and handles the datagram.
async fn socket_loop(
    what: String,
    sock: AsyncFd<Socket>,
    mut remake: impl FnMut(&mut Option<AsyncFd<Socket>>) -> io::Result<()>,
    mut step: impl FnMut(&AsyncFd<Socket>) -> io::Result<()>,
    mut stale: impl FnMut() -> bool,
) {
    let mut sock = Some(sock);
    let mut dead = false;
    let mut b = Backoff::new();
    loop {
        if dead {
            match remake(&mut sock) {
                Ok(()) => dead = false,
                Err(e) => {
                    b.fail(&what, &e).await;
                    continue;
                }
            }
        }
        let Some(s) = sock.as_ref() else {
            dead = true;
            continue;
        };
        // A socket bound to a deleted-and-recreated device goes silent without
        // an error: `stale` is asked every `IFINDEX_CHECK` of silence (#660).
        let Ok(ready) = tokio::time::timeout(IFINDEX_CHECK, s.readable()).await else {
            dead = stale();
            continue;
        };
        let mut guard = match ready {
            Ok(g) => g,
            Err(e) => {
                b.fail(&what, &e).await;
                dead = true;
                continue;
            }
        };
        match guard.try_io(&mut step) {
            Ok(Ok(())) => b.recovered(&what),
            Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
            Ok(Err(e)) => b.fail(&what, &e).await,
            Err(_) => {}
        }
    }
}

async fn rx_loop(
    sock: AsyncFd<Socket>,
    table: String,
    vrf: String,
    v6: bool,
    multihop: bool,
    demux: Demux,
) {
    let mut buf = [0u8; 128];
    let mut have = ifindex(&vrf);
    socket_loop(
        format!("udp table={table} v6={v6} multihop={multihop}"),
        sock,
        |old| {
            // The port is not SO_REUSEADDR: the dead socket goes first.
            drop(old.take());
            *old = Some(rx_socket(&vrf, v6, port(multihop))?);
            info!(table = %table, v6, multihop, "bfd receive socket recreated");
            Ok(())
        },
        |s| {
            let d = recv_one(s.get_ref().as_raw_fd(), &mut buf)?;
            // TTL check (RFC 5881 §5 / RFC 5883 §5) is per session, in `route`.
            let ok = demux.route(&table, d.src, multihop, d.ttl, &buf[..d.len.min(buf.len())]);
            debug!(peer = %d.src, ttl = ?d.ttl, delivered = ok, "bfd packet received");
            Ok(())
        },
        || {
            // The VRF was recreated (a `nos-ribd` restart): its index changed.
            let now = ifindex(&vrf);
            let changed = now != 0 && now != have;
            if changed {
                have = now;
            }
            changed
        },
    )
    .await;
}

/// Whether a transmit socket must be rebuilt: its device or VRF has another
/// index than at open, checked once per `IFINDEX_CHECK` or right after a send
/// error (#660).
fn needs_rebuild(have: (u32, u32), now: (u32, u32), since: Duration, err: bool) -> bool {
    have != now && now.0 != 0 && now.1 != 0 && (err || since >= IFINDEX_CHECK)
}

struct TxState {
    sock: Arc<Socket>,
    /// (device, VRF) indexes the socket was made for.
    have: (u32, u32),
    last_check: Instant,
    /// The last send failed (not `EMSGSIZE`).
    err: bool,
    /// One `warn!` per failing streak.
    warned: bool,
    /// Bumped on each rebuild: S-BFD's receive loop follows it.
    epoch: u32,
}

/// A connected UDP transmit socket that survives its device (or VRF) being
/// deleted and recreated, as a `nos-ribd` restart does: the old socket is
/// bound to the dead index and every send fails (#660).
struct UdpTx {
    device: String,
    vrf: String,
    key: SessionKey,
    dport: u16,
    /// Rebind the same source port on a rebuild (S-BFD's reflections return to it).
    keep_port: bool,
    st: Mutex<TxState>,
}

impl UdpTx {
    fn new(
        device: &str,
        vrf: &str,
        key: &SessionKey,
        dport: u16,
        keep_port: bool,
    ) -> io::Result<Self> {
        let have = (ifindex(device), ifindex(vrf));
        let sock = Arc::new(tx_socket(device, vrf, key, dport, None)?);
        Ok(UdpTx {
            device: device.to_string(),
            vrf: vrf.to_string(),
            key: key.clone(),
            dport,
            keep_port,
            st: Mutex::new(TxState {
                sock,
                have,
                last_check: Instant::now(),
                err: false,
                warned: false,
                epoch: 0,
            }),
        })
    }

    fn socket(&self) -> Arc<Socket> {
        self.st.lock().unwrap().sock.clone()
    }

    fn generation(&self) -> u32 {
        self.st.lock().unwrap().epoch
    }

    /// Rebuilds the socket when due and the indexes changed; a failed rebuild
    /// keeps the old socket and retries on the next send.
    fn refresh(&self, st: &mut TxState) {
        let since = st.last_check.elapsed();
        if !st.err && since < IFINDEX_CHECK {
            return;
        }
        st.last_check = Instant::now();
        let now = (ifindex(&self.device), ifindex(&self.vrf));
        if !needs_rebuild(st.have, now, since, st.err) {
            return;
        }
        let port = if self.keep_port {
            st.sock
                .local_addr()
                .ok()
                .and_then(|a| a.as_socket())
                .map(|a| a.port())
        } else {
            None
        };
        match tx_socket(&self.device, &self.vrf, &self.key, self.dport, port) {
            Ok(s) => {
                st.sock = Arc::new(s);
                st.have = now;
                st.epoch = st.epoch.wrapping_add(1);
                st.err = false;
                info!(peer = %self.key.peer, table = %self.key.table, "bfd transmit socket recreated");
            }
            Err(e) => {
                debug!(peer = %self.key.peer, error = %e, "bfd transmit socket not recreated");
            }
        }
    }
}

impl Tx for UdpTx {
    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        let mut st = self.st.lock().unwrap();
        self.refresh(&mut st);
        let r = st.sock.send(bytes).map(|_| ());
        st.err = matches!(&r, Err(e) if e.raw_os_error() != Some(libc::EMSGSIZE));
        match &r {
            Err(e) if st.err && !st.warned => {
                st.warned = true;
                warn!(peer = %self.key.peer, error = %e, "bfd send failing");
            }
            Ok(()) => st.warned = false,
            _ => {}
        }
        r
    }
}

/// Whether interface `name` is enslaved to the VRF device `vrf`.
fn in_vrf(name: &str, vrf: &str) -> bool {
    std::fs::read_link(format!("/sys/class/net/{name}/master"))
        .is_ok_and(|m| m.file_name().is_some_and(|f| f == vrf))
}

fn as_bits(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

/// The local address on the connected network of `peer` and the interface
/// holding it: of `interface`, or else of any interface in `vrf`.
fn local_for(peer: IpAddr, vrf: &str, interface: Option<&str>) -> Option<(IpAddr, String)> {
    let sock_ip = |a: nix::sys::socket::SockaddrStorage| -> Option<IpAddr> {
        a.as_sockaddr_in()
            .map(|s| IpAddr::V4(s.ip()))
            .or_else(|| a.as_sockaddr_in6().map(|s| IpAddr::V6(s.ip())))
    };
    nix::ifaddrs::getifaddrs().ok()?.find_map(|ifa| {
        let ok = match interface {
            Some(i) => ifa.interface_name == i,
            None => in_vrf(&ifa.interface_name, vrf),
        };
        let (addr, mask) = (sock_ip(ifa.address?)?, sock_ip(ifa.netmask?)?);
        (ok && addr.is_ipv4() == peer.is_ipv4()
            && as_bits(addr) & as_bits(mask) == as_bits(peer) & as_bits(mask))
        .then_some((addr, ifa.interface_name))
    })
}

/// The source address the kernel would use towards `peer` in `vrf`: a
/// connected UDP socket's local address is a route lookup, nothing is sent.
/// RFC 5883 §4 wants the multihop local address fixed; a client that does
/// not name one gets this one. ponytail: re-derived only when `UdpTx`
/// rebuilds its socket, not if the route's source changes alone.
fn kernel_source(peer: IpAddr, vrf: &str) -> Option<IpAddr> {
    let s = Socket::new(domain(peer.is_ipv6()), Type::DGRAM, Some(Protocol::UDP)).ok()?;
    s.bind_device(Some(vrf.as_bytes())).ok()?;
    s.connect(&SocketAddr::new(peer, BFD_MULTIHOP_PORT).into())
        .ok()?;
    let ip = s.local_addr().ok()?.as_socket()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

fn tx_socket(
    device: &str,
    vrf: &str,
    key: &SessionKey,
    dport: u16,
    prefer_port: Option<u16>,
) -> io::Result<Socket> {
    let v6 = key.peer.is_ipv6();
    let s = Socket::new(domain(v6), Type::DGRAM, Some(Protocol::UDP))?;
    s.bind_device(Some(device.as_bytes()))?;
    // RFC 9764 §3: padded packets must not be fragmented, or they would test
    // nothing (EMSGSIZE on send instead). Harmless for bare packets.
    if v6 {
        s.set_unicast_hops_v6(TTL)?;
        set_int(s.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1)?;
        // An S-BFD initiator's reflections arrive here (`open_sbfd`) and are TTL-checked.
        set_int(
            s.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVHOPLIMIT,
            1,
        )?;
    } else {
        set_int(s.as_raw_fd(), libc::IPPROTO_IP, libc::IP_RECVTTL, 1)?;
        s.set_ttl_v4(TTL)?;
        set_int(
            s.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_DO,
        )?;
    }
    // A wildcard source left to the kernel goes out as 0.0.0.0 from a socket
    // bound to a VRF, so the source is picked here.
    let local = key
        .local
        .or_else(|| {
            if key.multihop {
                kernel_source(key.peer, vrf)
            } else {
                local_for(key.peer, vrf, key.interface.as_deref()).map(|(a, _)| a)
            }
        })
        .ok_or_else(|| io::Error::other("no local address towards the peer yet"))?;
    let mut prefer_port = prefer_port;
    let mut bound = false;
    let mut err = io::Error::other("no free source port");
    for _ in 0..32 {
        let port = prefer_port
            .take()
            .unwrap_or_else(|| 49152 + u16::try_from(rand_u32() % 16384).unwrap_or(0));
        match s.bind(&SocketAddr::new(local, port).into()) {
            Ok(()) => {
                bound = true;
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => err = e,
            Err(e) => return Err(e),
        }
    }
    if !bound {
        return Err(err);
    }
    let scope = key.interface.as_deref().map_or(0, ifindex);
    let peer: SockAddr = match key.peer {
        IpAddr::V6(a) => SocketAddrV6::new(a, dport, 0, scope).into(),
        IpAddr::V4(a) => SocketAddr::new(a.into(), dport).into(),
    };
    s.connect(&peer)?;
    s.set_nonblocking(true)?;
    Ok(s)
}

/// Echo packets out through the neighbour: its MAC is kept fresh by a task.
struct L2Echo {
    /// Swapped by `echo_rx_loop` when it recreates the socket (#693).
    sock: Arc<Mutex<Arc<L2Unicast>>>,
    mac: Arc<Mutex<Option<[u8; 6]>>>,
    local: IpAddr,
    sport: u16,
}

impl EchoTx for L2Echo {
    fn send(&self, payload: &[u8]) -> io::Result<()> {
        let mac = (*self.mac.lock().unwrap())
            .ok_or_else(|| io::Error::other("no neighbour entry for the peer yet"))?;
        let ip = echo::build(self.local, self.sport, payload);
        let sock = self.sock.lock().unwrap().clone();
        sock.send(mac, &ip)
    }
}

/// Keeps `mac` equal to the kernel's entry for `peer` on `ifindex`; asks
/// again fast while there is none.
async fn neigh_loop(
    nl: rtnetlink::Handle,
    peer: IpAddr,
    ifindex: u32,
    mac: Arc<Mutex<Option<[u8; 6]>>>,
    kick: Option<UdpTx>,
) {
    loop {
        let found = neigh::lookup(&nl, peer, ifindex).await;
        let delay = match found {
            Ok(m) => {
                *mac.lock().unwrap() = m;
                if m.is_some() {
                    Duration::from_secs(1)
                } else {
                    // An unaffiliated session has no Control traffic to make
                    // the kernel resolve the peer: an empty datagram does.
                    if let Some(k) = &kick {
                        let _ = k.send(&[]);
                    }
                    Duration::from_millis(200)
                }
            }
            Err(e) => {
                debug!(peer = %peer, error = %e, "bfd neighbour lookup failed");
                Duration::from_secs(1)
            }
        };
        tokio::time::sleep(delay).await;
    }
}

async fn echo_rx_loop(
    slot: Arc<Mutex<Arc<L2Unicast>>>,
    iface: String,
    ethertype: u16,
    local: IpAddr,
    disc: u32,
    unaffiliated: bool,
    out: tokio::sync::mpsc::Sender<Looped>,
) {
    let mut b = Backoff::new();
    let what = format!("echo iface={iface}");
    let mut have = nos_l2_socket::if_index(&iface).unwrap_or(0);
    loop {
        let sock = slot.lock().unwrap().clone();
        let got = match tokio::time::timeout(IFINDEX_CHECK, sock.recv()).await {
            Ok(r) => r,
            Err(_) => match ifindex_changed(&iface, have) {
                Some(i) => {
                    have = i;
                    Err(io::Error::other("interface index changed"))
                }
                None => continue,
            },
        };
        match got {
            Ok(p) => {
                b.recovered(&what);
                let looped = if unaffiliated {
                    // RFC 9747 §3: our own Control packet, TTL exactly 254.
                    echo::parse_udp(&p, local)
                        .filter(|(_, ttl)| *ttl == 254)
                        .and_then(|(pl, _)| packet::decode(pl).ok())
                        .filter(|c| c.my_discriminator == disc)
                        .map(|c| Looped::Control(c.state))
                } else {
                    echo::parse(&p, local)
                        .filter(|(d, _)| *d == disc)
                        .map(|(_, seq)| Looped::Seq(seq))
                };
                if let Some(l) = looped {
                    let _ = out.try_send(l);
                }
            }
            Err(e) => {
                // Any error may mean a stale ifindex: rebuild the socket (#693).
                b.fail(&what, &e).await;
                let new = reopen(&what, &mut b, || {
                    L2Unicast::open(&iface, ethertype, echo::ECHO_PORT)
                })
                .await;
                *slot.lock().unwrap() = Arc::new(new);
                have = nos_l2_socket::if_index(&iface).unwrap_or(have);
                info!(iface = %iface, "bfd echo receive socket recreated");
            }
        }
    }
}

/// One RFC 7130 micro-BFD session's transport: control packets leave the LAG
/// member in an IP/UDP frame to the dedicated multicast MAC; two receive
/// tasks (untagged, and 802.1p tag 0) feed the `Demux`. The member's own
/// socket is not affected by the bond enslaving it (it is bound to the
/// member's ifindex and the bond's `rx_handler` re-targets the skb after the
/// packet tap: `nos-e2e`'s `micro-bfd` phase proves it).
struct MicroTx {
    /// Swapped by the untagged `micro_rx_loop` when it recreates the socket (#693).
    sock: Arc<Mutex<Arc<L2Socket>>>,
    local: IpAddr,
    peer: IpAddr,
    sport: u16,
    rx: Vec<tokio::task::AbortHandle>,
}

impl Tx for MicroTx {
    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        let ip = micro::build_frame(self.local, self.peer, self.sport, bytes)
            .ok_or_else(|| io::Error::other("local and peer address families differ"))?;
        let sock = self.sock.lock().unwrap().clone();
        sock.send(&ip)
    }
}

impl Drop for MicroTx {
    fn drop(&mut self) {
        for t in &self.rx {
            t.abort();
        }
    }
}

/// A member's receive socket: the untagged UDP 6784 one (also the TX socket),
/// or the 802.1p-tagged one.
fn micro_open(member: &str, ethertype: u16, tagged: bool) -> io::Result<L2Socket> {
    let s = if tagged {
        // ponytail: no kernel filter on the tagged socket: it wakes for every
        // VLAN frame of the member (RFC 7130 §2.3 wants tag 0 received).
        L2Socket::open(member, 0x8100, micro::GROUP, RX_FRAME)?
    } else {
        L2Socket::open_udp(member, ethertype, micro::GROUP, RX_FRAME, micro::PORT)?
    };
    Ok(s.accept_own_unicast())
}

async fn micro_rx_loop(
    slot: Arc<Mutex<Arc<L2Socket>>>,
    ethertype: u16,
    tagged: bool,
    member: String,
    local: IpAddr,
    demux: Demux,
) {
    let mut b = Backoff::new();
    let what = format!("micro member={member} tagged={tagged}");
    let mut have = nos_l2_socket::if_index(&member).unwrap_or(0);
    loop {
        let sock = slot.lock().unwrap().clone();
        let got = match tokio::time::timeout(IFINDEX_CHECK, sock.recv()).await {
            Ok(r) => r,
            Err(_) => match ifindex_changed(&member, have) {
                Some(i) => {
                    have = i;
                    Err(io::Error::other("interface index changed"))
                }
                None => continue,
            },
        };
        let payload = match got {
            Ok(p) => {
                b.recovered(&what);
                p
            }
            Err(e) => {
                // Any error may mean a stale ifindex: rebuild the socket (#693).
                b.fail(&what, &e).await;
                let new = reopen(&what, &mut b, || micro_open(&member, ethertype, tagged)).await;
                *slot.lock().unwrap() = Arc::new(new);
                have = nos_l2_socket::if_index(&member).unwrap_or(have);
                info!(member = %member, tagged, "bfd micro receive socket recreated");
                continue;
            }
        };
        let ip = if tagged {
            micro::untag_priority(&payload)
        } else {
            Some(&payload[..])
        };
        // Addressed to the bond's address; TTL 255 is `parse_frame`'s.
        if let Some(f) = ip.and_then(micro::parse_frame).filter(|f| f.dst == local) {
            let ok = demux.route_micro(&member, f.src, f.pdu);
            debug!(member = %member, peer = %f.src, delivered = ok, "bfd micro packet received");
        }
    }
}

/// Reads reflections off an initiator's own socket (RFC 7881 §2: they come
/// back to its source port) and hands them to the session with their TTL.
async fn sbfd_rx_loop(
    sock: AsyncFd<Socket>,
    tx: Arc<UdpTx>,
    peer: IpAddr,
    out: tokio::sync::mpsc::Sender<sbfd::Reflection>,
) {
    let mut buf = [0u8; 128];
    let seen = AtomicU32::new(tx.generation());
    socket_loop(
        format!("sbfd peer={peer}"),
        sock,
        |old| {
            // Reflections come back to the transmit socket's source port:
            // follow it (`UdpTx` swaps it when its device is recreated).
            seen.store(tx.generation(), Ordering::Relaxed);
            *old = Some(register_fd(tx.socket().try_clone()?)?);
            info!(peer = %peer, "bfd sbfd receive socket recreated");
            Ok(())
        },
        |s| match recv_one(s.get_ref().as_raw_fd(), &mut buf) {
            Ok(d) => {
                if let Ok(p) = packet::decode(&buf[..d.len.min(buf.len())]) {
                    let _ = out.try_send((p, d.ttl));
                }
                Ok(())
            }
            // ICMP errors on a connected socket (reflector unreachable) are not fatal.
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ECONNREFUSED | libc::EHOSTUNREACH | libc::ENETUNREACH)
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        },
        || tx.generation() != seen.load(Ordering::Relaxed),
    )
    .await;
}

/// Whether `a` may be the source of a reply: not loopback (RFC 7881 §6.1 lets
/// the kernel pick then), not a broadcast/multicast/unspecified destination.
fn reply_source(a: IpAddr) -> Option<IpAddr> {
    let ok = !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || matches!(a, IpAddr::V4(v) if v.is_broadcast()));
    ok.then_some(a)
}

fn reflector_socket(vrf: &str, v6: bool) -> io::Result<AsyncFd<Socket>> {
    let s = Socket::new(domain(v6), Type::DGRAM, Some(Protocol::UDP))?;
    s.bind_device(Some(vrf.as_bytes()))?;
    let fd = s.as_raw_fd();
    let bind: SocketAddr = if v6 {
        s.set_only_v6(true)?;
        set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
        s.set_unicast_hops_v6(TTL)?;
        (Ipv6Addr::UNSPECIFIED, sbfd::PORT).into()
    } else {
        set_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
        s.set_ttl_v4(TTL)?;
        (Ipv4Addr::UNSPECIFIED, sbfd::PORT).into()
    };
    s.bind(&bind.into())?;
    s.set_nonblocking(true)?;
    register_fd(s)
}

async fn reflect_loop(sock: AsyncFd<Socket>, vrf: String, v6: bool, reflector: Arc<Reflector>) {
    let mut buf = [0u8; 128];
    socket_loop(
        format!("reflector vrf={vrf} v6={v6}"),
        sock,
        |old| {
            drop(old.take());
            *old = Some(reflector_socket(&vrf, v6)?);
            info!(vrf = %vrf, v6, "bfd reflector socket recreated");
            Ok(())
        },
        |s| {
            let fd = s.get_ref().as_raw_fd();
            let p = recv_probe(fd, &mut buf)?;
            let data = &buf[..p.len.min(buf.len())];
            if let Some(reply) = reflector.handle(std::time::Instant::now(), p.src, p.dst, data)
                && let Err(e) = send_from(fd, &p.name, reply_source(p.dst), &reply)
            {
                debug!(peer = %p.src, error = %e, "bfd reflector reply failed");
            }
            Ok(())
        },
        || false, // `ReflectorNet::apply` follows the VRF's index
    )
    .await;
}

type ReflectorTasks = HashMap<(String, bool), (u32, JoinHandle<()>)>;

/// The reflector's UDP 7784 sockets: one per (VRF, family) while a
/// discriminator is configured, restarted when the VRF device is recreated.
pub struct ReflectorNet {
    watchdog_socket: PathBuf,
    reflector: Arc<Reflector>,
    /// (table, v6) -> (VRF ifindex it was opened for, its task).
    tasks: Mutex<ReflectorTasks>,
}

impl ReflectorNet {
    pub fn new(watchdog_socket: PathBuf, reflector: Arc<Reflector>) -> Self {
        ReflectorNet {
            watchdog_socket,
            reflector,
            tasks: Mutex::default(),
        }
    }

    /// Follows the running config: the policy, then the sockets of every table.
    pub async fn configure(&self, cfg: &nos_proto::Config) {
        self.reflector.set_policy(crate::reflector::policy_of(cfg));
        let tables: Vec<String> = cfg.routing_tables.iter().map(|t| t.name.clone()).collect();
        self.apply(&tables).await;
    }

    /// Makes the sockets match the policy and the routing `tables`; idempotent.
    pub async fn apply(&self, tables: &[String]) {
        if !self.reflector.enabled() {
            for (_, (_, t)) in self.tasks.lock().unwrap().drain() {
                t.abort();
            }
            return;
        }
        self.tasks.lock().unwrap().retain(|(t, _), (_, task)| {
            let keep = tables.contains(t);
            if !keep {
                task.abort();
            }
            keep
        });
        for table in tables {
            let Some(vrf) = vrf_name(&self.watchdog_socket, table).await else {
                continue;
            };
            let idx = ifindex(&vrf);
            for v6 in [false, true] {
                let mut tasks = self.tasks.lock().unwrap();
                let key = (table.clone(), v6);
                if let Some((have, task)) = tasks.get(&key) {
                    if *have == idx && !task.is_finished() {
                        continue;
                    }
                    task.abort();
                }
                match reflector_socket(&vrf, v6) {
                    Ok(sock) => {
                        tasks.insert(
                            key,
                            (
                                idx,
                                tokio::spawn(reflect_loop(
                                    sock,
                                    vrf.clone(),
                                    v6,
                                    self.reflector.clone(),
                                )),
                            ),
                        );
                    }
                    Err(e) => debug!(vrf = %vrf, v6, error = %e, "bfd reflector socket not opened"),
                }
            }
        }
    }
}

type RxTasks = HashMap<(String, bool, bool), (u32, JoinHandle<()>)>;

/// The real transport. Owns the receive sockets and feeds the `Demux`.
pub struct UdpNet {
    watchdog_socket: PathBuf,
    demux: Demux,
    /// (table, v6, multihop) -> (VRF ifindex it was opened for, its receive task).
    rx: Mutex<RxTasks>,
    /// The shared rtnetlink handle for neighbour lookups, made on first use.
    nl: Mutex<Option<rtnetlink::Handle>>,
}

impl UdpNet {
    pub fn new(watchdog_socket: PathBuf, demux: Demux) -> Arc<Self> {
        Arc::new(UdpNet {
            watchdog_socket,
            demux,
            rx: Mutex::default(),
            nl: Mutex::default(),
        })
    }

    fn netlink(&self) -> io::Result<rtnetlink::Handle> {
        let mut nl = self.nl.lock().unwrap();
        if let Some(h) = nl.as_ref() {
            return Ok(h.clone());
        }
        let (conn, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(conn);
        *nl = Some(handle.clone());
        Ok(handle)
    }

    async fn try_open_echo(
        &self,
        key: &SessionKey,
        disc: u32,
        unaffiliated: bool,
    ) -> io::Result<EchoPath> {
        let vrf = vrf_name(&self.watchdog_socket, &key.table)
            .await
            .ok_or_else(|| io::Error::other("the table has no VRF yet"))?;
        let (addr, iface) = local_for(key.peer, &vrf, key.interface.as_deref())
            .ok_or_else(|| io::Error::other("no interface towards the peer"))?;
        let local = key.local.unwrap_or(addr);
        let ethertype = if local.is_ipv4() { 0x0800 } else { 0x86dd };
        let sock = Arc::new(Mutex::new(Arc::new(L2Unicast::open(
            &iface,
            ethertype,
            echo::ECHO_PORT,
        )?)));
        let ifindex = u32::try_from(nos_l2_socket::if_index(&iface)?).unwrap_or(0);
        let mac = Arc::new(Mutex::new(None));
        let (seq_tx, seq_rx) = tokio::sync::mpsc::channel(64);
        let rx = tokio::spawn(echo_rx_loop(
            sock.clone(),
            iface.clone(),
            ethertype,
            local,
            disc,
            unaffiliated,
            seq_tx,
        ));
        let kick = if unaffiliated {
            let device = key.interface.as_deref().unwrap_or(&vrf);
            Some(UdpTx::new(device, &vrf, key, echo::ECHO_PORT, false)?)
        } else {
            None
        };
        let neigh = tokio::spawn(neigh_loop(
            self.netlink()?,
            key.peer,
            ifindex,
            mac.clone(),
            kick,
        ));
        let sport = 49152 + u16::try_from(rand_u32() % 16384).unwrap_or(0);
        Ok(EchoPath {
            tx: Arc::new(L2Echo {
                sock,
                mac,
                local,
                sport,
            }),
            rx: seq_rx,
            tasks: vec![rx.abort_handle(), neigh.abort_handle()],
        })
    }

    fn open_micro(&self, key: &SessionKey) -> io::Result<Arc<dyn Tx>> {
        let member = key
            .interface
            .clone()
            .ok_or_else(|| io::Error::other("micro-BFD session without a member"))?;
        let local = key
            .local
            .ok_or_else(|| io::Error::other("micro-BFD session without a source address"))?;
        let ethertype = if local.is_ipv4() { 0x0800 } else { 0x86dd };
        let ip = Arc::new(Mutex::new(Arc::new(micro_open(&member, ethertype, false)?)));
        let tag = Arc::new(Mutex::new(Arc::new(micro_open(&member, ethertype, true)?)));
        let rx = [(ip.clone(), false), (tag, true)]
            .into_iter()
            .map(|(slot, tagged)| {
                tokio::spawn(micro_rx_loop(
                    slot,
                    ethertype,
                    tagged,
                    member.clone(),
                    local,
                    self.demux.clone(),
                ))
                .abort_handle()
            })
            .collect();
        Ok(Arc::new(MicroTx {
            sock: ip,
            local,
            peer: key.peer,
            sport: 49152 + u16::try_from(rand_u32() % 16384).unwrap_or(0),
            rx,
        }))
    }

    /// Starts the table's receive socket, or restarts it when the VRF device
    /// behind it was recreated (a `nos-ribd` restart): the old socket is
    /// bound to the deleted device's index.
    fn ensure_rx(&self, table: &str, vrf: &str, v6: bool, multihop: bool) -> io::Result<()> {
        let idx = ifindex(vrf);
        let mut rx = self.rx.lock().unwrap();
        if let Some((have, task)) = rx.get(&(table.to_string(), v6, multihop)) {
            if *have == idx && !task.is_finished() {
                return Ok(());
            }
            task.abort();
        }
        let sock = rx_socket(vrf, v6, port(multihop))?;
        let task = tokio::spawn(rx_loop(
            sock,
            table.to_string(),
            vrf.to_string(),
            v6,
            multihop,
            self.demux.clone(),
        ));
        rx.insert((table.to_string(), v6, multihop), (idx, task));
        Ok(())
    }
}

#[async_trait]
impl Net for UdpNet {
    async fn open(&self, key: &SessionKey) -> io::Result<Arc<dyn Tx>> {
        if key.aggregate.is_some() {
            return self.open_micro(key);
        }
        let vrf = vrf_name(&self.watchdog_socket, &key.table)
            .await
            .ok_or_else(|| io::Error::other("the table has no VRF yet"))?;
        self.ensure_rx(&key.table, &vrf, key.peer.is_ipv6(), key.multihop)?;
        let device = key
            .interface
            .as_deref()
            .filter(|_| !key.multihop)
            .unwrap_or(&vrf);
        Ok(Arc::new(UdpTx::new(
            device,
            &vrf,
            key,
            port(key.multihop),
            false,
        )?))
    }

    async fn listen(&self, table: &str, v6: bool) -> io::Result<()> {
        let vrf = vrf_name(&self.watchdog_socket, table)
            .await
            .ok_or_else(|| io::Error::other("the table has no VRF yet"))?;
        self.ensure_rx(table, &vrf, v6, false)
    }

    async fn open_sbfd(&self, key: &SessionKey) -> io::Result<SbfdPath> {
        let vrf = vrf_name(&self.watchdog_socket, &key.table)
            .await
            .ok_or_else(|| io::Error::other("the table has no VRF yet"))?;
        let device = key
            .interface
            .as_deref()
            .filter(|_| !key.multihop)
            .unwrap_or(&vrf);
        // Its own source port (never 7784, unique per session: `bind` fails
        // on a port in use) so the reflections find their way back.
        let tx = Arc::new(UdpTx::new(device, &vrf, key, sbfd::PORT, true)?);
        let rx = register_fd(tx.socket().try_clone()?)?;
        let (out, rx_chan) = tokio::sync::mpsc::channel(64);
        let task = tokio::spawn(sbfd_rx_loop(rx, tx.clone(), key.peer, out));
        Ok(SbfdPath {
            tx,
            rx: rx_chan,
            task: task.abort_handle(),
        })
    }

    async fn open_echo(&self, key: &SessionKey, disc: u32, unaffiliated: bool) -> Option<EchoPath> {
        // ponytail: tried once, at session start. A session whose interface
        // has no address yet never runs Echo until it is re-registered.
        match self.try_open_echo(key, disc, unaffiliated).await {
            Ok(p) => Some(p),
            Err(e) => {
                warn!(peer = %key.peer, table = %key.table, error = %e, "bfd echo unavailable");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_the_cap_and_resets() {
        let mut d = BACKOFF_MIN;
        for want in [20, 40, 80, 160, 320, 640, 1000, 1000] {
            d = next_backoff(d);
            assert_eq!(d, Duration::from_millis(want));
        }
        let mut b = Backoff::new();
        assert_eq!(b.failed(), (true, Duration::from_millis(10)));
        assert_eq!(b.failed(), (false, Duration::from_millis(20)));
        assert!(b.ok());
        assert!(!b.ok());
        assert_eq!(b.failed(), (true, Duration::from_millis(10)));
    }

    #[test]
    fn rebuild_needs_a_changed_index_and_a_reason() {
        let s = Duration::from_millis(100);
        let l = Duration::from_secs(1);
        assert!(!needs_rebuild((3, 4), (3, 4), l, true));
        assert!(!needs_rebuild((3, 4), (3, 9), s, false));
        assert!(needs_rebuild((3, 4), (3, 9), l, false));
        assert!(needs_rebuild((3, 4), (3, 9), s, true));
        assert!(!needs_rebuild((3, 4), (3, 0), l, true));
    }
}
