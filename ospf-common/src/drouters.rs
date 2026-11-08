//! `AllDRouters` multicast membership (RFC 2328 A.1 `224.0.0.6`, RFC 5340 A.1
//! `ff02::6`): the one socket-option helper in this crate. Deciding *when* to
//! join (election outcome, link type) stays in the daemons.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};

use socket2::Socket;

pub const ALL_D_ROUTERS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 6);
pub const ALL_D_ROUTERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 6);

// Linux errno values (the daemons are Linux-only); avoids a libc dependency.
const EADDRINUSE: i32 = 98;
const EADDRNOTAVAIL: i32 = 99;

/// The interface to join on; implies the group's address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Iface {
    V4(Ipv4Addr),
    V6(u32),
}

/// RFC 2328 §8.2: only the DR and BDR listen on `AllDRouters`, never on a
/// point-to-point link.
#[must_use]
pub const fn wants_all_drouters(is_dr_or_backup: bool, point_to_point: bool) -> bool {
    is_dr_or_backup && !point_to_point
}

/// Where a flooded LSU or delayed `LSAck` goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    /// One unicast per adjacent neighbor.
    Unicast,
    AllSpfRouters,
    AllDRouters,
}

impl Dest {
    /// The `dest=` log value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unicast => "unicast",
            Self::AllSpfRouters => "all-spf-routers",
            Self::AllDRouters => "all-drouters",
        }
    }
}

/// RFC 2328 §13.3 step 5 / §13.5: on a broadcast network a DR or Backup
/// multicasts to `AllSPFRouters`, any other router to `AllDRouters`; every
/// other network type stays unicast.
#[must_use]
pub const fn flood_dest(broadcast: bool, dr_or_backup: bool) -> Dest {
    match (broadcast, dr_or_backup) {
        (false, _) => Dest::Unicast,
        (true, true) => Dest::AllSpfRouters,
        (true, false) => Dest::AllDRouters,
    }
}

/// Idempotent `AllDRouters` membership for one socket.
#[derive(Default)]
pub struct AllDRouters {
    joined: AtomicBool,
}

impl AllDRouters {
    /// Join or leave so membership equals `want`. Returns whether the state
    /// changed. Already-in-state kernel errors are tolerated; any other error
    /// leaves the state unchanged so the next call retries.
    ///
    /// # Errors
    /// The socket-option error, other than the tolerated ones.
    pub fn sync(&self, socket: &Socket, iface: Iface, want: bool) -> io::Result<bool> {
        if self.joined.load(Ordering::Acquire) == want {
            return Ok(false);
        }
        let res = match (iface, want) {
            (Iface::V4(i), true) => socket.join_multicast_v4(&ALL_D_ROUTERS_V4, &i),
            (Iface::V4(i), false) => socket.leave_multicast_v4(&ALL_D_ROUTERS_V4, &i),
            (Iface::V6(i), true) => socket.join_multicast_v6(&ALL_D_ROUTERS_V6, i),
            (Iface::V6(i), false) => socket.leave_multicast_v6(&ALL_D_ROUTERS_V6, i),
        };
        if let Err(e) = res {
            let tolerated = match e.raw_os_error() {
                Some(n) if want => n == EADDRINUSE || n == EADDRNOTAVAIL,
                Some(n) => n == EADDRNOTAVAIL,
                None => false,
            };
            if !tolerated {
                return Err(e);
            }
        }
        self.joined.store(want, Ordering::Release);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Protocol, Type};

    #[test]
    fn truth_table() {
        assert!(wants_all_drouters(true, false));
        assert!(!wants_all_drouters(true, true));
        assert!(!wants_all_drouters(false, false));
        assert!(!wants_all_drouters(false, true));
    }

    #[test]
    fn flood_dest_truth_table() {
        assert_eq!(flood_dest(true, true), Dest::AllSpfRouters);
        assert_eq!(flood_dest(true, false), Dest::AllDRouters);
        assert_eq!(flood_dest(false, true), Dest::Unicast);
        assert_eq!(flood_dest(false, false), Dest::Unicast);
        assert_eq!(Dest::Unicast.as_str(), "unicast");
        assert_eq!(Dest::AllSpfRouters.as_str(), "all-spf-routers");
        assert_eq!(Dest::AllDRouters.as_str(), "all-drouters");
    }

    fn udp(d: Domain) -> Socket {
        Socket::new(d, Type::DGRAM, Some(Protocol::UDP)).unwrap()
    }

    #[test]
    #[cfg_attr(miri, ignore = "real UDP socket")]
    fn v4_idempotent_cycle() {
        let s = udp(Domain::IPV4);
        let a = AllDRouters::default();
        let i = Iface::V4(Ipv4Addr::LOCALHOST);
        assert!(a.sync(&s, i, true).unwrap());
        assert!(!a.sync(&s, i, true).unwrap());
        assert!(a.sync(&s, i, false).unwrap());
        assert!(!a.sync(&s, i, false).unwrap());
        assert!(a.sync(&s, i, true).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "real UDP socket")]
    fn v4_already_joined_is_tolerated() {
        let s = udp(Domain::IPV4);
        s.join_multicast_v4(&ALL_D_ROUTERS_V4, &Ipv4Addr::LOCALHOST)
            .unwrap();
        let a = AllDRouters::default();
        assert!(a.sync(&s, Iface::V4(Ipv4Addr::LOCALHOST), true).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "real UDP socket")]
    fn v4_leave_when_never_joined_is_tolerated() {
        // Flag says joined, kernel says not: leave hits EADDRNOTAVAIL.
        let s = udp(Domain::IPV4);
        let a = AllDRouters::default();
        a.joined.store(true, Ordering::Release);
        assert!(a.sync(&s, Iface::V4(Ipv4Addr::LOCALHOST), false).unwrap());
        assert!(!a.joined.load(Ordering::Acquire));
    }

    #[test]
    #[cfg_attr(miri, ignore = "real UDP socket")]
    fn v6_idempotent_cycle() {
        // lo is ifindex 1 on Linux.
        let s = udp(Domain::IPV6);
        let a = AllDRouters::default();
        let i = Iface::V6(1);
        assert!(a.sync(&s, i, true).unwrap(), "IPv6 loopback required");
        assert!(!a.sync(&s, i, true).unwrap());
        assert!(a.sync(&s, i, false).unwrap());
        assert!(!a.sync(&s, i, false).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "real UDP socket")]
    fn failure_leaves_state_unchanged() {
        // v6 join on a v4 socket is rejected with a non-tolerated error.
        let s = udp(Domain::IPV4);
        let a = AllDRouters::default();
        assert!(a.sync(&s, Iface::V6(1), true).is_err());
        assert!(!a.sync(&s, Iface::V6(1), false).unwrap());
    }
}
