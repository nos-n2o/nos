//! RFC 4724 graceful restart with RFC 8538's notification (N) bit: the pure
//! decisions — what a peer's capability says, whether a session that just
//! ended keeps its routes, and which Cease goes out as a Hard Reset. The
//! state lives in `rib.rs` (`BgpRib.gr`, the stale sets and deadlines) and
//! the wire format in `message.rs`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use nos_proto::AddressFamily;

use crate::message::{CeaseSubcode, GrFamily, GracefulRestartCap};

/// The families this crate knows, as one bit each (`AddressFamily::ALL`
/// order) — keeps `PeerGr` `Copy`, like `fsm::RemoteInfo`.
fn bit(family: AddressFamily) -> u16 {
    match family {
        AddressFamily::Ipv4Unicast => 1,
        AddressFamily::Ipv6Unicast => 2,
        AddressFamily::L2vpnEvpn => 4,
        AddressFamily::Ipv4Flowspec => 8,
        AddressFamily::Ipv6Flowspec => 16,
        AddressFamily::Vpnv4Unicast => 32,
        AddressFamily::Vpnv6Unicast => 64,
        AddressFamily::RtConstraint => 128,
        AddressFamily::Vpnv4Flowspec => 256,
        AddressFamily::Vpnv6Flowspec => 512,
    }
}

/// The `(afi, safi)` of a family this crate knows.
pub fn afi_safi(family: AddressFamily) -> (u16, u8) {
    match family {
        AddressFamily::Ipv4Unicast => (1, 1),
        AddressFamily::Ipv6Unicast => (2, 1),
        AddressFamily::L2vpnEvpn => (crate::message::AFI_L2VPN, crate::message::SAFI_EVPN),
        AddressFamily::Ipv4Flowspec => (1, crate::message::SAFI_FLOWSPEC),
        AddressFamily::Ipv6Flowspec => (2, crate::message::SAFI_FLOWSPEC),
        AddressFamily::Vpnv4Unicast => (1, crate::message::SAFI_VPN),
        AddressFamily::Vpnv6Unicast => (2, crate::message::SAFI_VPN),
        AddressFamily::RtConstraint => (1, crate::message::SAFI_RTC),
        AddressFamily::Vpnv4Flowspec => (1, crate::message::SAFI_FLOWSPEC_VPN),
        AddressFamily::Vpnv6Flowspec => (2, crate::message::SAFI_FLOWSPEC_VPN),
    }
}

/// The family an `(afi, safi)` names, if this crate knows it.
pub fn family_of(afi: u16, safi: u8) -> Option<AddressFamily> {
    AddressFamily::ALL
        .into_iter()
        .find(|f| afi_safi(*f) == (afi, safi))
}

/// A peer's graceful restart capability, as received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerGr {
    pub restart: bool,
    pub notification: bool,
    pub time: u16,
    /// Families listed in the capability (a family this crate doesn't know
    /// is dropped), and the ones among them whose F bit is set.
    families: u16,
    forwarding: u16,
}

impl PeerGr {
    pub fn from_cap(cap: &GracefulRestartCap) -> Self {
        let mut gr = PeerGr {
            restart: cap.restart,
            notification: cap.notification,
            time: cap.time,
            families: 0,
            forwarding: 0,
        };
        for f in &cap.families {
            if let Some(family) = family_of(f.afi, f.safi) {
                gr.families |= bit(family);
                if f.forwarding {
                    gr.forwarding |= bit(family);
                }
            }
        }
        gr
    }

    pub fn has(&self, family: AddressFamily) -> bool {
        self.families & bit(family) != 0
    }

    /// F bit: the peer kept its forwarding state for `family`.
    pub fn forwarding(&self, family: AddressFamily) -> bool {
        self.forwarding & bit(family) != 0
    }

    /// The listed families, in `AddressFamily::ALL` order.
    pub fn families(&self) -> Vec<AddressFamily> {
        AddressFamily::ALL
            .into_iter()
            .filter(|f| self.has(*f))
            .collect()
    }
}

/// Our own capability: N always set (RFC 8538, no knob), one tuple per
/// configured family, each with F = `forwarding`.
pub fn our_cap(
    time: u16,
    families: &[AddressFamily],
    restart: bool,
    forwarding: bool,
) -> GracefulRestartCap {
    GracefulRestartCap {
        restart,
        notification: true,
        time,
        families: families
            .iter()
            .map(|f| {
                let (afi, safi) = afi_safi(*f);
                GrFamily {
                    afi,
                    safi,
                    forwarding,
                }
            })
            .collect(),
    }
}

/// How a session ended, as far as graceful restart is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disconnect {
    /// The TCP connection went away (EOF, error), or a new connection
    /// replaced it (RFC 4724 §4.2).
    Transport,
    /// A NOTIFICATION other than a Hard Reset, sent or received while N was
    /// exchanged — hold-timer expiry included (RFC 8538 §4).
    Graceful,
    /// Anything else: a Hard Reset, any NOTIFICATION without N, or a peer
    /// being deconfigured/shut.
    Hard,
}

/// Whether a NOTIFICATION `(code, subcode)` ending a session keeps the
/// peer's routes: with N, everything but a Hard Reset (Cease/9).
pub fn notification_disconnect(code: u8, subcode: u8, n_exchanged: bool) -> Disconnect {
    if n_exchanged && !(code == 6 && subcode == CeaseSubcode::HardReset as u8) {
        Disconnect::Graceful
    } else {
        Disconnect::Hard
    }
}

/// Whether a session ending with `kind` keeps the routes of a peer whose
/// last capability is `peer` (RFC 4724 §4.2, RFC 8538 §4): never on a Hard
/// end, never for a peer with no capability or one listing no family, and on
/// a NOTIFICATION only once N was exchanged.
pub fn retains(kind: Disconnect, peer: Option<&PeerGr>) -> bool {
    let Some(gr) = peer else {
        return false;
    };
    match kind {
        Disconnect::Hard => false,
        Disconnect::Graceful => gr.notification && gr.families != 0,
        Disconnect::Transport => gr.families != 0,
    }
}

/// RFC 8538 §5.1: with N exchanged, these Cease subcodes go out as a Hard
/// Reset wrapping the original; the rest (Other Configuration Change, …)
/// stay graceful. Without N, never (§4).
pub fn sends_hard_reset(subcode: CeaseSubcode, n_exchanged: bool) -> bool {
    n_exchanged
        && matches!(
            subcode,
            CeaseSubcode::MaximumPrefixesReached
                | CeaseSubcode::AdministrativeShutdown
                | CeaseSubcode::PeerDeconfigured
                | CeaseSubcode::AdministrativeReset
        )
}

/// RFC 4724 §4.1 selection deferral of a restarting speaker (one whose
/// `nos-ribd` still held BGP routes at startup): nothing leaves the process
/// — UPDATEs, End-of-RIB, kernel and EVPN pushes — until every configured
/// peer has sent End-of-RIB for each negotiated family, or the
/// `selection-deferral-time` runs out. The Loc-RIB still fills meanwhile.
#[derive(Debug)]
pub struct Deferral {
    started: Instant,
    until: Instant,
    restart_time: Duration,
    /// Configured, non-shut peers not done yet.
    waiting: HashSet<IpAddr>,
    /// Of those, the ones `Established`: families still owing End-of-RIB.
    pending: HashMap<IpAddr, HashSet<AddressFamily>>,
    /// `nos-ribd`'s redistributed routes are in the Loc-RIB, so our own
    /// End-of-RIB won't go out without them.
    // ponytail: EVPN routes from nos-fdbd / IP-VRF tables aren't waited
    // for; one arriving after the deferral is sent on its own, after a
    // helper may already have purged our stale copy.
    local: bool,
}

impl Deferral {
    pub fn new(
        now: Instant,
        restart_time: u16,
        selection_deferral_time: u16,
        peers: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        Deferral {
            started: now,
            until: now + Duration::from_secs(u64::from(selection_deferral_time)),
            restart_time: Duration::from_secs(u64::from(restart_time)),
            waiting: peers.into_iter().collect(),
            pending: HashMap::new(),
            local: false,
        }
    }

    /// `peer` reached `Established`. One that sent no capability (§4.1:
    /// it won't send End-of-RIB) or is restarting itself (R bit — two
    /// restarting speakers would otherwise wait for each other) is done.
    pub fn established(
        &mut self,
        peer: IpAddr,
        gr: Option<PeerGr>,
        families: &HashSet<AddressFamily>,
    ) {
        if !self.waiting.contains(&peer) {
            return;
        }
        match gr {
            Some(g) if !g.restart && !families.is_empty() => {
                self.pending.insert(peer, families.clone());
            }
            _ => self.done(peer),
        }
    }

    pub fn end_of_rib(&mut self, peer: IpAddr, family: AddressFamily) {
        if let Some(left) = self.pending.get_mut(&peer) {
            left.remove(&family);
            if left.is_empty() {
                self.done(peer);
            }
        }
    }

    /// The session ended; a `hard` end (a peer deconfigured or shut, or a
    /// Hard Reset) stops waiting for it altogether.
    pub fn disconnected(&mut self, peer: IpAddr, hard: bool) {
        self.pending.remove(&peer);
        if hard {
            self.waiting.remove(&peer);
        }
    }

    /// Stops waiting for a peer still not `Established` our restart time
    /// after we started: a dead peer must not hold every update for the
    /// whole deferral, past a helper's stale timer (#12, owner Q9).
    pub fn drop_dead(&mut self, now: Instant, established: impl Fn(IpAddr) -> bool) {
        if now >= self.started + self.restart_time {
            self.waiting.retain(|p| established(*p));
        }
    }

    /// `nos-ribd`'s first redistribution snapshot arrived.
    pub fn local_routes_in(&mut self) {
        self.local = true;
    }

    /// The peers still waited for, sorted (`reconcile::tests`).
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> Vec<IpAddr> {
        let mut w: Vec<IpAddr> = self.waiting.iter().copied().collect();
        w.sort();
        w
    }

    /// Why the deferral is over, if it is.
    pub fn over(&self, now: Instant) -> Option<&'static str> {
        if self.waiting.is_empty() && self.local {
            Some("end-of-rib")
        } else if now >= self.until {
            Some("timer")
        } else {
            None
        }
    }

    fn done(&mut self, peer: IpAddr) {
        self.waiting.remove(&peer);
        self.pending.remove(&peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(notification: bool, families: &[(AddressFamily, bool)]) -> PeerGr {
        PeerGr::from_cap(&GracefulRestartCap {
            restart: false,
            notification,
            time: 120,
            families: families
                .iter()
                .map(|(f, forwarding)| {
                    let (afi, safi) = afi_safi(*f);
                    GrFamily {
                        afi,
                        safi,
                        forwarding: *forwarding,
                    }
                })
                .collect(),
        })
    }

    #[test]
    fn every_family_has_its_own_bit_and_tuple_including_rtc() {
        let mut seen = 0u16;
        for f in AddressFamily::ALL {
            assert_eq!(seen & bit(f), 0, "{f} shares a bit");
            seen |= bit(f);
            let (afi, safi) = afi_safi(f);
            assert_eq!(family_of(afi, safi), Some(f));
        }
        assert_eq!(seen, 0x3ff);
        assert_eq!(afi_safi(AddressFamily::RtConstraint), (1, 132));
        let gr = cap(true, &[(AddressFamily::RtConstraint, true)]);
        assert!(gr.has(AddressFamily::RtConstraint) && !gr.has(AddressFamily::Vpnv4Unicast));
    }

    #[test]
    fn capability_families_and_f_bits() {
        let gr = cap(
            true,
            &[
                (AddressFamily::Ipv4Unicast, true),
                (AddressFamily::L2vpnEvpn, false),
            ],
        );
        assert!(gr.has(AddressFamily::Ipv4Unicast) && gr.forwarding(AddressFamily::Ipv4Unicast));
        assert!(gr.has(AddressFamily::L2vpnEvpn) && !gr.forwarding(AddressFamily::L2vpnEvpn));
        assert!(!gr.has(AddressFamily::Ipv6Unicast));
        assert_eq!(
            gr.families(),
            [AddressFamily::Ipv4Unicast, AddressFamily::L2vpnEvpn]
        );
    }

    /// The retention table over end × N × tuples.
    #[test]
    fn retention_decision_table() {
        let v4 = [(AddressFamily::Ipv4Unicast, true)];
        let with_n = cap(true, &v4);
        let without_n = cap(false, &v4);
        let no_tuples = cap(true, &[]);
        for (kind, gr, want) in [
            (Disconnect::Transport, Some(&with_n), true),
            (Disconnect::Transport, Some(&without_n), true),
            (Disconnect::Transport, Some(&no_tuples), false),
            (Disconnect::Transport, None, false),
            (Disconnect::Graceful, Some(&with_n), true),
            (Disconnect::Graceful, Some(&without_n), false),
            (Disconnect::Hard, Some(&with_n), false),
        ] {
            assert_eq!(retains(kind, gr), want, "{kind:?} {gr:?}");
        }
        assert_eq!(notification_disconnect(6, 6, true), Disconnect::Graceful);
        assert_eq!(notification_disconnect(4, 0, true), Disconnect::Graceful);
        assert_eq!(notification_disconnect(6, 9, true), Disconnect::Hard);
        assert_eq!(notification_disconnect(6, 6, false), Disconnect::Hard);
    }

    #[test]
    fn deferral_ends_on_the_last_end_of_rib_or_the_timers() {
        let (a, b) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        let v4 = HashSet::from([AddressFamily::Ipv4Unicast]);
        let t0 = Instant::now();
        let gr = Some(cap(true, &[(AddressFamily::Ipv4Unicast, true)]));

        let mut d = Deferral::new(t0, 120, 360, [a, b]);
        d.local_routes_in();
        d.established(a, gr, &v4);
        d.end_of_rib(a, AddressFamily::Ipv6Unicast);
        assert_eq!(d.over(t0), None);
        d.end_of_rib(a, AddressFamily::Ipv4Unicast);
        // b never came up: dropped once our restart time has passed.
        d.drop_dead(t0 + Duration::from_secs(119), |_| false);
        assert_eq!(d.over(t0), None);
        d.drop_dead(t0 + Duration::from_secs(120), |_| false);
        assert_eq!(d.over(t0), Some("end-of-rib"));

        // An established GR peer that never sends End-of-RIB: the timer.
        let mut d = Deferral::new(t0, 120, 360, [a]);
        d.established(a, gr, &v4);
        d.drop_dead(t0 + Duration::from_secs(200), |p| p == a);
        assert_eq!(d.over(t0 + Duration::from_secs(359)), None);
        assert_eq!(d.over(t0 + Duration::from_secs(360)), Some("timer"));

        // A hard end (deconfigured) stops waiting; a soft one doesn't.
        let mut d = Deferral::new(t0, 120, 360, [a]);
        d.established(a, gr, &v4);
        d.disconnected(a, true);
        // ...and nothing goes out before the redistributed routes are in.
        assert_eq!(d.over(t0), None);
        d.local_routes_in();
        assert_eq!(d.over(t0), Some("end-of-rib"));
        let mut d = Deferral::new(t0, 120, 360, [a]);
        d.local_routes_in();
        d.established(a, gr, &v4);
        d.disconnected(a, false);
        assert_eq!(d.over(t0), None);
        d.disconnected(a, true);
        assert_eq!(d.over(t0), Some("end-of-rib"));
    }

    #[test]
    fn hard_reset_per_cease_subcode() {
        use CeaseSubcode::*;
        for s in [
            MaximumPrefixesReached,
            AdministrativeShutdown,
            PeerDeconfigured,
            AdministrativeReset,
        ] {
            assert!(sends_hard_reset(s, true), "{s:?}");
            assert!(!sends_hard_reset(s, false), "{s:?}");
        }
        assert!(!sends_hard_reset(OtherConfigurationChange, true));
        assert!(!sends_hard_reset(ConnectionCollisionResolution, true));
        // RFC 9384: Cease/10 is graceful with N, a Hard Reset only when the
        // caller forces it (`FsmCommand::BfdDown { flush }`).
        assert_eq!(BfdDown as u8, 10);
        assert!(!sends_hard_reset(BfdDown, true));
        assert_eq!(notification_disconnect(6, 10, true), Disconnect::Graceful);
        assert_eq!(notification_disconnect(6, 10, false), Disconnect::Hard);
    }
}
