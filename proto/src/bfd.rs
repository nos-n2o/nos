//! `nos-bfdd`'s IPC protocol (RFC 5880 sessions on behalf of other daemons).
//! One-shot request/event pairs framed by `IpcCodec` over a Unix socket
//! resolved via the watchdog broker (`ServiceRef::Bfd`, a single system-wide
//! instance). Clients (`bgpd`/`ribd`/`ospfd`/`ospfv3d`) `Register` a session
//! and are told of state changes; `nos-cli`/`nos-restd` query with `GetSessions`.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::schema::{BfdAuthMethod, BfdProfile};

/// What identifies one BFD session: a routing table, the remote system and
/// the path to it (RFC 5881 single-hop is bound to an interface, RFC 5883
/// multihop is not).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionKey {
    /// Routing table (VRF) the session runs in.
    pub table: String,
    /// Remote system's address.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub peer: IpAddr,
    /// Local source address, if pinned.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub local: Option<IpAddr>,
    /// Egress interface, required for single-hop sessions on link-local addresses.
    pub interface: Option<String>,
    /// Whether this is a multihop session (RFC 5883) rather than single-hop (RFC 5881).
    pub multihop: bool,
    /// RFC 7130 micro-BFD: the `PortAggregate` this session probes a member of
    /// (`interface` is the member, `table` is empty). Appended last for postcard.
    #[serde(default)]
    pub aggregate: Option<String>,
}

/// RFC 5880 §4.1 `Sta` values.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BfdState {
    /// `AdminDown` (RFC 5880 section 4.1): administratively held down.
    AdminDown,
    /// `Down`: no session, or the remote reported Down.
    Down,
    /// `Init`: the remote is heard but has not yet seen us.
    Init,
    /// `Up`: bidirectional connectivity confirmed.
    Up,
}

impl BfdState {
    /// The 2-bit wire value.
    pub const fn code(self) -> u8 {
        match self {
            BfdState::AdminDown => 0,
            BfdState::Down => 1,
            BfdState::Init => 2,
            BfdState::Up => 3,
        }
    }

    /// Decodes the 2-bit State field of a BFD control packet (RFC 5880 section 4.1).
    pub const fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => BfdState::AdminDown,
            1 => BfdState::Down,
            2 => BfdState::Init,
            3 => BfdState::Up,
            _ => return None,
        })
    }
}

impl fmt::Display for BfdState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BfdState::AdminDown => "admin-down",
            BfdState::Down => "down",
            BfdState::Init => "init",
            BfdState::Up => "up",
        })
    }
}

/// RFC 5880 §4.1 diagnostic codes 0-8.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BfdDiag {
    /// No diagnostic (code 0, RFC 5880 section 4.1).
    NoDiagnostic,
    /// Control Detection Time Expired (code 1).
    ControlDetectionTimeExpired,
    /// Echo Function Failed (code 2).
    EchoFunctionFailed,
    /// Neighbor Signaled Session Down (code 3).
    NeighborSignaledSessionDown,
    /// Forwarding Plane Reset (code 4).
    ForwardingPlaneReset,
    /// Path Down (code 5).
    PathDown,
    /// Concatenated Path Down (code 6).
    ConcatenatedPathDown,
    /// Administratively Down (code 7).
    AdministrativelyDown,
    /// Reverse Concatenated Path Down (code 8).
    ReverseConcatenatedPathDown,
}

impl BfdDiag {
    /// The 5-bit wire value.
    pub const fn code(self) -> u8 {
        match self {
            BfdDiag::NoDiagnostic => 0,
            BfdDiag::ControlDetectionTimeExpired => 1,
            BfdDiag::EchoFunctionFailed => 2,
            BfdDiag::NeighborSignaledSessionDown => 3,
            BfdDiag::ForwardingPlaneReset => 4,
            BfdDiag::PathDown => 5,
            BfdDiag::ConcatenatedPathDown => 6,
            BfdDiag::AdministrativelyDown => 7,
            BfdDiag::ReverseConcatenatedPathDown => 8,
        }
    }

    /// Decodes the 5-bit Diagnostic field of a BFD control packet (RFC 5880 section 4.1).
    pub const fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => BfdDiag::NoDiagnostic,
            1 => BfdDiag::ControlDetectionTimeExpired,
            2 => BfdDiag::EchoFunctionFailed,
            3 => BfdDiag::NeighborSignaledSessionDown,
            4 => BfdDiag::ForwardingPlaneReset,
            5 => BfdDiag::PathDown,
            6 => BfdDiag::ConcatenatedPathDown,
            7 => BfdDiag::AdministrativelyDown,
            8 => BfdDiag::ReverseConcatenatedPathDown,
            _ => return None,
        })
    }
}

impl fmt::Display for BfdDiag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BfdDiag::NoDiagnostic => "no-diagnostic",
            BfdDiag::ControlDetectionTimeExpired => "control-detection-time-expired",
            BfdDiag::EchoFunctionFailed => "echo-function-failed",
            BfdDiag::NeighborSignaledSessionDown => "neighbor-signaled-session-down",
            BfdDiag::ForwardingPlaneReset => "forwarding-plane-reset",
            BfdDiag::PathDown => "path-down",
            BfdDiag::ConcatenatedPathDown => "concatenated-path-down",
            BfdDiag::AdministrativelyDown => "administratively-down",
            BfdDiag::ReverseConcatenatedPathDown => "reverse-concatenated-path-down",
        })
    }
}

/// One session, for `show bfd sessions`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BfdSessionView {
    /// Session identity.
    pub key: SessionKey,
    /// Current session state.
    pub state: BfdState,
    /// Diagnostic for the last state change.
    pub diag: BfdDiag,
    /// My Discriminator (RFC 5880 section 6.8.1).
    pub local_discriminator: u32,
    /// Your Discriminator learned from the peer; zero until heard.
    pub remote_discriminator: u32,
    /// Negotiated transmit interval, microseconds.
    pub tx_interval_us: u32,
    /// Detection time, microseconds.
    pub detection_time_us: u32,
    /// The configured authentication (never the key), `None` when off.
    pub auth_method: Option<BfdAuthMethod>,
    /// Key ID of the authentication key in use, if the session is authenticated (RFC 5880 section 6.7).
    pub auth_key_id: Option<u8>,
    /// Packets dropped by RFC 5880 §6.7 authentication since the session started.
    pub auth_failures: u64,
    /// The Echo function is running (RFC 5880 §6.4).
    pub echo_active: bool,
    /// Negotiated Echo transmit interval, microseconds; 0 while inactive.
    pub echo_interval_us: u32,
    /// RFC 9747 unaffiliated Echo: no Control traffic at all.
    pub echo_only: bool,
    /// RFC 9764: the UDP payload size Control packets are padded to, 0 when not padded.
    pub tx_pdu_bytes: u32,
    /// RFC 7880 S-BFD: which end of which protocol this session is.
    pub kind: BfdSessionKind,
}

/// What a session is: a classical RFC 5880 peer, or an RFC 7880 S-BFD
/// initiator probing a stateless reflector.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum BfdSessionKind {
    /// A regular BFD session (RFC 5880).
    #[default]
    Classical,
    /// A Seamless BFD initiator session (RFC 7880).
    SbfdInitiator,
    /// RFC 9468: created by an unsolicited packet, owned by no client.
    Unsolicited,
}

impl fmt::Display for BfdSessionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BfdSessionKind::Classical => "classical",
            BfdSessionKind::SbfdInitiator => "sbfd-initiator",
            BfdSessionKind::Unsolicited => "unsolicited",
        })
    }
}

/// Why the S-BFD reflector dropped a packet, counted per reason.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReflectorDiscards {
    /// Not a valid BFD Control packet.
    pub malformed: u64,
    /// UDP source port 7784 (RFC 7881 §6).
    pub source_port: u64,
    /// A martian source address (RFC 7881 §7).
    pub martian: u64,
    /// Not in `allow-from`.
    pub filtered: u64,
    /// Over the reflector's global packet rate.
    pub rate_limited: u64,
    /// The A bit is set: reflector authentication is not built yet.
    pub authenticated: u64,
    /// D bit clear (RFC 7880 §7.2.3).
    pub demand_clear: u64,
    /// Your Discriminator is not one of the reflector's.
    pub unknown_discriminator: u64,
}

/// The S-BFD reflector, for `show bfd reflector`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReflectorView {
    /// The discriminators answered for, as 32-bit values.
    pub discriminators: Vec<u32>,
    /// Packets that reached the reflector.
    pub received: u64,
    /// Replies sent.
    pub replied: u64,
    /// Packets the S-BFD reflector discarded, by cause.
    pub discarded: ReflectorDiscards,
}

/// Requests to `nos-bfdd`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BfdRequest {
    /// Start (or refresh) a session; the reply stream is `BfdEvent::State`.
    Register {
        /// Routing table (VRF) of the session.
        table: String,
        /// Remote system's address.
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        peer: IpAddr,
        /// Local source address, if pinned.
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
        local: Option<IpAddr>,
        /// Egress interface, required for single-hop sessions on link-local addresses.
        interface: Option<String>,
        /// The `bfd-profile` the session takes its timers and authentication from.
        profile: BfdProfile,
        /// Whether this is a multihop session (RFC 5883) rather than single-hop (RFC 5881).
        multihop: bool,
    },
    /// Stop tracking a session.
    Deregister {
        /// Session identity.
        key: SessionKey,
    },
    /// Query sessions, optionally filtered by peer.
    GetSessions {
        /// Only sessions to this peer.
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
        peer: Option<IpAddr>,
    },
    /// The S-BFD reflector's discriminators and counters.
    GetReflector,
}

/// Events and replies from `nos-bfdd`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BfdEvent {
    /// A session changed state.
    State {
        /// Session identity.
        key: SessionKey,
        /// Current session state.
        state: BfdState,
        /// Diagnostic for the last state change.
        diag: BfdDiag,
        /// The C bit (RFC 5880 §4.1) set at both ends: the local session and
        /// the last packet received. RFC 5882 §4.3: only then is a BFD Down a
        /// forwarding failure a graceful restart must not outlive.
        control_plane_independent: bool,
    },
    /// Reply to `GetSessions`.
    Sessions(Vec<BfdSessionView>),
    /// Reply to the reflector query: S-BFD reflector counters.
    Reflector(ReflectorView),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::IpcCodec;
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    fn key() -> SessionKey {
        SessionKey {
            aggregate: None,
            table: "rt1".into(),
            peer: "192.0.2.1".parse().unwrap(),
            local: None,
            interface: Some("eth1".into()),
            multihop: false,
        }
    }

    #[test]
    fn requests_and_events_round_trip() {
        let mut c = IpcCodec::<BfdRequest>::default();
        for r in [
            BfdRequest::Register {
                table: "rt1".into(),
                peer: "2001:db8::1".parse().unwrap(),
                local: Some("2001:db8::2".parse().unwrap()),
                interface: None,
                profile: BfdProfile::default(),
                multihop: true,
            },
            BfdRequest::Deregister { key: key() },
            BfdRequest::GetSessions { peer: None },
            BfdRequest::GetReflector,
        ] {
            let mut b = BytesMut::new();
            c.encode(r.clone(), &mut b).unwrap();
            assert_eq!(c.decode(&mut b).unwrap(), Some(r));
        }
        let mut c = IpcCodec::<BfdEvent>::default();
        let e = BfdEvent::State {
            key: key(),
            state: BfdState::Up,
            diag: BfdDiag::NoDiagnostic,
            control_plane_independent: true,
        };
        let mut b = BytesMut::new();
        c.encode(e.clone(), &mut b).unwrap();
        assert_eq!(c.decode(&mut b).unwrap(), Some(e));
    }

    #[test]
    fn wire_codes_and_names() {
        for c in 0..=3 {
            assert_eq!(BfdState::from_code(c).unwrap().code(), c);
        }
        assert_eq!(BfdState::from_code(4), None);
        for c in 0..=8 {
            assert_eq!(BfdDiag::from_code(c).unwrap().code(), c);
        }
        assert_eq!(BfdDiag::from_code(9), None);
        assert_eq!(
            BfdDiag::ControlDetectionTimeExpired.to_string(),
            "control-detection-time-expired"
        );
        assert_eq!(BfdState::AdminDown.to_string(), "admin-down");
    }
}
