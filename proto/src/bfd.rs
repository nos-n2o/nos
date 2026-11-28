//! `nos-bfdd`'s IPC protocol (RFC 5880 sessions on behalf of other daemons).
//! One-shot request/event pairs framed by `IpcCodec` over a Unix socket
//! resolved via the watchdog broker (`ServiceRef::Bfd`, a single system-wide
//! instance). Clients (`bgpd`/`ribd`/`ospfd`/`ospfv3d`) `Register` a session
//! and are told of state changes; `nos-cli`/`nos-restd` query with `GetSessions`.

use std::fmt;
use std::net::IpAddr;

use nos_proto_derive::View;
use serde::{Deserialize, Serialize};

use crate::schema::{BfdAuthMethod, BfdProfile};

/// What identifies one BFD session: a routing table, the remote system and
/// the path to it (RFC 5881 single-hop is bound to an interface, RFC 5883
/// multihop is not).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, View)]
pub struct SessionKey {
    /// Routing table (VRF) the session runs in.
    #[view(brief, order = 0, header = "Table")]
    pub table: String,
    /// Remote system's address.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[view(brief, order = 1, sort, header = "Peer", text)]
    pub peer: IpAddr,
    /// Local source address, if pinned.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, order = 2, header = "Local", text)]
    pub local: Option<IpAddr>,
    /// Egress interface, required for single-hop sessions on link-local addresses.
    #[view(brief, order = 3, header = "Interface")]
    pub interface: Option<String>,
    /// Whether this is a multihop session (RFC 5883) rather than single-hop (RFC 5881).
    #[view(brief, order = 40, header = "Multihop", unit = bool)]
    pub multihop: bool,
    /// RFC 7130 micro-BFD: the `PortAggregate` this session probes a member of
    /// (`interface` is the member, `table` is empty). Appended last for postcard.
    #[serde(default)]
    #[view(brief, order = 4, header = "Aggregate")]
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
#[allow(
    clippy::struct_excessive_bools,
    reason = "a flat wire view: each bool is its own column"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, View)]
pub struct BfdSessionView {
    /// Session identity.
    #[view(brief, nested, order = 0)]
    pub key: SessionKey,
    /// Current session state.
    #[view(brief, order = 1, text)]
    pub state: BfdState,
    /// Diagnostic for the last state change.
    #[view(brief, order = 2, text)]
    pub diag: BfdDiag,
    /// My Discriminator (RFC 5880 section 6.8.1).
    #[view(brief, order = 3, header = "Local-Disc", unit = count)]
    pub local_discriminator: u32,
    /// Your Discriminator learned from the peer; zero until heard.
    #[view(brief, order = 4, header = "Remote-Disc", unit = count)]
    pub remote_discriminator: u32,
    /// Negotiated transmit interval, microseconds.
    #[view(brief, order = 5, header = "Tx-Interval", unit = micros)]
    pub tx_interval_us: u32,
    /// Detection time, microseconds.
    #[view(brief, order = 6, header = "Detection", unit = micros)]
    pub detection_time_us: u32,
    /// The configured authentication (never the key), `None` when off.
    #[view(brief, order = 42, header = "Auth", text)]
    pub auth_method: Option<BfdAuthMethod>,
    /// Key ID of the authentication key in use, if the session is authenticated (RFC 5880 section 6.7).
    #[view(brief, order = 43, header = "Auth-Key", unit = count)]
    pub auth_key_id: Option<u8>,
    /// Packets dropped by RFC 5880 §6.7 authentication since the session started.
    #[view(brief, order = 44, header = "Auth-Failures", unit = count)]
    pub auth_failures: u64,
    /// The Echo function is running (RFC 5880 §6.4).
    #[view(brief, order = 45, header = "Echo", unit = bool)]
    pub echo_active: bool,
    /// Negotiated Echo transmit interval, microseconds; 0 while inactive.
    #[view(brief, order = 46, header = "Echo-Interval", unit = micros)]
    pub echo_interval_us: u32,
    /// RFC 9747 unaffiliated Echo: no Control traffic at all.
    #[view(brief, order = 47, header = "Echo-Only", unit = bool)]
    pub echo_only: bool,
    /// RFC 9764: the UDP payload size Control packets are padded to, 0 when not padded.
    #[view(brief, order = 48, header = "Pdu", unit = bytes)]
    pub tx_pdu_bytes: u32,
    /// RFC 7880 S-BFD: which end of which protocol this session is.
    #[view(brief, order = 41, header = "Kind", text)]
    pub kind: BfdSessionKind,
    /// Seconds since the session last went Up; `None` while not Up. Per session lifetime in the daemon: resets on re-creation, mode switch or `nos-bfdd` restart.
    #[serde(default)]
    #[view(brief, order = 49, header = "Uptime", unit = secs)]
    pub uptime_secs: Option<u64>,
    /// Age of the last state change in seconds (from session creation when there was none).
    #[serde(default)]
    #[view(unit = secs)]
    pub last_change_secs: u64,
    /// Transitions from Up to any other state since the session was created.
    #[serde(default)]
    #[view(unit = count)]
    pub down_count: u32,
    /// Control packets sent (echo-only sessions send none). Per session lifetime.
    #[serde(default)]
    #[view(unit = count)]
    pub tx_packets: u64,
    /// Packets that passed authentication; for an S-BFD initiator or an unaffiliated-echo loop, what that loop accepted. Per session lifetime.
    #[serde(default)]
    #[view(unit = count)]
    pub rx_packets: u64,
    /// The peer's advertised Required Min RX, microseconds; `None` until a packet arrived.
    #[serde(default)]
    #[view(unit = micros)]
    pub remote_min_rx_us: Option<u32>,
    /// The peer's advertised Desired Min TX, microseconds; `None` until a packet arrived.
    #[serde(default)]
    #[view(unit = micros)]
    pub remote_desired_min_tx_us: Option<u32>,
    /// The peer's Detect Mult; `None` until a packet arrived.
    #[serde(default)]
    #[view(unit = count)]
    pub remote_detect_mult: Option<u8>,
    /// Role labels of the clients using the session (sorted, deduplicated); empty when unsolicited.
    #[serde(default)]
    #[view(text)]
    pub clients: Vec<String>,
    /// This system asks the peer for Demand mode (RFC 5880 §6.6): the profile's `demand`.
    #[serde(default)]
    #[view(brief, order = 50, header = "Demand", unit = bool)]
    pub demand: bool,
    /// The peer's Demand (D) bit in its last packet; false until one arrived.
    #[serde(default)]
    #[view(brief, order = 51, header = "Remote-Demand", unit = bool)]
    pub remote_demand: bool,
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
    /// The A bit is set but no configured key matches its type and key id.
    pub authenticated: u64,
    /// D bit clear (RFC 7880 §7.2.3).
    pub demand_clear: u64,
    /// Your Discriminator is not one of the reflector's.
    pub unknown_discriminator: u64,
    /// The A bit is set, a key matches, but the digest or password is wrong.
    #[serde(default)]
    pub auth_failed: u64,
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
    fn session_view_wire_appends_stats_last() {
        let mut v = BfdSessionView {
            key: key(),
            state: BfdState::Down,
            diag: BfdDiag::NoDiagnostic,
            local_discriminator: 0,
            remote_discriminator: 0,
            tx_interval_us: 0,
            detection_time_us: 0,
            auth_method: None,
            auth_key_id: None,
            auth_failures: 0,
            echo_active: false,
            echo_interval_us: 0,
            echo_only: false,
            tx_pdu_bytes: 0,
            kind: BfdSessionKind::Classical,
            uptime_secs: None,
            last_change_secs: 0,
            down_count: 0,
            tx_packets: 0,
            rx_packets: 0,
            remote_min_rx_us: None,
            remote_desired_min_tx_us: None,
            remote_detect_mult: None,
            clients: vec![],
            demand: false,
            remote_demand: false,
        };
        // The eleven appended fields, all empty, are eleven zero bytes at the end.
        let mut c = IpcCodec::<BfdEvent>::default();
        let mut b = BytesMut::new();
        c.encode(BfdEvent::Sessions(vec![v.clone()]), &mut b)
            .unwrap();
        assert_eq!(b[b.len() - 11..], [0u8; 11]);
        v.uptime_secs = Some(5);
        v.remote_detect_mult = Some(3);
        v.clients = vec!["bgp".into(), "static".into()];
        let e = BfdEvent::Sessions(vec![v]);
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
