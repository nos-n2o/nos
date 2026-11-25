//! Shared, queryable per-peer session status — the gap `fsm::run`'s own
//! `State` doesn't fill, since it's entirely local to that async task's
//! stack and never persisted anywhere else. `server.rs`'s `GetSummary`
//! handler reads this (via `SessionManager::peer_summaries`) to answer
//! `nos-cli`'s `show bgp summary`.

use std::net::Ipv4Addr;
use std::os::fd::RawFd;

use tokio::sync::watch;
use tokio::time::Instant;

/// Mirrors `nos_proto::bgp::BgpSessionState` — kept as a separate type here
/// (rather than depending on `nos-proto` for this one enum) since `Instant`,
/// which the rest of this struct carries, isn't itself wire-serializable;
/// `session::SessionManager::peer_summaries` does the conversion at the
/// query boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Idle,
    OpenSent,
    OpenConfirm,
    Established,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeerStatus {
    pub state: PeerState,
    pub remote_asn: Option<u32>,
    pub remote_bgp_id: Option<Ipv4Addr>,
    pub established_since: Option<Instant>,
    pub negotiated_hold_time: Option<u16>,
    pub negotiated_keepalive: Option<u16>,
    /// The live socket fd of whichever connection is `Established`, captured
    /// by `fsm::run` right before it stops owning the raw `TcpStream` — read
    /// on demand for a `TCP_AO_INFO` readback (`session::to_peer_summary`),
    /// never otherwise inspected here.
    pub fd: Option<RawFd>,
}

impl Default for PeerStatus {
    fn default() -> Self {
        Self {
            state: PeerState::Idle,
            remote_asn: None,
            remote_bgp_id: None,
            established_since: None,
            negotiated_hold_time: None,
            negotiated_keepalive: None,
            fd: None,
        }
    }
}

/// The sender half of a peer's status channel — `fsm::run` (or, on it
/// returning, its caller in `session.rs`) is the sole writer; `watch`'s
/// always-has-a-current-value semantics make it a natural fit for a one-shot
/// query rather than a queued channel.
pub type StatusHandle = watch::Sender<PeerStatus>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_idle_with_nothing_else_known() {
        let status = PeerStatus::default();
        assert_eq!(status.state, PeerState::Idle);
        assert_eq!(status.remote_asn, None);
        assert_eq!(status.remote_bgp_id, None);
        assert_eq!(status.established_since, None);
        assert_eq!(status.negotiated_hold_time, None);
        assert_eq!(status.negotiated_keepalive, None);
        assert_eq!(status.fd, None);
    }
}
