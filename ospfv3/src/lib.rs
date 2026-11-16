// nos-ospfv3: OSPFv3 (RFC 5340) daemon — Phase 1: single-area intra-area
// adjacency, SPF, and route installation over real IPv6 links. See root
// CLAUDE.md's "New features require an end-to-end Docker verification
// phase" and the OSPFv3 Phase 1 plan for scope.

// One client for both daemons: ospf link semantics, not generic daemon
// plumbing, so the files stay in `ospf/src` (not `nos-daemon`).
#[path = "../../ospf/src/bfd_client.rs"]
pub mod bfd_client;
// The RFC 5187 graceful-restart marker (`<instance>.gr`) is shared with
// `nos-ospfd`; v3 does not use the boot counter (RFC 7166 keeps its sequence
// in the socket).
#[path = "../../ospf/src/boot.rs"]
pub mod boot;
pub mod exchange;
pub mod interface_client;
pub mod link;
#[path = "../../ospf/src/link_client.rs"]
pub mod link_client;
pub mod lsa;
pub mod lsdb;
pub mod packet;
pub mod reconcile;
pub mod rib_client;
pub mod rib_push_client;
pub mod server;
pub mod socket;
pub mod spf;

/// Daemon name in the shared `link_client` log lines.
pub const DAEMON: &str = "ospfv3";

pub use nos_ospf_common::{bfd, election, neighbor};
