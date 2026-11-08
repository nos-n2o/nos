// nos-ospf: OSPF daemon — Hello-protocol neighbor discovery up to 2-Way,
// point-to-point and broadcast (RFC 2328 DR/BDR election) links (see
// ospf/CLAUDE.md)

/// Daemon name in the `link_client` log lines (shared with `nos-ospfv3`).
pub const DAEMON: &str = "ospf";

pub mod bfd_client;
pub mod boot;
pub mod exchange;
pub mod interface_client;
pub mod link;
pub mod link_client;
pub mod lls;
pub mod lsa;
pub mod lsdb;
pub mod packet;
pub mod reconcile;
pub mod rib_client;
pub mod rib_push_client;
pub mod server;
pub mod socket;
pub mod spf;

pub use nos_ospf_common::{bfd, election, neighbor};
