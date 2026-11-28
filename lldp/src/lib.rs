// nos-lldp: a from-scratch IEEE 802.1AB Link Layer Discovery Protocol
// implementation (see lldp/CLAUDE.md). Runs a raw AF_PACKET socket per
// LLDP-enabled physical interface, transmitting this system's identity and
// recording the neighbors it hears. Never touches rtnetlink.

pub mod link;
pub mod link_client;
pub mod med;
pub mod neighbor;
pub mod packet;
pub mod reconcile;
pub mod server;
pub mod socket;
