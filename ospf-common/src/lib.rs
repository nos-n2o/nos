//! Pure, address-family-agnostic OSPF logic shared by `nos-ospf` (`OSPFv2`)
//! and `nos-ospfv3` (`OSPFv3`) — the neighbor FSM and DR/BDR election
//! algorithm are identical between RFC 2328 and RFC 5340 (v3's DR/BDR
//! fields are router-ids, not addresses, so even `election`'s `Ipv4Addr`
//! typing is just an opaque-id representation, not a real v2-only address
//! dependency). Kept dependency-light (no `nos-proto`; no I/O except the socket-option helper in `drouters`) so both
//! daemons can depend on it without gaining any daemon-to-daemon coupling —
//! see root `CLAUDE.md`'s dependency-graph section.

pub mod areas;
pub mod bfd;
pub mod boot;
pub mod dbd_fault;
pub mod drouters;
pub mod election;
pub mod exchange;
pub mod flood;
pub mod lsa;
pub mod lsdb;
pub mod neighbor;
pub mod ratelimit;
pub mod restart;
pub mod throttle;
