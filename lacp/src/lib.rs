// nos-lacp: a from-scratch IEEE 802.1AX Link Aggregation Control Protocol
// implementation (see lacp/CLAUDE.md). The kernel bond device stays
// dataplane-only (BondMode::BalanceXor, owned by nos-interfaced) — this
// crate runs the real LACPDU exchange and Actor/Partner state machines and
// pushes its negotiated active-member set over IPC.

pub mod aggregate;
pub mod churn_machine;
pub mod conversation;
pub mod interface_client;
pub mod link;
pub mod mux_machine;
pub mod packet;
pub mod periodic_tx_machine;
pub mod receive_machine;
pub mod reconcile;
pub mod selection;
pub mod server;
pub mod socket;
