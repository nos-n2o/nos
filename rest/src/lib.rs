// nos-rest: the HTTPS+JSON management API (mutual TLS) (`nos-restd`, see rest/CLAUDE.md).
// One process per `RoutingTable` that has `rest-api` pinned to it, listening
// on that table's configured address inside its VRF. A thin translation layer:
// every endpoint resolves a daemon through the watchdog broker (or talks to
// `nos-configd`) and forwards one existing nos-proto request.

pub mod api;
pub mod auth;
pub mod clear;
pub mod error;
pub mod ipc;
pub mod listen;
pub mod login;
pub mod merge_patch;
pub mod openapi;
pub mod ratelimit;
pub mod show;
pub mod tls;
pub mod tx;
