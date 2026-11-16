//! Boilerplate every NOS daemon shares: resolving endpoints through
//! `nos-watchdogd`, fetching/subscribing to `nos-configd`, one-shot IPC
//! queries and the `main()` tracing/identity bootstrap. Depends only on
//! `nos-proto`, `nos-pki` and `nos-log-client`, never on another component.

pub mod bootstrap;
pub mod config;
pub mod ipc;
pub mod liveness;
pub mod watchdog;
