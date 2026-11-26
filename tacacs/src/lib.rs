//! TACACS+ client (RFC 8907): PAP and ASCII authentication, authorization of the login
//! (role in the `role` AV pair) and accounting, over TCP. No NOS dependencies:
//! callers pass servers and strings and get a verdict. MD5 is the protocol's
//! own body obfuscation, not a choice (see `docs/architecture/auth.md`).

mod client;
mod packet;
mod stub;

pub use client::{account, av, login, AuthError, Pool, Server};
pub use packet::{AcctFlags, DecodeError};
pub use stub::{serve_listener, serve_stub, StubUser};
