//! RADIUS client (RFC 2865 authentication, RFC 2866 accounting, RFC 3579
//! Message-Authenticator) over UDP. No NOS dependencies: callers pass plain
//! servers and strings and get back a verdict. MD5 and HMAC-MD5 are the
//! protocol's own primitives, not a choice (see `docs/architecture/auth.md`).

mod client;
mod packet;
mod stub;

pub use client::{account, authenticate, Accepted, AuthError, Server};
pub use packet::{attr, hide_password, make_reply, unhide_password, Code, DecodeError, Packet};
pub use stub::{serve_stub, StubUser};
