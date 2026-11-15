//! `pam_nos.so`: a PAM module that checks a user's password against
//! `nos-watchdogd`'s login broker over post-quantum mutual TLS (#996, part of
//! #987). See `pam/CLAUDE.md`.

pub mod login;
pub mod module;
pub mod options;
pub mod session;

#[cfg(test)]
mod tests;

pub use module::NosPam;
pub use session::NosTicket;

// The only `unsafe` in this crate; nonstick's own code is the FFI.
#[allow(
    unsafe_code,
    reason = "pam_export! expands to extern \"C\" entry points"
)]
mod export {
    use crate::NosPam;
    nonstick::pam_export!(NosPam);
}
