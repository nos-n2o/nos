//! SSH login-shell mode (#991): `nos` as a user's shell, redeeming the PAM login ticket.

use std::ffi::OsString;
use std::path::Path;

use zeroize::Zeroizing;

use crate::watchdog_client::{self, Issued, WatchdogClientError};

/// Decodes the raw `NOS_LOGIN_TICKET` value; absent or malformed is `None`.
/// The raw buffer is zeroized on the way out.
pub fn parse_ticket(raw: Option<OsString>) -> Option<Zeroizing<Vec<u8>>> {
    use std::os::unix::ffi::OsStringExt as _;
    let raw = Zeroizing::new(raw?.into_vec());
    let s = std::str::from_utf8(&raw).ok()?;
    nos_proto::ticket_from_env(s).map(Zeroizing::new)
}

/// Redeems `ticket` for a certificate on a fresh key. `Ok(None)`: the watchdog
/// refused it (the caller falls back to the prompt); `Err`: the watchdog was
/// unreachable or misbehaved (the caller fails closed). The ticket is never
/// printed, and neither is the refusal reason.
pub async fn redeem_ticket(
    watchdog_socket: &Path,
    ticket: &[u8],
) -> anyhow::Result<Option<(Issued, Zeroizing<Vec<u8>>)>> {
    let (csr, key) = nos_pki::generate_csr()?;
    match watchdog_client::redeem(watchdog_socket, ticket, csr).await {
        Ok(issued) => Ok(Some((issued, key))),
        Err(WatchdogClientError::Denied(_)) => {
            eprintln!("session ticket not accepted; please log in");
            Ok(None)
        }
        Err(e) => anyhow::bail!("cannot log in: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt as _;

    #[test]
    fn ticket_parsing() {
        let t = nos_proto::ticket_to_env(&[7; nos_proto::LOGIN_TICKET_LEN]);
        assert_eq!(parse_ticket(Some(t.into())).unwrap().as_slice(), &[7; 32]);
        assert!(parse_ticket(None).is_none());
        assert!(parse_ticket(Some("not a ticket!".into())).is_none());
        assert!(parse_ticket(Some(OsString::from_vec(vec![0xff, 0xfe]))).is_none());
    }
}
