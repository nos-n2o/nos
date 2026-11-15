use std::fmt;
use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

/// What a successful `pam_sm_authenticate` leaves in the PAM handle
/// (`set_module_data(NosSession::KEY, ..)`) for #989's hand-off: the
/// certificate `nos-watchdogd` issued, the private key behind it (made here,
/// never sent anywhere) and the certificate's lifetime. nonstick drops it with
/// the handle (`pam_end`); a second `authenticate` overwrites it.
pub struct NosSession {
    pub user: String,
    pub cert_der: Vec<u8>,
    pub key: Zeroizing<Vec<u8>>,
    pub lifetime: Duration,
}

impl NosSession {
    /// The module-data key, a contract with #989.
    pub const KEY: &'static str = "nos_pam_session";
}

impl Drop for NosSession {
    fn drop(&mut self) {
        // Not secret, but free; `key` zeroizes itself.
        self.cert_der.zeroize();
    }
}

impl fmt::Debug for NosSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NosSession")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}
