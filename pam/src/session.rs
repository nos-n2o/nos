use std::fmt;

use zeroize::Zeroizing;

/// What a successful `pam_sm_authenticate` leaves in the PAM handle
/// (`set_module_data(NosTicket::KEY, ..)`): the single-use login ticket the
/// watchdog issued for `user`, in `NOS_LOGIN_TICKET`'s encoding. `open_session`
/// exports it (#992); nonstick drops it (zeroized) with the handle, a second
/// `authenticate` overwrites it.
pub struct NosTicket {
    pub user: String,
    pub encoded: Zeroizing<String>,
}

impl NosTicket {
    /// The module-data key.
    pub const KEY: &'static str = "nos_pam_ticket";
}

impl fmt::Debug for NosTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NosTicket")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}
