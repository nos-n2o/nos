//! Login lockout policy (`Config.login_policy`, #1148): how many failed
//! logins lock an account (per source address and user) in `nos-restd`, and
//! for how long; `nos-watchdogd` applies `max_failures` to its direct-login
//! connections.

use garde::Validate;
use nos_proto_derive::Cli;
use serde::{Deserialize, Serialize};

use super::Config;

/// Failures before lockout, unless configured.
pub const MAX_FAILURES_DEFAULT: u8 = 5;
/// Lockout window in seconds, unless configured.
pub const LOCKOUT_WINDOW_SECS_DEFAULT: u32 = 60;

/// Login lockout settings.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct LoginPolicy {
    /// Failed logins inside the window that lock the account out: 1 to 100.
    #[serde(default = "max_failures_default")]
    #[garde(range(min = 1, max = 100))]
    #[cli(topic = LoginPolicyMaxFailures)]
    pub max_failures: u8,

    /// Seconds from the first failure that failures are counted, and a lockout lasts: 1 to 86400.
    #[serde(default = "lockout_window_default")]
    #[garde(range(min = 1, max = 86400))]
    #[cli(topic = LoginPolicyLockoutWindow)]
    pub lockout_window_secs: u32,
}

fn max_failures_default() -> u8 {
    MAX_FAILURES_DEFAULT
}

fn lockout_window_default() -> u32 {
    LOCKOUT_WINDOW_SECS_DEFAULT
}

impl Default for LoginPolicy {
    fn default() -> Self {
        Self {
            max_failures: MAX_FAILURES_DEFAULT,
            lockout_window_secs: LOCKOUT_WINDOW_SECS_DEFAULT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_absent_and_bounds_validated() {
        let p: LoginPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p, LoginPolicy::default());
        let c = Config::default();
        for (m, w, ok) in [
            (0, 60, false),
            (101, 60, false),
            (1, 0, false),
            (100, 86400, true),
        ] {
            let p = LoginPolicy {
                max_failures: m,
                lockout_window_secs: w,
            };
            assert_eq!(p.validate_with(&c).is_ok(), ok, "{m} {w}");
        }
    }
}
