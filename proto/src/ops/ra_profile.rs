use serde::{Deserialize, Serialize};

use crate::schema::{Config, RaProfile};

use super::OpError;

/// An edit to a named `RaProfile`. Applied without validation — `garde`
/// only runs at commit, where a deleted-but-still-referenced profile is
/// reported once per user by `ra_profile_reference_valid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaProfileOp {
    /// Creates the profile with defaults if missing; no-op otherwise.
    Ensure {
        /// Name of the RA profile this op targets.
        name: String,
    },
    /// Deletes the RA profile and everything nested under it.
    Delete {
        /// Name of the RA profile this op targets.
        name: String,
    },
}

impl RaProfileOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            RaProfileOp::Ensure { name } => {
                if !config.ra_profiles.iter().any(|p| &p.name == name) {
                    config.ra_profiles.push(RaProfile {
                        name: name.clone(),
                        ..Default::default()
                    });
                }
                Ok(())
            }
            RaProfileOp::Delete { name } => {
                let before = config.ra_profiles.len();
                config.ra_profiles.retain(|p| &p.name != name);
                if config.ra_profiles.len() == before {
                    return Err(OpError::RaProfileNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_is_idempotent_and_delete_errors_when_missing() {
        let mut c = Config::default();
        let ensure = RaProfileOp::Ensure { name: "a".into() };
        ensure.apply(&mut c).unwrap();
        ensure.apply(&mut c).unwrap();
        assert_eq!(c.ra_profiles.len(), 1);
        let del = RaProfileOp::Delete { name: "a".into() };
        del.apply(&mut c).unwrap();
        assert!(matches!(
            del.apply(&mut c),
            Err(OpError::RaProfileNotFound(_))
        ));
    }
}
