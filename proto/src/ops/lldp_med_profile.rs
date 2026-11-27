use serde::{Deserialize, Serialize};

use crate::schema::{Config, LldpMedProfile};

use super::OpError;

/// An edit to a named `LldpMedProfile`. Applied without validation — `garde`
/// only runs at commit, where a deleted-but-still-referenced profile is
/// reported once per user by `lldp_med_profile_reference_valid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LldpMedProfileOp {
    /// Creates the profile with defaults if missing; no-op otherwise.
    Ensure {
        /// Name of the LLDP-MED profile this op targets.
        name: String,
    },
    /// Deletes the LLDP-MED profile and everything nested under it.
    Delete {
        /// Name of the LLDP-MED profile this op targets.
        name: String,
    },
}

impl LldpMedProfileOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            LldpMedProfileOp::Ensure { name } => {
                if !config.lldp_med_profiles.iter().any(|p| &p.name == name) {
                    config.lldp_med_profiles.push(LldpMedProfile {
                        name: name.clone(),
                        ..Default::default()
                    });
                }
                Ok(())
            }
            LldpMedProfileOp::Delete { name } => {
                let before = config.lldp_med_profiles.len();
                config.lldp_med_profiles.retain(|p| &p.name != name);
                if config.lldp_med_profiles.len() == before {
                    return Err(OpError::LldpMedProfileNotFound(name.clone()));
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
        let ensure = LldpMedProfileOp::Ensure { name: "a".into() };
        ensure.apply(&mut c).unwrap();
        ensure.apply(&mut c).unwrap();
        assert_eq!(c.lldp_med_profiles.len(), 1);
        let del = LldpMedProfileOp::Delete { name: "a".into() };
        del.apply(&mut c).unwrap();
        assert!(matches!(
            del.apply(&mut c),
            Err(OpError::LldpMedProfileNotFound(_))
        ));
    }
}
