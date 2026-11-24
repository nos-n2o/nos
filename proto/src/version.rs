//! Compile-time build version, shared by `nos` (`show version`) and `nos-restd` (`GET /v1/version`).

use nos_proto_derive::View;
use serde::{Deserialize, Serialize};

/// The workspace crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Short git revision from the Docker build's `NOS_BUILD_REV`; `unknown` for a plain `cargo build`.
pub const REVISION: &str = env!("NOS_BUILD_REV");

/// What `show version` / `GET /v1/version` report.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, View)]
pub struct VersionInfo {
    /// `CARGO_PKG_VERSION`.
    #[view(brief)]
    pub version: String,
    /// Short git revision, or `unknown`.
    #[view(brief)]
    pub revision: String,
}

impl VersionInfo {
    /// This build's values.
    pub fn current() -> Self {
        Self {
            version: VERSION.to_string(),
            revision: REVISION.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_set() {
        assert_ne!(VERSION, "");
        assert_ne!(REVISION, "");
        assert_eq!(VersionInfo::current().version, VERSION);
    }
}
