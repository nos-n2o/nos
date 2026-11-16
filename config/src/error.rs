use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("validation failed:\n{0}")]
    Validation(#[from] garde::Report),
    // The `validation failed: ` prefix of the next five is load-bearing:
    // `nos-restd`'s `ApiError::from_config` maps it to 422 (#675).
    #[error("validation failed: it would remove every user and lock everyone out")]
    NoUsersLeft,
    #[error(
        "validation failed: it would remove every administrator and lock everyone out of editing"
    )]
    NoAdminLeft,
    #[error("validation failed: syslog server '{server}': tls trust-anchor is not a PEM certificate: {reason}")]
    SyslogTrustAnchor { server: String, reason: String },
    #[error(
        "validation failed: password hash upgrade refused: no such user, stale hash, or not a hash"
    )]
    HashUpgradeRefused,
    #[error(
        "validation failed: ssh host key refused: already set, or not the base64 of a 32-byte seed"
    )]
    SshHostKeyRefused,
    #[error("validation failed: {0} was sent as the mask text '<hidden>' but has no earlier value to keep")]
    MaskedSecret(String),
    /// `nos-restd` keys on the `no history entry` prefix (404).
    #[error("no history entry {index}: {have} kept")]
    HistoryOutOfRange { index: u32, have: usize },
    #[error("config history is not available on this daemon (no --config-file, or its directory is not writable)")]
    HistoryUnavailable,
    /// The caller's `User.role` does not allow the request; `nos-restd` keys on the prefix (403).
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("no transaction named '{0}'")]
    TransactionNotFound(String),
    /// An `if_match` precondition (RFC 9110 §13.1.1) named a generation the
    /// transaction has moved past. `nos-restd` keys on the message prefix.
    #[error("precondition failed: transaction generation is {actual}, not one of {expected:?}")]
    PreconditionFailed { expected: Vec<u64>, actual: u64 },
    /// Commit rebases a `Current` transaction onto running by 3-way merge
    /// (#1034); these paths changed on both sides. Same `precondition failed`
    /// prefix, so `nos-restd` answers 412.
    #[error("precondition failed: {}; re-apply your change on a fresh transaction or edit the conflicting values", stale_paths(paths))]
    StaleBase { paths: Vec<String> },
    /// The merge itself was clean but the result does not validate
    /// (keeps the 422 prefix).
    #[error("validation failed: after merging concurrent changes: {0}")]
    MergedInvalid(Box<ConfigError>),
    #[error("invalid transaction name: use 1-64 characters of letters, digits, '.', '_' or '-'")]
    InvalidTransactionName,
    #[error("too many transactions: {0} are open; commit or discard one first")]
    TooManyTransactions(usize),
    #[error("validation failed: too many clear-text passwords in one edit (at most {0})")]
    TooManyClearPasswords(usize),
    #[error("edit failed: {0}")]
    Op(#[from] nos_proto::OpError),
    #[error("config path: {0}")]
    Path(#[from] nos_proto::config_path::PathError),
    #[error("invalid JSON body for config path: {0}")]
    Json(#[from] serde_json::Error),
    #[error("config persistence is not configured on this daemon (no --config-file set)")]
    PersistenceNotConfigured,
    #[error("IPC I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to read/write config file at {path}: {source}")]
    Persistence {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to (de)serialize config: {0}")]
    Serialization(#[from] serde_norway::Error),
}

fn stale_paths(paths: &[String]) -> String {
    let shown = paths
        .iter()
        .take(10)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    match paths.len().saturating_sub(10) {
        0 => format!("another transaction changed the same value: {shown}"),
        n => format!("another transaction changed the same values: {shown}, and {n} more"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `nos-restd` maps the `validation failed` prefix to 422 (#675): a reword
    /// of a semantic refusal must keep it.
    #[test]
    fn semantic_refusals_keep_the_422_prefix() {
        for e in [
            ConfigError::NoUsersLeft,
            ConfigError::NoAdminLeft,
            ConfigError::SyslogTrustAnchor {
                server: "s".into(),
                reason: "r".into(),
            },
            ConfigError::HashUpgradeRefused,
            ConfigError::SshHostKeyRefused,
            ConfigError::MaskedSecret("user 'u'".into()),
            ConfigError::TooManyClearPasswords(4),
            ConfigError::MergedInvalid(Box::new(ConfigError::NoUsersLeft)),
        ] {
            assert!(e.to_string().starts_with("validation failed"), "{e}");
        }
    }

    #[test]
    fn stale_base_keeps_the_412_prefix_and_caps_the_paths() {
        let paths: Vec<String> = (0..12).map(|i| format!("p{i}")).collect();
        let m = ConfigError::StaleBase { paths }.to_string();
        assert!(m.starts_with("precondition failed"), "{m}");
        assert!(
            m.contains("p9") && !m.contains("p10") && m.contains("and 2 more"),
            "{m}"
        );
    }
}
