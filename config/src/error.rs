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
    #[error("no transaction named '{0}'")]
    TransactionNotFound(String),
    /// An `if_match` precondition (RFC 9110 §13.1.1) named a generation the
    /// transaction has moved past. `nos-restd` keys on the message prefix.
    #[error("precondition failed: transaction generation is {actual}, not one of {expected:?}")]
    PreconditionFailed { expected: Vec<u64>, actual: u64 },
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `nos-restd` maps the `validation failed` prefix to 422 (#675): a reword
    /// of a semantic refusal must keep it.
    #[test]
    fn semantic_refusals_keep_the_422_prefix() {
        for e in [
            ConfigError::NoUsersLeft,
            ConfigError::SyslogTrustAnchor {
                server: "s".into(),
                reason: "r".into(),
            },
            ConfigError::HashUpgradeRefused,
            ConfigError::SshHostKeyRefused,
            ConfigError::MaskedSecret("user 'u'".into()),
            ConfigError::TooManyClearPasswords(4),
        ] {
            assert!(e.to_string().starts_with("validation failed"), "{e}");
        }
    }
}
