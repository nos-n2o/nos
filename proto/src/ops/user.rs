use std::fmt;

use serde::{Deserialize, Serialize};

use crate::schema::{Config, User};

use super::OpError;

/// An edit to a single named `User`. Applied without validation, like every
/// other `Op`. `password` here is normally clear text; `nos-configd` hashes it
/// right after applying (see `ConfigStore::apply_op`) — proto stores it as given.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserOp {
    /// Creates the user if missing, then sets its password.
    SetPassword {
        /// Login name of the user.
        name: String,
        /// Plaintext password, argon2id-hashed by `nos-configd` before storage.
        password: String,
    },
    /// Deletes the user and everything nested under it.
    Delete {
        /// Login name of the user.
        name: String,
    },
}

// Manual `Debug`: `ConfigOp` is logged (`?op`) and forwarded to `nos-logd`.
impl fmt::Debug for UserOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserOp::SetPassword { name, .. } => f
                .debug_struct("SetPassword")
                .field("name", name)
                .field("password", &"<hidden>")
                .finish(),
            UserOp::Delete { name } => f.debug_struct("Delete").field("name", name).finish(),
        }
    }
}

impl UserOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            UserOp::SetPassword { name, password } => {
                if let Some(u) = config.users.iter_mut().find(|u| &u.name == name) {
                    u.password.clone_from(password);
                } else {
                    config.users.push(User {
                        name: name.clone(),
                        password: password.clone(),
                        ..User::default()
                    });
                }
                Ok(())
            }
            UserOp::Delete { name } => {
                let before = config.users.len();
                config.users.retain(|u| &u.name != name);
                if config.users.len() == before {
                    return Err(OpError::UserNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(name: &str, password: &str) -> UserOp {
        UserOp::SetPassword {
            name: name.to_string(),
            password: password.to_string(),
        }
    }

    #[test]
    fn set_password_creates_then_updates() {
        let mut cfg = Config::default();
        set("a", "x").apply(&mut cfg).unwrap();
        set("a", "y").apply(&mut cfg).unwrap();
        assert_eq!(cfg.users.len(), 1);
        assert_eq!(cfg.users[0].password, "y");
    }

    #[test]
    fn delete_removes_and_missing_errors() {
        let mut cfg = Config::default();
        set("a", "x").apply(&mut cfg).unwrap();
        UserOp::Delete { name: "a".into() }.apply(&mut cfg).unwrap();
        assert_eq!(cfg.users, []);
        let err = UserOp::Delete { name: "a".into() }
            .apply(&mut cfg)
            .unwrap_err();
        assert!(matches!(err, OpError::UserNotFound(n) if n == "a"));
    }

    #[test]
    fn debug_hides_password() {
        assert!(!format!("{:?}", set("a", "hunter2")).contains("hunter2"));
    }
}
