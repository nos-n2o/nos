use std::fmt;

use garde::Validate;
use precis_core::profile::PrecisFastInvocation;
use precis_profiles::UsernameCasePreserved;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::Config;
use nos_proto_derive::Cli;

/// Prefix of every stored password hash (argon2id PHC string, see
/// `nos-password`). Anything else in `User.password` is clear text that
/// `nos-configd` hashes on the way in, so a committed config never has any.
pub const PASSWORD_HASH_PREFIX: &str = "$argon2id$";

/// A local user who may log in to `nos-cli` and call the REST API (HTTP
/// Basic). Every user is a full administrator — there are no roles.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct User {
    #[garde(
        length(min = 1, max = 64),
        custom(|n: &String, ctx: &Config| valid_username(n).and_then(|()| unique_key_in(n, &ctx.users, |u| &u.name)))
    )]
    #[cli(key)]
    /// Login name, 1 to 64 characters (letters, digits, `_`, `-`), unique among users.
    pub name: String,

    /// An argon2id hash at rest. Setting a clear-text value is allowed — the
    /// config daemon replaces it with a hash (keeping the old hash when the
    /// clear text still matches it, so re-setting the same password is not a
    /// change).
    #[cfg_attr(feature = "openapi", schema(write_only))]
    #[garde(custom(|p: &String, _ctx: &Config| valid_password_hash(p)))]
    #[cli(topic = UserPassword, secret)]
    pub password: String,
}

// Manual `Debug`: never print the password field (a hash, or briefly clear text).
impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("name", &self.name)
            .field("password", &"<hidden>")
            .finish()
    }
}

/// RFC 8265 PRECIS `UsernameCasePreserved`: `name` must already be in its
/// own NFC-normalized, disallowed-code-point-free canonical form — the form
/// `nos-config`'s `users::normalize_names` puts it in on every edit — so two
/// Unicode representations of the same visible name can never both pass
/// `unique_key_in` below as "different" users.
fn valid_username(n: &str) -> garde::Result {
    match UsernameCasePreserved::enforce(n) {
        Ok(ref enforced) if enforced == n => Ok(()),
        _ => Err(garde::Error::new(
            "username must be RFC 8265 PRECIS UsernameCasePreserved text, already NFC-normalized, with no disallowed code points",
        )),
    }
}

fn valid_password_hash(p: &str) -> garde::Result {
    if !p.starts_with(PASSWORD_HASH_PREFIX) {
        return Err(garde::Error::new(
            "password must be stored as an argon2id hash",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(users: Vec<User>) -> Config {
        Config {
            users,
            ..Default::default()
        }
    }

    fn user(name: &str, password: &str) -> User {
        User {
            name: name.to_string(),
            password: password.to_string(),
        }
    }

    #[test]
    fn hashed_user_passes() {
        let c = cfg(vec![user("alice", "$argon2id$v=19$whatever")]);
        assert!(c.validate_with(&c).is_ok());
    }

    #[test]
    fn clear_text_password_is_rejected() {
        let c = cfg(vec![user("alice", "hunter2")]);
        assert!(c.validate_with(&c).is_err());
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let c = cfg(vec![user("a", "$argon2id$x"), user("a", "$argon2id$y")]);
        assert!(c.validate_with(&c).is_err());
    }

    #[test]
    fn nfd_form_name_is_rejected() {
        // "café" spelled with a combining acute accent (NFD) rather than
        // the precomposed U+00E9 (NFC) — not the canonical form
        // `normalize_names` would have put it in.
        let c = cfg(vec![user("cafe\u{301}", "$argon2id$x")]);
        assert!(c.validate_with(&c).is_err());
    }

    #[test]
    fn nfc_form_name_passes() {
        let c = cfg(vec![user("caf\u{e9}", "$argon2id$x")]);
        assert!(c.validate_with(&c).is_ok());
    }

    #[test]
    fn disallowed_code_point_in_name_is_rejected() {
        // A bare control character is disallowed by the PRECIS IdentifierClass.
        let c = cfg(vec![user("a\u{0}b", "$argon2id$x")]);
        assert!(c.validate_with(&c).is_err());
    }

    #[test]
    fn debug_hides_password() {
        assert!(!format!("{:?}", user("a", "hunter2")).contains("hunter2"));
    }
}
