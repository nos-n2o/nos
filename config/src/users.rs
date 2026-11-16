//! Password handling for `Config.users`: hashing clear-text passwords on the
//! way in (keeping an existing hash when it still matches, so re-setting the
//! same password isn't a change) and the first-boot default user.

use nos_proto::{Config, User, PASSWORD_HASH_PREFIX};
use precis_core::profile::PrecisFastInvocation;
use precis_profiles::UsernameCasePreserved;
use tracing::warn;

pub const DEFAULT_USER: &str = "admin";
pub const DEFAULT_PASSWORD: &str = "admin";

pub(crate) fn is_clear(u: &User) -> bool {
    !u.password.starts_with(PASSWORD_HASH_PREFIX)
}

/// RFC 8265 PRECIS `UsernameCasePreserved`-normalizes every `User.name`
/// (NFC + disallowed-code-point rejection) so two Unicode representations of
/// the same visible name can never coexist as distinct users. Best-effort: a
/// name that can't be PRECIS-enforced (disallowed code points) is left as
/// given, so it still shows up as a plain diff and is rejected by
/// `nos_proto`'s `valid_username` at commit rather than silently accepted.
pub(crate) fn normalize_names(users: &mut [User]) {
    for u in users.iter_mut() {
        if let Ok(enforced) = UsernameCasePreserved::enforce(u.name.as_str()) {
            u.name = enforced.into_owned();
        }
    }
}

/// Replaces every clear-text password in `users` with an argon2id hash. If a
/// `known` list (earlier states of the same config — the transaction before
/// this edit, then running) holds a hash for that user which the clear text
/// still verifies against, that hash is reused verbatim instead of salting a
/// new one — this is what keeps "set the same password again" from showing up
/// as a diff.
///
/// Blocking (tens of ms per password): the store runs it on `spawn_blocking`.
pub(crate) fn hash_clear_passwords(users: &mut [User], known: &[&[User]]) {
    for u in users.iter_mut().filter(|u| is_clear(u)) {
        let same = known
            .iter()
            .flat_map(|list| list.iter())
            .filter(|k| k.name == u.name && !is_clear(k))
            .find(|k| nos_password::verify(&u.password, &k.password));
        u.password = match same {
            Some(k) => k.password.clone(),
            None => nos_password::hash(&u.password),
        };
    }
}

/// Adds `admin`/`admin` (clear text — `ConfigStore::new` hashes it) when the
/// config has no users at all, so a fresh box (or one upgraded from before
/// users existed) isn't locked out of both the CLI and REST.
pub fn seed_default_user(config: &mut Config) {
    if config.users.is_empty() {
        warn!(
            user = DEFAULT_USER,
            "no users configured, creating the default user — change its password"
        );
        config.users.push(User {
            name: DEFAULT_USER.to_string(),
            password: DEFAULT_PASSWORD.to_string(),
            ..Default::default()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(name: &str, pw: &str) -> User {
        User {
            name: name.to_string(),
            password: pw.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn hash_prefix_matches_nos_password() {
        assert_eq!(PASSWORD_HASH_PREFIX, nos_password::HASH_PREFIX);
    }

    #[test]
    fn nfd_name_normalizes_to_nfc() {
        let mut users = vec![u("cafe\u{301}", "pw")];
        normalize_names(&mut users);
        assert_eq!(users[0].name, "caf\u{e9}");
    }

    #[test]
    fn already_canonical_name_is_unchanged() {
        let mut users = vec![u("caf\u{e9}", "pw")];
        normalize_names(&mut users);
        assert_eq!(users[0].name, "caf\u{e9}");
    }

    #[test]
    fn disallowed_code_point_is_left_as_given() {
        let mut users = vec![u("a\u{0}b", "pw")];
        normalize_names(&mut users);
        assert_eq!(users[0].name, "a\u{0}b");
    }

    #[test]
    fn two_nfc_nfd_forms_normalize_to_the_same_name() {
        let mut users = vec![u("caf\u{e9}", "pw"), u("cafe\u{301}", "pw2")];
        normalize_names(&mut users);
        assert_eq!(users[0].name, users[1].name);
    }

    #[test]
    fn clear_becomes_hash_and_same_clear_keeps_it() {
        let mut users = vec![u("a", "pw")];
        hash_clear_passwords(&mut users, &[]);
        let h = users[0].password.clone();
        assert!(nos_password::verify("pw", &h));

        let mut again = vec![u("a", "pw")];
        hash_clear_passwords(&mut again, &[&users]);
        assert_eq!(again[0].password, h);

        let mut other = vec![u("a", "different")];
        hash_clear_passwords(&mut other, &[&users]);
        assert_ne!(other[0].password, h);
        assert!(nos_password::verify("different", &other[0].password));
    }

    #[test]
    fn existing_hashes_are_untouched() {
        let mut users = vec![u("a", "$argon2id$v=19$keep")];
        hash_clear_passwords(&mut users, &[]);
        assert_eq!(users[0].password, "$argon2id$v=19$keep");
    }

    #[test]
    fn seeds_only_when_empty() {
        let mut c = Config::default();
        seed_default_user(&mut c);
        assert_eq!(c.users.len(), 1);
        seed_default_user(&mut c);
        assert_eq!(c.users.len(), 1);
    }
}
