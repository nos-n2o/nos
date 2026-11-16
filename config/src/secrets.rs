//! The mask round trip (#507): `nos-restd` returns secrets as `<hidden>`, so a
//! client that GETs a config and PUTs it back sends the mask where a secret
//! was. The mask must keep the stored value, never become the value.

use nos_proto::cli::render::HIDDEN;
use nos_proto::{Admin, AdminOp, Config, ConfigOp, User, UserOp};

use crate::error::ConfigError;

fn refused(what: String) -> ConfigError {
    ConfigError::MaskedSecret(what)
}

/// Replaces each `<hidden>` secret of `config` (admin keys, user password
/// hashes) with the value the same label/name has in the first of `earlier`
/// that holds one. A mask with nothing earlier to keep is refused.
pub(crate) fn restore_masked(config: &mut Config, earlier: &[&Config]) -> Result<(), ConfigError> {
    restore_admin(&mut config.admin, earlier)?;
    restore_users(&mut config.users, earlier)
}

/// [`restore_masked`] for the admin keystore alone.
pub(crate) fn restore_admin(admin: &mut Admin, earlier: &[&Config]) -> Result<(), ConfigError> {
    for k in admin.keys.iter_mut().filter(|k| k.secret == HIDDEN) {
        let old = earlier.iter().find_map(|c| c.key(&k.label));
        k.secret = old
            .ok_or_else(|| refused(format!("admin key '{}'", k.label)))?
            .to_string();
    }
    Ok(())
}

/// [`restore_masked`] for the user list alone.
pub(crate) fn restore_users(users: &mut [User], earlier: &[&Config]) -> Result<(), ConfigError> {
    for u in users.iter_mut().filter(|u| u.password == HIDDEN) {
        let old = earlier
            .iter()
            .find_map(|c| c.users.iter().find(|o| o.name == u.name));
        u.password = old
            .ok_or_else(|| refused(format!("user '{}'", u.name)))?
            .password
            .clone();
    }
    Ok(())
}

/// The same for a single op: a `SetKey`/`SetPassword` carrying the mask is
/// rewritten to carry the stored value. Done before applying, so a refusal
/// leaves the transaction untouched.
pub(crate) fn unmask_op(op: ConfigOp, earlier: &[&Config]) -> Result<ConfigOp, ConfigError> {
    Ok(match op {
        ConfigOp::Admin(AdminOp::SetKey { label, secret }) if secret == HIDDEN => {
            let old = earlier.iter().find_map(|c| c.key(&label));
            let secret = old
                .ok_or_else(|| refused(format!("admin key '{label}'")))?
                .to_string();
            ConfigOp::Admin(AdminOp::SetKey { label, secret })
        }
        ConfigOp::User(UserOp::SetPassword { name, password }) if password == HIDDEN => {
            let old = earlier
                .iter()
                .find_map(|c| c.users.iter().find(|u| u.name == name));
            let password = old
                .ok_or_else(|| refused(format!("user '{name}'")))?
                .password
                .clone();
            ConfigOp::User(UserOp::SetPassword { name, password })
        }
        op => op,
    })
}

#[cfg(test)]
mod tests {
    use nos_proto::{Admin, AdminKey, User};

    use super::*;

    fn cfg(secret: &str, pw: &str) -> Config {
        Config {
            admin: Admin {
                keys: vec![AdminKey {
                    label: "k".into(),
                    secret: secret.into(),
                }],
            },
            users: vec![User {
                name: "u".into(),
                password: pw.into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn mask_keeps_the_earlier_value() {
        let mut c = cfg(HIDDEN, HIDDEN);
        restore_masked(&mut c, &[&Config::default(), &cfg("real", "$argon2id$x")]).unwrap();
        assert_eq!(c, cfg("real", "$argon2id$x"));
    }

    #[test]
    fn mask_on_a_new_label_or_user_is_refused() {
        let mut c = cfg(HIDDEN, "$argon2id$x");
        assert!(matches!(
            restore_masked(&mut c, &[&Config::default()]),
            Err(ConfigError::MaskedSecret(w)) if w.contains("admin key 'k'")
        ));
        let mut c = cfg("s", HIDDEN);
        assert!(matches!(
            restore_masked(&mut c, &[&Config::default()]),
            Err(ConfigError::MaskedSecret(w)) if w.contains("user 'u'")
        ));
    }

    #[test]
    fn real_values_are_untouched() {
        let mut c = cfg("new", "$argon2id$y");
        restore_masked(&mut c, &[&cfg("old", "$argon2id$x")]).unwrap();
        assert_eq!(c, cfg("new", "$argon2id$y"));
    }

    #[test]
    fn masked_ops_are_rewritten_or_refused() {
        let set_key = |s: &str| {
            ConfigOp::Admin(AdminOp::SetKey {
                label: "k".into(),
                secret: s.into(),
            })
        };
        let set_pw = |s: &str| {
            ConfigOp::User(UserOp::SetPassword {
                name: "u".into(),
                password: s.into(),
            })
        };
        let old = cfg("real", "$argon2id$x");
        assert_eq!(
            unmask_op(set_key(HIDDEN), &[&old]).unwrap(),
            set_key("real")
        );
        assert_eq!(
            unmask_op(set_pw(HIDDEN), &[&old]).unwrap(),
            set_pw("$argon2id$x")
        );
        assert_eq!(unmask_op(set_key("v"), &[&old]).unwrap(), set_key("v"));
        let none = Config::default();
        assert!(unmask_op(set_key(HIDDEN), &[&none]).is_err());
        assert!(unmask_op(set_pw(HIDDEN), &[&none]).is_err());
        // Any other op passes through.
        let h = ConfigOp::SetHostname("h".into());
        assert_eq!(unmask_op(h.clone(), &[&none]).unwrap(), h);
    }
}
