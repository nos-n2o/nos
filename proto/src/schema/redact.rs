//! Per-role visibility of secrets (#384). `nos-configd` runs every config
//! reply and diff through [`Config::for_role`], so a daemon only receives the
//! password hashes and admin-keystore secrets it can actually use. It is a
//! second layer after the request allow-list (`nos-config`'s `authz`).

use std::collections::BTreeSet;

use crate::broker::Role;

use super::{Admin, BgpAuth, Config, OspfAuth, User};

/// Which key families a role may read. Exhaustive `match` on [`Role`]: a
/// new role must be classified here before it compiles.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Visible {
    users: bool,
    /// Everything in the keystore, referenced or not (people and the REST bridge).
    all_keys: bool,
    bgp: bool,
    ospf: bool,
    ospfv3: bool,
    bfd: bool,
}

fn visible(role: Role) -> Visible {
    let none = Visible {
        users: false,
        all_keys: false,
        bgp: false,
        ospf: false,
        ospfv3: false,
        bfd: false,
    };
    match role {
        Role::User | Role::Restd => Visible {
            users: true,
            all_keys: true,
            ..none
        },
        // Verifies logins, holds no protocol keys.
        Role::Watchdog => Visible {
            users: true,
            ..none
        },
        Role::Bgpd => Visible {
            bgp: true,
            bfd: true,
            ..none
        },
        Role::Ospfd => Visible {
            ospf: true,
            bfd: true,
            ..none
        },
        Role::Ospfv3d => Visible {
            ospfv3: true,
            bfd: true,
            ..none
        },
        // Ribd and Bfdd register BFD sessions with the profile's auth.
        Role::Ribd | Role::Bfdd => Visible { bfd: true, ..none },
        Role::Configd
        | Role::Logd
        | Role::Interfaced
        | Role::Lacpd
        | Role::Lldpd
        | Role::Fdbd
        | Role::Stpd
        | Role::Acld => none,
    }
}

/// What a role sees of a config: two roles with the same class get the same
/// [`Config::for_role`] output, so a caller can compute one diff per class
/// instead of one per subscriber (#751).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ViewClass(Visible);

impl ViewClass {
    /// The class of `role`.
    #[must_use]
    pub fn of(role: Role) -> Self {
        Self(visible(role))
    }
}

fn bgp_labels(a: Option<&BgpAuth>, out: &mut BTreeSet<String>) {
    match a {
        Some(BgpAuth::Md5 { key_ref }) => {
            out.insert(key_ref.clone());
        }
        Some(BgpAuth::Ao { keys }) => out.extend(keys.iter().map(|k| k.key_ref.clone())),
        None => {}
    }
}

fn ospf_labels(a: Option<&OspfAuth>, out: &mut BTreeSet<String>) {
    match a {
        Some(OspfAuth::Simple { key }) => {
            out.insert(key.clone());
        }
        Some(OspfAuth::Crypto { keys }) => out.extend(keys.iter().map(|k| k.key.clone())),
        None => {}
    }
}

impl Config {
    /// A copy holding only the secrets `role` may see: `users` (password
    /// hashes) and the admin-keystore entries its sections reference. The
    /// auth structures keep their labels, so the config still parses.
    #[must_use]
    pub fn for_role(&self, role: Role) -> Config {
        let (users, admin) = self.role_secrets(role);
        Config {
            users,
            admin,
            ..self.clone()
        }
    }

    /// The only two fields [`Config::for_role`] changes, as `role` sees them:
    /// `users` and `admin`. Everything else is `self`'s, so a per-role diff
    /// only re-diffs these (`diff_configs_for_role`, #778).
    #[must_use]
    pub fn role_secrets(&self, role: Role) -> (Vec<User>, Admin) {
        let v = visible(role);
        let users = if v.users {
            self.users.clone()
        } else {
            Vec::new()
        };
        let mut admin = self.admin.clone();
        if v.all_keys {
            return (users, admin);
        }
        let mut keep = BTreeSet::new();
        if v.bgp {
            for i in &self.bgp_instances {
                i.peer_groups
                    .iter()
                    .for_each(|g| bgp_labels(g.auth.as_ref(), &mut keep));
                i.rpki_caches
                    .iter()
                    .for_each(|c| bgp_labels(c.auth.as_ref(), &mut keep));
            }
        }
        if v.ospf {
            for a in self.ospf_instances.iter().flat_map(|i| &i.areas) {
                a.profiles
                    .iter()
                    .for_each(|p| ospf_labels(p.auth.as_ref(), &mut keep));
                a.virtual_links
                    .iter()
                    .for_each(|l| ospf_labels(l.auth.as_ref(), &mut keep));
            }
        }
        if v.ospfv3 {
            for p in self
                .ospfv3_instances
                .iter()
                .flat_map(|i| &i.areas)
                .flat_map(|a| &a.profiles)
            {
                keep.extend(p.auth.iter().flatten().map(|k| k.key.clone()));
            }
        }
        if v.bfd {
            keep.extend(
                self.bfd_profiles
                    .iter()
                    .filter_map(|p| p.auth.as_ref().map(|a| a.key.clone())),
            );
        }
        admin.keys.retain(|k| keep.contains(&k.label));
        (users, admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        AdminKey, BfdAuth, BfdProfile, BgpAoKey, BgpInstance, BgpPeerGroup, OspfArea,
        OspfCryptoKey, OspfInstance, OspfProfile, Ospfv3Area, Ospfv3Instance, Ospfv3Profile,
        RpkiCache, User,
    };

    const SENTINELS: [&str; 6] = [
        "SECRET-bgp",
        "SECRET-rpki",
        "SECRET-ospf2",
        "SECRET-ospfv3",
        "SECRET-bfd",
        "SECRET-user",
    ];

    /// A sentinel in every secret place. A new secret-bearing field must be
    /// added here (and to `for_role`), or this test cannot notice it.
    #[allow(clippy::field_reassign_with_default)] // a long literal reads worse
    fn fixture() -> Config {
        let key = |l: &str| AdminKey {
            label: l.into(),
            secret: format!("SECRET-{l}"),
        };
        let crypto = |l: &str| OspfCryptoKey {
            key_id: 1,
            algorithm: crate::schema::OspfCryptoAlgorithm::HmacSha256,
            key: l.into(),
            is_current: true,
        };
        let mut c = Config::default();
        c.hostname = "visible-host".into();
        c.admin.keys = ["bgp", "rpki", "ospf2", "ospfv3", "bfd"].map(key).to_vec();
        c.users = vec![User {
            name: "u".into(),
            password: "SECRET-user".into(),
        }];
        c.bgp_instances = vec![BgpInstance {
            peer_groups: vec![BgpPeerGroup {
                auth: Some(BgpAuth::Ao {
                    keys: vec![BgpAoKey {
                        send_id: 1,
                        recv_id: 1,
                        algorithm: crate::schema::BgpAoAlgorithm::HmacSha1_96,
                        key_ref: "bgp".into(),
                        is_current: true,
                        is_rnext: false,
                        exclude_options: false,
                    }],
                }),
                ..Default::default()
            }],
            bmp_stations: Vec::new(),
            rpki_caches: vec![RpkiCache {
                auth: Some(BgpAuth::Md5 {
                    key_ref: "rpki".into(),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }];
        c.ospf_instances = vec![OspfInstance {
            areas: vec![OspfArea {
                profiles: vec![OspfProfile {
                    auth: Some(OspfAuth::Crypto {
                        keys: vec![crypto("ospf2")],
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }];
        c.ospfv3_instances = vec![Ospfv3Instance {
            areas: vec![Ospfv3Area {
                profiles: vec![Ospfv3Profile {
                    auth: Some(vec![crypto("ospfv3")]),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }];
        c.bfd_profiles = vec![BfdProfile {
            auth: Some(BfdAuth {
                key: "bfd".into(),
                ..Default::default()
            }),
            ..Default::default()
        }];
        c
    }

    fn seen(c: &Config) -> Vec<&'static str> {
        let json = serde_json::to_string(c).unwrap();
        SENTINELS.into_iter().filter(|s| json.contains(s)).collect()
    }

    #[test]
    fn each_role_sees_exactly_its_secrets() {
        let cfg = fixture();
        for role in Role::ALL {
            let want: Vec<&str> = match role {
                Role::User | Role::Restd => SENTINELS.to_vec(),
                Role::Watchdog => vec!["SECRET-user"],
                Role::Bgpd => vec!["SECRET-bgp", "SECRET-rpki", "SECRET-bfd"],
                Role::Ospfd => vec!["SECRET-ospf2", "SECRET-bfd"],
                Role::Ospfv3d => vec!["SECRET-ospfv3", "SECRET-bfd"],
                Role::Ribd | Role::Bfdd => vec!["SECRET-bfd"],
                Role::Configd
                | Role::Logd
                | Role::Interfaced
                | Role::Lacpd
                | Role::Lldpd
                | Role::Fdbd
                | Role::Stpd
                | Role::Acld => vec![],
            };
            let got = cfg.for_role(role);
            assert_eq!(seen(&got), want, "{role:?}");
            // Everything but the secrets is untouched.
            assert_eq!(got.hostname, "visible-host");
            assert_eq!(got.bgp_instances, cfg.bgp_instances, "{role:?}");
            assert_eq!(got.bfd_profiles, cfg.bfd_profiles, "{role:?}");
        }
    }

    /// #778: the per-role diff without projections equals the diff of the
    /// projections, for every role and secret edit.
    #[test]
    fn the_per_role_diff_matches_the_diff_of_the_projections() {
        let base = fixture();
        let mut cands = vec![Config::default(), base.clone()];
        let mut c = base.clone();
        c.admin.keys[0].secret = "SECRET-changed".into();
        c.users[0].password = "SECRET-other".into();
        c.hostname = "h2".into();
        cands.push(c);
        let mut c = base.clone();
        c.admin.keys.remove(4);
        c.users.clear();
        c.bgp_instances.clear();
        cands.push(c);
        for cand in &cands {
            for role in Role::ALL {
                for (b, c) in [(&base, cand), (cand, &base)] {
                    assert_eq!(
                        crate::diff_configs_for_role(b, c, role),
                        crate::diff_configs(&b.for_role(role), &c.for_role(role)),
                        "{role:?}"
                    );
                }
            }
        }
    }
}
