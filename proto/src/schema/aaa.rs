//! Login backends (`Config.aaa`, #1153): RADIUS servers `nos-watchdogd`'s
//! login broker asks, and the order it tries backends in.

use std::net::IpAddr;

use garde::Validate;
use nos_proto_derive::Cli;
use serde::{Deserialize, Serialize};

use crate::validators::{routing_table_reference_valid, unique_key_in};

use super::Config;

/// RADIUS authentication port (RFC 2865), unless configured.
pub const RADIUS_PORT_DEFAULT: u16 = 1812;
/// Seconds to wait for one reply, unless configured.
pub const RADIUS_TIMEOUT_DEFAULT_SECS: u8 = 3;
/// RADIUS accounting port (RFC 2866), unless configured.
pub const RADIUS_ACCT_PORT_DEFAULT: u16 = 1813;
/// Extra attempts per server, unless configured.
pub const RADIUS_RETRIES_DEFAULT: u8 = 2;

/// Where a password login is checked.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum LoginBackend {
    /// The local `users` list.
    #[default]
    Local,
    /// The configured RADIUS servers.
    Radius,
}

/// The Access-Accept attribute whose text names the user's role
/// (`admin`, `operator` or `read-only`; anything else is read-only).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum RoleAttribute {
    /// Filter-Id (11).
    #[default]
    FilterId,
    /// Class (25).
    Class,
    /// Reply-Message (18).
    ReplyMessage,
}

/// Login and accounting backends.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct Aaa {
    /// RADIUS servers, tried in list order.
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = AaaRadiusServer, words = "radius-server")]
    pub servers: Vec<RadiusServer>,

    /// Backends tried in order; empty means `local` only. A RADIUS reject
    /// ends the login; the next backend is tried only when no server
    /// answered (or, after `local`, when no such local user exists).
    #[serde(default)]
    #[garde(custom(|v: &Vec<LoginBackend>, ctx: &Config| valid_order(v, ctx)))]
    #[cli(topic = AaaLoginOrder, words = "login-order")]
    pub login_order: Vec<LoginBackend>,

    /// Send RADIUS accounting (RFC 2866) to every server: a Start at each
    /// login, a Stop when its session ends, and an Interim-Update per config
    /// commit. Best effort through a bounded queue; never delays a login or a
    /// commit. Default off.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = AaaAccounting)]
    pub accounting: bool,

    /// Where the reply carries the role. Default `filter-id`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = AaaRoleAttribute, words = "role-attribute")]
    pub role_attribute: RoleAttribute,
}

/// One RADIUS server.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct RadiusServer {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n: &String, ctx: &Config| unique_key_in(n, &ctx.aaa.servers, |s| &s.name))
    )]
    #[cli(key)]
    /// Server name, unique among RADIUS servers.
    pub name: String,

    /// The server's address (an IP: there is no resolver).
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[garde(custom(|a: &IpAddr, _ctx: &Config| valid_address(a)))]
    #[cli(topic = RadiusAddress)]
    pub address: IpAddr,

    /// UDP port. Default 1812.
    #[serde(default)]
    #[garde(custom(|p: &Option<u16>, _ctx: &Config| valid_port(*p)))]
    #[cli(topic = RadiusPort)]
    pub port: Option<u16>,

    /// Accounting UDP port. Default 1813.
    #[serde(default)]
    #[garde(custom(|p: &Option<u16>, _ctx: &Config| valid_port(*p)))]
    #[cli(topic = RadiusAccountingPort)]
    pub accounting_port: Option<u16>,

    /// Send from inside this routing table's VRF. Default: the default netns.
    #[serde(default)]
    #[garde(custom(|rt: &Option<String>, ctx: &Config| routing_table_reference_valid(rt.as_ref(), ctx)))]
    #[cli(topic = RadiusRoutingTable)]
    pub routing_table: Option<String>,

    /// Label of the admin-keystore entry holding the shared secret (never
    /// inline: the keystore is masked for REST and the CLI).
    #[garde(custom(|l: &String, ctx: &Config| valid_secret(l, ctx)))]
    #[cli(topic = RadiusSecretRef)]
    pub secret_ref: String,

    /// Seconds to wait per attempt, 1 to 30. Default 3.
    #[serde(default)]
    #[garde(custom(|t: &Option<u8>, _ctx: &Config| in_range(*t, 30, "timeout")))]
    #[cli(topic = RadiusTimeout)]
    pub timeout_secs: Option<u8>,

    /// Extra attempts before the next server, 0 to 10. Default 2.
    #[serde(default)]
    #[garde(custom(|t: &Option<u8>, _ctx: &Config| zero_to(*t, 10, "retries")))]
    #[cli(topic = RadiusRetries)]
    pub retries: Option<u8>,
}

impl Default for RadiusServer {
    fn default() -> Self {
        RadiusServer {
            name: String::new(),
            address: IpAddr::from([0, 0, 0, 0]),
            port: None,
            accounting_port: None,
            routing_table: None,
            secret_ref: String::new(),
            timeout_secs: None,
            retries: None,
        }
    }
}

fn valid_address(a: &IpAddr) -> garde::Result {
    if a.is_unspecified() || a.is_multicast() {
        return Err(garde::Error::new(
            "a RADIUS server address must be a unicast address",
        ));
    }
    Ok(())
}

fn valid_port(p: Option<u16>) -> garde::Result {
    if p == Some(0) {
        return Err(garde::Error::new("a RADIUS port must be 1 to 65535"));
    }
    Ok(())
}

fn in_range(v: Option<u8>, max: u8, what: &str) -> garde::Result {
    match v {
        Some(0) => Err(garde::Error::new(format!(
            "RADIUS {what} must be at least 1"
        ))),
        Some(n) if n > max => Err(garde::Error::new(format!("RADIUS {what} is at most {max}"))),
        _ => Ok(()),
    }
}

fn zero_to(v: Option<u8>, max: u8, what: &str) -> garde::Result {
    match v {
        Some(n) if n > max => Err(garde::Error::new(format!("RADIUS {what} is at most {max}"))),
        _ => Ok(()),
    }
}

fn valid_secret(label: &str, cfg: &Config) -> garde::Result {
    match cfg.key(label) {
        None => Err(garde::Error::new(format!(
            "radius-server references unknown admin key '{label}'"
        ))),
        Some("") => Err(garde::Error::new(format!(
            "admin key '{label}' is empty, a RADIUS shared secret cannot be"
        ))),
        Some(_) => Ok(()),
    }
}

fn valid_order(order: &[LoginBackend], cfg: &Config) -> garde::Result {
    for (i, b) in order.iter().enumerate() {
        if order[..i].contains(b) {
            return Err(garde::Error::new(format!("login-order lists {b:?} twice")));
        }
    }
    if order.contains(&LoginBackend::Radius) && cfg.aaa.servers.is_empty() {
        return Err(garde::Error::new(
            "login-order names radius but no radius-server is configured",
        ));
    }
    Ok(())
}

impl Aaa {
    /// The effective order: `local` alone when none is configured.
    #[must_use]
    pub fn order(&self) -> Vec<LoginBackend> {
        if self.login_order.is_empty() {
            vec![LoginBackend::Local]
        } else {
            self.login_order.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Admin, AdminKey};

    fn cfg(order: Vec<LoginBackend>, secret: &str, label: &str) -> Config {
        Config {
            admin: Admin {
                keys: vec![AdminKey {
                    label: "radius".into(),
                    secret: secret.into(),
                }],
            },
            aaa: Aaa {
                servers: vec![RadiusServer {
                    name: "r1".into(),
                    address: "192.0.2.1".parse().unwrap(),
                    port: None,
                    accounting_port: None,
                    routing_table: None,
                    secret_ref: label.into(),
                    timeout_secs: None,
                    retries: None,
                }],
                login_order: order,
                role_attribute: RoleAttribute::default(),
                accounting: false,
            },
            ..Default::default()
        }
    }

    fn ok(c: &Config) -> bool {
        c.validate_with(c).is_ok()
    }

    #[test]
    fn validation() {
        use LoginBackend::{Local, Radius};
        assert!(ok(&cfg(vec![Radius, Local], "s", "radius")));
        assert!(!ok(&cfg(vec![Radius, Radius], "s", "radius")), "duplicate");
        assert!(!ok(&cfg(vec![], "s", "nope")), "unknown key");
        assert!(!ok(&cfg(vec![], "", "radius")), "empty secret");
        let mut c = cfg(vec![Radius], "s", "radius");
        c.aaa.servers.clear();
        assert!(!ok(&c), "radius without servers");
        let mut c = cfg(vec![], "s", "radius");
        c.aaa.servers[0].timeout_secs = Some(31);
        assert!(!ok(&c));
        c.aaa.servers[0].timeout_secs = Some(5);
        c.aaa.servers[0].retries = Some(11);
        assert!(!ok(&c));
        c.aaa.servers[0].retries = Some(0);
        c.aaa.servers[0].port = Some(0);
        assert!(!ok(&c));
        c.aaa.servers[0].port = Some(1812);
        c.aaa.servers[0].address = "0.0.0.0".parse().unwrap();
        assert!(!ok(&c));
    }

    #[test]
    fn order_defaults_to_local() {
        assert_eq!(Aaa::default().order(), vec![LoginBackend::Local]);
    }
}
