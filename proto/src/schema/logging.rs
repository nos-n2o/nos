//! Log export settings (`Config.logging`): RFC 5424 syslog to remote
//! collectors, sent by `nos-logd` (#71).

use std::net::IpAddr;

use garde::Validate;
use nos_proto_derive::Cli;
use serde::{Deserialize, Serialize};

use crate::log::LogLevel;
use crate::validators::{routing_table_reference_valid, unique_key_in};

use super::Config;

/// System-wide logging settings.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct LoggingSettings {
    /// Remote syslog collectors every log entry is exported to.
    #[serde(default)]
    #[garde(
        dive,
        custom(|v: &Vec<SyslogServer>, _ctx: &Config| tls_consistent(v))
    )]
    #[cli(topic = LoggingSyslog, words = "syslog")]
    pub syslog: Vec<SyslogServer>,
}

/// One remote syslog collector (RFC 5424 messages).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct SyslogServer {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n: &String, ctx: &Config| unique_key_in(n, &ctx.logging.syslog, |s| &s.name))
    )]
    #[cli(key)]
    /// Collector name, unique among syslog servers.
    pub name: String,

    /// The collector's address. An IP, not a name: there is no resolver
    /// inside a VRF.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[garde(custom(|a: &IpAddr, _ctx: &Config| valid_address(a)))]
    #[cli(topic = SyslogAddress)]
    pub address: IpAddr,

    /// Destination port. Default: 514 (udp), 601 (tcp), 6514 (tls).
    #[serde(default)]
    #[garde(custom(|p: &Option<u16>, _ctx: &Config| valid_port(*p)))]
    #[cli(topic = SyslogPort)]
    pub port: Option<u16>,

    /// Transport. Default `udp` (RFC 5426); `tcp` uses RFC 6587 octet counting;
    /// `tls` is RFC 5425 over post-quantum TLS 1.3 and needs a `tls` block.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = SyslogTransport)]
    pub transport: SyslogTransport,

    /// Send from inside this routing table's VRF. Default: the default netns.
    #[serde(default)]
    #[garde(custom(|rt: &Option<String>, ctx: &Config| routing_table_reference_valid(rt.as_ref(), ctx)))]
    #[cli(topic = SyslogRoutingTable)]
    pub routing_table: Option<String>,

    /// Minimum severity exported. Default `info`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = SyslogLevel)]
    pub level: Option<LogLevel>,

    /// Syslog facility of every message. Default `local7`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = SyslogFacility)]
    pub facility: Option<SyslogFacility>,

    /// How the collector is authenticated; required by (and only valid with)
    /// transport `tls`. There is no "trust anything" mode.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = SyslogTls)]
    pub tls: Option<SyslogTls>,
}

/// Authentication of a TLS syslog collector (RFC 5425 §4.2). Server
/// authentication only: `nos-logd` presents no client certificate.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct SyslogTls {
    /// PEM CA certificate(s) the collector's certificate must chain to
    /// (RFC 5425 §4.2.1). Exactly one of this and `fingerprint`.
    #[serde(default)]
    #[cli(topic = SyslogTlsTrustAnchor)]
    pub trust_anchor: Option<String>,

    /// `SHA-256:AB:CD:...`: the SHA-256 of the collector's own certificate
    /// (RFC 5425 §4.2.2). Exactly one of this and `trust_anchor`.
    #[serde(default)]
    #[cli(topic = SyslogTlsFingerprint)]
    pub fingerprint: Option<String>,

    /// The DNS name the collector's certificate must carry. Default: match the
    /// collector's address against the certificate's IP address SANs.
    #[serde(default)]
    #[cli(topic = SyslogTlsServerName)]
    pub server_name: Option<String>,

    /// Also allows TLS 1.2 with classical (non-post-quantum) key exchange, for
    /// collectors that need RFC 9662; TLS 1.3 stays post-quantum only, but
    /// traffic sent over TLS 1.2 can be decrypted by a future quantum computer.
    #[serde(default)]
    #[cli(topic = SyslogTlsAllowTls12)]
    pub allow_tls12: bool,
}

/// `SHA-256:` plus 32 colon-separated hex octets (case-insensitive).
pub fn parse_fingerprint(s: &str) -> Option<[u8; 32]> {
    let rest = s.strip_prefix("SHA-256:")?;
    let mut out = [0u8; 32];
    let mut parts = rest.split(':');
    for b in &mut out {
        let p = parts.next()?;
        if p.len() != 2 || !p.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn tls_consistent(servers: &[SyslogServer]) -> garde::Result {
    for s in servers {
        let n = &s.name;
        match (s.transport, &s.tls) {
            (SyslogTransport::Tls, None) => {
                return Err(garde::Error::new(format!(
                    "syslog server '{n}': transport tls needs a tls block (trust-anchor or fingerprint)"
                )))
            }
            (SyslogTransport::Tls, Some(t)) => {
                if t.trust_anchor.is_some() == t.fingerprint.is_some() {
                    return Err(garde::Error::new(format!(
                        "syslog server '{n}': set exactly one of tls trust-anchor and fingerprint"
                    )));
                }
                if t.fingerprint.as_deref().is_some_and(|f| parse_fingerprint(f).is_none()) {
                    return Err(garde::Error::new(format!(
                        "syslog server '{n}': fingerprint must be SHA-256:XX:XX:... (32 octets)"
                    )));
                }
                if t.server_name.as_deref().is_some_and(str::is_empty) {
                    return Err(garde::Error::new(format!(
                        "syslog server '{n}': tls server-name is empty"
                    )));
                }
            }
            (_, Some(_)) => {
                return Err(garde::Error::new(format!(
                    "syslog server '{n}': tls settings need transport tls (delete them)"
                )))
            }
            (_, None) => {}
        }
    }
    Ok(())
}

impl Default for SyslogServer {
    fn default() -> Self {
        SyslogServer {
            name: String::new(),
            address: IpAddr::from([0, 0, 0, 0]),
            port: None,
            transport: SyslogTransport::default(),
            routing_table: None,
            level: None,
            facility: None,
            tls: None,
        }
    }
}

impl SyslogServer {
    /// The configured port, else 514 (UDP), 601 (TCP) or 6514 (TLS).
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(match self.transport {
            SyslogTransport::Udp => 514,
            SyslogTransport::Tcp => 601,
            SyslogTransport::Tls => 6514,
        })
    }

    /// The configured minimum level, else `Info`.
    pub fn effective_level(&self) -> LogLevel {
        self.level.unwrap_or(LogLevel::Info)
    }

    /// The configured facility, else `Local7`.
    pub fn effective_facility(&self) -> SyslogFacility {
        self.facility.unwrap_or(SyslogFacility::Local7)
    }
}

fn valid_address(a: &IpAddr) -> garde::Result {
    if a.is_unspecified() || a.is_multicast() {
        return Err(garde::Error::new(
            "syslog address must be a unicast address",
        ));
    }
    Ok(())
}

fn valid_port(p: Option<u16>) -> garde::Result {
    if p == Some(0) {
        return Err(garde::Error::new("syslog port must be 1-65535"));
    }
    Ok(())
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
/// How a syslog server is reached.
pub enum SyslogTransport {
    /// RFC 5426: one message per datagram.
    #[default]
    Udp,
    /// RFC 6587 octet-counted frames on one connection.
    Tcp,
    /// RFC 5425 octet-counted frames inside TLS (post-quantum TLS 1.3).
    Tls,
}

/// The user-level facilities, `local0`-`local7`; the others are reserved for
/// operating-system subsystems.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub enum SyslogFacility {
    /// Facility `local0` (code 16).
    Local0,
    /// Facility `local1` (code 17).
    Local1,
    /// Facility `local2` (code 18).
    Local2,
    /// Facility `local3` (code 19).
    Local3,
    /// Facility `local4` (code 20).
    Local4,
    /// Facility `local5` (code 21).
    Local5,
    /// Facility `local6` (code 22).
    Local6,
    #[default]
    /// Facility `local7` (code 23).
    Local7,
}

impl SyslogFacility {
    /// RFC 5424 Table 1 numerical code (local0 is 16).
    pub const fn code(self) -> u8 {
        16 + self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(name: &str) -> SyslogServer {
        SyslogServer {
            name: name.into(),
            address: "192.0.2.9".parse().unwrap(),
            ..SyslogServer::default()
        }
    }

    fn cfg(servers: Vec<SyslogServer>) -> Config {
        let mut c = Config::default();
        c.logging.syslog = servers;
        c
    }

    fn ok(c: &Config) -> bool {
        c.validate_with(c).is_ok()
    }

    #[test]
    fn defaults() {
        let s = server("c1");
        assert_eq!(s.effective_port(), 514);
        assert_eq!(s.effective_level(), LogLevel::Info);
        assert_eq!(s.effective_facility().code(), 23);
        let t = SyslogServer {
            transport: SyslogTransport::Tcp,
            ..s
        };
        assert_eq!(t.effective_port(), 601);
    }

    #[test]
    fn facility_codes_follow_rfc_5424() {
        assert_eq!(SyslogFacility::Local0.code(), 16);
        assert_eq!(SyslogFacility::Local3.code(), 19);
    }

    #[test]
    fn validation_rules() {
        assert!(ok(&cfg(vec![server("a"), server("b")])));
        assert!(!ok(&cfg(vec![server("a"), server("a")])));
        let mut s = server("a");
        s.port = Some(0);
        assert!(!ok(&cfg(vec![s])));
        let mut s = server("a");
        s.address = "0.0.0.0".parse().unwrap();
        assert!(!ok(&cfg(vec![s])));
        let mut s = server("a");
        s.address = "224.0.0.1".parse().unwrap();
        assert!(!ok(&cfg(vec![s])));
        let mut s = server("a");
        s.routing_table = Some("nope".into());
        assert!(!ok(&cfg(vec![s])));
    }

    #[test]
    fn routing_table_must_exist() {
        let mut c = cfg(vec![]);
        c.routing_tables.push(crate::schema::RoutingTable {
            name: "rt1".into(),
            ..Default::default()
        });
        let mut s = server("a");
        s.routing_table = Some("rt1".into());
        c.logging.syslog = vec![s];
        assert!(ok(&c));
        c.routing_tables.clear();
        assert!(!ok(&c));
    }

    fn tls_server(tls: Option<SyslogTls>) -> SyslogServer {
        SyslogServer {
            transport: SyslogTransport::Tls,
            tls,
            ..server("t")
        }
    }

    const FP: &str = "SHA-256:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";

    #[test]
    fn tls_rules() {
        let anchor = SyslogTls {
            trust_anchor: Some("pem".into()),
            ..SyslogTls::default()
        };
        let fp = SyslogTls {
            fingerprint: Some(FP.into()),
            ..SyslogTls::default()
        };
        assert!(ok(&cfg(vec![tls_server(Some(anchor.clone()))])));
        assert!(ok(&cfg(vec![tls_server(Some(fp.clone()))])));
        // no tls block, an empty one, both trust modes, a bad fingerprint
        assert!(!ok(&cfg(vec![tls_server(None)])));
        assert!(!ok(&cfg(vec![tls_server(Some(SyslogTls::default()))])));
        let both = SyslogTls {
            fingerprint: fp.fingerprint.clone(),
            ..anchor.clone()
        };
        assert!(!ok(&cfg(vec![tls_server(Some(both))])));
        let bad = SyslogTls {
            fingerprint: Some("SHA-256:00".into()),
            ..SyslogTls::default()
        };
        assert!(!ok(&cfg(vec![tls_server(Some(bad))])));
        // allow_tls12 is valid with both trust modes
        for t in [anchor.clone(), fp] {
            let t = SyslogTls {
                allow_tls12: true,
                ..t
            };
            assert!(ok(&cfg(vec![tls_server(Some(t))])));
        }
        // a tls block on a non-tls transport
        let mut s = server("a");
        s.tls = Some(anchor);
        assert!(!ok(&cfg(vec![s])));
        assert_eq!(tls_server(None).effective_port(), 6514);
    }

    #[test]
    fn tls_block_without_allow_tls12_loads_as_false() {
        let t: SyslogTls = serde_json::from_str(r#"{"fingerprint":"x"}"#).unwrap();
        assert!(!t.allow_tls12);
    }

    #[test]
    fn fingerprint_parsing() {
        assert_eq!(parse_fingerprint(FP).unwrap()[15], 0xff);
        assert!(parse_fingerprint("SHA-1:00").is_none());
        assert!(parse_fingerprint(&format!("{FP}:00")).is_none());
        assert!(parse_fingerprint(&FP.replace(":ff", ":fg")).is_none());
        assert!(parse_fingerprint(&FP.replace(":ff", ":f")).is_none());
    }

    #[test]
    fn config_without_logging_still_loads() {
        let json = serde_json::to_value(Config::default()).unwrap();
        let mut obj = json.as_object().unwrap().clone();
        obj.remove("logging");
        let c: Config = serde_json::from_value(obj.into()).unwrap();
        assert_eq!(c.logging, LoggingSettings::default());
    }
}
