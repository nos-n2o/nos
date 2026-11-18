//! Who is on the other end of a connection: a `(role, name)` pair carried in
//! one URI SAN of the peer's certificate, `nos://<role>/<name>`.

use std::fmt::{self, Write};

use x509_parser::extensions::GeneralName;

/// The pseudo-role of the extra URI SAN that carries a role claim.
pub(crate) const CLAIM_ROLE: &str = "claim";

/// Who a peer is: the `nos://<role>/<name>` URI SAN of its certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId {
    /// A daemon family or `user`: `bgpd`, `ribd`, `configd`, ….
    pub role: String,
    /// The instance/table/user name; empty for a singleton daemon.
    pub name: String,
}

impl PeerId {
    /// Builds a `PeerId` from a role and an instance name.
    pub fn new(role: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            name: name.into(),
        }
    }

    pub(crate) fn uri(&self) -> String {
        let mut out = format!("nos://{}/", self.role);
        for b in self.name.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') {
                out.push(b as char);
            } else {
                let _ = write!(out, "%{b:02X}");
            }
        }
        out
    }

    fn parse(uri: &str) -> Option<Self> {
        let (role, name) = uri.strip_prefix("nos://")?.split_once('/')?;
        let mut bytes = Vec::with_capacity(name.len());
        let mut it = name.bytes();
        while let Some(b) = it.next() {
            if b == b'%' {
                let hex = [it.next()?, it.next()?];
                bytes.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
            } else {
                bytes.push(b);
            }
        }
        Some(Self::new(role, String::from_utf8(bytes).ok()?))
    }

    /// The role claim (`nos://claim/<claim>` URI SAN) a CA-signed certificate
    /// carries, if any: see `Ca::sign_csr_claiming`.
    pub(crate) fn claim_from_cert_der(der: &[u8]) -> Option<String> {
        let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
        let san = cert.subject_alternative_name().ok()??;
        san.value.general_names.iter().find_map(|g| match g {
            GeneralName::URI(u) => Self::parse(u)
                .filter(|p| p.role == CLAIM_ROLE)
                .map(|p| p.name),
            _ => None,
        })
    }

    /// The identity a (CA-signed) certificate asserts. The CA writes exactly
    /// one `nos://` URI SAN, so the first one is the one.
    pub(crate) fn from_cert_der(der: &[u8]) -> Option<Self> {
        let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
        let san = cert.subject_alternative_name().ok()??;
        san.value.general_names.iter().find_map(|g| match g {
            GeneralName::URI(u) => Self::parse(u),
            _ => None,
        })
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.role, self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_round_trips_awkward_names() {
        for name in ["rt1", "", "a b/c", "vrf%1", "é"] {
            let id = PeerId::new("ribd", name);
            assert_eq!(PeerId::parse(&id.uri()), Some(id));
        }
    }

    #[test]
    fn uri_is_byte_exact_and_escapes_uppercase_hex() {
        assert_eq!(PeerId::new("ribd", "a.b-c_d9").uri(), "nos://ribd/a.b-c_d9");
        assert_eq!(PeerId::new("x", " ").uri(), "nos://x/%20");
        assert_eq!(PeerId::new("x", "/").uri(), "nos://x/%2F");
        assert_eq!(PeerId::new("x", "%").uri(), "nos://x/%25");
        assert_eq!(PeerId::new("x", "\u{e9}").uri(), "nos://x/%C3%A9");
        for name in [".", "-", "_", "._-", "a b/c%\u{e9}"] {
            let id = PeerId::new("ribd", name);
            assert_eq!(PeerId::parse(&id.uri()), Some(id));
        }
    }

    #[test]
    fn display_is_role_slash_name() {
        assert_eq!(PeerId::new("ribd", "rt1").to_string(), "ribd/rt1");
    }

    #[test]
    fn foreign_uris_are_not_identities() {
        assert_eq!(PeerId::parse("https://ribd/rt1"), None);
        assert_eq!(PeerId::parse("nos://ribd"), None);
        assert_eq!(PeerId::parse("nos://ribd/%zz"), None);
    }
}
