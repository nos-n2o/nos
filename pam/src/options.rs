use std::ffi::CStr;
use std::path::PathBuf;

use nos_proto::{DEFAULT_PKI_CA, DEFAULT_WATCHDOG_SOCKET};

/// Module arguments from the PAM stack line.
#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    /// `socket=`: the watchdog's broker socket.
    pub socket: PathBuf,
    /// `ca=`: the CA certificate (PEM) the broker's certificate must chain to.
    pub ca: PathBuf,
    /// `use_first_pass`: take the password already in `PAM_AUTHTOK`, never prompt.
    pub use_first_pass: bool,
    /// `try_first_pass`: accepted for stack compatibility; the password comes from
    /// `PAM_AUTHTOK` when set and from a prompt otherwise (what `authtok` does).
    pub try_first_pass: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            socket: DEFAULT_WATCHDOG_SOCKET.into(),
            ca: DEFAULT_PKI_CA.into(),
            use_first_pass: false,
            try_first_pass: false,
        }
    }
}

impl Options {
    /// Parses `args`; the second value is every unknown option's *name* (the
    /// part before `=`), for the caller to log. Unknown options are ignored,
    /// as `pam_unix` does.
    pub fn parse(args: &[&CStr]) -> (Self, Vec<String>) {
        let mut o = Self::default();
        let mut unknown = Vec::new();
        for arg in args {
            let arg = arg.to_string_lossy();
            match arg.split_once('=') {
                Some(("socket", v)) => o.socket = v.into(),
                Some(("ca", v)) => o.ca = v.into(),
                None if arg == "use_first_pass" => o.use_first_pass = true,
                None if arg == "try_first_pass" => o.try_first_pass = true,
                _ => unknown.push(arg.split('=').next().unwrap_or_default().to_string()),
            }
        }
        (o, unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> (Options, Vec<String>) {
        let c: Vec<std::ffi::CString> = args
            .iter()
            .map(|a| std::ffi::CString::new(*a).unwrap())
            .collect();
        let r: Vec<&CStr> = c.iter().map(std::ffi::CString::as_c_str).collect();
        Options::parse(&r)
    }

    #[test]
    fn defaults_come_from_nos_proto() {
        let (o, unknown) = parse(&[]);
        assert_eq!(o, Options::default());
        assert_eq!(o.socket, PathBuf::from(DEFAULT_WATCHDOG_SOCKET));
        assert_eq!(o.ca, PathBuf::from(DEFAULT_PKI_CA));
        assert_eq!(unknown, Vec::<String>::new());
    }

    #[test]
    fn known_options() {
        let (o, unknown) = parse(&[
            "socket=/x/s",
            "ca=/x/ca.crt",
            "use_first_pass",
            "try_first_pass",
        ]);
        assert_eq!(o.socket, PathBuf::from("/x/s"));
        assert_eq!(o.ca, PathBuf::from("/x/ca.crt"));
        assert!(o.use_first_pass && o.try_first_pass);
        assert_eq!(unknown, Vec::<String>::new());
    }

    #[test]
    fn unknown_options_are_named_without_their_value() {
        let (o, unknown) = parse(&["debug", "password=hunter2", "use_first_pass=1"]);
        assert_eq!(unknown, ["debug", "password", "use_first_pass"]);
        assert_eq!(o, Options::default());
    }
}
