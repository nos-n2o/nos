//! The TCP client: one connection per exchange (no single-connect), failover
//! down the server list.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use crate::packet::{
    self, acct_request, authen_start, author_request, open, parse_acct_reply, parse_authen_reply,
    parse_author_response, seal, session_id, AcctFlags, Header, ACCT_SUCCESS, AUTHEN_FAIL,
    AUTHEN_PASS, AUTHOR_PASS_ADD, AUTHOR_PASS_REPL, HEADER, MAX_BODY, TYPE_ACCT, TYPE_AUTHEN,
    TYPE_AUTHOR, VERSION_PAP,
};

/// One TACACS+ server, tried in list order.
#[derive(Clone, Debug)]
pub struct Server {
    pub addr: SocketAddr,
    pub key: Vec<u8>,
    /// Connect plus one request/reply.
    pub timeout: Duration,
    /// Linux VRF device to connect through (`SO_BINDTODEVICE`); `None` is the default netns.
    pub vrf: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// A server answered: the credentials, or the user's authorization, are
    /// refused (never a reason to try another backend).
    #[error("login refused")]
    Rejected,
    /// No server gave a valid answer.
    #[error("no TACACS+ server answered")]
    Unreachable,
    /// A user name or password over the wire's 255-byte field limit.
    #[error("user or password too long for TACACS+")]
    TooLong,
}

async fn connect(s: &Server) -> std::io::Result<TcpStream> {
    let sock = if s.addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(v) = &s.vrf {
        sock.bind_device(Some(v.as_bytes()))?;
    }
    sock.connect(s.addr).await
}

/// Sends one request and returns the decrypted reply body, `None` for any
/// failure: no connection, a timeout, or a reply that is not a genuine answer
/// to this session (wrong type, sequence or session id, over-long).
async fn exchange(s: &Server, ty: u8, body: Vec<u8>) -> Option<Vec<u8>> {
    let call = async {
        let mut c = connect(s).await.ok()?;
        let session = session_id();
        c.write_all(&seal(VERSION_PAP, ty, 1, session, &s.key, body))
            .await
            .ok()?;
        let mut head = [0u8; HEADER];
        c.read_exact(&mut head).await.ok()?;
        let h = Header::decode(&head);
        if h.ty != ty || h.seq != 2 || h.session != session || h.len as usize > MAX_BODY {
            return None;
        }
        let mut reply = vec![0u8; h.len as usize];
        c.read_exact(&mut reply).await.ok()?;
        open(&h, &s.key, &mut reply);
        Some(reply)
    };
    timeout(s.timeout, call).await.ok().flatten()
}

fn too_long(parts: &[&str]) -> bool {
    parts.iter().any(|p| p.len() > 255)
}

/// PAP login then authorization of `service=nos` on the same server. `Ok` is
/// the authorization's AV pairs (the role is `role=<name>`); a FAIL from
/// either step is final, a server that errs or stays silent hands over to the
/// next one.
pub async fn login(
    servers: &[Server],
    user: &str,
    password: &str,
    rem_addr: &str,
) -> Result<Vec<String>, AuthError> {
    if too_long(&[user, password, rem_addr]) {
        return Err(AuthError::TooLong);
    }
    for s in servers {
        let Some(r) = exchange(s, TYPE_AUTHEN, authen_start(user, rem_addr, password)).await else {
            continue;
        };
        match parse_authen_reply(&r) {
            Ok(AUTHEN_PASS) => {}
            Ok(AUTHEN_FAIL) => return Err(AuthError::Rejected),
            _ => continue,
        }
        let args = ["service=nos".to_string(), "protocol=login".to_string()];
        let Some(r) = exchange(s, TYPE_AUTHOR, author_request(user, rem_addr, &args)).await else {
            continue;
        };
        match parse_author_response(&r) {
            Ok((AUTHOR_PASS_ADD | AUTHOR_PASS_REPL, args)) => return Ok(args),
            Ok((packet::AUTHOR_FAIL, _)) => return Err(AuthError::Rejected),
            _ => {}
        }
    }
    Err(AuthError::Unreachable)
}

/// The value of AV pair `name` (`name=value` or the optional `name*value`).
pub fn av<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().find_map(|a| {
        let rest = a.strip_prefix(name)?;
        rest.strip_prefix('=').or_else(|| rest.strip_prefix('*'))
    })
}

/// RFC 8907 §7: one accounting record; `true` once a server acknowledged it.
pub async fn account(servers: &[Server], flags: AcctFlags, user: &str, args: &[String]) -> bool {
    if too_long(&[user]) || args.iter().any(|a| a.len() > 255) {
        return false;
    }
    for s in servers {
        let body = acct_request(flags, user, "nos", args);
        if let Some(r) = exchange(s, TYPE_ACCT, body).await
            && parse_acct_reply(&r) == Ok(ACCT_SUCCESS)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stub::{serve_listener, StubUser};
    use tokio::net::TcpListener;

    const KEY: &[u8] = b"k3y";

    async fn stub(key: &'static [u8]) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let users = vec![
            StubUser {
                name: "alice".into(),
                password: "pw".into(),
                role: "admin".into(),
            },
            StubUser {
                name: "norole".into(),
                password: "pw".into(),
                role: String::new(),
            },
        ];
        tokio::spawn(serve_listener(l, key, users));
        addr
    }

    fn server(addr: SocketAddr, key: &[u8]) -> Server {
        Server {
            addr,
            key: key.to_vec(),
            timeout: Duration::from_millis(300),
            vrf: None,
        }
    }

    #[tokio::test]
    async fn login_carries_the_role_and_a_fail_is_final() {
        let s = [server(stub(KEY).await, KEY)];
        let args = login(&s, "alice", "pw", "1.2.3.4").await.unwrap();
        assert_eq!(av(&args, "role"), Some("admin"));
        let args = login(&s, "norole", "pw", "x").await.unwrap();
        assert_eq!(av(&args, "role"), None);
        assert_eq!(
            login(&s, "alice", "bad", "x").await.unwrap_err(),
            AuthError::Rejected
        );
        assert_eq!(
            login(&s, "bob", "pw", "x").await.unwrap_err(),
            AuthError::Rejected
        );
    }

    #[tokio::test]
    async fn dead_server_fails_over_and_all_dead_is_unreachable() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let live = stub(KEY).await;
        let both = [server(dead_addr, KEY), server(live, KEY)];
        assert!(login(&both, "alice", "pw", "x").await.is_ok());
        assert_eq!(
            login(&both[..1], "alice", "pw", "x").await.unwrap_err(),
            AuthError::Unreachable
        );
    }

    #[tokio::test]
    async fn wrong_key_is_unreachable_not_a_reject() {
        let addr = stub(b"other").await;
        let r = login(&[server(addr, KEY)], "alice", "pw", "x").await;
        assert_eq!(r.unwrap_err(), AuthError::Unreachable);
    }

    #[tokio::test]
    async fn long_fields_are_refused_locally() {
        let r = login(&[], "a", &"x".repeat(256), "x").await;
        assert_eq!(r.unwrap_err(), AuthError::TooLong);
    }

    #[tokio::test]
    async fn accounting_is_acknowledged() {
        let s = [server(stub(KEY).await, KEY)];
        let args = vec!["task_id=1".to_string()];
        assert!(account(&s, AcctFlags::Start, "alice", &args).await);
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = dead.local_addr().unwrap();
        drop(dead);
        assert!(!account(&[server(a, KEY)], AcctFlags::Stop, "alice", &args).await);
    }
}
