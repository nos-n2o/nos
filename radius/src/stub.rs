//! A scripted RADIUS server for tests and the e2e lab (`nos-radius-stub`): a
//! fixed user list, answers every Accounting-Request. Not for production.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::packet::{attr, make_reply, unhide_password, Code, Packet};

/// One account the stub accepts; `role` goes out as Filter-Id.
#[derive(Clone, Debug)]
pub struct StubUser {
    pub name: String,
    pub password: String,
    pub role: String,
}

/// The reply to one request datagram, plus a line describing what happened.
fn answer(secret: &[u8], users: &[StubUser], wire: &[u8]) -> Option<(Vec<u8>, String)> {
    let req = Packet::decode(wire).ok()?;
    match req.code {
        Code::AccessRequest => {
            let name = String::from_utf8_lossy(req.attr(attr::USER_NAME)?).into_owned();
            let pw = unhide_password(req.attr(attr::USER_PASSWORD)?, secret, &req.authenticator);
            let hit = users
                .iter()
                .find(|u| u.name == name && u.password.as_bytes() == pw);
            let (code, attrs, what) = match hit {
                Some(u) => (
                    Code::AccessAccept,
                    vec![(attr::FILTER_ID, u.role.as_bytes().to_vec())],
                    "accept",
                ),
                None => (Code::AccessReject, vec![], "reject"),
            };
            Some((
                make_reply(code, &req, secret, attrs, true),
                format!("{what} user={name}"),
            ))
        }
        Code::AccountingRequest => {
            let text = |ty| {
                req.attr(ty)
                    .map_or_else(String::new, |v| String::from_utf8_lossy(v).into_owned())
            };
            let status = req
                .attr(attr::ACCT_STATUS_TYPE)
                .and_then(|v| <[u8; 4]>::try_from(v).ok())
                .map_or(0, u32::from_be_bytes);
            Some((
                make_reply(Code::AccountingResponse, &req, secret, vec![], false),
                format!(
                    "accounting status={status} user={} session={}",
                    text(attr::USER_NAME),
                    text(attr::ACCT_SESSION_ID)
                ),
            ))
        }
        _ => None,
    }
}

/// Serves `addr` forever, printing one line per request to stdout.
pub async fn serve_stub(
    addr: SocketAddr,
    secret: &[u8],
    users: &[StubUser],
) -> std::io::Result<()> {
    let sock = UdpSocket::bind(addr).await?;
    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        if let Some((reply, line)) = answer(secret, users, &buf[..n]) {
            println!("radius-stub: {line}");
            let _ = sock.send_to(&reply, from).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{account, authenticate, AuthError, Server};
    use std::time::Duration;

    #[tokio::test]
    async fn stub_serves_the_client_end_to_end() {
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let users = vec![StubUser {
            name: "alice".into(),
            password: "pw".into(),
            role: "admin".into(),
        }];
        tokio::spawn(async move { serve_stub(addr, b"k", &users).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let s = [Server {
            addr,
            secret: b"k".to_vec(),
            timeout: Duration::from_millis(500),
            retries: 1,
        }];
        let ok = authenticate(&s, "alice", "pw", "t").await.unwrap();
        assert_eq!(ok.attr(attr::FILTER_ID), Some(&b"admin"[..]));
        assert_eq!(
            authenticate(&s, "alice", "bad", "t").await.unwrap_err(),
            AuthError::Rejected
        );
        assert!(account(&s, vec![(attr::ACCT_STATUS_TYPE, vec![0, 0, 0, 1])]).await);
    }
}
