//! The UDP client: per-server timeout and retries, failover down the list.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::packet::{attr, random16, Code, Packet};

/// RFC 2865 §5.2: a User-Password is at most 128 bytes.
const MAX_PASSWORD: usize = 128;

/// One RADIUS server, tried in list order.
#[derive(Clone, Debug)]
pub struct Server {
    pub addr: SocketAddr,
    pub secret: Vec<u8>,
    /// How long to wait for a reply to each attempt.
    pub timeout: Duration,
    /// Extra attempts after the first, before moving to the next server.
    pub retries: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// A server answered: the credentials are wrong (never a reason to try another backend).
    #[error("access rejected")]
    Rejected,
    /// No server gave a valid answer.
    #[error("no RADIUS server answered")]
    Unreachable,
    #[error("password too long for RADIUS")]
    PasswordTooLong,
}

/// An Access-Accept's attributes.
#[derive(Debug)]
pub struct Accepted(Packet);

impl Accepted {
    pub fn attr(&self, ty: u8) -> Option<&[u8]> {
        self.0.attr(ty)
    }
}

/// Sends `build(secret)` to each server in turn until one gives a reply that
/// `genuine` accepts; `None` when none does. A reply failing the check is
/// ignored (it may be forged or stray) and waiting goes on until the timeout.
async fn exchange(
    servers: &[Server],
    id: u8,
    build: impl Fn(&[u8]) -> (Packet, [u8; 16]),
) -> Option<Packet> {
    for s in servers {
        let Ok(sock) = bind_for(s.addr).await else {
            continue;
        };
        if sock.connect(s.addr).await.is_err() {
            continue;
        }
        // Fresh authenticator per attempt: a retransmission is a new request.
        for _ in 0..=s.retries {
            let (req, ra) = build(&s.secret);
            if sock.send(&req.encode(&s.secret)).await.is_err() {
                break;
            }
            let deadline = Instant::now() + s.timeout;
            let mut buf = [0u8; 4096];
            while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
                let wire = &buf[..n];
                if n >= 4
                    && wire[1] == id
                    && Packet::reply_is_genuine(wire, &s.secret, &ra)
                    && let Ok(p) = Packet::decode(wire)
                {
                    return Some(p);
                }
            }
        }
    }
    None
}

async fn bind_for(peer: SocketAddr) -> std::io::Result<UdpSocket> {
    // ponytail: the default netns only; per-VRF sourcing needs SO_BINDTODEVICE (#1153 follow-up).
    UdpSocket::bind(if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
}

/// RFC 2865 login: Access-Request with `user`/`password`; Access-Accept is
/// `Ok`, Access-Reject (and a Challenge, unsupported) is `Rejected`.
pub async fn authenticate(
    servers: &[Server],
    user: &str,
    password: &str,
    nas_identifier: &str,
) -> Result<Accepted, AuthError> {
    if password.len() > MAX_PASSWORD {
        return Err(AuthError::PasswordTooLong);
    }
    let id = random16()[0];
    let reply = exchange(servers, id, |secret| {
        let p = Packet::access_request(
            id,
            secret,
            vec![
                (attr::USER_NAME, user.as_bytes().to_vec()),
                (attr::USER_PASSWORD, password.as_bytes().to_vec()),
                (attr::NAS_IDENTIFIER, nas_identifier.as_bytes().to_vec()),
            ],
        );
        let ra = p.authenticator;
        (p, ra)
    })
    .await
    .ok_or(AuthError::Unreachable)?;
    match reply.code {
        Code::AccessAccept => Ok(Accepted(reply)),
        _ => Err(AuthError::Rejected),
    }
}

/// RFC 2866: sends an Accounting-Request with `attrs`; `true` once a server
/// acknowledged it.
pub async fn account(servers: &[Server], attrs: Vec<(u8, Vec<u8>)>) -> bool {
    let id = random16()[0];
    exchange(servers, id, |secret| {
        let p = Packet {
            code: Code::AccountingRequest,
            id,
            authenticator: [0; 16],
            attrs: attrs.clone(),
        };
        let ra = p.accounting_authenticator(secret);
        (p, ra)
    })
    .await
    .is_some_and(|p| p.code == Code::AccountingResponse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::make_reply;

    const SECRET: &[u8] = b"s3cret";

    /// A one-user stub: replies per `answer(request)`; `None` stays silent.
    async fn stub(
        secret: &'static [u8],
        answer: impl Fn(&Packet) -> Option<(Code, Vec<(u8, Vec<u8>)>)> + Send + 'static,
    ) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                let Ok(req) = Packet::decode(&buf[..n]) else {
                    continue;
                };
                if let Some((code, attrs)) = answer(&req) {
                    let _ = sock
                        .send_to(&make_reply(code, &req, secret, attrs, true), from)
                        .await;
                }
            }
        });
        addr
    }

    fn server(addr: SocketAddr, secret: &[u8]) -> Server {
        Server {
            addr,
            secret: secret.to_vec(),
            timeout: Duration::from_millis(150),
            retries: 0,
        }
    }

    #[tokio::test]
    async fn accept_carries_attributes_and_reject_is_final() {
        let addr = stub(SECRET, |r| {
            Some(if r.attr(attr::USER_NAME) == Some(b"alice") {
                (
                    Code::AccessAccept,
                    vec![(attr::FILTER_ID, b"admin".to_vec())],
                )
            } else {
                (Code::AccessReject, vec![])
            })
        })
        .await;
        let s = [server(addr, SECRET)];
        let ok = authenticate(&s, "alice", "pw", "nos").await.unwrap();
        assert_eq!(ok.attr(attr::FILTER_ID), Some(&b"admin"[..]));
        assert_eq!(
            authenticate(&s, "bob", "pw", "nos").await.unwrap_err(),
            AuthError::Rejected
        );
    }

    #[tokio::test]
    async fn silent_server_fails_over_and_all_silent_is_unreachable() {
        let dead = stub(SECRET, |_| None).await;
        let live = stub(SECRET, |_| Some((Code::AccessAccept, vec![]))).await;
        let both = [server(dead, SECRET), server(live, SECRET)];
        assert!(authenticate(&both, "a", "p", "nos").await.is_ok());
        assert_eq!(
            authenticate(&both[..1], "a", "p", "nos").await.unwrap_err(),
            AuthError::Unreachable
        );
    }

    #[tokio::test]
    async fn wrong_secret_reply_is_ignored() {
        let addr = stub(b"other", |_| Some((Code::AccessAccept, vec![]))).await;
        let r = authenticate(&[server(addr, SECRET)], "a", "p", "nos").await;
        assert_eq!(r.unwrap_err(), AuthError::Unreachable);
    }

    #[tokio::test]
    async fn long_password_is_refused_locally() {
        let r = authenticate(&[], "a", &"x".repeat(129), "nos").await;
        assert_eq!(r.unwrap_err(), AuthError::PasswordTooLong);
    }

    #[tokio::test]
    async fn accounting_is_acknowledged() {
        let addr = stub(SECRET, |_| Some((Code::AccountingResponse, vec![]))).await;
        let attrs = vec![(attr::ACCT_STATUS_TYPE, vec![0, 0, 0, 1])];
        assert!(account(&[server(addr, SECRET)], attrs.clone()).await);
        let dead = stub(SECRET, |_| None).await;
        assert!(!account(&[server(dead, SECRET)], attrs).await);
    }
}
