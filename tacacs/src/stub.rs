//! A scripted TACACS+ server for tests and the e2e lab (`nos-tacacs-stub`): a
//! fixed user list, role out as the `role` AV pair, acknowledges every
//! accounting request. Not for production.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::packet::{
    acct_reply, authen_reply, author_response, open, parse_authen_start, parse_request, seal,
    Header, ACCT_SUCCESS, AUTHEN_FAIL, AUTHEN_PASS, AUTHOR_FAIL, AUTHOR_PASS_ADD, HEADER, MAX_BODY,
    TYPE_ACCT, TYPE_AUTHEN, TYPE_AUTHOR, VERSION_PAP,
};

/// One account the stub accepts; a non-empty `role` goes out as `role=<role>`.
#[derive(Clone, Debug)]
pub struct StubUser {
    pub name: String,
    pub password: String,
    pub role: String,
}

/// Reads one request, answers it and prints what happened.
async fn serve_one(mut c: TcpStream, key: &[u8], users: &[StubUser]) -> Option<()> {
    let mut head = [0u8; HEADER];
    c.read_exact(&mut head).await.ok()?;
    let h = Header::decode(&head);
    if h.len as usize > MAX_BODY {
        return None;
    }
    let mut body = vec![0u8; h.len as usize];
    c.read_exact(&mut body).await.ok()?;
    open(&h, key, &mut body);
    let (reply, line) = match h.ty {
        TYPE_AUTHEN => {
            let (user, pw) = parse_authen_start(&body).ok()?;
            let ok = users.iter().any(|u| u.name == user && u.password == pw);
            let (status, what) = if ok {
                (AUTHEN_PASS, "pass")
            } else {
                (AUTHEN_FAIL, "fail")
            };
            (
                authen_reply(status, ""),
                format!("authen {what} user={user}"),
            )
        }
        TYPE_AUTHOR => {
            let r = parse_request(&body, false).ok()?;
            match users.iter().find(|u| u.name == r.user) {
                Some(u) => {
                    let args = if u.role.is_empty() {
                        vec![]
                    } else {
                        vec![format!("role={}", u.role)]
                    };
                    (
                        author_response(AUTHOR_PASS_ADD, &args),
                        format!("author pass user={} role={}", r.user, u.role),
                    )
                }
                None => (
                    author_response(AUTHOR_FAIL, &[]),
                    format!("author fail user={}", r.user),
                ),
            }
        }
        TYPE_ACCT => {
            let r = parse_request(&body, true).ok()?;
            (
                acct_reply(ACCT_SUCCESS),
                format!(
                    "accounting flags={} user={} {}",
                    r.flags?.byte(),
                    r.user,
                    r.args.join(" ")
                ),
            )
        }
        _ => return None,
    };
    println!("tacacs-stub: {line}");
    let wire = seal(VERSION_PAP, h.ty, h.seq + 1, h.session, key, reply);
    c.write_all(&wire).await.ok()
}

/// Serves `listener` forever, one session per connection.
pub async fn serve_listener(listener: TcpListener, key: &'static [u8], users: Vec<StubUser>) {
    let users: &'static [StubUser] = Box::leak(users.into_boxed_slice());
    while let Ok((c, _)) = listener.accept().await {
        tokio::spawn(serve_one(c, key, users));
    }
}

/// Binds `addr` and serves forever (the stub binary).
pub async fn serve_stub(addr: SocketAddr, key: &str, users: Vec<StubUser>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let key: &'static [u8] = Box::leak(key.as_bytes().to_vec().into_boxed_slice());
    serve_listener(listener, key, users).await;
    Ok(())
}
