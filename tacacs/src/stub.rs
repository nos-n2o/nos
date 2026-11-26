//! A scripted TACACS+ server for tests and the e2e lab (`nos-tacacs-stub`): a
//! fixed user list, role out as the `role` AV pair, acknowledges every
//! accounting request. PAP and ASCII (GETUSER when the START has no user,
//! then GETPASS) authentication, single-connect when the client asks. Not for
//! production.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::packet::{
    acct_reply, authen_prompt, author_response, open, parse_authen_continue, parse_authen_start,
    parse_request, seal, Header, ACCT_SUCCESS, AUTHEN_FAIL, AUTHEN_GETPASS, AUTHEN_GETUSER,
    AUTHEN_PASS, AUTHOR_FAIL, AUTHOR_PASS_ADD, FLAG_SINGLE_CONNECT, HEADER, MAX_BODY, TYPE_ACCT,
    TYPE_AUTHEN, TYPE_AUTHOR,
};

/// One account the stub accepts; a non-empty `role` goes out as `role=<role>`.
#[derive(Clone, Debug)]
pub struct StubUser {
    pub name: String,
    pub password: String,
    pub role: String,
}

/// An ASCII login in progress: the session it belongs to and the name so far.
struct Ascii {
    session: u32,
    user: Option<String>,
}

fn verdict(users: &[StubUser], user: &str, pw: &str, kind: &str) -> (Vec<u8>, String, bool) {
    let ok = users.iter().any(|u| u.name == user && u.password == pw);
    let (status, what) = if ok {
        (AUTHEN_PASS, "pass")
    } else {
        (AUTHEN_FAIL, "fail")
    };
    (
        authen_prompt(status, false, ""),
        format!("authen {what} user={user} type={kind}"),
        true,
    )
}

/// Serves sessions on one connection: one, or until the client closes it
/// when it asked for single-connect. Prints what happened.
pub(crate) async fn serve_conn(mut c: TcpStream, key: &[u8], users: &[StubUser]) {
    println!("tacacs-stub: connection opened");
    let mut single = None;
    let mut ascii: Option<Ascii> = None;
    loop {
        let mut head = [0u8; HEADER];
        if c.read_exact(&mut head).await.is_err() {
            return;
        }
        let h = Header::decode(&head);
        if h.len as usize > MAX_BODY {
            return;
        }
        let mut body = vec![0u8; h.len as usize];
        if c.read_exact(&mut body).await.is_err() {
            return;
        }
        open(&h, key, &mut body);
        // The first packet decides, as the RFC says.
        let single = *single.get_or_insert(h.flags & FLAG_SINGLE_CONNECT != 0);
        let Some((reply, line, done)) = answer(&h, &body, users, &mut ascii) else {
            return;
        };
        println!("tacacs-stub: {line}");
        let r = Header {
            seq: h.seq + 1,
            flags: if single { FLAG_SINGLE_CONNECT } else { 0 },
            ..h
        };
        if c.write_all(&seal(&r, key, reply)).await.is_err() || (done && !single) {
            return;
        }
    }
}

/// `(reply body, log line, session over)`.
fn answer(
    h: &Header,
    body: &[u8],
    users: &[StubUser],
    ascii: &mut Option<Ascii>,
) -> Option<(Vec<u8>, String, bool)> {
    Some(match h.ty {
        TYPE_AUTHEN if h.seq == 1 => {
            let s = parse_authen_start(body).ok()?;
            if !s.ascii {
                verdict(users, &s.user, &s.data, "pap")
            } else if s.user.is_empty() {
                *ascii = Some(Ascii {
                    session: h.session,
                    user: None,
                });
                (
                    authen_prompt(AUTHEN_GETUSER, false, "Username: "),
                    "authen getuser".into(),
                    false,
                )
            } else {
                *ascii = Some(Ascii {
                    session: h.session,
                    user: Some(s.user),
                });
                (
                    authen_prompt(AUTHEN_GETPASS, true, "Password: "),
                    "authen getpass".into(),
                    false,
                )
            }
        }
        TYPE_AUTHEN => {
            let (msg, abort) = parse_authen_continue(body).ok()?;
            let st = ascii.take().filter(|a| a.session == h.session)?;
            if abort {
                return Some((
                    authen_prompt(AUTHEN_FAIL, false, ""),
                    "authen abort".into(),
                    true,
                ));
            }
            match st.user {
                None => {
                    *ascii = Some(Ascii {
                        session: h.session,
                        user: Some(msg),
                    });
                    (
                        authen_prompt(AUTHEN_GETPASS, true, "Password: "),
                        "authen getpass".into(),
                        false,
                    )
                }
                Some(user) => verdict(users, &user, &msg, "ascii"),
            }
        }
        TYPE_AUTHOR => {
            let r = parse_request(body, false).ok()?;
            let (reply, line) = match users.iter().find(|u| u.name == r.user) {
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
            };
            (reply, line, true)
        }
        TYPE_ACCT => {
            let r = parse_request(body, true).ok()?;
            (
                acct_reply(ACCT_SUCCESS),
                format!(
                    "accounting flags={} user={} {}",
                    r.flags?.byte(),
                    r.user,
                    r.args.join(" ")
                ),
                true,
            )
        }
        _ => return None,
    })
}

/// Serves `listener` forever, one task per connection.
pub async fn serve_listener(listener: TcpListener, key: &'static [u8], users: Vec<StubUser>) {
    let users: &'static [StubUser] = Box::leak(users.into_boxed_slice());
    while let Ok((c, _)) = listener.accept().await {
        tokio::spawn(serve_conn(c, key, users));
    }
}

/// Binds `addr` and serves forever (the stub binary).
pub async fn serve_stub(addr: SocketAddr, key: &str, users: Vec<StubUser>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let key: &'static [u8] = Box::leak(key.as_bytes().to_vec().into_boxed_slice());
    serve_listener(listener, key, users).await;
    Ok(())
}
