//! The TCP client: failover down the server list. One connection per session,
//! or, with `Server.pool` set, a single-connect connection (RFC 8907 §4.5)
//! kept between sessions.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use crate::packet::{
    self, acct_request, authen_continue, authen_start, authen_start_ascii, author_request, open,
    parse_acct_reply, parse_authen_reply, parse_author_response, seal, session_id, AcctFlags,
    Header, ACCT_SUCCESS, AUTHEN_FAIL, AUTHEN_GETDATA, AUTHEN_GETPASS, AUTHEN_GETUSER, AUTHEN_PASS,
    AUTHOR_PASS_ADD, AUTHOR_PASS_REPL, FLAG_SINGLE_CONNECT, HEADER, MAX_BODY, TYPE_ACCT,
    TYPE_AUTHEN, TYPE_AUTHOR, VERSION_ASCII, VERSION_PAP,
};

/// A pooled connection unused for this long is dropped, not reused.
const IDLE: Duration = Duration::from_secs(60);
/// CONTINUE packets an ASCII login may exchange before it is aborted.
const MAX_ROUNDS: usize = 6;

struct Conn {
    stream: TcpStream,
    /// The server echoed the single-connect flag: the connection outlives a session.
    single: bool,
    used: Instant,
}

type Slot = (SocketAddr, Option<String>);

/// Single-connect connections, one per server, shared by clones. Idle ones are
/// dropped when next asked for (ponytail: no reaper task, a dead server's socket
/// lingers until then).
#[derive(Clone, Default)]
pub struct Pool(Arc<Mutex<HashMap<Slot, Conn>>>);

impl Pool {
    fn take(&self, s: &Server) -> Option<Conn> {
        let c = self.0.lock().ok()?.remove(&(s.addr, s.vrf.clone()))?;
        (c.used.elapsed() < IDLE).then_some(c)
    }
    fn put(&self, s: &Server, mut c: Conn) {
        c.used = Instant::now();
        if let Ok(mut m) = self.0.lock() {
            m.insert((s.addr, s.vrf.clone()), c);
        }
    }
}

/// One TACACS+ server, tried in list order.
#[derive(Clone)]
pub struct Server {
    pub addr: SocketAddr,
    pub key: Vec<u8>,
    /// Connect plus one request/reply.
    pub timeout: Duration,
    /// Linux VRF device to connect through (`SO_BINDTODEVICE`); `None` is the default netns.
    pub vrf: Option<String>,
    /// ASCII authentication (prompts and CONTINUEs) instead of PAP.
    pub ascii: bool,
    /// Ask for single-connect and keep the connection here between sessions.
    pub pool: Option<Pool>,
}

// The key is a secret: never printed.
impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("addr", &self.addr)
            .field("key", &"<hidden>")
            .field("vrf", &self.vrf)
            .field("ascii", &self.ascii)
            .field("single_connect", &self.pool.is_some())
            .finish_non_exhaustive()
    }
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

async fn connect(s: &Server) -> Option<Conn> {
    let call = async {
        let sock = if s.addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Some(v) = &s.vrf {
            sock.bind_device(Some(v.as_bytes()))?;
        }
        sock.connect(s.addr).await
    };
    let stream = timeout(s.timeout, call).await.ok()?.ok()?;
    Some(Conn {
        stream,
        single: false,
        used: Instant::now(),
    })
}

/// One TACACS+ session: packets numbered 1, 3, 5, ... from us, answered by 2, 4, 6, ...
struct Session<'a> {
    s: &'a Server,
    conn: Conn,
    /// `conn` came out of the pool: it may be stale.
    reused: bool,
    ty: u8,
    version: u8,
    id: u32,
    seq: u8,
}

impl<'a> Session<'a> {
    async fn begin(s: &'a Server, ty: u8, version: u8) -> Option<Session<'a>> {
        let pooled = s.pool.as_ref().and_then(|p| p.take(s));
        let reused = pooled.is_some();
        let conn = match pooled {
            Some(c) => c,
            None => connect(s).await?,
        };
        Some(Session {
            s,
            conn,
            reused,
            ty,
            version,
            id: session_id(),
            seq: 1,
        })
    }

    /// Sends `body`, returns the decrypted reply body, `None` for any failure:
    /// a timeout, or a reply that is not a genuine answer to this session
    /// (wrong type, sequence or session id, over-long). A pooled connection
    /// that fails on the first packet is stale (the server closed it): one
    /// retry on a fresh connection.
    async fn step(&mut self, body: Vec<u8>) -> Option<Vec<u8>> {
        let r = self.try_step(&body).await;
        if r.is_none() && self.reused && self.seq == 1 {
            self.conn = connect(self.s).await?;
            self.reused = false;
            self.id = session_id();
            return self.try_step(&body).await;
        }
        r
    }

    async fn try_step(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let (s, seq) = (self.s, self.seq);
        let h = Header {
            version: self.version,
            ty: self.ty,
            seq,
            flags: if s.pool.is_some() {
                FLAG_SINGLE_CONNECT
            } else {
                0
            },
            session: self.id,
            len: 0,
        };
        let conn = &mut self.conn;
        let call = async {
            conn.stream
                .write_all(&seal(&h, &s.key, body.to_vec()))
                .await
                .ok()?;
            let mut head = [0u8; HEADER];
            conn.stream.read_exact(&mut head).await.ok()?;
            let r = Header::decode(&head);
            if r.ty != h.ty || r.seq != seq.wrapping_add(1) || r.session != h.session {
                return None;
            }
            if r.len as usize > MAX_BODY {
                return None;
            }
            let mut reply = vec![0u8; r.len as usize];
            conn.stream.read_exact(&mut reply).await.ok()?;
            open(&r, &s.key, &mut reply);
            if seq == 1 {
                conn.single = s.pool.is_some() && r.flags & FLAG_SINGLE_CONNECT != 0;
            }
            Some(reply)
        };
        let reply = timeout(s.timeout, call).await.ok().flatten()?;
        self.seq = seq.wrapping_add(2);
        Some(reply)
    }

    /// The session is over: a single-connect connection goes back to the pool.
    fn finish(self) {
        if self.conn.single
            && let Some(p) = &self.s.pool
        {
            p.put(self.s, self.conn);
        }
    }
}

fn too_long(parts: &[&str]) -> bool {
    parts.iter().any(|p| p.len() > 255)
}

/// PAP or ASCII authentication on `s`: `Some(true)` PASS, `Some(false)` FAIL,
/// `None` the server failed (silent, ERROR, a prompt PAP cannot answer, too
/// many rounds).
async fn authenticate(s: &Server, user: &str, password: &str, rem_addr: &str) -> Option<bool> {
    let (version, start) = if s.ascii {
        (VERSION_ASCII, authen_start_ascii(user, rem_addr))
    } else {
        (VERSION_PAP, authen_start(user, rem_addr, password))
    };
    let mut sess = Session::begin(s, TYPE_AUTHEN, version).await?;
    let mut reply = sess.step(start).await?;
    for _ in 0..=MAX_ROUNDS {
        let answer = match parse_authen_reply(&reply).ok()? {
            AUTHEN_PASS => {
                sess.finish();
                return Some(true);
            }
            AUTHEN_FAIL => {
                sess.finish();
                return Some(false);
            }
            AUTHEN_GETUSER if s.ascii => user,
            AUTHEN_GETPASS | AUTHEN_GETDATA if s.ascii => password,
            _ => return None,
        };
        reply = sess.step(authen_continue(answer, false)).await?;
    }
    // RFC 8907 §5.3: tell the server we give up.
    let _ = sess.step(authen_continue("", true)).await;
    None
}

/// Authentication (PAP, or ASCII with its prompts answered) then authorization
/// of `service=nos` on the same server. `Ok` is the authorization's AV pairs
/// (the role is `role=<name>`); a FAIL from either step is final, a server
/// that errs or stays silent hands over to the next one.
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
        match authenticate(s, user, password, rem_addr).await {
            Some(true) => {}
            Some(false) => return Err(AuthError::Rejected),
            None => continue,
        }
        let args = ["service=nos".to_string(), "protocol=login".to_string()];
        let Some(mut sess) = Session::begin(s, TYPE_AUTHOR, VERSION_PAP).await else {
            continue;
        };
        let Some(r) = sess
            .step(author_request(user, rem_addr, &args, s.ascii))
            .await
        else {
            continue;
        };
        sess.finish();
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
        let Some(mut sess) = Session::begin(s, TYPE_ACCT, VERSION_PAP).await else {
            continue;
        };
        if let Some(r) = sess.step(acct_request(flags, user, "nos", args)).await {
            sess.finish();
            if parse_acct_reply(&r) == Ok(ACCT_SUCCESS) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        authen_prompt, authen_reply, parse_authen_continue, AUTHEN_GETDATA as GETDATA,
    };
    use crate::stub::{serve_conn, serve_listener, StubUser};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    const KEY: &[u8] = b"k3y";

    fn users() -> Vec<StubUser> {
        vec![
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
        ]
    }

    async fn stub(key: &'static [u8]) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve_listener(l, key, users()));
        addr
    }

    fn server(addr: SocketAddr, key: &[u8]) -> Server {
        Server {
            addr,
            key: key.to_vec(),
            timeout: Duration::from_millis(300),
            vrf: None,
            ascii: false,
            pool: None,
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

    #[tokio::test]
    async fn ascii_login_answers_the_prompts() {
        let mut s = server(stub(KEY).await, KEY);
        s.ascii = true;
        let s = [s];
        let args = login(&s, "alice", "pw", "1.2.3.4").await.unwrap();
        assert_eq!(av(&args, "role"), Some("admin"));
        assert_eq!(
            login(&s, "alice", "bad", "x").await.unwrap_err(),
            AuthError::Rejected
        );
        assert_eq!(
            login(&s, "bob", "pw", "x").await.unwrap_err(),
            AuthError::Rejected
        );
        // No user in the START: the stub asks for it (GETUSER) first.
        let args = login(&s, "", "pw", "x").await;
        assert_eq!(args.unwrap_err(), AuthError::Rejected);
    }

    /// Answers each packet it reads with the next scripted reply body; returns
    /// the CONTINUE messages it saw.
    async fn scripted(
        replies: Vec<Vec<u8>>,
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<(String, bool)>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut seen = Vec::new();
            for reply in replies {
                let mut head = [0u8; HEADER];
                if c.read_exact(&mut head).await.is_err() {
                    break;
                }
                let h = Header::decode(&head);
                let mut body = vec![0u8; h.len as usize];
                c.read_exact(&mut body).await.unwrap();
                open(&h, KEY, &mut body);
                if h.seq > 1 {
                    seen.push(parse_authen_continue(&body).unwrap());
                }
                let r = Header {
                    seq: h.seq + 1,
                    flags: 0,
                    len: 0,
                    ..h
                };
                c.write_all(&seal(&r, KEY, reply)).await.unwrap();
            }
            seen
        });
        (addr, task)
    }

    #[tokio::test]
    async fn ascii_prompts_getuser_getpass_getdata_are_answered_in_order() {
        let (addr, task) = scripted(vec![
            authen_prompt(AUTHEN_GETUSER, false, "User: "),
            authen_prompt(AUTHEN_GETPASS, true, "Password: "),
            authen_prompt(GETDATA, false, "more: "),
            authen_reply(AUTHEN_FAIL, ""),
        ])
        .await;
        let mut s = server(addr, KEY);
        s.ascii = true;
        assert_eq!(
            login(&[s], "u", "p", "x").await.unwrap_err(),
            AuthError::Rejected
        );
        let seen = task.await.unwrap();
        let msgs: Vec<_> = seen.iter().map(|(m, a)| (m.as_str(), *a)).collect();
        assert_eq!(msgs, [("u", false), ("p", false), ("p", false)]);
    }

    #[tokio::test]
    async fn ascii_that_never_ends_is_aborted_and_error_fails_the_server() {
        let prompts = vec![authen_prompt(AUTHEN_GETPASS, true, "Password: "); 20];
        let (addr, task) = scripted(prompts).await;
        let mut s = server(addr, KEY);
        s.ascii = true;
        assert_eq!(
            login(&[s], "u", "p", "x").await.unwrap_err(),
            AuthError::Unreachable
        );
        let seen = task.await.unwrap();
        assert_eq!(seen.len(), MAX_ROUNDS + 2, "the rounds, then the abort");
        assert_eq!(
            seen.last(),
            Some(&(String::new(), true)),
            "ends with an abort"
        );

        let (addr, _t) = scripted(vec![authen_reply(7, "")]).await;
        let mut s = server(addr, KEY);
        s.ascii = true;
        assert_eq!(
            login(&[s], "u", "p", "x").await.unwrap_err(),
            AuthError::Unreachable
        );
    }

    #[tokio::test]
    async fn pap_refuses_a_prompt() {
        let (addr, _t) = scripted(vec![authen_prompt(AUTHEN_GETPASS, true, "")]).await;
        let r = login(&[server(addr, KEY)], "u", "p", "x").await;
        assert_eq!(r.unwrap_err(), AuthError::Unreachable);
    }

    /// A stub that counts the connections it accepts; `kill_first` drops the
    /// first one once it has served a session (a server closing an idle link).
    async fn counting_stub(
        kill_first: bool,
    ) -> (
        SocketAddr,
        Arc<AtomicUsize>,
        Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    ) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let handles = Arc::new(Mutex::new(Vec::new()));
        let (n2, h2) = (n.clone(), handles.clone());
        let _ = kill_first;
        tokio::spawn(async move {
            while let Ok((c, _)) = l.accept().await {
                n2.fetch_add(1, Ordering::SeqCst);
                let key: &'static [u8] = KEY;
                let users: &'static [StubUser] = Box::leak(users().into_boxed_slice());
                h2.lock().unwrap().push(tokio::spawn(async move {
                    serve_conn(c, key, users).await;
                }));
            }
        });
        (addr, n, handles)
    }

    #[tokio::test]
    async fn single_connect_reuses_one_connection_for_everything() {
        let (addr, n, _h) = counting_stub(false).await;
        for ascii in [false, true] {
            n.store(0, Ordering::SeqCst);
            let mut s = server(addr, KEY);
            s.ascii = ascii;
            s.pool = Some(Pool::default());
            let s = [s];
            login(&s, "alice", "pw", "x").await.unwrap();
            login(&s, "norole", "pw", "x").await.unwrap();
            assert_eq!(
                login(&s, "alice", "bad", "x").await.unwrap_err(),
                AuthError::Rejected
            );
            assert!(account(&s, AcctFlags::Stop, "alice", &["a=b".to_string()]).await);
            assert_eq!(
                n.load(Ordering::SeqCst),
                1,
                "ascii={ascii}: one TCP connection"
            );
        }
        // Without a pool every session opens its own.
        n.store(0, Ordering::SeqCst);
        let s = [server(addr, KEY)];
        login(&s, "alice", "pw", "x").await.unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 2, "authen and author");
    }

    #[tokio::test]
    async fn a_pooled_connection_the_server_closed_is_replaced() {
        let (addr, n, handles) = counting_stub(true).await;
        let mut s = server(addr, KEY);
        s.pool = Some(Pool::default());
        let s = [s];
        login(&s, "alice", "pw", "x").await.unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 1);
        for h in handles.lock().unwrap().drain(..) {
            h.abort();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        login(&s, "alice", "pw", "x").await.unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 2, "reconnected after the close");
    }

    #[tokio::test]
    async fn a_server_that_does_not_agree_gets_one_connection_per_session() {
        // The scripted server never echoes the flag.
        let (addr, task) = scripted(vec![authen_reply(AUTHEN_PASS, "")]).await;
        let mut s = server(addr, KEY);
        s.pool = Some(Pool::default());
        let pool = s.pool.clone().unwrap();
        let mut sess = Session::begin(&s, TYPE_AUTHEN, VERSION_PAP).await.unwrap();
        sess.step(authen_start("u", "x", "p")).await.unwrap();
        assert!(!sess.conn.single);
        sess.finish();
        assert!(pool.take(&s).is_none());
        task.await.unwrap();
    }

    #[test]
    fn debug_never_prints_the_key() {
        let s = server("127.0.0.1:49".parse().unwrap(), b"hunter2-secret");
        let d = format!("{s:?}");
        assert!(!d.contains("hunter2") && d.contains("hidden"));
    }
}
