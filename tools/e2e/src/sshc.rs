//! A tiny SSH client for the `ssh-login-shell` phase (#992, reused by #1002): keyboard-interactive
//! auth, a pty shell or one exec request, reading a channel until a pattern or its end. The
//! harness has no `ssh` CLI, and a pty is needed to see what `nos` prints. libssh2 (`ssh2`), not
//! `russh`: russh's `russh-util` pulls chrono (RUSTSEC-2026-0543, #1250).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{bail, Context};
use ssh2::{Channel, ErrorCode, KeyboardInteractivePrompt, Prompt, Session};
use tokio::time::{sleep, Instant};

/// libssh2 is blocking; after login the session is switched to non-blocking and every read
/// polls. `LIBSSH2_ERROR_EAGAIN` (-37) is its "nothing yet".
const EAGAIN: i32 = -37;
/// `LIBSSH2_ERROR_AUTHENTICATION_FAILED`.
const AUTH_FAILED: i32 = -18;
const POLL: Duration = Duration::from_millis(20);

struct Answer<'a>(&'a str);

impl KeyboardInteractivePrompt for Answer<'_> {
    fn prompt(&mut self, _: &str, _: &str, prompts: &[Prompt<'_>]) -> Vec<String> {
        prompts.iter().map(|_| self.0.to_string()).collect()
    }
}

pub struct Ssh {
    sess: Session,
}

/// A live channel and what it has said so far.
pub struct Chan {
    ch: Channel,
    pub out: String,
    pub exit: Option<u32>,
    pub closed: bool,
    /// Cursor-position queries (`ESC[6n`) already answered.
    asked: usize,
    mark: usize,
}

fn would_block(e: &ssh2::Error) -> bool {
    e.code() == ErrorCode::Session(EAGAIN)
}

/// Runs `f` until it stops answering "would block" (30s at most).
async fn retry<T>(mut f: impl FnMut() -> Result<T, ssh2::Error>) -> Result<T, ssh2::Error> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match f() {
            Err(e) if would_block(&e) && Instant::now() < deadline => sleep(POLL).await,
            r => return r,
        }
    }
}

impl Ssh {
    /// Connects and tries a password; `Ok(None)` when the server refuses it.
    pub async fn password(
        addr: &str,
        port: u16,
        user: &str,
        password: &str,
    ) -> anyhow::Result<Option<Self>> {
        let (addr, user, password) = (addr.to_string(), user.to_string(), password.to_string());
        // Handshake and auth are blocking calls: keep them off the runtime threads.
        tokio::task::spawn_blocking(move || {
            let sa = (addr.as_str(), port)
                .to_socket_addrs()?
                .next()
                .context("no address")?;
            let tcp =
                TcpStream::connect_timeout(&sa, Duration::from_secs(20)).context("ssh connect")?;
            let mut sess = Session::new()?;
            sess.set_tcp_stream(tcp);
            sess.set_timeout(30_000);
            // ponytail: no host-key pinning; the lab network is private and `ssh-hostkey`
            // already proves the key. Pin the fingerprint if this client ever leaves the lab.
            sess.handshake().context("ssh handshake")?;
            // `nos-sshd` offers keyboard-interactive only (`PasswordAuthentication no`):
            // pam_nos asks for the password as one prompt.
            match sess.userauth_keyboard_interactive(&user, &mut Answer(&password)) {
                Ok(()) if sess.authenticated() => {}
                Ok(()) => return Ok(None),
                Err(e) if e.code() == ErrorCode::Session(AUTH_FAILED) => return Ok(None),
                Err(e) => return Err(anyhow::Error::from(e).context("ssh auth")),
            }
            sess.set_blocking(false);
            Ok(Some(Self { sess }))
        })
        .await?
    }

    /// An interactive shell on a pty (what `ssh host` gives).
    pub async fn shell(&self) -> anyhow::Result<Chan> {
        let mut ch = retry(|| self.sess.channel_session()).await?;
        retry(|| ch.request_pty("xterm", None, Some((200, 50, 0, 0)))).await?;
        retry(|| ch.shell()).await?;
        Ok(Chan::new(ch))
    }

    /// `ssh -L`/`-W`: a `direct-tcpip` channel; `Ok(false)` when the server refuses it.
    pub async fn direct_tcpip(&self, host: &str, port: u16) -> anyhow::Result<bool> {
        Ok(retry(|| self.sess.channel_direct_tcpip(host, port, None))
            .await
            .is_ok())
    }

    /// `ssh host <cmd>`: one exec request, no pty.
    pub async fn exec(&self, cmd: &str) -> anyhow::Result<Chan> {
        let mut ch = retry(|| self.sess.channel_session()).await?;
        retry(|| ch.exec(cmd)).await?;
        Ok(Chan::new(ch))
    }
}

impl Chan {
    fn new(ch: Channel) -> Self {
        Self {
            ch,
            out: String::new(),
            exit: None,
            closed: false,
            asked: 0,
            mark: 0,
        }
    }

    pub async fn send(&mut self, line: &str) -> anyhow::Result<()> {
        self.write_all(format!("{line}\r").as_bytes()).await
    }

    async fn write_all(&mut self, mut b: &[u8]) -> anyhow::Result<()> {
        while !b.is_empty() {
            match self.ch.write(b) {
                Ok(n) => b = &b[n..],
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => sleep(POLL).await,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Drains what the channel has now (stdout and stderr); sets `closed` and `exit` at EOF.
    fn pump(&mut self) {
        let mut buf = [0u8; 4096];
        for stderr in [false, true] {
            loop {
                let r = if stderr {
                    self.ch.stderr().read(&mut buf)
                } else {
                    self.ch.read(&mut buf)
                };
                match r {
                    Ok(n) if n > 0 => self.out.push_str(&String::from_utf8_lossy(&buf[..n])),
                    _ => break,
                }
            }
        }
        if self.ch.eof() && !self.closed {
            // Non-blocking: `wait_close` may answer EAGAIN, so `closed` waits for the status.
            let _ = self.ch.close();
            if self.ch.wait_close().is_ok() {
                self.closed = true;
                self.exit = self
                    .ch
                    .exit_status()
                    .ok()
                    .and_then(|c| u32::try_from(c).ok());
            }
        }
    }

    /// Reads until `out` contains `needle` (from the start of the session, so call sites say what
    /// they expect next by sending first), or fails after `secs` or when the channel ends.
    pub async fn expect(&mut self, needle: &str, secs: u64) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !self.since_mark().contains(needle) {
            if self.closed {
                bail!("channel closed before {needle:?}; output: {:?}", self.out);
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for {needle:?}; output: {:?}", self.out);
            }
            self.pump();
            self.answer_cursor().await?;
            sleep(POLL).await;
        }
        // Sequential: the next `expect` only looks past this match.
        let at = self.since_mark().find(needle).unwrap_or(0);
        self.mark += at + needle.len();
        Ok(())
    }

    /// Reads until the channel ends (or `secs` pass).
    pub async fn finish(&mut self, secs: u64) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !self.closed {
            if Instant::now() >= deadline {
                bail!("channel still open after {secs}s; output: {:?}", self.out);
            }
            self.pump();
            sleep(POLL).await;
        }
        Ok(())
    }

    /// `nos`'s line editor asks the terminal where the cursor is and gives up without an answer.
    async fn answer_cursor(&mut self) -> anyhow::Result<()> {
        let asked = self.out.matches("\x1b[6n").count();
        for _ in self.asked..asked {
            self.write_all(b"\x1b[1;1R").await?;
        }
        self.asked = asked;
        Ok(())
    }

    /// `out` without terminal escape sequences (`ESC [ ... final` and `ESC 7`/`ESC 8`).
    pub fn text(&self) -> String {
        let mut r = String::new();
        let mut it = self.out.chars().peekable();
        while let Some(c) = it.next() {
            if c != '\x1b' {
                r.push(c);
            } else if it.peek() == Some(&'[') {
                it.next();
                for f in it.by_ref() {
                    if f.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                it.next();
            }
        }
        r
    }

    fn since_mark(&self) -> String {
        let t = self.text();
        t.get(self.mark..).unwrap_or_default().to_string()
    }
}
