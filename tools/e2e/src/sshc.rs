//! A tiny SSH client for the `ssh-login-shell` phase (#992, reused by #1002): password auth,
//! a pty shell or one exec request, reading a channel until a pattern or its end. The harness
//! has no `ssh` CLI, and a pty is needed to see what `nos` prints.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use russh::client::{self, Handle, Handler, KeyboardInteractiveAuthResponse};
use russh::keys::PublicKeyOrCertificate;
use russh::{Channel, ChannelMsg};

struct Any;

impl Handler for Any {
    type Error = russh::Error;

    // ponytail: no host-key pinning; the lab network is private and `ssh-hostkey` already
    // proves the key. Pin the fingerprint if this client ever leaves the lab.
    #[allow(clippy::unused_async_trait_impl, reason = "the trait method is async")]
    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub struct Ssh {
    handle: Handle<Any>,
}

/// A live channel and what it has said so far.
pub struct Chan {
    ch: Channel<client::Msg>,
    pub out: String,
    pub exit: Option<u32>,
    pub closed: bool,
    /// Cursor-position queries (`ESC[6n`) already answered.
    asked: usize,
    mark: usize,
}

impl Ssh {
    /// Connects and tries a password; `Ok(None)` when the server refuses it.
    pub async fn password(
        addr: &str,
        port: u16,
        user: &str,
        password: &str,
    ) -> anyhow::Result<Option<Self>> {
        let cfg = Arc::new(client::Config::default());
        let mut handle = tokio::time::timeout(
            Duration::from_secs(20),
            client::connect(cfg, (addr, port), Any),
        )
        .await
        .context("ssh connect timed out")??;
        // `nos-sshd` offers keyboard-interactive only (`PasswordAuthentication no`): pam_nos
        // asks for the password as one prompt.
        let auth = async {
            let mut r = handle
                .authenticate_keyboard_interactive_start(user, None)
                .await?;
            for _ in 0..5 {
                match r {
                    KeyboardInteractiveAuthResponse::Success => return Ok(true),
                    KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
                    KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                        let answers = prompts.iter().map(|_| password.to_string()).collect();
                        r = handle
                            .authenticate_keyboard_interactive_respond(answers)
                            .await?;
                    }
                }
            }
            Ok::<_, russh::Error>(false)
        };
        let ok = tokio::time::timeout(Duration::from_secs(30), auth)
            .await
            .context("ssh auth timed out")??;
        Ok(ok.then_some(Self { handle }))
    }

    /// An interactive shell on a pty (what `ssh host` gives).
    pub async fn shell(&self) -> anyhow::Result<Chan> {
        let ch = self.handle.channel_open_session().await?;
        ch.request_pty(true, "xterm", 200, 50, 0, 0, &[]).await?;
        ch.request_shell(true).await?;
        Ok(Chan::new(ch))
    }

    /// `ssh -L`/`-W`: a `direct-tcpip` channel; `Ok(false)` when the server refuses it.
    pub async fn direct_tcpip(&self, host: &str, port: u32) -> anyhow::Result<bool> {
        Ok(self
            .handle
            .channel_open_direct_tcpip(host, port, "127.0.0.1", 0)
            .await
            .is_ok())
    }

    /// A `direct-streamlocal@openssh.com` channel to a Unix socket; `Ok(false)` when refused.
    pub async fn direct_streamlocal(&self, path: &str) -> anyhow::Result<bool> {
        Ok(self
            .handle
            .channel_open_direct_streamlocal(path)
            .await
            .is_ok())
    }

    /// `ssh host <cmd>`: one exec request, no pty.
    pub async fn exec(&self, cmd: &str) -> anyhow::Result<Chan> {
        let ch = self.handle.channel_open_session().await?;
        ch.exec(true, cmd).await?;
        Ok(Chan::new(ch))
    }
}

impl Chan {
    fn new(ch: Channel<client::Msg>) -> Self {
        Self {
            ch,
            out: String::new(),
            exit: None,
            closed: false,
            asked: 0,
            mark: 0,
        }
    }

    pub async fn send(&self, line: &str) -> anyhow::Result<()> {
        self.ch.data_bytes(format!("{line}\r").into_bytes()).await?;
        Ok(())
    }

    /// Reads until `out` contains `needle` (from the start of the session, so call sites say what
    /// they expect next by sending first), or fails after `secs` or when the channel ends.
    pub async fn expect(&mut self, needle: &str, secs: u64) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        while !self.since_mark().contains(needle) {
            if self.closed {
                bail!("channel closed before {needle:?}; output: {:?}", self.out);
            }
            match tokio::time::timeout_at(deadline, self.ch.wait()).await {
                Err(_) => bail!("timed out waiting for {needle:?}; output: {:?}", self.out),
                Ok(m) => self.absorb(m),
            }
            self.answer_cursor().await?;
        }
        // Sequential: the next `expect` only looks past this match.
        let at = self.since_mark().find(needle).unwrap_or(0);
        self.mark += at + needle.len();
        Ok(())
    }

    /// Reads until the channel ends (or `secs` pass).
    pub async fn finish(&mut self, secs: u64) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        while !self.closed {
            match tokio::time::timeout_at(deadline, self.ch.wait()).await {
                Err(_) => bail!("channel still open after {secs}s; output: {:?}", self.out),
                Ok(m) => self.absorb(m),
            }
        }
        Ok(())
    }

    /// `nos`'s line editor asks the terminal where the cursor is and gives up without an answer.
    async fn answer_cursor(&mut self) -> anyhow::Result<()> {
        let asked = self.out.matches("\x1b[6n").count();
        for _ in self.asked..asked {
            self.ch.data_bytes(&b"\x1b[1;1R"[..]).await?;
        }
        self.asked = asked;
        Ok(())
    }

    fn absorb(&mut self, m: Option<ChannelMsg>) {
        match m {
            Some(ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. }) => {
                self.out.push_str(&String::from_utf8_lossy(&data));
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => self.exit = Some(exit_status),
            Some(ChannelMsg::Close) | None => self.closed = true,
            Some(_) => {}
        }
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
