use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use clap::Parser;
use nos_cli::actions::{
    doc_for_blocking, handle_action, resolve_config_socket, subscribe_hostname_task, DocCache,
    LeaveChoice, Outcome,
};
use nos_cli::command::Command;
use nos_cli::completer::NosCompleter;
use nos_cli::help_menu::HelpMenu;
use nos_cli::login;
use nos_cli::session::{self, Mode};
use nos_cli::{client, watchdog_client};
use nos_pki::Identity;
use nos_proto::{CommandDoc, Topic};
use reedline::{
    default_emacs_keybindings, ColumnarMenu, Completer, Emacs, KeyCode, KeyModifiers, MenuBuilder,
    Prompt, PromptEditMode, PromptHistorySearch, Reedline, ReedlineEvent, ReedlineMenu, Signal,
};

#[derive(Parser)]
#[command(name = "nos", about = "NOS interactive shell")]
struct Args {
    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address and, for `show route`, a specific nos-ribd
    /// instance's address — rather than assuming a hardcoded default.
    #[arg(long, default_value = nos_proto::DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// The public CA certificate `nos-watchdogd` publishes — the trust anchor
    /// every daemon connection is checked against. It authenticates the
    /// watchdog to this shell and grants nothing.
    #[arg(long, default_value = nos_proto::DEFAULT_PKI_CA)]
    pki_ca: PathBuf,

    /// Run as a login shell (implied by a leading `-` in `argv[0]`): redeem
    /// the PAM login ticket instead of prompting first.
    #[arg(long, hide = true)]
    login_shell: bool,

    /// Refused: sshd runs `ssh host cmd` as `<shell> -c cmd`; use the REST API.
    #[arg(short = 'c', hide = true)]
    command: Option<String>,
}

/// `nos -c <cmd>` is refused in every mode (checked before any watchdog contact).
fn refuse_command(args: &Args) -> Option<&'static str> {
    args.command.is_some().then_some(
        "nos: running a command is not supported; use the API (REST) or an interactive session",
    )
}

/// Takes `NOS_LOGIN_TICKET` out of the environment.
#[allow(
    unsafe_code,
    reason = "single-threaded: runs in main before the tokio runtime and any other thread"
)]
fn take_login_ticket() -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let raw = std::env::var_os(nos_proto::LOGIN_TICKET_ENV);
    // SAFETY: only called from `main` before any thread exists.
    unsafe { std::env::remove_var(nos_proto::LOGIN_TICKET_ENV) };
    login::parse_ticket(raw)
}

/// Placeholder shown until the daemon is reachable — see `subscribe_hostname_task`.
const FALLBACK_HOSTNAME: &str = "nos";

struct NosPrompt {
    hostname: Arc<Mutex<String>>,
    suffix: String,
}

impl NosPrompt {
    fn for_mode(hostname: Arc<Mutex<String>>, mode: &Mode) -> Self {
        let suffix = match mode {
            Mode::Operational => String::new(),
            Mode::Configuration {
                transaction, path, ..
            } if path.is_root() => format!("({transaction})"),
            Mode::Configuration {
                transaction, path, ..
            } => format!("({transaction}/{path})"),
        };
        Self { hostname, suffix }
    }
}

impl Prompt for NosPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        let hostname = self.hostname.lock().unwrap().clone();
        Cow::Owned(format!("{hostname}{}", self.suffix))
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(&self, _mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Borrowed("> ")
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed(":::  ")
    }

    fn render_prompt_history_search_indicator(&self, _search: PromptHistorySearch) -> Cow<'_, str> {
        Cow::Borrowed("(search)> ")
    }
}

/// `?` and Tab both leave text insertion alone otherwise, so both need an
/// explicit keybinding on top of `default_emacs_keybindings()`: Tab opens
/// (or cycles) `completion_menu`, and `?` opens (or, on a second consecutive
/// press — see `help_menu::HelpMenu`) deepens `nos_help`. Both follow the
/// same `UntilFound([Menu(name), MenuNext-ish])` shape reedline's own docs
/// use for Tab — `ReedlineEvent::Menu(name)` only fires when no menu is
/// already active, so the second event in each pair is what a repeat press
/// falls through to.
fn keybindings() -> reedline::Keybindings {
    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Char('?'),
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("nos_help".to_string()),
            ReedlineEvent::MenuPageNext,
        ]),
    );
    keybindings
}

/// Builds the completer for the *current* `mode` — called fresh each loop
/// iteration (mirroring `NosPrompt::for_mode`, already rebuilt every
/// iteration) so completions/`?`/`help` always reflect the mode the last
/// command actually landed in.
fn completer_for(socket: &Path, cache: DocCache, mode: &Mode) -> Box<dyn Completer + Send> {
    let doc_socket = socket.to_path_buf();
    let doc_source: Box<dyn FnMut(Topic) -> CommandDoc + Send> =
        Box::new(move |topic| doc_for_blocking(&doc_socket, &cache, topic));
    // The open transaction's config (what `edit`/`set`/`delete` act on),
    // else the running one (`show route <table>` in operational mode).
    let socket = socket.to_path_buf();
    let transaction = match mode {
        Mode::Configuration { transaction, .. } => Some(transaction.clone()),
        Mode::Operational => None,
    };
    let config_source: Box<dyn FnMut() -> Option<serde_json::Value> + Send> = Box::new(move || {
        let config = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match &transaction {
                    Some(t) => client::get_transaction(&socket, t)
                        .await
                        .map(|snap| snap.config),
                    None => client::fetch_running_config(&socket).await,
                }
            })
        });
        serde_json::to_value(config.ok()?).ok()
    });
    Box::new(NosCompleter::new(mode.clone(), doc_source, config_source))
}

// Not `#[tokio::main]`: the ticket variable must be removed while still
// single-threaded (`remove_var` is only sound then).
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(msg) = refuse_command(&args) {
        eprintln!("{msg}");
        std::process::exit(2);
    }
    let argv0 = std::env::args_os().next().unwrap_or_default();
    let ticket = if login::login_shell_mode(&argv0, args.login_shell) {
        take_login_ticket()
    } else {
        None
    };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(args, ticket))
}

async fn run(args: Args, ticket: Option<zeroize::Zeroizing<Vec<u8>>>) -> anyhow::Result<()> {
    let mut mode = Mode::Operational;
    let doc_cache: DocCache = Arc::new(Mutex::new(HashMap::new()));

    // Trust the watchdog's CA, log in through it (it checks the password and
    // certifies a key we generate here), and only then talk to any daemon.
    let ca = std::fs::read(&args.pki_ca).with_context(|| {
        format!(
            "cannot read the ipc trust anchor {} — is nos-watchdogd running, with its /run/nos shared with this shell?",
            args.pki_ca.display()
        )
    })?;
    let identity = Identity::anonymous_from_pem(&ca).context("the ipc trust anchor is unusable")?;
    nos_pki::install(identity.clone());
    login(&args.watchdog_socket, &identity, ticket).await?;
    let config_socket = resolve_config_socket(&args.watchdog_socket).await;

    let completion_menu = ColumnarMenu::default().with_name("completion_menu");
    let mut line_editor = Reedline::create()
        .with_completer(completer_for(&config_socket, doc_cache.clone(), &mode))
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(completion_menu)))
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(HelpMenu::new())))
        .with_edit_mode(Box::new(Emacs::new(keybindings())));

    let hostname = Arc::new(Mutex::new(FALLBACK_HOSTNAME.to_string()));
    match client::fetch_running_config(&config_socket).await {
        Ok(cfg) => *hostname.lock().unwrap() = cfg.hostname,
        Err(_) => eprintln!(
            "warning: could not reach nos-configd at startup; hostname prompt may be stale"
        ),
    }

    // `RepaintSignal` isn't reachable outside the reedline crate (its return
    // type here is public but its owning module isn't) — capture it in a
    // closure instead of naming it, so `subscribe_hostname_task` only needs
    // an `impl Fn()` bound.
    let repaint_signal = line_editor.repaint_signal();
    let notify_repaint = move || repaint_signal.request_repaint();
    tokio::spawn(subscribe_hostname_task(
        config_socket.clone(),
        hostname.clone(),
        notify_repaint,
    ));

    println!("NOS interactive shell. Type 'help' for available commands, or press '?' at any point while typing.");

    loop {
        let prompt = NosPrompt::for_mode(hostname.clone(), &mode);
        match line_editor.read_line(&prompt) {
            Ok(Signal::Success(line)) => {
                let action = session::resolve(&mode, Command::parse(&line));
                match handle_action(
                    action,
                    mode,
                    &config_socket,
                    &args.watchdog_socket,
                    &doc_cache,
                    prompt_leave_choice,
                )
                .await
                {
                    Outcome::Continue(next_mode) => mode = next_mode,
                    Outcome::Exit => break,
                }
                line_editor = line_editor.with_completer(completer_for(
                    &config_socket,
                    doc_cache.clone(),
                    &mode,
                ));
            }
            Ok(Signal::CtrlC | Signal::CtrlD) => {
                if let Mode::Configuration { transaction, .. } = &mode {
                    println!(
                        "transaction '{transaction}' left open on the daemon — resume with 'configure {transaction}'"
                    );
                }
                break;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            }
        }
    }

    Ok(())
}

/// How many wrong username/password pairs are tolerated before the shell exits.
const LOGIN_ATTEMPTS: usize = 3;

/// Prompts for a username and password (no echo) and logs in through
/// `nos-watchdogd`: it checks them against the running config's users and, if
/// they match, certifies a key generated here — the certificate is held in
/// memory only and renewed in the background. Fails closed: with the watchdog
/// unreachable there is nobody to authenticate to, so the shell refuses to
/// start. The password check no longer happens in this process at all, and the
/// password hashes never leave the daemons.
async fn login(
    watchdog_socket: &Path,
    identity: &Identity,
    ticket: Option<zeroize::Zeroizing<Vec<u8>>>,
) -> anyhow::Result<()> {
    // SSH login shell: PAM already verified the password; a refused or
    // missing ticket falls back to the prompt, an unreachable watchdog fails.
    if let Some(ticket) = ticket
        && let Some((issued, key)) = login::redeem_ticket(watchdog_socket, &ticket).await?
    {
        identity.set_certificate(issued.cert_der, key)?;
        keep_certificate_fresh(
            watchdog_socket.to_path_buf(),
            identity.clone(),
            issued.lifetime,
        );
        return Ok(());
    }
    for _ in 0..LOGIN_ATTEMPTS {
        print!("login: ");
        std::io::stdout().flush()?;
        let mut name = String::new();
        if std::io::stdin().read_line(&mut name)? == 0 {
            anyhow::bail!("no login supplied");
        }
        let name = name.trim();
        let password = rpassword::prompt_password("password: ")?;
        let (csr, key) = nos_pki::generate_csr()?;
        match watchdog_client::login(watchdog_socket, name, &password, csr).await {
            Ok(issued) => {
                identity.set_certificate(issued.cert_der, key)?;
                keep_certificate_fresh(
                    watchdog_socket.to_path_buf(),
                    identity.clone(),
                    issued.lifetime,
                );
                return Ok(());
            }
            Err(watchdog_client::WatchdogClientError::Denied(_)) => eprintln!("login incorrect"),
            Err(e) => anyhow::bail!("cannot log in: {e}"),
        }
    }
    anyhow::bail!("too many failed login attempts")
}

/// Renews the session's certificate at half its lifetime, with no password
/// (the still-valid certificate is the proof), retrying every 30s if the
/// watchdog can't be reached.
// ponytail: if renewal keeps failing until the certificate expires, commands
// start failing with connection errors and the user restarts the shell. A
// re-prompt for the password instead would need the prompt owned by the loop.
fn keep_certificate_fresh(
    watchdog_socket: PathBuf,
    identity: Identity,
    lifetime: std::time::Duration,
) {
    const RETRY: std::time::Duration = std::time::Duration::from_secs(60);
    tokio::spawn(async move {
        let mut next = lifetime;
        loop {
            tokio::time::sleep(next / 2).await;
            let renewed = async {
                let (csr, key) = nos_pki::generate_csr().ok()?;
                let issued = watchdog_client::renew(&watchdog_socket, csr).await.ok()?;
                identity.set_certificate(issued.cert_der, key).ok()?;
                Some(issued.lifetime)
            }
            .await;
            next = renewed.unwrap_or(RETRY);
        }
    });
}

/// Blocking stdin prompt for what to do with an uncommitted transaction on
/// plain `exit`. Deliberately not a `reedline`-edited line — this is a
/// one-off yes/no-style question, not command input.
fn prompt_leave_choice(transaction: &str) -> LeaveChoice {
    loop {
        print!(
            "Transaction '{transaction}' has uncommitted changes. [c]ommit / [d]iscard / [l]eave open (default): "
        );
        if io::stdout().flush().is_err() {
            return LeaveChoice::LeaveOpen;
        }
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return LeaveChoice::LeaveOpen;
        }
        match input.trim().to_lowercase().as_str() {
            "c" | "commit" => return LeaveChoice::Commit,
            "d" | "discard" | "abort" => return LeaveChoice::Discard,
            "" | "l" | "leave" | "leave open" => return LeaveChoice::LeaveOpen,
            _ => println!("please enter c, d, or l"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(path: &[&str], dirty: bool) -> Mode {
        Mode::Configuration {
            transaction: "t1".to_string(),
            path: session::Path::from(path.iter().map(ToString::to_string).collect::<Vec<_>>()),
            dirty,
        }
    }

    #[test]
    fn prompt_shows_transaction_and_position() {
        let host = Arc::new(Mutex::new("r1".to_string()));
        let render = |mode: &Mode| {
            NosPrompt::for_mode(host.clone(), mode)
                .render_prompt_left()
                .into_owned()
        };
        assert_eq!(render(&Mode::Operational), "r1");
        assert_eq!(render(&config(&[], false)), "r1(t1)");
        assert_eq!(
            render(&config(&["bgp-instance", "i"], false)),
            "r1(t1/bgp-instance:i)"
        );
        let p = NosPrompt::for_mode(host, &Mode::Operational);
        assert_eq!(p.render_prompt_right(), "");
        assert_eq!(p.render_prompt_indicator(PromptEditMode::Default), "> ");
        assert_eq!(p.render_prompt_multiline_indicator(), ":::  ");
        let search =
            PromptHistorySearch::new(reedline::PromptHistorySearchStatus::Passing, String::new());
        assert_eq!(
            p.render_prompt_history_search_indicator(search),
            "(search)> "
        );
    }

    #[test]
    fn args_parse_with_defaults() {
        let args = Args::try_parse_from(["nos"]).unwrap();
        assert_eq!(
            args.watchdog_socket,
            PathBuf::from(nos_proto::DEFAULT_WATCHDOG_SOCKET)
        );
        let _ = keybindings();
    }

    #[test]
    fn dash_c_is_refused() {
        let a = Args::try_parse_from(["nos", "-c", "show version"]).unwrap();
        assert!(refuse_command(&a).unwrap().contains("not supported"));
        assert!(refuse_command(&Args::try_parse_from(["nos"]).unwrap()).is_none());
    }
}
