use std::ffi::{CStr, OsStr, OsString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use nonstick::items::Items;
use nonstick::{
    AuthnFlags, BaseFlags, CredAction, EnvironMapMut, ErrorCode, ModuleClient, PamModule,
    Result as PamResult,
};
use zeroize::Zeroizing;

use crate::login::{login, LoginError};
use crate::options::Options;
use crate::session::NosTicket;

/// One overall deadline for the broker round trip (dial, TLS, request, reply).
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);

pub struct NosPam;

/// A panic must never unwind across the C boundary into sshd's monitor.
pub fn guard<T>(f: impl FnOnce() -> PamResult<T>) -> PamResult<T> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(Err(ErrorCode::ServiceError))
}

/// The fields of a `passwd` entry the guard looks at.
pub struct Passwd {
    pub uid: u32,
    pub shell: String,
}

/// `getpwnam_r` through NSS (`files nos`); `Ok(None)` = no such name.
pub fn lookup(name: &str) -> PamResult<Option<Passwd>> {
    match nix::unistd::User::from_name(name) {
        Ok(u) => Ok(u.map(|u| Passwd {
            uid: u.uid.as_raw(),
            shell: u.shell.to_string_lossy().into_owned(),
        })),
        Err(_) => Err(ErrorCode::AuthInfoUnavailable),
    }
}

/// A system account (root, daemon, a local login) never reaches the broker (#1375): a name
/// that resolves must be a NOS user (the `nos` shell, the NSS uid range). An unresolvable
/// name passes: the broker decides, and over ssh its empty token already stops it.
pub fn account_guard(
    lookup: impl Fn(&str) -> PamResult<Option<Passwd>>,
    user: &str,
) -> PamResult<()> {
    match lookup(user) {
        Err(e) => Err(e),
        Ok(None) => Ok(()),
        Ok(Some(p))
            if p.shell == nos_proto::NOS_LOGIN_SHELL
                && nos_proto::NOS_UID_RANGE.contains(&p.uid) =>
        {
            Ok(())
        }
        Ok(Some(_)) => Err(ErrorCode::AuthenticationError),
    }
}

/// The PAM-free core of `authenticate`: every input check, the broker round
/// trip and the return-code mapping. Empty or non-UTF-8 names and passwords never
/// reach the broker.
pub fn authenticate_user(
    opts: &Options,
    user: &OsStr,
    password: OsString,
    timeout: Duration,
) -> PamResult<NosTicket> {
    let user = user.to_str().filter(|u| !u.is_empty());
    // ponytail: `into_string` drops a non-UTF-8 password un-zeroed, and nonstick's
    // `authtok` copy of it is plain memory; both live only until this returns.
    let password = password.into_string().ok().map(Zeroizing::new);
    let (Some(user), Some(password)) = (user, password.filter(|p| !p.is_empty())) else {
        return Err(ErrorCode::AuthenticationError);
    };
    account_guard(lookup, user)?;
    match login(&opts.socket, &opts.ca, user, &password, timeout) {
        Ok(ticket) => Ok(ticket),
        Err(LoginError::Denied) => Err(ErrorCode::AuthenticationError),
        Err(LoginError::Unavailable) => Err(ErrorCode::AuthInfoUnavailable),
    }
}

/// `account_management`'s decision: only a flow that authenticated *this* user
/// through this module passes. Never `Ignore`: with `account required` that
/// would let a stack that skipped `authenticate` through.
pub fn check_account(ticket: Option<&NosTicket>, user: &OsStr) -> PamResult<()> {
    account_guard(lookup, user.to_str().ok_or(ErrorCode::AuthenticationError)?)?;
    match ticket {
        Some(s) if user.to_str() == Some(s.user.as_str()) => Ok(()),
        _ => Err(ErrorCode::AuthenticationError),
    }
}

/// The variable `nos` (login-shell mode, #991) reads the ticket from.
pub use nos_proto::LOGIN_TICKET_ENV;

fn outcome(r: &PamResult<NosTicket>) -> &'static str {
    match r {
        Ok(_) => "success",
        Err(ErrorCode::AuthenticationError) => "denied",
        Err(_) => "unavailable",
    }
}

/// The one audit line `authenticate` logs: never the password, the ticket or an error source.
pub fn audit_line(user: &OsStr, service: &OsStr, outcome: &str) -> String {
    format!(
        "user={} service={} outcome={}",
        user.to_string_lossy(),
        service.to_string_lossy(),
        outcome
    )
}

impl<T: ModuleClient> PamModule<T> for NosPam {
    fn authenticate(handle: &mut T, args: Vec<&CStr>, _flags: AuthnFlags) -> PamResult<()> {
        guard(|| {
            let (opts, unknown) = Options::parse(&args);
            for name in unknown {
                nonstick::warn!(handle, "ignoring unknown option {name}");
            }
            let user = handle.username(None)?;
            let password = if opts.use_first_pass {
                handle
                    .authtok_item()?
                    .ok_or(ErrorCode::AuthenticationError)?
            } else {
                handle.authtok(None)?
            };
            let service = handle.items().service()?.unwrap_or_default();
            let result = authenticate_user(&opts, &user, password, LOGIN_TIMEOUT);
            // Never the password, the broker's text or an error source.
            nonstick::info!(handle, "{}", audit_line(&user, &service, outcome(&result)));
            let ticket = result?;
            // sshd runs authenticate + acct_mgmt in a forked child (keyboard-interactive) and
            // copies that child's `pam_getenvlist()` to the session; open_session runs in the
            // monitor, whose handle never saw this module data. So the export happens here.
            handle
                .environ_mut()
                .insert(LOGIN_TICKET_ENV, ticket.encoded.as_str());
            handle.set_module_data(NosTicket::KEY, ticket)
        })
    }

    fn account_management(handle: &mut T, _args: Vec<&CStr>, _flags: AuthnFlags) -> PamResult<()> {
        guard(|| {
            let user = handle.username(None)?;
            check_account(handle.get_module_data::<NosTicket>(NosTicket::KEY), &user)
        })
    }

    fn set_credentials(
        _handle: &mut T,
        _args: Vec<&CStr>,
        _action: CredAction,
        _flags: BaseFlags,
    ) -> PamResult<()> {
        // Nothing to establish or delete here; the ticket hand-off is #989.
        guard(|| Ok(()))
    }
}
