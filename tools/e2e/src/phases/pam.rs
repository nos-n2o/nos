//! `pam_nos.so` (#987/#998): the PAM module sshd will load, exercised with
//! `pamtester` (lab image only) against the real watchdog login broker, so the
//! `PamModule` adapters that `cargo test -p nos-pam` cannot reach are proven too.

use anyhow::{bail, Context};
use reqwest::Method;

use crate::consts::*;
use crate::router::log;
use crate::world::World;

/// Runs `pamtester <service> <user> <op>` on router-a with `password` on stdin (no tty in
/// an exec); `(exit code, output)`. The password goes through `$1`, not the command line.
pub(super) async fn pamtester(
    w: &World,
    service: &str,
    user: &str,
    password: &str,
    op: &str,
) -> anyhow::Result<(i64, String)> {
    let script = "printf '%s\\n' \"$1\" | pamtester \"$2\" \"$3\" \"$4\" 2>&1";
    w.dock
        .exec(
            "router-a",
            &["sh", "-c", script, "sh", password, service, user, op],
        )
        .await
}

/// Expects `pamtester` to refuse with `needle` in its output.
fn refused(what: &str, (code, out): (i64, String), needle: &str) -> anyhow::Result<()> {
    if code == 0 || !out.contains(needle) {
        bail!("{what} must be refused with {needle:?}, got exit {code}: {out}");
    }
    Ok(())
}

/// Right password authenticates; wrong password, unknown user and empty password do not;
/// `acct_mgmt` needs a prior `authenticate`; a caller with no access to the CA fails closed. Needs `up`.
pub async fn pam(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    // pam_nos asks for a login ticket (#992), not a certificate: success is `ticket issued`.
    let user_line = |verb: &str, user: &str| match verb {
        "accepted" => format!("login ticket issued user=\"{user}\""),
        _ => format!("login {verb} user=\"{user}\""),
    };

    log("pam: right password");
    let n = a.count(&user_line("accepted", E2E_USER));
    let (code, out) = pamtester(w, PAM_SERVICE, E2E_USER, E2E_PASSWORD, "authenticate").await?;
    if code != 0 || !out.contains("successfully authenticated") {
        bail!("the right password must authenticate, got exit {code}: {out}");
    }
    a.wait_new(&user_line("accepted", E2E_USER), n, 15).await?;

    log("pam: wrong password");
    let n = a.count(&user_line("rejected", E2E_USER));
    let r = pamtester(w, PAM_SERVICE, E2E_USER, PAM_WRONG_PASSWORD, "authenticate").await?;
    refused("a wrong password", r, "Authentication failure")?;
    a.wait_new(&user_line("rejected", E2E_USER), n, 15).await?;

    log("pam: unknown user");
    let n = a.count(&user_line("rejected", PAM_UNKNOWN_USER));
    let r = pamtester(
        w,
        PAM_SERVICE,
        PAM_UNKNOWN_USER,
        E2E_PASSWORD,
        "authenticate",
    )
    .await?;
    refused("an unknown user", r, "Authentication failure")?;
    a.wait_new(&user_line("rejected", PAM_UNKNOWN_USER), n, 15)
        .await?;

    log("pam: empty password is refused locally, the broker never hears of it");
    let any = "login \\(ticket issued\\|rejected\\) user=";
    let n = a.count(any);
    let r = pamtester(w, PAM_SERVICE, E2E_USER, "", "authenticate").await?;
    refused("an empty password", r, "Authentication failure")?;
    a.assert_quiet(any, n, 3).await?;

    log("pam: acct_mgmt without a prior authenticate");
    let n = a.count(any);
    let (code, out) = pamtester(w, PAM_SERVICE, E2E_USER, E2E_PASSWORD, "acct_mgmt").await?;
    if code == 0 {
        bail!("acct_mgmt alone must be refused, got: {out}");
    }
    a.assert_quiet(any, n, 3).await?;

    // /run/nos is group `nos` only: `nobody` can read neither ca.crt nor the broker socket, so
    // the module cannot get an answer and must fail closed (a different error than a denial).
    log("pam: no access to the CA or the broker fails closed");
    let n = a.count(any);
    let (code, out) = w
        .dock
        .exec_as(
            "router-a",
            Some("nobody"),
            &[
                "sh",
                "-c",
                "printf '%s\\n' \"$1\" | pamtester \"$2\" \"$3\" authenticate 2>&1",
                "sh",
                E2E_PASSWORD,
                PAM_SERVICE,
                E2E_USER,
            ],
        )
        .await?;
    refused(
        "a login without access to the CA",
        (code, out),
        "cannot retrieve authentication info",
    )?;
    a.assert_quiet(any, n, 2).await?;

    nss(w).await
}

/// `nos-configd` mirrors the user names into `/run/nos-users/passwd` (#999): a created user
/// resolves through `getent` (uid 20000..=59999, shell `/usr/bin/nos`) and authenticates, the
/// file holds no hash, a deleted one disappears, and a re-created one gets the same uid back.
async fn nss(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    let tx = format!("/v1/transactions/{NSS_TX}");
    let user = format!("{tx}/user/{NSS_USER}");
    let body = format!(r#"{{"name":"{NSS_USER}","password":"{NSS_PASSWORD}"}}"#);
    let getent = || async {
        w.dock
            .exec("router-a", &["getent", "passwd", NSS_USER])
            .await
    };
    let edit = |method: Method, status: u16| {
        let (tx, user, body) = (&tx, &user, &body);
        async move {
            a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
                .await?;
            let b = (method == Method::PUT).then_some(body.as_str());
            a.rest_expect(method, user, b, status).await?;
            a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
                .await
        }
    };
    let uid_of = |line: &str| -> anyhow::Result<u32> {
        let f: Vec<&str> = line.trim().split(':').collect();
        if f.len() != 7 || f[0] != NSS_USER || f[6] != "/usr/bin/nos" {
            bail!("unexpected passwd entry: {line:?}");
        }
        let uid: u32 = f[2].parse()?;
        if !(20_000..=59_999).contains(&uid) || f[3] != f[2] {
            bail!("uid/gid out of the NSS range: {line:?}");
        }
        Ok(uid)
    };

    log("pam: a created user resolves through getent and authenticates");
    edit(Method::PUT, 200).await?;
    let (code, out) = getent().await?;
    if code != 0 {
        bail!("getent passwd {NSS_USER} failed ({code}): {out}");
    }
    let uid = uid_of(&out)?;
    let (code, out) = pamtester(w, PAM_SERVICE, NSS_USER, NSS_PASSWORD, "authenticate").await?;
    if code != 0 {
        bail!("the new user must authenticate, got exit {code}: {out}");
    }
    let (_, file) = w
        .dock
        .exec("router-a", &["cat", "/run/nos-users/passwd"])
        .await?;
    if file.contains("argon2") || file.contains(NSS_PASSWORD) {
        bail!("/run/nos-users/passwd leaks a credential: {file}");
    }

    log("pam: a deleted user disappears");
    edit(Method::DELETE, 204).await?;
    if getent().await?.0 == 0 {
        bail!("getent still resolves the deleted user");
    }
    let r = pamtester(w, PAM_SERVICE, NSS_USER, NSS_PASSWORD, "authenticate").await?;
    refused("a deleted user", r, "Authentication failure")?;

    log("pam: a re-created user keeps its uid");
    edit(Method::PUT, 200).await?;
    let (code, out) = getent().await?;
    if code != 0 || uid_of(&out).context("re-created user")? != uid {
        bail!("re-created user must get uid {uid} back, got ({code}): {out}");
    }
    // leave the lab as found
    edit(Method::DELETE, 204).await?;
    Ok(())
}
