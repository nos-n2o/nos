//! `pam_nos.so` (#987/#998): the PAM module sshd will load, exercised with
//! `pamtester` (lab image only) against the real watchdog login broker, so the
//! `PamModule` adapters that `cargo test -p nos-pam` cannot reach are proven too.

use anyhow::bail;

use crate::consts::*;
use crate::router::log;
use crate::world::World;

/// Runs `pamtester <service> <user> <op>` on router-a with `password` on stdin (no tty in
/// an exec); `(exit code, output)`. The password goes through `$1`, not the command line.
async fn pamtester(
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
    let user_line = |verb: &str, user: &str| format!("login {verb} user=\"{user}\"");

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
    let any = "login \\(accepted\\|rejected\\) user=";
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
    a.assert_quiet(any, n, 2).await
}
