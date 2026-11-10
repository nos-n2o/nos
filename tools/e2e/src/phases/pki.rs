//! IPC transport security: every daemon connection is mutually authenticated
//! post-quantum TLS (ML-KEM key exchange, ML-DSA certificates), `nos-watchdogd`
//! is the certificate authority, and humans log in.
//!
//! Every other phase is already an implicit test of the happy path — none of
//! them could pass if a daemon couldn't authenticate to another — so these
//! only assert what they can't: who each daemon believes it is, that login
//! accepts the right password and refuses the wrong one, that revocation (a
//! CRL pushed down every daemon's stdin) locks out a deleted user, a changed
//! password and a restarted daemon at once, and that hot rotation really keeps
//! long-lived daemons connectable after their first certificate has expired.

use anyhow::{bail, Context};
use reqwest::Method;

use super::bgp;
use crate::consts::*;
use crate::router::{log, A};
use crate::world::World;

/// A daemon's log line for the identity it was handed: `role` is what its
/// certificate asserts, `name` the instance/table (empty for singletons).
fn identity(message: &str, fields: &str, role: &str, name: &str) -> String {
    format!("{message} {fields}peer=Some(PeerId {{ role: \"{role}\", name: \"{name}\" }})")
}

/// Runs `nos-provision` on router-a as `password`, the way an operator or the
/// bench would: it must log in before it may touch `nos-configd`.
async fn provision_as(w: &World, password: &str) -> anyhow::Result<(i64, String)> {
    run_provision(w, &["--login-user", E2E_USER, "--login-password", password]).await
}

/// `nos-provision` on router-a with `auth` (how it gets a certificate) and
/// router-a's own base flags — an idempotent re-apply of its config.
async fn run_provision(w: &World, auth: &[&str]) -> anyhow::Result<(i64, String)> {
    let mut cmd = vec![
        "nos-provision".to_string(),
        "--config-socket".to_string(),
        "/run/nos/config.sock".to_string(),
    ];
    cmd.extend(auth.iter().map(ToString::to_string));
    cmd.extend(A.base_flags());
    let cmd: Vec<&str> = cmd.iter().map(String::as_str).collect();
    w.dock.exec("router-a", &cmd).await
}

/// Each daemon holds the identity the watchdog minted for it, login works, and
/// a wrong password is refused. Requires `up` (and `established`) to have run.
pub async fn pki(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.wait("ipc certificate authority ready").await?;
    a.wait(&identity("ipc identity loaded", "", "configd", ""))
        .await?;
    a.wait(&identity("nos-ribd starting", "table=rt1 ", "ribd", "rt1"))
        .await?;
    // Whatever the instance is called, its certificate must carry that name.
    a.wait(&identity("nos-bgpd starting", "instance=.* ", "bgpd", ".*"))
        .await?;

    check_uids(w).await?;

    // Every IPC handshake is hybrid ML-KEM key exchange with ML-DSA-65
    // certificates — and none, on any daemon, negotiated anything else.
    a.wait("ipc tls handshake ok side=server kx=X25519MLKEM768 peer_key=ML-DSA-65")
        .await?;
    let classical = a.count("ipc tls handshake ok side=[a-z]* kx=[^X]");
    if classical != 0 {
        bail!("{classical} IPC handshakes negotiated a key exchange other than X25519MLKEM768");
    }
    // The REST listener is certified separately, by the REST CA.
    a.wait("issued a REST listener certificate").await?;

    log("logging in with the wrong password (must be refused)");
    let rejected = a.count(&format!("login rejected user=\"{E2E_USER}\""));
    let (code, out) = provision_as(w, "not-the-password").await?;
    if code == 0 || !out.contains("login refused") {
        bail!("a wrong password must be refused, got exit {code}: {out}");
    }
    a.wait_new(&format!("login rejected user=\"{E2E_USER}\""), rejected, 15)
        .await?;

    log("logging in with the right password, then editing config as that user");
    let accepted = a.count(&format!("login accepted user=\"{E2E_USER}\""));
    let (code, out) = provision_as(w, E2E_PASSWORD).await?;
    if code != 0 || !out.contains("provisioning complete") {
        bail!("login with the right password should provision, got exit {code}: {out}");
    }
    a.wait_new(&format!("login accepted user=\"{E2E_USER}\""), accepted, 15)
        .await?;

    revoke_user(w).await?;
    revoke_restarted_daemon(w).await
}

/// The watchdog (the CA) runs on its own uid and every role on its own
/// (#512, #513): the `starting` lines carry the ids, `/proc` agrees, and a
/// daemon cannot unlink another's 0660 `group nos` socket in the sticky
/// `/run/nos`.
async fn check_uids(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.wait("starting process=nos-configd program=/usr/local/bin/nos-configd uid=10001 gid=991")
        .await?;
    // `/proc/<pid>/status` is world-readable; the runtime image has no `ps`.
    let uid_of = |comm: &'static str| async move {
        let script = format!(
            "for p in /proc/[0-9]*; do [ \"$(cat $p/comm 2>/dev/null)\" = {comm} ] && \
             awk '/^Uid:/ {{print $2}}' $p/status && break; done"
        );
        let (_, out) = w.dock.exec("router-a", &["sh", "-c", &script]).await?;
        anyhow::Ok(out.trim().to_string())
    };
    let want = [
        ("nos-watchdogd", "990"),
        ("nos-configd", "10001"),
        ("nos-logd", "10002"),
        ("nos-bgpd", "10003"),
        ("nos-ribd", "10004"),
    ];
    for (comm, uid) in want {
        let got = uid_of(comm).await?;
        if got != uid {
            bail!("expected {comm} uid {uid}, got {got:?}");
        }
    }
    // nos-bgpd (10003) cannot remove nos-logd's socket: /run/nos is sticky.
    let (code, out) = w
        .dock
        .exec_as("router-a", Some("10003"), &["rm", "/run/nos/log.sock"])
        .await?;
    if code == 0 {
        bail!("nos-bgpd's uid unlinked nos-logd's socket: {out}");
    }
    let (code, out) = w
        .dock
        .exec("router-a", &["stat", "-c", "%a %U %G", "/run/nos/log.sock"])
        .await?;
    if code != 0 || out.trim() != "660 nos-logd nos" {
        bail!("log.sock should be 660 nos-logd nos after the refused rm, got {code}: {out:?}");
    }
    Ok(())
}

/// A throwaway user for the revocation checks (router-a only).
const REVOKED_USER: &str = "revoked";
/// Where `nos-provision` keeps that user's certificate between two runs.
const REVOKED_CERT: &str = "/tmp/revoked-user.identity";

/// Logs `REVOKED_USER` in with `password`, keeping the certificate.
async fn login_keeping_cert(w: &World, password: &str) -> anyhow::Result<()> {
    let (code, out) = run_provision(
        w,
        &[
            "--login-user",
            REVOKED_USER,
            "--login-password",
            password,
            "--pki-cert-out",
            REVOKED_CERT,
        ],
    )
    .await?;
    if code != 0 {
        bail!("{REVOKED_USER} could not log in with {password}: exit {code}: {out}");
    }
    Ok(())
}

/// Whether the certificate `login_keeping_cert` saved still opens `nos-configd`.
async fn saved_cert_works(w: &World) -> anyhow::Result<bool> {
    let (code, _) = run_provision(w, &["--pki-cert-in", REVOKED_CERT]).await?;
    Ok(code == 0)
}

/// A user's shell certificates are revoked the moment its password changes or
/// it is deleted — over IPC, where no server re-checks the user per request.
async fn revoke_user(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    let revoked = format!("certificates revoked role=user name={REVOKED_USER} ");
    let refused = "IPC tls handshake failed error=.*[Rr]evoked";

    log("a throwaway user logs in; its certificate works for a second connection");
    a.provision(&["--user", &format!("{REVOKED_USER}=first-password")])
        .await?;
    login_keeping_cert(w, "first-password").await?;
    if !saved_cert_works(w).await? {
        bail!("a fresh user certificate was refused");
    }
    // The same user's REST certificate: the REST CA has no CRL, so the
    // watchdog's allowlist (checked by nos-restd on every request) revokes it.
    let Ok(rest_id) = a.rest.login(REVOKED_USER, "first-password").await? else {
        bail!("{REVOKED_USER} could not log in over REST");
    };
    let rest_client = a.rest.with_identity(&rest_id)?;
    let config = |client: reqwest::Client| async move {
        a.rest_with(&client, Method::GET, "/v1/config", None)
            .await
            .map(|(status, _)| status)
    };
    if config(rest_client.clone()).await? != 200 {
        bail!("a fresh REST certificate was refused");
    }

    log("changing its password revokes that certificate");
    let (revocations, refusals) = (a.count(&revoked), a.count(refused));
    a.provision(&["--user", &format!("{REVOKED_USER}=second-password")])
        .await?;
    a.wait_new(&revoked, revocations, 30).await?;
    if saved_cert_works(w).await? {
        bail!("a certificate issued before the password change still opens nos-configd");
    }
    a.wait_new(refused, refusals, 15).await?;
    if config(rest_client).await? != 401 {
        bail!("a REST certificate issued before the password change still works");
    }
    let Ok(fresh) = a.rest.login(REVOKED_USER, "second-password").await? else {
        bail!("{REVOKED_USER} could not log in over REST with the new password");
    };
    if config(a.rest.with_identity(&fresh)?).await? != 200 {
        bail!("a REST certificate issued after the password change was refused");
    }
    login_keeping_cert(w, "second-password").await?;
    if !saved_cert_works(w).await? {
        bail!("a certificate issued after the password change was refused");
    }

    log("deleting the user revokes its certificate");
    let revocations = a.count(&revoked);
    a.edit(|config| {
        config.users.retain(|u| u.name != REVOKED_USER);
        Ok(())
    })
    .await?;
    a.wait_new(&revoked, revocations, 30).await?;
    if saved_cert_works(w).await? {
        bail!("a deleted user's certificate still opens nos-configd");
    }
    login_burst(w).await
}

/// #381: 200 unauthenticated logins on made-up usernames at once. Every reply
/// is 401 (checked) or 429 (refused for load); the watchdog survives the
/// burst (it would log `broker IPC listening` again if restarted) and a good
/// login still works.
async fn login_burst(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    log("a burst of 200 logins on distinct usernames is bounded, not fatal");
    let starts = a.count("broker IPC listening");
    let replies = futures::future::join_all((0..200).map(|i| {
        let rest = &a.rest;
        async move { rest.login(&format!("nobody-{i}"), "wrong").await }
    }))
    .await;
    for r in replies {
        match r?.err() {
            Some(401 | 429) => {}
            other => bail!("burst login answered {other:?}, want 401 or 429"),
        }
    }
    // The in-flight cap turned most of the burst away before it could fail,
    // so top the failures up one at a time (no contention: a 429 now is the
    // per-address limit, 20 failures in 60s).
    let mut locked = false;
    for i in 0..60 {
        match a.rest.login(&format!("topup-{i}"), "wrong").await?.err() {
            Some(401) => {}
            Some(429) => {
                locked = true;
                break;
            }
            other => bail!("login answered {other:?}, want 401 or 429"),
        }
    }
    if !locked {
        bail!("60 failed logins from one address were never rate limited");
    }
    if a.count("broker IPC listening") != starts {
        bail!("nos-watchdogd restarted during the login burst");
    }
    // The harness's address is locked out for the rest of the 60s window,
    // even with the right password; it must recover once the window ends.
    if a.rest.login(E2E_USER, E2E_PASSWORD).await?.err() != Some(429) {
        bail!("a locked-out address was not answered 429");
    }
    let mut recovered = false;
    for _ in 0..70 {
        if a.rest.login(E2E_USER, E2E_PASSWORD).await?.is_ok() {
            recovered = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if !recovered {
        bail!("a good login still failed 70s after the burst");
    }
    a.established().await
}

/// A daemon's certificate dies with its process: the watchdog revokes it on
/// exit and every other daemon applies the new CRL, while the replacement —
/// a fresh certificate — is trusted as before.
async fn revoke_restarted_daemon(w: &World) -> anyhow::Result<()> {
    // A learned route, so the restarted nos-ribd has something to be re-told.
    w.b()?.provision(&bgp::redistribute()).await?;
    let a = w.a()?;
    a.wait(&bgp::learned()).await?;
    let revoked = "certificates revoked role=ribd name=rt1 ";
    let snapshot = "sent initial bgp route snapshot to nos-ribd";
    let (revocations, updates, ribds, snapshots, kernel_routes) = (
        a.count(revoked),
        a.count("ipc crl updated entries="),
        a.count("nos-ribd starting"),
        a.count(snapshot),
        a.count("added route"),
    );
    log("killing router-a's nos-ribd; its certificate must be revoked");
    w.dock
        .kill_process("router-a", "nos-ribd")
        .await
        .context("killing nos-ribd")?;
    a.wait_new(revoked, revocations, 30).await?;
    a.wait_new("ipc crl updated entries=", updates, 30).await?;
    a.wait_new("nos-ribd starting", ribds, 30).await?;
    // #718: with no route change at all, nos-bgpd notices the closed push
    // connection, reconnects, re-sends its snapshot and the route is
    // reinstalled in the kernel.
    a.wait_new(snapshot, snapshots, 30).await?;
    a.wait_new("added route", kernel_routes, 30).await?;
    // nos-restd (holding the new CRL) dials the new nos-ribd: still trusted.
    // nos-restd lives in rt1's VRF, which the new nos-ribd recreates: its
    // listener may take a moment to come back, so a refused connect is retried.
    for _ in 0..60 {
        if matches!(
            a.rest(Method::GET, "/v1/routes/rt1", None).await,
            Ok((200, _))
        ) {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    bail!("the restarted nos-ribd never answered a route query")
}

/// #858: the watchdog's per-write line; `crl_bytes=0` is a rotation frame.
const PUSHED_EMPTY: &str = "identity pushed process=[^ ]* crl_bytes=0";
const PUSHED_CRL: &str = "identity pushed process=[^ ]* crl_bytes=[1-9]";

/// Hot rotation: with certificates that expire in seconds, wait past a whole
/// lifetime, then force fresh handshakes between long-lived processes. Each
/// only succeeds if the dialing daemon had rotated to a certificate that isn't
/// the (long expired) one it was started with.
pub async fn pki_rotation(w: &mut World) -> anyhow::Result<()> {
    let lifetime = format!("--pki-leaf-lifetime={PKI_LEAF_LIFETIME_SECS}");
    let rotate = format!("--pki-rotate-every={PKI_ROTATE_EVERY_SECS}");
    let cap = format!("--pki-ipc-session-max={PKI_IPC_SESSION_MAX_SECS}");
    w.up(&[&lifetime, &rotate, &cap]).await?;
    bgp::established(w).await?;
    let logged_in = std::time::Instant::now();
    ipc_session_cap_start(w).await?;

    let a = w.a()?;
    a.wait_new("ipc identity rotated", 0, PKI_ROTATE_EVERY_SECS * 3)
        .await?;
    // #858: a rotation frame omits the CRL (empty = keep the one held).
    a.wait(PUSHED_EMPTY).await?;

    let wait = PKI_LEAF_LIFETIME_SECS + 10;
    log(format!(
        "waiting {wait}s: every certificate the daemons started with expires in {PKI_LEAF_LIFETIME_SECS}s"
    ));
    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;

    // nos-bgpd is long-lived, so its handshake with the *restarted* nos-ribd
    // uses whatever certificate it holds now — which is only valid if the
    // rotation reached it. Router-b advertises a prefix to router-a first;
    // after the kill nos-bgpd notices the closed push connection by itself.
    w.b()?.provision(&bgp::redistribute()).await?;
    w.a()?.wait(&bgp::learned()).await?;
    let a = w.a()?;
    let snapshot = "sent initial bgp route snapshot to nos-ribd";
    let (pushed, empty, updates) = (
        a.count(PUSHED_CRL),
        a.count(PUSHED_EMPTY),
        a.count("ipc crl updated entries="),
    );
    let (snapshots, kernel_routes, ribds) = (
        a.count(snapshot),
        a.count("added route"),
        a.count("nos-ribd starting"),
    );
    log("killing router-a's nos-ribd; the watchdog restarts it with a fresh identity");
    w.dock
        .kill_process("router-a", "nos-ribd")
        .await
        .context("killing nos-ribd")?;
    a.wait_new("nos-ribd starting", ribds, 30).await?;
    // The revocation reaches the children as a CRL-carrying frame, and the
    // rotations after it go back to empty frames (#858).
    a.wait_new(PUSHED_CRL, pushed, 30).await?;
    a.wait_new("ipc crl updated entries=", updates, 30).await?;
    a.wait_new(PUSHED_EMPTY, empty, PKI_ROTATE_EVERY_SECS * 3)
        .await?;

    // Router-a's long-lived nos-bgpd sees the old socket close, reconnects to
    // the new nos-ribd with its rotated identity, and the route lands in the
    // kernel — the whole path, on rotated identities.
    let a = w.a()?;
    a.wait_new(snapshot, snapshots, 60).await?;
    a.wait_new("added route", kernel_routes, 60).await?;
    ipc_session_cap_end(w, logged_in).await
}

/// Where the cap check keeps the shell user's certificate.
const CAPPED_CERT: &str = "/tmp/capped-user.identity";
const CAP_REFUSED: &str = "renewal refused, ipc certificate unknown or past the session cap";

/// #637: log in, and renew inside the cap (the renewed certificate inherits
/// the login time).
async fn ipc_session_cap_start(w: &World) -> anyhow::Result<()> {
    let (code, out) = run_provision(
        w,
        &[
            "--login-user",
            E2E_USER,
            "--login-password",
            E2E_PASSWORD,
            "--pki-cert-out",
            CAPPED_CERT,
        ],
    )
    .await?;
    if code != 0 {
        bail!("login for the session-cap check failed: exit {code}: {out}");
    }
    let (code, out) = run_provision(w, &["--pki-cert-in", CAPPED_CERT, "--renew-probe"]).await?;
    if code != 0 || !out.contains("renewed") {
        bail!("a renewal inside the session cap was refused: exit {code}: {out}");
    }
    Ok(())
}

/// #637: once the cap since the login has passed, renewing the (already
/// renewed) certificate is refused, and a fresh login starts a new session.
async fn ipc_session_cap_end(w: &World, logged_in: std::time::Instant) -> anyhow::Result<()> {
    let cap = std::time::Duration::from_secs(PKI_IPC_SESSION_MAX_SECS + 2);
    if let Some(left) = cap.checked_sub(logged_in.elapsed()) {
        tokio::time::sleep(left).await;
    }
    let a = w.a()?;
    let refused = a.count(CAP_REFUSED);
    let (code, out) = run_provision(w, &["--pki-cert-in", CAPPED_CERT, "--renew-probe"]).await?;
    if code == 0 || !out.contains("renew refused") {
        bail!("a renewal past the IPC session cap must be refused, got exit {code}: {out}");
    }
    a.wait_new(CAP_REFUSED, refused, 15).await?;
    let (code, out) = provision_as(w, E2E_PASSWORD).await?;
    if code != 0 {
        bail!("a fresh login after the cap must work: exit {code}: {out}");
    }
    Ok(())
}

/// A throwaway user for `pki_crl` (router-a only).
const CRL_USER: &str = "crl-user";
/// Logins `pki_crl` makes: 12% above the ~26.4k serials that filled the old
/// 1 MiB identity frame (~39 bytes per CRL entry), so the CRL is ~1.17 MB.
const CRL_BURST: usize = 30_000;
/// The burst is one `docker exec` with no per-wait deadline; argon2id (two at
/// a time in the broker) makes it 20-40 minutes.
const CRL_BURST_DEADLINE_SECS: u64 = 45 * 60;

/// #677: a CRL bigger than the old 1 MiB frame cap still reaches every daemon.
/// 30,000 logins of one user, then a password change revokes all of them in
/// one CRL; every child must apply it and keep reading its identity pipe
/// (before the fix the first oversize frame silently ended rotation).
pub async fn pki_crl(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.provision(&["--user", &format!("{CRL_USER}=first-password")])
        .await?;
    let revoked = format!("certificates revoked role=user name={CRL_USER} serials={CRL_BURST}");
    let updated = "ipc crl updated entries=3[0-9][0-9][0-9][0-9]";
    let (revocations, updates, broken) = (
        a.count(&revoked),
        a.count(updated),
        a.count("identity pipe broke"),
    );

    log(format!("{CRL_BURST} logins as {CRL_USER} (slow: argon2id)"));
    let started = std::time::Instant::now();
    let count = CRL_BURST.to_string();
    let auth = [
        "--login-user",
        CRL_USER,
        "--login-password",
        "first-password",
        "--login-burst",
        &count,
    ];
    let (code, out) = tokio::time::timeout(
        std::time::Duration::from_secs(CRL_BURST_DEADLINE_SECS),
        run_provision(w, &auth),
    )
    .await
    .context("the login burst did not finish in time")??;
    log(format!("burst took {}s", started.elapsed().as_secs()));
    if code != 0 {
        let tail: String = out.lines().rev().take(10).collect::<Vec<_>>().join("\n");
        bail!("login burst failed: exit {code}: {tail}");
    }

    log("changing the password revokes every one of those certificates in one CRL");
    let a = w.a()?;
    a.provision(&["--user", &format!("{CRL_USER}=second-password")])
        .await?;
    a.wait_new(&revoked, revocations, 120).await?;
    a.wait_new(updated, updates, 120).await?;
    a.assert_quiet("identity pipe broke", broken, 60).await?;
    a.established().await?;
    let (status, _) = a.rest(Method::GET, "/v1/config", None).await?;
    if status != 200 {
        bail!("REST read after the large CRL answered {status}");
    }

    a.edit(|config| {
        config.users.retain(|u| u.name != CRL_USER);
        Ok(())
    })
    .await?;
    Ok(())
}
