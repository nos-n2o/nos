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
use base64::Engine as _;
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

    login_policy(w).await?;
    revoke_user(w).await?;
    user_roles(w).await?;
    revoke_restarted_daemon(w).await
}

/// Starts the RADIUS stub with `users` (`name:password:role`), points `aaa` at it with
/// `login-order radius local` and accounting on. `radius_down` undoes the config.
pub(super) async fn radius_up(w: &World, users: &[&str]) -> anyhow::Result<()> {
    let mut args = vec!["nos-radius-stub", "--secret", RADIUS_SECRET];
    for u in users {
        args.extend(["--user", u]);
    }
    w.dock
        .start_nos_tool(RADIUS_STUB, NET, IP_RADIUS_STUB.s(), &args, &[])
        .await?;
    log("login-order radius local, one server");
    w.a()?
        .edit(|c| {
            c.admin.keys.push(nos_proto::AdminKey {
                label: "radius".into(),
                secret: RADIUS_SECRET.into(),
            });
            c.aaa.servers = vec![nos_proto::RadiusServer {
                name: "stub".into(),
                address: IP_RADIUS_STUB.s().parse()?,
                port: None,
                accounting_port: Some(1812),
                routing_table: Some("rt1".into()),
                secret_ref: "radius".into(),
                timeout_secs: Some(1),
                retries: Some(0),
            }];
            c.aaa.accounting = true;
            c.aaa.login_order = vec![
                nos_proto::LoginBackend::Radius,
                nos_proto::LoginBackend::Local,
            ];
            Ok(())
        })
        .await
        .map(drop)
}

/// Removes the stub container and the `aaa` config `radius_up` added.
pub(super) async fn radius_down(w: &World) -> anyhow::Result<()> {
    w.dock.container_remove(RADIUS_STUB).await;
    w.dock.container_remove(TACACS_STUB).await;
    w.a()?
        .edit(|c| {
            c.aaa = nos_proto::Aaa::default();
            c.admin
                .keys
                .retain(|k| k.label != "radius" && k.label != "tacacs");
            Ok(())
        })
        .await
        .map(drop)
}

/// #1153: RADIUS login. A scripted server (`nos-radius-stub`) knows an admin
/// and a read-only user; `login-order radius local` makes the watchdog ask it
/// first. Checks the role carried in the certificate (admin edits, read-only
/// is refused), that a reject never falls back to the local user of the same
/// name, and that a silent server does.
pub async fn aaa(w: &mut World) -> anyhow::Result<()> {
    radius_up(
        w,
        &[
            "rad-admin:pw-admin:admin",
            "rad-ro:pw-ro:read-only",
            "rad-ext:pw-ext:read-only",
            "Rad-Upper:pw-up:read-only",
        ],
    )
    .await?;
    let a = w.a()?;

    log("a RADIUS admin (no local entry) provisions the router");
    let accepted = a.count("login accepted by radius user=\"rad-admin\" role=\"admin\"");
    let (code, out) = run_provision(
        w,
        &["--login-user", "rad-admin", "--login-password", "pw-admin"],
    )
    .await?;
    if code != 0 || !out.contains("provisioning complete") {
        bail!("a RADIUS admin should provision, got exit {code}: {out}");
    }
    a.wait_new(
        "login accepted by radius user=\"rad-admin\" role=\"admin\"",
        accepted,
        15,
    )
    .await?;

    log("accounting: a Start for the login and an Interim-Update for its commit reach the server");
    for needle in [
        "accounting status=1 user=rad-admin",
        "accounting status=3 user=rad-admin session=commit:",
    ] {
        let mut seen = false;
        for _ in 0..15 {
            if w.dock.logs(RADIUS_STUB).await?.contains(needle) {
                seen = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        if !seen {
            bail!("the RADIUS stub never saw '{needle}'");
        }
    }

    log("a RADIUS read-only user logs in but its role refuses the edits");
    let refused = a.count("the user's role does not allow it");
    let (code, _) =
        run_provision(w, &["--login-user", "rad-ro", "--login-password", "pw-ro"]).await?;
    if code == 0 {
        bail!("a read-only RADIUS user must not be able to provision");
    }
    a.wait_new("the user's role does not allow it", refused, 15)
        .await?;

    log("a RADIUS reject never falls back to a local user with that password");
    let rejected = a.count(&format!("radius login rejected user=\"{E2E_USER}\""));
    let (code, out) = provision_as(w, E2E_PASSWORD).await?;
    if code == 0 || !out.contains("login refused") {
        bail!("a RADIUS reject must end the login, got exit {code}: {out}");
    }
    a.wait_new(
        &format!("radius login rejected user=\"{E2E_USER}\""),
        rejected,
        15,
    )
    .await?;

    log("#1360: REST logins honour login-order: rad-admin over REST, same RADIUS role");
    rest_radius(w).await?;

    log("#1376: a RADIUS accept allocates the ssh account, a reject or unsafe name none");
    external_users(w).await?;

    log("with the server gone the local user logs in");
    w.dock.container_remove(RADIUS_STUB).await;
    let silent = a.count("no radius server answered");
    let (code, out) = provision_as(w, E2E_PASSWORD).await?;
    if code != 0 || !out.contains("provisioning complete") {
        bail!("a silent RADIUS server must fall back to local, got exit {code}: {out}");
    }
    a.wait_new("no radius server answered", silent, 15).await?;

    log("#1155: TACACS+ login, authorization and accounting");
    tacacs(w).await?;

    log("back to local-only login");
    a.edit(|c| {
        c.aaa = nos_proto::Aaa::default();
        c.admin
            .keys
            .retain(|k| k.label != "radius" && k.label != "tacacs");
        Ok(())
    })
    .await?;
    let (code, out) = provision_as(w, E2E_PASSWORD).await?;
    if code != 0 {
        bail!("local login after removing aaa failed: {code}: {out}");
    }
    Ok(())
}

/// #1155: `login-order tacacs local` against `nos-tacacs-stub` (through the
/// VRF of `rt1`): PAP login, `role` AV pair in the certificate, START/STOP
/// accounting, and a reject that never falls back to the local user.
async fn tacacs(w: &World) -> anyhow::Result<()> {
    w.dock
        .start_nos_tool(
            TACACS_STUB,
            NET,
            IP_TACACS_STUB.s(),
            &[
                "nos-tacacs-stub",
                "--listen",
                &format!("0.0.0.0:{TACACS_PORT}"),
                "--key",
                TACACS_KEY,
                "--user",
                "tac-admin:pw-admin:admin",
                "--user",
                "tac-ro:pw-ro:read-only",
            ],
            &[],
        )
        .await?;
    let a = w.a()?;
    a.edit(|c| {
        c.aaa = nos_proto::Aaa::default();
        c.admin.keys.push(nos_proto::AdminKey {
            label: "tacacs".into(),
            secret: TACACS_KEY.into(),
        });
        c.aaa.tacacs_servers = vec![nos_proto::TacacsServer {
            name: "stub".into(),
            address: IP_TACACS_STUB.s().parse()?,
            port: Some(TACACS_PORT),
            routing_table: Some("rt1".into()),
            key_ref: "tacacs".into(),
            timeout_secs: Some(2),
            ..Default::default()
        }];
        c.aaa.accounting = true;
        c.aaa.login_order = vec![
            nos_proto::LoginBackend::Tacacs,
            nos_proto::LoginBackend::Local,
        ];
        Ok(())
    })
    .await?;

    log("a TACACS+ admin (no local entry) provisions the router");
    let needle = "login accepted by tacacs user=\"tac-admin\" role=\"admin\"";
    let accepted = a.count(needle);
    let (code, out) = run_provision(
        w,
        &["--login-user", "tac-admin", "--login-password", "pw-admin"],
    )
    .await?;
    if code != 0 || !out.contains("provisioning complete") {
        bail!("a TACACS+ admin should provision, got exit {code}: {out}");
    }
    a.wait_new(needle, accepted, 15).await?;

    log("the server saw the authorization and the START and commit records");
    for needle in [
        "authen pass user=tac-admin",
        "author pass user=tac-admin role=admin",
        "accounting flags=2 user=tac-admin",
        "accounting flags=4 user=tac-admin service=nos task_id=commit:",
    ] {
        let mut seen = false;
        for _ in 0..15 {
            if w.dock.logs(TACACS_STUB).await?.contains(needle) {
                seen = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        if !seen {
            bail!("the TACACS+ stub never saw '{needle}'");
        }
    }

    log("a TACACS+ read-only user logs in but its role refuses the edits");
    let refused = a.count("the user's role does not allow it");
    let (code, _) =
        run_provision(w, &["--login-user", "tac-ro", "--login-password", "pw-ro"]).await?;
    if code == 0 {
        bail!("a read-only TACACS+ user must not be able to provision");
    }
    a.wait_new("the user's role does not allow it", refused, 15)
        .await?;

    log("a TACACS+ reject never falls back to a local user with that password");
    let rejected = format!("tacacs login rejected user=\"{E2E_USER}\"");
    let before = a.count(&rejected);
    let (code, out) = provision_as(w, E2E_PASSWORD).await?;
    if code == 0 || !out.contains("login refused") {
        bail!("a TACACS+ reject must end the login, got exit {code}: {out}");
    }
    a.wait_new(&rejected, before, 15).await?;

    tacacs_ascii_single_connect(w).await?;
    w.dock.container_remove(TACACS_STUB).await;
    Ok(())
}

/// Occurrences of `needle` in the stub's log.
async fn stub_count(w: &World, needle: &str) -> anyhow::Result<usize> {
    Ok(w.dock.logs(TACACS_STUB).await?.matches(needle).count())
}

/// Authentication, authorization and accounting sessions the stub has served.
fn stub_sessions(logs: &str) -> usize {
    [
        "tacacs-stub: authen pass",
        "tacacs-stub: author",
        "tacacs-stub: accounting",
    ]
    .iter()
    .map(|n| logs.matches(n).count())
    .sum()
}

/// #1155: the same server switched to ASCII authentication and single-connect:
/// the login is prompted (GETPASS, CONTINUE) and the exchanges of a whole
/// provisioning run (authentication, authorization, accounting) share fewer
/// TCP connections than sessions.
async fn tacacs_ascii_single_connect(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.edit(|c| {
        let s = &mut c.aaa.tacacs_servers[0];
        s.authentication = nos_proto::TacacsAuthentication::Ascii;
        s.single_connect = true;
        Ok(())
    })
    .await?;
    log("ASCII login over single-connect: prompted, and sessions share connections");
    let opened = stub_count(w, "connection opened").await?;
    let before = stub_sessions(&w.dock.logs(TACACS_STUB).await?);
    let prompts = stub_count(w, "authen getpass").await?;
    let needle = "login accepted by tacacs user=\"tac-admin\" role=\"admin\"";
    let accepted = a.count(needle);
    let (code, out) = run_provision(
        w,
        &["--login-user", "tac-admin", "--login-password", "pw-admin"],
    )
    .await?;
    if code != 0 || !out.contains("provisioning complete") {
        bail!("an ASCII TACACS+ admin should provision, got exit {code}: {out}");
    }
    a.wait_new(needle, accepted, 15).await?;
    // The commit and START records are sent by a worker: let them land.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    if stub_count(w, "authen pass user=tac-admin type=ascii").await? == 0 {
        bail!("the stub never saw an ASCII authentication");
    }
    if stub_count(w, "authen getpass").await? <= prompts {
        bail!("the ASCII login was never prompted for a password");
    }
    let logs = w.dock.logs(TACACS_STUB).await?;
    let sessions = stub_sessions(&logs) - before;
    let conns = logs.matches("connection opened").count() - opened;
    log(format!("{sessions} sessions over {conns} connection(s)"));
    if sessions < 3 || conns >= sessions {
        bail!("single-connect should share connections: {sessions} sessions, {conns} connections");
    }
    Ok(())
}

/// #1376: allocation at the first RADIUS accept, and the PAM ticket path for a RADIUS user.
async fn external_users(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    let getent = |name: &'static str| async move {
        w.dock.exec("router-a", &["getent", "passwd", name]).await
    };
    let uid_of = |out: &str| -> anyhow::Result<u32> {
        let uid: u32 = out
            .trim()
            .split(':')
            .nth(2)
            .context("no uid field")?
            .parse()?;
        if !(20_000..=59_999).contains(&uid) {
            bail!("uid {uid} outside 20000-59999");
        }
        Ok(uid)
    };
    if getent("rad-ext").await?.0 == 0 {
        bail!("rad-ext resolves before any login");
    }
    let n = a.count("external user allocated user=\"rad-ext\"");
    if a.rest.login("rad-ext", "pw-ext").await?.is_err() {
        bail!("rad-ext could not log in over REST");
    }
    a.wait_new("external user allocated user=\"rad-ext\"", n, 15)
        .await?;
    let (code, out) = getent("rad-ext").await?;
    if code != 0 {
        bail!("getent passwd rad-ext failed after the accept: {out}");
    }
    let uid = uid_of(&out)?;

    log("a second login keeps the uid");
    if a.rest.login("rad-ext", "pw-ext").await?.is_err() {
        bail!("rad-ext second login failed");
    }
    let (_, out) = getent("rad-ext").await?;
    if uid_of(&out)? != uid {
        bail!("uid changed across logins: {uid} -> {out}");
    }

    log("a rejected user and an unsafe name allocate nothing");
    let allocs = a.count("external user allocated");
    if a.rest.login("rad-ext", "wrong").await?.is_ok() {
        bail!("a wrong RADIUS password logged in");
    }
    let accepted = a.count("login accepted by radius user=\"Rad-Upper\"");
    if a.rest.login("Rad-Upper", "pw-up").await?.is_err() {
        bail!("an unsafe name is still a valid RADIUS login over REST");
    }
    a.wait_new("login accepted by radius user=\"Rad-Upper\"", accepted, 15)
        .await?;
    a.assert_quiet("external user allocated", allocs, 3).await?;
    if getent("Rad-Upper").await?.0 == 0 {
        bail!("an unsafe name got a passwd entry");
    }

    log("pamtester: the allocated RADIUS user gets a login ticket");
    let n = a.count("login ticket issued user=\"rad-ext\"");
    let (code, out) =
        super::pam::pamtester(w, PAM_SERVICE, "rad-ext", "pw-ext", "authenticate").await?;
    if code != 0 {
        bail!("rad-ext must authenticate through pam, got exit {code}: {out}");
    }
    a.wait_new("login ticket issued user=\"rad-ext\"", n, 15)
        .await
}

/// #1360: the REST half of `aaa`. An admin with no local entry logs in over
/// REST (`POST /v1/login` through the watchdog's `login-order`), edits and
/// commits as that user; a read-only one is refused by its role; a renewal
/// keeps the role (taken from the session, not the client); a RADIUS reject of
/// a local user's name never falls back. Accounting (#1361): the REST login
/// puts its own Start and its commit an Interim-Update in the stub's log, and
/// a reject sends nothing.
async fn rest_radius(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    let starts = |logs: &str| logs.matches("accounting status=1 user=rad-admin").count();
    let starts_before = starts(&w.dock.logs(RADIUS_STUB).await?);
    let accepted = a.count("login accepted by radius user=\"rad-admin\" role=\"admin\"");
    let Ok(admin) = a.rest.login("rad-admin", "pw-admin").await? else {
        bail!("rad-admin could not log in over REST");
    };
    a.wait_new(
        "login accepted by radius user=\"rad-admin\" role=\"admin\"",
        accepted,
        15,
    )
    .await?;
    let client = a.rest.with_identity(&admin)?;
    let tx = "/v1/transactions/rad-rest";
    let open = format!("{tx}?base=current");
    let host = format!("{tx}/hostname");
    let (s, _) = a.rest_with(&client, Method::POST, &open, None).await?;
    let (put, _) = a
        .rest_with(&client, Method::PUT, &host, Some("\"rad-e2e\""))
        .await?;
    let (commit, _) = a
        .rest_with(&client, Method::POST, &format!("{tx}/commit"), None)
        .await?;
    if (s, put, commit) != (201, 200, 200) {
        bail!("rad-admin over REST: open {s}, edit {put}, commit {commit}, want 201/200/200");
    }
    log("accounting: the REST login has its own Start, its commit an Interim-Update");
    let interim = "accounting status=3 user=rad-admin session=commit:rad-rest";
    for _ in 0..15 {
        let logs = w.dock.logs(RADIUS_STUB).await?;
        if starts(&logs) > starts_before && logs.contains(interim) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let logs = w.dock.logs(RADIUS_STUB).await?;
    if starts(&logs) <= starts_before || !logs.contains(interim) {
        bail!("the stub saw no REST Start/Interim-Update for rad-admin");
    }
    a.wait("rest request user=\"rad-admin\"").await?;
    a.wait("config commit audit transaction=\"rad-rest\" actor=\"rad-admin\" claim=Some(Admin)")
        .await?;

    log("a renewal keeps the claimed role");
    let (csr, key) = nos_pki::generate_csr_for(nos_pki::KeyAlg::EcdsaP256)?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let resp = client
        .post(format!("{}/v1/renew", a.rest.base()))
        .json(&serde_json::json!({ "csr": b64.encode(csr) }))
        .send()
        .await?;
    if resp.status() != 200 {
        bail!("renewal of a RADIUS REST session -> {}", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    let cert = b64.decode(body["certificate"].as_str().context("no certificate")?)?;
    let renewed = a
        .rest
        .with_identity(&crate::rest::Identity::new(cert, key))?;
    let (s, _) = a.rest_with(&renewed, Method::POST, &open, None).await?;
    let (put, _) = a
        .rest_with(&renewed, Method::PUT, &host, Some("\"rad-e2e2\""))
        .await?;
    let _ = a.rest(Method::DELETE, tx, None).await;
    if (s, put) != (201, 200) {
        bail!("renewed rad-admin: open {s}, edit {put}, want 201/200");
    }

    log("a RADIUS read-only user over REST reads but its role refuses the edit");
    let refused = a.count("the user's role does not allow it");
    let Ok(ro) = a.rest.login("rad-ro", "pw-ro").await? else {
        bail!("rad-ro could not log in over REST");
    };
    let client = a.rest.with_identity(&ro)?;
    let (get, _) = a
        .rest_with(&client, Method::GET, "/v1/config", None)
        .await?;
    let (opened, _) = a.rest_with(&client, Method::POST, &open, None).await?;
    let (put, _) = a
        .rest_with(&client, Method::PUT, &host, Some("\"x\""))
        .await?;
    let _ = a.rest(Method::DELETE, tx, None).await;
    if get != 200 || put != 403 {
        bail!("rad-ro over REST: read {get} (want 200), open {opened}, edit {put} (want 403)");
    }
    a.wait_new("the user's role does not allow it", refused, 15)
        .await?;

    log("a RADIUS reject of the local user's name over REST never falls back");
    if a.rest.login(E2E_USER, E2E_PASSWORD).await?.err() != Some(401) {
        bail!("a RADIUS reject over REST must end the login with 401");
    }
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    if (w.dock.logs(RADIUS_STUB).await?).contains(&format!("accounting status=1 user={E2E_USER}")) {
        bail!("a rejected REST login must not be accounted");
    }
    Ok(())
}

/// #1148: `login-policy max-failures 2` is applied live by `nos-restd` and
/// `nos-watchdogd` (both log it), two bad logins then lock a user out (429,
/// `login lockout started`), and restoring the defaults is applied too.
async fn login_policy(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    let set = |max: u8, window: u32| {
        move |c: &mut nos_proto::Config| {
            c.login_policy.max_failures = max;
            c.login_policy.lockout_window_secs = window;
            Ok(())
        }
    };
    log("login-policy max-failures 2 is applied live by nos-restd and nos-watchdogd");
    let (rest, broker) = (
        a.count("login policy applied max_failures=2 window_secs=30"),
        a.count("broker login policy applied max_failures=2"),
    );
    a.edit(set(2, 30)).await?;
    a.wait_new(
        "login policy applied max_failures=2 window_secs=30",
        rest,
        30,
    )
    .await?;
    a.wait_new("broker login policy applied max_failures=2", broker, 30)
        .await?;

    log("two failed logins lock the user out");
    let locked = a.count("login lockout started user=\"lockme\"");
    for _ in 0..2 {
        if a.rest.login("lockme", "wrong").await?.err() != Some(401) {
            bail!("a bad login must be answered 401");
        }
    }
    if a.rest.login("lockme", "wrong").await?.err() != Some(429) {
        bail!("the third login after max-failures 2 must be answered 429");
    }
    a.wait_new("login lockout started user=\"lockme\"", locked, 10)
        .await?;

    log("restoring the default policy");
    let rest = a.count("login policy applied max_failures=5 window_secs=60");
    a.edit(set(5, 60)).await?;
    a.wait_new(
        "login policy applied max_failures=5 window_secs=60",
        rest,
        30,
    )
    .await
}

/// The watchdog (the CA) runs on its own uid and every role on its own
/// (#512, #513): the `starting` lines carry the ids, `/proc` agrees, and a
/// daemon cannot unlink another's 0660 `group nos` socket in the sticky
/// `/run/nos`.
async fn check_uids(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    a.wait("starting process=nos-configd program=/usr/local/bin/nos-configd .*uid=10001 gid=991")
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

/// #1147: `User.role` is enforced by `nos-configd` per request. A read-only
/// and an operator user read the config but get 403 on every edit and on
/// `save`; after promoting the user, a fresh login edits.
async fn user_roles(w: &World) -> anyhow::Result<()> {
    use nos_proto::UserRole;
    let a = w.a()?;
    let users = [
        ("ro-user", UserRole::ReadOnly),
        ("op-user", UserRole::Operator),
    ];
    for (name, role) in users {
        a.provision(&["--user", &format!("{name}=role-password")])
            .await?;
        a.edit(|config| {
            let u = config.users.iter_mut().find(|u| u.name == name);
            u.context("user was not created")?.role = role;
            Ok(())
        })
        .await?;
    }
    let mut clients = Vec::new();
    for (name, _) in users {
        let Ok(id) = a.rest.login(name, "role-password").await? else {
            bail!("{name} could not log in over REST");
        };
        clients.push((name, a.rest.with_identity(&id)?));
    }
    for (name, client) in &clients {
        log(format!(
            "{name} reads the config but cannot edit or save it"
        ));
        let get = |m: Method, path: &'static str, body: Option<&'static str>| {
            let client = client.clone();
            async move { a.rest_with(&client, m, path, body).await.map(|(s, _)| s) }
        };
        let tx = "/v1/transactions/roles";
        if get(Method::GET, "/v1/config", None).await? != 200 {
            bail!("{name} should read the config");
        }
        if get(Method::POST, "/v1/transactions/roles?base=current", None).await? != 201 {
            bail!("{name} may open a transaction");
        }
        let put = get(
            Method::PUT,
            "/v1/transactions/roles/hostname",
            Some("\"x\""),
        )
        .await?;
        let save = get(Method::POST, "/v1/config/save", None).await?;
        let _ = a.rest(Method::DELETE, tx, None).await;
        if put != 403 || save != 403 {
            bail!("{name}: edit -> {put}, save -> {save}, both should be 403");
        }
    }

    log(
        "promoting a user revokes its old certificate (the user record changed); a new login edits",
    );
    a.edit(|config| {
        let u = config.users.iter_mut().find(|u| u.name == "ro-user");
        u.context("ro-user vanished")?.role = UserRole::Admin;
        Ok(())
    })
    .await?;
    let Ok(id) = a.rest.login("ro-user", "role-password").await? else {
        bail!("ro-user could not log in again");
    };
    let client = &a.rest.with_identity(&id)?;
    let (s, _) = a
        .rest_with(
            client,
            Method::POST,
            "/v1/transactions/roles?base=current",
            None,
        )
        .await?;
    let (put, _) = a
        .rest_with(
            client,
            Method::PUT,
            "/v1/transactions/roles/hostname",
            Some("\"x\""),
        )
        .await?;
    let _ = a.rest(Method::DELETE, "/v1/transactions/roles", None).await;
    if s != 201 || put == 403 {
        bail!("a promoted user is still refused (open {s}, edit {put})");
    }
    a.edit(|config| {
        config
            .users
            .retain(|u| u.name != "ro-user" && u.name != "op-user");
        Ok(())
    })
    .await?;
    Ok(())
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
    let a = w.a()?;
    let learned_before = a.count(&bgp::learned());
    w.b()?.provision(&bgp::redistribute()).await?;
    a.wait_new(&bgp::learned(), learned_before, 60).await?;
    let revoked = "certificates revoked role=ribd name=rt1 ";
    let snapshot = "sent initial bgp route snapshot to nos-ribd";
    let (revocations, updates, ribds, snapshots, released, removed) = (
        a.count(revoked),
        a.count("ipc crl updated entries="),
        a.count("nos-ribd starting"),
        a.count(snapshot),
        a.count(HOLD_RELEASED),
        a.count("removed route"),
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
    // connection, reconnects and re-sends its snapshot; the startup hold
    // (#654) kept the kernel route, so nothing is re-added, and the hold is
    // released once the producer has re-pushed.
    a.wait_new(snapshot, snapshots, 30).await?;
    a.wait_new(HOLD_RELEASED, released, 30).await?;
    a.assert_quiet("removed route", removed, 3).await?;
    // nos-restd (holding the new CRL) dials the new nos-ribd: still trusted.
    // nos-restd lives in rt1's VRF, which the new nos-ribd recreates: its
    // listener may take a moment to come back, so a refused connect is retried.
    for _ in 0..60 {
        if matches!(
            a.rest(Method::GET, "/v1/routes/rt1", None).await,
            Ok((200, body)) if body.contains(crate::consts::REDISTRIBUTE_PREFIX)
        ) {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    bail!("the restarted nos-ribd never answered a route query")
}

/// #654: a restarted nos-ribd keeps the kernel routes until producers re-push.
const HOLD_RELEASED: &str = "startup hold released table=rt1 reason=\"all sources re-pushed\"";

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
    ipc_session_cap_end(w, logged_in).await?;

    // nos-bgpd is long-lived, so its handshake with the *restarted* nos-ribd
    // uses whatever certificate it holds now — which is only valid if the
    // rotation reached it. Router-b advertises a prefix to router-a first;
    // after the kill nos-bgpd notices the closed push connection by itself.
    // #839: `wait` (baseline 0) matched the earlier `pki` phase's learn of the
    // same prefix, so the kill raced the real learn; take a baseline first.
    let learned_before = w.a()?.count(&bgp::learned());
    w.b()?.provision(&bgp::redistribute()).await?;
    w.a()?.wait_new(&bgp::learned(), learned_before, 60).await?;
    let a = w.a()?;
    let snapshot = "sent initial bgp route snapshot to nos-ribd";
    let (pushed, empty, updates) = (
        a.count(PUSHED_CRL),
        a.count(PUSHED_EMPTY),
        a.count("ipc crl updated entries="),
    );
    let (snapshots, released, removed, ribds) = (
        a.count(snapshot),
        a.count(HOLD_RELEASED),
        a.count("removed route"),
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
    // kernel (kept by the startup hold, released on the re-push) — the whole
    // path, on rotated identities.
    let a = w.a()?;
    a.wait_new(snapshot, snapshots, 60).await?;
    a.wait_new(HOLD_RELEASED, released, 60).await?;
    a.assert_quiet("removed route", removed, 3).await
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
