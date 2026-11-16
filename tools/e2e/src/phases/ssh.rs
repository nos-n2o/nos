//! `nos-sshd`'s host key as a config secret (#1104): generated at first start, kept in the
//! admin keystore under `ssh-host-key`, stable across a daemon restart, hidden from REST and
//! logs, regenerated when the label is deleted, same after Save + a full container restart.
//! Also the VRF-only `ssh` phase (#1002).

use anyhow::{bail, Context};
use nos_proto::SSH_HOST_KEY_LABEL;
use reqwest::Method;

use crate::consts::*;
use crate::router::{log, strings};
use crate::sshc::Ssh;
use crate::world::World;

const FP: &str = "host key fingerprint=SHA256:";

fn fingerprint(a: &crate::router::Router) -> anyhow::Result<String> {
    let line = a.logs.last(FP).context("no host key fingerprint line")?;
    Ok(line[line.find("SHA256:").context("no SHA256")?..].to_string())
}

/// Needs `up`; leaves `ssh-server` cleared again (the key stays in the keystore). Restarts
/// router-a, so BGP is re-established before it returns.
pub async fn ssh_hostkey(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;

    log("ssh-hostkey: first start generates the key");
    let before = a.count(FP);
    a.provision(&[
        "--ssh-server-address",
        IP_A.s(),
        "--ssh-server-port",
        "2222",
    ])
    .await?;
    a.wait_new(FP, before, 60).await?;
    a.wait("ssh listening").await?;
    let f1 = fingerprint(a)?;

    log("ssh-hostkey: hidden from REST and logs");
    let config = a.rest_expect(Method::GET, "/v1/config", None, 200).await?;
    let json: serde_json::Value = serde_json::from_str(&config)?;
    let key = json["admin"]["keys"]
        .as_array()
        .and_then(|ks| ks.iter().find(|e| e["label"] == SSH_HOST_KEY_LABEL))
        .context("ssh-host-key missing from the config")?;
    if key["secret"] != "<hidden>" || config.contains("OPENSSH") {
        bail!("ssh-host-key must be masked over REST: {key}");
    }
    if a.count("OPENSSH PRIVATE") != 0 {
        bail!("a private key reached the logs");
    }

    log("ssh-hostkey: a respawned nos-sshd keeps the key");
    let before = a.count(FP);
    w.dock.kill_process("router-a", "nos-sshd").await?;
    a.wait_new(FP, before, 60).await?;
    let now = fingerprint(a)?;
    if now != f1 {
        bail!("host key changed across a restart: {f1} -> {now}");
    }

    log("ssh-hostkey: Save + a full container restart keeps the key");
    a.rest_expect(Method::POST, "/v1/config/save", None, 204)
        .await?;
    w.restart(crate::router::A).await?;
    // A fresh log follower; `nos-logd`'s buffer may or may not have survived, so the log alone
    // cannot say the line is new: the listener must be back as well (a new `nos-sshd`).
    let a = w.a()?;
    a.wait_new(FP, 0, 90).await?;
    let mut up = false;
    for _ in 0..60 {
        let (_, t4) = w.dock.exec("router-a", &["cat", "/proc/net/tcp"]).await?;
        if listeners(&t4).iter().any(|(_, p)| *p == SSH_PORT) {
            up = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if !up {
        bail!("nos-sshd did not listen again after the container restart");
    }
    let now = fingerprint(a)?;
    if now != f1 {
        bail!("host key changed across a container restart: {f1} -> {now}");
    }
    a.established().await?;

    log("ssh-hostkey: deleting the label regenerates it");
    let before = a.count(FP);
    a.edit(|cfg| {
        cfg.admin.keys.retain(|key| key.label != SSH_HOST_KEY_LABEL);
        Ok(())
    })
    .await?;
    a.wait_new(FP, before, 60).await?;
    let f2 = fingerprint(a)?;
    if f2 == f1 {
        bail!("host key was not regenerated after the label was deleted");
    }

    a.provision(&strings(&["--clear-ssh-server"])).await?;
    a.established().await?;
    Ok(())
}

/// The user the `ssh-login-shell` phase creates (and deletes) over REST.
const LOGIN_USER: &str = "ssh-bob";
const LOGIN_PASSWORD: &str = "ssh-bob-pw";
const LOGIN_TX: &str = "ssh-login-user";
const SSH_PORT: u16 = 2222;

async fn login_user(a: &crate::router::Router, create: bool) -> anyhow::Result<()> {
    let tx = format!("/v1/transactions/{LOGIN_TX}");
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    let body = format!(r#"{{"name":"{LOGIN_USER}","password":"{LOGIN_PASSWORD}"}}"#);
    let path = format!("{tx}/user/{LOGIN_USER}");
    if create {
        a.rest_expect(Method::PUT, &path, Some(&body), 200).await?;
    } else {
        a.rest_expect(Method::DELETE, &path, None, 204).await?;
    }
    a.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
        .await?;
    Ok(())
}

/// The live login shell's pid and the owner's numeric uid.
async fn live_shell(w: &World) -> anyhow::Result<(String, String)> {
    let script = r#"for p in /proc/[0-9]*; do
  case "$(tr '\0' ' ' < $p/cmdline 2>/dev/null)" in -nos*) echo ${p#/proc/} ;; esac
done"#;
    let (_, out) = w.dock.exec_root("router-a", &["sh", "-c", script]).await?;
    let pid = out
        .lines()
        .next()
        .context("no -nos login shell")?
        .to_string();
    let (_, passwd) = w
        .dock
        .exec("router-a", &["getent", "passwd", LOGIN_USER])
        .await?;
    let uid = passwd.split(':').nth(2).context("getent uid")?.to_string();
    Ok((pid, uid))
}

/// SSH password login lands in `nos` through `pam_nos` + the NSS shell (#992): no `login:`
/// prompt, ticket issued and redeemed once, a config commit attributed to the user, `ssh host
/// cmd` refused, a replayed ticket refused, a deleted user cut off, bad logins rejected.
/// Needs `up`; leaves `ssh-server` cleared.
pub async fn ssh_login_shell(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let ip = IP_A.s();
    let user_line = |verb: &str| format!("login ticket {verb} user=\"{LOGIN_USER}\"");

    a.provision(&[
        "--ssh-server-address",
        ip,
        "--ssh-server-port",
        &SSH_PORT.to_string(),
    ])
    .await?;
    a.wait("ssh listening").await?;
    login_user(a, true).await?;

    log("ssh-login-shell: password login lands in nos, no login prompt");
    let (issued, redeemed) = (
        a.count(&user_line("issued")),
        a.count(&user_line("redeemed")),
    );
    let ssh = Ssh::password(ip, SSH_PORT, LOGIN_USER, LOGIN_PASSWORD)
        .await?
        .context("the right password must log in over SSH")?;
    let mut sh = ssh.shell().await?;
    sh.expect("NOS interactive shell", 30).await?;
    // Keystrokes sent before the prompt exists are eaten by the line editor's cursor query.
    sh.expect("> ", 30).await?;
    if sh.text().contains("login:") || sh.text().contains("password:") {
        bail!("the login shell prompted for credentials: {:?}", sh.text());
    }
    a.wait_new(&user_line("issued"), issued, 15).await?;
    a.wait_new(&user_line("redeemed"), redeemed, 15).await?;

    log("ssh-login-shell: a commit from that session is attributed to the user");
    let cfg: serde_json::Value =
        serde_json::from_str(&a.rest_expect(Method::GET, "/v1/config", None, 200).await?)?;
    let hostname = cfg["hostname"].as_str().context("hostname")?.to_string();
    let audit = format!("config commit audit.*actor=\"{LOGIN_USER}\"");
    let n = a.count(&audit);
    for name in ["ssh-shell-host", hostname.as_str()] {
        sh.send("configure ssh-login").await?;
        sh.expect("(ssh-login)", 20).await?;
        sh.send(&format!("set hostname {name}")).await?;
        sh.send("commit").await?;
        sh.expect("committed", 20).await?;
        // A commit leaves configuration mode; wait for the operational prompt.
        sh.expect("> ", 20).await?;
    }
    a.wait_new(&audit, n, 15).await?;

    log("ssh-login-shell: ssh host <cmd> is refused and redeems nothing");
    let redeemed = a.count(&user_line("redeemed"));
    let mut cmd = ssh.exec("show config").await?;
    cmd.finish(20).await?;
    if !cmd.out.contains("running a command is not supported") || cmd.exit.unwrap_or(0) == 0 {
        bail!(
            "exec must be refused with a non-zero status: {:?} {:?}",
            cmd.out,
            cmd.exit
        );
    }
    a.assert_quiet(&user_line("redeemed"), redeemed, 3).await?;

    // `nos` is setgid (to reach /run/nos), which makes it non-dumpable: even its owner cannot
    // read `/proc/<pid>/environ`, so the ticket in its environment is not exposed to the user's
    // other processes. That also means no live ticket can be fished out to replay; a ticket the
    // watchdog never issued stands in (single use is unit-tested in the watchdog, #990).
    log(
        "ssh-login-shell: the login shell's environment is not readable, a bogus ticket is refused",
    );
    let (pid, uid) = live_shell(w).await?;
    let (code, out) = w
        .dock
        .exec_as(
            "router-a",
            Some(&uid),
            &["cat", &format!("/proc/{pid}/environ")],
        )
        .await?;
    if code == 0 || !out.contains("Permission denied") {
        bail!("the login shell's environ must be unreadable by its owner, got ({code}): {out:?}");
    }
    let refused = a.count("login ticket refused");
    let bogus = nos_proto::ticket_to_env(&[0x5a; nos_proto::LOGIN_TICKET_LEN]);
    let (_, out) = w
        .dock
        .exec(
            "router-a",
            &[
                "sh",
                "-c",
                "NOS_LOGIN_TICKET=$1 /usr/bin/nos </dev/null 2>&1",
                "sh",
                &bogus,
            ],
        )
        .await?;
    if !out.contains("session ticket not accepted") {
        bail!("an unknown ticket must be refused, got: {out}");
    }
    a.wait_new("login ticket refused", refused, 15).await?;

    log("ssh-login-shell: deleting the user cuts it off");
    let gone = format!("certificates revoked role=user name={LOGIN_USER}");
    let revoked = a.count(&gone);
    login_user(a, false).await?;
    a.wait_new(&gone, revoked, 30).await?;
    if Ssh::password(ip, SSH_PORT, LOGIN_USER, LOGIN_PASSWORD)
        .await?
        .is_some()
    {
        bail!("a deleted user must not log in over SSH");
    }
    log("ssh-login-shell: the already-open shell fails its next command");
    sh.send("show config").await?;
    sh.expect("CertificateRevoked", 30).await?;
    drop(sh);
    drop(ssh);

    log("ssh-login-shell: wrong password and unknown user are rejected");
    let rejected = a.count("login rejected");
    for user in [E2E_USER, PAM_UNKNOWN_USER] {
        if Ssh::password(ip, SSH_PORT, user, PAM_WRONG_PASSWORD)
            .await?
            .is_some()
        {
            bail!("{user} must not log in with a wrong password");
        }
    }
    a.wait_new("login rejected", rejected, 15).await?;

    a.provision(&strings(&["--clear-ssh-server"])).await?;
    Ok(())
}

/// `/proc/net/tcp{,6}` LISTEN (state 0A) local addresses, as `(hex addr, port)`.
fn listeners(proc_net: &str) -> Vec<(String, u16)> {
    proc_net
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (addr, port) = f.get(1)?.split_once(':')?;
            (f.get(3) == Some(&"0A"))
                .then_some((addr.to_string(), u16::from_str_radix(port, 16).ok()?))
        })
        .collect()
}

/// `/proc/net/tcp`'s little-endian hex for a dotted quad.
fn hex_v4(ip: &str) -> String {
    let o: Vec<u8> = ip.split('.').map(|p| p.parse().unwrap()).collect();
    format!("{:02X}{:02X}{:02X}{:02X}", o[3], o[2], o[1], o[0])
}

/// `nos-sshd` is bound to the VRF's address only (#988): a LISTEN socket on `IP_A:2222` and none
/// on the wildcard, unreachable from the default VRF, one login works, and clearing the
/// config removes listener and process. Needs `up`; leaves `ssh-server` cleared.
pub async fn ssh(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;
    let ip = IP_A.s();

    a.provision(&[
        "--ssh-server-address",
        ip,
        "--ssh-server-port",
        &SSH_PORT.to_string(),
    ])
    .await?;
    a.wait("ssh listening").await?;

    log("ssh: listening on the VRF address only");
    let (_, t4) = w.dock.exec("router-a", &["cat", "/proc/net/tcp"]).await?;
    let (_, t6) = w.dock.exec("router-a", &["cat", "/proc/net/tcp6"]).await?;
    let (v4, v6) = (listeners(&t4), listeners(&t6));
    if !v4.contains(&(hex_v4(ip), SSH_PORT)) {
        bail!("no LISTEN socket on {ip}:{SSH_PORT}: {v4:?}");
    }
    let wild = v4.iter().any(|(h, p)| *p == SSH_PORT && h == "00000000")
        || v6
            .iter()
            .any(|(h, p)| *p == SSH_PORT && h.bytes().all(|b| b == b'0'));
    if wild {
        bail!("{SSH_PORT} listens on a wildcard address: {v4:?} {v6:?}");
    }

    log("ssh: not reachable from the default VRF");
    let probe = format!("exec 3<>/dev/tcp/{ip}/{SSH_PORT}");
    let (code, out) = w.dock.exec("router-a", &["bash", "-c", &probe]).await?;
    if code == 0 {
        bail!("the default VRF reached the ssh listener on {ip}:{SSH_PORT}");
    }
    log(format!(
        "ssh: default-VRF connect refused ({code}): {}",
        out.trim()
    ));

    log("ssh: a login through the VRF works");
    Ssh::password(ip, SSH_PORT, E2E_USER, E2E_PASSWORD)
        .await?
        .context("the seeded user must log in over SSH")?;

    log("ssh: clearing the config removes the listener and the process");
    a.provision(&strings(&["--clear-ssh-server"])).await?;
    let mut gone = false;
    for _ in 0..30 {
        let (_, o) = w.dock.exec("router-a", &["cat", "/proc/net/tcp"]).await?;
        let (_, c) = w
            .dock
            .exec_root(
                "router-a",
                &["sh", "-c", "cat /proc/[0-9]*/comm 2>/dev/null"],
            )
            .await?;
        if !listeners(&o).iter().any(|(_, p)| *p == SSH_PORT) && !c.lines().any(|l| l == "nos-sshd")
        {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if !gone {
        bail!("nos-sshd or its listener survived --clear-ssh-server");
    }
    if Ssh::password(ip, SSH_PORT, E2E_USER, E2E_PASSWORD)
        .await
        .is_ok()
    {
        bail!("an SSH connect succeeded after --clear-ssh-server");
    }
    a.established().await?;
    Ok(())
}
