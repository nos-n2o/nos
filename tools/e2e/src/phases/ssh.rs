//! `nos-sshd`'s host key as a config secret (#1104): generated at first start, kept in the
//! admin keystore under `ssh-host-key`, stable across a daemon restart, hidden from REST and
//! logs, regenerated when the label is deleted.

use anyhow::{bail, Context};
use nos_proto::SSH_HOST_KEY_LABEL;
use reqwest::Method;

use crate::consts::*;
use crate::router::{log, strings};
use crate::world::World;

const FP: &str = "host key fingerprint=SHA256:";

fn fingerprint(a: &crate::router::Router) -> anyhow::Result<String> {
    let line = a.logs.last(FP).context("no host key fingerprint line")?;
    Ok(line[line.find("SHA256:").context("no SHA256")?..].to_string())
}

/// Needs `up`; leaves `ssh-server` cleared again (the key stays in the keystore).
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
    Ok(())
}
