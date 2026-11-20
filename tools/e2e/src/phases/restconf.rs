//! RESTCONF conformance (#1177, part of #1173): the facade's data, checked by
//! an oracle that is not our code. The generated YANG module
//! (`docs/yang/nos-config.yang`) validates a live `GET /restconf/data` with
//! `yanglint` (libyang), run on the host and never shipped in the runtime
//! image; then the RFC 8040 behaviours that need a real daemon behind them
//! (no-op PUT, 409, the daemon's own validation text, secrets, RBAC).

use anyhow::{bail, Context};
use reqwest::Method;
use serde_json::{json, Value};

use crate::router::{log, Router};
use crate::world::World;

const MODULE_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/yang/nos-config.yang"
);
const RO_TX_USER: &str = "rc-ro";
const RO_PASSWORD: &str = "rc-ro-password";

/// `yanglint --type data <module> <data>`; `Err` carries its output.
#[allow(clippy::disallowed_types, reason = "independent oracle: yanglint")]
fn yanglint(data: &Value) -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!("nos-e2e-restconf-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let file = dir.join("data.json");
    std::fs::write(&file, serde_json::to_vec(data)?)?;
    let out = std::process::Command::new("yanglint")
        .args(["--type", "data"])
        .arg(MODULE_FILE)
        .arg(&file)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    let out = match out {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "yanglint not found in PATH: install it (`apt-get install libyang3-tools`, `libyang2-tools` on older Ubuntu/Debian); \
             this phase has no silent skip"
        ),
        Err(e) => bail!("running yanglint: {e}"),
    };
    if !out.status.success() {
        bail!(
            "yanglint rejected the data: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// The `error-tag` of a RESTCONF `errors` body.
fn error_tag(body: &str) -> anyhow::Result<String> {
    let v: Value = serde_json::from_str(body).with_context(|| format!("not JSON: {body}"))?;
    v["ietf-restconf:errors"]["error"][0]["error-tag"]
        .as_str()
        .map(str::to_string)
        .with_context(|| format!("not an ietf-restconf errors body: {body}"))
}

pub async fn restconf_conformance(w: &mut World) -> anyhow::Result<()> {
    let a = w.a()?;

    // The module the router serves is the committed one.
    let served = a
        .rest_expect(Method::GET, "/restconf/yang/nos-config.yang", None, 200)
        .await?;
    if served != std::fs::read_to_string(MODULE_FILE)? {
        bail!("router-a serves a nos-config.yang that differs from docs/yang/nos-config.yang");
    }

    // GET of the whole, provisioned config is valid instance data. The bare
    // `/restconf/data` wraps it as `ietf-restconf:data`; top-level nodes of a
    // module must be module-qualified (RFC 7951 §4) for the oracle.
    let (etag, body) = a
        .rest_expect_full(Method::GET, "/restconf/data", None, None, 200)
        .await?;
    let etag = etag.context("GET /restconf/data carries no ETag")?;
    let data: Value = serde_json::from_str(&body)?;
    let Some(Value::Object(inner)) = data.get("ietf-restconf:data") else {
        bail!("GET /restconf/data is not an ietf-restconf:data wrapper: {body}");
    };
    let qualified: serde_json::Map<String, Value> = inner
        .iter()
        .map(|(k, v)| (format!("nos-config:{k}"), v.clone()))
        .collect();
    yanglint(&Value::Object(qualified))?;
    log("router-a: GET /restconf/data validates against nos-config.yang (yanglint)");

    // Secrets stay redacted.
    if body.contains("$argon2") || !body.contains("<hidden>") {
        bail!("router-a: RESTCONF GET leaks or lost the redaction of secrets");
    }

    // PUT of the document just read changes nothing: same ETag, no session or
    // daemon churn.
    let (_, cfg_body) = a
        .rest_expect_full(
            Method::GET,
            "/restconf/data/nos-config:config",
            None,
            None,
            200,
        )
        .await?;
    let sessions = "inbound bgp session ended\\|outbound bgp session ended\\|spawning nos-";
    let baseline = a.count_fresh(sessions).await;
    a.rest_expect_full(
        Method::PUT,
        "/restconf/data/nos-config:config",
        Some(&cfg_body),
        None,
        204,
    )
    .await?;
    let (after, _) = a
        .rest_expect_full(Method::GET, "/restconf/data", None, None, 200)
        .await?;
    if after.as_deref() != Some(etag.as_str()) {
        bail!("router-a: PUT of the unchanged config moved the ETag ({etag} -> {after:?})");
    }
    a.assert_quiet(sessions, baseline, 5).await?;
    a.established().await?;
    log("router-a: PUT of the GET document is a no-op");

    // POST of an existing list entry: 409 data-exists, as an ietf-restconf body.
    let r1 = a
        .rest_expect(
            Method::GET,
            "/restconf/data/nos-config:bgp-instance=r1",
            None,
            200,
        )
        .await?;
    let r1: Value = serde_json::from_str(&r1)?;
    let dup = json!({"nos-config:bgp_instances": r1["nos-config:bgp-instance"]}).to_string();
    let (status, text) = a.rest(Method::POST, "/restconf/data", Some(&dup)).await?;
    if status != 409 || error_tag(&text)? != "data-exists" {
        bail!("router-a: duplicate POST -> {status} {text}, want 409 data-exists");
    }

    // DELETE of the peer-group a peer references: the daemon's validation
    // text, nothing changed.
    let (status, text) = a
        .rest(
            Method::DELETE,
            "/restconf/data/nos-config:bgp-instance=r1/peer-group=pg1",
            None,
        )
        .await?;
    if status != 422 || error_tag(&text)? != "operation-failed" || !text.contains("peer-group") {
        bail!("router-a: DELETE of a referenced peer-group -> {status} {text}, want 422 naming the peer-group");
    }
    let (after, _) = a
        .rest_expect_full(Method::GET, "/restconf/data", None, None, 200)
        .await?;
    if after.as_deref() != Some(etag.as_str()) {
        bail!("router-a: a refused DELETE changed the config");
    }
    log("router-a: duplicate POST is 409 data-exists, a referenced DELETE 422 with the daemon's text");

    read_only_user(a).await?;
    Ok(())
}

/// #1147 through RESTCONF: a read-only user reads, every write method is 403.
async fn read_only_user(a: &Router) -> anyhow::Result<()> {
    use nos_proto::UserRole;
    a.provision(&["--user", &format!("{RO_TX_USER}={RO_PASSWORD}")])
        .await?;
    a.edit(|config| {
        let u = config.users.iter_mut().find(|u| u.name == RO_TX_USER);
        u.context("user was not created")?.role = UserRole::ReadOnly;
        Ok(())
    })
    .await?;
    let Ok(id) = a.rest.login(RO_TX_USER, RO_PASSWORD).await? else {
        bail!("{RO_TX_USER} could not log in over REST");
    };
    let client = a.rest.with_identity(&id)?;
    let host = "/restconf/data/nos-config:hostname";
    let body = json!({"nos-config:hostname": "ro"}).to_string();
    let (get, _) = a
        .rest_with(&client, Method::GET, "/restconf/data", None)
        .await?;
    let mut codes = vec![];
    // The POST body names a leaf that does not exist yet: an existing one is
    // 409 before RBAC, which `nos-configd` applies at the edit.
    let new = json!({"nos-config:bgp_instances": [{"name": "rc-new", "asn": 65099, "router_id": "9.9.9.9"}]}).to_string();
    for (m, path, b) in [
        (Method::POST, "/restconf/data", &new),
        (Method::PUT, host, &body),
        (Method::PATCH, host, &body),
        (Method::DELETE, host, &body),
    ] {
        let (s, _) = a.rest_with(&client, m.clone(), path, Some(b)).await?;
        codes.push((m, s));
    }
    // Always remove the user again, whatever the checks say.
    a.edit(|config| {
        config.users.retain(|u| u.name != RO_TX_USER);
        Ok(())
    })
    .await?;
    if get != 200 || codes.iter().any(|(_, s)| *s != 403) {
        bail!("read-only user: GET {get}, writes {codes:?}; want 200 and all 403");
    }
    log("router-a: a read-only user reads /restconf/data and gets 403 on POST/PUT/PATCH/DELETE");
    Ok(())
}
