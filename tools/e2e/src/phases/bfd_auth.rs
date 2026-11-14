//! BFD authentication (RFC 5880 §6.7, #289).

use reqwest::Method;

use super::bfd::{bfd_route, session_is};
use super::bgp::no_leak;
use crate::consts::*;
use crate::router::{log, strings, Router, A, B};
use crate::world::World;

/// The secret every step starts from: distinctive, so a leak is greppable.
const MARKER: &str = "s3cr3t-bfd-marker";

/// Profile flags: `meticulous-sha1`-style `method`, key id and secret, with
/// 5 s intervals (15 s detection) so two sequential REST edits fit in one
/// detection time.
fn auth(method: &str, id: u8, secret: &str) -> Vec<String> {
    strings(&[
        "--bfd-auth",
        &format!("{method}:{id}:{secret}"),
        "--bfd-interval-ms",
        "5000",
    ])
}

/// Applies the same flags to both routers at once.
async fn both(a: &Router, b: &Router, flags: &[String]) -> anyhow::Result<()> {
    tokio::try_join!(a.provision(flags), b.provision(flags))?;
    Ok(())
}

/// The one session of `r` to `peer`, as `GET /v1/bfd/sessions` shows it.
async fn session(r: &Router, peer: &str) -> anyhow::Result<(serde_json::Value, String)> {
    let path = format!("/v1/bfd/sessions?peer={peer}");
    let body = r.rest_expect(Method::GET, &path, None, 200).await?;
    let v: serde_json::Value = serde_json::from_str(&body)?;
    Ok((v[0].clone(), body))
}

/// Both routers report `method` and `key_id`, and neither prints a secret.
async fn shows_auth(w: &World, method: &str, key_id: u8) -> anyhow::Result<()> {
    for (r, peer) in [(w.a()?, IP_B.s()), (w.b()?, IP_A.s())] {
        let (s, body) = session(r, peer).await?;
        anyhow::ensure!(
            s["auth_method"] == method && s["auth_key_id"] == key_id,
            "{}: expected {method} key {key_id}: {body}",
            r.name()
        );
        for secret in [MARKER, "wrong", "n3w"] {
            anyhow::ensure!(
                !body.contains(secret),
                "{}: leaks the key: {body}",
                r.name()
            );
        }
    }
    Ok(())
}

/// `bfd-auth`, self-contained. Both routers run `bfd-profile fast` (5 s x 3)
/// with `meticulous-sha1` and reach Up; REST shows the method and key id but
/// never the key. A wrong secret on router-a keeps the session Down and logs
/// `bfd auth failed` on router-b (the counter shows it too). A live change of
/// key id and secret on both, then of the method, never flaps the session (the
/// old key is accepted for 4 detection times; the sequence space resets with
/// the method). Finally an unauthenticated FRR `bfdd` (`router-f`, no RFC 5880
/// §6.7 support) stays Down against the authenticated profile and comes Up once
/// the authentication is removed everywhere.
pub async fn bfd_auth(w: &mut World) -> anyhow::Result<()> {
    let mut fa = A.base_flags();
    fa.extend(bfd_route(BFD_PREFIX_B, IP_B.s()));
    fa.extend(auth("meticulous-sha1", 1, MARKER));
    let mut fb = B.base_flags();
    fb.extend(bfd_route(BFD_PREFIX_A, IP_A.s()));
    fb.extend(auth("meticulous-sha1", 1, MARKER));
    w.start(A, Some(fa), &[]).await?;
    w.start(B, Some(fb), &[]).await?;
    let (a, b) = (w.a()?, w.b()?);

    let up_a = format!("bfd session up peer={IP_B}");
    let down_a = format!("bfd session down peer={IP_B}");
    let down_b = format!("bfd session down peer={IP_A}");
    let failed_b = format!("bfd auth failed peer={IP_A}");

    log("matching meticulous-sha1 keys: Up, REST shows the method and key id, not the key");
    a.wait(&up_a).await?;
    b.wait(&format!("bfd session up peer={IP_A}")).await?;
    shows_auth(w, "MeticulousSha1", 1).await?;

    log("a wrong secret on router-a: Down, rejected packets logged, no Up for 10 s");
    let (n_failed, n_up) = (b.count(&failed_b), a.count(&up_a));
    a.provision(&auth("meticulous-sha1", 1, "wrong")).await?;
    b.wait_new(&failed_b, n_failed, 20).await?;
    session_is(a, IP_B.s(), "Down", None, 40).await?;
    a.assert_quiet(&up_a, n_up, 10).await?;
    let (s, body) = session(b, IP_A.s()).await?;
    anyhow::ensure!(
        s["auth_failures"].as_u64().is_some_and(|n| n > 0),
        "router-b should count the failures: {body}"
    );

    log("the secret restored: Up again");
    a.provision(&auth("meticulous-sha1", 1, MARKER)).await?;
    a.wait_new(&up_a, n_up, 30).await?;
    session_is(a, IP_B.s(), "Up", None, 10).await?;

    log("the secret lives in the admin keystore only: not in the config view, not in any log (#510)");
    for r in [a, b] {
        no_leak(r, &[MARKER]).await?;
    }

    log("rotating the secret under the same admin label on both: no flap");
    let rotated = "r0tated-bfd-marker";
    let (n_down_a, n_down_b) = (a.count(&down_a), b.count(&down_b));
    both(a, b, &auth("meticulous-sha1", 1, rotated)).await?;
    a.assert_quiet(&down_a, n_down_a, 20).await?;
    b.assert_quiet(&down_b, n_down_b, 0).await?;
    session_is(a, IP_B.s(), "Up", None, 10).await?;
    for r in [a, b] {
        no_leak(r, &[MARKER, rotated]).await?;
    }

    log("live key change on both (id 2, new secret), then the method (keyed-md5, id 3): no flap");
    let (n_down_a, n_down_b) = (a.count(&down_a), b.count(&down_b));
    both(a, b, &auth("meticulous-sha1", 2, "n3w")).await?;
    a.assert_quiet(&down_a, n_down_a, 20).await?;
    shows_auth(w, "MeticulousSha1", 2).await?;
    both(a, b, &auth("keyed-md5", 3, "n3w")).await?;
    a.assert_quiet(&down_a, n_down_a, 20).await?;
    b.assert_quiet(&down_b, n_down_b, 0).await?;
    session_is(a, IP_B.s(), "Up", None, 10).await?;
    shows_auth(w, "KeyedMd5", 3).await?;

    log("interop: FRR bfdd has no authentication, so the authenticated profile never reaches it");
    let conf = format!(
        "frr defaults traditional\nhostname router-f\n!\nbfd\n peer {IP_A}\n  \
         detect-multiplier 3\n  receive-interval 5000\n  transmit-interval 5000\n  \
         no shutdown\n exit\nexit\n"
    );
    w.dock.container_remove("router-f").await;
    w.dock.ensure_pulled(FRR_IMAGE).await?;
    w.dock
        .start_plain_caps(
            "router-f",
            FRR_IMAGE,
            NET,
            IP_G.s(),
            &[
                "sh",
                "-c",
                "sed -i 's/^bfdd=no/bfdd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start",
            ],
            ("/etc/frr", "frr.conf", conf.as_bytes()),
            &["NET_ADMIN", "NET_RAW", "SYS_ADMIN"],
        )
        .await?;
    let mut route = bfd_route(BFD_PREFIX_F, IP_G.s());
    route.extend(strings(&["--bfd-interval-ms", "5000"]));
    a.provision(&route).await?;
    let up_g = format!("bfd session up peer={IP_G}");
    a.wait(&format!("bfd auth failed peer={IP_G}")).await?;
    a.assert_quiet(&up_g, 0, 8).await?;

    log("authentication removed on both: FRR and router-b reach Up");
    let off = strings(&["--no-bfd-auth", "--bfd-interval-ms", "5000"]);
    both(a, b, &off).await?;
    a.wait(&up_g).await?;
    session_is(a, IP_B.s(), "Up", None, 30).await?;
    session_is(b, IP_A.s(), "Up", None, 30).await?;
    w.dock.container_remove("router-f").await;
    Ok(())
}
