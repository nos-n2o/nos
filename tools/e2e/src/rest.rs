//! A router's REST API as a client sees it: HTTPS with mutual TLS. The harness
//! reads the REST CA out of the container (over the docker API, a channel it
//! already trusts), logs in once with the seeded user's password to trade it
//! for a client certificate on a key it generated, and presents that
//! certificate on every call — renewing by logging in again at half its life.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use base64::Engine as _;
use nos_pki::{generate_csr_for, KeyAlg};
use reqwest::Client;
use tokio::sync::Mutex;

use crate::consts::{E2E_PASSWORD, E2E_USER};

/// A REST-CA certificate and the key it was issued for.
#[derive(Clone)]
pub struct Identity {
    pub cert: Vec<u8>,
    pub key: nos_pki::Zeroizing<Vec<u8>>,
    lifetime: Duration,
}

struct Session {
    client: Client,
    renew_at: Instant,
}

#[derive(Clone)]
pub struct Rest {
    base: String,
    ca_pem: Arc<Vec<u8>>,
    session: Arc<Mutex<Option<Session>>>,
}

impl Identity {
    /// A renewed certificate (`POST /v1/renew`) on the key it was issued for.
    pub fn new(cert: Vec<u8>, key: nos_pki::Zeroizing<Vec<u8>>) -> Self {
        Self {
            cert,
            key,
            lifetime: Duration::from_secs(60),
        }
    }
}

impl Rest {
    pub fn new(ip: &str, port: u16, ca_pem: Vec<u8>) -> Self {
        Self {
            base: format!("https://{ip}:{port}"),
            ca_pem: Arc::new(ca_pem),
            session: Arc::default(),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn ca_pem(&self) -> &[u8] {
        &self.ca_pem
    }

    fn build(&self, identity: Option<&Identity>) -> anyhow::Result<Client> {
        let cfg = nos_pki::rest::client_config(
            &self.ca_pem,
            identity.map(|i| (i.cert.as_slice(), i.key.as_slice())),
        )?;
        Ok(Client::builder()
            .timeout(Duration::from_secs(10))
            .tls_backend_preconfigured(cfg)
            .build()?)
    }

    /// A client that presents no certificate.
    pub fn anonymous(&self) -> anyhow::Result<Client> {
        self.build(None)
    }

    /// A fresh client (so, a fresh connection) presenting `identity`.
    pub fn with_identity(&self, identity: &Identity) -> anyhow::Result<Client> {
        self.build(Some(identity))
    }

    /// `POST /v1/login`: `Ok(Ok(identity))` on success, `Ok(Err(status))` when the
    /// API refused. Only a transport failure is an `Err`.
    pub async fn login(&self, user: &str, password: &str) -> anyhow::Result<Result<Identity, u16>> {
        let (csr, key) = generate_csr_for(KeyAlg::EcdsaP256)?;
        let resp = self
            .anonymous()?
            .post(format!("{}/v1/login", self.base))
            .json(&serde_json::json!({
                "user": user,
                "password": password,
                "csr": base64::engine::general_purpose::STANDARD.encode(csr),
            }))
            .send()
            .await?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Ok(Err(status));
        }
        let body: serde_json::Value = resp.json().await?;
        let cert = base64::engine::general_purpose::STANDARD.decode(
            body["certificate"]
                .as_str()
                .context("no certificate in login reply")?,
        )?;
        Ok(Ok(Identity {
            cert,
            key,
            lifetime: Duration::from_secs(body["lifetime_secs"].as_u64().unwrap_or(60)),
        }))
    }

    /// A client presenting the harness's own certificate, logging in on first
    /// use and again once the certificate is half spent.
    pub async fn client(&self) -> anyhow::Result<Client> {
        let mut session = self.session.lock().await;
        if let Some(s) = session.as_ref()
            && Instant::now() < s.renew_at
        {
            return Ok(s.client.clone());
        }
        let identity = match self.login(E2E_USER, E2E_PASSWORD).await? {
            Ok(identity) => identity,
            Err(status) => bail!("login as {E2E_USER} -> {status}"),
        };
        let client = self.with_identity(&identity)?;
        *session = Some(Session {
            client: client.clone(),
            renew_at: Instant::now() + identity.lifetime / 2,
        });
        Ok(client)
    }
}
