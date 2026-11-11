//! Fake-daemon plumbing shared by `actions.rs` (the happy paths) and
//! `actions_unhappy.rs` (every "not running" / error / populated arm), #345.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_cli::actions::{handle_action, DocCache, LeaveChoice, Outcome};
use nos_cli::command::Command;
use nos_cli::session::{self, Mode};
use nos_pki::testing::shared;
use nos_proto::{BgpInstance, Config, IpcCodec, TransactionSnapshot};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio_util::codec::{FramedRead, FramedWrite};

/// Serves `role`/`name` on `path` until the test ends: every request on
/// every connection gets `handler`'s events, in order.
pub fn serve<Req, Ev>(
    role: &str,
    name: &str,
    path: &Path,
    handler: impl Fn(Req) -> Vec<Ev> + Send + Sync + 'static,
) where
    Req: DeserializeOwned + Serialize + Send + 'static,
    Ev: DeserializeOwned + Serialize + Send + 'static,
{
    serve_with(role, name, path, false, handler);
}

/// `serve`, closing each connection after its first request when `once`
/// (a `show log --follow` tail ends when the daemon goes away).
pub fn serve_with<Req, Ev>(
    role: &str,
    name: &str,
    path: &Path,
    once: bool,
    handler: impl Fn(Req) -> Vec<Ev> + Send + Sync + 'static,
) where
    Req: DeserializeOwned + Serialize + Send + 'static,
    Ev: DeserializeOwned + Serialize + Send + 'static,
{
    let listener = shared().identity(role, name).listen(path).unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        while let Ok(conn) = listener.accept().await {
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let Ok((stream, _)) = conn.handshake().await else {
                    return;
                };
                let (r, w) = tokio::io::split(stream);
                let mut reader = FramedRead::new(r, IpcCodec::<Req>::default());
                let mut writer = FramedWrite::new(w, IpcCodec::<Ev>::default());
                while let Some(Ok(req)) = reader.next().await {
                    for ev in handler(req) {
                        if writer.send(ev).await.is_err() {
                            return;
                        }
                    }
                    if once {
                        return;
                    }
                }
            });
        }
    });
}

pub fn snapshot(name: &str, config: &Config) -> TransactionSnapshot {
    TransactionSnapshot {
        name: name.to_string(),
        config: config.clone(),
        dirty: true,
        resumed: name == "resumed",
        generation: 1,
    }
}

pub struct Lab {
    pub _dir: tempfile::TempDir,
    pub config: PathBuf,
    pub watchdog: PathBuf,
    pub docs: DocCache,
}

pub fn discard(_: &str) -> LeaveChoice {
    LeaveChoice::Discard
}

pub fn commit(_: &str) -> LeaveChoice {
    LeaveChoice::Commit
}

pub fn leave_open(_: &str) -> LeaveChoice {
    LeaveChoice::LeaveOpen
}

/// Runs `lines` as typed input, returning the mode after each.
pub async fn run(
    lab: &Lab,
    mut mode: Mode,
    lines: &[&str],
    ask: fn(&str) -> LeaveChoice,
) -> (Mode, bool) {
    for line in lines {
        let action = session::resolve(&mode, Command::parse(line));
        match handle_action(action, mode, &lab.config, &lab.watchdog, &lab.docs, ask).await {
            Outcome::Continue(next) => mode = next,
            Outcome::Exit => return (Mode::Operational, true),
        }
    }
    (mode, false)
}

/// The running config both fake `nos-configd`s start from: hostname `r1` and
/// one instance of each routing protocol (`b1`, `o1`, `v3`).
pub fn base_running() -> Config {
    Config {
        hostname: "r1".to_string(),
        bgp_instances: vec![BgpInstance {
            name: "b1".to_string(),
            router_id: "1.1.1.1".parse().unwrap(),
            asn: 65000,
            peer_groups: Vec::new(),
            peers: Vec::new(),
            cluster_id: None,
            maximum_paths: None,
            confederation: nos_proto::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            bmp_stations: Vec::new(),
            aggregates: Vec::new(),
            graceful_restart: nos_proto::BgpGracefulRestart::default(),
            routing_table: None,
            redistribute_policy: None,
        }],
        ospf_instances: vec![nos_proto::OspfInstance {
            name: "o1".to_string(),
            router_id: "1.1.1.1".parse().unwrap(),
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
            graceful_restart_helper_max_grace_period: None,
            prefix_suppression: false,
            max_metric_on_startup: None,
            max_metric_on_shutdown: None,
            max_metric_administrative: false,
            host_router: false,
            remote_lfa: false,
            redistribute_metric: None,
            redistribute_metric_type: None,
        }],
        ospfv3_instances: vec![nos_proto::Ospfv3Instance {
            name: "v3".to_string(),
            router_id: "1.1.1.1".parse().unwrap(),
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            extended_lsa: false,
            graceful_restart_grace_period: None,
            graceful_restart_helper_max_grace_period: None,
        }],
        ..Default::default()
    }
}
