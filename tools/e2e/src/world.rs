//! The set of running routers plus the docker plumbing phases share.

use std::collections::BTreeMap;

use anyhow::Context;
use reqwest::Method;

use crate::consts::*;
use crate::docker::{image, Dock};
use crate::router::{log, Id, Router, A, B, C, D, E};

pub struct World {
    pub dock: Dock,
    routers: BTreeMap<&'static str, Router>,
}

impl World {
    /// Connects to docker and attaches to any router that is already running,
    /// so a single phase can be run against containers `up` left behind.
    pub async fn new() -> anyhow::Result<Self> {
        let dock = Dock::connect()?;
        let mut routers = BTreeMap::new();
        for id in [A, B, C, D, E] {
            let running = dock
                .docker
                .inspect_container(id.name, None)
                .await
                .ok()
                .and_then(|i| i.state)
                .and_then(|s| s.running)
                .unwrap_or(false);
            if running {
                let router = Router::attach(&dock, id).await?;
                router.logs.settle().await;
                routers.insert(id.name, router);
            }
        }
        Ok(Self { dock, routers })
    }

    pub fn get(&self, id: Id) -> anyhow::Result<&Router> {
        self.routers
            .get(id.name)
            .with_context(|| format!("{} is not running — run `nos-e2e up` first", id.name))
    }

    pub fn a(&self) -> anyhow::Result<&Router> {
        self.get(A)
    }

    pub fn b(&self) -> anyhow::Result<&Router> {
        self.get(B)
    }

    pub fn c(&self) -> anyhow::Result<&Router> {
        self.get(C)
    }

    /// Creates the primary network (dual-stack when the docker daemon allows).
    pub async fn ensure_network(&self) -> anyhow::Result<()> {
        self.dock.require_image(&image()).await?;
        if self.dock.network_exists(NET).await {
            return Ok(());
        }
        log(format!("creating network {NET} ({SUBNET}, {SUBNET6})"));
        // IPv6 is needed even for ospfv3's point-to-point link alone: docker
        // disables it on a container's veth unless the network is dual-stack.
        // It can fail when the daemon itself has no IPv6 support; every
        // non-ospfv3 phase works without it, so fall back to IPv4-only.
        if self
            .dock
            .network_create(NET, &[SUBNET, SUBNET6], true)
            .await
            .is_err()
        {
            log("warning: dual-stack network create failed (docker daemon may lack IPv6 support) — falling back to IPv4-only; ospfv3/ospfv3-dr will not work on this host");
            self.dock.network_create(NET, &[SUBNET], false).await?;
        }
        Ok(())
    }

    /// Fails clearly unless `NET` is dual-stack: `ensure_network` falls back
    /// to IPv4-only when the docker daemon can't make an IPv6 network.
    pub async fn require_ipv6(&self) -> anyhow::Result<()> {
        self.ensure_network().await?;
        let net = self.dock.docker.inspect_network(NET, None).await?;
        if net.enable_ipv6 != Some(true) {
            anyhow::bail!("docker daemon lacks IPv6: {NET} is IPv4-only");
        }
        Ok(())
    }

    /// (Re)starts `id`; see `Router::start`.
    pub async fn start(
        &mut self,
        id: Id,
        seed_flags: Option<Vec<String>>,
        watchdog_args: &[&str],
    ) -> anyhow::Result<()> {
        self.ensure_network().await?;
        // Drop the old log follower before its container goes away.
        self.routers.remove(id.name);
        let router = Router::start(&self.dock, id, seed_flags, watchdog_args).await?;
        self.routers.insert(id.name, router);
        Ok(())
    }

    /// Stops following `id`'s logs and removes its container and volumes.
    pub async fn remove(&mut self, id: Id) {
        self.routers.remove(id.name);
        self.dock.container_remove(id.name).await;
        self.dock.volume_remove(&format!("{}-run", id.name)).await;
        self.dock.volume_remove(&format!("{}-data", id.name)).await;
    }

    /// The two-router BGP topology every scenario starts from.
    pub async fn up(&mut self, watchdog_args: &[&str]) -> anyhow::Result<()> {
        self.start(A, None, watchdog_args).await?;
        self.start(B, None, watchdog_args).await
    }

    const CONTAINERS: [&'static str; 14] = [
        "router-a",
        "router-b",
        "router-c",
        "router-d",
        "router-e",
        "router-r",
        "router-g",
        "router-f",
        CE_HOST,
        H_HOST,
        RPKI_CACHE,
        RTR_STUB,
        SYSLOG_COLLECTOR,
        BMP_COLLECTOR,
    ];

    /// On a group failure: the last `n` `docker logs` lines of every container
    /// that exists (running or not), so a router whose REST API never came up
    /// still explains itself before `down` removes it.
    pub async fn dump_docker_logs(&self, n: usize) {
        for name in Self::CONTAINERS {
            let Ok(out) = self.dock.logs(name).await else {
                continue;
            };
            println!("=== docker logs {name} ===");
            let lines: Vec<&str> = out.lines().collect();
            for line in &lines[lines.len().saturating_sub(n)..] {
                println!("{line}");
            }
        }
    }

    pub async fn down(&mut self) {
        self.routers.clear();
        for name in Self::CONTAINERS {
            self.dock.container_remove(name).await;
            self.dock.volume_remove(&format!("{name}-run")).await;
            self.dock.volume_remove(&format!("{name}-data")).await;
        }
        for net in [
            NET,
            NET_BOND1,
            NET_BOND2,
            NET_CE_A,
            NET_CE_B,
            NET_H,
            NET_OSPF_FRR,
            NET_OSPFV3_A1,
            NET_L3_A,
            NET_L3_B,
        ] {
            self.dock.network_remove(net).await;
        }
    }

    /// `nos-e2e logs [n]`: the last `n` log lines of every running router, via REST.
    pub async fn print_logs(&self, n: usize) -> anyhow::Result<()> {
        for r in self.routers.values() {
            println!("===== {} =====", r.name());
            let body = r
                .rest_expect(Method::GET, &format!("/v1/logs?limit={n}"), None, 200)
                .await?;
            let entries: Vec<nos_proto::LogEntry> = serde_json::from_str(&body)?;
            for e in entries {
                println!("{} {}", e.source, crate::logs::render(&e));
            }
        }
        Ok(())
    }

    // --- extra links (port-aggregate / lacp / lldp) ---

    /// Connects router-a to the two bond networks (docker gives it eth1/eth2).
    pub async fn connect_bond_networks(&self) -> anyhow::Result<()> {
        for net in [NET_BOND1, NET_BOND2] {
            if !self.dock.network_exists(net).await {
                self.dock.network_create(net, &[], false).await?;
            }
            self.dock.network_connect(net, "router-a").await;
        }
        Ok(())
    }

    /// Two direct veth pairs between router-a and router-b (eth1/eth2). A
    /// docker network is a Linux bridge, which never forwards the
    /// slow-protocols/LLDP link-local multicast, so no LACPDU/LLDPDU could
    /// cross one; a veth pair is a plain L2 wire. Creating one across two
    /// containers needs iproute2 + CAP_NET_ADMIN, which the runtime image
    /// deliberately lacks, so a throwaway privileged helper does it.
    pub async fn link_veths(&self) -> anyhow::Result<()> {
        self.dock.ensure_helper_image(NETNS_HELPER_IMAGE).await?;
        // `port-aggregate` leaves both routers on the bond networks, whose
        // eth1/eth2 would otherwise be reused in place of a veth.
        for router in ["router-a", "router-b"] {
            for net in [NET_BOND1, NET_BOND2] {
                self.dock.network_disconnect(net, router).await;
            }
        }
        let pid_a = self.dock.pid("router-a").await?.to_string();
        let pid_b = self.dock.pid("router-b").await?.to_string();
        for iface in ["eth1", "eth2"] {
            let exists = self
                .dock
                .ip(
                    NETNS_HELPER_IMAGE,
                    Some("router-a"),
                    false,
                    &["link", "show", iface],
                )
                .await
                .is_ok();
            if exists {
                continue;
            }
            log(format!(
                "creating veth pair {iface} between router-a and router-b"
            ));
            self.dock
                .ip(
                    NETNS_HELPER_IMAGE,
                    None,
                    true,
                    &[
                        "link", "add", iface, "netns", &pid_a, "type", "veth", "peer", "name",
                        iface, "netns", &pid_b,
                    ],
                )
                .await?;
        }
        Ok(())
    }

    /// `ip link set <iface> up|down` inside `router`'s network namespace (the
    /// runtime image has no iproute2, the privileged helper does it).
    pub async fn set_link(&self, router: &str, iface: &str, up: bool) -> anyhow::Result<()> {
        let state = if up { "up" } else { "down" };
        self.dock
            .ip(
                NETNS_HELPER_IMAGE,
                Some(router),
                false,
                &["link", "set", iface, state],
            )
            .await
            .map(drop)
    }

    /// Deleting one end of a veth pair deletes both.
    pub async fn unlink_veths(&self) {
        for iface in ["eth1", "eth2"] {
            let _ = self
                .dock
                .ip(
                    NETNS_HELPER_IMAGE,
                    Some("router-a"),
                    false,
                    &["link", "del", iface],
                )
                .await;
        }
    }
}
