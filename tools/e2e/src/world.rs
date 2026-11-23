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
            if dock.running(id.name).await {
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
            .network_create(NET, &[SUBNET.s(), SUBNET6.s()], true)
            .await
            .is_err()
        {
            log("warning: dual-stack network create failed (docker daemon may lack IPv6 support) — falling back to IPv4-only; ospfv3/ospfv3-dr will not work on this host");
            self.dock.network_create(NET, &[SUBNET.s()], false).await?;
        }
        Ok(())
    }

    /// Fails clearly unless `NET` is dual-stack: `ensure_network` falls back
    /// to IPv4-only when the docker daemon can't make an IPv6 network.
    pub async fn require_ipv6(&self) -> anyhow::Result<()> {
        self.ensure_network().await?;
        if !self.dock.network_ipv6(NET).await? {
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

    /// Reboots `id`'s container (volumes kept, tmpfs lost) and re-attaches to it: the REST CA
    /// is new, so the old client and log follower are dropped. Waits for the REST API.
    pub async fn restart(&mut self, id: Id) -> anyhow::Result<()> {
        self.routers.remove(id.name);
        // #839: /run/nos is a kept volume, so the old boot's rest-ca.crt would
        // still be there until the new watchdog republishes it; `attach` could
        // read it and fail the TLS handshake with BadSignature.
        self.dock
            .exec_root(id.name, &["rm", "-f", crate::consts::REST_CA_PATH])
            .await?;
        self.dock.restart(id.name).await?;
        let router = Router::attach(&self.dock, id).await?;
        router.wait_ready().await?;
        router.logs.settle().await;
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

    const CONTAINERS: [&'static str; 16] = [
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
        RADIUS_STUB,
        TACACS_STUB,
        SYSLOG_COLLECTOR,
        BMP_COLLECTOR,
    ];

    /// The container `err` names (a failed assertion starts with its router's
    /// name), if any.
    pub fn failing_container(err: &str) -> Option<&'static str> {
        Self::CONTAINERS.into_iter().find(|c| err.contains(c))
    }

    /// On a group failure: the last `n` `docker logs` lines of the container
    /// the error names, from the start of the failing phase (`since`, unix
    /// seconds) so the cause is not cut off; with no culprit, every container
    /// that exists (running or not, so a router whose REST API never came up
    /// still explains itself before `down` removes it).
    pub async fn dump_docker_logs(&self, n: usize, err: &str, since: i32) {
        let one = Self::failing_container(err);
        let (n, since) = if one.is_some() {
            (n * 10, since)
        } else {
            (n, 0)
        };
        for name in Self::CONTAINERS {
            if one.is_some_and(|o| o != name) {
                continue;
            }
            let Ok(out) = self.dock.logs_since(name, since).await else {
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
        // By the lab label, so this lab's containers, volumes and networks go
        // and another lab's stay (#1049).
        self.dock.teardown_lab().await;
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
        for iface in ["eth1", "eth2"] {
            self.ensure_veth(iface).await?;
        }
        Ok(())
    }

    /// One veth pair `iface` between router-a and router-b, unless it exists.
    pub async fn ensure_veth(&self, iface: &str) -> anyhow::Result<()> {
        let pid_a = self.dock.pid("router-a").await?.to_string();
        let pid_b = self.dock.pid("router-b").await?.to_string();
        {
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
                return Ok(());
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

    /// Delete the veth pair `iface` (best effort).
    pub async fn unlink_veth(&self, iface: &str) {
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

#[cfg(test)]
mod tests {
    use super::World;

    #[test]
    fn failing_container_picks_the_named_router() {
        let e = "router-a: no new log line matching 'x' within 30s";
        assert_eq!(World::failing_container(e), Some("router-a"));
        assert_eq!(World::failing_container("boom"), None);
    }
}
