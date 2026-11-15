//! The Docker daemon, driven through `bollard` — no `docker` CLI.

use std::collections::HashMap;

use anyhow::{bail, Context};
use bollard::models::{
    ContainerCreateBody, EndpointIpamConfig, EndpointSettings, HostConfig, Ipam, IpamConfig,
    NetworkConnectRequest, NetworkCreateRequest, NetworkDisconnectRequest, NetworkingConfig,
    VolumeCreateRequest,
};
use bollard::query_parameters::{
    BuildImageOptionsBuilder, CreateContainerOptionsBuilder, ListContainersOptionsBuilder,
    ListNetworksOptionsBuilder, ListVolumesOptionsBuilder, LogsOptionsBuilder,
    RemoveContainerOptionsBuilder, RemoveVolumeOptionsBuilder, UploadToContainerOptionsBuilder,
};
use bollard::{body_full, Docker};
use futures::StreamExt;

use crate::lab::{lab_env, prefixed, LAB_LABEL};

/// The nos image every router container runs: `NOS_E2E_IMAGE`, default `nos:local`
/// (CI). A per-worktree tag (`make docker-build IMAGE=nos:issue-N`) lets two labs
/// run two builds without sharing the mutable `nos:local` tag (#1048).
pub fn image() -> String {
    image_from(std::env::var("NOS_E2E_IMAGE").ok())
}

fn image_from(v: Option<String>) -> String {
    v.filter(|s| !s.is_empty())
        .unwrap_or_else(|| "nos:local".to_string())
}

/// Daemons default to `trace`, which includes `mio`/`hyper`/rtnetlink packet
/// dumps. Over REST that is self-amplifying — serving the log stream makes
/// `nos-restd` log poller activity, which is forwarded and streamed again — and
/// the forwarding layer drops entries under backpressure. `debug` keeps every
/// message the phases assert on and silences that noise.
const RUST_LOG: &str = "debug,mio=info,hyper=info,hyper_util=info,h2=info,rtnetlink=info,netlink_proto=info,netlink_sys=info,tokio_util=info,tower_http=info,reqwest=info";

/// Everything `Dock::start` needs to launch one router container.
pub struct ContainerSpec<'a> {
    pub name: &'a str,
    pub network: &'a str,
    pub ip: &'a str,
    /// Arguments handed to the image's entrypoint (`nos-watchdogd`).
    pub cmd: Vec<String>,
    /// `(path inside /var/lib/nos, contents)`, uploaded before the container starts.
    pub seed: Option<(&'a str, Vec<u8>)>,
}

pub struct Dock {
    pub docker: Docker,
    /// The lab id (#1049): every name below is mapped through it, so callers
    /// keep using the lab-0 names (`router-a`, `nos-verify-net`).
    lab: u8,
}

impl Dock {
    pub fn connect() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults().context("connecting to docker")?;
        let lab = lab_env().map_err(anyhow::Error::msg)?;
        Ok(Self { docker, lab })
    }

    /// `name` (container, network or volume) as docker knows it in this lab.
    fn n(&self, name: &str) -> String {
        prefixed(self.lab, name)
    }

    /// The label every object of this lab carries.
    fn labels(&self) -> HashMap<String, String> {
        HashMap::from([(LAB_LABEL.to_string(), self.lab.to_string())])
    }

    /// `label=nos-e2e.lab=<k>` as a docker list filter.
    fn lab_filter(&self) -> HashMap<String, Vec<String>> {
        HashMap::from([(
            "label".to_string(),
            vec![format!("{LAB_LABEL}={}", self.lab)],
        )])
    }

    /// Whether `name` is a running container (a router `up` left behind).
    pub async fn running(&self, name: &str) -> bool {
        self.docker
            .inspect_container(&self.n(name), None)
            .await
            .ok()
            .and_then(|i| i.state)
            .and_then(|s| s.running)
            .unwrap_or(false)
    }

    pub async fn network_ipv6(&self, name: &str) -> anyhow::Result<bool> {
        let net = self.docker.inspect_network(&self.n(name), None).await?;
        Ok(net.enable_ipv6 == Some(true))
    }

    /// Removes every container, volume and network of this lab, by label: one
    /// lab's `down` never touches the other's.
    pub async fn teardown_lab(&self) {
        let filters = self.lab_filter();
        let opts = ListContainersOptionsBuilder::default()
            .all(true)
            .filters(&filters)
            .build();
        for c in self
            .docker
            .list_containers(Some(opts))
            .await
            .unwrap_or_default()
        {
            if let Some(id) = c.id {
                self.container_remove_raw(&id).await;
            }
        }
        let opts = ListVolumesOptionsBuilder::default()
            .filters(&filters)
            .build();
        for v in self
            .docker
            .list_volumes(Some(opts))
            .await
            .map_or_default(|r| r.volumes.unwrap_or_default())
        {
            self.volume_remove_raw(&v.name).await;
        }
        let opts = ListNetworksOptionsBuilder::default()
            .filters(&filters)
            .build();
        for n in self
            .docker
            .list_networks(Some(opts))
            .await
            .unwrap_or_default()
        {
            if let Some(id) = n.id {
                let _ = self.docker.remove_network(&id).await;
            }
        }
    }

    /// The harness never builds the image (that needs BuildKit); fail fast instead.
    pub async fn require_image(&self, image: &str) -> anyhow::Result<()> {
        if self.docker.inspect_image(image).await.is_err() {
            bail!("docker image {image} not found — run `make docker-build` first");
        }
        Ok(())
    }

    // --- networks ---

    pub async fn network_exists(&self, name: &str) -> bool {
        self.docker
            .inspect_network(&self.n(name), None)
            .await
            .is_ok()
    }

    /// `subnets` are all put in the network's IPAM config; `ipv6` turns on IPv6.
    pub async fn network_create(
        &self,
        name: &str,
        subnets: &[&str],
        ipv6: bool,
    ) -> anyhow::Result<()> {
        let config = subnets
            .iter()
            .map(|s| IpamConfig {
                subnet: Some((*s).to_string()),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let req = NetworkCreateRequest {
            name: self.n(name),
            labels: Some(self.labels()),
            enable_ipv6: Some(ipv6),
            ipam: (!config.is_empty()).then(|| Ipam {
                config: Some(config),
                ..Default::default()
            }),
            ..Default::default()
        };
        self.docker
            .create_network(req)
            .await
            .with_context(|| format!("creating network {name}"))?;
        Ok(())
    }

    pub async fn network_remove(&self, name: &str) {
        let _ = self.docker.remove_network(&self.n(name)).await;
    }

    pub async fn network_connect(&self, network: &str, container: &str) {
        let req = NetworkConnectRequest {
            container: self.n(container),
            ..Default::default()
        };
        let _ = self.docker.connect_network(&self.n(network), req).await;
    }

    /// `network_connect` at a fixed address, so nos's config can name it.
    pub async fn network_connect_ip(
        &self,
        network: &str,
        container: &str,
        ip: &str,
    ) -> anyhow::Result<()> {
        let req = NetworkConnectRequest {
            container: self.n(container),
            endpoint_config: Some(EndpointSettings {
                ipam_config: Some(EndpointIpamConfig {
                    ipv4_address: Some(ip.to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        self.docker
            .connect_network(&self.n(network), req)
            .await
            .with_context(|| format!("connecting {container} to {network}"))
    }

    pub async fn network_disconnect(&self, network: &str, container: &str) {
        let req = NetworkDisconnectRequest {
            container: self.n(container),
            force: Some(true),
        };
        let _ = self.docker.disconnect_network(&self.n(network), req).await;
    }

    // --- volumes / containers ---

    async fn volume_recreate(&self, name: &str) -> anyhow::Result<()> {
        let opts = RemoveVolumeOptionsBuilder::default().force(true).build();
        let _ = self.docker.remove_volume(name, Some(opts)).await;
        self.docker
            .create_volume(VolumeCreateRequest {
                name: Some(name.to_string()),
                labels: Some(self.labels()),
                ..Default::default()
            })
            .await
            .with_context(|| format!("creating volume {name}"))?;
        Ok(())
    }

    pub async fn container_remove(&self, name: &str) {
        self.container_remove_raw(&self.n(name)).await;
    }

    /// By docker's own name or id (no lab prefix).
    async fn container_remove_raw(&self, name: &str) {
        let opts = RemoveContainerOptionsBuilder::default().force(true).build();
        let _ = self.docker.remove_container(name, Some(opts)).await;
    }

    pub async fn volume_remove(&self, name: &str) {
        self.volume_remove_raw(&self.n(name)).await;
    }

    async fn volume_remove_raw(&self, name: &str) {
        let opts = RemoveVolumeOptionsBuilder::default().force(true).build();
        let _ = self.docker.remove_volume(name, Some(opts)).await;
    }

    /// Replaces any existing container of that name (with fresh volumes, so no
    /// state — registries, log buffer — leaks between runs), seeds it, starts it.
    pub async fn start(&self, spec: &ContainerSpec<'_>) -> anyhow::Result<()> {
        let (name, network) = (self.n(spec.name), self.n(spec.network));
        let (name, network) = (name.as_str(), network.as_str());
        self.container_remove_raw(name).await;
        let run_vol = format!("{name}-run");
        let data_vol = format!("{name}-data");
        self.volume_recreate(&run_vol).await?;
        self.volume_recreate(&data_vol).await?;

        let endpoint = EndpointSettings {
            ipam_config: Some(EndpointIpamConfig {
                ipv4_address: Some(spec.ip.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let body = ContainerCreateBody {
            image: Some(image()),
            labels: Some(self.labels()),
            cmd: Some(spec.cmd.clone()),
            // Short 802.1AX churn-detection time so the `lacp` phase needn't wait 60s.
            env: Some(vec![
                format!("RUST_LOG={RUST_LOG}"),
                "NOS_LACP_CHURN_SECS=8".to_string(),
            ]),
            host_config: Some(HostConfig {
                binds: Some(vec![
                    format!("{run_vol}:/run/nos"),
                    format!("{data_vol}:/var/lib/nos"),
                ]),
                cap_add: Some(
                    ["NET_ADMIN", "NET_RAW", "NET_BIND_SERVICE"]
                        .map(String::from)
                        .to_vec(),
                ),
                // A hard cap keeps a runaway daemon from taking down the host
                // instead of just its own container.
                memory: Some(2 << 30),
                memory_swap: Some(2 << 30),
                // Mirrors docker-compose.yml: read-only rootfs, writable /tmp and
                // /run/nos-users (the NSS passwd file nos-configd writes, #999);
                // no `no-new-privileges` (it ignores file capabilities, the
                // watchdog's cap_setuid/cap_setgid/cap_chown included).
                readonly_rootfs: Some(true),
                tmpfs: Some(HashMap::from([
                    ("/tmp".to_string(), String::new()),
                    ("/run/nos-users".to_string(), String::new()),
                ])),
                network_mode: Some(network.to_string()),
                ..Default::default()
            }),
            networking_config: Some(NetworkingConfig {
                endpoints_config: Some(HashMap::from([(network.to_string(), endpoint)])),
            }),
            ..Default::default()
        };
        let opts = CreateContainerOptionsBuilder::default().name(name).build();
        self.docker
            .create_container(Some(opts), body)
            .await
            .with_context(|| format!("creating container {name}"))?;

        if let Some((file, contents)) = &spec.seed {
            let opts = UploadToContainerOptionsBuilder::default()
                .path("/var/lib/nos")
                .build();
            self.docker
                .upload_to_container(name, Some(opts), body_full(tar_one(file, contents)?.into()))
                .await
                .with_context(|| format!("seeding {file} into {name}"))?;
        }
        self.docker
            .start_container(name, None)
            .await
            .with_context(|| format!("starting container {name}"))?;
        Ok(())
    }

    /// Starts a plain (non-nos) container: `image` on `network` at `ip`, with
    /// one file `(dir, name, contents)` uploaded before it starts. No volumes,
    /// no capabilities — for a third-party BGP speaker acting as a test peer.
    pub async fn start_plain(
        &self,
        name: &str,
        image: &str,
        network: &str,
        ip: &str,
        cmd: &[&str],
        seed: (&str, &str, &[u8]),
    ) -> anyhow::Result<()> {
        self.start_plain_caps(name, image, network, ip, cmd, seed, &[])
            .await
    }

    /// A container with no seeded file, for images that run as they are
    /// (`FROM scratch` GoBMP).
    pub async fn start_plain_unseeded(
        &self,
        name: &str,
        image: &str,
        network: &str,
        ip: &str,
        cmd: &[&str],
    ) -> anyhow::Result<()> {
        self.start_plain_inner(name, image, network, ip, None, cmd, None, &[])
            .await
    }

    /// `start_plain` with extra capabilities (FRR's daemons need
    /// `NET_ADMIN`/`NET_RAW`/`SYS_ADMIN` to start at all).
    #[allow(clippy::too_many_arguments)]
    pub async fn start_plain_caps(
        &self,
        name: &str,
        image: &str,
        network: &str,
        ip: &str,
        cmd: &[&str],
        seed: (&str, &str, &[u8]),
        caps: &[&str],
    ) -> anyhow::Result<()> {
        self.start_plain_inner(name, image, network, ip, None, cmd, Some(seed), caps)
            .await
    }

    /// A tool shipped in the nos image (`image()`) run in place of its
    /// `nos-watchdogd` entrypoint, e.g. `nos-rtr-stub`.
    pub async fn start_nos_tool(
        &self,
        name: &str,
        network: &str,
        ip: &str,
        argv: &[&str],
        caps: &[&str],
    ) -> anyhow::Result<()> {
        self.start_plain_inner(name, &image(), network, ip, Some(argv), &[], None, caps)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_plain_inner(
        &self,
        name: &str,
        image: &str,
        network: &str,
        ip: &str,
        entrypoint: Option<&[&str]>,
        cmd: &[&str],
        seed: Option<(&str, &str, &[u8])>,
        caps: &[&str],
    ) -> anyhow::Result<()> {
        self.container_remove(name).await;
        let (full, network) = (self.n(name), self.n(network));
        let network = network.as_str();
        let endpoint = EndpointSettings {
            ipam_config: Some(EndpointIpamConfig {
                ipv4_address: Some(ip.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let body = ContainerCreateBody {
            image: Some(image.to_string()),
            labels: Some(self.labels()),
            entrypoint: entrypoint.map(|e| e.iter().map(|s| (*s).to_string()).collect()),
            cmd: Some(cmd.iter().map(|s| (*s).to_string()).collect()),
            host_config: Some(HostConfig {
                network_mode: Some(network.to_string()),
                cap_add: Some(caps.iter().map(|c| (*c).to_string()).collect()),
                ..Default::default()
            }),
            networking_config: Some(NetworkingConfig {
                endpoints_config: Some(HashMap::from([(network.to_string(), endpoint)])),
            }),
            ..Default::default()
        };
        let opts = CreateContainerOptionsBuilder::default().name(&full).build();
        self.docker
            .create_container(Some(opts), body)
            .await
            .with_context(|| format!("creating container {name}"))?;
        if let Some((dir, file, contents)) = seed {
            self.upload(name, dir, file, contents).await?;
        }
        self.docker
            .start_container(&full, None)
            .await
            .with_context(|| format!("starting container {name}"))?;
        Ok(())
    }

    /// Writes `dir/file` into a container, created or running.
    pub async fn upload(
        &self,
        name: &str,
        dir: &str,
        file: &str,
        contents: &[u8],
    ) -> anyhow::Result<()> {
        let opts = UploadToContainerOptionsBuilder::default().path(dir).build();
        self.docker
            .upload_to_container(
                &self.n(name),
                Some(opts),
                body_full(tar_one(file, contents)?.into()),
            )
            .await
            .with_context(|| format!("writing {dir}/{file} into {name}"))
    }

    /// Starts an end-host container: `image` on `network` with `NET_ADMIN`/
    /// `NET_RAW` (its own bonds, addresses, `tcpdump`), idling. Further
    /// networks are attached with `network_connect`.
    pub async fn start_host(&self, name: &str, image: &str, network: &str) -> anyhow::Result<()> {
        self.container_remove(name).await;
        let (full, network) = (self.n(name), self.n(network));
        let body = ContainerCreateBody {
            image: Some(image.to_string()),
            labels: Some(self.labels()),
            cmd: Some(vec!["sleep".to_string(), "infinity".to_string()]),
            host_config: Some(HostConfig {
                cap_add: Some(["NET_ADMIN", "NET_RAW"].map(String::from).to_vec()),
                network_mode: Some(network),
                ..Default::default()
            }),
            ..Default::default()
        };
        let opts = CreateContainerOptionsBuilder::default().name(&full).build();
        self.docker
            .create_container(Some(opts), body)
            .await
            .with_context(|| format!("creating container {name}"))?;
        self.docker
            .start_container(&full, None)
            .await
            .with_context(|| format!("starting container {name}"))?;
        Ok(())
    }

    /// Runs `cmd` inside a running container; `(exit code, stdout+stderr)`.
    /// A NOS router (`router-*`) is exec'd as `nos`, the shared client user
    /// (group `nos` reaches the sockets): the image's default user is the
    /// watchdog's `nos-wd` (#512), and each daemon has its own uid (#513), so
    /// `nos` can neither `kill` them nor read their state (`exec_root` does).
    /// Other containers keep their own.
    pub async fn exec(&self, container: &str, cmd: &[&str]) -> anyhow::Result<(i64, String)> {
        // router-f (FRR) and router-g (ExaBGP) are third-party images with no `nos` user.
        let user = (container.starts_with("router-")
            && !matches!(container, "router-f" | "router-g"))
        .then_some("nos");
        self.exec_as(container, user, cmd).await
    }

    /// `exec` as root (it holds `CAP_KILL`/`DAC_OVERRIDE` in Docker's default
    /// set): to signal or read files of any daemon uid.
    pub async fn exec_root(&self, container: &str, cmd: &[&str]) -> anyhow::Result<(i64, String)> {
        self.exec_as(container, Some("root"), cmd).await
    }

    /// `exec` as `user` (the container's default when `None`).
    pub async fn exec_as(
        &self,
        container: &str,
        user: Option<&str>,
        cmd: &[&str],
    ) -> anyhow::Result<(i64, String)> {
        use bollard::exec::StartExecResults;
        use bollard::models::ExecConfig;
        let created = self
            .docker
            .create_exec(
                &self.n(container),
                ExecConfig {
                    cmd: Some(cmd.iter().map(|s| (*s).to_string()).collect()),
                    user: user.map(String::from),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let mut out = String::new();
        if let StartExecResults::Attached { mut output, .. } =
            self.docker.start_exec(&created.id, None).await?
        {
            while let Some(chunk) = output.next().await {
                out.push_str(&chunk?.to_string());
            }
        }
        let code = self.docker.inspect_exec(&created.id).await?.exit_code;
        Ok((code.unwrap_or(-1), out))
    }

    /// SIGKILL: the process gets no chance to shut down cleanly.
    pub async fn kill_process(&self, container: &str, comm: &str) -> anyhow::Result<()> {
        self.signal_process(container, comm, "-9").await
    }

    /// Sends `signal` (a `kill` flag, e.g. `-TERM`) to every process named
    /// `comm`. The runtime image has no `ps`/`pgrep`, so scan `/proc/*/comm`
    /// (POSIX sh only).
    pub async fn signal_process(
        &self,
        container: &str,
        comm: &str,
        signal: &str,
    ) -> anyhow::Result<()> {
        let script = format!(
            "for p in /proc/[0-9]*; do [ -r \"$p/comm\" ] || continue; \
             if [ \"$(cat \"$p/comm\" 2>/dev/null)\" = \"{comm}\" ]; then kill {signal} \"${{p#/proc/}}\"; fi; done"
        );
        self.exec_root(container, &["sh", "-c", &script]).await?;
        Ok(())
    }

    /// `kill_process` for only the `comm` processes whose command line holds
    /// `needle` (one `nos-ribd` among several: `--table <name>`).
    pub async fn kill_process_matching(
        &self,
        container: &str,
        comm: &str,
        needle: &str,
    ) -> anyhow::Result<()> {
        let script = format!(
            "for p in /proc/[0-9]*; do [ \"$(cat \"$p/comm\" 2>/dev/null)\" = \"{comm}\" ] || continue; \
             case \"$(tr '\\0' ' ' < \"$p/cmdline\")\" in *\"{needle}\"*) kill -9 \"${{p#/proc/}}\";; esac; done"
        );
        self.exec_root(container, &["sh", "-c", &script]).await?;
        Ok(())
    }

    pub async fn pid(&self, container: &str) -> anyhow::Result<i64> {
        let info = self
            .docker
            .inspect_container(&self.n(container), None)
            .await?;
        info.state
            .and_then(|s| s.pid)
            .with_context(|| format!("no pid for {container}"))
    }

    /// The MAC address docker gave `container`'s interface on `network`.
    pub async fn mac(&self, container: &str, network: &str) -> anyhow::Result<String> {
        let info = self
            .docker
            .inspect_container(&self.n(container), None)
            .await?;
        let network = self.n(network);
        info.network_settings
            .and_then(|s| s.networks)
            .and_then(|mut n| n.remove(&network))
            .and_then(|e| e.mac_address)
            .filter(|m| !m.is_empty())
            .with_context(|| format!("{container} has no MAC address on {network}"))
    }

    /// Whole stdout+stderr of a container (only used where REST itself is what
    /// the check kills, so its own log stream is gone).
    pub async fn logs(&self, container: &str) -> anyhow::Result<String> {
        self.logs_raw(&self.n(container)).await
    }

    async fn logs_raw(&self, container: &str) -> anyhow::Result<String> {
        let opts = LogsOptionsBuilder::default()
            .stdout(true)
            .stderr(true)
            .build();
        let mut stream = self.docker.logs(container, Some(opts));
        let mut out = String::new();
        while let Some(chunk) = stream.next().await {
            out.push_str(&chunk?.to_string());
        }
        Ok(out)
    }

    // --- helper container (iproute2) for veths ---

    /// Builds a tiny debian+iproute2 image once, from an in-memory tar.
    pub async fn ensure_helper_image(&self, tag: &str) -> anyhow::Result<()> {
        self.ensure_image(
            tag,
            "FROM debian:bookworm-slim\n\
            RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \\\n \
            && rm -rf /var/lib/apt/lists/*\n",
        )
        .await
    }

    /// Pulls `image` (a `repo:tag`) unless it is already present.
    pub async fn ensure_pulled(&self, image: &str) -> anyhow::Result<()> {
        if self.docker.inspect_image(image).await.is_ok() {
            return Ok(());
        }
        let _lock = helper_build_lock().await?;
        if self.docker.inspect_image(image).await.is_ok() {
            return Ok(());
        }
        let opts = bollard::query_parameters::CreateImageOptionsBuilder::default()
            .from_image(image)
            .build();
        let mut stream = self.docker.create_image(Some(opts), None, None);
        while let Some(step) = stream.next().await {
            step.with_context(|| format!("pulling image {image}"))?;
        }
        Ok(())
    }

    /// Builds `tag` from an inline Dockerfile, once.
    pub async fn ensure_image(&self, tag: &str, dockerfile: &str) -> anyhow::Result<()> {
        if self.docker.inspect_image(tag).await.is_ok() {
            return Ok(());
        }
        // Two labs share these tags: the second waits, then finds it built.
        let _lock = helper_build_lock().await?;
        if self.docker.inspect_image(tag).await.is_ok() {
            return Ok(());
        }
        let opts = BuildImageOptionsBuilder::default()
            .dockerfile("Dockerfile")
            .t(tag)
            .rm(true)
            .build();
        let mut stream = self.docker.build_image(
            opts,
            None,
            Some(body_full(
                tar_one("Dockerfile", dockerfile.as_bytes())?.into(),
            )),
        );
        while let Some(step) = stream.next().await {
            let step = step.with_context(|| format!("building image {tag}"))?;
            if let Some(err) = step.error_detail.and_then(|e| e.message) {
                bail!("building image {tag}: {err}");
            }
        }
        Ok(())
    }

    /// Runs `ip <args>` in a throwaway privileged container joined to
    /// `container`'s network namespace (or the host pid namespace when
    /// `host_pid`), returning its output; errors on a non-zero exit.
    pub async fn ip(
        &self,
        helper_image: &str,
        netns_of: Option<&str>,
        host_pid: bool,
        args: &[&str],
    ) -> anyhow::Result<String> {
        let mut cmd = vec!["ip"];
        cmd.extend_from_slice(args);
        self.helper(helper_image, netns_of, host_pid, &cmd).await
    }

    /// Runs any iproute2 command (`bridge fdb ...`) in `container`'s network
    /// namespace — the runtime image has no iproute2, so the helper image
    /// does it, exactly like `ip`.
    pub async fn in_netns(
        &self,
        helper_image: &str,
        container: &str,
        cmd: &[&str],
    ) -> anyhow::Result<String> {
        self.helper(helper_image, Some(container), false, cmd).await
    }

    async fn helper(
        &self,
        helper_image: &str,
        netns_of: Option<&str>,
        host_pid: bool,
        cmd: &[&str],
    ) -> anyhow::Result<String> {
        let body = ContainerCreateBody {
            image: Some(helper_image.to_string()),
            labels: Some(self.labels()),
            cmd: Some(cmd.iter().map(|s| (*s).to_string()).collect()),
            host_config: Some(HostConfig {
                privileged: Some(true),
                network_mode: netns_of.map(|c| format!("container:{}", self.n(c))),
                pid_mode: host_pid.then(|| "host".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let created = self.docker.create_container(None, body).await?;
        let id = created.id;
        self.docker.start_container(&id, None).await?;
        let mut wait = self.docker.wait_container(&id, None);
        let code = match wait.next().await {
            Some(Ok(r)) => r.status_code,
            Some(Err(bollard::errors::Error::DockerContainerWaitError { code, .. })) => code,
            Some(Err(e)) => return Err(e.into()),
            None => -1,
        };
        let out = self.logs_raw(&id).await.unwrap_or_default();
        self.container_remove_raw(&id).await;
        if code != 0 {
            bail!("{}: exit {code}: {}", cmd.join(" "), out.trim());
        }
        Ok(out)
    }
}

/// The host-wide lock that serialises building/pulling the shared helper images
/// (`nos-e2e-gobgp:local`, FRR, the netns helper) across labs; an `flock`, so a
/// killed run never leaves it held.
async fn helper_build_lock() -> anyhow::Result<std::fs::File> {
    tokio::task::spawn_blocking(|| {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open("/tmp/nos-e2e-helper-build.lock")
            .context("opening the helper-image build lock")?;
        f.lock().context("taking the helper-image build lock")?;
        Ok(f)
    })
    .await?
}

/// A tar archive holding one regular file (mode 0644).
fn tar_one(path: &str, contents: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, path, contents)?;
    Ok(builder.into_inner()?)
}

#[cfg(test)]
mod image_tests {
    use super::image_from;

    #[test]
    fn image_env_override() {
        assert_eq!(image_from(None), "nos:local");
        assert_eq!(image_from(Some(String::new())), "nos:local");
        assert_eq!(image_from(Some("nos:issue-7".into())), "nos:issue-7");
    }
}
