//! The Docker daemon, driven through `bollard` — no `docker` CLI.

use std::collections::HashMap;

use anyhow::{bail, Context};
use bollard::models::{
    ContainerCreateBody, EndpointIpamConfig, EndpointSettings, HostConfig, Ipam, IpamConfig,
    NetworkConnectRequest, NetworkCreateRequest, NetworkDisconnectRequest, NetworkingConfig,
    VolumeCreateRequest,
};
use bollard::query_parameters::{
    BuildImageOptionsBuilder, CreateContainerOptionsBuilder, LogsOptionsBuilder,
    RemoveContainerOptionsBuilder, RemoveVolumeOptionsBuilder, UploadToContainerOptionsBuilder,
};
use bollard::{body_full, Docker};
use futures::StreamExt;

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
}

impl Dock {
    pub fn connect() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults().context("connecting to docker")?;
        Ok(Self { docker })
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
        self.docker.inspect_network(name, None).await.is_ok()
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
            name: name.to_string(),
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
        let _ = self.docker.remove_network(name).await;
    }

    pub async fn network_connect(&self, network: &str, container: &str) {
        let req = NetworkConnectRequest {
            container: container.to_string(),
            ..Default::default()
        };
        let _ = self.docker.connect_network(network, req).await;
    }

    /// `network_connect` at a fixed address, so nos's config can name it.
    pub async fn network_connect_ip(
        &self,
        network: &str,
        container: &str,
        ip: &str,
    ) -> anyhow::Result<()> {
        let req = NetworkConnectRequest {
            container: container.to_string(),
            endpoint_config: Some(EndpointSettings {
                ipam_config: Some(EndpointIpamConfig {
                    ipv4_address: Some(ip.to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        self.docker
            .connect_network(network, req)
            .await
            .with_context(|| format!("connecting {container} to {network}"))
    }

    pub async fn network_disconnect(&self, network: &str, container: &str) {
        let req = NetworkDisconnectRequest {
            container: container.to_string(),
            force: Some(true),
        };
        let _ = self.docker.disconnect_network(network, req).await;
    }

    // --- volumes / containers ---

    async fn volume_recreate(&self, name: &str) -> anyhow::Result<()> {
        let opts = RemoveVolumeOptionsBuilder::default().force(true).build();
        let _ = self.docker.remove_volume(name, Some(opts)).await;
        self.docker
            .create_volume(VolumeCreateRequest {
                name: Some(name.to_string()),
                ..Default::default()
            })
            .await
            .with_context(|| format!("creating volume {name}"))?;
        Ok(())
    }

    pub async fn container_remove(&self, name: &str) {
        let opts = RemoveContainerOptionsBuilder::default().force(true).build();
        let _ = self.docker.remove_container(name, Some(opts)).await;
    }

    pub async fn volume_remove(&self, name: &str) {
        let opts = RemoveVolumeOptionsBuilder::default().force(true).build();
        let _ = self.docker.remove_volume(name, Some(opts)).await;
    }

    /// Replaces any existing container of that name (with fresh volumes, so no
    /// state — registries, log buffer — leaks between runs), seeds it, starts it.
    pub async fn start(&self, spec: &ContainerSpec<'_>) -> anyhow::Result<()> {
        let (name, network) = (spec.name, spec.network);
        self.container_remove(name).await;
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
                // Mirrors docker-compose.yml: read-only rootfs, writable /tmp;
                // no `no-new-privileges` (it ignores file capabilities, the
                // watchdog's cap_setuid/cap_setgid/cap_chown included).
                readonly_rootfs: Some(true),
                tmpfs: Some(HashMap::from([("/tmp".to_string(), String::new())])),
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
        let endpoint = EndpointSettings {
            ipam_config: Some(EndpointIpamConfig {
                ipv4_address: Some(ip.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let body = ContainerCreateBody {
            image: Some(image.to_string()),
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
        let opts = CreateContainerOptionsBuilder::default().name(name).build();
        self.docker
            .create_container(Some(opts), body)
            .await
            .with_context(|| format!("creating container {name}"))?;
        if let Some((dir, file, contents)) = seed {
            self.upload(name, dir, file, contents).await?;
        }
        self.docker
            .start_container(name, None)
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
            .upload_to_container(name, Some(opts), body_full(tar_one(file, contents)?.into()))
            .await
            .with_context(|| format!("writing {dir}/{file} into {name}"))
    }

    /// Starts an end-host container: `image` on `network` with `NET_ADMIN`/
    /// `NET_RAW` (its own bonds, addresses, `tcpdump`), idling. Further
    /// networks are attached with `network_connect`.
    pub async fn start_host(&self, name: &str, image: &str, network: &str) -> anyhow::Result<()> {
        self.container_remove(name).await;
        let body = ContainerCreateBody {
            image: Some(image.to_string()),
            cmd: Some(vec!["sleep".to_string(), "infinity".to_string()]),
            host_config: Some(HostConfig {
                cap_add: Some(["NET_ADMIN", "NET_RAW"].map(String::from).to_vec()),
                network_mode: Some(network.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let opts = CreateContainerOptionsBuilder::default().name(name).build();
        self.docker
            .create_container(Some(opts), body)
            .await
            .with_context(|| format!("creating container {name}"))?;
        self.docker
            .start_container(name, None)
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
                container,
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
        let info = self.docker.inspect_container(container, None).await?;
        info.state
            .and_then(|s| s.pid)
            .with_context(|| format!("no pid for {container}"))
    }

    /// The MAC address docker gave `container`'s interface on `network`.
    pub async fn mac(&self, container: &str, network: &str) -> anyhow::Result<String> {
        let info = self.docker.inspect_container(container, None).await?;
        info.network_settings
            .and_then(|s| s.networks)
            .and_then(|mut n| n.remove(network))
            .and_then(|e| e.mac_address)
            .filter(|m| !m.is_empty())
            .with_context(|| format!("{container} has no MAC address on {network}"))
    }

    /// Whole stdout+stderr of a container (only used where REST itself is what
    /// the check kills, so its own log stream is gone).
    pub async fn logs(&self, container: &str) -> anyhow::Result<String> {
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
            cmd: Some(cmd.iter().map(|s| (*s).to_string()).collect()),
            host_config: Some(HostConfig {
                privileged: Some(true),
                network_mode: netns_of.map(|c| format!("container:{c}")),
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
        let out = self.logs(&id).await.unwrap_or_default();
        self.container_remove(&id).await;
        if code != 0 {
            bail!("{}: exit {code}: {}", cmd.join(" "), out.trim());
        }
        Ok(out)
    }
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
