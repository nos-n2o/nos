use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener};
use nos_proto::{FdbEvent, FdbRequest, IpcCodec, Role};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, trace, warn};

use crate::fdb::Fdb;

struct Context {
    domain: String,
    fdb: Arc<Fdb>,
}

/// Binds `listen_socket` and spawns the accept loop.
pub fn start(
    listen_socket: &Path,
    domain: String,
    fdb: Arc<Fdb>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(domain = %domain, socket = %listen_socket.display(), "FDB IPC server listening");
    let ctx = Arc::new(Context { domain, fdb });
    Ok(tokio::spawn(accept_loop(listener, ctx)))
}

/// Who may send what. The route push becomes kernel forwarding state, so it
/// is `nos-bgpd`'s alone; queries are for people (and `Restd` for them).
// ponytail: role-level only — `bgpd/r2` could still push into r1's domain;
// binding an instance to its domains needs a config lookup.
fn allowed(role: Role, req: &FdbRequest) -> bool {
    match req {
        FdbRequest::GetMacs => matches!(role, Role::User | Role::Restd),
        FdbRequest::PushEvpnRoutes(_) => role == Role::Bgpd,
    }
}

async fn accept_loop(listener: Listener, ctx: Arc<Context>) {
    loop {
        let incoming = listener.accept_resilient().await;
        tokio::spawn(serve(incoming, ctx.clone()));
    }
}

async fn serve(incoming: Incoming, ctx: Arc<Context>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, name, ctx).await,
        Err(e) => debug!(domain = %ctx.domain, error = %e, "FDB IPC handshake refused"),
    }
}

async fn handle_connection(stream: nos_pki::Stream, role: Role, name: String, ctx: Arc<Context>) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<FdbRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<FdbEvent>::default());
    let mut staging = nos_proto::chunk::FullStaging::default();

    while let Some(msg) = reader.next().await {
        let req = match msg {
            Ok(req) if !allowed(role, &req) => {
                warn!(
                    domain = %ctx.domain, role = role.as_str(), name = %name,
                    "FDB request refused: this role may not send it"
                );
                break;
            }
            Ok(req) => req,
            Err(e) => {
                warn!(domain = %ctx.domain, error = %e, "FDB IPC read error");
                break;
            }
        };
        trace!(domain = %ctx.domain, request = ?req, "serving FDB request");
        match req {
            FdbRequest::GetMacs => {
                if writer
                    .send(FdbEvent::Table(ctx.fdb.table().await))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            // Fire-and-forget, no reply.
            FdbRequest::PushEvpnRoutes(update) => {
                // A chunked `Full` is applied once, on its closing frame.
                if let Some((update, parts)) = update.absorb(&mut staging) {
                    if parts > 1
                        && let nos_proto::EvpnUpdate::Full(r) = &update
                    {
                        info!(
                            domain = %ctx.domain,
                            routes = r.len(),
                            parts,
                            "assembled chunked evpn route snapshot"
                        );
                    }
                    ctx.fdb.apply_push(update).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod authz_tests {
    use nos_proto::EvpnUpdate;

    use super::*;

    #[test]
    fn only_bgpd_pushes_and_only_people_query() {
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &FdbRequest::PushEvpnRoutes(EvpnUpdate::Full(vec![]))),
                role == Role::Bgpd,
                "{role:?} push"
            );
            assert_eq!(
                allowed(role, &FdbRequest::GetMacs),
                matches!(role, Role::User | Role::Restd),
                "{role:?} query"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nos_pki::{PeerId, Stream};
    use nos_proto::{EvpnKey, EvpnRoute, EvpnUpdate, MacSource};

    use super::*;
    use crate::driver::NoopFdbDriver;
    use crate::fdb::Ready;

    type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<FdbEvent>>;
    type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<FdbRequest>>;

    const RT: u64 = 0x0002_fde8_0000_2774;

    async fn connect(path: &Path, role: Role) -> (Reader, Writer) {
        let id = nos_pki::testing::shared().identity(role.as_str(), "x");
        let s = id.connect(path, &PeerId::new("fdbd", "")).await.unwrap();
        let (r, w) = tokio::io::split(s);
        (
            FramedRead::new(r, IpcCodec::default()),
            FramedWrite::new(w, IpcCodec::default()),
        )
    }

    /// A ready domain, so a pushed remote MAC lands in `table()`.
    async fn server(path: &Path) -> Arc<Fdb> {
        let fdb = Fdb::new("d1".into(), Arc::new(NoopFdbDriver), Duration::ZERO);
        fdb.set_ready(Some(Ready {
            vni: 10100,
            bridge: "br1".into(),
            vtep: "192.0.2.1".parse().unwrap(),
            underlay: "eth0".into(),
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
            rt_import: vec![RT],
            rt_export: vec![RT],
            bgp_instance: "r1".into(),
            arp: false,
            connected: Vec::new(),
            es_ports: Vec::new(),
            neigh_suppress: false,
            max_remote_macs: None,
            irb: None,
        }))
        .await;
        let id = nos_pki::testing::shared().identity("fdbd", "");
        drop(start(path, "d1".into(), fdb.clone(), &id).unwrap());
        fdb
    }

    fn push() -> FdbRequest {
        FdbRequest::PushEvpnRoutes(EvpnUpdate::Add(EvpnRoute {
            key: EvpnKey::Mac {
                rd: [0; 8],
                mac: [0, 0, 0, 0, 0, 1],
            },
            vni: 10100,
            next_hop: "192.0.2.9".parse().unwrap(),
            ext_communities: vec![RT],
            esi: [0; 10],
            l3_vni: None,
        }))
    }

    async fn next(r: &mut Reader) -> Option<FdbEvent> {
        tokio::time::timeout(Duration::from_secs(5), r.next())
            .await
            .expect("connection left open")
            .map(|e| e.unwrap())
    }

    async fn remote_macs(fdb: &Fdb) -> usize {
        fdb.table()
            .await
            .macs
            .iter()
            .filter(|m| m.source == MacSource::Remote)
            .count()
    }

    #[tokio::test]
    async fn only_people_query() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("fdb.sock");
        let _fdb = server(&path).await;
        for role in Role::ALL {
            let (mut r, mut w) = connect(&path, role).await;
            w.send(FdbRequest::GetMacs).await.unwrap();
            let reply = next(&mut r).await;
            if matches!(role, Role::User | Role::Restd) {
                assert!(
                    matches!(reply, Some(FdbEvent::Table(ref t)) if t.domain == "d1"),
                    "{role:?}: {reply:?}"
                );
            } else {
                assert!(reply.is_none(), "{role:?} must get no reply");
            }
        }
    }

    #[tokio::test]
    async fn only_bgpd_pushes() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("fdb.sock");
        let fdb = server(&path).await;

        // Every non-bgpd role: closed, nothing applied.
        for role in Role::ALL.into_iter().filter(|r| *r != Role::Bgpd) {
            let (mut r, mut w) = connect(&path, role).await;
            w.send(push()).await.unwrap();
            assert!(next(&mut r).await.is_none(), "{role:?} must be closed");
            assert_eq!(remote_macs(&fdb).await, 0, "{role:?} push applied");
        }

        // `bgpd` is applied, with no reply frame.
        let (_r, mut w) = connect(&path, Role::Bgpd).await;
        w.send(push()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while remote_macs(&fdb).await != 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("bgpd push applied");
    }
}

#[cfg(test)]
mod chunked_tests {
    use std::time::Duration;

    use nos_pki::PeerId;
    use nos_proto::{EvpnKey, EvpnRoute, EvpnUpdate, MacSource};

    use super::*;
    use crate::driver::NoopFdbDriver;
    use crate::fdb::Ready;

    const RT: u64 = 0x0002_fde8_0000_2774;

    async fn remote(fdb: Arc<Fdb>) -> usize {
        fdb.table()
            .await
            .macs
            .iter()
            .filter(|m| m.source == MacSource::Remote)
            .count()
    }

    #[tokio::test]
    async fn a_chunked_full_is_applied_only_on_its_closing_frame() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("fdb.sock");
        let fdb = Fdb::new("d1".into(), Arc::new(NoopFdbDriver), Duration::ZERO);
        fdb.set_ready(Some(Ready {
            vni: 10100,
            bridge: "br1".into(),
            vtep: "192.0.2.1".parse().unwrap(),
            underlay: "eth0".into(),
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
            rt_import: vec![RT],
            rt_export: vec![RT],
            bgp_instance: "r1".into(),
            arp: false,
            connected: Vec::new(),
            es_ports: Vec::new(),
            neigh_suppress: false,
            max_remote_macs: None,
            irb: None,
        }))
        .await;
        let id = nos_pki::testing::shared().identity("fdbd", "");
        let _srv = start(&path, "d1".into(), fdb.clone(), &id).unwrap();

        let routes: Vec<EvpnRoute> = (0..30u8)
            .map(|i| EvpnRoute {
                key: EvpnKey::Mac {
                    rd: [0; 8],
                    mac: [0, 0, 0, 0, 0, i],
                },
                vni: 10100,
                next_hop: "192.0.2.9".parse().unwrap(),
                ext_communities: vec![RT],
                esi: [0; 10],
                l3_vni: None,
            })
            .collect();
        let frames = EvpnUpdate::Full(routes).split_with(200);
        assert!(frames.len() > 2);
        let last = frames.len() - 1;

        let s = nos_pki::testing::shared()
            .identity("bgpd", "x")
            .connect(&path, &PeerId::new("fdbd", ""))
            .await
            .unwrap();
        let (_r, w) = tokio::io::split(s);
        let mut w = FramedWrite::new(w, IpcCodec::<FdbRequest>::default());
        for f in &frames[..last] {
            w.send(FdbRequest::PushEvpnRoutes(f.clone())).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(remote(fdb.clone()).await, 0, "half a snapshot applied");
        w.send(FdbRequest::PushEvpnRoutes(frames[last].clone()))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while remote(fdb.clone()).await != 30 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("closing Full applied the whole set");
    }
}
