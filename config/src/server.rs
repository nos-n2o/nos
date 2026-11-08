use std::fmt;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::str::FromStr;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, PeerId};
use nos_proto::{Event, IpcCodec, Request, Role};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, warn};

use crate::authz;
use crate::store::ConfigStore;

/// Where the IPC server binds: a Unix socket path (absolute or relative to
/// the CWD), e.g. `/run/nos/config.sock`.
///
/// There is deliberately no TCP variant: every connection is mutually
/// authenticated TLS over a Unix socket, and a network listener would need
/// its own answer to "who may reach it".
#[derive(Debug, Clone)]
pub enum ListenAddr {
    Unix(PathBuf),
}

impl FromStr for ListenAddr {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ListenAddr::Unix(PathBuf::from(s)))
    }
}

impl fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ListenAddr::Unix(path) = self;
        write!(f, "unix:{}", path.display())
    }
}

/// Who is on the other end of one connection, from its certificate.
struct Caller {
    role: Role,
    name: String,
}

impl Caller {
    fn from_peer(peer: PeerId) -> Option<Self> {
        Some(Self {
            role: Role::parse(&peer.role)?,
            name: peer.name,
        })
    }
}

/// Binds the given address and spawns the IPC accept loop.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    addr: &ListenAddr,
    store: ConfigStore,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let ListenAddr::Unix(path) = addr;
    let listener = identity.listen(path)?;
    info!(listen = %addr, "config IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, store)))
}

async fn accept_loop(listener: Listener, store: ConfigStore) {
    loop {
        match listener.accept().await {
            Ok(incoming) => {
                tokio::spawn(serve(incoming, store.clone()));
            }
            Err(e) => {
                error!(error = %e, "IPC accept loop terminated");
                break;
            }
        }
    }
}

/// One connection, handshake to hang-up. The handshake runs here, in the
/// connection's own task, so a slow peer never stalls the accept loop.
async fn serve(incoming: Incoming, store: ConfigStore) {
    let (stream, peer) = match incoming.handshake().await {
        Ok(ok) => ok,
        Err(e) => {
            debug!(error = %e, "IPC tls handshake failed");
            return;
        }
    };
    let Some(caller) = peer.and_then(Caller::from_peer) else {
        warn!("IPC peer's certificate carries no recognised role, dropping it");
        return;
    };
    handle_connection(stream, caller, store).await;
}

/// Handles every `Request` variant except `Subscribe`/`Unsubscribe`, which
/// the caller manages itself since they control the connection's forwarder
/// task rather than producing a single reply `Event`.
async fn dispatch_request(store: &ConfigStore, caller: &Caller, req: Request) -> Option<Event> {
    Some(match req {
        Request::Get => Event::Config(store.running_snapshot().await.for_role(caller.role)),
        Request::ListBgpInstances => Event::InstanceNames(store.bgp_instance_names().await),
        Request::ListOspfInstances => Event::InstanceNames(store.ospf_instance_names().await),
        Request::ListOspfv3Instances => Event::InstanceNames(store.ospfv3_instance_names().await),
        Request::GetRestApi { table } => Event::RestApi(store.rest_api(&table).await),
        Request::UserExists { name } => Event::UserExists(store.user_exists(&name).await),
        Request::Save => match store.save_to_disk().await {
            Ok(()) => Event::Saved,
            Err(e) => {
                warn!(error = %e, "save to disk failed");
                Event::Error(e.to_string())
            }
        },
        Request::OpenTransaction { name, base, actor } => {
            debug!(transaction = %name, actor = ?effective_actor(caller, actor), "transaction open");
            match store.open_transaction(&name, base).await {
                Ok(snap) => Event::Transaction(snap),
                Err(e) => {
                    debug!(transaction = %name, error = %e, "open transaction failed");
                    Event::Error(e.to_string())
                }
            }
        }
        Request::ApplyOp { name, op, actor } => match store.apply_op(&name, op).await {
            Ok(snap) => {
                debug!(transaction = %name, actor = ?effective_actor(caller, actor), "transaction op applied");
                Event::Transaction(snap)
            }
            Err(e) => {
                debug!(transaction = %name, error = %e, "apply op failed");
                Event::Error(e.to_string())
            }
        },
        Request::GetTransaction { name } => match store.get_transaction(&name).await {
            Ok(snap) => Event::Transaction(snap),
            Err(e) => {
                debug!(transaction = %name, error = %e, "get transaction failed");
                Event::Error(e.to_string())
            }
        },
        Request::CommitTransaction {
            name,
            if_match,
            actor,
        } => match store.commit_transaction(&name, if_match).await {
            Ok(warnings) => {
                info!(transaction = ?name, actor = ?effective_actor(caller, actor), "config commit audit");
                for w in &warnings {
                    warn!(transaction = ?name, warning = %w, "commit warning");
                }
                Event::Committed { warnings }
            }
            Err(e) => {
                warn!(transaction = %name, error = %e, "commit failed");
                Event::Error(e.to_string())
            }
        },
        Request::DiscardTransaction { name, if_match } => {
            match store.discard_transaction(&name, if_match).await {
                Ok(()) => Event::Discarded,
                Err(e) => {
                    debug!(transaction = %name, error = %e, "discard transaction failed");
                    Event::Error(e.to_string())
                }
            }
        }
        Request::Describe { topic } => Event::Description(crate::docs::command_doc(topic)),
        Request::DiffTransaction { name } => match store.diff_transaction(&name).await {
            Ok(diff) => Event::Diff(diff),
            Err(e) => {
                debug!(transaction = %name, error = %e, "diff transaction failed");
                Event::Error(e.to_string())
            }
        },
        Request::SetTransactionPath {
            name,
            path,
            value,
            if_match,
            position,
        } => {
            match store
                .set_transaction_path(&name, &path, value.as_deref(), if_match, position)
                .await
            {
                Ok(snap) => Event::Transaction(snap),
                Err(e) => {
                    debug!(transaction = %name, error = %e, "set transaction path failed");
                    Event::Error(e.to_string())
                }
            }
        }
        Request::EditTransactionPath {
            name,
            path,
            value,
            if_match,
            position,
        } => {
            match store
                .edit_transaction_path(&name, &path, value.as_deref(), if_match, position)
                .await
            {
                Ok(e) => Event::TransactionEdit {
                    generation: e.generation,
                    dirty: e.dirty,
                    value: e.value,
                },
                Err(e) => {
                    debug!(transaction = %name, error = %e, "edit transaction path failed");
                    Event::Error(e.to_string())
                }
            }
        }
        Request::UpgradePasswordHash { user, old, new } => {
            match store.upgrade_password_hash(&user, &old, new).await {
                Ok(()) => Event::Committed { warnings: vec![] },
                Err(e) => {
                    debug!(user = ?user, error = %e, "password hash upgrade refused");
                    Event::Error(e.to_string())
                }
            }
        }
        Request::Subscribe | Request::Unsubscribe | Request::SubscribeDiff { .. } => return None,
    })
}

/// Who a transaction request is attributed to. A `User` is its certificate
/// name, whatever the body says; `Restd` vouches for the REST user it names;
/// anyone else has no attribution to give. Debug-printed by callers, so a
/// hostile name can't forge a log line.
fn effective_actor(caller: &Caller, body: Option<String>) -> String {
    match caller.role {
        Role::Restd => body.unwrap_or_else(|| "unknown".to_string()),
        _ => caller.name.clone(),
    }
}

async fn handle_connection<S>(stream: S, caller: Caller, store: ConfigStore)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<Request>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<Event>::default());

    // mpsc bridges the broadcast channel to this connection so we never hold
    // a &mut borrow across select! arms. The forwarder task builds the exact
    // `Event` to send (Config for Subscribe, Diff for SubscribeDiff), so this
    // channel is type-erased at the Event level rather than tied to one kind
    // of subscription.
    let (sub_tx, mut sub_rx) = mpsc::channel::<Event>(16);
    let mut sub_task: Option<JoinHandle<()>> = None;
    // A Subscribe/SubscribeDiff client is expected to send its request then
    // drop (or never touch again) its write half — "the caller owns its
    // lifetime" per `client::subscribe`'s doc comment — so seeing EOF/an
    // error on `reader` must not tear down the connection while a
    // subscription is active; it only means no further *requests* will
    // arrive. Once there is no active subscription, EOF/error does mean the
    // connection is genuinely done.
    let mut reader_open = true;

    loop {
        // Each arm only decides *what* happened; the work of acting on it
        // lives in `on_request` below, so this stays a two-line dispatch.
        tokio::select! {
            msg = reader.next(), if reader_open => {
                let req = match msg {
                    Some(Ok(req)) => req,
                    other => {
                        if let Some(Err(e)) = other {
                            warn!(error = %e, "IPC read error");
                        }
                        if sub_task.is_none() {
                            break;
                        }
                        reader_open = false;
                        continue;
                    }
                };
                let flow =
                    on_request(req, &caller, &store, &mut writer, &sub_tx, &mut sub_task).await;
                if flow.is_break() {
                    break;
                }
            }
            Some(event) = sub_rx.recv() => {
                // Only the forwarder feeds `sub_rx`; an Error is its terminal
                // "lagged" (#632): flush it, then close so the client resubscribes.
                let terminal = matches!(event, Event::Error(_));
                if writer.send(event).await.is_err() || terminal {
                    break;
                }
            }
        }
    }

    set_forwarder(&mut sub_task, None);
}

/// Handles one request, replying on `writer`. `Break` means the client is
/// gone (a write failed) and the connection should close.
async fn on_request<S>(
    req: Request,
    caller: &Caller,
    store: &ConfigStore,
    writer: &mut FramedWrite<tokio::io::WriteHalf<S>, IpcCodec<Event>>,
    sub_tx: &mpsc::Sender<Event>,
    sub_task: &mut Option<JoinHandle<()>>,
) -> ControlFlow<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if !authz::allowed(caller.role, &req) {
        // `Request`'s Debug never prints a password (`UserOp` hides it).
        let shown = format!("{req:?}");
        warn!(
            role = caller.role.as_str(), name = ?caller.name,
            request = %shown.chars().take(80).collect::<String>(),
            "config request refused: this role may not send it"
        );
        let _ = writer
            .send(Event::Error("permission denied".to_string()))
            .await;
        return ControlFlow::Break(());
    }
    let reply = match req {
        Request::Subscribe => {
            let (initial, forwarder) = store.subscribe_config(caller.role, sub_tx.clone()).await;
            set_forwarder(sub_task, Some(forwarder));
            debug!("IPC client subscribed");
            initial
        }
        Request::SubscribeDiff { scopes } => {
            debug!(?scopes, "IPC client subscribed to diff");
            let (initial, forwarder) = store
                .subscribe_diff(caller.role, scopes, sub_tx.clone())
                .await;
            set_forwarder(sub_task, Some(forwarder));
            initial
        }
        Request::Unsubscribe => {
            set_forwarder(sub_task, None);
            debug!("IPC client unsubscribed");
            return ControlFlow::Continue(());
        }
        req => match dispatch_request(store, caller, req).await {
            Some(reply) => reply,
            None => return ControlFlow::Continue(()),
        },
    };
    match writer.send(reply).await {
        Ok(()) => ControlFlow::Continue(()),
        Err(_) => ControlFlow::Break(()),
    }
}

/// Installs this connection's forwarder task, aborting whichever one it
/// replaces — `None` both unsubscribes and tears the connection down.
fn set_forwarder(slot: &mut Option<JoinHandle<()>>, next: Option<JoinHandle<()>>) {
    if let Some(previous) = std::mem::replace(slot, next) {
        previous.abort();
    }
}
