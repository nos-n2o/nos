//! Fake IPC servers for tests (#347). Dev-dependency only, behind `fakes`.
//! Every fake speaks real mutual TLS (`nos_pki::testing`) and the daemons'
//! real codecs; the server identity must match what the client dials with.
#![cfg(feature = "fakes")]

mod fakes;
mod ports;
pub use fakes::*;
pub use ports::free_port;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::stream::BoxStream;
use futures::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::codec::{FramedRead, FramedWrite};

use nos_proto::IpcCodec;

/// A running fake. Dropping it aborts the accept loop and every connection.
pub struct Server<Req> {
    pub path: PathBuf,
    seen: Arc<Mutex<Vec<Req>>>,
    connections: Arc<AtomicUsize>,
    generation: watch::Sender<u64>,
    task: JoinHandle<()>,
}

impl<Req> Server<Req> {
    /// Connections accepted so far (resync counters).
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Drains the requests received so far (`Push*`, `SetStpPortStates`).
    pub fn take_seen(&self) -> Vec<Req> {
        std::mem::take(&mut self.seen.lock().unwrap())
    }

    /// Drops every live connection; the accept loop keeps running.
    pub fn close_connections(&self) {
        self.generation.send_modify(|g| *g += 1);
    }
}

impl<Req> Drop for Server<Req> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// What a fake does with one request.
pub enum Reply<Ev> {
    /// Fire-and-forget: send nothing, keep reading.
    None,
    One(Ev),
    Many(Vec<Ev>),
    /// Initial events, then forward the stream until `close_connections()`,
    /// the stream ending, or the client leaving.
    Stream(Vec<Ev>, BoxStream<'static, Ev>),
    /// Drop the connection.
    Close,
}

/// Loop-accepting: every connection is served until it closes. `Req` is
/// recorded for `take_seen` after `handler` has seen it. Needs a tokio
/// runtime; `listen()` errors panic (test code).
pub fn serve<Req, Ev, H>(path: &Path, role: &str, name: &str, handler: H) -> Server<Req>
where
    Req: DeserializeOwned + Send + 'static,
    Ev: Serialize + Send + 'static,
    H: Fn(&Req) -> Reply<Ev> + Send + Sync + 'static,
{
    let listener = nos_pki::testing::shared()
        .identity(role, name)
        .listen(path)
        .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let (generation, _) = watch::channel(0u64);
    let handler = Arc::new(handler);
    let task = {
        let (seen, connections, generation) =
            (seen.clone(), connections.clone(), generation.clone());
        tokio::spawn(async move {
            // The JoinSet dies with this task, aborting every connection.
            let mut conns = JoinSet::new();
            while let Ok(incoming) = listener.accept().await {
                connections.fetch_add(1, Ordering::SeqCst);
                conns.spawn(connection(
                    incoming,
                    handler.clone(),
                    seen.clone(),
                    generation.subscribe(),
                ));
            }
        })
    };
    Server {
        path: path.to_path_buf(),
        seen,
        connections,
        generation,
        task,
    }
}

async fn connection<Req, Ev, H>(
    incoming: nos_pki::Incoming,
    handler: Arc<H>,
    seen: Arc<Mutex<Vec<Req>>>,
    mut generation: watch::Receiver<u64>,
) where
    Req: DeserializeOwned,
    Ev: Serialize,
    H: Fn(&Req) -> Reply<Ev>,
{
    let Ok((stream, _)) = incoming.handshake().await else {
        return;
    };
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<Req>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Ev>::default());
    loop {
        let req = tokio::select! {
            r = reader.next() => match r { Some(Ok(req)) => req, _ => return },
            _ = generation.changed() => return,
        };
        let reply = handler(&req);
        seen.lock().unwrap().push(req);
        match reply {
            Reply::None => {}
            Reply::One(e) => {
                let _ = writer.send(e).await;
            }
            Reply::Many(es) => {
                for e in es {
                    let _ = writer.send(e).await;
                }
            }
            Reply::Close => return,
            Reply::Stream(initial, mut stream) => {
                for e in initial {
                    let _ = writer.send(e).await;
                }
                loop {
                    tokio::select! {
                        item = stream.next() => match item {
                            Some(e) => { let _ = writer.send(e).await; }
                            None => return,
                        },
                        _ = generation.changed() => return,
                        r = reader.next() => if r.is_none() { return },
                    }
                }
            }
        }
    }
}
