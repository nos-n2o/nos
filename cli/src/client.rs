use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::config_path::ListPosition;
use nos_proto::{
    CommandDoc, Config, ConfigDiff, ConfigOp, Event, IpcCodec, Request, Role, Topic,
    TransactionBase, TransactionSnapshot,
};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("could not connect to nos-configd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-configd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-configd: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-configd reported an error: {0}")]
    Daemon(String),
}

type Reader = FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<Event>>;
type Writer = FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<Request>>;

/// Dials `nos-configd` for a single request/reply exchange.
async fn connect(socket_path: &Path) -> Result<(Reader, Writer), ClientError> {
    let stream = nos_pki::connect(socket_path, Role::Configd, "")
        .await
        .map_err(|source| ClientError::Connect {
            path: socket_path.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    Ok((
        FramedRead::new(r, IpcCodec::<Event>::default()),
        FramedWrite::new(w, IpcCodec::<Request>::default()),
    ))
}

fn expect_transaction(
    event: Option<Result<Event, std::io::Error>>,
) -> Result<TransactionSnapshot, ClientError> {
    match event {
        Some(Ok(Event::Transaction(snap))) => Ok(snap),
        Some(Ok(Event::Error(msg))) => Err(ClientError::Daemon(msg)),
        Some(Ok(_)) => Err(ClientError::Daemon(
            "unexpected event in reply to a transaction request".to_string(),
        )),
        Some(Err(e)) => Err(ClientError::Io(e)),
        None => Err(ClientError::ConnectionClosed),
    }
}

/// Opens a long-lived connection: sends `Request::Subscribe` and returns the
/// reader half for the caller to loop on indefinitely (an initial config
/// snapshot, then one more `Event::Config` per future commit). Unlike every
/// other function here, this connection is not one-shot — the caller owns
/// its lifetime.
pub async fn subscribe(socket_path: &Path) -> Result<Reader, ClientError> {
    let (reader, mut writer) = connect(socket_path).await?;
    writer.send(Request::Subscribe).await?;
    Ok(reader)
}

/// Dials the daemon, sends a one-shot `Request::Get`, and returns the snapshot.
pub async fn fetch_running_config(socket_path: &Path) -> Result<Config, ClientError> {
    let (mut reader, mut writer) = connect(socket_path).await?;
    writer.send(Request::Get).await?;

    match reader.next().await {
        Some(Ok(Event::Config(cfg))) => Ok(cfg),
        Some(Ok(Event::Error(msg))) => Err(ClientError::Daemon(msg)),
        Some(Ok(_)) => Err(ClientError::Daemon(
            "unexpected event in reply to Get".to_string(),
        )),
        Some(Err(e)) => Err(ClientError::Io(e)),
        None => Err(ClientError::ConnectionClosed),
    }
}

/// Dials the daemon, sends a one-shot `Request::Save`, and waits for
/// confirmation that the running config was persisted to disk.
pub async fn save_running_config(socket_path: &Path) -> Result<(), ClientError> {
    let (mut reader, mut writer) = connect(socket_path).await?;
    writer.send(Request::Save).await?;

    match reader.next().await {
        Some(Ok(Event::Saved)) => Ok(()),
        Some(Ok(Event::Error(msg))) => Err(ClientError::Daemon(msg)),
        Some(Ok(_)) => Err(ClientError::Daemon(
            "unexpected event in reply to Save".to_string(),
        )),
        Some(Err(e)) => Err(ClientError::Io(e)),
        None => Err(ClientError::ConnectionClosed),
    }
}

/// Opens (or resumes) a named transaction.
pub async fn open_transaction(
    socket_path: &Path,
    name: &str,
    base: TransactionBase,
) -> Result<TransactionSnapshot, ClientError> {
    let (mut reader, mut writer) = connect(socket_path).await?;
    writer
        .send(Request::OpenTransaction {
            actor: None,
            name: name.to_string(),
            base,
        })
        .await?;
    expect_transaction(reader.next().await)
}

/// Applies one edit to a named transaction.
pub async fn apply_op(
    socket_path: &Path,
    name: &str,
    op: ConfigOp,
) -> Result<TransactionSnapshot, ClientError> {
    let (mut reader, mut writer) = connect(socket_path).await?;
    writer
        .send(Request::ApplyOp {
            actor: None,
            name: name.to_string(),
            op,
        })
        .await?;
    expect_transaction(reader.next().await)
}

/// Sets (`Some(json)`) or removes (`None`) one subsection of a named
/// transaction by config path — the config grammar's writes. Returns the
/// transaction's `dirty` flag after the edit (the reply carries no config,
/// #774).
pub async fn edit_transaction_path(
    socket_path: &Path,
    name: &str,
    path: Vec<String>,
    value: Option<String>,
    position: Option<ListPosition>,
) -> Result<bool, ClientError> {
    let (mut reader, mut writer) = connect(socket_path).await?;
    writer
        .send(Request::EditTransactionPath {
            name: name.to_string(),
            path,
            value,
            if_match: None,
            position,
        })
        .await?;
    match reader.next().await {
        Some(Ok(Event::TransactionEdit { dirty, .. })) => Ok(dirty),
        other => expect_transaction(other).map(|s| s.dirty),
    }
}

/// Fetches a named transaction's current in-progress config.
pub async fn get_transaction(
    socket_path: &Path,
    name: &str,
) -> Result<TransactionSnapshot, ClientError> {
    let (mut reader, mut writer) = connect(socket_path).await?;
    writer
        .send(Request::GetTransaction {
            name: name.to_string(),
        })
        .await?;
    expect_transaction(reader.next().await)
}

/// Validates and commits a named transaction, replacing the running config.
/// Returns the daemon's commit warnings and whether the running config is
/// now unsaved.
pub async fn commit_transaction(
    socket_path: &Path,
    name: &str,
) -> Result<(Vec<String>, bool), ClientError> {
    let (mut reader, mut writer) = connect(socket_path).await?;
    writer
        .send(Request::CommitTransaction {
            actor: None,
            name: name.to_string(),
            if_match: None,
        })
        .await?;
    match reader.next().await {
        Some(Ok(Event::Committed { warnings, unsaved })) => Ok((warnings, unsaved)),
        Some(Ok(Event::Error(msg))) => Err(ClientError::Daemon(msg)),
        Some(Ok(_)) => Err(ClientError::Daemon(
            "unexpected event in reply to CommitTransaction".to_string(),
        )),
        Some(Err(e)) => Err(ClientError::Io(e)),
        None => Err(ClientError::ConnectionClosed),
    }
}

/// Dials the daemon, sends a one-shot `Request::Describe` for a single
/// topic, and returns its documentation.
pub async fn describe(socket_path: &Path, topic: Topic) -> Result<CommandDoc, ClientError> {
    let (mut reader, mut writer) = connect(socket_path).await?;
    writer.send(Request::Describe { topic }).await?;

    match reader.next().await {
        Some(Ok(Event::Description(doc))) => Ok(doc),
        Some(Ok(Event::Error(msg))) => Err(ClientError::Daemon(msg)),
        Some(Ok(_)) => Err(ClientError::Daemon(
            "unexpected event in reply to Describe".to_string(),
        )),
        Some(Err(e)) => Err(ClientError::Io(e)),
        None => Err(ClientError::ConnectionClosed),
    }
}

/// Fetches the structural difference between the running config and a named
/// transaction's in-progress config.
pub async fn diff_transaction(socket_path: &Path, name: &str) -> Result<ConfigDiff, ClientError> {
    let (mut reader, mut writer) = connect(socket_path).await?;
    writer
        .send(Request::DiffTransaction {
            name: name.to_string(),
        })
        .await?;
    match reader.next().await {
        Some(Ok(Event::Diff(diff))) => Ok(diff),
        Some(Ok(Event::Error(msg))) => Err(ClientError::Daemon(msg)),
        Some(Ok(_)) => Err(ClientError::Daemon(
            "unexpected event in reply to DiffTransaction".to_string(),
        )),
        Some(Err(e)) => Err(ClientError::Io(e)),
        None => Err(ClientError::ConnectionClosed),
    }
}

/// Deletes a named transaction without touching the running config.
pub async fn discard_transaction(socket_path: &Path, name: &str) -> Result<(), ClientError> {
    let (mut reader, mut writer) = connect(socket_path).await?;
    writer
        .send(Request::DiscardTransaction {
            name: name.to_string(),
            if_match: None,
        })
        .await?;
    match reader.next().await {
        Some(Ok(Event::Discarded)) => Ok(()),
        Some(Ok(Event::Error(msg))) => Err(ClientError::Daemon(msg)),
        Some(Ok(_)) => Err(ClientError::Daemon(
            "unexpected event in reply to DiscardTransaction".to_string(),
        )),
        Some(Err(e)) => Err(ClientError::Io(e)),
        None => Err(ClientError::ConnectionClosed),
    }
}
