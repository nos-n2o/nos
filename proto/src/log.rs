use serde::{Deserialize, Serialize};

/// Wire twin of `tracing::Level` — kept separate so no component needs to
/// depend on `tracing`'s own (de)serialization support.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, nos_proto_derive::Cli)]
pub enum LogLevel {
    /// Very fine-grained diagnostics.
    Trace,
    /// Debugging detail.
    Debug,
    /// Normal operation.
    Info,
    /// Something unexpected but recoverable.
    Warn,
    /// Something failed.
    Error,
}

/// One structured log record, as forwarded by any component process to
/// `nos-logd` (`LogRequest::Push`) or returned to a querying client
/// (`LogEvent::Logs`/`Line`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Milliseconds since the Unix epoch, from the forwarding process's own
    /// clock — `nos-logd` never rewrites this on receipt, so ordering
    /// reflects when the event was emitted, not when it arrived.
    pub timestamp_ms: u64,
    /// Severity.
    pub level: LogLevel,
    /// Identifies which process emitted this entry, e.g. `"nos-ribd[rt1]"`,
    /// `"nos-bgpd[r1]"`, `"nos-interfaced"`, `"nos-configd"`,
    /// `"nos-watchdogd"` — the same identity `nos-watchdogd` already uses
    /// for its own `ProcessSpec` names.
    pub source: String,
    /// The `tracing` event's target (typically a module path).
    pub target: String,
    /// The message text, including structured fields.
    pub message: String,
    /// The event's structured fields (other than `message`), flattened to
    /// their `Display`/`Debug` text — e.g. `("table", "rt1")`.
    pub fields: Vec<(String, String)>,
}

/// Messages sent from a client to `nos-logd`'s IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogRequest {
    /// Forwards one log record. Sent by every other component process over
    /// one long-lived connection held for the process's whole lifetime — not
    /// a one-shot request, so `nos-logd` sends no reply to it (see
    /// `LogEvent`'s doc comment).
    Push(LogEntry),
    /// One-shot: the current buffer, optionally filtered by `source` (exact
    /// match) and capped to the most recent `limit` entries.
    GetLogs {
        /// Only entries from this daemon.
        source: Option<String>,
        /// Maximum number of entries to return.
        limit: Option<usize>,
    },
    /// Like `GetLogs`, but the connection stays open afterwards: the reply
    /// is followed by one `LogEvent::Line` per new matching entry, streamed
    /// until the client disconnects.
    Tail {
        /// Only entries from this daemon.
        source: Option<String>,
    },
}

/// Messages sent from `nos-logd` to a client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogEvent {
    /// Reply to `GetLogs`, and the first reply to `Tail` (the buffer as it
    /// stood at subscribe time, before any streamed `Line`).
    Logs(Vec<LogEntry>),
    /// One new matching entry, streamed after `Tail`'s initial `Logs` reply.
    Line(LogEntry),
    /// Something failed.
    Error(String),
}
