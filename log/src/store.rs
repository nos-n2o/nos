use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use nos_proto::LogEntry;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{trace, warn};

/// Live `Tail` subscribers each get their own receiver off this channel;
/// a slow/absent subscriber never blocks `record` — `broadcast::Sender::send`
/// only fails when there are zero receivers, which is the normal, expected
/// case whenever nothing is tailing.
const TAIL_CHANNEL_CAPACITY: usize = 1024;

/// Hard, non-configurable ceiling on the memory `nos-logd` spends holding log
/// entries: [`RING_BYTES`] for the in-memory ring plus [`PERSIST_QUEUE_BYTES`]
/// for entries queued for the disk-persistence task. It exists because one
/// misbehaving daemon logging in a hot loop once grew `nos-logd` to ~14 GB
/// (an entry-count cap alone doesn't bound bytes, and the persistence queue
/// was unbounded). Past it, the oldest ring entries are evicted and new
/// entries are simply not queued for disk — the process never grows further.
pub const MAX_MEMORY_BYTES: usize = 20 * 1024 * 1024;
const PERSIST_QUEUE_BYTES: usize = 4 * 1024 * 1024;
const RING_BYTES: usize = MAX_MEMORY_BYTES - PERSIST_QUEUE_BYTES;

/// Most [`entry_size`] bytes one `GetLogs`/`Tail` reply carries. `entry_size`
/// over-counts an entry's postcard encoding (≥ 100 bytes of fixed overhead
/// against a few bytes of varint lengths), so the reply stays under the
/// codec's `MAX_FRAME`; the headroom covers the enum tag and vec length.
pub const REPLY_BYTES: usize = nos_proto::codec::MAX_FRAME - 1024;

/// Approximate heap footprint of one entry — string payloads plus a fixed
/// per-entry/per-field overhead. Deliberately an estimate, not an exact
/// allocator-accurate figure.
pub fn entry_size(entry: &LogEntry) -> usize {
    let fields: usize = entry
        .fields
        .iter()
        .map(|(k, v)| k.len() + v.len() + 48)
        .sum();
    128 + entry.source.len() + entry.target.len() + entry.message.len() + fields
}

/// Largest [`entry_size`] a recorded entry may have (#640): bigger entries are
/// truncated by [`clamp_entry`], so one `Push` (up to the 16 MiB frame) cannot
/// fill the ring or the disk file by itself.
pub const MAX_ENTRY_BYTES: usize = 64 * 1024;
const MAX_MESSAGE: usize = 16 * 1024;
const MAX_FIELDS: usize = 32;
const MAX_KEY: usize = 128;
const MAX_VALUE: usize = 1024;
const MAX_IDENT: usize = 256;
const TRUNCATED: &str = "...[truncated]";

/// Cuts `s` to at most `max` bytes (marker included) on a UTF-8 boundary.
fn truncate(s: &mut String, max: usize) -> bool {
    if s.len() <= max {
        return false;
    }
    let mut end = max.saturating_sub(TRUNCATED.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s.push_str(TRUNCATED);
    true
}

/// Bounds an entry to [`MAX_ENTRY_BYTES`] by truncating (and marking) its
/// message, source, target and fields; small entries are left untouched.
pub fn clamp_entry(entry: &mut LogEntry) {
    let mut cut = truncate(&mut entry.message, MAX_MESSAGE);
    cut |= truncate(&mut entry.source, MAX_IDENT);
    cut |= truncate(&mut entry.target, MAX_IDENT);
    if entry.fields.len() > MAX_FIELDS {
        entry.fields.truncate(MAX_FIELDS);
        cut = true;
    }
    for (k, v) in &mut entry.fields {
        cut |= truncate(k, MAX_KEY);
        cut |= truncate(v, MAX_VALUE);
    }
    if cut {
        warn!(source = %entry.source, "oversized log entry truncated");
    }
}

#[derive(Default)]
struct Ring {
    entries: VecDeque<LogEntry>,
    bytes: usize,
}

impl Ring {
    fn push(&mut self, entry: LogEntry, capacity: usize) -> usize {
        self.bytes += entry_size(&entry);
        self.entries.push_back(entry);
        let mut evicted = 0;
        while self.entries.len() > capacity || self.bytes > RING_BYTES {
            let Some(old) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= entry_size(&old);
            evicted += 1;
        }
        evicted
    }
}

/// Cheap-`Clone` handle (like `nos-config`'s `ConfigStore`) over the
/// in-memory ring buffer, a broadcast channel for live `Tail` subscribers,
/// and the channel feeding the background persistence task.
#[derive(Clone)]
pub struct LogStore {
    buffer: Arc<RwLock<Ring>>,
    capacity: usize,
    tail_tx: broadcast::Sender<LogEntry>,
    persist_tx: mpsc::UnboundedSender<LogEntry>,
    /// Bytes currently sitting in the persistence queue — incremented here,
    /// decremented by `persistence::run` as it drains (see
    /// `persist_queue_bytes`).
    persist_queued: Arc<AtomicUsize>,
}

impl LogStore {
    /// `seed` (oldest-first) pre-populates the buffer from disk at startup —
    /// see `persistence::load_recent`. `persist_tx` feeds the background
    /// persistence task; entries are never re-persisted here.
    pub fn new(
        capacity: usize,
        seed: Vec<LogEntry>,
        persist_tx: mpsc::UnboundedSender<LogEntry>,
    ) -> Self {
        let mut ring = Ring::default();
        for entry in seed.into_iter().rev().take(capacity).collect::<Vec<_>>() {
            // Seeded newest-first, so stop once the byte budget is spent.
            let size = entry_size(&entry);
            if ring.bytes + size > RING_BYTES {
                break;
            }
            ring.bytes += size;
            ring.entries.push_front(entry);
        }
        let (tail_tx, _) = broadcast::channel(TAIL_CHANNEL_CAPACITY);
        Self {
            buffer: Arc::new(RwLock::new(ring)),
            capacity,
            tail_tx,
            persist_tx,
            persist_queued: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The persistence queue's byte counter, to hand to `persistence::run` so
    /// it can release bytes as it writes entries out.
    pub fn persist_queue_bytes(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.persist_queued)
    }

    /// Records one entry: appends to the in-memory buffer (evicting the
    /// oldest if at capacity), notifies any live `Tail` subscribers, and
    /// forwards it to the persistence task. Never blocks on disk I/O.
    pub async fn record(&self, mut entry: LogEntry) {
        clamp_entry(&mut entry);
        {
            let mut buffer = self.buffer.write().await;
            if buffer.push(entry.clone(), self.capacity) > 0 {
                trace!(
                    capacity = self.capacity,
                    "log buffer full, evicted oldest entry"
                );
            }
        }
        // No subscribers is a normal, expected state, not an error.
        let _ = self.tail_tx.send(entry.clone());

        // Over the persistence queue's byte budget the entry is dropped from
        // the disk path (it's still in the ring) rather than queued — this is
        // what keeps a logging flood from growing the process without bound.
        let size = entry_size(&entry);
        if self.persist_queued.load(Ordering::Relaxed) + size > PERSIST_QUEUE_BYTES {
            return;
        }
        self.persist_queued.fetch_add(size, Ordering::Relaxed);
        if self.persist_tx.send(entry).is_err() {
            self.persist_queued.fetch_sub(size, Ordering::Relaxed);
            warn!("persistence task not running, log entry not persisted to disk");
        }
    }

    /// A filtered, capped snapshot of the buffer, oldest-first — the most
    /// recent `limit` matching entries when `limit` is given, and never more
    /// than [`REPLY_BYTES`] of them, so the `LogEvent::Logs` reply always
    /// fits one IPC frame: past it the oldest entries are left out.
    pub async fn snapshot(&self, source: Option<&str>, limit: Option<usize>) -> Vec<LogEntry> {
        let buffer = self.buffer.read().await;
        let mut budget = REPLY_BYTES;
        let mut newest_first: Vec<LogEntry> = buffer
            .entries
            .iter()
            .rev()
            .filter(|e| source.is_none_or(|s| e.source == s))
            .take(limit.unwrap_or(usize::MAX))
            .take_while(|e| match budget.checked_sub(entry_size(e)) {
                Some(left) => {
                    budget = left;
                    true
                }
                None => false,
            })
            .cloned()
            .collect();
        newest_first.reverse();
        newest_first
    }

    /// A fresh receiver for live-tailing new entries as they're recorded.
    /// Filtering by `source` is left to the caller (see `server::dispatch`)
    /// since a broadcast channel has one shared stream for every subscriber.
    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.tail_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use nos_proto::LogLevel;

    use super::*;

    fn entry(source: &str, message: &str) -> LogEntry {
        LogEntry {
            timestamp_ms: 0,
            level: LogLevel::Info,
            source: source.to_string(),
            target: "test".to_string(),
            message: message.to_string(),
            fields: Vec::new(),
        }
    }

    fn store(capacity: usize) -> LogStore {
        let (tx, _rx) = mpsc::unbounded_channel();
        LogStore::new(capacity, Vec::new(), tx)
    }

    #[tokio::test]
    async fn snapshot_reflects_recorded_entries_in_order() {
        let store = store(10);
        store.record(entry("a", "one")).await;
        store.record(entry("a", "two")).await;
        let snap = store.snapshot(None, None).await;
        assert_eq!(
            snap.iter().map(|e| e.message.as_str()).collect::<Vec<_>>(),
            vec!["one", "two"]
        );
    }

    #[tokio::test]
    async fn snapshot_filters_by_source() {
        let store = store(10);
        store.record(entry("a", "one")).await;
        store.record(entry("b", "two")).await;
        let snap = store.snapshot(Some("a"), None).await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].message, "one");
    }

    #[tokio::test]
    async fn snapshot_respects_limit_keeping_most_recent() {
        let store = store(10);
        for i in 0..5 {
            store.record(entry("a", &i.to_string())).await;
        }
        let snap = store.snapshot(None, Some(2)).await;
        assert_eq!(
            snap.iter().map(|e| e.message.as_str()).collect::<Vec<_>>(),
            vec!["3", "4"]
        );
    }

    #[tokio::test]
    async fn buffer_evicts_oldest_beyond_capacity() {
        let store = store(2);
        for i in 0..3 {
            store.record(entry("a", &i.to_string())).await;
        }
        let snap = store.snapshot(None, None).await;
        assert_eq!(
            snap.iter().map(|e| e.message.as_str()).collect::<Vec<_>>(),
            vec!["1", "2"]
        );
    }

    #[tokio::test]
    async fn ring_never_exceeds_its_byte_budget() {
        let store = store(usize::MAX);
        let big = "x".repeat(64 * 1024);
        for _ in 0..1000 {
            store.record(entry("a", &big)).await;
        }
        let snap = store.snapshot(None, None).await;
        let total: usize = snap.iter().map(entry_size).sum();
        assert!(total <= RING_BYTES, "ring holds {total} bytes");
        assert_ne!(snap, [] as [nos_proto::LogEntry; 0]);
    }

    /// A ring full of large entries (worst case for the reply, #380) is
    /// served newest-first up to `REPLY_BYTES`, and that reply encodes into
    /// one IPC frame.
    #[tokio::test]
    async fn a_full_ring_reply_fits_one_frame() {
        use tokio_util::codec::Encoder;

        let store = store(usize::MAX);
        // Small entries fill the ring to within one entry of `RING_BYTES`,
        // past `REPLY_BYTES`.
        for i in 0..100_000 {
            let mut e = entry("a", &"x".repeat(32));
            e.fields = vec![("i".into(), i.to_string())];
            store.record(e).await;
        }
        let snap = store.snapshot(None, None).await;
        assert!(snap.iter().map(entry_size).sum::<usize>() <= REPLY_BYTES);
        assert_eq!(snap.last().unwrap().fields[0].1, "99999", "newest kept");
        let ring = store.buffer.read().await.entries.len();
        assert!(snap.len() < ring, "the cap left out the oldest");
        nos_proto::IpcCodec::<nos_proto::LogEvent>::default()
            .encode(nos_proto::LogEvent::Logs(snap), &mut bytes::BytesMut::new())
            .unwrap();
    }

    #[tokio::test]
    async fn persistence_queue_stops_accepting_past_its_byte_budget() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let store = LogStore::new(usize::MAX, Vec::new(), tx);
        let big = "x".repeat(64 * 1024);
        // Nothing drains the queue, as if the persistence task were stalled.
        for _ in 0..1000 {
            store.record(entry("a", &big)).await;
        }
        let mut queued = 0;
        while rx.try_recv().is_ok() {
            queued += 1;
        }
        let mut clamped = entry("a", &big);
        clamp_entry(&mut clamped);
        assert!(queued * entry_size(&clamped) <= PERSIST_QUEUE_BYTES);
        assert!(queued > 0 && queued < 1000);
    }

    #[test]
    fn seed_is_truncated_to_capacity_keeping_most_recent() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let seed = (0..5).map(|i| entry("a", &i.to_string())).collect();
        let store = LogStore::new(2, seed, tx);
        // No async runtime needed just to inspect the seeded buffer length
        // via a blocking read — spin one up for the snapshot call instead.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let snap = rt.block_on(store.snapshot(None, None));
        assert_eq!(
            snap.iter().map(|e| e.message.as_str()).collect::<Vec<_>>(),
            vec!["3", "4"]
        );
    }
}
