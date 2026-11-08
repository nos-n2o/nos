use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use nos_proto::LogEntry;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::store::{entry_size, MAX_MEMORY_BYTES};

/// Once the store file grows past `capacity * COMPACT_FACTOR` lines, it's
/// rewritten down to the most recent `capacity` — bounds disk usage without
/// paying a full rewrite on every single append.
const COMPACT_FACTOR: usize = 2;

/// Disk ceiling (#640): the file is also compacted once it passes this many
/// bytes, so large entries cannot reach `capacity * 2` lines of gigabytes.
/// Twice the tail window `compact` keeps; not configurable.
const MAX_FILE_BYTES: u64 = 2 * MAX_MEMORY_BYTES as u64;

/// Loads up to `capacity` most-recent entries from `path`, oldest-first, for
/// seeding `LogStore` at startup. A missing file is not an error — the first
/// run has nothing to load yet, exactly like `nos-config`'s
/// `persistence::load_or_default`. A line that fails to parse (e.g. written
/// by a future, incompatible version) is skipped rather than failing the
/// whole load.
///
/// Only the last `MAX_MEMORY_BYTES` of the file are read (#756): a persisted
/// line is no larger than its `entry_size` estimate, so that tail covers all
/// the ring can hold, and a huge `--capacity` cannot spike the heap.
pub fn load_recent(path: &Path, capacity: usize) -> Vec<LogEntry> {
    load_recent_with(path, capacity, MAX_MEMORY_BYTES as u64)
}

/// `load_recent` with an explicit tail window (tests use a small one).
fn load_recent_with(path: &Path, capacity: usize, max_bytes: u64) -> Vec<LogEntry> {
    let Ok(mut file) = File::open(path) else {
        return Vec::new();
    };
    let len = file.metadata().map_or(0, |m| m.len());
    let start = len.saturating_sub(max_bytes);
    if start > 0 && file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut reader = BufReader::new(file);
    if start > 0 {
        // Landed mid-line: drop the partial first line.
        let mut partial = Vec::new();
        let _ = reader.read_until(b'\n', &mut partial);
    }
    let mut lines: VecDeque<String> = VecDeque::with_capacity(capacity);
    for line in reader.lines().map_while(Result::ok) {
        if lines.len() >= capacity {
            lines.pop_front();
        }
        lines.push_back(line);
    }
    lines
        .into_iter()
        .filter_map(|line| match serde_json::from_str(&line) {
            Ok(entry) => Some(entry),
            Err(e) => {
                warn!(error = %e, "skipping malformed log store line");
                None
            }
        })
        .collect()
}

/// Runs until `rx` closes or `drain` fires: appends every received entry as
/// one JSON line to `path`, compacting back down to `capacity` lines once the
/// file grows past `capacity * COMPACT_FACTOR`.
///
/// `drain` (#679) is how shutdown flushes: live connections each hold a
/// `LogStore` clone, so the sender never drops. On the trigger, `run` closes
/// `rx` itself (further `record` sends fail and refund the queue), writes
/// what is already queued and returns.
///
/// A failure to open or write the file disables persistence for the rest of
/// this run (a warning is logged once) rather than crashing `nos-logd` —
/// the in-memory buffer keeps serving queries either way.
///
/// `queued` is `LogStore::persist_queue_bytes`: each received entry's bytes are
/// released from it, which is what lets the store bound the queue's memory.
pub async fn run(
    path: PathBuf,
    capacity: usize,
    mut rx: mpsc::UnboundedReceiver<LogEntry>,
    queued: Arc<AtomicUsize>,
    mut drain: watch::Receiver<bool>,
) {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
        && let Err(e) = fs::create_dir_all(parent)
    {
        warn!(error = %e, path = %parent.display(), "failed to create log store directory");
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .inspect_err(|e| {
            warn!(error = %e, path = %path.display(), "failed to open log store file, persistence disabled");
        })
        .ok();
    if file.is_some() {
        info!(path = %path.display(), "log persistence started");
    }
    let mut sink = file.map(|file| {
        let bytes_since_compact = file.metadata().map_or(0, |m| m.len());
        Sink {
            // ponytail: bounded count = lines in the tail window only; a file
            // above MAX_FILE_BYTES is compacted on the first append.
            lines_since_compact: count_lines(&path).unwrap_or(0),
            bytes_since_compact,
            file,
        }
    });

    // Without a file, entries are just discarded so senders never block on a
    // full mpsc queue.
    loop {
        tokio::select! {
            entry = rx.recv() => {
                let Some(entry) = entry else { return };
                handle(&mut sink, &path, capacity, &queued, &entry);
            }
            _ = drain.wait_for(|d| *d) => break,
        }
    }
    rx.close();
    while let Some(entry) = rx.recv().await {
        handle(&mut sink, &path, capacity, &queued, &entry);
    }
}

struct Sink {
    file: File,
    lines_since_compact: usize,
    bytes_since_compact: u64,
}

/// Releases `entry`'s queue bytes and, if persistence is on, appends it
/// (compacting when due).
fn handle(
    sink: &mut Option<Sink>,
    path: &Path,
    capacity: usize,
    queued: &AtomicUsize,
    entry: &LogEntry,
) {
    queued.fetch_sub(entry_size(entry), Ordering::Relaxed);
    let Some(Sink {
        file,
        lines_since_compact,
        bytes_since_compact,
    }) = sink
    else {
        return;
    };
    match serde_json::to_string(entry) {
        Ok(line) => match writeln!(file, "{line}") {
            Ok(()) => {
                *lines_since_compact += 1;
                *bytes_since_compact += line.len() as u64 + 1;
            }
            Err(e) => warn!(error = %e, "failed to append to log store file"),
        },
        Err(e) => warn!(error = %e, "failed to serialize log entry for persistence"),
    }

    if *lines_since_compact > capacity.saturating_mul(COMPACT_FACTOR)
        || *bytes_since_compact > MAX_FILE_BYTES
    {
        match compact(path, capacity) {
            Ok(new_file) => {
                *bytes_since_compact = new_file.metadata().map_or(0, |m| m.len());
                *file = new_file;
                *lines_since_compact = capacity.min(*lines_since_compact);
                debug!(path = %path.display(), capacity, "compacted log store file");
            }
            Err(e) => warn!(error = %e, "failed to compact log store file"),
        }
    }
}

/// Lines in the last `MAX_FILE_BYTES` of the file (bounded read).
fn count_lines(path: &Path) -> std::io::Result<usize> {
    let mut file = File::open(path)?;
    let start = file.metadata()?.len().saturating_sub(MAX_FILE_BYTES);
    file.seek(SeekFrom::Start(start))?;
    Ok(BufReader::new(file).lines().map_while(Result::ok).count())
}

/// Rewrites `path` keeping only its last `capacity` lines (via a temp file
/// in the same directory, renamed over `path` — the same atomic-write
/// pattern as `nos-config`'s `persistence::save_to_disk`), then reopens it
/// for appending.
fn compact(path: &Path, capacity: usize) -> std::io::Result<File> {
    compact_with(path, capacity, MAX_MEMORY_BYTES as u64)
}

fn compact_with(path: &Path, capacity: usize, max_bytes: u64) -> std::io::Result<File> {
    let kept = load_recent_with(path, capacity, max_bytes);
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match dir {
        Some(dir) => tempfile::NamedTempFile::new_in(dir),
        None => tempfile::NamedTempFile::new(),
    }?;
    for entry in &kept {
        let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
        writeln!(tmp, "{line}")?;
    }
    tmp.persist(path)
        .map_err(|e| std::io::Error::other(e.error))?;
    OpenOptions::new().append(true).open(path)
}

#[cfg(test)]
mod tests {
    use nos_proto::LogLevel;

    use super::*;

    fn entry(message: &str) -> LogEntry {
        LogEntry {
            timestamp_ms: 0,
            level: LogLevel::Info,
            source: "test".to_string(),
            target: "test".to_string(),
            message: message.to_string(),
            fields: Vec::new(),
        }
    }

    #[test]
    fn load_recent_returns_empty_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.jsonl");
        assert_eq!(load_recent(&path, 10), Vec::new());
    }

    #[tokio::test]
    async fn run_persists_entries_and_load_recent_reads_them_back() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/entries.jsonl");
        let (tx, rx) = mpsc::unbounded_channel();

        tx.send(entry("one")).unwrap();
        tx.send(entry("two")).unwrap();
        drop(tx);
        run(
            path.clone(),
            10,
            rx,
            Arc::default(),
            watch::channel(false).1,
        )
        .await;

        let loaded = load_recent(&path, 10);
        assert_eq!(
            loaded
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>(),
            vec!["one", "two"]
        );
    }

    #[tokio::test]
    async fn run_compacts_once_past_the_threshold() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("entries.jsonl");
        let (tx, rx) = mpsc::unbounded_channel();

        // capacity=1, factor=2 -> compacts once more than 2 lines exist.
        for i in 0..5 {
            tx.send(entry(&i.to_string())).unwrap();
        }
        drop(tx);
        run(path.clone(), 1, rx, Arc::default(), watch::channel(false).1).await;

        let loaded = load_recent(&path, 10);
        assert_eq!(
            loaded
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>(),
            vec!["4"]
        );
    }

    /// #679: a live sender clone keeps the channel open (every connection
    /// holds one), yet the drain trigger still flushes the queue and returns.
    #[tokio::test]
    async fn drain_flushes_queue_despite_live_sender() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("entries.jsonl");
        let (tx, rx) = mpsc::unbounded_channel();
        let (drain_tx, drain_rx) = watch::channel(false);
        for i in 0..5 {
            tx.send(entry(&i.to_string())).unwrap();
        }
        drain_tx.send(true).unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run(path.clone(), 10, rx, Arc::default(), drain_rx),
        )
        .await
        .expect("run must return on drain");
        assert_eq!(load_recent(&path, 10).len(), 5);
        assert!(tx.send(entry("late")).is_err(), "channel closed by drain");
    }

    #[tokio::test]
    async fn drain_returns_when_the_file_cannot_be_opened() {
        let tmp = tempfile::tempdir().unwrap();
        // A directory path cannot be opened for append.
        let (tx, rx) = mpsc::unbounded_channel();
        let (drain_tx, drain_rx) = watch::channel(false);
        tx.send(entry("x")).unwrap();
        drain_tx.send(true).unwrap();
        let queued = Arc::new(AtomicUsize::new(entry_size(&entry("x"))));
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run(tmp.path().to_path_buf(), 10, rx, queued.clone(), drain_rx),
        )
        .await
        .expect("run must return on drain");
        assert_eq!(queued.load(Ordering::Relaxed), 0);
        drop(tx);
    }

    #[test]
    fn bytes_threshold_compacts_few_large_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("e.jsonl");
        let mut sink = Some(Sink {
            file: OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap(),
            lines_since_compact: 0,
            bytes_since_compact: MAX_FILE_BYTES,
        });
        // Far below capacity * 2 lines, but over the byte bound.
        handle(
            &mut sink,
            &path,
            1000,
            &AtomicUsize::new(1 << 20),
            &entry("x"),
        );
        assert!(sink.unwrap().bytes_since_compact < 1024);
    }

    #[test]
    fn oversized_file_is_compacted_on_first_append() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("e.jsonl");
        write_lines(&path, 10);
        let file = OpenOptions::new().append(true).open(&path).unwrap();
        let mut sink = Some(Sink {
            file,
            lines_since_compact: count_lines(&path).unwrap(),
            bytes_since_compact: MAX_FILE_BYTES + 1,
        });
        handle(
            &mut sink,
            &path,
            3,
            &AtomicUsize::new(1 << 20),
            &entry("new"),
        );
        let kept = load_recent(&path, 100);
        assert_eq!(msgs(&kept), ["m008", "m009", "new"]);
    }

    fn write_lines(path: &Path, n: usize) {
        let mut f = File::create(path).unwrap();
        for i in 0..n {
            writeln!(
                f,
                "{}",
                serde_json::to_string(&entry(&format!("m{i:03}"))).unwrap()
            )
            .unwrap();
        }
    }

    fn msgs(v: &[LogEntry]) -> Vec<&str> {
        v.iter().map(|e| e.message.as_str()).collect()
    }

    #[test]
    fn tail_window_returns_only_newest_without_a_malformed_cut_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("e.jsonl");
        write_lines(&path, 100);
        let line = std::fs::metadata(&path).unwrap().len() / 100;
        let got = load_recent_with(&path, 1000, line * 10 + line / 2);
        assert!(got.len() >= 9 && got.len() <= 10, "{}", got.len());
        assert_eq!(msgs(&got).last(), Some(&"m099"));
        assert_eq!(load_recent_with(&path, 1000, 1 << 30).len(), 100);
        assert_eq!(
            msgs(&load_recent_with(&path, 3, 1 << 30)),
            ["m097", "m098", "m099"]
        );
        assert_eq!(load_recent_with(&path, 3, line * 10).len(), 3);
    }

    #[test]
    fn compact_on_an_oversized_file_keeps_only_the_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("e.jsonl");
        write_lines(&path, 100);
        let line = std::fs::metadata(&path).unwrap().len() / 100;
        compact_with(&path, 1000, line * 5 + line / 2).unwrap();
        let kept = load_recent_with(&path, 1000, 1 << 30);
        assert!(kept.len() <= 5 && !kept.is_empty());
        assert_eq!(msgs(&kept).last(), Some(&"m099"));
    }
}
