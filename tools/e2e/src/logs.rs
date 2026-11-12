//! A router's logs, collected over its REST API.
//!
//! A background task holds `GET /v1/logs/follow` (Server-Sent Events) open and
//! appends every entry to a growing list, so assertions never depend on the
//! `nos-logd` ring buffer not wrapping. On a dropped stream it reconnects and
//! re-reads the buffered backlog, de-duplicating by entry.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use nos_proto::LogEntry;
use regex::Regex;
use tokio::task::JoinHandle;

use crate::rest::Rest;

#[derive(Default)]
struct Store {
    lines: Vec<String>,
    /// `timestamp_ms` of each line in `lines`, same index.
    stamps: Vec<u64>,
    seen: HashSet<(u64, String)>,
}

pub struct Logs {
    store: Arc<Mutex<Store>>,
    task: JoinHandle<()>,
}

impl Drop for Logs {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One entry as `LEVEL target: message k=v k=v` — the shape `tracing`'s own fmt
/// layer prints (minus the timestamp and colors), so patterns written against
/// container stdout keep working.
pub fn render(e: &LogEntry) -> String {
    let mut s = format!("{:?} {}: {}", e.level, e.target, e.message);
    for (k, v) in &e.fields {
        let _ = write!(s, " {k}={v}");
    }
    s
}

/// Translates a POSIX basic regex (what the old script's `grep` patterns were)
/// into a `regex` crate pattern: `\|` is alternation, and `( ) + ? { } |` are
/// literals in BRE but operators here.
pub fn bre(pattern: &str) -> Regex {
    let mut out = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('|') => out.push('|'),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push_str("\\\\"),
            },
            '(' | ')' | '+' | '?' | '{' | '}' | '|' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    Regex::new(&out).unwrap_or_else(|e| panic!("bad log pattern {pattern:?}: {e}"))
}

impl Logs {
    /// Starts following a router's logs over its REST API.
    pub fn follow(rest: Rest) -> Self {
        let store = Arc::new(Mutex::new(Store::default()));
        let task = tokio::spawn(follow_forever(rest, store.clone()));
        Self { store, task }
    }

    /// Waits until the backlog has been read (the line count stops growing),
    /// so baselines taken right after attaching aren't racing the first fetch.
    pub async fn settle(&self) {
        self.quiesce(1, 1, Duration::from_millis(400), Duration::from_secs(60))
            .await;
    }

    /// Returns once the stored line count has been unchanged for 2 consecutive
    /// 250ms polls (#884): quiescence, not a guarantee every line was
    /// delivered. Capped at 10s so a chatty router cannot hang the harness;
    /// on the cap it warns and returns.
    #[allow(dead_code, reason = "reached via Router::count_fresh (#885-#887)")]
    pub async fn barrier(&self) {
        if !self
            .quiesce(0, 2, Duration::from_millis(250), Duration::from_secs(10))
            .await
        {
            crate::router::log("log barrier: store still growing after 10s, continuing");
        }
    }

    /// Polls every `step` until the line count is `> min_lines` and unchanged
    /// for `stable` consecutive polls; `false` if `cap` elapses first.
    async fn quiesce(&self, min_lines: usize, stable: u32, step: Duration, cap: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + cap;
        let mut last = usize::MAX;
        let mut same = 0;
        while tokio::time::Instant::now() < deadline {
            let now = self.store.lock().unwrap().lines.len();
            same = if now == last { same + 1 } else { 0 };
            if now > min_lines && same >= stable {
                return true;
            }
            last = now;
            tokio::time::sleep(step).await;
        }
        false
    }

    /// `(timestamp_ms, line)` of every match past the first `baseline`.
    pub fn matches_since(&self, pattern: &str, baseline: usize) -> Vec<(u64, String)> {
        let re = bre(pattern);
        let st = self.store.lock().unwrap();
        st.lines
            .iter()
            .zip(&st.stamps)
            .filter(|(l, _)| re.is_match(l))
            .skip(baseline)
            .map(|(l, t)| (*t, l.clone()))
            .collect()
    }

    /// Timestamp of the `n`th (0-based) match of `pattern`, or, with `None`,
    /// of the last stored line.
    pub fn stamp_of(&self, pattern: &str, n: Option<usize>) -> Option<u64> {
        let st = self.store.lock().unwrap();
        match n {
            None => st.stamps.last().copied(),
            Some(n) => {
                let re = bre(pattern);
                st.lines
                    .iter()
                    .zip(&st.stamps)
                    .filter(|(l, _)| re.is_match(l))
                    .nth(n)
                    .map(|(_, t)| *t)
            }
        }
    }

    /// Number of collected lines matching the BRE `pattern`.
    pub fn count(&self, pattern: &str) -> usize {
        let re = bre(pattern);
        self.store
            .lock()
            .unwrap()
            .lines
            .iter()
            .filter(|l| re.is_match(l))
            .count()
    }

    /// Milliseconds (the daemons' own log timestamps) from the latest
    /// `before` match not after it, to the first `after` match past the first
    /// `after_baseline` matches. `None` if either is missing.
    pub fn delay_ms(&self, before: &str, after: &str, after_baseline: usize) -> Option<u64> {
        let (b, a) = (bre(before), bre(after));
        let st = self.store.lock().unwrap();
        let t_after = st
            .lines
            .iter()
            .zip(&st.stamps)
            .filter(|(l, _)| a.is_match(l))
            .nth(after_baseline)
            .map(|(_, t)| *t)?;
        let t_before = st
            .lines
            .iter()
            .zip(&st.stamps)
            .filter(|(l, t)| b.is_match(l) && **t <= t_after)
            .map(|(_, t)| *t)
            .max()?;
        Some(t_after - t_before)
    }

    /// The most recent line matching `pattern`.
    pub fn last(&self, pattern: &str) -> Option<String> {
        let re = bre(pattern);
        self.store
            .lock()
            .unwrap()
            .lines
            .iter()
            .rev()
            .find(|l| re.is_match(l))
            .cloned()
    }

    /// The last `n` lines matching `pattern`, oldest first.
    pub fn tail(&self, pattern: &str, n: usize) -> Vec<String> {
        let re = bre(pattern);
        let store = self.store.lock().unwrap();
        let mut out: Vec<_> = store
            .lines
            .iter()
            .rev()
            .filter(|l| re.is_match(l))
            .take(n)
            .cloned()
            .collect();
        out.reverse();
        out
    }

    /// Waits until more than `baseline` lines match; `false` on timeout.
    pub async fn wait_over(&self, pattern: &str, baseline: usize, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.count(pattern) > baseline {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

async fn follow_forever(rest: Rest, store: Arc<Mutex<Store>>) {
    // `limit` trims the backlog to the most recent N; ask for "everything".
    let url = format!("{}/v1/logs/follow?limit=100000000", rest.base());
    loop {
        // Not yet up (or being restarted) is just "try again": `client` logs in
        // for a certificate each time it needs one.
        if let Ok(client) = rest.client().await
            && let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            read_stream(resp, &store).await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn read_stream(resp: reqwest::Response, store: &Mutex<Store>) {
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    while let Some(Ok(chunk)) = stream.next().await {
        buf.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(end) = buf.find("\n\n") {
            let event: String = buf.drain(..end + 2).collect();
            if let Some(entry) = parse_event(&event) {
                push(store, &entry);
            }
        }
    }
}

fn push(store: &Mutex<Store>, entry: &LogEntry) {
    let line = render(entry);
    let mut s = store.lock().unwrap();
    if s.seen.insert((entry.timestamp_ms, line.clone())) {
        s.lines.push(line);
        s.stamps.push(entry.timestamp_ms);
    }
}

/// The `LogEntry` of one SSE event block, if it is an `event: log`.
fn parse_event(block: &str) -> Option<LogEntry> {
    let mut is_log = false;
    let mut data = String::new();
    for line in block.lines() {
        if let Some(v) = line.strip_prefix("event:") {
            is_log = v.trim() == "log";
        } else if let Some(v) = line.strip_prefix("data:") {
            data.push_str(v.strip_prefix(' ').unwrap_or(v));
        }
    }
    if is_log {
        serde_json::from_str(&data).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logs_with(lines: &[(u64, &str)]) -> Logs {
        let store = Arc::new(Mutex::new(Store::default()));
        for (t, m) in lines {
            let e = LogEntry {
                timestamp_ms: *t,
                level: nos_proto::LogLevel::Info,
                source: "s".into(),
                target: "t".into(),
                message: (*m).into(),
                fields: vec![],
            };
            push(&store, &e);
        }
        Logs {
            store,
            task: tokio::spawn(async {}),
        }
    }

    #[tokio::test]
    async fn matches_since_skips_baseline_and_keeps_stamps() {
        let l = logs_with(&[(10, "up a"), (20, "down"), (30, "up b"), (45, "up c")]);
        assert_eq!(
            l.matches_since("up", 1),
            vec![(30, "Info t: up b".into()), (45, "Info t: up c".into())]
        );
        assert_eq!(l.matches_since("up", 3).len(), 0);
        assert_eq!(l.stamp_of("up", Some(1)), Some(30));
        assert_eq!(l.stamp_of("up", None), Some(45));
    }

    #[tokio::test(start_paused = true)]
    async fn barrier_returns_once_pushes_stop() {
        let l = logs_with(&[(1, "a")]);
        let t0 = tokio::time::Instant::now();
        l.barrier().await;
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn barrier_is_capped_when_store_keeps_growing() {
        let l = logs_with(&[(1, "a")]);
        let store = l.store.clone();
        let feeder = tokio::spawn(async move {
            for i in 0..1000u64 {
                {
                    let mut s = store.lock().unwrap();
                    s.lines.push(format!("x{i}"));
                    s.stamps.push(i);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let t0 = tokio::time::Instant::now();
        l.barrier().await;
        let e = t0.elapsed();
        feeder.abort();
        assert!(e >= Duration::from_secs(10) && e < Duration::from_secs(11));
    }

    #[test]
    fn bre_translates_grep_patterns() {
        assert!(bre("source=Some(Ospf)").is_match("added route source=Some(Ospf)"));
        assert!(bre("a\\|b").is_match("xb"));
        assert!(bre("addresses=\\[10.0.0.1\\]").is_match("addresses=[10.0.0.1]"));
        assert!(bre("lsa installed.*neighbor=1.1.1.1").is_match("lsa installed x neighbor=1.1.1.1"));
    }

    #[test]
    fn parses_a_log_event_and_ignores_others() {
        let block = "event: log\ndata: {\"timestamp_ms\":1,\"level\":\"Info\",\"source\":\"s\",\"target\":\"t\",\"message\":\"m\",\"fields\":[[\"k\",\"v\"]]}\n\n";
        let e = parse_event(block).unwrap();
        assert_eq!(render(&e), "Info t: m k=v");
        assert!(parse_event("event: error\ndata: boom\n\n").is_none());
    }
}
