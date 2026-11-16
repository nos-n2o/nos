//! Commit history (#1141): the running configs replaced by recent commits,
//! one file each in `<config path>.history/`, so `rollback N` survives a
//! restart. Independent of `save` and of `<path>.bak`; startup never loads it.
//!
//! The commit path only hands an `Arc<Config>` to a writer thread through a
//! bounded channel; a full channel or a failed write is a warning, never a
//! failed commit.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, Sender, SyncSender, TrySendError};
use std::sync::Arc;

use nos_proto::{Config, HistoryEntry};
use tracing::warn;

use crate::error::ConfigError;
use crate::persistence::{check_as_run, write_durable};

/// Entries kept. ponytail: a const, not a config knob; hard cap 100 if one is added.
pub const RING: usize = 20;
const QUEUE: usize = 8;
const HEADER: &str = "# nos-history";

enum Msg {
    Write(u64, Meta, Arc<Config>),
    Flush(Sender<()>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Meta {
    time: u64,
    actor: String,
    kind: &'static str,
}

pub struct History {
    next: AtomicU64,
    tx: SyncSender<Msg>,
    dir: PathBuf,
}

fn dir_of(config_path: &Path) -> PathBuf {
    let mut os = config_path.as_os_str().to_owned();
    os.push(".history");
    os.into()
}

fn file(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id:020}.yaml"))
}

/// Entry ids on disk, ascending.
fn ids(dir: &Path) -> Vec<u64> {
    let mut v: Vec<u64> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            name.strip_suffix(".yaml")?.parse().ok()
        })
        .collect();
    v.sort_unstable();
    v
}

impl History {
    /// `None` (with a warning) when the directory cannot be made.
    pub fn open(config_path: &Path) -> Option<Self> {
        use std::os::unix::fs::DirBuilderExt as _;
        let dir = dir_of(config_path);
        if let Err(e) = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
        {
            warn!(dir = %dir.display(), error = %e, "config history disabled: cannot create directory");
            return None;
        }
        let next = ids(&dir).last().map_or(1, |m| m + 1);
        let (tx, rx) = sync_channel(QUEUE);
        let wdir = dir.clone();
        std::thread::Builder::new()
            .name("config-history".into())
            .spawn(move || writer(&wdir, &rx))
            .ok()?;
        Some(Self {
            next: AtomicU64::new(next),
            tx,
            dir,
        })
    }

    /// Records `config`, the running config a commit of `kind` by `actor` replaced.
    pub fn push(&self, config: Arc<Config>, kind: &'static str, actor: &str) {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let actor = actor
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "-_.@".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let msg = Msg::Write(id, Meta { time, actor, kind }, config);
        match self.tx.try_send(msg) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                warn!(id, "config history queue full, entry dropped");
            }
            Err(TrySendError::Disconnected(_)) => {
                warn!(id, "config history writer is gone, entry dropped");
            }
        }
    }

    /// Waits for every queued write to reach the disk.
    fn flush(&self) {
        let (done, wait) = std::sync::mpsc::channel();
        if self.tx.send(Msg::Flush(done)).is_ok() {
            let _ = wait.recv();
        }
    }

    /// Valid entries, newest first (index 1 = the latest commit's predecessor).
    /// Blocking: waits for queued writes, then parses up to `RING` files.
    /// ponytail: parsed per call, no cache; add an `Arc<Config>` LRU if listing gets hot.
    pub fn entries(&self) -> Vec<(HistoryEntry, Arc<Config>)> {
        self.flush();
        let mut out = Vec::new();
        for id in ids(&self.dir).into_iter().rev() {
            let Ok(text) = std::fs::read_to_string(file(&self.dir, id)) else {
                continue;
            };
            let Some(meta) = parse_header(&text) else {
                continue;
            };
            let Ok(cfg) = serde_norway::from_str::<Config>(&text) else {
                warn!(id, "config history entry does not parse, skipped");
                continue;
            };
            if check_as_run(&cfg).is_err() {
                warn!(id, "config history entry no longer validates, skipped");
                continue;
            }
            out.push((
                HistoryEntry {
                    index: u32::try_from(out.len() + 1).unwrap_or(u32::MAX),
                    time: meta.time,
                    actor: meta.actor,
                    kind: meta.kind.to_string(),
                },
                Arc::new(cfg),
            ));
        }
        out
    }

    /// The config `index` commits back (1-based).
    pub fn get(&self, index: u32) -> Result<Arc<Config>, ConfigError> {
        let entries = self.entries();
        let have = entries.len();
        entries
            .into_iter()
            .find(|(e, _)| e.index == index)
            .map(|(_, c)| c)
            .ok_or(ConfigError::HistoryOutOfRange { index, have })
    }
}

fn parse_header(text: &str) -> Option<Meta> {
    let line = text.lines().next()?.strip_prefix(HEADER)?;
    let (mut time, mut actor, mut kind) = (None, String::new(), "commit");
    for f in line.split_whitespace() {
        match f.split_once('=')? {
            ("time", v) => time = v.parse().ok(),
            ("actor", v) => actor = v.to_string(),
            ("kind", v) => {
                kind = [
                    "rollback",
                    "commit-confirmed",
                    "auto-rollback",
                    "cancel-rollback",
                ]
                .into_iter()
                .find(|k| *k == v)
                .unwrap_or("commit");
            }
            _ => {}
        }
    }
    Some(Meta {
        time: time?,
        actor,
        kind,
    })
}

fn writer(dir: &Path, rx: &Receiver<Msg>) {
    for msg in rx {
        match msg {
            Msg::Flush(done) => {
                let _ = done.send(());
            }
            Msg::Write(id, m, cfg) => {
                let res = serde_norway::to_string(&*cfg)
                    .map_err(ConfigError::from)
                    .and_then(|y| {
                        let head = format!(
                            "{HEADER} time={} kind={} actor={}\n{y}",
                            m.time, m.kind, m.actor
                        );
                        write_durable(&file(dir, id), head.as_bytes())
                    });
                if let Err(e) = res {
                    warn!(id, error = %e, "config history write failed");
                    continue;
                }
                let all = ids(dir);
                for old in &all[..all.len().saturating_sub(RING)] {
                    let _ = std::fs::remove_file(file(dir, *old));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn cfg(host: &str) -> Arc<Config> {
        Arc::new(Config {
            hostname: host.into(),
            ..Default::default()
        })
    }

    fn name(i: usize) -> String {
        let c = (b'a' + u8::try_from(i).unwrap()) as char;
        format!("h{c}")
    }

    fn host(c: &Config) -> String {
        c.hostname.clone()
    }

    #[test]
    fn ring_is_bounded_newest_first_and_private() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        let h = History::open(&path).unwrap();
        for i in 0..RING + 5 {
            h.push(cfg(&name(i)), "commit", "alice");
            h.flush(); // commits are human-paced; a burst past the queue is dropped
        }
        let e = h.entries();
        assert_eq!(e.len(), RING);
        assert_eq!(host(&e[0].1), name(RING + 4));
        assert_eq!(e[0].0.index, 1);
        assert_eq!(e[0].0.actor, "alice");
        assert_eq!(host(&h.get(2).unwrap()), name(RING + 3));
        assert!(matches!(
            h.get(u32::try_from(RING).unwrap() + 1),
            Err(ConfigError::HistoryOutOfRange { .. })
        ));
        let dir = dir_of(&path);
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for f in std::fs::read_dir(&dir).unwrap() {
            let m = f.unwrap().metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
        }
    }

    #[test]
    fn survives_restart_and_skips_corrupt_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.yaml");
        {
            let h = History::open(&path).unwrap();
            h.push(cfg("a"), "commit", "x y");
            h.push(cfg("b"), "rollback", "");
            h.entries();
        }
        let dir = dir_of(&path);
        std::fs::write(
            file(&dir, 99),
            "# nos-history time=1 kind=commit actor=\n{{{",
        )
        .unwrap();
        std::fs::write(file(&dir, 98), "no header\n").unwrap();
        let h = History::open(&path).unwrap();
        let e = h.entries();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].0.kind, "rollback");
        assert_eq!(e[1].0.actor, "x_y");
        h.push(cfg("c"), "commit", "");
        assert_eq!(host(&h.get(1).unwrap()), "c", "ids continue past the max");
    }
}
