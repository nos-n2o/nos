//! `nos-acld --flowspec-file <path>` (hidden, a test hook, owner decision B
//! of #561): a JSON `FlowspecSet` applied like a `PushFlowspec`, re-read
//! when its content changes. A missing file is an empty snapshot.

use std::path::{Path, PathBuf};
use std::time::Duration;

use nos_proto::FlowspecSet;
use tokio::sync::watch;
use tracing::warn;

use crate::driver::Driver;
use crate::engine::Shared;

const POLL: Duration = Duration::from_secs(1);

/// The file and what was last applied from it.
#[derive(Debug)]
pub struct Watch {
    path: PathBuf,
    /// The bytes last seen (`None`: absent). Compared, not the mtime: a
    /// file copied in by `docker cp` keeps its archive's mtime.
    seen: Option<Vec<u8>>,
    /// The instance the last snapshot named, cleared when it goes.
    instance: Option<String>,
}

impl Watch {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            seen: None,
            instance: None,
        }
    }

    /// The snapshots to apply since the last call, in order: clearing the
    /// previous instance when the file went or names another one, then the
    /// new one. An unreadable file keeps what was applied.
    pub fn poll(&mut self) -> Vec<FlowspecSet> {
        let bytes = std::fs::read(&self.path).ok();
        if bytes == self.seen {
            return Vec::new();
        }
        self.seen.clone_from(&bytes);
        let next = match bytes.map(|b| serde_json::from_slice::<FlowspecSet>(&b)) {
            None => None,
            Some(Ok(set)) => Some(set),
            Some(Err(e)) => {
                warn!(path = %self.path.display(), error = %e, "flowspec file unreadable");
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        if let Some(old) = self.instance.take()
            && next.as_ref().is_none_or(|n| n.instance != old)
        {
            out.push(FlowspecSet {
                instance: old,
                table: None,
                devices: Vec::new(),
                rules: Vec::new(),
            });
        }
        if let Some(set) = next {
            self.instance = Some(set.instance.clone());
            out.push(set);
        }
        out
    }
}

/// Polls every second until `shutdown`, pushing what changed.
pub async fn run<D: Driver>(path: PathBuf, engine: Shared<D>, mut shutdown: watch::Receiver<bool>) {
    let mut w = Watch::new(&path);
    loop {
        for set in w.poll() {
            let engine = engine.clone();
            let _ = tokio::task::spawn_blocking(move || engine.lock().unwrap().push_flowspec(set))
                .await;
        }
        tokio::select! {
            () = tokio::time::sleep(POLL) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(instance: &str) -> String {
        format!(
            r#"{{"instance":"{instance}","devices":["eth0"],"rules":[{{"flow":"f","ipv6":false,
            "components":[{{"Protocol":[{{"and":false,"lt":false,"gt":false,"eq":true,"value":6}}]}}],
            "actions":[{{"RateBytes":0.0}}]}}]}}"#
        )
    }

    #[test]
    fn applies_changes_and_clears_what_went() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("flowspec.json");
        let mut w = Watch::new(&path);
        assert_eq!(w.poll(), []);
        std::fs::write(&path, json("b1")).unwrap();
        let got = w.poll();
        assert_eq!((got.len(), got[0].instance.as_str()), (1, "b1"));
        assert_eq!(got[0].rules[0].flow, "f");
        // Unchanged: nothing.
        assert_eq!(w.poll(), []);
        // Garbage: logged, the last snapshot stays.
        std::fs::write(&path, "{").unwrap();
        assert_eq!(w.poll(), []);
        // Another instance: the old one is cleared first.
        std::fs::write(&path, json("b2")).unwrap();
        let got: Vec<_> = w
            .poll()
            .into_iter()
            .map(|s| (s.instance, s.rules.len()))
            .collect();
        assert_eq!(got, [("b1".to_string(), 0), ("b2".to_string(), 1)]);
        std::fs::remove_file(&path).unwrap();
        let got = w.poll();
        assert_eq!((got.len(), got[0].instance.as_str()), (1, "b2"));
        assert!(got[0].rules.is_empty() && got[0].devices.is_empty());
        assert_eq!(w.poll(), []);
    }
}
