//! Records every call and keeps a pretend entry per (ifindex, direction):
//! `--driver noop` and the tests.

use std::collections::BTreeMap;
use std::io;

use super::{Counter, Direction, Driver};
use crate::compile::Compiled;
use crate::flowspec::Lowered;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Install(u32, Direction, u32),
    Switch(u32, Direction, u32),
    Flush(u32, Direction, u32),
    Detach(u32, Direction),
    /// `(ifindex, prio, cookie)`; `None` clears the priority.
    Flowspec(u32, u16, Option<u32>),
}

#[derive(Debug, Default)]
pub struct NoopDriver {
    pub calls: Vec<Call>,
    /// What `live_chain` reports; `switch`/`detach` keep it current.
    pub live: BTreeMap<(u32, Direction), u32>,
    /// Makes the next `install` fail (a kernel refusal).
    pub fail_install: bool,
    /// Makes the next `switch` fail; `Some(true)`: the entry has already
    /// moved (a driver that failed half-way).
    pub fail_switch: Option<bool>,
    /// What `counters` reports per (ifindex, direction), whatever the chain.
    pub counts: BTreeMap<(u32, Direction), Vec<Counter>>,
    /// Makes `counters` and `flowspec_counters` fail (the device vanished).
    pub fail_counters: bool,
    /// Flowspec priority -> cookie per ifindex; `flowspec_set` keeps it.
    pub flowspec: BTreeMap<u32, BTreeMap<u16, u32>>,
    /// Makes the next `flowspec_set` with a rule fail.
    pub fail_flowspec: bool,
    /// What `flowspec_counters` reports per ifindex.
    pub flowspec_counts: BTreeMap<u32, BTreeMap<u16, (u64, u64)>>,
}

impl Driver for NoopDriver {
    fn live_chain(&mut self, ifindex: u32, dir: Direction) -> io::Result<Option<u32>> {
        Ok(self.live.get(&(ifindex, dir)).copied())
    }

    fn install(
        &mut self,
        ifindex: u32,
        dir: Direction,
        chain: u32,
        _acl: &Compiled,
    ) -> io::Result<()> {
        self.calls.push(Call::Install(ifindex, dir, chain));
        if std::mem::take(&mut self.fail_install) {
            return Err(io::Error::other("refused"));
        }
        Ok(())
    }

    fn switch(
        &mut self,
        ifindex: u32,
        dir: Direction,
        chain: u32,
        _old: Option<u32>,
    ) -> io::Result<()> {
        self.calls.push(Call::Switch(ifindex, dir, chain));
        if let Some(repoint) = self.fail_switch.take() {
            if repoint {
                self.live.insert((ifindex, dir), chain);
            }
            return Err(io::Error::other("refused"));
        }
        self.live.insert((ifindex, dir), chain);
        Ok(())
    }

    fn flush(&mut self, ifindex: u32, dir: Direction, chain: u32) -> io::Result<()> {
        self.calls.push(Call::Flush(ifindex, dir, chain));
        Ok(())
    }

    fn detach(&mut self, ifindex: u32, dir: Direction) -> io::Result<()> {
        self.calls.push(Call::Detach(ifindex, dir));
        self.live.remove(&(ifindex, dir));
        Ok(())
    }

    fn counters(&mut self, ifindex: u32, dir: Direction, _chain: u32) -> io::Result<Vec<Counter>> {
        if self.fail_counters {
            return Err(io::Error::other("gone"));
        }
        Ok(self
            .counts
            .get(&(ifindex, dir))
            .cloned()
            .unwrap_or_default())
    }

    fn flowspec_set(
        &mut self,
        ifindex: u32,
        prio: u16,
        rule: Option<(u32, &Lowered)>,
    ) -> io::Result<()> {
        let cookie = rule.map(|r| r.0);
        self.calls.push(Call::Flowspec(ifindex, prio, cookie));
        let held = self.flowspec.entry(ifindex).or_default();
        held.remove(&prio);
        if let Some(c) = cookie {
            if std::mem::take(&mut self.fail_flowspec) {
                return Err(io::Error::other("refused"));
            }
            held.insert(prio, c);
        }
        Ok(())
    }

    fn flowspec_prios(&mut self, ifindex: u32) -> io::Result<Vec<u16>> {
        Ok(self
            .flowspec
            .get(&ifindex)
            .map_or_default(|m| m.keys().copied().collect()))
    }

    fn flowspec_counters(&mut self, ifindex: u32) -> io::Result<BTreeMap<u16, (u64, u64)>> {
        if self.fail_counters {
            return Err(io::Error::other("gone"));
        }
        Ok(self
            .flowspec_counts
            .get(&ifindex)
            .cloned()
            .unwrap_or_default())
    }
}
