//! Holds the kernel to the [`Plan`]: per (device, direction), the compiled
//! ACL in the live chain. Driver calls block, so each pass runs on
//! `spawn_blocking` with the engine moved in and back out.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use nos_proto::{AclAttachment, AclDirection, AclStatus};
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::compile::Compiled;
use crate::driver::{idle, Direction, Driver};
use crate::link_client::LinkTable;
use crate::logger;
use crate::plan::{Device, Plan};
use crate::status;

type Key = (String, Direction);

/// What one (device, direction) holds.
#[derive(Debug, Clone)]
struct Installed {
    ifindex: u32,
    chain: u32,
    /// The ACL's name; `None` with `acl`.
    name: Option<String>,
    /// `None`: found live at start (a previous run's), contents unknown.
    acl: Option<Arc<Compiled>>,
}

pub struct Engine<D> {
    driver: D,
    /// The compiled ACLs of the last plan, for `show acl`.
    acls: BTreeMap<String, Arc<Compiled>>,
    installed: BTreeMap<Key, Installed>,
    /// Attachments whose device is absent, logged once until it appears.
    pending: BTreeSet<Key>,
    /// The first known link table was checked for a previous run's entries.
    swept: bool,
    /// The last link table a pass saw, for flowspec pushes between passes.
    links: LinkTable,
    /// Flowspec rules per pushing instance, and what each device holds.
    fs: flowspec_src::State,
}

/// The kernel name of `device`; while its bond is unknown, `Err` with a
/// name to log (`<aggregate>` or `<aggregate>.<tag>`).
fn resolve(device: &Device, links: &LinkTable) -> Result<String, String> {
    let with_tag = |base: &str, tag: u16| {
        if tag == 0 {
            base.to_string()
        } else {
            format!("{base}.{tag}")
        }
    };
    match device {
        Device::Kernel(n) => Ok(n.clone()),
        Device::Aggregate { name, tag } => match links.bond(name) {
            Some(bond) => Ok(with_tag(bond, *tag)),
            None => Err(with_tag(name, *tag)),
        },
    }
}

impl<D: Driver> Engine<D> {
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            acls: BTreeMap::new(),
            installed: BTreeMap::new(),
            pending: BTreeSet::new(),
            swept: false,
            links: LinkTable::default(),
            fs: flowspec_src::State::default(),
        }
    }

    pub fn driver(&self) -> &D {
        &self.driver
    }

    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    /// Adopts what a previous run left enforcing (D9: a crash fails
    /// closed), so the diff below replaces or detaches it.
    fn sweep(&mut self, links: &LinkTable) {
        for l in links.links.values() {
            for dir in Direction::BOTH {
                match self.driver.live_chain(l.ifindex, dir) {
                    Ok(Some(chain)) => {
                        let at = Installed {
                            ifindex: l.ifindex,
                            chain,
                            name: None,
                            acl: None,
                        };
                        self.installed.insert((l.name.clone(), dir), at);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(interface = %l.name, direction = %dir, error = %e, "could not read the acl entry");
                    }
                }
            }
            self.sweep_flowspec(&l.name, l.ifindex);
        }
        self.swept = true;
    }

    /// One pass. Nothing happens until the link table is known.
    pub fn sync(&mut self, plan: &Plan, links: &LinkTable) {
        self.acls.clone_from(&plan.acls);
        self.fs.attached.clone_from(&plan.flowspec);
        self.links.clone_from(links);
        if !links.known {
            return;
        }
        if !self.swept {
            self.sweep(links);
        }
        // A device that went away took its qdisc, and our filters, with it.
        self.installed.retain(|(dev, _), at| {
            links
                .links
                .get(dev)
                .is_some_and(|l| l.ifindex == at.ifindex)
        });

        let mut desired: BTreeMap<Key, (u32, &str, Option<&Arc<Compiled>>)> = BTreeMap::new();
        let mut pending = BTreeSet::new();
        for a in &plan.attachments {
            let resolved = resolve(&a.device, links);
            let Some(link) = resolved.as_ref().ok().and_then(|n| links.links.get(n)) else {
                let (Ok(shown) | Err(shown)) = resolved;
                if !self.pending.contains(&(shown.clone(), a.dir)) {
                    info!(interface = %shown, direction = %a.dir, acl = %a.acl, reason = "absent", "acl pending");
                }
                pending.insert((shown, a.dir));
                continue;
            };
            let key = (link.name.clone(), a.dir);
            desired.insert(key, (link.ifindex, &a.acl, plan.acls.get(&a.acl)));
        }
        self.pending = pending;

        let gone: Vec<Key> = self
            .installed
            .keys()
            .filter(|k| !desired.contains_key(*k))
            .cloned()
            .collect();
        for key in gone {
            self.detach(&key);
        }
        for (key, (ifindex, name, acl)) in desired {
            // No compile yet (it failed): leave the kernel as it is.
            if let Some(acl) = acl {
                self.apply(&key, ifindex, name, acl);
            }
        }
        self.apply_flowspec();
    }

    fn apply(&mut self, key: &Key, ifindex: u32, name: &str, acl: &Arc<Compiled>) {
        self.apply_with(key, ifindex, name, acl, false);
    }

    /// `force` reinstalls an unchanged ACL (a counter clear).
    fn apply_with(
        &mut self,
        key: &Key,
        ifindex: u32,
        name: &str,
        acl: &Arc<Compiled>,
        force: bool,
    ) {
        let current = self.installed.get(key);
        if !force
            && current
                .and_then(|c| c.acl.as_ref())
                .is_some_and(|c| c == acl)
        {
            return;
        }
        let (dev, dir) = (&key.0, key.1);
        let old = current.map(|c| c.chain);
        let chain = idle(old);
        let mut switched = false;
        let result = self
            .driver
            .install(ifindex, dir, chain, acl)
            .and_then(|()| {
                switched = true;
                self.driver.switch(ifindex, dir, chain, old)
            });
        if let Err(e) = result {
            // Fail closed: the old chain stays live; drop the half-filled one.
            error!(interface = %dev, direction = %dir, acl = %name, error = %e, "acl not applied, keeping the previous state");
            if switched {
                // The driver may have failed half-way: never flush a chain
                // the entry might still name.
                if let Some(o) = old {
                    if let Err(e) = self.driver.switch(ifindex, dir, o, Some(chain)) {
                        error!(interface = %dev, direction = %dir, chain = o, error = %e, "could not point the acl back at the previous chain");
                    }
                } else {
                    let _ = self.driver.detach(ifindex, dir);
                    return;
                }
            }
            let _ = self.driver.flush(ifindex, dir, chain);
            return;
        }
        if let Some(old) = old
            && let Err(e) = self.driver.flush(ifindex, dir, old)
        {
            warn!(interface = %dev, direction = %dir, chain = old, error = %e, "could not flush the old acl chain");
        }
        let at = Installed {
            ifindex,
            chain,
            name: Some(name.to_string()),
            acl: Some(acl.clone()),
        };
        self.installed.insert(key.clone(), at);
        info!(interface = %dev, direction = %dir, acl = %name, chain, "acl attached");
    }

    /// Reinstalls every ACL (or the named one) on its idle chain and
    /// switches, so the kernel counters restart at 0 without a window
    /// without a filter. `(found, attachments replaced)`. Entries adopted
    /// from a previous run (contents unknown) are skipped: the next pass
    /// replaces them anyway.
    pub fn clear_counters(&mut self, only: Option<&str>) -> (bool, u32) {
        let found = only.is_none_or(|n| self.acls.contains_key(n));
        let targets: Vec<(Key, u32, String, Arc<Compiled>)> = self
            .installed
            .iter()
            .filter_map(|(k, at)| {
                let (name, acl) = (at.name.as_ref()?, at.acl.as_ref()?);
                only.is_none_or(|n| n == name)
                    .then(|| (k.clone(), at.ifindex, name.clone(), acl.clone()))
            })
            .collect();
        let mut n = 0;
        for (key, ifindex, name, acl) in targets {
            let before = self.installed.get(&key).map(|a| a.chain);
            self.apply_with(&key, ifindex, &name, &acl, true);
            if self.installed.get(&key).map(|a| a.chain) != before {
                n += 1;
            }
        }
        info!(acl = %only.unwrap_or("*"), attachments = n, "acl counters cleared");
        (found, n)
    }

    fn detach(&mut self, key: &Key) {
        let Some(at) = self.installed.remove(key) else {
            return;
        };
        match self.driver.detach(at.ifindex, key.1) {
            Ok(()) => info!(interface = %key.0, direction = %key.1, "acl detached"),
            Err(e) => {
                error!(interface = %key.0, direction = %key.1, error = %e, "acl not detached");
            }
        }
    }

    /// Every ACL (or the named one) with the counters of its live chains,
    /// ordered by name. A device whose dump fails is skipped, not an error.
    pub fn show(&mut self, only: Option<&str>) -> Vec<AclStatus> {
        let mut out = Vec::new();
        for (name, compiled) in &self.acls {
            if only.is_some_and(|o| o != name) {
                continue;
            }
            let mut attached = Vec::new();
            for ((dev, dir), at) in &self.installed {
                if at.name.as_deref() != Some(name) {
                    continue;
                }
                match self.driver.counters(at.ifindex, *dir, at.chain) {
                    Ok(counters) => {
                        let direction = match dir {
                            Direction::In => AclDirection::In,
                            Direction::Out => AclDirection::Out,
                        };
                        let interface = dev.clone();
                        attached.push((
                            AclAttachment {
                                interface,
                                direction,
                            },
                            counters,
                        ));
                    }
                    Err(e) => {
                        warn!(interface = %dev, direction = %dir, error = %e, "could not read the acl counters");
                    }
                }
            }
            out.push(status::status(name, compiled, &attached));
        }
        out
    }

    /// `(interface, acl, rule)` names of rule index `rule` installed on
    /// (`ifindex`, `dir`), for an `acl log` line; `None` for what this run did
    /// not install or an index past the ACL.
    pub fn log_target(
        &self,
        ifindex: u32,
        dir: Direction,
        rule: u32,
    ) -> Option<(String, String, String)> {
        let ((dev, _), at) = self
            .installed
            .iter()
            .find(|((_, d), at)| *d == dir && at.ifindex == ifindex)?;
        let (rule, _) = at
            .acl
            .as_ref()?
            .rule_names
            .get(usize::try_from(rule).ok()?)?;
        Some((dev.clone(), at.name.clone()?, rule.clone()))
    }

    /// An installed ACL has a `log` rule.
    pub fn logs(&self) -> bool {
        self.installed
            .values()
            .any(|at| at.acl.as_ref().is_some_and(|a| a.logs()))
    }

    /// The chains every (device, direction) points at, for tests and logs.
    pub fn live(&self) -> BTreeMap<Key, u32> {
        self.installed
            .iter()
            .map(|(k, v)| (k.clone(), v.chain))
            .collect()
    }
}

/// The engine, shared with the `show acl` server: a pass and a counter read
/// take the same lock, so a read never sees a chain a pass is replacing.
pub type Shared<D> = Arc<Mutex<Engine<D>>>;

/// Runs passes on every plan or link change until `shutdown`. Stopping leaves
/// every filter enforcing (fail closed, #663): the next start adopts them. An
/// input channel closing (its feeder task died) is an error, so the process
/// exits non-zero and the watchdog restarts it. With `log` (the Linux driver), the first pass
/// that installs a `log` rule starts the [`logger`] thread.
pub async fn run<D: Driver>(
    engine: Shared<D>,
    mut plan_rx: watch::Receiver<Option<Plan>>,
    mut links_rx: watch::Receiver<LinkTable>,
    mut shutdown: watch::Receiver<bool>,
    mut log: bool,
) -> anyhow::Result<()> {
    loop {
        let plan = plan_rx.borrow_and_update().clone();
        let links = links_rx.borrow_and_update().clone();
        if let Some(plan) = plan {
            let pass = engine.clone();
            tokio::task::spawn_blocking(move || pass.lock().unwrap().sync(&plan, &links))
                .await
                .expect("acl pass panicked");
            if log && engine.lock().unwrap().logs() {
                log = false;
                logger::spawn(engine.clone());
            }
        }
        tokio::select! {
            r = plan_rx.changed() => if r.is_err() { anyhow::bail!("plan feed closed") },
            r = links_rx.changed() => if r.is_err() { anyhow::bail!("link feed closed") },
            _ = shutdown.changed() => break,
        }
    }
    info!("acl engine stopped, filters left in place");
    Ok(())
}

#[path = "engine_flowspec.rs"]
mod flowspec_src;

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
