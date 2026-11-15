//! The running config to what `nos-acld` must hold (pure): every ACL
//! compiled, and every `acl in/out` attach point.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use nos_proto::schema::{flowspec_points, Acl, Config, Subinterface};
use tracing::{error, info};

use crate::compile::{compile_within, Compiled, MAX_LEVELS};
use crate::driver::Direction;

/// An attach point's kernel device, before the link table resolves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Device {
    /// A physical interface or its `<name>.<tag>` subinterface.
    Kernel(String),
    /// A `PortAggregate` (its bond, named by `nos-interfaced`) or the bond's
    /// `<bond>.<tag>`; tag 0 is the bond itself.
    Aggregate { name: String, tag: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub device: Device,
    pub dir: Direction,
    pub acl: String,
}

/// What the engine applies. An ACL missing from `acls` (its compile failed
/// and none succeeded before) leaves its devices as they are.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Plan {
    pub acls: BTreeMap<String, Arc<Compiled>>,
    pub attachments: Vec<Attachment>,
    /// Per (BGP instance, VRF), the devices its flowspec rules filter
    /// (ingress): `None` = every `flowspec` device in the instance's own
    /// table, `Some(t)` = those in VRF `t`, a table whose `vpn` rides the
    /// instance.
    pub flowspec: FlowspecDevices,
}

/// `Plan::flowspec`.
pub type FlowspecDevices = BTreeMap<(String, Option<String>), Vec<Device>>;

fn attach(
    out: &mut Vec<Attachment>,
    device: &Device,
    acl_in: Option<&String>,
    acl_out: Option<&String>,
) {
    for (dir, acl) in [(Direction::In, acl_in), (Direction::Out, acl_out)] {
        if let Some(acl) = acl {
            out.push(Attachment {
                device: device.clone(),
                dir,
                acl: acl.clone(),
            });
        }
    }
}

/// Every attach point, in config order. Placement (no member, loopback or
/// switched port; one ACL per direction on an untagged device) is the
/// commit's job (`schema::acl::valid_acl_references`).
pub fn attachments(cfg: &Config) -> Vec<Attachment> {
    let mut out = Vec::new();
    let subs =
        |out: &mut Vec<Attachment>, subs: &[Subinterface], device: &dyn Fn(u16) -> Device| {
            for s in subs {
                attach(out, &device(s.tag), s.acl_in.as_ref(), s.acl_out.as_ref());
            }
        };
    for i in &cfg.interfaces {
        let device = Device::Kernel(i.name.clone());
        attach(&mut out, &device, i.acl_in.as_ref(), i.acl_out.as_ref());
        subs(&mut out, &i.subinterfaces, &|tag| {
            Device::Kernel(if tag == 0 {
                i.name.clone()
            } else {
                format!("{}.{tag}", i.name)
            })
        });
    }
    for a in &cfg.port_aggregates {
        let device = |tag| Device::Aggregate {
            name: a.name.clone(),
            tag,
        };
        attach(&mut out, &device(0), a.acl_in.as_ref(), a.acl_out.as_ref());
        subs(&mut out, &a.subinterfaces, &device);
    }
    out
}

/// Every `flowspec` device, per BGP instance owning its routing table
/// (#562 D-A). Placement is the commit's job
/// (`schema::acl::valid_flowspec_placements`).
pub fn flowspec_devices(cfg: &Config) -> FlowspecDevices {
    let mut out = FlowspecDevices::new();
    for p in flowspec_points(cfg) {
        let device = if p.aggregate {
            Device::Aggregate {
                name: p.parent.to_string(),
                tag: p.tag,
            }
        } else {
            Device::Kernel(p.device())
        };
        for b in &cfg.bgp_instances {
            if p.table.is_some() && b.routing_table.as_deref() == p.table {
                out.entry((b.name.clone(), None))
                    .or_default()
                    .push(device.clone());
            }
        }
        for t in &cfg.routing_tables {
            if let Some(b) = &t.vpn.bgp_instance
                && p.table == Some(t.name.as_str())
            {
                out.entry((b.clone(), Some(t.name.clone())))
                    .or_default()
                    .push(device.clone());
            }
        }
    }
    out
}

/// Compiles each ACL once per change; a failed compile keeps the last good
/// one (fail closed: the kernel keeps enforcing it).
pub struct Compiler {
    cache: HashMap<String, (Acl, Option<Arc<Compiled>>)>,
    max_levels: usize,
}

impl Default for Compiler {
    fn default() -> Self {
        Self {
            cache: HashMap::new(),
            max_levels: MAX_LEVELS,
        }
    }
}

impl Compiler {
    pub fn plan(&mut self, cfg: &Config) -> Plan {
        self.cache
            .retain(|name, _| cfg.acls.iter().any(|a| &a.name == name));
        let mut acls = BTreeMap::new();
        for acl in &cfg.acls {
            let previous = self.cache.get(&acl.name);
            let compiled = match previous {
                Some((seen, compiled)) if seen == acl => compiled.clone(),
                _ => {
                    let last = previous.and_then(|(_, c)| c.clone());
                    let compiled = compile_logged(acl, self.max_levels).map(Arc::new).or(last);
                    self.cache
                        .insert(acl.name.clone(), (acl.clone(), compiled.clone()));
                    compiled
                }
            };
            if let Some(c) = compiled {
                acls.insert(acl.name.clone(), c);
            }
        }
        Plan {
            acls,
            attachments: attachments(cfg),
            flowspec: flowspec_devices(cfg),
        }
    }
}

fn compile_logged(acl: &Acl, max_levels: usize) -> Option<Compiled> {
    match compile_within(acl, max_levels) {
        Ok(c) => {
            info!(
                acl = %acl.name, rules = c.rules, filters = c.filters(),
                levels = c.levels.len(), shadowed = c.shadowed.len(),
                trailing = c.trailing.len(), "compiled acl"
            );
            Some(c)
        }
        Err(e) => {
            error!(acl = %acl.name, error = %e, "acl does not compile, keeping the previous one");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use nos_proto::schema::{AclAction, AclRule, Interface, PortAggregate, PortRange};

    use super::*;

    fn sub(tag: u16, acl_in: Option<&str>, acl_out: Option<&str>) -> Subinterface {
        Subinterface {
            tag,
            acl_in: acl_in.map(Into::into),
            acl_out: acl_out.map(Into::into),
            ..Default::default()
        }
    }

    fn at(device: Device, dir: Direction, acl: &str) -> Attachment {
        Attachment {
            device,
            dir,
            acl: acl.into(),
        }
    }

    #[test]
    fn every_attach_point_resolves_to_its_device() {
        let cfg = Config {
            interfaces: vec![Interface {
                name: "eth0".into(),
                acl_in: Some("A".into()),
                subinterfaces: vec![sub(0, None, Some("B")), sub(100, Some("C"), None)],
                ..Default::default()
            }],
            port_aggregates: vec![PortAggregate {
                name: "agg".into(),
                acl_out: Some("D".into()),
                subinterfaces: vec![sub(7, Some("E"), Some("F"))],
                ..Default::default()
            }],
            ..Default::default()
        };
        let k = |n: &str| Device::Kernel(n.into());
        let agg = |tag| Device::Aggregate {
            name: "agg".into(),
            tag,
        };
        assert_eq!(
            attachments(&cfg),
            [
                at(k("eth0"), Direction::In, "A"),
                at(k("eth0"), Direction::Out, "B"),
                at(k("eth0.100"), Direction::In, "C"),
                at(agg(0), Direction::Out, "D"),
                at(agg(7), Direction::In, "E"),
                at(agg(7), Direction::Out, "F"),
            ]
        );
    }

    /// #562 D-A: a device follows its own table (the untagged
    /// subinterface's for the parent); a table no instance owns gives none.
    #[test]
    fn flowspec_devices_follow_their_table_to_its_instance() {
        use nos_proto::schema::{BgpInstance, RoutingTable, RoutingTableVpn};
        let in_table = |tag, rt: &str, flowspec| Subinterface {
            tag,
            routing_table: Some(rt.into()),
            flowspec,
            ..Default::default()
        };
        let cfg = Config {
            bgp_instances: vec![BgpInstance {
                name: "b1".into(),
                routing_table: Some("rt1".into()),
                ..Default::default()
            }],
            interfaces: vec![Interface {
                name: "eth0".into(),
                flowspec: true,
                subinterfaces: vec![in_table(0, "rt1", false), in_table(9, "rt2", true)],
                ..Default::default()
            }],
            port_aggregates: vec![PortAggregate {
                name: "agg".into(),
                subinterfaces: vec![in_table(7, "rt1", true)],
                ..Default::default()
            }],
            ..Default::default()
        };
        let got = flowspec_devices(&cfg);
        assert_eq!(
            got,
            BTreeMap::from([(
                ("b1".to_string(), None),
                vec![
                    Device::Kernel("eth0".into()),
                    Device::Aggregate {
                        name: "agg".into(),
                        tag: 7
                    }
                ]
            )])
        );
        // A VRF whose vpn rides b1 gets its own key; another instance's VRF
        // gives none.
        let vrf = |name: &str, b: &str| RoutingTable {
            name: name.into(),
            vpn: RoutingTableVpn {
                bgp_instance: Some(b.into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut cfg2 = cfg.clone();
        cfg2.routing_tables = vec![vrf("rt2", "b1"), vrf("rt3", "other")];
        cfg2.interfaces[0].subinterfaces[1].routing_table = Some("rt2".into());
        let got2 = flowspec_devices(&cfg2);
        assert_eq!(
            got2[&("b1".to_string(), Some("rt2".to_string()))],
            [Device::Kernel("eth0.9".into())]
        );
        assert_eq!(got2.len(), 2);
        assert_eq!(Compiler::default().plan(&cfg).flowspec, got);
    }

    /// `rules` denies that each overlap every earlier one without being
    /// inside it: `rules` levels.
    fn acl(rules: u16) -> Acl {
        Acl {
            name: "A".into(),
            default_action: AclAction::Permit,
            rules: (0..rules)
                .map(|i| AclRule {
                    name: format!("r{i}"),
                    action: AclAction::Deny,
                    destination_port: Some(PortRange { start: 0, end: i }),
                    ..Default::default()
                })
                .collect(),
        }
    }

    #[test]
    fn compiles_once_per_change_and_keeps_the_last_good_one() {
        let mut c = Compiler {
            max_levels: 4,
            ..Compiler::default()
        };
        let mut cfg = Config {
            acls: vec![acl(1)],
            ..Default::default()
        };
        let first = c.plan(&cfg).acls["A"].clone();
        assert!(
            Arc::ptr_eq(&first, &c.plan(&cfg).acls["A"]),
            "recompiled unchanged"
        );
        cfg.acls[0] = acl(5);
        assert!(
            Arc::ptr_eq(&first, &c.plan(&cfg).acls["A"]),
            "failure must keep the last"
        );
        cfg.acls[0] = acl(2);
        assert_eq!(c.plan(&cfg).acls["A"].rules, 2);
        cfg.acls.clear();
        assert!(c.plan(&cfg).acls.is_empty());
        cfg.acls = vec![acl(5)];
        assert!(c.plan(&cfg).acls.is_empty(), "nothing good to keep");
        cfg.acls[0].rules = vec![AclRule {
            log: true,
            ..Default::default()
        }];
        assert_eq!(c.plan(&cfg).acls["A"].rules, 1);
    }
}
