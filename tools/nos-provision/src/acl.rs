//! `--acl-rule`/`--acl-default`/`--acl-in` (#541) and
//! `--flowspec-interface` (#562): applied straight to a
//! local `Config`, like the spanning-tree flags (no `ConfigOp` exists for an
//! ACL). Only `nos-e2e` applies them; the binary refuses them.

use anyhow::{bail, Context};
use nos_proto::schema::{Acl, AclAction, AclRule, Config};

use crate::Args;

/// One `--acl-rule`: the ACL, the rule, and the rule it goes before.
type RuleFlag = (String, AclRule, Option<String>);

fn action(s: &str) -> anyhow::Result<AclAction> {
    Ok(match s {
        "permit" => AclAction::Permit,
        "deny" => AclAction::Deny,
        _ => bail!("action must be permit or deny, not '{s}'"),
    })
}

/// `ACL,RULE,permit|deny,PROTO,SRC,DST,DPORT[,before=RULE]`, `any` for an
/// unset field.
fn parse_rule(flag: &str) -> anyhow::Result<RuleFlag> {
    let f: Vec<&str> = flag.split(',').collect();
    let ctx = || format!("--acl-rule {flag}");
    if !(7..=8).contains(&f.len()) {
        bail!(
            "{}: want ACL,RULE,ACTION,PROTO,SRC,DST,DPORT[,before=RULE]",
            ctx()
        );
    }
    let any = |s: &str| (s != "any").then_some(s.to_string());
    let rule = AclRule {
        name: f[1].to_string(),
        action: action(f[2]).with_context(ctx)?,
        protocol: any(f[3])
            .map(|p| p.parse())
            .transpose()
            .map_err(anyhow::Error::msg)?,
        source: any(f[4]).map(|p| p.parse()).transpose().with_context(ctx)?,
        destination: any(f[5]).map(|p| p.parse()).transpose().with_context(ctx)?,
        destination_port: any(f[6])
            .map(|p| p.parse())
            .transpose()
            .map_err(anyhow::Error::msg)?,
        ..Default::default()
    };
    let before = match f.get(7) {
        Some(b) => Some(b.strip_prefix("before=").with_context(ctx)?.to_string()),
        None => None,
    };
    Ok((f[0].to_string(), rule, before))
}

fn on_off(s: &str) -> anyhow::Result<bool> {
    Ok(match s {
        "on" => true,
        "off" => false,
        _ => bail!("want on or off, not '{s}'"),
    })
}

/// `NAME=VALUE`.
fn pair<'a>(flag: &'a str, what: &str) -> anyhow::Result<(&'a str, &'a str)> {
    flag.split_once('=')
        .with_context(|| format!("--{what} {flag}: want NAME=VALUE"))
}

/// Every ACL flag parses (called from `build_ops`, which can fail).
pub fn check(args: &Args) -> anyhow::Result<()> {
    for f in &args.acl_rule {
        parse_rule(f)?;
    }
    for f in &args.acl_default {
        action(pair(f, "acl-default")?.1)?;
    }
    for f in &args.acl_in {
        pair(f, "acl-in")?;
    }
    for f in &args.flowspec_interface {
        on_off(pair(f, "flowspec-interface")?.1)?;
    }
    Ok(())
}

fn acl<'a>(config: &'a mut Config, name: &str) -> &'a mut Acl {
    if let Some(i) = config.acls.iter().position(|a| a.name == name) {
        return &mut config.acls[i];
    }
    config.acls.push(Acl {
        name: name.to_string(),
        ..Default::default()
    });
    config.acls.last_mut().expect("just pushed")
}

/// The flags applied to `config`; a rule already there is replaced in place
/// (or moved, with `before=`); `--acl-in IFACE=` detaches.
pub fn apply_acl(args: &Args, config: &mut Config) {
    for (name, value) in args.acl_default.iter().filter_map(|f| f.split_once('=')) {
        if let Ok(a) = action(value) {
            acl(config, name).default_action = a;
        }
    }
    for (name, rule, before) in args.acl_rule.iter().filter_map(|f| parse_rule(f).ok()) {
        let rules = &mut acl(config, &name).rules;
        let at = rules.iter().position(|r| r.name == rule.name);
        match (at, before) {
            (Some(i), None) => rules[i] = rule,
            (at, before) => {
                if let Some(i) = at {
                    rules.remove(i);
                }
                let i = before
                    .and_then(|b| rules.iter().position(|r| r.name == b))
                    .unwrap_or(rules.len());
                rules.insert(i, rule);
            }
        }
    }
    for (iface, name) in args.acl_in.iter().filter_map(|f| f.split_once('=')) {
        for i in config.interfaces.iter_mut().filter(|i| i.name == iface) {
            i.acl_in = (!name.is_empty()).then(|| name.to_string());
        }
    }
    for (iface, value) in args
        .flowspec_interface
        .iter()
        .filter_map(|f| f.split_once('='))
    {
        if let Ok(on) = on_off(value) {
            for i in config.interfaces.iter_mut().filter(|i| i.name == iface) {
                i.flowspec = on;
            }
        }
    }
}

/// True when any ACL flag is given (the binary refuses them).
pub fn any(args: &Args) -> bool {
    !(args.acl_rule.is_empty()
        && args.acl_default.is_empty()
        && args.acl_in.is_empty()
        && args.flowspec_interface.is_empty())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use nos_proto::schema::{AclProtocol, Interface, PortRange};

    use super::*;

    fn args(flags: &[&str]) -> Args {
        let base = [
            "p",
            "--address",
            "10.0.0.1/24",
            "--asn",
            "1",
            "--router-id",
            "1.1.1.1",
            "--remote-as",
            "2",
            "--peer",
            "10.0.0.2",
        ];
        let argv: Vec<String> = base
            .into_iter()
            .chain(flags.iter().copied())
            .map(ToString::to_string)
            .collect();
        // Same big-stack parse as `lib.rs`'s test `parse`.
        std::thread::Builder::new()
            .stack_size(16 << 20)
            .spawn(move || Args::try_parse_from(argv).unwrap())
            .unwrap()
            .join()
            .unwrap()
    }

    fn names(c: &Config) -> Vec<&str> {
        c.acls[0].rules.iter().map(|r| r.name.as_str()).collect()
    }

    #[test]
    fn rules_defaults_and_attach() {
        let a = args(&[
            "--acl-default",
            "E=permit",
            "--acl-rule",
            "E,p-bgp,permit,tcp,10.50.0.3/32,any,179",
            "--acl-rule",
            "E,p-icmp,permit,icmp,any,any,any",
            "--acl-in",
            "eth0=E",
        ]);
        check(&a).unwrap();
        assert!(any(&a));
        let mut c = Config {
            interfaces: vec![Interface {
                name: "eth0".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        apply_acl(&a, &mut c);
        assert_eq!(c.acls[0].default_action, AclAction::Permit);
        assert_eq!(names(&c), ["p-bgp", "p-icmp"]);
        let r = &c.acls[0].rules[0];
        assert_eq!(r.protocol, Some(AclProtocol::Tcp));
        assert_eq!(r.source, Some("10.50.0.3/32".parse().unwrap()));
        assert_eq!(r.destination, None);
        assert_eq!(
            r.destination_port,
            Some(PortRange {
                start: 179,
                end: 179
            })
        );
        assert_eq!(c.interfaces[0].acl_in.as_deref(), Some("E"));

        // Insert before, move, replace in place, detach.
        apply_acl(
            &args(&["--acl-rule", "E,d,deny,tcp,any,any,any,before=p-bgp"]),
            &mut c,
        );
        assert_eq!(names(&c), ["d", "p-bgp", "p-icmp"]);
        apply_acl(
            &args(&["--acl-rule", "E,d,deny,tcp,any,any,any,before=p-icmp"]),
            &mut c,
        );
        assert_eq!(names(&c), ["p-bgp", "d", "p-icmp"]);
        apply_acl(
            &args(&["--acl-rule", "E,p-bgp,deny,udp,any,any,53"]),
            &mut c,
        );
        assert_eq!(names(&c), ["p-bgp", "d", "p-icmp"]);
        assert_eq!(c.acls[0].rules[0].action, AclAction::Deny);
        apply_acl(&args(&["--acl-in", "eth0="]), &mut c);
        assert_eq!(c.interfaces[0].acl_in, None);
        let on = args(&["--flowspec-interface", "eth0=on"]);
        check(&on).unwrap();
        assert!(any(&on));
        apply_acl(&on, &mut c);
        assert!(c.interfaces[0].flowspec);
        apply_acl(&args(&["--flowspec-interface", "eth0=off"]), &mut c);
        assert!(!c.interfaces[0].flowspec);
        assert!(!any(&args(&[])));
    }

    #[test]
    fn hold_time_and_flag_checks_reach_build_ops() {
        use nos_proto::{BgpPeerGroupOp as Op, ConfigOp};
        let ops = crate::build_ops(&args(&["--hold-time", "9"])).unwrap();
        assert!(ops.iter().any(|o| matches!(
            o,
            ConfigOp::BgpPeerGroup(Op::SetHoldTime { hold_time: 9, .. })
        )));
        let ops = crate::build_ops(&args(&["--no-hold-time"])).unwrap();
        assert!(ops
            .iter()
            .any(|o| matches!(o, ConfigOp::BgpPeerGroup(Op::ClearHoldTime { .. }))));
        assert!(crate::build_ops(&args(&["--acl-in", "eth0"])).is_err());
    }

    #[test]
    fn a_port_range_and_udp_parse() {
        let a = args(&["--acl-rule", "E,r,deny,udp,any,198.51.100.0/25,1000-2000"]);
        let mut c = Config::default();
        apply_acl(&a, &mut c);
        let r = &c.acls[0].rules[0];
        assert_eq!(r.protocol, Some(AclProtocol::Udp));
        assert_eq!(
            r.destination_port,
            Some(PortRange {
                start: 1000,
                end: 2000
            })
        );
    }

    #[test]
    fn bad_flags_are_refused() {
        for bad in [
            ["--acl-rule", "E,r,permit"],
            ["--acl-rule", "E,r,allow,tcp,any,any,any"],
            ["--acl-rule", "E,r,permit,ospf,any,any,any"],
            ["--acl-rule", "E,r,permit,tcp,nope,any,any"],
            ["--acl-rule", "E,r,permit,tcp,any,nope,any"],
            ["--acl-rule", "E,r,permit,tcp,any,any,x"],
            ["--acl-rule", "E,r,permit,tcp,any,any,any,after=x"],
            ["--acl-default", "E"],
            ["--acl-default", "E=maybe"],
            ["--acl-in", "eth0"],
            ["--flowspec-interface", "eth0"],
            ["--flowspec-interface", "eth0=yes"],
        ] {
            assert!(check(&args(&bad)).is_err(), "{bad:?}");
        }
    }
}
