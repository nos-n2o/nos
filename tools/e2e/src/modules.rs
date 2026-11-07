//! Host kernel modules the lab needs (a container cannot `modprobe`). The one
//! list is the `table` in `tools/ci/e2e-preflight.sh` (`module phases-it-blocks`
//! per line); this file reads it so a failed run names the missing modules and
//! the phases they block instead of looking like a product regression (#897).

use crate::phases;

const SCRIPT: &str = include_str!("../../ci/e2e-preflight.sh");

/// `(module, phases it blocks)`; `*` stands for every phase.
fn table() -> Vec<(&'static str, Vec<&'static str>)> {
    SCRIPT
        .lines()
        .skip_while(|l| !l.starts_with("table='"))
        .skip(1)
        .take_while(|l| !l.starts_with('\''))
        .filter_map(|l| {
            let (m, blocks) = l.split_once(' ')?;
            Some((m, blocks.split(',').collect()))
        })
        .collect()
}

/// Whether the running kernel has `m`: loaded (`/sys/module`) or built in.
fn present(m: &str) -> bool {
    if std::path::Path::new(&format!("/sys/module/{m}")).is_dir() {
        return true;
    }
    let Ok(rel) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return true; // not Linux: say nothing rather than blame a module
    };
    std::fs::read_to_string(format!("/lib/modules/{}/modules.builtin", rel.trim()))
        .is_ok_and(|b| b.contains(&format!("/{m}.ko")))
}

/// The modules `have` rejects that block something `cmd` (a phase, a group,
/// `all`, or any other command) runs, with the blocked phases.
fn missing_for(cmd: &str, have: impl Fn(&str) -> bool) -> Vec<(&'static str, Vec<&'static str>)> {
    let run: Vec<&str> = match cmd {
        "all" => phases::ALL.to_vec(),
        c => phases::group(c).map_or_else(|| vec![c], <[&str]>::to_vec),
    };
    table()
        .into_iter()
        .filter(|(m, _)| !have(m))
        .filter_map(|(m, blocks)| {
            let hit: Vec<&str> = if blocks.contains(&"*") {
                vec!["every phase"]
            } else {
                blocks.into_iter().filter(|p| run.contains(p)).collect()
            };
            (!hit.is_empty()).then_some((m, hit))
        })
        .collect()
}

/// After a failed `cmd`: the missing host modules that block it, if any.
pub fn report_missing(cmd: &str) {
    let missing = missing_for(cmd, present);
    if missing.is_empty() {
        return;
    }
    eprintln!(
        "[nos-e2e] the host lacks kernel modules this run needs; the failure may be that, not a regression:"
    );
    for (m, hit) in missing {
        eprintln!("[nos-e2e]   {m}: blocks {}", hit.join(", "));
    }
    eprintln!(
        "[nos-e2e] fix: `make e2e-preflight`; modprobe line in docs/architecture/e2e-harness.md"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_parses_and_names_real_phases() {
        let t = table();
        assert!(t.len() >= 16, "script table not parsed: {t:?}");
        for (m, blocks) in t {
            for p in blocks {
                assert!(
                    p == "*" || phases::ALL.contains(&p),
                    "{m}: unknown phase {p}"
                );
            }
        }
    }

    #[test]
    fn missing_module_is_named_with_its_phases() {
        let without = |gone: &'static str| move |m: &str| m != gone;
        assert_eq!(
            missing_for("vpn-v6", without("mpls_router")),
            vec![("mpls_router", vec!["vpn-v6"])]
        );
        // a group blocks its members; an unrelated phase is not blamed
        assert!(missing_for("multi", without("mpls_router"))
            .iter()
            .any(|(m, _)| *m == "mpls_router"));
        assert_eq!(missing_for("gtsm", without("mpls_router")).len(), 0);
        assert_eq!(
            missing_for("gtsm", without("vrf")),
            vec![("vrf", vec!["every phase"])]
        );
        assert_eq!(missing_for("all", |_| true).len(), 0);
    }
}
