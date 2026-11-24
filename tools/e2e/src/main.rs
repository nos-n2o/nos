//! End-to-end verification against a real kernel: routers are real
//! `nos-watchdogd` containers, provisioned and observed only over their REST
//! API (see `router.rs`). Usage: `nos-e2e <phase|group|up|down|logs [n]|all>`.

// A test harness, not a daemon: the phase bodies are long, linear scripts over
// shared constants, so these pedantic lints only add noise.
#![allow(
    clippy::wildcard_imports,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

mod consts;
mod docker;
mod lab;
mod logd_mem;
mod logs;
mod modules;
mod phases;
mod rest;
mod router;
mod sshc;
mod world;

use std::process::ExitCode;

use world::World;

/// A phase's result in keep-going mode.
struct Outcome<'a> {
    phase: &'a str,
    error: Option<String>,
}

/// `NOS_E2E_KEEP_GOING=1` (the nightly only, #1294): run every phase, report at the end.
fn keep_going() -> bool {
    std::env::var("NOS_E2E_KEEP_GOING").as_deref() == Ok("1")
}

fn first_line(err: &str) -> String {
    err.lines().next().unwrap_or("").chars().take(200).collect()
}

/// `phase_start` tracks the unix second the running phase began. Fail-fast by
/// default (first error returns). With `keep_going` a phase error is recorded and
/// its docker logs dumped at once; only `up`/`established` stay fatal (nothing
/// later can run without the lab).
async fn run_all<'a>(
    w: &mut World,
    names: &[&'a str],
    phase_start: &mut i32,
    keep_going: bool,
    n: usize,
) -> anyhow::Result<Vec<Outcome<'a>>> {
    let mut outcomes = Vec::new();
    for &name in names {
        *phase_start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i32::try_from(d.as_secs()).unwrap_or(0));
        match phases::run(name, w).await {
            Ok(()) => outcomes.push(Outcome {
                phase: name,
                error: None,
            }),
            Err(e) if keep_going && !matches!(name, "up" | "established") => {
                let err = format!("{e:#}");
                eprintln!("[nos-e2e] phase {name} FAILED: {}", first_line(&err));
                w.dump_docker_logs(n, &err, *phase_start).await;
                outcomes.push(Outcome {
                    phase: name,
                    error: Some(err),
                });
            }
            Err(e) => return Err(e),
        }
    }
    Ok(outcomes)
}

/// The keep-going summary text and, when any phase failed, the group's error.
/// A failure after the first "may be a cascade": a failed phase skips its own
/// cleanup, so its leftovers are visible to every later phase.
fn summarize(group: &str, outcomes: &[Outcome]) -> (String, Option<anyhow::Error>) {
    use std::fmt::Write;
    let failed = outcomes.iter().filter(|o| o.error.is_some()).count();
    let mut text = format!(
        "[nos-e2e] {group} summary: {} run, {failed} failed\n",
        outcomes.len()
    );
    let mut first: Option<(&str, &str)> = None;
    for o in outcomes {
        match &o.error {
            None => {
                let _ = writeln!(text, "[nos-e2e]   OK      {}", o.phase);
            }
            Some(e) => {
                let note = if first.is_some() {
                    "   (after an earlier failure: may be a cascade)"
                } else {
                    ""
                };
                let _ = writeln!(
                    text,
                    "[nos-e2e]   FAILED  {}: {}{note}",
                    o.phase,
                    first_line(e)
                );
                first.get_or_insert((o.phase, e));
            }
        }
    }
    let err = first
        .map(|(p, e)| anyhow::anyhow!("{failed} phase(s) failed, first {p}: {}", first_line(e)));
    (text, err)
}

/// The groups `nos-e2e all` runs (CI's matrix minus the slow `pki-crl` (own job)
/// and `multi`, skipped until the `evpn-l3-chunked` hang is fixed (#839)).
const ALL_GROUPS: &[&str] = &["base", "drivers", "rpl", "ospf-suite", "pki-suite"];

/// One self-contained group: dump the failing router's logs on error, tear down
/// either way (`VERIFY_E2E_KEEP=1` keeps the containers for `nos-e2e logs`).
async fn run_group(w: &mut World, group: &str, n: usize) -> anyhow::Result<()> {
    let mut since = 0;
    let keep = keep_going();
    let names = phases::group(group).unwrap_or_default();
    let result = run_all(w, names, &mut since, keep, n).await;
    if let Err(e) = &result {
        w.dump_docker_logs(n, &format!("{e:#}"), since).await;
    }
    if std::env::var("VERIFY_E2E_KEEP").as_deref() != Ok("1") {
        w.down().await;
    }
    let outcomes = result?;
    if keep {
        let (text, err) = summarize(group, &outcomes);
        eprint!("{text}");
        if let Some(e) = err {
            return Err(e);
        }
    }
    Ok(())
}

async fn dispatch(cmd: &str, n: usize) -> anyhow::Result<()> {
    let mut w = World::new().await?;
    match cmd {
        "down" => {
            w.down().await;
            Ok(())
        }
        "logs" => w.print_logs(n).await,
        "logd-mem" => logd_mem::run(&w).await,
        "mem-wave" => logd_mem::wave(&w).await,
        // #887: `all` = the CI groups in sequence, each on a fresh `up` (what CI
        // proves); one shared lab across every phase piles up stale log lines.
        "all" => {
            let keep = keep_going();
            let mut errs = Vec::new();
            for g in ALL_GROUPS {
                match run_group(&mut w, g, n).await {
                    Err(e) if keep => errs.push(format!("{g}: {e:#}")),
                    r => r?,
                }
            }
            if errs.is_empty() {
                Ok(())
            } else {
                Err(anyhow::anyhow!("{}", errs.join("; ")))
            }
        }
        group if phases::group(group).is_some() => run_group(&mut w, group, n).await,
        phase => phases::run(phase, &mut w).await,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        eprintln!("usage: nos-e2e <phase|base|drivers|rpl|ospf-suite|multi|all|up|down|logs [n]>");
        return ExitCode::from(2);
    };
    let n = args.next().and_then(|s| s.parse().ok()).unwrap_or(200);
    match dispatch(&cmd, n).await {
        Ok(()) => {
            eprintln!("[nos-e2e] {cmd}: OK");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[nos-e2e] {cmd}: FAILED: {e:#}");
            modules::report_missing(&cmd);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o<'a>(phase: &'a str, error: Option<&str>) -> Outcome<'a> {
        Outcome {
            phase,
            error: error.map(String::from),
        }
    }

    #[test]
    fn all_ok() {
        let (t, e) = summarize("g", &[o("a", None), o("b", None)]);
        assert!(e.is_none() && !t.contains("FAILED") && t.contains("2 run, 0 failed"));
    }

    #[test]
    fn one_failure_keeps_first_line() {
        let (t, e) = summarize("g", &[o("a", None), o("b", Some("boom\nchain"))]);
        assert_eq!(e.unwrap().to_string(), "1 phase(s) failed, first b: boom");
        assert!(t.contains("FAILED  b: boom\n") && !t.contains("cascade"));
    }

    #[test]
    fn cascade_only_after_first() {
        let (t, e) = summarize("g", &[o("a", Some("x")), o("b", Some("y"))]);
        assert!(e
            .unwrap()
            .to_string()
            .contains("2 phase(s) failed, first a: x"));
        assert!(t.contains("FAILED  a: x\n"));
        assert!(t.contains("FAILED  b: y   (after an earlier failure: may be a cascade)"));
    }

    #[test]
    fn long_error_truncated() {
        let long = "z".repeat(500);
        let (t, _) = summarize("g", &[o("a", Some(&long))]);
        assert!(t.contains(&"z".repeat(200)) && !t.contains(&"z".repeat(201)));
    }

    /// `all` cannot drift from the phase list: every group resolves, and every
    /// phase of `ALL` is in some group or in the exempt ones (`multi`, `pki-crl`).
    #[test]
    fn all_groups_cover_every_phase() {
        let mut covered: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for g in ALL_GROUPS.iter().chain(&["multi", "pki-crl"]) {
            covered.extend(
                phases::group(g)
                    .unwrap_or_else(|| panic!("group {g}"))
                    .iter()
                    .copied(),
            );
        }
        let orphans: Vec<&str> = phases::ALL
            .iter()
            .copied()
            .filter(|p| !covered.contains(p))
            .collect();
        assert_eq!(
            orphans,
            ["logd-memory", "config-mem"],
            "phases in no group (the memory probes are manual runs)"
        );
    }
}
