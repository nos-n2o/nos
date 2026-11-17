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

/// `phase_start` tracks the unix second the running phase began.
async fn run_all(w: &mut World, names: &[&str], phase_start: &mut i32) -> anyhow::Result<()> {
    for name in names {
        *phase_start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i32::try_from(d.as_secs()).unwrap_or(0));
        phases::run(name, w).await?;
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
        "all" => run_all(&mut w, phases::ALL, &mut 0).await,
        group if phases::group(group).is_some() => {
            let mut since = 0;
            let result =
                run_all(&mut w, phases::group(group).unwrap_or_default(), &mut since).await;
            if let Err(e) = &result {
                w.dump_docker_logs(n, &format!("{e:#}"), since).await;
            }
            // Tear down whether it passed or failed; VERIFY_E2E_KEEP=1 keeps
            // the containers for `nos-e2e logs` / manual inspection.
            if std::env::var("VERIFY_E2E_KEEP").as_deref() != Ok("1") {
                w.down().await;
            }
            result
        }
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
