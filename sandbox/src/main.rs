//! `nos-sandbox-exec --profile <name> -- <program> [args...]`: applies `NO_NEW_PRIVS`
//! to itself and execs the daemon with its file capabilities intact (see CLAUDE.md).
//! Fail closed: any error exits 126 and never execs unsandboxed.

use std::path::Path;

use nos_sandbox::{check_target, parse_args, sys, TARGET_DIR};

fn run() -> Result<std::convert::Infallible, nos_sandbox::Error> {
    // nosemgrep: rust.lang.security.args.args -- skip(1): only the arguments after argv[0] are used
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let inv = parse_args(&argv)?;
    let target = check_target(Path::new(&inv.program), Path::new(TARGET_DIR))?;
    let caps = sys::read_file_caps(&target)?;
    sys::set_caps(caps.permitted)?;
    sys::clear_ambient()?;
    sys::no_new_privs()?;
    // Built before install, so a build failure never leaves a half-sandboxed process.
    let filter = nos_sandbox::seccomp::deny_list()?;
    nos_sandbox::seccomp::install(&filter)?;
    Err(sys::exec(&target, &inv.args))
}

fn main() {
    // `run` only returns on error.
    let Err(e) = run();
    eprintln!("nos-sandbox-exec: {e}");
    std::process::exit(126);
}
