//! The shell's escape surface (#1215, #1185): `nos` is an SSH login shell, so
//! no command may spawn a program, take a path, or read the environment beyond
//! `NOS_LOGIN_TICKET`/`NO_COLOR`. A source scan over `cli/src` (this file) plus
//! parse tests; clippy (`cli/clippy.toml`) and the `cli_parser` fuzz target are
//! the other guards. See docs/cli.md "Escape surface".

use nos_cli::command::Command;
use nos_cli::session::{self, Mode, Path, Resolved};

const FORBIDDEN: &[&str] = &[
    "tokio::process",
    "Command::new",
    "std::os::unix::process",
    "libc::system",
    "libc::exec",
    "libc::fork",
    "EDITOR",
    "PAGER",
    "SHELL",
    "\"HOME\"",
    "XDG_",
];
const FILE_ACCESS: &[&str] = &[
    "std::fs",
    "tokio::fs",
    "File::open",
    "File::create",
    "OpenOptions",
];
const ENV_READS: &[&str] = &["env::var", "env::vars", "env::args"];

fn is_code(line: &str) -> bool {
    !line.trim_start().starts_with("//")
}

/// Violations of the escape-surface rules in one source file.
fn violations(file: &str, src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate().filter(|(_, l)| is_code(l)) {
        let at = format!("{file}:{}", i + 1);
        // `std::process::exit` ends the shell; any other `std::process` item spawns.
        if line
            .replace("std::process::exit", "")
            .contains("std::process")
        {
            out.push(format!("{at}: std::process"));
        }
        for f in FORBIDDEN {
            if line.contains(f) {
                out.push(format!("{at}: forbidden `{f}`"));
            }
        }
        if file != "main.rs" && FILE_ACCESS.iter().any(|f| line.contains(f)) {
            out.push(format!("{at}: file access outside main.rs"));
        }
        if ENV_READS.iter().any(|e| line.contains(e))
            && !(line.contains("LOGIN_TICKET_ENV") || line.contains("\"NO_COLOR\""))
        {
            out.push(format!(
                "{at}: env read other than NOS_LOGIN_TICKET/NO_COLOR"
            ));
        }
    }
    if file == "main.rs" {
        // The single `--pki-ca` read; a second one fails here.
        let n = src
            .lines()
            .filter(|l| is_code(l) && FILE_ACCESS.iter().any(|f| l.contains(f)))
            .count();
        if n != 1 {
            out.push(format!(
                "{file}: {n} file accesses, exactly 1 (--pki-ca) allowed"
            ));
        }
    }
    out
}

#[test]
fn cli_source_has_no_escape_surface() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut bad = Vec::new();
    let mut files = 0;
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "rs") {
            files += 1;
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            bad.extend(violations(&name, &std::fs::read_to_string(&p).unwrap()));
        }
    }
    assert!(files > 20, "scan found only {files} files");
    assert!(
        bad.is_empty(),
        "escape surface (docs/cli.md \"Escape surface\"):\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_scan_fires() {
    let fires = |f: &str, s: &str| !violations(f, s).is_empty();
    for (f, s) in [
        ("x.rs", "let _ = std::process::Command::new(\"ls\");"),
        ("x.rs", "let _ = Command::new(\"ls\");"),
        ("x.rs", "let h = std::env::var(\"HOME\");"),
        ("x.rs", "let h = std::env::var_os(\"EDITOR\");"),
        ("x.rs", "let h = std::fs::read(p);"),
        ("main.rs", "std::fs::read(a);\nlet _ = tokio::fs::read(c);"),
        ("main.rs", "let x = 1;"),
    ] {
        assert!(fires(f, s), "{s}");
    }
    // allowed forms
    for (f, s) in [
        (
            "x.rs",
            "std::process::exit(2);\n// Command::new in a comment",
        ),
        ("x.rs", "std::env::var_os(nos_proto::LOGIN_TICKET_ENV);"),
        ("x.rs", "std::env::var_os(\"NO_COLOR\");"),
        ("main.rs", "std::fs::read(&pki_ca);"),
    ] {
        assert!(!fires(f, s), "{s}");
    }
}

#[test]
fn shell_metacharacters_never_become_commands_with_effects() {
    for line in [
        "!ls",
        "show version; ls",
        "`id`",
        "$(id)",
        "show version | sh",
        "show version > /tmp/x",
        "ls",
        "edit; id",
    ] {
        let cmd = Command::parse(line);
        assert!(
            matches!(cmd, Command::Unknown(_) | Command::Config(_)),
            "{line:?} parsed as {cmd:?}"
        );
        for mode in [
            Mode::Operational,
            Mode::Configuration {
                transaction: "t".into(),
                path: Path::from(vec![]),
                dirty: false,
            },
        ] {
            let r = session::resolve(&mode, cmd.clone());
            assert!(!matches!(r, Resolved::ExitShell), "{line:?} -> {r:?}");
        }
    }
}
