#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nos_cli::command::Command;
use nos_cli::completer::NosCompleter;
use nos_cli::config_grammar;
use nos_cli::session::{self, Mode, Path};
use nos_proto::{CommandDoc, Topic};
use reedline::Completer;
use serde_json::Value;

fn config() -> &'static Value {
    static C: OnceLock<Value> = OnceLock::new();
    C.get_or_init(|| {
        let mut c = nos_proto::Config::default();
        c.bgp_instances.push(nos_proto::schema::BgpInstance {
            name: "r1".into(),
            ..Default::default()
        });
        serde_json::to_value(c).unwrap()
    })
}

const CONTEXTS: &[&[&str]] = &[&[], &["bgp-instance", "r1"], &["interface", "eth0"]];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Ok(line) = std::str::from_utf8(rest) else {
        return;
    };
    // The first byte picks the mode: operational, or configuration at one of CONTEXTS.
    let ctx: Vec<String> = CONTEXTS[sel as usize % CONTEXTS.len()]
        .iter()
        .map(ToString::to_string)
        .collect();
    let mode = if sel % 4 == 0 {
        Mode::Operational
    } else {
        Mode::Configuration {
            transaction: "t".into(),
            path: Path::from(ctx.clone()),
            dirty: false,
        }
    };
    let _ = session::resolve(&mode, Command::parse(line));
    let _ = config_grammar::parse(line, &ctx, config());
    let words: Vec<&str> = line.split_whitespace().collect();
    let _ = config_grammar::complete(&words, &ctx, config());
    let mut completer = NosCompleter::new(
        mode,
        Box::new(|topic: Topic| CommandDoc {
            topic,
            summary: String::new(),
            detail: String::new(),
        }),
        Box::new(|| Some(config().clone())),
    );
    let mut pos = (line.len() / 2 + sel as usize % 3).min(line.len());
    while !line.is_char_boundary(pos) {
        pos -= 1;
    }
    let _ = completer.complete(line, pos);
});
