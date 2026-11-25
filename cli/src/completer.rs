//! Tab-completion and the data behind the live `?` key (see `help_menu.rs`):
//! the show/shell rows of `spec::COMMAND_SPECS` filtered to the current
//! `Mode`, and — for `edit`/`set`/`delete` — the schema's config tree
//! (`config_grammar::complete`). Both read `Suggestion`s from here, so they
//! always agree on what's valid to type next.

use nos_proto::{CommandDoc, Topic};
use reedline::{Completer, CompletionResult, Span, Suggestion};
use serde_json::Value;

use crate::config_grammar;
use crate::session::Mode;
use crate::spec::{self, Doc, Token};

/// Tab-completion for the nos-cli grammar. Talks to `nos-configd` only
/// through the two injected closures, so it never blocks on IPC directly
/// and stays testable without a real daemon.
pub struct NosCompleter {
    mode: Mode,
    /// Resolves a `Doc::FromConfig` topic to its text — production code
    /// wraps a cache-first, blocking-on-miss call to `client::describe`;
    /// tests supply canned docs.
    doc_source: Box<dyn FnMut(Topic) -> CommandDoc + Send>,
    /// The config to complete names and keys from, as JSON: the open
    /// transaction's, else the running one. Called at most once per
    /// completion.
    config_source: Box<dyn FnMut() -> Option<Value> + Send>,
    /// The log sources `nos-logd` holds, for `show log <source>`: production
    /// caches them for the session (#1452); called at most once per completion.
    log_sources: Box<dyn FnMut() -> Vec<String> + Send>,
}

impl NosCompleter {
    pub fn new(
        mode: Mode,
        doc_source: Box<dyn FnMut(Topic) -> CommandDoc + Send>,
        config_source: Box<dyn FnMut() -> Option<Value> + Send>,
        log_sources: Box<dyn FnMut() -> Vec<String> + Send>,
    ) -> Self {
        Self {
            mode,
            doc_source,
            config_source,
            log_sources,
        }
    }

    /// (summary, detail) for a `Doc` — a single call regardless of which
    /// text ends up displayed, so the live `?` key's second press (switching
    /// to detail) never needs a fresh fetch.
    fn doc_text_for(&mut self, doc: &Doc) -> (String, String) {
        match doc {
            Doc::Local { summary, detail } => ((*summary).to_string(), (*detail).to_string()),
            Doc::FromConfig(topic) => {
                let doc = (self.doc_source)(*topic);
                (doc.summary, doc.detail)
            }
        }
    }

    fn suggestion(
        &mut self,
        word: String,
        doc: Option<Doc>,
        usage: String,
        span: Span,
    ) -> Suggestion {
        let (description, extra) = match doc {
            Some(doc) => {
                let (summary, detail) = self.doc_text_for(&doc);
                // [usage, detail] — see `help_menu::HelpMenu::render_line`.
                (Some(summary), Some(vec![usage, detail]))
            }
            None => (None, None),
        };
        Suggestion {
            value: word,
            description,
            extra,
            span,
            append_whitespace: true,
            ..Default::default()
        }
    }
}

impl Completer for NosCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> CompletionResult {
        let line = &line[..pos];
        let ends_with_whitespace = line.chars().next_back().is_none_or(char::is_whitespace);
        let tokens = spec::tokenize_with_offsets(line);

        let (typed, partial_start, partial): (&[(usize, &str)], usize, &str) =
            if ends_with_whitespace || tokens.is_empty() {
                (&tokens, line.len(), "")
            } else {
                let (start, text) = tokens[tokens.len() - 1];
                (&tokens[..tokens.len() - 1], start, text)
            };
        let span = Span::new(partial_start, line.len());
        let words: Vec<&str> = typed.iter().map(|&(_, t)| t).collect();
        let mut out: Vec<Suggestion> = Vec::new();
        let mut config: Option<Option<Value>> = None;
        let mut config = |source: &mut Box<dyn FnMut() -> Option<Value> + Send>| {
            config.get_or_insert_with(source).clone()
        };

        let mut sources: Option<Vec<String>> = None;
        let typed_words: Vec<(usize, &str)> = typed.to_vec();
        for spec in spec::COMMAND_SPECS {
            if !spec::availability_matches(spec.availability, &self.mode) {
                continue;
            }
            let Some(walk) = spec::walk(spec, line, &typed_words) else {
                continue;
            };
            for token in walk.next {
                match token {
                    Token::Literal(lit) => {
                        if lit.starts_with(partial) && !out.iter().any(|s| s.value == lit) {
                            let s = self.suggestion(
                                lit.to_string(),
                                Some(spec.doc),
                                spec.usage.to_string(),
                                span,
                            );
                            out.push(s);
                        }
                    }
                    Token::Arg(kind) => {
                        let mut words: Vec<String> = kind
                            .fixed_values()
                            .into_iter()
                            .flatten()
                            .map(|v| (*v).to_string())
                            .collect();
                        if let Some(list) = kind.config_list() {
                            let doc = config(&mut self.config_source);
                            let names = doc.and_then(|d| d[list].as_array().cloned());
                            let names = names.unwrap_or_default();
                            words.extend(
                                names
                                    .iter()
                                    .filter_map(|e| e["name"].as_str().map(str::to_string)),
                            );
                        }
                        if kind == spec::ArgKind::LogSource {
                            let src = sources.get_or_insert_with(&mut self.log_sources);
                            words.extend(src.iter().cloned());
                        }
                        words.retain(|w| w.starts_with(partial));
                        words.retain(|w| !out.iter().any(|s| &s.value == w));
                        for w in words {
                            out.push(self.suggestion(w, None, String::new(), span));
                        }
                    }
                    Token::Opt(_) => {}
                }
            }
        }

        if let Mode::Configuration { path, .. } = &self.mode {
            let path = path.clone();
            if words.is_empty() {
                for (verb, doc) in spec::CONFIG_VERBS {
                    if verb.starts_with(partial) {
                        let s = self.suggestion(
                            (*verb).to_string(),
                            Some(*doc),
                            format!("{verb} …"),
                            span,
                        );
                        out.push(s);
                    }
                }
            } else if spec::CONFIG_VERBS.iter().any(|(v, _)| *v == words[0]) {
                let doc = config(&mut self.config_source).unwrap_or(Value::Null);
                for c in config_grammar::complete(&words, path.segments(), &doc) {
                    if c.word.starts_with(partial) && !out.iter().any(|s| s.value == c.word) {
                        let s =
                            self.suggestion(c.word, c.topic.map(Doc::FromConfig), c.usage, span);
                        out.push(s);
                    }
                }
            }
        }
        CompletionResult::fresh(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Path;

    fn doc_source() -> Box<dyn FnMut(Topic) -> CommandDoc + Send> {
        Box::new(|topic| CommandDoc {
            topic,
            summary: format!("summary for {topic:?}"),
            detail: format!("detail for {topic:?}"),
        })
    }

    fn config() -> Box<dyn FnMut() -> Option<Value> + Send> {
        Box::new(|| {
            let mut c = nos_proto::Config::default();
            c.bgp_instances.push(nos_proto::schema::BgpInstance {
                name: "r1".into(),
                ..Default::default()
            });
            c.routing_tables.push(nos_proto::schema::RoutingTable {
                name: "rt1".into(),
                ..Default::default()
            });
            serde_json::to_value(c).ok()
        })
    }

    fn log_sources() -> Box<dyn FnMut() -> Vec<String> + Send> {
        Box::new(|| vec!["nos-bgpd[r1]".into(), "nos-ribd[rt1]".into()])
    }

    fn values(mode: Mode, line: &str) -> Vec<String> {
        values_with(mode, line, log_sources())
    }

    fn values_with(
        mode: Mode,
        line: &str,
        sources: Box<dyn FnMut() -> Vec<String> + Send>,
    ) -> Vec<String> {
        let mut completer = NosCompleter::new(mode, doc_source(), config(), sources);
        let result = completer.complete(line, line.len());
        let mut v: Vec<String> = result
            .suggestions()
            .iter()
            .map(|s| s.value.clone())
            .collect();
        v.sort();
        v
    }

    fn configuring(path: &[&str]) -> Mode {
        Mode::Configuration {
            transaction: "t1".into(),
            path: Path::from(path.iter().map(ToString::to_string).collect::<Vec<_>>()),
            dirty: false,
        }
    }

    #[test]
    fn operational_mode_offers_show_rows_but_no_config_verbs() {
        let v = values(Mode::Operational, "");
        assert!(v.contains(&"show".to_string()) && v.contains(&"configure".to_string()));
        assert!(!v.contains(&"set".to_string()) && !v.contains(&"commit".to_string()));
    }

    #[test]
    fn configuration_mode_offers_the_config_verbs() {
        let v = values(configuring(&[]), "");
        for w in ["set", "delete", "edit", "commit", "show"] {
            assert!(v.contains(&w.to_string()), "{w} missing from {v:?}");
        }
    }

    #[test]
    fn config_words_come_from_the_tree_in_canonical_spelling() {
        let v = values(configuring(&[]), "set bg");
        assert!(v.contains(&"bgp".to_string()), "{v:?}");
        assert_eq!(
            values(configuring(&[]), "set bgp "),
            vec!["instance".to_string()]
        );
        assert_eq!(
            values(configuring(&[]), "edit bgp instance "),
            vec!["r1".to_string()]
        );
        let v = values(configuring(&["bgp-instance", "r1"]), "set ");
        assert!(
            v.contains(&"asn".to_string()) && v.contains(&"peer-group".to_string()),
            "{v:?}"
        );
    }

    #[test]
    fn enum_values_complete() {
        let v = values(
            configuring(&["bgp-instance", "r1"]),
            "set peer-group pg next-hop ",
        );
        assert_eq!(v, vec!["self".to_string(), "unchanged".to_string()]);
    }

    #[test]
    fn named_show_arguments_complete_from_the_config() {
        assert_eq!(
            values(Mode::Operational, "show route "),
            vec!["rt1".to_string()]
        );
    }

    fn show_log(line: &str) -> Vec<String> {
        values(Mode::Operational, line)
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn show_log_offers_the_clauses_and_sources() {
        assert_eq!(
            show_log("show log "),
            strs(&[
                "--follow",
                "last",
                "level",
                "match",
                "nos-bgpd[r1]",
                "nos-ribd[rt1]"
            ])
        );
        assert_eq!(
            show_log("show log nos-x "),
            strs(&["--follow", "last", "level", "match"])
        );
        assert_eq!(show_log("show log nos-r"), strs(&["nos-ribd[rt1]"]));
        assert_eq!(
            show_log("show log level "),
            strs(&["debug", "error", "info", "trace", "warn"])
        );
        assert_eq!(
            show_log("show log last 5 level warn "),
            strs(&["--follow", "match"])
        );
        assert_eq!(
            show_log("show log --follow last 5 level warn match "),
            Vec::<String>::new()
        );
    }

    #[test]
    fn log_sources_are_fetched_once_and_may_be_empty() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        let v = values_with(
            Mode::Operational,
            "show log ",
            Box::new(move || {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                vec!["nos-a".into()]
            }),
        );
        assert!(v.contains(&"nos-a".to_string()));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let v = values_with(Mode::Operational, "show log ", Box::new(Vec::new));
        assert_eq!(v, strs(&["--follow", "last", "level", "match"]));
    }

    #[test]
    fn fixed_values_complete_by_prefix() {
        let v = spec::ArgKind::LogLevel.fixed_values().unwrap();
        assert_eq!(v, ["trace", "debug", "info", "warn", "error"]);
        assert!(spec::ArgKind::Plain.fixed_values().is_none());
    }

    #[test]
    fn extra_carries_usage_and_detail_for_help_menu() {
        let mut completer = NosCompleter::new(
            configuring(&["bgp-instance", "r1"]),
            doc_source(),
            config(),
            log_sources(),
        );
        let result = completer.complete("set as", 6);
        let s = &result.suggestions()[0];
        assert_eq!(s.value, "asn");
        assert_eq!(s.description.as_deref(), Some("summary for BgpInstanceAsn"));
        assert_eq!(
            s.extra,
            Some(vec![
                "asn <n>".to_string(),
                "detail for BgpInstanceAsn".to_string()
            ])
        );
    }
}
