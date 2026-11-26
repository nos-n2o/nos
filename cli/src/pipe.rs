//! The `| <pipe>` tail of a `show` line (#1415). The single place that knows
//! the pipe grammar (#1420 adds the jq expression here), plus the escape-safe
//! JSON printer. Pure: no I/O besides the `Write` handed in.

use crate::jq::{self, Program, Tail};
use serde::Serialize;
use std::fmt::Write as _;
use std::io::Write;

/// What follows the `|`.
#[derive(Debug, Clone, PartialEq)]
pub enum Pipe {
    Json,
    DisplaySet,
    /// `| jq <expression>` (#1507), already parsed
    Jq(Program),
}

/// How a reply is printed.
#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    Text,
    Json,
    /// `| jq <expression>` (#1507)
    Jq(Program),
    /// `| display set` (#1462)
    Set,
}

impl Output {
    pub fn of(pipe: Option<Pipe>) -> Self {
        match pipe {
            None => Output::Text,
            Some(Pipe::Json) => Output::Json,
            Some(Pipe::DisplaySet) => Output::Set,
            Some(Pipe::Jq(p)) => Output::Jq(p),
        }
    }
}

/// Splits `line` at its first `|`. Only a `show` line (not `show log`, whose
/// `match <text>` takes the rest of the line, #1412) is split: any other line
/// is returned untouched, since a config value may legitimately hold a `|`.
pub fn split(line: &str) -> Result<(&str, Option<Pipe>), String> {
    let mut words = line.split_whitespace();
    let is_show = words.next() == Some("show") && words.next() != Some("log");
    let Some((head, tail)) = line.split_once('|').filter(|_| is_show) else {
        return Ok((line, None));
    };
    if let Some(rest) = tail
        .trim_start()
        .strip_prefix("jq")
        .filter(|r| r.is_empty() || r.starts_with(char::is_whitespace))
    {
        {
            let expr = rest.trim();
            // The expression may be wrapped in single quotes, as in a shell.
            let expr = expr
                .strip_prefix('\'')
                .and_then(|e| e.strip_suffix('\''))
                .unwrap_or(expr);
            if expr.is_empty() {
                return Err("usage: | jq <expression>".into());
            }
            return Ok((
                head,
                Some(Pipe::Jq(jq::parse(expr).map_err(|e| e.to_string())?)),
            ));
        }
    }
    match tail.split_whitespace().collect::<Vec<_>>()[..] {
        ["json"] => Ok((head, Some(Pipe::Json))),
        ["display", "set"] => Ok((head, Some(Pipe::DisplaySet))),
        [] => Err("'|' needs a pipe: json, display set, jq".into()),
        ["display", ..] => Err("usage: | display set".into()),
        [other, ..] => Err(format!(
            "unknown pipe '{other}' (known: json, display set, jq)"
        )),
    }
}

/// `serde_json` leaves DEL and the C1 range raw (U+009B is a CSI on some
/// terminals): rewrite them to `\u00XX`. They only occur inside JSON strings,
/// so a character-level replace keeps the JSON valid and lossless.
pub fn escape(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if matches!(c, '\u{7f}'..='\u{9f}') {
            let _ = write!(out, "\\u{:04x}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

/// A reply as pretty, escape-safe JSON — serialized directly (not through a
/// `Value`) so the key order equals the REST body's.
pub fn json_pretty<T: Serialize>(reply: &T) -> String {
    escape(&serde_json::to_string_pretty(reply).unwrap_or_else(|_| "null".into()))
}

/// One streamed JSON array, a page at a time (memory is one page): `[`, the
/// elements one per line, `]`. Dropping it without `end` leaves the array
/// unterminated on purpose, so a failed walk is not valid JSON.
pub struct JsonArray<'a, W: Write> {
    out: &'a mut W,
    any: bool,
}

impl<'a, W: Write> JsonArray<'a, W> {
    pub fn begin(out: &'a mut W) -> Self {
        let _ = write!(out, "[");
        Self { out, any: false }
    }

    pub fn page<T: Serialize>(&mut self, rows: &[T]) {
        for r in rows {
            let sep = if self.any { "," } else { "" };
            let row = escape(&serde_json::to_string(r).unwrap_or_default());
            let _ = write!(self.out, "{sep}\n{row}");
            self.any = true;
        }
    }

    pub fn end(self) {
        let _ = writeln!(self.out, "{}]", if self.any { "\n" } else { "" });
    }
}

/// A streamed array filtered by `| jq` (#1508): `Tail::Each` runs per row and
/// prints each result at once; `Tail::Count` only counts. The first per-row
/// error is kept (later rows are skipped) for the caller to report.
pub struct JqStream<'a, W: Write> {
    out: &'a mut W,
    tail: Tail,
    count: usize,
    err: Option<jq::JqError>,
}

impl<'a, W: Write> JqStream<'a, W> {
    pub fn begin(out: &'a mut W, tail: Tail) -> Self {
        Self {
            out,
            tail,
            count: 0,
            err: None,
        }
    }

    pub fn page<T: Serialize>(&mut self, rows: &[T]) {
        for r in rows {
            if self.err.is_some() {
                return;
            }
            match &self.tail {
                Tail::Count => self.count += 1,
                Tail::Each(p) => {
                    let v = serde_json::to_value(r).unwrap_or_default();
                    match p.run(&v) {
                        Ok(rs) => {
                            for x in rs {
                                let _ = writeln!(self.out, "{}", escape(&x.to_string()));
                            }
                        }
                        Err(e) => self.err = Some(e),
                    }
                }
            }
        }
    }

    /// Prints the count (if counting); the first error, if any.
    pub fn end(self) -> Result<(), jq::JqError> {
        if let Some(e) = self.err {
            return Err(e);
        }
        if matches!(self.tail, Tail::Count) {
            let _ = writeln!(self.out, "{}", self.count);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_grammar() {
        assert_eq!(split("show route rt1"), Ok(("show route rt1", None)));
        assert_eq!(
            split("show bfd sessions  |  json "),
            Ok(("show bfd sessions  ", Some(Pipe::Json)))
        );
        assert_eq!(split("show x |json"), Ok(("show x ", Some(Pipe::Json))));
        assert!(split("show x |").unwrap_err().contains("needs a pipe"));
        assert!(split("show x | yq .")
            .unwrap_err()
            .contains("unknown pipe 'yq'"));
        assert!(split("show x | jqx").is_err());
        assert!(split("show x | jq").unwrap_err().contains("usage: | jq"));
        assert!(split("show x | jq ''").unwrap_err().contains("usage: | jq"));
        assert!(split("show x | jq .a.").unwrap_err().starts_with("jq:"));
        assert!(split("show x | json | jq .").is_err());
        let jq = |l| match split(l) {
            Ok((h, Some(Pipe::Jq(p)))) => (h, p),
            o => panic!("{o:?}"),
        };
        assert_eq!(jq("show x | jq .").0, "show x ");
        let want = jq::parse(r#".[] | select(.a == "x|y")"#).unwrap();
        assert_eq!(jq(r#"show x | jq '.[] | select(.a == "x|y")'"#).1, want);
        assert_eq!(jq(r#"show x | jq .[] | select(.a == "x|y")"#).1, want);
        assert_eq!(Output::of(Some(Pipe::Jq(want.clone()))), Output::Jq(want));
        assert!(split("show x | json | json").is_err());
        assert_eq!(
            split("show config | display set"),
            Ok(("show config ", Some(Pipe::DisplaySet)))
        );
        for bad in [
            "display",
            "display foo",
            "display set x",
            "display set | json",
        ] {
            assert!(split(&format!("show config | {bad}")).is_err(), "{bad}");
        }
        assert_eq!(Output::of(Some(Pipe::DisplaySet)), Output::Set);
        // Not a show line, or `show log`: untouched.
        assert_eq!(
            split("set description a|b"),
            Ok(("set description a|b", None))
        );
        assert_eq!(
            split("show log match a|b"),
            Ok(("show log match a|b", None))
        );
        assert_eq!(split("showx | json"), Ok(("showx | json", None)));
    }

    #[test]
    fn escape_rewrites_del_and_c1() {
        let s = json_pretty(&"a\u{1b}b\u{9b}c\u{7f}d\ne\"");
        assert_eq!(s, r#""a\u001bb\u009bc\u007fd\ne\"""#);
        assert_eq!(
            serde_json::from_str::<String>(&s).unwrap(),
            "a\u{1b}b\u{9b}c\u{7f}d\ne\""
        );
    }

    #[test]
    fn key_order_is_declaration_order() {
        #[derive(Serialize)]
        struct S {
            z: u8,
            a: u8,
        }
        assert_eq!(
            json_pretty(&S { z: 1, a: 2 }),
            "{\n  \"z\": 1,\n  \"a\": 2\n}"
        );
    }

    #[test]
    fn array_streams_valid_json() {
        let mut buf = Vec::new();
        let mut a = JsonArray::begin(&mut buf);
        a.page::<u8>(&[]);
        a.page(&[1, 2]);
        a.page(&[3]);
        a.end();
        let v: Vec<u8> = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v, [1, 2, 3]);
        let mut buf = Vec::new();
        JsonArray::begin(&mut buf).end();
        assert_eq!(
            serde_json::from_slice::<Vec<u8>>(&buf).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn jq_stream_matches_whole_array() {
        let rows = [
            serde_json::json!({"a": 1, "s": "x"}),
            serde_json::json!({"a": 2, "s": "y"}),
        ];
        let pages: [&[serde_json::Value]; 3] = [&rows[..1], &[], &rows[1..]];
        let run = |src: &str, pages: &[&[serde_json::Value]]| {
            let mut buf = Vec::new();
            let mut s = JqStream::begin(&mut buf, jq::parse(src).unwrap().stream_tail().unwrap());
            for p in pages {
                s.page(p);
            }
            let r = s.end();
            (String::from_utf8(buf).unwrap(), r)
        };
        assert_eq!(run(".[] | select(.a == 2) | .s", &pages).0, "\"y\"\n");
        assert_eq!(run(".[] | .a", &pages).0, "1\n2\n");
        assert_eq!(run("length", &pages).0, "2\n");
        assert_eq!(run("length", &[&[]]).0, "0\n");
        // first error stops output, reported once
        let (o, r) = run(".[] | .a | length", &pages);
        assert_eq!(o, "");
        assert!(r.is_err());
    }
}
