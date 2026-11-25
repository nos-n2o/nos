//! The `| <pipe>` tail of a `show` line (#1415). The single place that knows
//! the pipe grammar (#1420 adds the jq expression here), plus the escape-safe
//! JSON printer. Pure: no I/O besides the `Write` handed in.

use serde::Serialize;
use std::fmt::Write as _;
use std::io::Write;

/// What follows the `|`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pipe {
    Json,
}

/// How a reply is printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Text,
    Json,
}

impl Output {
    pub fn of(pipe: Option<Pipe>) -> Self {
        pipe.map_or(Output::Text, |Pipe::Json| Output::Json)
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
    match tail.split_whitespace().collect::<Vec<_>>()[..] {
        ["json"] => Ok((head, Some(Pipe::Json))),
        [] => Err("'|' needs a pipe: json".into()),
        [other, ..] => Err(format!("unknown pipe '{other}' (known: json)")),
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
        assert!(split("show x | jq .")
            .unwrap_err()
            .contains("unknown pipe 'jq'"));
        assert!(split("show x | json | json").is_err());
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
}
