//! Generic `show` renderer (#1422): turns any reply type that derives
//! `nos_proto::view::View` into a table (a list) or a key/value block (one
//! object), driven only by its `#[view]` metadata and `serde_json::to_value`.
//! Pure, no I/O. Unit helpers and the table layout are `table.rs`.
//!
//! `to_value` is the one seam: `| json` (#1415) and the jq filter (#1420)
//! start from it, the renderers below start from it too.

use crate::format::sanitize_line;
use crate::table::{human_bytes, human_count, human_duration, human_us, table, Align, Col};
use nos_proto::view::{view_of, Field, Node, Sort, Unit, ViewValue};
use serde::Serialize;
use serde_json::Value;
use std::cmp::Ordering;

/// Placeholder for a field with no printable value.
const NONE: &str = "-";

/// The reply as the JSON `nos-restd` serves it.
pub fn to_value<T: Serialize>(reply: &T) -> Value {
    serde_json::to_value(reply).unwrap_or(Value::Null)
}

/// `to_value`, then a table (a JSON array) or a detail block (an object).
pub fn render<T: Serialize + ViewValue>(reply: &T, empty: &str) -> String {
    let value = to_value(reply);
    match (view_of::<T>(), &value) {
        (Some(node), Value::Array(_)) => render_table(node, &value, empty),
        (Some(node), Value::Object(_)) => render_detail(node, &value),
        _ => cell(&TEXT, &value),
    }
}

/// A scalar reply has no node: print it as text.
static TEXT: Field = Field {
    key: "",
    header: "",
    unit: Unit::Text,
    brief: true,
    hidden: false,
    order: 0,
    sort: None,
    nested: None,
};

/// The one place a JSON value becomes text. Every string is sanitized.
fn cell(f: &Field, v: &Value) -> String {
    let raw = |v: &Value| match v {
        Value::String(s) => sanitize_line(s).into_owned(),
        other => other.to_string(),
    };
    match (v, f.unit) {
        (Value::Null, _) => NONE.into(),
        (Value::Array(a), _) => a.iter().map(|e| cell(f, e)).collect::<Vec<_>>().join(", "),
        (Value::Bool(b), _) => (if *b { "yes" } else { "no" }).into(),
        (v, Unit::Secs) => v.as_u64().map_or_else(|| raw(v), human_duration),
        (v, Unit::Micros) => v.as_u64().map_or_else(|| raw(v), human_us),
        (v, Unit::Bytes) => v.as_u64().map_or_else(|| raw(v), human_bytes),
        (v, Unit::Count) => v.as_u64().map_or_else(|| raw(v), human_count),
        (v, Unit::Mbps) => v.as_u64().map_or_else(|| raw(v), |n| format!("{n} Mb/s")),
        (v, _) => raw(v),
    }
}

/// A table column: the path of keys from a row to the value.
struct Column {
    path: Vec<&'static Field>,
}

fn get<'a>(path: &[&'static Field], row: &'a Value) -> &'a Value {
    path.iter()
        .try_fold(row, |v, f| v.get(f.key))
        .unwrap_or(&Value::Null)
}

impl Column {
    fn leaf(&self) -> &'static Field {
        self.path[self.path.len() - 1]
    }
}

/// Brief columns of `node`. A nested struct that is an object in some row is
/// the row's identity: its own brief fields lead as plain columns (no dotted
/// header). A nested list or an always-null one is detail only.
fn columns(node: &'static Node, rows: &[Value], prefix: &[&'static Field], out: &mut Vec<Column>) {
    for f in node.columns() {
        let mut path = prefix.to_vec();
        path.push(f);
        match f.nested_node() {
            None => out.push(Column { path }),
            Some(sub) => {
                if rows.iter().any(|r| get(&path, r).is_object()) {
                    columns(sub, rows, &path, out);
                }
            }
        }
    }
}

fn cmp_values(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Null, Value::Null) => Ordering::Equal,
        (Value::Null, _) => Ordering::Greater,
        (_, Value::Null) => Ordering::Less,
        (Value::Number(x), Value::Number(y)) => x
            .as_f64()
            .partial_cmp(&y.as_f64())
            .unwrap_or(Ordering::Equal),
        // Addresses order numerically, not as text.
        (Value::String(x), Value::String(y)) => {
            match (x.parse::<std::net::IpAddr>(), y.parse::<std::net::IpAddr>()) {
                (Ok(x), Ok(y)) => x.cmp(&y),
                _ => x.cmp(y),
            }
        }
        _ => Ordering::Equal,
    }
}

/// A JSON array of rows as a table of the node's brief fields; no rows gives
/// `empty`. Rows follow the `sort` field (stable), per page.
pub fn render_table(node: &'static Node, rows: &Value, empty: &str) -> String {
    let rows = rows.as_array().map_or(&[][..], Vec::as_slice);
    if rows.is_empty() {
        return empty.to_string();
    }
    let mut cols = Vec::new();
    columns(node, rows, &[], &mut cols);
    let mut order: Vec<&Value> = rows.iter().collect();
    if let Some(c) = cols.iter().find(|c| c.leaf().sort.is_some()) {
        let desc = c.leaf().sort == Some(Sort::Desc);
        order.sort_by(|a, b| {
            let o = cmp_values(get(&c.path, a), get(&c.path, b));
            if desc {
                o.reverse()
            } else {
                o
            }
        });
    }
    let heads: Vec<Col> = cols
        .iter()
        .map(|c| {
            let f = c.leaf();
            let align = match f.unit {
                Unit::Count | Unit::Secs | Unit::Micros | Unit::Bytes | Unit::Mbps => Align::Right,
                Unit::Bool | Unit::Text => Align::Left,
            };
            Col {
                header: f.header,
                align,
            }
        })
        .collect();
    let body: Vec<Vec<String>> = order
        .iter()
        .map(|r| {
            cols.iter()
                .map(|c| cell(c.leaf(), get(&c.path, r)))
                .collect()
        })
        .collect();
    table(&heads, &body)
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One object as `header  value` lines of every field not hidden. A nested
/// struct is a title line then its own indented block, a nested list a title
/// then an indented sub-table.
pub fn render_detail(node: &'static Node, obj: &Value) -> String {
    let fields = node.details();
    let width = fields
        .iter()
        .filter(|f| f.nested.is_none())
        .map(|f| f.header.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = Vec::new();
    for f in fields {
        let v = obj.get(f.key).unwrap_or(&Value::Null);
        match (f.nested_node(), v) {
            (Some(sub), Value::Object(_)) => {
                out.push(f.header.to_string());
                out.push(indent(&render_detail(sub, v)));
            }
            (Some(sub), Value::Array(a)) if !a.is_empty() => {
                out.push(f.header.to_string());
                out.push(indent(&render_table(sub, v, "")));
            }
            _ => out.push(format!("{:<width$}  {}", f.header, cell(f, v))),
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const fn field(key: &'static str, header: &'static str, unit: Unit) -> Field {
        Field {
            key,
            header,
            unit,
            brief: true,
            hidden: false,
            order: 0,
            sort: None,
            nested: None,
        }
    }
    fn inner() -> &'static Node {
        static N: Node = Node {
            fields: &[
                field("a", "A", Unit::Text),
                Field {
                    sort: Some(Sort::Asc),
                    ..field("b", "B", Unit::Count)
                },
            ],
        };
        &N
    }
    fn outer() -> &'static Node {
        static N: Node = Node {
            fields: &[
                Field {
                    nested: Some(inner),
                    ..field("id", "Id", Unit::Text)
                },
                field("dur", "Dur", Unit::Secs),
                Field {
                    brief: false,
                    ..field("note", "Note", Unit::Text)
                },
                Field {
                    hidden: true,
                    ..field("secret", "Secret", Unit::Text)
                },
                field("on", "On", Unit::Bool),
                Field {
                    nested: Some(inner),
                    ..field("kids", "Kids", Unit::Text)
                },
                Field {
                    order: 9,
                    ..field("rare", "Rare", Unit::Bytes)
                },
                Field {
                    order: 1,
                    ..field("mbps", "Rate", Unit::Mbps)
                },
            ],
        };
        &N
    }

    fn row(b: u64) -> Value {
        json!({"id": {"a": "x", "b": b}, "dur": 125, "note": "n", "secret": "s",
               "on": true, "kids": [{"a": "k", "b": 1}], "rare": 1500, "mbps": 100})
    }

    #[test]
    fn table_flattens_identity_sorts_and_formats() {
        let t = render_table(outer(), &json!([row(20), row(3)]), "none");
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "A   B    Dur  On       Rate    Rare");
        assert_eq!(lines[2], "x   3  2m05s  yes  100 Mb/s  1.5 KB");
        assert!(lines[3].starts_with("x  20"));
        assert!(!t.contains("Secret") && !t.contains("Note") && !t.contains("Kids"));
    }

    #[test]
    fn empty_and_drift_do_not_panic() {
        assert_eq!(render_table(outer(), &json!([]), "none"), "none");
        let t = render_table(
            outer(),
            &json!([{"id": {"a": 5}, "dur": "x", "on": null}]),
            "",
        );
        assert!(t.contains('5') && t.contains('x') && t.contains('-'));
    }

    #[test]
    fn detail_nests_titled() {
        let d = render_detail(outer(), &row(7));
        assert!(d.contains("Id\n  A  x\n  B  7\n"), "{d}");
        assert!(d.contains("Kids\n  A  B\n  -  -\n  k  1"), "{d}");
        assert!(d.contains("Note") && !d.contains("Secret"));
    }

    #[test]
    fn forged_strings_cannot_add_lines_or_escapes() {
        let mut r = row(1);
        r["id"]["a"] = json!("eth0\nFORGED  up");
        r["note"] = json!("\u{1b}[2J");
        let t = render_table(outer(), &json!([r.clone()]), "");
        assert_eq!(t.lines().count(), 3);
        let d = render_detail(outer(), &r);
        assert!(!t.contains('\u{1b}') && !d.contains('\u{1b}'));
        assert!(!d.contains("\nFORGED"));
    }

    #[test]
    fn value_to_text_only_in_cell() {
        let src = include_str!("view.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        let hits: Vec<_> = prod.lines().filter(|l| l.contains("to_string()")).collect();
        // `cell`'s raw fallback, plus `&str` conversions.
        assert!(
            hits.iter().all(|l| l.contains("other.to_string()")
                || l.contains("header.to_string()")
                || l.contains("empty.to_string()")),
            "{hits:?}"
        );
    }
}
