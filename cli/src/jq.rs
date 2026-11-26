//! The `| jq <expression>` filter (#1507, #1420): a small hand-written subset
//! of jq over a reply's JSON (`view::to_value`). Pure: no I/O.
//!
//! Grammar: `pipe := term ('|' term)*`, `term := path | select(cond) | length
//! | { key: path, ... }`, `path := '.' (key | "key" | '[' n ']' | '[]')*`,
//! `cond := path [op literal]` with `op` one of `== != < <= > >=`.

use serde_json::{Map, Value};
use std::fmt;

const MAX_LEN: usize = 512;
const MAX_STAGES: usize = 16;
/// Results of one run: guards `.[]` fan-out on a big reply.
const MAX_RESULTS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JqError(String);

impl fmt::Display for JqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "jq: {}", self.0)
    }
}

type Res<T> = Result<T, JqError>;

fn err<T>(msg: impl Into<String>) -> Res<T> {
    Err(JqError(msg.into()))
}

#[derive(Debug, Clone, PartialEq)]
enum Seg {
    Key(String),
    Idx(usize),
    Iter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, PartialEq)]
enum Term {
    Path(Vec<Seg>),
    /// `select(path)` (truthy) or `select(path op literal)`
    Select(Vec<Seg>, Option<(Op, Value)>),
    Length,
    Object(Vec<(String, Vec<Seg>)>),
}

/// A parsed expression.
#[derive(Debug, Clone, PartialEq)]
pub struct Program(Vec<Term>);

struct Parser<'a> {
    s: &'a str,
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.s[self.i..].chars().next()
    }

    fn bump(&mut self) {
        self.i += self.peek().map_or(0, char::len_utf8);
    }

    fn ws(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.bump();
        }
    }

    fn eat(&mut self, c: char) -> bool {
        let hit = self.peek() == Some(c);
        if hit {
            self.bump();
        }
        hit
    }

    fn fail<T>(&self, what: &str) -> Res<T> {
        match self.peek() {
            Some(c) => err(format!("{what}, found '{c}' at byte {}", self.i)),
            None => err(format!(
                "{what}, found end of expression at byte {}",
                self.i
            )),
        }
    }

    fn expect(&mut self, c: char) -> Res<()> {
        if self.eat(c) {
            Ok(())
        } else {
            self.fail(&format!("expected '{c}'"))
        }
    }

    fn ident(&mut self) -> String {
        let start = self.i;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            self.bump();
        }
        self.s[start..self.i].to_string()
    }

    fn program(&mut self) -> Res<Program> {
        let mut terms = vec![self.term()?];
        loop {
            self.ws();
            if !self.eat('|') {
                break;
            }
            if terms.len() == MAX_STAGES {
                return err(format!("more than {MAX_STAGES} pipe stages"));
            }
            terms.push(self.term()?);
        }
        if self.peek().is_some() {
            return self.fail("unexpected input");
        }
        Ok(Program(terms))
    }

    fn term(&mut self) -> Res<Term> {
        self.ws();
        match self.peek() {
            Some('.') => Ok(Term::Path(self.path()?)),
            Some('{') => self.object(),
            Some(c) if c.is_ascii_alphabetic() => match self.ident().as_str() {
                "length" => Ok(Term::Length),
                "select" => {
                    self.ws();
                    self.expect('(')?;
                    self.ws();
                    let path = self.path()?;
                    self.ws();
                    let cmp = if matches!(self.peek(), Some('=' | '!' | '<' | '>')) {
                        let op = self.op()?;
                        self.ws();
                        Some((op, self.literal()?))
                    } else {
                        None
                    };
                    self.ws();
                    self.expect(')')?;
                    Ok(Term::Select(path, cmp))
                }
                f => err(format!("unknown function '{f}' (known: select, length)")),
            },
            _ => self.fail("expected a path, select(...), length or {...}"),
        }
    }

    fn op(&mut self) -> Res<Op> {
        let first = self.peek();
        self.bump();
        let eq = self.eat('=');
        match (first, eq) {
            (Some('='), true) => Ok(Op::Eq),
            (Some('!'), true) => Ok(Op::Ne),
            (Some('<'), true) => Ok(Op::Le),
            (Some('>'), true) => Ok(Op::Ge),
            (Some('<'), false) => Ok(Op::Lt),
            (Some('>'), false) => Ok(Op::Gt),
            _ => self.fail("expected one of == != < <= > >="),
        }
    }

    fn path(&mut self) -> Res<Vec<Seg>> {
        self.expect('.')?;
        let mut segs = vec![];
        let mut after_dot = true;
        loop {
            match self.peek() {
                Some(c) if after_dot && (c.is_ascii_alphabetic() || c == '_') => {
                    segs.push(Seg::Key(self.ident()));
                    after_dot = false;
                }
                Some('"') if after_dot => {
                    segs.push(Seg::Key(self.string()?));
                    after_dot = false;
                }
                Some('[') => {
                    self.bump();
                    self.ws();
                    if self.eat(']') {
                        segs.push(Seg::Iter);
                    } else {
                        let start = self.i;
                        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                            self.bump();
                        }
                        let Ok(n) = self.s[start..self.i].parse() else {
                            return self.fail("expected an index or ']'");
                        };
                        self.ws();
                        self.expect(']')?;
                        segs.push(Seg::Idx(n));
                    }
                    after_dot = false;
                }
                Some('.') if !after_dot => {
                    self.bump();
                    after_dot = true;
                }
                _ => break,
            }
        }
        if after_dot && !segs.is_empty() {
            return self.fail("expected a key after '.'");
        }
        Ok(segs)
    }

    fn object(&mut self) -> Res<Term> {
        self.expect('{')?;
        let mut fields = vec![];
        loop {
            self.ws();
            let key = match self.peek() {
                Some('"') => self.string()?,
                Some(c) if c.is_ascii_alphabetic() || c == '_' => self.ident(),
                _ => return self.fail("expected an object key"),
            };
            self.ws();
            self.expect(':')?;
            self.ws();
            fields.push((key, self.path()?));
            self.ws();
            if self.eat('}') {
                return Ok(Term::Object(fields));
            }
            self.expect(',')?;
        }
    }

    fn literal(&mut self) -> Res<Value> {
        match self.peek() {
            Some('"') => Ok(Value::String(self.string()?)),
            Some(c) if c == '-' || c.is_ascii_digit() => {
                let start = self.i;
                while self
                    .peek()
                    .is_some_and(|c| c.is_ascii_digit() || matches!(c, '-' | '+' | '.' | 'e' | 'E'))
                {
                    self.bump();
                }
                match self.s[start..self.i]
                    .parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                {
                    Some(n) => Ok(Value::Number(n)),
                    None => err(format!("bad number at byte {start}")),
                }
            }
            Some(c) if c.is_ascii_alphabetic() => {
                let at = self.i;
                match self.ident().as_str() {
                    "true" => Ok(Value::Bool(true)),
                    "false" => Ok(Value::Bool(false)),
                    "null" => Ok(Value::Null),
                    w => err(format!("unknown literal '{w}' at byte {at}")),
                }
            }
            _ => self.fail("expected a literal"),
        }
    }

    fn string(&mut self) -> Res<String> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            let at = self.i;
            let Some(c) = self.peek() else {
                return err(format!("unterminated string at byte {at}"));
            };
            self.bump();
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let Some(e) = self.peek() else {
                        return err(format!("unterminated string at byte {at}"));
                    };
                    self.bump();
                    out.push(match e {
                        '"' | '\\' => e,
                        'n' => '\n',
                        't' => '\t',
                        // ponytail: no surrogate pairs (a lone \uD83D is refused); add if needed
                        'u' => {
                            let hex = self.s.get(self.i..self.i + 4).unwrap_or("");
                            let ch = u32::from_str_radix(hex, 16)
                                .ok()
                                .and_then(char::from_u32)
                                .filter(|_| hex.len() == 4);
                            let Some(ch) = ch else {
                                return err(format!("bad \\u escape at byte {at}"));
                            };
                            self.i += 4;
                            ch
                        }
                        _ => return err(format!("bad escape '\\{e}' at byte {at}")),
                    });
                }
                c => out.push(c),
            }
        }
    }
}

/// Parses an expression; the errors carry a byte offset.
pub fn parse(src: &str) -> Res<Program> {
    if src.len() > MAX_LEN {
        return err(format!("expression longer than {MAX_LEN} bytes"));
    }
    Parser { s: src, i: 0 }.program()
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn too_many<T>() -> Res<T> {
    err(format!("more than {MAX_RESULTS} results"))
}

fn walk(segs: &[Seg], v: &Value) -> Res<Vec<Value>> {
    let mut cur = vec![v.clone()];
    for seg in segs {
        let mut next = vec![];
        for x in cur {
            match (seg, x) {
                (Seg::Key(_) | Seg::Idx(_), Value::Null) => next.push(Value::Null),
                (Seg::Key(k), Value::Object(mut m)) => next.push(m.remove(k).unwrap_or_default()),
                (Seg::Key(k), x) => return err(format!("cannot index {} with \"{k}\"", kind(&x))),
                (Seg::Idx(i), Value::Array(mut a)) => {
                    next.push(if *i < a.len() {
                        a.swap_remove(*i)
                    } else {
                        Value::Null
                    });
                }
                (Seg::Idx(_), x) => return err(format!("cannot index {} with number", kind(&x))),
                (Seg::Iter, Value::Array(a)) => next.extend(a),
                (Seg::Iter, Value::Object(m)) => next.extend(m.into_iter().map(|(_, v)| v)),
                (Seg::Iter, x) => return err(format!("cannot iterate over {}", kind(&x))),
            }
            if next.len() > MAX_RESULTS {
                return too_many();
            }
        }
        cur = next;
    }
    Ok(cur)
}

fn truthy(v: &Value) -> bool {
    !matches!(v, Value::Null | Value::Bool(false))
}

fn holds(a: &Value, op: Op, b: &Value) -> bool {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let ord = match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64().partial_cmp(&y.as_f64()),
        (Value::String(x), Value::String(y)) => Some(x.cmp(y)),
        // Across kinds only (in)equality is defined (jq orders them; we don't).
        _ => return (op == Op::Eq && a == b) || (op == Op::Ne && a != b),
    };
    matches!(
        (op, ord),
        (Op::Eq, Some(Equal))
            | (Op::Ne, Some(Less | Greater) | None)
            | (Op::Lt, Some(Less))
            | (Op::Le, Some(Less | Equal))
            | (Op::Gt, Some(Greater))
            | (Op::Ge, Some(Greater | Equal))
    )
}

impl Term {
    fn apply(&self, v: &Value, out: &mut Vec<Value>) -> Res<()> {
        match self {
            Term::Path(segs) => out.extend(walk(segs, v)?),
            Term::Select(segs, cmp) => {
                for r in walk(segs, v)? {
                    let keep = match cmp {
                        Some((op, lit)) => holds(&r, *op, lit),
                        None => truthy(&r),
                    };
                    if keep {
                        out.push(v.clone());
                    }
                }
            }
            Term::Length => out.push(match v {
                Value::Null => 0.into(),
                Value::String(s) => s.chars().count().into(),
                Value::Array(a) => a.len().into(),
                Value::Object(m) => m.len().into(),
                _ => return err(format!("{} has no length", kind(v))),
            }),
            Term::Object(fields) => {
                // ponytail: keys come out sorted (serde_json without preserve_order, which would reorder the REST snapshot workspace-wide)
                let mut m = Map::new();
                for (k, segs) in fields {
                    let mut vals = walk(segs, v)?;
                    if vals.len() != 1 {
                        return err(format!("object value for \"{k}\" must be a single value"));
                    }
                    m.insert(k.clone(), vals.remove(0));
                }
                out.push(Value::Object(m));
            }
        }
        if out.len() > MAX_RESULTS {
            return too_many();
        }
        Ok(())
    }
}

impl Program {
    /// The results, in order (one input can yield many or none).
    pub fn run(&self, input: &Value) -> Res<Vec<Value>> {
        let mut cur = vec![input.clone()];
        for t in &self.0 {
            let mut next = vec![];
            for v in cur {
                t.apply(&v, &mut next)?;
            }
            cur = next;
        }
        Ok(cur)
    }

    /// The program after a leading `.[]`, for a streamed walk to apply per
    /// element (#1508); `None` when it does not start that way.
    pub fn split_iter(&self) -> Option<Program> {
        match self.0.split_first() {
            Some((Term::Path(s), rest)) if s == &[Seg::Iter] => Some(Program(rest.to_vec())),
            _ => None,
        }
    }

    /// How a streamed array walk can run this program without holding the
    /// array (#1508): per element after `.[]`, or a bare `length` as a count.
    pub fn stream_tail(&self) -> Option<Tail> {
        match self.0.as_slice() {
            [Term::Length] => Some(Tail::Count),
            _ => self.split_iter().map(Tail::Each),
        }
    }
}

/// See [`Program::stream_tail`].
#[derive(Debug, Clone, PartialEq)]
pub enum Tail {
    Each(Program),
    Count,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(src: &str, v: &Value) -> Vec<Value> {
        parse(src).unwrap().run(v).unwrap()
    }

    fn run_err(src: &str, v: &Value) -> String {
        parse(src).unwrap().run(v).unwrap_err().to_string()
    }

    fn parse_err(src: &str) -> String {
        parse(src).unwrap_err().to_string()
    }

    fn doc() -> Value {
        json!({"a": {"b": [10, 20, 30]}, "s": "héllo", "n": null,
               "rows": [{"state": "up", "id": 1}, {"state": "down", "id": 2}, {"id": 3}]})
    }

    #[test]
    fn stream_tail_classes() {
        let t = |s: &str| parse(s).unwrap().stream_tail();
        assert_eq!(t("length"), Some(Tail::Count));
        for yes in [".[]", ".[] | .a", ".[] | select(.a == 1)", ".[] | length"] {
            assert!(matches!(t(yes), Some(Tail::Each(_))), "{yes}");
        }
        for no in [".[0]", "select(.a == 1)", ".", ".a", "{a: .b}"] {
            assert_eq!(t(no), None, "{no}");
        }
    }

    #[test]
    fn paths() {
        let d = doc();
        assert_eq!(run(".", &d), std::slice::from_ref(&d));
        assert_eq!(run(".a.b[1]", &d), [json!(20)]);
        assert_eq!(run(".a.b[]", &d), [json!(10), json!(20), json!(30)]);
        assert_eq!(run(".rows[].id", &d), [json!(1), json!(2), json!(3)]);
        assert_eq!(run(".\"s\"", &d), [json!("héllo")]);
        assert_eq!(run(". | .s | .", &d), [json!("héllo")]);
        assert_eq!(run(".[0]", &json!([7])), [json!(7)]);
        assert_eq!(run(".[]", &json!({"x": 1, "y": 2})), [json!(1), json!(2)]);
    }

    #[test]
    fn missing_is_null() {
        let d = doc();
        assert_eq!(run(".zz", &d), [Value::Null]);
        assert_eq!(run(".a.b[9]", &d), [Value::Null]);
        assert_eq!(run(".n.x[3]", &d), [Value::Null]);
    }

    #[test]
    fn select_ops() {
        let d = doc();
        let ids = |e: &str| -> Vec<i64> {
            run(e, &d)
                .iter()
                .map(|r| r["id"].as_i64().unwrap())
                .collect()
        };
        let sel = |e: &str| ids(&format!(".rows[] | select({e})"));
        assert_eq!(sel(".state == \"up\""), [1]);
        assert_eq!(sel(".state != \"up\""), [2, 3]);
        assert_eq!(sel(".id < 2"), [1]);
        assert_eq!(sel(".id <= 2"), [1, 2]);
        assert_eq!(sel(".id > 2"), [3]);
        assert_eq!(sel(".id >= 2"), [2, 3]);
        assert_eq!(sel(".state"), [1, 2]);
        assert_eq!(sel(".state < 3"), Vec::<i64>::new());
        assert_eq!(sel(".state == null"), [3]);
        assert_eq!(sel(".id == 1.0e0"), [1]);
        assert_eq!(
            sel(".state == \"a\\u0062\\\"\\n\\t\\\\\""),
            Vec::<i64>::new()
        );
    }

    #[test]
    fn length_kinds() {
        let d = doc();
        assert_eq!(run(".rows | length", &d), [json!(3)]);
        assert_eq!(run(".s | length", &d), [json!(5)]);
        assert_eq!(run(".a | length", &d), [json!(1)]);
        assert_eq!(run(".n | length", &d), [json!(0)]);
        assert!(run_err(".a.b[0] | length", &d).contains("number has no length"));
    }

    #[test]
    fn object_construction_sorts_keys() {
        let d = doc();
        let r = run("{z: .s, a: .a.b[0], \"q r\": .n}", &d);
        let keys: Vec<_> = r[0].as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["a", "q r", "z"]);
        assert!(run_err("{x: .rows[]}", &d).contains("single value"));
    }

    #[test]
    fn composition() {
        let d = doc();
        assert_eq!(
            run(".rows[] | select(.id >= 2) | {id: .id}", &d),
            [json!({"id": 2}), json!({"id": 3})]
        );
    }

    #[test]
    fn runtime_errors() {
        let d = doc();
        assert_eq!(run_err(".s.x", &d), "jq: cannot index string with \"x\"");
        assert!(run_err(".s[0]", &d).contains("cannot index string with number"));
        assert!(run_err(".s[]", &d).contains("cannot iterate over string"));
        assert!(run_err(".n[]", &d).contains("cannot iterate over null"));
    }

    #[test]
    fn parse_errors() {
        assert_eq!(
            parse_err("}"),
            "jq: expected a path, select(...), length or {...}, found '}' at byte 0"
        );
        assert!(parse_err("").contains("end of expression"));
        assert!(parse_err(".a |").contains("end of expression"));
        assert!(parse_err(".a.").contains("expected a key"));
        assert!(parse_err(".a b").contains("unexpected input"));
        assert!(parse_err(".[-1]").contains("expected an index"));
        assert!(parse_err(".[1").contains("expected ']'"));
        assert!(parse_err("foo").contains("unknown function 'foo'"));
        assert!(parse_err("select(.a = 1)").contains("expected one of"));
        assert!(parse_err("select(.a == bar)").contains("unknown literal"));
        assert!(parse_err("select(.a == 1.2.3)").contains("bad number"));
        assert!(parse_err("select(.a == \"x)").contains("unterminated string"));
        assert!(parse_err("select(.a == \"x\\").contains("unterminated string"));
        assert!(parse_err("select(.a == \"\\q\")").contains("bad escape"));
        assert!(parse_err("select(.a == \"\\u12\")").contains("bad \\u escape"));
        assert!(parse_err("select(.a == \"\\ud800\")").contains("bad \\u escape"));
        assert!(parse_err("select(.a == 1").contains("expected ')'"));
        assert!(parse_err("{a .b}").contains("expected ':'"));
        assert!(parse_err("{}").contains("object key"));
        assert!(parse_err("{a: .b").contains("expected ','"));
        assert!(parse_err(&format!(".{}", "a".repeat(512))).contains("longer than 512"));
        assert!(parse(&vec!["."; 16].join("|")).is_ok());
        assert!(parse_err(&vec!["."; 17].join("|")).contains("more than 16 pipe stages"));
    }

    #[test]
    fn result_cap() {
        let big = Value::Array(vec![Value::Null; 400]);
        // 400 * 400 = 160_000 > cap
        let nested = Value::Array(vec![big; 400]);
        assert!(run_err(".[] | .[]", &nested).contains("more than 100000 results"));
        assert!(run_err(".[][]", &nested).contains("more than 100000 results"));
    }

    #[test]
    fn split_iter_takes_the_tail() {
        let p = parse(".[] | select(.a) | length").unwrap();
        assert_eq!(p.split_iter(), Some(parse("select(.a) | length").unwrap()));
        assert_eq!(parse(".a[]").unwrap().split_iter(), None);
        assert_eq!(parse("length").unwrap().split_iter(), None);
    }
}
