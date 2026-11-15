use std::net::IpAddr;

use ipnet::IpNet;

use crate::CompileError;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Newline,
    Indent,
    Dedent,
    Ident(String),
    Int(i64),
    Str(String),
    Prefix(IpNet),
    IpAddr(IpAddr),
    If,
    Elif,
    Else,
    Set,
    Accept,
    Reject,
    Call,
    And,
    Or,
    Not,
    In,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Assign,
    Colon,
    Dot,
    Comma,
    LParen,
    RParen,
    Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpannedToken {
    pub token: Token,
    pub line: usize,
}

/// Tokenizes `src` using Python-style significant indentation (a stack of
/// indent widths; `Indent`/`Dedent` are synthesized on width changes).
/// Blank lines and comment-only lines are skipped entirely — they never
/// affect the indent stack and never emit `Newline`. Tabs are rejected
/// outright rather than given an arbitrary width, since mixing tabs and
/// spaces is exactly the kind of silent-indentation-bug this format can't
/// afford to allow.
pub fn lex(src: &str) -> Result<Vec<SpannedToken>, CompileError> {
    let mut tokens = Vec::new();
    let mut indent_stack = vec![0usize];

    for (line_idx, raw_line) in src.lines().enumerate() {
        let line = line_idx + 1;
        let code = &raw_line[..code_end(raw_line)];
        if code.trim().is_empty() {
            continue;
        }
        if code.contains('\t') {
            return Err(CompileError::new(line, "tabs are not allowed; use spaces"));
        }
        let indent = code.len() - code.trim_start_matches(' ').len();
        let rest = code.trim_start_matches(' ');

        let current = *indent_stack.last().unwrap();
        if indent > current {
            indent_stack.push(indent);
            tokens.push(SpannedToken {
                token: Token::Indent,
                line,
            });
        } else if indent < current {
            while *indent_stack.last().unwrap() > indent {
                indent_stack.pop();
                tokens.push(SpannedToken {
                    token: Token::Dedent,
                    line,
                });
            }
            if *indent_stack.last().unwrap() != indent {
                return Err(CompileError::new(line, "inconsistent indentation"));
            }
        }

        lex_line(rest, line, &mut tokens)?;
        tokens.push(SpannedToken {
            token: Token::Newline,
            line,
        });
    }

    let last_line = src.lines().count().max(1);
    while indent_stack.len() > 1 {
        indent_stack.pop();
        tokens.push(SpannedToken {
            token: Token::Dedent,
            line: last_line,
        });
    }
    tokens.push(SpannedToken {
        token: Token::Eof,
        line: last_line,
    });
    Ok(tokens)
}

/// Scans a string literal body: `rest` starts just after the opening `"`.
/// Returns the decoded text and the bytes consumed including the closing
/// quote; `Ok(None)` = unterminated. `\"` decodes to `"`; every other legal
/// backslash pair (`\` + ASCII punctuation, or a letter the `regex` crate
/// accepts as an escape) is kept verbatim for the as-path regex; anything
/// else is an error. Shared by `lex_line` and `code_end` so they can't drift.
fn scan_string(rest: &str) -> Result<Option<(String, usize)>, String> {
    let mut out = String::new();
    let mut chars = rest.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Ok(Some((out, i + 1))),
            '\\' => match chars.next() {
                None => return Ok(None),
                Some((_, '"')) => out.push('"'),
                Some((_, e)) if e.is_ascii_punctuation() || "dDwWsSbBAznrtfvaxuUpP".contains(e) => {
                    out.push('\\');
                    out.push(e);
                }
                Some((_, e)) => {
                    return Err(format!(
                        "unknown escape '\\{e}' in string literal (use \\\" for a quote; \
                         other backslash sequences are regex escapes)"
                    ))
                }
            },
            _ => out.push(c),
        }
    }
    Ok(None)
}

/// Byte index where the code on `line` ends: the first `#` outside a `"..."`
/// literal (escapes as in `scan_string`), else the line's end. A bad or
/// unterminated string returns the line's end so `lex_line` reports it.
fn code_end(line: &str) -> usize {
    let mut skip_to = 0;
    for (j, c) in line.char_indices() {
        if j < skip_to {
            continue;
        }
        match c {
            '"' => match scan_string(&line[j + 1..]) {
                Ok(Some((_, n))) => skip_to = j + 1 + n,
                _ => return line.len(),
            },
            '#' => return j,
            _ => {}
        }
    }
    line.len()
}

fn lex_line(line: &str, lineno: usize, out: &mut Vec<SpannedToken>) -> Result<(), CompileError> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == ' ' {
            i += 1;
            continue;
        }
        if let Some((tok, n)) = scan_ipv6(&line[i..]) {
            out.push(SpannedToken {
                token: tok,
                line: lineno,
            });
            i += n;
            continue;
        }
        if c.is_ascii_digit() {
            // IPv4-dotted-decimal and prefix literals (IPv6 is tried above).
            let start = i;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if c.is_ascii_digit() || c == '.' || c == '/' {
                    i += 1;
                } else {
                    break;
                }
            }
            let text = &line[start..i];
            out.push(SpannedToken {
                token: classify_numeric(text, lineno)?,
                line: lineno,
            });
            continue;
        }
        if c == '"' {
            let (text, n) = match scan_string(&line[i + 1..]) {
                Ok(Some(r)) => r,
                Ok(None) => return Err(CompileError::new(lineno, "unterminated string literal")),
                Err(msg) => return Err(CompileError::new(lineno, msg)),
            };
            out.push(SpannedToken {
                token: Token::Str(text),
                line: lineno,
            });
            i += 1 + n;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if c.is_ascii_alphanumeric() || c == '_' {
                    i += 1;
                } else {
                    break;
                }
            }
            let word = &line[start..i];
            out.push(SpannedToken {
                token: keyword_or_ident(word),
                line: lineno,
            });
            if word == "call" {
                // The callee is a policy name, which may contain '-': scan
                // it whole instead of splitting at the hyphen.
                while bytes.get(i) == Some(&b' ') {
                    i += 1;
                }
                let name_start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || b"_-".contains(&bytes[i]))
                {
                    i += 1;
                }
                if i > name_start {
                    out.push(SpannedToken {
                        token: Token::Ident(line[name_start..i].to_string()),
                        line: lineno,
                    });
                }
            }
            continue;
        }
        let (tok, width) = match c {
            '=' if bytes.get(i + 1) == Some(&b'=') => (Token::Eq, 2),
            '!' if bytes.get(i + 1) == Some(&b'=') => (Token::Ne, 2),
            '<' if bytes.get(i + 1) == Some(&b'=') => (Token::Le, 2),
            '>' if bytes.get(i + 1) == Some(&b'=') => (Token::Ge, 2),
            '<' => (Token::Lt, 1),
            '>' => (Token::Gt, 1),
            '=' => (Token::Assign, 1),
            '+' => (Token::Plus, 1),
            '-' => (Token::Minus, 1),
            ':' => (Token::Colon, 1),
            '.' => (Token::Dot, 1),
            ',' => (Token::Comma, 1),
            '(' => (Token::LParen, 1),
            ')' => (Token::RParen, 1),
            other => {
                return Err(CompileError::new(
                    lineno,
                    format!("unexpected character '{other}'"),
                ))
            }
        };
        out.push(SpannedToken {
            token: tok,
            line: lineno,
        });
        i += width;
    }
    Ok(())
}

/// Bare IPv6 address/prefix literal at the start of `rest`: the maximal run of
/// `[0-9A-Fa-f:./]` parsed by `std`; on failure ONE trailing `:` (the block
/// colon, as in `this.prefix in 2001:db8::/32:`) is dropped and it retries.
/// `None` for anything the std parser rejects (communities such as `65000:100`,
/// identifiers like `fe80`), so those keep their existing lexing.
fn scan_ipv6(rest: &str) -> Option<(Token, usize)> {
    let len = rest
        .bytes()
        .take_while(|b| b.is_ascii_hexdigit() || b":./".contains(b))
        .count();
    let mut run = &rest[..len];
    if !run.contains(':') {
        return None;
    }
    for _ in 0..2 {
        if run.contains('/') {
            if let Ok(n @ IpNet::V6(_)) = run.parse::<IpNet>() {
                return Some((Token::Prefix(n), run.len()));
            }
        } else if let Ok(a @ IpAddr::V6(_)) = run.parse::<IpAddr>() {
            return Some((Token::IpAddr(a), run.len()));
        }
        run = run.strip_suffix(':')?;
    }
    None
}

fn keyword_or_ident(word: &str) -> Token {
    match word {
        "if" => Token::If,
        "elif" => Token::Elif,
        "else" => Token::Else,
        "set" => Token::Set,
        "accept" => Token::Accept,
        "reject" => Token::Reject,
        "call" => Token::Call,
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "in" => Token::In,
        _ => Token::Ident(word.to_string()),
    }
}

fn classify_numeric(text: &str, line: usize) -> Result<Token, CompileError> {
    if let Ok(n) = text.parse::<i64>() {
        return Ok(Token::Int(n));
    }
    if text.contains('/') {
        return text
            .parse::<IpNet>()
            .map(Token::Prefix)
            .map_err(|_| CompileError::new(line, format!("invalid prefix literal '{text}'")));
    }
    text.parse::<IpAddr>().map(Token::IpAddr).map_err(|_| {
        CompileError::new(line, format!("invalid numeric or address literal '{text}'"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens_of(src: &str) -> Vec<Token> {
        lex(src).unwrap().into_iter().map(|t| t.token).collect()
    }

    #[test]
    fn simple_accept() {
        assert_eq!(
            tokens_of("accept\n"),
            vec![Token::Accept, Token::Newline, Token::Eof]
        );
    }

    #[test]
    fn if_else_produces_indent_dedent() {
        let toks = tokens_of("if this.bgp.local_pref < 100:\n    reject\nelse:\n    accept\n");
        assert_eq!(
            toks,
            vec![
                Token::If,
                Token::Ident("this".to_string()),
                Token::Dot,
                Token::Ident("bgp".to_string()),
                Token::Dot,
                Token::Ident("local_pref".to_string()),
                Token::Lt,
                Token::Int(100),
                Token::Colon,
                Token::Newline,
                Token::Indent,
                Token::Reject,
                Token::Newline,
                Token::Dedent,
                Token::Else,
                Token::Colon,
                Token::Newline,
                Token::Indent,
                Token::Accept,
                Token::Newline,
                Token::Dedent,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        assert_eq!(
            tokens_of("# a comment\n\naccept # trailing\n"),
            vec![Token::Accept, Token::Newline, Token::Eof]
        );
    }

    #[test]
    fn hash_inside_string_is_literal() {
        let s = |t: &str| Token::Str(t.to_string());
        assert_eq!(
            tokens_of("\"^65001#\"\n"),
            vec![s("^65001#"), Token::Newline, Token::Eof]
        );
        assert_eq!(
            tokens_of("\"a#b\" # note\n"),
            vec![s("a#b"), Token::Newline, Token::Eof]
        );
        assert_eq!(
            tokens_of("\"#\"\n"),
            vec![s("#"), Token::Newline, Token::Eof]
        );
        assert_eq!(
            tokens_of("accept # \"quoted\" in comment\n"),
            vec![Token::Accept, Token::Newline, Token::Eof]
        );
        assert!(lex("\"abc # x\n").is_err());
    }

    fn str_tok(src: &str) -> Result<Token, String> {
        lex(src)
            .map(|v| v[0].token.clone())
            .map_err(|e| e.to_string())
    }

    #[test]
    fn escaped_quote_decodes_and_keeps_regex_escapes() {
        let s = |t: &str| Ok(Token::Str(t.to_string()));
        assert_eq!(str_tok(r#""a\"b""#), s("a\"b"));
        assert_eq!(str_tok(r#""\\""#), s(r"\\"));
        assert_eq!(str_tok(r#""\\\"""#), s("\\\\\""));
        assert_eq!(str_tok(r##""a\"#b" # note"##), s("a\"#b"));
        for ok in [
            r"^65001_",
            r"\_65001\_",
            "[_]",
            r"^\{65001\}$",
            r"\d+",
            r"\\",
        ] {
            assert_eq!(str_tok(&format!("\"{ok}\"")), s(ok));
        }
    }

    #[test]
    fn bad_escapes_and_unterminated_are_errors() {
        for bad in [r#""\q""#, r#""\ ""#, r#""\1""#, "\"\\é\""] {
            let e = str_tok(bad).unwrap_err();
            assert!(e.contains("unknown escape"), "{bad}: {e}");
        }
        for bad in [r#""\""#, r#""abc\"#] {
            assert!(str_tok(bad).unwrap_err().contains("unterminated"), "{bad}");
        }
        let e = lex("accept\n\"\\q\"\n").unwrap_err();
        assert_eq!(e.line, 2);
    }

    #[test]
    fn code_end_skips_escaped_quotes() {
        assert_eq!(code_end(r##""a\"#" # c"##), 7);
        assert_eq!(code_end(r#""\\" # c"#), 5);
        assert_eq!(code_end(r#""a\"#), 3);
    }

    #[test]
    fn prefix_and_ip_literals() {
        let toks = tokens_of("10.0.0.0/8\n192.0.2.1\n");
        assert_eq!(
            toks,
            vec![
                Token::Prefix("10.0.0.0/8".parse().unwrap()),
                Token::Newline,
                Token::IpAddr("192.0.2.1".parse().unwrap()),
                Token::Newline,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn tabs_are_rejected() {
        assert!(lex("\taccept\n").is_err());
    }

    #[test]
    fn inconsistent_indentation_is_rejected() {
        let src = "a:\n    b\n        c\n      d\n";
        assert!(lex(src).is_err());
    }

    #[test]
    fn call_scans_a_hyphenated_name() {
        assert_eq!(
            tokens_of("call my-pol_2\n"),
            vec![
                Token::Call,
                Token::Ident("my-pol_2".into()),
                Token::Newline,
                Token::Eof
            ]
        );
    }

    #[test]
    fn ipv6_literals() {
        let p = |s: &str| Token::Prefix(s.parse().unwrap());
        let a = |s: &str| Token::IpAddr(s.parse().unwrap());
        let nl = |mut v: Vec<Token>| {
            v.extend([Token::Newline, Token::Eof]);
            v
        };
        for (src, tok) in [
            ("2001:db8::/32", p("2001:db8::/32")),
            ("::/0", p("::/0")),
            ("::1", a("::1")),
            ("fe80::1", a("fe80::1")),
        ] {
            assert_eq!(tokens_of(src), nl(vec![tok]), "{src}");
        }
        // Trailing block colon is not part of the literal.
        assert_eq!(
            tokens_of("2001:db8::/32:"),
            nl(vec![p("2001:db8::/32"), Token::Colon])
        );
        assert_eq!(
            tokens_of("2001:db8:::"),
            nl(vec![a("2001:db8::"), Token::Colon])
        );
        assert_eq!(tokens_of("2001:db8::"), nl(vec![a("2001:db8::")]));
        // Communities and identifiers are unchanged.
        let i = |n| Token::Int(n);
        assert_eq!(
            tokens_of("65000:100"),
            nl(vec![i(65000), Token::Colon, i(100)])
        );
        assert_eq!(
            tokens_of("3:2:900"),
            nl(vec![i(3), Token::Colon, i(2), Token::Colon, i(900)])
        );
        assert_eq!(tokens_of("fe80"), nl(vec![Token::Ident("fe80".into())]));
        assert_eq!(tokens_of("abcd"), nl(vec![Token::Ident("abcd".into())]));
        // Malformed: lexes as pieces, which the parser rejects.
        assert!(crate::compile(
            "if this.prefix in 2001:db8:::/32:\n  accept\nreject\n",
            &crate::Symbols::EMPTY
        )
        .is_err());
    }
}
