use crate::ast::{BinOp, Expr, ExprKind, ExtKind, Policy, Postfix, Stmt, StmtKind, UnaryOp};
use crate::lexer::{SpannedToken, Token};
use crate::CompileError;

/// Maximum AST depth (statement nesting plus expression depth) and parser
/// recursion depth: bounds the stack of every recursive pass (check,
/// codegen, `Drop`) over the tree, which a left-deep `a or a or ...` chain
/// would otherwise blow without any parser recursion.
const MAX_DEPTH: usize = 64;

struct Parser<'a> {
    tokens: &'a [SpannedToken],
    pos: usize,
    /// Statement-suite nesting of the node being parsed.
    nest: usize,
    /// Parser recursion depth (suites, `not`, parentheses).
    rec: usize,
    /// Depth of the expression most recently returned (a leaf is 1).
    d: usize,
}

pub fn parse(tokens: &[SpannedToken]) -> Result<Policy, CompileError> {
    let mut p = Parser {
        tokens,
        pos: 0,
        nest: 0,
        rec: 0,
        d: 0,
    };
    let policy = p.parse_block_body()?;
    p.expect(&Token::Eof)?;
    Ok(policy)
}

impl Parser<'_> {
    fn too_deep(&self) -> CompileError {
        CompileError::new(self.line(), format!("nesting deeper than {MAX_DEPTH}"))
    }

    /// Enters a recursive construct, failing past `MAX_DEPTH`.
    fn enter(&mut self) -> Result<(), CompileError> {
        self.rec += 1;
        if self.rec > MAX_DEPTH {
            return Err(self.too_deep());
        }
        Ok(())
    }

    /// Records the depth of a new expression node and enforces the cap.
    fn node(&mut self, d: usize) -> Result<(), CompileError> {
        self.d = d;
        if self.nest + d > MAX_DEPTH {
            return Err(self.too_deep());
        }
        Ok(())
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos].token
    }

    fn peek_at(&self, offset: usize) -> &Token {
        let idx = (self.pos + offset).min(self.tokens.len() - 1);
        &self.tokens[idx].token
    }

    fn line(&self) -> usize {
        self.tokens[self.pos].line
    }

    fn advance(&mut self) -> Token {
        let t = self.tokens[self.pos].token.clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, want: &Token) -> Result<(), CompileError> {
        if self.peek() == want {
            self.advance();
            Ok(())
        } else {
            Err(CompileError::new(
                self.line(),
                format!("expected {want:?}, found {:?}", self.peek()),
            ))
        }
    }

    fn expect_ident(&mut self) -> Result<String, CompileError> {
        match self.advance() {
            Token::Ident(s) => Ok(s),
            other => Err(CompileError::new(
                self.line(),
                format!("expected identifier, found {other:?}"),
            )),
        }
    }

    /// A sequence of statements up to (not including) the token that ends
    /// the enclosing block (`Dedent`/`Eof`).
    fn parse_block_body(&mut self) -> Result<Vec<Stmt>, CompileError> {
        let mut stmts = Vec::new();
        while !matches!(self.peek(), Token::Dedent | Token::Eof) {
            stmts.push(self.parse_stmt()?);
        }
        Ok(stmts)
    }

    /// `":" NEWLINE INDENT <block> DEDENT`, shared by `if`/`elif`/`else`.
    fn parse_suite(&mut self) -> Result<Vec<Stmt>, CompileError> {
        self.expect(&Token::Colon)?;
        self.expect(&Token::Newline)?;
        self.expect(&Token::Indent)?;
        self.enter()?;
        self.nest += 1;
        if self.nest > MAX_DEPTH {
            return Err(self.too_deep());
        }
        let body = self.parse_block_body()?;
        self.nest -= 1;
        self.rec -= 1;
        self.expect(&Token::Dedent)?;
        Ok(body)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, CompileError> {
        let line = self.line();
        let kind = match self.peek() {
            Token::If => self.parse_if()?,
            Token::Set => self.parse_set()?,
            Token::Ident(name) if name == "this" => self.parse_this_stmt()?,
            Token::Accept => {
                self.advance();
                self.expect(&Token::Newline)?;
                StmtKind::Accept
            }
            Token::Reject => {
                self.advance();
                self.expect(&Token::Newline)?;
                StmtKind::Reject
            }
            Token::Call => {
                self.advance();
                let Token::Ident(name) = self.peek().clone() else {
                    return Err(CompileError::new(line, "'call' needs a policy name"));
                };
                self.advance();
                self.expect(&Token::Newline)?;
                StmtKind::Call(name)
            }
            other => {
                return Err(CompileError::new(
                    line,
                    format!("expected a statement, found {other:?}"),
                ))
            }
        };
        Ok(Stmt { kind, line })
    }

    /// `this.<field>.add(..)` / `.remove(..)` / `.clear()` — parsed by
    /// reusing `parse_postfix` and then requiring the last segment to be
    /// exactly one of these three method calls.
    fn parse_this_stmt(&mut self) -> Result<StmtKind, CompileError> {
        let line = self.line();
        let expr = self.parse_postfix()?;
        let ExprKind::This(mut segments) = expr.kind else {
            unreachable!("parse_postfix always returns ExprKind::This for a 'this'-led atom");
        };
        let Some(Postfix::Call(name, mut args)) = segments.pop() else {
            return Err(CompileError::new(
                line,
                "expected a statement: 'set ... = ...' or 'this.<field>.add(..)'/'.remove(..)'/'.remove_matching(..)'/'.clear()'",
            ));
        };
        let target = Expr {
            kind: ExprKind::This(segments),
            line,
        };
        let kind = match (name.as_str(), args.len()) {
            ("add", 1) => StmtKind::CommunityAdd(target, args.remove(0)),
            ("remove", 1) => StmtKind::CommunityRemove(target, args.remove(0)),
            ("remove_matching", 1) => StmtKind::CommunityRemoveMatching(target, args.remove(0)),
            ("clear", 0) => StmtKind::CommunityClear(target),
            ("prepend", 1 | 2) => StmtKind::AsPathPrepend(target, args),
            _ => {
                return Err(CompileError::new(
                    line,
                    format!("unknown statement '.{name}(..)'"),
                ))
            }
        };
        self.expect(&Token::Newline)?;
        Ok(kind)
    }

    fn parse_if(&mut self) -> Result<StmtKind, CompileError> {
        self.expect(&Token::If)?;
        let mut branches = Vec::new();
        let cond = self.parse_expr()?;
        let body = self.parse_suite()?;
        branches.push((cond, body));

        while matches!(self.peek(), Token::Elif) {
            self.advance();
            let cond = self.parse_expr()?;
            let body = self.parse_suite()?;
            branches.push((cond, body));
        }

        let else_body = if matches!(self.peek(), Token::Else) {
            self.advance();
            Some(self.parse_suite()?)
        } else {
            None
        };

        Ok(StmtKind::If {
            branches,
            else_body,
        })
    }

    fn parse_set(&mut self) -> Result<StmtKind, CompileError> {
        self.expect(&Token::Set)?;
        let target = self.parse_postfix()?;
        let relative = match self.peek() {
            Token::Plus => Some(false),
            Token::Minus => Some(true),
            _ => None,
        };
        if relative.is_some() {
            self.advance();
        }
        self.expect(&Token::Assign)?;
        let value = self.parse_expr()?;
        self.expect(&Token::Newline)?;
        Ok(match relative {
            Some(negate) => StmtKind::SetRelative(target, negate, value),
            None => StmtKind::Set(target, value),
        })
    }

    fn parse_expr(&mut self) -> Result<Expr, CompileError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr, CompileError> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Token::Or) {
            let line = self.line();
            let ld = self.d;
            self.advance();
            let rhs = self.parse_and()?;
            self.node(ld.max(self.d) + 1)?;
            lhs = Expr {
                kind: ExprKind::Binary(BinOp::Or, Box::new(lhs), Box::new(rhs)),
                line,
            };
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, CompileError> {
        let mut lhs = self.parse_not()?;
        while matches!(self.peek(), Token::And) {
            let line = self.line();
            let ld = self.d;
            self.advance();
            let rhs = self.parse_not()?;
            self.node(ld.max(self.d) + 1)?;
            lhs = Expr {
                kind: ExprKind::Binary(BinOp::And, Box::new(lhs), Box::new(rhs)),
                line,
            };
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<Expr, CompileError> {
        if matches!(self.peek(), Token::Not) {
            let line = self.line();
            self.advance();
            self.enter()?;
            let inner = self.parse_not()?;
            self.rec -= 1;
            self.node(self.d + 1)?;
            Ok(Expr {
                kind: ExprKind::Unary(UnaryOp::Not, Box::new(inner)),
                line,
            })
        } else {
            self.parse_comparison()
        }
    }

    fn parse_comparison(&mut self) -> Result<Expr, CompileError> {
        let lhs = self.parse_sum()?;
        let line = self.line();
        let op = match self.peek() {
            Token::Eq => BinOp::Eq,
            Token::Ne => BinOp::Ne,
            Token::Lt => BinOp::Lt,
            Token::Le => BinOp::Le,
            Token::Gt => BinOp::Gt,
            Token::Ge => BinOp::Ge,
            Token::In => BinOp::In,
            _ => return Ok(lhs),
        };
        let ld = self.d;
        self.advance();
        let rhs = self.parse_sum()?;
        self.node(ld.max(self.d) + 1)?;
        Ok(Expr {
            kind: ExprKind::Binary(op, Box::new(lhs), Box::new(rhs)),
            line,
        })
    }

    fn parse_sum(&mut self) -> Result<Expr, CompileError> {
        let mut lhs = self.parse_postfix()?;
        loop {
            let line = self.line();
            let op = match self.peek() {
                Token::Plus => BinOp::Add,
                Token::Minus => BinOp::Sub,
                _ => break,
            };
            let ld = self.d;
            self.advance();
            let rhs = self.parse_postfix()?;
            self.node(ld.max(self.d) + 1)?;
            lhs = Expr {
                kind: ExprKind::Binary(op, Box::new(lhs), Box::new(rhs)),
                line,
            };
        }
        Ok(lhs)
    }

    fn parse_postfix(&mut self) -> Result<Expr, CompileError> {
        let atom = self.parse_atom()?;
        let line = atom.line;
        let ExprKind::This(mut segments) = atom.kind else {
            return Ok(atom);
        };
        let mut depth = 1;
        loop {
            if !matches!(self.peek(), Token::Dot) {
                break;
            }
            self.advance();
            let name = self.expect_ident()?;
            if matches!(self.peek(), Token::LParen) {
                self.advance();
                let mut args = Vec::new();
                if !matches!(self.peek(), Token::RParen) {
                    args.push(self.parse_expr()?);
                    depth = depth.max(self.d + 1);
                    while matches!(self.peek(), Token::Comma) {
                        self.advance();
                        args.push(self.parse_expr()?);
                        depth = depth.max(self.d + 1);
                    }
                }
                self.expect(&Token::RParen)?;
                segments.push(Postfix::Call(name, args));
            } else {
                segments.push(Postfix::Field(name));
            }
        }
        self.node(depth)?;
        Ok(Expr {
            kind: ExprKind::This(segments),
            line,
        })
    }

    /// `rt(`/`soo(`/`rd(` already consumed up to the `(`: `asn:nn` or
    /// `a.b.c.d:nn`, then `)`.
    fn parse_ext_lit(&mut self, name: &str, line: usize) -> Result<ExprKind, CompileError> {
        self.expect(&Token::LParen)?;
        let admin = self.advance();
        self.expect(&Token::Colon)?;
        let Token::Int(nn) = self.advance() else {
            return Err(CompileError::new(
                line,
                format!("{name}() needs asn:nn or a.b.c.d:nn"),
            ));
        };
        self.expect(&Token::RParen)?;
        let kind = match name {
            "rt" => ExtKind::Rt,
            "soo" => ExtKind::Soo,
            _ => ExtKind::Rd,
        };
        let value = encode_ext(kind, &admin, nn)
            .ok_or_else(|| CompileError::new(line, format!("{name}() value out of range")))?;
        Ok(ExprKind::ExtLit(kind, value))
    }

    fn parse_atom(&mut self) -> Result<Expr, CompileError> {
        let line = self.line();
        let kind = match self.advance() {
            Token::Int(n) => {
                // `65000:100` / `3:2:900` — a colon-literal community value.
                // Only consume `Colon` here when it's immediately followed by
                // another `Int`, so the block-starting colon in `if cond:`
                // (always followed by `Newline`) is left untouched.
                let mut parts = vec![n];
                while matches!(self.peek(), Token::Colon)
                    && matches!(self.peek_at(1), Token::Int(_))
                {
                    self.advance(); // Colon
                    let Token::Int(next) = self.advance() else {
                        unreachable!("peek_at(1) just confirmed an Int");
                    };
                    parts.push(next);
                }
                if parts.len() == 1 {
                    ExprKind::IntLit(parts[0])
                } else {
                    ExprKind::ColonLit(parts)
                }
            }
            Token::Str(s) => ExprKind::StrLit(s),
            Token::Prefix(p) => ExprKind::PrefixLit(p),
            Token::IpAddr(a) => ExprKind::IpLit(a),
            Token::LParen => {
                self.enter()?;
                let inner = self.parse_expr()?;
                self.rec -= 1;
                self.expect(&Token::RParen)?;
                // Parentheses add no node but still recurse: count them.
                self.node(self.d + 1)?;
                return Ok(inner);
            }
            Token::Ident(name) if name == "this" => ExprKind::This(Vec::new()),
            Token::Ident(name)
                if matches!(name.as_str(), "rt" | "soo" | "rd")
                    && matches!(self.peek(), Token::LParen) =>
            {
                self.parse_ext_lit(&name, line)?
            }
            Token::Ident(name) => {
                if matches!(self.peek(), Token::Dot) {
                    self.advance();
                    let variant = self.expect_ident()?;
                    ExprKind::EnumLit(name, variant)
                } else {
                    ExprKind::Ident(name)
                }
            }
            other => {
                return Err(CompileError::new(
                    line,
                    format!("expected an expression, found {other:?}"),
                ))
            }
        };
        self.node(1)?;
        Ok(Expr { kind, line })
    }
}

/// The 8-octet value of `kind` for `admin:nn`, with the same type choice as
/// `nos_proto::evpn_id::parse_rt`/`parse_rd` (a `bgp`-side test pins that
/// equality, since this crate cannot depend on `nos-proto`): a 16-bit AS is
/// type 0 with a 32-bit number, any other AS type 2 and a 16-bit number, an
/// IPv4 address type 1 and a 16-bit number.
fn encode_ext(kind: ExtKind, admin: &Token, nn: i64) -> Option<u64> {
    let nn = u64::try_from(nn).ok()?;
    let (ty, admin, nn_bits) = match admin {
        Token::Int(asn) => {
            let asn = u32::try_from(*asn).ok()?;
            if u16::try_from(asn).is_ok() {
                (0u64, u64::from(asn), 32)
            } else {
                (2, u64::from(asn), 16)
            }
        }
        Token::IpAddr(std::net::IpAddr::V4(ip)) => (1, u64::from(u32::from(*ip)), 16),
        _ => return None,
    };
    if nn >= 1 << nn_bits {
        return None;
    }
    let (first, sub) = match kind {
        ExtKind::Rt => (ty, 0x02),
        ExtKind::Soo => (ty, 0x03),
        ExtKind::Rd => (0, ty),
    };
    // Two-octet admin: 16 bits then 32; otherwise 32 bits then 16.
    let body = if nn_bits == 32 {
        (admin << 32) | nn
    } else {
        (admin << 16) | nn
    };
    Some((first << 56) | (sub << 48) | body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    fn parse_src(src: &str) -> Policy {
        parse(&lex(src).unwrap()).unwrap()
    }

    #[test]
    fn accept_only() {
        let policy = parse_src("accept\n");
        assert_eq!(policy.len(), 1);
        assert_eq!(policy[0].kind, StmtKind::Accept);
    }

    #[test]
    fn if_else_with_set() {
        let policy = parse_src(
            "if this.bgp.local_pref < 100:\n    set this.bgp.local_pref = 150\n    accept\nelse:\n    reject\n",
        );
        let StmtKind::If {
            branches,
            else_body,
        } = &policy[0].kind
        else {
            panic!("expected if");
        };
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].1.len(), 2);
        assert!(else_body.is_some());
    }

    #[test]
    fn field_access_and_method_call() {
        let policy =
            parse_src("if this.bgp.as_path.contains(65010):\n    reject\nelse:\n    accept\n");
        let StmtKind::If { branches, .. } = &policy[0].kind else {
            panic!("expected if");
        };
        let ExprKind::This(segments) = &branches[0].0.kind else {
            panic!("expected this expr");
        };
        assert_eq!(
            segments,
            &vec![
                Postfix::Field("bgp".to_string()),
                Postfix::Field("as_path".to_string()),
                Postfix::Call(
                    "contains".to_string(),
                    vec![Expr {
                        kind: ExprKind::IntLit(65010),
                        line: 1
                    }]
                ),
            ]
        );
    }

    #[test]
    fn enum_literal() {
        let policy =
            parse_src("if this.bgp.origin == origin.igp:\n    accept\nelse:\n    reject\n");
        let StmtKind::If { branches, .. } = &policy[0].kind else {
            panic!("expected if");
        };
        let ExprKind::Binary(BinOp::Eq, _, rhs) = &branches[0].0.kind else {
            panic!("expected ==");
        };
        assert_eq!(
            rhs.kind,
            ExprKind::EnumLit("origin".to_string(), "igp".to_string())
        );
    }

    #[test]
    fn missing_else_parses_as_non_terminating_if() {
        let policy = parse_src("if this.prefix in 10.0.0.0/8:\n    reject\n");
        let StmtKind::If { else_body, .. } = &policy[0].kind else {
            panic!("expected if");
        };
        assert!(else_body.is_none());
    }

    #[test]
    fn colon_literal_parses_as_colon_lit() {
        let policy = parse_src("this.bgp.communities.add(65000:100)\naccept\n");
        let StmtKind::CommunityAdd(_, value) = &policy[0].kind else {
            panic!("expected CommunityAdd");
        };
        assert_eq!(value.kind, ExprKind::ColonLit(vec![65000, 100]));
    }

    #[test]
    fn three_part_colon_literal() {
        let policy = parse_src("this.bgp.large_communities.add(65000:1:2)\naccept\n");
        let StmtKind::CommunityAdd(_, value) = &policy[0].kind else {
            panic!("expected CommunityAdd");
        };
        assert_eq!(value.kind, ExprKind::ColonLit(vec![65000, 1, 2]));
    }

    #[test]
    fn block_colon_is_not_consumed_as_a_colon_literal() {
        let policy = parse_src("if this.bgp.local_pref < 100:\n    reject\nelse:\n    accept\n");
        let StmtKind::If { branches, .. } = &policy[0].kind else {
            panic!("expected if");
        };
        let ExprKind::Binary(BinOp::Lt, _, rhs) = &branches[0].0.kind else {
            panic!("expected <");
        };
        assert_eq!(rhs.kind, ExprKind::IntLit(100));
    }

    #[test]
    fn community_remove_matching_parses() {
        let policy = parse_src("this.bgp.communities.remove_matching(\"^65000:\")\naccept\n");
        assert!(matches!(
            policy[0].kind,
            StmtKind::CommunityRemoveMatching(..)
        ));
    }

    #[test]
    fn community_remove_and_clear_parse() {
        let policy = parse_src(
            "this.bgp.communities.remove(65000:100)\nthis.bgp.communities.clear()\naccept\n",
        );
        assert!(matches!(policy[0].kind, StmtKind::CommunityRemove(..)));
        assert!(matches!(policy[1].kind, StmtKind::CommunityClear(..)));
    }

    #[test]
    fn call_statement_parses_and_needs_a_name() {
        let policy = parse(&lex("call a-b\naccept\n").unwrap()).unwrap();
        assert_eq!(policy[0].kind, StmtKind::Call("a-b".into()));
        assert!(parse(&lex("call\naccept\n").unwrap()).is_err());
    }
}
