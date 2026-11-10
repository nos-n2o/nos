//! AST -> bytecode, combined with type checking in a single pass (there's
//! nothing a separate type-check pass would learn that emission doesn't
//! already need to know, so keeping them together avoids re-deriving field
//! resolution twice). `check.rs` handles the one thing this pass doesn't
//! need: the termination/reachability structure of the statement tree.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::ast::{BinOp, Expr, ExprKind, ExtKind, Policy, Postfix, Stmt, StmtKind, UnaryOp};
use crate::schema::{self, FieldInfo, FieldType};
use crate::symbols::Symbols;
use crate::vm::{
    AsPathRegexes, CmpKind, CommunityValue, CompiledPolicy, Op, Role, ValidationState,
    MAX_CODE_OPS, MAX_STACK_DEPTH,
};
use crate::CompileError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Int,
    Bool,
    Prefix,
    Ip,
    Enum(&'static str),
}

pub fn compile(policy: &Policy, symbols: &Symbols) -> Result<CompiledPolicy, CompileError> {
    let mut cg = Codegen {
        code: Vec::new(),
        depth: 0,
        max_depth: 0,
        symbols,
        call_stack: Vec::new(),
        accept_patches: Vec::new(),
        callees: HashMap::new(),
    };
    cg.compile_stmts(policy)?;
    if cg.max_depth > MAX_STACK_DEPTH {
        return Err(CompileError::new(
            policy.first().map_or(1, |s| s.line),
            "policy expression is too deeply nested to compile",
        ));
    }
    Ok(CompiledPolicy {
        code: cg.code,
        max_stack_depth: cg.max_depth,
    })
}

struct Codegen<'a> {
    code: Vec<Op>,
    depth: usize,
    max_depth: usize,
    symbols: &'a Symbols<'a>,
    /// Policies being inlined right now (outermost first).
    call_stack: Vec<String>,
    /// One frame per active `call`: indices of the `Jump`s an `accept` in
    /// that callee emitted, patched to the continuation after the callee.
    accept_patches: Vec<Vec<usize>>,
    /// Parsed + termination-checked callees, so one used N times is parsed once.
    callees: HashMap<String, Policy>,
}

/// Deepest `call` nesting (owner decision, #870).
const MAX_CALL_DEPTH: usize = 8;

impl Codegen<'_> {
    fn emit(&mut self, op: Op, delta: isize) -> usize {
        let idx = self.code.len();
        self.code.push(op);
        self.depth = self.depth.saturating_add_signed(delta);
        self.max_depth = self.max_depth.max(self.depth);
        idx
    }

    fn patch_jump(&mut self, idx: usize) {
        let target = self.code.len();
        match &mut self.code[idx] {
            Op::JumpIfFalse(t) | Op::Jump(t) => *t = target,
            other => unreachable!("patch_jump called on {other:?}"),
        }
    }

    fn compile_call(&mut self, name: &str, line: usize) -> Result<(), CompileError> {
        if let Some(pos) = self.call_stack.iter().position(|n| n == name) {
            let mut chain = self.call_stack[pos..].to_vec();
            chain.push(name.to_string());
            return Err(CompileError::new(
                line,
                format!("policy call cycle: {}", chain.join(" -> ")),
            ));
        }
        if self.call_stack.len() >= MAX_CALL_DEPTH {
            return Err(CompileError::new(
                line,
                format!("policy calls nested deeper than {MAX_CALL_DEPTH}"),
            ));
        }
        match name {
            "deny-all" => {
                self.emit(Op::Reject, 0);
                return Ok(());
            }
            "accept-all" => return Ok(()),
            _ => {}
        }
        if !self.callees.contains_key(name) {
            let Some((_, src)) = self.symbols.policies.iter().find(|(n, _)| *n == name) else {
                return Err(CompileError::new(line, format!("unknown policy '{name}'")));
            };
            let wrap = |e: CompileError| {
                CompileError::new(line, format!("in called policy '{name}': {e}"))
            };
            crate::check_source_len(src).map_err(wrap)?;
            let tokens = crate::lexer::lex(src).map_err(wrap)?;
            let callee = crate::parser::parse(&tokens).map_err(wrap)?;
            crate::check::check_termination(&callee).map_err(wrap)?;
            self.callees.insert(name.to_string(), callee);
        }
        let callee = self.callees[name].clone();
        self.call_stack.push(name.to_string());
        self.accept_patches.push(Vec::new());
        let res = self.compile_stmts(&callee);
        self.call_stack.pop();
        let patches = self.accept_patches.pop().unwrap_or_default();
        res.map_err(|e| {
            // Keep the innermost message; only attach the callee name once.
            if e.message.starts_with("in called policy")
                || e.message.starts_with("policy call cycle")
                || e.message.starts_with("policy calls nested")
                || e.message.starts_with("policy too large")
                || e.message.starts_with("unknown policy")
            {
                CompileError::new(line, e.message)
            } else {
                CompileError::new(line, format!("in called policy '{name}': {e}"))
            }
        })?;
        let target = self.code.len();
        for idx in patches {
            self.code[idx] = Op::Jump(target);
        }
        Ok(())
    }

    fn compile_stmts(&mut self, stmts: &[Stmt]) -> Result<(), CompileError> {
        for stmt in stmts {
            self.compile_stmt(stmt)?;
        }
        Ok(())
    }

    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), CompileError> {
        if self.code.len() > MAX_CODE_OPS {
            return Err(CompileError::new(
                stmt.line,
                format!("policy too large after inlining calls (limit {MAX_CODE_OPS} ops)"),
            ));
        }
        match &stmt.kind {
            StmtKind::Accept => {
                // Inside a callee, accept returns to the caller.
                if let Some(frame) = self.accept_patches.last_mut() {
                    let idx = self.code.len();
                    frame.push(idx);
                    self.emit(Op::Jump(0), 0);
                } else {
                    self.emit(Op::Accept, 0);
                }
            }
            StmtKind::Call(name) => self.compile_call(name, stmt.line)?,
            StmtKind::Reject => {
                self.emit(Op::Reject, 0);
            }
            StmtKind::Set(target, value) => {
                let info = resolve_settable_field(target)?;
                match info.ty {
                    FieldType::Int | FieldType::OptionalInt => {
                        let value_ty = self.compile_expr(value)?;
                        expect_ty(value_ty, Ty::Int, value.line)?;
                        self.emit(Op::SetField(info.id), -1);
                    }
                    FieldType::Enum(name) => {
                        let value_ty = self.compile_expr(value)?;
                        expect_ty(value_ty, Ty::Enum(name), value.line)?;
                        self.emit(Op::SetOrigin, -1);
                    }
                    FieldType::OptionalIp => {
                        if matches!(&value.kind, ExprKind::Ident(n) if n == "self") {
                            self.emit(Op::SetNextHopSelf, 0);
                        } else {
                            let value_ty = self.compile_expr(value)?;
                            expect_ty(value_ty, Ty::Ip, value.line)?;
                            self.emit(Op::SetNextHop, -1);
                        }
                    }
                    _ => {
                        return Err(CompileError::new(
                            target.line,
                            "this field can't be assigned with 'set'",
                        ))
                    }
                }
            }
            StmtKind::SetRelative(target, negate, value) => {
                let info = resolve_settable_field(target)?;
                if !matches!(info.ty, FieldType::Int | FieldType::OptionalInt) {
                    return Err(CompileError::new(
                        target.line,
                        "'+=' / '-=' is only valid on a numeric field",
                    ));
                }
                if *negate {
                    self.emit(Op::LoadConstInt(0), 1);
                }
                let value_ty = self.compile_expr(value)?;
                expect_ty(value_ty, Ty::Int, value.line)?;
                if *negate {
                    self.emit(Op::Sub, -1);
                }
                self.emit(Op::AddField(info.id), -1);
            }
            StmtKind::AsPathPrepend(target, args) => {
                let info = resolve_settable_field(target)?;
                if info.id != schema::FieldId::BgpAsPath {
                    return Err(CompileError::new(
                        target.line,
                        "'.prepend(..)' is only valid on 'this.bgp.as_path'",
                    ));
                }
                let asn = int_literal(&args[0], "an AS number")?;
                let asn = u32::try_from(asn).map_err(|_| {
                    CompileError::new(args[0].line, "AS number literal out of range")
                })?;
                let count = match args.get(1) {
                    Some(e) => int_literal(e, "a repeat count")?,
                    None => 1,
                };
                let count = u8::try_from(count)
                    .ok()
                    .filter(|n| (1..=MAX_PREPEND).contains(n))
                    .ok_or_else(|| {
                        CompileError::new(
                            stmt.line,
                            format!("prepend count must be between 1 and {MAX_PREPEND}"),
                        )
                    })?;
                self.emit(Op::AsPathPrepend(asn, count), 0);
            }
            StmtKind::CommunityAdd(target, value) => {
                let info = resolve_settable_field(target)?;
                for val in self.community_values_for(info.ty, value)? {
                    self.emit(Op::CommunityAdd(info.id, val), 0);
                }
            }
            StmtKind::CommunityRemove(target, value) => {
                let info = resolve_settable_field(target)?;
                for val in self.community_values_for(info.ty, value)? {
                    self.emit(Op::CommunityRemove(info.id, val), 0);
                }
            }
            StmtKind::CommunityRemoveMatching(target, pattern) => {
                let info = resolve_settable_field(target)?;
                if !is_community_list(info.ty) {
                    return Err(CompileError::new(
                        target.line,
                        "'.remove_matching(..)' is only valid on a community-list field",
                    ));
                }
                let re = community_regex(pattern)?;
                self.emit(Op::CommunityRemoveMatching(info.id, re), 0);
            }
            StmtKind::CommunityClear(target) => {
                let info = resolve_settable_field(target)?;
                if !is_community_list(info.ty) {
                    return Err(CompileError::new(
                        target.line,
                        "'.clear()' is only valid on a community-list field",
                    ));
                }
                self.emit(Op::CommunityClear(info.id), 0);
            }
            StmtKind::If {
                branches,
                else_body,
            } => self.compile_if(branches, else_body.as_ref())?,
        }
        Ok(())
    }

    fn compile_if(
        &mut self,
        branches: &[(Expr, Vec<Stmt>)],
        else_body: Option<&Vec<Stmt>>,
    ) -> Result<(), CompileError> {
        let mut end_jumps = Vec::new();
        let mut prev_jf: Option<usize> = None;

        for (cond, body) in branches {
            if let Some(jf) = prev_jf.take() {
                self.patch_jump(jf);
            }
            let cond_ty = self.compile_expr(cond)?;
            expect_ty(cond_ty, Ty::Bool, cond.line)?;
            let jf = self.emit(Op::JumpIfFalse(0), -1);
            self.compile_stmts(body)?;
            if !body_halts(body) {
                end_jumps.push(self.emit(Op::Jump(0), 0));
            }
            prev_jf = Some(jf);
        }

        match else_body {
            Some(else_body) => {
                if let Some(jf) = prev_jf.take() {
                    self.patch_jump(jf);
                }
                self.compile_stmts(else_body)?;
            }
            None => {
                if let Some(jf) = prev_jf.take() {
                    self.patch_jump(jf);
                }
            }
        }

        for j in end_jumps {
            self.patch_jump(j);
        }
        Ok(())
    }

    fn compile_expr(&mut self, expr: &Expr) -> Result<Ty, CompileError> {
        match &expr.kind {
            ExprKind::IntLit(n) => {
                self.emit(Op::LoadConstInt(*n), 1);
                Ok(Ty::Int)
            }
            ExprKind::PrefixLit(p) => {
                self.emit(Op::LoadConstPrefix(*p), 1);
                Ok(Ty::Prefix)
            }
            ExprKind::IpLit(a) => {
                self.emit(Op::LoadConstIp(*a), 1);
                Ok(Ty::Ip)
            }
            ExprKind::EnumLit(name, variant) => {
                let (enum_name, discriminant) = resolve_enum_literal(name, variant, expr.line)?;
                self.emit(Op::LoadConstEnum(discriminant), 1);
                Ok(Ty::Enum(enum_name))
            }
            ExprKind::StrLit(_) => Err(CompileError::new(
                expr.line,
                "a string literal is only valid as the argument to '.matches(..)'",
            )),
            ExprKind::ColonLit(_) => Err(CompileError::new(
                expr.line,
                "a colon-separated literal is only valid as an argument to '.contains(..)', '.add(..)', or '.remove(..)'",
            )),
            ExprKind::ExtLit(..) => Err(CompileError::new(
                expr.line,
                "rt(..)/soo(..) is only valid as an argument to '.contains(..)', '.add(..)' or '.remove(..)' on 'this.bgp.extended_communities'; rd(..) only in '==' / '!=' with 'this.bgp.rd'",
            )),
            ExprKind::Ident(name) => Err(CompileError::new(
                expr.line,
                format!(
                    "'{name}' is only valid as an argument to '.contains(..)', '.add(..)', '.remove(..)', or as the right-hand side of 'in'"
                ),
            )),
            ExprKind::This(segments) => self.compile_field_access(segments, expr.line),
            ExprKind::Unary(UnaryOp::Not, inner) => {
                let ty = self.compile_expr(inner)?;
                expect_ty(ty, Ty::Bool, inner.line)?;
                self.emit(Op::Not, 0);
                Ok(Ty::Bool)
            }
            ExprKind::Binary(op, lhs, rhs) => self.compile_binary(*op, lhs, rhs, expr.line),
        }
    }

    fn compile_binary(
        &mut self,
        op: BinOp,
        lhs: &Expr,
        rhs: &Expr,
        line: usize,
    ) -> Result<Ty, CompileError> {
        match op {
            BinOp::And | BinOp::Or => {
                let lt = self.compile_expr(lhs)?;
                expect_ty(lt, Ty::Bool, lhs.line)?;
                let rt = self.compile_expr(rhs)?;
                expect_ty(rt, Ty::Bool, rhs.line)?;
                self.emit(if op == BinOp::And { Op::And } else { Op::Or }, -1);
                Ok(Ty::Bool)
            }
            BinOp::Add | BinOp::Sub => {
                let lt = self.compile_expr(lhs)?;
                expect_ty(lt, Ty::Int, lhs.line)?;
                let rt = self.compile_expr(rhs)?;
                expect_ty(rt, Ty::Int, rhs.line)?;
                self.emit(if op == BinOp::Add { Op::Add } else { Op::Sub }, -1);
                Ok(Ty::Int)
            }
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge | BinOp::Eq | BinOp::Ne
                if self.try_as_accessor_cmp(op, lhs, rhs, line)? =>
            {
                Ok(Ty::Bool)
            }
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
                let lt = self.compile_expr(lhs)?;
                expect_ty(lt, Ty::Int, lhs.line)?;
                let rt = self.compile_expr(rhs)?;
                expect_ty(rt, Ty::Int, rhs.line)?;
                let cmp_op = match op {
                    BinOp::Lt => Op::CmpLt,
                    BinOp::Le => Op::CmpLe,
                    BinOp::Gt => Op::CmpGt,
                    BinOp::Ge => Op::CmpGe,
                    _ => unreachable!(),
                };
                self.emit(cmp_op, -1);
                Ok(Ty::Bool)
            }
            BinOp::Eq | BinOp::Ne => {
                // An optional address field (`next_hop`, `peer`, ...) can't
                // be pushed when unset, so comparing it to a literal is its
                // own op: an unset field is simply never equal.
                if let (Some(id), ExprKind::IpLit(ip)) = (optional_ip_field(lhs), &rhs.kind) {
                    self.emit(Op::OptIpEq(id, *ip), 1);
                    if op == BinOp::Ne {
                        self.emit(Op::Not, 0);
                    }
                    return Ok(Ty::Bool);
                }
                if is_rd_field(lhs) || matches!(rhs.kind, ExprKind::ExtLit(ExtKind::Rd, _)) {
                    let (ExprKind::ExtLit(ExtKind::Rd, rd), true) = (&rhs.kind, is_rd_field(lhs))
                    else {
                        return Err(CompileError::new(
                            line,
                            "'this.bgp.rd' is only comparable with '==' / '!=' to rd(..)",
                        ));
                    };
                    self.emit(Op::OptRdEq(*rd), 1);
                    if op == BinOp::Ne {
                        self.emit(Op::Not, 0);
                    }
                    return Ok(Ty::Bool);
                }
                let lt = self.compile_expr(lhs)?;
                let rt = self.compile_expr(rhs)?;
                if lt != rt {
                    return Err(CompileError::new(
                        line,
                        format!("cannot compare {lt:?} with {rt:?}"),
                    ));
                }
                self.emit(
                    if op == BinOp::Eq {
                        Op::CmpEq
                    } else {
                        Op::CmpNe
                    },
                    -1,
                );
                Ok(Ty::Bool)
            }
            BinOp::In => {
                if let Some(id) = optional_ip_field(lhs) {
                    match &rhs.kind {
                        ExprKind::PrefixLit(net) => {
                            self.emit(Op::OptIpIn(id, *net), 1);
                        }
                        ExprKind::Ident(name) => {
                            let Some((_, entries)) = self
                                .symbols
                                .prefix_lists
                                .iter()
                                .find(|(n, _)| *n == name.as_str())
                            else {
                                return Err(CompileError::new(
                                    rhs.line,
                                    format!("undefined prefix-list '{name}'"),
                                ));
                            };
                            self.emit(Op::OptIpInList(id, entries.to_vec()), 1);
                        }
                        _ => {
                            return Err(CompileError::new(
                                rhs.line,
                                "'in' on an address field needs a prefix literal or a prefix-list",
                            ));
                        }
                    }
                    return Ok(Ty::Bool);
                }
                if let (ExprKind::Ident(name), true) = (&rhs.kind, is_as_path(lhs)) {
                    let Some((_, patterns)) = self
                        .symbols
                        .as_path_lists
                        .iter()
                        .find(|(n, _)| *n == name.as_str())
                    else {
                        return Err(CompileError::new(
                            rhs.line,
                            format!("undefined as-path-list '{name}'"),
                        ));
                    };
                    let re =
                        AsPathRegexes::new(patterns).map_err(|e| CompileError::new(rhs.line, e))?;
                    self.emit(Op::AsPathMatches(re), 1);
                    return Ok(Ty::Bool);
                }
                if let ExprKind::Ident(name) = &rhs.kind {
                    let Some((_, entries)) = self
                        .symbols
                        .prefix_lists
                        .iter()
                        .find(|(n, _)| *n == name.as_str())
                    else {
                        return Err(CompileError::new(
                            rhs.line,
                            format!("undefined prefix-list '{name}'"),
                        ));
                    };
                    let entries = entries.to_vec();
                    let lt = self.compile_expr(lhs)?;
                    expect_ty(lt, Ty::Prefix, lhs.line)?;
                    self.emit(Op::PrefixInList(entries), 0);
                    return Ok(Ty::Bool);
                }
                let lt = self.compile_expr(lhs)?;
                expect_ty(lt, Ty::Prefix, lhs.line)?;
                let rt = self.compile_expr(rhs)?;
                expect_ty(rt, Ty::Prefix, rhs.line)?;
                self.emit(Op::PrefixIn, -1);
                Ok(Ty::Bool)
            }
        }
    }

    /// `this.bgp.{local,remote}_role ==/!= role.*`: emits `Op::OptEnumEq`.
    fn compile_role_cmp(
        &mut self,
        op: BinOp,
        id: schema::FieldId,
        rhs: &Expr,
        line: usize,
    ) -> Result<(), CompileError> {
        let bad =
            || CompileError::new(line, "a role is only comparable with '==' / '!=' to role.*");
        let ExprKind::EnumLit(name, variant) = &rhs.kind else {
            return Err(bad());
        };
        let (enum_name, v) = resolve_enum_literal(name, variant, rhs.line)?;
        if enum_name != "role" {
            return Err(bad());
        }
        self.emit(Op::OptEnumEq(id, v), 1);
        if op == BinOp::Ne {
            self.emit(Op::Not, 0);
        }
        Ok(())
    }

    /// `this.bgp.{first,neighbor,origin}_as <cmp> <int literal>`: emits
    /// `Op::OptIntCmp` and returns true; false when `lhs` is not an AS
    /// accessor. An accessor with any other rhs, or on the rhs, is an error.
    fn try_as_accessor_cmp(
        &mut self,
        op: BinOp,
        lhs: &Expr,
        rhs: &Expr,
        line: usize,
    ) -> Result<bool, CompileError> {
        if let (Some(id), BinOp::Eq | BinOp::Ne) = (optional_role_field(lhs), op) {
            self.compile_role_cmp(op, id, rhs, line)?;
            return Ok(true);
        }
        let l = optional_int_field(lhs);
        if l.is_none() && optional_int_field(rhs).is_none() {
            return Ok(false);
        }
        let (Some(id), ExprKind::IntLit(n)) = (l, &rhs.kind) else {
            return Err(CompileError::new(
                line,
                "'first_as'/'neighbor_as'/'origin_as' compare only as 'this.bgp.<field> <op> <integer literal>'",
            ));
        };
        let kind = match op {
            BinOp::Eq => CmpKind::Eq,
            BinOp::Ne => CmpKind::Ne,
            BinOp::Lt => CmpKind::Lt,
            BinOp::Le => CmpKind::Le,
            BinOp::Gt => CmpKind::Gt,
            _ => CmpKind::Ge,
        };
        self.emit(Op::OptIntCmp(id, kind, *n), 1);
        Ok(true)
    }

    fn compile_field_access(
        &mut self,
        segments: &[Postfix],
        line: usize,
    ) -> Result<Ty, CompileError> {
        if segments.is_empty() {
            return Err(CompileError::new(line, "'this' cannot be used by itself"));
        }
        let mut names = Vec::new();
        for seg in segments {
            match seg {
                Postfix::Field(n) => names.push(n.clone()),
                Postfix::Call(..) => break,
            }
        }
        let Some((info, consumed)) = schema::resolve_field(&names) else {
            return Err(CompileError::new(
                line,
                format!("unknown field 'this.{}'", names.join(".")),
            ));
        };
        let leftover = &segments[consumed..];
        if leftover.is_empty() {
            return self.compile_plain_field(info, line);
        }
        if leftover.len() > 1 {
            return Err(CompileError::new(
                line,
                "unsupported field access: at most one property or method may follow a field",
            ));
        }
        match &leftover[0] {
            Postfix::Field(name) if name == "length" => self.compile_field_len(info, line),
            Postfix::Field(name)
                if name == "path_length" && info.id == schema::FieldId::BgpAsPath =>
            {
                self.emit(Op::AsPathLen, 1);
                Ok(Ty::Int)
            }
            Postfix::Field(other) => Err(CompileError::new(
                line,
                format!("unknown property '.{other}'"),
            )),
            Postfix::Call(name, args) if name == "contains" => {
                self.compile_contains(info, args, line)
            }
            Postfix::Call(name, args)
                if name == "matches" && info.id == schema::FieldId::BgpAsPath =>
            {
                let re = str_lit_regex("as-path", args, line)?;
                self.emit(Op::AsPathMatches(re), 1);
                Ok(Ty::Bool)
            }
            Postfix::Call(name, args) if name == "matches" && is_community_list(info.ty) => {
                let re = str_lit_regex("community", args, line)?;
                self.emit(Op::CommunityMatches(info.id, re), 1);
                Ok(Ty::Bool)
            }
            Postfix::Call(other, _) => Err(CompileError::new(
                line,
                format!("unknown method '.{other}(..)'"),
            )),
        }
    }

    fn compile_plain_field(
        &mut self,
        info: &'static FieldInfo,
        line: usize,
    ) -> Result<Ty, CompileError> {
        match info.ty {
            FieldType::Int => {
                self.emit(Op::LoadField(info.id), 1);
                Ok(Ty::Int)
            }
            FieldType::Bool => {
                self.emit(Op::LoadField(info.id), 1);
                Ok(Ty::Bool)
            }
            FieldType::Prefix => {
                self.emit(Op::LoadField(info.id), 1);
                Ok(Ty::Prefix)
            }
            FieldType::Enum(name) => {
                self.emit(Op::LoadField(info.id), 1);
                Ok(Ty::Enum(name))
            }
            FieldType::OptionalInt if info.id == schema::FieldId::BgpMed => {
                self.emit(Op::LoadMed, 1);
                Ok(Ty::Int)
            }
            FieldType::OptionalInt => Err(CompileError::new(
                line,
                "this field may be unset: compare it with '==', '!=', '<', '<=', '>' or '>=' against an integer literal",
            )),
            FieldType::OptionalEnum(_) => Err(CompileError::new(
                line,
                "this field may be unset: compare it only with '==' / '!=' against a literal of its enum",
            )),
            FieldType::OptionalIp | FieldType::OptionalRd => Err(CompileError::new(
                line,
                "this field may be unset and can't be read directly yet (only 'set' is supported)",
            )),
            FieldType::ListInt
            | FieldType::ListIp
            | FieldType::ListCommunity
            | FieldType::ListExtCommunity
            | FieldType::ListLargeCommunity => Err(CompileError::new(
                line,
                "this field is a list — use '.length' or '.contains(...)'",
            )),
        }
    }

    fn compile_field_len(
        &mut self,
        info: &'static FieldInfo,
        line: usize,
    ) -> Result<Ty, CompileError> {
        match info.ty {
            FieldType::Prefix
            | FieldType::ListInt
            | FieldType::ListIp
            | FieldType::ListCommunity
            | FieldType::ListExtCommunity
            | FieldType::ListLargeCommunity => {
                self.emit(Op::FieldLen(info.id), 1);
                Ok(Ty::Int)
            }
            _ => Err(CompileError::new(
                line,
                "'.length' is only valid on a prefix or list field",
            )),
        }
    }

    fn compile_contains(
        &mut self,
        info: &'static FieldInfo,
        args: &[Expr],
        line: usize,
    ) -> Result<Ty, CompileError> {
        if args.len() != 1 {
            return Err(CompileError::new(
                line,
                "'.contains(..)' takes exactly one argument",
            ));
        }
        match info.ty {
            FieldType::ListInt => {
                let ExprKind::IntLit(n) = args[0].kind else {
                    return Err(CompileError::new(
                        args[0].line,
                        "'.contains(..)' on this field requires an integer literal",
                    ));
                };
                let n = u32::try_from(n).map_err(|_| {
                    CompileError::new(args[0].line, "AS number literal out of range")
                })?;
                self.emit(Op::ListContainsInt(info.id, n), 1);
                Ok(Ty::Bool)
            }
            FieldType::ListIp => {
                let ExprKind::IpLit(IpAddr::V4(addr)) = args[0].kind else {
                    return Err(CompileError::new(
                        args[0].line,
                        "'.contains(..)' on this field requires an IPv4 address literal",
                    ));
                };
                self.emit(Op::ListContainsIp(info.id, addr), 1);
                Ok(Ty::Bool)
            }
            FieldType::ListCommunity
            | FieldType::ListExtCommunity
            | FieldType::ListLargeCommunity => {
                let vals = self.community_values_for(info.ty, &args[0])?;
                let Some((first, rest)) = vals.split_first() else {
                    return Err(CompileError::new(
                        args[0].line,
                        "community group has no members",
                    ));
                };
                self.emit(Op::ListContainsCommunity(info.id, *first), 1);
                for val in rest {
                    self.emit(Op::ListContainsCommunity(info.id, *val), 1);
                    self.emit(Op::Or, -1);
                }
                Ok(Ty::Bool)
            }
            _ => Err(CompileError::new(
                line,
                "'.contains(..)' is only valid on a list field",
            )),
        }
    }

    /// Resolves a `.contains(..)`/`.add(..)`/`.remove(..)` argument against
    /// the target field's community kind, expanding a `community-alias`/
    /// `community-group` reference into its member value(s) — one value for
    /// a plain literal or an alias, one per member for a group (flat, no
    /// nesting). The caller reduces multiple values with `Op::Or` for
    /// `.contains`, or emits one `CommunityAdd`/`CommunityRemove` per value.
    fn community_values_for(
        &self,
        ty: FieldType,
        expr: &Expr,
    ) -> Result<Vec<CommunityValue>, CompileError> {
        let ExprKind::Ident(name) = &expr.kind else {
            return Ok(vec![community_value_for(ty, expr)?]);
        };
        if let Some((_, parts)) = self
            .symbols
            .aliases
            .iter()
            .find(|(n, _)| *n == name.as_str())
        {
            return Ok(vec![community_value_from_parts(ty, parts, expr.line)?]);
        }
        if let Some((_, members)) = self
            .symbols
            .groups
            .iter()
            .find(|(n, _)| *n == name.as_str())
        {
            return members
                .iter()
                .map(|parts| community_value_from_parts(ty, parts, expr.line))
                .collect();
        }
        Err(CompileError::new(
            expr.line,
            format!("undefined community alias or group '{name}'"),
        ))
    }
}

/// The one string-literal argument of `.matches(..)`, compiled.
fn str_lit_regex(kind: &str, args: &[Expr], line: usize) -> Result<AsPathRegexes, CompileError> {
    let [Expr {
        kind: ExprKind::StrLit(pattern),
        ..
    }] = args
    else {
        return Err(CompileError::new(
            line,
            "'.matches(..)' takes exactly one string literal",
        ));
    };
    AsPathRegexes::new_for(kind, &[pattern.as_str()]).map_err(|e| CompileError::new(line, e))
}

/// `.remove_matching(..)`'s argument: exactly one string literal.
fn community_regex(arg: &Expr) -> Result<AsPathRegexes, CompileError> {
    let ExprKind::StrLit(pattern) = &arg.kind else {
        return Err(CompileError::new(
            arg.line,
            "'.remove_matching(..)' takes exactly one string literal",
        ));
    };
    AsPathRegexes::new_for("community", &[pattern.as_str()])
        .map_err(|e| CompileError::new(arg.line, e))
}

fn is_community_list(ty: FieldType) -> bool {
    matches!(
        ty,
        FieldType::ListCommunity | FieldType::ListExtCommunity | FieldType::ListLargeCommunity
    )
}

/// Validates and packs a `.contains(..)`/`.add(..)`/`.remove(..)` argument
/// against the target field's community kind. Shared by all three call
/// sites so arity/range checking lives in one place.
fn community_value_for(ty: FieldType, expr: &Expr) -> Result<CommunityValue, CompileError> {
    if let ExprKind::ExtLit(kind, value) = &expr.kind {
        return match (ty, kind) {
            (FieldType::ListExtCommunity, ExtKind::Rt | ExtKind::Soo) => {
                Ok(CommunityValue::Extended(*value))
            }
            (_, ExtKind::Rd) => Err(CompileError::new(
                expr.line,
                "rd(..) is a Route Distinguisher, not a community; compare it with 'this.bgp.rd'",
            )),
            _ => Err(CompileError::new(
                expr.line,
                "rt(..)/soo(..) is only valid on 'this.bgp.extended_communities'",
            )),
        };
    }
    let ExprKind::ColonLit(parts) = &expr.kind else {
        return Err(CompileError::new(
            expr.line,
            "this argument requires a colon-separated community literal, e.g. 65000:100",
        ));
    };
    community_value_from_parts(ty, parts, expr.line)
}

/// The packing logic `community_value_for` applies to an inline `ColonLit`'s
/// parts, factored out so a resolved `community-alias`/`community-group`
/// member's already-flattened parts (see `Codegen::community_values_for`)
/// reuse the exact same arity/range checking.
fn community_value_from_parts(
    ty: FieldType,
    parts: &[i64],
    line: usize,
) -> Result<CommunityValue, CompileError> {
    let range_err = || CompileError::new(line, "community literal part out of range");
    match ty {
        FieldType::ListCommunity => {
            let [aa, nn] = parts else {
                return Err(CompileError::new(
                    line,
                    "a standard community literal takes exactly two parts, e.g. 65000:100",
                ));
            };
            let aa = u16::try_from(*aa).map_err(|_| range_err())?;
            let nn = u16::try_from(*nn).map_err(|_| range_err())?;
            Ok(CommunityValue::Standard(
                (u32::from(aa) << 16) | u32::from(nn),
            ))
        }
        FieldType::ListExtCommunity => {
            let [ty_octet, subtype, value] = parts else {
                return Err(CompileError::new(
                    line,
                    "an extended community literal takes exactly three parts, e.g. 0:2:100",
                ));
            };
            let ty_octet = u8::try_from(*ty_octet).map_err(|_| range_err())?;
            let subtype = u8::try_from(*subtype).map_err(|_| range_err())?;
            let value = u64::try_from(*value)
                .ok()
                .filter(|v| *v < (1u64 << 48))
                .ok_or_else(range_err)?;
            let packed = (u64::from(ty_octet) << 56) | (u64::from(subtype) << 48) | value;
            Ok(CommunityValue::Extended(packed))
        }
        FieldType::ListLargeCommunity => {
            let [ga, l1, l2] = parts else {
                return Err(CompileError::new(
                    line,
                    "a large community literal takes exactly three parts, e.g. 65000:1:1",
                ));
            };
            let ga = u32::try_from(*ga).map_err(|_| range_err())?;
            let l1 = u32::try_from(*l1).map_err(|_| range_err())?;
            let l2 = u32::try_from(*l2).map_err(|_| range_err())?;
            Ok(CommunityValue::Large(ga, l1, l2))
        }
        _ => Err(CompileError::new(
            line,
            "'.add'/'.remove' is only valid on a community-list field",
        )),
    }
}

fn expect_ty(got: Ty, want: Ty, line: usize) -> Result<(), CompileError> {
    if got == want {
        Ok(())
    } else {
        Err(CompileError::new(
            line,
            format!("expected {want:?}, found {got:?}"),
        ))
    }
}

fn body_halts(body: &[Stmt]) -> bool {
    matches!(
        body.last().map(|s| &s.kind),
        Some(StmtKind::Accept | StmtKind::Reject)
    )
}

/// Largest `.prepend(asn, count)` repeat — what real networks use is 1-5;
/// the cap just stops a typo from building a 255-hop path.
const MAX_PREPEND: u8 = 16;

fn int_literal(expr: &Expr, what: &str) -> Result<i64, CompileError> {
    match expr.kind {
        ExprKind::IntLit(n) => Ok(n),
        _ => Err(CompileError::new(
            expr.line,
            format!("expected an integer literal for {what}"),
        )),
    }
}

/// The `FieldId` of `this.<field>` when it is exactly an optional-address
/// field (see `Op::OptIpEq`).
fn optional_ip_field(expr: &Expr) -> Option<schema::FieldId> {
    let ExprKind::This(segments) = &expr.kind else {
        return None;
    };
    let names: Vec<String> = segments
        .iter()
        .map(|s| match s {
            Postfix::Field(n) => Some(n.clone()),
            Postfix::Call(..) => None,
        })
        .collect::<Option<_>>()?;
    let (info, consumed) = schema::resolve_field(&names)?;
    (consumed == names.len() && info.ty == FieldType::OptionalIp).then_some(info.id)
}

/// The `FieldId` of `this.bgp.{local,remote}_role` exactly.
fn optional_role_field(expr: &Expr) -> Option<schema::FieldId> {
    let ExprKind::This(s) = &expr.kind else {
        return None;
    };
    match s.as_slice() {
        [Postfix::Field(a), Postfix::Field(b)] if a == "bgp" && b == "local_role" => {
            Some(schema::FieldId::BgpLocalRole)
        }
        [Postfix::Field(a), Postfix::Field(b)] if a == "bgp" && b == "remote_role" => {
            Some(schema::FieldId::BgpRemoteRole)
        }
        _ => None,
    }
}

/// `this.bgp.rd` exactly.
fn is_rd_field(expr: &Expr) -> bool {
    matches!(&expr.kind, ExprKind::This(s)
        if matches!(s.as_slice(), [Postfix::Field(a), Postfix::Field(b)] if a == "bgp" && b == "rd"))
}

/// The `FieldId` of `this.bgp.{first,neighbor,origin}_as` exactly.
fn optional_int_field(expr: &Expr) -> Option<schema::FieldId> {
    use crate::schema::FieldId::{BgpFirstAs, BgpNeighborAs, BgpOriginAs, BgpOtc};
    let ExprKind::This(segments) = &expr.kind else {
        return None;
    };
    let names: Vec<String> = segments
        .iter()
        .map(|s| match s {
            Postfix::Field(n) => Some(n.clone()),
            Postfix::Call(..) => None,
        })
        .collect::<Option<_>>()?;
    let (info, consumed) = schema::resolve_field(&names)?;
    (consumed == names.len()
        && matches!(info.id, BgpFirstAs | BgpNeighborAs | BgpOriginAs | BgpOtc))
    .then_some(info.id)
}

/// `this.bgp.as_path` exactly, with no suffix.
fn is_as_path(expr: &Expr) -> bool {
    matches!(&expr.kind, ExprKind::This(s)
        if matches!(s.as_slice(), [Postfix::Field(a), Postfix::Field(b)] if a == "bgp" && b == "as_path"))
}

fn resolve_settable_field(expr: &Expr) -> Result<&'static FieldInfo, CompileError> {
    let ExprKind::This(segments) = &expr.kind else {
        return Err(CompileError::new(
            expr.line,
            "assignment target must be a 'this' field",
        ));
    };
    let mut names = Vec::with_capacity(segments.len());
    for seg in segments {
        match seg {
            Postfix::Field(n) => names.push(n.clone()),
            Postfix::Call(..) => {
                return Err(CompileError::new(
                    expr.line,
                    "assignment target cannot include a method call",
                ))
            }
        }
    }
    let Some((info, consumed)) = schema::resolve_field(&names) else {
        return Err(CompileError::new(
            expr.line,
            format!("unknown field 'this.{}'", names.join(".")),
        ));
    };
    if consumed != names.len() {
        return Err(CompileError::new(
            expr.line,
            "assignment target must name a field exactly, with no suffix",
        ));
    }
    if !info.mutable {
        return Err(CompileError::new(
            expr.line,
            format!("field 'this.{}' is not settable", names.join(".")),
        ));
    }
    Ok(info)
}

fn resolve_enum_literal(
    name: &str,
    variant: &str,
    line: usize,
) -> Result<(&'static str, u8), CompileError> {
    match (name, variant) {
        ("origin", "igp") => Ok(("origin", 0)),
        ("origin", "egp") => Ok(("origin", 1)),
        ("origin", "incomplete") => Ok(("origin", 2)),
        ("rpki", "valid") => Ok(("rpki", ValidationState::Valid as u8)),
        ("rpki", "invalid") => Ok(("rpki", ValidationState::Invalid as u8)),
        ("rpki", "not_found") => Ok(("rpki", ValidationState::NotFound as u8)),
        ("role", "provider") => Ok(("role", Role::Provider as u8)),
        ("role", "rs") => Ok(("role", Role::RouteServer as u8)),
        ("role", "rs_client") => Ok(("role", Role::RouteServerClient as u8)),
        ("role", "customer") => Ok(("role", Role::Customer as u8)),
        ("role", "peer") => Ok(("role", Role::Peer as u8)),
        _ => Err(CompileError::new(
            line,
            format!("unknown enum literal '{name}.{variant}'"),
        )),
    }
}

#[cfg(test)]
// Community/ASN values are conventionally written and read in decimal
// (`65000:100`, matching this language's own literal syntax) — hex/binary
// notation would make these test fixtures harder to read, not easier.
#[allow(clippy::decimal_bitwise_operands, clippy::identity_op)]
mod tests {
    use super::*;
    use crate::lexer::lex;
    use crate::parser::parse;
    use crate::schema::FieldId;
    use crate::symbols::PrefixListEntry;
    use crate::vm::{self, BgpInput, Edits, Input, NextHopSet, Origin, Verdict};
    use std::net::Ipv4Addr;

    fn compile_src(src: &str) -> CompiledPolicy {
        compile_src_with(src, &Symbols::EMPTY)
    }

    fn compile_err(src: &str) -> CompileError {
        compile_err_with(src, &Symbols::EMPTY)
    }

    fn compile_src_with(src: &str, symbols: &Symbols) -> CompiledPolicy {
        let tokens = lex(src).unwrap();
        let policy = parse(&tokens).unwrap();
        crate::check::check_termination(&policy).unwrap();
        compile(&policy, symbols).unwrap()
    }

    fn compile_err_with(src: &str, symbols: &Symbols) -> CompileError {
        let tokens = lex(src).unwrap();
        let policy = parse(&tokens).unwrap();
        crate::check::check_termination(&policy).unwrap();
        compile(&policy, symbols).unwrap_err()
    }

    fn default_input(prefix: &str) -> (ipnet::IpNet, Vec<u32>, Vec<Ipv4Addr>) {
        (prefix.parse().unwrap(), Vec::new(), Vec::new())
    }

    fn make_input<'a>(
        prefix: ipnet::IpNet,
        as_path: &'a [u32],
        local_pref: u32,
        med: Option<u32>,
        cluster_list: &'a [Ipv4Addr],
    ) -> Input<'a> {
        Input {
            prefix,
            bgp: BgpInput {
                origin: Origin::Igp,
                as_path,
                as_path_segments: &[],
                local_pref,
                med,
                next_hop: None,
                learned_via_ibgp: false,
                router_id: None,
                originator_id: None,
                peer: None,
                peer_as: 0,
                cluster_list,
                communities: &[],
                extended_communities: &[],
                large_communities: &[],
                validation_state: ValidationState::default(),
                rd: None,
                local_role: None,
                remote_role: None,
                otc: None,
            },
        }
    }

    fn make_community_input<'a>(
        prefix: ipnet::IpNet,
        communities: &'a [u32],
        extended_communities: &'a [u64],
        large_communities: &'a [(u32, u32, u32)],
    ) -> Input<'a> {
        Input {
            prefix,
            bgp: BgpInput {
                origin: Origin::Igp,
                as_path: &[],
                as_path_segments: &[],
                local_pref: 100,
                med: None,
                next_hop: None,
                learned_via_ibgp: false,
                router_id: None,
                originator_id: None,
                cluster_list: &[],
                peer: None,
                peer_as: 0,
                communities,
                extended_communities,
                large_communities,
                validation_state: ValidationState::default(),
                rd: None,
                local_role: None,
                remote_role: None,
                otc: None,
            },
        }
    }

    /// RFC 9234 / #872: `this.bgp.{local,remote}_role` and `this.bgp.otc`.
    #[test]
    fn role_and_otc_fields() {
        let (prefix, as_path, cluster_list) = default_input("10.0.0.0/8");
        let mut input = make_input(prefix, &as_path, 100, None, &cluster_list);
        let rejects =
            |src: &str, input: &Input| vm::run(&compile_src(src), input) == Verdict::Reject;
        let eq = "if this.bgp.local_role == role.customer:\n    reject\naccept\n";
        let ne = "if this.bgp.remote_role != role.provider:\n    reject\naccept\n";
        // Unset: `==` false, `!=` true.
        assert!(!rejects(eq, &input));
        assert!(rejects(ne, &input));
        input.bgp.local_role = Some(vm::Role::Customer);
        input.bgp.remote_role = Some(vm::Role::Provider);
        assert!(rejects(eq, &input));
        assert!(!rejects(ne, &input));
        for (lit, role) in [
            ("rs", vm::Role::RouteServer),
            ("rs_client", vm::Role::RouteServerClient),
            ("peer", vm::Role::Peer),
        ] {
            input.bgp.remote_role = Some(role);
            let src = format!("if this.bgp.remote_role == role.{lit}:\n    reject\naccept\n");
            assert!(rejects(&src, &input), "{lit}");
        }
        for src in [
            "if this.bgp.local_role < role.peer:\n    reject\naccept\n",
            "if role.peer == this.bgp.local_role:\n    reject\naccept\n",
            "if this.bgp.local_role == origin.igp:\n    reject\naccept\n",
            "if this.bgp.local_role == 3:\n    reject\naccept\n",
            "if this.bgp.local_role:\n    reject\naccept\n",
        ] {
            compile_err(src);
        }
        assert!(
            compile_err("if this.bgp.local_role == role.bogus:\n    reject\naccept\n")
                .message
                .contains("unknown enum literal")
        );
        for src in [
            "set this.bgp.local_role = role.peer\naccept\n",
            "set this.bgp.otc = 1\naccept\n",
        ] {
            assert!(compile_err(src).message.contains("not settable"));
        }
        // OTC: unset compares false, `!=` true.
        for (otc, cond, rejected) in [
            (None, "this.bgp.otc == 65000", false),
            (None, "this.bgp.otc != 65000", true),
            (None, "this.bgp.otc < 65000", false),
            (Some(65000), "this.bgp.otc == 65000", true),
            (Some(65000), "this.bgp.otc != 65000", false),
            (Some(65000), "this.bgp.otc < 65001", true),
        ] {
            input.bgp.otc = otc;
            let src = format!("if {cond}:\n    reject\naccept\n");
            assert_eq!(rejects(&src, &input), rejected, "{cond} {otc:?}");
        }
    }

    /// RFC 6811 / #17: `this.bgp.validation_state` against `rpki.*`.
    #[test]
    fn validation_state_enum() {
        let policy =
            compile_src("if this.bgp.validation_state == rpki.invalid:\n    reject\naccept\n");
        assert!(policy.reads_validation_state());
        assert!(!compile_src("accept\n").reads_validation_state());
        let (prefix, as_path, cluster_list) = default_input("10.0.0.0/8");
        let mut input = make_input(prefix, &as_path, 100, None, &cluster_list);
        for (state, rejected) in [
            (vm::ValidationState::Invalid, true),
            (vm::ValidationState::Valid, false),
            (vm::ValidationState::NotFound, false),
        ] {
            input.bgp.validation_state = state;
            assert_eq!(vm::run(&policy, &input) == Verdict::Reject, rejected);
        }
        assert!(
            compile_err("if this.bgp.validation_state == origin.igp:\n    reject\naccept\n")
                .message
                .contains("Enum")
        );
        assert!(
            compile_err("if this.bgp.validation_state == rpki.bogus:\n    reject\naccept\n")
                .message
                .contains("unknown enum literal")
        );
        assert!(
            compile_err("set this.bgp.validation_state = rpki.valid\naccept\n")
                .message
                .contains("not settable")
        );
    }

    #[test]
    fn worked_example_matches_plan() {
        let policy = compile_src("if this.bgp.local_pref < 100:\n    reject\nelse:\n    accept\n");
        assert_eq!(
            policy.code,
            vec![
                Op::LoadField(FieldId::BgpLocalPref),
                Op::LoadConstInt(100),
                Op::CmpLt,
                Op::JumpIfFalse(5),
                Op::Reject,
                Op::Accept,
            ]
        );
    }

    #[test]
    fn reject_branch_runs_for_low_local_pref() {
        let policy = compile_src("if this.bgp.local_pref < 100:\n    reject\nelse:\n    accept\n");
        let (prefix, as_path, cluster) = default_input("10.0.0.0/8");
        let input = make_input(prefix, &as_path, 50, None, &cluster);
        assert_eq!(vm::run(&policy, &input), Verdict::Reject);
    }

    #[test]
    fn accept_branch_runs_for_high_local_pref() {
        let policy = compile_src("if this.bgp.local_pref < 100:\n    reject\nelse:\n    accept\n");
        let (prefix, as_path, cluster) = default_input("10.0.0.0/8");
        let input = make_input(prefix, &as_path, 200, None, &cluster);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 200,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn relative_set_adds_and_subtracts_saturating() {
        let policy = compile_src(
            "set this.bgp.local_pref += 50\nset this.bgp.med -= 5\nset this.bgp.med += 20\naccept\n",
        );
        let (prefix, as_path, cluster) = default_input("10.0.0.0/8");
        let input = make_input(prefix, &as_path, 100, None, &cluster);
        let Verdict::Accept {
            local_pref, med, ..
        } = vm::run(&policy, &input)
        else {
            panic!("expected accept");
        };
        // unset med counts as 0: 0 - 5 saturates to 0, then + 20.
        assert_eq!((local_pref, med), (150, Some(20)));
    }

    #[test]
    fn relative_set_rejects_non_numeric_field() {
        let err = compile_err("set this.bgp.origin += 1\naccept\n");
        assert!(err.message.contains("numeric") || err.message.contains("settable"));
    }

    #[test]
    fn as_path_prepend_and_regex_match() {
        let policy = compile_src(
            "if this.bgp.as_path.matches(\"^65001_\"):\n    this.bgp.as_path.prepend(65000, 2)\n    accept\nelse:\n    reject\n",
        );
        let (prefix, _, cluster) = default_input("10.0.0.0/8");
        let hit = vec![65001, 65002];
        let Verdict::Accept { edits, .. } =
            vm::run(&policy, &make_input(prefix, &hit, 100, None, &cluster))
        else {
            panic!("expected accept");
        };
        assert_eq!(edits.as_path, Some(vec![65000, 65000, 65001, 65002]));
        let miss = vec![65002, 65001];
        assert_eq!(
            vm::run(&policy, &make_input(prefix, &miss, 100, None, &cluster)),
            Verdict::Reject
        );
    }

    #[test]
    fn as_path_list_matches_any_entry_and_undefined_is_error() {
        let patterns: &[&str] = &["^65001$", "_65009_"];
        let lists: &[(&str, &[&str])] = &[("TRANSIT", patterns)];
        let symbols = Symbols {
            as_path_lists: lists,
            ..Symbols::EMPTY
        };
        let policy = compile_src_with(
            "if this.bgp.as_path in TRANSIT:\n    reject\nelse:\n    accept\n",
            &symbols,
        );
        let (prefix, _, cluster) = default_input("10.0.0.0/8");
        for (path, rejected) in [
            (vec![65001], true),
            (vec![1, 65009, 2], true),
            (vec![65010], false),
        ] {
            let v = vm::run(&policy, &make_input(prefix, &path, 100, None, &cluster));
            assert_eq!(v == Verdict::Reject, rejected, "{path:?}");
        }
        let err = compile_err("if this.bgp.as_path in NOPE:\n    reject\nelse:\n    accept\n");
        assert!(err.message.contains("undefined as-path-list"));
    }

    #[test]
    fn hash_in_regex_string_compiles() {
        compile_src(
            "if this.bgp.as_path.matches(\"^65001#\"): # c\n    accept\nelse:\n    reject\n",
        );
    }

    #[test]
    fn escaped_quote_and_bad_escape_in_matches() {
        compile_src("if this.bgp.as_path.matches(\"\\\"\"):\n    accept\nelse:\n    reject\n");
        let err = lex("if this.bgp.as_path.matches(\"\\q\"):\n    accept\nelse:\n    reject\n")
            .unwrap_err();
        assert!(err.message.contains("unknown escape '\\q'"));
    }

    #[test]
    fn bad_regex_and_bad_prepend_are_compile_errors() {
        assert!(compile_err(
            "if this.bgp.as_path.matches(\"(\"):\n    accept\nelse:\n    reject\n"
        )
        .message
        .contains("invalid as-path regex"));
        assert!(compile_err("this.bgp.as_path.prepend(65000, 99)\naccept\n")
            .message
            .contains("prepend count"));
        assert!(compile_err("set this.bgp.as_path = 1\naccept\n")
            .message
            .contains("can't be assigned"));
    }

    #[test]
    fn set_origin_next_hop_and_peer_match() {
        let policy = compile_src(
            "if this.bgp.peer_as == 65100 and this.bgp.peer == 10.0.0.1:\n    set this.bgp.origin = origin.incomplete\n    set this.bgp.next_hop = 192.0.2.1\n    if this.bgp.next_hop == 192.0.2.1:\n        accept\n    else:\n        reject\nelse:\n    set this.bgp.next_hop = self\n    accept\n",
        );
        let (prefix, as_path, cluster) = default_input("10.0.0.0/8");
        let mut input = make_input(prefix, &as_path, 100, None, &cluster);
        input.bgp.peer = Some("10.0.0.1".parse().unwrap());
        input.bgp.peer_as = 65100;
        let Verdict::Accept { edits, .. } = vm::run(&policy, &input) else {
            panic!("expected accept");
        };
        assert_eq!(edits.origin, Some(Origin::Incomplete));
        assert_eq!(
            edits.next_hop,
            NextHopSet::Addr("192.0.2.1".parse().unwrap())
        );
        // Locally-redistributed (no peer): falls to the else branch.
        input.bgp.peer = None;
        input.bgp.peer_as = 0;
        let Verdict::Accept { edits, .. } = vm::run(&policy, &input) else {
            panic!("expected accept");
        };
        assert_eq!(
            (edits.origin, edits.next_hop),
            (None, NextHopSet::SelfAddress)
        );
    }

    #[test]
    fn next_hop_needs_an_address_and_origin_needs_an_enum() {
        assert!(compile_err("set this.bgp.next_hop = 5\naccept\n")
            .message
            .contains("Ip"));
        assert!(compile_err("set this.bgp.origin = 1\naccept\n")
            .message
            .contains("Enum"));
    }

    #[test]
    fn set_mutates_local_pref_before_accept() {
        let policy = compile_src(
            "if this.prefix in 203.0.113.0/16:\n    set this.bgp.local_pref = 150\n    accept\nelse:\n    reject\n",
        );
        let (prefix, as_path, cluster) = default_input("203.0.113.0/24");
        let input = make_input(prefix, &as_path, 100, None, &cluster);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 150,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn set_med_wraps_in_some() {
        let policy = compile_src(
            "if this.bgp.as_path.contains(65010):\n    set this.bgp.med = 50\n    accept\nelse:\n    accept\n",
        );
        let (prefix, _, cluster) = default_input("198.51.100.0/24");
        let as_path = vec![65010, 65020];
        let input = make_input(prefix, &as_path, 100, None, &cluster);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: Some(50),
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn as_path_length_and_reject() {
        let policy =
            compile_src("if this.bgp.as_path.length > 2:\n    reject\nelse:\n    accept\n");
        let (prefix, _, cluster) = default_input("10.0.0.0/8");
        let long_path = vec![1, 2, 3, 4];
        let input = make_input(prefix, &long_path, 100, None, &cluster);
        assert_eq!(vm::run(&policy, &input), Verdict::Reject);
    }

    #[test]
    fn prefix_length_range() {
        let policy = compile_src(
            "if this.prefix in 203.0.113.0/16 and this.prefix.length <= 24:\n    accept\nelse:\n    reject\n",
        );
        let (prefix, as_path, cluster) = default_input("203.0.113.0/20");
        let input = make_input(prefix, &as_path, 100, None, &cluster);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn origin_enum_comparison() {
        let policy =
            compile_src("if this.bgp.origin == origin.igp:\n    accept\nelse:\n    reject\n");
        let (prefix, as_path, cluster) = default_input("10.0.0.0/8");
        let input = make_input(prefix, &as_path, 100, None, &cluster);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn cluster_list_contains() {
        let policy = compile_src(
            "if this.bgp.cluster_list.contains(1.2.3.4):\n    reject\nelse:\n    accept\n",
        );
        let (prefix, as_path, _) = default_input("10.0.0.0/8");
        let cluster = vec![Ipv4Addr::new(1, 2, 3, 4)];
        let input = make_input(prefix, &as_path, 100, None, &cluster);
        assert_eq!(vm::run(&policy, &input), Verdict::Reject);
    }

    #[test]
    fn standard_community_contains_true_and_false() {
        let policy = compile_src(
            "if this.bgp.communities.contains(65000:100):\n    reject\nelse:\n    accept\n",
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let present = make_community_input(prefix, &[(65000 << 16) | 100], &[], &[]);
        assert_eq!(vm::run(&policy, &present), Verdict::Reject);
        let absent = make_community_input(prefix, &[(65000 << 16) | 200], &[], &[]);
        assert_eq!(
            vm::run(&policy, &absent),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: vec![(65000 << 16) | 200],
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn community_add_then_contains_sees_own_write() {
        let policy = compile_src(
            "this.bgp.communities.add(65000:100)\nif this.bgp.communities.contains(65000:100):\n    accept\nelse:\n    reject\n",
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let input = make_community_input(prefix, &[], &[], &[]);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: vec![(65000 << 16) | 100],
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn community_remove_drops_matching_value() {
        let policy = compile_src("this.bgp.communities.remove(65000:100)\naccept\n");
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let input = make_community_input(
            prefix,
            &[(65000 << 16) | 100, (65000 << 16) | 200],
            &[],
            &[],
        );
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: vec![(65000 << 16) | 200],
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    /// Runs `src` over one std community `65000:100` and `65001:7`, returning
    /// whether `accept` was reached and the surviving std communities.
    fn std_run(src: &str) -> Option<Vec<u32>> {
        let policy = compile_src(src);
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let input =
            make_community_input(prefix, &[(65000 << 16) | 100, (65001 << 16) | 7], &[], &[]);
        match vm::run(&policy, &input) {
            Verdict::Accept { communities, .. } => Some(communities),
            Verdict::Reject => None,
        }
    }

    fn std_matches(pat: &str) -> bool {
        let src =
            format!("if this.bgp.communities.matches(\"{pat}\"):\n    accept\nelse:\n    reject\n");
        std_run(&src).is_some()
    }

    #[test]
    fn community_matches_underscore_semantics() {
        assert!(std_matches("^65000:"));
        assert!(std_matches("_65000:"));
        assert!(std_matches(":100_"));
        assert!(std_matches("_65000:100_"));
        // No boundary in the middle of the token.
        assert!(!std_matches("_65000:_"));
        assert!(!std_matches("^65002:"));
        assert!(!std_matches("^65000:101$"));
        // `[_]` and `\_` are literal.
        assert!(!std_matches("[_]"));
        assert!(!std_matches("\\_"));
    }

    #[test]
    fn community_remove_matching_strips_only_matches() {
        assert_eq!(
            std_run("this.bgp.communities.remove_matching(\"^65000:\")\naccept\n"),
            Some(vec![(65001 << 16) | 7])
        );
        // No match: list untouched.
        assert_eq!(
            std_run("this.bgp.communities.remove_matching(\"^1:\")\naccept\n"),
            Some(vec![(65000 << 16) | 100, (65001 << 16) | 7])
        );
        // Sees its own earlier add, and a later contains sees the removal.
        let src = "this.bgp.communities.add(65000:9)\nthis.bgp.communities.remove_matching(\"^65000:\")\nif this.bgp.communities.contains(65000:9):\n    reject\naccept\n";
        assert_eq!(std_run(src), Some(vec![(65001 << 16) | 7]));
        // matches sees an earlier add.
        let src = "this.bgp.communities.add(7:7)\nif this.bgp.communities.matches(\"^7:7$\"):\n    accept\nreject\n";
        assert!(std_run(src).is_some());
        // Still rejects after a removal.
        assert_eq!(
            std_run("this.bgp.communities.remove_matching(\"^65000:\")\nreject\n"),
            None
        );
    }

    #[test]
    fn community_matches_and_remove_matching_ext_and_large() {
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        // ext 0:2:100 and 1:2:200; large 65000:1:2 and 65001:1:2.
        let ext = [(2u64 << 48) | 100, (1u64 << 56) | (2u64 << 48) | 200];
        let large = [(65000, 1, 2), (65001, 1, 2)];
        let input = make_community_input(prefix, &[], &ext, &large);
        let policy = compile_src(
            "this.bgp.extended_communities.remove_matching(\"^0:\")\nthis.bgp.large_communities.remove_matching(\"_65000:\")\nif this.bgp.extended_communities.matches(\"^1:2:200$\") and this.bgp.large_communities.matches(\"^65001:1:2$\"):\n    accept\nreject\n",
        );
        match vm::run(&policy, &input) {
            Verdict::Accept {
                extended_communities,
                large_communities,
                ..
            } => {
                assert_eq!(extended_communities, vec![ext[1]]);
                assert_eq!(large_communities, vec![large[1]]);
            }
            Verdict::Reject => panic!("expected accept"),
        }
    }

    #[test]
    fn community_regex_errors() {
        let err = compile_err("if this.bgp.communities.matches(\"(\"):\n    accept\nreject\n");
        assert!(err.to_string().contains("invalid community regex"));
        let err = compile_err("this.bgp.communities.remove_matching(\"(\")\naccept\n");
        assert!(err.to_string().contains("invalid community regex"));
        let err = compile_err("this.bgp.communities.remove_matching(65000:1)\naccept\n");
        assert!(err.to_string().contains("exactly one string literal"));
        let err = compile_err("this.bgp.as_path.remove_matching(\"1\")\naccept\n");
        assert!(err.to_string().contains("community-list"));
        let err = compile_err("if this.bgp.communities.matches(65000:1):\n    accept\nreject\n");
        assert!(err.to_string().contains("exactly one string literal"));
        let err = compile_err("if this.bgp.cluster_list.matches(\"1\"):\n    accept\nreject\n");
        assert!(err.to_string().contains("unknown method"));
    }

    #[test]
    fn community_clear_empties_length() {
        let policy = compile_src(
            "this.bgp.communities.clear()\nif this.bgp.communities.length == 0:\n    accept\nelse:\n    reject\n",
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let input = make_community_input(prefix, &[(65000 << 16) | 100], &[], &[]);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn extended_community_contains() {
        let policy = compile_src(
            "if this.bgp.extended_communities.contains(0:2:100):\n    accept\nelse:\n    reject\n",
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let packed = (0u64 << 56) | (2u64 << 48) | 100u64;
        let extended = [packed];
        let input = make_community_input(prefix, &[], &extended, &[]);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: vec![packed],
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn large_community_add_then_length() {
        let policy = compile_src(
            "this.bgp.large_communities.add(65000:1:1)\nif this.bgp.large_communities.length == 1:\n    accept\nelse:\n    reject\n",
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let input = make_community_input(prefix, &[], &[], &[]);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: vec![(65000, 1, 1)],
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn community_literal_wrong_arity_is_a_compile_error() {
        let err = compile_err(
            "if this.bgp.communities.contains(65000:100:1):\n    accept\nelse:\n    reject\n",
        );
        assert!(err.to_string().contains("exactly two parts"));
    }

    #[test]
    fn community_literal_out_of_range_is_a_compile_error() {
        let err = compile_err(
            "if this.bgp.communities.contains(999999:100):\n    accept\nelse:\n    reject\n",
        );
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn adding_to_immutable_list_field_is_a_compile_error() {
        let err = compile_err("this.bgp.cluster_list.add(65000:100)\naccept\n");
        assert!(err.to_string().contains("not settable"));
    }

    #[test]
    fn reading_optional_field_is_a_compile_error() {
        let err = compile_err("if this.bgp.first_as:\n    accept\nelse:\n    reject\n");
        assert!(err.to_string().contains("unset"));
    }

    #[test]
    fn reading_list_field_directly_is_a_compile_error() {
        let err = compile_err("if this.bgp.as_path == 5:\n    accept\nelse:\n    reject\n");
        assert!(err.to_string().contains("list"));
    }

    #[test]
    fn setting_immutable_field_is_a_compile_error() {
        let err = compile_err("set this.bgp.router_id = 1\naccept\n");
        assert!(err.to_string().contains("not settable"));
    }

    #[test]
    fn type_mismatch_in_comparison_is_a_compile_error() {
        let err =
            compile_err("if this.bgp.local_pref < this.prefix:\n    accept\nelse:\n    reject\n");
        assert!(err.to_string().contains("expected Int"));
    }

    #[test]
    fn unknown_field_is_a_compile_error() {
        let err = compile_err("if this.bgp.nonexistent == 1:\n    accept\nelse:\n    reject\n");
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn community_alias_resolves_in_contains() {
        let cust_a: &[i64] = &[65000, 100];
        let aliases: &[(&str, &[i64])] = &[("CUSTOMER_A", cust_a)];
        let symbols = Symbols {
            aliases,
            groups: &[],
            prefix_lists: &[],
            as_path_lists: &[],
            policies: &[],
        };
        let policy = compile_src_with(
            "if this.bgp.communities.contains(CUSTOMER_A):\n    reject\nelse:\n    accept\n",
            &symbols,
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let present = make_community_input(prefix, &[(65000 << 16) | 100], &[], &[]);
        assert_eq!(vm::run(&policy, &present), Verdict::Reject);
    }

    #[test]
    fn community_group_contains_matches_any_member() {
        let a: &[i64] = &[65000, 100];
        let b: &[i64] = &[65000, 200];
        let members: &[&[i64]] = &[a, b];
        let groups: &[(&str, &[&[i64]])] = &[("CUSTOMERS", members)];
        let symbols = Symbols {
            aliases: &[],
            groups,
            prefix_lists: &[],
            as_path_lists: &[],
            policies: &[],
        };
        let policy = compile_src_with(
            "if this.bgp.communities.contains(CUSTOMERS):\n    reject\nelse:\n    accept\n",
            &symbols,
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let matches_second = make_community_input(prefix, &[(65000 << 16) | 200], &[], &[]);
        assert_eq!(vm::run(&policy, &matches_second), Verdict::Reject);
        let matches_neither = make_community_input(prefix, &[(65000 << 16) | 999], &[], &[]);
        assert_eq!(
            vm::run(&policy, &matches_neither),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: vec![(65000 << 16) | 999],
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn community_group_add_adds_every_member() {
        let a: &[i64] = &[65000, 100];
        let b: &[i64] = &[65000, 200];
        let members: &[&[i64]] = &[a, b];
        let groups: &[(&str, &[&[i64]])] = &[("CUSTOMERS", members)];
        let symbols = Symbols {
            aliases: &[],
            groups,
            prefix_lists: &[],
            as_path_lists: &[],
            policies: &[],
        };
        let policy = compile_src_with("this.bgp.communities.add(CUSTOMERS)\naccept\n", &symbols);
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let input = make_community_input(prefix, &[], &[], &[]);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: vec![(65000 << 16) | 100, (65000 << 16) | 200],
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn undefined_community_alias_is_a_compile_error() {
        let err = compile_err(
            "if this.bgp.communities.contains(NOT_DEFINED):\n    accept\nelse:\n    reject\n",
        );
        assert!(err
            .to_string()
            .contains("undefined community alias or group"));
    }

    #[test]
    fn prefix_list_exact_match() {
        let entries: &[PrefixListEntry] = &[PrefixListEntry {
            cidr: "10.0.0.0/8".parse().unwrap(),
            range: None,
        }];
        let lists: &[(&str, &[PrefixListEntry])] = &[("BLOCKS", entries)];
        let symbols = Symbols {
            aliases: &[],
            groups: &[],
            prefix_lists: lists,
            as_path_lists: &[],
            policies: &[],
        };
        let policy = compile_src_with(
            "if this.prefix in BLOCKS:\n    reject\nelse:\n    accept\n",
            &symbols,
        );

        let (exact, as_path, cluster) = default_input("10.0.0.0/8");
        let input = make_input(exact, &as_path, 100, None, &cluster);
        assert_eq!(vm::run(&policy, &input), Verdict::Reject);

        let (more_specific, as_path2, cluster2) = default_input("10.0.0.0/24");
        let input2 = make_input(more_specific, &as_path2, 100, None, &cluster2);
        assert_eq!(
            vm::run(&policy, &input2),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn prefix_list_range_match() {
        let entries: &[PrefixListEntry] = &[PrefixListEntry {
            cidr: "10.0.0.0/8".parse().unwrap(),
            range: Some((24, 32)),
        }];
        let lists: &[(&str, &[PrefixListEntry])] = &[("BLOCKS", entries)];
        let symbols = Symbols {
            aliases: &[],
            groups: &[],
            prefix_lists: lists,
            as_path_lists: &[],
            policies: &[],
        };
        let policy = compile_src_with(
            "if this.prefix in BLOCKS:\n    reject\nelse:\n    accept\n",
            &symbols,
        );

        let (in_range, as_path, cluster) = default_input("10.0.0.0/24");
        let input = make_input(in_range, &as_path, 100, None, &cluster);
        assert_eq!(vm::run(&policy, &input), Verdict::Reject);

        let (too_short, as_path2, cluster2) = default_input("10.0.0.0/16");
        let input2 = make_input(too_short, &as_path2, 100, None, &cluster2);
        assert_eq!(
            vm::run(&policy, &input2),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn undefined_prefix_list_is_a_compile_error() {
        let err = compile_err("if this.prefix in BLOCKS:\n    accept\nelse:\n    reject\n");
        assert!(err.to_string().contains("undefined prefix-list"));
    }

    /// #582: `rt()`/`soo()` are the raw `type:subtype:value` literals spelled
    /// out, in all three type forms.
    #[test]
    fn rt_and_soo_literals_encode_like_the_raw_form() {
        for (sugar, raw) in [
            ("rt(65000:2)", "0:2:279172874240002"),
            ("rt(10.0.0.1:7)", "1:2:10995116343303"),
            ("rt(4200000000:9)", "2:2:275251200000009"),
            ("soo(65001:77)", "0:3:279177169207373"),
        ] {
            let sugar_p = compile_src(&format!(
                "this.bgp.extended_communities.add({sugar})\naccept\n"
            ));
            let raw_p = compile_src(&format!(
                "this.bgp.extended_communities.add({raw})\naccept\n"
            ));
            assert_eq!(sugar_p, raw_p, "{sugar}");
        }
        // contains/remove take them too.
        let p = compile_src(
            "if this.bgp.extended_communities.contains(rt(65000:1)):\n    this.bgp.extended_communities.remove(rt(65000:1))\n    this.bgp.extended_communities.add(soo(65001:5))\naccept\n",
        );
        let rt1 = (2u64 << 48) | (65000 << 32) | 1;
        let soo5 = (3u64 << 48) | (65001 << 32) | 5;
        let ext = [rt1, 7];
        let input = make_community_input("10.0.0.0/8".parse().unwrap(), &[], &ext, &[]);
        let Verdict::Accept {
            extended_communities,
            ..
        } = vm::run(&p, &input)
        else {
            panic!("accept expected");
        };
        assert_eq!(extended_communities, vec![7, soo5]);
    }

    #[test]
    fn bad_rt_rd_literals_are_compile_errors() {
        let ext = |lit: &str| {
            crate::compile(
                &format!("this.bgp.extended_communities.add({lit})\naccept\n"),
                &Symbols::EMPTY,
            )
        };
        for bad in [
            "rt(65000:4294967296)", // nn too big for a 16-bit AS
            "rt(70000:65536)",      // nn too big for a 32-bit AS
            "rt(4294967296:1)",     // AS too big
            "rt(10.0.0.1:65536)",   // nn too big for an IPv4 admin
            "rt(65000)",            // no nn
            "rd(65001:1)",          // an RD is not a community
        ] {
            assert!(ext(bad).is_err(), "{bad}");
        }
        // rt() on a standard-community list, and a bare rt()/rd() as a value.
        assert!(crate::compile(
            "this.bgp.communities.add(rt(65000:1))\naccept\n",
            &Symbols::EMPTY
        )
        .is_err());
        assert!(crate::compile(
            "if rt(65000:1):\n    accept\nelse:\n    reject\n",
            &Symbols::EMPTY
        )
        .is_err());
    }

    /// #582: `this.bgp.rd` compares with `==`/`!=` against `rd()`; an absent
    /// RD (a non-VPN route) never equals anything.
    #[test]
    fn bgp_rd_matches_only_an_equal_rd() {
        let eq = compile_src("if this.bgp.rd == rd(65001:1):\n    reject\nelse:\n    accept\n");
        let ne = compile_src("if this.bgp.rd != rd(65001:1):\n    reject\nelse:\n    accept\n");
        let rd_65001_1 = (65001u64 << 32) | 1;
        let rd_ip = (1u64 << 48) | (0x0a00_0001 << 16) | 7;
        let rd_asn4 = (2u64 << 48) | (4_200_000_000 << 16) | 9;
        let accept = |p: &CompiledPolicy, rd: Option<u64>| {
            let (pfx, a, c) = default_input("10.0.0.0/8");
            let mut input = make_input(pfx, &a, 100, None, &c);
            input.bgp.rd = rd;
            matches!(vm::run(p, &input), Verdict::Accept { .. })
        };
        assert!(!accept(&eq, Some(rd_65001_1)) && accept(&eq, Some(rd_ip)) && accept(&eq, None));
        // `!=` is the plain negation, so an absent RD is "not equal".
        assert!(accept(&ne, Some(rd_65001_1)) && !accept(&ne, Some(rd_ip)) && !accept(&ne, None));
        for (lit, want) in [("rd(10.0.0.1:7)", rd_ip), ("rd(4200000000:9)", rd_asn4)] {
            let p = compile_src(&format!(
                "if this.bgp.rd == {lit}:\n    accept\nelse:\n    reject\n"
            ));
            assert!(
                accept(&p, Some(want)) && !accept(&p, Some(rd_65001_1)),
                "{lit}"
            );
        }
    }

    #[test]
    fn bgp_rd_is_read_only_and_only_comparable_to_rd() {
        for src in [
            "if this.bgp.rd == 5:\n    accept\nelse:\n    reject\n",
            "if this.bgp.rd == rt(65000:1):\n    accept\nelse:\n    reject\n",
            "if this.bgp.rd < rd(65001:1):\n    accept\nelse:\n    reject\n",
            "if this.bgp.rd:\n    accept\nelse:\n    reject\n",
            "set this.bgp.rd = rd(65001:1)\naccept\n",
            "if rd(65001:1) == this.bgp.rd:\n    accept\nelse:\n    reject\n",
        ] {
            assert!(crate::compile(src, &Symbols::EMPTY).is_err(), "{src}");
        }
    }

    /// Runs `pre` then `if cond: accept else: reject`; true when accepted.
    fn eval(
        pre: &str,
        cond: &str,
        symbols: &Symbols,
        segs: &[vm::Segment],
        med: Option<u32>,
        next_hop: Option<std::net::IpAddr>,
    ) -> bool {
        let p = compile_src_with(
            &format!("{pre}\nif {cond}:\n    accept\nelse:\n    reject\n"),
            symbols,
        );
        let flat: Vec<u32> = segs.iter().flat_map(|s| s.asns.iter().copied()).collect();
        let (prefix, _, cl) = default_input("10.0.0.0/8");
        let mut input = make_input(prefix, &flat, 100, med, &cl);
        input.bgp.as_path_segments = segs;
        input.bgp.next_hop = next_hop;
        matches!(vm::run(&p, &input), Verdict::Accept { .. })
    }

    fn seg(kind: vm::SegKind, asns: &[u32]) -> vm::Segment<'_> {
        vm::Segment { kind, asns }
    }

    #[test]
    fn med_reads_zero_when_unset_and_sees_own_writes() {
        let ev = |pre: &str, c: &str, med| eval(pre, c, &Symbols::EMPTY, &[], med, None);
        assert!(ev("", "this.bgp.med == 0", None));
        assert!(ev("", "this.bgp.med < 1", None));
        assert!(ev("", "this.bgp.med == 7", Some(7)));
        assert!(ev("", "this.bgp.med != 0", Some(7)));
        assert!(ev("", "this.bgp.med <= 7", Some(7)));
        assert!(ev("", "this.bgp.med >= 7", Some(7)));
        assert!(ev("", "this.bgp.med > 6", Some(7)));
        assert!(!ev("", "this.bgp.med > 7", Some(7)));
        assert!(ev("set this.bgp.med = 5", "this.bgp.med > 4", None));
        assert!(ev("set this.bgp.med += 2", "this.bgp.med == 2", None));
        assert!(ev("", "this.bgp.med + 1 == 8", Some(7)));
    }

    #[test]
    fn next_hop_in_prefix_and_prefix_list() {
        let entries: &[PrefixListEntry] = &[
            PrefixListEntry {
                cidr: "10.1.0.1/32".parse().unwrap(),
                range: None,
            },
            PrefixListEntry {
                cidr: "2001:db8::/32".parse().unwrap(),
                range: Some((64, 128)),
            },
        ];
        let lists: &[(&str, &[PrefixListEntry])] = &[("NH", entries)];
        let symbols = Symbols {
            aliases: &[],
            groups: &[],
            prefix_lists: lists,
            as_path_lists: &[],
            policies: &[],
        };
        let v4: Option<std::net::IpAddr> = Some("10.1.0.1".parse().unwrap());
        let v4b: Option<std::net::IpAddr> = Some("10.1.0.2".parse().unwrap());
        let v6: Option<std::net::IpAddr> = Some("2001:db8::5".parse().unwrap());
        let ev = |pre: &str, c: &str, nh| eval(pre, c, &symbols, &[], None, nh);
        assert!(ev("", "this.bgp.next_hop in 10.0.0.0/8", v4));
        assert!(!ev("", "this.bgp.next_hop in 10.0.0.0/8", v6));
        assert!(!ev("", "this.bgp.next_hop in 10.0.0.0/8", None));
        assert!(ev("", "not this.bgp.next_hop in 10.0.0.0/8", None));
        assert!(ev("", "this.bgp.next_hop in NH", v4));
        assert!(!ev("", "this.bgp.next_hop in NH", v4b));
        assert!(ev("", "this.bgp.next_hop in NH", v6));
        assert!(!ev("", "this.bgp.next_hop in NH", None));
        assert!(ev(
            "set this.bgp.next_hop = 10.0.0.1",
            "this.bgp.next_hop in 10.0.0.0/8",
            None
        ));
        assert!(!ev(
            "set this.bgp.next_hop = self",
            "this.bgp.next_hop in 10.0.0.0/8",
            v4
        ));
        assert!(ev("", "this.bgp.peer in 10.0.0.0/8 or this.bgp.router_id in 1.0.0.0/8 or this.bgp.originator_id in 1.0.0.0/8 or this.bgp.next_hop in 10.0.0.0/8", v4));
        let err = compile_err_with(
            "if this.bgp.next_hop in NOPE:\n    accept\nelse:\n    reject\n",
            &symbols,
        );
        assert!(err.to_string().contains("undefined prefix-list"));
        assert!(crate::compile(
            "if this.bgp.next_hop in 5:\n    accept\nelse:\n    reject\n",
            &Symbols::EMPTY
        )
        .is_err());
    }

    #[test]
    fn as_accessors_and_path_length() {
        use vm::SegKind::*;
        let ev = |pre: &str, c: &str, segs: &[vm::Segment]| {
            eval(pre, c, &Symbols::EMPTY, segs, None, None)
        };
        let seq = [seg(Sequence, &[65001, 65002, 65003])];
        assert!(ev("", "this.bgp.first_as == 65001", &seq));
        assert!(ev("", "this.bgp.neighbor_as == 65001", &seq));
        assert!(ev("", "this.bgp.origin_as == 65003", &seq));
        assert!(ev(
            "",
            "this.bgp.origin_as >= 65003 and this.bgp.origin_as <= 65003",
            &seq
        ));
        assert!(ev(
            "",
            "this.bgp.origin_as > 1 and this.bgp.origin_as < 70000",
            &seq
        ));
        assert!(ev("", "this.bgp.as_path.path_length == 3", &seq));
        assert!(ev("", "this.bgp.as_path.length == 3", &seq));
        // Leading confed segment: neighbor skips it, first_as is unset.
        let confed = [
            seg(ConfedSequence, &[65100]),
            seg(Sequence, &[65001]),
            seg(Set, &[1, 2, 3]),
        ];
        assert!(!ev("", "this.bgp.first_as == 65100", &confed));
        assert!(ev("", "this.bgp.first_as != 65100", &confed));
        assert!(ev("", "this.bgp.neighbor_as == 65001", &confed));
        // Ends in an AS_SET: origin unset, == false, != true; set counts 1.
        assert!(!ev("", "this.bgp.origin_as == 3", &confed));
        assert!(ev("", "this.bgp.origin_as != 3", &confed));
        assert!(!ev("", "this.bgp.origin_as < 100", &confed));
        assert!(ev("", "this.bgp.as_path.path_length == 2", &confed));
        // A leading AS_SET: neighbor unset too.
        let set_first = [seg(Set, &[1, 2]), seg(Sequence, &[9])];
        assert!(!ev("", "this.bgp.neighbor_as == 1", &set_first));
        assert!(ev("", "this.bgp.origin_as == 9", &set_first));
        // Empty segments: everything unset / zero, even with a flat path.
        assert!(ev("", "this.bgp.as_path.path_length == 0", &[]));
        assert!(ev("", "this.bgp.first_as != 1", &[]));
        assert!(!ev("", "this.bgp.origin_as == 0", &[]));
        // Prepend joins the first sequence, or leads a new one.
        assert!(ev(
            "this.bgp.as_path.prepend(7, 3)",
            "this.bgp.first_as == 7 and this.bgp.as_path.path_length == 6 and this.bgp.origin_as == 65003",
            &seq
        ));
        assert!(ev(
            "this.bgp.as_path.prepend(7, 2)",
            "this.bgp.neighbor_as == 7 and this.bgp.as_path.path_length == 4 and this.bgp.as_path.length == 7",
            &confed
        ));
        let only_set = [seg(Set, &[5, 6])];
        assert!(ev(
            "this.bgp.as_path.prepend(7)",
            "this.bgp.first_as == 7 and this.bgp.origin_as != 6 and this.bgp.as_path.path_length == 2",
            &only_set
        ));
        // Empty segments + prepend: the prepended ASNs are the whole path.
        assert!(ev(
            "this.bgp.as_path.prepend(7, 2)",
            "this.bgp.first_as == 7 and this.bgp.origin_as == 7 and this.bgp.as_path.path_length == 2",
            &[]
        ));
    }

    #[test]
    fn as_accessor_misuse_is_a_compile_error() {
        for src in [
            "if this.bgp.first_as:\n    accept\nelse:\n    reject\n",
            "if this.bgp.first_as == this.bgp.peer_as:\n    accept\nelse:\n    reject\n",
            "if 5 < this.bgp.origin_as:\n    accept\nelse:\n    reject\n",
            "set this.bgp.first_as = 5\naccept\n",
            "if this.bgp.local_pref.path_length == 1:\n    accept\nelse:\n    reject\n",
            "if this.bgp.first_as in 10.0.0.0/8:\n    accept\nelse:\n    reject\n",
        ] {
            assert!(crate::compile(src, &Symbols::EMPTY).is_err(), "{src}");
        }
    }

    #[test]
    fn empty_segments_ignore_flat_path() {
        let (prefix, _, cl) = default_input("10.0.0.0/8");
        let flat = [65001, 65002];
        let input = make_input(prefix, &flat, 100, None, &cl);
        let p = compile_src(
            "if this.bgp.as_path.path_length == 0 and this.bgp.first_as != 65001:\n    accept\nelse:\n    reject\n",
        );
        // segments empty but flat non-empty violates the contract only for
        // non-empty segments, so this is the documented "no fallback" case.
        assert!(matches!(vm::run(&p, &input), Verdict::Accept { .. }));
    }

    fn call_syms<'a>(p: &'a [(&'a str, &'a str)]) -> Symbols<'a> {
        Symbols {
            policies: p,
            ..Symbols::EMPTY
        }
    }

    fn verdict_of(src: &str, p: &[(&str, &str)]) -> Verdict {
        let policy = compile_src_with(src, &call_syms(p));
        let (prefix, path, cluster) = default_input("10.0.0.0/8");
        let input = make_input(prefix, &path, 100, None, &cluster);
        vm::run(&policy, &input)
    }

    fn call_err(src: &str, p: &[(&str, &str)]) -> String {
        let tokens = lex(src).unwrap();
        let policy = parse(&tokens).unwrap();
        crate::check::check_termination(&policy).unwrap();
        compile(&policy, &call_syms(p)).unwrap_err().to_string()
    }

    fn is_accept(v: &Verdict) -> bool {
        matches!(v, Verdict::Accept { .. })
    }

    #[test]
    fn call_callee_accept_returns_to_caller() {
        let p = [("my-pol", "accept\n")];
        assert_eq!(verdict_of("call my-pol\nreject\n", &p), Verdict::Reject);
        assert!(is_accept(&verdict_of("call my-pol\naccept\n", &p)));
    }

    #[test]
    fn call_callee_reject_rejects_and_set_is_visible() {
        let p = [
            ("r", "reject\n"),
            ("s", "set this.bgp.origin = origin.incomplete\naccept\n"),
        ];
        assert_eq!(verdict_of("call r\naccept\n", &p), Verdict::Reject);
        let Verdict::Accept { edits, .. } = verdict_of("call s\naccept\n", &p) else {
            panic!("expected accept")
        };
        assert_eq!(edits.origin, Some(Origin::Incomplete));
    }

    #[test]
    fn call_nested_accept_in_if_and_twice() {
        let p = [(
            "c",
            "if this.prefix in 10.0.0.0/8:\n    accept\nelse:\n    reject\n",
        )];
        assert!(is_accept(&verdict_of("call c\ncall c\naccept\n", &p)));
        let p2 = [
            ("a", "call b\naccept\n"),
            ("b", "call c\naccept\n"),
            ("c", "accept\n"),
        ];
        assert!(is_accept(&verdict_of("call a\naccept\n", &p2)));
    }

    #[test]
    fn call_builtin_policies() {
        assert!(is_accept(&verdict_of("call accept-all\naccept\n", &[])));
        assert_eq!(verdict_of("call deny-all\naccept\n", &[]), Verdict::Reject);
    }

    #[test]
    fn call_errors() {
        assert!(call_err("call nope\naccept\n", &[]).contains("unknown policy 'nope'"));
        let p = [("a", "call b\naccept\n"), ("b", "call a\naccept\n")];
        assert!(call_err("call a\naccept\n", &p).contains("cycle: a -> b -> a"));
        let p = [("a", "call a\naccept\n")];
        assert!(call_err("call a\naccept\n", &p).contains("cycle: a -> a"));
        let p = [("bad", "set this.bgp.local_pref = 1\n")];
        let e = call_err("call bad\naccept\n", &p);
        assert!(e.contains("in called policy 'bad'") && e.contains("does not terminate"));
    }

    #[test]
    fn call_depth_limit() {
        // p0 -> p1 -> ... -> p9 (leaf): the root calling p0 nests 10 deep.
        let srcs: Vec<(String, String)> = (0..10)
            .map(|i| {
                let body = if i == 9 {
                    "accept\n".to_string()
                } else {
                    format!("call p{}\naccept\n", i + 1)
                };
                (format!("p{i}"), body)
            })
            .collect();
        let at = |n: usize| -> Vec<(&str, &str)> {
            srcs[n..]
                .iter()
                .map(|(a, b)| (a.as_str(), b.as_str()))
                .collect()
        };
        // root -> p2 .. p9 is 8 nested calls: fine; root -> p1 is 9: error.
        assert!(is_accept(&verdict_of("call p2\naccept\n", &at(2))));
        assert!(call_err("call p1\naccept\n", &at(1)).contains("deeper than 8"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "78k-call fan-out, minutes under the interpreter")]
    fn call_fan_out_hits_size_cap() {
        let mut srcs: Vec<(String, String)> = (0..7)
            .map(|i| {
                let c = format!("call p{}\n", i + 1);
                (format!("p{i}"), format!("{c}{c}{c}{c}{c}accept\n"))
            })
            .collect();
        srcs.push(("p7".into(), "set this.bgp.local_pref = 1\naccept\n".into()));
        let p: Vec<(&str, &str)> = srcs.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        assert!(call_err("call p0\naccept\n", &p).contains("too large"));
    }
}
