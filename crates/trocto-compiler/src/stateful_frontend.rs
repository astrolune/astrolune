// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Typed lexical scopes, short circuiting, and bounded flat control flow.

use crate::stateful::{Binary, CheckedProgram, Step, Type};
use crate::{
    CompileError, MAX_IDENTIFIER_BYTES, MAX_INSTRUCTIONS, MAX_LOCALS, MAX_NESTING,
    MAX_SOURCE_BYTES, MAX_STATE_KEY_BYTES, MAX_STATE_KEYS, MAX_TOKENS, Operator,
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind<'a> {
    Word(&'a str),
    Number(u64),
    Key(&'a str),
    Symbol(&'a str),
    End,
}
#[derive(Clone, Copy, Debug)]
struct Token<'a> {
    kind: TokenKind<'a>,
    offset: usize,
}

fn lex(source: &str) -> Result<Vec<Token<'_>>, CompileError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(CompileError::new(
            MAX_SOURCE_BYTES,
            "source byte limit exceeded",
        ));
    }
    let bytes = source.as_bytes();
    let mut pos = 0;
    let mut tokens = Vec::new();
    while pos < bytes.len() {
        let offset = pos;
        let byte = bytes[pos];
        if byte.is_ascii_whitespace() {
            pos += 1;
            continue;
        }
        if byte == b'/' && bytes.get(pos + 1) == Some(&b'/') {
            pos += 2;
            while pos < bytes.len() && bytes[pos] != b'\n' {
                pos += 1;
            }
            continue;
        }
        if tokens.len() >= MAX_TOKENS {
            return Err(CompileError::new(offset, "token limit exceeded"));
        }
        let kind = if byte.is_ascii_alphabetic() || byte == b'_' {
            pos += 1;
            while pos < bytes.len() && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
                pos += 1;
            }
            if pos - offset > MAX_IDENTIFIER_BYTES {
                return Err(CompileError::new(offset, "identifier byte limit exceeded"));
            }
            TokenKind::Word(&source[offset..pos])
        } else if byte.is_ascii_digit() {
            pos += 1;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                pos += 1;
            }
            TokenKind::Number(
                source[offset..pos]
                    .parse()
                    .map_err(|_| CompileError::new(offset, "integer literal exceeds u64"))?,
            )
        } else if byte == b'"' {
            pos += 1;
            let start = pos;
            while pos < bytes.len() && bytes[pos] != b'"' {
                if !bytes[pos].is_ascii()
                    || bytes[pos] < 32
                    || bytes[pos] == 127
                    || bytes[pos] == b'\\'
                {
                    return Err(CompileError::new(
                        pos,
                        "state keys require literal printable ASCII without escapes",
                    ));
                }
                pos += 1;
            }
            if pos == bytes.len() {
                return Err(CompileError::new(offset, "unterminated state key"));
            }
            if pos - start == 0 || pos - start > MAX_STATE_KEY_BYTES {
                return Err(CompileError::new(offset, "state key byte limit exceeded"));
            }
            let key = &source[start..pos];
            pos += 1;
            TokenKind::Key(key)
        } else {
            let pair = bytes.get(pos..pos + 2);
            if matches!(
                pair,
                Some(b"->" | b"==" | b"!=" | b"<=" | b">=" | b"&&" | b"||")
            ) {
                pos += 2;
            } else if b"(){}:;,+-*/%=!<>".contains(&byte) {
                pos += 1;
            } else {
                return Err(CompileError::new(offset, "unsupported source character"));
            }
            TokenKind::Symbol(&source[offset..pos])
        };
        tokens.push(Token { kind, offset });
    }
    tokens.push(Token {
        kind: TokenKind::End,
        offset: source.len(),
    });
    Ok(tokens)
}

#[derive(Clone, Copy)]
struct Value {
    register: usize,
    ty: Type,
}
#[derive(Clone, Copy)]
struct Binding {
    local: usize,
    ty: Type,
    mutable: bool,
}
struct Parser<'a> {
    tokens: Vec<Token<'a>>,
    pos: usize,
    instructions: Vec<Step>,
    registers: usize,
    locals: usize,
    scopes: Vec<BTreeMap<&'a str, Binding>>,
    keys: BTreeMap<Vec<u8>, usize>,
    context: bool,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Token<'a> {
        self.tokens[self.pos]
    }
    fn error(&self, msg: &str) -> CompileError {
        CompileError::new(self.peek().offset, msg)
    }
    fn has(&self, text: &str) -> bool {
        matches!(self.peek().kind,TokenKind::Word(s)|TokenKind::Symbol(s) if s==text)
    }
    fn take(&mut self, text: &str) -> bool {
        if self.has(text) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, text: &str) -> Result<(), CompileError> {
        if self.take(text) {
            Ok(())
        } else {
            Err(self.error("unexpected token or unsupported syntax"))
        }
    }
    fn emit(&mut self, step: Step) -> Result<usize, CompileError> {
        if self.instructions.len() >= MAX_INSTRUCTIONS {
            return Err(self.error("instruction limit exceeded"));
        }
        let index = self.instructions.len();
        self.instructions.push(step);
        Ok(index)
    }
    fn register(&mut self, ty: Type) -> Result<Value, CompileError> {
        if self.registers >= MAX_INSTRUCTIONS {
            return Err(self.error("instruction limit exceeded"));
        }
        let value = Value {
            register: self.registers,
            ty,
        };
        self.registers += 1;
        Ok(value)
    }
    fn typed(&self, value: Value, ty: Type) -> Result<Value, CompileError> {
        if value.ty == ty {
            Ok(value)
        } else {
            Err(self.error("incompatible value type"))
        }
    }
    fn binding_for(&self, name: &str) -> Option<Binding> {
        self.scopes.iter().rev().find_map(|s| s.get(name).copied())
    }
    fn key(&mut self) -> Result<usize, CompileError> {
        let TokenKind::Key(key) = self.peek().kind else {
            return Err(self.error("literal state key required"));
        };
        self.pos += 1;
        self.context = true;
        if let Some(index) = self.keys.get(key.as_bytes()) {
            return Ok(*index);
        }
        if self.keys.len() >= MAX_STATE_KEYS {
            return Err(self.error("state key count limit exceeded"));
        }
        let index = self.keys.len();
        self.keys.insert(key.as_bytes().to_vec(), index);
        Ok(index)
    }
    fn block(&mut self, depth: usize) -> Result<bool, CompileError> {
        if depth >= MAX_NESTING {
            return Err(self.error("statement nesting limit exceeded"));
        }
        self.expect("{")?;
        self.scopes.push(BTreeMap::new());
        let mut returns = false;
        while !self.has("}") {
            if self.peek().kind == TokenKind::End {
                return Err(self.error("closing brace expected"));
            }
            if returns {
                return Err(self.error("unreachable statement after unconditional return"));
            }
            returns = self.statement(depth)?;
        }
        self.expect("}")?;
        self.scopes.pop();
        Ok(returns)
    }
    fn statement(&mut self, depth: usize) -> Result<bool, CompileError> {
        if self.take("let") {
            return self.local_statement();
        }
        if self.take("return") {
            let value = self.expression(0, 0)?;
            self.typed(value, Type::U64)?;
            self.expect(";")?;
            self.emit(Step::Return(value.register))?;
            return Ok(true);
        }
        if self.take("if") {
            return self.if_statement(depth);
        }
        if self.take("while") {
            return self.while_statement(depth);
        }
        if self.has("state_set")
            || self.has("state_delete")
            || self.has("emit")
            || self.has("state_set_at")
            || self.has("state_delete_at")
        {
            let TokenKind::Word(name) = self.peek().kind else {
                unreachable!()
            };
            self.pos += 1;
            self.expect("(")?;
            if name == "emit" {
                let topic = self.expression(0, 0)?;
                self.typed(topic, Type::U64)?;
                self.expect(",")?;
                let data = self.expression(0, 0)?;
                self.typed(data, Type::U64)?;
                self.expect(")")?;
                self.expect(";")?;
                self.context = true;
                self.emit(Step::Emit {
                    topic: topic.register,
                    data: data.register,
                })?;
            } else if name.ends_with("_at") {
                self.context = true;
                let key = self.expression(0, 0)?;
                self.typed(key, Type::U64)?;
                let step = if name == "state_set_at" {
                    self.expect(",")?;
                    let value = self.expression(0, 0)?;
                    self.typed(value, Type::U64)?;
                    Step::SetAt {
                        key: key.register,
                        source: value.register,
                    }
                } else {
                    Step::DeleteAt { key: key.register }
                };
                self.expect(")")?;
                self.expect(";")?;
                self.emit(step)?;
            } else {
                let key = self.key()?;
                if name == "state_set" {
                    self.expect(",")?;
                    let value = self.expression(0, 0)?;
                    self.typed(value, Type::U64)?;
                    self.expect(")")?;
                    self.expect(";")?;
                    self.emit(Step::Set {
                        key,
                        source: value.register,
                    })?;
                } else {
                    self.expect(")")?;
                    self.expect(";")?;
                    self.emit(Step::Delete { key })?;
                }
            }
            return Ok(false);
        }
        let TokenKind::Word(name) = self.peek().kind else {
            return Err(self.error("statement expected"));
        };
        let binding = self
            .binding_for(name)
            .ok_or_else(|| self.error("undefined assignment target"))?;
        if !binding.mutable {
            return Err(self.error("assignment requires let mut"));
        }
        self.pos += 1;
        self.expect("=")?;
        let value = self.expression(0, 0)?;
        self.typed(value, binding.ty)?;
        self.expect(";")?;
        self.emit(Step::Store {
            local: binding.local,
            source: value.register,
            charge: true,
        })?;
        Ok(false)
    }
    fn local_statement(&mut self) -> Result<bool, CompileError> {
        let mutable = self.take("mut");
        let TokenKind::Word(name) = self.peek().kind else {
            return Err(self.error("local identifier expected"));
        };
        if matches!(
            name,
            "input"
                | "fn"
                | "call"
                | "let"
                | "mut"
                | "return"
                | "u64"
                | "bool"
                | "true"
                | "false"
                | "if"
                | "else"
                | "while"
                | "unsafe"
                | "extern"
                | "import"
                | "state_get"
                | "state_set"
                | "state_delete"
                | "emit"
                | "height"
                | "caller"
                | "key_count"
                | "key_word"
                | "state_get_at"
                | "state_set_at"
                | "state_delete_at"
        ) {
            return Err(self.error("reserved local identifier"));
        }
        if self.scopes.last().is_some_and(|s| s.contains_key(name)) {
            return Err(self.error("local cannot be redefined in its scope"));
        }
        if self.locals >= MAX_LOCALS {
            return Err(self.error("local binding limit exceeded"));
        }
        self.pos += 1;
        let declared = if self.take(":") {
            Some(if self.take("u64") {
                Type::U64
            } else if self.take("bool") {
                Type::Bool
            } else {
                return Err(self.error("only u64 and bool locals are supported"));
            })
        } else {
            None
        };
        self.expect("=")?;
        let value = self.expression(0, 0)?;
        if let Some(ty) = declared {
            self.typed(value, ty)?;
        }
        self.expect(";")?;
        let local = self.locals;
        self.locals += 1;
        self.emit(Step::Store {
            local,
            source: value.register,
            charge: false,
        })?;
        self.scopes.last_mut().expect("body scope exists").insert(
            name,
            Binding {
                local,
                ty: value.ty,
                mutable,
            },
        );
        Ok(false)
    }
    fn if_statement(&mut self, depth: usize) -> Result<bool, CompileError> {
        let condition = self.expression(0, 0)?;
        self.typed(condition, Type::Bool)?;
        let branch = self.emit(Step::Branch {
            condition: condition.register,
            yes: 0,
            no: 0,
        })?;
        let yes = self.instructions.len();
        let yes_returns = self.block(depth + 1)?;
        let skip = if yes_returns {
            None
        } else {
            Some(self.emit(Step::Jump(0))?)
        };
        let no = self.instructions.len();
        let no_returns = if self.take("else") {
            self.block(depth + 1)?
        } else {
            false
        };
        let after = self.instructions.len();
        self.instructions[branch] = Step::Branch {
            condition: condition.register,
            yes,
            no,
        };
        if let Some(skip) = skip {
            self.instructions[skip] = Step::Jump(after);
        }
        Ok(yes_returns && no_returns)
    }
    fn while_statement(&mut self, depth: usize) -> Result<bool, CompileError> {
        let start = self.instructions.len();
        let condition = self.expression(0, 0)?;
        self.typed(condition, Type::Bool)?;
        let branch = self.emit(Step::Branch {
            condition: condition.register,
            yes: 0,
            no: 0,
        })?;
        let yes = self.instructions.len();
        let body_returns = self.block(depth + 1)?;
        if !body_returns {
            self.emit(Step::Jump(start))?;
        }
        let no = self.instructions.len();
        self.instructions[branch] = Step::Branch {
            condition: condition.register,
            yes,
            no,
        };
        Ok(false)
    }
    fn expression(&mut self, minimum: u8, depth: usize) -> Result<Value, CompileError> {
        if depth >= MAX_NESTING {
            return Err(self.error("expression nesting limit exceeded"));
        }
        let mut left = self.atom(depth)?;
        while let TokenKind::Symbol(operator) = self.peek().kind {
            let precedence = match operator {
                "||" => 1,
                "&&" => 2,
                "==" | "!=" => 3,
                "<" | "<=" | ">" | ">=" => 4,
                "+" | "-" => 5,
                "*" | "/" | "%" => 6,
                _ => break,
            };
            if precedence < minimum {
                break;
            }
            self.pos += 1;
            if operator == "&&" || operator == "||" {
                self.typed(left, Type::Bool)?;
                let result = self.register(Type::Bool)?;
                self.emit(Step::Move {
                    destination: result.register,
                    source: left.register,
                })?;
                let branch = self.emit(Step::Branch {
                    condition: left.register,
                    yes: 0,
                    no: 0,
                })?;
                let rhs = self.instructions.len();
                let right = self.expression(precedence + 1, depth + 1)?;
                self.typed(right, Type::Bool)?;
                self.emit(Step::Move {
                    destination: result.register,
                    source: right.register,
                })?;
                let after = self.instructions.len();
                self.instructions[branch] = if operator == "&&" {
                    Step::Branch {
                        condition: left.register,
                        yes: rhs,
                        no: after,
                    }
                } else {
                    Step::Branch {
                        condition: left.register,
                        yes: after,
                        no: rhs,
                    }
                };
                left = result;
                continue;
            }
            let right = self.expression(precedence + 1, depth + 1)?;
            let (binary, ty) = self.binary_type(operator, left, right)?;
            let result = self.register(ty)?;
            self.emit(Step::Binary {
                destination: result.register,
                operator: binary,
                left: left.register,
                right: right.register,
            })?;
            left = result;
        }
        Ok(left)
    }
    fn binary_type(
        &self,
        operator: &str,
        left: Value,
        right: Value,
    ) -> Result<(Binary, Type), CompileError> {
        let result = match operator {
            "==" | "!=" => {
                if left.ty != right.ty {
                    return Err(self.error("comparison operand types differ"));
                }
                (
                    if operator == "==" {
                        Binary::Equal
                    } else {
                        Binary::NotEqual
                    },
                    Type::Bool,
                )
            }
            "<" | "<=" | ">" | ">=" => {
                self.typed(left, Type::U64)?;
                self.typed(right, Type::U64)?;
                (
                    match operator {
                        "<" => Binary::Less,
                        "<=" => Binary::LessEqual,
                        ">" => Binary::Greater,
                        _ => Binary::GreaterEqual,
                    },
                    Type::Bool,
                )
            }
            _ => {
                self.typed(left, Type::U64)?;
                self.typed(right, Type::U64)?;
                (
                    Binary::Arithmetic(match operator {
                        "+" => Operator::Add,
                        "-" => Operator::Subtract,
                        "*" => Operator::Multiply,
                        "/" => Operator::Divide,
                        _ => Operator::Remainder,
                    }),
                    Type::U64,
                )
            }
        };
        Ok(result)
    }
    fn atom(&mut self, depth: usize) -> Result<Value, CompileError> {
        let token = self.peek();
        match token.kind {
            TokenKind::Number(value) => {
                self.pos += 1;
                let result = self.register(Type::U64)?;
                self.emit(Step::Constant {
                    destination: result.register,
                    value,
                })?;
                Ok(result)
            }
            TokenKind::Word("true" | "false") => {
                self.pos += 1;
                let result = self.register(Type::Bool)?;
                self.emit(Step::Constant {
                    destination: result.register,
                    value: u64::from(token.kind == TokenKind::Word("true")),
                })?;
                Ok(result)
            }
            TokenKind::Symbol("!") => {
                self.pos += 1;
                let source = self.expression(7, depth + 1)?;
                self.typed(source, Type::Bool)?;
                let result = self.register(Type::Bool)?;
                self.emit(Step::Not {
                    destination: result.register,
                    source: source.register,
                })?;
                Ok(result)
            }
            TokenKind::Symbol("(") => {
                self.pos += 1;
                let value = self.expression(0, depth + 1)?;
                self.expect(")")?;
                Ok(value)
            }
            TokenKind::Word("input") => {
                self.pos += 1;
                let result = self.register(Type::U64)?;
                self.emit(Step::Input {
                    destination: result.register,
                })?;
                Ok(result)
            }
            TokenKind::Word(
                name @ ("state_get" | "height" | "caller" | "key_count" | "key_word"
                | "state_get_at"),
            ) => self.builtin(name, depth),
            TokenKind::Word(name) => {
                let binding = self
                    .binding_for(name)
                    .ok_or_else(|| self.error("undefined local or unsupported expression"))?;
                self.pos += 1;
                let result = self.register(binding.ty)?;
                self.emit(Step::Load {
                    destination: result.register,
                    local: binding.local,
                })?;
                Ok(result)
            }
            _ => Err(self.error("typed expression expected")),
        }
    }
    fn builtin(&mut self, name: &str, depth: usize) -> Result<Value, CompileError> {
        self.pos += 1;
        self.expect("(")?;
        let result = self.register(Type::U64)?;
        self.context = true;
        let step = match name {
            "state_get" => Step::Get {
                destination: result.register,
                key: self.key()?,
            },
            "height" => Step::Height {
                destination: result.register,
            },
            "key_count" => Step::KeyCount {
                destination: result.register,
            },
            "state_get_at" => {
                let key = self.expression(0, depth + 1)?;
                self.typed(key, Type::U64)?;
                Step::GetAt {
                    destination: result.register,
                    key: key.register,
                }
            }
            "key_word" => {
                let key = self.expression(0, depth + 1)?;
                self.typed(key, Type::U64)?;
                self.expect(",")?;
                let word = self.limb("key word must be a literal 0..3")?;
                Step::KeyWord {
                    destination: result.register,
                    key: key.register,
                    word,
                }
            }
            _ => {
                let index = self.limb("caller index must be a literal 0..3")?;
                Step::Caller {
                    destination: result.register,
                    index,
                }
            }
        };
        self.expect(")")?;
        self.emit(step)?;
        Ok(result)
    }
    fn limb(&mut self, message: &str) -> Result<usize, CompileError> {
        let TokenKind::Number(index) = self.peek().kind else {
            return Err(self.error(message));
        };
        let index = usize::try_from(index).map_err(|_| self.error(message))?;
        if index > 3 {
            return Err(self.error(message));
        }
        self.pos += 1;
        Ok(index)
    }
}

pub(crate) fn parse(source: &str) -> Result<CheckedProgram, CompileError> {
    let mut parser = Parser {
        tokens: lex(source)?,
        pos: 0,
        instructions: Vec::new(),
        registers: 0,
        locals: 0,
        scopes: Vec::new(),
        keys: BTreeMap::new(),
        context: false,
    };
    for token in ["fn", "call", "(", "input", ":", "u64", ")", "->", "u64"] {
        parser.expect(token)?;
    }
    if !parser.block(0)? {
        return Err(parser.error("every function path must return u64"));
    }
    if parser.peek().kind != TokenKind::End {
        return Err(parser.error("trailing source or additional functions are unsupported"));
    }
    let mut mapping = vec![0; parser.keys.len()];
    let mut keys = Vec::new();
    for (key, old) in parser.keys {
        mapping[old] = keys.len();
        keys.push(key);
    }
    for step in &mut parser.instructions {
        match step {
            Step::Get { key, .. } | Step::Set { key, .. } | Step::Delete { key } => {
                *key = mapping[*key];
            }
            _ => {}
        }
    }
    Ok(CheckedProgram {
        instructions: parser.instructions,
        registers: parser.registers,
        locals: parser.locals,
        keys,
        context: parser.context,
    })
}
