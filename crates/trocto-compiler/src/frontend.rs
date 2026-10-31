// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded lexer and expression parser producing a flat instruction sequence.

use std::collections::BTreeMap;

use crate::{
    CompileError, Instruction, MAX_IDENTIFIER_BYTES, MAX_INSTRUCTIONS, MAX_LOCALS, MAX_NESTING,
    MAX_SOURCE_BYTES, MAX_TOKENS, Operator,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind<'a> {
    Word(&'a str),
    Number(u64),
    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
    Colon,
    Semicolon,
    Equal,
    Arrow,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    End,
}

#[derive(Clone, Copy, Debug)]
struct Token<'a> {
    kind: Kind<'a>,
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
    let mut position = 0;
    let mut tokens = Vec::new();
    while position < bytes.len() {
        let offset = position;
        let byte = bytes[position];
        if byte.is_ascii_whitespace() {
            position += 1;
            continue;
        }
        if byte == b'/' && bytes.get(position + 1) == Some(&b'/') {
            position += 2;
            while position < bytes.len() && bytes[position] != b'\n' {
                position += 1;
            }
            continue;
        }
        if tokens.len() >= MAX_TOKENS {
            return Err(CompileError::new(offset, "token limit exceeded"));
        }
        let kind = if byte.is_ascii_alphabetic() || byte == b'_' {
            position += 1;
            while position < bytes.len()
                && (bytes[position].is_ascii_alphanumeric() || bytes[position] == b'_')
            {
                position += 1;
            }
            if position - offset > MAX_IDENTIFIER_BYTES {
                return Err(CompileError::new(offset, "identifier byte limit exceeded"));
            }
            Kind::Word(&source[offset..position])
        } else if byte.is_ascii_digit() {
            position += 1;
            while position < bytes.len() && bytes[position].is_ascii_digit() {
                position += 1;
            }
            Kind::Number(
                source[offset..position]
                    .parse()
                    .map_err(|_| CompileError::new(offset, "integer literal exceeds u64"))?,
            )
        } else {
            position += 1;
            match byte {
                b'(' => Kind::LeftParen,
                b')' => Kind::RightParen,
                b'{' => Kind::LeftBrace,
                b'}' => Kind::RightBrace,
                b':' => Kind::Colon,
                b';' => Kind::Semicolon,
                b'=' => Kind::Equal,
                b'+' => Kind::Plus,
                b'-' if bytes.get(position) == Some(&b'>') => {
                    position += 1;
                    Kind::Arrow
                }
                b'-' => Kind::Minus,
                b'*' => Kind::Star,
                b'/' => Kind::Slash,
                b'%' => Kind::Percent,
                _ => return Err(CompileError::new(offset, "unsupported source character")),
            }
        };
        tokens.push(Token { kind, offset });
    }
    tokens.push(Token {
        kind: Kind::End,
        offset: source.len(),
    });
    Ok(tokens)
}

struct Parser<'a> {
    tokens: Vec<Token<'a>>,
    position: usize,
    locals: BTreeMap<&'a str, usize>,
    instructions: Vec<Instruction>,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Token<'a> {
        self.tokens[self.position]
    }

    fn expect(&mut self, kind: Kind<'a>, message: &str) -> Result<(), CompileError> {
        let token = self.peek();
        if token.kind != kind {
            return Err(CompileError::new(token.offset, message));
        }
        self.position += 1;
        Ok(())
    }

    fn word(&mut self, word: &'a str) -> Result<(), CompileError> {
        self.expect(
            Kind::Word(word),
            "unexpected identifier or unsupported syntax",
        )
    }

    fn emit(&mut self, instruction: Instruction, offset: usize) -> Result<usize, CompileError> {
        if self.instructions.len() >= MAX_INSTRUCTIONS {
            return Err(CompileError::new(offset, "instruction limit exceeded"));
        }
        let index = self.instructions.len();
        self.instructions.push(instruction);
        Ok(index)
    }

    fn binding(&mut self) -> Result<(), CompileError> {
        self.word("let")?;
        let token = self.peek();
        let Kind::Word(name) = token.kind else {
            return Err(CompileError::new(token.offset, "local identifier expected"));
        };
        if matches!(
            name,
            "input"
                | "fn"
                | "call"
                | "let"
                | "return"
                | "u64"
                | "mut"
                | "unsafe"
                | "import"
                | "extern"
                | "if"
                | "else"
                | "while"
                | "for"
                | "loop"
        ) {
            return Err(CompileError::new(token.offset, "reserved local identifier"));
        }
        if self.locals.contains_key(name) {
            return Err(CompileError::new(
                token.offset,
                "immutable local cannot be redefined",
            ));
        }
        if self.locals.len() >= MAX_LOCALS {
            return Err(CompileError::new(
                token.offset,
                "local binding limit exceeded",
            ));
        }
        self.position += 1;
        if self.peek().kind == Kind::Colon {
            self.position += 1;
            self.word("u64")?;
        }
        self.expect(Kind::Equal, "local initializer expected")?;
        // The binding is unavailable while its initializer is being checked.
        let value = self.expression(0, 0)?;
        self.expect(
            Kind::Semicolon,
            "semicolon required after local initializer",
        )?;
        self.locals.insert(name, value);
        Ok(())
    }

    fn expression(&mut self, minimum: u8, depth: usize) -> Result<usize, CompileError> {
        if depth >= MAX_NESTING {
            return Err(CompileError::new(
                self.peek().offset,
                "expression nesting limit exceeded",
            ));
        }
        let mut left = self.atom(depth)?;
        loop {
            let token = self.peek();
            let (operator, precedence) = match token.kind {
                Kind::Plus => (Operator::Add, 1),
                Kind::Minus => (Operator::Subtract, 1),
                Kind::Star => (Operator::Multiply, 2),
                Kind::Slash => (Operator::Divide, 2),
                Kind::Percent => (Operator::Remainder, 2),
                _ => break,
            };
            if precedence < minimum {
                break;
            }
            self.position += 1;
            let right = self.expression(precedence + 1, depth + 1)?;
            left = self.emit(
                Instruction::Binary {
                    operator,
                    left,
                    right,
                },
                token.offset,
            )?;
        }
        Ok(left)
    }

    fn atom(&mut self, depth: usize) -> Result<usize, CompileError> {
        let token = self.peek();
        match token.kind {
            Kind::Number(value) => {
                self.position += 1;
                self.emit(Instruction::Constant(value), token.offset)
            }
            Kind::Word("input") => {
                self.position += 1;
                self.emit(Instruction::Input, token.offset)
            }
            Kind::Word(name) => {
                let value = self.locals.get(name).copied().ok_or_else(|| {
                    CompileError::new(token.offset, "undefined local or unsupported expression")
                })?;
                self.position += 1;
                self.emit(Instruction::Copy(value), token.offset)
            }
            Kind::LeftParen => {
                self.position += 1;
                let value = self.expression(0, depth + 1)?;
                self.expect(Kind::RightParen, "closing parenthesis expected")?;
                Ok(value)
            }
            _ => Err(CompileError::new(token.offset, "u64 expression expected")),
        }
    }
}

pub(crate) fn parse(source: &str) -> Result<(Vec<Instruction>, usize), CompileError> {
    let mut parser = Parser {
        tokens: lex(source)?,
        position: 0,
        locals: BTreeMap::new(),
        instructions: Vec::new(),
    };
    parser.word("fn")?;
    parser.word("call")?;
    parser.expect(Kind::LeftParen, "call parameter list expected")?;
    parser.word("input")?;
    parser.expect(Kind::Colon, "call input type expected")?;
    parser.word("u64")?;
    parser.expect(Kind::RightParen, "exactly one input parameter is required")?;
    parser.expect(Kind::Arrow, "call return type expected")?;
    parser.word("u64")?;
    parser.expect(Kind::LeftBrace, "call body expected")?;
    while parser.peek().kind == Kind::Word("let") {
        parser.binding()?;
    }
    parser.word("return")?;
    let result = parser.expression(0, 0)?;
    parser.expect(Kind::Semicolon, "semicolon required after return value")?;
    parser.expect(
        Kind::RightBrace,
        "only immutable locals and one return are supported",
    )?;
    parser.expect(
        Kind::End,
        "trailing source or additional functions are unsupported",
    )?;
    Ok((parser.instructions, result))
}
