// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Minimal JSON serialization and JSON-RPC message types.
//!
//! This module provides a lightweight JSON parser and serializer that avoids
//! external dependencies. It handles the subset of JSON needed for RPC
//! communication: objects, arrays, strings, numbers, booleans, and null.

use std::fmt::{self, Write};
use types::{Address, Hash256};

/// A JSON value represented as a tree of owned strings and primitives.
///
/// This is a simplified JSON representation sufficient for RPC messages.
/// It supports Unicode escapes and surrogate pairs, but not floating-point numbers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonValue {
    /// JSON null.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// JSON integer (stored as i64).
    Number(i64),
    /// JSON string.
    String(String),
    /// JSON array.
    Array(Vec<JsonValue>),
    /// JSON object with string keys.
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Returns the value as a string reference, if it is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the value as an i64, if it is a number.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Returns the value as a bool, if it is a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the value as an array reference, if it is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Returns a field value from an object, if this value is an object
    /// and the key exists.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            Self::Object(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// A JSON parsing error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonError {
    /// Description of the parsing failure.
    message: String,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JSON parse error: {}", self.message)
    }
}

impl std::error::Error for JsonError {}

/// A simple recursive-descent JSON parser.
struct Parser {
    input: Vec<char>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            pos: 0,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.input.get(self.pos).copied();
        if ch.is_some() {
            self.pos += 1;
        }
        ch
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek() {
            if matches!(ch, ' ' | '\t' | '\n' | '\r') {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), JsonError> {
        match self.advance() {
            Some(ch) if ch == expected => Ok(()),
            Some(ch) => Err(JsonError {
                message: format!("expected '{expected}', found '{ch}'"),
            }),
            None => Err(JsonError {
                message: format!("expected '{expected}', found end of input"),
            }),
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, JsonError> {
        self.skip_whitespace();
        if self.depth >= 32 {
            return Err(JsonError {
                message: "JSON nesting limit exceeded".into(),
            });
        }
        self.depth += 1;
        let result = match self.peek() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('t' | 'f') => self.parse_bool(),
            Some('n') => self.parse_null(),
            Some(ch) if ch.is_ascii_digit() || ch == '-' => self.parse_number(),
            Some(ch) => Err(JsonError {
                message: format!("unexpected character '{ch}'"),
            }),
            None => Err(JsonError {
                message: "unexpected end of input".into(),
            }),
        };
        self.depth -= 1;
        result
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonError> {
        self.expect('{')?;
        self.skip_whitespace();
        let mut fields = Vec::new();
        let mut keys = std::collections::BTreeSet::new();

        if self.peek() == Some('}') {
            self.advance();
            return Ok(JsonValue::Object(fields));
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            if !keys.insert(key.clone()) {
                return Err(JsonError {
                    message: "duplicate object key".into(),
                });
            }
            self.skip_whitespace();
            self.expect(':')?;
            let value = self.parse_value()?;
            fields.push((key, value));
            self.skip_whitespace();
            match self.advance() {
                Some(',') => {}
                Some('}') => break,
                other => {
                    return Err(JsonError {
                        message: format!("expected ',' or '}}', got {other:?}"),
                    });
                }
            }
        }

        Ok(JsonValue::Object(fields))
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonError> {
        self.expect('[')?;
        self.skip_whitespace();
        let mut items = Vec::new();

        if self.peek() == Some(']') {
            self.advance();
            return Ok(JsonValue::Array(items));
        }

        loop {
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.advance() {
                Some(',') => {}
                Some(']') => break,
                other => {
                    return Err(JsonError {
                        message: format!("expected ',' or ']', got {other:?}"),
                    });
                }
            }
        }

        Ok(JsonValue::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.expect('"')?;
        let mut result = String::new();
        loop {
            match self.advance() {
                Some('"') => return Ok(result),
                Some('\\') => match self.advance() {
                    Some('"') => result.push('"'),
                    Some('\\') => result.push('\\'),
                    Some('/') => result.push('/'),
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('b') => result.push('\x08'),
                    Some('f') => result.push('\x0C'),
                    Some('u') => {
                        // Parse 4 hex digits as a Unicode code point
                        let mut hex = String::new();
                        for _ in 0..4 {
                            hex.push(self.advance().ok_or(JsonError {
                                message: "incomplete unicode escape".into(),
                            })?);
                        }
                        if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                            return Err(JsonError {
                                message: "invalid unicode escape".into(),
                            });
                        }
                        let code_point = u32::from_str_radix(&hex, 16).map_err(|e| JsonError {
                            message: format!("invalid unicode escape: {e}"),
                        })?;
                        let code_point = if (0xD800..=0xDBFF).contains(&code_point) {
                            self.expect('\\')?;
                            self.expect('u')?;
                            let mut low = String::new();
                            for _ in 0..4 {
                                low.push(self.advance().ok_or(JsonError {
                                    message: "incomplete surrogate pair".into(),
                                })?);
                            }
                            if !low.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                                return Err(JsonError {
                                    message: "invalid surrogate pair".into(),
                                });
                            }
                            let low = u32::from_str_radix(&low, 16).map_err(|_| JsonError {
                                message: "invalid surrogate pair".into(),
                            })?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(JsonError {
                                    message: "invalid surrogate pair".into(),
                                });
                            }
                            0x10000 + ((code_point - 0xD800) << 10) + low - 0xDC00
                        } else {
                            code_point
                        };
                        result.push(char::from_u32(code_point).ok_or(JsonError {
                            message: "invalid Unicode scalar".into(),
                        })?);
                    }
                    Some(ch) => {
                        return Err(JsonError {
                            message: format!("invalid escape character '\\{ch}'"),
                        });
                    }
                    None => {
                        return Err(JsonError {
                            message: "unexpected end of string escape".into(),
                        });
                    }
                },
                Some(ch) if ch < '\u{0020}' => {
                    return Err(JsonError {
                        message: "unescaped control character".into(),
                    });
                }
                Some(ch) => result.push(ch),
                None => {
                    return Err(JsonError {
                        message: "unterminated string".into(),
                    });
                }
            }
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, JsonError> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.advance();
        }
        let digits_start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.advance();
        }
        if self.pos > digits_start + 1 && self.input[digits_start] == '0' {
            return Err(JsonError {
                message: "leading zero in number".into(),
            });
        }
        let s: String = self.input[start..self.pos].iter().collect();
        let n: i64 = s.parse().map_err(|_| JsonError {
            message: format!("invalid number: {s}"),
        })?;
        Ok(JsonValue::Number(n))
    }

    fn parse_bool(&mut self) -> Result<JsonValue, JsonError> {
        if self.input[self.pos..].starts_with(&['t', 'r', 'u', 'e']) {
            self.pos += 4;
            Ok(JsonValue::Bool(true))
        } else if self.input[self.pos..].starts_with(&['f', 'a', 'l', 's', 'e']) {
            self.pos += 5;
            Ok(JsonValue::Bool(false))
        } else {
            Err(JsonError {
                message: "invalid boolean".into(),
            })
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, JsonError> {
        if self.input[self.pos..].starts_with(&['n', 'u', 'l', 'l']) {
            self.pos += 4;
            Ok(JsonValue::Null)
        } else {
            Err(JsonError {
                message: "invalid null".into(),
            })
        }
    }
}

/// Parses a JSON string into a `JsonValue`.
///
/// # Errors
///
/// Returns `JsonError` if the input is malformed JSON.
pub fn parse_json(input: &str) -> Result<JsonValue, JsonError> {
    let mut parser = Parser::new(input);
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.pos != parser.input.len() {
        return Err(JsonError {
            message: "trailing characters after JSON value".into(),
        });
    }
    Ok(value)
}

/// Serializes a `JsonValue` into a JSON string.
///
/// Produces compact, single-line JSON output without indentation.
pub fn to_json(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".into(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::String(s) => {
            let mut out = String::from('"');
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c.is_control() => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
        JsonValue::Array(items) => {
            let inner: Vec<String> = items.iter().map(to_json).collect();
            format!("[{}]", inner.join(","))
        }
        JsonValue::Object(fields) => {
            let inner: Vec<String> = fields
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", escape_json_key(k), to_json(v)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}

/// Escapes a string for use as a JSON object key.
fn escape_json_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// A JSON-RPC 2.0 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonRpcRequest {
    /// Request identifier for matching responses.
    pub id: i64,
    /// Method name to invoke.
    pub method: String,
    /// Parameters as a JSON value.
    pub params: JsonValue,
}

/// A JSON-RPC 2.0 response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonRpcResponse {
    /// Matching request identifier.
    pub id: i64,
    /// Result value on success.
    pub result: Option<JsonValue>,
    /// Error object on failure.
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonRpcError {
    /// Numeric error code.
    pub code: i64,
    /// Human-readable error message.
    pub message: String,
    /// Optional additional error data.
    pub data: Option<JsonValue>,
}

/// Parses a JSON-RPC request from a JSON string.
///
/// # Errors
///
/// Returns `JsonError` if the input is not valid JSON or does not match
/// the JSON-RPC 2.0 request format.
pub fn parse_rpc_request(input: &str) -> Result<JsonRpcRequest, JsonError> {
    let value = parse_json(input)?;
    let JsonValue::Object(obj) = &value else {
        return Err(JsonError {
            message: "request must be a JSON object".into(),
        });
    };

    let id = obj
        .iter()
        .find(|(k, _)| k == "id")
        .and_then(|(_, v)| v.as_i64())
        .unwrap_or(1);

    let method = obj
        .iter()
        .find(|(k, _)| k == "method")
        .and_then(|(_, v)| v.as_str())
        .ok_or_else(|| JsonError {
            message: "missing 'method' field".into(),
        })?
        .to_owned();

    let params = obj
        .iter()
        .find(|(k, _)| k == "params")
        .map_or(JsonValue::Object(Vec::new()), |(_, v)| v.clone());

    Ok(JsonRpcRequest { id, method, params })
}

/// Serializes a JSON-RPC response into a JSON string.
#[must_use]
pub fn serialize_rpc_response(response: &JsonRpcResponse) -> String {
    let mut fields = Vec::new();
    fields.push(("jsonrpc".into(), JsonValue::String("2.0".into())));
    fields.push(("id".into(), JsonValue::Number(response.id)));

    if let Some(ref result) = response.result {
        fields.push(("result".into(), result.clone()));
    }

    if let Some(ref error) = response.error {
        let mut err_fields = Vec::new();
        err_fields.push(("code".into(), JsonValue::Number(error.code)));
        err_fields.push(("message".into(), JsonValue::String(error.message.clone())));
        if let Some(ref data) = error.data {
            err_fields.push(("data".into(), data.clone()));
        }
        fields.push(("error".into(), JsonValue::Object(err_fields)));
    }

    to_json(&JsonValue::Object(fields))
}

/// Builds a JSON-RPC success response.
#[must_use]
pub fn rpc_success(id: i64, result: JsonValue) -> JsonRpcResponse {
    JsonRpcResponse {
        id,
        result: Some(result),
        error: None,
    }
}

/// Builds a JSON-RPC error response.
#[must_use]
pub fn rpc_error(id: i64, code: i64, message: impl Into<String>) -> JsonRpcResponse {
    JsonRpcResponse {
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
            data: None,
        }),
    }
}

/// Creates a hex string from a `Hash256`.
#[must_use]
pub fn hash_to_hex(hash: Hash256) -> String {
    let mut out = String::with_capacity(64);
    for byte in hash.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Creates a hex string from an `Address`.
#[must_use]
pub fn address_to_hex(addr: Address) -> String {
    let mut out = String::with_capacity(64);
    for byte in addr.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_serialize_null() {
        let v = parse_json("null").unwrap();
        assert_eq!(v, JsonValue::Null);
        assert_eq!(to_json(&v), "null");
    }

    #[test]
    fn parse_and_serialize_bool() {
        let t = parse_json("true").unwrap();
        assert_eq!(t, JsonValue::Bool(true));
        let f = parse_json("false").unwrap();
        assert_eq!(f, JsonValue::Bool(false));
    }

    #[test]
    fn parse_and_serialize_number() {
        let n = parse_json("42").unwrap();
        assert_eq!(n, JsonValue::Number(42));
        let neg = parse_json("-7").unwrap();
        assert_eq!(neg, JsonValue::Number(-7));
    }

    #[test]
    fn parse_and_serialize_string() {
        let s = parse_json("\"hello world\"").unwrap();
        assert_eq!(s, JsonValue::String("hello world".into()));
        assert_eq!(to_json(&s), "\"hello world\"");
    }

    #[test]
    fn parse_string_escaping() {
        let s = parse_json("\"line1\\nline2\"").unwrap();
        assert_eq!(s, JsonValue::String("line1\nline2".into()));
    }

    #[test]
    fn parse_array() {
        let a = parse_json("[1, 2, 3]").unwrap();
        let arr = a.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], JsonValue::Number(1));
    }

    #[test]
    fn parse_nested_object() {
        let input = r#"{"name":"test","value":42,"active":true}"#;
        let obj = parse_json(input).unwrap();
        assert_eq!(obj.get("name"), Some(&JsonValue::String("test".into())));
        assert_eq!(obj.get("value"), Some(&JsonValue::Number(42)));
        assert_eq!(obj.get("active"), Some(&JsonValue::Bool(true)));
    }

    #[test]
    fn rpc_request_parse() {
        let input = r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#;
        let req = parse_rpc_request(input).unwrap();
        assert_eq!(req.id, 1);
        assert_eq!(req.method, "eth_chainId");
    }

    #[test]
    fn rpc_response_serialize() {
        let resp = rpc_success(1, JsonValue::Number(7));
        let json = serialize_rpc_response(&resp);
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"result\":7"));
    }

    #[test]
    fn rpc_error_response_serialize() {
        let resp = rpc_error(1, -32600, "invalid request");
        let json = serialize_rpc_response(&resp);
        assert!(json.contains("\"code\":-32600"));
        assert!(json.contains("\"message\":\"invalid request\""));
    }

    #[test]
    fn hash_to_hex_format() {
        let hash = Hash256([0xAB; 32]);
        let hex = hash_to_hex(hash);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn address_to_hex_format() {
        let addr = Address([0xCD; 32]);
        let hex = address_to_hex(addr);
        assert_eq!(hex.len(), 64);
    }
}
