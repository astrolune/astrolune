// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! The shared parser must reject ambiguous or unbounded network input.

use rpc::json::{JsonValue, parse_json, to_json};

#[test]
fn bounds_nesting_and_rejects_duplicate_keys_at_every_depth() {
    assert!(parse_json(&format!("{}0{}", "[".repeat(31), "]".repeat(31))).is_ok());
    assert!(parse_json(&format!("{}0{}", "[".repeat(32), "]".repeat(32))).is_err());
    assert!(parse_json(&"[".repeat(100_000)).is_err());
    for value in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":{"b":1,"b":2}}"#,
        r#"{"a":1,"\u0061":2}"#,
    ] {
        assert!(parse_json(value).is_err());
    }
}

#[test]
fn strictly_decodes_json_strings_numbers_and_whitespace() {
    for value in [
        "01",
        "-01",
        "1.",
        "+1",
        "-",
        "1e2",
        "\x0c0",
        "\"raw\nnewline\"",
        r#""\ud800""#,
        r#""\udc00""#,
        r#""\ud800\u0041""#,
        r#""\u00zz""#,
        r#""\u+041""#,
    ] {
        assert!(parse_json(value).is_err(), "{value:?}");
    }
    assert_eq!(
        parse_json(r#""\ud83c\udf19""#).unwrap(),
        JsonValue::String("🌙".into())
    );
    let value = JsonValue::String("\x00\n🌙é".into());
    assert_eq!(parse_json(&to_json(&value)).unwrap(), value);
}
