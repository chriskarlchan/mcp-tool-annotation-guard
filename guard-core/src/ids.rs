// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Request IDs kept as raw JSON tokens and compared by type and exact token.
//!
//! An [`Id`] keeps the token exactly as the client sent it, so it can be echoed
//! byte for byte (integers beyond 64 bits survive). Comparison is by type
//! first, so `7` never equals `"7"`.
//!
//! Two spellings are treated as the same ID because every JSON parser reads
//! them as the same value: a string with escapes (`"\u0061"`) equals its
//! decoded form (`"a"`), and `-0` equals `0`. Matching more spellings is the
//! safe direction for both uses of IDs: duplicate detection in batches finds
//! more duplicates, and list responses re-serialised by the server are still
//! recognised.
//!
//! [`may_answer`] is looser still, for the one place where a missed match is
//! the unsafe direction: finding responses a client could read that the guard
//! does not filter.

use std::hash::{Hash, Hasher};

/// A valid JSON-RPC request ID: a JSON string or an integer.
#[derive(Clone, Debug)]
pub struct Id {
    /// The token exactly as received (for strings: with quotes and escapes).
    raw: String,
    key: Key,
}

/// What two IDs are compared by.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key {
    /// Decoded string value.
    Str(String),
    /// Integer digits with an optional `-`; `-0` is stored as `0`.
    Int(String),
}

/// The outcome of reading an `id` member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdToken {
    /// A string or an integer.
    Valid(Id),
    /// JSON `null` (allowed only on error responses).
    Null,
    /// A boolean, fraction, exponent, object or array.
    Invalid,
}

impl Id {
    /// Reads a raw JSON value (already validated as JSON) as an ID.
    pub fn from_raw(raw: &str) -> IdToken {
        let token = raw.trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r'));
        match token.as_bytes().first() {
            Some(b'"') => match serde_json::from_str::<String>(token) {
                Ok(decoded) => IdToken::Valid(Id {
                    raw: token.to_owned(),
                    key: Key::Str(decoded),
                }),
                Err(_) => IdToken::Invalid,
            },
            Some(b'-' | b'0'..=b'9') => match integer_key(token) {
                Some(key) => IdToken::Valid(Id {
                    raw: token.to_owned(),
                    key: Key::Int(key),
                }),
                None => IdToken::Invalid,
            },
            _ if token == "null" => IdToken::Null,
            _ => IdToken::Invalid,
        }
    }

    /// The token exactly as received, for echoing in replies.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The finite number a JavaScript client converts this ID to with
    /// `Number(id)`, if any.
    fn number(&self) -> Option<f64> {
        match &self.key {
            Key::Int(digits) => digits.parse::<f64>().ok().filter(|n| n.is_finite()),
            Key::Str(text) => js_number(text),
        }
    }
}

/// Whether some client could take a message whose `id` is the raw JSON value
/// `raw` for a response to one of `expected`: the same ID, or a string or
/// number that converts to the same number. The MCP TypeScript SDK, for
/// example, looks responses up by `Number(id)`, so `"1"`, `1.0`, `1e0` and
/// `"0x1"` all answer the request with ID `1`.
pub fn may_answer(raw: &str, expected: &[Id]) -> bool {
    let number = match Id::from_raw(raw) {
        IdToken::Valid(id) if expected.contains(&id) => return true,
        IdToken::Valid(id) => id.number(),
        IdToken::Invalid => json_number(raw),
        IdToken::Null => None,
    };
    number.is_some_and(|n| expected.iter().any(|id| id.number() == Some(n)))
}

/// A JSON number token (fraction or exponent allowed) as a finite number.
fn json_number(raw: &str) -> Option<f64> {
    let token = raw.trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r'));
    match token.as_bytes().first() {
        Some(b'-' | b'0'..=b'9') => serde_json::from_str::<f64>(token)
            .ok()
            .filter(|n| n.is_finite()),
        _ => None,
    }
}

/// JavaScript's `Number(text)`, when the result is finite: surrounding white
/// space removed, empty is 0, `0x`/`0o`/`0b` prefixes, then a decimal literal.
/// White space is taken broadly, which can only match more IDs.
fn js_number(text: &str) -> Option<f64> {
    let text = text.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if text.is_empty() {
        return Some(0.0);
    }
    let radix = match text.get(..2) {
        Some("0x" | "0X") => Some(16),
        Some("0o" | "0O") => Some(8),
        Some("0b" | "0B") => Some(2),
        _ => None,
    };
    if let Some(radix) = radix {
        let digits = text.get(2..).filter(|d| !d.is_empty())?;
        let mut value = 0.0_f64;
        for c in digits.chars() {
            value = value * f64::from(radix) + f64::from(c.to_digit(radix)?);
        }
        return Some(value).filter(|n| n.is_finite());
    }
    if !text
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'))
    {
        return None;
    }
    text.parse::<f64>().ok().filter(|n| n.is_finite())
}

/// Returns the comparison key for a JSON integer token, or `None` if the
/// number has a fraction or an exponent.
fn integer_key(token: &str) -> Option<String> {
    let digits = token.strip_prefix('-').unwrap_or(token);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // JSON forbids leading zeros, so `-0` is the only other spelling of a value.
    if digits == "0" {
        return Some("0".to_owned());
    }
    Some(token.to_owned())
}

impl PartialEq for Id {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for Id {}

impl Hash for Id {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(raw: &str) -> Id {
        match Id::from_raw(raw) {
            IdToken::Valid(id) => id,
            other => unreachable!("{raw} should be a valid id, got {other:?}"),
        }
    }

    #[test]
    fn strings_and_integers_are_valid() {
        assert_eq!(valid(r#""abc""#).raw(), r#""abc""#);
        assert_eq!(valid("7").raw(), "7");
        assert_eq!(valid("-12").raw(), "-12");
        assert_eq!(valid("0").raw(), "0");
    }

    #[test]
    fn integer_and_string_never_compare_equal() {
        assert_ne!(valid("7"), valid(r#""7""#));
    }

    #[test]
    fn null_is_reported_separately() {
        assert_eq!(Id::from_raw("null"), IdToken::Null);
    }

    #[test]
    fn booleans_fractions_exponents_and_containers_are_invalid() {
        for raw in [
            "true",
            "false",
            "1.5",
            "1e3",
            "1E3",
            "-2.0",
            "1.0e2",
            "{}",
            "[]",
            "[1]",
            r#"{"a":1}"#,
        ] {
            assert_eq!(Id::from_raw(raw), IdToken::Invalid, "{raw}");
        }
    }

    #[test]
    fn integers_beyond_64_bits_are_kept_exactly() {
        let big = "123456789012345678901234567890";
        assert_eq!(valid(big).raw(), big);
        assert_ne!(valid(big), valid("123456789012345678901234567891"));
        let negative = "-98765432109876543210987654321";
        assert_eq!(valid(negative).raw(), negative);
    }

    #[test]
    fn escaped_strings_keep_their_raw_token_but_compare_by_value() {
        let escaped = valid(r#""a\u0062""#);
        assert_eq!(escaped.raw(), r#""a\u0062""#);
        assert_eq!(escaped, valid(r#""ab""#));
    }

    #[test]
    fn minus_zero_equals_zero() {
        assert_eq!(valid("-0"), valid("0"));
        assert_eq!(valid("-0").raw(), "-0");
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        assert_eq!(valid(" 7\n").raw(), "7");
    }

    #[test]
    fn hashing_follows_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        assert!(set.insert(valid(r#""a""#)));
        assert!(!set.insert(valid(r#""\u0061""#)));
        assert!(set.insert(valid("1")));
        assert!(!set.insert(valid("1")));
        assert!(set.insert(valid(r#""1""#)));
    }

    #[test]
    fn ids_a_client_converts_to_the_same_number_may_answer() {
        let one = [valid("1")];
        for raw in [
            "1", r#""1""#, "1.0", "1e0", "10e-1", r#""0x1""#, r#""0b1""#, r#""0o1""#, r#"" 1 ""#,
            r#""+1""#, r#""1.""#,
        ] {
            assert!(may_answer(raw, &one), "{raw}");
        }
        for raw in [
            "2",
            r#""2""#,
            "1.5",
            r#""1a""#,
            r#""-0x1""#,
            r#""Infinity""#,
            "true",
            "null",
            "[1]",
            r#"{"id":1}"#,
            "1e400",
        ] {
            assert!(!may_answer(raw, &one), "{raw}");
        }
        assert!(may_answer(r#""""#, &[valid("0")]), "Number(\"\") is 0");
        assert!(may_answer("-0.0", &[valid("0")]));
        assert!(may_answer("1", &[valid(r#""1""#)]), "a numeric string id");
        assert!(may_answer(r#""abc""#, &[valid(r#""abc""#)]));
        assert!(!may_answer(r#""ABC""#, &[valid(r#""abc""#)]));
    }
}
