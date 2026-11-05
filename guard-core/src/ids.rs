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
}
