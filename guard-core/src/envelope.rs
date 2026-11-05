// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! JSON-RPC envelope validation: strict JSON, duplicate keys, message kinds, routing and batches.
//!
//! [`inspect_request`] is the entry point for a client POST body. It never
//! panics and never forwards anything it cannot interpret: every input either
//! gets a [`Routing`] or an [`EnvelopeError`].
//!
//! Design choices:
//! - Duplicate keys are refused at every depth of a message, not only in the
//!   envelope and `params`.
//! - A batch larger than `limits.maxBatchSize` is refused as
//!   `unsupported_batch` (the spec lists no separate detail).
//! - A `tools/call` request without `params` gets `params_type`; a `params`
//!   object without a string `name` gets `missing_tool_name`.
//! - In a batch, a `tools/call` with bad `params` is refused like a denied
//!   call: nothing is forwarded and the element gets its own
//!   `invalid_params` entry.

use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;

use crate::ids::{Id, IdToken};

/// The MCP method that lists tools.
pub const TOOLS_LIST: &str = "tools/list";
/// The MCP method that calls a tool.
pub const TOOLS_CALL: &str = "tools/call";
/// The only `MCP-Protocol-Version` that allows batches (an absent header means the same).
pub const BATCH_PROTOCOL_VERSION: &str = "2025-03-26";

/// The configured limits envelope validation needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeLimits {
    /// `limits.maxBatchSize`.
    pub max_batch_size: usize,
    /// `limits.maxToolNameBytes` (UTF-8 bytes of the decoded name).
    pub max_tool_name_bytes: usize,
}

/// `data.detail` values for `invalid_request`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestDetail {
    Envelope,
    IdType,
    DuplicateKeys,
    DuplicateIds,
    EmptyBatch,
    UnsupportedBatch,
    NotificationToolCall,
}

impl RequestDetail {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestDetail::Envelope => "envelope",
            RequestDetail::IdType => "id_type",
            RequestDetail::DuplicateKeys => "duplicate_keys",
            RequestDetail::DuplicateIds => "duplicate_ids",
            RequestDetail::EmptyBatch => "empty_batch",
            RequestDetail::UnsupportedBatch => "unsupported_batch",
            RequestDetail::NotificationToolCall => "notification_tool_call",
        }
    }
}

/// `data.detail` values for `invalid_params`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamsDetail {
    MissingToolName,
    NameTooLong,
    ParamsType,
}

impl ParamsDetail {
    pub fn as_str(self) -> &'static str {
        match self {
            ParamsDetail::MissingToolName => "missing_tool_name",
            ParamsDetail::NameTooLong => "name_too_long",
            ParamsDetail::ParamsType => "params_type",
        }
    }
}

/// Why a request body was refused before any policy decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// `parse_error`: not strict UTF-8 JSON.
    Parse,
    /// `invalid_request`, with its detail.
    InvalidRequest(RequestDetail),
    /// `invalid_params` for a single `tools/call` request, with its id.
    InvalidParams { id: Id, detail: ParamsDetail },
}

/// What the guard does with a valid request body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Routing {
    /// Forward unchanged; nothing to remember.
    PassThrough,
    /// Forward with `Accept-Encoding: identity`, and expect a `tools/list`
    /// response for these ids.
    ExpectList(Vec<Id>),
    /// Decide every tool call before anything is forwarded.
    Decide {
        /// The body was an array, so any refusal is an array too.
        batch: bool,
        /// Every request element in order (a single message has one).
        requests: Vec<RequestElement>,
    },
}

/// One request in a body that needs a decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestElement {
    pub id: Id,
    pub call: CallCheck,
}

/// What a request element asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallCheck {
    /// A request other than `tools/call` (in a batch with calls).
    Other,
    /// A `tools/call` with a valid, decoded tool name.
    Call { name: String },
    /// A `tools/call` in a batch whose `params` are invalid.
    InvalidParams(ParamsDetail),
}

/// The kind of one JSON-RPC message (request, notification or response).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Request {
        id: Id,
    },
    Notification,
    /// `id` is `None` only for an error response with `"id": null`.
    Response {
        id: Option<Id>,
        is_error: bool,
    },
}

/// One validated message. Members other than these stay untouched in the body.
#[derive(Clone, Debug)]
pub struct Message<'a> {
    pub kind: Kind,
    /// Decoded method name (requests and notifications).
    pub method: Option<String>,
    pub params: Option<&'a RawValue>,
    pub result: Option<&'a RawValue>,
}

/// Failure of the strict JSON check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrictError {
    /// Not RFC 8259 JSON in UTF-8 (including a byte-order mark).
    Parse,
    /// Valid JSON, but some object has the same key twice (after decoding escapes).
    DuplicateKeys,
}

/// Checks that `bytes` is one strict RFC 8259 JSON value in UTF-8, with no
/// duplicate keys in any object.
///
/// Limits inherited from `serde_json` (allowed by RFC 8259 §9): nesting deeper
/// than 128 levels and numbers outside the `f64` range (e.g. `1e400`) are
/// parse errors.
pub fn check_strict_json(bytes: &[u8]) -> Result<(), StrictError> {
    if bytes.starts_with(b"\xEF\xBB\xBF") || std::str::from_utf8(bytes).is_err() {
        return Err(StrictError::Parse);
    }
    let duplicate = Cell::new(false);
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    Strict {
        duplicate: &duplicate,
    }
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end())
    .map_err(|_| StrictError::Parse)?;
    // Duplicates are reported only for otherwise valid JSON, so the outcome
    // does not depend on where in the body the first problem is.
    if duplicate.get() {
        return Err(StrictError::DuplicateKeys);
    }
    Ok(())
}

/// Visits every value and records whether any object repeats a key.
#[derive(Clone, Copy)]
struct Strict<'s> {
    duplicate: &'s Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for Strict<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(self)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = HashSet::new();
        // `String` decodes escapes, so `"name"` and `"n\u0061me"` collide.
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                self.duplicate.set(true);
            }
            map.next_value_seed(self)?;
        }
        Ok(())
    }
}

/// Validates a client POST body and decides how it is routed.
///
/// `protocol_version` is the `MCP-Protocol-Version` header, if present.
pub fn inspect_request(
    body: &[u8],
    protocol_version: Option<&str>,
    limits: EnvelopeLimits,
) -> Result<Routing, EnvelopeError> {
    check_strict_json(body).map_err(|err| match err {
        StrictError::Parse => EnvelopeError::Parse,
        StrictError::DuplicateKeys => EnvelopeError::InvalidRequest(RequestDetail::DuplicateKeys),
    })?;
    let root: &RawValue = serde_json::from_slice(body).map_err(|_| EnvelopeError::Parse)?;
    match first_byte(root) {
        Some(b'{') => inspect_single(root, limits),
        Some(b'[') => inspect_batch(root, protocol_version, limits),
        _ => Err(EnvelopeError::InvalidRequest(RequestDetail::Envelope)),
    }
}

fn inspect_single(root: &RawValue, limits: EnvelopeLimits) -> Result<Routing, EnvelopeError> {
    let message = parse_message(root).map_err(EnvelopeError::InvalidRequest)?;
    Ok(match route(&message, limits)? {
        Route::List(id) => Routing::ExpectList(vec![id]),
        Route::Request(RequestElement {
            id,
            call: CallCheck::InvalidParams(detail),
        }) => return Err(EnvelopeError::InvalidParams { id, detail }),
        Route::Request(
            element @ RequestElement {
                call: CallCheck::Call { .. },
                ..
            },
        ) => Routing::Decide {
            batch: false,
            requests: vec![element],
        },
        Route::Request(_) | Route::NotARequest => Routing::PassThrough,
    })
}

fn inspect_batch(
    root: &RawValue,
    protocol_version: Option<&str>,
    limits: EnvelopeLimits,
) -> Result<Routing, EnvelopeError> {
    let unsupported = EnvelopeError::InvalidRequest(RequestDetail::UnsupportedBatch);
    if let Some(version) = protocol_version {
        if version.trim_matches(|c| c == ' ' || c == '\t') != BATCH_PROTOCOL_VERSION {
            return Err(unsupported);
        }
    }
    let elements: Vec<&RawValue> =
        serde_json::from_str(root.get()).map_err(|_| EnvelopeError::Parse)?;
    if elements.is_empty() {
        return Err(EnvelopeError::InvalidRequest(RequestDetail::EmptyBatch));
    }
    if elements.len() > limits.max_batch_size {
        return Err(unsupported);
    }

    // Every element must be valid before anything else is looked at.
    let mut routes = Vec::with_capacity(elements.len());
    for element in elements {
        let message = parse_message(element).map_err(EnvelopeError::InvalidRequest)?;
        routes.push(route(&message, limits)?);
    }

    let mut seen = HashSet::new();
    let mut list_ids = Vec::new();
    let mut requests = Vec::new();
    let mut has_call = false;
    for route in routes {
        let id = match &route {
            Route::List(id) | Route::Request(RequestElement { id, .. }) => id.clone(),
            Route::NotARequest => continue,
        };
        if !seen.insert(id) {
            return Err(EnvelopeError::InvalidRequest(RequestDetail::DuplicateIds));
        }
        match route {
            Route::List(id) => list_ids.push(id),
            Route::Request(element) => {
                has_call |= !matches!(element.call, CallCheck::Other);
                requests.push(element);
            }
            Route::NotARequest => {}
        }
    }

    if !list_ids.is_empty() {
        // A list response must never share a buffered body with other responses.
        if !requests.is_empty() {
            return Err(unsupported);
        }
        return Ok(Routing::ExpectList(list_ids));
    }
    if has_call {
        return Ok(Routing::Decide {
            batch: true,
            requests,
        });
    }
    Ok(Routing::PassThrough)
}

/// How one valid message is routed.
enum Route {
    /// A `tools/list` request.
    List(Id),
    /// Any other request.
    Request(RequestElement),
    /// A notification or a response.
    NotARequest,
}

fn route(message: &Message<'_>, limits: EnvelopeLimits) -> Result<Route, EnvelopeError> {
    let method = message.method.as_deref();
    match (&message.kind, method) {
        (Kind::Request { id }, Some(TOOLS_LIST)) => Ok(Route::List(id.clone())),
        (Kind::Request { id }, Some(TOOLS_CALL)) => Ok(Route::Request(RequestElement {
            id: id.clone(),
            call: check_call_params(message.params, limits),
        })),
        (Kind::Request { id }, _) => Ok(Route::Request(RequestElement {
            id: id.clone(),
            call: CallCheck::Other,
        })),
        // It would execute with no reply path.
        (Kind::Notification, Some(TOOLS_CALL)) => Err(EnvelopeError::InvalidRequest(
            RequestDetail::NotificationToolCall,
        )),
        (Kind::Notification | Kind::Response { .. }, _) => Ok(Route::NotARequest),
    }
}

fn check_call_params(params: Option<&RawValue>, limits: EnvelopeLimits) -> CallCheck {
    let Some(params) = params.filter(|p| first_byte(p) == Some(b'{')) else {
        return CallCheck::InvalidParams(ParamsDetail::ParamsType);
    };
    let Ok(members) = serde_json::from_str::<BTreeMap<String, &RawValue>>(params.get()) else {
        return CallCheck::InvalidParams(ParamsDetail::ParamsType);
    };
    let Some(name) = members.get("name").and_then(|raw| decode_string(raw)) else {
        return CallCheck::InvalidParams(ParamsDetail::MissingToolName);
    };
    if name.len() > limits.max_tool_name_bytes {
        return CallCheck::InvalidParams(ParamsDetail::NameTooLong);
    }
    CallCheck::Call { name }
}

/// Classifies one message object. The input must already
/// have passed [`check_strict_json`] as part of its body.
pub fn parse_message(raw: &RawValue) -> Result<Message<'_>, RequestDetail> {
    let envelope = RequestDetail::Envelope;
    if first_byte(raw) != Some(b'{') {
        return Err(envelope);
    }
    let members: BTreeMap<String, &RawValue> =
        serde_json::from_str(raw.get()).map_err(|_| envelope)?;

    if members
        .get("jsonrpc")
        .and_then(|v| decode_string(v))
        .as_deref()
        != Some("2.0")
    {
        return Err(envelope);
    }
    let method = match members.get("method") {
        None => None,
        Some(raw) => Some(decode_string(raw).ok_or(envelope)?),
    };
    let params = members.get("params").copied();
    if let Some(params) = params {
        if !matches!(first_byte(params), Some(b'{' | b'[')) {
            return Err(envelope);
        }
        if method.as_deref() == Some(TOOLS_LIST) && first_byte(params) != Some(b'{') {
            return Err(envelope);
        }
    }
    let result = members.get("result").copied();
    let has_error = members.contains_key("error");
    let id = members.get("id").map(|raw| Id::from_raw(raw.get()));

    let kind = if method.is_some() {
        if result.is_some() || has_error {
            return Err(envelope);
        }
        match id {
            None => Kind::Notification,
            Some(IdToken::Valid(id)) => Kind::Request { id },
            Some(IdToken::Null | IdToken::Invalid) => return Err(RequestDetail::IdType),
        }
    } else {
        if result.is_some() == has_error {
            return Err(envelope);
        }
        match id {
            None => return Err(envelope),
            Some(IdToken::Valid(id)) => Kind::Response {
                id: Some(id),
                is_error: has_error,
            },
            Some(IdToken::Null) if has_error => Kind::Response {
                id: None,
                is_error: true,
            },
            Some(IdToken::Null | IdToken::Invalid) => return Err(RequestDetail::IdType),
        }
    };

    Ok(Message {
        kind,
        method,
        params,
        result,
    })
}

/// The first byte of a raw value (raw values carry no surrounding whitespace).
fn first_byte(raw: &RawValue) -> Option<u8> {
    raw.get().trim_start().as_bytes().first().copied()
}

/// Decodes a JSON string value, or `None` if the value is not a string.
fn decode_string(raw: &RawValue) -> Option<String> {
    if first_byte(raw) != Some(b'"') {
        return None;
    }
    serde_json::from_str(raw.get()).ok()
}

// --- HTTP request gate ----------------------------------------------------

/// What to do with a client request before looking at its body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// A POST: buffer the body and inspect it.
    Inspect,
    /// A bodiless GET, DELETE, OPTIONS or HEAD.
    PassThrough,
    Refuse(HttpRefusal),
}

/// Refusals decided from the method and headers alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpRefusal {
    MethodNotAllowed,
    Encoded,
    TooLarge,
}

/// Headers that ask a server to treat a request as another method.
pub const METHOD_OVERRIDE_HEADERS: [&str; 3] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

/// `true` for an absent, empty or `identity` content coding (every listed
/// coding must be `identity`).
pub fn is_identity_encoding(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        value
            .split(',')
            .map(str::trim)
            .all(|coding| coding.is_empty() || coding.eq_ignore_ascii_case("identity"))
    })
}

/// The HTTP method rules. `header` looks a header up by lowercase name.
/// Method names are case-sensitive (RFC 9110), so `post` is another method.
pub fn gate_request<'h>(method: &str, header: impl Fn(&str) -> Option<&'h str>) -> Gate {
    match method {
        "POST" => {
            if is_identity_encoding(header("content-encoding")) {
                Gate::Inspect
            } else {
                Gate::Refuse(HttpRefusal::Encoded)
            }
        }
        "GET" | "DELETE" | "OPTIONS" | "HEAD" => {
            let no_body = header("transfer-encoding").is_none()
                && header("content-length").is_none_or(|len| len.trim().parse::<u64>() == Ok(0));
            let no_override = METHOD_OVERRIDE_HEADERS
                .iter()
                .all(|name| header(name).is_none());
            if no_body && no_override {
                Gate::PassThrough
            } else {
                Gate::Refuse(HttpRefusal::MethodNotAllowed)
            }
        }
        _ => Gate::Refuse(HttpRefusal::MethodNotAllowed),
    }
}

/// The body-size rule for a buffered POST body.
pub fn check_body_size(len: usize, max_request_body_bytes: usize) -> Result<(), HttpRefusal> {
    if len > max_request_body_bytes {
        Err(HttpRefusal::TooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: EnvelopeLimits = EnvelopeLimits {
        max_batch_size: 4,
        max_tool_name_bytes: 16,
    };

    fn inspect(body: &str) -> Result<Routing, EnvelopeError> {
        inspect_request(body.as_bytes(), None, LIMITS)
    }

    fn inspect_v(body: &str, version: &str) -> Result<Routing, EnvelopeError> {
        inspect_request(body.as_bytes(), Some(version), LIMITS)
    }

    fn invalid(detail: RequestDetail) -> Result<Routing, EnvelopeError> {
        Err(EnvelopeError::InvalidRequest(detail))
    }

    fn id(raw: &str) -> Id {
        match Id::from_raw(raw) {
            IdToken::Valid(id) => id,
            other => unreachable!("{raw} should be a valid id, got {other:?}"),
        }
    }

    fn call(id_raw: &str, name: &str) -> RequestElement {
        RequestElement {
            id: id(id_raw),
            call: CallCheck::Call {
                name: name.to_owned(),
            },
        }
    }

    fn other(id_raw: &str) -> RequestElement {
        RequestElement {
            id: id(id_raw),
            call: CallCheck::Other,
        }
    }

    fn call_body(id: &str, name: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}"}}}}"#
        )
    }

    fn list_body(id: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/list"}}"#)
    }

    const PING: &str = r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#;
    const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

    // --- strict JSON ---------------------------------------------------------

    #[test]
    fn byte_order_mark_is_a_parse_error() {
        let mut body = b"\xEF\xBB\xBF".to_vec();
        body.extend_from_slice(PING.as_bytes());
        assert_eq!(
            inspect_request(&body, None, LIMITS),
            Err(EnvelopeError::Parse)
        );
    }

    #[test]
    fn invalid_utf8_is_a_parse_error() {
        let body = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"p\xFFng\"}";
        assert_eq!(
            inspect_request(body, None, LIMITS),
            Err(EnvelopeError::Parse)
        );
    }

    #[test]
    fn lenient_json_is_a_parse_error() {
        for body in [
            "",
            "   ",
            r#"{"jsonrpc":"2.0","id":1,"method":"ping",}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"} x"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}{}"#,
            r#"{"jsonrpc":"2.0","id":01,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":NaN,"method":"ping"}"#,
            r#"{'jsonrpc':'2.0'}"#,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"} // comment",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"pi\u{1}ng\"}",
            r#"{"jsonrpc":"2.0","id":1,"method":"\ud800"}"#,
        ] {
            assert_eq!(inspect(body), Err(EnvelopeError::Parse), "{body:?}");
        }
    }

    #[test]
    fn surrounding_whitespace_is_allowed() {
        assert_eq!(
            inspect(&format!(" \n{PING}\r\n\t")),
            Ok(Routing::PassThrough)
        );
    }

    #[test]
    fn syntax_errors_win_over_duplicate_keys() {
        let body = r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"ping""#;
        assert_eq!(inspect(body), Err(EnvelopeError::Parse));
    }

    #[test]
    fn deep_nesting_is_a_parse_error() {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"a":{}0{}}}}}"#,
            "[".repeat(200),
            "]".repeat(200)
        );
        assert_eq!(inspect(&body), Err(EnvelopeError::Parse));
    }

    // --- duplicate keys ------------------------------------------------------

    #[test]
    fn duplicate_keys_at_every_level_are_refused() {
        for body in [
            // envelope
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}"#,
            // params
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1,"a":2}}"#,
            // tools/call params
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","name":"delete"}}"#,
            // deep inside arguments
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"x":[{"k":1,"k":1}]}}}"#,
            // a response's result
            r#"{"jsonrpc":"2.0","id":1,"result":{"a":1,"a":1}}"#,
            // a batch element
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"id":3,"method":"ping"}]"#,
        ] {
            assert_eq!(
                inspect(body),
                invalid(RequestDetail::DuplicateKeys),
                "{body}"
            );
        }
    }

    #[test]
    fn escaped_duplicate_keys_are_refused() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","n\u0061me":"delete"}}"#;
        assert_eq!(inspect(body), invalid(RequestDetail::DuplicateKeys));
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools\/call","params":{"name":"echo"}}"#;
        assert_eq!(inspect(body), invalid(RequestDetail::DuplicateKeys));
    }

    #[test]
    fn same_key_in_sibling_objects_is_allowed() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":{"k":1},"b":{"k":1}}}"#;
        assert_eq!(inspect(body), Ok(Routing::PassThrough));
    }

    // --- root and message kinds ---------------------------------------------

    #[test]
    fn scalar_and_null_roots_are_invalid() {
        for body in ["1", r#""tools/call""#, "true", "null"] {
            assert_eq!(inspect(body), invalid(RequestDetail::Envelope), "{body}");
        }
    }

    #[test]
    fn nested_arrays_and_non_object_batch_elements_are_invalid() {
        for body in [
            format!("[[{PING}]]"),
            "[1]".to_owned(),
            r#"["x"]"#.to_owned(),
            "[null]".to_owned(),
            format!("[{PING},[]]"),
        ] {
            assert_eq!(inspect(&body), invalid(RequestDetail::Envelope), "{body}");
        }
    }

    #[test]
    fn missing_or_wrong_jsonrpc_is_invalid() {
        for body in [
            r#"{"id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
            r#"{"jsonrpc":2.0,"id":1,"method":"ping"}"#,
            r#"{"jsonrpc":null,"id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0 ","id":1,"method":"ping"}"#,
        ] {
            assert_eq!(inspect(body), invalid(RequestDetail::Envelope), "{body}");
        }
    }

    #[test]
    fn escaped_jsonrpc_version_is_decoded() {
        assert_eq!(
            inspect(r#"{"jsonrpc":"2\u002e0","id":1,"method":"ping"}"#),
            Ok(Routing::PassThrough)
        );
    }

    #[test]
    fn malformed_message_shapes_are_invalid() {
        for body in [
            // method with result / error
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","error":{}}"#,
            // result with error
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{}}"#,
            // neither method, result nor error
            r#"{"jsonrpc":"2.0","id":1}"#,
            // response without id
            r#"{"jsonrpc":"2.0","result":{}}"#,
            // non-string method
            r#"{"jsonrpc":"2.0","id":1,"method":7}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":null}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":["tools/call"]}"#,
            // empty object
            "{}",
        ] {
            assert_eq!(inspect(body), invalid(RequestDetail::Envelope), "{body}");
        }
    }

    #[test]
    fn params_of_wrong_type_are_invalid() {
        for body in [
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":5}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":"x"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":null}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/x","params":true}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[]}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":5}"#,
        ] {
            assert_eq!(inspect(body), invalid(RequestDetail::Envelope), "{body}");
        }
    }

    #[test]
    fn array_params_are_fine_for_other_methods() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"custom","params":[1,2]}"#;
        assert_eq!(inspect(body), Ok(Routing::PassThrough));
    }

    #[test]
    fn valid_responses_and_notifications_pass_through() {
        for body in [
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":"a","error":{"code":-1,"message":"x"}}"#,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}"#,
            INITIALIZED,
            r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed","extra":1}"#,
        ] {
            assert_eq!(inspect(body), Ok(Routing::PassThrough), "{body}");
        }
    }

    // --- ids -----------------------------------------------------------------

    #[test]
    fn invalid_request_ids_are_refused() {
        for raw in ["null", "true", "false", "1.5", "1e3", "-1E2", "{}", "[1]"] {
            let body = format!(r#"{{"jsonrpc":"2.0","id":{raw},"method":"ping"}}"#);
            assert_eq!(inspect(&body), invalid(RequestDetail::IdType), "{raw}");
        }
    }

    #[test]
    fn null_id_is_allowed_only_on_error_responses() {
        assert_eq!(
            inspect(r#"{"jsonrpc":"2.0","id":null,"result":{}}"#),
            invalid(RequestDetail::IdType)
        );
        assert_eq!(
            inspect(r#"{"jsonrpc":"2.0","id":1.5,"error":{}}"#),
            invalid(RequestDetail::IdType)
        );
    }

    #[test]
    fn big_integer_ids_are_echoed_exactly() {
        let big = "123456789012345678901234567890";
        let Ok(Routing::Decide { requests, .. }) = inspect(&call_body(big, "echo")) else {
            unreachable!("expected a decision");
        };
        assert_eq!(requests.first().map(|r| r.id.raw()), Some(big));
    }

    // --- routing of single messages -----------------------------------------

    #[test]
    fn tools_list_expects_a_list_response() {
        assert_eq!(
            inspect(&list_body("7")),
            Ok(Routing::ExpectList(vec![id("7")]))
        );
        let with_params =
            r#"{"jsonrpc":"2.0","id":"c","method":"tools/list","params":{"cursor":"x"}}"#;
        assert_eq!(
            inspect(with_params),
            Ok(Routing::ExpectList(vec![id(r#""c""#)]))
        );
    }

    #[test]
    fn tools_call_needs_a_decision() {
        assert_eq!(
            inspect(&call_body("1", "echo")),
            Ok(Routing::Decide {
                batch: false,
                requests: vec![call("1", "echo")]
            })
        );
    }

    #[test]
    fn escaped_method_and_tool_names_are_decoded() {
        let body =
            r#"{"jsonrpc":"2.0","id":1,"method":"tools\/call","params":{"name":"d\u0065lete"}}"#;
        assert_eq!(
            inspect(body),
            Ok(Routing::Decide {
                batch: false,
                requests: vec![call("1", "delete")]
            })
        );
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools\u002flist"}"#;
        assert_eq!(inspect(body), Ok(Routing::ExpectList(vec![id("1")])));
    }

    #[test]
    fn method_names_are_compared_exactly() {
        for method in [
            "Tools/Call",
            "tools/call ",
            " tools/call",
            "tools/call\u{0}",
            "tools//call",
        ] {
            let body =
                serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":{"name":"x"}})
                    .to_string();
            assert_eq!(inspect(&body), Ok(Routing::PassThrough), "{method:?}");
        }
    }

    #[test]
    fn tools_call_params_are_checked() {
        let params = |p: &str| format!(r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call"{p}}}"#);
        let err = |detail| {
            Err(EnvelopeError::InvalidParams {
                id: id("3"),
                detail,
            })
        };
        assert_eq!(inspect(&params("")), err(ParamsDetail::ParamsType));
        assert_eq!(
            inspect(&params(r#","params":["echo"]"#)),
            err(ParamsDetail::ParamsType)
        );
        assert_eq!(
            inspect(&params(r#","params":{}"#)),
            err(ParamsDetail::MissingToolName)
        );
        assert_eq!(
            inspect(&params(r#","params":{"name":7}"#)),
            err(ParamsDetail::MissingToolName)
        );
        assert_eq!(
            inspect(&params(r#","params":{"name":null}"#)),
            err(ParamsDetail::MissingToolName)
        );
        assert_eq!(
            inspect(&params(r#","params":{"name":"abcdefghijklmnopq"}"#)),
            err(ParamsDetail::NameTooLong)
        );
    }

    #[test]
    fn tool_name_length_counts_utf8_bytes_of_the_decoded_name() {
        // 16 bytes is the limit: exactly 16 passes.
        assert!(matches!(
            inspect(&call_body("1", "abcdefghijklmnop")),
            Ok(Routing::Decide { .. })
        ));
        // 8 × "é" = 8 characters but 16 bytes: passes; 9 × "é" = 18 bytes: too long.
        assert!(matches!(
            inspect(&call_body("1", &"é".repeat(8))),
            Ok(Routing::Decide { .. })
        ));
        assert!(matches!(
            inspect(&call_body("1", &"é".repeat(9))),
            Err(EnvelopeError::InvalidParams {
                detail: ParamsDetail::NameTooLong,
                ..
            })
        ));
        // Escapes are decoded before counting: 16 escaped ASCII letters are 16 bytes.
        let escaped = "\\u0061".repeat(16);
        assert!(matches!(
            inspect(&call_body("1", &escaped)),
            Ok(Routing::Decide { .. })
        ));
    }

    #[test]
    fn tools_call_notification_is_refused() {
        let body = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"}}"#;
        assert_eq!(inspect(body), invalid(RequestDetail::NotificationToolCall));
    }

    #[test]
    fn other_requests_pass_through() {
        assert_eq!(inspect(PING), Ok(Routing::PassThrough));
    }

    // --- batches ---------------------------------------------------------------

    #[test]
    fn batches_depend_on_the_protocol_version() {
        let body = format!("[{PING}]");
        assert_eq!(inspect(&body), Ok(Routing::PassThrough));
        assert_eq!(inspect_v(&body, "2025-03-26"), Ok(Routing::PassThrough));
        assert_eq!(inspect_v(&body, " 2025-03-26 "), Ok(Routing::PassThrough));
        assert_eq!(
            inspect_v(&body, "2025-06-18"),
            invalid(RequestDetail::UnsupportedBatch)
        );
        assert_eq!(
            inspect_v(&body, ""),
            invalid(RequestDetail::UnsupportedBatch)
        );
    }

    #[test]
    fn single_messages_are_allowed_with_any_version() {
        assert_eq!(inspect_v(PING, "2025-06-18"), Ok(Routing::PassThrough));
    }

    #[test]
    fn empty_and_oversized_batches_are_refused() {
        assert_eq!(inspect("[]"), invalid(RequestDetail::EmptyBatch));
        assert_eq!(inspect(" [ ] "), invalid(RequestDetail::EmptyBatch));
        let four = [INITIALIZED; 4].join(",");
        assert_eq!(inspect(&format!("[{four}]")), Ok(Routing::PassThrough));
        let five = [INITIALIZED; 5].join(",");
        assert_eq!(
            inspect(&format!("[{five}]")),
            invalid(RequestDetail::UnsupportedBatch)
        );
    }

    #[test]
    fn one_invalid_element_invalidates_the_batch() {
        let body = format!(r#"[{PING},{{"jsonrpc":"2.0","id":true,"method":"ping"}}]"#);
        assert_eq!(inspect(&body), invalid(RequestDetail::IdType));
        let body = format!(
            r#"[{},{{"jsonrpc":"1.0","id":2,"method":"ping"}}]"#,
            call_body("1", "echo")
        );
        assert_eq!(inspect(&body), invalid(RequestDetail::Envelope));
    }

    #[test]
    fn duplicate_request_ids_are_refused() {
        let body = format!("[{},{}]", call_body("1", "echo"), call_body("1", "echo"));
        assert_eq!(inspect(&body), invalid(RequestDetail::DuplicateIds));
        let body = format!(
            "[{},{}]",
            call_body(r#""a""#, "echo"),
            call_body(r#""\u0061""#, "echo")
        );
        assert_eq!(inspect(&body), invalid(RequestDetail::DuplicateIds));
    }

    #[test]
    fn same_id_of_different_types_is_not_a_duplicate() {
        let body = format!(
            "[{},{}]",
            call_body("7", "echo"),
            call_body(r#""7""#, "echo")
        );
        assert_eq!(
            inspect(&body),
            Ok(Routing::Decide {
                batch: true,
                requests: vec![call("7", "echo"), call(r#""7""#, "echo")]
            })
        );
    }

    #[test]
    fn response_ids_do_not_count_as_duplicate_request_ids() {
        let body = format!(
            r#"[{},{{"jsonrpc":"2.0","id":1,"result":{{}}}}]"#,
            call_body("1", "echo")
        );
        assert!(matches!(inspect(&body), Ok(Routing::Decide { .. })));
    }

    #[test]
    fn list_combined_with_another_request_is_refused() {
        for other in [call_body("2", "echo"), PING.to_owned()] {
            let body = format!("[{},{other}]", list_body("1"));
            assert_eq!(
                inspect(&body),
                invalid(RequestDetail::UnsupportedBatch),
                "{other}"
            );
        }
    }

    #[test]
    fn list_only_batches_mark_every_id() {
        let body = format!(
            r#"[{},{INITIALIZED},{},{{"jsonrpc":"2.0","id":5,"result":{{}}}}]"#,
            list_body("1"),
            list_body(r#""b""#)
        );
        assert_eq!(
            inspect(&body),
            Ok(Routing::ExpectList(vec![id("1"), id(r#""b""#)]))
        );
    }

    #[test]
    fn batches_with_calls_list_every_request_in_order() {
        let body = format!(
            "[{},{INITIALIZED},{PING},{}]",
            call_body("1", "echo"),
            call_body("2", "delete")
        );
        assert_eq!(
            inspect(&body),
            Ok(Routing::Decide {
                batch: true,
                requests: vec![call("1", "echo"), other("9"), call("2", "delete")]
            })
        );
    }

    #[test]
    fn invalid_call_params_in_a_batch_become_an_element_refusal() {
        let body = format!(
            r#"[{},{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{}}}}]"#,
            call_body("1", "echo")
        );
        assert_eq!(
            inspect(&body),
            Ok(Routing::Decide {
                batch: true,
                requests: vec![
                    call("1", "echo"),
                    RequestElement {
                        id: id("2"),
                        call: CallCheck::InvalidParams(ParamsDetail::MissingToolName)
                    }
                ]
            })
        );
    }

    #[test]
    fn tools_call_notification_in_a_batch_is_refused() {
        let body = format!(
            r#"[{PING},{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"echo"}}}}]"#
        );
        assert_eq!(inspect(&body), invalid(RequestDetail::NotificationToolCall));
    }

    #[test]
    fn notification_only_batch_passes() {
        let body = format!("[{INITIALIZED},{INITIALIZED}]");
        assert_eq!(inspect(&body), Ok(Routing::PassThrough));
    }

    #[test]
    fn batch_without_calls_or_lists_passes() {
        let body = format!(r#"[{PING},{{"jsonrpc":"2.0","id":1,"result":{{}}}}]"#);
        assert_eq!(inspect(&body), Ok(Routing::PassThrough));
    }

    // --- message parsing for the response side -------------------------

    #[test]
    fn parse_message_reports_response_kinds() {
        let raw = |s: &'static str| -> &'static RawValue {
            serde_json::from_str(s).unwrap_or_else(|_| unreachable!("valid JSON"))
        };
        let ok = parse_message(raw(r#"{"jsonrpc":"2.0","id":4,"result":{"tools":[]}}"#));
        assert!(matches!(
            ok,
            Ok(Message {
                kind: Kind::Response {
                    id: Some(_),
                    is_error: false
                },
                result: Some(_),
                ..
            })
        ));
        let err = parse_message(raw(r#"{"jsonrpc":"2.0","id":null,"error":{}}"#));
        assert!(matches!(
            err,
            Ok(Message {
                kind: Kind::Response {
                    id: None,
                    is_error: true
                },
                ..
            })
        ));
        // A server-to-client request that reuses an id is a request, not a response.
        let req = parse_message(raw(
            r#"{"jsonrpc":"2.0","id":4,"method":"sampling/createMessage"}"#,
        ));
        assert!(matches!(
            req,
            Ok(Message {
                kind: Kind::Request { .. },
                ..
            })
        ));
    }

    // --- HTTP gate -------------------------------------------------------------------------

    fn gate(method: &str, headers: &[(&'static str, &'static str)]) -> Gate {
        gate_request(method, |name| {
            headers.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
        })
    }

    #[test]
    fn post_is_inspected_unless_encoded() {
        assert_eq!(gate("POST", &[]), Gate::Inspect);
        assert_eq!(
            gate("POST", &[("content-type", "text/plain")]),
            Gate::Inspect,
            "any content type"
        );
        assert_eq!(
            gate("POST", &[("content-encoding", "identity")]),
            Gate::Inspect
        );
        assert_eq!(
            gate("POST", &[("content-encoding", " Identity ")]),
            Gate::Inspect
        );
        for coding in ["gzip", "br", "identity, gzip", "x-custom"] {
            assert_eq!(
                gate("POST", &[("content-encoding", coding)]),
                Gate::Refuse(HttpRefusal::Encoded),
                "{coding}"
            );
        }
    }

    #[test]
    fn bodiless_methods_pass_only_without_body_or_override() {
        for method in ["GET", "DELETE", "OPTIONS", "HEAD"] {
            assert_eq!(gate(method, &[]), Gate::PassThrough, "{method}");
            assert_eq!(
                gate(method, &[("content-length", "0")]),
                Gate::PassThrough,
                "{method}"
            );
            let refused = Gate::Refuse(HttpRefusal::MethodNotAllowed);
            assert_eq!(
                gate(method, &[("content-length", "5")]),
                refused,
                "{method}"
            );
            assert_eq!(
                gate(method, &[("content-length", "abc")]),
                refused,
                "{method}"
            );
            assert_eq!(
                gate(method, &[("transfer-encoding", "chunked")]),
                refused,
                "{method}"
            );
            for name in METHOD_OVERRIDE_HEADERS {
                assert_eq!(gate(method, &[(name, "POST")]), refused, "{method} {name}");
            }
        }
    }

    #[test]
    fn other_methods_are_refused() {
        for method in [
            "PUT", "PATCH", "TRACE", "CONNECT", "post", "Get", "PROPFIND",
        ] {
            assert_eq!(
                gate(method, &[]),
                Gate::Refuse(HttpRefusal::MethodNotAllowed),
                "{method}"
            );
        }
    }

    #[test]
    fn body_size_limit() {
        assert_eq!(check_body_size(1024, 1024), Ok(()));
        assert_eq!(check_body_size(1025, 1024), Err(HttpRefusal::TooLarge));
    }
}
