// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! `tools/list` response inspection and filtering.
//!
//! The response is never rebuilt from a parsed tree. Only the matched
//! `result.tools` arrays are replaced, by splicing the original bytes of the
//! kept entries, so every other byte — `nextCursor`, unknown fields, key
//! order and numeric tokens — is preserved exactly.
//!
//! Design choices:
//! - Duplicate keys anywhere in a list response body make it
//!   `response_invalid` (the spec requires it for the envelope, `result`,
//!   tool entries and annotations; nothing else is in a list response).
//! - In JSON mode, a body without a matching response, or with a message that
//!   is not a valid JSON-RPC message, is `response_invalid`. Two responses
//!   with the same marked id are `response_invalid` too.
//! - Invalid entries are removed only when filtering is active; with
//!   `filterToolsList: false` or in audit mode the body is forwarded unchanged.
//! - `tool_definition_conflict` is reported for every name listed more than
//!   once in one response, with the distinct candidate classes seen.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use serde_json::value::RawValue;
use serde_json::Value;

use crate::catalog::Pin;
use crate::classify::{classify_tool, Classified, Outcome};
use crate::config::{Class, Config};
use crate::envelope::{check_strict_json, is_identity_encoding, parse_message, Kind, StrictError};
use crate::freshness::StaleReason;
use crate::ids::Id;

// --- pre-checks ---------------------------------------------------------------

/// How a response to a marked `tools/list` request is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Precheck {
    /// Non-2xx: pass through, no catalog change.
    PassThrough,
    /// Pass through unfiltered and mark the catalog stale.
    Stale(StaleReason),
    Json,
    Sse,
}

/// Status, `Content-Encoding` and media-type checks.
pub fn precheck(
    status: u16,
    content_encoding: Option<&str>,
    content_type: Option<&str>,
) -> Precheck {
    if !(200..300).contains(&status) {
        return Precheck::PassThrough;
    }
    if !is_identity_encoding(content_encoding) {
        return Precheck::Stale(StaleReason::Encoded);
    }
    match content_type.and_then(media_type) {
        Some(MediaType::Json) => Precheck::Json,
        Some(MediaType::EventStream) => Precheck::Sse,
        None => Precheck::Stale(StaleReason::UnsupportedContentType),
    }
}

enum MediaType {
    Json,
    EventStream,
}

/// Parses `type/subtype; params` (case-insensitive); `charset` must be absent
/// or `utf-8`, other parameters are ignored.
fn media_type(value: &str) -> Option<MediaType> {
    let mut parts = value.split(';');
    let essence = parts.next()?.trim().to_ascii_lowercase();
    for param in parts {
        let mut kv = param.splitn(2, '=');
        let key = kv.next().unwrap_or_default().trim();
        if key.eq_ignore_ascii_case("charset") {
            let charset = kv.next().unwrap_or_default().trim().trim_matches('"');
            if !charset.eq_ignore_ascii_case("utf-8") {
                return None;
            }
        }
    }
    match essence.as_str() {
        "application/json" => Some(MediaType::Json),
        "text/event-stream" => Some(MediaType::EventStream),
        _ => None,
    }
}

// --- inspection ----------------------------------------------------------------------

/// One classified, valid list entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tool {
    pub name: String,
    pub classified: Classified,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    /// Byte range of the entry in the source.
    range: Range<usize>,
    /// `None` for an invalid entry.
    tool: Option<Tool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    /// Byte range of the `result.tools` array in the source.
    tools: Range<usize>,
    entries: Vec<Entry>,
}

/// A validated list response with at least one matching `result`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListResult {
    source: String,
    targets: Vec<Target>,
}

/// What inspecting one JSON document found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inspection {
    /// No message answers a marked id.
    NotFound,
    /// Only error responses answer the marked ids: pass through, no change.
    ErrorsOnly,
    /// Pass through unfiltered, no pins, mark stale.
    Stale(StaleReason),
    Lists(ListResult),
}

/// Inspects a JSON document for responses to the marked list ids.
pub fn inspect(body: &[u8], expected: &[Id], config: &Config) -> Inspection {
    match check_strict_json(body) {
        Ok(()) => {}
        Err(StrictError::Parse) => return Inspection::Stale(StaleReason::ParseError),
        Err(StrictError::DuplicateKeys) => return Inspection::Stale(StaleReason::ResponseInvalid),
    }
    let Ok(source) = std::str::from_utf8(body) else {
        return Inspection::Stale(StaleReason::ParseError);
    };
    match inspect_source(source, expected, config) {
        Ok(Some(targets)) if targets.is_empty() => Inspection::ErrorsOnly,
        Ok(Some(targets)) => Inspection::Lists(ListResult {
            source: source.to_owned(),
            targets,
        }),
        Ok(None) => Inspection::NotFound,
        Err(reason) => Inspection::Stale(reason),
    }
}

/// JSON mode: a body without a matching response is `response_invalid`.
pub fn inspect_json(body: &[u8], expected: &[Id], config: &Config) -> Inspection {
    match inspect(body, expected, config) {
        Inspection::NotFound => Inspection::Stale(StaleReason::ResponseInvalid),
        other => other,
    }
}

/// `Ok(None)`: nothing matched. `Ok(Some(targets))`: matched, `targets`
/// holds the `result`s (empty if all matches were errors).
fn inspect_source(
    source: &str,
    expected: &[Id],
    config: &Config,
) -> Result<Option<Vec<Target>>, StaleReason> {
    let invalid = StaleReason::ResponseInvalid;
    let root: &RawValue = serde_json::from_str(source).map_err(|_| invalid)?;
    let messages: Vec<&RawValue> = match root.get().as_bytes().first() {
        Some(b'[') => serde_json::from_str(root.get()).map_err(|_| invalid)?,
        Some(b'{') => vec![root],
        _ => return Err(invalid),
    };
    let mut matched = BTreeSet::new();
    let mut found = false;
    let mut targets = Vec::new();
    for raw in messages {
        let message = parse_message(raw).map_err(|_| invalid)?;
        let Kind::Response {
            id: Some(id),
            is_error,
        } = message.kind
        else {
            // Requests (even reusing the list id), notifications, `id: null` errors.
            continue;
        };
        let Some(position) = expected.iter().position(|e| *e == id) else {
            continue;
        };
        if !matched.insert(position) {
            return Err(invalid);
        }
        found = true;
        if is_error {
            continue;
        }
        let result = message.result.ok_or(invalid)?;
        targets.push(inspect_result(source, result, config)?);
    }
    Ok(found.then_some(targets))
}

/// The byte range of `raw`, which must be a slice of `source`.
fn range_in(source: &str, raw: &str) -> Result<Range<usize>, StaleReason> {
    let start = (raw.as_ptr() as usize)
        .checked_sub(source.as_ptr() as usize)
        .ok_or(StaleReason::InternalError)?;
    let range = start..start + raw.len();
    match source.get(range.clone()) {
        Some(slice) if slice.as_ptr() == raw.as_ptr() => Ok(range),
        _ => Err(StaleReason::InternalError),
    }
}

fn inspect_result(source: &str, result: &RawValue, config: &Config) -> Result<Target, StaleReason> {
    let invalid = StaleReason::ResponseInvalid;
    if result.get().as_bytes().first() != Some(&b'{') {
        return Err(invalid);
    }
    let members: BTreeMap<String, &RawValue> =
        serde_json::from_str(result.get()).map_err(|_| invalid)?;
    let tools = members.get("tools").ok_or(invalid)?;
    if tools.get().as_bytes().first() != Some(&b'[') {
        return Err(invalid);
    }
    let items: Vec<&RawValue> = serde_json::from_str(tools.get()).map_err(|_| invalid)?;
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        entries.push(Entry {
            range: range_in(source, item.get())?,
            tool: entry_tool(item, config),
        });
    }
    Ok(Target {
        tools: range_in(source, tools.get())?,
        entries,
    })
}

/// Validates and classifies one entry; `None` if invalid.
fn entry_tool(item: &RawValue, config: &Config) -> Option<Tool> {
    if item.get().as_bytes().first() != Some(&b'{') {
        return None;
    }
    let members: BTreeMap<String, &RawValue> = serde_json::from_str(item.get()).ok()?;
    let name: String = serde_json::from_str(members.get("name")?.get()).ok()?;
    if name.len() > config.limits.max_tool_name_bytes {
        return None;
    }
    let annotations: Option<Value> = match members.get("annotations") {
        Some(raw) => Some(serde_json::from_str(raw.get()).ok()?),
        None => None,
    };
    let classified = classify_tool(&name, annotations.as_ref(), config);
    Some(Tool { name, classified })
}

impl ListResult {
    /// Every valid entry, in order (for `tool_classified` and other logs).
    pub fn tools(&self) -> impl Iterator<Item = &Tool> {
        self.targets
            .iter()
            .flat_map(|t| t.entries.iter())
            .filter_map(|e| e.tool.as_ref())
    }

    /// The number of invalid entries (`list_entry_invalid`).
    pub fn invalid_entries(&self) -> usize {
        self.targets
            .iter()
            .flat_map(|t| t.entries.iter())
            .filter(|e| e.tool.is_none())
            .count()
    }

    /// Candidates to merge into the catalog. Blocked and overridden
    /// tools are never pinned.
    pub fn observations(&self) -> Vec<(&str, Pin)> {
        self.tools()
            .filter_map(|tool| match tool.classified.outcome {
                Outcome::Candidate { class, source } => {
                    Some((tool.name.as_str(), Pin { class, source }))
                }
                Outcome::Blocked | Outcome::Override(_) => None,
            })
            .collect()
    }

    /// Names listed more than once, with the distinct candidate classes seen
    /// (`tool_definition_conflict`).
    pub fn conflicts(&self) -> Vec<(&str, Vec<Class>)> {
        let mut seen: BTreeMap<&str, (usize, BTreeSet<Class>)> = BTreeMap::new();
        for tool in self.tools() {
            let slot = seen.entry(tool.name.as_str()).or_default();
            slot.0 += 1;
            if let Outcome::Candidate { class, .. } = tool.classified.outcome {
                slot.1.insert(class);
            }
        }
        seen.into_iter()
            .filter(|(_, (count, _))| *count > 1)
            .map(|(name, (_, classes))| (name, classes.into_iter().collect()))
            .collect()
    }

    /// The source with each matched `tools` array reduced to the valid
    /// entries for which `keep` is true. Returns the new body and the
    /// number of entries removed.
    pub fn rewrite(&self, mut keep: impl FnMut(&str) -> bool) -> (String, usize) {
        let mut out = String::with_capacity(self.source.len());
        let mut removed = 0;
        let mut cursor = 0;
        for target in &self.targets {
            out.push_str(
                self.source
                    .get(cursor..target.tools.start)
                    .unwrap_or_default(),
            );
            out.push('[');
            let mut first = true;
            for entry in &target.entries {
                let kept = entry.tool.as_ref().is_some_and(|tool| keep(&tool.name));
                if !kept {
                    removed += 1;
                    continue;
                }
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(self.source.get(entry.range.clone()).unwrap_or_default());
            }
            out.push(']');
            cursor = target.tools.end;
        }
        out.push_str(self.source.get(cursor..).unwrap_or_default());
        (out, removed)
    }
}

// --- header hygiene -----------------------------------------------------------

/// Headers removed after a body rewrite.
pub const REMOVED_AFTER_REWRITE: [&str; 5] = [
    "etag",
    "content-md5",
    "digest",
    "content-digest",
    "repr-digest",
];

/// Headers set after a body rewrite of `new_len` bytes (lowercase names).
pub fn headers_after_rewrite(new_len: usize) -> [(&'static str, String); 2] {
    [
        ("content-length", new_len.to_string()),
        ("cache-control", "no-store".to_owned()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::Source;
    use crate::ids::IdToken;
    use serde_json::json;

    fn config(value: Value) -> Config {
        Config::from_json(value.to_string().as_bytes()).unwrap_or_else(|err| unreachable!("{err}"))
    }

    fn id(raw: &str) -> Id {
        match Id::from_raw(raw) {
            IdToken::Valid(id) => id,
            _ => unreachable!("{raw}"),
        }
    }

    fn lists(body: &str, expected: &[&str], c: &Config) -> ListResult {
        let ids: Vec<Id> = expected.iter().map(|raw| id(raw)).collect();
        match inspect_json(body.as_bytes(), &ids, c) {
            Inspection::Lists(result) => result,
            other => unreachable!("{other:?}"),
        }
    }

    fn outcome(body: &str, expected: &[&str]) -> Inspection {
        let ids: Vec<Id> = expected.iter().map(|raw| id(raw)).collect();
        inspect_json(body.as_bytes(), &ids, &config(json!({})))
    }

    const LIST: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object","maximum":1.50}},{"name":"drop","annotations":{"destructiveHint":true}},{"name":"edit","annotations":{"readOnlyHint":false,"destructiveHint":false}}],"nextCursor":"abc","zeta":12345678901234567890123}}"#;

    // --- pre-checks -----------------------------------------------------------------------

    #[test]
    fn prechecks() {
        assert_eq!(
            precheck(500, None, Some("application/json")),
            Precheck::PassThrough
        );
        assert_eq!(precheck(302, None, None), Precheck::PassThrough);
        assert_eq!(
            precheck(200, Some("gzip"), Some("application/json")),
            Precheck::Stale(StaleReason::Encoded)
        );
        assert_eq!(
            precheck(200, Some("Identity"), Some("application/json")),
            Precheck::Json
        );
        assert_eq!(
            precheck(200, None, Some("Application/JSON; charset=UTF-8")),
            Precheck::Json
        );
        assert_eq!(
            precheck(200, None, Some("application/json; charset=\"utf-8\"")),
            Precheck::Json
        );
        assert_eq!(
            precheck(200, None, Some("text/event-stream; foo=bar")),
            Precheck::Sse
        );
        for unsupported in [
            None,
            Some("application/json; charset=iso-8859-1"),
            Some("text/plain"),
            Some("application/json-seq"),
            Some(""),
        ] {
            assert_eq!(
                precheck(200, None, unsupported),
                Precheck::Stale(StaleReason::UnsupportedContentType),
                "{unsupported:?}"
            );
        }
    }

    // --- inspection -----------------------------------------------------------------------

    #[test]
    fn a_valid_list_is_classified() {
        let result = lists(LIST, &["1"], &config(json!({})));
        let observed: Vec<(&str, Class)> = result
            .observations()
            .iter()
            .map(|(n, p)| (*n, p.class))
            .collect();
        assert_eq!(
            observed,
            vec![
                ("search", Class::Read),
                ("drop", Class::Destructive),
                ("edit", Class::Write)
            ]
        );
        assert_eq!(result.invalid_entries(), 0);
        assert!(result.conflicts().is_empty());
    }

    #[test]
    fn filtering_preserves_every_other_byte() {
        let result = lists(LIST, &["1"], &config(json!({})));
        let (body, removed) = result.rewrite(|name| name != "drop");
        assert_eq!(removed, 1);
        assert_eq!(
            body,
            LIST.replace(
                r#",{"name":"drop","annotations":{"destructiveHint":true}}"#,
                ""
            )
        );
        assert!(body.contains(r#""maximum":1.50"#) && body.contains("12345678901234567890123"));
        assert!(body.ends_with(r#""nextCursor":"abc","zeta":12345678901234567890123}}"#));
        let (unchanged, removed) = result.rewrite(|_| true);
        assert_eq!((unchanged.as_str(), removed), (LIST, 0));
    }

    #[test]
    fn removing_everything_leaves_an_empty_array_and_the_cursor() {
        let result = lists(LIST, &["1"], &config(json!({})));
        let (body, removed) = result.rewrite(|_| false);
        assert_eq!(removed, 3);
        assert!(body.contains(r#""tools":[],"nextCursor":"abc""#), "{body}");
    }

    #[test]
    fn invalid_entries_are_removed_and_never_pinned() {
        let c = config(json!({"limits": {"maxToolNameBytes": 8}}));
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[
            "str", 5, null, [], {"annotations":{}}, {"name":7}, {"name":"waytoolongname"},
            {"name":"ok","annotations":{"readOnlyHint":true}}]}}"#;
        let result = lists(body, &["1"], &c);
        assert_eq!(result.invalid_entries(), 7);
        assert_eq!(result.observations().len(), 1);
        let (out, removed) = result.rewrite(|_| true);
        assert_eq!(removed, 7);
        assert!(
            out.contains(r#""tools":[{"name":"ok","annotations":{"readOnlyHint":true}}]"#),
            "{out}"
        );
    }

    #[test]
    fn blocked_and_overridden_tools_are_listed_but_not_pinned() {
        let c = config(
            json!({"blockedTools": ["drop"], "toolOverrides": [{"name": "edit", "class": "read"}]}),
        );
        let result = lists(LIST, &["1"], &c);
        let names: Vec<&str> = result.observations().iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["search"]);
        assert_eq!(result.tools().count(), 3);
    }

    #[test]
    fn duplicate_tools_are_reported_and_both_observed() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[
            {"name":"t","annotations":{"readOnlyHint":true}},
            {"name":"t","annotations":{"destructiveHint":true}}]}}"#;
        let result = lists(body, &["1"], &config(json!({})));
        assert_eq!(
            result.conflicts(),
            vec![("t", vec![Class::Read, Class::Destructive])]
        );
        let classes: Vec<Class> = result.observations().iter().map(|(_, p)| p.class).collect();
        assert_eq!(
            classes,
            vec![Class::Read, Class::Destructive],
            "the catalog merge keeps the max"
        );
    }

    #[test]
    fn invalid_responses_mark_stale_without_pins() {
        let stale = |reason| Inspection::Stale(reason);
        let invalid = stale(StaleReason::ResponseInvalid);
        let cases = [
            (
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[],"tools":[]}}"#,
                invalid.clone(),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"id":1,"result":{"tools":[]}}"#,
                invalid.clone(),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","name":"b"}]}}"#,
                invalid.clone(),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","annotations":{"readOnlyHint":true,"readOnlyHint":false}}]}}"#,
                invalid.clone(),
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":{}}}"#,
                invalid.clone(),
            ),
            (r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, invalid.clone()),
            (r#"{"jsonrpc":"2.0","id":1,"result":[]}"#, invalid.clone()),
            (
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]},"error":{"code":1,"message":"x"}}"#,
                invalid.clone(),
            ),
            (
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#,
                invalid.clone(),
            ),
            (
                r#"{"jsonrpc":"2.0","id":"1","result":{"tools":[]}}"#,
                invalid.clone(),
            ),
            (
                r#"[{"jsonrpc":"2.0","id":1,"result":{"tools":[]}},{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}]"#,
                invalid.clone(),
            ),
            (
                r#"[{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}, 5]"#,
                invalid.clone(),
            ),
            ("5", invalid.clone()),
            (
                r#"{"jsonrpc":"2.0","id":1,"result":"#,
                stale(StaleReason::ParseError),
            ),
            ("\u{feff}{}", stale(StaleReason::ParseError)),
        ];
        for (body, expected) in cases {
            assert_eq!(outcome(body, &["1"]), expected, "{body}");
        }
    }

    #[test]
    fn error_responses_change_nothing() {
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}"#;
        assert_eq!(outcome(body, &["1"]), Inspection::ErrorsOnly);
    }

    #[test]
    fn a_server_request_reusing_the_list_id_is_ignored() {
        let body = r#"[{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}},
                       {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","annotations":{}}]}}]"#;
        let result = lists(body, &["1"], &config(json!({})));
        assert_eq!(result.observations().len(), 1);
        let only_request = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        assert_eq!(
            outcome(only_request, &["1"]),
            Inspection::Stale(StaleReason::ResponseInvalid)
        );
    }

    #[test]
    fn list_only_batches_rewrite_every_matching_element_in_any_order() {
        let body = r#"[{"jsonrpc":"2.0","id":"b","result":{"tools":[{"name":"x","annotations":{"readOnlyHint":true}},{"name":"y"}]}},{"jsonrpc":"2.0","id":"a","error":{"code":1,"message":"m"}},{"jsonrpc":"2.0","id":"c","result":{"tools":[{"name":"y"}],"nextCursor":"n"}}]"#;
        let result = lists(body, &[r#""a""#, r#""b""#, r#""c""#], &config(json!({})));
        assert_eq!(result.observations().len(), 3);
        let (out, removed) = result.rewrite(|name| name == "x");
        assert_eq!(removed, 2);
        assert_eq!(
            out,
            r#"[{"jsonrpc":"2.0","id":"b","result":{"tools":[{"name":"x","annotations":{"readOnlyHint":true}}]}},{"jsonrpc":"2.0","id":"a","error":{"code":1,"message":"m"}},{"jsonrpc":"2.0","id":"c","result":{"tools":[],"nextCursor":"n"}}]"#
        );
    }

    #[test]
    fn escaped_member_names_are_decoded() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"too\u006cs":[{"n\u0061me":"t","annotations":{"readOnlyHint":true}}]}}"#;
        let result = lists(body, &["1"], &config(json!({})));
        assert_eq!(
            result.observations().first().map(|(n, p)| (*n, p.source)),
            Some(("t", Source::Annotations))
        );
    }

    #[test]
    fn whitespace_between_entries_is_normalised_only_inside_the_array() {
        let body = "{ \"jsonrpc\" : \"2.0\", \"id\" : 1, \"result\" : { \"tools\" : [ {\"name\":\"a\"} ,\n {\"name\":\"b\"} ] } }";
        let result = lists(body, &["1"], &config(json!({})));
        let (out, _) = result.rewrite(|_| true);
        assert_eq!(
            out,
            "{ \"jsonrpc\" : \"2.0\", \"id\" : 1, \"result\" : { \"tools\" : [{\"name\":\"a\"},{\"name\":\"b\"}] } }"
        );
    }

    #[test]
    fn audit_mode_and_disabled_filtering_still_learn_pins() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[
            {"name":"search","annotations":{"readOnlyHint":true}},
            {"name":"drop","annotations":{"destructiveHint":true}}]}}"#;
        let enforce = config(json!({}));
        let expected = lists(body, &["1"], &enforce).observations().len();
        assert_eq!(expected, 2);
        for c in [
            config(json!({"mode": "audit"})),
            config(json!({"filterToolsList": false})),
        ] {
            assert!(!crate::decide::filtering_active(&c));
            let result = lists(body, &["1"], &c);
            let learned: Vec<(&str, Class)> = result
                .observations()
                .iter()
                .map(|(n, p)| (*n, p.class))
                .collect();
            assert_eq!(
                learned,
                vec![("search", Class::Read), ("drop", Class::Destructive)]
            );
        }
    }

    #[test]
    fn header_hygiene() {
        let set = headers_after_rewrite(42);
        assert_eq!(set[0], ("content-length", "42".to_owned()));
        assert_eq!(set[1], ("cache-control", "no-store".to_owned()));
        assert!(
            REMOVED_AFTER_REWRITE.contains(&"etag")
                && REMOVED_AFTER_REWRITE.contains(&"repr-digest")
        );
    }
}
