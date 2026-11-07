// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! SSE parsing and the buffered SSE mode.
//!
//! The whole stream is buffered and processed all-or-nothing: either every
//! target event is rewritten, or the stream is forwarded unchanged.
//!
//! Design choices:
//! - The stream is read the way clients read it: invalid UTF-8 becomes
//!   U+FFFD and one leading byte-order mark is removed (and re-emitted when
//!   the stream is rewritten, so a second one never becomes visible).
//! - An event whose `data` does not start like JSON, or is JSON that no
//!   client could take for a response to a marked id (a heartbeat, a
//!   notification, a response to another id), is forwarded unchanged and does
//!   not affect the result. One that might be such a response but cannot be
//!   validated is `response_invalid`: duplicate keys, a malformed envelope, a
//!   batch, JSON-looking data the guard cannot parse, or an id a client
//!   converts to a marked one (`"1"` or `1.0` for `1`).
//! - A stream that starts with a byte-order mark misread as Latin-1 is
//!   `response_invalid`, because some clients strip it and read the first
//!   event that a spec parser ignores.
//! - A trailing event without its terminating empty line is never dispatched
//!   (WHATWG) and is forwarded unchanged.
//! - `notifications/tools/list_changed` marks the catalog stale only when it
//!   follows the last target event; a change announced before the list is
//!   already reflected in it.
//! - No target event in a complete stream is `response_invalid`.

use std::collections::HashSet;
use std::fmt;

use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::value::RawValue;

use crate::config::Config;
use crate::envelope::{check_strict_json, parse_message, Kind, StrictError};
use crate::filter::{inspect, Inspection, ListResult, Rewritten, BOM};
use crate::freshness::StaleReason;
use crate::ids::{self, Id};

pub const LIST_CHANGED: &str = "notifications/tools/list_changed";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Line {
    /// A field other than `data`, or a comment: re-emitted as is.
    Keep(String),
    Data,
}

/// One dispatched event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// The exact bytes of the event, including its terminating empty line.
    raw: String,
    lines: Vec<Line>,
    /// `data` lines joined with `\n`; `None` if the event has none.
    pub data: Option<String>,
}

/// Splits a stream into dispatched events and the undispatched tail.
pub fn parse_events(stream: &str) -> (Vec<Event>, &str) {
    let mut events = Vec::new();
    let mut lines = Vec::new();
    let mut data: Option<String> = None;
    let mut event_start = 0;
    let mut pos = 0;
    while let Some((line, next)) = next_line(stream, pos) {
        pos = next;
        if line.is_empty() {
            if !lines.is_empty() || data.is_some() {
                events.push(Event {
                    raw: stream.get(event_start..pos).unwrap_or_default().to_owned(),
                    lines: std::mem::take(&mut lines),
                    data: data.take(),
                });
            }
            event_start = pos;
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        if field == "data" {
            match &mut data {
                Some(existing) => {
                    existing.push('\n');
                    existing.push_str(value);
                }
                None => data = Some(value.to_owned()),
            }
            lines.push(Line::Data);
        } else {
            // Comments (empty field name) and other fields.
            lines.push(Line::Keep(line.to_owned()));
        }
    }
    (events, stream.get(event_start..).unwrap_or_default())
}

/// The next complete line starting at `pos` and the position after its end
/// (`\n`, `\r\n` or `\r`). An unterminated last line is not complete. The
/// stream is complete (buffered mode), so a final `\r` is a line end.
fn next_line(stream: &str, pos: usize) -> Option<(&str, usize)> {
    let rest = stream.get(pos..)?;
    let end = rest.find(['\n', '\r'])?;
    let line = rest.get(..end)?;
    let after = match rest.as_bytes().get(end..end + 2) {
        Some(b"\r\n") => end + 2,
        _ => end + 1,
    };
    Some((line, pos + after))
}

impl Event {
    /// The event with its `data` replaced: non-`data` lines unchanged
    /// and in order, then `data` as `data:` lines, then the empty line.
    fn rewritten(&self, data: &str) -> String {
        let mut out = String::with_capacity(data.len() + 64);
        for line in &self.lines {
            if let Line::Keep(text) = line {
                out.push_str(text);
                out.push('\n');
            }
        }
        // `data` holds no `\r`, and each `\n` in it joined two `data` lines,
        // so one `data:` line per piece decodes back to exactly `data`.
        for piece in data.split('\n') {
            out.push_str("data: ");
            out.push_str(piece);
            out.push('\n');
        }
        out.push('\n');
        out
    }
}

// --- buffered mode ------------------------------------------------------------------------

/// What the buffered stream contained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamInspection {
    /// Only error responses answer the marked ids: forward, no change.
    ErrorsOnly,
    /// Forward unchanged, no pins, mark stale.
    Stale(StaleReason),
    Lists(StreamLists),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamLists {
    /// The stream started with a byte-order mark.
    bom: bool,
    events: Vec<Event>,
    tail: String,
    /// `(event index, list)` for every target event.
    targets: Vec<(usize, ListResult)>,
    /// `list_changed` seen after the last target event.
    pub list_changed_after: bool,
}

/// Inspects a complete buffered stream (buffered mode).
pub fn inspect_stream(stream: &[u8], expected: &[Id], config: &Config) -> StreamInspection {
    let decoded = String::from_utf8_lossy(stream);
    let (bom, text) = match decoded.strip_prefix(BOM) {
        Some(rest) => (true, rest),
        None => (false, decoded.as_ref()),
    };
    if text.starts_with(MISREAD_BOM) {
        return StreamInspection::Stale(StaleReason::ResponseInvalid);
    }
    let (events, tail) = parse_events(text);
    let mut targets = Vec::new();
    let mut errors_only = false;
    let mut list_changed_at = None;
    for (index, event) in events.iter().enumerate() {
        let Some(data) = &event.data else { continue };
        let strict = check_strict_json(data.as_bytes());
        if strict == Err(StrictError::Parse) {
            if looks_like_json(data) {
                return StreamInspection::Stale(StaleReason::ResponseInvalid);
            }
            continue;
        }
        if is_list_changed(data) {
            list_changed_at = Some(index);
            continue;
        }
        if strict == Err(StrictError::DuplicateKeys) {
            if may_answer(data, expected) {
                return StreamInspection::Stale(StaleReason::ResponseInvalid);
            }
            continue;
        }
        match inspect(data.as_bytes(), expected, config) {
            Inspection::NotFound => {}
            Inspection::ErrorsOnly => errors_only = true,
            Inspection::Stale(StaleReason::ResponseInvalid) if !may_answer(data, expected) => {}
            Inspection::Stale(reason) => return StreamInspection::Stale(reason),
            Inspection::Lists(list) => targets.push((index, list)),
        }
    }
    let last_target = targets.last().map(|(index, _)| *index);
    if targets.is_empty() {
        return match (list_changed_at, errors_only) {
            (Some(_), _) => StreamInspection::Stale(StaleReason::ListChanged),
            (None, true) => StreamInspection::ErrorsOnly,
            (None, false) => StreamInspection::Stale(StaleReason::ResponseInvalid),
        };
    }
    StreamInspection::Lists(StreamLists {
        list_changed_after: list_changed_at > last_target,
        bom,
        events,
        tail: tail.to_owned(),
        targets,
    })
}

/// Whether some client might read `data` (JSON the guard could not validate
/// as a message) as a response to a marked id: a batch, an object whose
/// top-level keys repeat, or an object whose `id` is a marked id.
fn may_answer(data: &str, expected: &[Id]) -> bool {
    match data.trim_start().as_bytes().first() {
        Some(b'{') => {}
        Some(b'[') => return true,
        _ => return false,
    }
    let Ok(top) = serde_json::from_str::<TopLevel<'_>>(data) else {
        return true;
    };
    top.duplicate
        || top
            .id
            .is_some_and(|raw| ids::may_answer(raw.get(), expected))
}

/// Data the guard cannot parse but a client might: JavaScript's
/// `JSON.parse` accepts numbers beyond the range of `f64`, unpaired
/// surrogate escapes and deeper nesting.
fn looks_like_json(data: &str) -> bool {
    matches!(data.trim_start().as_bytes().first(), Some(b'{' | b'['))
}

/// A byte-order mark decoded as Latin-1 (`ï»¿`). The SSE parser of the MCP
/// TypeScript SDK removes it from the start of a stream; parsers that follow
/// the specification read the first line as an unknown field instead.
const MISREAD_BOM: &str = "\u{ef}\u{bb}\u{bf}";

/// The top-level `id` of a JSON object, and whether any top-level key
/// repeats (after decoding escapes).
struct TopLevel<'a> {
    duplicate: bool,
    id: Option<&'a RawValue>,
}

impl<'de> Deserialize<'de> for TopLevel<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(TopLevelVisitor)
    }
}

struct TopLevelVisitor;

impl<'de> Visitor<'de> for TopLevelVisitor {
    type Value = TopLevel<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<TopLevel<'de>, A::Error> {
        let mut seen = HashSet::new();
        let mut top = TopLevel {
            duplicate: false,
            id: None,
        };
        while let Some(key) = map.next_key::<String>()? {
            if key == "id" {
                top.id = Some(map.next_value()?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
            if !seen.insert(key) {
                top.duplicate = true;
            }
        }
        Ok(top)
    }
}

fn is_list_changed(data: &str) -> bool {
    let Ok(raw) = serde_json::from_str::<&serde_json::value::RawValue>(data) else {
        return false;
    };
    parse_message(raw).is_ok_and(|message| {
        message.kind == Kind::Notification && message.method.as_deref() == Some(LIST_CHANGED)
    })
}

impl StreamLists {
    /// Every list found in target events.
    pub fn lists(&self) -> impl Iterator<Item = &ListResult> {
        self.targets.iter().map(|(_, list)| list)
    }

    /// The stream with every target event rewritten by `keep` (see
    /// [`ListResult::rewrite`]); every other event and the tail are unchanged.
    pub fn rewrite(&self, mut keep: impl FnMut(&str) -> bool) -> Rewritten {
        let mut out = String::new();
        if self.bom {
            out.push_str(BOM);
        }
        let mut removed = 0;
        let mut scoped = 0;
        let mut targets = self.targets.iter().peekable();
        for (index, event) in self.events.iter().enumerate() {
            match targets.next_if(|(target, _)| *target == index) {
                Some((_, list)) => {
                    let data = list.rewrite(&mut keep);
                    removed += data.removed;
                    scoped += data.scoped;
                    out.push_str(&event.rewritten(&data.body));
                }
                None => out.push_str(&event.raw),
            }
        }
        out.push_str(&self.tail);
        Rewritten {
            body: out,
            removed,
            scoped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_view;
    use crate::ids::IdToken;
    use serde_json::json;

    fn config() -> Config {
        Config::from_json(b"{}").unwrap_or_else(|err| unreachable!("{err}"))
    }

    fn id(raw: &str) -> Id {
        match Id::from_raw(raw) {
            IdToken::Valid(id) => id,
            _ => unreachable!("{raw}"),
        }
    }

    fn inspect1(stream: &str) -> StreamInspection {
        inspect_stream(stream.as_bytes(), &[id("1")], &config())
    }

    fn lists(stream: &str) -> StreamLists {
        match inspect1(stream) {
            StreamInspection::Lists(lists) => lists,
            other => unreachable!("{other:?}"),
        }
    }

    const RESULT: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","annotations":{"readOnlyHint":true}},{"name":"b"}]}}"#;
    const FILTERED: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","annotations":{"readOnlyHint":true}}]}}"#;

    // --- parsing ------------------------------------------------------------------------

    #[test]
    fn line_endings_and_multi_line_data() {
        for sep in ["\n", "\r\n", "\r"] {
            let stream =
                format!("event: message{sep}data: one{sep}data:two{sep}data:  three{sep}{sep}tail");
            let (events, tail) = parse_events(&stream);
            assert_eq!(events.len(), 1, "{sep:?}");
            assert_eq!(
                events.first().and_then(|e| e.data.as_deref()),
                Some("one\ntwo\n three")
            );
            assert_eq!(tail, "tail");
        }
    }

    #[test]
    fn comments_and_fields_without_values() {
        let (events, tail) = parse_events(": keep-alive\n\ndata\n\nid: 5\nretry: 10\n: c\n\n");
        assert_eq!(events.len(), 3);
        assert_eq!(events.first().and_then(|e| e.data.clone()), None);
        assert_eq!(events.get(1).and_then(|e| e.data.as_deref()), Some(""));
        assert_eq!(tail, "");
    }

    #[test]
    fn an_unterminated_event_is_not_dispatched() {
        let (events, tail) = parse_events("data: {}\n\ndata: {\"partial\"");
        assert_eq!(events.len(), 1);
        assert_eq!(tail, "data: {\"partial\"");
        let (events, tail) = parse_events("data: x\n");
        assert!(events.is_empty());
        assert_eq!(tail, "data: x\n");
        let (events, tail) = parse_events("data: x\r\r");
        assert_eq!(events.len(), 1, "CR-only endings at the end of the stream");
        assert_eq!(tail, "");
    }

    // --- buffered processing ----------------------------------------------------------------

    #[test]
    fn only_the_target_event_is_rewritten() {
        let stream = format!(
            ": hello\n\nid: 7\nevent: message\ndata: {RESULT}\n\ndata: not json\n\nevent: other\r\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{}}}}\r\n\r\n"
        );
        let found = lists(&stream);
        let Rewritten {
            body: out, removed, ..
        } = found.rewrite(|name| name == "a");
        assert_eq!(removed, 1);
        assert_eq!(
            out,
            format!(
                ": hello\n\nid: 7\nevent: message\ndata: {FILTERED}\n\ndata: not json\n\nevent: other\r\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{}}}}\r\n\r\n"
            )
        );
        assert!(!found.list_changed_after);
    }

    /// The one list a client reads for id 1 from `out`.
    fn client_tools(out: &str) -> Vec<String> {
        let mut found = client_view::sse_lists(out.as_bytes(), 1);
        assert_eq!(found.len(), 1, "one readable response to id 1 in {out:?}");
        found.pop().unwrap_or_default()
    }

    /// `text` split before each of `marks`.
    fn split_before<'a>(text: &'a str, marks: &[&str]) -> Vec<&'a str> {
        let mut pieces = Vec::new();
        let mut rest = text;
        for mark in marks {
            let at = rest.find(mark).unwrap_or_else(|| unreachable!("{mark}"));
            let (piece, tail) = rest.split_at(at);
            pieces.push(piece);
            rest = tail;
        }
        pieces.push(rest);
        pieces
    }

    #[test]
    fn a_rewritten_multi_line_event_decodes_for_clients() {
        let p = split_before(RESULT, &["\"id\"", "{\"name\":\"b\""]);
        let [head, mid, tail] = p.as_slice() else {
            unreachable!()
        };
        let streams = [
            format!("id: 3\ndata: {head}\ndata: {mid}{tail}\n: note\n\n"),
            format!(
                "id: 3\r\nevent: message\r\ndata: {head}\r\ndata: {mid}\r\ndata: {tail}\r\n\r\n"
            ),
            format!("data:{head}\ndata\ndata:{mid}\ndata:{tail}\n\n"),
            format!("data: {head}\ndata:  {mid}\rdata: {tail}\r\r"),
        ];
        for stream in &streams {
            for keep in ["a", "b"] {
                let Rewritten {
                    body: out, removed, ..
                } = lists(stream).rewrite(|name| name == keep);
                assert_eq!(removed, 1, "{stream:?}");
                assert_eq!(client_tools(&out), [keep], "{stream:?} -> {out:?}");
            }
        }
        let Rewritten { body: out, .. } =
            lists(streams.first().map_or("", String::as_str)).rewrite(|_| false);
        let events = client_view::sse_events(out.as_bytes());
        assert_eq!(
            events.first().map(|e| e.last_event_id.as_str()),
            Some("3"),
            "the event id survives"
        );
    }

    #[test]
    fn a_rewritten_event_keeps_an_entry_split_across_lines() {
        let stream = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"},\ndata: {\"name\":\"b\",\ndata: \"annotations\":{\"readOnlyHint\":true}}]}}\n\n";
        for keep in ["a", "b"] {
            let Rewritten { body: out, .. } = lists(stream).rewrite(|name| name == keep);
            assert_eq!(client_tools(&out), [keep], "{out:?}");
        }
    }

    #[test]
    fn one_leading_bom_is_removed_like_a_client_does() {
        for stream in [
            format!("\u{feff}data: {RESULT}\n\n"),
            format!("\u{feff}event: message\ndata: {RESULT}\n\n"),
            format!("\u{feff}: hello\n\ndata: {RESULT}\n\n"),
        ] {
            let Rewritten {
                body: out, removed, ..
            } = lists(&stream).rewrite(|name| name == "a");
            assert_eq!(removed, 1, "{stream:?}");
            assert_eq!(client_tools(&out), ["a"], "{out:?}");
        }
    }

    #[test]
    fn only_one_bom_is_removed() {
        // A client removes one BOM; the second makes the first line an unknown field.
        assert_eq!(
            inspect1(&format!("\u{feff}\u{feff}data: {RESULT}\n\n")),
            StreamInspection::Stale(StaleReason::ResponseInvalid)
        );
        let stream = format!("\u{feff}\u{feff}data: {RESULT}\n\ndata: {RESULT}\n\n");
        let Rewritten {
            body: out, removed, ..
        } = lists(&stream).rewrite(|name| name == "a");
        assert_eq!(removed, 1);
        assert_eq!(client_tools(&out), ["a"], "{out:?}");
    }

    #[test]
    fn a_misread_bom_at_the_start_marks_stale() {
        for stream in [
            format!("\u{ef}\u{bb}\u{bf}data: {RESULT}\n\ndata: {RESULT}\n\n"),
            format!("\u{feff}\u{ef}\u{bb}\u{bf}data: {RESULT}\n\ndata: {RESULT}\n\n"),
            format!("\u{ef}\u{bb}\u{bf}: hello\n\ndata: {RESULT}\n\n"),
        ] {
            assert_eq!(
                inspect1(&stream),
                StreamInspection::Stale(StaleReason::ResponseInvalid),
                "{stream:?}"
            );
        }
    }

    #[test]
    fn a_response_a_client_could_read_for_the_list_id_marks_stale() {
        let list = |id: &str, extra: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"tools":[{{"name":"a","annotations":{{"readOnlyHint":true}}}},{{"name":"b"}}]{extra}}}}}"#
            )
        };
        let deep = format!(
            r#","_meta":{{"d":{}1{}}}"#,
            "[".repeat(130),
            "]".repeat(130)
        );
        let doubtful = [
            // IDs a client converts to 1.
            list(r#""1""#, ""),
            list("1.0", ""),
            list("1e0", ""),
            list(r#""0x1""#, ""),
            list(r#""1""#, r#","_meta":{"k":1,"k":2}"#),
            // JSON that JavaScript parses and the guard cannot.
            list("1", r#","_meta":{"n":1e400}"#),
            list("1", r#","_meta":{"s":"\ud83d"}"#),
            list("1", &deep),
        ];
        let error = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"x"}}"#;
        for first in &doubtful {
            for stream in [
                format!("data: {first}\n\n"),
                format!("data: {first}\n\ndata: {RESULT}\n\n"),
                format!("data: {first}\n\ndata: {error}\n\n"),
                format!("data: {RESULT}\n\ndata: {first}\n\n"),
            ] {
                assert_eq!(
                    inspect1(&stream),
                    StreamInspection::Stale(StaleReason::ResponseInvalid),
                    "{stream}"
                );
            }
        }
        // The client model reads the converted IDs as answers too.
        assert_eq!(
            client_view::sse_lists(format!("data: {}\n\n", list(r#""0x1""#, "")).as_bytes(), 1),
            [["a", "b"]]
        );
    }

    #[test]
    fn invalid_utf8_is_decoded_like_a_client_does() {
        let stream = [
            b": \xff\n\n".as_slice(),
            format!("data: {RESULT}\n\n").as_bytes(),
        ]
        .concat();
        let StreamInspection::Lists(found) = inspect_stream(&stream, &[id("1")], &config()) else {
            unreachable!("a bad byte in a comment poisons the stream")
        };
        let Rewritten { body: out, .. } = found.rewrite(|name| name == "a");
        assert_eq!(client_tools(&out), ["a"]);

        let target = RESULT.replace("{\"name\":\"b\"}", "{\"name\":\"b\",\"description\":\"X\"}");
        let stream = format!("data: {target}\n\n")
            .replace('X', "\u{0}")
            .into_bytes();
        let stream: Vec<u8> = stream
            .into_iter()
            .map(|b| if b == 0 { 0xFF } else { b })
            .collect();
        let StreamInspection::Lists(found) = inspect_stream(&stream, &[id("1")], &config()) else {
            unreachable!("a bad byte in the target is read as U+FFFD")
        };
        let Rewritten { body: out, .. } = found.rewrite(|name| name == "a");
        assert_eq!(client_tools(&out), ["a"]);
    }

    #[test]
    fn json_events_that_are_not_responses_are_ignored() {
        for other in [
            "event: ping\ndata: {}\n\n",
            "data: {\"type\":\"heartbeat\"}\n\n",
            "data: 5\n\n",
            "data: \"ping\"\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"a\":1,\"a\":2}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"x\":1,\"x\":2}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":true,\"result\":{}}\n\n",
        ] {
            for stream in [
                format!("{other}data: {RESULT}\n\n"),
                format!("data: {RESULT}\n\n{other}"),
            ] {
                let StreamInspection::Lists(found) = inspect1(&stream) else {
                    unreachable!("{stream:?} -> {:?}", inspect1(&stream))
                };
                let Rewritten { body: out, removed, .. } = found.rewrite(|name| name == "a");
                assert_eq!(removed, 1, "{stream:?}");
                assert_eq!(client_tools(&out), ["a"], "{out:?}");
            }
        }
    }

    #[test]
    fn a_doubtful_response_to_the_list_id_marks_stale() {
        for doubtful in [
            r#"{"id":1,"result":{"tools":[]}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"x","result":{"tools":[]}}"#,
            r#"{"jsonrpc":"2.0","id":2,"id":1,"result":{"tools":[]}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","name":"b"}]}}"#,
            r#"{"a":1,"a":2}"#,
            r#"[{"type":"heartbeat"}]"#,
        ] {
            assert_eq!(
                inspect1(&format!("data: {doubtful}\n\ndata: {RESULT}\n\n")),
                StreamInspection::Stale(StaleReason::ResponseInvalid),
                "{doubtful}"
            );
        }
    }

    #[test]
    fn invalid_target_marks_stale() {
        let stream = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":5}}\n\n";
        assert_eq!(
            inspect1(stream),
            StreamInspection::Stale(StaleReason::ResponseInvalid)
        );
    }

    #[test]
    fn no_target_event_marks_stale() {
        assert_eq!(
            inspect1("data: hello\n\n"),
            StreamInspection::Stale(StaleReason::ResponseInvalid)
        );
        let truncated = format!("data: {RESULT}");
        assert_eq!(
            inspect1(&truncated),
            StreamInspection::Stale(StaleReason::ResponseInvalid)
        );
    }

    #[test]
    fn error_responses_change_nothing() {
        let stream =
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-1,\"message\":\"m\"}}\n\n";
        assert_eq!(inspect1(stream), StreamInspection::ErrorsOnly);
    }

    #[test]
    fn a_server_request_with_the_same_id_is_not_the_target() {
        let stream = format!("data: {{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"roots/list\"}}\n\ndata: {RESULT}\n\n");
        let found = lists(&stream);
        let Rewritten {
            body: out, removed, ..
        } = found.rewrite(|_| false);
        assert_eq!(removed, 2);
        assert!(
            out.starts_with("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"roots/list\"}\n\n")
        );
    }

    #[test]
    fn list_changed_after_the_list_marks_stale() {
        let changed = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        let after = lists(&format!("data: {RESULT}\n\ndata: {changed}\n\n"));
        assert!(after.list_changed_after);
        let before = lists(&format!("data: {changed}\n\ndata: {RESULT}\n\n"));
        assert!(!before.list_changed_after);
        assert_eq!(
            inspect1(&format!("data: {changed}\n\n")),
            StreamInspection::Stale(StaleReason::ListChanged)
        );
        let Rewritten { body: out, .. } = after.rewrite(|_| true);
        assert!(
            out.ends_with(&format!("data: {changed}\n\n")),
            "the notification is forwarded"
        );
    }

    #[test]
    fn batched_target_in_one_event() {
        let data =
            json!([{"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "x"}]}}]).to_string();
        let found = lists(&format!("data: {data}\n\n"));
        assert_eq!(found.lists().count(), 1);
    }
}
