// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! SSE parsing and the buffered SSE mode.
//!
//! The whole stream is buffered and processed all-or-nothing: either every
//! target event is rewritten, or the stream is forwarded unchanged.
//!
//! Design choices:
//! - An event whose `data` is not JSON is forwarded unchanged; one whose
//!   `data` is JSON with duplicate keys is `response_invalid`, since it might
//!   be the target.
//! - A trailing event without its terminating empty line is never dispatched
//!   (WHATWG) and is forwarded unchanged.
//! - `notifications/tools/list_changed` marks the catalog stale only when it
//!   follows the last target event; a change announced before the list is
//!   already reflected in it.
//! - No target event in a complete stream is `response_invalid`.

use crate::config::Config;
use crate::envelope::{check_strict_json, parse_message, Kind, StrictError};
use crate::filter::{inspect, Inspection, ListResult};
use crate::freshness::StaleReason;
use crate::ids::Id;

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
    /// and in order, then one `data:` line, then the empty line.
    fn rewritten(&self, data: &str) -> String {
        let mut out = String::with_capacity(data.len() + 64);
        for line in &self.lines {
            if let Line::Keep(text) = line {
                out.push_str(text);
                out.push('\n');
            }
        }
        out.push_str("data: ");
        out.push_str(data);
        out.push_str("\n\n");
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
    events: Vec<Event>,
    tail: String,
    /// `(event index, list)` for every target event.
    targets: Vec<(usize, ListResult)>,
    /// `list_changed` seen after the last target event.
    pub list_changed_after: bool,
}

/// Inspects a complete buffered stream (buffered mode).
pub fn inspect_stream(stream: &[u8], expected: &[Id], config: &Config) -> StreamInspection {
    let Ok(stream) = std::str::from_utf8(stream) else {
        return StreamInspection::Stale(StaleReason::ParseError);
    };
    let (events, tail) = parse_events(stream);
    let mut targets = Vec::new();
    let mut errors_only = false;
    let mut list_changed_at = None;
    for (index, event) in events.iter().enumerate() {
        let Some(data) = &event.data else { continue };
        match check_strict_json(data.as_bytes()) {
            Ok(()) => {}
            Err(StrictError::Parse) => continue,
            Err(StrictError::DuplicateKeys) => {
                return StreamInspection::Stale(StaleReason::ResponseInvalid)
            }
        }
        if is_list_changed(data) {
            list_changed_at = Some(index);
            continue;
        }
        match inspect(data.as_bytes(), expected, config) {
            Inspection::NotFound => {}
            Inspection::ErrorsOnly => errors_only = true,
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
        events,
        tail: tail.to_owned(),
        targets,
    })
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

    /// The stream with every target event rewritten by `keep`; every other
    /// event and the tail are unchanged. Returns the stream and the number of
    /// entries removed.
    pub fn rewrite(&self, mut keep: impl FnMut(&str) -> bool) -> (String, usize) {
        let mut out = String::new();
        let mut removed = 0;
        let mut targets = self.targets.iter().peekable();
        for (index, event) in self.events.iter().enumerate() {
            match targets.next_if(|(target, _)| *target == index) {
                Some((_, list)) => {
                    let (data, n) = list.rewrite(&mut keep);
                    removed += n;
                    out.push_str(&event.rewritten(&data));
                }
                None => out.push_str(&event.raw),
            }
        }
        out.push_str(&self.tail);
        (out, removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let (out, removed) = found.rewrite(|name| name == "a");
        assert_eq!(removed, 1);
        assert_eq!(
            out,
            format!(
                ": hello\n\nid: 7\nevent: message\ndata: {FILTERED}\n\ndata: not json\n\nevent: other\r\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{}}}}\r\n\r\n"
            )
        );
        assert!(!found.list_changed_after);
    }

    #[test]
    fn multi_line_target_data_becomes_one_line() {
        let stream = "id: 3\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"}]}}\n: note\n\n";
        let (out, _) = lists(stream).rewrite(|_| true);
        assert_eq!(
            out,
            "id: 3\n: note\ndata: {\"jsonrpc\":\"2.0\",\n\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"}]}}\n\n"
        );
    }

    #[test]
    fn duplicate_keys_in_any_json_event_mark_stale() {
        let stream = format!("data: {{\"a\":1,\"a\":2}}\n\ndata: {RESULT}\n\n");
        assert_eq!(
            inspect1(&stream),
            StreamInspection::Stale(StaleReason::ResponseInvalid)
        );
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
        let (out, removed) = found.rewrite(|_| false);
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
        let (out, _) = after.rewrite(|_| true);
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

    #[test]
    fn invalid_utf8_is_a_parse_error() {
        assert_eq!(
            inspect_stream(b"data: \xff\n\n", &[id("1")], &config()),
            StreamInspection::Stale(StaleReason::ParseError)
        );
    }
}
