// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Test helpers that read the guard's output the way MCP clients do, so
//! tests check what a client receives instead of comparing against strings
//! built from the implementation. Written separately from `sse.rs`.

use serde_json::Value;

/// One event as a WHATWG `EventSource` client dispatches it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientEvent {
    pub event_type: String,
    pub data: String,
    pub last_event_id: String,
}

/// WHATWG event-stream interpretation: UTF-8 decode (one leading BOM
/// removed, invalid bytes replaced), `\n`, `\r\n` and `\r` line ends,
/// dispatch on an empty line, and the unterminated end discarded.
pub fn sse_events(bytes: &[u8]) -> Vec<ClientEvent> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let text = String::from_utf8_lossy(bytes);
    let mut events = Vec::new();
    let (mut data, mut event_type, mut last_event_id) =
        (String::new(), String::new(), String::new());
    let mut line = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\r' && c != '\n' {
            line.push(c);
            continue;
        }
        if c == '\r' && chars.peek() == Some(&'\n') {
            chars.next();
        }
        let line = std::mem::take(&mut line);
        if line.is_empty() {
            if !data.is_empty() {
                data.pop();
                events.push(ClientEvent {
                    event_type: if event_type.is_empty() {
                        "message".to_owned()
                    } else {
                        event_type.clone()
                    },
                    data: std::mem::take(&mut data),
                    last_event_id: last_event_id.clone(),
                });
            }
            event_type.clear();
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line.as_str(), ""),
        };
        match field {
            "event" => event_type = value.to_owned(),
            "data" => {
                data.push_str(value);
                data.push('\n');
            }
            "id" if !value.contains('\0') => last_event_id = value.to_owned(),
            _ => {}
        }
    }
    events
}

/// The tool names in `data` if it parses (like `JSON.parse`) as a response
/// to `id` with a `result.tools` array.
pub fn tools_answering(data: &str, id: u64) -> Option<Vec<String>> {
    let value: Value = serde_json::from_str(data).ok()?;
    if request_number(value.get("id")?)? != id as f64 {
        return None;
    }
    let tools = value.get("result")?.get("tools")?.as_array()?;
    Some(
        tools
            .iter()
            .filter_map(|tool| tool.get("name")?.as_str().map(str::to_owned))
            .collect(),
    )
}

/// The request a response is matched to by the MCP TypeScript SDK, which
/// accepts a string or integer `id` and looks it up with `Number(id)`.
fn request_number(id: &Value) -> Option<f64> {
    match id {
        Value::Number(number) => number.as_f64().filter(|n| n.fract() == 0.0),
        Value::String(text) => {
            let text = text.trim();
            if text.is_empty() {
                return Some(0.0);
            }
            for (prefix, radix) in [
                ("0x", 16),
                ("0X", 16),
                ("0o", 8),
                ("0O", 8),
                ("0b", 2),
                ("0B", 2),
            ] {
                if let Some(digits) = text.strip_prefix(prefix) {
                    return u64::from_str_radix(digits, radix).ok().map(|n| n as f64);
                }
            }
            if text.contains(|c: char| c.is_ascii_alphabetic() && !matches!(c, 'e' | 'E')) {
                return None;
            }
            text.parse::<f64>().ok().filter(|n| n.is_finite())
        }
        _ => None,
    }
}

/// Every list answering `id` in `message` events of an SSE stream.
pub fn sse_lists(bytes: &[u8], id: u64) -> Vec<Vec<String>> {
    sse_events(bytes)
        .iter()
        .filter(|event| event.event_type == "message")
        .filter_map(|event| tools_answering(&event.data, id))
        .collect()
}

/// The list answering `id` in a JSON body, read like `fetch().json()`:
/// one leading BOM removed, invalid bytes replaced.
pub fn json_list(bytes: &[u8], id: u64) -> Option<Vec<String>> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    tools_answering(&String::from_utf8_lossy(bytes), id)
}
