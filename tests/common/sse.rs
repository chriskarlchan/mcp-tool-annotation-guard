// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Reads an event stream the way an EventSource client does, so tests check
//! what a client receives.

/// The `data` of every dispatched event: one leading byte-order mark
/// removed, `\r\n`, `\r` and `\n` line ends, `data` lines joined with `\n`,
/// one space after the colon removed, and an event dispatched only at an
/// empty line. Text after the last line end is an unfinished line, and an
/// event that is not followed by an empty line is never dispatched.
pub fn sse_events(stream: &str) -> Vec<String> {
    let stream = stream.strip_prefix('\u{feff}').unwrap_or(stream);
    let mut lines: Vec<&str> = stream
        .split("\r\n")
        .flat_map(|l| l.split(['\r', '\n']))
        .collect();
    lines.pop();
    let mut events = Vec::new();
    let mut data: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            events.extend(data.take());
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        if field == "data" {
            match data.as_mut() {
                Some(d) => {
                    d.push('\n');
                    d.push_str(value);
                }
                None => data = Some(value.to_owned()),
            }
        }
    }
    events
}

#[test]
fn only_events_followed_by_an_empty_line_are_dispatched() {
    assert_eq!(sse_events("data: a\n\n"), ["a"]);
    assert_eq!(sse_events("data: a\r\n\r\ndata: b\r\r"), ["a", "b"]);
    assert_eq!(sse_events("\u{feff}data: a\ndata: b\n\n"), ["a\nb"]);
    assert!(sse_events("data: a\n").is_empty());
    assert!(sse_events("data: a").is_empty());
    assert!(sse_events("event: message\ndata: {").is_empty());
}
