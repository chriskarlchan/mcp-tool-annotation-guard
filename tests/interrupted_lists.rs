// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! List responses that stop part-way through their body: the upstream closes
//! the connection, or stops sending until the gateway's response timeout
//! ends the request. Both for JSON and SSE.
//!
//! Each case starts from a catalog in which `operate` is read-only, so a
//! default caller may call it. The server then sends a list that marks it
//! destructive and stops. The client must not get that list, the catalog must
//! be stale (the call is refused `unknown_tool` and never reaches the server),
//! and a list the guard can inspect must make it fresh again. An event stream
//! the upstream closes mid-event is a complete body to the gateway and is
//! forwarded, but its unterminated last event is never dispatched by a client.
//! A client that hangs up before the list arrives has the same effect, and a
//! later page that doesn't show `operate` does not make it trusted again.
//!
//! The upstream is a small server in this test, on host port
//! `INTERRUPTED_MOCK_PORT` (default 8091), reached from the gateway container
//! at `host.docker.internal`. The Response Timeout policy (2 s) runs before
//! the guard.
//!
//! Opt-in (needs Docker Desktop): `make build && cargo test --test
//! interrupted_lists -- --ignored --nocapture`

mod common;
#[path = "common/sse.rs"]
mod sse;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::HttpMockConfig;
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;
use sse::sse_events;

const PORT: Port = 8081;
const RESPONSE_TIMEOUT_SECONDS: u64 = 2;
/// How long a stalled upstream waits before closing, well past the timeout.
const STALL: Duration = Duration::from_secs(20);

fn mock_port() -> u16 {
    std::env::var("INTERRUPTED_MOCK_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8091)
}

fn read_only_list() -> String {
    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "operate", "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": true}}
    ], "nextCursor": "p2"}})
    .to_string()
}

/// A later page, without `operate`.
fn page_two() -> String {
    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "other", "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": true}}
    ]}})
    .to_string()
}

/// The start of a list in which `operate` is destructive; it never ends.
fn destructive_start() -> String {
    r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"operate","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":false,"destructiveHint":true}},"#.to_owned()
}

/// Reads one request: its `x-test-reply` header and its body.
fn read_request(stream: &TcpStream) -> std::io::Result<(String, String)> {
    let mut reader = BufReader::new(stream);
    let mut reply = String::new();
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "x-test-reply" => reply = value.to_owned(),
                "content-length" => length = value.parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok((reply, String::from_utf8_lossy(&body).into_owned()))
}

fn respond(mut stream: &TcpStream, content_type: &str, body: &str) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Sends the headers and the start of a list, then closes or stalls.
fn interrupt(mut stream: &TcpStream, reply: &str) -> std::io::Result<()> {
    let sse = reply.starts_with("sse-");
    let head = if sse {
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n".to_owned()
    } else {
        // Announces more bytes than it sends.
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100000\r\nconnection: close\r\n\r\n".to_owned()
    };
    let body = if sse {
        format!("event: message\ndata: {}", destructive_start())
    } else {
        destructive_start()
    };
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()?;
    if reply.ends_with("stalled") {
        std::thread::sleep(STALL);
    }
    Ok(())
}

fn serve(stream: TcpStream, calls: &AtomicUsize) -> std::io::Result<()> {
    let (reply, body) = read_request(&stream)?;
    if body.contains(r#""method":"tools/call""#) {
        calls.fetch_add(1, Ordering::SeqCst);
        return respond(
            &stream,
            "application/json",
            r#"{"jsonrpc":"2.0","id":2,"result":{"content":[]}}"#,
        );
    }
    match reply.as_str() {
        "read" => respond(&stream, "application/json", &read_only_list()),
        "page2" => respond(&stream, "application/json", &page_two()),
        _ => interrupt(&stream, &reply),
    }
}

/// Starts the upstream; returns the count of `tools/call` requests it served.
fn start_upstream(port: u16) -> anyhow::Result<Arc<AtomicUsize>> {
    // Docker Desktop delivers host.docker.internal connections on loopback.
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let counter = Arc::clone(&counter);
            std::thread::spawn(move || {
                let _ = serve(stream, &counter);
            });
        }
    });
    Ok(calls)
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    body: Value,
    reply: &str,
) -> (Option<u16>, String) {
    let sent = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("x-test-reply", reply)
        .body(body.to_string())
        .send()
        .await;
    match sent {
        Ok(response) => {
            let status = response.status().as_u16();
            (Some(status), response.text().await.unwrap_or_default())
        }
        Err(_) => (None, String::new()),
    }
}

fn list() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
}

fn call(id: u64) -> Value {
    call_tool(id, "operate")
}

fn call_tool(id: u64, tool: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": tool, "arguments": {}}})
}

fn reason(text: &str) -> Option<String> {
    let body: Value = serde_json::from_str(text).ok()?;
    body.pointer("/error/data/reason")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[pdk_test]
#[ignore = "needs host.docker.internal (Docker Desktop); run explicitly"]
async fn interrupted_lists_mark_the_catalog_stale() -> anyhow::Result<()> {
    let port = mock_port();
    let calls = start_upstream(port)?;

    // Only used for its address: the gateway reaches the upstream on the host.
    let host_upstream = HttpMockConfig::builder()
        .hostname("host.docker.internal")
        .port(port)
        .build();
    let timeout = PolicyConfig::builder()
        .name("response-timeout-flex")
        .configuration(json!({"timeout": RESPONSE_TIMEOUT_SECONDS}))
        .build();
    let guard = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(json!({}))
        .build();
    let api = ApiConfig::builder()
        .name("interruptedListsApi")
        .upstream(&host_upstream)
        .path("/")
        .port(PORT)
        .policies([timeout, guard])
        .build();
    let flex_config = FlexConfig::builder()
        .version(flex_version())
        .hostname("local-flex")
        .with_api(api)
        .config_mounts([(POLICY_DIR, "policy"), (COMMON_CONFIG_DIR, "common")])
        .build();
    let composite = TestComposite::builder()
        .with_service(flex_config)
        .build()
        .await?;
    let flex: Flex = composite.service()?;
    let url = format!("{}/mcp", flex.external_url(PORT).unwrap());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
    println!("Omni Gateway {}", flex_version());

    // A list teaches `operate` as read-only, so a default caller may call it.
    let (status, _) = post(&client, &url, list(), "read").await;
    assert_eq!(status, Some(200));
    let (status, text) = post(&client, &url, call(2), "none").await;
    assert_eq!(status, Some(200));
    assert_eq!(reason(&text), None, "forwarded: {text}");
    let mut forwarded = 1;
    assert_eq!(calls.load(Ordering::SeqCst), forwarded);

    let mut id = 10;
    for reply in ["json-closed", "json-stalled", "sse-closed", "sse-stalled"] {
        let start = Instant::now();
        let (status, text) = post(&client, &url, list(), reply).await;
        let took = start.elapsed();
        println!(
            "{reply}: status {status:?} after {took:?}: {}",
            text.chars().take(120).collect::<String>()
        );
        if reply.starts_with("sse-") && status == Some(200) {
            // An event stream without a length ends when the upstream
            // closes, so the gateway sees a complete body. Its last event
            // has no terminating empty line, so no client dispatches it.
            assert!(sse_events(&text).is_empty(), "{}: {}", reply, text);
        } else {
            assert_ne!(
                status,
                Some(200),
                "{reply}: the client got the list: {text}"
            );
            assert!(!text.contains("destructiveHint"), "{}: {}", reply, text);
        }
        if reply.ends_with("stalled") {
            assert!(
                took < STALL,
                "{}: not ended by the gateway's timeout",
                reply
            );
        }

        // The catalog is stale, so the read-only pin is not used.
        let (status, text) = post(&client, &url, call(id), "none").await;
        assert_eq!(status, Some(200), "{reply}");
        assert_eq!(
            reason(&text).as_deref(),
            Some("unknown_tool"),
            "{reply}: {text}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            forwarded,
            "{reply}: reached the server"
        );

        // A list the guard inspects makes the catalog fresh again.
        let (status, _) = post(&client, &url, list(), "read").await;
        assert_eq!(status, Some(200));
        let (status, text) = post(&client, &url, call(id + 1), "none").await;
        assert_eq!(status, Some(200));
        assert_eq!(reason(&text), None, "{reply}, re-listed: {text}");
        forwarded += 1;
        assert_eq!(calls.load(Ordering::SeqCst), forwarded);
        id += 2;
    }

    // A client that hangs up while the list is on its way.
    let impatient = reqwest::Client::builder()
        .timeout(Duration::from_millis(300))
        .build()?;
    let (status, _) = post(&impatient, &url, list(), "json-stalled").await;
    assert_eq!(status, None, "the client gave up");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (_, text) = post(&client, &url, call(id), "none").await;
    println!(
        "after a client hang-up: {}",
        reason(&text).unwrap_or_default()
    );
    assert_eq!(reason(&text).as_deref(), Some("unknown_tool"), "{}", text);
    assert_eq!(calls.load(Ordering::SeqCst), forwarded);

    // A later page shows only `other`: `operate` is still not trusted.
    let (status, _) = post(&client, &url, list(), "page2").await;
    assert_eq!(status, Some(200));
    let (_, text) = post(&client, &url, call(id + 1), "none").await;
    assert_eq!(reason(&text).as_deref(), Some("unknown_tool"), "{}", text);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        forwarded,
        "reached the server"
    );
    let (_, text) = post(&client, &url, call_tool(id + 2, "other"), "none").await;
    assert_eq!(reason(&text), None, "page 2's own tool: {}", text);
    forwarded += 1;
    assert_eq!(calls.load(Ordering::SeqCst), forwarded);

    // The page that shows `operate` makes it trusted again.
    post(&client, &url, list(), "read").await;
    let (_, text) = post(&client, &url, call(id + 3), "none").await;
    assert_eq!(reason(&text), None, "re-listed: {}", text);
    forwarded += 1;
    assert_eq!(calls.load(Ordering::SeqCst), forwarded);
    Ok(())
}
