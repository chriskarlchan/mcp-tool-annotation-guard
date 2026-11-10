// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for `tools/list` responses through a
//! local Omni Gateway. They cover what the pdk-unit tests cannot: the real
//! gateway's handling of a replaced body (`Content-Length`), the
//! `Accept-Encoding` rewrite reaching the upstream and encoded responses,
//! buffered SSE (events whose data spans several lines, and a leading
//! byte-order mark), a list the gateway will not take back once changed, and
//! the catalog learned on the response leg governing a later request.

mod common;
#[path = "common/sse.rs"]
mod sse;

use httpmock::{Method::POST, MockServer};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;
use sse::sse_events;

const PORT: Port = 8081;

/// `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"drop","annotations":{"destructiveHint":true}}]}}`,
/// gzip-compressed (Python `gzip.compress(body, mtime=0)`).
const GZIP_LIST: [u8; 107] = [
    31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 21, 203, 49, 14, 128, 32, 12, 70, 225, 187, 252, 51, 49,
    234, 200, 9, 188, 131, 113, 32, 210, 1, 131, 45, 161, 213, 133, 112, 119, 113, 124, 201, 247,
    26, 46, 21, 174, 229, 132, 199, 58, 205, 112, 72, 17, 126, 113, 168, 164, 79, 54, 248, 6, 19,
    201, 10, 191, 55, 112, 184, 105, 184, 88, 165, 12, 24, 152, 197, 130, 37, 97, 253, 89, 36, 181,
    250, 156, 150, 94, 218, 18, 143, 115, 20, 245, 126, 244, 254, 1, 205, 143, 42, 44, 100, 0, 0,
    0,
];

fn list_body() -> String {
    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "search", "annotations": {"readOnlyHint": true}},
        {"name": "drop", "annotations": {"destructiveHint": true}}
    ]}})
    .to_string()
}

/// `search` plus a destructive `tool`.
fn sse_list_with(tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "search", "annotations": {"readOnlyHint": true}},
        {"name": tool, "annotations": {"destructiveHint": true}}
    ]}})
    .to_string()
}

/// A list of read-only tools, `len` bytes long, with a `cacheScope` the
/// guard must change: the changed list no longer fits the gateway's buffer.
fn near_limit_list(len: usize) -> String {
    let with = |pad: usize| {
        json!({"jsonrpc": "2.0", "id": 1, "result": {"cacheScope": 0, "tools": [
            {"name": "search", "annotations": {"readOnlyHint": true}},
            {"name": "notes", "description": "x".repeat(pad), "annotations": {"readOnlyHint": true}}
        ]}})
        .to_string()
    };
    let base = with(0).len();
    let body = with(len - base);
    assert_eq!(body.len(), len);
    body
}

struct Reply {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Tool names of a JSON list, or of the first SSE event, decoded as a
    /// client does (one leading BOM removed, `data:` lines joined).
    fn tool_names(&self) -> Vec<String> {
        let text = self.text();
        let sse = self
            .header("content-type")
            .is_some_and(|t| t.starts_with("text/event-stream"));
        let json = if sse {
            sse_events(&text).into_iter().next().unwrap_or_default()
        } else {
            text
        };
        let value: Value = serde_json::from_str(&json).unwrap_or(Value::Null);
        value
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|tool| tool.get("name").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    body: Value,
    reply: &str,
) -> anyhow::Result<Reply> {
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("accept-encoding", "gzip")
        .header("x-test-reply", reply)
        .body(body.to_string())
        .send()
        .await?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response.bytes().await?.to_vec();
    Ok(Reply {
        status,
        headers,
        body,
    })
}

fn list() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
}

fn call(id: u64, tool: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {}}})
}

#[pdk_test]
async fn list_processing() -> anyhow::Result<()> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let policy = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(json!({}))
        .build();

    let api = ApiConfig::builder()
        .name("listApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(PORT)
        .policies([policy])
        .build();

    let flex_config = FlexConfig::builder()
        .version(flex_version())
        .hostname("local-flex")
        .with_api(api)
        .config_mounts([(POLICY_DIR, "policy"), (COMMON_CONFIG_DIR, "common")])
        .build();

    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    let flex: Flex = composite.service()?;
    let url = format!("{}/mcp", flex.external_url(PORT).unwrap());
    let httpmock: HttpMock = composite.service()?;
    let server = MockServer::connect_async(httpmock.socket()).await;
    let client = reqwest::Client::new();

    // Each list mock matches only when the upstream request carries
    // `Accept-Encoding: identity`, although the client sent `gzip`.
    let json_list = server
        .mock_async(|when, then| {
            when.method(POST)
                .header("x-test-reply", "json")
                .header("accept-encoding", "identity")
                .body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .header("etag", "\"v1\"")
                .header("digest", "sha-256=abc")
                .body(list_body());
        })
        .await;
    let sse_list = server
        .mock_async(|when, then| {
            when.method(POST)
                .header("x-test-reply", "sse")
                .header("accept-encoding", "identity")
                .body_contains("tools/list");
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(format!("event: message\nid: 1\ndata: {}\n\n", list_body()));
        })
        .await;
    // An event whose data spans several lines, and streams that start with
    // a byte-order mark, each listing a destructive tool of its own.
    let sse_variants = [
        ("sse-multi", "purge", "event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{\"tools\":[{\"name\":\"search\",\"annotations\":{\"readOnlyHint\":true}},\ndata: {\"name\":\"purge\",\"annotations\":{\"destructiveHint\":true}}]}}\n\n".to_owned()),
        ("sse-bom-data", "wipe", format!("\u{feff}data: {}\n\n", sse_list_with("wipe"))),
        ("sse-bom-event", "erase", format!("\u{feff}event: message\ndata: {}\n\n", sse_list_with("erase"))),
    ];
    let mut sse_variant_mocks = Vec::new();
    let mut hidden_calls = Vec::new();
    for (reply, tool, body) in &sse_variants {
        let (reply, body) = (reply.to_string(), body.clone());
        sse_variant_mocks.push(
            server
                .mock_async(|when, then| {
                    when.method(POST)
                        .header("x-test-reply", reply.as_str())
                        .body_contains("tools/list");
                    then.status(200)
                        .header("content-type", "text/event-stream")
                        .body(body);
                })
                .await,
        );
        let needle = format!("\"name\":\"{tool}\"");
        hidden_calls.push(
            server
                .mock_async(|when, then| {
                    when.method(POST).body_contains(needle.as_str());
                    then.status(200)
                        .header("content-type", "application/json")
                        .body(r#"{"jsonrpc":"2.0","id":2,"result":{"content":[]}}"#);
                })
                .await,
        );
    }
    // An upstream that compresses anyway.
    let gzip_list = server
        .mock_async(|when, then| {
            when.method(POST)
                .header("x-test-reply", "gzip")
                .body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .header("content-encoding", "gzip")
                .body(GZIP_LIST);
        })
        .await;
    // Larger than the gateway's default buffer limit (1 MiB).
    let big_list = server
        .mock_async(|when, then| {
            when.method(POST)
                .header("x-test-reply", "big")
                .body_contains("tools/list");
            let tools: Vec<Value> = (0..12_000)
                .map(|i| json!({"name": format!("tool_{i:05}"), "description": "x".repeat(80)}))
                .collect();
            then.status(200)
                .header("content-type", "application/json")
                .body(json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}).to_string());
        })
        .await;
    // Nothing hidden, but the cache scope must become private.
    let scope_list = server
        .mock_async(|when, then| {
            when.method(POST)
                .header("x-test-reply", "scope")
                .body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .header("etag", "\"v1\"")
                .body(
                    json!({"jsonrpc": "2.0", "id": 1, "result": {
                        "tools": [{"name": "search", "annotations": {"readOnlyHint": true}}],
                        "ttlMs": 60000, "cacheScope": "public"}})
                    .to_string(),
                );
        })
        .await;
    // Fits the gateway's buffer (1 MiB) by 4 bytes; with `"cacheScope":"private"`
    // it would not.
    let near_limit = server
        .mock_async(|when, then| {
            when.method(POST)
                .header("x-test-reply", "near-limit")
                .body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .header("etag", "\"v1\"")
                .body(near_limit_list(1024 * 1024 - 4));
        })
        .await;
    // Read-only tools whose names have characters a server or client may
    // drop or cut the name at.
    let hidden_names = server
        .mock_async(|when, then| {
            when.method(POST)
                .header("x-test-reply", "hidden-names")
                .body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
                        {"name": "search", "annotations": {"readOnlyHint": true}},
                        {"name": "drop\u{0}", "annotations": {"readOnlyHint": true}},
                        {"name": "drop\n", "annotations": {"readOnlyHint": true}},
                        {"name": "dr\u{200b}op", "annotations": {"readOnlyHint": true}}
                    ]}})
                    .to_string(),
                );
        })
        .await;
    let drop_call = server
        .mock_async(|when, then| {
            when.method(POST).body_contains("\"name\":\"drop\"");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":2,"result":{"content":[]}}"#);
        })
        .await;

    // The destructive tool is hidden, and
    // the replaced body arrives whole with a matching Content-Length.
    let reply = post(&client, &url, list(), "json").await?;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.tool_names(), vec!["search"]);
    let length = reply.body.len().to_string();
    assert_eq!(
        reply.header("content-length"),
        Some(length.as_str()),
        "content-length"
    );
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("etag"), None);
    assert_eq!(reply.header("digest"), None);
    json_list.assert_hits_async(1).await;

    // The pin learned on the response leg governs the next request: `drop`
    // is known and destructive, so the refusal is level_insufficient.
    let reply = post(&client, &url, call(2, "drop"), "none").await?;
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    assert_eq!(
        body.pointer("/error/data/reason"),
        Some(&json!("level_insufficient"))
    );
    drop_call.assert_hits_async(0).await;

    // A server that reads numbers as doubles would answer this ID with a
    // rounded one, so the list is refused before it reaches the server, and
    // what the guard learned stays trusted.
    let huge_id_list =
        json!({"jsonrpc": "2.0", "id": 9_007_199_254_740_993_u64, "method": "tools/list"});
    let reply = post(&client, &url, huge_id_list, "json").await?;
    assert_eq!(reply.status, 400);
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    assert_eq!(body.pointer("/error/data/detail"), Some(&json!("id_range")));
    json_list.assert_hits_async(1).await;
    let reply = post(&client, &url, call(2, "drop"), "none").await?;
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    assert_eq!(
        body.pointer("/error/data/reason"),
        Some(&json!("level_insufficient"))
    );
    drop_call.assert_hits_async(0).await;

    // A server that ignores case or trims may read these as `tools/list`
    // and answer with the whole list, so they are refused as well.
    for method in ["tools/list ", "Tools/List", "tools/list\u{0}"] {
        let variant = json!({"jsonrpc": "2.0", "id": 1, "method": method});
        let reply = post(&client, &url, variant, "json").await?;
        assert_eq!(reply.status, 400, "{method:?}");
        let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        assert_eq!(
            body.pointer("/error/data/detail"),
            Some(&json!("ambiguous_method")),
            "{method:?}"
        );
    }
    json_list.assert_hits_async(1).await;

    // SSE, buffered whole.
    let reply = post(&client, &url, list(), "sse").await?;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.tool_names(), vec!["search"]);
    assert!(
        reply.text().starts_with("event: message\nid: 1\ndata: "),
        "{}",
        reply.text()
    );
    sse_list.assert_hits_async(1).await;

    // Each variant is inspected, not forwarded: a client decoding the stream
    // sees valid JSON without the destructive tool, and the guard learned it.
    for (i, ((reply_name, tool, _), mock)) in
        sse_variants.iter().zip(&sse_variant_mocks).enumerate()
    {
        let reply = post(&client, &url, list(), reply_name).await?;
        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.tool_names(),
            vec!["search"],
            "{reply_name}: {}",
            reply.text()
        );
        mock.assert_hits_async(1).await;
        let reply = post(&client, &url, call(10 + i as u64, tool), "none").await?;
        let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        assert_eq!(
            body.pointer("/error/data/reason"),
            Some(&json!("level_insufficient")),
            "{reply_name}"
        );
        hidden_calls[i].assert_hits_async(0).await;
    }

    // A list with nothing hidden is still meant for this caller only: a
    // shared cache scope becomes private, and the validators are removed.
    let reply = post(&client, &url, list(), "scope").await?;
    assert_eq!(reply.status, 200);
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    assert_eq!(body.pointer("/result/cacheScope"), Some(&json!("private")));
    assert_eq!(body.pointer("/result/ttlMs"), Some(&json!(60000)));
    assert_eq!(reply.tool_names(), vec!["search"]);
    let length = reply.body.len().to_string();
    assert_eq!(reply.header("content-length"), Some(length.as_str()));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("etag"), None);
    scope_list.assert_hits_async(1).await;

    // A compressed response reaches the client as sent (the
    // gateway does not decompress it) and marks the catalog stale.
    let reply = post(&client, &url, list(), "gzip").await?;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("content-encoding"), Some("gzip"));
    assert_eq!(reply.body, GZIP_LIST.to_vec());
    gzip_list.assert_hits_async(1).await;

    // Stale: the pin of `drop` is ignored, so it is unknown now.
    let reply = post(&client, &url, call(3, "drop"), "none").await?;
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    assert_eq!(
        body.pointer("/error/data/reason"),
        Some(&json!("unknown_tool"))
    );
    drop_call.assert_hits_async(0).await;

    // The guard must change this list but the gateway refuses the changed
    // body: the client gets an error instead of the list.
    let reply = post(&client, &url, list(), "near-limit").await?;
    assert_eq!(reply.status, 200);
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    assert_eq!(body.get("id"), Some(&json!(1)), "{body}");
    assert_eq!(body.pointer("/error/code"), Some(&json!(-32603)));
    assert_eq!(
        body.pointer("/error/data/reason"),
        Some(&json!("internal_error"))
    );
    assert!(body.get("result").is_none());
    let length = reply.body.len().to_string();
    assert_eq!(reply.header("content-length"), Some(length.as_str()));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("etag"), None);
    near_limit.assert_hits_async(1).await;

    // The list itself was inspected, but it did not show `drop`, so `drop`
    // stays unknown.
    let reply = post(&client, &url, call(4, "drop"), "none").await?;
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    assert_eq!(
        body.pointer("/error/data/reason"),
        Some(&json!("unknown_tool"))
    );
    drop_call.assert_hits_async(0).await;

    // Once a list shows `drop` again, the guard decides with what it
    // learned: `drop` is known and destructive.
    let reply = post(&client, &url, list(), "json").await?;
    assert_eq!(reply.tool_names(), vec!["search"]);
    json_list.assert_hits_async(2).await;
    let reply = post(&client, &url, call(5, "drop"), "none").await?;
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    assert_eq!(
        body.pointer("/error/data/reason"),
        Some(&json!("level_insufficient"))
    );
    drop_call.assert_hits_async(0).await;

    // The gateway's buffer limit applies to responses: an oversized
    // list is answered with 500 before the policy runs, so no unfiltered
    // list reaches the client.
    let reply = post(&client, &url, list(), "big").await?;
    assert_eq!(
        reply.status,
        500,
        "{}",
        reply.text().chars().take(200).collect::<String>()
    );
    assert!(reply.tool_names().is_empty());
    big_list.assert_hits_async(1).await;

    // Entries whose names have hidden characters are removed, though they
    // say they are read-only, and calls to such names are refused.
    let reply = post(&client, &url, list(), "hidden-names").await?;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.tool_names(), vec!["search"]);
    hidden_names.assert_hits_async(1).await;
    let reply = post(&client, &url, call(3, "drop\u{0}"), "none").await?;
    assert_eq!(reply.status, 200);
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    assert_eq!(body.pointer("/error/code"), Some(&json!(-32602)), "{body}");
    assert_eq!(
        body.pointer("/error/data/detail"),
        Some(&json!("name_characters"))
    );

    Ok(())
}
