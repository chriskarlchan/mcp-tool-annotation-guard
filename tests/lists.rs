// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for `tools/list` responses through a
//! local Omni Gateway. They cover what the pdk-unit tests cannot: the real
//! gateway's handling of a replaced body (`Content-Length`), the
//! `Accept-Encoding` rewrite reaching the upstream and encoded responses,
//! buffered SSE, and the catalog learned on the response leg
//! governing a later request.

mod common;

use httpmock::{Method::POST, MockServer};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;

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

    /// Tool names of a JSON list, or of the first `data:` line of an SSE list.
    fn tool_names(&self) -> Vec<String> {
        let text = self.text();
        let json = text
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap_or(&text);
        let value: Value = serde_json::from_str(json).unwrap_or(Value::Null);
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
    // An upstream that compresses anyway.
    let gzip_list = server
        .mock_async(|when, then| {
            when.method(POST)
                .header("x-test-reply", "gzip")
                .body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .header("content-encoding", "gzip")
                .body(GZIP_LIST.to_vec());
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

    Ok(())
}
