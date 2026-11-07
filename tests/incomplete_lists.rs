// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! A list response the gateway ends before its body is complete (here, a
//! body over the gateway's 1 MiB buffer limit) never reaches the policy's
//! body step. The client gets an error instead of the list, and the catalog
//! is marked stale, so what earlier lists taught is not used until a list is
//! inspected again.

mod common;

use httpmock::{Method::POST, MockServer};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;

const PORT: Port = 8081;

async fn post(
    client: &reqwest::Client,
    url: &str,
    body: Value,
    reply: &str,
) -> anyhow::Result<(u16, Value)> {
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("x-test-reply", reply)
        .body(body.to_string())
        .send()
        .await?;
    let status = response.status().as_u16();
    let text = response.text().await?;
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
}

fn list() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
}

fn call(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": "operate", "arguments": {}}})
}

fn reason(body: &Value) -> Option<&str> {
    body.pointer("/error/data/reason").and_then(Value::as_str)
}

/// A list where `operate` is destructive, padded past the gateway's buffer.
fn big_list() -> String {
    let schema = json!({"type": "object"});
    let mut tools = vec![json!({"name": "operate", "inputSchema": schema,
        "annotations": {"readOnlyHint": false, "destructiveHint": true}})];
    tools.extend((0..12_000).map(|i| {
        json!({"name": format!("pad_{i:05}"), "inputSchema": schema,
            "description": "x".repeat(80)})
    }));
    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}).to_string()
}

#[pdk_test]
async fn an_unfinished_list_marks_the_catalog_stale() -> anyhow::Result<()> {
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
        .name("incompleteListsApi")
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

    let read_list = server
        .mock_async(|when, then| {
            when.method(POST)
                .header("x-test-reply", "read")
                .body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
                        {"name": "operate", "inputSchema": {"type": "object"},
                            "annotations": {"readOnlyHint": true}}
                    ]}})
                    .to_string(),
                );
        })
        .await;
    let big_json = server
        .mock_async(|when, then| {
            when.method(POST)
                .header("x-test-reply", "big-json")
                .body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .body(big_list());
        })
        .await;
    let big_sse = server
        .mock_async(|when, then| {
            when.method(POST)
                .header("x-test-reply", "big-sse")
                .body_contains("tools/list");
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(format!("event: message\ndata: {}\n\n", big_list()));
        })
        .await;
    let operate = server
        .mock_async(|when, then| {
            when.method(POST)
                .body_contains("tools/call")
                .body_contains(r#""name":"operate""#);
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":2,"result":{"content":[]}}"#);
        })
        .await;

    // A list teaches `operate` as read-only, so a default caller may call it.
    let (status, _) = post(&client, &url, list(), "read").await?;
    assert_eq!(status, 200);
    let (status, body) = post(&client, &url, call(2), "none").await?;
    assert_eq!(status, 200);
    assert_eq!(reason(&body), None, "forwarded: {body}");
    operate.assert_hits_async(1).await;
    let mut forwarded = 1;

    for (reply, mock, id) in [("big-json", &big_json, 3), ("big-sse", &big_sse, 5)] {
        // The server now marks `operate` destructive, in a list the gateway
        // cannot buffer: the client gets an error, not the list.
        let (status, _) = post(&client, &url, list(), reply).await?;
        mock.assert_hits_async(1).await;
        assert_eq!(status, 500, "{reply}");

        // The catalog is stale, so the read-only pin is not used.
        let (status, body) = post(&client, &url, call(id), "none").await?;
        assert_eq!(status, 200);
        assert_eq!(reason(&body), Some("unknown_tool"), "{reply}: {body}");
        operate.assert_hits_async(forwarded).await;

        // A list the policy inspects makes the catalog fresh again.
        let (status, _) = post(&client, &url, list(), "read").await?;
        assert_eq!(status, 200);
        let (status, body) = post(&client, &url, call(id + 1), "none").await?;
        assert_eq!(status, 200);
        assert_eq!(reason(&body), None, "{reply}, re-listed: {body}");
        forwarded += 1;
        operate.assert_hits_async(forwarded).await;
    }
    read_list.assert_hits_async(3).await;
    Ok(())
}
