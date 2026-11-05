// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Request-phase integration tests: the built policy in a local Omni
//! Gateway in front of a mock MCP backend. They cover what the pdk-unit tests
//! cannot: the gateway compiling the DataWeave expression, a refused call never
//! reaching the backend over a real network, and an invalid configuration
//! failing closed with 503.

mod common;

use httpmock::{Method::POST, MockServer};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;

/// API with a valid configuration.
const GUARDED_PORT: Port = 8081;
/// API whose policy configuration is invalid.
const BROKEN_PORT: Port = 8082;

const ALLOWED_RESULT: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#;

fn call(id: u64, tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {}}})
        .to_string()
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    body: String,
    headers: &[(&str, &str)],
) -> anyhow::Result<(u16, Option<String>, Value)> {
    let mut request = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(body);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await?;
    let status = response.status().as_u16();
    let cache_control = response
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let text = response.text().await?;
    let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    Ok((status, cache_control, body))
}

fn reason(body: &Value) -> &Value {
    body.pointer("/error/data/reason").unwrap_or(&Value::Null)
}

#[pdk_test]
async fn request_phase_enforcement() -> anyhow::Result<()> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    // The gateway compiles this DataWeave expression (dw2pel).
    let guarded_policy = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(json!({
            "callerAttributes": "#[attributes.headers['x-test-roles']]",
            "callerAttributeSeparator": ",",
            "grants": [{"attribute": "editor", "level": "write"}],
            "toolOverrides": [
                {"name": "search", "class": "read"},
                {"name": "update_ticket", "class": "write"}
            ],
            "blockedTools": ["delete_repository"]
        }))
        .build();

    // errorCode inside the reserved JSON-RPC range is rejected at configure time.
    let broken_policy = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(json!({"denial": {"errorCode": -32700}}))
        .build();

    let guarded_api = ApiConfig::builder()
        .name("guardedApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(GUARDED_PORT)
        .policies([guarded_policy])
        .build();

    let broken_api = ApiConfig::builder()
        .name("brokenApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(BROKEN_PORT)
        .policies([broken_policy])
        .build();

    let flex_config = FlexConfig::builder()
        .version(flex_version())
        .hostname("local-flex")
        .with_api(guarded_api)
        .with_api(broken_api)
        .config_mounts([(POLICY_DIR, "policy"), (COMMON_CONFIG_DIR, "common")])
        .build();

    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    let flex: Flex = composite.service()?;
    let guarded_url = format!("{}/mcp", flex.external_url(GUARDED_PORT).unwrap());
    let broken_url = format!("{}/mcp", flex.external_url(BROKEN_PORT).unwrap());
    let httpmock: HttpMock = composite.service()?;
    let mock_server = MockServer::connect_async(httpmock.socket()).await;
    let client = reqwest::Client::new();

    // One mock per tool, so each assertion counts only its own requests.
    let mock_for = |tool: &'static str| {
        let server = &mock_server;
        async move {
            server
                .mock_async(|when, then| {
                    when.method(POST)
                        .path_contains("/mcp")
                        .body_contains(format!("\"name\":\"{tool}\""));
                    then.status(200)
                        .header("content-type", "application/json")
                        .body(ALLOWED_RESULT);
                })
                .await
        }
    };
    let search = mock_for("search").await;
    let unknown = mock_for("delete_everything").await;
    let blocked = mock_for("delete_repository").await;
    let update = mock_for("update_ticket").await;

    // A read tool is forwarded.
    let (status, _, body) = post(&client, &guarded_url, call(1, "search"), &[]).await?;
    assert_eq!(status, 200);
    assert_eq!(body["result"], json!({"content": []}));
    search.assert_hits_async(1).await;

    // An unknown tool is refused at the gateway and never reaches the backend.
    let (status, cache_control, body) =
        post(&client, &guarded_url, call(7, "delete_everything"), &[]).await?;
    assert_eq!(status, 200);
    assert_eq!(cache_control.as_deref(), Some("no-store"));
    assert_eq!(body["id"], json!(7));
    assert_eq!(body["error"]["code"], json!(-32008));
    assert_eq!(reason(&body), &json!("unknown_tool"));
    unknown.assert_hits_async(0).await;

    // blockedTools.
    let (_, _, body) = post(&client, &guarded_url, call(2, "delete_repository"), &[]).await?;
    assert_eq!(reason(&body), &json!("tool_blocked"));
    blocked.assert_hits_async(0).await;

    // The header grant raises the caller to write.
    let (_, _, body) = post(&client, &guarded_url, call(3, "update_ticket"), &[]).await?;
    assert_eq!(reason(&body), &json!("level_insufficient"));
    update.assert_hits_async(0).await;
    let roles = [("x-test-roles", "viewer,editor")];
    let (status, _, _) = post(&client, &guarded_url, call(4, "update_ticket"), &roles).await?;
    assert_eq!(status, 200);
    update.assert_hits_async(1).await;

    // An invalid configuration fails closed.
    let (status, _, _) = post(&client, &broken_url, call(5, "search"), &[]).await?;
    assert_eq!(status, 503);
    search.assert_hits_async(1).await;

    Ok(())
}
