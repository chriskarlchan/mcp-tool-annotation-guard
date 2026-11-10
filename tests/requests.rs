// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Request-phase integration tests: the built policy in a local Omni
//! Gateway in front of a mock MCP backend. They cover what the pdk-unit tests
//! cannot: the gateway compiling the DataWeave expression, a refused call never
//! reaching the backend over a real network, an invalid configuration
//! failing closed with 503, and audit mode forwarding everything.

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
/// API with the valid configuration in audit mode.
const AUDIT_PORT: Port = 8083;

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
    let guarded = json!({
        "callerAttributes": "#[attributes.headers['x-test-roles']]",
        "callerAttributeSeparator": ",",
        "grants": [{"attribute": "editor", "level": "write"}],
        "toolOverrides": [
            {"name": "search", "class": "read"},
            {"name": "update_ticket", "class": "write"}
        ],
        "blockedTools": ["delete_repository"]
    });
    let mut audit = guarded.clone();
    audit["mode"] = json!("audit");
    let guarded_policy = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(guarded)
        .build();
    let audit_policy = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(audit)
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

    let audit_api = ApiConfig::builder()
        .name("auditApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(AUDIT_PORT)
        .policies([audit_policy])
        .build();

    let flex_config = FlexConfig::builder()
        .version(flex_version())
        .hostname("local-flex")
        .with_api(guarded_api)
        .with_api(broken_api)
        .with_api(audit_api)
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
    let audit_url = format!("{}/mcp", flex.external_url(AUDIT_PORT).unwrap());
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

    // A server may read "Name" as name (Go's encoding/json matches member
    // names regardless of case), so keys like these are refused as
    // duplicates and never reach the backend.
    let smuggled = r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"search","Name":"delete_repository"}}"#;
    let (status, _, body) = post(&client, &guarded_url, smuggled.to_owned(), &[]).await?;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], json!(-32600));
    assert_eq!(reason(&body), &json!("invalid_request"));
    assert_eq!(body["error"]["data"]["detail"], json!("duplicate_keys"));
    search.assert_hits_async(1).await;

    // A server that reads numbers as doubles, as JavaScript does, answers
    // 2^53 + 1 with 2^53, so a request with such an ID is refused.
    let big_id = 9_007_199_254_740_993_u64;
    for big in [
        call(big_id, "search"),
        json!({"jsonrpc": "2.0", "id": big_id, "method": "tools/list"}).to_string(),
    ] {
        let (status, _, body) = post(&client, &guarded_url, big.clone(), &[]).await?;
        assert_eq!(status, 400, "{}", big);
        assert_eq!(body["id"], json!(big_id), "{}", big);
        assert_eq!(body["error"]["code"], json!(-32600));
        assert_eq!(reason(&body), &json!("invalid_request"));
        assert_eq!(body["error"]["data"]["detail"], json!("id_range"));
    }
    search.assert_hits_async(1).await;

    // Without a "method" key this is a response to the guard, but a request
    // to a server that reads "Method" as method and takes any message with a
    // method for a request (as Go SDKs do).
    for smuggled in [
        r#"{"jsonrpc":"2.0","id":9,"result":{},"Method":"tools/call","params":{"name":"delete_repository"}}"#,
        r#"{"jsonrpc":"2.0","id":9,"error":{"code":0,"message":""},"Method":"tools/call","params":{"name":"delete_repository"}}"#,
    ] {
        let (status, _, body) = post(&client, &guarded_url, smuggled.to_owned(), &[]).await?;
        assert_eq!(status, 400, "{}", smuggled);
        assert_eq!(reason(&body), &json!("invalid_request"));
        assert_eq!(body["error"]["data"]["detail"], json!("ambiguous_keys"));
    }
    blocked.assert_hits_async(0).await;

    // A server may read these methods as tools/call: some ignore case or
    // trim, and readers built on C strings end a string at its first NUL.
    for method in ["Tools/Call", "tools/call ", "tools/call\u{0}x"] {
        let smuggled = json!({"jsonrpc": "2.0", "id": 15, "method": method, "params": {"name": "delete_repository"}});
        let (status, _, body) = post(&client, &guarded_url, smuggled.to_string(), &[]).await?;
        assert_eq!(status, 400, "{method:?}");
        assert_eq!(reason(&body), &json!("invalid_request"));
        assert_eq!(body["error"]["data"]["detail"], json!("ambiguous_method"));
    }
    // Such a reader also reads "name\u0000x" as name.
    let nul_key = r#"{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"search","name\u0000x":"delete_repository"}}"#;
    let (status, _, body) = post(&client, &guarded_url, nul_key.to_owned(), &[]).await?;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["data"]["detail"], json!("ambiguous_keys"));
    blocked.assert_hits_async(0).await;
    search.assert_hits_async(1).await;

    // A tool name with a control or invisible character is refused.
    for name in [
        "delete_repository\u{0}",
        "delete_repository\n",
        "delete\u{200b}_repository",
    ] {
        let (status, _, body) = post(&client, &guarded_url, call(17, name), &[]).await?;
        assert_eq!(status, 200, "{name:?}");
        assert_eq!(body["id"], json!(17));
        assert_eq!(body["error"]["code"], json!(-32602));
        assert_eq!(reason(&body), &json!("invalid_params"));
        assert_eq!(body["error"]["data"]["detail"], json!("name_characters"));
    }

    // Express's express.json() decodes a body with the charset its client
    // names. In UTF-7, "+AG4-ame" is "name", so the server would run the
    // last name.
    let utf7 = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"search","+AG4-ame":"delete_repository"}}"#;
    let response = client
        .post(&guarded_url)
        .header("content-type", "application/json; charset=utf-7")
        .header("accept", "application/json, text/event-stream")
        .body(utf7)
        .send()
        .await?;
    assert_eq!(response.status().as_u16(), 415);
    let body: Value = serde_json::from_str(&response.text().await?)?;
    assert_eq!(reason(&body), &json!("encoded"));
    search.assert_hits_async(1).await;

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

    // Audit mode refuses nothing: the calls refused above and the requests
    // refused as protocol errors all reach the backend unchanged.
    let forwarded = [
        (call(11, "delete_everything"), &unknown, 1),
        (call(12, "delete_repository"), &blocked, 1),
        (call(13, "update_ticket"), &update, 2),
        (smuggled.to_owned(), &search, 2),
        (
            r#"{"jsonrpc":"2.0","id":9,"result":{},"Method":"tools/call","params":{"name":"delete_repository"}}"#.to_owned(),
            &blocked,
            2,
        ),
        (call(big_id, "search"), &search, 3),
        (
            json!({"jsonrpc": "2.0", "id": 15, "method": "Tools/Call", "params": {"name": "delete_repository"}}).to_string(),
            &blocked,
            3,
        ),
        // Not valid JSON.
        (
            r#"{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"search""#.to_owned(),
            &search,
            4,
        ),
    ];
    for (body, mock, hits) in forwarded {
        let (status, _, response) = post(&client, &audit_url, body.clone(), &[]).await?;
        assert_eq!(status, 200, "{}", body);
        assert_eq!(response["result"], json!({"content": []}), "{}", body);
        mock.assert_hits_async(hits).await;
    }
    let response = client
        .post(&audit_url)
        .header("content-type", "application/json; charset=utf-7")
        .header("accept", "application/json, text/event-stream")
        .body(utf7)
        .send()
        .await?;
    assert_eq!(response.status().as_u16(), 200);
    search.assert_hits_async(5).await;

    Ok(())
}
