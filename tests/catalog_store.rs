// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! The shared catalog store on a real gateway, across reconfiguration:
//! - a reload with the same classification keeps what the last list taught;
//! - a classification change starts from an empty catalog, and removes the
//!   catalogs of the earlier configuration from the shared store.
//!
//! A configuration the gateway served before may come back as the same
//! running instance, with the copies its workers kept. So each step uses a
//! configuration the gateway has not served yet, and only the shared store
//! carries catalogs from one step to the next.
//!
//! The test writes its own ApiInstance into a folder under the gateway's
//! `conf.d` and replaces it to reconfigure the running gateway. Every request
//! opens a new connection, so none is served by a draining listener.

mod common;

use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use httpmock::{Method::POST, MockServer};
use pdk_test::port::Port;
use pdk_test::services::flex::{Flex, FlexConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;

const PORT: Port = 8081;
/// Where the ApiInstance folder is mounted, inside the gateway's `conf.d`.
const MOUNT: &str = "catalog-store";

fn api_instance(config: &Value) -> String {
    format!(
        r#"apiVersion: gateway.mulesoft.com/v1alpha1
kind: ApiInstance
metadata:
  name: catalog-store-api
spec:
  address: http://0.0.0.0:{PORT}
  services:
    upstream:
      address: http://backend:80
      routes:
        - config:
            destinationPath: /anything/echo/
  policies:
    - policyRef:
        name: {POLICY_NAME}
        namespace: default
      config: {config}
"#
    )
}

/// Replaces the ApiInstance in one step, so the gateway never reads half a file.
fn configure(dir: &Path, staging: &Path, config: &Value) -> anyhow::Result<()> {
    let next = staging.join("api.yaml");
    std::fs::write(&next, api_instance(config))?;
    std::fs::rename(&next, dir.join("api.yaml"))?;
    Ok(())
}

async fn post(url: &str, body: Value) -> anyhow::Result<(u16, Value)> {
    // A new client per request: no pooled connection outlives a reload.
    let response = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()?
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
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

fn call(id: u64, name: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": name, "arguments": {}}})
}

fn reason(body: &Value) -> Option<&str> {
    body.pointer("/error/data/reason").and_then(Value::as_str)
}

fn code(body: &Value) -> Option<i64> {
    body.pointer("/error/code").and_then(Value::as_i64)
}

/// Sends a call the guard always refuses until the refusal has `status` and
/// `error_code`, that is, until the gateway serves the new configuration.
/// Nothing is forwarded while waiting.
async fn wait_for_refusal(
    url: &str,
    status: u16,
    error_code: i64,
    what: &str,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (got, reply) = post(url, call(100, "not_listed")).await?;
        if got == status
            && code(&reply) == Some(error_code)
            && reason(&reply) == Some("unknown_tool")
        {
            return Ok(());
        }
        if Instant::now() > deadline {
            anyhow::bail!("gateway never served {what}: last reply {got} {reply}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[pdk_test]
async fn catalogs_follow_the_classification_across_reloads() -> anyhow::Result<()> {
    // A new folder for every run, as pdk-test does for its own configuration:
    // Docker Desktop may not see a folder that was deleted and created again.
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("catalog-store-{}-{nanos}", std::process::id()));
    let dir = root.join("conf");
    let staging = root.join("staging");
    std::fs::create_dir_all(&dir)?;
    std::fs::create_dir_all(&staging)?;

    // Same classification, so the same catalogs: only the refusal differs,
    // which shows when the gateway serves the new configuration.
    let first = json!({});
    let reloaded = json!({"denial": {"httpStatus": "403"}});
    let first_again = json!({"denial": {"httpStatus": "403", "errorCode": -32001}});
    // A name rule changes the classification, even one that matches nothing.
    let reclassified = json!({"nameRules": [{"pattern": "^never_matches$", "class": "read"}]});
    configure(&dir, &staging, &first)?;

    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();
    let flex_config = FlexConfig::builder()
        .version(flex_version())
        .hostname("local-flex")
        .ports([PORT])
        .config_mounts([
            (POLICY_DIR, "policy"),
            (COMMON_CONFIG_DIR, "common"),
            (dir.to_str().unwrap(), MOUNT),
        ])
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

    let tools_list = server
        .mock_async(|when, then| {
            when.method(POST).body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
                        {"name": "list_issues", "annotations": {"readOnlyHint": true}}
                    ]}})
                    .to_string(),
                );
        })
        .await;
    let forwarded = server
        .mock_async(|when, then| {
            when.method(POST)
                .body_contains("tools/call")
                .body_contains(r#""name":"list_issues""#);
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":2,"result":{"content":[]}}"#);
        })
        .await;

    // 1. A list teaches `list_issues` as read-only, so it may be called.
    let (status, _) = post(&url, list()).await?;
    assert_eq!(status, 200);
    tools_list.assert_hits_async(1).await;
    let (status, body) = post(&url, call(2, "list_issues")).await?;
    assert_eq!(status, 200);
    assert_eq!(reason(&body), None, "forwarded: {body}");
    forwarded.assert_hits_async(1).await;

    // 2. A reload with the same classification keeps the catalog: no new list.
    configure(&dir, &staging, &reloaded)?;
    wait_for_refusal(&url, 403, -32008, "the reloaded configuration").await?;
    let (status, body) = post(&url, call(3, "list_issues")).await?;
    assert_eq!(status, 200, "kept after a reload: {body}");
    assert_eq!(reason(&body), None, "forwarded: {body}");
    forwarded.assert_hits_async(2).await;
    tools_list.assert_hits_async(1).await;

    // 3. A classification change starts from an empty catalog.
    configure(&dir, &staging, &reclassified)?;
    wait_for_refusal(&url, 200, -32008, "the new classification").await?;
    let (status, body) = post(&url, call(4, "list_issues")).await?;
    assert_eq!(status, 200);
    assert_eq!(
        reason(&body),
        Some("unknown_tool"),
        "new catalog is empty: {body}"
    );
    forwarded.assert_hits_async(2).await;
    let (status, _) = post(&url, list()).await?;
    assert_eq!(status, 200);
    let (status, body) = post(&url, call(5, "list_issues")).await?;
    assert_eq!(status, 200);
    assert_eq!(reason(&body), None, "learned again from a new list: {body}");
    forwarded.assert_hits_async(3).await;

    // 4. Back to the first classification: its catalog was removed from the
    // shared store in step 3, so nothing old comes back.
    configure(&dir, &staging, &first_again)?;
    wait_for_refusal(&url, 403, -32001, "the first classification again").await?;
    let (status, body) = post(&url, call(6, "list_issues")).await?;
    assert_eq!(status, 403, "old catalog removed: {body}");
    assert_eq!(
        reason(&body),
        Some("unknown_tool"),
        "old catalog removed: {body}"
    );
    forwarded.assert_hits_async(3).await;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
