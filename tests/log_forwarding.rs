// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Log forwarding: the guard's log events reach a third-party log
//! destination through the gateway's own log forwarding, a `Configuration`
//! resource with `spec.logging.outputs` (Fluent Bit outputs) used by
//! `runtimeLogs` (docs.mulesoft.com/gateway/latest/local-third-party-logs-config).
//!
//! Two outputs receive the runtime logs:
//! - `file`: one line per log message, so each guard event can be parsed as
//!   complete JSON.
//! - `opentelemetry`: OTLP/HTTP to `/v1/logs` on the mock backend, to show
//!   that an OpenTelemetry collector receives the same events.
//!
//! Opt-in (not part of `make test`): `make build && cargo test --test
//! log_forwarding -- --ignored --nocapture`. It writes only to
//! `target/log-forwarding/`.

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use httpmock::{Method::POST, MockServer};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;

const PORT: Port = 8081;
/// Where the log folder is mounted, inside the gateway's `conf.d`.
const MOUNT: &str = "log-forwarding";
const CONTAINER_LOG: &str =
    "/usr/local/share/mulesoft/flex-gateway/conf.d/log-forwarding/runtime.log";

fn logging_config() -> String {
    format!(
        r#"apiVersion: gateway.mulesoft.com/v1alpha1
kind: Configuration
metadata:
  name: log-forwarding
spec:
  logging:
    outputs:
      - name: file
        type: file
        parameters:
          file: {CONTAINER_LOG}
          format: template
          template: "{{message}}"
      - name: otlp
        type: opentelemetry
        parameters:
          host: backend
          port: "80"
          logs_uri: /v1/logs
    runtimeLogs:
      logLevel: info
      outputs:
        - file
        - otlp
"#
    )
}

/// The guard events in the forwarded file, parsed.
fn guard_events(log: &str) -> Vec<Value> {
    log.lines()
        .filter_map(|line| line.find(r#"{"event":"#).map(|start| &line[start..]))
        .filter_map(|json| serde_json::from_str(json).ok())
        .collect()
}

async fn post(client: &reqwest::Client, url: &str, body: Value) -> anyhow::Result<u16> {
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(body.to_string())
        .send()
        .await?;
    Ok(response.status().as_u16())
}

#[pdk_test]
#[ignore = "log forwarding check; run explicitly"]
async fn log_forwarding() -> anyhow::Result<()> {
    let log_dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/log-forwarding"
    ));
    let _ = std::fs::remove_dir_all(&log_dir);
    std::fs::create_dir_all(&log_dir)?;
    std::fs::write(log_dir.join("logs-config.yaml"), logging_config())?;
    let log_file = log_dir.join("runtime.log");

    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let api = ApiConfig::builder()
        .name("loggedApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(PORT)
        .policies([PolicyConfig::builder()
            .name(POLICY_NAME)
            .configuration(json!({
                "callerAttributes": "#[attributes.headers['x-test-roles']]",
                "grants": [{"attribute": "admin", "level": "destructive"}]
            }))
            .build()])
        .build();

    let flex_config = FlexConfig::builder()
        .version(flex_version())
        .hostname("local-flex")
        .with_api(api)
        .config_mounts([
            (POLICY_DIR, "policy"),
            (COMMON_CONFIG_DIR, "common"),
            (log_dir.to_str().unwrap(), MOUNT),
        ])
        .build();

    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    let flex: Flex = composite.service()?;
    let httpmock: HttpMock = composite.service()?;
    let server = MockServer::connect_async(httpmock.socket()).await;
    let client = reqwest::Client::new();

    // MCP upstream. The content type keeps OTLP posts (protobuf) out of it.
    server
        .mock_async(|when, then| {
            when.method(POST)
                .header("content-type", "application/json")
                .body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
                        {"name": "list_issues", "annotations": {"readOnlyHint": true}},
                        {"name": "delete_branch", "annotations": {"destructiveHint": true}}
                    ]}})
                    .to_string(),
                );
        })
        .await;
    // OTLP collector: counts the posts that carry a guard refusal.
    let otlp = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v1/logs")
                .body_contains("call_denied");
            then.status(200);
        })
        .await;
    server
        .mock_async(|when, then| {
            when.method(POST).path("/v1/logs");
            then.status(200);
        })
        .await;

    let url = format!("{}/mcp", flex.external_url(PORT).unwrap());
    // id 1: the upstream mock always answers id 1.
    let list = post(
        &client,
        &url,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await?;
    assert_eq!(list, 200);
    let refused = post(
        &client,
        &url,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "delete_branch", "arguments": {}}}),
    )
    .await?;
    println!("list {list}, delete_branch call {refused}");

    // Fluent Bit flushes on its own schedule.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut denied = None;
    let mut otlp_hits = 0;
    while Instant::now() < deadline && (denied.is_none() || otlp_hits == 0) {
        std::thread::sleep(Duration::from_secs(2));
        let log = std::fs::read_to_string(&log_file).unwrap_or_default();
        denied = guard_events(&log)
            .into_iter()
            .find(|e| e["event"] == "call_denied");
        otlp_hits = otlp.hits_async().await;
    }

    let log = std::fs::read_to_string(&log_file).unwrap_or_default();
    let events = guard_events(&log);
    println!(
        "file output: {} lines, {} guard events",
        log.lines().count(),
        events.len()
    );
    for event in &events {
        println!("  {event}");
    }
    println!("otlp posts with call_denied: {otlp_hits}");

    let denied = denied.expect("no call_denied event in the file output");
    assert_eq!(denied["tool"], "delete_branch");
    assert_eq!(denied["reason"], "level_insufficient");
    assert!(
        denied["apiInstance"].is_string(),
        "event without apiInstance: {denied}"
    );
    assert!(otlp_hits > 0, "no OTLP post carried the call_denied event");
    Ok(())
}
