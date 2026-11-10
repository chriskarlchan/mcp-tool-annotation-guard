// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Request IDs with a real JavaScript server. The repo's Node mock reads JSON
//! with `JSON.parse`, as servers written in JavaScript do, so it answers an
//! integer ID beyond ±9007199254740991 with a rounded one.
//!
//! The test first shows that rounding by asking the server directly, then
//! checks through the guard that:
//! - a list or a call with such an ID is refused `id_range`, answered with
//!   the ID as sent, and never reaches the server;
//! - a list with the largest safe ID, or with the same digits as a string, is
//!   filtered and answered with the ID as sent;
//! - what the guard learned stays trusted: a read call still goes through and
//!   a destructive call is still refused.
//!
//! The upstream is the repo's Node mock, started by the test on host port
//! `JS_IDS_MOCK_PORT` (default 8093) and reached from the gateway container
//! at `host.docker.internal`.
//!
//! Opt-in (needs Node and Docker Desktop): `make build && cargo test --test
//! js_server_ids -- --ignored --nocapture`

mod common;

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::HttpMockConfig;
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;

const GUARDED: Port = 8081;
const ACCEPT: &str = "application/json, text/event-stream";
/// 2^53 + 1, which a double can't hold: JavaScript reads it as 2^53.
const BIG_ID: &str = "9007199254740993";
const ROUNDED_ID: &str = "9007199254740992";

/// The Node mock, stopped when the test ends.
struct NodeMock(Child);

impl Drop for NodeMock {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn mock_port() -> u16 {
    std::env::var("JS_IDS_MOCK_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8093)
}

async fn start_mock(port: u16) -> anyhow::Result<NodeMock> {
    let child = Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/mock-mcp-server/server.mjs"
        ))
        .env("PORT", port.to_string())
        .env("RESPONSE_MODE", "json")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mock = NodeMock(child);
    let client = reqwest::Client::new();
    let wire = format!("http://127.0.0.1:{port}/__wire");
    for _ in 0..50 {
        if client.get(&wire).send().await.is_ok() {
            return Ok(mock);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("the mock did not start on port {port}")
}

/// A `tools/list` request with `id` written exactly as given.
fn list(id: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/list"}}"#)
}

/// A `tools/call` request with `id` written exactly as given.
fn call(id: &str, tool: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{{}}}}}}"#
    )
}

/// Status and body text of a POST.
async fn post(client: &reqwest::Client, url: &str, body: String) -> anyhow::Result<(u16, String)> {
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", ACCEPT)
        .body(body)
        .send()
        .await?;
    let status = response.status().as_u16();
    Ok((status, response.text().await?))
}

fn parse(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::Null)
}

fn tool_names(body: &Value) -> Vec<&str> {
    body.pointer("/result/tools")
        .and_then(Value::as_array)
        .map(|tools| tools.iter().filter_map(|t| t["name"].as_str()).collect())
        .unwrap_or_default()
}

/// Whether a list answer is the filtered list a default (read) caller gets.
fn is_filtered(body: &Value) -> bool {
    let names = tool_names(body);
    names.contains(&"list_issues") && !names.contains(&"delete_repository")
}

async fn diagnostics(client: &reqwest::Client, port: u16, path: &str) -> anyhow::Result<Value> {
    let url = format!("http://127.0.0.1:{port}{path}");
    Ok(serde_json::from_str(
        &client.get(url).send().await?.text().await?,
    )?)
}

/// Requests the mock received since the last reset.
async fn received(client: &reqwest::Client, port: u16) -> anyhow::Result<usize> {
    let wire = diagnostics(client, port, "/__wire").await?;
    Ok(wire["requests"].as_array().map_or(0, Vec::len))
}

async fn reset(client: &reqwest::Client, port: u16) -> anyhow::Result<()> {
    client
        .post(format!("http://127.0.0.1:{port}/__reset"))
        .send()
        .await?;
    Ok(())
}

#[pdk_test]
#[ignore = "needs Node and host.docker.internal; run explicitly"]
async fn js_server_ids() -> anyhow::Result<()> {
    let port = mock_port();
    let _mock = start_mock(port).await?;
    let client = reqwest::Client::new();

    // ---- The server answers 2^53 + 1 with 2^53 ----
    let direct = format!("http://127.0.0.1:{port}/mcp");
    let (status, text) = post(&client, &direct, list(BIG_ID)).await?;
    anyhow::ensure!(status == 200, "direct list: status {status}");
    anyhow::ensure!(
        text.contains(&format!(r#""id":{ROUNDED_ID}"#)) && !text.contains(BIG_ID),
        "the server echoed the ID unchanged, so this test shows nothing: {text}"
    );
    println!("The server answered id {BIG_ID} with id {ROUNDED_ID}");

    // Only used for its address: the gateway reaches the mock on the host.
    let host_mock = HttpMockConfig::builder()
        .hostname("host.docker.internal")
        .port(port)
        .build();
    let guard = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(json!({}))
        .build();
    let guarded = ApiConfig::builder()
        .name("guardedApi")
        .upstream(&host_mock)
        .path("/")
        .port(GUARDED)
        .policies([guard])
        .build();
    let flex_config = FlexConfig::builder()
        .version(flex_version())
        .hostname("local-flex")
        .with_api(guarded)
        .config_mounts([(POLICY_DIR, "policy"), (COMMON_CONFIG_DIR, "common")])
        .build();
    let composite = TestComposite::builder()
        .with_service(flex_config)
        .build()
        .await?;
    let flex: Flex = composite.service()?;
    let url = format!("{}/mcp", flex.external_url(GUARDED).unwrap());
    println!("Omni Gateway {}", flex_version());

    // Every check runs, so a failure shows everything that went wrong.
    let mut failures: Vec<String> = Vec::new();
    let mut check = |ok: bool, what: String| {
        println!("{} {what}", if ok { "ok  " } else { "FAIL" });
        if !ok {
            failures.push(what);
        }
    };

    // ---- IDs the server echoes as sent are filtered as usual ----
    let (status, text) = post(&client, &url, list("9007199254740991")).await?;
    let body = parse(&text);
    check(
        status == 200 && body["id"] == json!(9_007_199_254_740_991_u64) && is_filtered(&body),
        format!("a list with id 9007199254740991 is filtered: status {status}, {text}"),
    );
    let (status, text) = post(&client, &url, list(&format!("\"{BIG_ID}\""))).await?;
    let body = parse(&text);
    check(
        status == 200 && body["id"] == json!(BIG_ID) && is_filtered(&body),
        format!("a list with id \"{BIG_ID}\" is filtered: status {status}, {text}"),
    );

    // ---- IDs the server would round are refused and never forwarded ----
    let negative = format!("-{BIG_ID}");
    for (what, id, request) in [
        ("call", BIG_ID, call(BIG_ID, "list_issues")),
        ("list", BIG_ID, list(BIG_ID)),
        ("list", negative.as_str(), list(&negative)),
    ] {
        reset(&client, port).await?;
        let (status, text) = post(&client, &url, request.clone()).await?;
        let detail = parse(&text).pointer("/error/data/detail").cloned();
        check(
            status == 400
                && detail == Some(json!("id_range"))
                && text.contains(&format!(r#""id":{id},"#)),
            format!("a {what} {request} is refused id_range with its id: status {status}, {text}"),
        );
        let count = received(&client, port).await?;
        check(
            count == 0,
            format!("the {what} {request} is not forwarded: the server got {count} requests"),
        );
    }

    // ---- What the guard learned is still trusted ----
    reset(&client, port).await?;
    let (status, text) = post(&client, &url, call("2", "list_issues")).await?;
    check(
        status == 200 && parse(&text).pointer("/result/content").is_some(),
        format!("a read call goes through: status {status}, {text}"),
    );
    let (status, text) = post(&client, &url, call("3", "delete_repository")).await?;
    let reason = parse(&text).pointer("/error/data/reason").cloned();
    check(
        reason == Some(json!("level_insufficient")),
        format!("a destructive call is refused: status {status}, {text}"),
    );
    let calls = diagnostics(&client, port, "/__calls").await?;
    check(
        calls["calls"] == json!(["list_issues"]),
        format!("only the read call reached the server: {calls}"),
    );

    anyhow::ensure!(failures.is_empty(), "\n{}", failures.join("\n"));
    Ok(())
}
