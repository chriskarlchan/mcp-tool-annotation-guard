// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! SSE list with a server request first: a `tools/list` answered with an SSE stream
//! whose server first sends a server-to-client request (an elicitation) and
//! waits for the client's reply before sending the list.
//!
//! The guard buffers SSE list responses whole, so the client never sees
//! the elicitation and can't reply: the list stalls. One local gateway serves
//! two APIs on the same upstream, one with the guard and one without:
//! - without the guard, the client gets the elicitation, replies, then gets
//!   the list (the exchange itself is valid);
//! - with the guard and nobody replying, no response reaches the client; the
//!   test reports what happens within `STALL_LIMIT`;
//! - with the guard and the reply sent straight to the server (standing in
//!   for a client that could see the request), the buffered stream completes
//!   and the client gets the elicitation event and the filtered list.
//!
//! The upstream is the repo's Node mock (`SSE_SERVER_REQUEST_FIRST=true`),
//! started by the test on host port `S22_MOCK_PORT` (default 8090) and
//! reached from the gateway container at `host.docker.internal`.
//!
//! Opt-in (needs Node and Docker Desktop; slow): `make build && cargo test
//! --test sse_server_request_first -- --ignored --nocapture`

mod common;

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::HttpMockConfig;
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;

const GUARDED: Port = 8081;
const BARE: Port = 8082;
/// How long the test waits for the stalled list before giving up.
const STALL_LIMIT: Duration = Duration::from_secs(120);
const ACCEPT: &str = "application/json, text/event-stream";

/// The Node mock, stopped when the test ends.
struct NodeMock(Child);

impl Drop for NodeMock {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn mock_port() -> u16 {
    std::env::var("S22_MOCK_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8090)
}

async fn start_mock(port: u16) -> anyhow::Result<NodeMock> {
    let child = Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/mock-mcp-server/server.mjs"
        ))
        .env("PORT", port.to_string())
        .env("RESPONSE_MODE", "sse")
        .env("SSE_SERVER_REQUEST_FIRST", "true")
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

fn list(id: i64) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"}).to_string()
}

fn reply(id: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": {"action": "decline"}}).to_string()
}

/// JSON payloads of the `data:` lines received so far.
fn events(raw: &str) -> Vec<Value> {
    raw.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str(data.trim()).ok())
        .collect()
}

fn tool_names(events: &[Value]) -> Option<Vec<String>> {
    events.iter().find_map(|event| {
        let tools = event.pointer("/result/tools")?.as_array()?;
        Some(
            tools
                .iter()
                .filter_map(|t| t["name"].as_str().map(str::to_owned))
                .collect(),
        )
    })
}

#[pdk_test]
#[ignore = "needs Node and host.docker.internal; slow; run explicitly"]
async fn sse_server_request_first() -> anyhow::Result<()> {
    let port = mock_port();
    let _mock = start_mock(port).await?;
    let direct = format!("http://127.0.0.1:{port}/mcp");

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
    let bare = ApiConfig::builder()
        .name("bareApi")
        .upstream(&host_mock)
        .path("/")
        .port(BARE)
        .policies(Vec::<PolicyConfig>::new())
        .build();
    let flex_config = FlexConfig::builder()
        .version(flex_version())
        .hostname("local-flex")
        .with_api(guarded)
        .with_api(bare)
        .config_mounts([(POLICY_DIR, "policy"), (COMMON_CONFIG_DIR, "common")])
        .build();
    let composite = TestComposite::builder()
        .with_service(flex_config)
        .build()
        .await?;
    let flex: Flex = composite.service()?;
    let guarded_url = format!("{}/mcp", flex.external_url(GUARDED).unwrap());
    let bare_url = format!("{}/mcp", flex.external_url(BARE).unwrap());
    let client = reqwest::Client::new();
    println!("Omni Gateway {}", flex_version());

    // ---- 1. Without the guard: elicitation, reply, list ----
    let start = Instant::now();
    let mut response = client
        .post(&bare_url)
        .header("content-type", "application/json")
        .header("accept", ACCEPT)
        .body(list(1))
        .send()
        .await?;
    anyhow::ensure!(
        response.status() == 200,
        "bare list: status {}",
        response.status()
    );
    let mut raw = String::new();
    let server_request = loop {
        let chunk = tokio::time::timeout(Duration::from_secs(10), response.chunk())
            .await
            .map_err(|_| anyhow::anyhow!("bare: no elicitation within 10 s"))??
            .ok_or_else(|| anyhow::anyhow!("bare: stream ended before the elicitation"))?;
        raw.push_str(&String::from_utf8_lossy(&chunk));
        if let Some(e) = events(&raw)
            .into_iter()
            .find(|e| e["method"] == "elicitation/create")
        {
            break e;
        }
    };
    let elicitation_after = start.elapsed();
    let answered = client
        .post(&bare_url)
        .header("content-type", "application/json")
        .header("accept", ACCEPT)
        .body(reply(&server_request["id"]))
        .send()
        .await?;
    anyhow::ensure!(
        answered.status() == 202,
        "bare reply: status {}",
        answered.status()
    );
    while let Some(chunk) = tokio::time::timeout(Duration::from_secs(10), response.chunk())
        .await
        .map_err(|_| anyhow::anyhow!("bare: no list within 10 s of the reply"))??
    {
        raw.push_str(&String::from_utf8_lossy(&chunk));
    }
    let bare_tools =
        tool_names(&events(&raw)).ok_or_else(|| anyhow::anyhow!("bare: no list in {raw}"))?;
    println!(
        "1. without the guard: elicitation after {:.0} ms, list after the reply ({} tools, total {:.0} ms)",
        elicitation_after.as_secs_f64() * 1e3,
        bare_tools.len(),
        start.elapsed().as_secs_f64() * 1e3,
    );
    anyhow::ensure!(
        bare_tools.iter().any(|t| t == "delete_branch"),
        "bare list: {bare_tools:?}"
    );

    // ---- 2. With the guard, nobody replies: the list stalls ----
    let start = Instant::now();
    let stalled = tokio::time::timeout(STALL_LIMIT, async {
        let response = client
            .post(&guarded_url)
            .header("content-type", "application/json")
            .header("accept", ACCEPT)
            .body(list(2))
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        anyhow::Ok((status, body))
    })
    .await;
    let waited = start.elapsed();
    match &stalled {
        Err(_) => println!(
            "2. with the guard, no reply: no response within {} s",
            STALL_LIMIT.as_secs()
        ),
        Ok(Ok((status, body))) => println!(
            "2. with the guard, no reply: HTTP {status} after {:.1} s, body {:?}",
            waited.as_secs_f64(),
            body.chars().take(200).collect::<String>(),
        ),
        Ok(Err(err)) => println!(
            "2. with the guard, no reply: error after {:.1} s: {err}",
            waited.as_secs_f64()
        ),
    }
    if let Ok(Ok((_, body))) = &stalled {
        anyhow::ensure!(
            tool_names(&events(body)).is_none(),
            "a list reached the client: {body}"
        );
    }
    anyhow::ensure!(
        waited >= Duration::from_secs(10),
        "answered within {waited:?}, expected a stall"
    );

    // ---- 3. With the guard, the reply goes straight to the server ----
    // The mock numbers its requests srv-1, srv-2, …; this list gets the next one.
    let next = server_request["id"]
        .as_str()
        .and_then(|id| id.strip_prefix("srv-"))
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("unexpected server request id {}", server_request["id"]))?
        + 2;
    let start = Instant::now();
    let pending = tokio::spawn({
        let client = client.clone();
        let url = guarded_url.clone();
        async move {
            let response = client
                .post(&url)
                .header("content-type", "application/json")
                .header("accept", ACCEPT)
                .body(list(3))
                .send()
                .await?;
            let status = response.status();
            let body = response.text().await?;
            anyhow::Ok((status, body, start.elapsed()))
        }
    });
    tokio::time::sleep(Duration::from_secs(3)).await;
    anyhow::ensure!(
        !pending.is_finished(),
        "the guarded list answered before the reply"
    );
    let answered = client
        .post(&direct)
        .header("content-type", "application/json")
        .header("accept", ACCEPT)
        .body(reply(&json!(format!("srv-{next}"))))
        .send()
        .await?;
    anyhow::ensure!(
        answered.status() == 202,
        "direct reply: status {}",
        answered.status()
    );
    let (status, body, elapsed) = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .map_err(|_| anyhow::anyhow!("guarded: no list within 10 s of the reply"))???;
    let received = events(&body);
    let guarded_tools =
        tool_names(&received).ok_or_else(|| anyhow::anyhow!("guarded: no list in {body}"))?;
    println!(
        "3. with the guard, reply sent to the server after 3 s: HTTP {status} after {:.1} s, elicitation event {}, {} of {} tools",
        elapsed.as_secs_f64(),
        if received.iter().any(|e| e["method"] == "elicitation/create") { "included" } else { "missing" },
        guarded_tools.len(),
        bare_tools.len(),
    );
    anyhow::ensure!(status == 200, "guarded list: status {status}");
    anyhow::ensure!(
        !guarded_tools.iter().any(|t| t == "delete_branch"),
        "not filtered: {guarded_tools:?}"
    );
    Ok(())
}
