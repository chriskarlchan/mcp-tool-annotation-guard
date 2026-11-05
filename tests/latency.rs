// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Latency gate: added p99 on `tools/call` with the
//! guard ≤ 1 ms. One local gateway serves two otherwise identical APIs, one
//! with the guard and one without; requests alternate between them so drift
//! affects both equally. 100 warm-up and 1000 measured sequential calls per
//! API, 10 KB request bodies, warm catalog.
//!
//! Opt-in (timing-sensitive, not part of `make test`):
//! `make build && cargo test --test latency -- --ignored --nocapture`

mod common;

use std::time::{Duration, Instant};

use httpmock::{Method::POST, MockServer};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::json;

use common::*;

const GUARDED: Port = 8081;
const BARE: Port = 8082;
const WARMUP: usize = 100;
const MEASURED: usize = 1000;
const BUDGET: Duration = Duration::from_millis(1);

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn summary(label: &str, samples: &mut [Duration]) -> Duration {
    samples.sort();
    let mean = samples.iter().sum::<Duration>() / samples.len() as u32;
    let p99 = percentile(samples, 99.0);
    println!(
        "{label:>8}: p50 {:>8.3} ms  p90 {:>8.3} ms  p99 {:>8.3} ms  mean {:>8.3} ms  max {:>8.3} ms",
        percentile(samples, 50.0).as_secs_f64() * 1e3,
        percentile(samples, 90.0).as_secs_f64() * 1e3,
        p99.as_secs_f64() * 1e3,
        mean.as_secs_f64() * 1e3,
        samples[samples.len() - 1].as_secs_f64() * 1e3,
    );
    p99
}

async fn timed(client: &reqwest::Client, url: &str, body: &str) -> anyhow::Result<Duration> {
    let start = Instant::now();
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(body.to_owned())
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    let elapsed = start.elapsed();
    anyhow::ensure!(status == 200, "status {status}");
    anyhow::ensure!(
        !bytes.windows(7).any(|w| w == b"\"error\""),
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(elapsed)
}

#[pdk_test]
#[ignore = "timing benchmark; run explicitly"]
async fn latency_gate() -> anyhow::Result<()> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let guard = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(json!({}))
        .build();
    let guarded = ApiConfig::builder()
        .name("guardedApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(GUARDED)
        .policies([guard])
        .build();
    let bare = ApiConfig::builder()
        .name("bareApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
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
        .with_service(httpmock_config)
        .build()
        .await?;

    let flex: Flex = composite.service()?;
    let guarded_url = format!("{}/mcp", flex.external_url(GUARDED).unwrap());
    let bare_url = format!("{}/mcp", flex.external_url(BARE).unwrap());
    let httpmock: HttpMock = composite.service()?;
    let server = MockServer::connect_async(httpmock.socket()).await;

    server
        .mock_async(|when, then| {
            when.method(POST).body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
                        {"name": "fetch", "annotations": {"readOnlyHint": true}}
                    ]}})
                    .to_string(),
                );
        })
        .await;
    server
        .mock_async(|when, then| {
            when.method(POST).body_contains("tools/call");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}"#);
        })
        .await;

    let client = reqwest::Client::new();
    // Warm catalog: the guard learns `fetch` from a list.
    timed(
        &client,
        &guarded_url,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
    )
    .await?;

    // Precondition: the guard is on the guarded API only (an unlisted tool is
    // refused there and forwarded on the bare API).
    let unlisted = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "unlisted", "arguments": {}}})
    .to_string();
    // A missing or misnamed policy is only logged by the gateway, which then
    // serves the API without it; this check stops the run from timing that.
    let probe = timed(&client, &guarded_url, &unlisted).await;
    assert!(
        probe.is_err(),
        "guard not active on the guarded API: {:?} (run `make build`)",
        probe
    );
    timed(&client, &bare_url, &unlisted).await?;

    // 10 KB `tools/call` body.
    let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "fetch", "arguments": {"payload": "x".repeat(10_140)}}})
    .to_string();
    assert!((10_000..10_400).contains(&call.len()), "{}", call.len());

    for _ in 0..WARMUP {
        timed(&client, &guarded_url, &call).await?;
        timed(&client, &bare_url, &call).await?;
    }
    let mut with_guard = Vec::with_capacity(MEASURED);
    let mut without = Vec::with_capacity(MEASURED);
    for i in 0..MEASURED {
        // Alternate which API goes first, so ordering effects cancel out.
        if i % 2 == 0 {
            with_guard.push(timed(&client, &guarded_url, &call).await?);
            without.push(timed(&client, &bare_url, &call).await?);
        } else {
            without.push(timed(&client, &bare_url, &call).await?);
            with_guard.push(timed(&client, &guarded_url, &call).await?);
        }
    }

    println!("{MEASURED} sequential tools/call, {} B body", call.len());
    let p99_guard = summary("guard", &mut with_guard);
    let p99_bare = summary("no guard", &mut without);
    let added = p99_guard.saturating_sub(p99_bare);
    println!(
        "   added p99: {:.3} ms (budget {:.3} ms)",
        added.as_secs_f64() * 1e3,
        BUDGET.as_secs_f64() * 1e3
    );
    assert!(
        added <= BUDGET,
        "added p99 {:?} exceeds {:?}",
        added,
        BUDGET
    );
    Ok(())
}
