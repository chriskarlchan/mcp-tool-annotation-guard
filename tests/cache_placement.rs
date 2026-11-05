// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Response cache placement: a response cache placed closer to
//! the upstream than the guard still has every hit authorized and filtered per
//! caller; the reverse order is unsupported. Uses the P4A MCP Response Cache
//! (github.com/P4A-Policies-for-Agents/mcp-response-cache-policy), which caches
//! `tools/list` with one shared key and allowlisted read-only `tools/call`
//! results, and serves hits as early responses (`x-mcp-cache: hit`).
//!
//! One local gateway serves two APIs on the same upstream:
//! - ordered: guard → cache → upstream
//! - misordered: cache → guard → upstream (documents why the cache must come after the guard)
//!
//! `get_file` is read-only by its annotations, so the cache will cache it, but
//! the guard overrides it to `write`: a reader must never get it.
//!
//! Opt-in (needs the cache built outside this repo; not part of `make test`):
//! 1. `git clone https://github.com/P4A-Policies-for-Agents/mcp-response-cache-policy <dir>`
//! 2. `cd <dir>/definition && make release-local` (writes the definition to
//!    `~/.exchange/exchange_modules/…`; nothing is sent to Anypoint)
//! 3. `cd <dir>/implementation && make build && anypoint-cli-v4 pdk install-policy
//!    --target <out> --path target/mcp_response_cache_policy/implementation/`
//! 4. `make build && MCP_RESPONSE_CACHE_DIR=<out> cargo test --test cache_placement -- --ignored --nocapture`
//!
//! Clean up afterwards with `rm -rf ~/.exchange <dir> <out>` (if nothing else
//! uses `~/.exchange`).

mod common;

use httpmock::{Method::POST, MockServer};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;

const ORDERED: Port = 8081;
const MISORDERED: Port = 8082;
const CACHE_POLICY_NAME: &str = "mcp-response-cache-policy-flex-v1-0";

const READER: &[(&str, &str)] = &[];
const EDITOR: &[(&str, &str)] = &[("x-test-roles", "editor")];
const ADMIN: &[(&str, &str)] = &[("x-test-roles", "admin")];

struct Reply {
    status: u16,
    cache: Option<String>,
    body: Value,
}

impl Reply {
    fn tool_names(&self) -> Vec<&str> {
        self.body
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .map(|tools| tools.iter().filter_map(|t| t["name"].as_str()).collect())
            .unwrap_or_default()
    }

    fn refusal(&self) -> Option<&str> {
        self.body
            .pointer("/error/data/reason")
            .and_then(Value::as_str)
    }

    fn text(&self) -> Option<&str> {
        self.body
            .pointer("/result/content/0/text")
            .and_then(Value::as_str)
    }
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> anyhow::Result<Reply> {
    let mut request = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.body(body.to_string()).send().await?;
    let status = response.status().as_u16();
    let cache = response
        .headers()
        .get("x-mcp-cache")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = response.bytes().await?;
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
    Ok(Reply {
        status,
        cache,
        body,
    })
}

fn list(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"})
}

fn call(id: u64, tool: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": tool, "arguments": {"path": "payroll.csv"}}})
}

#[pdk_test]
#[ignore = "needs the P4A MCP Response Cache built locally; run explicitly"]
async fn cache_placement() -> anyhow::Result<()> {
    let cache_dir = std::env::var("MCP_RESPONSE_CACHE_DIR").expect(
        "set MCP_RESPONSE_CACHE_DIR to the installed cache policy folder (see this file's header)",
    );

    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let guard = || {
        PolicyConfig::builder()
            .name(POLICY_NAME)
            .configuration(json!({
                "callerAttributes": "#[attributes.headers['x-test-roles']]",
                "callerAttributeSeparator": ",",
                "grants": [
                    {"attribute": "editor", "level": "write"},
                    {"attribute": "admin", "level": "destructive"}
                ],
                "toolOverrides": [{"name": "get_file", "class": "write"}]
            }))
            .build()
    };
    let cache = || {
        PolicyConfig::builder()
            .name(CACHE_POLICY_NAME)
            .configuration(json!({
                "discovery": {"cacheable": true, "ttl": 60},
                "tools": [{"name": "get_file", "cacheable": true, "ttl": 60, "scope": "shared"}]
            }))
            .build()
    };

    // The first policy in the list is closest to the client.
    let ordered = ApiConfig::builder()
        .name("orderedApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(ORDERED)
        .policies([guard(), cache()])
        .build();
    let misordered = ApiConfig::builder()
        .name("misorderedApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(MISORDERED)
        .policies([cache(), guard()])
        .build();

    let flex_config = FlexConfig::builder()
        .version(flex_version())
        .hostname("local-flex")
        .with_api(ordered)
        .with_api(misordered)
        .config_mounts([
            (POLICY_DIR, "policy"),
            (cache_dir.as_str(), "cache"),
            (COMMON_CONFIG_DIR, "common"),
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

    let upstream_list = server
        .mock_async(|when, then| {
            when.method(POST).body_contains("tools/list");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
                        {"name": "list_issues", "annotations": {"readOnlyHint": true}},
                        {"name": "get_file", "annotations": {"readOnlyHint": true}},
                        {"name": "delete_branch", "annotations": {"destructiveHint": true}}
                    ]}})
                    .to_string(),
                );
        })
        .await;
    let upstream_call = server
        .mock_async(|when, then| {
            when.method(POST).body_contains("tools/call").body_contains("get_file");
            then.status(200).header("content-type", "application/json").body(
                json!({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "salary data"}]}})
                    .to_string(),
            );
        })
        .await;

    // ---- Ordered: guard → cache → upstream ----
    let url = format!("{}/mcp", flex.external_url(ORDERED).unwrap());

    // id 1: the upstream mock always answers id 1 (see the misordered case).
    let admin_list = post(&client, &url, list(1), ADMIN).await?;
    println!(
        "ordered    admin  list: {:?} {:?}",
        admin_list.cache,
        admin_list.tool_names()
    );
    assert_eq!(
        admin_list.cache.as_deref(),
        Some("miss"),
        "cache not active on the ordered API"
    );
    assert_eq!(
        admin_list.tool_names(),
        ["list_issues", "get_file", "delete_branch"]
    );

    // The reader's list is a cache hit (the upstream is not called again)
    // and is still filtered by the guard.
    let reader_list = post(&client, &url, list(2), READER).await?;
    println!(
        "ordered    reader list: {:?} {:?}",
        reader_list.cache,
        reader_list.tool_names()
    );
    assert_eq!(reader_list.cache.as_deref(), Some("hit"));
    assert_eq!(upstream_list.hits_async().await, 1);
    assert_eq!(
        reader_list.tool_names(),
        ["list_issues"],
        "cache hit not filtered for the reader"
    );
    assert_eq!(reader_list.body["id"], 2);

    // The editor's call warms the tool cache.
    let first = post(&client, &url, call(3, "get_file"), EDITOR).await?;
    let second = post(&client, &url, call(4, "get_file"), EDITOR).await?;
    println!(
        "ordered    editor call: {:?} then {:?}",
        first.cache, second.cache
    );
    assert_eq!(
        (first.cache.as_deref(), second.cache.as_deref()),
        (Some("miss"), Some("hit"))
    );
    assert_eq!(second.text(), Some("salary data"));
    assert_eq!(upstream_call.hits_async().await, 1);

    // The reader is refused before the cache is consulted.
    let reader_call = post(&client, &url, call(5, "get_file"), READER).await?;
    println!(
        "ordered    reader call: {} {:?} {:?}",
        reader_call.status,
        reader_call.cache,
        reader_call.refusal()
    );
    assert_eq!(reader_call.refusal(), Some("level_insufficient"));
    assert_eq!(reader_call.cache, None, "the cache saw a refused call");
    assert_eq!(reader_call.text(), None);
    assert_eq!(upstream_call.hits_async().await, 1);

    // ---- Misordered (unsupported): cache → guard → upstream ----
    let url = format!("{}/mcp", flex.external_url(MISORDERED).unwrap());

    // id 1: the upstream mock always answers id 1, and the guard rejects a
    // list whose id does not match the request.
    let admin_list = post(&client, &url, list(1), ADMIN).await?;
    println!(
        "misordered admin  list: {:?} {:?}",
        admin_list.cache,
        admin_list.tool_names()
    );
    assert_eq!(
        admin_list.cache.as_deref(),
        Some("miss"),
        "caches are shared between the two APIs"
    );

    // Precondition: the guard is active on this API.
    let reader_delete = post(&client, &url, call(12, "delete_branch"), READER).await?;
    assert_eq!(
        reader_delete.refusal(),
        Some("level_insufficient"),
        "guard not active on the misordered API"
    );

    let reader_list = post(&client, &url, list(13), READER).await?;
    println!(
        "misordered reader list: {:?} {:?}",
        reader_list.cache,
        reader_list.tool_names()
    );

    let first = post(&client, &url, call(14, "get_file"), EDITOR).await?;
    let second = post(&client, &url, call(15, "get_file"), EDITOR).await?;
    println!(
        "misordered editor call: {:?} then {:?}",
        first.cache, second.cache
    );

    let reader_call = post(&client, &url, call(16, "get_file"), READER).await?;
    println!(
        "misordered reader call: {} {:?} refusal {:?} text {:?}",
        reader_call.status,
        reader_call.cache,
        reader_call.refusal(),
        reader_call.text()
    );

    // Expected leak: hits are served before the guard runs, so the reader
    // gets the admin's list and the editor's cached result. If this ever
    // changes, update the policy-order documentation.
    assert_eq!(reader_list.cache.as_deref(), Some("hit"));
    assert_eq!(
        reader_list.tool_names(),
        ["list_issues", "get_file", "delete_branch"]
    );
    assert_eq!(reader_call.cache.as_deref(), Some("hit"));
    assert_eq!(reader_call.text(), Some("salary data"));
    Ok(())
}
