// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Many workers at once, with a catalog of 5,000 tools (the default
//! `maxCachedTools`). Every step uses many connections at once, which the
//! gateway spreads over its workers (the test gateway runs four).
//! - Lists are read in pages from many connections, so workers save the
//!   catalog at the same time. Meanwhile, calls to tools above the caller's
//!   level are sent from other connections: none reaches the server.
//! - Afterwards every read tool is allowed and every other tool refused: no
//!   worker's save lost another's tools.
//! - Once a client has a list in which tools turned destructive, no
//!   connection gets a call to them through.

mod common;

use std::collections::BTreeSet;
use std::ops::Range;

use httpmock::{Method::POST, MockServer};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};
use tokio::task::JoinHandle;

use common::*;

const PORT: Port = 8081;
const PAGES: usize = 10;
const PER_PAGE: usize = 500;
const TOOLS: usize = PAGES * PER_PAGE;
/// Concurrent clients in each step.
const CLIENTS: usize = 64;
const CALL_RESULT: &str =
    r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}"#;

/// Every third tool is read-only (`safe_`); the others are a write tool
/// (`edit_`) and an unannotated tool (`wipe_`, destructive by default).
fn name(i: usize) -> String {
    let prefix = ["safe", "edit", "wipe"][i % 3];
    format!("{prefix}_{i:04}")
}

fn is_safe(i: usize) -> bool {
    i.is_multiple_of(3)
}

/// Tool `i`. With `turned`, the read-only tools declare they are destructive.
fn tool(i: usize, turned: bool) -> Value {
    let schema = json!({"type": "object"});
    match i % 3 {
        0 if turned => json!({"name": name(i), "inputSchema": schema,
            "annotations": {"readOnlyHint": false, "destructiveHint": true}}),
        0 => json!({"name": name(i), "inputSchema": schema,
            "annotations": {"readOnlyHint": true}}),
        1 => json!({"name": name(i), "inputSchema": schema,
            "annotations": {"readOnlyHint": false, "destructiveHint": false}}),
        _ => json!({"name": name(i), "inputSchema": schema}),
    }
}

fn page_tools(page: usize) -> Range<usize> {
    page * PER_PAGE..(page + 1) * PER_PAGE
}

fn page_body(page: usize, turned: bool) -> String {
    let tools: Vec<Value> = page_tools(page).map(|i| tool(i, turned)).collect();
    let mut result = json!({ "tools": tools });
    if page + 1 < PAGES {
        result["nextCursor"] = json!(format!("p{}", page + 1));
    }
    json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string()
}

fn list(page: usize) -> Value {
    if page == 0 {
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    } else {
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": {"cursor": format!("p{page}")}})
    }
}

fn call(i: usize) -> Value {
    json!({"jsonrpc": "2.0", "id": i, "method": "tools/call",
        "params": {"name": name(i), "arguments": {}}})
}

async fn post(client: &reqwest::Client, url: &str, body: &Value) -> anyhow::Result<(u16, Value)> {
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(body.to_string())
        .send()
        .await?;
    let status = response.status().as_u16();
    let bytes = response.bytes().await?;
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

/// A client that opens a new connection for every request.
fn unpooled() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()?)
}

fn shown(reply: &Value) -> BTreeSet<String> {
    reply
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn safe_tools(page: usize) -> BTreeSet<String> {
    page_tools(page).filter(|&i| is_safe(i)).map(name).collect()
}

fn reason(reply: &Value) -> Option<&str> {
    reply.pointer("/error/data/reason").and_then(Value::as_str)
}

fn allowed(status: u16, reply: &Value) -> bool {
    status == 200 && reply.get("result").is_some() && reply.get("error").is_none()
}

fn excerpt(reply: &Value) -> String {
    reply.to_string().chars().take(300).collect()
}

type Task = JoinHandle<anyhow::Result<Vec<String>>>;

/// Every task's problems, once all of them are done.
async fn problems(tasks: Vec<Task>) -> anyhow::Result<Vec<String>> {
    let mut problems = Vec::new();
    for task in tasks {
        problems.extend(task.await??);
    }
    Ok(problems)
}

fn assert_none(step: &str, problems: &[String]) {
    assert!(
        problems.is_empty(),
        "{step}: {} problems, the first: {:#?}",
        problems.len(),
        &problems[..problems.len().min(5)]
    );
}

#[pdk_test]
async fn many_workers_share_one_catalog() -> anyhow::Result<()> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();
    let guard = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(json!({}))
        .build();
    let api = ApiConfig::builder()
        .name("workersApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(PORT)
        .policies([guard])
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

    // The first page is asked for without a cursor, the others with one.
    let first_page = server
        .mock_async(|when, then| {
            when.method(POST).body_contains("\"tools/list\"}");
            then.status(200)
                .header("content-type", "application/json")
                .body(page_body(0, false));
        })
        .await;
    for page in 1..PAGES {
        let cursor = format!("\"cursor\":\"p{page}\"");
        server
            .mock_async(|when, then| {
                when.method(POST).body_contains(cursor.as_str());
                then.status(200)
                    .header("content-type", "application/json")
                    .body(page_body(page, false));
            })
            .await;
    }
    let mut calls = Vec::new();
    for prefix in ["safe", "edit", "wipe"] {
        let needle = format!("\"name\":\"{prefix}_");
        calls.push(
            server
                .mock_async(|when, then| {
                    when.method(POST).body_contains(needle.as_str());
                    then.status(200)
                        .header("content-type", "application/json")
                        .body(CALL_RESULT);
                })
                .await,
        );
    }

    // Precondition: the guard runs (a tool it hasn't seen is refused).
    let (status, reply) = post(&unpooled()?, &url, &call(0)).await?;
    assert_eq!(
        reason(&reply),
        Some("unknown_tool"),
        "before any list: HTTP {status}, {}",
        excerpt(&reply)
    );

    // 1. Half the clients read every page, each starting at another page,
    //    while the other half call write and destructive tools.
    let mut tasks: Vec<Task> = Vec::new();
    for client_no in 0..CLIENTS / 2 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let client = unpooled()?;
            let mut problems = Vec::new();
            for step in 0..PAGES {
                let page = (client_no + step) % PAGES;
                let (status, reply) = post(&client, &url, &list(page)).await?;
                if status != 200 || shown(&reply) != safe_tools(page) {
                    problems.push(format!(
                        "page {page}: HTTP {status}, {} tools shown, {}",
                        shown(&reply).len(),
                        excerpt(&reply)
                    ));
                }
            }
            Ok(problems)
        }));
    }
    for client_no in 0..CLIENTS / 2 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let client = unpooled()?;
            let mut problems = Vec::new();
            for k in 0..2 * PAGES {
                // A write or destructive tool, spread over every page.
                let i = ((client_no * 2 * PAGES + k) * 37 % (TOOLS / 3)) * 3 + 1 + k % 2;
                let (status, reply) = post(&client, &url, &call(i)).await?;
                match reason(&reply) {
                    Some("unknown_tool") | Some("level_insufficient") => {}
                    _ => problems.push(format!("{}: HTTP {status}, {}", name(i), excerpt(&reply))),
                }
            }
            Ok(problems)
        }));
    }
    assert_none("while workers saved the catalog", &problems(tasks).await?);
    println!(
        "{} lists of {PER_PAGE} tools and {} refused calls on new connections",
        CLIENTS / 2 * PAGES,
        CLIENTS / 2 * 2 * PAGES
    );

    // 2. Every tool, from clients that each keep a connection.
    let mut tasks: Vec<Task> = Vec::new();
    for client_no in 0..CLIENTS {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut problems = Vec::new();
            for i in (client_no..TOOLS).step_by(CLIENTS) {
                let (status, reply) = post(&client, &url, &call(i)).await?;
                let expected = if is_safe(i) {
                    allowed(status, &reply)
                } else {
                    reason(&reply) == Some("level_insufficient")
                };
                if !expected {
                    problems.push(format!("{}: HTTP {status}, {}", name(i), excerpt(&reply)));
                }
            }
            Ok(problems)
        }));
    }
    assert_none("calls after the lists", &problems(tasks).await?);
    println!("{TOOLS} calls decided as listed, over {CLIENTS} connections");

    // 3. The first page's read tools turn destructive. Once a client has the
    //    new page, no connection gets a call to them through.
    first_page.delete_async().await;
    server
        .mock_async(|when, then| {
            when.method(POST).body_contains("\"tools/list\"}");
            then.status(200)
                .header("content-type", "application/json")
                .body(page_body(0, true));
        })
        .await;
    let (status, reply) = post(&unpooled()?, &url, &list(0)).await?;
    assert!(
        status == 200 && shown(&reply).is_empty(),
        "first page after its read tools turned destructive: HTTP {status}, {}",
        excerpt(&reply)
    );
    let forwarded = calls[0].hits_async().await;
    let turned: Vec<usize> = page_tools(0).filter(|&i| is_safe(i)).collect();
    let mut tasks: Vec<Task> = Vec::new();
    for client_no in 0..CLIENTS {
        let url = url.clone();
        let turned = turned.clone();
        tasks.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut problems = Vec::new();
            for k in 0..turned.len() {
                let i = turned[(client_no + k) % turned.len()];
                let (status, reply) = post(&client, &url, &call(i)).await?;
                if reason(&reply) != Some("level_insufficient") {
                    problems.push(format!("{}: HTTP {status}, {}", name(i), excerpt(&reply)));
                }
            }
            Ok(problems)
        }));
    }
    assert_none(
        "calls to tools that turned destructive",
        &problems(tasks).await?,
    );
    println!(
        "{} calls to {} tools that turned destructive refused",
        CLIENTS * turned.len(),
        turned.len()
    );

    assert_eq!(
        calls[0].hits_async().await,
        forwarded,
        "a call to a tool that turned destructive reached the server"
    );
    assert_eq!(
        calls[1].hits_async().await,
        0,
        "a write tool call reached the server"
    );
    assert_eq!(
        calls[2].hits_async().await,
        0,
        "a destructive tool call reached the server"
    );
    Ok(())
}
