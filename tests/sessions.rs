// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Negotiated MCP sessions through a local Omni Gateway, the way a client
//! talks to a server: `initialize`, `notifications/initialized`, `tools/list`,
//! then allowed and refused `tools/call`.
//!
//! - Protocol versions: 2025-03-26 and 2025-06-18, requested by the client
//!   and negotiated by the server (the test checks the server's answer).
//! - Responses: JSON, and SSE on the POST (one event, then the stream ends).
//! - Policy order: JWT Validation (RS256, static key), then the guard.
//! - Gateway: the image from `flex_version()` (1.13.0 unless
//!   `PDK_TEST_FLEX_IMAGE_VERSION` is set).
//! - Server: an httpmock stand-in that answers like a Streamable HTTP MCP
//!   server. It sets `Mcp-Session-Id` on `initialize` and answers later
//!   requests only when they carry it (and, for 2025-06-18, the
//!   `MCP-Protocol-Version` header), so the gateway is shown to pass both.
//!   Tools are protocol-valid, with an `inputSchema`.
//!
//! For each session the test checks that the client gets the tools its
//! verified identity may use, with their descriptors and annotations
//! unchanged, that allowed calls reach the server, and that refused calls do
//! not. MCP Support and MCP Schema Validation do not run on a local gateway;
//! they are covered by the scripted run on a Connected gateway.

mod common;
#[path = "common/jwt.rs"]
mod jwt;

use httpmock::{Method::POST, Mock, MockServer};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;
use jwt::{claims, jwt_validation, SigningKey};

const PORT: Port = 8081;

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Json,
    Sse,
}

#[derive(Clone, Copy, PartialEq)]
enum Caller {
    /// No grant: the default level, read.
    Viewer,
    /// Granted write by the `editor` role.
    Editor,
}

struct Session {
    version: &'static str,
    format: Format,
    caller: Caller,
}

impl Session {
    fn label(&self) -> String {
        let format = match self.format {
            Format::Json => "json",
            Format::Sse => "sse",
        };
        let caller = match self.caller {
            Caller::Viewer => "viewer",
            Caller::Editor => "editor",
        };
        format!("{}-{format}-{caller}", self.version)
    }

    fn id(&self) -> String {
        format!("session-{}", self.label())
    }

    /// Sent from `initialize` on, as a client does after negotiation.
    fn sends_protocol_header(&self) -> bool {
        self.version != "2025-03-26"
    }
}

fn sessions() -> [Session; 4] {
    [
        Session {
            version: "2025-03-26",
            format: Format::Json,
            caller: Caller::Viewer,
        },
        Session {
            version: "2025-03-26",
            format: Format::Sse,
            caller: Caller::Editor,
        },
        Session {
            version: "2025-06-18",
            format: Format::Json,
            caller: Caller::Editor,
        },
        Session {
            version: "2025-06-18",
            format: Format::Sse,
            caller: Caller::Viewer,
        },
    ]
}

/// The server's tools, as it lists them.
fn tools() -> Vec<Value> {
    let schema = |property: &str| {
        json!({"type": "object", "properties": {property: {"type": "string"}},
            "required": [property]})
    };
    vec![
        json!({"name": "search_issues", "description": "Search issues.",
            "inputSchema": schema("query"),
            "annotations": {"title": "Search issues", "readOnlyHint": true,
                "openWorldHint": false}}),
        json!({"name": "update_issue", "description": "Update an issue.",
            "inputSchema": schema("id"),
            "annotations": {"title": "Update issue", "readOnlyHint": false,
                "destructiveHint": false, "idempotentHint": true}}),
        json!({"name": "delete_repo", "description": "Delete a repository.",
            "inputSchema": schema("repo"),
            "annotations": {"title": "Delete repository", "readOnlyHint": false,
                "destructiveHint": true}}),
    ]
}

/// The tools a caller should see, unchanged.
fn visible(caller: Caller) -> Vec<Value> {
    let count = match caller {
        Caller::Viewer => 1,
        Caller::Editor => 2,
    };
    tools().into_iter().take(count).collect()
}

fn guard() -> PolicyConfig {
    PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(json!({
            "callerAttributes": "#[authentication.properties.claims.roles]",
            "grants": [{"attribute": "editor", "level": "write"}]
        }))
        .build()
}

fn token(key: &SigningKey, caller: Caller) -> String {
    let roles = match caller {
        Caller::Viewer => json!(["viewer"]),
        Caller::Editor => json!(["viewer", "editor"]),
    };
    key.sign(&claims(&json!({"roles": roles})))
}

/// The body of a server reply, in the session's format.
fn framed(format: Format, message: &Value) -> String {
    match format {
        Format::Json => message.to_string(),
        Format::Sse => format!("event: message\nid: 1\ndata: {message}\n\n"),
    }
}

fn content_type(format: Format) -> &'static str {
    match format {
        Format::Json => "application/json",
        Format::Sse => "text/event-stream",
    }
}

struct Reply {
    status: u16,
    headers: reqwest::header::HeaderMap,
    text: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The JSON-RPC message: the body, or the `data:` of the first SSE event.
    fn message(&self) -> Value {
        let data = if self
            .header("content-type")
            .is_some_and(|t| t.starts_with("text/event-stream"))
        {
            self.text
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .unwrap_or_default()
        } else {
            self.text.as_str()
        };
        serde_json::from_str(data).unwrap_or(Value::Null)
    }

    fn reason(&self) -> Option<String> {
        self.message()
            .pointer("/error/data/reason")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }
}

struct Client<'a> {
    http: reqwest::Client,
    url: &'a str,
    token: Option<String>,
    session: Option<String>,
    protocol: Option<&'static str>,
}

impl Client<'_> {
    async fn post(&self, message: Value) -> anyhow::Result<Reply> {
        let mut request = self
            .http
            .post(self.url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(message.to_string());
        if let Some(token) = &self.token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if let Some(session) = &self.session {
            request = request.header("mcp-session-id", session);
        }
        if let Some(protocol) = self.protocol {
            request = request.header("mcp-protocol-version", protocol);
        }
        let response = request.send().await?;
        Ok(Reply {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            text: response.text().await?,
        })
    }
}

fn initialize(session: &Session) -> Value {
    json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": session.version,
        "capabilities": {},
        "clientInfo": {"name": format!("client-{}", session.label()), "version": "1.0.0"}}})
}

fn call(id: u64, tool: &str, argument: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": tool, "arguments": {argument: "x"}}})
}

/// The server side of one session.
struct Server<'a> {
    initialize: Mock<'a>,
    initialized: Mock<'a>,
    list: Mock<'a>,
    calls: Vec<(&'static str, Mock<'a>)>,
}

async fn serve<'a>(server: &'a MockServer, session: &Session) -> Server<'a> {
    let format = session.format;
    let id = session.id();
    let version = session.version;
    let protocol = session.sends_protocol_header();
    // A request that belongs to this session, after `initialize`.
    let in_session = move |when: httpmock::When| {
        let when = when.method(POST).header("mcp-session-id", id.as_str());
        if protocol {
            when.header("mcp-protocol-version", version)
        } else {
            when
        }
    };

    let initialize = server
        .mock_async(|when, then| {
            when.method(POST)
                .body_contains(r#""method":"initialize""#)
                .body_contains(format!(r#""protocolVersion":"{version}""#))
                .body_contains(format!(r#""name":"client-{}""#, session.label()));
            let result = json!({"jsonrpc": "2.0", "id": 0, "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": true}},
                "serverInfo": {"name": "session-test-server", "version": "1.0.0"}}});
            then.status(200)
                .header("content-type", content_type(format))
                .header("mcp-session-id", session.id())
                .body(framed(format, &result));
        })
        .await;
    let initialized = server
        .mock_async(|when, then| {
            in_session(when).body_contains(r#""method":"notifications/initialized""#);
            then.status(202);
        })
        .await;
    let list = server
        .mock_async(|when, then| {
            in_session(when).body_contains(r#""method":"tools/list""#);
            let result = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tools()}});
            then.status(200)
                .header("content-type", content_type(format))
                .body(framed(format, &result));
        })
        .await;
    let mut calls = Vec::new();
    for tool in ["search_issues", "update_issue", "delete_repo"] {
        let mock = server
            .mock_async(|when, then| {
                in_session(when)
                    .body_contains(r#""method":"tools/call""#)
                    .body_contains(format!(r#""name":"{tool}""#));
                let result = json!({"jsonrpc": "2.0", "id": 2, "result": {
                    "content": [{"type": "text", "text": format!("{tool} done")}]}});
                then.status(200)
                    .header("content-type", content_type(format))
                    .body(framed(format, &result));
            })
            .await;
        calls.push((tool, mock));
    }
    Server {
        initialize,
        initialized,
        list,
        calls,
    }
}

impl Server<'_> {
    async fn calls_of(&self, tool: &str) -> usize {
        match self.calls.iter().find(|(name, _)| *name == tool) {
            Some((_, mock)) => mock.hits_async().await,
            None => unreachable!("no mock for {}", tool),
        }
    }
}

#[pdk_test]
async fn negotiated_sessions() -> anyhow::Result<()> {
    let key = SigningKey::generate();
    let other_key = SigningKey::generate_named("sessions-other");

    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();
    let api = ApiConfig::builder()
        .name("sessionsApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(PORT)
        .policies([jwt_validation(&key.public_pem), guard()])
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

    for session in sessions() {
        let label = session.label();
        let mock = serve(&server, &session).await;
        let mut client = Client {
            http: reqwest::Client::new(),
            url: &url,
            token: Some(token(&key, session.caller)),
            session: None,
            protocol: None,
        };

        // initialize: the server's version and session id reach the client.
        let reply = client.post(initialize(&session)).await?;
        assert_eq!(reply.status, 200, "{label}: {}", reply.text);
        let message = reply.message();
        let negotiated = message
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        assert_eq!(negotiated, session.version, "{label}: {message}");
        assert_eq!(
            reply.header("mcp-session-id"),
            Some(session.id().as_str()),
            "{label}"
        );
        mock.initialize.assert_hits_async(1).await;
        client.session = Some(session.id());
        if session.sends_protocol_header() {
            client.protocol = Some(session.version);
        }

        let reply = client
            .post(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await?;
        assert_eq!(reply.status, 202, "{label}: {}", reply.text);
        mock.initialized.assert_hits_async(1).await;

        // tools/list: what this caller may use, each descriptor unchanged.
        let reply = client
            .post(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
            .await?;
        assert_eq!(reply.status, 200, "{label}: {}", reply.text);
        assert!(
            reply
                .header("content-type")
                .is_some_and(|t| t.starts_with(content_type(session.format))),
            "{label}: {:?}",
            reply.header("content-type")
        );
        assert_eq!(
            reply.message().pointer("/result/tools"),
            Some(&json!(visible(session.caller))),
            "{label}"
        );
        assert_eq!(reply.header("cache-control"), Some("no-store"), "{label}");
        mock.list.assert_hits_async(1).await;

        // Allowed calls reach the server; refused calls do not.
        let allowed: &[(&str, &str)] = match session.caller {
            Caller::Viewer => &[("search_issues", "query")],
            Caller::Editor => &[("search_issues", "query"), ("update_issue", "id")],
        };
        let refused: &[(&str, &str)] = match session.caller {
            Caller::Viewer => &[("update_issue", "id"), ("delete_repo", "repo")],
            Caller::Editor => &[("delete_repo", "repo")],
        };
        for (i, (tool, argument)) in allowed.iter().enumerate() {
            let reply = client.post(call(2 + i as u64, tool, argument)).await?;
            assert_eq!(reply.status, 200, "{label} {tool}: {}", reply.text);
            assert_eq!(
                reply.message().pointer("/result/content/0/text"),
                Some(&json!(format!("{tool} done"))),
                "{label} {tool}: {}",
                reply.text
            );
            assert_eq!(mock.calls_of(tool).await, 1, "{label} {tool}");
        }
        for (i, (tool, argument)) in refused.iter().enumerate() {
            let reply = client.post(call(10 + i as u64, tool, argument)).await?;
            assert_eq!(reply.status, 200, "{label} {tool}: {}", reply.text);
            assert_eq!(
                reply.reason().as_deref(),
                Some("level_insufficient"),
                "{label} {tool}: {}",
                reply.text
            );
            assert_eq!(
                reply.message().get("id"),
                Some(&json!(10 + i as u64)),
                "{label} {tool}"
            );
            assert_eq!(mock.calls_of(tool).await, 0, "{label} {tool}");
        }

        // Only a verified identity counts: the same session with a token
        // from another key is refused by JWT Validation, before the guard.
        client.token = Some(token(&other_key, Caller::Editor));
        let reply = client
            .post(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
            .await?;
        assert!(
            (400..500).contains(&reply.status),
            "{label}: {} {}",
            reply.status,
            reply.text
        );
        mock.list.assert_hits_async(1).await;

        println!(
            "session {label}: requested {}, negotiated {negotiated}, gateway {}, \
             policies jwt-validation-flex -> {POLICY_NAME}",
            session.version,
            flex_version()
        );
    }
    Ok(())
}
