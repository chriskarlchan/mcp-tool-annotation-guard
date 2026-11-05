// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! PDK unit tests of the glue: the request phase
//! and `tools/list` responses. guard-core has the exhaustive tests;
//! these check that the glue applies its results: what reaches the backend,
//! status, headers and body.

use std::rc::Rc;

use pdk_unit::{
    dw2pel, TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder,
};
use serde_json::{json, Value};

/// A `tools/list` result with these tools.
fn list_body(tools: Value) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}).to_string()
}

fn mixed_tools() -> Value {
    json!([
        {"name": "search", "annotations": {"readOnlyHint": true}},
        {"name": "drop", "annotations": {"destructiveHint": true}}
    ])
}

/// Answers with the reply the request asks for in `x-test-reply`; a plain
/// JSON-RPC result otherwise.
fn ok_backend(request: UnitHttpRequest) -> UnitHttpResponse {
    let json = |body: String| {
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_header("etag", "\"v1\"")
            .with_header("digest", "sha-256=abc")
            .with_body(body.into_bytes())
    };
    match request.header("x-test-reply") {
        Some("list") => json(list_body(mixed_tools())),
        Some("list-read-only") => json(list_body(
            json!([{"name": "search", "annotations": {"readOnlyHint": true}}]),
        )),
        // `drop` now claims to be read-only: a downgrade.
        Some("list-downgrade") => json(list_body(
            json!([{"name": "drop", "annotations": {"readOnlyHint": true}}]),
        )),
        Some("list-chunked") => UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_body(list_body(mixed_tools()).into_bytes()),
        Some("list-gzip") => json(list_body(mixed_tools())).with_header("content-encoding", "gzip"),
        Some("list-sse") => UnitHttpResponse::new(200)
            .with_header("content-type", "text/event-stream")
            .with_body(
                format!("event: message\ndata: {}\n\n", list_body(mixed_tools())).into_bytes(),
            ),
        _ => UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_body(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec()),
    }
}

/// The recording upstream every test sends to.
type Upstream = TraceBackend<fn(UnitHttpRequest) -> UnitHttpResponse>;

struct Harness {
    backend: Rc<Upstream>,
    tester: pdk_unit::UnitTest,
}

fn harness(config: Value) -> Harness {
    let backend: Rc<Upstream> = Rc::new(TraceBackend::new(ok_backend));
    let tester = UnitTestBuilder::default()
        .with_config(config.to_string())
        .with_backend(Rc::clone(&backend))
        .with_entrypoint(super::configure);
    Harness { backend, tester }
}

fn call(id: u64, tool: &str) -> Vec<u8> {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {}}})
        .to_string()
        .into_bytes()
}

fn post(body: Vec<u8>) -> UnitHttpRequest {
    UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("accept", "application/json, text/event-stream")
        .with_body(body)
}

fn body_json(response: &UnitHttpResponse) -> Value {
    serde_json::from_slice(response.body()).unwrap_or(Value::Null)
}

/// The JSON-RPC error of a refusal, or `Null`.
fn error_of(response: &UnitHttpResponse) -> Value {
    body_json(response)
        .get("error")
        .cloned()
        .unwrap_or(Value::Null)
}

fn reason_of(response: &UnitHttpResponse) -> Value {
    error_of(response)
        .pointer("/data/reason")
        .cloned()
        .unwrap_or(Value::Null)
}

impl Harness {
    fn send(&mut self, request: UnitHttpRequest) -> UnitHttpResponse {
        self.tester.request(request)
    }

    /// `true` if the request reached the backend (drains one entry).
    fn forwarded(&self) -> bool {
        self.backend.next().is_some()
    }
}

// --- unknown and unannotated tools under defaults ----------

#[test]
fn unknown_tool_call_is_refused_without_reaching_the_backend() {
    let mut h = harness(json!({}));
    let response = h.send(post(call(7, "delete_everything")));
    assert_eq!(response.status_code(), 200);
    assert_eq!(response.header("cache-control"), Some("no-store"));
    let body = body_json(&response);
    assert_eq!(body["id"], json!(7));
    assert_eq!(error_of(&response)["code"], json!(-32008));
    assert_eq!(reason_of(&response), json!("unknown_tool"));
    assert!(
        !h.forwarded(),
        "a refused request must not reach the upstream"
    );
}

#[test]
fn classify_by_name_allows_a_matching_read_tool() {
    let mut h = harness(json!({
        "onUnknownTool": "classifyByName",
        "nameRules": [{"pattern": "^get_", "class": "read"}]
    }));
    let allowed = h.send(post(call(1, "get_weather")));
    assert_eq!(allowed.status_code(), 200);
    assert!(h.forwarded());

    // No rule matches: unannotatedAs (destructive) is above the default level.
    let refused = h.send(post(call(2, "drop_table")));
    assert_eq!(reason_of(&refused), json!("level_insufficient"));
    assert!(!h.forwarded());
}

#[test]
fn overrides_make_a_tool_known() {
    let mut h = harness(json!({"toolOverrides": [{"name": "search", "class": "read"}]}));
    let response = h.send(post(call(1, "search")));
    assert_eq!(response.status_code(), 200);
    assert!(h.forwarded());
}

// --- grants through caller attributes ---------------------

#[test]
fn header_attributes_raise_the_caller_level() {
    let mut h = harness(json!({
        "callerAttributes": dw2pel("attributes.headers['x-test-roles']"),
        "callerAttributeSeparator": ",",
        "grants": [{"attribute": "editor", "level": "write"}],
        "toolOverrides": [{"name": "update_ticket", "class": "write"}]
    }));
    let without = h.send(post(call(1, "update_ticket")));
    assert_eq!(reason_of(&without), json!("level_insufficient"));
    assert!(!h.forwarded());

    let with = h.send(post(call(2, "update_ticket")).with_header("x-test-roles", "viewer,editor"));
    assert_eq!(with.status_code(), 200);
    assert!(h.forwarded());
}

// --- blockedTools -------------------------------------------------------

#[test]
fn blocked_tools_are_denied_to_every_caller() {
    let mut h = harness(json!({
        "defaultLevel": "destructive",
        "blockedTools": ["delete_repository"],
        "toolOverrides": [{"name": "read_file", "class": "read"}]
    }));
    let blocked = h.send(post(call(1, "delete_repository")));
    assert_eq!(reason_of(&blocked), json!("tool_blocked"));
    assert!(!h.forwarded());

    let allowed = h.send(post(call(2, "read_file")));
    assert_eq!(allowed.status_code(), 200);
    assert!(h.forwarded());
}

// --- status, code and id of refusals --------------------------------------

#[test]
fn http_status_403_applies_to_policy_refusals() {
    let mut h = harness(json!({"denial": {"httpStatus": "403"}}));
    let response = h.send(post(call(1, "anything")));
    assert_eq!(response.status_code(), 403);
    assert!(!h.forwarded());
}

#[test]
fn batch_with_one_refused_call_is_refused_as_a_whole() {
    let mut h = harness(json!({"toolOverrides": [{"name": "search", "class": "read"}]}));
    let batch = json!([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "search"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "wipe"}}
    ]);
    let response = h.send(post(batch.to_string().into_bytes()));
    let replies = body_json(&response);
    assert_eq!(replies.as_array().map(Vec::len), Some(2));
    assert!(!h.forwarded());
}

#[test]
fn protocol_errors_refuse_bad_bodies() {
    let mut h = harness(json!({}));
    let parse = h.send(post(b"{not json".to_vec()));
    assert_eq!(error_of(&parse)["code"], json!(-32700));
    assert!(!h.forwarded());

    let duplicate =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}"#;
    let response = h.send(post(duplicate.to_vec()));
    assert_eq!(error_of(&response)["code"], json!(-32600));
    assert!(!h.forwarded());
}

#[test]
fn oversized_and_encoded_bodies_are_refused() {
    let mut h = harness(json!({"limits": {"maxRequestBodyBytes": 1024}}));
    let big =
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "x".repeat(2000)}});
    let response = h.send(post(big.to_string().into_bytes()));
    assert_ne!(error_of(&response), Value::Null);
    assert!(!h.forwarded());

    let encoded = h.send(post(call(1, "x")).with_header("content-encoding", "gzip"));
    assert_ne!(error_of(&encoded), Value::Null);
    assert!(!h.forwarded());
}

// --- audit mode -----------------------------------------------------------

#[test]
fn audit_mode_forwards_everything() {
    let mut h = harness(json!({"mode": "audit"}));
    let call = h.send(post(call(1, "delete_everything")));
    assert_eq!(call.status_code(), 200);
    assert!(h.forwarded());

    let parse = h.send(post(b"{not json".to_vec()));
    assert_eq!(parse.status_code(), 200);
    assert!(h.forwarded());

    let put = h.send(UnitHttpRequest::custom("PUT").with_body(b"{}".to_vec()));
    assert_eq!(put.status_code(), 200);
    assert!(h.forwarded());
}

// --- method rules and pass-through -----------------------------------------

#[test]
fn method_rules() {
    let mut h = harness(json!({}));
    let get = h.send(UnitHttpRequest::get());
    assert_eq!(get.status_code(), 200);
    assert!(h.forwarded());

    let put = h.send(UnitHttpRequest::custom("PUT").with_body(b"{}".to_vec()));
    assert_eq!(put.status_code(), 405);
    assert!(put.header("allow").is_some());
    assert!(!h.forwarded());

    let get_with_body = h.send(
        UnitHttpRequest::get()
            .with_header("content-length", "2")
            .with_body(b"{}".to_vec()),
    );
    assert_eq!(get_with_body.status_code(), 405);
    assert!(!h.forwarded());

    let overridden = h.send(UnitHttpRequest::get().with_header("x-http-method-override", "POST"));
    assert_eq!(overridden.status_code(), 405);
    assert!(!h.forwarded());
}

#[test]
fn other_messages_pass_through_unchanged() {
    let mut h = harness(json!({}));
    for body in [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
    ] {
        let bytes = body.to_string().into_bytes();
        let response = h.send(post(bytes.clone()));
        assert_eq!(response.status_code(), 200);
        let upstream = h.backend.next();
        assert_eq!(upstream.as_ref().map(|r| r.body().to_vec()), Some(bytes));
    }
}

#[test]
fn list_requests_ask_for_identity_encoding() {
    let mut h = harness(json!({}));
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let request = post(list.to_string().into_bytes()).with_header("accept-encoding", "gzip");
    let response = h.send(request);
    assert_eq!(response.status_code(), 200);
    let upstream = h.backend.next();
    assert_eq!(
        upstream.as_ref().and_then(|r| r.header("accept-encoding")),
        Some("identity")
    );
}

// --- an invalid configuration fails closed ----------------------------------

#[test]
fn invalid_configuration_fails_closed() {
    let mut h = harness(json!({"denial": {"errorCode": -32700}}));
    let response = h.send(post(call(1, "search")));
    assert_eq!(response.status_code(), 503);
    assert!(!h.forwarded());
}

// --- tools/list responses ------------------------------------------------------

fn list_request(reply: &str) -> UnitHttpRequest {
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    post(list.to_string().into_bytes()).with_header("x-test-reply", reply)
}

/// Tool names in a JSON or SSE list response.
fn tool_names(response: &UnitHttpResponse) -> Vec<String> {
    let text = String::from_utf8_lossy(response.body());
    let json = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or(&text);
    let value: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    value
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool.get("name").and_then(Value::as_str).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_list_hides_tools_above_the_caller_level() {
    let mut h = harness(json!({}));
    let response = h.send(list_request("list"));
    assert_eq!(tool_names(&response), vec!["search"]);
    let length = response.body().len().to_string();
    assert_eq!(response.header("content-length"), Some(length.as_str()));
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(response.header("etag"), None);
    assert_eq!(response.header("digest"), None);
}

// A chunked response is not given a Content-Length.
#[test]
fn a_chunked_list_stays_without_content_length() {
    let mut h = harness(json!({}));
    let response = h.send(list_request("list-chunked"));
    assert_eq!(tool_names(&response), vec!["search"]);
    assert_eq!(response.header("content-length"), None);
    assert_eq!(response.header("cache-control"), Some("no-store"));
}

#[test]
fn a_list_with_nothing_hidden_is_forwarded_unchanged() {
    let mut h = harness(json!({}));
    let response = h.send(list_request("list-read-only"));
    let expected = list_body(json!([{"name": "search", "annotations": {"readOnlyHint": true}}]));
    assert_eq!(response.body(), expected.as_bytes());
    assert_eq!(response.header("etag"), Some("\"v1\""));
    assert_eq!(response.header("cache-control"), None);
}

// SSE, buffered whole
#[test]
fn an_sse_list_is_filtered() {
    let mut h = harness(json!({}));
    let response = h.send(list_request("list-sse"));
    assert_eq!(tool_names(&response), vec!["search"]);
    assert!(String::from_utf8_lossy(response.body()).starts_with("event: message\n"));
}

// A downgrade is refused, and the catalog learned from a list governs later calls.
#[test]
fn a_downgrade_cannot_unhide_a_tool() {
    let mut h = harness(json!({}));
    h.send(list_request("list"));
    let downgraded = h.send(list_request("list-downgrade"));
    assert!(tool_names(&downgraded).is_empty(), "drop stays destructive");
    h.backend.next();
    h.backend.next();

    assert_eq!(
        reason_of(&h.send(post(call(2, "drop")))),
        json!("level_insufficient")
    );
    assert!(!h.forwarded());
    assert_eq!(h.send(post(call(3, "search"))).status_code(), 200);
    assert!(h.forwarded());
}

// The list is filtered for the caller of the list request.
#[test]
fn a_granted_caller_sees_more() {
    let mut h = harness(json!({
        "callerAttributes": dw2pel("attributes.headers['x-test-roles']"),
        "grants": [{"attribute": "admin", "level": "destructive"}]
    }));
    let response = h.send(list_request("list").with_header("x-test-roles", "admin"));
    assert_eq!(tool_names(&response), vec!["search", "drop"]);
}

#[test]
fn partitions_learn_separately() {
    let mut h = harness(json!({"catalogPartition": dw2pel("attributes.headers['x-tenant']")}));
    h.send(list_request("list").with_header("x-tenant", "a"));
    h.backend.next();
    let a = h.send(post(call(2, "search")).with_header("x-tenant", "a"));
    assert_eq!(a.status_code(), 200);
    assert!(h.forwarded());
    let b = h.send(post(call(3, "search")).with_header("x-tenant", "b"));
    assert_eq!(
        reason_of(&b),
        json!("unknown_tool"),
        "tenant b has not listed tools"
    );
    assert!(!h.forwarded());
}

// An uninspectable list marks the catalog stale; the next good list recovers.
#[test]
fn a_stale_catalog_recovers_on_the_next_list() {
    let mut h = harness(json!({}));
    h.send(list_request("list"));
    let encoded = h.send(list_request("list-gzip"));
    assert_eq!(
        tool_names(&encoded),
        vec!["search", "drop"],
        "forwarded unchanged"
    );
    h.backend.next();
    h.backend.next();

    assert_eq!(
        reason_of(&h.send(post(call(2, "search")))),
        json!("unknown_tool")
    );
    assert!(!h.forwarded());
    h.send(list_request("list"));
    h.backend.next();
    assert_eq!(h.send(post(call(3, "search"))).status_code(), 200);
    assert!(h.forwarded());
}

// Audit mode learns but does not filter.
#[test]
fn audit_mode_does_not_filter_lists() {
    let mut h = harness(json!({"mode": "audit"}));
    let response = h.send(list_request("list"));
    assert_eq!(tool_names(&response), vec!["search", "drop"]);
    assert_eq!(response.header("etag"), Some("\"v1\""));
}
