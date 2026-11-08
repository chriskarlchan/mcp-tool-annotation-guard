// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! One `tools/list` response, end to end.
//!
//! The policy glue calls [`on_headers`] with the response headers and, if it
//! returns a body mode, [`on_body`] with the complete body, then applies the
//! [`Outcome`]. Every catalog write and every log event happens here.
//!
//! Design choices:
//! - `catalog_stale` is logged for every recorded failure, with its reason
//!   (the `warn` rate limit bounds the volume), not only on the transition.
//! - In buffered SSE mode `limits.maxListResponseBytes` bounds the whole
//!   buffered stream (`too_large`).
//! - When the partition is unavailable, a response that cannot be inspected
//!   is forwarded unfiltered like any uninspectable response, and no
//!   catalog is updated.
//! - A filtered list is meant for one caller: it is sent with
//!   `Cache-Control: no-store`, and a `cacheScope` other than `"private"`
//!   becomes `"private"`. When nothing is removed and `cacheScope` needs no
//!   change, the body is forwarded byte for byte.
//! - When the gateway refuses the filtered body, the client gets an
//!   `internal_error` for each list request instead of the original.
//! - When `list_changed` follows the list in a stream, the list's pins are
//!   learned, the catalog ends stale, and the list is filtered against the
//!   stale catalog (only overrides and `classifyByName` stay visible).

use crate::catalog::{Catalog, Catalogs, PartitionUnavailable, Pin, PinChange, Store, WriteReport};
use crate::classify::Outcome as Classification;
use crate::config::Config;
use crate::decide::{self, Caller, CatalogView, ListHandling};
use crate::filter::{self, Inspection, ListResult, Precheck, Rewritten, Tool, BOM};
use crate::freshness::StaleReason;
use crate::ids::Id;
use crate::log::Event;
use crate::response::{self, ProtocolError};
use crate::sse::{self, StreamInspection};

/// What the request phase knew about a marked `tools/list` request; carried
/// to the response phase.
#[derive(Clone, Debug)]
pub struct Pending {
    pub ids: Vec<Id>,
    pub caller: Caller,
    /// The catalog key, or the partition was unavailable.
    pub key: Result<String, PartitionUnavailable>,
}

/// How the body is inspected once the headers passed the pre-checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyMode {
    Json,
    /// Buffered SSE.
    Sse,
}

/// What the glue does with the response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Forward the response unchanged.
    Forward,
    /// A filtered list whose body needs no change: forward the body
    /// unchanged and apply [`HeaderChanges::no_store`].
    ForwardNoStore,
    /// Replace the body and apply [`header_changes`]. If the gateway refuses
    /// the new body, call [`on_rewrite_refused`].
    Rewrite(String),
}

/// Receives each log event with the catalog key it concerns.
pub type Log<'a> = dyn FnMut(&Event<'_>, Option<&str>) + 'a;

/// What list processing works with.
pub struct Env<'a, S> {
    pub config: &'a Config,
    pub catalogs: &'a mut Catalogs<S>,
    pub now_ms: u64,
    pub log: &'a mut Log<'a>,
}

/// Step 1: the response headers (pre-checks). `Some(mode)`: buffer the
/// body and call [`on_body`]. `None`: forward unchanged; a failure is
/// already recorded.
pub fn on_headers<S: Store>(
    status: u16,
    content_encoding: Option<&str>,
    content_type: Option<&str>,
    pending: &Pending,
    env: &mut Env<'_, S>,
) -> Option<BodyMode> {
    if pending.key.is_err() {
        (env.log)(&Event::PartitionUnavailable, None);
    }
    match filter::precheck(status, content_encoding, content_type) {
        Precheck::PassThrough => None,
        Precheck::Stale(reason) => {
            fail(pending, reason, env);
            None
        }
        Precheck::Json => Some(BodyMode::Json),
        Precheck::Sse => Some(BodyMode::Sse),
    }
}

/// Step 2: the complete body.
pub fn on_body<S: Store>(
    mode: BodyMode,
    body: &[u8],
    pending: &Pending,
    env: &mut Env<'_, S>,
) -> Outcome {
    if body.len() > env.config.limits.max_list_response_bytes {
        fail(pending, StaleReason::TooLarge, env);
        return Outcome::Forward;
    }
    match mode {
        BodyMode::Json => match filter::inspect_json(body, &pending.ids, env.config) {
            Inspection::ErrorsOnly => Outcome::Forward,
            // `inspect_json` reports a missing response as `response_invalid`.
            Inspection::NotFound => {
                fail(pending, StaleReason::ResponseInvalid, env);
                Outcome::Forward
            }
            Inspection::Stale(reason) => {
                fail(pending, reason, env);
                Outcome::Forward
            }
            Inspection::Lists(list) => {
                process(&[&list], false, pending, env, |keep| list.rewrite(keep))
            }
        },
        BodyMode::Sse => match sse::inspect_stream(body, &pending.ids, env.config) {
            StreamInspection::ErrorsOnly => Outcome::Forward,
            StreamInspection::Stale(reason) => {
                fail(pending, reason, env);
                Outcome::Forward
            }
            StreamInspection::Lists(stream) => {
                let lists: Vec<&ListResult> = stream.lists().collect();
                process(&lists, stream.list_changed_after, pending, env, |keep| {
                    stream.rewrite(keep)
                })
            }
        },
    }
}

/// The gateway refused the filtered body. The original must not reach the
/// client (it may show tools this caller may not see, or let a shared cache
/// serve it to others), so it is replaced by an `internal_error` for each
/// list request: one JSON array if the original was one, one SSE event per
/// error in SSE mode. The catalog keeps what the list taught: the list was
/// inspected, and the client never receives it. Returns the new body.
pub fn on_rewrite_refused<S: Store>(
    mode: BodyMode,
    original: &[u8],
    pending: &Pending,
    env: &mut Env<'_, S>,
) -> Vec<u8> {
    let err = ProtocolError::Internal {
        id: pending.ids.first().cloned(),
    };
    (env.log)(&Event::RequestRejected(&err), pending.key.as_deref().ok());
    let sse = mode == BodyMode::Sse;
    response::list_errors(&pending.ids, !sse && is_array(original), sse)
}

/// `true` when a JSON body (after an optional byte-order mark) is an array.
fn is_array(body: &[u8]) -> bool {
    let body = body.strip_prefix(BOM.as_bytes()).unwrap_or(body);
    body.iter()
        .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        .is_some_and(|byte| *byte == b'[')
}

/// The gateway refused even the error body, so the original reaches the
/// client unfiltered: mark the catalog stale (`internal_error`) so that
/// calls fall back to the stale rules.
pub fn on_rewrite_failed<S: Store>(pending: &Pending, env: &mut Env<'_, S>) {
    fail(pending, StaleReason::InternalError, env);
}

/// The gateway ended the response after its headers but before the end of
/// its body (a body over the gateway's buffer limit, an upstream reset or a
/// timeout). The client never received the list, but it was never inspected
/// either, so whatever changed in it is unknown: mark the catalog stale
/// (`incomplete`).
pub fn on_incomplete<S: Store>(pending: &Pending, env: &mut Env<'_, S>) {
    fail(pending, StaleReason::Incomplete, env);
}

/// Header changes after a rewrite (header hygiene, lowercase names).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderChanges {
    pub remove: &'static [&'static str],
    pub set: Vec<(&'static str, String)>,
}

impl HeaderChanges {
    /// For a filtered list whose body is unchanged: validators and digests
    /// still match, so only `Cache-Control` is set.
    pub fn no_store() -> HeaderChanges {
        HeaderChanges {
            remove: &[],
            set: vec![("cache-control", "no-store".to_owned())],
        }
    }
}

/// `Content-Length` is set to the new length only when the upstream sent
/// one; a response without it (chunked) stays without it.
pub fn header_changes(new_len: usize, had_content_length: bool) -> HeaderChanges {
    let set = filter::headers_after_rewrite(new_len)
        .into_iter()
        .filter(|(name, _)| had_content_length || *name != "content-length")
        .collect();
    HeaderChanges {
        remove: &filter::REMOVED_AFTER_REWRITE,
        set,
    }
}

/// A list response that could not be inspected: mark the catalog stale.
fn fail<S: Store>(pending: &Pending, reason: StaleReason, env: &mut Env<'_, S>) {
    let Ok(key) = pending.key.as_deref() else {
        return;
    };
    let report = env.catalogs.record_failure(key, env.now_ms);
    (env.log)(&Event::CatalogStale(reason), Some(key));
    if report.retry_exhausted {
        (env.log)(&Event::CatalogMergeRetryExhausted, Some(key));
    }
}

type Rewrite<'r> = dyn FnMut(&str) -> bool + 'r;

/// Processing a valid list result: classify, merge pins, filter.
fn process<S: Store>(
    lists: &[&ListResult],
    changed_after: bool,
    pending: &Pending,
    env: &mut Env<'_, S>,
    rewrite: impl FnOnce(&mut Rewrite<'_>) -> Rewritten,
) -> Outcome {
    let Env {
        config,
        catalogs,
        now_ms,
        log,
    } = env;
    let key = pending.key.as_deref().ok();
    log_classification(lists, key, log);

    let tools: Vec<&Tool> = lists.iter().flat_map(|list| list.tools()).collect();
    let total = tools.len()
        + lists
            .iter()
            .map(|list| list.invalid_entries())
            .sum::<usize>();

    let (key, catalog) = match (key, decide::list_handling(config, key.is_some())) {
        (_, ListHandling::ForwardWithoutLearning) => return Outcome::Forward,
        (None, _) | (_, ListHandling::Empty) => {
            // Fail closed: every list becomes empty, no catalog is updated.
            return filtered(total, None, log, |_| false, rewrite);
        }
        (Some(key), ListHandling::Learn) => {
            let candidates: Vec<(&Tool, Pin)> =
                tools.iter().filter_map(|tool| candidate(tool)).collect();
            let observations: Vec<(&str, Pin)> = candidates
                .iter()
                .map(|(tool, pin)| (tool.name.as_str(), *pin))
                .collect();
            let report = if changed_after {
                catalogs.record_success_then_changed(key, *now_ms, &observations)
            } else {
                catalogs.record_success(key, *now_ms, &observations)
            };
            log_write(&candidates, &report, changed_after, key, log);
            if !decide::filtering_active(config) {
                return Outcome::Forward;
            }
            (key, catalogs.local_copy(key))
        }
    };

    let max_age_seconds = catalogs.settings().max_age_seconds;
    let caller = &pending.caller;
    let visible = |name: &str| {
        let view = catalog.map_or(
            CatalogView {
                pin: None,
                stale: true,
            },
            |catalog: &Catalog| catalog.view(name, *now_ms, max_age_seconds),
        );
        decide::list_entry_visible(name, config, caller, view)
    };
    filtered(total, Some(key), log, visible, rewrite)
}

/// Rewrites with `visible`, logging `list_filtered` if anything was removed.
fn filtered(
    total: usize,
    key: Option<&str>,
    log: &mut Log<'_>,
    mut visible: impl FnMut(&str) -> bool,
    rewrite: impl FnOnce(&mut Rewrite<'_>) -> Rewritten,
) -> Outcome {
    let mut hidden: Vec<String> = Vec::new();
    let rewritten = rewrite(&mut |name: &str| {
        let keep = visible(name);
        if !keep {
            hidden.push(name.to_owned());
        }
        keep
    });
    if rewritten.removed > 0 {
        let names: Vec<&str> = hidden.iter().map(String::as_str).collect();
        log(
            &Event::ListFiltered {
                total,
                hidden: &names,
            },
            key,
        );
    }
    if rewritten.changed() {
        Outcome::Rewrite(rewritten.body)
    } else {
        Outcome::ForwardNoStore
    }
}

/// The pin candidate of a tool; blocked and overridden tools have none.
fn candidate<'t>(tool: &&'t Tool) -> Option<(&'t Tool, Pin)> {
    match tool.classified.outcome {
        Classification::Candidate { class, source } => Some((*tool, Pin { class, source })),
        Classification::Blocked | Classification::Override(_) => None,
    }
}

/// Annotation notes, duplicate names and invalid entries.
fn log_classification(lists: &[&ListResult], key: Option<&str>, log: &mut Log<'_>) {
    let mut invalid = 0;
    for list in lists {
        for tool in list.tools() {
            for note in &tool.classified.notes {
                log(&Event::note(&tool.name, *note), key);
            }
        }
        for (tool, classes) in list.conflicts() {
            log(
                &Event::ToolDefinitionConflict {
                    tool,
                    classes: &classes,
                },
                key,
            );
        }
        invalid += list.invalid_entries();
    }
    if invalid > 0 {
        log(&Event::ListEntryInvalid { count: invalid }, key);
    }
}

/// Pin changes, capacity, freshness and write-verify results.
fn log_write(
    candidates: &[(&Tool, Pin)],
    report: &WriteReport,
    changed_after: bool,
    key: &str,
    log: &mut Log<'_>,
) {
    for ((tool, _), change) in candidates.iter().zip(&report.changes) {
        match change {
            PinChange::New(pin) => {
                let event = Event::ToolClassified {
                    tool: &tool.name,
                    class: pin.class,
                    source: pin.source,
                    idempotent_hint: tool.classified.idempotent_hint,
                    open_world_hint: tool.classified.open_world_hint,
                };
                log(&event, Some(key));
            }
            // Capacity is logged once per write, below.
            PinChange::NotPinned(_) | PinChange::Unchanged => {}
            other => {
                if let Some(event) = Event::pin_change(&tool.name, other) {
                    log(&event, Some(key));
                }
            }
        }
    }
    if let Some(limit) = report.capacity {
        log(&Event::PinCapacityExhausted(limit), Some(key));
    }
    if report.retry_exhausted {
        log(&Event::CatalogMergeRetryExhausted, Some(key));
    }
    if changed_after {
        log(&Event::CatalogStale(StaleReason::ListChanged), Some(key));
    } else if report.became_fresh {
        log(&Event::CatalogFresh, Some(key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{CatalogSettings, MemoryStore};
    use crate::config::Class;
    use crate::ids::IdToken;
    use serde_json::{json, Value};
    use std::collections::BTreeSet;

    fn config(value: Value) -> Config {
        Config::from_json(value.to_string().as_bytes()).unwrap_or_else(|err| unreachable!("{err}"))
    }

    fn id(raw: &str) -> Id {
        match Id::from_raw(raw) {
            IdToken::Valid(id) => id,
            _ => unreachable!("{raw}"),
        }
    }

    /// One worker's catalogs plus the configuration and the events logged.
    struct World {
        config: Config,
        catalogs: Catalogs<MemoryStore>,
        events: Vec<(String, Option<String>)>,
    }

    impl World {
        fn new(value: Value) -> World {
            let config = config(value);
            let catalogs = Catalogs::new(
                MemoryStore::default(),
                CatalogSettings::from_config(&config),
                "index".to_owned(),
            );
            World {
                config,
                catalogs,
                events: Vec::new(),
            }
        }

        fn pending(&self, attributes: &[&str], key: Result<&str, PartitionUnavailable>) -> Pending {
            let attributes: BTreeSet<String> = attributes.iter().map(|a| (*a).to_owned()).collect();
            Pending {
                ids: vec![id("1")],
                caller: Caller::new(&self.config, attributes),
                key: key.map(str::to_owned),
            }
        }

        /// Runs both steps on a 200 response.
        fn respond(
            &mut self,
            content_type: &str,
            body: &str,
            pending: &Pending,
            now_ms: u64,
        ) -> Outcome {
            self.respond_with(200, None, content_type, body, pending, now_ms)
        }

        fn respond_with(
            &mut self,
            status: u16,
            encoding: Option<&str>,
            content_type: &str,
            body: &str,
            pending: &Pending,
            now_ms: u64,
        ) -> Outcome {
            let events = &mut self.events;
            let mut log = |event: &Event<'_>, key: Option<&str>| {
                events.push((event.name().to_owned(), key.map(str::to_owned)));
            };
            let mut env = Env {
                config: &self.config,
                catalogs: &mut self.catalogs,
                now_ms,
                log: &mut log,
            };
            match on_headers(status, encoding, Some(content_type), pending, &mut env) {
                None => Outcome::Forward,
                Some(mode) => on_body(mode, body.as_bytes(), pending, &mut env),
            }
        }

        fn logged(&self, name: &str) -> usize {
            self.events
                .iter()
                .filter(|(event, _)| event == name)
                .count()
        }

        fn stale(&mut self, key: &str, now_ms: u64) -> bool {
            let max_age = self.catalogs.settings().max_age_seconds;
            self.catalogs.read(key).is_stale(now_ms, max_age)
        }

        fn pin(&mut self, key: &str, tool: &str) -> Option<Class> {
            self.catalogs.read(key).pin(tool).map(|pin| pin.class)
        }

        /// The tool's pin may be used for decisions.
        fn trusted(&mut self, key: &str, tool: &str, now_ms: u64) -> bool {
            let max_age = self.catalogs.settings().max_age_seconds;
            !self.catalogs.read(key).view(tool, now_ms, max_age).stale
        }
    }

    const JSON: &str = "application/json";
    const SSE: &str = "text/event-stream";

    fn list(tools: Value, extra: Value) -> String {
        let mut result = json!({"tools": tools});
        if let (Some(result), Some(extra)) = (result.as_object_mut(), extra.as_object()) {
            result.extend(extra.clone());
        }
        json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string()
    }

    fn read(name: &str) -> Value {
        json!({"name": name, "annotations": {"readOnlyHint": true}})
    }

    fn destructive(name: &str) -> Value {
        json!({"name": name, "annotations": {"destructiveHint": true}})
    }

    fn names(body: &str) -> Vec<String> {
        let value: Value = serde_json::from_str(body).unwrap_or(Value::Null);
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

    fn rewritten(outcome: Outcome) -> String {
        match outcome {
            Outcome::Rewrite(body) => body,
            other => unreachable!("expected a rewrite: {other:?}"),
        }
    }

    // --- filtering and unchanged lists ---------------------------------------------------------------

    #[test]
    fn destructive_and_unannotated_tools_are_hidden_from_a_read_caller() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        let body = list(
            json!([read("search"), destructive("drop"), {"name": "bare"}]),
            json!({}),
        );
        let out = rewritten(w.respond(JSON, &body, &pending, 100));
        assert_eq!(names(&out), vec!["search"]);
        assert_eq!(w.logged("list_filtered"), 1);
        assert_eq!(w.logged("tool_classified"), 3);
        assert_eq!(w.pin("k", "drop"), Some(Class::Destructive));
        assert_eq!(
            w.pin("k", "bare"),
            Some(Class::Destructive),
            "unannotatedAs"
        );
    }

    #[test]
    fn a_list_with_only_visible_tools_keeps_its_body() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        let body = list(json!([read("a"), read("b")]), json!({}));
        // Still meant for this caller only, so it is not stored.
        assert_eq!(
            w.respond(JSON, &body, &pending, 100),
            Outcome::ForwardNoStore
        );
        assert_eq!(w.logged("list_filtered"), 0);
        assert_eq!(w.pin("k", "a"), Some(Class::Read));
    }

    #[test]
    fn grants_and_overrides_decide_visibility() {
        let mut w = World::new(json!({
            "grants": [{"attribute": "admin", "level": "destructive"}],
            "toolOverrides": [{"name": "drop", "class": "read"}],
            "blockedTools": ["nuke"]
        }));
        let body = list(
            json!([destructive("drop"), destructive("wipe"), read("nuke")]),
            json!({}),
        );
        let viewer = w.pending(&[], Ok("k"));
        assert_eq!(
            names(&rewritten(w.respond(JSON, &body, &viewer, 100))),
            vec!["drop"]
        );
        let admin = w.pending(&["admin"], Ok("k"));
        assert_eq!(
            names(&rewritten(w.respond(JSON, &body, &admin, 101))),
            vec!["drop", "wipe"]
        );
        assert_eq!(
            w.pin("k", "drop"),
            None,
            "overridden tools are never pinned"
        );
        assert_eq!(w.pin("k", "nuke"), None, "blocked tools are never pinned");
    }

    #[test]
    fn mcp_2026_07_28_result_fields_are_kept() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        let extra = json!({"resultType": "complete", "ttlMs": 60000, "cacheScope": "private", "_meta": {"x": 1}});
        let body = list(json!([read("search"), destructive("drop")]), extra);
        let out = rewritten(w.respond(JSON, &body, &pending, 100));
        let value: Value = serde_json::from_str(&out).unwrap_or(Value::Null);
        let expected = json!({"tools": [read("search")], "resultType": "complete", "ttlMs": 60000,
            "cacheScope": "private", "_meta": {"x": 1}});
        assert_eq!(value.get("result"), Some(&expected));
    }

    #[test]
    fn a_shared_cache_scope_becomes_private() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        // Something removed, and nothing removed: both are meant for this caller only.
        for (tools, visible) in [
            (json!([read("search"), destructive("drop")]), 1),
            (json!([read("search")]), 1),
        ] {
            let body = list(tools, json!({"ttlMs": 60000, "cacheScope": "public"}));
            let out = rewritten(w.respond(JSON, &body, &pending, 100));
            let value: Value = serde_json::from_str(&out).unwrap_or(Value::Null);
            assert_eq!(value.pointer("/result/cacheScope"), Some(&json!("private")));
            assert_eq!(value.pointer("/result/ttlMs"), Some(&json!(60000)));
            assert_eq!(names(&out).len(), visible);
        }
        assert_eq!(w.logged("list_filtered"), 1, "only when a tool is hidden");
        // A list that is already private keeps its body.
        let private = list(json!([read("search")]), json!({"cacheScope": "private"}));
        assert_eq!(
            w.respond(JSON, &private, &pending, 100),
            Outcome::ForwardNoStore
        );
    }

    #[test]
    fn an_sse_list_gets_a_private_cache_scope() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        let data = list(json!([read("search")]), json!({"cacheScope": "public"}));
        let out = rewritten(w.respond(SSE, &format!("data: {data}\n\n"), &pending, 100));
        let private = list(json!([read("search")]), json!({"cacheScope": "private"}));
        assert_eq!(out, format!("data: {private}\n\n"));
    }

    #[test]
    fn without_filtering_the_cache_scope_is_kept() {
        for value in [json!({"mode": "audit"}), json!({"filterToolsList": false})] {
            let mut w = World::new(value);
            let pending = w.pending(&[], Ok("k"));
            let body = list(json!([read("search")]), json!({"cacheScope": "public"}));
            assert_eq!(w.respond(JSON, &body, &pending, 100), Outcome::Forward);
        }
    }

    // --- pagination and SSE ------------------------------------------------------------

    #[test]
    fn an_emptied_page_keeps_its_cursor() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        let body = list(
            json!([destructive("drop")]),
            json!({"nextCursor": "page-2"}),
        );
        let out = rewritten(w.respond(JSON, &body, &pending, 100));
        let value: Value = serde_json::from_str(&out).unwrap_or(Value::Null);
        assert_eq!(
            value.get("result"),
            Some(&json!({"tools": [], "nextCursor": "page-2"}))
        );
    }

    #[test]
    fn an_sse_list_is_rewritten_and_other_events_kept() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        let data = list(json!([read("search"), destructive("drop")]), json!({}));
        let progress = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{}}"#;
        let stream = format!("event: message\nid: 9\ndata: {data}\n\ndata: {progress}\n\n");
        let out = rewritten(w.respond(SSE, &stream, &pending, 100));
        let filtered = list(json!([read("search")]), json!({}));
        assert_eq!(
            out,
            format!("event: message\nid: 9\ndata: {filtered}\n\ndata: {progress}\n\n")
        );
    }

    #[test]
    fn list_changed_after_the_list_learns_pins_and_marks_stale() {
        let mut w =
            World::new(json!({"toolOverrides": [{"name": "pinned_by_admin", "class": "read"}]}));
        let pending = w.pending(&[], Ok("k"));
        let data = list(json!([read("search"), read("pinned_by_admin")]), json!({}));
        let changed = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        let stream = format!("data: {data}\n\ndata: {changed}\n\n");
        let out = rewritten(w.respond(SSE, &stream, &pending, 100));
        assert_eq!(
            names_in_sse(&out),
            vec!["pinned_by_admin"],
            "only overrides survive a stale catalog"
        );
        assert!(w.stale("k", 100));
        assert_eq!(w.pin("k", "search"), Some(Class::Read));
        assert_eq!(w.logged("catalog_stale"), 1);
        // The next list clears it.
        let fresh = list(json!([read("search")]), json!({}));
        assert_eq!(
            w.respond(JSON, &fresh, &pending, 200),
            Outcome::ForwardNoStore
        );
        assert!(!w.stale("k", 200));
        assert_eq!(w.logged("catalog_fresh"), 1);
    }

    fn names_in_sse(stream: &str) -> Vec<String> {
        stream
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .flat_map(names)
            .collect()
    }

    // --- monotonic pins ------------------------------------------------------------------

    #[test]
    fn a_downgrade_is_ignored_and_logged() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        w.respond(
            JSON,
            &list(json!([destructive("drop")]), json!({})),
            &pending,
            100,
        );
        let out = rewritten(w.respond(
            JSON,
            &list(json!([read("drop"), read("new")]), json!({})),
            &pending,
            200,
        ));
        assert_eq!(
            names(&out),
            vec!["new"],
            "the downgraded tool stays hidden, the new one is learned"
        );
        assert_eq!(w.pin("k", "drop"), Some(Class::Destructive));
        assert_eq!(w.logged("classification_downgrade_ignored"), 1);
    }

    #[test]
    fn an_upgrade_applies_at_once() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        w.respond(JSON, &list(json!([read("t")]), json!({})), &pending, 100);
        let out = rewritten(w.respond(
            JSON,
            &list(json!([destructive("t")]), json!({})),
            &pending,
            200,
        ));
        assert!(names(&out).is_empty());
        assert_eq!(w.logged("classification_upgraded"), 1);
    }

    #[test]
    fn capacity_fails_closed() {
        let mut w = World::new(json!({"limits": {"maxCachedTools": 1}}));
        let pending = w.pending(&[], Ok("k"));
        let out = rewritten(w.respond(
            JSON,
            &list(json!([read("a"), read("b")]), json!({})),
            &pending,
            100,
        ));
        assert_eq!(
            names(&out),
            vec!["a"],
            "an unpinned tool is unknown, so hidden"
        );
        assert_eq!(w.logged("pin_capacity_exhausted"), 1);
    }

    // --- partitions ---------------------------------------------------------------------

    #[test]
    fn partitions_learn_separately() {
        let mut w = World::new(json!({}));
        let a = w.pending(&[], Ok("a"));
        let b = w.pending(&[], Ok("b"));
        w.respond(JSON, &list(json!([read("operate")]), json!({})), &a, 100);
        let out = rewritten(w.respond(
            JSON,
            &list(json!([destructive("operate")]), json!({})),
            &b,
            100,
        ));
        assert!(names(&out).is_empty());
        assert_eq!(w.pin("a", "operate"), Some(Class::Read));
        assert_eq!(w.pin("b", "operate"), Some(Class::Destructive));
    }

    #[test]
    fn an_unavailable_partition_gets_an_empty_list_and_updates_nothing() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Err(PartitionUnavailable));
        let out = rewritten(w.respond(JSON, &list(json!([read("a")]), json!({})), &pending, 100));
        assert!(names(&out).is_empty());
        assert_eq!(w.logged("partition_unavailable"), 1);
        assert_eq!(w.logged("tool_classified"), 0);
        // An uninspectable response is forwarded and still updates nothing.
        let encoded = w.respond_with(200, Some("gzip"), JSON, "x", &pending, 100);
        assert_eq!(encoded, Outcome::Forward);
        assert_eq!(w.logged("catalog_stale"), 0);
    }

    #[test]
    fn an_unavailable_partition_without_filtering_forwards() {
        let mut w = World::new(json!({"mode": "audit"}));
        let pending = w.pending(&[], Err(PartitionUnavailable));
        assert_eq!(
            w.respond(
                JSON,
                &list(json!([destructive("a")]), json!({})),
                &pending,
                100
            ),
            Outcome::Forward
        );
        assert_eq!(w.logged("tool_classified"), 0);
    }

    // --- stale fallback and recovery ------------------------------------------------------

    #[test]
    fn uninspectable_responses_mark_stale_and_pass_through() {
        let body = list(json!([destructive("drop")]), json!({}));
        let cases: [(Option<&str>, &str, String); 4] = [
            (Some("gzip"), JSON, body.clone()),
            (None, "text/plain", body.clone()),
            (None, JSON, "{not json".to_owned()),
            (
                None,
                JSON,
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":{}}}"#.to_owned(),
            ),
        ];
        for (encoding, content_type, body) in cases {
            let mut w = World::new(json!({}));
            let pending = w.pending(&[], Ok("k"));
            let out = w.respond_with(200, encoding, content_type, &body, &pending, 100);
            assert_eq!(out, Outcome::Forward, "{content_type} {body}");
            assert!(w.stale("k", 100), "{content_type} {body}");
            assert_eq!(w.pin("k", "drop"), None, "no pins from an invalid response");
            assert_eq!(w.logged("catalog_stale"), 1);
        }
    }

    #[test]
    fn too_large_marks_stale() {
        let mut w = World::new(json!({"limits": {"maxListResponseBytes": 1024}}));
        let pending = w.pending(&[], Ok("k"));
        let big = list(json!([read(&"x".repeat(2000))]), json!({}));
        assert_eq!(w.respond(JSON, &big, &pending, 100), Outcome::Forward);
        assert!(w.stale("k", 100));
    }

    #[test]
    fn errors_and_non_2xx_change_nothing() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        let error = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}"#;
        assert_eq!(w.respond(JSON, error, &pending, 100), Outcome::Forward);
        assert_eq!(
            w.respond_with(500, None, JSON, "oops", &pending, 100),
            Outcome::Forward
        );
        assert!(!w.stale("k", 100));
        assert!(w.events.is_empty(), "{:?}", w.events);
    }

    #[test]
    fn a_later_page_trusts_only_the_tools_it_shows() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        let page1 = list(json!([read("wipe")]), json!({"nextCursor": "p2"}));
        w.respond(JSON, &page1, &pending, 100);
        assert!(w.trusted("k", "wipe", 100));

        // The server raises wipe to destructive, but the guard can't inspect
        // the list that says so.
        let raised = list(json!([destructive("wipe")]), json!({"nextCursor": "p2"}));
        w.respond_with(200, Some("gzip"), JSON, &raised, &pending, 200);
        assert!(!w.trusted("k", "wipe", 200));

        // Listing only page 2 does not make wipe's old read pin trusted.
        let page2 = list(json!([read("other")]), json!({}));
        assert_eq!(
            w.respond(JSON, &page2, &pending, 300),
            Outcome::ForwardNoStore
        );
        assert!(w.trusted("k", "other", 300));
        assert!(!w.trusted("k", "wipe", 300), "not shown since the failure");
        assert_eq!(w.pin("k", "wipe"), Some(Class::Read), "kept, not trusted");

        // A list that shows wipe raises it and trusts it again.
        let out = rewritten(w.respond(JSON, &raised, &pending, 400));
        assert!(names(&out).is_empty(), "hidden from a read caller");
        assert!(w.trusted("k", "wipe", 400));
        assert_eq!(w.pin("k", "wipe"), Some(Class::Destructive));
    }

    #[test]
    fn under_classify_by_name_a_stale_catalog_never_lowers_a_class() {
        let mut w = World::new(json!({
            "onUnknownTool": "classifyByName",
            "nameRules": [{"pattern": "^get_", "class": "read"}]
        }));
        let pending = w.pending(&[], Ok("k"));
        let page1 = list(
            json!([destructive("get_records")]),
            json!({"nextCursor": "p2"}),
        );
        w.respond(JSON, &page1, &pending, 100);
        w.respond_with(200, Some("gzip"), JSON, &page1, &pending, 200);
        let page2 = list(json!([read("get_other")]), json!({}));
        w.respond(JSON, &page2, &pending, 300);

        let max_age = w.catalogs.settings().max_age_seconds;
        let view = w.catalogs.read("k").view("get_records", 300, max_age);
        assert!(view.stale);
        assert_eq!(
            decide::effective_class("get_records", &w.config, view),
            decide::Effective::Known {
                class: Class::Destructive,
                basis: decide::Basis::Pin(crate::classify::Source::Annotations),
            },
            "the name rule says read, but the pin is destructive"
        );
        assert!(!decide::list_entry_visible(
            "get_records",
            &w.config,
            &pending.caller,
            view
        ));
    }

    #[test]
    fn a_later_page_does_not_hide_tools_of_an_earlier_page_from_view() {
        // Page 2's list is filtered with page 2's tools only, so an earlier
        // page's tools never decide what page 2 shows.
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        w.respond(
            JSON,
            &list(json!([read("a")]), json!({"nextCursor": "p2"})),
            &pending,
            100,
        );
        let page2 = list(json!([read("b"), destructive("c")]), json!({}));
        let out = rewritten(w.respond(JSON, &page2, &pending, 200));
        assert_eq!(names(&out), vec!["b"]);
        assert!(
            w.trusted("k", "a", 200),
            "no failure since page 1 showed it"
        );
    }

    #[test]
    fn max_age_counts_from_the_list_that_showed_each_tool() {
        let mut w = World::new(json!({"catalog": {"maxAgeSeconds": 60}}));
        let pending = w.pending(&[], Ok("k"));
        w.respond(
            JSON,
            &list(json!([read("a")]), json!({"nextCursor": "p2"})),
            &pending,
            1_000,
        );
        w.respond(JSON, &list(json!([read("b")]), json!({})), &pending, 50_000);
        assert!(w.trusted("k", "a", 61_000));
        assert!(!w.trusted("k", "a", 61_001), "page 2 does not renew page 1");
        assert!(w.trusted("k", "b", 61_001));
    }

    // --- no filtering in audit mode or with filterToolsList: false --------------------

    #[test]
    fn audit_mode_and_disabled_filtering_learn_but_forward() {
        for value in [json!({"mode": "audit"}), json!({"filterToolsList": false})] {
            let mut w = World::new(value);
            let pending = w.pending(&[], Ok("k"));
            let body = list(json!([destructive("drop"), 5]), json!({}));
            assert_eq!(w.respond(JSON, &body, &pending, 100), Outcome::Forward);
            assert_eq!(w.pin("k", "drop"), Some(Class::Destructive));
        }
    }

    #[test]
    fn events_carry_the_catalog_key() {
        let mut w = World::new(json!({}));
        let pending = w.pending(&[], Ok("k"));
        w.respond(
            JSON,
            &list(json!([destructive("drop")]), json!({})),
            &pending,
            100,
        );
        assert!(
            w.events.iter().all(|(_, key)| key.as_deref() == Some("k")),
            "{:?}",
            w.events
        );
    }
}

#[cfg(test)]
mod glue_tests {
    use super::*;
    use crate::catalog::{CatalogSettings, MemoryStore};
    use crate::classify::Source;
    use crate::config::Class;
    use std::collections::BTreeSet;

    #[test]
    fn content_length_is_set_only_when_present() {
        let with = header_changes(42, true);
        assert_eq!(
            with.set,
            vec![
                ("content-length", "42".to_owned()),
                ("cache-control", "no-store".to_owned())
            ]
        );
        assert_eq!(with.remove, &filter::REMOVED_AFTER_REWRITE);
        let without = header_changes(42, false);
        assert_eq!(without.set, vec![("cache-control", "no-store".to_owned())]);
    }

    #[test]
    fn a_failed_rewrite_marks_the_catalog_stale() {
        let config = Config::from_json(b"{}").unwrap_or_else(|err| unreachable!("{err}"));
        let mut catalogs = Catalogs::new(
            MemoryStore::default(),
            CatalogSettings::from_config(&config),
            "index".to_owned(),
        );
        catalogs.record_success("k", 100, &[]);
        let pending = Pending {
            ids: Vec::new(),
            caller: Caller::new(&config, BTreeSet::new()),
            key: Ok("k".to_owned()),
        };
        let mut events = Vec::new();
        let mut log = |event: &Event<'_>, _: Option<&str>| events.push(event.name().to_owned());
        let mut env = Env {
            config: &config,
            catalogs: &mut catalogs,
            now_ms: 200,
            log: &mut log,
        };
        on_rewrite_failed(&pending, &mut env);
        assert!(catalogs.read("k").is_stale(200, 0));
        assert_eq!(events, vec!["catalog_stale"]);
    }

    fn refused(mode: BodyMode, original: &[u8], ids: &[&str]) -> (String, Vec<String>, bool) {
        let config = Config::from_json(b"{}").unwrap_or_else(|err| unreachable!("{err}"));
        let mut catalogs = Catalogs::new(
            MemoryStore::default(),
            CatalogSettings::from_config(&config),
            "index".to_owned(),
        );
        catalogs.record_success("k", 100, &[]);
        let pending = Pending {
            ids: ids
                .iter()
                .map(|raw| match Id::from_raw(raw) {
                    crate::ids::IdToken::Valid(id) => id,
                    _ => unreachable!("{raw}"),
                })
                .collect(),
            caller: Caller::new(&config, BTreeSet::new()),
            key: Ok("k".to_owned()),
        };
        let mut events = Vec::new();
        let mut log = |event: &Event<'_>, _: Option<&str>| events.push(event.name().to_owned());
        let mut env = Env {
            config: &config,
            catalogs: &mut catalogs,
            now_ms: 200,
            log: &mut log,
        };
        let body = on_rewrite_refused(mode, original, &pending, &mut env);
        let stale = catalogs.read("k").is_stale(200, 0);
        (String::from_utf8_lossy(&body).into_owned(), events, stale)
    }

    fn internal_error(id: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32603,
            "message": "The gateway rejected this request (internal_error).",
            "data": {"policy": "mcp-tool-annotation-guard", "reason": "internal_error"}}})
    }

    #[test]
    fn a_refused_rewrite_answers_each_list_request_with_an_error() {
        use serde_json::{json, Value};
        let parse = |text: &str| serde_json::from_str::<Value>(text).unwrap_or(Value::Null);

        let (body, events, stale) = refused(BodyMode::Json, br#"{"id":1}"#, &["1"]);
        assert_eq!(parse(&body), internal_error(json!(1)));
        assert_eq!(events, vec!["request_rejected"]);
        assert!(!stale, "the list was inspected and its pins kept");

        // A batch answer stays a batch, even with one list request in it.
        let (body, _, _) = refused(BodyMode::Json, "\u{feff} \n[{}]".as_bytes(), &["1"]);
        assert_eq!(parse(&body), json!([internal_error(json!(1))]));
        let (body, _, _) = refused(BodyMode::Json, b"[{},{}]", &["1", r#""b""#]);
        assert_eq!(
            parse(&body),
            json!([internal_error(json!(1)), internal_error(json!("b"))])
        );

        // SSE: one event per list request.
        let (body, _, _) = refused(BodyMode::Sse, b"data: [{},{}]\n\n", &["1", "2"]);
        let events: Vec<Value> = body
            .split("\n\n")
            .filter(|event| !event.is_empty())
            .map(|event| {
                parse(
                    event
                        .strip_prefix("event: message\ndata: ")
                        .unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(
            events,
            vec![internal_error(json!(1)), internal_error(json!(2))]
        );
        assert!(body.ends_with("\n\n"));
    }

    #[test]
    fn a_kept_body_only_gets_no_store() {
        let changes = HeaderChanges::no_store();
        assert!(changes.remove.is_empty(), "validators still match");
        assert_eq!(changes.set, vec![("cache-control", "no-store".to_owned())]);
    }

    #[test]
    fn an_incomplete_response_marks_the_catalog_stale() {
        let config = Config::from_json(b"{}").unwrap_or_else(|err| unreachable!("{err}"));
        let mut catalogs = Catalogs::new(
            MemoryStore::default(),
            CatalogSettings::from_config(&config),
            "index".to_owned(),
        );
        let read = Pin {
            class: Class::Read,
            source: Source::Annotations,
        };
        catalogs.record_success("k", 100, &[("search", read)]);
        let pending = Pending {
            ids: Vec::new(),
            caller: Caller::new(&config, BTreeSet::new()),
            key: Ok("k".to_owned()),
        };
        let mut reasons = Vec::new();
        let mut log = |event: &Event<'_>, catalog: Option<&str>| {
            if let Event::CatalogStale(reason) = event {
                reasons.push((reason.as_str(), catalog.map(str::to_owned)));
            }
        };
        let mut env = Env {
            config: &config,
            catalogs: &mut catalogs,
            now_ms: 200,
            log: &mut log,
        };
        on_incomplete(&pending, &mut env);
        let catalog = catalogs.read("k");
        assert!(catalog.is_stale(200, 0));
        assert_eq!(catalog.pin("search"), Some(read), "pins are kept");
        assert_eq!(reasons, vec![("incomplete", Some("k".to_owned()))]);
    }
}
