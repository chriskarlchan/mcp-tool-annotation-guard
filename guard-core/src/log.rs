// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Structured log events.
//!
//! Each event renders to one JSON line that starts with `event` and `policy`,
//! followed by the request context and the event's own fields. The policy
//! glue hands the line to the PDK logger at the event's level.
//!
//! Events carry only fixed fields, so tool arguments, tool
//! results, tokens and claims cannot reach a log line. Caller attributes are
//! added only when `logging.logCallerAttributes` is set.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;

use crate::catalog::{CapacityLimit, PinChange};
use crate::classify::{Note, Source};
use crate::config::{Class, Config, Level, Limits, Logging, Mode};
use crate::decide::Refusal;
use crate::freshness::StaleReason;
use crate::response::{ProtocolError, POLICY_NAME};

/// Longest string value in a log line, in bytes.
pub const MAX_LOGGED_BYTES: usize = 128;
/// Most names in one list field.
pub const MAX_LOGGED_NAMES: usize = 50;
/// Repeated `warn` events of one type for one catalog: at most one per this
/// interval.
pub const WARN_INTERVAL_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
}

/// The request context included in every event.
#[derive(Clone, Copy, Debug, Default)]
pub struct Context<'a> {
    pub api_instance: &'a str,
    pub request_id: Option<&'a str>,
    pub client_id: Option<&'a str>,
    /// Logged only with `logging.logCallerAttributes`, and only on call events.
    pub caller_attributes: Option<&'a BTreeSet<String>>,
}

/// One log event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    CallDenied(&'a Refusal),
    /// `would_deny` for a policy refusal in audit mode.
    WouldDeny(&'a Refusal),
    /// `would_deny` for a protocol error in audit mode.
    WouldReject(&'a ProtocolError),
    CallAllowed {
        tool: &'a str,
        class: Class,
        caller_level: Level,
    },
    RequestRejected(&'a ProtocolError),
    ListFiltered {
        total: usize,
        hidden: &'a [&'a str],
    },
    /// Invalid entries in one list response (`count` is the number of entries).
    ListEntryInvalid {
        count: usize,
    },
    ToolClassified {
        tool: &'a str,
        class: Class,
        source: Source,
        idempotent_hint: Option<bool>,
        open_world_hint: Option<bool>,
    },
    ClassificationUpgraded {
        tool: &'a str,
        from: Class,
        to: Class,
    },
    ClassificationDowngradeIgnored {
        tool: &'a str,
        pinned: Class,
        observed: Class,
    },
    AnnotationsContradictory {
        tool: &'a str,
    },
    AnnotationsMalformed {
        tool: &'a str,
        field: &'static str,
    },
    ToolDefinitionConflict {
        tool: &'a str,
        classes: &'a [Class],
    },
    CatalogStale(StaleReason),
    CatalogFresh,
    PinCapacityExhausted(CapacityLimit),
    CatalogMergeRetryExhausted,
    PartitionUnavailable,
    CallerAttributesUnavailable,
    /// At policy start: the configured `limits.*`, to compare with the
    /// gateway buffer limit.
    LimitsConfigured(&'a Limits),
}

impl<'a> Event<'a> {
    /// `call_denied`, or `would_deny` in audit mode.
    pub fn refusal(config: &Config, refusal: &'a Refusal) -> Event<'a> {
        match config.mode {
            Mode::Enforce => Event::CallDenied(refusal),
            Mode::Audit => Event::WouldDeny(refusal),
        }
    }

    /// `request_rejected`, or `would_deny` in audit mode.
    pub fn protocol(config: &Config, err: &'a ProtocolError) -> Event<'a> {
        match config.mode {
            Mode::Enforce => Event::RequestRejected(err),
            Mode::Audit => Event::WouldReject(err),
        }
    }

    /// The event for a pin change that is worth logging. A new pin is logged
    /// as `tool_classified` by the caller, which has the hints.
    pub fn pin_change(tool: &'a str, change: &PinChange) -> Option<Event<'a>> {
        match *change {
            PinChange::Upgraded { from, to } => {
                Some(Event::ClassificationUpgraded { tool, from, to })
            }
            PinChange::DowngradeIgnored { pinned, observed } => {
                Some(Event::ClassificationDowngradeIgnored {
                    tool,
                    pinned,
                    observed,
                })
            }
            PinChange::NotPinned(limit) => Some(Event::PinCapacityExhausted(limit)),
            PinChange::New(_) | PinChange::Unchanged => None,
        }
    }

    pub fn note(tool: &'a str, note: Note) -> Event<'a> {
        match note {
            Note::Malformed { field } => Event::AnnotationsMalformed { tool, field },
            Note::Contradictory => Event::AnnotationsContradictory { tool },
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Event::CallDenied(_) => "call_denied",
            Event::WouldDeny(_) | Event::WouldReject(_) => "would_deny",
            Event::CallAllowed { .. } => "call_allowed",
            Event::RequestRejected(_) => "request_rejected",
            Event::ListFiltered { .. } => "list_filtered",
            Event::ListEntryInvalid { .. } => "list_entry_invalid",
            Event::ToolClassified { .. } => "tool_classified",
            Event::ClassificationUpgraded { .. } => "classification_upgraded",
            Event::ClassificationDowngradeIgnored { .. } => "classification_downgrade_ignored",
            Event::AnnotationsContradictory { .. } => "annotations_contradictory",
            Event::AnnotationsMalformed { .. } => "annotations_malformed",
            Event::ToolDefinitionConflict { .. } => "tool_definition_conflict",
            Event::CatalogStale(_) => "catalog_stale",
            Event::CatalogFresh => "catalog_fresh",
            Event::PinCapacityExhausted(_) => "pin_capacity_exhausted",
            Event::CatalogMergeRetryExhausted => "catalog_merge_retry_exhausted",
            Event::PartitionUnavailable => "partition_unavailable",
            Event::CallerAttributesUnavailable => "caller_attributes_unavailable",
            Event::LimitsConfigured(_) => "limits_configured",
        }
    }

    pub fn level(&self) -> LogLevel {
        match self {
            Event::CallAllowed { .. }
            | Event::ToolClassified { .. }
            | Event::CallerAttributesUnavailable => LogLevel::Debug,
            Event::CallDenied(_)
            | Event::WouldDeny(_)
            | Event::WouldReject(_)
            | Event::ListFiltered { .. }
            | Event::ClassificationUpgraded { .. }
            | Event::AnnotationsContradictory { .. }
            | Event::CatalogFresh
            | Event::LimitsConfigured(_) => LogLevel::Info,
            Event::RequestRejected(_)
            | Event::ListEntryInvalid { .. }
            | Event::ClassificationDowngradeIgnored { .. }
            | Event::AnnotationsMalformed { .. }
            | Event::ToolDefinitionConflict { .. }
            | Event::CatalogStale(_)
            | Event::PinCapacityExhausted(_)
            | Event::CatalogMergeRetryExhausted
            | Event::PartitionUnavailable => LogLevel::Warn,
        }
    }

    /// `call_allowed` is logged only with `logging.logAllowedCalls`.
    pub fn enabled(&self, logging: &Logging) -> bool {
        !matches!(self, Event::CallAllowed { .. }) || logging.log_allowed_calls
    }

    fn is_call_event(&self) -> bool {
        matches!(
            self,
            Event::CallDenied(_)
                | Event::WouldDeny(_)
                | Event::WouldReject(_)
                | Event::CallAllowed { .. }
        )
    }
}

/// Renders an event as one JSON line (no trailing newline).
pub fn render(event: &Event<'_>, context: &Context<'_>, logging: &Logging) -> String {
    let mut line = Line::new(event.name());
    line.str("apiInstance", context.api_instance);
    line.opt_str("requestId", context.request_id);
    line.opt_str("clientId", context.client_id);
    if logging.log_caller_attributes && event.is_call_event() {
        if let Some(attributes) = context.caller_attributes {
            line.names("callerAttributes", attributes.iter().map(String::as_str));
        }
    }
    match *event {
        Event::CallDenied(refusal) | Event::WouldDeny(refusal) => {
            line.str("tool", &refusal.tool);
            if let Some(class) = refusal.class {
                line.str("toolClass", class.as_str());
            }
            line.str("callerLevel", refusal.caller_level.as_str());
            line.str("reason", refusal.reason.as_str());
        }
        Event::WouldReject(err) | Event::RequestRejected(err) => {
            line.str("reason", err.reason());
            line.opt_str("detail", err.detail());
        }
        Event::CallAllowed {
            tool,
            class,
            caller_level,
        } => {
            line.str("tool", tool);
            line.str("toolClass", class.as_str());
            line.str("callerLevel", caller_level.as_str());
        }
        Event::ListFiltered { total, hidden } => {
            line.num("toolsTotal", total);
            line.num("toolsHidden", hidden.len());
            line.names("hiddenTools", hidden.iter().copied());
        }
        Event::ListEntryInvalid { count } => line.num("count", count),
        Event::ToolClassified {
            tool,
            class,
            source,
            idempotent_hint,
            open_world_hint,
        } => {
            line.str("tool", tool);
            line.str("class", class.as_str());
            line.str("source", source.as_str());
            line.opt_bool("idempotentHint", idempotent_hint);
            line.opt_bool("openWorldHint", open_world_hint);
        }
        Event::ClassificationUpgraded { tool, from, to } => {
            line.str("tool", tool);
            line.str("from", from.as_str());
            line.str("to", to.as_str());
        }
        Event::ClassificationDowngradeIgnored {
            tool,
            pinned,
            observed,
        } => {
            line.str("tool", tool);
            line.str("pinned", pinned.as_str());
            line.str("observed", observed.as_str());
        }
        Event::AnnotationsContradictory { tool } => line.str("tool", tool),
        Event::AnnotationsMalformed { tool, field } => {
            line.str("tool", tool);
            line.str("field", field);
        }
        Event::ToolDefinitionConflict { tool, classes } => {
            line.str("tool", tool);
            line.names("classes", classes.iter().map(|class| class.as_str()));
        }
        Event::CatalogStale(reason) => line.str("reason", reason.as_str()),
        Event::PinCapacityExhausted(limit) => line.str("limit", limit.as_str()),
        Event::LimitsConfigured(limits) => {
            line.num("maxRequestBodyBytes", limits.max_request_body_bytes);
            line.num("maxListResponseBytes", limits.max_list_response_bytes);
            line.num("maxToolNameBytes", limits.max_tool_name_bytes);
            line.num("maxBatchSize", limits.max_batch_size);
            line.num("maxCachedTools", limits.max_cached_tools);
            line.num("maxCatalogBytes", limits.max_catalog_bytes);
            line.num("maxCatalogs", limits.max_catalogs);
        }
        Event::CatalogFresh
        | Event::CatalogMergeRetryExhausted
        | Event::PartitionUnavailable
        | Event::CallerAttributesUnavailable => {}
    }
    line.finish()
}

/// Truncates to at most [`MAX_LOGGED_BYTES`], at a character boundary.
pub fn bounded(value: &str) -> &str {
    let mut end = value.len().min(MAX_LOGGED_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.get(..end).unwrap_or_default()
}

/// A JSON object written field by field, so the order is fixed.
struct Line(String);

impl Line {
    fn new(event: &str) -> Line {
        let mut line = Line(String::with_capacity(256));
        line.0.push_str("{\"event\":");
        push_json_string(&mut line.0, event);
        line.str("policy", POLICY_NAME);
        line
    }

    fn key(&mut self, key: &str) {
        self.0.push(',');
        push_json_string(&mut self.0, key);
        self.0.push(':');
    }

    fn str(&mut self, key: &str, value: &str) {
        self.key(key);
        push_json_string(&mut self.0, bounded(value));
    }

    fn opt_str(&mut self, key: &str, value: Option<&str>) {
        if let Some(value) = value {
            self.str(key, value);
        }
    }

    fn num(&mut self, key: &str, value: usize) {
        self.key(key);
        let _ = write!(self.0, "{value}");
    }

    fn opt_bool(&mut self, key: &str, value: Option<bool>) {
        if let Some(value) = value {
            self.key(key);
            self.0.push_str(if value { "true" } else { "false" });
        }
    }

    fn names<'n>(&mut self, key: &str, names: impl Iterator<Item = &'n str>) {
        self.key(key);
        self.0.push('[');
        for (i, name) in names.take(MAX_LOGGED_NAMES).enumerate() {
            if i > 0 {
                self.0.push(',');
            }
            push_json_string(&mut self.0, bounded(name));
        }
        self.0.push(']');
    }

    fn finish(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

/// Appends `value` as a JSON string (RFC 8259 §7).
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Limits repeated `warn` events of one type for one catalog to one per
/// [`WARN_INTERVAL_MS`]. Each worker has its own limiter.
#[derive(Debug)]
pub struct WarnLimiter {
    last: HashMap<(&'static str, String), u64>,
    capacity: usize,
}

impl WarnLimiter {
    /// `capacity` bounds the number of (event, catalog) pairs remembered.
    pub fn new(capacity: usize) -> WarnLimiter {
        WarnLimiter {
            last: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    pub fn len(&self) -> usize {
        self.last.len()
    }

    pub fn is_empty(&self) -> bool {
        self.last.is_empty()
    }

    /// Whether to log `event` now. `catalog` is the catalog key, if the
    /// event concerns one; events without a catalog share one slot per type.
    /// Non-warn events are always logged. A clock that moved backwards
    /// resets the interval rather than suppressing until it catches up.
    pub fn allow(&mut self, event: &Event<'_>, catalog: Option<&str>, now_ms: u64) -> bool {
        if event.level() != LogLevel::Warn {
            return true;
        }
        let key = (event.name(), catalog.unwrap_or_default().to_owned());
        if let Some(&last) = self.last.get(&key) {
            if now_ms >= last && now_ms - last < WARN_INTERVAL_MS {
                return false;
            }
        } else if self.last.len() >= self.capacity {
            self.last
                .retain(|_, last| now_ms >= *last && now_ms - *last < WARN_INTERVAL_MS);
            if self.last.len() >= self.capacity {
                // Still full: forget the oldest pair. That event may then be
                // logged again early, which errs towards more logging.
                let oldest = self
                    .last
                    .iter()
                    .min_by_key(|(_, last)| **last)
                    .map(|(key, _)| key.clone());
                if let Some(oldest) = oldest {
                    self.last.remove(&oldest);
                }
            }
        }
        self.last.insert(key, now_ms);
        true
    }
}

/// Everything the glue needs to log one event: `None` if it is disabled or
/// rate-limited, otherwise the level and the rendered line.
pub fn prepare(
    event: &Event<'_>,
    context: &Context<'_>,
    logging: &Logging,
    limiter: &mut WarnLimiter,
    catalog: Option<&str>,
    now_ms: u64,
) -> Option<(LogLevel, String)> {
    if !event.enabled(logging) || !limiter.allow(event, catalog, now_ms) {
        return None;
    }
    Some((event.level(), render(event, context, logging)))
}

#[cfg(test)]
// Indexing a `serde_json::Value` returns `Null` for a missing key; it never panics.
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::catalog::Pin;
    use crate::decide::{
        decide_requests, CallDecision, Caller, CatalogView, ElementDecision, Lookup, Reason,
    };
    use crate::envelope::{inspect_request, Routing};
    use serde_json::{json, Value};

    fn config(value: Value) -> Config {
        Config::from_json(value.to_string().as_bytes()).unwrap_or_else(|err| unreachable!("{err}"))
    }

    fn parse(line: &str) -> Value {
        serde_json::from_str(line).unwrap_or_else(|err| unreachable!("{err}: {line}"))
    }

    fn keys(line: &str) -> Vec<String> {
        let value: serde_json::Map<String, Value> =
            serde_json::from_str(line).unwrap_or_else(|_| unreachable!());
        // serde_json's map is sorted, so read the order from the text instead.
        let mut found: Vec<(usize, String)> = value
            .keys()
            .map(|key| {
                (
                    line.find(&format!("\"{key}\":")).unwrap_or(usize::MAX),
                    key.clone(),
                )
            })
            .collect();
        found.sort();
        found.into_iter().map(|(_, key)| key).collect()
    }

    fn test_id() -> crate::ids::Id {
        match crate::ids::Id::from_raw("1") {
            crate::ids::IdToken::Valid(id) => id,
            other => unreachable!("{other:?}"),
        }
    }

    const CONTEXT: Context<'static> = Context {
        api_instance: "api-1",
        request_id: Some("req-7"),
        client_id: Some("client-9"),
        caller_attributes: None,
    };

    fn refusal() -> Refusal {
        Refusal {
            reason: Reason::LevelInsufficient,
            tool: "drop_table".to_owned(),
            caller_level: Level::Read,
            class: Some(Class::Destructive),
        }
    }

    #[test]
    fn every_event_renders_one_json_object_with_common_fields_first() {
        let refusal = refusal();
        let err = ProtocolError::MethodNotAllowed;
        let hidden = ["a", "b"];
        let classes = [Class::Read, Class::Destructive];
        let events = [
            Event::CallDenied(&refusal),
            Event::WouldDeny(&refusal),
            Event::WouldReject(&err),
            Event::CallAllowed {
                tool: "t",
                class: Class::Read,
                caller_level: Level::Read,
            },
            Event::RequestRejected(&err),
            Event::ListFiltered {
                total: 5,
                hidden: &hidden,
            },
            Event::ListEntryInvalid { count: 2 },
            Event::ToolClassified {
                tool: "t",
                class: Class::Write,
                source: Source::NameRule,
                idempotent_hint: Some(true),
                open_world_hint: None,
            },
            Event::ClassificationUpgraded {
                tool: "t",
                from: Class::Read,
                to: Class::Write,
            },
            Event::ClassificationDowngradeIgnored {
                tool: "t",
                pinned: Class::Destructive,
                observed: Class::Read,
            },
            Event::AnnotationsContradictory { tool: "t" },
            Event::AnnotationsMalformed {
                tool: "t",
                field: "readOnlyHint",
            },
            Event::ToolDefinitionConflict {
                tool: "t",
                classes: &classes,
            },
            Event::CatalogStale(StaleReason::ListChanged),
            Event::CatalogFresh,
            Event::PinCapacityExhausted(CapacityLimit::MaxCatalogBytes),
            Event::CatalogMergeRetryExhausted,
            Event::PartitionUnavailable,
            Event::CallerAttributesUnavailable,
        ];
        let defaults = config(json!({}));
        let logging = defaults.logging;
        let events: Vec<Event<'_>> = events
            .into_iter()
            .chain([Event::LimitsConfigured(&defaults.limits)])
            .collect();
        for event in events {
            let line = render(&event, &CONTEXT, &logging);
            assert!(!line.contains('\n'), "{line}");
            let value = parse(&line);
            assert_eq!(value["event"], event.name(), "{line}");
            assert_eq!(value["policy"], POLICY_NAME);
            assert_eq!(value["apiInstance"], "api-1");
            assert_eq!(value["requestId"], "req-7");
            assert_eq!(value["clientId"], "client-9");
            let order = keys(&line);
            assert_eq!(
                order.get(..5),
                Some(
                    &["event", "policy", "apiInstance", "requestId", "clientId"].map(String::from)
                        [..]
                ),
                "{line}"
            );
        }
    }

    #[test]
    fn event_fields_follow_the_table() {
        let logging = config(json!({})).logging;
        let refusal = refusal();
        let value = parse(&render(&Event::CallDenied(&refusal), &CONTEXT, &logging));
        assert_eq!(value["tool"], "drop_table");
        assert_eq!(value["toolClass"], "destructive");
        assert_eq!(value["callerLevel"], "read");
        assert_eq!(value["reason"], "level_insufficient");

        let unknown = Refusal {
            reason: Reason::UnknownTool,
            class: None,
            ..refusal.clone()
        };
        let value = parse(&render(&Event::CallDenied(&unknown), &CONTEXT, &logging));
        assert_eq!(value.get("toolClass"), None);

        let err = ProtocolError::InvalidParams {
            id: test_id(),
            detail: crate::envelope::ParamsDetail::MissingToolName,
        };
        let value = parse(&render(&Event::RequestRejected(&err), &CONTEXT, &logging));
        assert_eq!(value["reason"], "invalid_params");
        assert_eq!(value["detail"], "missing_tool_name");

        let value = parse(&render(
            &Event::ToolClassified {
                tool: "t",
                class: Class::Write,
                source: Source::Annotations,
                idempotent_hint: Some(false),
                open_world_hint: None,
            },
            &CONTEXT,
            &logging,
        ));
        assert_eq!(value["class"], "write");
        assert_eq!(value["source"], "annotations");
        assert_eq!(value["idempotentHint"], false);
        assert_eq!(value.get("openWorldHint"), None);

        let value = parse(&render(
            &Event::PinCapacityExhausted(CapacityLimit::MaxCachedTools),
            &CONTEXT,
            &logging,
        ));
        assert_eq!(value["limit"], "maxCachedTools");

        let defaults = config(json!({}));
        let value = parse(&render(
            &Event::LimitsConfigured(&defaults.limits),
            &CONTEXT,
            &logging,
        ));
        assert_eq!(value["maxRequestBodyBytes"], 1_048_576);
        assert_eq!(value["maxListResponseBytes"], 1_048_576);
        assert_eq!(value["maxCatalogs"], 1000);

        let minimal = Context {
            api_instance: "api-1",
            ..Context::default()
        };
        let value = parse(&render(&Event::CatalogFresh, &minimal, &logging));
        assert_eq!(value.get("requestId"), None);
        assert_eq!(value.get("clientId"), None);
    }

    #[test]
    fn audit_mode_logs_would_deny() {
        let refusal = refusal();
        let err = ProtocolError::Parse;
        let enforce = config(json!({}));
        let audit = config(json!({"mode": "audit"}));
        assert_eq!(Event::refusal(&enforce, &refusal).name(), "call_denied");
        assert_eq!(Event::refusal(&audit, &refusal).name(), "would_deny");
        assert_eq!(Event::protocol(&enforce, &err).name(), "request_rejected");
        assert_eq!(Event::protocol(&audit, &err).level(), LogLevel::Info);
        let value = parse(&render(
            &Event::protocol(&audit, &err),
            &CONTEXT,
            &audit.logging,
        ));
        assert_eq!(value["event"], "would_deny");
        assert_eq!(value["reason"], "parse_error");
    }

    #[test]
    fn pin_changes_and_notes_map_to_events() {
        let upgraded = PinChange::Upgraded {
            from: Class::Read,
            to: Class::Destructive,
        };
        assert_eq!(
            Event::pin_change("t", &upgraded),
            Some(Event::ClassificationUpgraded {
                tool: "t",
                from: Class::Read,
                to: Class::Destructive
            })
        );
        assert_eq!(
            Event::pin_change("t", &PinChange::NotPinned(CapacityLimit::MaxCachedTools)),
            Some(Event::PinCapacityExhausted(CapacityLimit::MaxCachedTools))
        );
        let new = PinChange::New(Pin {
            class: Class::Read,
            source: Source::Default,
        });
        assert_eq!(Event::pin_change("t", &new), None);
        assert_eq!(Event::pin_change("t", &PinChange::Unchanged), None);
        assert_eq!(
            Event::note("t", Note::Contradictory).level(),
            LogLevel::Info
        );
        assert_eq!(
            Event::note(
                "t",
                Note::Malformed {
                    field: "openWorldHint"
                }
            )
            .level(),
            LogLevel::Warn
        );
    }

    #[test]
    fn strings_are_escaped() {
        let logging = config(json!({})).logging;
        let tool = "a\"b\\c\nd\u{1}e\u{7f}\u{2028}";
        let line = render(
            &Event::AnnotationsContradictory { tool },
            &CONTEXT,
            &logging,
        );
        assert!(!line.contains('\n'));
        assert_eq!(parse(&line)["tool"], tool);
    }

    #[test]
    fn names_are_bounded_in_length_and_number() {
        let logging = config(json!({})).logging;
        let long = "é".repeat(100); // 200 bytes
        let line = render(
            &Event::AnnotationsContradictory { tool: &long },
            &CONTEXT,
            &logging,
        );
        let tool = parse(&line)["tool"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_default();
        assert_eq!(tool.len(), MAX_LOGGED_BYTES);
        assert_eq!(tool, "é".repeat(64));

        let odd = format!("x{}", "é".repeat(100)); // boundary falls inside a character
        assert_eq!(bounded(&odd).len(), MAX_LOGGED_BYTES - 1);
        assert_eq!(bounded("short"), "short");

        let names: Vec<String> = (0..80).map(|i| format!("tool_{i}")).collect();
        let hidden: Vec<&str> = names.iter().map(String::as_str).collect();
        let value = parse(&render(
            &Event::ListFiltered {
                total: 100,
                hidden: &hidden,
            },
            &CONTEXT,
            &logging,
        ));
        assert_eq!(value["toolsTotal"], 100);
        assert_eq!(value["toolsHidden"], 80);
        assert_eq!(
            value["hiddenTools"].as_array().map(Vec::len),
            Some(MAX_LOGGED_NAMES)
        );
        assert_eq!(value["hiddenTools"][49], "tool_49");

        let request_id = "r".repeat(1000);
        let context = Context {
            request_id: Some(&request_id),
            ..CONTEXT
        };
        let value = parse(&render(&Event::CatalogFresh, &context, &logging));
        assert_eq!(
            value["requestId"].as_str().map(str::len),
            Some(MAX_LOGGED_BYTES)
        );
    }

    #[test]
    fn caller_attributes_only_when_enabled_and_only_on_call_events() {
        let attributes: BTreeSet<String> = ["role:admin".to_owned(), "team:ops".to_owned()].into();
        let context = Context {
            caller_attributes: Some(&attributes),
            ..CONTEXT
        };
        let refusal = refusal();
        let off = config(json!({})).logging;
        let on = config(json!({"logging": {"logCallerAttributes": true}})).logging;

        let line = render(&Event::CallDenied(&refusal), &context, &off);
        assert!(!line.contains("role:admin"), "{line}");
        assert_eq!(parse(&line).get("callerAttributes"), None);

        let value = parse(&render(&Event::CallDenied(&refusal), &context, &on));
        assert_eq!(value["callerAttributes"], json!(["role:admin", "team:ops"]));

        let line = render(&Event::CatalogFresh, &context, &on);
        assert!(!line.contains("role:admin"), "{line}");
    }

    #[test]
    fn allowed_calls_are_logged_only_when_enabled() {
        let event = Event::CallAllowed {
            tool: "t",
            class: Class::Read,
            caller_level: Level::Read,
        };
        assert_eq!(event.level(), LogLevel::Debug);
        assert!(!event.enabled(&config(json!({})).logging));
        assert!(event.enabled(&config(json!({"logging": {"logAllowedCalls": true}})).logging));
        assert!(Event::CatalogFresh.enabled(&config(json!({})).logging));
    }

    #[test]
    fn warn_events_are_rate_limited_per_type_and_catalog() {
        let mut limiter = WarnLimiter::new(100);
        let stale = Event::CatalogStale(StaleReason::Encoded);
        let retry = Event::CatalogMergeRetryExhausted;
        assert!(limiter.allow(&stale, Some("k1"), 1_000));
        assert!(!limiter.allow(&stale, Some("k1"), 1_000 + WARN_INTERVAL_MS - 1));
        assert!(
            !limiter.allow(
                &Event::CatalogStale(StaleReason::TooLarge),
                Some("k1"),
                2_000
            ),
            "same type, other reason"
        );
        assert!(limiter.allow(&stale, Some("k2"), 2_000), "other catalog");
        assert!(limiter.allow(&retry, Some("k1"), 2_000), "other type");
        assert!(limiter.allow(&stale, Some("k1"), 1_000 + WARN_INTERVAL_MS));
        assert!(!limiter.allow(&stale, Some("k1"), 1_000 + WARN_INTERVAL_MS + 1));

        // Info and debug events are never limited.
        for _ in 0..3 {
            assert!(limiter.allow(&Event::CatalogFresh, Some("k1"), 5_000));
        }

        // Events without a catalog share one slot per type.
        assert!(limiter.allow(&Event::PartitionUnavailable, None, 0));
        assert!(!limiter.allow(&Event::PartitionUnavailable, None, 10));

        // A clock that moved backwards resets the interval.
        let mut limiter = WarnLimiter::new(10);
        assert!(limiter.allow(&stale, Some("k"), 500_000));
        assert!(limiter.allow(&stale, Some("k"), 100_000));
        assert!(!limiter.allow(&stale, Some("k"), 100_001));
    }

    #[test]
    fn rate_limiter_memory_is_bounded() {
        let mut limiter = WarnLimiter::new(3);
        let stale = Event::CatalogStale(StaleReason::Encoded);
        for i in 0..10u64 {
            assert!(limiter.allow(&stale, Some(&format!("k{i}")), i));
            assert!(limiter.len() <= 3);
        }
        // Expired pairs are dropped before the oldest live one.
        let mut limiter = WarnLimiter::new(2);
        assert!(limiter.allow(&stale, Some("old"), 0));
        assert!(limiter.allow(&stale, Some("live"), WARN_INTERVAL_MS));
        assert!(limiter.allow(&stale, Some("new"), WARN_INTERVAL_MS + 1));
        assert!(!limiter.allow(&stale, Some("live"), WARN_INTERVAL_MS + 2));
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn prepare_combines_enablement_and_rate_limit() {
        let logging = config(json!({})).logging;
        let mut limiter = WarnLimiter::new(10);
        let allowed = Event::CallAllowed {
            tool: "t",
            class: Class::Read,
            caller_level: Level::Read,
        };
        assert_eq!(
            prepare(&allowed, &CONTEXT, &logging, &mut limiter, None, 0),
            None
        );
        let first = prepare(
            &Event::PartitionUnavailable,
            &CONTEXT,
            &logging,
            &mut limiter,
            None,
            0,
        );
        assert_eq!(
            first.as_ref().map(|(level, _)| *level),
            Some(LogLevel::Warn)
        );
        assert_eq!(
            prepare(
                &Event::PartitionUnavailable,
                &CONTEXT,
                &logging,
                &mut limiter,
                None,
                1
            ),
            None
        );
    }

    /// Tool arguments, results, tokens and claims never reach the logs.
    #[test]
    fn secrets_never_reach_log_lines() {
        const SECRET: &str = "S3CR3T-hunter2";
        let body = format!(
            r#"[
                {{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"search","arguments":{{"password":"{SECRET}"}},"_meta":{{"token":"{SECRET}"}}}}}},
                {{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"drop","arguments":{{"apiKey":"{SECRET}"}}}}}},
                {{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"arguments":{{"x":"{SECRET}"}}}}}}
            ]"#
        );
        for logging_config in [
            json!({"logging": {"logAllowedCalls": true}}),
            json!({"mode": "audit", "logging": {"logAllowedCalls": true}}),
        ] {
            let c = config(logging_config);
            let attributes: BTreeSet<String> = [format!("bearer {SECRET}")].into();
            let caller = Caller::new(&c, attributes.clone());
            let requests =
                match inspect_request(body.as_bytes(), Some("2025-03-26"), c.limits.envelope()) {
                    Ok(Routing::Decide { requests, .. }) => requests,
                    other => unreachable!("{other:?}"),
                };
            let decisions = decide_requests(&requests, &c, &caller, |name| {
                Lookup::Catalog(CatalogView {
                    pin: (name == "search").then_some(Pin {
                        class: Class::Read,
                        source: Source::Annotations,
                    }),
                    stale: false,
                })
            });
            let context = Context {
                caller_attributes: Some(&attributes),
                ..CONTEXT
            };
            let mut lines = Vec::new();
            for (_, decision) in &decisions {
                let line = match decision {
                    ElementDecision::Call(CallDecision::Allow { class, .. }) => render(
                        &Event::CallAllowed {
                            tool: "search",
                            class: *class,
                            caller_level: caller.level,
                        },
                        &context,
                        &c.logging,
                    ),
                    ElementDecision::Call(CallDecision::Deny(refusal)) => {
                        render(&Event::refusal(&c, refusal), &context, &c.logging)
                    }
                    ElementDecision::InvalidParams(detail) => {
                        let err = ProtocolError::InvalidParams {
                            id: test_id(),
                            detail: *detail,
                        };
                        render(&Event::protocol(&c, &err), &context, &c.logging)
                    }
                    ElementDecision::NotACall => continue,
                };
                lines.push(line);
            }
            assert_eq!(lines.len(), 3);
            for line in &lines {
                assert!(!line.contains(SECRET), "{line}");
                assert!(
                    !line.contains("password") && !line.contains("arguments"),
                    "{line}"
                );
            }
        }
    }
}
