// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Caller level and the authorization decision for `tools/call` and `tools/list`.
//!
//! Design choices:
//! - Splitting a string by `callerAttributeSeparator` drops empty pieces but
//!   does not trim whitespace, so comparison stays exact (`"a, b"` split by
//!   `","` gives `"a"` and `" b"`). Empty strings are never attributes.
//! - When `catalogPartition` is unavailable, every `tools/call` is refused
//!   with `partition_unavailable`, before the blocked and override checks.
//! - `tools/list` filtering uses the same class a call would be decided with
//!   right after the merge, so an entry is shown iff calling it would be
//!   allowed. Tools that stay unknown (capacity, or a catalog still stale
//!   because of a later failure) are hidden under `onUnknownTool: deny`.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::catalog::Pin;
use crate::classify::{by_name, Source};
use crate::config::{Class, Config, Level, Mode, OnUnknownTool};
use crate::envelope::{CallCheck, ParamsDetail, RequestElement};
use crate::ids::Id;

// --- caller ----------------------------------------------------------

/// Normalises the evaluated `callerAttributes` expression.
///
/// `value` is `None` when the expression is unset or failed to evaluate;
/// both give the empty set and never deny on their own.
pub fn normalize_attributes(value: Option<&Value>, separator: Option<&str>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    match value {
        Some(Value::String(s)) => match separator {
            Some(sep) if !sep.is_empty() => {
                out.extend(
                    s.split(sep)
                        .filter(|piece| !piece.is_empty())
                        .map(str::to_owned),
                );
            }
            _ => {
                if !s.is_empty() {
                    out.insert(s.clone());
                }
            }
        },
        Some(Value::Array(items)) => {
            out.extend(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
            );
        }
        _ => {}
    }
    out
}

/// The caller of one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    pub attributes: BTreeSet<String>,
    pub level: Level,
}

impl Caller {
    /// `callerLevel = max(defaultLevel, max{grant.level | grant.attribute ∈ attributes})`.
    pub fn new(config: &Config, attributes: BTreeSet<String>) -> Caller {
        let level = config
            .grants
            .iter()
            .filter(|grant| attributes.contains(&grant.attribute))
            .map(|grant| grant.level)
            .fold(config.default_level, Level::max);
        Caller { attributes, level }
    }
}

/// The `grants[].attribute` values that would allow `class`, in configuration
/// order without repeats (`revealGrantNames`).
pub fn grants_providing(config: &Config, class: Class) -> Vec<&str> {
    let mut seen = BTreeSet::new();
    config
        .grants
        .iter()
        .filter(|grant| grant.level >= class.level())
        .map(|grant| grant.attribute.as_str())
        .filter(|matches| seen.insert(*matches))
        .collect()
}

// --- effective class ----------------------------------------------

/// What the catalog for the request's partition says about one tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogView {
    pub pin: Option<Pin>,
    pub stale: bool,
}

/// Where the class used for a decision came from (logged as `source`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    Override,
    /// A pin in a fresh catalog.
    Pin(Source),
    /// An unknown tool under `onUnknownTool: classifyByName`.
    ByName(Source),
}

impl Basis {
    pub fn as_str(self) -> &'static str {
        match self {
            Basis::Override => "override",
            Basis::Pin(_) => "pin",
            Basis::ByName(_) => "classifyByName",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effective {
    Blocked,
    Known {
        class: Class,
        basis: Basis,
    },
    /// Unknown under `onUnknownTool: deny`.
    Unknown,
}

/// The class a tool is decided with.
pub fn effective_class(name: &str, config: &Config, view: CatalogView) -> Effective {
    if config.blocked_tools.contains(name) {
        return Effective::Blocked;
    }
    if let Some(class) = config.tool_overrides.get(name) {
        return Effective::Known {
            class: *class,
            basis: Basis::Override,
        };
    }
    if let (false, Some(pin)) = (view.stale, view.pin) {
        return Effective::Known {
            class: pin.class,
            basis: Basis::Pin(pin.source),
        };
    }
    match config.on_unknown_tool {
        OnUnknownTool::Deny => Effective::Unknown,
        OnUnknownTool::ClassifyByName => {
            let (class, source) = by_name(name, &config.classification);
            Effective::Known {
                class,
                basis: Basis::ByName(source),
            }
        }
    }
}

// --- tools/call ---------------------------------------------------------------

/// The reason of a policy refusal (`reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    LevelInsufficient,
    ToolBlocked,
    UnknownTool,
    PartitionUnavailable,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::LevelInsufficient => "level_insufficient",
            Reason::ToolBlocked => "tool_blocked",
            Reason::UnknownTool => "unknown_tool",
            Reason::PartitionUnavailable => "partition_unavailable",
        }
    }
}

/// A denied `tools/call`, with what the refusal message needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub reason: Reason,
    pub tool: String,
    pub caller_level: Level,
    /// The tool's class, for `level_insufficient`.
    pub class: Option<Class>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallDecision {
    Allow { class: Class, basis: Basis },
    Deny(Refusal),
}

impl CallDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, CallDecision::Allow { .. })
    }
}

/// The catalog for a request, or the reason there is none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    PartitionUnavailable,
    Catalog(CatalogView),
}

/// Decides one `tools/call`. `lookup` is the catalog view for `name`.
pub fn decide_call(name: &str, config: &Config, caller: &Caller, lookup: Lookup) -> CallDecision {
    let deny = |reason, class| {
        CallDecision::Deny(Refusal {
            reason,
            tool: name.to_owned(),
            caller_level: caller.level,
            class,
        })
    };
    let view = match lookup {
        Lookup::PartitionUnavailable => return deny(Reason::PartitionUnavailable, None),
        Lookup::Catalog(view) => view,
    };
    match effective_class(name, config, view) {
        Effective::Blocked => deny(Reason::ToolBlocked, None),
        Effective::Unknown => deny(Reason::UnknownTool, None),
        Effective::Known { class, basis } => {
            if class.level() <= caller.level {
                CallDecision::Allow { class, basis }
            } else {
                deny(Reason::LevelInsufficient, Some(class))
            }
        }
    }
}

/// The decision for one request element of a `Decide` routing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElementDecision {
    /// Not a `tools/call` (another request method): never refused by itself.
    NotACall,
    Call(CallDecision),
    /// A `tools/call` with invalid `params` (batch only).
    InvalidParams(ParamsDetail),
}

impl ElementDecision {
    pub fn is_refused(&self) -> bool {
        match self {
            ElementDecision::NotACall => false,
            ElementDecision::Call(decision) => !decision.is_allowed(),
            ElementDecision::InvalidParams(_) => true,
        }
    }
}

/// Decides every request element. A batch is forwarded only if no element
/// is refused (`batch_rejected`). `lookup` gives the catalog view
/// for a tool name.
pub fn decide_requests(
    requests: &[RequestElement],
    config: &Config,
    caller: &Caller,
    mut lookup: impl FnMut(&str) -> Lookup,
) -> Vec<(Id, ElementDecision)> {
    requests
        .iter()
        .map(|element| {
            let decision = match &element.call {
                CallCheck::Other => ElementDecision::NotACall,
                CallCheck::InvalidParams(detail) => ElementDecision::InvalidParams(*detail),
                CallCheck::Call { name } => {
                    ElementDecision::Call(decide_call(name, config, caller, lookup(name)))
                }
            };
            (element.id.clone(), decision)
        })
        .collect()
}

// --- tools/list ---------------------------------------------------------------

/// `true` when list responses are filtered: not with
/// `filterToolsList: false`, and never in audit mode.
pub fn filtering_active(config: &Config) -> bool {
    config.filter_tools_list && config.mode == Mode::Enforce
}

/// `true` when a list entry is shown to this caller. `view` is the
/// catalog after this response's pins were merged.
pub fn list_entry_visible(name: &str, config: &Config, caller: &Caller, view: CatalogView) -> bool {
    match effective_class(name, config, view) {
        Effective::Blocked | Effective::Unknown => false,
        Effective::Known { class, .. } => class.level() <= caller.level,
    }
}

/// How a valid `tools/list` response is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListHandling {
    /// Learn its pins, then filter it if [`filtering_active`].
    Learn,
    /// The partition is unavailable: replace every list with an empty array
    /// and update no catalog (fail closed).
    Empty,
    /// The partition is unavailable but filtering is off (audit mode or
    /// `filterToolsList: false`): forward unchanged and update no catalog.
    ForwardWithoutLearning,
}

pub fn list_handling(config: &Config, partition_available: bool) -> ListHandling {
    match (partition_available, filtering_active(config)) {
        (true, _) => ListHandling::Learn,
        (false, true) => ListHandling::Empty,
        (false, false) => ListHandling::ForwardWithoutLearning,
    }
}

// --- audit mode ---------------------------------------------------------------

/// What to do with a request or response the guard would refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Forward,
    /// Audit mode: forward unchanged and log `would_deny`.
    ForwardWouldDeny,
    Refuse,
}

/// Applies `mode` to a refusal the guard would generate (audit mode).
pub fn action_for(config: &Config, refused: bool) -> Action {
    match (refused, config.mode) {
        (false, _) => Action::Forward,
        (true, Mode::Enforce) => Action::Refuse,
        (true, Mode::Audit) => Action::ForwardWouldDeny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{inspect_request, EnvelopeLimits, Routing};
    use serde_json::json;

    fn config(value: Value) -> Config {
        Config::from_json(value.to_string().as_bytes()).unwrap_or_else(|err| unreachable!("{err}"))
    }

    fn attrs(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn caller(config: &Config, items: &[&str]) -> Caller {
        Caller::new(config, attrs(items))
    }

    fn pinned(class: Class) -> Lookup {
        Lookup::Catalog(CatalogView {
            pin: Some(Pin {
                class,
                source: Source::Annotations,
            }),
            stale: false,
        })
    }

    fn stale(class: Class) -> Lookup {
        Lookup::Catalog(CatalogView {
            pin: Some(Pin {
                class,
                source: Source::Annotations,
            }),
            stale: true,
        })
    }

    const UNKNOWN: Lookup = Lookup::Catalog(CatalogView {
        pin: None,
        stale: false,
    });

    fn reason(decision: &CallDecision) -> Option<Reason> {
        match decision {
            CallDecision::Allow { .. } => None,
            CallDecision::Deny(refusal) => Some(refusal.reason),
        }
    }

    // --- attributes and level ---------------------------------------------------------

    #[test]
    fn attribute_normalisation() {
        assert_eq!(
            normalize_attributes(Some(&json!("admin")), None),
            attrs(&["admin"])
        );
        assert_eq!(
            normalize_attributes(Some(&json!("mcp.read  mcp.write")), Some(" ")),
            attrs(&["mcp.read", "mcp.write"]),
            "empty pieces are dropped"
        );
        assert_eq!(
            normalize_attributes(Some(&json!("a, b")), Some(",")),
            attrs(&["a", " b"]),
            "pieces are not trimmed"
        );
        assert_eq!(
            normalize_attributes(Some(&json!("a b")), None),
            attrs(&["a b"]),
            "no separator, no split"
        );
        assert_eq!(
            normalize_attributes(Some(&json!(["x", 1, null, "y", "", {"z": 1}])), Some(",")),
            attrs(&["x", "y"]),
            "arrays keep their string elements, unsplit"
        );
        for other in [
            json!(null),
            json!(5),
            json!({"roles": ["x"]}),
            json!(true),
            json!(""),
        ] {
            assert!(
                normalize_attributes(Some(&other), None).is_empty(),
                "{other}"
            );
        }
        assert!(
            normalize_attributes(None, None).is_empty(),
            "unset or evaluation error"
        );
    }

    #[test]
    fn caller_level_is_the_max_of_default_and_matching_grants() {
        let c = config(json!({
            "defaultLevel": "read",
            "grants": [
                {"attribute": "writer", "level": "write"},
                {"attribute": "admin", "level": "destructive"},
                {"attribute": "viewer", "level": "read"}
            ]
        }));
        assert_eq!(caller(&c, &[]).level, Level::Read);
        assert_eq!(caller(&c, &["viewer"]).level, Level::Read);
        assert_eq!(caller(&c, &["writer"]).level, Level::Write);
        assert_eq!(caller(&c, &["writer", "admin"]).level, Level::Destructive);
        assert_eq!(
            caller(&c, &["Admin", "admin "]).level,
            Level::Read,
            "exact, case-sensitive"
        );

        let none = config(
            json!({"defaultLevel": "none", "grants": [{"attribute": "app-1", "level": "read"}]}),
        );
        assert_eq!(caller(&none, &[]).level, Level::None);
        assert_eq!(caller(&none, &["app-1"]).level, Level::Read);
    }

    #[test]
    fn grants_providing_a_class() {
        let c = config(json!({
            "grants": [
                {"attribute": "writer", "level": "write"},
                {"attribute": "admin", "level": "destructive"},
                {"attribute": "writer", "level": "write"}
            ]
        }));
        assert_eq!(grants_providing(&c, Class::Write), vec!["writer", "admin"]);
        assert_eq!(grants_providing(&c, Class::Destructive), vec!["admin"]);
    }

    // --- tools/call -------------------------------------------------------------------

    #[test]
    fn level_check() {
        let c = config(json!({"grants": [{"attribute": "writer", "level": "write"}]}));
        let reader = caller(&c, &[]);
        let writer = caller(&c, &["writer"]);
        assert!(decide_call("t", &c, &reader, pinned(Class::Read)).is_allowed());
        assert_eq!(
            decide_call("t", &c, &reader, pinned(Class::Write)),
            CallDecision::Deny(Refusal {
                reason: Reason::LevelInsufficient,
                tool: "t".into(),
                caller_level: Level::Read,
                class: Some(Class::Write),
            })
        );
        assert!(decide_call("t", &c, &writer, pinned(Class::Write)).is_allowed());
        assert_eq!(
            reason(&decide_call("t", &c, &writer, pinned(Class::Destructive))),
            Some(Reason::LevelInsufficient)
        );
        let nobody = config(json!({"defaultLevel": "none"}));
        assert_eq!(
            reason(&decide_call(
                "t",
                &nobody,
                &caller(&nobody, &[]),
                pinned(Class::Read)
            )),
            Some(Reason::LevelInsufficient),
            "level none allows nothing"
        );
    }

    #[test]
    fn blocked_beats_everything_and_overrides_beat_pins() {
        let c = config(json!({
            "defaultLevel": "destructive",
            "blockedTools": ["drop"],
            "toolOverrides": [{"name": "search", "class": "read"}, {"name": "send", "class": "destructive"}]
        }));
        let admin = caller(&c, &[]);
        assert_eq!(
            reason(&decide_call("drop", &c, &admin, pinned(Class::Read))),
            Some(Reason::ToolBlocked)
        );
        assert_eq!(
            decide_call("search", &c, &admin, pinned(Class::Destructive)),
            CallDecision::Allow {
                class: Class::Read,
                basis: Basis::Override
            },
            "an override lowers a pin"
        );
        let c2 = config(json!({"toolOverrides": [{"name": "send", "class": "destructive"}]}));
        let reader = caller(&c2, &[]);
        assert_eq!(
            reason(&decide_call("send", &c2, &reader, pinned(Class::Read))),
            Some(Reason::LevelInsufficient),
            "an override raises a pin"
        );
    }

    #[test]
    fn unknown_tools_follow_on_unknown_tool() {
        let deny = config(json!({"defaultLevel": "destructive"}));
        assert_eq!(
            reason(&decide_call("new", &deny, &caller(&deny, &[]), UNKNOWN)),
            Some(Reason::UnknownTool)
        );

        let by_name = config(json!({
            "onUnknownTool": "classifyByName",
            "nameRules": [{"pattern": "^get_", "class": "read"}]
        }));
        let reader = caller(&by_name, &[]);
        assert_eq!(
            decide_call("get_user", &by_name, &reader, UNKNOWN),
            CallDecision::Allow {
                class: Class::Read,
                basis: Basis::ByName(Source::NameRule)
            }
        );
        assert_eq!(
            reason(&decide_call("set_user", &by_name, &reader, UNKNOWN)),
            Some(Reason::LevelInsufficient),
            "no rule: unannotatedAs (destructive)"
        );
    }

    #[test]
    fn a_stale_catalog_makes_pinned_tools_unknown_but_not_overrides() {
        let c = config(json!({"toolOverrides": [{"name": "search", "class": "read"}]}));
        let reader = caller(&c, &[]);
        assert_eq!(
            reason(&decide_call("t", &c, &reader, stale(Class::Read))),
            Some(Reason::UnknownTool)
        );
        assert!(decide_call("search", &c, &reader, stale(Class::Destructive)).is_allowed());

        let by_name = config(
            json!({"onUnknownTool": "classifyByName", "nameRules": [{"pattern": ".", "class": "read"}]}),
        );
        assert_eq!(
            decide_call(
                "t",
                &by_name,
                &caller(&by_name, &[]),
                stale(Class::Destructive)
            ),
            CallDecision::Allow {
                class: Class::Read,
                basis: Basis::ByName(Source::NameRule)
            },
            "while stale, the pin is ignored (classifyByName applies)"
        );
    }

    #[test]
    fn an_unavailable_partition_refuses_every_call() {
        let c = config(json!({
            "defaultLevel": "destructive",
            "catalogPartition": "#[authentication.properties.claims.tid]",
            "toolOverrides": [{"name": "search", "class": "read"}],
            "blockedTools": ["drop"]
        }));
        let admin = caller(&c, &[]);
        for name in ["search", "drop", "other"] {
            assert_eq!(
                reason(&decide_call(name, &c, &admin, Lookup::PartitionUnavailable)),
                Some(Reason::PartitionUnavailable),
                "{name}"
            );
        }
    }

    #[test]
    fn look_alike_names_are_unknown() {
        let c = config(json!({"defaultLevel": "destructive"}));
        let admin = caller(&c, &[]);
        // Only "search" is pinned; variants are looked up under their own name.
        let lookup = |name: &str| {
            if name == "search" {
                pinned(Class::Read)
            } else {
                UNKNOWN
            }
        };
        for name in ["Search", "search\u{200B}", "search "] {
            assert_eq!(
                reason(&decide_call(name, &c, &admin, lookup(name))),
                Some(Reason::UnknownTool),
                "{name:?}"
            );
        }
    }

    #[test]
    fn batch_elements_are_decided_individually() {
        let c = config(json!({}));
        let reader = caller(&c, &[]);
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"drop"}},
            {"jsonrpc":"2.0","id":3,"method":"resources/read","params":{}},
            {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}}
        ]"#;
        let limits = EnvelopeLimits {
            max_batch_size: 10,
            max_tool_name_bytes: 128,
        };
        let requests = match inspect_request(body, Some("2025-03-26"), limits) {
            Ok(Routing::Decide {
                batch: true,
                requests,
            }) => requests,
            other => unreachable!("{other:?}"),
        };
        let decisions = decide_requests(&requests, &c, &reader, |name| {
            if name == "search" {
                pinned(Class::Read)
            } else {
                pinned(Class::Destructive)
            }
        });
        let refused: Vec<bool> = decisions.iter().map(|(_, d)| d.is_refused()).collect();
        assert_eq!(refused, vec![false, true, false, true]);
        assert_eq!(
            decisions.get(2).map(|(_, d)| d),
            Some(&ElementDecision::NotACall)
        );
        assert_eq!(
            decisions.get(3).map(|(_, d)| d),
            Some(&ElementDecision::InvalidParams(
                ParamsDetail::MissingToolName
            ))
        );
        assert_eq!(decisions.first().map(|(id, _)| id.raw()), Some("1"));
    }

    // --- tools/list ---------------------------------------------------------------------

    #[test]
    fn list_entries_follow_the_call_decision() {
        let c = config(json!({
            "blockedTools": ["drop"],
            "toolOverrides": [{"name": "send", "class": "read"}],
            "grants": [{"attribute": "writer", "level": "write"}]
        }));
        let reader = caller(&c, &[]);
        let writer = caller(&c, &["writer"]);
        let view = |class| CatalogView {
            pin: Some(Pin {
                class,
                source: Source::Annotations,
            }),
            stale: false,
        };
        assert!(list_entry_visible("search", &c, &reader, view(Class::Read)));
        assert!(!list_entry_visible("edit", &c, &reader, view(Class::Write)));
        assert!(list_entry_visible("edit", &c, &writer, view(Class::Write)));
        assert!(
            !list_entry_visible("drop", &c, &writer, view(Class::Read)),
            "blocked is always hidden"
        );
        assert!(
            list_entry_visible("send", &c, &reader, view(Class::Destructive)),
            "override applies"
        );
        let unpinned = CatalogView {
            pin: None,
            stale: false,
        };
        assert!(
            !list_entry_visible("full", &c, &writer, unpinned),
            "not pinned (capacity) is hidden"
        );

        let by_name = config(
            json!({"onUnknownTool": "classifyByName", "nameRules": [{"pattern": "^get", "class": "read"}]}),
        );
        assert!(list_entry_visible(
            "get_x",
            &by_name,
            &caller(&by_name, &[]),
            unpinned
        ));
    }

    #[test]
    fn an_unavailable_partition_empties_lists_without_learning() {
        let enforce = config(json!({"catalogPartition": "#[vars.tenant]"}));
        let audit = config(json!({"catalogPartition": "#[vars.tenant]", "mode": "audit"}));
        let unfiltered =
            config(json!({"catalogPartition": "#[vars.tenant]", "filterToolsList": false}));
        assert_eq!(list_handling(&enforce, true), ListHandling::Learn);
        assert_eq!(list_handling(&audit, true), ListHandling::Learn);
        assert_eq!(list_handling(&enforce, false), ListHandling::Empty);
        assert_eq!(
            list_handling(&audit, false),
            ListHandling::ForwardWithoutLearning
        );
        assert_eq!(
            list_handling(&unfiltered, false),
            ListHandling::ForwardWithoutLearning
        );
    }

    #[test]
    fn filtering_is_off_in_audit_mode_or_when_disabled() {
        assert!(filtering_active(&config(json!({}))));
        assert!(!filtering_active(&config(
            json!({"filterToolsList": false})
        )));
        assert!(!filtering_active(&config(json!({"mode": "audit"}))));
    }

    #[test]
    fn audit_mode_forwards_and_reports() {
        let enforce = config(json!({}));
        let audit = config(json!({"mode": "audit"}));
        assert_eq!(action_for(&enforce, false), Action::Forward);
        assert_eq!(action_for(&enforce, true), Action::Refuse);
        assert_eq!(action_for(&audit, false), Action::Forward);
        assert_eq!(action_for(&audit, true), Action::ForwardWouldDeny);
    }
}
