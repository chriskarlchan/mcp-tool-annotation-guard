// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Configuration model and validation.
//!
//! [`Config::from_json`] reads the policy configuration JSON (the shape of
//! `definition/gcl.yaml`) and validates it. Every problem is reported
//! at once, so an administrator can fix them in one pass.
//!
//! The two DataWeave expressions (`callerAttributes`, `catalogPartition`) are
//! evaluated by the policy crate; this crate only records whether
//! `catalogPartition` is set, because that changes behaviour.
//!
//! Design choice: an empty
//! `callerAttributeSeparator` or `denial.hint` is treated as unset.

use std::collections::{HashMap, HashSet};
use std::fmt;

use regex::Regex;
use serde::de::{self, Deserializer};
use serde::Deserialize;

use crate::envelope::EnvelopeLimits;

/// A caller's access level. Ordered: `None < Read < Write < Destructive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    None,
    Read,
    Write,
    Destructive,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::None => "none",
            Level::Read => "read",
            Level::Write => "write",
            Level::Destructive => "destructive",
        }
    }
}

/// A tool's class. Ordered: `Read < Write < Destructive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Read,
    Write,
    Destructive,
}

impl Class {
    /// The lowest caller level that may use a tool of this class.
    pub fn level(self) -> Level {
        match self {
            Class::Read => Level::Read,
            Class::Write => Level::Write,
            Class::Destructive => Level::Destructive,
        }
    }

    pub fn as_str(self) -> &'static str {
        self.level().as_str()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Enforce,
    Audit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OnUnknownTool {
    Deny,
    ClassifyByName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DenialStyle {
    JsonRpcError,
    ToolResultError,
}

/// `grants[]`: callers whose attributes contain `attribute` get at least `level`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub attribute: String,
    pub level: Level,
}

/// One compiled `nameRules[]` entry.
#[derive(Clone, Debug)]
pub struct NameRule {
    pub pattern: String,
    pub regex: Regex,
    pub class: Class,
}

/// The classification-relevant settings (they form the catalog fingerprint).
#[derive(Clone, Debug)]
pub struct Classification {
    pub unannotated_as: Class,
    pub strict_contradictions: bool,
    pub name_rules: Vec<NameRule>,
}

impl Classification {
    /// The class of the first name rule matching `name`, if any.
    pub fn name_rule_class(&self, name: &str) -> Option<Class> {
        self.name_rules
            .iter()
            .find(|rule| rule.regex.is_match(name))
            .map(|rule| rule.class)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denial {
    pub style: DenialStyle,
    pub error_code: i64,
    pub http_status: u16,
    pub include_required_level: bool,
    pub reveal_grant_names: bool,
    pub hint: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_request_body_bytes: usize,
    pub max_list_response_bytes: usize,
    pub max_tool_name_bytes: usize,
    pub max_batch_size: usize,
    pub max_cached_tools: usize,
    pub max_catalog_bytes: usize,
    pub max_catalogs: usize,
}

impl Limits {
    pub fn envelope(&self) -> EnvelopeLimits {
        EnvelopeLimits {
            max_batch_size: self.max_batch_size,
            max_tool_name_bytes: self.max_tool_name_bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Logging {
    pub log_allowed_calls: bool,
    pub log_caller_attributes: bool,
}

/// A validated configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub mode: Mode,
    pub default_level: Level,
    /// `true` when `callerAttributes` is configured (evaluated by the policy crate).
    pub has_caller_attributes: bool,
    pub caller_attribute_separator: Option<String>,
    pub grants: Vec<Grant>,
    /// `true` when `catalogPartition` is configured: it then fails closed.
    pub has_catalog_partition: bool,
    pub classification: Classification,
    pub tool_overrides: HashMap<String, Class>,
    pub blocked_tools: HashSet<String>,
    pub on_unknown_tool: OnUnknownTool,
    pub filter_tools_list: bool,
    pub catalog_max_age_seconds: u64,
    pub denial: Denial,
    pub limits: Limits,
    pub logging: Logging,
}

/// Why a configuration was rejected. `Display` lists every problem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub problems: Vec<String>,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid mcp-tool-annotation-guard configuration: {}",
            self.problems.join("; ")
        )
    }
}

impl std::error::Error for ConfigError {}

/// Standard JSON-RPC error codes, never allowed for `denial.errorCode`.
const STANDARD_CODES: [i64; 5] = [-32700, -32600, -32601, -32602, -32603];
/// Longest `denial.hint`, in characters.
const MAX_HINT_CHARS: usize = 512;

impl Config {
    /// Parses and validates the policy configuration JSON.
    pub fn from_json(bytes: &[u8]) -> Result<Config, ConfigError> {
        let raw: RawConfig = serde_json::from_slice(bytes).map_err(|err| ConfigError {
            problems: vec![err.to_string()],
        })?;
        raw.validate()
    }

    /// One line with the configured limits, logged at startup so operators can
    /// compare them with the gateway buffer limit.
    pub fn limits_summary(&self) -> String {
        let l = &self.limits;
        format!(
            "maxRequestBodyBytes={} maxListResponseBytes={} maxToolNameBytes={} maxBatchSize={} \
             maxCachedTools={} maxCatalogBytes={} maxCatalogs={}",
            l.max_request_body_bytes,
            l.max_list_response_bytes,
            l.max_tool_name_bytes,
            l.max_batch_size,
            l.max_cached_tools,
            l.max_catalog_bytes,
            l.max_catalogs
        )
    }
}

// --- raw JSON shape -----------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RawConfig {
    mode: Mode,
    default_level: Level,
    caller_attributes: Option<de::IgnoredAny>,
    caller_attribute_separator: Option<String>,
    grants: Vec<RawGrant>,
    catalog_partition: Option<de::IgnoredAny>,
    unannotated_as: Class,
    strict_contradictions: bool,
    name_rules: Vec<RawNameRule>,
    tool_overrides: Vec<RawToolOverride>,
    blocked_tools: Vec<String>,
    on_unknown_tool: OnUnknownTool,
    filter_tools_list: bool,
    catalog: RawCatalog,
    denial: RawDenial,
    limits: RawLimits,
    logging: RawLogging,
}

impl Default for RawConfig {
    fn default() -> Self {
        RawConfig {
            mode: Mode::Enforce,
            default_level: Level::Read,
            caller_attributes: None,
            caller_attribute_separator: None,
            grants: Vec::new(),
            catalog_partition: None,
            unannotated_as: Class::Destructive,
            strict_contradictions: false,
            name_rules: Vec::new(),
            tool_overrides: Vec::new(),
            blocked_tools: Vec::new(),
            on_unknown_tool: OnUnknownTool::Deny,
            filter_tools_list: true,
            catalog: RawCatalog::default(),
            denial: RawDenial::default(),
            limits: RawLimits::default(),
            logging: RawLogging::default(),
        }
    }
}

#[derive(Deserialize)]
struct RawGrant {
    attribute: String,
    level: Class,
}

#[derive(Deserialize)]
struct RawNameRule {
    pattern: String,
    class: Class,
}

#[derive(Deserialize)]
struct RawToolOverride {
    name: String,
    class: Class,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RawCatalog {
    max_age_seconds: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RawDenial {
    style: DenialStyle,
    error_code: i64,
    #[serde(deserialize_with = "status_code")]
    http_status: u16,
    include_required_level: bool,
    reveal_grant_names: bool,
    hint: Option<String>,
}

impl Default for RawDenial {
    fn default() -> Self {
        RawDenial {
            style: DenialStyle::JsonRpcError,
            error_code: -32008,
            http_status: 200,
            include_required_level: true,
            reveal_grant_names: false,
            hint: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RawLimits {
    max_request_body_bytes: u64,
    max_list_response_bytes: u64,
    max_tool_name_bytes: u64,
    max_batch_size: u64,
    max_cached_tools: u64,
    max_catalog_bytes: u64,
    max_catalogs: u64,
}

impl Default for RawLimits {
    fn default() -> Self {
        RawLimits {
            max_request_body_bytes: 1_048_576,
            max_list_response_bytes: 1_048_576,
            max_tool_name_bytes: 256,
            max_batch_size: 32,
            max_cached_tools: 5000,
            max_catalog_bytes: 524_288,
            max_catalogs: 1000,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RawLogging {
    log_allowed_calls: bool,
    log_caller_attributes: bool,
}

/// `denial.httpStatus` is an enum of `200` and `403`; accept it as a number
/// or as a string, since schema tools render enums either way.
fn status_code<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumberOrString {
        Number(u64),
        String(String),
    }
    let value = match NumberOrString::deserialize(deserializer)? {
        NumberOrString::Number(n) => n,
        NumberOrString::String(s) => s.parse().map_err(|_| {
            de::Error::custom(format!("denial.httpStatus must be 200 or 403, got \"{s}\""))
        })?,
    };
    match value {
        200 => Ok(200),
        403 => Ok(403),
        other => Err(de::Error::custom(format!(
            "denial.httpStatus must be 200 or 403, got {other}"
        ))),
    }
}

// --- validation ---------------------------------------------------------------

/// Collects problems and returns a value within range (or a placeholder).
struct Problems(Vec<String>);

impl Problems {
    fn range(&mut self, field: &str, value: u64, min: u64, max: Option<u64>) -> usize {
        let too_big = max.is_some_and(|max| value > max);
        if value < min || too_big {
            let range = match max {
                Some(max) => format!("{min}–{max}"),
                None => format!("≥ {min}"),
            };
            self.0.push(format!("{field} must be {range}, got {value}"));
        }
        usize::try_from(value).unwrap_or(usize::MAX)
    }
}

fn error_code_allowed(code: i64) -> bool {
    if STANDARD_CODES.contains(&code) {
        return false;
    }
    (-32099..=-32000).contains(&code) || !(-32768..=-32000).contains(&code)
}

impl RawConfig {
    fn validate(self) -> Result<Config, ConfigError> {
        let mut problems = Problems(Vec::new());

        let mut name_rules = Vec::with_capacity(self.name_rules.len());
        for (index, rule) in self.name_rules.into_iter().enumerate() {
            match Regex::new(&rule.pattern) {
                Ok(regex) => name_rules.push(NameRule {
                    pattern: rule.pattern,
                    regex,
                    class: rule.class,
                }),
                Err(err) => problems.0.push(format!(
                    "nameRules[{index}].pattern {:?} is not a valid regular expression: {err}",
                    rule.pattern
                )),
            }
        }

        let blocked_tools: HashSet<String> = self.blocked_tools.into_iter().collect();
        let mut tool_overrides = HashMap::with_capacity(self.tool_overrides.len());
        for entry in self.tool_overrides {
            if blocked_tools.contains(&entry.name) {
                problems.0.push(format!(
                    "tool {:?} is in both blockedTools and toolOverrides",
                    entry.name
                ));
            }
            if tool_overrides
                .insert(entry.name.clone(), entry.class)
                .is_some()
            {
                problems.0.push(format!(
                    "toolOverrides lists {:?} more than once",
                    entry.name
                ));
            }
        }

        let d = self.denial;
        if !error_code_allowed(d.error_code) {
            problems.0.push(format!(
                "denial.errorCode {} is reserved by JSON-RPC: use -32099…-32000 (not a standard code) \
                 or a value outside -32768…-32000",
                d.error_code
            ));
        }
        let hint = d.hint.filter(|h| !h.is_empty());
        if let Some(h) = &hint {
            let chars = h.chars().count();
            if chars > MAX_HINT_CHARS {
                problems.0.push(format!(
                    "denial.hint must be at most {MAX_HINT_CHARS} characters, got {chars}"
                ));
            }
        }

        let l = self.limits;
        let limits = Limits {
            max_request_body_bytes: problems.range(
                "limits.maxRequestBodyBytes",
                l.max_request_body_bytes,
                1024,
                None,
            ),
            max_list_response_bytes: problems.range(
                "limits.maxListResponseBytes",
                l.max_list_response_bytes,
                1024,
                None,
            ),
            max_tool_name_bytes: problems.range(
                "limits.maxToolNameBytes",
                l.max_tool_name_bytes,
                1,
                Some(1024),
            ),
            max_batch_size: problems.range("limits.maxBatchSize", l.max_batch_size, 1, Some(256)),
            max_cached_tools: problems.range("limits.maxCachedTools", l.max_cached_tools, 1, None),
            max_catalog_bytes: problems.range(
                "limits.maxCatalogBytes",
                l.max_catalog_bytes,
                4096,
                None,
            ),
            max_catalogs: problems.range("limits.maxCatalogs", l.max_catalogs, 1, None),
        };

        if !problems.0.is_empty() {
            return Err(ConfigError {
                problems: problems.0,
            });
        }

        Ok(Config {
            mode: self.mode,
            default_level: self.default_level,
            has_caller_attributes: self.caller_attributes.is_some(),
            caller_attribute_separator: self.caller_attribute_separator.filter(|s| !s.is_empty()),
            grants: self
                .grants
                .into_iter()
                .map(|g| Grant {
                    attribute: g.attribute,
                    level: g.level.level(),
                })
                .collect(),
            has_catalog_partition: self.catalog_partition.is_some(),
            classification: Classification {
                unannotated_as: self.unannotated_as,
                strict_contradictions: self.strict_contradictions,
                name_rules,
            },
            tool_overrides,
            blocked_tools,
            on_unknown_tool: self.on_unknown_tool,
            filter_tools_list: self.filter_tools_list,
            catalog_max_age_seconds: self.catalog.max_age_seconds,
            denial: Denial {
                style: d.style,
                error_code: d.error_code,
                http_status: d.http_status,
                include_required_level: d.include_required_level,
                reveal_grant_names: d.reveal_grant_names,
                hint,
            },
            limits,
            logging: Logging {
                log_allowed_calls: self.logging.log_allowed_calls,
                log_caller_attributes: self.logging.log_caller_attributes,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(value: serde_json::Value) -> Result<Config, ConfigError> {
        Config::from_json(value.to_string().as_bytes())
    }

    fn ok(value: serde_json::Value) -> Config {
        parse(value).unwrap_or_else(|err| unreachable!("config should be valid: {err}"))
    }

    fn problems(value: serde_json::Value) -> Vec<String> {
        match parse(value) {
            Err(err) => err.problems,
            Ok(_) => unreachable!("config should be invalid"),
        }
    }

    fn has_problem(value: serde_json::Value, needle: &str) {
        let found = problems(value);
        assert!(
            found.iter().any(|p| p.contains(needle)),
            "{needle:?} not in {found:?}"
        );
    }

    #[test]
    fn empty_object_gives_the_documented_defaults() {
        let c = ok(json!({}));
        assert_eq!(c.mode, Mode::Enforce);
        assert_eq!(c.default_level, Level::Read);
        assert!(!c.has_caller_attributes);
        assert_eq!(c.caller_attribute_separator, None);
        assert!(c.grants.is_empty());
        assert!(!c.has_catalog_partition);
        assert_eq!(c.classification.unannotated_as, Class::Destructive);
        assert!(!c.classification.strict_contradictions);
        assert!(c.classification.name_rules.is_empty());
        assert!(c.tool_overrides.is_empty());
        assert!(c.blocked_tools.is_empty());
        assert_eq!(c.on_unknown_tool, OnUnknownTool::Deny);
        assert!(c.filter_tools_list);
        assert_eq!(c.catalog_max_age_seconds, 0);
        assert_eq!(
            c.denial,
            Denial {
                style: DenialStyle::JsonRpcError,
                error_code: -32008,
                http_status: 200,
                include_required_level: true,
                reveal_grant_names: false,
                hint: None,
            }
        );
        assert_eq!(
            c.limits,
            Limits {
                max_request_body_bytes: 1_048_576,
                max_list_response_bytes: 1_048_576,
                max_tool_name_bytes: 256,
                max_batch_size: 32,
                max_cached_tools: 5000,
                max_catalog_bytes: 524_288,
                max_catalogs: 1000,
            }
        );
        assert_eq!(
            c.logging,
            Logging {
                log_allowed_calls: false,
                log_caller_attributes: false
            }
        );
    }

    #[test]
    fn levels_and_classes_are_ordered() {
        assert!(
            Level::None < Level::Read
                && Level::Read < Level::Write
                && Level::Write < Level::Destructive
        );
        assert!(Class::Read < Class::Write && Class::Write < Class::Destructive);
        assert_eq!(Class::Write.level(), Level::Write);
    }

    #[test]
    fn example_b_entra_roles() {
        let c = ok(json!({
            "callerAttributes": "#[authentication.properties.claims.roles]",
            "defaultLevel": "read",
            "grants": [
                {"attribute": "mcp.editor", "level": "write"},
                {"attribute": "mcp.admin", "level": "destructive"}
            ],
            "blockedTools": ["delete_repository"]
        }));
        assert!(c.has_caller_attributes);
        assert_eq!(
            c.grants,
            vec![
                Grant {
                    attribute: "mcp.editor".into(),
                    level: Level::Write
                },
                Grant {
                    attribute: "mcp.admin".into(),
                    level: Level::Destructive
                },
            ]
        );
        assert!(c.blocked_tools.contains("delete_repository"));
    }

    #[test]
    fn example_c_client_application() {
        let c = ok(json!({
            "callerAttributes": "#[authentication.clientId]",
            "defaultLevel": "none",
            "grants": [
                {"attribute": "3f2a9c-support-bot", "level": "read"},
                {"attribute": "81bd07-release-agent", "level": "destructive"}
            ]
        }));
        assert_eq!(c.default_level, Level::None);
    }

    #[test]
    fn example_d_name_rules() {
        let c = ok(json!({
            "nameRules": [{"pattern": "^get_", "class": "read"}],
            "unannotatedAs": "destructive",
            "onUnknownTool": "classifyByName"
        }));
        assert_eq!(c.on_unknown_tool, OnUnknownTool::ClassifyByName);
        // Names observed on a live MCP Bridge.
        assert_eq!(
            c.classification.name_rule_class("get_issues"),
            Some(Class::Read)
        );
        assert_eq!(
            c.classification.name_rule_class("get_orders_id"),
            Some(Class::Read)
        );
        for name in [
            "post_issues",
            "put_issues_id",
            "patch_issues_id",
            "delete_branches_name",
        ] {
            assert_eq!(c.classification.name_rule_class(name), None, "{name}");
        }
        // Anchored: a write whose path starts with /get is not read.
        assert_eq!(c.classification.name_rule_class("post_get_status"), None);
    }

    #[test]
    fn example_e_audit_with_scopes() {
        let c = ok(json!({
            "mode": "audit",
            "callerAttributes": "#[authentication.properties.claims.scope]",
            "callerAttributeSeparator": " ",
            "grants": [
                {"attribute": "tools:write", "level": "write"},
                {"attribute": "tools:delete", "level": "destructive"}
            ]
        }));
        assert_eq!(c.mode, Mode::Audit);
        assert_eq!(c.caller_attribute_separator.as_deref(), Some(" "));
    }

    #[test]
    fn example_g_partition() {
        let c = ok(json!({
            "catalogPartition": "#[authentication.properties.claims.tid]",
            "callerAttributes": "#[authentication.properties.claims.roles]",
            "grants": [{"attribute": "mcp.admin", "level": "destructive"}]
        }));
        assert!(c.has_catalog_partition);
    }

    #[test]
    fn nested_settings_are_read() {
        let c = ok(json!({
            "strictContradictions": true,
            "toolOverrides": [{"name": "search", "class": "read"}],
            "filterToolsList": false,
            "catalog": {"maxAgeSeconds": 600},
            "denial": {
                "style": "toolResultError",
                "errorCode": -32001,
                "httpStatus": 403,
                "includeRequiredLevel": false,
                "revealGrantNames": true,
                "hint": "Ask #mcp-help."
            },
            "limits": {
                "maxRequestBodyBytes": 2048,
                "maxListResponseBytes": 4096,
                "maxToolNameBytes": 64,
                "maxBatchSize": 8,
                "maxCachedTools": 10,
                "maxCatalogBytes": 8192,
                "maxCatalogs": 5
            },
            "logging": {"logAllowedCalls": true, "logCallerAttributes": true}
        }));
        assert!(c.classification.strict_contradictions);
        assert_eq!(c.tool_overrides.get("search"), Some(&Class::Read));
        assert!(!c.filter_tools_list);
        assert_eq!(c.catalog_max_age_seconds, 600);
        assert_eq!(c.denial.style, DenialStyle::ToolResultError);
        assert_eq!(c.denial.error_code, -32001);
        assert_eq!(c.denial.http_status, 403);
        assert!(!c.denial.include_required_level);
        assert!(c.denial.reveal_grant_names);
        assert_eq!(c.denial.hint.as_deref(), Some("Ask #mcp-help."));
        assert_eq!(c.limits.max_batch_size, 8);
        assert_eq!(
            c.limits.envelope(),
            EnvelopeLimits {
                max_batch_size: 8,
                max_tool_name_bytes: 64
            }
        );
        assert!(c.logging.log_allowed_calls && c.logging.log_caller_attributes);
        assert!(c.limits_summary().contains("maxBatchSize=8"));
    }

    #[test]
    fn empty_separator_and_hint_mean_unset() {
        let c = ok(json!({"callerAttributeSeparator": "", "denial": {"hint": ""}}));
        assert_eq!(c.caller_attribute_separator, None);
        assert_eq!(c.denial.hint, None);
    }

    #[test]
    fn invalid_enum_values_are_rejected() {
        for config in [
            json!({"mode": "permissive"}),
            json!({"defaultLevel": "admin"}),
            json!({"unannotatedAs": "none"}),
            json!({"grants": [{"attribute": "x", "level": "none"}]}),
            json!({"nameRules": [{"pattern": "x", "class": "blocked"}]}),
            json!({"toolOverrides": [{"name": "x", "class": "Read"}]}),
            json!({"onUnknownTool": "refresh"}),
            json!({"denial": {"style": "html"}}),
        ] {
            assert!(parse(config.clone()).is_err(), "{config}");
        }
    }

    #[test]
    fn http_status_accepts_200_and_403_only() {
        assert_eq!(
            ok(json!({"denial": {"httpStatus": "403"}}))
                .denial
                .http_status,
            403
        );
        assert_eq!(
            ok(json!({"denial": {"httpStatus": 200}}))
                .denial
                .http_status,
            200
        );
        for status in [json!(404), json!("500"), json!("forbidden")] {
            assert!(
                parse(json!({"denial": {"httpStatus": status}})).is_err(),
                "{status}"
            );
        }
    }

    #[test]
    fn invalid_patterns_are_rejected_with_their_index() {
        has_problem(
            json!({"nameRules": [{"pattern": "ok", "class": "read"}, {"pattern": "(unclosed", "class": "read"}]}),
            "nameRules[1].pattern",
        );
    }

    #[test]
    fn tool_override_conflicts_are_rejected() {
        has_problem(
            json!({"toolOverrides": [{"name": "a", "class": "read"}, {"name": "a", "class": "write"}]}),
            "more than once",
        );
        has_problem(
            json!({"blockedTools": ["a"], "toolOverrides": [{"name": "a", "class": "read"}]}),
            "both blockedTools and toolOverrides",
        );
    }

    #[test]
    fn error_code_rules() {
        for allowed in [-32008, -32000, -32099, -32769, -40000, -31999, 0, 1, 42] {
            assert!(
                parse(json!({"denial": {"errorCode": allowed}})).is_ok(),
                "{allowed}"
            );
        }
        for rejected in [
            -32700, -32600, -32601, -32602, -32603, -32100, -32768, -32500,
        ] {
            has_problem(
                json!({"denial": {"errorCode": rejected}}),
                "denial.errorCode",
            );
        }
    }

    #[test]
    fn hint_length_counts_characters() {
        assert!(parse(json!({"denial": {"hint": "é".repeat(512)}})).is_ok());
        has_problem(json!({"denial": {"hint": "é".repeat(513)}}), "denial.hint");
    }

    #[test]
    fn limit_ranges_are_enforced() {
        for (field, low, high) in [
            ("maxRequestBodyBytes", 1023, None),
            ("maxListResponseBytes", 1023, None),
            ("maxToolNameBytes", 0, Some(1025)),
            ("maxBatchSize", 0, Some(257)),
            ("maxCachedTools", 0, None),
            ("maxCatalogBytes", 4095, None),
            ("maxCatalogs", 0, None),
        ] {
            has_problem(json!({"limits": {field: low}}), &format!("limits.{field}"));
            if let Some(high) = high {
                has_problem(json!({"limits": {field: high}}), &format!("limits.{field}"));
            }
        }
        for (field, edge) in [
            ("maxRequestBodyBytes", 1024),
            ("maxToolNameBytes", 1),
            ("maxToolNameBytes", 1024),
            ("maxBatchSize", 1),
            ("maxBatchSize", 256),
            ("maxCatalogBytes", 4096),
        ] {
            assert!(
                parse(json!({"limits": {field: edge}})).is_ok(),
                "{field}={edge}"
            );
        }
    }

    #[test]
    fn negative_numbers_and_wrong_types_are_rejected() {
        assert!(parse(json!({"catalog": {"maxAgeSeconds": -1}})).is_err());
        assert!(parse(json!({"limits": {"maxBatchSize": 1.5}})).is_err());
        assert!(parse(json!({"blockedTools": "a"})).is_err());
        assert!(parse(json!({"strictContradictions": "yes"})).is_err());
        assert!(Config::from_json(b"not json").is_err());
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let found = problems(json!({
            "nameRules": [{"pattern": "[", "class": "read"}],
            "denial": {"errorCode": -32600, "hint": "x".repeat(600)},
            "limits": {"maxBatchSize": 0}
        }));
        assert_eq!(found.len(), 4, "{found:?}");
        let message = ConfigError { problems: found }.to_string();
        assert!(message.starts_with("invalid mcp-tool-annotation-guard configuration: "));
    }
}
