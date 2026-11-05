// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Tool classification from overrides, annotations and name rules.
//!
//! Design choice: `annotations_malformed` is
//! reported for any of the four MCP hints (`readOnlyHint`, `destructiveHint`,
//! `idempotentHint`, `openWorldHint`) present with a non-boolean value; only
//! the first two affect the class.

use serde_json::{Map, Value};

use crate::config::{Class, Classification, Config};

/// Where a candidate class came from (logged as `source`, stored in the catalog).
/// Ordered only so that merging pins is deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    Annotations,
    NameRule,
    Default,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Annotations => "annotations",
            Source::NameRule => "nameRule",
            Source::Default => "default",
        }
    }
}

/// The result of the precedence rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// In `blockedTools`: denied to everyone, always hidden, never pinned.
    Blocked,
    /// In `toolOverrides`: applies exactly as configured, never pinned.
    Override(Class),
    /// A candidate for the pin.
    Candidate { class: Class, source: Source },
}

/// Something about the annotations worth logging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// `annotations_malformed` (warn): a hint with a non-boolean value.
    Malformed { field: &'static str },
    /// `annotations_contradictory` (info): `readOnlyHint` and `destructiveHint` both true.
    Contradictory,
}

/// A classified `tools/list` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classified {
    pub outcome: Outcome,
    pub notes: Vec<Note>,
    /// Logged with `tool_classified`; never used for the decision.
    pub idempotent_hint: Option<bool>,
    pub open_world_hint: Option<bool>,
}

const READ_ONLY_HINT: &str = "readOnlyHint";
const DESTRUCTIVE_HINT: &str = "destructiveHint";
const IDEMPOTENT_HINT: &str = "idempotentHint";
const OPEN_WORLD_HINT: &str = "openWorldHint";

/// Reads a hint: `Some(bool)` if present and boolean, `None` otherwise
/// (recording a note if present with another type).
fn hint(
    annotations: &Map<String, Value>,
    field: &'static str,
    notes: &mut Vec<Note>,
) -> Option<bool> {
    match annotations.get(field) {
        None => None,
        Some(Value::Bool(value)) => Some(*value),
        Some(_) => {
            notes.push(Note::Malformed { field });
            None
        }
    }
}

/// The annotation algorithm: hints to a class.
pub fn classify_annotations(
    annotations: &Map<String, Value>,
    strict_contradictions: bool,
) -> (Class, Vec<Note>) {
    let mut notes = Vec::new();
    let read_only = hint(annotations, READ_ONLY_HINT, &mut notes);
    let destructive = hint(annotations, DESTRUCTIVE_HINT, &mut notes);

    let class = if read_only == Some(true) {
        if destructive == Some(true) {
            notes.push(Note::Contradictory);
            if strict_contradictions {
                Class::Destructive
            } else {
                // MCP: destructiveHint is meaningless when the tool is read-only.
                Class::Read
            }
        } else {
            Class::Read
        }
    } else if destructive == Some(false) {
        Class::Write
    } else {
        // destructiveHint true or absent (MCP default true).
        Class::Destructive
    };
    (class, notes)
}

/// Classifies one `tools/list` entry by the precedence rules.
///
/// `annotations` is the entry's `annotations` member, if present. `name` must
/// already be validated.
pub fn classify_tool(name: &str, annotations: Option<&Value>, config: &Config) -> Classified {
    if config.blocked_tools.contains(name) {
        return plain(Outcome::Blocked);
    }
    if let Some(class) = config.tool_overrides.get(name) {
        return plain(Outcome::Override(*class));
    }
    let classification = &config.classification;
    if let Some(Value::Object(annotations)) = annotations {
        let (class, mut notes) =
            classify_annotations(annotations, classification.strict_contradictions);
        let idempotent_hint = hint(annotations, IDEMPOTENT_HINT, &mut notes);
        let open_world_hint = hint(annotations, OPEN_WORLD_HINT, &mut notes);
        return Classified {
            outcome: Outcome::Candidate {
                class,
                source: Source::Annotations,
            },
            notes,
            idempotent_hint,
            open_world_hint,
        };
    }
    let (class, source) = by_name(name, classification);
    plain(Outcome::Candidate { class, source })
}

/// The class of a tool with no usable annotations: the first matching name
/// rule, else `unannotatedAs` (also used by `onUnknownTool: classifyByName`).
pub fn by_name(name: &str, classification: &Classification) -> (Class, Source) {
    match classification.name_rule_class(name) {
        Some(class) => (class, Source::NameRule),
        None => (classification.unannotated_as, Source::Default),
    }
}

fn plain(outcome: Outcome) -> Classified {
    Classified {
        outcome,
        notes: Vec::new(),
        idempotent_hint: None,
        open_world_hint: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(value: Value) -> Config {
        Config::from_json(value.to_string().as_bytes()).unwrap_or_else(|err| unreachable!("{err}"))
    }

    fn annotations_class(annotations: Value, strict: bool) -> (Class, Vec<Note>) {
        match annotations {
            Value::Object(map) => classify_annotations(&map, strict),
            _ => unreachable!("test annotations must be an object"),
        }
    }

    fn candidate(class: Class, source: Source) -> Outcome {
        Outcome::Candidate { class, source }
    }

    #[test]
    fn annotation_table_from_section_6_3() {
        use Class::*;
        // (annotations, default class, strict class)
        let table = [
            (json!({"readOnlyHint": true}), Read, Read),
            (
                json!({"readOnlyHint": true, "destructiveHint": false}),
                Read,
                Read,
            ),
            (
                json!({"readOnlyHint": true, "destructiveHint": true}),
                Read,
                Destructive,
            ),
            (json!({"destructiveHint": false}), Write, Write),
            (
                json!({"readOnlyHint": false, "destructiveHint": false}),
                Write,
                Write,
            ),
            (
                json!({"readOnlyHint": false, "destructiveHint": true}),
                Destructive,
                Destructive,
            ),
            (json!({}), Destructive, Destructive),
            (json!({"readOnlyHint": "true"}), Destructive, Destructive),
        ];
        for (annotations, default_class, strict_class) in table {
            assert_eq!(
                annotations_class(annotations.clone(), false).0,
                default_class,
                "{annotations}"
            );
            assert_eq!(
                annotations_class(annotations.clone(), true).0,
                strict_class,
                "{annotations} strict"
            );
        }
    }

    #[test]
    fn contradiction_is_noted_in_both_modes() {
        let both = json!({"readOnlyHint": true, "destructiveHint": true});
        assert_eq!(
            annotations_class(both.clone(), false).1,
            vec![Note::Contradictory]
        );
        assert_eq!(annotations_class(both, true).1, vec![Note::Contradictory]);
        assert!(annotations_class(
            json!({"readOnlyHint": true, "destructiveHint": false}),
            false
        )
        .1
        .is_empty());
    }

    #[test]
    fn malformed_hints_are_noted_and_treated_as_absent() {
        let (class, notes) = annotations_class(
            json!({"readOnlyHint": 1, "destructiveHint": "false"}),
            false,
        );
        assert_eq!(class, Class::Destructive);
        assert_eq!(
            notes,
            vec![
                Note::Malformed {
                    field: "readOnlyHint"
                },
                Note::Malformed {
                    field: "destructiveHint"
                }
            ]
        );
        // A malformed readOnlyHint with an explicit destructiveHint false is write.
        assert_eq!(
            annotations_class(
                json!({"readOnlyHint": null, "destructiveHint": false}),
                false
            )
            .0,
            Class::Write
        );
    }

    #[test]
    fn other_hints_never_change_the_class() {
        let (class, _) = annotations_class(
            json!({"idempotentHint": true, "openWorldHint": false}),
            false,
        );
        assert_eq!(class, Class::Destructive);
        let (class, _) =
            annotations_class(json!({"readOnlyHint": true, "openWorldHint": true}), false);
        assert_eq!(class, Class::Read);
    }

    #[test]
    fn hint_names_are_case_sensitive() {
        assert_eq!(
            annotations_class(json!({"readonlyhint": true}), false).0,
            Class::Destructive
        );
    }

    #[test]
    fn precedence_blocked_then_override_then_annotations() {
        let c = config(json!({
            "blockedTools": ["drop"],
            "toolOverrides": [{"name": "search", "class": "write"}],
            "nameRules": [{"pattern": ".*", "class": "read"}]
        }));
        let read_only = json!({"readOnlyHint": true});
        assert_eq!(
            classify_tool("drop", Some(&read_only), &c).outcome,
            Outcome::Blocked
        );
        assert_eq!(
            classify_tool("search", Some(&read_only), &c).outcome,
            Outcome::Override(Class::Write)
        );
        assert_eq!(
            classify_tool("other", Some(&json!({})), &c).outcome,
            candidate(Class::Destructive, Source::Annotations),
            "real annotations (even empty) win over name rules"
        );
    }

    #[test]
    fn name_rules_apply_when_annotations_are_absent_null_or_not_an_object() {
        let c = config(json!({
            "nameRules": [
                {"pattern": "_get_", "class": "read"},
                {"pattern": "^api_", "class": "write"}
            ]
        }));
        for annotations in [
            None,
            Some(json!(null)),
            Some(json!("readOnly")),
            Some(json!([true])),
        ] {
            assert_eq!(
                classify_tool("api_get_users", annotations.as_ref(), &c).outcome,
                candidate(Class::Read, Source::NameRule),
                "first matching rule wins ({annotations:?})"
            );
        }
        assert_eq!(
            classify_tool("api_post_users", None, &c).outcome,
            candidate(Class::Write, Source::NameRule)
        );
        assert_eq!(
            classify_tool("x_get_y", None, &c).outcome,
            candidate(Class::Read, Source::NameRule),
            "patterns are unanchored unless they use ^ or $"
        );
    }

    #[test]
    fn default_is_unannotated_as() {
        assert_eq!(
            classify_tool("anything", None, &config(json!({}))).outcome,
            candidate(Class::Destructive, Source::Default)
        );
        assert_eq!(
            classify_tool("anything", None, &config(json!({"unannotatedAs": "write"}))).outcome,
            candidate(Class::Write, Source::Default)
        );
    }

    #[test]
    fn names_are_matched_exactly() {
        let c = config(
            json!({"blockedTools": ["drop"], "toolOverrides": [{"name": "search", "class": "read"}]}),
        );
        for look_alike in ["Drop", "drop ", "dr\u{200B}op"] {
            assert_ne!(
                classify_tool(look_alike, None, &c).outcome,
                Outcome::Blocked,
                "{look_alike:?}"
            );
        }
        assert_eq!(
            classify_tool("Search", None, &c).outcome,
            candidate(Class::Destructive, Source::Default)
        );
    }

    #[test]
    fn extra_hints_are_reported_for_logging() {
        let c = config(json!({}));
        let annotations =
            json!({"readOnlyHint": true, "idempotentHint": true, "openWorldHint": "yes"});
        let classified = classify_tool("t", Some(&annotations), &c);
        assert_eq!(
            classified.outcome,
            candidate(Class::Read, Source::Annotations)
        );
        assert_eq!(classified.idempotent_hint, Some(true));
        assert_eq!(classified.open_world_hint, None);
        assert_eq!(
            classified.notes,
            vec![Note::Malformed {
                field: "openWorldHint"
            }]
        );
    }

    #[test]
    fn by_name_is_used_for_unknown_tools() {
        let c = config(
            json!({"nameRules": [{"pattern": "^get", "class": "read"}], "unannotatedAs": "write"}),
        );
        assert_eq!(
            by_name("getUser", &c.classification),
            (Class::Read, Source::NameRule)
        );
        assert_eq!(
            by_name("setUser", &c.classification),
            (Class::Write, Source::Default)
        );
    }
}
