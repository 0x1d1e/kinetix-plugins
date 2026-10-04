//! Thinking translation contract for plugins.
//!
//! A plugin that owns reasoning behavior ships `thinking-contract.json` and
//! runs it through this module from its own tests. Two shapes exist:
//!
//! * Adapter contracts (`"kind": "adapter"`) drive the real `build_body` with a
//!   canonical `thinking.level` and pin the complete provider body, or the
//!   explicit rejection, for every canonical level on every model class.
//!   `"translation"` must equal the manifest's `provides.thinking_translation`.
//! * Model-source contracts (`"kind": "model_source"`) drive the plugin's real
//!   discovery normalization and pin the reasoning capability the host will
//!   consume. Such plugins cannot declare `thinking_translation`: the host
//!   builds the provider body from the capability, and the matching body
//!   goldens live in the host's `tests/fixtures/thinking-translation/`.
//!
//! `scripts/validate_manifests.py` requires a contract for every plugin that
//! provides a provider adapter or a model source and checks that the plugin's
//! sources actually run it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::Adapter;

const REQUEST_TEXT: &str = include_str!("../../wit/fixtures/plugin-adapter/v1/requests/text.json");

/// Every canonical level (`ThinkingLevel`) that can reach a plugin.
pub const CANONICAL_LEVELS: &[&str] = &[
    "off", "default", "minimal", "low", "medium", "high", "xhigh", "max",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterContract {
    schema_version: u32,
    #[serde(rename = "kind")]
    _kind: String,
    plugin: String,
    translation: bool,
    #[serde(default = "empty_object")]
    provider: Value,
    models: BTreeMap<String, Value>,
    cases: Vec<AdapterCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterCase {
    name: String,
    model: String,
    /// Canonical level, or `null` when the client sent no thinking intent.
    level: Option<String>,
    expect: Expect,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Expect {
    /// The complete provider-facing JSON body.
    Body(Value),
    /// Explicit rejection; the error contains this text.
    Rejected(String),
}

fn empty_object() -> Value {
    json!({})
}

/// Run an adapter contract against the plugin's real `build_body`.
pub fn check_thinking_contract(adapter: &impl Adapter, contract_json: &str) -> Result<(), String> {
    let contract: AdapterContract = serde_json::from_str(contract_json)
        .map_err(|error| format!("invalid thinking contract: {error}"))?;
    if contract.schema_version != 1 {
        return Err(format!(
            "{} thinking contract has unsupported schema_version {}",
            contract.plugin, contract.schema_version
        ));
    }
    if contract.models.is_empty() {
        return Err(format!(
            "{} thinking contract declares no models",
            contract.plugin
        ));
    }

    let mut seen_names = BTreeSet::new();
    let mut seen_pairs = BTreeSet::new();
    let mut accepted_levels = 0usize;
    for case in &contract.cases {
        if !seen_names.insert(case.name.as_str()) {
            return Err(format!("duplicate thinking case '{}'", case.name));
        }
        if !seen_pairs.insert((case.model.as_str(), case.level.as_deref())) {
            return Err(format!(
                "model '{}' pins level {:?} more than once",
                case.model, case.level
            ));
        }
        if let Some(level) = case.level.as_deref() {
            if !CANONICAL_LEVELS.contains(&level) {
                return Err(format!(
                    "case '{}' uses unknown canonical level '{level}'",
                    case.name
                ));
            }
        }
        let model = contract
            .models
            .get(&case.model)
            .ok_or_else(|| format!("case '{}' names unknown model '{}'", case.name, case.model))?;

        let mut request: Value = serde_json::from_str(REQUEST_TEXT)
            .map_err(|error| format!("shared text request fixture is invalid: {error}"))?;
        request["thinking"] = match case.level.as_deref() {
            Some(level) => json!({ "level": level }),
            None => Value::Null,
        };
        let outcome = adapter.build_body(&request, &contract.provider, model);
        match (&case.expect, outcome) {
            (Expect::Body(expected), Ok(actual)) => {
                if *expected != actual {
                    return Err(format!(
                        "{} / {}: provider body changed\nexpected: {}\nactual:   {}",
                        contract.plugin,
                        case.name,
                        serde_json::to_string_pretty(expected).unwrap_or_default(),
                        serde_json::to_string_pretty(&actual).unwrap_or_default(),
                    ));
                }
                if case.level.is_some() {
                    accepted_levels += 1;
                }
            }
            (Expect::Body(_), Err(error)) => {
                return Err(format!(
                    "{} / {}: expected a provider body but the adapter rejected it: {error}",
                    contract.plugin, case.name
                ));
            }
            (Expect::Rejected(needle), Err(error)) => {
                if needle.trim().is_empty() {
                    return Err(format!(
                        "{} / {}: rejection needs a message substring",
                        contract.plugin, case.name
                    ));
                }
                let lower = error.to_ascii_lowercase();
                if !error.contains(needle.as_str()) {
                    return Err(format!(
                        "{} / {}: rejection did not contain '{needle}'; got: {error}",
                        contract.plugin, case.name
                    ));
                }
                // A rejection must say the control is unsupported, never
                // look like an unrelated failure (bad JSON, auth, ...).
                if !lower.contains("unsupported") && !lower.contains("not support") {
                    return Err(format!(
                        "{} / {}: rejection must be explicit about unsupported thinking; got: {error}",
                        contract.plugin, case.name
                    ));
                }
            }
            (Expect::Rejected(_), Ok(actual)) => {
                return Err(format!(
                    "{} / {}: expected rejection but the adapter built a body: {actual}",
                    contract.plugin, case.name
                ));
            }
        }
    }

    // Matrix coverage: every model pins absent plus every canonical level.
    for model in contract.models.keys() {
        let covered: BTreeSet<Option<&str>> = contract
            .cases
            .iter()
            .filter(|case| case.model == *model)
            .map(|case| case.level.as_deref())
            .collect();
        if !covered.contains(&None) {
            return Err(format!(
                "model '{model}' does not pin the absent-thinking body"
            ));
        }
        for level in CANONICAL_LEVELS {
            if !covered.contains(&Some(*level)) {
                return Err(format!(
                    "model '{model}' does not pin canonical level '{level}'"
                ));
            }
        }
    }

    if contract.translation {
        if accepted_levels == 0 {
            return Err(format!(
                "{} declares thinking translation but never translates a level",
                contract.plugin
            ));
        }
    } else if accepted_levels != 0 {
        return Err(format!(
            "{} does not declare thinking translation but translates {accepted_levels} level(s)",
            contract.plugin
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelSourceContract {
    schema_version: u32,
    #[serde(rename = "kind")]
    _kind: String,
    plugin: String,
    cases: Vec<ModelSourceCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelSourceCase {
    name: String,
    /// Plugin-specific discovery input (an upstream model list item, a model id).
    input: Value,
    /// Exact `capabilities.reasoning` the host consumes; `null` is unknown.
    reasoning: Value,
}

/// Run a model-source contract. `discover` maps a case input to the plugin's
/// real normalized `capabilities_json`.
pub fn check_model_source_contract(
    contract_json: &str,
    discover: impl Fn(&Value) -> Result<String, String>,
) -> Result<(), String> {
    let contract: ModelSourceContract = serde_json::from_str(contract_json)
        .map_err(|error| format!("invalid thinking contract: {error}"))?;
    if contract.schema_version != 1 {
        return Err(format!(
            "{} thinking contract has unsupported schema_version {}",
            contract.plugin, contract.schema_version
        ));
    }
    if contract.cases.is_empty() {
        return Err(format!(
            "{} thinking contract declares no cases",
            contract.plugin
        ));
    }
    let mut seen = BTreeSet::new();
    for case in &contract.cases {
        if !seen.insert(case.name.as_str()) {
            return Err(format!("duplicate thinking case '{}'", case.name));
        }
        let raw = discover(&case.input).map_err(|error| {
            format!(
                "{} / {}: discovery failed: {error}",
                contract.plugin, case.name
            )
        })?;
        let capabilities: Value = serde_json::from_str(&raw).map_err(|error| {
            format!(
                "{} / {}: invalid capabilities_json: {error}",
                contract.plugin, case.name
            )
        })?;
        let actual = capabilities
            .get("reasoning")
            .cloned()
            .unwrap_or(Value::Null);
        if actual != case.reasoning {
            return Err(format!(
                "{} / {}: discovered reasoning capability changed\nexpected: {}\nactual:   {}",
                contract.plugin, case.name, case.reasoning, actual
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;

    impl Adapter for Echo {
        fn build_body(&self, request: &Value, _: &Value, model: &Value) -> Result<Value, String> {
            match request["thinking"]["level"].as_str() {
                None => Ok(json!({"model": model["id"]})),
                Some("high") => Ok(json!({"model": model["id"], "effort": "high"})),
                Some(level) => Err(format!("unsupported level {level}")),
            }
        }
        fn parse_stream_chunk(&self, _: &Value) -> Result<Value, String> {
            unreachable!()
        }
        fn parse_full_response(&self, _: &Value) -> Result<Value, String> {
            unreachable!()
        }
        fn classify_error(&self, _: u16, _: &Value, _: &Value) -> Result<Value, String> {
            unreachable!()
        }
    }

    fn contract(translation: bool, drop_level: Option<&str>, high_body: Value) -> String {
        let mut cases =
            vec![json!({"name":"absent","model":"m","level":null,"expect":{"body":{"model":"x"}}})];
        for level in CANONICAL_LEVELS {
            if Some(*level) == drop_level {
                continue;
            }
            let expect = if *level == "high" {
                json!({"body": high_body})
            } else {
                json!({"rejected": "unsupported"})
            };
            cases.push(json!({"name": level, "model": "m", "level": level, "expect": expect}));
        }
        json!({
            "schema_version": 1, "kind": "adapter", "plugin": "t", "translation": translation,
            "models": {"m": {"id": "x"}}, "cases": cases
        })
        .to_string()
    }

    #[test]
    fn accepts_a_complete_matching_contract() {
        let raw = contract(true, None, json!({"model":"x","effort":"high"}));
        check_thinking_contract(&Echo, &raw).unwrap();
    }

    #[test]
    fn rejects_a_changed_provider_body() {
        let raw = contract(true, None, json!({"model":"x","effort":"low"}));
        let error = check_thinking_contract(&Echo, &raw).unwrap_err();
        assert!(error.contains("provider body changed"), "{error}");
    }

    #[test]
    fn rejects_an_incomplete_level_matrix() {
        let raw = contract(true, Some("xhigh"), json!({"model":"x","effort":"high"}));
        let error = check_thinking_contract(&Echo, &raw).unwrap_err();
        assert!(error.contains("'xhigh'"), "{error}");
    }

    #[test]
    fn rejects_a_translation_flag_without_translated_levels() {
        let raw = contract(false, None, json!({"model":"x","effort":"high"}));
        let error = check_thinking_contract(&Echo, &raw).unwrap_err();
        assert!(
            error.contains("does not declare thinking translation"),
            "{error}"
        );
    }

    #[test]
    fn model_source_contract_pins_the_reasoning_capability() {
        let raw = json!({
            "schema_version": 1, "kind": "model_source", "plugin": "t",
            "cases": [{"name":"a","input":{},"reasoning":{"supported":true}}]
        })
        .to_string();
        check_model_source_contract(&raw, |_| Ok(r#"{"reasoning":{"supported":true}}"#.into()))
            .unwrap();
        let error = check_model_source_contract(&raw, |_| Ok(r#"{}"#.into())).unwrap_err();
        assert!(error.contains("changed"), "{error}");
    }
}
