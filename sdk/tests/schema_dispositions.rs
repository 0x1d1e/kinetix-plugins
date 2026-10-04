//! Policy conformance for `sdk::schema`: every classified keyword is probed
//! through every profile and mode, and the output must match the declared
//! disposition. The same probes drive the per-adapter exact-wire runner.

use kinetix_plugin_sdk::schema::{
    classified_keywords, translate_tool_parameters, Disposition, SchemaMode, SchemaProfile,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

const PROBES: &str = include_str!("../../wit/fixtures/plugin-adapter/v1/schema-keywords.json");

const PROFILES: [SchemaProfile; 6] = [
    SchemaProfile::Antigravity,
    SchemaProfile::Gemini,
    SchemaProfile::OpenAI,
    SchemaProfile::OpenAIResponses,
    SchemaProfile::Anthropic,
    SchemaProfile::OpenAICompatible,
];

fn parameters(probe: &Value) -> Value {
    let mut root = Map::new();
    root.insert("type".into(), json!("object"));
    root.insert("properties".into(), json!({"probe": probe["schema"]}));
    root.insert("required".into(), json!(["probe"]));
    for (key, value) in probe["root"].as_object().into_iter().flatten() {
        root.insert(key.clone(), value.clone());
    }
    Value::Object(root)
}

fn observed<'a>(probe: &Value, keyword: &str, output: &'a Value) -> Option<&'a Value> {
    match probe["at"].as_str().unwrap_or("probe") {
        "root" => output.get(keyword),
        _ => output["properties"]["probe"].get(keyword),
    }
}

#[test]
fn every_classified_keyword_has_exactly_one_probe() {
    let probes: Value = serde_json::from_str(PROBES).unwrap();
    let probed: BTreeSet<_> = probes["keywords"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let classified: BTreeSet<_> = classified_keywords().map(String::from).collect();
    assert_eq!(probed, classified);
}

#[test]
fn output_matches_declared_disposition_for_every_profile_and_mode() {
    let probes: Value = serde_json::from_str(PROBES).unwrap();
    for (keyword, probe) in probes["keywords"].as_object().unwrap() {
        let schema = parameters(probe);
        for profile in PROFILES {
            for mode in [SchemaMode::Strict, SchemaMode::Compatible] {
                let disposition = profile.disposition(keyword, mode).unwrap();
                let context = format!("{keyword} / {profile:?} / {mode:?} / {disposition:?}");
                let result = translate_tool_parameters(&schema, profile, mode);
                match disposition {
                    Disposition::Preserve => {
                        let output = result.unwrap_or_else(|e| panic!("{context}: {e}"));
                        assert_eq!(
                            observed(probe, keyword, &output),
                            observed(probe, keyword, &schema),
                            "{context}: not preserved: {output}"
                        );
                    }
                    Disposition::Consume => {
                        let output = result.unwrap_or_else(|e| panic!("{context}: {e}"));
                        assert!(
                            observed(probe, keyword, &output).is_none(),
                            "{context}: {output}"
                        );
                    }
                    Disposition::Reject => {
                        assert!(result.is_err(), "{context}: accepted");
                    }
                    Disposition::Normalize => {
                        let normalized = probe
                            .get("normalized")
                            .unwrap_or_else(|| panic!("{context}: probe has no normalized shape"));
                        if probe["lossy"].as_bool() == Some(true) && mode == SchemaMode::Strict {
                            assert!(result.is_err(), "{context}: lossy rewrite accepted");
                            continue;
                        }
                        let output = result.unwrap_or_else(|e| panic!("{context}: {e}"));
                        assert_eq!(
                            &output["properties"]["probe"], normalized,
                            "{context}: wrong normalized shape"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn strict_mode_only_tightens_consumption() {
    for profile in PROFILES {
        for keyword in classified_keywords() {
            let compatible = profile
                .disposition(keyword, SchemaMode::Compatible)
                .unwrap();
            let strict = profile.disposition(keyword, SchemaMode::Strict).unwrap();
            let tightened = compatible == Disposition::Consume && strict == Disposition::Reject;
            assert!(
                strict == compatible || tightened,
                "{profile:?} {keyword}: strict {strict:?} vs compatible {compatible:?}"
            );
        }
    }
}

#[test]
fn rejections_name_the_offending_keyword_path() {
    let probes: Value = serde_json::from_str(PROBES).unwrap();
    for (keyword, probe) in probes["keywords"].as_object().unwrap() {
        let schema = parameters(probe);
        for profile in PROFILES {
            if profile.disposition(keyword, SchemaMode::Strict) != Some(Disposition::Reject) {
                continue;
            }
            let error = translate_tool_parameters(&schema, profile, SchemaMode::Strict)
                .expect_err("rejected keyword was accepted");
            let scope = match probe["at"].as_str() {
                Some("root") => "$.",
                _ => "$.properties.probe.",
            };
            // Keywords of one feature group (if/then/else) report the first hit.
            let named = error
                .path
                .strip_prefix(scope)
                .unwrap_or_else(|| panic!("{keyword} / {profile:?}: path {}", error.path));
            assert_eq!(
                profile.disposition(named, SchemaMode::Strict),
                Some(Disposition::Reject),
                "{keyword} / {profile:?}: path {}",
                error.path
            );
        }
    }
}
