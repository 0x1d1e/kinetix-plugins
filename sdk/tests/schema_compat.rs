use kinetix_plugin_sdk::schema::{
    translate,
    SchemaMode::{Compatible, Strict},
    SchemaProfile::{self, Anthropic, Antigravity, Gemini, OpenAI, OpenAICompatible},
};
use serde_json::{json, Value};

fn ag(schema: &Value) -> Value {
    translate(schema, Antigravity, Compatible).unwrap()
}

// Independent assertion: do not ask the production profile which fields it
// supports or a policy regression could make both output and test pass.
fn assert_antigravity_output(schema: &Value) {
    if let Some(map) = schema.as_object() {
        for keyword in [
            "patternProperties",
            "minProperties",
            "maxProperties",
            "minLength",
            "maxLength",
            "minItems",
            "maxItems",
            "prefixItems",
            "additionalItems",
            "$defs",
            "definitions",
            "$ref",
            "const",
            "allOf",
            "oneOf",
            "exclusiveMinimum",
            "exclusiveMaximum",
            "multipleOf",
            "format",
            "uniqueItems",
            "not",
            "if",
            "then",
            "else",
            "contains",
            "propertyNames",
            "unevaluatedProperties",
        ] {
            assert!(
                !map.contains_key(keyword),
                "unsupported {keyword}: {schema}"
            );
        }
        if schema["type"] == "object" {
            assert!(!schema["properties"].as_object().unwrap().is_empty());
        }
        if schema["type"] == "array" {
            assert!(schema.get("items").is_some());
        }
        for key in ["properties"] {
            if let Some(properties) = map.get(key).and_then(Value::as_object) {
                for schema in properties.values() {
                    assert_antigravity_output(schema);
                }
            }
        }
        for key in ["items", "additionalProperties"] {
            if let Some(schema) = map.get(key) {
                assert_antigravity_output(schema);
            }
        }
        if let Some(branches) = map.get("anyOf").and_then(Value::as_array) {
            for schema in branches {
                assert_antigravity_output(schema);
            }
        }
    }
}

#[test]
fn real_tool_corpus_matches_upstream_goldens() {
    let corpus: Value =
        serde_json::from_str(include_str!("fixtures/schema-compat/corpus.json")).unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        let original = case["schema"].clone();
        let got = ag(&original);
        assert_eq!(got, case["expected"], "{}", case["name"]);
        assert_antigravity_output(&got);
        assert_eq!(original, case["schema"]);
        assert_eq!(ag(&got), got, "translation must be idempotent");
    }
}

#[test]
fn profiles_do_not_inherit_antigravity_degradation() {
    let schema = json!({"type": "object", "patternProperties": {"^.*$": {"type": "string", "maxLength": 100, "pattern": "(?=a)a"}}, "minProperties": 1, "additionalProperties": false});
    for profile in [Gemini, OpenAI, Anthropic, OpenAICompatible] {
        for mode in [Strict, Compatible] {
            assert_eq!(translate(&schema, profile, mode).unwrap(), schema);
        }
    }
    assert!(translate(&schema, Antigravity, Strict).is_err());
    let got = ag(&schema);
    assert!(got.get("patternProperties").is_none());
    assert!(
        got.get("additionalProperties").is_none(),
        "stripping patterns must not forbid dynamic record keys"
    );
    let schema_tail = json!({"properties": {"fixed": {"type": "boolean"}}, "patternProperties": {"^x": {"type": "number"}}, "additionalProperties": {"type": "string"}});
    let got = ag(&schema_tail);
    assert_eq!(got["properties"]["fixed"], json!({"type": "boolean"}));
    assert!(got.get("additionalProperties").is_none());
}

#[test]
fn strict_rejects_only_lossy_unions() {
    for overlap in [
        json!({"oneOf": [{"enum": [1]}, {"enum": [1.0]}]}),
        json!({"oneOf": [{"enum": [{"n": 1}]}, {"enum": [{"n": 1.0}]}]}),
    ] {
        assert!(translate(&overlap, Antigravity, Strict).is_err());
    }
    let overlapping = json!({"oneOf": [{"type": "number"}, {"type": "integer"}]});
    assert!(translate(&overlapping, Antigravity, Strict).is_err());
    assert!(ag(&overlapping).get("anyOf").is_some());
    let disjoint = json!({"oneOf": [{"type": "string"}, {"type": "integer"}]});
    assert_eq!(
        translate(&disjoint, Antigravity, Strict).unwrap(),
        json!({"anyOf": [{"type": "string"}, {"type": "integer"}]})
    );
}

#[test]
fn safe_all_of_merge_and_conflicts() {
    let schema = json!({"allOf": [{"properties": {"a": {"type": "string"}}, "required": ["a"]}, {"properties": {"b": {"type": "number"}}, "required": ["b"]}]});
    assert_eq!(
        translate(&schema, Antigravity, Strict).unwrap(),
        json!({"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "number"}}, "required": ["a", "b"]})
    );
    for schema in [
        json!({"allOf": [{"type": "string"}, {"type": "number"}]}),
        json!({"allOf": [{"properties": {"a": {"type": "string"}}, "additionalProperties": false}, {"properties": {"b": {"type": "number"}}}]}),
        json!({"$defs": {"v": {"type": "integer"}}, "$ref": "#/$defs/v", "type": "string"}),
    ] {
        for mode in [Strict, Compatible] {
            assert!(translate(&schema, Antigravity, mode).is_err());
        }
    }
}

#[test]
fn local_refs_are_inlined_and_cycles_fail_closed() {
    let schema = json!({"$defs": {"a/b~c": {"type": "string"}}, "properties": {"v": {"$ref": "#/$defs/a~1b~0c", "description": "value"}}});
    assert_eq!(
        ag(&schema),
        json!({"type": "object", "properties": {"v": {"type": "string", "description": "value"}}})
    );
    for reference in ["#/$defs/missing", "https://example.org/s.json", "#"] {
        let schema = json!({"$ref": reference});
        for mode in [Strict, Compatible] {
            assert!(translate(&schema, Antigravity, mode).is_err());
        }
    }
    let recursive = json!({"type": "object", "properties": {"next": {"$ref": "#"}}});
    for profile in [Gemini, OpenAI, Anthropic, OpenAICompatible] {
        assert_eq!(translate(&recursive, profile, Strict).unwrap(), recursive);
    }
    let scoped = json!({"properties": {"v": {"$id": "nested", "$ref": "#/$defs/v"}}, "$defs": {"v": {"type": "string"}}});
    assert!(translate(&scoped, Antigravity, Compatible).is_err());
}

#[test]
fn repair_required_and_structural_requirements() {
    let schema =
        json!({"properties": {"x": {"type": "string"}}, "required": ["x", "x", "missing", 7]});
    assert_eq!(ag(&schema)["required"], json!(["x"]));
    assert!(translate(&schema, Antigravity, Strict).is_err());
    let malformed = json!({"properties": {"x": {"type": "string", "required": true}}});
    assert_eq!(ag(&malformed)["required"], json!(["x"]));
    assert!(translate(&malformed, Antigravity, Strict).is_err());
    assert_eq!(
        ag(&json!({"type": "array"})),
        json!({"type": "array", "items": {}})
    );
    let empty = ag(&json!({"type": "object", "properties": {}, "additionalProperties": false}));
    assert_antigravity_output(&empty);
    assert!(empty.get("required").is_none());
    assert!(translate(&json!({"type": "object"}), Antigravity, Strict).is_err());
    // Dynamic required keys are valid JSON Schema outside structural profiles.
    let dynamic = json!({"type": "object", "required": ["key"]});
    assert_eq!(translate(&dynamic, Anthropic, Strict).unwrap(), dynamic);
}

#[test]
fn generic_normalization_preserves_data_literals() {
    let schema = json!({"properties": {"minimum": {"type": "INT32", "minimum": "1"}, "example": {"const": {"maxLength": "not a keyword", "$ref": "literal data"}}}});
    let got = ag(&schema);
    assert_eq!(
        got["properties"]["minimum"],
        json!({"type": "integer", "minimum": 1})
    );
    assert_eq!(
        got["properties"]["example"]["enum"],
        json!([{"maxLength": "not a keyword", "$ref": "literal data"}])
    );
    let nullable_enum = ag(&json!({"type": "string", "enum": ["x"], "nullable": true}));
    assert_eq!(
        nullable_enum,
        json!({"anyOf": [{"type": "string", "enum": ["x"]}, {"type": "null"}]})
    );
}

#[test]
fn invalid_values_and_unknown_keywords_fail_both_modes() {
    for schema in [
        json!({"type": "fantasy"}),
        json!({"pattern": 42}),
        json!({"maxLength": "NaN"}),
        json!({"maxLength": -1}),
        json!({"properties": []}),
        json!({"items": 7}),
        json!({"enum": []}),
        json!({"anyOf": []}),
        json!({"const": "x", "enum": ["y"]}),
        json!({"unknownKeyword": true}),
        json!({"patternProperties": {".*": {"vendorMagic": true}}}),
    ] {
        for mode in [Strict, Compatible] {
            assert!(translate(&schema, Antigravity, mode).is_err(), "{schema}");
        }
    }
}

#[test]
fn resource_limits_bound_expansion() {
    let mut schema = json!({"type": "string"});
    for _ in 0..70 {
        schema = json!({"type": "array", "items": schema});
    }
    assert!(translate(&schema, Antigravity, Compatible)
        .unwrap_err()
        .message
        .contains("limit"));
    let mut defs = serde_json::Map::new();
    defs.insert("leaf".into(), json!({"type": "string"}));
    let mut previous = "leaf".to_string();
    for i in 0..16 {
        let name = format!("n{i}");
        defs.insert(name.clone(), json!({"properties": {"left": {"$ref": format!("#/$defs/{previous}")}, "right": {"$ref": format!("#/$defs/{previous}")}}}));
        previous = name;
    }
    let schema = json!({"$defs": defs, "$ref": format!("#/$defs/{previous}")});
    assert!(translate(&schema, Antigravity, Compatible)
        .unwrap_err()
        .message
        .contains("limit"));
}

#[test]
fn config_alias_is_explicit() {
    assert_eq!("permissive".parse(), Ok(Compatible));
    assert_eq!("compatible".parse(), Ok(Compatible));
    assert_eq!("strict".parse(), Ok(Strict));
    assert!("mystery"
        .parse::<kinetix_plugin_sdk::schema::SchemaMode>()
        .is_err());
    // Profile enum is usable by plugins without inspecting engine internals.
    let _: SchemaProfile = Antigravity;
}
