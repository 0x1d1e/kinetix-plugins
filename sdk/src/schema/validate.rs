use super::{error, profiles::feature, walk, SchemaError, SchemaProfile};
use serde_json::{Map, Value};

pub(super) fn node(
    map: &Map<String, Value>,
    path: &str,
    repaired: bool,
) -> Result<(), SchemaError> {
    for (key, value) in map {
        let path = format!("{path}.{key}");
        let valid = match key.as_str() {
            "type" => match value {
                Value::String(kind) => valid_type(kind),
                Value::Array(types) => {
                    !types.is_empty() && types.iter().all(|v| v.as_str().is_some_and(valid_type))
                }
                _ => false,
            },
            "title" | "description" | "pattern" | "format" | "$schema" | "$id" | "$anchor"
            | "$comment" | "$ref" | "contentMediaType" | "contentEncoding" => value.is_string(),
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => value.is_number(),
            "multipleOf" => value.as_f64().is_some_and(|v| v > 0.0),
            "minLength" | "maxLength" | "minItems" | "maxItems" | "minProperties"
            | "maxProperties" | "minContains" | "maxContains" => value.as_u64().is_some(),
            "enum" => value.as_array().is_some_and(|v| !v.is_empty()),
            "allOf" | "anyOf" | "oneOf" => value.as_array().is_some_and(|v| !v.is_empty()),
            "prefixItems" => value.is_array(),
            "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas"
            | "dependencies" | "dependentRequired" => value.is_object(),
            "required" if !repaired => true, // repaired according to policy later
            "required" | "propertyOrdering" => strings(value),
            "items" => value.is_object() || value.is_boolean() || value.is_array(),
            "additionalProperties"
            | "additionalItems"
            | "not"
            | "if"
            | "then"
            | "else"
            | "propertyNames"
            | "contains"
            | "unevaluatedProperties"
            | "unevaluatedItems"
            | "contentSchema" => value.is_object() || value.is_boolean(),
            "uniqueItems" | "deprecated" | "readOnly" | "writeOnly" | "strict" | "encrypted" => {
                value.is_boolean()
            }
            "default" | "example" => true,
            "examples" => value.is_array(),
            other => {
                return Err(error(
                    &path,
                    format!("unknown JSON Schema keyword '{other}'"),
                ))
            }
        };
        if !valid {
            let message = if matches!(key.as_str(), "pattern" | "title" | "description" | "$ref") {
                "must be a string"
            } else {
                "invalid keyword value"
            };
            return Err(error(&path, message));
        }
        if key == "dependentRequired" || key == "dependencies" {
            for (name, dependency) in value.as_object().unwrap() {
                if (key == "dependentRequired" || dependency.is_array()) && !strings(dependency) {
                    return Err(error(
                        &format!("{path}.{name}"),
                        "must be an array of strings",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate(schema: &Value, profile: SchemaProfile) -> Result<(), SchemaError> {
    let mut checked = schema.clone();
    walk::postorder(&mut checked, "$", 0, &mut 0, &mut |node_value, path| {
        let Some(map) = node_value.as_object() else {
            if node_value.is_boolean() && !profile.needs_structure() {
                return Ok(());
            }
            return Err(error(path, "schema nodes must be JSON objects"));
        };
        node(map, path, true)?;
        for key in map.keys() {
            if feature(key).is_some_and(|feature| !profile.supports(feature)) {
                return Err(error(
                    &format!("{path}.{key}"),
                    "unsupported keyword survived translation",
                ));
            }
        }
        if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
            if (!reference.starts_with("#/") && reference != "#")
                || schema.pointer(&reference[1..]).is_none()
            {
                return Err(error(
                    &format!("{path}.$ref"),
                    "unresolved or non-local reference",
                ));
            }
            if !schema
                .pointer(&reference[1..])
                .is_some_and(|v| v.is_object() || v.is_boolean())
            {
                return Err(error(
                    &format!("{path}.$ref"),
                    "reference target must be a schema",
                ));
            }
        }
        if profile.needs_structure() {
            if map.get("type") == Some(&Value::String("array".into())) && !map.contains_key("items")
            {
                return Err(error(path, "array must have items"));
            }
            if map.get("type") == Some(&Value::String("object".into()))
                && !map
                    .get("properties")
                    .and_then(Value::as_object)
                    .is_some_and(|p| !p.is_empty())
            {
                return Err(error(path, "object must have nonempty properties"));
            }
        }
        Ok(())
    })
}

fn valid_type(kind: &str) -> bool {
    matches!(
        kind,
        "object" | "array" | "string" | "number" | "integer" | "boolean" | "null"
    )
}
fn strings(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|values| values.iter().all(Value::is_string))
}
