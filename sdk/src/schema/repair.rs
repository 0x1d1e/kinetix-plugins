use super::{error, walk, SchemaError, SchemaMode, SchemaProfile};
use serde_json::{json, Value};

pub(super) fn repair(
    schema: &mut Value,
    profile: SchemaProfile,
    mode: SchemaMode,
) -> Result<(), SchemaError> {
    walk::postorder(schema, "$", 0, &mut 0, &mut |node, path| {
        if profile.needs_structure() && node == &json!(true) {
            *node = json!({});
        }
        if profile.needs_structure() && node == &json!(false) {
            return Err(error(
                path,
                "false schema cannot be represented by Antigravity",
            ));
        }
        let Some(map) = node.as_object_mut() else {
            return Ok(());
        };
        if let Some(required) = map.get("required") {
            let properties = map.get("properties").and_then(Value::as_object);
            let mut clean = Vec::new();
            let mut invalid = false;
            if let Some(required) = required.as_array() {
                for item in required {
                    // Other JSON Schema profiles may legally require dynamic
                    // properties absent from properties. Only structural profiles
                    // need a declared property for each required entry.
                    if item.as_str().is_some_and(|name| {
                        !profile.needs_structure()
                            || properties.is_some_and(|p| p.contains_key(name))
                    }) {
                        if !clean.contains(item) {
                            clean.push(item.clone());
                        }
                    } else {
                        invalid = true;
                    }
                }
            } else {
                invalid = true;
            }
            if invalid && mode == SchemaMode::Strict {
                return Err(error(
                    &format!("{path}.required"),
                    "required must name declared properties",
                ));
            }
            map.insert("required".into(), Value::Array(clean));
        }
        if profile.needs_structure() {
            let kinds: Vec<&str> = match map.get("type") {
                Some(Value::String(kind)) => vec![kind],
                Some(Value::Array(types)) => types.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            let is_object = kinds.contains(&"object");
            let is_array = kinds.contains(&"array");
            if is_array && !map.contains_key("items") {
                map.insert("items".into(), json!({}));
            }
            if is_object
                && map
                    .get("properties")
                    .and_then(Value::as_object)
                    .is_none_or(|p| p.is_empty())
            {
                if mode == SchemaMode::Strict {
                    return Err(error(
                        &format!("{path}.properties"),
                        "empty object requires lossy placeholder repair",
                    ));
                }
                map.insert("properties".into(), json!({
                    "_placeholder": {"type": "boolean", "description": "Optional placeholder; omit when unused."}
                }));
                // A placeholder is optional. Never add it to required.
            }
        }
        Ok(())
    })
}
