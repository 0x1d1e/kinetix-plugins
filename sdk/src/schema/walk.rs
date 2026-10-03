use super::{error, SchemaError};
use serde_json::Value;

pub(super) const MAX_DEPTH: usize = 64;
pub(super) const MAX_NODES: usize = 10_000;

pub(super) fn limit(path: &str, depth: usize, nodes: &mut usize) -> Result<(), SchemaError> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES {
        return Err(error(path, "schema complexity limit exceeded"));
    }
    Ok(())
}

/// Visit schema positions only. Property names, const/enum data and annotations
/// must never be mistaken for schema keywords.
pub(super) fn children(
    node: &mut Value,
    path: &str,
    mut visit: impl FnMut(&mut Value, &str) -> Result<(), SchemaError>,
) -> Result<(), SchemaError> {
    let Some(map) = node.as_object_mut() else {
        return Ok(());
    };
    for (key, value) in map {
        let child_path = format!("{path}.{key}");
        match key.as_str() {
            "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas" => {
                let schemas = value
                    .as_object_mut()
                    .ok_or_else(|| error(&child_path, "must be an object"))?;
                for (name, schema) in schemas {
                    visit(schema, &format!("{child_path}.{name}"))?;
                }
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                let schemas = value
                    .as_array_mut()
                    .ok_or_else(|| error(&child_path, "expected an array of schemas"))?;
                for (i, schema) in schemas.iter_mut().enumerate() {
                    visit(schema, &format!("{child_path}[{i}]"))?;
                }
            }
            "items" if value.is_array() => {
                for (i, schema) in value.as_array_mut().unwrap().iter_mut().enumerate() {
                    visit(schema, &format!("{child_path}[{i}]"))?;
                }
            }
            "additionalProperties" if value.is_boolean() => {}
            "items"
            | "additionalProperties"
            | "additionalItems"
            | "contains"
            | "not"
            | "if"
            | "then"
            | "else"
            | "propertyNames"
            | "unevaluatedProperties"
            | "unevaluatedItems"
            | "contentSchema" => visit(value, &child_path)?,
            "dependencies" => {
                let dependencies = value
                    .as_object_mut()
                    .ok_or_else(|| error(&child_path, "must be an object"))?;
                for (name, dependency) in dependencies {
                    if !dependency.is_array() {
                        visit(dependency, &format!("{child_path}.{name}"))?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn postorder(
    node: &mut Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
    pass: &mut impl FnMut(&mut Value, &str) -> Result<(), SchemaError>,
) -> Result<(), SchemaError> {
    limit(path, depth, nodes)?;
    children(node, path, |child, path| {
        postorder(child, path, depth + 1, nodes, pass)
    })?;
    pass(node, path)
}
