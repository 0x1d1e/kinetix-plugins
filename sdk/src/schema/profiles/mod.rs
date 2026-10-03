mod antigravity;

use super::SchemaProfile;

/// Features are grouped by semantics rather than a plugin-local keyword denylist.
#[derive(Clone, Copy)]
pub(super) enum Feature {
    StringBounds,
    ObjectBounds,
    ArrayBounds,
    ExclusiveBounds,
    MultipleOf,
    Format,
    PatternProperties,
    Tuple,
    Intersection,
    ExclusiveUnion,
    Reference,
    JsonApplicator,
}

impl SchemaProfile {
    pub(super) fn supports(self, feature: Feature) -> bool {
        match self {
            Self::Antigravity => antigravity::supports(feature),
            // These profiles describe ordinary JSON Schema tool inputs, not
            // constrained-decoding/strict output. Do not invent endpoint limits.
            Self::Gemini | Self::OpenAI | Self::Anthropic | Self::OpenAICompatible => true,
        }
    }

    pub(super) fn needs_structure(self) -> bool {
        self == Self::Antigravity
    }
}

pub(super) fn feature(keyword: &str) -> Option<Feature> {
    Some(match keyword {
        "minLength" | "maxLength" => Feature::StringBounds,
        "minProperties" | "maxProperties" => Feature::ObjectBounds,
        "minItems" | "maxItems" | "uniqueItems" => Feature::ArrayBounds,
        "exclusiveMinimum" | "exclusiveMaximum" => Feature::ExclusiveBounds,
        "multipleOf" => Feature::MultipleOf,
        "format" => Feature::Format,
        "patternProperties" => Feature::PatternProperties,
        "prefixItems" | "additionalItems" => Feature::Tuple,
        "allOf" => Feature::Intersection,
        "oneOf" => Feature::ExclusiveUnion,
        "$ref" | "$defs" | "definitions" => Feature::Reference,
        "not"
        | "if"
        | "then"
        | "else"
        | "propertyNames"
        | "contains"
        | "minContains"
        | "maxContains"
        | "unevaluatedItems"
        | "unevaluatedProperties"
        | "dependentSchemas"
        | "dependentRequired"
        | "dependencies" => Feature::JsonApplicator,
        _ => return None,
    })
}
