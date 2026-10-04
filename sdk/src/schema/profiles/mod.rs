use super::{Disposition, SchemaMode, SchemaProfile};

/// Keywords are grouped by semantics, and each profile classifies every group
/// exhaustively (see [`Disposition`]). There is no keyword denylist elsewhere.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Feature {
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
    /// Non-validating metadata. Consuming it never weakens validation.
    Annotation,
}

impl Feature {
    fn is_annotation(self) -> bool {
        self == Self::Annotation
    }
}

#[derive(Clone, Copy)]
pub(super) struct ProfilePolicy {
    pub disposition: fn(Feature) -> Disposition,
    pub objects: ObjectPolicy,
    pub coerce_numeric_strings: bool,
    pub normalize_type_aliases: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ObjectPolicy {
    JsonSchema,
    RequireDeclaredProperties,
}

impl ProfilePolicy {
    /// Effective disposition. Strict mode never accepts a lossy `Consume`.
    pub(super) fn disposition(self, feature: Feature, mode: SchemaMode) -> Disposition {
        match (self.disposition)(feature) {
            Disposition::Consume if mode == SchemaMode::Strict && !feature.is_annotation() => {
                Disposition::Reject
            }
            other => other,
        }
    }

    /// Profile-level classification, before the mode adjustment.
    pub(super) fn declared(self, feature: Feature) -> Disposition {
        (self.disposition)(feature)
    }
}

/// JSON Schema protocol baseline: every keyword group reaches the wire intact.
fn preserve_all(_: Feature) -> Disposition {
    Disposition::Preserve
}

// Exhaustive on purpose: a new `Feature` forces a decision for this profile.
fn antigravity(feature: Feature) -> Disposition {
    use Disposition::*;
    match feature {
        Feature::StringBounds
        | Feature::ObjectBounds
        | Feature::ArrayBounds
        | Feature::ExclusiveBounds
        | Feature::MultipleOf
        | Feature::Format
        | Feature::PatternProperties
        | Feature::JsonApplicator
        | Feature::Annotation => Consume,
        Feature::Tuple | Feature::Intersection | Feature::ExclusiveUnion | Feature::Reference => {
            Normalize
        }
    }
}

const fn standard_policy() -> ProfilePolicy {
    ProfilePolicy {
        disposition: preserve_all,
        objects: ObjectPolicy::JsonSchema,
        coerce_numeric_strings: true,
        normalize_type_aliases: true,
    }
}

const ANTIGRAVITY: ProfilePolicy = ProfilePolicy {
    disposition: antigravity,
    objects: ObjectPolicy::RequireDeclaredProperties,
    coerce_numeric_strings: true,
    normalize_type_aliases: true,
};

const GEMINI: ProfilePolicy = standard_policy();
const OPENAI: ProfilePolicy = standard_policy();
const OPENAI_RESPONSES: ProfilePolicy = standard_policy();
const ANTHROPIC: ProfilePolicy = standard_policy();
const OPENAI_COMPATIBLE: ProfilePolicy = standard_policy();

impl SchemaProfile {
    pub(super) fn policy(self) -> &'static ProfilePolicy {
        match self {
            Self::Antigravity => &ANTIGRAVITY,
            Self::Gemini => &GEMINI,
            Self::OpenAI => &OPENAI,
            Self::OpenAIResponses => &OPENAI_RESPONSES,
            Self::Anthropic => &ANTHROPIC,
            Self::OpenAICompatible => &OPENAI_COMPATIBLE,
        }
    }

    pub(super) fn needs_structure(self) -> bool {
        self.policy().objects == ObjectPolicy::RequireDeclaredProperties
    }

    pub(super) fn inlines_local_refs(self) -> bool {
        self.policy().declared(Feature::Reference) == Disposition::Normalize
    }
}

/// Every classified keyword, with the group that decides its disposition.
pub const KEYWORDS: &[(&str, Feature)] = &[
    ("minLength", Feature::StringBounds),
    ("maxLength", Feature::StringBounds),
    ("minProperties", Feature::ObjectBounds),
    ("maxProperties", Feature::ObjectBounds),
    ("minItems", Feature::ArrayBounds),
    ("maxItems", Feature::ArrayBounds),
    ("uniqueItems", Feature::ArrayBounds),
    ("exclusiveMinimum", Feature::ExclusiveBounds),
    ("exclusiveMaximum", Feature::ExclusiveBounds),
    ("multipleOf", Feature::MultipleOf),
    ("format", Feature::Format),
    ("patternProperties", Feature::PatternProperties),
    ("prefixItems", Feature::Tuple),
    ("additionalItems", Feature::Tuple),
    ("allOf", Feature::Intersection),
    ("oneOf", Feature::ExclusiveUnion),
    ("$ref", Feature::Reference),
    ("$defs", Feature::Reference),
    ("definitions", Feature::Reference),
    ("not", Feature::JsonApplicator),
    ("if", Feature::JsonApplicator),
    ("then", Feature::JsonApplicator),
    ("else", Feature::JsonApplicator),
    ("propertyNames", Feature::JsonApplicator),
    ("contains", Feature::JsonApplicator),
    ("minContains", Feature::JsonApplicator),
    ("maxContains", Feature::JsonApplicator),
    ("unevaluatedItems", Feature::JsonApplicator),
    ("unevaluatedProperties", Feature::JsonApplicator),
    ("dependentSchemas", Feature::JsonApplicator),
    ("dependentRequired", Feature::JsonApplicator),
    ("dependencies", Feature::JsonApplicator),
    ("$schema", Feature::Annotation),
    ("$comment", Feature::Annotation),
    ("$id", Feature::Annotation),
    ("$anchor", Feature::Annotation),
    ("strict", Feature::Annotation),
    ("encrypted", Feature::Annotation),
    ("default", Feature::Annotation),
    ("examples", Feature::Annotation),
    ("example", Feature::Annotation),
    ("deprecated", Feature::Annotation),
    ("readOnly", Feature::Annotation),
    ("writeOnly", Feature::Annotation),
];

pub(super) fn feature(keyword: &str) -> Option<Feature> {
    KEYWORDS
        .iter()
        .find_map(|(name, feature)| (*name == keyword).then_some(*feature))
}
