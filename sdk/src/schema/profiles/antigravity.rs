use super::Feature;

// v1internal parametersJsonSchema policy. Preserve the adapter's established
// pattern, anyOf, type-array and additionalProperties behavior. Do not copy
// OmniRoute's legacy OpenAPI-field degradation into other JSON Schema surfaces.
pub(super) fn supports(feature: Feature) -> bool {
    match feature {
        Feature::StringBounds
        | Feature::ObjectBounds
        | Feature::ArrayBounds
        | Feature::ExclusiveBounds
        | Feature::MultipleOf
        | Feature::Format
        | Feature::PatternProperties
        | Feature::Tuple
        | Feature::Intersection
        | Feature::ExclusiveUnion
        | Feature::Reference
        | Feature::JsonApplicator => false,
    }
}
