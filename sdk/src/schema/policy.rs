use super::{error, SchemaError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaMode {
    /// Preserve semantics, translate losslessly, or reject.
    Strict,
    /// Permit the profile's documented lossy compatibility transformations.
    Compatible,
}

impl std::str::FromStr for SchemaMode {
    type Err = SchemaError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "strict" => Ok(Self::Strict),
            "compatible" | "permissive" => Ok(Self::Compatible),
            _ => Err(error("$", format!("unknown schema mode '{value}'"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaProfile {
    Antigravity,
    /// Gemini's parametersJsonSchema surface, not the legacy OpenAPI parameters field.
    Gemini,
    /// Non-strict function parameters; upstream strict-output rules are separate.
    OpenAI,
    /// Responses API function parameters.
    OpenAIResponses,
    /// Non-strict input_schema; does not inherit Gemini degradation.
    Anthropic,
    /// JSON Schema protocol baseline. Endpoint-specific extensions need a new profile.
    OpenAICompatible,
}

/// What a profile does with a keyword. Classification is owned by the profile,
/// never by scattered keyword matches in an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Reaches the wire unchanged.
    Preserve,
    /// Rewritten into a form the upstream accepts; the keyword itself is gone.
    Normalize,
    /// Removed in `Compatible` mode (the upstream cannot carry it). Strict mode
    /// rejects it, except for non-validating annotations.
    Consume,
    /// Always an error.
    Reject,
}

impl std::str::FromStr for SchemaProfile {
    type Err = SchemaError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "antigravity" => Ok(Self::Antigravity),
            "gemini" => Ok(Self::Gemini),
            "openai" => Ok(Self::OpenAI),
            "openai-responses" => Ok(Self::OpenAIResponses),
            "anthropic" => Ok(Self::Anthropic),
            "openai-compatible" => Ok(Self::OpenAICompatible),
            _ => Err(error("$", format!("unknown schema profile '{value}'"))),
        }
    }
}

impl SchemaProfile {
    /// Effective disposition of a classified keyword, or `None` when the keyword
    /// is not a classified feature (structural keywords such as `type`).
    pub fn disposition(self, keyword: &str, mode: SchemaMode) -> Option<Disposition> {
        let feature = super::profiles::feature(keyword)?;
        Some(self.policy().disposition(feature, mode))
    }
}

/// Every keyword whose disposition a profile classifies.
pub fn classified_keywords() -> impl Iterator<Item = &'static str> {
    super::profiles::KEYWORDS.iter().map(|(name, _)| *name)
}
