//! Versioned normalized metadata for `DiscoveredModel.capabilities_json`.
//!
//! Plugin API v1 still carries capability metadata as an optional JSON string.
//! These types give producers and consumers a strict shared schema without
//! changing the WIT ABI.

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt};

pub const MODEL_CAPABILITIES_SCHEMA_V1: u32 = 1;
pub const MODEL_CAPABILITIES_SCHEMA_VERSION: u32 = MODEL_CAPABILITIES_SCHEMA_V1;
pub const MODEL_CAPABILITIES_SCHEMA_V2: u32 = 2;
pub const MODEL_CAPABILITIES_SCHEMA_V3: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilitiesV1 {
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<SupportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<ReasoningCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<SupportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vision: Option<VisionCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_output: Option<SupportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modalities: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prices: Option<serde_json::Value>,
}

impl Default for ModelCapabilitiesV1 {
    fn default() -> Self {
        Self {
            schema_version: MODEL_CAPABILITIES_SCHEMA_VERSION,
            transport: None,
            text: None,
            reasoning: None,
            tools: None,
            vision: None,
            structured_output: None,
            modalities: None,
            prices: None,
        }
    }
}

impl ModelCapabilitiesV1 {
    pub fn is_empty(&self) -> bool {
        self.transport.is_none()
            && self.text.is_none()
            && self.reasoning.is_none()
            && self.tools.is_none()
            && self.vision.is_none()
            && self.structured_output.is_none()
            && self.modalities.is_none()
            && self.prices.is_none()
    }

    pub fn validate(&self) -> Result<(), CapabilityMetadataError> {
        if self.schema_version != MODEL_CAPABILITIES_SCHEMA_VERSION {
            return Err(CapabilityMetadataError::validation(format!(
                "unsupported schema_version {}; expected {}",
                self.schema_version, MODEL_CAPABILITIES_SCHEMA_VERSION
            )));
        }

        if let Some(transport) = &self.transport {
            if transport.format.trim().is_empty() {
                return Err(CapabilityMetadataError::validation(
                    "transport.format must not be empty",
                ));
            }
        }

        if let Some(reasoning) = &self.reasoning {
            reasoning.validate()?;
        }

        if let Some(prices) = &self.prices {
            let prices = prices.as_object().ok_or_else(|| {
                CapabilityMetadataError::validation("prices must be a JSON object")
            })?;
            for key in [
                "input_per_1m",
                "output_per_1m",
                "cached_per_1m",
                "cache_write_per_1m",
                "thinking_per_1m",
            ] {
                let Some(value) = prices.get(key) else {
                    continue;
                };
                if value.is_null() {
                    continue;
                }
                let Some(value) = value.as_f64() else {
                    return Err(CapabilityMetadataError::validation(format!(
                        "prices.{key} must be a non-negative number or null"
                    )));
                };
                if !value.is_finite() || value < 0.0 {
                    return Err(CapabilityMetadataError::validation(format!(
                        "prices.{key} must be a non-negative finite number or null"
                    )));
                }
            }
        }

        Ok(())
    }

    pub fn to_json(&self) -> Result<String, CapabilityMetadataError> {
        self.validate()?;
        serde_json::to_string(self).map_err(CapabilityMetadataError::Json)
    }

    pub fn from_json(value: &str) -> Result<Self, CapabilityMetadataError> {
        let metadata: Self = serde_json::from_str(value).map_err(CapabilityMetadataError::Json)?;
        metadata.validate()?;
        Ok(metadata)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilitiesV2 {
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<SupportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<ReasoningCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<SupportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vision: Option<VisionCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_output: Option<SupportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modalities: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prices: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<ModelIdentityV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque_state: Option<OpaqueStateCapabilityV1>,
}

impl Default for ModelCapabilitiesV2 {
    fn default() -> Self {
        Self {
            schema_version: MODEL_CAPABILITIES_SCHEMA_V2,
            transport: None,
            text: None,
            reasoning: None,
            tools: None,
            vision: None,
            structured_output: None,
            modalities: None,
            prices: None,
            identity: None,
            opaque_state: None,
        }
    }
}

impl ModelCapabilitiesV2 {
    pub fn is_empty(&self) -> bool {
        self.transport.is_none()
            && self.text.is_none()
            && self.reasoning.is_none()
            && self.tools.is_none()
            && self.vision.is_none()
            && self.structured_output.is_none()
            && self.modalities.is_none()
            && self.prices.is_none()
            && self.identity.is_none()
            && self.opaque_state.is_none()
    }

    pub fn validate(&self) -> Result<(), CapabilityMetadataError> {
        if self.schema_version != MODEL_CAPABILITIES_SCHEMA_V2 {
            return Err(CapabilityMetadataError::validation(format!(
                "unsupported schema_version {}; expected {}",
                self.schema_version, MODEL_CAPABILITIES_SCHEMA_V2
            )));
        }
        if let Some(transport) = &self.transport {
            if transport.format.trim().is_empty() {
                return Err(CapabilityMetadataError::validation(
                    "transport.format must not be empty",
                ));
            }
        }
        if let Some(reasoning) = &self.reasoning {
            reasoning.validate()?;
        }
        if let Some(identity) = &self.identity {
            identity.validate()?;
        }
        if let Some(opaque_state) = &self.opaque_state {
            opaque_state.validate()?;
        }
        validate_prices(self.prices.as_ref())
    }

    pub fn to_json(&self) -> Result<String, CapabilityMetadataError> {
        self.validate()?;
        serde_json::to_string(self).map_err(CapabilityMetadataError::Json)
    }

    pub fn from_json(value: &str) -> Result<Self, CapabilityMetadataError> {
        let metadata: Self = serde_json::from_str(value).map_err(CapabilityMetadataError::Json)?;
        metadata.validate()?;
        Ok(metadata)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilitiesV3 {
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<ModelTransportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<SupportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<ReasoningCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<SupportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel_tools: Option<SupportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vision: Option<VisionCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_output: Option<SupportCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modalities: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prices: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<ModelIdentityV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque_state: Option<OpaqueStateCapabilityV1>,
}

impl Default for ModelCapabilitiesV3 {
    fn default() -> Self {
        Self {
            schema_version: MODEL_CAPABILITIES_SCHEMA_V3,
            transport: None,
            text: None,
            reasoning: None,
            tools: None,
            parallel_tools: None,
            vision: None,
            structured_output: None,
            modalities: None,
            prices: None,
            identity: None,
            opaque_state: None,
        }
    }
}

impl ModelCapabilitiesV3 {
    pub fn validate(&self) -> Result<(), CapabilityMetadataError> {
        if self.schema_version != MODEL_CAPABILITIES_SCHEMA_V3 {
            return Err(CapabilityMetadataError::validation(format!(
                "unsupported schema_version {}; expected {}",
                self.schema_version, MODEL_CAPABILITIES_SCHEMA_V3
            )));
        }
        if let Some(transport) = &self.transport {
            transport.validate()?;
        }
        if self
            .parallel_tools
            .as_ref()
            .is_some_and(|parallel| parallel.supported)
            && !self.tools.as_ref().is_some_and(|tools| tools.supported)
        {
            return Err(CapabilityMetadataError::validation(
                "parallel_tools.supported requires tools.supported",
            ));
        }
        if let Some(reasoning) = &self.reasoning {
            reasoning.validate()?;
        }
        if let Some(identity) = &self.identity {
            identity.validate()?;
        }
        if let Some(opaque_state) = &self.opaque_state {
            opaque_state.validate()?;
        }
        validate_prices(self.prices.as_ref())
    }

    pub fn to_json(&self) -> Result<String, CapabilityMetadataError> {
        self.validate()?;
        serde_json::to_string(self).map_err(CapabilityMetadataError::Json)
    }

    pub fn from_json(value: &str) -> Result<Self, CapabilityMetadataError> {
        let metadata: Self = serde_json::from_str(value).map_err(CapabilityMetadataError::Json)?;
        metadata.validate()?;
        Ok(metadata)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelIdentityV2 {
    pub canonical_model_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<ProviderVariantV1>,
}

impl ModelIdentityV2 {
    pub fn validate(&self) -> Result<(), CapabilityMetadataError> {
        let id = self.canonical_model_id.trim();
        if id.is_empty() || !id.contains('/') || id.chars().any(char::is_control) {
            return Err(CapabilityMetadataError::validation(
                "identity.canonical_model_id must be a non-empty provider/model id without control characters",
            ));
        }
        if let Some(variant) = &self.variant {
            variant.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderVariantV1 {
    pub kind: ProviderVariantKind,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_level: Option<ReasoningLevel>,
    pub fixed: bool,
}

impl ProviderVariantV1 {
    pub fn validate(&self) -> Result<(), CapabilityMetadataError> {
        if self.id.trim().is_empty() || self.id.chars().any(char::is_control) {
            return Err(CapabilityMetadataError::validation(
                "identity.variant.id must not be empty",
            ));
        }
        if self.reasoning_level.is_some() && self.kind != ProviderVariantKind::ReasoningTier {
            return Err(CapabilityMetadataError::validation(
                "identity.variant.reasoning_level is only valid for reasoning_tier",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderVariantKind {
    ReasoningTier,
    ProviderAlias,
    ThinkingVariant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueStateCapabilityV1 {
    pub kind: OpaqueStateCapabilityKind,
    pub family: String,
    pub encoding_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder_strategy: Option<OpaqueStatePlaceholderStrategy>,
}

impl OpaqueStateCapabilityV1 {
    pub fn validate(&self) -> Result<(), CapabilityMetadataError> {
        let family = self.family.as_str();
        if family.is_empty()
            || family.len() > 64
            || !family
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(CapabilityMetadataError::validation(
                "opaque_state.family must be a safe non-empty identifier up to 64 bytes",
            ));
        }
        if self.encoding_version == 0 {
            return Err(CapabilityMetadataError::validation(
                "opaque_state.encoding_version must be >= 1",
            ));
        }
        if self.placeholder_strategy == Some(OpaqueStatePlaceholderStrategy::Gemini3SkipValidator)
            && self.kind != OpaqueStateCapabilityKind::GeminiThoughtSignature
        {
            return Err(CapabilityMetadataError::validation(
                "gemini3_skip_validator requires gemini_thought_signature",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpaqueStateCapabilityKind {
    GeminiThoughtSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpaqueStatePlaceholderStrategy {
    Gemini3SkipValidator,
}

fn validate_prices(prices: Option<&serde_json::Value>) -> Result<(), CapabilityMetadataError> {
    let Some(prices) = prices else {
        return Ok(());
    };
    let prices = prices
        .as_object()
        .ok_or_else(|| CapabilityMetadataError::validation("prices must be a JSON object"))?;
    for key in [
        "input_per_1m",
        "output_per_1m",
        "cached_per_1m",
        "cache_write_per_1m",
        "thinking_per_1m",
    ] {
        let Some(value) = prices.get(key) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let Some(value) = value.as_f64() else {
            return Err(CapabilityMetadataError::validation(format!(
                "prices.{key} must be a non-negative number or null"
            )));
        };
        if !value.is_finite() || value < 0.0 {
            return Err(CapabilityMetadataError::validation(format!(
                "prices.{key} must be a non-negative finite number or null"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelTransportCapability {
    pub format: TransportFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<TransportOption>,
}

impl ModelTransportCapability {
    pub fn new(format: TransportFormat) -> Self {
        Self {
            format,
            endpoint: None,
            alternatives: Vec::new(),
        }
    }

    pub fn at_endpoint(format: TransportFormat, endpoint: impl Into<String>) -> Self {
        Self {
            format,
            endpoint: Some(endpoint.into()),
            alternatives: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), CapabilityMetadataError> {
        let preferred = TransportOption {
            format: self.format,
            endpoint: self.endpoint.clone(),
        };
        preferred.validate()?;
        let mut options = HashSet::new();
        options.insert(preferred);
        for alternative in &self.alternatives {
            alternative.validate()?;
            if !options.insert(alternative.clone()) {
                return Err(CapabilityMetadataError::validation(
                    "transport alternatives must not duplicate the preferred or another alternative",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportOption {
    pub format: TransportFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl TransportOption {
    pub fn new(format: TransportFormat) -> Self {
        Self {
            format,
            endpoint: None,
        }
    }

    pub fn at_endpoint(format: TransportFormat, endpoint: impl Into<String>) -> Self {
        Self {
            format,
            endpoint: Some(endpoint.into()),
        }
    }

    fn validate(&self) -> Result<(), CapabilityMetadataError> {
        let Some(endpoint) = &self.endpoint else {
            return Ok(());
        };
        if !endpoint.starts_with('/')
            || endpoint.starts_with("//")
            || endpoint.trim() != endpoint
            || endpoint.chars().any(|character| {
                character.is_control()
                    || character.is_whitespace()
                    || matches!(character, '?' | '#' | '\\')
            })
            || endpoint
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
        {
            return Err(CapabilityMetadataError::validation(
                "transport endpoint must be a relative path without query, fragment, whitespace, or dot segments",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportFormat {
    #[serde(rename = "openai-chat")]
    OpenAiChat,
    #[serde(rename = "openai-responses")]
    OpenAiResponses,
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "gemini")]
    Gemini,
    #[serde(rename = "plugin-native")]
    PluginNative,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportCapability {
    pub format: String,
}

impl TransportCapability {
    pub fn new(format: impl Into<String>) -> Self {
        Self {
            format: format.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportCapability {
    pub supported: bool,
}

impl SupportCapability {
    pub fn new(supported: bool) -> Self {
        Self { supported }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisionCapability {
    pub input: bool,
}

impl VisionCapability {
    pub fn new(input: bool) -> Self {
        Self { input }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningMode {
    Toggle,
    Level,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReasoningLevel {
    #[serde(rename = "minimal")]
    Minimal,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "xhigh")]
    XHigh,
    #[serde(rename = "max")]
    Max,
}

impl ReasoningLevel {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "minimal" => Some(Self::Minimal),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "xhigh" => Some(Self::XHigh),
            "max" => Some(Self::Max),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningCapability {
    pub supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ReasoningMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub levels: Option<Vec<ReasoningLevel>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<ReasoningLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_disable: Option<bool>,
}

impl ReasoningCapability {
    pub fn unsupported() -> Self {
        Self {
            supported: false,
            mode: None,
            levels: None,
            default: None,
            can_disable: None,
        }
    }

    pub fn supported_unknown() -> Self {
        Self {
            supported: true,
            mode: None,
            levels: None,
            default: None,
            can_disable: None,
        }
    }

    pub fn toggle(can_disable: bool) -> Self {
        Self {
            supported: true,
            mode: Some(ReasoningMode::Toggle),
            levels: None,
            default: None,
            can_disable: Some(can_disable),
        }
    }

    pub fn level(
        levels: Vec<ReasoningLevel>,
        default: Option<ReasoningLevel>,
        can_disable: bool,
    ) -> Self {
        Self {
            supported: true,
            mode: Some(ReasoningMode::Level),
            levels: Some(levels),
            default,
            can_disable: Some(can_disable),
        }
    }

    pub fn validate(&self) -> Result<(), CapabilityMetadataError> {
        if !self.supported {
            if self.mode.is_some()
                || self.levels.is_some()
                || self.default.is_some()
                || self.can_disable.is_some()
            {
                return Err(CapabilityMetadataError::validation(
                    "unsupported reasoning must not declare mode, levels, default, or can_disable",
                ));
            }
            return Ok(());
        }

        match self.mode {
            None => {
                if self.levels.is_some() || self.default.is_some() {
                    return Err(CapabilityMetadataError::validation(
                        "reasoning levels/default require mode=level",
                    ));
                }
            }
            Some(ReasoningMode::Toggle) => {
                if self.levels.is_some() || self.default.is_some() {
                    return Err(CapabilityMetadataError::validation(
                        "toggle reasoning must not declare levels or default",
                    ));
                }
            }
            Some(ReasoningMode::Level) => {
                let levels = self.levels.as_ref().ok_or_else(|| {
                    CapabilityMetadataError::validation(
                        "level reasoning requires a non-empty levels list",
                    )
                })?;
                if levels.is_empty() {
                    return Err(CapabilityMetadataError::validation(
                        "level reasoning requires a non-empty levels list",
                    ));
                }
                let unique: HashSet<ReasoningLevel> = levels.iter().copied().collect();
                if unique.len() != levels.len() {
                    return Err(CapabilityMetadataError::validation(
                        "reasoning levels must not contain duplicates",
                    ));
                }
                if let Some(default) = self.default {
                    if !levels.contains(&default) {
                        return Err(CapabilityMetadataError::validation(
                            "reasoning default must be present in levels",
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum CapabilityMetadataError {
    Json(serde_json::Error),
    Validation(String),
}

impl CapabilityMetadataError {
    fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }
}

impl fmt::Display for CapabilityMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "invalid capability metadata JSON: {error}"),
            Self::Validation(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for CapabilityMetadataError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pricing_round_trips_through_v1_envelope() {
        let capabilities = ModelCapabilitiesV1 {
            prices: Some(serde_json::json!({
                "input_per_1m": 0.0,
                "output_per_1m": 0.0,
                "cached_per_1m": 0.0,
                "cache_write_per_1m": 0.0,
                "thinking_per_1m": 0.0
            })),
            ..Default::default()
        };

        let encoded = capabilities.to_json().unwrap();
        let decoded = ModelCapabilitiesV1::from_json(&encoded).unwrap();

        assert_eq!(decoded.prices, capabilities.prices);
    }

    #[test]
    fn v2_identity_variant_and_opaque_state_round_trip() {
        let capabilities = ModelCapabilitiesV2 {
            reasoning: Some(ReasoningCapability::level(
                vec![ReasoningLevel::High],
                Some(ReasoningLevel::High),
                false,
            )),
            identity: Some(ModelIdentityV2 {
                canonical_model_id: "google/gemini-3.8-flash".into(),
                variant: Some(ProviderVariantV1 {
                    kind: ProviderVariantKind::ReasoningTier,
                    id: "high".into(),
                    reasoning_level: Some(ReasoningLevel::High),
                    fixed: true,
                }),
            }),
            opaque_state: Some(OpaqueStateCapabilityV1 {
                kind: OpaqueStateCapabilityKind::GeminiThoughtSignature,
                family: "gemini".into(),
                encoding_version: 1,
                placeholder_strategy: Some(OpaqueStatePlaceholderStrategy::Gemini3SkipValidator),
            }),
            ..Default::default()
        };

        let encoded = capabilities.to_json().unwrap();
        let decoded = ModelCapabilitiesV2::from_json(&encoded).unwrap();
        assert_eq!(decoded, capabilities);
    }

    #[test]
    fn v2_rejects_malformed_identity_variant_and_opaque_state() {
        let malformed = [
            serde_json::json!({
                "schema_version": 2,
                "identity": {"canonical_model_id": "gemini-3.8-flash"}
            }),
            serde_json::json!({
                "schema_version": 2,
                "identity": {
                    "canonical_model_id": "google/gemini-3.8-flash",
                    "variant": {
                        "kind": "provider_alias",
                        "id": "alias",
                        "reasoning_level": "high",
                        "fixed": false
                    }
                }
            }),
            serde_json::json!({
                "schema_version": 2,
                "opaque_state": {
                    "kind": "gemini_thought_signature",
                    "family": "bad family",
                    "encoding_version": 1
                }
            }),
            serde_json::json!({
                "schema_version": 2,
                "opaque_state": {
                    "kind": "gemini_thought_signature",
                    "family": "gemini",
                    "encoding_version": 0
                }
            }),
        ];
        for value in malformed {
            assert!(ModelCapabilitiesV2::from_json(&value.to_string()).is_err());
        }
    }

    #[test]
    fn v3_transport_preferences_and_alternatives_round_trip() {
        let mut capabilities = ModelCapabilitiesV3::default();
        capabilities.transport = Some(ModelTransportCapability {
            format: TransportFormat::OpenAiResponses,
            endpoint: Some("/zen/v1/responses".into()),
            alternatives: vec![TransportOption::at_endpoint(
                TransportFormat::OpenAiChat,
                "/zen/v1/chat/completions",
            )],
        });
        capabilities.tools = Some(SupportCapability::new(true));
        capabilities.parallel_tools = Some(SupportCapability::new(true));

        let encoded = capabilities.to_json().unwrap();
        let decoded = ModelCapabilitiesV3::from_json(&encoded).unwrap();
        assert_eq!(decoded, capabilities);
        assert!(encoded.contains("\"format\":\"openai-responses\""));
        assert!(encoded.contains("\"endpoint\":\"/zen/v1/responses\""));
    }

    #[test]
    fn v3_transport_rejects_invalid_endpoints_and_duplicate_options() {
        for endpoint in [
            "https://example.com/path",
            "//example.com/path",
            "/a/../b",
            "/a?query=1",
            "/a#fragment",
            "/a\\\\b",
        ] {
            let mut capabilities = ModelCapabilitiesV3::default();
            capabilities.transport = Some(ModelTransportCapability::at_endpoint(
                TransportFormat::OpenAiChat,
                endpoint,
            ));
            assert!(capabilities.to_json().is_err(), "{endpoint}");
        }

        let mut capabilities = ModelCapabilitiesV3::default();
        let option = TransportOption::at_endpoint(TransportFormat::OpenAiChat, "/chat");
        capabilities.transport = Some(ModelTransportCapability {
            format: option.format,
            endpoint: option.endpoint.clone(),
            alternatives: vec![option],
        });
        assert!(capabilities.to_json().is_err());
    }

    #[test]
    fn v3_parallel_tools_requires_tools() {
        let mut capabilities = ModelCapabilitiesV3::default();
        capabilities.parallel_tools = Some(SupportCapability::new(true));
        assert!(capabilities.to_json().is_err());

        capabilities.tools = Some(SupportCapability::new(false));
        assert!(capabilities.to_json().is_err());

        capabilities.tools = Some(SupportCapability::new(true));
        assert!(capabilities.to_json().is_ok());
    }

    #[test]
    fn v3_rejects_unknown_transport_families() {
        assert!(ModelCapabilitiesV3::from_json(
            r#"{"schema_version":3,"transport":{"preferred":{"format":"unknown"}}}"#
        )
        .is_err());
    }

    #[test]
    fn invalid_prices_are_rejected_by_sdk_producers() {
        let capabilities = ModelCapabilitiesV1 {
            prices: Some(serde_json::json!({
                "input_per_1m": -1.0
            })),
            ..Default::default()
        };

        assert!(capabilities.to_json().is_err());
    }
}
