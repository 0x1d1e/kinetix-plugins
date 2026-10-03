//! Versioned integration-level feature declarations for plugin manifests.
//!
//! These declarations describe an integration ceiling. A feature is available
//! for a specific model only when both the integration and model metadata
//! declare support.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::model_capabilities::{
    ModelCapabilitiesV1, ModelCapabilitiesV2, ModelCapabilitiesV3, TransportFormat,
};

pub const INTEGRATION_FEATURES_SCHEMA_V1: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationFeaturesV1 {
    pub schema_version: u32,
    pub streaming: bool,
    pub tools: bool,
    pub parallel_tools: bool,
    pub vision: bool,
    pub reasoning: bool,
    pub structured_output: bool,
    pub model_discovery: bool,
    pub quota_probe: bool,
    pub health_probe: bool,
}

impl IntegrationFeaturesV1 {
    pub fn validate(&self) -> Result<(), IntegrationFeaturesError> {
        if self.schema_version != INTEGRATION_FEATURES_SCHEMA_V1 {
            return Err(IntegrationFeaturesError::validation(format!(
                "unsupported schema_version {}; expected {}",
                self.schema_version, INTEGRATION_FEATURES_SCHEMA_V1
            )));
        }
        if self.parallel_tools && !self.tools {
            return Err(IntegrationFeaturesError::validation(
                "parallel_tools requires tools",
            ));
        }
        Ok(())
    }

    pub fn from_json(value: &str) -> Result<Self, IntegrationFeaturesError> {
        let features: Self = serde_json::from_str(value).map_err(IntegrationFeaturesError::Json)?;
        features.validate()?;
        Ok(features)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationProtocolsV1 {
    pub input: Vec<TransportFormat>,
    pub upstream: Vec<TransportFormat>,
}

impl IntegrationProtocolsV1 {
    pub fn validate(&self) -> Result<(), IntegrationFeaturesError> {
        for (name, formats) in [("input", &self.input), ("upstream", &self.upstream)] {
            let unique: HashSet<_> = formats.iter().collect();
            if unique.len() != formats.len() {
                return Err(IntegrationFeaturesError::validation(format!(
                    "protocols.{name} must not contain duplicates"
                )));
            }
        }
        Ok(())
    }
}

/// Result of intersecting integration-level and model-level support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilitySupport {
    Supported,
    Unsupported,
    Unknown,
}

/// A missing declaration remains unknown; either explicit false vetoes support.
pub const fn intersect_support(
    integration: Option<bool>,
    model: Option<bool>,
) -> CapabilitySupport {
    match (integration, model) {
        (Some(false), _) | (_, Some(false)) => CapabilitySupport::Unsupported,
        (Some(true), Some(true)) => CapabilitySupport::Supported,
        _ => CapabilitySupport::Unknown,
    }
}

/// Resolves one of the per-model support values represented in metadata v1.
pub fn model_support(
    integration: Option<bool>,
    model: &ModelCapabilitiesV1,
    feature: ModelFeature,
) -> CapabilitySupport {
    let model = match feature {
        ModelFeature::Tools => model.tools.as_ref().map(|value| value.supported),
        ModelFeature::Vision => model.vision.as_ref().map(|value| value.input),
        ModelFeature::Reasoning => model.reasoning.as_ref().map(|value| value.supported),
        ModelFeature::StructuredOutput => model
            .structured_output
            .as_ref()
            .map(|value| value.supported),
    };
    intersect_support(integration, model)
}

/// Resolves per-model support for metadata v2.
pub fn model_support_v2(
    integration: Option<bool>,
    model: &ModelCapabilitiesV2,
    feature: ModelFeature,
) -> CapabilitySupport {
    let model = match feature {
        ModelFeature::Tools => model.tools.as_ref().map(|value| value.supported),
        ModelFeature::Vision => model.vision.as_ref().map(|value| value.input),
        ModelFeature::Reasoning => model.reasoning.as_ref().map(|value| value.supported),
        ModelFeature::StructuredOutput => model
            .structured_output
            .as_ref()
            .map(|value| value.supported),
    };
    intersect_support(integration, model)
}

/// Resolves per-model support for metadata v3.
pub fn model_support_v3(
    integration: Option<bool>,
    model: &ModelCapabilitiesV3,
    feature: ModelFeatureV3,
) -> CapabilitySupport {
    let model = match feature {
        ModelFeatureV3::Tools => model.tools.as_ref().map(|value| value.supported),
        ModelFeatureV3::ParallelTools => model.parallel_tools.as_ref().map(|value| value.supported),
        ModelFeatureV3::Vision => model.vision.as_ref().map(|value| value.input),
        ModelFeatureV3::Reasoning => model.reasoning.as_ref().map(|value| value.supported),
        ModelFeatureV3::StructuredOutput => model
            .structured_output
            .as_ref()
            .map(|value| value.supported),
    };
    intersect_support(integration, model)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelFeature {
    Tools,
    Vision,
    Reasoning,
    StructuredOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelFeatureV3 {
    Tools,
    ParallelTools,
    Vision,
    Reasoning,
    StructuredOutput,
}

#[derive(Debug)]
pub enum IntegrationFeaturesError {
    Json(serde_json::Error),
    Validation(String),
}

impl IntegrationFeaturesError {
    fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }
}

impl std::fmt::Display for IntegrationFeaturesError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "invalid integration feature JSON: {error}"),
            Self::Validation(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for IntegrationFeaturesError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_capabilities::{
        ModelCapabilitiesV1, ModelCapabilitiesV3, SupportCapability, VisionCapability,
    };

    fn features() -> IntegrationFeaturesV1 {
        IntegrationFeaturesV1 {
            schema_version: 1,
            streaming: true,
            tools: true,
            parallel_tools: true,
            vision: true,
            reasoning: true,
            structured_output: true,
            model_discovery: true,
            quota_probe: false,
            health_probe: false,
        }
    }

    #[test]
    fn versioned_feature_contract_round_trips_and_rejects_unknown_fields() {
        let encoded = serde_json::to_string(&features()).unwrap();
        assert_eq!(
            IntegrationFeaturesV1::from_json(&encoded).unwrap(),
            features()
        );
        assert!(IntegrationFeaturesV1::from_json(
            r#"{"schema_version":1,"streaming":true,"tools":true,"parallel_tools":true,"vision":true,"reasoning":true,"structured_output":true,"model_discovery":true,"quota_probe":false,"health_probe":false,"experimental":true}"#
        )
        .is_err());
        assert!(IntegrationFeaturesV1::from_json(
            r#"{"schema_version":2,"streaming":true,"tools":true,"parallel_tools":true,"vision":true,"reasoning":true,"structured_output":true,"model_discovery":true,"quota_probe":false,"health_probe":false}"#
        )
        .is_err());
    }

    #[test]
    fn parallel_tools_requires_tools() {
        let mut features = features();
        features.tools = false;
        assert!(features.validate().is_err());

        features.parallel_tools = false;
        assert!(features.validate().is_ok());
    }

    #[test]
    fn explicit_model_false_narrows_integration_support() {
        let model = ModelCapabilitiesV1 {
            tools: Some(SupportCapability::new(true)),
            vision: Some(VisionCapability::new(false)),
            ..Default::default()
        };

        assert_eq!(
            model_support(Some(true), &model, ModelFeature::Tools),
            CapabilitySupport::Supported
        );
        assert_eq!(
            model_support(Some(true), &model, ModelFeature::Vision),
            CapabilitySupport::Unsupported
        );
        assert_eq!(
            model_support(Some(true), &model, ModelFeature::Reasoning),
            CapabilitySupport::Unknown
        );
        assert_eq!(
            model_support(Some(false), &model, ModelFeature::Tools),
            CapabilitySupport::Unsupported
        );
    }

    #[test]
    fn v3_parallel_tools_support_is_narrowed_per_model() {
        let model = ModelCapabilitiesV3 {
            tools: Some(SupportCapability::new(true)),
            parallel_tools: Some(SupportCapability::new(false)),
            ..Default::default()
        };

        assert_eq!(
            model_support_v3(Some(true), &model, ModelFeatureV3::Tools),
            CapabilitySupport::Supported
        );
        assert_eq!(
            model_support_v3(Some(true), &model, ModelFeatureV3::ParallelTools),
            CapabilitySupport::Unsupported
        );
        assert_eq!(
            model_support_v3(None, &model, ModelFeatureV3::Vision),
            CapabilitySupport::Unknown
        );
    }

    #[test]
    fn protocol_lists_reject_duplicate_values() {
        let protocols = IntegrationProtocolsV1 {
            input: vec![TransportFormat::OpenAiChat, TransportFormat::OpenAiChat],
            upstream: vec![],
        };
        assert!(protocols.validate().is_err());
    }
}
