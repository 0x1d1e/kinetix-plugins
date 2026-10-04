//! Shared conformance suite for Kinetix account model sources.
//!
//! Shared cases (`wit/fixtures/model-discovery/v1/cases.json`) cover the
//! contract every `account-model-source` honors: account ownership, endpoint,
//! credential attachment, and failure classification. A plugin's
//! `discovery-conformance.json` profile declares how it reaches its upstream
//! and carries the provider's own catalog cases (exact `discovered-model`
//! output for a recorded upstream response). The suite drives the compiled
//! component's `account-model-source` export against a scripted host.

use serde::Deserialize;
use serde_json::Value;

#[cfg(any(feature = "runtime", test))]
const CASES: &str = include_str!("../../wit/fixtures/model-discovery/v1/cases.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub source: String,
    pub provider_id: String,
    pub account_id: String,
    pub request: Request,
    pub credential: Credential,
    /// Scripted response of a catalog with no usable model.
    pub empty_response: Value,
    /// Plugin-owned cases in the shared case schema. `baseline` is required:
    /// its response and models stand in for `$baseline` in shared cases.
    pub cases: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub method: String,
    pub endpoint: Endpoint,
}

/// How the request URL is formed.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Endpoint {
    /// `base_url` joined with `models_path`; blank inputs fall back to defaults.
    Derived { default_url: String },
    /// A provider-owned URL; the host-supplied inputs are not used.
    Fixed { url: String },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credential {
    /// The host injects the account credential into the request.
    HostInjected,
    /// The plugin reads a static API key and sends it in a header.
    ApiKey {
        plaintext_template: Value,
        header: Header,
    },
    /// The plugin reads OAuth state and sends the access token in a header.
    Oauth {
        plaintext_template: Value,
        header: Header,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    /// `$secret` stands for the access token or key.
    pub value: String,
}

impl Credential {
    pub fn kind(&self) -> &'static str {
        match self {
            Credential::HostInjected => "host_injected",
            Credential::ApiKey { .. } => "api_key",
            Credential::Oauth { .. } => "oauth",
        }
    }
}

impl Endpoint {
    pub fn kind(&self) -> &'static str {
        match self {
            Endpoint::Derived { .. } => "derived",
            Endpoint::Fixed { .. } => "fixed",
        }
    }
}

/// A case's `when` filter: every listed key must contain the profile's value.
#[cfg(feature = "runtime")]
fn applies(case: &Value, profile: &Profile) -> bool {
    let Some(when) = case.get("when").and_then(Value::as_object) else {
        return true;
    };
    when.iter().all(|(key, allowed)| {
        let actual = match key.as_str() {
            "credential" => profile.credential.kind(),
            "endpoint" => profile.request.endpoint.kind(),
            _ => return false,
        };
        allowed
            .as_array()
            .is_some_and(|allowed| allowed.iter().any(|value| value.as_str() == Some(actual)))
    })
}

/// Replace `$secret` inside every string of `template`.
#[cfg(feature = "runtime")]
fn substitute(template: &Value, secret: &str) -> Value {
    match template {
        Value::String(text) => Value::String(text.replace("$secret", secret)),
        Value::Array(items) => Value::Array(items.iter().map(|v| substitute(v, secret)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), substitute(value, secret)))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(feature = "runtime")]
mod runtime;
#[cfg(feature = "runtime")]
pub use runtime::check;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_cases_have_unique_ids_and_parse() {
        let doc: Value = serde_json::from_str(CASES).unwrap();
        let mut ids = std::collections::BTreeSet::new();
        for case in doc["cases"].as_array().unwrap() {
            assert!(ids.insert(case["id"].as_str().unwrap().to_string()));
        }
        assert!(ids.len() > 15);
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn substitute_replaces_inside_nested_strings() {
        let got = substitute(&serde_json::json!({"a": ["Bearer $secret"], "b": 1}), "k");
        assert_eq!(got, serde_json::json!({"a": ["Bearer k"], "b": 1}));
    }
}
