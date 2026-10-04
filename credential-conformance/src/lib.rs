//! Shared conformance suite for Kinetix credential strategies.
//!
//! Cases are canonical (`wit/fixtures/credential-strategy/v1/cases.json`) and
//! describe credential state abstractly. A plugin's `credential-conformance.json`
//! profile maps that state to the plugin's own credential and storage shapes and
//! declares the policy choices the contract leaves open. The suite drives the
//! compiled component's `credential-strategy` exports against a scripted host,
//! so the production entrypoint, not a test shim, is what is checked.

use serde::Deserialize;
use serde_json::Value;
#[cfg(any(feature = "runtime", test))]
use std::collections::BTreeMap;

const CASES: &str = include_str!("../../wit/fixtures/credential-strategy/v1/cases.json");

/// A plugin's mapping from canonical cases to its own credential shape.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub strategy: String,
    pub provider_id: String,
    pub account_id: String,
    /// Credential JSON as the host stores it. A string value that is exactly
    /// `$access_token`, `$refresh_token`, `$expires_at_ms` or `$expiry_rfc3339`
    /// is replaced by the case value; the key is dropped when the case omits it.
    pub credential_template: Value,
    pub refresh: Refresh,
    pub state: State,
    pub lease_key_prefix: String,
    pub policy: Policy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refresh {
    pub url: String,
    /// `json` or `form`.
    pub encoding: String,
    pub refresh_token_field: String,
}

/// Where the plugin persists rotated lifecycle state in host storage.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub key_prefix: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expiry: StateExpiry,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateExpiry {
    pub pointer: String,
    /// `unix_ms` or `rfc3339`.
    pub encoding: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub refresh_lead_ms: u64,
    /// `trust` or `refresh`: handling of a stored access token with no expiry.
    pub missing_expiry_on_stored_token: String,
    /// `"none"`, or `{"default_ttl_secs": N}`: the lifetime applied to a refresh
    /// response that has no `expires_in`.
    pub missing_expires_in: Value,
}

impl Policy {
    /// Lifetime a refresh response without `expires_in` gets, if any.
    pub fn default_ttl_ms(&self) -> Option<u64> {
        match &self.missing_expires_in {
            Value::String(text) if text == "none" => None,
            other => Some(
                other["default_ttl_secs"]
                    .as_u64()
                    .expect("missing_expires_in must be \"none\" or {\"default_ttl_secs\": N}")
                    * 1000,
            ),
        }
    }

    #[cfg(any(feature = "runtime", test))]
    fn tag(&self, key: &str) -> Option<&str> {
        match key {
            "missing_expiry_on_stored_token" => Some(&self.missing_expiry_on_stored_token),
            _ => None,
        }
    }
}

/// Case ids a profile must run; used to prove the fixture was not emptied.
pub fn case_ids() -> Vec<String> {
    let doc: Value = serde_json::from_str(CASES).expect("credential cases are JSON");
    doc["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| case["id"].as_str().expect("case id").to_string())
        .collect()
}

#[cfg(any(feature = "runtime", test))]
fn applies(case: &Value, policy: &Policy) -> bool {
    let Some(when) = case.get("when").and_then(Value::as_object) else {
        return true;
    };
    when.iter()
        .all(|(key, want)| policy.tag(key).map(Value::from).as_ref() == Some(want))
}

#[cfg(any(feature = "runtime", test))]
fn substitute(template: &Value, values: &BTreeMap<&str, Value>) -> Value {
    match template {
        Value::String(text) if text.starts_with('$') => {
            values.get(&text[1..]).cloned().unwrap_or(Value::Null)
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .filter_map(|(key, value)| {
                    let replaced = substitute(value, values);
                    let dropped =
                        value.as_str().is_some_and(|t| t.starts_with('$')) && replaced.is_null();
                    (!dropped).then(|| (key.clone(), replaced))
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(feature = "runtime")]
mod runtime;
#[cfg(feature = "runtime")]
pub use runtime::check;
