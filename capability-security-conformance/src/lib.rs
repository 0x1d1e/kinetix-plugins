//! Adversarial guest for host conformance, never a marketplace plugin.
//! `health-probe.probe` accepts a JSON operation in `account-id`.
//! WASM-only: never expose adversarial guest exports as a native library.

#![cfg(target_arch = "wasm32")]

use kinetix::plugin::{host_clock, host_credential, host_http, host_log, host_storage, types::*};
use serde_json::Value;

wit_bindgen::generate!({
    path: "../wit",
    world: "plugin",
});

struct Component;

fn error(message: impl Into<String>) -> PluginError {
    PluginError {
        code: "fixture_error".into(),
        message: message.into(),
        retryable: false,
        retry_after: None,
        reset_at: None,
    }
}

fn text<'a>(operation: &'a Value, name: &str) -> Result<&'a str, PluginError> {
    operation[name]
        .as_str()
        .ok_or_else(|| error(format!("missing {name}")))
}

fn credential(operation: &Value) -> Result<CredentialRef, PluginError> {
    if let Some(named) = operation["named"].as_str() {
        return Ok(CredentialRef::Named(named.into()));
    }
    Ok(CredentialRef::Account(AccountRef {
        provider_id: text(operation, "provider")?.into(),
        account_id: text(operation, "account")?.into(),
    }))
}

fn request(operation: &Value) -> Result<HttpRequest, PluginError> {
    Ok(HttpRequest {
        method: "POST".into(),
        url: text(operation, "url")?.into(),
        headers: Vec::new(),
        body: vec![b'x'; operation["bytes"].as_u64().unwrap_or(0) as usize],
        credential: if operation.get("provider").is_some() || operation.get("named").is_some() {
            Some(credential(operation)?)
        } else {
            None
        },
    })
}

fn probe(operation: &Value) -> Result<String, PluginError> {
    match text(operation, "op")? {
        "http" => {
            let mut response = None;
            for _ in 0..operation["repeat"].as_u64().unwrap_or(1) {
                response = Some(host_http::send(&request(operation)?)?);
            }
            let response = response.ok_or_else(|| error("zero requests"))?;
            Ok(serde_json::json!({
                "status": response.status,
                "body_bytes": response.body.len(),
                "truncated": response.body_truncated,
            })
            .to_string())
        }
        "read" => host_credential::read(&credential(operation)?),
        "lease" => host_credential::lease(&credential(operation)?),
        "sign" => {
            let signed = host_credential::sign(&request(operation)?, &credential(operation)?)?;
            // Deliberately expose the returned headers to detect plaintext leakage.
            Ok(serde_json::to_string(&signed.headers).unwrap())
        }
        "put" => {
            host_storage::put(
                &text(operation, "key")?
                    .repeat(operation["key_repeat"].as_u64().unwrap_or(1) as usize),
                &vec![b'x'; operation["bytes"].as_u64().unwrap_or(0) as usize],
            )
            .map_err(error)?;
            Ok("stored".into())
        }
        "get" => Ok(serde_json::to_string(&host_storage::get(text(operation, "key")?)).unwrap()),
        "delete" => {
            host_storage::delete(text(operation, "key")?).map_err(error)?;
            Ok("deleted".into())
        }
        "cache-set" => {
            host_storage::cache_set("fixture", "{}", 1000).map_err(error)?;
            Ok("cached".into())
        }
        "log" => {
            let message = text(operation, "message")?
                .repeat(operation["message_repeat"].as_u64().unwrap_or(1) as usize);
            for _ in 0..operation["repeat"].as_u64().unwrap_or(1) {
                host_log::log(host_log::Level::Info, &message);
            }
            Ok("logged".into())
        }
        "error" => Err(error(text(operation, "message")?)),
        "clock" => Ok(host_clock::now_unix_millis().to_string()),
        other => Err(error(format!("unknown operation {other}"))),
    }
}

impl exports::health_probe::Guest for Component {
    fn probe(_provider_id: String, operation: String) -> Result<HealthObservation, PluginError> {
        let operation: Value =
            serde_json::from_str(&operation).map_err(|_| error("invalid JSON"))?;
        Ok(HealthObservation {
            state: "unknown".into(),
            quota_state: None,
            reset_at: None,
            retry_after: None,
            detail_code: Some(probe(&operation)?),
        })
    }
}

// Typed API-v1 hosts require the complete world's exports. The manifest only
// provides health probes: other exports reject invocation without host calls.
fn deny_undeclared<T>() -> Result<T, PluginError> {
    Err(PluginError {
        code: "permission_denied".into(),
        message: "fixture manifest only provides health probes".into(),
        retryable: false,
        retry_after: None,
        reset_at: None,
    })
}

impl exports::credential_strategy::Guest for Component {
    fn resolve(_: String, _: String, _: String) -> Result<CredentialLease, PluginError> {
        deny_undeclared()
    }
    fn health(_: String, _: String) -> Result<String, PluginError> {
        deny_undeclared()
    }
    fn rotate(_: String, _: String) -> Result<(), PluginError> {
        deny_undeclared()
    }
}
impl exports::model_source::Guest for Component {
    fn discover(_: String, _: String, _: String) -> Result<Vec<DiscoveredModel>, PluginError> {
        deny_undeclared()
    }
}
impl exports::routing_facts::Guest for Component {
    fn facts(_: String) -> Result<Vec<RoutingFact>, PluginError> {
        deny_undeclared()
    }
}
impl exports::hooks::Guest for Component {
    fn on_request_normalized(_: String) -> Result<(), PluginError> {
        deny_undeclared()
    }
    fn on_target_candidate(_: String) -> Result<(), PluginError> {
        deny_undeclared()
    }
    fn on_usage_finalized(_: String) -> Result<(), PluginError> {
        deny_undeclared()
    }
}

export!(Component);
