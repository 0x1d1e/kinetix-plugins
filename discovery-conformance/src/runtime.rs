use super::*;
use anyhow::{bail, ensure, Context, Result};
use kinetix_plugin_component_runtime_conformance::{
    account_ref, build_component, http_outcome, Guest, HostState, Outcome, Val, WireError,
};
use serde_json::json;
use std::path::Path;

const INTERFACE: &str = "account-model-source";

/// Run every applicable shared and plugin-owned case against `package`'s
/// compiled component. Panics with every failing case.
pub fn check(package: &str, profile_json: &str) {
    let profile: Profile = serde_json::from_str(profile_json)
        .unwrap_or_else(|error| panic!("{package}: invalid discovery-conformance.json: {error}"));
    assert_eq!(
        profile.schema_version, 1,
        "{package}: unsupported profile schema_version"
    );
    let component = build_component(package).unwrap_or_else(|e| panic!("{package}: {e:#}"));
    let doc: Value = serde_json::from_str(CASES).expect("discovery cases are JSON");
    let shared = doc["cases"].as_array().expect("cases");
    let baseline = profile
        .cases
        .iter()
        .find(|case| case["id"] == "baseline")
        .unwrap_or_else(|| panic!("{package}: profile has no `baseline` case"));

    let mut failures = Vec::new();
    let mut ran = 0;
    let mut seen = std::collections::BTreeSet::new();
    for case in shared.iter().chain(&profile.cases) {
        let id = case["id"].as_str().unwrap_or("?");
        if !seen.insert(id) {
            failures.push(format!("  {id}: duplicate case id"));
            continue;
        }
        if !applies(case, &profile) {
            continue;
        }
        ran += 1;
        if let Err(error) = run_case(&component, &profile, &doc, baseline, case) {
            failures.push(format!("  {id}: {error:#}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{package}: {} of {ran} discovery conformance cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn expand_http(profile: &Profile, baseline: &Value, case: &Value) -> Result<Vec<Value>> {
    let mut script = Vec::new();
    for item in case["http"].as_array().context("case has no http script")? {
        match item.as_str() {
            Some("$baseline") => script.extend(
                baseline["http"]
                    .as_array()
                    .context("baseline has no http script")?
                    .iter()
                    .cloned(),
            ),
            Some("$empty") => script.push(profile.empty_response.clone()),
            Some(other) => bail!("unknown http reference {other}"),
            None => script.push(item.clone()),
        }
    }
    Ok(script)
}

/// The credential the host returns on read. A case may replace the profile's
/// template with its own `credential_plaintext` (e.g. an expired token).
fn plaintext(profile: &Profile, case: &Value, secret: &str) -> Option<String> {
    match &profile.credential {
        Credential::HostInjected => None,
        Credential::ApiKey {
            plaintext_template, ..
        }
        | Credential::Oauth {
            plaintext_template, ..
        } => Some(
            match substitute(
                case.get("credential_plaintext")
                    .unwrap_or(plaintext_template),
                secret,
            ) {
                Value::String(text) => text,
                other => other.to_string(),
            },
        ),
    }
}

fn run_case(
    component: &Path,
    profile: &Profile,
    doc: &Value,
    baseline: &Value,
    case: &Value,
) -> Result<()> {
    let defaults = &doc["defaults"];
    let text = |value: &Value, fallback: &Value| -> Result<String> {
        let value = if value.is_null() { fallback } else { value };
        Ok(value.as_str().context("expected a string")?.to_string())
    };
    let provider = text(&case["provider_id"], &json!(profile.provider_id))?;
    let account_provider = text(&case["account_provider_id"], &json!(provider))?;
    let base_url = text(&case["base_url"], &defaults["base_url"])?;
    let models_path = text(&case["models_path"], &defaults["models_path"])?;
    let secret = text(&case["secret"], &doc["secret"])?;

    let mut host = HostState {
        now_ms: doc["now_unix_millis"].as_u64().context("now_unix_millis")?,
        ..HostState::default()
    };
    if case["credential_read"] != "fails" {
        host.credential = plaintext(profile, case, &secret);
    }
    for (key, value) in case["storage"].as_object().into_iter().flatten() {
        host.storage.insert(
            key.clone(),
            value.as_str().context("storage value")?.as_bytes().to_vec(),
        );
    }
    for spec in expand_http(profile, baseline, case)? {
        host.http.push_back(http_outcome(&spec)?);
    }

    let mut guest = Guest::instantiate(component, host)?;
    let result = guest.call(
        INTERFACE,
        "discover",
        &[
            Val::String(provider),
            account_ref(&account_provider, &profile.account_id),
            Val::String(base_url),
            Val::String(models_path),
        ],
    )?;

    let expect = &case["expect"];
    if let Some(want) = expect.get("requests") {
        let seen = guest.host().requests.len();
        ensure!(
            want.as_u64() == Some(seen as u64),
            "expected {want} upstream requests, saw {seen}"
        );
    }
    check_credential_reads(&guest, profile, &account_provider)?;
    if expect["catalog_request"] != false && !guest.host().requests.is_empty() {
        check_catalog_request(&guest, profile, doc, case, &account_provider, &secret)?;
    }
    for (index, want) in expect["request_log"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        check_logged_request(&guest, index, want)?;
    }
    for want in expect["storage"].as_array().into_iter().flatten() {
        check_storage(&guest, want)?;
    }

    match (result, expect.get("models"), expect.get("error")) {
        (Outcome::Ok(value), Some(want), None) => {
            let want = if want == "baseline" {
                &baseline["expect"]["models"]
            } else {
                want
            };
            let got = models_json(&value)?;
            ensure!(
                &got == want,
                "models differ\n    expected: {want}\n    actual:   {got}"
            );
            Ok(())
        }
        (Outcome::Err(error), None, Some(want)) => check_error(&error, want, &secret),
        (Outcome::Ok(value), None, _) => bail!("expected an error, got Ok({value})"),
        (Outcome::Err(error), _, None) => bail!("expected success, got {error:?}"),
        _ => bail!("case must expect exactly one of models or error"),
    }
}

/// The plugin may only read the account it was asked about, and a
/// host-injected credential is never read.
fn check_credential_reads(guest: &Guest, profile: &Profile, provider: &str) -> Result<()> {
    let reads = &guest.host().credential_reads;
    if matches!(profile.credential, Credential::HostInjected) {
        ensure!(reads.is_empty(), "host-injected plugin read the credential");
        return Ok(());
    }
    let want = json!({"account": {"provider_id": provider, "account_id": profile.account_id}});
    ensure!(
        reads.iter().all(|read| *read == want),
        "credential read for {reads:?}, expected only {want}"
    );
    Ok(())
}

fn check_catalog_request(
    guest: &Guest,
    profile: &Profile,
    doc: &Value,
    case: &Value,
    provider: &str,
    secret: &str,
) -> Result<()> {
    let request = guest.host().requests.last().context("no request")?;
    ensure!(
        request.method.eq_ignore_ascii_case(&profile.request.method),
        "catalog request used {}, expected {}",
        request.method,
        profile.request.method
    );
    let url = match &profile.request.endpoint {
        Endpoint::Fixed { url } => url.clone(),
        Endpoint::Derived { default_url } => match case["expect"]["url"].as_str() {
            Some("$default") => default_url.clone(),
            Some(url) => url.to_string(),
            None => doc["defaults"]["derived_url"]
                .as_str()
                .context("no expected url")?
                .to_string(),
        },
    };
    ensure!(
        request.url == url,
        "catalog request went to {}, expected {url}",
        request.url
    );
    if !secret.is_empty() {
        let leaked =
            request.url.contains(secret) || String::from_utf8_lossy(&request.body).contains(secret);
        ensure!(!leaked, "the credential appears in the request URL or body");
    }
    match &profile.credential {
        Credential::HostInjected => {
            let want =
                json!({"account": {"provider_id": provider, "account_id": profile.account_id}});
            ensure!(
                request.credential.as_ref() == Some(&want),
                "request credential is {:?}, expected {want}",
                request.credential
            );
        }
        Credential::ApiKey { header, .. } | Credential::Oauth { header, .. } => {
            ensure!(
                request.credential.is_none(),
                "plugin asked the host to inject a credential and also sent its own"
            );
            let want = match case["expect"]["header_value"].as_str() {
                Some(value) => value.to_string(),
                None => header.value.replace("$secret", secret),
            };
            let got = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(&header.name))
                .map(|(_, value)| value);
            ensure!(
                got == Some(&want),
                "header {} is {got:?}, expected {want:?}",
                header.name
            );
        }
    }
    Ok(())
}

/// `{url?, method?, headers?, body_contains?}` for the `index`th request.
fn check_logged_request(guest: &Guest, index: usize, want: &Value) -> Result<()> {
    let request = guest
        .host()
        .requests
        .get(index)
        .with_context(|| format!("request {index} was never sent"))?;
    if let Some(url) = want["url"].as_str() {
        ensure!(
            request.url == url,
            "request {index} went to {}",
            request.url
        );
    }
    if let Some(method) = want["method"].as_str() {
        ensure!(
            request.method.eq_ignore_ascii_case(method),
            "request {index} used {}",
            request.method
        );
    }
    let body = String::from_utf8_lossy(&request.body);
    for part in want["body_contains"].as_array().into_iter().flatten() {
        let part = part.as_str().context("body_contains entry")?;
        ensure!(body.contains(part), "request {index} body lacks {part:?}");
    }
    Ok(())
}

/// `{key, pointer, equals}`: persisted JSON under a storage key.
fn check_storage(guest: &Guest, want: &Value) -> Result<()> {
    let key = want["key"].as_str().context("storage key")?;
    let raw = guest
        .host()
        .storage
        .get(key)
        .with_context(|| format!("nothing persisted under {key}"))?;
    let state: Value = serde_json::from_slice(raw)?;
    let pointer = want["pointer"].as_str().context("storage pointer")?;
    ensure!(
        state.pointer(pointer) == Some(&want["equals"]),
        "{key}{pointer} is {:?}, expected {}",
        state.pointer(pointer),
        want["equals"]
    );
    Ok(())
}

fn check_error(error: &WireError, want: &Value, secret: &str) -> Result<()> {
    if let Some(code) = want.get("code") {
        ensure!(
            code.as_str() == Some(&error.code),
            "expected error code {code}, got {error:?}"
        );
    }
    ensure!(
        want["retryable"].as_bool() == Some(error.retryable),
        "expected retryable={}, got {error:?}",
        want["retryable"]
    );
    if let Some(retry_after) = want.get("retry_after") {
        ensure!(
            retry_after.as_u64() == error.retry_after,
            "expected retry_after {retry_after}, got {:?}",
            error.retry_after
        );
    }
    ensure!(
        secret.is_empty() || !error.message.contains(secret),
        "the error message contains the credential: {}",
        error.message
    );
    Ok(())
}

/// Render `list<discovered-model>` with its JSON-in-string fields parsed, so
/// fixtures state `capabilities` and `raw_metadata` as JSON.
fn models_json(value: &Value) -> Result<Value> {
    let parse = |field: &Value| -> Result<Value> {
        match field {
            Value::Null => Ok(Value::Null),
            Value::String(text) => {
                serde_json::from_str(text).context("model JSON field is not valid JSON")
            }
            other => bail!("model JSON field is {other}"),
        }
    };
    let models = value.as_array().context("discover did not return a list")?;
    models
        .iter()
        .map(|model| {
            Ok(json!({
                "id": model["id"],
                "display_name": model["display_name"],
                "context_window": model["context_window"],
                "max_output_tokens": model["max_output_tokens"],
                "capabilities": parse(&model["capabilities_json"])?,
                "raw_metadata": parse(&model["raw_metadata"])?,
            }))
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}
