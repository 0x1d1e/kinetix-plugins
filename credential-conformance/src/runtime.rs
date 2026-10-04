use super::*;
use anyhow::{anyhow, bail, ensure, Context, Result};
use kinetix_plugin_component_runtime_conformance::{
    build_component, Guest, HostState, HttpOutcome, HttpResponse, Outcome, Val, WireError,
};
use kinetix_plugin_sdk::oauth::{format_rfc3339_ms, parse_rfc3339_ms};
use std::path::Path;

const INTERFACE: &str = "credential-strategy";

/// Run every applicable canonical case against `package`'s compiled component.
/// Panics with every failing case so one run reports all regressions.
pub fn check(package: &str, profile_json: &str) {
    let profile: Profile = serde_json::from_str(profile_json)
        .unwrap_or_else(|error| panic!("{package}: invalid credential-conformance.json: {error}"));
    assert_eq!(
        profile.schema_version, 1,
        "{package}: unsupported profile schema_version"
    );
    let component = build_component(package).unwrap_or_else(|e| panic!("{package}: {e:#}"));
    let doc: Value = serde_json::from_str(CASES).expect("credential cases are JSON");
    let now = doc["now_unix_millis"].as_u64().expect("now_unix_millis");
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in doc["cases"].as_array().expect("cases") {
        if !applies(case, &profile.policy) {
            continue;
        }
        ran += 1;
        if let Err(error) = run_case(&component, &profile, now, case) {
            failures.push(format!(
                "  {}: {error:#}",
                case["id"].as_str().unwrap_or("?")
            ));
        }
    }
    assert!(ran > 0, "{package}: no credential conformance case applied");
    assert!(
        failures.is_empty(),
        "{package}: {} of {ran} credential conformance cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn expiry_ms(spec: &Value, now: u64, lead: u64) -> Result<Option<u64>> {
    if spec.is_null() {
        return Ok(None);
    }
    let (base, delta) = if let Some(delta) = spec.get("window_delta_ms") {
        (now as i128 + lead as i128, delta)
    } else if let Some(delta) = spec.get("in_ms") {
        (now as i128, delta)
    } else {
        bail!("unknown expiry spec {spec}");
    };
    let at = base + delta.as_i64().context("expiry delta")? as i128;
    Ok(Some(u64::try_from(at).context("expiry before epoch")?))
}

fn render_credential(profile: &Profile, now: u64, spec: &Value) -> Result<(String, Option<u64>)> {
    let expiry = expiry_ms(&spec["expiry"], now, profile.policy.refresh_lead_ms)?;
    let mut values: BTreeMap<&str, Value> = BTreeMap::new();
    for key in ["access_token", "refresh_token"] {
        if let Some(value) = spec.get(key) {
            values.insert(key, value.clone());
        }
    }
    if let Some(ms) = expiry {
        values.insert("expires_at_ms", ms.into());
        values.insert(
            "expiry_rfc3339",
            format_rfc3339_ms(ms).context("format expiry")?.into(),
        );
    }
    Ok((
        substitute(&profile.credential_template, &values).to_string(),
        expiry,
    ))
}

fn outcome(spec: &Value) -> Result<HttpOutcome> {
    if let Some(failure) = spec.get("failure") {
        return Ok(HttpOutcome::Failure(WireError {
            code: failure["code"].as_str().context("failure code")?.into(),
            message: failure["message"].as_str().unwrap_or("").into(),
            retryable: failure["retryable"].as_bool().unwrap_or(false),
            retry_after: failure["retry_after"].as_u64(),
            reset_at: None,
        }));
    }
    let body = if let Some(json) = spec.get("json") {
        json.to_string().into_bytes()
    } else if let Some(text) = spec.get("text") {
        text.as_str().context("text body")?.as_bytes().to_vec()
    } else if let Some(hex) = spec.get("hex") {
        let hex = hex.as_str().context("hex body")?;
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<_, _>>()?
    } else {
        Vec::new()
    };
    Ok(HttpOutcome::Response(HttpResponse {
        status: spec["status"].as_u64().context("status")? as u16,
        headers: Vec::new(),
        body,
        truncated: spec["truncated"].as_bool().unwrap_or(false),
    }))
}

fn run_case(component: &Path, profile: &Profile, now: u64, case: &Value) -> Result<()> {
    let mut host = HostState {
        now_ms: now,
        ..HostState::default()
    };
    let mut imported_expiry = None;
    if !case["credential"].is_null() {
        let (raw, expiry) = render_credential(profile, now, &case["credential"])?;
        host.credential = Some(raw);
        imported_expiry = expiry;
    }
    for spec in case["http"].as_array().context("http")? {
        host.http.push_back(outcome(spec)?);
    }
    let mut guest = Guest::instantiate(component, host)?;
    for (index, step) in case["steps"]
        .as_array()
        .context("steps")?
        .iter()
        .enumerate()
    {
        if let Some(ms) = step.get("advance_ms") {
            guest.host_mut().now_ms += ms.as_u64().context("advance_ms")?;
            continue;
        }
        run_step(&mut guest, profile, imported_expiry, step)
            .with_context(|| format!("step {index} ({})", step["call"]))?;
    }
    Ok(())
}

fn run_step(
    guest: &mut Guest,
    profile: &Profile,
    imported_expiry: Option<u64>,
    step: &Value,
) -> Result<()> {
    let call = step["call"].as_str().context("call")?;
    let expect = &step["expect"];
    let before = guest.host().storage.clone();
    let requests_before = guest.host().requests.len();
    let mut params = vec![
        Val::String(profile.provider_id.clone()),
        Val::String(profile.account_id.clone()),
    ];
    if call == "resolve" {
        params.push(Val::String("Conformance Account".into()));
    }
    let result = guest.call(INTERFACE, call, &params)?;

    let requests = guest.host().requests.len() - requests_before;
    if let Some(want) = expect.get("requests") {
        ensure!(
            want.as_u64() == Some(requests as u64),
            "expected {want} upstream requests, saw {requests}"
        );
    }
    let storage = &guest.host().storage;
    if expect.get("storage_unchanged") == Some(&Value::Bool(true)) {
        ensure!(
            *storage == before,
            "a failed operation changed host storage"
        );
    }

    match (result, expect.get("ok"), expect.get("error")) {
        (Outcome::Ok(value), Some(ok), None) => check_ok(
            guest,
            profile,
            imported_expiry,
            call,
            &value,
            ok,
            requests_before,
        ),
        (Outcome::Err(error), None, Some(want)) => check_error(&error, want),
        (Outcome::Ok(value), None, _) => bail!("expected an error, got Ok({value})"),
        (Outcome::Err(error), _, None) => bail!("expected success, got {error:?}"),
        _ => bail!("step must expect exactly one of ok or error"),
    }
}

fn check_error(error: &WireError, want: &Value) -> Result<()> {
    ensure!(
        want["code"].as_str() == Some(&error.code),
        "expected error code {}, got {error:?}",
        want["code"]
    );
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
    Ok(())
}

fn persisted_state(guest: &Guest, profile: &Profile) -> Result<Option<Value>> {
    let mut found = guest
        .host()
        .storage
        .iter()
        .filter(|(key, _)| key.starts_with(&profile.state.key_prefix));
    let Some((key, raw)) = found.next() else {
        return Ok(None);
    };
    ensure!(
        found.next().is_none(),
        "more than one persisted state key under {}",
        profile.state.key_prefix
    );
    serde_json::from_slice(raw)
        .map(Some)
        .with_context(|| format!("persisted state {key} is not JSON"))
}

fn state_expiry(state: &Value, profile: &Profile) -> Result<Option<u64>> {
    match state.pointer(&profile.state.expiry.pointer) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => match profile.state.expiry.encoding.as_str() {
            "unix_ms" => Ok(Some(
                value.as_u64().context("persisted expiry is not a u64")?,
            )),
            "rfc3339" => Ok(Some(
                parse_rfc3339_ms(value.as_str().context("persisted expiry is not a string")?)
                    .context("persisted expiry is not RFC3339")?,
            )),
            other => bail!("unknown expiry encoding {other}"),
        },
    }
}

fn check_ok(
    guest: &Guest,
    profile: &Profile,
    imported_expiry: Option<u64>,
    call: &str,
    value: &Value,
    ok: &Value,
    requests_before: usize,
) -> Result<()> {
    let now = guest.host().now_ms;
    if let Some(want) = ok.get("health") {
        ensure!(value == want, "expected health {want}, got {value}");
    }
    if let Some(want) = ok.get("refresh_token_sent") {
        let request = guest.host().requests[requests_before..]
            .last()
            .context("no refresh request was sent")?;
        ensure!(
            request.url == profile.refresh.url,
            "refresh went to {}",
            request.url
        );
        ensure!(
            request.method.eq_ignore_ascii_case("POST"),
            "refresh used {}",
            request.method
        );
        let sent = refresh_token_in(profile, &request.body)?;
        ensure!(
            want.as_str() == Some(&sent),
            "sent refresh token {sent:?}, expected {want}"
        );
    }
    let state = persisted_state(guest, profile)?;
    if let Some(want) = ok.get("persisted") {
        let state = state.as_ref().context("nothing was persisted")?;
        for (key, pointer) in [
            ("access_token", &profile.state.access_token),
            ("refresh_token", &profile.state.refresh_token),
        ] {
            if let Some(want) = want.get(key) {
                ensure!(
                    state.pointer(pointer) == Some(want),
                    "persisted {key} is {:?}, expected {want}",
                    state.pointer(pointer)
                );
            }
        }
        if let Some(want) = want.get("expiry") {
            let expected = if want.as_str() == Some("per_policy") {
                profile.policy.default_ttl_ms().map(|ttl| now + ttl)
            } else {
                expiry_ms(want, now, profile.policy.refresh_lead_ms)?
            };
            let actual = state_expiry(state, profile)?;
            ensure!(
                actual == expected,
                "persisted expiry is {actual:?}, expected {expected:?}"
            );
        }
    }
    if call == "resolve" {
        check_lease(guest, profile, imported_expiry, state.as_ref(), value, ok)?;
    }
    Ok(())
}

fn check_lease(
    guest: &Guest,
    profile: &Profile,
    imported_expiry: Option<u64>,
    state: Option<&Value>,
    lease: &Value,
    ok: &Value,
) -> Result<()> {
    let handle = lease["handle"].as_str().context("lease has no handle")?;
    let key = format!("{}{handle}", profile.lease_key_prefix);
    let leased = guest
        .host()
        .storage
        .get(&key)
        .with_context(|| format!("no leased token under {key}"))?;
    let leased = String::from_utf8(leased.clone()).context("leased token is not UTF-8")?;
    ensure!(
        !lease.to_string().contains(&leased),
        "the access token appears in the lease return value"
    );
    if let Some(want) = ok.get("leased_access_token") {
        ensure!(
            want.as_str() == Some(&leased),
            "leased {leased:?}, expected {want}"
        );
    }
    if let Some(want) = ok.get("lease_health") {
        ensure!(
            &lease["health"] == want,
            "lease health is {}, expected {want}",
            lease["health"]
        );
    }
    // The lease may not claim an expiry the persisted (or imported) state lacks.
    let known = match state {
        Some(state) => state_expiry(state, profile)?,
        None => imported_expiry,
    };
    let claimed = match lease["expires_at"].as_str() {
        Some(text) => Some(
            parse_rfc3339_ms(text)
                .ok_or_else(|| anyhow!("lease expires_at {text:?} is not RFC3339"))?,
        ),
        None => None,
    };
    ensure!(
        claimed == known,
        "lease expires_at is {claimed:?} but credential state expires at {known:?}"
    );
    Ok(())
}

fn refresh_token_in(profile: &Profile, body: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(body).context("refresh body is not UTF-8")?;
    let field = &profile.refresh.refresh_token_field;
    match profile.refresh.encoding.as_str() {
        "json" => serde_json::from_str::<Value>(text)?[field.as_str()]
            .as_str()
            .map(str::to_string)
            .with_context(|| format!("refresh body has no {field}")),
        "form" => text
            .split('&')
            .find_map(|pair| pair.split_once('=').filter(|(k, _)| k == field))
            .map(|(_, v)| percent_decode(v))
            .with_context(|| format!("refresh form has no {field}")),
        other => bail!("unknown refresh encoding {other}"),
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
