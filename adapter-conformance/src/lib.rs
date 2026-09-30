//! Shared semantic conformance checks for Kinetix provider adapters.
//!
//! This crate is a dev-dependency only. Adapter crates provide a thin bridge
//! to their private implementation and a JSON profile declaring support per
//! upstream transport. The same Kinetix request/response fixtures then check
//! that supported semantics survive translation and unsupported semantics are
//! rejected explicitly.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{json, Value};

const REQUEST_TEXT: &str = include_str!("../../wit/fixtures/plugin-adapter/v1/requests/text.json");
const REQUEST_IMAGE: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/image.json");
const REQUEST_REASONING: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/reasoning.json");
const REQUEST_TOOL_CALL: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/tool-call.json");
const REQUEST_PARALLEL_TOOLS: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/parallel-tools.json");
const REQUEST_TOOL_CONTINUATION: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/tool-result-continuation.json");
const REQUEST_SCHEMA: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/structured-schema.json");
const REQUEST_SCHEMA_MAX_LENGTH: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/schema-max-length.json");
const REQUEST_MALFORMED_TOOL_ARGUMENTS: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/malformed-tool-arguments.json");
const REQUEST_MALFORMED_TOOL_HISTORY: &str =
    include_str!("../../wit/fixtures/plugin-adapter/v1/requests/malformed-tool-history.json");
const REQUEST_MIXED: &str =
    include_str!("../../wit/fixtures/plugin-request/v1/mixed-vision-tools-reasoning.json");
const RESPONSE_FIXTURES: &str = include_str!("../../wit/fixtures/plugin-adapter/v1/responses.json");
const CANONICAL_RESPONSE_FIXTURE: &str =
    include_str!("../../wit/fixtures/plugin-response/v1/parallel-tools-reasoning.json");

const REQUIRED_CAPABILITIES: &[&str] = &[
    "text_generation",
    "streaming",
    "non_streaming",
    "tool_calls",
    "parallel_tool_calls",
    "tool_result_continuation",
    "image_input",
    "reasoning_controls",
    "reasoning_output",
    "structured_schemas",
    "schema_max_length",
    "stop_reasons",
    "usage_extraction",
    "error_classification",
    "client_cancellation",
];

/// Adapter entry points exercised by the reusable fixture suite.
pub trait Adapter {
    fn build_body(&self, request: &Value, provider: &Value, model: &Value)
        -> Result<Value, String>;

    fn parse_stream_chunk(&self, chunk: &Value) -> Result<Value, String>;
    fn parse_full_response(&self, response: &Value) -> Result<Value, String>;
    fn classify_error(&self, status: u16, body: &Value, headers: &Value) -> Result<Value, String>;
}

#[derive(Debug, Deserialize)]
struct Profile {
    schema_version: u32,
    adapter: String,
    transports: Vec<TransportProfile>,
}

#[derive(Debug, Deserialize)]
struct TransportProfile {
    format: String,
    model: Value,
    #[serde(default = "empty_object")]
    provider: Value,
    capabilities: BTreeMap<String, CapabilityStatus>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CapabilityStatus {
    Supported,
    Unsupported,
    NotApplicable,
}

fn empty_object() -> Value {
    json!({})
}

/// Run the complete shared fixture set against every declared transport.
pub fn check(adapter: &impl Adapter, profile_json: &str) -> Result<(), String> {
    let profile: Profile = serde_json::from_str(profile_json)
        .map_err(|error| format!("invalid adapter conformance profile: {error}"))?;
    if profile.schema_version != 1 {
        return Err(format!(
            "{} profile has unsupported schema_version {}",
            profile.adapter, profile.schema_version
        ));
    }
    if profile.adapter.trim().is_empty() || profile.transports.is_empty() {
        return Err("adapter profile requires a name and at least one transport".into());
    }

    let responses: Value = serde_json::from_str(RESPONSE_FIXTURES)
        .expect("shared adapter response fixtures must be valid JSON");
    let protocol_fixtures = responses
        .get("transports")
        .and_then(Value::as_object)
        .expect("response fixtures must contain transports");
    let canonical_response: Value = serde_json::from_str(CANONICAL_RESPONSE_FIXTURE)
        .expect("canonical plugin response fixture must be valid JSON");
    let canonical_events = canonical_response["events"]
        .as_array()
        .expect("canonical plugin response fixture must contain events");
    let mut formats = BTreeSet::new();

    for transport in &profile.transports {
        if !formats.insert(transport.format.as_str()) {
            return Err(format!(
                "{} declares transport '{}' more than once",
                profile.adapter, transport.format
            ));
        }
        validate_capabilities(&profile.adapter, transport)?;
        let context = format!("{} / {}", profile.adapter, transport.format);

        check_request_feature(
            adapter,
            &context,
            transport,
            "text_generation",
            REQUEST_TEXT,
            &["conformance text"],
        )?;
        check_request_feature(
            adapter,
            &context,
            transport,
            "image_input",
            REQUEST_IMAGE,
            &["QUJD"],
        )?;
        check_reasoning(adapter, &context, transport)?;
        check_request_feature(
            adapter,
            &context,
            transport,
            "tool_calls",
            REQUEST_TOOL_CALL,
            &["read_file", "src/main.rs"],
        )?;
        check_request_feature(
            adapter,
            &context,
            transport,
            "parallel_tool_calls",
            REQUEST_PARALLEL_TOOLS,
            &["get_weather", "read_file", "Paris", "src/main.rs"],
        )?;
        check_request_feature(
            adapter,
            &context,
            transport,
            "tool_result_continuation",
            REQUEST_TOOL_CONTINUATION,
            &["read_file", "fn main() {}"],
        )?;
        check_request_feature(
            adapter,
            &context,
            transport,
            "structured_schemas",
            REQUEST_SCHEMA,
            &["query", "required", "Search files"],
        )?;
        check_request_feature(
            adapter,
            &context,
            transport,
            "schema_max_length",
            REQUEST_SCHEMA_MAX_LENGTH,
            &["maxLength", "32"],
        )?;
        check_malformed_tool_arguments(adapter, &context, transport)?;
        check_malformed_tool_history(adapter, &context, transport)?;
        check_mixed_request(adapter, &context, transport)?;

        let response_fixture = protocol_fixtures
            .get(&transport.format)
            .ok_or_else(|| format!("{context} has no shared response fixture"))?;
        check_expected_response_fixture(&context, response_fixture, canonical_events)?;
        check_response_feature(
            adapter,
            &context,
            transport,
            response_fixture,
            "streaming",
            true,
        )?;
        check_response_feature(
            adapter,
            &context,
            transport,
            response_fixture,
            "non_streaming",
            false,
        )?;
        check_stop_reasons(adapter, &context, transport, response_fixture)?;
        check_error_classification(adapter, &context, transport)?;
    }

    Ok(())
}

fn validate_capabilities(adapter: &str, transport: &TransportProfile) -> Result<(), String> {
    let found: BTreeSet<_> = transport.capabilities.keys().map(String::as_str).collect();
    let required: BTreeSet<_> = REQUIRED_CAPABILITIES.iter().copied().collect();
    let missing: Vec<_> = required.difference(&found).copied().collect();
    let unknown: Vec<_> = found.difference(&required).copied().collect();
    if !missing.is_empty() || !unknown.is_empty() {
        return Err(format!(
            "{adapter} / {} capability declaration mismatch; missing: [{}], unknown: [{}]",
            transport.format,
            missing.join(", "),
            unknown.join(", ")
        ));
    }
    for dependent in ["parallel_tool_calls", "tool_result_continuation"] {
        if transport.capabilities[dependent] == CapabilityStatus::Supported
            && transport.capabilities["tool_calls"] != CapabilityStatus::Supported
        {
            return Err(format!(
                "{adapter} / {} declares {dependent} supported without tool_calls",
                transport.format
            ));
        }
    }
    if transport.capabilities["schema_max_length"] == CapabilityStatus::Supported
        && transport.capabilities["structured_schemas"] != CapabilityStatus::Supported
    {
        return Err(format!(
            "{adapter} / {} declares schema_max_length supported without structured_schemas",
            transport.format
        ));
    }
    if transport.capabilities["client_cancellation"] != CapabilityStatus::NotApplicable {
        return Err(format!(
            "{adapter} / {} must mark client_cancellation not_applicable; cancellation is outside the adapter test seam",
            transport.format
        ));
    }
    Ok(())
}

fn parse_fixture(raw: &str) -> Value {
    serde_json::from_str(raw).expect("shared adapter request fixture must be valid JSON")
}

fn check_request_feature(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
    capability: &str,
    fixture: &str,
    markers: &[&str],
) -> Result<(), String> {
    let request = parse_fixture(fixture);
    match transport.capabilities[capability] {
        CapabilityStatus::Supported => {
            let body = adapter
                .build_body(&request, &transport.provider, &transport.model)
                .map_err(|error| {
                    format!("{context} declares {capability} supported but rejected it: {error}")
                })?;
            let serialized = body.to_string();
            for marker in markers {
                if !serialized.contains(marker) {
                    return Err(format!(
                        "{context} silently lost {capability} marker '{marker}'"
                    ));
                }
            }
            if transport.format != "antigravity" {
                let identities: &[&str] = match capability {
                    "tool_calls" => &["call_read"],
                    "parallel_tool_calls" => &["call_weather", "call_read"],
                    "tool_result_continuation" => &["call_read"],
                    _ => &[],
                };
                for id in identities {
                    if !serialized.contains(id) {
                        return Err(format!(
                            "{context} silently lost {capability} identity '{id}'"
                        ));
                    }
                }
            }
            if capability == "reasoning_controls" && transport.format == "antigravity" {
                if body.pointer("/request/generationConfig/thinkingConfig/thinkingLevel")
                    != Some(&json!("high"))
                {
                    return Err(format!(
                        "{context} did not map high reasoning effort to Gemini thinkingLevel"
                    ));
                }
            }
            Ok(())
        }
        CapabilityStatus::Unsupported => expect_unsupported(
            context,
            capability,
            adapter.build_body(&request, &transport.provider, &transport.model),
        ),
        CapabilityStatus::NotApplicable => Ok(()),
    }
}

fn check_reasoning(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    check_request_feature(
        adapter,
        context,
        transport,
        "reasoning_controls",
        REQUEST_REASONING,
        &["thinking", "high"],
    )
}

fn expect_unsupported<T>(
    context: &str,
    capability: &str,
    result: Result<T, String>,
) -> Result<(), String> {
    match result {
        Ok(_) => Err(format!(
            "{context} declares {capability} unsupported but accepted it"
        )),
        Err(error) => {
            let lower = error.to_ascii_lowercase();
            if lower.contains("unsupported") || lower.contains("not support") {
                Ok(())
            } else {
                Err(format!(
                    "{context} must explicitly reject unsupported {capability}; got: {error}"
                ))
            }
        }
    }
}

fn check_malformed_tool_arguments(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    let request = parse_fixture(REQUEST_MALFORMED_TOOL_ARGUMENTS);
    match adapter.build_body(&request, &transport.provider, &transport.model) {
        Err(error) if !error.trim().is_empty() => Ok(()),
        Err(_) => Err(format!(
            "{context} returned an empty malformed-arguments error"
        )),
        Ok(body) => Err(format!(
            "{context} forwarded malformed tool arguments upstream: {body}"
        )),
    }
}

fn check_malformed_tool_history(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    let request = parse_fixture(REQUEST_MALFORMED_TOOL_HISTORY);
    match adapter.build_body(&request, &transport.provider, &transport.model) {
        Err(error) if !error.trim().is_empty() => Ok(()),
        Err(_) => Err(format!(
            "{context} returned an empty malformed-history error"
        )),
        Ok(body) => Err(format!(
            "{context} forwarded malformed tool history upstream: {body}"
        )),
    }
}

fn check_mixed_request(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    let request = parse_fixture(REQUEST_MIXED);
    let required = [
        "image_input",
        "tool_calls",
        "tool_result_continuation",
        "reasoning_controls",
    ];
    if let Some(capability) = required
        .iter()
        .find(|capability| transport.capabilities[**capability] == CapabilityStatus::Unsupported)
    {
        return expect_unsupported(
            context,
            capability,
            adapter.build_body(&request, &transport.provider, &transport.model),
        );
    }
    if required
        .iter()
        .any(|capability| transport.capabilities[*capability] == CapabilityStatus::NotApplicable)
    {
        return Ok(());
    }

    let body = adapter
        .build_body(&request, &transport.provider, &transport.model)
        .map_err(|error| format!("{context} rejected the canonical mixed request: {error}"))?;
    let serialized = body.to_string();
    for marker in [
        "fixture:plugin-mixed inspect image",
        "QUJD",
        "read_file",
        "call_plugin_1",
        "fn main() {}",
    ] {
        if !serialized.contains(marker) {
            return Err(format!(
                "{context} silently lost canonical mixed-request marker '{marker}'"
            ));
        }
    }
    Ok(())
}

fn check_expected_response_fixture(
    context: &str,
    fixture: &Value,
    canonical_events: &[Value],
) -> Result<(), String> {
    let expected = fixture
        .get("expected")
        .ok_or_else(|| format!("{context} response fixture lacks expected events"))?;
    let canonical_thinking = canonical_events
        .iter()
        .find(|event| event["type"] == "thinking_delta" && event["text"].as_str() != Some(""))
        .and_then(|event| event["text"].as_str())
        .ok_or_else(|| "canonical response fixture lacks reasoning text".to_string())?;
    if expected["thinking"].as_str() != Some(canonical_thinking) {
        return Err(format!(
            "{context} response fixture reasoning differs from the canonical response fixture"
        ));
    }

    let canonical_calls: Vec<_> = canonical_events
        .iter()
        .filter(|event| event["type"] == "tool_call_start")
        .collect();
    let expected_calls = expected["tools"]
        .as_array()
        .ok_or_else(|| format!("{context} response fixture lacks expected tool calls"))?;
    if canonical_calls.len() != expected_calls.len() {
        return Err(format!(
            "{context} response fixture has a different tool count than the canonical response"
        ));
    }
    for canonical_call in canonical_calls {
        let name = canonical_call["name"].as_str().unwrap_or_default();
        let expected_call = expected_calls
            .iter()
            .find(|call| call["name"].as_str() == Some(name))
            .ok_or_else(|| format!("{context} response fixture lost canonical tool '{name}'"))?;
        let index = canonical_call["index"].as_u64().unwrap_or_default();
        let canonical_args = canonical_events
            .iter()
            .filter(|event| {
                event["type"] == "tool_call_args_delta" && event["index"].as_u64() == Some(index)
            })
            .filter_map(|event| event["args"].as_str())
            .collect::<String>();
        let canonical_args: Value = serde_json::from_str(&canonical_args)
            .map_err(|error| format!("canonical tool '{name}' has invalid arguments: {error}"))?;
        if expected_call["arguments"] != canonical_args {
            return Err(format!(
                "{context} response fixture arguments for '{name}' differ from the canonical response"
            ));
        }
    }

    let canonical_finish = canonical_events
        .iter()
        .find(|event| event["type"] == "finish")
        .and_then(|event| event["reason"].as_str())
        .ok_or_else(|| "canonical response fixture lacks a finish reason".to_string())?;
    if expected["finish_reason"].as_str() != Some(canonical_finish) {
        return Err(format!(
            "{context} response fixture finish reason differs from the canonical response"
        ));
    }
    let canonical_usage = canonical_events
        .iter()
        .find(|event| event["type"] == "usage")
        .ok_or_else(|| "canonical response fixture lacks usage".to_string())?;
    for field in ["input", "output", "thinking"] {
        if !canonical_usage[field].is_null() && expected["usage"][field] != canonical_usage[field] {
            return Err(format!(
                "{context} response fixture usage.{field} differs from the canonical response"
            ));
        }
    }
    Ok(())
}

fn check_response_feature(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
    fixture: &Value,
    capability: &str,
    streaming: bool,
) -> Result<(), String> {
    match transport.capabilities[capability] {
        CapabilityStatus::Supported => {
            let events = parse_response(adapter, context, fixture, streaming)?;
            let events = events.as_array().ok_or_else(|| {
                format!("{context} parser must return an event array, got {events}")
            })?;
            assert_expected_events(context, fixture, events, &transport.capabilities)
        }
        CapabilityStatus::Unsupported => expect_unsupported(
            context,
            capability,
            parse_response(adapter, context, fixture, streaming),
        ),
        CapabilityStatus::NotApplicable => Ok(()),
    }
}

fn parse_response(
    adapter: &impl Adapter,
    context: &str,
    fixture: &Value,
    streaming: bool,
) -> Result<Value, String> {
    if streaming {
        let chunks = fixture
            .get("stream")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{context} fixture has no stream chunks"))?;
        let mut events = Vec::new();
        for chunk in chunks {
            let chunk_events = adapter
                .parse_stream_chunk(chunk)
                .map_err(|error| format!("{context} stream parser failed: {error}"))?;
            extend_events(&mut events, chunk_events, context)?;
        }
        Ok(Value::Array(events))
    } else {
        let response = fixture
            .get("full")
            .ok_or_else(|| format!("{context} fixture has no full response"))?;
        adapter
            .parse_full_response(response)
            .map_err(|error| format!("{context} full-response parser failed: {error}"))
    }
}

fn extend_events(events: &mut Vec<Value>, output: Value, context: &str) -> Result<(), String> {
    let values = output
        .as_array()
        .ok_or_else(|| format!("{context} parser must return an event array, got {output}"))?;
    events.extend(values.iter().cloned());
    Ok(())
}

fn assert_expected_events(
    context: &str,
    fixture: &Value,
    events: &[Value],
    capabilities: &BTreeMap<String, CapabilityStatus>,
) -> Result<(), String> {
    let expected = fixture
        .get("expected")
        .ok_or_else(|| format!("{context} response fixture lacks expected events"))?;
    let event_type = |event: &&Value, expected_type: &str| {
        event.get("type").and_then(Value::as_str) == Some(expected_type)
    };

    let request_id = expected["request_id"].as_str().unwrap();
    if !events
        .iter()
        .any(|event| event_type(&event, "start") && event["upstream_request_id"] == request_id)
    {
        return Err(format!("{context} response lost upstream request id"));
    }
    for (capability, feature, event_kind, field) in [
        (
            "reasoning_output",
            "reasoning",
            "thinking_delta",
            "thinking",
        ),
        ("text_generation", "text", "text_delta", "text"),
    ] {
        if capabilities[capability] != CapabilityStatus::Supported {
            continue;
        }
        let value = expected[field].as_str().unwrap();
        if !events
            .iter()
            .any(|event| event_type(&event, event_kind) && event["text"].as_str() == Some(value))
        {
            return Err(format!(
                "{context} response lost {feature} content '{value}'"
            ));
        }
    }

    let expected_calls = expected["tools"].as_array().unwrap();
    if capabilities["tool_calls"] == CapabilityStatus::Supported {
        let call_count = if capabilities["parallel_tool_calls"] == CapabilityStatus::Supported {
            expected_calls.len()
        } else {
            expected_calls.len().min(1)
        };
        for call in expected_calls.iter().take(call_count) {
            let index = call["index"].as_u64().unwrap();
            let name = call["name"].as_str().unwrap();
            let start = events.iter().find(|event| {
                event_type(&event, "tool_call_start")
                    && event["index"].as_u64() == Some(index)
                    && event["name"].as_str() == Some(name)
            });
            let Some(start) = start else {
                return Err(format!(
                    "{context} response lost tool call {index} '{name}'; events: {events:?}"
                ));
            };
            if let Some(id) = call.get("id").and_then(Value::as_str) {
                if start["id"].as_str() != Some(id) {
                    return Err(format!(
                        "{context} response changed tool call id for '{name}'"
                    ));
                }
            }
            let args = call["arguments"].as_object().unwrap();
            let mut actual_args = String::new();
            for event in events.iter().filter(|event| {
                event_type(&event, "tool_call_args_delta") && event["index"].as_u64() == Some(index)
            }) {
                if let Some(value) = event["args"].as_str() {
                    actual_args.push_str(value);
                }
            }
            let parsed_args: Value = serde_json::from_str(&actual_args).map_err(|error| {
                format!("{context} emitted invalid arguments for tool '{name}': {error}")
            })?;
            if parsed_args != Value::Object(args.clone()) {
                return Err(format!("{context} changed arguments for tool '{name}'"));
            }
        }
    }

    if capabilities["stop_reasons"] == CapabilityStatus::Supported {
        let finish_reason = expected["finish_reason"].as_str().unwrap();
        if !events.iter().any(|event| {
            event_type(&event, "finish") && event["reason"].as_str() == Some(finish_reason)
        }) {
            return Err(format!(
                "{context} changed finish reason to something other than '{finish_reason}'"
            ));
        }
    }

    if capabilities["usage_extraction"] != CapabilityStatus::Supported {
        return Ok(());
    }
    let usage = expected["usage"].as_object().unwrap();
    let usage_events: Vec<_> = events
        .iter()
        .filter(|event| event_type(event, "usage"))
        .collect();
    for (field, expected_value) in usage {
        if expected_value.is_null() {
            continue;
        }
        if !usage_events
            .iter()
            .any(|event| event[field] == *expected_value)
        {
            return Err(format!("{context} response lost usage.{field}"));
        }
    }
    Ok(())
}

fn check_stop_reasons(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
    fixture: &Value,
) -> Result<(), String> {
    match transport.capabilities["stop_reasons"] {
        CapabilityStatus::Supported => {
            for probe in fixture["stop_probes"].as_array().unwrap() {
                let expected = probe["expected"].as_str().unwrap();
                let stream = adapter
                    .parse_stream_chunk(&probe["stream"])
                    .map_err(|error| format!("{context} failed to parse stop reason: {error}"))?;
                assert_finish_reason(context, expected, &stream)?;
                let full = adapter
                    .parse_full_response(&probe["full"])
                    .map_err(|error| {
                        format!("{context} failed to parse full stop reason: {error}")
                    })?;
                assert_finish_reason(context, expected, &full)?;
            }
            Ok(())
        }
        CapabilityStatus::Unsupported => {
            for probe in fixture["stop_probes"].as_array().unwrap() {
                let stream = adapter.parse_stream_chunk(&probe["stream"]);
                expect_unsupported(context, "stop_reasons", stream)?;
                let full = adapter.parse_full_response(&probe["full"]);
                expect_unsupported(context, "stop_reasons", full)?;
            }
            Ok(())
        }
        CapabilityStatus::NotApplicable => Ok(()),
    }
}

fn assert_finish_reason(context: &str, expected: &str, events: &Value) -> Result<(), String> {
    let events = events
        .as_array()
        .ok_or_else(|| format!("{context} parser must return an event array"))?;
    if events
        .iter()
        .any(|event| event["type"] == "finish" && event["reason"].as_str() == Some(expected))
    {
        Ok(())
    } else {
        Err(format!(
            "{context} failed to preserve finish reason '{expected}'"
        ))
    }
}

fn check_error_classification(
    adapter: &impl Adapter,
    context: &str,
    transport: &TransportProfile,
) -> Result<(), String> {
    let body = json!({"error":{"message":"rate limited"}});
    let headers = json!({"retry-after":"7"});
    match transport.capabilities["error_classification"] {
        CapabilityStatus::Supported => {
            let error = adapter
                .classify_error(429, &body, &headers)
                .map_err(|error| format!("{context} failed to classify upstream error: {error}"))?;
            if error["status"].as_u64() != Some(429)
                || error["retry_after_secs"].as_u64() != Some(7)
                || error["message"].as_str() != Some("rate limited")
                || !matches!(
                    error["kind"].as_str(),
                    Some("rate_limit" | "quota_exhausted")
                )
            {
                return Err(format!("{context} lost classified error evidence: {error}"));
            }
            Ok(())
        }
        CapabilityStatus::Unsupported => expect_unsupported(
            context,
            "error_classification",
            adapter.classify_error(429, &body, &headers),
        ),
        CapabilityStatus::NotApplicable => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_capabilities_cover_issue_scope() {
        for required in [
            "text_generation",
            "streaming",
            "non_streaming",
            "tool_calls",
            "parallel_tool_calls",
            "tool_result_continuation",
            "image_input",
            "reasoning_controls",
            "reasoning_output",
            "structured_schemas",
            "schema_max_length",
            "stop_reasons",
            "usage_extraction",
            "error_classification",
            "client_cancellation",
        ] {
            assert!(REQUIRED_CAPABILITIES.contains(&required));
        }
    }
}
