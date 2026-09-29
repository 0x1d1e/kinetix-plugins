//! Shared OAuth token and credential lifecycle helpers.
//!
//! These helpers cover protocol-independent mechanics. Plugins remain
//! responsible for provider endpoints, authorization flows, scopes, and state
//! key selection.

use serde::{de::DeserializeOwned, Serialize};

/// A validated OAuth token response with any refresh-token rotation applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in_secs: Option<u64>,
    pub expires_at_ms: Option<u64>,
    pub scope: Option<String>,
    pub token_type: Option<String>,
}

/// Parse and validate a token response, retaining the previous refresh token
/// when the provider omits a replacement.
pub fn parse_token_response(
    body: &str,
    previous_refresh_token: Option<&str>,
    now_ms: u64,
) -> Result<OAuthTokenResponse, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid token JSON: {e}"))?;
    let access_token = value
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "token response missing access_token".to_string())?
        .to_string();
    let refresh_token = value
        .get("refresh_token")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            previous_refresh_token
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        });
    let expires_in_secs = value.get("expires_in").and_then(serde_json::Value::as_u64);

    Ok(OAuthTokenResponse {
        access_token,
        refresh_token,
        expires_in_secs,
        expires_at_ms: expires_at_ms(now_ms, expires_in_secs),
        scope: value
            .get("scope")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        token_type: value
            .get("token_type")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    })
}

/// Calculate an absolute expiry without overflowing either unsigned operation.
pub fn expires_at_ms(now_ms: u64, expires_in_secs: Option<u64>) -> Option<u64> {
    now_ms.checked_add(expires_in_secs?.checked_mul(1_000)?)
}

/// Return true when the expiry is at or within the refresh lead window.
pub fn needs_refresh(expires_at_ms: u64, now_ms: u64, refresh_lead_ms: u64) -> bool {
    expires_at_ms.saturating_sub(now_ms) <= refresh_lead_ms
}

/// Parse an RFC3339 timestamp into Unix milliseconds.
///
/// Fractional seconds are truncated to millisecond precision. Timestamps before
/// the Unix epoch and values that cannot be represented as `u64` return `None`.
pub fn parse_rfc3339_ms(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }

    let year = parse_digits(&bytes[0..4])? as i64;
    let month = parse_digits(&bytes[5..7])?;
    let day = parse_digits(&bytes[8..10])?;
    let hour = parse_digits(&bytes[11..13])? as i64;
    let minute = parse_digits(&bytes[14..16])? as i64;
    let second = parse_digits(&bytes[17..19])? as i64;
    if year == 0 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    let mut position = 19;
    let mut millis = 0u64;
    if bytes.get(position) == Some(&b'.') {
        position += 1;
        let start = position;
        let mut digits = 0;
        while let Some(byte @ b'0'..=b'9') = bytes.get(position) {
            if digits < 3 {
                millis = millis * 10 + u64::from(byte - b'0');
            }
            digits += 1;
            position += 1;
        }
        if position == start {
            return None;
        }
        for _ in digits.min(3)..3 {
            millis *= 10;
        }
    }

    let offset_seconds = match bytes.get(position) {
        Some(b'Z' | b'z') if position + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-')) if position + 6 == bytes.len() => {
            if bytes.get(position + 3) != Some(&b':') {
                return None;
            }
            let offset_hour = parse_digits(&bytes[position + 1..position + 3])? as i64;
            let offset_minute = parse_digits(&bytes[position + 4..position + 6])? as i64;
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            let offset = offset_hour * 3_600 + offset_minute * 60;
            if *sign == b'+' {
                offset
            } else {
                -offset
            }
        }
        _ => return None,
    };

    let local_seconds = days
        .checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)?;
    let utc_seconds = local_seconds.checked_sub(offset_seconds)?;
    let timestamp_ms = utc_seconds.checked_mul(1_000)?.checked_add(millis as i64)?;
    u64::try_from(timestamp_ms).ok()
}

/// Format Unix milliseconds as a UTC RFC3339 timestamp with millisecond
/// precision. Years outside RFC3339's four-digit range return `None`.
pub fn format_rfc3339_ms(timestamp_ms: u64) -> Option<String> {
    let seconds = i64::try_from(timestamp_ms / 1_000).ok()?;
    let millis = timestamp_ms % 1_000;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    if !(1..=9_999).contains(&year) {
        return None;
    }

    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    ))
}

/// Load a credential previously written to host KV.
pub fn load_persisted_credential<T: DeserializeOwned>(key: &str) -> Result<Option<T>, String> {
    let Some(bytes) = crate::kinetix::plugin::host_storage::get(key) else {
        return Ok(None);
    };
    let raw = String::from_utf8(bytes)
        .map_err(|_| "persisted OAuth credential state is not UTF-8".to_string())?;
    deserialize_credential_state(&raw).map(Some)
}

/// Persist the complete latest credential state, including any rotated token.
pub fn persist_rotated_credential<T: Serialize>(key: &str, credential: &T) -> Result<(), String> {
    let raw = serialize_credential_state(credential)?;
    crate::helpers::kv_put_string(key, &raw)
        .map_err(|error| format!("writing OAuth credential state: {error}"))
}

/// Decode serialized credential state. Useful when a plugin uses a distinct
/// host world or an injected test store but wants the SDK's shared encoding.
pub fn deserialize_credential_state<T: DeserializeOwned>(raw: &str) -> Result<T, String> {
    serde_json::from_str(raw).map_err(|error| format!("decoding OAuth credential state: {error}"))
}

/// Encode complete credential state before writing it to host KV.
pub fn serialize_credential_state<T: Serialize>(credential: &T) -> Result<String, String> {
    serde_json::to_string(credential)
        .map_err(|error| format!("encoding OAuth credential state: {error}"))
}

/// Consistent classification for OAuth token refresh endpoint failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthRefreshError {
    pub code: &'static str,
    pub message: String,
    pub retryable: bool,
    pub retry_after_secs: Option<u64>,
}

impl OAuthRefreshError {
    fn terminal(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: false,
            retry_after_secs: None,
        }
    }

    fn retryable(message: impl Into<String>, retry_after_secs: Option<u64>) -> Self {
        Self {
            code: "upstream_unavailable",
            message: message.into(),
            retryable: true,
            retry_after_secs: Some(retry_after_secs.unwrap_or(5)),
        }
    }
}

/// Classify an HTTP failure from a token endpoint.
///
/// `invalid_grant` is terminal credential revocation. Rate limits and server
/// errors remain retryable; other statuses are terminal protocol errors.
pub fn classify_refresh_http_error(status: u16, body: &str) -> OAuthRefreshError {
    let parsed = serde_json::from_str::<serde_json::Value>(body).ok();
    let oauth_error = parsed
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(serde_json::Value::as_str);
    let description = parsed
        .as_ref()
        .and_then(|value| value.get("error_description"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty());

    if oauth_error == Some("invalid_grant") {
        return OAuthRefreshError::terminal(
            "credential_expired",
            description
                .unwrap_or("OAuth provider rejected the refresh token as invalid or expired"),
        );
    }

    let detail = oauth_error
        .map(|error| {
            description
                .map(|description| format!("{error}: {description}"))
                .unwrap_or_else(|| error.to_string())
        })
        .unwrap_or_else(|| format!("HTTP {status}"));
    let message = format!("OAuth token endpoint returned {detail}");
    if status == 429
        || status >= 500
        || matches!(
            oauth_error,
            Some("temporarily_unavailable" | "server_error")
        )
    {
        OAuthRefreshError::retryable(message, None)
    } else {
        OAuthRefreshError::terminal("protocol_error", message)
    }
}

/// Classify a host transport failure while requesting a token.
pub fn classify_refresh_transport_error(
    code: &str,
    message: &str,
    retry_after_secs: Option<u64>,
) -> OAuthRefreshError {
    OAuthRefreshError::retryable(format!("{code}: {message}"), retry_after_secs)
}

/// Build a retryable error for incomplete token endpoint responses.
pub fn retryable_refresh_error(message: impl Into<String>) -> OAuthRefreshError {
    OAuthRefreshError::retryable(message, None)
}

fn parse_digits(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0u32, |value, byte| {
        value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
    })
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) {
        return None;
    }
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > month_days {
        return None;
    }

    let adjusted_year = if month <= 2 { year - 1 } else { year };
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let month_prime = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn refresh_window_handles_expired_boundary_and_large_values() {
        assert!(needs_refresh(99, 100, 0));
        assert!(needs_refresh(150, 100, 50));
        assert!(!needs_refresh(151, 100, 50));
        assert!(needs_refresh(u64::MAX, u64::MAX, u64::MAX));
    }

    #[test]
    fn expiry_calculation_rejects_multiplication_and_addition_overflow() {
        assert_eq!(expires_at_ms(10, Some(2)), Some(2_010));
        assert_eq!(expires_at_ms(0, Some(u64::MAX)), None);
        assert_eq!(expires_at_ms(u64::MAX - 500, Some(1)), None);
        assert_eq!(expires_at_ms(0, None), None);
    }

    #[test]
    fn parses_and_formats_rfc3339_with_offsets_and_fractional_seconds() {
        let timestamp = parse_rfc3339_ms("2024-02-29T12:34:56.78+02:30").unwrap();
        assert_eq!(
            format_rfc3339_ms(timestamp).as_deref(),
            Some("2024-02-29T10:04:56.780Z")
        );
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00.123456Z"), Some(123));
    }

    #[test]
    fn rejects_invalid_rfc3339_dates_and_times() {
        for value in [
            "2023-02-29T00:00:00Z",
            "2024-13-01T00:00:00Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:00:60Z",
            "2024-01-01T00:00:00",
            "2024-01-01T00:00:00+24:00",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(parse_rfc3339_ms(value), None, "accepted {value}");
        }
        assert_eq!(format_rfc3339_ms(u64::MAX), None);
    }

    #[test]
    fn token_parser_validates_access_and_applies_refresh_rotation() {
        let rotated = parse_token_response(
            r#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"scope":"read","token_type":"Bearer"}"#,
            Some("old-refresh"),
            1_000,
        )
        .unwrap();
        assert_eq!(rotated.access_token, "new-access");
        assert_eq!(rotated.refresh_token.as_deref(), Some("new-refresh"));
        assert_eq!(rotated.expires_at_ms, Some(3_601_000));
        assert_eq!(rotated.scope.as_deref(), Some("read"));
        assert_eq!(rotated.token_type.as_deref(), Some("Bearer"));

        let retained =
            parse_token_response(r#"{"access_token":"next"}"#, Some("old-refresh"), 0).unwrap();
        assert_eq!(retained.refresh_token.as_deref(), Some("old-refresh"));
        assert_eq!(retained.expires_at_ms, None);
        assert!(parse_token_response(r#"{"access_token":""}"#, None, 0).is_err());
        assert!(parse_token_response("not json", None, 0).is_err());
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct SavedCredential {
        access_token: String,
        refresh_token: String,
    }

    #[test]
    fn credential_state_round_trips_rotated_tokens() {
        let saved = SavedCredential {
            access_token: "access-2".into(),
            refresh_token: "refresh-2".into(),
        };
        let encoded = serialize_credential_state(&saved).unwrap();
        let loaded: SavedCredential = deserialize_credential_state(&encoded).unwrap();
        assert_eq!(loaded, saved);
    }

    #[test]
    fn refresh_failures_distinguish_revocation_from_transient_errors() {
        let revoked = classify_refresh_http_error(
            400,
            r#"{"error":"invalid_grant","error_description":"revoked"}"#,
        );
        assert_eq!(revoked.code, "credential_expired");
        assert!(!revoked.retryable);
        assert_eq!(revoked.retry_after_secs, None);

        for status in [429, 500, 503] {
            let transient = classify_refresh_http_error(status, "{}");
            assert_eq!(transient.code, "upstream_unavailable");
            assert!(transient.retryable);
            assert_eq!(transient.retry_after_secs, Some(5));
        }
        let transport = classify_refresh_transport_error("timeout", "connection reset", None);
        assert_eq!(transport.code, "upstream_unavailable");
        assert!(transport.retryable);
        assert_eq!(transport.retry_after_secs, Some(5));
        assert_eq!(
            classify_refresh_transport_error("timeout", "busy", Some(12)).retry_after_secs,
            Some(12)
        );
        assert_eq!(
            classify_refresh_http_error(400, r#"{"error":"invalid_request"}"#).code,
            "protocol_error"
        );
        let provider_transient =
            classify_refresh_http_error(400, r#"{"error":"temporarily_unavailable"}"#);
        assert_eq!(provider_transient.code, "upstream_unavailable");
        assert!(provider_transient.retryable);
    }
}
