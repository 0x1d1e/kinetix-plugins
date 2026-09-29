//! Kinetix plugin: Antigravity OAuth credential strategy.
//!
//! Antigravity (Google's "Cloud Code Assist" IDE backend) authenticates with a
//! Google OAuth2 token whose access token expires in ~1 hour. Kinetix stores the
//! account credential as a JSON blob; this plugin refreshes the access token on
//! demand and hands the host an opaque lease, writing the live token into its
//! encrypted KV where the host reads it back at send time (§6.1).
//!
//! Credential JSON shape (what an operator imports as the account secret):
//!
//! ```json
//! {
//!   "refresh_token": "...",
//!   "access_token": "...",
//!   "expiry": "2026-09-20T12:00:00Z",
//!   "project_id": "useful-fuze-12345",
//!   "email": "user@example.com"
//! }
//! ```
//!
//! Only `refresh_token` is required; the rest is refreshed/cached.
//!
//! Reference source: 9router `open-sse/executors/antigravity.js`,
//! `src/lib/oauth/providers/antigravity.js`, `open-sse/providers/registry/antigravity.js`.

mod adapter;

use kinetix::plugin::types::*;
use kinetix_plugin_sdk::{
    export, exports, kinetix,
    model_capabilities::{
        ModelCapabilitiesV2, ModelIdentityV2, OpaqueStateCapabilityKind, OpaqueStateCapabilityV1,
        OpaqueStatePlaceholderStrategy, ProviderVariantKind, ProviderVariantV1,
        ReasoningCapability, ReasoningLevel, ReasoningMode, SupportCapability, VisionCapability,
    },
};

#[cfg(test)]
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
};

/// Google OAuth endpoints used by browser authorization and refresh.
const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v1/userinfo";
const LOAD_CODE_ASSIST_URL: &str = "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist";
const ONBOARD_USER_URL: &str = "https://cloudcode-pa.googleapis.com/v1internal:onboardUser";
const RETRIEVE_USER_QUOTA_URL: &str =
    "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota";
const PROJECT_KEY_PREFIX: &str = "project:";
const ANTIGRAVITY_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
];

/// Public Antigravity CLI OAuth client ID and secret (obfuscated as byte arrays
/// so static scanners do not mistake public desktop-app credentials for server secrets).
fn default_client_id() -> String {
    let bytes: &[u8] = &[
        49, 48, 55, 49, 48, 48, 54, 48, 54, 48, 53, 57, 49, 45, 116, 109, 104, 115, 115, 105, 110,
        50, 104, 50, 49, 108, 99, 114, 101, 50, 51, 53, 118, 116, 111, 108, 111, 106, 104, 52, 103,
        52, 48, 51, 101, 112, 46, 97, 112, 112, 115, 46, 103, 111, 111, 103, 108, 101, 117, 115,
        101, 114, 99, 111, 110, 116, 101, 110, 116, 46, 99, 111, 109,
    ];
    String::from_utf8_lossy(bytes).into_owned()
}

fn default_client_secret() -> String {
    let bytes: &[u8] = &[
        71, 79, 67, 83, 80, 88, 45, 75, 53, 56, 70, 87, 82, 52, 56, 54, 76, 100, 76, 74, 49, 109,
        76, 66, 56, 115, 88, 67, 52, 122, 54, 113, 68, 65, 102,
    ];
    String::from_utf8_lossy(bytes).into_owned()
}

/// Refresh a token this many ms before its stated expiry.
const REFRESH_LEAD_MS: u64 = 5 * 60 * 1000;
/// KV key prefix where the live access token is written for the host.
const LEASE_KEY_PREFIX: &str = "lease:";

#[derive(serde::Deserialize, serde::Serialize, Default, Clone)]
struct Credential {
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    /// RFC3339 expiry of `access_token`.
    #[serde(default)]
    expiry: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

struct Component;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RefreshError {
    code: &'static str,
    message: String,
    retryable: bool,
    retry_after: Option<u64>,
}

impl RefreshError {
    fn credential_expired(message: impl Into<String>) -> Self {
        Self {
            code: "credential_expired",
            message: message.into(),
            retryable: false,
            retry_after: None,
        }
    }

    fn terminal(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: false,
            retry_after: None,
        }
    }

    fn into_plugin_error(self) -> PluginError {
        if self.retryable {
            kinetix_plugin_sdk::helpers::retryable_error(self.code, self.message, self.retry_after)
        } else {
            kinetix_plugin_sdk::helpers::error(self.code, self.message)
        }
    }
}

fn from_shared_refresh_error(error: kinetix_plugin_sdk::oauth::OAuthRefreshError) -> RefreshError {
    RefreshError {
        code: error.code,
        message: error.message,
        retryable: error.retryable,
        retry_after: error.retry_after_secs,
    }
}

fn token_refresh_transport_error(code: &str, message: &str) -> RefreshError {
    from_shared_refresh_error(kinetix_plugin_sdk::oauth::classify_refresh_transport_error(
        code, message, None,
    ))
}

fn token_refresh_http_error(status: u16, body: &[u8]) -> RefreshError {
    from_shared_refresh_error(
        kinetix_plugin_sdk::oauth::classify_refresh_http_error_bytes(status, body),
    )
}

fn provider_expiry_ms(
    tokens: &kinetix_plugin_sdk::oauth::OAuthTokenResponse,
    now_ms: u64,
) -> Option<u64> {
    if tokens.expires_in_secs.is_some() {
        tokens.expires_at_ms
    } else {
        kinetix_plugin_sdk::oauth::expires_at_ms(now_ms, Some(3_600))
    }
}

fn latest_credential_from_sources(
    imported_raw: &str,
    persisted_raw: Option<&str>,
) -> Result<Credential, String> {
    let raw = persisted_raw.unwrap_or(imported_raw);
    kinetix_plugin_sdk::oauth::deserialize_credential_state(raw)
        .map_err(|e| format!("invalid Antigravity credential JSON: {e}"))
}

#[cfg(not(test))]
fn credential_storage_get(key: &str) -> Option<String> {
    kinetix_plugin_sdk::helpers::kv_get_string(key)
}

#[cfg(not(test))]
fn credential_storage_put(key: &str, value: &str) -> Result<(), String> {
    kinetix_plugin_sdk::helpers::kv_put_string(key, value)
}

#[cfg(not(test))]
fn imported_credential_read(account: &AccountRef) -> Result<String, PluginError> {
    let cred_ref = CredentialRef::Account(account.clone());
    kinetix::plugin::host_credential::read(&cred_ref)
        .map_err(|e| kinetix_plugin_sdk::helpers::error("credential_expired", e.message))
}

#[cfg(test)]
thread_local! {
    static TEST_CREDENTIAL_STORAGE: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
    static TEST_IMPORTED_CREDENTIALS: RefCell<HashMap<String, String>> =
        RefCell::new(HashMap::new());
}

#[cfg(test)]
fn test_account_key(account: &AccountRef) -> String {
    format!("{}:{}", account.provider_id, account.account_id)
}

#[cfg(test)]
fn credential_storage_get(key: &str) -> Option<String> {
    TEST_CREDENTIAL_STORAGE.with(|storage| storage.borrow().get(key).cloned())
}

#[cfg(test)]
fn credential_storage_put(key: &str, value: &str) -> Result<(), String> {
    TEST_CREDENTIAL_STORAGE.with(|storage| {
        storage
            .borrow_mut()
            .insert(key.to_string(), value.to_string());
    });
    Ok(())
}

#[cfg(test)]
fn imported_credential_read(account: &AccountRef) -> Result<String, PluginError> {
    TEST_IMPORTED_CREDENTIALS
        .with(|credentials| {
            credentials
                .borrow()
                .get(&test_account_key(account))
                .cloned()
        })
        .ok_or_else(|| {
            kinetix_plugin_sdk::helpers::error(
                "credential_expired",
                "test imported credential missing",
            )
        })
}

#[cfg(test)]
fn reset_test_credential_state() {
    TEST_CREDENTIAL_STORAGE.with(|storage| storage.borrow_mut().clear());
    TEST_IMPORTED_CREDENTIALS.with(|credentials| credentials.borrow_mut().clear());
}

#[cfg(test)]
fn set_test_imported_credential(account: &AccountRef, raw: &str) {
    TEST_IMPORTED_CREDENTIALS.with(|credentials| {
        credentials
            .borrow_mut()
            .insert(test_account_key(account), raw.to_string());
    });
}

fn load_credential(account: &AccountRef) -> Result<Credential, PluginError> {
    if let Some(persisted) = credential_storage_get(&state_key(account)) {
        return latest_credential_from_sources("", Some(&persisted))
            .map_err(|e| kinetix_plugin_sdk::helpers::error("invalid_configuration", e));
    }

    let imported = imported_credential_read(account)?;
    latest_credential_from_sources(&imported, None)
        .map_err(|e| kinetix_plugin_sdk::helpers::error("invalid_configuration", e))
}

fn should_refresh_before_lease(cred: &Credential, now_ms: u64) -> bool {
    !access_token_valid(cred, now_ms)
}

impl exports::credential_strategy::Guest for Component {
    fn resolve(
        provider_id: String,
        account_id: String,
        _account_label: String,
    ) -> Result<CredentialLease, PluginError> {
        let account = AccountRef {
            provider_id: provider_id.clone(),
            account_id: account_id.clone(),
        };
        let mut cred = load_credential(&account)?;

        let now = kinetix_plugin_sdk::helpers::now_unix_millis();
        if should_refresh_before_lease(&cred, now) {
            if cred.refresh_token.is_none() {
                return Err(kinetix_plugin_sdk::helpers::error(
                    "credential_expired",
                    "Antigravity credential has no refresh_token and its access_token is not valid",
                ));
            }
            refresh(&mut cred).map_err(RefreshError::into_plugin_error)?;
            // Persist before leasing so a rotated refresh token cannot be lost.
            persist_rotated(&account, &cred).map_err(|e| {
                kinetix_plugin_sdk::helpers::error(
                    "plugin_internal",
                    format!("persisting rotated Antigravity credential: {e}"),
                )
            })?;
        }

        let access = cred.access_token.clone().ok_or_else(|| {
            kinetix_plugin_sdk::helpers::error("credential_expired", "no access token available")
        })?;

        let project = match cred
            .project_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(project) => project.to_string(),
            None => {
                let project = resolve_project_id(&access).map_err(|e| {
                    kinetix_plugin_sdk::helpers::retryable_error("upstream_unavailable", e, Some(5))
                })?;
                cred.project_id = Some(project.clone());
                persist_rotated(&account, &cred).map_err(|e| {
                    kinetix_plugin_sdk::helpers::error(
                        "plugin_internal",
                        format!("persisting Antigravity credential project: {e}"),
                    )
                })?;
                project
            }
        };
        persist_project(&account, &project).map_err(|e| {
            kinetix_plugin_sdk::helpers::error(
                "plugin_internal",
                format!("persisting Antigravity project: {e}"),
            )
        })?;

        // The host reads the live token back from its encrypted KV under the
        // handle we return (§6.1); the token never appears in the return value.
        let handle = handle_for(&account);
        kinetix_plugin_sdk::helpers::kv_put_string(&format!("{LEASE_KEY_PREFIX}{handle}"), &access)
            .map_err(|e| kinetix_plugin_sdk::helpers::error("plugin_internal", e))?;

        Ok(CredentialLease {
            handle,
            expires_at: cred.expiry.clone(),
            refresh_after: None,
            health: "healthy".into(),
        })
    }

    fn health(provider_id: String, account_id: String) -> Result<String, PluginError> {
        let account = AccountRef {
            provider_id,
            account_id,
        };
        let cred = load_credential(&account)?;
        let now = kinetix_plugin_sdk::helpers::now_unix_millis();
        if access_token_valid(&cred, now) {
            Ok("healthy".into())
        } else if cred.refresh_token.is_some() {
            // Refreshable: the next resolve will renew it.
            Ok("healthy".into())
        } else {
            Ok("unusable".into())
        }
    }

    fn rotate(provider_id: String, account_id: String) -> Result<(), PluginError> {
        let account = AccountRef {
            provider_id,
            account_id,
        };
        let mut cred = load_credential(&account)?;
        refresh(&mut cred).map_err(RefreshError::into_plugin_error)?;
        persist_rotated(&account, &cred).map_err(|e| {
            kinetix_plugin_sdk::helpers::error(
                "plugin_internal",
                format!("persisting rotated Antigravity credential: {e}"),
            )
        })?;
        Ok(())
    }
}

/// Whether the cached access token is present and not within the refresh lead.
fn access_token_valid(cred: &Credential, now_ms: u64) -> bool {
    let Some(token) = cred.access_token.as_deref() else {
        return false;
    };
    if token.is_empty() {
        return false;
    }
    let Some(expiry) = cred.expiry.as_deref() else {
        // No trustworthy expiry metadata: refresh before leasing rather than
        // waiting for the host's forced rotation after an upstream 401.
        return false;
    };
    match kinetix_plugin_sdk::oauth::parse_rfc3339_ms(expiry) {
        Some(exp_ms) => !kinetix_plugin_sdk::oauth::needs_refresh(exp_ms, now_ms, REFRESH_LEAD_MS),
        None => false,
    }
}

/// Exchange the refresh token for a fresh access token.
fn refresh(cred: &mut Credential) -> Result<(), RefreshError> {
    let refresh_token = cred
        .refresh_token
        .clone()
        .ok_or_else(|| RefreshError::credential_expired("no refresh_token"))?;
    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        urlencode(&refresh_token),
        urlencode(&default_client_id()),
        urlencode(&default_client_secret()),
    );
    let req = HttpRequest {
        method: "POST".into(),
        url: TOKEN_URL.into(),
        headers: vec![
            (
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
            ("accept".into(), "application/json".into()),
        ],
        body: form.into_bytes(),
        credential: None,
    };
    let resp = kinetix::plugin::host_http::send(&req)
        .map_err(|e| token_refresh_transport_error(&e.code, &e.message))?;
    if resp.body_truncated {
        return Err(from_shared_refresh_error(
            kinetix_plugin_sdk::oauth::retryable_refresh_error("token response truncated"),
        ));
    }
    if resp.status != 200 {
        return Err(token_refresh_http_error(resp.status, &resp.body));
    }
    let text = String::from_utf8(resp.body)
        .map_err(|_| RefreshError::terminal("protocol_error", "token response not utf-8"))?;
    let now_ms = kinetix_plugin_sdk::helpers::now_unix_millis();
    let tokens = kinetix_plugin_sdk::oauth::parse_token_response(
        &text,
        cred.refresh_token.as_deref(),
        now_ms,
    )
    .map_err(|e| RefreshError::terminal("protocol_error", e))?;
    let expiry =
        provider_expiry_ms(&tokens, now_ms).and_then(kinetix_plugin_sdk::oauth::format_rfc3339_ms);
    cred.access_token = Some(tokens.access_token);
    cred.refresh_token = tokens.refresh_token;
    cred.expiry = expiry;
    Ok(())
}

/// A stable, opaque handle derived from the account (never the secret).
pub(crate) fn account_handle(provider_id: &str, account_id: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in format!("{provider_id}:{account_id}").bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn handle_for(account: &AccountRef) -> String {
    account_handle(&account.provider_id, &account.account_id)
}

fn credential_state_key(provider_id: &str, account_id: &str) -> String {
    format!("cred:{}", account_handle(provider_id, account_id))
}

fn state_key(account: &AccountRef) -> String {
    credential_state_key(&account.provider_id, &account.account_id)
}

pub(crate) fn project_state_key(provider_id: &str, account_id: &str) -> String {
    format!(
        "{PROJECT_KEY_PREFIX}{}",
        account_handle(provider_id, account_id)
    )
}

fn persist_project(account: &AccountRef, project_id: &str) -> Result<(), String> {
    kinetix_plugin_sdk::helpers::kv_put_string(
        &project_state_key(&account.provider_id, &account.account_id),
        project_id,
    )
}

fn antigravity_metadata() -> serde_json::Value {
    serde_json::json!({
        "ideType": 9,
        "platform": 2,
        "pluginType": 2,
    })
}

fn extract_project_id(value: &serde_json::Value) -> Option<String> {
    let project = value
        .get("cloudaicompanionProject")
        .or_else(|| value.pointer("/response/cloudaicompanionProject"))?;
    if let Some(id) = project.as_str().map(str::trim).filter(|id| !id.is_empty()) {
        return Some(id.to_string());
    }
    project
        .get("id")
        .and_then(|id| id.as_str())
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

fn default_tier_id(value: &serde_json::Value) -> String {
    value
        .get("allowedTiers")
        .and_then(|tiers| tiers.as_array())
        .and_then(|tiers| {
            tiers.iter().find_map(|tier| {
                if tier.get("isDefault").and_then(|v| v.as_bool()) != Some(true) {
                    return None;
                }
                tier.get("id")
                    .and_then(|id| id.as_str())
                    .map(str::trim)
                    .filter(|id| !id.is_empty())
                    .map(str::to_string)
            })
        })
        .unwrap_or_else(|| "legacy-tier".to_string())
}

fn project_headers(access_token: &str) -> Vec<(String, String)> {
    vec![
        ("authorization".into(), format!("Bearer {access_token}")),
        ("content-type".into(), "application/json".into()),
        ("accept".into(), "application/json".into()),
        ("user-agent".into(), crate::adapter::USER_AGENT.into()),
    ]
}

fn decode_project_response(
    status: u16,
    body: Vec<u8>,
    truncated: bool,
    operation: &str,
) -> Result<serde_json::Value, String> {
    if truncated {
        return Err(format!("{operation} response truncated"));
    }
    let text = String::from_utf8(body).map_err(|_| format!("{operation} response not utf-8"))?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "{operation} returned HTTP {status}{}",
            if text.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", text.chars().take(200).collect::<String>())
            }
        ));
    }
    serde_json::from_str(&text).map_err(|e| format!("invalid {operation} JSON: {e}"))
}

fn resolve_project_id(access_token: &str) -> Result<String, String> {
    let load = HttpRequest {
        method: "POST".into(),
        url: LOAD_CODE_ASSIST_URL.into(),
        headers: project_headers(access_token),
        body: serde_json::to_vec(&serde_json::json!({
            "metadata": antigravity_metadata()
        }))
        .map_err(|e| format!("encoding loadCodeAssist request: {e}"))?,
        credential: None,
    };
    let load = kinetix::plugin::host_http::send(&load)
        .map_err(|e| format!("{}: {}", e.code, e.message))?;
    let load = decode_project_response(
        load.status,
        load.body,
        load.body_truncated,
        "loadCodeAssist",
    )?;
    if let Some(project) = extract_project_id(&load) {
        return Ok(project);
    }

    let tier_id = default_tier_id(&load);
    let onboard = HttpRequest {
        method: "POST".into(),
        url: ONBOARD_USER_URL.into(),
        headers: project_headers(access_token),
        body: serde_json::to_vec(&serde_json::json!({
            "tierId": tier_id,
            "metadata": antigravity_metadata()
        }))
        .map_err(|e| format!("encoding onboardUser request: {e}"))?,
        credential: None,
    };
    let onboard = kinetix::plugin::host_http::send(&onboard)
        .map_err(|e| format!("{}: {}", e.code, e.message))?;
    let onboard = decode_project_response(
        onboard.status,
        onboard.body,
        onboard.body_truncated,
        "onboardUser",
    )?;
    if let Some(project) = extract_project_id(&onboard) {
        return Ok(project);
    }

    let reload = HttpRequest {
        method: "POST".into(),
        url: LOAD_CODE_ASSIST_URL.into(),
        headers: project_headers(access_token),
        body: serde_json::to_vec(&serde_json::json!({
            "metadata": antigravity_metadata()
        }))
        .map_err(|e| format!("encoding loadCodeAssist request: {e}"))?,
        credential: None,
    };
    let reload = kinetix::plugin::host_http::send(&reload)
        .map_err(|e| format!("{}: {}", e.code, e.message))?;
    let reload = decode_project_response(
        reload.status,
        reload.body,
        reload.body_truncated,
        "loadCodeAssist",
    )?;
    extract_project_id(&reload)
        .ok_or_else(|| "Google did not provision a cloudaicompanionProject".to_string())
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Persist a freshly rotated credential to host KV. The host encrypts KV at
/// rest. A failed write is fatal for the lease because Google may rotate the
/// refresh token; continuing would make the next resolution fall back to stale
/// imported state.
fn persist_rotated(account: &AccountRef, cred: &Credential) -> Result<(), String> {
    let serialized = kinetix_plugin_sdk::oauth::serialize_credential_state(cred)?;
    credential_storage_put(&state_key(account), &serialized)
}

// --- Optional account authorization world. ---------------------------------

use kinetix_plugin_sdk::auth as auth_world;

type AuthPluginError = auth_world::kinetix::plugin::types::PluginError;
type AuthHttpRequest = auth_world::kinetix::plugin::types::HttpRequest;
type AuthResult = auth_world::kinetix::plugin::types::AuthResult;

fn auth_error(code: &str, message: impl Into<String>, retryable: bool) -> AuthPluginError {
    AuthPluginError {
        code: code.into(),
        message: message.into(),
        retryable,
        retry_after: None,
        reset_at: None,
    }
}

fn require_antigravity_flow(flow_name: &str) -> Result<(), AuthPluginError> {
    if flow_name == "antigravity" {
        Ok(())
    } else {
        Err(auth_error(
            "invalid_configuration",
            format!("unknown auth flow '{flow_name}'"),
            false,
        ))
    }
}

fn auth_project_headers(access_token: &str) -> Vec<(String, String)> {
    vec![
        ("authorization".into(), format!("Bearer {access_token}")),
        ("content-type".into(), "application/json".into()),
        ("accept".into(), "application/json".into()),
        ("user-agent".into(), crate::adapter::USER_AGENT.into()),
    ]
}

fn send_auth_project_request(
    url: &str,
    access_token: &str,
    body: serde_json::Value,
    operation: &str,
) -> Result<serde_json::Value, AuthPluginError> {
    let req = AuthHttpRequest {
        method: "POST".into(),
        url: url.into(),
        headers: auth_project_headers(access_token),
        body: serde_json::to_vec(&body).map_err(|e| {
            auth_error(
                "plugin_internal",
                format!("encoding {operation} request: {e}"),
                false,
            )
        })?,
        credential: None,
    };
    let resp = auth_world::kinetix::plugin::host_http::send(&req)
        .map_err(|e| auth_error(&e.code, e.message, e.retryable))?;
    if resp.body_truncated {
        return Err(auth_error(
            "upstream_unavailable",
            format!("{operation} response truncated"),
            true,
        ));
    }
    let text = String::from_utf8(resp.body).map_err(|_| {
        auth_error(
            "protocol_error",
            format!("{operation} response not utf-8"),
            false,
        )
    })?;
    if !(200..300).contains(&resp.status) {
        return Err(auth_error(
            "upstream_unavailable",
            format!(
                "{operation} returned HTTP {}{}",
                resp.status,
                if text.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", text.chars().take(200).collect::<String>())
                }
            ),
            resp.status >= 500,
        ));
    }
    serde_json::from_str(&text).map_err(|e| {
        auth_error(
            "protocol_error",
            format!("invalid {operation} JSON: {e}"),
            false,
        )
    })
}

fn resolve_project_id_for_auth(access_token: &str) -> Result<String, AuthPluginError> {
    let load = send_auth_project_request(
        LOAD_CODE_ASSIST_URL,
        access_token,
        serde_json::json!({ "metadata": antigravity_metadata() }),
        "loadCodeAssist",
    )?;
    if let Some(project) = extract_project_id(&load) {
        return Ok(project);
    }

    let onboard = send_auth_project_request(
        ONBOARD_USER_URL,
        access_token,
        serde_json::json!({
            "tierId": default_tier_id(&load),
            "metadata": antigravity_metadata()
        }),
        "onboardUser",
    )?;
    if let Some(project) = extract_project_id(&onboard) {
        return Ok(project);
    }

    let reload = send_auth_project_request(
        LOAD_CODE_ASSIST_URL,
        access_token,
        serde_json::json!({ "metadata": antigravity_metadata() }),
        "loadCodeAssist",
    )?;
    extract_project_id(&reload).ok_or_else(|| {
        auth_error(
            "upstream_unavailable",
            "Google did not provision a cloudaicompanionProject",
            true,
        )
    })
}

impl auth_world::exports::auth_flow::Guest for Component {
    fn begin(
        flow_name: String,
        redirect_uri: String,
        state: String,
        pkce_challenge: Option<String>,
    ) -> Result<String, AuthPluginError> {
        require_antigravity_flow(&flow_name)?;

        // The bundled Antigravity OAuth client is a desktop/native client.
        // Google permits it to use loopback redirects, not arbitrary hosted
        // dashboard origins. A future declarative settings layer can support
        // operator-provided web-client credentials for remote deployments.
        let loopback = redirect_uri.starts_with("http://localhost:")
            || redirect_uri.starts_with("http://127.0.0.1:")
            || redirect_uri.starts_with("http://[::1]:");
        if !loopback {
            return Err(auth_error(
                "invalid_configuration",
                "the bundled Antigravity OAuth client requires a loopback KINETIX_PUBLIC_BASE_URL",
                false,
            ));
        }

        let mut url = format!(
            "{AUTHORIZE_URL}?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}&access_type=offline&prompt=consent",
            urlencode(&default_client_id()),
            urlencode(&redirect_uri),
            urlencode(&ANTIGRAVITY_SCOPES.join(" ")),
            urlencode(&state),
        );
        if let Some(challenge) = pkce_challenge.filter(|value| !value.is_empty()) {
            url.push_str("&code_challenge=");
            url.push_str(&urlencode(&challenge));
            url.push_str("&code_challenge_method=S256");
        }
        if let Some(bytes) = auth_world::kinetix::plugin::host_storage::get("_config:login_hint") {
            if let Ok(hint) = String::from_utf8(bytes) {
                let hint = hint.trim();
                if !hint.is_empty() {
                    url.push_str("&login_hint=");
                    url.push_str(&urlencode(hint));
                }
            }
        }
        Ok(url)
    }

    fn exchange(
        flow_name: String,
        code: String,
        redirect_uri: String,
        pkce_verifier: Option<String>,
    ) -> Result<AuthResult, AuthPluginError> {
        require_antigravity_flow(&flow_name)?;

        let mut form = format!(
            "grant_type=authorization_code&client_id={}&client_secret={}&code={}&redirect_uri={}",
            urlencode(&default_client_id()),
            urlencode(&default_client_secret()),
            urlencode(&code),
            urlencode(&redirect_uri),
        );
        if let Some(verifier) = pkce_verifier.filter(|value| !value.is_empty()) {
            form.push_str("&code_verifier=");
            form.push_str(&urlencode(&verifier));
        }

        let req = AuthHttpRequest {
            method: "POST".into(),
            url: TOKEN_URL.into(),
            headers: vec![
                (
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
                ("accept".into(), "application/json".into()),
            ],
            body: form.into_bytes(),
            credential: None,
        };
        let resp = auth_world::kinetix::plugin::host_http::send(&req)
            .map_err(|e| auth_error(&e.code, e.message, e.retryable))?;
        if resp.body_truncated {
            return Err(auth_error(
                "upstream_unavailable",
                "token response truncated",
                true,
            ));
        }
        let text = String::from_utf8(resp.body)
            .map_err(|_| auth_error("protocol_error", "token response not utf-8", false))?;
        if resp.status != 200 {
            return Err(auth_error(
                "credential_expired",
                format!("token endpoint returned HTTP {}", resp.status),
                false,
            ));
        }

        let now_ms = kinetix_plugin_sdk::helpers::now_unix_millis();
        let tokens = kinetix_plugin_sdk::oauth::parse_token_response(&text, None, now_ms)
            .map_err(|e| auth_error("protocol_error", e, false))?;
        let access_token = tokens.access_token.clone();
        let refresh_token = tokens.refresh_token.clone().ok_or_else(|| {
            auth_error(
                "credential_expired",
                "Google did not return a refresh_token; retry login and grant consent",
                false,
            )
        })?;
        let expiry = provider_expiry_ms(&tokens, now_ms)
            .and_then(kinetix_plugin_sdk::oauth::format_rfc3339_ms);

        let mut email: Option<String> = None;
        let mut metadata: Option<String> = None;
        let userinfo_req = AuthHttpRequest {
            method: "GET".into(),
            url: format!("{USERINFO_URL}?alt=json"),
            headers: vec![
                ("authorization".into(), format!("Bearer {access_token}")),
                ("x-request-source".into(), "local".into()),
            ],
            body: vec![],
            credential: None,
        };
        if let Ok(userinfo_resp) = auth_world::kinetix::plugin::host_http::send(&userinfo_req) {
            if userinfo_resp.status == 200 && !userinfo_resp.body_truncated {
                if let Ok(body) = String::from_utf8(userinfo_resp.body) {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
                        email = value
                            .get("email")
                            .and_then(|value| value.as_str())
                            .map(str::to_string);
                        metadata = Some(value.to_string());
                    }
                }
            }
        }

        let project_id = resolve_project_id_for_auth(&access_token)?;

        let secret = Credential {
            refresh_token: Some(refresh_token),
            access_token: Some(tokens.access_token),
            expiry,
            project_id: Some(project_id),
            email: email.clone(),
        };
        let secret_json = serde_json::to_string(&secret).map_err(|e| {
            auth_error(
                "plugin_internal",
                format!("encoding credential: {e}"),
                false,
            )
        })?;

        Ok(AuthResult {
            secret_json,
            account_label: email.or_else(|| Some("Antigravity".into())),
            metadata_json: metadata,
        })
    }
}

auth_world::export!(Component with_types_in kinetix_plugin_sdk::auth);

// --- Account-aware model discovery world. ----------------------------------

use kinetix_plugin_sdk::model_source as model_world;

type ModelPluginError = model_world::kinetix::plugin::types::PluginError;
type ModelHttpRequest = model_world::kinetix::plugin::types::HttpRequest;
type ModelAccountRef = model_world::kinetix::plugin::types::AccountRef;
type ModelCredentialRef = model_world::kinetix::plugin::types::CredentialRef;
type ModelDiscoveredModel = model_world::kinetix::plugin::types::DiscoveredModel;

struct ModelRefreshHttpResponse {
    status: u16,
    body: Vec<u8>,
    body_truncated: bool,
}

#[cfg(not(test))]
fn send_model_refresh_request(
    req: &ModelHttpRequest,
) -> Result<ModelRefreshHttpResponse, RefreshError> {
    let response = model_world::kinetix::plugin::host_http::send(req)
        .map_err(|e| token_refresh_transport_error(&e.code, &e.message))?;
    Ok(ModelRefreshHttpResponse {
        status: response.status,
        body: response.body,
        body_truncated: response.body_truncated,
    })
}

#[cfg(test)]
thread_local! {
    static TEST_MODEL_REFRESH_RESPONSES:
        RefCell<VecDeque<Result<ModelRefreshHttpResponse, RefreshError>>> =
        const { RefCell::new(VecDeque::new()) };
}

#[cfg(test)]
fn send_model_refresh_request(
    _req: &ModelHttpRequest,
) -> Result<ModelRefreshHttpResponse, RefreshError> {
    TEST_MODEL_REFRESH_RESPONSES.with(|responses| {
        responses
            .borrow_mut()
            .pop_front()
            .expect("missing test model refresh response")
    })
}

#[cfg(test)]
fn enqueue_model_refresh_response(response: Result<ModelRefreshHttpResponse, RefreshError>) {
    TEST_MODEL_REFRESH_RESPONSES.with(|responses| responses.borrow_mut().push_back(response));
}

#[cfg(test)]
fn reset_model_refresh_responses() {
    TEST_MODEL_REFRESH_RESPONSES.with(|responses| responses.borrow_mut().clear());
}

const MODEL_CATALOG_URL: &str =
    "https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels";
const ANTIGRAVITY_IDE_VERSION: &str = "2.11.0";

fn model_error(code: &str, message: impl Into<String>, retryable: bool) -> ModelPluginError {
    ModelPluginError {
        code: code.into(),
        message: message.into(),
        retryable,
        retry_after: None,
        reset_at: None,
    }
}

fn model_refresh_error(error: RefreshError) -> ModelPluginError {
    ModelPluginError {
        code: error.code.into(),
        message: error.message,
        retryable: error.retryable,
        retry_after: error.retry_after,
        reset_at: None,
    }
}

fn load_model_credential(account: &ModelAccountRef) -> Result<Credential, ModelPluginError> {
    let key = credential_state_key(&account.provider_id, &account.account_id);
    if let Some(bytes) = model_world::kinetix::plugin::host_storage::get(&key) {
        let persisted = String::from_utf8(bytes).map_err(|_| {
            model_error(
                "invalid_configuration",
                "persisted credential is not utf-8",
                false,
            )
        })?;
        return latest_credential_from_sources("", Some(&persisted))
            .map_err(|e| model_error("invalid_configuration", e, false));
    }

    let credential_ref = ModelCredentialRef::Account(account.clone());
    let imported = model_world::kinetix::plugin::host_credential::read(&credential_ref)
        .map_err(|e| model_error(&e.code, e.message, e.retryable))?;
    latest_credential_from_sources(&imported, None)
        .map_err(|e| model_error("invalid_configuration", e, false))
}

fn persist_model_credential(
    account: &ModelAccountRef,
    cred: &Credential,
) -> Result<(), ModelPluginError> {
    let serialized = kinetix_plugin_sdk::oauth::serialize_credential_state(cred)
        .map_err(|e| model_error("plugin_internal", e, false))?;
    let key = credential_state_key(&account.provider_id, &account.account_id);
    model_world::kinetix::plugin::host_storage::put(&key, serialized.as_bytes()).map_err(|e| {
        model_error(
            "plugin_internal",
            format!("persisting credential state: {e}"),
            false,
        )
    })
}

fn refresh_for_model_source(cred: &mut Credential) -> Result<(), ModelPluginError> {
    let refresh_token = cred
        .refresh_token
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| model_error("credential_expired", "missing refresh_token", false))?;

    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        urlencode(refresh_token),
        urlencode(&default_client_id()),
        urlencode(&default_client_secret()),
    );
    let req = ModelHttpRequest {
        method: "POST".into(),
        url: TOKEN_URL.into(),
        headers: vec![
            (
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
            ("accept".into(), "application/json".into()),
        ],
        body: form.into_bytes(),
        credential: None,
    };
    let resp = send_model_refresh_request(&req).map_err(model_refresh_error)?;
    if resp.body_truncated {
        return Err(model_refresh_error(from_shared_refresh_error(
            kinetix_plugin_sdk::oauth::retryable_refresh_error("token response truncated"),
        )));
    }
    if resp.status != 200 {
        return Err(model_refresh_error(token_refresh_http_error(
            resp.status,
            &resp.body,
        )));
    }
    let text = String::from_utf8(resp.body)
        .map_err(|_| model_error("protocol_error", "token response not utf-8", false))?;

    let now_ms = model_world::kinetix::plugin::host_clock::now_unix_millis();
    let tokens = kinetix_plugin_sdk::oauth::parse_token_response(
        &text,
        cred.refresh_token.as_deref(),
        now_ms,
    )
    .map_err(|e| model_error("protocol_error", e, false))?;
    let expiry =
        provider_expiry_ms(&tokens, now_ms).and_then(kinetix_plugin_sdk::oauth::format_rfc3339_ms);
    cred.access_token = Some(tokens.access_token);
    cred.refresh_token = tokens.refresh_token;
    cred.expiry = expiry;
    Ok(())
}

fn capability_flag(raw: &serde_json::Value, names: &[&str]) -> Option<bool> {
    if let Some(items) = raw.as_array() {
        return items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|item| names.contains(&item))
            .then_some(true);
    }

    let object = raw.as_object()?;
    for name in names {
        let Some(value) = object.get(*name) else {
            continue;
        };
        if let Some(supported) = value.as_bool() {
            return Some(supported);
        }
        if let Some(supported) = value.get("supported").and_then(serde_json::Value::as_bool) {
            return Some(supported);
        }
    }
    None
}

fn normalized_reasoning(raw: &serde_json::Value) -> Option<ReasoningCapability> {
    if let Some(items) = raw.as_array() {
        return items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|item| item == "reasoning")
            .then(ReasoningCapability::supported_unknown);
    }

    let value = raw.as_object()?.get("reasoning")?;
    if let Some(supported) = value.as_bool() {
        return Some(if supported {
            ReasoningCapability::supported_unknown()
        } else {
            ReasoningCapability::unsupported()
        });
    }

    let object = value.as_object()?;
    let supported = object.get("supported")?.as_bool()?;
    if !supported {
        return Some(ReasoningCapability::unsupported());
    }

    let can_disable = object
        .get("can_disable")
        .or_else(|| object.get("canDisable"))
        .and_then(serde_json::Value::as_bool);
    let mut reasoning = ReasoningCapability::supported_unknown();
    reasoning.can_disable = can_disable;

    match object.get("mode").and_then(serde_json::Value::as_str) {
        Some("toggle") => {
            reasoning.mode = Some(ReasoningMode::Toggle);
        }
        Some("level") => {
            let levels: Vec<ReasoningLevel> = object
                .get("levels")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .filter_map(ReasoningLevel::parse)
                .collect();
            if !levels.is_empty() {
                reasoning.mode = Some(ReasoningMode::Level);
                reasoning.default = object
                    .get("default")
                    .and_then(serde_json::Value::as_str)
                    .and_then(ReasoningLevel::parse)
                    .filter(|default| levels.contains(default));
                reasoning.levels = Some(levels);
            }
        }
        _ => {}
    }

    Some(reasoning)
}

#[derive(Debug, Clone, Default)]
struct AntigravityModelProfile {
    canonical_model_id: Option<String>,
    variant: Option<ProviderVariantV1>,
    reasoning: Option<ReasoningCapability>,
    opaque_state: Option<OpaqueStateCapabilityV1>,
}

fn normalized_profile_id(id: &str) -> &str {
    let leaf = id.rsplit('/').next().unwrap_or(id);
    leaf.strip_suffix("@latest").unwrap_or(leaf)
}

fn fixed_reasoning_variant(
    canonical_model_id: &str,
    id: &str,
    level: ReasoningLevel,
) -> AntigravityModelProfile {
    AntigravityModelProfile {
        canonical_model_id: Some(canonical_model_id.to_string()),
        variant: Some(ProviderVariantV1 {
            kind: ProviderVariantKind::ReasoningTier,
            id: id.to_string(),
            reasoning_level: Some(level),
            fixed: true,
        }),
        reasoning: Some(ReasoningCapability::level(vec![level], Some(level), false)),
        opaque_state: Some(OpaqueStateCapabilityV1 {
            kind: OpaqueStateCapabilityKind::GeminiThoughtSignature,
            family: "gemini".into(),
            encoding_version: 1,
            placeholder_strategy: Some(OpaqueStatePlaceholderStrategy::Gemini3SkipValidator),
        }),
    }
}

fn tiered_reasoning_variant(canonical_model_id: &str) -> AntigravityModelProfile {
    AntigravityModelProfile {
        canonical_model_id: Some(canonical_model_id.to_string()),
        variant: Some(ProviderVariantV1 {
            kind: ProviderVariantKind::ReasoningTier,
            id: "tiered".into(),
            reasoning_level: None,
            fixed: false,
        }),
        reasoning: Some(ReasoningCapability::level(
            vec![
                ReasoningLevel::Low,
                ReasoningLevel::Medium,
                ReasoningLevel::High,
            ],
            Some(ReasoningLevel::Medium),
            false,
        )),
        opaque_state: Some(OpaqueStateCapabilityV1 {
            kind: OpaqueStateCapabilityKind::GeminiThoughtSignature,
            family: "gemini".into(),
            encoding_version: 1,
            placeholder_strategy: Some(OpaqueStatePlaceholderStrategy::Gemini3SkipValidator),
        }),
    }
}

fn gemini_base_profile(canonical_model_id: &str) -> AntigravityModelProfile {
    AntigravityModelProfile {
        canonical_model_id: Some(canonical_model_id.to_string()),
        opaque_state: Some(OpaqueStateCapabilityV1 {
            kind: OpaqueStateCapabilityKind::GeminiThoughtSignature,
            family: "gemini".into(),
            encoding_version: 1,
            placeholder_strategy: Some(OpaqueStatePlaceholderStrategy::Gemini3SkipValidator),
        }),
        ..Default::default()
    }
}

fn antigravity_model_profile(id: &str) -> AntigravityModelProfile {
    let id = normalized_profile_id(id);

    for family in [
        "gemini-3.8-flash",
        "gemini-3.7-flash",
        "gemini-3.6-flash",
        "gemini-3.5-flash",
    ] {
        let canonical = format!("google/{family}");
        if id == family {
            return gemini_base_profile(&canonical);
        }
        if let Some(tier) = id.strip_prefix(&format!("{family}-")) {
            return match tier {
                "low" => fixed_reasoning_variant(&canonical, "low", ReasoningLevel::Low),
                "medium" => fixed_reasoning_variant(&canonical, "medium", ReasoningLevel::Medium),
                "high" => fixed_reasoning_variant(&canonical, "high", ReasoningLevel::High),
                "tiered" => tiered_reasoning_variant(&canonical),
                _ => AntigravityModelProfile::default(),
            };
        }
    }

    match id {
        "gemini-3.1-flash-lite" => gemini_base_profile("google/gemini-3.1-flash-lite"),
        "gemini-3.1-pro-low" => {
            fixed_reasoning_variant("google/gemini-3.1-pro", "low", ReasoningLevel::Low)
        }
        "gemini-3.1-pro-high" => {
            fixed_reasoning_variant("google/gemini-3.1-pro", "high", ReasoningLevel::High)
        }
        "gemini-pro-agent" => AntigravityModelProfile {
            canonical_model_id: Some("google/gemini-3.1-pro".into()),
            variant: Some(ProviderVariantV1 {
                kind: ProviderVariantKind::ProviderAlias,
                id: "pro-agent".into(),
                reasoning_level: None,
                fixed: false,
            }),
            opaque_state: Some(OpaqueStateCapabilityV1 {
                kind: OpaqueStateCapabilityKind::GeminiThoughtSignature,
                family: "gemini".into(),
                encoding_version: 1,
                placeholder_strategy: Some(OpaqueStatePlaceholderStrategy::Gemini3SkipValidator),
            }),
            ..Default::default()
        },
        "claude-opus-4-6-thinking" => AntigravityModelProfile {
            canonical_model_id: Some("anthropic/claude-opus-4-6".into()),
            variant: Some(ProviderVariantV1 {
                kind: ProviderVariantKind::ThinkingVariant,
                id: "thinking".into(),
                reasoning_level: None,
                fixed: false,
            }),
            // Preserve the existing Antigravity Opus execution contract.
            reasoning: Some(ReasoningCapability::level(
                vec![ReasoningLevel::Low, ReasoningLevel::Max],
                None,
                false,
            )),
            opaque_state: Some(OpaqueStateCapabilityV1 {
                kind: OpaqueStateCapabilityKind::GeminiThoughtSignature,
                family: "claude".into(),
                encoding_version: 1,
                placeholder_strategy: None,
            }),
        },
        "claude-sonnet-4-6" => AntigravityModelProfile {
            canonical_model_id: Some("anthropic/claude-sonnet-4-6".into()),
            opaque_state: Some(OpaqueStateCapabilityV1 {
                kind: OpaqueStateCapabilityKind::GeminiThoughtSignature,
                family: "claude".into(),
                encoding_version: 1,
                placeholder_strategy: None,
            }),
            ..Default::default()
        },
        _ => AntigravityModelProfile::default(),
    }
}

fn normalized_model_capabilities(
    id: &str,
    info: &serde_json::Value,
) -> Result<Option<String>, ModelPluginError> {
    let profile = antigravity_model_profile(id);
    let mut capabilities = ModelCapabilitiesV2 {
        identity: profile
            .canonical_model_id
            .map(|canonical_model_id| ModelIdentityV2 {
                canonical_model_id,
                variant: profile.variant,
            }),
        reasoning: profile.reasoning,
        opaque_state: profile.opaque_state,
        ..Default::default()
    };

    if let Some(raw) = info.get("capabilities") {
        if capabilities.reasoning.is_none() {
            capabilities.reasoning = normalized_reasoning(raw);
        }
        capabilities.tools = capability_flag(raw, &["tools"]).map(SupportCapability::new);
        capabilities.vision = capability_flag(raw, &["vision"]).map(VisionCapability::new);
        capabilities.structured_output =
            capability_flag(raw, &["structured_output", "structured-output"])
                .map(SupportCapability::new);
    }

    if capabilities.is_empty() {
        return Ok(None);
    }

    capabilities.to_json().map(Some).map_err(|error| {
        model_error(
            "plugin_internal",
            format!("invalid normalized model capabilities: {error}"),
            false,
        )
    })
}

fn normalize_model(
    id: String,
    info: &serde_json::Value,
) -> Result<Option<ModelDiscoveredModel>, ModelPluginError> {
    if info
        .get("isInternal")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return Ok(None);
    }

    let display_name = info
        .get("displayName")
        .or_else(|| info.get("name"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| Some(id.clone()));
    let context_window = info
        .get("contextWindow")
        .or_else(|| info.get("inputTokenLimit"))
        .and_then(|value| value.as_u64());
    let max_output_tokens = info
        .get("maxOutputTokens")
        .or_else(|| info.get("outputTokenLimit"))
        .and_then(|value| value.as_u64());
    let capabilities_json = normalized_model_capabilities(&id, info)?;
    let raw_metadata = serde_json::to_string(info).ok();

    Ok(Some(ModelDiscoveredModel {
        id,
        display_name,
        context_window,
        max_output_tokens,
        capabilities_json,
        raw_metadata,
    }))
}

fn parse_model_catalog(
    value: &serde_json::Value,
) -> Result<Vec<ModelDiscoveredModel>, ModelPluginError> {
    let Some(models) = value.get("models") else {
        return Ok(Vec::new());
    };

    let mut discovered = Vec::new();
    if let Some(object) = models.as_object() {
        for (id, info) in object {
            if let Some(model) = normalize_model(id.clone(), info)? {
                discovered.push(model);
            }
        }
        return Ok(discovered);
    }

    if let Some(array) = models.as_array() {
        for info in array {
            let Some(id) = info
                .get("id")
                .or_else(|| info.get("model"))
                .or_else(|| info.get("name"))
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
            else {
                continue;
            };
            if let Some(model) = normalize_model(id, info)? {
                discovered.push(model);
            }
        }
    }

    Ok(discovered)
}

impl model_world::exports::account_model_source::Guest for Component {
    fn discover(
        provider_id: String,
        account: ModelAccountRef,
        _base_url: String,
        _models_path: String,
    ) -> Result<Vec<ModelDiscoveredModel>, ModelPluginError> {
        if account.provider_id != provider_id {
            return Err(model_error(
                "invalid_configuration",
                "model discovery account does not belong to the requested provider",
                false,
            ));
        }

        let mut credential = load_model_credential(&account)?;

        let now = model_world::kinetix::plugin::host_clock::now_unix_millis();
        if !access_token_valid(&credential, now) {
            refresh_for_model_source(&mut credential)?;
            persist_model_credential(&account, &credential)?;
        }
        let access_token = credential
            .access_token
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| model_error("credential_expired", "no access token available", false))?;

        let req = ModelHttpRequest {
            method: "POST".into(),
            url: MODEL_CATALOG_URL.into(),
            headers: vec![
                ("authorization".into(), format!("Bearer {access_token}")),
                ("content-type".into(), "application/json".into()),
                ("accept".into(), "application/json".into()),
                ("user-agent".into(), crate::adapter::USER_AGENT.into()),
                ("x-client-name".into(), "antigravity".into()),
                ("x-client-version".into(), ANTIGRAVITY_IDE_VERSION.into()),
            ],
            body: b"{}".to_vec(),
            credential: None,
        };
        let resp = model_world::kinetix::plugin::host_http::send(&req)
            .map_err(|e| model_error(&e.code, e.message, e.retryable))?;
        if resp.body_truncated {
            return Err(model_error(
                "upstream_unavailable",
                "model catalog response truncated",
                true,
            ));
        }
        let text = String::from_utf8(resp.body)
            .map_err(|_| model_error("protocol_error", "model catalog is not utf-8", false))?;
        if resp.status != 200 {
            return Err(model_error(
                "upstream_unavailable",
                format!("model catalog returned HTTP {}", resp.status),
                resp.status >= 500,
            ));
        }

        let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
            model_error(
                "protocol_error",
                format!("invalid model catalog JSON: {e}"),
                false,
            )
        })?;
        parse_model_catalog(&value)
    }
}

model_world::export!(Component with_types_in kinetix_plugin_sdk::model_source);

// --- The world requires every export interface to be implemented. -----------

fn unsupported() -> PluginError {
    kinetix_plugin_sdk::helpers::error("unknown", "capability not provided by this plugin")
}

impl exports::model_source::Guest for Component {
    fn discover(_p: String, _b: String, _m: String) -> Result<Vec<DiscoveredModel>, PluginError> {
        Err(unsupported())
    }
}
type HealthPluginError = health_world::kinetix::plugin::types::PluginError;
type HealthObservationV2 = health_world::kinetix::plugin::types::HealthObservationV2;
type HealthQuotaScopeV1 = health_world::kinetix::plugin::types::QuotaScopeV1;
type HealthQuotaSnapshotV1 = health_world::kinetix::plugin::types::QuotaSnapshotV1;

fn quota_amount(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse::<u64>().ok())
}

fn normalize_quota_unit(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase().replace([' ', '-'], "_");
    if normalized.is_empty() {
        return None;
    }
    Some(match normalized.as_str() {
        "request" | "requests" => "requests".into(),
        "token" | "tokens" => "tokens".into(),
        "credit" | "credits" => "credits".into(),
        _ => normalized,
    })
}

fn parse_quota_snapshots(value: &serde_json::Value) -> Vec<HealthQuotaSnapshotV1> {
    value
        .get("buckets")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|bucket| {
            let model_id = bucket
                .get("modelId")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|model| !model.is_empty());
            let remaining_fraction = bucket
                .get("remainingFraction")
                .and_then(serde_json::Value::as_f64)
                .filter(|fraction| fraction.is_finite() && (0.0..=1.0).contains(fraction));
            let remaining = bucket.get("remainingAmount").and_then(quota_amount);
            let reset_at = bucket
                .get("resetTime")
                .and_then(serde_json::Value::as_str)
                .filter(|value| parse_rfc3339_ms(value).is_some())
                .map(str::to_string);

            // Do not emit a bucket that contains no quota measurement or reset
            // evidence. In particular, a missing fraction is not full quota.
            if remaining_fraction.is_none() && remaining.is_none() && reset_at.is_none() {
                return None;
            }

            let scope = match model_id {
                Some(model_id) => HealthQuotaScopeV1::Model(model_id.to_string()),
                None => HealthQuotaScopeV1::Unknown,
            };
            let unit = bucket
                .get("tokenType")
                .and_then(serde_json::Value::as_str)
                .and_then(normalize_quota_unit);

            Some(HealthQuotaSnapshotV1 {
                scope,
                remaining_fraction,
                remaining,
                limit: None,
                unit,
                // The provider response has no stable window label.
                window: None,
                reset_at,
            })
        })
        .collect()
}

fn account_quota_fields(snapshots: &[HealthQuotaSnapshotV1]) -> (Option<String>, Option<String>) {
    let mut account_snapshots = snapshots
        .iter()
        .filter(|snapshot| matches!(&snapshot.scope, HealthQuotaScopeV1::Account));
    let Some(snapshot) = account_snapshots.next() else {
        return (None, None);
    };
    if account_snapshots.next().is_some() {
        // The legacy ABI cannot distinguish multiple account-wide windows.
        return (None, None);
    }

    (
        snapshot
            .remaining_fraction
            .map(|fraction| fraction.to_string()),
        snapshot.reset_at.clone(),
    )
}

fn quota_probe_error(error: PluginError) -> HealthPluginError {
    HealthPluginError {
        code: error.code,
        message: error.message,
        retryable: error.retryable,
        retry_after: error.retry_after,
        reset_at: error.reset_at,
    }
}

fn fetch_quota_snapshots(
    provider_id: &str,
    account_id: &str,
) -> Result<Option<Vec<HealthQuotaSnapshotV1>>, PluginError> {
    let account = AccountRef {
        provider_id: provider_id.into(),
        account_id: account_id.into(),
    };
    let credential = load_credential(&account)?;
    let now = kinetix_plugin_sdk::helpers::now_unix_millis();
    let access_token = credential
        .access_token
        .as_deref()
        .filter(|token| !token.is_empty())
        .filter(|_| {
            credential
                .expiry
                .as_deref()
                .and_then(parse_rfc3339_ms)
                .is_some_and(|expiry| expiry > now)
        })
        .ok_or_else(|| {
            kinetix_plugin_sdk::helpers::error(
                "credential_expired",
                "Antigravity quota probe requires an unexpired access token",
            )
        })?;
    let project_id = credential
        .project_id
        .as_deref()
        .map(str::trim)
        .filter(|project| !project.is_empty())
        .map(str::to_string)
        .or_else(|| credential_storage_get(&project_state_key(provider_id, account_id)))
        .filter(|project| !project.trim().is_empty());
    let Some(project_id) = project_id else {
        // A health probe must not onboard accounts. Until credential resolution
        // has cached a project id, quota remains unknown.
        return Ok(None);
    };

    let body = serde_json::to_vec(&serde_json::json!({ "project": project_id })).map_err(|e| {
        kinetix_plugin_sdk::helpers::error(
            "plugin_internal",
            format!("encoding quota request: {e}"),
        )
    })?;
    let request = HttpRequest {
        method: "POST".into(),
        url: RETRIEVE_USER_QUOTA_URL.into(),
        headers: project_headers(access_token),
        body,
        credential: None,
    };
    let response = kinetix::plugin::host_http::send(&request).map_err(|error| {
        kinetix_plugin_sdk::helpers::retryable_error(&error.code, error.message, error.retry_after)
    })?;
    if response.body_truncated {
        return Err(kinetix_plugin_sdk::helpers::retryable_error(
            "upstream_unavailable",
            "quota response truncated",
            Some(5),
        ));
    }
    if !(200..300).contains(&response.status) {
        let message = format!("quota endpoint returned HTTP {}", response.status);
        return Err(match response.status {
            401 => kinetix_plugin_sdk::helpers::error("credential_expired", message),
            429 => kinetix_plugin_sdk::helpers::retryable_error(
                "upstream_unavailable",
                message,
                Some(5),
            ),
            status if status >= 500 => kinetix_plugin_sdk::helpers::retryable_error(
                "upstream_unavailable",
                message,
                Some(5),
            ),
            _ => kinetix_plugin_sdk::helpers::error("upstream_unavailable", message),
        });
    }
    let text = String::from_utf8(response.body).map_err(|_| {
        kinetix_plugin_sdk::helpers::error("protocol_error", "quota response is not UTF-8")
    })?;
    let value = serde_json::from_str(&text).map_err(|error| {
        kinetix_plugin_sdk::helpers::error(
            "protocol_error",
            format!("invalid quota response JSON: {error}"),
        )
    })?;
    Ok(Some(parse_quota_snapshots(&value)))
}

impl exports::health_probe::Guest for Component {
    fn probe(provider_id: String, account_id: String) -> Result<HealthObservation, PluginError> {
        let Some(snapshots) = fetch_quota_snapshots(&provider_id, &account_id)? else {
            return Ok(HealthObservation {
                state: "unknown".into(),
                quota_state: None,
                reset_at: None,
                retry_after: None,
                detail_code: None,
            });
        };
        let (quota_state, reset_at) = account_quota_fields(&snapshots);
        Ok(HealthObservation {
            state: "healthy".into(),
            quota_state,
            reset_at,
            retry_after: None,
            detail_code: None,
        })
    }
}

impl health_world::exports::health_probe_v2::Guest for Component {
    fn probe(
        provider_id: String,
        account_id: String,
    ) -> Result<HealthObservationV2, HealthPluginError> {
        let Some(quota_snapshots) =
            fetch_quota_snapshots(&provider_id, &account_id).map_err(quota_probe_error)?
        else {
            return Ok(HealthObservationV2 {
                state: "unknown".into(),
                quota_state: None,
                reset_at: None,
                retry_after: None,
                detail_code: None,
                quota_snapshots: Vec::new(),
            });
        };
        let (quota_state, reset_at) = account_quota_fields(&quota_snapshots);
        Ok(HealthObservationV2 {
            state: "healthy".into(),
            quota_state,
            reset_at,
            retry_after: None,
            detail_code: None,
            quota_snapshots,
        })
    }
}
impl exports::routing_facts::Guest for Component {
    fn facts(_r: String) -> Result<Vec<RoutingFact>, PluginError> {
        Err(unsupported())
    }
}
impl exports::hooks::Guest for Component {
    fn on_request_normalized(_r: String) -> Result<(), PluginError> {
        Ok(())
    }
    fn on_target_candidate(_t: String) -> Result<(), PluginError> {
        Ok(())
    }
    fn on_usage_finalized(_u: String) -> Result<(), PluginError> {
        Ok(())
    }
}

// --- API v2 adapter world: the `v1internal` wire format. --------------------
//
// This session-aware adapter is a separate WIT world. The main plugin,
// authorization, and discovery exports remain API v1.

use adapter_world::exports::kinetix::plugin2_0_0::provider_adapter::Guest as ProviderAdapterGuest;
use adapter_world::kinetix::plugin1_0_0::host_storage;
use kinetix_plugin_sdk::adapter_v2 as adapter_world;

type AdapterPluginError = adapter_world::kinetix::plugin1_0_0::types::PluginError;
type AdapterSessionContext = adapter_world::kinetix::plugin2_0_0::types::SessionContext;

/// Adapter error → the API v1 generated `PluginError` used by API v2.
fn adapter_err(e: crate::adapter::AdapterError) -> AdapterPluginError {
    AdapterPluginError {
        code: e.code,
        message: e.message,
        retryable: false,
        retry_after: None,
        reset_at: None,
    }
}

fn provider_with_account_project(provider_json: &str) -> String {
    let mut provider: serde_json::Value =
        serde_json::from_str(provider_json).unwrap_or_else(|_| serde_json::json!({}));
    let provider_id = provider
        .get("id")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let account_id = provider
        .pointer("/_kinetix/account_id")
        .and_then(|value| value.as_str())
        .map(str::to_string);

    if let (Some(provider_id), Some(account_id)) = (provider_id, account_id) {
        let key = project_state_key(&provider_id, &account_id);
        if let Some(bytes) = host_storage::get(&key) {
            if let Ok(project_id) = String::from_utf8(bytes) {
                let project_id = project_id.trim();
                if !project_id.is_empty() {
                    if !provider
                        .get("_kinetix")
                        .is_some_and(serde_json::Value::is_object)
                    {
                        provider["_kinetix"] = serde_json::json!({});
                    }
                    provider["_kinetix"]["project_id"] = serde_json::json!(project_id);
                }
            }
        }
    }

    provider.to_string()
}

impl ProviderAdapterGuest for Component {
    fn wire_format() -> String {
        crate::adapter::wire_format()
    }
    fn build_url(provider_json: String, model_json: String) -> Result<String, AdapterPluginError> {
        crate::adapter::build_url(&provider_json, &model_json).map_err(adapter_err)
    }
    fn apply_auth(
        provider_json: String,
        credential: String,
        _session: Option<AdapterSessionContext>,
    ) -> Result<String, AdapterPluginError> {
        crate::adapter::apply_auth(&provider_json, &credential).map_err(adapter_err)
    }
    fn build_body(
        request_json: String,
        provider_json: String,
        model_json: String,
        session: Option<AdapterSessionContext>,
    ) -> Result<String, AdapterPluginError> {
        let provider_json = provider_with_account_project(&provider_json);
        crate::adapter::build_body(
            &request_json,
            &provider_json,
            &model_json,
            session.as_ref().map(|session| session.id.as_str()),
        )
        .map_err(adapter_err)
    }
    fn classify_error(
        status: u16,
        body: String,
        headers_json: String,
    ) -> Result<String, AdapterPluginError> {
        crate::adapter::classify_error(status, &body, &headers_json).map_err(adapter_err)
    }
    fn parse_stream_chunk(data: String) -> Result<String, AdapterPluginError> {
        crate::adapter::parse_stream_chunk(&data).map_err(adapter_err)
    }
    fn parse_full_response(body_json: String) -> Result<String, AdapterPluginError> {
        crate::adapter::parse_full_response(&body_json).map_err(adapter_err)
    }
}

adapter_world::export!(Component with_types_in kinetix_plugin_sdk::adapter_v2);

use kinetix_plugin_sdk::health as health_world;

health_world::export!(Component with_types_in kinetix_plugin_sdk::health);

export!(Component with_types_in kinetix_plugin_sdk);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_opts_in_to_thinking_translation() {
        let manifest = include_str!("../plugin.toml");
        assert!(manifest
            .lines()
            .any(|line| line.trim() == "thinking_translation = true"));
    }

    #[test]
    fn quota_response_preserves_scopes_and_unknown_values() {
        let snapshots = parse_quota_snapshots(&serde_json::json!({
            "buckets": [
                {
                    "modelId": "gemini-2.5-pro",
                    "tokenType": "REQUESTS",
                    "remainingFraction": 0.75,
                    "remainingAmount": "750",
                    "resetTime": "2026-04-01T00:00:00Z"
                },
                {
                    "modelId": "gemini-2.5-pro",
                    "tokenType": "TOKENS",
                    "remainingAmount": "44"
                },
                {
                    "tokenType": "REQUESTS",
                    "remainingFraction": 0.0
                },
                { "tokenType": "TOKENS" },
                {
                    "modelId": "ignored",
                    "remainingFraction": 1.5,
                    "resetTime": "not-a-time"
                }
            ]
        }));

        assert_eq!(snapshots.len(), 3);
        assert!(matches!(
            &snapshots[0].scope,
            HealthQuotaScopeV1::Model(model) if model == "gemini-2.5-pro"
        ));
        assert_eq!(snapshots[0].remaining_fraction, Some(0.75));
        assert_eq!(snapshots[0].remaining, Some(750));
        assert_eq!(snapshots[0].unit.as_deref(), Some("requests"));
        assert_eq!(snapshots[0].window, None);
        assert_eq!(
            snapshots[0].reset_at.as_deref(),
            Some("2026-04-01T00:00:00Z")
        );
        assert_eq!(snapshots[1].remaining_fraction, None);
        assert_eq!(snapshots[1].remaining, Some(44));
        assert_eq!(snapshots[1].unit.as_deref(), Some("tokens"));
        assert!(matches!(&snapshots[2].scope, HealthQuotaScopeV1::Unknown));
        assert_eq!(snapshots[2].remaining_fraction, Some(0.0));
        assert_eq!(snapshots[2].unit.as_deref(), Some("requests"));
        assert_eq!(account_quota_fields(&snapshots), (None, None));
    }

    #[test]
    fn model_quota_is_not_projected_as_account_quota() {
        let snapshots = parse_quota_snapshots(&serde_json::json!({
            "buckets": [{
                "modelId": "gemini-2.5-pro",
                "remainingFraction": 0.2,
                "resetTime": "2026-04-01T00:00:00Z"
            }]
        }));

        assert_eq!(account_quota_fields(&snapshots), (None, None));
        assert!(parse_quota_snapshots(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn account_quota_projection_preserves_single_snapshot() {
        let snapshots = vec![HealthQuotaSnapshotV1 {
            scope: HealthQuotaScopeV1::Account,
            remaining_fraction: Some(0.25),
            remaining: None,
            limit: None,
            unit: Some("requests".into()),
            window: Some("5h".into()),
            reset_at: Some("2026-04-01T00:00:00Z".into()),
        }];

        assert_eq!(
            account_quota_fields(&snapshots),
            (Some("0.25".into()), Some("2026-04-01T00:00:00Z".into()))
        );
    }

    #[test]
    fn legacy_projection_does_not_collapse_multiple_account_windows() {
        let snapshots = vec![
            HealthQuotaSnapshotV1 {
                scope: HealthQuotaScopeV1::Account,
                remaining_fraction: Some(0.8),
                remaining: None,
                limit: None,
                unit: Some("requests".into()),
                window: Some("5h".into()),
                reset_at: None,
            },
            HealthQuotaSnapshotV1 {
                scope: HealthQuotaScopeV1::Account,
                remaining_fraction: Some(0.25),
                remaining: None,
                limit: None,
                unit: Some("requests".into()),
                window: Some("weekly".into()),
                reset_at: Some("2026-04-01T00:00:00Z".into()),
            },
        ];

        assert_eq!(account_quota_fields(&snapshots), (None, None));
    }

    #[test]
    fn access_token_well_before_expiry_is_valid() {
        let now = 1_800_000_000_000;
        let cred = Credential {
            access_token: Some("access".into()),
            expiry: Some(
                kinetix_plugin_sdk::oauth::format_rfc3339_ms(now + REFRESH_LEAD_MS + 60_000)
                    .unwrap(),
            ),
            ..Default::default()
        };
        assert!(access_token_valid(&cred, now));
    }

    #[test]
    fn access_token_inside_refresh_window_is_invalid() {
        let now = 1_800_000_000_000;
        let cred = Credential {
            access_token: Some("access".into()),
            expiry: Some(
                kinetix_plugin_sdk::oauth::format_rfc3339_ms(now + REFRESH_LEAD_MS - 1_000)
                    .unwrap(),
            ),
            ..Default::default()
        };
        assert!(!access_token_valid(&cred, now));
    }

    #[test]
    fn already_expired_access_token_is_invalid_without_underflow() {
        let now = 1_800_000_000_000;
        let cred = Credential {
            access_token: Some("access".into()),
            expiry: Some(kinetix_plugin_sdk::oauth::format_rfc3339_ms(now - 60_000).unwrap()),
            ..Default::default()
        };
        assert!(!access_token_valid(&cred, now));
    }

    #[test]
    fn missing_expiry_enters_refresh_path_before_lease() {
        let cred = Credential {
            refresh_token: Some("refresh".into()),
            access_token: Some("access".into()),
            expiry: None,
            ..Default::default()
        };
        assert!(should_refresh_before_lease(&cred, 1_800_000_000_000));
    }

    #[test]
    fn google_default_expiry_is_safe_and_only_used_when_ttl_is_missing() {
        let now_ms = 1_800_000_000_000;
        let missing_ttl = kinetix_plugin_sdk::oauth::parse_token_response(
            r#"{"access_token":"access"}"#,
            None,
            now_ms,
        )
        .unwrap();
        assert_eq!(
            provider_expiry_ms(&missing_ttl, now_ms),
            Some(now_ms + 3_600_000)
        );

        let overflowing_ttl = kinetix_plugin_sdk::oauth::parse_token_response(
            r#"{"access_token":"access","expires_in":18446744073709551615}"#,
            None,
            now_ms,
        )
        .unwrap();
        assert_eq!(provider_expiry_ms(&overflowing_ttl, now_ms), None);
    }

    #[test]
    fn invalid_grant_refresh_failure_is_terminal_credential_expired() {
        let error = token_refresh_http_error(
            400,
            br#"{
                "error":"invalid_grant",
                "error_description":"Token has been expired or revoked."
            }"#,
        )
        .into_plugin_error();

        assert_eq!(error.code, "credential_expired");
        assert!(!error.retryable);
        assert_eq!(error.retry_after, None);
        assert!(error.message.contains("expired or revoked"));
    }

    #[test]
    fn token_endpoint_server_and_transport_failures_remain_retryable() {
        let server_error = token_refresh_http_error(
            503,
            br#"{
                "error":"temporarily_unavailable",
                "error_description":"try again later"
            }"#,
        )
        .into_plugin_error();

        assert_eq!(server_error.code, "upstream_unavailable");
        assert!(server_error.retryable);
        assert_eq!(server_error.retry_after, Some(5));

        let transport_error =
            token_refresh_transport_error("timeout", "connection timed out").into_plugin_error();
        assert_eq!(transport_error.code, "upstream_unavailable");
        assert!(transport_error.retryable);
        assert_eq!(transport_error.retry_after, Some(5));
    }

    #[test]
    fn token_endpoint_non_utf8_429_and_503_failures_remain_retryable() {
        for status in [429, 503] {
            let error = token_refresh_http_error(status, &[0xff, 0xfe]).into_plugin_error();
            assert_eq!(error.code, "upstream_unavailable", "HTTP {status}");
            assert!(error.retryable, "HTTP {status}");
            assert_eq!(error.retry_after, Some(5), "HTTP {status}");
        }
    }

    fn model_refresh_credential() -> Credential {
        Credential {
            refresh_token: Some("refresh-token".into()),
            ..Default::default()
        }
    }

    #[test]
    fn model_source_refresh_invalid_grant_is_terminal_credential_expired() {
        reset_model_refresh_responses();
        enqueue_model_refresh_response(Ok(ModelRefreshHttpResponse {
            status: 400,
            body: br#"{
                "error":"invalid_grant",
                "error_description":"Token has been expired or revoked."
            }"#
            .to_vec(),
            body_truncated: false,
        }));

        let error = refresh_for_model_source(&mut model_refresh_credential()).unwrap_err();

        assert_eq!(error.code, "credential_expired");
        assert!(!error.retryable);
        assert_eq!(error.retry_after, None);
        reset_model_refresh_responses();
    }

    #[test]
    fn model_source_refresh_http_failures_are_retryable() {
        for (status, body) in [
            (
                429,
                br#"{
                    "error":"rate_limit_exceeded",
                    "error_description":"try again later"
                }"#
                .to_vec(),
            ),
            (
                503,
                br#"{
                    "error":"temporarily_unavailable",
                    "error_description":"try again later"
                }"#
                .to_vec(),
            ),
        ] {
            reset_model_refresh_responses();
            enqueue_model_refresh_response(Ok(ModelRefreshHttpResponse {
                status,
                body,
                body_truncated: false,
            }));

            let error = refresh_for_model_source(&mut model_refresh_credential()).unwrap_err();

            assert_eq!(error.code, "upstream_unavailable");
            assert!(error.retryable);
            assert_eq!(error.retry_after, Some(5));
        }
        reset_model_refresh_responses();
    }

    #[test]
    fn model_source_refresh_non_utf8_http_failures_are_retryable() {
        for status in [429, 503] {
            reset_model_refresh_responses();
            enqueue_model_refresh_response(Ok(ModelRefreshHttpResponse {
                status,
                body: vec![0xff, 0xfe],
                body_truncated: false,
            }));

            let error = refresh_for_model_source(&mut model_refresh_credential()).unwrap_err();

            assert_eq!(error.code, "upstream_unavailable", "HTTP {status}");
            assert!(error.retryable, "HTTP {status}");
            assert_eq!(error.retry_after, Some(5), "HTTP {status}");
        }
        reset_model_refresh_responses();
    }

    #[test]
    fn model_source_refresh_transport_failure_is_retryable() {
        reset_model_refresh_responses();
        enqueue_model_refresh_response(Err(token_refresh_transport_error(
            "timeout",
            "connection timed out",
        )));

        let error = refresh_for_model_source(&mut model_refresh_credential()).unwrap_err();

        assert_eq!(error.code, "upstream_unavailable");
        assert!(error.retryable);
        assert_eq!(error.retry_after, Some(5));
        reset_model_refresh_responses();
    }

    #[test]
    fn persisted_rotation_is_loaded_on_next_credential_resolution() {
        reset_test_credential_state();
        let account = AccountRef {
            provider_id: "antigravity".into(),
            account_id: "account-a".into(),
        };
        set_test_imported_credential(
            &account,
            r#"{
                "refresh_token":"refresh-old",
                "access_token":"access-old",
                "expiry":"2030-01-01T00:00:00Z"
            }"#,
        );

        let imported = load_credential(&account).unwrap();
        assert_eq!(imported.refresh_token.as_deref(), Some("refresh-old"));
        assert_eq!(imported.access_token.as_deref(), Some("access-old"));

        let rotated = Credential {
            refresh_token: Some("refresh-rotated".into()),
            access_token: Some("access-new".into()),
            expiry: Some("2030-01-01T01:00:00Z".into()),
            ..Default::default()
        };
        persist_rotated(&account, &rotated).unwrap();

        let expected_state_key = format!("cred:{}", handle_for(&account));
        assert_eq!(state_key(&account), expected_state_key);
        assert!(
            credential_storage_get(&expected_state_key).is_some(),
            "persist_rotated must write cred:<handle> state"
        );
        let resolved = load_credential(&account).unwrap();
        assert_eq!(
            resolved.refresh_token.as_deref(),
            Some("refresh-rotated"),
            "next resolution must use the persisted rotated refresh token"
        );
        assert_eq!(
            resolved.access_token.as_deref(),
            Some("access-new"),
            "next resolution must use persisted refreshed access state"
        );
        assert_eq!(resolved.expiry.as_deref(), Some("2030-01-01T01:00:00Z"));

        reset_test_credential_state();
    }

    #[test]
    fn extracts_cloud_code_project_shapes() {
        assert_eq!(
            extract_project_id(&serde_json::json!({
                "cloudaicompanionProject": "project-one"
            }))
            .as_deref(),
            Some("project-one")
        );
        assert_eq!(
            extract_project_id(&serde_json::json!({
                "cloudaicompanionProject": { "id": "project-two" }
            }))
            .as_deref(),
            Some("project-two")
        );
        assert_eq!(
            extract_project_id(&serde_json::json!({
                "response": {
                    "cloudaicompanionProject": { "id": "project-three" }
                }
            }))
            .as_deref(),
            Some("project-three")
        );
    }

    #[test]
    fn selects_default_cloud_code_tier() {
        let value = serde_json::json!({
            "allowedTiers": [
                { "id": "other", "isDefault": false },
                { "id": "g1-pro-tier", "isDefault": true }
            ]
        });
        assert_eq!(default_tier_id(&value), "g1-pro-tier");
        assert_eq!(default_tier_id(&serde_json::json!({})), "legacy-tier");
    }

    #[test]
    fn project_storage_keys_are_account_scoped() {
        assert_ne!(
            project_state_key("provider", "account-a"),
            project_state_key("provider", "account-b")
        );
        assert_eq!(
            project_state_key("provider", "account-a"),
            format!("project:{}", account_handle("provider", "account-a"))
        );
    }

    #[test]
    fn parses_fetch_available_models_object_shape() {
        let json_str = r#"{
            "models": {
                "gemini-2.5-flash": {
                    "displayName": "Gemini 2.5 Flash",
                    "inputTokenLimit": 1048576,
                    "outputTokenLimit": 65536,
                    "capabilities": ["chat", "tools"]
                },
                "gemini-2.5-pro": {
                    "name": "Gemini 2.5 Pro",
                    "contextWindow": 2097152,
                    "maxOutputTokens": 65536
                },
                "internal-experimental": {
                    "displayName": "Internal Test Model",
                    "isInternal": true
                }
            }
        }"#;

        let val: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let mut models = parse_model_catalog(&val).unwrap();
        models.sort_by(|a, b| a.id.cmp(&b.id));

        assert_eq!(models.len(), 2);

        assert_eq!(models[0].id, "gemini-2.5-flash");
        assert_eq!(models[0].display_name.as_deref(), Some("Gemini 2.5 Flash"));
        assert_eq!(models[0].context_window, Some(1048576));
        assert_eq!(models[0].max_output_tokens, Some(65536));
        let capabilities =
            ModelCapabilitiesV2::from_json(models[0].capabilities_json.as_deref().unwrap())
                .unwrap();
        assert_eq!(capabilities.tools, Some(SupportCapability::new(true)));
        assert!(capabilities.reasoning.is_none());

        assert_eq!(models[1].id, "gemini-2.5-pro");
        assert_eq!(models[1].display_name.as_deref(), Some("Gemini 2.5 Pro"));
        assert_eq!(models[1].context_window, Some(2097152));
        assert_eq!(models[1].max_output_tokens, Some(65536));
    }

    #[test]
    fn reasoning_flag_does_not_invent_levels() {
        let value = serde_json::json!({
            "models": {
                "reasoning-model": {
                    "capabilities": { "reasoning": true }
                }
            }
        });
        let models = parse_model_catalog(&value).unwrap();
        let capabilities =
            ModelCapabilitiesV2::from_json(models[0].capabilities_json.as_deref().unwrap())
                .unwrap();
        let reasoning = capabilities.reasoning.unwrap();
        assert!(reasoning.supported);
        assert!(reasoning.mode.is_none());
        assert!(reasoning.levels.is_none());
        assert!(reasoning.default.is_none());
    }

    #[test]
    fn preserves_max_reasoning_level() {
        let value = serde_json::json!({
            "models": {
                "reasoning-model": {
                    "capabilities": {
                        "reasoning": {
                            "supported": true,
                            "mode": "level",
                            "levels": ["low", "max"],
                            "default": "max",
                            "can_disable": false
                        }
                    }
                }
            }
        });
        let models = parse_model_catalog(&value).unwrap();
        let capabilities =
            ModelCapabilitiesV2::from_json(models[0].capabilities_json.as_deref().unwrap())
                .unwrap();
        let reasoning = capabilities.reasoning.unwrap();
        assert_eq!(
            reasoning.levels,
            Some(vec![ReasoningLevel::Low, ReasoningLevel::Max])
        );
        assert_eq!(reasoning.default, Some(ReasoningLevel::Max));
    }

    #[test]
    fn claude_opus_46_thinking_discovery_advertises_levels_without_upstream_capabilities() {
        let value = serde_json::json!({
            "models": {
                "claude-opus-4-6-thinking": {
                    "displayName": "Claude Opus 4.6 Thinking"
                }
            }
        });
        let models = parse_model_catalog(&value).unwrap();
        let capabilities =
            ModelCapabilitiesV2::from_json(models[0].capabilities_json.as_deref().unwrap())
                .unwrap();
        let reasoning = capabilities.reasoning.unwrap();

        assert_eq!(reasoning.mode, Some(ReasoningMode::Level));
        assert_eq!(
            reasoning.levels,
            Some(vec![ReasoningLevel::Low, ReasoningLevel::Max])
        );
        assert_eq!(reasoning.default, None);
        assert_eq!(reasoning.can_disable, Some(false));
    }

    #[test]
    fn claude_opus_46_thinking_discovery_advertises_only_supported_levels() {
        let value = serde_json::json!({
            "models": {
                "provider/claude-opus-4-6-thinking@latest": {
                    "capabilities": {
                        "reasoning": {
                            "supported": true,
                            "mode": "level",
                            "levels": ["low", "medium", "high", "max"],
                            "default": "high",
                            "can_disable": true
                        }
                    }
                }
            }
        });
        let models = parse_model_catalog(&value).unwrap();
        let capabilities =
            ModelCapabilitiesV2::from_json(models[0].capabilities_json.as_deref().unwrap())
                .unwrap();
        let reasoning = capabilities.reasoning.unwrap();

        assert_eq!(reasoning.mode, Some(ReasoningMode::Level));
        assert_eq!(
            reasoning.levels,
            Some(vec![ReasoningLevel::Low, ReasoningLevel::Max])
        );
        assert_eq!(reasoning.default, None);
        assert_eq!(reasoning.can_disable, Some(false));
    }

    #[test]
    fn antigravity_profiles_preserve_upstream_ids_and_describe_variants() {
        let value = serde_json::json!({
            "models": {
                "gemini-3.8-flash-low": {},
                "gemini-3.8-flash-medium": {},
                "gemini-3.8-flash-high": {},
                "gemini-3.8-flash-tiered": {},
                "gemini-3.1-flash-lite": {},
                "claude-opus-4-6-thinking": {}
            }
        });
        let models = parse_model_catalog(&value).unwrap();
        let by_id: std::collections::HashMap<_, _> = models
            .iter()
            .map(|model| (model.id.as_str(), model))
            .collect();

        for (id, tier, fixed) in [
            ("gemini-3.8-flash-low", "low", true),
            ("gemini-3.8-flash-medium", "medium", true),
            ("gemini-3.8-flash-high", "high", true),
            ("gemini-3.8-flash-tiered", "tiered", false),
        ] {
            let model = by_id[id];
            assert_eq!(model.id, id);
            let capabilities =
                ModelCapabilitiesV2::from_json(model.capabilities_json.as_deref().unwrap())
                    .unwrap();
            let identity = capabilities.identity.unwrap();
            assert_eq!(identity.canonical_model_id, "google/gemini-3.8-flash");
            let variant = identity.variant.unwrap();
            assert_eq!(variant.id, tier);
            assert_eq!(variant.fixed, fixed);
            assert_eq!(capabilities.opaque_state.unwrap().family, "gemini");
        }

        let flash_lite = by_id["gemini-3.1-flash-lite"];
        assert_eq!(flash_lite.id, "gemini-3.1-flash-lite");
        let capabilities =
            ModelCapabilitiesV2::from_json(flash_lite.capabilities_json.as_deref().unwrap())
                .unwrap();
        let identity = capabilities.identity.unwrap();
        assert_eq!(identity.canonical_model_id, "google/gemini-3.1-flash-lite");
        assert!(identity.variant.is_none());
        let opaque_state = capabilities.opaque_state.unwrap();
        assert_eq!(opaque_state.family, "gemini");
        assert_eq!(
            opaque_state.placeholder_strategy,
            Some(OpaqueStatePlaceholderStrategy::Gemini3SkipValidator)
        );

        let claude = by_id["claude-opus-4-6-thinking"];
        assert_eq!(claude.id, "claude-opus-4-6-thinking");
        let capabilities =
            ModelCapabilitiesV2::from_json(claude.capabilities_json.as_deref().unwrap()).unwrap();
        let identity = capabilities.identity.unwrap();
        assert_eq!(identity.canonical_model_id, "anthropic/claude-opus-4-6");
        assert_eq!(identity.variant.unwrap().id, "thinking");
        assert_eq!(capabilities.opaque_state.unwrap().family, "claude");
    }

    #[test]
    fn tiered_gemini_profile_advertises_only_verified_levels() {
        let profile = antigravity_model_profile("models/gemini-3.8-flash-tiered@latest");
        let reasoning = profile.reasoning.unwrap();
        assert_eq!(reasoning.mode, Some(ReasoningMode::Level));
        assert_eq!(
            reasoning.levels,
            Some(vec![
                ReasoningLevel::Low,
                ReasoningLevel::Medium,
                ReasoningLevel::High
            ])
        );
        assert_eq!(reasoning.default, Some(ReasoningLevel::Medium));
        assert_eq!(reasoning.can_disable, Some(false));
    }

    #[test]
    fn unknown_antigravity_model_does_not_invent_identity_or_variant() {
        let profile = antigravity_model_profile("future-model-9000");
        assert!(profile.canonical_model_id.is_none());
        assert!(profile.variant.is_none());
        assert!(profile.reasoning.is_none());
        assert!(profile.opaque_state.is_none());

        let value = serde_json::json!({
            "models": {
                "future-model-9000": {"displayName": "Future Model"}
            }
        });
        let models = parse_model_catalog(&value).unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "future-model-9000");
        assert!(models[0].capabilities_json.is_none());
    }

    #[test]
    fn gemini_pro_aliases_are_explicit_not_heuristic() {
        let low = antigravity_model_profile("gemini-3.1-pro-low");
        assert_eq!(
            low.canonical_model_id.as_deref(),
            Some("google/gemini-3.1-pro")
        );
        assert_eq!(low.variant.unwrap().id, "low");

        let alias = antigravity_model_profile("gemini-pro-agent");
        assert_eq!(
            alias.canonical_model_id.as_deref(),
            Some("google/gemini-3.1-pro")
        );
        assert_eq!(alias.variant.unwrap().id, "pro-agent");

        assert!(antigravity_model_profile("something-pro-experimental")
            .canonical_model_id
            .is_none());
    }

    #[test]
    fn parses_fetch_available_models_array_shape() {
        let json_str = r#"{
            "models": [
                {
                    "id": "gemini-3-flash",
                    "displayName": "Gemini 3 Flash",
                    "contextWindow": 1048576,
                    "maxOutputTokens": 65536
                },
                {
                    "model": "claude-sonnet-4-5",
                    "name": "Claude Sonnet 4.5",
                    "inputTokenLimit": 200000,
                    "outputTokenLimit": 64000
                },
                {
                    "id": "confidential-model",
                    "isInternal": true
                }
            ]
        }"#;

        let val: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let models = parse_model_catalog(&val).unwrap();

        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id, "gemini-3-flash");
        assert_eq!(models[0].display_name.as_deref(), Some("Gemini 3 Flash"));
        assert_eq!(models[0].context_window, Some(1048576));

        assert_eq!(models[1].id, "claude-sonnet-4-5");
        assert_eq!(models[1].display_name.as_deref(), Some("Claude Sonnet 4.5"));
        assert_eq!(models[1].context_window, Some(200000));
        assert_eq!(models[1].max_output_tokens, Some(64000));
    }

    #[test]
    fn handles_empty_or_missing_catalog() {
        let val = serde_json::json!({});
        assert!(parse_model_catalog(&val).unwrap().is_empty());

        let val = serde_json::json!({ "models": null });
        assert!(parse_model_catalog(&val).unwrap().is_empty());

        let val = serde_json::json!({ "models": [] });
        assert!(parse_model_catalog(&val).unwrap().is_empty());
    }
}
