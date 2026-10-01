# Antigravity OAuth

Kinetix plugin for Google Antigravity / Cloud Code Assist. It provides:

- the `antigravity-oauth` credential strategy;
- the `antigravity` AuthFlow;
- account-aware model discovery and structured quota health observations;
- the `antigravity` (`v1internal`) provider adapter.

Quota probes query both unstable quota RPCs on `daily-cloudcode-pa.googleapis.com` first, then fall back to `cloudcode-pa.googleapis.com`. `retrieveUserQuotaSummary` supplies grouped short-window and weekly buckets; `retrieveUserQuota` supplements per-model buckets. Either source may fail without discarding the other's evidence. A quota RPC returning 404 on both hosts is treated as unsupported; if both RPCs are unsupported, quota remains unknown. Grouped buckets retain provider group and bucket labels; windows are normalized from explicit values or bucket labels. Disabled weekly buckets are omitted, while disabled 5h/session buckets report zero remaining. Buckets without an exact model ID stay unknown-scoped; absent measurements stay unknown. Probes do not onboard accounts when no project ID is cached.

## Connect from Kinetix

For the bundled desktop/native Google OAuth client, use a loopback public base URL such as `http://127.0.0.1:8080`, bind the provider to this plugin, then use **Connect** from Plugins & Integrations.

```text
provider.credential_plugin = "plugin:dev.kinetix.antigravity-oauth/antigravity-oauth"
provider.wire_plugin       = "plugin:dev.kinetix.antigravity-oauth/antigravity"
```

## Permissions

The v3 adapter is a pure translator and has no host imports. Before `build-body`, Kinetix provides `_kinetix.project_id` from the selected account credential's non-secret project identity and `_kinetix.now_unix_millis` in `provider-json`; the adapter does not retrieve account state or time from host storage/clock capabilities.

The manifest requests:

- outbound HTTP to `accounts.google.com`, `oauth2.googleapis.com`, `www.googleapis.com`, `cloudcode-pa.googleapis.com`, and `daily-cloudcode-pa.googleapis.com`;
- credential scope `credential_strategy:antigravity-oauth`;
- plaintext credential read for OAuth refresh-token exchange.

`credential_read = true` is a materially higher-risk permission and should remain visible in Kinetix permission review.

## Build

```sh
rustup target add wasm32-unknown-unknown
scripts/build-plugin.sh plugins/antigravity-oauth
```
