# Antigravity OAuth

Kinetix plugin for Google Antigravity / Cloud Code Assist. It provides:

- the `antigravity-oauth` credential strategy;
- the `antigravity` AuthFlow;
- account-aware model discovery and structured quota health observations;
- the `antigravity` (`v1internal`) provider adapter.

Quota probes call Antigravity's unstable `retrieveUserQuotaSummary` RPC on `daily-cloudcode-pa.googleapis.com`. Grouped short-window and weekly buckets retain provider group, bucket, and window labels. Buckets without an exact model ID stay unknown-scoped; absent measurements stay unknown. Probes do not onboard accounts when no project ID is cached.

## Connect from Kinetix

For the bundled desktop/native Google OAuth client, use a loopback public base URL such as `http://127.0.0.1:8080`, bind the provider to this plugin, then use **Connect** from Plugins & Integrations.

```text
provider.credential_plugin = "plugin:dev.kinetix.antigravity-oauth/antigravity-oauth"
provider.wire_plugin       = "plugin:dev.kinetix.antigravity-oauth/antigravity"
```

## Permissions

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
