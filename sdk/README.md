# Kinetix Plugin SDK (Rust)

Author-facing Rust bindings for the Kinetix plugin ABI. The canonical ABI lives at `../wit/kinetix-plugin.wit`; the SDK keeps a synchronized copy in `sdk/wit/` for `wit-bindgen`.

Host/runtime architecture is documented in the main [Kinetix repository](https://github.com/PrightCord/kinetix/blob/main/docs/KINETIX-PLUGIN-ARCHITECTURE.md).

## Build a plugin component

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

Use `scripts/build-plugin.sh plugins/<plugin>` from the repository root to wrap the compiled component into a deterministic `.kxp` package.

The ABI is the WIT interface, not this crate. Breaking changes require a new `plugin_api` major; deployed API v1 and v2 packages retain their existing contracts.

## Plugin/core ownership

Plugins implement provider mechanisms: authorization steps, credential resolution, discovery, health observations, request/response translation, and deterministic routing facts. They report results; they do not choose accounts, models, or runtime targets.

Kinetix core owns scheduling, observation and credential persistence, health interpretation, retry/fallback, concurrency, cache affinity, and target selection. `host-storage` holds plugin-private state; core persists account health, model inventory, and credentials. `health-observation` and `quota-snapshot` are evidence, and `routing-fact` informs core policy without selecting a target. Adapter inputs describe the provider/model already selected by core. API v1 and v2 retain their existing host-import contracts. API v3 adapters have no host imports; core supplies reserved `_kinetix` context in `provider-json` (account ID, host time, and a non-secret project ID when available) rather than letting adapters read storage or a clock.

`sdk/tests/policy_boundary.rs` guards versioned WIT operations and import contracts. `scripts/test_adapter_component_runtime.sh` invokes the compiled Antigravity v3 adapter with every host import set to trap. Provider conformance tests live in `adapter-conformance/`.

## Session-aware adapter APIs v2 and v3

Keep existing plugins on `plugin_api = "1"` and the `adapter` bindings. Existing session-aware API v2 packages keep `kinetix_plugin_sdk::adapter_v2` (`plugin-adapter-v2` in `kinetix:plugin@2.0.0`) and their host imports. New plugins that need the import-free adapter contract use `kinetix_plugin_sdk::adapter_v3` (`plugin-adapter-v3` in `kinetix:plugin@3.0.0`) and declare `plugin_api = "3"`. API v3 retains the session-aware adapter signatures, removes host imports, and receives reserved `_kinetix` context from core. Hosts can support API v1, v2, and v3 concurrently; older hosts reject API majors they do not support.

## Capability metadata

Use the SDK's versioned model capability types for `DiscoveredModel.capabilities_json`, and declare integration-wide features and protocols in `plugin.toml`. See [plugin capability contracts](../docs/plugin-capabilities.md) for scope, validation, and compatibility details. The WIT field remains an optional string, so plugin API v1 is unchanged.

## OAuth lifecycle

`kinetix_plugin_sdk::oauth` provides provider-neutral helpers for checked expiry arithmetic, RFC3339 expiry parsing, token-response validation and rotation, persisted credential state, and refresh-error classification. Providers still own their authorization protocol and KV key selection.

```rust,ignore
let tokens = kinetix_plugin_sdk::oauth::parse_token_response(body, previous_refresh, now_ms)?;
if kinetix_plugin_sdk::oauth::needs_refresh(expires_at_ms, now_ms, refresh_lead_ms) {
    // Refresh using the provider-specific endpoint, then persist the full state.
}
```

## Versioned health quota observations

The optional `plugin-health-v2` world exposes `HealthObservationV2` and multiple `QuotaSnapshotV1` values without changing the legacy health-probe ABI. Plugins can export both worlds; hosts must opt into v2 to read snapshots, while older plugins continue using `plugin`.

Quota is evidence, not a routing decision. Missing fields and an empty snapshot list mean unknown, never zero or full. Use account scope only when the provider establishes it; model scope requires the exact provider model ID. Preserve provider groups and bucket IDs without inferring scope. Report only provider-supplied amounts, units, windows, and RFC3339 reset times. Amounts are finite, non-negative, and may be fractional; `remaining_fraction` is in `[0, 1]`.
