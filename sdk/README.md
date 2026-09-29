# Kinetix Plugin SDK (Rust)

Author-facing Rust bindings for the Kinetix plugin ABI. The canonical ABI lives at `../wit/kinetix-plugin.wit`; the SDK keeps a synchronized copy in `sdk/wit/` for `wit-bindgen`.

Host/runtime architecture is documented in the main [Kinetix repository](https://github.com/PrightCord/kinetix/blob/main/docs/KINETIX-PLUGIN-ARCHITECTURE.md).

## Build a plugin component

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

Use `scripts/build-plugin.sh plugins/<plugin>` from the repository root to wrap the compiled component into a deterministic `.kxp` package.

The ABI is the WIT interface, not this crate.

## Session-aware adapter API v2

Keep existing plugins on `plugin_api = "1"` and the `adapter` bindings. Plugins that need opaque session context must use `kinetix_plugin_sdk::adapter_v2` (`plugin-adapter-v2` in `kinetix:plugin@2.0.0`) and declare `plugin_api = "2"`. API v1 WIT and adapter exports remain unchanged; the v2 world reuses v1 host capabilities and plugin types. Hosts can support both adapter worlds concurrently, while v1-only hosts reject API v2 plugins.

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
