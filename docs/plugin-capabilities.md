# Plugin capabilities

Kinetix has two capability declarations with different scope:

- Integration metadata in `plugin.toml` is the integration-wide ceiling.
- `DiscoveredModel.capabilities_json` narrows support for one discovered model.

A missing model declaration means unknown, not unsupported. An explicit `false` at either level vetoes support. Inference adapters remain responsible for implementing the declared behavior.

## Integration metadata

A manifest may declare versioned features and protocol compatibility together:

```toml
[integrations.features]
schema_version = 1
streaming = true
tools = true
parallel_tools = false
vision = false
reasoning = true
structured_output = false
model_discovery = true
quota_probe = false
health_probe = false

[integrations.protocols]
input = ["openai-chat", "anthropic"]
upstream = ["plugin-native"]
```

Feature fields are required booleans. Protocol values use the normalized transport names: `openai-chat`, `openai-responses`, `anthropic`, `gemini`, and `plugin-native`. `protocols.input` is a hard routing allowlist; an empty list permits no inbound protocol. `protocols.upstream` is validated against the configured provider transport when the integration creates or reconciles a provider; `plugin-native` requires a usable bound provider adapter. `parallel_tools` requires `tools`; `model_discovery` must match whether the integration declares a `model_source`. Older manifests may omit both tables during migration; declaring only one is invalid.

## Per-model metadata

The WIT ABI continues to carry `capabilities_json` as an optional string. The SDK provides strict versioned types. V1 and V2 remain available; V3 adds typed transport formats, endpoint paths, transport alternatives, and `parallel_tools`.

```json
{
  "schema_version": 3,
  "transport": {
    "format": "openai-responses",
    "endpoint": "/zen/v1/responses",
    "alternatives": [
      { "format": "openai-chat", "endpoint": "/zen/v1/chat/completions" }
    ]
  },
  "tools": { "supported": true },
  "parallel_tools": { "supported": false }
}
```

`transport.format` is the preferred semantic protocol. Alternatives are ordered fallbacks. An endpoint, when supplied, is a relative path beginning with `/`; it cannot contain a query, fragment, whitespace, backslash, or `.`/`..` path segment. An adapter may derive an endpoint when metadata omits one, but should not infer a model's protocol from its ID. If it cannot resolve an unknown model safely, it should fail conservatively.

Use `ModelCapabilitiesV3::to_json()` and `from_json()` to validate V3 metadata. The SDK also exposes `IntegrationFeaturesV1`, `IntegrationProtocolsV1`, and helpers for intersecting integration and model support. Manifest declarations are checked by `scripts/validate_manifests.py` and its focused tests.
