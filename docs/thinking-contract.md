# Plugin thinking contract

A plugin that owns reasoning behavior ships `plugins/<name>/thinking-contract.json` and runs it from its own tests. **A declaration without executable proof fails CI.**

Host-side counterpart: the host's `docs/thinking-contract.md` pins `client intent -> canonical intent -> exact provider body` for built-in adapters. A plugin adapter receives the canonical level as `thinking: {"level": "<key>"}`, so these contracts pin `canonical level -> exact provider body`. Client intent to canonical level is host-owned and shared by every plugin.

## Who needs a contract

| Plugin provides | Contract `kind` | Proves |
|---|---|---|
| `provider_adapters` | `adapter` | real `build_body`: the complete provider body or an explicit rejection for every canonical level on every model class |
| `model_sources` / `account_model_sources` (no adapter) | `model_source` | real discovery: the exact `capabilities.reasoning` the host consumes |
| neither (credential-only plugins) | none | nothing to prove |

`scripts/validate_manifests.py` enforces, for every plugin (so future plugins are covered automatically):

- the contract file exists, `plugin` equals the manifest id, `kind` matches;
- an adapter contract's `translation` equals `provides.thinking_translation`;
- `provides.thinking_translation = true` requires a provider adapter and a contract that translates at least one level;
- the plugin's sources run the contract (`check_thinking_contract` / `check_model_source_contract` with `include_str!("../thinking-contract.json")`).

## Adapter contracts

`{schema_version, kind: "adapter", plugin, translation, provider, models: {name: <model json>}, cases: [{name, model, level, expect}]}`

`level` is a canonical level or `null` (client sent no thinking intent). `expect` is `{"body": <complete provider JSON>}` or `{"rejected": "<message>"}`; a rejection must also say the control is unsupported.

Matrix, enforced by `adapter-conformance/src/thinking.rs`: every model pins the absent case and all eight canonical levels (`off`, `default`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`).

- `off` is the disable shape, or a rejection when the provider cannot disable.
- `default` is the adaptive intent (Anthropic `thinking: adaptive` without effort). A plugin must translate it or reject it; it may not silently drop it.
- Explicit budgets reach plugins as the canonical level the host bucketed them into; the provider budget value for that level is pinned in the body (for example `thinkingBudget: 8192` for `medium`).
- Categorical levels are each mapped or rejected.
- `translation: false` means every level is rejected; any accepted level fails.

## Model-source contracts

`{schema_version, kind: "model_source", plugin, cases: [{name, input, reasoning}]}`

`input` is a plugin-specific upstream list item; `reasoning` is the exact `capabilities.reasoning` JSON (`null` = unknown). The plugin cannot declare `thinking_translation`: the host builds the provider body from this capability. A `level` capability with a known dialect becomes an executable map (B.AI: `reasoning_effort` `low` / `high` / `max`, plus `none` when `can_disable`); `{"supported": true}` alone carries no control metadata, so the host rejects every level for it. The matching body goldens live in the host's `tests/fixtures/thinking-translation/plugin-b-ai.json` and `plugin-ai-studio.json`.

## Changing a golden

1. Change the behavior and run `cargo test -p <plugin crate> thinking`.
2. Review each reported `expected` / `actual` diff against the provider's documentation.
3. Edit the fixture by hand and explain the compatibility change in the PR. Provider behavior needs official documentation or observed upstream evidence; do not invent mappings to make a level pass.
