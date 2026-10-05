# Declarative install plans v1 (draft)

This proposal is not frozen. Host parser support and shared manifest conformance must land before this contract is finalized or packages using its new fields are released.

Install plans are reviewable proposals, not installation authority. Kinetix owns credential enrollment, storage, validation, permission approval, object persistence, and traffic activation. Generating a plan runs no plugin code and reads no host state or secrets.

## Declarations

The [manifest schema](../schemas/plugin-manifest-v1.schema.json) defines installation metadata. Every integration used in a plan must explicitly declare the core-owned `credential_mode`:

- `none`: no credential binding, account proposal, or credential proposal.
- `manual`: `manual_credential.kind` and nonempty `manual_credential.requirements` name the inputs the host must request. They contain no values, defaults, or plugin-defined validation rules. A credential strategy is optional.
- `auth_flow`: `auth_flow` and `credential_strategy` reference capabilities provided by the same package. The plan does not start the flow.

Legacy manifests without a mode remain valid package metadata. The planner rejects them instead of duplicating the host's legacy enrollment inference. Unknown or incomplete installation declarations fail before any plan is emitted.

Accounts and routes are opt-in. For a manual integration, for example:

```toml
# Inside an existing [[integrations]] declaration:
credential_mode = "manual"

[integrations.manual_credential]
kind = "api_key"
requirements = ["api_key"]

[integrations.install.account]
name = "My account"

[[integrations.install.routes]]
id = "chat"
model = "gemini-2.5-flash"
```

An account proposal also produces a credential acquisition request, never a credential value. With no `install.account`, neither object is proposed. Routes target the integration's provider account pool, even when an initial account is proposed. They never pin that account; ranking, balancing, failover, and sticky-affinity selection remain core-owned. Missing routes stay absent; model discovery does not invent them. An install declaration requires a provider template. V1 supports one account proposal per integration, with route IDs unique within that integration.

**Host coordination:** `credential_mode` already exists in core. `manual_credential` and `install` are new manifest fields; strict older hosts reject them. The host parser must support these fields before packages containing them are released. [Kinetix PR #190](https://github.com/0x1d1e/kinetix/pull/190) adds parsing and validation only, without applying proposals or changing enrollment policy. Older parsers remain incompatible.

## Generate and inspect

```sh
python3 scripts/plan_install.py --manifest plugins/ai-studio/plugin.toml
python3 scripts/plan_install.py --package dist/dev.kinetix.ai-studio-0.1.2.kxp
python3 scripts/test_plan_install.py
```

The package path performs structural package validation and includes the complete archive SHA-256. It does not verify signature trust or host compatibility. Source-manifest plans make no archive digest claim.

The [plan schema](../schemas/install-plan-v1.schema.json) defines the portable result. Object references are package-local proposal keys, not database IDs. Integrations retain their declarations except `install`; account and credential proposals reference each other, and routes reference only their integration. Permissions remain requests, including plaintext credential-read requests.

`manifest_sha256` hashes the parsed manifest serialized with Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)` and encoded as ASCII, with no trailing newline. This semantic digest covers all manifest fields and is distinct from the byte-level package signing digest. It does not establish trust.

Plan JSON uses sorted keys, two-space indentation, ASCII escapes, and a final LF. Object arrays sort by integration ID, then route ID; permission lists and acquisition requirements sort lexically. Identical inputs yield identical bytes, with no timestamps or random IDs. Array reordering in the input may change the semantic manifest digest.

Every plan states `apply_requires_approval = true` and `traffic_enabled = false`. These are contract invariants, not approval tokens. The host must bind review to the package digest, obtain explicit approval, resolve local references, and perform enrollment before it can enable traffic. A plugin cannot supply approval, activation, routing priorities, or secret values through installation metadata. There is no apply command.

[Shared manifest vectors](../wit/fixtures/plugin-manifest/v1/cases.json) cover native-only packages, anonymous auth, public connection parameters, legacy metadata, proposed objects, and invalid declarations. The identical corpus is tested by the companion Kinetix parser. `host_baseline` pins the main revision tested before the companion; `baseline_valid` records its acceptance, while `valid` records acceptance with companion support. `plan_valid` additionally requires explicit enrollment metadata.

[Plan fixtures](../wit/fixtures/plugin-install/v1/) cover OpenCode Free, Antigravity, AI Studio, B.AI, and invalid declarations. Their models and account labels are examples, not claims of host acceptance or current upstream availability.
