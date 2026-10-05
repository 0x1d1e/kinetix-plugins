# Kinetix Plugins

Official plugin collection, plugin SDK, catalog metadata, build tooling, and release artifacts for [Kinetix](https://github.com/0x1d1e/kinetix).

This repository is split out of the Kinetix monorepo so plugin development, testing, signing, and distribution can evolve independently from the host runtime.

> [!IMPORTANT]
> **kinetix-plugins is rebooting at 0.1.0 together with Kinetix.** The reboot
> breaks the plugin contract. When 0.1.0 ships, all existing releases and tags
> (including per-plugin tags such as `opencode-free-v0.1.9`) will be deleted.
> The pre-reboot source will stay on the `legacy/v0.6` branch.
>
> - `kinetix update` on 0.6.x will not detect 0.1.0. Reinstall Kinetix
>   manually with `install.sh`.
> - Plugin installs from Kinetix 0.6.x will fail once the old release assets
>   are gone.
> - Plugin version numbers restart, so a version string such as `0.1.7` may
>   refer to a different artifact before and after the reboot.
>
> Plan: [Kinetix docs/reboot.md](https://github.com/0x1d1e/kinetix/blob/main/docs/reboot.md).
> Decision: [ADR-0001](https://github.com/0x1d1e/kinetix/blob/main/docs/adr/0001-reboot-versioning.md).

## Repository layout

```text
.
├── plugins/                  # First-party plugin sources
├── sdk/                      # Rust guest SDK
├── wit/                      # Mirror of the host plugin contract (WIT, schemas, fixtures)
├── catalog.json              # Authoritative marketplace metadata
├── trusted-publishers.json   # Publisher trust metadata
├── scripts/                  # Build/signing helpers
└── .github/workflows/        # Plugin CI and release automation
```

The Kinetix host runtime, dashboard integration, database migrations, and host-side plugin tests remain in `0x1d1e/kinetix`.

## Build plugins

Prerequisites:

- Rust
- `wasm32-unknown-unknown`
- `wasm-tools`

Build one plugin:

```sh
rustup target add wasm32-unknown-unknown
bash scripts/build-plugin.sh plugins/claude-code-oauth
```

That produces two versioned artifacts beside the plugin source:

```text
dev.kinetix.claude-code-oauth-0.1.0.kxp
dev.kinetix.claude-code-oauth-0.1.0.wasm
```

The `.kxp` is the canonical installable Kinetix package. The `.wasm` file is the standalone WebAssembly Component binary contained by that package. See [the v1 package contract](docs/plugin-packages-v1.md) for archive, identity, digest, signature, and provenance rules.

Inspect proposed installation objects and permissions without applying them:

```sh
python3 scripts/plan_install.py --manifest plugins/ai-studio/plugin.toml
```

See [the draft install-plan contract](docs/plugin-install-v1.md) for credential declarations, package inspection, and host approval requirements. New fields require [companion host support](https://github.com/0x1d1e/kinetix/pull/190) before release.

Build every first-party plugin into one output directory:

```sh
bash scripts/build-all.sh --out-dir dist
```

GitHub Actions is validation-only. Production plugin artifacts are built and published locally by maintainers.

## Releases

Plugins are released locally and independently. The release command derives the version from `plugin.toml` and uses a tag in the form:

```text
<plugin-directory>-v<semver>
```

Dry-run the full build/sign/validation path first:

```sh
export KINETIX_PLUGIN_SIGNING_KEY_FILE=~/.config/kinetix/plugin-signing.pem
bash scripts/release-plugin.sh claude-code-oauth
```

Publish after the dry run succeeds:

```sh
bash scripts/release-plugin.sh claude-code-oauth --publish
```

The local release script requires an authenticated `gh` CLI for publishing. It builds from a clean detached source worktree, signs the package locally, validates the WebAssembly component, generates `SHA256SUMS`, creates/pushes the annotated tag, and uploads immutable release assets:

- `<plugin-id>-<version>.kxp` — signed installable package;
- `<plugin-id>-<version>.wasm` — standalone component binary;
- `SHA256SUMS` — hashes for both artifacts.

The signing private key stays on the maintainer machine and never enters GitHub Actions.

A release does **not** automatically make a catalog entry installable. After the signed release exists, update `catalog.json` with its exact distribution URL, SHA-256, publisher key id, and allowed hosts before setting `installable = true`.

## Current plugins

- **Google AI Studio** (`dev.kinetix.ai-studio`) — native Gemini provider defaults and authenticated live model discovery.
- **B.AI** (`dev.kinetix.b-ai`) — native OpenAI provider defaults, authenticated live discovery, and provider-specific model metadata.
- **Google Antigravity** (`dev.kinetix.antigravity-oauth`) — OAuth credential strategy, account model discovery, and `v1internal` provider adapter.
- **Claude Code OAuth** (`dev.kinetix.claude-code-oauth`) — Anthropic Claude Code PKCE OAuth, token exchange, and refresh-token rotation.
- **OpenCode Free** (`dev.kinetix.opencode-free`) — OpenCode Free no-auth provider adapter and dynamic model discovery.

## Compatibility

The plugin contract is owned by `0x1d1e/kinetix`: its `wit/` directory holds the canonical WIT worlds, JSON contract schemas, and shared golden fixtures. This repository keeps byte-identical copies in `wit/` and `sdk/wit*/`; only the fixture trees listed in `PLUGIN_OWNED` (`scripts/sync_host_contract.py`) originate here. Change the contract in the host first, then mirror it:

```bash
scripts/sync_host_contract.py            # copy from $KINETIX_DIR or ../kinetix
scripts/sync_host_contract.py --check    # CI: fail on drift
```

Plugins that provide a provider adapter or model source must pin their reasoning behavior with a `thinking-contract.json`; `provides.thinking_translation = true` without a passing contract fails CI. See [Plugin thinking contract](docs/thinking-contract.md).

Before adding host imports or another plugin runtime, read the [WASM capability security contract](docs/wasm-capability-security-v1.md) and run its consumer conformance fixtures.

See [MIGRATION.md](MIGRATION.md) for the original extraction boundary and source revision.
