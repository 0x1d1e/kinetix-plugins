# Kinetix Plugins

Guest SDK, first-party plugins, catalog, and `.kxp` packaging for the Kinetix gateway. The host runtime lives in `PrightCord/kinetix`.

## Boundaries

- `sdk/` - Rust guest SDK. `plugins/` - first-party plugin crates. `catalog.json` / `trusted-publishers.json` - authoritative marketplace and trust metadata.
- The plugin contract (WIT worlds, JSON schemas, shared golden fixtures) is canonical in the host repo's `wit/`. `wit/` and `sdk/wit*/` here are byte-identical mirrors: change the host first, then run `scripts/sync_host_contract.py`. Never edit mirrored files directly.
- Only the fixture trees in `PLUGIN_OWNED` (`scripts/sync_host_contract.py`) originate here.

## Invariants

- Plugins are untrusted by the host; never rely on host leniency for malformed output.
- Provider-specific behavior must be backed by official documentation or observed upstream behavior.
- Do not invent model capabilities, pricing, token limits, or credential behavior.
- Publishing: a signed release does not make a catalog entry installable; follow `README.md`.

## Validation

```bash
scripts/run-ci.sh   # needs a host checkout at $KINETIX_DIR or ../kinetix
```

Use Conventional Commits.
