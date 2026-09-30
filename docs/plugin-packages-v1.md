# Plugin package contract v1

This repository defines plugin metadata and `.kxp` packaging. Kinetix owns installation-time compatibility checks, permission approval, digest verification, and signature trust decisions. The validators here check the source manifest and package structure; they do not authorize installation.

## Manifest and identity

[`schemas/plugin-manifest-v1.schema.json`](../schemas/plugin-manifest-v1.schema.json) is the canonical schema for parsed `plugin.toml`. Unknown manifest fields are invalid. `id` and `version` define package identity; catalog names and descriptions are display metadata and cannot replace them. `plugin_api` names the ABI major as a decimal string. Compatibility fields are claims for the host to evaluate; a missing bound makes no compatibility claim. Resource limits and permissions are requests, not grants.

A release artifact is named `<id>-<version>.kxp`. The catalog's `id`, `latest_version`, and `artifact_name` must match the manifest identity. The host must report a mismatch rather than silently installing under the catalog's identity.

## `.kxp` archive

A v1 `.kxp` is an uncompressed TAR with regular files at the archive root. `plugin.toml` and `plugin.wasm` are required. `README.md`, `LICENSE`, `signature.ed25519`, and `provenance.json` are optional. The WASM file must have the WebAssembly magic and version header. Duplicate names, nested paths, traversal paths, and non-regular entries are invalid. The host also enforces a 64 MiB package limit, a 64 MiB component limit, 2 MiB each for `plugin.toml`, `README.md`, and `LICENSE`, and a 4096-byte signature limit. This repository's validator also caps `provenance.json` at 2 MiB.

Unknown top-level regular files have no v1 meaning and are ignored by the host. Producers should emit only the listed files. The package validator accepts such unknown files to match host parsing behavior.

The package SHA-256 is over the complete `.kxp` byte stream. Catalog distribution digests cover the archive bytes, including TAR headers and optional entries. `scripts/build-plugin.sh` emits a deterministic TAR so identical inputs produce the same artifact digest.

## Signatures and publisher identity

`signature.ed25519` contains either 64 raw Ed25519 signature bytes or their Base64 encoding. The signed message is the 32-byte SHA-256 digest of `plugin.wasm` bytes followed by the exact UTF-8 bytes of `plugin.toml`. The signature does not cover README, LICENSE, provenance, or TAR headers. The build script emits raw signature bytes.

Publisher keys live in [`trusted-publishers.json`](../trusted-publishers.json), validated against [`schemas/trusted-publishers-v1.schema.json`](../schemas/trusted-publishers-v1.schema.json). Each record names an Ed25519 key and its publisher label. The catalog selects a `publisher_key_id`; its publisher label must match the selected key record. A signature verifies only when it matches an enabled trusted key. Missing signatures are unsigned; well-formed signatures that do not verify against a trusted key are untrusted. The host decides whether an unsigned or untrusted package may be installed.

No publisher identity is embedded in the signed payload. The trusted key registry supplies the key-to-publisher association; catalog text alone does not establish trust.

## Provenance and unknown values

Optional `provenance.json` follows [`schemas/package-provenance-v1.schema.json`](../schemas/package-provenance-v1.schema.json). It records source repository, revision, and whether the source tree was clean when the package was built. Provenance is informational and is not covered by the package signature. Missing provenance means unknown source metadata, not trusted or compatible.

The manifest schema rejects unknown fields. Missing optional compatibility or capability metadata remains unspecified; consumers must not infer support. Package/catalog identity mismatches fail validation. Unknown archive files are ignored and do not confer capabilities or trust.

## Fixtures and checks

[`wit/fixtures/kxp/v1/`](../wit/fixtures/kxp/v1/) covers valid, malformed, incompatible, unsigned, identity-mismatched, and tampered cases. The valid, incompatible, and tampered signatures use a fixture-only publisher key; its private key is not committed. The tests verify the signatures against the public key and confirm the tampered manifest no longer verifies.

Run package, manifest, and catalog checks with:

```sh
python3 scripts/test_validate_manifests.py
python3 scripts/validate_manifests.py
python3 scripts/test_validate_packages.py
python3 scripts/test_validate_catalog.py
python3 scripts/validate_catalog.py
```
