#!/usr/bin/env python3
"""Check catalog identity, artifact, and publisher metadata against plugin sources."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import pathlib
import re
import sys
import tomllib
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

from validate_manifests import validate_plugin_directory

ROOT = pathlib.Path(__file__).resolve().parent.parent
TRUSTED_PUBLISHERS_SCHEMA = json.loads(
    (ROOT / "schemas/trusted-publishers-v1.schema.json").read_text(encoding="utf-8")
)
TRUSTED_PUBLISHERS_VALIDATOR = Draft202012Validator(TRUSTED_PUBLISHERS_SCHEMA)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_catalog_data(
    catalog: object,
    publishers_data: object,
    plugin_versions: dict[str, str],
    plugin_capabilities: dict[str, set[str]] | None = None,
) -> int:
    require(isinstance(catalog, dict), "catalog must be an object")
    require(catalog.get("schema_version") == 1, "catalog schema_version must be 1")
    entries = catalog.get("plugins")
    require(isinstance(entries, list), "catalog plugins must be an array")

    publisher_errors = sorted(
        TRUSTED_PUBLISHERS_VALIDATOR.iter_errors(publishers_data),
        key=lambda error: list(map(str, error.absolute_path)),
    )
    if publisher_errors:
        error = publisher_errors[0]
        location = ".".join(map(str, error.absolute_path)) or "trusted-publishers"
        raise ValueError(f"{location}: {error.message}")

    trusted: dict[str, dict] = {}
    for item in publishers_data["publishers"]:
        key_id = item["id"]
        require(key_id not in trusted, f"duplicate publisher key id {key_id}")
        try:
            public_key = base64.b64decode(item["public_key_base64"], validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError(f"publisher {key_id} has invalid base64 public key") from error
        require(len(public_key) == 32, f"publisher {key_id} public key must be 32 bytes")
        trusted[key_id] = item

    seen: set[str] = set()
    for entry in entries:
        require(isinstance(entry, dict), "catalog plugin entry must be an object")
        plugin_id = entry.get("id")
        version = entry.get("latest_version")
        require(isinstance(plugin_id, str) and plugin_id, "catalog plugin id is required")
        require(plugin_id not in seen, f"duplicate catalog plugin id {plugin_id}")
        seen.add(plugin_id)
        require(plugin_id in plugin_versions, f"catalog entry has no source package {plugin_id}")
        require(plugin_versions[plugin_id] == version,
                f"catalog {plugin_id} version {version!r} does not match plugin.toml {plugin_versions[plugin_id]!r}")
        require(isinstance(version, str) and re.fullmatch(
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?",
            version,
        ) is not None, f"catalog {plugin_id} has invalid latest_version")
        expected_artifact = f"{plugin_id}-{version}.kxp"
        require(entry.get("artifact_name") == expected_artifact,
                f"catalog {plugin_id} artifact_name must be {expected_artifact!r}")

        distribution = entry.get("distribution")
        require(isinstance(distribution, dict), f"catalog {plugin_id} distribution must be an object")
        digest = distribution.get("sha256")
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                f"catalog {plugin_id} distribution sha256 must be 64 lowercase hex characters")
        key_id = distribution.get("publisher_key_id")
        require(isinstance(key_id, str) and key_id in trusted,
                f"catalog {plugin_id} references unknown publisher key {key_id!r}")
        require(trusted[key_id]["enabled"], f"catalog {plugin_id} references disabled publisher key {key_id}")
        publisher = entry.get("publisher")
        require(isinstance(publisher, str) and publisher,
                f"catalog {plugin_id} publisher is required")
        require(publisher == trusted[key_id]["publisher"],
                f"catalog {plugin_id} publisher metadata does not match publisher key {key_id}")

        if plugin_capabilities is not None:
            capabilities = entry.get("capabilities")
            require(isinstance(capabilities, list) and all(isinstance(value, str) for value in capabilities),
                    f"catalog {plugin_id} capabilities must be a string array")
            require(set(capabilities).issubset(plugin_capabilities[plugin_id]),
                    f"catalog {plugin_id} advertises capabilities absent from plugin.toml")

        url = distribution.get("url")
        allowed_hosts = distribution.get("allowed_hosts")
        require(isinstance(url, str), f"catalog {plugin_id} distribution url is required")
        require(isinstance(allowed_hosts, list) and allowed_hosts and all(
            isinstance(host, str) and host for host in allowed_hosts
        ), f"catalog {plugin_id} allowed_hosts must be a non-empty string array")
        parsed = urlsplit(url)
        require(parsed.scheme == "https" and parsed.hostname in allowed_hosts,
                f"catalog {plugin_id} distribution host must be HTTPS and listed in allowed_hosts")
        require(parsed.path.rsplit("/", 1)[-1] == expected_artifact,
                f"catalog {plugin_id} download URL must name {expected_artifact!r}")

    require(seen == set(plugin_versions), "catalog plugin set does not match plugins/*/plugin.toml")
    if plugin_capabilities is not None:
        require(seen == set(plugin_capabilities), "catalog plugin set does not match source capability metadata")
    return len(entries)


def source_capabilities(manifest: dict) -> set[str]:
    provides = manifest.get("provides", {})
    capabilities = set()
    fields = {
        "credential_strategies": "credential_strategy",
        "auth_flows": "auth_flow",
        "model_sources": "model_source",
        "account_model_sources": "model_source",
        "provider_adapters": "provider_adapter",
        "health_probes": "health_probe",
        "routing_facts": "routing_facts",
        "hooks": "hooks",
    }
    for field, capability in fields.items():
        if provides.get(field):
            capabilities.add(capability)
    if provides.get("thinking_translation"):
        capabilities.add("thinking_translation")
    return capabilities


def load_source_metadata(root: pathlib.Path) -> tuple[dict[str, str], dict[str, set[str]]]:
    versions = {}
    capabilities = {}
    for manifest_path in sorted((root / "plugins").glob("*/plugin.toml")):
        plugin_id, version, _ = validate_plugin_directory(manifest_path.parent)
        require(plugin_id not in versions, f"duplicate plugin id {plugin_id}")
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        versions[plugin_id] = version
        capabilities[plugin_id] = source_capabilities(manifest)
    return versions, capabilities


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    args = parser.parse_args()
    try:
        catalog = json.loads((args.root / "catalog.json").read_text(encoding="utf-8"))
        publishers = json.loads((args.root / "trusted-publishers.json").read_text(encoding="utf-8"))
        versions, capabilities = load_source_metadata(args.root)
        count = validate_catalog_data(catalog, publishers, versions, capabilities)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"validated catalog metadata for {count} plugin(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
