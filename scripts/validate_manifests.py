#!/usr/bin/env python3
"""Validate plugin manifests and the versioned integration feature contract."""

from __future__ import annotations

import pathlib
import sys
import tomllib

REQUIRED = {"manifest_version", "id", "name", "version", "plugin_api"}
FEATURES = {
    "streaming",
    "tools",
    "parallel_tools",
    "vision",
    "reasoning",
    "structured_output",
    "model_discovery",
    "quota_probe",
    "health_probe",
}
PROTOCOLS = {"openai-chat", "openai-responses", "anthropic", "gemini", "plugin-native"}


def require(condition: bool, path: pathlib.Path, message: str) -> None:
    if not condition:
        raise ValueError(f"{path}: {message}")


def validate_integration(path: pathlib.Path, integration: object) -> None:
    require(isinstance(integration, dict), path, "integrations entries must be tables")
    assert isinstance(integration, dict)
    features = integration.get("features")
    protocols = integration.get("protocols")
    require(
        (features is None) == (protocols is None),
        path,
        "integrations.features and integrations.protocols must be declared together",
    )
    if features is None:
        return

    require(isinstance(features, dict), path, "integrations.features must be a table")
    assert isinstance(features, dict)
    require(
        features.get("schema_version") == 1 and type(features.get("schema_version")) is int,
        path,
        "integrations.features.schema_version must be 1",
    )
    unknown_features = features.keys() - FEATURES - {"schema_version"}
    missing_features = FEATURES - features.keys()
    require(not unknown_features, path, f"unknown integration features: {sorted(unknown_features)}")
    require(not missing_features, path, f"missing integration features: {sorted(missing_features)}")
    for name in FEATURES:
        require(type(features[name]) is bool, path, f"integrations.features.{name} must be a boolean")
    require(
        not features["parallel_tools"] or features["tools"],
        path,
        "parallel_tools requires tools",
    )
    has_model_source = bool(integration.get("model_source"))
    require(
        features["model_discovery"] == has_model_source,
        path,
        "model_discovery must match whether model_source is declared",
    )

    require(isinstance(protocols, dict), path, "integrations.protocols must be a table")
    assert isinstance(protocols, dict)
    require(
        protocols.keys() == {"input", "upstream"},
        path,
        "integrations.protocols must contain only input and upstream",
    )
    for name in ("input", "upstream"):
        values = protocols[name]
        require(isinstance(values, list), path, f"integrations.protocols.{name} must be an array")
        require(
            all(isinstance(value, str) and value in PROTOCOLS for value in values),
            path,
            f"integrations.protocols.{name} contains an unknown protocol",
        )
        require(
            len(values) == len(set(values)),
            path,
            f"integrations.protocols.{name} must not contain duplicates",
        )


def validate_manifest(path: pathlib.Path, data: object) -> str:
    require(isinstance(data, dict), path, "manifest root must be a table")
    assert isinstance(data, dict)
    missing = REQUIRED - data.keys()
    require(not missing, path, f"missing required keys: {sorted(missing)}")
    require(data["manifest_version"] == 1, path, "manifest_version must be 1")
    integrations = data.get("integrations", [])
    require(isinstance(integrations, list), path, "integrations must be an array of tables")
    for integration in integrations:
        validate_integration(path, integration)
    return data["id"]


def validate_directory(root: pathlib.Path) -> int:
    manifests = sorted((root / "plugins").glob("*/plugin.toml"))
    if not manifests:
        raise ValueError(f"{root}: no plugin manifests found")
    ids = set()
    for path in manifests:
        try:
            data = tomllib.loads(path.read_text())
            plugin_id = validate_manifest(path, data)
        except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
            raise ValueError(f"{path}: {error}") from error
        require(plugin_id not in ids, path, f"duplicate plugin id {plugin_id}")
        ids.add(plugin_id)
    return len(manifests)


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    try:
        count = validate_directory(root)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    print(f"validated {count} plugin manifest(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
