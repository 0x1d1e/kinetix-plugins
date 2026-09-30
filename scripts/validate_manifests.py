#!/usr/bin/env python3
"""Validate plugin.toml against the canonical v1 manifest schema."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tomllib

from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas/plugin-manifest-v1.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)


def require(condition: bool, path: pathlib.Path, message: str) -> None:
    if not condition:
        raise ValueError(f"{path}: {message}")


def validate_manifest(path: pathlib.Path, data: object) -> str:
    errors = sorted(VALIDATOR.iter_errors(data), key=lambda error: list(map(str, error.absolute_path)))
    if errors:
        error = errors[0]
        location = ".".join(map(str, error.absolute_path)) or "manifest"
        raise ValueError(f"{path}: {location}: {error.message}")

    assert isinstance(data, dict)
    plugin_id = data["id"]
    require(
        re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]|[a-z0-9]", plugin_id) is not None,
        path,
        "id must contain lowercase letters, digits, '.', '-', or '_'",
    )
    require(".." not in plugin_id and not plugin_id.startswith(".") and not plugin_id.endswith("."),
            path, "id has invalid dot placement")

    provides = data.get("provides", {})
    integrations = data.get("integrations", [])
    integration_ids: set[str] = set()
    capability_keys = {
        "provider_adapter": "provider_adapters",
        "credential_strategy": "credential_strategies",
        "auth_flow": "auth_flows",
        "model_source": None,
    }
    for integration in integrations:
        integration_id = integration["id"]
        require(integration_id not in integration_ids, path, f"duplicate integration id {integration_id}")
        integration_ids.add(integration_id)

        features = integration.get("features")
        protocols = integration.get("protocols")
        require(
            (features is None) == (protocols is None),
            path,
            "integrations.features and integrations.protocols must be declared together",
        )
        if features is not None:
            require(
                not features["parallel_tools"] or features["tools"],
                path,
                "parallel_tools requires tools",
            )
            require(
                features["model_discovery"] == bool(integration.get("model_source")),
                path,
                f"integration {integration_id}: model_discovery must match model_source",
            )

        for field, provided_key in capability_keys.items():
            name = integration.get(field)
            if not name:
                continue
            if field == "model_source":
                names = provides.get("model_sources", []) + provides.get("account_model_sources", [])
                require(name in names, path, f"integration {integration_id} references unprovided model_source {name}")
            elif provided_key:
                require(
                    name in provides.get(provided_key, []),
                    path,
                    f"integration {integration_id} references unprovided {field} {name}",
                )

        mode = integration.get("credential_mode")
        if mode == "auth_flow":
            require(
                bool(integration.get("auth_flow")) and bool(integration.get("credential_strategy")),
                path,
                f"integration {integration_id}: auth_flow credential mode requires auth_flow and credential_strategy",
            )
        elif mode == "none":
            require(
                not integration.get("auth_flow") and not integration.get("credential_strategy"),
                path,
                f"integration {integration_id}: none credential mode cannot declare auth_flow or credential_strategy",
            )
        elif mode == "manual":
            require(
                not integration.get("auth_flow"),
                path,
                f"integration {integration_id}: manual credential mode cannot declare auth_flow",
            )

    return plugin_id


def validate_plugin_directory(plugin_dir: pathlib.Path) -> tuple[str, str, str]:
    manifest_path = plugin_dir / "plugin.toml"
    cargo_path = plugin_dir / "Cargo.toml"
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        cargo = tomllib.loads(cargo_path.read_text(encoding="utf-8"))
        plugin_id = validate_manifest(manifest_path, manifest)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        raise ValueError(f"{plugin_dir}: {error}") from error

    package = cargo.get("package")
    require(isinstance(package, dict), cargo_path, "[package] table is required")
    crate_version = package.get("version")
    require(isinstance(crate_version, str), cargo_path, "[package].version must be a string")
    manifest_version = manifest["version"]
    require(
        crate_version == manifest_version,
        manifest_path,
        f"plugin.toml version ({manifest_version}) does not match Cargo.toml version ({crate_version})",
    )
    return plugin_id, manifest_version, package.get("name", "")


def validate_directory(root: pathlib.Path) -> int:
    manifests = sorted((root / "plugins").glob("*/plugin.toml"))
    if not manifests:
        raise ValueError(f"{root}: no plugin manifests found")
    ids = set()
    for manifest_path in manifests:
        plugin_id, _, _ = validate_plugin_directory(manifest_path.parent)
        require(plugin_id not in ids, manifest_path, f"duplicate plugin id {plugin_id}")
        ids.add(plugin_id)
    return len(manifests)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT, help="repository root")
    parser.add_argument("--plugin-dir", type=pathlib.Path, help="validate one plugin directory")
    parser.add_argument("--print-fields", action="store_true", help="print id, version, and crate name as TSV")
    args = parser.parse_args()

    try:
        if args.plugin_dir:
            plugin_id, version, crate_name = validate_plugin_directory(args.plugin_dir)
            if args.print_fields:
                print(f"{plugin_id}\t{version}\t{crate_name}")
            else:
                print(f"validated {plugin_id} {version}")
        else:
            count = validate_directory(args.root)
            print(f"validated {count} plugin manifest(s)")
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
