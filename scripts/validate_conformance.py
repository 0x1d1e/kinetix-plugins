#!/usr/bin/env python3
"""Classify every plugin from its manifest and require the conformance
evidence its declared capabilities imply.

    provider adapter        -> adapter-conformance.json, run by a crate test
    host-native wire format -> manifest/host-adapter contract (validate_manifests.py)
    credential/auth         -> crate unit tests (no shared suite yet)
    model discovery         -> crate unit tests (no shared suite yet)

"No adapter" is derived from the manifest, never declared.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROFILE = "adapter-conformance.json"
PROFILE_SCHEMA_VERSION = 2
RUNNER_CALL = "kinetix_adapter_conformance::check"


def classify(manifest: dict) -> set[str]:
    provides = manifest.get("provides", {})
    classes = set()
    if provides.get("provider_adapters"):
        classes.add("adapter")
    if provides.get("credential_strategies") or provides.get("auth_flows"):
        classes.add("auth")
    if provides.get("model_sources") or provides.get("account_model_sources"):
        classes.add("discovery")
    for integration in manifest.get("integrations", []):
        wire = integration.get("provider", {}).get("wire_format", "plugin")
        if integration.get("provider") and wire != "plugin":
            classes.add("host-adapter")
    return classes


def check_adapter(plugin_dir: pathlib.Path, manifest: dict) -> list[str]:
    name = plugin_dir.name
    declared = set(manifest["provides"]["provider_adapters"])
    profile_path = plugin_dir / PROFILE
    if not profile_path.is_file():
        return [f"{name}: declares provider_adapters {sorted(declared)} but has no {PROFILE}"]
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        return [f"{name}: {PROFILE} is not valid JSON: {error}"]
    errors = []
    if profile.get("schema_version") != PROFILE_SCHEMA_VERSION:
        errors.append(f"{name}: {PROFILE} must use schema_version {PROFILE_SCHEMA_VERSION}")
    if {profile.get("adapter")} != declared:
        errors.append(f"{name}: {PROFILE} adapter {profile.get('adapter')!r} must be the declared provider_adapters {sorted(declared)}")
    if not profile.get("transports"):
        errors.append(f"{name}: {PROFILE} declares no transports")
    sources = [path.read_text(encoding="utf-8") for path in sorted((plugin_dir / "src").rglob("*.rs"))]
    if not any(PROFILE in text and RUNNER_CALL in text for text in sources):
        errors.append(f"{name}: no crate test feeds {PROFILE} to {RUNNER_CALL}")
    return errors


def validate(root: pathlib.Path) -> tuple[list[str], dict[str, set[str]]]:
    errors: list[str] = []
    report: dict[str, set[str]] = {}
    for manifest_path in sorted((root / "plugins").glob("*/plugin.toml")):
        plugin_dir = manifest_path.parent
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        classes = classify(manifest)
        report[plugin_dir.name] = classes
        if "adapter" in classes:
            errors += check_adapter(plugin_dir, manifest)
        elif (plugin_dir / PROFILE).exists():
            errors.append(f"{plugin_dir.name}: has {PROFILE} but declares no provider_adapters")
        if not classes:
            errors.append(f"{plugin_dir.name}: manifest declares nothing to classify")
    return errors, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    args = parser.parse_args()
    errors, report = validate(args.root)
    for name, classes in report.items():
        print(f"{name}: {', '.join(sorted(classes)) or '-'}")
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
