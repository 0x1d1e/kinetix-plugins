#!/usr/bin/env python3
"""Classify every plugin from its manifest and require the conformance
evidence its declared capabilities imply.

    provider_adapters       -> adapter-conformance.json, run by a crate test
    credential_strategies   -> credential-conformance.json, run by a crate test
    host-native wire format -> manifest/host-adapter contract (validate_manifests.py)
    account_model_sources   -> discovery-conformance.json, run by a crate test
    auth_flows              -> crate unit tests (no shared suite yet)
    model_sources (legacy)  -> crate unit tests (no shared suite yet)

"No adapter" is derived from the manifest, never declared. A profile for a
capability the manifest does not declare is an error, as is a profile that no
crate test feeds to its shared runner.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tomllib
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Suite:
    """One shared conformance runner, keyed by a manifest capability."""

    cls: str
    provides: str  # manifest `[provides]` key that requires the suite
    profile: str  # profile file in the plugin directory
    schema_version: int
    names: str  # profile field naming the declared capability id
    runner: str  # call a crate test must make with the profile

    def missing(self, name: str, declared: set[str]) -> str:
        return f"{name}: declares {self.provides} {sorted(declared)} but has no {self.profile}"


SUITES = (
    Suite("adapter", "provider_adapters", "adapter-conformance.json", 2, "adapter", "kinetix_adapter_conformance::check"),
    Suite("credential", "credential_strategies", "credential-conformance.json", 1, "strategy", "kinetix_credential_conformance::check"),
    Suite("discovery", "account_model_sources", "discovery-conformance.json", 1, "source", "kinetix_discovery_conformance::check"),
)
PROFILE = SUITES[0].profile
RUNNER_CALL = SUITES[0].runner


def classify(manifest: dict) -> set[str]:
    provides = manifest.get("provides", {})
    classes = {suite.cls for suite in SUITES if provides.get(suite.provides)}
    if provides.get("auth_flows"):
        classes.add("auth-flow")
    if provides.get("model_sources"):
        classes.add("legacy-model-source")
    for integration in manifest.get("integrations", []):
        wire = integration.get("provider", {}).get("wire_format", "plugin")
        if integration.get("provider") and wire != "plugin":
            classes.add("host-adapter")
    return classes


def crate_sources(plugin_dir: pathlib.Path) -> list[str]:
    """Rust text of the crate's `src/` and integration `tests/`."""
    paths = [path for sub in ("src", "tests") for path in sorted((plugin_dir / sub).rglob("*.rs"))]
    return [path.read_text(encoding="utf-8") for path in paths]


def check_suite(suite: Suite, plugin_dir: pathlib.Path, manifest: dict) -> list[str]:
    name = plugin_dir.name
    declared = set(manifest["provides"][suite.provides])
    profile_path = plugin_dir / suite.profile
    if not profile_path.is_file():
        return [suite.missing(name, declared)]
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        return [f"{name}: {suite.profile} is not valid JSON: {error}"]
    errors = []
    if profile.get("schema_version") != suite.schema_version:
        errors.append(f"{name}: {suite.profile} must use schema_version {suite.schema_version}")
    if {profile.get(suite.names)} != declared:
        errors.append(
            f"{name}: {suite.profile} {suite.names} {profile.get(suite.names)!r} must be the declared {suite.provides} {sorted(declared)}"
        )
    if suite.cls == "adapter" and not profile.get("transports"):
        errors.append(f"{name}: {suite.profile} declares no transports")
    if not any(suite.profile in text and suite.runner in text for text in crate_sources(plugin_dir)):
        errors.append(f"{name}: no crate test feeds {suite.profile} to {suite.runner}")
    return errors


def validate(root: pathlib.Path) -> tuple[list[str], dict[str, set[str]]]:
    errors: list[str] = []
    report: dict[str, set[str]] = {}
    for manifest_path in sorted((root / "plugins").glob("*/plugin.toml")):
        plugin_dir = manifest_path.parent
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        classes = classify(manifest)
        report[plugin_dir.name] = classes
        for suite in SUITES:
            if suite.cls in classes:
                errors += check_suite(suite, plugin_dir, manifest)
            elif (plugin_dir / suite.profile).exists():
                errors.append(f"{plugin_dir.name}: has {suite.profile} but declares no {suite.provides}")
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
