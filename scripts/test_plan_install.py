#!/usr/bin/env python3
"""Contract and CLI tests for deterministic, inspect-only install proposals."""

import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import tomllib
import unittest

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from plan_install import generate_plan, plan_json  # noqa: E402
from test_validate_packages import make_archive  # noqa: E402
from validate_manifests import SCHEMA, validate_manifest  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "wit/fixtures/plugin-install/v1"
PLAN_SCHEMA = json.loads((ROOT / "schemas/install-plan-v1.schema.json").read_text())
REGISTRY = Registry().with_resource(SCHEMA["$id"], Resource.from_contents(SCHEMA))
VALIDATOR = Draft202012Validator(PLAN_SCHEMA, registry=REGISTRY)
CASES = ("opencode-free", "antigravity-oauth", "ai-studio", "b-ai")


def fixture(case):
    return tomllib.loads((FIXTURES / case / "plugin.toml").read_text())


def cli(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts/plan_install.py"), *map(str, args)],
        capture_output=True, text=True, check=False,
    )


class InstallPlanTests(unittest.TestCase):
    def test_reference_vectors_match_byte_for_byte_and_validate(self):
        Draft202012Validator.check_schema(PLAN_SCHEMA)
        for case in CASES:
            with self.subTest(case=case):
                data = fixture(case)
                before = copy.deepcopy(data)
                expected = (FIXTURES / case / "plan.json").read_text()
                for _ in range(3):
                    plan = generate_plan(data)
                    VALIDATOR.validate(plan)
                    self.assertEqual(plan_json(plan), expected)
                    self.assertEqual(data, before)
                result = cli("--manifest", FIXTURES / case / "plugin.toml")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
                self.assertEqual(result.stderr, "")

    def test_none_proposes_no_account_or_credential_and_needs_no_secret(self):
        plan = generate_plan(fixture("opencode-free"))
        self.assertEqual(plan["objects"]["accounts"], [])
        self.assertEqual(plan["objects"]["credentials"], [])
        self.assertNotIn("account", plan["objects"]["routes"][0])
        self.assertFalse(plan["requested_permissions"]["credential_read"])
        self.assertTrue(plan["apply_requires_approval"])
        self.assertFalse(plan["traffic_enabled"])

    def test_acquisition_requests_preserve_declared_modes_and_requirements(self):
        for case in CASES[1:]:
            with self.subTest(case=case):
                plan = generate_plan(fixture(case))
                objects = plan["objects"]
                acquisition = objects["credentials"][0]["acquisition"]
                if case == "antigravity-oauth":
                    self.assertEqual(acquisition, {
                        "mode": "auth_flow", "flow": "antigravity", "strategy": "antigravity-oauth",
                    })
                else:
                    self.assertEqual(acquisition, {
                        "mode": "manual", "kind": "api_key", "requirements": ["api_key"],
                    })
                self.assertEqual(objects["accounts"][0]["credential"], objects["credentials"][0]["ref"])
                self.assertEqual(objects["routes"][0]["account"], objects["accounts"][0]["ref"])

    def test_optional_proposals_are_not_invented_and_permissions_are_not_grants(self):
        for path in sorted((ROOT / "plugins").glob("*/plugin.toml")):
            with self.subTest(path=path):
                data = tomllib.loads(path.read_text())
                plan = generate_plan(data)
                self.assertEqual(len(plan["objects"]["integrations"]), len(data["integrations"]))
                for key in ("accounts", "credentials", "routes"):
                    self.assertEqual(plan["objects"][key], [])
                self.assertEqual(plan["requested_permissions"], {
                    "network_hosts": sorted(data["permissions"]["network_hosts"]),
                    "credential_scopes": sorted(data["permissions"]["credential_scopes"]),
                    "credential_read": data["permissions"]["credential_read"],
                })

    def test_multiple_integrations_have_unique_local_references_and_stable_order(self):
        data = fixture("ai-studio")
        other = copy.deepcopy(data["integrations"][0])
        other["id"] = "another"
        data["integrations"].append(other)
        data["integrations"][0]["install"]["routes"].append({"id": "aaa", "model": "another-model"})
        plan = generate_plan(data)
        VALIDATOR.validate(plan)
        refs = [obj["ref"] for group in plan["objects"].values() for obj in group]
        self.assertEqual(len(refs), len(set(refs)))
        for group in plan["objects"].values():
            self.assertEqual([obj["ref"] for obj in group], sorted(obj["ref"] for obj in group))
        self.assertEqual(plan_json(generate_plan(data)), plan_json(plan))
        # Dictionary insertion order does not affect the digest or serialization.
        self.assertEqual(generate_plan(dict(reversed(list(data.items())))), plan)

    def test_returned_proposals_do_not_alias_input(self):
        data = fixture("ai-studio")
        original = copy.deepcopy(data)
        plan = generate_plan(data)
        plan["objects"]["integrations"][0]["declaration"]["provider"]["base_url"] = "changed"
        plan["requested_permissions"]["network_hosts"].clear()
        self.assertEqual(data, original)

    def test_invalid_and_incomplete_portable_vectors_fail_closed(self):
        for case in json.loads((FIXTURES / "invalid.json").read_text()):
            with self.subTest(case=case["name"]), self.assertRaisesRegex(ValueError, case["error"]):
                generate_plan(case["manifest"])

    def test_legacy_manifest_is_valid_but_cannot_silently_infer_install_mode(self):
        data = fixture("opencode-free")
        data["integrations"][0].pop("credential_mode")
        data["integrations"][0].pop("install")
        validate_manifest(pathlib.Path("legacy/plugin.toml"), data)
        with self.assertRaisesRegex(ValueError, "explicit credential_mode"):
            generate_plan(data)

    def test_contradictions_and_host_policy_or_secret_fields_are_rejected(self):
        changes = (
            {"credential_mode": "manual", "auth_flow": "missing"},
            {"credential_mode": "none", "credential_strategy": "missing"},
            {"manual_credential": {"kind": "api_key", "requirements": ["api_key", "api_key"]}},
            {"install": {"account": {"name": "  "}}},
            {"install": {"routes": [{"id": "test", "model": " "}]}},
            {"install": {"enabled": True}},
            {"install": {"account": {"name": "Test", "secret": "not-a-secret"}}},
            {"install": {"routes": [{"id": "test", "model": "test", "priority": 1}]}},
        )
        for change in changes:
            data = fixture("ai-studio")
            data["integrations"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                generate_plan(data)
        data = fixture("ai-studio")
        data["integrations"][0].pop("provider")
        with self.assertRaisesRegex(ValueError, "requires a provider template"):
            generate_plan(data)

    def test_modes_reject_contradictory_or_missing_provided_auth_bindings(self):
        for mode in ("manual", "none"):
            data = fixture("antigravity-oauth")
            data["integrations"][0]["credential_mode"] = mode
            if mode == "manual":
                data["integrations"][0]["manual_credential"] = {"kind": "api_key", "requirements": ["api_key"]}
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, f"{mode} credential mode cannot declare"):
                generate_plan(data)
        for binding in ("auth_flow", "credential_strategy"):
            data = fixture("antigravity-oauth")
            data["integrations"][0].pop(binding)
            with self.subTest(binding=binding), self.assertRaisesRegex(ValueError, "requires auth_flow and credential_strategy"):
                generate_plan(data)

    def test_plan_schema_forbids_secrets_and_implicit_approval_or_activation(self):
        for field, value in (("apply_requires_approval", False), ("traffic_enabled", True)):
            plan = generate_plan(fixture("ai-studio"))
            plan[field] = value
            self.assertFalse(VALIDATOR.is_valid(plan))
        plan = generate_plan(fixture("ai-studio"))
        plan["objects"]["credentials"][0]["value"] = "not-a-secret"
        self.assertFalse(VALIDATOR.is_valid(plan))

    def test_package_cli_is_repeatable_digest_bound_and_read_only(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = pathlib.Path(temp)
            for case in CASES:
                with self.subTest(case=case):
                    data = fixture(case)
                    package = directory / f"{data['id']}-{data['version']}.kxp"
                    make_archive(package, manifest=(FIXTURES / case / "plugin.toml").read_bytes())
                    contents = package.read_bytes()
                    first = cli("--package", package)
                    second = cli("--package", package)
                    self.assertEqual(first.returncode, 0, first.stderr)
                    self.assertEqual(first.stdout, second.stdout)
                    plan = json.loads(first.stdout)
                    VALIDATOR.validate(plan)
                    self.assertEqual(plan["package"].pop("sha256"), hashlib.sha256(contents).hexdigest())
                    self.assertEqual(plan, generate_plan(data))
                    self.assertEqual(package.read_bytes(), contents)
            self.assertEqual(len(list(directory.iterdir())), len(CASES))

    def test_cli_invalid_input_emits_no_partial_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = pathlib.Path(temp) / "plugin.toml"
            for content in ("not TOML", "manifest_version = 999"):
                manifest.write_text(content)
                result = cli("--manifest", manifest)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertTrue(result.stderr)
            result = cli("--package", pathlib.Path(temp) / "missing.kxp")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            result = cli("--manifest", manifest, "--package", manifest)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
