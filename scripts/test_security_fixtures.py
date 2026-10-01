#!/usr/bin/env python3
"""Check security fixture integrity, not host authorization behavior."""

import argparse
import json
import pathlib
import sys
import tomllib
import unittest

from validate_manifests import validate_manifest
from validate_packages import validate_package

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "wit/fixtures/capability-security/v1"
VECTORS = json.loads((FIXTURES / "cases.json").read_text())


class SecurityFixtureTests(unittest.TestCase):
    def test_profiles_use_canonical_permission_vocabulary(self):
        for profile in ("denied", "scoped", "over-permission"):
            with self.subTest(profile=profile):
                path = FIXTURES / profile / "plugin.toml"
                manifest = tomllib.loads(path.read_text())
                self.assertEqual(validate_manifest(path, manifest), "dev.kinetix.security-fixture")
                self.assertEqual(manifest["provides"], {"health_probes": ["fixture"]})
        path = FIXTURES / "unknown-permission/plugin.toml"
        with self.assertRaisesRegex(ValueError, "filesystem"):
            validate_manifest(path, tomllib.loads(path.read_text()))

    def test_vectors_have_unique_ids_and_known_profiles(self):
        self.assertEqual(VECTORS["schema_version"], 1)
        ids = [case["id"] for case in VECTORS["cases"] + VECTORS["ambient_imports"]]
        self.assertEqual(len(ids), len(set(ids)))
        manifests = {
            profile: tomllib.loads((FIXTURES / profile / "plugin.toml").read_text())
            for profile in ("denied", "scoped", "over-permission")
        }
        outcomes = {"allow", "deny", "error", "deny-or-opaque", "deny-or-drop",
                    "allow-or-drop", "deny-or-return-redirect"}
        for case in VECTORS["cases"]:
            with self.subTest(case=case["id"]):
                self.assertIn(case["package"], manifests)
                self.assertIn(case["approval"], VECTORS["approvals"])
                self.assertIn(case["expect"]["outcome"], outcomes)
                self.assertIn(case["operation"]["op"], {
                    "http", "read", "lease", "sign", "put", "get", "delete",
                    "cache-set", "log", "error", "clock",
                })
        # Prevent accidentally replacing the key risk vectors with only load tests.
        cases = {case["id"]: case for case in VECTORS["cases"]}
        for name in ("http-undeclared", "http-unapproved", "plaintext-undeclared",
                     "plaintext-unapproved", "credential-egress", "storage-aggregate"):
            self.assertEqual(cases[name]["expect"]["outcome"], "deny")
        self.assertFalse(cases["sign-no-plaintext"]["expect"]["guest_contains_secret"])
        self.assertFalse(cases["error-redaction"]["expect"]["client_error_contains_secret"])
        self.assertEqual(cases["storage-at-limit"]["operation"]["bytes"], 16)
        self.assertEqual(cases["storage-over-limit"]["operation"]["bytes"], 17)
        self.assertEqual(cases["log-bounds"]["expect"]["max_log_record_bytes"],
                         VECTORS["setup"]["log_record_bytes"])

    def test_ambient_categories_are_present(self):
        self.assertEqual({item["id"] for item in VECTORS["ambient_imports"]}, {
            "filesystem", "host-paths", "process-shell", "environment", "raw-sockets",
            "arbitrary-network", "system-credentials", "randomness",
        })


def check_packages(directory):
    packages = sorted(directory.rglob("*.kxp"))
    if len(packages) != 4 + len(VECTORS["ambient_imports"]):
        raise ValueError("missing generated security packages")
    for package in packages:
        if package.parent.name == "unknown-permission":
            try:
                validate_package(package)
            except ValueError as error:
                if "filesystem" not in str(error):
                    raise
            else:
                raise ValueError("unknown permission was accepted")
        else:
            manifest, _, signed = validate_package(package)
            if signed or manifest["id"] != "dev.kinetix.security-fixture":
                raise ValueError("security fixtures must be unsigned and test-only")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=pathlib.Path)
    args, remaining = parser.parse_known_args()
    if args.packages:
        check_packages(args.packages)
    unittest.main(argv=[sys.argv[0]] + remaining)
