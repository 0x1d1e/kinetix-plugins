#!/usr/bin/env python3
"""Tests for manifest-derived conformance classification."""

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from validate_conformance import PROFILE, RUNNER_CALL, classify, validate  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

ADAPTER_MANIFEST = '[provides]\nprovider_adapters = ["demo"]\n'
GOOD_PROFILE = {"schema_version": 2, "adapter": "demo", "transports": [{"format": "x"}]}
GOOD_SOURCE = f'include_str!("adapter-conformance.json"); {RUNNER_CALL}(&a, p);'


def plugin(root, name, manifest, profile=None, source=None):
    directory = pathlib.Path(root) / "plugins" / name
    (directory / "src").mkdir(parents=True)
    (directory / "plugin.toml").write_text(manifest)
    if profile is not None:
        (directory / PROFILE).write_text(json.dumps(profile))
    if source is not None:
        (directory / "src/lib.rs").write_text(source)


class ClassificationTests(unittest.TestCase):
    def errors(self, manifest, profile=None, source=None):
        with tempfile.TemporaryDirectory() as root:
            plugin(root, "demo", manifest, profile, source)
            return validate(pathlib.Path(root))[0]

    def test_shipped_plugins_pass(self):
        errors, report = validate(ROOT)
        self.assertEqual(errors, [])
        self.assertIn("adapter", report["antigravity-oauth"])
        self.assertIn("adapter", report["opencode-free"])
        for name in ("ai-studio", "b-ai", "claude-code-oauth"):
            self.assertNotIn("adapter", report[name])

    def test_adapter_without_profile_fails(self):
        self.assertTrue(any("no adapter-conformance.json" in e for e in self.errors(ADAPTER_MANIFEST)))

    def test_adapter_with_profile_and_runner_call_passes(self):
        self.assertEqual(self.errors(ADAPTER_MANIFEST, GOOD_PROFILE, GOOD_SOURCE), [])

    def test_profile_without_runner_call_fails(self):
        errors = self.errors(ADAPTER_MANIFEST, GOOD_PROFILE, "fn unrelated() {}")
        self.assertTrue(any(RUNNER_CALL in e for e in errors))

    def test_profile_must_name_the_declared_adapter(self):
        errors = self.errors(ADAPTER_MANIFEST, {**GOOD_PROFILE, "adapter": "other"}, GOOD_SOURCE)
        self.assertTrue(any("must be the declared" in e for e in errors))

    def test_stale_profile_schema_version_fails(self):
        errors = self.errors(ADAPTER_MANIFEST, {**GOOD_PROFILE, "schema_version": 1}, GOOD_SOURCE)
        self.assertTrue(any("schema_version" in e for e in errors))

    def test_profile_without_adapter_fails(self):
        manifest = '[provides]\ncredential_strategies = ["x"]\n'
        errors = self.errors(manifest, GOOD_PROFILE, GOOD_SOURCE)
        self.assertTrue(any("declares no provider_adapters" in e for e in errors))

    def test_classes_come_from_the_manifest(self):
        self.assertEqual(classify({"provides": {"auth_flows": ["a"], "account_model_sources": ["m"]}}), {"auth", "discovery"})
        host = {"integrations": [{"provider": {"wire_format": "gemini"}}]}
        self.assertEqual(classify(host), {"host-adapter"})
        self.assertEqual(classify({"integrations": [{"provider": {}}]}), set())


if __name__ == "__main__":
    unittest.main()
