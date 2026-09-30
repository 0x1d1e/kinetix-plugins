#!/usr/bin/env python3
"""Focused tests for plugin manifest feature and protocol validation."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from validate_manifests import validate_manifest  # noqa: E402


FEATURES = {
    "schema_version": 1,
    "streaming": True,
    "tools": True,
    "parallel_tools": True,
    "vision": False,
    "reasoning": True,
    "structured_output": False,
    "model_discovery": True,
    "quota_probe": False,
    "health_probe": False,
}
PROTOCOLS = {"input": ["openai-chat"], "upstream": ["plugin-native"]}


def manifest(features=None, protocols=None):
    integration = {"id": "test", "model_source": "test-models"}
    if features is not None:
        integration["features"] = features
        integration["protocols"] = protocols
    return {
        "manifest_version": 1,
        "id": "dev.kinetix.test",
        "name": "Test",
        "version": "0.1.0",
        "plugin_api": "1",
        "integrations": [integration],
    }


class ManifestValidationTests(unittest.TestCase):
    path = pathlib.Path("test/plugin.toml")

    def test_unextended_manifest_remains_compatible(self):
        self.assertEqual(validate_manifest(self.path, manifest()), "dev.kinetix.test")

    def test_versioned_features_and_protocols_are_valid(self):
        self.assertEqual(
            validate_manifest(self.path, manifest(FEATURES, PROTOCOLS)), "dev.kinetix.test"
        )

    def test_rejects_unknown_or_missing_features(self):
        for changed in (
            FEATURES | {"experimental": True},
            {key: value for key, value in FEATURES.items() if key != "vision"},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_manifest(self.path, manifest(changed, PROTOCOLS))

    def test_rejects_invalid_feature_values_and_version(self):
        for key, value in (("tools", "yes"), ("schema_version", 2)):
            changed = FEATURES | {key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_manifest(self.path, manifest(changed, PROTOCOLS))

    def test_rejects_protocol_typos_and_duplicates(self):
        for protocols in (
            {"input": ["openai-chat", "openai-chat"], "upstream": ["plugin-native"]},
            {"input": ["openai-magic"], "upstream": ["plugin-native"]},
            {"input": ["openai-chat"], "upstream": ["plugin-native"], "other": []},
        ):
            with self.subTest(protocols=protocols), self.assertRaises(ValueError):
                validate_manifest(self.path, manifest(FEATURES, protocols))

    def test_parallel_tools_requires_tools_and_discovery_requires_source(self):
        no_tools = FEATURES | {"tools": False}
        with self.assertRaises(ValueError):
            validate_manifest(self.path, manifest(no_tools, PROTOCOLS))

        no_source = manifest(FEATURES, PROTOCOLS)
        del no_source["integrations"][0]["model_source"]
        with self.assertRaises(ValueError):
            validate_manifest(self.path, no_source)

    def test_feature_and_protocol_blocks_must_be_paired(self):
        with self.assertRaises(ValueError):
            validate_manifest(self.path, manifest(FEATURES))


if __name__ == "__main__":
    unittest.main()
