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
    integration = {
        "id": "test",
        "name": "Test integration",
        "description": "Fixture integration",
        "model_source": "test-models",
    }
    if features is not None:
        integration["features"] = features
        integration["protocols"] = protocols
    return {
        "manifest_version": 1,
        "id": "dev.kinetix.test",
        "name": "Test",
        "version": "0.1.0",
        "plugin_api": "1",
        "provides": {"model_sources": ["test-models"]},
        "integrations": [integration],
        "permissions": {"network_hosts": [], "credential_scopes": [], "credential_read": False},
        "limits": {
            "memory": "32MiB",
            "wall_time_ms": 1000,
            "max_outbound_requests": 0,
            "max_http_body": "1KiB",
            "storage": "1KiB",
        },
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

    def test_schema_rejects_unknown_fields_and_missing_permissions(self):
        changed = manifest()
        changed["extra"] = True
        with self.assertRaises(ValueError):
            validate_manifest(self.path, changed)

        changed = manifest()
        del changed["permissions"]
        with self.assertRaises(ValueError):
            validate_manifest(self.path, changed)

    def test_rejects_invalid_semver_and_accepts_valid_prerelease(self):
        for version in (
            "1.0.0-01",
            "01.0.0",
            "1.0.0-",
            "1.0.0+build..2",
            "18446744073709551616.0.0",
        ):
            changed = manifest()
            changed["version"] = version
            with self.subTest(version=version), self.assertRaises(ValueError):
                validate_manifest(self.path, changed)

        changed = manifest()
        changed["version"] = "1.0.0-rc.1+build.7"
        self.assertEqual(validate_manifest(self.path, changed), "dev.kinetix.test")

    def test_plugin_id_matches_host_character_and_dot_rules(self):
        for plugin_id in ("-plugin", "_plugin", "plugin-", "plugin_"):
            changed = manifest()
            changed["id"] = plugin_id
            with self.subTest(plugin_id=plugin_id):
                self.assertEqual(validate_manifest(self.path, changed), plugin_id)

        for plugin_id in (".plugin", "plugin.", "a..b"):
            changed = manifest()
            changed["id"] = plugin_id
            with self.subTest(plugin_id=plugin_id), self.assertRaises(ValueError):
                validate_manifest(self.path, changed)

    def test_pricing_scope_matches_host_enum(self):
        for pricing_scope in ("integration", "direct_api"):
            changed = manifest()
            changed["integrations"][0]["provider"] = {
                "base_url": "https://provider.invalid",
                "wire_format": "openai",
                "auth_scheme": "bearer",
                "timeout_ms": 1000,
                "capability_mode": "permissive",
                "follow_redirects": False,
                "pricing_scope": pricing_scope,
            }
            self.assertEqual(validate_manifest(self.path, changed), "dev.kinetix.test")

        changed = manifest()
        changed["integrations"][0]["provider"] = {
            "base_url": "https://provider.invalid",
            "wire_format": "openai",
            "auth_scheme": "bearer",
            "timeout_ms": 1000,
            "capability_mode": "permissive",
            "follow_redirects": False,
            "pricing_scope": "whatever",
        }
        with self.assertRaises(ValueError):
            validate_manifest(self.path, changed)

    def test_source_requires_a_capability_and_adapter_for_thinking_translation(self):
        changed = manifest()
        changed["provides"] = {}
        with self.assertRaises(ValueError):
            validate_manifest(self.path, changed)

        changed = manifest()
        changed["provides"]["thinking_translation"] = True
        with self.assertRaises(ValueError):
            validate_manifest(self.path, changed)

    def test_resource_limits_use_host_byte_size_semantics(self):
        for field in ("memory", "max_http_body", "storage"):
            for value in ("banana", "?", "18446744073709551615 KiB"):
                changed = manifest()
                changed["limits"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_manifest(self.path, changed)

        for value in ("1", "+1", "1 MiB", "+1 MiB", " 2 GB ", "18446744073709551615 B"):
            changed = manifest()
            changed["limits"]["memory"] = value
            self.assertEqual(validate_manifest(self.path, changed), "dev.kinetix.test")

    def test_credential_scopes_and_cached_routing_cadence_match_host(self):
        changed = manifest()
        changed["permissions"]["credential_scopes"] = ["provider:provider-id"]
        self.assertEqual(validate_manifest(self.path, changed), "dev.kinetix.test")

        changed = manifest()
        changed["provides"]["credential_strategies"] = ["test-credentials"]
        changed["permissions"]["credential_scopes"] = ["credential_strategy:test-credentials"]
        self.assertEqual(validate_manifest(self.path, changed), "dev.kinetix.test")

        for scope in ("provider:", "credential_strategy:missing", "credential"):
            changed = manifest()
            changed["permissions"]["credential_scopes"] = [scope]
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                validate_manifest(self.path, changed)

        for refresh in (4_999, 3_600_001):
            changed = manifest()
            changed["provides"]["routing_facts"] = ["test-facts"]
            changed["routing_facts_mode"] = "cached"
            changed["routing_facts_refresh_ms"] = refresh
            with self.subTest(refresh=refresh), self.assertRaises(ValueError):
                validate_manifest(self.path, changed)

    def test_integration_bindings_must_match_provided_capabilities(self):
        changed = manifest()
        changed["integrations"][0]["model_source"] = "missing-models"
        with self.assertRaises(ValueError):
            validate_manifest(self.path, changed)

        changed = manifest()
        changed["provides"]["account_model_sources"] = ["test-models"]
        with self.assertRaises(ValueError):
            validate_manifest(self.path, changed)

        changed = manifest()
        changed["integrations"][0].pop("model_source")
        with self.assertRaises(ValueError):
            validate_manifest(self.path, changed)

    def test_provider_source_constraints_match_host(self):
        base_provider = {
            "base_url": "https://provider.invalid",
            "wire_format": "openai",
            "auth_scheme": "bearer",
            "timeout_ms": 1000,
            "capability_mode": "permissive",
            "follow_redirects": False,
            "pricing_scope": "integration",
        }
        changed = manifest()
        changed["integrations"][0]["provider"] = base_provider | {"base_url": "HTTPS://provider.invalid"}
        self.assertEqual(validate_manifest(self.path, changed), "dev.kinetix.test")

        invalid_providers = (
            base_provider | {"base_url": "http://provider.invalid"},
            base_provider | {"base_url": "https://user:secret@provider.invalid"},
            base_provider | {"models_path": "https://provider.invalid/models"},
            base_provider | {"credential_hosts": ["provider.invalid:443"]},
            base_provider | {"extra_headers": {"X-Test": "bad\r\nvalue"}},
            base_provider | {"auth_scheme": "custom_header", "custom_header_name": "  "},
        )
        for provider in invalid_providers:
            changed = manifest()
            changed["integrations"][0]["provider"] = provider
            with self.subTest(provider=provider), self.assertRaises(ValueError):
                validate_manifest(self.path, changed)

        changed = manifest(FEATURES, {"input": ["openai-chat"], "upstream": ["openai-chat"]})
        changed["integrations"][0]["provider"] = base_provider | {"wire_format": "anthropic"}
        with self.assertRaises(ValueError):
            validate_manifest(self.path, changed)

    def test_host_compatibility_remains_host_owned(self):
        changed = manifest()
        changed["plugin_api"] = "99"
        self.assertEqual(validate_manifest(self.path, changed), "dev.kinetix.test")


if __name__ == "__main__":
    unittest.main()
