#!/usr/bin/env python3
"""Tests for catalog-to-manifest identity and publisher consistency."""

import base64
import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from validate_catalog import validate_catalog_data  # noqa: E402


PUBLISHERS = {
    "schema_version": 1,
    "publishers": [{
        "id": "fixture-key",
        "publisher": "Fixture",
        "algorithm": "ed25519",
        "public_key_base64": base64.b64encode(bytes(range(32))).decode(),
        "enabled": True,
    }],
}
CATALOG = {
    "schema_version": 1,
    "plugins": [{
        "id": "dev.kinetix.fixture",
        "name": "Display name is catalog metadata",
        "description": "Fixture",
        "publisher": "Fixture",
        "official": False,
        "homepage": "https://example.com",
        "latest_version": "1.0.0",
        "artifact_name": "dev.kinetix.fixture-1.0.0.kxp",
        "capabilities": ["model_source"],
        "installable": True,
        "distribution": {
            "url": "https://github.com/example/plugin/releases/download/v1/dev.kinetix.fixture-1.0.0.kxp",
            "sha256": "a" * 64,
            "publisher_key_id": "fixture-key",
            "allowed_hosts": ["github.com"],
        },
    }],
}
SOURCE_VERSIONS = {"dev.kinetix.fixture": "1.0.0"}
SOURCE_CAPABILITIES = {"dev.kinetix.fixture": {"model_source"}}


class CatalogValidationTests(unittest.TestCase):
    def test_accepts_catalog_metadata_matching_manifest_identity(self):
        self.assertEqual(
            validate_catalog_data(CATALOG, PUBLISHERS, SOURCE_VERSIONS, SOURCE_CAPABILITIES), 1
        )

    def test_rejects_identity_and_version_mismatches(self):
        changed = copy.deepcopy(CATALOG)
        changed["plugins"][0]["id"] = "dev.kinetix.other"
        with self.assertRaisesRegex(ValueError, "no source package"):
            validate_catalog_data(changed, PUBLISHERS, SOURCE_VERSIONS, SOURCE_CAPABILITIES)

        changed = copy.deepcopy(CATALOG)
        changed["plugins"][0]["latest_version"] = "2.0.0"
        with self.assertRaisesRegex(ValueError, "does not match plugin.toml"):
            validate_catalog_data(changed, PUBLISHERS, SOURCE_VERSIONS, SOURCE_CAPABILITIES)

    def test_rejects_untrusted_publisher_or_distribution_mismatch(self):
        changed = copy.deepcopy(CATALOG)
        changed["plugins"][0]["distribution"]["publisher_key_id"] = "unknown-key"
        with self.assertRaisesRegex(ValueError, "unknown publisher key"):
            validate_catalog_data(changed, PUBLISHERS, SOURCE_VERSIONS, SOURCE_CAPABILITIES)

        changed = copy.deepcopy(CATALOG)
        changed["plugins"][0]["distribution"]["allowed_hosts"] = ["example.com"]
        with self.assertRaisesRegex(ValueError, "allowed_hosts"):
            validate_catalog_data(changed, PUBLISHERS, SOURCE_VERSIONS, SOURCE_CAPABILITIES)

        changed = copy.deepcopy(CATALOG)
        changed["plugins"][0]["artifact_name"] = "different.kxp"
        with self.assertRaisesRegex(ValueError, "artifact_name"):
            validate_catalog_data(changed, PUBLISHERS, SOURCE_VERSIONS, SOURCE_CAPABILITIES)

        changed = copy.deepcopy(CATALOG)
        changed["plugins"][0]["distribution"]["sha256"] = "short"
        with self.assertRaisesRegex(ValueError, "sha256"):
            validate_catalog_data(changed, PUBLISHERS, SOURCE_VERSIONS, SOURCE_CAPABILITIES)

    def test_requires_explicit_publisher_identity(self):
        publishers = copy.deepcopy(PUBLISHERS)
        del publishers["publishers"][0]["publisher"]
        with self.assertRaisesRegex(ValueError, "publisher.*required"):
            validate_catalog_data(CATALOG, publishers, SOURCE_VERSIONS, SOURCE_CAPABILITIES)

        catalog = copy.deepcopy(CATALOG)
        del catalog["plugins"][0]["publisher"]
        with self.assertRaisesRegex(ValueError, "publisher is required"):
            validate_catalog_data(catalog, PUBLISHERS, SOURCE_VERSIONS, SOURCE_CAPABILITIES)

        publishers = copy.deepcopy(PUBLISHERS)
        publishers["publishers"][0]["extra"] = True
        with self.assertRaisesRegex(ValueError, "Additional properties are not allowed"):
            validate_catalog_data(CATALOG, publishers, SOURCE_VERSIONS, SOURCE_CAPABILITIES)

    def test_rejects_catalog_capability_mismatch(self):
        changed = copy.deepcopy(CATALOG)
        changed["plugins"][0]["capabilities"] = ["provider_adapter"]
        with self.assertRaisesRegex(ValueError, "advertises capabilities absent"):
            validate_catalog_data(changed, PUBLISHERS, SOURCE_VERSIONS, SOURCE_CAPABILITIES)

    def test_catalog_display_name_does_not_override_package_identity(self):
        changed = copy.deepcopy(CATALOG)
        changed["plugins"][0]["name"] = "Renamed in marketplace"
        self.assertEqual(
            validate_catalog_data(changed, PUBLISHERS, SOURCE_VERSIONS, SOURCE_CAPABILITIES), 1
        )


if __name__ == "__main__":
    unittest.main()
