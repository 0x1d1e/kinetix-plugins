#!/usr/bin/env python3
"""Tests for the portable .kxp container contract and v1 fixtures."""

import base64
import hashlib
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from validate_packages import (  # noqa: E402
    normalized_repository_url,
    validate_package,
    validate_provenance,
)


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "wit/fixtures/kxp/v1"
MANIFEST = b'''manifest_version = 1
id = "dev.kinetix.fixture"
name = "Fixture"
version = "1.0.0"
plugin_api = "1"

[provides]
model_sources = ["fixture-models"]

[permissions]
network_hosts = []
credential_scopes = []
credential_read = false

[limits]
memory = "32MiB"
wall_time_ms = 1000
max_outbound_requests = 0
max_http_body = "1KiB"
storage = "1KiB"
'''
WASM = b"\x00asm\x01\x00\x00\x00"
PROVENANCE = json.dumps({"schema_version": 1}).encode()


def add_member(archive, name, content, entry_type=tarfile.REGTYPE):
    info = tarfile.TarInfo(name)
    info.type = entry_type
    info.size = len(content)
    info.mode = 0o644
    archive.addfile(info, io.BytesIO(content))


def make_archive(path, manifest=MANIFEST, wasm=WASM, signature=None, provenance=PROVENANCE, extra=None):
    members = {"plugin.toml": manifest, "plugin.wasm": wasm}
    if signature is not None:
        members["signature.ed25519"] = signature
    if provenance is not None:
        members["provenance.json"] = provenance
    members.update(extra or {})
    with tarfile.open(path, "w:") as archive:
        for name, content in members.items():
            add_member(archive, name, content)


def package_from_fixture(case, output_dir):
    fixture = FIXTURES / case
    manifest_bytes = (fixture / "plugin.toml").read_bytes()
    if case == "malformed":
        filename = "dev.kinetix.b-ai-0.1.1.kxp"
    else:
        manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
        if case == "mismatched":
            filename = "dev.kinetix.other-0.1.1.kxp"
        else:
            filename = f"{manifest['id']}-{manifest['version']}.kxp"

    provenance_path = fixture / "provenance.json"
    signature_path = fixture / "signature.ed25519"
    make_archive(
        output_dir / filename,
        manifest=manifest_bytes,
        wasm=(FIXTURES / "plugin.wasm").read_bytes(),
        signature=signature_path.read_bytes() if signature_path.exists() else None,
        provenance=provenance_path.read_bytes() if provenance_path.exists() else None,
    )
    return output_dir / filename


class PackageContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.temp.name)
        self.package = self.directory / "dev.kinetix.fixture-1.0.0.kxp"
        make_archive(self.package)

    def tearDown(self):
        self.temp.cleanup()

    def test_accepts_structurally_valid_unsigned_package(self):
        manifest, digest, has_signature = validate_package(self.package)
        self.assertEqual(manifest["id"], "dev.kinetix.fixture")
        self.assertEqual(len(digest), 64)
        self.assertFalse(has_signature)

    def test_accepts_syntactically_valid_but_host_incompatible_api(self):
        incompatible = MANIFEST.replace(b'plugin_api = "1"', b'plugin_api = "99"')
        make_archive(self.package, manifest=incompatible)
        manifest, _, _ = validate_package(self.package)
        self.assertEqual(manifest["plugin_api"], "99")

    def test_checks_full_package_digest(self):
        _, expected, _ = validate_package(self.package)
        make_archive(self.package, wasm=WASM + b"changed")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            validate_package(self.package, expected_sha256=expected)

    def test_rejects_host_invalid_semver_and_pricing_scope(self):
        bad_semver = MANIFEST.replace(b'version = "1.0.0"', b'version = "1.0.0-01"')
        make_archive(self.package, manifest=bad_semver)
        with self.assertRaisesRegex(ValueError, "plugin.toml"):
            validate_package(self.package)

        bad_pricing_scope = MANIFEST + b'''\n[[integrations]]\nid = "fixture"\nname = "Fixture integration"\ndescription = "Fixture integration"\nmodel_source = "fixture-models"\n\n[integrations.provider]\nbase_url = "https://provider.invalid"\nwire_format = "openai"\nauth_scheme = "bearer"\ntimeout_ms = 1000\ncapability_mode = "permissive"\nfollow_redirects = false\npricing_scope = "whatever"\n'''
        make_archive(self.package, manifest=bad_pricing_scope)
        with self.assertRaisesRegex(ValueError, "plugin.toml"):
            validate_package(self.package)

    def test_rejects_malformed_manifest_signature_length_and_identity(self):
        for kwargs, message in (
            ({"manifest": MANIFEST + b"id = 'duplicate'\n"}, "plugin.toml"),
            ({"signature": b"short"}, "signature.ed25519"),
            ({"manifest": MANIFEST.replace(b"1.0.0", b"2.0.0")}, "filename must be"),
        ):
            with self.subTest(message=message):
                make_archive(self.package, **kwargs)
                with self.assertRaisesRegex(ValueError, message):
                    validate_package(self.package)

    def test_accepts_base64_signature_and_unknown_regular_entries(self):
        make_archive(
            self.package,
            signature=base64.b64encode(b"s" * 64),
            extra={"future-metadata.json": b"{}"},
        )
        _, _, has_signature = validate_package(self.package)
        self.assertTrue(has_signature)

    def test_rejects_duplicate_and_non_top_level_entries(self):
        with tarfile.open(self.package, "w:") as archive:
            add_member(archive, "plugin.toml", MANIFEST)
            add_member(archive, "plugin.toml", MANIFEST)
            add_member(archive, "plugin.wasm", WASM)
        with self.assertRaisesRegex(ValueError, "duplicate package entry"):
            validate_package(self.package)

        make_archive(self.package, extra={"nested/metadata.json": b"{}"})
        with self.assertRaisesRegex(ValueError, "top-level file path"):
            validate_package(self.package)

    def test_provenance_schema_and_safe_repository_normalization(self):
        normalized = normalized_repository_url(
            "https://fixture-user@GitHub.com/PrightCord/kinetix-plugins.git"
        )
        self.assertEqual(normalized, "https://github.com/PrightCord/kinetix-plugins")
        self.assertNotIn("fixture-user", normalized)
        validate_provenance({"schema_version": 1}, "fixture")
        with self.assertRaises(ValueError):
            validate_provenance({"schema_version": 1, "source": {"revision": "unknown"}}, "fixture")

    def test_v1_fixture_cases(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = pathlib.Path(temp)

            valid, _, signed = validate_package(package_from_fixture("valid", directory))
            self.assertEqual(valid["id"], "dev.kinetix.b-ai")
            self.assertTrue(signed)

            unsigned, _, signed = validate_package(package_from_fixture("unsigned", directory))
            self.assertEqual(unsigned["id"], "dev.kinetix.b-ai")
            self.assertFalse(signed)

            incompatible, _, _ = validate_package(package_from_fixture("incompatible", directory))
            self.assertEqual(incompatible["plugin_api"], "99")

            malformed = package_from_fixture("malformed", directory)
            with self.assertRaisesRegex(ValueError, "invalid plugin.toml"):
                validate_package(malformed)

            mismatched = package_from_fixture("mismatched", directory)
            with self.assertRaisesRegex(ValueError, "filename must be"):
                validate_package(mismatched)

            tampered, _, signed = validate_package(package_from_fixture("tampered", directory))
            self.assertTrue(signed)
            self.assertNotEqual(
                (FIXTURES / "valid/plugin.toml").read_bytes(),
                (FIXTURES / "tampered/plugin.toml").read_bytes(),
            )

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required to verify signing vectors")
    def test_documented_byte_level_signing_vector(self):
        vector = json.loads((FIXTURES / "signing-vector.json").read_text(encoding="utf-8"))
        wasm = bytes.fromhex(vector["plugin_wasm_hex"])
        manifest = bytes.fromhex(vector["plugin_toml_hex"])
        digest = hashlib.sha256(wasm + manifest).digest()
        self.assertEqual(digest.hex(), vector["message_sha256_hex"])

        public_key_der = bytes.fromhex("302a300506032b6570032100" + vector["public_key_ed25519_raw_hex"])
        signature = bytes.fromhex(vector["signature_ed25519_hex"])
        with (
            tempfile.NamedTemporaryFile() as public_key_file,
            tempfile.NamedTemporaryFile() as digest_file,
            tempfile.NamedTemporaryFile() as signature_file,
        ):
            public_key_file.write(public_key_der)
            public_key_file.flush()
            digest_file.write(digest)
            digest_file.flush()
            signature_file.write(signature)
            signature_file.flush()
            result = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                    "-inkey", public_key_file.name, "-in", digest_file.name,
                    "-sigfile", signature_file.name,
                ],
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required to verify fixture signatures")
    def test_fixture_signatures_cover_wasm_and_manifest(self):
        publisher_key = FIXTURES / "test-publisher.pem"
        publisher_data = json.loads((FIXTURES / "test-publisher.json").read_text(encoding="utf-8"))
        public_der = subprocess.check_output(
            ["openssl", "pkey", "-pubin", "-in", str(publisher_key), "-outform", "DER"]
        )
        self.assertEqual(base64.b64decode(publisher_data["public_key_base64"]), public_der[-32:])

        wasm = (FIXTURES / "plugin.wasm").read_bytes()
        for case, expected in (("valid", True), ("incompatible", True), ("tampered", False)):
            payload = hashlib.sha256(wasm + (FIXTURES / case / "plugin.toml").read_bytes()).digest()
            with (
                self.subTest(case=case),
                tempfile.NamedTemporaryFile() as digest_file,
                tempfile.NamedTemporaryFile() as signature_file,
            ):
                digest_file.write(payload)
                digest_file.flush()
                signature_file.write(
                    base64.b64decode(
                        (FIXTURES / case / "signature.ed25519").read_text().strip(), validate=True
                    )
                )
                signature_file.flush()
                result = subprocess.run(
                    [
                        "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                        "-inkey", str(publisher_key), "-in", digest_file.name,
                        "-sigfile", signature_file.name,
                    ],
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, expected)


if __name__ == "__main__":
    unittest.main()
