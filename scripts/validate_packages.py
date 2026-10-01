#!/usr/bin/env python3
"""Validate the plugin-side .kxp v1 container contract."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import tomllib
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from validate_manifests import validate_manifest  # noqa: E402

PROVENANCE_SCHEMA = json.loads(
    (ROOT / "schemas/package-provenance-v1.schema.json").read_text(encoding="utf-8")
)
PROVENANCE_VALIDATOR = Draft202012Validator(PROVENANCE_SCHEMA)
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_COMPONENT_BYTES = 64 * 1024 * 1024
MAX_TEXT_ENTRY_BYTES = 2 * 1024 * 1024
MAX_SIGNATURE_BYTES = 4096
PACKAGE_ENTRY_LIMITS = {
    "plugin.toml": MAX_TEXT_ENTRY_BYTES,
    "plugin.wasm": MAX_COMPONENT_BYTES,
    "README.md": MAX_TEXT_ENTRY_BYTES,
    "LICENSE": MAX_TEXT_ENTRY_BYTES,
    "signature.ed25519": MAX_SIGNATURE_BYTES,
    "provenance.json": MAX_TEXT_ENTRY_BYTES,
}


def normalized_repository_url(value: str) -> str | None:
    """Convert common Git remote forms to credential-free HTTPS URLs."""
    if re.fullmatch(r"[^/@:]+@[^/:]+:[^?]+", value):
        _, host, path = re.fullmatch(r"([^@]+)@([^:]+):(.+)", value).groups()
        scheme = "https"
    else:
        try:
            parsed = urlsplit(value)
        except ValueError:
            return None
        if parsed.scheme not in {"http", "https", "ssh", "git"} or not parsed.hostname:
            return None
        host = parsed.hostname
        path = parsed.path.lstrip("/")
        scheme = "https"
        if parsed.query or parsed.fragment:
            return None
    if scheme != "https" or not host or not path:
        return None
    path = path.removesuffix(".git").strip("/")
    parts = path.split("/")
    if len(parts) != 2 or any(not part or part in {".", ".."} for part in parts):
        return None
    return f"https://{host.lower()}/{parts[0]}/{parts[1]}"


def make_provenance(root: pathlib.Path = ROOT) -> dict:
    provenance = {"schema_version": 1}
    try:
        revision = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip().lower()
        remote = subprocess.check_output(
            ["git", "-C", str(root), "config", "--get", "remote.origin.url"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        status = subprocess.check_output(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return provenance

    repository = normalized_repository_url(remote)
    if repository and re.fullmatch(r"([0-9a-f]{40}|[0-9a-f]{64})", revision):
        provenance["source"] = {
            "repository": repository,
            "revision": revision,
            "working_tree_clean": not status,
        }
    return provenance


def validate_provenance(data: object, source: str) -> None:
    errors = sorted(PROVENANCE_VALIDATOR.iter_errors(data), key=lambda error: list(map(str, error.absolute_path)))
    if errors:
        error = errors[0]
        location = ".".join(map(str, error.absolute_path)) or "provenance"
        raise ValueError(f"{source}: {location}: {error.message}")


def validate_package(
    package_path: pathlib.Path,
    expected_sha256: str | None = None,
) -> tuple[dict, str, bool]:
    if not package_path.is_file():
        raise ValueError(f"{package_path}: package file does not exist")
    if package_path.stat().st_size > MAX_PACKAGE_BYTES:
        raise ValueError(f"{package_path}: package exceeds {MAX_PACKAGE_BYTES} bytes")
    package_bytes = package_path.read_bytes()
    package_digest = hashlib.sha256(package_bytes).hexdigest()
    if expected_sha256 and package_digest.lower() != expected_sha256.lower():
        raise ValueError(f"{package_path}: package SHA-256 does not match expected digest")

    try:
        with tarfile.open(fileobj=io.BytesIO(package_bytes), mode="r:") as archive:
            names: set[str] = set()
            files: dict[str, bytes] = {}
            for member in archive.getmembers():
                name = member.name
                if (
                    not name
                    or name in {".", ".."}
                    or name.startswith("/")
                    or "/" in name
                    or chr(92) in name
                ):
                    raise ValueError(f"package entry {name!r} must be a top-level file path")
                if name in names:
                    raise ValueError(f"duplicate package entry {name!r}")
                if not member.isfile():
                    raise ValueError(f"package entry {name!r} must be a regular file")
                names.add(name)
                max_size = PACKAGE_ENTRY_LIMITS.get(name)
                if max_size is None:
                    continue
                if member.size > max_size:
                    raise ValueError(f"package entry {name!r} exceeds {max_size} bytes")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f"cannot read package entry {name!r}")
                files[name] = stream.read()
    except (tarfile.TarError, OSError) as error:
        raise ValueError(f"{package_path}: invalid uncompressed tar archive: {error}") from error

    missing = {"plugin.toml", "plugin.wasm"} - files.keys()
    if missing:
        raise ValueError(f"{package_path}: missing required entries: {', '.join(sorted(missing))}")
    component = files["plugin.wasm"]
    if len(component) < 8 or not component.startswith(b"\x00asm"):
        raise ValueError(f"{package_path}: plugin.wasm is not a WebAssembly module (bad magic)")
    if "signature.ed25519" in files:
        signature = files["signature.ed25519"]
        if len(signature) != 64:
            try:
                signature = base64.b64decode(signature.decode("ascii").strip(), validate=True)
            except (UnicodeDecodeError, binascii.Error) as error:
                raise ValueError(
                    f"{package_path}: signature.ed25519 must be 64 raw bytes or base64"
                ) from error
        if len(signature) != 64:
            raise ValueError(f"{package_path}: signature.ed25519 must decode to 64 bytes")

    try:
        manifest = tomllib.loads(files["plugin.toml"].decode("utf-8"))
        validate_manifest(package_path, manifest)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError) as error:
        raise ValueError(f"{package_path}: invalid plugin.toml: {error}") from error

    expected_name = f"{manifest['id']}-{manifest['version']}.kxp"
    if package_path.name != expected_name:
        raise ValueError(
            f"{package_path}: filename must be {expected_name!r} to match packaged identity/version"
        )
    if "provenance.json" in files:
        try:
            provenance = json.loads(files["provenance.json"])
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"{package_path}: invalid provenance.json: {error}") from error
        validate_provenance(provenance, f"{package_path}: provenance.json")
    return manifest, package_digest, "signature.ed25519" in files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", nargs="?", type=pathlib.Path)
    parser.add_argument("--expected-sha256", help="compare the full archive digest with a catalog digest")
    parser.add_argument("--write-provenance", type=pathlib.Path, help="write source metadata for a package")
    parser.add_argument("--root", type=pathlib.Path, default=ROOT, help="source repository root")
    args = parser.parse_args()

    try:
        if args.write_provenance:
            if args.package:
                parser.error("provide either a package or --write-provenance, not both")
            data = make_provenance(args.root)
            validate_provenance(data, "generated provenance")
            args.write_provenance.write_text(
                json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            return 0
        if not args.package:
            parser.error("a package path is required")
        manifest, digest, has_signature = validate_package(args.package, args.expected_sha256)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1

    signature_status = "present" if has_signature else "absent"
    print(f"validated {manifest['id']} {manifest['version']} signature={signature_status} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
