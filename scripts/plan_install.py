#!/usr/bin/env python3
"""Print an inspectable install proposal from plugin.toml or a .kxp; never apply it."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import tomllib

from validate_manifests import validate_manifest
from validate_packages import validate_package


def plan_json(plan: dict) -> str:
    """Canonical v1 output: sorted keys, two-space indent, ASCII escapes, final LF."""
    return json.dumps(plan, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def generate_plan(manifest: dict) -> dict:
    """Pure proposal generation. No host state, secret inputs, or plugin execution."""
    validate_manifest(pathlib.Path("plugin.toml"), manifest)
    # Snapshot input so returned proposals cannot mutate the caller's manifest.
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    data = json.loads(encoded)
    objects: dict[str, list] = {key: [] for key in ("integrations", "accounts", "credentials", "routes")}
    for integration in sorted(data.get("integrations", []), key=lambda item: item["id"]):
        integration_id = integration["id"]
        mode = integration.get("credential_mode")
        if mode is None:
            raise ValueError(f"integration {integration_id}: install planning requires explicit credential_mode; legacy inference is host-owned")
        integration_ref = f"integration/{integration_id}"
        account_ref = f"account/{integration_id}"
        credential_ref = f"credential/{integration_id}"
        install = integration.pop("install", {})
        objects["integrations"].append({"ref": integration_ref, "declaration": integration})
        account = install.get("account")
        if account is not None:
            acquisition = {"mode": mode}
            if mode == "manual":
                acquisition.update(integration["manual_credential"])
                acquisition["requirements"] = sorted(acquisition["requirements"])
            elif mode == "auth_flow":
                acquisition["flow"] = integration["auth_flow"]
            if integration.get("credential_strategy"):
                acquisition["strategy"] = integration["credential_strategy"]
            objects["accounts"].append({
                "ref": account_ref, "integration": integration_ref,
                "name": account["name"], "credential": credential_ref,
            })
            objects["credentials"].append({
                "ref": credential_ref, "integration": integration_ref,
                "account": account_ref, "acquisition": acquisition,
            })
        for route in sorted(install.get("routes", []), key=lambda item: item["id"]):
            proposal = {
                "ref": f"route/{integration_id}/{route['id']}",
                "integration": integration_ref, "model": route["model"],
            }
            if account is not None:
                proposal["account"] = account_ref
            objects["routes"].append(proposal)

    permissions = data["permissions"]
    permissions["network_hosts"].sort()
    permissions["credential_scopes"].sort()
    return {
        "schema_version": 1,
        "package": {
            "id": data["id"], "version": data["version"], "plugin_api": data["plugin_api"],
            "manifest_sha256": hashlib.sha256(encoded.encode("ascii")).hexdigest(),
        },
        "requested_permissions": permissions,
        "objects": objects,
        "apply_requires_approval": True,
        "traffic_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--manifest", type=pathlib.Path, help="source plugin.toml")
    source.add_argument("--package", type=pathlib.Path, help="structurally validate and inspect a .kxp")
    args = parser.parse_args()
    try:
        if args.package:
            manifest, digest, _ = validate_package(args.package)
            plan = generate_plan(manifest)
            plan["package"]["sha256"] = digest
        else:
            manifest = tomllib.loads(args.manifest.read_text(encoding="utf-8"))
            plan = generate_plan(manifest)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    sys.stdout.write(plan_json(plan))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
