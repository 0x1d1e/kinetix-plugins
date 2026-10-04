#!/usr/bin/env python3
"""Mirror the canonical plugin contract from a Kinetix host checkout.

The host repository (`PrightCord/kinetix`) owns `wit/`: the WIT worlds,
JSON contract schemas, and shared golden fixtures. This repository keeps
byte-identical copies under `wit/` and `sdk/wit*/`. Only the fixture trees in
`PLUGIN_OWNED` originate here.

    scripts/sync_host_contract.py [--check] [--host PATH]

`--host` defaults to `$KINETIX_DIR`, then `../kinetix`. `--check` reports
drift without writing and exits non-zero when any copy differs.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN_OWNED = (
    "wit/fixtures/capability-security",
    "wit/fixtures/credential-strategy",
    "wit/fixtures/kxp",
    "wit/fixtures/model-discovery",
    "wit/fixtures/plugin-adapter",
    "wit/fixtures/plugin-install",
)
SDK_COPIES = {"sdk/wit": "wit", "sdk/wit-v2": "wit/v2", "sdk/wit-v3": "wit/v3"}


def files_under(base: pathlib.Path) -> set[str]:
    if not base.is_dir():
        return set()
    return {path.relative_to(base).as_posix() for path in base.rglob("*") if path.is_file()}


def plugin_owned(local: str) -> bool:
    return any(local == owned or local.startswith(owned + "/") for owned in PLUGIN_OWNED)


def expected_copies(host: pathlib.Path) -> tuple[dict[str, pathlib.Path], set[str]]:
    """Return local path -> host source, and the local trees the host owns."""
    copies = {f"wit/{rel}": host / "wit" / rel for rel in files_under(host / "wit")}
    for sdk_dir, host_dir in SDK_COPIES.items():
        for rel in files_under(host / host_dir):
            if sdk_dir == "sdk/wit" and "/" in rel:
                continue  # sdk/wit holds only the top-level v1 world
            copies[f"{sdk_dir}/{rel}"] = host / host_dir / rel
    return copies, {"wit", *SDK_COPIES}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="report drift without writing")
    parser.add_argument(
        "--host",
        type=pathlib.Path,
        default=pathlib.Path(os.environ.get("KINETIX_DIR", ROOT.parent / "kinetix")),
        help="Kinetix host checkout (default: $KINETIX_DIR or ../kinetix)",
    )
    args = parser.parse_args()
    host = args.host.resolve()
    if not (host / "wit" / "kinetix-plugin.wit").is_file():
        print(f"error: {host} is not a Kinetix host checkout (missing wit/kinetix-plugin.wit)", file=sys.stderr)
        return 2

    copies, owned_trees = expected_copies(host)
    stale = sorted(
        local
        for local, source in copies.items()
        if not (ROOT / local).is_file() or (ROOT / local).read_bytes() != source.read_bytes()
    )
    extra = sorted(
        f"{tree}/{rel}"
        for tree in owned_trees
        for rel in files_under(ROOT / tree)
        if f"{tree}/{rel}" not in copies and not plugin_owned(f"{tree}/{rel}")
    )

    if args.check:
        for local in stale:
            state = "differs from" if (ROOT / local).is_file() else "missing; expected"
            print(f"drift: {local} {state} host {copies[local].relative_to(host)}")
        for local in extra:
            print(f"drift: {local} has no host counterpart")
        if stale or extra:
            print(f"run scripts/sync_host_contract.py --host {host} to mirror the host contract", file=sys.stderr)
            return 1
        print(f"plugin contract matches host ({len(copies)} files)")
        return 0

    for local in stale:
        target = ROOT / local
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(copies[local], target)
        print(f"synced {local}")
    for local in extra:
        (ROOT / local).unlink()
        print(f"removed {local}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
