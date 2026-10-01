#!/usr/bin/env python3
"""Build test-only .kxp security fixtures. Never sign or publish these packages."""

import argparse
import io
import json
import pathlib
import shutil
import subprocess
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "wit/fixtures/capability-security/v1"


def package(output, manifest, component):
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:") as archive:
        for name, content in (("plugin.toml", manifest), ("plugin.wasm", component)):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(content))


def build(output):
    subprocess.run([
        "cargo", "build", "--locked", "--release", "--target", "wasm32-unknown-unknown",
        "-p", "kinetix-plugin-security-fixture",
    ], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="kinetix-security-fixtures-") as temp:
        temp = pathlib.Path(temp)
        component = temp / "probe.wasm"
        subprocess.run([
            "wasm-tools", "component", "new",
            str(ROOT / "target/wasm32-unknown-unknown/release/kinetix_plugin_security_fixture.wasm"),
            "-o", str(component),
        ], check=True)
        subprocess.run(["wasm-tools", "validate", str(component)], check=True)
        component_bytes = component.read_bytes()
        for profile in ("denied", "scoped", "over-permission"):
            package(output / profile / "dev.kinetix.security-fixture-0.1.0.kxp",
                    (FIXTURES / profile / "plugin.toml").read_bytes(), component_bytes)
        shutil.copyfile(component, output / "probe.wasm")
        # Inert type import: a control, not an ambient-denial vector.
        type_control = temp / "type-only.wat"
        type_control.write_text('''(component
            (import "wasi:filesystem/types@0.2.0"
                (instance $types (export "descriptor" (type (sub resource)))))
            (alias export $types "descriptor" (type $descriptor))
            (export "descriptor" (type $descriptor))
        )''')
        subprocess.run([
            "wasm-tools", "parse", str(type_control), "-o", str(output / "type-only.wasm"),
        ], check=True)
        subprocess.run(["wasm-tools", "validate", str(output / "type-only.wasm")], check=True)
        vectors = json.loads((FIXTURES / "cases.json").read_text())
        for ambient in vectors["ambient_imports"]:
            # Compile callable probes against pinned upstream WASI WIT. Unused
            # imports disappear, retaining real resource aliases and signatures.
            subprocess.run([
                "cargo", "build", "--locked", "--release", "--target", "wasm32-unknown-unknown",
                "-p", "kinetix-plugin-security-fixture", "--features", ambient["id"],
            ], cwd=ROOT, check=True)
            wasm = output / "ambient" / (ambient["id"] + ".wasm")
            wasm.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run([
                "wasm-tools", "component", "new",
                str(ROOT / "target/wasm32-unknown-unknown/release/kinetix_plugin_security_fixture.wasm"),
                "-o", str(wasm),
            ], check=True)
            subprocess.run(["wasm-tools", "validate", str(wasm)], check=True)
            package(output / "ambient" / ambient["id"] / "dev.kinetix.security-fixture-0.1.0.kxp",
                    (FIXTURES / "denied/plugin.toml").read_bytes(), wasm.read_bytes())
        package(output / "unknown-permission" / "dev.kinetix.security-fixture-0.1.0.kxp",
                (FIXTURES / "unknown-permission/plugin.toml").read_bytes(), component_bytes)
    shutil.copyfile(FIXTURES / "cases.json", output / "cases.json")
    print(f"Test-only security fixtures: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=pathlib.Path, required=True)
    build(parser.parse_args().out_dir.resolve())
