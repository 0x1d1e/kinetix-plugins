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
        vectors = json.loads((FIXTURES / "cases.json").read_text())
        probe_wat = subprocess.check_output(
            ["wasm-tools", "print", str(component)], text=True,
        ).rstrip()
        for ambient in vectors["ambient_imports"]:
            # Require a real WASI resource or function, not a made-up signature
            # that would hide permissive registration behind a type mismatch.
            if "resource" in ambient:
                declarations = ""
                required = '(export ' + json.dumps(ambient["resource"]) + ' (type (sub resource)))'
            else:
                declarations = '(type $forbidden-import-op (func ' + ambient["signature"] + '))'
                required = '(export ' + json.dumps(ambient["function"]) + ' (func (type $forbidden-import-op)))'
            wat = temp / "ambient.wat"
            wat.write_text(
                probe_wat[:-1] + '\n' + declarations + '(import '
                + json.dumps(ambient["import"]) + ' (instance ' + required + ')))\n'
            )
            wasm = output / "ambient" / (ambient["id"] + ".wasm")
            wasm.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["wasm-tools", "parse", str(wat), "-o", str(wasm)], check=True)
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
