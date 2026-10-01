#!/usr/bin/env bash
# Build and invoke the production Antigravity v3 adapter component with every
# host import configured to trap. This catches capability use hidden behind a
# different generated WIT world.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

command -v wasm-tools >/dev/null || { echo "wasm-tools is required" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kinetix-adapter-runtime.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

cargo build --locked --release --target wasm32-unknown-unknown -p kinetix-plugin-antigravity-oauth
MODULE="target/wasm32-unknown-unknown/release/kinetix_plugin_antigravity_oauth.wasm"
wasm-tools component new "$MODULE" -o "$WORK/antigravity.component.wasm"
wasm-tools validate --features component-model "$WORK/antigravity.component.wasm"
cargo run --locked --release -p kinetix-plugin-component-runtime-conformance --features runtime -- "$WORK/antigravity.component.wasm"
