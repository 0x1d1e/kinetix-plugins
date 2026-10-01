#!/usr/bin/env bash
# Validate portable security packages and prove probes reach their host imports.
# Kinetix consumers must separately execute cases.json against real host policy.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kinetix-security.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
python3 scripts/test_security_fixtures.py
python3 scripts/build_security_fixtures.py --out-dir "$WORK"
python3 scripts/test_security_fixtures.py --packages "$WORK"
cargo run --locked --release -p kinetix-plugin-component-runtime-conformance \
  --features runtime --bin security-fixture-smoke -- "$WORK"
