#!/usr/bin/env bash
# The `arbitrary` crate is fuzz-only (#1216): `nos-proto`'s `arbitrary` feature is enabled
# solely by fuzz/Cargo.toml, so no workspace build (check, release, docker) may resolve it.
# Self-check: asking for the feature explicitly MUST match, so this cannot rot to always-green.
set -euo pipefail
cd "$(dirname "$0")/../.."
if cargo tree --workspace -e normal,build,dev -i arbitrary >/dev/null 2>&1; then
  echo "error: 'arbitrary' is in the workspace build graph; keep nos-proto's 'arbitrary' feature fuzz-only (docs/architecture/development.md, Fuzzing)" >&2
  exit 1
fi
cargo tree -p nos-proto --features arbitrary -e normal -i arbitrary >/dev/null 2>&1 || {
  echo "error: self-check failed: 'nos-proto/arbitrary' no longer pulls the arbitrary crate" >&2
  exit 1
}
echo "ok: arbitrary is not in the default workspace build"
