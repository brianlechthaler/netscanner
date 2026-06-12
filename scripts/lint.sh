#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose run --rm dev bash -c '
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features -- -D warnings
'
