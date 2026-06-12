#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Running unit tests"
cargo test --workspace --lib

echo "==> Measuring coverage with cargo-llvm-cov"
if ! cargo llvm-cov --version >/dev/null 2>&1; then
  cargo install cargo-llvm-cov --locked
fi

cargo llvm-cov \
  --workspace \
  --lib \
  --all-features \
  --lcov \
  --output-path lcov.info \
  --fail-under-lines 100

echo "All tests passed with 100% line coverage."
