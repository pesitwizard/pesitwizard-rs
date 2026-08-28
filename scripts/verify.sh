#!/usr/bin/env bash
# Verification suite: fmt (nightly) → clippy (-D warnings) → tests.
# Toggle individual gates with SKIP_FMT=1, SKIP_CLIPPY=1, SKIP_TEST=1.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${SKIP_FMT:-0}" != "1" ]; then
    echo "==> fmt"
    cargo +nightly fmt --all -- --check
fi
if [ "${SKIP_CLIPPY:-0}" != "1" ]; then
    echo "==> clippy"
    cargo clippy --workspace --all-targets -- -D warnings
fi
if [ "${SKIP_TEST:-0}" != "1" ]; then
    echo "==> test"
    cargo test --workspace
fi
echo "==> verify OK"
