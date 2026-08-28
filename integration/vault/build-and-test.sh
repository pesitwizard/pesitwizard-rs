#!/usr/bin/env bash
# Build the node binary and run the native Vault PKI integration test.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
echo "1. Building release binary..."
(cd "$ROOT" && cargo build --release -p pesit-node)
cp "$ROOT/target/release/pesitwizard" "$DIR/../cx/pw-node/"
echo "2. Building images + running Vault integration..."
cd "$DIR"
docker compose build >/dev/null
set +e
docker compose up --abort-on-container-exit --exit-code-from test-runner
EXIT_CODE=$(docker inspect --format '{{.State.ExitCode}}' vault-test-runner 2>/dev/null || echo 1)
set -e
echo "test-runner exit code: $EXIT_CODE"
docker compose down -v >/dev/null 2>&1
rm -f "$DIR/../cx/pw-node/pesitwizard"
exit "$EXIT_CODE"
