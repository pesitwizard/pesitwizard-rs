#!/usr/bin/env bash
# Build the Rust binaries, the Docker images, and run the Connect:Express integration tests.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
TEST_SCRIPT="${TEST_SCRIPT:-/tests/run-tests.sh}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
export COMPOSE_FILE

echo "1. Building release binaries..."
(cd "$ROOT" && cargo build --release --workspace)
cp "$ROOT/target/release/pesitwizard" "$DIR/pw-node/"

echo "2. Building Docker images..."
cd "$DIR"
TEST_SCRIPT="$TEST_SCRIPT" docker compose build

echo "3. Running integration tests ($TEST_SCRIPT)..."
set +e
TEST_SCRIPT="$TEST_SCRIPT" docker compose up --abort-on-container-exit --exit-code-from test-runner
RUNNER=$(docker compose ps -a --format '{{.Name}}' test-runner 2>/dev/null | head -1)
EXIT_CODE=$(docker inspect --format '{{.State.ExitCode}}' "${RUNNER:-test-runner}" 2>/dev/null || echo 1)
set -e
echo "test-runner exit code: $EXIT_CODE"

if [ "${KEEP_LOGS:-0}" = "1" ] || [ $EXIT_CODE -ne 0 ]; then
    mkdir -p "$DIR/logs"
    docker compose logs --no-color pw-node > "$DIR/logs/pw-node.log" 2>&1 || true
    docker compose logs --no-color cx-server > "$DIR/logs/cx-server.log" 2>&1 || true
    echo "Logs saved in $DIR/logs"
fi
echo "4. Cleaning up..."
docker compose down -v
rm -f "$DIR/pw-node/pesitwizard"
exit $EXIT_CODE
