#!/usr/bin/env bash
# Launch a throwaway pesitwizard node for the Playwright UI tests.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
BIN="${PESIT_BIN:-$ROOT/target/debug/pesitwizard}"
WORK="$DIR/.work"
ADMIN_PORT="${PW_ADMIN_PORT:-8199}"
TRANSFER_PORT="${PW_TRANSFER_PORT:-9199}"

if [ ! -x "$BIN" ]; then
  echo "building pesitwizard…" >&2
  (cd "$ROOT" && cargo build -p pesit-node) >&2
fi
rm -rf "$WORK"
mkdir -p "$WORK/received" "$WORK/send" "$WORK/cp" "$WORK/cpo" "$WORK/tls"

export PESIT_API_KEY="e2e-key"
export RUST_LOG="${RUST_LOG:-warn,pesitwizard=info,pesit_client=info}"
"$BIN" \
  --api-port "$ADMIN_PORT" --transfer-port "$TRANSFER_PORT" --api-bind 127.0.0.1 \
  --db "$WORK/node.db" --checkpoint-dir "$WORK/cp" --client-checkpoint-dir "$WORK/cpo" \
  --receive-dir "$WORK/received" --client-tls-dir "$WORK/tls" --pki-dir "$WORK/pki" 2>&1 | tee "$WORK/node.log"
