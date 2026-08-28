#!/usr/bin/env bash
# Local end-to-end check: starts the server and client binaries, configures them through the REST
# API exactly like the Docker integration tests do, and runs transfers in both directions.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/target/debug}"
S="${E2E_DIR:-$(mktemp -d)}"
KEY=integration-test-key
SRV=http://127.0.0.1:${E2E_SERVER_API:-8090}
CLI=http://127.0.0.1:${E2E_CLIENT_API:-9091}
PESIT_PORT=${E2E_PESIT_PORT:-5011}
mkdir -p "$S/srv/received" "$S/srv/send" "$S/cli/send" "$S/cli/received" "$S/cli/db"
FAILED=0
check() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; else echo "  [FAIL] $1: got '$2', expected '$3'"; FAILED=$((FAILED + 1)); fi; }

RUST_LOG=info,pesit=debug PESIT_API_KEY=$KEY "$BIN/pesitwizard-server" --api-port "${E2E_SERVER_API:-8090}" --db "$S/srv/server.db" --checkpoint-dir "$S/srv/cp" > "$S/server.log" 2>&1 &
SPID=$!
RUST_LOG=info,pesit=debug "$BIN/pesitwizard-client" serve --api-port "${E2E_CLIENT_API:-9091}" --db "$S/cli/db/client.db" --checkpoint-dir "$S/cli/db/cp" --receive-dir "$S/cli/received" > "$S/client.log" 2>&1 &
CPID=$!
trap 'kill $SPID $CPID 2>/dev/null' EXIT
for i in $(seq 1 50); do curl -sf "$SRV/actuator/health" > /dev/null && curl -sf "$CLI/actuator/health" > /dev/null && break; sleep 0.2; done

h() { curl -s -H "X-API-Key: $KEY" -H "Content-Type: application/json" "$@"; }
c() { curl -s -H "Content-Type: application/json" "$@"; }
wait_done() {
    for i in $(seq 1 300); do
        ST=$(c "$CLI/api/v1/transfers/$1" | jq -r .status)
        case "$ST" in COMPLETED|FAILED|CANCELLED|INTERRUPTED) break ;; esac
        sleep 0.2
    done
    c "$CLI/api/v1/transfers/$1"
}

echo "== configuration"
check "health" "$(curl -s $SRV/actuator/health | jq -r .status)" "UP"
check "api key enforced" "$(curl -s -o /dev/null -w '%{http_code}' $SRV/api/v1/config/partners)" "401"
h -X POST $SRV/api/v1/config/partners -d '{"id":"PWSRV01","description":"client","password":"","enabled":true,"accessType":"BOTH","maxConnections":10}' > /dev/null
h -X POST $SRV/api/v1/config/files -d "{\"id\":\"PWSEND\",\"enabled\":true,\"direction\":\"RECEIVE\",\"receiveDirectory\":\"$S/srv/received\",\"receiveFilenamePattern\":\"from_client_\${transferId}\",\"overwrite\":false,\"recordLength\":4096,\"recordFormat\":0}" > /dev/null
h -X POST $SRV/api/v1/config/files -d "{\"id\":\"PWRECV\",\"enabled\":true,\"direction\":\"SEND\",\"sendFile\":\"$S/srv/send/PWRECV\",\"recordLength\":4096,\"recordFormat\":0}" > /dev/null
h -X POST $SRV/api/v1/servers -d "{\"serverId\":\"PWSERVER\",\"port\":$PESIT_PORT,\"receiveDirectory\":\"$S/srv/received\",\"sendDirectory\":\"$S/srv/send\",\"maxEntitySize\":32768,\"syncPointsEnabled\":true,\"syncIntervalKb\":256,\"autoStart\":true}" > /dev/null
sleep 0.3
check "server running" "$(h $SRV/api/v1/servers/PWSERVER/status | jq -r .status)" "RUNNING"
c -X POST $CLI/api/v1/servers -d "{\"name\":\"pw-server\",\"host\":\"127.0.0.1\",\"port\":$PESIT_PORT,\"serverId\":\"PWSERVER\",\"tlsEnabled\":false,\"enabled\":true,\"defaultServer\":true}" > /dev/null

echo "== transfers"
dd if=/dev/urandom of="$S/cli/send/medium.dat" bs=1M count=5 2>/dev/null
MD5=$(md5sum "$S/cli/send/medium.dat" | cut -d' ' -f1)
T=$(c -X POST $CLI/api/v1/transfers/send -d "{\"server\":\"pw-server\",\"partnerId\":\"PWSRV01\",\"filename\":\"$S/cli/send/medium.dat\",\"remoteFilename\":\"PWSEND\",\"syncPointsEnabled\":true}" | jq -r .transferId)
R=$(wait_done "$T")
check "5 MB send completed" "$(echo "$R" | jq -r .status)" "COMPLETED"
check "5 MB send used sync points" "$(echo "$R" | jq -r '.lastSyncPoint > 0')" "true"
check "5 MB received intact" "$(md5sum "$S"/srv/received/from_client_* | cut -d' ' -f1 | head -1)" "$MD5"
dd if=/dev/urandom of="$S/srv/send/PWRECV" bs=1M count=3 2>/dev/null
MD5R=$(md5sum "$S/srv/send/PWRECV" | cut -d' ' -f1)
T=$(c -X POST $CLI/api/v1/transfers/receive -d "{\"server\":\"pw-server\",\"partnerId\":\"PWSRV01\",\"filename\":\"$S/cli/received/got.dat\",\"remoteFilename\":\"PWRECV\"}" | jq -r .transferId)
check "3 MB receive completed" "$(wait_done "$T" | jq -r .status)" "COMPLETED"
check "3 MB received intact" "$(md5sum "$S/cli/received/got.dat" | cut -d' ' -f1)" "$MD5R"
check "message with reply" "$(c -X POST $CLI/api/v1/transfers/message -d '{"server":"pw-server","partnerId":"PWSRV01","message":"hello","expectsReply":true}' | jq -r .reply)" "OK"
: > "$S/cli/send/empty.dat"
T=$(c -X POST $CLI/api/v1/transfers/send -d "{\"server\":\"pw-server\",\"partnerId\":\"PWSRV01\",\"filename\":\"$S/cli/send/empty.dat\",\"remoteFilename\":\"PWSEND\"}" | jq -r .transferId)
check "empty file" "$(wait_done "$T" | jq -r .status)" "COMPLETED"

echo "== errors"
check "unknown server" "$(c -X POST $CLI/api/v1/transfers/send -d '{"server":"nope","filename":"/x","remoteFilename":"PWSEND"}' | jq -r .status)" "404"
check "missing file" "$(c -X POST $CLI/api/v1/transfers/send -d '{"server":"pw-server","filename":"/does/not/exist","remoteFilename":"PWSEND"}' | jq -r .status)" "400"
T=$(c -X POST $CLI/api/v1/transfers/send -d "{\"server\":\"pw-server\",\"partnerId\":\"UNKNOWN\",\"filename\":\"$S/cli/send/empty.dat\",\"remoteFilename\":\"PWSEND\"}" | jq -r .transferId)
check "unknown partner refused (D3-301)" "$(wait_done "$T" | jq -r .diagnosticCode)" "D3-301"
T=$(c -X POST $CLI/api/v1/transfers/send -d "{\"server\":\"pw-server\",\"partnerId\":\"PWSRV01\",\"filename\":\"$S/cli/send/empty.dat\",\"remoteFilename\":\"NOFILE\"}" | jq -r .transferId)
check "unknown virtual file refused (D2-226)" "$(wait_done "$T" | jq -r .diagnosticCode)" "D2-226"
check "retry of unknown transfer" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $CLI/api/v1/transfers/nonexistent/retry)" "404"

echo
echo "Logs in $S ; failures: $FAILED"
exit $FAILED
