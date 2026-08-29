#!/usr/bin/env bash
# S3 connector integration test (host-driven): receive a file into S3, then read it back from S3.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
KEY=integration-test-key
A=http://localhost:8090; T=http://localhost:9090
PASSED=0; FAILED=0
ok(){ echo "   [PASS] $1"; PASSED=$((PASSED+1)); }
ko(){ echo "   [FAIL] $1"; FAILED=$((FAILED+1)); }
h(){ curl -s -H "X-API-Key: $KEY" -H 'Content-Type: application/json' "$@"; }
c(){ curl -s -H 'Content-Type: application/json' "$@"; }
wait_done(){ for i in $(seq 1 120); do local st; st=$(c "$T/api/v1/transfers/$1"|jq -r .status); case "$st" in COMPLETED|FAILED|CANCELLED) echo "$st"; return;; esac; sleep 0.5; done; echo TIMEOUT; }

echo "1. Building node image..."
(cd "$ROOT" && cargo build --release -p pesit-node) || exit 1
cp "$ROOT/target/release/pesitwizard" "$DIR/../cx/pw-node/"
cd "$DIR"
cleanup(){ docker compose down -v >/dev/null 2>&1; rm -f "$DIR/../cx/pw-node/pesitwizard"; }
trap cleanup EXIT
docker compose build >/dev/null
docker compose up -d minio createbucket pw-node
for i in $(seq 1 60); do curl -sf "$A/actuator/health" >/dev/null 2>&1 && break; sleep 1; done

echo "2. Configure an S3 connector (MinIO) and virtual files..."
CT=$(h "$A/api/v1/config/connectors" -X POST -d '{"id":"s3","type":"s3","bucket":"pesit","endpoint":"http://minio:9000","region":"us-east-1","accessKey":"minioadmin","secretKey":"minioadmin","pathStyle":true}')
[ "$(echo "$CT" | jq -r '.id')" = "s3" ] && ok "S3 connector created" || ko "connector create ($CT)"
TEST=$(h "$A/api/v1/config/connectors/s3/test" -X POST)
[ "$(echo "$TEST" | jq -r '.success')" = "true" ] && ok "S3 connector reachable" || ko "connector test ($TEST)"
h "$A/api/v1/config/partners" -X POST -d '{"id":"SELF","enabled":true,"accessType":"BOTH"}' >/dev/null
h "$A/api/v1/config/files" -X POST -d '{"id":"PUTS3","enabled":true,"direction":"RECEIVE","connector":"s3","connectorPath":"roundtrip.dat","recordLength":4096,"recordFormat":128}' >/dev/null
h "$A/api/v1/config/files" -X POST -d '{"id":"GETS3","enabled":true,"direction":"SEND","connector":"s3","connectorPath":"roundtrip.dat","recordLength":4096,"recordFormat":128}' >/dev/null
h "$A/api/v1/servers" -X POST -d '{"serverId":"S","port":5001,"receiveDirectory":"/data/received","sendDirectory":"/data/send","maxEntitySize":32768,"syncPointsEnabled":true,"autoStart":true}' >/dev/null
sleep 1
c "$T/api/v1/servers" -X POST -d '{"name":"self","host":"127.0.0.1","port":5001,"serverId":"S","enabled":true}' >/dev/null

echo "3. Receive a file into S3..."
docker exec pw-node sh -c 'head -c 300000 /dev/urandom > /data/send/orig.dat; md5sum /data/send/orig.dat' > /tmp/s3orig.txt 2>/dev/null
MD5=$(awk '{print $1}' /tmp/s3orig.txt)
TID=$(c "$T/api/v1/transfers/send" -X POST -d '{"server":"self","partnerId":"SELF","filename":"/data/send/orig.dat","remoteFilename":"PUTS3"}' | jq -r '.transferId // .id')
ST=$(wait_done "$TID"); echo "   send->S3: $ST"
[ "$ST" = COMPLETED ] && ok "file received and uploaded to S3" || ko "receive->S3 ($ST)"
# object present in MinIO (resolve the compose-generated network name dynamically)
NET=$(docker network ls --format '{{.Name}}' | grep 's3-net' | head -1)
docker run --rm --entrypoint /bin/sh --network "$NET" minio/mc:latest -c 'until mc alias set m http://minio:9000 minioadmin minioadmin >/dev/null 2>&1; do sleep 1; done; mc stat m/pesit/roundtrip.dat >/dev/null 2>&1' && ok "object exists in the S3 bucket" || ko "object missing in S3"

echo "4. Read the file back from S3..."
TID2=$(c "$T/api/v1/transfers/receive" -X POST -d '{"server":"self","partnerId":"SELF","filename":"/data/received/froms3.dat","remoteFilename":"GETS3"}' | jq -r '.transferId // .id')
ST2=$(wait_done "$TID2"); echo "   S3->receive: $ST2"
[ "$ST2" = COMPLETED ] && ok "file read back from S3" || ko "S3->receive ($ST2)"
GOT=$(docker exec pw-node sh -c 'md5sum /data/received/froms3.dat 2>/dev/null | cut -d" " -f1')
[ -n "$MD5" ] && [ "$GOT" = "$MD5" ] && ok "round-trip through S3 preserves the file (md5 $MD5)" || ko "S3 round-trip md5 ($GOT vs $MD5)"

echo "=========================================="
echo "  Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ $FAILED -eq 0 ]
