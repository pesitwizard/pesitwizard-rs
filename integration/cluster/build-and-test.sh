#!/usr/bin/env bash
# Clustering integration test (host-driven so it can start node-c late).
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
KEY=integration-test-key
PASSED=0; FAILED=0
ok(){ echo "   [PASS] $1"; PASSED=$((PASSED+1)); }
ko(){ echo "   [FAIL] $1"; FAILED=$((FAILED+1)); }
A=http://localhost:8090; B=http://localhost:8091; C=http://localhost:8092
h(){ local base=$1; shift; curl -s -H "X-API-Key: $KEY" -H 'Content-Type: application/json' "$base$@"; }
has_partner(){ h "$1" /api/v1/config/partners | grep -q "\"$2\""; }
wait_partner(){ for i in $(seq 1 30); do has_partner "$1" "$2" && return 0; sleep 0.5; done; return 1; }
wait_health(){ for i in $(seq 1 60); do curl -sf "$1/actuator/health" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

echo "1. Building node image..."
(cd "$ROOT" && cargo build --release -p pesit-node) || exit 1
cp "$ROOT/target/release/pesitwizard" "$DIR/../cx/pw-node/"
cd "$DIR"
cleanup(){ docker compose --profile late down -v >/dev/null 2>&1; rm -f "$DIR/../cx/pw-node/pesitwizard"; }
trap cleanup EXIT
docker compose build >/dev/null

echo "2. Starting NATS + node-a + node-b..."
docker compose up -d nats node-a node-b
wait_health "$A" && wait_health "$B" || { echo "nodes did not come up"; docker compose logs --no-color | tail -30; exit 1; }
sleep 3   # let membership settle

echo "3. Live configuration propagation..."
h "$A" /api/v1/config/partners -X POST -d '{"id":"CLUSTER_A","description":"made on A","enabled":true,"accessType":"BOTH"}' >/dev/null
wait_partner "$B" "CLUSTER_A" && ok "partner created on node-a replicated to node-b" || ko "A -> B replication"
h "$B" /api/v1/config/partners -X POST -d '{"id":"CLUSTER_B","enabled":true,"accessType":"READ"}' >/dev/null
wait_partner "$A" "CLUSTER_B" && ok "partner created on node-b replicated to node-a" || ko "B -> A replication"

echo "4. Membership and leader..."
CL=$(h "$A" /api/v1/cluster)
echo "   cluster: $(echo "$CL" | jq -c '{members:[.members[].nodeId],leader,isLeader}')"
[ "$(echo "$CL" | jq '.members | length')" = "2" ] && ok "two members visible" || ko "member count"
LEADER=$(echo "$CL" | jq -r '.leader')
[ -n "$LEADER" ] && [ "$LEADER" != "null" ] && ok "a leader is elected ($LEADER)" || ko "leader election"
LB=$(h "$B" /api/v1/cluster | jq -r '.leader')
[ "$LEADER" = "$LB" ] && ok "both nodes agree on the leader" || ko "leader agreement ($LEADER vs $LB)"

echo "5. Snapshot catch-up: node-c joins late..."
docker compose --profile late up -d node-c
wait_health "$C" || { echo "node-c did not come up"; exit 1; }
if wait_partner "$C" "CLUSTER_A" && has_partner "$C" "CLUSTER_B"; then ok "late-joining node-c caught up existing configuration via snapshot"; else ko "node-c snapshot catch-up"; fi
[ "$(h "$C" /api/v1/cluster | jq '.members | length')" = "3" ] && ok "node-c sees three members" || ko "three members"

echo "6. Cluster-wide transfer history..."
# a loopback transfer on node-a, then check node-b's aggregated view sees it
h "$A" /api/v1/config/files -X POST -d '{"id":"CLFILE","enabled":true,"direction":"RECEIVE","receiveDirectory":"/data/received","receiveFilenamePattern":"cl_${transferId}","overwrite":true,"recordLength":4096,"recordFormat":128}' >/dev/null
h "$A" /api/v1/servers -X POST -d '{"serverId":"LOOP","port":5052,"receiveDirectory":"/data/received","sendDirectory":"/data/send","maxEntitySize":32768,"syncPointsEnabled":true,"autoStart":true}' >/dev/null
h "$A" /api/v1/config/partners -X POST -d '{"id":"node-a","enabled":true,"accessType":"BOTH"}' >/dev/null
sleep 1
curl -s -H 'Content-Type: application/json' -X POST http://localhost:8090/client/api/v1/servers -d '{"name":"self","host":"127.0.0.1","port":5052,"serverId":"LOOP","enabled":true}' >/dev/null
docker exec node-a sh -c 'head -c 100000 /dev/urandom > /data/send/clx.dat' 2>/dev/null
TID=$(curl -s -H 'Content-Type: application/json' -X POST http://localhost:8090/client/api/v1/transfers/send -d '{"server":"self","partnerId":"node-a","filename":"/data/send/clx.dat","remoteFilename":"CLFILE"}' | jq -r '.transferId // .id')
for i in $(seq 1 40); do ST=$(curl -s http://localhost:8090/client/api/v1/transfers/$TID | jq -r .status); [ "$ST" = COMPLETED -o "$ST" = FAILED ] && break; sleep 0.5; done
echo "   loopback on node-a: $ST"
FOUND=0; for i in $(seq 1 20); do h "$B" /api/v1/cluster/transfers | jq -e '.[] | select(.node=="node-a")' >/dev/null 2>&1 && { FOUND=1; break; }; sleep 0.5; done
[ "$FOUND" = 1 ] && ok "node-a's transfer visible in node-b's cluster-wide history" || ko "cluster-wide transfer aggregation"

echo "7. Deletion propagates..."
h "$A" /api/v1/config/partners/CLUSTER_A -X DELETE >/dev/null
for i in $(seq 1 30); do has_partner "$B" "CLUSTER_A" || break; sleep 0.5; done
has_partner "$B" "CLUSTER_A" && ko "deletion propagation" || ok "deletion on node-a propagated to node-b"

echo "=========================================="
echo "  Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ $FAILED -eq 0 ]
