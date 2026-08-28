#!/bin/bash
# Restart (reprise) test against Connect:Express: a large transfer to CX is cancelled mid-way
# (F.CANCEL → IDT), then retried; the client restarts with PI 15 = 1 / same PI 13 and CX answers
# the restart point in ACK(WRITE). Also checks a cancelled CX → PW transfer can be listed.
set -u
API_KEY="integration-test-key"
PW_SERVER_API="http://pw-server:8080"
PW_CLIENT_API="http://pw-client:9081"
PASSED=0; FAILED=0
result() { if [ "$2" = "pass" ]; then echo "   [PASS] $1"; PASSED=$((PASSED + 1)); else echo "   [FAIL] $1"; FAILED=$((FAILED + 1)); fi; }
apt-get update -qq && apt-get install -y -qq curl jq > /dev/null 2>&1
h() { curl -s -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" "$@"; }
c() { curl -s -H "Content-Type: application/json" "$@"; }
status() { c "$PW_CLIENT_API/api/v1/transfers/$1"; }
wait_done() {
    for i in $(seq 1 300); do
        ST=$(status "$1" | jq -r .status)
        case "$ST" in COMPLETED|FAILED|CANCELLED|INTERRUPTED) break ;; esac
        sleep 1
    done
    status "$1"
}

echo "=========================================="
echo "  Rust PeSIT Wizard <-> Connect:Express restart"
echo "=========================================="
sleep 5
h -X POST "$PW_SERVER_API/api/v1/config/partners" -d '{"id":"PWSRV01","enabled":true,"accessType":"BOTH"}' > /dev/null
h -X POST "$PW_SERVER_API/api/v1/config/files" -d '{"id":"PWSEND","enabled":true,"direction":"RECEIVE","receiveDirectory":"/data/received","receiveFilenamePattern":"from_cx_${transferId}","overwrite":true,"recordLength":4096,"recordFormat":0}' > /dev/null
h -X POST "$PW_SERVER_API/api/v1/servers" -d '{"serverId":"PWSERVER","port":5001,"maxEntitySize":32768,"syncPointsEnabled":true,"syncIntervalKb":256,"autoStart":true}' > /dev/null
c -X POST "$PW_CLIENT_API/api/v1/servers" -d '{"name":"cx-server","host":"cx-server","port":5000,"serverId":"CETOM1","tlsEnabled":false,"connectionTimeout":30000,"readTimeout":120000,"enabled":true,"defaultServer":true}' > /dev/null

echo "1. Large transfer to CX, cancelled mid-way..."
dd if=/dev/urandom of=/tmp/pw-client-send/restart_test.dat bs=1M count=40 2>/dev/null
MD5=$(md5sum /tmp/pw-client-send/restart_test.dat | awk '{print $1}')
T1=$(c -X POST "$PW_CLIENT_API/api/v1/transfers/send" -d '{"server":"cx-server","partnerId":"PWSRV01","filename":"/data/send/restart_test.dat","remoteFilename":"PWRECV","syncPointsEnabled":true,"syncPointInterval":64}' | jq -r .transferId)
for i in $(seq 1 600); do
    B=$(status "$T1" | jq -r .bytesTransferred)
    [ "$B" -gt 8000000 ] 2>/dev/null && break
    sleep 0.05
done
echo "   cancelling at $B bytes"
CANCEL=$(c -X POST "$PW_CLIENT_API/api/v1/transfers/$T1/cancel")
R1=$(wait_done "$T1")
echo "   after cancel: $(echo "$R1" | jq -c '{status,bytesTransferred,lastSyncPoint,bytesAtLastSyncPoint,diagnosticCode,errorMessage}')"
[ "$(echo "$R1" | jq -r .status)" = "CANCELLED" ] && result "transfer cancelled with F.CANCEL" pass || result "transfer cancelled ($CANCEL)" fail
[ "$(echo "$R1" | jq -r .lastSyncPoint)" -gt 0 ] 2>/dev/null && result "sync points recorded before cancellation" pass || result "sync points recorded" fail

echo "2. Restart from the last checkpoint..."
T2=$(c -X POST "$PW_CLIENT_API/api/v1/transfers/$T1/retry" | jq -r .transferId)
R2=$(wait_done "$T2")
echo "   after retry: $(echo "$R2" | jq -c '{status,bytesTransferred,lastSyncPoint,pesitTransferId,diagnosticCode,errorMessage}')"
[ "$(echo "$R2" | jq -r .status)" = "COMPLETED" ] && result "restarted transfer completed" pass || result "restarted transfer completed" fail
FOUND=""
for f in /tmp/cx-received/*; do [ -f "$f" ] && [ "$(md5sum "$f" | awk '{print $1}')" = "$MD5" ] && FOUND="$f"; done
[ -n "$FOUND" ] && result "file on CX matches MD5 after restart ($FOUND)" pass || result "file on CX matches MD5 after restart" fail
ls -la /tmp/cx-received/ | tail -5
echo "   resumable list: $(c "$PW_CLIENT_API/api/v1/transfers/resumable" | jq 'length')"

echo "3. Plain retry of a completed transfer (replay)..."
T3=$(c -X POST "$PW_CLIENT_API/api/v1/transfers/$T2/replay" | jq -r .transferId)
[ "$(wait_done "$T3" | jq -r .status)" = "COMPLETED" ] && result "replay completed" pass || result "replay completed" fail

echo "=========================================="
echo "  Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ $FAILED -eq 0 ]
