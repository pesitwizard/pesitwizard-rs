#!/bin/bash
# TLS interoperability tests between the Rust PeSIT Wizard and Connect:Express.
#  1. PW client -> CX over TLS (SSLPARM1, server mode, TCPIP_HEADER=N), CA uploaded through the API
#  2. CX -> PW server over TLS (SSLPARM2, client mode) using the CX trigger watcher
set -u
API_KEY="integration-test-key"
PW_SERVER_API="http://pw-server:8080"
PW_CLIENT_API="http://pw-client:9081"
PASSED=0; FAILED=0
result() { if [ "$2" = "pass" ]; then echo "   [PASS] $1"; PASSED=$((PASSED + 1)); else echo "   [FAIL] $1"; FAILED=$((FAILED + 1)); fi; }
apt-get update -qq && apt-get install -y -qq curl jq > /dev/null 2>&1
h() { curl -s -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" "$@"; }
c() { curl -s -H "Content-Type: application/json" "$@"; }
wait_done() {
    for i in $(seq 1 150); do
        ST=$(c "$PW_CLIENT_API/api/v1/transfers/$1" | jq -r .status)
        case "$ST" in COMPLETED|FAILED|CANCELLED|INTERRUPTED) break ;; esac
        sleep 2
    done
    c "$PW_CLIENT_API/api/v1/transfers/$1"
}

echo "=========================================="
echo "  Rust PeSIT Wizard <-> Connect:Express TLS"
echo "=========================================="
sleep 5
echo "1. Configuring PW server (TLS listener on 5001, no transport header)..."
h -X POST "$PW_SERVER_API/api/v1/config/partners" -d '{"id":"PWSRV01","description":"CX","enabled":true,"accessType":"BOTH"}' > /dev/null
h -X POST "$PW_SERVER_API/api/v1/config/files" -d '{"id":"PWSEND","enabled":true,"direction":"RECEIVE","receiveDirectory":"/data/received","receiveFilenamePattern":"from_cx_tls_${transferId}","overwrite":true,"recordLength":4096,"recordFormat":128}' > /dev/null
h -X POST "$PW_SERVER_API/api/v1/servers" -d '{"serverId":"PWSERVER","port":5001,"maxEntitySize":32768,"syncPointsEnabled":true,"syncIntervalKb":256,"sslEnabled":true,"tcpipHeader":false,"autoStart":true}' > /dev/null
sleep 1
STATUS=$(h "$PW_SERVER_API/api/v1/servers/PWSERVER/status" | jq -r .status)
[ "$STATUS" = "RUNNING" ] && result "TLS listener started" pass || result "TLS listener started ($STATUS)" fail

echo "2. Configuring PW client (cx-server-tls:5001, TLS, no transport header)..."
SRV=$(c -X POST "$PW_CLIENT_API/api/v1/servers" -d '{"name":"cx-server-tls","host":"cx-server-tls","port":5001,"serverId":"CETOM1","tlsEnabled":true,"tcpipHeader":false,"hostnameVerification":true,"connectionTimeout":30000,"readTimeout":120000,"enabled":true,"defaultServer":true}')
SERVER_ID=$(echo "$SRV" | jq -r .id)
UPLOAD=$(curl -s -X POST "$PW_CLIENT_API/api/v1/servers/$SERVER_ID/tls/truststore" -F "file=@/certs/ca-cert.pem" -F "password=")
[ "$(echo "$UPLOAD" | jq -r .success)" = "true" ] && result "CA certificate uploaded" pass || result "CA certificate uploaded ($UPLOAD)" fail
P12=$(curl -s -X POST "$PW_CLIENT_API/api/v1/servers/$SERVER_ID/tls/truststore" -F "file=@/certs/ca-truststore.p12" -F "password=changeit")
[ "$(echo "$P12" | jq -r .success)" = "false" ] && result "PKCS#12 upload rejected with an explanation" pass || result "PKCS#12 upload handling" fail

echo "3. PW client -> CX over TLS..."
dd if=/dev/urandom of=/tmp/pw-client-send/tls_test.dat bs=1M count=2 2>/dev/null
MD5=$(md5sum /tmp/pw-client-send/tls_test.dat | awk '{print $1}')
T=$(c -X POST "$PW_CLIENT_API/api/v1/transfers/send" -d '{"server":"cx-server-tls","partnerId":"PWSRV01","filename":"/data/send/tls_test.dat","remoteFilename":"PWRECV","syncPointsEnabled":true}' | jq -r .transferId)
R=$(wait_done "$T")
echo "   status: $(echo "$R" | jq -c '{status,bytesTransferred,lastSyncPoint,errorMessage,diagnosticCode}')"
[ "$(echo "$R" | jq -r .status)" = "COMPLETED" ] && result "2 MB sent to CX over TLS" pass || result "2 MB sent to CX over TLS" fail
FOUND=""
for f in /tmp/cx-received/*; do [ -f "$f" ] && [ "$(md5sum "$f" | awk '{print $1}')" = "$MD5" ] && FOUND="$f"; done
[ -n "$FOUND" ] && result "file on CX matches MD5 ($FOUND)" pass || result "file on CX matches MD5" fail

echo "4. CX -> PW server over TLS (trigger watcher)..."
dd if=/dev/urandom of=/tmp/cx-send/cx_tls_test.dat bs=1M count=2 2>/dev/null
MD5CX=$(md5sum /tmp/cx-send/cx_tls_test.dat | awk '{print $1}')
rm -f /tmp/cx-send/.transfer_log /tmp/cx-send/.transfer_exitcode
printf 'SEND_FILE=/tmp/cx-send/cx_tls_test.dat\nLOGICAL_FILE=PWSEND\n' > /tmp/cx-send/.trigger
for i in $(seq 1 60); do [ -f /tmp/cx-send/.transfer_exitcode ] && break; sleep 2; done
echo "   p1b8preq exit code: $(cat /tmp/cx-send/.transfer_exitcode 2>/dev/null || echo none)"
RECEIVED=""
for i in $(seq 1 60); do
    for f in /tmp/pw-received/from_cx_tls_*; do [ -f "$f" ] && [ "$(md5sum "$f" | awk '{print $1}')" = "$MD5CX" ] && RECEIVED="$f"; done
    [ -n "$RECEIVED" ] && break
    sleep 2
done
[ -n "$RECEIVED" ] && result "2 MB received from CX over TLS ($RECEIVED)" pass || result "2 MB received from CX over TLS" fail
echo "   server records: $(h "$PW_SERVER_API/api/v1/transfers?limit=3" | jq -c '.[] | {status,bytesTransferred,partnerId,lastSyncPoint}')"

echo "=========================================="
echo "  Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ $FAILED -eq 0 ]
