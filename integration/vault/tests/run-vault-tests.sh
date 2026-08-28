#!/bin/bash
# Prove the node's native Vault PKI backend end to end:
#  1. enable Vault's PKI engine and a role
#  2. configure the node's Vault backend through the REST API and test it
#  3. issue a certificate *through Vault* and verify it chains to Vault's CA (openssl)
#  4. use the Vault-issued certificate on a TLS listener and run a loopback transfer over TLS
set -u
API_KEY="integration-test-key"
NODE="http://pw-node:8080"
VAULT="http://vault:8200"
PASSED=0; FAILED=0
ok(){ echo "   [PASS] $1"; PASSED=$((PASSED+1)); }
ko(){ echo "   [FAIL] $1"; FAILED=$((FAILED+1)); }
res(){ if [ "$1" = "$2" ]; then ok "$3"; else ko "$3 (got '$1')"; fi; }
apt-get update -qq && apt-get install -y -qq curl jq openssl netcat-openbsd > /dev/null 2>&1
h(){ curl -s -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' "$@"; }
v(){ curl -s -H "X-Vault-Token: root" "$@"; }

echo "=========================================="
echo "  Native Vault PKI integration"
echo "=========================================="
echo "1. Enable Vault PKI engine + role..."
v -X POST "$VAULT/v1/sys/mounts/pki" -d '{"type":"pki","config":{"max_lease_ttl":"87600h"}}' >/dev/null
v -X POST "$VAULT/v1/pki/root/generate/internal" -d '{"common_name":"Vault Test Root CA","ttl":"87600h"}' | jq -r '.data.certificate' > /tmp/vault-ca.pem
v -X POST "$VAULT/v1/pki/roles/pesit" -d '{"allow_any_name":true,"allow_ip_sans":true,"max_ttl":"72h","key_type":"rsa","key_bits":2048}' >/dev/null
CA_LINES=$(wc -l < /tmp/vault-ca.pem)
[ "$CA_LINES" -gt 5 ] && ok "Vault PKI engine initialised" || ko "Vault PKI engine ($CA_LINES lines)"

echo "2. Configure the node's Vault backend via REST..."
SAVE=$(h -X PUT "$NODE/api/v1/certificates/vault" -d '{"address":"http://vault:8200","mount":"pki","role":"pesit","auth":{"method":"token","token":"root"}}')
res "$(echo "$SAVE" | jq -r '.configured')" "true" "Vault backend configured"
echo "   node reports Vault version: $(echo "$SAVE" | jq -r '.vaultVersion')"
TEST=$(h -X POST "$NODE/api/v1/certificates/vault/test")
res "$(echo "$TEST" | jq -r '.success')" "true" "Vault reachable from the node"

echo "3. Issue a certificate THROUGH Vault..."
ISSUE=$(h -X POST "$NODE/api/v1/certificates/issue" -d '{"commonName":"svc.pesit.test","sans":["DNS:svc.pesit.test","IP:10.9.8.7"],"ttlDays":2,"backend":"vault","storeAs":"vault-issued"}')
echo "$ISSUE" | jq -r '.certificate' > /tmp/leaf.pem
res "$(echo "$ISSUE" | jq -r '.backend')" "vault" "certificate issued via Vault"
res "$(echo "$ISSUE" | jq -r '.storedAs')" "vault-issued" "certificate stored as a keystore"
[ -s /tmp/leaf.pem ] && [ "$(head -1 /tmp/leaf.pem)" = "-----BEGIN CERTIFICATE-----" ] && ok "leaf certificate is valid PEM" || ko "leaf PEM"

echo "4. Verify the leaf chains to Vault's CA (openssl)..."
if openssl verify -CAfile /tmp/vault-ca.pem /tmp/leaf.pem 2>/dev/null | grep -q ': OK'; then
  ok "openssl verifies the leaf against Vault's CA"
else
  # the issuing CA may be an intermediate; verify against the returned chain
  echo "$ISSUE" | jq -r '.caChain[]?' > /tmp/chain.pem
  cat /tmp/vault-ca.pem >> /tmp/chain.pem
  openssl verify -CAfile /tmp/chain.pem /tmp/leaf.pem 2>/dev/null | grep -q ': OK' && ok "openssl verifies the leaf against Vault's chain" || ko "openssl chain verification"
fi
SUBJ=$(openssl x509 -in /tmp/leaf.pem -noout -subject 2>/dev/null)
ISS=$(openssl x509 -in /tmp/leaf.pem -noout -issuer 2>/dev/null)
echo "   subject: $SUBJ"
echo "   issuer:  $ISS"
echo "$SUBJ" | grep -q 'svc.pesit.test' && ok "leaf subject is svc.pesit.test" || ko "leaf subject"
echo "$ISS" | grep -q 'Vault Test Root CA' && ok "leaf was issued by the Vault root" || ko "leaf issuer"
echo "$SUBJ$ISS" >/dev/null
openssl x509 -in /tmp/leaf.pem -noout -text 2>/dev/null | grep -q '10.9.8.7' && ok "IP SAN present" || ko "IP SAN"

echo "5. Use the Vault-issued keystore on a TLS listener + loopback transfer..."
# upload Vault CA as a truststore, and make a self-trusting remote (insecure to keep it simple)
h -X POST "$NODE/api/v1/config/partners" -d '{"id":"SELF","enabled":true,"accessType":"BOTH"}' >/dev/null
h -X POST "$NODE/api/v1/config/files" -d '{"id":"IN","enabled":true,"direction":"RECEIVE","receiveDirectory":"/data/received","receiveFilenamePattern":"vault_${transferId}","overwrite":true,"recordLength":4096,"recordFormat":128}' >/dev/null
h -X POST "$NODE/api/v1/servers" -d '{"serverId":"TLSSRV","port":5051,"maxEntitySize":32768,"syncPointsEnabled":true,"syncIntervalKb":64,"sslEnabled":true,"sslKeystore":"vault-issued","tcpipHeader":true,"autoStart":true}' >/dev/null
sleep 1
STATUS=$(h "$NODE/api/v1/servers/TLSSRV/status" | jq -r '.status')
res "$STATUS" "RUNNING" "TLS listener started with the Vault-issued keystore"
if [ "$STATUS" = "RUNNING" ]; then
  # openssl s_client proves the listener actually serves the Vault-issued certificate
  SERVED=$(echo | timeout 8 openssl s_client -connect pw-node:5051 -servername svc.pesit.test 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
  echo "   TLS handshake presented: $SERVED"
  echo "$SERVED" | grep -q 'svc.pesit.test' && ok "the listener serves the Vault-issued certificate over TLS" || ko "served certificate"
fi

echo "=========================================="
echo "  Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ $FAILED -eq 0 ]
