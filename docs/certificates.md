# Certificate & CA management

The node manages TLS material itself: an on-disk **certificate store**, an optional **local CA**, and
a native **HashiCorp Vault PKI** backend. Implemented in the `pesit-pki` crate and exposed under
`/api/v1/certificates` (admin API, `X-API-Key`) and in the **Certificates** tab of the web UI.
Material lives under `--pki-dir` (default `/data/pki`); private keys are written `0600`.

## Store

* **Keystores** — a certificate plus its private key, used as a TLS identity. `POST
  /api/v1/certificates/keystores` (`name`, `certificate`, `privateKey` PEM) to import;
  `GET`/`DELETE .../keystores/{name}`.
* **Truststores** — a bundle of CA certificates used to verify peers. `POST
  /api/v1/certificates/truststores` (`name`, `certificates` PEM bundle); `GET`/`DELETE`.
* `POST /api/v1/certificates/inspect` (`{pem}`) returns subject, issuer, serial, validity, SANs, CA
  flag and SHA-256 fingerprint for any PEM.

## Local CA

`POST /api/v1/certificates/ca` (`commonName`, `organization?`, `ttlDays?`) generates a self-signed CA
(kept as `ca.crt.pem` / `ca.key.pem` under the PKI directory). `GET /api/v1/certificates/ca` returns
it. Certificates are then issued from it (see below).

## Native Vault PKI backend

`PUT /api/v1/certificates/vault` configures the backend and verifies it (`GET`/`DELETE` to read /
clear, `POST .../vault/test` to re-check):

```json
{
  "address": "https://vault.example.com:8200",
  "mount": "pki",
  "role": "pesit",
  "auth": { "method": "token", "token": "s.xxxxx" },
  "namespace": "team-a",
  "caPem": "-----BEGIN CERTIFICATE----- …",
  "insecure": false
}
```

Authentication is either a fixed `token` or `appRole` (`{ "method": "appRole", "roleId": "...",
"secretId": "...", "mount": "approle" }` — a token is fetched and cached). `caPem` trusts a private
CA for the TLS connection to Vault; `namespace` targets a Vault Enterprise namespace.

## Issuing

`POST /api/v1/certificates/issue`:

```json
{ "commonName": "node.example.com", "sans": ["DNS:node.example.com", "IP:10.0.0.5"],
  "ttlDays": 365, "serverAuth": true, "clientAuth": true,
  "backend": "local", "storeAs": "node-tls" }
```

`backend` is `local` (the local CA, via `rcgen`) or `vault` (Vault's `pki/issue/<role>`). With
`storeAs`, the issued certificate and key are saved as a keystore ready for a listener.

## Using managed material for TLS

A listener may reference managed material instead of file paths:

```json
{ "serverId": "SECURE", "port": 5051, "sslEnabled": true,
  "sslKeystore": "node-tls", "sslTruststore": "partner-cas" }
```

`sslKeystore` provides the listener's certificate and key; `sslTruststore` verifies client
certificates. Remote servers accept an uploaded CA truststore through
`POST /api/v1/servers/{id}/tls/truststore`.

## Rotation and revocation

`POST /api/v1/certificates/keystores/{name}/rotate` re-issues a managed keystore in place, keeping its
common name and SANs and using the backend it was issued with (local CA or Vault). Set
`PESIT_CERT_ROTATION_DAYS` to have a background task (leader-driven in a cluster) auto-rotate keystores
that expire within that many days.

`POST /api/v1/certificates/revoked` (`{"serial":"1a:2b:…"}`) revokes a certificate serial;
`GET /api/v1/certificates/revoked` lists them and `GET /api/v1/certificates/crl` returns a CRL (PEM)
signed by the local CA. The Certificates tab exposes a Rotate button per keystore and a revocation
panel with a CRL download.

## Integration test

`make vault-test` runs an end-to-end test against a dev-mode Vault in Docker: it enables Vault's PKI
engine and a role, configures the node's Vault backend through the REST API, issues a certificate
*through Vault*, verifies with `openssl` that the leaf chains to Vault's CA, then starts a TLS
listener using the Vault-issued keystore and checks the TLS handshake serves that certificate.
