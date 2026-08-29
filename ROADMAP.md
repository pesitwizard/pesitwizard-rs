# Roadmap

PeSIT Wizard is being consolidated into a **single open-source `pesitwizard` node** — no commercial
edition, no license gating. The core (protocol, listeners, outbound engine, REST APIs, web UI) is in
place. The capabilities below carry the worthwhile parts of the former "enterprise" modules into the
one binary, as plain features (config-toggled where relevant), and drop the rest.

## Delivered

- Single node: listen + initiate in one process, shared config store, two REST surfaces, web UI.
- PeSIT E: CRC, compression, multi-article DTF, segmentation, synchronisation points with window,
  restart / resynchronisation, clean cancellation, text/binary record formats, TLS (with/without
  transport header), pre-connection.
- Web UI (dashboard, listeners, partners, virtual files, remote servers, send/receive/message,
  transfers) with Playwright end-to-end tests.
- Connect:Express interoperability (Docker): transfers both ways, sync points, restart, TLS.
- **Certificate / CA management with native HashiCorp Vault support** (see below).
- **Audit log** and **configuration backup / restore** (see below).
- **Clustering / HA** over NATS + JetStream (see below).
- **Storage connectors** (S3, SFTP, local) that back virtual files (see below).

## Dropped (no value for a never-commercialised product)

- License management and the license-admin tool.
- The OSS / enterprise split itself: everything is open source, in one binary.

## Planned

### 1. Certificate / CA management with native HashiCorp Vault support — *done*

Replaces the enterprise `pki` + admin CA/certificate features. See
[docs/certificates.md](docs/certificates.md).

- Certificate store: keystores (TLS identity) and truststores (CA bundles), with inspection
  (subject, issuer, SAN, validity, fingerprint) via `x509-parser`. ✔
- Local CA: generate a CA and issue partner / server certificates via `rcgen`. ✔
- **Native Vault PKI backend**: issue and sign through Vault's PKI secrets engine (token / AppRole),
  configurable per node via `reqwest`. ✔
- Managed keystores / truststores wired into the listener TLS layer; REST + web UI tab. ✔
- Certificate rotation: `POST /api/v1/certificates/keystores/{name}/rotate` re-issues a managed
  keystore in place (same identity, recorded backend), and a leader-driven task auto-rotates
  keystores within `PESIT_CERT_ROTATION_DAYS` of expiry. ✔
- Revocation: `POST /api/v1/certificates/revoked` revokes a serial and `GET /api/v1/certificates/crl`
  returns a CRL signed by the local CA. ✔
- **Online OCSP responder** (RFC 6960) at `/ocsp` (POST and GET, unauthenticated): answers the
  revocation status of certificates issued by the local CA, signed by the CA key. Validated with
  `openssl ocsp` (`Response verify OK`, `good` → `revoked` after revocation). ✔

### 2. Audit log — *done*

- Append-only audit of configuration changes, listener start/stop, certificate / Vault operations
  and transfer outcomes, queryable via `/api/v1/audit` and the **System** web UI tab. Backed by the
  shared store. ✔ (retention policy: later.)

### 3. Backup / restore — *done*

- Export the whole configuration (partners, virtual files, listeners, remote servers, Vault config
  and certificate material) as a JSON bundle and import it back — `/api/v1/backup` and the System
  web UI tab. ✔ (bundle signing / a CLI subcommand: later.)

### 4. Clustering / HA — via NATS + JetStream — *done (v1)*

Replaces the enterprise JGroups cluster module with a Rust-native design (`async-nats`), in the
`pesit-cluster` crate.

- Node membership via a JetStream KV bucket with a TTL heartbeat; `/api/v1/cluster` and a **Cluster**
  web UI tab. ✔
- Leader election via a KV lease (create-to-acquire, renew, TTL failover). ✔
- Shared-policy configuration (partners, virtual files, remote partners) replicated live over NATS;
  a joining node catches up by requesting a full snapshot from a peer. ✔
- Cluster-wide transfer history: `GET /api/v1/cluster/transfers` aggregates every member's records
  (shown in the Cluster web UI tab). ✔
- **Scheduled transfers** driven by the leader: recurring send / receive jobs (`/api/v1/schedules`,
  Schedules web UI tab) fired only on the cluster leader so each job runs once. Each job runs on a
  fixed interval or a **cron expression** (5, 6 or 7 fields; `cron` field / UI input). ✔
- Later: richer work distribution across the cluster.

### 5. Storage connectors — *done*

A virtual file can be backed by an external storage system instead of the local filesystem, in the
`pesit-connector` crate.

- Connector types: **S3** (any S3-compatible object store — AWS S3, MinIO, …, via `aws-sdk-s3`),
  **SFTP** (`russh` / `russh-sftp`) and **local** directory. Managed at `/api/v1/config/connectors`
  and the **Connectors** web UI tab, with a `POST .../{id}/test` reachability check. ✔
- A virtual file references a connector by id plus a target path template (`connectorPath`, e.g.
  `incoming/${transferId}.dat`). On a *receive*, the file is staged locally then uploaded to the
  connector when the transfer completes; on a *send*, it is fetched from the connector into a staging
  file and streamed to the partner. Staging files are cleaned up on completion or failure. ✔
- Connector definitions are included in configuration backup / restore. Secrets stay node-local
  (connectors are not replicated across the cluster). ✔
- Validated end to end against **MinIO** (`integration/s3/`): a received file lands in the bucket and
  is read back from it with a matching checksum. ✔
- Later: streaming without a staging file, and per-connector retry / bandwidth policy.

## Related

- Update the project website: remove the commercial/enterprise messaging, position PeSIT Wizard as
  fully open source.
