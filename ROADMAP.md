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
- Later: certificate rotation, an OCSP responder.

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
- Later: transfer-record replication / cluster-wide history, and work distribution for scheduled
  transfers driven by the leader.

## Related

- Update the project website: remove the commercial/enterprise messaging, position PeSIT Wizard as
  fully open source.
