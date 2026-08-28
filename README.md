# PeSIT Wizard (Rust)

A from-scratch Rust implementation of the PeSIT E (Hors-SIT profile) file transfer protocol, and a
single **`pesitwizard`** node that both listens for incoming transfers and initiates outgoing ones,
with a web UI. Written from the PeSIT E protocol specification and the Java PeSIT Wizard code base,
and validated for interoperability with IBM Sterling Connect:Express (see [docs/](docs/)).

Fully open source — there is no separate commercial edition.

| Crate | Purpose |
|-------|---------|
| `pesit-core` | Protocol model: FPDU encode/decode, parameters (PI/PGI), diagnostics, CRC, compression, articles, the protocol state tables |
| `pesit-io` | Async session engines on tokio: transport framing (TCP / TLS, with or without transport header), pre-connection, requester and responder sessions, data phase with sync points / restart / resync / interruption |
| `pesit-app` | Shared plumbing (SQLite JSON store, REST helpers) |
| `pesit-client` | Library: the outbound transfer engine, its REST API and DTOs |
| `pesit-pki` | Certificate & CA management: X.509 inspection, a local CA (`rcgen`) and a native HashiCorp Vault PKI backend |
| `pesit-cluster` | Clustering over NATS / JetStream: membership, leader election and configuration replication |
| `pesit-node` | The `pesitwizard` binary: listeners + outbound engine + REST APIs + web UI, sharing one store |

## Build & verify

```bash
cargo build --release --workspace     # binary at target/release/pesitwizard
make verify                           # fmt (nightly) + clippy -D warnings + tests
make e2e                              # local end-to-end run through the REST APIs
make ui-test                          # Playwright end-to-end tests of the web UI
make docker-test                      # Connect:Express integration tests (docker compose)
make docker-test-tls                  # Connect:Express TLS integration tests
```

## The node

```bash
PESIT_API_KEY=secret pesitwizard        # runs the node (default subcommand: serve)
```

One process exposes two REST surfaces backed by the same store, plus the web UI:

* **Admin API** on `--api-port` (default 8080, `X-API-Key`): partners, virtual files, listeners
  (`/api/v1/servers` + `/start|/stop|/status`), inbound transfer records, and the **web UI at `/`**.
  The transfer API is also mounted here under `/client` for the UI.
* **Transfer API** on `--transfer-port` (default 9081): remote servers (`/api/v1/servers`),
  `/api/v1/transfers/send|receive|message`, outbound history, `/{id}/cancel|retry`.

Selected environment / flags: `PESIT_API_PORT`, `PESIT_TRANSFER_PORT`, `PESIT_API_KEY` (unset = no
auth), `PESIT_DB`, `PESIT_CHECKPOINT_DIR`, `PESIT_CLIENT_CHECKPOINT_DIR`, `PESIT_CLIENT_RECEIVE_DIR`,
`PESIT_CONFIG` (YAML bootstrap: `partners`, `files`, `remotePartners`, `servers`), `PESIT_NODE_ID`,
`PESIT_CLIENT_ID`; listener TLS `PESIT_SSL_ENABLED`/`PESIT_SSL_CERT_PATH`/`PESIT_SSL_KEY_PATH`/
`PESIT_SSL_CA_CERT_PATH`/`PESIT_SSL_CLIENT_AUTH`/`PESIT_SSL_PROTOCOL`; outbound TLS
`PESIT_CLIENT_SSL_CA_CERT_PATH`/`PESIT_CLIENT_SSL_CERT_PATH`/`PESIT_CLIENT_SSL_KEY_PATH`/
`PESIT_CLIENT_SSL_INSECURE`; `RUST_LOG`.

Listeners are created through the admin API and may be flagged `autoStart`. Options beyond the Java
ones: `syncWindow` (ACK(SYN) window, 0 = no acknowledgement), `sslEnabled`, `tcpipHeader` (transport
header on TLS connections, Connect:Express `TCPIP_HEADER`), `compression` (0–3). Virtual files accept
`text: true` for line records (LF stripped / appended) instead of binary chunks; partners accept
`preconnectPassword` for Connect:Express partners of type T/O.

### One-shot CLI

```bash
pesitwizard send    --host cx --port 5000 --server-id CETOM1 --partner PWSRV01 file.dat --remote PWRECV
pesitwizard receive --host cx --port 5000 --server-id CETOM1 --partner PWSRV01 PWSEND --file out.dat
pesitwizard message --host cx --port 5000 --server-id CETOM1 --partner PWSRV01 "hello" --reply
```

### Transfers

Requests accept the Java fields (`server`, `partnerId`, `password`, `filename`, `remoteFilename`,
`syncPointsEnabled`, `syncPointInterval`, `resyncEnabled`, `resumeFromTransferId`, `recordLength`,
`correlationId`) plus `compressionEnabled`, `crcEnabled`, `text`, `maxEntitySize`.
`POST /api/v1/transfers/{id}/retry` restarts an interrupted transfer from its last checkpoint;
if the peer refuses the restart, the client transparently falls back to a full retransfer.

Received files are written to `<name>.part` and renamed on completion; synchronisation checkpoints
are persisted so an interrupted transfer can be restarted, the server answering the restart point in
`ACK(WRITE)`. TLS truststores are PEM CA bundles (`POST /api/v1/servers/{id}/tls/truststore`,
multipart `file`); PKCS#12 stores are not supported — convert them with `openssl pkcs12`.

## Documentation

* [docs/architecture.md](docs/architecture.md) — design of the crates and of the session engines
* [docs/protocol-reference.md](docs/protocol-reference.md) — PeSIT E reference from the specification
* [docs/ui.md](docs/ui.md) — the web UI
* [docs/certificates.md](docs/certificates.md) — certificate / CA management and the native Vault PKI backend
* [docs/clustering.md](docs/clustering.md) — NATS / JetStream clustering
* [docs/gap-analysis.md](docs/gap-analysis.md) — gaps of the Java implementation and how this addresses them
* [ROADMAP.md](ROADMAP.md) — planned capabilities (certificate/CA + Vault, audit, backup/restore, clustering)
