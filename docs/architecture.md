# Architecture

## Crates

```
pesit-core      protocol model (no I/O)         pesit-io        tokio session engines
pesit-app       SQLite JSON store + REST utils  pesit-client    outbound engine (library)
pesit-pki       X.509 / local CA / Vault PKI,   pesit-cluster   NATS/JetStream membership,
                OCSP, backup signing                            leader election, replication
pesit-connector S3 / SFTP / local staging       pesit-node      the `pesitwizard` binary
pesit-node      listeners + outbound engine + REST APIs + web UI, wiring the crates above
```

The node is a single process. It runs the listener manager and the outbound transfer engine over
one shared store, and exposes two REST surfaces (admin on `--api-port`, transfer on
`--transfer-port`) plus a web UI. The transfer API is also mounted under `/client` on the admin port
so the single-origin UI can reach both. There is no separate client or server binary, and no
commercial edition.

### pesit-core

* `pi` — the parameter catalogue (`Pi` enum with type, maximum length, name) and the parameter groups
  (`Pgi` 9/30/40/50 with their members).
* `fpdu` — `FpduKind` (phase byte + type byte, canonical parameter template per FPDU, taken from the
  Connect:Express parse tables), `Fpdu` (header ids, sorted parameters, data) with strict decoding
  (ascending codes, LI ≠ 0, template, maximum lengths) mapped to the D3-318 / D3-311 diagnostics.
* `params` — typed views of the negotiated parameters: `SyncOption` (PI 7), `Compression` (PI 21),
  `AccessType` (PI 22), `Version`, `RequestedAttributes`, `EndCode` (PI 19) and their negotiation rules.
* `diag` — the complete diagnostic list (PI 2) with descriptions.
* `crc` — the ISO 8073 check bytes appended to each FPDU when PI 1 = 1 (verified against the C:X
  Connect:Express).
* `compress` — PeSIT compression (horizontal / vertical / mixed, 63-byte chunks, reference article).
* `article` — record formats (BU/BF/BV/TV/TF), article cutting, multi-article DTF packing, segmentation
  (DTFDA/DTFMA/DTFFA) and reassembly.
* `state` — the 54-state protocol automaton, with the
  received / local events and the ignore rules; both roles use the same table.
* `builder` — constructors for every FPDU (`ConnectParams`, `FileSpec`, `syn`, `resyn`, `idt`, ...).
* `frame` — entity building (concatenation of DTF*/DTF.END/SYN up to PI 25) and splitting.
* `ebcdic` — CP037 tables and the 24-byte pre-connection message / ACK0 / NAK0.

### pesit-io

* `transport` — framing over any `AsyncRead + AsyncWrite`: `LengthPrefixed` (2-byte header, TCP or
  TLS with `TCPIP_HEADER=Y`) or `Raw` (TLS with `TCPIP_HEADER=N`, FPDUs delimited by their own length,
  CRC detected from PI 1 of the CONNECT). The first read recognises a pre-connection message.
* `link` — full-duplex link: a background task reads entities into a queue so that a sender can poll
  for asynchronous FPDUs (ACK(SYN), RESYN, IDT, ABORT) while it streams data.
* `datapath` — the data phase shared by both roles: `send_data` (article packing, synchronisation
  points every *n* KB, acknowledgement window, RESYN/IDT handling, cancellation) and `receive_data`
  (reassembly, decompression, checkpoints on SYN, ACK(SYN) unless the window is 0, resynchronisation
  on CRC error, IDT).
* `requester` — client session: pre-connection, F.CONNECT negotiation, `send_file` (CREATE → ORF →
  WRITE → data → TRANS.END → CRF → DESELECT), `receive_file` (SELECT → ORF → READ → ...),
  `send_message` (MSG or MSGDM/MSGMM/MSGFM), release / abort.
* `responder` — server session driven by a synchronous `ServerHandler` trait (authenticate, create,
  select, message, transfer events, cancellation flag).
* `io` — `ArticleSource` / `ArticleSink` with file implementations (`.part` files, positions for
  rewind / truncate) and in-memory ones for tests.
* `checkpoint` — synchronisation point bookkeeping (memory / JSON file).
* `tls` — rustls connector / acceptor (ring), optional host-name check, client certificates.

Every engine transition goes through `state::Machine`; an FPDU that the tables reject aborts the
session with D3-311, an ignored one (late ACK(SYN), data after RESYN) is dropped as C:X does.

### Restart semantics

The sender records a checkpoint *before* the first article following each SYN
(`file_offset`, `data_bytes`, `articles`); the receiver flushes its sink on each SYN and records the
same numbers. A restart (`PI 15 = 1`, same `PI 13`) lets the receiver choose the point
(`ACK(WRITE) PI 18`, or `READ PI 18` when the requester reads); both sides rewind to the checkpoint
and the sync numbering continues from it. RESYN during the data phase uses the same store.

## Binaries

Configuration objects and transfer records are JSON documents in SQLite (`pesit-app::store`), so the
REST DTOs and the storage format match the Java API field names. Inbound and outbound records are
separate tables in the one database. Listeners are tokio tasks owned by `ServerManager`; every
accepted connection runs `responder::serve` with a `PwHandler` that resolves partners and virtual
files from the store and publishes transfer records. The outbound `Engine` runs transfers as
background tasks, updates the history record on progress / sync points, and keeps a per-transfer
checkpoint file so that `retry` can resume — falling back to a full retransfer when the peer refuses
the restart.

## Connect:Express interoperability notes

* CX sends the pre-connection message for partner types T/O only; the server accepts it optionally.
* CX proposes a sync window of 2 and no resynchronisation unless configured; negotiation takes the
  minimum.
* CX refuses the last article of a `BF` file when it is shorter than LREC (TRC 5010): use `BU`
  (`recordFormat: 0x80`) or exact multiples.
* TLS: match `TCPIP_HEADER` of the SSLPARM entry with `tcpipHeader` on the listener / server.
