# Gap analysis — PeSIT Wizard (Java) vs Connect:Express / PeSIT E

Result of reading the Java code (pesitwizard-pesit / server / client), the PeSIT E spec and the
interoperability testing with Connect:Express. Items marked **[interop]**
can break exchanges with C:X in some configuration; **[spec]** = missing protocol feature;
**[perf]** = performance; **[design]** = structural weakness fixed by the Rust design.

1. **CRC (PI 1) not implemented** [interop][spec]. C:X session tables have `CRC=Y/N`; with Y every
   NSDU carries a 2-byte Fletcher-255 checksum and C:X expects one back. Java only
   stores a flag → frame length mismatch. Rust: full CRC support (negotiated in CONNECT/ACONNECT).
2. **Compression (PI 21) not implemented** [spec]. C:X presentation tables offer horizontal /
   vertical / mixed compression; Java never proposes it and ignores the server's choice in
   ACK(ORF). Rust: implements the three algorithms,
   negotiates them in ORF/ACK(ORF), counts compressed bytes for PI 27 and sync intervals.
3. **Article segmentation DTFDA/DTFMA/DTFFA misunderstood** [spec]. Java documents them as "data
   with ack / middle / final"; they are start/middle/end of ONE article that exceeds the entity
   size. Receiving side works by accident for binary streams; sending side never segments (an
   article larger than PI 25 − 6 is silently split into multiple DTF = multiple articles). Rust:
   proper segmentation/reassembly with record boundaries.
4. **Multi-article DTF not used by the client, tiny DTFs** [perf]. The Java client sends one DTF per
   `recordLength` bytes (default 506) → ~60× more FPDUs than needed with a 32 KB entity. Rust:
   packs articles into entities like C:X, up to 255 articles / entity.
5. **Restart semantics broken** [interop][spec]. Server READ uses the restart point (a sync point
   *number*) as a *byte offset*; ACK(WRITE) always returns PI 18 = 0; PI 15 is ignored; sync point
   → offset maps are in-memory only. Rust: persistent per-transfer checkpoint store (sync number ↔
   byte offset ↔ article count), correct PI 15/18 negotiation on both sides.
6. **Sync window (PI 7 byte 3) not exploited** [perf][spec]. Java waits for every ACK(SYN) inline.
   C:X keeps sending within the window and accepts late ACK(SYN) even after DTF.END. Rust:
   asynchronous window handling per the state tables.
7. **RESYN / IDT only handled in narrow synchronous spots** [design][spec]. Java's request/response
   coding style cannot deal with a RESYN or IDT arriving while it is sending, nor with the
   collision rules (§4.3.1 f, §4.8.3). Rust: full event-driven state machine (54 states, C:X
   tables) driven by a select loop over network + application events; F.CANCEL exposed to users.
8. **Text record formats ignored** [interop]. C:X `TF/TV` files are sent as articles without the
   line feed and rebuilt with LF on reception; `BF` needs fixed-length padding. Java treats
   everything as a byte stream → text files received from C:X lose their newlines. Rust: article
   codecs (binary undefined / binary fixed / text variable / text fixed) selectable per virtual file.
9. **Diagnostic catalogue incomplete** [spec]. Rust ships the full Annex D list (type 1/2/3) with
   C:X-compatible texts, plus PI 29 diagnostic complements.
10. **PI order / mandatory PI validation** loosely done (Java answers D3-304 for order errors);
    C:X parses PIs in a strict canonical order and rejects with 318/TRC 14YY. Rust: table-driven
    per-FPDU templates (exactly the canonical order) with 318 on violation.
11. **SELECT transfer id** must be 0 for a new read transfer (server assigns); Java sends a counter.
12. **Pre-connection**: server-side auto-detection exists; the client cannot send one (needed for
    C:X partners defined as type TOM). Rust: configurable per partner.
13. **TLS framing** hard-coded to "no length header"; C:X SSLPARM `TCPIP_HEADER` can be Y. Rust:
    configurable (`length_prefix: auto|always|never`).
14. **PI 99 / PI 37 / PI 61 / PI 62 / PI 16 / PI 26** are not exposed to users (C:X uses PI 99 for
    physical file names and CNX_MSG, PI 37 labels). Rust: exposed in transfer requests and records.
15. **State machines** are hand-written subsets (server enters/exits pending states inside one
    handler). Rust: the state tables are data (same shape as C:X), shared by client and server.
16. **ASCII↔EBCDIC data translation** (PI 16) absent; Rust provides CP037 translation as an
    article codec option.
17. **Interrupted-transfer bookkeeping**: Java cancellation just throws and closes the socket
    (C:X logs a network incident). Rust: clean F.CANCEL (IDT 19=16/12) then CRF/DESELECT/RELEASE.

## Status in the Rust implementation (2026-08-28)

| # | Gap | Rust status |
|---|-----|-------------|
| 1 | CRC | Done — `pesit-core::crc`, negotiated in CONNECT, verified on every entity, raw-TLS detection from PI 1 |
| 2 | Compression | Done (horizontal / vertical / mixed, `compression` capability on listeners, `compressionEnabled` on client requests); disabled by default |
| 3 | Segmentation | Done — `ArticlePacker` / `Reassembler` (DTFDA/DTFMA/DTFFA = one article across entities) |
| 4 | Multi-article DTF | Done — up to 255 articles per DTF, entities filled up to PI 25 |
| 5 | Restart | Done — persistent checkpoints, PI 15/13/18 on both sides, `retry` endpoint. Restart works end to end PW↔PW (server offers the point in ACK(WRITE), the client resumes in place). Connect:Express refuses a remote-requester-driven reprise of a CREATE (D2-204), so `retry` against CX automatically falls back to a full retransfer |
| 6 | Sync window | Done — asynchronous `Link`, window from PI 7 byte 3, `syncWindow` listener option |
| 7 | RESYN / IDT | Done — handled in the data loop of both roles, collisions per the state tables; F.CANCEL through `/cancel` endpoints |
| 8 | Text record formats | Done — `RecordFormat` BU/BF/BV/TV/TF, `text: true` on virtual files / requests |
| 9 | Diagnostics | Done — full catalogue with descriptions, PI 29 / PI 99 texts surfaced in errors |
| 10 | PI validation | Done — per-FPDU templates in canonical order, D3-318 / D3-311 |
| 11 | SELECT transfer id | Done — the client sends 0 for a new read, keeps the server's PI 13 |
| 12 | Pre-connection | Done — optional on the server (auto-detected), `preconnectId/preconnectPassword` per client server entry |
| 13 | TLS framing | Done — `tcpipHeader` flag (listener and client server entry) instead of the `auto` mode |
| 14 | Extra PIs | Partial — `FileSpec` carries PI 16/37/61/62/99 and the server returns labels/dates; the REST transfer requests do not expose them yet |
| 15 | State machine | Done — the 54 C:X states as data, shared by both roles |
| 16 | ASCII/EBCDIC translation | Not done — CP037 tables exist (pre-connection) but no article codec option yet |
| 17 | Clean cancellation | Done — IDT with end code 12/16 then CRF/DESELECT/RELEASE |

Validated against Connect:Express 1.5 in Docker (`integration/cx/`), all suites green:
* `run-tests.sh` (16/16): CX → server (small, 5 MB), client → CX (small, 5 MB, 10 MB with sync
  points, 3 concurrent), error handling and edge cases (empty / 1-byte / spaces in name).
* `run-tls-tests.sh` (6/6): TLS both ways (SSLPARM1 server mode, TCPIP_HEADER=N), PEM CA upload,
  PKCS#12 rejected with an explanation.
* `run-restart-tests.sh` (5/5): F.CANCEL mid-transfer, restart (fallback retransfer against CX),
  replay.
