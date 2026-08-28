# PeSIT E (Hors-SIT) — condensed protocol reference used by the Rust implementation

Sources: PeSIT version E specification (14 July 1989, GSIT, `pesitwizard-pesit/pesit.html`,
chapters 3–4; chapter 4.8 state tables recovered from Connect:Express — see
C:X user guide appendix B (diagnostics), the PeSIT E specification, Java PeSIT Wizard.

## 1. FPDU header (§4.7.1)
```
octets 1-2 : total length of the FPDU (header + content), big-endian, includes itself
octet  3   : phase  0x40 = connection FPDUs, 0x00 = DTF/DTFDA/DTFMA/DTFFA, 0xC0 = everything else
octet  4   : type
octet  5   : ID.DST  (connection id of the destination)
octet  6   : ID.SRC  (connection phase: sender's connection id; DTF mono-article: 0;
                      DTF multi-article: number of articles N>1; other FPDUs: 0)
```
X = requester connection id (≠0, chosen in CONNECT), Y = server connection id (≠0, chosen in ACONNECT).
```
CONNECT  40 20 dst=0 src=X      ACONNECT 40 21 dst=X src=Y   RCONNECT 40 22 dst=X src=0
RELEASE  40 23 dst=Y src=X      RELCONF  40 24 dst=X src=Y   ABORT    40 25 dst=Y/X src=X/Y (dst=0 if unknown)
CREATE C0 11 | ACK(CREATE) C0 30 | SELECT C0 12 | ACK(SELECT) C0 31 | DESELECT C0 13 | ACK(DESELECT) C0 32
MSG C0 16 | MSGDM C0 17 | MSGMM C0 18 | MSGFM C0 19 | ACK(MSG) C0 3B
ORF C0 14 | ACK(ORF) C0 33 | CRF C0 15 | ACK(CRF) C0 34
READ C0 01 | ACK(READ) C0 35 | WRITE C0 02 | ACK(WRITE) C0 36 | TRANS.END C0 08 | ACK(TRANS.END) C0 37
DTF 00 00 | DTFDA 00 41 | DTFMA 00 40 | DTFFA 00 42 | DTF.END C0 04
SYN C0 03 | ACK(SYN) C0 38 | RESYN C0 05 | ACK(RESYN) C0 39 | IDT C0 06 | ACK(IDT) C0 3A
```
Requester→server file-phase FPDUs carry dst=Y, src=0; server→requester ACKs carry dst=X, src=0.
Data-phase FPDUs (DTF*, DTF.END, SYN, ACK(SYN), RESYN, ACK(RESYN), IDT, ACK(IDT)) carry
dst = peer id (Y when sent by requester, X when sent by server), src = 0 (or N for multi-article DTF).

## 2. Parameters (§4.7.2)
PI unit = `[PI code (1)] [LI] [value]`; PGI unit = `[PGI code (1)] [LI] [PI units...]`.
LI = 1 byte for 1..254, or `FF` + 2 bytes big-endian for 255..65535. LI = 0 is rejected.
Units must be in **ascending code order** (PGI 9 precedes its PI 3/4). A given parameter appears
at most once (first occurrence kept, error signalled). Numeric/symbolic values: leading zero bytes
removed (min 1 byte). Strings: ASCII, trailing blanks not significant.
Types: C string, N unsigned int, S symbolic (1 byte), M bit mask, D date `AAMMJJhhmmss` (12 chars), A aggregate.

| PI | name | type | max len | notes |
|---|---|---|---|---|
| 1 | CRC usage | S | 1 | 0 none / 1 CRC (PeSIT.F' PAD); optional, default 0 |
| 2 | Diagnostic | A | 3 | byte 1 severity/type, bytes 2-3 reason code (see §6) |
| 3 | Requester id | C | 24 | mandatory in CONNECT, optional in PGI 9 |
| 4 | Server id | C | 24 | idem |
| 5 | Access control | C | 16 | optional; bytes 1-8 password, 9-16 new password |
| 6 | Version | N | 1 (spec says C len 2) | 1 = PeSIT D, 2 = PeSIT E; encoded as 1 binary byte by every implementation |
| 7 | Sync points option | A | 3 | bytes 1-2 interval in KB (0 = none, FFFF = undefined), byte 3 ack window (0 = no ack; ≤16) |
| 11 | File type | N | 2 | Hors-SIT: 0; MSG: FFFF outbound msg, FFFE return msg |
| 12 | File name | C | 76 (Hors-SIT) / 14 (ETEBAC) | |
| 13 | Transfer id | N | 3 | CREATE: ≠0 chosen by requester; SELECT: 0 for new transfer (server assigns in ACK(SELECT)); restart: reuse |
| 14 | Requested attributes | M | 1 | b1 logical, b2 physical, b3 historical; MSG: 1 = message expected in ACK(MSG) |
| 15 | Transfer restarted | S | 1 | 0 new, 1 restart |
| 16 | Data code | S | 1 | 0 ASCII, 1 EBCDIC, 2 binary |
| 17 | Priority | S | 1 | 0 urgent, 1 normal, 2 low |
| 18 | Restart point | N | 3 | sync point number (0 = start of file) |
| 19 | End-of-transfer code | S | 1 | 4 error (restart follows), 8 suspension, 12 cancel by server, 16 cancel by requester |
| 20 | Sync point number | N | 3 | 1..999999, increments by 1 |
| 21 | Compression | A | 2 | byte 1: 0 no / 1 yes; byte 2: 1 horizontal, 2 vertical, 3 both |
| 22 | Access type | S | 1 | 0 write, 1 read, 2 mixed |
| 23 | Resynchronisation | S | 1 | 0 F.RESTART not allowed, 1 allowed |
| 25 | Max data entity size | N | 2 | bytes; server answers ≤ proposed |
| 26 | Timeout | N | 2 | seconds (ETEBAC5), unused Hors-SIT |
| 27 | Byte count | N | 8 | data bytes (excl. multi-article length prefixes, incl. compression headers) |
| 28 | Article count | N | 4 | |
| 29 | Diagnostic complement | A | 254 | free format (Hors-SIT) |
| 31 | Article format | M | 1 | 0 fixed, 0x80 variable |
| 32 | Article length | N | 2 | exact (fixed) or max (variable), bytes |
| 33 | File organisation | S | 1 | 0 sequential, 1 relative, 2 indexed |
| 34 | Signature taken into account | N | 2 | SIT only |
| 36 | SIT seal | N | 64 | SIT only |
| 37 | File label | C | 80 | |
| 38 | Key length | N | 2 | indexed files |
| 39 | Key offset | N | 2 | indexed files |
| 41 | Space reservation unit | S | 1 | 0 KB, 1 articles |
| 42 | Max space reservation | N | 4 | |
| 51 | Creation date/time | D | 12 | |
| 52 | Last extraction date/time | D | 12 | |
| 61 | Client id | C | 24 | store-and-forward: initial sender |
| 62 | Bank id | C | 24 | final receiver |
| 63 | File access control | C | 16 | ETEBAC5 |
| 64 | Server date/time | D | 12 | ETEBAC5 |
| 71-83 | security unit | | | 71 auth type A3, 72 auth elements N n, 73 seal type A4, 74 seal elements, 75 cipher type A4, 76 cipher elements, 77 signature type A4, 78 seal N, 79 signature N, 80 accreditation N, 81 signature ack N, 82 second signature N, 83 second accreditation N |
| 91 | Message | C | 4096 | |
| 99 | Free message | C | 254 | (PeSIT D: 64) |

PGI: 9 file identifier {3, 4, 11, 12}; 30 logical attributes {31, 32, 33, 34, 36, 37, 38, 39};
40 physical attributes {41, 42}; 50 historical attributes {51, 52}.

## 3. FPDU contents (spec §3.6 + §4.4, cross-checked with C:X parse templates)
`[x]` optional. Order is the ascending code order.
```
CONNECT        [1] 3 4 [5] 6 [7] 22 [23] [26] [99]
ACONNECT       [5] 6 [7] [23] [99]              (PI 6 may be lower than proposed → requester may refuse)
RCONNECT       2 [29] [99]
RELEASE        2 [29] [99]        RELCONF [99]        ABORT 2 [29]
CREATE         PGI9{[3][4] 11 12} 13 [15] [16] 17 25 PGI30{[31] 32 [33] [34] [36] [37] [38] [39]} PGI40{[41] 42} [PGI50{51 [52]}] [61] [62] [63] [71..80] [99]
ACK(CREATE)    2 [13] 25 [29] [64] [72] [80] [83] [99]
SELECT         PGI9{[3][4] 11 12} 13 [14] [15] 17 25 [61] [62] [63] [71..80] [99]
ACK(SELECT)    2 PGI9{...} 13 [16] 25 [29] [PGI30] [PGI40] [PGI50] [64] [72] [80] [83] [99]   (attributes per PI 14 request)
DESELECT       2 [29] [99]        ACK(DESELECT) 2 [29] [99]
ORF            [21] [72] [74] [76] [80] [83]        ACK(ORF) 2 [21] [29] [74] [76]
CRF            2 [29]             ACK(CRF) 2 [29]
READ           18                 ACK(READ) 2 [29]
WRITE          (none)             ACK(WRITE) 2 18 [29]
DTF*           raw data (see §4)  DTF.END 2 [29] [78] [79] [82]
SYN            20 [78]            ACK(SYN) 20
RESYN          2 18 [29]          ACK(RESYN) 18
IDT            2 [19] [29]        ACK(IDT) (none)
TRANS.END      [27] [28] [81]     ACK(TRANS.END) 2 [27] [28] [29] [81]
MSG / MSGDM    PGI9 13 [14] [16] 17 [PGI30 PGI40] [PGI50] [61] [62] [73 74 77 78 79 80 81] [91]
MSGMM / MSGFM  [91]               ACK(MSG) 2 [13] [16] [29] [79] [80] [81] [91]
```
Negative acknowledgements = same ACK FPDU with PI 2 ≠ 0 (state goes back).

## 4. Data phase
* Entity = one NSDU handed to the transport, ≤ negotiated PI 25. It may contain several
  concatenated FPDUs (§4.5): DTF, DTFDA, DTFMA, DTFFA, DTF.END, SYN (no concatenation when CRC used).
* DTF mono-article (src=0): content = one whole article. Multi-article (src=N>1):
  `[len1(2)][article1][len2(2)][article2]...`.
* Article longer than entity-6: segmented into DTFDA (start) + 0..n DTFMA (middle) + DTFFA (end).
  SYN only between articles (after DTFFA / before DTFDA).
* Sync points: sender emits SYN(20=n) at most every `interval` KB of data (counting data bytes,
  excluding multi-article length prefixes); receiver flushes then answers ACK(SYN)(20=n).
  Window w: at most w unacknowledged SYNs; ACK of n implicitly acks < n. Window 0 = no ACKs.
* Restart (relance) on a new connection: CREATE/SELECT with PI 15=1 and same PI 13; the
  receiver fixes the restart point (ACK(WRITE) PI 18 for writes, READ PI 18 for reads):
  0 = start, else a sync point number ≥ last acknowledged.
* Resynchronisation (PI 23 negotiated): either side sends RESYN(2, 18=n); peer answers
  ACK(RESYN)(18=m): m == n (accepted), m ≥ n (receiver-initiated, sender may propose later
  point), or 0 (restart from beginning). Transfer continues from that point in the same phase.
* Interruption: IDT(2, 19=code) from either side; peer answers ACK(IDT); both go to
  "transfer idle" (OF02). Codes: 4 error/restart later, 8 suspension, 12/16 cancellation.
* End: sender DTF.END(2=diag); the *requester* then sends TRANS.END([27][28]); the server
  answers ACK(TRANS.END)(2 [27][28]) — the ACK acknowledges all sync points. Then CRF/ACK(CRF),
  DESELECT/ACK(DESELECT), then RELEASE/RELCONF (or another CREATE/SELECT in the same connection).
* Timers: Tp watchdog (default 30 s, PI 26), Td idle between transfers on server (≥ 5 min),
  Tc connect wait (30 s), Tr network disconnect wait.

## 5. Transport (PeSIT over TCP/IP as implemented by C:X / PeSIT Wizard)
* Plain TCP: every NSDU preceded by a 2-byte big-endian length (not counting itself).
* TLS: same, or raw FPDUs (C:X SSLPARM `TCPIP_HEADER=N`, usual). Configurable.
* Optional pre-connection (Hors-SIT, EBCDIC, not PeSIT FPDUs): requester sends 24 bytes
  `"PESIT   "` + id (8, blank padded) + password (8); responder answers `ACK0` or `NAK0`
  (4 bytes EBCDIC). C:X sends it for partner types T and O (not N) and auto-detects it.
* CRC (PI 1 = 1): 2 bytes appended after each FPDU (not counted in the FPDU length): Fletcher
  mod 255. No concatenation when CRC is on.

## 6. Diagnostics (PI 2 = [type][code hi][code lo]; Annex D via C:X appendix B)
type 0 = success (0 000). type 1: 100 transmission error. type 2 (file/transfer):
200 insufficient file characteristics, 201 system resources temporarily insufficient,
202 user resources temporarily insufficient, 203 non-priority transfer, 204 file already exists,
205 file not found, 206 disk quota exceeded, 207 file busy, 208 file too old, 209 message type not
accepted, 210 presentation context negotiation failed, 211 cannot open file, 212 cannot close file,
213 I/O error, 214 restart point negotiation failed, 215 system-specific error, 216 voluntary
premature stop, 217 too many unacknowledged sync points, 218 resynchronisation impossible,
219 file space exhausted, 220 incorrect record length, 221 end-of-transmission timer expired,
222 too much data without sync point, 223 abnormal end of transfer, 224 file larger than announced,
225 application congested / file deleted, 226 transfer refused, 227..230 restart impossible
(227 not restartable, 228 unknown sync point, 229 file modified, 230 delay exceeded),
233 no transfer restart context, 299 other. type 3 (connection/protocol): 300 local
communication system congested, 301 caller id unknown, 302 caller not attached to an SSAP /
unauthorized, 303 called partner unknown / remote congestion, 304 caller not authorised
(security), 305 SELECT negotiation failed, 306 RESYNC negotiation failed, 307 SYNC negotiation
failed, 308 version not supported, 309 too many connections, 310 network incident,
311 remote protocol error, 312 service closed by user, 313 idle connection cut (Td), 314 unused
connection cut for a new one, 315 negotiation failure, 316 administrative cut, 317 timeout (Tp),
318 mandatory PI absent or illegal PI content, 319 incorrect byte/article count, 320 too many
resynchronisations, 321 call backup number, 322 call back later, 399 other.

## 7. Profiles
Hors-SIT (the one implemented): functional units Kernel, Write, Sync mandatory; Read, Resync,
Suspension (IDT), Message, Error control (CRC) optional; multi-article and segmentation allowed
(no dynamic negotiation — agreed beforehand); requester/server ids = 1..24 ASCII chars; file name
1..76 chars; PI 11 = 0 unless agreed; compression allowed; optional pre-connection.
