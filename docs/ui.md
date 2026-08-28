# Web UI

The node serves a self-contained web UI at `/` on the **admin port** (`--api-port`, default 8080).
It is a single HTML page (`crates/pesit-node/src/web/app.html`) — vanilla JavaScript, no build step,
no external assets — that drives the REST APIs. It talks to the admin API same-origin (`/api/v1/...`,
sending `X-API-Key`) and to the transfer API through the admin port under `/client/api/v1/...`.

Open `http://<host>:8080/`, paste the API key in the field at the top right (stored in
`localStorage`), and the dashboard populates. A light / dark / system theme toggle sits at the
bottom of the sidebar.

## Tabs

| Tab | What it does |
|-----|--------------|
| **Dashboard** | Live overview: listeners up, in-progress / completed / failed counts and bytes across inbound *and* outbound, plus the most recent transfers (both directions) and configuration counts. |
| **Listeners** | Inbound PeSIT E listeners: status (with start / stop), transport (plain / TLS), sync settings; a form to create a listener (server id, port, entity size, sync interval / window, directories, TLS, auto-start). |
| **Partners** | Remote parties allowed to connect: access type, password, max connections, allowed files; create / delete. |
| **Virtual files** | Logical files exposed to partners: direction, record format (binary / text), record length, receive directory + filename pattern or send file; create / delete. |
| **Remote servers** | Servers this node connects out to: address, server id, transport, default; test connectivity, upload a CA (truststore), set default, delete. |
| **Send / Receive** | Initiate an outgoing transfer (send / receive) or a message: pick a remote server, partner id, file names, sync / compression / text options; a live table of outbound transfers with cancel / retry. |
| **Certificates** | Keystores, truststores, the local CA and the Vault PKI backend — see [certificates.md](certificates.md). |
| **Transfers** | Inbound and outbound transfer records (toggle), with live status, progress, and cancel. |
| **System** | The append-only audit log (config changes, listener start/stop, certificate / Vault operations, transfer outcomes) and configuration backup / restore (download a JSON bundle, restore it back). |

Tables on the live tabs auto-refresh without disturbing a form you are filling in (only the table
body is updated).

## End-to-end tests

The UI is covered by Playwright end-to-end tests in `integration/ui/`, run with:

```bash
make ui-test
```

They start a throwaway node, drive the browser through a full configuration (partner → virtual file
→ listener started → remote server → a real loopback transfer that reaches `COMPLETED` with a
byte-identical received file), exercise the API-key gate, and generate a local CA + issue a stored
certificate through the Certificates tab.
