# Storage connectors

A virtual file is normally backed by the local filesystem (`sendDirectory` / `receiveDirectory` of a
listener, or an explicit path). A **connector** lets a virtual file be backed by an external storage
system instead: a file received over PeSIT is written to the connector, and a file to send is read
from it. Implemented in the `pesit-connector` crate.

## Connector types

| Type    | Backend                                             | Library                 |
|---------|-----------------------------------------------------|-------------------------|
| `s3`    | Any S3-compatible object store (AWS S3, MinIO, …)   | `aws-sdk-s3`            |
| `sftp`  | An SFTP server (a fresh SSH connection per op)      | `russh` / `russh-sftp` |
| `local` | A directory on the node (staging into another tree) | `tokio::fs`            |

## Managing connectors

REST under `/api/v1/config/connectors` (admin API, `X-API-Key`) and the **Connectors** web UI tab:

* `GET /api/v1/config/connectors` — list.
* `POST /api/v1/config/connectors` — create / replace. Body (only the fields for the chosen `type`):

  ```json
  { "id": "s3", "type": "s3", "bucket": "pesit", "region": "us-east-1",
    "endpoint": "http://minio:9000", "accessKey": "…", "secretKey": "…", "pathStyle": true }
  ```
  ```json
  { "id": "partnerftp", "type": "sftp", "host": "sftp.example.com", "port": 22,
    "user": "pesit", "password": "…", "basePath": "/uploads" }
  ```
  ```json
  { "id": "archive", "type": "local", "basePath": "/data/archive" }
  ```
* `DELETE /api/v1/config/connectors/{id}` — remove.
* `POST /api/v1/config/connectors/{id}/test` — check reachability. Returns
  `{ "success": true, "type": "s3" }` or `{ "success": false, "message": "…" }`.

Connectors are included in configuration backup / restore. They are **not** replicated across a
cluster: the credentials stay node-local (like listeners), so each node owns its own connectors.

## Backing a virtual file with a connector

On a virtual file, set `connector` to a connector id and `connectorPath` to a target-path template:

```json
{ "id": "INVOICES", "enabled": true, "direction": "RECEIVE",
  "connector": "s3", "connectorPath": "incoming/${transferId}.dat" }
```

`connectorPath` placeholders: `${transferId}`, `${virtualFile}`, `${partner}`, `${date}`. If it is
omitted, a name derived from the transfer is used.

### How a transfer flows

* **Receive** (a partner sends to us): the data is written to a local **staging** file
  (`$TMPDIR/pesitwizard-staging/…`); when the transfer completes it is uploaded to the connector at
  the resolved path, and the staging file is removed. The transfer record's `localPath` is set to
  `connectorId:remotePath`.
* **Send** (we send to a partner): the object is fetched from the connector into a staging file,
  streamed to the partner, and the staging file is removed.
* On failure or cancellation the staging file is cleaned up and nothing is written to the connector.

Staging keeps checkpoint / restart, CRC and record-format handling exactly as for a local file — the
connector only sees the fully assembled object at the boundaries of a completed transfer.

## Integration test

`make connector-test` (`integration/s3/`) starts a **MinIO** object store and a node in Docker, then:

1. creates an S3 connector pointing at MinIO and checks `/{id}/test` succeeds,
2. receives a file into a virtual file backed by that connector and confirms the object appears in
   the bucket,
3. reads it back through a second virtual file backed by the same connector and checks the checksum
   round-trips.
