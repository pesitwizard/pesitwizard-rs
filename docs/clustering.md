# Clustering (NATS / JetStream)

Several nodes can form a cluster over a NATS server with JetStream enabled, so that configuration is
shared and one node is elected leader. Set `PESIT_CLUSTER_NATS` (e.g. `nats://nats:4222`) and, if you
run more than one cluster against the same NATS, `PESIT_CLUSTER_NAME`. Implemented in the
`pesit-cluster` crate (`async-nats`).

## What the cluster does

* **Membership** — each node heartbeats into a JetStream KV bucket (`pesit_<name>_members`) with a
  TTL; a node that stops is dropped when its key expires. `GET /api/v1/cluster` and the **Cluster**
  web UI tab list the members.
* **Leader election** — a KV lease (`pesit_<name>_leader`): a node acquires the `leader` key with a
  create (atomic), renews it while alive, and the TTL lets another node take over on failure.
* **Cluster-wide transfer history** — `GET /api/v1/cluster/transfers` aggregates the transfer records
  of every member (each node must advertise a reachable address via `PESIT_CLUSTER_ADVERTISE`,
  `host:port` of its admin API). Shown in the Cluster web UI tab.
* **Scheduled transfers** — recurring send / receive jobs (`/api/v1/schedules`, Schedules web UI tab)
  replicate across the cluster (like the shared-policy tables). Each node evaluates every schedule but
  fires only the ones it *owns* — the owner is a deterministic slice of the schedule id over the
  sorted live members — so a due job runs exactly once and the load spreads. The new next-run time is
  replicated so a peer can take over on failover. A standalone node owns everything.
* **Configuration replication** — a change to a shared-policy object (partners, virtual files, remote
  partners and schedules) is published on `pesit.<name>.config` and applied by every other node. A
  joining node first requests a full snapshot on `pesit.<name>.sync` from a peer and restores it, then
  follows the live stream. Listeners and connectors stay node-local (ports, binding and credentials
  are per node).

## Integration test

`make cluster-test` starts a NATS server and three nodes in Docker and checks that a partner created
on one node appears on the others, that membership and the leader are consistent, that a late-joining
node catches up the existing configuration via snapshot, and that deletions propagate.
