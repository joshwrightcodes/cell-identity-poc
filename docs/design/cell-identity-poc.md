# Cell identity PoC: design

Status: draft for owner review, revision 2. Date: 2026-11-08. Facts that can change are as of
this date.

Source markers: **[owner]** means the project owner decided it. **[call]** means the author
chose it, and the owner can overrule it. Text without a marker follows from those decisions.

`docs/design/base-cell.md` describes the cluster template that every cluster in this design
uses. That document is built and verified. This document builds on it.

Revision 2 applies the results of four adversarial reviews: security, network, DevOps and
infrastructure. Each result that depends on upstream behaviour was checked against upstream
source or documentation on 2026-11-08.

## Intent

The PoC proves that a management plane, a cell control plane (CCP) and cell clusters can
authenticate to each other with SPIFFE identities. No credential is copied between clusters.
Management rejects an unexpected worker, and that includes a worker that attempts a
man-in-the-middle (MITM) attack. **[owner]**

The PoC runs on one Mac with `container cluster`. The same design then deploys to EKS. Nothing
above one provider adapter depends on AWS. **[owner]**

## Domain model **[owner]**

```text
Management plane (own cluster)
├── oversees cells and cell control planes
├── sends direct operations to cells
├── shows one central Argo CD view of every cluster
└── Cell control plane (own cluster, 1:1 with an environment)
    ├── provisions cells on request from management
    ├── sends cross-cutting operations to all cells of its environment
    └── Cell (one or more regions; AWS, GCP, Azure or self-hosted)
        └── Kubernetes cluster (one or more per cell)
            ├── Worker service (one per cluster; a service, not a node or DaemonSet)
            └── Argo CD (manages only services in this cluster)
```

- Each plane runs in its own cluster, and every cluster starts from the base cell. **[owner]**
- Each Argo CD instance manages only its own cluster. **[owner]**
- The worker handles hydrated resources after provisioning. Argo CD applies only what the worker publishes. **[owner]**
- A cell is contained. It cannot call another cell, except through the management API. **[owner]**
- The worker service scales with an HPA, so one service has many replicas. **[owner]**
- One operation is work for exactly one replica. **[call]**

## Acceptance checks

`mise run poc:demo` shows these checks, and `mise run poc:gate` asserts them. **[call]**

1. Management creates two new workers, through the CCP. Each worker has its own cell cluster. **[owner]**
2. Each worker registers and authenticates with management. **[owner]**
3. Both workers appear in management as valid. **[owner]**
4. A third, malicious worker starts, and management rejects it. **[owner]**

The gate also covers these behaviours:

- Management and the CCP send operations to a worker and read information from it. The worker pushes status to both. **[owner]**
- Management shows every cluster in one Argo CD view, with live manifests. Nothing is copied between clusters for it, and the view cannot change a cell. **[owner]**
- Each case in "Rejection tests" fails with the stated result.
- The HPA scales a worker under operation fan-out, with no lost operation and no double application.
- Direct operations continue while the CCP is down. Cross-cutting operations continue while management is down, within the record lifetime.
- A rebuilt management or CCP cluster takes back its cells with no manual step in any cell.
- A bad management bundle rolls back in the cell on its own.

## Goals, non-goals and anti-goals

Goals:

- One attestation method across AWS, GCP, Azure and self-hosted clusters.
- Separate network and trust boundaries, with a test for each boundary.
- A local demo from a clean Mac, and a deployment to four EKS clusters.
- The latest stable release of each tool and component. **[owner]**
- Recovery from the loss of a whole plane cluster, with no credential copied and no manual step in a cell.

Non-goals:

- Node identity, TPM attestation or measured boot. A worker is a service, so these checks do not apply.
- Production HA and multi-region failover. The design names the HA path for each single component.
- GCP and Azure adapters. The design keeps their shape, but the PoC builds only `local`, `kind` and `aws`.
- Approval workflows and compliance controls. **[call]**
- Creation of the management and CCP clusters by the system itself. The harness creates them. **[call]**
- A service mesh across clusters.
- IPv6 and dual-stack clusters. The harness refuses them. **[call]**

Anti-goals. The PoC fails if any of these hold, even when all tests pass:

- A long-lived credential is copied between clusters, or the CCP keeps a kubeconfig for a cell.
- A cell cluster accepts an inbound connection from another plane. The provider bootstrap and the operator break-glass path, both on the tailnet, are the only exceptions.
- Management, the CCP or the central Argo CD view changes a cell by any path other than a worker operation. This must hold even when management itself is compromised.
- AWS types or identifiers appear above the provider adapter.
- A test passes because a check was weakened, retried until green or stubbed.
- The result claims a stronger property than the tests prove.

## Constraints

- Local runtime: Apple `container` 1.7.1, from the signed GitHub release, managed by mise. **[owner]** The harness asserts the exact version. The Homebrew build of 1.7.1 has no cluster plugins.
- Kubernetes v1.37.0 node image, pinned by digest. **[call]**
- `container` clusters cannot be stopped and started again. The design treats a Mac restart as the loss of every cluster, and recovers through the disaster recovery path. **[call]**
- Versions are pinned in `mise.toml`, `cell.env` and the image digests. Each bump goes through the vendor review in `vendor/README.md`.
- Go 1.27, module path `github.com/joshwrightcodes/cell-identity-poc`, ko for images and distroless images.
- Images: locally, ko builds into the `container` image store, and clusters use `--shared-image-store`. On EKS, images live in ECR. CI pushes through GitHub OIDC, and nodes pull with their IAM role. **[call]**
- Telemetry goes through OpenTelemetry (OTLP) with the slog bridge. Do not add Prometheus client libraries, `/metrics` endpoints or ServiceMonitors. Upstream metrics listeners are turned off where the component allows it.
- Upstream SPIRE and Argo CD Agent stay unforked. SPIRE is extended only through its plugin interfaces. Fixes that the PoC needs upstream are offered as contributions, after the owner approves each one. **[call]**
- Read each third-party component before it runs, and report the result.
- Scripts do not write secrets to disk.
- Every repository may become public. Documents name roles, not people.

### Keys and roots of trust **[call]**

Keys fall into three classes:

| Class | Members | Where it lives |
| --- | --- | --- |
| Roots of trust | SPIRE root CA for each trust domain, the offline recovery key | Secret store only |
| Signing keys | Order, record, direct bundle and cross-cutting bundle keys | Secret store, delivered into the owner's cluster |
| Rebuildable keys | SPIRE intermediate CAs, the Argo CD Agent JWT key, mesh CAs | Generated inside the cluster, and generated again after a rebuild |

- Locally, `mise run keys:seed` reads each key from the secret manager CLI on standard input, and creates the Kubernetes Secret directly. Nothing is written to disk.
- On EKS, an external store holds the same keys. A provider-neutral sync delivers them, and each key rotates with one command.
- The offline recovery key never enters a cluster. It signs key set changes only.

## Topology and trust boundaries

| Cluster | Role set on top of the base cell | SPIRE server |
| --- | --- | --- |
| `management` | Management API and registry, gateways, telemetry gateway, Argo CD UI and Agent principal | `management.poc.internal` |
| `ccp-dev` | CCP API, gateway | `env-dev.poc.internal` |
| `cell-a-1` | Worker service, HPA, metrics adapter | None |
| `cell-b-1` | The same services | None |
| `rogue` | Genuine worker and agent images, plus attack tools | Its own, unregistered |

The provider adapter runs outside every plane cluster, as an operator tool on the tailnet.
Locally, the host service on the Mac is that adapter. **[call]**

No SPIRE signing key sits in a cell cluster. A cell workload gets each identity from a SPIRE
server in another cluster, through an agent sidecar in its own pod.

Local size: management and the CCP get 6 CPUs and 12 GB each, and cells get 4 CPUs and 8 GB
each. `rogue` gets 2 CPUs and 4 GB. The total is 22 CPUs and 44 GB, and the README states it.
**[call]**

### State and its recovery **[call]**

| State | Owner | Store | After a lost cluster |
| --- | --- | --- | --- |
| Cell registry, cell records, used order IDs | Management, CCP | Postgres-compatible database | Restore from backup |
| Operation queues, fencing epochs | Management, CCP | The same database | Restore. In-flight operations expire, and senders send them again |
| SPIRE entries and agents | Both SPIRE servers | The same database | Rebuild from the registry. Agents attest again |
| Roots of trust and signing keys | Owner | Secret store | Load again from the store |
| Bundles in a cell | Worker | Store on a persistent volume, plus last digests per sender | Senders publish again on reconnect |

- Locally, each plane runs Postgres on a persistent volume. `mise run plane:backup` streams a backup to the Mac. The backup holds no secret, because keys live in the secret store.
- On EKS, each plane uses a managed Postgres-compatible service with point-in-time recovery.
- Every cluster gets a storage provisioner, which passes the vendor review first. EKS uses the EBS CSI driver.
- The HA path for each SPIRE server is a second server in another zone, with the same database and the same root. The PoC runs one server per plane.

### Two identities for each worker replica **[owner]**

Each worker replica holds two SVIDs, one from each upstream:

- A management SVID, issued by management's SPIRE server. The worker uses it only on its management stream.
- An environment SVID, issued by its CCP's SPIRE server. The worker uses it only on its CCP stream.

Because of this:

- Management rejects an unexpected worker by itself, at its own SPIRE server and gateway. Acceptance check 4 does not depend on the CCP.
- A compromised CCP can mint environment SVIDs, but not management SVIDs.
- Each path continues when the other plane is down.

Each worker pod runs two SPIRE agent sidecars, one for each server. **[call]** Each sidecar
serves its own Workload API socket, and the worker reads each socket for one stream only.

### SPIFFE IDs **[call]**

| Principal | SPIFFE ID |
| --- | --- |
| Management service | `spiffe://management.poc.internal/control` |
| Management telemetry gateway | `spiffe://management.poc.internal/telemetry` |
| Argo CD Agent principal | `spiffe://management.poc.internal/argocd/principal` |
| Worker, management identity | `spiffe://management.poc.internal/cell/<cell>/cluster/<cluster>/worker` |
| Collector in a cluster | `spiffe://management.poc.internal/cell/<cell>/cluster/<cluster>/otel` |
| Argo CD agent | `spiffe://management.poc.internal/argocd-agent/<agent-name>` |
| CCP service | `spiffe://env-dev.poc.internal/ccp` |
| Worker, environment identity | `spiffe://env-dev.poc.internal/cell/<cell>/cluster/<cluster>/worker` |
| SPIRE server | `spiffe://<domain>/spire/server` |
| SPIRE agent, per pod | `spiffe://<domain>/spire/agent/cluster_jwt/<cell>/<cluster>/<pod-uid>` |

- The worker identity is per service, so denial works per service and not per replica.
- Authorization reads parsed path segments, never string prefixes.
- Management assigns each agent name when it signs the cell record. Names are unique and follow DNS label rules. The CCP cluster also gets an agent name.

### Plane endpoints **[call]**

- The signed cell record carries an endpoint set: the address and port of each plane listener.
- During a move, the set holds the old and the new endpoints together.
- Locally, a relay on the Mac listens on fixed ports at the vmnet gateway address, and forwards to the current node IPs. A rebuilt plane therefore keeps its address.
- On EKS, each NLB has fixed Elastic IPs through subnet mappings.
- NodePorts sit in the range 30000–32767. The relay and the NLBs map the public ports onto them.

### Network flows

The less-trusted side opens every cross-cluster connection. **[call, consistent with the owner's requirement that the worker pushes status]**

| Source | Destination | Purpose |
| --- | --- | --- |
| Cell SPIRE sidecar, management | Management SPIRE server | Attestation and SVID renewal |
| Cell SPIRE sidecar, environment | CCP SPIRE server | Attestation and SVID renewal |
| Worker replica | Management cell gateway | Registration, direct operations, status, cell-to-cell requests |
| Worker replica | CCP gateway | Cross-cutting operations, status |
| Argo CD agent proxy | Management principal proxy | Application status and the live resource view |
| Cell collector proxy | Management telemetry gateway | Telemetry and denial codes |
| CCP service | Management CCP gateway | Registration, provision orders, records, status |
| CCP | Provider adapter | Create and delete a cell, under a management-signed order |
| Management service | Provider adapter | Read cluster signing keys |
| Provider adapter, operators | Cell Kubernetes API, over the tailnet | Bootstrap and break-glass only |

- Each listener trusts exactly one trust domain. Management has separate listeners for cells and for the CCP.
- Trust domains do not federate through bundle endpoints. Each side pins the other's root CA, which never changes during normal operation.
- Cross-cluster TLS does not terminate at a load balancer or ingress.
- Plane listeners see real client addresses: `externalTrafficPolicy: Local` locally, and client IP preservation or the PROXY protocol on EKS. SPIRE limits attestation to one attempt per second per address, so shared addresses would queue every cell.
- No flow goes from one cell to another.

Zero trust rule: the identity check decides every access. Network controls only reduce exposure.

### Kubernetes API access **[owner]**

- A cluster's Kubernetes API is reachable only from the operators' tailnet. Other clusters and the internet cannot reach it.
- On EKS, each cluster has a private API endpoint only.
- Tailnet ACLs let only the operator and adapter tags reach cell routes. Each cluster VPC has its own CIDR. **[call]**
- Locally, every cluster shares vmnet, so vmnet stands in for the tailnet. The local run cannot prove this property. The EKS run proves it.
- Locally, the Mac's packet filter lets only the management and CCP addresses reach the host service. **[call]**
- The `rogue` cluster is never on the tailnet.

### Network isolation **[call]**

- Each cluster gets its own VPC on EKS, with no peering and no transit gateway between cluster VPCs.
- Every namespace has default deny, `kube-system` included. A cluster-scoped policy also denies sources outside the cluster. AdminNetworkPolicy provides it where the CNI supports it.
- On EKS, VPC CNI runs network policy in strict mode, so a new pod has no traffic until its policy applies.
- The worker renders the rules that depend on cluster facts: node addresses, control-plane sources and API server endpoints. It renders them again when nodes or EndpointSlices change. Management's bundle holds every other rule.
- On EKS, control-plane sources for webhooks and API services are the cluster subnet CIDRs, read as a provider-neutral fact.
- The harness refuses a cluster with IPv6 addresses.

## Identity

### Why a custom attestor

SPIRE's `k8s_psat` attestor validates through TokenReview. A remote server needs a kubeconfig
for each cluster
([docs](https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_k8s_psat.md),
checked 2026-11-07). That is a stored cross-cluster credential, so the PoC cannot use it.

The PoC adds a small SPIRE NodeAttestor plugin pair, `cluster_jwt`. **[call]** It validates a
projected service account token against the public signing keys of that cluster. Teleport's
`static_jwks` join method and the SPIFFE `spire-identity-exchange` validator do the same. Read
both before the attestor is written, and reuse code where its licence and review allow.

### SPIRE roots and pinned bundles **[call]**

- Each SPIRE server uses the `disk` UpstreamAuthority with that domain's root CA from the secret store. The server rotates only its intermediate CA.
- Every sidecar pins the root CA, not the server CA. A CA rotation therefore never changes the anchor.
- `insecure_bootstrap` stays off.
- A rebuilt SPIRE server loads the same root, so every pinned bundle stays valid.
- The root CA lives for 10 years. Rotating it is a planned key set change.

### Attestation

The SPIRE agent runs as a sidecar in each pod that needs an identity. **[call]** It needs no
DaemonSet, host path, CSI driver or kubelet access.

The sidecar connects to the server and verifies the exact server ID. Only then does it send a
projected token, with the audience `spire-management` or `spire-env-dev`.

The server plugin takes these steps. Any error denies:

1. It reads the claimed cell and cluster from the request, and loads the signed cell record. It refuses an expired or revoked record.
2. It verifies the token signature against the signing keys in that record. It never selects keys from the `iss` claim, because all local clusters share one default issuer.
3. It checks audience, namespace and service account against the record.
4. It requires a token bound to a pod, with the pod UID and node claims. It refuses a token that is not bound to a pod.
5. It requires a lifetime (`exp` minus `iat`) of 15 minutes or less, and an `iat` no older than 15 minutes.
6. It refuses a token ID (`jti`) that it has seen before. The cache keeps each ID for 15 minutes.
7. It derives the agent ID and selectors from the pod UID.

The pod spec requests a token lifetime of 10 minutes, the Kubernetes minimum. The requester
otherwise chooses the lifetime, and `cell-a-1` sets no maximum, so steps 4–6 bound it.

A node alias entry maps cluster and service account selectors to the workload parent, so HPA
scale events write no entries. The server prunes expired agents with
`prune_attested_nodes_expired_for` (SPIRE 1.13 or later).

### Replica cap **[call]**

- A worker sends its pod UID in the stream hello. A new stream with the same pod UID replaces the old one.
- A gateway counts pod UIDs that have sent a heartbeat in the last 30 seconds.
- Gateway replicas share the count through the plane database.
- The cap in the cell record allows `maxReplicas`, plus rollout surge, plus one reconnect for each replica.

### Independent key lookup

The CCP creates cells, so it cannot be the source of cell signing keys:

- Management reads those keys itself through `Lookup` on the provider adapter, with its own copy of the cluster reference.
- It signs them into the cell record, and sends the record to the CCP.
- It calls `Lookup` every 15 minutes, and at once when an attestor reports an unknown key ID. The immediate path allows one call per cluster per minute. **[call]**
- A record keeps a retired key until every token signed with it has expired.

### Cell records **[call]**

A cell record holds the cell's signing keys, endpoint set, agent name, replica cap, bundle
key sets and status. It also carries:

- A revision as `(epoch, counter)`. The epoch changes with each record key, and survives a restore because it is derived from the key ID.
- An expiry 6 hours after signing. Management signs the record again every hour.

Because of this, a CCP that loses contact with management stops work for a cell within 6 hours.
That is the longest revocation delay during a partition, and also the longest management
outage that cross-cutting work survives.

### Signing keys and key sets **[call]**

| Key | Owner | Signs |
| --- | --- | --- |
| Order key | Management | Provision and delete orders |
| Record key | Management | Cell records |
| Direct bundle key | Management | Hydrated bundles for direct operations |
| Cross-cutting bundle key | CCP | Hydrated bundles for cross-cutting operations |
| Offline recovery key | Owner | Key set changes only |

- Each key has one purpose, and maps to exactly one stream sender.
- A cell pins key sets, not single keys. Each set holds the current key and the next key.
- A key set change needs signatures from the current key and from the offline recovery key.
- A rotation publishes the next key first. It retires the old key only after every valid cell acknowledges the new set.

### Lifetimes

- SVIDs live 1 hour. **[call]** This is also the longest SPIRE server outage that open streams survive.
- TLS 1.3 has no renegotiation, so a stream opens a new connection when its SVID renews, and closes the old one after the handover.

## Provisioning flow **[owner, details are a call]**

1. Management records a pending cell: ID, environment, cluster reference, agent name and replica cap. Management chooses the cluster reference.
2. Management sends a signed, single-use order to the CCP. The order pins the cluster reference, the environment, and the digests of the bootstrap set and every image in it.
3. The CCP records the order ID durably, then relays the order to the provider adapter.
4. The adapter verifies management's signature, the caller's exact SPIFFE ID and the environment. It then creates exactly that cluster.
5. The adapter applies only the pinned bootstrap set: namespaces, Argo CD, the store, the worker and the network policy bundle. It reads the cluster facts that the policies need, so a cell never runs without default deny.
6. The adapter confirms the cluster reference. It returns no kubeconfig to the CCP.
7. Management calls `Lookup` with its own reference, signs the cell record and sends it to the CCP.
8. Worker sidecars attest to both SPIRE servers.
9. Workers register with management. Management marks the cell `valid`.
10. Workers connect to the CCP and accept operations.
11. The cell's Argo CD agent connects to the principal, and the cell appears in the central view.

Management receives no cell credential at any step. `Delete` also needs a management-signed
order.

### Provider adapter

```go
type Provider interface {
    Create(ctx context.Context, order SignedOrder) (ClusterRef, error) // CCP relays; management signs
    Lookup(ctx context.Context, ref ClusterRef) (ClusterKeys, error)   // Management only
    Delete(ctx context.Context, order SignedOrder) error              // CCP relays; management signs
}
```

| Adapter | Use | `Create` | `Lookup` |
| --- | --- | --- | --- |
| `local` | Mac demo | Host service runs `container cluster create` and applies the pinned bootstrap set | Host service reads `/openid/v1/jwks` |
| `kind` | Linux CI only | `kind create cluster` and the same bootstrap set | Reads `/openid/v1/jwks` |
| `aws` | EKS | Calls the EKS API, then uses a temporary access entry for bootstrap over the tailnet, and removes it | Separate read-only role reads the issuer JWKS |
| `gcp`, `azure`, `selfhosted` | Not built | Not built | Provider issuer, or operator enrolment of keys |

- The adapter authorizes the exact caller ID: `spiffe://env-dev.poc.internal/ccp` for `Create` and `Delete`, and `spiffe://management.poc.internal/control` for `Lookup`. **[call]**
- Each CCP may act only on cluster references of its own environment.
- The adapter is a tagged tailnet node. On EKS it runs outside every plane VPC, with its own IAM role. **[call]**
- The bootstrap access ends before the cell record exists.

### Revocation **[call]**

- Management marks a cell `revoked` in the registry, and signs a record with status `revoked`.
- Both gateways and the principal proxy drop that cell's streams at once, and refuse new ones.
- Management bans the cell's SPIRE agents, and deletes the cell's self-registered cluster Secret at the principal.
- The CCP stops work for the cell when it receives the revoked record, or when the last valid record expires, whichever comes first.

### Break-glass access **[call]**

- `mise run cell:break-glass <cell>` grants an operator Kubernetes access to one cell, over the tailnet only. A second command revokes it.
- Each grant is logged, and expires after 1 hour.
- The runbook covers a cell that has lost both streams.

## Operations

### Streams and claims

Each worker replica holds two outbound streams, one to management and one to the CCP.
**[owner: direct and cross-cutting paths; call: stream form]**

Management and the CCP each keep their own operation queue. Replicas compete for work:

1. A stream message signals that work exists, and it carries the current backlog.
2. A replica with free capacity claims the next operation under a time-limited lease.
3. The lease carries a fencing token that includes the queue epoch. The upstream refuses a result with an old token.
4. If a replica dies, the lease expires, and another replica claims the operation.

The worker pushes status on both streams. Read requests are normal operations, and their
results return on the same stream.

Stream health **[call]**:

- Clients send gRPC keepalives every 30 seconds, with a 10-second timeout, even with no active call.
- Servers allow pings every 20 seconds.
- An application heartbeat runs every 10 seconds. A stream with no heartbeat for 30 seconds is closed.
- Reconnects use jittered exponential backoff.

### Protocol versions **[call]**

- The stream protocol and the attestation payload carry a version.
- Server version N accepts clients N and N−1. The gate runs an N−1 worker and sidecar against N.
- All bespoke binaries come from one Go module with one release version.

### Sender rules

| Kind | Allowed sender | Example |
| --- | --- | --- |
| Direct | Management only | `cell.info`, `cell.bundle.apply` |
| Cross-cutting | The cell's own CCP only | `env.sleep`, `env.bundle.apply` |
| Cell-to-cell | A cell, to management only | `cell.request` |

- Each operation has a 128-bit random ID, an expiry, a kind and a target. The target is a named resource.
- The worker checks the kind against the stream peer before it starts work.
- An operation past its expiry is reported as `expired`, never silently dropped.

### Who may change what in a cell **[owner]**

The worker applies a separate allow-list for each sender:

| Sender | May change |
| --- | --- |
| Management | Network policy, mesh policy, Argo CD, `cell-system`, the worker and the collector |
| The cell's CCP | The environment's application components only |

- The worker refuses a bundle that touches a component outside its sender's list, with `component_not_allowed`.
- Each sender has its own Argo CD AppProject, limited to that sender's store path, namespaces and kinds. **[call]**
- The worker upgrades through a management bundle, with N−1 compatibility and the rollback below.

### Signed bundles and orders **[call]**

Each DSSE payload binds these fields: target cell and cluster, sender, component, operation
ID, expiry and a sequence number per sender and component.

- The worker refuses a sequence at or below the high-water mark for that sender and component.
- The worker keeps the high-water marks and the last digest for each sender in a ConfigMap. They are not secret.
- A rollback signs the old content again, with a new sequence.
- The CCP refuses an order for another environment, or an order ID that it has already used.

### Root bundle and rollback **[call]**

- The worker composes the root bundle from the last digest of each sender. It holds one cell-wide Lease while it composes.
- It updates the sender state with a compare-and-swap on the ConfigMap `resourceVersion`.
- It never publishes a root that lacks a digest for either sender.
- It reports an operation as done only when Argo CD reports the root Synced and Healthy at that digest.
- It keeps the last root digest that passed the health check.

After a management bundle, the health check needs three facts within 10 minutes: both streams
are up, Argo CD reports Synced and Healthy, and the store answers. If any fact fails, the
worker publishes the last good root again, and reports `rolled_back`.

The worker also refuses, before it publishes, a network policy bundle that would block the
endpoints in the current record.

Management sends a bundle to one canary cell first, and to other cells only after the canary
passes the health check.

After a stream reconnects, each sender sends its latest bundles again. A reconnect therefore
repairs a lost store.

### Proof of single application **[call]**

The synthetic kind `test.apply` writes a create-only record in the cell, named by the operation
ID. A second application of the same operation fails to create that record. The fan-out test
counts these records.

### Fan-out

The CCP splits one cross-cutting operation into one child per target cell cluster. It then
combines results by cell. An offline cell keeps its child until the child expires, and the
parent reports a partial result. **[call]**

Within a cell cluster:

- Each replica has an in-flight limit, and it reserves capacity for direct operations.
- A Kubernetes Lease per target allows one operation at a time. The lock lives in the cell, because neither upstream can see the other's queue.
- On EKS, direct operations meet a p95 latency of 5 seconds or less during a CCP fan-out. The local run records the latency but does not enforce it. **[call]**

### HPA **[owner: consider HPA; details are a call]**

The HPA scales on queued work plus work in progress, per replica. An empty queue does not mean
idle workers. Temporal users report early scale-down under fan-out when backlog is the only
signal.

- Each replica reports its backlog from both streams, and its used in-flight slots, to a small in-cell adapter.
- The adapter serves `external.metrics.k8s.io` to the HPA. It needs no inbound cross-cluster connection.
- `minReplicas` is 1, because a replica must hold a stream to see any backlog.
- `maxReplicas` limits the effect of a bad signal.
- A new replica reports ready when it holds at least one SVID and its stream. It claims work only on streams that it holds.
- On SIGTERM, a replica stops claims and finishes or abandons work. `terminationGracePeriodSeconds` exceeds the lease duration.

## Cell containment **[owner]**

- A cell has no PoC listener that another cluster can reach, and the network isolation rules deny every other source outside the cluster.
- A cell that needs another cell sends `cell.request` to management, on its management stream.
- Management reads the sender from the verified SVID, never from the request body.
- Management applies a default-deny policy of allowed cell pairs and kinds. The PoC policy allows one pair, for one read kind. **[call]**
- Management then sends a direct operation to the target cell, and returns the result to the sender.
- The CCP accepts no cell-to-cell kinds.

## Argo CD and hydrated resources **[owner]**

The base cell already applies hydrated bundles from an in-cluster store, pinned by digest. In
this design, the worker becomes the publisher:

1. An operation delivers a signed, hydrated bundle to the worker.
2. The worker verifies the signature and the sequence. It checks each object against its sender's allow-list of components, kinds and namespaces.
3. The worker pushes the bundle by digest to the in-cluster store, then composes the root bundle.
4. Argo CD applies it to its own cluster, within the sender's AppProject.

Store rules **[call]**:

- The store runs on a persistent volume, with registry garbage collection.
- Access to the store stays inside the cluster, so it depends on neither plane.
- The `cell-proxy` binary in token mode fronts the store. It checks a projected service account token with the cluster's own TokenReview API, for the audience `bundle-store`.
- The store allows writes only from the worker's service account, and reads only from Argo CD's repo server.
- A sidecar in `argocd-repo-server` adds its token to each request.

Management and the CCP use the same pattern, with their own service as publisher. The harness
seeds their first bundle. **[call]**

## SPIFFE proxy **[call]**

One small binary, `cell-proxy`, built in this repository with go-spiffe, handles every
connection that an upstream component cannot secure well itself:

| Mode | Used by | Behaviour |
| --- | --- | --- |
| `spiffe-client` | Argo CD agent, cell collector | Presents the pod's SVID. Accepts only the exact upstream SPIFFE ID |
| `spiffe-server` | Principal, telemetry gateway | Requires a client SVID that matches an anchored pattern. Sets the identity header from the verified SVID, and removes any copy that the client sent |
| `token` | Cell store | Checks a service account token with the local TokenReview API |

go-spiffe sources follow bundle and SVID changes at run time, so a CA rotation needs no
restart.

## Central Argo CD view **[owner]**

Management shows every cluster in one Argo CD view, with live manifests and logs. No
credential is copied between clusters for this. The view never changes a cell, even when
management is compromised.

### Components

- Management runs the Argo CD UI, API server, repo server and Redis, plus the Argo CD Agent principal.
- Each cell and the CCP keep their own Argo CD, and add an Argo CD agent in autonomous mode. **[owner: central view; call: autonomous mode]**
- Management's own Argo CD still manages management's own cluster, through the hybrid architecture. The fallback is a second core install in another namespace. **[call]**

### Identity and connection **[call]**

Argo CD Agent v0.10.0 has three behaviours that this design cannot accept as they are:

- In SPIRE mode, the agent accepts any SVID from the trust bundle as the principal (`AuthorizeAny()` in `pkg/client/remote.go`).
- In SPIRE mode, the principal reads the SPIRE bundle once at startup, so a CA rotation breaks every agent until a restart.
- The principal authenticates once, then issues a 5-minute access token and a 24-hour refresh token.

The design therefore does not use the built-in SPIRE mode. It uses the header-based mode with
`cell-proxy` on both ends:

1. The agent connects in plaintext to `cell-proxy` in `spiffe-client` mode, inside its own pod.
2. That proxy presents the agent SVID, and accepts only `spiffe://management.poc.internal/argocd/principal`.
3. At management, `cell-proxy` in `spiffe-server` mode accepts only the pattern `^spiffe://management\.poc\.internal/argocd-agent/([a-z0-9-]+)$`, and checks the registry for each stream.
4. It forwards to the principal on `127.0.0.1`, with the verified identity in the header.
5. The principal extracts the agent name from that header, and self-registration creates the cluster Secret.

The proxy closes a revoked agent's stream at once. That bounds the principal's own token
lifetimes. An `AuthorizeID` option for the agent is a candidate upstream contribution.

### The view cannot change a cell **[call]**

The boundary sits in the cell, not in management's RBAC:

- The agent's service account replaces the upstream agent role. It gets read verbs on Applications and AppProjects, the writes that autonomous mode needs (verify which at M8), and the built-in `view` ClusterRole.
- A ValidatingAdmissionPolicy denies every other write by the agent's service account. It also denies changes to `.operation` on any Application, so no sync or terminate can come from management.
- `view` excludes Secrets and `pods/exec`. The agent has no Secret access in any namespace, `argocd` too.
- Small aggregated roles add the Istio and Argo CD CRDs to `view`. Each new CRD needs the same check.
- Argo CD RBAC at management also denies sync, terminate, delete, action and exec. This is defence in depth, not the boundary.

### Upgrades **[call]**

The principal refuses any agent with a different version string (`principal/apis/auth/auth.go`).
An agent upgrade is therefore planned as one release:

1. A second principal at the new version starts beside the current one, on its own listener.
2. Each agent moves when its management bundle updates it. The endpoint set lists both principals.
3. The old principal stops when every valid cell has moved.

An alert fires while the count of connected agents is lower than the count of valid clusters.
The principal's beta active/passive HA is the path to principal redundancy after the PoC.

The agent and the principal run with their metrics listeners off, if the flags allow it. Verify
at M8.

### Versions

Argo CD Agent v0.10.0 is built against Argo CD v3.5.1. The base cell runs v3.6.1. Test that
pair of versions first. The fallback is the newest v3.5 release on every cluster. **[call]**

## Istio

Istio runs inside each cluster, as the base cell describes. It stays off the trust path
between planes:

- No mesh link joins two clusters. This also holds for two clusters in the same cell.
- The worker, the SPIRE sidecars, `cell-proxy` and the Argo CD agent run outside the mesh, in namespaces with no injection.
- Each cluster's mesh CA is a rebuildable key inside that cluster. Nothing outside the cluster trusts it.
- The cross-plane rejection tests give the same result with and without the mesh.

## Telemetry and alerts **[call]**

- Each cluster's collector sends OTLP to management's telemetry gateway, through `cell-proxy` in `spiffe-client` mode. The connection is outbound.
- Denial codes, attestation results and stream events reach management this way.
- If management is down, the collector keeps a bounded buffer and drops the oldest data first.

Signals and alerts:

| Signal | Alert when |
| --- | --- |
| SVID time to expiry, per sidecar | Less than 15 minutes |
| Attestation denials, by code | Any denial for a valid cell |
| Streams up, per cell and plane | A valid cell has no stream for 2 minutes |
| Root digest in the cell compared with the intended digest | They differ for 10 minutes |
| Argo CD health, per cluster | Not Healthy for 10 minutes |
| Queue age, per plane | Oldest operation older than half its expiry |
| Record age at the CCP | Older than 2 hours |
| Connected agents compared with valid clusters | Fewer connected agents |

## Rejection tests

Each row is an automated end-to-end test. Clients of PoC services see only `denied` and a
request ID. The code appears in logs and in the test assertion. For an upstream component,
the test asserts the observable result. A MITM test uses a valid SVID with the wrong ID, as
well as a self-made certificate.

| # | Attacker | Stopped at | Result |
| --- | --- | --- | --- |
| 1 | Rogue cluster runs a genuine worker | Both SPIRE servers | `unknown_cluster_keys` |
| 2 | Rogue cluster claims `cell-a-1`, with the same default issuer | Signature check | `token_invalid` |
| 3 | Pod in a real cell, with another service account or namespace | Attestor | `subject_mismatch` |
| 4 | Pod in a real cell, with a token for the wrong audience | Attestor | `audience_mismatch` |
| 5 | Expired token | Attestor | `token_expired` |
| 6 | Token requested with a lifetime of 1 year | Attestor lifetime check | `token_lifetime` |
| 7 | Token that is not bound to a pod | Attestor | `token_unbound` |
| 8 | Token replayed after a successful attestation | Attestor ID cache | `token_replayed` |
| 9 | Pod with the real service account, beyond the replica cap | Gateway count | `replica_cap` |
| 10 | Worker in cell A claims cell B | ID comes from verified claims | `cell_mismatch` |
| 11 | Compromised CCP mints a worker SVID and connects to management | Cell listener trusts only the management domain | `peer_untrusted` |
| 12 | Rogue SPIRE server with domain `env-other.poc.internal`, or with the name `env-dev.poc.internal` and another root, sends an operation | Worker TLS check | `peer_untrusted` |
| 13 | Direct kind on the CCP stream, or the reverse | Worker sender rules | `kind_not_allowed` |
| 14 | Unordered cell, a repeated order, or an order for another environment | CCP or adapter | `order_invalid` |
| 15 | CCP creates a rogue cluster, or reports another reference, for a pending cell | Management `Lookup` on its own reference | `lookup_mismatch`, or `unknown_cluster_keys` |
| 16 | CCP supplies a modified bootstrap set | Adapter checks the pinned digests | `order_invalid` |
| 17 | A worker presents a JWT-SVID with the CCP audience to the adapter | Adapter exact-ID check | `peer_not_allowed` |
| 18 | TLS interception, worker to management, with a self-made certificate or a valid SVID of another ID | Worker, before any token leaves | `peer_untrusted`, or `peer_not_allowed` |
| 19 | The same, worker to CCP | Worker | `peer_untrusted`, or `peer_not_allowed` |
| 20 | The same, SPIRE sidecar to SPIRE server | Sidecar, before any token leaves | Connection refused |
| 21 | The same, agent to principal. Includes a cell A worker SVID that poses as the principal to cell B | `cell-proxy` exact-ID check | `peer_not_allowed` |
| 22 | Self-made certificate at a listener, or a valid SVID of another domain or path | Listener | `peer_untrusted`, or `peer_not_allowed` |
| 23 | TCP relay that only forwards | Sees ciphertext only | The plaintext marker never appears |
| 24 | TCP relay that alters bytes | TLS, and the operation does not run | `peer_untrusted` |
| 25 | Tampered or unsigned hydrated bundle | Worker, and Argo CD does not change | `bundle_invalid` |
| 26 | CCP sends a bundle that changes network policy or Argo CD | Worker sender allow-list | `component_not_allowed` |
| 27 | Old, validly signed bundle replayed | Worker high-water mark | `bundle_replayed` |
| 28 | Bundle signed for cell A applied in cell B | Worker target check | `bundle_wrong_target` |
| 29 | Network policy bundle that blocks the plane endpoints | Worker check before publish | `policy_blocks_planes` |
| 30 | Argo CD's token writes to the store, or the worker's token reads as Argo CD | Store `cell-proxy` | `peer_not_allowed` |
| 31 | Stale fencing token after lease loss, or after a queue restore | Upstream queue | `lease_lost` |
| 32 | Pod in cell A, or in `rogue`, scans every pod IP, node address and NodePort in cell B | Isolation rules, and no PoC listener in cell B | Every connection fails |
| 33 | Cell A's service account token is presented to cell B's store | Cell B's TokenReview | `peer_not_allowed` |
| 34 | Cell A asks the CCP to reach cell B | CCP accepts no cell-to-cell kinds | `kind_not_allowed` |
| 35 | Cell A asks management to reach cell B, with no policy | Management policy | `cross_cell_denied` |
| 36 | Cell A names another cell as the sender | Management reads the sender from the SVID | `cell_mismatch` |
| 37 | Revoked cell reconnects, at both planes and the principal | Gateways, `cell-proxy` | `cell_revoked` |
| 38 | Revoked cell, while management cannot reach the CCP | CCP, after the record expires | `record_expired` |
| 39 | Rogue cluster runs a genuine Argo CD agent | Management SPIRE server | `unknown_cluster_keys` |
| 40 | Worker identity connects to the principal as an agent | `cell-proxy` pattern | `peer_not_allowed` |
| 41 | Cell A's agent reports Applications as cell B | Agent name comes from the SVID | Status appears under cell A only |
| 42 | `.operation` is set on a cell Application in management, directly with kubectl | ValidatingAdmissionPolicy in the cell | The cell Application does not change |
| 43 | Create, patch or delete through the live view, the root Application too | Agent RBAC and ValidatingAdmissionPolicy in the cell | Forbidden, and the cell does not change |
| 44 | Read a Secret in `argocd` or any other namespace through the live view | Agent RBAC in the cell | Forbidden |
| 45 | Request a cell B resource through cell A's agent | Principal, by agent name | Not found or refused |
| 46 | A CCP pod connects to a cell's Kubernetes API | Tailnet ACLs and private endpoint | Connection fails |
| 47 | Client on the internet, or a pod in another cluster, connects to a cell's Kubernetes API on EKS | Private endpoint | Connection fails |
| 48 | New pod on EKS sends traffic before its policy applies | VPC CNI strict mode | Traffic is dropped |

The gate also asserts these facts:

- The CCP holds no cell kubeconfig.
- No Argo CD has a remote cluster secret.
- No secret for Argo CD Agent exists outside management.
- No plane has an inbound path into a cell, apart from the tailnet paths.

## Survivability tests

Outage tests are event-driven, not fixed in time. Each test sets SVID lifetimes to 10 minutes
and the SPIRE intermediate CA lifetime to 30 minutes. **[call]**

| Test | Pass when |
| --- | --- |
| CCP cut off by policy | Direct operations continue. Management SVIDs renew twice. A new worker replica becomes ready |
| Management cut off by policy | Cross-cutting operations continue. Environment SVIDs renew twice. A new worker replica becomes ready |
| Partition without a pod restart, and a one-way partition | Streams recover, and the replica cap refuses no real replica |
| Two intermediate CA rotations, then every worker pod deleted | Every replica attests again |
| Cell service account key rotated, with two `--service-account-key-file` values | Attestation recovers within one immediate `Lookup` |
| Store pod deleted during a management outage | No Application is pruned, and the store refills after reconnect |
| Bad management bundle | The worker rolls back within 10 minutes, and the canary stops the rollout |
| Management cluster deleted, rebuilt from empty, then restored | Every cell reconnects with no step in any cell |
| CCP cluster deleted, rebuilt from empty, then restored | Every cell of the environment reconnects with no step in any cell |
| Attestation burst after an outage, at M9 load | Every sidecar attests within 5 minutes |

Every random choice in a test records its seed.

## Residual risks

The result must state these plainly:

- The cluster token signing key is the root of trust for a cluster. A cluster admin who can request tokens can act as that cluster's worker. Authorization limits this to one cell cluster.
- A rogue pod with the real service account and namespace, under the replica cap, looks like a replica. A ValidatingAdmissionPolicy narrows this path. The denial unit is the service.
- A token read from a live pod works elsewhere until it expires, at most 15 minutes, and only once, because of the token ID cache.
- Signature checks cannot tell that a pod or service account was deleted, as TokenReview could. The 15-minute token bound limits this exposure.
- A compromised CCP can mint environment identities. Signed orders stop it from a change to a new cell's bootstrap set.
- A compromised management plane can read every non-secret object in every cell through the live view. It cannot change a cell, except through signed worker operations.
- Compromised Argo CD effectively has cluster-admin in its own cluster.
- During a partition, a revoked cell can receive cross-cutting work for up to 6 hours.
- Locally, any cluster can reach another cluster's Kubernetes API on vmnet. That API still requires authentication. EKS removes this path with private endpoints.
- Argo CD Agent is a v0.x project in active development, and its principal HA is beta.

## Portability

Everything above the adapter stays the same on each host. The expected differences are:

| Concern | Local | CI | EKS | Others, not built |
| --- | --- | --- | --- | --- |
| Cluster creation | `container cluster` | kind on Linux | EKS API | Provider API |
| Cluster keys | Read from the API server by the host service | Read from the API server | Public issuer JWKS | GKE and AKS issuers. Self-hosted through operator enrolment |
| Plane endpoints | Mac relay at the vmnet gateway | Docker network relay | NLB with Elastic IPs | Provider load balancer |
| Kubernetes API | vmnet, which stands in for the tailnet | Runner network | Private endpoint, reached over the tailnet **[owner]** | Private endpoint |
| NetworkPolicy | kindnet | kindnet | VPC CNI in strict mode | Provider CNI |
| Plane database | Postgres on a persistent volume | The same | Managed Postgres-compatible service | Provider service |
| Keys | Secret manager CLI into Secrets | Generated per run | External store with sync | Provider store |

The NLBs have no source allow-list, because the identity check decides every access and cell
egress addresses change. **[call]** For the EKS milestone, the rogue cluster runs on the Mac,
off the tailnet.

## Testing tiers **[call]**

| Tier | Runs on | Covers |
| --- | --- | --- |
| Unit and component tests | GitHub CI | Go packages, the attestor, `cell-proxy`, signature and sequence checks |
| Linux gate | GitHub CI, with kind and the `kind` adapter | Acceptance checks and the rejection tests that do not need EKS |
| Mac gate | The owner's Mac | Everything in the Linux gate, on `container cluster` |
| EKS gate | Four EKS clusters | Everything, plus tests 47–48 and the latency bounds |

Hosted macOS runners cannot run `container`, because they do not allow nested virtualization.
The repository uses no self-hosted Mac runner, because it may become public.

## Prior art

No single system combines these parts. Each part has precedent:

| Part | Prior art |
| --- | --- |
| Token validation against exported cluster keys | Teleport `kubernetes` join method with `static_jwks`; SPIFFE `spire-identity-exchange` Kubernetes validator |
| Agents that connect out to a control plane | GKE Connect Agent, Azure Arc, Rancher. These tunnel API access, which this design avoids |
| Pull of specs from a queue, with no stored credentials | Redpanda BYOC |
| Hub and spoke with registration on both sides | Open Cluster Management |
| Central Argo CD view with agents | Argo CD Agent, which this design uses |
| Workers that compete for queued work, scaled by an autoscaler | Temporal with KEDA |

## Milestones

Each milestone closes with an automated test.

| # | Milestone | Done when |
| --- | --- | --- |
| M0 | Base cell | Done on 2026-11-07. One cell passes all 15 base checks |
| M1 | Harness, isolation and state | Five clusters start twice from clean, with storage, Postgres, the Mac relay and keys from the secret store. The `kind` adapter and the Linux gate run in CI. Test 32 passes |
| M2 | `cluster_jwt` attestor and SPIRE roots | A worker gets two SVIDs through two sidecars. Tests 1–8 and 20 pass. The CA rotation and key rotation tests pass |
| M3 | Registry, records and registration | Worker appears as `valid`. Tests 9–11 pass |
| M4 | Streams, operations and `cell-proxy` | Direct, cross-cutting and cell-to-cell operations, read requests and status work. Tests 12, 13, 18, 19, 22 and 33–36 pass |
| M5 | Provisioning | Checks 1–3 pass from one management request. Tests 14–17 pass |
| M6 | Malicious worker and MITM | Check 4 and tests 23 and 24 pass |
| M7 | Worker publishes bundles | A hydrated bundle reaches Argo CD in all clusters. Tests 25–30 pass, and the rollback and store loss tests pass |
| M8 | Central Argo CD view | Management shows all clusters with live manifests. Tests 21 and 39–45 pass |
| M9 | Fan-out, telemetry, revocation and outages | 1,000 operations with random replica kills lose none and apply none twice. Alerts fire on their conditions. Tests 31, 37 and 38 and the outage and partition tests pass |
| M10 | Disaster recovery | Both rebuild-from-empty tests pass, locally and in the Linux gate |
| M11 | EKS | The `aws` adapter creates cells. `mise run poc:gate` passes across four EKS clusters. Tests 46–48 and the latency bounds pass |

M11 touches a real AWS account, so it starts only after the owner approves the account and
the spend. **[call]**

## To verify at the milestone

| Item | Milestone | Fallback |
| --- | --- | --- |
| Pod-to-NodePort traffic across `container cluster` clusters, through the Mac relay | M1 | Stop and report |
| `--shared-image-store` serves ko images to cluster nodes | M1 | A registry container on vmnet |
| A storage provisioner that passes review, on `container cluster` | M1 | Stop and report |
| AdminNetworkPolicy on kindnet | M1 | Default deny in every namespace, maintained by the worker |
| Host service reachable from plane pods at the vmnet gateway address | M1 | A small adapter proxy on vmnet |
| Two SPIRE agent sidecars in one pod, each with its own socket | M2 | One sidecar with two agent processes |
| Sidecar SPIRE agent with the `unix` workload attestor | M2 | DaemonSet agent on platforms that allow it |
| The `disk` UpstreamAuthority with a root from a mounted Secret | M2 | Report, and redesign how roots load |
| Service account key rotation on `container cluster` nodes | M2 | Run that test in the Linux gate only |
| Argo CD OCI source through a localhost proxy that adds a token | M7 | Local TLS on the proxy |
| Argo CD Agent v0.10.0 with Argo CD v3.6.1 | M8 | The newest v3.5 release |
| Header-based agent authentication behind `cell-proxy` | M8 | Report, and consider the upstream `AuthorizeID` contribution |
| Writes that autonomous mode needs from the agent's service account | M8 | Report the gap |
| Principal next to management's own application controller | M8 | A second core install in another namespace |
| UI diff view through the resource proxy in autonomous mode | M8 | Report the gap |
| Metrics listeners off for the agent and the principal | M8 | NetworkPolicy blocks the listener |
| EKS issuer JWKS reachable while the API endpoint is private (not verified) | M11 | The adapter reads `/openid/v1/jwks` over the tailnet |
| How early EKS publishes a new service account key | M11 | Rely on the immediate `Lookup` |
| AdminNetworkPolicy, or an equivalent, on VPC CNI | M11 | Default deny in every namespace |
| Path MTU on each EKS path, with 64 KB frames | M11 | Lower the TLS record size |

## Open questions for the owner

- Whether clusters in the same cell call each other directly, or only through management. The PoC has one cluster per cell, so it does not depend on the answer.

## Left to the builder

- Database schema for the registry, records and queues.
- Protobuf definitions and the stream frame format.
- Choice of storage provisioner, Postgres operator and metrics adapter library. Each choice must pass third-party review.
- How to package the SPIRE plugins, within the distroless rule.
- Timer values, except where this document sets a bound.
- Layout of the new code in this repository.
