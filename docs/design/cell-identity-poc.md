# Cell identity PoC: design

Status: draft for owner review. Date: 2026-11-08. Facts that can change are as of this date.

Source markers: **[owner]** means the project owner decided it. **[call]** means the author
chose it, and the owner can overrule it. Text without a marker follows from those decisions.

`docs/design/base-cell.md` describes the cluster template that every cluster in this design
uses. That document is built and verified. This document builds on it.

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
- Management shows every cluster in one Argo CD view, with live manifests, and nothing is copied between clusters for it. **[owner]**
- Each case in "Rejection tests" fails with the stated result.
- The HPA scales a worker under operation fan-out, with no lost operation and no double application.
- Direct operations continue while the CCP is down. Cross-cutting operations continue while management is down.

## Goals, non-goals and anti-goals

Goals:

- One attestation method across AWS, GCP, Azure and self-hosted clusters.
- Separate network and trust boundaries, with a test for each boundary.
- A local demo from a clean Mac, and a deployment to four EKS clusters.
- The latest stable release of each tool and component. **[owner]**

Non-goals:

- Node identity, TPM attestation or measured boot. A worker is a service, so these checks do not apply.
- Production HA, multi-region failover and fleet-scale load.
- GCP and Azure adapters. The design keeps their shape, but the PoC builds only `local` and `aws`.
- Worker self-update through Argo CD, approval workflows and compliance controls. **[call]**
- Creation of the management and CCP clusters by the system itself. The harness creates them. **[call]**
- A service mesh across clusters.

Anti-goals. The PoC fails if any of these hold, even when all tests pass:

- A long-lived credential is copied between clusters, or the CCP keeps a kubeconfig for a cell.
- A cell cluster accepts an inbound connection from another plane. The one exception is the provider bootstrap, which "Provider adapter" bounds.
- Management, the CCP or the central Argo CD view changes a cell by any path other than a worker operation.
- AWS types or identifiers appear above the provider adapter.
- A test passes because a check was weakened, retried until green or stubbed.
- The result claims a stronger property than the tests prove.

## Constraints

- Local runtime: Apple `container` 1.7.1, from the signed GitHub release, managed by mise. **[owner]** The Homebrew build of 1.7.1 has no cluster plugins.
- Kubernetes v1.37.0 node image, pinned by digest. kind itself is not used, because it has no provider for Apple `container`. **[call]**
- Versions are pinned in `mise.toml`, `cell.env` and the image digests. Each bump goes through the vendor review in `vendor/README.md`.
- Go 1.27, module path `github.com/joshwrightcodes/cell-identity-poc`, ko for images and distroless images.
- Locally, ko builds into the `container` image store, and clusters use `--shared-image-store`. On EKS, images live in ECR. CI pushes through GitHub OIDC, and nodes pull with their IAM role, so no pull secret is copied. **[call]**
- Telemetry goes through OpenTelemetry (OTLP) with the slog bridge. Do not add Prometheus client libraries, `/metrics` endpoints or ServiceMonitors.
- Upstream SPIRE and Argo CD Agent stay unforked. SPIRE is extended only through its plugin interfaces. **[call]**
- Read each third-party component before it runs, and report the result.
- Locally, each key and CA is generated inside the cluster that owns it. Scripts do not write secrets to disk. **[call]**
- On EKS, the four signing keys and the Argo CD Agent JWT key live in an external store. An engineer only sets or rotates a key there. A provider-neutral sync delivers it, and each key rotates with one command. **[call]**
- SPIRE keeps its CA keys in its own key manager, and rotates them itself. **[call]**
- Every repository may become public. Documents name roles, not people.

## Topology and trust boundaries

| Cluster | Role set on top of the base cell | SPIRE server |
| --- | --- | --- |
| `management` | Management API and registry, gateway, Argo CD UI and Agent principal | `management.poc.internal` |
| `ccp-dev` | CCP API, gateway, provider adapter client | `env-dev.poc.internal` |
| `cell-a-1` | Worker service, HPA, metrics adapter | None |
| `cell-b-1` | The same services | None |
| `rogue` | Genuine worker and agent images, plus attack tools | Its own, unregistered |

No SPIRE signing key sits in a cell cluster. A cell workload gets each identity from a SPIRE
server in another cluster, through an agent sidecar in its own pod.

Management and the CCP keep state that must survive a pod restart: the SPIRE datastore and CA,
the registry, the operation queue and the signing keys. Their role sets add a storage
provisioner, which passes the vendor review first. **[call]** EKS uses the EBS CSI driver.
Cells keep no state that the planes cannot publish again.

Local size: management and the CCP get 6 CPUs and 12 GB each, and cells get 4 CPUs and 8 GB
each. `rogue` gets 2 CPUs and 4 GB. **[call]** The base cell needs about 6 CPUs and 12 GB with
its demo workloads, so cells leave out the demo workloads.

### Two identities for each worker replica **[owner]**

Each worker replica holds two SVIDs, one from each upstream:

- A management SVID, issued by management's SPIRE server. The worker uses it only on its management stream.
- An environment SVID, issued by its CCP's SPIRE server. The worker uses it only on its CCP stream.

Because of this:

- Management rejects an unexpected worker by itself, at its own SPIRE server and gateway. Acceptance check 4 does not depend on the CCP.
- A compromised CCP can mint environment SVIDs, but not management SVIDs. It cannot open a management stream as a cell.
- Each path continues when the other plane is down.

Each worker pod runs two SPIRE agent sidecars, one for each server. **[call]** Each sidecar
serves its own Workload API socket, and the worker reads each socket for one stream only.

### SPIFFE IDs **[call]**

| Principal | SPIFFE ID |
| --- | --- |
| Management service | `spiffe://management.poc.internal/control` |
| Argo CD Agent principal | `spiffe://management.poc.internal/argocd/principal` |
| Worker, management identity | `spiffe://management.poc.internal/cell/<cell>/cluster/<cluster>/worker` |
| Argo CD agent in a cluster | `spiffe://management.poc.internal/cell/<cell>/cluster/<cluster>/argocd-agent` |
| CCP service | `spiffe://env-dev.poc.internal/ccp` |
| Worker, environment identity | `spiffe://env-dev.poc.internal/cell/<cell>/cluster/<cluster>/worker` |
| SPIRE agent, per pod | `spiffe://<domain>/spire/agent/cluster_jwt/<cell>/<cluster>/<pod-uid>` |

The worker identity is per service, so denial works per service and not per replica.
Authorization reads parsed path segments, never string prefixes.

The CCP cluster also runs an Argo CD agent, with the ID
`spiffe://management.poc.internal/ccp/<environment>/argocd-agent`. Management's own cluster
needs no agent. **[call]**

### Network flows

The less-trusted side opens every cross-cluster connection. **[call, consistent with the owner's requirement that the worker pushes status]**

| Source | Destination | Port | Purpose |
| --- | --- | --- | --- |
| Cell SPIRE agent, management sidecar | Management SPIRE server | TCP 8081, TLS | Attestation and SVID renewal |
| Cell SPIRE agent, environment sidecar | CCP SPIRE server | TCP 8081, TLS | Attestation and SVID renewal |
| Worker replica | Management gateway | TCP 8443, mTLS, one stream | Registration, direct operations, status, cell-to-cell requests |
| Worker replica | CCP gateway | TCP 8443, mTLS, one stream | Cross-cutting operations, status |
| Argo CD agent | Management Agent principal | TCP 8444, mTLS, gRPC | Application status and the live resource view |
| CCP service | Management gateway | TCP 8443, mTLS, one stream | Registration, provision orders, status |
| CCP SPIRE server | Management SPIRE bundle endpoint, and the reverse | HTTPS, SPIFFE auth | Federated bundle exchange for the CCP service only |
| CCP service | Provider adapter | Provider API | Create and delete a cell |
| Management service | Provider adapter | Provider API | Read cluster signing keys |

- Cross-cluster TLS does not terminate at a load balancer or ingress.
- Locally, flows use NodePorts on node IPs. On EKS, an NLB in TCP passthrough mode carries them.
- No flow goes from one cell to another.
- The base cell NetworkPolicy allows these flows only from `cell-system` and `argocd`.

Zero trust rule: the identity check decides every access. Network controls only reduce exposure.

### Kubernetes API access **[owner]**

- A cluster's Kubernetes API is reachable only from the operators' tailnet. Other clusters and the internet cannot reach it.
- On EKS, each cluster has a private API endpoint only. The provider adapter and the test harness reach it over the tailnet.
- Locally, every cluster shares vmnet, so vmnet stands in for the tailnet. The local run cannot prove this property. The EKS run proves it.
- The provider adapter and the test harness are operator tools on the tailnet. They are not planes, so the inbound rule does not apply to them.

## Identity

### Why a custom attestor

SPIRE's `k8s_psat` attestor validates through TokenReview. A remote server needs a kubeconfig
for each cluster
([docs](https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_k8s_psat.md),
checked 2026-11-07). That is a stored cross-cluster credential, so the PoC cannot use it.

The PoC adds a small SPIRE NodeAttestor plugin pair, `cluster_jwt`. **[call]** It validates a
projected service account token against the public signing keys of that cluster. The plugin
SDK lets a server plugin return the agent ID, selectors and `can_reattest`.

Prior art supports this approach. Teleport's `kubernetes` join method with `static_jwks`
validates service account tokens against exported keys, with no cluster access. The SPIFFE
`spire-identity-exchange` Kubernetes validator checks tokens against JWKS too. Read both before
the attestor is written, and reuse code where its licence and review allow.

### Attestation

The SPIRE agent runs as a sidecar in each pod that needs an identity. **[call]** It needs no
DaemonSet, host path, CSI driver or kubelet access.

The agent starts with a pinned trust bundle, and `insecure_bootstrap` stays off. It connects
to the server and verifies it. Only then does it send a projected token, with the audience
`spire-management` or `spire-env-dev`.

The server plugin takes these steps. Any error denies:

1. It reads the claimed cell and cluster from the request, and loads the signed cell record.
2. It verifies the token signature against the signing keys in that record. It never selects keys from the `iss` claim, because all local clusters share one default issuer.
3. It checks audience, expiry, namespace and service account against the record.
4. It reads the pod UID from the token, and derives the agent ID and selectors.

A node alias entry maps cluster and service account selectors to the workload parent, so HPA
scale events write no entries. The server prunes expired agents with
`prune_attested_nodes_expired_for` (SPIRE 1.13 or later).

### Replica cap

Each gateway counts live streams per worker service, and refuses a stream beyond the cap in
the cell record. **[call]** A dead pod drops its stream at once, so the count stays current.
The cap must allow `maxReplicas` plus rollout surge.

### Independent key lookup

The CCP creates cells, so it cannot be the source of cell signing keys. Management reads those
keys itself through `Lookup` on the provider adapter. It then signs them into the cell record,
and sends the record to the CCP. Management also calls `Lookup` again every 6 hours, and
updates the record when the keys change. **[call]**

Management's SPIRE server attests against the management copy of the record. The CCP's SPIRE
server attests against the copy that management sent.

### Federation

Federation carries only the CCP service identity to management, and the management identity to
the CCP. The harness pins each initial bundle at CCP enrolment. SPIFFE federation then rotates
bundles.

A cell workload needs no federation. Each of its sidecars holds the bundle of its own server.
A listener accepts peers only from its configured domain, and then applies an exact-ID or
registry check.

### Signing keys **[call]**

| Key | Owner | Signs |
| --- | --- | --- |
| Order key | Management | Provision orders |
| Record key | Management | Cell records |
| Direct bundle key | Management | Hydrated bundles for direct operations |
| Cross-cutting bundle key | CCP | Hydrated bundles for cross-cutting operations |

- Each key has one purpose. The worker pins both bundle public keys.
- A cell record has a monotonic revision and no short expiry. A lower revision is refused.
- Locally, a job inside the owner's cluster generates each key at first start, into a Secret. On EKS, the key comes from the external store.

### Lifetimes

- SVIDs live 1 hour. **[call]**
- A stream re-authenticates when its SVID renews, and closes if the renewal fails.

## Provisioning flow **[owner, details are a call]**

1. Management records a pending cell: ID, environment, cluster reference and replica cap. Management chooses the cluster reference. **[call]**
2. Management sends a signed, single-use order to the CCP over the CCP's stream. The order carries the cluster reference.
3. The CCP verifies the order and calls `Create` on the provider adapter, for exactly that reference.
4. The adapter creates the cluster and applies the base cell bootstrap set, the network policy bundle and the worker. The bootstrap set contains no secret.
   The adapter reads the cluster facts that the policies need, so a cell never runs without default deny. **[call]**
5. The adapter confirms the cluster reference. It returns no kubeconfig to the CCP.
6. Management calls `Lookup` with its own copy of the reference, signs the cell record and sends it to the CCP.
7. Worker sidecars attest to both SPIRE servers.
8. Workers register with management. Management marks the cell `valid`.
9. Workers connect to the CCP and accept operations.
10. The cell's Argo CD agent connects to the principal, and the cell appears in the central view.

Management receives no cell credential at any step.

### Provider adapter

```go
type Provider interface {
    Create(ctx context.Context, order CellOrder) (ClusterRef, error) // CCP role only
    Lookup(ctx context.Context, ref ClusterRef) (ClusterKeys, error) // Management role only
    Delete(ctx context.Context, ref ClusterRef) error                // CCP role only
}
```

| Adapter | `Create` | `Lookup` | Caller authentication |
| --- | --- | --- | --- |
| `local` | Host service runs `container cluster create` and applies the bootstrap set with its own kubeconfig | Host service reads `/openid/v1/jwks` | JWT-SVID with a per-role audience, over TLS with a pinned certificate |
| `aws` | Separate adapter service calls the EKS API, then uses a temporary access entry for bootstrap and removes it | Separate read-only role reads the issuer JWKS | EKS Pod Identity or IRSA inside the adapter |
| `gcp`, `azure`, `selfhosted` | Not built | Provider issuer, or operator enrolment of keys for self-hosted | Not built |

- The `aws` adapter runs as its own service, with its own IAM role and service account. The CCP never sees cluster-admin access. **[call]**
- The bootstrap access is the only inbound path into a cell. It ends before the cell record exists.
- The local host service stands in for a cloud API. It touches only clusters with the prefix `cell-`. **[call]**

### Revocation **[call]**

- Management marks a cell `revoked` in the registry.
- Both gateways drop that cell's streams at once, and refuse new ones.
- Management deletes the SPIRE entries for the cell, so no new SVID is issued.

## Operations

### Streams and claims

Each worker replica holds two outbound streams, one to management and one to the CCP.
**[owner: direct and cross-cutting paths; call: stream form]**

Management and the CCP each keep their own operation queue. Replicas compete for work:

1. A stream message signals that work exists, and it carries the current backlog.
2. A replica with free capacity claims the next operation under a time-limited lease.
3. The lease carries a fencing token. The upstream refuses a result with an old token.
4. If a replica dies, the lease expires, and another replica claims the operation.

The worker pushes status on both streams. Read requests are normal operations, and their
results return on the same stream.

### Sender rules

| Kind | Allowed sender | Example |
| --- | --- | --- |
| Direct | Management only | `cell.info`, `cell.bundle.apply` |
| Cross-cutting | The cell's own CCP only | `env.sleep`, `env.bundle.apply` |
| Cell-to-cell | A cell, to management only | `cell.request` |

- Each operation has an ID, an expiry, a kind and a target. The target is a named resource. **[call]**
- The worker checks the kind against the stream peer before it starts work.
- An operation past its expiry is reported as `expired`, never silently dropped.
- Provision orders and hydrated bundles also carry a DSSE signature, so a compromised gateway cannot forge them.

### Who may change what in a cell **[owner]**

The worker applies a separate allow-list for each sender:

| Sender | May change |
| --- | --- |
| Management | Network policy, mesh policy, Argo CD, `cell-system` and the worker |
| The cell's CCP | The environment's application components only |

- The worker refuses a bundle that touches a component outside its sender's list, with `component_not_allowed`.
- Each sender's components go in their own bundles. The root bundle pins every bundle by digest.
- The worker builds the root bundle from the latest bundle of each sender. A sender cannot remove or replace the other sender's bundles.

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
- Direct operations meet a p95 latency of 5 seconds or less during a CCP fan-out. **[call]**

### HPA **[owner: consider HPA; details are a call]**

The HPA scales on queued work plus work in progress, per replica. An empty queue does not mean
idle workers. Temporal users report early scale-down under fan-out when backlog is the only
signal.

- Each replica reports its backlog from both streams, and its used in-flight slots, to a small in-cell adapter.
- The adapter serves `external.metrics.k8s.io` to the HPA. It needs no inbound cross-cluster connection.
- `minReplicas` is 1, because a replica must hold a stream to see any backlog.
- `maxReplicas` limits the effect of a bad signal.
- A new replica reports ready when it holds at least one SVID and its stream. It claims work only on streams that it holds. **[call]**
- On SIGTERM, a replica stops claims and finishes or abandons work. `terminationGracePeriodSeconds` exceeds the lease duration.

## Cell containment **[owner]**

- A cell has no listener that another cluster can reach. The base cell NetworkPolicy blocks all egress except the listed flows.
- A cell that needs another cell sends `cell.request` to management, on its management stream.
- Management reads the sender from the verified SVID, never from the request body.
- Management applies a default-deny policy of allowed cell pairs and kinds. The PoC policy allows one pair, for one read kind. **[call]**
- Management then sends a direct operation to the target cell, and returns the result to the sender.
- The CCP accepts no cell-to-cell kinds.

## Argo CD and hydrated resources **[owner]**

The base cell already applies hydrated bundles from an in-cluster store, pinned by digest. In
this design, the worker becomes the publisher:

1. An operation delivers a signed, hydrated bundle to the worker.
2. The worker verifies the signature. It checks each object against its sender's allow-list of components, kinds and namespaces.
3. The worker pushes the bundle by digest to the in-cluster store, then the root bundle that pins it.
4. Argo CD applies it to its own cluster, within the `cell` AppProject.

- Access to the store stays inside the cluster, so it depends on neither plane. **[call]**
- A small auth proxy in front of the store checks a projected service account token with the cluster's own TokenReview API. The token audience is `bundle-store`.
- The store allows writes only from the worker's service account, and reads only from Argo CD's repo server.
- A sidecar in `argocd-repo-server` adds its token to each request. This replaces the plain HTTP of the base cell.
- Management and the CCP use the same pattern, with their own service as publisher. The harness seeds their first bundle. **[call]**

## Central Argo CD view **[owner]**

Management shows every cluster in one Argo CD view, with live manifests and logs. No
credential is copied between clusters for this. The view never changes a cell.

### Components

- Management runs the Argo CD UI, API server, repo server and Redis, plus the Argo CD Agent principal.
- Each cell and the CCP keep their own Argo CD, and add an Argo CD agent in autonomous mode. **[owner: central view; call: autonomous mode]**
- In autonomous mode, the cluster owns its Applications. The agent reports them up, and management cannot change their spec.
- Management's own Argo CD still manages management's own cluster. Argo CD Agent does not support an application controller next to the principal, except through its hybrid architecture. Verify that at the milestone. **[call]** The fallback is a second core install in another namespace.

### Identity

- The agent pod has a SPIRE agent sidecar that attests to management's SPIRE server with `cluster_jwt`.
- The principal uses SPIRE mTLS mode. It takes the agent name from the cluster segment of the agent's SPIFFE ID.
- SPIRE mode needs the principal's self-registration. Management SPIRE issues an agent ID only for a cluster with a signed record, so issuance is the gate.
- The principal's JWT signing key and its shared resource-proxy client certificate are generated inside management by a bootstrap job. They never leave management.
- No secret is created in a cell or CCP cluster for the agent.

### Live view, and its limits

- The resource proxy is on, at the principal and at every agent.
- The agent service account has its minimal role plus the built-in `view` ClusterRole. `view` is read-only, and excludes Secrets and `pods/exec`.
- Small aggregated roles add the Istio and Argo CD CRDs to `view`. Each new CRD needs the same check.
- Argo CD RBAC at management denies sync, terminate, delete, action and exec on every agent's Applications.
- Repository credentials never travel, because autonomous mode keeps them local, and the local store needs none.

### Versions

Argo CD Agent v0.10.0 is built against Argo CD v3.5.1. The base cell runs v3.6.1. Test that
pair of versions first. The fallback is the newest v3.5 release on every cluster. **[call]**

## Istio

Istio runs inside each cluster, as the base cell describes. It stays off the trust path
between planes:

- No mesh link joins two clusters. This also holds for two clusters in the same cell.
- The worker, the SPIRE sidecars and the Argo CD agent run outside the mesh, in namespaces with no injection.
- Each cluster's mesh CA is a signing key inside that cluster. Nothing outside the cluster trusts it.
- The cross-plane rejection tests give the same result with and without the mesh.

## Rejection tests

Each row is an automated end-to-end test. Clients of PoC services see only `denied` and a
request ID. The code appears in logs and in the test assertion. For an upstream component,
the test asserts the observable result.

| # | Attacker | Stopped at | Result |
| --- | --- | --- | --- |
| 1 | Rogue cluster runs a genuine worker | Both SPIRE servers | `unknown_cluster_keys` |
| 2 | Rogue cluster claims `cell-a-1`, with the same default issuer | Signature check | `token_invalid` |
| 3 | Pod in a real cell, with another service account or namespace | Attestor | `subject_mismatch` |
| 4 | Pod in a real cell, with a token for the wrong audience | Attestor | `audience_mismatch` |
| 5 | Expired token | Attestor | `token_expired` |
| 6 | Pod with the real service account, beyond the replica cap | Gateway stream count | `replica_cap` |
| 7 | Worker in cell A claims cell B | ID comes from verified claims | `cell_mismatch` |
| 8 | Compromised CCP mints a worker SVID and connects to management | Management accepts worker streams from its own domain only | `peer_not_allowed` |
| 9 | Rogue SPIRE server with domain `env-other.poc.internal`, or with the name `env-dev.poc.internal` and another key, sends an operation | Worker TLS check | `peer_untrusted` |
| 10 | Direct kind on the CCP stream, or the reverse | Worker sender rules | `kind_not_allowed` |
| 11 | Unordered cell, or a repeated order | CCP or management | `order_invalid` |
| 12 | CCP creates a rogue cluster, or reports another reference, for a pending cell | Management `Lookup` on its own reference, and attestation against those keys | `lookup_mismatch`, or `unknown_cluster_keys` |
| 13 | TLS interception, worker to management | Worker, before any token leaves | `peer_untrusted` |
| 14 | TLS interception, agent sidecar to SPIRE server | Sidecar, before any token leaves | `peer_untrusted` |
| 15 | Self-made certificate at a listener, or a valid management SVID on a path that is not its own | Listener | `peer_untrusted`, or `peer_not_allowed` |
| 16 | TCP relay that only forwards | Sees ciphertext only | The plaintext marker never appears |
| 17 | TCP relay that alters bytes | TLS, and the operation does not run | `peer_untrusted` |
| 18 | Tampered or unsigned hydrated bundle | Worker, and Argo CD does not change | `bundle_invalid` |
| 18a | CCP sends a bundle that changes network policy or Argo CD | Worker sender allow-list | `component_not_allowed` |
| 19 | Argo CD's token is used to write to the store, or the worker's token reads as Argo CD | Store auth proxy | `peer_not_allowed` |
| 20 | Stale fencing token after lease loss | Upstream queue | `lease_lost` |
| 21 | Pod in cell A connects directly to cell B | Egress policy in cell A, and cell B has no PoC listener | Connection fails |
| 22 | Cell A's service account token is presented to cell B's store | Cell B's TokenReview | `peer_not_allowed` |
| 23 | Cell A asks the CCP to reach cell B | CCP accepts no cell-to-cell kinds | `kind_not_allowed` |
| 24 | Cell A asks management to reach cell B, with no policy | Management policy | `cross_cell_denied` |
| 25 | Cell A names another cell as the sender | Management reads the sender from the SVID | `cell_mismatch` |
| 26 | Revoked cell reconnects | Both gateways | `cell_revoked` |
| 27 | Rogue cluster runs a genuine Argo CD agent | Management SPIRE server | `unknown_cluster_keys` |
| 28 | Worker identity connects to the principal as an agent | Principal auth pattern | Connection refused |
| 29 | Cell A's agent reports Applications as cell B | Agent name comes from the SVID | Status appears under cell A only |
| 30 | TLS interception, agent to principal | Agent | Connection refused, no data sent |
| 31 | Sync, delete or exec on a cell Application from management's UI | Argo CD RBAC at management | Permission denied |
| 32 | Read a cell Secret through the live view | Kubernetes RBAC in the cell | Forbidden |
| 33 | Request a cell B resource through cell A's agent | Principal, by agent name | Not found or refused |
| 34 | Client on the internet, or a pod in another cluster, connects to a cell's Kubernetes API on EKS | Private endpoint | Connection fails |

The gate also asserts these facts:

- The CCP holds no cell kubeconfig.
- No Argo CD has a remote cluster secret.
- No secret for Argo CD Agent exists outside management.

## Outage tests

"Down" means that policy cuts off the plane's gateway and SPIRE server, and then its pods restart. **[call]**
The tests set SVID lifetimes to 10 minutes, and each outage lasts 30 minutes.

- With the CCP down, direct operations and status to management continue. Management SVIDs renew, and a new worker replica becomes ready.
- With management down, cross-cutting operations continue. Environment SVIDs renew, and a new worker replica becomes ready.
- After each outage, streams reconnect without manual steps, and no operation is applied twice.

## Residual risks

The result must state these plainly:

- The cluster token signing key is the root of trust. A cluster admin who can request tokens can act as that cluster's worker. Authorization limits this to one cell cluster.
- A rogue pod with the real service account and namespace, under the replica cap, looks like a replica. A ValidatingAdmissionPolicy narrows this path. The denial unit is the service.
- A token read from a live pod works elsewhere until it expires. The Kubernetes minimum lifetime is 10 minutes. A test measures the real exposure.
- Signature checks alone cannot tell that a pod or service account was deleted, as TokenReview could. The token lifetime bounds this exposure.
- A compromised CCP can mint environment identities, and it can install a bad bootstrap set in a cell that it creates. Two identities stop only its path to management.
- A compromised management plane can read every non-secret object in every cell through the live view. It still cannot change a cell, except through worker operations.
- Compromised Argo CD effectively has cluster-admin in its own cluster.
- Locally, any cluster can reach another cluster's Kubernetes API on vmnet. That API still requires authentication. EKS removes this path with private endpoints.
- Argo CD Agent is a v0.x project in active development. Its principal has no HA, and its self-registration is a beta feature.

## Portability

Everything above the adapter stays the same on each host. The expected differences are:

| Concern | Local | EKS | Others, not built |
| --- | --- | --- | --- |
| Cluster keys | Read from the API server by the host service | Public issuer JWKS | GKE and AKS issuers. Self-hosted through operator enrolment |
| Cross-cluster path | NodePort on vmnet | Internet-facing NLB in TCP passthrough, limited by source CIDR **[call]** | Interconnect or public endpoint |
| Kubernetes API | vmnet, standing in for the tailnet | Private endpoint, reached over the tailnet **[owner]** | Private endpoint |
| NetworkPolicy | kindnet, verified in the base cell | VPC CNI with network policy turned on | Provider CNI |
| Cluster facts for policies | kubeadm configuration | EKS API and VPC data | Provider APIs |

For the EKS milestone, the rogue cluster runs on the Mac, and its source CIDR is allowed at the
NLBs. **[call]**

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
| M1 | Harness and spike | Five clusters start twice from clean. A pod in one cluster reaches a NodePort in another. A token validates against pinned keys. Test 21 passes |
| M2 | `cluster_jwt` attestor | A worker gets two SVIDs through two sidecars. Tests 1–5 and 14 pass |
| M3 | Registry and registration | Worker appears as `valid`. Tests 6–8 pass |
| M4 | Streams and operations | Direct, cross-cutting and cell-to-cell operations, read requests and status work. Tests 9, 10, 15 and 22–25 pass |
| M5 | Provisioning | Checks 1–3 pass from one management request. Tests 11 and 12 pass |
| M6 | Malicious worker and MITM | Check 4 and tests 13, 16 and 17 pass |
| M7 | Worker publishes bundles | A hydrated bundle reaches Argo CD in all clusters. Tests 18, 18a and 19 pass |
| M8 | Central Argo CD view | Management shows all clusters with live manifests. Tests 27–33 pass |
| M9 | Fan-out, revocation and outages | 1,000 operations with random replica kills lose none and apply none twice. The latency bound holds. Test 20, test 26 and the outage tests pass |
| M10 | EKS | The `aws` adapter creates cells. `mise run poc:gate` passes across four EKS clusters. Test 34 passes |

M10 touches a real AWS account, so it starts only after the owner approves the account and
the spend. **[call]**

## To verify at the milestone

| Item | Milestone | Fallback |
| --- | --- | --- |
| Pod-to-NodePort traffic across `container cluster` clusters | M1 | Stop and report |
| Host service reachable from a pod at the vmnet gateway address | M1 | A small adapter proxy on vmnet |
| Two SPIRE agent sidecars in one pod, each with its own socket | M2 | One sidecar with two agent processes |
| Sidecar SPIRE agent with the `unix` workload attestor | M2 | DaemonSet agent on platforms that allow it |
| Argo CD OCI source through a localhost proxy that adds a token | M7 | Local TLS on the proxy |
| `--shared-image-store` serves ko images to cluster nodes | M1 | A registry container on vmnet |
| A storage provisioner that passes review, on `container cluster` | M1 | Stop and report |
| Argo CD Agent v0.10.0 with Argo CD v3.6.1 | M8 | The newest v3.5 release |
| Principal next to management's own application controller | M8 | A second core install in another namespace |
| Agent checks the principal's exact SPIFFE ID, not only the trust domain | M8 | Report as a residual risk |
| UI diff view through the resource proxy in autonomous mode | M8 | Report the gap |
| EKS issuer JWKS reachable while the API endpoint is private (not verified) | M10 | The adapter reads `/openid/v1/jwks` over the tailnet |

## Open questions for the owner

- Whether clusters in the same cell call each other directly, or only through management. The PoC has one cluster per cell, so it does not depend on the answer.

## Left to the builder

- Queue store for management and the CCP, and the schema.
- Protobuf definitions and the stream frame format.
- Choice of store auth proxy, storage provisioner and metrics adapter library. Each choice must pass third-party review.
- How to package the SPIRE plugins, within the distroless rule.
- Timer values, except where this document sets a bound.
- Layout of the new code in this repository.
