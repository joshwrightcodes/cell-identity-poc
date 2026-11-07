# Cell identity PoC: design

Status: draft for owner review, revision 3. Date: 2026-11-08. Facts that can change are as of
this date.

Source markers: **[owner]** means the project owner decided it. **[call]** means the author
chose it, and the owner can overrule it. **[canon]** means the Kiln design canon in the
`kiln-concept` repository says it. Text without a marker follows from those sources.

`docs/design/base-cell.md` describes the cluster template that every cluster uses. That
document is built and verified. This document builds on it.

Revision 3 adopts Kiln's layer model. Kiln is the management plane, each environment has an
environment control plane, and cells serve. It replaces the earlier model with a separate
management plane and a cell control plane, and the two identities for each worker that the
earlier model needed.

## Intent

The PoC proves that Kiln, its environment control planes and its cells can authenticate to
each other with SPIFFE identities. No credential is copied between clusters. An unexpected
cell is rejected, and that includes a cell that attempts a man-in-the-middle (MITM) attack.
**[owner]**

The PoC runs on one Mac with `container cluster`. The same design then deploys to EKS. Nothing
above the cell controller's provider backend depends on AWS. **[owner]**

## Domain model

```text
Kiln (management plane, decides)                                      [owner, canon]
└── <env> environment control plane, <env>-cp (executes)              [owner, canon]
    │   kiln-envd · SPIRE server · cell gateway · relay · cell controller with ACK
    └── cell (serves): one account, one VPC, one Kubernetes cluster   [canon]
            Argo CD · kiln-celld · bundle store · ops-runs · ack-system controllers
```

- `<env>` names the scope that one environment control plane serves. The design does not fix that scope. **[owner]**
- Kiln opens no connection into an environment or a cell. kiln-envd dials out to Kiln. **[canon]**
- Each layer continues with what it last knew when the layer above it is down. This is island mode. **[owner, canon]**
- Each cell runs its own Argo CD, which manages only that cell's cluster. **[owner]**
- Customer-data operations run inside the product cell. **[owner]**
- `kiln-celld` is the cell's executor, the counterpart of `kiln-envd`. It is a service with many replicas, not a node agent. **[owner]**
- Logs and other OpenTelemetry signals hold no personal data, only product identifiers for correlation. **[owner]**

## Acceptance checks

`mise run poc:demo` shows these checks, and `mise run poc:gate` asserts them. **[call]**

1. Kiln requests two new cells, and the environment control plane creates them.
2. Each cell's `kiln-celld` registers and authenticates with its environment control plane.
3. Both cells appear in Kiln as valid.
4. A third, malicious cell starts, and it is rejected.

The gate also covers these behaviours:

- Kiln sends operations to a cell and reads information from it, through the environment control plane. `kiln-celld` pushes status up.
- Kiln shows every cell in one Argo CD view, with live manifests and logs. The view cannot change a cell, even when Kiln is compromised.
- An environment cut off from Kiln, and a cell cut off from its environment control plane, both keep working on their last known state.
- A customer-data operation runs inside the cell, and an export leaves the cell only as ciphertext.
- Each case in "Rejection tests" fails with the stated result.
- The HPA scales `kiln-celld` under fan-out, with no lost operation and no double application.
- A rebuilt environment control plane takes back its cells with no manual step in any cell.

## Goals, non-goals and anti-goals

Goals:

- One attestation method across AWS, GCP, Azure and self-hosted clusters.
- Separate network and trust boundaries, with a test for each boundary.
- A local demo from a clean Mac, and a deployment to EKS.
- The latest stable release of each tool and component. **[owner]**
- Recovery from the loss of an environment control plane, with no credential copied and no manual step in a cell.

Non-goals:

- Kiln itself. The PoC includes a small Kiln stand-in: an API that holds intent, signs specs and hosts the Argo CD Agent principal.
- Node identity, TPM attestation or measured boot.
- Production HA and multi-region failover. The design names the HA path for each single component.
- GCP and Azure backends for the cell controller.
- A service mesh across clusters.
- IPv6 and dual-stack clusters. The harness refuses them. **[call]**

Anti-goals. The PoC fails if any of these hold, even when all tests pass:

- A long-lived credential is copied between clusters.
- A cell accepts an inbound connection from another cluster. The bootstrap and break-glass paths over the operator tailnet are the only exceptions.
- Kiln, the environment control plane or the central Argo CD view changes a cell by a path other than a `kiln-celld` operation.
- An environment or a cell stops serving because the layer above it is unreachable.
- Customer data leaves a cell in plaintext.
- AWS types or identifiers appear above the cell controller's provider backend.
- A test passes because a check was weakened, retried until green or stubbed.

## Constraints

- Local runtime: Apple `container` 1.7.1, from the signed GitHub release, managed by mise. **[owner]**
- Kubernetes v1.37.0 node image, pinned by digest.
- `container` clusters cannot be stopped and started again, so a Mac restart is a disaster recovery event.
- Go 1.27, module path `github.com/joshwrightcodes/cell-identity-poc`, ko for images and distroless images.
- Images: locally, ko builds into the `container` image store, and clusters use `--shared-image-store`. On EKS, images live in ECR. CI pushes through GitHub OIDC, and nodes pull with their IAM role.
- Telemetry goes through OpenTelemetry (OTLP) with the slog bridge. Do not add Prometheus client libraries, `/metrics` endpoints or ServiceMonitors.
- Upstream SPIRE and Argo CD Agent stay unforked. Fixes needed upstream are offered as contributions, after the owner approves each one.
- Read each third-party component before it runs, and report the result.
- Scripts do not write secrets to disk.
- Every repository may become public. Documents name roles, not people.

### Names **[call]**

| Kind | Rule | Examples |
| --- | --- | --- |
| Namespaces we own | End in `-system` | `cell-system`, `observability-system`, `istio-system` |
| Upstream namespaces | Keep the upstream name | `argocd`, `istio-egress`, `ack-system` |
| Workload namespaces | Plain names | `ops-runs`, product namespaces |
| Components | Named after their namespace | `observability-system` |
| Trust domains | `<subject>.<kind>.poc.internal` | `kiln.poc.internal`, `<env>.env.poc.internal`, `<cell>.mesh.poc.internal` |
| Kiln executors | `kiln-<scope>d` | `kiln-envd`, `kiln-celld` |

Local instances use `dev` as `<env>`: the clusters are `kiln`, `dev-cp`, `dev-cell-1`, `dev-cell-2` and `rogue`.

### Keys and roots of trust **[call]**

| Class | Members | Where it lives |
| --- | --- | --- |
| Roots of trust | Kiln's SPIRE root, each environment's SPIRE root, the offline recovery key | Secret store only |
| Kiln signing keys | Spec key, record key, platform bundle key, application bundle key, operation key | Kiln's secret store |
| Rebuildable keys | SPIRE intermediate CAs, the Argo CD Agent JWT key, mesh CAs | Generated inside the cluster, and generated again after a rebuild |

- Locally, `mise run keys:seed` reads each key from the secret manager CLI on standard input, and creates the Kubernetes Secret directly. Nothing is written to disk.
- On EKS, an external store holds the same keys. A provider-neutral sync delivers them, and each key rotates with one command.
- The offline recovery key never enters a cluster. It signs key set changes only.

## Topology and trust boundaries

| Cluster | Runs | Trust domain |
| --- | --- | --- |
| `kiln` | Kiln stand-in: intent, signed specs, key lookup, Argo CD Agent principal, telemetry gateway | `kiln.poc.internal` |
| `dev-cp` | kiln-envd, SPIRE server, cell gateway, relay, session broker, cell controller with ACK | `dev.env.poc.internal` |
| `dev-cell-1`, `dev-cell-2` | The base cell, plus `kiln-celld`, ops-runs, `ack-system` controllers | Identities from `dev.env.poc.internal`; mesh in `<cell>.mesh.poc.internal` |
| `rogue` | Genuine `kiln-celld` and agent images, plus attack tools | Unregistered |

Local size: `kiln` and `dev-cp` get 4 CPUs and 8 GB each, cells get 4 CPUs and 8 GB each, and
`rogue` gets 2 CPUs and 4 GB. The total is 18 CPUs and 36 GB. **[call]**

### Identities **[call]**

Each workload holds one SVID from the SPIRE server of its own layer's trust domain:

| Principal | SPIFFE ID |
| --- | --- |
| Kiln API | `spiffe://kiln.poc.internal/api` |
| Kiln Argo CD Agent principal | `spiffe://kiln.poc.internal/argocd/principal` |
| Kiln telemetry gateway | `spiffe://kiln.poc.internal/telemetry` |
| kiln-envd | `spiffe://<env>.env.poc.internal/kiln-envd` |
| Cell gateway, relay, session broker | `spiffe://<env>.env.poc.internal/cp/<name>` |
| kiln-celld | `spiffe://<env>.env.poc.internal/cell/<cell>/kiln-celld` |
| Argo CD agent | `spiffe://<env>.env.poc.internal/cell/<cell>/argocd-agent` |
| Cell collector | `spiffe://<env>.env.poc.internal/cell/<cell>/otel` |
| Explore gateway | `spiffe://<env>.env.poc.internal/cell/<cell>/explore` |
| SPIRE agent, per pod | `spiffe://<env>.env.poc.internal/spire/agent/cluster_jwt/<cell>/<pod-uid>` |

- Kiln and each environment pin each other's SPIRE root. Trust domains do not federate through bundle endpoints, so no connection goes into an environment.
- Authorization reads parsed path segments, never string prefixes.
- The `kiln-celld` identity is per service, so denial works per service and not per replica.

### Network flows

Every connection goes up a layer. **[owner, canon]**

| Source | Destination | Purpose |
| --- | --- | --- |
| Cell SPIRE sidecars | `<env>-cp` SPIRE server | Attestation and SVID renewal |
| kiln-celld | `<env>-cp` cell gateway | Operations, status, cell-to-cell requests |
| Argo CD agent, cell collector | `<env>-cp` relay, then Kiln | Status, live view and telemetry, end to end through a TLS passthrough relay |
| Explore gateway | `<env>-cp` session broker | Reverse tunnel for an approved session |
| kiln-envd | Kiln API | Pull signed specs, report status |
| `<env>-cp` relay | Kiln principal and telemetry gateway | Forward cell streams, without terminating TLS |
| Cell controller | Provider APIs | Create and delete cells |
| Cell controller, operators | A cell's Kubernetes API, over the tailnet | Bootstrap and break-glass only |

- Each listener trusts exactly one trust domain.
- Cross-cluster TLS ends only at the two endpoints, never at a load balancer, an ingress or the relay.
- Plane listeners see real client addresses, because SPIRE limits attestation to one attempt per second per address.
- No flow goes from one cell to another.

Zero trust rule: the identity check decides every access. Network controls only reduce exposure.

### Plane endpoints **[call]**

- The signed cell record carries an endpoint set for the environment control plane. During a move, the set holds the old and the new endpoints together.
- Locally, a relay on the Mac listens on fixed ports at the vmnet gateway address, and forwards to current node IPs. On EKS, each NLB has fixed Elastic IPs.
- NodePorts sit in the range 30000–32767.
- The NLBs have no source allow-list, because identity decides access and cell egress addresses change.

### Kubernetes API access **[owner]**

- A cluster's Kubernetes API is reachable only from the operators' tailnet. On EKS, each cluster has a private API endpoint only.
- Tailnet ACLs let only the operator and cell controller tags reach cell routes. Each cluster VPC has its own CIDR.
- Locally, vmnet stands in for the tailnet, so the local run cannot prove this property. The EKS run proves it.
- `rogue` is never on the tailnet.

### Network isolation **[call]**

- Each cluster gets its own VPC on EKS, with no peering between cluster VPCs.
- Every namespace has default deny, `kube-system` included. A cluster-scoped policy denies sources outside the cluster, through AdminNetworkPolicy where the CNI supports it.
- On EKS, VPC CNI runs network policy in strict mode.
- `kiln-celld` renders the rules that depend on cluster facts, and renders them again when nodes or EndpointSlices change.

## Identity

### Why a custom attestor

SPIRE's `k8s_psat` attestor validates through TokenReview, so a remote server needs a
kubeconfig for each cluster. That is a stored cross-cluster credential, so the PoC cannot use
it. The PoC adds a small NodeAttestor plugin pair, `cluster_jwt`. **[call]** It validates a
projected service account token against the public signing keys of that cluster. Teleport's
`static_jwks` join method and the SPIFFE `spire-identity-exchange` validator do the same. Read
both before the attestor is written.

### SPIRE roots and pinned bundles **[call]**

- Each SPIRE server uses the `disk` UpstreamAuthority with its domain's root CA from the secret store. The server rotates only its intermediate CA.
- Every sidecar pins the root CA, so a CA rotation never changes the anchor. `insecure_bootstrap` stays off.
- A rebuilt SPIRE server loads the same root, so every pinned bundle stays valid.

### Attestation

The SPIRE agent runs as a sidecar in each pod that needs an identity. It needs no DaemonSet,
host path, CSI driver or kubelet access. The sidecar verifies the exact server ID before it
sends a projected token with the audience `spire-<env>`.

The server plugin takes these steps. Any error denies:

1. It loads the cell record for the claimed cell from the current signed spec. It refuses a revoked cell.
2. It verifies the token signature against the cluster keys in that record, never against keys chosen by the `iss` claim.
3. It checks audience, namespace and service account against the record.
4. It requires a token bound to a pod, with the pod UID and node claims.
5. It requires a lifetime of 15 minutes or less, and an `iat` no older than 15 minutes.
6. It refuses a token ID (`jti`) that it has seen in the last 15 minutes.
7. It derives the agent ID and selectors from the pod UID.

A node alias entry maps cluster and service account selectors to the workload parent, so HPA
scale events write no entries.

### Independent key check **[call]**

The environment control plane creates cells, so it cannot also vouch for their keys:

- Kiln reads each new cluster's signing keys from the provider's public issuer, which needs no credential.
- Kiln signs the keys into the cell record, inside the environment spec. The SPIRE server attests only against keys from a Kiln-signed record.
- Kiln checks again every 15 minutes. kiln-envd asks Kiln for an immediate check when an attestor reports an unknown key ID, at most once per cluster per minute.
- Locally, the cell controller's `local` backend serves `/openid/v1/jwks` to Kiln as a stand-in for the public issuer.

### Signed specs and records **[canon, details are a call]**

- Each environment spec revision carries Kiln's signature and a monotonic revision. kiln-envd refuses an unsigned spec or an older revision.
- A cell record inside the spec holds the cell's cluster keys, endpoint set, agent name, replica cap, bundle key sets and status.
- Specs and records have no expiry, so island mode never stops an environment. Freshness comes from the revision.

### Signing keys and key sets **[call]**

- Each Kiln key has one purpose. The platform bundle key signs platform components. The application bundle key signs product services.
- A cell pins key sets, each with the current and the next key. A key set change needs signatures from the current key and the offline recovery key.
- A rotation publishes the next key first, and retires the old key only after every valid cell acknowledges the new set.

### Lifetimes

- SVIDs live 1 hour. This is also the longest SPIRE server outage that open streams survive.
- A stream opens a new connection when its SVID renews, and closes the old one after the handover.
- Nothing inside a cell needs an SVID to keep serving. The bundle store checks local service account tokens.

## Provisioning flow **[owner, canon; details are a call]**

1. A developer requests a cell in Kiln. An approver who is not the author approves it.
2. Kiln adds a pending cell to the environment spec: cell name, cluster reference, agent name, replica cap and the digests of the bootstrap set.
3. kiln-envd pulls the spec, and gives the step to the cell controller.
4. The cell controller creates the account, VPC and cluster through its provider backend: ACK on EKS, `container cluster` locally.
5. Over the tailnet, it applies only the pinned bootstrap set. The set holds namespaces, Argo CD, the bundle store, `kiln-celld`, network policy and the cluster facts. It then removes its own access.
6. Kiln reads the cluster's keys from the public issuer, and signs the cell record into a new spec revision.
7. Cell sidecars attest to the environment's SPIRE server.
8. `kiln-celld` connects to the cell gateway. kiln-envd reports the cell as valid, and Kiln shows it.
9. The cell's Argo CD agent connects to Kiln's principal through the relay.

### Cell controller **[owner: custom controller with ACK; details are a call]**

The cell controller runs in `<env>-cp`. It is the only component that knows a provider.

| Backend | Use | Creates clusters with | Reads keys with |
| --- | --- | --- | --- |
| `aws` | EKS | ACK controllers | Public issuer JWKS |
| `local` | Mac demo | `container cluster`, through a host service on the Mac | Host service serves `/openid/v1/jwks` |
| `kind` | Linux CI | kind | `/openid/v1/jwks` |

- The cell controller acts only on steps of a Kiln-signed spec, and only on cells of its own environment.
- It is a tagged tailnet node for bootstrap. Its bootstrap access ends before the cell record exists.
- Inside each cell, ACK controllers in `ack-system` and custom controllers in `cell-system` manage resources created after provisioning. They use the cell account's own roles through EKS Pod Identity. Their resource definitions arrive in Kiln-signed platform bundles.

### Revocation **[call]**

- When connected, Kiln marks a cell revoked in a new spec revision. The SPIRE server and the cell gateway refuse the cell at once, and the relay closes its agent and telemetry streams.
- In island mode, an operator revokes the cell locally at `<env>-cp` with one command over the tailnet. The action is audited locally, and reconciled with Kiln on reconnect.
- A revoked cell keeps serving its customers on its last known state. Stopping service is a decommission, not a revocation.

### Break-glass access **[call]**

- `mise run cell:break-glass <cell>` grants an operator Kubernetes access to one cell, over the tailnet only. A second command revokes it.
- Each grant is logged and expires after 1 hour.

## Operations

### Streams and claims

Each `kiln-celld` replica holds one outbound stream to the cell gateway. The environment
control plane keeps the operation queue, and replicas compete for work:

1. A stream message signals that work exists, and carries the current backlog.
2. A replica with free capacity claims the next operation under a time-limited lease.
3. The lease carries a fencing token that includes the queue epoch. A result with an old token is refused.
4. If a replica dies, the lease expires, and another replica claims the operation.

Stream health **[call]**: gRPC keepalives every 30 seconds with a 10-second timeout, an
application heartbeat every 10 seconds, and jittered backoff on reconnect.

### Operations and their signatures **[call]**

- Kiln signs every operation, bundle and session grant. The DSSE payload binds the target cell, the kind, the operation ID, the expiry and a sequence number.
- `kiln-celld` refuses an unsigned item, a sequence at or below its high-water mark, or an item for another cell.
- The environment control plane orders and relays work, but cannot forge or change it.
- Operation IDs are 128-bit random values. An operation past its expiry is reported as `expired`, never applied late.

### Replica cap **[call]**

- `kiln-celld` sends its pod UID in the stream hello. A new stream with the same pod UID replaces the old one.
- The gateway counts pod UIDs with a heartbeat in the last 30 seconds, shared through the database.
- The cap allows `maxReplicas`, plus rollout surge, plus one reconnect for each replica.

### Bundles, Argo CD and rollback **[owner: Argo CD per cell; details are a call]**

1. An operation delivers a signed, hydrated bundle to `kiln-celld`.
2. `kiln-celld` verifies the signature, the sequence and the target. It checks each object against the key's allow-list: platform components for the platform key, product namespaces for the application key.
3. It pushes the bundle by digest to the bundle store, and composes the root bundle under a cell-wide Lease.
4. Argo CD applies it to its own cluster, within an AppProject for each key.

- The root bundle never drops a component that the new bundle does not replace.
- `kiln-celld` reports an operation as done only when Argo CD reports the root Synced and Healthy at that digest.
- After a platform bundle, a health check runs for up to 10 minutes. It needs the stream up, Argo CD Synced and Healthy, and the bundle store answering. Otherwise `kiln-celld` publishes the last good root again, and reports `rolled_back`.
- `kiln-celld` refuses a network policy bundle that would block the endpoints in its record.
- Platform bundles go to one canary cell first.
- After a stream reconnects, kiln-envd sends the latest bundles again. A reconnect therefore repairs a lost bundle store.

### Customer-data operations **[owner; details follow the canon]**

- Each operation runs as one Kubernetes Job in the cell's `ops-runs` namespace, started by `kiln-celld`.
- Each run gets its own service account, credentials that last 1 hour or less, and egress only to its targets.
- `ops-runs` is outside the mesh. The data stores are managed services, so TLS and a per-request IAM credential protect that path. **[call]**
- Reports hold counts, never rows.
- Approval follows the canon: the author never approves, and deletion and unmasking need Data Protection.

### Exports **[owner: encrypted in transit and at rest; details are a call]**

- An export is encrypted inside the cell before it leaves.
- Each export gets its own data key, wrapped to a recipient key named in the signed request. The recipient's private key never enters the cell.
- The export goes to an export store in the cell's region, over mTLS. The store holds only ciphertext.
- A provider-neutral key adapter wraps the data key: KMS on EKS, a key from the secret store locally.

### Exploration **[call]**

| Kind | Path |
| --- | --- |
| Metadata discovery: schemas, sizes, indexes, plans | An ordinary read operation. Results are metadata, so they go up like status |
| Queries over customer rows | An interactive session through an in-cell explore gateway |

A session works like this:

1. Kiln signs a session grant bound to one person, cell, database, masking level and time limit of 60 minutes or less.
2. `kiln-celld` starts an explore gateway pod in `ops-runs`, with credentials that last 15 minutes each.
3. The gateway dials out to a session broker in the cell's region, run by the environment control plane, and holds a reverse tunnel.
4. The person connects to the broker. Their TLS runs end to end to the gateway, so the broker cannot read rows.
5. The gateway enforces read-only access, hides personal data by default, applies row limits and timeouts, and logs each query to Kiln, never its results.
6. The session ends at its time limit or on revocation, and the gateway pod is deleted.

Sessions need the environment control plane, so they are unavailable while a cell is an island.

### Fan-out and HPA **[owner: consider HPA; details are a call]**

- Kiln splits a fleet operation into one child per cell. An offline cell keeps its child until the child expires.
- Each replica has an in-flight limit.
- A Kubernetes Lease per target allows one operation at a time.
- The HPA scales on queued work plus work in progress, per replica, through a small in-cell metrics adapter. An empty queue does not mean idle workers.
- `minReplicas` is 1. A replica reports ready when it holds an SVID and its stream. Its liveness never depends on the upstream connection, so an island does not cause restarts.

### Cell-to-cell requests **[owner]**

- A cell that needs another cell sends `cell.request` to its environment control plane.
- The environment control plane reads the sender from the verified SVID. It applies a default-deny policy of allowed pairs and kinds, then sends an operation to the target cell.
- A request to a cell in another environment goes through Kiln, under the same kind of policy.

## Island mode **[owner]**

| Cut off | What keeps working | What stops |
| --- | --- | --- |
| An environment from Kiln | kiln-envd runs the last signed spec. SPIRE keeps issuing SVIDs. Queued operations still reach cells | New intent, new approvals, the central view and telemetry for that environment |
| A cell from its environment control plane | Customer traffic. Argo CD applies the last good state. In-cell controllers keep reconciling | New operations and bundles, exploration sessions, the central view for that cell |

- `kiln-celld` and the Argo CD agent keep running, and reconnect with jittered backoff.
- The collector keeps a bounded buffer, and drops the oldest data first.
- On reconnect, sidecars attest again, kiln-envd sends the latest bundles again, and local revocations reconcile with Kiln.

## Central Argo CD view **[owner]**

Kiln shows every cell in one Argo CD view, with live manifests and logs. No credential is
copied for it, and the view never changes a cell.

### Path **[call]**

1. The cell's Argo CD agent runs in autonomous mode, and connects in plaintext to `cell-proxy` in its own pod.
2. `cell-proxy` presents the agent SVID through the environment control plane's relay, which passes TLS through.
3. At Kiln, `cell-proxy` accepts only `^spiffe://[a-z0-9-]+\.env\.poc\.internal/cell/([a-z0-9-]+)/argocd-agent$`, with each environment's pinned root. It checks Kiln's registry for each stream.
4. It forwards to the principal on `127.0.0.1`, with the verified identity in the header.

Argo CD Agent v0.10.0 accepts any SVID as its principal in SPIRE mode, reads the SPIRE bundle
only at startup, and refreshes its own sessions for 24 hours. `cell-proxy` on both ends works
around all three. The agent requires an exact version match with the principal, so an upgrade
runs a second principal beside the first until every cell has moved.

### The view cannot change a cell **[call]**

- The agent's service account gets read verbs, the writes that autonomous mode needs (verify at M7), and the built-in `view` role.
- A ValidatingAdmissionPolicy in the cell denies every other write by that service account, and every change to `.operation`.
- `view` excludes Secrets and `pods/exec`.
- Argo CD RBAC at Kiln also denies sync, terminate, delete and exec, as defence in depth.

## `cell-proxy` **[call]**

One small binary, built in this repository with go-spiffe:

| Mode | Used by | Behaviour |
| --- | --- | --- |
| `spiffe-client` | Argo CD agent, cell collector | Presents the pod's SVID, and accepts only the exact upstream ID |
| `spiffe-server` | Kiln principal, Kiln telemetry gateway | Requires an anchored client ID pattern, checks the registry, sets the identity header and removes any copy from the client |
| `token` | Bundle store | Checks a service account token with the cell's own TokenReview API |

go-spiffe follows bundle and SVID changes at run time, so a CA rotation needs no restart.

## Telemetry **[owner: no personal data in signals; details are a call]**

- Each cell's collector sends OTLP through the relay to Kiln's telemetry gateway.
- The collector forwards only attributes on an allow-list, so the cell drops any other field.
- Pod logs in the live view come straight from Kubernetes, so they rest on the rule that services log only product identifiers.

| Signal | Alert when |
| --- | --- |
| SVID time to expiry | Less than 15 minutes |
| Attestation denials, by code | Any denial for a valid cell |
| Stream up, per cell | No stream for 2 minutes |
| Root digest compared with the intended digest | Different for 10 minutes |
| Argo CD health, per cell | Not Healthy for 10 minutes |
| Queue age | Oldest operation older than half its expiry |
| Connected agents compared with valid cells | Fewer connected agents |

## State and recovery **[call]**

| State | Lives in | After the loss of its cluster |
| --- | --- | --- |
| Intent, specs, approvals, registry | Kiln database | Restore Kiln. Environments keep running meanwhile |
| Operation queue, fencing epochs, SPIRE datastore | `<env>-cp` database | Restore from backup. SPIRE entries rebuild from the spec. Agents attest again |
| Roots of trust, signing keys | Secret store | Load again |
| Bundles and sender state | The cell's bundle store on a persistent volume, and a ConfigMap | kiln-envd sends bundles again on reconnect |

- Locally, Postgres runs on a persistent volume, and `mise run plane:backup` streams a backup to the Mac with no secret in it. On EKS, a managed Postgres-compatible service gives point-in-time recovery.
- Every cluster gets a storage provisioner, which passes the vendor review first.
- The HA path for a SPIRE server is a second server in another zone, with the same database and root.

## Rejection tests

Each row is an automated test. PoC services return only `denied` and a request ID; the code
appears in logs and in the test assertion. MITM tests use a self-made certificate and a valid
SVID with the wrong ID.

| # | Attacker | Stopped at | Result |
| --- | --- | --- | --- |
| 1 | Rogue cluster runs a genuine `kiln-celld` | SPIRE attestor: keys match no Kiln-signed record | `unknown_cluster_keys` |
| 2 | Rogue cluster claims a real cell's name, with the same default issuer | Signature check | `token_invalid` |
| 3 | Pod in a real cell, with another service account or namespace | Attestor | `subject_mismatch` |
| 4 | Token for the wrong audience | Attestor | `audience_mismatch` |
| 5 | Expired token | Attestor | `token_expired` |
| 6 | Token requested with a lifetime of 1 year | Attestor | `token_lifetime` |
| 7 | Token not bound to a pod | Attestor | `token_unbound` |
| 8 | Token replayed after a successful attestation | Attestor ID cache | `token_replayed` |
| 9 | Pod with the real service account, beyond the replica cap | Cell gateway | `replica_cap` |
| 10 | `kiln-celld` in cell A claims cell B | ID comes from verified claims | `cell_mismatch` |
| 11 | Environment control plane, or a gateway in it, forges or changes an operation or bundle | `kiln-celld` signature check | `signature_invalid` |
| 12 | Old, validly signed bundle or operation replayed | `kiln-celld` high-water mark | `replayed` |
| 13 | Item signed for cell A presented in cell B | `kiln-celld` target check | `wrong_target` |
| 14 | Application-key bundle that changes network policy or Argo CD | `kiln-celld` key allow-list | `component_not_allowed` |
| 15 | Network policy bundle that blocks the plane endpoints | `kiln-celld` check before publish | `policy_blocks_planes` |
| 16 | Spec with a lower revision, or no Kiln signature | kiln-envd | `spec_invalid` |
| 17 | Cell controller asked to create a cell with no Kiln-signed step, or with a modified bootstrap set | Cell controller | `step_invalid` |
| 18 | TLS interception, `kiln-celld` to the cell gateway | `kiln-celld`, before any token leaves | `peer_untrusted`, or `peer_not_allowed` |
| 19 | TLS interception, SPIRE sidecar to SPIRE server | Sidecar | Connection refused |
| 20 | TLS interception at the relay, Argo CD agent to Kiln's principal | `cell-proxy` exact-ID check | `peer_not_allowed` |
| 21 | Cell A's SVID poses as Kiln's principal to cell B | `cell-proxy` exact-ID check | `peer_not_allowed` |
| 22 | kiln-envd connects to a fake Kiln | kiln-envd pinned Kiln root | `peer_untrusted` |
| 23 | TCP relay that only forwards | Sees ciphertext only | The plaintext marker never appears |
| 24 | TCP relay that alters bytes | TLS | `peer_untrusted` |
| 25 | `kiln-celld` identity connects to the principal as an agent | `cell-proxy` pattern | `peer_not_allowed` |
| 26 | Agent from environment X claims a cell of environment Y | `cell-proxy` pins each environment's root to its own cells | `peer_not_allowed` |
| 27 | `.operation` set on a cell Application in Kiln, directly with kubectl | Admission policy in the cell | The cell does not change |
| 28 | Create, patch or delete through the live view, root Application included | Agent RBAC and admission policy in the cell | Forbidden |
| 29 | Read a Secret through the live view | Agent RBAC in the cell | Forbidden |
| 30 | Argo CD's token writes to the bundle store, or `kiln-celld`'s token reads as Argo CD | Store `cell-proxy` | `peer_not_allowed` |
| 31 | Stale fencing token | Queue | `lease_lost` |
| 32 | Pod in cell A, or in `rogue`, scans every pod IP, node address and NodePort in cell B | Isolation rules, and no listener in cell B | Every connection fails |
| 33 | Cell A asks to reach cell B, with no policy | Environment control plane policy | `cross_cell_denied` |
| 34 | Cell A names another cell as the sender | Sender comes from the SVID | `cell_mismatch` |
| 35 | Revoked cell reconnects | SPIRE server and cell gateway | `cell_revoked` |
| 36 | Operation Job reaches a host that is not its target | Run NetworkPolicy | Connection fails |
| 37 | Export written in plaintext, or to a store outside the cell's region | `kiln-celld` export check | `export_refused` |
| 38 | Session broker reads a session's rows | End-to-end TLS | Sees ciphertext only |
| 39 | Session used by another person, after its time limit, or for writes | Explore gateway | `session_denied` |
| 40 | A pod in another cluster, or on the internet, connects to a cell's Kubernetes API on EKS | Private endpoint | Connection fails |
| 41 | New pod on EKS sends traffic before its policy applies | VPC CNI strict mode | Traffic is dropped |

The gate also asserts that no long-lived credential exists in a cluster other than its owner,
and that no Argo CD has a remote cluster secret.

## Survivability tests

Outage tests are event-driven. Each sets SVID lifetimes to 10 minutes and the SPIRE
intermediate CA lifetime to 30 minutes.

| Test | Pass when |
| --- | --- |
| Kiln cut off from `dev-cp` | Queued operations continue. SVIDs renew twice. A new `kiln-celld` replica becomes ready |
| A cell cut off from `dev-cp` | Customer traffic continues. Argo CD keeps the last good state. No pod restarts |
| Partition without a pod restart, one-way too | Streams recover, and the replica cap refuses no real replica |
| Two intermediate CA rotations, then every `kiln-celld` pod deleted | Every replica attests again |
| Cell service account key rotated | Attestation recovers within one immediate key check |
| Bundle store pod deleted during an island | No Application is pruned, and the store refills after reconnect |
| Bad platform bundle | `kiln-celld` rolls back within 10 minutes, and the canary stops the rollout |
| `dev-cp` deleted, rebuilt from empty, then restored | Every cell reconnects with no step in any cell |
| Local revocation in island mode | The cell is refused at once, and Kiln shows the revocation after reconnect |

Every random choice in a test records its seed.

## Residual risks

- A cell's cluster token signing key is the root of trust for that cell. A cluster admin who can request tokens can act as that cell's `kiln-celld`.
- A rogue pod with the real service account and namespace, under the replica cap, looks like a replica. The denial unit is the service.
- A stolen token works once, for at most 15 minutes.
- A compromised environment control plane can mint identities in its environment and stop work from reaching cells. It cannot forge Kiln-signed work.
- A compromised Kiln can read every non-secret object in every cell through the live view. It cannot change a cell, except through signed `kiln-celld` operations, which a compromised Kiln can sign.
- During an island, a cell that Kiln revoked continues until an operator revokes it locally.
- Pod logs in the live view rest on the rule that services log no personal data.
- Locally, any cluster can reach another cluster's Kubernetes API on vmnet. EKS removes this path.
- Argo CD Agent is a v0.x project, and its principal HA is beta.

## Testing tiers **[call]**

| Tier | Runs on | Covers |
| --- | --- | --- |
| Unit and component tests | GitHub CI | Go packages, the attestor, `cell-proxy`, signature and sequence checks |
| Linux gate | GitHub CI, with kind | Acceptance checks and the rejection tests that do not need EKS |
| Mac gate | The owner's Mac | Everything in the Linux gate, on `container cluster` |
| EKS gate | EKS | Everything, plus tests 40–41 and the latency bounds |

## Prior art

| Part | Prior art |
| --- | --- |
| Token validation against exported cluster keys | Teleport `static_jwks` join method; SPIFFE `spire-identity-exchange` validator |
| Agents that connect out to a control plane | GKE Connect, Azure Arc, Rancher. These tunnel API access, which this design avoids |
| Pull of signed specs with no stored credentials | Redpanda BYOC; Kiln's own kiln-envd |
| Central Argo CD view with agents | Argo CD Agent, which this design uses |
| Workers that compete for queued work | Temporal with KEDA |

## Milestones

| # | Milestone | Done when |
| --- | --- | --- |
| M0 | Base cell | Done on 2026-11-07, renamed on 2026-11-08. 15 base checks pass |
| M1 | Harness, isolation and state | `kiln`, `dev-cp`, two cells and `rogue` start twice from clean, with storage, Postgres, the Mac relay and keys from the secret store. The Linux gate runs in CI. Test 32 passes |
| M2 | Attestor and SPIRE roots | `kiln-celld` gets an SVID through a sidecar. Tests 1–8 and 19 pass, and the rotation tests pass |
| M3 | Kiln stand-in, specs and records | kiln-envd pulls signed specs. A cell appears valid in Kiln. Tests 9, 10, 16 and 22 pass |
| M4 | Streams, operations and `cell-proxy` | Operations, status and cell-to-cell requests work. Tests 11–13, 18, 33 and 34 pass |
| M5 | Cell controller and provisioning | Checks 1–3 pass from one Kiln request. Test 17 passes |
| M6 | Malicious cell and MITM | Check 4 and tests 23 and 24 pass |
| M7 | Bundles and the central view | Bundles reach Argo CD in every cell, and Kiln shows every cell. Tests 14, 15, 20, 21 and 25–30 pass |
| M8 | Customer-data operations | Jobs, encrypted exports and exploration sessions work. Tests 36–39 pass |
| M9 | Fan-out, telemetry, revocation and island mode | 1,000 operations with random replica kills lose none and apply none twice. Tests 31 and 35 and the island tests pass |
| M10 | Disaster recovery | The `dev-cp` rebuild test passes, locally and in the Linux gate |
| M11 | EKS | The `aws` backend creates cells. `mise run poc:gate` passes on EKS, with tests 40 and 41 |

M11 touches a real AWS account, so it starts only after the owner approves the account and the
spend.

## To verify at the milestone

| Item | Milestone | Fallback |
| --- | --- | --- |
| Pod-to-NodePort traffic across `container cluster` clusters, through the Mac relay | M1 | Stop and report |
| `--shared-image-store` serves ko images to cluster nodes | M1 | A registry container on vmnet |
| A storage provisioner that passes review | M1 | Stop and report |
| AdminNetworkPolicy on kindnet | M1 | Default deny in every namespace, maintained by `kiln-celld` |
| Sidecar SPIRE agent with the `unix` workload attestor | M2 | DaemonSet agent where allowed |
| The `disk` UpstreamAuthority with a root from a mounted Secret | M2 | Redesign root loading |
| Service account key rotation on `container cluster` nodes | M2 | Run that test in the Linux gate only |
| Argo CD OCI source through a localhost proxy that adds a token | M7 | Local TLS on the proxy |
| Argo CD Agent v0.10.0 with Argo CD v3.6.1, header auth behind `cell-proxy` | M7 | The newest v3.5 release; the upstream `AuthorizeID` contribution |
| Writes that autonomous mode needs from the agent's service account | M7 | Report the gap |
| Principal metrics listener off | M7 | NetworkPolicy blocks it |
| EKS issuer JWKS reachable while the API endpoint is private | M11 | The cell controller serves the keys over the tailnet |
| AdminNetworkPolicy or an equivalent on VPC CNI | M11 | Default deny in every namespace |

## Departures from the Kiln canon

- The canon moves Argo CD into `<env>-cp`. This design keeps Argo CD in every cell, so a cell keeps its last good state on its own. **[owner]**
- The canon runs customer-data operations and the data gateway in a tools cell. This design runs them in the product cell. **[owner]**
- The canon's in-region workers reach Kiln's database directly. This design has `kiln-celld` claim work from the environment control plane over an authenticated stream.
- The canon uses Crossplane in its earlier boards. This design uses the custom cell controller with ACK. **[owner]**

## Open questions for the owner

- Whether clusters in the same cell call each other directly. The canon says a cell is one cluster, so the PoC assumes one.

## Left to the builder

- Database schema for specs, records and queues.
- Protobuf definitions and the stream frame format.
- Choice of storage provisioner, Postgres operator and metrics adapter library, after third-party review.
- How to package the SPIRE plugins, within the distroless rule.
- Timer values, except where this document sets a bound.
- Layout of the new code in this repository.
