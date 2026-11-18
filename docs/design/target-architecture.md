# Cell identity: target architecture

Status: draft for owner review, revision 5. Date: 2026-11-08. Facts that can change are as of
this date.

This is the reference design. `docs/design/poc-scope.md` says what the first build proves, and
which parts of this design it simplifies or defers.

Source markers: **[owner]** means the project owner decided it. **[call]** means the author
chose it, and the owner can overrule it. **[canon]** means the Kiln design canon in the
`kiln-concept` repository says it. Text without a marker follows from those sources.

`docs/design/base-cell.md` describes the cluster template that every cluster uses. That
document is built and verified. This document builds on it.

Revision 5 applies a third round of security, network, DevOps and infrastructure reviews.
Each finding that depends on upstream behaviour was checked against upstream source or
documentation on 2026-11-08.

## Intent

The PoC proves that Kiln, its environment control planes and its cells can authenticate to
each other with SPIFFE identities. No credential is copied between clusters. An unexpected
cell is rejected, and that includes a cell that attempts a man-in-the-middle (MITM) attack.
**[owner]**

The PoC runs on one Mac, with kind clusters in a Colima VM. The same design then deploys to EKS. Nothing
above the cell controller's provider backend depends on AWS. **[owner]**

## Domain model

```text
Kiln (management plane, decides)                                      [owner, canon]
└── <env> environment control plane, <env>-cp (executes)              [owner, canon]
    │   envd · SPIRE server · cell gateway · relay · cell controller with ACK
    └── cell (serves): one account, one VPC, one Kubernetes cluster   [canon]
            Argo CD · celld · bundle store · ops-runs · ack-system controllers
```

- `<env>` names the scope that one environment control plane serves. The design does not fix that scope. **[owner]**
- Kiln opens no connection into an environment or a cell. Every connection goes up a layer. **[owner, canon]**
- Each layer keeps on with what it last knew when the layer above it is down. This is island mode, and an island is an incident. **[owner]**
- Each cell runs its own Argo CD, which manages only that cell's cluster. **[owner]**
- Customer-data operations run inside the product cell. **[owner]**
- `celld` is the cell's executor, the counterpart of `envd`. It is a service with many replicas. **[owner]**
- Logs and other OpenTelemetry signals hold no personal data, only product identifiers. **[owner]**
- Cells check approvers' own signatures, so a compromised Kiln alone cannot export or unmask data. **[owner]**

## Phases **[owner]**

`docs/design/poc-scope.md` defines the first build. Sections marked **[phase 2]** come in later
increments, listed under "Milestones".

## Acceptance checks

`mise run poc:demo` shows these checks, and `mise run poc:gate` asserts them. **[call]**

1. Kiln requests two new cells, and the environment control plane creates them.
2. Each cell's `celld` registers and authenticates with its environment control plane.
3. Both cells appear in Kiln as valid.
4. A third, malicious cell starts, and it is rejected.

The design also covers these behaviours:

- Kiln sends operations to a cell and reads information from it, through the environment control plane.
- Kiln shows every cell in one Argo CD view, with live manifests. The view cannot change a cell.
- An environment cut off from Kiln, and a cell cut off from its environment control plane, continue on their last known state.
- A customer-data operation runs inside the cell, and an export leaves only as ciphertext, after approvers sign it.
- A bad `celld`, Argo CD or platform bundle rolls back with no step in the cell, and no rollback deletes a provider resource.
- Each case in "Rejection tests" fails with the stated result.

## Goals, non-goals and anti-goals

Goals:

- One attestation method across AWS, GCP, Azure and self-hosted clusters.
- Separate network and trust boundaries, with a test for each boundary.
- A local demo from a clean Mac. EKS follows in phase 2.
- The latest stable release of each tool and component. **[owner]**

Non-goals:

- Kiln itself. The PoC includes a Kiln stand-in, sized in "Kiln stand-in".
- Node identity, TPM attestation or measured boot.
- Production HA. The design names the HA path for each single component.
- GCP and Azure backends for the cell controller.
- A service mesh across clusters.
- IPv6 and dual-stack clusters. The harness refuses them.

Anti-goals. The PoC fails if any of these hold, even when all tests pass:

- A long-lived credential is copied between clusters. A bootstrap credential is short-lived, scoped and removed by a separate actor.
- A cell accepts an inbound connection from another cluster. Bootstrap and break-glass over the operator tailnet are the only exceptions.
- Kiln, the environment control plane or the central view changes a cell by any path other than a signed `celld` operation.
- An environment or a cell stops service to customers because the layer above it is unreachable.
- Customer data leaves a cell in plaintext, by any path, logs included.
- A rollback deletes a provider resource.
- AWS types or identifiers appear above the cell controller's provider backend.
- A test passes because a check was weakened, retried until green or stubbed.

## Constraints

- Local runtime: kind 0.33.0 on a Colima 0.10.3 VM with the Docker runtime. **[owner]** The repository's `mise.toml` pins every tool, and mise tasks are the only entry points. The harness asserts the exact versions.
- Kubernetes v1.37.0 node image, pinned by digest.
- kind clusters do not survive a restart of the Colima VM. The M1 restart check showed nodes that return to Ready, but `istiod` and the mesh pods do not recover. A Mac restart is a disaster recovery event, and the Mac must stay awake for the whole gate.
- Go 1.27, module path `github.com/joshwrightcodes/cell-identity-poc`, ko for images and distroless images. Every bespoke binary comes from one Go module with one release version.
- Images: locally, ko pushes to one registry container on the `kind` network, and each node's containerd uses it as a mirror. On EKS, images live in ECR. CI pushes through GitHub OIDC, and nodes pull with their IAM role.
- Telemetry leaves a cluster only as OpenTelemetry (OTLP). **[owner]** Bespoke binaries write every log as compact JSON, one object per line, to stdout, and export OTLP, with no Prometheus client libraries or ServiceMonitors. A command whose stdout carries data prints only that data on success, and one JSON error line on failure. Upstream components use their JSON log format where they have one. Upstream components that expose only Prometheus metrics keep their endpoint, and only the collector in the same cluster may scrape it.
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
| Trust domains | `<subject>.<kind>.poc.internal` | `mgmt.poc.internal`, `<env>.env.poc.internal`, `<cell>.mesh.poc.internal` |
| Executors | `<scope>d` | `envd`, `celld` |
| Agent names | `<env>-<cell>` | `dev-dev-cell-1` |

Local instances use `dev` as `<env>`: the clusters are `management`, `dev-cp`, `dev-cell-1`, `dev-cell-2` and `rogue`. M1 renames the base cell from `cell-a-1`.

### Keys and roots of trust **[call]**

| Class | Members | Where it lives |
| --- | --- | --- |
| Offline roots | Each trust domain's root CA, the five recovery keys | Offline. Used only to sign intermediates and the changes in the signer matrix |
| Online intermediates | Each SPIRE server's upstream intermediate, valid 30 days | The secret store, delivered to that SPIRE server |
| Kiln signing keys | Spec, record, platform bundle, application bundle and operation keys | Kiln's secret store |
| Approver keys | One signing key per approver, held on the approver's device | Never in a cluster. Public keys travel in signed approver directories |
| Rebuildable keys | SPIRE server CAs, the Argo CD Agent JWT key, mesh CAs | Generated inside the cluster |

- Locally, the secret manager holds each key at `<cluster>/<service>/<key>`. The External Secrets Operator syncs the keys into a Kubernetes Secret in the cluster. Unit tests generate throwaway keys in memory.
- On EKS, an external store holds the online keys. A provider-neutral sync delivers them, and each key rotates with one command.
- Key set changes follow the signer matrix in "Key rotation and recovery".

## Topology and trust boundaries

| Cluster | Runs | Trust domain |
| --- | --- | --- |
| `management` | Kiln stand-in: intent, approvals, signed specs, key checks, Argo CD Agent principal, telemetry gateway. Also a SPIRE server for Kiln's own workloads, the observability stack and Kiali | `mgmt.poc.internal` |
| `dev-cp` | envd, SPIRE server, cell gateway, relay, cell controller with ACK, local alert rules | `dev.env.poc.internal` |
| `dev-cell-1`, `dev-cell-2` | The base cell, plus `celld`, its watchdog, `ops-runs`, `ack-system` controllers | Identities from `dev.env.poc.internal`; mesh in `<cell>.mesh.poc.internal` |
| `rogue` | The attestation client of `celld`, plus attack tools | Unregistered |

Local size is measured at M1, and the README states it. The Mac has 18 cores and 64 GB, so the
gate keeps headroom for the builder and ko. **[call]**

### Kiln stand-in **[call]**

The stand-in holds only what the tests need: intent and approvals for two environments, the
signing keys, the key check, a registry of cells, the Argo CD UI with the principal, and the
telemetry gateway. It has no developer portal, catalog or workflow engine.

### Identities **[call]**

| Principal | SPIFFE ID |
| --- | --- |
| Kiln API | `spiffe://mgmt.poc.internal/api` |
| Kiln principal proxy | `spiffe://mgmt.poc.internal/argocd/principal` |
| Kiln telemetry gateway | `spiffe://mgmt.poc.internal/telemetry` |
| envd | `spiffe://<env>.env.poc.internal/envd` |
| Cell gateway, relay | `spiffe://<env>.env.poc.internal/cp/<name>` |
| celld | `spiffe://<env>.env.poc.internal/cell/<cell>/celld` |
| Argo CD agent | `spiffe://<env>.env.poc.internal/cell/<cell>/argocd-agent` |
| Cell collector | `spiffe://<env>.env.poc.internal/cell/<cell>/otel` |
| Plane collector | `spiffe://<env>.env.poc.internal/cp/otel` |
| Cell mesh tunnel | `spiffe://<env>.env.poc.internal/cell/<cell>/mesh-view` |
| Kiln Kiali | `spiffe://mgmt.poc.internal/kiali` |
| SPIRE agent, per pod | `spiffe://<env>.env.poc.internal/spire/agent/cluster_jwt/<cell>/<pod-uid>` |

- Kiln and each environment pin each other's root CA. Trust domains do not federate through bundle endpoints.
- Authorization reads parsed path segments, never string prefixes.
- The `celld` identity is per service. The pod UID comes from the attested SPIRE agent, never from the client.

### Second proof for traffic to Kiln **[call]**

The environment's SPIRE server can mint any identity in its environment. Everything a cell
sends up to Kiln therefore carries a second proof that the environment control plane cannot
mint:

- Each upward stream, and each result, acknowledgement and high-water mark that `celld` reports through envd, carries a projected service account token from the cell.
- The token's audience names Kiln and the item, for example `mgmt-result/<cell>/<operation-id>`.
- Kiln verifies the token against the cluster keys in the Kiln-signed cell record, and checks that its subject matches the reported cell.
- Kiln's root is pinned in each cell at bootstrap and read from a static file, never from the Workload API. The environment control plane therefore cannot pose as Kiln to a cell.

A compromised environment control plane can still drop or delay traffic. It cannot pose as a
cell to Kiln, or as Kiln to a cell. The issuer binding is trust on first use: the environment
control plane chooses which cluster it creates, and the nonce token proves only that the
cluster answers.

### Network flows

Every connection goes up a layer. **[owner, canon]**

| Source | Destination | Purpose |
| --- | --- | --- |
| Cell SPIRE sidecars | `<env>-cp` SPIRE server | Attestation and SVID renewal |
| celld | `<env>-cp` cell gateway | Operations, status, cell-to-cell requests |
| Argo CD agent, cell collector | `<env>-cp` relay, then Kiln | Status, live view and telemetry |
| envd | Kiln API | Pull signed specs, report status |
| `<env>-cp` relay | Kiln listener for that environment | Forward cell streams |
| Cell controller | Provider APIs | Create and delete cells |
| Bootstrap actor, operators | A cell's Kubernetes API, over the tailnet | Bootstrap and break-glass only |

- Each Kiln listener serves one environment and trusts that environment's root only.
- Cross-cluster TLS never ends at a load balancer or an ingress. At the relay, only the outer layer ends; the inner layer ends at its two endpoints.
- No flow goes from one cell to another.

Zero trust rule: the identity check decides every access. Network controls only reduce exposure.

### The relay **[call]**

The relay carries agent and telemetry streams from cells to Kiln. Each stream has two TLS
layers:

1. An outer mTLS layer, which ends at the relay: the cell presents its SVID, and the relay presents `cp/relay` to Kiln.
2. An inner TLS layer from the cell's `cell-proxy` to Kiln's `cell-proxy`, which ends only at those two endpoints.

The cell's `cell-proxy` expects the relay's ID on the outer layer and Kiln's ID on the inner
layer. Because the relay sees the outer identity, it:

- routes by the inner SNI, checked against the endpoints in the cell's signed record;
- authorizes each cell against the current spec, and closes its streams when the cell is revoked;
- caps connections and bytes per cell, and enforces handshake and first-byte timeouts;
- ends each downstream stream when its upstream connection ends.

Agent and telemetry streams use separate relay deployments, so a telemetry backlog after an
island cannot starve the live view. Kiln's listener admits only relays.

### Plane endpoints **[call]**

- The signed cell record carries an endpoint set for the environment control plane. During a move, the set holds the old and the new endpoints together. Every client tries each address in the set.
- The SPIRE agent takes one server address, so each sidecar connects through a small local forwarder that tries the endpoint set.
- The endpoints outlive the environment control plane. On EKS, the provider backend owns each NLB and its target groups outside `<env>-cp`, with cross-zone load balancing on. TargetGroupBinding binds them to the cluster. A PrivateLink endpoint service is the alternative if internet exposure is not wanted.
- Locally, every node is a container on the shared `kind` network in the Colima VM. The endpoint set holds node addresses on that network, so no relay on the Mac is needed.
- NodePort values are pinned, in the range 30000–32767. Plane listeners use `externalTrafficPolicy: Local`, and each platform has its own ingress rule for them.
- The NLBs have no source allow-list. A pre-authentication limiter in front of each plane listener bounds handshakes and connections.

### Kubernetes API access **[owner]**

- A cluster's Kubernetes API is reachable only from the operators' tailnet. On EKS, each cluster has a private API endpoint only.
- Tailnet access to a cell uses grants whose destination is that cell's CIDR, through that cell's router tag. Tags alone do not control subnet routes.
- The bootstrap actor has its own grant, which Kiln deletes at the end of bootstrap. The gate tests that a connection then fails, not only that the grant is gone.
- Each cell has two subnet routers outside its cluster, with persisted state, so break-glass does not depend on the cell's cluster or on Kiln. Operators re-enrol a router with their own tailnet admin role.
- Each cell has a unique CIDR allocation, recorded in the signed record. Routes are approved only for that CIDR.
- Locally, the shared `kind` network stands in for the tailnet, so the local run cannot prove this property. The EKS run proves it.

### Network isolation **[call]**

- Each cluster gets its own VPC on EKS, with no peering between cluster VPCs.
- Every namespace has default deny, `kube-system` included. `celld` refuses a bundle that creates a namespace without the platform default deny, and an admission policy denies pods in a namespace that has none.
- Traffic from nodes is allowed only to probe and webhook ports, per workload. Locally, rules name each node by its own address. On EKS, pods use a secondary CIDR through custom networking, so node and control-plane subnets stay separate from pods. Webhook ports admit only the control-plane subnets.
- An admission policy in each cell denies `NodePort` and `LoadBalancer` Services, `externalIPs`, writes to `status.loadBalancer`, `hostPort` and `hostNetwork`. Exemptions name a service account and an exact object.
- Kiln signs a network policy template. `celld` fills in only typed facts: node addresses, subnet CIDRs and named endpoints such as the DNS resolver. Each fact must fall inside the cell's allocation in the signed record. A static egress rule lets `celld` reach the plane endpoints without rendered facts.
- On EKS, VPC CNI runs network policy in strict mode, so every add-on needs its own policy. Any cluster-wide policy type stays inside the provider backend.
- Each upward flow has its own egress rule from the namespace that needs it.

## Identity

### Why a custom attestor

SPIRE's `k8s_psat` attestor validates through TokenReview, so a remote server needs a
kubeconfig for each cluster. The PoC adds a small NodeAttestor plugin pair, `cluster_jwt`. It
validates a projected service account token against the public signing keys of that cluster.
Teleport's `static_jwks` join method and the SPIFFE `spire-identity-exchange` validator do the
same. Read both before the attestor is written.

### SPIRE CAs **[call]**

- Each environment's root CA stays offline. It signs an upstream intermediate valid for 30 days, which the SPIRE server loads through the `disk` UpstreamAuthority with `bundle_file_path`.
- The next intermediate is signed ahead, with overlapping validity, and staged in the secret store. The server switches at half the current intermediate's life. An alert fires at half life if no next intermediate is staged.
- Cells pin the root, so a planned intermediate change is invisible to them.
- A compromised intermediate is denied by its subject key ID. The deny-list reaches cells as a narrowing key set, and `cell-proxy` and `celld` check it during verification. Revoking the root itself would also drop every good identity.
- Root rotation adds the next root to every cell's key set, and retires the old root only after every cell that is not decommissioned acknowledges. **[phase 2]**

### Attestation

The SPIRE agent runs as a sidecar in each pod that needs an identity, with no DaemonSet, host
path, CSI driver or kubelet access. The sidecar verifies the exact server ID before it sends a
token.

The server plugin takes these steps. Any error denies:

1. It loads the cell record from the current signed spec, with any local revocation overlay. It refuses a revoked cell.
2. It rejects an unknown key ID before any signature work, then verifies the token signature against the cluster keys in the record. It never uses keys chosen by the `iss` claim.
3. It checks namespace and service account against the record.
4. It requires a token bound to a pod, with the pod UID and node claims.
5. It requires a lifetime of 15 minutes or less, and an `iat` no older than 15 minutes.
6. It requires the audience `spire-<env>/<nonce>`, where the nonce comes from the server for this attestation. The sidecar requests that token through TokenRequest for its own service account. A copied token therefore works only once, and only for the attestation it was made for.
7. It caps the challenges in flight for each cell (default 8). After a token validates, it charges a per-cell rate budget (default 2 each second, burst 10). Failed attempts use none of the budget.
8. It returns `can_reattest = false`, and an agent ID that includes the nonce's hash: `spiffe://<env>.env.poc.internal/spire/agent/cluster_jwt/<cell>/<pod-uid>/<nonce-hash>`. The nonce hash is the first 16 bytes of SHA-256 over the base64url nonce string, in hex.

Because agents do not re-attest, a running agent renews its SVID without a new token. SPIRE
re-attests a re-attestable agent on every rotation (verified in `pkg/agent/svid/rotator.go`),
which would fail during an island after a cluster key rotation. A sidecar whose SVID has
expired attests again as a new agent, with a new nonce.

- The server prunes old agents with `prune_tofu_nodes = true` and `prune_attested_nodes_expired_for`.
- SPIRE's built-in per-IP limit is turned off, because cells share addresses. The server makes each nonce inside one attestation stream, so a token copied into another stream fails, and no nonce cache is needed.
- Plugins have no datastore access: SPIRE offers server plugins only the `identityprovider`, `agentstore` and `metrics` host services (as of 2026-11-08). Each server keeps the in-flight cap and the rate budget in memory, so a second server divides the budget.
- A node alias entry maps cluster and service account selectors to the workload parent, so HPA scale events write no entries.
- Registration entries are `ClusterStaticEntry` manifests that spire-controller-manager reconciles in static manifest mode.
- SPIRE returns the reason of a refusal to the agent as `nodeattestor(cluster_jwt): <reason>`, verified on 2026-11-09 with SPIRE v1.15.5. The plugin also logs the reason, the cell and the key ID. The reason holds no token contents.

### Independent key check **[call]**

The environment control plane creates cells, so it cannot vouch for their keys:

- Kiln reads each new cluster's signing keys from the provider's public issuer, which needs no credential.
- The issuer is bound to the cell at first start. `celld` sends Kiln a projected token whose audience is a nonce from Kiln. Kiln accepts the issuer only if that token verifies against it.
- Kiln signs the keys into the cell record. Kiln checks again every 15 minutes, and at once when an attestor reports an unknown key ID, at most once per cluster per minute.
- Locally, a host service on the Mac, outside every cluster, serves each cluster's `/openid/v1/jwks` over TLS with a certificate that Kiln pins.

### Signed specs and records **[canon; details are a call]**

- Each spec revision carries Kiln's signature and a revision of the form `(epoch, counter)`. envd refuses an unsigned spec or an older revision.
- A cell record holds the cell's cluster keys and issuer, endpoint set, agent name, replica cap, key sets, approver directory, export allow-list and status.
- Specs and records have no expiry, so an island never stops an environment.
- Record changes are staged per cell. envd refuses a revision that would newly invalidate more than one cell at a time, unless it carries a recovery-key signature.

### Island mode and keys **[owner]**

An island is an incident. While it lasts, no trust changes:

- No cell record, key set, approver directory or SPIRE root changes.
- An attestor does not accept a cluster key that is not in the last signed record.
- EKS rotates each cluster's signing key every 7 days, and that rotation cannot be paused. After a rotation during an environment island, new pods that need an identity in that cell cannot attest until Kiln confirms the new key.
- Running SPIRE agents renew without a new token, because they do not re-attest, so running workloads keep their identities.

The incident response is a change freeze. The HPA holds its current size, rollouts wait, and
alerts fire at once. Customer traffic is never affected.

### Key rotation and recovery **[call]**

Every trust change follows the same rules, whatever the key:

1. **Signed key sets.** A change to what a component trusts arrives as a key set with a version and an epoch, signed as the matrix below requires. The receiver verifies it, whatever channel carried it. Kiln keeps every key set, and delivers them in order.
2. **Overlap.** The next key is published before it is used. The old key retires only after every receiver that is not decommissioned acknowledges the new set. Time alone never retires a key.
3. **No downgrade.** A receiver refuses a key set with a lower version.
4. **Narrow freely, widen only when connected.** Removing trust is allowed at any time, also locally during an island. A narrowing can never remove the recovery keys or the last path that widens trust. Adding trust never happens during an island.
5. **Key sets first on reconnect.** After an island, a component applies pending key sets before any other work. Only then does Kiln confirm rotated cluster keys, and only then does queued work run.

Who signs each change:

| Change | Signed by |
| --- | --- |
| Add a cell cluster key from the bound issuer | Kiln, in the cell record. More than two new keys between checks also needs an approver, because it may mean a compromised issuer |
| Planned rotation of a Kiln key: add the next key, retire the old one | The current Kiln key and two approvers |
| Add an approver | Kiln and two approvers. A Data Protection role needs a Data Protection approver |
| Remove an approver | Two approvers, or the recovery quorum |
| Add an export recipient or store | Kiln and a Data Protection approver |
| Remove a Kiln key after a compromise | The recovery quorum |
| Replace a root, or bump the epoch after a restore | The recovery quorum |
| Revoke a cell, or deny an intermediate | Kiln, or a local operator during an island |

The recovery quorum is 3 of 5 recovery keys, each held offline by a different holder. Every
cell pins all five public keys, and a change needs three separate signatures, so no key is
ever put back together on one device. Three holders together replace a lost or departing
holder. A runbook names the holders, the meeting process, the tool, and a drill every
quarter.

| Key | Planned rotation | Emergency rotation | Recovery from loss |
| --- | --- | --- | --- |
| Cell cluster signing key, rotated by the provider | Kiln adds the new key from the bound issuer, and keeps the old one until its tokens expire | Kiln removes the key in a new record. Locally, an operator rotates it with two `--service-account-key-file` values | The provider holds it. Kiln confirms the next key from the issuer |
| SPIRE intermediate CA | Next intermediate staged ahead, switched at half life | Deny by subject key ID, then switch to the staged intermediate | Sign a new intermediate with the offline root |
| SPIRE root CA | Next root added, old root retired after every acknowledgement. **[phase 2]** | Recovery quorum replaces the root. Islands trust the old root until they reconnect | Recovery quorum |
| Kiln signing keys | Current and next in each key set | Recovery quorum removes the key. Sensitive items still need approver signatures, which bounds the damage | Recovery quorum adds a new key |
| Approver keys | The approver enrols a new device key | Removal, which narrows trust | The approver enrols a new device key |
| Export recipient keys | Next recipient added. Old private keys stay with the recipient until the exports' retention ends | Removal from the allow-list | Exports to a lost key cannot be read |
| Recovery keys | Three holders sign a replacement | Three holders remove the compromised key | Three holders replace a lost key. With fewer than three, cells re-bootstrap through break-glass, the last resort |
| Mesh CA, Argo CD Agent JWT key | Regenerated inside the cluster | Regenerate, then restart the affected workloads | Regenerate |

### Revocation **[call]**

- When connected, Kiln marks a cell revoked in a new spec revision. The SPIRE server, the cell gateway and the relay refuse the cell at once. Kiln's `cell-proxy` closes its live streams.
- In island mode, an operator revokes the cell at `<env>-cp` with one command over the tailnet. The revocation is a local overlay that only narrows trust. It stays in force until a Kiln revision includes it.
- A revocation is mirrored to Kiln at once when connected. A restore never goes back past the last revocation.
- A revoked cell keeps serving its customers. Stopping service is a decommission.

### Restore and counters **[call]**

- Every counter carries an epoch: spec revisions, queue fencing tokens and component versions.
- After a restore, Kiln bumps the epoch with a recovery-key signature, and resumes above the high-water marks that envd and `celld` report.
- A restore of an environment control plane bumps its queue epoch, and reapplies local revocations from Kiln's mirror.

## Provisioning flow **[owner, canon; details are a call]**

1. A developer requests a cell in Kiln. Approvers who are not the author sign it.
2. Kiln adds a pending cell to the spec: name, cluster reference, agent name, replica cap and the digests of the bootstrap set.
3. envd pulls the spec, and gives the step to the cell controller.
4. The cell controller creates the account, VPC and cluster through its provider backend. It tags every resource with the cell and the step, and records each provider ID.
5. The bootstrap actor applies only the pinned bootstrap set over the tailnet. Locally, the actor is the host service on the Mac. On EKS, it is a separate service with a scoped, short-lived credential, not the cell controller.
6. Kiln removes the bootstrap access: the tailnet tag, the EKS access entry and the account's administrator role.
7. Kiln binds the cluster's issuer, reads its keys and signs the cell record into a new spec revision.
8. Cell sidecars attest. `celld` connects to the cell gateway, and envd reports the cell as valid.
9. The cell's Argo CD agent connects to Kiln's principal through the relay.

### Cell controller **[owner: custom controller with ACK; details are a call]**

| Backend | Use | Creates clusters with | Keys from |
| --- | --- | --- | --- |
| `kind` | Mac demo, every local milestone, and any Linux host with Docker | kind, through the host service | Host service, over pinned TLS |
| `aws` | EKS, phase 2 | ACK controllers | Public issuer JWKS |

- The `kind` backend is the only way the harness creates cells from M1, so there is one provisioning path.
- The host service runs on the Mac, outside every cluster, and listens on the loopback address only. Clusters reach it through `host.docker.internal`, which Colima forwards to the Mac's loopback address.
- Each cluster gets its own pod and service subnets, recorded in the signed record. The harness refuses an overlap.
- The cell controller acts only on steps of a Kiln-signed spec, for cells of its own environment.
- On EKS, an organisation-level policy that the environment cannot change denies the cell controller's roles any access or IAM change in cell accounts after bootstrap. Accounts come from a narrow provisioner in the management account, triggered only by Kiln-signed steps. **[phase 2]**
- A cell that fails part way is left tagged. A sweeper compares tags with the spec, and a decommission step removes what the spec does not hold.
- A rebuilt environment control plane adopts provider resources by recorded ID, and never creates duplicates.

### Provider resources and deletion **[call]**

- Every ACK resource, in `<env>-cp` and in cells, carries `services.k8s.aws/deletion-policy: retain`. An admission policy refuses ACK resources without it.
- CRDs and stateful resources carry the Argo CD options `Prune=false` and `Delete=false`.
- Only an explicit, approver-signed decommission operation deletes a provider resource.

## Operations

### Streams and claims

Each `celld` replica holds one outbound stream to the cell gateway. The environment
control plane keeps the operation queue, and replicas compete for work:

1. A stream message signals that work exists.
2. A replica with free capacity claims the next operation under a time-limited lease.
3. The lease carries a fencing token with the queue epoch. A result with an old token is refused, and the in-cell Lease for the target also checks it.
4. If a replica dies, the lease expires, and another replica claims the operation.

Stream health **[call]**: clients send gRPC keepalives every 30 seconds with a 10-second
timeout, and servers allow pings every 20 seconds. An application heartbeat runs every 10
seconds. Reconnects use jittered backoff.

### Protocol versions **[call]**

- The stream hello negotiates a version. Servers support the last three versions.
- One fixed message, "accept an upgrade bundle", never changes, so a cell that returns from a long island can always be upgraded.
- SPIRE servers upgrade one minor version at a time. They wait while any cell of the environment is an island, unless an operator overrides the hold, which is audited.

### Signed work and idempotency **[call]**

- Kiln signs every operation, bundle and session grant. The DSSE payload binds the target cell, kind, operation ID, expiry, version and approver signatures.
- `celld` refuses an unsigned item or an item for another cell.
- Each operation applies at most once, by its 128-bit operation ID. Before it applies, `celld` creates a record for the operation in state `claimed`. It moves the record to `applied` with the result, then to `reported`.
- A second claim of the same operation returns the stored result. It never applies the operation again, even after a lease expired during a partition.
- An operation past its expiry is reported as `expired`, never applied late. Expiry is shorter than record retention, so an old operation cannot be replayed.
- Bundles carry a component version with an epoch, kept in an object in the cell. `celld` refuses a lower version, and treats a resend with the same digest as a no-op.

### Approvals in the cell **[owner: cells check approvers; details are a call]**

- Each signed record carries an approver directory: approvers' public keys and roles. Changes follow the signer matrix.
- An approval is the approver's own signature over the decoded item. The approver's client shows what it signs: the target, the kind, the version, and for an export the recipient key fingerprint and the store. A compromised Kiln therefore cannot get a signature for a different item than the one shown.
- `celld` checks the policy itself: the author never approves, deletion, unmasking and exports need a Data Protection approver, and platform bundles need a platform approver.
- Application bundles need an independent second signature: an approver, or a build-provenance signer pinned in the record.
- Approvers also sign a security floor version for platform components. `celld` refuses a bundle below that floor, so an old approved bundle cannot bring back a state without a newer guard.
- Because of this, a compromised Kiln alone cannot export data, unmask it, ship a workload, or remove a cell's guards.

### Bundles, Argo CD and safe updates **[owner: Argo CD per cell; details are a call]**

1. An operation delivers a signed, hydrated bundle to `celld`.
2. `celld` verifies the signatures, the version, the floor and the target. It checks every object against the key's allow-list, by kind and namespace.
3. It pushes the bundle by digest to the bundle store, and composes the root bundle under a cell-wide Lease.
4. Argo CD applies it, within an AppProject for each key. Each AppProject repeats the kind and namespace limits.

Key allow-lists:

| Key | May change |
| --- | --- |
| Platform bundle key | Platform components, network policy, mesh policy, `ack-system`, `observability-system`, and Argo CD configuration |
| Application bundle key | Product namespaces only. Never `NetworkPolicy`, `ServiceEntry`, `Sidecar`, `AuthorizationPolicy`, `PeerAuthentication`, `EnvoyFilter`, Gateway API kinds, the sidecar injection opt-out, or a `Service` that is not `ClusterIP` |

No bundle may change `celld`, its watchdog, the Argo CD workloads, or the pinned roots and
recovery keys. Those objects are outside every Argo CD Application, and an admission policy
refuses bundles that name them.

Rollback and health **[call]**:

- A rollback points the root back at the last good root that Kiln signed, by digest. It creates no new version, so it never collides with Kiln's next one. `celld` reports `rolled_back`, and Kiln issues its next version above the failed one.
- A rollback never removes an Application, so nothing is pruned.
- The health check uses in-cell signals only. It needs Argo CD Synced and Healthy at the digest, a reply from the bundle store, and the updated workloads ready. A partition alone never triggers a rollback.
- The bundle store runs on a persistent volume. `celld` also keeps the last two signed bundle sets in its own durable state. It can refill a lost store without the environment control plane.
- Registry garbage collection runs offline, under the cell-wide Lease, and keeps the last two good roots.
- Platform bundles go to the canary cell named in the spec first.

`celld` and Argo CD update through their own path:

- An update is an operation that `celld` applies directly, outside Argo CD.
- `celld` updates blue/green. The record allows the replica cap plus one per version during an update. The old version stops only after the new one passes in-cell checks. A missing stream keeps both versions running.
- A small static watchdog in `cell-system` reverts a rollout that does not become healthy within its deadline. For Argo CD, healthy means it reconciles a canary Application at the expected digest. The watchdog itself changes only through break-glass.
- The plane clusters `management` and `<env>-cp` update the same way, under their own watchdogs.

### Customer-data operations **[owner; details follow the canon]**

- Each operation runs as one Kubernetes Job named by its operation ID, in the cell's `ops-runs` namespace.
- Each run gets its own service account, credentials that last 1 hour or less, and egress only to its targets.
- `ops-runs` is outside the mesh. TLS and a per-request IAM credential protect the data store path.
- On EKS, run egress goes through VPC endpoints whose policies allow only the export bucket and the run's key. Data store traffic goes to their subnets, on their ports. **[phase 2]**
- Reports hold counts, never rows. Jobs log through a structured logger whose message templates are fixed, so error details with row values are dropped.

### Exports **[owner: encrypted in transit and at rest; details are a call]**

- An export is encrypted inside the cell before it leaves, with a data key per export.
- The data key is wrapped to a recipient public key. Recipients and export stores come from the allow-list in the cell record, never from the request.
- No unwrap key is ever in or near the cell.
- The export goes to an export store in the cell's region, over mTLS. The store holds only ciphertext.

### Exploration sessions **[phase 2]**

| Kind | Path |
| --- | --- |
| Metadata discovery | An ordinary read operation |
| Queries over customer rows | An interactive session through an in-cell explore gateway |

A session works like this:

1. Approvers sign a grant bound to one person's client public key, cell, database, masking level and time limit of 60 minutes or less.
2. `celld` starts an explore gateway as a Job in `ops-runs`, and reports its ephemeral key fingerprint. Kiln adds the fingerprint to the grant.
3. The gateway dials out to a session broker in the cell's region, and holds a reverse tunnel with keepalives under 300 seconds.
4. The person connects through the broker with mutual TLS. The gateway requires the person's key from the grant, and the person's client pins the gateway's fingerprint. A broker that holds a valid gateway identity still cannot read rows or relay the grant.
5. The database enforces read-only access and masking, through a role with SELECT only on masked views and a reader endpoint. The gateway adds row limits, timeouts and query logs.

### Fan-out and HPA **[phase 2]**

- Kiln splits a fleet operation into one child per cell. An offline cell keeps its child until the child expires.
- The HPA scales on queued work plus work in progress, per replica. `minReplicas` is 1.
- A replica's liveness never depends on the upstream connection, so an island causes no restarts.

### Cell-to-cell requests **[owner]**

- Within an environment, a cell sends `cell.request` to its environment control plane. The sender comes from the verified SVID, and a default-deny policy allows named pairs and kinds.
- Across environments, requests go through Kiln under the same kind of policy. **[phase 2]**

## Island mode **[owner]**

| Cut off | What keeps working | What stops |
| --- | --- | --- |
| An environment from Kiln | The last signed spec. SPIRE still renews SVIDs. Queued work still reaches cells | New intent, approvals, trust changes, the central view and telemetry |
| A cell from its environment control plane | Customer traffic. Argo CD applies the last good state. In-cell controllers keep reconciling | New work and bundles, the central view for that cell |

- An island is an incident: alerts fire, and a change freeze starts.
- `celld` and the Argo CD agent stay up, and reconnect with jittered backoff.
- The collector queues to a persistent volume sized for 24 hours of signals.
- On reconnect, sidecars attest again if needed, envd resends the latest bundles, and local revocations reconcile with Kiln.

## Central Argo CD view **[owner]**

Kiln shows every cell in one Argo CD view, with live manifests. No credential is copied for it,
and the view never changes a cell.

### Path **[call]**

1. The cell's Argo CD agent runs in autonomous mode, and connects in plaintext to `cell-proxy` in its own pod.
2. `cell-proxy` presents the agent SVID and the second proof, through the relay.
3. At Kiln, the listener for that environment accepts only `^spiffe://<env>\.env\.poc\.internal/cell/([a-z0-9-]+)/argocd-agent$`, and checks the registry for each stream.
4. It forwards to the principal, which listens on `127.0.0.1` only, with the verified identity in the header.
5. On every call, `cell-proxy` checks that the principal's session subject matches the SVID's cell. It closes the stream when the registry changes.

The agent name is `<env>-<cell>`, so names never collide across environments.

### The view cannot change a cell **[call]**

Argo CD Agent v0.10.0 lets the principal replace every annotation of an autonomous
Application, not only `.operation` (verified in `internal/manager/application`). Its resource
proxy also forwards creates, patches and deletes, and its terminal path runs exec in pods
(verified in `agent/resource.go` and `agent/terminal.go`). The guard therefore sits in the
cell:

- The agent's service account has an explicit Role in each namespace it may read. It has no wildcard resources, and none of `pods/exec`, `pods/attach`, `pods/portforward`, `*/proxy` or `serviceaccounts/token`.
- The Role has no write verb on Applications. The principal sends an event for each change of a mirrored Application, and the agent logs a Forbidden for each one.
- A ValidatingAdmissionPolicy denies every update, delete and connect request of that service account. It also denies every create request, except the bound token request of its own SPIRE agent.
- The token request names the account `argocd-agent`, one audience `spire-<env>/<nonce>`, and the Pod that sends it. A token for another audience, account or Pod is denied.
- The agent's Applications live in `argocd`, next to the Secrets `argocd-redis`, `argocd-secret` and `bundle-store`. The agent may list and watch Secrets there, because its informer requires it. It has no `get` verb.
- An admission policy keeps the set of Secrets in `argocd` closed, and RBAC refuses a Secret `get`. The resource proxy refuses a Secret list.
- The agent's read access excludes `ops-runs`, so Job logs never reach the view.
- Argo CD RBAC at Kiln also denies sync, terminate, delete and exec, as defence in depth.
- Tests drive real principal events and resource requests. A separate test binds a temporary Role to a test group. The Role holds Application, ConfigMap and ServiceAccount writes, exec and token create. The test then shows that the policy alone denies each write.
- A refresh from the central view fails by design, because the central `argocd-server` is read-only in the agent namespaces.

### Upgrades **[call]**

The principal refuses any agent with a different version (verified in
`principal/apis/auth/auth.go`). Kiln runs a principal and its Argo CD for each supported
version. The cell record names the principal endpoint for the cell's agent version, and the
relay routes to it by inner SNI. An upgrade moves cells as their updates land, and stops an
old principal when no cell uses it. Each cell's Argo CD, agent and principal upgrade as one
tested set. An alert fires on any version mismatch.

## `cell-proxy` **[call]**

One small binary, built in this repository with go-spiffe:

| Mode | Used by | Behaviour |
| --- | --- | --- |
| `spiffe-client` | Argo CD agent, cell collector | Presents the pod's SVID and the second proof. Accepts only the exact upstream ID |
| `spiffe-server` | Kiln listeners | Requires an anchored client ID pattern and the second proof, checks the registry, sets the identity header and removes any copy from the client |
| `token` | Bundle store | Checks a service account token with the cell's own TokenReview API |

| `tunnel` | Cell mesh tunnel | Dials up to Kiln and holds one stream. It serves Kiali's read requests back down the stream, against an allow-list of read-only Kubernetes API paths |

go-spiffe follows bundle and SVID changes at run time, so a CA rotation needs no restart.

## Mesh view **[owner: central Kiali; details are a call]**

Kiali runs in the `management` cluster. It shows the mesh of each cell, and it changes nothing.

- Metrics come from the observability stack. Each cell's collector scrapes the Envoy and istiod endpoints in its own cluster, and exports them as OTLP.
- Kiali also reads each cell's Kubernetes and Istio objects. Kiln dials into no cell, so the cell's `cell-proxy` opens a tunnel up to Kiln, through the relay. Kiali's requests travel down that tunnel.
- At the cell end, the tunnel answers only `get`, `list` and `watch` on an allow-list of paths. A service account with an explicit read-only Role serves them. It has no access to Secrets, `pods/exec`, `pods/log` in `ops-runs`, or any write verb.
- Kiali in Kiln uses its own SVID, `spiffe://mgmt.poc.internal/kiali`, and sees one remote cluster per cell. No kubeconfig credential leaves a cell.
- Each cell is its own mesh, with its own trust domain. Kiali shows them as separate meshes, not as one multi-cluster mesh.

## Telemetry **[owner: no personal data in signals; details are a call]**

- Each cell's collector sends OTLP through the telemetry relay to Kiln. The `<env>-cp` collector sends OTLP to Kiln directly, with its own SVID.
- Each collector also scrapes the Prometheus endpoints of upstream components in its own cluster: Argo CD, Argo CD Agent, istiod and Envoy. A NetworkPolicy admits only the collector to those endpoints.
- Locally, Kiln's telemetry gateway feeds the `otel-lgtm` image, which runs Grafana, Loki, Tempo and Prometheus.
- Every collector tags every log, span and metric with the source attributes in the table below. **[owner]** The attributes become Prometheus labels, Loki index labels and Tempo search fields, so every view can filter by cluster, plane, environment and cell.
- The telemetry gateway does not trust the attributes that a cell sends. It sets them again from the verified SPIFFE ID of the stream. A cell therefore cannot label its signals as another cell's. The gateway counts each overwrite that changes a value, and an alert fires on any such change.

| Attribute | Value | Set on |
| --- | --- | --- |
| `k8s.cluster.name` | The cluster name, for example `dev-cell-1` | Every cluster |
| `platform.plane` | `management`, `environment` or `cell` | Every cluster |
| `deployment.environment.name` | The environment, for example `dev` | Environment and cell clusters |
| `platform.cell` | The cell name, for example `dev-cell-1` | Cell clusters |
- The collector forwards only allow-listed attributes, span names and event names. Log bodies come only from fixed message templates.
- The collector runs as a StatefulSet with the Recreate strategy, with a persistent queue sized in bytes for 24 hours. It filters before it queues, and the relay limits the rate at which a backlog drains after an island.
- `celld` status messages carry a health summary for the cell: Argo CD health, root digest, SVID expiry and collector drops. The environment control plane can therefore see its cells during an island with Kiln.
- Each `<env>-cp` runs an alert evaluator, chosen after third-party review, and sends notifications through its own declared egress flow.
- A test injects a canary personal-data string into a cell, and asserts that it never reaches Kiln.

| Signal | Alert when |
| --- | --- |
| Island state, per environment and per cell | Any island |
| SVID time to expiry | Less than 15 minutes |
| Attestation denials, by code | Any denial for a valid cell |
| Root digest compared with the intended digest | Different for 10 minutes |
| Argo CD health | Not Healthy for 10 minutes |
| Record revision lag, per cell | More than one revision behind |
| Intermediate CA | Half life reached with no next intermediate staged |
| Agent version mismatch | Any |
| Collector drops | Any |
| Backup age | Older than its schedule |

## State and recovery **[call]**

| State | Lives in | After the loss of its cluster |
| --- | --- | --- |
| Intent, records, approvals, registry, revocation mirror | Kiln database | Restore Kiln, bump the epoch. Environments keep running meanwhile |
| Operation queue, fencing epochs, provider resource IDs | `<env>-cp` queue database | Restore, bump the queue epoch, merge provider IDs to Kiln |
| SPIRE datastore, nonce cache, attestation limits | Its own database | Rebuild from the records. Agents attest again |
| Local revocation overlays | A signed log on the operator side, outside `<env>-cp` | Reapply on restore. A restore that crosses an island needs operator confirmation |
| Online keys | Secret store | Load again |
| Bundles, operation records, versions | The cell: persistent bundle store, `celld` durable state, objects | Survive. envd resends what the hello reports missing |

- Each cell record has its own version. The environment spec is a signed index of record digests. A key rotation in one cell then changes one record, and lag is measured per record.
- The cell controller writes each provider resource ID to the queue database before it calls the provider. It looks up resources by deterministic tags before every create, so a retry never duplicates.
- A rebuilt environment control plane adopts resources with ACK's strict `adopt` and an empty spec, so adoption never changes live infrastructure.
- The sweeper only reports. Deleting a provider resource needs an approver-signed operation that lists explicit IDs, after a quarantine period.
- A cell that fails during creation reuses its account on retry. AWS accounts close only after a wait, and count against the limit while closed.
- The organisation policy denies the cell controller's roles access-entry and IAM changes in cell accounts. It does not deny adoption, upgrade or decommission.
- If its database stalls, the cell gateway keeps open streams and cached cap state, and refuses only new streams.
- The HA path for a SPIRE server is a second server in another zone, with the same root, its own intermediate, and the shared datastore. **[phase 2]**

## Break-glass access **[call]**

- `mise run cell:break-glass <cell>` grants an operator Kubernetes access to one cell over the tailnet, with a credential that carries its own 1-hour lifetime.
- The path needs neither Kiln nor the environment control plane: on EKS, the operator's own role creates a short-lived access entry; locally, the Mac's kubeconfig.
- Each grant is logged locally and reconciled with Kiln.

## Rejection tests

Each row is an automated test. PoC services return only `denied` and a request ID; the code
appears in logs and in the test assertion. MITM tests use a self-made certificate and a valid
SVID with the wrong ID, including one minted by the environment's own CA.

| # | Attacker | Stopped at | Result | Phase |
| --- | --- | --- | --- | --- |
| 1 | Rogue cluster presents its own token with the attestation client of `celld` | Attestor: keys match no record | `unknown_kid` at the attestor, and `token_invalid` with the detail `unknown_kid` at bind | 1 |
| 2 | Rogue cluster claims a real cell's name, with the same default issuer | Signature check | `bad_signature` or `unknown_kid` at the attestor, and `token_invalid` at bind | 1 |
| 3 | Pod with another service account or namespace | Attestor | `subject_mismatch` | 1 |
| 4 | Token for the wrong audience | Attestor | `audience_mismatch` | 1 |
| 5 | Expired token | Attestor | `token_expired` | 1 |
| 6 | Token requested with a lifetime of 1 year | Attestor | `token_lifetime` | 1 |
| 7 | Token not bound to a pod | Attestor | `token_unbound` | 1 |
| 8 | Copied token used again, or for another attestation | Attestor nonce check | `token_replayed` | 1 |
| 9 | Rogue serves its own JWKS for a real cell, or calls the host service | Kiln pinned TLS; host service mTLS | `issuer_untrusted` at the client. A rogue caller of the host service gets `handshake_failed` | 1 |
| 10 | Pod beyond the replica cap, or claiming another pod's UID | Cell gateway | `replica_cap` | 1 |
| 11 | `celld` in cell A claims cell B | ID from verified claims | `cell_mismatch` | 1 |
| 12 | Environment control plane forges or changes an operation or bundle | `celld` signature check | `signature_invalid` | 1 |
| 13 | Operation applied twice, or replayed after its expiry | Operation record; expiry | `already_applied`, or `expired` | 1 |
| 14 | Bundle with a lower version | `celld` in a cell, envd in `dev-cp` | `version_old`. The detail is `version_conflict` when a set repeats a version with other content | 1 |
| 15 | Item signed for cell A presented in cell B | `celld` and envd target check | `wrong_target` for an operation of another target. `wrong_target` with the detail `target` for a set whose attestation names another target | 1 |
| 16 | Export, unmask, platform bundle or application bundle signed by Kiln without the required second signature | `celld` approval policy | `approval_missing` | 1 |
| 17 | Export to a recipient or store not on the allow-list | `celld` | `export_refused` | 1 |
| 18 | Application-key bundle with a forbidden kind or namespace | `celld` and envd policy, then AppProject, then `bundles-app-limits` | `component_not_allowed`, with a detail such as `kind`, `namespace`, `component_unknown`, `harness_object`, `service_type` or `mesh_opt_out`. A bundle that bypasses the applier fails at sync, in the AppProject or in `bundles-app-limits` | 1 |
| 19 | Network policy bundle that blocks the plane endpoints | `celld` and envd policy, then the harness guard | `policy_blocks_planes`. The detail is `<namespace>/<name>` of the harness plane policy, or `mesh_injection` | 1 |
| 20 | Spec with a lower revision, no Kiln signature, or invalidating several cells | envd | `spec_invalid` | 1 |
| 21 | Cell controller step without a Kiln signature, or with a modified bootstrap set | Cell controller; bootstrap actor | `step_invalid` | 1 |
| 22 | Environment control plane poses as a cell to Kiln, on a stream or in a reported result | Kiln second proof | `proof_missing` | 1 |
| 23 | TLS interception, `celld` to the cell gateway | `celld` | The `reason` field of the `bind failed` and `stream ended` logs, which unit tests check: `peer_untrusted`, `peer_not_allowed` or `handshake_failed` | 1 |
| 24 | TLS interception, sidecar to SPIRE server | Sidecar | The attestation client refuses the server certificate, and the impostor receives no token | 1 |
| 25 | Relay or Kiln impostor between agent and principal, with an environment-minted SVID | `cell-proxy` exact ID | `peer_untrusted` for an SVID of the environment CA, and `peer_not_allowed` for a Kiln SVID with another ID | 1 |
| 26 | envd connects to a fake Kiln | Pinned Kiln root | `peer_untrusted` in the error field of the `pull failed` log line | 1 |
| 27 | TCP relay that only forwards, or alters bytes | TLS | Ciphertext only, `handshake_failed`, or the connection closes | 1 |
| 28 | Revoked cell's existing relay and principal streams | Relay; Kiln `cell-proxy` | Closed within 5 seconds | 1 |
| 29 | Forged identity header sent straight to the principal port | Principal on `127.0.0.1` | Connection refused on the pod address | 1 |
| 30 | Annotation change other than refresh, `.operation`, or any write through the view | Admission policy in the cell | Denied; the cell does not change | 1 |
| 31 | Read a Secret, or `ops-runs` logs, through the view | Agent RBAC in the cell | Forbidden | 1 |
| 32 | Agent from environment X claims a cell of environment Y | Per-environment listener | `peer_not_allowed` | 1 |
| 33 | Argo CD's token writes to the bundle store, or `celld`'s reads as Argo CD | Store `cell-proxy` | `peer_not_allowed` with the detail `subject`, `no_token`, `token_invalid` or `audience`. `request_not_allowed` with the detail `method` or `path` for any other request. A denial is HTTP 403. A proxy with too many token reviews at once answers 503 with `overloaded` | 1 |
| 34 | Stale fencing token after lease loss or a restore | Queue; in-cell Lease | `lease_lost` | 1 |
| 35 | Pod in cell A, or in `rogue`, scans cell B, and a host network pod scans `dev-cp` and `management` | Isolation rules and admission policy | Every connection fails, except the residual ports of the shared network | 1 |
| 36 | Cell A asks to reach cell B with no policy, or names another sender | Environment control plane | `cross_cell_denied`, `cell_mismatch` | 1 |
| 37 | Revoked cell reconnects, or reappears after the next spec revision | Attestor overlay; gateway | `cell_revoked` | 1 |
| 38 | Operation Job reaches a host that is not its target | Run NetworkPolicy | Connection fails | 1 |
| 39 | Canary personal-data string logged in a cell | Collector allow-list; view RBAC | Never reaches Kiln | 1 |
| 40 | Rollback of a bundle that created an ACK resource | Retain policy; no prune | The provider resource remains | 1 |
| 40a | Key set without the signers the matrix requires, with a lower version, that widens trust during an island, or that removes the recovery keys | Receiver | `keyset_invalid` | 1 |
| 40c | Environment's SPIRE server serves a fake Kiln bundle to a cell | Static Kiln root in the cell | `peer_untrusted` | 1 |
| 40d | Platform bundle below the signed security floor | `celld` | `version_old` | 1 |
| 40b | Item signed by a retired or removed key | `celld` | `signature_invalid` | 1 |
| 41 | Session broker with a valid gateway SVID relays a person's grant | Person-bound mTLS | `session_denied` | 2 |
| 42 | Session used by another person, after its time limit, or for writes | Explore gateway; database role | `session_denied` | 2 |
| 43 | Cell controller adds an access entry to a cell after bootstrap | Organisation policy | `AccessDenied` | 2 |
| 44 | CCP pod or internet client connects to a cell's Kubernetes API on EKS | Private endpoint; tailnet ACL | Connection fails | 2 |
| 45 | New pod on EKS sends traffic before its policy applies | VPC CNI strict mode | Traffic is dropped | 2 |

Rows 16 and 40d in the PoC form:

- The PoC has no approver signatures and no signed security floor. The management plane signs every set alone, so row 16 stays with the later increment that adds approvals.
- M8 gives row 40d the version rule of row 14 only. A set below the mark gets `version_old`, and no floor binds a set above the mark. A writer of the state ConfigMap can lower the mark.
- The attestation envelope can carry approver signatures later, and the engine then checks them locally.

## Survivability tests

Tests are event-driven. A test profile shortens SVID and intermediate lifetimes, within
SPIRE's limits. The Mac gate has a fast tier and a slow tier.

| Test | Pass when | Phase |
| --- | --- | --- |
| Kiln cut off from `dev-cp` | Queued operations continue. SVIDs renew. No trust changes | 1 |
| A cell cut off from `dev-cp` for three SVID lifetimes | Customer traffic continues. Argo CD keeps the last good state. No pod restarts. Sidecars attest again on reconnect | 1 |
| Sidecar restart within its token's lifetime | It attests again with the reused token | 1 |
| Partition without a pod restart, one-way too | Streams recover, and the replica cap refuses no real replica | 1 |
| Cell key rotated while connected | Attestation recovers within one immediate key check | 1 |
| Cell key rotated during an environment island | Running workloads keep identities. New pods wait. Kiln confirms the key on reconnect | 1 |
| Bad platform bundle, bad `celld`, bad Argo CD, each separately | Rolled back with no step in the cell | 1 |
| Bundle store lost during an island | No Application is pruned, and the store refills after reconnect | 1 |
| Local revocation in island mode | The cell stays refused after the next Kiln revision | 1 |
| Planned rotation of a Kiln signing key and the SPIRE intermediate, under load | No operation fails and no identity lapses | 1 |
| Emergency removal of a Kiln key while one cell is an island | Connected cells refuse the key at once. The island cell applies the key set before any work on reconnect | 1 |
| One recovery key replaced by three holders | Cells accept the new key, and refuse key sets signed by the old one | 2 |
| Kiln restored from a backup one hour old | Environments accept the next spec, and cells accept the next operation | 2 |
| `dev-cp` deleted, rebuilt from empty, then restored | Every cell reconnects with no step in any cell, at the same endpoints | 2 |
| Attestation burst after an outage, with a rogue flood | Every real sidecar attests within 5 minutes | 2 |
| 1,000 operations with random replica kills and partitions | None lost, none applied twice | 2 |

Every random choice in a test records its seed.

## Residual risks

- A cell's cluster token signing key is the root of trust for that cell. A cluster admin who can request tokens can act as that cell's `celld`.
- The environment control plane is trusted on first use for the cells it creates, because it chooses which cluster the issuer binding proves. After bootstrap, it can mint identities in its environment and stop work on its way to cells. It cannot forge Kiln-signed work, pose as a cell to Kiln, or change a cell's access.
- Kiln and its approvers together can change any cell. Kiln alone cannot export, unmask or remove guards.
- During an environment island, a rotated cell key blocks new pods that need an identity in that cell until Kiln reconnects.
- During an island, a cell that Kiln revoked continues until an operator revokes it locally.
- An emergency key removal cannot reach a cell in island mode until it reconnects. Until then, approver signatures bound what a stolen Kiln key can do there.
- Live-view pod logs outside `ops-runs` rest on the rule that services log no personal data.
- Locally, any cluster can reach another cluster's Kubernetes API on the shared `kind` network. EKS removes this.
- Argo CD Agent is a v0.x project, and its principal HA is beta.

## Testing tiers **[call]**

| Tier | Runs on | Covers |
| --- | --- | --- |
| Unit and component tests | GitHub-hosted runners | Go packages, the attestor, `cell-proxy`, signature, approval and idempotency checks |
| Mac gate, fast | The owner's Mac | Acceptance and rejection tests of the build in progress |
| Mac gate, slow | The owner's Mac | Survivability tests |
| EKS gate | EKS, phase 2 | Everything, plus the provider, tailnet and isolation tests that need AWS |

Hosted runners for private repositories have 2 CPUs, 8 GB and 14 GB of disk (verified), so they
run no clusters. A larger runner is an option later, and needs no design change.

Some tests cannot pass on the Mac by design. Locally, clusters share the `kind` network, so isolation tests
target the pod network only. Tests of ACK deletion policy and per-request IAM credentials need
AWS, so they run in the EKS gate.

## Prior art

| Part | Prior art |
| --- | --- |
| Token validation against exported cluster keys | Teleport `static_jwks` join method; SPIFFE `spire-identity-exchange` validator |
| Agents that connect out to a control plane | GKE Connect, Azure Arc, Rancher. These tunnel API access, which this design avoids |
| Pull of signed specs with no stored credentials | Redpanda BYOC; Kiln's own envd |
| Central Argo CD view with agents | Argo CD Agent, which this design uses |
| Workers that compete for queued work | Temporal with KEDA |

## Milestones

`docs/design/poc-scope.md` defines the first build and its milestones. Later increments follow
this order, each with its own scope document:

1. Approvals in the cell, key sets and the recovery quorum.
2. Customer-data operations and encrypted exports.
3. Relay hardening, the watchdog and blue/green updates.
4. Restore, rebuild from empty, and provider inventory.
5. Exploration sessions, cross-environment requests and HPA fan-out.
6. EKS with the `aws` backend, the tailnet and AWS isolation rules. This touches a real AWS account, so it starts only after the owner approves the account and the spend.

## To verify at the milestone

| Item | Milestone | Fallback |
| --- | --- | --- |
| Pod-to-NodePort traffic between kind clusters on the `kind` network | M1 | Stop and report. Result 2026-11-08: it works, so no fallback applies |
| Pod traffic to another cluster leaves with its own node address | M1 | Tests key on SVIDs only. Result 2026-11-08: it does, when the server Service uses `externalTrafficPolicy: Local`, so no fallback applies |
| Pods reach the host service through `host.docker.internal` | M1 | A fixed gateway address in the cluster config. Result 2026-11-08: they do, so no fallback applies |
| Each node pulls ko images through the registry mirror | M1 | `kind load` for each cluster. Result 2026-11-08: every node of all five clusters pulls through the mirror, so no fallback applies |
| kind's local-path provisioner passes review | M1 | Stop and report. Result 2026-11-08: the review in `vendor/README.md` found nothing that blocks its use |
| kind clusters survive a restart of the Colima VM | M1 | Treat a restart as disaster recovery. Result 2026-11-08: they do not survive, so this fallback applies. Result 2026-11-15 and 2026-11-16: the same. After each restart, `gate:m1` found ports 30081, 30443, 30444 and 30445 open on `dev-cp` from `rogue`. The nodes had new addresses, and the policies of `dev-cp` still admitted old ones. The SPIRE server policy admitted them on port 30081, and the relay policy on ports 30443 to 30445. In the second restart, `rogue` held the old address of `dev-cell-2`, which the policy of the SPIRE server admitted. The same cause reaches the gateway ports 30450 and 30451, and the management ports 8446 and 31443 to 31445, which the scan did not show. The identity checks still hold. `rogue` reaches only the unauthenticated surface, and the real cell is shut out |
| Sidecar SPIRE agent with the `unix` workload attestor | M2 | DaemonSet agent where allowed. Result 2026-11-08, SPIRE v1.15.5: it works in `dev-cell-1` and `dev-cell-2`. The `celld` pod shares one process namespace. The agent runs as user 1000 with no capabilities, reads the caller uid 65532 from `/proc`, and issues the `celld` SVID. On 2026-11-09 a test stopped the agent container on the node. The new container loaded the SVID from the pod memory volume, kept the agent ID and renewed, with no new attestation. So no fallback applies |
| Non-reattestable agents with a nonce in the agent ID, renewal without a token, and a sidecar's TokenRequest with a nonce audience | M2 | Report and redesign. Result 2026-11-09, SPIRE v1.15.5: it works. Each agent ID holds the pod UID and the nonce hash. A test removes the RoleBinding that lets `celld` request tokens. The agent then renews twice through `RenewAgent`, `celld` gets two newer SVIDs, and the server logs no second attestation. With `can_reattest` set to true, the same test fails. A token with the audience of another nonce fails with `wrong_audience`. So no redesign is needed |
| Shortest SVID and intermediate lifetimes SPIRE allows, for the test profile | M2 | Longer slow tier. Result 2026-11-08, SPIRE v1.15.5. The shortest tested values that run cleanly are `ca_ttl` 1m, `default_x509_svid_ttl` 10s and `agent_ttl` 10s, with `default_jwt_svid_ttl` 10s. SPIRE sets no lower bound, but it warns when an SVID lifetime exceeds `ca_ttl` divided by 6. The CA rotator runs every 10 seconds, so with a `ca_ttl` of 30s the CA expires before the next rotation. With the default JWT lifetime of 5 minutes, the shortest values are `ca_ttl` 30m and 5m for both SVID lifetimes. `spire-server validate` hides these warnings, so the check used `spire-server run` with no agent. Result 2026-11-09: `SPIRE_SVID_TTL` in `cells/dev-cp.env` sets `default_x509_svid_ttl` and `agent_ttl` to 1m, with `ca_ttl` 24h. Agents and `celld` renew about every 30 seconds, and the M2 renewal tests pass. Agent renewal at 10s is not verified. The lifetime of the upstream intermediate is not measured yet. No fallback applies |
| Service account key rotation on kind nodes | M2 | Stop and report. Result 2026-11-09: it works. A test edits the static API server manifest of `dev-cell-1` on the node. It adds a second `--service-account-key-file` and signs with the new key. The API server publishes both keys and signs with the new one. The running `celld` agent keeps its renewals, and a new pod fails with `unknown_kid`, because the record holds only the first key. The cleanup restores the manifest and deletes the key. It makes sure that `kube-controller-manager`, which keeps a token for each controller in memory, runs a new container, and it deletes any pod that holds a token from that key. `mise run gate:m2:repair` runs the same cleanup after an interrupted run. So no fallback applies |
| Approver signatures from device-held keys in the PoC | M5 | Software keys per test approver. Result: deferred. M5 operations carry no approver signatures, and no test covers them. A later increment owns the row |
| Argo CD v3.6.1 reads an OCI source through a loopback proxy that adds a token, with `insecureOCIForceHttp` | M8 | Local TLS on the proxy. Report first. Result 2026-11-18: it does. The repo credentials Secret `argocd/bundle-store` holds `insecureOCIForceHttp: "true"`, `type: oci` and `url: oci://127.0.0.1:5000/bundles`. Every Application of the four clusters is Synced at its digest. A root error showed the plain HTTP path `HEAD http://127.0.0.1:5000/v2/bundles/root/manifests/current`. The store proxy logged no denial after the egress rule N47 applied, so the token review of the repo server token passes. The proxy logs no allowed request, so this evidence is indirect |
| Argo CD reads a bundle from `bundle.Pack` at path `.` | M8 | Copy the layout of an `oras push` bundle, read with `oras manifest fetch`. Report first. Result 2026-11-18: it does. The manifest of the `spire-server` bundle in `dev-cp` has the media type `application/vnd.oci.image.manifest.v1+json`, no `artifactType`, the empty config and one layer of type `application/vnd.oci.image.layer.v1.tar`. The Application has `path: .` and is Synced and Healthy at that digest |
| `kubectl port-forward pod/bundle-store-0 <port>:5001` reaches a registry that binds `127.0.0.1:5001` in the pod | M8 | A third subject `cell-system/bundle-bootstrap`, with a token from `kubectl create token` held in memory. Stop and report. Result 2026-11-18: it does. Each bootstrap publish in `dev-cp` and `dev-cell-1` pushed through it with no token, and `oras resolve` of `root:current` gave the published root. It also works while `store-proxy` is in a crash loop |
| A `celld` pod and the envd pod reach `registry-mirror` at its `kind` address on 5000 under an `ipBlock` rule in kindnet | M8 | None. Stop and report. Result 2026-11-18, `celld`: it does. Both pods fetched all 11 bundles of the first signed set under the rule N45. That rule is an `ipBlock` of the mirror address with TCP 5000. The log shows no fetch error. envd: it does. It fetched all 14 bundles under the rule N48, an `ipBlock` of the mirror address with TCP 5000. The outcome is `applied` |
| A named `clusterResourceBlacklist` entry in an AppProject blocks the sync of a bundle object of that kind and name. `ClusterResourceRestrictionItem.Name` exists in v3.6.1 | M8 | A residual line: only the engine protects the guard objects. Result: <measured in the live part> |
| Two times, in a cell and in `dev-cp`: a signed set to every Application healthy at the new root, and a rollback | M8 | None. Record it, and report above 10 minutes. Result 2026-11-18, cells: the first signed set with unchanged content took 2 s in `dev-cell-1` and 9 s in `dev-cell-2`. A set that adds or removes `apps-sample` took about 20 s, from the root sync to the result. `dev-cp`: the first signed set took 34 s, and later test sets took 20 to 30 s. Rollback: <measured in the live part> |
| `status.sync.revision` of an OCI child Application holds the manifest digest | M8 | None. Stop and report. Result 2026-11-18: it does. In all four clusters, `status.sync.revision` of every child equals the manifest digest, and that of `root` equals the digest that `oras resolve root:current` gives. For `spire-server` in `dev-cp` all three values are `sha256:907306cc7fcc7f32517ba667dd964373782d2333fa646684d3d95ac8b956ff44` |
| A `bundle.apply` effect of 5 minutes keeps the `celld` stream heartbeats and the lease renewals | M8 | Run the effect in its own goroutine under the lease renewal. Report first. Source read 2026-11-18 (`internal/executor/streamloop.go`): the loop runs the effect in its own goroutine and keeps pings, status and renewals. Result: <measured in the live part> |
| An apply of 5 minutes in envd keeps the spec pull, the record writes and the gateway sync on time | M8 | Run the plane apply in its own goroutine. Report first. Source read 2026-11-18 (`internal/envd`): the plane apply runs in its own goroutine, and `Offer` never blocks. Result 2026-11-18, for the two test sets of 20 to 30 s: envd still sent its reports. The gateway sync reached `mgmtd` every 10 s with no gap. Both cells stayed valid. The 5 minute case: <measured in the live part> |
| The M6 admit stage passes through the signed `dev-cp` path, and the time of a full provision | M8 | None. Record it, and report a total above 75 minutes. Result 2026-11-18: `TestM8CpAdmitStageSigned` passed in 547 s. After `cell:down` the plane set went from version 1/3 to 1/4, and the admit stage made it 1/5. It was healthy at every sample, and `dev-cell-2` was valid again about 9 minutes after `cell:down`. The telemetry check of the new cell failed for up to 5 minutes more. The time of a full provision: <measured in the live part> |
| cosign v3.1.4 verifies an Ed25519 DSSE attestation from `record.SignEnvelope`. It uses `--key` and `--insecure-ignore-tlog=true`, a v0.3 bundle with a key hint and no log entry, and the referrers tag schema on Distribution 3.1.2 | M8 | Ed25519 fails: move `mgmtd` to ECDSA P-256. Referrer lookup fails: `cosign verify-blob-attestation --bundle` on the file. Report first. Result 2026-11-18: it verifies, offline, in the referrer form, in the old `.att` tag form and as a bundle file. The P-256 control passes in the same forms, so no fallback applies |
| `controller.sync.timeout.seconds: "240"` ends a sync that waits on a later wave, and the rollback completes in the 5 minute wait | M8 | Terminate the operation of each child of the failed set, with `patch` on those children. Report first. Result: <measured in the live part> |
| The Rego evaluation of the `argocd` bundle under the limited capabilities: time and peak memory of `celld` and envd | M8 | Raise the memory limit. Report a time above 10 s. Result 2026-11-18, `celld`: the memory peak was 93.0 MiB in `dev-cell-1` and 88.6 MiB in `dev-cell-2`. This is 36% of the 256Mi limit, with no restart. The whole first set took 1.9 s in `dev-cell-1` and 9 s in `dev-cell-2`, from the signature to the result. That span covers 11 fetches, the checks of all bundles, the root compare and the state write. So the Rego time is below 2 s in `dev-cell-1`, as an upper bound. `celld` logs no fetch or check time. The real `argocd` render holds 37 objects in 2.08 MB, not about 2000. A unit test with 2000 generated objects checks in about 2.1 s under `-race`. envd: the memory peak was 108.2 MiB. This is 42% of the 256Mi limit, with no restart. The whole first set took 34 s, and envd logs no check time |
| containerd v2.4.2 `core/remotes/docker` compiles no `github.com/prometheus/` package and about the module list of the v2.2.0 probe | M8 | Stop and report. Result 2026-11-18: no Prometheus package compiles. The probe lists 15 third-party modules beside containerd, and the v2.2.0 probe lists 13. A stripped probe binary is 8.26 MB, against 3.34 MB for the baseline |
| Argo CD Agent v0.10.0 with Argo CD v3.6.1, header auth behind `cell-proxy` | M3 | The newest v3.5 release. Result 2026-11-13: it works. In two `gate:m3` runs, `TestM3AgentAuthenticatedAsOwnCell`, `TestM3AgentClientBinds` and `TestM3CentralViewShowsLiveResources` pass for both cells, so no fallback applies |
| The writes autonomous mode needs, beyond the refresh annotation | M3 | Report the gap. Result 2026-11-11, Argo CD Agent v0.10.0: it needs none. The agent Role has no write verb on Applications, and the agent still mirrors every Application. The gate run made the agent try these writes. For each principal event of a changed management copy, it tried to patch the Application: `spec-update`, `set-operation` and `terminate-operation`. Through the resource proxy it also tried to create a ConfigMap, patch a Deployment and delete a Service. The API server refused each one with Forbidden from RBAC, and the policy `argocd-agent-read-only` saw none. A token POST for the ServiceAccount of the agent stopped at the managed-object check of the agent. A Secret list stopped at the refusal of the resource proxy, and a Secret get stopped at RBAC. `TestM3GuardDeniesWithoutRBAC` shows that the policy denies the same writes when a Role grants them. No gap remains |
| Only the in-cluster collector reaches the principal and agent metrics endpoints | M3 | Turn the endpoint off. Result 2026-11-13: it does. In two `gate:m3` runs, `TestM3MetricsEndpointsCollectorOnly` passes for the principal, each agent and the other scraped endpoints in four clusters, so no fallback applies |
| Istio metric names survive the OTLP path into Prometheus, so Kiali finds `istio_requests_total` | M3 | A collector transform that restores the names. Result 2026-11-13: they do. In two `gate:m3` runs, `TestM3IstioMetricsSurviveOTLP` passes for both cells, so no fallback applies |
| Kiali accepts a remote cluster served through the `cell-proxy` tunnel, with no credential in its kubeconfig | M3 | A Kiali view that uses metrics only. Report the gap first. Result 2026-11-13: it does. The render gives each cell kubeconfig an empty user and no credential. In two `gate:m3` runs, `TestM3KialiSeesBothCells` passes, so no fallback applies |
| Kiali shows several separate meshes, each with its own trust domain, in one instance | M3 | One Kiali for each cell in `management`. Result 2026-11-13: it does. In two `gate:m3` runs, `TestM3KialiSeparateMeshes` passes, so no fallback applies |
| The time from an `envd` write of `cell-records` to the plugin log `records reloaded`, through the kubelet ConfigMap sync on kind v1.37 | M4 | None. Record it, and report a time above 120 seconds. Result 2026-11-13: 50 and 60 seconds. The span covers the kubelet sync of the volume and the reload every 10 seconds |
| A SPIRE agent sidecar in a crash loop attests after its record lands, and the time from bind to Ready | M4 | `attest-wait.sh` deletes the `celld` pod once. Result 2026-11-13: in both cells the agent was in a crash loop before the record existed. `attest-wait.sh` deleted the pod once, and the new pod attested. Bind to Ready took about 70 and 60 seconds, so the fallback applies. The wait for the deletion of the old pod has not run live |
| `mgmtd` reaches the host service at the resolved address under an ipBlock egress rule in kindnet | M4 | Stop and report. Result 2026-11-13: it does. `TestM4MgmtdReachesHostService` passes in two `gate:m4` runs, so no fallback applies |
| Argo CD prunes the M2 ConfigMaps `cell-record-<cell>` when they leave the `spire-server` bundle | M4 | Delete them once, and report. Result 2026-11-13: it does. After the `cell:up` of `dev-cp`, `spire-system` holds no `cell-record-*` ConfigMap, so no fallback applies |
| The kubelet fills an `optional: true` ConfigMap volume that was absent at pod start | M4 | Restart the SPIRE server once after `envd` creates `cell-records`. Result 2026-11-13: it does, with no restart. The first `records reloaded` came 160 seconds after `envd` created the ConfigMap, so no fallback applies |
| On the kind local-path volume, `fsGroup` leaves the key file at mode 0400 across a `mgmtd` restart | M4 | Set `fsGroupChangePolicy: OnRootMismatch`. Result 2026-11-13: it does. After `TestM4MgmtdStatePersists` deleted `mgmtd-0`, `TestM4SigningKeyReaders` found mode 0400 and the image uid 65532, so no fallback applies |
| An HTTP/2 full-duplex stream survives the `dev-cp` NodePort with kindnet, with PING keepalive and a reconnect at each SVID update, with no work gap above 15 s for 30 minutes | M5 | One long-poll claim request at a time, held up to 25 s. Result 2026-11-16: it works. `gate:m5:soak` sent 30 operations in 30 minutes. Each applied once. The largest claim gap was 747 ms, with 0 stream failures and 66 restarts for a new SVID. The soak samples the gap once for each operation, so an outage between samples is not measured. No fallback applies |
| TokenRequest on Kubernetes v1.37 accepts a 143-character audience | M5 | The first 32 hex characters of the digest. Result 2026-11-14: it accepts one of 149 characters and one of 96 characters, so no fallback applies |
| SQLite in WAL mode on the kind local-path volume keeps the queue across a pod delete and a VM restart | M5 | `journal_mode(DELETE)`. Result: the pod delete part passed on 2026-11-14. `TestM5GatewayStatePersists` found the epoch unchanged and the outbox item still there. The VM restart part is not verified. On 2026-11-16 the clusters did not survive the restart, as in the M1 row. `cell-gateway-0` stayed in a crash loop with the error `x509 source from the workload api: context deadline exceeded`, so no epoch was read. The cause is not verified. A rebuild is the recovery, and `mise run gw:reset` covers a lost volume |
| The `cluster_jwt` server plugin process gets an API client through `rest.InClusterConfig` | M5 | Config key `hint_token_file`. Result 2026-11-14: it works with no token file. The plugin patched `attest-hints`, and `TestM5UnknownKidTriggersKeyCheck` shows that the hint reached `mgmtd`, so no fallback applies |
| The time from an `unknown_kid` attestation to an issued one through the hint path | M5 | None. Report a time above 5 minutes. Result 2026-11-14 UTC: 40 to 112 seconds in five runs. Four test runs gave 74, 40, 87 and 79 seconds, and the full `gate:m5` run gave 112 seconds. The `keys_updated` hint check came 7, 3, 6, 8 and 8 seconds after the first refusal. The probe granularity is about 15 seconds |
| The Argo CD agent connects through a `spiffe-client` that writes the proof frame before it pipes bytes | M5 | None. Stop and report. Result 2026-11-14: it does. The principal listed both agent streams after the change, so no fallback applies |
| The dates of `modernc.org/sqlite` v1.61.0 and of every module it pulls in | M5 | The newest older release whose tree passes. Result 2026-11-14: the release is dated 2026-10-21, and the whole tree is dated 2026-10-26 or earlier. The review in `vendor/README.md` passed, and the module has no provenance document |
| The time from a `cell-registry` update to `registry reloaded`, through the kubelet ConfigMap sync | M5 | None. Report a time above 3 minutes. Result 2026-11-14: 28, 74 and 81 seconds for the slowest of the three servers. The time starts at the `keys_updated` log line of `mgmtd`
| `mise run cell:up` runs as a child of `hostsvc serve`, which `hostsvc-serve.sh` starts with `nohup` and `env -i`: `PATH`, `DOCKER_HOST` and the mise trust of the checkout reach it, and its `vm:up` dependency runs there | M6 | `hostsvc-serve.sh` passes `--bootstrap-cmd "<command -v mise> run cell:up"`. Report first. Result 2026-11-17, both runs of `gate:m6:provision` ran `cell:up` for each new cell as a child of the host service, and passed |
| A group SIGTERM, and the SIGKILL 10 seconds later, end `mise run cell:up` and its `kubectl`, `kind` and `docker` children on macOS | M6 | Kill each pid from `ps -g`. Report first. Result 2026-11-18: the mechanism holds on macOS. `TestGroupStopKillsTrapper` and `TestActorStageTimeoutKillsTrapper` end a child that ignores SIGTERM. No live stage was stopped with real `kubectl`, `kind` and `docker` children |
| The admit stage needs no secret token while the `dev-cp` store is connected | M6 | None. The stage fails with the hint. Result 2026-11-18: holds. All 7 step logs of two provision runs and `harness:up` show a connected store and no read of `.envrc.local` |
| The time of each stage for each cell, and the total from one portal request to both cells valid | M6 | None. Record it, and report a total above 75 minutes. Result: 2026-11-17, second run of `gate:m6:provision`: creating 25 and 26 s, admitting 1m9s and 1m19s, bootstrapping 6m38s and 5m17s, both steps done 15m6s after the request (first run 13m28s). No total above 75 minutes |
| The M3 Kiali tunnel wait and the M5 `registry_wait` pass in a `cell:link` that runs after cells were recreated, and with zero live cells | M6 | None. Stop and report. Result: 2026-11-17, passed in both runs of `gate:m6:provision`, whose step 10 links `management` after `cell:down` of both cells, and in the drill that rebuilt `management` |
| A server-side apply that deletes a rule or an `ipBlock` peer removes it from the live NetworkPolicy | M6 | None. Stop and report. Result 2026-11-17, in step 2 of both runs of `gate:m6:provision`, `cell:verify` of `dev-cp` with no cell found no rule or peer left from the render with cells (the drift check passed) |
| `POC_SECRET_TOKEN_CMD` is set inside `cell:up` after mise loads the global and parent configs under the actor | M6 | The actor sets `MISE_GLOBAL_CONFIG_FILE=/dev/null` and `MISE_CEILING_PATHS`, not verified for the pinned mise. Report first. Result 2026-11-18: no step log read `.envrc.local` (0 of 7), and the global mise config does not name the variable. The value inside the actor was not printed |
| A client that verifies its peer sends nothing to an impostor server, and each hop gives the reason of the rejection table. The SPIRE agent binary is not under test, because it is upstream code. Unit tests check the `reason` field of the `celld` logs. The live tests check the probe output of the same TLS settings | M7 | None. Stop and report. Result 2026-11-18, `TestM7InterceptCelldBind`, `CelldStream`, `SpireSidecar` and `CellProxyHops` (hops A to G) passed in two clean runs, and each hop gave the reason of the table. Two mutations (the exact-ID check, the bind client ID check) failed the matching subtests |
| A forwarder that flips one byte of the handshake or of the proof record ends the connection. The principal accepts no peer. A clean request through the same forwarder succeeds | M7 | None. Stop and report. Result 2026-11-18, `TestM7RelayForwardsCiphertextOnly`, `RelayAlteredHandshakeFails` and `RelayAlteredRecordFails` passed in two clean runs |
| In a namespace with a policy that denies all egress, no dial from a new `dev-cell-1` pod connects after 10 seconds. An attestation probe of another subject gets no SVID | M7 | None. Report a time above 10 seconds. Result 2026-11-18, `TestM7PolicyWindow` passed in four runs. The last dial that connected came at 800 to 807 ms, and the probe of another subject got `subject_not_allowed` and no SVID |
| A host network pod in `rogue` reaches exactly the residual ports of the `dev-cp` and `management` nodes. One in a cell also reaches the ports that admit its node address, and no others. Each mutual TLS port answers a handshake with no certificate with a TLS alert or a closed connection | M7 | None. Stop and report. Result 2026-11-18, `TestM7CellPodScansOtherCell`, `HostNetworkScan` and `PrincipalLoopbackOnly` passed in two clean runs |
| A pod of `rogue` that sends no certificate, or a wrong one, to the host service gets a TLS alert. The host service logs `handshake refused` | M7 | None. Stop and report. Result 2026-11-18, `TestM7RogueHandshakeToHostService` passed in two clean runs |
| A token that `rogue` signs fails at the attestor and at bind, and a client with another pin gets `issuer_untrusted`. `TestM2RejectRogueKey`, `TestM5BindRefusalsLive` and `TestM4HostServiceServesPinnedKeys` prove this in the gates of M2, M4 and M5 | M7 | None. Run those gates at the head of M7. Result: 2026-11-18, run alone at the head of M7 (61a0209): `TestM2RejectRogueKey` passed (15.4 s, 02:42 UTC), `TestM5BindRefusalsLive` passed (207 s, 02:43 UTC) and `TestM4HostServiceServesPinnedKeys` passed (0.8 s, 02:47 UTC) |

## Departures from the Kiln canon

- The canon moves Argo CD into `<env>-cp`. This design keeps Argo CD in every cell. **[owner]**
- The canon runs customer-data operations and the data gateway in a tools cell. This design runs them in the product cell. **[owner]**
- The canon's in-region workers reach Kiln's database directly. This design has `celld` claim work over an authenticated stream.
- The canon enforces approvals in Kiln. This design also enforces them in the cell. **[owner]**
- The canon's earlier boards use Crossplane. This design uses the custom cell controller with ACK. **[owner]**

## Open questions for the owner

- Whether clusters in the same cell call each other directly. The canon says a cell is one cluster, so the PoC assumes one.

## Left to the builder

- Database schemas for specs, records, queues and operation records.
- Protobuf definitions and the stream frame format, within the version rules above.
- Choice of storage provisioner, Postgres operator and metrics adapter library, after third-party review.
- How to package the SPIRE plugins, within the distroless rule.
- Timer values, except where this document sets a bound.
- Layout of the new code in this repository.
