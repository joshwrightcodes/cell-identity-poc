# Cell identity PoC: design

Status: draft for owner review, revision 4. Date: 2026-11-08. Facts that can change are as of
this date.

Source markers: **[owner]** means the project owner decided it. **[call]** means the author
chose it, and the owner can overrule it. **[canon]** means the Kiln design canon in the
`kiln-concept` repository says it. Text without a marker follows from those sources.

`docs/design/base-cell.md` describes the cluster template that every cluster uses. That
document is built and verified. This document builds on it.

Revision 4 applies a second round of security, network, DevOps and infrastructure reviews.
Each finding that depends on upstream behaviour was checked against upstream source or
documentation on 2026-11-08.

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
- Kiln opens no connection into an environment or a cell. Every connection goes up a layer. **[owner, canon]**
- Each layer keeps on with what it last knew when the layer above it is down. This is island mode, and an island is an incident. **[owner]**
- Each cell runs its own Argo CD, which manages only that cell's cluster. **[owner]**
- Customer-data operations run inside the product cell. **[owner]**
- `kiln-celld` is the cell's executor, the counterpart of `kiln-envd`. It is a service with many replicas. **[owner]**
- Logs and other OpenTelemetry signals hold no personal data, only product identifiers. **[owner]**
- Cells check approvers' own signatures, so a compromised Kiln alone cannot export or unmask data. **[owner]**

## Phases **[owner]**

| Phase | Covers |
| --- | --- |
| 1 | Attestation, Kiln-signed work, `kiln-celld`, bundles and safe updates, island mode and revocation, the read-only central view, customer-data operations and encrypted exports |
| 2 | Exploration sessions, cross-environment requests, HPA fan-out, rebuild-from-empty recovery, root rotation, and EKS |

Phase 2 sections are marked. A builder plans phase 1 first.

## Acceptance checks

`mise run poc:demo` shows these checks, and `mise run poc:gate` asserts them. **[call]**

1. Kiln requests two new cells, and the environment control plane creates them.
2. Each cell's `kiln-celld` registers and authenticates with its environment control plane.
3. Both cells appear in Kiln as valid.
4. A third, malicious cell starts, and it is rejected.

Phase 1 also covers these behaviours:

- Kiln sends operations to a cell and reads information from it, through the environment control plane.
- Kiln shows every cell in one Argo CD view, with live manifests. The view cannot change a cell.
- An environment cut off from Kiln, and a cell cut off from its environment control plane, continue on their last known state.
- A customer-data operation runs inside the cell, and an export leaves only as ciphertext, after approvers sign it.
- A bad `kiln-celld`, Argo CD or platform bundle rolls back with no step in the cell, and no rollback deletes a provider resource.
- Each phase 1 case in "Rejection tests" fails with the stated result.

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
- Kiln, the environment control plane or the central view changes a cell by any path other than a signed `kiln-celld` operation.
- An environment or a cell stops service to customers because the layer above it is unreachable.
- Customer data leaves a cell in plaintext, by any path, logs included.
- A rollback deletes a provider resource.
- AWS types or identifiers appear above the cell controller's provider backend.
- A test passes because a check was weakened, retried until green or stubbed.

## Constraints

- Local runtime: Apple `container` 1.7.1, from the signed GitHub release, pinned in the global mise config. **[owner]** The harness asserts the exact version.
- Kubernetes v1.37.0 node image, pinned by digest.
- `container` clusters cannot be stopped and started again, so a Mac restart is a disaster recovery event. The gate runs under `caffeinate`.
- Go 1.27, module path `github.com/joshwrightcodes/cell-identity-poc`, ko for images and distroless images. Every bespoke binary comes from one Go module with one release version.
- Images: locally, ko builds into the `container` image store, and clusters use `--shared-image-store`. On EKS, images live in ECR. CI pushes through GitHub OIDC, and nodes pull with their IAM role.
- Telemetry goes through OpenTelemetry (OTLP). Do not add Prometheus client libraries, `/metrics` endpoints or ServiceMonitors. Upstream metrics listeners are turned off.
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
| Agent names | `<env>-<cell>` | `dev-dev-cell-1` |

Local instances use `dev` as `<env>`: the clusters are `kiln`, `dev-cp`, `dev-cell-1`, `dev-cell-2` and `rogue`. M1 renames the base cell from `cell-a-1`.

### Keys and roots of trust **[call]**

| Class | Members | Where it lives |
| --- | --- | --- |
| Offline roots | Each trust domain's root CA, the recovery key | Offline. Used only to sign intermediates and key set changes |
| Online intermediates | Each SPIRE server's upstream intermediate, valid 30 days | The secret store, delivered to that SPIRE server |
| Kiln signing keys | Spec, record, platform bundle, application bundle and operation keys | Kiln's secret store |
| Approver keys | One signing key per approver, held on the approver's device | Never in a cluster. Public keys travel in signed approver directories |
| Rebuildable keys | SPIRE server CAs, the Argo CD Agent JWT key, mesh CAs | Generated inside the cluster |

- Locally, `mise run keys:seed` reads each key from the secret manager CLI on standard input, and creates the Kubernetes Secret directly. CI generates throwaway roots per run, passed on standard input.
- On EKS, an external store holds the online keys. A provider-neutral sync delivers them, and each key rotates with one command.
- A key set change needs signatures from the current key and from the recovery key.

## Topology and trust boundaries

| Cluster | Runs | Trust domain |
| --- | --- | --- |
| `kiln` | Kiln stand-in: intent, approvals, signed specs, key checks, Argo CD Agent principal, telemetry gateway | `kiln.poc.internal` |
| `dev-cp` | kiln-envd, SPIRE server, cell gateway, relay, cell controller with ACK, local alert rules | `dev.env.poc.internal` |
| `dev-cell-1`, `dev-cell-2` | The base cell, plus `kiln-celld`, its watchdog, `ops-runs`, `ack-system` controllers | Identities from `dev.env.poc.internal`; mesh in `<cell>.mesh.poc.internal` |
| `rogue` | Genuine `kiln-celld` and agent images, plus attack tools | Unregistered |

Local size is measured at M1, and the README states it. The Mac has 18 cores and 64 GB, so the
gate keeps headroom for the builder and ko. **[call]**

### Kiln stand-in **[call]**

The stand-in holds only what the tests need: intent and approvals for two environments, the
signing keys, the key check, a registry of cells, the Argo CD UI with the principal, and the
telemetry gateway. It has no developer portal, catalog or workflow engine.

### Identities **[call]**

| Principal | SPIFFE ID |
| --- | --- |
| Kiln API | `spiffe://kiln.poc.internal/api` |
| Kiln principal proxy | `spiffe://kiln.poc.internal/argocd/principal` |
| Kiln telemetry gateway | `spiffe://kiln.poc.internal/telemetry` |
| kiln-envd | `spiffe://<env>.env.poc.internal/kiln-envd` |
| Cell gateway, relay | `spiffe://<env>.env.poc.internal/cp/<name>` |
| kiln-celld | `spiffe://<env>.env.poc.internal/cell/<cell>/kiln-celld` |
| Argo CD agent | `spiffe://<env>.env.poc.internal/cell/<cell>/argocd-agent` |
| Cell collector | `spiffe://<env>.env.poc.internal/cell/<cell>/otel` |
| SPIRE agent, per pod | `spiffe://<env>.env.poc.internal/spire/agent/cluster_jwt/<cell>/<pod-uid>` |

- Kiln and each environment pin each other's root CA. Trust domains do not federate through bundle endpoints.
- Authorization reads parsed path segments, never string prefixes.
- The `kiln-celld` identity is per service. The pod UID comes from the attested SPIRE agent, never from the client.

### Second proof for traffic to Kiln **[call]**

The environment's SPIRE server can mint any identity in its environment. Traffic that a cell
sends up to Kiln therefore carries a second proof that the environment control plane cannot
mint:

- Each upward stream also presents a projected service account token from the cell, with the audience `kiln`.
- Kiln verifies that token against the cluster keys in the Kiln-signed cell record, and checks that its subject matches the SVID.
- A compromised environment control plane can still drop or delay traffic, but it cannot pose as a cell to Kiln.

### Network flows

Every connection goes up a layer. **[owner, canon]**

| Source | Destination | Purpose |
| --- | --- | --- |
| Cell SPIRE sidecars | `<env>-cp` SPIRE server | Attestation and SVID renewal |
| kiln-celld | `<env>-cp` cell gateway | Operations, status, cell-to-cell requests |
| Argo CD agent, cell collector | `<env>-cp` relay, then Kiln | Status, live view and telemetry |
| kiln-envd | Kiln API | Pull signed specs, report status |
| `<env>-cp` relay | Kiln listener for that environment | Forward cell streams |
| Cell controller | Provider APIs | Create and delete cells |
| Bootstrap actor, operators | A cell's Kubernetes API, over the tailnet | Bootstrap and break-glass only |

- Each Kiln listener serves one environment and trusts that environment's root only.
- Cross-cluster TLS ends only at the two endpoints, never at a load balancer, an ingress or the relay.
- No flow goes from one cell to another.

Zero trust rule: the identity check decides every access. Network controls only reduce exposure.

### The relay **[call]**

The relay carries agent and telemetry streams from cells to Kiln. Each stream has two TLS
layers:

1. An outer mTLS layer from the cell to the relay, with the cell's SVID, and from the relay to Kiln, with the relay's SVID.
2. An inner TLS layer from the cell's `cell-proxy` to Kiln's `cell-proxy`, end to end. The relay cannot read it.

Because the relay sees the outer identity, it:

- authorizes each cell against the current spec, and closes its streams when the cell is revoked;
- caps connections per cell, and enforces handshake and first-byte timeouts;
- uses separate ports for agent and telemetry streams, so a telemetry flush cannot starve the live view.

Kiln's listener admits only relays.

### Plane endpoints **[call]**

- The signed cell record carries an endpoint set for the environment control plane. During a move, the set holds the old and the new endpoints together.
- The endpoints outlive the environment control plane. Locally, pf on the Mac forwards fixed ports at the vmnet gateway address. On EKS, Elastic IPs are allocated outside the control plane's lifecycle and recorded in the spec.
- NodePort values are pinned, in the range 30000–32767.
- The NLBs have no source allow-list. Identity decides access.

### Kubernetes API access **[owner]**

- A cluster's Kubernetes API is reachable only from the operators' tailnet. On EKS, each cluster has a private API endpoint only.
- Tailnet tags are per environment and per cell. The bootstrap actor reaches only a cell with the bootstrap tag. Kiln removes that tag at the end of bootstrap, and the gate checks the removal.
- Each cell's subnet router joins with a single-use, short-lived key. Routes are approved only for the CIDR allocated to that cell.
- Locally, vmnet stands in for the tailnet, so the local run cannot prove this property. The EKS run proves it.

### Network isolation **[call]**

- Each cluster gets its own VPC on EKS, with no peering between cluster VPCs.
- Every namespace has default deny, `kube-system` included.
- Traffic from nodes is allowed only to probe and webhook ports, per workload. On EKS, webhook calls come from the cluster subnets, so those CIDRs are allowed for webhook ports.
- A ValidatingAdmissionPolicy in each cell denies `NodePort` and `LoadBalancer` Services, `hostPort` and `hostNetwork`, except for named platform components.
- Kiln signs a network policy template. `kiln-celld` fills in only typed fact fields under a schema: subnet CIDRs, never single node addresses. A static egress rule lets `kiln-celld` reach the plane endpoints without rendered facts.
- On EKS, VPC CNI runs network policy in strict mode. Any cluster-wide policy type stays inside the provider backend.
- Each upward flow has its own egress rule from the namespace that needs it, listed with the component in the bundles.

## Identity

### Why a custom attestor

SPIRE's `k8s_psat` attestor validates through TokenReview, so a remote server needs a
kubeconfig for each cluster. The PoC adds a small NodeAttestor plugin pair, `cluster_jwt`. It
validates a projected service account token against the public signing keys of that cluster.
Teleport's `static_jwks` join method and the SPIFFE `spire-identity-exchange` validator do the
same. Read both before the attestor is written.

### SPIRE CAs **[call]**

- Each environment's root CA stays offline. It signs an upstream intermediate valid for 30 days, which the SPIRE server loads through the `disk` UpstreamAuthority with `bundle_file_path`.
- Rotating the intermediate is one command, and cells notice nothing, because they pin the root.
- Every sidecar pins the root. `insecure_bootstrap` stays off.
- Root rotation is a key set change delivered in platform bundles, with the old and new roots trusted together. **[phase 2]**

### Attestation

The SPIRE agent runs as a sidecar in each pod that needs an identity, with no DaemonSet, host
path, CSI driver or kubelet access. The sidecar verifies the exact server ID before it sends a
projected token with the audience `spire-<env>`.

The server plugin takes these steps. Any error denies:

1. It loads the cell record from the current signed spec, with any local revocation overlay. It refuses a revoked cell.
2. It verifies the token signature against the cluster keys in that record, never against keys chosen by the `iss` claim.
3. It checks audience, namespace and service account against the record.
4. It requires a token bound to a pod, with the pod UID and node claims.
5. It requires a lifetime of 15 minutes or less, and an `iat` no older than 15 minutes.
6. It refuses a token ID (`jti`) already used by a different pod UID. The same pod may retry with the same token, because kubelet reuses tokens until 80% of their lifetime.
7. It limits attestation per cell, after the signature check.
8. It returns `can_reattest = true`, so a sidecar whose SVID expired attests again with a fresh token.

- SPIRE's built-in rate limit of one attestation per second per IP is turned off, because cells share NAT and relay addresses. Step 7 replaces it.
- A node alias entry maps cluster and service account selectors to the workload parent, so HPA scale events write no entries.
- The server prunes expired agents with `prune_attested_nodes_expired_for`.

### Independent key check **[call]**

The environment control plane creates cells, so it cannot vouch for their keys:

- Kiln reads each new cluster's signing keys from the provider's public issuer, which needs no credential.
- The issuer is bound to the cell at first start. `kiln-celld` sends Kiln a projected token whose audience is a nonce from Kiln. Kiln accepts the issuer only if that token verifies against it.
- Kiln signs the keys into the cell record. Kiln checks again every 15 minutes, and at once when an attestor reports an unknown key ID, at most once per cluster per minute.
- Locally, a host service on the Mac, outside every cluster, serves each cluster's `/openid/v1/jwks` over TLS with a certificate that Kiln pins.

### Signed specs and records **[canon; details are a call]**

- Each spec revision carries Kiln's signature and a revision of the form `(epoch, counter)`. kiln-envd refuses an unsigned spec or an older revision.
- A cell record holds the cell's cluster keys and issuer, endpoint set, agent name, replica cap, key sets, approver directory, export allow-list and status.
- Specs and records have no expiry, so an island never stops an environment.
- Record changes are staged per cell. kiln-envd refuses a revision that would newly invalidate more than one cell at a time, unless it carries a recovery-key signature.

### Island mode and keys **[owner]**

An island is an incident. While it lasts, no trust changes:

- No cell record, key set, approver directory or SPIRE root changes.
- An attestor does not accept a cluster key that is not in the last signed record.
- EKS rotates each cluster's signing key every 7 days, and that rotation cannot be paused. After a rotation during an environment island, new pods that need an identity in that cell cannot attest until Kiln confirms the new key.
- Running SPIRE agents renew over their current connection, without a new token, so running workloads keep their identities.

The incident response is a change freeze. The HPA holds its current size, rollouts wait, and
alerts fire at once. Customer traffic is never affected.

### Key rotation and recovery **[call]**

Every trust change follows the same rules, whatever the key:

1. **Signed key sets.** A change to what a component trusts arrives as a key set with a version and an epoch. The receiver verifies it with the current key and the recovery key, whatever channel carried it. A compromised channel can delay a key set, but cannot forge or alter one.
2. **Overlap.** The next key is published before it is used. The old key retires only after every valid receiver acknowledges the new set, or after a fixed maximum time.
3. **No downgrade.** A receiver refuses a key set with a lower version.
4. **Narrow freely, widen only when connected.** Removing trust is allowed at any time, also locally during an island. Adding trust needs Kiln and the recovery key, so it never happens during an island.
5. **Key sets first on reconnect.** After an island, a component applies pending key sets before any other work. Only then does Kiln confirm rotated cluster keys, and only then does queued work run.

| Key | Planned rotation | Emergency rotation, after a suspected compromise | Recovery from loss |
| --- | --- | --- | --- |
| Cell cluster signing key, rotated by the provider | Kiln fetches the new key from the bound issuer, adds it, and keeps the old one until its tokens expire. More than two new keys since the last check needs an approver signature, because it may mean a compromised issuer | Kiln removes the key in a new record. On EKS the provider rotates; locally an operator rotates with two `--service-account-key-file` values | The provider holds it. Kiln confirms the next key from the issuer |
| SPIRE intermediate CA | Replaced at half its 30-day life. Cells notice nothing, because they pin the root | The offline root signs a new intermediate. The environment's SVIDs reissue within one lifetime | Load a new intermediate from the offline root |
| SPIRE root CA | Next root added to every cell's key set, then the old root retired after acknowledgement. **[phase 2]** | A recovery-signed key set removes the root. Islands trust it until they reconnect | Key set signed by the recovery key |
| Kiln signing keys | Current and next in each key set | A recovery-signed key set removes the key. Sensitive items still need approver signatures, which bounds the damage | Key set signed by the recovery key |
| Approver keys | Directory change, signed by Kiln and the recovery key | Removal from the directory, which narrows trust and needs only the recovery key | The approver enrols a new device key |
| Export recipient keys | Next recipient added to the allow-list. Old private keys stay in the recipient's store until the exports' retention ends | Removal from the allow-list | Exports to a lost key cannot be read. Retention of recipient private keys is the recipient's duty |
| Recovery key | A ceremony: the old key signs the new one | Split into shares, so no single holder can use it. M of N holders replace it | If fewer than M shares remain, cells re-bootstrap through break-glass. This is the last resort |
| Mesh CA, Argo CD Agent JWT key | Rebuildable, regenerated inside the cluster | Regenerate, then restart the affected workloads | Regenerate |

The recovery key uses 3 of 5 shares, and its public key is pinned in every cell at bootstrap.

### Revocation **[call]**

- When connected, Kiln marks a cell revoked in a new spec revision. The SPIRE server, the cell gateway and the relay refuse the cell at once. Kiln's `cell-proxy` closes its live streams.
- In island mode, an operator revokes the cell at `<env>-cp` with one command over the tailnet. The revocation is a local overlay that only narrows trust. It stays in force until a Kiln revision includes it.
- A revocation is mirrored to Kiln at once when connected. A restore never goes back past the last revocation.
- A revoked cell keeps serving its customers. Stopping service is a decommission.

### Restore and counters **[call]**

- Every counter carries an epoch: spec revisions, queue fencing tokens and component versions.
- After a restore, Kiln bumps the epoch with a recovery-key signature, and resumes above the high-water marks that kiln-envd and `kiln-celld` report.
- A restore of an environment control plane bumps its queue epoch, and reapplies local revocations from Kiln's mirror.

## Provisioning flow **[owner, canon; details are a call]**

1. A developer requests a cell in Kiln. Approvers who are not the author sign it.
2. Kiln adds a pending cell to the spec: name, cluster reference, agent name, replica cap and the digests of the bootstrap set.
3. kiln-envd pulls the spec, and gives the step to the cell controller.
4. The cell controller creates the account, VPC and cluster through its provider backend. It tags every resource with the cell and the step, and records each provider ID.
5. The bootstrap actor applies only the pinned bootstrap set over the tailnet. Locally, the actor is the host service on the Mac. On EKS, it is a separate service with a scoped, short-lived credential, not the cell controller.
6. Kiln removes the bootstrap access: the tailnet tag, the EKS access entry and the account's administrator role.
7. Kiln binds the cluster's issuer, reads its keys and signs the cell record into a new spec revision.
8. Cell sidecars attest. `kiln-celld` connects to the cell gateway, and kiln-envd reports the cell as valid.
9. The cell's Argo CD agent connects to Kiln's principal through the relay.

### Cell controller **[owner: custom controller with ACK; details are a call]**

| Backend | Use | Creates clusters with | Keys from |
| --- | --- | --- | --- |
| `local` | Mac demo and every local milestone | `container cluster`, through the host service | Host service, over pinned TLS |
| `kind` | Linux CI | kind, through a runner-side service | The same, on the runner |
| `aws` | EKS, phase 2 | ACK controllers | Public issuer JWKS |

- The `local` backend is the only way the harness creates cells from M1, so there is one provisioning path.
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

Each `kiln-celld` replica holds one outbound stream to the cell gateway. The environment
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
- SPIRE servers upgrade one minor version at a time, and never while any cell of the environment is an island.

### Signed work and idempotency **[call]**

- Kiln signs every operation, bundle and session grant. The DSSE payload binds the target cell, kind, operation ID, expiry and approver signatures.
- `kiln-celld` refuses an unsigned item or an item for another cell.
- Each operation applies at most once, by its 128-bit operation ID. `kiln-celld` records each applied ID with a create-only object, kept until the operation's expiry. A second application fails to create the record.
- An operation past its expiry is reported as `expired`, never applied late. Expiry is shorter than record retention, so an old operation cannot be replayed.
- Bundles carry a component version with an epoch. `kiln-celld` refuses a lower version, and treats a resend with the same digest as a no-op.

### Approvals in the cell **[owner: cells check approvers; details are a call]**

- Each signed record carries an approver directory: approvers' public keys and roles. A change to the directory is a key set change.
- Kiln forwards each approval as the approver's own signature over the item's digest.
- `kiln-celld` checks the policy itself: the author never approves, deletion, unmasking and exports need a Data Protection approver, and platform bundles need a platform approver.
- Because of this, a compromised Kiln alone cannot export data, unmask it, or remove a cell's guards.

### Bundles, Argo CD and safe updates **[owner: Argo CD per cell; details are a call]**

1. An operation delivers a signed, hydrated bundle to `kiln-celld`.
2. `kiln-celld` verifies the signatures, the version and the target. It checks every object against the key's allow-list, by kind and namespace.
3. It pushes the bundle by digest to the bundle store, and composes the root bundle under a cell-wide Lease.
4. Argo CD applies it, within an AppProject for each key. Each AppProject repeats the kind and namespace limits.

Key allow-lists:

| Key | May change |
| --- | --- |
| Platform bundle key | Platform components, network policy, mesh policy, Argo CD, `cell-system`, `ack-system`, `observability-system` |
| Application bundle key | Product namespaces only. Not `ServiceEntry` with `exportTo: "*"`, `EnvoyFilter`, `PeerAuthentication`, `Service` of type `NodePort` or `LoadBalancer` |

Rollback and health **[call]**:

- A rollback is a roll-forward. Kiln, or the cell on its own, publishes the previous content as a new version. It never removes an Application, so nothing is pruned.
- The health check uses in-cell signals only: Argo CD Synced and Healthy at the digest, a reply from the bundle store, and the updated workloads ready. A network partition alone never triggers a rollback.
- The bundle store keeps the last two good roots and the bundles they pin, safe from garbage collection.
- Platform bundles go to the canary cell named in the spec first.

`kiln-celld` and Argo CD update through their own path, because they run the normal one:

- `kiln-celld` updates blue/green. The new version starts beside the old one, and the old one stops only after the new one holds its stream and passes its checks.
- A small static watchdog in `cell-system` reverts a `kiln-celld` or Argo CD rollout that does not become healthy within its deadline. Bundles cannot change the watchdog.
- Argo CD upgrades are applied by `kiln-celld` directly, under the same watchdog, not by Argo CD itself.

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
| Metadata discovery | An ordinary read operation, in phase 1 |
| Queries over customer rows | An interactive session through an in-cell explore gateway |

A session works like this:

1. Approvers sign a grant bound to one person's client public key, cell, database, masking level and time limit of 60 minutes or less.
2. `kiln-celld` starts an explore gateway as a Job in `ops-runs`, and reports its ephemeral key fingerprint. Kiln adds the fingerprint to the grant.
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
- `kiln-celld` and the Argo CD agent stay up, and reconnect with jittered backoff.
- The collector queues to a persistent volume sized for 24 hours of signals.
- On reconnect, sidecars attest again if needed, kiln-envd resends the latest bundles, and local revocations reconcile with Kiln.

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
Application, not only `.operation` (verified in `internal/manager/application`). The guard
therefore sits in the cell:

- A ValidatingAdmissionPolicy lets the agent's service account change only the `argocd.argoproj.io/refresh` annotation. It denies every other annotation, `.operation`, and every create, update or delete.
- The agent's Applications live in a namespace that holds no Secrets. The agent may list and watch Secrets there, because its informer requires it, and never get them elsewhere.
- The agent's read access is bound per namespace. It excludes `ops-runs`, so Job logs never reach the view.
- Argo CD RBAC at Kiln also denies sync, terminate, delete and exec, as defence in depth.

### Upgrades **[call]**

The principal refuses any agent with a different version (verified in
`principal/apis/auth/auth.go`). The cell record lists a principal endpoint for each version,
and principals split agents by namespace. An upgrade starts a new principal, moves cells as
their bundles update, and stops the old one when no cell uses it. Kiln's Argo CD, the cell's
Argo CD, the agent and the principal upgrade as one tested set. An alert fires on any version
mismatch.

## `cell-proxy` **[call]**

One small binary, built in this repository with go-spiffe:

| Mode | Used by | Behaviour |
| --- | --- | --- |
| `spiffe-client` | Argo CD agent, cell collector | Presents the pod's SVID and the second proof. Accepts only the exact upstream ID |
| `spiffe-server` | Kiln listeners | Requires an anchored client ID pattern and the second proof, checks the registry, sets the identity header and removes any copy from the client |
| `token` | Bundle store | Checks a service account token with the cell's own TokenReview API |

go-spiffe follows bundle and SVID changes at run time, so a CA rotation needs no restart.

## Telemetry **[owner: no personal data in signals; details are a call]**

- Each cell's collector sends OTLP through the relay to Kiln.
- The collector forwards only allow-listed attributes, span names and event names. Log bodies come only from fixed message templates.
- A test injects a canary personal-data string into a cell, and asserts that it never reaches Kiln.
- Each `<env>-cp` evaluates local alert rules, so an island is visible without Kiln.

| Signal | Alert when |
| --- | --- |
| Island state, per environment and per cell | Any island |
| SVID time to expiry | Less than 15 minutes |
| Attestation denials, by code | Any denial for a valid cell |
| Root digest compared with the intended digest | Different for 10 minutes |
| Argo CD health | Not Healthy for 10 minutes |
| Spec revision lag | A cell more than one revision behind |
| Intermediate CA expiry | Less than 7 days |
| Agent version mismatch | Any |
| Collector drops | Any |

## State and recovery **[call]**

| State | Lives in | After the loss of its cluster |
| --- | --- | --- |
| Intent, specs, approvals, registry, revocation mirror | Kiln database | Restore Kiln, bump the epoch. Environments keep running meanwhile |
| Operation queue, fencing epochs | `<env>-cp` queue database | Restore, bump the queue epoch |
| SPIRE datastore | Its own database, separate from the queue | Rebuild from the spec. Agents attest again |
| Provider resource IDs | Kiln record | Adopt by ID |
| Online keys | Secret store | Load again |
| Bundles, applied operation IDs, sender state | The cell's bundle store and objects | kiln-envd resends; operation records survive in the cell |

- If its database stalls, the cell gateway keeps its open streams and cached cap state. It refuses only new streams.
- Locally, Postgres runs on a persistent volume, and `mise run plane:backup` streams a backup to the Mac with no secret in it.
- The HA path for a SPIRE server is a second server in another zone, with the same root and its own intermediate. **[phase 2]**

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
| 1 | Rogue cluster runs a genuine `kiln-celld` | Attestor: keys match no record | `unknown_cluster_keys` | 1 |
| 2 | Rogue cluster claims a real cell's name, with the same default issuer | Signature check | `token_invalid` | 1 |
| 3 | Pod with another service account or namespace | Attestor | `subject_mismatch` | 1 |
| 4 | Token for the wrong audience | Attestor | `audience_mismatch` | 1 |
| 5 | Expired token | Attestor | `token_expired` | 1 |
| 6 | Token requested with a lifetime of 1 year | Attestor | `token_lifetime` | 1 |
| 7 | Token not bound to a pod | Attestor | `token_unbound` | 1 |
| 8 | Token reused by another pod | Attestor | `token_replayed` | 1 |
| 9 | Rogue serves its own JWKS for a real cell, or reaches the host service | Kiln pinned TLS; Mac packet filter | `issuer_untrusted` | 1 |
| 10 | Pod beyond the replica cap, or claiming another pod's UID | Cell gateway | `replica_cap` | 1 |
| 11 | `kiln-celld` in cell A claims cell B | ID from verified claims | `cell_mismatch` | 1 |
| 12 | Environment control plane forges or changes an operation or bundle | `kiln-celld` signature check | `signature_invalid` | 1 |
| 13 | Operation applied twice, or replayed after its expiry | Operation record; expiry | `already_applied`, or `expired` | 1 |
| 14 | Bundle with a lower version | `kiln-celld` | `version_old` | 1 |
| 15 | Item signed for cell A presented in cell B | `kiln-celld` target check | `wrong_target` | 1 |
| 16 | Export, unmask or platform bundle signed by Kiln without valid approver signatures | `kiln-celld` approval policy | `approval_missing` | 1 |
| 17 | Export to a recipient or store not on the allow-list | `kiln-celld` | `export_refused` | 1 |
| 18 | Application-key bundle with a forbidden kind or namespace | `kiln-celld` allow-list and AppProject | `component_not_allowed` | 1 |
| 19 | Network policy bundle that blocks the plane endpoints | `kiln-celld` | `policy_blocks_planes` | 1 |
| 20 | Spec with a lower revision, no Kiln signature, or invalidating several cells | kiln-envd | `spec_invalid` | 1 |
| 21 | Cell controller step without a Kiln signature, or with a modified bootstrap set | Cell controller; bootstrap actor | `step_invalid` | 1 |
| 22 | Environment control plane poses as a cell to Kiln with an SVID it minted | Kiln second proof | `proof_missing` | 1 |
| 23 | TLS interception, `kiln-celld` to the cell gateway | `kiln-celld` | `peer_untrusted`, or `peer_not_allowed` | 1 |
| 24 | TLS interception, sidecar to SPIRE server | Sidecar | Connection refused | 1 |
| 25 | Relay or Kiln impostor between agent and principal, with an environment-minted SVID | `cell-proxy` exact ID | `peer_not_allowed` | 1 |
| 26 | kiln-envd connects to a fake Kiln | Pinned Kiln root | `peer_untrusted` | 1 |
| 27 | TCP relay that only forwards, or alters bytes | TLS | Ciphertext only; `peer_untrusted` | 1 |
| 28 | Revoked cell's existing relay and principal streams | Relay; Kiln `cell-proxy` | Closed within 5 seconds | 1 |
| 29 | Forged identity header sent straight to the principal port | Principal on `127.0.0.1` | Connection refused | 1 |
| 30 | Annotation change other than refresh, `.operation`, or any write through the view | Admission policy in the cell | Denied; the cell does not change | 1 |
| 31 | Read a Secret, or `ops-runs` logs, through the view | Agent RBAC in the cell | Forbidden | 1 |
| 32 | Agent from environment X claims a cell of environment Y | Per-environment listener | `peer_not_allowed` | 1 |
| 33 | Argo CD's token writes to the bundle store, or `kiln-celld`'s reads as Argo CD | Store `cell-proxy` | `peer_not_allowed` | 1 |
| 34 | Stale fencing token after lease loss or a restore | Queue; in-cell Lease | `lease_lost` | 1 |
| 35 | Pod in cell A, or in `rogue`, scans cell B, with NodePort and hostNetwork attackers | Isolation rules and admission policy | Every connection fails | 1 |
| 36 | Cell A asks to reach cell B with no policy, or names another sender | Environment control plane | `cross_cell_denied`, `cell_mismatch` | 1 |
| 37 | Revoked cell reconnects, or reappears after the next spec revision | Attestor overlay; gateway | `cell_revoked` | 1 |
| 38 | Operation Job reaches a host that is not its target | Run NetworkPolicy | Connection fails | 1 |
| 39 | Canary personal-data string logged in a cell | Collector allow-list; view RBAC | Never reaches Kiln | 1 |
| 40 | Rollback of a bundle that created an ACK resource | Retain policy; no prune | The provider resource remains | 1 |
| 40a | Key set without the recovery signature, with a lower version, or that widens trust during an island | Receiver | `keyset_invalid` | 1 |
| 40b | Item signed by a retired or removed key | `kiln-celld` | `signature_invalid` | 1 |
| 41 | Session broker with a valid gateway SVID relays a person's grant | Person-bound mTLS | `session_denied` | 2 |
| 42 | Session used by another person, after its time limit, or for writes | Explore gateway; database role | `session_denied` | 2 |
| 43 | Cell controller adds an access entry to a cell after bootstrap | Organisation policy | `AccessDenied` | 2 |
| 44 | CCP pod or internet client connects to a cell's Kubernetes API on EKS | Private endpoint; tailnet ACL | Connection fails | 2 |
| 45 | New pod on EKS sends traffic before its policy applies | VPC CNI strict mode | Traffic is dropped | 2 |

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
| Bad platform bundle, bad `kiln-celld`, bad Argo CD, each separately | Rolled back with no step in the cell | 1 |
| Bundle store lost during an island | No Application is pruned, and the store refills after reconnect | 1 |
| Local revocation in island mode | The cell stays refused after the next Kiln revision | 1 |
| Planned rotation of a Kiln signing key and the SPIRE intermediate, under load | No operation fails and no identity lapses | 1 |
| Emergency removal of a Kiln key while one cell is an island | Connected cells refuse the key at once. The island cell applies the key set before any work on reconnect | 1 |
| Recovery key replaced from 3 of 5 shares | Cells accept the new recovery key, and refuse key sets signed by the old one | 2 |
| Kiln restored from a backup one hour old | Environments accept the next spec, and cells accept the next operation | 2 |
| `dev-cp` deleted, rebuilt from empty, then restored | Every cell reconnects with no step in any cell, at the same endpoints | 2 |
| Attestation burst after an outage, with a rogue flood | Every real sidecar attests within 5 minutes | 2 |
| 1,000 operations with random replica kills and partitions | None lost, none applied twice | 2 |

Every random choice in a test records its seed.

## Residual risks

- A cell's cluster token signing key is the root of trust for that cell. A cluster admin who can request tokens can act as that cell's `kiln-celld`.
- The environment control plane is trusted on first use for the cells it creates. After bootstrap, it can mint identities in its environment and stop work on its way to cells. It cannot forge Kiln-signed work, pose as a cell to Kiln, or change a cell's access.
- Kiln and its approvers together can change any cell. Kiln alone cannot export, unmask or remove guards.
- During an environment island, a rotated cell key blocks new pods that need an identity in that cell until Kiln reconnects.
- During an island, a cell that Kiln revoked continues until an operator revokes it locally.
- An emergency key removal cannot reach a cell in island mode until it reconnects. Until then, approver signatures bound what a stolen Kiln key can do there.
- Live-view pod logs outside `ops-runs` rest on the rule that services log no personal data.
- Locally, any cluster can reach another cluster's Kubernetes API on vmnet, and every cluster shares one source address. EKS removes both.
- Argo CD Agent is a v0.x project, and its principal HA is beta.

## Testing tiers **[call]**

| Tier | Runs on | Covers |
| --- | --- | --- |
| Unit and component tests | GitHub CI | Go packages, the attestor, `cell-proxy`, signature, approval and idempotency checks |
| Linux gate | GitHub CI, 4 CPUs and 16 GB | `kiln`, `dev-cp`, one cell and `rogue`, with Istio off where a test does not need it. Throwaway roots. Does not test how roots load from the secret store |
| Mac gate, fast | The owner's Mac | Phase 1 acceptance and rejection tests |
| Mac gate, slow | The owner's Mac | Survivability tests |
| EKS gate | EKS, phase 2 | Everything, plus tests 43–45 and latency bounds |

## Prior art

| Part | Prior art |
| --- | --- |
| Token validation against exported cluster keys | Teleport `static_jwks` join method; SPIFFE `spire-identity-exchange` validator |
| Agents that connect out to a control plane | GKE Connect, Azure Arc, Rancher. These tunnel API access, which this design avoids |
| Pull of signed specs with no stored credentials | Redpanda BYOC; Kiln's own kiln-envd |
| Central Argo CD view with agents | Argo CD Agent, which this design uses |
| Workers that compete for queued work | Temporal with KEDA |

## Milestones

Phase 1:

| # | Milestone | Done when |
| --- | --- | --- |
| M0 | Base cell | Done on 2026-11-07, renamed on 2026-11-08 |
| M1 | Harness and provisioning path | The `local` backend and host service create `kiln`, `dev-cp`, two cells and `rogue` twice from clean, with storage and keys. The Linux gate runs. Test 35 passes |
| M2 | Attestor | `kiln-celld` gets an SVID, against a test-signed record. Tests 1–8, 10, 11 and 24 pass |
| M3 | Kiln stand-in, specs and records | Specs and records come from Kiln, with the key check and the issuer bound to each cell. Tests 9, 20, 22 and 26 pass |
| M4 | Streams and signed work | Operations, status and cell-to-cell requests work, with idempotency and approvals. Tests 12–17, 23, 34 and 36 pass |
| M5 | Provisioning end to end | Checks 1–3 pass from one Kiln request. Test 21 passes |
| M6 | Malicious cell and MITM | Check 4 and tests 25 and 27 pass |
| M7 | Bundles and safe updates | Tests 18, 19, 33 and 40 pass, and the bad-bundle tests pass |
| M8 | Central view | Kiln shows every cell. Tests 28–32 and 39 pass |
| M9 | Customer-data operations and exports | Jobs and encrypted exports work. Test 38 passes |
| M10 | Island mode, revocation and key rotation | Tests 37, 40a and 40b and the phase 1 survivability tests pass |

Phase 2: exploration sessions, cross-environment requests, HPA fan-out, Kiln and `dev-cp`
restore and rebuild, root rotation, the HA SPIRE server, and EKS with the `aws` backend. EKS
touches a real AWS account, so it starts only after the owner approves the account and the
spend.

## To verify at the milestone

| Item | Milestone | Fallback |
| --- | --- | --- |
| Pod-to-NodePort traffic across `container cluster` clusters through pf | M1 | Stop and report |
| `--shared-image-store` serves ko images to cluster nodes | M1 | A registry container on vmnet |
| A storage provisioner that passes review | M1 | Stop and report |
| The Linux gate fits in 4 CPUs and 16 GB | M1 | Fewer components per run |
| Sidecar SPIRE agent with the `unix` workload attestor | M2 | DaemonSet agent where allowed |
| `can_reattest` with a per-pod agent ID, and agent behaviour after SVID expiry | M2 | Report and redesign |
| Shortest SVID and intermediate lifetimes SPIRE allows, for the test profile | M2 | Longer slow tier |
| Service account key rotation on `container cluster` nodes | M2 | Run that test in the Linux gate only |
| Approver signatures from device-held keys in the PoC | M4 | Software keys per test approver |
| Argo CD OCI source through a localhost proxy that adds a token | M7 | Local TLS on the proxy |
| Argo CD Agent v0.10.0 with Argo CD v3.6.1, header auth behind `cell-proxy` | M8 | The newest v3.5 release |
| The writes autonomous mode needs, beyond the refresh annotation | M8 | Report the gap |
| Principal metrics listener off | M8 | NetworkPolicy blocks it |

## Departures from the Kiln canon

- The canon moves Argo CD into `<env>-cp`. This design keeps Argo CD in every cell. **[owner]**
- The canon runs customer-data operations and the data gateway in a tools cell. This design runs them in the product cell. **[owner]**
- The canon's in-region workers reach Kiln's database directly. This design has `kiln-celld` claim work over an authenticated stream.
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
