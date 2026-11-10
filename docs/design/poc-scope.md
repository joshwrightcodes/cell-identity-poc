# Cell identity PoC: build scope

Status: draft for owner review. Date: 2026-11-08.

This document says what the first build proves, and nothing more. The full design is in
`docs/design/target-architecture.md`. Where this document names a mechanism, the target
architecture describes it, and this document gives the simpler PoC form. Source markers follow
the target architecture: **[owner]**, **[call]** and **[canon]**.

## What the PoC proves **[owner]**

On one Mac, with no credential copied between clusters:

1. The portal requests two new cells, and the environment control plane creates them.
2. Each cell's `celld` registers and authenticates with its environment control plane.
3. Both cells appear in the management plane as valid, from proof that only the cells can produce.
4. A third, malicious cell is rejected, and so is a man in the middle.

It also shows three properties that the owner set:

- Island mode: an environment cut off from the management plane, and a cell cut off from its environment control plane, keep working on their last known state.
- A read-only central Argo CD view in the management plane, which cannot change a cell.
- Central observability in the `management` cluster: logs, metrics and traces from every cluster in one Grafana, and one Kiali view of each cell's mesh. Signals cross clusters only as OTLP, over SPIFFE mTLS.

## What is in scope

| Area | PoC form | Target architecture section |
| --- | --- | --- |
| Clusters | `management`, `dev-cp`, `dev-cell-1`, `dev-cell-2` and `rogue`, as kind clusters in one Colima VM | Topology |
| Provisioning | The cell controller in `dev-cp` sends a step that the management plane signs to a host service on the Mac. The host service creates the cluster and applies the pinned bootstrap set | Cell controller |
| Cluster keys | The host service serves each cluster's JWKS over TLS with a certificate that the management plane pins. The management plane binds the issuer with a nonce token at first start | Independent key check |
| Identity | SPIRE server in `dev-cp`. The External Secrets Operator copies its intermediate CA from the secret manager. A root that no cluster can read signs the intermediate | SPIRE CAs |
| Management plane identities | A second SPIRE server in `management` issues `mgmt.poc.internal` identities to local workloads, through the `k8s_psat` attestor. The management plane and `dev` pin each other's root CA | Identities |
| Attestation | `cluster_jwt` with pod-bound tokens of 15 minutes or less. Agents do not re-attest: each attestation gets a fresh agent ID, and running agents renew without a new token | Attestation |
| Specs | The management plane stand-in signs specs and cell records with one key. envd pulls them, and refuses unsigned or older ones | Signed specs and records |
| Work | `celld` holds one stream to the cell gateway, claims operations that the management plane signs, and applies each one at most once by operation ID | Signed work and idempotency |
| Proof to the management plane | `celld` sends status and results with a projected token for the audience `mgmt`. The management plane checks it against the record's keys, so `dev-cp` cannot pose as a cell | Second proof for traffic to Kiln |
| The management plane's root in cells | Pinned in the bootstrap set, and read from a static file, never from the Workload API | Network flows |
| Bundles | `celld` publishes bundles that the management plane signs to the bundle store, and Argo CD in the cell applies them. A rollback points the root back at the last good root that the management plane signed | Bundles, Argo CD and safe updates |
| Central view | Argo CD Agent in autonomous mode, with the principal in `management`. Agents connect through `cell-proxy` and a TLS passthrough relay in `dev-cp`. An admission policy in the cell blocks every write, every annotation except refresh, `.operation`, and exec | Central Argo CD view |
| Observability | The `otel-lgtm` image in `management` runs Grafana, Loki, Tempo and Prometheus. Each cluster's collector scrapes local Prometheus endpoints and receives OTLP. It exports OTLP through `cell-proxy` and the telemetry relay to a gateway in `management` | Telemetry |
| Mesh view | Kiali in `management` reads mesh metrics from the stack. It reads each cell's mesh state through a tunnel that the cell's `cell-proxy` opens up to `management` | Mesh view |
| Island mode | Both levels, with no trust change during an island | Island mode |
| Revocation | The management plane revokes in a spec. During an island, an operator revokes locally, and the overlay holds until a spec from the management plane includes it | Revocation |

## What is not in scope

These stay in the target architecture, and come in later increments:

| Deferred | Why it can wait |
| --- | --- |
| Approver signatures checked in cells | Needs approver tooling. The PoC's claims do not depend on it |
| Customer-data operations, encrypted exports, exploration sessions | A separate capability on top of signed work |
| Key sets, the recovery key and its ceremonies, root rotation | The PoC uses a fixed root and fixed record keys. `pki:rotate-intermediate` replaces only the intermediate CA |
| Restore with epochs, rebuild from empty, provider inventory and the sweeper | Disaster recovery work, once the core holds |
| Relay hardening: outer mTLS, per-cell caps, revocation at the relay | The PoC relay only passes TLS through. The management plane enforces identity |
| Watchdog and blue/green updates of `celld` and Argo CD | In the PoC, the harness updates `celld`, and a bundle updates Argo CD. The residual limits say what a bundle can still change |
| HPA fan-out, cross-environment requests, alert evaluators, the personal-data canary test | Scale and operations work |
| EKS, ACK, the tailnet and AWS-specific network rules | The second environment target |
| Integration tests in GitHub CI | Hosted runners for private repositories have 2 CPUs and 8 GB. CI runs unit and component tests only |

## Simplifications **[call]**

- One signing key for the management plane, one environment, one SPIRE server, and no HA.
- The queue in `dev-cp` and the SPIRE datastore use SQLite on persistent volumes.
- Every cluster uses the local-path provisioner that kind ships, after the vendor review. The bundle store moves to a persistent volume.
- `celld` and its Deployment are outside every Argo CD Application, and the harness applies them. The target also keeps Argo CD outside every Application, with an admission policy that keeps bundles away from both. The residual list says what is not in place yet.
- The relay is a TLS passthrough that routes by port. The management plane has one listener for `dev`.
- Each cluster gets its own pod and service subnets. Pod networks are not routed between clusters, so cross-cluster traffic uses node addresses on the `kind` network.
- Observability uses the `otel-lgtm` all-in-one image, with local storage and no HA.
- Until M4, the test-signed record from M2 is the management plane's registry of cells.
- Upstream components keep their Prometheus endpoints. Only the collector in the same cluster scrapes them, and signals leave a cluster only as OTLP.
- The External Secrets Operator is the provider-neutral sync from the secret manager into each cluster. A cluster gets its own install when it first needs a secret. In M2, only `dev-cp` has one.

## Bespoke components

| Component | Purpose |
| --- | --- |
| Host service | Stands in for the provider: creates clusters, applies bootstrap sets, serves JWKS over pinned TLS, checks steps that the management plane signs |
| Management plane stand-in | Holds intent from the portal, signs specs and operations, checks cell keys and proofs, hosts the principal and the Argo CD UI |
| envd | Pulls signed specs, orders steps, reports status |
| Cell gateway | Queues work, takes status, enforces the replica cap |
| `cluster_jwt` | SPIRE NodeAttestor plugin pair |
| `celld` | Claims and verifies work, publishes bundles, reports status with its proof |
| `cell-proxy` | SPIFFE client and server proxy for the central view and telemetry, the read-only tunnel for Kiali, and token checks for the bundle store |
| Relay | TLS passthrough from cells to the management plane |
| Cell controller | Turns spec steps into host service calls |

Third-party components that need a review before they run: SPIRE, spire-controller-manager,
the External Secrets Operator, Argo CD Agent, the `otel-lgtm` image, Kiali, kind's local-path provisioner, the registry image, and
SQLite drivers.

## Milestones

Each milestone ends with an automated test, and each test runs only once the thing that stops
it exists.

| # | Milestone | Done when |
| --- | --- | --- |
| M0 | Base cell | Done |
| M1 | Harness | The host service creates all five clusters twice from clean, with storage and one registry mirror. A pod in `rogue` reaches no port on a cell's node except the residual ports 2379, 2380, 6443, 10250 and 10256 |
| M2 | Attestor | Against a test-signed record, `celld` gets an SVID. Pod-bound, lifetime, audience, subject and unknown key ID tests fail as expected. A sidecar renews without a new token |
| M3 | Central view and observability | `management` shows both cells in one Argo CD UI, with live manifests. Writes, annotation changes, `.operation`, exec and Secret reads through the view fail. A cell's SVID cannot pose as the management plane's principal. Grafana shows logs, metrics and traces from all five clusters, each tagged with its cluster, plane, environment and cell. A cell that labels its signals as another cell's is corrected at the gateway, and telemetry from `rogue` fails. Kiali shows the mesh of each cell, and cannot change it |
| M4 | Management plane stand-in and specs | envd pulls signed specs, and refuses unsigned or older ones. The management plane binds issuers and checks keys. The test-signed record fixture is deleted |
| M5 | Signed work | `celld` claims, verifies and applies operations once. Forged, replayed, expired and wrong-target items fail. `dev-cp` cannot pose as a cell to the management plane |
| M6 | Provisioning end to end | Checks 1–3 pass from one portal request. A step with no management plane signature fails |
| M7 | Malicious cell and MITM | Check 4 passes. A rogue cluster, a rogue JWKS, TLS interception at each hop, and a relay that alters bytes all fail |
| M8 | Bundles | Bundles that the management plane signs reach Argo CD in each cell. A bundle outside its allow-list fails, and a rollback restores the last good root |
| M9 | Island mode and revocation | Both island levels hold for three SVID lifetimes, with no pod restarts. Revocation works connected and locally |

The full gate runs on the Mac, with a fast tier for M1–M8 and a slow tier for M9. Each tier has a
time budget, set at M1. The Mac must stay awake for the whole gate, so a keep-awake tool must run.
macOS still sleeps when the lid closes on battery power.

## Residual limits of the PoC

- Locally, every cluster shares the `kind` network, so clusters can reach each other's Kubernetes API, kubelet, etcd and kube-proxy health ports. The residual ports are 2379, 2380, 6443, 10250 and 10256. On 2026-11-08 a scan of ports 1 to 65535 from `rogue` found exactly these ports open on each node of `management`, `dev-cp`, `dev-cell-1` and `dev-cell-2`. The M1 test fails if any other port opens. It also fails if port 6443 or 10250 is closed, because then the scan did not work. The scan covers TCP over IPv4 only. The `kind` network is dual-stack with the IPv6 prefix `fc00:f853:ccd:e793::/64`, and no test scans the IPv6 node addresses. A NodePort Service with no ready endpoint does not show as open.
- Every cluster shares the registry `registry-mirror`, which accepts a push or a delete without authentication. The namespaces that the bundles own deny that egress. Pods in a namespace without NetworkPolicy still reach the registry: `kube-system`, `default` and `local-path-storage` in each cluster, and every namespace of `rogue`. Host network pods and new pods in the kindnet window below reach it too. Each render pins a local image by the digest that `mise run images` recorded on this Mac, and it computes a plugin checksum from the image at that digest. So a pushed tag cannot change a render. Those pods can still push new tags and delete images. A deleted image stops the next render or pod start. Before M7 runs attack tools, registry deletes must be turned off.
- The same pods reach every listener on the loopback interface of the Mac through `host.docker.internal`, not only the host service. The owned namespaces deny that egress.
- A compromised management plane can sign any work. Approver checks in cells come later.
- Keys stay fixed for the life of a run, apart from the intermediate CA. `mise run pki:rotate-intermediate` replaces the intermediate, and `cell:verify` in `dev-cp` fails 7 days before it expires. No task rotates the root or the record keys. The M2 key rotation test changes the signing key of `dev-cell-1` for two to three minutes, and then restores it.
- `dev-cp` gives agent and workload SVIDs a lifetime of 1 minute (`SPIRE_SVID_TTL` in `cells/dev-cp.env`). After a pause longer than the remaining lifetime, for example while the Mac sleeps, an agent cannot renew. The rotator then ends the agent (`pkg/agent/svid/rotator.go:102-105` in v1.15.5), and the restarted container attests as a new agent. The server keeps the old agent entries until it prunes them. The exit follows from the agent source, and no test verifies it.
- Any identity that can create a pod in `cell-identity-system` can run it as the `celld` service account, and so attest as that cell. The rejection tests rely on this. In each cell, the Argo CD application controller can also create a token for any service account there. `istiod` cannot create a token there, but it can create Deployments and ServiceAccounts in every namespace (ClusterRole `istiod-gateway-controller-istio-system`). Because of this, `istiod` can also run a pod as `celld`. On 2026-11-09, `kubectl auth can-i` confirmed each of these rights in `dev-cell-1`. Admission control that limits pod creation and token requests there comes later.
- In `spire-system` of `dev-cp`, several service accounts can read Secret `spire-upstream` with the intermediate CA key, and the copy of the access token. They are the Argo CD application controller, `istiod`, `istio-system/istio-reader-service-account` and the External Secrets Operator. The garbage collector and the namespace controller in `kube-system`, and cluster administrators, can read them too. `istio-reader-service-account` can read Secrets in every namespace.
- The intermediate CA key and the access token rest unencrypted in the etcd of `dev-cp`, on the disk of the VM. The kind clusters do not encrypt Secrets at rest. No script writes a key to a file, but etcd stores each Secret.
- Until signed bundles in M8, a bundle in the store of `dev-cp` is the root of every identity in `dev.env.poc.internal`. The `spire-server` bundle holds the server config, the records and the record public keys together, and nothing signs it. A writer to that bundle can add a record or a key, or change an entry, and so issue any identity in the trust domain. The bundle store admits the `argocd` namespace on port 5000. The AppProject allows every namespace and kind, so a bundle that names an object in another namespace can change it.
- The SPIRE server NetworkPolicy admits by the node address of each agent cell, so admission is per node, not per workload. Each pod that the policies of its own namespace let out reaches the SPIRE port, and the token checks of the plugin decide which pod attests.
- kindnet accepts each packet of a root process in the host network (`meta skuid 0`) before it checks a NetworkPolicy. Because of this, NetworkPolicy does not constrain root processes on a node, or root host network pods. On the `dev-cp` node, every root process reaches the SPIRE server port 8081 with no check. Examples are host network pods in `kube-system`, and the `pods/proxy` and `services/proxy` paths of the API server.
- One shared vault and one access token serve every PoC cluster. Because of this, a compromised cluster can read every PoC secret, including the SPIRE intermediate key. Production uses a vault and a token for each cluster.
- The External Secrets Operator in `dev-cp` reads and writes only the Secrets of `spire-system`. Its NetworkPolicy still admits DNS and every public address on TCP port 443, so the operator can reach any public host on that port.
- The relay cannot close a revoked cell's streams. The management plane closes them.
- The relay limits open connections to 256 in all and 16 for each client address. A cell node address stands for every pod of that cell, so one pod can use the 16 slots of its cell. The management view listener keeps 64 handshake slots for all cells, and a client that sends one byte takes one for 10 seconds. Two cells with 16 connections each cannot fill them, but the relay has no limit for each cell beyond the address.
- Every pod of a cell that no NetworkPolicy limits reaches the relay node ports through the node address of its cell. In `dev-cp`, such a pod reaches `management` on 31443 directly. An address spoofed on the `kind` bridge reaches the same ports. Identity at cell-proxy is the control, as for the SPIRE node port.
- The identities `argocd/argocd-agent` and `observability-system/otel-uplink` follow the same rule as `celld`: any identity that can create a pod in the namespace can run it as that service account. The agent pod can request a token for its own service account, so it can attest as a node. The agent exposes `/debug/pprof` on its health port, and the pod admits no ingress to it. ConfigMap `mgmt-root` can be overwritten by a bundle that writes to `argocd`, and the new root applies at the next pod start.
- The agent can list and watch every Secret of `argocd`, because it does not start without that access. The admission policy limits the Secret names and not their contents.
- A revoked record stops new attestations only. The plugin reads the records when the server starts, and the running agents of a revoked cell renew until an operator evicts them. M9 needs a ban of those agents.
- The SPIRE node port has no limiter before authentication, which the target architecture requires for each plane listener. SPIRE also limits no attestation per address (`ratelimit { attestation = false }` in `server.conf`). The plugin limits each cell only after a token validates, and it limits no failed attestation. A payload with an unknown cell name ends before the in-flight cap. Because of this, failed attestations have no rate limit.
- Each cell has at most 8 attestation streams in flight (`per_cell_inflight`). Each stream waits up to `challenge_timeout`, 10 seconds, for the reply to its challenge. A client that opens a new stream each time an old one ends keeps all 8 slots full. This blocks every new attestation of that cell for as long as the client continues. The client needs no credential. The SPIRE port admits the node address of each agent cell, and not only the cell that an attestation names. So any pod in a namespace without policies in any agent cell can hold these slots for any cell. Examples are `kube-system`, `default` and `local-path-storage`, and any host network pod. Running agents renew over their existing identity, so only new pods of the cell wait.
- A privileged host network pod in `rogue` can claim the address of a cell node with gratuitous ARP on the shared `kind` bridge. It can then reach the SPIRE node port from an admitted address. This gives reach and denial of service only, because an attestation still needs a pod-bound token of the cell. M7 tests it.
- kindnet sends pod packets to its NetworkPolicy process through an nfqueue rule with the `bypass` flag. Without a process on the queue, the kernel accepts the packets. So NetworkPolicy fails open by construction while the kindnet pod of a node restarts. The cleanup of the M2 key rotation test and `gate:m2:repair` restart the kindnet pod of `dev-cell-1` when its projected token comes from the test key.
- kindnet applies NetworkPolicy to a pod only after it adds the pod address to its nftables sets. Until then no queue rule matches the pod, so both egress and ingress of the pod are open. On 2026-11-09 the egress window took about 2 seconds after the pod became Ready. In that window, the pod reached the internet and the `dev-cp` node port with no policy. Short-lived probe pods in `argocd`, `cell-system`, `observability-system` and `cell-identity-system` all reached the internet in this window. The window repeats for every new pod, so anyone who can create pods can use it again. The PoC accepts this property of the kind CNI, and a production CNI differs. Each `cell:verify` probe records the time to its first blocked dial in `build/<cluster>/verify-probes.log`, and it fails above 10 seconds. M7 plans an attack test for the window.
- No CRD carries an Argo CD tracking ID, so Argo CD never prunes a CRD that leaves a bundle. On 2026-11-09 the CRDs of the External Secrets Operator in `dev-cp` had no tracking annotation. A CRD that a bundle drops stays in the cluster, with its objects, until a person deletes it. `eso:migrate` deletes the ClusterSecretStore CRD for this reason.
- The harness apply does not prune. An object that leaves a harness bundle stays in the cluster until a person deletes it. `cell:verify` reports an extra object of a kind that the bundle holds, but not an extra object of another kind.
- Argo CD still comes from a bundle in its own Application. No admission policy stops a bundle from writing to `argocd` or `cell-identity-system` yet, because the project allows every namespace and kind. A bundle that names an object there can change it.
