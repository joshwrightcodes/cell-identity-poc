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
| Key sets, the recovery key and its ceremonies, root rotation | The PoC uses a fixed root. `pki:rotate-intermediate` replaces the intermediate CA, and `mgmt -- rotate-signing-key` replaces the signing key of `mgmtd` |
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
- The management plane stand-in keeps its key and its state in files on its own persistent volume.
- Upstream components keep their Prometheus endpoints. Only the collector in the same cluster scrapes them, and signals leave a cluster only as OTLP.
- The External Secrets Operator is the provider-neutral sync from the secret manager into each cluster. A cluster gets its own install when it first needs a secret. In M2, only `dev-cp` has one. In M3, `management` has an operator with no store, for its Password generator.

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
| M3 | Central view and observability | `management` shows both cells in one Argo CD UI, with live manifests. Writes, annotation changes, `.operation`, exec and Secret reads through the view fail. A cell's SVID cannot pose as the management plane's principal. Grafana shows logs, metrics and traces from every registered cluster, each tagged with its cluster, plane, environment and cell. A cell that labels its signals as another cell's is corrected at the gateway, and telemetry from `rogue` fails. Kiali shows the mesh of each cell, and cannot change it |
| M4 | Management plane stand-in and specs | envd pulls signed specs, and refuses unsigned or older ones. The management plane binds issuers and checks keys. The test-signed record fixture is deleted |
| M5 | Signed work | `celld` claims, verifies and applies operations once. Forged, replayed, expired and wrong-target items fail. `dev-cp` cannot pose as a cell to the management plane on the view, telemetry and mesh view streams |
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
- A run keeps its roots. Three tasks replace a key: `mise run pki:rotate-intermediate` replaces the intermediate, and `cell:verify` in `dev-cp` fails 7 days before it expires. `mise run mgmt:rotate-ca` replaces the management root, and `mise run view:rotate-keys` replaces the view keys. `mise run mgmt -- rotate-signing-key` replaces the signing key of `mgmtd` as a break-glass action. No task rotates the root of `dev-cp`. The M2 key rotation test changes the signing key of `dev-cell-1` for two to three minutes, and then restores it.
- `dev-cp` gives agent and workload SVIDs a lifetime of 1 minute (`SPIRE_SVID_TTL` in `cells/dev-cp.env`). After a pause longer than the remaining lifetime, for example while the Mac sleeps, an agent cannot renew. The rotator then ends the agent (`pkg/agent/svid/rotator.go:102-105` in v1.15.5), and the restarted container attests as a new agent. The server keeps the old agent entries until it prunes them. The exit follows from the agent source, and no test verifies it.
- Any identity that can create a pod in `cell-identity-system` can run it as the `celld` service account, and so attest as that cell. The rejection tests rely on this. In each cell, the Argo CD application controller can also create a token for any service account there. `istiod` cannot create a token there, but it can create Deployments and ServiceAccounts in every namespace (ClusterRole `istiod-gateway-controller-istio-system`). Because of this, `istiod` can also run a pod as `celld`. On 2026-11-09, `kubectl auth can-i` confirmed each of these rights in `dev-cell-1`. Admission control that limits pod creation and token requests there comes later.
- In `spire-system` of `dev-cp`, several service accounts can read Secret `spire-upstream` with the intermediate CA key, and the copy of the access token. They are the Argo CD application controller, `istiod`, `istio-system/istio-reader-service-account` and the External Secrets Operator. The garbage collector and the namespace controller in `kube-system`, and cluster administrators, can read them too. `istio-reader-service-account` can read Secrets in every namespace.
- The intermediate CA key and the access token rest unencrypted in the etcd of `dev-cp`, on the disk of the VM. The kind clusters do not encrypt Secrets at rest. No script writes a key to a file, but etcd stores each Secret.
- Until signed bundles in M8, a bundle in the store of `dev-cp` is the root of every identity in `dev.env.poc.internal`. The `spire-server` bundle holds the server config and the pinned management key, and nothing signs it. A writer to that bundle can replace the key, and so issue any identity in the trust domain. The spec and the records carry the management signature, and they are not in that bundle. The bundle store admits only the repo server of `argocd` on port 5000. The AppProject allows every namespace and kind, so a bundle that names an object in another namespace can change it.
- The SPIRE server NetworkPolicy admits by the node address of each agent cell, so admission is per node, not per workload. Each pod that the policies of its own namespace let out reaches the SPIRE port, and the token checks of the plugin decide which pod attests.
- kindnet accepts each packet of a root process in the host network (`meta skuid 0`) before it checks a NetworkPolicy. Because of this, NetworkPolicy does not constrain root processes on a node, or root host network pods. On the `dev-cp` node, every root process reaches the SPIRE server port 8081 with no check. Examples are host network pods in `kube-system`, and the `pods/proxy` and `services/proxy` paths of the API server.
- One shared vault and one access token serve `dev-cp`. `management` holds no token. Because of this, a compromised `dev-cp` can read every PoC secret, including the SPIRE intermediate key. Production gives each cluster its own token and vault.
- The External Secrets Operator in `dev-cp` reads and writes only the Secrets of `spire-system`. Its NetworkPolicy still admits DNS and every public address on TCP port 443, so the operator can reach any public host on that port.
- The External Secrets Operator in `management` reads and writes every Secret in `observability-system`, Secret `grafana-admin` included. Its NetworkPolicy admits only DNS and the API server.
- The relay cannot close a revoked cell's streams. The management plane closes them.
- The relay limits open connections to 256 in all and 16 for each client address. A cell node address stands for every pod of that cell, so one pod can use the 16 slots of its cell. One limiter serves every route of a relay, so silent connections on one route use slots of the other routes too. The management view listener keeps 64 handshake slots for all cells, and a client that sends one byte takes one for 10 seconds. Two cells with 16 connections each cannot fill them, but the relay has no limit for each cell beyond the address.
- Every pod of a cell that no NetworkPolicy limits reaches the relay node ports through the node address of its cell. In `dev-cp`, such a pod reaches `management` on 31443 directly. An address spoofed on the `kind` bridge reaches the same ports. Identity at cell-proxy is the control, as for the SPIRE node port.
- The identities `argocd/argocd-agent`, `observability-system/otel-uplink` and `mesh-view-system/mesh-view` follow the same rule as `celld`: any identity that can create a pod in the namespace can run it as that service account. The agent pod can request a token for its own service account, so it can attest as a node. The agent exposes `/debug/pprof` on its health port, and the pod admits no ingress to it. ConfigMap `mgmt-root` can be overwritten by a bundle that writes to `argocd`, and the new root applies at the next pod start.
- The agent can list and watch every Secret of `argocd`, because it does not start without that access. The admission policy limits the Secret names and not their contents.
- A revoked record stops new attestations only. The plugin reloads the records every 10 seconds, and the running agents of a revoked cell renew until an operator evicts them. M9 needs a ban of those agents.
- The SPIRE node port has no limiter before authentication, which the target architecture requires for each plane listener. SPIRE also limits no attestation per address (`ratelimit { attestation = false }` in `server.conf`). The plugin limits each cell only after a token validates, and it limits no failed attestation. A payload with an unknown cell name ends before the in-flight cap. Because of this, failed attestations have no rate limit.
- Each cell has at most 8 attestation streams in flight (`per_cell_inflight`). Each stream waits up to `challenge_timeout`, 10 seconds, for the reply to its challenge. A client that opens a new stream each time an old one ends keeps all 8 slots full. This blocks every new attestation of that cell for as long as the client continues. The client needs no credential. The SPIRE port admits the node address of each agent cell, and not only the cell that an attestation names. So any pod in a namespace without policies in any agent cell can hold these slots for any cell. Examples are `kube-system`, `default` and `local-path-storage`, and any host network pod. Running agents renew over their existing identity, so only new pods of the cell wait.
- A privileged host network pod in `rogue` can claim the address of a cell node with gratuitous ARP on the shared `kind` bridge. It can then reach the SPIRE node port from an admitted address. This gives reach and denial of service only, because an attestation still needs a pod-bound token of the cell. M7 tests it.
- kindnet sends pod packets to its NetworkPolicy process through an nfqueue rule with the `bypass` flag. Without a process on the queue, the kernel accepts the packets. So NetworkPolicy fails open by construction while the kindnet pod of a node restarts. The cleanup of the M2 key rotation test and `gate:m2:repair` restart the kindnet pod of `dev-cell-1` when its projected token comes from the test key.
- kindnet applies NetworkPolicy to a pod only after it adds the pod address to its nftables sets. Until then no queue rule matches the pod, so both egress and ingress of the pod are open. On 2026-11-09 the egress window took about 2 seconds after the pod became Ready. In that window, the pod reached the internet and the `dev-cp` node port with no policy. Short-lived probe pods in `argocd`, `cell-system`, `observability-system` and `cell-identity-system` all reached the internet in this window. The window repeats for every new pod, so anyone who can create pods can use it again. The PoC accepts this property of the kind CNI, and a production CNI differs. Each `cell:verify` probe records the time to its first blocked dial in `build/<cluster>/verify-probes.log`, and it fails above 10 seconds. M7 plans an attack test for the window.
- No CRD carries an Argo CD tracking ID, so Argo CD never prunes a CRD that leaves a bundle. On 2026-11-09 the CRDs of the External Secrets Operator in `dev-cp` had no tracking annotation. A CRD that a bundle drops stays in the cluster, with its objects, until a person deletes it. `eso:migrate` deletes the ClusterSecretStore CRD for this reason.
- The harness apply does not prune. An object that leaves a harness bundle stays in the cluster until a person deletes it. `cell:verify` reports an extra object of a kind that the bundle holds, but not an extra object of another kind.
- Argo CD still comes from a bundle in its own Application. No admission policy stops a bundle from writing to `argocd` or `cell-identity-system` yet, because the project allows every namespace and kind. A bundle that names an object there can change it.
- The principal resource proxy, Redis proxy, metrics and health ports bind every interface, so NetworkPolicy is their only limit.
- The collectors read no container log files, so upstream stdout logs stay in each cluster.
- Until M5, a compromised `dev-cp` can mint a cell SVID. With it, the attacker can send telemetry as that cell. The attacker can also open a view stream that displaces the principal session of the cell. The attacker can take over the mesh tunnel of the cell too, because the newest connection wins. Then the attacker serves fabricated Kiali responses and a fabricated central view of that cell.
- The CA of the management plane has no offline root key in the PoC. Production roots it offline.
- The CA key of the SPIRE server in `management` rests unencrypted on the data volume, on the disk of the VM. The volume directory has mode 0777, so a pod that mounts the host path can read it.
- In `management`, the local-path provisioner service account can create host path pods. The Argo CD application controller can use `pods/exec` in `spire-system`. Either right gives access to the CA key, and so to every `mgmt.poc.internal` identity.
- A management CA rotation needs every view cell to be up, because its refresh runs the link phase of each cell. A new data volume in `management` gives a new root, and each peer copy fails until `cell:up` runs again.
- In a namespace that a harness or link component shares with a bundle, `cell:verify` compares only the labelled objects with the harness bundle.
- The SPIRE server role of `management` and `dev-cp` can read any pod and node of its cluster. The Prometheus port 9988 of both servers binds every address.
- The SPIRE listeners are dual-stack. Any process in the host network namespace reaches ports 8081 and 9988 over the pod IPv6 link-local address. A root process is not required, because the kindnet IPv6 pod set is empty.
- A cell can make the `dev-cp` SPIRE server send TokenReview calls to its API through `k8s_psat`, with no rate limit. The port 30081 of `dev-cp` admits every cell node address.
- A pod that can create pods with a plane service account gets the SVID of that plane identity. `cell:verify` detects such a pod and does not prevent it.
- The principal Redis proxy serves cell cache reads to `argocd-server` with no authentication.
- `argocd-server` can read every Secret in `central-view-system`, including the Agent JWT signing key, the Redis password and the client keys. The principal and `argocd-server` read the Applications of every namespace.
- Any holder of `pods/proxy` in `central-view-system`, and any root host process, can reach the pprof endpoint on the principal port 8003.
- Some upstream images from before M3 run by tag, not by digest, and some of their containers have no CPU or memory bounds. `TestRenderedPodsPinnedAndBounded` lists them, and every new container is pinned and bounded.
- `pods/portforward`, `pods/exec` or `pods/ephemeralcontainers` on the principal pod reach `127.0.0.1:8443`. They can set `x-cell-agent` for any agent and so bypass `cell-proxy`.
- The principal and agent images are Alpine with a shell and busybox, not distroless. The principal binary links Argo CD v3.5.1 and the server runs v3.6.1. The review did not read 172 modules of the principal.
- The agent Role can update and patch Applications in `argocd-apps`. The view can read ConfigMaps in `argocd`, `istio-system` and `observability-system`, and CRDs, ClusterRoles and webhook configurations in every namespace.
- A bundle writer can change the copy of AppProject `cell` in `argocd-apps`, and the principal mirrors the change. `check_cell_subject_pods` does not see a bare Pod in an owned namespace.
- The canary Secret `view-canary` in the published `apps-demo` bundle holds a literal test marker. Any bundle reader can see it.
- A central view read can fail with an empty HTTP 500 for up to 3 minutes (upstream Argo CD Agent issue 1107). This happens when a cache key expires in the Redis of a cell. The tests retry it. The UI shows an error until the controller writes the key again.
- While `view:ui`, `mesh:ui` or `obs:ui` runs, every pod can read that UI through the Mac loopback. This includes pods in `rogue`. The central UI and Kiali are anonymous.
- A rule that admits the `dev-cp` node address admits every pod in `dev-cp`, because pod egress leaves through the node address.
- The namespace-wide DNS rule lets any pod send data out in DNS queries.
- Node addresses reach the collector port 4317 and the uplink port 4319 for the kubelet probes. They also reach the Argo CD, `istiod` and Envoy metrics ports.
- `otel-uplink` accepts plaintext OTLP on the pod network, and NetworkPolicy limits it to the collector pod. The collector pod sends its own telemetry on loopback, which no NetworkPolicy covers. `lgtm` accepts plaintext OTLP on port 4317 from two pod selectors.
- A connection to `cell-proxy` or the uplink outlives the SVID that authorised it.
- The gateway has no rate or cardinality limit for each sender.
- Signals can carry personal data, and no processor filters it.
- The gateway counts a dropped hostile resource as at least one rejected record, not as an exact number. A record larger than the batch bound of 101,000 to 129,000 bytes is dropped by the exporter batcher.
- The readiness probe of the gateway covers the first connection to the store only. A later store outage leaves the pod Ready, and senders get `Unavailable`.
- The gateway exports its own metrics straight to `lgtm`, and the OTel SDK retries them in memory only.
- The collector of `management` has no gateway, so its scraped Envoy `source_cluster` and `destination_cluster` labels get no second check.
- The filter for the gateway alarm series matches the metric name and the name with its unit. A name and unit pair that Prometheus rewrites, for example the unit `s`, can still forge the series.
- Every pod with `get` on Secrets in `observability-system` can read the Grafana admin password. If someone deletes `grafana-admin` and keeps the Grafana database, `obs:password` is wrong until `obs:rotate-password restore` runs.
- Grafana blocks the user `admin` for 5 minutes after 5 failed logins, and the block also refuses the right password. Several negative login checks in a row trigger it.
- `lgtm` runs six processes in one pod without a mesh proxy. Its 10Gi `local-path` volume has no backup, and the data is lost with the volume. Nobody inspected the collector image layers.
- Code that runs inside the tunnel pod can use the SVID of that pod. The API server proxy of `management` reaches the hub listeners from a node address, because the listeners use plain HTTP.
- The tunnel role reads every namespace of a cell, not only `MESH_VIEW_NAMESPACES`.
- A hostile cell can crash-loop the shared Kiali. One absent cell stops Kiali from starting, and it recovers about 5 minutes after the cell returns.
- `prom-readonly` does not enforce `query_scope`, and the path is read-only. The Kiali signing key is predictable and unused under the `anonymous` strategy.
- The tunnel state comes from the hub log, and the tunnel probe runs `whoami`. A pod that started in the same second as a newer view key, and did not read it, counts as current.
- `harness:status` reads the current principal log, so a log rotation can hide connected agents.
- The signing key of `mgmtd` rests in the file `ed25519.key` on the volume of `mgmtd-0`, with mode 0400. The disk of the VM does not encrypt it. No Secret holds it, and only `mgmtd-0` mounts the volume.
- A subject with a pod right in `mgmt-system` can reach the key. `TestM4SigningKeyReaders` logged these subjects on 2026-11-13. `argocd-application-controller` can create pods, use exec and add ephemeral containers. The `kube-system` controllers `daemon-set-controller`, `job-controller`, `persistent-volume-binder`, `replicaset-controller`, `replication-controller` and `statefulset-controller` can create pods. `generic-garbage-collector` can add ephemeral containers.
- Node access reaches the key file too. So does each subject that can create a hostPath pod, such as the local-path provisioner. Pod Security stops such a pod only in a namespace that enforces restricted or baseline.
- A separate list holds the subjects that can change ConfigMap `mgmt-signing-pub`, from the same test and day: `argocd-application-controller`, `generic-garbage-collector`, `istiod`, `root-ca-cert-publisher` and `storage-version-migrator-controller`. A change to that ConfigMap shows in `cell:verify` only while `mgmtd-0` is Ready. When `mgmtd-0` is not Ready, a `dev-cp` render refuses a key that differs from the pinned key. A `dev-cp` with no pin, for example a rebuilt one, accepts the key without a check. `MGMT_KEY_ACCEPT_CHANGE=1` allows a deliberate change.
- The same writers can change ConfigMaps `peer-root`, `mgmt-intent` and `hostsvc-pin` in `mgmt-system`. `mgmtd` reads `peer-root` at each handshake. A writer that adds a root of its own for `dev.env.poc.internal` can mint an `envd` identity and report any applied revision. That releases each drop that waits at once, and `envd` then refuses later specs with `too_many_invalidated`. A change to `mgmt-intent` takes effect at the next `mgmtd` start, and it can drop cells. `cell:verify` compares `peer-root` with the live root.
- A writer to ConfigMaps in `envd-system` can replace `mgmt-spec-key` or `peer-root`. After a restart, `envd` refuses every spec or cannot dial, so deliveries stop and revocations stop with them. The plugin keeps its last records. `cell:verify` and `harness:status` show the refusal.
- A key rotation leaves the `dev-cp` plugin with no records after the restart of its server. This lasts until `envd` writes the first spec under the new key. New pods cannot attest in that window, and agents that already run still renew. The measured windows were 71 and 91 seconds, and `mise run mgmt -- rotate-signing-key` took about 5 minutes.
- From the `dev-cp` render until each cell binds, `dev-cp` has no records, so no new agent attests. After a bind, `envd` writes the records, and the server reloads them. The measured span from the `envd` write to the log line `records reloaded` was 50 and 60 seconds. It covers the kubelet sync of the ConfigMap volume and the reload that runs every 10 seconds. Agents that already run still renew.
- The registry of each central view follows the records of `mgmtd` only at a link of `management`. Between a record change and the next link, `cell:verify` and `harness:status` fail and print `CELL=management LINK_ONLY=<component> mise run cell:link`. The `cell-proxy` of the view loads the registry once at start. It uses only the name, the environment and the revoked flag of each record. So a stale key list has no effect. A revocation or a new cell takes effect only after the next link.
- A rebuilt `management` has a new signing key and an empty state. `envd` refuses its specs until a new render pins the key, and each cell binds again. A new pinned key makes `envd` and the plugin start their marks again. A lost state does the same through `mise run mgmt -- reset-state`, which moves both files aside and starts `mgmtd` with a new key.
- The state file holds 50 whole bundles of at most 900 KiB, and a save writes a full temporary copy beside it. Both need to fit in the 64 Mi volume. With about 13 cells of large key sets, a commit can fail with no space, and `mgmtd` then signs nothing. The two cells of the PoC use a few KiB.
- The issuer binding trusts the host service, which reads cluster keys with the administrator kubeconfig of the Mac.
- Every pod that reaches the Mac loopback reaches the host service, because Lima delivers every caller as `127.0.0.1`. Only a client with the `mgmtd` SVID gets keys. A cache of 60 seconds and 2 lookups in flight bound the cost of each lookup. The TLS handshake and the client check run first, in a pool of 1024 pending connections. A silent connection leaves that pool after 1 second, and any other connection leaves it after 5 seconds. A pod can fill the pool with new connections. The service then refuses new connections at once, those of `mgmtd` included. While the pool is full, key checks and binds that need a fetch fail with `issuer_unavailable`. Binds of bound cells with known keys still work. Only verified `mgmtd` connections use the 16 slots and the age limit of 30 seconds, so such a pod cannot hold them.
- The host service makes a new TLS key at each start. Until `hostsvc:serve -- restart` links `mgmt-api` again, key checks and binds fail with `issuer_untrusted`.
- The bind listener accepts TLS with no client certificate from every pod that reaches it through `dev-cp`. `mgmtd` cannot tell sources apart. A caller can send a `traceparent` header, so the listener starts a new trace for each request and links the caller trace. The nonce route answers 200 with `bound` for a cell of the intent, and 403 for any other name. A caller can list the cells this way and see which one is unbound. Nonces hold no state. A forged token neither consumes a nonce nor starts the key update gap, so requests alone cannot lock out a cell. A connection that has not sent a full request ends after 5 seconds. A connection that has sent one ends after 25 seconds at most. A pod can hold all 64 bind slots for as long as it opens new connections. Real binds then receive a fast refusal until a slot is free. The relay admits at most 16 connections for each client address and dials only after the first byte. So the pods of one cell hold at most 16 slots through `relay-bind`, and a silent connection holds none.
- A rotated cluster key blocks new pods of that cell until the next key check, `mise run mgmt -- keycheck`, or the next `celld` start in that cell.
- A writer to ConfigMaps in `spire-system` can replace `cell-records` with an older signed spec and its records. The plugin keeps its marks in a file on the data volume of the server, so it refuses older records even after a restart. `envd` reads the stored state as its own at start, so after a restart it holds the older revision until it writes the next one. A deleted `cell-records` makes `envd` start from an empty state. The same writer can rewrite ConfigMap `spire-server`, so `record_public_keys` changes at the next server start and the writer can issue any identity. The writer can also delete `cell-records` or its `spec-envelope.json`. The plugin then drops every record until `envd` writes it again and the kubelet syncs it, about 70 seconds, and the writer can repeat this.
- `envd` can create any ConfigMap name in `spire-system`.
- The `celld` container mounts a projected API token for ServiceAccount `celld` in `cell-identity-system`. Any process in that container, and any account that can run `exec` in it, reads the token. The token lives 1 hour and is bound to the pod. It allows one action: a TokenRequest for ServiceAccount `celld` with an audience of its choice, the attestation audience included. The Role `celld-token` limits the token to that account.
- `envd` has a similar token for ServiceAccount `envd`. It allows `create` on ConfigMaps in `spire-system`, and `get` and `update` on ConfigMap `cell-records` only.
