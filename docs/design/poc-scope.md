# Cell identity PoC: build scope

Status: draft for owner review. Date: 2026-11-08.

This document says what the first build proves, and nothing more. The full design is in
`docs/design/target-architecture.md`. Where this document names a mechanism, the target
architecture describes it, and this document gives the simpler PoC form. Source markers follow
the target architecture: **[owner]**, **[call]** and **[canon]**.

## What the PoC proves **[owner]**

On one Mac, with no credential copied between clusters:

1. Kiln requests two new cells, and the environment control plane creates them.
2. Each cell's `kiln-celld` registers and authenticates with its environment control plane.
3. Both cells appear in Kiln as valid, from proof that only the cells can produce.
4. A third, malicious cell is rejected, and so is a man in the middle.

It also shows three properties that the owner set:

- Island mode: an environment cut off from Kiln, and a cell cut off from its environment control plane, keep working on their last known state.
- A read-only central Argo CD view in Kiln, which cannot change a cell.
- Central observability in the `management` cluster: logs, metrics and traces from every cluster in one Grafana, and one Kiali view of each cell's mesh. Signals cross clusters only as OTLP, over SPIFFE mTLS.

## What is in scope

| Area | PoC form | Target architecture section |
| --- | --- | --- |
| Clusters | `management`, `dev-cp`, `dev-cell-1`, `dev-cell-2` and `rogue`, as kind clusters in one Colima VM | Topology |
| Provisioning | The cell controller in `dev-cp` sends a Kiln-signed step to a host service on the Mac. The host service creates the cluster and applies the pinned bootstrap set | Cell controller |
| Cluster keys | The host service serves each cluster's JWKS over TLS with a certificate that Kiln pins. Kiln binds the issuer with a nonce token at first start | Independent key check |
| Identity | SPIRE server in `dev-cp`. Its intermediate CA comes from the secret manager CLI on standard input, signed by a root kept off every cluster | SPIRE CAs |
| Kiln identities | A second SPIRE server in `management` issues `kiln.poc.internal` identities to local workloads, through the `k8s_psat` attestor. Kiln and `dev` pin each other's root CA | Identities |
| Attestation | `cluster_jwt` with pod-bound tokens of 15 minutes or less. Agents do not re-attest: each attestation gets a fresh agent ID, and running agents renew without a new token | Attestation |
| Specs | The Kiln stand-in signs specs and cell records with one key. kiln-envd pulls them, and refuses unsigned or older ones | Signed specs and records |
| Work | `kiln-celld` holds one stream to the cell gateway, claims Kiln-signed operations, and applies each one at most once by operation ID | Signed work and idempotency |
| Proof to Kiln | `kiln-celld` sends status and results with a projected token for the audience `kiln`. Kiln checks it against the record's keys, so `dev-cp` cannot pose as a cell | Second proof for traffic to Kiln |
| Kiln's root in cells | Pinned in the bootstrap set, and read from a static file, never from the Workload API | Network flows |
| Bundles | `kiln-celld` publishes Kiln-signed bundles to the bundle store, and Argo CD in the cell applies them. A rollback points the root back at the last good root that Kiln signed | Bundles, Argo CD and safe updates |
| Central view | Argo CD Agent in autonomous mode, with the principal in `management`. Agents connect through `cell-proxy` and a TLS passthrough relay in `dev-cp`. An admission policy in the cell blocks every write, every annotation except refresh, `.operation`, and exec | Central Argo CD view |
| Observability | The `otel-lgtm` image in `management` runs Grafana, Loki, Tempo and Prometheus. Each cluster's collector scrapes local Prometheus endpoints and receives OTLP. It exports OTLP through `cell-proxy` and the telemetry relay to a gateway in `management` | Telemetry |
| Mesh view | Kiali in `management` reads mesh metrics from the stack. It reads each cell's mesh state through a tunnel that the cell's `cell-proxy` opens up to `management` | Mesh view |
| Island mode | Both levels, with no trust change during an island | Island mode |
| Revocation | Kiln revokes in a spec. During an island, an operator revokes locally, and the overlay holds until a Kiln spec includes it | Revocation |

## What is not in scope

These stay in the target architecture, and come in later increments:

| Deferred | Why it can wait |
| --- | --- |
| Approver signatures checked in cells | Needs approver tooling. The PoC's claims do not depend on it |
| Customer-data operations, encrypted exports, exploration sessions | A separate capability on top of signed work |
| Key sets, the recovery key and its ceremonies, root and intermediate rotation | The PoC uses fixed keys. A key change means re-seeding the clusters |
| Restore with epochs, rebuild from empty, provider inventory and the sweeper | Disaster recovery work, once the core holds |
| Relay hardening: outer mTLS, per-cell caps, revocation at the relay | The PoC relay only passes TLS through. Kiln enforces identity |
| Watchdog and blue/green updates of `kiln-celld` and Argo CD | In the PoC, the harness updates them. Bundles cannot change them |
| HPA fan-out, cross-environment requests, alert evaluators, the personal-data canary test | Scale and operations work |
| EKS, ACK, the tailnet and AWS-specific network rules | The second environment target |
| Integration tests in GitHub CI | Hosted runners for private repositories have 2 CPUs and 8 GB. CI runs unit and component tests only |

## Simplifications **[call]**

- One Kiln signing key, one environment, one SPIRE server, and no HA.
- The queue in `dev-cp` and the SPIRE datastore use SQLite on persistent volumes.
- Every cluster uses the local-path provisioner that kind ships, after the vendor review. The bundle store moves to a persistent volume.
- `kiln-celld`, Argo CD and their Deployments are outside every Argo CD Application. An admission policy keeps bundles away from them.
- The relay is a TLS passthrough that routes by port. Kiln has one listener for `dev`.
- Each cluster gets its own pod and service subnets. Pod networks are not routed between clusters, so cross-cluster traffic uses node addresses on the `kind` network.
- Observability uses the `otel-lgtm` all-in-one image, with local storage and no HA.
- Until M4, the test-signed record from M2 is Kiln's registry of cells.
- Upstream components keep their Prometheus endpoints. Only the collector in the same cluster scrapes them, and signals leave a cluster only as OTLP.

## Bespoke components

| Component | Purpose |
| --- | --- |
| Host service | Stands in for the provider: creates clusters, applies bootstrap sets, serves JWKS over pinned TLS, checks Kiln-signed steps |
| Kiln stand-in | Holds intent, signs specs and operations, checks cell keys and proofs, hosts the principal and the Argo CD UI |
| kiln-envd | Pulls signed specs, orders steps, reports status |
| Cell gateway | Queues work, takes status, enforces the replica cap |
| `cluster_jwt` | SPIRE NodeAttestor plugin pair |
| `kiln-celld` | Claims and verifies work, publishes bundles, reports status with its proof |
| `cell-proxy` | SPIFFE client and server proxy for the central view and telemetry, the read-only tunnel for Kiali, and token checks for the bundle store |
| Relay | TLS passthrough from cells to Kiln |
| Cell controller | Turns spec steps into host service calls |

Third-party components that need a review before they run: SPIRE, spire-controller-manager,
Argo CD Agent, the `otel-lgtm` image, Kiali, kind's local-path provisioner, the registry image, and
SQLite drivers.

## Milestones

Each milestone ends with an automated test, and each test runs only once the thing that stops
it exists.

| # | Milestone | Done when |
| --- | --- | --- |
| M0 | Base cell | Done |
| M1 | Harness | The host service creates all five clusters twice from clean, with storage and one registry mirror. A pod in `rogue` reaches no port on a cell's node except the residual ports 2379, 2380, 6443, 10250 and 10256 |
| M2 | Attestor | Against a test-signed record, `kiln-celld` gets an SVID. Pod-bound, lifetime, audience, subject and unknown-key tests fail as expected. A sidecar renews without a new token |
| M3 | Central view and observability | `management` shows both cells in one Argo CD UI, with live manifests. Writes, annotation changes, `.operation`, exec and Secret reads through the view fail. A cell's SVID cannot pose as Kiln's principal. Grafana shows logs, metrics and traces from all five clusters, and telemetry from `rogue` fails. Kiali shows the mesh of each cell, and cannot change it |
| M4 | Kiln stand-in and specs | kiln-envd pulls signed specs, and refuses unsigned or older ones. Kiln binds issuers and checks keys. The test-signed record fixture is deleted |
| M5 | Signed work | `kiln-celld` claims, verifies and applies operations once. Forged, replayed, expired and wrong-target items fail. `dev-cp` cannot pose as a cell to Kiln |
| M6 | Provisioning end to end | Checks 1–3 pass from one Kiln request. A step with no Kiln signature fails |
| M7 | Malicious cell and MITM | Check 4 passes. A rogue cluster, a rogue JWKS, TLS interception at each hop, and a relay that alters bytes all fail |
| M8 | Bundles | Kiln-signed bundles reach Argo CD in each cell. A bundle outside its allow-list fails, and a rollback restores the last good root |
| M9 | Island mode and revocation | Both island levels hold for three SVID lifetimes, with no pod restarts. Revocation works connected and locally |

The full gate runs on the Mac, under `caffeinate`, with a fast tier for M1–M8 and a slow tier
for M9. Each tier has a time budget, set at M1.

## Residual limits of the PoC

- Locally, every cluster shares the `kind` network, so clusters can reach each other's Kubernetes API, kubelet, etcd and kube-proxy health ports. The residual ports are 2379, 2380, 6443, 10250 and 10256. On 2026-11-08 a scan of ports 1 to 65535 from `rogue` found exactly these ports open on each node of `management`, `dev-cp`, `dev-cell-1` and `dev-cell-2`. The M1 test fails if any other port opens. It also fails if port 6443 or 10250 is closed, because then the scan did not work. The scan covers TCP only. A NodePort Service with no ready endpoint does not show as open.
- Every cluster shares the registry `kiln-registry`. Every pod in every cluster, including `rogue`, can push to it or delete from it without authentication. Before M7 runs attack tools, images must be referenced by digest and registry deletes must be turned off.
- Every pod, including those in `rogue`, reaches every listener on the loopback interface of the Mac through `host.docker.internal`, not only the host service.
- A compromised Kiln can sign any work. Approver checks in cells come later.
- Keys are fixed for the life of a run.
- The relay cannot close a revoked cell's streams. Kiln closes them.
