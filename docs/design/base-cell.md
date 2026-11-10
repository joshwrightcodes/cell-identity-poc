# Base cell

Status: first milestone. This document describes the cluster template that the management
plane, each cell control plane (CCP) and each worker cell start from.

## Intent

Every cluster in the PoC has the same base: a Kubernetes cluster, Argo CD, Istio, network
policy and an OpenTelemetry collector. Each role then adds its own services. A shared base
lets one set of checks prove the base once, for every role.

This milestone builds the base cell as one cell on one cluster. It adds no SPIRE, worker or other planes. It
proves that the base works before identity work starts.

## Goals

- One command creates the cell, and one command checks it.
- Argo CD manages every component after bootstrap, including Argo CD itself.
- Argo CD applies only hydrated bundles from a store inside the cluster.
- The mesh protects traffic between workloads inside the cluster.
- NetworkPolicy contains every namespace, so a workload cannot leave the cluster unless a rule allows it.
- The same layout runs on kind and on EKS.

## Non-goals

- Identity between planes. SPIRE, the worker and the gateways come in later milestones.
- A mesh across clusters. No mesh link joins two clusters, including clusters in the same cell.
- A telemetry backend. The collector prints what it receives.

## Layers

| Layer | Contents | Applied by |
| --- | --- | --- |
| 1. Cluster | Kubernetes cluster | Provider: kind on a Colima VM locally |
| 2. Bootstrap set | Namespaces, Argo CD core, bundle store | `scripts/up.sh`, once |
| 3. Platform set | Network policy, Istio, egress gateway, collector, mesh policy | Argo CD |
| 4. Role set | Services for management, CCP or worker cell | Argo CD, in later milestones |

The demo workloads in `apps-demo` take the place of the role set in this milestone.

## Namespaces

| Namespace | Contents | Mesh | Pod Security |
| --- | --- | --- | --- |
| `argocd` | Argo CD core install, and the root Application | No | restricted |
| `argocd-apps` | Every child Application, and no Secret | No | restricted |
| `cell-system` | Bundle store; later the worker and SPIRE agent sidecars | No | restricted |
| `istio-system` | istiod, istio-cni | Control plane | privileged |
| `istio-egress` | Egress gateway | Yes | restricted |
| `observability-system` | OpenTelemetry collector | No | restricted |
| `apps-demo` | Demo workloads | Yes | restricted |

Argo CD stays out of the mesh because Argo CD installs Istio. If Istio fails, Argo CD can
still repair it. `cell-system` stays out of the mesh because SPIRE identities protect it.

The collector stays out of the mesh because Envoy sends traces and access logs to it in
plaintext. Strict mTLS on the collector would reject them.

## Rules

### Argo CD

- Argo CD runs as a core install, with no UI and no API server.
- Argo CD has no remote cluster secrets. The only destination is `https://kubernetes.default.svc`.
- The only source is the in-cluster bundle store, under `oci://bundle-store.cell-system.svc.cluster.local:5000/bundles/`.
- A root Application follows the `current` tag of the root bundle.
- Bootstrap applies the root Application once. It is the only object that Argo CD does not manage, because a self-managed root waits on itself.
- Each child Application pins its bundle by digest.
- Every child Application lives in `argocd-apps` and uses the AppProject `cell`. The root Application stays in `argocd`.
- The setting `application.namespaces: argocd-apps` in `argocd-cmd-params-cm` and `sourceNamespaces` in the AppProject `cell` allow this.
- The application controller reads `application.namespaces` when it starts. Its pod template carries the annotation `poc.internal/cmd-params-sha256`, the SHA-256 of `components/argocd/argocd-cmd-params-cm.yaml`. A change to that file restarts the controller.
- The ValidatingAdmissionPolicy `argocd-apps-no-secrets` and its binding deny a Secret in `argocd-apps`, for every user.
- `mise run cell:ui` serves the UI of `argocd admin dashboard`. That local server does not read `application.namespaces`, so the UI lists only the root Application. The script prints the child Applications of `argocd-apps` first.
- Sync waves order the components. Argo CD reports the health of child Applications, so each wave waits for the one before it.
- The Istio Applications ignore the webhook fields that istiod writes at run time.

### Move of the child Applications

An older cell keeps its child Applications in `argocd`. The next `mise run cell:up` moves them.

1. The bootstrap set applies the new namespace, the project, the setting and the policy. The controller restarts.
2. The new root bundle holds each child Application in `argocd-apps`. The root Application creates them and prunes the old copies in `argocd`.
3. The wait in `cell:up` ends when `argocd` holds only the root Application and `argocd-apps` holds one Application per component.

Two states are transient. While both copies of an Application exist, Argo CD can report `SharedResourceWarning` on the objects that they both claim. The warning ends when the root Application prunes the old copy.

The tracking ID of every object changes to the form `argocd-apps_<name>:<group>/<kind>:<namespace>/<name>`. The old form was `<name>:...`. Scripts that read the tracking ID accept both forms.

The live move on the four base-cell clusters left no old Application behind. If one stays, run `mise run cell:up` again, so that the root Application prunes it. If `cell:verify` still reports it, run `kubectl -n argocd delete application <name>`. An Application has no finalizer, so the delete leaves the managed objects in place.

### Bundles

- `scripts/hydrate.sh` renders each component into plain YAML.
- `scripts/publish.sh` pushes each bundle as a single-layer OCI artifact and records its digest.
- The publish script stands in for the worker, which publishes bundles in a later milestone.
- The bundle store keeps bundles on a 1Gi volume from the default StorageClass, so a pod restart keeps them.
- The bundle store accepts plain HTTP for now. The SVID proxy replaces it when SPIRE arrives.

### Mesh

- The mesh runs in sidecar mode with istio-cni, so workload pods meet the restricted Pod Security level.
- istiod uses its own self-signed CA. The trust domain is `<cluster>.mesh.poc.internal`, for example `dev-cell-1.mesh.poc.internal`.
- The mesh trust domain is never federated, and it never chains to a shared root.
- This CA is a signing key inside the cell. The design allows it because nothing outside the cell trusts it.
- Peer authentication is strict for the whole mesh.
- Each workload namespace starts with an AuthorizationPolicy that denies every request.
- Outbound traffic is limited to registered hosts. External hosts leave through the egress gateway.

### Network policy

- Every owned namespace denies all ingress and egress by default.
- Each namespace then allows only DNS, traffic from the node addresses, and its own listed peers.
- Only the egress gateway reaches the internet, on port 443, and never a private address range.
- Only Argo CD reaches the bundle store.
- NetworkPolicy is the containment control. A pod with no mesh proxy bypasses Istio egress rules, but not NetworkPolicy.

### Telemetry

- Istio sends traces and access logs to the collector over OTLP.
- Argo CD and the bundle store send traces to the collector over OTLP.
- Istio Prometheus merging and Istio Prometheus stats are off. The collector exposes no metrics endpoint.

## Checks

`mise run cell:verify` runs one check for each rule that the running cluster can show.

| Check | Rule |
| --- | --- |
| Every Application is Synced and Healthy | Argo CD manages every component |
| No Application is outside `argocd-apps`, except the root | Child Applications stay in one namespace |
| No remote clusters, and only the local store as a source | Argo CD stays local |
| `argocd`, `cell-system` and `observability-system` have no mesh proxies | Platform stays out of the mesh |
| Demo workloads have mesh proxies, except `plaintext` | Workloads join the mesh |
| Mesh certificates use the cell trust domain | Cell CA and trust domain |
| `client` reaches `echo` | mTLS and allow rule |
| `intruder` gets HTTP 403 from `echo` | Default deny in the mesh |
| `plaintext` cannot reach `echo` | Strict mTLS |
| `client` reaches `example.com` through the egress gateway | Egress path |
| `client` cannot reach `example.org` | Registered hosts only |
| `plaintext` cannot reach the internet | NetworkPolicy containment |
| No workload reaches the bundle store | Only Argo CD reads bundles |
| A privileged pod is rejected in `apps-demo` | Pod Security level |
| The collector receives telemetry for `echo` | OTLP telemetry |

## Findings from the first run (2026-11-07)

- All checks pass on `container` 1.6.1 and 1.7.1, Kubernetes v1.37.0, Argo CD v3.6.1 and
  Istio 1.30.8. The 1.7.1 run uses the signed GitHub release, because the Homebrew build of
  1.7.1 has no cluster plugins.
- On 2026-11-08, all checks pass on kind 0.33.0 in a Colima 0.10.3 VM, with the same Kubernetes,
  Argo CD and Istio versions.
- kindnet enforces NetworkPolicy. With the `apps-demo` policies removed, `plaintext` reached
  `example.com`. With the policies back, the request timed out.
- Argo CD self-heal restored the deleted policies, once automated sync was back on.
- The Istio gateway chart sets a pod security context with no seccomp profile. The restricted
  level rejects it, so `components/istio-egress/values.yaml` sets the profile.
- The gateway chart adds a CPU autoscaler by default. The cluster has no metrics API, so the
  values turn the autoscaler off.
- Istio trims most Envoy stats. The egress check reads per-host counters from `/clusters` instead.
- On 2026-11-08, the cluster `cell-a-1` was the M0 base cell. M1 replaced it with `dev-cell-1` and three more clusters.
- On 2026-11-08, the fourth kind cluster failed to start. systemd in the node container reported
  "Too many open files" because the VM allows 128 inotify instances. `vm:up` now raises the limit to 1024.
  The setting resets when the VM restarts, and `vm:up` sets it again.
- On 2026-11-08, all 15 checks pass on `management`, `dev-cp`, `dev-cell-1` and `dev-cell-2`. The per-cluster issuer
  that the host service sets changes no check result.

## Differences on EKS

- The provider adapter creates the cluster and records its signing keys.
- `scripts/facts.sh` reads kubeadm configuration, which EKS does not have. EKS needs its own facts source.
- The VPC CNI enforces NetworkPolicy only after network policy support is turned on.
- The temporary admin access for bootstrap is removed after the bootstrap set is applied.

## Open questions

- Whether clusters in the same cell call each other directly, or only through management.
