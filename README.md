# cell-identity-poc

A proof of concept for identity between a management plane, cell control planes and cells,
with no shared credentials. Each plane runs in its own Kubernetes cluster.

The first milestone is the base cell: one cluster with Argo CD, Istio, network policy and an
OpenTelemetry collector. Every later plane starts from this base.
`docs/design/base-cell.md` describes it.

## What the PoC shows

![The management cluster, dev-cp and three cells in a Colima VM, with a host service on the Mac](docs/images/poc-architecture.svg)

Five kind clusters run in one Colima VM on a Mac. Each connection goes up a layer, and Kiln
connects to no cluster. A host service on the Mac acts as the cloud provider. The
markers match this list:

1. Kiln requests two new cells, and `dev-cp` creates them. The cell controller acts only on a
   step that Kiln signs.
2. Each cell's `celld` registers and authenticates. The `cluster_jwt` attestor checks a
   pod-bound token against the cell's keys in a signed record.
3. Both cells appear valid in Kiln. Kiln reads each cluster's keys itself, and checks a second
   proof that `dev-cp` cannot make.
4. `dev-cp` and Kiln reject a rogue cell and a man in the middle. The rogue cluster's keys are in no
   record, and TLS interception fails at every hop.

- **I:** island mode at both levels. If Kiln or `dev-cp` goes away, cells keep their
  identities and their last good state.
- **V:** a read-only central view in Kiln. It shows the Argo CD state of both cells, and it
  cannot change a cell.

`docs/design/poc-scope.md` gives the build scope. `docs/design/target-architecture.md` gives
the full design.

## What you need

- A Mac with Apple silicon and macOS 26 or later.
- mise. It installs every tool at the version that `mise.toml` pins, Colima, Lima and the Docker
  CLI included.
- 14 CPUs, 40 GB of memory and 120 GB of disk for the Colima VM `poc`.

## Set up the cell

```sh
mise install
mise run harness:up
CELL=dev-cell-1 mise run cell:verify
```

`harness:up` first runs `harness:preflight`, which starts the Colima VM and checks the tool versions. It then creates all five clusters through the host service.
After that it runs `cell:up` for each cluster that has the `base-cell` component set in `harness/topology.yaml`. The `rogue` cluster has no components.
`cell:up` applies the bootstrap set, publishes the bundles and waits until Argo CD reports every Application as Synced and Healthy.
`cell:verify` runs one check for each base rule and prints PASS or FAIL.

The `CELL` variable picks the cluster for the `cell:*` tasks. The default is `dev-cell-1`.
An unknown name fails with a list of the known cells. For example, `CELL=management mise run cell:up` sets up the base cell on `management` only.

## Size and time

`harness/versions.env` holds the expected tool versions and the time budget of `gate:m1`.
`harness:preflight` fails when a tool version or the Colima profile `poc` differs from that file.
`harness:size` prints the memory and CPU of every node container and of `kiln-registry`.

Two runs from clean, each with `harness:down` and `harness:up`, gave these `harness:up` durations on 2026-11-08:

| Run | `harness:up` |
| --- | --- |
| 1 | 17 minutes 2 seconds |
| 2 | 17 minutes 13 seconds |

The final `gate:m1`, with five tests, ran after the last fixes on the healthy clusters.
It took about 102 seconds in one run and 103 seconds in the slower run.
An earlier version of the gate took 65 and 64 seconds, so those numbers no longer apply.

After the clusters were healthy, the five node containers used about 8 GiB of memory in total:

| Container | Memory | CPU |
| --- | --- | --- |
| `management`, `dev-cp`, `dev-cell-1`, `dev-cell-2` (each) | 1.7 to 1.8 GiB | 6 to 10 percent |
| `rogue` | 0.6 GiB | 5 percent |
| `kiln-registry` | 32 MiB | 0 percent |

The VM reports 8.5 GB of 40 GB in use, and 16 GB more in the file cache.

`gate:m1` prints its elapsed time. It fails when the run takes longer than `GATE_M1_BUDGET_MINUTES`.
The budget is 3 minutes. This is 1.5 times the slower run of 103 seconds, rounded up to the next minute.
The budget does not cover `harness:up`.

## Restart of the VM

`harness:restart-check` stops and starts the VM, waits until every node is Ready, and runs `gate:m1`.
On 2026-11-08 the clusters did not survive a restart.
All five nodes returned to Ready within seconds.
The workloads did not recover: `istiod` and the Istio CNI pod stayed not Ready, and the mesh pods stayed in `Unknown` or `istio-validation` back-off.
Eight of the 15 `cell:verify` checks failed, and the first `gate:m1` run failed one test.
Treat a restart of the Mac or the VM as a disaster recovery event.
Run `mise run harness:down` and `mise run harness:up` after it.

## How a change reaches the cell

1. Change a component under `components/`.
2. Run `mise run cell:hydrate` to render every component into `build/<cluster>/bundles/`.
3. Run `mise run cell:publish` to push the bundles to the bundle store in the cluster.
4. Argo CD syncs the changed bundles. Each Application pins its bundle by digest.

The bundle store keeps bundles on a persistent volume, so they survive a pod restart.

## Layout

| Path | Contents |
| --- | --- |
| `cells/` | `common.env` holds upstream versions. `<cluster>.env` holds the name, trust domain and bundle store port |
| `harness/` | The topology of the five clusters |
| `bootstrap/` | The root Application, applied once |
| `components/` | One directory for each bundle |
| `scripts/` | The scripts behind the mise tasks |
| `vendor/` | Reviewed upstream files: the Argo CD install and the Istio charts |
| `docs/design/` | Design documents |

## Look at the cell

The cell runs the Argo CD core install, which has no UI. `mise run cell:ui` serves the UI
from your Mac at <http://localhost:8080> and reads the cluster through your kubeconfig.
It needs no login, and it stops when you press Ctrl-C.

```sh
mise run cell:ui
kubectl --context kind-dev-cell-1 -n argocd get applications
kubectl --context kind-dev-cell-1 -n observability-system logs deploy/otel-collector
```

## Remove the cell

```sh
CELL=dev-cell-1 mise run cell:down
mise run harness:down
```

`cell:down` deletes one cluster. `harness:down` deletes all five.
