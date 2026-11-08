# cell-identity-poc

A proof of concept for identity between a management plane, cell control planes and cells,
with no shared credentials. Each plane runs in its own Kubernetes cluster.

The first milestone is the base cell: one cluster with Argo CD, Istio, network policy and an
OpenTelemetry collector. Every later plane starts from this base.
`docs/design/base-cell.md` describes it.

## What the PoC shows

![Kiln, dev-cp and three cells in a Colima VM, with a host service on the Mac](docs/images/poc-architecture.svg)

Five kind clusters run in one Colima VM on a Mac. Each connection goes up a layer, and Kiln
connects to no cluster. A host service on the Mac stands in for the cloud provider. The
markers match this list:

1. Kiln requests two new cells, and `dev-cp` creates them. The cell controller acts only on a
   step that Kiln signs.
2. Each cell's `kiln-celld` registers and authenticates. The `cluster_jwt` attestor checks a
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

## Stand up the cell

```sh
mise install
mise run harness:up
CELL=dev-cell-1 mise run cell:verify
```

`harness:up` starts the Colima VM, through `vm:up`. It then creates all five clusters through the host service.
After that it runs `cell:up` for each cluster that has the `base-cell` component set in `harness/topology.yaml`. The `rogue` cluster has no components.
`cell:up` applies the bootstrap set, publishes the bundles and waits until Argo CD reports every Application as Synced and Healthy.
`cell:verify` runs one check for each base rule and prints PASS or FAIL.

The `CELL` variable picks the cluster for the `cell:*` tasks. The default is `dev-cell-1`.
An unknown name fails with a list of the known cells. For example, `CELL=kiln mise run cell:up` stands up the base cell on `kiln` only.

## How a change reaches the cell

1. Change a component under `components/`.
2. Run `mise run cell:hydrate` to render every component into `build/<cluster>/bundles/`.
3. Run `mise run cell:publish` to push the bundles to the bundle store in the cluster.
4. Argo CD syncs the changed bundles. Each Application pins its bundle by digest.

The bundle store keeps bundles in an `emptyDir` volume.
If its pod restarts, run `mise run cell:publish` again.

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
