# cell-identity-poc

A proof of concept for identity between a management plane, cell control planes and cells,
with no shared credentials. Each plane runs in its own Kubernetes cluster.

The first milestone is the base cell: one cluster with Argo CD, Istio, network policy and an
OpenTelemetry collector. Every later plane starts from this base.
`docs/design/base-cell.md` describes it.

## What you need

- A Mac with Apple silicon and macOS 26 or later.
- Apple `container` 1.6.1 or later, with `container system start` done.
- mise. It installs every other tool at the version that `mise.toml` pins.
- About 6 CPUs and 12 GB of memory free for the cell.

## Stand up the cell

```sh
mise install
mise run cell:up
mise run cell:verify
```

`cell:up` creates the `cell-a-1` cluster and applies the bootstrap set. It then publishes the
bundles and waits until Argo CD reports every Application as Synced and Healthy.
`cell:verify` runs one check for each base rule and prints PASS or FAIL.

## How a change reaches the cell

1. Change a component under `components/`.
2. Run `mise run cell:hydrate` to render every component into `build/bundles/`.
3. Run `mise run cell:publish` to push the bundles to the store in the cluster.
4. Argo CD syncs the changed bundles. Each Application pins its bundle by digest.

The store keeps bundles in an `emptyDir` volume, because the cluster has no StorageClass.
If its pod restarts, run `mise run cell:publish` again.

## Layout

| Path | Contents |
| --- | --- |
| `cell.env` | Cell name, size, trust domain and upstream versions |
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
kubectl --context cell-a-1 -n argocd get applications
kubectl --context cell-a-1 -n otel logs deploy/otel-collector
```

## Remove the cell

```sh
mise run cell:down
```
