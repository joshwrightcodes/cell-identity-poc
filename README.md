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
`harness:size` prints the memory and CPU of every node container and of `registry-mirror`.

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
| `registry-mirror` | 32 MiB | 0 percent |

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

## Keys

The SPIRE server in `dev-cp` gets its CA from an intermediate CA, and a root CA signs the intermediate.
The keys live in your secret manager. The External Secrets Operator in `dev-cp` copies them into Secret
`spire-upstream` in the namespace `spire-system`. No step in this repository writes a key to disk.

A cluster reads each key from the remote key `<cluster>/<service>/<key>`.
The ExternalSecret `spire-upstream` reads these three keys:

| Remote key | Secret key | Contents |
| --- | --- | --- |
| `dev-cp/spire-server/intermediate-key` | `intermediate-key` | The private key of the intermediate CA, as one PEM block `EC PRIVATE KEY` |
| `dev-cp/spire-server/intermediate-cert` | `intermediate-cert` | The certificate of the intermediate CA |
| `dev-cp/spire-server/root-cert` | `root-cert` | The certificate of the root CA |

Each provider of the operator maps the key at path `<cluster>/<service>/<key>` to its own structure.
The operator documentation for your provider says how it reads a remote key.

The SPIRE agents read the root certificate from ConfigMap `spire-trust-bundle`.

`mise run pki` prints PEM on standard output. `root` and `intermediate` print a bundle: the key, then the certificate.
`key` and `cert` read a bundle on standard input and print one part of it.
The steps below use placeholders in angle brackets.
Replace `<read>` and `<write>` with the read and write commands of your secret manager.
`<write> <dev-cp/spire-server/root-cert>` stores standard input at the place that this remote key names.
`<root-ca-bundle>` is a placeholder for the name of the root CA bundle in your secret manager.

The root CA bundle holds the root private key.
Keep it in a vault that the cluster access token cannot read.
Then no cluster can read the root key.

A failed `mise run pki` prints one JSON error line and exits with a non-zero status.
Each step keeps the output in a shell variable, and `&&` runs a write only after success.
Because of this, an error line never reaches your secret manager.

1. Create the root CA, and store its bundle:

   ```sh
   root="$(mise run pki -- root)" && printf '%s\n' "$root" | <write> <root-ca-bundle>
   unset root
   ```

2. Create the intermediate CA from the root bundle, and store its key and certificate as separate items:

   ```sh
   inter="$(<read> <root-ca-bundle> | mise run pki -- intermediate --days 30)" &&
     key="$(printf '%s\n' "$inter" | mise run pki -- key)" &&
     cert="$(printf '%s\n' "$inter" | mise run pki -- cert)" &&
     printf '%s\n' "$key" | <write> <dev-cp/spire-server/intermediate-key> &&
     printf '%s\n' "$cert" | <write> <dev-cp/spire-server/intermediate-cert>
   unset inter key cert
   ```

3. Store the root certificate on its own:

   ```sh
   cert="$(<read> <root-ca-bundle> | mise run pki -- cert)" &&
     printf '%s\n' "$cert" | <write> <dev-cp/spire-server/root-cert>
   unset cert
   ```

4. Copy `.envrc.local.example` to `.envrc.local`, and replace each placeholder.
   Git ignores `.envrc.local`, and direnv loads it through `.envrc`.
   `POC_SECRET_TOKEN_CMD` prints the read-only access token.
   `POC_SECRET_STORE_PROVIDER` holds the provider block of the store, as JSON.

5. Connect the operator in `dev-cp` to your secret manager:

   ```sh
   CELL=dev-cp mise run secrets:connect
   ```

`secrets:connect` needs the operator in the cluster, so run it after the `external-secrets` Application is Healthy.
`cell:up` for `dev-cp` waits until the SPIRE server is healthy, and the server needs Secret `spire-upstream`.
Because of this, run `secrets:connect` in a second shell while `cell:up` waits.

`secrets:connect` creates Secret `poc-secrets-token` in the namespace `external-secrets`.
It then applies ClusterSecretStore `poc-secrets` and waits until the store is Ready.
Only the namespaces in `SECRET_STORE_NAMESPACES` of `cells/<cluster>.env` can use the store.
The token reaches `kubectl` through a pipe, and the script never prints it.
The Secret and the store live outside every bundle, so Argo CD never deletes them.
Run `secrets:connect` again after a change of the access token.

The intermediate is valid for 30 days, and the root for one year.
Create a new intermediate before the old one expires.
The operator reads the keys again every hour.
The SPIRE server reads the new files when it signs its next CA.

## Layout

| Path | Contents |
| --- | --- |
| `cells/` | `common.env` holds upstream versions. `<cluster>.env` holds the name, trust domain and bundle store port |
| `harness/` | The topology of the five clusters |
| `bootstrap/` | The root Application, applied once |
| `components/` | One directory for each bundle |
| `scripts/` | The scripts behind the mise tasks |
| `vendor/` | Reviewed upstream files: the Argo CD install, the Istio charts and the External Secrets Operator chart |
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
