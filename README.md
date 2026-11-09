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

Before the first `harness:up`, create the keys and `.envrc.local` as [Keys](#keys) describes.
The SPIRE server in `dev-cp` cannot start without them.

```sh
mise install
mise run harness:up
CELL=dev-cell-1 mise run cell:verify
```

`harness:up` first runs `harness:preflight`, which starts the Colima VM and checks the tool versions. It then creates all five clusters through the host service.
After that it runs `cell:up` for each cluster that has the `base-cell` component set in `harness/topology.yaml`. The `rogue` cluster has no components.
`harness:up` handles the clusters in topology order, so `dev-cp` is ready before the cells. The `cell-identity` render of each cell reads the trust bundle from the SPIRE server in `dev-cp`.
`cell:up` applies the bootstrap set, publishes the bundles and waits until Argo CD reports every Application as Synced and Healthy at the published revision.
Last, `cell:up` applies the harness components, for example `cell-identity`, and waits for their rollout.
Harness components stay outside every Argo CD Application. A bundle can still write to their namespace, as the residual limits in `docs/design/poc-scope.md` say.
`cell:verify` runs one check for each base rule and prints PASS or FAIL.

`harness:up` stops at the first cluster that fails, so a failure in `dev-cp` also stops the cells.
To resume, fix the cause and run the remaining clusters in topology order:

```sh
CELL=dev-cp mise run cell:up
CELL=dev-cell-1 mise run cell:up
CELL=dev-cell-2 mise run cell:up
```

Each `cell:up` of `dev-cp` signs the test records of the cells again, with a new key.
The server config changes because of this, so the SPIRE server pod restarts. M4 replaces the test records.

The `CELL` variable picks the cluster for the `cell:*` tasks. The default is `dev-cell-1`.
An unknown name fails with a list of the known cells. For example, `CELL=management mise run cell:up` sets up the base cell on `management` only.

## Rebuild one cluster

A rebuilt cluster can get a new node address from Docker, and a rebuilt cell gets a new service account key.
Renders read both facts once, so the other clusters keep the old values until they render again.
`cell:verify` compares the deployed values with the host service, and it prints the command to run when they differ.

To rebuild a cell, for example `dev-cell-1`, create the cluster first.
Then `dev-cp` can sign a record with the new key before the cell agent attests:

```sh
CELL=dev-cell-1 mise run cell:down
mise run hostsvc -- up --only dev-cell-1
CELL=dev-cp mise run cell:up
CELL=dev-cell-1 mise run cell:up
CELL=dev-cp mise run cell:verify
CELL=dev-cell-1 mise run cell:verify
```

To rebuild `dev-cp`, set it up first. Its `cell:up` waits for the SPIRE server, which needs Secret `spire-upstream`.
Run `secrets:connect` in a second shell while that `cell:up` waits, as [Keys](#keys) describes.
Then render each cell again, because each cell holds the `dev-cp` node address.
The new server has an empty datastore, so it knows no earlier agent.
`cell:restart` restarts `celld` in a cell, so that its agent attests again:

```sh
CELL=dev-cp mise run cell:down
CELL=dev-cp mise run cell:up            # first shell
CELL=dev-cp mise run secrets:connect    # second shell, while cell:up waits
CELL=dev-cell-1 mise run cell:up
CELL=dev-cell-2 mise run cell:up
CELL=dev-cell-1 mise run cell:restart
CELL=dev-cell-2 mise run cell:restart
CELL=dev-cp mise run cell:verify
CELL=dev-cell-1 mise run cell:verify
CELL=dev-cell-2 mise run cell:verify
```

## Size and time

`gate:m1` and `gate:m2` run only on this Mac, against the local clusters. CI runs `mise run test` and `mise run lint`.
`harness/versions.env` holds the expected tool versions and the time budgets of `gate:m1` and `gate:m2`.
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
`gate:m2` fails when the run takes longer than `GATE_M2_BUDGET_MINUTES`.
The budget is 14 minutes. This is 1.5 times the slowest run, 547 seconds, rounded up to the next minute.
In that run, the cleanup of the key rotation test waited a few minutes for kubelet to start `kube-controller-manager` again.
Many API server restarts in a short time raise that back-off, up to 5 minutes.
Other runs took 312 to 471 seconds.
The M2 key rotation test restarts the API server of `dev-cell-1` twice, and it takes two to three minutes of that time.
The budgets do not cover `harness:up`.

## Side effects of gate:m2

`gate:m2` changes the clusters while it runs, and it puts them back before it ends:

- It publishes test bundles of `root` and `spire-server` in `dev-cp`, with an entry under `/m2-test/`, for about two minutes.
- It replaces the `celld` pod in each cell, so the SPIRE server keeps about six old agent entries until it prunes them, one hour after they expire.
- It removes the `celld-token` RoleBinding of `dev-cell-2` for about a minute, and then applies it again from the harness bundle.
- It edits the API server manifest of `dev-cell-1` on the node and signs tokens with a test key for two to three minutes.
- After the edit, it makes sure that `kube-controller-manager` of `dev-cell-1` runs a new container, because it keeps a token for each controller in memory.
  kubelet can delay that container by its restart back-off, up to 5 minutes.
  Until it runs, no controller of `dev-cell-1` replaces a pod.
- It replaces each pod of `dev-cell-1` that received a token from the test key.
  The `kindnet` pod comes first, and the others follow one at a time.
  A Deployment outside the harness and outside Argo CD gets a rollout restart, so `coredns` keeps one ready pod.
  The other pods are deleted, and their controllers create them again.
  While the `kindnet` pod restarts, NetworkPolicy probably fails open, as the residual limits in `docs/design/poc-scope.md` say.

A run that stops before its cleanups, for example after Ctrl-C, a go test timeout or a closed terminal, can leave these changes in place.
The next `gate:m2` run then stops before its other checks.
`CELL=dev-cp mise run cell:verify` and `CELL=dev-cell-1 mise run cell:verify` fail, and a render of `dev-cp` refuses to sign the record of a changed cell.
Each of them prints the repair command:

```sh
mise run gate:m2:repair
CELL=dev-cp mise run cell:verify
CELL=dev-cell-1 mise run cell:verify
```

The repair puts back the bundles of `dev-cp` and the API server of `dev-cell-1`, and it is safe to run again.
The repair, the gate prechecks and `cell:verify` in `dev-cp` take `build/dev-cp/published.env` of this checkout as the truth, which the last `cell:publish` from this checkout wrote.
After a publish from another checkout, run `CELL=dev-cp mise run cell:up` here instead of the repair.
It usually takes a few minutes.
Each wait has a bound, and the log names it.
The fixed waits add up to about 20 minutes, and each replaced pod adds up to 3 minutes.
kubelet back-off alone can take 5 minutes of that time.
New pods of `dev-cell-1` wait while `kube-scheduler` is in kubelet back-off, so the repair waits for it before it replaces pods.
A repair in the cleanup of a test can outlast the `go test` timeout in the worst case.
The next run then stops in its precheck and prints the repair command.
A stopped run can also leave probe objects in `cell-identity-system`, and the next gate run deletes them.
If the precheck reports a missing `celld-token` RoleBinding, run `CELL=<cell> mise run cell:up` for that cell.

## SVID lifetimes and sleep

`SPIRE_SVID_TTL` in `cells/dev-cp.env` sets the lifetime of agent and workload SVIDs.
The value is `1m`, so a gate sees two renewals in about a minute.
For an environment that stays up without gates, set `SPIRE_SVID_TTL=1h` and run `CELL=dev-cp mise run cell:up`.
The render accepts values from `1m` to `4h`, which is `ca_ttl` divided by 6.
`cell:verify` in `dev-cp` checks that the server runs the value of `SPIRE_SVID_TTL`.

With `1m`, a sleep of the Mac longer than about half a minute lets agent SVIDs expire.
An agent with an expired SVID exits, and its new container attests as a new agent.
The Mac must stay awake for the whole gate, so run a keep-awake tool while the gate runs.
macOS still sleeps when you close the lid on battery power, whatever tool runs.

After a sleep, follow these steps:

1. Run `CELL=<cluster> mise run cell:verify` for `dev-cp`, `dev-cell-1` and `dev-cell-2`.
2. If new pods stay in `ContainerCreating` and the events show `Unauthorized` from `istio-cni`, delete the `istio-cni-node` pod of that cell.
   Its DaemonSet creates a new pod with a new token.
3. If `celld` holds no current SVID, run `CELL=<cell> mise run cell:restart`.
4. If a gate stopped during the sleep, run `mise run gate:m2:repair`.

## Restart of the VM

`harness:restart-check` stops and starts the VM, waits until every node is Ready, and runs `gate:m1`.
On 2026-11-08 the clusters did not survive a restart.
All five nodes returned to Ready within seconds.
The workloads did not recover: `istiod` and the Istio CNI pod stayed not Ready, and the mesh pods stayed in `Unknown` or `istio-validation` back-off.
Eight of the 15 `cell:verify` checks failed, and the first `gate:m1` run failed one test.
Treat a restart of the Mac or the VM as a disaster recovery event.
Run `mise run harness:down` and `mise run harness:up` after it.

## How a change reaches the cell

1. Change a component under `components/`. After a change under `cmd/` or `internal/`, run `mise run images` first.
   Renders fail while `build/images.env` is older than the Go sources.
2. Run `mise run cell:hydrate` to render every component into `build/<cluster>/bundles/`.
3. Run `mise run cell:publish` to push the bundles to the bundle store in the cluster.
4. Argo CD syncs the changed bundles. Each Application pins its bundle by digest.

The bundle store keeps bundles on a persistent volume, so they survive a pod restart.

A harness component, for example `cell-identity`, reaches a cell only through `CELL=<cell> mise run cell:up`.
`cell:publish` does not push it. `cell:up` applies it with server-side apply and does not prune.
An object that leaves the bundle therefore stays in the cluster until you delete it.
`cell:verify` compares the live objects with the bundle.
It checks the field values, the objects of each kind that the bundle holds, and the field managers of those objects.
It does not report an extra object of a kind that the bundle does not hold.

Each image reaches its cluster through one command:

| Image | Runs in | Reaches the cluster through |
| --- | --- | --- |
| `netprobe` | Test pods of the gates and `cell:verify` probes in every cluster | `mise run gate:m1`, `mise run gate:m2` and `mise run cell:verify` |
| `cluster-jwt-server` | The init container of the SPIRE server in `dev-cp` | `CELL=dev-cp mise run cell:up`, through the `spire-server` bundle and Argo CD |
| `cluster-jwt-agent` | The init container of the `celld` pod in each cell | `CELL=<cell> mise run cell:up`, through the harness apply |
| `celld` | The `celld` container in each cell | `CELL=<cell> mise run cell:up`, through the harness apply |
| `attestprobe` | Test Jobs of `gate:m2` in `dev-cell-1` | `mise run gate:m2` |

`mise run images` builds all five and records their digests in `build/images.env`.
`cell:verify` fails when a running image differs from that file.
`mise run images` builds without VCS stamps, so a digest changes only when the sources of that image change.
A comment line in `build/images.env` records the commit of the build.
`gate:m1` and `gate:m2` run `mise run images` first.
After a change under `cmd/` or `internal/`, run `cell:up` for `dev-cp` and for each cell before `cell:verify`.
`gate:m2` first compares the deployed images with `build/images.env`, and it prints the `cell:up` commands when they differ.

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
Last, it forces a sync of each ExternalSecret that uses the store, and waits until each target Secret exists.
An ExternalSecret that failed before the store existed would otherwise wait for its retry delay.
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
