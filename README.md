# cell-identity-poc

A proof of concept for identity between a management plane, cell control planes and cells,
with no shared credentials. Each plane runs in its own Kubernetes cluster.

The first milestone is the base cell: one cluster with Argo CD, Istio, network policy and an
OpenTelemetry collector. Every later plane starts from this base.
`docs/design/base-cell.md` describes it.

## What the PoC shows

![The management cluster, dev-cp and three cells in a Colima VM, with a host service on the Mac](docs/images/poc-architecture.svg)

Five kind clusters run in one Colima VM on a Mac. Each connection goes up a layer, and the
management plane connects to no cluster. A host service on the Mac acts as the cloud provider. The
markers match this list:

1. The portal requests two new cells, and `dev-cp` creates them. The cell controller acts only on
   a step that the management plane signs.
2. Each cell's `celld` registers and authenticates. The `cluster_jwt` attestor checks a
   pod-bound token against the cell's keys in a signed record.
3. Both cells appear valid in the management plane. The management plane reads each cluster's keys
   itself, and checks a second proof that `dev-cp` cannot make.
4. `dev-cp` and the management plane reject a rogue cell and a man in the middle. The rogue
   cluster's keys are in no record, and TLS interception fails at every hop.

- **I:** island mode at both levels. If the management plane or `dev-cp` goes away, cells keep
  their identities and their last good state.
- **V:** a read-only central view in the management plane. It shows the Argo CD state of both
  cells, and it cannot change a cell.

`docs/design/poc-scope.md` gives the build scope. `docs/design/target-architecture.md` gives
the full design.

## What you need

- A Mac with Apple silicon and macOS 26 or later.
- git, to clone the repository.
- mise. It installs every tool at the version that `mise.toml` pins, Colima, Lima and the Docker
  CLI included. Run `mise trust` once in the checkout, because mise does not load an untrusted
  `mise.toml`.
- 14 CPUs, 40 GB of memory and 120 GB of disk for the Colima VM `poc`.
- A secret manager with a provider in the External Secrets Operator 2.14. The operator must reach
  it on a public address over TCP port 443, because its NetworkPolicy blocks private ranges.
  The secret manager holds the CA keys, as [Keys](#keys) describes.
- direnv is optional. After `direnv allow`, it loads `.envrc.local` in the checkout. Without it,
  `secrets:connect` and `pki:rotate-intermediate` read `.envrc.local` themselves.

## Set up the cell

Follow these steps for the first setup:

1. Run `mise trust` and `mise install` in the checkout.
2. Create the keys and `.envrc.local`, as steps 1 to 4 of [Keys](#keys) describe.
   The SPIRE server in `dev-cp` cannot start without them.
3. Create and check the clusters:

   ```sh
   mise run harness:up
   mise run harness:verify
   ```

Step 5 of [Keys](#keys), `secrets:connect`, needs the cluster, so it comes during or after `harness:up`.

With `POC_SECRET_TOKEN_CMD` in the environment, `harness:up` connects the secret store of `dev-cp` itself.
Without it, the `cell:up` of `dev-cp` prints this command once a minute while the SPIRE server waits for its keys.
Run it in a second shell:

```sh
CELL=dev-cp mise run secrets:connect
```

`harness:up` first runs `harness:preflight`, which starts the Colima VM and checks the tool versions.
It then creates all five clusters through the host service, and builds the images with `mise run images`.
After that it runs `cell:up` for each cluster that has the `base-cell` component set in `harness/topology.yaml`. The `rogue` cluster has no components.
`harness:up` handles the clusters in topology order, so `dev-cp` is ready before the cells. The `cell-identity` render of each cell reads the trust bundle from the SPIRE server in `dev-cp`.
`cell:up` applies the bootstrap set, publishes the bundles and waits until Argo CD reports every Application as Synced and Healthy at the published revision.
In `dev-cp`, that wait also runs `secrets:connect` once, or prints the command above, while the secret store is not connected.
Then `cell:up` applies the harness components, for example `cell-identity`, and waits for their rollout.
Last, `cell:up` runs the link phase of a cluster with link components, as [Central Argo CD view](#central-argo-cd-view) describes.
`harness:up` sets up `management` first with `CELL_UP_SKIP_LINK=1`, and runs `CELL=management mise run cell:link` after the cells.
Harness components stay outside every Argo CD Application. A bundle can still write to their namespace, as the residual limits in `docs/design/poc-scope.md` say.
`cell:verify` runs the checks of one cluster and prints PASS or FAIL for each.
`harness:verify` runs `cell:verify` on each cluster with components, and prints one line for each cluster at the end.

`harness:up` stops at the first cluster that fails, so a failure in `dev-cp` also stops the cells.
It then prints the commands for the remaining clusters. Fix the cause, and run them in topology order:

```sh
CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up
CELL=dev-cp mise run cell:up
CELL=dev-cell-1 mise run cell:up
CELL=dev-cell-2 mise run cell:up
CELL=management mise run cell:link
```

Each `cell:up` of `dev-cp` signs the test records of the cells again, with a new key.
The server config changes because of this, so the SPIRE server pod restarts. M4 replaces the test records.

The `CELL` variable picks the cluster for the `cell:*` tasks. The default is `dev-cell-1`.
An unknown name fails with a list of the known cells. For example, `CELL=dev-cell-1 mise run cell:up` sets up `dev-cell-1` only.
`cell:up` of `management` also runs its link phase, which needs `dev-cp` and each cell of `VIEW_CELLS`.
When one of them is missing, `cell:up` stops before its first apply and prints the command.
To set up the base cell of `management` alone, run `CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up`.

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
With `POC_SECRET_TOKEN_CMD` in the environment, `cell:up` runs `secrets:connect` itself.
Otherwise run `secrets:connect` in a second shell while that `cell:up` waits, as [Keys](#keys) describes.
Then render each cell again, because each cell holds the `dev-cp` node address.
The new server has an empty datastore, so it knows no earlier agent.
`cell:restart` restarts `celld` in a cell, so that its agent attests again:

```sh
CELL=dev-cp mise run cell:down
CELL=dev-cp mise run cell:up            # first shell
CELL=dev-cp mise run secrets:connect    # second shell, only without POC_SECRET_TOKEN_CMD
CELL=dev-cell-1 mise run cell:up
CELL=dev-cell-2 mise run cell:up
CELL=dev-cell-1 mise run cell:restart
CELL=dev-cell-2 mise run cell:restart
CELL=management mise run cell:link
mise run harness:verify
```

The last `cell:link` copies the new `dev-cp` root and node address into the central view.

`CELL=dev-cp mise run cell:restart` restarts the SPIRE server, which then signs a new CA through the intermediate.
The server keeps its datastore, so the agents keep their identities.
On 2026-11-09 the new server pod was Ready about 2 seconds after the old pod stopped. No agent of a cell restarted.
A `cell:restart` of `dev-cp` took 3 seconds from the delete to a Ready new pod. The agents of both cells ran on for 75 seconds after it with no restart, longer than one SVID lifetime.

## Central Argo CD view

The `management` cluster holds one read-only Argo CD UI for both cells, in `central-view-system`.
The link component `central-view` renders it in the link phase, after every other component.
Its render reads the live root and node address of `dev-cp`, and it signs a record for each cell of `VIEW_CELLS` in `cells/management.env`.
Because of this, the cells and `dev-cp` must exist first.

The view has these parts:

- `argocd-server`, `argocd-repo-server` and `argocd-redis` from the full Argo CD install. The view runs no application controller.
- The Argo CD Agent principal, with `cell-proxy` and a SPIRE agent in the same pod.
  `cell-proxy` accepts SPIFFE mTLS on node port 31443 from the `dev-cp` node only.
  It admits only `spiffe://dev.env.poc.internal/cell/<cell>/argocd-agent` for a registered cell.
  It then calls the principal on `127.0.0.1:8443` with the header `x-cell-agent: <env>-<cell>`.
- One agent namespace `<env>-<cell>` for each cell, with a default deny.
- Job `viewkeys`, which makes the keys of the view inside the cluster. No Secret holds the key of the agent CA.

Run the link phase again after a change to a cell, to `dev-cp` or to `VIEW_CELLS`:

```sh
CELL=management mise run cell:link
```

Open the UI on `http://127.0.0.1:8090`. The anonymous user can read and cannot sync, change or delete:

```sh
mise run view:ui
```

The view is read-only, so a refresh in the UI fails with a permission error.
`argocd-server` may read the Applications of the agent namespaces and change none of them.
Before the agents of the cells connect (a later milestone task), the list of Applications is empty. That is the expected result.

While `view:ui` runs, the page is open on the Mac loopback. Every pod on the VM, `rogue` included, can reach it through `host.docker.internal`.
The task prints a warning about this when it starts. Stop it with Ctrl-C when you are done.

Make new view keys and a new central Redis password with one command. The command restarts `argocd-redis`, `argocd-repo-server`, the principal and `argocd-server`, and prints one JSON line:

```sh
mise run view:rotate-keys
```

If the task stops before its end, run it again. It is safe to run again, and only one run may go at a time.

The client certificates of the view are valid for 180 days. `cell:verify` fails 30 days before they expire. Run `view:rotate-keys` then.
`viewkeys` keeps no CA key. When a certificate Secret is missing or does not match the CA, for example after a new cell in `VIEW_CELLS`, `cell:link` makes a new CA and new certificates, and starts the principal and `argocd-server` again.
`cell:verify` of `management` also compares the view listener address and ConfigMap `peer-root` with the live values of `dev-cp`. After a rebuild of `dev-cp`, it prints `CELL=management mise run cell:link`.

## Add or remove a cell

A cell is an entry in `harness/topology.yaml` and a file `cells/<cell>.env`.
To add a cell, for example `dev-cell-3`, follow these steps:

1. Add the cluster to `harness/topology.yaml`, with pod and service subnets that overlap no other subnet, and the component sets `base-cell` and `cell-identity`.
2. Copy `cells/dev-cell-2.env` to `cells/dev-cell-3.env`. Set `CELL_NAME`, `CELL_MESH_TRUST_DOMAIN`, and a `CELL_BUNDLE_STORE_PORT` that no other cell uses.
3. Add the cell to `SPIRE_AGENT_CELLS` in `cells/dev-cp.env`.
4. Change the cluster count in `TestValidateAcceptsHarnessTopology` of `internal/topology`, which checks the real file.
5. Create the cluster, sign its record in `dev-cp`, and set it up:

   ```sh
   mise run hostsvc -- up --only dev-cell-3
   CELL=dev-cp mise run cell:up
   CELL=dev-cell-3 mise run cell:up
   mise run harness:verify
   ```

`harness:up`, `harness:verify`, the image check of `gate:m2` and the cell loops of the end-to-end tests read the cells from `harness/topology.yaml`.
The M2 rejection and renewal tests use `dev-cell-1` and `dev-cell-2` by name, because each test gives one of them its own role.

To remove a cell, remove it from `SPIRE_AGENT_CELLS` and run `CELL=dev-cp mise run cell:up`.
Then delete the cluster with `CELL=<cell> mise run cell:down`, and remove its entry and its `cells/<cell>.env`.
The server keeps the entries of the old agents of that cell until they expire and it prunes them.
To end them at once, evict each agent of the cell:

```sh
mise x -- kubectl --context kind-dev-cp -n spire-system exec spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server agent list -socketPath /run/spire/sockets/api.sock
mise x -- kubectl --context kind-dev-cp -n spire-system exec spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server agent evict -socketPath /run/spire/sockets/api.sock -spiffeID <agent ID>
```

## Size and time

`gate:m1` and `gate:m2` run only on this Mac, against the local clusters. CI runs `mise run test` and `mise run lint`.
`harness/versions.env` holds the expected tool versions and the time budgets of `gate:m1` and `gate:m2`.
`harness:preflight` fails when a tool version or the Colima profile `poc` differs from that file.
`harness:size` prints the memory and CPU of every node container and of `registry-mirror`.

Two runs from clean on 2026-11-09, each with `harness:down` and then `harness:up`, gave these durations.
Neither run needed a manual step. `secrets:connect` ran inside the `dev-cp` step.

| Run | `harness:up` | `management` | `dev-cp` | `dev-cell-1` | `dev-cell-2` |
| --- | --- | --- | --- | --- | --- |
| 1 | 16 minutes 53 seconds | 195 s | 271 s | 183 s | 223 s |
| 2 | 16 minutes 53 seconds | 217 s | 220 s | 233 s | 201 s |

The rest of each run creates the five clusters, in about 100 seconds, and builds the images, in about 15 seconds.
`harness:verify` passed every check in both runs.
After each run, `gate:m1` took 104 and 105 seconds, and `gate:m2` took 400 and 401 seconds.

After the clusters were healthy, the five node containers used about 8 GiB of memory in total:

| Container | Memory | CPU |
| --- | --- | --- |
| `dev-cp` | 2.0 to 2.1 GiB | 9 percent |
| `management`, `dev-cell-1`, `dev-cell-2` (each) | 1.75 to 1.9 GiB | 8 to 16 percent |
| `rogue` | 0.6 GiB | 5 to 6 percent |
| `registry-mirror` | 70 MiB | 0 percent |

The VM reports 8.9 GB of 40 GB in use, and 18 GB more in the file cache.

`gate:m1` prints its elapsed time. It fails when the run takes longer than `GATE_M1_BUDGET_MINUTES`.
The budget is 3 minutes. This is 1.5 times the slowest run of 104 seconds, rounded up to the next minute.
`gate:m1` runs only the clock check of the end-to-end prechecks. The M2 prechecks run for `gate:m2`, and for a direct `go test` run with no `-run` pattern.
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
  While the `kindnet` pod restarts, NetworkPolicy fails open, as the residual limits in `docs/design/poc-scope.md` say.

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
Only one repair runs at a time. A repair holds the lock `build/gate-m2-repair.lock`, and a second repair or a gate precheck refuses to start beside it.
A stopped run can also leave probe objects in `cell-identity-system`, and the next gate run deletes them.
If the precheck reports a missing `celld-token` RoleBinding, run `CELL=<cell> mise run cell:up` for that cell.

## SVID lifetimes and sleep

`SPIRE_SVID_TTL` in `cells/dev-cp.env` sets the lifetime of agent and workload SVIDs.
The value is `1m`, so a gate sees two renewals in about a minute.
For an environment that stays up without gates, change the value to `1h` in `cells/dev-cp.env`, and run `CELL=dev-cp mise run cell:up`.
A value in the shell environment has no effect, because mise and `scripts/lib.sh` load `cells/dev-cp.env` after the shell.
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
`spire-upstream` in the namespace `spire-system`.
No script in this repository writes a key to a file. etcd in `dev-cp` still stores each Secret on the disk of the VM, with no encryption.

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
`trust-bundle` checks PEM certificates of a trust bundle and prints them again.
`info` reads one certificate and prints its subject key ID and expiry as JSON.
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
   Git ignores `.envrc.local`. direnv loads it through `.envrc` after `direnv allow`.
   `POC_SECRET_TOKEN_CMD` prints the read-only access token.
   `POC_SECRET_STORE_PROVIDER` holds the provider block of the store, as JSON.
   The three other settings serve `pki:rotate-intermediate` only.

5. Connect the operator in `dev-cp` to your secret manager:

   ```sh
   mise run secrets:connect
   ```

`secrets:connect` acts on `dev-cp` unless `CELL` names another cluster.
It needs the operator in the cluster, so it first waits up to `SECRETS_CONNECT_ESO_WAIT` seconds for it.
The default is 300 seconds.
`cell:up` for `dev-cp` runs it when `POC_SECRET_TOKEN_CMD` is set and the store is not connected.
Otherwise run it in a second shell while `cell:up` waits.

The operator works only in the namespace in `SECRET_STORE_NAMESPACES` of `cells/dev-cp.env`, `spire-system`.
In that namespace, `secrets:connect` creates Secret `poc-secrets-token`.
It then applies SecretStore `poc-secrets` and waits until the store is Ready.
Last, it forces a sync of each ExternalSecret that uses the store.
It waits up to `SECRETS_CONNECT_SYNC_WAIT` seconds, 120 by default, until each target Secret exists.
An ExternalSecret that failed before the store existed would otherwise wait for its retry delay.
The token reaches `kubectl` through a pipe, and the script never prints it.
The Secret and the store live outside every bundle, so Argo CD never deletes them.
Run `secrets:connect` again after a change of the access token.
`cell:verify` in `dev-cp` checks that the store is Ready and that each ExternalSecret refreshed within twice its interval.

The intermediate is valid for 30 days, and the root for one year.
The operator reads the keys again every hour.
`cell:verify` in `dev-cp` fails when the intermediate expires in 7 days or less.
To replace the intermediate in one step, run:

```sh
mise run pki:rotate-intermediate
```

The task reads the root CA bundle at the remote key `POC_ROOT_CA_BUNDLE` through `POC_SECRET_READ_CMD`, and pkigen signs a new intermediate.
`POC_SECRET_WRITE_CMD` stores the new key and certificate at the two remote keys of the table above.
The task then runs `secrets:connect`, and waits until Secret `spire-upstream` holds the new certificate.
Next, it runs `cell:restart` in `dev-cp`.
Last, it checks that the active X.509 authority of the server has the new intermediate as its upstream authority.
`PKI_ROTATE_CHECK_WAIT` bounds each of the two waits in seconds. The default is 120.
`cell:verify` in `dev-cp` also fails when the active authority does not chain to the intermediate in the Secret.
The keys stay in shell variables and pipes, and the task prints no key.
`PKI_INTERMEDIATE_DAYS` sets the validity of the new intermediate. The default is 30.
Use a write identity for this task, and not the read-only cluster token.

### Keys of the management plane

`management` holds no secret manager token, and its operator has no secret store.
The operator works only in `observability-system`, the namespace in `EXTERNAL_SECRETS_NAMESPACE` of `cells/management.env`.
It has no route to the internet.

The SPIRE server in `management` makes its CA inside the cluster, with no upstream authority.
The CA is a self-signed root of the trust domain `mgmt.poc.internal`.
It lives 90 days, from `SPIRE_CA_TTL=2160h`.
SPIRE prepares a new root by itself after 60 days, and signs with it after 83 days.
`cell:verify` in `management` fails 7 days before day 60.
Run `mgmt:rotate-ca` before then.
The server keeps the CA key in the file `keys.json` on its data volume, the PersistentVolumeClaim `data-spire-server-0` in `spire-system`.
The key has no encryption on the disk of the VM.

A restart of the server loads the same key from the volume, so the root stays the same.
This applies to `CELL=management mise run cell:restart`, a node restart and a pod eviction.
Each copy of the root in another cluster then stays valid, and no other cluster needs a new render.
A new data volume gives a new root, for example after `cell:down` and `cell:up` of `management`.
Then each copy of the old root fails, so run `cell:up` again on each cluster that holds a copy.
`pki:rotate-intermediate` does not apply to `management`.

To replace the CA of `management`, run:

```sh
mise run mgmt:rotate-ca
```

Use it when someone may hold a copy of `keys.json`, or before SPIRE prepares a new root.
The task finds each copy of the root in the other clusters.
A copy is a ConfigMap with the key `root.crt` and the annotation `poc.internal/peer-root-sha256`.
The task also finds the trust bundle of each SPIRE agent sidecar of a link component in `management`, for example `spire-trust-bundle-argocd-agent-principal`.
A new pod of that workload attests with this bundle, so the bundle must hold the active root.
The task then runs these steps:

1. It prepares a new X.509 authority and a new JWT authority. The bundle then holds the old and the new root.
2. It runs `cell:up` on each other cluster that holds a copy, and `cell:link` in `management` for its own copies. Then it waits until each copy equals the bundle.
3. It activates the new authorities. New SVIDs chain to the new root, and each copy holds it.
4. It taints the old authorities, so the agents replace their SVIDs. After `MGMT_ROTATE_TAINT_WAIT` seconds, 120 by default, it revokes them.
5. It runs the refresh of step 2 again, and waits until each copy holds only the new root.

`MGMT_ROTATE_WAIT` bounds each wait for the copies in seconds. The default is 900.
The old key stays in `keys.json` until SPIRE prepares a new authority in its place.
No copy trusts its root after step 5.
`cell:down` and `cell:up` of `management` remain the last resort, because they also delete the datastore.

## Move a live dev-cp to the scoped operator

A `dev-cp` from before the scoped External Secrets Operator runs the cluster-wide operator and ClusterSecretStore `poc-secrets`.
`cell:verify` then fails its store and operator checks.
Run the one migration command, with the settings of `secrets:connect` in place:

```sh
mise run eso:migrate
mise run harness:verify
```

First, the task annotates Namespace `spire-system` with `Prune=false,Delete=false`, and it reads the annotation back.
No bundle of the old Application holds the namespace any more. Without the guard, Argo CD can delete it, with the SPIRE server and its datastore.
The task then publishes the bundles, waits for the scoped controller, and runs `secrets:connect`.
It checks the UIDs of the namespace and the datastore volume, the store, the operator permissions and the SPIRE server.
Last, it deletes the token copy in `external-secrets`, ClusterSecretStore `poc-secrets` and its CRD.
A run on a migrated cluster only checks and cleans up.
On a failure after the annotation, the task prints the rollback commands.

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
The UI lists only the root Application. The script prints the child Applications first, and the `kubectl` line below lists them again.

```sh
mise run cell:ui
kubectl --context kind-dev-cell-1 -n argocd-apps get applications
kubectl --context kind-dev-cell-1 -n observability-system logs deploy/otel-collector
```

## Remove the cell

```sh
CELL=dev-cell-1 mise run cell:down
mise run harness:down
```

`cell:down` deletes one cluster. `harness:down` deletes all five.
