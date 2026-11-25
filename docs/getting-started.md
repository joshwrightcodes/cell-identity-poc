# Get started with the cell identity PoC

This guide takes a clean Mac to the four web UIs of the PoC.
The [README](../README.md) holds the details, and most sections below link to it.

## What the PoC shows

Five kind clusters run in one Colima VM: `management`, `dev-cp`, two cells and a `rogue` cluster.
Each workload proves who it is with a SPIFFE ID from SPIRE, and no cluster holds a copied credential.
The UIs in `management` show the cells, their telemetry and their meshes, and they cannot change a cell.

## What you need

- A Mac with Apple silicon and macOS 26 or later.
- Room for the VM. `mise run vm:up` asks for 14 CPUs, 40 GB of memory and 120 GB of disk.
- git and [mise](https://mise.jdx.dev). mise installs the tools that `mise.toml` pins, Colima and the Docker CLI included.
- direnv, to load `.envrc.local` into your shell. The tasks also read that file without direnv.
- A secret manager with a provider in the External Secrets Operator 2.14.
- A public address for that secret manager on TCP port 443. The operator in `dev-cp` cannot reach private address ranges.
- A command-line client for the secret manager. It reads and writes one value for each remote key.

## Prepare the Mac once

1. Clone the repository. Change to its directory.
2. Run `mise trust`. Then run `mise install`.
3. Create the root CA, the intermediate CA and the root certificate in your secret manager.
   Follow steps 1 to 3 of [Keys](../README.md#keys).
   Keep the root CA bundle where the cluster access token cannot read it.
4. Copy `.envrc.local.example` to `.envrc.local`. Replace each placeholder.
   Git ignores `.envrc.local`.
5. Run `direnv allow`, if you use direnv.

`.envrc.local` holds these values:

| Value | Purpose |
| --- | --- |
| `POC_SECRET_TOKEN_CMD` | Prints the read-only access token that the cluster uses |
| `POC_SECRET_STORE_PROVIDER` | The provider block of SecretStore `poc-secrets`, as JSON |
| `POC_SECRET_READ_CMD`, `POC_SECRET_WRITE_CMD` | Read and write one remote key on the Mac. Give them a write identity, not the cluster access token |
| `POC_OPERATOR_KEY` | The prefix of the remote keys that hold the operator key |
| `POC_ROOT_CA_BUNDLE` | The remote key of the root CA bundle |

## Start the PoC

```sh
mise run harness:up
```

`harness:up` starts the VM with `vm:up` and checks the tool versions.
It then creates `management`, `dev-cp` and `rogue` through the host service, and builds the images.
Then it runs these eight steps in order:

| Step | Command | What it does |
| --- | --- | --- |
| 1 | `CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up` | Prepares the management plane |
| 2 | `CELL=management LINK_ONLY=mgmt-api mise run cell:link` | Starts `mgmtd` |
| 3 | `CELL=dev-cp mise run cell:up` | Prepares the environment control plane and its SPIRE server |
| 4 | `CELL=management LINK_ONLY=mgmt-api mise run cell:link` | Adds the root of `dev-cp` to `mgmtd` |
| 5 | `mise run portal -- request --cell dev-cell-1 --cell dev-cell-2` | Asks for the two cells |
| 6 | `mise run portal -- wait --cell dev-cell-1 --cell dev-cell-2` | Waits until both cells are valid |
| 7 | `CELL=management mise run cell:link` | Creates the central Argo CD view, the telemetry gateway and the mesh view |
| 8 | `mise run bundle -- publish --target dev-cp --target dev-cell-1 --target dev-cell-2 --wait` | Publishes a signed bundle set to each cluster |

Step 3 connects the secret store of `dev-cp` with `POC_SECRET_TOKEN_CMD`.
Without that value, step 3 prints `CELL=dev-cp mise run secrets:connect` once a minute.
Run that command in a second shell.

### The operator key

Step 3 stops when `management` has no operator key.
On a new `management` cluster, this always happens.
The operator key signs local revocations, and each Mac has its own key.
[Operator key](../README.md#operator-key) describes it.

On the first setup on this Mac, create the key:

```sh
mise run operator:create-key
```

After a rebuild on the same Mac, restore the key that the secret manager holds:

```sh
mise run operator:restore-key
```

`operator:restore-key` compares the key with `build/operator/key.env`, and then writes ConfigMap `mgmt-system/operator-pub`.

Next, run the commands that `harness:up` printed when it stopped, in the same order.
These are steps 3 to 8 of the table above.
Run `mise run operator:check-key` after step 4. It prints `"match":true` when every pin holds the key.

### Check the health

```sh
mise run harness:status
```

The task prints one JSON object for each cluster, and exits with status 1 when a value is bad.
The `telemetry` value can read bad for up to 5 minutes after a start. Run the task again after 5 minutes.
[Operator status and logs](../README.md#operator-status-and-logs) describes each field.

## How long it takes

| Part | Time |
| --- | --- |
| Step 1, `management` | 326 seconds on 2026-11-26 |
| Step 3, `dev-cp`, until the stop at the operator key | 330 seconds on 2026-11-26 |
| First run of `harness:up`, until that stop | 835 seconds on 2026-11-26 |
| Clean `harness:up` with both cells, on 2026-11-18 | 1,674 seconds, about 28 minutes. Later milestones added components, so a clean run now takes longer |
| `harness:up` again on a healthy harness | 181 to 214 seconds |
| `harness:status` | About 2 minutes |

[Size and time](../README.md#size-and-time) holds every measurement.

## Open the UIs

Each task below runs until you press Ctrl-C. Run each one in its own shell.
While a task of `management` runs, every pod on the VM can reach its page through `host.docker.internal`.

| UI | Command | Address | Sign-in |
| --- | --- | --- | --- |
| Central Argo CD view | `mise run view:ui` | <http://127.0.0.1:8090> | None. The view is read-only |
| Grafana | `mise run obs:password \| pbcopy`, then `mise run obs:ui` | <http://127.0.0.1:3300> | User `admin`, with the copied password |
| Kiali | `mise run mesh:ui` | <http://127.0.0.1:20001/kiali> | None. The view is read-only |
| Argo CD of one cell | `mise run cell:ui` | <http://localhost:8080> | None |

`cell:ui` serves `dev-cell-1` by default. Run `CELL=dev-cell-2 mise run cell:ui` for the other cell.

### Central Argo CD view

The Applications of each cell appear in the namespaces `dev-dev-cell-1` and `dev-dev-cell-2`.
Each cell agent dials the relay in `dev-cp`, and `management` connects to no cluster.
`cell-proxy` admits an agent only with the SPIFFE ID `spiffe://dev.env.poc.internal/cell/<cell>/argocd-agent`.
The agent accepts only `spiffe://mgmt.poc.internal/argocd/principal`.
A refresh in this UI fails with a permission error, because the view is read-only.
The `agents` field of `harness:status` lists the agents with an open stream.
[Central Argo CD view](../README.md#central-argo-cd-view) gives the details.

### Grafana

Open Explore in Grafana. Choose the Prometheus data source. Run this query:

```promql
sum by (sender_cluster, attribute) (cellproxy_gateway_attribute_overwrites_total)
```

Each cluster sends its telemetry through the telemetry gateway in `management`.
The gateway sets the source attributes from the verified SPIFFE ID of the sender, for example `spiffe://dev.env.poc.internal/cell/dev-cell-1/otel`.
These attributes are `k8s.cluster.name`, `platform.plane`, `platform.cell` and `deployment.environment.name`.
The counter rises only when a sender claims values that differ from its verified ID.
Prometheus keeps `platform_cell` and `platform_plane` as labels. Use them to select one cell or one plane.
[Telemetry store](../README.md#telemetry-store) gives the details.

### Kiali

Kiali shows `dev-cell-1` and `dev-cell-2` as two separate clusters, each with its own mesh.
Each cell opens a tunnel to `management` through the relay in `dev-cp`, with the ID `spiffe://dev.env.poc.internal/cell/<cell>/mesh-view`.
The tunnel accepts only the server ID `spiffe://mgmt.poc.internal/kiali`, and it allows only reads.
The page shows no Istio version, and the Kiali log reports a failed port forward. Both are expected.
Run `mise run mesh:status` to see the state of each tunnel.
[Mesh view](../README.md#mesh-view) gives the details.

### SPIRE server in dev-cp

List the agents that attested to the SPIRE server of `dev-cp`:

```sh
mise x -- kubectl --context kind-dev-cp -n spire-system exec spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server agent list -socketPath /run/spire/sockets/api.sock
```

A cell agent has an ID of the form `spiffe://dev.env.poc.internal/spire/agent/cluster_jwt/<cell>/<pod UID>/<nonce hash>`.
Each attestation gives a new agent ID. Run `entry show` instead of `agent list` to see the workload IDs.

## Stop and rebuild

Delete all five clusters. Then stop the VM:

```sh
mise run harness:down
mise run vm:down
```

The clusters do not survive a restart of the VM or the Mac.
After a restart, start the VM first, because `harness:down` reads the clusters through Docker:

```sh
mise run vm:up
mise run harness:down
mise run harness:up
```

`harness:up` then stops at the operator key. Run `mise run operator:restore-key`.
Then continue as [The operator key](#the-operator-key) describes.
[Restart of the VM](../README.md#restart-of-the-vm) explains why the clusters do not recover.

A Mac sleep of more than about 30 seconds lets the agent SVIDs expire, because their lifetime is 1 minute.
Keep the Mac awake while you use the PoC. [SVID lifetimes and sleep](../README.md#svid-lifetimes-and-sleep) gives the repair steps.

## Problems and fixes

| Message | Cause and fix |
| --- | --- |
| `ConfigMap mgmt-system/operator-pub in management is absent` (step 3) | `management` has no operator key. See [The operator key](#the-operator-key) |
| `mgmt-api render: ConfigMap mgmt-system/operator-pub is absent, so mgmtd adopts no local revocation` (step 2) | Expected on a new `management`. `harness:up` continues, and step 3 then stops at the operator key |
| `mgmtd-0 is not Ready, so the key files and the dev root of the host service stay as they are` (step 2) | Expected on a new `management`. `harness:up` continues, and step 4 runs the same link again |
| `build/operator/key.env exists, so an operator key exists` | This Mac created a key before. Run `mise run operator:restore-key` |
| `build/operator/key.env is absent, so no earlier operator key is known` | This Mac has no key yet. Run `mise run operator:create-key` |
| `Run in a second shell: CELL=dev-cp mise run secrets:connect` | `POC_SECRET_TOKEN_CMD` is not set. Run the command in a second shell |
| `FAIL: <tool> is <version>, expected <version>` | A tool version differs from `harness/versions.env`. Run `mise install` |
| `harness:down` fails with a Docker error after a restart | The VM does not run. Run `mise run vm:up` first |
| `cell_needs_step: cell <cell> has no cluster` | Only the portal creates a cell. Run the portal command in the message |
| `telemetry` is bad in `harness:status` | The collectors retry for up to 5 minutes after a start. Run `harness:status` again after 5 minutes |
