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
   mise run harness:status
   ```

Step 5 of [Keys](#keys), `secrets:connect`, needs the cluster, so it comes during or after `harness:up`.

The `telemetry` value of `harness:status` can read bad for up to 5 minutes after a start or a restart.
The collectors log export errors until the gateway exists, and `obs:uplink-status` counts the errors of the last 5 minutes.
The task then exits with status 1 and says to wait. Run it again after 5 minutes.

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
`harness:up` sets up `management` first with `CELL_UP_SKIP_LINK=1`.
It runs `CELL=management LINK_ONLY=mgmt-api mise run cell:link` after `management`, and again after `dev-cp`.
The second run adds the `dev-cp` root, so `mgmtd` admits `envd`.
The full `CELL=management mise run cell:link` runs after the cells.
Harness components stay outside every Argo CD Application. A bundle can still write to their namespace, as the residual limits in `docs/design/poc-scope.md` say.
`cell:verify` runs the checks of one cluster and prints PASS or FAIL for each.
`harness:verify` runs `cell:verify` on each cluster with components, and prints one line for each cluster at the end.
`harness:status` answers the wider question "is the PoC healthy". [Operator status and logs](#operator-status-and-logs) describes it.

`harness:up` stops at the first cluster that fails, so a failure in `dev-cp` also stops the cells.
It then prints the commands for the remaining clusters. Fix the cause, and run them in topology order:

```sh
CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up
CELL=management LINK_ONLY=mgmt-api mise run cell:link
CELL=dev-cp mise run cell:up
CELL=management LINK_ONLY=mgmt-api mise run cell:link
CELL=dev-cell-1 mise run cell:up
CELL=dev-cell-2 mise run cell:up
CELL=management mise run cell:link
```

`mgmtd` signs the records of the cells, and `envd` delivers them to `dev-cp`.
A `cell:up` of `dev-cp` leaves the records and the server config unchanged.

The `CELL` variable picks the cluster for the `cell:*` tasks. The default is `dev-cell-1`.
An unknown name fails with a list of the known cells. For example, `CELL=dev-cell-1 mise run cell:up` sets up `dev-cell-1` only.
`cell:up` of `management` also runs its link phase, which needs `dev-cp` and each cell of `VIEW_CELLS`.
When one of them is missing, `cell:up` stops before its first apply and prints the command.
To set up the base cell of `management` alone, run `CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up`.

## Rebuild one cluster

A rebuilt cluster can get a new node address from Docker, and a rebuilt cell gets a new service account key.
Renders read both facts once, so the other clusters keep the old values until they render again.
`cell:verify` compares the deployed values with the host service, and it prints the command to run when they differ.

Renders copy values from other clusters, so a rebuild needs these commands in this order.
The table also covers a new root that no one planned. For a planned change of the root of `management`, run `mise run mgmt:rotate-ca`, which keeps the old and the new root side by side.


| Rebuilt cluster | Then run | Reason |
| --- | --- | --- |
| `management` | `mise run hostsvc -- up --only management`, `CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up`, `CELL=management LINK_ONLY=mgmt-api mise run cell:link`, `CELL=dev-cp mise run cell:up`, `cell:up` for each cell, `CELL=management mise run cell:link` | The relay targets the node address of `management`. The uplinks and the cells hold its root. `dev-cp` reads the signing key of `mgmtd`, so `mgmt-api` links before it. |
| `dev-cp` | `CELL=dev-cp mise run cell:up`, `CELL=management LINK_ONLY=mgmt-api mise run cell:link`, `cell:up` and `cell:restart` for each cell, then `CELL=management mise run cell:link` | The cells and the link phase hold the node address of `dev-cp`. `mgmtd` admits `envd` by that address and by the root of `dev-cp`, so `mgmt-api` links before the cells. |
| a cell | `CELL=dev-cp mise run cell:up`, `CELL=<cell> mise run cell:up` | The relay, the gateway and the SPIRE node port admit the node addresses of the cells. A rebuilt cell binds with a new key, and `mgmtd` publishes its record to the registries of the views. |
| the host service restarts, or the root of `management` changes | `mise run hostsvc:serve -- restart` | The service makes a new TLS key at each start. It trusts only the root that it read at start. The command links `mgmt-api` again. |

A restart of the SPIRE server in `management` keeps its root, because the CA key stays on the data volume. It needs none of these commands.
A new data volume in `management` makes a new root, so treat it as a rebuild of `management`.
`mise run harness:status` lists each copy that is out of date, and `cell:verify` prints the command for it.

To rebuild a cell, for example `dev-cell-1`, create the cluster first.
Then `mgmtd` binds the new cell and signs its record, and `envd` delivers the record before the agent attests:

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
CELL=management LINK_ONLY=mgmt-api mise run cell:link
CELL=dev-cell-1 mise run cell:up
CELL=dev-cell-2 mise run cell:up
CELL=dev-cell-1 mise run cell:restart
CELL=dev-cell-2 mise run cell:restart
CELL=management mise run cell:link
mise run harness:status
```

The last `cell:link` copies the new `dev-cp` root and node address into the central view.

`CELL=dev-cp mise run cell:restart` restarts the SPIRE server, which then signs a new CA through the intermediate.
The server keeps its datastore, so the agents keep their identities.
On 2026-11-09 the new server pod was Ready about 2 seconds after the old pod stopped. No agent of a cell restarted.
A `cell:restart` of `dev-cp` took 3 seconds from the delete to a Ready new pod. The agents of both cells ran on for 75 seconds after it with no restart, longer than one SVID lifetime.

## Host service and mgmtd

The host service runs on this Mac.
It answers the key requests of `mgmtd` on `127.0.0.1:17443`.
Pods reach it at the address that `host.docker.internal` has in the node container of `management`.

The service accepts one client.
The client must present the SVID `spiffe://mgmt.poc.internal/api` that chains to the live root of `management`.
The service makes a new certificate at each start.
`mgmtd` trusts only the certificate in ConfigMap `hostsvc-pin`.

```sh
mise run hostsvc:serve -- start
mise run hostsvc:serve -- status
mise run hostsvc:serve -- restart
mise run hostsvc:serve -- stop
```

`start` fetches the live root of `management` and writes it to `build/hostsvc/mgmt-root.crt`.
It builds `build/bin/hostsvc` and runs it in the background.
The pid file is `build/hostsvc/serve.pid`, and the log is `build/hostsvc/serve.log`.
`start` fails when another process holds the port.
`restart` stops the service, starts it, and links `mgmt-api` again, so `mgmtd` gets the new pin.
`stop` ends only a process with the command line `build/bin/hostsvc serve`.
A logout or a reboot of the Mac stops the service.
The service runs in its own process group, so a Ctrl-C of the task that started it leaves it running.
`harness:down` stops it last.

`mgmtd` runs in namespace `mgmt-system` as StatefulSet `mgmtd`.
The link component `mgmt-api` renders it.
Run the first pass before `dev-cp` exists, and run the link again after the `cell:up` of `dev-cp`:

```sh
mise run images -- mgmtd
CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up
CELL=management LINK_ONLY=mgmt-api mise run cell:link
```

`LINK_ONLY` makes `cell:link` handle one link component and skip the checks of the other clusters.
A link run that stops prints one command for the failed component and for each later one.
`mise run images -- mgmtd` builds one image and changes only its line in `build/images.env`.
`cell:restart` of `management` also restarts `mgmtd`.

Use `mise run mgmt -- status` to read the state of `mgmtd`.
The other arguments are `records`, `pubkey`, `keys --cell <cell>`, `keycheck --cell <cell>`, `restore` and `rotate-key [--stage|--commit|--emergency]`.
`rotate-signing-key` is the argument that also renders the new key. See "Rotate the signing key of mgmtd".
`reset-state` starts `mgmtd` with a fresh state. See "Recover lost management state".
The command prints one JSON line.
When `mgmtd-0` is absent or not Ready, it prints one JSON error line with the link command.
When `kubectl exec` fails and prints nothing, it prints one JSON error line with the exit code.

`cell:verify` of `management` checks the host service copies.
The checks cover the pin, the root, the host address, the `dev-cp` node address, ConfigMap `peer-root` and ConfigMap `mgmt-signing-pub`.
Each failed check prints the command that repairs it.
`mise run gate:m4:repair` starts the host service again and sets the replicas of `mgmtd` and `envd` back to 1.
It also serves the latest spec again, deletes the test namespaces and probe objects of `gate:m4`, and runs `gate:m2:repair`.
With `--check`, it only reports.
`mise run gate:m4` runs the M4 end-to-end tests. Run `mise run images` first.
`mise run gate:m4:rotate` rotates the signing key and prints the attestation gap. Run it alone, after `gate:m4`.
`mise run mgmt:rotate-ca` restarts the host service in both refresh steps.

## Signed records and envd

`mgmtd` signs the spec and the record of each cell. `envd` delivers them to the SPIRE server of `dev-cp`.
`envd` runs in namespace `envd-system` of `dev-cp`, as the harness component `envd`.
It pulls the signed spec from the API of `mgmtd` on node port 31446, and verifies it under the key in ConfigMap `mgmt-spec-key`.
Then it writes the spec and the records to ConfigMap `cell-records` in `spire-system`.
Its Role allows `create` on ConfigMaps, and `get` and `update` on `cell-records` only.

The SPIRE server of `dev-cp` trusts only the key of `mgmtd` in `record_public_keys`.
The pod mounts `cell-records` as an optional volume.
The `cluster_jwt` plugin reloads the records every 10 seconds, and it keeps its marks in `/run/spire/data/cluster_jwt-marks.json`.
Until `envd` writes the ConfigMap, no new agent can attest.
Agents that already run still renew their SVIDs.

The bind listener of the cell gateway in `dev-cp` takes the bind requests of the cells on node port 30451.
`celld` reaches the gateway on node ports 30450 (stream) and 30451 (bind) of `dev-cp`, and trusts it through ConfigMap `spire-trust-bundle`.
ConfigMap `mgmt-op-key` in `cell-identity-system` holds the signing key of `mgmtd`, and `celld` applies only operations that this key signed.
`celld` reads both ConfigMaps only at start, so each one has a checksum annotation on the pod template, and a new key restarts the pod.

`cell:up` of a cell runs `scripts/attest-wait.sh` for `cell-identity`.
The script waits for four stages in turn:

| Stage | Meaning | Limit |
| --- | --- | --- |
| `bound` | `mise run mgmt -- status` shows the cell as bound, with the key IDs that the cell publishes now | 120 s |
| `applied` | `cell-records` holds the revision of the record of the cell | 60 s |
| `reloaded` | The server log shows the record of the cell at that revision or a later one | 150 s |
| `ready` | The rollout of `celld` finishes | 300 s |

The `reloaded` stage reads the server log since the last record change. A log that has rotated away makes it fail.
A stage that fails prints its name, the reason and the next command.
When the `bound` stage fails, the script prints two causes.
The first is the last bind refusal of the gateway for the cell, from `mise run gw -- status`.
The second is the last refusal of `mgmtd` for the cell.
After a new `source_mismatch` or `cell_unknown` from the gateway, it prints `CELL=dev-cp mise run cell:up` first.
The gateway admits a cell only by its node address.
When `mise run mgmt -- status` does not answer, the script prints `CELL=management LINK_ONLY=mgmt-api mise run cell:link` and does not wait.
When `mgmtd` has no `peer-root` for `dev-cp`, or `envd` logs a TLS refusal, the `applied` failure names the same command first.
At the start of `ready`, the script deletes a `celld` pod once when its `spire-agent` container is in `CrashLoopBackOff`.

`cell:verify` of `dev-cp` checks the key pins, the revision in `cell-records`, the node address of `management` and the envd objects.
`cell:verify` of a cell reads its record in `cell-records`.
A record with other keys than the cell publishes prints `mise run mgmt -- keycheck --cell <cell>`.

## Cell gateway

The cell gateway runs in `dev-cp`, in namespace `gateway-system`, as the harness component `cell-gateway`.
It is the StatefulSet `cell-gateway` with one replica and a SPIRE agent sidecar that attests with `k8s_psat`.
Its SVID is `spiffe://dev.env.poc.internal/cp/gateway`.
The stream listener is on node port 30450, and the bind listener is on node port 30451.
Both admit only the node addresses of the cells.
`envd` reaches the API of the gateway through Service `cell-gateway` on port 8452.
The gateway keeps its queue and its outbox in SQLite on a volume of 256 MiB.

The `cell:up` of `dev-cp` renders the gateway again.
Run it after a rebuilt cell.
After a restart of the VM, rebuild the harness, as the section on restarts says.

Use `mise run gw -- status` to read the state of the gateway.
The command prints one JSON line.
Other commands are `queue --cell <cell>`, `outbox`, `enqueue --cell <cell>` and `inject`.
The last two read standard input.

When the store of the gateway is lost, corrupt or full, run `mise run gw:reset`.
It sets the replicas to 0, waits until the pod is gone, deletes the volume claim `store-cell-gateway-0` and sets the replicas to 1.
When `envd` has a ready replica, it also waits for the first sync of `envd`.
It fails with one JSON error line when the volume claim does not exist.
It prints one JSON line with the old and the new epoch.
Use it only for this case, because the queue starts empty.

### Signed operations in a cell

`celld` keeps one open stream to the gateway, claims each signed operation on it, applies the operation and reports the result.
The only kind in production is `demo.append`.
It adds the line `<operation id> <text>` to ConfigMap `cell-ops-system/demo-log`.
`celld` keeps one ConfigMap `op-<id>` for each operation in the same namespace, with the state `claimed`, `applied` or `reported`.
Namespace `cell-ops-system` holds no pod.
Role `celld-ops` allows `celld` to create, get, list, update and delete ConfigMaps there, and nothing else.
`celld` and `celld` alone write `op-<id>` and `demo-log`, and both carry the label `poc.internal/made-by=celld`.
`cell:verify` and the harness prune leave them alone.

To follow one operation, run these commands:

```sh
mise run mgmt -- op create --cell dev-cell-1 --line "hello"
mise run mgmt -- op get <id>
mise x -- kubectl --context kind-dev-cell-1 -n cell-ops-system get configmap op-<id> -o jsonpath='{.data.record\.json}'
mise run gw -- status
```

To see where an operation stands, run `mise run ops -- trace <id>`.
It prints the operation at `mgmtd`, without its envelopes, and each row of the gateway queue that has the ID.
For an ID that `mgmtd` does not hold, it reads the queue of each cell.
To end an open or expired operation, run `mise run ops -- close <id>`.
`mgmtd` then signs a refusal and the operation is final.

The record becomes `reported` only after `mgmtd` holds the final result `applied`.
`mise run gw -- status` shows the number of open streams of each cell under `streams`.
The gateway allows two streams for each cell, one for each `celld` pod, and refuses a third with `replica_cap`.

Suppose `cell:verify` of a cell reports that `mgmt-op-key` differs from the key of `mgmtd`.
Then run `CELL=<cell> mise run cell:up`.
Suppose `cell:verify` of `dev-cp` reports that a cell has no stream.
Then run `CELL=<cell> mise run cell:up`, and read the log of the `celld` pod.
After a reset of `mgmtd`, run `cell:up` for each cell before the full link.
Each cell holds the old key until then.

`mise run gate:m5:soak` sends one operation to `dev-cell-1` each minute for 30 minutes.
It checks that each operation is applied once, also after the last minute.
It samples the gap between the enqueue and the first record in the cell once for each operation, 30 samples in all.
The gate fails when a sample reaches 15 seconds.
It prints the number of stream failures and of restarts for a new SVID.
Run it alone, after `mise run gate:m5`.

`mise run gate:m5:drill` loses the gateway volume while an operation is in flight.
It stops `celld`, signs an operation, stops `mgmtd` and lets `celld` apply the operation.
It waits until the outbox holds an item of kind `result` with the ID of that operation.
The status items of both cells also fill the outbox, so only that item shows the lost result.
Then it runs `mise run gw:reset` and starts `mgmtd` again.
Afterwards the epoch is higher, the operation is final with `applied` or `already_applied`, and the demo log holds one line for it.
At the end, `mise run harness:status` exits 0.
The drill runs `gw:reset` on purpose.
Run it alone, after `mise run gate:m5`.

After `gate:m5`, `gate:m5:soak` and `gate:m5:drill`, a scan reads the logs of `cellgw`, `envd`, `mgmtd`, `celld` and each `cell-proxy` since the start of the run.
A line with the shape of a signed token (two base64 parts that start with `eyJ`, each followed by a dot) fails the gate.
The scan prints the cluster, pod, container and line number, and never the line.
It cannot read the logs of a pod that a test deleted, or the log of a middle instance of a container that restarted twice.

After each apply, the harness deletes the objects of a component that its render no longer holds.
This covers Deployments, StatefulSets, DaemonSets, Services, ConfigMaps, ServiceAccounts, Roles, RoleBindings, NetworkPolicies, ClusterRoles, ClusterRoleBindings, ValidatingAdmissionPolicies and ValidatingAdmissionPolicyBindings.
The prune stops, and deletes nothing, when it cannot read the render or the render holds no object.
An object with the label `poc.internal/made-by` stays, because a process wrote it at run time.

### Read a refused operation or result

`celld` applies an operation only when the signature, the environment, the cell and the time are right.
It logs each refusal as `operation result` with `outcome`, `reason` and the operation ID.
The reasons are `signature_invalid`, `payload_invalid`, `wrong_target`, `env_mismatch` and `kind_unknown`.
The outcome `expired` means that the operation was late.
`celld` makes no `op-<id>` record and no `demo-log` line for a refused or expired operation.

When the envelope does not verify, `celld` cannot trust the ID in it.
The log line then holds the ID in `peeked_id` and leaves `op_id` empty.
`celld` reports such a refusal with an empty operation ID, and `mgmtd` counts it as `forgedSeen` for the cell.
`mgmtd` also counts a result with a wrong cell or a wrong envelope digest.
Such a result never closes the operation.
Run `mise run mgmt -- status` to read `forgedSeen` and `lastRefusal` of each cell.
`mgmtd` logs one `forged_seen` line for each cell in 5 minutes, so read the counter and not the log.
After a result with an empty operation ID, the gateway holds the queue row for 5 minutes.
The row ends at its 6th claim, about 25 minutes after the first.
To end a held row at once, wait for the operation to expire, then queue its genuine envelope again.
Run `mise run gw -- enqueue --cell <cell> --replay` with the envelope from `op get` on standard input.

`mgmtd` refuses a result item when its proof does not match the exact body of the item.
`lastRefusal` shows `proof_missing`, or `proof_invalid` with the detail `wrong_audience` or `subject_mismatch`.
A token of a key that the record of the cell does not hold gets the answer `retry` with the detail `unknown_kid`.
`mgmtd` then queues one key check for the cell in 60 seconds, and the counter `mgmtd.report.retry_unknown_kid` rises.
A refused report item has no request ID.
The log line `report_refused` holds the kind, the reason and the detail, and `mgmtd` writes one for each such set in 5 minutes.
The field `lastRefusal` of the cell holds the same set with the time.

An operation that no cell applies stays open until it expires.
When `mise run mgmt -- op get <id>` shows the state `expired`, run `mise run mgmt -- op close <id>`.
The command refuses during the 60 seconds of grace after the expiry.

The bind listener of the gateway checks the source address first.
A request whose source is not the node of the named cell gets `source_mismatch` and the status 403.
The gateway log shows `bind_denied` with the request ID that the probe prints.

### An operation does not finish

Run `mise run ops -- trace <id>` first.
It prints the operation at `mgmtd` and each row of the gateway queue that has the ID.
Read the cases in this order:

| What you see | What it means | What to do |
| --- | --- | --- |
| State `open`, no queue row | `envd` has not synced the operation to the gateway | Read `syncedAt` in `mise run gw -- status`, then the log of `envd` |
| Row `queued` with no holder and no claims | The cell has no stream | Run `CELL=<cell> mise run cell:up` and read the log of `celld` |
| Row `leased`, `claims` above 3 | The cell claims the operation again and again | Read the log of `celld` for the reason, then `mise run ops -- close <id>` after the expiry |
| Row `done`, state still `open` | The result is in the outbox or refused by `mgmtd` | Run `mise run gw -- outbox`, then read `lastRefusal` in `mise run mgmt -- status` |
| State `expired` with no final result | No cell applied it in time | Run `mise run ops -- close <id>` |
| An ID with no operation but a queue row | A forged or a replayed envelope | Read `forgedSeen` and `lastRefusal`, and see the section on refused operations |

The outbox of the gateway holds at most 10,000 items and 64 MiB, and each cell at most 2,000 items and 16 MiB.
The gateway counts an item that it cannot keep in `dropped`, and `harness:status` fails for 15 minutes after the last drop.
`celld` keeps each result until `mgmtd` reports it, and sends it again after a new stream, so a dropped result reaches `mgmtd` later.
A lost or full store of the gateway needs `mise run gw:reset`, as the section on the cell gateway says.

## Refused keys, signing key rotation and lost state

### Fix unknown_kid

A new `celld` pod can fail with `unknown_kid` after the API server of its cell gets a new service account key.
The record of the cell then lists only the old keys. `mgmtd` finds the new key on one of these events:

- The SPIRE server refuses a token with `unknown_kid` for a cell that has a record. Its plugin writes a hint into ConfigMap `spire-system/attest-hints`, `envd` carries the hint to `mgmtd`, and `mgmtd` checks the keys of the cell at once. The plugin writes at most one hint for each cell in 60 seconds.
- The cell gateway refuses a hello of `celld` with `unknown_kid`, or `mgmtd` refuses a report with `unknown_kid`. Each one also queues one key check for the cell.
- A new `celld` pod binds with a token from the new key. This happens when a `celld` pod starts in that cell, for example after `CELL=<cell> mise run cell:restart`.
- The periodic key check runs. It runs every 15 minutes for each cell.
- An operator runs a key check.

In the measured runs of 2026-11-14 UTC, `mgmtd` checked the keys 3 to 8 seconds after the first refusal.
The SPIRE server issued a new pod 40 to 112 seconds after it.
Four test runs gave 74, 40, 87 and 79 seconds, and the full `gate:m5` run gave 112 seconds.
Most of that time is the kubelet update of the ConfigMap that the SPIRE server mounts.
If a pod is still refused after 5 minutes, check these in order:

1. `mise run mgmt -- status` shows a `hintAt` and a `lastHintCheck` for the cell. A cell with no `hintAt` got no hint.
2. ConfigMap `spire-system/attest-hints` exists in `dev-cp`. `CELL=dev-cp mise run cell:verify` checks it. `CELL=dev-cp mise run cell:up` makes `envd` create it again.
3. The SPIRE server log shows `hints_configmap_missing` or a failed patch. The Role `spire-server-hints` lets the server read and patch only that ConfigMap.

To check at once, run `mise run mgmt -- keycheck --cell <cell>`.
The answer `keys_updated` means `mgmtd` signed a new record with both key IDs.
`envd` then writes the record, and the SPIRE server reloads it 50 to 60 seconds later in the measured runs.
The answer `rate_limited` means the last check or key update is less than 60 seconds old. Run the command again after 61 seconds.
Other answers are `unchanged`, `not_bound`, `issuer_unavailable`, `issuer_untrusted` and `keys_untrusted`.
`mise run mgmt -- status` shows the key IDs and the last check of each cell.

### Rotate the signing key of mgmtd

Run `mise run mgmt -- rotate-signing-key` to replace the key that `mgmtd` signs with.
The cells trust both keys while they roll, so an operation that `mgmtd` signed under either key still applies.
The command runs these steps in order:

1. It stages a next key with `rotate-key --stage`. `mgmtd` publishes the public half as key `next.pub` in ConfigMap `mgmt-signing-pub`. The signing key does not change.
2. It waits until ConfigMap `mgmt-signing-pub` holds `next.pub`.
3. It runs `cell:up` for each cluster with the `cell-identity` set. ConfigMap `mgmt-op-key` then holds the live key and the staged key, and each `celld` pod restarts with both.
4. It commits with `rotate-key --commit`. `mgmtd` signs the spec, every record and every open operation again at the first counter of the next epoch. Then it publishes the new key as `spec.pub`.
5. It waits until ConfigMap `mgmt-signing-pub` holds the new key.
6. It runs `cell:up` for `dev-cp`, which renders the new key into `envd`, the cell gateway and the SPIRE server. Then it runs `cell:link` for `management`.
7. It runs `cell:up` for each cluster with the `cell-identity` set again. `mgmt-op-key` then holds the new key alone.
8. It waits until the rollout of `celld` has finished in each of those clusters. Then it runs `cell:verify` for `management` and for `dev-cp`.

The steps took 5 minutes 30 seconds in the measured run of 2026-11-15.
The stage took 1 second and the first cell pass 98 seconds. The commit took 1 second, the planes 129 seconds and the second cell pass 96 seconds.
The whole default run took 9 minutes 13 seconds, with the rollout wait and the two `cell:verify` runs.
The command prints one JSON line.
The line holds the SHA-256 fingerprints of the old and the new key, the new epoch and the run time in seconds.
The line holds public key data only.
A failure prints the commands that remain, from the failed step on, as text on standard error and in the JSON error line.
Run them in the printed order.

Between the commit (step 4) and the second cell pass (step 7), `cell:verify` of each cell fails in the check `check_op_key_pinned`.
`mgmt-op-key` then holds the old `op.pub`, which is neither the live key nor a staged key.
This is a planned state. If a person repairs a cell in that window, run `CELL=<cell> mise run cell:up`, which is also the fix.
Do not rotate the signing key while a test runs that rotates a cell key. The servers of `cell-proxy` keep the last good registry from the commit until the link of step 6.

To run one step, use `mise run mgmt -- rotate-signing-key --step stage|cells|commit|planes`.
The step `stage` and the step `commit` include their wait. The step `planes` runs `CELL=dev-cp mise run cell:up` and `CELL=management mise run cell:link`, and no verify.
Each `cell:up` pass takes the replica field of `celld` back, so a pass restores a `celld` that a test set to 0.

For an emergency, run `mise run mgmt -- rotate-signing-key --emergency`.
It makes a new key at once, and it skips the stage and the first cell pass.
`cell:verify` of each cell also fails in `check_op_key_pinned` between the `--emergency` rotation and its cell pass. The same `cell:up` fixes it.
A bare `mise run mgmt -- rotate-key` and `rotate-key --emergency` discard a staged key. The file moves to `ed25519.next.key.stale-<unix>`, and `next.pub` leaves `mgmt-signing-pub`. Only `rotate-key --commit` promotes a staged key.
A cell that has not rolled yet refuses an operation of the new key as `signature_invalid`. The gateway holds that operation for 5 minutes and offers it again. The operation applies after the cell rolls.

Between the restart of the SPIRE server and the first write of `envd` under the new key, the plugin holds no records.
In that time a new pod cannot attest. Agents that already run still renew.
`mise run gate:m4:rotate` measures this time and prints it as `ATTESTATION_GAP_SECONDS`.
The rotation sets the counter back to 1, and it clears the stored history. `restore` then has no older revision to serve.

### Check a bind

`celld` binds its cell to `mgmtd` through the bind listener of the cell gateway when it starts.
It repeats the bind until `mgmtd` holds a record.
Run `mise run mgmt -- status` to read the result. Each entry of `cells` shows `bound`, the issuer, the key IDs and `lastCheck`.
A cell that is not bound has no record, so its new pods cannot attest.
The refusal reasons of a bind are `cell_unknown`, `nonce_invalid`, `token_invalid`, `issuer_untrusted`, `issuer_unavailable`, `keys_untrusted`, `rate_limited` and `restore_active`.
The reason `issuer_untrusted` after a restart of the host service means that `mgmt-api` still holds the old pin. Run `mise run hostsvc:serve -- restart`.
The reason `issuer_unavailable` means that the host service did not answer. Run `mise run hostsvc:serve -- status`.
The reason `keys_untrusted` stays until a bind proves the new key. Run `CELL=<cell> mise run cell:restart`, because the new `celld` pod binds again.
The reason `restore_active` means that `mgmtd` serves an older revision. See "Serve an older revision".
`mise run harness:status` shows the same fields in its `management` object, and it names the next command for each case.
It compares the times of `mgmtd` with the clock of the Mac. After the Mac sleeps, a clock difference of more than 60 seconds can show a false "no report from envd".
In that case, run `mise run harness:status` again after one minute.

### Read a refusal of envd

`envd` refuses a spec that does not verify or that is older than the one it holds.
It logs `spec refused` with a reason, and it reports the refusal to `mgmtd`.
`mise run mgmt -- status` shows it as `lastRefusal`, with the reason, the revision and the time. A failed write shows as `storeError`.
Common reasons:

| Reason | Meaning | Next step |
| --- | --- | --- |
| `signature_invalid` | The spec does not verify under the key that `envd` pins | Render `dev-cp` again: `CELL=dev-cp mise run cell:up`. After a rotation, use `mise run mgmt -- rotate-signing-key` |
| `revision_old` | The spec is older than the revision that `envd` holds | Run `mise run mgmt -- status`. When `restoreActive` is true, run `mise run mgmt -- restore --revision latest`. When `stateBehindApplied` is true, see "Recover lost management state" |
| `spec_invalid` | The spec drops a cell that has a mark and is not retired, or retires a cell below its mark | Read `lastRefusal` and the log of `envd` in `dev-cp` |
| `store_failed`, `state_unverifiable` | `envd` cannot write or verify `cell-records` | Read the log of `envd` in `dev-cp` |

`envd` keeps its last good records after a refusal, so agents that run and new attestations continue.
`mise run harness:status` exits 1 when the refusal is newer than the last applied revision.

### Serve an older revision

`mise run mgmt -- restore --revision <counter>` makes `mgmtd` serve a stored revision of the current epoch.
`envd` refuses it with `revision_old` and keeps its newer records.
While `mgmtd` serves an older revision, `restoreActive` is true and each record change fails with `restore_active`.
Run `mise run mgmt -- restore --revision latest` to end it. `mise run gate:m4:repair` also does this.
A signing key rotation clears the stored history, so no older revision remains after it.

### Attestation gaps

In two gaps, new agents cannot attest. Agents that already run still renew their SVIDs in both.

- From the render of `dev-cp` until each cell binds, the SPIRE server holds no record of that cell. After the bind, `envd` writes the records, and the server reloads them.
  The measured span from the `envd` write to the log line `records reloaded` was 50 and 60 seconds.
  That span covers the kubelet sync of the ConfigMap volume and the reload that runs every 10 seconds.
- In a signing key rotation, the plugin holds no records between the server restart and the first new spec. The measured gaps were 71 and 91 seconds.

`attest-wait.sh` shows which stage of the first gap is slow. A `celld` pod that starts in a gap can restart its agent container until the record lands.

### Check the registry of a view

`mgmtd` publishes ConfigMap `cell-registry` into `central-view-system`, `observability-system` and `mesh-view-system`.
The object carries only the label `poc.internal/made-by=mgmtd`.
`mgmtd` writes it after each change of a record, and checks it again every minute.
Each view server loads the registry every 10 seconds, and refuses a registry that another key signed.
Each view bundle holds ConfigMap `registry-signer` with the key of `mgmtd`, and a Role that lets `mgmtd` write the registry.
After the apply, the link waits up to 60 seconds until the registry lists each cell, and only then does it prune.
If the wait fails, run `CELL=<cell> mise run cell:up` for the cell that the message names, so that its `celld` binds.
Then run `mise run mgmt -- status`, and read the log of `mgmtd-0`.
`cell:verify` of `management` fails when a registry differs from the output of `mise run mgmt -- records`.
A record change reaches the views without a link.

#### One-time step after an upgrade

A harness that ran a render of an older version holds `cell-registry` objects with the field manager `kubectl`.
On that harness, `cell:verify` of `management`, `harness:status` and `gate:m3` (`TestM3StatusHealthy`) fail.
Each failure says that `central-view-system` or `mesh-view-system` holds an object with another field manager.
Delete the three objects once:

```sh
for ns in central-view-system observability-system mesh-view-system; do
  mise x -- kubectl --context kind-management -n "$ns" delete configmap cell-registry
done
```

`mgmtd` creates them again within a minute, and the view servers keep their last good registry meanwhile.
A new harness never needs this step.

### Recover lost management state

`mgmtd` keeps its state and its signing key in two files on its data volume.
When the state file is absent or does not parse, `mgmtd` starts with a new state at epoch 1 and counter 1.
It also makes a new signing key.
In these two cases, run only the two commands that this section lists after the Job steps, and skip `reset-state`.
A file that does not parse moves to `state.json.corrupt-<unix time>` first.
A file that parses but fails validation stays in place. `mgmtd` does not start and logs `state_invalid`.
A state that fails validation needs the move of both files. The image has no shell, so one command does it:

```sh
mise run mgmt -- reset-state
```

The command runs these steps in order:

1. It scales `mgmtd` to 0 and waits until `mgmtd-0` stops.
2. It runs a one-shot Job with the `mgmtd` image.
   The Job renames `state.json` and `ed25519.key` on the volume to `<name>.reset-<unix time>`. It deletes nothing.
3. It deletes the Job and scales `mgmtd` to 1.
4. It waits until `mgmtd-0` is Ready.

The command prints one JSON line with the moved files and the next commands.
A failure in step 2, or an interrupt, scales `mgmtd` back to 1. The Job can move one file before it fails on the other, so the files can be partly moved.
If that happens, `mgmtd` starts with a new state and a new signing key. Run `mise run mgmt -- status` to check.
An invalid `MGMT_RESET_WAIT` prints one JSON error line.
Run the printed commands in this order:

```sh
CELL=dev-cp mise run cell:up
CELL=dev-cell-1 mise run cell:up
CELL=dev-cell-2 mise run cell:up
CELL=management mise run cell:link
```

The command prints one `cell:up` for each cell that `dev-cp` lists in `SPIRE_AGENT_CELLS`.
Each cell holds the old signing key in ConfigMap `mgmt-op-key` until its `cell:up`, and until then `celld` refuses every new operation as `signature_invalid`.

The fresh state starts with a new signing key.
The `dev-cp` render pins that key, so `envd` and the plugin of the SPIRE server both start their marks again.
`dev-cp` then applies the records of the new key, and no rotation is needed.
Each cell binds again on its own, because `celld` repeats its bind until `mgmtd` holds a record.
In the drill, both cells bound again and `harness:status` passed.
Then run `CELL=management mise run cell:verify` and `CELL=dev-cp mise run cell:verify`.

When `mgmtd-0` is not Ready, a `dev-cp` render refuses a `mgmt-signing-pub` key that differs from the key that `dev-cp` pins.
The error prints the command that starts `mgmtd`.
To accept a deliberate change of the key, set `MGMT_KEY_ACCEPT_CHANGE=1` for that `cell:up`.

## Central Argo CD view

The `management` cluster holds one read-only Argo CD UI for both cells, in `central-view-system`.
The link component `central-view` renders it in the link phase, after every other component.
Its render reads the live root and node address of `dev-cp`. It reads the signed record of each cell of `VIEW_CELLS` in `cells/management.env` from `mgmtd`.
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

Each cell runs the harness component `argocd-agent` in the namespace `argocd`.
The agent runs in autonomous mode with `--namespace=argocd`, and sends the child Applications of `argocd` to the principal.
The root Application carries the label `argocd-agent.argoproj-labs.io/ignore-sync`, so the agent does not send it.
The principal stores the Applications in `<env>-<cell>`, and the project as `<env>-<cell>-cell` in `central-view-system`.
The `cell-proxy` sidecar of the agent dials the relay in `dev-cp` on node port 30443, and accepts only the principal ID `spiffe://mgmt.poc.internal/argocd/principal`.
It trusts that ID only through ConfigMap `mgmt-root`, a copy of the live root of `management`.
The agent reads the live objects of the bundle kinds for the view.
`argocd` holds a closed set of Secrets: `argocd-redis`, `argocd-secret` and `bundle-store`.
`argocd-redis` holds the Redis password of the cell, and `argocd-secret` holds the signing key while `cell:ui` runs. `bundle-store` holds no credential.
An admission policy denies every other Secret in `argocd`, and a second policy admits only Applications of the project `cell`.
The agent can list and watch these Secrets, because it does not start without that access, but it cannot get one, and it cannot create, change or delete an Application or a Secret.
The agent in autonomous mode never sends a Secret to the central view, and the resource proxy refuses a Secret read.
The network policies of `argocd` leave the agent pod out. The agent has its own policy: ingress only from the collector, on the metrics port, and egress only to the relay, the SPIRE server, the API server, Redis and the collector.
Only the repo server reaches the bundle store.

The relay in `dev-cp` is the bundle `relay-system` at wave 8.
Deployment `relay-view` passes node ports 30443 and 30445 to node ports 31443 and 31445 of `management`.
Deployment `relay-telemetry` passes node port 30444 to node port 31444.
The relay ends no TLS. It holds at most 256 connections, and 16 from one client address.
The NetworkPolicy admits the node addresses of the cells. Every pod of a cell that no policy limits reaches the relay through its node address, so cell-proxy, and not the network, decides who is a peer.

`cell:verify` of a cell checks the agent objects, its images, the `dev-cp` node address, ConfigMap `mgmt-root` and the stream to the principal.
After a rebuild of `dev-cp` or a new root of `management`, it prints `CELL=<cell> mise run cell:up`.
`cell:verify` of `dev-cp` checks that the relay routes and admit lists use the current node addresses of `management` and the cells. When it fails, run `CELL=dev-cp mise run cell:up`.

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
The principal and `argocd-server` read the view keys from the API at start, and they mount no copy.
A `cell:link` that stopped after `viewkeys` made new keys can leave both pods on the old certificates.
`cell:verify` of `management` compares the start time of each pod with the creation time of the newest view key Secret. When a pod is older, it prints `mise run view:rotate-keys`.

## Telemetry store

The `management` cluster holds one telemetry store in `observability-system`.
It is StatefulSet `lgtm`, the image `grafana/otel-lgtm` with Grafana, Prometheus, Loki and Tempo.
The bundle `observability-store` at wave 8 holds it, and `vendor/README.md` records its review.
The pod runs as user 10001 on a read-only root file system, and it has no route out.
Its data lives on a 10 GiB volume.

The store receives OTLP on port 4317 from two senders only. The pod listens on more ports (3100, 3200, 4040, 4318, and 9090, which also accepts remote write), and the NetworkPolicy admits no pod to any of them:

- The collector `otel-collector` in `management`. It deletes every form of the source attributes at every level that it reaches, then sets `k8s.cluster.name` and `platform.plane` to `management`, and exports to `lgtm`. The section "Collectors and uplinks" gives the details. Its NetworkPolicy admits only `COLLECTOR_SENDERS` of `cells/management.env`, so no other pod can forge the signals of a cell. The gateway sends its own telemetry straight to `lgtm`, and this collector drops each metric whose name, joined to its unit, maps to the alarm series. A sender can still forge that series through a form that the filter does not name.
- The telemetry gateway, the link component `telemetry-gateway`. It runs `cell-proxy` with the `otlp` backend and a SPIRE agent in one pod.
  It accepts SPIFFE mTLS on node port 31444 from the `dev-cp` node only, and its ID is `spiffe://mgmt.poc.internal/telemetry`.
  It admits `spiffe://dev.env.poc.internal/cell/<cell>/otel` for a registered cell, and `spiffe://dev.env.poc.internal/cp/otel`.
  It sets the source attributes of every resource again from the verified ID, and it counts each change in `cellproxy_gateway_attribute_overwrites_total`.
  The node port admits the address of the `dev-cp` node, so every pod of `dev-cp` with egress to the `management` node reaches it. The mTLS check of `cell-proxy` decides who may send.
  The pod opens its listener only after the first connection to the store is ready, and its probe covers that first connection only. A later outage leaves the pod Ready. The metric `cellproxy.gateway.upstream.failures` shows it, and `cell:verify` reads it.

Prometheus accepts samples up to 25 hours old, so a collector queue can drain after a long outage.
Each component keeps 48 hours of data. Prometheus also stops at 3 GB. The volume has a request of 10Gi, but `local-path` enforces no size, so `cell:verify` fails when `/data` of `lgtm-0` holds more than 8 GiB.
Prometheus keeps `platform.plane` and `platform.cell` as labels, and Loki makes the four source attributes index labels.

Grafana has no anonymous access. Its admin password comes from an External Secrets `Password` generator in the cluster, so no secret manager takes part.
Print it, and open Grafana on `http://127.0.0.1:3300`:

```sh
mise run obs:password | pbcopy
mise run obs:ui
```

`OBS_UI_PORT` sets another port. The task prints one JSON line and stops when the port is busy.
While `obs:ui` runs, every pod on the VM, `rogue` included, can reach Grafana through `host.docker.internal`.

Rotate the admin password with one command. It changes the password through the Grafana API, replaces Secret `grafana-admin`, and checks that the new password works and the old one gets 401.
It writes no file, and the new password never reaches the output:

```sh
mise run obs:rotate-password
```

The Secret keeps its value after a restart, because the generator runs only once. A new data volume makes Grafana read the Secret again for its first password.
The task changes the Secret with a merge patch and never uses `kubectl apply`, because a client-side apply copies the password into the annotation `last-applied-configuration`. The same patch removes that annotation. `cell:verify` fails when a Secret of `observability-system` has it.
If the Secret and Grafana differ after a failed rotation, the error line holds the command that sets Grafana to the password of the Secret. Print it with `scripts/obs-rotate-password.sh --restore-command`. `TestM3GrafanaRestoreCommand` runs it.
Grafana blocks the user `admin` for 5 minutes after 5 failed logins, and the block refuses the right password too. `cell:verify`, `obs:rotate-password` and the gate each make one or two failed logins on purpose. When a check shows HTTP 401 after several runs in a row, wait 5 minutes before you suspect a wrong password.

## Collectors and uplinks

Every cluster runs the StatefulSet `otel-collector` in `observability-system`, at wave 3.
It uses the image `otel/opentelemetry-collector-k8s` 0.164.0, pinned by digest, and a volume of 2 GiB for its queue.
The pod has no SPIRE sidecar. Only its collector container mounts a Kubernetes API token, for the receivers below.

The collector has these parts:

- **Receivers:** OTLP on port 4317 (gRPC), the Prometheus receiver, and `k8s_objects` for the Kubernetes events.
  Port 4318 (HTTP) serves the bundle store only. Its NetworkPolicy admits no other pod on 4318.
- **Scrape jobs:** `envoy` (port 15090 of each pod with an `istio-proxy` container), `istiod` (15014), and `argocd`.
  The `argocd` job reads ports 8082 and 8084, and the central server on 8083 in `management`.
  Each cluster adds the jobs in `COLLECTOR_JOBS` of its env file.
  These are `argocd-agent` (8181) in a cell, `spire-server` (9988) in `management` and `dev-cp`, and `argocd-agent-principal` (8000) in `management`.
  Each job copies `pod` and `namespace` into the labels of the data points.
  The metrics ports of the agent (8181), the principal (8000) and the SPIRE server (9988) admit the collector pod only.
  The ports of the Argo CD controller (8082), the repo server (8084), istiod (15014) and Envoy (15090) also admit the node address.
  The policy `allow-from-nodes` admits it on every port.
  The ports of istiod, Envoy in `apps-demo`, the controller and the repo server admit the pods of their own namespace too.
- **Source attributes:** the transform processors delete every form of `k8s.cluster.name`, `platform.plane`, `platform.cell` and `deployment.environment.name`. OTLP data also loses `source_cluster` and `destination_cluster`, but scraped Envoy data keeps them.
  The resource processor then sets the row of its cluster. A pod cannot forge the attributes of another cluster in this collector.
  In `dev-cp` and the cells, the gateway sets the attributes and the two Istio labels again. `management` has no gateway, so its scraped Envoy labels get no second check.
- **Exporter:** one `otlp_grpc` exporter with a timeout of 15 seconds, retries with no end, client keepalive every 30 seconds, and 4 consumers.
  A request has at most 3,000,000 bytes. The gateway refuses a request of more than 1,024 resources, and the exporter then drops the batch.
  The batcher appends resources and counts bytes only. So a request to the gateway has at most 1,000 times the smallest resource of the cluster.
  That bound is 101,000 bytes in `dev-cp` and 129,000 bytes in a cell. `management` exports straight to `lgtm`, which has no resource cap.
  The batcher drops a single record above the bound, and logs it.
  The gateway drops one resource that passes a shape cap of one resource, forwards the others, and reports a partial success.
- **Own metrics:** the collector sends them as OTLP to its own port 4317, so Prometheus holds `otelcol_exporter_queue_size` for every cluster.

| Cluster | `k8s.cluster.name` | `platform.plane` | `deployment.environment.name` | `platform.cell` | Exports to |
| --- | --- | --- | --- | --- | --- |
| `management` | `management` | `management` | absent | absent | `lgtm` |
| `dev-cp` | `dev-cp` | `environment` | `POC_ENV` | absent | the uplink |
| `dev-cell-1`, `dev-cell-2` | the cell | `cell` | `POC_ENV` | the cell | the uplink |

The uplink is the harness component `otel-uplink` in `dev-cp` and in each cell.
It runs `cell-proxy spiffe-client` on port 4319 and a SPIRE agent sidecar. Only the collector of its cluster may reach the port.
In a cell, the uplink has the ID `spiffe://dev.env.poc.internal/cell/<cell>/otel`, a `cluster_jwt` sidecar, and the relay of `dev-cp` on node port 30444 as its upstream. ConfigMap `mgmt-root` holds the roots of `management`.
In `dev-cp`, the uplink has the ID `spiffe://dev.env.poc.internal/cp/otel`, a `k8s_psat` sidecar, and the gateway on the node port 31444 of `management` as its upstream. ConfigMap `peer-root` holds the roots of `management`.
Both uplinks accept only the ID `spiffe://mgmt.poc.internal/telemetry`.
`dev-cp` renders its uplink after the SPIRE server exists, because the sidecar needs the live roots of `dev-cp`.
`cell:verify` compares the node address and the roots in each uplink with the live values. `cell:up` writes them again.

Istio gets the cell name as its cluster name (`global.multiCluster.clusterName`), so `source_cluster` equals the cell.
A sidecar keeps the cluster ID that it had at start. After a change, run the task below for each cluster.
It deletes the pods of every Deployment in the injected namespaces, waits for new Ready pods, and checks `ISTIO_META_CLUSTER_ID` of each `istio-proxy`. It prints one JSON line.
The task deletes pods, because `kubectl rollout restart` writes an annotation that Argo CD then shows as a difference.

```sh
CELL=dev-cell-1 mise run cell:restart-mesh
```

Find the failing hop of a telemetry path with one task. It reads the collector and the uplink in the cluster itself, so the answer does not depend on the path. It reads the gateway counts and the newest sample from management.
It prints one JSON object that names the first failing hop, and it exits with status 1 when a hop fails:

```sh
mise run obs:uplink-status dev-cell-1
```

The queue of a collector is a file on its volume of 2 GiB. `QUEUE_MAX_BYTES` in `components/observability-system/render.sh` bounds each of the three queues at 384 MiB, and `local-path` enforces no size on the claim.
The task reports `queue_file_peak_kib`, the largest size that the queue file reached.
The file shrinks at the start of the collector, and when it is over 100 MiB and its live data falls below 10 MiB.
The value is not the current queue size.
The metric `otelcol_exporter_queue_size` of a cell reaches Prometheus through the same uplink, so it shows the queue only while the path works.

To add a sender of OTLP, add its namespace to `COLLECTOR_SENDERS` in the env file of the cluster, then run `cell:up`.

## Mesh view

The `management` cluster holds one read-only Kiali for both cells, in `mesh-view-system`.
Kiali shows the Istio mesh of each cell, with its namespaces, workloads and traffic graph.
It sees each cell as a separate cluster with its own mesh, and it joins no mesh to another.

The mesh view has these parts:

- Harness component `mesh-view` in each cell, with `cell-proxy` in tunnel mode and a SPIRE agent in the same pod.
  The tunnel dials the relay in `dev-cp` on node port 30445. It accepts only the server ID `spiffe://mgmt.poc.internal/kiali`.
  It serves the requests that come back through the tunnel to the Kubernetes API of the cell, with the token of its own pod.
- Link component `mesh-view-hub` in `management`. The hub is `cell-proxy` with a SPIRE agent.
  It accepts SPIFFE mTLS on node port 31445 from the `dev-cp` node only, and it admits only `spiffe://dev.env.poc.internal/cell/<cell>/mesh-view` for a registered cell.
  For each cell of `MESH_VIEW_CELLS` it opens one plain HTTP port, where only Kiali connects.
- Kiali from the vendored `kiali-server` chart. Kiali reads the Kubernetes API of a cell through the hub port of that cell.
  It reads metrics from `prom-readonly`, a read-only Prometheus proxy in `observability-system`.
  Port 9090 of the store `lgtm` admits only that proxy.

The tunnel allows only reads of the kinds that Kiali shows. The allow-list and the ClusterRole `mesh-view-read` hold the same kinds.
Secrets, logs, `exec`, port forwards and every write get the answer `403 denied` from the tunnel.
The cell Role grants ConfigMaps in `istio-system` only.
Kiali has no log view in this PoC. The tunnel answers `403 denied` to `pods/log` by design, and the feature flag `logs-tab` is off.
Kiali also tries to read the version of each `istiod` through a port forward. The hub refuses it, because the port forward needs a protocol upgrade.
The Kiali log then holds the lines `Failing starting the port forwarding` and `Unable to get version info`, and the page shows no Istio version. This is expected.
Kiali v2.34.1 has no setting that stops this call, so an alert on Kiali errors sees one error line for each cell and minute.
The hub and each tunnel run one replica with the strategy `Recreate`.
The hub reads the registry of cells every 10 seconds, so it refuses a revoked cell at its next connection.
An open tunnel ends at the expiry of the cell leaf.
`mgmtd` publishes the registry, and the hub pod starts again only when the registry signer changes.
The hub passes only the headers `Accept`, `Accept-Encoding`, `Content-Type` and `User-Agent`.
The allow-list of the cell tunnel is the control that limits the requests, and the hub does not repeat it.

The mesh view has these residual limits:

- Code that runs inside the tunnel pod of a cell can use the SVID of that pod. The guard `mesh-view-read-only` limits what its token can write.
- The hub ports are plain HTTP, and Kiali has no SVID. The NetworkPolicy admits only Kiali, but a request through the API server proxy of `management` arrives from a node address, which the policy does not stop.
- The tunnel and `mesh-view-read` read every namespace of a cell, while Kiali reads only `MESH_VIEW_NAMESPACES`.
- `prom-readonly` passes every query expression, because it does not enforce the `query_scope` label. The path is read-only.
- A cell that answers with errors, or not at all, stops the mesh view for every cell, as the next steps describe.
- The login signing key of Kiali is predictable, because it derives from the public root of `management`. No login uses it under the strategy `anonymous`, and the render refuses any other strategy. Kiali can read the key from a Secret, but the External Secrets Operator of `management` serves one namespace only.

Create the mesh view in this order, because Kiali reads its cluster list once at start:

```sh
CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up
CELL=dev-cell-1 mise run cell:up
CELL=dev-cell-2 mise run cell:up
CELL=management mise run cell:link
```

`cell:link` applies the hub first and waits up to 300 seconds until the hub reports the tunnel of each cell up. It reads the state that the hub process serves.
It then applies Kiali. A timeout fails the task and names each cell without a tunnel.
Kiali needs every cell to answer at start, and it has no setting that skips a cluster.
When one cell is absent, Kiali exits with a fatal error at the discovery of that cell (`failed to get server groups: the server is currently unable to handle the request`).
The kubelet starts it again, with a longer wait each time, up to five minutes. The mesh view of the other cell is down too.
Kiali stays up when a cell goes away after it started.
Run `mise run mesh:status` to see which cell, the hub or Kiali is not up. The hub and each tunnel pod serve their own tunnel state on a loopback address, and the task reads it. The state names the cause of the last end of a tunnel: `expiry`, `replaced`, `peer_closed` or `local_close`. A tunnel that the hub replaced with a newer one never reads as down. When the cell is back, Kiali starts within five minutes.
An absent cell takes the mesh view down for every cell. This is a residual limit of the PoC. The fallback is one Kiali for each cell.

Open Kiali on `http://127.0.0.1:20001/kiali`. The page is anonymous and read-only:

```sh
mise run mesh:ui
```

`kubectl port-forward` enters the Kiali pod through the kubelet, so the NetworkPolicy, which admits no pod on port 20001, does not block it.
While `mesh:ui` runs, every pod on the VM can reach the page through `host.docker.internal`. Stop it with Ctrl-C when you are done.

`cell:verify` of a cell checks the tunnel objects, its images, the `dev-cp` node address and ConfigMap `mgmt-root`.
`cell:verify` of `management` also checks the hub listener address, ConfigMap `peer-root` and the tunnel of each cell.
When a tunnel is down, read the state with `mise run mesh:status`. A cell is absent only when its own API does not answer, and then the task names `CELL=<cell> mise run cell:up`. Otherwise the task names `CELL=dev-cp mise run cell:verify`, which finds a left-over firewall rule. `mise run harness:status` names the absent cell in the field `kiali.note`.
For the Prometheus path, run `mise run obs:uplink-status management`.

## Operator status and logs

Run this task to learn whether the PoC is healthy:

```sh
mise run harness:status
```

The task prints one JSON object on each line of standard output, one for each cluster with components, in the order of `harness/topology.yaml`.
The `rogue` cluster has no components, so it has no object. Its health shows as probe failures in `dev-cp`, for example "could not start a probe pod in rogue/default".
Progress lines go to standard error. The exit status is 1 when any value is bad.
The task reads all clusters at the same time. It takes about two minutes, because it runs `cell:verify` on each cluster.
It reads the checks of `cell:verify`, the hops of `obs:uplink-status` and the parts of `mesh:status` from those tasks. Use them for the detail of one part.

Every object has these fields. Later milestones can add fields, but they keep these names:

| Field | Description |
| --- | --- |
| `cluster` | The name of the cluster. |
| `ok` | `true` when every value below is good. |
| `applications` | `total` is the number of Argo CD Applications. `bad` holds one text for each Application that is not Synced and Healthy. |
| `verify` | `ok` is the result of `cell:verify`. `failed` holds the name of each failed check. |
| `telemetry` | `ok` is the result of `obs:uplink-status`. `verdict` names the first hop that fails. `wait` is `true` when the only bad hop is the export of the collector and the store has a fresh sample. This state clears by itself within 5 minutes, and the problem says to wait. |
| `problems` | One sentence for each bad value, with the command to run. |

The object of `management` has these fields too:

| Field | Description |
| --- | --- |
| `agents` | `expected` holds the agent names `<env>-<cell>` of `VIEW_CELLS`. `connected` holds the agents with an open stream to the principal. `missing` holds the others. The task reads the current log of the principal. The kubelet rotates that log after about 10 hours, and the connect line goes with it. An agent with no stream line then counts as connected when the principal logged an event from it in the last 5 minutes. A later line that closes the stream wins. Run `CELL=<cell> mise run cell:verify` for that cell to check its agent. |
| `samples` | The age in seconds of the last Prometheus sample for each `k8s_cluster_name`. |
| `stale_samples` | Each cluster with no sample, or with a sample of 300 seconds or more. |
| `kiali` | `ready` is the state of the Kiali Deployment. `accessible` holds the clusters that Kiali reaches. `missing` holds the cells of `MESH_VIEW_CELLS` that it does not reach. `down_cells` holds the cells without a tunnel at the hub. `absent_cells` holds the cells among them whose own API does not answer. `note` is empty, or says what to do. |
| `mesh` | `ok` is the exit status of `mesh:status`. `lines` holds its output. |

The object of `dev-cp` has the field `gateway`. It holds `epoch`, `epochChangedAt`, `syncedAt`, `outboxItems`, `oldestOutboxAt`, `dropped`, `droppedAt`, `recordOld`, `recordOldAt`, `queued`, `streams`, `mostClaimed`, `lastBindRefusal` and `storeError`.
It holds only `error` when the gateway does not answer.
The `management` object holds `cells`, and each cell has `lastStatusAt`, `unreported`, `oldestUnreportedAt`, `records`, `openOps`, `expiredOps`, `forgedSeen`, `lastRefusal` and `lastHintCheck`.
It also lists `expiredOps`, the operations that expired with no final result, each as `id`, `cell` and `expiredAt`.

`mise run harness:status` exits 1, and prints the next command, in these cases for signed work:

| Case | Command |
| --- | --- |
| The gateway reports a store error | `mise run gw:reset` |
| `envd` synced with the gateway more than 2 minutes ago | Read the log of `envd`, then `CELL=dev-cp mise run cell:up` |
| The oldest outbox item is older than 2 minutes while `mgmtd` answers | `mise run gw -- outbox` |
| The gateway dropped an item in the last 15 minutes | `mise run gw -- outbox` |
| The gateway refused an older record in the last 15 minutes | `CELL=dev-cp mise run cell:up` |
| A bound cell has no stream at the gateway | `CELL=<cell> mise run cell:up` |
| One operation was claimed more than 3 times by one cell | `mise run ops -- trace <id>` |
| A bound cell sent no status in the last 2 minutes | `CELL=<cell> mise run cell:verify` |
| A cell has unreported items older than 5 minutes, or more than 800 records | `CELL=<cell> mise run cell:verify` |
| An operation expired in the last 15 minutes with no final result | `mise run ops -- close <id>` |
| A hint check of a cell is `keys_untrusted`, `issuer_untrusted`, `issuer_unavailable` or `error` | The command in the problem text |

`cell:verify` owns three more checks. `harness:status` includes them in the `verify` field of `dev-cp`. They cover the sync and the store error of the gateway, the record revisions that the gateway holds, and the ConfigMap `attest-hints`.
A failure of one of them shows in `verify.failed`, and its repair command is in `problems`.
The sync case then shows twice, once from `cell:verify` and once from the gateway field.

While a cell is down, Kiali cannot start. It stops during discovery and restarts with longer waits.
It recovers about five minutes after the cell returns.
A cell counts as absent only when its own API does not answer.
In this state, `kiali.ready` is `false` and `kiali.absent_cells` names the cell.
The field `kiali.note` says so and gives the command, for example `CELL=dev-cell-2 mise run cell:up`.
When a tunnel is down and the cell API answers, the cell is not absent. The note then says that the cell has no tunnel at the hub, and points to `mise run mesh:status`.
When every tunnel is down and the cell APIs answer, the note also points to `CELL=dev-cp mise run cell:verify`.
That check names a firewall rule that a stopped gate run left.
The same sentence appears in `problems`.

To read the logs of a hop, run this task with a cluster, or `all`, and a label selector:

```sh
mise run harness:logs all app.kubernetes.io/name=argocd-agent-principal
```

The task prints the JSON log lines of the pods that match, one on each line, with the added fields `cluster`, `namespace`, `pod` and `container`.
A line that is not JSON becomes `{"cluster": ..., "raw": ...}` with the same fields.
A line that already has a `cluster` field keeps its value in `source_cluster`.
A cluster that the task cannot read gives one error line with its name, and the exit status is 1 at the end.
`LOGS_TAIL` sets the number of lines for each container, 200 by default, and `LOGS_SINCE` limits their age, for example `10m`.

Each stream has hops. Read the log of the first hop that fails, from the source to the store:

| Stream | Hop | Cluster | Selector `app.kubernetes.io/name=` |
| --- | --- | --- | --- |
| View | Agent and its `cell-proxy` | cell | `argocd-agent` |
| View | Relay | `dev-cp` | `relay-view` |
| View | `cell-proxy` and principal | `management` | `argocd-agent-principal` |
| Telemetry | Collector | any | `otel-collector` |
| Telemetry | Uplink | cell, `dev-cp` | `otel-uplink` |
| Telemetry | Relay | `dev-cp` | `relay-telemetry` |
| Records | Cell gateway | `dev-cp` | `cell-gateway` |
| Records | Executor of the environment | `dev-cp` | `envd` |
| Telemetry | Gateway | `management` | `telemetry-gateway` |
| Telemetry | Store | `management` | `lgtm` |
| Mesh view | Tunnel pod | cell | `mesh-view` |
| Mesh view | Relay | `dev-cp` | `relay-view` |
| Mesh view | Hub | `management` | `mesh-view-hub` |
| Mesh view | Kiali | `management` | `kiali` |

The `cell-proxy` logs carry a `reason` field when they refuse a peer or a request. The values are:

| Reason | Description |
| --- | --- |
| `peer_untrusted` | The certificate of the peer does not chain to the peer bundle. A copy of a root is old. |
| `peer_not_allowed` | The ID of the peer is not the expected ID, or the registry does not list it. |
| `subject_mismatch` | The token of a request names another agent than the connection. |
| `request_not_allowed` | The request is not one that the backend serves. |
| `upstream_unavailable` | The backend cannot reach its upstream. |
| `overloaded` | The server holds its maximum number of connections. |
| `no_client_cert` | The client sent no certificate, as a probe does. |
| `protocol_not_h2` | The handshake did not agree on HTTP/2. |
| `handshake_failed` | The handshake failed for another reason, for example a timeout. |
| `request_too_large` | The gateway refused an export that is over a size limit of the gateway or of its upstream. |
| `resource_refused` | One resource of an export is over a size limit. The gateway drops it and forwards the other resources. |
| `proof_missing` | A cell source sent no proof, or the proof frame did not arrive in time. The log message is `proof refused`. |
| `proof_invalid` | The proof of a cell source failed a check. The log message is `proof refused`, and the line carries the detail. |

The hub and each tunnel pod also log the end of a tunnel as `tunnel_down` with a `cause`: `expiry`, `replaced`, `peer_closed` or `local_close`.
A tunnel that the hub replaced with a newer one never counts as down.

## Add or remove a cell

A cell is an entry in `harness/topology.yaml` and a file `cells/<cell>.env`.
To add a cell, for example `dev-cell-3`, follow these steps:

1. Add the cluster to `harness/topology.yaml`, with pod and service subnets that overlap no other subnet, and the component sets `base-cell`, `cell-identity`, `argocd-agent`, `otel-uplink` and `mesh-view`.
2. Copy `cells/dev-cell-2.env` to `cells/dev-cell-3.env`. Set `CELL_NAME`, `CELL_MESH_TRUST_DOMAIN`, and a `CELL_BUNDLE_STORE_PORT` that no other cell uses.
3. Add the cell to `SPIRE_AGENT_CELLS` in `cells/dev-cp.env`, and to `VIEW_CELLS` and `MESH_VIEW_CELLS` in `cells/management.env`.
   Give the cell a hub port in `MESH_VIEW_CELLS` that no other cell uses. Add `mesh-view-system` to `COLLECTOR_SENDERS` in the env file of the cell.
   The SPIRE server renders a node alias `cell/<cell>/agents/<role>` and a role entry for each subject of `SPIRE_CELL_SUBJECTS`. `mgmtd` signs the record of the cell when its `celld` binds.
   The relay admits the node address of the cell.
4. Change the cluster count in `TestValidateAcceptsHarnessTopology` of `internal/topology`, which checks the real file.
5. Create the cluster, bind it in `mgmtd`, and set it up:

   ```sh
   mise run hostsvc -- up --only dev-cell-3
   CELL=dev-cp mise run cell:up
   CELL=dev-cell-3 mise run cell:up
   CELL=management mise run cell:link
   mise run harness:status
   ```

`harness:up`, `harness:verify`, `harness:status`, the image check of `gate:m2` and the cell loops of the end-to-end tests read the cells from `harness/topology.yaml`.
The M2 rejection and renewal tests use `dev-cell-1` and `dev-cell-2` by name, because each test gives one of them its own role.

To remove a cell, remove it from `SPIRE_AGENT_CELLS`, `VIEW_CELLS` and `MESH_VIEW_CELLS`.
Then run `CELL=dev-cp mise run cell:up`, which also takes the cell out of the relay admit lists, and `CELL=management mise run cell:link`, which removes the view record of the cell.
The link keeps the agent namespace `<env>-<cell>` in `management`. Delete it with `mise x -- kubectl --context kind-management delete namespace <env>-<cell>`.
Then run `CELL=management mise run cell:verify`, which passes when no object of the cell is left.
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
`harness/versions.env` holds the expected tool versions and the time budgets of `gate:m1`, `gate:m2` and `gate:m3`.
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

A run from clean on 2026-11-13, with the M3 components, took 21 minutes 53 seconds and needed no manual step.
`secrets:connect` ran inside the `dev-cp` step.

| Run | `harness:up` | `management` | `dev-cp` | `dev-cell-1` | `dev-cell-2` |
| --- | --- | --- | --- | --- | --- |
| 2026-11-13 | 21 minutes 53 seconds | 281 s | 231 s | 211 s | 244 s |

The image build took 25 seconds. The rest of the run creates the five clusters and runs the link phase of `management`.
`harness:status` and `harness:verify` passed.
After the run, `gate:m1` took 131 seconds, `gate:m2` took 453 seconds, and `gate:m3` took 2,611 and 2,613 seconds.
A run from clean with the M4 components took about 26 minutes for `harness:up`, plus about 5 minutes of wait for `secrets:connect`.

After the second `gate:m3` run, the five node containers used about 11 GiB of memory in total:

| Container | Memory | CPU |
| --- | --- | --- |
| `management` | 3.7 GiB | 11 percent |
| `dev-cp` | 2.3 GiB | 35 percent |
| `dev-cell-1`, `dev-cell-2` (each) | 2.1 to 2.2 GiB | 13 to 20 percent |
| `rogue` | 0.6 GiB | 4 percent |
| `registry-mirror` | 60 MiB | 0 percent |

The VM reports 11.6 GB of 40 GB in use, and 22 GB more in the file cache.
After the M4 rebuild drill, `management` used 3.5 GiB, `dev-cp` 2.4 GiB, and each cell 2.2 GiB.
The VM then reported 11.7 GB in use.

`gate:m1` prints its elapsed time. It fails when the run takes longer than `GATE_M1_BUDGET_MINUTES`.
The budget is 3 minutes. This is 1.5 times the slowest run of 104 seconds, rounded up to the next minute.
`gate:m1` runs only the clock check of the end-to-end prechecks. The M2 prechecks run for `gate:m2`, and for a direct `go test` run with no `-run` pattern.
`gate:m2` fails when the run takes longer than `GATE_M2_BUDGET_MINUTES`.
The budget is 14 minutes. This is 1.5 times the slowest run, 547 seconds, rounded up to the next minute.
In that run, the cleanup of the key rotation test waited a few minutes for kubelet to start `kube-controller-manager` again.
Many API server restarts in a short time raise that back-off, up to 5 minutes.
Other runs took 312 to 471 seconds.
The M2 key rotation test restarts the API server of `dev-cell-1` twice, and it takes two to three minutes of that time.
`gate:m3` fails when the run takes longer than `GATE_M3_BUDGET_MINUTES`.
The budget is 66 minutes. This is 1.5 times the slower of two runs, 2,613 seconds on 2026-11-13, rounded up to the next minute.
The test timeout of `go test` is twice the budget, with a floor of 30 minutes.
Because of this, the budget check reports a slow run before the timeout ends it.
This gives `gate:m1` and `gate:m2` 30 minutes, and `gate:m3` 132 minutes.
`TestM3StatusHealthy` takes about seven minutes. Earlier tests restart the SPIRE server of `management`, and `obs:uplink-status` counts exporter failures of the last five minutes. `TestM3VerifyDetectsPeerRootDrift` takes about 80 seconds.
The tests of the mesh view add about ten minutes. The tests of the telemetry store add about two minutes. The collector tests add about eight minutes. The rogue telemetry test waits 3 minutes on purpose, and the check of every cluster waits for the signals to arrive. The probes of `TestM3LgtmHardened` and the three dial tests of `TestM3TelemetryNodePortAdmission` run in parallel, and the gateway exports metrics every 10 seconds, to keep that time short.
`gate:m3` writes the events of `go test -json` to `build/gate-m3.json`, and the duration of each test, slowest first, to `build/gate-m3-durations.txt`.
`gate:m4` fails when the run takes longer than `GATE_M4_BUDGET_MINUTES`.
The budget is 40 minutes. This is 1.5 times the slower of two runs, 1,586 seconds on 2026-11-13, rounded up to the next minute.
The test timeout of `gate:m4` is 80 minutes. `TestM4StatusShowsSpec` takes about 2.5 minutes.
Each test that changes a cell record links the three registry components again in its cleanup, and that adds gate time.
It prints the twelve slowest tests at the end.
The slowest tests are the management CA rotation (574 seconds) and the rogue telemetry test (246 seconds).
The rogue test waits 180 seconds on purpose. The fresh-namespace dial tests take 97 seconds.
`gate:m5` fails when the run takes longer than `GATE_M5_BUDGET_MINUTES`.
The budget is 80 minutes. This is 1.5 times the slowest M5 run before the fixes, 3,096 seconds of tests on 2026-11-15 (UTC), rounded up to 5 minutes.
The test timeout is 160 minutes, twice the budget.
`gate:m5:soak` has its own budget of 40 minutes, and `gate:m5:drill` has the floor of 30 minutes for its test timeout.
All times of the next paragraph are wall time in seconds, measured on 2026-11-15 and 2026-11-16 (UTC).
`gate:m1` took 108 seconds, `gate:m2` 490 and 453 seconds, `gate:m3` 2,693 seconds and `gate:m4` 791 seconds.
The other gates took 592 seconds for `gate:m4:rotate` and 1,764 seconds for `gate:m5:soak`.
The gate `gate:m5:drill` took 440 seconds with the wait for the result of X.
The last full `gate:m5` took 2,945 seconds.
Two runs from clean with the M5 components took 1,730 and 1,507 seconds for `harness:up`.
After the second run, the five node containers used about 11 GiB of memory in total:

| Container | Memory | CPU |
| --- | --- | --- |
| `management` | 3.6 GiB | 12 percent |
| `dev-cp` | 2.4 GiB | 15 percent |
| `dev-cell-1`, `dev-cell-2` (each) | 2.0 to 2.2 GiB | 11 to 12 percent |
| `rogue` | 0.6 GiB | 4 percent |
| `registry-mirror` | 51 MiB | 0 percent |

The VM reported 11.3 GB in use and 22 GB in the file cache.
The numbers come from `harness:size` after `gate:m5:drill`.
The rebuild of `management` took 21 minutes 36 seconds from `cell:down` to the first `harness:status` that exited 0. The first `harness:status` failed only on collector export retries, which clear by themselves within 5 minutes.
The slowest M5 tests are the key rotation tests, about 6 to 11 minutes each, and `TestM5DevCPCannotPoseOnReports`, about 6 minutes.
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
  The repair reads the start of the API server from the container runtime on the node.
  It does not read the mirror pods, because their status can still show the old containers.
  It stops a manager or scheduler container that started before the API server, and it reads the Lease holder first.
  Then it waits until each component runs a container that started after the API server and holds a live Lease.
  After a stop, the Lease needs a new holder, because the old process renews its Lease against the new API server before the stop.
- It replaces each pod of `dev-cell-1` that received a token from the test key.
  The repair replaces the pods one at a time, in three ranks.
  The ranks are the node pods (`kindnet`, `kube-proxy` and `istio-cni-node`), `istiod`, and all other pods.
  An app pod waits for a certificate from `istiod`, so an `istiod` with a token of the old key goes before it.
  A Deployment outside the harness and outside Argo CD gets a rollout restart, so `coredns` keeps one ready pod.
  The other pods are deleted, and their controllers create them again.
  While the `kindnet` pod restarts, NetworkPolicy fails open, as the residual limits in `docs/design/poc-scope.md` say.

A run that stops before its cleanups, for example after Ctrl-C, a go test timeout or a closed terminal, can leave these changes in place.
The next `gate:m2` run then stops before its other checks.
`CELL=dev-cp mise run cell:verify` and `CELL=dev-cell-1 mise run cell:verify` fail.
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
New pods of `dev-cell-1` wait while `kube-scheduler` is in kubelet back-off, so the repair waits for its Lease before it replaces pods.
A rollout restart that does not finish in 120 seconds is logged, and the final wait for every workload decides.
After many key switches in a row, the back-off of the controller manager grows. This is a residual limit in `docs/design/poc-scope.md`.
A repair in the cleanup of a test can outlast the `go test` timeout in the worst case.
The next run then stops in its precheck and prints the repair command.
Only one repair runs at a time. A repair holds the lock `build/gate-m2-repair.lock`, and a second repair or a gate precheck refuses to start beside it.
A stopped run can also leave probe objects in `cell-identity-system`, and the next gate run deletes them.
If the precheck reports a missing `celld-token` RoleBinding, run `CELL=<cell> mise run cell:up` for that cell.

## Side effects of gate:m3

`gate:m3` changes the clusters while it runs, and it puts them back before it ends:

- It patches the management copy of the Application `apps-demo` of `dev-cell-1`, with an annotation, a sync operation and a status. The agent refuses each change. A cleanup removes the test annotation and the operation.
- It makes a Role, a RoleBinding, a ClusterRole, a ClusterRoleBinding, a Namespace `view-guard-test` and a ServiceAccount in each cell, for about 10 seconds. Each object has the label `poc.internal/test=view-guard`. The Roles bind to the group `poc:guard-test`, so the real agent never holds them.
- It sends server-side dry runs as the agent ServiceAccount. These make no change. It also mints bound tokens of 10 minutes for the SPIRE audience.
- It replaces the agent Pod of `dev-cell-1`. The new Pod attests again, and the SPIRE server keeps the old agent entry until it prunes it.
- It rotates the view keys of the principal, rotates the CA of the SPIRE server in `management`, and restarts that server. The agents connect again within two minutes.
- It starts test pods in fresh namespaces of every cluster, and it deletes them.
- It rotates the Grafana admin password in `management` once. The Secret `grafana-admin` then holds a new value, and the old value stops working.
- It deletes the `relay-view` pod in `dev-cp` and the Kiali pod in `management`. It scales `mesh-view` to zero in both cells for up to 30 seconds, and then applies the bundle again.
- It changes ConfigMap `mesh-view-system/mgmt-root` in `dev-cell-1` for about 80 seconds, so that `cell:verify` can show the drift. The running tunnel keeps its roots. If a run stops hard, the next start of the tunnel pod fails to verify the hub. Run `mise run gate:m3:repair`, which applies the live roots of `management` again.
- It adds two firewall rules on the `dev-cp` node that drop the packets between the relay and the hub, for up to four minutes in total. The test removes them, and a timer in the node removes them after 120 seconds. If a run stops hard, `mise run cell:verify` of `dev-cp` fails and names the repair. Run `mise run gate:m3:repair`, which also removes these rules.
- It sends test metrics, logs and spans through the telemetry gateway as `dev-cell-1` and `dev-cp`. The store keeps them under unique markers for 48 hours, then each component deletes them.

A run that stops before its cleanups can leave objects with the label `poc.internal/test` in a cell.
`cell:verify` fails on each of them, and on any binding for the agent ServiceAccount or the test group that the render does not hold.
The next `gate:m3` refuses to start. Each of them prints the repair command:

```sh
mise run gate:m3:repair -- --check
mise run gate:m3:repair
```

The repair deletes every object with the label, waits until each one is gone, and is safe to run again.

In normal operation the agent logs one error line for each event of the principal that it cannot apply.
Each line says `cannot patch resource "applications"`, because the Role of the agent has no write verb.
This is the expected answer of RBAC, and it is not a guard denial.
A guard denial names the policy.
To list the denials of the policy, run `mise x -- kubectl --context kind-<cell> -n argocd logs deploy/argocd-agent -c spire-agent | grep argocd-agent-read-only`.
In normal operation this prints nothing.

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

The restart check ran again on 2026-11-15 and 2026-11-16, and the result was the same.
After the second restart, the gateway pod `cell-gateway-0` stayed in `CrashLoopBackOff` for at least 6 minutes, with the error `x509 source from the workload api: context deadline exceeded`.
The gateway epoch could not be read, so the check does not show that the gateway state survives a restart.
Every node had a new address, and the policies of `dev-cp` still held the old addresses.
The last step, `gate:m1`, then found ports 30081 and 30443 to 30445 open on `dev-cp` from `rogue`.
`rogue` held an address that a cell had held before.
The SPIRE server policy admits the cell addresses on port 30081, and the relay policy admits them on ports 30443 to 30445.
The same old addresses also reach two more groups of ports, which the scan did not show because the gateway pod did not run.
The gateway ports 30450 and 30451 admit the old cell addresses in their ingress rules and in the `--cell-node` check.
The policies of `management` admit the old `dev-cp` address on port 8446 and on the view ports 31443 to 31445.
The identity checks still hold.
A pod of `rogue` at an old address reaches only the unauthenticated surface that a pod on a cell node already has.
The real cell, at its new address, is shut out.
The `gate:m1` step is expected to fail after a restart, and a pass does not show that the harness works.
Rebuild with `harness:down` and `harness:up`.
A run of `CELL=dev-cp mise run cell:up` alone does not repair the policies of `management`.

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
| `mgmtd` | StatefulSet `mgmtd` in `mgmt-system` of `management` | `CELL=management LINK_ONLY=mgmt-api mise run cell:link`, after `mise run images -- mgmtd` |
| `envd` | Deployment `envd` in `envd-system` of `dev-cp` | `CELL=dev-cp mise run cell:up`, through the harness apply |

`mise run images` builds every image and records their digests in `build/images.env`.
`cell:verify` fails when a running image differs from that file.
`mise run images` builds without VCS stamps, so a digest changes only when the sources of that image change.
A comment line in `build/images.env` records the commit of the build.
`mise run images -- <name>` keeps that line, unless the names cover every image.
`gate:m1` and `gate:m2` run `mise run images` first.
A new worktree has no build output. Before a live gate, copy `build/images.env` and each `build/<cluster>` directory from the checkout that set up the clusters.
The gate stops at once and prints the copy command when they are absent.
A new worktree also has no `.envrc.local`. Copy it from the same checkout, or set `POC_ENVRC_LOCAL` to its path.
`harness:up` and `secrets:connect` print this fix when the file is absent.
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
It makes one Secret there: `grafana-admin`, from a `Password` generator. The operator can read and write every Secret in that namespace.

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

### Keys of mgmtd and the host service

The signing key of `mgmtd` is an Ed25519 key.
It rests in the file `ed25519.key` on the volume of `mgmtd-0`, with mode 0400.
No Secret holds it, and only `mgmtd-0` mounts the volume. The disk of the VM does not encrypt the file.
`mgmtd` publishes the public key as ConfigMap `mgmt-signing-pub`.
The render of `dev-cp` copies that key into ConfigMap `mgmt-spec-key` for `envd`, and into `record_public_keys` of the SPIRE server.
`cell:verify` checks that the three copies agree.
A restart of `mgmtd-0` keeps the key.
A rebuild of `management` makes a new key and an empty state.
Then `envd` refuses the specs until you render `dev-cp` again, and each cell binds again.
On 2026-11-13 the rebuild drill took 13 minutes from `cell:down` of `management` until both cells were bound.
The last link of the drill ended after 16 minutes.
`mise run mgmt -- rotate-signing-key` replaces the key as a break-glass action. The runbook describes it.

The host service makes a TLS key in memory at each start, and its certificate lives 90 days.
ConfigMap `hostsvc-pin` holds the PEM certificate, and `mgmtd` trusts only that certificate.
`mise run hostsvc:serve -- status` reports `expires_soon` 14 days before the end, and `harness:status` then exits 1.
Run `mise run hostsvc:serve -- restart` to make a new certificate and pin it.

The host service checks its client too.
It accepts only a client with the SVID `spiffe://mgmt.poc.internal/api` that chains to the live root of `management`.
A client with another SVID, another root or no certificate gets a TLS alert.
The service keeps a cache of each key answer for 60 seconds, and it runs at most 2 lookups at once.
After `mgmt:rotate-ca`, the task restarts the service so that it reads the new root.

## Move a live dev-cp to the scoped operator

A `dev-cp` from before the scoped External Secrets Operator runs the cluster-wide operator and ClusterSecretStore `poc-secrets`.
`cell:verify` then fails its store and operator checks.
Run the one migration command, with the settings of `secrets:connect` in place:

```sh
mise run eso:migrate
mise run harness:status
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
The UI lists every Application of the cell.
The local server writes a signing key into `argocd-secret` in the cluster. The script removes the key when you stop the UI. After a killed run, use `mise run cell:ui:clean`.

```sh
mise run cell:ui
kubectl --context kind-dev-cell-1 -n argocd get applications
kubectl --context kind-dev-cell-1 -n observability-system logs statefulset/otel-collector
```

## Remove the cell

```sh
CELL=dev-cell-1 mise run cell:down
mise run harness:down
```

`cell:down` deletes one cluster. `harness:down` deletes all five.
