# Agent Instructions

## Tools

- Run every tool through `mise run <task>` or `mise x -- <tool>`, because `mise.toml` pins the versions.
- Use the kubeconfig context that kind writes, `kind-<cluster>`. Do not write another kubeconfig file.
- CI pins the same mise version as the local install, in `.github/workflows/unit.yml`. Update both together, because an older mise cannot read the `mise.lock` format of a newer one.
- Run Go only through mise. `mise.toml` sets `GOFLAGS=-mod=readonly`, because `vendor/` holds review records, not Go modules.
- Every Docker command uses the PoC VM through `DOCKER_HOST` in `mise.toml`. Do not change the Docker context.

## Commands

| Task | Command |
| --- | --- |
| Start or stop the Colima VM | `mise run vm:up`, `mise run vm:down` |
| Create `management`, `dev-cp` and `rogue`, build the images, set up each cluster with components, and create the two cells through the portal (see README "Provisioning") | `mise run harness:up` |
| Report whether the PoC is healthy: one JSON object for each cluster (see README "Operator status and logs") | `mise run harness:status` |
| Run `cell:verify` on every cluster with components | `mise run harness:verify` |
| Print the JSON logs of pods by label selector, with a `cluster` field | `mise run harness:logs all app.kubernetes.io/name=otel-uplink` |
| Build the in-cluster images and record their digests in `build/images.env` | `mise run images` |
| Delete all five clusters | `mise run harness:down` |
| Set up one cell (`CELL` defaults to `dev-cell-1`) | `CELL=management mise run cell:up` |
| Check the cell | `mise run cell:verify` |
| Restart `celld` in a cell, or the SPIRE server in `dev-cp` or `management` | `CELL=dev-cp mise run cell:restart` |
| Start the sidecars of a cluster again, so each has the cell name as its cluster ID (see README "Collectors and uplinks") | `CELL=dev-cell-1 mise run cell:restart-mesh` |
| Run the link phase of `management`: the central Argo CD view (see README "Central Argo CD view") | `mise run cell:link` |
| Central read-only Argo CD UI on 127.0.0.1:8090 | `mise run view:ui` |
| Read-only Kiali mesh view on 127.0.0.1:20001/kiali (see README "Mesh view") | `mise run mesh:ui` |
| Show the tunnel of each cell, the tunnel pods and Kiali | `mise run mesh:status` |
| New view keys and central Redis password, then restarts | `mise run view:rotate-keys` |
| Grafana of `management` on 127.0.0.1:3300, and its admin password (see README "Telemetry store") | `mise run obs:ui`, `mise run obs:password` |
| New Grafana admin password, through the Grafana API and Secret `grafana-admin` | `mise run obs:rotate-password` |
| Report each hop of the telemetry path of one cluster, and the first failing hop (see README "Collectors and uplinks") | `mise run obs:uplink-status dev-cell-1` |
| Render bundles only | `mise run cell:hydrate` |
| Push bundles after a change | `mise run cell:hydrate && mise run cell:publish` |
| Argo CD UI on localhost:8080 | `mise run cell:ui` |
| Remove what the `cell:ui` server wrote into `argocd` | `mise run cell:ui:clean` |
| Delete the cell | `mise run cell:down` |
| Fetch upstream files for review | `mise run vendor:fetch` |
| Connect the External Secrets Operator to the secret manager (see README "Keys"; `CELL` defaults to `dev-cp` here) | `mise run secrets:connect` |
| Replace the intermediate CA of the SPIRE server (see README "Keys") | `mise run pki:rotate-intermediate` |
| Replace the CA of the SPIRE server in `management` and refresh every peer copy of its root (see README "Keys") | `mise run mgmt:rotate-ca` |
| Move a live `dev-cp` from the cluster-wide External Secrets Operator to the scoped one | `mise run eso:migrate` |
| Run the Go unit tests | `mise run test`, or `mise run test -- ./internal/topology/...` |
| Check the Go code | `mise run lint` |
| Run the M1 end-to-end gate | `mise run gate:m1` |
| Run the M2 end-to-end gate against the SPIRE server in `dev-cp` | `mise run gate:m2` |
| Run the M3 end-to-end gate against the management plane and `dev-cp` | `mise run gate:m3` |
| Repair the objects and firewall rules that a `gate:m3` run left when it stopped before its cleanups (`--check` only lists them) | `mise run gate:m3:repair` |
| Repair `dev-cp` and `dev-cell-1` after any `gate:m2` run that stopped before its cleanups (usually a few minutes; the README lists the bounds) | `mise run gate:m2:repair` |
| Run the host service on this Mac (see README "Host service and mgmtd"): `start`, `stop`, `restart [--force]`, `status`, `pin`, `sync`, `steps [--reset]`, `log --step <id> [--follow]` or `cancel` | `mise run hostsvc:serve -- status` |
| Ask for a cell, wait for it, withdraw it, ask again, retry or cancel its step (see README "Provisioning"): `request`, `wait`, `withdraw`, `recreate`, `retry`, `cancel` | `mise run portal -- request --cell dev-cell-1 --wait` |
| Run `mgmtd ctl` in `mgmtd-0`: `status`, `records`, `pubkey`, `keys`, `keycheck`, `restore`, `rotate-key [--stage|--commit|--emergency]`, `rotate-signing-key [--emergency|--step <name>]` for the overlap rotation of the signing key, with the cell passes and the render of the new key (see README "Rotate the signing key of mgmtd"), or `reset-state` to start `mgmtd` with a fresh state (see README "Recover lost management state") | `mise run mgmt -- status` |
| Run the M4 end-to-end gate (build the images first with `mise run images`) | `mise run gate:m4` |
| Rotate the signing key of `mgmtd` and print the attestation gap. Run it alone, after `gate:m4` | `mise run gate:m4:rotate` |
| Start the host service again, set the replicas of `mgmtd` and `envd` back to 1 (`--check` only reports) | `mise run gate:m4:repair` |
| Run `cellgw ctl` in `cell-gateway-0` of `dev-cp`: `status`, `queue --cell <cell>`, `outbox`, `enqueue` or `inject` (see README "Cell gateway") | `mise run gw -- status` |
| Start the cell gateway with an empty store when its store is lost, corrupt or full (break-glass) | `mise run gw:reset` |
| Run the M5 end-to-end gate (build the images first with `mise run images`) | `mise run gate:m5` |
| Send one operation a minute for 30 minutes and check that each applies once. Run it alone, after `gate:m5` | `mise run gate:m5:soak` |
| Lose the gateway volume with an operation in flight, run `gw:reset` and check the operation. Run it alone, after `gate:m5` | `mise run gate:m5:drill` |
| Repair what `gate:m5` leaves: replicas of the gateway and `celld`, test namespaces `m5-*`, and each `celld` stream (`--check` only reports) | `mise run gate:m5:repair` |
| Run the M6 end-to-end gate: signed steps, the host service and the cell controller (build the images first with `mise run images`) | `mise run gate:m6` |
| Delete both cells and create them again through one portal request. Run it alone, after `gate:m6` | `mise run gate:m6:provision` |
| Repair what `gate:m6` and `gate:m6:provision` leave: the key files, the replicas of the cell controller, recorded steps, test namespaces `m6-*`, and the cells after an interrupted provision run (`--check` only reports) | `mise run gate:m6:repair` |
| Run the M7 end-to-end gate: a malicious cell, interception at each hop and a relay that alters bytes (build the images first) | `mise run gate:m7` |
| Delete the test namespaces `m7-*` of every cluster and wait until they are gone (`--check` only reports) | `mise run gate:m7:repair` |
| Publish and repair the signed bundle sets of a cell or `dev-cp` with `publish`, `get`, `verify`, `cosign` or `repair` (see README "Signed bundle sets") | `mise run bundle -- publish --target dev-cp --wait` |
| Run the M8 end-to-end gate (build the images first; `GATE_M8_LONG=1` adds the long tests) | `mise run gate:m8` |
| Repair what `gate:m8` leaves: test objects, and each target that a test changed. It repairs before it publishes, with `dev-cp` first (`--check` only reports) | `mise run gate:m8:repair` |
| Trace a signed operation (`trace <id>`: its state at `mgmtd` and its gateway queue rows) or close it (`close <id>`) | `mise run ops -- trace <id>` |
| Print CA keys and certificates as PEM (see README "Keys") | `mise run pki -- root` |

## References

| Need | File |
| --- | --- |
| Base cell design and rules | `docs/design/base-cell.md` |
| Layout and workflow | `README.md` |
| Upstream files and their review | `vendor/README.md` |

## Key Conventions

- Add a component as `components/<name>/`, then add it to a component set in `scripts/lib.sh`.
  An Argo CD component goes in a set that `COMPONENTS` takes. A harness component, which stays outside
  Argo CD, goes in a set that `HARNESS_COMPONENTS` takes. `cell:up` applies harness components itself.
  A link component reads live facts of other clusters, goes in a set that `LINK_COMPONENTS` takes, and
  renders and applies in the link phase (`scripts/link.sh`). `CELL_UP_SKIP_LINK=1` skips that phase.
- Every harness and link object carries the label `cell.poc.internal/harness=<component>`.
- A component is a kustomization, or an executable `render.sh` that prints YAML.
- `@CELL_NAME@` and `@CELL_MESH_TRUST_DOMAIN@` in rendered output are replaced by `scripts/hydrate.sh`.
- Extra Application fields for a component go in `components/<name>/application.yaml`.
- Each new rule in the design gets a check in `scripts/verify.sh`.
- Pin every image by digest.
- Review third-party files before they run, and record the result in `vendor/README.md`.
- `build/` is generated. Do not edit it or commit it.

Cell settings come from `cells/common.env` and `cells/<cluster>.env` alone. `scripts/lib.sh` drops every variable that a cell env file defines before it sources them, so an override in the shell, for example `SPIRE_SVID_TTL=1m CELL=dev-cp mise run cell:up`, has no effect. Edit the file instead.
