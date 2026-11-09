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
| Create all five clusters, build the images and set up each cluster with components | `mise run harness:up` |
| Run `cell:verify` on every cluster with components | `mise run harness:verify` |
| Build the in-cluster images and record their digests in `build/images.env` | `mise run images` |
| Delete all five clusters | `mise run harness:down` |
| Set up one cell (`CELL` defaults to `dev-cell-1`) | `CELL=management mise run cell:up` |
| Check the cell | `mise run cell:verify` |
| Restart `celld` in a cell, or the SPIRE server in `dev-cp` | `CELL=dev-cp mise run cell:restart` |
| Render bundles only | `mise run cell:hydrate` |
| Push bundles after a change | `mise run cell:hydrate && mise run cell:publish` |
| Argo CD UI on localhost:8080 | `mise run cell:ui` |
| Delete the cell | `mise run cell:down` |
| Fetch upstream files for review | `mise run vendor:fetch` |
| Connect the External Secrets Operator to the secret manager (see README "Keys"; `CELL` defaults to `dev-cp` here) | `mise run secrets:connect` |
| Replace the intermediate CA of the SPIRE server (see README "Keys") | `mise run pki:rotate-intermediate` |
| Move a live `dev-cp` from the cluster-wide External Secrets Operator to the scoped one | `mise run eso:migrate` |
| Run the Go unit tests | `mise run test`, or `mise run test -- ./internal/topology/...` |
| Check the Go code | `mise run lint` |
| Run the M1 end-to-end gate | `mise run gate:m1` |
| Run the M2 end-to-end gate against the SPIRE server in `dev-cp` | `mise run gate:m2` |
| Repair `dev-cp` and `dev-cell-1` after any `gate:m2` run that stopped before its cleanups (usually a few minutes; the README lists the bounds) | `mise run gate:m2:repair` |
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
- A component is a kustomization, or an executable `render.sh` that prints YAML.
- `@CELL_NAME@` and `@CELL_MESH_TRUST_DOMAIN@` in rendered output are replaced by `scripts/hydrate.sh`.
- Extra Application fields for a component go in `components/<name>/application.yaml`.
- Each new rule in the design gets a check in `scripts/verify.sh`.
- Pin every image by digest.
- Review third-party files before they run, and record the result in `vendor/README.md`.
- `build/` is generated. Do not edit it or commit it.
