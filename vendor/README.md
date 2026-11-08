# Vendored upstream files

This directory holds third-party files that the cell applies. Each file is reviewed before
it is committed. `mise run vendor:fetch` downloads the versions that `cell.env` pins.

| Path | Source | Version |
| --- | --- | --- |
| `argocd/v3.6.1/core-install.yaml` | Argo CD repository, `manifests/core-install.yaml` | v3.6.1 |
| `charts/istio-1.30.8/{base,cni,istiod,gateway}` | `oci://gcr.io/istio-release/charts` | 1.30.8 |

SHA-256 of `argocd/v3.6.1/core-install.yaml`:
`0b38189d6e1fd76ef5c3db10355026c48a02020d82bf21a1a1b5ab16dffe4f3c`

Istio 1.31 releases exist on GitHub, but the chart and image registries had no 1.31 release
as of 2026-11-07. Because of this, the cell uses 1.30.8, the newest release in those registries.

## Review checks

Run these checks on each new version, and record the result here.

- Hidden Unicode: bidirectional controls, zero-width characters and other invisible characters.
- Long encoded strings, and what each one contains.
- External URLs, and any download or shell command in a template.
- `privileged`, `hostNetwork`, `hostPID`, `hostIPC` and `hostPath`.
- ClusterRoles with wildcard verbs or resources.
- Container images and their registries.

## Result for the current versions (2026-11-07)

- No hidden Unicode. One en dash appears in a comment in `istiod/files/grpc-agent.yaml`.
- The only long encoded strings are the SSH host public keys that Argo CD ships for GitHub,
  GitLab, Bitbucket and Azure DevOps.
- URLs are documentation links and the Istio chart repository in chart READMEs. No template
  downloads anything or runs a shell command.
- `istio-cni` uses `hostNetwork` and `hostPath` and runs as root. It installs the CNI plugin on
  each node, so this is expected. It runs in `istio-system`, which has the privileged Pod
  Security level for this reason.
- `privileged: true` appears only in the sidecar template branch for iptables trace logging.
  The cell does not turn on that branch.
- The Argo CD application controller has a ClusterRole with wildcards. A core install needs
  this to manage the whole cluster. Its rules did not change from v3.5.6 to v3.6.1.
- v3.6.1 adds one object compared with v3.5.6: a headless Service for the application controller.
- Images: `quay.io/argoproj/argocd:v3.6.1`, `public.ecr.aws/docker/library/redis:8.10.1-alpine`,
  and Istio images from `registry.istio.io/release`. The review did not inspect image contents.
