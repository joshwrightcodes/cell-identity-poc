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

## Go module, tools and CI actions (2026-11-08)

Each item was cloned at the tagged commit into a scratch directory and read. Nothing ran
during the review. The checks above apply, with these results.

| Item | Version | Commit | Result |
| --- | --- | --- | --- |
| `sigs.k8s.io/yaml` | v1.6.0 | `048d724aca2d37ddb5b03c90b5b4550a3a48766d` | No hidden Unicode. No `net`, `net/http` or `os/exec` import outside tests. It depends on `go.yaml.in/yaml/v2` v2.4.2. |
| `go.yaml.in/yaml/v2` | v2.4.2 | not cloned | Indirect module from the YAML fork that Kubernetes maintains. Its module checksum is in `go.sum`. The review did not read its source. |
| `ko` | v0.19.1 | `e388f65a1f036f19703b8aff13e1aa5521bc6988` | No hidden Unicode. `curl` and `sudo` appear only in `pkg/caps/gen.sh`, a developer script that ko does not run. mise pins the binary checksum in `mise.lock`. |
| `go` | 1.27.3 | not cloned | Official toolchain from mise. mise pins the archive checksum in `mise.lock`. The review did not read its source. |
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | No hidden Unicode. `curl` appears only in a developer script under `src/misc`. The workflow sets `persist-credentials: false`. |
| `jdx/mise-action` | v5.2.3 | `82a612c5ab8bcda7cc5db6b7e81a8e7584c3dc6e` | See below. |

`jdx/mise-action` downloads the mise binary from `github.com/jdx/mise` releases, and falls back
to `mise.jdx.dev`. It checks the signed checksums and, from mise 2026.9.3, a signed release
attestation. It runs `chmod`, `tar` and `mv`, and it writes only to the mise data directory,
`GITHUB_ENV` and `GITHUB_PATH`. It does not use `sudo`. It keeps the GitHub token local to the
action by default. The bundled `dist/index.js` has ten zero-width characters inside character
tables of bundled libraries. The review did not rebuild `dist/index.js` from source. v5.2.4 to
v5.2.7 are less than two weeks old as of 2026-11-08.

Base image `gcr.io/distroless/static-debian13:nonroot` is pinned by digest in `.ko.yaml`. The
review did not inspect the image contents.
