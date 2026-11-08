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

## kind library and its modules (2026-11-08)

The host service imports `sigs.k8s.io/kind` v0.33.0 as a Go library: `pkg/cluster`,
`pkg/apis/config/v1alpha4` and the Docker provider. The review read a scratch clone at the
tagged commit `407a9675e6d9af1200b5f57f9ca52ec6cdacce74` and ran nothing from it.

- No hidden Unicode in `pkg/`. One emoji appears in a comment in `pkg/internal/env/term.go`.
- `net/http` appears only in `pkg/build/nodeimage`, which the host service does not import.
- `os/exec` appears only in `pkg/exec`, the wrapper that all providers use.
- No `sudo`, `curl` or `wget`. No access to credentials. The Docker provider reads the Docker
  CLI proxy settings from `~/.docker/config.json` and the `KIND_EXPERIMENTAL_DOCKER_NETWORK` variable.
- The Docker provider runs the `docker` command line: `docker run`, `inspect`, `network`,
  `ps`, `rm`, `exec`, `logs`, `pull` and `info`. The host service depends on `docker` on `PATH`
  and on `DOCKER_HOST`. mise provides both.
- kind creates containers from the node image, which has a digest pin in `harness/topology.yaml`.
  The review did not inspect the image contents. Node containers run privileged, as kind requires.

The host service reads cluster facts with the Go standard library and the kubeconfig from kind.
It does not use `client-go`.

| Module | Version | Result |
| --- | --- | --- |
| `sigs.k8s.io/kind` | v0.33.0 | See above. |
| `al.essio.dev/pkg/shellescape` | v1.5.1 | Read from the Go module cache, which `go mod verify` checked. No hidden Unicode, no network or process code. |
| `github.com/BurntSushi/toml` | v1.4.0 | Same result. A test runner outside the build uses `os/exec`. |
| `github.com/evanphx/json-patch/v5` | v5.6.0 | Same result. |
| `github.com/pelletier/go-toml` | v1.9.5 | Same result. A code generator outside the build uses `os/exec`. |
| `github.com/pkg/errors` | v0.9.1 | Same result. |
| `github.com/spf13/cobra` | v1.8.0 | Same result. |
| `github.com/spf13/pflag` | v1.0.5 | Same result. It imports `net` only to parse IP flags. |
| `go.yaml.in/yaml/v3` | v3.0.4 | Same result. |
| `golang.org/x/sys` | v0.6.0 | Same result. `execabs` and platform files use process calls, as expected. |
| `github.com/mattn/go-isatty` | v0.0.20 | Same result. |

Base image `gcr.io/distroless/static-debian13:nonroot` is pinned by digest in `.ko.yaml`. The
review did not inspect the image contents.
