# Vendored upstream files

This directory holds third-party files that the cell applies. Each file is reviewed before
it is committed. `mise run vendor:fetch` downloads the versions that `cells/common.env` pins.

| Path | Source | Version |
| --- | --- | --- |
| `argocd/v3.6.1/core-install.yaml` | Argo CD repository, `manifests/core-install.yaml` | v3.6.1 |
| `argocd/v3.6.1/install.yaml` | Argo CD repository, `manifests/install.yaml` (central view only) | v3.6.1 |
| `argocd-agent/v0.10.0/{principal,agent}` | Argo CD Agent tag archive, `install/kubernetes/` | v0.10.0 |
| `charts/istio-1.30.8/{base,cni,istiod,gateway}` | `oci://gcr.io/istio-release/charts` | 1.30.8 |
| `charts/external-secrets-2.14.0/external-secrets` | `oci://ghcr.io/external-secrets/charts/external-secrets` | 2.14.0 |

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

The review cloned each item at the tagged commit into a scratch directory and read it. Nothing ran
during the review. The checks above apply, with these results.

| Item | Version | Commit | Result |
| --- | --- | --- | --- |
| `sigs.k8s.io/yaml` | v1.6.0 | `048d724aca2d37ddb5b03c90b5b4550a3a48766d` | No hidden Unicode. No `net`, `net/http` or `os/exec` import outside tests. It depends on `go.yaml.in/yaml/v2` v2.4.2. |
| `go.yaml.in/yaml/v2` | v2.4.2 | not cloned | Indirect module from the YAML fork that Kubernetes maintains. The review read it in the Go module cache, which `go mod verify` checked. No hidden Unicode: the only non-ASCII characters are curly quotes in a comment in `scannerc.go` and text fixtures in tests. No long encoded strings. The non-test files import no `os`, `net`, `net/http`, `os/exec`, `log`, `syscall` or `unsafe` package, and they contain no `sudo`. The module has no file or environment access, so it has no path to persistence or credentials. Only test files import `os`, `net` and `log`. The module compiles into `hostsvc` and the end-to-end tests. |
| `github.com/go-jose/go-jose/v4` | v4.1.6 | `a0111f82742fa92bceec9ede40845e73319e6230` | Published 2026-10-14, the newest release at least two weeks old. A separate review of this version read `jws.go`, `signing.go`, `jwk.go` and the `jwt` package, and read the project advisories as of 2026-11-08. This entry follows it. A second read of the tagged commit in a scratch clone ran nothing. The module cache matches that clone, and `go mod verify` passes. No hidden Unicode in non-test code: the only non-ASCII characters are in three comments in `json/`. No long encoded strings. The non-test code of the root package, `jwt`, `cipher`, `cryptosigner` and `json` imports no `net`, `net/http`, `os`, `os/exec`, `syscall`, `unsafe`, `plugin` or `log` package. It contains no `sudo` and no environment reads. It has no module dependency outside the standard library, apart from `testutils` in tests. The module has no path to the network, files, persistence or credentials. `internal/clusterjwt` uses it to parse and verify tokens, and restricts the algorithms to RS256 and ES256. The five advisories that v4.1.7 fixes appeared after the cut-off date. The review found none reachable through compact tokens and a key set that the signed record supplies. go-jose accepts a token with no `exp` and skips the audience check for an empty expectation, so `internal/clusterjwt` checks `exp`, `iat` and the audience itself. SPIRE and go-spiffe require v4.1.4, so `go.mod` requires v4.1.6 explicitly. The review did not read `jose-util`, which the PoC does not build. |
| `ko` | v0.19.1 | `e388f65a1f036f19703b8aff13e1aa5521bc6988` | No hidden Unicode. `curl` and `sudo` appear only in `pkg/caps/gen.sh`, a developer script that ko does not run. mise pins the binary checksum in `mise.lock`. |
| `go` | 1.27.3 | not cloned | Official toolchain from mise. mise pins the archive checksum in `mise.lock`. The review did not read its source. |
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | No hidden Unicode. `curl` appears only in a developer script under `src/misc`. The workflow sets `persist-credentials: false`. |
| `jdx/mise-action` | v5.2.3 | `82a612c5ab8bcda7cc5db6b7e81a8e7584c3dc6e` | See below. |

`jdx/mise-action` downloads the mise binary from `github.com/jdx/mise` releases. A pinned
version comes only from GitHub. The action checks the signed checksums and, from mise 2026.9.3, a
signed release attestation. It runs `chmod`, `tar` and `mv`, and it writes only to the mise data
directory, `GITHUB_ENV` and `GITHUB_PATH`. It does not use `sudo`. By default it keeps the GitHub
token local to the action. The file `dist/index.js` contains the libraries of the action, and ten
zero-width characters sit inside character tables of those libraries. The review did not rebuild
`dist/index.js` from source. v5.2.4 to v5.2.7 are less than two weeks old as of 2026-11-08.

The workflow `.github/workflows/unit.yml` sets the `version` input of the action to mise
2026.11.3, released on 2026-11-06. This is an owner exception to the two-week rule: CI pins the
same mise version as the local install. A newer mise writes `mise.lock` in a newer format, and an
older mise cannot read it. Change the local and CI versions together. The action also has a `sha256` input, a checksum of the mise binary for one
platform. The workflow does not set it, because the action already checks the signed checksums of
a pinned version, and the review found no use of that input in `dist/index.js`.

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
| `github.com/inconshreveable/mousetrap` | v1.1.0 | Same result. Two small files: a no-op for non-Windows builds, and a Windows-only check of the parent process (`explorer.exe`) through `syscall`. No network, no `os/exec`. Cobra needs it only on Windows, so it is not in the macOS build. |

The file `.ko.yaml` pins the base image `gcr.io/distroless/static-debian13:nonroot` by digest.
The review did not inspect the image contents.

## Registry image (2026-11-08)

The image `docker.io/library/registry:3.1.2@sha256:38907510915c3f1604c7e83d6ab602ab3020d092f73bdaed8696773693ff768c`
runs as `registry-mirror` on the Mac and as the bundle store in each base cell. The review read the
image configuration and history with `docker image inspect` and `docker history`, and copied
`/entrypoint.sh` and `/etc/distribution/config.yml` out of a container that the review created and never started.

- Base: Alpine 3.24.4 minirootfs. The build adds `ca-certificates` from `apk`.
- The build downloads the `registry` binary from the `distribution/distribution` release `v3.1.2`.
  The build checks a pinned SHA-256 for each architecture, and the digest above pins the result.
- Entrypoint `/entrypoint.sh`, default command `/etc/distribution/config.yml`. The user is not set,
  so the image runs as root by default. `registry-mirror` runs as user 65534 and the bundle store pod sets the same user. Exposed port 5000. Volume `/var/lib/registry`.
- Environment: `PATH` and `OTEL_TRACES_EXPORTER=none`.
- `entrypoint.sh` is eight lines of shell. It prepends `registry serve` or `registry` to the
  arguments and runs `exec`. It has no network call, no `sudo` and no credential access.
- The default configuration stores blobs on the local filesystem and enables delete. It also opens a
  debug listener on port 5001 inside the container, with Prometheus `/metrics` turned on.
  `registry-mirror` and the bundle store set `REGISTRY_HTTP_DEBUG_ADDR` to empty, and `netstat` in each
  container then shows only port 5000.
- Setuid and setgid: `docker run --rm --entrypoint find <image> / -xdev ( -perm -4000 -o -perm -2000 ) -type f`
  printed nothing. The entrypoint override runs only `find`, not the registry.
- Persistence: a shell with the entrypoint overridden checked the usual startup paths. The image has no
  `/etc/init.d`, `/etc/rc.d`, `/etc/cron.d`, `/etc/local.d`, `/etc/conf.d` or `/etc/rc.local`.
  The default Alpine crontab for root exists, but all five `/etc/periodic` directories are empty.
  The entrypoint starts no `crond`.
  The entrypoint runs no `init` and no login shell, so `/etc/inittab` and `/etc/profile.d` take no effect.
  Whether these two paths hold only Alpine defaults is not verified, because no package check ran.
- Volume: `docker image inspect` shows the declared volume `/var/lib/registry`. `internal/hostsvc/registry.go`
  mounts the named volume `registry-mirror-data` at that path. Blobs should persist after a container restart because of this named volume. This is not verified, because no restart test ran.
- The scripts and configuration contain no non-ASCII characters.
- The review did not decompile the `registry` binary, which is 52 MB and owned by root.
- The review did not check that binary against the upstream source tag.
- The review did not read the Alpine packages or any file outside the paths named above.
- The review did not observe the network behaviour of the binary at run time.
- The `registry-mirror` container has no credentials and no authentication. Docker publishes it on
  `127.0.0.1:5001` on the Mac. It also joins the `kind` network, where the nodes pull from
  `http://registry-mirror:5000`. Any pod in any cluster, including `rogue`, can reach it without
  authentication. The default configuration allows deletes, so such a pod can also push to it and
  delete from it.

## Local-path provisioner (2026-11-08)

The image `docker.io/kindest/local-path-provisioner:v20260820-69b56db7` provides the `standard`
StorageClass in every kind cluster. The bundle store uses it for its volume. The provisioner has run in all
five clusters since M0, so this review took place after its first run. The kind node image starts the provisioner at cluster
creation, from the manifest `/kind/manifests/default-storage.yaml`, and the nodes pull the provisioner image.
The review did not run any code from the sources.

- The kind v0.33.0 source holds the image definition in `images/local-path-provisioner`. The `Makefile`
  pins the upstream `rancher/local-path-provisioner` at `v0.0.34`.
  The upstream tag resolves to commit `af49f3fdf69e2e5ad790d295b6005ba3767ec991`.
  The `Dockerfile` builds that tag with the Go toolchain and copies the binary into `gcr.io/distroless/static-debian13`.
  The build also runs `go install github.com/google/go-licenses@latest` in the build stage. The final image does not contain that tool.
- The upstream source has three Go files, `main.go`, `provisioner.go` and `util.go`, with 1778 lines in
  all Go files outside `vendor/`. The files contain no non-ASCII characters.
- The files contain no `net/http` client, no `net.Dial`, no `os/exec` and no `sudo`.
  The only network peer is the Kubernetes API server, through `client-go`.
  The only environment reads are `HOME`, `KUBECONFIG` and the settings that the manifest passes.
- The provisioner creates a short-lived helper pod for each volume setup and teardown.
  The helper pod mounts the parent directory of the volume as a `hostPath` on the node.
  It runs the `setup` and `teardown` scripts from the `local-path-config` ConfigMap.
  The helper image is `docker.io/kindest/local-path-helper:v20260131-7181c60a`.
  The scripts are `mkdir -m 0777 -p "$VOL_DIR"` and `rm -rf "$VOL_DIR"`.
  The helper pod has no `privileged` setting in the provisioner source or in the manifest.
  It runs as the image user, which is root, and it tolerates every taint.
- The provisioner creates each PersistentVolume as a `hostPath` volume under `/var/local-path-provisioner`
  on the node. The directory mode is 0777, so every pod user can write to the volume.
- The RBAC comes from `/kind/manifests/default-storage.yaml` in the node image.
  A Role in `local-path-storage` allows create, update and delete on `pods`.
  A ClusterRole reads nodes, claims, ConfigMaps, pods and pod logs.
  The ClusterRole also manages PersistentVolumes, creates events and reads StorageClasses.
  The account cannot read Secrets.
- The provisioner pod has no `securityContext`, no `privileged` setting and no `hostPath` of its own.
  It mounts only the `local-path-config` ConfigMap.
- The ConfigMap `local-path-config` holds only the node path map, the two scripts and the helper pod template.
- The review did not read the vendored Go modules under `vendor/` in the upstream source.
- The review did not check the published image against a build of the source.
- The review did not observe the network behaviour of the image at run time.
- Result: no obfuscation, hidden Unicode, unexpected network call, `sudo`, persistence or credential
  access. The root helper pod with a node `hostPath` is the main exposure. It is the normal design of this provisioner and
  stays inside the kind node.

## SPIRE v1.15.5 (2026-11-08)

The cell will use SPIRE v1.15.5 with the external plugin `cluster-jwt-server`. The tag is
`v1.15.5` at commit `f62d747d56e9caa6a38ad4bcbc32dbcc3dc1399a`. The SPIRE project published it on 2026-10-20,
so it meets the two-week rule. SPIRE v1.16.0 is too new. The review read a scratch clone and
ran nothing from it.

| Image | Index digest |
| --- | --- |
| `ghcr.io/spiffe/spire-server:1.15.5` | `sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384` |
| `ghcr.io/spiffe/spire-agent:1.15.5` | `sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481` |

Manifests must pin the index digest. Each index also holds attestation manifests for the build.
The server image runs as user 1000 and the agent image runs as root. Both images hold only a CA
bundle, empty directories and one static binary, with no shell and no package manager.
Because of this, a plugin binary must be static and must be readable by user 1000.

The go.mod of the tag pins these versions: go-jose v4.1.4, go-spiffe v2.8.1,
plugin SDK `v1.4.4-0.20260617144146-5dcde407c4d1`, hcl `v1.0.1-vault-7`, go-plugin v1.8.0,
go-hclog v1.6.3 and grpc v1.84.0.

The review read these paths:

- The server API for agent attestation and renewal, and the server NodeAttestor plugin wrapper.
- The code that maps a plugin error to the status that the agent receives.
- The agent attestor and the SVID rotator.
- The rate limit middleware and the server limits.
- The node manager and the datastore queries that prune nodes.
- The external plugin loader, the plugin configuration code and the code that connects host services.
- The `disk` UpstreamAuthority plugin and its documentation.

Findings that the cell relies on:

- The server applies the attestation rate limit first. The default is one attestation each
  second for each source IP, and the limit queues requests. The setting `attestation = false`
  disables it.
- The server does not reject a repeat attestation for an agent ID that exists and is not
  banned. It overwrites the stored certificate. Because of this, the one-time property comes
  from the nonce hash in the agent ID, and not from SPIRE.
- A plugin error reaches the agent with the gRPC code and the message
  `nodeattestor(<plugin name>): <message>`. SPIRE first removes a leading `<plugin name>: ` from
  the plugin message (`pkg/common/plugin/facade.go`). On 2026-11-09 the M2 rejection tests got
  `nodeattestor(cluster_jwt): not_pod_bound` at the client. The server also logs the message. A
  plugin must put no token contents in a message.
- The rotator attests again on every rotation when the agent is re-attestable. The plugin
  returns `can_reattest` as false, so rotation uses `RenewAgent` and needs no new token.
- The server prunes non-reattestable nodes only when `prune_tofu_nodes = true`. It prunes
  about every hour. It never prunes a banned node.
- The loader runs `plugin_cmd` directly, with no search of `PATH`. The setting `plugin_checksum`
  is optional and needs 64 hex characters. The example in the SPIRE documentation shows 40 characters,
  and that value fails the load. SPIRE logs a notice and runs the binary when no checksum is set.
- SPIRE offers server plugins three host services: `identityprovider`, `agentstore` and
  `metrics`. Agent plugins get only `metrics`. The plugin uses none of them.
- Plugin logs written through the SDK logger appear in the SPIRE log.

The review found no obfuscation and no hidden Unicode in `pkg/` and `cmd/`. That search did not
cover files that are not Go source.

The review did not read these items:

- The rest of the SPIRE tree: other plugins, the datastore, federation and the Windows paths.
- The release binaries in the images. The review did not compare them with a source build.
- Image signatures and build attestations.
- The text of the final agent log line for a plugin error. The review confirmed the code
  path by reading, and did not run it.
- The effect on registration entries when pruning removes their parent agent.

### The server image in dev-cp

`components/spire-server` runs the server image by its index digest. The arm64 manifest is
`sha256:567e088a6995705d540a126bc8fdab64a0e3df2dc43153b6d30d97216e2ec259`. The image config for
arm64 has user `1000:1000`, the entrypoint `/opt/spire/bin/spire-server run`, no command and
no exposed port. These facts were read from the registry on 2026-11-08.

The cell depends on these facts from the source:

- The `disk` UpstreamAuthority loads a key in `PRIVATE KEY`, `EC PRIVATE KEY` or `RSA PRIVATE KEY`
  PEM form. It checks that the certificate matches the key.
- With `bundle_file_path`, the plugin verifies the certificate against the bundle with the
  default Go key usage. A CA certificate with no extended key usage passes this check.
- The plugin reads the three files again for each new CA. It keeps the last good copy when a read fails.
- `spire-server healthcheck -socketPath <path>` calls the gRPC health service on the admin socket.
  The probes use it, because the image has no shell. The health listener is off by default.
- go-plugin v1.8.0 creates the plugin socket in the temporary directory. Because of this, the
  server container needs a writable `/tmp` with a read-only root file system.
- The flag `-expandEnv` is off by default, so the server does not expand variables in its config.

## spire-controller-manager v0.8.0 (2026-11-08)

The SPIRE server pod runs spire-controller-manager as a sidecar in static manifest mode. The tag is
`v0.8.0` at commit `d24609e816d4bf0dfaa6383fc4f94b14edb19b1f`, published 2026-09-29. The review
read a scratch clone and ran nothing from it.

| Image | Digest |
| --- | --- |
| `ghcr.io/spiffe/spire-controller-manager:0.8.0` index | `sha256:19e418e9d7f23fe82cbabccdc3e71861590f69a1fa8451bfdb267d7371b2b73e` |
| amd64 manifest | `sha256:191261f33581f44885e0b9851112059ea09a2690760df0b2ad69c9ca118a0d88` |
| arm64 manifest | `sha256:5ebd15e0e166ece42122ecfda968e903dde703b5aff99fdbfaf2e0ead7ebfedd` |

The image runs as user `1000:1000` with the entrypoint `/spire-controller-manager`. Its base is
Debian 13 with only a CA bundle, passwd, group and time zone files. The build history shows one
copied binary. The change log says that 0.8.0 is the first release that runs as user 1000.

The review read `cmd/main.go`, the config types and loader, the ClusterStaticEntry loader, the
entry and federation reconcilers, the SPIRE API client, the config and CRD documents, the static
example and the change log.

Findings that the cell relies on:

- Static mode passes no Kubernetes client to the reconcilers, and it builds the manager from an
  empty REST config. Because of this, it needs no RBAC, ServiceAccount token, webhook or CRD.
- The controller reads every file that ends in `.yaml` in `staticManifestPath`, with no recursion.
  It decodes one object for each file, and it skips other kinds.
- A file that fails to parse stops the reconcile before any delete. A missing directory also stops it.
  An empty directory declares no entries, so the controller deletes every entry with its prefix.
- With `entryIDPrefix: poc`, the controller gives new entries the ID `poc.<uuid>`. It ignores
  every entry outside the prefix.
- With no prefix, the controller deletes every undeclared entry on the server. An empty
  `entryIDPrefixCleanup` deletes every entry with no dot in its ID. The cell sets the prefix
  and leaves the cleanup setting unset.
- Federation relationships have no prefix. The cell turns off their reconciliation, because the
  controller would otherwise delete every relationship on the server.
- With an explicit `reconcile` block, the defaults do not apply. The cell lists all three values.
- Without `clusterDomain`, the controller looks up the default Kubernetes service name in DNS.
  The cell sets `clusterDomain`, so the controller needs no egress.
- The controller requires controller-runtime v0.25.1. With an empty metrics address, that version
  listens on `:8080` (`pkg/metrics/server/server.go`). The cell sets the metrics and health
  addresses to `"0"`, so the sidecar opens no port.
- The program talks only to the SPIRE server socket in static mode. No `net/http` client,
  `os/exec`, `sudo`, credential read, persistence or hidden Unicode appeared in the files above.
- After `staticRun` returns, `main` goes on to the Kubernetes mode. A clean shutdown therefore
  likely ends with an error and a non-zero exit. This comes from the code, not from a run.

API compatibility with SPIRE v1.15.5. The controller requires `spire-api-sdk` v1.15.3 at commit
`adb81b3b0fb87a881693d1d42eaf8b2fa1223e42`. SPIRE v1.15.5 requires the pseudo-version
`v1.2.5-0.20260428072036-00f73a61093a`, commit `00f73a61093a26a3f676563386abdd2218619101` on
the `next` branch. The `proto/` trees of the two commits are identical (`git diff --quiet` on
`proto/`). The tag carries the same two proto changes as cherry-picks. The controller calls only
the entry, trust domain and bundle services of the v1 API. Because of this, the server serves
every message and field that the controller sends.

The review did not read these items:

- The Kubernetes mode: the webhook manager, the ClusterSPIFFEID reconciler and the RBAC manifests.
- The `demo/` tree, the Dockerfile, the Makefile, the test files, and the server handling of
  fields that the controller marks as unsupported.
- The image signature. The review did not compare the binary with a source build or run the image.

Result: low concern. The cell sets the prefix, leaves the cleanup unset, turns off federation
reconciliation and sets `clusterDomain`.

## SPIRE plugin SDK and plugin modules (2026-11-08)

The plugin imports `github.com/spiffe/spire-plugin-sdk` at the exact version that the SPIRE
v1.15.5 go.mod pins: `v1.4.4-0.20260617144146-5dcde407c4d1`. A plugin and the server share one
wire contract only when they use the same version. This version is commit
`5dcde407c4d1a35478487926526db4d26dc5845e` on the `next` branch, dated 2026-06-17. It has no tag.
The repository tags `v1.4.3` to `v1.4.7` and later do not point at this commit. How these tags
relate to the `next` branch is not verified. `go.mod` requires the pseudo-version, and the review
confirmed it against the go.mod of SPIRE at the tag.

The review read these SDK paths: `pluginmain`, `plugintest`, `internal` (serve and handshake),
`private`, `pluginsdk`, the server and agent NodeAttestor protos with their generated stubs,
the config service, the host service protos and `go.mod`.

- The server NodeAttestor service has one stream RPC, `Attest`. The first request holds the
  payload and later requests hold challenge responses. The last response holds the agent
  attributes: ID, selector values and `can_reattest`.
- A service implementation must embed `UnimplementedNodeAttestorServer` by value.
- The SDK calls `SetLogger` on an implementation that has it. Logs then reach the SPIRE log.
- `pluginmain.Serve` runs go-plugin with a magic cookie that equals the plugin type, protocol
  version 1 and gRPC only.
- `plugintest.ServeInBackground` serves the plugin inside the test process through go-plugin
  reattach. It needs a `*testing.T` and dials only an in-process listener.
- Non-test, non-generated SDK code has no `net/http`, `os/exec`, `sudo` or raw network dial.
  The review found no hidden Unicode in `.go` and `.proto` files.
- The SDK requires go-jose v3 for `pluginsdk/support/bundleformat`. The plugin does not import
  that package, so go-jose v3 does not enter the build.

The review did not read the generated `.pb.go` files beyond the stubs above, the test files,
`cmd/protoc-gen-go-spire`, or the Makefile and CI workflow. It did not build the SDK or run its tests.

The plugin also adds these modules to the build. The review searched each version in the Go
module cache, which `go mod verify` checks, and ran nothing from it. The search covered hidden
Unicode, `os/exec`, `sudo` and `net/http` in non-test code.

| Module | Version | Result |
| --- | --- | --- |
| `github.com/hashicorp/hcl` | v1.0.1-vault-7 | Parses the plugin configuration. SPIRE pins the same version. No hidden Unicode. Only `hcl/fmtcmd`, which the build does not import, uses `os/exec`. |
| `github.com/hashicorp/go-plugin` | v1.8.0 (2026-04-29) | Matches the SPIRE pin. It runs a plugin as a child process on the host side. The plugin side only serves gRPC and reads the handshake variables. `client.go` imports `os/exec`, and the plugin never starts a child. No hidden Unicode. |
| `github.com/hashicorp/go-hclog` | v1.6.3 | Matches the SPIRE pin. No hidden Unicode and no process or network code. |
| `github.com/hashicorp/yamux` | v0.1.2 | Stream multiplexer for go-plugin. No hidden Unicode and no process or network code beyond `net.Conn` use. |
| `github.com/oklog/run` | v1.1.0 | Goroutine group helper. No hidden Unicode and no process or network code. |
| `github.com/fatih/color`, `github.com/mattn/go-colorable` | v1.15.0, v0.1.13 | Terminal colour for hclog. No hidden Unicode and no process or network code. |
| `google.golang.org/grpc` | v1.84.0 (2026-09-17) | Matches the SPIRE pin. Only the server side is relevant to the plugin, and the listener is a local socket. `os/exec` appears only in a Windows file and in a test tool that the build does not import. No hidden Unicode. |
| `google.golang.org/protobuf`, `github.com/golang/protobuf` | v1.36.11, v1.5.4 | This row covers the server plugin at the time of its review. The agent build uses a newer protobuf version, described in the Kubernetes client section. `os/exec` appears only in code generators that the build does not import. No hidden Unicode. |
| `golang.org/x/net`, `golang.org/x/text`, `golang.org/x/sys` | v0.57.0 (2026-07-08), v0.40.0 (2026-07-08), v0.47.0 (2026-06-30) | Standard extension modules. `os/exec` appears only in generators and test helpers. The word `sudo` appears once, in a language name table in `x/text`. No hidden Unicode. The upgrade of `x/sys` from v0.6.0 also reaches the other modules that use it. |
| `google.golang.org/genproto/googleapis/rpc` | v0.0.0-20260706201446-f0a921348800 | Generated status types. The review read only its entry in the module list. |

The review compared no module with its upstream repository. Because of this, the result rests
on the module checksums in `go.sum` and on the read of the cache.

## SPIRE API SDK for attestprobe (2026-11-09)

`cmd/attestprobe` calls `AttestAgent` on the SPIRE server, as an agent does. It imports
`github.com/spiffe/spire-api-sdk` at the version that the SPIRE v1.15.5 go.mod pins:
`v1.2.5-0.20260428072036-00f73a61093a`. This is commit `00f73a61093a26a3f676563386abdd2218619101`,
dated 2026-04-28, so it meets the two-week rule. The probe and the server then share one wire contract.

The review read the module cache copy, which `go mod verify` checks, before any test ran. Nothing
ran during the review.

- The module holds 36 Go files. Each file is `protoc-gen-go` or `protoc-gen-go-grpc` output for the
  server and agent APIs and their types. The module has no hand-written Go code.
- The files import only `context`, `reflect`, `sync`, `unsafe`, gRPC, protobuf and the module's own
  `types` package. `unsafe` appears only in the generated descriptor code.
- No file has `os/exec`, `net/http`, a raw network dial or `sudo`. Each `init` function only
  registers the file's message types with the protobuf runtime.
- No file has a non-ASCII character, so the module has no hidden Unicode.
- `go.mod` requires gRPC v1.74.2 and protobuf v1.36.7. The cell already pins newer versions, so the
  module raises no other module.
- The review read `proto/spire/api/server/agent/v1/agent.proto` and the field numbers of the
  `AttestAgent` messages and of `types.X509SVID`.

The probe also uses the go-spiffe package `spiffetls/tlsconfig`, which the celld build does not hold.
The package has three files and imports only `crypto/tls`, `crypto/x509` and other go-spiffe packages.
The client configuration sets `InsecureSkipVerify` and puts a `VerifyPeerCertificate` callback in
its place. The callback verifies the chain against the bundle, and then checks the server ID.

The review did not read the `Makefile`, the CI files or the generated code beyond the agent API.

## Kubernetes client modules (2026-11-08)

The agent plugin requests a service account token through the Kubernetes API. It imports
`k8s.io/client-go`, `k8s.io/api` and `k8s.io/apimachinery` at v0.37.1, which matches Kubernetes
1.37. The tag date is 2026-09-23. Version v0.37.2 is dated 2026-10-28 and is too new.

The plugin uses only the typed core client (`kubernetes/typed/core/v1`) and `rest.InClusterConfig`.
The tests also import the fake clientset and `testing` package. The review searched the packages
in the build of `cmd/cluster-jwt-agent` in the Go module cache. It ran nothing from them. The
search covered 218 packages from the Kubernetes, `sigs.k8s.io`, OpenAPI, YAML and OAuth modules
in the table below, and found no hidden Unicode.

| Finding | Detail |
| --- | --- |
| Network | The client dials the API server only. `rest.InClusterConfig` reads `KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT` and the mounted service account files. The plugin sets no other address. |
| Process start | `client-go/plugin/pkg/client/auth/exec` uses `os/exec` to run a credential helper. The plugin never sets that option, because an in-cluster configuration has none. The code stays in the binary. |
| `sudo` | No match in the searched packages. |
| Credentials | The client reads the pod token file. The plugin never logs a token. |

The build also adds these modules: `go-restful`, `go-openapi/*`, `gnostic-models`,
`kube-openapi`, `json-iterator`, `modern-go/*`, `fxamacker/cbor`, `x448/float16`, `klog`,
`go-logr`, `golang.org/x/oauth2`, `x/term`, `x/time`, `gopkg.in/inf.v0`, `json-patch.v4`,
`structured-merge-diff`, `sigs.k8s.io/json`, `sigs.k8s.io/randfill`, `google/uuid`,
`munnerz/goautoneg` and `go-spew`. They are transitive. The review matched their code only
against the searches above.

Protobuf. The go.mod files of `client-go` v0.37.1 and `apimachinery` v0.37.1 require
`google.golang.org/protobuf` v1.36.12-0.20260120151049-f2248ac996af, so the build uses this version
for the server plugin and the agent plugin. SPIRE v1.15.5 pins v1.36.11, and the earlier rows of
this file describe that version. The commit date is 2026-01-20, which is more than two weeks old.
The tag v1.36.12 exists and is dated 2026-08-10. The tag contains this commit and three later
commits (GitHub compare: ahead by 3, behind by 0). `go.mod` keeps the pseudo-version, because
`client-go` v0.37.1 requires exactly this version. The review compared the module cache copies of
v1.36.11 and this version. Nine non-generated, non-test Go files differ: `protogen`, `protodelim`,
`protojson` (two files), `prototext`, `generate-protos`, `descfmt`, `internal/version` and
`protodesc`. The added lines hold no `os/exec`, `net/http`, `net`, `sudo`, `syscall` or `unsafe`
reference and no hidden Unicode. The review did not read the changed logic line by line, and it
did not review the generated files or tests. A plugin does not need the same protobuf version as
SPIRE, because they share only the wire format. The effect of this difference is not verified.

Release dates from the Go proxy (the `.info` files, read 2026-11-08):

| Module | Version | Date |
| --- | --- | --- |
| `github.com/spf13/pflag` | v1.0.10 | 2025-09-02 |
| `go.yaml.in/yaml/v2` | v2.4.4 | 2026-03-06 |
| `github.com/go-openapi/swag` | v0.27.1 | 2026-07-19 |
| `k8s.io/kube-openapi` | v0.0.0-20260721132016-d427ff9ee9ad | 2026-07-21 |
| `k8s.io/api`, `k8s.io/apimachinery` | v0.37.1 | 2026-09-23 |
| `k8s.io/klog/v2` | v2.140.0 | 2026-03-03 |
| `k8s.io/utils` | v0.0.0-20260626114624-be93311217bd | 2026-06-26 |
| `sigs.k8s.io/structured-merge-diff/v6` | v6.4.2 | 2026-07-07 |
| `sigs.k8s.io/randfill` | v1.0.0 | 2025-03-04 |
| `github.com/emicklei/go-restful/v3` | v3.13.0 | 2025-08-14 |
| `github.com/fxamacker/cbor/v2` | v2.9.1 | 2026-03-30 |
| `github.com/google/gnostic-models` | v0.7.0 | 2025-06-26 |
| `golang.org/x/oauth2`, `x/time` | v0.36.0, v0.15.0 | 2026-02-11 |
| `golang.org/x/term` | v0.45.0 | 2026-07-08 |
| `github.com/go-logr/logr` | v1.4.3 | 2025-05-19 |
| `github.com/google/uuid` | v1.6.0 | 2024-01-23 |
| `gopkg.in/evanphx/json-patch.v4` | v4.13.0 | 2025-01-28 |
| `github.com/json-iterator/go` | v1.1.12 | 2021-09-11 |
| `github.com/x448/float16` | v0.8.4 | 2020-01-17 |
| `k8s.io/client-go` | v0.37.1 | 2026-09-23 |
| `github.com/go-openapi/jsonpointer` | v1.0.0 | 2026-07-07 |
| `github.com/go-openapi/jsonreference` | v1.0.0 | 2026-07-07 |
| `github.com/go-openapi/swag/cmdutils` | v0.27.1 | 2026-07-19 |
| `github.com/go-openapi/swag/conv` | v0.27.1 | 2026-07-19 |
| `github.com/go-openapi/swag/fileutils` | v0.27.1 | 2026-07-19 |
| `github.com/go-openapi/swag/jsonutils` | v0.27.1 | 2026-07-19 |
| `github.com/go-openapi/swag/loading` | v0.27.1 | 2026-07-19 |
| `github.com/go-openapi/swag/mangling` | v0.27.1 | 2026-07-19 |
| `github.com/go-openapi/swag/netutils` | v0.27.1 | 2026-07-19 |
| `github.com/go-openapi/swag/pools` | v0.27.1 | 2026-07-19 |
| `github.com/go-openapi/swag/stringutils` | v0.27.1 | 2026-07-19 |
| `github.com/go-openapi/swag/typeutils` | v0.27.1 | 2026-07-19 |
| `github.com/go-openapi/swag/yamlutils` | v0.27.1 | 2026-07-19 |
| `github.com/modern-go/concurrent` | v0.0.0-20180306012644-bacd9c7ef1dd | 2018-03-06 |
| `github.com/modern-go/reflect2` | v1.0.3-0.20250322232337-35a7c28c31ee | 2025-03-22 |
| `github.com/munnerz/goautoneg` | v0.0.0-20191010083416-a7dc8b61c822 | 2019-10-10 |
| `github.com/davecgh/go-spew` | v1.1.2-0.20180830191138-d8f796af33cc | 2018-08-30 |
| `sigs.k8s.io/json` | v0.0.0-20250730193827-2d320260d730 | 2025-07-30 |
| `gopkg.in/inf.v0` | v0.9.1 | 2018-03-26 |

Every date is more than two weeks before 2026-11-08. The upgrade also raises `spf13/pflag` from
v1.0.5 and `go.yaml.in/yaml/v2` from v2.4.2, because the three Kubernetes modules require the new
versions.

The agent binary links the whole `internal/clusterjwt` package. Because of this, it also contains
the server code and its go-jose and hcl imports, although it never calls the server code.

The review did not read the other client-go packages, the generated clientset for other API
groups, or the test files. It did not compare any module with its upstream repository. Because of
this, the result rests on the checksums in `go.sum` and on the read of the cache.

## External Secrets Operator v2.14.0 (2026-11-08)

The External Secrets Operator (ESO) copies keys from the secret manager into `dev-cp`. The cell
uses chart 2.14.0 and image v2.14.0. The ESO project published both on 2026-10-23. This is the newest
release on or before 2026-10-25, so it meets the two-week rule. The tag `v2.14.0` points at commit
`e932f3a3f6f274e8e269c01aa1f5fb3d1322e3c9`. The review read the chart and a scratch clone of the
tag, and ran nothing from them.

| Item | Digest |
| --- | --- |
| Chart archive `external-secrets-2.14.0.tgz` | SHA-256 `0a6d9e91b1ff50adfdbf24b50b582babfa7c5b7df42b21974ca4b3fb88ee5e34` |
| Chart manifest in `ghcr.io/external-secrets/charts` | `sha256:0e3d45f11522f2730ff55deef57bc43e0ff4aadc00bdab5557fa4d354b0c3ab7` |
| `ghcr.io/external-secrets/external-secrets:v2.14.0` index | `sha256:10608eb53e636e744903d5f3657a4d9c44e28d9d9c181b73e07bc7dd2e6884dc` |
| amd64 manifest | `sha256:0fc0750017357a3874b3bd102e1f3d5c8b9acac3d828f8108b6f176383f66ed2` |
| arm64 manifest | `sha256:a6a2f852e771830554a31f3392e68d6251ef9322990413b20b9df2554c8b0ab7` |

The chart archive from the registry and the archive in the GitHub release `helm-chart-2.14.0` have
the same SHA-256. `cells/common.env` holds this value, and `vendor:fetch` checks it before it
unpacks the chart. The unpacked files match the reviewed copy.

### Image

These facts come from the registry and from the binary layer, read on 2026-11-08.

- The arm64 image config has user `65534`, the entrypoint `/bin/external-secrets`, no command and no
  exposed port. The chart runs the container as user 1000.
- The base is distroless static on Debian 13. The build adds one static binary of 290 MB.
- `go version -m` read the build information of the binary without a run. The binary uses Go 1.27.3,
  `CGO_ENABLED=0` and the build tag `all_providers`. It has no VCS stamp, so the review could not tie
  the binary to the commit.

### Chart

The checks at the top of this file give these results:

- No hidden Unicode. The non-ASCII characters are the micro sign and em dashes in CRD descriptions,
  and the greater-than-or-equal sign and a curly apostrophe in comments.
- No long encoded strings.
- URLs are documentation links and example addresses in a subchart note. No template downloads
  anything, runs a shell command or calls `lookup`.
- No `privileged`, `hostPID`, `hostIPC`, `hostPath` or `hostPort`. `hostNetwork` is a value, and it
  is false.
- No ClusterRole has a wildcard.
- The chart bundles an SDK server subchart. It is off by default, and the cell leaves it off.

The webhook and the cert controller:

- The webhook validates SecretStore, ClusterSecretStore and ExternalSecret objects. It also serves
  CRD conversion when `crds.conversion.enabled` is true. That value is false by default.
- The cert controller creates and renews the webhook certificate. It writes the CA bundle into the
  webhook configuration and the CRDs.
- The controller command in `cmd/controller/root.go` never requests the webhook server.
  controller-runtime v0.25.2 starts that server only on such a request, so the controller opens no
  webhook port.
- Because of this, the controller runs ExternalSecret and SecretStore objects without the
  webhook and the cert controller, and the cell disables both.
- Cost: the provider check of a store runs only in the webhook. Without it, a store error shows only
  when the controller creates a provider client. `secrets:connect` checks the token reference itself.
- The cert controller ClusterRole can read every CRD. It can update and patch only the three ESO CRDs
  and the two ESO webhook configurations, by name. The cell does not render it.

`components/external-secrets/values.yaml` also disables these items:

- The reconcilers and CRDs for ClusterExternalSecret, ClusterSecretStore, PushSecret,
  ClusterPushSecret and ClusterGenerator.
- ServiceAccount token creation, leader election RBAC and the ClusterRole for service bindings.
- Aggregation of ESO permissions to the `view`, `edit` and `admin` ClusterRoles.
- The OpenShift finalizer permissions.
- The health listener, through `--live-addr=0`. No probe uses it.

The cell scopes the operator to one namespace, the store namespace `spire-system` from
`SECRET_STORE_NAMESPACES` in `cells/dev-cp.env`:

- `scopedRBAC: true` renders Roles and one RoleBinding in `scopedNamespace`, and no ClusterRole
  (`templates/rbac.yaml` in the chart).
- `scopedNamespace` adds `--namespace=spire-system`. The controller command then limits the
  manager cache to that namespace (`cmd/controller/root.go`, `DefaultNamespaces`).
- With `scopedRBAC`, the chart also turns off the reconcilers of ClusterSecretStore,
  ClusterExternalSecret and ClusterPushSecret (`templates/deployment.yaml`).
- The SecretStore reconciler stays on. It sets the Ready condition of the store.
- The store is a namespaced SecretStore. For such a store the token reference resolves in the
  namespace of the ExternalSecret, whatever namespace it names (`runtime/esutils/resolvers/secret_ref.go`).
  Because of this, `secrets:connect` puts a copy of the token Secret in each store namespace.
- The render holds Namespace `spire-system`, because the Role lives there and the
  `spire-server` bundle comes in a later sync wave. The namespace carries `Prune=false,Delete=false`.
- On 2026-11-09 the scoped controller ran in a test namespace of `rogue`, with the fake provider of
  ESO. A SecretStore became Ready, an ExternalSecret synced its target Secret, and the log held no
  RBAC error. `kubectl auth can-i` gave the controller Secret access in that namespace only. The
  check then removed every object that it created.

Role `external-secrets-controller` in `spire-system` keeps these permissions:

- Read, create, update, patch and delete Secrets in `spire-system`.
- Read ConfigMaps and ServiceAccounts in `spire-system`. Its rule for namespaces grants nothing,
  because a Role cannot grant a resource of the cluster scope.
- Read and update ExternalSecret and SecretStore objects and their status.
- Manage GeneratorState objects, read generator objects, and create events.

The chart also renders Roles `external-secrets-view` and `external-secrets-edit` in `spire-system`.
They have no binding, so they grant nothing.

The controller configures zap through controller-runtime with `Development` false. controller-runtime
then uses its JSON encoder, so the controller writes JSON logs to standard error. No flag changes
the format. The cell sets the time encoding to `iso8601`. The controller serves Prometheus metrics
on port 8080. No Service selects it, and the NetworkPolicy admits no ingress.

### Provider of the secret manager

The cell uses the ESO provider for the secret manager. `.envrc.local` selects it. The review read
the provider package at the tag, the vendor SDK that it wraps, and the SDK code that sends requests.

What the provider reads:

- One key of one Kubernetes Secret, from the token reference in the store. A namespaced
  SecretStore reads it in the namespace of the ExternalSecret.
- At client creation, the provider makes one remote call with the token. A store becomes Ready only
  after this call succeeds.

Where it connects:

- The SDK sends requests only to host names that match a fixed list of vendor domains. The list
  includes test domains of the vendor.
- The host check does not restrict the scheme or the port, and it does not run again after a
  redirect. The NetworkPolicy limits egress to TCP port 443 on public addresses.
- The SDK gives its compiled code no file system access.

How it holds the token:

- Only in memory. The provider passes the token to the SDK when it creates a client.
- The provider keeps one client for each version of a store. A new token in the Secret alone does
  not reach a cached client. Because of this, `secrets:connect` changes an annotation on the store,
  and the store gets a new resource version.

Searches:

- The provider package and the SDK Go code have no hidden Unicode.
- The provider package imports no `net`, `net/http`, `os`, `os/exec`, `syscall` or `unsafe` package.
- The module checksums in the ESO `go.sum` match the build information of the binary.

The review did not read these items:

- The part of the SDK that ships as compiled code. The review did not decompile it.
- Other ESO providers, the generators and the PushSecret code.
- Image signatures and the provenance files of the release.
- The binary compared with a source build, and its network behaviour at run time.

Result: medium concern. SDK code that the review could not read holds the token, and its allowed
hosts include vendor test domains. The controller can read and write only the Secrets of
`spire-system`, and it reads no store of the cluster scope. Two gaps remain:

- The NetworkPolicy admits DNS and every public address on TCP port 443. It blocks only the
  private and link-local ranges, so the controller can reach any public host on that port.
- In `spire-system`, the controller can read Secret `spire-upstream` with the intermediate CA key,
  and the copy of the access token. Other accounts can read them too, as the residual limits in
  `docs/design/poc-scope.md` list, for example `istio-reader-service-account` in every namespace.

## celld modules (2026-11-08)

`cmd/celld` gets its X.509 SVID through go-spiffe and exports logs, traces and metrics through the
OpenTelemetry Go SDK. The review cloned each item at its tag into a scratch directory and read it.
Nothing ran during the review. The module cache copies match the clones, apart from a `LICENSE`
file that each OpenTelemetry submodule archive adds. `go mod verify` passes.

The unit tests of `cmd/celld` ran once before this review was complete. Those tests start the
go-spiffe client and the OpenTelemetry SDK in the test process. They export nothing and connect only
to a local test socket.

| Module | Version | Commit | Date |
| --- | --- | --- | --- |
| `github.com/spiffe/go-spiffe/v2` | v2.9.0 | `77c6d2e0c1203e36804e26a02faa8f893d72e7e5` | 2026-10-05 |
| `go.opentelemetry.io/otel` and the `sdk`, `sdk/metric`, `sdk/log`, `trace`, `metric`, `log` submodules | v1.47.0 | `66cfc9520e205b7d450183532772401bc2b6674c` | 2026-10-02 |
| `go.opentelemetry.io/otel/exporters/otlp/otlptrace` and `otlptrace/otlptracegrpc` | v1.47.0 | same commit | 2026-10-02 |
| `go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc` | v1.47.0 | same commit | 2026-10-02 |
| `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc` | v0.23.0 | same commit | 2026-10-02 |
| `go.opentelemetry.io/contrib/bridges/otelslog` | v0.21.0 | `0c76f6137a2ceea80984d55e3de165924d823f71` | 2026-10-02 |

SPIRE v1.15.5 pins go-spiffe v2.8.1. The cell uses v2.9.0, the newest release at least two weeks
old. go-spiffe is a client library, so it does not need the SPIRE version.

go-spiffe:

- It reads one variable, `SPIFFE_ENDPOINT_SOCKET`, in `workloadapi/addr.go`.
- It connects only to that address. The address must be a `unix` path or a `tcp` IP address and
  port, so it has no DNS lookup. The client dials plaintext gRPC and adds the `workload.spiffe.io`
  header (`workloadapi/client.go`).
- The 15 packages in the build have no `os/exec`, `net/http`, `sudo` or file writes.

OpenTelemetry:

- The SDK and the exporters read the standard `OTEL_*` variables. These cover the exporter
  endpoints, headers, timeouts, compression and certificate paths. They also cover the resource
  attributes, the service name, the sampler and the limits.
- The exporters connect only to the OTLP endpoint. The default is `localhost:4317`, and the pod
  sets the collector address. Each exporter creates its gRPC client lazily, so it connects at its
  first export.
- `sdk/resource/host_id_exec.go` uses `os/exec` to read a host ID. The file builds only for
  Darwin and BSD, and celld does not ask for a host ID.
- `net/http` appears in the propagation types, in exporter option types and in the gateway files of
  `go.opentelemetry.io/proto/otlp`. No package in the build creates an HTTP client.
- The build has no Prometheus package. celld does not use the `autoexport` module, because that
  module brings a Prometheus exporter.

Searches over the 400 non-test Go files of the 102 third-party packages in the celld build:

- No hidden Unicode: no bidirectional controls, zero-width characters or other format characters.
- Other non-ASCII characters appear only in comments, apart from the replacement character that
  `baggage.go` writes for invalid UTF-8.
- No `sudo`, `Setuid` or `Setgid`.

The module also adds or raises the modules below. The searches above covered only the packages
in the celld build. `x/term`, `go.yaml.in/yaml/v3` and the swag modules are not in that build.
The next subsection reviews their diffs for the binaries that contain them.

| Module | Version | Date | Note |
| --- | --- | --- | --- |
| `go.opentelemetry.io/proto/otlp` | v1.11.0 | 2026-07-22 | Generated OTLP types |
| `github.com/grpc-ecosystem/grpc-gateway/v2` | v2.30.0 | 2026-08-05 | Required by the OTLP types |
| `go.opentelemetry.io/auto/sdk` | v1.2.1 | 2025-09-15 | Required by `otel/trace` |
| `github.com/cenkalti/backoff/v5` | v5.0.3 | 2025-07-23 | Exporter retries |
| `github.com/cespare/xxhash/v2` | v2.3.0 | 2024-04-04 | Hashes in the metric SDK |
| `github.com/go-logr/logr`, `github.com/go-logr/stdr` | v1.4.4, v1.2.2 | 2026-07-20, 2021-12-14 | Internal SDK logger |
| `github.com/Microsoft/go-winio` | v0.6.2 | not checked | Windows only, so not in the build |
| `golang.org/x/net`, `x/sys`, `x/text`, `x/term` | v0.59.0, v0.48.0, v0.42.0, v0.46.0 | 2026-09-08, 2026-08-31, 2026-09-08, 2026-09-08 | Raised from v0.57.0, v0.47.0, v0.40.0, v0.45.0 |
| `google.golang.org/genproto/googleapis/rpc` and `api` | v0.0.0-20260928230214-8a89bd6388cc | 2026-09-28 | Raised from the July version |
| `google.golang.org/protobuf` | v1.36.12 | 2026-08-10 | See below |
| `go.yaml.in/yaml/v3` | v3.0.5 | 2026-07-26 | Raised from v3.0.4 |
| `github.com/go-openapi/swag` and its 11 submodules | v0.28.0 | 2026-07-27 | Raised from v0.27.1, because grpc-gateway requires it |

Every binary of the Go module shares these modules, so the plugin binaries also get the raised
versions. go-spiffe v2.9.0 and the exporters require protobuf v1.36.12, so `go.mod` now
pins the tag instead of the earlier pseudo-version. A diff of the two module cache copies shows
these non-test, non-generated changes: `internal/encoding/defval/default.go`,
`internal/genid/descriptor_gen.go`, `internal/version/version.go` and
`reflect/protoreflect/source_gen.go`. The generated descriptor types also changed. The review did
not read the changed logic line by line.

### Raised modules outside the celld build (2026-11-09)

The review read the diff of each module between the two versions in the Go module cache, which
`go mod verify` checks. Nothing ran. The review looked for process starts, network calls, file
writes, `unsafe`, environment reads, `init` side effects and hidden Unicode in the changed lines.

| Module | Change | In the binaries | Result |
| --- | --- | --- | --- |
| `github.com/go-openapi/swag` and its 11 submodules | v0.27.1 to v0.28.0 | `cluster-jwt-agent`, `cluster-jwt-server` | Benign. See below. |
| `go.yaml.in/yaml/v3` | v3.0.4 to v3.0.5 | `cluster-jwt-agent`, `cluster-jwt-server`, `hostsvc`, `recordgen` | Benign. Every changed Go line is a comment. `go.mod` retracts v3.0.0 and v3.0.1 and drops a test dependency. |
| `golang.org/x/term` | v0.45.0 to v0.46.0 | `cluster-jwt-agent`, `cluster-jwt-server` | Benign. `Terminal.ReadLine` now keeps a read error until it has processed the data of that read. `go.mod` raises `x/sys`. |

The swag diff:

- Seven submodules have identical files outside tests: `cmdutils`, `fileutils`, `mangling`,
  `netutils`, `pools`, `stringutils` and `typeutils`.
- `jsonutils` and `yamlutils` change only in `go.mod`, where the versions of the sibling submodules rise.
- `conv` adds `AppendInteger`, `AppendUinteger`, `AppendFloat` and `AppendBool`, which call `strconv` only.
- `loading` adds `rootRelative`, `toOSPath` and `stripLeadingDriveSlash` to the loader for an `os.Root`.
  An absolute path now moves onto the root before `os.Root` opens it, and `os.Root` still rejects
  a path that leaves the root. The change adds imports of `path/filepath` and `runtime` only.
- The root module changes `go.mod` and the pinned commits of its CI workflows.
- The changed lines add no process start, network call, file write, `unsafe`, environment read or
  `init` function. The only non-ASCII characters are em dashes in comments.

The review did not read the unchanged code of these modules again, and it did not check which
swag functions the plugins call.

The review did not read these items:

- The OpenTelemetry packages outside the celld build, the contrib repository outside `otelslog`,
  and the test files.
- The full exporter retry and transform code. The review read the configuration and connection code.
- Any module compared with a source build of its binary.

### SPIRE agent image

The celld pod runs `ghcr.io/spiffe/spire-agent:1.15.5` by its index digest. The arm64 manifest is
`sha256:1a249242cd1020ee632e50bbb4f44625e014c072f8e9871adc6a79c694191f76`. These facts come from the
registry, read on 2026-11-08. The review listed the layer files and ran nothing from the image.

- The config has user `0:0`, the entrypoint `/opt/spire/bin/spire-agent run`, the working directory
  `/opt/spire` and no exposed port.
- Four layers: the CA bundle, empty directories, and one static binary of 62 MB with mode 0755.
  No file is setuid or setgid.
- The pod runs the sidecar as user 1000, with a read-only root file system and no capabilities.
- The review did not compare the binary with a source build, and did not check image signatures.

## M3 version dates (2026-11-09)

Each version that M3 pins must have a publish date on or before 2026-10-26, two weeks before the
work date. The table gives the date of the release artefact and its source. Read-only `gh api`
calls and registry queries gave each date.

| Item | Version | Date (UTC) | Source |
| --- | --- | --- | --- |
| go-spiffe | v2.9.0 | 2026-10-05T18:26:53Z | GitHub release `published_at` |
| OpenTelemetry Go | v1.47.0 | 2026-10-02T08:18:45Z | GitHub release `published_at` |
| grpc-go | v1.84.0 | 2026-09-17T20:03:39Z | GitHub release `published_at` |
| `google.golang.org/protobuf` | v1.36.12 | 2026-08-10T15:29:56Z | GitHub release `published_at` |
| `golang.org/x/net` | v0.59.0 | 2026-09-08T19:18:02Z | `proxy.golang.org` version info, because the repository has no GitHub releases |
| `go.opentelemetry.io/proto/otlp` | v1.11.0 | 2026-07-22T21:40:59Z | `proxy.golang.org` version info |
| SPIRE | v1.15.5 | 2026-10-20T18:35:18Z | GitHub release; image `spire-server` created 2026-10-20T18:07:27Z |
| Argo CD | v3.6.1 | 2026-11-04T14:20:31Z | GitHub release; image `quay.io/argoproj/argocd` created 2026-11-04T13:48:52Z |
| Argo CD Agent | v0.10.0 | 2026-08-26T21:32:56Z | GitHub release; image `quay.io/argoprojlabs/argocd-agent` created 2026-08-26T21:24:06Z |
| `grafana/otel-lgtm` | v0.38.0 | 2026-10-23T11:18:25Z | GitHub release of `grafana/docker-otel-lgtm`; image created 2026-10-23T11:10:11Z |
| Kiali | v2.34.0 | 2026-10-25T13:59:52Z | GitHub release; image `quay.io/kiali/kiali` created 2026-10-25T13:59:23Z |
| kiali-server chart | 2.34.0 | 2026-10-26T16:06:40Z | Commit date of tag `v2.34.0` in `kiali/helm-charts` |
| Collector Kubernetes distribution | 0.164.0 | 2026-10-26T23:46:44Z | GitHub release; image `opentelemetry-collector-k8s` created 2026-10-26T23:48:32Z |
| Istio | 1.30.8 | 2026-11-06T19:00:51Z | GitHub release; image `pilot` created 2026-11-06T13:54:46Z; chart `istiod` created 2026-11-06T17:21:39Z |
| External Secrets Operator | 2.14.0 | 2026-10-23T15:06:48Z | GitHub release; chart release 2026-10-23T16:22:37Z; image created 2026-10-23T13:01:14Z |

- The collector Kubernetes distribution 0.165.0 has a publish date of 2026-11-07, after the
  cutoff. M3 uses 0.164.0 instead, which has a publish date on the cutoff day.
- Argo CD v3.6.1 and Istio 1.30.8 have publish dates after the cutoff. Earlier milestones pinned
  them, and the decision about them belongs to the maintainers. M3 does not change them.
- The Kiali chart index gives 258 of its 280 entries the same `created` value, 2026-11-02T17:06:56Z.
  That value is the time of an index build, not a publish date. The table uses the tag commit date.

## cell-proxy modules (2026-11-09)

`internal/cellproxy` makes two modules direct requirements. Both were already in the module graph
at the same versions, so `go.sum` does not change.

| Module | Version | Commit | Date | Package that cell-proxy uses |
| --- | --- | --- | --- | --- |
| `golang.org/x/net` | v0.59.0 | `540d04cfe5028e2655754591a4d3e08c586809f2` | 2026-09-08 | `http2` |
| `google.golang.org/protobuf` | v1.36.12 | `cdd4c5f7406e82462949c7a65defa9f3029c162d` | 2026-08-10 | `encoding/protowire` |

The review read the files in the Go module cache, and `go mod verify` passes. Nothing ran during
the review.

- With Go 1.27, `x/net/http2` wraps the HTTP/2 code of `net/http`. The build tag
  `go1.27 && !http2legacy` selects `server_wrap.go`, `transport_wrap.go` and `clientconn.go`.
- Those files import only standard library packages. `NewClientConn` uses the connection that the
  caller gives, and it does not dial.
- The `init` function in `http2.go` reads only `GODEBUG`, for debug logs and extended CONNECT.
- `protowire` imports `io`, `math`, `math/bits` and one internal errors package. It has no file,
  network or environment access.
- The 71 files of `x/net/http2` and `protowire` have no hidden Unicode. The only other non-ASCII
  characters are ellipses in comments of `protowire/wire.go`.
- The files that the review read have no `sudo`, `os/exec`, `unsafe` or `syscall` import.
- Go 1.27 marks `http2.ClientConn` as deprecated in favour of `net/http.ClientConn`.
- The tests also use `types/known/wrapperspb` from the protobuf module and `encoding/gzip` from
  grpc-go. Neither is in the `cell-proxy` binary.

The review did not read the HTTP/2 code of the Go standard library, or the frame and `hpack` code
of `x/net/http2`.

`internal/telemetry` now holds the OpenTelemetry setup that `cmd/celld` had. It adds no module, so
the "celld modules" review above covers its exporters, the SDK and `logr`.

## Telemetry gateway modules (2026-11-09)

The `otlp` backend of `cell-proxy` makes `go.opentelemetry.io/proto/otlp` v1.11.0 a direct
requirement. The module was already in the graph at that version, so `go.sum` does not change.
The `go list -deps` output for `cmd/cell-proxy` holds the same OTLP, grpc-gateway and gzip
packages before and after this change, because the OTLP exporters already import them.

The review read the module in the Go module cache, and `go mod verify` passes. Nothing ran during
the review.

- The module has 14 Go files, all generated by `protoc-gen-go` and `protoc-gen-go-grpc` v1.1.0.
  Five files hold the message types, and the `collector` packages hold the services.
- The message and service files import only `context`, `reflect`, `sync`, protobuf runtime
  packages and grpc-go. Each `init` function registers only the file descriptor.
- The three `*.pb.gw.go` files import grpc-gateway and `net/http`. They define handler
  registration functions, and `cell-proxy` calls none of them.
- No hidden Unicode. The only non-ASCII characters are box characters in a comment of
  `metrics/v1/metrics.pb.go`.
- No `os/exec`, `unsafe`, `syscall`, `sudo`, environment reads, file access or network dials.

The gateway server imports `google.golang.org/grpc/encoding/gzip` from grpc-go v1.84.0. That
package imports only `compress/gzip`, `fmt`, `io`, `sync` and the grpc `encoding` package. Its
`init` function registers the compressor. It has no non-ASCII characters.

grpc-go v1.84.0 applies `MaxRecvMsgSize` after decompression, in `rpc_util.go` lines 985 to 1040.
A compressed message larger than the limit fails with `ResourceExhausted`, and a unit test checks
this.

The review did not read the grpc-gateway runtime line by line. The `celld` review searched it
together with the other packages of that build.

### Upstream limits of the gateway (2026-11-10)

The gateway receive limit depends on the OTLP receiver of `otel-lgtm` v0.38.0. The review read the
files of tag `v0.38.0` of `grafana/docker-otel-lgtm` through `gh api`, and ran nothing.

- `docker/Dockerfile` pins `otelcol-contrib` v0.163.1. `docker/download-otelcol.sh` checks the
  archive with `cosign verify-blob` before it unpacks it.
- `docker/otelcol-config.yaml` sets the gRPC receiver endpoint `0.0.0.0:4317` and no
  `max_recv_msg_size_mib`.
- In collector core v0.163.0, `config/configgrpc/configgrpc.go` lines 358 and 359 add
  `grpc.MaxRecvMsgSize` only for a value above 0. The receiver therefore keeps the grpc-go default
  of 4 MiB.
- The review did not check which core version `otelcol-contrib` v0.163.1 uses. It did not inspect
  the image contents.

The cell collectors use collector 0.164.0. In that version `exporter/otlpexporter/factory.go`
lines 41 to 47 set gzip compression by default and no client keepalive.

A gateway test writes raw HTTP/2 frames with the `Framer` of `x/net/http2` (`frame.go`) and the
`hpack` package, from `x/net` v0.59.0. On 2026-11-10 the review searched both in the module cache
for the checks below, and ran nothing from them during the review. It did not read the frame
parsing or the HPACK code line by line.

- `frame.go` imports standard library packages, `x/net/http/httpguts`, `x/net/internal/httpsfv`
  and `hpack`. It logs frames only when `GODEBUG` sets `http2debug=2`.
- The `hpack` files import only standard library packages. `gen.go` has the build tag `ignore`,
  so no build compiles it.
- No hidden Unicode and no other non-ASCII characters. No `os/exec`, `unsafe`, `syscall`, `sudo`,
  environment reads or dials, and no `init` function.
- `go list` shows that both build into `cell-proxy` as part of `x/net/http2`. These searches
  narrow the gap that the `cell-proxy` modules review above names.

## Argo CD v3.6.1 full install for the central view (2026-11-10)

`argocd/v3.6.1/install.yaml` is the full install of the Argo CD tag `v3.6.1`. Its SHA-256 is
`7be23ca7d9ca3d3074dee8332f1ca92a933b990cee7c9cf22cf3843ee8c2913e`. `components/central-view` names
the file directly. The kustomization of the cells keeps `core-install.yaml` alone. The review read
the file and ran nothing from it.

- No hidden Unicode and no other non-ASCII characters, the same as `core-install.yaml`.
- The long encoded strings are the SSH host keys that `core-install.yaml` also holds.
- The URLs are the same as in `core-install.yaml`. No object downloads anything or runs a shell
  command, apart from the `copyutil` init container of the repo server, which copies the `argocd`
  binary into a shared volume.
- No `privileged`, `hostNetwork`, `hostPID`, `hostIPC` or `hostPath`.
- Images: `quay.io/argoproj/argocd:v3.6.1`, `public.ecr.aws/docker/library/redis:8.10.1-alpine` and,
  for Dex only, `ghcr.io/dexidp/dex:v2.46.0`. The view pins the index digests
  `sha256:296e3d74f449b2ce45265613fcb68c18ed7366488360c8ea32f5f2a93d2e5c54` (Argo CD) and
  `sha256:ef216d85ec44f4fdf7c0e6df2d1757a4734ed32fbb278cabd3181b5a27353b79` (Redis), read from the
  registries on 2026-11-10. The review did not inspect the image contents.

The view keeps `argocd-server`, `argocd-repo-server` and `argocd-redis` with their ServiceAccounts,
Services, ConfigMaps and the Roles of the server and Redis. It drops the CRDs, the application
controller, the ApplicationSet controller, Dex, notifications, Secret `argocd-secret` and the
upstream NetworkPolicies. `viewkeys` makes `argocd-secret`, because `argocd-server` needs
`server.secretkey`.

RBAC of `argocd-server`, as the view changes it:

| Rule in v3.6.1 | In the view | Reason |
| --- | --- | --- |
| Role: create, get, list, watch, update, patch and delete on Secrets and ConfigMaps | get, list and watch | The server reads its settings, the cluster Secrets and the keys. |
| Role: every verb on Applications, AppProjects and ApplicationSets | get, list and watch | The view changes no object in its namespace. |
| Role: create and list on Events | kept | Write that stays: the server records an Event for each user action. |
| ClusterRole: delete, get and patch on every resource, update on every finalizer | removed | The view reaches cell resources only through the resource proxy. |
| ClusterRole: get, list and watch on Applications and ApplicationSets | kept | The server lists the Applications of every namespace. |
| ClusterRole: list Events, get pods and logs, create Jobs and Workflows | removed | The view runs no resource action in management. |

`argocd-server` stops at start when AppProject `default` is missing and it cannot create it
(observed on 2026-11-10: `appprojects.argoproj.io is forbidden ... cannot create resource`). The
view renders AppProject `default` with no source and no destination.

The full install starts the Redis password with an init container: `secret-init` in Deployment
`argocd-redis` runs `argocd admin redis-initial-password`. It creates Secret `argocd-redis` when it is
missing. v3.6.1 has no Job `argocd-redis-secret-init`. The view gives only that init container a
projected API token. Role `argocd-redis` keeps get on Secret `argocd-redis` and create on Secrets.

`argocd-server` reads two Redis addresses: `REDIS_SERVER` for its own cache and
`REPO_SERVER_REDIS_SERVER` for the cache of the repo server (`util/cache/cache.go` line 225 and
`cmd/argocd-server/commands/argocd_server.go` line 364 of v3.6.1). Without the second one, it uses
`argocd-redis:6379`. The view sets both to the Redis proxy of the principal.

## Argo CD Agent v0.10.0 (2026-11-10)

The central view runs the principal of Argo CD Agent v0.10.0. The tag `v0.10.0` points at commit
`78a3788f5aa757707c00e563198f3d4c676fe04b`. The review read a copy of the tag archive in a scratch
directory and ran nothing from it.

| Item | Digest |
| --- | --- |
| Tag archive from `codeload.github.com` | SHA-256 `9060a59f18891b41efd662c09a0c93a824462bf8507f136ebbe4c346075d4d07` |
| `install/kubernetes/principal` and `agent`, sorted file list | SHA-256 `c0cda6f7fbed368c4b3f7dd085095df47f79436cd4894d22a6cfa9eb0d647c56` (`ARGOCD_AGENT_MANIFESTS_SHA256`) |
| `quay.io/argoprojlabs/argocd-agent:v0.10.0` index | `sha256:ec9baba6e81555bfa5ce1fa6252f06c6100b56ae7f85273ba2f7e2309303800d` |
| arm64 manifest | `sha256:a5c9027ff491e05649b159cf6a105de05af0c1cbb84bd54f36575ceb955c696d` |
| amd64 manifest | `sha256:e262e4ef7da9128d9b72d133383b624bd4fb0ada8ceb127d10ff9e2f72f7a64f` |

`vendor:fetch` downloads the archive, checks the SHA-256 of the file list and copies the two
directories into `argocd-agent/v0.10.0/`. The view uses its own manifest
(`components/central-view/principal.yaml`), and so do the cells (`components/argocd-agent/manifests.yaml`).
The vendored files are the review record.

### Image

These facts come from the registry and from the binary layer, read on 2026-11-10.

- The arm64 image config has user `999`, the entrypoint `/bin/argocd-agent` and no exposed port.
  The base is Alpine 3.23.5 with `apk upgrade`, so the image holds a shell and busybox.
- The last layer holds one file, `/bin/argocd-agent`, 116 MB.
- `go version -m` read the build information of the binary without a run: Go 1.26.3,
  `CGO_ENABLED=0`, module `github.com/argoproj-labs/argocd-agent` v0.10.0, VCS revision
  `78a3788f5aa757707c00e563198f3d4c676fe04b` with `vcs.modified=false`. The binary therefore comes
  from the reviewed commit. It links 172 modules, among them Argo CD v3.5.1.
- The `Dockerfile` of the tag builds with `golang:1.26.3` and copies the binary into `alpine:3.23`,
  which matches the image history.

### Manifests

- No hidden Unicode and no other non-ASCII characters. No long encoded strings. No URL.
- No `privileged`, `hostNetwork`, `hostPID`, `hostIPC` or `hostPath`.
- The upstream principal ClusterRole can create, update and delete Applications, AppProjects and
  ApplicationSets in every namespace, and create namespaces. The view lists and watches them in
  every namespace, writes Applications only through a Role in each agent namespace, and writes
  AppProjects only in `central-view-system`. Each write that stays has a call in v0.10.0:
  - Applications in an agent namespace, create: `principal/event.go` line 263 (`appManager.Create`
    of an Application that an autonomous agent sends; line 846 sets the namespace to the agent).
  - Applications, update and patch: lines 281 and 306 (`UpdateAutonomousApp`), lines 318 and 418
    (`UpdateStatus`), and `principal/callbacks.go` line 153 (`RemoveFinalizers`). The backend calls
    are `Update` and `Patch` in `internal/backend/kubernetes/application/kubernetes.go` lines 157 to 167.
  - Applications, delete: `principal/event.go` lines 332 and 376.
  - AppProjects in `central-view-system`, create, update and delete: `principal/event.go` lines 573,
    592 and 608, after line 568 sets the namespace to the namespace of the principal.
  - ApplicationSets are written only in HA mode (`principal/ha_integration.go`), so the view grants
    no write on them.
- The upstream principal Role can write every Secret and ConfigMap of its namespace. The view
  grants get, list and watch only.
- `principal-params-cm.yaml` says that header authentication needs the gRPC listener on
  `127.0.0.1`. The view sets `--listen-host=127.0.0.1`.

### Source

The review read `cmd/argocd-agent/principal.go`, `principal/server.go`, `principal/resource.go`,
`principal/event.go`, `pkg/principal/identity.go`, `internal/argocd/cluster/`, `internal/tlsutil/`
and `cmd/ctl/` (`ca.go`, `jwt.go`, `agent.go`).

- Every flag that the view sets exists in `cmd/argocd-agent/principal.go`: `--namespace`,
  `--listen-host`, `--listen-port`, `--insecure-plaintext`, `--auth`, `--allowed-namespaces`,
  `--namespace-create-enable`, `--enable-resource-proxy`, `--redis-server-address`,
  `--metrics-port`, `--healthz-port` and `--log-format`. `--auth header:<name>:<regex>` takes the
  first capture group as the agent name, and needs `--insecure-plaintext`
  (`validateAuthTLSPairing`).
- Only the gRPC listener takes a host. The resource proxy listens on `0.0.0.0:9090` and the Redis
  proxy on `0.0.0.0:6379` (`principal/server.go` lines 232 to 236). Metrics listen on `:8000` and
  health on `:8003`.
- `cmd/argocd-agent/principal.go` imports `net/http/pprof`, which registers on the default HTTP mux.
  The health server serves that mux (`principal/server.go` lines 872 to 884). So port 8003 also
  serves `/debug/pprof/`. On 2026-11-10 `wget http://127.0.0.1:8003/debug/pprof/cmdline` inside the
  pod printed the arguments of the principal. The view probes the health port from inside the
  pod, and no NetworkPolicy rule admits a peer on 8003. The API server pod proxy
  (`pods/<pod>:8003/proxy/debug/pprof/`) and root processes on the node skip NetworkPolicy, so
  each holder of `pods/proxy` in `central-view-system` can still read and load pprof.
- The Redis proxy on 6379 answers `get` and `subscribe` on the keys `app|managed-resources|<agent>_*`
  and `app|resources-tree|<agent>_*` from the agent, before any `AUTH` reaches `argocd-redis`
  (`principal/redisproxy/redisproxy.go` lines 343 to 440). So a peer that reaches 6379 reads the
  live state of every cell Application with no password. NetworkPolicy flow N4 is the only control.
- At start the principal reads ConfigMap `argocd-agent-principal-identity`, and creates it when it
  is missing (`pkg/principal/identity.go`, `principal/server.go` line 710). The view renders it with
  a fixed value, so the principal writes no ConfigMap.
- With `--insecure-plaintext` the principal loads no root CA for agents. The resource proxy reads its
  certificate from Secret `argocd-agent-resource-proxy-tls`, which must have the type
  `kubernetes.io/tls`, and its client CA from `tls.crt` and `ca.crt` of `argocd-agent-ca`
  (`getResourceProxyTLSConfigFromKube`, `internal/tlsutil/kubernetes.go`). No key of the CA is read.
- The resource proxy takes the agent name from the CN of the client certificate, or from a bearer
  token that the principal signed (`principal/resource.go`, `extractAgentFromAuth`).
- The principal writes Secrets only for self-registered agents and in HA mode, which the view leaves
  off. It keeps cluster state in Redis.
- `internal/kube/client.go` imports `os/exec` only for an exit error type. No `sudo`, no HTTP client
  call and no hidden Unicode in the non-test Go code of `cmd`, `principal`, `internal` and `pkg`.

`cmd/viewkeys` copies these formats from `argocd-agentctl`:

- `argocd-agent-jwt`: key `jwt.key`, an RSA key of 4096 bits in PKCS#8 PEM (`cmd/ctl/jwt.go`).
- `argocd-agent-resource-proxy-tls`: type `kubernetes.io/tls`, `tls.crt` and `tls.key`
  (`cmd/ctl/ca.go`, `issueAndSaveSecret`).
- `cluster-<agent>`: label `argocd.argoproj.io/secret-type: cluster`, label
  `argocd-agent.argoproj-labs.io/agent-name: <agent>`, annotations `managed-by: argocd-agent` and
  `argocd.argoproj.io/skip-reconcile: "true"`, and keys `name`, `server` and `config`
  (`cmd/ctl/agent.go`, `internal/argocd/cluster/conversion.go`). The server is
  `https://<host>:9090?agentName=<agent>`.
- The validity: 3650 days for the CA and 180 days for each leaf (`internal/tlsutil/generate.go`).

`viewkeys` differs from `argocd-agentctl` in four points. It keeps no CA key, so `argocd-agent-ca`
has the type `Opaque`, because a `kubernetes.io/tls` Secret needs `tls.key`. It gives each
certificate a random serial number, where `argocd-agentctl` uses 1. It sets only the key usages that
each certificate needs. It uses ECDSA P-256 keys for the certificates.

### Agent side (2026-11-10)

The review read `cmd/argocd-agent/agent.go`, `agent/agent.go`, `agent/filters.go`, `agent/tracking.go`,
`agent/options.go`, the connect and authentication path of `pkg/client/remote.go`,
`internal/resync/resync.go`, `principal/apis/auth/auth.go`, `principal/apis/eventstream/eventstream.go`
and the AppProject path of `principal/event.go`, in the same scratch copy. It ran nothing from it.

- Every flag that the cells set exists in `cmd/argocd-agent/agent.go`: `--agent-mode`, `--creds`,
  `--insecure-plaintext`, `--server-address`, `--server-port`, `--namespace`, `--redis-addr`,
  `--redis-creds-dir-path`, `--enable-compression`, `--metrics-port`, `--healthz-port` and
  `--log-format`. `--creds header:` gives the method `header` with no credential (`parseCreds`).
- `--redis-creds-dir-path` reads the password from the file `auth` in that directory (`redisCreds`).
  So the agent reads the Redis password of the cell from a Secret volume, and needs no Secret read.
- The agent watches Applications, AppProjects, repository Secrets and GPG ConfigMaps in its own
  namespace only, and Namespaces in the cluster (`agent/agent.go` lines 300 to 470). Its settings
  manager reads `argocd-cm` in that namespace (`agent/tracking.go`).
- Argo CD reads AppProjects only in its own namespace, and the agent sends only the AppProjects of
  its namespace, which is `argocd`. So the agent sends AppProject `cell` from `argocd`. The principal
  stores it as `<agent>-cell` in its namespace, with `sourceNamespaces` set to the agent namespace
  (`principal/event.go` lines 525 to 545). The central `argocd-server` needs that project, because
  `getAppEnforceRBAC` loads the project of each Application (`server/application/application.go`
  lines 248 to 252 of Argo CD v3.6.1).
- `/healthz` answers 200 only while the stream to the principal is up (`agent/agent.go` lines 736
  to 743). The cells probe the metrics port instead. The health port must be from 1 to 32767
  (`WithHealthzPort`), so it cannot be off.
- `cmd/argocd-agent/agent.go` imports `net/http/pprof`, and the health server serves the default
  mux (`agent/agent.go` lines 626 to 634). So port 8002 of the agent also serves `/debug/pprof/`,
  on every address. The namespace-wide policy `argocd` admits every pod of `argocd` to it.
- The agent sends the access token as the raw `authorization` value, and `RefreshToken` with no
  `authorization` value (`pkg/client/remote.go`). The principal rejects an agent whose version
  differs from its own (`principal/apis/auth/auth.go` lines 150 to 153).
- The principal logs "An agent connected to the subscription stream" and "Closing EventStream"
  with the field `client` (`principal/apis/eventstream/eventstream.go` lines 190 and 508).
- No `sudo`, no `os/exec` call, no HTTP client outside the remote and the resource proxy, and no
  hidden Unicode in the files above.

The review did not read these items:

- The agent resource proxy and Redis proxy line by line, and `agent/inbound*.go` and `agent/outbound*.go`.
- The Redis proxy and the event stream code line by line, the HA code and the test files.
- The 172 modules of the binary, and the image signatures.
- The network behaviour of the binary at run time.

Result: medium concern. The image holds a shell and busybox. The health ports of the principal and
the agent serve pprof, and the resource and Redis proxies of the principal bind every address.
NetworkPolicy limits each of them.

## grafana/otel-lgtm v0.38.0 (2026-11-10)

`management` runs `docker.io/grafana/otel-lgtm:0.38.0` as StatefulSet `lgtm`. The repository is
`grafana/docker-otel-lgtm`. The review read these files of tag `v0.38.0` through `gh api`, in a scratch
directory, and ran nothing from them before it ended: `docker/Dockerfile`, every `docker/run-*.sh`,
`docker/download-*.sh`, `docker/install-cosign.sh`, `docker/grafana-plugins.sh`, `docker/common.sh`,
`docker/logging.sh`, `docker/healthcheck.sh` and every baked config. The review checked these files for
hidden Unicode, `sudo`, persistence, credential access and obfuscated code. It found none.

| Item | Digest |
| --- | --- |
| Index `grafana/otel-lgtm:0.38.0`, pinned by the pod | `sha256:75cdf892daffadf3763ef61c16a6d7f8586216fce0b40bba7874a0b053121084` |
| arm64 manifest, the one that the VM pulls | `sha256:61ffd7c074d354759207d7541a0361cc2b4a897f0e06003c9672384a6b8cc2f6` |
| amd64 manifest | `sha256:bf33fa01b1a0314edc88c5bc2a295067e65270cf9c3f678a943a4a2c2a2472fd` |

### What the image holds

- The base is `ubi9-micro` 9.8, pinned by digest, with `curl-minimal` added. The image sets no `USER`.
- Six processes run in one container: Grafana v13.2.4, Prometheus v3.15.0, Loki v3.7.8, Tempo v3.1.0,
  Pyroscope v2.4.1 and `otelcol-contrib` v0.163.1. The OBI eBPF agent is off unless `ENABLE_OBI=true`.
  Grafana also starts 13 backend plugin binaries for its data sources (Elasticsearch, PostgreSQL, MySQL,
  MSSQL, InfluxDB, OpenTSDB, Cloud Monitoring, Jaeger, Zipkin, Loki, Prometheus, Tempo and Pyroscope),
  and `run-all.sh` ends with `sleep infinity`. The store uses only four of those data sources.
  `GF_PLUGINS_DISABLE_PLUGINS` could stop the others. The PoC does not set it, because the list of
  plugin IDs is not verified for this image.
- Prometheus runs with `--web.enable-remote-write-receiver` and `--web.enable-otlp-receiver`, so port 9090
  accepts writes. Loki (3100), Tempo (3200), Pyroscope (4040) and the `otelcol` HTTP receiver (4318) also
  accept data on `0.0.0.0`. Only the NetworkPolicy keeps pods away from them, and a peer that Task 11
  admits to 9090 must be `promql-proxy` alone.
- The image sets no retention for Loki or Pyroscope, 14 days for Tempo and 15 days for Prometheus. The
  pod sets 48 hours for each, through `loki.yaml`, `TEMPO_EXTRA_ARGS`, `PYROSCOPE_EXTRA_ARGS` and
  `PROMETHEUS_EXTRA_ARGS`.
- The build downloads each component from its upstream release page. It checks the SHA-256 file of
  Loki, Tempo, Prometheus and Pyroscope, and the checksum that `grafana.com` gives for Grafana. It
  checks `otelcol-contrib` with `cosign verify-blob`, which the build installs from a checked RPM.
  The review did not check these archives itself.
- `eval` appears once in `run-all.sh`, and it uses only the fixed component names of the script.
- `run-otelcol.sh` adds an export to a remote OTLP endpoint only when an `OTEL_EXPORTER_OTLP_*`
  variable is set. The pod sets none. It writes `otelcol-config-export-http.yaml` into the working
  directory in that case only, so the read-only root file system does not break the start.

### Start-up downloads and calls to the Internet

- `run-grafana.sh` always sets `GF_PLUGINS_PREINSTALL` to `grafana-llm-app`. Grafana then installs
  that plugin and the Drilldown apps from `grafana.com` at each start. The pod sets
  `GF_PLUGINS_PREINSTALL_DISABLED=true` and `GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false`, so Grafana
  downloads nothing. The live plugin list below shows that none of them is present.
- Grafana checks for updates and sends usage reports by default. The pod turns each off with
  `GF_ANALYTICS_REPORTING_ENABLED`, `GF_ANALYTICS_CHECK_FOR_UPDATES` and
  `GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES`.
- Loki, Tempo and Pyroscope report usage by default. The Loki override sets
  `analytics.reporting_enabled: false`. `TEMPO_EXTRA_ARGS=-reporting.enabled=false` and
  `PYROSCOPE_EXTRA_ARGS=-usage-stats.enabled=false` turn the other two off. Both flags exist in the
  binaries, which the review checked with `-help` in the running pod.
- The NetworkPolicy gives the pod no egress, and the namespace policy `allow-dns` leaves it out. A
  `curl` from the pod to `grafana.com` and to `1.1.1.1` fails, and `TestM3LgtmHardened` checks both.

### Controls

- The pod runs as user and group 10001, with `fsGroup` 10001, `runAsNonRoot`, no capability, no
  privilege escalation, the `RuntimeDefault` seccomp profile and `readOnlyRootFilesystem: true`.
  The image starts under these limits without root, and all six components reach their health check.
- Writable paths: the volume `data` at `/data` (Grafana, Loki, Prometheus, Tempo and Pyroscope), a
  memory-backed `emptyDir` at `/tmp` (Grafana plugin sockets and `/tmp/ready`) and one at `/var/tempo`.
- The pod mounts no service account token. Anonymous access is off. The admin password comes from
  Secret `grafana-admin`.

### Findings

- The brief mandates `GF_SECURITY_ADMIN_PASSWORD__FILE`. The suffix `__FILE` belongs to the
  `run.sh` of the official Grafana image, and this image starts `./bin/grafana server` directly.
  On the live pod, Grafana ignored the variable and created the admin user with the password
  `admin`: `admin:admin` got HTTP 200. The pod therefore sets
  `GF_SECURITY_ADMIN_PASSWORD=$__file{/run/grafana-admin/password}`. Grafana expands `$__file{}`
  in a setting itself. With that value, `admin:admin` gets 401 and the generated password gets 200.
- The image provisions four data sources, not three: Prometheus, Loki and Tempo, and Pyroscope
  (`docker/grafana-datasources.yaml`). All four pass their health check as user 10001.
- The Prometheus config of the image already promotes `deployment.environment.name` and
  `k8s.cluster.name`. The override adds `platform.plane` and `platform.cell`.
- Data sources are present and healthy with the default log setting, so `ENABLE_LOGS_GRAFANA=true`
  was not needed.

### Plugins of the running image

`/api/plugins?embedded=0` lists 46 plugins with `GF_PLUGINS_PREINSTALL_DISABLED=true`. They are the
core plugins of Grafana 13.2.4: `alertlist`, `alertmanager`, `annolist`, `barchart`, `bargauge`,
`candlestick`, `canvas`, `cloudwatch`, `dashlist`, `elasticsearch`, `flamegraph`, `gauge`, `geomap`,
`gettingstarted`, `grafana-azure-monitor-datasource`, `grafana-postgresql-datasource`,
`grafana-pyroscope-datasource`, `grafana-testdata-datasource`, `graphite`, `heatmap`, `histogram`,
`influxdb`, `jaeger`, `logs`, `logstable`, `loki`, `mssql`, `mysql`, `news`, `nodeGraph`, `opentsdb`,
`piechart`, `prometheus`, `stackdriver`, `stat`, `state-timeline`, `status-history`, `table`,
`tempo`, `text`, `timeseries`, `traces`, `trend`, `welcome`, `xychart` and `zipkin`.
`TestM3LgtmHardened` compares the live list with this one.

### Not inspected

The review did not inspect the layers of the image, the six binaries, the 13 plugin binaries or the image signature. It did
not compare the downloaded archives with a source build.

### Collector Kubernetes distribution 0.164.0 (2026-11-10)

The collector of `management` uses `docker.io/otel/opentelemetry-collector-k8s:0.164.0`, pinned by the
index digest `sha256:8f7e5aaac0302f090164d5f9c14e4437d8037c5aaa2d025fc3ad74c1922602eb`. The
processor `resource` is not in the core image, and the render needs it to set `k8s.cluster.name` and
`platform.plane`. The review read `distributions/otelcol-k8s/manifest.yaml` of tag `v0.164.0` in
`open-telemetry/opentelemetry-collector-releases`. The manifest lists `resourceprocessor`,
`prometheusreceiver`, `k8seventsreceiver`, `k8sobjectsreceiver`, `filestorage` and `otlpexporter`.
This settles row 10 of the M3 verify table for the component list, not for the image contents. The
review did not inspect the image.

#### Use in every cluster (2026-11-11)

Task 10 runs this image as the collector of every cluster. The manifest of components was read before
the image ran, and the image then ran in `management` for several hours. Then the review ran the image with
`otelcol-k8s components` and `otelcol-k8s validate --config` on a copy of each rendered config. No
other command ran in the image, and no config for the check reached a network.

- `components` lists the receivers `otlp`, `prometheus` and `k8s_objects`, the processors
  `memory_limiter`, `resource` and `transform`, the exporter `otlp_grpc`, and the extension
  `file_storage`. The names differ from the plan: `k8s_objects` is not `k8sobjects`, and the exporter
  is `otlp_grpc` (the name `otlp` is an alias). All modules show contrib v0.164.1 on core 0.164.0.
- `validate` accepts the rendered config of `management`, `dev-cp`, `dev-cell-1` and `dev-cell-2`. It
  also refuses an unknown value (`sizer: bogus`), so the check does decode the queue and batch keys.
- The pod ran with a persistent queue, compaction at start, the bytes sizer for the queue and the
  batch, the Prometheus scrape jobs, and the own metrics over OTLP. The review read the log of one
  pod and found no call to an address outside the cluster. The config holds no such address.
- Verify row 10 passes: the distribution holds the `prometheus` and `k8s_objects` receivers and the
  `file_storage` extension. The fallback to contrib is not needed.
- The review did not inspect the layers or the binary of the image.

Rows 3 and 4 of the M3 verify table (2026-11-11):

- Row 3 passes. The metrics ports of the agent, the principal and the SPIRE server admit the collector pod
  only. The ports of the Argo CD controller, the repo server, istiod and Envoy also admit the pods of
  their own namespace. `TestM3MetricsEndpointsCollectorOnly` shows that a pod of a fresh
  namespace times out on each port, and that every scrape job of every cluster has `up` equal to 1.
- Row 4 passes. `istio_requests_total` and `istio_request_duration_milliseconds_bucket` reach
  Prometheus with their names and labels, with `source_cluster` and `destination_cluster` equal to the
  cell. `TestM3IstioMetricsSurviveOTLP` shows this. The value `telemetry.v2.prometheus.enabled: false`
  had turned the Envoy metrics off, so the cell showed no Istio metric at all before this task.
