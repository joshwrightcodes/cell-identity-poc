# Vendored upstream files

This directory holds third-party files that the cell applies. Each file is reviewed before
it is committed. `mise run vendor:fetch` downloads the versions that `cells/common.env` pins.

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

The cell runs SPIRE v1.15.5 with the external plugin `cluster-jwt-server`. The tag is
`v1.15.5` at commit `f62d747d56e9caa6a38ad4bcbc32dbcc3dc1399a`. It was published on 2026-10-20,
so it meets the two-week rule. SPIRE v1.16.0 is too new. The review read a scratch clone and
ran nothing from it.

| Image | Index digest |
| --- | --- |
| `ghcr.io/spiffe/spire-server:1.15.5` | `sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384` |
| `ghcr.io/spiffe/spire-agent:1.15.5` | `sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481` |

The manifests pin the index digest. Each index also holds attestation manifests for the build.
The server image runs as user 1000 and the agent image runs as root. Both images hold only a CA
bundle, empty directories and one static binary, with no shell and no package manager.
Because of this, a plugin binary must be static and must be readable by user 1000.

The go.mod of the tag pins these versions: go-jose v4.1.4, go-spiffe v2.8.1,
plugin SDK `v1.4.4-0.20260617144146-5dcde407c4d1`, hcl `v1.0.1-vault-7`, go-plugin v1.8.0,
go-hclog v1.6.3 and grpc v1.84.0.

The review read these paths:

- The server API for agent attestation and renewal, and the server NodeAttestor plugin wrapper.
- The error mapping that carries a plugin error to the agent.
- The agent attestor and the SVID rotator.
- The rate limit middleware and the server limits.
- The node manager and the datastore queries that prune nodes.
- The external plugin loader, the plugin configuration code and the host service wiring.
- The `disk` UpstreamAuthority plugin and its documentation.

Findings that the cell relies on:

- The server applies the attestation rate limit first. The default is one attestation each
  second for each source IP, and the limit queues requests. The setting `attestation = false`
  turns it off.
- The server does not reject a repeat attestation for an agent ID that exists and is not
  banned. It overwrites the stored certificate. Because of this, the one-time property comes
  from the nonce hash in the agent ID, and not from SPIRE.
- A plugin error reaches the agent with the gRPC code and the message
  `nodeattestor(<plugin name>): <message>`. The server also logs the message. A plugin must put no
  token contents in a message.
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
| `github.com/hashicorp/go-plugin` | v1.8.0 | Matches the SPIRE pin. It runs a plugin as a child process on the host side. The plugin side only serves gRPC and reads the handshake variables. `client.go` imports `os/exec`, and the plugin never starts a child. No hidden Unicode. |
| `github.com/hashicorp/go-hclog` | v1.6.3 | Matches the SPIRE pin. No hidden Unicode and no process or network code. |
| `github.com/hashicorp/yamux` | v0.1.2 | Stream multiplexer for go-plugin. No hidden Unicode and no process or network code beyond `net.Conn` use. |
| `github.com/oklog/run` | v1.1.0 | Goroutine group helper. No hidden Unicode and no process or network code. |
| `github.com/fatih/color`, `github.com/mattn/go-colorable` | v1.15.0, v0.1.13 | Terminal colour for hclog. No hidden Unicode and no process or network code. |
| `google.golang.org/grpc` | v1.84.0 | Matches the SPIRE pin. Only the server side is relevant to the plugin, and the listener is a local socket. `os/exec` appears only in a Windows file and in a test tool that the build does not import. No hidden Unicode. |
| `google.golang.org/protobuf`, `github.com/golang/protobuf` | v1.36.11, v1.5.4 | `os/exec` appears only in code generators that the build does not import. No hidden Unicode. |
| `golang.org/x/net`, `golang.org/x/text`, `golang.org/x/sys` | v0.57.0, v0.40.0, v0.47.0 | Standard extension modules. `os/exec` appears only in generators and test helpers. The word `sudo` appears once, in a language name table in `x/text`. No hidden Unicode. The upgrade of `x/sys` from v0.6.0 also reaches the other modules that use it. |
| `google.golang.org/genproto/googleapis/rpc` | v0.0.0-20260706201446-f0a921348800 | Generated status types. The review did not read it beyond the module listing. |

The review compared no module with its upstream repository. Because of this, the result rests
on the module checksums in `go.sum` and on the read of the cache.
