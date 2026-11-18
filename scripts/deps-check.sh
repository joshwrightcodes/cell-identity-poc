#!/usr/bin/env bash
# Check the module rules of the Go binaries. Usage: deps-check.sh
# For each platform in DEPS_CHECK_PLATFORMS, the script lists every package that each binary in cmd/ compiles, and the direct
# imports of every package of the module, its tests and the e2e tests included. The default platforms are the ko platforms
# of KO_DEFAULTPLATFORMS (comma-separated, linux/arm64 when it is unset) and darwin/arm64, where hostsvc runs. It prints one
# line for each broken rule, binary or package and platform, and exits 1:
#   prometheus              a binary compiles a github.com/prometheus/ package
#   prometheus_import       a package, its tests included, imports a github.com/prometheus/ package
#   opa_forbidden           a package imports, or a binary compiles, opa/v1/sdk, opa/v1/plugins, opa/v1/runtime or opa/v1/storage/disk
#   opa_outside_appliers    a binary other than celld and envd compiles an OPA package
#   opa_outside_bundleapply a package outside internal/bundleapply imports an OPA package
# It runs only `go list`, and it builds and runs nothing. A failed `go list` exits 2.
set -euo pipefail
cd "$(dirname "$0")/.."

module=github.com/joshwrightcodes/cell-identity-poc
opa=github.com/open-policy-agent/opa
forbidden=("$opa/v1/sdk" "$opa/v1/plugins" "$opa/v1/runtime" "$opa/v1/storage/disk")
appliers=" celld envd "
ko_platforms="${KO_DEFAULTPLATFORMS:-linux/arm64}"
platforms="${DEPS_CHECK_PLATFORMS:-${ko_platforms//,/ } darwin/arm64}"
failures=0
nl=$'\n'

fail() {
  echo "deps-check: $*" >&2
  failures=$((failures + 1))
}

# first_match <prefix> <packages> prints the first of the space-separated packages that is the prefix or lies below it.
first_match() {
  grep -m1 -E "^${1//./\\.}(/|\$)" <<<"${2// /$nl}"
}

binaries=0
for platform in $platforms; do
  goos=${platform%/*} goarch=${platform#*/}
  cgo=1
  [[ "$goos" == linux ]] && cgo=0
  # One line for each binary: its import path, then every package that it compiles.
  if ! deps="$(GOOS=$goos GOARCH=$goarch CGO_ENABLED=$cgo go list -f '{{.ImportPath}}{{range .Deps}} {{.}}{{end}}' ./cmd/...)"; then
    echo "deps-check: go list of ./cmd/... failed for $platform" >&2
    exit 2
  fi
  while read -r bin pkgs; do
    [[ -n "$bin" ]] || continue
    binaries=$((binaries + 1))
    name=${bin##*/}
    if hit="$(first_match github.com/prometheus "$pkgs")"; then
      fail "prometheus: $name compiles $hit ($platform)"
    fi
    for f in "${forbidden[@]}"; do
      if hit="$(first_match "$f" "$pkgs")"; then
        fail "opa_forbidden: $name compiles $hit ($platform)"
      fi
    done
    if [[ "$appliers" != *" $name "* ]] && hit="$(first_match "$opa" "$pkgs")"; then
      fail "opa_outside_appliers: $name compiles $hit ($platform)"
    fi
  done <<<"$deps"

  # One line for each package of the module: its import path, then its imports, test imports and external test imports.
  if ! imports="$(GOOS=$goos GOARCH=$goarch CGO_ENABLED=$cgo go list -tags e2e -f '{{.ImportPath}}{{range .Imports}} {{.}}{{end}}{{range .TestImports}} {{.}}{{end}}{{range .XTestImports}} {{.}}{{end}}' ./...)"; then
    echo "deps-check: go list of ./... failed for $platform" >&2
    exit 2
  fi
  while read -r pkg pkgs; do
    [[ -n "$pkg" ]] || continue
    rel=${pkg#"$module"/}
    if hit="$(first_match github.com/prometheus "$pkgs")"; then
      fail "prometheus_import: $rel imports $hit ($platform)"
    fi
    for f in "${forbidden[@]}"; do
      if hit="$(first_match "$f" "$pkgs")"; then
        fail "opa_forbidden: $rel imports $hit ($platform)"
      fi
    done
    if [[ "$rel" != internal/bundleapply && "$rel" != internal/bundleapply/* ]] && hit="$(first_match "$opa" "$pkgs")"; then
      fail "opa_outside_bundleapply: $rel imports $hit ($platform)"
    fi
  done <<<"$imports"
done

if [[ $binaries -eq 0 ]]; then
  echo "deps-check: go list found no binary in ./cmd/..." >&2
  exit 2
fi
if [[ $failures -gt 0 ]]; then
  echo "deps-check: $failures rule failures" >&2
  exit 1
fi
echo "deps-check: ok, $binaries binary listings on $platforms"
