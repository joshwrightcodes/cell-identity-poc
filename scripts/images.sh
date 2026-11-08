#!/usr/bin/env bash
# Build and push every in-cluster image with ko, then record the reference that ko printed for each
# image in build/images.env, one IMAGE_<NAME>=<repo>@sha256:<digest> line each. Renders pin these
# references and never resolve a tag, so a tag that another client pushes cannot change a render.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out_file="$root/build/images.env"
: "${KO_DOCKER_REPO:?}"
images=(netprobe cluster-jwt-server cluster-jwt-agent celld)

die() { printf 'error: images: %s\n' "$*" >&2; exit 1; }

cd "$root"
paths=()
for name in "${images[@]}"; do paths+=("./cmd/$name"); done
# ko prints one reference for each image on standard output, and its progress on standard error.
refs="$(ko build --base-import-paths --tags latest "${paths[@]}")" || die "ko build failed"

mkdir -p "$root/build"
tmp="$(mktemp "$root/build/.images.env.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
for name in "${images[@]}"; do
  ref="$(grep -E "^${KO_DOCKER_REPO}/${name}@sha256:[0-9a-f]{64}$" <<<"$refs" || true)"
  [[ -n "$ref" && "$(wc -l <<<"$ref")" -eq 1 ]] || die "ko printed no single reference for $name: $refs"
  var="IMAGE_$(tr 'a-z-' 'A-Z_' <<<"$name")"
  printf '%s=%s\n' "$var" "$ref" >>"$tmp"
done
mv "$tmp" "$out_file"
trap - EXIT
printf '==> wrote %s\n' "$out_file" >&2
cat "$out_file" >&2
