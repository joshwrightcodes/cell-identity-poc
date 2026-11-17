#!/usr/bin/env bash
# Build and push in-cluster images with ko, then record the reference that ko printed for each
# image in build/images.env, one IMAGE_<NAME>=<repo>@sha256:<digest> line each. Renders pin these
# references and never resolve a tag, so a tag that another client pushes cannot change a render.
# With no argument, the script builds every image. With image names, it builds and pushes only those
# images and replaces only their lines, so each other image keeps its digest, and the checks of the
# deployed images stay green. It keeps the `# commit` line too, unless the names cover every image.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out_file="$root/build/images.env"
: "${KO_DOCKER_REPO:?}"
all=(netprobe cluster-jwt-server cluster-jwt-agent celld attestprobe cell-proxy viewkeys relay mgmtd envd cell-controller cellgw)

die() { printf 'error: images: %s\n' "$*" >&2; exit 1; }

images=("$@")
if ((${#images[@]} == 0)); then
  images=("${all[@]}")
  named=0
else
  named=1
  for name in "${images[@]}"; do
    [[ " ${all[*]} " == *" $name "* ]] || die "unknown image '$name'. Known: ${all[*]}"
  done
  [[ -f "$out_file" ]] || die "no $out_file to update. Run mise run images with no argument first"
fi

cd "$root"
paths=()
for name in "${images[@]}"; do paths+=("./cmd/$name"); done
# ko prints one reference for each image on standard output, and its progress on standard error.
refs="$(ko build --base-import-paths --tags latest "${paths[@]}")" || die "ko build failed"

mkdir -p "$root/build"
tmp="$(mktemp "$root/build/.images.env.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
# The binaries carry no VCS stamp, so the commit is a note for people. Readers skip comment lines.
commit="$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
git -C "$root" diff --quiet HEAD -- 2>/dev/null || commit+=" with local changes"
# A build of some images keeps the commit line of the file, because the other digests come from that commit.
old_commit=""
if ((named)); then
  old_commit="$(grep -m1 '^# commit ' "$out_file" || true)"
  all_named=1
  for name in "${all[@]}"; do [[ " ${images[*]} " == *" $name "* ]] || all_named=0; done
  ((all_named)) && old_commit=""
fi
if [[ -n "$old_commit" ]]; then printf '%s\n' "$old_commit" >"$tmp"; else printf '# commit %s\n' "$commit" >"$tmp"; fi
# line_for <name> prints the new IMAGE_<NAME>=<reference> line.
line_for() {
  local ref var
  ref="$(grep -E "^${KO_DOCKER_REPO}/${1}@sha256:[0-9a-f]{64}$" <<<"$refs" || true)"
  [[ -n "$ref" && "$(wc -l <<<"$ref")" -eq 1 ]] || die "ko printed no single reference for $1: $refs"
  var="IMAGE_$(tr 'a-z-' 'A-Z_' <<<"$1")"
  printf '%s=%s\n' "$var" "$ref"
}
if ((named)); then
  # Keep the old lines in their order. An image that the old file lacks goes at the end.
  seen=" "
  while IFS= read -r line; do
    case "$line" in
      "#"* | "") continue ;;
    esac
    replaced=0
    for name in "${images[@]}"; do
      if [[ "${line%%=*}" == "IMAGE_$(tr 'a-z-' 'A-Z_' <<<"$name")" ]]; then
        line_for "$name" >>"$tmp"
        seen+="$name "
        replaced=1
      fi
    done
    ((replaced)) || printf '%s\n' "$line" >>"$tmp"
  done <"$out_file"
  for name in "${images[@]}"; do
    [[ "$seen" == *" $name "* ]] || line_for "$name" >>"$tmp"
  done
else
  for name in "${images[@]}"; do line_for "$name" >>"$tmp"; done
fi
mv "$tmp" "$out_file"
trap - EXIT
printf '==> wrote %s\n' "$out_file" >&2
cat "$out_file" >&2
