# Helpers for the ko images in the local registry at localhost:5001. Source this file from a
# render script. Each helper prints one value on success. On failure it prints the reason on
# standard error and returns 1, so the caller can stop.
#
# `mise run images` records the reference of each image that this Mac built in build/images.env.
# The helpers read only those references and never resolve a tag. IMAGES_ENV overrides the path.

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

# ko_image <name> prints the pinned reference <repo>@sha256:<digest> of the image cmd/<name>.
# It fails when build/images.env is missing, older than the Go sources, or names an image that the
# registry does not hold.
ko_image() {
  local name="$1" root file var ref newer
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  file="${IMAGES_ENV:-$root/build/images.env}"
  if [[ ! -f "$file" ]]; then
    printf 'error: no %s. Run mise run images first.\n' "$file" >&2
    return 1
  fi
  newer="$(find "$root/cmd/$name" "$root/internal" "$root/go.mod" "$root/go.sum" "$root/.ko.yaml" \
    -newer "$file" \( -name '*.go' ! -name '*_test.go' -o -name go.mod -o -name go.sum -o -name .ko.yaml \) -print 2>/dev/null | head -n 1)"
  if [[ -n "$newer" ]]; then
    printf 'error: %s is older than %s. Run mise run images again.\n' "$file" "${newer#"$root"/}" >&2
    return 1
  fi
  var="IMAGE_$(tr 'a-z-' 'A-Z_' <<<"$name")"
  ref="$(sed -n "s/^${var}=//p" "$file")"
  if [[ ! "$ref" =~ ^localhost:5001/${name}@sha256:[0-9a-f]{64}$ ]]; then
    printf "error: %s has no valid %s, it has '%s'. Run mise run images.\n" "$file" "$var" "$ref" >&2
    return 1
  fi
  if ! oras manifest fetch --plain-http "$ref" >/dev/null 2>&1; then
    printf 'error: the registry has no %s. Run mise run images.\n' "$ref" >&2
    return 1
  fi
  printf '%s\n' "$ref"
}

# ko_binary_sha256 <ref> <path> prints the SHA-256 of the file <path> in the image <repo>@<digest>.
# ko puts the binary in the last layer of a single-platform image. The helper hashes the manifest
# and the layer itself and compares each hash with the digest that names it.
ko_binary_sha256() {
  local ref="$1" path="$2" repo manifest layer blob checksum
  repo="${ref%@*}"
  blob="$(mktemp)"
  if ! oras manifest fetch --plain-http --output "$blob" "$ref" >/dev/null 2>&1 \
    || [[ "sha256:$(sha256 <"$blob")" != "${ref#*@}" ]]; then
    rm -f "$blob"
    printf 'error: could not fetch the manifest of %s with a matching digest\n' "$ref" >&2
    return 1
  fi
  manifest="$(cat "$blob")"
  if ! jq -e '.mediaType == "application/vnd.oci.image.manifest.v1+json"' <<<"$manifest" >/dev/null; then
    rm -f "$blob"
    printf 'error: %s is not a single-platform image manifest\n' "$ref" >&2
    return 1
  fi
  layer="$(jq -r '.layers[-1].digest' <<<"$manifest")"
  if ! oras blob fetch --plain-http --output "$blob" "$repo@$layer" >/dev/null 2>&1 \
    || [[ "sha256:$(sha256 <"$blob")" != "$layer" ]]; then
    rm -f "$blob"
    printf 'error: could not fetch layer %s of %s with a matching digest\n' "$layer" "$ref" >&2
    return 1
  fi
  checksum="$(tar -xzOf "$blob" "$path" 2>/dev/null | sha256)"
  rm -f "$blob"
  # The second value is the SHA-256 of empty input.
  if [[ ! "$checksum" =~ ^[0-9a-f]{64}$ || "$checksum" == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]]; then
    printf 'error: no %s in the last layer of %s\n' "$path" "$ref" >&2
    return 1
  fi
  printf '%s\n' "$checksum"
}
