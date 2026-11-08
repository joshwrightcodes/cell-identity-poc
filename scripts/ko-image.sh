# Helpers for the ko images in the local registry at localhost:5001. Source this file from a
# render script. Each helper prints one value on success. On failure it prints the reason on
# standard error and returns 1, so the caller can stop.

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

# ko_digest <repo> prints the digest of <repo>:latest.
ko_digest() {
  local repo="$1" digest
  if ! digest="$(oras resolve --plain-http "$repo:latest" 2>/dev/null)"; then
    printf 'error: no image %s:latest. Run mise run images first.\n' "$repo" >&2
    return 1
  fi
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf "error: image %s:latest resolved to '%s'\n" "$repo" "$digest" >&2
    return 1
  fi
  printf '%s\n' "$digest"
}

# ko_binary_sha256 <repo> <digest> <path> prints the SHA-256 of the file <path> in the image.
# ko puts the binary in the last layer of a single-platform image.
ko_binary_sha256() {
  local repo="$1" digest="$2" path="$3" manifest layer checksum
  manifest="$(oras manifest fetch --plain-http "$repo@$digest")" || return 1
  if ! jq -e '.mediaType == "application/vnd.oci.image.manifest.v1+json"' <<<"$manifest" >/dev/null; then
    printf 'error: %s@%s is not a single-platform image manifest\n' "$repo" "$digest" >&2
    return 1
  fi
  layer="$(jq -r '.layers[-1].digest' <<<"$manifest")"
  if ! checksum="$(oras blob fetch --plain-http --output - "$repo@$layer" | tar -xzOf - "$path" 2>/dev/null | sha256)"; then
    printf 'error: could not read %s from %s@%s\n' "$path" "$repo" "$digest" >&2
    return 1
  fi
  # The second value is the SHA-256 of empty input.
  if [[ ! "$checksum" =~ ^[0-9a-f]{64}$ || "$checksum" == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]]; then
    printf 'error: no %s in the last layer of %s@%s\n' "$path" "$repo" "$digest" >&2
    return 1
  fi
  printf '%s\n' "$checksum"
}
