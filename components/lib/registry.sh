# The cell registry of a cell-proxy server in a plane. Source this file from a render script.
#
# The management plane signs the records. The registry holds the records that
# `mise run mgmt -- records` prints, byte for byte, and the signing key of mgmtd, from
# components/lib/mgmt-key.sh. A cell has a record after its celld binds to the management plane.

REGISTRY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REGISTRY_ROOT/scripts/ko-image.sh"
source "$REGISTRY_ROOT/components/lib/mgmt-key.sh"

# registry_configmap <namespace> <env> <cells...> prints ConfigMap cell-registry. It holds
# <cell>.dsse.json for each cell, and signers.pub with the public key of mgmtd. The annotation
# poc.internal/registry-content-sha256 holds the SHA-256 of the sorted "<name> <env> <revoked>"
# lines of the records, which cell-proxy logs at start as content_sha256. The signatures and the
# key stay out of it, so a render with new signatures and the same cells gives the same value, and
# restarts no pod. The helper prints nothing when a step fails, and returns 1 with the reason on
# standard error.
registry_configmap() {
  local ns="$1" env="$2" cell all record pub lines="" data='{}' body
  shift 2
  if (($# == 0)); then
    printf 'error: registry_configmap: no cell\n' >&2
    return 1
  fi
  pub="$(mgmt_signing_pub)" || return 1
  if ! all="$(cd "$REGISTRY_ROOT" && mise run mgmt -- records 2>/dev/null)" || ! jq -e 'type == "object"' >/dev/null 2>&1 <<<"$all"; then
    printf 'error: could not read the records of mgmtd: %s. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link\n' "${all:-no output}" >&2
    return 1
  fi
  for cell in "$@"; do
    if ! record="$(jq -ce --arg c "$cell" '.[$c] // empty' <<<"$all")" || [[ -z "$record" ]]; then
      printf 'error: mgmtd holds no record of %s. Run CELL=%s mise run cell:up, so its celld binds\n' "$cell" "$cell" >&2
      return 1
    fi
    if ! body="$(jq -ce '.payload | @base64d | fromjson' <<<"$record" 2>/dev/null)" \
      || ! jq -e --arg c "$cell" --arg e "$env" '.name == $c and .env == $e and (.revoked | type == "boolean")' >/dev/null <<<"$body"; then
      printf 'error: the record of %s from mgmtd is not a record of %s in env %s\n' "$cell" "$cell" "$env" >&2
      return 1
    fi
    lines+="$(jq -r '"\(.name) \(.env) \(.revoked)"' <<<"$body")"$'\n'
    data="$(KEY="$cell.dsse.json" VALUE="$record" yq -o=json -I=0 '.[strenv(KEY)] = strenv(VALUE)' <<<"$data")"
  done
  # Each line ends with a newline, and the byte order of LC_ALL=C sort is the order of cell-proxy.
  DATA="$data" KEYS="$pub"$'\n' NS="$ns" SUM="$(printf '%s' "$lines" | LC_ALL=C sort | sha256)" yq -n '
    .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "cell-registry" | .metadata.namespace = strenv(NS)
    | .metadata.annotations["poc.internal/registry-content-sha256"] = strenv(SUM)
    | .data = (strenv(DATA) | from_json) | .data["signers.pub"] = strenv(KEYS)
    | .data["signers.pub"] style="literal"'
}
