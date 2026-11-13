# The cell registry of a cell-proxy server in a plane. Source this file from a render script.
#
# Until the portal signs records (M4), the management plane signs its own registry with
# record:fixture, with a new throwaway key for each record, so it trusts no signer of dev-cp.
# record:fixture reads the facts of each cell from the host service, so each cell must exist.

REGISTRY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REGISTRY_ROOT/scripts/ko-image.sh"

# REGISTRY_SUBJECTS are the subjects of each cell record: the four cell workloads that reach a plane
# or the SPIRE server (the SPIFFE IDs and subjects table of the M3 plan).
REGISTRY_SUBJECTS=(argocd/argocd-agent observability-system/otel-uplink mesh-view-system/mesh-view cell-identity-system/celld)

# registry_configmap <namespace> <env> <cells...> prints ConfigMap cell-registry. It holds
# <cell>.dsse.json for each cell, and signers.pub with one base64 public key for each line. The
# annotation poc.internal/registry-content-sha256 holds the SHA-256 of the sorted
# "<name> <env> <revoked>" lines of the records, which cell-proxy logs at start as content_sha256.
# The signatures and keys stay out of it, so a render with new keys and the same cells gives the
# same value, and restarts no pod. The helper prints nothing when a step fails, and returns 1 with
# the reason on standard error.
registry_configmap() {
  local ns="$1" env="$2" cell record key keys="" lines="" data='{}' args subject
  shift 2
  if (($# == 0)); then
    printf 'error: registry_configmap: no cell\n' >&2
    return 1
  fi
  for cell in "$@"; do
    args=(--cluster "$cell" --env "$env")
    for subject in "${REGISTRY_SUBJECTS[@]}"; do
      args+=(--subject "$subject")
    done
    if ! record="$(cd "$REGISTRY_ROOT" && mise run record:fixture -- "${args[@]}" 2>/dev/null)"; then
      printf 'error: could not sign the record of %s: %s. The cluster must exist: run CELL=%s mise run cell:up\n' \
        "$cell" "${record:-no output}" "$cell" >&2
      return 1
    fi
    if ! NAME="cell-record-$cell" yq -e '.kind == "ConfigMap" and .metadata.name == strenv(NAME)
        and (.data."record.dsse.json" | length) > 0' <<<"$record" >/dev/null 2>&1; then
      printf 'error: record:fixture printed no ConfigMap cell-record-%s\n' "$cell" >&2
      return 1
    fi
    key="$(yq -r '.data."signer.pub"' <<<"$record")"
    if [[ ! "$key" =~ ^[A-Za-z0-9+/]+=*$ ]]; then
      printf 'error: record:fixture printed no base64 public key for %s\n' "$cell" >&2
      return 1
    fi
    keys+="$key"$'\n'
    lines+="$cell $env false"$'\n'
    data="$(KEY="$cell.dsse.json" VALUE="$(yq -r '.data."record.dsse.json"' <<<"$record")" \
      yq -o=json -I=0 '.[strenv(KEY)] = strenv(VALUE)' <<<"$data")"
  done
  # Each line ends with a newline, and the byte order of LC_ALL=C sort is the order of cell-proxy.
  DATA="$data" KEYS="$keys" NS="$ns" SUM="$(printf '%s' "$lines" | LC_ALL=C sort | sha256)" yq -n '
    .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "cell-registry" | .metadata.namespace = strenv(NS)
    | .metadata.annotations["poc.internal/registry-content-sha256"] = strenv(SUM)
    | .data = (strenv(DATA) | from_json) | .data["signers.pub"] = strenv(KEYS)
    | .data["signers.pub"] style="literal"'
}
