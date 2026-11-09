# The roots of a live SPIRE server in another cluster. Source this file from a render script.
#
# Roots hold only public certificates, so a render reads them from the live server and copies them
# into a ConfigMap. pkigen checks each certificate first: it must be a CA of the trust domain and
# valid now. Each helper prints nothing when a check fails, and returns 1 with the reason and the
# command to run on standard error.

PEER_ROOT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$PEER_ROOT_ROOT/scripts/ko-image.sh"

# peer_root_pem <server cluster> <trust domain> prints the X.509 roots that spire-server bundle show
# prints in that cluster, as PEM.
peer_root_pem() {
  local cluster="$1" td="$2" err bundle checked
  err="$(mktemp)"
  if ! bundle="$(kubectl --context "kind-$cluster" -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem 2>"$err")"; then
    printf 'error: could not read the trust bundle from spire-server-0 in %s. Run CELL=%s mise run cell:up first. kubectl: %s\n' \
      "$cluster" "$cluster" "$(tail -n 1 "$err")" >&2
    rm -f "$err"
    return 1
  fi
  rm -f "$err"
  # pkigen prints the certificates again, or one JSON error line when a check fails.
  if ! checked="$(cd "$PEER_ROOT_ROOT" && mise run pki -- trust-bundle --trust-domain "$td" <<<"$bundle" 2>/dev/null)"; then
    printf 'error: the trust bundle from %s failed the check: %s\n' "$cluster" "${checked:-no output}" >&2
    return 1
  fi
  printf '%s\n' "$checked"
}

# peer_root_configmap <name> <namespace> <server cluster> <trust domain> prints a ConfigMap with the
# roots in key root.crt. Its annotation poc.internal/peer-root-sha256 holds the SHA-256 of that
# value. A render copies the annotation to the pod template, so a new root restarts the pod.
peer_root_configmap() {
  local name="$1" ns="$2" pem
  pem="$(peer_root_pem "$3" "$4")" || return 1
  NAME="$name" NS="$ns" PEM="$pem" SUM="$(printf '%s' "$pem" | sha256)" yq -n '
    .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = strenv(NAME) | .metadata.namespace = strenv(NS)
    | .metadata.annotations["poc.internal/peer-root-sha256"] = strenv(SUM)
    | .data["root.crt"] = strenv(PEM) | .data["root.crt"] style="literal"'
}
