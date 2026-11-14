# The cell registry of a cell-proxy server in a plane. Source this file from scripts/lib.sh and from the
# renders of the view components.
#
# mgmtd publishes ConfigMap cell-registry into each view namespace, with the label
# poc.internal/made-by=mgmtd. The renders of the view components hold ConfigMap registry-signer, which pins
# the key that signs the registry, and a Role that lets mgmtd write the registry.

REGISTRY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REGISTRY_ROOT/scripts/ko-image.sh"
source "$REGISTRY_ROOT/components/lib/mgmt-key.sh"

# registry_signer_configmap <namespace> prints ConfigMap registry-signer. Key signer.pub holds the public key
# of mgmtd, in the form of signers.pub in the registry: the standard base64 and a newline. The annotation
# poc.internal/registry-signer-sha256 holds the SHA-256 of that value, so a new key restarts the server pods.
# The helper prints nothing when mgmt_signing_pub fails, and returns 1.
registry_signer_configmap() {
  local ns="$1" pub
  pub="$(mgmt_signing_pub)" || return 1
  NS="$ns" PUB="$pub"$'\n' SUM="$(printf '%s\n' "$pub" | sha256)" yq -n '
    .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "registry-signer" | .metadata.namespace = strenv(NS)
    | .metadata.annotations["poc.internal/registry-signer-sha256"] = strenv(SUM)
    | .data["signer.pub"] = strenv(PUB)
    | .data["signer.pub"] style="literal"'
}

# registry_publisher_rbac <namespace> prints Role cell-registry-publish and its RoleBinding for the ServiceAccount
# mgmtd in mgmt-system. Create cannot name the object, and get and update name only cell-registry.
registry_publisher_rbac() {
  NS="$1" yq -n '
    .apiVersion = "rbac.authorization.k8s.io/v1" | .kind = "Role"
    | .metadata.name = "cell-registry-publish" | .metadata.namespace = strenv(NS)
    | .rules = [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]},
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["cell-registry"], "verbs": ["get", "update"]}]'
  echo "---"
  NS="$1" yq -n '
    .apiVersion = "rbac.authorization.k8s.io/v1" | .kind = "RoleBinding"
    | .metadata.name = "cell-registry-publish" | .metadata.namespace = strenv(NS)
    | .roleRef = {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "cell-registry-publish"}
    | .subjects = [{"kind": "ServiceAccount", "name": "mgmtd", "namespace": "mgmt-system"}]'
}

# registry_wait <namespace> waits until ConfigMap cell-registry in the namespace of the current cluster
# carries the label poc.internal/made-by=mgmtd, holds at least one *.dsse.json key, and lists a record
# for each cell of harness/topology.yaml that has the cell-identity set. It checks every 2 seconds for
# REGISTRY_WAIT_SECONDS seconds (default 60). It fails with the cells that have no record, and the
# command that binds each one. The wait covers a mgmtd that is still waiting for the Role of the view
# component, which the apply of the component has just made.
registry_wait() {
  local ns="$1" wait="${REGISTRY_WAIT_SECONDS:-60}" cells cell cm marked keys missing end
  cells="$(yq -r '.clusters[] | select(.components[] == "cell-identity") | .name' "$REGISTRY_ROOT/harness/topology.yaml")" \
    || die "registry_wait: could not read the cells of harness/topology.yaml"
  [[ -n "$cells" ]] || die "registry_wait: no cluster in harness/topology.yaml has the cell-identity set"
  end=$((SECONDS + wait))
  while :; do
    missing="" keys=""
    if cm="$(k -n "$ns" get configmap cell-registry -o json 2>/dev/null)"; then
      marked="$(jq -r '.metadata.labels["poc.internal/made-by"] // ""' <<<"$cm")"
      keys="$(jq -r '.data // {} | keys[] | select(endswith(".dsse.json")) | sub("\\.dsse\\.json$"; "")' <<<"$cm")"
      if [[ "$marked" != mgmtd ]]; then
        missing="ConfigMap $ns/cell-registry has no label poc.internal/made-by=mgmtd, so mgmtd has not published it"
      elif [[ -z "$keys" ]]; then
        missing="ConfigMap $ns/cell-registry holds no record"
      else
        for cell in $cells; do
          grep -qx -- "$cell" <<<"$keys" || missing+="${missing:+ }$cell"
        done
        [[ -z "$missing" ]] || missing="ConfigMap $ns/cell-registry has no record of: $missing"
      fi
    else
      missing="ConfigMap $ns/cell-registry does not exist, so mgmtd has not published it"
    fi
    [[ -n "$missing" ]] || return 0
    if ((SECONDS >= end)); then
      printf 'error: %s after %s s.\n' "$missing" "$wait" >&2
      for cell in $cells; do
        grep -qx -- "$cell" <<<"${keys:-}" || printf 'Run: CELL=%s mise run cell:up, so its celld binds\n' "$cell" >&2
      done
      printf 'Then check: mise run mgmt -- status, and the log of mgmtd-0 in mgmt-system\n' >&2
      return 1
    fi
    sleep 2
  done
}
