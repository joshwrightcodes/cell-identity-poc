# Helpers of cell:verify that scripts/verify.sh sources, so the tests can source them too. Each check
# function prints the reason and the repair command on standard output, and fails.
# check_mgmt_* need scripts/lib.sh and the helpers of components/lib/hostsvc-pin.sh, peer-root.sh and mgmt-key.sh.

# pem_lines prints each PEM certificate on standard input as one line, sorted.
pem_lines() {
  awk '/-----BEGIN CERTIFICATE-----/ { b = "" } { b = b $0 } /-----END CERTIFICATE-----/ { print b }' | sort
}

# peer_root_pods_current <namespace> <app> <ConfigMap> <fix command> succeeds when every running pod of the
# workload carries the digest of the ConfigMap in its annotation poc.internal/peer-root-sha256. The process reads
# the roots once at start, so a ConfigMap that is right does not show that the pod trusts the same roots.
peer_root_pods_current() {
  local ns="$1" app="$2" cm="$3" fix="$4" raw want pods bad
  raw="$(k -n "$ns" get configmap "$cm" -o jsonpath='{.data.root\.crt}')" || { echo "could not read ConfigMap $ns/$cm"; return 1; }
  want="$(printf '%s' "$raw" | shasum -a 256 | cut -d' ' -f1)"
  pods="$(k -n "$ns" get pods -l "app.kubernetes.io/name=$app" -o json)" || { echo "could not read the pods of $app in $ns"; return 1; }
  bad="$(jq -r --arg want "$want" '[.items[] | select(.metadata.deletionTimestamp == null) | .metadata.name as $n
      | ((.metadata.annotations["poc.internal/peer-root-sha256"] // "") | if . == "" then "none" else . end) as $got | select($got != $want) | "\($n) carries the root digest \($got)"] | .[]' <<<"$pods")"
  if [[ -z "$(jq -r '[.items[] | select(.metadata.deletionTimestamp == null)] | length | select(. > 0)' <<<"$pods")" ]]; then
    echo "$app has no running pod in $ns."
    echo "Run: $fix"
    return 1
  fi
  if [[ -n "$bad" ]]; then
    echo "$bad"
    echo "ConfigMap $ns/$cm has the digest $want, and a pod reads the roots only at start."
    echo "Run: $fix"
    return 1
  fi
}

node_ip() {
  local facts ip
  facts="$(cd "$ROOT" && mise run hostsvc -- facts --cluster "$1" 2>/dev/null)" || { echo "no host service facts for $1"; return 1; }
  ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
  [[ -n "$ip" ]] || { echo "the host service reports no node address for $1"; return 1; }
  printf '%s\n' "$ip"
}

# mgmtd copies the certificate of the host service, the address of the host service, the node address of
# VIEW_CONTROL_PLANE and its root, and the host service copies the root of management. Each can fall behind
# a restart of the host service or a rebuild. A mismatch prints the command that brings it up to date.
check_mgmt_hostsvc_pin() {
  local live got status want
  live="$("$(hostsvc_serve_script)" pin 2>&1)" || { echo "$live"; echo "Run: $(dependents_of hostsvc)"; return 1; }
  got="$(k -n mgmt-system get configmap hostsvc-pin -o jsonpath='{.data.hostsvc\.crt}')" \
    || { echo "could not read ConfigMap mgmt-system/hostsvc-pin"; return 1; }
  if [[ "$(pem_lines <<<"$got")" != "$(pem_lines <<<"$live")" ]]; then
    echo "ConfigMap mgmt-system/hostsvc-pin holds another certificate than the host service presents."
    echo "Run: $(dependents_of hostsvc)"
    return 1
  fi
  status="$("$(hostsvc_serve_script)" status)" || return 1
  want="$(jq -r '.cert_sha256' <<<"$status")"
  got="$(k -n mgmt-system get pod mgmtd-0 -o jsonpath='{.metadata.annotations.poc\.internal/hostsvc-pin-sha256}')" \
    || { echo "could not read the pod mgmtd-0"; return 1; }
  if [[ "$got" != "$want" ]]; then
    echo "mgmtd-0 carries the pin digest '$got', and the host service presents $want."
    echo "Run: $(dependents_of hostsvc)"
    return 1
  fi
}

check_mgmt_hostsvc_root() {
  local status have live
  status="$("$(hostsvc_serve_script)" status)" || return 1
  have="$(jq -r '.root_sha256' <<<"$status")"
  live="$(peer_root_pem "$CELL_NAME" "$SPIRE_TRUST_DOMAIN" | pem_der_sha256)" || { echo "could not read the live root of $CELL_NAME"; return 1; }
  if [[ "$have" != "$live" ]]; then
    echo "the host service trusts the management root $have, and the live root is $live."
    echo "Run: $(dependents_of hostsvc)"
    return 1
  fi
}

check_mgmt_hostsvc_address() {
  local want got arg
  want="$(hostsvc_address "$CELL_NAME" 2>&1)" || { echo "$want"; return 1; }
  got="$(k -n mgmt-system get networkpolicy mgmtd -o json \
    | jq -r --argjson p "$HOSTSVC_PORT" '[.spec.egress[] | select(any(.ports[]; .port == $p)) | .to[].ipBlock.cidr] | join(" ")')" \
    || { echo "could not read NetworkPolicy mgmt-system/mgmtd"; return 1; }
  arg="$(k -n mgmt-system get statefulset mgmtd -o json | jq -r '.spec.template.spec.containers[] | select(.name == "mgmtd") | .args[] | select(startswith("--hostsvc-addr="))')"
  if [[ "$got" != "$want/32" || "$arg" != "--hostsvc-addr=$want:$HOSTSVC_PORT" ]]; then
    echo "host.docker.internal is $want in the node, but the policy admits '$got' and mgmtd runs '$arg'."
    echo "Run: $(fix_command mgmt-api)"
    return 1
  fi
}

check_mgmt_env_address() {
  local want got port
  if ! kind get clusters 2>/dev/null | grep -qx "$VIEW_CONTROL_PLANE"; then
    got="$(k -n mgmt-system get networkpolicy mgmtd -o json | jq -r '[.spec.ingress[] | select(any(.ports[]; .port == 8446 or .port == 8447)) | .from[].ipBlock.cidr] | join(" ")')"
    [[ -z "$got" ]] || { echo "$VIEW_CONTROL_PLANE does not exist, but the API and bind ports admit '$got'."; echo "Run: $(fix_command mgmt-api)"; return 1; }
    return 0
  fi
  want="$(node_ip "$VIEW_CONTROL_PLANE")" || { echo "$want"; return 1; }
  for port in 8446 8447; do
    got="$(k -n mgmt-system get networkpolicy mgmtd -o json \
      | jq -r --argjson p "$port" '[.spec.ingress[] | select(any(.ports[]; .port == $p)) | .from[].ipBlock.cidr] | join(" ")')" \
      || { echo "could not read NetworkPolicy mgmt-system/mgmtd"; return 1; }
    if [[ "$got" != "$want/32" ]]; then
      echo "the $VIEW_CONTROL_PLANE node is $want, but port $port admits '$got'."
      echo "Run: $(fix_command mgmt-api)"
      return 1
    fi
  done
}

check_mgmt_peer_root() {
  local live got
  live="$(peer_root_pem "$VIEW_CONTROL_PLANE" dev.env.poc.internal 2>&1)" || { echo "$live"; return 1; }
  got="$(k -n mgmt-system get configmap peer-root -o jsonpath='{.data.root\.crt}' 2>/dev/null | pem_lines)"
  if [[ -z "$got" || "$got" != "$(pem_lines <<<"$live")" ]]; then
    echo "ConfigMap mgmt-system/peer-root is absent or holds other roots than the live bundle of $VIEW_CONTROL_PLANE."
    echo "Run: $(fix_command mgmt-api)"
    return 1
  fi
  peer_root_pods_current mgmt-system mgmtd peer-root "$(fix_command mgmt-api)" || return 1
}

