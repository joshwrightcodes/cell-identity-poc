# The operator public keys. Source this file from a render script or from scripts/operator-key.sh. It needs kubectl, jq, docker
# and mise, and it never reaches the secret manager.
#
# ConfigMap mgmt-system/operator-pub in management is the source of every pin: key spec.pub, key next.pub during a rotation only,
# and key spec.name. The pins in a cluster are key keys.pub of ConfigMaps envd-system/operator-key and gateway-system/operator-key,
# one standard base64 key on each line, and operator_public_keys in server.conf of ConfigMap spire-system/spire-server.

OPERATOR_KEY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# operator_key_valid <key> succeeds when the key is the standard base64 of 32 bytes.
operator_key_valid() {
  [[ "$1" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]] && [[ "$(printf '%s' "$1" | base64 -d 2>/dev/null | wc -c | tr -d ' ')" == 32 ]]
}

# operator_pub_cm prints ConfigMap mgmt-system/operator-pub of management as JSON, and nothing when it is absent. A failed read
# returns 1.
operator_pub_cm() {
  kubectl --context kind-management -n mgmt-system get configmap operator-pub --ignore-not-found -o json
}

# operator_keys_of <operator-pub JSON> prints spec.pub, then next.pub when it is set, one key on each line. It fails with the reason
# on standard error when a key is not the standard base64 of 32 bytes, or when next.pub repeats spec.pub.
operator_keys_of() {
  local spec next
  spec="$(printf '%s' "$1" | jq -r '.data["spec.pub"] // ""')" || return 1
  next="$(printf '%s' "$1" | jq -r '.data["next.pub"] // ""')" || return 1
  if ! operator_key_valid "$spec"; then
    printf 'error: key spec.pub of ConfigMap mgmt-system/operator-pub is not the standard base64 of 32 bytes. Run: mise run operator:check-key\n' >&2
    return 1
  fi
  if [[ -n "$next" ]] && ! operator_key_valid "$next"; then
    printf 'error: key next.pub of ConfigMap mgmt-system/operator-pub is not the standard base64 of 32 bytes. Run: mise run operator:check-key\n' >&2
    return 1
  fi
  if [[ "$next" == "$spec" ]]; then
    printf 'error: key next.pub of ConfigMap mgmt-system/operator-pub repeats spec.pub\n' >&2
    return 1
  fi
  printf '%s\n' "$spec"
  [[ -z "$next" ]] || printf '%s\n' "$next"
}

# operator_pin_name <cluster> <envd|gateway|server> prints the name of one pin, as the operator scripts report it.
operator_pin_name() {
  case "$2" in
    envd | gateway) printf '%s %s-system/operator-key\n' "$1" "$2" ;;
    server) printf '%s spire-system/spire-server operator_public_keys\n' "$1" ;;
  esac
}

# operator_pin <cluster> <envd|gateway|server> prints the keys of one pin in the cluster, sorted and joined with commas. It prints
# nothing when the pin is absent. A failed read returns 1.
operator_pin() {
  local cm
  case "$2" in
    envd | gateway)
      cm="$(kubectl --context "kind-$1" -n "$2-system" get configmap operator-key --ignore-not-found -o json)" || return 1
      printf '%s' "$cm" | jq -r '.data["keys.pub"] // "" | split("\n") | map(select(length > 0)) | sort | join(",")'
      ;;
    server)
      cm="$(kubectl --context "kind-$1" -n spire-system get configmap spire-server --ignore-not-found -o json)" || return 1
      printf '%s' "$cm" | jq -r '.data["server.conf"] // ""
        | [scan("(?m)^[ \t]*operator_public_keys[ \t]*=[ \t]*\\[([^\\]]*)\\]") | .[0] | scan("[A-Za-z0-9+/=]+")] | sort | join(",")'
      ;;
    *) return 1 ;;
  esac
}

# operator_connected succeeds when the environment is connected: mgmtd received a status report of envd within 2 minutes, by the
# clock of the node dev-cp-control-plane, and envd applied the revision that mgmtd signed last. Otherwise it prints the reason on
# standard error and returns 1.
operator_connected() {
  local status now verdict
  if ! status="$(cd "$OPERATOR_KEY_ROOT" && mise run mgmt -- status 2>/dev/null)"; then
    printf 'error: not connected: mise run mgmt -- status failed. Run: mise run harness:status\n' >&2
    return 1
  fi
  if ! now="$(docker exec dev-cp-control-plane date +%s 2>/dev/null)" || [[ ! "$now" =~ ^[0-9]+$ ]]; then
    printf 'error: not connected, because the clock of dev-cp-control-plane could not be read. Run: mise run harness:status\n' >&2
    return 1
  fi
  verdict="$(printf '%s' "$status" | jq -r --argjson now "$now" '
    def ts: try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch null;
    (.lastReportAt // "" | ts) as $at
    | if $at == null then "mgmtd holds no status report of envd"
      elif ($now - $at) > 120 then "the newest status report of envd at mgmtd is \($now - $at) seconds old"
      elif .applied != .signed or .signed == null then "envd applied \(.applied.epoch // 0).\(.applied.counter // 0), and mgmtd signed \(.signed.epoch // 0).\(.signed.counter // 0)"
      else "ok" end' 2>/dev/null)" || verdict="mise run mgmt -- status printed no status object"
  [[ "$verdict" != ok ]] || return 0
  printf 'error: not connected: %s. Run: mise run harness:status\n' "${verdict:-mise run mgmt -- status printed no status object}" >&2
  return 1
}

# operator_pub_keys <cluster> prints the operator keys for a render of the cluster: spec.pub of operator-pub, then next.pub when a
# rotation is in progress, one key on each line. A pin of the cluster that exists and holds another key set is a change. The helper
# refuses a change unless OPERATOR_KEY_ACCEPT_CHANGE=1, and refuses any change while not connected. Only the operator scripts set
# that variable. The helper fails with the reason on standard error.
operator_pub_keys() {
  local cluster="${1:?usage: operator_pub_keys <cluster>}" cm keys want which pinned changed=()
  if ! cm="$(operator_pub_cm)"; then
    printf 'error: ConfigMap mgmt-system/operator-pub in management could not be read. Run: mise run harness:status\n' >&2
    return 1
  fi
  if [[ -z "$cm" ]]; then
    printf 'error: ConfigMap mgmt-system/operator-pub in management is absent. The owner creates the operator key once with: mise run operator:create-key\n' >&2
    return 1
  fi
  keys="$(operator_keys_of "$cm")" || return 1
  want="$(printf '%s\n' "$keys" | LC_ALL=C sort | paste -sd, -)"
  for which in envd gateway server; do
    if ! pinned="$(operator_pin "$cluster" "$which")"; then
      printf 'error: the pin %s could not be read in %s, so the operator keys are unchecked. Run: mise run harness:status\n' "$(operator_pin_name "$cluster" "$which")" "$cluster" >&2
      return 1
    fi
    [[ -z "$pinned" || "$pinned" == "$want" ]] || changed+=("$(operator_pin_name "$cluster" "$which")")
  done
  if ((${#changed[@]} > 0)); then
    if [[ "${OPERATOR_KEY_ACCEPT_CHANGE:-}" != 1 ]]; then
      printf 'error: the pins %s hold other keys than ConfigMap mgmt-system/operator-pub. Compare them with the secret manager: mise run operator:check-key. To accept the keys of operator-pub, set OPERATOR_KEY_ACCEPT_CHANGE=1\n' "$(printf '%s; ' "${changed[@]}" | sed 's/; $//')" >&2
      return 1
    fi
    if ! operator_connected; then
      printf 'error: the operator keys of %s change, and the render refuses any change of the operator keys while not connected\n' "$cluster" >&2
      return 1
    fi
  fi
  printf '%s\n' "$keys"
}
