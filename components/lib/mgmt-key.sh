# The public signing key of mgmtd. Source this file from a script that runs on this Mac.

MGMT_KEY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# mgmt_signing_pub prints the public key of mgmtd: key spec.pub of ConfigMap mgmt-system/mgmt-signing-pub
# in management, the standard base64 of 32 bytes. Whenever mgmtd-0 is Ready, the value must equal
# the answer of `mise run mgmt -- pubkey`. The helper fails with the reason on standard error, and
# with the link command when the ConfigMap is absent.
mgmt_signing_pub() {
  local cm pub live ready
  if ! cm="$(kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o json 2>/dev/null)"; then
    printf 'error: ConfigMap mgmt-system/mgmt-signing-pub is absent. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link\n' >&2
    return 1
  fi
  pub="$(jq -r '.data["spec.pub"] // ""' <<<"$cm")"
  if [[ ! "$pub" =~ ^[A-Za-z0-9+/]{43}=$ ]] || [[ "$(printf '%s' "$pub" | base64 -d 2>/dev/null | wc -c | tr -d ' ')" != 32 ]]; then
    printf 'error: key spec.pub of mgmt-signing-pub is not the base64 of 32 bytes\n' >&2
    return 1
  fi
  ready="$(kubectl --context kind-management -n mgmt-system get pod mgmtd-0 \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  if [[ "$ready" == True ]]; then
    live="$(cd "$MGMT_KEY_ROOT" && mise run mgmt -- pubkey 2>/dev/null | jq -r '."spec.pub" // ""')" || live=""
    if [[ "$live" != "$pub" ]]; then
      printf 'error: ConfigMap mgmt-signing-pub holds %s, and mgmtd-0 signs with %s. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link\n' "$pub" "${live:-no key}" >&2
      return 1
    fi
  fi
  printf '%s\n' "$pub"
}
