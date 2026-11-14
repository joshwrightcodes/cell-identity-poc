# The public signing key of mgmtd. Source this file from a script that runs on this Mac.

MGMT_KEY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# mgmt_signing_pub prints the public key of mgmtd: key spec.pub of ConfigMap mgmt-system/mgmt-signing-pub
# in management, the standard base64 of 32 bytes. Whenever mgmtd-0 is Ready, the value must equal
# the answer of `mise run mgmt -- pubkey`. When mgmtd-0 is not Ready, the value must equal the key that
# ConfigMap envd-system/mgmt-spec-key in dev-cp already pins, unless nothing is pinned yet or
# MGMT_KEY_ACCEPT_CHANGE=1 allows a deliberate change. The helper fails with the reason on standard
# error, and with the link command when the ConfigMap is absent.
mgmt_signing_pub() {
  local cm pub live ready pinned
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
  if [[ "$ready" != True && "${MGMT_KEY_ACCEPT_CHANGE:-}" != 1 ]]; then
    if ! pinned="$(kubectl --context kind-dev-cp -n envd-system get configmap mgmt-spec-key --ignore-not-found \
      -o jsonpath='{.data.spec\.pub}' 2>/dev/null)"; then
      printf 'error: mgmtd-0 is not Ready and the key that dev-cp pins could not be read, so mgmt-signing-pub is unchecked. Start mgmtd with: CELL=management LINK_ONLY=mgmt-api mise run cell:link. To accept the key anyway, set MGMT_KEY_ACCEPT_CHANGE=1\n' >&2
      return 1
    fi
    if [[ -n "$pinned" && "$pinned" != "$pub" ]]; then
      printf 'error: mgmtd-0 is not Ready, and ConfigMap mgmt-signing-pub holds %s, but dev-cp pins %s. Start mgmtd with: CELL=management LINK_ONLY=mgmt-api mise run cell:link. After a lost state, run: mise run mgmt -- reset-state. To accept the new key, set MGMT_KEY_ACCEPT_CHANGE=1\n' "$pub" "$pinned" >&2
      return 1
    fi
  fi
  printf '%s\n' "$pub"
}

# mgmt_signing_next_pub prints the key that mgmtd has staged for the next rotation: key next.pub of ConfigMap
# mgmt-system/mgmt-signing-pub, the standard base64 of 32 bytes. It prints nothing when the ConfigMap holds no next.pub and
# `mise run mgmt -- status` shows no stagedKey, or when the ConfigMap holds no next.pub and mgmtd-0 is not Ready. Otherwise
# it requires mgmtd-0 to be Ready and the SHA-256 of the bytes of next.pub to equal stagedKey. It fails with the reason on
# standard error and has no override, so a writer of the ConfigMap cannot add a signing key to a cell. MGMT_KEY_ACCEPT_CHANGE
# applies to spec.pub only.
mgmt_signing_next_pub() {
  local cm next ready status staged fp
  if ! cm="$(kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o json 2>/dev/null)"; then
    printf 'error: ConfigMap mgmt-system/mgmt-signing-pub is absent. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link\n' >&2
    return 1
  fi
  next="$(jq -r '.data["next.pub"] // ""' <<<"$cm")"
  ready="$(kubectl --context kind-management -n mgmt-system get pod mgmtd-0 \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  if [[ -z "$next" && "$ready" != True ]]; then
    return 0
  fi
  if [[ "$ready" != True ]]; then
    printf 'error: ConfigMap mgmt-signing-pub holds a next.pub, and mgmtd-0 is not Ready, so the staged key is unchecked. Start mgmtd with: CELL=management LINK_ONLY=mgmt-api mise run cell:link\n' >&2
    return 1
  fi
  status="$(cd "$MGMT_KEY_ROOT" && mise run mgmt -- status 2>/dev/null)" || status=""
  if ! staged="$(jq -er '.stagedKey // ""' <<<"$status" 2>/dev/null)"; then
    printf 'error: mise run mgmt -- status printed no status object\n' >&2
    return 1
  fi
  if [[ -z "$next" && -z "$staged" ]]; then
    return 0
  fi
  if [[ ! "$next" =~ ^[A-Za-z0-9+/]{43}=$ ]] || [[ "$(printf '%s' "$next" | base64 -d 2>/dev/null | wc -c | tr -d ' ')" != 32 ]]; then
    printf 'error: key next.pub of mgmt-signing-pub is %s, and mgmtd shows the staged key %s. next.pub is not the base64 of 32 bytes\n' "${next:-absent}" "${staged:-none}" >&2
    return 1
  fi
  fp="$(printf '%s' "$next" | base64 -d | shasum -a 256 | cut -d' ' -f1)"
  if [[ "$fp" != "$staged" ]]; then
    printf 'error: key next.pub of mgmt-signing-pub has the SHA-256 %s, and mgmtd shows the staged key %s. Run: mise run mgmt -- status, and CELL=management LINK_ONLY=mgmt-api mise run cell:link\n' "$fp" "${staged:-none}" >&2
    return 1
  fi
  printf '%s\n' "$next"
}
