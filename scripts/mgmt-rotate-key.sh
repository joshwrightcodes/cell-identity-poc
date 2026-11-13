#!/usr/bin/env bash
# Rotate the signing key of the management plane: mise run mgmt -- rotate-signing-key.
# The steps run in this order:
#   1. mgmtd ctl rotate-key makes a new key, re-signs the spec and every record at the first revision of
#      the next epoch, and publishes the new public key in ConfigMap mgmt-system/mgmt-signing-pub.
#   2. The script waits until that ConfigMap holds the new key.
#   3. CELL=dev-cp mise run cell:up renders the new key into envd and the SPIRE server of dev-cp.
#   4. CELL=management mise run cell:link renders the new key into the link components of management.
#   5. cell:verify runs for management and for dev-cp.
# Until envd of dev-cp writes the records under the new key, the plugin of the SPIRE server holds no
# records, so a new pod cannot attest for that time. Running agents renew.
# The script prints one JSON line on standard output with the fingerprints of the old and the new key
# (SHA-256 of the public key, in hex) and the new epoch. A failure after step 1 prints the commands
# that are left, in order, on standard error. MGMT_ROTATE_KEY_WAIT bounds step 2 in seconds (default 180).
# Only public key material leaves mgmtd.
export CELL=management
source "$(dirname "$0")/lib.sh"

wait_seconds="${MGMT_ROTATE_KEY_WAIT:-180}"
[[ "$wait_seconds" =~ ^[0-9]+$ ]] || die "MGMT_ROTATE_KEY_WAIT takes a number of seconds"
cd "$ROOT"

fingerprint() { printf '%s' "$1" | base64 -d | shasum -a 256 | cut -d' ' -f1; }

before="$(mise run mgmt -- pubkey)" || json_fail mgmt-rotate-key "could not read the current public key of mgmtd"
old_pub="$(jq -er '."spec.pub"' <<<"$before")" || json_fail mgmt-rotate-key "mgmtd ctl pubkey printed no spec.pub: $before"

# The first step fails with nothing changed, unless the output says rotated.
rotated="$(mise run mgmt -- rotate-key)" || json_fail mgmt-rotate-key "mgmtd ctl rotate-key failed: ${rotated:-no output}. If it printed rotated:true, run the remaining commands by hand: mise run mgmt -- pubkey, CELL=dev-cp mise run cell:up, CELL=management mise run cell:link, CELL=management mise run cell:verify, CELL=dev-cp mise run cell:verify"
new_pub="$(jq -er '."spec.pub"' <<<"$rotated")" || json_fail mgmt-rotate-key "mgmtd ctl rotate-key printed no spec.pub: $rotated"
epoch="$(jq -er '.signed.epoch' <<<"$rotated")" || json_fail mgmt-rotate-key "mgmtd ctl rotate-key printed no signed epoch: $rotated"
[[ "$new_pub" != "$old_pub" ]] || json_fail mgmt-rotate-key "the key did not change"
log "mgmtd signs with a new key at epoch $epoch"

steps=(
  "wait until ConfigMap mgmt-system/mgmt-signing-pub holds the new key"
  "CELL=dev-cp mise run cell:up"
  "CELL=management mise run cell:link"
  "CELL=management mise run cell:verify"
  "CELL=dev-cp mise run cell:verify"
)
# stop <index> <reason> prints the commands from step <index> on, and exits with status 1.
stop() {
  local i="$1" reason="$2"
  printf 'error: the signing key rotated, but %s. Run these commands in order:\n' "$reason" >&2
  for ((; i < ${#steps[@]}; i++)); do
    if [[ "${steps[i]}" == wait* ]]; then
      printf '  mise x -- kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o jsonpath={.data.spec\\.pub}\n' >&2
    else
      printf '  %s\n' "${steps[i]}" >&2
    fi
  done
  exit 1
}

published() {
  local got
  got="$(kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o jsonpath='{.data.spec\.pub}' 2>/dev/null)" || return 1
  [[ "$got" == "$new_pub" ]]
}
end=$((SECONDS + wait_seconds))
until published; do
  ((SECONDS < end)) || stop 0 "ConfigMap mgmt-signing-pub does not hold the new key after ${wait_seconds}s"
  sleep 2
done
log "mgmt-signing-pub holds the new key"

CELL=dev-cp mise run cell:up >&2 || stop 1 "cell:up of dev-cp failed"
CELL=management mise run cell:link >&2 || stop 2 "cell:link of management failed"
CELL=management mise run cell:verify >&2 || stop 3 "cell:verify of management failed"
CELL=dev-cp mise run cell:verify >&2 || stop 4 "cell:verify of dev-cp failed"

jq -nc --arg old "$(fingerprint "$old_pub")" --arg new "$(fingerprint "$new_pub")" --argjson epoch "$epoch" \
  '{rotated: true, old_key_sha256: $old, new_key_sha256: $new, epoch: $epoch}'
