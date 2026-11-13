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
# (SHA-256 of the public key, in hex) and the new epoch. A failure prints one JSON error line on
# standard output instead. After step 1 that line holds rotated:true, the failed step, the key
# fingerprints and the commands that are left, and the same commands go to standard error as text.
# MGMT_ROTATE_KEY_WAIT bounds step 2 in seconds (default 180). Only public key material leaves mgmtd.
export CELL=management
source "$(dirname "$0")/lib.sh"

wait_seconds="${MGMT_ROTATE_KEY_WAIT:-180}"
[[ "$wait_seconds" =~ ^[0-9]+$ ]] || die "MGMT_ROTATE_KEY_WAIT takes a number of seconds"
cd "$ROOT"

fingerprint() { printf '%s' "$1" | base64 -d | shasum -a 256 | cut -d' ' -f1; }

before="$(mise run mgmt -- pubkey)" || json_fail mgmt-rotate-key "could not read the current public key of mgmtd"
old_pub="$(jq -er '."spec.pub"' <<<"$before")" || json_fail mgmt-rotate-key "mgmtd ctl pubkey printed no spec.pub: $before"
old_fp="$(fingerprint "$old_pub")"

steps=(
  "wait until ConfigMap mgmt-system/mgmt-signing-pub holds the new key"
  "CELL=dev-cp mise run cell:up"
  "CELL=management mise run cell:link"
  "CELL=management mise run cell:verify"
  "CELL=dev-cp mise run cell:verify"
)
names=(publish cell:up-dev-cp cell:link-management cell:verify-management cell:verify-dev-cp)
new_pub="" new_fp=""

# remaining <index> prints the commands from step <index> on, one for each line.
remaining() {
  local i
  for ((i = $1; i < ${#steps[@]}; i++)); do
    if [[ "${steps[i]}" == wait* ]]; then
      printf 'mise x -- kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o jsonpath={.data.spec\.pub}\n'
    else
      printf '%s\n' "${steps[i]}"
    fi
  done
}

# stop <index> <reason> reports a failure after the key rotated: the commands that are left as text on standard error, and
# one JSON error line on standard output with the failed step and the fingerprints. It exits with status 1.
stop() {
  local i="$1" reason="$2" cmds
  cmds="$(remaining "$i")"
  printf 'error: the signing key rotated, but %s. Run these commands in order:\n' "$reason" >&2
  sed 's/^/  /' <<<"$cmds" >&2
  jq -nc --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg error "the signing key rotated, but $reason" --arg step "${names[i]}" \
    --arg old "$old_fp" --arg new "$new_fp" --arg cmds "$cmds" \
    '{time: $time, level: "ERROR", msg: "mgmt-rotate-key failed", error: $error, rotated: true, step: $step, old_key_sha256: $old, new_key_sha256: $new,
      remaining: ($cmds | split("\n") | map(select(length > 0)))}'
  exit 1
}

# The first step can fail with nothing changed, or after the key rotated: the ctl error line then says rotated:true, or the answer
# of the exec was lost. So after any failure the script reads the public key again. A key that differs from the old one means the
# key rotated. Its public half may not have published, and mgmtd retries the publish, so the script goes on with the wait.
rotated="$(mise run mgmt -- rotate-key)" && ok=1 || ok=0
if ((ok)); then
  new_pub="$(jq -er '."spec.pub"' <<<"$rotated")" || json_fail mgmt-rotate-key "mgmtd ctl rotate-key printed no spec.pub: $rotated"
  epoch="$(jq -er '.signed.epoch' <<<"$rotated")" || json_fail mgmt-rotate-key "mgmtd ctl rotate-key printed no signed epoch: $rotated"
else
  after="$(mise run mgmt -- pubkey)" && new_pub="$(jq -er '."spec.pub"' <<<"$after")" || new_pub=""
  said_rotated=0
  jq -e '.rotated == true' <<<"$rotated" >/dev/null 2>&1 && said_rotated=1
  if ((said_rotated)) || { [[ -n "$new_pub" ]] && [[ "$new_pub" != "$old_pub" ]]; }; then
    if [[ -z "$new_pub" ]]; then
      jq -nc --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg error "mgmtd ctl rotate-key rotated the key, and the new public key could not be read. Run: mise run mgmt -- pubkey" \
        '{time: $time, level: "ERROR", msg: "mgmt-rotate-key failed", error: $error, rotated: true}'
      exit 1
    fi
    epoch="$(mise run mgmt -- status | jq -er '.signed.epoch')" || epoch=0
    log "mgmtd rotated the key, but the answer or the publish of its public half did not arrive: $(jq -r '.error // ""' <<<"$rotated" 2>/dev/null || true)"
  else
    json_fail mgmt-rotate-key "mgmtd ctl rotate-key failed: ${rotated:-no output}"
  fi
fi
[[ "$new_pub" != "$old_pub" ]] || json_fail mgmt-rotate-key "the key did not change"
new_fp="$(fingerprint "$new_pub")"
log "mgmtd signs with a new key at epoch $epoch"

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

jq -nc --arg old "$old_fp" --arg new "$new_fp" --argjson epoch "$epoch" \
  '{rotated: true, old_key_sha256: $old, new_key_sha256: $new, epoch: $epoch}'
