#!/usr/bin/env bash
# Create, check and rotate the operator key: mise run operator:create-key, operator:check-key, operator:rotate-key [-- --emergency].
#
# The operator key is an Ed25519 key that signs local revocations on this Mac. Its seed lives only in the secret manager, at the
# remote key <POC_OPERATOR_KEY>/<UTC time yyyymmddThhmmssZ>. The seed moves only through pipes between the read or write command
# and operatorctl. No file, shell variable, argument or log line holds it.
# ConfigMap mgmt-system/operator-pub in management holds the public key (spec.pub), the remote key name (spec.name), and the next
# public key during a rotation (next.pub). The renders pin its keys in envd, the cell gateway and the SPIRE server of dev-cp, and
# mgmtd mounts it. build/operator/key.env holds the key name and the SHA-256 of the public key, both public. Without key.env, each
# command reads the key name from spec.name of operator-pub.
#
# Settings in .envrc.local, as in .envrc.local.example: POC_SECRET_READ_CMD, POC_SECRET_WRITE_CMD and POC_OPERATOR_KEY.
#
# create  Owner action, once. It refuses when key.env or operator-pub exists. keygen pipes a new seed into the write command.
#         The read command pipes it back into operatorctl pub, and the two public keys must match. Only then does create write
#         operator-pub and key.env. It prints one JSON line with keyName, keySHA256 and the next commands. A failed write or
#         read-back writes no pin. Run create again after the fix. It writes a new remote key.
# check   The read command pipes the seed into operatorctl pub. check compares that public key with operator-pub, each pin in
#         dev-cp and key.env. It prints one JSON line with match, one field for each pin, and the names of the pins that differ.
#         It exits 1 when a pin differs.
# rotate  It refuses while not connected, while a cut of the partition tool or the slow-tier marker exists, and while envd holds
#         a local revocation entry. It checks all of these before it reads the secret manager. The default is the overlap. A new
#         key goes to next.pub, the renders pin both keys, and cell:verify runs. Then the new key replaces the old one, the renders
#         pin it alone, and cell:verify runs again. --emergency replaces the old key at once. Use it for a lost or leaked key, or
#         to finish a rotation that stopped. The old seed stays in the secret manager. Delete it there by hand.
#
# The owner creates the key once:
#   1. Add this line to .envrc.local: export POC_OPERATOR_KEY='<remote key prefix for the operator key>'
#   2. Run: mise run operator:create-key
#   3. Run: CELL=dev-cp mise run cell:up
#   4. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link
#   5. Run: mise run operator:check-key. Expected: "match":true.
# A failure prints one JSON error line on standard output. No error line holds the output of the read command.
export CELL=management
source "$(dirname "$0")/lib.sh"
source "$ROOT/components/lib/operator-key.sh"
cd "$ROOT"

key_dir="$BUILD_ROOT/operator"
key_env="$key_dir/key.env"
marker="$BUILD_ROOT/gate/m9-svid-ttl"
started=$SECONDS

usage() { awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"; }

fail() { json_fail operator-key "$@"; }

# need_settings <name...> reads .envrc.local when a setting is unset, and fails when one is still unset.
need_settings() {
  local name
  load_local_settings "$@"
  for name in "$@"; do
    [[ -n "${!name:-}" ]] || fail "$name is not set. Copy it from .envrc.local.example to .envrc.local and complete it. direnv loads .envrc.local after you run direnv allow, and this script reads it when a setting is unset"
  done
}

# key_name_now prints a new remote key name: the prefix, a slash and the UTC time.
key_name_now() { printf '%s/%s\n' "$POC_OPERATOR_KEY" "$(date -u +%Y%m%dT%H%M%SZ)"; }

# sha_of_pub <key> prints the lowercase hex SHA-256 of the 32 bytes of a public key, as revoke.KeySHA256 does.
sha_of_pub() { printf '%s' "$1" | base64 -d | sha256; }

# key_env_value <name> prints one value of key.env. The file holds public data, and the script never sources it.
key_env_value() { sed -n "s/^$1=//p" "$key_env" | head -n 1; }

write_key_env() {
  mkdir -p "$key_dir" && printf 'OPERATOR_KEY_NAME=%s\nOPERATOR_KEY_SHA256=%s\n' "$1" "$2" >"$key_env.new" && mv "$key_env.new" "$key_env"
}

# read_operator_pub sets PUB_CM to ConfigMap operator-pub as JSON, or to nothing when it is absent.
read_operator_pub() {
  PUB_CM="$(operator_pub_cm)" || fail "could not read ConfigMap mgmt-system/operator-pub in management. Run: mise run harness:status"
}

pub_field() { printf '%s' "$PUB_CM" | jq -r --arg k "$1" '.data[$k] // ""'; }

# write_operator_pub <create|replace> <spec.pub> <spec.name> [next.pub] writes ConfigMap mgmt-system/operator-pub with field manager
# operator. create fails when the ConfigMap exists. replace keeps the resourceVersion of PUB_CM, so a change since that read fails it.
write_operator_pub() {
  local verb="$1" base='{"metadata":{}}'
  [[ "$verb" == create ]] || base="$PUB_CM"
  printf '%s' "$base" | jq -c --arg spec "$2" --arg name "$3" --arg next "${4:-}" '{apiVersion: "v1", kind: "ConfigMap",
      metadata: ((.metadata // {} | with_entries(select(.key == "resourceVersion" or .key == "labels" or .key == "annotations")))
        + {name: "operator-pub", namespace: "mgmt-system"}),
      data: ({"spec.pub": $spec, "spec.name": $name} + (if $next == "" then {} else {"next.pub": $next} end))}' \
    | kubectl --context kind-management -n mgmt-system "$verb" --field-manager=operator -f - >&2
}

# new_key <name> makes a key at the remote key <name>. keygen pipes the seed into the write command and writes the public key to
# build/operator/new.pub. Then the read command pipes the seed back into operatorctl pub. When both public keys agree, it sets NEW_PUB.
# Otherwise it sets STEP_REASON and returns 1.
new_key() {
  local name="$1" pub_file="$key_dir/new.pub" want got
  NEW_PUB=""
  mkdir -p "$key_dir" || { STEP_REASON="could not create $key_dir"; return 1; }
  rm -f "$pub_file"
  if ! mise run operatorctl -- keygen --public-file "$pub_file" | bash -c "$POC_SECRET_WRITE_CMD" _ "$name" >&2; then
    rm -f "$pub_file"
    STEP_REASON="keygen or POC_SECRET_WRITE_CMD failed for the remote key $name. Delete any value there by hand"
    return 1
  fi
  want="$(cat "$pub_file" 2>/dev/null)" || want=""
  rm -f "$pub_file"
  if ! operator_key_valid "$want"; then
    STEP_REASON="keygen wrote no public key. Delete the value at the remote key $name by hand"
    return 1
  fi
  if ! got="$(bash -c "$POC_SECRET_READ_CMD" _ "$name" | mise run operatorctl -- pub)"; then
    STEP_REASON="the read back of the remote key $name through POC_SECRET_READ_CMD and operatorctl pub failed ($(printf '%s' "$got" | jq -r '.error // empty' 2>/dev/null || true)). Delete the value at $name by hand"
    return 1
  fi
  if [[ "$got" != "$want" ]]; then
    STEP_REASON="the public key of the read back of the remote key $name differs from the key that keygen made. Delete the value at $name by hand"
    return 1
  fi
  NEW_PUB="$want"
}

cmd_create() {
  (($# == 0)) || fail "create takes no argument"
  need_settings POC_SECRET_READ_CMD POC_SECRET_WRITE_CMD POC_OPERATOR_KEY
  [[ "$POC_OPERATOR_KEY" =~ ^[^[:space:]]*[^[:space:]/]$ ]] || fail "POC_OPERATOR_KEY must be one word with no slash at the end"
  [[ ! -e "$key_env" ]] \
    || fail "build/operator/key.env exists, so an operator key exists. Compare it with: mise run operator:check-key. Replace it with: mise run operator:rotate-key"
  read_operator_pub
  [[ -z "$PUB_CM" ]] \
    || fail "ConfigMap mgmt-system/operator-pub exists in management, so an operator key exists. Compare it with: mise run operator:check-key. Replace it with: mise run operator:rotate-key"
  local name sha
  name="$(key_name_now)"
  log "writing a new operator key to the remote key $name"
  new_key "$name" || fail "$STEP_REASON. No pin was written. Run: mise run operator:create-key"
  write_operator_pub create "$NEW_PUB" "$name" \
    || fail "the secret manager holds the new key at $name, but ConfigMap mgmt-system/operator-pub could not be written. No pin was written. Delete the value at $name by hand, then run: mise run operator:create-key"
  sha="$(sha_of_pub "$NEW_PUB")"
  write_key_env "$name" "$sha" || fail "operator-pub holds the new key, but build/operator/key.env could not be written. The commands read spec.name of operator-pub instead"
  log "created the operator key $sha. Run next: CELL=dev-cp mise run cell:up, then CELL=management LINK_ONLY=mgmt-api mise run cell:link, then mise run operator:check-key"
  jq -nc --arg name "$name" --arg sha "$sha" '{created: true, keyName: $name, keySHA256: $sha,
    next: ["CELL=dev-cp mise run cell:up", "CELL=management LINK_ONLY=mgmt-api mise run cell:link", "mise run operator:check-key"]}'
}

cmd_check() {
  (($# == 0)) || fail "check takes no argument"
  need_settings POC_SECRET_READ_CMD
  read_operator_pub
  [[ -n "$PUB_CM" ]] || fail "ConfigMap mgmt-system/operator-pub is absent in management. The owner creates the key once with: mise run operator:create-key"
  local spec next spec_name name derived sha which pinned env_name env_sha
  local -a names=() oks=() mismatch=()
  spec="$(pub_field spec.pub)"
  next="$(pub_field next.pub)"
  spec_name="$(pub_field spec.name)"
  name="$spec_name"
  [[ ! -f "$key_env" ]] || name="$(key_env_value OPERATOR_KEY_NAME)"
  [[ -n "$name" ]] || fail "neither build/operator/key.env nor spec.name of operator-pub names the remote key"
  derived="$(bash -c "$POC_SECRET_READ_CMD" _ "$name" | mise run operatorctl -- pub)" \
    || fail "the read of the remote key $name through POC_SECRET_READ_CMD and operatorctl pub failed ($(printf '%s' "$derived" | jq -r '.error // empty' 2>/dev/null || true))"
  sha="$(sha_of_pub "$derived")"

  # Each pin must hold the key of the secret manager alone. A next.pub outside a rotation is a mismatch of operator-pub.
  names+=(operatorPub)
  if [[ "$spec" == "$derived" && -z "$next" ]]; then oks+=(true); else oks+=(false); mismatch+=("management mgmt-system/operator-pub"); fi
  for which in envd gateway server; do
    pinned="$(operator_pin dev-cp "$which")" || fail "could not read the pin $(operator_pin_name dev-cp "$which"). Run: mise run harness:status"
    case "$which" in server) names+=(serverConf) ;; *) names+=("$which") ;; esac
    if [[ "$pinned" == "$derived" ]]; then oks+=(true); else oks+=(false); mismatch+=("$(operator_pin_name dev-cp "$which")"); fi
  done
  if [[ -f "$key_env" ]]; then
    env_name="$(key_env_value OPERATOR_KEY_NAME)"
    env_sha="$(key_env_value OPERATOR_KEY_SHA256)"
    names+=(keyEnv)
    if [[ "$env_sha" == "$sha" && "$env_name" == "$spec_name" ]]; then oks+=(true); else oks+=(false); mismatch+=("build/operator/key.env"); fi
  fi

  local fields='{}' i
  for i in "${!names[@]}"; do
    fields="$(printf '%s' "$fields" | jq -c --arg k "${names[i]}" --argjson v "${oks[i]}" '.[$k] = $v')"
  done
  printf '%s' "$fields" | jq -c --arg name "$name" --arg sha "$sha" --arg mm "$(printf '%s\n' ${mismatch[@]+"${mismatch[@]}"})" \
    '{match: ($mm == ""), keyName: $name, keySHA256: $sha} + . + {mismatch: ($mm | split("\n") | map(select(length > 0)))}'
  if ((${#mismatch[@]} > 0)); then
    printf 'error: these pins differ from the key in the secret manager: %s. If the secret manager holds the right key, render the pins with: OPERATOR_KEY_ACCEPT_CHANGE=1 CELL=dev-cp mise run cell:up\n' \
      "$(printf '%s; ' "${mismatch[@]}" | sed 's/; $//')" >&2
    exit 1
  fi
  log "every pin holds the operator key $sha"
}

# refuse_rotation fails when the rotation must not start: while not connected, while a cut of the partition tool or the slow-tier
# marker exists, or while envd holds a local revocation entry. It reads no secret.
refuse_rotation() {
  local reason clusters c tool rules records held
  reason="$(operator_connected 2>&1)" \
    || fail "the rotation needs a connected environment, and the check says: ${reason#error: }"
  clusters="$(existing_clusters)" || fail "kind does not answer, so a cut of the partition tool cannot be ruled out"
  for c in $clusters; do
    for tool in iptables ip6tables; do
      rules="$(docker exec "$c-control-plane" "$tool" -S)" \
        || fail "could not read the $tool rules of $c-control-plane, so a cut cannot be ruled out. Run: mise run harness:status"
      [[ "$rules" != *gate-m9-cut-* ]] \
        || fail "a cut of the partition tool is in place on $c-control-plane ($tool). List it with: mise run partition -- list. Heal it with: mise run partition -- heal"
    done
  done
  [[ ! -e "$marker" ]] \
    || fail "the slow-tier marker build/gate/m9-svid-ttl exists, so a slow tier runs or stopped early. Repair it with: mise run gate:m9:repair"
  records="$(kubectl --context kind-dev-cp -n spire-system get configmap cell-records -o json)" \
    || fail "could not read ConfigMap spire-system/cell-records in dev-cp, so the local revocation entries that envd holds are unknown"
  held="$(printf '%s' "$records" | jq -r '.data["local-revocations.json"] // "[]" | fromjson
    | if type != "array" then error("not an array") else . end
    | if length == 0 then "" else "\(length) (\([.[] | (try (.payload | @base64d | fromjson | .cell // "unknown") catch "unknown")] | join(", ")))" end')" \
    || fail "key local-revocations.json of ConfigMap spire-system/cell-records in dev-cp is no JSON array, so the held entries are unknown"
  [[ -z "$held" ]] \
    || fail "envd holds local revocation entries for these cells: $held. A rotation would drop each held entry at its next verification. Settle them first: mise run mgmt -- status, then mise run revoke -- clean"
}

# The steps of a rotation after the new key exists. Each step has a name, the command that a person runs by hand, and its function.
names=() cmds=() funcs=()
add() { names+=("$1"); cmds+=("$2"); funcs+=("$3"); }

render_dev_cp() { OPERATOR_KEY_ACCEPT_CHANGE=1 CELL=dev-cp mise run cell:up >&2; }
link_management() { OPERATOR_KEY_ACCEPT_CHANGE=1 CELL=management LINK_ONLY=mgmt-api mise run cell:link >&2; }
verify_cluster() { CELL="$1" mise run cell:verify >&2; }

add_renders() {
  add render-dev-cp "OPERATOR_KEY_ACCEPT_CHANGE=1 CELL=dev-cp mise run cell:up" render_dev_cp
  add link-management "OPERATOR_KEY_ACCEPT_CHANGE=1 CELL=management LINK_ONLY=mgmt-api mise run cell:link" link_management
  add verify-dev-cp "CELL=dev-cp mise run cell:verify" "verify_cluster dev-cp"
  add verify-management "CELL=management mise run cell:verify" "verify_cluster management"
}

set_next() {
  read_operator_pub
  write_operator_pub replace "$old_pub" "$old_name" "$NEW_PUB" || { STEP_REASON="ConfigMap mgmt-system/operator-pub could not take next.pub"; return 1; }
}

switch_key() {
  read_operator_pub
  write_operator_pub replace "$NEW_PUB" "$new_name" || { STEP_REASON="ConfigMap mgmt-system/operator-pub could not take the new key"; return 1; }
  switched=true
  write_key_env "$new_name" "$new_sha" || { STEP_REASON="build/operator/key.env could not be written. The commands read spec.name of operator-pub instead"; return 1; }
  log "operator-pub holds the new key $new_sha alone"
}

# stop <index> <reason> prints the commands that are left on standard error and one JSON error line on standard output, and exits 1.
stop() {
  local i="$1" reason="$2" left=() j lead
  if [[ "$switched" == true ]]; then
    for ((j = i + 1; j < ${#cmds[@]}; j++)); do left+=("${cmds[j]}"); done
    [[ "${names[i]}" == switch ]] || left=("${cmds[i]}" ${left[@]+"${left[@]}"})
    lead="the new key $new_sha is in force in operator-pub, but $reason"
  else
    left=("mise run operator:rotate-key -- --emergency")
    lead="the rotation stopped before the switch, because $reason. The secret manager holds an unused key at $new_name"
  fi
  printf 'error: %s. Run these commands in order:\n' "$lead" >&2
  printf '  %s\n' "${left[@]}" >&2
  json_fail operator-key "$lead" "step=${names[i]}" "switched:=$switched" "remaining=$(printf '%s; ' "${left[@]}" | sed 's/; $//')"
}

cmd_rotate() {
  local mode=overlap
  case "${1:-}" in
    "") ;;
    --emergency) mode=emergency ;;
    *) fail "usage: operator-key.sh rotate [--emergency]" ;;
  esac
  (($# <= 1)) || fail "usage: operator-key.sh rotate [--emergency]"
  need_settings POC_SECRET_READ_CMD POC_SECRET_WRITE_CMD POC_OPERATOR_KEY
  [[ "$POC_OPERATOR_KEY" =~ ^[^[:space:]]*[^[:space:]/]$ ]] || fail "POC_OPERATOR_KEY must be one word with no slash at the end"
  read_operator_pub
  [[ -n "$PUB_CM" ]] || fail "ConfigMap mgmt-system/operator-pub is absent in management, so there is no key to rotate. The owner creates it with: mise run operator:create-key"
  old_pub="$(pub_field spec.pub)"
  old_name="$(pub_field spec.name)"
  operator_key_valid "$old_pub" || fail "key spec.pub of operator-pub is not the standard base64 of 32 bytes. Replace the key with: mise run operator:rotate-key -- --emergency"
  if [[ "$mode" == overlap && -n "$(pub_field next.pub)" ]]; then
    fail "operator-pub holds next.pub, so an earlier rotation stopped. Finish it with a new key: mise run operator:rotate-key -- --emergency"
  fi
  refuse_rotation

  old_sha="$(sha_of_pub "$old_pub")"
  new_name="$(key_name_now)"
  if [[ "$new_name" == "$old_name" ]]; then
    sleep 1
    new_name="$(key_name_now)"
  fi
  log "writing the next operator key to the remote key $new_name ($mode rotation)"
  new_key "$new_name" || fail "$STEP_REASON. No pin changed. Run the rotation again"
  new_sha="$(sha_of_pub "$NEW_PUB")"
  switched=false
  if [[ "$mode" == overlap ]]; then
    add next "write next.pub to ConfigMap mgmt-system/operator-pub" set_next
    add_renders
  fi
  add switch "write the new key alone to ConfigMap mgmt-system/operator-pub" switch_key
  add_renders
  local i
  for i in "${!funcs[@]}"; do
    STEP_REASON=""
    # shellcheck disable=SC2086
    ${funcs[i]} || stop "$i" "${STEP_REASON:-${names[i]} failed}"
  done
  log "rotated the operator key from $old_sha to $new_sha. Delete the old seed at the remote key $old_name by hand"
  jq -nc --arg mode "$mode" --arg old "$old_sha" --arg new "$new_sha" --arg oldName "$old_name" --arg newName "$new_name" \
    --argjson seconds "$((SECONDS - started))" \
    '{rotated: true, mode: $mode, oldKeyName: $oldName, oldKeySHA256: $old, newKeyName: $newName, newKeySHA256: $new, seconds: $seconds}'
}

case "${1:-}" in
  create) shift; cmd_create "$@" ;;
  check) shift; cmd_check "$@" ;;
  rotate) shift; cmd_rotate "$@" ;;
  help | -h | --help) usage ;;
  *) usage >&2; exit 2 ;;
esac
