#!/usr/bin/env bash
# Rotate the signing key of the management plane: mise run mgmt -- rotate-signing-key [--emergency | --step <name>] [--force].
#
# The default run is the overlap rotation. Each cell trusts both keys while it rolls, so an operation that mgmtd signed under
# either key applies. The steps run in this order:
#   1. stage:   mgmtd ctl rotate-key --stage makes the next key and publishes it as next.pub in ConfigMap
#               mgmt-system/mgmt-signing-pub. The signing key does not change.
#   2. The script waits until that ConfigMap holds next.pub. Then hostsvc:serve -- sync gives next.pub to the host service, and
#      CELL=dev-cp HARNESS_ONLY=cell-controller mise run cell:up gives it to the cell controller.
#   3. cells:   CELL=<cell> mise run cell:up for each live cell (the cells of harness/topology.yaml with the cell-identity set whose
#               cluster exists). mgmt-op-key then holds the live key and the staged key, and each celld pod restarts with both.
#   4. commit:  mgmtd ctl rotate-key --commit makes the staged key the signing key, re-signs the spec, every record and every
#               open operation at the first revision of the next epoch, and publishes the new key as spec.pub.
#   5. The script waits until that ConfigMap holds the new key. Then hostsvc:serve -- sync gives the new key to the host service,
#      which removes next.pub, because no key is staged.
#   6. planes:  CELL=dev-cp HARNESS_ONLY=envd mise run cell:up and CELL=dev-cp HARNESS_ONLY=cell-controller mise run cell:up render
#               the new key into envd and the cell controller first, so a step that mgmtd re-signed reaches the host service
#               without waiting for the full render. CELL=dev-cp mise run cell:up renders the new key into the cell gateway and
#               the SPIRE server of dev-cp as well. CELL=management mise run cell:link renders it into the link components of
#               management.
#   7. cells:   the cell passes run again. mgmt-op-key then holds the new key alone, and each celld pod restarts with it.
#   8. The script waits until celld of each cluster has finished its rollout. Then cell:verify runs for management and for dev-cp.
# Between the commit and the second cell pass, cell:verify of each cell fails, because mgmt-op-key holds an old key that is neither
# the live key nor a staged key. CELL=<cell> mise run cell:up repairs that.
# --emergency makes a new key at once and skips the stage and the first cell pass: rotate-key --emergency, the wait, the sync, the
# planes, the cell pass and the verify. A staged key moves aside, and the sync removes next.pub from the host service. A cell that refuses an operation meanwhile keeps it queued until the cell
# rolls.
# --step stage|cells|commit|planes runs one step. cells and planes run no verify, so a test can hold a cell down between them.
# stage and commit include their wait and their sync.
# The cell passes and the planes take the lock of their clusters, and an admit stage holds the lock of dev-cp. So the script refuses to
# start while hostsvc:serve -- stages shows a step that runs a stage, or when it cannot read the steps. --force skips that check and
# sets CLUSTER_LOCK_WAIT=900 for each cell command, so that it waits for the lock of the stage.
#
# The script prints one JSON line on standard output: the SHA-256 fingerprints of the old and the new key (of the public key, in
# hex), the new epoch and the run time in seconds. A failure prints one JSON error line on standard output instead, with the failed
# step, rotated (true once the commit or the emergency rotation went through), the fingerprints and the commands that are left. The
# same commands go to standard error as text. Run them in order.
# MGMT_ROTATE_KEY_WAIT bounds each wait in seconds (default 180). Only public key material leaves mgmtd.
export CELL=management
source "$(dirname "$0")/lib.sh"

wait_seconds="${MGMT_ROTATE_KEY_WAIT:-180}"
[[ "$wait_seconds" =~ ^[0-9]+$ ]] || die "MGMT_ROTATE_KEY_WAIT takes a number of seconds"

mode=default
one_step=""
force=0
args=("$@")
if ((${#args[@]} > 0)) && [[ "${args[${#args[@]}-1]}" == --force ]]; then
  force=1
  unset 'args[${#args[@]}-1]'
elif ((${#args[@]} > 0)) && [[ "${args[0]}" == --force ]]; then
  force=1
  args=("${args[@]:1}")
fi
set -- ${args[@]+"${args[@]}"}
case "${1:-}" in
  "") ;;
  --emergency)
    mode=emergency
    (($# == 1)) || die "--emergency takes no other argument"
    ;;
  --step)
    mode=step
    one_step="${2:-}"
    case "$one_step" in stage | cells | commit | planes) ;; *) die "--step takes stage, cells, commit or planes" ;; esac
    (($# == 2)) || die "--step takes one name"
    ;;
  *) die "usage: mgmt-rotate-key.sh [--emergency | --step stage|cells|commit|planes] [--force]" ;;
esac
cd "$ROOT"
started=$SECONDS
if ((force)); then
  export CLUSTER_LOCK_WAIT="${CLUSTER_LOCK_WAIT:-900}"
else
  # hostsvc:serve -- stages prints one line "<id> <cell> <state>" for each step that runs a stage. The mise task header goes to
  # standard error, so only standard output counts.
  stages_err="$(mktemp)"
  if ! running="$(mise run hostsvc:serve -- stages 2>"$stages_err")"; then
    reason="$(tr '\n' ' ' <"$stages_err")"
    rm -f "$stages_err"
    json_fail mgmt-rotate-key "cannot tell whether a step runs a stage, because the read failed: ${reason:-no output}. Read it with: mise run hostsvc:serve -- steps. To go on anyway, add --force"
  fi
  rm -f "$stages_err"
  [[ -z "$running" ]] \
    || json_fail mgmt-rotate-key "a step runs a stage: ${running//$'\n'/; }. Wait until it ends, or cancel it with: mise run hostsvc:serve -- cancel --step <id>. To go on anyway, add --force"
fi

fingerprint() { printf '%s' "$1" | base64 -d | shasum -a 256 | cut -d' ' -f1; }

# The live cells run celld, so each needs both cell passes. A cell that does not exist gets no pass, and its next cell:up pins the live key.
live="$(live_cells)" || json_fail mgmt-rotate-key "kind does not answer, so the live cells are unknown"
cells=()
while IFS= read -r c; do
  [[ -z "$c" ]] || cells+=("$c")
done <<<"$live"

before="$(mise run mgmt -- pubkey)" || json_fail mgmt-rotate-key "could not read the current public key of mgmtd"
old_pub="$(jq -er '."spec.pub"' <<<"$before")" || json_fail mgmt-rotate-key "mgmtd ctl pubkey printed no spec.pub: $before"
old_fp="$(fingerprint "$old_pub")"
new_pub="" new_fp="" next_pub="" epoch=0 rotated_flag=false STEP_REASON=""

# The steps of the run: a name, the command that a person runs by hand, and the function that runs it.
names=() cmds=() funcs=()
add() { names+=("$1"); cmds+=("$2"); funcs+=("$3"); }

cell_up() { CELL="$1" mise run cell:up >&2; }
cell_up_only() { CELL=dev-cp HARNESS_ONLY="$1" mise run cell:up >&2; }
hostsvc_sync() { mise run hostsvc:serve -- sync >&2; }
cell_link() { CELL=management mise run cell:link >&2; }
cell_verify() { CELL="$1" mise run cell:verify >&2; }
rollout() { kubectl --context "kind-$1" -n cell-identity-system rollout status deployment/celld --timeout=300s >&2; }

add_cells() {
  local c
  for c in "${cells[@]}"; do add "cell:up-$c" "CELL=$c mise run cell:up" "cell_up $c"; done
}
# add_staged_sync gives the staged key to the host service and the cell controller, so each trusts next.pub before the commit.
add_staged_sync() {
  add hostsvc-sync-staged "mise run hostsvc:serve -- sync" hostsvc_sync
  add cell-controller-next "CELL=dev-cp HARNESS_ONLY=cell-controller mise run cell:up" "cell_up_only cell-controller"
}
# add_planes renders the new key into envd and the cell controller before the full render of dev-cp, because a step that mgmtd
# re-signed reaches the host service only after envd and the cell controller hold the new key, and the host service holds a re-signed
# step at a stage boundary for 10 minutes at most.
add_planes() {
  add envd-render "CELL=dev-cp HARNESS_ONLY=envd mise run cell:up" "cell_up_only envd"
  add cell-controller-render "CELL=dev-cp HARNESS_ONLY=cell-controller mise run cell:up" "cell_up_only cell-controller"
  add cell:up-dev-cp "CELL=dev-cp mise run cell:up" "cell_up dev-cp"
  add cell:link-management "CELL=management mise run cell:link" cell_link
}
# add_rollout waits until celld of each cluster has finished its rollout, so that cell:verify does not race the new pods.
add_rollout() {
  local c
  for c in "${cells[@]}"; do
    add "rollout-$c" "mise x -- kubectl --context kind-$c -n cell-identity-system rollout status deployment/celld --timeout=300s" "rollout $c"
  done
}
add_verify() {
  add cell:verify-management "CELL=management mise run cell:verify" "cell_verify management"
  add cell:verify-dev-cp "CELL=dev-cp mise run cell:verify" "cell_verify dev-cp"
}
wait_cmd() {
  printf 'mise x -- kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o jsonpath={.data.%s}' "$1"
}

case "$mode" in
  default)
    add stage "mise run mgmt -- rotate-key --stage" do_stage
    add next-published "$(wait_cmd 'next\.pub')" wait_next
    add_staged_sync
    add_cells
    add commit "mise run mgmt -- rotate-key --commit" "do_rotate --commit"
    add publish "$(wait_cmd 'spec\.pub')" wait_new
    add hostsvc-sync-new "mise run hostsvc:serve -- sync" hostsvc_sync
    add_planes
    add_cells
    add_rollout
    add_verify
    ;;
  emergency)
    add emergency "mise run mgmt -- rotate-key --emergency" "do_rotate --emergency"
    add publish "$(wait_cmd 'spec\.pub')" wait_new
    add hostsvc-sync-new "mise run hostsvc:serve -- sync" hostsvc_sync
    add_planes
    add_cells
    add_rollout
    add_verify
    ;;
  step)
    case "$one_step" in
      stage)
        add stage "mise run mgmt -- rotate-key --stage" do_stage
        add next-published "$(wait_cmd 'next\.pub')" wait_next
        add_staged_sync
        ;;
      cells) add_cells ;;
      commit)
        add commit "mise run mgmt -- rotate-key --commit" "do_rotate --commit"
        add publish "$(wait_cmd 'spec\.pub')" wait_new
        add hostsvc-sync-new "mise run hostsvc:serve -- sync" hostsvc_sync
        ;;
      planes) add_planes ;;
    esac
    ;;
esac

# stop <index> <reason> reports a failure: the commands that are left as text on standard error, and one JSON error line on standard
# output with the failed step and the fingerprints. It exits with status 1.
stop() {
  local i="$1" reason="$2" lead left=() j
  for ((j = i; j < ${#cmds[@]}; j++)); do left+=("${cmds[j]}"); done
  if [[ "$rotated_flag" == true ]]; then lead="the signing key rotated, but $reason"; else lead="the signing key did not rotate, because $reason"; fi
  printf 'error: %s. Run these commands in order:\n' "$lead" >&2
  printf '  %s\n' "${left[@]}" >&2
  jq -nc --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg error "$lead" --arg step "${names[i]}" \
    --arg old "$old_fp" --arg new "$new_fp" --argjson rotated "$rotated_flag" --arg cmds "$(printf '%s\n' "${left[@]}")" \
    '{time: $time, level: "ERROR", msg: "mgmt-rotate-key failed", error: $error, rotated: $rotated, step: $step, old_key_sha256: $old, new_key_sha256: $new,
      remaining: ($cmds | split("\n") | map(select(length > 0)))}'
  exit 1
}

# do_stage makes the next key. It sets next_pub, and fails the step when mgmtd prints no next.pub.
do_stage() {
  local out
  out="$(mise run mgmt -- rotate-key --stage)" || { STEP_REASON="mgmtd ctl rotate-key --stage failed: ${out:-no output}"; return 1; }
  next_pub="$(jq -er '."next.pub"' <<<"$out")" || { STEP_REASON="mgmtd ctl rotate-key --stage printed no next.pub: $out"; return 1; }
  new_fp="$(fingerprint "$next_pub")"
  log "mgmtd staged a key with the SHA-256 $new_fp"
}

# poll_pub <jsonpath key> <value> waits until a key of ConfigMap mgmt-signing-pub equals the value, within wait_seconds.
poll_pub() {
  local key="$1" want="$2" end=$((SECONDS + wait_seconds)) got
  until got="$(kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o "jsonpath={.data.$key}" 2>/dev/null)" && [[ "$got" == "$want" ]]; do
    ((SECONDS < end)) || { STEP_REASON="ConfigMap mgmt-signing-pub does not hold the expected key after ${wait_seconds}s"; return 1; }
    sleep 2
  done
}

wait_next() {
  [[ -n "$next_pub" ]] || { STEP_REASON="mgmtd staged no key"; return 1; }
  poll_pub 'next\.pub' "$next_pub" || return 1
  log "mgmt-signing-pub holds the staged key"
}

wait_new() {
  poll_pub 'spec\.pub' "$new_pub" || return 1
  log "mgmt-signing-pub holds the new key"
}

# do_rotate <--commit|--emergency> runs mgmtd ctl rotate-key. The call can fail with nothing changed, or after the key rotated: the ctl
# error line then says rotated:true, or the answer of the exec was lost. So after any failure the script reads the public key again. A
# key that differs from the old one means the key rotated. Its public half may not have published, and mgmtd retries the publish, so
# the script goes on with the wait.
do_rotate() {
  local flag="$1" out after said_rotated=0
  if out="$(mise run mgmt -- rotate-key "$flag")"; then
    new_pub="$(jq -er '."spec.pub"' <<<"$out")" || { STEP_REASON="mgmtd ctl rotate-key printed no spec.pub: $out"; return 1; }
    epoch="$(jq -er '.signed.epoch' <<<"$out")" || { STEP_REASON="mgmtd ctl rotate-key printed no signed epoch: $out"; return 1; }
  else
    after="$(mise run mgmt -- pubkey)" && new_pub="$(jq -er '."spec.pub"' <<<"$after")" || new_pub=""
    jq -e '.rotated == true' <<<"$out" >/dev/null 2>&1 && said_rotated=1
    if ((said_rotated)) || { [[ -n "$new_pub" ]] && [[ "$new_pub" != "$old_pub" ]]; }; then
      rotated_flag=true
      if [[ -z "$new_pub" ]]; then
        jq -nc --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg error "mgmtd ctl rotate-key rotated the key, and the new public key could not be read. Run: mise run mgmt -- pubkey" \
          '{time: $time, level: "ERROR", msg: "mgmt-rotate-key failed", error: $error, rotated: true}'
        exit 1
      fi
      epoch="$(mise run mgmt -- status | jq -er '.signed.epoch')" || epoch=0
      log "mgmtd rotated the key, but the answer or the publish of its public half did not arrive: $(jq -r '.error // ""' <<<"$out" 2>/dev/null || true)"
    else
      STEP_REASON="mgmtd ctl rotate-key $flag failed: ${out:-no output}"
      return 1
    fi
  fi
  if [[ "$new_pub" == "$old_pub" ]]; then
    rotated_flag=false
    STEP_REASON="the key did not change"
    return 1
  fi
  rotated_flag=true
  new_fp="$(fingerprint "$new_pub")"
  if [[ "$flag" == --commit && -n "$next_pub" && "$new_pub" != "$next_pub" ]]; then
    STEP_REASON="the key that mgmtd committed is not the key that this run staged"
    return 1
  fi
  log "mgmtd signs with a new key at epoch $epoch"
}

# A run of the commit step alone has no stage step before it: read the staged key, so that the commit can check it. The key must hash
# to stagedKey of mgmtd, as the cell render requires, or the commit stops before it changes anything.
if [[ "$mode" == step && "$one_step" == commit ]]; then
  next_pub="$(kubectl --context kind-management -n mgmt-system get configmap mgmt-signing-pub -o 'jsonpath={.data.next\.pub}' 2>/dev/null)" || next_pub=""
  [[ -n "$next_pub" ]] || json_fail mgmt-rotate-key "ConfigMap mgmt-signing-pub holds no next.pub, so no key is staged. Run: mise run mgmt -- rotate-signing-key --step stage"
  staged_hash="$(mise run mgmt -- status | jq -er '.stagedKey // ""')" || json_fail mgmt-rotate-key "could not read stagedKey from mise run mgmt -- status"
  [[ "$(fingerprint "$next_pub")" == "$staged_hash" ]] \
    || json_fail mgmt-rotate-key "next.pub of mgmt-signing-pub has the SHA-256 $(fingerprint "$next_pub"), and mgmtd shows the staged key '${staged_hash:-none}'. Run: mise run mgmt -- status"
  new_fp="$(fingerprint "$next_pub")"
fi
# A run of the cells or the planes step alone changes no key.
if [[ "$mode" == step && ( "$one_step" == cells || "$one_step" == planes ) ]]; then
  new_fp="$old_fp"
fi

for i in "${!funcs[@]}"; do
  STEP_REASON=""
  # shellcheck disable=SC2086
  if ! ${funcs[i]}; then
    stop "$i" "${STEP_REASON:-${names[i]} failed}"
  fi
done

secs=$((SECONDS - started))
if [[ "$mode" == step && "$one_step" == stage ]]; then
  stage_epoch="$(mise run mgmt -- status | jq -er '.signed.epoch')" || json_fail mgmt-rotate-key "the key is staged, but the epoch could not be read from mise run mgmt -- status" staged:=true
  jq -nc --arg old "$old_fp" --arg new "$new_fp" --argjson epoch "$stage_epoch" --argjson seconds "$secs" \
    '{rotated: false, staged: true, old_key_sha256: $old, new_key_sha256: $new, epoch: $epoch, seconds: $seconds}'
elif [[ "$mode" == step && ( "$one_step" == cells || "$one_step" == planes ) ]]; then
  jq -nc --arg key "$old_fp" --arg step "$one_step" --argjson seconds "$secs" '{rotated: false, step: $step, key_sha256: $key, seconds: $seconds}'
else
  jq -nc --arg old "$old_fp" --arg new "$new_fp" --argjson epoch "$epoch" --argjson seconds "$secs" \
    '{rotated: true, old_key_sha256: $old, new_key_sha256: $new, epoch: $epoch, seconds: $seconds}'
fi
