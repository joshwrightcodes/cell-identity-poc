#!/usr/bin/env bash
# Wait for the first attestation of celld in one cell, stage by stage, so a failure names the stage.
# Usage: attest-wait.sh <cell>
#
# cell:up runs it for the cell-identity component in place of the plain rollout wait. When
# `mise run mgmt -- status` does not answer, the management plane is not up. The script then prints the
# link command as a warning and exits 0 without a wait, because no bind can happen.
# Otherwise it runs four stages, each with its own limit:
#   bound     mgmt -- status shows the cell bound, within 120 s.
#   applied   ConfigMap cell-records in the SPIRE server cluster holds the spec revision of the record
#             of the cell, within 60 s.
#   reloaded  the log of the SPIRE server has "records reloaded" with the cell, within 150 s. The
#             kubelet syncs the ConfigMap volume, and the plugin reloads it every 10 s.
#   ready     the rollout of celld finishes, within 300 s. A spire-agent container in CrashLoopBackOff at the
#             start of this stage gets its pod deleted once, because the back-off grows with each crash.
# Each stage prints its time. A failing stage prints its name, the reason and the next command, and
# the script exits 1. ATTEST_BOUND_WAIT, ATTEST_APPLIED_WAIT, ATTEST_RELOADED_WAIT, ATTEST_READY_WAIT and
# ATTEST_POLL (seconds) change the limits and the poll interval, for the tests.
source "$(dirname "$0")/lib.sh"

cell="${1:-$CELL_NAME}"
[[ "$cell" == "$CELL_NAME" ]] || die "attest-wait.sh got the cell $cell, and CELL is $CELL_NAME"
server_cluster="${SPIRE_SERVER_CLUSTER:-dev-cp}"
poll="${ATTEST_POLL:-3}"
link="CELL=management LINK_ONLY=mgmt-api mise run cell:link"

# mgmt_status prints the status of mgmtd. It fails when the command fails or prints no JSON object.
mgmt_status() {
  local out
  out="$(cd "$ROOT" && mise run mgmt -- status 2>/dev/null)" || return 1
  jq -e 'type == "object"' <<<"$out" >/dev/null 2>&1 || return 1
  printf '%s\n' "$out"
}
ctx() { kubectl --context "kind-$1" "${@:2}"; }

fail() {
  local stage="$1" reason="$2" next="$3"
  printf 'error: attest-wait %s: stage %s failed: %s\n' "$cell" "$stage" "$reason" >&2
  printf 'Next: %s\n' "$next" >&2
  exit 1
}

# poll_until <limit seconds> <command...> runs the command until it succeeds or the limit passes.
poll_until() {
  local limit="$1" end=$((SECONDS + $1))
  shift
  until "$@"; do
    ((SECONDS < end)) || return 1
    sleep "$poll"
  done
}

status_json=""
cell_bound() {
  status_json="$(mgmt_status)" || return 1
  jq -e --arg cell "$cell" 'any(.cells[]?; .name == $cell and .bound == true)' <<<"$status_json" >/dev/null
}

if ! status_json="$(mgmt_status)"; then
  printf 'warning: attest-wait %s: mise run mgmt -- status does not answer, so no bind can happen and the wait is skipped. Run: %s\n' "$cell" "$link" >&2
  exit 0
fi

stage_start=$SECONDS
if ! poll_until "${ATTEST_BOUND_WAIT:-120}" cell_bound; then
  celld_line="$(ctx "$cell" -n cell-identity-system logs deploy/celld -c celld --tail=200 2>&1 | grep -i bind | tail -n 1 || true)"
  denial="$(ctx management -n mgmt-system logs mgmtd-0 -c mgmtd --tail=300 2>&1 | grep bind_denied | grep -F "\"$cell\"" | tail -n 1 || true)"
  fail bound "mgmtd does not show $cell as bound after $((SECONDS - stage_start))s. Last celld bind log line: ${celld_line:-none}. Last mgmtd denial for $cell: ${denial:-none}" \
    "mise x -- kubectl --context kind-$cell -n cell-identity-system logs deploy/celld -c celld, and mise run mgmt -- status"
fi
log "attest-wait $cell: stage bound took $((SECONDS - stage_start))s"

# The record of the cell has a spec revision. The ConfigMap must hold that revision or a later one.
want_epoch="$(jq -r --arg cell "$cell" '[.cells[] | select(.name == $cell)][0].record.epoch' <<<"$status_json")"
want_counter="$(jq -r --arg cell "$cell" '[.cells[] | select(.name == $cell)][0].record.counter' <<<"$status_json")"
records_applied() {
  local cm epoch counter
  cm="$(ctx "$server_cluster" -n spire-system get configmap cell-records -o json 2>/dev/null)" || return 1
  epoch="$(jq -r '.metadata.annotations["poc.internal/spec-epoch"] // "0"' <<<"$cm")"
  counter="$(jq -r '.metadata.annotations["poc.internal/spec-counter"] // "0"' <<<"$cm")"
  ((epoch > want_epoch || (epoch == want_epoch && counter >= want_counter)))
}
stage_start=$SECONDS
if ! poll_until "${ATTEST_APPLIED_WAIT:-60}" records_applied; then
  now="$(mgmt_status || true)"
  refusal="$(jq -c '.lastRefusal // "none"' <<<"${now:-null}" 2>/dev/null || echo none)"
  store_error="$(jq -r '.storeError // "none"' <<<"${now:-null}" 2>/dev/null || echo none)"
  fail applied "ConfigMap cell-records in $server_cluster does not reach the revision $want_epoch/$want_counter of the record of $cell after $((SECONDS - stage_start))s. lastRefusal: $refusal. storeError: $store_error" \
    "mise x -- kubectl --context kind-$server_cluster -n envd-system logs deploy/envd -c envd, and mise run mgmt -- status"
fi
log "attest-wait $cell: stage applied took $((SECONDS - stage_start))s"

records_reloaded() {
  ctx "$server_cluster" -n spire-system logs spire-server-0 -c spire-server --tail=500 2>/dev/null \
    | grep -F 'records reloaded' | grep -qF "\"$cell\""
}
stage_start=$SECONDS
if ! poll_until "${ATTEST_RELOADED_WAIT:-150}" records_reloaded; then
  fail reloaded "the log of the SPIRE server in $server_cluster has no 'records reloaded' with $cell after $((SECONDS - stage_start))s. The kubelet syncs the ConfigMap volume of the server pod before the plugin reloads it (verify row 1: the time from the write to the log line; row 5: a volume that was absent at pod start)" \
    "mise x -- kubectl --context kind-$server_cluster -n spire-system logs spire-server-0 -c spire-server --tail=100, then CELL=$server_cluster mise run cell:restart"
fi
log "attest-wait $cell: stage reloaded took $((SECONDS - stage_start))s"

stage_start=$SECONDS
crashing="$(k -n cell-identity-system get pods -l app.kubernetes.io/name=celld -o json 2>/dev/null \
  | jq -r '.items[] | select(any(.status.containerStatuses[]?; .name == "spire-agent" and .state.waiting.reason == "CrashLoopBackOff")) | .metadata.name')" || crashing=""
for pod in $crashing; do
  log "attest-wait $cell: spire-agent in $pod is in CrashLoopBackOff, so the pod is deleted once (verify row 2)"
  k -n cell-identity-system delete pod "$pod" --wait=false >/dev/null || fail ready "could not delete the pod $pod" "mise x -- kubectl --context kind-$cell -n cell-identity-system delete pod $pod"
done
if ! k -n cell-identity-system rollout status deployment/celld --timeout="${ATTEST_READY_WAIT:-300}s" >/dev/null 2>&1; then
  fail ready "deployment/celld in $cell did not finish its rollout in ${ATTEST_READY_WAIT:-300}s" \
    "mise x -- kubectl --context kind-$cell -n cell-identity-system describe deployment/celld, and logs deploy/celld --all-containers"
fi
log "attest-wait $cell: stage ready took $((SECONDS - stage_start))s"
