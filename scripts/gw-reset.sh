#!/usr/bin/env bash
# Start the cell gateway with an empty store: mise run gw:reset. Break-glass. Use it when the store of the gateway
# is lost, corrupt or full. The steps run in this order:
#   1. Read the epoch of the old store, when the gateway answers.
#   2. Set the replicas of StatefulSet cell-gateway to 0 through scripts/harness-replicas.sh, and wait until pod
#      cell-gateway-0 is gone.
#   3. Delete PersistentVolumeClaim store-cell-gateway-0, which holds the queue and the outbox.
#      The step fails when the claim does not exist, so a wrong claim name never gives a silent no-op.
#   4. Set the replicas to 1, and wait until the pod is Ready.
#   5. When envd has a ready replica, wait until envd has synced with the new store, so the queue holds the open
#      operations again. celld resends each result that it did not report.
# The script prints one JSON line with the old and the new epoch. A failure prints one JSON error line on standard
# output, and the EXIT trap sets the replicas back to 1. GW_RESET_WAIT bounds each wait in seconds (default 180). The worst case is
# 660 seconds: 180 for the pod to stop, 120 for the claim delete, 180 for the pod to be Ready and 180 for the sync. The drill test bounds
# the whole run at 12 minutes, and its TERM reaches this script before its KILL, so the EXIT trap runs.
# HARNESS_REPLICAS and GW_SCRIPT name other scripts, for the tests.
export CELL=dev-cp
source "$(dirname "$0")/lib.sh"

wait_seconds="${GW_RESET_WAIT:-180}"
[[ "$wait_seconds" =~ ^[0-9]+$ ]] || json_fail gw-reset "GW_RESET_WAIT takes a number of seconds" step=read-wait
ns=gateway-system
replicas="${HARNESS_REPLICAS:-$ROOT/scripts/harness-replicas.sh}"
gw="${GW_SCRIPT:-$ROOT/scripts/gw.sh}"

scale() { "$replicas" "$CELL_NAME" "$ns" statefulset/cell-gateway "$1" >/dev/null; }
poll() {
  local end=$((SECONDS + $1))
  shift
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < end)) || return 1
    sleep 2
  done
}
pod_gone() {
  local out
  out="$(k -n "$ns" get pod cell-gateway-0 --ignore-not-found -o name 2>/dev/null)" || return 1
  [[ -z "$out" ]]
}
pod_ready() { [[ "$(k -n "$ns" get pod cell-gateway-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" == True ]]; }
envd_ready() { [[ "$(k -n envd-system get deployment envd -o jsonpath='{.status.readyReplicas}' 2>/dev/null)" =~ ^[1-9] ]]; }
# synced is true when the gateway reports a sync with envd.
synced() { "$gw" status 2>/dev/null | jq -e '.syncedAt != null and .syncedAt != "0001-01-01T00:00:00Z"' >/dev/null; }

down=0
cleanup() {
  trap - EXIT
  if ((down)); then scale 1 || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

old_epoch="$("$gw" status 2>/dev/null | jq -c '.epoch // null' 2>/dev/null || true)"
[[ -n "$old_epoch" ]] || old_epoch=null

down=1
scale 0 || json_fail gw-reset "could not set the replicas of cell-gateway to 0" step=scale-down
poll "$wait_seconds" pod_gone || json_fail gw-reset "pod cell-gateway-0 did not stop in ${wait_seconds}s" step=wait-gone
k -n "$ns" delete pvc store-cell-gateway-0 --wait=true --timeout=120s >/dev/null \
  || json_fail gw-reset "could not delete PersistentVolumeClaim store-cell-gateway-0, so the store is not wiped" step=delete-pvc
scale 1 || json_fail gw-reset "could not set the replicas of cell-gateway to 1" step=scale-up
down=0
poll "$wait_seconds" pod_ready || json_fail gw-reset "pod cell-gateway-0 is not Ready after ${wait_seconds}s. Run: CELL=dev-cp mise run cell:up" step=wait-ready
if envd_ready; then
  poll "$wait_seconds" synced || json_fail gw-reset "envd has not synced with the new store after ${wait_seconds}s. Read the log: mise x -- kubectl --context kind-dev-cp -n envd-system logs deploy/envd -c envd" step=wait-sync
fi
new_epoch="$("$gw" status 2>/dev/null | jq -c '.epoch // null' 2>/dev/null || true)"
[[ -n "$new_epoch" ]] || new_epoch=null
jq -nc --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson old "$old_epoch" --argjson new "$new_epoch" \
  '{time: $time, level: "INFO", msg: "gw:reset done", oldEpoch: $old, newEpoch: $new}'
