#!/usr/bin/env bash
# Report the state of the mesh view of management, one line for each part, so that an operator finds the
# part that fails. The hub log gives the tunnel state of each cell by conn_id (hub_cell_up in
# scripts/lib.sh). The tunnel pod is read in its own cell. Exit status 1 when a part is not up.
source "$(dirname "$0")/lib.sh"

[[ -n "${MESH_VIEW_CELLS:-}" ]] || die "cluster $CELL_NAME has no MESH_VIEW_CELLS. Run: CELL=management mise run mesh:status"
status=0
# The state comes from the hub process itself (cell-proxy tunnel-status). The log of the hub by conn_id is
# the fallback when the process does not answer.
hub_json="$(hub_status)" || hub_json=""
logs="$(k -n mesh-view-system logs deploy/mesh-view-hub -c cell-proxy 2>&1)" || die "could not read the log of the hub: $logs"
for entry in $MESH_VIEW_CELLS; do
  cell="${entry%%=*}"
  if [[ -n "$hub_json" ]]; then
    line="$(CELL_ARG="$cell" jq -r '.cells[env.CELL_ARG] | if .up then "tunnel up (conn_id \(.conn_id), \(.age_seconds | floor) s old)" else "no open tunnel for \(.down_seconds | floor) s" end
      + (if .last_end then ", last end \(.last_end.cause) \(.last_end.detail // "")" else "" end)' <<<"$hub_json")"
    if CELL_ARG="$cell" jq -e '.cells[env.CELL_ARG].up == true' <<<"$hub_json" >/dev/null; then
      echo "hub    $cell: $line"
    else
      echo "hub    $cell: $line. Run: CELL=$cell mise run cell:up"
      status=1
    fi
  elif hub_cell_up "$cell" <<<"$logs"; then
    echo "hub    $cell: tunnel up (from the hub log, the hub process did not answer)"
  else
    echo "hub    $cell: no open tunnel (from the hub log). Run: CELL=$cell mise run cell:up"
    status=1
  fi
  refused="$(CELL_ARG="$cell" jq -Rr 'fromjson? | select(.cell == env.CELL_ARG and .msg == "tunnel_refused") | "\(.time) \(.reason)"' <<<"$logs" | tail -n 1)"
  [[ -z "$refused" ]] || echo "hub    $cell: last refusal $refused"
  ready="$(kubectl --context "kind-$cell" -n mesh-view-system get deployment mesh-view -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
  own="$(kubectl --context "kind-$cell" -n mesh-view-system exec deploy/mesh-view -c cell-proxy -- /ko-app/cell-proxy tunnel-status 2>/dev/null | jq -r '.cells.self | if .up then "tunnel up \(.age_seconds | floor) s" else "tunnel down \(.down_seconds | floor) s" end' 2>/dev/null || true)"
  if [[ "${ready:-0}" == 1 ]]; then
    echo "pod    $cell: mesh-view Ready (${own:-no state})"
  else
    echo "pod    $cell: mesh-view not Ready. Run: CELL=$cell mise run cell:verify"
    status=1
  fi
done
ready="$(k -n mesh-view-system get deployment kiali -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
if [[ "${ready:-0}" == 1 ]]; then
  echo "kiali  $CELL_NAME: Ready"
else
  echo "kiali  $CELL_NAME: not Ready. Kiali waits for every cell tunnel before it serves. Run: CELL=management mise run cell:link"
  status=1
fi
exit "$status"
