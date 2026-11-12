#!/usr/bin/env bash
# Report the state of the mesh view of management, one line for each part, so that an operator finds the
# part that fails. The hub process serves the tunnel state of each cell, and the tunnel pod serves its own
# state in its cell (cell-proxy tunnel-status). The log of the hub by conn_id is the fallback (hub_cell_up in
# scripts/lib.sh). Exit status 1 when a part is not up.
source "$(dirname "$0")/lib.sh"

[[ -n "${MESH_VIEW_CELLS:-}" ]] || die "cluster $CELL_NAME has no MESH_VIEW_CELLS. Run: CELL=management mise run mesh:status"
status=0
# down_hint <cell> says what to run for a hub tunnel that is down. A cell is absent only when its own API does
# not answer, the same rule as harness:status. Otherwise a left-over firewall rule, relay-view or a hub restart is
# the more likely cause, and cell:up of the cell does not remove them.
down_hint() {
  if kubectl --context "kind-$1" --request-timeout=10s get --raw /readyz >/dev/null 2>&1; then
    echo "The API of $1 answers. Run: CELL=dev-cp mise run cell:verify, and then mise run mesh:status"
  else
    echo "Run: CELL=$1 mise run cell:up"
  fi
}
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
      echo "hub    $cell: $line. $(down_hint "$cell")"
      status=1
    fi
  elif hub_cell_up "$cell" <<<"$logs"; then
    echo "hub    $cell: tunnel up (from the hub log, the hub process did not answer)"
  else
    echo "hub    $cell: no open tunnel (from the hub log). $(down_hint "$cell")"
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
  echo "kiali  $CELL_NAME: not Ready. Kiali needs every cell at start and restarts until all answer, for up to five minutes after the last cell returns. Run CELL=<cell> mise run cell:up for a cell that does not answer"
  status=1
fi
exit "$status"
