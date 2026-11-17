#!/usr/bin/env bash
# Delete the cell cluster and its kubeconfig context. In order:
#   1. Cancel the open step of the cell at the host service (hostsvc:serve -- cancel --cell <cell>), and wait up to
#      CELL_DOWN_WAIT seconds (default 30) until no step of the cell runs a stage. A stage still running after that
#      stops the command, and the message names hostsvc:serve -- cancel. When the host service does not run, the cancel
#      is skipped, because a stopped service runs no stage.
#   2. Take the lock of the cluster (cluster_lock in scripts/lib.sh) and delete the cluster.
#   3. Release the lock, and for a cell of the catalog run CELL=dev-cp mise run cell:up and CELL=management mise run
#      cell:link, so that the admit lists of dev-cp and the lists of management drop the deleted node. Set
#      CELL_DOWN_SKIP_RERENDER=1 to skip them, for example when harness:down deletes every cluster next.
# HOSTSVC_SERVE names another host service script, for the tests.
source "$(dirname "$0")/lib.sh"

serve="${HOSTSVC_SERVE:-$ROOT/scripts/hostsvc-serve.sh}"
is_cell=0
grep -qx -- "$CELL_NAME" <<<"$(catalog_cells)" && is_cell=1

# running_stages prints the entries of this cell that run a stage, one on each line.
running_stages() {
  "$serve" steps | jq -r --arg cell "$CELL_NAME" '.steps[]? | select(.cell == $cell)
    | select(.state == "creating" or .state == "admitting" or .state == "bootstrapping") | "\(.id) \(.state)"'
}

if [[ "$("$serve" status | jq -r '.running')" == true ]]; then
  log "cancelling the open step of $CELL_NAME at the host service"
  "$serve" cancel --cell "$CELL_NAME"
  end=$((SECONDS + ${CELL_DOWN_WAIT:-30}))
  until [[ -z "$(running_stages)" ]]; do
    if ((SECONDS >= end)); then
      die "after ${CELL_DOWN_WAIT:-30}s the step of $CELL_NAME still runs a stage: $(running_stages | paste -sd';' -). Cancel it with: mise run hostsvc:serve -- cancel --cell $CELL_NAME, then run CELL=$CELL_NAME mise run cell:down again"
    fi
    sleep "${CELL_DOWN_POLL:-1}"
  done
else
  log "the host service does not run, so it runs no stage, and the cancel is skipped"
fi

cluster_lock "$CELL_NAME"
(cd "$ROOT" && mise run hostsvc -- down --only "$CELL_NAME")
rm -rf "$BUILD"
cluster_lock_release

if ((is_cell)) && [[ "${CELL_DOWN_SKIP_RERENDER:-}" != 1 ]]; then
  log "rendering dev-cp and linking management again, so that their lists drop $CELL_NAME"
  (cd "$ROOT" && CELL=dev-cp mise run cell:up)
  (cd "$ROOT" && CELL=management mise run cell:link)
fi
