#!/usr/bin/env bash
# Delete the cell cluster and its kubeconfig context. In order:
#   1. Cancel the open step of the cell at the host service (hostsvc:serve -- cancel --cell <cell>), and wait up to
#      CELL_DOWN_WAIT seconds (default 30) until no step of the cell runs a stage. A stage still running after that
#      stops the command, and the message names hostsvc:serve -- cancel. When the host service does not run, the step
#      stays in its journal and runs again at the next start. For a cell of the catalog the script then runs
#      portal -- cancel --cell <cell>, which mgmtd signs, and the host cancels the dropped step at its next start. A cell
#      that has no open step needs no cancel. When mgmtd answers with another error, the script stops with a hint.
#   2. Take the lock of the cluster (cluster_lock in scripts/lib.sh) and delete the cluster.
#   3. Release the lock, and for a cell of the catalog run CELL=dev-cp mise run cell:up and CELL=management mise run
#      cell:link, so that the admit lists of dev-cp and the lists of management drop the deleted node. Set
#      CELL_DOWN_SKIP_RERENDER=1 to skip them, for example when harness:down deletes every cluster next.
# HOSTSVC_SERVE and PORTAL_SH name other scripts, for the tests.
source "$(dirname "$0")/lib.sh"

serve="${HOSTSVC_SERVE:-$ROOT/scripts/hostsvc-serve.sh}"
portal="${PORTAL_SH:-$ROOT/scripts/portal.sh}"
is_cell=0
catalog="$(catalog_cells)" || catalog_failed=1
[[ -z "${catalog_failed:-}" ]] && grep -qx -- "$CELL_NAME" <<<"$catalog" && is_cell=1

# running_stages prints the entries of this cell that run a stage, one on each line. A failed read fails the function.
running_stages() {
  local json
  json="$("$serve" steps)" || return 1
  jq -r --arg cell "$CELL_NAME" '.steps[]? | select(.cell == $cell)
    | select(.state == "creating" or .state == "admitting" or .state == "bootstrapping") | "\(.id) \(.state)"' <<<"$json"
}

read_fail="could not read the steps of the host service, so a running stage is unknown. Read them: mise run hostsvc:serve -- steps. Then run CELL=$CELL_NAME mise run cell:down again"
status_json="$("$serve" status)" || die "could not read the host service status. Run: mise run hostsvc:serve -- status. Then run CELL=$CELL_NAME mise run cell:down again"
running="$(jq -r '.running' <<<"$status_json")" || die "the host service status is no JSON object: $status_json"
if [[ "$running" == true ]]; then
  log "cancelling the open step of $CELL_NAME at the host service"
  "$serve" cancel --cell "$CELL_NAME"
  end=$((SECONDS + ${CELL_DOWN_WAIT:-30}))
  while :; do
    stages="$(running_stages)" || die "$read_fail"
    [[ -n "$stages" ]] || break
    if ((SECONDS >= end)); then
      die "after ${CELL_DOWN_WAIT:-30}s the step of $CELL_NAME still runs a stage: $(paste -sd';' - <<<"$stages"). Cancel it with: mise run hostsvc:serve -- cancel --cell $CELL_NAME, then run CELL=$CELL_NAME mise run cell:down again"
    fi
    sleep "${CELL_DOWN_POLL:-1}"
  done
elif [[ -n "${catalog_failed:-}" ]]; then
  die "the host service does not run, and the catalog of harness/topology.yaml is unreadable, so a step of $CELL_NAME could not be cancelled. Check yq and harness/topology.yaml, or start the service with: mise run hostsvc:serve -- start. Then run CELL=$CELL_NAME mise run cell:down again"
elif ((is_cell)); then
  log "the host service does not run, so mgmtd cancels the step of $CELL_NAME: portal -- cancel"
  cancel_rc=0
  cancel_out="$("$portal" cancel --cell "$CELL_NAME" 2>&1)" || cancel_rc=$?
  if ((cancel_rc != 0)); then
    cancel_reason="$(grep '^{' <<<"$cancel_out" | jq -r '.reason // empty' 2>/dev/null | tail -n 1)" || cancel_reason=""
    case "$cancel_reason" in
      no_step) log "$CELL_NAME has no open step, so nothing needs a cancel" ;;
      restore_active) die "the host service does not run, and mgmtd serves an older revision, so it did not cancel the step of $CELL_NAME: $cancel_out. End the restore with: mise run mgmt -- restore --revision latest. Then run CELL=$CELL_NAME mise run cell:down again" ;;
      "") die "the host service does not run, and mgmtd did not answer, so the step of $CELL_NAME is not cancelled: ${cancel_out:-no output}. A queued step would run again at the next start. Reach mgmtd with: CELL=management LINK_ONLY=mgmt-api mise run cell:link. Then run CELL=$CELL_NAME mise run cell:down again" ;;
      *) die "the host service does not run, and mgmtd refused to cancel the step of $CELL_NAME with the reason $cancel_reason: $cancel_out. Fix the reason, or start the service with: mise run hostsvc:serve -- start. Then run CELL=$CELL_NAME mise run cell:down again" ;;
    esac
  fi
else
  log "the host service does not run, and $CELL_NAME is not a cell of the catalog, so it has no step to cancel"
fi

cluster_lock "$CELL_NAME"
(cd "$ROOT" && mise run hostsvc -- down --only "$CELL_NAME")
rm -rf "$BUILD"
cluster_lock_release

if [[ -n "${catalog_failed:-}" && "${CELL_DOWN_SKIP_RERENDER:-}" != 1 ]]; then
  # The delete is done, but the catalog is unreadable, so whether $CELL_NAME is a cell is unknown.
  log "could not read the catalog of harness/topology.yaml, so the re-render is not run. If $CELL_NAME is a cell, run: CELL=dev-cp mise run cell:up, then CELL=management mise run cell:link"
  exit 1
fi
if ((is_cell)) && [[ "${CELL_DOWN_SKIP_RERENDER:-}" != 1 ]]; then
  log "rendering dev-cp and linking management again, so that their lists drop $CELL_NAME"
  (cd "$ROOT" && CELL=dev-cp mise run cell:up)
  (cd "$ROOT" && CELL=management mise run cell:link)
fi
