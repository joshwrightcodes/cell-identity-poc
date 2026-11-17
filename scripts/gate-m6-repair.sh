#!/usr/bin/env bash
# Repair what a gate:m6 run can leave behind. It runs gate-m5-repair.sh first, which runs the M4 and M2 repairs once. Then it
#   1. runs hostsvc:serve -- sync, so the host service holds the dev root, the keys and the spec of mgmtd, and sets the replicas of
#      Deployment cell-controller in dev-cp back to 1 (a test can scale it down to see the host side alone);
#      It also removes each key <cell>.step.json of ConfigMap cell-steps that is not the step that the spec indexes;
#   2. cancels, through portal -- cancel, each open step whose ID a test recorded in build/gate/m6-steps. It never
#      cancels a step that the provision test signed, because no test records those;
#   3. deletes the test namespaces m6-* (label cell.poc.internal/e2e=true) in management, dev-cp, rogue and each live cell;
#   4. restores the cells while the marker build/gate/m6-provision exists. TestProvisionFromPortal writes the cells that it deletes into the
#      marker before it deletes them, and removes the marker after both cells are valid again, so an interrupted run leaves it. With the
#      marker, the M5 repair does not run first, because a half-built cell counts as live and has no celld. The repair instead
#      a. cancels each open step of a cell that the marker names (portal -- cancel, then cell:down, which waits until no stage runs and
#         deletes the half-built cluster), and runs hostsvc:serve -- sync;
#      b. waits until mgmtd holds no pending drop of a catalog cell, runs one portal -- request for every catalog cell that is not
#         requested, portal -- recreate for each cell of a, portal -- wait for every catalog cell, CELL=management mise run cell:link,
#         then the M5 repair, which waits for the stream of each new cell;
#      c. removes the marker last, after each cell is bound with no open step.
# It is safe to run again.
#
# Usage: gate-m6-repair.sh [--check]
#   --check prints each drift with the command that repairs it, and exits 1. It exits 0 when it finds none. It also fails when a step
#   that no test recorded is open: a gate starts with no open step. It fails too while the marker build/gate/m6-provision exists.
# GATE_M5_REPAIR names another M5 repair script, HOSTSVC_SERVE another host service script, HARNESS_REPLICAS another replicas script
# and PORTAL another portal script, for the tests.
export CELL=dev-cp
source "$(dirname "$0")/lib.sh"

check=0
[[ "${1:-}" == "--check" ]] && check=1
repair="mise run gate:m6:repair"
status=0
serve="${HOSTSVC_SERVE:-$ROOT/scripts/hostsvc-serve.sh}"
recorded="$BUILD_ROOT/gate/m6-steps"
marker="$BUILD_ROOT/gate/m6-provision"

portal() { if [[ -n "${PORTAL:-}" ]]; then "$PORTAL" "$@"; else mise run portal -- "$@"; fi; }

# marker_cells prints the cells that the marker names, one on each line: the lines of the marker that are catalog cells, or every
# catalog cell when the marker names none.
marker_cells() {
  local catalog cell named=""
  catalog="$(catalog_cells)" || die "could not read the cells of the topology"
  for cell in $catalog; do
    ! grep -qx -- "$cell" "$marker" 2>/dev/null || named+="$cell"$'\n'
  done
  if [[ -n "$named" ]]; then printf '%s' "$named"; else printf '%s\n' "$catalog"; fi
}

# reopen holds the cells of the marker whose step was open at the host service. restore_cells asks for them again with recreate.
reopen=()

# clear_interrupted_steps handles each cell of the marker that has an open step: the step belongs to the interrupted run, which the
# marker proves. It cancels the step at mgmtd, then cell:down cancels it at the host, waits until no stage runs, and deletes a
# half-built cluster. A step of a cell that the marker does not name is never touched. A half-built cell counts as live, so the M5
# repair (which restore_cells runs last) would fail on it.
clear_interrupted_steps() {
  local json cell open existing
  json="$("$serve" steps)" || die "could not read the steps of the host service. Run: mise run hostsvc:serve -- steps"
  existing="$(existing_clusters)" || die "could not list the clusters"
  for cell in $(marker_cells); do
    open="$(jq -r --arg c "$cell" '.steps[]? | select(.cell == $c)
      | select(.state != "done" and .state != "failed_final" and .state != "refused" and .state != "cancelled") | .id' <<<"$json")" \
      || die "the steps of the host service are no journal. Run: mise run hostsvc:serve -- steps"
    [[ -n "$open" ]] || continue
    log "cancelling the open step of $cell, which the interrupted provision run left"
    (cd "$ROOT" && portal cancel --cell "$cell") || die "could not cancel the step of $cell. Run: mise run portal -- cancel --cell $cell"
    if grep -qx -- "$cell" <<<"$existing"; then
      (cd "$ROOT" && CELL="$cell" CELL_DOWN_SKIP_RERENDER=1 CELL_DOWN_WAIT="${GATE_M6_STAGE_WAIT:-120}" mise run cell:down) \
        || die "could not delete the half-built $cell. Run: CELL=$cell mise run cell:down"
    fi
    reopen+=("$cell")
  done
}

if ((check)); then
  "${GATE_M5_REPAIR:-$ROOT/scripts/gate-m5-repair.sh}" --check || status=1
elif [[ -e "$marker" ]]; then
  # The M5 repair runs at the end of restore_cells, when each cell has its celld.
  clear_interrupted_steps
  "$serve" sync || die "could not sync the host service. Run: mise run hostsvc:serve -- sync"
else
  "${GATE_M5_REPAIR:-$ROOT/scripts/gate-m5-repair.sh}" || die "the repair of gate:m5 failed. Run: mise run gate:m5:repair"
  "$serve" sync || die "could not sync the host service. Run: mise run hostsvc:serve -- sync"
fi

# A test that scales the cell controller to 0 and stops early leaves no controller, and its steps do not move.
replicas="$(kubectl --context kind-dev-cp -n cell-controller-system get deployment cell-controller -o jsonpath='{.spec.replicas}' 2>/dev/null)" \
  || { echo "Deployment cell-controller is absent in dev-cp. Run: CELL=dev-cp mise run cell:up"; exit 1; }
if [[ "$replicas" != 1 ]]; then
  if ((check)); then
    status=1
    echo "Deployment cell-controller has $replicas replicas. Run: $repair"
  else
    log "setting the replicas of cell-controller from $replicas to 1"
    "${HARNESS_REPLICAS:-$ROOT/scripts/harness-replicas.sh}" dev-cp cell-controller-system deployment/cell-controller 1 \
      || die "could not set the replicas of cell-controller. Run: scripts/harness-replicas.sh dev-cp cell-controller-system deployment/cell-controller 1"
    kubectl --context kind-dev-cp -n cell-controller-system rollout status deployment/cell-controller --timeout=300s >/dev/null \
      || die "deployment/cell-controller did not finish its rollout in 300s"
  fi
fi

# stray_step_keys prints each key <cell>.step.json of ConfigMap cell-steps whose envelope is not the step that the spec in the same
# ConfigMap indexes for the cell: the SHA-256 of its payload differs from stepSHA256, or the spec indexes no step for the cell. A test
# that patches the ConfigMap leaves such a key when it stops early, and envd rewrites the ConfigMap only when its own content changes.
b64d() { if printf 'AA==' | base64 -d >/dev/null 2>&1; then base64 -d; else base64 -D; fi; }
stray_step_keys() {
  local cm index key cell sum want
  cm="$(kubectl --context kind-dev-cp -n cell-controller-system get configmap cell-steps -o json 2>/dev/null)" || return 0
  index="$(jq -r '.data["spec-envelope.json"] // empty | fromjson | .payload' <<<"$cm" 2>/dev/null | b64d 2>/dev/null \
    | jq -r '.steps[]? | "\(.name) \(.stepSHA256)"' 2>/dev/null)" || index=""
  for key in $(jq -r '(.data // {}) | keys[] | select(endswith(".step.json"))' <<<"$cm"); do
    cell="${key%.step.json}"
    sum="$(jq -r --arg k "$key" '.data[$k] | fromjson | .payload' <<<"$cm" 2>/dev/null | b64d 2>/dev/null | shasum -a 256 | cut -d' ' -f1)" || sum=""
    want="$(awk -v c="$cell" '$1 == c { print $2 }' <<<"$index")"
    [[ -n "$want" && "$sum" == "$want" ]] || echo "$key"
  done
}
for key in $(stray_step_keys); do
  if ((check)); then
    status=1
    echo "ConfigMap cell-steps holds the key $key, and it is not the step that the spec indexes. Run: $repair"
  else
    log "removing the key $key from ConfigMap cell-steps"
    kubectl --context kind-dev-cp -n cell-controller-system patch configmap cell-steps --type merge -p "{\"data\":{\"$key\":null}}" >/dev/null \
      || die "could not remove the key $key from ConfigMap cell-steps"
  fi
done

# open_steps prints "<id> <cell> <state>" for each step that has no final state at the host service.
open_steps() {
  local json
  json="$("$serve" steps)" || return 1
  jq -r '.steps[]? | select(.state != "done" and .state != "failed_final" and .state != "refused" and .state != "cancelled")
    | "\(.id) \(.cell) \(.state)"' <<<"$json"
}

if [[ "$("$serve" status | jq -r '.running')" != true ]]; then
  echo "the host service does not run, so its open steps are unknown. Run: mise run hostsvc:serve -- start"
  status=1
else
  open="$(open_steps)" || die "could not read the steps of the host service. Run: mise run hostsvc:serve -- steps"
  while read -r id cell state; do
    [[ -n "$id" ]] || continue
    if grep -qx -- "$id" "$recorded" 2>/dev/null; then
      if ((check)); then
        status=1
        echo "step $id of $cell is $state, and a gate test recorded it. Run: $repair"
      else
        log "cancelling step $id of $cell, which a gate test recorded"
        (cd "$ROOT" && portal cancel --cell "$cell") || die "could not cancel step $id. Run: mise run portal -- cancel --cell $cell"
      fi
    elif ((check)); then
      status=1
      echo "step $id of $cell is $state, and no gate test recorded it. Read it: mise run hostsvc:serve -- steps. Then wait for it, or run: mise run portal -- cancel --cell $cell"
    fi
  done <<<"$open"
fi

# The test namespaces of the M6 tests carry the label cell.poc.internal/e2e=true.
test_label="cell.poc.internal/e2e"
clusters="$(
  existing="$(existing_clusters)" || die "could not list the clusters"
  live="$(live_cells)" || die "could not list the live cells"
  for c in management dev-cp rogue $live; do
    grep -qx -- "$c" <<<"$existing" && echo "$c"
  done | sort -u
)"
for cluster in $clusters; do
  names="$(kubectl --context "kind-$cluster" get namespaces -o json | jq -r --arg l "$test_label" '.items[]
    | select(.metadata.labels[$l] == "true" and (.metadata.name | startswith("m6-"))) | .metadata.name')" \
    || die "could not list the namespaces of $cluster"
  [[ -n "$names" ]] || continue
  if ((check)); then
    status=1
    echo "$cluster holds the test namespaces $(paste -sd' ' - <<<"$names"). Run: $repair"
  else
    for name in $names; do
      log "deleting namespace $name in $cluster"
      kubectl --context "kind-$cluster" delete namespace "$name" --ignore-not-found --wait=true --timeout=180s >/dev/null \
        || die "could not delete namespace $name in $cluster"
    done
  fi
done

# restore_cells brings the cells back after an interrupted provision run. Each command is safe to run again, and the marker
# stays until the last one has succeeded. It first waits until mgmtd holds no pending drop of a catalog cell, because a request
# before the drop leaves the old record in place and the step would never close (hint: wait, then run the repair again).
restore_cells() {
  local catalog status_json requested pending blocked missing=() margs=() cell args=() end poll="${GATE_M6_POLL:-5}"
  catalog="$(catalog_cells)" || die "could not read the cells of the topology"
  end=$((SECONDS + ${GATE_M6_DROP_WAIT:-300}))
  while :; do
    status_json="$(cd "$ROOT" && mise run mgmt -- status)" || die "could not read mgmt -- status. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"
    pending="$(jq -r '.pendingDrops[]?' <<<"$status_json")" || die "mgmt -- status printed no status object"
    blocked=""
    for cell in $catalog; do
      ! grep -qx -- "$cell" <<<"$pending" || blocked+=" $cell"
    done
    [[ -n "$blocked" ]] || break
    ((SECONDS < end)) || die "after ${GATE_M6_DROP_WAIT:-300}s mgmtd still holds the pending drop of$blocked. Wait for envd to apply it, then run: $repair"
    sleep "$poll"
  done
  requested="$(jq -r '.cells[]? | select(.requested == true) | .name' <<<"$status_json")" || die "mgmt -- status printed no status object"
  for cell in $catalog; do
    grep -qx -- "$cell" <<<"$requested" || missing+=("$cell")
    args+=(--cell "$cell")
  done
  if ((${#missing[@]} > 0)); then
    log "requesting ${missing[*]}"
    for cell in "${missing[@]}"; do margs+=(--cell "$cell"); done
    (cd "$ROOT" && portal request "${margs[@]}") || die "could not request ${missing[*]}. Run: mise run portal -- request ${margs[*]}"
  fi
  for cell in ${reopen[@]+"${reopen[@]}"}; do
    log "requesting $cell again, because its step was cancelled"
    (cd "$ROOT" && portal recreate --cell "$cell") || die "could not request $cell again. Run: mise run portal -- recreate --cell $cell"
  done
  log "waiting until ${catalog//$'\n'/ } are valid"
  (cd "$ROOT" && portal wait "${args[@]}") || die "a cell is not valid. Read the step: mise run hostsvc:serve -- steps. Then run: $repair"
  log "linking management"
  (cd "$ROOT" && CELL=management mise run cell:link) || die "could not link management. Run: CELL=management mise run cell:link, then $repair"
  "${GATE_M5_REPAIR:-$ROOT/scripts/gate-m5-repair.sh}" || die "the repair of gate:m5 failed, or a cell holds no stream at the gateway. Run: $repair"
  # Each cell must be bound with no open step, or the next gate fails its check for an open step.
  end=$((SECONDS + ${GATE_M6_BOUND_WAIT:-120}))
  while :; do
    status_json="$(cd "$ROOT" && mise run mgmt -- status)" || die "could not read mgmt -- status. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"
    blocked="$(jq -r '.cells[]? | select(.bound != true or ((.step // null) != null and ((.step.doneAt // "") == ""))) | .name' <<<"$status_json")" \
      || die "mgmt -- status printed no status object"
    [[ -z "$blocked" ]] && break
    ((SECONDS < end)) || die "after ${GATE_M6_BOUND_WAIT:-120}s these cells are not bound, or have an open step: $(paste -sd' ' - <<<"$blocked"). Read: mise run mgmt -- status. Then run: mise run portal -- cancel --cell <cell> if its step is stale, and $repair"
    sleep "$poll"
  done
  rm -f "$marker" || die "could not remove $marker"
}
if [[ -e "$marker" ]]; then
  if ((check)); then
    status=1
    echo "the marker $marker exists, so a provision run stopped early and a cell can be missing. Run: $repair"
  else
    log "restoring the cells, because $marker exists"
    restore_cells
  fi
fi
exit "$status"
