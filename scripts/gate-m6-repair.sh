#!/usr/bin/env bash
# Repair what a gate:m6 run can leave behind. It runs gate-m5-repair.sh first, which runs the M4 and M2 repairs once. Then it
#   1. runs hostsvc:serve -- sync, so the host service holds the dev root, the keys and the spec of mgmtd;
#   2. cancels, through portal -- cancel, each open step whose ID a test recorded in build/gate/m6-steps. It never
#      cancels a step that the provision test signed, because no test records those;
#   3. deletes the test namespaces m6-* (label cell.poc.internal/e2e=true) in management, dev-cp, rogue and each live cell.
# It is safe to run again.
#
# Usage: gate-m6-repair.sh [--check]
#   --check prints each drift with the command that repairs it, and exits 1. It exits 0 when it finds none. It also fails when a step
#   that no test recorded is open: a gate starts with no open step.
# GATE_M5_REPAIR names another M5 repair script, HOSTSVC_SERVE another host service script and PORTAL another portal script, for
# the tests.
export CELL=dev-cp
source "$(dirname "$0")/lib.sh"

check=0
[[ "${1:-}" == "--check" ]] && check=1
repair="mise run gate:m6:repair"
status=0
serve="${HOSTSVC_SERVE:-$ROOT/scripts/hostsvc-serve.sh}"
recorded="$BUILD_ROOT/gate/m6-steps"

portal() { if [[ -n "${PORTAL:-}" ]]; then "$PORTAL" "$@"; else mise run portal -- "$@"; fi; }

if ((check)); then
  "${GATE_M5_REPAIR:-$ROOT/scripts/gate-m5-repair.sh}" --check || status=1
else
  "${GATE_M5_REPAIR:-$ROOT/scripts/gate-m5-repair.sh}" || die "the repair of gate:m5 failed. Run: mise run gate:m5:repair"
  "$serve" sync || die "could not sync the host service. Run: mise run hostsvc:serve -- sync"
fi

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
exit "$status"
