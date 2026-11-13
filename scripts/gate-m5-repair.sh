#!/usr/bin/env bash
# Repair what a gate:m5 run can leave behind. It runs gate-m4-repair.sh first, which repairs the host service, the
# replicas of mgmtd and envd, the registries and the M2 traces. Then it sets the replicas of StatefulSet cell-gateway
# in dev-cp back to 1 through scripts/harness-replicas.sh, and deletes the test namespaces m5-* of every cluster.
# It is safe to run again.
#
# Usage: gate-m5-repair.sh [--check]
#   --check prints each drift with the command that repairs it, and exits 1. It exits 0 when it finds none.
# GATE_M4_REPAIR names another M4 repair script, and HARNESS_REPLICAS another replicas script, for the tests.
export CELL=dev-cp
source "$(dirname "$0")/lib.sh"

check=0
[[ "${1:-}" == "--check" ]] && check=1
repair="mise run gate:m5:repair"
status=0

if ((check)); then
  "${GATE_M4_REPAIR:-$ROOT/scripts/gate-m4-repair.sh}" --check || status=1
else
  "${GATE_M4_REPAIR:-$ROOT/scripts/gate-m4-repair.sh}" || die "the repair of gate:m4 failed. Run: mise run gate:m4:repair"
fi

replicas="$(kubectl --context kind-dev-cp -n gateway-system get statefulset cell-gateway -o jsonpath='{.spec.replicas}' 2>/dev/null)" \
  || { echo "StatefulSet cell-gateway is absent in dev-cp. Run: CELL=dev-cp mise run cell:up"; exit 1; }
if [[ "$replicas" != 1 ]]; then
  status=1
  if ((check)); then
    echo "StatefulSet cell-gateway has $replicas replicas. Run: $repair"
  else
    log "setting the replicas of cell-gateway from $replicas to 1"
    "${HARNESS_REPLICAS:-$ROOT/scripts/harness-replicas.sh}" dev-cp gateway-system statefulset/cell-gateway 1 \
      || die "could not set the replicas of cell-gateway. Run: scripts/harness-replicas.sh dev-cp gateway-system statefulset/cell-gateway 1"
    kubectl --context kind-dev-cp -n gateway-system rollout status statefulset/cell-gateway --timeout=300s >/dev/null \
      || die "statefulset/cell-gateway did not finish its rollout in 300s"
    status=0
  fi
fi

# The test namespaces of the M5 tests carry the label cell.poc.internal/e2e=true.
test_label="cell.poc.internal/e2e"
for cluster in $(yq -r '.clusters[].name' "$ROOT/harness/topology.yaml"); do
  names="$(kubectl --context "kind-$cluster" get namespaces -o json | jq -r --arg l "$test_label" '.items[]
    | select(.metadata.labels[$l] == "true" and (.metadata.name | startswith("m5-"))) | .metadata.name')" \
    || die "could not list the namespaces of $cluster"
  [[ -n "$names" ]] || continue
  status=1
  if ((check)); then
    echo "$cluster holds the test namespaces $(paste -sd' ' - <<<"$names"). Run: $repair"
  else
    for name in $names; do
      log "deleting namespace $name in $cluster"
      kubectl --context "kind-$cluster" delete namespace "$name" --ignore-not-found --wait=true --timeout=180s >/dev/null \
        || die "could not delete namespace $name in $cluster"
    done
    status=0
  fi
done
exit "$status"
