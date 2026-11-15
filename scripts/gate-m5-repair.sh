#!/usr/bin/env bash
# Repair what a gate:m5 run can leave behind. It runs gate-m4-repair.sh first, which repairs the host service, the
# replicas of mgmtd and envd, the registries and the M2 traces. Then it sets the replicas of StatefulSet cell-gateway
# in dev-cp, and of Deployment celld in each cell with the cell-identity set, back to 1 through
# scripts/harness-replicas.sh, and deletes the test namespaces m5-* of every cluster.
# It also checks that the gateway holds a stream for each cell with the cell-identity set. The repair cannot open a stream, so the
# script reports a cell with no stream in both modes, with the cell:up of that cell, and exits 1. After a repair it waits up to
# GATE_M5_STREAM_WAIT seconds (default 120) for the streams of the celld pods that it restarted.
# It is safe to run again.
#
# Usage: gate-m5-repair.sh [--check]
#   --check prints each drift with the command that repairs it, and exits 1. It exits 0 when it finds none.
# GATE_M4_REPAIR names another M4 repair script, HARNESS_REPLICAS another replicas script and GW_SCRIPT another gw.sh, for the tests.
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

# TestM5ReplicaCap runs two celld pods in a cell, and a run that stops early leaves them.
for cluster in $(yq -r '.clusters[] | select(.components[] == "cell-identity") | .name' "$ROOT/harness/topology.yaml"); do
  replicas="$(kubectl --context "kind-$cluster" -n cell-identity-system get deployment celld -o jsonpath='{.spec.replicas}' 2>/dev/null)" \
    || { echo "Deployment celld is absent in $cluster. Run: CELL=$cluster mise run cell:up"; status=1; continue; }
  [[ "$replicas" != 1 ]] || continue
  if ((check)); then
    status=1
    echo "Deployment celld in $cluster has $replicas replicas. Run: $repair"
  else
    log "setting the replicas of celld in $cluster from $replicas to 1"
    "${HARNESS_REPLICAS:-$ROOT/scripts/harness-replicas.sh}" "$cluster" cell-identity-system deployment/celld 1 \
      || die "could not set the replicas of celld in $cluster. Run: scripts/harness-replicas.sh $cluster cell-identity-system deployment/celld 1"
    kubectl --context "kind-$cluster" -n cell-identity-system rollout status deployment/celld --timeout=300s >/dev/null \
      || die "deployment/celld in $cluster did not finish its rollout in 300s"
  fi
done

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

# Each celld opens one stream to the gateway when it starts, so a cell with no stream means that celld does not run or does not reach the gateway.
streams_missing() {
  local gw cluster n out=""
  gw="$("${GW_SCRIPT:-$ROOT/scripts/gw.sh}" status)" || true
  if ! jq -e 'type == "object" and has("streams")' >/dev/null 2>&1 <<<"$gw"; then
    echo "the gateway status failed: $(jq -Rsr '(split("\n") | map(fromjson? | select(type == "object")) | .[0].error) // "no status"' <<<"$gw"). Run: CELL=dev-cp mise run cell:up"
    return 1
  fi
  for cluster in $(yq -r '.clusters[] | select(.components[] == "cell-identity") | .name' "$ROOT/harness/topology.yaml"); do
    n="$(jq -r --arg c "$cluster" '.streams[$c] // 0' <<<"$gw")"
    ((n >= 1)) || out+="the gateway holds no stream of $cluster. Run: CELL=$cluster mise run cell:up"$'\n'
  done
  [[ -z "$out" ]] || { printf '%s' "$out"; return 1; }
}
if ((check)); then
  streams_missing || status=1
else
  end=$((SECONDS + ${GATE_M5_STREAM_WAIT:-120}))
  until problems="$(streams_missing)"; do
    ((SECONDS < end)) || { printf '%s\n' "$problems"; status=1; break; }
    sleep 2
  done
fi
exit "$status"
