#!/usr/bin/env bash
# Repair what a gate:m7 run can leave behind. Each M7 test runs its probe pods, its impostor servers and its forwarders in a namespace
# m7-<hex> with the label cell.poc.internal/e2e=true, in the cluster of its client. The script deletes every such namespace in every
# existing cluster, and then waits until no one is left, so a stuck namespace is an error and not a silent leftover. It never touches a
# namespace without the label, and none with another prefix. It is safe to run again.
#
# Usage: gate-m7-repair.sh [--check]
#   --check prints each cluster that holds an m7 namespace, with the command that repairs it, and exits 1. It exits 0 when it finds none.
# GATE_M7_WAIT sets the seconds to wait for the deletions (default 180) and GATE_M7_POLL the seconds between two reads (default 5).
export CELL=dev-cp
source "$(dirname "$0")/lib.sh"

check=0
[[ "${1:-}" == "--check" ]] && check=1
repair="mise run gate:m7:repair"
test_label="cell.poc.internal/e2e"

# m7_namespaces prints "<cluster> <namespace>" for each test namespace of M7, one on each line.
m7_namespaces() {
  local cluster clusters names name
  clusters="$(existing_clusters)" || die "could not list the clusters. Run: mise run harness:status"
  for cluster in $clusters; do
    names="$(kubectl --context "kind-$cluster" get namespaces -o json | jq -r --arg l "$test_label" '.items[]
      | select(.metadata.labels[$l] == "true" and (.metadata.name | startswith("m7-"))) | .metadata.name')" \
      || die "could not list the namespaces of $cluster"
    for name in $names; do
      printf '%s %s\n' "$cluster" "$name"
    done
  done
}

found="$(m7_namespaces)" || exit 1
[[ -n "$found" ]] || exit 0

if ((check)); then
  while read -r cluster name; do
    echo "$cluster holds the test namespace $name. Run: $repair"
  done <<<"$found"
  exit 1
fi

while read -r cluster name; do
  log "deleting namespace $name in $cluster"
  kubectl --context "kind-$cluster" delete namespace "$name" --ignore-not-found --wait=true --timeout=180s >/dev/null \
    || die "could not delete namespace $name in $cluster"
done <<<"$found"

end=$((SECONDS + ${GATE_M7_WAIT:-180}))
while :; do
  left="$(m7_namespaces)" || exit 1
  [[ -n "$left" ]] || break
  ((SECONDS < end)) || die "after ${GATE_M7_WAIT:-180}s these namespaces (cluster, name) still exist: $(paste -sd, - <<<"$left"). Run: kubectl --context kind-<cluster> get namespace <name> -o yaml, then $repair"
  sleep "${GATE_M7_POLL:-5}"
done
